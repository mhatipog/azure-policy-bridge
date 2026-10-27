"""Strictly bounded *advisory* offline match of selected Azure Policy operators.

Not an Azure Policy engine: aliases, deployment/request context, initiative controls,
assignment selectors and policy exemptions can alter enforcement. A locally matched
rule only means 'review this candidate'; a local non-match never grants permission.
"""
from __future__ import annotations
import re
from typing import Any
from .core import Change, _assignment_index

UNKNOWN = object()
PARAM = re.compile(r"^\[parameters\('([a-zA-Z0-9_]+)'\)\]$", re.I)
ALIASES = {
    "microsoft.storage/storageaccounts/publicnetworkaccess": "azurerm_storage_account",
    "microsoft.keyvault/vaults/publicnetworkaccess": "azurerm_key_vault",
    "microsoft.sql/servers/publicnetworkaccess": "azurerm_mssql_server",
    "microsoft.servicebus/namespaces/publicnetworkaccess": "azurerm_servicebus_namespace",
}


def _values(x: Any) -> list[dict]:
    arr = x.get("value", x.get("definitions", [])) if isinstance(x, dict) else x
    return [item for item in arr if isinstance(item, dict)] if isinstance(arr, list) else []


def _resolve(value: Any, parameters: dict[str, Any]) -> Any:
    if isinstance(value, str):
        match = PARAM.fullmatch(value)
        if match:
            return parameters.get(match.group(1).lower(), UNKNOWN)
        # No ARM template expression evaluation or dynamic evaluation.
        if value.startswith("[") and value.endswith("]"):
            return UNKNOWN
    return value


def _field(change: Change, alias: str) -> Any:
    key = alias.lower()
    if key == "type":
        return change.azure_type if change.azure_type else UNKNOWN
    if key == "location":
        return change.known.get("location", UNKNOWN)
    if key in ALIASES:
        if change.kind != ALIASES[key]:
            return UNKNOWN
        prop = change.known.get("public_network_access_enabled", UNKNOWN)
        if isinstance(prop, bool):
            return "Enabled" if prop else "Disabled"
        return UNKNOWN
    return UNKNOWN


def _eval_rule(expr: Any, change: Change, params: dict[str, Any]) -> Any:
    if not isinstance(expr, dict):
        return UNKNOWN
    if "allOf" in expr:
        conditions = expr["allOf"]
        if not isinstance(conditions, list) or not conditions:
            return UNKNOWN
        result = [_eval_rule(x, change, params) for x in conditions]
        return False if False in result else UNKNOWN if UNKNOWN in result else True
    if "anyOf" in expr:
        conditions = expr["anyOf"]
        if not isinstance(conditions, list) or not conditions:
            return UNKNOWN
        result = [_eval_rule(x, change, params) for x in conditions]
        return True if True in result else UNKNOWN if UNKNOWN in result else False
    if "not" in expr:
        result = _eval_rule(expr["not"], change, params)
        return not result if result is not UNKNOWN else UNKNOWN
    field = expr.get("field")
    if not isinstance(field, str) or any(k in expr for k in ("count", "where", "value", "like", "match", "contains", "greater", "less")):
        return UNKNOWN
    actual = _field(change, field)
    if actual is UNKNOWN:
        return UNKNOWN
    operators = [op for op in ("equals", "notEquals", "in", "notIn", "exists") if op in expr]
    if len(operators) != 1:
        return UNKNOWN
    op = operators[0]
    expected = _resolve(expr[op], params)
    if expected is UNKNOWN:
        return UNKNOWN
    if op == "exists":
        if isinstance(expected, bool):
            return expected  # Known field present; absence requires real alias semantics.
        if isinstance(expected, str) and expected.lower() in ("true", "false"):
            return expected.lower() == "true"
        return UNKNOWN
    if isinstance(expected, list):
        expected = [x.lower() if isinstance(x, str) else x for x in expected]
    normalized = actual.lower() if isinstance(actual, str) else actual
    if isinstance(expected, str):
        expected = expected.lower()
    if op == "equals":
        return normalized == expected
    if op == "notEquals":
        return normalized != expected
    if op in ("in", "notIn") and isinstance(expected, list):
        result = normalized in expected
        return result if op == "in" else not result
    return UNKNOWN


def _parameters(definition: dict, assignment_parameters: dict, reference_parameters: dict | None = None) -> dict[str, Any]:
    props = definition.get("properties", {})
    values: dict[str, Any] = {}
    for name, value in (props.get("parameters") or {}).items():
        if isinstance(value, dict) and "defaultValue" in value:
            values[name.lower()] = value["defaultValue"]
    for name, value in assignment_parameters.items():
        if isinstance(value, dict) and "value" in value:
            values[name.lower()] = value["value"]
    if reference_parameters:
        for name, value in reference_parameters.items():
            if isinstance(value, dict) and "value" in value:
                values[name.lower()] = _resolve(value["value"], values)
    return values


def find_candidates(changes: list[Change], assignments: Any, definitions: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """Return supported positive candidates only, with explicit incomplete-evidence gaps.

    Includes simple policies and initiative references when all referenced definitions
    are supplied. Never returns an official Azure deny/allow decision.
    """
    definition_index = {item["id"].lower(): item for item in _values(definitions)
                        if isinstance(item.get("id"), str)}
    candidates: list[dict[str, Any]] = []
    gaps: set[str] = set()
    for assignment_id, assignment in _assignment_index(assignments).items():
        props = assignment.get("properties") or {}
        if props.get("enforcementMode") == "DoNotEnforce":
            continue
        if props.get("enforcementMode") == "Enroll":
            gaps.add("Enrolled policy assignments require cloud-side enrolment evidence; skipped.")
            continue
        if props.get("resourceSelectors") or props.get("overrides"):
            gaps.add("Assignment selectors/overrides require Azure evaluation; static matching was skipped.")
            continue
        policy_id = props.get("policyDefinitionId", "")
        definition = definition_index.get(policy_id.lower()) if isinstance(policy_id, str) else None
        if not definition:
            gaps.add("Some policy definitions or initiatives are absent from the snapshot; they were not evaluated.")
            continue
        dprops = definition.get("properties", {})
        rules: list[tuple[str, str | None, dict, dict]] = []
        if isinstance(dprops.get("policyRule"), dict):
            rules.append((policy_id, None, definition, _parameters(definition, props.get("parameters") or {})))
        elif isinstance(dprops.get("policyDefinitions"), list):
            initiative_params = _parameters(definition, props.get("parameters") or {})
            for ref in dprops["policyDefinitions"]:
                if not isinstance(ref, dict) or not isinstance(ref.get("policyDefinitionId"), str):
                    gaps.add("Initiative has a reference without a policy definition ID; skipped.")
                    continue
                rid = ref["policyDefinitionId"]
                target = definition_index.get(rid.lower())
                if not target or not isinstance((target.get("properties") or {}).get("policyRule"), dict):
                    gaps.add("At least one referenced initiative policy definition is missing or unsupported.")
                    continue
                rules.append((rid, ref.get("policyDefinitionReferenceId"), target,
                              _parameters(target, initiative_params_to_assignment(initiative_params), ref.get("parameters"))))
        else:
            gaps.add("Unsupported policy definition / initiative; no inference made.")
            continue
        scope = props.get("scope")
        excluded = props.get("notScopes", [])
        for rule_id, ref_id, target, params in rules:
            rule = (target.get("properties") or {}).get("policyRule")
            if not isinstance(rule, dict):
                continue
            effect = _resolve((rule.get("then") or {}).get("effect"), params)
            if not isinstance(effect, str) or effect.lower() != "deny":
                continue
            for change in changes:
                if "delete" in change.actions and "create" not in change.actions:
                    continue
                rid = change.resource_id
                if rid and isinstance(excluded, list) and any(isinstance(x, str) and (rid.lower() == x.lower() or rid.lower().startswith(x.lower().rstrip("/") + "/")) for x in excluded):
                    continue
                if excluded and not rid:
                    gaps.add("Assignments have exclusions but planned resources lack IDs; applicability is not proven.")
                if isinstance(scope, str) and rid and scope.startswith("/subscriptions/") and not (rid.lower() == scope.lower() or rid.lower().startswith(scope.lower().rstrip("/") + "/")):
                    continue
                result = _eval_rule(rule.get("if"), change, params)
                if result is True:
                    candidates.append({
                        "status": "POSSIBLE_POLICY_CONFLICT_NOT_AZURE_VERIFIED",
                        "terraform_address": change.address,
                        "assignment_id": assignment_id,
                        "policy_definition_id": rule_id,
                        "initiative_reference_id": ref_id,
                        "assignment_name": props.get("displayName") if isinstance(props.get("displayName"), str) else None,
                        "scope": scope,
                        "confidence": "LIMITED_STATIC_MATCH",
                        "recommended_action": "Review the relevant rule with central cloud governance, adapt Terraform to the supported pattern, and verify through authorized Azure tooling.",
                    })
                elif result is UNKNOWN:
                    gaps.add("Some aliases, parameters or planned property values cannot be evaluated safely offline.")
    return candidates, sorted(gaps)


def initiative_params_to_assignment(params: dict[str, Any]) -> dict[str, dict]:
    """Resolve initiative-level parameters before resolving per-reference mappings."""
    return {key: {"value": value} for key, value in params.items()}
