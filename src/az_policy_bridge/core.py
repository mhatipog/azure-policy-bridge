"""Turn Azure ARM denial evidence + Terraform changes into an actionable review.

Trust contract:
- A policy denial is *confirmed* only from Azure's error/event evidence.
- Static plan inspection is advisory, never proof of Azure policy compliance.
- Outputs contain allowlisted configuration metadata, not plan values or credentials.
- Neither the library nor CLI changes cloud resources or policies.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from .terraform_log import extract_policy_identifiers

POLICY_ERROR_CODES = {"requestdisallowedbypolicy", "policyviolation", "resourcedeniedbypolicy", "policyevaluationfailed"}
OTHER_BLOCKER_CODES = {
    "authorizationfailed": ("Identity/RBAC", "Identity or subscription administrator"),
    "linkedauthorizationfailed": ("Cross-scope identity/RBAC", "Identity and referenced-scope administrators"),
    "missingsubscriptionregistration": ("Resource-provider registration", "Subscription administrator"),
    "subscriptionnotregistered": ("Resource-provider registration", "Subscription administrator"),
    "quotaexceeded": ("Quota/capacity", "Subscription administrator"),
    "operationnotallowed": ("Platform restriction (not necessarily Policy)", "Platform administrator"),
    "disallowedbypolicy": ("Azure Policy", "Policy administrator"),
}
# Explicitly limited to widely-recognized common Terraform AzureRM resource mappings.
TERRAFORM_AZURE = {
    "azurerm_storage_account": "Microsoft.Storage/storageAccounts",
    "azurerm_key_vault": "Microsoft.KeyVault/vaults",
    "azurerm_mssql_server": "Microsoft.Sql/servers",
    "azurerm_servicebus_namespace": "Microsoft.ServiceBus/namespaces",
    "azurerm_resource_group": "Microsoft.Resources/resourceGroups",
    "azurerm_container_app_environment": "Microsoft.App/managedEnvironments",
    "azurerm_container_registry": "Microsoft.ContainerRegistry/registries",
    "azurerm_public_ip": "Microsoft.Network/publicIPAddresses",
}

# Advisory signals, not statements about assignments in the target tenant.
SIGNALS = {
    "azurerm_storage_account": [
        ("public_network_access_enabled", True, "Public network access", "high", "Disable public access and confirm the supported private endpoint and DNS configuration."),
        ("shared_access_key_enabled", True, "Shared-key authentication", "high", "Use Entra ID / managed identities if the application and operations support it."),
        ("min_tls_version", "TLS1_0", "Legacy TLS", "high", "Require TLS 1.2+ after checking client compatibility."),
    ],
    "azurerm_key_vault": [
        ("public_network_access_enabled", True, "Public Key Vault endpoint", "high", "Use private connectivity and an approved access pattern."),
        ("enable_rbac_authorization", False, "Key Vault legacy access policies", "medium", "Review the supported managed-identity and Azure RBAC access pattern."),
    ],
    "azurerm_mssql_server": [
        ("public_network_access_enabled", True, "Public SQL endpoint", "high", "Disable public access and use approved private connectivity."),
    ],
    "azurerm_servicebus_namespace": [
        ("public_network_access_enabled", True, "Public Service Bus endpoint", "high", "Validate the namespace SKU, Private Link and private DNS requirements."),
    ],
}

@dataclass(frozen=True)
class Change:
    address: str
    kind: str
    azure_type: str | None
    actions: tuple[str, ...]
    proposed_name: str | None
    known: Mapping[str, Any]
    unknown: frozenset[str]
    resource_id: str | None


def _short(value: Any, max_len: int = 180) -> str:
    """Stable bounded label; never use on arbitrary error-message bodies."""
    return str(value)[:max_len]


def _safe_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    # Azure resource IDs are identifiers, not secrets, but retain a strict shape.
    if len(value) > 1024 or not re.fullmatch(r"/[A-Za-z0-9_{}.\-]+(?:/[A-Za-z0-9_{}.\-]+)+", value):
        return None
    return value


def _node_name(resource_id: str | None) -> str | None:
    return resource_id.rstrip("/").split("/")[-1] if resource_id else None


def _safe_label(v: Any) -> str | None:
    if not isinstance(v, str) or len(v) > 256 or not re.fullmatch(r"[\w .(),:/\-]+", v):
        return None
    return v


def parse_plan(payload: Any) -> list[Change]:
    if not isinstance(payload, dict) or not isinstance(payload.get("resource_changes"), list):
        raise ValueError("Expected the JSON output of `terraform show -json PLANFILE` (resource_changes array)")
    changes: list[Change] = []
    for entry in payload["resource_changes"]:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("type")
        address = entry.get("address")
        if not isinstance(kind, str) or not isinstance(address, str):
            continue
        c = entry.get("change", {})
        if not isinstance(c, dict):
            continue
        actions = tuple(x for x in c.get("actions", []) if isinstance(x, str))
        if not actions or actions == ("no-op",):
            continue
        after = c.get("after") if isinstance(c.get("after"), dict) else {}
        before = c.get("before") if isinstance(c.get("before"), dict) else {}
        after_unknown = c.get("after_unknown") if isinstance(c.get("after_unknown"), dict) else {}
        # Deliberately NOT storing arbitrary after/before values; plan JSON may contain passwords.
        safe_fields = {"public_network_access_enabled", "shared_access_key_enabled", "enable_rbac_authorization", "min_tls_version", "location"}
        known: dict[str, Any] = {}
        for field in safe_fields:
            value = after.get(field)
            if isinstance(value, bool) or (field in ("min_tls_version", "location") and isinstance(value, str) and len(value) <= 40):
                known[field] = value
        azure_type = TERRAFORM_AZURE.get(kind)
        name = _safe_label(after.get("name")) or _safe_label(before.get("name"))
        rid = _safe_id(before.get("id")) or _safe_id(after.get("id"))
        changes.append(Change(_short(address, 256), kind, azure_type, actions, name, known, frozenset(k for k, v in after_unknown.items() if v), rid))
    return changes


def advisory_signals(changes: list[Change]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for change in changes:
        if "delete" in change.actions and "create" not in change.actions:
            continue
        for field, value, label, severity, remedy in SIGNALS.get(change.kind, []):
            if field not in change.known or change.known[field] != value:
                continue
            findings.append({"status": "ADVISORY", "resource": change.address, "resource_type": change.azure_type,
                             "signal": label, "field": field, "observed_value": value,
                             "severity": severity, "owner": "Deployment author (proposed configuration)",
                             "suggested_action": remedy,
                             "evidence": "Terraform plan; not a confirmed Azure Policy conflict"})
    return findings


def _nested_errors(tree: Any) -> list[dict[str, Any]]:
    """Walk documented ARM `error`, `details` and `additionalInfo` shapes only.

    JSON-encoded error *messages* may contain credentials; do not parse arbitrary text.
    """
    results = []
    stack = [tree]
    seen = set()
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, list):
            stack.extend(node[:2000])
        elif isinstance(node, dict):
            if isinstance(node.get("code"), str):
                results.append(node)
            for key in ("error", "details", "innererror", "additionalInfo", "statusMessage", "properties", "value"):
                child = node.get(key)
                if isinstance(child, (list, dict)):
                    stack.append(child)
                elif key == "statusMessage" and isinstance(child, str) and len(child) < 1_000_000 and child.lstrip().startswith("{"):
                    try:
                        stack.append(json.loads(child))
                    except json.JSONDecodeError:
                        pass
    return results


def _policy_info(node: dict[str, Any]) -> list[dict[str, Any]]:
    found = []
    additional = node.get("additionalInfo")
    for element in additional if isinstance(additional, list) else []:
        if not isinstance(element, dict):
            continue
        info = element.get("info")
        if isinstance(info, dict) and str(element.get("type", "")).lower() in {"policyviolation", "policyevaluationdetails", "policyviolationinfo"}:
            found.append(info)
    # Some deployment responses supply identifiers only within a message.
    if str(node.get("code", "")).lower() in POLICY_ERROR_CODES:
        found.extend(extract_policy_identifiers(node.get("message")))
    # Some providers put policy metadata at the top of their error payload.
    if any(key in node for key in ("policyAssignmentId", "policyDefinitionId")):
        found.append(node)
    return found


def _extract_observation(info: Mapping[str, Any]) -> list[dict[str, str]]:
    details = info.get("evaluationDetails") or info.get("evaluationdetails") or {}
    exprs = details.get("evaluatedExpressions", []) if isinstance(details, dict) else []
    allow = {"location", "type", "tags", "microsoft.storage/storageaccounts/publicnetworkaccess",
             "microsoft.keyvault/vaults/publicnetworkaccess", "microsoft.sql/servers/publicnetworkaccess",
             "microsoft.servicebus/namespaces/publicnetworkaccess", "microsoft.storage/storageaccounts/allowsharedkeyaccess"}
    result = []
    for expr in exprs if isinstance(exprs, list) else []:
        if not isinstance(expr, dict):
            continue
        alias = expr.get("path") or expr.get("expression")
        if not isinstance(alias, str) or alias.lower() not in allow:
            continue
        # Values are limited to non-secret scalars; no raw expressions or arbitrary property bags.
        entry = {"field": alias}
        for source, dest in (("expressionValue", "actual"), ("targetValue", "required")):
            value = expr.get(source)
            if isinstance(value, bool):
                entry[dest] = str(value).lower()
            elif isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9_\-]{1,40}", value):
                entry[dest] = value
        if entry:
            result.append(entry)
    return result[:8]


def _assignment_index(data: Any) -> dict[str, dict]:
    items = data.get("value", []) if isinstance(data, dict) else data
    index = {}
    if not isinstance(items, list):
        return index
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            index[item["id"].lower()] = item
    return index


def _match_plan(resource_id: str | None, changes: list[Change]) -> str | None:
    if not resource_id:
        return None
    lower_id = resource_id.lower()
    direct = [c.address for c in changes if c.resource_id and c.resource_id.lower() == lower_id]
    if len(direct) == 1:
        return direct[0]
    # Only match by last segment AND resource type; reject ambiguity.
    resource_name = _node_name(resource_id)
    if not resource_name:
        return None
    matches = [c.address for c in changes if c.azure_type and ("/providers/" + c.azure_type.lower() + "/") in lower_id
               and c.proposed_name and c.proposed_name.lower() == resource_name.lower()]
    return matches[0] if len(matches) == 1 else None


def _known_advice(observations: list[dict]) -> tuple[str, str]:
    aliases = " ".join(x.get("field", "") for x in observations).lower()
    if "publicnetworkaccess" in aliases:
        return ("Check the supported private networking path and change the deployment configuration where appropriate.",
                "Disabling this guardrail can expose a data-plane endpoint beyond intended private network boundaries; evaluate identity, firewall, DNS, monitoring and data sensitivity.")
    if "allowsharedkeyaccess" in aliases:
        return ("Check whether the workload supports managed identity / Entra ID authentication and update Terraform and client configuration.",
                "Allowing shared keys increases the impact of key compromise and complicates least-privilege enforcement.")
    if "location" in aliases:
        return ("Move the workload to an approved Azure region or request an explicit data residency / capability review.",
                "A location exception may affect residency, resilience, regulatory obligations or centrally supported operations.")
    return ("Read the evaluated rule and parameters, then adapt the deployment to the documented allowed configuration when possible.",
            "The risk of an exception cannot be rated from the denial alone; the policy intent, workload sensitivity, scope and compensating controls require review.")


def _owner_hint(assignment: dict | None) -> str:
    if not assignment:
        return "Policy owner not identified in supplied evidence"
    props = assignment.get("properties") or {}
    metadata = props.get("metadata") or {}
    for key in ("owner", "technicalOwner", "contact", "team"):
        value = metadata.get(key)
        if isinstance(value, str) and len(value) <= 120 and "@" not in value:
            safe = _safe_label(value)
            if safe:
                return safe
    return "Policy owner not identified in assignment metadata"


def triage(plan: Any | None = None, azure_errors: Any | None = None, assignments: Any | None = None) -> dict[str, Any]:
    changes = parse_plan(plan) if plan is not None else []
    index = _assignment_index(assignments) if assignments is not None else {}
    advisories = advisory_signals(changes)
    policy_findings: list[dict[str, Any]] = []
    other_findings: list[dict[str, Any]] = []
    unclassified: list[dict[str, str]] = []
    seen: set[tuple] = set()
    for node in _nested_errors(azure_errors) if azure_errors is not None else []:
        code = node.get("code", "")
        if not isinstance(code, str):
            continue
        code_key = code.lower()
        policy_infos = _policy_info(node)
        if policy_infos or code_key in POLICY_ERROR_CODES:
            if not policy_infos:
                policy_infos = [{}]
            for info in policy_infos:
                assignment_id = _safe_id(info.get("policyAssignmentId"))
                definition_id = _safe_id(info.get("policyDefinitionId"))
                initiative_id = _safe_id(info.get("policySetDefinitionId"))
                resource_id = _safe_id(info.get("resourceId")) or _safe_id(node.get("target"))
                log_address = _safe_label(node.get("terraformAddress"))
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\-\[\]\"']{0,255}", log_address or ""):
                    log_address = None
                if changes and log_address not in {c.address for c in changes}:
                    log_address = None
                reference_id = _safe_label(info.get("policyDefinitionReferenceId"))
                key = (assignment_id, definition_id, reference_id, resource_id, log_address, code_key)
                if key in seen:
                    continue
                seen.add(key)
                assignment = index.get((assignment_id or "").lower())
                assignment_props = assignment.get("properties", {}) if assignment else {}
                observations = _extract_observation(info)
                fix, risk = _known_advice(observations)
                matched_plan = _match_plan(resource_id, changes)
                linked_address = matched_plan or log_address
                plan_observations = [
                    {"field": a["field"], "observed_value": a["observed_value"], "signal": a["signal"]}
                    for a in advisories if a["resource"] == linked_address
                ]
                if plan_observations and not observations:
                    risk = ("The Terraform plan independently proposes: " +
                            ", ".join(x["signal"] for x in plan_observations) +
                            ". This could expand exposure or weaken controls if deployed; it does NOT establish which predicate Azure Policy evaluated. " + risk)
                    relevant = next(a for a in advisories if a["resource"] == linked_address)
                    fix = ("Terraform preflight suggests: " + relevant["suggested_action"] +
                           " Confirm the actual denial rule with the policy owner before treating this as the fix.")
                policy_findings.append({
                    "status": "CONFIRMED_AZURE_POLICY_DENIAL",
                    "code": code,
                    "resource_id": resource_id,
                    "terraform_address": linked_address,
                    "address_evidence": "matched_plan" if matched_plan else "error_log" if log_address else "unavailable",
                    "plan_observations_not_azure_confirmed": plan_observations,
                    "assignment_id": assignment_id,
                    "assignment_name": _safe_label(assignment_props.get("displayName")) if assignment else None,
                    "assignment_scope": _safe_id(assignment_props.get("scope")) if assignment else None,
                    "policy_definition_id": definition_id,
                    "initiative_id": initiative_id,
                    "initiative_reference_id": reference_id,
                    "non_compliance_message": _safe_label(next((msg.get("message") for msg in assignment_props.get("nonComplianceMessages", []) if isinstance(msg, dict) and (msg.get("policyDefinitionReferenceId") in (None, reference_id))), None)) if assignment else None,
                    "enforcement_mode": _safe_label(assignment_props.get("enforcementMode")) if assignment else None,
                    "evaluation_evidence": observations,
                    "developer_action": fix,
                    "central_decision": "Check the policy intent, approved deployment options and whether further review is warranted; no automatic policy changes.",
                    "governance_owner": _owner_hint(assignment),
                    "exception_risk": risk,
                    "evidence_source": "Azure denial payload",
                })
            continue
        if code_key in OTHER_BLOCKER_CODES:
            category, owner = OTHER_BLOCKER_CODES[code_key]
            if category == "Azure Policy":
                continue
            resource_id = _safe_id(node.get("target"))
            key = (code_key, resource_id)
            if key in seen:
                continue
            seen.add(key)
            other_findings.append({"status": "CONFIRMED_AZURE_NON_POLICY_ERROR", "code": code,
                                   "category": category, "resource_id": resource_id,
                                   "terraform_address": _match_plan(resource_id, changes) or (_safe_label(node.get("terraformAddress")) if not changes and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\-\[\]\"']{0,255}", str(node.get("terraformAddress", ""))) else None),
                                   "owner_to_contact": owner,
                                   "next_step": "Check the relevant operation and permission details; do not assume Azure Policy is responsible."})
            continue
        if code_key not in {"deploymentfailed", "resourcevalidationfailed", "deploymentdiagnostics", "terraformapplyfailed"} and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,90}", code):
            unclassified.append({"code": code, "status": "UNCLASSIFIED_ERROR"})
    change_summary = [{"address": c.address, "terraform_type": c.kind, "azure_type": c.azure_type,
                       "actions": list(c.actions), "name": c.proposed_name} for c in changes]
    return {"schema_version": 1, "tool": "azure-policy-bridge", "source": "azure_error" if plan is None else "terraform_plan_and_optional_azure_error",
            "verdict": "CONFIRMED_POLICY_BLOCKERS" if policy_findings else "OTHER_AZURE_BLOCKERS" if other_findings else "UNCLASSIFIED_AZURE_ERRORS" if unclassified else "UNVERIFIED_NO_DENIAL_EVIDENCE",
            "changes": change_summary,
            "confirmed_policy_denials": policy_findings,
            "other_azure_errors": other_findings,
            "unclassified_azure_errors": list({e["code"].lower(): e for e in unclassified}.values())[:30],
            "terraform_advisories": advisories,
            "evidence_gaps": (["No Azure deployment evidence supplied: any plan signals are advisory only."] if azure_errors is None else
                              ["No matching Azure Policy denial found in available diagnostics; this does not prove compliance or deployment success."] if not policy_findings else []) +
                             (["No Terraform plan supplied: resource configuration and changes were not verified."] if plan is None else []) +
                             (["No assignment inventory supplied: cannot resolve policy names, ownership or scope details."] if policy_findings and assignments is None else []),
            "trust_boundary": "The report does not grant policy exemptions, alter tenant policy, determine enterprise risk acceptance, or prove an Azure deployment would succeed."}
