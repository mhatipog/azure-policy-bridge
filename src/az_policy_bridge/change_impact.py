"""Read-only review of Azure Policy changes, assignments and possible workload overlap.

This is intentionally NOT a policy evaluator. Source snapshots are evidence for
review, not proof that an Azure resource will pass or fail policy enforcement.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any

_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-.+)?$")
_SEVERITY = {"review": 0, "attention": 1, "priority": 2}
_SECTIONS = ("definitions", "initiatives", "assignments")
_KEYS = {"definitions": ("definitions", "policyDefinitions"),
         "initiatives": ("initiatives", "policySetDefinitions"),
         "assignments": ("assignments", "policyAssignments")}


def _properties(row: dict[str, Any]) -> dict[str, Any]:
    return row.get("properties") if isinstance(row.get("properties"), dict) else row


def _items(snapshot: dict[str, Any], section: str) -> list[dict[str, Any]]:
    for key in _KEYS[section]:
        if key in snapshot:
            value = snapshot[key]
            if isinstance(value, dict) and isinstance(value.get("value"), list):
                value = value["value"]
            if not isinstance(value, list) or any(not isinstance(r, dict) for r in value):
                raise ValueError(f"{section} must be an array of policy objects")
            return value
    return []


def _identity(row: dict[str, Any]) -> str:
    return str(row.get("id") or row.get("name") or "").lower().rstrip("/")


def _index(rows: list[dict[str, Any]], section: str) -> dict[str, dict[str, Any]]:
    result = {}
    for row in rows:
        name = _identity(row)
        if not name or name in result:
            raise ValueError(f"{section} has missing or duplicate policy IDs")
        result[name] = row
    return result


def _value(row: dict[str, Any] | None, key: str, default: Any = None) -> Any:
    return _properties(row).get(key, default) if row else default


def _version(row: dict[str, Any] | None) -> tuple[str | None, bool]:
    if not row:
        return None, False
    props = _properties(row)
    if props.get("version"):
        return str(props["version"]), True
    meta = props.get("metadata", {})
    if isinstance(meta, dict) and meta.get("version"):
        return str(meta["version"]), False
    return None, False


def _deprecated(row: dict[str, Any] | None) -> bool:
    meta = _value(row, "metadata", {}) or {}
    return isinstance(meta, dict) and str(meta.get("deprecated", "false")).lower() == "true"


def _preview(row: dict[str, Any] | None) -> bool:
    meta = _value(row, "metadata", {}) or {}
    return isinstance(meta, dict) and str(meta.get("preview", "false")).lower() == "true"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _effects(value: Any) -> set[str]:
    """Extract static THEN effects; parameter expressions are indeterminate."""
    effects: set[str] = set()
    if isinstance(value, dict):
        then = value.get("then")
        if isinstance(then, dict) and isinstance(then.get("effect"), str):
            name = then["effect"]
            if not name.startswith("["):
                effects.add(name.lower())
        for k, v in value.items():
            if k != "then":
                effects.update(_effects(v))
    elif isinstance(value, list):
        for child in value:
            effects.update(_effects(child))
    return effects


def _types(rule: Any) -> list[str]:
    """Explicit type predicates only, NOT an actual policy scope/evaluation."""
    found: set[str] = set()
    def visit(obj: Any) -> None:
        if isinstance(obj, dict):
            if str(obj.get("field", "")).lower() == "type":
                for val in ([obj["equals"]] if "equals" in obj else obj.get("in", []) if isinstance(obj.get("in"), list) else []):
                    if isinstance(val, str) and val.lower().startswith("microsoft."):
                        found.add(val.lower())
            for val in obj.values():
                visit(val)
        elif isinstance(obj, list):
            for val in obj:
                visit(val)
    visit(rule)
    return sorted(found)


def _initiative_members(row: dict[str, Any]) -> set[str]:
    members = _value(row, "policyDefinitions", [])
    if not isinstance(members, list):
        return set()
    return {_identity({"id": r.get("policyDefinitionId")}) for r in members if isinstance(r, dict) and r.get("policyDefinitionId")}


def _related_assignments(policy_id: str, assignments: dict[str, dict[str, Any]],
                         initiatives: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    relevant = []
    for a in assignments.values():
        target = str(_value(a, "policyDefinitionId", "")).lower().rstrip("/")
        if target == policy_id or (target in initiatives and policy_id in _initiative_members(initiatives[target])):
            relevant.append(a)
    return sorted(relevant, key=_identity)


def _version_auto_ingest(selector: Any, old_version: str | None, new_version: str | None) -> str:
    """Informational; assignment selectors and overrides can limit applicability."""
    if not isinstance(selector, str) or not selector:
        return "unknown (default/version selection depends on assignment and Azure evaluation)"
    old, new = _SEMVER.match(old_version or ""), _SEMVER.match(new_version or "")
    pieces = selector.split(".")
    if not old or not new or len(pieces) != 3:
        return "unknown"
    if pieces[0].isdigit() and int(pieces[0]) != int(new.group(1)):
        return "outside configured major version"
    if pieces[1].isdigit() and int(pieces[1]) != int(new.group(2)):
        return "outside configured minor version"
    if pieces[0] == new.group(1) and pieces[1] in ("*", new.group(2)) and pieces[2] == "*":
        return "potentially auto-ingested (verify overrides/exemptions)"
    return "needs assignment-version review"


def _plan_resources(plan: dict[str, Any] | None) -> list[dict[str, str]]:
    if plan is None:
        return []
    if not isinstance(plan, dict) or not isinstance(plan.get("resource_changes", []), list):
        raise ValueError("Terraform plan must contain resource_changes array")
    out = []
    for row in plan.get("resource_changes", []):
        if not isinstance(row, dict):
            continue
        actions = (row.get("change") or {}).get("actions", [])
        if isinstance(actions, list) and actions and all(a in ("no-op", "read") for a in actions):
            continue
        resource_type = row.get("type")
        if isinstance(resource_type, str):
            out.append({"terraform_type": resource_type, "address": str(row.get("address") or "(address missing)")})
    return out


def analyse(before: dict[str, Any], after: dict[str, Any], plan: dict[str, Any] | None = None,
            type_map: dict[str, str] | None = None) -> dict[str, Any]:
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("Snapshots must be JSON objects")
    if type_map is None:
        type_map = {}
    if not isinstance(type_map, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in type_map.items()):
        raise ValueError("Type map must be an object of Terraform types to ARM resource types")
    supplied = {section: (any(k in before for k in _KEYS[section]),
                          any(k in after for k in _KEYS[section])) for section in _SECTIONS}
    old = {s: _index(_items(before, s), s) if supplied[s][0] else {} for s in _SECTIONS}
    new = {s: _index(_items(after, s), s) if supplied[s][1] else {} for s in _SECTIONS}
    resources = _plan_resources(plan)
    findings: list[dict[str, Any]] = []
    enriched_initiatives = {**old["initiatives"], **new["initiatives"]}
    enriched_assignments = {**old["assignments"], **new["assignments"]}
    # Index by target definition and expanded initiative membership once.
    # A naive per-definition scan becomes quadratic on large policy estates.
    target_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    members_index: dict[str, set[str]] = defaultdict(set)
    for initiative_id, item in old["initiatives"].items():
        for member in _initiative_members(item):
            members_index[member].add(initiative_id)
    for initiative_id, item in new["initiatives"].items():
        for member in _initiative_members(item):
            members_index[member].add(initiative_id)
    for assignment in enriched_assignments.values():
        target = str(_value(assignment, "policyDefinitionId", "")).lower().rstrip("/")
        target_index[target].append(assignment)
    gaps = []
    for section, (had_before, has_after) in supplied.items():
        if not had_before or not has_after:
            gaps.append(f"{section} missing from {'before' if not had_before else 'after'} snapshot"
                        + (" and after snapshot" if not had_before and not has_after else "")
                        + "; comparison skipped for this section.")
    if not any(supplied["assignments"]):
        gaps.append("No assignment inventory: workload applicability cannot be established.")
    if plan is not None and not type_map:
        gaps.append("Terraform type mapping not supplied: workload overlap cannot be inferred safely.")

    def emit(section: str, id_: str, changes: list[str], priority: str, resource_types: list[str] | None = None,
             old_version: str | None = None, new_version: str | None = None,
             version_authoritative: bool = True) -> None:
        if not changes:
            return
        if section == "definitions":
            by_id = {_identity(a): a for target in [id_, *sorted(members_index.get(id_, set()))]
                     for a in target_index.get(target, [])}
            related = [by_id[k] for k in sorted(by_id)]
        elif section == "initiatives":
            related = sorted(target_index.get(id_, []), key=_identity)
        else:
            related = [enriched_assignments[id_]] if id_ in enriched_assignments else []
        linked = []
        types = resource_types or []
        if plan is not None and types and type_map:
            linked = [r["address"] for r in resources if type_map.get(r["terraform_type"], "").lower() in types]
        if section == "definitions" and related:
            version_adoption = [{"assignment_id": _identity(a),
                                 "version_effect": _version_auto_ingest(_value(a, "definitionVersion"), old_version, new_version)}
                                for a in related]
        else:
            version_adoption = []
        findings.append({
            "category": section, "id": id_, "priority": priority, "changes": changes,
            "assigned_in_supplied_snapshot": bool(related),
            "related_assignment_ids": [_identity(a) for a in related],
            "resource_type_candidates": types,
            "terraform_resource_candidates": sorted(set(linked)),
            "version_before": old_version, "version_after": new_version,
            "version_field_authoritative": version_authoritative,
            "version_adoption": version_adoption,
            "guidance": "Review intended control, assignment scope, effective parameters and exclusions; validate with Azure Policy before enforcing."
        })

    for section in _SECTIONS:
        if not all(supplied[section]):
            continue
        for id_ in sorted(set(old[section]) | set(new[section])):
            was = old[section].get(id_)
            now = new[section].get(id_)
            if was is None or now is None:
                emit(section, id_, ["added to snapshot" if was is None else "removed from snapshot (may be inventory visibility)"],
                     "attention", _types(_value(now or was, "policyRule", {})))
                continue
            changes = []
            level = "review"
            ov, oa = _version(was)
            nv, na = _version(now)
            if ov != nv:
                changes.append(f"reported definition version changed: {ov or 'unknown'} → {nv or 'unknown'}")
            if _deprecated(was) != _deprecated(now):
                changes.append("deprecated flag changed (review supported replacement)")
                level = "attention"
            if _preview(was) != _preview(now):
                changes.append("preview status changed")
            if section == "definitions":
                previous_rule, current_rule = _value(was, "policyRule"), _value(now, "policyRule")
                if _canonical(previous_rule) != _canonical(current_rule):
                    changes.append("policy rule logic changed; Azure evaluation required")
                    level = "priority"
                    past, future = _effects(previous_rule), _effects(current_rule)
                    new_enforcement = (future - past) & {"deny", "denyaction", "modify", "append", "deployifnotexists"}
                    if new_enforcement:
                        changes.append("new literal enforcement effects: " + ", ".join(sorted(new_enforcement)))
                if _canonical(_value(was, "parameters")) != _canonical(_value(now, "parameters")):
                    changes.append("policy parameter schema/defaults changed")
                    level = "attention" if level == "review" else level
                types = sorted(set(_types(previous_rule) + _types(current_rule)))
            elif section == "initiatives":
                before_members = _initiative_members(was)
                after_members = _initiative_members(now)
                if before_members != after_members:
                    changes.append(f"initiative membership changed (+{len(after_members-before_members)}/-{len(before_members-after_members)})")
                    level = "priority"
                if _canonical(_value(was, "parameters")) != _canonical(_value(now, "parameters")):
                    changes.append("initiative parameter schema/defaults changed")
                    level = "attention" if level == "review" else level
                types = []
            else:
                # Deliberately do not include parameter VALUES, only property names.
                sensitive_fields = {
                    "enforcementMode": "enforcement mode", "definitionVersion": "version selection",
                    "policyDefinitionId": "target definition", "scope": "scope",
                    "parameters": "parameter values", "notScopes": "exclusions",
                    "resourceSelectors": "resource selectors", "overrides": "overrides",
                }
                for key, label in sensitive_fields.items():
                    if _canonical(_value(was, key)) != _canonical(_value(now, key)):
                        changes.append(label + " changed")
                        if key not in ("definitionVersion",):
                            level = "priority"
                types = []
            if changes:
                emit(section, id_, changes, level, types, ov, nv, oa and na)

    findings.sort(key=lambda v: (-_SEVERITY[v["priority"]], v["category"], v["id"]))
    return {
        "schema_version": "1.0", "comparison": "Azure Policy snapshot review (not policy evaluation)",
        "findings": findings, "finding_count": len(findings),
        "workload_count": len(resources),
        "evidence_gaps": gaps + ["Resource-type intersections are candidates only; tenant inheritance, assignments, exemptions, selectors, overrides and effective versions require verification."],
    }


def to_markdown(report: dict[str, Any]) -> str:
    lines = ["# Azure Policy change-impact review", "", "*Read-only advisory comparison. Not a policy pass/fail decision.*", "",
             f"**{report['finding_count']} changes** | {report['workload_count']} proposed Terraform resources inspected", ""]
    if not report["findings"]:
        lines.append("No differences detected in the **supplied snapshots**. This does not establish policy compliance or catalog freshness.")
    for f in report["findings"]:
        lines += [f"## {f['priority'].upper()} · {f['category']} · `{f['id']}`", "", *[f"- {change}" for change in f["changes"]]]
        lines.append("- Related assignments in supplied inventory: " + (", ".join(f"`{i}`" for i in f["related_assignment_ids"]) or "none identified"))
        if f["resource_type_candidates"]:
            lines.append("- Rule type references (not proven applicability): " + ", ".join(f"`{t}`" for t in f["resource_type_candidates"]))
        if f["terraform_resource_candidates"]:
            lines.append("- Possible workload intersections: " + ", ".join(f"`{x}`" for x in f["terraform_resource_candidates"]))
        for a in f["version_adoption"]:
            lines.append(f"- Assignment `{a['assignment_id']}`: {a['version_effect']}")
        lines += ["- Next: " + f["guidance"], ""]
    lines += ["## Evidence boundaries", "", *[f"- {x}" for x in report["evidence_gaps"]], ""]
    return "\n".join(lines)
