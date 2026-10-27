"""Concise deployment triage with explicit evidence levels and next actions."""
from __future__ import annotations
import json
from typing import Any


def markdown(report: dict[str, Any]) -> str:
    lines = ["# Azure deployment triage", "", f"**Diagnosis:** {report['verdict']}",
             f"**Confirmed Azure Policy denials:** {len(report['confirmed_policy_denials'])}",
             f"**Other Azure blockers:** {len(report['other_azure_errors'])}",
             f"**Changes in supplied plan:** {len(report['changes'])}", ""]
    for idx, blocker in enumerate(report['confirmed_policy_denials'], 1):
        lines.extend([f"## Blocker {idx}: Azure Policy denial", "",
                      f"- Azure code: `{blocker['code']}`",
                      f"- Assignment ID: `{blocker['assignment_id'] or 'not supplied'}`",
                      f"- Definition ID: `{blocker['policy_definition_id'] or 'not supplied'}`",
                      f"- Scope: `{blocker['assignment_scope'] or 'not supplied'}`",
                      f"- Resource ID: `{blocker['resource_id'] or 'not supplied'}`",
                      f"- Terraform address: `{blocker['terraform_address'] or 'not identified'}`",
                      f"- Address evidence: {blocker['address_evidence']}",
                      f"- Initiative reference: `{blocker['initiative_reference_id'] or 'not supplied'}`",
                      f"- Assignment display name: {blocker['assignment_name'] or 'not supplied'}", "",
                      f"**Developer action:** {blocker['developer_action']}", "",
                      f"**Policy review:** {blocker['central_decision']}", "",
                      f"**Potential impact of an exception:** {blocker['exception_risk']}", ""])
        if blocker.get('evaluation_evidence'):
            lines.append("Azure-evaluated properties (allowlisted values):")
            for item in blocker['evaluation_evidence']:
                lines.append(f"- `{item['field']}`: actual `{item.get('actual', '?')}`; expected `{item.get('required', '?')}`")
            lines.append("")
        elif blocker['assignment_id'] or blocker['policy_definition_id']:
            lines.extend(["**Verify next:** Retrieve the assignment and policy definition using the IDs above. ",
                          "The denial identifies the policy but does not by itself prove which setting needs changing.", ""])
        if blocker.get('plan_observations_not_azure_confirmed'):
            lines.append("Separate Terraform observations (not the confirmed denied predicate):")
            for item in blocker['plan_observations_not_azure_confirmed']:
                lines.append(f"- `{item['field']}` = `{item['observed_value']}` ({item['signal']})")
            lines.append("")
    if report['other_azure_errors']:
        lines.extend(["## Non-policy Azure errors", ""])
        for issue in report['other_azure_errors']:
            lines.append(f"- `{issue['code']}`: {issue['category']}. Next: {issue['next_step']}")
        lines.append("")
    if report.get('unclassified_azure_errors'):
        lines.extend(["## Errors needing further investigation", ""])
        for issue in report['unclassified_azure_errors']:
            lines.append(f"- `{issue['code']}` (not classified; inspect the original error securely)")
        lines.append("")
    if report.get('preflight_candidates'):
        lines.extend(["## Possible static policy matches (not Azure-confirmed)", ""])
        for item in report['preflight_candidates']:
            lines.append(f"- `{item['terraform_address']}` may match assignment `{item['assignment_id']}`.")
        lines.append("")
    if report['terraform_advisories']:
        lines.extend(["## Configuration observations (not policy findings)", ""])
        for item in report['terraform_advisories']:
            lines.append(f"- `{item['resource']}`: {item['signal']}. {item['suggested_action']}")
        lines.append("")
    if report['evidence_gaps']:
        lines.extend(["## Evidence still needed", ""])
        lines.extend(f"- {gap}" for gap in dict.fromkeys(report['evidence_gaps']))
        lines.append("")
    if report['confirmed_policy_denials']:
        lines.extend(["## Review checklist", "",
                      "Confirm the evaluated rule and permitted deployment pattern first. If a deviation is requested,",
                      "document the exact affected resources, reason, scope, data sensitivity, accountable approver,",
                      "duration, compensating controls and rollback. This report grants no exceptions.", ""])
    lines.extend([f"> {report['trust_boundary']}", ""])
    return "\n".join(lines)


def json_report(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2) + "\n"
