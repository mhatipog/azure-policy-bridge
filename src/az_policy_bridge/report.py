"""Human-readable, safe-to-share-as-reviewed summary of governance blockers."""
from __future__ import annotations
import json
from typing import Any


def markdown(report: dict[str, Any]) -> str:
    lines = ["# Azure deployment governance triage", "", f"**Status:** {report['verdict']}",
             f"**Planned resources changed:** {len(report['changes'])}",
             f"**Azure policy denials (evidence-based):** {len(report['confirmed_policy_denials'])}",
             f"**Other Azure blockers:** {len(report['other_azure_errors'])}",
             f"**Terraform-only advisory signals:** {len(report['terraform_advisories'])}", ""]
    for n, blocker in enumerate(report['confirmed_policy_denials'], 1):
        lines += [f"## Confirmed policy blocker {n}", "",
                  f"- Azure error: `{blocker['code']}`",
                  f"- Resource: `{blocker['resource_id'] or 'not provided'}`",
                  f"- Terraform: `{blocker['terraform_address'] or 'not linked uniquely'}`",
                  f"- Assignment: `{blocker['assignment_id'] or 'not provided'}`",
                  f"- Assignment name: {blocker['assignment_name'] or 'not available'}",
                  f"- Scope: `{blocker['assignment_scope'] or 'not available'}`",
                  f"- Definition: `{blocker['policy_definition_id'] or 'not provided'}`",
                  f"- Initiative reference: `{blocker['initiative_reference_id'] or 'not provided'}`",
                  f"- **Business developer:** {blocker['developer_action']}",
                  f"- **Central team:** {blocker['central_decision']}",
                  f"- Contact / ownership: {blocker['governance_owner']}",
                  f"- **Risk if bypassed:** {blocker['exception_risk']}", ""]
        if blocker['evaluation_evidence']:
            lines.append("Azure evaluation evidence (allowlisted fields only):")
            for e in blocker['evaluation_evidence']:
                lines.append(f"- `{e['field']}`: observed `{e.get('actual', '?')}`, expected `{e.get('required', '?')}`")
            lines.append("")
    if report['other_azure_errors']:
        lines.extend(["## Other Azure failures (not Azure Policy)", ""])
        for e in report['other_azure_errors']:
            lines.append(f"- **{e['code']}** — {e['category']}; contact: {e['owner_to_contact']}")
        lines.append("")
    if report['terraform_advisories']:
        lines.extend(["## Proposed design risks (NOT policy denials)", ""])
        for e in report['terraform_advisories']:
            lines.append(f"- `{e['resource']}`: {e['signal']}; {e['suggested_action']}")
        lines.append("")
    if report['evidence_gaps']:
        lines.extend(["## Missing evidence", ""])
        lines += [f"- {gap}" for gap in report['evidence_gaps']]
        lines.append("")
    lines += ["## Central-cloud review request", "",
              "Before requesting an exemption, ask for the supported landing-zone pattern and explain why it cannot meet the business requirement.",
              "If an exception is still proposed, supply: business purpose, precise resource IDs and scope, data classification, risk owner, duration/expiry, network and identity controls, monitoring, and a documented rollback.",
              "**An exemption is a central governance decision, never an automated recommendation to disable security.**", "",
              f"> {report['trust_boundary']}", ""]
    return "\n".join(lines)


def json_report(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2) + "\n"
