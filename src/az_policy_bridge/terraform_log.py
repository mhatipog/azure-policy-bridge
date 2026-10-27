"""Extract structured identifiers from Terraform's ordinary stderr without publishing logs.

Typical AzureRM errors contain `Policy identifiers: '[{"policyAssignment":...}]'`.
Only bounded JSON arrays after this exact marker are parsed. Other message text is
never included in results. This is a parser for error evidence, not an evaluator.
"""
from __future__ import annotations
import json
import re
from typing import Any

# There may be multiple `Error:` blocks in a single apply failure.
ADDRESS = re.compile(r"\bwith\s+([a-zA-Z_][a-zA-Z0-9_.\-\[\]\"']+)\s*,")
POLICY_MARKER = re.compile(r"Policy identifiers\s*:\s*'?\s*", re.IGNORECASE)
CODE = re.compile(r"\b(RequestDisallowedByPolicy|ResourceDeniedByPolicy|AuthorizationFailed|LinkedAuthorizationFailed)\b", re.I)
ID_RE = re.compile(r"^/[\w\-.{}]+(?:/[\w\-.{}]+)+$")


def _id(value: Any) -> str | None:
    return value if isinstance(value, str) and len(value) <= 1024 and ID_RE.fullmatch(value) else None


def parse_terraform_log(text: str) -> dict:
    if len(text) > 5_000_000:
        raise ValueError("Log exceeds 5MB; extract the relevant failure blocks locally")
    blocks = re.split(r"(?=^\s*(?:Error:|╷))", text, flags=re.M)
    details = []
    for block in blocks:
        match = CODE.search(block)
        if not match:
            continue
        code = match.group(1)
        address_matches = ADDRESS.findall(block)
        address = address_matches[-1] if len(set(address_matches)) == 1 else None
        if code.lower() == "requestdisallowedbypolicy" or code.lower() == "resourcedeniedbypolicy":
            markers = list(POLICY_MARKER.finditer(block))
            extracted = False
            for marker in markers[:30]:
                remainder = block[marker.end():].lstrip()
                if not remainder.startswith("["):
                    continue
                try:
                    data, _ = json.JSONDecoder().raw_decode(remainder)
                except (ValueError, TypeError):
                    continue
                if not isinstance(data, list):
                    continue
                for policy in data[:60]:
                    if not isinstance(policy, dict):
                        continue
                    assignment = policy.get("policyAssignment", {})
                    definition = policy.get("policyDefinition", {})
                    initiative = policy.get("policySetDefinition", {})
                    if not isinstance(assignment, dict) or not isinstance(definition, dict):
                        continue
                    info = {"policyAssignmentId": _id(assignment.get("id")),
                            "policyDefinitionId": _id(definition.get("id")),
                            "policySetDefinitionId": _id(initiative.get("id")) if isinstance(initiative, dict) else None,
                            "policyDefinitionReferenceId": policy.get("policyDefinitionReferenceId")}
                    if not info["policyAssignmentId"] and not info["policyDefinitionId"]:
                        continue
                    details.append({"code": code, "terraformAddress": address,
                                    "additionalInfo": [{"type": "PolicyViolation", "info": info}]})
                    extracted = True
            if not extracted:
                # Confirm denial code from AzureRM text, not assignment identity.
                details.append({"code": code, "terraformAddress": address})
        else:
            details.append({"code": code, "terraformAddress": address})
    return {"error": {"code": "TerraformApplyFailed", "details": details}}
