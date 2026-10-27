"""Extract bounded Azure error identifiers from diagnostic text without echoing logs.

Only a recognized Azure error code and the structured `Policy identifiers` array
are consumed. Never retain a raw message, URL, query string or arbitrary property.
"""
from __future__ import annotations
import json
import re
from typing import Any

ADDRESS = re.compile(r"\bwith\s+([a-zA-Z_][a-zA-Z0-9_.\-\[\]\"']+)\s*,")
POLICY_MARKER = re.compile(r"Policy identifiers\s*:\s*'?\s*", re.IGNORECASE)
CODE = re.compile(
    r"\b(RequestDisallowedByPolicy|ResourceDeniedByPolicy|PolicyViolation|"
    r"AuthorizationFailed|LinkedAuthorizationFailed|MissingSubscriptionRegistration|"
    r"SubscriptionNotRegistered|QuotaExceeded|OperationNotAllowed)\b", re.I)
ID_RE = re.compile(r"^/[\w\-.{}]+(?:/[\w\-.{}]+)+$")


def _id(value: Any) -> str | None:
    return value if isinstance(value, str) and len(value) <= 1024 and ID_RE.fullmatch(value) else None


def extract_policy_identifiers(text: Any) -> list[dict[str, Any]]:
    """Extract exact Azure policy IDs from known-format messages, discarding text.

    Parses only JSON arrays immediately after `Policy identifiers:`. The Azure
    error may contain arbitrary sensitive text elsewhere, which is never emitted.
    """
    if not isinstance(text, str) or len(text) > 1_000_000:
        return []
    found: list[dict[str, Any]] = []
    for marker in list(POLICY_MARKER.finditer(text))[:30]:
        remainder = text[marker.end():].lstrip()
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
            assignment = policy.get("policyAssignment")
            definition = policy.get("policyDefinition")
            initiative = policy.get("policySetDefinition")
            aid = _id(assignment.get("id")) if isinstance(assignment, dict) else None
            did = _id(definition.get("id")) if isinstance(definition, dict) else None
            sid = _id(initiative.get("id")) if isinstance(initiative, dict) else None
            ref = policy.get("policyDefinitionReferenceId")
            safe_ref = ref if isinstance(ref, str) and re.fullmatch(r"[\w\-.]{1,128}", ref) else None
            if aid or did:
                found.append({"policyAssignmentId": aid, "policyDefinitionId": did,
                              "policySetDefinitionId": sid, "policyDefinitionReferenceId": safe_ref})
    # Deduplicate the structured identifiers, preserving order.
    unique = []
    seen = set()
    for item in found:
        key = tuple(item.values())
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def parse_terraform_log(text: str) -> dict[str, Any]:
    if len(text) > 5_000_000:
        raise ValueError("Log exceeds 5MB; extract relevant failures locally")
    # Terraform renders either `Error:` blocks or Unicode frame blocks.
    blocks = re.split(r"(?=^\s*(?:Error:|╷))", text, flags=re.M)
    details: list[dict[str, Any]] = []
    for block in blocks:
        match = CODE.search(block)
        if not match:
            continue
        code = match.group(1)
        addresses = ADDRESS.findall(block)
        address = addresses[0] if len(set(addresses)) == 1 and addresses else None
        infos = extract_policy_identifiers(block) if code.lower() in {
            "requestdisallowedbypolicy", "resourcedeniedbypolicy", "policyviolation"} else []
        if infos:
            for info in infos:
                details.append({"code": code, "terraformAddress": address,
                                "additionalInfo": [{"type": "PolicyViolation", "info": info}]})
        else:
            details.append({"code": code, "terraformAddress": address})
    return {"error": {"code": "DeploymentDiagnostics", "details": details}}
