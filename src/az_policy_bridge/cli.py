"""CLI for non-privileged developers diagnosing centrally-owned Azure policies."""
from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path
from .core import parse_plan, triage
from .preflight import find_candidates
from .report import markdown, json_report
from .terraform_log import parse_terraform_log


def _load(path: str | None):
    if path is None:
        return None
    p = Path(path)
    if p.stat().st_size > 25_000_000:
        raise ValueError(f"Input too large: {p.name}; reduce scope before processing")
    return json.loads(p.read_text(encoding="utf-8"))


def _write(path: str | None, data: str) -> None:
    if path is None or path == "-":
        print(data, end="")
        return
    # New report only, owner-readable, refuse overwrite/symlink follow.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fp:
        fp.write(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="az-policy-bridge", description="Explain actual Azure Policy denials against Terraform changes; produce a governance review packet.")
    parser.add_argument("plan", help="JSON from `terraform show -json tfplan` (treat input as sensitive)")
    parser.add_argument("--errors", help="Terraform apply stderr .txt OR ARM deployment error JSON")
    parser.add_argument("--assignments", help="Optional read-only Azure Policy assignment list, to enrich confirmed blockers")
    parser.add_argument("--definitions", help="Optional policy definitions snapshot for a limited non-authoritative preflight")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", help="Create a NEW private file (mode 0600); defaults to stdout")
    parser.add_argument("--fail-on", choices=("none", "confirmed", "candidate"), default="none",
                        help="CI exit 2 for confirmed Azure denials, or also static candidates")
    args = parser.parse_args(argv)
    try:
        plan = _load(args.plan)
        errors = None
        if args.errors:
            error_path = Path(args.errors)
            if error_path.stat().st_size > 5_000_000:
                raise ValueError("Error log exceeds limit")
            text = error_path.read_text(encoding="utf-8")
            try:
                errors = json.loads(text)
            except json.JSONDecodeError:
                errors = parse_terraform_log(text)
        assignments = _load(args.assignments)
        definitions = _load(args.definitions)
        if definitions is not None and assignments is None:
            raise ValueError("--definitions requires --assignments")
        report = triage(plan, errors, assignments)
        if assignments is not None and definitions is not None:
            candidates, gaps = find_candidates(parse_plan(plan), assignments, definitions)
            report["preflight_candidates"] = candidates
            report["evidence_gaps"].extend(gaps)
        else:
            report["preflight_candidates"] = []
        output = json_report(report) if args.format == "json" else markdown(report)
        if args.format == "markdown" and report["preflight_candidates"]:
            output += "\n## Offline policy candidates (NOT confirmed)\n\n"
            for item in report["preflight_candidates"]:
                output += f"- `{item['terraform_address']}` may match `{item['assignment_id']}`. **Requires Azure-side verification.**\n"
        _write(args.output, output)
        if args.fail_on == "confirmed" and report["confirmed_policy_denials"]:
            return 2
        if args.fail_on == "candidate" and (report["confirmed_policy_denials"] or report["preflight_candidates"]):
            return 2
        return 0
    except (ValueError, OSError, json.JSONDecodeError, TypeError) as exc:
        # Never echo the plan or raw Azure error which may contain secrets.
        print(f"az-policy-bridge: input/report error ({type(exc).__name__}); verify format and file permissions", file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
