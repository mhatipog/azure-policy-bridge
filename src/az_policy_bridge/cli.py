"""Offline, evidence-first Azure deployment error diagnosis."""
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


def _text(path: str, limit: int) -> str:
    if path == "-":
        # Bounded streaming read so pasted logs cannot consume unlimited memory.
        data = sys.stdin.read(limit + 1)
    else:
        p = Path(path)
        if p.stat().st_size > limit:
            raise ValueError("Input exceeds size limit")
        data = p.read_text(encoding="utf-8")
    if len(data.encode("utf-8")) > limit:
        raise ValueError("Input exceeds size limit")
    return data


def _load(path: str | None, limit: int = 25_000_000):
    return json.loads(_text(path, limit)) if path is not None else None


def _write(path: str | None, data: str) -> None:
    if path is None or path == "-":
        print(data, end="")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fp:
        fp.write(data)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "changes":
        return _changes_main(argv[1:])
    parser = argparse.ArgumentParser(
        prog="az-policy-bridge",
        description="Explain Azure deployment failures from Terraform logs or ARM/Bicep JSON; optionally enrich with a plan.")
    parser.add_argument("plan", nargs="?", help="Optional Terraform plan JSON. Handle as sensitive. Use '-' for stdin.")
    parser.add_argument("--errors", help="Azure diagnostic JSON or Terraform stderr; '-' to read piped/pasted stdin")
    parser.add_argument("--assignments", help="Optional read-only policy assignment snapshot")
    parser.add_argument("--definitions", help="Optional policy definition snapshot for limited advisory preflight")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", help="Create a new owner-readable file (0600), or stdout by default")
    parser.add_argument("--fail-on", choices=("none", "confirmed", "candidate"), default="none",
                        help="Exit 2 if confirmed denial or, optionally, a static advisory candidate is present")
    args = parser.parse_args(argv)
    try:
        if not args.plan and not args.errors:
            parser.error("Provide --errors PATH or a Terraform plan JSON")
        if args.plan == "-" and args.errors == "-":
            raise ValueError("Only one input may consume stdin")
        plan = _load(args.plan)
        errors = None
        if args.errors:
            error_text = _text(args.errors, 5_000_000)
            try:
                errors = json.loads(error_text)
            except json.JSONDecodeError:
                errors = parse_terraform_log(error_text)
        assignments = _load(args.assignments)
        definitions = _load(args.definitions)
        if definitions is not None and assignments is None:
            raise ValueError("Policy definitions require assignments")
        report = triage(plan, errors, assignments)
        if assignments is not None and definitions is not None and plan is not None:
            candidates, gaps = find_candidates(parse_plan(plan), assignments, definitions)
            report["preflight_candidates"] = candidates
            report["evidence_gaps"].extend(gaps)
        else:
            report["preflight_candidates"] = []
            if definitions is not None and plan is None:
                report["evidence_gaps"].append("Policy preflight needs a Terraform plan; error diagnosis was still performed.")
        output = json_report(report) if args.format == "json" else markdown(report)
        _write(args.output, output)
        if args.fail_on == "confirmed" and report["confirmed_policy_denials"]:
            return 2
        if args.fail_on == "candidate" and (report["confirmed_policy_denials"] or report["preflight_candidates"]):
            return 2
        return 0
    except (ValueError, OSError, json.JSONDecodeError, TypeError, UnicodeError) as exc:
        # Do not surface error text: input paths and Azure messages can be sensitive.
        print(f"az-policy-bridge: input/report error ({type(exc).__name__}); check input and permissions", file=sys.stderr)
        return 3


def _changes_main(argv: list[str]) -> int:
    from .change_impact import analyse, to_markdown
    parser = argparse.ArgumentParser(prog="az-policy-bridge changes",
                    description="Compare Azure Policy snapshots and show advisory change impact (read-only).")
    parser.add_argument("--before", required=True, help="Previous policy inventory JSON")
    parser.add_argument("--after", required=True, help="Current policy inventory JSON")
    parser.add_argument("--plan", help="Optional Terraform show -json plan (may contain secrets)")
    parser.add_argument("--type-map", help="Explicit Terraform-to-ARM type mapping JSON")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", help="Create owner-only new report file, defaults to stdout")
    args = parser.parse_args(argv)
    try:
        before, after = _load(args.before), _load(args.after)
        plan = _load(args.plan) if args.plan else None
        types = _load(args.type_map) if args.type_map else None
        report = analyse(before, after, plan, types)
        result = json.dumps(report, indent=2, sort_keys=True) + "\n" if args.format == "json" else to_markdown(report)
        _write(args.output, result)
        return 0  # Advisory only, cannot prove compliance or block deployment.
    except (ValueError, OSError, json.JSONDecodeError, TypeError, UnicodeError) as exc:
        print(f"az-policy-bridge: change-review error ({type(exc).__name__}); check input and permissions", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
