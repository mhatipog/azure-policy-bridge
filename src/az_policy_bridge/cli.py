"""Small, read-only CLI for reviewing changes in Azure Policy inventories."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from . import __version__
from .change_impact import analyse, to_markdown


def _read_json(path: str, max_bytes: int = 100_000_000):
    source = Path(path)
    if source.stat().st_size > max_bytes:
        raise ValueError("input exceeds the configured size limit")
    with source.open(encoding="utf-8") as handle:
        value = json.load(handle)
    return value


def _write(path: str | None, content: str) -> None:
    if not path or path == "-":
        sys.stdout.write(content)
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)


def main(argv: list[str] | None = None) -> int:
    args_list = sys.argv[1:] if argv is None else list(argv)
    # Preserve the published command while allowing a simpler direct invocation.
    if args_list and args_list[0] == "changes":
        args_list = args_list[1:]
    parser = argparse.ArgumentParser(
        prog="az-policy-bridge",
        description="Review Azure Policy inventory changes, optionally against Terraform resource types.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--before", required=True, help="Previous policy snapshot JSON")
    parser.add_argument("--after", required=True, help="Current policy snapshot JSON")
    parser.add_argument("--plan", help="Optional Terraform show -json plan; may contain secrets")
    parser.add_argument("--type-map", help="Optional explicit Terraform-to-ARM resource type map")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", help="New, owner-only output file; stdout by default")
    args = parser.parse_args(args_list)
    try:
        report = analyse(
            _read_json(args.before), _read_json(args.after),
            _read_json(args.plan) if args.plan else None,
            _read_json(args.type_map) if args.type_map else None,
        )
        output = (json.dumps(report, indent=2, sort_keys=True) + "\n"
                  if args.format == "json" else to_markdown(report))
        _write(args.output, output)
        return 0  # An advisory review, never an Azure compliance gate.
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        # Avoid echoing possibly sensitive paths or input values into CI logs.
        print(f"az-policy-bridge: review failed ({type(exc).__name__}); check inputs and permissions", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
