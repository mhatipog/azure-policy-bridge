#!/usr/bin/env bash
# Opt-in, read-only Azure CLI inventory. Store snapshots privately.
set -euo pipefail
if [[ $# -ne 1 || -z "$1" ]]; then
  echo 'Usage: bash scripts/capture-policy-snapshot.sh NEW_FILE.json' >&2
  exit 2
fi
if [[ -e "$1" ]]; then
  echo 'Output exists; choose an unused filename.' >&2
  exit 2
fi
command -v az >/dev/null || { echo 'Azure CLI is required.' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'Python 3 is required.' >&2; exit 2; }
umask 077
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
subscription=$(az account show --query id --output tsv)
if [[ -z "$subscription" ]]; then
  echo 'Select a subscription with az account set before collecting.' >&2
  exit 2
fi
az policy definition list --subscription "$subscription" --output json > "$workdir/definitions.json"
az policy set-definition list --subscription "$subscription" --output json > "$workdir/initiatives.json"
az policy assignment list --subscription "$subscription" \
  --scope "/subscriptions/$subscription" --disable-scope-strict-match true \
  --output json > "$workdir/assignments.json"
python3 - "$workdir" "$1" <<'PY'
import json
import os
from pathlib import Path
import sys
source, destination = Path(sys.argv[1]), Path(sys.argv[2])
blob = {}
for key in ("definitions", "initiatives", "assignments"):
    data = json.loads((source / (key + ".json")).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit(f"Azure CLI inventory {key} did not return an array")
    blob[key] = data
# Exclusive creation protects the previous snapshot. Full JSON is confidential.
fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    json.dump(blob, output, indent=2)
    output.write("\n")
PY
printf 'Collected read-only policy snapshot at %s (review completeness before use).\n' "$1"
