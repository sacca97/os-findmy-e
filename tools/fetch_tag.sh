#!/usr/bin/env bash
# Fetch the location reports of one of your own tags with the saved token of STATE's machine.
# Usage: tools/fetch_tag.sh STATE [--summary] [--days N] [--dry-run]
# The private key (base64) is asked for here, hidden, and lives only in this process's environment.
set -euo pipefail
cd "$(dirname "$0")/.."
state="${1:?usage: tools/fetch_tag.sh STATE [--summary] [--days N] [--dry-run]}"; shift
if [ -z "${FINDMY_KEY:-}" ]; then read -r -s -p "Tag private key (base64, hidden): " FINDMY_KEY; echo; fi
echo "key: ${#FINDMY_KEY} characters"
FINDMY_KEY="$FINDMY_KEY" \
  .venv/bin/python tools/machoadi/fetch_reports.py --state "$state" "$@"
