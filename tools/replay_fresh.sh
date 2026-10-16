#!/usr/bin/env bash
# Replay a saved Find My token with a machine provisioned seconds ago.
#
# A 200 here, next to a 401 for the aged login machine, means the token is fine and only
# an aged machine's headers are refused. A 401 here means the token itself is rejected.
# Usage: tools/replay_fresh.sh [SESSION] [COUNT] [INTERVAL_SECONDS]
#   SESSION   file from tools/login.sh (default: /tmp/macadi/session-login3.json)
#   COUNT     requests to send (default: 4)
#   INTERVAL  seconds between requests (default: 20)
set -euo pipefail

cd "$(dirname "$0")/.."
session="${1:-/tmp/macadi/session-login3.json}"
count="${2:-4}"
interval="${3:-20}"
state="/tmp/macadi/replay-fresh"

[ -f "$session" ] || { echo "no session file: $session (run tools/login.sh first)" >&2; exit 1; }

rm -rf "$state"
.venv/bin/python tools/machoadi/mac_anisette.py provision --state "$state" >/dev/null
.venv/bin/python tools/machoadi/replay.py --state "$state" --session "$session" \
  --count "$count" --interval "$interval"
