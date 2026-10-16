#!/usr/bin/env bash
# Replay the saved token with the machine that logged in (NOT a new machine: EVIDENCE.md section 6 showed a
# token only works with its own machine's headers), answering resync between fetches.
# Usage: tools/replay_aged.sh STATE [COUNT] [INTERVAL_S] [KEEPALIVE_S]
#   defaults: COUNT=12  INTERVAL=30  KEEPALIVE=45 (0 = never resync; shows the bare lease)
# Prints machine age (seconds since provisioning) per fetch, the bad-token control (must be 401),
# and for any non-200 the headers/body and whether the fetch itself carries a SIM.
set -euo pipefail
cd "$(dirname "$0")/.."
state="${1:?usage: tools/replay_aged.sh STATE [COUNT] [INTERVAL] [KEEPALIVE]}"
session="$state-session.json"
[ -f "$session" ] || { echo "no $session: run tools/aged_login.sh $state first" >&2; exit 1; }
.venv/bin/python tools/machoadi/cooldown.py
.venv/bin/python tools/machoadi/replay.py --state "$state" --session "$session" \
  --count "${2:-12}" --interval "${3:-30}" --keepalive "${4:-45}" --dump-refusal
