#!/usr/bin/env bash
# Use a SAVED login: no Apple ID prompt, no password prompt at login, no 2FA code.
#
# Usage: tools/restored_run.sh STATE [--tags [--tags-list] [--tags-save FILE]]
#   STATE-login.json is written by tools/aged_login.sh (a credential: tokens + password, mode 0600).
# It first checks the machine (answering Apple's resync if needed) and that the saved token still works
# (one request); if either fails it says so and stops. --tags asks for the passcode as before.
set -euo pipefail
cd "$(dirname "$0")/.."
state="${1:?usage: tools/restored_run.sh STATE [--tags ...]}"; shift
login="$state-login.json"
[ -f "$login" ] || { echo "no $login: log in once with tools/aged_login.sh $state" >&2; exit 1; }
.venv/bin/python tools/machoadi/cooldown.py
.venv/bin/python auth_probe.py --macadi "$state" --state-dir "$state-auth" --auto-resync \
  --restore-login "$login" "$@"
