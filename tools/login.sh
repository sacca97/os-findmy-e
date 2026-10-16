#!/usr/bin/env bash
# Provision a fresh Mac Anisette machine and log in at once.
#
# The login must start within about 60 s of the provisioning, so both steps run in one script.
# Usage: tools/login.sh [NAME] [extra auth_probe.py args...]
#   NAME   state name; files go to /tmp/macadi/NAME, /tmp/macadi/NAME-auth and
#          /tmp/macadi/session-NAME.json (default: login3)
# Example: FINDMY_KEY='<base64 private key>' tools/login.sh login3 --reports
set -euo pipefail

cd "$(dirname "$0")/.."
name="${1:-login3}"
[ $# -gt 0 ] && shift

state="/tmp/macadi/$name"
rm -rf "$state" "$state-auth"
mkdir -p /tmp/macadi

.venv/bin/python tools/machoadi/mac_anisette.py provision --state "$state"
.venv/bin/python auth_probe.py --macadi "$state" --state-dir "$state-auth" --sms \
  --save-session "/tmp/macadi/session-$name.json" "$@"
