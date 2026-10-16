#!/usr/bin/env bash
# Provision a fresh Mac Anisette machine and log in at once.
#
# The login must start within about 60 s of the provisioning, so both steps run in one script and the
# Apple ID and password are asked for first.
# Usage: tools/login.sh [NAME] [--2fa device|sms] [--show-password] [extra auth_probe.py args...]
#   NAME   state name; files go to /tmp/macadi/NAME, /tmp/macadi/NAME-auth and
#          /tmp/macadi/session-NAME.json (default: login3)
#   --2fa  second factor: "device" (default) takes the code from a trusted Apple device,
#          "sms" sends it to the account's first phone number
#   --show-password  show the password while you type it, to avoid a blind typo
# Example: FINDMY_KEY='<base64 private key>' tools/login.sh login3 --2fa sms --reports
set -euo pipefail

cd "$(dirname "$0")/.."

tfa=device
show=0
positional=()
while [ $# -gt 0 ]; do
  case "$1" in
    --show-password) show=1; shift ;;
    --2fa) [ $# -ge 2 ] || { echo "--2fa needs device or sms" >&2; exit 2; }; tfa="$2"; shift 2 ;;
    *) positional+=("$1"); shift ;;
  esac
done
case "$tfa" in
  device) tfa_args=() ;;
  sms) tfa_args=(--sms) ;;
  *) echo "unknown --2fa value: $tfa (use device or sms)" >&2; exit 2 ;;
esac

name="${positional[0]:-login3}"
extra=("${positional[@]:1}")

# Ask for the credentials first. A fresh machine is only accepted for about 60 s after provisioning,
# so no typing may happen between the provisioning and the login. They go to auth_probe.py in the
# environment of that one command (never argv, never a file) and it removes them once read.
if [ -z "${APPLE_ID:-}" ]; then read -r -p "Apple ID: " APPLE_ID; fi
if [ -z "${APPLE_PASSWORD:-}" ]; then
  if [ "$show" = 1 ]; then read -r -p "Password (visible): " APPLE_PASSWORD
  else read -r -s -p "Password: " APPLE_PASSWORD; echo; fi
fi
# The length shows a typo or a stray space without showing the password.
echo "Apple ID: ${#APPLE_ID} characters, password: ${#APPLE_PASSWORD} characters"

state="/tmp/macadi/$name"
rm -rf "$state" "$state-auth"
mkdir -p /tmp/macadi

.venv/bin/python tools/machoadi/mac_anisette.py provision --state "$state"
APPLE_ID="$APPLE_ID" APPLE_PASSWORD="$APPLE_PASSWORD" \
  .venv/bin/python auth_probe.py --macadi "$state" --state-dir "$state-auth" \
  ${tfa_args[@]+"${tfa_args[@]}"} \
  --save-session "/tmp/macadi/session-$name.json" ${extra[@]+"${extra[@]}"}
