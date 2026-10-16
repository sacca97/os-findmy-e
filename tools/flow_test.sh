#!/usr/bin/env bash
# The whole experiment in one run: enroll, log in, then watch whether the token keeps working.
#
#   1. provision a fresh machine ("enrollment") and log in at once, with SMS for 2FA;
#   2. for WATCH seconds, send the same Find My request every INTERVAL s through the live
#      account, a clean one holding only the saved token, a bad-token control, and (after 40 s)
#      a second machine provisioned then;
#   3. replay the saved token with a second, freshly provisioned machine.
#
# Usage: [FINDMY_KEY='<base64 private key>'] tools/flow_test.sh [--2fa device|sms] [--request-push] [--show-password] [NAME] [WATCH_SECONDS] [INTERVAL_SECONDS]
#   --2fa  second factor: "device" (default) takes the code from a trusted Apple device,
#          "sms" sends it to the account's first phone number
#   --request-push  with --2fa device, ask Apple to send the prompt again and print its answer
#   defaults: NAME=flow, WATCH_SECONDS=120, INTERVAL_SECONDS=5
# Reading the output:
#   live 200, clean 401 ........ the token needs the live session; a saved token alone is not enough
#   all 200, then all 401 ...... the machine window also limits fetches (note the age at the flip)
#   other 200 after the flip ... the token outlives its machine: one login plus a fresh machine per fetch works
#   other 401 after the flip ... the token dies with the machine that logged in
#   both 200 throughout ........ the token is fine; replay.py is at fault
#   step 2 200 / step 2 401 .... the token is not / is bound to the machine that logged in
set -euo pipefail

cd "$(dirname "$0")/.."
tfa=device
positional=()
extra=()
while [ $# -gt 0 ]; do
  case "$1" in
    --request-push) extra+=(--request-push); shift ;;
    --show-password) extra+=(--show-password); shift ;;
    --2fa) [ $# -ge 2 ] || { echo "--2fa needs device or sms" >&2; exit 2; }; tfa="$2"; shift 2 ;;
    *) positional+=("$1"); shift ;;
  esac
done
name="${positional[0]:-flow}"
watch="${positional[1]:-120}"
interval="${positional[2]:-5}"

# With FINDMY_KEY set (base64 private key of one of your own tags), also fetch its reports.
[ -n "${FINDMY_KEY:-}" ] && extra+=(--reports)

echo "== 1/2  enrol and log in, then watch for ${watch}s every ${interval}s"
tools/login.sh "$name" --2fa "$tfa" --watch "$watch" --watch-interval "$interval" ${extra[@]+"${extra[@]}"}

echo
echo "== 2/2  same token, second machine provisioned just now"
tools/replay_fresh.sh "/tmp/macadi/session-$name.json" 4 "$interval"
