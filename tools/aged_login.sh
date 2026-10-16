#!/usr/bin/env bash
# Log in on an EXISTING machine (never provisions), answering Apple's resync on the way.
#
#   preflight: a credential-free init; on 434 it synchronises first, so no password attempt is
#              spent on a machine Apple would refuse (auth_probe.py aborts if it is still refused);
#   login:     any 434 during the login is answered and the request repeated;
#   2FA:       the machine is renewed again right after you type the code and before it is submitted.
#
# Usage: tools/aged_login.sh STATE [--2fa device|sms] [--show-password] [--no-save-login] [extra auth_probe args]
#   The login is SAVED by default to STATE-login.json (0600, a credential: tokens + password) so that
#   tools/restored_run.sh can use it with no new login and no 2FA. --no-save-login disables that.
#   STATE  an already provisioned machine, e.g. /tmp/macadi/age1 (or rt1 from age_check.py)
# Files: STATE-auth (login state) and STATE-session.json (0600: dsid + searchPartyToken, no password).
# Then:  tools/replay_aged.sh STATE
set -euo pipefail
cd "$(dirname "$0")/.."

state="${1:?usage: tools/aged_login.sh STATE [--2fa device|sms]}"; shift
[ -f "$state/identity.json" ] || { echo "$state is not a provisioned machine" >&2; exit 2; }
.venv/bin/python tools/machoadi/cooldown.py
tfa=device; show=0; extra=(); save=1
while [ $# -gt 0 ]; do
  case "$1" in
    --show-password) show=1; shift ;;
    --no-save-login) save=0; shift ;;
    --2fa) [ $# -ge 2 ] || { echo "--2fa needs device or sms" >&2; exit 2; }; tfa="$2"; shift 2 ;;
    *) extra+=("$1"); shift ;;
  esac
done
case "$tfa" in device) tfa_args=() ;; sms) tfa_args=(--sms) ;; *) echo "bad --2fa: $tfa" >&2; exit 2 ;; esac

# Credentials first, in this process's environment only (never argv, never a file).
if [ -z "${APPLE_ID:-}" ]; then read -r -p "Apple ID: " APPLE_ID; fi
if [ -z "${APPLE_PASSWORD:-}" ]; then
  if [ "$show" = 1 ]; then read -r -p "Password (visible): " APPLE_PASSWORD
  else read -r -s -p "Password: " APPLE_PASSWORD; echo; fi
fi
echo "Apple ID: ${#APPLE_ID} characters, password: ${#APPLE_PASSWORD} characters"
if [ -n "${ADI_FROZEN_TIME:-}" ]; then echo "clock: FROZEN (old behaviour)"; else echo "clock: real"; fi
[ "$save" = 1 ] && extra+=(--save-login "$state-login.json")

rm -rf "$state-auth"
APPLE_ID="$APPLE_ID" APPLE_PASSWORD="$APPLE_PASSWORD" \
  .venv/bin/python auth_probe.py --macadi "$state" --state-dir "$state-auth" --auto-resync \
  ${tfa_args[@]+"${tfa_args[@]}"} --save-session "$state-session.json" ${extra[@]+"${extra[@]}"}
