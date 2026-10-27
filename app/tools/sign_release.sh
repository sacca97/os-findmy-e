#!/usr/bin/env bash
# Signs app-release-unsigned.apk with the release key kept OUTSIDE the repository.
# Key material: $OPENFINDER_SIGNING_DIR (default ~/.android/openfinder-release) with release.keystore and signing.properties
# (storePassword=, keyAlias=, keyPassword=). Never commit either file. Usage: app/tools/sign_release.sh [apksigner build-tools dir]
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
dir="${OPENFINDER_SIGNING_DIR:-$HOME/.android/openfinder-release}"
bt="${1:-$(ls -d "$HOME"/Android/Sdk/build-tools/* | sort -V | tail -1)}"
out="$root/app/android/app/build/outputs/apk/release"
prop() { grep "^$1=" "$dir/signing.properties" | cut -d= -f2-; }
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
"$bt/zipalign" -f -p 4 "$out/app-release-unsigned.apk" "$tmp/aligned.apk"
"$bt/apksigner" sign --ks "$dir/release.keystore" --ks-pass "pass:$(prop storePassword)" --ks-key-alias "$(prop keyAlias)" \
  --key-pass "pass:$(prop keyPassword)" --out "$out/openfinder-release.apk" "$tmp/aligned.apk"
"$bt/apksigner" verify --print-certs "$out/openfinder-release.apk" 2>/dev/null | grep 'SHA-256'
echo "$out/openfinder-release.apk"
