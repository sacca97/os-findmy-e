#!/bin/sh
# Byte-for-byte check: the Rust core against the Python harness, same store, same pinned clock.
#   native/compare.sh COREADI_FILE STATE_DIR
# STATE_DIR is a provisioned state in the Python layout (identity.json, store/). It is copied, so
# neither side modifies it. Run from the repository root.
set -eu
dylib=$1; state=$2
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cp -r "$state" "$tmp/py"; cp -r "$state" "$tmp/rs"
py=${PYTHON:-.venv/bin/python}
COREADI_PATH=$dylib ADI_FROZEN_TIME=1 "$py" - "$tmp/py" > "$tmp/py.out" <<'PY'
import sys
sys.path.insert(0, "tools/machoadi")
from pathlib import Path
import mac_anisette
a = mac_anisette.MacAnisette(Path(sys.argv[1])); a._ensure_initialized()
o = a.adi.request_otp(-2)
print("mid=" + o.outputs["mid"].hex()); print("otp=" + o.outputs["otp"].hex())
PY
(cd native/adi-core && cargo build --release -q)
native/adi-core/target/release/adi-cli --dylib "$dylib" --state "$tmp/rs" --frozen 1700000000 --repeat "${REPEAT:-50}" 2>/dev/null > "$tmp/rs.out"
if cmp -s "$tmp/py.out" "$tmp/rs.out"; then echo "identical:"; cat "$tmp/rs.out" | cut -c1-72; else echo MISMATCH; diff "$tmp/py.out" "$tmp/rs.out"; exit 1; fi
