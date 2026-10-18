#!/bin/sh
# Stateful byte-for-byte check of the Rust core against the Python harness.
#   native/compare.sh COREADI_FILE STATE_DIR
# Runs N sessions (default 60) with a pinned clock that advances 30 s per session. The Python side
# builds a fresh CoreADI per session (a new process, as akd does); the Rust side is one long-lived
# process that resets between sessions. Every MID, OTP, routing value and the store hash after each
# session must match. STATE_DIR (a provisioned state in the Python layout) is copied, not modified.
# Run from any directory; PYTHON overrides the interpreter.
set -eu
if [ "$#" -ne 2 ]; then
  echo "Usage: native/compare.sh COREADI_FILE STATE_DIR" >&2
  exit 2
fi
dylib=$1; state=$2; n=${REPEAT:-60}
case "$dylib" in /*) ;; *) dylib="$PWD/$dylib" ;; esac
case "$state" in /*) ;; *) state="$PWD/$state" ;; esac
repo_root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cp -r "$state" "$tmp/py"; cp -r "$state" "$tmp/rs"
py=${PYTHON:-.venv/bin/python}
if [ ! -x "$py" ] && ! command -v "$py" >/dev/null 2>&1; then
  echo "Python interpreter not found: $py (set PYTHON to its path)" >&2
  exit 2
fi
COREADI_PATH=$dylib "$py" - "$tmp/py" "$n" > "$tmp/py.out" <<'PY'
import hashlib, sys
sys.path.insert(0, "tools/machoadi")
from pathlib import Path
import stubs, mac_anisette
state, n = Path(sys.argv[1]), int(sys.argv[2])
for i in range(n):
    t = 1700000000 + 30 * i
    stubs.time.time = lambda t=t: float(t)
    a = mac_anisette.MacAnisette(state)
    a._ensure_initialized()
    assert a.is_provisioned()
    o = a.adi.request_otp(-2)
    routing = a.adi.get_routing(-2).outputs["routing"]
    a._save_store()
    h = hashlib.sha256()
    for k, v in sorted(a.adi.stubs.files.items()):
        h.update(k.encode()); h.update(bytes(v))
    print(f"t={t} mid={o.outputs['mid'].hex()} otp={o.outputs['otp'].hex()} routing={routing} store={h.hexdigest()}")
PY
(cd native/adi-core && cargo build --release -q)
native/target/release/adi-cli --dylib "$dylib" --state "$tmp/rs" --frozen 1700000000 --step 30 --repeat "$n" --all 2>/dev/null > "$tmp/rs.out"
if cmp -s "$tmp/py.out" "$tmp/rs.out"; then echo "identical over $n sessions; last line:"; tail -1 "$tmp/rs.out" | cut -c1-110
else echo MISMATCH; diff "$tmp/py.out" "$tmp/rs.out" | head -6; exit 1; fi
