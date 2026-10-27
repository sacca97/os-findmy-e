#!/usr/bin/env python3
"""Pin the escrow-recovery SRP (`findmy/keychain/recovery.py`) to fixed inputs.

    python app/tools/oracle/recovery_srp_vectors.py

Recovery is *standard* SRP-6a (identity included in `x`), unlike Grand Slam. That flag is a
process-global in pysrp, so the login vectors do not cover it. This records `A` and `M1` for a fixed
secret and a fixed challenge, so the Rust `SrpClient::new_standard` can be compared exactly.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "app/android/app/src/test/resources/fixtures/keychain"

import srp._pysrp as srp  # noqa: E402

PASSCODE = "123456"
DSID = "1234567890"
# `secrets.token_bytes(32).rjust(256, b"\x00")`: the 32 random bytes are the *low* end.
SECRET = bytes(range(32))
PADDED = SECRET.rjust(256, b"\x00")
SALT = bytes(range(16))
# Any value below N works as the server's public; use a realistic 256-byte one.
SERVER_PUBLIC = bytes((0x11 + i) % 256 for i in range(256))

CASES = [("fixed", SALT, SERVER_PUBLIC)]


def main() -> int:
    # `findmy.reports.account` enables RFC 5054 mode at import; recovery relies on it being set. Do it
    # explicitly so this oracle does not silently use pysrp's unpadded default.
    srp.rfc5054_enable()
    previous = srp._no_username_in_x  # noqa: SLF001
    srp.no_username_in_x(False)  # recovery includes the identity
    try:
        results = []
        for name, salt, server_public in CASES:
            user = srp.User("", PASSCODE, hash_alg=srp.SHA256, ng_type=srp.NG_2048, bytes_a=PADDED)
            _, client_public = user.start_authentication()
            user.I = DSID
            proof = user.process_challenge(salt, server_public)
            results.append({
                "name": name,
                "salt": salt.hex(),
                "server_public": server_public.hex(),
                "password": PASSCODE,
                "identity": DSID,
                "secret": SECRET.hex(),
                "client_public": client_public.hex(),
                "proof": proof.hex(),
            })
    finally:
        srp.no_username_in_x(previous)  # noqa: SLF001

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "recovery_srp.json").write_text(json.dumps({"cases": results}, indent=1, sort_keys=True) + "\n")
    print("wrote", OUT / "recovery_srp.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
