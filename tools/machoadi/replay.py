#!/usr/bin/env python3
"""Replay a saved Find My token against `acsnservice` with a given machine's Anisette.

Answers two questions the login alone cannot:

* does the token still work once the machine that logged in is older than the ~60 s
  acceptance window (`--state` = that machine, `--count`/`--interval` to watch it age)?
* is the token bound to that machine at all (`--state` = a machine provisioned just now)?

No login happens here. The saved session holds only the dsid and the `searchPartyToken`
(see `auth_probe.py --save-session`). The request is the empty-id probe, so it asks for no
location data; it only shows whether the token and the headers are accepted.

    .venv/bin/python tools/machoadi/replay.py --state S --session FILE --count 8 --interval 60
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools" / "machoadi"))

from auth_probe import FETCH_BODIES, make_mac_account  # noqa: E402

URL = "https://gateway.icloud.com/acsnservice/fetch"


def provisioned_at(state: Path) -> float:
    """Unix time the store was written: the clock the 60 s window runs on."""
    return max(p.stat().st_mtime for p in (state / "store").glob("adi*.pb"))


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", type=Path, required=True, help="provisioned machine whose Anisette is used")
    ap.add_argument("--session", type=Path, required=True, help="file written by auth_probe.py --save-session")
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--interval", type=float, default=60.0, help="seconds between requests")
    args = ap.parse_args()

    session = json.loads(args.session.read_text())
    account = make_mac_account(args.state)
    born = provisioned_at(args.state)
    try:
        for i in range(args.count):
            headers = await account.get_anisette_headers()
            response = await account._http.post(
                URL, auth=(session["dsid"], session["searchPartyToken"]),
                headers=headers, json=FETCH_BODIES[URL])
            age = time.time() - born
            # Control: the same request with the last token character changed. It has to be 401.
            token = session["searchPartyToken"]
            bad = await account._http.post(
                URL, auth=(session["dsid"], token[:-1] + ("A" if token[-1] != "A" else "B")),
                headers=await account.get_anisette_headers(), json=FETCH_BODIES[URL])
            print(f"machine age {age:7.0f} s   acsnservice -> {response.status_code}  {len(response.content)} bytes"
                  f"   (bad-token control -> {bad.status_code})", flush=True)
            if i + 1 < args.count:
                await asyncio.sleep(args.interval)
    finally:
        await account.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
