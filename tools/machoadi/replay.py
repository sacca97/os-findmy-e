#!/usr/bin/env python3
"""Replay a saved Find My token against `acsnservice` with a given machine's Anisette.

Answers two questions the login alone cannot:

* does the token still work once the machine that logged in is older than the ~60 s
  acceptance window (`--state` = that machine, `--count`/`--interval` to watch it age)?
* is the token bound to that machine at all (`--state` = a machine provisioned just now)?
* does answering Apple's resync keep the machine, and so the token, working (`--keepalive S`)?

No login happens here. The saved session holds only the dsid and the `searchPartyToken`
(see `auth_probe.py --save-session`). The request is the empty-id probe, so it asks for no
location data; it only shows whether the token and the headers are accepted.

    .venv/bin/python tools/machoadi/replay.py --state S --session FILE --count 8 --interval 60
    .venv/bin/python tools/machoadi/replay.py --state S --session FILE --count 12 --interval 30 \
        --keepalive 45 --dump-refusal

`--keepalive S` runs one credential-free resync round (resync.py: init, and on 434 synchronise,
POST, init) before the first fetch and then whenever S seconds have passed since the last one.
`--dump-refusal` prints, for any answer other than 200, the response's Apple headers and the first
bytes of its body, and says whether it carries an `X-Apple-I-MD-DATA` (a resync request from the
fetch endpoint itself); if it does, that SIM is answered and the fetch is retried once.
Machine age is seconds since *provisioning* (identity.json), not the store's mtime.
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
from mac_anisette import provisioned_at  # noqa: E402
from resync import Resyncer, sim_from_response  # noqa: E402

URL = "https://gateway.icloud.com/acsnservice/fetch"


def describe_refusal(response) -> str:  # noqa: ANN001
    apple = {k: v for k, v in dict(response.headers).items()
             if k.lower().startswith("x-apple") or k.lower() in ("www-authenticate", "content-type")}
    head = response.content[:160].decode("utf-8", "replace").replace("\n", " ")
    return f"headers={apple} body[:160]={head!r} carries_SIM={bool(sim_from_response(response))}"


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", type=Path, required=True, help="provisioned machine whose Anisette is used")
    ap.add_argument("--session", type=Path, required=True, help="file written by auth_probe.py --save-session")
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--interval", type=float, default=60.0, help="seconds between requests")
    ap.add_argument("--keepalive", type=float, default=0.0, metavar="S",
                    help="answer Apple's resync before the first fetch and every S seconds (0 = never)")
    ap.add_argument("--dump-refusal", action="store_true", help="show headers/body of every non-200 answer")
    ap.add_argument("--max-requests", type=int, default=60, help="cap on resync requests (default 60)")
    args = ap.parse_args()

    session = json.loads(args.session.read_text())
    account = make_mac_account(args.state)
    born = provisioned_at(args.state)
    resyncer = None
    if args.keepalive or args.dump_refusal:
        def forget_cached_otp() -> None:
            account._anisette._window = None  # the provider caches headers per 30 s window

        resyncer = Resyncer(args.state, max_requests=args.max_requests, on_synced=forget_cached_otp)
    last_keepalive = None
    try:
        for i in range(args.count):
            if args.keepalive and (last_keepalive is None or time.time() - last_keepalive >= args.keepalive):
                outcome = await resyncer.ensure_fresh()
                last_keepalive = time.time()
                print(f"   keepalive -> {outcome}", flush=True)
                forget_cached_otp()
            headers = await account.get_anisette_headers()
            response = await account._http.post(
                URL, auth=(session["dsid"], session["searchPartyToken"]),
                headers=headers, json=FETCH_BODIES[URL])
            if response.status_code != 200 and args.dump_refusal:
                print("   refusal:", describe_refusal(response), flush=True)
                sim = sim_from_response(response)
                if sim:
                    answered = await resyncer.answer_sim(sim)
                    forget_cached_otp()
                    response = await account._http.post(
                        URL, auth=(session["dsid"], session["searchPartyToken"]),
                        headers=await account.get_anisette_headers(), json=FETCH_BODIES[URL])
                    print(f"   answered the fetch's own SIM (ok={answered['ok']}); retry -> {response.status_code}",
                          flush=True)
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
