#!/usr/bin/env python3
"""Fetch and decrypt the location reports of ONE of your own tags, with a saved token and its machine.

No login happens here. It uses what `tools/aged_login.sh` (or `login.sh`) left behind:

  * the machine state (identity + CoreADI store): its headers are the only ones the token works with
    (EVIDENCE.md section 6), so the state that logged in must be passed;
  * `<state>-session.json`: dsid + searchPartyToken.

The tag's private key is read from the environment, never argv and never a file:

    read -rs FINDMY_KEY; export FINDMY_KEY      # paste the base64 private key (28 bytes), Enter
    ADI_REAL_TIME=1 .venv/bin/python tools/machoadi/fetch_reports.py --state /tmp/macadi/rt1 --dry-run
    ADI_REAL_TIME=1 .venv/bin/python tools/machoadi/fetch_reports.py --state /tmp/macadi/rt1

The request is exactly the library's own (`AsyncAppleAccount.fetch_raw_reports`): POST
`findmyservice/v2/fetch` with the hashed advertisement key as a primary id and a start/end window, auth
(dsid, searchPartyToken), the machine's Anisette headers. Empty 200s are retried (FindMy.py#185). Anything
other than 200 is dumped (Apple's headers and the first bytes of the body; whether it carries an
`X-Apple-I-MD-DATA`, i.e. a resync request) and the run stops: nothing is retried and nothing logs in.

Output is local only: the number of encrypted reports, how many decrypted, and for each decrypted one the
time, position, accuracy and confidence. `--summary` prints counts only (no coordinates).
Only use a key of a tag you own.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools" / "machoadi"))

URL = "https://gateway.icloud.com/findmyservice/v2/fetch"


def build_body(hashed_b64: str, days: int, *, secondary: bool = False, now: datetime | None = None) -> dict:
    """The library's own request body for one key."""
    now = now or datetime.now(tz=timezone.utc)
    start = int((now - timedelta(days=days)).timestamp()) * 1000
    end = int(now.timestamp()) * 1000
    return {
        "clientContext": {"clientBundleIdentifier": "com.apple.icloud.searchpartyuseragent",
                          "policy": "foregroundClient"},
        "fetch": [{
            "ownedDeviceIds": [], "keyType": 1,
            "startDate": start, "startDateSecondary": start, "endDate": end,
            "primaryIds": [] if secondary else [hashed_b64],
            "secondaryIds": [hashed_b64] if secondary else [],
        }],
    }


def parse_payload(response_json: dict) -> tuple[str | None, list[tuple[bytes, bytes]]]:
    """(statusCode, [(hashed_adv_key, encrypted_report), ...]) from a v2 answer."""
    block = response_json.get("acsnLocations", {})
    out = []
    for entry in block.get("locationPayload", []):
        hashed = base64.b64decode(entry["id"])
        for report in entry.get("locationInfo", []):
            out.append((hashed, base64.b64decode(report)))
    return block.get("statusCode"), out


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", type=Path, required=True, help="the machine that logged in")
    ap.add_argument("--session", type=Path, help="default: <state>-session.json")
    ap.add_argument("--days", type=int, default=7, help="history window (default 7)")
    ap.add_argument("--secondary", action="store_true", help="send the key as a secondary id (default: primary)")
    ap.add_argument("--summary", action="store_true", help="print counts only, no coordinates")
    ap.add_argument("--dry-run", action="store_true", help="check inputs and print the request shape; send nothing")
    args = ap.parse_args()

    session_path = args.session or Path(str(args.state) + "-session.json")
    if not session_path.exists():
        raise SystemExit(f"no session file {session_path}: log in first (tools/aged_login.sh {args.state})")
    session = json.loads(session_path.read_text())
    key_b64 = os.environ.get("FINDMY_KEY", "").strip()
    if not key_b64:
        raise SystemExit("FINDMY_KEY is not set (base64 private key of your own tag; see --help)")

    from findmy import KeyPair  # noqa: PLC0415

    try:
        key = KeyPair.from_b64(key_b64)
    except Exception as error:  # noqa: BLE001
        raise SystemExit(f"FINDMY_KEY is not a usable key ({type(error).__name__}); expected base64 of the "
                         "28-byte private key") from None
    del key_b64
    hashed = key.hashed_adv_key_b64
    body = build_body(hashed, args.days, secondary=args.secondary)
    print(f"key: hashed id {hashed[:8]}... ({'secondary' if args.secondary else 'primary'}), window {args.days} d; "
          f"session saved {session.get('saved_at', '?')}", flush=True)
    if args.dry_run:
        print("dry run: nothing sent; request body shape:",
              json.dumps({k: (v if k != 'fetch' else [{kk: ('<id>' if 'Ids' in kk and vv else vv)
                                                       for kk, vv in v[0].items()}]) for k, v in body.items()}))
        return 0

    from auth_probe import make_mac_account  # noqa: PLC0415
    from mac_anisette import provisioned_at  # noqa: PLC0415
    from resync import sim_from_response  # noqa: PLC0415

    account = make_mac_account(args.state)
    born = provisioned_at(args.state)
    try:
        for attempt in range(1, 7):
            response = await account._http.post(
                URL, auth=(session["dsid"], session["searchPartyToken"]),
                headers=await account.get_anisette_headers(), json=body)
            age = time.time() - born
            if response.status_code == 200 and not response.text().strip() and attempt < 6:
                print(f"empty 200 (machine age {age:.0f} s), retry {attempt}/5 in {2 * attempt} s", flush=True)
                await asyncio.sleep(2 * attempt)
                continue
            break
        print(f"machine age {age:.0f} s   {URL.rsplit('/', 2)[-2]} -> {response.status_code}  "
              f"{len(response.content)} bytes", flush=True)
        if response.status_code != 200:
            apple = {k: v for k, v in dict(response.headers).items()
                     if k.lower().startswith("x-apple") or k.lower() in ("www-authenticate", "content-type")}
            print("refused:", apple, response.content[:200], "carries_SIM:", bool(sim_from_response(response)))
            return 1
        try:
            status, reports = parse_payload(response.json())
        except (ValueError, KeyError) as error:
            print(f"unexpected answer shape ({type(error).__name__}); first bytes: {response.content[:200]!r}")
            return 1
        print(f"acsnLocations statusCode {status}; encrypted reports: {len(reports)}", flush=True)
        from findmy.reports.reports import LocationReport  # noqa: PLC0415

        decrypted, failed = [], 0
        for hashed_key, payload in reports:
            report = LocationReport(payload, hashed_key)
            try:
                report.decrypt(key)
                decrypted.append(report)
            except Exception:  # noqa: BLE001 - count it; do not print key material
                failed += 1
        print(f"decrypted: {len(decrypted)}, failed: {failed}", flush=True)
        if not args.summary:
            for r in sorted(decrypted, key=lambda r: r.timestamp)[-20:]:
                print(f"  {r.timestamp.isoformat()}  {r.latitude:.5f}, {r.longitude:.5f}  "
                      f"+-{r.horizontal_accuracy} m  confidence {r.confidence}")
        elif decrypted:
            print("newest report:", max(r.timestamp for r in decrypted).isoformat())
        return 0
    finally:
        await account.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
