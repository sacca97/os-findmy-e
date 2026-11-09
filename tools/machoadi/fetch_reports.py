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

Static tags default to POST `acsnservice/fetch`, with only the owned hashed key, the saved
(dsid, searchPartyToken), and its machine's Anisette headers. Live A/B/A checks on 2026-11-09
found this path returning new reports while `findmyservice/v2/fetch` returned old ones for the
same key. `--protocol v2` retains the library's original request for explicit comparisons.
Empty 200s are retried (FindMy.py#185). HTTP refusals report status only, never raw headers/body.

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

URL = "https://gateway.icloud.com/acsnservice/fetch"
V2_URL = "https://gateway.icloud.com/findmyservice/v2/fetch"


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
    """Decode either wire format without changing the authenticated encrypted payloads."""
    if "results" in response_json:
        return str(response_json.get("statusCode")), [
            (base64.b64decode(entry["id"]), base64.b64decode(entry["payload"]))
            for entry in response_json["results"]
        ]
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
    ap.add_argument("--protocol", choices=("legacy", "v2"), default="legacy",
                    help="static keys default to legacy; v2 may return stale reports (live-checked 2026-11-09)")
    ap.add_argument("--summary", action="store_true", help="print counts only, no coordinates")
    ap.add_argument("--dry-run", action="store_true", help="check inputs and print the request shape; send nothing")
    args = ap.parse_args()
    if args.secondary and args.protocol != "v2":
        ap.error("--secondary requires --protocol v2")

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
    endpoint = V2_URL if args.protocol == "v2" else URL
    if args.protocol == "legacy":
        body = {"search": [{"startDate": body["fetch"][0]["startDate"], "ids": [hashed]}]}
    print(f"key: one owned hashed id ({'secondary' if args.secondary else 'primary'}), window {args.days} d; "
          "saved session loaded", flush=True)
    if args.dry_run:
        print("dry run: nothing sent; endpoint:", endpoint, "; protocol:", args.protocol,
              "; one owned hashed key (redacted)")
        return 0

    from auth_probe import make_mac_account  # noqa: PLC0415
    from mac_anisette import provisioned_at  # noqa: PLC0415
    from resync import sim_from_response  # noqa: PLC0415

    account = make_mac_account(args.state)
    born = provisioned_at(args.state)
    try:
        for attempt in range(1, 7):
            response = await account._http.post(
                endpoint, auth=(session["dsid"], session["searchPartyToken"]),
                headers=await account.get_anisette_headers(), json=body)
            age = time.time() - born
            if response.status_code == 200 and not response.text().strip() and attempt < 6:
                print(f"empty 200 (machine age {age:.0f} s), retry {attempt}/5 in {2 * attempt} s", flush=True)
                await asyncio.sleep(2 * attempt)
                continue
            break
        print(f"machine age {age:.0f} s   {args.protocol} -> {response.status_code}  "
              f"{len(response.content)} bytes", flush=True)
        if response.status_code != 200:
            print("refused: HTTP", response.status_code, "carries_SIM:", bool(sim_from_response(response)))
            return 1
        try:
            status, reports = parse_payload(response.json())
        except (ValueError, KeyError) as error:
            print(f"unexpected answer shape ({type(error).__name__})")
            return 1
        print(f"acsnLocations statusCode {status}; encrypted reports: {len(reports)}", flush=True)
        if str(status) != "200":
            print("Apple refused the report query; no locations accepted.")
            return 1
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
