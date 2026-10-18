#!/usr/bin/env python3
"""Drive the emulated macOS 26 `adid`: one live provisioning round, then
offline use of the store it writes.

Unlike the 4.19 dylib, the macOS 26 daemon keeps its machine store at
``/var/db/fpsd/adi/adi.pb`` (the modern `fpsd` path, not the legacy
``/Users/Shared/adi``).  We run the daemon on a synthetic filesystem, so after a
round we save that virtual filesystem and reload it into later runs: a fresh
daemon then starts already provisioned and answers ``RequestOTP`` offline.

Only ``provision`` touches the network, and only once per fresh identity.

    macos-adi-emulator provision
    macos-adi-emulator status
    macos-adi-emulator headers
    macos-adi-emulator --state DIR status
"""
from __future__ import annotations

import argparse
import base64
import json
import locale
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from . import adi
from .gsa import GSA, Device
from .identity import mint_identity

DS_ID = -2


# -- state ---------------------------------------------------------------
def load_identity(state: Path) -> dict:
    path = state / "identity.json"
    if path.exists():
        return json.loads(path.read_text())
    return mint_identity()


def load_store(d: adi.Adid, state: Path) -> int:
    """Restore the daemon's whole virtual filesystem from store.json."""
    path = state / "store.json"
    if not path.exists():
        return 0
    files = json.loads(path.read_text())
    for vpath, b64 in files.items():
        d.stubs.files[vpath] = bytearray(base64.b64decode(b64))
    return len(files)


def save_store(d: adi.Adid, state: Path) -> int:
    files = {p: base64.b64encode(bytes(v)).decode() for p, v in d.stubs.files.items()}
    (state / "store.json").write_text(json.dumps(files, indent=2) + "\n")
    return len(files)


def save_provisioning(state: Path, info: dict) -> None:
    (state / "provisioning.json").write_text(
        json.dumps({k: (base64.b64encode(v).decode() if isinstance(v, bytes) else v)
                    for k, v in info.items()}, indent=2) + "\n")


# -- commands ------------------------------------------------------------
def headers_from(d: adi.Adid, identity: dict, routing: int) -> dict[str, str]:
    mid, otp = d.request_otp(DS_ID)
    return {
        "X-Apple-I-Client-Time": datetime.now(timezone.utc).replace(
            microsecond=0).isoformat().replace("+00:00", "Z"),
        "X-Apple-I-MD": base64.b64encode(otp).decode(),
        "X-Apple-I-MD-M": base64.b64encode(mid).decode(),
        "X-Apple-I-MD-RINFO": str(routing),
        "X-Apple-I-MD-LU": base64.b64encode(identity["local_user_uuid"].encode()).decode(),
        "X-Apple-I-SRL-NO": identity.get("serial"),
        "X-Apple-I-TimeZone": "UTC",
        "X-Apple-Locale": locale.getlocale()[0] or "en_US",
        "X-MMe-Client-Info": identity["client_info"],
        "X-Mme-Device-Id": identity["device_id"],
    }


def boot(state: Path) -> adi.Adid:
    identity = load_identity(state)
    d = adi.Adid(host_uuid=bytes.fromhex(identity["host_uuid"]))
    load_store(d, state)
    return d


def cmd_provision(state: Path) -> int:
    state.mkdir(parents=True, exist_ok=True)
    identity = load_identity(state)
    print(f"device_id      {identity['device_id']}")
    print(f"host_uuid      {identity['host_uuid']}")
    print(f"client_info    {identity['client_info']}")
    print(f"serial         {identity.get('serial')}")

    d = adi.Adid(host_uuid=bytes.fromhex(identity["host_uuid"]))
    if load_store(d, state) and d.is_machine_provisioned(DS_ID):
        print("already provisioned; erase the state directory to redo this")
        return 0

    gsa = GSA(Device(identity["device_id"], identity["client_info"],
                     identity["local_user_uuid"], identity.get("serial")))
    gsa.load_urlbag()
    print("url bag loaded")

    spim = gsa.start_provisioning()
    print(f"spim           {len(spim)} bytes")
    cpim, session = d.start_provisioning(DS_ID, spim)
    print(f"cpim           {len(cpim)} bytes")
    print(f"session        {session}")

    finished = gsa.finish_provisioning(cpim)
    print(f"ptm            {len(finished['ptm'])} bytes")
    print(f"tk             {len(finished['tk'])} bytes")
    print(f"routing        {finished['routing']}")

    d.end_provisioning(session, finished["ptm"], finished["tk"])
    print("ProvisioningEnd ok")
    if finished["routing"]:
        d.set_idms_routing(DS_ID, finished["routing"])

    print(f"is_provisioned {d.is_machine_provisioned(DS_ID)}")
    print(f"accounts       {len(d.get_all_provisioned_accounts())}")

    identity["routing"] = finished["routing"]
    identity["provisioned_at"] = time.time()
    (state / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    save_provisioning(state, {
        "spim": spim, "cpim": cpim, "session": session,
        "ptm": finished["ptm"], "tk": finished["tk"], "routing": finished["routing"],
    })
    n = save_store(d, state)
    print(f"store          {n} entries -> {state/'store.json'}")

    try:
        hdrs = headers_from(d, identity, finished["routing"])
        print(f"OTP            X-Apple-I-MD {len(base64.b64decode(hdrs['X-Apple-I-MD']))} B, "
              f"X-Apple-I-MD-M {len(base64.b64decode(hdrs['X-Apple-I-MD-M']))} B")
    except adi.AdidError as exc:
        print(f"RequestOTP: {exc}")
    return 0


def cmd_status(state: Path) -> int:
    identity = load_identity(state)
    d = boot(state)
    print(f"state          {state}")
    print(f"device_id      {identity['device_id']}")
    print(f"host_uuid      {identity['host_uuid']}")
    print(f"store loaded   {(state/'store.json').exists()}")
    print(f"is_provisioned {d.is_machine_provisioned(DS_ID)}")
    print(f"accounts       {d.get_all_provisioned_accounts()}")
    return 0


def cmd_headers(state: Path) -> int:
    identity = load_identity(state)
    if not (state / "store.json").exists():
        raise SystemExit("no store.json; run `provision` (live) first")
    d = boot(state)
    if not d.is_machine_provisioned(DS_ID):
        raise SystemExit("the saved store does not provision this machine")
    print(json.dumps(headers_from(d, identity, identity.get("routing") or 0), indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", nargs="?", default="provision",
                    choices=("provision", "status", "headers"))
    ap.add_argument(
        "--state",
        default=os.environ.get(
            "ANISETTE_MAC26_STATE",
            Path.home() / ".local" / "state" / "anisette-mac26",
        ),
    )
    args = ap.parse_args()
    state = Path(args.state)
    return {"provision": cmd_provision,
            "status": cmd_status,
            "headers": cmd_headers}[args.command](state)


if __name__ == "__main__":
    raise SystemExit(main())
