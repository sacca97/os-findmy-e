#!/usr/bin/env python3
"""Mac-lineage Anisette, produced on Linux by Apple's own CoreADI whitebox.

This is the "option 4" artefact: it does *not* reimplement ADI.  It runs the
genuine x86_64 ``CoreADI.framework`` from iTunes 12.8.3 for Mac under Unicorn
(``harness.py`` + ``stubs.py``), talks to Apple's ``MidService`` provisioning
endpoints over HTTP (``gsa.py``) exactly the way ``akd`` does, and then asks
the library for an OTP.

The machine identity the library hashes into the CPIM is whatever
``gethostuuid`` returns, so the store is only meaningful together with the
``host_uuid`` recorded next to it -- all of it lives in one state directory:

    <state>/identity.json     device id, local-user id, client info, host uuid
    <state>/store/*.pb        the virtual /Users/Shared/adi contents

Usage::

    .venv/bin/python tools/machoadi/mac_anisette.py provision
    .venv/bin/python tools/machoadi/mac_anisette.py headers
    .venv/bin/python tools/machoadi/mac_anisette.py headers --out /tmp/h.json
"""

from __future__ import annotations

import argparse
import base64
import json
import locale
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from adi_run import CoreADI  # noqa: E402
from gsa import GSA, Device, GSAError  # noqa: E402

DS_ID = -2  # Apple's "no account" pseudo-DSID, same one akd uses locally.
STORE_DIR = "/Users/Shared/adi"
DEFAULT_CLIENT_INFO = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

# A Mac's `X-Mme-Device-Id` is its **provisioning UDID**, which a live Mac reports as 8 hex,
# a dash, and 16 hex (`system_profiler SPHardwareDataType`, 25 characters) -- and which is
# *not* its IOPlatformUUID, so a UUID is not a Mac device id at all. `X-Apple-I-SRL-NO` is 12
# alphanumeric characters, with no I or O. Both are minted here rather than read from
# hardware: the MID is derived from `host_uuid`, so the identity is at least consistent with
# itself, which is all this layer can promise. Whether Apple needs these values to be *true*
# rather than correctly shaped is exactly what a real Mac is needed to answer.
_UDID_PREFIX = "00006000"
_SERIAL_ALPHABET = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def _mint_identity() -> dict:
    """A fresh machine identity, in the shapes Apple's own client uses."""
    return {
        "device_id": f"{_UDID_PREFIX}-{secrets.token_hex(8).upper()}",
        "local_user_uuid": secrets.token_hex(16).upper(),
        "client_info": DEFAULT_CLIENT_INFO,
        "host_uuid": secrets.token_hex(16),
        "routing": None,
        "serial": "C02" + "".join(secrets.choice(_SERIAL_ALPHABET) for _ in range(9)),
    }


class MacAnisette:
    def __init__(self, state: Path, *, log: bool = False) -> None:
        self.state = Path(state)
        self.state.mkdir(parents=True, exist_ok=True)
        self.log = log

        self.identity = self._load_identity()
        self.adi = CoreADI(log=log)
        self.adi.stubs.hostuuid = bytes.fromhex(self.identity["host_uuid"])
        self._load_store()
        self._initialized = False

    def _ensure_initialized(self) -> None:
        """Call the library's ``Initialize`` once, the way ``akd`` does at startup."""
        if not self._initialized:
            self.adi.initialize()
            self._initialized = True

    # -- identity ---------------------------------------------------------
    def _load_identity(self) -> dict:
        path = self.state / "identity.json"
        if path.exists():
            return json.loads(path.read_text())
        return _mint_identity()

    def _save_identity(self) -> None:
        (self.state / "identity.json").write_text(json.dumps(self.identity, indent=2) + "\n")

    # -- store ------------------------------------------------------------
    def _load_store(self) -> None:
        """Repopulate the virtual ``/Users/Shared/adi`` from the state directory.

        ``adi.pb`` is deliberately *not* restored. It is the legacy whole-machine
        blob, and whenever it is present the load path stops before opening the
        per-user blob at all and reports the machine unprovisioned -- present or
        empty, and regardless of ``getuid`` or ``/var/db/.AppleSetupUser``, the
        outcome is identical. The modern store is ``adi-{uid:08X}.pb`` and that
        is what a cold process actually reads; keeping the legacy file around
        would only make every later run look unprovisioned.
        """
        for blob in sorted((self.state / "store").glob("*")):
            if blob.name == "adi.pb":
                continue
            self.adi.stubs.files[f"{STORE_DIR}/{blob.name}"] = bytearray(blob.read_bytes())

    def _save_store(self) -> None:
        out = self.state / "store"
        out.mkdir(exist_ok=True)
        for name, data in self.adi.stubs.files.items():
            if name.startswith(STORE_DIR + "/"):
                (out / name.rsplit("/", 1)[1]).write_bytes(bytes(data))

    # -- operations -------------------------------------------------------
    def is_provisioned(self) -> bool:
        self._ensure_initialized()
        return self.adi.is_machine_provisioned(DS_ID).ret == 0

    def provision(self, gsa: GSA | None = None) -> dict:
        self._ensure_initialized()
        if self.is_provisioned():
            raise SystemExit("already provisioned; erase the state directory to redo this")
        gsa = gsa or GSA(
            Device(
                self.identity["device_id"],
                self.identity["client_info"],
                self.identity["local_user_uuid"],
                self.identity.get("serial"),
            )
        )
        gsa.load_urlbag()

        spim = gsa.start_provisioning()
        started = self.adi.provisioning_start(DS_ID, spim)
        if started.ret != 0:
            raise SystemExit(f"ProvisioningStart failed: {started.ret}")
        cpim = started.outputs["cpim"]
        session = started.outputs["session_id"]

        finished = gsa.finish_provisioning(cpim)
        ended = self.adi.provisioning_end(session, finished["ptm"], finished["tk"])
        if ended.ret != 0:
            raise SystemExit(f"ProvisioningEnd failed: {ended.ret}")

        self.identity["routing"] = finished["routing"]
        self.adi.set_routing(DS_ID, finished["routing"])
        self._save_identity()
        self._save_store()
        return {
            "spim_len": len(spim),
            "cpim_len": len(cpim),
            "session": session,
            "routing": finished["routing"],
            "ptm_len": len(finished["ptm"]),
            "tk_len": len(finished["tk"]),
            "store_bytes": sum(
                len(v) for k, v in self.adi.stubs.files.items() if k.startswith(STORE_DIR + "/")
            ),
        }

    def headers(self) -> dict[str, str]:
        self._ensure_initialized()
        if not self.is_provisioned():
            raise SystemExit("not provisioned: run `provision` first")
        otp = self.adi.request_otp(DS_ID)
        if otp.ret != 0:
            raise SystemExit(f"RequestOTP failed: {otp.ret}")
        self._save_store()

        routing = self.adi.get_routing(DS_ID).outputs.get("routing") or 0
        return {
            "X-Apple-I-Client-Time": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "X-Apple-I-MD": base64.b64encode(otp.outputs["otp"]).decode(),
            "X-Apple-I-MD-LU": base64.b64encode(self.identity["local_user_uuid"].encode()).decode(),
            "X-Apple-I-MD-M": base64.b64encode(otp.outputs["mid"]).decode(),
            "X-Apple-I-MD-RINFO": str(routing),
            "X-Apple-I-SRL-NO": self.identity["serial"],
            "X-Apple-I-TimeZone": "UTC",
            "X-Apple-Locale": locale.getlocale()[0] or "en_US",
            "X-MMe-Client-Info": self.identity["client_info"],
            "X-Mme-Device-Id": self.identity["device_id"],
        }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["provision", "headers", "info"])
    ap.add_argument("--state", default="/tmp/macadi/macadi", help="state directory")
    ap.add_argument("--out", help="write `headers` output as JSON here instead of stdout")
    ap.add_argument("--log", action="store_true", help="log the synthetic syscalls")
    args = ap.parse_args()


    ani = MacAnisette(Path(args.state), log=args.log)
    if args.command == "provision":
        try:
            print(json.dumps(ani.provision(), indent=2))
        except GSAError as exc:  # pragma: no cover - network path
            print(f"provisioning failed: {exc}", file=sys.stderr)
            return 1
    elif args.command == "info":
        print(json.dumps({
            "state": str(ani.state),
            "provisioned": ani.is_provisioned(),
            "identity": ani.identity,
            "store_files": sorted(
                k.rsplit("/", 1)[1] for k in ani.adi.stubs.files if k.startswith(STORE_DIR + "/")
            ),
        }, indent=2))
    else:
        try:
            headers = ani.headers()
        except GSAError as exc:  # pragma: no cover - network path
            print(f"gsa error: {exc}", file=sys.stderr)
            return 1
        text = json.dumps(headers, indent=2) + "\n"
        if args.out:
            Path(args.out).write_text(text)
            print(f"wrote {args.out}")
        else:
            print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
