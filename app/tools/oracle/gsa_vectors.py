#!/usr/bin/env python3
"""Capture the exact Grand Slam `MidService` requests the Python sends (offline, no Apple).

    python app/tools/oracle/gsa_vectors.py [OUT]

Patch `urllib.request.urlopen` so `tools/machoadi/gsa.py` records every request (URL, method, headers, body)
for the URL bag, `midStartProvisioning`, `midFinishProvisioning` and `midSyncMachine`, and writes
`fixtures/gsa/requests.json`. Nothing is sent.
"""

from __future__ import annotations

import base64
import json
import plistlib
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools" / "machoadi"))

import gsa as G  # noqa: E402

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = ROOT / "app/android/app/src/test/resources/fixtures/gsa"

DEVICE = G.Device(unique_device_id="00006000-0A1B2C3D4E5F6071", client_info=G.DEFAULT_CLIENT_INFO,
                  local_user_uuid="8F2C6A1E5B7D49C3A0E1F2D3C4B5A697", serial="C02SYNTH0001")
BAG = {
    "midStartProvisioning": "https://gsa.apple.com/grandslam/MidService/midStartProvisioning",
    "midFinishProvisioning": "https://gsa.apple.com/grandslam/MidService/midFinishProvisioning",
    "midSyncMachine": "https://gsa.apple.com/grandslam/MidService/midSyncMachine",
}
SPIM = bytes(range(48))
PTM = bytes(range(16))
TK = bytes(range(32))
CPIM = bytes(range(64))
SRM = bytes(range(32))
MID = bytes(range(60))


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self.status = 200

    def read(self) -> bytes:
        return self._body

    def __enter__(self):  # noqa: ANN204
        return self

    def __exit__(self, *a):  # noqa: ANN002
        return False


def response_for(url: str) -> bytes:
    if url.endswith("/lookup"):
        return plistlib.dumps({"urls": BAG})
    if url.endswith("midStartProvisioning"):
        return plistlib.dumps({"Response": {"spim": base64.b64encode(SPIM).decode()}})
    if url.endswith("midFinishProvisioning"):
        return plistlib.dumps({"Response": {"ptm": base64.b64encode(PTM).decode(), "tk": base64.b64encode(TK).decode(),
                                            "X-Apple-I-MD-RINFO": 84215045}})
    if url.endswith("midSyncMachine"):
        return plistlib.dumps({"Response": {"Status": {"ec": 0}}})
    raise AssertionError(url)


seen: list[dict] = []


def fake_urlopen(req, timeout=None, context=None):  # noqa: ANN001
    seen.append({
        "url": req.full_url,
        "method": req.get_method(),
        "headers": dict(req.header_items()),
        "body": base64.b64encode(req.data or b"").decode(),
    })
    return FakeResponse(response_for(req.full_url))


def main() -> int:
    # Pin the client time so the fixture is deterministic; the Rust side ignores this header's value.
    class FixedDateTime:
        @staticmethod
        def now(tz=None):  # noqa: ANN001, ANN205
            import datetime

            return datetime.datetime(2026, 10, 17, 12, 34, 56, tzinfo=tz)

    original_datetime = G.datetime
    original_urlopen = urllib.request.urlopen
    G.datetime = FixedDateTime  # type: ignore[assignment]
    urllib.request.urlopen = fake_urlopen  # type: ignore[assignment]

    from gsa import GSA

    client = GSA(DEVICE)
    client.load_urlbag()
    client.start_provisioning()
    client.finish_provisioning(CPIM)
    client.sync_machine(base64.b64encode(MID).decode(), base64.b64encode(SRM).decode(), 84215045)

    urllib.request.urlopen = original_urlopen  # type: ignore[assignment]
    G.datetime = original_datetime  # type: ignore[assignment]

    document = {
        "device": {"unique_device_id": DEVICE.unique_device_id, "client_info": DEVICE.client_info,
                   "local_user_uuid": DEVICE.local_user_uuid, "serial": DEVICE.serial},
        "bag": BAG,
        "spim": SPIM.hex(),
        "cpim": CPIM.hex(),
        "ptm": PTM.hex(),
        "tk": TK.hex(),
        "mid": base64.b64encode(MID).decode(),
        "srm": base64.b64encode(SRM).decode(),
        "requests": seen,
    }
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    out.mkdir(parents=True, exist_ok=True)
    (out / "requests.json").write_text(json.dumps(document, indent=1, sort_keys=True) + "\n")
    print("wrote", out / "requests.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
