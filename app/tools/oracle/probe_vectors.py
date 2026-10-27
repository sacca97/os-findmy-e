#!/usr/bin/env python3
"""Capture the exact Grand Slam `init` request the Python probe sends (offline, no Apple).

    python app/tools/oracle/probe_vectors.py [OUT]

Uses the library's own `AsyncAppleAccount._gsa_request` with the `StaticAnisetteProvider` from
`tools/machoadi/gsa_init.py`, a fixed Anisette dict, a fixed SRP ephemeral and a fake HTTP that records the
request. Writes `fixtures/probe/init.json` (request body + headers + cpd) so the Rust `probe_init` can be
asserted byte-for-byte. Nothing is sent.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools" / "machoadi"))

import srp._pysrp as srp  # noqa: E402

from findmy import AsyncAppleAccount  # noqa: E402
from findmy.reports.anisette import BaseAnisetteProvider, DeviceIdentity  # noqa: E402

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = ROOT / "app/android/app/src/test/resources/fixtures/probe"

IDENTITY = DeviceIdentity(model="MacBookPro13,2", os_name="macOS", os_version="13.1", os_build="22C65",
                          cfnetwork="1404.0.5", darwin="22.2.0")
SERIAL = "C02SYNTH0001"
UID = "8F2C6A1E5B7D49C3A0E1F2D3C4B5A697"
DEVID = "00006000-0A1B2C3D4E5F6071"
CLIENT_AKD = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
USERNAME = "probe-deadbeef@example.invalid"
SECRET = bytes(range(256))
CLIENT_TIME = "2026-10-17T12:34:56Z"

# What `tools/machoadi/mac_anisette.py headers()` produces: no `loc`, `X-Apple-I-TimeZone` is UTC, and it
# carries `X-MMe-Client-Info` (which the library's own `get_headers` does not).
ANISETTE = {
    "X-Apple-I-Client-Time": CLIENT_TIME,
    "X-Apple-I-MD": base64.b64encode(bytes(range(28))).decode(),
    "X-Apple-I-MD-LU": base64.b64encode(UID.encode()).decode(),
    "X-Apple-I-MD-M": base64.b64encode(bytes(range(100, 160))).decode(),
    "X-Apple-I-MD-RINFO": "84215045",
    "X-Apple-I-SRL-NO": SERIAL,
    "X-Apple-I-TimeZone": "UTC",
    "X-Apple-Locale": "en_US",
    "X-MMe-Client-Info": CLIENT_AKD,
    "X-Mme-Device-Id": DEVID,
}


class StaticProvider(BaseAnisetteProvider):
    def __init__(self) -> None:
        super().__init__(serial=SERIAL, identity=IDENTITY)
        self._h = dict(ANISETTE)

    otp = property(lambda self: self._h["X-Apple-I-MD"])
    machine = property(lambda self: self._h["X-Apple-I-MD-M"])
    client_akd = property(lambda self: self._h["X-MMe-Client-Info"])

    async def get_headers(self, user_id, device_id, serial=None, with_client_info=False):  # noqa: ANN001
        headers = dict(self._h)
        headers["X-Apple-I-Client-Time"] = CLIENT_TIME
        return headers

    async def close(self) -> None:
        return None

    def to_json(self, dst=None, /):  # noqa: ANN001
        raise NotImplementedError

    @classmethod
    def from_json(cls, mapping):  # noqa: ANN001, ANN206
        raise NotImplementedError


class FakeResponse:
    status_code = 200
    content = b""
    ok = True

    def plist(self):  # noqa: ANN201
        return {"Response": {"Status": {"ec": -20970}}}


class FakeHttp:
    def __init__(self) -> None:
        self.seen: list[dict] = []

    async def post(self, url, *, headers=None, data=None, json=None, **kw):  # noqa: ANN001, ANN003
        self.seen.append({"url": url, "headers": dict(headers or {}), "body": base64.b64encode(data).decode()})
        return FakeResponse()

    async def close(self) -> None:
        return None


async def main() -> int:
    provider = StaticProvider()
    account = AsyncAppleAccount(provider, uid=UID, devid=DEVID, timeout=30)
    http = FakeHttp()
    account._http = http  # pyright: ignore [reportAttributeAccessIssue]
    user = srp.User(USERNAME, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048, bytes_a=SECRET)
    _, a2k = user.start_authentication()
    await account._gsa_request({"A2k": a2k, "u": USERNAME, "ps": ["s2k", "s2k_fo"], "o": "init"})
    await account.close()
    sent = http.seen[0]
    document = {
        "anisette": ANISETTE,
        "username": USERNAME,
        "secret": SECRET.hex(),
        "a2k": a2k.hex(),
        "url": sent["url"],
        "headers": sent["headers"],
        "body": sent["body"],
    }
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    out.mkdir(parents=True, exist_ok=True)
    (out / "init.json").write_text(json.dumps(document, indent=1, sort_keys=True) + "\n")
    print("wrote", out / "init.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
