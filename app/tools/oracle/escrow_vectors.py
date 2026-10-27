#!/usr/bin/env python3
"""Capture the exact escrow-proxy requests the Python sends (offline, no Apple).

    python app/tools/oracle/escrow_vectors.py [OUT]

Runs the real `findmy.keychain.escrow.AsyncEscrowProxy` against a fake HTTP that records every request, for
`get_records`, `srp_init` and `recover`, and writes `fixtures/escrow/requests.json`. Nothing is sent.
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

from findmy.reports.anisette import DeviceIdentity  # noqa: E402
from findmy.keychain.escrow import AsyncEscrowProxy, escrow_host  # noqa: E402

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = ROOT / "app/android/app/src/test/resources/fixtures/escrow"

IDENTITY = DeviceIdentity(model="MacBookPro13,2", os_name="macOS", os_version="13.1", os_build="22C65",
                          cfnetwork="1404.0.5", darwin="22.2.0")
ANISETTE = {
    "X-Apple-I-Client-Time": "2026-10-17T12:34:56Z",
    "X-Apple-I-MD": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGw==",
    "X-Apple-I-MD-LU": "OEYyQzZBMUU1QjdENDlDM0EwRTFGMkQzQzRCNUE2OTc=",
    "X-Apple-I-MD-M": "ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6f",
    "X-Apple-I-MD-RINFO": "84215045",
    "X-Apple-I-SRL-NO": "C02SYNTH0001",
    "X-Apple-I-TimeZone": "UTC",
    "X-Apple-Locale": "en_US",
    "X-Mme-Device-Id": "00006000-0A1B2C3D4E5F6071",
    "loc": "en_US",
}
LABEL = "com.apple.icdp.record.PEER-1"
TRANSACTION = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0"
CLIENT_PUBLIC = bytes(range(64))
PROOF = bytes(range(32))


class FakeAccount:
    identity = IDENTITY
    timeout = 30
    account_name = "synthetic@example.invalid"

    async def get_anisette_headers(self):  # noqa: ANN201
        return dict(ANISETTE)


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    status_code = 200
    ok = True
    content = b""

    def plist(self):  # noqa: ANN201
        return self._payload


class FakeHttp:
    def __init__(self) -> None:
        self.seen: list[dict] = []

    async def post(self, url, *, headers=None, auth=None, data=None, json=None, **kw):  # noqa: ANN001, ANN003
        self.seen.append({
            "url": url,
            "auth": list(auth) if auth else None,
            "headers": dict(headers or {}),
            "body": base64.b64encode(data or b"").decode(),
        })
        return FakeResponse({"success": True, "metadataList": [], "respBlob": "", "dsid": "1234567890"})

    async def close(self) -> None:
        return None


async def main() -> int:
    proxy = AsyncEscrowProxy(FakeAccount(), escrow_host("42"), "SYNTHETIC-PET")  # pyright: ignore
    http = FakeHttp()
    proxy._http = http  # pyright: ignore [reportAttributeAccessIssue]
    await proxy.list_records()
    await proxy.srp_init(LABEL, CLIENT_PUBLIC, TRANSACTION)
    await proxy.recover(LABEL, PROOF, TRANSACTION, dsid="1234567890")
    document = {
        "host": escrow_host("42"),
        "anisette": ANISETTE,
        "label": LABEL,
        "transaction": TRANSACTION,
        "pet": "SYNTHETIC-PET",
        "account_name": FakeAccount.account_name,
        "identity": {"model": IDENTITY.model, "os_name": IDENTITY.os_name, "os_version": IDENTITY.os_version,
                     "os_build": IDENTITY.os_build, "cfnetwork": IDENTITY.cfnetwork, "darwin": IDENTITY.darwin},
        "requests": http.seen,
    }
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    out.mkdir(parents=True, exist_ok=True)
    (out / "requests.json").write_text(json.dumps(document, indent=1, sort_keys=True) + "\n")
    print("wrote", out / "requests.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
