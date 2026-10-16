#!/usr/bin/env python3
"""Ask Grand Slam `init` what it thinks of *this* machine's Anisette headers.

`init_probe.py` at the repository root searches the space of request shapes, but it
always obtains its baseline Anisette headers from an ADI library -- the Android one
in `.venv`, or a remote anisette server. That makes it useless for the one question
this file exists to answer:

    does Apple accept an OTP produced by the **Mac** CoreADI lineage?

So the headers here come from a plain dictionary, and nothing else does. The request
itself is still the library's own SRP `init`, sent through the library's own HTTP
client, so the bytes on the wire differ from `init_probe.py` only in the Anisette
values.

Credential-free, like the root probe: `init` is answered before any password is
considered, and the Apple ID is a synthetic `.invalid` address.

    .venv/bin/python tools/machoadi/gsa_init.py --headers-json /tmp/macadi/mac_headers.json
    .venv/bin/python tools/machoadi/gsa_init.py --state /tmp/macadi/macadi

The second form generates the headers live through `mac_anisette.py`, which means the
`init` request and the OTP come from the same process.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import secrets
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from findmy import AsyncAppleAccount  # noqa: E402
from findmy.reports import account as account_module  # noqa: E402
from findmy.reports.anisette import (  # noqa: E402
    CLIENT_IDENTITY,
    CLIENT_SERIAL,
    BaseAnisetteProvider,
)

# Grand Slam's own reply, and the codes seen here, are documented in EVIDENCE.md.
SENTINEL_OK = 0


class StaticAnisetteProvider(BaseAnisetteProvider):
    """An Anisette provider backed by a fixed dict instead of an ADI library."""

    def __init__(self, headers: dict[str, str], client_info: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self._h = dict(headers)
        self._client_info = client_info

    # The three members BaseAnisetteProvider leaves abstract. The OTP and MID
    # properties only feed the base class's own get_headers, which this class
    # replaces, so they just echo the dict.
    @property
    def otp(self) -> str:
        return self._h["X-Apple-I-MD"]

    @property
    def machine(self) -> str:
        return self._h["X-Apple-I-MD-M"]

    @property
    def client_akd(self) -> str:
        """What `init` is told is speaking; the base class would compose it from
        sample hardware this machine is not claiming."""
        return self._client_info

    async def get_headers(
        self,
        user_id: str,
        device_id: str,
        serial: str | None = None,
        with_client_info: bool = False,
    ) -> dict[str, str]:
        headers = dict(self._h)
        headers["X-Apple-I-Client-Time"] = (
            datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )
        headers["X-Apple-I-MD-LU"] = headers.get(
            "X-Apple-I-MD-LU", base64.b64encode(str(user_id).encode()).decode()
        )
        headers["X-Mme-Device-Id"] = headers.get("X-Mme-Device-Id", str(device_id)).upper()
        headers["X-Apple-I-SRL-NO"] = serial or headers.get("X-Apple-I-SRL-NO", self._serial)
        return headers

    async def close(self) -> None:
        return None

    # Serializable's pair. A fixed dict of headers has no state worth round-tripping
    # through the account file, and pretending otherwise would invite a stale OTP to
    # be restored from an account that thinks it still owns a live device.
    def to_json(self, dst=None, /) -> dict[str, str]:
        raise NotImplementedError("static Anisette headers are not a serializable provider")

    @classmethod
    def from_json(cls, mapping):
        raise NotImplementedError("static Anisette headers are not a serializable provider")


# The machine UUID the MID is derived from, once `run` has found it. The variants below
# exist because of nab138/isideload#27: after 2026-10-12 a *genuine* local ADI is still
# refused (-22410) unless it is sent with the device values that ADI instance is paired
# with, and the reporter had to read the real `X-Mme-Device-Id` / `X-Apple-I-MD-LU` /
# `X-Apple-I-MD-RINFO` out of iCloud-for-Windows' own log to get past it. The OTP comes
# from ``gethostuuid``, so the machine UUID is the first candidate for those values.
CONTEXT: dict[str, str] = {}


def _dashed(value: str) -> str:
    """32 hex characters as a UUID, the shape a real ``X-Mme-Device-Id`` has."""
    return f"{value[0:8]}-{value[8:12]}-{value[12:16]}-{value[16:20]}-{value[20:32]}".upper()


def _machine(cpd: dict) -> str:
    return CONTEXT.get("host_uuid") or ""


def _mac_udid(value: str, prefix: str | None = None) -> str:
    """The shape a real Mac sends as ``X-Mme-Device-Id``: 8 hex, a dash, 16 hex.

    Measured on a live Mac, not guessed: ``system_profiler SPHardwareDataType`` reports the
    provisioning UDID as ``xxxxxxxx-xxxxxxxxxxxxxxxx`` (25 characters), and it is *not* the
    IOPlatformUUID. Nothing here can make the value true -- only Apple hardware can -- so this
    variant exists for the one question left open: does Apple check the *shape* (and merely
    accepted arbitrary UUIDs until 2026-10-12), or does it check the value against the machine?
    """
    return f"{prefix or value[0:8]}-{value[8:24]}".upper()


# name -> (description, cpd mutation)
VARIANTS: dict[str, tuple[str, object]] = {
    "mac": ("headers exactly as produced", lambda cpd: None),
    # The device values, held constant everywhere else, so the only thing that moves is
    # whether Apple pairs this Anisette with the identity beside it.
    "devid-machine-uuid": (
        "X-Mme-Device-Id = the machine UUID the MID derives from",
        lambda cpd: cpd.update(**{"X-Mme-Device-Id": _dashed(_machine(cpd))}) if _machine(cpd) else None,
    ),
    "devid-machine-hex": (
        "X-Mme-Device-Id = that UUID as 32 hex characters, no dashes",
        lambda cpd: cpd.update(**{"X-Mme-Device-Id": _machine(cpd).upper()}) if _machine(cpd) else None,
    ),
    "devid-dotted": (
        "X-Mme-Device-Id in the dotted-hex form iCloud for Windows sends (guess at the grouping)",
        lambda cpd: cpd.update(
            **{"X-Mme-Device-Id": ".".join(
                _machine(cpd)[i : i + 8] for i in range(0, 32, 8)
            ).upper()}
        )
        if _machine(cpd)
        else None,
    ),
    "devid-mac-udid": (
        "X-Mme-Device-Id in the Mac UDID shape, <8 hex>-<16 hex>, from the machine UUID",
        lambda cpd: cpd.update(**{"X-Mme-Device-Id": _mac_udid(_machine(cpd))}) if _machine(cpd) else None,
    ),
    "devid-mac-udid-prefix": (
        "the same shape with a fixed Apple-silicon-looking prefix",
        lambda cpd: cpd.update(**{"X-Mme-Device-Id": _mac_udid(_machine(cpd), "00006000")})
        if _machine(cpd)
        else None,
    ),
    # These two ask the question the device-value variants only circle around: is `-22421`
    # a verdict on the OTP at all? Every identity-side change left it exactly as it was,
    # which is equally consistent with "Apple evaluates the machine" and with "Apple never
    # looks at the machine and something else is refused". Removing the OTP distinguishes
    # them, and costs one request.
    "no-md": (
        "X-Apple-I-MD and X-Apple-I-MD-M removed entirely: is -22421 about the OTP at all?",
        lambda cpd: (cpd.pop("X-Apple-I-MD", None), cpd.pop("X-Apple-I-MD-M", None)),
    ),
    "garbage-md": (
        "well-framed but cryptographically invalid OTP, everything else untouched",
        lambda cpd: cpd.update(
            **{
                "X-Apple-I-MD": base64.b64encode(
                    struct.pack(">I", 5) + struct.pack(">I", 16) + secrets.token_bytes(16) + struct.pack(">I", 1)
                ).decode(),
                "X-Apple-I-MD-M": base64.b64encode(secrets.token_bytes(60)).decode(),
            }
        ),
    ),
    "devid-ios-udid": (
        "X-Mme-Device-Id as 40 hex characters, the shape a real iPhone sends",
        lambda cpd: cpd.update(**{"X-Mme-Device-Id": (_machine(cpd) + _machine(cpd)[:8]).upper()})
        if _machine(cpd)
        else None,
    ),
    "serial-drop": (
        "X-Apple-I-SRL-NO removed -- which is what provisioning actually sent (gsa.py "
        "does not put a serial in the MidService headers), so this makes the login identity "
        "match the one Apple was given when the machine was registered",
        lambda cpd: cpd.pop("X-Apple-I-SRL-NO", None),
    ),
    "serial-0": (
        "X-Apple-I-SRL-NO = the literal '0' the older ecosystem clients sent",
        lambda cpd: cpd.update(**{"X-Apple-I-SRL-NO": "0"}),
    ),
    "lu-machine-uuid": (
        "X-Apple-I-MD-LU = base64 of that UUID instead of a 32-hex string",
        lambda cpd: cpd.update(
            **{"X-Apple-I-MD-LU": base64.b64encode(_dashed(_machine(cpd)).encode()).decode()}
        )
        if _machine(cpd)
        else None,
    ),
    "ram": ("X-Apple-I-MD-RINFO removed", lambda cpd: cpd.pop("X-Apple-I-MD-RINFO", None)),
    "rinfo-android": (
        "X-Apple-I-MD-RINFO forced to the hard-coded 17106176 every Android build sends",
        lambda cpd: cpd.update(**{"X-Apple-I-MD-RINFO": "17106176"}),
    ),
    "lu-raw": (
        "X-Apple-I-MD-LU sent without base64, as the provisioning request sends it",
        lambda cpd: cpd.update(
            **{"X-Apple-I-MD-LU": base64.b64decode(cpd["X-Apple-I-MD-LU"]).decode()}
        ),
    ),
    "lu-drop": ("X-Apple-I-MD-LU removed", lambda cpd: cpd.pop("X-Apple-I-MD-LU", None)),
}


def load_headers(args: argparse.Namespace) -> tuple[dict[str, str], str]:
    if args.headers_json:
        loaded = json.loads(Path(args.headers_json).read_text())
        # Same shape init_probe.py accepts: an optional "_http" object for values that
        # travel as HTTP headers rather than in the plist body.
        http = loaded.pop("_http", {})
        client_info = loaded.pop("_client_info", None) or http.get("X-MMe-Client-Info")
        if loaded.get("_host_uuid"):
            CONTEXT["host_uuid"] = loaded.pop("_host_uuid")
        return loaded, client_info or DEFAULT_CLIENT_INFO

    from mac_anisette import MacAnisette  # noqa: PLC0415 - keeps --headers-json path light

    ani = MacAnisette(Path(args.state))
    headers = ani.headers()
    CONTEXT["host_uuid"] = ani.identity["host_uuid"]
    return headers, ani.identity["client_info"]


DEFAULT_CLIENT_INFO = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"


async def run(args: argparse.Namespace) -> int:
    headers, client_info = load_headers(args)
    if args.client_info:
        client_info = args.client_info
    provider = StaticAnisetteProvider(headers, client_info, serial=CLIENT_SERIAL, identity=CLIENT_IDENTITY)
    account = AsyncAppleAccount(provider, timeout=30)
    username = args.username or f"probe-{secrets.token_hex(4)}@example.invalid"

    original_get_cpd = provider.get_cpd
    selected: dict[str, object] = {}

    async def get_cpd(*a, **k):
        cpd = await original_get_cpd(*a, **k)
        mutate = selected.get("mutate")
        if mutate is not None:
            mutate(cpd)  # type: ignore[operator]
        return cpd

    provider.get_cpd = get_cpd

    original_ua = account_module._GSA_USER_AGENT
    if args.user_agent:
        account_module._GSA_USER_AGENT = args.user_agent

    names = args.variants or ["mac"]
    results = []
    try:
        for index, name in enumerate(names):
            description, mutate = VARIANTS[name]
            selected.update(mutate=mutate, name=name)
            if index:
                await asyncio.sleep(args.delay)
            import srp._pysrp as srp

            _, a2k = srp.User(username, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048).start_authentication()
            parameters = {"A2k": a2k, "u": username, "ps": ["s2k", "s2k_fo"], "o": "init"}
            try:
                response = await account._gsa_request(parameters)
                status = response.get("Status") or {}
                outcome = {
                    "ec": status.get("ec"),
                    "em": status.get("em"),
                    "hsc": status.get("hsc"),
                    "keys": sorted(k for k in response if k != "Status"),
                }
            except Exception as error:  # noqa: BLE001 - a transport failure is a result here
                outcome = {"error": f"{type(error).__name__}: {error}"}
            outcome.update(
                variant=name,
                note=description,
                at=datetime.now(timezone.utc).strftime("%H:%M:%S"),
            )
            results.append(outcome)
            print(json.dumps(outcome), flush=True)
    finally:
        account_module._GSA_USER_AGENT = original_ua
        await account.close()

    if results and len(results) > 1:
        base = results[0].get("ec")
        changed = [r["variant"] for r in results if r.get("ec") != base]
        print(f"\nec differing from {results[0]['variant']}: {changed or 'none'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--headers-json", help="JSON of anisette headers (see mac_anisette.py headers)")
    source.add_argument("--state", help="MacAnisette state directory; headers are generated live")
    parser.add_argument("--variants", nargs="*", choices=sorted(VARIANTS))
    parser.add_argument("--username", help="Apple ID for the request; default is synthetic .invalid")
    parser.add_argument("--client-info", help="override the X-MMe-Client-Info header")
    parser.add_argument("--user-agent", help="override the GSA User-Agent header")
    parser.add_argument("--delay", type=float, default=10.0, help="seconds between requests")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
