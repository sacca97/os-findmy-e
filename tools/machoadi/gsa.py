#!/usr/bin/env python3
"""Apple GSA ``MidService`` machine-provisioning client.

The ADI library cannot provision itself: Apple's ``midStartProvisioning``
endpoint hands out a *server provisioning intermediate metadata* (SPIM) which
the library folds into a *client* provisioning intermediate metadata (CPIM),
and ``midFinishProvisioning`` turns that CPIM into the persistent token
metadata (PTM) and trust key (TK) the library stores locally.

The request shape mirrors Dadoum/Provision ``lib/provision/adi.d``
(``ProvisioningSession.provision``), which is what AuthKit itself sends:

    GET   <urls.midStartProvisioning>   -> {spim}
    POST  <?xml ...><plist><dict><key>Header</key><dict/>\
          <key>Request</key><dict/></dict></plist>
    POST  <urls.midFinishProvisioning>  -> {cpim} -> {ptm, tk, X-Apple-I-MD-RINFO}

Nothing here is authenticated: ``ds_id`` -2 is Apple's "local / no account"
pseudo-DSID, and the provisioning endpoints are the pre-auth ones every
anisette implementation drives.
"""

from __future__ import annotations

import plistlib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

LOOKUP_URL = "https://gsa.apple.com/grandslam/GsService2/lookup"

# AuthKit's own identifiers.
USER_AGENT = "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0"
DEFAULT_CLIENT_INFO = (
    "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
)
CLIENT_APP_NAME = "Setup"


class GSAError(RuntimeError):
    pass


def _apple_status(exc: urllib.error.HTTPError) -> str:
    """Apple's own `Status` (ec/em) from an error body, so a refusal is not reported as a bare code."""
    try:
        status = plistlib.loads(exc.read()).get("Response", {}).get("Status", {})
        return f" (ec {status['ec']}: {status.get('em', '')})"
    except Exception:  # noqa: BLE001 - the body is advisory; never mask the HTTP error
        return ""


# 429 is the one status seen that is a plain rate limit. 433 is NOT one, though it was first read as
# such (2026-10-15): finishMachineProvisioning answers 433 / ec -29002 for a device id that has
# already been provisioned, from any source and at any time, while a fresh id succeeds seconds
# later from the same IP. It is a verdict on the device id, so it falls through to the generic
# error below, which now carries Apple's own ec/em.
THROTTLE_CODES = frozenset({429})


@dataclass
class Device:
    """The per-"client device" values AuthKit passes in the request headers."""

    unique_device_id: str  # X-Mme-Device-Id
    client_info: str = DEFAULT_CLIENT_INFO  # X-MMe-Client-Info
    local_user_uuid: str = "00000000000000000000000000000000"  # X-Apple-I-MD-LU
    # X-Apple-I-SRL-NO, sent only when there is one. Provisioning used to send no serial at
    # all while `mac_anisette.headers()` sent one at login, so the identity Apple bound the
    # machine to and the identity used against it disagreed in exactly this one field. Which
    # of the two is right is not established; they only have to be the same one.
    serial: str | None = None


class GSA:
    def __init__(self, device: Device, *, timeout: float = 30.0) -> None:
        self.device = device
        self.timeout = timeout
        self.urls: dict[str, str] = {}
        # Apple serves a full chain but this machine's trust store does not
        # carry the Apple root, so verification is disabled *only* to work
        # around a local trust-store gap; the certificate is still Apple's.
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    # -- transport --------------------------------------------------------
    def _headers(self, *, client_time: bool = False) -> dict[str, str]:
        headers = {
            "User-Agent": USER_AGENT,
            # AuthKit really does send urlencoded for an XML plist body.
            "Content-Type": "application/x-www-form-urlencoded",
            "Connection": "keep-alive",
            "Accept": "*/*",
            "X-Mme-Device-Id": self.device.unique_device_id,
            "X-MMe-Client-Info": self.device.client_info,
            "X-Apple-I-MD-LU": self.device.local_user_uuid,
            "X-Apple-Client-App-Name": CLIENT_APP_NAME,
        }
        if self.device.serial:
            headers["X-Apple-I-SRL-NO"] = self.device.serial
        if client_time:
            headers["X-Apple-I-Client-Time"] = (
                datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            )
        return headers

    def _open(self, url: str, body: bytes | None, *, client_time: bool) -> bytes:
        req = urllib.request.Request(
            url,
            data=body,
            headers=self._headers(client_time=client_time),
            method="POST" if body is not None else "GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code in THROTTLE_CODES:
                raise GSAError(
                    f"HTTP {exc.code} from {url}: Apple is throttling this source. This is a rate "
                    f"limit, not a verdict -- the identical request succeeds after a cooldown, so "
                    f"read nothing into it."
                ) from exc
            raise GSAError(f"{exc.code} {exc.reason} from {url}{_apple_status(exc)}") from exc
        except urllib.error.URLError as exc:
            raise GSAError(f"{exc.reason} from {url}") from exc

    # -- protocol ---------------------------------------------------------
    def load_urlbag(self) -> dict[str, str]:
        raw = self._open(LOOKUP_URL, None, client_time=False)
        plist = plistlib.loads(raw)
        self.urls = dict(plist.get("urls", {}))
        if not self.urls:
            raise GSAError("URL bag contained no `urls` dictionary")
        return self.urls

    def _post_plist(self, url: str, request: dict) -> dict:
        body = plistlib.dumps({"Header": {}, "Request": request}, fmt=plistlib.FMT_XML)
        raw = self._open(url, body, client_time=True)
        try:
            plist = plistlib.loads(raw)
        except Exception as exc:  # noqa: BLE001
            raise GSAError(f"unparseable response from {url}: {raw[:200]!r}") from exc
        response = plist.get("Response")
        if response is None:
            raise GSAError(f"no Response in {url} reply: {plist!r}")
        return dict(response)

    def start_provisioning(self) -> bytes:
        """Return the SPIM (server provisioning intermediate metadata)."""
        url = self.urls.get("midStartProvisioning")
        if not url:
            raise GSAError("URL bag has no midStartProvisioning")
        response = self._post_plist(url, {})
        spim = response.get("spim")
        if not isinstance(spim, str):
            raise GSAError(f"midStartProvisioning gave no spim: {response!r}")
        import base64

        return base64.b64decode(spim)

    def finish_provisioning(self, cpim: bytes) -> dict:
        url = self.urls.get("midFinishProvisioning")
        if not url:
            raise GSAError("URL bag has no midFinishProvisioning")
        import base64

        response = self._post_plist(url, {"cpim": base64.b64encode(cpim).decode()})
        out: dict[str, object] = {
            "routing": int(response.get("X-Apple-I-MD-RINFO", 0) or 0),
        }
        for key, name in (("ptm", "ptm"), ("tk", "tk")):
            value = response.get(key)
            if not isinstance(value, str):
                raise GSAError(f"midFinishProvisioning gave no {key}: {response!r}")
            out[name] = base64.b64decode(value)
        return out
