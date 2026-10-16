#!/usr/bin/env python3
"""A ``findmy`` Anisette provider backed by the emulated Mac CoreADI.

``MacAnisetteProvider`` is the bridge between the two halves of this project: the
genuine Mac ``CoreADI.framework``, running under Unicorn in ``mac_anisette.py``,
supplies the OTP and machine ID, and the ``findmy`` library drives the login with
them exactly as it would drive any other provider.

Two things matter here.

* **The values come from a fresh process.** Dispatches inside one Unicorn process
  eventually fault after ~8 ``RequestOTP`` calls, so the CLI is invoked as a
  subprocess and its answer reused for the rest of that 30-second OTP window --
  the OTP is a pure function of *(store, host uuid, window)*, so one call per
  window is all a request burst needs.

* **The identity is the provisioned one, in every header.** The emulator
  registered this machine with Apple's ``MidService`` under one client info, one
  device id and one local user id; ``AsyncAppleAccount`` has to be given that same
  ``uid``/``devid`` pair, and the provider has to describe the same platform. A
  login that presents a different identity is a different machine, and Apple is
  entitled to refuse it for reasons that have nothing to do with the lineage --
  see the "pass both or neither" note on the account constructor.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from findmy.reports.anisette import BaseAnisetteProvider, DeviceIdentity

CLI = Path(__file__).resolve().parent / "mac_anisette.py"

# The platform ``mac_anisette.py`` provisions under (``DEFAULT_CLIENT_INFO``).
# macOS 13.1 is build 22C65, Darwin 22.2.0, CFNetwork 1404.0.5 -- the six values
# are one release and are only correct together.
IDENTITY = DeviceIdentity(
    model="MacBookPro13,2",
    os_name="macOS",
    os_version="13.1",
    os_build="22C65",
    cfnetwork="1404.0.5",
    darwin="22.2.0",
)

WINDOW = 30  # seconds: the OTP only changes at a multiple of 30 of the Unix epoch


class MacAnisetteProvider(BaseAnisetteProvider):
    """OTP/machine ID from the emulated Mac CoreADI in ``state``."""

    def __init__(self, state: str | Path, *, timeout: float = 180.0) -> None:
        self._state = Path(state)
        identity_path = self._state / "identity.json"
        if not identity_path.exists():
            raise SystemExit(
                f"{identity_path} not found: provision first with\n"
                f"  .venv/bin/python {CLI} provision --state {self._state}"
            )
        # Kept for the account constructor: these two are the half of the identity
        # the headers do not carry, and they have to be the pair that provisioned.
        self.identity_json: dict = json.loads(identity_path.read_text())
        super().__init__(serial=self.identity_json["serial"], identity=IDENTITY)

        self._timeout = timeout
        self._window: int | None = None
        self._headers: dict[str, str] | None = None

    # -- the one place the emulator is asked anything ----------------------
    def _fetch(self) -> dict[str, str]:
        window = int(time.time()) // WINDOW
        if self._headers is None or window != self._window:
            done = subprocess.run(
                [sys.executable, str(CLI), "headers", "--state", str(self._state)],
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            if done.returncode != 0:
                raise SystemExit(f"mac_anisette.py headers failed:\n{done.stderr.strip()}")
            self._headers = json.loads(done.stdout)
            self._window = window
        return self._headers

    # -- the four values the library reads ---------------------------------
    @property
    def otp(self) -> str:
        return self._fetch()["X-Apple-I-MD"]

    @property
    def machine(self) -> str:
        return self._fetch()["X-Apple-I-MD-M"]

    @property
    def router(self) -> str:
        # Not 17106176 or 50660608: this is the routing Apple itself handed back
        # at provisioning, and it is what the machine is registered under.
        return str(self._fetch()["X-Apple-I-MD-RINFO"])

    @property
    def timestamp(self) -> str:
        # From the same call as the OTP, so the time beside it cannot describe a
        # different window than the OTP was minted for.
        return self._fetch()["X-Apple-I-Client-Time"]

    # -- lifecycle ---------------------------------------------------------
    async def close(self) -> None:
        # Nothing is held open: the emulator runs to completion inside `_fetch`, one
        # subprocess per OTP window, and leaves nothing behind but the store.
        self._headers = None
        self._window = None

    # -- persistence -------------------------------------------------------
    # An account cannot be restored onto this provider: the store is bound to a
    # host UUID and lives beside this file, so the state directory *is* the saved
    # identity. Serializing the provider would duplicate it, and a second copy
    # that drifts is worse than none.
    def to_json(self, dst: str | Path | None = None, /) -> dict:
        raise NotImplementedError("the Mac CoreADI state directory is the saved identity")

    @classmethod
    def from_json(cls, mapping):
        raise NotImplementedError("the Mac CoreADI state directory is the saved identity")
