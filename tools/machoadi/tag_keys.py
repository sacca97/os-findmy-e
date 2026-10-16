"""Get your own tags' keys out of your own iCloud account, then fetch their locations.

Runs INSIDE a login (`auth_probe.py --tags ...`), because the CloudKit and keychain calls need the live
account object, not just the saved search-party token.

Path (all read-only; the library's `recover_service_keys` docstring: "nothing is created, signed or enrolled"):

  1. `AsyncKeychainSession.recovery_options()`: lists the escrow records the account holds. No passcode.
  2. YOU pick the record of a device whose screen-lock passcode you know, and type that passcode (hidden).
     It is the screen-lock passcode (PIN or Mac login password) of THAT device, not the Apple ID password.
  3. `recover()` opens the escrowed peer, `pcs_keys()` reads the keychain's key material,
     `AsyncBeaconStore.fetch_accessories()` decrypts the BeaconStore records into accessories (your tags).
  4. Each accessory's locations are fetched with the library's own fetcher and printed locally.

The one thing NOT done: `AsyncKeychainSession.join()`. It is the library's only irreversible call (adds a peer to
the keychain circle and an escrow record nothing displays) and its own docstring says reading does not need it.

Guard rails
  * The passcode is asked for once, only after you confirm the device by typing YES. A wrong passcode is NOT
    retried: Apple's escrow normally limits wrong guesses, so the script stops at the first failure.
  * `--tags-list` stops after step 1 (no passcode is ever requested).
  * Nothing secret is printed or logged. `--tags-save FILE` writes the accessories (their master keys are
    secrets) to FILE with mode 0600 so later fetches need no passcode.
"""

from __future__ import annotations

import getpass
import json
import os
from pathlib import Path


def _describe(record) -> str:  # noqa: ANN001
    try:
        return record.describe()
    except Exception:  # noqa: BLE001 - never let a cosmetic method break the listing
        return f"{getattr(record, 'device_name', '?')} / {getattr(record, 'device_model', '?')}"


async def run(account, *, list_only: bool = False, save: str | None = None, days: int = 7,  # noqa: ANN001, PLR0912
              ask=input, ask_secret=getpass.getpass, say=print) -> int:  # noqa: ANN001
    from findmy.cloudkit import AsyncBeaconStore  # noqa: PLC0415
    from findmy.keychain import session as ks  # noqa: PLC0415

    say("[tags] opening the keychain session (read-only)")
    session = await ks.AsyncKeychainSession.open(account)
    try:
        options = await session.recovery_options()
        records = list(options.recoverable)
        say(f"[tags] {len(records)} recoverable escrow record(s); "
            f"{len(options.described_but_not_viable)} not viable")
        for index, record in enumerate(records):
            say(f"  [{index}] {_describe(record)}")
        if list_only:
            say("[tags] --tags-list: stopping before any passcode is requested")
            return 0
        if not records:
            say("[tags] nothing recoverable: no device on this account can be recovered from")
            return 1

        choice = ask("Record number to recover from (the device whose screen-lock passcode you know): ").strip()
        if not choice.isdigit() or int(choice) >= len(records):
            say("[tags] not a valid record number; nothing was sent")
            return 1
        record = records[int(choice)]
        say(f"[tags] chosen: {_describe(record)}")
        say("[tags] This asks Apple to check ONE passcode guess against that device's escrow record. "
            "A wrong guess counts against a limit and is not retried here.")
        if ask("Type YES to continue: ").strip() != "YES":
            say("[tags] cancelled; nothing was sent")
            return 1
        passcode = ask_secret("Screen-lock passcode of that device (hidden): ")
        try:
            peer = await session.recover(record, passcode)
        finally:
            del passcode
        say("[tags] recovered the escrowed peer")

        keys = await session.pcs_keys(peer)
        say(f"[tags] {len(keys)} elliptic-curve key(s) read from the keychain views")
        store = AsyncBeaconStore(account)
        try:
            accessories = await store.fetch_accessories(keys)
        finally:
            await store.close()
        say(f"[tags] {len(accessories)} accessory/ies decrypted from the account")
        for number, accessory in enumerate(accessories):
            say(f"  ({number}) {accessory.name or '?'}  model {accessory.model or '?'}  "
                f"serial {accessory.serial_number or '?'}")

        if save and accessories:
            payload = [a.to_json() for a in accessories]
            fd = os.open(save, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(payload, stream, default=str)
            say(f"[tags] accessories (with their master keys) saved, mode 0600: {Path(save)}")

        for accessory in accessories:
            try:
                reports = await account.fetch_location_history(accessory)
            except Exception as error:  # noqa: BLE001 - report per tag, keep going
                say(f"[tags] {accessory.name or '?'}: location fetch failed: {type(error).__name__}: {error}")
                continue
            if isinstance(reports, dict):
                reports = [r for group in reports.values() for r in group]
            say(f"[tags] {accessory.name or '?'}: {len(reports)} report(s)")
            for report in sorted(reports, key=lambda r: r.timestamp)[-5:]:
                say(f"    {report.timestamp.isoformat()}  {report.latitude:.5f}, {report.longitude:.5f}  "
                    f"+-{report.horizontal_accuracy} m")
        return 0
    finally:
        await session.close()
