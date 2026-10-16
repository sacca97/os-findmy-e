"""Get your own tags' keys out of your own iCloud account, then fetch their locations.

Runs INSIDE a login (`auth_probe.py --tags ...`), because the CloudKit and keychain calls need the live
account object, not just the saved search-party token.

Path (all read-only; the library's `recover_service_keys` docstring: "nothing is created, signed or enrolled"):

  1. `AsyncKeychainSession.recovery_options()`: lists the escrow records the account holds. No passcode.
  2. The record is chosen for you when there is only one (otherwise you pick); you type that device's passcode
     (hidden). It is the screen-lock passcode (PIN or Mac login password) of THAT device, not the Apple ID password.
  3. `recover()` opens the escrowed peer, `pcs_keys()` reads the keychain's key material,
     `AsyncBeaconStore.fetch_accessories()` decrypts the BeaconStore records into accessories (your tags).
  4. Each accessory's locations are fetched with the library's own fetcher and printed locally.

The one thing NOT done: `AsyncKeychainSession.join()`. It is the library's only irreversible call (adds a peer to
the keychain circle and an escrow record nothing displays) and its own docstring says reading does not need it.

Guard rails
  * The passcode is asked for once. A wrong passcode is NOT retried: Apple's escrow normally limits wrong
    guesses, so the script stops at the first failure.
  * `--tags-list` stops after step 1 (no passcode is ever requested).
  * Nothing secret is printed or logged. `--tags-save FILE` writes the accessories (their master keys are
    secrets) to FILE with mode 0600 so later fetches need no passcode.
"""

from __future__ import annotations

import getpass
import json
import os
import uuid
from pathlib import Path


class CloudKitIdentity:
    """The account, except that `device_uuid` is a real UUID, for the CloudKit clients only.

    The library's CloudKit client does `uuid.UUID(account.device_uuid)` and sends the value as CloudKit's
    device identifier. A Mac's `X-Mme-Device-Id` is the provisioning UDID (`00006000-` + 16 hex), which is not a
    UUID, so the client raised `ValueError: badly formed hexadecimal UUID string` before sending anything.
    CloudKit's identifier is a different thing from that header; the machine's host UUID (the IOPlatformUUID
    analogue our identity already carries) is the natural value. Everything else is forwarded to the real
    account, so the GSA requests, tokens and PET renewals still use the real `X-Mme-Device-Id`.
    """

    def __init__(self, account, device_uuid: str) -> None:  # noqa: ANN001
        self._account = account
        self._device_uuid = device_uuid

    @property
    def device_uuid(self) -> str:
        return self._device_uuid

    def __getattr__(self, name: str):  # noqa: ANN204
        return getattr(self._account, name)


def for_cloudkit(account):  # noqa: ANN001, ANN201
    """`account`, or a CloudKitIdentity over it when its device id is not a UUID."""
    try:
        uuid.UUID(account.device_uuid)
        return account
    except ValueError:
        pass
    host = getattr(getattr(account, "_anisette", None), "identity_json", {}).get("host_uuid")
    if not host:
        raise SystemExit("this account's device id is not a UUID and no host UUID is known to use instead")
    return CloudKitIdentity(account, str(uuid.UUID(host)).upper())


def _describe(record) -> str:  # noqa: ANN001
    try:
        return record.describe()
    except Exception:  # noqa: BLE001 - never let a cosmetic method break the listing
        return f"{getattr(record, 'device_name', '?')} / {getattr(record, 'device_model', '?')}"


async def read_accessories(store, keys, say=print) -> list:  # noqa: ANN001
    """What `store.fetch_accessories(keys)` does, step by step, saying what each step found.

    The library's one-call version drops what it cannot use *quietly* (a beacon with no private key is a device,
    not a tag; a record with no key held is someone else's). Here the counts are printed, so "my Chinese tag is
    missing" can be told from "it was never in the account": a tag paired through the Find My app is a master
    beacon with a private key; a clone flashed with its own keys is not in the account at all.
    No secret is printed: record types, counts, models, and whether a private key is present.
    """
    from findmy.cloudkit.beacons import (  # noqa: PLC0415
        accessories_from_records,
        can_be_located,
        decrypt_records,
        group_records,
    )

    zone_keys = await store.zone_keys(keys)
    records = await store.fetch_records()
    kinds: dict[str, int] = {}
    for record in records:
        kinds[record.record_type or "<untyped>"] = kinds.get(record.record_type or "<untyped>", 0) + 1
    say(f"[tags] fetched {len(records)} BeaconStore record(s): "
        + ", ".join(f"{n} x {kind}" for kind, n in sorted(kinds.items())))
    decrypted = decrypt_records(records, zone_keys,
                                default_master_keys=await store.zone_record_defaults(zone_keys))
    say(f"[tags] decrypted {len(decrypted)}; skipped: {dict(decrypted.skipped) or 'none'}")
    for group in group_records(decrypted):
        values = group.beacon.values
        secondary = [n for n in ("sharedSecret2", "secureLocationsSharedSecret") if isinstance(values.get(n), bytes)]
        say(f"  beacon model={values.get('model', '<none>')!r} secondary={'+'.join(secondary) or 'neither'} "
            f"private key={'yes' if can_be_located(group.beacon) else 'NO (a device, not a tag: dropped)'} "
            f"naming record={'yes' if group.naming else 'no'}")
    return accessories_from_records(decrypted)


async def run(account, *, list_only: bool = False, save: str | None = None, days: int = 7,  # noqa: ANN001, PLR0912
              ask=input, ask_secret=getpass.getpass, say=print) -> int:  # noqa: ANN001
    from findmy.cloudkit import AsyncBeaconStore  # noqa: PLC0415
    from findmy.keychain import session as ks  # noqa: PLC0415

    say("[tags] opening the keychain session (read-only)")
    ck_account = for_cloudkit(account)
    session = await ks.AsyncKeychainSession.open(ck_account)
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

        if len(records) == 1:
            record = records[0]
        else:
            choice = ask("Record number to recover from (the device whose screen-lock passcode you know): ").strip()
            if not choice.isdigit() or int(choice) >= len(records):
                say("[tags] not a valid record number; nothing was sent")
                return 1
            record = records[int(choice)]
        say(f"[tags] recovering from: {_describe(record)}")
        say("[tags] One passcode guess is sent and it is not retried: a wrong guess counts against Apple's limit "
            "on that device's escrow record.")
        passcode = ask_secret("Screen-lock passcode of that device (hidden): ")
        try:
            peer = await session.recover(record, passcode)
        finally:
            del passcode
        say("[tags] recovered the escrowed peer")

        keys = await session.pcs_keys(peer)
        say(f"[tags] {len(keys)} elliptic-curve key(s) read from the keychain views")
        store = AsyncBeaconStore(ck_account)
        try:
            accessories = await read_accessories(store, keys, say)
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
