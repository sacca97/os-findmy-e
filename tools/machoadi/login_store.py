"""Persist a logged-in account, and bring it back without a login or a 2FA code.

The library's own `AsyncAppleAccount.to_json` cannot be used: the Mac provider refuses to serialize (its state
directory *is* the saved identity). So this saves the rest of the account -- ids, username, optionally the
password, the login state with its service tokens -- and `restore` puts it back onto the same machine.

**The file is a credential.** It holds the service tokens and (unless `keep_password=False`) the Apple ID password
in clear text, mode 0600, in a directory you choose. Anyone who can read it is you. Delete it when done:

    rm /tmp/macadi/rt1-login.json

Without the password the tokens still work for fetches; only calls that re-authenticate (the keychain session's
`request_pet`) need it, and the restoring tool then asks for it at run time (hidden), once.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def save(account, path: str | Path, *, keep_password: bool = True) -> Path:  # noqa: ANN001
    state = {
        "type": "account",
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "ids": {"uid": account._uid, "devid": account._devid},
        "account": {
            "username": account._username,
            "password": account._password if keep_password else None,
            "info": account._account_info,
            **({"device_name": account._device_name} if account._device_name is not None else {}),
        },
        "login": {"state": account._login_state.value, "data": account._login_state_data},
        "anisette": {},  # the machine state directory is the anisette; see restore()
    }
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(state, stream, indent=2)
    os.replace(tmp, path)
    return path


def restore(state_dir: str | Path, path: str | Path):  # noqa: ANN201
    """The saved account, on the machine that logged in. Refuses a file made on a different machine."""
    from findmy import AsyncAppleAccount  # noqa: PLC0415
    from provider import MacAnisetteProvider  # noqa: PLC0415

    value = json.loads(Path(path).read_text())
    if value.get("type") != "account":
        raise SystemExit(f"{path} is not a saved login")
    provider = MacAnisetteProvider(state_dir)
    if value["ids"]["devid"] != provider.identity_json["device_id"]:
        raise SystemExit(f"{path} was saved on a different machine than {state_dir}: "
                         "a login only works with the machine that made it")
    return AsyncAppleAccount(provider, timeout=30, state_info=value)
