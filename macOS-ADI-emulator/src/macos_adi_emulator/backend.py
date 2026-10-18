"""Anisette backend powered by the macOS ADI emulator."""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import zipfile
from pathlib import Path
from typing import BinaryIO

from . import provision

_DS_ID = -2
_STATE_FILES = ("identity.json", "provisioning.json", "store.json")
_ARCHIVE_MARKER = "anisette-backend.json"
_ARCHIVE_VERSION = 1


class Mac26Backend:
    """An Anisette.py backend backed by the existing macOS 26 emulator."""

    def __init__(self, state: str | Path | None = None, *, _state_owner: object | None = None) -> None:
        default_state = Path.home() / ".local" / "state" / "anisette-mac26"
        self.state = Path(state or os.environ.get("ANISETTE_MAC26_STATE", default_state))
        self._state_owner = _state_owner

    @property
    def is_provisioned(self) -> bool:
        return provision.boot(self.state).is_machine_provisioned(_DS_ID)

    def provision(self) -> None:
        if self.is_provisioned:
            return
        # Reuse the same provisioning flow as the package command without
        # sending command-line progress output to the calling application.
        with contextlib.redirect_stdout(io.StringIO()):
            result = provision.cmd_provision(self.state)
        if result != 0 or not self.is_provisioned:
            raise RuntimeError("macOS 26 Anisette provisioning did not complete")

    def get_data(self) -> dict[str, str]:
        self.provision()
        identity = provision.load_identity(self.state)
        daemon = provision.boot(self.state)
        headers = provision.headers_from(daemon, identity, identity.get("routing") or 0)
        provision.save_store(daemon, self.state)
        return headers

    def save_provisioning(self, file: BinaryIO | str | Path) -> None:
        self.provision()
        with zipfile.ZipFile(file, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(_ARCHIVE_MARKER, json.dumps({"provider": "mac26", "version": _ARCHIVE_VERSION}))
            for name in _STATE_FILES:
                path = self.state / name
                if path.is_file():
                    archive.write(path, name)
        if isinstance(file, (str, Path)):
            Path(file).chmod(0o600)

    def save_all(self, file: BinaryIO | str | Path) -> None:
        self.save_provisioning(file)

    def save_libs(self, file: BinaryIO | str | Path) -> None:
        raise NotImplementedError("The macOS 26 binary is provided separately.")

    @classmethod
    def load(cls, file: BinaryIO | str | Path) -> Mac26Backend:
        owner = tempfile.TemporaryDirectory(prefix="anisette-mac26-")
        state = Path(owner.name)
        state.chmod(0o700)
        try:
            with zipfile.ZipFile(file) as archive:
                marker = json.loads(archive.read(_ARCHIVE_MARKER))
                if marker != {"provider": "mac26", "version": _ARCHIVE_VERSION}:
                    raise ValueError("Unsupported macOS 26 Anisette session file")
                for name in _STATE_FILES:
                    if name in archive.namelist():
                        path = state / name
                        path.write_bytes(archive.read(name))
                        path.chmod(0o600)
        except Exception:
            owner.cleanup()
            raise
        if not (state / "store.json").is_file():
            owner.cleanup()
            raise ValueError("The saved Anisette session has no macOS 26 state")
        return cls(state, _state_owner=owner)
