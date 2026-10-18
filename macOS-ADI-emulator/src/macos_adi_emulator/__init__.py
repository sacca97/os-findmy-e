"""Emulate Apple's macOS ADI daemon."""

from .adi import Adid, AdidError

__all__ = ["Adid", "AdidError"]
