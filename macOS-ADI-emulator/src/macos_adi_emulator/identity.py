from __future__ import annotations

import secrets

DEFAULT_CLIENT_INFO = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
_UDID_PREFIX = "00006000"
_SERIAL_ALPHABET = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def mint_identity() -> dict[str, str | int | None]:
    """Create the client identity used for macOS 26 ADI provisioning."""
    return {
        "device_id": f"{_UDID_PREFIX}-{secrets.token_hex(8).upper()}",
        "local_user_uuid": secrets.token_hex(16).upper(),
        "client_info": DEFAULT_CLIENT_INFO,
        "host_uuid": secrets.token_hex(16),
        "routing": None,
        "serial": "C02" + "".join(secrets.choice(_SERIAL_ALPHABET) for _ in range(9)),
    }
