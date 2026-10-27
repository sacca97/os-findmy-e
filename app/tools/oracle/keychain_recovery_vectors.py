#!/usr/bin/env python3
"""Oracle vectors for the keychain recovery framing and blobs (`keychain/{escrow,recovery}.rs`).

    python app/tools/oracle/keychain_recovery_vectors.py [OUT_DIR]

Writes `fixtures/keychain/{keyvault,recovery,escrow}.json` by running the real Python. The KeyVault
message framing, the SRP-proof framing, the two blob layers and the escrow-record metadata parsing are
all offline and deterministic (fixed keys, IVs, salts, timestamps); the escrow proxy / Cuttlefish
network calls are not exercised. Nothing real is involved.
"""

from __future__ import annotations

import base64
import hashlib
import json
import plistlib
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from findmy.keychain import escrow as E
from findmy.keychain import recovery as R

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE.parent.parent / "android/app/src/test/resources/fixtures/keychain"


def det(label: str, n: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"{label}/{counter}".encode()).digest()
        counter += 1
    return out[:n]


def build(header: bytes, sections: list) -> bytes:
    return E.build_keyvault_message(header, sections)


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    out.mkdir(parents=True, exist_ok=True)

    # ----------------------------------------------------------------- keyvault framing
    header = det("kv-header", 16)
    sections = [b"", det("kv-s0", 8), det("kv-s1", 24), b"tail"]
    built = build(header, sections)
    built_footprint = build(header, [E.KeyVaultSection(det("kv-token", 8), footprint=20), det("kv-proof", 32)])

    parsed = {}
    for name, (data, hl, sc) in {
        "basic": (built, 16, 4),
        "two_sections": (build(det("h2", 12), [b"one", b"two"]), 12, 2),
        "footprint": (built_footprint, 16, 2),
    }.items():
        prefix, hdr, secs = E.split_keyvault_message(data, hl, sc)
        parsed[name] = {"header": hdr.hex(), "sections": [s.hex() for s in secs], "declared": int.from_bytes(prefix, "big")}

    kv_errors = {}
    for name, (data, hl, sc) in {
        "too_short": (b"\x00\x00", 16, 2),
        "section_past_end": (build(det("h", 8), [b"a"])[:12] + (9999).to_bytes(4, "big"), 8, 1),
    }.items():
        try:
            E.split_keyvault_message(data, hl, sc)
            kv_errors[name] = {"data": data.hex(), "error": None}
        except E.EscrowError:
            kv_errors[name] = {"data": data.hex(), "error": "EscrowError"}

    # ----------------------------------------------------------------- recovery
    challenge = R.RecoveryChallenge(
        label="com.apple.icdp.record.PEER-1",
        transaction_id="0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0",
        prefix=b"\x00\x00\x00\x00",
        header=det("rec-header", 24),
        exchange_token=det("rec-token", 8),
        salt=det("rec-salt", 32),
        server_public=det("rec-b", 256),
        dsid="1234567890",
        club_type_id=None,
    )
    challenge_club = R.RecoveryChallenge(**{**challenge.__dict__, "club_type_id": 1})
    proof = det("rec-proof", 32)

    # outer blob: CBC and GCM.
    session_key = det("rec-session", 32)
    inner = det("rec-inner", 64)
    iv = det("rec-iv", 16)

    def outer_cbc() -> bytes:
        padder = padding.PKCS7(128).padder()
        padded = padder.update(inner) + padder.finalize()
        enc = Cipher(algorithms.AES(session_key), modes.CBC(iv)).encryptor()
        ct = enc.update(padded) + enc.finalize()
        h = bytearray(24)
        h[4:8] = (0).to_bytes(4, "big")
        return build(bytes(h), [b"proof", iv, ct])

    def outer_gcm() -> bytes:
        enc = Cipher(algorithms.AES(session_key), modes.GCM(iv)).encryptor()
        body = enc.update(inner) + enc.finalize()
        h = bytearray(24)
        h[4:8] = (2).to_bytes(4, "big")
        return build(bytes(h), [b"proof", iv, body + enc.tag])

    # inner blob.
    passcode = "123456"
    iterations = 1000
    salt = det("rec-inner-salt", 20)
    derived = hashlib.pbkdf2_hmac("sha256", passcode.encode(), salt, iterations, 16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(inner) + padder.finalize()
    enc = Cipher(algorithms.AES(derived), modes.CBC(salt[:16])).encryptor()
    inner_ct = enc.update(padded) + enc.finalize()
    inner_header = bytearray(16)
    inner_header[8:12] = iterations.to_bytes(4, "big")
    inner_blob = build(bytes(inner_header), [b"", salt, b"", inner_ct, b"", b""])

    # srp_init reply framing.
    srp_blob = build(det("srp-header", 24), [det("srp-token", 8), challenge.salt, challenge.server_public])
    srp_response = {"respBlob": base64.b64encode(srp_blob).decode(), "dsid": "1234567890", "clubTypeID": None}
    parsed_challenge = R.parse_challenge(srp_response, challenge.label, challenge.transaction_id)

    recovery = {
        "proof": {
            "header": challenge.header.hex(),
            "exchange_token": challenge.exchange_token.hex(),
            "club_type_id": challenge.club_type_id,
            "proof": proof.hex(),
            "expected": R.build_recovery_proof(challenge, proof).hex(),
        },
        "proof_club": {
            "header": challenge_club.header.hex(),
            "exchange_token": challenge_club.exchange_token.hex(),
            "club_type_id": challenge_club.club_type_id,
            "proof": proof.hex(),
            "expected": R.build_recovery_proof(challenge_club, proof).hex(),
        },
        "outer_cbc": {
            "session_key": session_key.hex(),
            "club_type_id": None,
            "blob": outer_cbc().hex(),
            "inner": inner.hex(),
        },
        "outer_gcm": {
            "session_key": session_key.hex(),
            "club_type_id": None,
            "blob": outer_gcm().hex(),
            "inner": inner.hex(),
        },
        "inner": {
            "passcode": passcode,
            "blob": inner_blob.hex(),
            "material": inner.hex(),
        },
        "challenge": {
            "header": parsed_challenge.header.hex(),
            "exchange_token": parsed_challenge.exchange_token.hex(),
            "salt": parsed_challenge.salt.hex(),
            "server_public": parsed_challenge.server_public.hex(),
            "dsid": parsed_challenge.dsid,
            "club_type_id": parsed_challenge.club_type_id,
            "label": parsed_challenge.label,
            "transaction_id": parsed_challenge.transaction_id,
            "response": srp_response,
        },
    }
    (out / "keyvault.json").write_text(
        json.dumps({"built": built.hex(), "built_footprint": built_footprint.hex(), "parsed": parsed, "errors": kv_errors}, indent=1, sort_keys=True) + "\n"
    )
    (out / "recovery.json").write_text(json.dumps(recovery, indent=1, sort_keys=True) + "\n")

    # ----------------------------------------------------------------- escrow records
    def metadata(label: str, **over: object) -> bytes:
        meta = {
            "ClientMetadata": {
                "device_name": "Synthetic Mac",
                "device_model": "MacBookPro18,3",
                "device_model_class": "MacBookPro",
            },
            "serial": "C02SYNTHETIC",
            "build": "22F82",
            "com.apple.securebackup.timestamp": datetime(2024, 3, 1, 12, 0, tzinfo=timezone.utc),
            "bottleID": "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0",
        }
        meta.update(over)
        meta = {k: v for k, v in meta.items() if v is not None}
        return plistlib.dumps(meta)

    records = [
        ("com.apple.icdp.record.PEER-1", metadata("a")),
        ("com.apple.icdp.record.PEER-2", metadata("b", serial="C02SECOND", bottleID=None)),
        ("com.apple.icdp.record.PEER-3.double", metadata("c")),
    ]
    listed = [{"label": label, "metadata": base64.b64encode(meta).decode()} for label, meta in records]
    parsed_records = [E._parse_metadata(label, base64.b64encode(meta).decode()) for label, meta in records]  # noqa: SLF001
    listing = E.EscrowListing(records=parsed_records, unreadable=[], status=0, message=None)
    options = E.join_recovery_options(listing, ["com.apple.icdp.record.PEER-1"], partial_count=1)

    def rec_json(r: E.EscrowRecord) -> dict:
        return {
            "label": r.label, "peer_id": r.peer_id, "is_companion": r.is_companion,
            "companion_of": r.companion_of, "device_name": r.device_name, "device_model": r.device_model,
            "serial": r.serial, "build": r.build, "bottle_id": r.bottle_id,
            "escrowed_at": r.escrowed_at.isoformat() if r.escrowed_at else None,
            "is_recovery_candidate": r.is_recovery_candidate,
        }

    escrow = {
        "listed": listed,
        "records": [rec_json(r) for r in parsed_records],
        "options": {
            "recoverable": [rec_json(r) for r in options.recoverable],
            "described_but_not_viable": [rec_json(r) for r in options.described_but_not_viable],
            "viable_but_undescribed": options.viable_but_undescribed,
            "device_count": options.device_count,
            "viability_is_trustworthy": options.viability_is_trustworthy,
        },
    }
    (out / "escrow.json").write_text(json.dumps(escrow, indent=1, sort_keys=True, default=str) + "\n")

    print("wrote keyvault.json, recovery.json, escrow.json to", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
