#!/usr/bin/env python3
"""Oracle vectors for the keychain session end-to-end test (`keychain/session.rs`).

    python app/tools/oracle/keychain_session_vectors.py [OUT_DIR]

Writes `fixtures/keychain/session.json`. Builds a synthetic recoverable escrow record (a real sealed
bottle), a synthetic recoverable key share wrapped to the recovered peer's encryption key, and the
Cuttlefish responses that carry them. The Rust test plays the escrow proxy's SRP server side itself and
runs `recovery_options -> recover -> key_shares`, all offline. Nothing real is involved.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from findmy.cloudkit.proto import cloudkit_pb2 as ck
from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.keychain import bottle as B
from findmy.keychain import shares as S

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE.parent.parent / "android/app/src/test/resources/fixtures/keychain"


def det(label: str, n: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"{label}/{counter}".encode()).digest()
        counter += 1
    return out[:n]


def text(value: str) -> ck.Record.Value:
    return ck.Record.Value(type=3, string_value=value)


def raw(value: bytes) -> ck.Record.Value:
    return ck.Record.Value(type=1, bytes_value=value)


def num(value: int) -> ck.Record.Value:
    return ck.Record.Value(type=7, signed_value=value)


def record(name: str, record_type: str, fields: list) -> ck.Record:
    proto = ck.Record()
    proto.record_identifier.value.name = name
    proto.record_identifier.value.type = ck.Identifier.RECORD
    proto.type.name = record_type
    for field_name, value in fields:
        field = proto.record_field.add()
        field.identifier.name = field_name
        field.value.CopyFrom(value)
    return proto


def wrap(proto: ck.Record) -> cf.RecordWrapper:
    return cf.RecordWrapper(record=proto.SerializeToString())


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    out.mkdir(parents=True, exist_ok=True)

    entropy = det("session-entropy", 72)
    adsid = "000123-05-synthetic"
    password = "123456"
    label = "com.apple.icdp.record.SYNTHETIC-PEER"
    peer = "SYNTHETIC-PEER"
    bottle_id = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0"

    new_signing = ec.derive_private_key(int.from_bytes(det("session-sign", 48), "big") % (2**383), ec.SECP384R1())
    new_encryption = ec.derive_private_key(int.from_bytes(det("session-enc", 48), "big") % (2**383), ec.SECP384R1())
    created = B.seal_bottle(
        peer_id=peer,
        signing_key=new_signing,
        encryption_key=new_encryption,
        entropy=entropy,
        adsid=adsid,
        bottle_id=bottle_id,
    )
    keys = B.derive_bottle_keys(entropy, adsid)
    opened = B.open_bottle(created.bottle, keys)
    recovered_encryption = opened.encryption()

    # The recoverable share, wrapped to the recovered peer's encryption key.
    view_uuid = "VIEW-UUID-1"
    class_uuid = "CLASS-A-UUID"
    top_key = det("session-top-key", 64)
    class_key = det("session-class-key", 64)
    material = cf.TlkKeyMaterial(uuid=view_uuid, zone_name="Manatee", key=top_key)
    parts = S.sfies_encrypt(
        recovered_encryption.public_key(),
        material.SerializeToString(),
        ephemeral=ec.derive_private_key(int.from_bytes(det("session-ephemeral", 48), "big") % (2**383), ec.SECP384R1()),
    )
    archive = S.archive_sfies(parts)

    point = recovered_encryption.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    share_record = record(
        "SHARE-1",
        "tlkshare",
        [
            ("sender", text("SHA256:SENDER")),
            ("receiver", text(peer)),
            ("receiverPublicEncryptionKey", text(base64.b64encode(point).decode())),
            ("wrappedkey", text(base64.b64encode(archive).decode())),
            ("signature", text("")),
            ("curve", num(4)),
            ("epoch", num(1)),
            ("poisoned", num(0)),
            ("version", num(0)),
        ],
    )
    tlk_record = record(view_uuid, "synckey", [("class", text("tlk"))])
    class_record = record(
        class_uuid,
        "synckey",
        [("class", text("classA")), ("wrappedkey", raw(AESSIV(top_key).encrypt(class_key, None)))],
    )
    entry = cf.RecoverableTlkShare(service="Manatee")
    entry.share.CopyFrom(wrap(share_record))
    entry.viewkeys.tlk.CopyFrom(wrap(tlk_record))
    entry.viewkeys.class_a.CopyFrom(wrap(class_record))

    viable = cf.FetchViableBottlesResponse()
    viable.valid.add(id=label, bottle=created.bottle)
    shares = cf.FetchRecoverableTlkSharesResponse()
    shares.shares.append(entry.SerializeToString())
    changes = cf.FetchChangesResponse()
    changes.changes.sync_token = "token-1"

    document = {
        "passcode": password,
        "adsid": adsid,
        "entropy": entropy.hex(),
        "label": label,
        "bottle_id": bottle_id,
        "peer": peer,
        "serial": "C02SYNTHETIC",
        "device_name": "Synthetic Mac",
        "viable_response": viable.SerializeToString().hex(),
        "changes_response": changes.SerializeToString().hex(),
        "shares_response": shares.SerializeToString().hex(),
        "view_uuid": view_uuid,
        "class_uuid": class_uuid,
        "expected_view_key": top_key.hex(),
        "expected_class_key": class_key.hex(),
    }
    (out / "session.json").write_text(json.dumps(document, indent=1, sort_keys=True) + "\n")
    print("wrote", out / "session.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
