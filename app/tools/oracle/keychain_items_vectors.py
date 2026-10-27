#!/usr/bin/env python3
"""Oracle vectors for the keychain items (`keychain/items.rs`).

    python app/tools/oracle/keychain_items_vectors.py [OUT_DIR]

Writes `fixtures/keychain/items.json`. Builds a synthetic `item` CloudKit record, wraps its own key under
a view key, encrypts a property list with the additional-data headers, and records the expected result.
All offline; nothing real is involved.
"""

from __future__ import annotations

import base64
import hashlib
import json
import plistlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from findmy.cloudkit import records as R
from findmy.cloudkit.proto import cloudkit_pb2 as ck
from findmy.keychain import items as I

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE.parent.parent / "android/app/src/test/resources/fixtures/keychain"

def det(label: str, n: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"{label}/{counter}".encode()).digest()
        counter += 1
    return out[:n]


def pad20(data: bytes) -> bytes:
    pad = (20 - (len(data) % 20)) % 20
    if pad == 0:
        pad = 20
    return data + b"\x80" + b"\x00" * (pad - 1)


def bytes_value(data: bytes) -> ck.Record.Value:
    return ck.Record.Value(type=1, bytes_value=data)


def string_value(text: str) -> ck.Record.Value:
    return ck.Record.Value(type=3, string_value=text)


def int_value(value: int) -> ck.Record.Value:
    return ck.Record.Value(type=7, signed_value=value)


def reference_value(name: str) -> ck.Record.Value:
    ref = ck.Reference()
    ref.record_identifier.value.name = name
    ref.record_identifier.value.type = ck.Identifier.RECORD
    return ck.Record.Value(type=9, reference_value=ref.SerializeToString())


def make_item(name: str, fields: list, record_type: str = "item") -> ck.Record:
    record = ck.Record()
    record.record_identifier.value.name = name
    record.record_identifier.value.type = ck.Identifier.RECORD
    record.type.name = record_type
    for field_name, value in fields:
        field = record.record_field.add()
        field.identifier.name = field_name
        field.value.CopyFrom(value)
    return record


def build_case(name: str, *, encver: int, extra_fields: list) -> dict:
    view_key = det(f"item-view-key/{name}", 64)
    view_uuid = f"VIEW-UUID-{name}"
    item_key = det(f"item-key/{name}", 64)
    iv = det(f"item-iv/{name}", 16)
    account = det(f"item-acct/{name}", 32)
    payload = det(f"item-payload/{name}", 70)

    plaintext = plistlib.dumps({"v_Data": payload, "acct": base64.b64encode(account).decode(), "class": "FINDMY"})

    fields = [
        ("acct", string_value(base64.b64encode(account).decode())),
        ("encver", int_value(encver)),
        ("gen", int_value(3)),
        ("parentkeyref", reference_value(view_uuid)),
        ("wrappedkey", bytes_value(AESSIV(view_key).encrypt(item_key, None))),
        *extra_fields,
    ]
    proto = make_item(name, fields)
    record = R.CloudKitRecord.from_proto(proto, "Manatee")

    # The item's `data` field: IV then AES-SIV(ciphertext) with the additional-data headers.
    additional = I.additional_data(record, view_uuid)
    headers = [iv, *additional]
    sealed = AESSIV(item_key).encrypt(pad20(plaintext), headers)

    proto.record_field.add().identifier.name = "data"
    proto.record_field[-1].value.CopyFrom(bytes_value(iv + sealed))

    return {
        "record": proto.SerializeToString().hex(),
        "view_key": view_key.hex(),
        "view_uuid": view_uuid,
        "v_data": payload.hex(),
        "acct": account.hex(),
        "additional_count": len(additional),
    }


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    out.mkdir(parents=True, exist_ok=True)

    pcs_public = det("item-pcs", 32)
    cases = [
        build_case("ITEM-ENCVER1", encver=1, extra_fields=[]),
        build_case(
            "ITEM-ENCVER2",
            encver=2,
            extra_fields=[
                ("pcsservice", string_value("ProtectedCloudStorage")),
                ("pcspublicidentity", bytes_value(det("item-pcs-id", 16))),
                ("pcspublickey", string_value("some-public-key")),
                ("agrp", string_value("com.apple.findmy")),
                ("class", string_value("FINDMY")),
                ("srvr", string_value("com.apple.icloud.searchpartyd")),
            ],
        ),
    ]
    document = {"cases": cases, "pcs_public": pcs_public.hex()}
    (out / "items.json").write_text(json.dumps(document, indent=1, sort_keys=True) + "\n")
    print("wrote", out / "items.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
