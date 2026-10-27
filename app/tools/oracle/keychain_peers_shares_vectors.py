#!/usr/bin/env python3
"""Oracle vectors for the keychain peers and shares (`keychain/{peers,shares}.rs`).

    python app/tools/oracle/keychain_peers_shares_vectors.py [OUT_DIR]

Writes `fixtures/keychain/{peers,shares}.json`. The peer identifier, public-key loading, NSKeyedArchiver
reading, SFIES, the class-key unwrap and the share signed-data construction are all offline; the
Cuttlefish/CloudKit network calls are not exercised. Nothing real is involved.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.keychain import peers as P
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


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    out.mkdir(parents=True, exist_ok=True)

    # ----------------------------------------------------------------- peers
    signing = ec.derive_private_key(int.from_bytes(det("sign", 48), "big") % (2**383), ec.SECP384R1())
    encryption = ec.derive_private_key(int.from_bytes(det("enc", 48), "big") % (2**383), ec.SECP384R1())
    permanent_signature = det("permanent-signature", 96)
    permanent = cf.PeerPermanentInfo(
        epoch=1,
        signing_key=signing.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint),
        encryption_key=encryption.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint),
        machine_id="SYNTH-MACHINE",
        model_id="MacBookPro18,3",
    )
    permanent_info = permanent.SerializeToString()
    peer_hash = P.peer_identifier(permanent_info, permanent_signature)

    peer = cf.CuttlefishPeer(hash=peer_hash)
    peer.permanent_info.info = permanent_info
    peer.permanent_info.signature = permanent_signature
    peer.stable_info.info = cf.PeerStableInfo(clock=7).SerializeToString()
    peer.dynamic_info.info = cf.PeerDynamicInfo(clock=9, includeds=["SHA256:X"], excludeds=["SHA256:Y"]).SerializeToString()

    changes = cf.CuttlefishChanges(sync_token="token-1")
    changes.changes.add().add.CopyFrom(peer)
    # A change that is not an add, which must be ignored.
    changes.changes.add()

    def pk_json(key: ec.EllipticCurvePrivateKey) -> dict:
        pub = key.public_key()
        return {
            "uncompressed": pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex(),
            "compressed": pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint).hex(),
            "spki": pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo).hex(),
        }

    peers_doc = {
        "identifier": {"permanent_info": permanent_info.hex(), "signature": permanent_signature.hex(), "peer_id": peer_hash},
        "public_keys": [
            {"key": pk_json(signing), "loaded": signing.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()},
            {"key": pk_json(ec.derive_private_key(12345, ec.SECP256R1())), "loaded": ec.derive_private_key(12345, ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()},
            {"garbage": "00", "loaded": None},
        ],
        "changes": changes.SerializeToString().hex(),
        "directory": {
            "sync_token": "token-1",
            "peers": [
                {
                    "hash": peer_hash,
                    "signing_key": signing.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex(),
                    "permanent_info": permanent_info.hex(),
                    "permanent_signature": permanent_signature.hex(),
                    "stable_clock": 7,
                    "dynamic_clock": 9,
                    "includeds": ["SHA256:X"],
                    "excludeds": ["SHA256:Y"],
                    "hash_is_derivable": True,
                }
            ],
        },
    }
    (out / "peers.json").write_text(json.dumps(peers_doc, indent=1, sort_keys=True) + "\n")

    # ----------------------------------------------------------------- shares
    receiver = ec.derive_private_key(int.from_bytes(det("receiver", 48), "big") % (2**383), ec.SECP384R1())
    ephemeral = ec.derive_private_key(int.from_bytes(det("ephemeral", 48), "big") % (2**383), ec.SECP384R1())
    plaintext = det("share-plaintext", 80)
    parts = S.sfies_encrypt(receiver.public_key(), plaintext, ephemeral=ephemeral)
    archive = S.archive_sfies(parts)

    receiver_b64 = base64.b64encode(receiver.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode()
    material = cf.TlkKeyMaterial()
    material.key = det("view-tlk", 64)
    material.uuid = "VIEW-UUID-1"
    material.zone_name = "Manatee"
    share = cf.TlkShare(
        service="Manatee",
        key_id="VIEW-UUID-1",
        curve=4,
        epoch=1,
        sender="SHA256:SENDER",
        receiver="SHA256:RECEIVER",
        receiver_public_encryption_key=receiver_b64,
        wrapped_key=base64.b64encode(archive).decode(),
        signature=base64.b64encode(det("share-signature", 96)).decode(),
    )

    class_key = det("class-key", 64)
    top_key = det("top-key", 64)
    wrapped_class = AESSIV(top_key).encrypt(class_key, None)

    shares_doc = {
        "sfies": {
            "receiver_private": receiver.private_numbers().private_value.to_bytes(48, "big").hex(),
            "receiver_point": receiver.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex(),
            "plaintext": plaintext.hex(),
            "point": parts.point.hex(),
            "ciphertext": parts.ciphertext.hex(),
            "code": parts.code.hex(),
            "archive": archive.hex(),
        },
        "class_key": {
            "top_level": top_key.hex(),
            "wrapped": wrapped_class.hex(),
            "unwrapped": class_key.hex(),
        },
        "share_signed_data": {
            "share": {
                "sender": share.sender,
                "receiver": share.receiver,
                "receiver_public_encryption_key": share.receiver_public_encryption_key,
                "wrapped_key": share.wrapped_key,
                "signature": share.signature,
                "curve": share.curve,
                "epoch": share.epoch,
                "poisoned": share.poisoned,
                "version": share.version,
            },
            "signed_data": S.share_signed_data(S.ShareRecord(
                sender=share.sender,
                receiver=share.receiver,
                receiver_public_encryption_key=base64.b64decode(share.receiver_public_encryption_key),
                wrapped_key=base64.b64decode(share.wrapped_key),
                signature=base64.b64decode(share.signature),
                curve=share.curve,
                epoch=share.epoch,
                poisoned=share.poisoned,
                version=share.version,
            )).hex(),
        },
        "material": {
            "uuid": material.uuid,
            "key": material.key.hex(),
            "serialized": material.SerializeToString().hex(),
        },
    }
    (out / "shares.json").write_text(json.dumps(shares_doc, indent=1, sort_keys=True) + "\n")

    print("wrote peers.json and shares.json to", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
