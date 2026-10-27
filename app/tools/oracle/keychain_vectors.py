#!/usr/bin/env python3
"""Oracle vectors for the Kotlin/Rust keychain port (`keychain/bottle.rs`).

    python app/tools/oracle/keychain_vectors.py [OUT_DIR]

Writes `fixtures/keychain/bottle.json` by running the real Python (`findmy.keychain.bottle`) on fixed
synthetic inputs. The bottle cryptography (HKDF-SHA384, the P-384 extra-random-bits scalar, AES-256-GCM
with a detached tag, the two signatures) is self-contained and can be verified offline; the escrow
proxy / Cuttlefish network path is not exercised here. Nothing real is involved.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from findmy.keychain import bottle as B
HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE.parent.parent / "android/app/src/test/resources/fixtures/keychain"


def det(label: str, n: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"{label}/{counter}".encode()).digest()
        counter += 1
    return out[:n]


def key_json(key: ec.EllipticCurvePrivateKey) -> dict:
    point = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    compressed = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {"point": point.hex(), "compressed": compressed.hex(), "spki": spki.hex()}


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    out.mkdir(parents=True, exist_ok=True)

    entropy = det("bottle-entropy", 72)
    adsid = "000123-05-synthetic"
    signing_key = ec.derive_private_key(int.from_bytes(det("sign", 48), "big") % (2**383), ec.SECP384R1())
    encryption_key = ec.derive_private_key(int.from_bytes(det("enc", 48), "big") % (2**383), ec.SECP384R1())
    bottle_id = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0"
    peer_id = "SHA256:" + hashlib.sha256(b"peer").hexdigest().upper()

    keys = B.derive_bottle_keys(entropy, adsid)

    sealed = B.seal_bottle(
        peer_id=peer_id,
        signing_key=signing_key,
        encryption_key=encryption_key,
        entropy=entropy,
        adsid=adsid,
        bottle_id=bottle_id,
    )
    opened = B.open_bottle(sealed.bottle, keys)

    gcm_key = det("gcm-key", 32)
    gcm_iv = det("gcm-iv", 32)
    gcm_aad = b"BeaconStore-REC-1-name"
    gcm_pt = b"hello bottle, a secret"
    gcm_out = AESGCM(gcm_key).encrypt(gcm_iv, gcm_pt, gcm_aad)

    document = {
        "derive": {
            "entropy": entropy.hex(),
            "adsid": adsid,
            "symmetric": keys.symmetric.hex(),
            "signing": key_json(keys.signing),
            "encryption": key_json(keys.encryption),
        },
        "match": {
            "entropy": entropy.hex(),
            "adsid": adsid,
            "escrowed_signing": sealed.bottle.escrowed_signing_key.hex(),
            "escrowed_encryption": B._spki(keys.encryption).hex(),
        },
        "open": {
            "bottle": sealed.bottle.SerializeToString().hex(),
            "entropy": entropy.hex(),
            "adsid": adsid,
            "signing_key": opened.signing_key.hex(),
            "encryption_key": opened.encryption_key.hex(),
            "signing_key_type": opened.signing_key_type,
            "encryption_key_type": opened.encryption_key_type,
            "key_encoding": opened.key_encoding,
            "escrowed_key_verified": opened.escrowed_key_verified,
        },
        "gcm32": {
            "key": gcm_key.hex(),
            "iv": gcm_iv.hex(),
            "aad": gcm_aad.hex(),
            "plaintext": gcm_pt.hex(),
            "ciphertext": gcm_out[:-16].hex(),
            "tag": gcm_out[-16:].hex(),
        },
        "peer_key": {
            "material": opened.signing_key.hex(),
            "point": opened.signing().public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
            ).hex(),
            "scalar": opened.signing().private_numbers().private_value.to_bytes(48, "big").hex(),
        },
    }
    (out / "bottle.json").write_text(json.dumps(document, indent=1, sort_keys=True) + "\n")
    print("wrote", out / "bottle.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
