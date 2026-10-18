//! The keys sealed inside a bottled peer (port of `findmy/keychain/bottle.py`, the read half:
//! `derive_bottle_keys`, `find_bottle_keys`, `parse_peer_private_key`, `open_bottle`).
//!
//! A recovered escrow record yields a *bottled peer*: the sealed identity of a device already in the
//! trust circle. Opening it borrows that device's identity. Everything here is offline once the
//! entropy is recovered; the escrow proxy and Cuttlefish calls that produce it are elsewhere.

use apple_proto::cuttlefish::{Bottle, OtBottle, OtInternalBottle};
use elliptic_curve::sec1::ToEncodedPoint;
use hkdf::Hkdf;
use num_bigint::BigUint;
use prost::Message;
use sha2::Sha384;

use crate::crypto::aes_gcm_decrypt;
use crate::error::{Error, Result};

pub const INFO_SYMMETRIC: &[u8] = b"Escrow Symmetric Key";
pub const INFO_SIGNING: &[u8] = b"Escrow Signing Private Key";
pub const INFO_ENCRYPTION: &[u8] = b"Escrow Encryption Private Key";
pub const SYMMETRIC_KEY_LENGTH: usize = 32;
pub const EC_KEY_MATERIAL_LENGTH: usize = 56;
pub const PEER_PUBLIC_POINT_LENGTH: usize = 97;
pub const PEER_PRIVATE_SCALAR_LENGTH: usize = 48;
pub const PEER_KEY_LENGTH: usize = PEER_PUBLIC_POINT_LENGTH + PEER_PRIVATE_SCALAR_LENGTH;
pub const GCM_TAG_LENGTH: usize = 16;

const P384_ORDER_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";

fn bottle_error(message: impl Into<String>) -> Error {
    Error::Backend(message.into())
}

fn p384_order() -> BigUint {
    BigUint::parse_bytes(P384_ORDER_HEX.as_bytes(), 16).unwrap()
}

/// The three keys a bottled peer is sealed under.
pub struct BottleKeys {
    /// 32 bytes. Opens the bottle, under AES-256-GCM.
    pub symmetric: Vec<u8>,
    /// P-384. Its public part must equal the bottle's escrowed signing key.
    pub signing: p384::SecretKey,
    /// P-384. Its public part must equal the bottle's escrowed encryption key.
    pub encryption: p384::SecretKey,
}

/// Convert 56 bytes into a P-384 scalar by FIPS 186-4 B.5.1 ("extra random bits").
fn scalar_from_extra_random_bits(material: &[u8]) -> Result<BigUint> {
    if material.len() != EC_KEY_MATERIAL_LENGTH {
        return Err(bottle_error(format!(
            "Expected {EC_KEY_MATERIAL_LENGTH} bytes of key material, got {}",
            material.len()
        )));
    }
    let order = p384_order();
    Ok((BigUint::from_bytes_be(material) % (&order - BigUint::from(1u8))) + BigUint::from(1u8))
}

fn private_key_from_material(material: &[u8]) -> Result<p384::SecretKey> {
    let scalar = scalar_from_extra_random_bits(material)?;
    let bytes = crate::reports::crypto::to_fixed(&scalar, PEER_PRIVATE_SCALAR_LENGTH);
    p384::SecretKey::from_slice(&bytes).map_err(|_| bottle_error("a derived P-384 scalar is invalid"))
}

fn hkdf(entropy: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha384>::new(Some(salt), entropy);
    let mut out = vec![0u8; length];
    hk.expand(info, &mut out).expect("HKDF length");
    out
}

/// Derive a bottled peer's three keys from its entropy (`derive_bottle_keys`).
pub fn derive_bottle_keys(entropy: &[u8], adsid: &str) -> Result<BottleKeys> {
    if entropy.is_empty() {
        return Err(bottle_error("Bottled peer entropy is empty; nothing to derive from"));
    }
    if adsid.is_empty() {
        return Err(bottle_error("The account identifier is the HKDF salt and cannot be empty"));
    }
    let salt = adsid.as_bytes();
    Ok(BottleKeys {
        symmetric: hkdf(entropy, salt, INFO_SYMMETRIC, SYMMETRIC_KEY_LENGTH),
        signing: private_key_from_material(&hkdf(entropy, salt, INFO_SIGNING, EC_KEY_MATERIAL_LENGTH))?,
        encryption: private_key_from_material(&hkdf(entropy, salt, INFO_ENCRYPTION, EC_KEY_MATERIAL_LENGTH))?,
    })
}

/// Render a key's public half every way a bottle might carry it.
pub fn public_key_encodings(key: &p384::SecretKey) -> Vec<(&'static str, Vec<u8>)> {
    use p384::pkcs8::EncodePublicKey;
    let public = key.public_key();
    let spki = public.to_public_key_der().map(|d| d.as_bytes().to_vec()).unwrap_or_default();
    vec![
        ("x962-uncompressed", public.to_encoded_point(false).as_bytes().to_vec()),
        ("x962-compressed", public.to_encoded_point(true).as_bytes().to_vec()),
        ("der-spki", spki),
    ]
}

/// The encoding under which a derived key equals an escrowed one, or `None`.
pub fn match_public_key(derived: &p384::SecretKey, escrowed: &[u8]) -> Option<&'static str> {
    public_key_encodings(derived)
        .into_iter()
        .find(|(_, encoded)| encoded.as_slice() == escrowed)
        .map(|(name, _)| name)
}

/// Check derived public keys against the ones the bottle carries.
pub fn keys_match_bottle(derived: &BottleKeys, escrowed_signing_key: &[u8], escrowed_encryption_key: &[u8]) -> bool {
    match_public_key(&derived.signing, escrowed_signing_key).is_some()
        && match_public_key(&derived.encryption, escrowed_encryption_key).is_some()
}

/// Derive the bottle's keys, trying each candidate salt until one matches (`find_bottle_keys`).
pub fn find_bottle_keys(
    entropy: &[u8],
    salts: &[String],
    escrowed_signing_key: &[u8],
    escrowed_encryption_key: &[u8],
) -> Result<(BottleKeys, String)> {
    let mut tried = 0usize;
    for salt in salts {
        if salt.is_empty() {
            continue;
        }
        tried += 1;
        let keys = derive_bottle_keys(entropy, salt)?;
        if keys_match_bottle(&keys, escrowed_signing_key, escrowed_encryption_key) {
            return Ok((keys, salt.clone()));
        }
    }
    Err(bottle_error(format!(
        "None of {tried} candidate salt(s) produced keys matching the ones this bottle escrowed ({} bytes each). \
         Either the passcode produced the wrong entropy, or the salt is a value not tried here.",
        escrowed_signing_key.len()
    )))
}

/// Read a peer's private key as a bottle carries it: the uncompressed point then the scalar (or the
/// reverse; the halves are checked against each other).
pub fn parse_peer_private_key(data: &[u8]) -> Result<p384::SecretKey> {
    if data.len() != PEER_KEY_LENGTH {
        return Err(bottle_error(format!(
            "A peer key is {PEER_KEY_LENGTH} bytes -- a {PEER_PUBLIC_POINT_LENGTH}-byte point and a \
             {PEER_PRIVATE_SCALAR_LENGTH}-byte scalar -- not {}",
            data.len()
        )));
    }
    let layouts: [(&str, &[u8], &[u8]); 2] = [
        ("point-then-scalar", &data[..PEER_PUBLIC_POINT_LENGTH], &data[PEER_PUBLIC_POINT_LENGTH..]),
        ("scalar-then-point", &data[PEER_PRIVATE_SCALAR_LENGTH..], &data[..PEER_PRIVATE_SCALAR_LENGTH]),
    ];
    for (name, point, scalar) in layouts {
        let Ok(key) = p384::SecretKey::from_slice(scalar) else { continue };
        if key.public_key().to_encoded_point(false).as_bytes() == point {
            let _ = name;
            return Ok(key);
        }
    }
    Err(bottle_error(
        "A peer key's halves do not agree: deriving a public key from the scalar does not reproduce the \
         point beside it, under either ordering.",
    ))
}

fn verify(signature: &[u8], signed: &[u8], key: Option<&p384::PublicKey>) -> bool {
    use p384::ecdsa::signature::Verifier;
    let Some(key) = key else { return false };
    if signature.is_empty() {
        return false;
    }
    let Ok(vk) = p384::ecdsa::VerifyingKey::from_sec1_bytes(&key.to_encoded_point(false).as_bytes().to_vec()) else {
        return false;
    };
    match p384::ecdsa::Signature::from_der(signature) {
        Ok(sig) => vk.verify(signed, &sig).is_ok(),
        Err(_) => false,
    }
}

/// A bottle's contents: the sponsoring peer's own private keys.
pub struct OpenedBottle {
    pub signing_key: Vec<u8>,
    pub encryption_key: Vec<u8>,
    pub signing_key_type: u32,
    pub encryption_key_type: u32,
    pub key_encoding: String,
    pub sponsor_known: bool,
    pub sponsor_verified: bool,
    pub escrowed_key_verified: bool,
}

impl OpenedBottle {
    pub fn signing(&self) -> Result<p384::SecretKey> {
        parse_peer_private_key(&self.signing_key)
    }

    pub fn encryption(&self) -> Result<p384::SecretKey> {
        parse_peer_private_key(&self.encryption_key)
    }
}

/// Open a bottle with the keys derived from its entropy.
pub fn open_bottle(
    bottle: &Bottle,
    keys: &BottleKeys,
    verify_keys: bool,
    sponsor: Option<&p384::PublicKey>,
) -> Result<OpenedBottle> {
    let payload = bottle.bottle.clone().ok_or_else(|| bottle_error("This bottle carries no sealed contents"))?;
    let inner = OtBottle::decode(payload.as_slice())
        .map_err(|e| bottle_error(format!("A bottle's sealed contents did not decode: {e}")))?;

    let mut encoding = "unchecked".to_string();
    if verify_keys {
        let signing_match = match_public_key(&keys.signing, inner.escrowed_signing_key.as_deref().unwrap_or(&[]));
        let encryption_match = match_public_key(&keys.encryption, inner.escrowed_encryption_key.as_deref().unwrap_or(&[]));
        match (signing_match, encryption_match) {
            (Some(s), Some(_)) => encoding = s.to_string(),
            _ => {
                return Err(bottle_error(
                    "The keys derived from the recovered entropy do not match the ones this bottle escrowed, \
                     which means the passcode produced the wrong entropy.",
                ))
            }
        }
    }

    use p384::pkcs8::DecodePublicKey;
    let escrowed_public = inner.escrowed_signing_key.as_deref().and_then(|b| {
        p384::PublicKey::from_public_key_der(b).ok().or_else(|| p384::PublicKey::from_sec1_bytes(b).ok())
    });
    let escrowed_verified = verify(
        bottle.escrowed_key_signature.as_deref().unwrap_or(&[]),
        &payload,
        escrowed_public.as_ref(),
    );
    let sponsor_verified = verify(bottle.peer_key_signature.as_deref().unwrap_or(&[]), &payload, sponsor);

    let sealed = inner.ciphertext.clone().ok_or_else(|| bottle_error("This bottle carries no ciphertext to open"))?;
    let ciphertext = sealed.ciphertext.clone().unwrap_or_default();
    if ciphertext.is_empty() {
        return Err(bottle_error("This bottle carries no ciphertext to open"));
    }
    let iv = sealed.initialization_vector.clone().unwrap_or_default();
    let tag = sealed.authentication_code.clone().unwrap_or_default();
    let plaintext = aes_gcm_decrypt(&keys.symmetric, &iv, &[], &ciphertext, &tag)
        .map_err(|_| bottle_error("The bottle did not authenticate under its symmetric key."))?;

    let contents = OtInternalBottle::decode(plaintext.as_slice())
        .map_err(|e| bottle_error(format!("A bottle opened but its contents did not decode: {e}")))?;
    let signing = contents.signing_key.unwrap_or_default();
    let encryption = contents.encryption_key.unwrap_or_default();
    Ok(OpenedBottle {
        signing_key: signing.key_data.unwrap_or_default(),
        encryption_key: encryption.key_data.unwrap_or_default(),
        signing_key_type: signing.key_type.unwrap_or(0),
        encryption_key_type: encryption.key_type.unwrap_or(0),
        key_encoding: encoding,
        sponsor_known: sponsor.is_some(),
        sponsor_verified,
        escrowed_key_verified: escrowed_verified,
    })
}
