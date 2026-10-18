//! The elliptic-curve and hash primitives of the Find My scheme (port of `findmy/util/crypto.py`'s
//! `x963_kdf` and `derive_ps_key`, `KeyPair.dh_exchange`, and the decryption in
//! `LocationReport.decrypt`; see also `apple/reports/ReportCrypto.kt`).

use aes::Aes128;
use aes_gcm::aead::generic_array::typenum::U16;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AesGcm, Nonce};
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::PrimeField;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Order of the P-224 group (`secp224r1`).
pub const N_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D";

pub const KEY_BYTES: usize = 28;
pub const POINT_BYTES: usize = 57;

pub fn n() -> BigUint {
    BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("P-224 order")
}

/// `0 < d < n`.
pub fn is_valid_private_scalar(d: &BigUint) -> bool {
    d > &BigUint::from(0u8) && d < &n()
}

/// The x coordinate of `d*G`, 28 bytes: the advertised key.
pub fn public_x(d: &BigUint) -> Vec<u8> {
    let scalar = scalar_from_biguint(d);
    let point = p224::ProjectivePoint::GENERATOR * scalar;
    let affine = point.to_affine();
    affine.to_encoded_point(false).x().expect("x coordinate").to_vec()
}

/// x963 KDF with SHA-256, one counter block per 32 bytes (`crypto.x963_kdf`).
pub fn x963_kdf(value: &[u8], shared_info: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    let mut counter: u32 = 1;
    while out.len() < length {
        let mut h = Sha256::new();
        h.update(value);
        h.update(counter.to_be_bytes());
        h.update(shared_info);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(length);
    out
}

/// `crypto.derive_ps_key`: the private key of an accessory for one secret key `sk` (SKN primary,
/// SKS secondary).
pub fn derive_ps_key(master_key: &[u8], sk: &[u8]) -> Vec<u8> {
    let priv_key = BigUint::from_bytes_be(master_key);
    let at = x963_kdf(sk, b"diversify", 72);
    let n = n();
    let n_minus_1 = &n - BigUint::from(1u8);
    let u = BigUint::from_bytes_be(&at[0..36]) % &n_minus_1 + BigUint::from(1u8);
    let v = BigUint::from_bytes_be(&at[36..72]) % &n_minus_1 + BigUint::from(1u8);
    let key = (u * priv_key + v) % n;
    to_fixed(&key, KEY_BYTES)
}

/// ECDH with an uncompressed 57-byte point (`04 || x || y`); the shared secret is the x coordinate.
pub fn ecdh(d: &BigUint, ephemeral_point: &[u8]) -> Result<Vec<u8>> {
    if ephemeral_point.len() != POINT_BYTES || ephemeral_point[0] != 4 {
        return Err(Error::Backend("bad ephemeral key".into()));
    }
    let encoded = p224::EncodedPoint::from_bytes(ephemeral_point)
        .map_err(|_| Error::Backend("bad ephemeral key".into()))?;
    let affine = Option::<p224::AffinePoint>::from(p224::AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| Error::Backend("bad ephemeral key".into()))?;
    let peer = p224::ProjectivePoint::from(affine);
    let scalar = scalar_from_biguint(d);
    let shared = (peer * scalar).to_affine();
    if bool::from(shared.is_identity()) {
        return Err(Error::Backend("bad ephemeral key".into()));
    }
    Ok(shared.to_encoded_point(false).x().expect("x coordinate").to_vec())
}

/// AES-128-GCM with a 16-byte IV, a 16-byte tag appended to the ciphertext and no AAD.
pub fn aes_gcm_decrypt(key: &[u8], iv: &[u8], ciphertext_and_tag: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 16 || iv.len() != 16 {
        return Err(Error::Backend("bad AES-GCM parameters".into()));
    }
    let cipher = AesGcm::<Aes128, U16>::new_from_slice(key).map_err(|_| Error::Backend("bad AES key".into()))?;
    let nonce = Nonce::<U16>::from_slice(iv);
    cipher
        .decrypt(nonce, ciphertext_and_tag)
        .map_err(|_| Error::Backend("authentication failed".into()))
}

/// Big-endian, left-padded to exactly `size` bytes (`int.to_bytes(size, "big")`).
pub fn to_fixed(value: &BigUint, size: usize) -> Vec<u8> {
    let raw = value.to_bytes_be();
    if raw.len() >= size {
        return raw[raw.len() - size..].to_vec();
    }
    let mut out = vec![0u8; size - raw.len()];
    out.extend_from_slice(&raw);
    out
}

fn scalar_from_biguint(d: &BigUint) -> p224::Scalar {
    let bytes = to_fixed(d, 28);
    let repr = p224::FieldBytes::clone_from_slice(&bytes);
    Option::<p224::Scalar>::from(p224::Scalar::from_repr(repr)).expect("scalar in range")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forked_refs() {
        // The P-224 generator's x, as a sanity check on the curve plumbing.
        let g = public_x(&BigUint::from(1u8));
        assert_eq!(g.len(), 28);
    }
}
