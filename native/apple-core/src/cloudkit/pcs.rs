//! Protected Cloud Storage: the read path of `findmy/cloudkit/pcs.py` and `apple/cloudkit/Pcs.kt`
//! (key derivation, structure parsing, unwrapping including `meta` and the zone level, field
//! decryption). The write half (`encrypt_field`) is not part of the app.

use std::collections::HashMap;

use aes::cipher::{BlockEncrypt, KeyInit};
use elliptic_curve::sec1::ToEncodedPoint;
use aes::Aes128;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};

use crate::cloudkit::der::{self, DerElement};
use crate::cloudkit::servicekeys;
use crate::error::{Error, Result};

pub const MASTER_KEY_LENGTH: usize = 16;
pub const LABEL_SHARE_KEY: &[u8] = b"MsaeEooevaX fooo 012";
pub const LABEL_HMAC_KEY: &[u8] = b"hmackey-of-masterkey";
pub const LABEL_KEY_ID: &[u8] = b"master key id labell";
pub const LABEL_ENCRYPTION_KEY: &[u8] = b"encryption key key m";
pub const KEY_ID_INPUT: &[u8] = b"M key input data 2 u";
const MASTER_EC_SALT: &[u8] = b"full master key";
const MASTER_EC_ITERATIONS: u32 = 10;
const MASTER_EC_LENGTH: usize = 128;
pub const ENCRYPTION_VERSION: u8 = 3;
pub const GCM_IV_LENGTH: usize = 12;
pub const GCM_TAG_LENGTH: usize = 12;
const SIGNATURE_DATA_VERSION_NO_SHARE_KEY: u32 = 5;

pub const SIGNATURE_ABSENT: &str = "the structure carries no signature data at all";
pub const SIGNATURE_UNPARSEABLE: &str = "its signature data would not parse";
pub const SIGNATURE_WRONG_SIGNER: &str = "every signature names a signer other than this record's master EC key";
pub const SIGNATURE_REJECTED: &str = "the signature parsed, named the right key, and did not verify over the signed data";

fn pcs_error(message: impl Into<String>) -> Error {
    Error::Backend(message.into())
}

/// RFC 6637's parameter block as PCS builds it.
fn rfc6637_param() -> Vec<u8> {
    let mut out = vec![8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    out.extend_from_slice(&[0x12, 0x03, 0x01, 0x08, 0x07]);
    out.extend_from_slice(b"Anonymous Sender    ");
    out.extend_from_slice(b"fingerprint");
    out.extend_from_slice(&[0u8; 9]);
    out
}

/// The two curves PCS key material uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcsCurve {
    P256,
    P384,
}

impl PcsCurve {
    pub fn size(self) -> usize {
        match self {
            PcsCurve::P256 => 32,
            PcsCurve::P384 => 48,
        }
    }

    pub fn order(self) -> BigUint {
        let hex = match self {
            PcsCurve::P256 => "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            PcsCurve::P384 => "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        };
        BigUint::parse_bytes(hex.as_bytes(), 16).unwrap()
    }

    pub fn name(self) -> &'static str {
        match self {
            PcsCurve::P256 => "secp256r1",
            PcsCurve::P384 => "secp384r1",
        }
    }

    pub fn of_scalar_length(length: usize) -> Option<PcsCurve> {
        [PcsCurve::P256, PcsCurve::P384].into_iter().find(|c| c.size() == length)
    }
}

/// An elliptic-curve private key as the PCS code handles it: a curve and a scalar, with the public
/// point computed on demand. Secret: never logged.
#[derive(Clone)]
pub struct PcsKey {
    pub curve: PcsCurve,
    pub d: BigUint,
}

impl PcsKey {
    pub fn new(curve: PcsCurve, d: BigUint) -> Result<PcsKey> {
        if d == BigUint::from(0u8) || d >= curve.order() {
            return Err(pcs_error("scalar out of range"));
        }
        Ok(PcsKey { curve, d })
    }

    pub fn from_scalar(curve: PcsCurve, scalar: &[u8]) -> Option<PcsKey> {
        PcsKey::new(curve, BigUint::from_bytes_be(scalar)).ok()
    }

    pub fn fixed(value: &BigUint, size: usize) -> Vec<u8> {
        let raw = value.to_bytes_be();
        if raw.len() >= size {
            raw[raw.len() - size..].to_vec()
        } else {
            let mut out = vec![0u8; size - raw.len()];
            out.extend_from_slice(&raw);
            out
        }
    }

    pub fn scalar_bytes(&self) -> Vec<u8> {
        PcsKey::fixed(&self.d, self.curve.size())
    }

    pub fn uncompressed(&self) -> Vec<u8> {
        match self.curve {
            PcsCurve::P256 => {
                let sk = p256::SecretKey::from_slice(&self.scalar_bytes()).unwrap();
                sk.public_key().to_encoded_point(false).as_bytes().to_vec()
            }
            PcsCurve::P384 => {
                let sk = p384::SecretKey::from_slice(&self.scalar_bytes()).unwrap();
                sk.public_key().to_encoded_point(false).as_bytes().to_vec()
            }
        }
    }

    pub fn compressed(&self) -> Vec<u8> {
        match self.curve {
            PcsCurve::P256 => {
                let sk = p256::SecretKey::from_slice(&self.scalar_bytes()).unwrap();
                sk.public_key().to_encoded_point(true).as_bytes().to_vec()
            }
            PcsCurve::P384 => {
                let sk = p384::SecretKey::from_slice(&self.scalar_bytes()).unwrap();
                sk.public_key().to_encoded_point(true).as_bytes().to_vec()
            }
        }
    }

    pub fn bare_x(&self) -> Vec<u8> {
        let u = self.uncompressed();
        u[1..1 + self.curve.size()].to_vec()
    }

    /// Every way this protocol writes a public key (`pcs.public_key_forms`): compressed,
    /// uncompressed, bare x, x|y.
    pub fn public_key_forms(&self) -> Vec<Vec<u8>> {
        let u = self.uncompressed();
        vec![
            self.compressed(),
            u.clone(),
            u[1..1 + self.curve.size()].to_vec(),
            u[1..].to_vec(),
        ]
    }

    /// ECDH: the x coordinate of d * peer, where `peer` is the peer's bare x coordinate.
    pub fn shared_x(&self, peer_x: &[u8]) -> Result<Vec<u8>> {
        let mut sec1 = vec![0x02];
        sec1.extend_from_slice(peer_x);
        match self.curve {
            PcsCurve::P256 => {
                let peer = p256::PublicKey::from_sec1_bytes(&sec1)
                    .map_err(|_| pcs_error("Ephemeral point is not on P-256"))?;
                let secret = p256::SecretKey::from_slice(&self.scalar_bytes()).unwrap();
                let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
                Ok(shared.raw_secret_bytes().to_vec())
            }
            PcsCurve::P384 => {
                let peer = p384::PublicKey::from_sec1_bytes(&sec1)
                    .map_err(|_| pcs_error("Ephemeral point is not on P-384"))?;
                let secret = p384::SecretKey::from_slice(&self.scalar_bytes()).unwrap();
                let shared = p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
                Ok(shared.raw_secret_bytes().to_vec())
            }
        }
    }

    pub fn verify_ecdsa_sha256(&self, signature: &[u8], data: &[u8]) -> bool {
        use p256::ecdsa::signature::Verifier;
        match self.curve {
            PcsCurve::P256 => {
                let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.compressed()) else {
                    return false;
                };
                let Ok(sig) = p256::ecdsa::Signature::from_der(signature) else {
                    return false;
                };
                vk.verify(data, &sig).is_ok()
            }
            PcsCurve::P384 => {
                use p384::ecdsa::signature::Verifier;
                let Ok(vk) = p384::ecdsa::VerifyingKey::from_sec1_bytes(&self.compressed()) else {
                    return false;
                };
                let Ok(sig) = p384::ecdsa::Signature::from_der(signature) else {
                    return false;
                };
                vk.verify(data, &sig).is_ok()
            }
        }
    }
}

impl std::fmt::Debug for PcsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PcsKey({}, <redacted>)", self.curve.name())
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = if key.is_empty() { vec![0u8; 64] } else { key.to_vec() };
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("HMAC");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// NIST SP 800-108 counter mode, HMAC-SHA256: `be32(i) | label | 00 | be32(bits)`, i from 1.
pub fn derive_key(master_key: &[u8], label: &[u8], length: Option<usize>) -> Vec<u8> {
    let n = length.filter(|l| *l != 0).unwrap_or(master_key.len());
    let mut out = Vec::new();
    let mut counter = 1u32;
    while out.len() < n {
        let mut input = be32(counter).to_vec();
        input.extend_from_slice(label);
        input.push(0);
        input.extend_from_slice(&be32((n as u32) * 8));
        out.extend_from_slice(&hmac_sha256(master_key, &input));
        counter += 1;
    }
    out.truncate(n);
    out
}

pub fn compute_key_id(master_key: &[u8]) -> Vec<u8> {
    hmac_sha256(&derive_key(master_key, LABEL_KEY_ID, None), KEY_ID_INPUT)
}

pub fn derive_encryption_key(master_key: &[u8]) -> Vec<u8> {
    derive_key(master_key, LABEL_ENCRYPTION_KEY, Some(MASTER_KEY_LENGTH))
}

pub fn derive_hmac_key(master_key: &[u8]) -> Vec<u8> {
    derive_key(master_key, LABEL_HMAC_KEY, None)
}

/// The master EC scalar: PBKDF2 x10 to 128 bytes, reversed, low 256 bits kept, one conditional
/// subtraction.
pub fn derive_master_ec_scalar(master_key: &[u8]) -> Result<BigUint> {
    let mut raw = vec![0u8; MASTER_EC_LENGTH];
    pbkdf2_hmac::<Sha256>(master_key, MASTER_EC_SALT, MASTER_EC_ITERATIONS, &mut raw);
    let order = PcsCurve::P256.order();
    raw.reverse();
    let mut value = BigUint::from_bytes_be(&raw);
    let mask = (BigUint::from(1u8) << order.bits() as usize) - BigUint::from(1u8);
    value = value & mask;
    if value > order {
        value -= &order;
    }
    if value == BigUint::from(0u8) || value >= order {
        return Err(pcs_error("Derived master EC scalar is out of range for P-256"));
    }
    Ok(value)
}

pub fn master_ec_key(master_key: &[u8]) -> Result<PcsKey> {
    PcsKey::new(PcsCurve::P256, derive_master_ec_scalar(master_key)?)
}

pub fn master_ec_keys(master_keys: &[Vec<u8>]) -> Result<Vec<PcsKey>> {
    master_keys.iter().map(|k| master_ec_key(k)).collect()
}

// --------------------------------------------------------------------------------------- structures

#[derive(Debug, Clone)]
pub struct ShareKey {
    pub key_type: BigUint,
    pub public_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub flags: Option<BigUint>,
}

impl ShareKey {
    pub fn read_only(&self) -> bool {
        self.flags.as_ref().map(|f| f.bit(0)).unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
pub struct SignatureData {
    pub version: BigUint,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PcsSignature {
    pub key_id: Vec<u8>,
    pub digest: BigUint,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PcsAttribute {
    pub key: BigUint,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ObjectSignature {
    pub roll_count: BigUint,
    pub outer_sign_key_type: BigUint,
    pub public_key_type: BigUint,
    pub public_key: Vec<u8>,
    pub signature: PcsSignature,
    pub symm_key_count: Option<BigUint>,
    pub signature2: Option<PcsSignature>,
    pub ec_key_list_der: Vec<u8>,
    pub attributes_der: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ShareProtection {
    pub keys: Vec<ShareKey>,
    pub meta: Vec<u8>,
    pub signature_data: SignatureData,
    pub hmac: Vec<u8>,
    pub truncated_key_id: Vec<u8>,
    pub signature: Option<PcsSignature>,
    pub attributes: Vec<PcsAttribute>,
    pub keyset_der: Vec<u8>,
    pub signature_data_der: Vec<u8>,
}

pub fn parse_signature(element: &DerElement) -> Result<PcsSignature> {
    let parts = element.children()?;
    Ok(PcsSignature {
        key_id: parts.first().map(|p| p.as_bytes().to_vec()).unwrap_or_default(),
        digest: parts.get(1).map(|p| p.as_uint()).unwrap_or_else(|| BigUint::from(0u8)),
        signature: parts.get(2).map(|p| p.as_bytes().to_vec()).unwrap_or_default(),
    })
}

impl ObjectSignature {
    pub fn from_der(data: &[u8]) -> Result<ObjectSignature> {
        let (element, _) = der::parse_one(data, 0)?;
        let parts = element.children()?;
        if parts.len() < 4 {
            return Err(pcs_error(format!("ObjectSignature has {} members, expected at least 4", parts.len())));
        }
        let key_ref = parts[2].children()?;
        if key_ref.len() < 2 {
            return Err(pcs_error("ObjectSignature's public key reference is incomplete"));
        }
        let mut symm = None;
        let mut sig2 = None;
        let mut ec_key_list = Vec::new();
        let mut attributes = Vec::new();
        for extra in &parts[4..] {
            if extra.is_context(0) {
                symm = Some(extra.unwrap_one()?.as_uint());
            } else if extra.is_context(1) {
                sig2 = Some(parse_signature(&extra.unwrap_one()?)?);
            } else if extra.is_context(2) {
                ec_key_list = extra.unwrap_one()?.raw;
            } else if extra.is_context(3) {
                attributes = extra.unwrap_one()?.raw;
            }
        }
        Ok(ObjectSignature {
            roll_count: parts[0].as_uint(),
            outer_sign_key_type: parts[1].as_uint(),
            public_key_type: key_ref[0].as_uint(),
            public_key: key_ref[1].as_bytes().to_vec(),
            signature: parse_signature(&parts[3])?,
            symm_key_count: symm,
            signature2: sig2,
            ec_key_list_der: ec_key_list,
            attributes_der: attributes,
        })
    }
}

impl ShareProtection {
    pub fn from_der(data: &[u8]) -> Result<ShareProtection> {
        let sequence = der::expect_application(data, 1).map_err(|e| pcs_error(e.to_string()))?;
        let mut keys = Vec::new();
        let mut keyset_der = Vec::new();
        let mut meta = Vec::new();
        let mut signature_data = None;
        let mut signature_data_der = Vec::new();
        let mut hmac = Vec::new();
        let mut truncated = Vec::new();
        let mut signature = None;
        let mut attributes = Vec::new();
        for element in sequence.children()? {
            if element.is_universal(der::TAG_SEQUENCE) && keyset_der.is_empty() {
                keys = parse_keyset(&element)?;
                keyset_der = element.raw.clone();
            } else if element.is_context(0) {
                meta = element.unwrap_one()?.as_bytes().to_vec();
            } else if element.is_context(1) {
                let inner = element.unwrap_one()?;
                let parts = inner.children()?;
                signature_data = Some(SignatureData {
                    version: parts.first().map(|p| p.as_uint()).unwrap_or_else(|| BigUint::from(0u8)),
                    data: parts.get(1).map(|p| p.as_bytes().to_vec()).unwrap_or_default(),
                });
                signature_data_der = inner.raw.clone();
            } else if element.is_universal(der::TAG_OCTET_STRING) {
                hmac = element.as_bytes().to_vec();
            } else if element.is_context(2) {
                truncated = element.unwrap_one()?.as_bytes().to_vec();
            } else if element.is_context(3) {
                signature = Some(parse_signature(&element.unwrap_one()?)?);
            } else if element.is_context(4) {
                let children = element.unwrap_one()?.children()?;
                for child in children {
                    let p = child.children()?;
                    attributes.push(PcsAttribute {
                        key: p.first().map(|x| x.as_uint()).unwrap_or_else(|| BigUint::from(0u8)),
                        value: p.get(1).map(|x| x.as_bytes().to_vec()).unwrap_or_default(),
                    });
                }
            }
        }
        let signature_data = signature_data.ok_or_else(|| pcs_error("Protection structure carries no signature data"))?;
        Ok(ShareProtection {
            keys,
            meta,
            signature_data,
            hmac,
            truncated_key_id: truncated,
            signature,
            attributes,
            keyset_der,
            signature_data_der,
        })
    }
}

fn parse_keyset(element: &DerElement) -> Result<Vec<ShareKey>> {
    let mut out = Vec::new();
    for child in element.children()? {
        if !child.is_universal(der::TAG_SET) {
            continue;
        }
        for entry in child.children()? {
            let parts = entry.children()?;
            if parts.len() < 2 {
                return Err(pcs_error(format!("ShareKey has {} members, expected at least 2", parts.len())));
            }
            let key_ref = parts[0].children()?;
            if key_ref.len() < 2 {
                return Err(pcs_error("KeyRef is missing its public key"));
            }
            out.push(ShareKey {
                key_type: key_ref[0].as_uint(),
                public_key: key_ref[1].as_bytes().to_vec(),
                ciphertext: parts[1].as_bytes().to_vec(),
                flags: parts.get(2).map(|p| p.as_uint()),
            });
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Default)]
pub struct MetaContents {
    pub symmetric_keys: Vec<Vec<u8>>,
    pub private_keys: Vec<PcsKey>,
}

/// A record's master key and how it was reached. Secret.
pub struct UnwrappedProtection {
    pub master_key: Vec<u8>,
    pub share_key_derived: bool,
    pub read_only: bool,
    pub hmac_verified: bool,
    pub signature_verified: Option<bool>,
    pub meta: MetaContents,
}

impl UnwrappedProtection {
    pub fn bare(master_key: Vec<u8>) -> UnwrappedProtection {
        UnwrappedProtection {
            master_key,
            share_key_derived: false,
            read_only: false,
            hmac_verified: false,
            signature_verified: None,
            meta: MetaContents::default(),
        }
    }

    pub fn master_keys(&self) -> Vec<Vec<u8>> {
        let mut out = vec![self.master_key.clone()];
        out.extend(self.meta.symmetric_keys.clone());
        out
    }
}

/// Which field a ciphertext belongs to; authenticated as `zone-record-field`.
#[derive(Debug, Clone, Default)]
pub struct FieldContext {
    pub zone_name: String,
    pub record_name: String,
    pub field_name: String,
}

impl FieldContext {
    pub fn none() -> FieldContext {
        FieldContext::default()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        if self.zone_name.is_empty() && self.record_name.is_empty() && self.field_name.is_empty() {
            Vec::new()
        } else {
            format!("{}-{}-{}", self.zone_name, self.record_name, self.field_name).into_bytes()
        }
    }
}

// --------------------------------------------------------------------------------------- unwrap

fn split_wrapped_key(ciphertext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if ciphertext.len() < 3 {
        return Err(pcs_error(format!(
            "Wrapped key is {} bytes, too short to carry an MPI",
            ciphertext.len()
        )));
    }
    let point_bits = ((ciphertext[0] as usize) << 8) | ciphertext[1] as usize;
    let point_end = 2 + point_bits.div_ceil(8);
    if ciphertext.len() <= point_end {
        return Err(pcs_error(format!(
            "Wrapped key claims a {point_bits}-bit point but is only {} bytes",
            ciphertext.len()
        )));
    }
    let point = ciphertext[2..point_end].to_vec();
    let wrapped_length = ciphertext[point_end] as usize;
    let end = ciphertext.len().min(point_end + 1 + wrapped_length);
    let wrapped = ciphertext[point_end + 1..end].to_vec();
    if wrapped.len() != wrapped_length {
        return Err(pcs_error(format!(
            "Wrapped key claims {wrapped_length} bytes but only {} remain",
            wrapped.len()
        )));
    }
    Ok((point, wrapped))
}

fn unframe_master_key(plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() < 4 {
        return Err(pcs_error(format!(
            "Unwrapped material is {} bytes, too short to be framed",
            plaintext.len()
        )));
    }
    if plaintext[0] != 1 {
        return Err(pcs_error(format!(
            "Unwrapped material announces algorithm {}, expected 1",
            plaintext[0]
        )));
    }
    let padding = plaintext[plaintext.len() - 1] as usize;
    let key_length = plaintext.len() as isize - padding as isize - 3;
    if key_length <= 0 || padding == 0 || padding > plaintext.len() - 3 {
        return Err(pcs_error("Unwrapped material has an implausible padding length"));
    }
    let key_length = key_length as usize;
    let key = plaintext[1..1 + key_length].to_vec();
    let checksum = ((plaintext[1 + key_length] as u16) << 8) | plaintext[2 + key_length] as u16;
    if key.iter().map(|b| *b as u32).sum::<u32>() % 65536 != checksum as u32 {
        return Err(pcs_error(
            "Unwrapped key fails its checksum; the key-encryption key is wrong",
        ));
    }
    for b in &plaintext[3 + key_length..] {
        if *b as usize != padding {
            return Err(pcs_error("Unwrapped material's padding is malformed"));
        }
    }
    Ok(key)
}

/// RFC 6637 ECDH key wrap: shared x -> SHA-256 KEK -> RFC 3394 unwrap -> framed master key.
pub fn unwrap_share_key(private_key: &PcsKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let (point, wrapped) = split_wrapped_key(ciphertext)?;
    if private_key.curve != PcsCurve::P256 {
        return Err(pcs_error(format!(
            "A {} key cannot agree with a P-256 point",
            private_key.curve.name()
        )));
    }
    let shared = private_key.shared_x(&point)?;
    let mut digest = Sha256::new();
    digest.update(be32(1));
    digest.update(&shared);
    digest.update(rfc6637_param());
    let kek = digest.finalize();
    if wrapped.len() < 24 || wrapped.len() % 8 != 0 {
        return Err(pcs_error("AES key unwrap failed its integrity check"));
    }
    let kek_arr: [u8; 16] = kek[..16].try_into().unwrap();
    let kw = aes_kw::KekAes128::from(kek_arr);
    let mut plaintext = vec![0u8; wrapped.len() - 8];
    kw.unwrap(&wrapped, &mut plaintext)
        .map_err(|_| pcs_error("AES key unwrap failed its integrity check. Either this entry is not for us, or the KEK was derived differently."))?;
    unframe_master_key(&plaintext)
}

fn u32_bytes(value: &BigUint) -> Result<[u8; 4]> {
    if value.bits() > 32 {
        return Err(pcs_error("A signed-data integer does not fit 32 bits"));
    }
    Ok(be32(value.try_into().unwrap_or(0u32)))
}

pub fn build_signed_data(protection: &ShareProtection, signature: &ObjectSignature) -> Result<Vec<u8>> {
    let mut out = protection.keyset_der.clone();
    out.extend_from_slice(&protection.meta);
    out.extend_from_slice(&u32_bytes(&signature.outer_sign_key_type)?);
    out.extend_from_slice(&u32_bytes(&signature.roll_count)?);
    out.extend_from_slice(&u32_bytes(signature.symm_key_count.as_ref().unwrap_or(&BigUint::from(0u8)))?);
    out.extend_from_slice(&u32_bytes(&signature.public_key_type)?);
    out.extend_from_slice(&signature.public_key);
    out.extend_from_slice(&signature.attributes_der);
    out.extend_from_slice(&signature.ec_key_list_der);
    Ok(out)
}

/// `None` when a signature verified, otherwise one of the four reasons.
pub fn describe_protection_signature(protection: &ShareProtection, master_key: &[u8]) -> Option<&'static str> {
    if protection.signature_data.data.is_empty() {
        return Some(SIGNATURE_ABSENT);
    }
    let object_signature = match ObjectSignature::from_der(&protection.signature_data.data) {
        Ok(s) => s,
        Err(_) => return Some(SIGNATURE_UNPARSEABLE),
    };
    let public_key = match master_ec_key(master_key) {
        Ok(k) => k,
        Err(_) => return Some(SIGNATURE_UNPARSEABLE),
    };
    let signed = match build_signed_data(protection, &object_signature) {
        Ok(s) => s,
        Err(_) => return Some(SIGNATURE_UNPARSEABLE),
    };
    let mut considered = 0;
    for candidate in [Some(&object_signature.signature), object_signature.signature2.as_ref()].into_iter().flatten() {
        if !candidate.key_id.is_empty() && candidate.key_id != public_key.compressed() {
            continue;
        }
        considered += 1;
        if public_key.verify_ecdsa_sha256(&candidate.signature, &signed) {
            return None;
        }
    }
    if considered > 0 {
        Some(SIGNATURE_REJECTED)
    } else {
        Some(SIGNATURE_WRONG_SIGNER)
    }
}

pub fn verify_protection_hmac(protection: &ShareProtection, master_key: &[u8]) -> bool {
    if protection.hmac.is_empty() {
        return false;
    }
    let mut input = protection.keyset_der.clone();
    input.extend_from_slice(&protection.meta);
    input.extend_from_slice(&protection.signature_data.data);
    let expected = hmac_sha256(&derive_hmac_key(master_key), &input);
    let n = protection.hmac.len();
    constant_time_eq(&expected[..n.min(expected.len())], &protection.hmac)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn find_our_key(protection: &ShareProtection, private_keys: &[PcsKey]) -> Result<(ShareKey, PcsKey)> {
    let mut by_public: HashMap<Vec<u8>, PcsKey> = HashMap::new();
    for key in private_keys {
        for form in key.public_key_forms() {
            by_public.insert(form, key.clone());
        }
    }
    for share_key in &protection.keys {
        if let Some(key) = by_public.get(&share_key.public_key) {
            return Ok((share_key.clone(), key.clone()));
        }
    }
    let theirs: std::collections::BTreeSet<usize> = protection.keys.iter().map(|k| k.public_key.len()).collect();
    let ours: std::collections::BTreeSet<usize> = private_keys
        .iter()
        .flat_map(|k| k.public_key_forms().into_iter().map(|f| f.len()))
        .collect();
    let named = protection
        .keys
        .iter()
        .take(4)
        .map(|k| crate::util::hex(&k.public_key[..k.public_key.len().min(8)]))
        .collect::<Vec<_>>()
        .join(", ");
    Err(Error::Backend(format!(
        "None of the {} key(s) held locally appears among the {} entries protecting this record. \
         Their public keys are {theirs:?} bytes; the forms compared against are {ours:?}. The record names: {named}",
        private_keys.len(),
        protection.keys.len()
    )))
}

/// Recover a structure's master key with the keys held. HMAC and signature are reported, not required.
pub fn unwrap_protection(protection: &ShareProtection, private_keys: &[PcsKey]) -> Result<UnwrappedProtection> {
    let (share_key, private_key) = find_our_key(protection, private_keys)?;
    let mut master_key = unwrap_share_key(&private_key, &share_key.ciphertext)?;
    let derived = protection.signature_data.version != BigUint::from(SIGNATURE_DATA_VERSION_NO_SHARE_KEY) && !share_key.read_only();
    if derived {
        master_key = derive_key(&master_key, LABEL_SHARE_KEY, None);
    }
    if !protection.truncated_key_id.is_empty() {
        let key_id = compute_key_id(&master_key);
        let n = protection.truncated_key_id.len().min(key_id.len());
        if key_id[..n] != protection.truncated_key_id[..n] {
            return Err(pcs_error(
                "Recovered a key, but its key id does not match the one the protection structure carries.",
            ));
        }
    }
    let hmac_verified = verify_protection_hmac(protection, &master_key);
    let signature_verified = if share_key.read_only() {
        None
    } else {
        Some(describe_protection_signature(protection, &master_key).is_none())
    };
    let meta = read_meta(&protection.meta, &master_key);
    Ok(UnwrappedProtection {
        master_key,
        share_key_derived: derived,
        read_only: share_key.read_only(),
        hmac_verified,
        signature_verified,
        meta,
    })
}

/// The zone's structure, opened with the keychain keys, gives the keys its records name.
pub fn unwrap_zone(protection_info: &[u8], service_keys: &[PcsKey]) -> Result<Vec<PcsKey>> {
    let protection = ShareProtection::from_der(protection_info)?;
    let unwrapped = unwrap_protection(&protection, service_keys)?;
    let mut keys = unwrapped.meta.private_keys.clone();
    keys.extend(master_ec_keys(&unwrapped.master_keys())?);
    if keys.is_empty() {
        return Err(pcs_error(format!(
            "The zone's protection structure unwrapped but yields no elliptic-curve keys ({} symmetric key(s)).",
            unwrapped.meta.symmetric_keys.len()
        )));
    }
    Ok(keys)
}

pub fn unwrap_zone_record_defaults(record_protection_info: &[u8], zone_keys: &[PcsKey]) -> Result<Vec<Vec<u8>>> {
    let protection = ShareProtection::from_der(record_protection_info)?;
    Ok(unwrap_protection(&protection, zone_keys)?.master_keys())
}

pub fn select_default_master_key(master_keys: &[Vec<u8>], pcs_key: &[u8]) -> Option<Vec<u8>> {
    if pcs_key.is_empty() {
        return if master_keys.len() == 1 { Some(master_keys[0].clone()) } else { None };
    }
    master_keys.iter().find_map(|key| {
        let id = compute_key_id(key);
        if pcs_key.len() <= id.len() && id[..pcs_key.len()] == *pcs_key {
            Some(key.clone())
        } else {
            None
        }
    })
}

// --------------------------------------------------------------------------------------- meta

pub fn read_meta(meta: &[u8], master_key: &[u8]) -> MetaContents {
    if meta.is_empty() {
        return MetaContents::default();
    }
    let plaintext = match decrypt_field(meta, &UnwrappedProtection::bare(master_key.to_vec()), &FieldContext::none(), false) {
        Ok(p) => p,
        Err(_) => return MetaContents::default(),
    };
    parse_meta(&plaintext).unwrap_or_default()
}

pub fn parse_meta(plaintext: &[u8]) -> Result<MetaContents> {
    let (mut element, _) = der::parse_one(plaintext, 0)?;
    if element.tag_class == der::CLASS_APPLICATION && element.constructed {
        if let Ok(inner) = element.unwrap_one() {
            element = inner;
        }
    }
    let mut symmetric = Vec::new();
    let mut private = Vec::new();
    for child in element.children()? {
        if child.is_context(0) {
            for key in child.unwrap_one()?.children()? {
                symmetric.push(key.as_bytes().to_vec());
            }
        } else if child.is_context(2) {
            for identity in child.unwrap_one()?.children()? {
                private.extend(identity_keys(&identity, 6));
            }
        }
    }
    Ok(MetaContents { symmetric_keys: symmetric, private_keys: private })
}

fn members_of(element: &DerElement) -> Vec<DerElement> {
    if !element.constructed {
        return Vec::new();
    }
    element.children().unwrap_or_default()
}

fn identity_keys(identity: &DerElement, depth: usize) -> Vec<PcsKey> {
    if depth == 0 {
        return Vec::new();
    }
    let mut keys = Vec::new();
    for member in members_of(identity) {
        if !member.is_universal(der::TAG_SET) {
            if let Ok(found) = servicekeys::keys_from_der(&member.raw) {
                keys.extend(found);
            }
        }
        if member.constructed {
            keys.extend(identity_keys(&member, depth - 1));
            continue;
        }
        if let Ok((nested, _)) = der::parse_one(member.as_bytes(), 0) {
            keys.extend(identity_keys(&nested, depth - 1));
        }
    }
    keys
}

// --------------------------------------------------------------------------------------- fields

#[derive(Debug, Clone)]
pub struct EncryptedField {
    pub version: u8,
    pub key_id: Vec<u8>,
    pub header: Vec<u8>,
    pub iv: Vec<u8>,
    pub tag: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub fn parse_encrypted_field(data: &[u8]) -> Result<EncryptedField> {
    if data.len() < 4 {
        return Err(pcs_error(format!(
            "Encrypted field is {} bytes, too short to carry a header",
            data.len()
        )));
    }
    let version = data[0];
    if version != ENCRYPTION_VERSION {
        return Err(pcs_error(format!(
            "Encrypted field announces version {version}, and only version {ENCRYPTION_VERSION} is described"
        )));
    }
    let header_length = 4 + data[3] as usize;
    if data.len() < header_length + GCM_IV_LENGTH + GCM_TAG_LENGTH {
        return Err(pcs_error("Encrypted field is truncated: header, IV and tag do not fit"));
    }
    let header = data[..header_length].to_vec();
    let mut key_id = data[1..3].to_vec();
    key_id.extend_from_slice(&data[4..header_length]);
    let body = header_length;
    Ok(EncryptedField {
        version,
        key_id,
        header,
        iv: data[body..body + GCM_IV_LENGTH].to_vec(),
        tag: data[body + GCM_IV_LENGTH..body + GCM_IV_LENGTH + GCM_TAG_LENGTH].to_vec(),
        ciphertext: data[body + GCM_IV_LENGTH + GCM_TAG_LENGTH..].to_vec(),
    })
}

/// AES-128-GCM, 12-byte tag before the ciphertext, AAD = header | context.
pub fn decrypt_field(
    data: &[u8],
    unwrapped: &UnwrappedProtection,
    context: &FieldContext,
    check_key_id: bool,
) -> Result<Vec<u8>> {
    let parsed = parse_encrypted_field(data)?;
    if check_key_id && !parsed.key_id.is_empty() {
        let expected = compute_key_id(&unwrapped.master_key);
        if parsed.key_id.len() > expected.len() || expected[..parsed.key_id.len()] != parsed.key_id[..] {
            return Err(pcs_error(
                "This field is encrypted under a different key than the one recovered from the record's protection structure.",
            ));
        }
    }
    let key = derive_encryption_key(&unwrapped.master_key);
    let mut aad = parsed.header.clone();
    aad.extend_from_slice(&context.as_bytes());
    gcm_decrypt(&key, &parsed.iv, &aad, &parsed.ciphertext, &parsed.tag).map_err(|_| {
        pcs_error(format!(
            "Field '{}' of record '{}' failed to authenticate.",
            context.field_name, context.record_name
        ))
    })
}

// ------------------------------------------------------------------- AES-128-GCM (12-byte tag)

fn aes_encrypt_block(key: &[u8], block: &mut [u8; 16]) {
    let cipher = Aes128::new_from_slice(key).expect("AES key");
    let mut b = aes::Block::clone_from_slice(block);
    cipher.encrypt_block(&mut b);
    block.copy_from_slice(&b);
}

fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> u128 {
    use ghash::{GHash, Key};
    use universal_hash::{KeyInit, UniversalHash};
    let mut g = GHash::new(Key::from_slice(h));
    let mut feed = |data: &[u8]| {
        if data.is_empty() {
            return;
        }
        let mut padded = data.to_vec();
        while padded.len() % 16 != 0 {
            padded.push(0);
        }
        let blocks: Vec<ghash::Block> = padded.chunks(16).map(|c| *ghash::Block::from_slice(c)).collect();
        g.update(&blocks);
    };
    feed(aad);
    feed(ciphertext);
    let mut len = [0u8; 16];
    len[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    g.update(&[*ghash::Block::from_slice(&len)]);
    let out: [u8; 16] = g.finalize().into();
    u128::from_be_bytes(out)
}

fn inc32(block: &mut [u8; 16]) {
    let mut counter = u32::from_be_bytes(block[12..16].try_into().unwrap());
    counter = counter.wrapping_add(1);
    block[12..16].copy_from_slice(&counter.to_be_bytes());
}

fn gcm_decrypt(key: &[u8], iv: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    if iv.len() != 12 || tag.len() != 12 {
        return Err(pcs_error("bad GCM parameters"));
    }
    let mut h_block = [0u8; 16];
    aes_encrypt_block(key, &mut h_block);

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;

    let s = ghash(&h_block, aad, ciphertext);
    let mut mask = j0;
    aes_encrypt_block(key, &mut mask);
    let full = u128::from_be_bytes(mask) ^ s;
    let expected = full.to_be_bytes();
    if !constant_time_eq(&expected[..12], tag) {
        return Err(pcs_error("authentication failed"));
    }

    let mut out = Vec::with_capacity(ciphertext.len());
    let mut counter = j0;
    for chunk in ciphertext.chunks(16) {
        inc32(&mut counter);
        let mut keystream = counter;
        aes_encrypt_block(key, &mut keystream);
        for (i, byte) in chunk.iter().enumerate() {
            out.push(byte ^ keystream[i]);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod gcm_tests {
    use super::gcm_decrypt;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn aes_block_vector() {
        let key = hx("000102030405060708090a0b0c0d0e0f");
        let mut block = [0u8; 16];
        block.copy_from_slice(&hx("00112233445566778899aabbccddeeff"));
        super::aes_encrypt_block(&key, &mut block);
        assert_eq!(hex(&block), "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    /// Our 12-byte-tag GCM must agree with the `aes-gcm` crate (a 16-byte tag standard
    /// implementation) on the truncated tag, including with AAD.
    #[test]
    fn gcm_agrees_with_the_reference() {
        use aes_gcm::aead::generic_array::typenum::U12;
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::AesGcm;
        type G = AesGcm<aes::Aes128, U12>;
        let key = hx("000102030405060708090a0b0c0d0e0f");
        let iv = hx("101112131415161718191a1b");
        let aad = hx("426561636f6e53746f72652d5245432d312d6e616d65");
        let pt = hx("68656c6c6f206669656c642c20612073656372657421");
        let cipher = G::new_from_slice(&key).unwrap();
        let out = cipher.encrypt(aes_gcm::Nonce::from_slice(&iv), Payload { msg: &pt, aad: &aad }).unwrap();
        let (ct, tag) = out.split_at(out.len() - 16);
        let plain = gcm_decrypt(&key, &iv, &aad, ct, &tag[..12]).expect("tag");
        assert_eq!(plain, pt);
        // A flipped tag byte must fail.
        let mut bad = tag[..12].to_vec();
        bad[0] ^= 1;
        assert!(gcm_decrypt(&key, &iv, &aad, ct, &bad).is_err());
    }
}
