//! The private-key CHOICE a protection structure's meta nests its identity keys in (port of the
//! subset of `findmy/keychain/servicekey.py` that `pcs._identity_keys` reaches, and
//! `apple/cloudkit/ServiceKeyReader.kt`).

use apple_proto::cuttlefish::PcsServiceKeys;
use prost::Message;

use crate::cloudkit::der;
use crate::cloudkit::pcs::{PcsCurve, PcsKey};
use crate::cloudkit::records::iterate_wire_fields;

const PRIVATE_KEY_V2_TAG: u32 = 5;

#[derive(Debug, Clone)]
pub enum ServiceKeyError {
    /// An item's key material cannot be read.
    Service(String),
    /// A 64/96-byte key blob whose public half does not match its scalar.
    KeyBlob(String),
}

impl std::fmt::Display for ServiceKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceKeyError::Service(m) | ServiceKeyError::KeyBlob(m) => write!(f, "{m}"),
        }
    }
}
impl std::error::Error for ServiceKeyError {}

struct Candidate {
    scalar: Vec<u8>,
    verified: bool,
}

/// `service_keys_from_der(...).for_pcs()`: the encryption key, then the signing key if there is one.
pub fn keys_from_der(payload: &[u8]) -> std::result::Result<Vec<PcsKey>, ServiceKeyError> {
    let (element, _) = der::parse_one(payload, 0)
        .map_err(|e| ServiceKeyError::Service(format!("An item's v_Data is not DER at all: {e}")))?;
    let usable = if element.tag_class == der::CLASS_APPLICATION && element.tag_number == PRIVATE_KEY_V2_TAG {
        from_v2(&element)?
    } else {
        from_v1(&element)?
    };
    Ok(usable.into_iter().take(2).collect())
}

/// A blob: 32/48 bytes is a bare scalar (unverified); 64/96 bytes is public x then scalar, checked.
fn scalar_in(blob: &[u8]) -> std::result::Result<Option<Candidate>, ServiceKeyError> {
    for curve in [PcsCurve::P256, PcsCurve::P384] {
        if blob.len() == curve.size() {
            return Ok(Some(Candidate { scalar: blob.to_vec(), verified: false }));
        }
        if blob.len() != 2 * curve.size() {
            continue;
        }
        let public_x = &blob[..curve.size()];
        let scalar = &blob[curve.size()..];
        let key = PcsKey::from_scalar(curve, scalar).ok_or_else(|| {
            ServiceKeyError::KeyBlob(format!(
                "A {}-byte key blob's trailing half is not a valid scalar",
                blob.len()
            ))
        })?;
        if key.bare_x() != public_x {
            return Err(ServiceKeyError::KeyBlob(format!(
                "A {}-byte key blob's halves disagree: the layout is public x first, then the scalar",
                blob.len()
            )));
        }
        return Ok(Some(Candidate { scalar: scalar.to_vec(), verified: true }));
    }
    Ok(None)
}

fn candidates_in(payload: &[u8]) -> std::result::Result<Vec<Candidate>, ServiceKeyError> {
    let mut found = Vec::new();
    for member in iterate_wire_fields(payload) {
        if member.wire_type != 2 || member.payload.is_empty() {
            continue;
        }
        if scalar_in(&member.payload)?.is_some_and(|c| {
            found.push(c);
            true
        }) {
            continue;
        }
        for inner in iterate_wire_fields(&member.payload) {
            if inner.wire_type == 2 && !inner.payload.is_empty() {
                if let Some(c) = scalar_in(&inner.payload)? {
                    found.push(c);
                    break;
                }
            }
        }
    }
    Ok(found)
}

fn keys_from_candidates(candidates: Vec<Candidate>) -> Vec<PcsKey> {
    let mut ordered: Vec<&Candidate> = candidates.iter().filter(|c| c.verified).collect();
    ordered.extend(candidates.iter().filter(|c| !c.verified));
    ordered
        .into_iter()
        .filter_map(|c| PcsCurve::of_scalar_length(c.scalar.len()).and_then(|curve| PcsKey::from_scalar(curve, &c.scalar)))
        .collect()
}

fn v2_payload(element: &der::DerElement) -> std::result::Result<Vec<u8>, ServiceKeyError> {
    let mut children = element
        .children()
        .map_err(|e| ServiceKeyError::Service(e.to_string()))?;
    if children.is_empty() {
        return Err(ServiceKeyError::Service("A v2 private key structure carries no data element".into()));
    }
    if children.len() == 1 && children[0].constructed && children[0].is_universal(der::TAG_SEQUENCE) {
        children = children[0].children().map_err(|e| ServiceKeyError::Service(e.to_string()))?;
    }
    children
        .iter()
        .find(|c| c.is_universal(der::TAG_OCTET_STRING))
        .map(|c| c.as_bytes().to_vec())
        .ok_or_else(|| ServiceKeyError::Service("A v2 private key structure holds no octet string".into()))
}

fn from_v2(element: &der::DerElement) -> std::result::Result<Vec<PcsKey>, ServiceKeyError> {
    let payload = v2_payload(element)?;
    let keys = PcsServiceKeys::decode(payload.as_slice()).unwrap_or_default();
    let mut candidates: Vec<Candidate> = Vec::new();
    for part in [keys.encryption_key.as_ref(), keys.signing_key.as_ref()].into_iter().flatten() {
        if let Some(key) = &part.key {
            if let Some(c) = scalar_in(key)? {
                candidates.push(c);
            }
        }
    }
    if !candidates.iter().any(|c| c.verified) {
        let positional = candidates_in(&payload)?;
        if !positional.is_empty() {
            candidates = positional;
        }
    }
    let usable = keys_from_candidates(candidates);
    if usable.is_empty() {
        return Err(ServiceKeyError::Service(format!(
            "A v2 private key structure's {}-byte payload carries no usable private key",
            payload.len()
        )));
    }
    Ok(usable)
}

fn from_v1(element: &der::DerElement) -> std::result::Result<Vec<PcsKey>, ServiceKeyError> {
    let children = element
        .children()
        .map_err(|e| ServiceKeyError::Service(e.to_string()))?;
    if children.is_empty() {
        return Err(ServiceKeyError::Service(
            "An item's v_Data is neither a v2 structure nor a sequence holding a key".into(),
        ));
    }
    let mut candidates = Vec::new();
    for child in children.iter().filter(|c| !c.constructed) {
        if let Some(c) = scalar_in(child.as_bytes())? {
            candidates.push(c);
        }
    }
    let usable = keys_from_candidates(candidates);
    if usable.is_empty() {
        return Err(ServiceKeyError::Service("A v1 private key structure carries no usable key".into()));
    }
    Ok(usable)
}
