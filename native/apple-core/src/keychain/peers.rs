//! Who is in the trust circle, and what they sign with (port of `findmy/keychain/peers.py`).
//!
//! A key share's signature is verified against its *sending* peer's key, and a recovered bottle carries a
//! signature from its *sponsoring* peer. Both name a peer by hash, and this directory is the only place
//! those hashes resolve.

use std::collections::BTreeMap;

use apple_proto::cuttlefish::{CuttlefishChanges, CuttlefishPeer, PeerDynamicInfo, PeerPermanentInfo, PeerStableInfo};
use elliptic_curve::sec1::ToEncodedPoint;
use prost::Message;

use crate::error::{Error, Result};

pub const PEER_ID_PREFIX: &str = "SHA256:";

fn peer_error(message: impl Into<String>) -> Error {
    Error::Backend(message.into())
}

/// A peer public key: the curve and its uncompressed SEC1 point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    P256(Vec<u8>),
    P384(Vec<u8>),
}

impl PublicKey {
    pub fn uncompressed(&self) -> &[u8] {
        match self {
            PublicKey::P256(b) | PublicKey::P384(b) => b,
        }
    }

    /// ECDSA-SHA256 verification (shares and vouchers are signed with SHA-256).
    pub fn verify_ecdsa_sha256(&self, signature: &[u8], data: &[u8]) -> bool {
        use p256::ecdsa::signature::Verifier;
        match self {
            PublicKey::P384(point) => {
                use p384::ecdsa::signature::Verifier;
                let Ok(vk) = p384::ecdsa::VerifyingKey::from_sec1_bytes(point) else { return false };
                let Ok(sig) = p384::ecdsa::Signature::from_der(signature) else { return false };
                vk.verify(data, &sig).is_ok()
            }
            PublicKey::P256(point) => {
                let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(point) else { return false };
                let Ok(sig) = p256::ecdsa::Signature::from_der(signature) else { return false };
                vk.verify(data, &sig).is_ok()
            }
        }
    }
}

/// Read a peer's public key, whichever way it is encoded.
pub fn load_public_key(data: &[u8]) -> Option<PublicKey> {
    use p384::pkcs8::DecodePublicKey;
    if let Ok(key) = p384::PublicKey::from_public_key_der(data) {
        return Some(PublicKey::P384(key.to_encoded_point(false).as_bytes().to_vec()));
    }
    if let Ok(key) = p256::PublicKey::from_public_key_der(data) {
        return Some(PublicKey::P256(key.to_encoded_point(false).as_bytes().to_vec()));
    }
    if let Ok(key) = p384::PublicKey::from_sec1_bytes(data) {
        return Some(PublicKey::P384(key.to_encoded_point(false).as_bytes().to_vec()));
    }
    if let Ok(key) = p256::PublicKey::from_sec1_bytes(data) {
        return Some(PublicKey::P256(key.to_encoded_point(false).as_bytes().to_vec()));
    }
    None
}

/// `SHA256:` followed by base64 of a SHA-256 over the serialised permanent info concatenated with its
/// signature.
pub fn peer_identifier(permanent_info: &[u8], signature: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(permanent_info);
    hasher.update(signature);
    let digest = hasher.finalize();
    format!("{PEER_ID_PREFIX}{}", base64::engine::general_purpose::STANDARD.encode(digest))
}

/// One peer of the trust circle.
#[derive(Debug, Clone)]
pub struct Peer {
    pub hash: String,
    pub signing_key: Vec<u8>,
    pub encryption_key: Vec<u8>,
    pub machine_id: String,
    pub model_id: String,
    pub permanent_info: Vec<u8>,
    pub permanent_signature: Vec<u8>,
    pub stable_clock: u64,
    pub dynamic_clock: u64,
    pub includeds: Vec<String>,
    pub excludeds: Vec<String>,
    pub voucher_info: Vec<u8>,
    pub voucher_signature: Vec<u8>,
}

impl Peer {
    pub fn signing_public_key(&self) -> Option<PublicKey> {
        load_public_key(&self.signing_key)
    }

    pub fn derived_hash(&self) -> String {
        peer_identifier(&self.permanent_info, &self.permanent_signature)
    }

    pub fn hash_is_derivable(&self) -> bool {
        !self.permanent_info.is_empty() && self.derived_hash() == self.hash
    }
}

/// The peers of a trust circle, indexed by hash.
#[derive(Debug, Clone, Default)]
pub struct PeerDirectory {
    pub peers: BTreeMap<String, Peer>,
    pub sync_token: Option<String>,
}

impl PeerDirectory {
    pub fn get(&self, peer_hash: &str) -> Option<&Peer> {
        self.peers.get(peer_hash)
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn contains(&self, peer_hash: &str) -> bool {
        self.peers.contains_key(peer_hash)
    }

    /// Fold a batch of changes in, returning a new directory.
    pub fn updated(&self, changes: &CuttlefishChanges) -> PeerDirectory {
        let mut peers = self.peers.clone();
        apply_changes(&mut peers, changes);
        let sync_token = changes.sync_token.clone().or_else(|| self.sync_token.clone());
        PeerDirectory { peers, sync_token }
    }
}

/// Fold one batch of changes into a peer map, in place. Returns how many peers were added.
pub fn apply_changes(peers: &mut BTreeMap<String, Peer>, changes: &CuttlefishChanges) -> usize {
    let mut added = 0;
    for change in &changes.changes {
        let Some(peer_proto) = &change.add else { continue };
        if let Some(peer) = peer_from_proto(peer_proto) {
            peers.insert(peer.hash.clone(), peer);
            added += 1;
        }
    }
    added
}

fn peer_from_proto(peer: &CuttlefishPeer) -> Option<Peer> {
    let hash = peer.hash.clone().filter(|h| !h.is_empty())?;
    let permanent = peer.permanent_info.clone().unwrap_or_default();
    let permanent_bytes = permanent.info.clone().unwrap_or_default();
    let info = PeerPermanentInfo::decode(permanent_bytes.as_slice()).ok()?;
    let signing_key = info.signing_key.clone().filter(|k| !k.is_empty())?;
    let dynamic = peer
        .dynamic_info
        .clone()
        .and_then(|d| PeerDynamicInfo::decode(d.info.unwrap_or_default().as_slice()).ok())
        .unwrap_or_default();
    let stable_clock = peer
        .stable_info
        .clone()
        .and_then(|s| PeerStableInfo::decode(s.info.unwrap_or_default().as_slice()).ok())
        .and_then(|s| s.clock)
        .unwrap_or(0);
    let voucher = peer.voucher.clone().unwrap_or_default();
    Some(Peer {
        hash,
        signing_key,
        encryption_key: info.encryption_key.clone().unwrap_or_default(),
        machine_id: info.machine_id.clone().unwrap_or_default(),
        model_id: info.model_id.clone().unwrap_or_default(),
        permanent_info: permanent_bytes,
        permanent_signature: permanent.signature.clone().unwrap_or_default(),
        stable_clock,
        dynamic_clock: dynamic.clock.unwrap_or(0),
        includeds: dynamic.includeds.clone(),
        excludeds: dynamic.excludeds.clone(),
        voucher_info: voucher.info.clone().unwrap_or_default(),
        voucher_signature: voucher.signature.clone().unwrap_or_default(),
    })
}

#[derive(Debug, Clone, Default)]
pub struct IdentifierCheck {
    pub matched: Vec<String>,
    pub mismatched: Vec<String>,
    pub uncheckable: Vec<String>,
}

impl IdentifierCheck {
    pub fn confirmed(&self) -> bool {
        !self.matched.is_empty() && self.mismatched.is_empty()
    }

    pub fn describe(&self) -> String {
        let mut parts = vec![format!("{} matched", self.matched.len()), format!("{} did not", self.mismatched.len())];
        if !self.uncheckable.is_empty() {
            parts.push(format!("{} carried nothing to check", self.uncheckable.len()));
        }
        parts.join(", ")
    }
}

/// Recompute every known peer's identifier and compare it against the one it reports.
pub fn check_peer_identifiers(directory: &PeerDirectory) -> IdentifierCheck {
    let mut check = IdentifierCheck::default();
    for peer in directory.peers.values() {
        if peer.permanent_info.is_empty() {
            check.uncheckable.push(peer.hash.clone());
        } else if peer.hash_is_derivable() {
            check.matched.push(peer.hash.clone());
        } else {
            check.mismatched.push(peer.hash.clone());
        }
    }
    check
}

/// Read the circle's peers through a CloudKit client (`fetchChanges` pages).
pub async fn fetch_peer_directory(
    client: &dyn crate::cloudkit::CloudKitApi,
    sync_token: Option<String>,
    max_pages: usize,
) -> Result<PeerDirectory> {
    let mut peers: BTreeMap<String, Peer> = BTreeMap::new();
    let mut token = sync_token;
    let mut restarted = false;
    let mut complete = false;

    for _ in 0..max_pages {
        let mut request = apple_proto::cuttlefish::FetchChangesRequest::default();
        if let Some(token) = &token {
            request.sync_token = Some(token.clone());
        }
        let serialized = match client
            .function_invoke(
                crate::cloudkit::constants::CUTTLEFISH_SERVICE,
                "fetchChanges",
                request.encode_to_vec(),
            )
            .await
        {
            Ok(s) => s,
            Err(e) if is_change_token_expired(&e) && !restarted => {
                restarted = true;
                peers.clear();
                token = None;
                continue;
            }
            Err(e) => return Err(e),
        };
        let response = apple_proto::cuttlefish::FetchChangesResponse::decode(serialized.as_slice())
            .map_err(|e| peer_error(format!("CloudKit accepted the call but its result did not decode as a fetchChanges response ({e})")))?;
        let changes = response.changes.unwrap_or_default();
        apply_changes(&mut peers, &changes);
        let previous = token.clone();
        if changes.sync_token.is_some() {
            token = changes.sync_token.clone();
        }
        // An empty page is the only thing that ends this.
        if changes.changes.is_empty() {
            complete = true;
            break;
        }
        // A token that does not advance would loop until max_pages; stop instead.
        if token.is_some() && token == previous {
            break;
        }
    }
    let _ = complete;
    Ok(PeerDirectory { peers, sync_token: token })
}

fn is_change_token_expired(error: &Error) -> bool {
    let text = error.to_string();
    text.contains("changeTokenExpired")
}
