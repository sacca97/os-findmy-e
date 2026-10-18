//! Key shares: the view keys a recovered peer is entitled to (port of `findmy/keychain/shares.py`, the
//! read path).
//!
//! A share is wrapped to the *receiving* peer's encryption key, which escrow recovery yields, so the
//! shares can be unwrapped without joining the circle. Two encodings are unique to this module: a
//! wrapped key is base64 of an `NSKeyedArchiver` archive, and what that expands to is an ECIES
//! ciphertext (`SFIES`).

use std::collections::BTreeMap;

use aes_siv::siv::Aes256Siv;
use aes_siv::KeyInit;
use apple_proto::cuttlefish::{RecordWrapper, RecoverableTlkShare, TlkKeyMaterial, ViewKeySet};
use base64::Engine as _;
use prost::Message;

use crate::cloudkit::records::CloudKitRecord;
use crate::error::{Error, Result};
use crate::keychain::peers::{PeerDirectory, PublicKey};
use crate::reports::crypto::x963_kdf;

const NEEDED_VIEWS: [&str; 2] = ["Manatee", "ProtectedCloudStorage"];
const MEMBER_POINT: &str = "EphemeralSenderPublicKey";
const MEMBER_CIPHERTEXT: &str = "SFCiphertext";
const MEMBER_CODE: &str = "AuthenticationCode";

fn share_error(message: impl Into<String>) -> Error {
    Error::Backend(message.into())
}

fn decode_base64(value: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap_or_else(|_| value.as_bytes().to_vec())
}

// --------------------------------------------------------------------------------- NSKeyedArchiver

/// A value resolved out of an `NSKeyedArchiver` archive.
#[derive(Debug, Clone, PartialEq)]
pub enum ArchiveValue {
    Bytes(Vec<u8>),
    Str(String),
    Int(i64),
    Bool(bool),
    Dict(BTreeMap<String, ArchiveValue>),
    List(Vec<ArchiveValue>),
    Null,
}

/// Read an `NSKeyedArchiver` archive far enough to resolve its `$objects`/`$top` references.
pub fn unarchive(data: &[u8]) -> Result<ArchiveValue> {
    let value: plist::Value = plist::from_bytes(data).map_err(|e| share_error(format!("Not a property list, so not an archive: {e}")))?;
    let dict = value.as_dictionary().ok_or_else(|| share_error("A property list, but not an NSKeyedArchiver archive"))?;
    let objects = dict
        .get("$objects")
        .and_then(|v| v.as_array())
        .ok_or_else(|| share_error("A property list, but not an NSKeyedArchiver archive"))?;
    let top = dict.get("$top").cloned().unwrap_or(plist::Value::Dictionary(Default::default()));
    resolve(&top, objects, 0)
}

fn resolve(value: &plist::Value, objects: &[plist::Value], depth: usize) -> Result<ArchiveValue> {
    if depth > 32 {
        return Ok(ArchiveValue::Null);
    }
    match value {
        plist::Value::Uid(uid) => {
            let index = uid.get() as usize;
            match objects.get(index) {
                Some(v) => resolve(v, objects, depth + 1),
                None => Ok(ArchiveValue::Null),
            }
        }
        plist::Value::String(s) => Ok(ArchiveValue::Str(s.clone())),
        plist::Value::Boolean(b) => Ok(ArchiveValue::Bool(*b)),
        plist::Value::Data(d) => Ok(ArchiveValue::Bytes(d.clone())),
        plist::Value::Integer(i) => Ok(ArchiveValue::Int(i.as_signed().unwrap_or(0))),
        plist::Value::Real(f) => Ok(ArchiveValue::Int(*f as i64)),
        plist::Value::Array(a) => Ok(ArchiveValue::List(a.iter().map(|v| resolve(v, objects, depth + 1)).collect::<Result<_>>()?)),
        plist::Value::Dictionary(d) => {
            let mut out = BTreeMap::new();
            for (k, v) in d {
                if k == "$class" {
                    continue;
                }
                out.insert(k.clone(), resolve(v, objects, depth + 1)?);
            }
            Ok(ArchiveValue::Dict(out))
        }
        _ => Ok(ArchiveValue::Null),
    }
}

/// Pull every byte member out of an archive, keyed by its path.
pub fn archived_members(data: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut found = BTreeMap::new();
    walk(unarchive(data)?, "", &mut found, 0);
    if found.is_empty() {
        return Err(share_error("This archive carries no byte string to unwrap"));
    }
    Ok(found)
}

fn walk(value: ArchiveValue, path: &str, found: &mut BTreeMap<String, Vec<u8>>, depth: usize) {
    if depth > 32 {
        return;
    }
    match value {
        ArchiveValue::Bytes(b) => {
            found.insert(path.to_string(), b);
        }
        ArchiveValue::Dict(d) => {
            for (k, v) in d {
                walk(v, &if path.is_empty() { k } else { format!("{path}.{k}") }, found, depth + 1);
            }
        }
        ArchiveValue::List(l) => {
            for (i, v) in l.into_iter().enumerate() {
                walk(v, &format!("{path}[{i}]"), found, depth + 1);
            }
        }
        _ => {}
    }
}

/// The three members of an `SFIESCiphertext`, with the ciphertext already trimmed.
#[derive(Debug, Clone)]
pub struct SfiesParts {
    pub point: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub code: Vec<u8>,
}

/// Read an `SFIESCiphertext` archive into the three pieces decryption needs.
pub fn sfies_parts(archive: &[u8]) -> Result<SfiesParts> {
    let members = archived_members(archive)?;
    let find = |fragment: &str| members.iter().find(|(k, _)| k.contains(fragment)).map(|(_, v)| v.clone());
    let point = find(MEMBER_POINT).ok_or_else(|| share_error("This archive is not an SFIESCiphertext"))?;
    let mut ciphertext = find(MEMBER_CIPHERTEXT).ok_or_else(|| share_error("This archive is not an SFIESCiphertext"))?;
    let code = find(MEMBER_CODE).ok_or_else(|| share_error("This archive is not an SFIESCiphertext"))?;
    let overrun = point.len() + code.len();
    if ciphertext.len() <= overrun {
        return Err(share_error(format!(
            "The ciphertext member is {} bytes, which is not longer than the {overrun}-byte overrun it is expected to carry",
            ciphertext.len()
        )));
    }
    ciphertext.truncate(ciphertext.len() - overrun);
    Ok(SfiesParts { point, ciphertext, code })
}

/// Decrypt an `SFIESCiphertext` with the receiving peer's P-384 encryption key.
pub fn sfies_decrypt(private_key: &p384::SecretKey, parts: &SfiesParts) -> Result<Vec<u8>> {
        let ephemeral = p384::PublicKey::from_sec1_bytes(&parts.point)
        .map_err(|_| share_error("The archived ephemeral key is not a point on P-384"))?;
    let shared = p384::ecdh::diffie_hellman(private_key.to_nonzero_scalar(), ephemeral.as_affine());
    let material = x963_kdf(shared.raw_secret_bytes(), &parts.point, 32 + 16);
    crate::crypto::aes_gcm_decrypt(&material[..32], &material[32..], &[], &parts.ciphertext, &parts.code)
        .map_err(|_| share_error("The SFIES ciphertext did not authenticate under this key"))
}

/// Read an `SFIESCiphertext` archive and decrypt it.
pub fn sfies_decrypt_archive(private_key: &p384::SecretKey, archive: &[u8]) -> Result<Vec<u8>> {
    sfies_decrypt(private_key, &sfies_parts(archive)?)
}

// --------------------------------------------------------------------------------- class keys / material

/// Unwrap a class key with the view's top-level key (AES-SIV, no associated data).
pub fn unwrap_class_key(wrapped: &[u8], top_level_key: &[u8]) -> Result<Vec<u8>> {
    let mut siv = Aes256Siv::new_from_slice(top_level_key)
        .map_err(|_| share_error(format!("The top-level key is not a usable AES-SIV key ({} bytes)", top_level_key.len())))?;
    siv.decrypt(std::iter::empty::<&[u8]>(), wrapped)
        .map_err(|_| share_error("The class key did not authenticate under the view's top-level key"))
}

/// A view's keys, addressable both by slot and by UUID.
#[derive(Debug, Clone, Default)]
pub struct ViewKeyring {
    pub by_uuid: BTreeMap<String, Vec<u8>>,
    pub by_slot: BTreeMap<String, Vec<u8>>,
}

impl ViewKeyring {
    pub fn get(&self, uuid: &str) -> Option<&Vec<u8>> {
        self.by_uuid.get(uuid)
    }
    pub fn len(&self) -> usize {
        self.by_slot.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_slot.is_empty()
    }
    pub fn describe(&self) -> String {
        self.by_slot.iter().map(|(n, k)| format!("{n}: {} bytes", k.len())).collect::<Vec<_>>().join(", ")
    }
}

/// Read what a decrypted share expands to (`TlkKeyMaterial`).
pub fn parse_key_material(plaintext: &[u8]) -> Result<TlkKeyMaterial> {
    let material = TlkKeyMaterial::decode(plaintext).map_err(|_| share_error("A share decrypted but its plaintext is not a key message"))?;
    if material.key.as_ref().map(|k| k.is_empty()).unwrap_or(true) {
        return Err(share_error("A share decrypted to a key message carrying no key at field 4"));
    }
    Ok(material)
}

// --------------------------------------------------------------------------------- records

fn field_str(record: &CloudKitRecord, name: &str) -> String {
    record
        .fields
        .get(name)
        .and_then(|f| f.value.string_value.clone())
        .unwrap_or_default()
}

fn field_int(record: &CloudKitRecord, name: &str) -> i64 {
    record.fields.get(name).and_then(|f| f.value.signed_value).unwrap_or(0)
}

fn field_bytes(record: &CloudKitRecord, name: &str) -> Vec<u8> {
    let Some(field) = record.fields.get(name) else { return Vec::new() };
    if let Some(b) = &field.value.bytes_value {
        return b.clone();
    }
    if let Some(s) = &field.value.string_value {
        return decode_base64(s);
    }
    Vec::new()
}

/// A key share, read out of the CloudKit record that carries it.
#[derive(Debug, Clone)]
pub struct ShareRecord {
    pub sender: String,
    pub receiver: String,
    pub receiver_public_encryption_key: Vec<u8>,
    pub wrapped_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub curve: i64,
    pub epoch: i64,
    pub poisoned: i64,
    pub version: i64,
}

impl ShareRecord {
    pub fn from_record(record: &CloudKitRecord) -> ShareRecord {
        ShareRecord {
            sender: field_str(record, "sender"),
            receiver: field_str(record, "receiver"),
            receiver_public_encryption_key: field_bytes(record, "receiverPublicEncryptionKey"),
            wrapped_key: field_bytes(record, "wrappedkey"),
            signature: field_bytes(record, "signature"),
            curve: field_int(record, "curve"),
            epoch: field_int(record, "epoch"),
            poisoned: field_int(record, "poisoned"),
            version: field_int(record, "version"),
        }
    }
}

/// One of a view's keys, from a `synckey` record.
#[derive(Debug, Clone)]
pub struct ViewKey {
    pub key_class: String,
    pub wrapped_key: Vec<u8>,
    pub upload_version: i64,
    pub uuid: String,
    pub slot: String,
}

impl ViewKey {
    pub fn from_record(record: &CloudKitRecord, slot: &str) -> ViewKey {
        ViewKey {
            key_class: field_str(record, "class"),
            wrapped_key: field_bytes(record, "wrappedkey"),
            upload_version: field_int(record, "uploadver"),
            uuid: record.name.clone(),
            slot: slot.to_string(),
        }
    }
}

/// One view's share, together with that view's keys.
#[derive(Debug, Clone)]
pub struct ShareEntry {
    pub view: String,
    pub share: ShareRecord,
    pub view_keys: Vec<ViewKey>,
}

fn record_in(wrapper: &RecordWrapper) -> Result<CloudKitRecord> {
    let bytes = wrapper.record.clone().unwrap_or_default();
    let record = apple_proto::cloudkit::Record::decode(bytes.as_slice())
        .map_err(|_| share_error("A share wrapper's payload did not decode as a CloudKit record"))?;
    Ok(CloudKitRecord::from_proto(&record, ""))
}

/// Read a view's keys out of their wrappers, remembering which slot each came from.
pub fn read_view_keys(keys: &ViewKeySet) -> Vec<ViewKey> {
    let mut found = Vec::new();
    for (slot, wrapper) in [("tlk", &keys.tlk), ("classA", &keys.class_a), ("classB", &keys.class_b)] {
        if let Some(wrapper) = wrapper {
            if let Ok(record) = record_in(wrapper) {
                found.push(ViewKey::from_record(&record, slot));
            }
        }
    }
    found
}

/// Read one entry of a share listing.
pub fn decode_share_entry(data: &[u8]) -> Result<Option<ShareEntry>> {
    let entry = RecoverableTlkShare::decode(data).map_err(|_| share_error("A share entry did not decode"))?;
    let service = entry.service.clone().unwrap_or_default();
    if service.is_empty() && entry.share.is_none() {
        return Err(share_error("A share entry carries neither a view name nor a share"));
    }
    let Some(wrapper) = &entry.share else {
        return Ok(None);
    };
    let record = match record_in(wrapper) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    Ok(Some(ShareEntry {
        view: service,
        share: ShareRecord::from_record(&record),
        view_keys: entry.viewkeys.as_ref().map(read_view_keys).unwrap_or_default(),
    }))
}

// --------------------------------------------------------------------------------- signatures

fn little_endian(value: i64, width: usize) -> Vec<u8> {
    let mask = if width >= 8 { u64::MAX } else { (1u64 << (8 * width)) - 1 };
    (value as u64 & mask).to_le_bytes()[..width].to_vec()
}

/// The bytes a key share's signature covers (seven fields, little-endian integers).
pub fn share_signed_data(share: &ShareRecord) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(little_endian(share.version, 8));
    out.extend_from_slice(share.receiver.as_bytes());
    out.extend_from_slice(share.sender.as_bytes());
    out.extend_from_slice(&share.wrapped_key);
    out.extend(little_endian(share.curve, 8));
    out.extend(little_endian(share.epoch, 8));
    out.extend(little_endian(share.poisoned, 8));
    out
}

/// Check a share against the peer that sent it (ECDSA-SHA256).
pub fn verify_share_signature(share: &ShareRecord, sender: &crate::keychain::peers::Peer) -> bool {
    if share.signature.is_empty() {
        return false;
    }
    match sender.signing_public_key() {
        Some(PublicKey::P256(_)) | Some(PublicKey::P384(_)) => {
            sender.signing_public_key().unwrap().verify_ecdsa_sha256(&share.signature, &share_signed_data(share))
        }
        None => false,
    }
}

/// One key share, and whatever could be made of it.
#[derive(Debug, Clone, Default)]
pub struct KeyShare {
    pub service: String,
    pub key_id: String,
    pub sender: String,
    pub receiver: String,
    pub wrapped_key: Vec<u8>,
    pub plaintext: Option<Vec<u8>>,
    pub error: Option<String>,
    pub view_keys: ViewKeyring,
    pub sender_known: bool,
    pub sender_verified: bool,
}

/// Assemble a view's keys (the top-level key is the share plaintext; class keys are unwrapped).
pub fn unwrap_view_keys(keys: &[ViewKey], share_plaintext: &[u8]) -> ViewKeyring {
    let material = match parse_key_material(share_plaintext) {
        Ok(m) => m,
        Err(_) => return ViewKeyring::default(),
    };
    let top = material.key.clone().unwrap_or_default();
    let mut by_uuid = BTreeMap::new();
    let mut by_slot = BTreeMap::new();
    if let Some(uuid) = material.uuid.clone() {
        if !uuid.is_empty() {
            by_uuid.insert(uuid, top.clone());
        }
    }
    by_slot.insert("tlk".to_string(), top.clone());

    for key in keys {
        if key.slot == "tlk" {
            if !key.uuid.is_empty() {
                by_uuid.insert(key.uuid.clone(), top.clone());
            }
            continue;
        }
        if key.wrapped_key.is_empty() {
            continue;
        }
        let name = if key.slot.is_empty() { key.key_class.clone() } else { key.slot.clone() };
        if let Ok(unwrapped) = unwrap_class_key(&key.wrapped_key, &top) {
            by_slot.insert(name, unwrapped.clone());
            if !key.uuid.is_empty() {
                by_uuid.insert(key.uuid.clone(), unwrapped);
            }
        }
    }
    ViewKeyring { by_uuid, by_slot }
}

/// Unwrap one share with the recovered peer's encryption key.
pub fn unwrap_share(
    entry: &ShareEntry,
    candidates: &[(&str, &p384::SecretKey)],
    directory: Option<&PeerDirectory>,
    expected_receiver: Option<&str>,
) -> KeyShare {
    use elliptic_curve::sec1::ToEncodedPoint;
    let share = &entry.share;
    let sender = directory.and_then(|d| d.get(&share.sender));
    let sender_known = sender.is_some();
    let sender_verified = sender.map(|s| verify_share_signature(share, s)).unwrap_or(false);

    let failed = |reason: String| KeyShare {
        service: entry.view.clone(),
        sender: share.sender.clone(),
        receiver: share.receiver.clone(),
        wrapped_key: share.wrapped_key.clone(),
        error: Some(reason),
        sender_known,
        sender_verified,
        ..Default::default()
    };

    if let Some(directory) = directory {
        if directory.len() > 0 && !sender_known {
            return failed(format!(
                "the sending peer {:?} is not in the trust circle, so nothing identifies who produced this key",
                share.sender
            ));
        }
    }
    if share.wrapped_key.is_empty() {
        return failed("this share carries no wrapped key".into());
    }
    if let Some(expected) = expected_receiver {
        if share.receiver != expected {
            return failed(format!(
                "this share is for peer {:?}, not the recovered peer {expected:?}, so no key we hold was ever going to open it",
                share.receiver
            ));
        }
    }

    // The share names the key it was wrapped to; if that is one of ours, try it first, else try all.
    let point_of = |k: &p384::SecretKey| k.public_key().to_encoded_point(false).as_bytes().to_vec();
    let declared = decode_base64_point(&share.receiver_public_encryption_key);
    let named = candidates.iter().find(|(_, k)| point_of(k) == declared).map(|(n, _)| *n);
    let order: Vec<(&str, &p384::SecretKey)> = match named {
        Some(name) => candidates.iter().filter(|(n, _)| *n == name).copied().collect(),
        None => candidates.to_vec(),
    };
    let mut plaintext = None;
    let mut used = "";
    for (name, key) in &order {
        if let Ok(p) = sfies_decrypt_archive(key, &share.wrapped_key) {
            plaintext = Some(p);
            used = name;
            break;
        }
    }
    if !used.is_empty() && used != "encryption" {
        tracing::warn!("this share unwrapped under the {used} key, not the encryption key");
    }
    match plaintext {
        Some(plaintext) => {
            let view_keys = unwrap_view_keys(&entry.view_keys, &plaintext);
            KeyShare {
                service: entry.view.clone(),
                sender: share.sender.clone(),
                receiver: share.receiver.clone(),
                wrapped_key: share.wrapped_key.clone(),
                plaintext: Some(plaintext),
                view_keys,
                sender_known,
                sender_verified,
                ..Default::default()
            }
        }
        None => failed("nothing authenticated as an ECIES ciphertext under the keys held".into()),
    }
}

/// Decode the share's declared receiver key (base64 text, or raw SEC1 bytes).
fn decode_base64_point(value: &[u8]) -> Vec<u8> {
    if value.starts_with(&[0x02]) || value.starts_with(&[0x03]) || value.starts_with(&[0x04]) {
        value.to_vec()
    } else {
        decode_base64(&String::from_utf8_lossy(value))
    }
}

/// Ask which key shares a peer is entitled to receive.
pub async fn fetch_recoverable_shares(
    client: &dyn crate::cloudkit::CloudKitApi,
    peer_id: &str,
) -> Result<Vec<ShareEntry>> {
    let request = apple_proto::cuttlefish::FetchRecoverableTlkSharesRequest { for_peer: Some(peer_id.to_string()) };
    let serialized = client
        .function_invoke(crate::cloudkit::constants::CUTTLEFISH_SERVICE, "fetchRecoverableTLKShares", request.encode_to_vec())
        .await?;
    let response = apple_proto::cuttlefish::FetchRecoverableTlkSharesResponse::decode(serialized.as_slice())
        .map_err(|e| share_error(format!("CloudKit accepted the call but its result did not decode as a fetchRecoverableTLKShares response ({e})")))?;
    let mut entries = Vec::new();
    for raw in &response.shares {
        if let Ok(Some(entry)) = decode_share_entry(raw) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// Describe what a set of shares yielded.
pub fn summarise(shares: &[KeyShare]) -> String {
    let readable = shares.iter().filter(|s| s.plaintext.is_some()).count();
    let mut services: Vec<&str> = shares.iter().filter(|s| !s.service.is_empty()).map(|s| s.service.as_str()).collect();
    services.sort();
    services.dedup();
    let mut parts = vec![format!("{readable}/{} unwrapped", shares.len())];
    if !services.is_empty() {
        parts.push(format!("views: {}", services.join(", ")));
    }
    parts.join("; ")
}

/// The views this project reads.
pub fn needed_views() -> &'static [&'static str] {
    &NEEDED_VIEWS
}
