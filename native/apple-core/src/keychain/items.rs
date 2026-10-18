//! Keychain items: the step from a view's keys to the EC key records are decrypted with (port of
//! `findmy/keychain/items.py`, the read path).
//!
//! A 64-byte AES-SIV view key never becomes an EC private key: the view key decrypts an *item*, and the
//! item's `v_Data` **contains** the EC private key.

use std::collections::BTreeMap;

use aes_siv::siv::Aes256Siv;
use base64::Engine as _;
use aes_siv::KeyInit;
use apple_proto::cloudkit::record::Value as FieldValue;
use apple_proto::cloudkit::{RecordIdentifier, Reference};
use prost::Message;

use crate::cloudkit::records::{iterate_wire_fields, CloudKitRecord};
use crate::error::{Error, Result};
use crate::keychain::shares::ViewKeyring;

pub const RECORD_TYPE_ITEM: &str = "item";
pub const RECORD_TYPE_CURRENT_ITEM: &str = "currentitem";
pub const SERVICE_KEY_TAG: &str = "com.apple.ProtectedCloudStorage-com.apple.icloud.searchparty";
pub const VIEW_MANATEE: &str = "Manatee";
pub const VIEW_PROTECTED_CLOUD_STORAGE: &str = "ProtectedCloudStorage";
const PADDING_MARKER: u8 = 0x80;
const IV_LENGTH: usize = 16;
const ENCVER_MINIMAL: i64 = 1;
const APPLE_EPOCH: i64 = 978_307_200;

fn item_error(message: impl Into<String>) -> Error {
    Error::Backend(message.into())
}

fn little_endian(value: i64, width: usize) -> Vec<u8> {
    (value as u64).to_le_bytes()[..width].to_vec()
}

/// Render one field's value as the additional data carries it.
pub fn render_value(value: &FieldValue, name: &str) -> Result<Vec<u8>> {
    if let Some(s) = &value.string_value {
        return Ok(s.as_bytes().to_vec());
    }
    if let Some(b) = &value.bytes_value {
        return Ok(b.clone());
    }
    if let Some(i) = value.signed_value {
        return Ok(little_endian(i, 8));
    }
    if let Some(f) = value.double_value {
        return Ok(little_endian(f as i64, 8));
    }
    if let Some(date) = &value.date_value {
        let date = apple_proto::cloudkit::Date::decode(date.as_slice())
            .map_err(|_| item_error(format!("Field {name:?} is a date whose payload does not decode")))?;
        let stamp = APPLE_EPOCH + date.time.unwrap_or(0.0) as i64;
        return Ok(crate::util::format_utc(stamp).into_bytes());
    }
    Err(item_error(format!(
        "Field {name:?} has no rendering for the additional data (type {:?}), and guessing one fails authentication with no diagnostic",
        value.r#type
    )))
}

/// Assemble the additional data an item's decryption authenticates against.
pub fn additional_data(record: &CloudKitRecord, parent_uuid: &str) -> Result<Vec<Vec<u8>>> {
    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let encver = value_of(record, "encver").and_then(|v| v.signed_value).unwrap_or(0);
    let gen = value_of(record, "gen").and_then(|v| v.signed_value).unwrap_or(0);
    entries.insert("UUID".into(), record.name.as_bytes().to_vec());
    entries.insert("encver".into(), little_endian(encver, 8));
    entries.insert("gen".into(), little_endian(gen, 8));
    // Not the wrappedkey field. The identifier parentkeyref points at.
    entries.insert("wrappedkey".into(), parent_uuid.as_bytes().to_vec());

    if encver != ENCVER_MINIMAL {
        for name in ["pcsservice", "pcspublicidentity", "pcspublickey"] {
            if let Some(value) = value_of(record, name) {
                entries.insert(name.to_string(), render_value(value, name)?);
            }
        }
        for (name, field) in &record.fields {
            if reserved(name) || name.starts_with("server_") {
                continue;
            }
            entries.insert(name.clone(), render_value(&field.value, name)?);
        }
    }

    // Sorted by name, then the names dropped. This line is the whole ordering.
    Ok(entries.into_values().collect())
}

fn reserved(name: &str) -> bool {
    matches!(
        name,
        "gen" | "pcspublickey" | "UUID" | "data" | "pcsservice" | "pcspublicidentity" | "parentkeyref" | "uploadver" | "wrappedkey" | "encver"
    )
}

fn value_of<'a>(record: &'a CloudKitRecord, name: &str) -> Option<&'a FieldValue> {
    record.fields.get(name).map(|f| &f.value)
}

fn bytes_of(record: &CloudKitRecord, name: &str) -> Vec<u8> {
    let Some(field) = record.fields.get(name) else { return Vec::new() };
    if let Some(b) = &field.value.bytes_value {
        return b.clone();
    }
    if let Some(s) = &field.value.string_value {
        return base64::engine::general_purpose::STANDARD.decode(s).unwrap_or_else(|_| s.as_bytes().to_vec());
    }
    Vec::new()
}

/// Remove an item plaintext's padding (multiple of 20, terminated by `0x80`).
pub fn strip_padding(plaintext: &[u8]) -> Result<Vec<u8>> {
    for index in (0..plaintext.len()).rev() {
        let byte = plaintext[index];
        if byte == PADDING_MARKER {
            return Ok(plaintext[..index].to_vec());
        }
        if byte != 0 {
            return Err(item_error(format!(
                "The plaintext's padding ends in {byte:#04x} rather than {PADDING_MARKER:#04x}, so this did not decrypt correctly"
            )));
        }
    }
    Err(item_error("The plaintext is entirely zeros, so it carries no padding marker"))
}

/// The record identifier a reference names (`reference_name`).
pub fn reference_name(value: &FieldValue) -> String {
    let Some(bytes) = &value.reference_value else { return String::new() };
    if let Ok(reference) = Reference::decode(bytes.as_slice()) {
        if let Some(name) = reference
            .record_identifier
            .as_ref()
            .and_then(|i| i.value.as_ref())
            .and_then(|v| v.name.clone())
        {
            return name;
        }
    }
    // The field number is ASSUMED; scan for a submessage that parses as a RecordIdentifier.
    for field in iterate_wire_fields(bytes) {
        if field.wire_type != 2 || field.payload.is_empty() {
            continue;
        }
        if let Ok(identifier) = RecordIdentifier::decode(field.payload.as_slice()) {
            if let Some(name) = identifier.value.and_then(|v| v.name) {
                return name;
            }
        }
    }
    String::new()
}

/// Which key unwraps this item (`parentkeyref` names a key UUID).
pub fn parent_key_uuid(record: &CloudKitRecord) -> String {
    value_of(record, "parentkeyref").map(reference_name).unwrap_or_default()
}

/// Decrypt one keychain item into its property-list dictionary.
pub fn decrypt_item(record: &CloudKitRecord, keyring: &ViewKeyring) -> Result<BTreeMap<String, crate::plist::Value>> {
    let uuid = parent_key_uuid(record);
    if uuid.is_empty() {
        return Err(item_error(format!("Item {} names no parent key, so nothing says what unwraps it", record.name)));
    }
    let Some(parent) = keyring.get(&uuid) else {
        return Err(item_error(format!(
            "Item {} is wrapped under key {uuid}, which this client does not hold. It holds {}: {}",
            record.name,
            keyring.len(),
            keyring.describe()
        )));
    };
    let wrapped = bytes_of(record, "wrappedkey");
    if wrapped.is_empty() {
        return Err(item_error(format!("Item {} carries no wrapped key", record.name)));
    }
    let item_key = aes_siv_decrypt(parent, &wrapped, &[])?;

    let data = bytes_of(record, "data");
    if data.len() <= IV_LENGTH {
        return Err(item_error(format!("Item {} carries {} bytes of data, too few to hold an IV", record.name, data.len())));
    }
    let iv = &data[..IV_LENGTH];
    let ciphertext = &data[IV_LENGTH..];
    let mut headers: Vec<Vec<u8>> = vec![iv.to_vec()];
    headers.extend(additional_data(record, &uuid)?);

    let padded = aes_siv_decrypt(&item_key, ciphertext, &headers).map_err(|_| {
        item_error(format!(
            "Item {} did not authenticate. Its own key unwrapped correctly, so the additional data is what to doubt -- {} value(s) after the IV",
            record.name,
            headers.len() - 1
        ))
    })?;
    let plain = strip_padding(&padded)?;
    crate::plist::parse_dict(&plain).map_err(|e| item_error(format!("Item {} decrypted but is not a property list: {e}", record.name)))
}

fn aes_siv_decrypt(key: &[u8], ciphertext: &[u8], headers: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut siv = Aes256Siv::new_from_slice(key)
        .map_err(|_| item_error(format!("The key is not a usable AES-SIV key ({} bytes)", key.len())))?;
    siv.decrypt(headers.iter().map(|h| h.as_slice()), ciphertext)
        .map_err(|_| item_error("did not authenticate under the view key"))
}

// --------------------------------------------------------------------------------- views

#[derive(Debug, Clone, Default)]
pub struct ViewContents {
    pub items: BTreeMap<String, CloudKitRecord>,
    pub pointers: BTreeMap<String, String>,
}

impl ViewContents {
    pub fn follow(&self, tag: &str) -> Option<&CloudKitRecord> {
        let target = self.pointers.get(tag)?;
        self.items.get(target)
    }
}

/// Sort a view's records into items and pointers, ignoring the other types.
pub fn split_view_records(records: &[CloudKitRecord]) -> ViewContents {
    let mut items = BTreeMap::new();
    let mut pointers = BTreeMap::new();
    for record in records {
        if record.record_type == RECORD_TYPE_ITEM {
            items.insert(record.name.clone(), record.clone());
        } else if record.record_type == RECORD_TYPE_CURRENT_ITEM {
            let target = record.fields.get(RECORD_TYPE_ITEM).map(|f| reference_name(&f.value)).unwrap_or_default();
            if !target.is_empty() {
                pointers.insert(record.name.clone(), target);
            }
        }
    }
    ViewContents { items, pointers }
}

/// Decrypt every item in the view this keyring opens, by `acct`.
pub fn readable_items(contents: &ViewContents, keyring: &ViewKeyring) -> BTreeMap<Vec<u8>, BTreeMap<String, crate::plist::Value>> {
    let mut found = BTreeMap::new();
    for record in contents.items.values() {
        if let Ok(item) = decrypt_item(record, keyring) {
            if let Some(account) = account_bytes(item.get("acct")) {
                if !account.is_empty() {
                    found.insert(account, item);
                }
            }
        }
    }
    found
}

fn account_bytes(value: Option<&crate::plist::Value>) -> Option<Vec<u8>> {
    match value {
        Some(crate::plist::Value::Data(b)) => Some(b.clone()),
        Some(crate::plist::Value::String(s)) => {
            Some(base64::engine::general_purpose::STANDARD.decode(s).unwrap_or_default())
        }
        _ => None,
    }
}

/// Read the Find My service key's item, by following its pointer.
pub fn service_key_item(contents: &ViewContents, keyring: &ViewKeyring) -> Result<BTreeMap<String, crate::plist::Value>> {
    let record = contents
        .follow(SERVICE_KEY_TAG)
        .ok_or_else(|| item_error(format!("This view has no pointer tagged {SERVICE_KEY_TAG}")))?;
    decrypt_item(record, keyring)
}

/// Read an item's `v_Data`, which is where the key lives.
pub fn payload_of(item: &BTreeMap<String, crate::plist::Value>) -> Result<Vec<u8>> {
    match item.get("v_Data") {
        Some(crate::plist::Value::Data(b)) if !b.is_empty() => Ok(b.clone()),
        _ => Err(item_error("This item carries no v_Data, so it holds no key")),
    }
}

/// Enumerate a keychain view's zone (the zone is the view name).
pub async fn fetch_view(
    client: &dyn crate::cloudkit::CloudKitApi,
    view: &str,
    continuation_token: Option<Vec<u8>>,
) -> Result<ViewContents> {
    let changes = client.iter_records(view, continuation_token, 100).await?;
    let records = CloudKitRecord::from_changes(&changes, view);
    Ok(split_view_records(&records))
}
