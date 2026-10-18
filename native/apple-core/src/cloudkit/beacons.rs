//! Find My accessories read from the owner's iCloud BeaconStore zone (port of the read path of
//! `findmy/cloudkit/beacons.py` and `apple/cloudkit/BeaconStore.kt`). Read-only: nothing here saves,
//! renames or deletes.

use std::collections::{BTreeMap, HashMap};

use prost::Message;
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::cloudkit::pcs::{self, FieldContext, PcsKey, ShareProtection, UnwrappedProtection};
use crate::cloudkit::records::CloudKitRecord;
use crate::error::{Error, Result};

pub const MASTER_KEY_TAIL: usize = 28;

fn apple_epoch() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(978_307_200).unwrap()
}
fn unix_epoch() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}
fn earliest() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_546_300_800).unwrap() // 2019-01-01
}

fn beacon_error(message: impl Into<String>) -> Error {
    Error::Backend(message.into())
}

/// A decrypted field's value.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Bytes(Vec<u8>),
    Str(String),
    Int(i64),
    Double(f64),
    Date(OffsetDateTime),
    /// A type this client does not model: the raw EncryptedValue bytes.
    Wrapper(Vec<u8>),
    None,
}

/// A record whose fields were decrypted and interpreted.
#[derive(Debug, Clone, Default)]
pub struct DecryptedRecord {
    pub name: String,
    pub record_type: String,
    pub values: BTreeMap<String, FieldValue>,
    pub raw_values: BTreeMap<String, Vec<u8>>,
    pub undecryptable: BTreeMap<String, String>,
}

/// The records that decrypted, with what did not.
#[derive(Debug, Clone, Default)]
pub struct DecryptedRecords {
    pub records: Vec<DecryptedRecord>,
    pub skipped: BTreeMap<String, i32>,
    pub first_miss: Option<String>,
}

/// One master beacon with the naming and alignment records that join to it.
#[derive(Debug, Clone)]
pub struct RecordGroup {
    pub beacon: DecryptedRecord,
    pub naming: Option<DecryptedRecord>,
    pub alignment: Option<DecryptedRecord>,
}

/// One accessory read out of the owner's BeaconStore. Secrets: never logged.
#[derive(Clone)]
pub struct DecryptedAccessory {
    pub master_key: Vec<u8>,
    pub skn: Vec<u8>,
    pub sks: Vec<u8>,
    pub paired_at: OffsetDateTime,
    pub name: Option<String>,
    pub model: Option<String>,
    pub identifier: String,
    pub group_identifier: Option<String>,
    pub serial_number: Option<String>,
    pub alignment_date: Option<OffsetDateTime>,
    pub alignment_index: Option<i64>,
}

/// A decrypted date's double as a moment: CloudKit's 2001 epoch, else the Unix epoch, whichever lands
/// between 2019 and tomorrow.
pub fn as_instant(seconds: f64, now: OffsetDateTime) -> Result<OffsetDateTime> {
    let latest = now + TimeDuration::days(1);
    if seconds.is_finite() && seconds.abs() < 1e14 {
        let whole = if seconds < 0.0 { seconds.ceil() } else { seconds.floor() };
        let micros = (whole as i64) * 1_000_000 + ((seconds - whole) * 1e6).round() as i64;
        for epoch in [apple_epoch(), unix_epoch()] {
            let moment = epoch + TimeDuration::microseconds(micros);
            if moment >= earliest() && moment <= latest {
                return Ok(moment);
            }
        }
    }
    Err(beacon_error("Decrypted date is not a plausible pairing time under either epoch."))
}

/// A decrypted field's bytes as the value its declared type promises (`interpret_plaintext`).
pub fn interpret_plaintext(value_type: i32, data: &[u8], now: OffsetDateTime) -> Result<FieldValue> {
    if value_type == crate::cloudkit::value_type::BYTES || value_type == crate::cloudkit::value_type::ENCRYPTED_BYTES {
        return Ok(FieldValue::Bytes(data.to_vec()));
    }
    let wrapper = apple_proto::cloudkit::EncryptedValue::decode(data)
        .map_err(|_| beacon_error("Decrypted field is not an EncryptedValue"))?;
    Ok(match value_type {
        crate::cloudkit::value_type::STRING => wrapper
            .string_value
            .map(FieldValue::Str)
            .ok_or_else(|| beacon_error("Field declares STRING_TYPE but its plaintext carries no string"))?,
        crate::cloudkit::value_type::INT64 => wrapper
            .signed_value
            .map(FieldValue::Int)
            .ok_or_else(|| beacon_error("Field declares INT64_TYPE but its plaintext carries no integer"))?,
        crate::cloudkit::value_type::DATE => {
            let time = wrapper
                .date_value
                .and_then(|d| d.time)
                .ok_or_else(|| beacon_error("Field declares DATE_TYPE but its plaintext carries no date"))?;
            FieldValue::Date(as_instant(time, now)?)
        }
        crate::cloudkit::value_type::DOUBLE => match wrapper.date_value.and_then(|d| d.time) {
            Some(time) => FieldValue::Double(time),
            None => FieldValue::Double(wrapper.signed_value.unwrap_or(0) as f64),
        },
        _ => FieldValue::Wrapper(data.to_vec()),
    })
}

fn is_wanted(record_type: &str) -> bool {
    matches!(
        record_type,
        crate::cloudkit::record_type::MASTER_BEACON
            | crate::cloudkit::record_type::BEACON_NAMING
            | crate::cloudkit::record_type::KEY_ALIGNMENT
    )
}

fn is_missing_key(error: &Error) -> bool {
    error.to_string().starts_with("None of the")
}

/// Decrypt every encrypted field of one record.
pub fn decrypt_record(
    record: &CloudKitRecord,
    private_keys: &[PcsKey],
    default_master_keys: &[Vec<u8>],
    now: OffsetDateTime,
    allow_privacy_sensitive: bool,
) -> Result<DecryptedRecord> {
    if record.record_type == crate::cloudkit::record_type::SAFE_LOCATION && !allow_privacy_sensitive {
        return Err(beacon_error(format!(
            "Refusing to decrypt a {} record: it holds the user's own locations.",
            record.record_type
        )));
    }
    match &record.protection_info {
        Some(protection) => {
            let parsed = ShareProtection::from_der(protection)?;
            let unwrapped = pcs::unwrap_protection(&parsed, private_keys)?;
            decrypt_fields(record, &unwrapped, now)
        }
        None => decrypt_with_zone_default(record, default_master_keys, now),
    }
}

fn decrypt_with_zone_default(record: &CloudKitRecord, defaults: &[Vec<u8>], now: OffsetDateTime) -> Result<DecryptedRecord> {
    if defaults.is_empty() {
        return Err(beacon_error(format!(
            "Record {} carries no protection info of its own, and the zone offered no recordProtectionInfo to fall back on.",
            record.name
        )));
    }
    // Phrased like `find_our_key`'s message so the caller counts it as "no key held", as the
    // Kotlin's MissingKeyException does.
    let master_key = pcs::select_default_master_key(defaults, &record.pcs_key).ok_or_else(|| {
        beacon_error(format!(
            "None of the {} default record key(s) the zone offered matches record {}'s pcsKey, and the record carries no protection info of its own.",
            defaults.len(),
            record.name
        ))
    })?;
    decrypt_fields(record, &UnwrappedProtection::bare(master_key), now)
}

fn decrypt_fields(record: &CloudKitRecord, unwrapped: &UnwrappedProtection, now: OffsetDateTime) -> Result<DecryptedRecord> {
    let mut values = BTreeMap::new();
    let mut raw = BTreeMap::new();
    let mut undecryptable = BTreeMap::new();
    for (name, field) in &record.fields {
        if !field.is_encrypted {
            values.insert(
                name.clone(),
                match &field.raw {
                    Some(b) => FieldValue::Bytes(b.clone()),
                    None => FieldValue::None,
                },
            );
            continue;
        }
        let Some(ciphertext) = &field.raw else {
            undecryptable.insert(name.clone(), "encrypted but carried no bytes".to_string());
            continue;
        };
        let context = FieldContext {
            zone_name: record.zone_name.clone(),
            record_name: record.name.clone(),
            field_name: name.clone(),
        };
        let plaintext = match pcs::decrypt_field(ciphertext, unwrapped, &context, true) {
            Ok(p) => p,
            Err(e) => {
                undecryptable.insert(name.clone(), e.to_string());
                continue;
            }
        };
        raw.insert(name.clone(), plaintext.clone());
        match interpret_plaintext(field.value_type, &plaintext, now) {
            Ok(v) => {
                values.insert(name.clone(), v);
            }
            Err(e) => {
                undecryptable.insert(name.clone(), e.to_string());
            }
        }
    }
    Ok(DecryptedRecord {
        name: record.name.clone(),
        record_type: record.record_type.clone(),
        values,
        raw_values: raw,
        undecryptable,
    })
}

/// Decrypt the records worth decrypting, and count rather than hide what was skipped.
pub fn decrypt_records(
    records: &[CloudKitRecord],
    private_keys: &[PcsKey],
    default_master_keys: &[Vec<u8>],
    now: OffsetDateTime,
) -> DecryptedRecords {
    let mut out = Vec::new();
    let mut skipped: BTreeMap<String, i32> = BTreeMap::new();
    let mut first_miss = None;
    for record in records {
        if !is_wanted(&record.record_type) {
            let key = if record.record_type.is_empty() { "<untyped>".to_string() } else { record.record_type.clone() };
            *skipped.entry(key).or_insert(0) += 1;
            continue;
        }
        match decrypt_record(record, private_keys, default_master_keys, now, false) {
            Ok(decrypted) => out.push(decrypted),
            Err(e) if is_missing_key(&e) => {
                *skipped.entry("no key held".to_string()).or_insert(0) += 1;
                if first_miss.is_none() {
                    first_miss = Some(e.to_string());
                }
            }
            Err(_) => {
                *skipped.entry("would not decrypt".to_string()).or_insert(0) += 1;
            }
        }
    }
    DecryptedRecords { records: out, skipped, first_miss }
}

/// Join beacons with their naming and alignment records; last one wins.
pub fn group_records(records: &[DecryptedRecord]) -> Vec<RecordGroup> {
    let mut naming: HashMap<String, &DecryptedRecord> = HashMap::new();
    let mut alignment: HashMap<String, &DecryptedRecord> = HashMap::new();
    for r in records {
        if r.record_type == crate::cloudkit::record_type::BEACON_NAMING {
            if let Some(FieldValue::Str(id)) = r.values.get("associatedBeacon") {
                naming.insert(id.clone(), r);
            }
        }
        if r.record_type == crate::cloudkit::record_type::KEY_ALIGNMENT {
            if let Some(FieldValue::Str(id)) = r.values.get("beaconIdentifier") {
                alignment.insert(id.clone(), r);
            }
        }
    }
    records
        .iter()
        .filter(|r| r.record_type == crate::cloudkit::record_type::MASTER_BEACON)
        .map(|r| RecordGroup {
            beacon: r.clone(),
            naming: naming.get(&r.name).map(|n| (*n).clone()),
            alignment: alignment.get(&r.name).map(|a| (*a).clone()),
        })
        .collect()
}

/// A beacon with a readable `privateKey` can be located; one without is a device, not a tag.
pub fn can_be_located(beacon: &DecryptedRecord) -> bool {
    matches!(beacon.values.get("privateKey"), Some(FieldValue::Bytes(_)))
}

fn truthy(value: Option<&FieldValue>) -> bool {
    match value {
        None | Some(FieldValue::None) => false,
        Some(FieldValue::Bytes(b)) => !b.is_empty(),
        Some(FieldValue::Str(s)) => !s.is_empty(),
        Some(FieldValue::Int(i)) => *i != 0,
        Some(FieldValue::Double(d)) => *d != 0.0,
        _ => true,
    }
}

/// One decrypted MasterBeaconRecord (plus companions) as an accessory.
pub fn accessory_from_record(
    beacon: &DecryptedRecord,
    naming: Option<&DecryptedRecord>,
    alignment: Option<&DecryptedRecord>,
) -> Result<DecryptedAccessory> {
    let values = &beacon.values;
    let private_key = match values.get("privateKey") {
        Some(FieldValue::Bytes(b)) => b.clone(),
        _ => return Err(beacon_error(format!("Record {} has no readable privateKey", beacon.name))),
    };
    let skn = match values.get("sharedSecret") {
        Some(FieldValue::Bytes(b)) => b.clone(),
        _ => return Err(beacon_error(format!("Record {} has no readable sharedSecret", beacon.name))),
    };
    let sks_value = if truthy(values.get("sharedSecret2")) {
        values.get("sharedSecret2")
    } else {
        values.get("secureLocationsSharedSecret")
    };
    let sks = match sks_value {
        Some(FieldValue::Bytes(b)) => b.clone(),
        _ => {
            return Err(beacon_error(format!(
                "Record {} has neither sharedSecret2 nor secureLocationsSharedSecret",
                beacon.name
            )))
        }
    };
    let paired_at = match values.get("pairingDate") {
        Some(FieldValue::Date(d)) => *d,
        _ => return Err(beacon_error(format!("Record {} has no readable pairingDate", beacon.name))),
    };
    let serial = match values.get("stableIdentifier") {
        Some(FieldValue::Str(s)) => extract_serial(s),
        _ => None,
    };
    let mut alignment_date = None;
    let mut alignment_index = None;
    if let Some(alignment) = alignment {
        if let (Some(FieldValue::Date(d)), Some(FieldValue::Int(i))) = (
            alignment.values.get("lastIndexObservationDate"),
            alignment.values.get("lastIndexObserved"),
        ) {
            alignment_date = Some(*d);
            alignment_index = Some(*i);
        }
    }
    let tail = private_key.len().saturating_sub(MASTER_KEY_TAIL);
    Ok(DecryptedAccessory {
        master_key: private_key[tail..].to_vec(),
        skn,
        sks,
        paired_at,
        name: naming.and_then(|n| match n.values.get("name") {
            Some(FieldValue::Str(s)) => Some(s.clone()),
            _ => None,
        }),
        model: match values.get("model") {
            Some(FieldValue::Str(s)) => Some(s.clone()),
            _ => None,
        },
        identifier: beacon.name.clone(),
        group_identifier: match values.get("groupIdentifier") {
            Some(FieldValue::Str(s)) => Some(s.clone()),
            _ => None,
        },
        serial_number: serial,
        // Python's FindMyAccessory fills these two itself: a missing alignment starts from the
        // pairing date at index 0.
        alignment_date: alignment_date.or(Some(paired_at)),
        alignment_index: alignment_index.or(Some(0)),
    })
}

/// Locatable beacons as accessories; one that cannot be assembled is skipped, not fatal.
pub fn accessories_from_records(records: &[DecryptedRecord]) -> Vec<DecryptedAccessory> {
    group_records(records)
        .iter()
        .filter(|g| can_be_located(&g.beacon))
        .filter_map(|g| accessory_from_record(&g.beacon, g.naming.as_ref(), g.alignment.as_ref()).ok())
        .collect()
}

/// The hardware serial in a `stableIdentifier`.
pub fn extract_serial(stable: &str) -> Option<String> {
    if stable.is_empty() {
        return None;
    }
    let tail = stable.rsplit("~#").next().unwrap_or(stable);
    if tail.starts_with('¶') {
        let sections: Vec<&str> = tail.split('§').collect();
        if sections.len() < 3 {
            return None;
        }
        let bytes = py_from_hex(sections[2])?;
        if bytes.iter().any(|b| *b >= 128) {
            return None;
        }
        return Some(String::from_utf8_lossy(&bytes).into_owned());
    }
    if tail != stable {
        Some(tail.to_string())
    } else {
        None
    }
}

/// Python's `bytes.fromhex`: hex pairs, ASCII whitespace allowed between (never inside) pairs.
fn py_from_hex(s: &str) -> Option<Vec<u8>> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if i + 1 >= chars.len() {
            return None;
        }
        let hi = chars[i].to_digit(16);
        let lo = chars[i + 1].to_digit(16);
        match (hi, lo) {
            (Some(hi), Some(lo)) if chars[i].is_ascii() && chars[i + 1].is_ascii() => out.push(((hi << 4) | lo) as u8),
            _ => return None,
        }
        i += 2;
    }
    Some(out)
}
