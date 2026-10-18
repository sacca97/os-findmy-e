//! Reading values out of CloudKit records (port of `findmy/cloudkit/records.py` and
//! `apple/cloudkit/Records.kt`). Decryption is in `pcs`; this stops where a key is needed.

use std::collections::BTreeMap;

use apple_proto::cloudkit::{record::Value, Record, RecordChange};

/// One top-level protobuf field: its number, wire type and (for length-delimited fields only) its
/// payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireField {
    pub number: u64,
    pub wire_type: i32,
    pub payload: Vec<u8>,
}

/// Walk a payload's top-level fields without a schema; stops (rather than throwing) when it runs off
/// the end.
pub fn iterate_wire_fields(data: &[u8]) -> Vec<WireField> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    macro_rules! varint {
        () => {{
            let mut value: u64 = 0;
            let mut shift = 0u32;
            loop {
                if offset >= data.len() {
                    break None;
                }
                let b = data[offset];
                offset += 1;
                if shift < 64 {
                    value |= ((b & 0x7f) as u64) << shift;
                }
                if b & 0x80 == 0 {
                    break Some(value);
                }
                shift += 7;
            }
        }};
    }
    while offset < data.len() {
        let Some(tag) = varint!() else { return out };
        let number = tag >> 3;
        let wire = (tag & 7) as i32;
        match wire {
            2 => {
                let Some(length) = varint!() else { return out };
                if length > (data.len() - offset) as u64 {
                    return out;
                }
                let payload = data[offset..offset + length as usize].to_vec();
                offset += length as usize;
                out.push(WireField { number, wire_type: wire, payload });
            }
            0 => {
                while offset < data.len() && data[offset] & 0x80 != 0 {
                    offset += 1;
                }
                offset += 1;
                out.push(WireField { number, wire_type: wire, payload: Vec::new() });
            }
            5 => {
                offset += 4;
                out.push(WireField { number, wire_type: wire, payload: Vec::new() });
            }
            1 => {
                offset += 8;
                out.push(WireField { number, wire_type: wire, payload: Vec::new() });
            }
            _ => return out,
        }
    }
    out
}

/// One named field of a record, before decryption. `value_type` describes the PLAINTEXT; branch on
/// `is_encrypted`.
#[derive(Debug, Clone)]
pub struct RecordField {
    pub name: String,
    pub value_type: i32,
    pub is_encrypted: bool,
    /// Ciphertext if encrypted, otherwise the field's `bytes_value` if it had one.
    pub raw: Option<Vec<u8>>,
    pub value: Value,
}

/// A record as fetched, fields indexed by name. `zone_name` is authenticated with every field.
#[derive(Debug, Clone)]
pub struct CloudKitRecord {
    pub name: String,
    pub zone_name: String,
    pub record_type: String,
    pub fields: BTreeMap<String, RecordField>,
    /// The DER protection structure, or `None` when the record carries none.
    pub protection_info: Option<Vec<u8>>,
    pub etag: String,
    pub protection_info_tag: String,
    pub pcs_key: Vec<u8>,
    pub source: Option<Record>,
}

impl CloudKitRecord {
    pub fn with_record_type(mut self, record_type: String) -> Self {
        self.record_type = record_type;
        self
    }

    pub fn from_proto(record: &Record, zone_name: &str) -> CloudKitRecord {
        let mut fields = BTreeMap::new();
        for field in &record.record_field {
            let name = field
                .identifier
                .as_ref()
                .and_then(|i| i.name.clone())
                .unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let value = field.value.clone().unwrap_or_default();
            let raw = value.bytes_value.clone();
            fields.insert(
                name.clone(),
                RecordField {
                    name,
                    value_type: value.r#type.unwrap_or(0),
                    is_encrypted: value.is_encrypted.unwrap_or(false),
                    raw,
                    value,
                },
            );
        }
        let protection = record
            .protection_info
            .as_ref()
            .and_then(|p| p.protection_info.clone())
            .filter(|b| !b.is_empty());
        let protection_info_tag = record
            .protection_info
            .as_ref()
            .and_then(|p| p.protection_info_tag.clone())
            .unwrap_or_default();
        let record_name = record
            .record_identifier
            .as_ref()
            .and_then(|r| r.value.as_ref())
            .and_then(|v| v.name.clone())
            .unwrap_or_default();
        let zone = if zone_name.is_empty() {
            record
                .record_identifier
                .as_ref()
                .and_then(|r| r.zone_identifier.as_ref())
                .and_then(|z| z.value.as_ref())
                .and_then(|v| v.name.clone())
                .unwrap_or_default()
        } else {
            zone_name.to_string()
        };
        CloudKitRecord {
            name: record_name,
            zone_name: zone,
            record_type: record.r#type.as_ref().and_then(|t| t.name.clone()).unwrap_or_default(),
            fields,
            protection_info: protection,
            etag: record.etag.clone().unwrap_or_default(),
            protection_info_tag,
            pcs_key: record.pcs_key.clone().unwrap_or_default(),
            source: Some(record.clone()),
        }
    }

    /// Changes to records, dropping changes that carry no record (deletions); the change's type fills
    /// a missing one.
    pub fn from_changes(changes: &[RecordChange], zone_name: &str) -> Vec<CloudKitRecord> {
        let mut out = Vec::new();
        for change in changes {
            let Some(record) = &change.record else { continue };
            let mut converted = CloudKitRecord::from_proto(record, zone_name);
            if converted.record_type.is_empty() {
                if let Some(record_type) = change.record_type.as_ref().and_then(|t| t.name.clone()) {
                    converted = converted.with_record_type(record_type);
                }
            }
            out.push(converted);
        }
        out
    }
}
