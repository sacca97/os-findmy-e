//! The secrets and bookkeeping of one findable accessory, with the official 15-minute key rollover
//! (port of `findmy.accessory.FindMyAccessory`, minus plist import, BLE advertising and scanner
//! helpers; `apple/reports/AccessoryKeys.kt` and `KeyPair.kt`).
//!
//! Key `i` is `derive_ps_key(master, SK_i)` where `SK_0` is the shared secret and
//! `SK_i = x963_kdf(SK_{i-1}, "update", 32)`. The primary key at index `i` comes from SKN; secondary
//! keys come from SKS at `i / 96 + 1` and `i / 96 + 2`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use num_bigint::BigUint;
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::reports::crypto;
use crate::util::b64;

/// `KeyPairType`, matching Python's `KeyPairType` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyPairType {
    Unknown = 0,
    Primary = 1,
    Secondary = 2,
}

impl KeyPairType {
    pub fn of(value: i32) -> Result<KeyPairType> {
        match value {
            0 => Ok(KeyPairType::Unknown),
            1 => Ok(KeyPairType::Primary),
            2 => Ok(KeyPairType::Secondary),
            _ => Err(Error::Backend(format!("unknown key type {value}"))),
        }
    }

    pub fn value(self) -> i32 {
        self as i32
    }
}

/// A P-224 private/public key pair of an accessory (port of `findmy.keys.KeyPair`). The private key
/// is a credential: nothing here logs it.
#[derive(Clone)]
pub struct KeyPair {
    scalar: BigUint,
    key_type: KeyPairType,
    name: Option<String>,
    adv_key: Vec<u8>,
    hashed: Vec<u8>,
}

impl KeyPair {
    pub fn new(private_key: &[u8], key_type: KeyPairType, name: Option<String>) -> Result<KeyPair> {
        let scalar = BigUint::from_bytes_be(private_key);
        if !crypto::is_valid_private_scalar(&scalar) {
            return Err(Error::Backend("not a valid P-224 private key".into()));
        }
        let adv_key = crypto::public_x(&scalar);
        let hashed = Sha256::digest(&adv_key).to_vec();
        Ok(KeyPair { scalar, key_type, name, adv_key, hashed })
    }

    pub fn from_b64(private_key_b64: &str) -> Result<KeyPair> {
        let bytes = crate::util::b64_decode(private_key_b64)
            .ok_or_else(|| Error::Backend("bad base64 private key".into()))?;
        KeyPair::new(&bytes, KeyPairType::Unknown, None)
    }

    pub fn key_type(&self) -> KeyPairType {
        self.key_type
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn private_key_bytes(&self) -> Vec<u8> {
        crypto::to_fixed(&self.scalar, crypto::KEY_BYTES)
    }

    pub fn private_key_b64(&self) -> String {
        b64(&self.private_key_bytes())
    }

    pub fn adv_key_bytes(&self) -> &[u8] {
        &self.adv_key
    }

    pub fn adv_key_b64(&self) -> String {
        b64(&self.adv_key)
    }

    pub fn hashed_adv_key_bytes(&self) -> &[u8] {
        &self.hashed
    }

    pub fn hashed_adv_key_b64(&self) -> String {
        b64(&self.hashed)
    }

    pub fn dh_exchange(&self, ephemeral_point: &[u8]) -> Result<Vec<u8>> {
        crypto::ecdh(&self.scalar, ephemeral_point)
    }

    pub fn to_json(&self) -> Json {
        json!({
            "type": "keypair",
            "private_key": self.private_key_b64(),
            "key_type": self.key_type.value(),
            "name": self.name,
        })
    }

    pub fn from_json(value: &Json) -> Result<KeyPair> {
        if value.get("type").and_then(|v| v.as_str()) != Some("keypair") {
            return Err(Error::Backend("not a keypair".into()));
        }
        let private = value
            .get("private_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Backend("incomplete keypair".into()))?;
        let key_type = value
            .get("key_type")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| Error::Backend("incomplete keypair".into()))?;
        if value.get("name").is_none() {
            return Err(Error::Backend("incomplete keypair".into()));
        }
        let name = value.get("name").and_then(|v| v.as_str()).map(str::to_string);
        let mut key = KeyPair::from_b64(private)?;
        key.key_type = KeyPairType::of(key_type as i32)?;
        key.name = name;
        Ok(key)
    }
}

impl PartialEq for KeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.hashed == other.hashed
    }
}
impl Eq for KeyPair {}

impl std::hash::Hash for KeyPair {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hashed.hash(state);
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("name", &self.name)
            .field("key_type", &self.key_type)
            .field("private", &"<redacted>")
            .finish()
    }
}

/// One kind of rolling key (`_AccessoryKeyGenerator`). A sequential checkpoint cache makes `keyAt(n)`
/// after `keyAt(n-1)` one KDF step.
struct RollingKeyGenerator {
    master_key: Vec<u8>,
    initial_sk: Vec<u8>,
    key_type: KeyPairType,
    state: Mutex<GenState>,
}

struct GenState {
    sk_cache: BTreeMap<i32, Vec<u8>>,
    memo: HashMap<i32, KeyPair>,
}

impl RollingKeyGenerator {
    fn new(master_key: Vec<u8>, initial_sk: Vec<u8>, key_type: KeyPairType) -> Result<Self> {
        if master_key.len() != 28 {
            return Err(Error::Backend("the master key must be 28 bytes long".into()));
        }
        if initial_sk.len() != 32 {
            return Err(Error::Backend("the sk must be 32 bytes long".into()));
        }
        Ok(RollingKeyGenerator {
            master_key,
            initial_sk,
            key_type,
            state: Mutex::new(GenState { sk_cache: BTreeMap::new(), memo: HashMap::new() }),
        })
    }

    fn key_at(&self, index: i32) -> Result<KeyPair> {
        if index < 0 {
            return Err(Error::Backend("the key index must be non-negative".into()));
        }
        let mut state = self.state.lock().unwrap();
        if let Some(k) = state.memo.get(&index) {
            return Ok(k.clone());
        }
        let sk = self.sk_at(&mut state, index);
        let key = KeyPair::new(&crypto::derive_ps_key(&self.master_key, &sk), self.key_type, None)?;
        if state.memo.len() >= 8192 {
            state.memo.clear();
        }
        state.memo.insert(index, key.clone());
        Ok(key)
    }

    /// The secret-key chain: index 0 is the initial `sk`, each later index one x963-KDF step.
    fn sk_at(&self, state: &mut GenState, index: i32) -> Vec<u8> {
        let mut best_index = 0;
        let mut best_sk = self.initial_sk.clone();
        if let Some((&i, sk)) = state.sk_cache.range(..=index).next_back() {
            if i >= best_index {
                best_index = i;
                best_sk = sk.clone();
            }
        }
        let mut cur = best_sk;
        let mut i = best_index + 1;
        while i <= index {
            cur = crypto::x963_kdf(&cur, b"update", 32);
            state.sk_cache.insert(i, cur.clone());
            i += 1;
        }
        cur
    }
}

/// An accessory JSON that is not what `FindMyAccessory.to_json` writes.
#[derive(Debug, Clone)]
pub struct AccessoryFormatError(pub String);

impl std::fmt::Display for AccessoryFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for AccessoryFormatError {}

/// The secrets and bookkeeping of one findable accessory.
pub struct AccessoryKeys {
    primary: RollingKeyGenerator,
    secondary: RollingKeyGenerator,
    master_key: Vec<u8>,
    skn: Vec<u8>,
    sks: Vec<u8>,
    pub paired_at: OffsetDateTime,
    pub name: Option<String>,
    pub model: Option<String>,
    pub identifier: Option<String>,
    pub group_identifier: Option<String>,
    pub serial_number: Option<String>,
    alignment: Mutex<(OffsetDateTime, i32)>,
}

impl AccessoryKeys {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        master_key: Vec<u8>,
        skn: Vec<u8>,
        sks: Vec<u8>,
        paired_at: OffsetDateTime,
        name: Option<String>,
        model: Option<String>,
        identifier: Option<String>,
        group_identifier: Option<String>,
        serial_number: Option<String>,
        alignment_date: Option<OffsetDateTime>,
        alignment_index: Option<i32>,
    ) -> Result<AccessoryKeys> {
        let primary = RollingKeyGenerator::new(master_key.clone(), skn.clone(), KeyPairType::Primary)?;
        let secondary = RollingKeyGenerator::new(master_key.clone(), sks.clone(), KeyPairType::Secondary)?;
        Ok(AccessoryKeys {
            primary,
            secondary,
            master_key,
            skn,
            sks,
            paired_at,
            name,
            model,
            identifier,
            group_identifier,
            serial_number,
            alignment: Mutex::new((alignment_date.unwrap_or(paired_at), alignment_index.unwrap_or(0))),
        })
    }

    pub fn master_key(&self) -> Vec<u8> {
        self.master_key.clone()
    }
    pub fn skn(&self) -> Vec<u8> {
        self.skn.clone()
    }
    pub fn sks(&self) -> Vec<u8> {
        self.sks.clone()
    }

    pub fn alignment_date(&self) -> OffsetDateTime {
        self.alignment.lock().unwrap().0
    }
    pub fn alignment_index(&self) -> i32 {
        self.alignment.lock().unwrap().1
    }

    /// A stable id: the identifier, else 8 bytes of SHA-256 of the secrets in hex.
    pub fn id(&self) -> String {
        if let Some(id) = &self.identifier {
            return id.clone();
        }
        let mut h = Sha256::new();
        h.update(&self.master_key);
        h.update(&self.skn);
        h.update(&self.sks);
        let d = h.finalize();
        d[..8].iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Lowest index the accessory could be at, at `dt`.
    pub fn min_index(&self, dt: OffsetDateTime) -> i32 {
        let (align_date, align_index) = *self.alignment.lock().unwrap();
        if dt >= align_date {
            return align_index;
        }
        let diff = (align_date - dt).whole_seconds() / 900;
        align_index - diff as i32
    }

    /// Highest index the accessory could be at, at `dt`.
    pub fn max_index(&self, dt: OffsetDateTime) -> i32 {
        let (align_date, align_index) = *self.alignment.lock().unwrap();
        if dt <= align_date {
            return align_index;
        }
        let diff = (dt - align_date).whole_seconds() / 900;
        align_index + diff as i32
    }

    /// Ignores anything that goes backwards in time or index; returns whether it moved.
    pub fn update_alignment(&self, dt: OffsetDateTime, index: i32) -> bool {
        let mut a = self.alignment.lock().unwrap();
        if dt < a.0 || index < a.1 {
            return false;
        }
        a.0 = dt;
        a.1 = index;
        true
    }

    pub fn primary_key_at(&self, index: i32) -> Result<KeyPair> {
        self.primary.key_at(index)
    }

    pub fn secondary_keys_at(&self, index: i32) -> Result<(KeyPair, KeyPair)> {
        Ok((self.secondary.key_at(index / 96 + 1)?, self.secondary.key_at(index / 96 + 2)?))
    }

    /// Primary and secondary keys that might be active at `index`; empty for a negative index.
    pub fn keys_at(&self, index: i32) -> Result<Vec<KeyPair>> {
        if index < 0 {
            return Ok(Vec::new());
        }
        let (s1, s2) = self.secondary_keys_at(index)?;
        let mut out = vec![self.primary_key_at(index)?, s1, s2];
        let mut seen = HashSet::new();
        out.retain(|k| seen.insert(k.hashed_adv_key_bytes().to_vec()));
        Ok(out)
    }

    /// Keys that could be active from `start` to `end` inclusive, each once, with the first index it
    /// occurs at.
    pub fn keys_between(&self, start: i32, end: i32) -> Result<Vec<(i32, KeyPair)>> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for i in start..=end {
            for key in self.keys_at(i)? {
                if seen.insert(key.hashed_adv_key_bytes().to_vec()) {
                    out.push((i, key));
                }
            }
        }
        Ok(out)
    }

    /// Same, for a time range: from `min_index(start)` to `max_index(end)`.
    pub fn keys_between_times(
        &self,
        start: OffsetDateTime,
        end: OffsetDateTime,
    ) -> Result<Vec<(i32, KeyPair)>> {
        self.keys_between(self.min_index(start), self.max_index(end))
    }

    pub fn to_json(&self) -> Json {
        let (align_date, align_index) = *self.alignment.lock().unwrap();
        json!({
            "type": "accessory",
            "master_key": hex(&self.master_key),
            "skn": hex(&self.skn),
            "sks": hex(&self.sks),
            "paired_at": isoformat(self.paired_at),
            "name": self.name,
            "model": self.model,
            "identifier": self.identifier,
            "group_identifier": self.group_identifier,
            "serial_number": self.serial_number,
            "alignment_date": isoformat(align_date),
            "alignment_index": align_index,
        })
    }

    pub fn from_json(value: &Json) -> std::result::Result<AccessoryKeys, AccessoryFormatError> {
        let fail = |m: &str| Err(AccessoryFormatError(m.to_string()));
        if value.get("type").and_then(|v| v.as_str()) != Some("accessory") {
            return fail("not an accessory");
        }
        for field in [
            "master_key",
            "skn",
            "sks",
            "paired_at",
            "name",
            "model",
            "identifier",
            "alignment_date",
            "alignment_index",
        ] {
            if value.get(field).is_none() {
                return fail(&format!("missing field {field}"));
            }
        }
        let str_field = |k: &str| value.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let unhex_field = |k: &str| -> std::result::Result<Vec<u8>, AccessoryFormatError> {
            let s = value
                .get(k)
                .and_then(|v| v.as_str())
                .ok_or_else(|| AccessoryFormatError(format!("bad field {k}")))?;
            unhex(s).map_err(|_| AccessoryFormatError(format!("bad hex in {k}")))
        };
        let alignment_date = match value.get("alignment_date") {
            Some(Json::Null) => None,
            Some(Json::String(s)) => Some(parse_iso(s).map_err(|_| AccessoryFormatError("invalid date".into()))?),
            _ => return fail("bad alignment_date"),
        };
        let alignment_index = match value.get("alignment_index") {
            Some(Json::Null) => None,
            Some(v) => v.as_i64().map(|i| i as i32),
            None => None,
        };
        let paired_at = str_field("paired_at")
            .ok_or_else(|| AccessoryFormatError("missing paired_at".into()))
            .and_then(|s| parse_iso(&s).map_err(|_| AccessoryFormatError("invalid date".into())))?;
        AccessoryKeys::new(
            unhex_field("master_key")?,
            unhex_field("skn")?,
            unhex_field("sks")?,
            paired_at,
            str_field("name"),
            str_field("model"),
            str_field("identifier"),
            str_field("group_identifier"),
            str_field("serial_number"),
            alignment_date,
            alignment_index,
        )
        .map_err(|e| AccessoryFormatError(e.to_string()))
    }

    pub fn from_json_str(text: &str) -> std::result::Result<AccessoryKeys, AccessoryFormatError> {
        let value: Json = serde_json::from_str(text)
            .map_err(|_| AccessoryFormatError("invalid accessory JSON".into()))?;
        AccessoryKeys::from_json(&value)
    }
}

/// `_extract_serial_from_stable_id`: the hardware serial in a plist `stableIdentifier` list, or None.
pub fn serial_from_stable_identifier(stable: Option<&[String]>) -> Option<String> {
    let stable = stable?;
    let first = stable.first()?;
    let tail = first.rsplit("~#").next().unwrap_or(first);
    if let Some(rest) = tail.strip_prefix('¶') {
        let sections: Vec<&str> = rest.split('§').collect();
        if sections.len() >= 3 {
            return match unhex(sections[2]) {
                Ok(raw) if raw.iter().all(|b| *b < 128) => Some(String::from_utf8_lossy(&raw).into_owned()),
                _ => None,
            };
        }
        return None;
    }
    if tail != first {
        Some(tail.to_string())
    } else {
        None
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(Error::Backend("odd hex".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in 0..s.len() / 2 {
        let hi = (bytes[2 * i] as char).to_digit(16);
        let lo = (bytes[2 * i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(hi), Some(lo)) => out.push(((hi << 4) | lo) as u8),
            _ => return Err(Error::Backend("bad hex".into())),
        }
    }
    Ok(out)
}

/// Python's `datetime.isoformat()` for an aware datetime: `T`, microseconds only when non-zero, and
/// an `+HH:MM` offset.
pub fn isoformat(dt: OffsetDateTime) -> String {
    let mut s = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    let micros = dt.nanosecond() / 1000;
    if micros != 0 {
        s.push_str(&format!(".{micros:06}"));
    }
    let total = dt.offset().whole_seconds();
    let abs = total.abs();
    s.push(if total < 0 { '-' } else { '+' });
    s.push_str(&format!("{:02}:{:02}", abs / 3600, (abs / 60) % 60));
    if abs % 60 != 0 {
        s.push_str(&format!(":{:02}", abs % 60));
    }
    s
}

/// `datetime.fromisoformat` for what [`isoformat`] writes (and `Z`, a space separator, date-only).
pub fn parse_iso(text: &str) -> Result<OffsetDateTime> {
    let normalized = if text.len() > 10 && text.as_bytes()[10] == b' ' {
        format!("{}T{}", &text[..10], &text[11..])
    } else {
        text.to_string()
    };
    if let Ok(dt) = OffsetDateTime::parse(&normalized, &Rfc3339) {
        return Ok(dt);
    }
    // A naive datetime or a date only: Python reads it in the system zone; UTC is used here.
    let with_z = if normalized.contains('T') {
        format!("{normalized}Z")
    } else {
        format!("{normalized}T00:00:00Z")
    };
    OffsetDateTime::parse(&with_z, &Rfc3339).map_err(|_| Error::Backend("invalid date".into()))
}
