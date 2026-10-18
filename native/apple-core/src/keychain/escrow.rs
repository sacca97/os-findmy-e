//! The escrow proxy's framing and record listing (port of `findmy/keychain/escrow.py`).
//!
//! The KeyVault message framing is used by both escrow blobs and nothing else in the protocol;
//! [`split_keyvault_message`] and [`build_keyvault_message`] are pure and testable offline. The record
//! metadata parsing and the recovery-option join are here too. The HTTP client for the proxy is
//! [`EscrowProxy`].

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;

use crate::error::{Error, Result};
use crate::plist::{self, Value};
use crate::reports::keys::parse_iso;

pub const ESCROW_LABEL_SECURE_BACKUP: &str = "com.apple.securebackup.record";
pub const ESCROW_LABEL_ICDP: &str = "com.apple.icdp.record";
pub const COMPANION_SUFFIX: &str = ".double";
pub const ROOT_CERT_VERSIONS: [i64; 4] = [101, 102, 103, 500];
pub const COMMAND_SPELLINGS: [(&str, &str); 6] = [
    ("get_records", "GETRECORDS"),
    ("get_club_cert", "GETCLUB"),
    ("srp_init", "SRP_INIT"),
    ("recover", "RECOVER"),
    ("enroll", "ENROLL"),
    ("delete", "DELETE"),
];
const CONTENT_TYPE: &str = "application/x-apple-plst";
const SBD_PRODUCT: &str = "com.apple.sbd/638.100.48";
const CLIENT_INFO_BUNDLE: &str = "com.apple.AuthKit/1 (com.apple.sbd/638.100.48)";

fn escrow_error(message: impl Into<String>) -> Error {
    Error::Backend(message.into())
}

/// Derive the escrow proxy's host from the account's iCloud partition.
pub fn escrow_host(partition: &str) -> String {
    format!("https://p{partition}-escrowproxy.icloud.com:443")
}

fn cert_versions() -> serde_json::Value {
    serde_json::json!({
        "baseRootCertVersions": ROOT_CERT_VERSIONS,
        "trustedRootCertVersions": ROOT_CERT_VERSIONS,
    })
}

// --------------------------------------------------------------------------------- KeyVault framing

/// One section of a framed message, which may occupy more space than it declares.
#[derive(Debug, Clone)]
pub struct KeyVaultSection {
    pub data: Vec<u8>,
    /// Total bytes this section occupies, its length prefix included. `None` means exact.
    pub footprint: Option<usize>,
}

impl KeyVaultSection {
    pub fn new(data: Vec<u8>) -> KeyVaultSection {
        KeyVaultSection { data, footprint: None }
    }

    pub fn with_footprint(data: Vec<u8>, footprint: usize) -> KeyVaultSection {
        KeyVaultSection { data, footprint: Some(footprint) }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = (self.data.len() as u32).to_be_bytes().to_vec();
        body.extend_from_slice(&self.data);
        match self.footprint {
            None => Ok(body),
            Some(footprint) if footprint >= body.len() => {
                body.resize(footprint, 0);
                Ok(body)
            }
            Some(footprint) => Err(escrow_error(format!(
                "A {}-byte section cannot fit a {footprint}-byte footprint",
                body.len()
            ))),
        }
    }
}

/// Split the framing both escrow blobs use.
pub fn split_keyvault_message(data: &[u8], header_length: usize, section_count: usize) -> Result<(Vec<u8>, Vec<u8>, Vec<Vec<u8>>)> {
    let offsets_at = 4 + header_length;
    let base = offsets_at + (section_count + 1) * 4;
    if data.len() < base {
        return Err(escrow_error(format!(
            "KeyVault message is {} bytes, too short for a {header_length}-byte header and {section_count} section offset(s)",
            data.len()
        )));
    }
    let prefix = data[..4].to_vec();
    let header = data[4..4 + header_length].to_vec();
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let raw = &data[offsets_at + index * 4..offsets_at + (index + 1) * 4];
        let offset = base + u32::from_be_bytes(raw.try_into().unwrap()) as usize;
        if offset + 4 > data.len() {
            return Err(escrow_error(format!("KeyVault section {index} starts past the end of the message")));
        }
        let length = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        if offset + 4 + length > data.len() {
            return Err(escrow_error(format!(
                "KeyVault section {index} claims {length} bytes but is truncated"
            )));
        }
        sections.push(data[offset + 4..offset + 4 + length].to_vec());
    }
    Ok((prefix, header, sections))
}

/// Parse a framed message, discarding its four leading bytes.
pub fn parse_keyvault_message(data: &[u8], header_length: usize, section_count: usize) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    let (_, header, sections) = split_keyvault_message(data, header_length, section_count)?;
    Ok((header, sections))
}

/// Build a message in the framing [`parse_keyvault_message`] reads.
pub fn build_keyvault_message(header: &[u8], sections: &[KeyVaultSection]) -> Result<Vec<u8>> {
    let offsets_at = 4 + header.len();
    let base = offsets_at + (sections.len() + 1) * 4;
    let mut body = Vec::new();
    let mut offsets = Vec::new();
    for section in sections {
        offsets.push(body.len() as u32);
        body.extend_from_slice(&section.encode()?);
    }
    offsets.push(body.len() as u32);
    let total = base + body.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u32).to_be_bytes());
    out.extend_from_slice(header);
    for offset in offsets {
        out.extend_from_slice(&offset.to_be_bytes());
    }
    out.extend_from_slice(&body);
    Ok(out)
}

// --------------------------------------------------------------------------------- records

#[derive(Debug, Clone)]
pub struct EscrowRecord {
    pub label: String,
    pub device_name: Option<String>,
    pub device_model: Option<String>,
    pub device_model_class: Option<String>,
    pub serial: Option<String>,
    pub build: Option<String>,
    pub escrowed_at: Option<time::OffsetDateTime>,
    pub bottle_id: Option<String>,
    pub passcode_generation: Option<i64>,
    pub metadata: BTreeMap<String, Value>,
}

impl EscrowRecord {
    pub fn peer_id(&self) -> String {
        let prefix = format!("{ESCROW_LABEL_ICDP}.");
        self.companion_of().strip_prefix(&prefix).unwrap_or(&self.companion_of()).to_string()
    }

    pub fn is_companion(&self) -> bool {
        self.label.ends_with(COMPANION_SUFFIX)
    }

    pub fn companion_of(&self) -> String {
        if self.is_companion() {
            self.label[..self.label.len() - COMPANION_SUFFIX.len()].to_string()
        } else {
            self.label.clone()
        }
    }

    pub fn is_recovery_candidate(&self) -> bool {
        self.bottle_id.is_some()
    }

    pub fn describe(&self) -> String {
        let mut parts = vec![self.device_name.clone().unwrap_or_else(|| "unnamed device".to_string())];
        if let Some(model) = &self.device_model {
            parts.push(model.clone());
        }
        if let Some(serial) = &self.serial {
            parts.push(format!("serial {serial}"));
        }
        if let Some(at) = self.escrowed_at {
            parts.push(format!("escrowed {}", &crate::reports::keys::isoformat(at)[..10]));
        }
        parts.join(", ")
    }
}

/// Decode one record's metadata plist, tolerating a shape this does not know.
pub fn parse_metadata(label: &str, encoded: &[u8]) -> Result<EscrowRecord> {
    let raw = if encoded.is_empty() {
        Vec::new()
    } else {
        // The proxy carries it base64 in a string; accept raw bytes too.
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap_or_else(|_| encoded.to_vec())
    };
    let metadata = plist::parse_dict(&raw)?;

    let client = metadata
        .get("ClientMetadata")
        .or_else(|| metadata.get("clientMetadata"))
        .and_then(|v| v.as_dict());
    let str_field = |key: &str| metadata.get(key).and_then(|v| v.as_str()).map(str::to_string);
    let client_str = |key: &str| client.and_then(|c| c.get(key)).and_then(|v| v.as_str()).map(str::to_string);

    let escrowed_at = metadata
        .get("com.apple.securebackup.timestamp")
        .or_else(|| metadata.get("timestamp"))
        .and_then(value_datetime);

    Ok(EscrowRecord {
        label: label.to_string(),
        device_name: client_str("device_name"),
        device_model: client_str("device_model"),
        device_model_class: client_str("device_model_class"),
        serial: str_field("serial"),
        build: str_field("build"),
        escrowed_at,
        bottle_id: str_field("bottleID"),
        passcode_generation: metadata.get("passcodeGeneration").and_then(|v| v.as_i64()),
        metadata,
    })
}

fn value_datetime(value: &Value) -> Option<time::OffsetDateTime> {
    match value {
        Value::Date(s) | Value::String(s) => parse_iso(s).ok(),
        _ => None,
    }
}

#[derive(Debug, Clone, Default)]
pub struct EscrowListing {
    pub records: Vec<EscrowRecord>,
    pub unreadable: Vec<String>,
    pub status: Option<i64>,
    pub message: Option<String>,
}

impl EscrowListing {
    pub fn recovery_candidates(&self) -> Vec<&EscrowRecord> {
        self.records.iter().filter(|r| r.is_recovery_candidate()).collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct RecoveryOptions {
    pub recoverable: Vec<EscrowRecord>,
    pub described_but_not_viable: Vec<EscrowRecord>,
    pub viable_but_undescribed: Vec<String>,
    pub viability_reported: bool,
}

impl RecoveryOptions {
    pub fn viability_is_trustworthy(&self) -> bool {
        self.viability_reported
    }

    pub fn safe_to_delete(&self) -> Vec<&EscrowRecord> {
        if !self.viability_is_trustworthy() {
            return Vec::new();
        }
        self.described_but_not_viable.iter().collect()
    }

    pub fn unsafe_to_delete(&self) -> Vec<&EscrowRecord> {
        self.recoverable.iter().collect()
    }

    pub fn device_count(&self) -> usize {
        let mut serials: BTreeSet<String> = BTreeSet::new();
        for record in self.recoverable.iter().chain(self.described_but_not_viable.iter()) {
            serials.insert(record.serial.clone().unwrap_or_else(|| record.label.clone()));
        }
        serials.len()
    }

    pub fn describe(&self) -> String {
        let mut parts = vec![format!("{} recoverable", self.recoverable.len())];
        if !self.described_but_not_viable.is_empty() {
            parts.push(format!("{} described but not viable", self.described_but_not_viable.len()));
        }
        if !self.viable_but_undescribed.is_empty() {
            parts.push(format!("{} viable but undescribed", self.viable_but_undescribed.len()));
        }
        parts.join(", ")
    }
}

/// Join escrow metadata against the bottles Cuttlefish considers usable.
pub fn join_recovery_options(listing: &EscrowListing, viable_bottle_ids: &[String]) -> RecoveryOptions {
    let viable: BTreeSet<&String> = viable_bottle_ids.iter().collect();
    let mut recoverable = Vec::new();
    let mut not_viable = Vec::new();
    for record in &listing.records {
        if !record.is_recovery_candidate() {
            continue;
        }
        if viable.contains(&record.label) {
            recoverable.push(record.clone());
        } else {
            not_viable.push(record.clone());
        }
    }
    let described: BTreeSet<&String> = listing.records.iter().map(|r| &r.label).collect();
    let mut undescribed: Vec<String> = viable
        .iter()
        .filter(|label| !described.contains(**label))
        .map(|s| (*s).clone())
        .collect();
    undescribed.sort();
    let viability_reported = !viable.is_empty();
    RecoveryOptions {
        recoverable,
        described_but_not_viable: not_viable,
        viable_but_undescribed: undescribed,
        viability_reported,
    }
}

// --------------------------------------------------------------------------------- proxy

/// What the escrow proxy needs from a signed-in account.
pub trait EscrowAccount: Send + Sync {
    /// The client-info string for a given bundle (`com.apple.sbd/...` for the proxy).
    fn client_info(&self, bundle: &str) -> String;
    fn user_agent(&self, product: &str) -> String;
    fn timeout(&self) -> std::time::Duration;
    fn anisette_headers<'a>(&'a self) -> crate::login::BoxFuture<'a, Result<BTreeMap<String, String>>>;
    fn http(&self) -> &crate::http::Http;
}

/// A read-only client for the escrow proxy. The PET is supplied by whatever logged in.
pub struct EscrowProxy {
    account: std::sync::Arc<dyn EscrowAccount>,
    host: String,
    pet: std::sync::Mutex<String>,
    /// The Apple ID the proxy authenticates as. The account trait is sync and cannot fetch it, so it is
    /// captured by the caller when the session opens (a restored `AppleAccount` returns it from its session).
    account_name: String,
}

/// The escrow commands the recovery path uses, so tests can inject a scripted proxy.
pub trait EscrowCommands: Send + Sync {
    fn list_records<'a>(&'a self) -> crate::login::BoxFuture<'a, Result<EscrowListing>>;
    fn srp_init<'a>(&'a self, label: &'a str, client_public: &'a [u8], transaction_id: &'a str)
        -> crate::login::BoxFuture<'a, Result<serde_json::Value>>;
    fn recover<'a>(&'a self, label: &'a str, proof_blob: &'a [u8], transaction_id: &'a str, dsid: Option<&'a str>)
        -> crate::login::BoxFuture<'a, Result<serde_json::Value>>;
    /// Replace the PET (it lasts about five minutes; a session that outlives it renews).
    fn replace_pet<'a>(&'a self, _pet: &'a str) -> crate::login::BoxFuture<'a, Result<()>> {
        Box::pin(async move { Ok(()) })
    }
}

impl EscrowCommands for EscrowProxy {
    fn replace_pet<'a>(&'a self, pet: &'a str) -> crate::login::BoxFuture<'a, Result<()>> {
        Box::pin(async move { EscrowProxy::replace_pet(self, pet) })
    }
    fn list_records<'a>(&'a self) -> crate::login::BoxFuture<'a, Result<EscrowListing>> {
        Box::pin(async move { EscrowProxy::list_records(self).await })
    }
    fn srp_init<'a>(&'a self, label: &'a str, client_public: &'a [u8], transaction_id: &'a str)
        -> crate::login::BoxFuture<'a, Result<serde_json::Value>>
    {
        Box::pin(async move { EscrowProxy::srp_init(self, label, client_public, transaction_id).await })
    }
    fn recover<'a>(&'a self, label: &'a str, proof_blob: &'a [u8], transaction_id: &'a str, dsid: Option<&'a str>)
        -> crate::login::BoxFuture<'a, Result<serde_json::Value>>
    {
        Box::pin(async move { EscrowProxy::recover(self, label, proof_blob, transaction_id, dsid).await })
    }
}

impl EscrowProxy {
    pub fn new(account: std::sync::Arc<dyn EscrowAccount>, host: String, pet: String, account_name: String) -> Result<EscrowProxy> {
        if pet.is_empty() {
            return Err(escrow_error("The escrow proxy needs a PET; an empty one will be rejected"));
        }
        if account_name.is_empty() {
            return Err(escrow_error("The escrow proxy needs the Apple ID to authenticate as"));
        }
        Ok(EscrowProxy {
            account,
            host: host.trim_end_matches('/').to_string(),
            pet: std::sync::Mutex::new(pet),
            account_name,
        })
    }

    pub fn replace_pet(&self, pet: &str) -> Result<()> {
        if pet.is_empty() {
            return Err(escrow_error("The escrow proxy needs a PET; an empty one will be rejected"));
        }
        *self.pet.lock().unwrap() = pet.to_string();
        Ok(())
    }

    async fn headers(&self) -> Result<Vec<(String, String)>> {
        let mut headers = vec![
            ("Content-Type".into(), CONTENT_TYPE.into()),
            ("User-Agent".into(), self.account.user_agent(SBD_PRODUCT)),
            ("X-Mme-Client-Info".into(), self.account.client_info(CLIENT_INFO_BUNDLE)),
            ("Accept".into(), "*/*".into()),
            ("Accept-Language".into(), "en-US,en;q=0.9".into()),
            ("X-Apple-I-Locale".into(), "en_US".into()),
            ("x-apple-i-device-type".into(), "1".into()),
        ];
        for (k, v) in self.account.anisette_headers().await? {
            headers.push((k, v));
        }
        Ok(headers)
    }

    async fn command(
        &self,
        command: &str,
        label: &str,
        user_action_label: &str,
        extra: &serde_json::Map<String, serde_json::Value>,
        transaction_id: Option<&str>,
    ) -> Result<serde_json::Value> {
        let body_command = COMMAND_SPELLINGS
            .iter()
            .find(|(path, _)| *path == command)
            .map(|(_, body)| *body)
            .ok_or_else(|| escrow_error(format!("Unknown escrow command {command:?}")))?;

        let mut body = serde_json::Map::new();
        body.insert("command".into(), serde_json::json!(body_command));
        body.insert("label".into(), serde_json::json!(label));
        body.insert(
            "transactionUUID".into(),
            serde_json::json!(transaction_id.map(str::to_string).unwrap_or_else(|| upper_uuid())),
        );
        body.insert("userActionLabel".into(), serde_json::json!(user_action_label));
        body.insert("version".into(), serde_json::json!(1));
        for (k, v) in extra {
            body.insert(k.clone(), v.clone());
        }
        let body_plist = plist::to_xml(&json_to_plist(&serde_json::Value::Object(body)));

        let url = format!("{}/escrowproxy/api/{command}", self.host);
        let pet = self.pet.lock().unwrap().clone();
        let response = self
            .account
            .http()
            .send(
                reqwest::Method::POST,
                &url,
                &self.headers().await?,
                Some(body_plist),
                Some((self.account_name.as_str(), pet.as_str())),
            )
            .await?;

        if !(200..300).contains(&response.status) {
            return Err(failure(command, &response));
        }
        let data = plist::parse_dict(&response.body).map_err(|_| escrow_error("The escrow reply is not a property list"))?;
        if data.get("success").and_then(|v| v.as_bool()) == Some(false) || data.get("errorCode").is_some() {
            let message = data.get("errorMessage").and_then(|v| v.as_str()).unwrap_or("no message");
            return Err(escrow_error(format!(
                "Escrow proxy rejected {command}: {message} (code {})",
                data.get("errorCode").and_then(|v| v.as_i64()).map(|c| c.to_string()).unwrap_or_default()
            )));
        }
        Ok(plist_to_json(&Value::Dict(data)))
    }

    pub async fn list_records(&self) -> Result<EscrowListing> {
        let data = self
            .command("get_records", ESCROW_LABEL_SECURE_BACKUP, "FindMy.py listing escrow records", &serde_json::Map::new(), None)
            .await?;
        let mut records = Vec::new();
        let mut unreadable = Vec::new();
        if let Some(list) = data.get("metadataList").and_then(|v| v.as_array()) {
            for entry in list {
                let label = entry.get("label").and_then(|v| v.as_str()).unwrap_or("");
                match entry.get("metadata").and_then(|v| v.as_str()) {
                    Some(encoded) => match parse_metadata(label, encoded.as_bytes()) {
                        Ok(record) => records.push(record),
                        Err(_) => unreadable.push(label.to_string()),
                    },
                    None => unreadable.push(label.to_string()),
                }
            }
        }
        Ok(EscrowListing {
            records,
            unreadable,
            status: data.get("status").and_then(|v| v.as_i64()),
            message: data.get("message").and_then(|v| v.as_str()).map(str::to_string),
        })
    }

    pub async fn srp_init(&self, label: &str, client_public: &[u8], transaction_id: &str) -> Result<serde_json::Value> {
        let mut extra = serde_json::Map::new();
        extra.insert("blob".into(), serde_json::json!(base64::engine::general_purpose::STANDARD.encode(client_public)));
        for (k, v) in cert_versions().as_object().unwrap() {
            extra.insert(k.clone(), v.clone());
        }
        self.command("srp_init", label, "FindMy.py beginning escrow recovery", &extra, Some(transaction_id))
            .await
    }

    pub async fn recover(&self, label: &str, proof_blob: &[u8], transaction_id: &str, dsid: Option<&str>) -> Result<serde_json::Value> {
        let mut extra = serde_json::Map::new();
        extra.insert("blob".into(), serde_json::json!(base64::engine::general_purpose::STANDARD.encode(proof_blob)));
        for (k, v) in cert_versions().as_object().unwrap() {
            extra.insert(k.clone(), v.clone());
        }
        if let Some(dsid) = dsid {
            extra.insert("dsid".into(), serde_json::json!(dsid));
        }
        self.command("recover", label, "FindMy.py completing escrow recovery", &extra, Some(transaction_id))
            .await
    }
}

fn failure(command: &str, response: &crate::http::Response) -> Error {
    let described = if let Ok(data) = plist::parse_dict(&response.body) {
        let status = data.get("status").or_else(|| data.get("errorCode")).and_then(|v| v.as_i64());
        let message = data.get("message").or_else(|| data.get("errorMessage")).and_then(|v| v.as_str());
        let mut text = format!("HTTP {}", response.status);
        if let Some(status) = status {
            text.push_str(&format!(", status {status}"));
        }
        if let Some(message) = message {
            text.push_str(&format!(" -- {message}"));
        }
        Some(text)
    } else {
        None
    };
    match described {
        Some(detail) => escrow_error(format!("Escrow proxy rejected {command}: {detail}")),
        None => escrow_error(format!("Escrow proxy returned HTTP {} for {command}", response.status)),
    }
}

fn upper_uuid() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Convert a `serde_json::Value` into a plist `Value` (strings, numbers, bools, arrays, objects).
pub fn json_to_plist(value: &serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::String(String::new()),
        serde_json::Value::Bool(b) => Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i)
            } else {
                Value::Real(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(a) => Value::Array(a.iter().map(json_to_plist).collect()),
        serde_json::Value::Object(o) => Value::Dict(o.iter().map(|(k, v)| (k.clone(), json_to_plist(v))).collect()),
    }
}

/// Convert a plist `Value` into JSON (dates and data become strings).
pub fn plist_to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::String(s) => serde_json::json!(s),
        Value::Integer(i) => serde_json::json!(i),
        Value::Real(f) => serde_json::json!(f),
        Value::Boolean(b) => serde_json::json!(b),
        Value::Date(s) => serde_json::json!(s),
        Value::Data(d) => serde_json::json!(base64::engine::general_purpose::STANDARD.encode(d)),
        Value::Array(a) => serde_json::json!(a.iter().map(plist_to_json).collect::<Vec<_>>()),
        Value::Dict(d) => serde_json::Value::Object(d.iter().map(|(k, v)| (k.clone(), plist_to_json(v))).collect()),
    }
}

impl EscrowAccount for crate::login::account::AppleAccount {
    fn client_info(&self, bundle: &str) -> String {
        self.device().identity.client_info(bundle)
    }
    fn user_agent(&self, product: &str) -> String {
        self.device().identity.user_agent(product)
    }
    fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(30)
    }
    fn anisette_headers<'a>(&'a self) -> crate::login::BoxFuture<'a, Result<BTreeMap<String, String>>> {
        Box::pin(async move { crate::login::account::AppleAccount::anisette_headers(self).await })
    }
    fn http(&self) -> &crate::http::Http {
        crate::login::account::AppleAccount::http(self)
    }
}
