//! A read-only client for one private CloudKit container (port of
//! `findmy.cloudkit.client.AsyncCloudKitClient`, minus `record_save`, and `apple/cloudkit/CloudKitClient.kt`).
//!
//! Opening the container (`ckAppInit`, HTTP Basic `dsid:mmeAuthToken` plus `x-cloudkit-authtoken`)
//! learns the CloudKit user id and the service URLs; operations are gzipped, length-delimited
//! `RequestOperation`s sent to the database or code gateway with `x-cloudkit-userid` /
//! `x-cloudkit-authtoken`. Nothing here persists.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use apple_proto::cloudkit::{
    request_operation::Header, ContainerEnvironment, Database, FunctionInvokeRequest, Identifier,
    IsolationLevel, Operation, RequestOperation, ResponseOperation, RetrieveChangesRequest,
    Result as CloudKitResult, ZoneRetrieveRequest, ZoneSummary,
};
use prost::Message;
use serde_json::Value;

use crate::cloudkit::{client_error_code, operation_type, CloudKitApi, CloudKitContainerInfo, RecordSyncPage};
use crate::error::{Error, Result};
use crate::http::Http;
use crate::login::account::AppleAccount;
use crate::login::{bundles, BoxFuture};

const LIBRARY_NAME: &str = "com.apple.cloudkit.CloudKitDaemon";
const LIBRARY_VERSION: &str = "1970";
const USER_AGENT: &str = "CloudKit/1970 (19H384)";
const MMCS_PROTOCOL_VERSION: &str = "5.0";
const DEFAULT_DEVICE_NAME: &str = "FindMy.py";

/// What the CloudKit client needs from a signed-in account.
pub trait CloudKitAccount: Send + Sync {
    fn dsid<'a>(&'a self) -> BoxFuture<'a, Result<String>>;
    fn device_uuid(&self) -> String;
    fn client_info(&self) -> String;
    fn serial(&self) -> Option<String>;
    fn service_token<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Option<String>>;
    fn anisette_headers<'a>(&'a self) -> BoxFuture<'a, Result<BTreeMap<String, String>>>;
    fn http(&self) -> &Http;
    fn timeout(&self) -> Duration;
}

impl CloudKitAccount for AppleAccount {
    fn dsid<'a>(&'a self) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move { AppleAccount::dsid(self).await })
    }
    fn device_uuid(&self) -> String {
        self.device().cloud_kit_device_uuid.clone()
    }
    fn client_info(&self) -> String {
        self.device().identity.client_info(bundles::XCODE)
    }
    fn serial(&self) -> Option<String> {
        self.device().serial.clone()
    }
    fn service_token<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Option<String>> {
        Box::pin(async move { AppleAccount::service_token(self, name).await })
    }
    fn anisette_headers<'a>(&'a self) -> BoxFuture<'a, Result<BTreeMap<String, String>>> {
        Box::pin(async move { AppleAccount::anisette_headers(self).await })
    }
    fn http(&self) -> &Http {
        AppleAccount::http(self)
    }
    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

/// The device this client claims to be, parsed from the account's `X-Mme-Client-Info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    pub model: String,
    pub os_version: String,
    pub prefix: String,
}

impl ClientIdentity {
    pub const CLIENT_INFO_BUNDLE: &'static str =
        "com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)";

    pub fn cloud_kit_client_info(&self) -> String {
        format!("{}<{}>", self.prefix, Self::CLIENT_INFO_BUNDLE)
    }

    /// `<MODEL> <OS;VERSION;BUILD> <BUNDLE>`; falls back to empty values rather than failing.
    pub fn parse(client_info: &str) -> ClientIdentity {
        let parsed: Vec<&str> = client_info
            .split('<')
            .filter(|s| s.contains('>'))
            .map(|s| s.split('>').next().unwrap_or(""))
            .collect();
        let model = parsed.first().copied().unwrap_or("").to_string();
        let os_version = parsed
            .get(1)
            .and_then(|s| s.split(';').nth(1))
            .unwrap_or("")
            .to_string();
        let prefix = parsed.iter().take(2).map(|s| format!("<{s}> ")).collect();
        ClientIdentity { model, os_version, prefix }
    }
}

/// The random correlation values CloudKit requests carry; replaceable so tests can reproduce the
/// Python's exact bytes.
pub trait CloudKitIds: Send + Sync {
    fn operation_id(&self) -> String;
    fn request_uuid(&self) -> String;
}

/// The production implementation.
pub struct RandomIds;

impl CloudKitIds for RandomIds {
    fn operation_id(&self) -> String {
        use rand::RngCore;
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        b.iter().map(|x| format!("{x:02X}")).collect()
    }
    fn request_uuid(&self) -> String {
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
}

/// Length-delimited protobuf framing (`encode_delimited`/`decode_delimited`).
pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            out.push(b | 0x80);
        } else {
            out.push(b);
            return out;
        }
    }
}

pub fn encode_delimited(message: &RequestOperation) -> Vec<u8> {
    let payload = message.encode_to_vec();
    let mut out = encode_varint(payload.len() as u64);
    out.extend_from_slice(&payload);
    out
}

pub fn decode_delimited(data: &[u8]) -> Result<Vec<ResponseOperation>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let mut length: u64 = 0;
        let mut shift = 0u32;
        loop {
            if offset >= data.len() {
                return Err(Error::Backend("Truncated varint in CloudKit response".into()));
            }
            let b = data[offset];
            offset += 1;
            if shift < 63 {
                length |= ((b & 0x7f) as u64) << shift;
            }
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        let available = (data.len() - offset) as u64;
        if length > available {
            return Err(Error::Backend(format!(
                "Truncated CloudKit response: wanted {length} bytes, got {available}"
            )));
        }
        let chunk = &data[offset..offset + length as usize];
        offset += length as usize;
        out.push(
            ResponseOperation::decode(chunk)
                .map_err(|_| Error::Backend("CloudKit returned a response operation that does not parse".into()))?,
        );
    }
    Ok(out)
}

/// Python's `urllib.parse.quote` with its default safe set (`/` and the unreserved characters).
pub fn py_quote(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        let c = *b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '/') {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).ok();
    encoder.finish().unwrap_or_default()
}

fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|_| Error::Backend("CloudKit's gzip reply does not decompress".into()))?;
    Ok(out)
}

/// Raise unless a result worked; PARTIAL passes. The message is the Python's:
/// `CloudKit operation failed (NAME): description [errorKey]`.
pub fn check_result(result: &CloudKitResult) -> Result<()> {
    if result.code == Some(1) || result.code == Some(2) {
        return Ok(());
    }
    let error = result.error.clone().unwrap_or_default();
    let client_code = error.client_error.as_ref().and_then(|c| c.code);
    let name = client_code
        .map(|c| format!(" ({})", client_error_code::name(c).map(str::to_string).unwrap_or_else(|| format!("client error {c}"))))
        .unwrap_or_default();
    let description = error
        .error_description
        .clone()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "no description given".to_string());
    let mut message = format!("CloudKit operation failed{name}: {description}");
    if let Some(key) = error.error_key.as_deref().filter(|k| !k.is_empty()) {
        message = format!("{message} [{key}]");
    }
    match client_code {
        Some(client_error_code::THROTTLED) => {
            let retry = error.retry_after_seconds;
            let wait = retry.map(|s| format!(" Apple asked for {s} s.")).unwrap_or_default();
            return Err(Error::Throttled(format!("{message}{wait}")));
        }
        Some(client_error_code::BAD_AUTH_TOKEN) | Some(client_error_code::NEEDS_AUTHENTICATION) => {
            return Err(Error::Authentication(message));
        }
        _ => {}
    }
    let code = client_code
        .or_else(|| error.server_error.as_ref().and_then(|s| s.code))
        .or(result.code);
    Err(Error::Rejected { http: Some(200), ec: code.map(|c| c as i64), message })
}

/// A read-only CloudKit client.
pub struct CloudKitClient {
    account: Arc<dyn CloudKitAccount>,
    container: String,
    bundle: String,
    environment: String,
    database_scope: String,
    device_name: String,
    device_serial: Option<String>,
    app_init_url: String,
    ids: Arc<dyn CloudKitIds>,
    info: tokio::sync::Mutex<Option<CloudKitContainerInfo>>,
}

impl CloudKitClient {
    pub fn new(account: Arc<dyn CloudKitAccount>) -> CloudKitClient {
        CloudKitClient {
            account,
            container: crate::cloudkit::constants::SEARCHPARTY_CONTAINER.to_string(),
            bundle: crate::cloudkit::constants::SEARCHPARTY_BUNDLE.to_string(),
            environment: "Production".to_string(),
            database_scope: "PRIVATE".to_string(),
            device_name: DEFAULT_DEVICE_NAME.to_string(),
            device_serial: None,
            app_init_url: crate::cloudkit::constants::CK_APP_INIT_URL.to_string(),
            ids: Arc::new(RandomIds),
            info: tokio::sync::Mutex::new(None),
        }
    }

    pub fn with_container(mut self, container: impl Into<String>) -> Self {
        self.container = container.into();
        self
    }

    pub fn with_bundle(mut self, bundle: impl Into<String>) -> Self {
        self.bundle = bundle.into();
        self
    }

    pub fn with_app_init_url(mut self, url: impl Into<String>) -> Self {
        self.app_init_url = url.into();
        self
    }

    pub fn with_ids(mut self, ids: Arc<dyn CloudKitIds>) -> Self {
        self.ids = ids;
        self
    }

    pub fn with_device_name(mut self, name: impl Into<String>) -> Self {
        self.device_name = name.into();
        self
    }

    pub async fn container_info(&self) -> Option<CloudKitContainerInfo> {
        self.info.lock().await.clone()
    }

    fn identity(&self) -> ClientIdentity {
        ClientIdentity::parse(&self.account.client_info())
    }

    fn device_serial(&self) -> Option<String> {
        self.device_serial.clone().or_else(|| self.account.serial())
    }

    fn device_hardware_id(&self) -> Result<String> {
        let hex = self
            .account
            .device_uuid()
            .replace("urn:", "")
            .replace("uuid:", "")
            .trim_matches(|c| c == '{' || c == '}')
            .replace('-', "");
        if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Backend(
                "This account's CloudKit device id is not a UUID; nothing was sent.".into(),
            ));
        }
        Ok(hex.to_uppercase())
    }

    async fn token(&self, name: &str) -> Result<String> {
        self.account.service_token(name).await.ok_or_else(|| {
            Error::Authentication(format!("No {name} for this account: sign in again."))
        })
    }

    async fn cloud_kit_headers(&self) -> Result<Vec<(String, String)>> {
        let mut headers = vec![
            ("x-cloudkit-containerid".into(), self.container.clone()),
            ("x-cloudkit-bundleid".into(), self.bundle.clone()),
            ("x-cloudkit-databasescope".into(), self.database_scope.clone()),
            ("x-cloudkit-environment".into(), self.environment.clone()),
            ("x-cloudkit-duetpreclearedmode".into(), "None".into()),
            ("x-apple-operation-group-id".into(), self.ids.operation_id()),
            ("x-apple-operation-id".into(), self.ids.operation_id()),
            ("x-apple-request-uuid".into(), self.ids.request_uuid()),
            ("x-apple-c2-metric-triggers".into(), "0".into()),
            ("user-agent".into(), USER_AGENT.into()),
            ("x-mme-client-info".into(), self.identity().cloud_kit_client_info()),
            ("accept".into(), "application/x-protobuf".into()),
            ("accept-encoding".into(), "gzip".into()),
            ("accept-language".into(), "en-US,en;q=0.9".into()),
            ("cache-control".into(), "no-transform".into()),
        ];
        for (k, v) in self.account.anisette_headers().await? {
            headers.push((k, v));
        }
        Ok(headers)
    }

    fn header(&self) -> Result<Header> {
        let mut h = Header {
            application_container: Some(self.container.clone()),
            application_bundle: Some(self.bundle.clone()),
            device_identifier: Some(Identifier {
                name: Some(self.account.device_uuid().to_uppercase()),
                r#type: Some(apple_proto::cloudkit::identifier::Type::Device as i32),
            }),
            device_software_version: Some(self.identity().os_version),
            device_hardware_version: Some(self.identity().model),
            device_library_name: Some(LIBRARY_NAME.into()),
            device_library_version: Some(LIBRARY_VERSION.into()),
            mmcs_protocol_version: Some(MMCS_PROTOCOL_VERSION.into()),
            application_container_environment: Some(ContainerEnvironment::Production as i32),
            device_assigned_name: Some(self.device_name.clone()),
            device_hardware_id: Some(self.device_hardware_id()?),
            target_database: Some(Database::PrivateDb as i32),
            isolation_level: Some(IsolationLevel::Zone as i32),
            group: Some(self.ids.operation_id()),
            unknown_29: Some(0),
            unknown_34: Some(0),
            unknown_35: Some(1),
            ..Default::default()
        };
        if let Some(serial) = self.device_serial() {
            h.device_serial = Some(serial);
        }
        Ok(h)
    }

    fn request(&self, operation: i32) -> Result<RequestOperation> {
        Ok(RequestOperation {
            header: Some(self.header()?),
            request: Some(Operation {
                operation_uuid: Some(self.ids.request_uuid()),
                r#type: Some(operation),
                synchronous_mode: Some(false),
                last: Some(true),
            }),
            ..Default::default()
        })
    }

    fn zone_identifier(&self, info: &CloudKitContainerInfo, zone_name: &str) -> apple_proto::cloudkit::RecordZoneIdentifier {
        apple_proto::cloudkit::RecordZoneIdentifier {
            value: Some(Identifier {
                name: Some(zone_name.to_string()),
                r#type: Some(apple_proto::cloudkit::identifier::Type::RecordZone as i32),
            }),
            owner_identifier: Some(Identifier {
                name: Some(info.user_id.clone()),
                r#type: Some(apple_proto::cloudkit::identifier::Type::User as i32),
            }),
            environment: Some(ContainerEnvironment::Production as i32),
        }
    }

    async fn post_operation(
        &self,
        path: &str,
        request: &RequestOperation,
        base_override: Option<&str>,
    ) -> Result<ResponseOperation> {
        let info = self.open_container(false).await?;
        let base = base_override
            .map(str::to_string)
            .or_else(|| info.database_gateway_url.clone())
            .filter(|b| !b.is_empty())
            .ok_or_else(|| Error::Backend("Container did not return a database gateway URL".into()))?;
        let mut headers = self.cloud_kit_headers().await?;
        headers.push(("content-encoding".into(), "gzip".into()));
        headers.push(("x-cloudkit-userid".into(), info.user_id.clone()));
        headers.push(("x-cloudkit-authtoken".into(), self.token("cloudKitToken").await?));
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let answer = self
            .send(
                &url,
                &headers,
                gzip(&encode_delimited(request)),
                Some(crate::cloudkit::constants::PROTOBUF_CONTENT_TYPE),
            )
            .await?;
        match answer.code {
            401 => return Err(Error::Authentication("CloudKit rejected the token for this operation; sign in again.".into())),
            429 => return Err(throttled(&answer, "a CloudKit operation")),
            500 if String::from_utf8_lossy(&answer.body).trim().is_empty() => {
                return Err(Error::Backend(
                    "CloudKit returned an empty HTTP 500, which means the request did not parse (a protobuf schema mismatch).".into(),
                ))
            }
            code if code >= 500 => return Err(Error::Backend(format!("CloudKit operation failed: HTTP {code}"))),
            code if !(200..300).contains(&code) => {
                return Err(Error::Rejected { http: Some(code), ec: None, message: format!("CloudKit operation failed: HTTP {code}") })
            }
            _ => {}
        }
        let responses = decode_delimited(&answer.body)?;
        let response = responses
            .into_iter()
            .next()
            .ok_or_else(|| Error::Backend("CloudKit returned no operations in its response".into()))?;
        if let Some(result) = &response.result {
            check_result(result)?;
        }
        Ok(response)
    }

    async fn send(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<Answer> {
        let mut all = headers.to_vec();
        if let Some(ct) = content_type {
            all.push(("content-type".into(), ct.to_string()));
        }
        let response = self
            .account
            .http()
            .send(reqwest::Method::POST, url, &all, Some(body), None)
            .await?;
        let encoded = response
            .headers
            .get("Content-Encoding")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().eq_ignore_ascii_case("gzip"))
            .unwrap_or(false);
        let body = if encoded { gunzip(&response.body)? } else { response.body };
        Ok(Answer {
            code: response.status,
            body,
            retry_after: response.headers.get("Retry-After").and_then(|v| v.to_str().ok()).map(str::to_string),
        })
    }

}

impl CloudKitApi for CloudKitClient {
    fn open_container<'a>(&'a self, refresh: bool) -> BoxFuture<'a, Result<CloudKitContainerInfo>> {
        Box::pin(async move {
            {
                let guard = self.info.lock().await;
                if let Some(info) = guard.as_ref() {
                    if !refresh {
                        return Ok(info.clone());
                    }
                }
            }
            let authorization = basic_auth(&self.account.dsid().await?, &self.token("mmeAuthToken").await?);
            let mut headers = self.cloud_kit_headers().await?;
            headers.push(("x-cloudkit-authtoken".into(), self.token("cloudKitToken").await?));
            headers.push(("Authorization".into(), authorization));
            let url = format!("{}?container={}", self.app_init_url, py_quote(&self.container));
            let answer = self.send(&url, &headers, Vec::new(), None).await?;
            match answer.code {
                401 => {
                    return Err(Error::Authentication(
                        "CloudKit rejected the iCloud token; signing in again obtains a fresh one.".into(),
                    ))
                }
                429 => return Err(throttled(&answer, "opening the CloudKit container")),
                code if code >= 500 => {
                    return Err(Error::Backend(format!("Failed to open the CloudKit container: HTTP {code}")))
                }
                code if !(200..300).contains(&code) => {
                    return Err(Error::Rejected {
                        http: Some(code),
                        ec: None,
                        message: format!("Failed to open the CloudKit container: HTTP {code}"),
                    })
                }
                _ => {}
            }
            let json: Value = serde_json::from_slice(&answer.body)
                .map_err(|_| Error::Backend("CloudKit's container answer is not JSON".into()))?;
            let user_id = json
                .get("cloudKitUserId")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::Backend("CloudKit did not return a user id; cannot address any private zone".into()))?
                .to_string();
            let raw: BTreeMap<String, Value> = json
                .as_object()
                .map(|o| o.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            let get = |k: &str| raw.get(k).and_then(|v| v.as_str()).map(str::to_string);
            let info = CloudKitContainerInfo {
                user_id,
                database_url: get("cloudKitDatabaseUrl"),
                database_gateway_url: get("cloudKitDatabaseGatewayUrl"),
                code_gateway_url: get("cloudKitCodeGatewayUrl"),
                share_gateway_url: get("cloudKitShareGatewayUrl"),
                raw,
            };
            *self.info.lock().await = Some(info.clone());
            Ok(info)
        })
    }

    fn zone_retrieve<'a>(&'a self) -> BoxFuture<'a, Result<Vec<ZoneSummary>>> {
        Box::pin(async move {
            let request = RequestOperation {
                zone_retrieve_request: Some(ZoneRetrieveRequest::default()),
                ..self.request(operation_type::ZONE_RETRIEVE)?
            };
            let response = self.post_operation(crate::cloudkit::constants::PATH_ZONE_RETRIEVE, &request, None).await?;
            Ok(response.zone_retrieve_response.map(|r| r.zone_summary).unwrap_or_default())
        })
    }

    fn record_sync<'a>(
        &'a self,
        zone_name: &'a str,
        continuation_token: Option<Vec<u8>>,
        max_changes: Option<i32>,
    ) -> BoxFuture<'a, Result<RecordSyncPage>> {
        Box::pin(async move {
            let info = self.open_container(false).await?;
            let mut changes = RetrieveChangesRequest {
                zone_identifier: Some(self.zone_identifier(&info, zone_name)),
                ..Default::default()
            };
            changes.sync_continuation_token = continuation_token;
            changes.max_changes = max_changes;
            let request = RequestOperation {
                retrieve_changes_request: Some(changes),
                ..self.request(operation_type::RECORD_RETRIEVE_CHANGES)?
            };
            let response = self.post_operation(crate::cloudkit::constants::PATH_RECORD_SYNC, &request, None).await?;
            let payload = response.retrieve_changes_response.unwrap_or_default();
            Ok(RecordSyncPage {
                changes: payload.record_change,
                continuation_token: payload.sync_continuation_token,
                status: payload.status,
            })
        })
    }

    fn function_invoke<'a>(
        &'a self,
        service: &'a str,
        name: &'a str,
        parameters: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let info = self.open_container(false).await?;
            let code = info
                .code_gateway_url
                .clone()
                .filter(|c| !c.is_empty())
                .ok_or_else(|| Error::Backend("Container did not return a code gateway URL; cannot invoke functions".into()))?;
            let request = RequestOperation {
                function_invoke_request: Some(FunctionInvokeRequest {
                    service: Some(service.to_string()),
                    name: Some(name.to_string()),
                    parameters: Some(parameters),
                    ..Default::default()
                }),
                ..self.request(operation_type::FUNCTION_INVOKE)?
            };
            let response = self
                .post_operation(crate::cloudkit::constants::PATH_CODE_INVOKE, &request, Some(&code))
                .await?;
            Ok(response.function_invoke_response.and_then(|r| r.serialized_result).unwrap_or_default())
        })
    }
}

fn throttled(answer: &Answer, what: &str) -> Error {
    let wait = answer
        .retry_after
        .as_deref()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|s| format!(" Apple asked for {s} s."))
        .unwrap_or_default();
    Error::Throttled(format!("CloudKit is throttling this account ({what}, HTTP 429).{wait}"))
}

fn basic_auth(user: &str, password: &str) -> String {
    format!("Basic {}", crate::util::b64(format!("{user}:{password}").as_bytes()))
}

struct Answer {
    code: u16,
    body: Vec<u8>,
    retry_after: Option<String>,
}

#[cfg(test)]
mod basic_auth_tests {
    #[test]
    fn authorization_carries_the_basic_scheme() {
        assert_eq!(super::basic_auth("user", "pass"), "Basic dXNlcjpwYXNz");
    }
}
