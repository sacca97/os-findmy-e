//! Apple's Grand Slam `MidService` machine-provisioning client (port of `tools/machoadi/gsa.py` and
//! `app/android/.../apple/GsaClient.kt`).
//!
//! The ADI library cannot provision itself: `midStartProvisioning` hands out a SPIM, the library
//! folds it into a CPIM, and `midFinishProvisioning` turns that into the PTM and trust key the
//! library stores. Nothing here is authenticated (`ds_id` -2 is Apple's "no account" pseudo-DSID).
//!
//! Failures are typed: HTTP 429 -> [`Error::Throttled`], any other HTTP error -> [`Error::Rejected`]
//! carrying Apple's own `ec`/`em` when the body has one, transport problems -> [`Error::Network`].
//! TLS verification stays ON.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::http::{host_of, Http};
use crate::plist::{self, Value};
use crate::util::{b64, b64_decode, now_utc};

pub const LOOKUP_URL: &str = "https://gsa.apple.com/grandslam/GsService2/lookup";
pub const USER_AGENT: &str = "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0";
pub const DEFAULT_CLIENT_INFO: &str =
    "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
pub const CLIENT_APP_NAME: &str = "Setup";

/// The per-"client device" values AuthKit puts in the request headers (`gsa.Device`).
#[derive(Debug, Clone)]
pub struct GsaDevice {
    /// `X-Mme-Device-Id`
    pub unique_device_id: String,
    /// `X-MMe-Client-Info`
    pub client_info: String,
    /// `X-Apple-I-MD-LU`, sent as is (login later sends its base64).
    pub local_user_uuid: String,
    /// `X-Apple-I-SRL-NO`, sent only when there is one. It must be the one the machine was
    /// provisioned with.
    pub serial: Option<String>,
}

impl GsaDevice {
    pub fn new(unique_device_id: impl Into<String>) -> Self {
        GsaDevice {
            unique_device_id: unique_device_id.into(),
            client_info: DEFAULT_CLIENT_INFO.to_string(),
            local_user_uuid: "00000000000000000000000000000000".to_string(),
            serial: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProvisioningResult {
    pub routing: i64,
    pub ptm: Vec<u8>,
    pub tk: Vec<u8>,
}

/// The MidService client. Construction is cheap; hold one per device.
pub struct GsaClient {
    device: GsaDevice,
    http: Http,
    lookup_url: String,
    urls: BTreeMap<String, String>,
}

impl GsaClient {
    pub fn new(device: GsaDevice, http: Http) -> Self {
        GsaClient { device, http, lookup_url: LOOKUP_URL.to_string(), urls: BTreeMap::new() }
    }

    /// Point the lookup at another origin (tests); the returned bag's URLs are used as is.
    pub fn with_lookup_url(mut self, url: impl Into<String>) -> Self {
        self.lookup_url = url.into();
        self
    }

    /// Apple's URL bag as loaded by [`GsaClient::load_url_bag`].
    pub fn urls(&self) -> &BTreeMap<String, String> {
        &self.urls
    }

    pub async fn load_url_bag(&mut self) -> Result<BTreeMap<String, String>> {
        let raw = self.send(&self.lookup_url.clone(), None, false, true).await?;
        let plist = parse_or_backend(&raw, &self.lookup_url)?;
        let bag: BTreeMap<String, String> = plist
            .get("urls")
            .and_then(|v| v.as_dict())
            .map(|d| {
                d.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        if bag.is_empty() {
            return Err(Error::Backend("the URL bag contained no `urls` dictionary".into()));
        }
        self.urls = bag.clone();
        Ok(bag)
    }

    /// The SPIM (server provisioning intermediate metadata).
    pub async fn start_provisioning(&self) -> Result<Vec<u8>> {
        let response = self.post_request(self.url("midStartProvisioning")?, BTreeMap::new()).await?;
        let spim = response
            .get("spim")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Backend("midStartProvisioning gave no spim".into()))?;
        b64_decode(spim).ok_or_else(|| Error::Backend("midStartProvisioning gave a bad spim".into()))
    }

    pub async fn finish_provisioning(&self, cpim: &[u8]) -> Result<ProvisioningResult> {
        let mut request = BTreeMap::new();
        request.insert("cpim".to_string(), Value::String(b64(cpim)));
        let response = self.post_request(self.url("midFinishProvisioning")?, request).await?;
        let blob = |key: &str| -> Result<Vec<u8>> {
            response
                .get(key)
                .and_then(|v| v.as_str())
                .and_then(b64_decode)
                .ok_or_else(|| Error::Backend(format!("midFinishProvisioning gave no {key}")))
        };
        let routing = response
            .get("X-Apple-I-MD-RINFO")
            .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .unwrap_or(0);
        Ok(ProvisioningResult { routing, ptm: blob("ptm")?, tk: blob("tk")? })
    }

    /// Answers Apple's resync (hsc 434 / `X-Apple-I-MD-DATA`) the way akd sends it. `srm` and
    /// `X-Apple-I-MD-M` are both required; the verdict is `Response -> Status`.
    pub async fn sync_machine(
        &self,
        mid_b64: &str,
        srm_b64: &str,
        routing: Option<i64>,
    ) -> Result<BTreeMap<String, Value>> {
        let mut request = BTreeMap::new();
        request.insert("srm".to_string(), Value::String(srm_b64.to_string()));
        request.insert("X-Apple-I-MD-M".to_string(), Value::String(mid_b64.to_string()));
        if let Some(r) = routing {
            request.insert("X-Apple-I-MD-RINFO".to_string(), Value::Integer(r));
        }
        self.post_request(self.url("midSyncMachine")?, request).await
    }

    fn url(&self, name: &str) -> Result<String> {
        self.urls
            .get(name)
            .cloned()
            .ok_or_else(|| Error::Backend(format!("the URL bag has no {name}")))
    }

    async fn post_request(
        &self,
        url: String,
        request: BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, Value>> {
        let body = plist::to_xml(&plist::dict([
            ("Header", Value::Dict(Default::default())),
            ("Request", Value::Dict(request)),
        ]));
        let raw = self.send(&url, Some(body), true, false).await?;
        let plist = parse_or_backend(&raw, &url)?;
        match plist.get("Response") {
            Some(Value::Dict(d)) => Ok(d.clone()),
            _ => Err(Error::Backend(format!("no Response in the reply from {url}"))),
        }
    }

    async fn send(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
        client_time: bool,
        _lookup: bool,
    ) -> Result<Vec<u8>> {
        let mut headers: Vec<(String, String)> = vec![
            ("User-Agent".into(), USER_AGENT.into()),
            // `gsa.py`'s `_headers` carry this on every request, the GET lookup included.
            ("Content-Type".into(), "application/x-www-form-urlencoded".into()),
            ("Accept".into(), "*/*".into()),
            ("X-Mme-Device-Id".into(), self.device.unique_device_id.clone()),
            ("X-MMe-Client-Info".into(), self.device.client_info.clone()),
            ("X-Apple-I-MD-LU".into(), self.device.local_user_uuid.clone()),
            ("X-Apple-Client-App-Name".into(), CLIENT_APP_NAME.into()),
        ];
        if let Some(serial) = &self.device.serial {
            headers.push(("X-Apple-I-SRL-NO".into(), serial.clone()));
        }
        if client_time {
            headers.push(("X-Apple-I-Client-Time".into(), now_utc()));
        }
        // AuthKit really does send urlencoded for an XML plist body.
        let method = if body.is_some() { reqwest::Method::POST } else { reqwest::Method::GET };
        let response = self.http.send(method, url, &headers, body, None).await?;
        if (200..300).contains(&response.status) {
            return Ok(response.body);
        }
        if response.status == 429 {
            return Err(Error::Throttled(
                "Apple answered HTTP 429. This is usually an inconsistent request or connection state \
                 (for example a reused connection), not a rate limit; retrying is safe."
                    .into(),
            ));
        }
        Err(rejected(response.status, &response.body, url))
    }
}

fn parse_or_backend(raw: &[u8], url: &str) -> Result<Value> {
    plist::parse(raw).map_err(|_| Error::Backend(format!("unparseable response from {}", host_of(url))))
}

/// HTTP error with Apple's own status (`Response -> Status -> ec/em`) when the body carries one.
fn rejected(http: u16, body: &[u8], url: &str) -> Error {
    let mut ec = None;
    let mut em = String::new();
    if let Ok(plist) = plist::parse(body) {
        if let Some(status) = plist.get("Response").and_then(|r| r.get("Status")) {
            ec = status.get("ec").and_then(|v| v.as_i64());
            em = status.get("em").and_then(|v| v.as_str()).unwrap_or("").to_string();
        }
    }
    let detail = match ec {
        Some(e) if !em.is_empty() => format!(" (ec {e}: {em})"),
        Some(e) => format!(" (ec {e})"),
        None => String::new(),
    };
    Error::Rejected {
        http: Some(http),
        ec,
        message: format!("HTTP {http} from {}{detail}", host_of(url)),
    }
}

/// The timeout the provisioning client uses.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// Eight random hex characters for a synthetic probe account.
fn probe_suffix() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A credential-free Grand Slam `init` (the `tools/machoadi/gsa_init.py` probe). It asks Apple what it
/// thinks of the machine's Anisette headers before any password is considered, so it is the cheapest
/// live check that the machine is accepted. Returns `Response -> Status` (`ec`/`hsc`).
pub async fn probe_init(
    http: &Http,
    endpoint: &str,
    identity: &crate::login::DeviceIdentity,
    anisette: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, Value>> {
    // A fresh synthetic account per probe, as `tools/machoadi/resync.py` does: a fixed one gets locked
    // by Apple after repeated credential-free `init`s (`ec -20209`), which reads as a machine problem
    // and is not one.
    let username = format!("probe-{}@example.invalid", probe_suffix());
    let mut params: BTreeMap<String, Value> = BTreeMap::new();
    params.insert("u".into(), Value::String(username.clone()));
    params.insert("ps".into(), Value::Array(vec![Value::String("s2k".into()), Value::String("s2k_fo".into())]));
    params.insert("o".into(), Value::String("init".into()));
    let srp = crate::login::srp::SrpClient::new(&username, &crate::login::srp::random_ephemeral());
    params.insert("A2k".into(), Value::Data(srp.public_a()));
    let body = crate::login::messages::gsa_body(&params, &crate::login::messages::cpd(anisette));
    let headers = crate::login::messages::gsa_headers(identity);
    let response = http.send(reqwest::Method::POST, endpoint, &headers, Some(body), None).await?;
    if response.status == 429 {
        return Err(Error::Throttled(
            "Apple answered HTTP 429: usually an inconsistent request or connection state, not a rate limit.".into(),
        ));
    }
    if !(200..300).contains(&response.status) {
        return Err(Error::Rejected { http: Some(response.status), ec: None, message: format!("HTTP {} from {endpoint}", response.status) });
    }
    let plist = crate::plist::parse_dict(&response.body)?;
    plist
        .get("Response")
        .and_then(|r| r.get("Status"))
        .and_then(|s| s.as_dict())
        .cloned()
        .ok_or_else(|| Error::Backend("the Grand Slam reply has no Response.Status".into()))
}
