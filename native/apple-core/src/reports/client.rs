//! Fetches and decrypts location reports from Apple's search-party service (port of
//! `findmy.reports.reports.LocationReportsFetcher` and `AsyncAppleAccount.fetch_raw_reports`, with
//! the small deliberate differences the Kotlin records: a report that cannot be decrypted is counted
//! and skipped instead of aborting, ids Apple answers for that were not asked about are skipped, and
//! domain-invalid reports are filtered out).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::Duration as StdDuration;

use serde_json::{json, Value};
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::error::{Error, Result};
use crate::http::Http;
use crate::login::account::AppleAccount;
use crate::login::BoxFuture;
use crate::reports::keys::{AccessoryKeys, KeyPair, KeyPairType};
use crate::reports::payload::{DecryptedReport, EncryptedReport};
use crate::util::{b64, b64_decode};

pub const ENDPOINT: &str = "https://gateway.icloud.com/findmyservice/v2/fetch";
pub const MAX_IDS: usize = 290;
/// The User-Agent the report fetch sends. The validated Python sends aiohttp's default; the plan's choice is
/// the AuthKit one, overridable if Apple's edge refuses it (`with_user_agent`).
pub const REPORT_USER_AGENT: &str = "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0";
const MAX_EMPTY_RETRIES: u32 = 5;

/// One `fetch` entry of the request: hashed advertisement keys (base64) as primary and secondary ids.
#[derive(Debug, Clone, Default)]
pub struct KeyIds {
    pub primary: Vec<String>,
    pub secondary: Vec<String>,
}

/// What the report-fetch piece needs from a signed-in account.
pub trait AccountContext: Send + Sync {
    fn service_token<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Option<String>>;
    fn dsid<'a>(&'a self) -> BoxFuture<'a, Result<String>>;
    fn anisette_headers<'a>(&'a self) -> BoxFuture<'a, Result<BTreeMap<String, String>>>;
    fn refresh_session<'a>(&'a self) -> BoxFuture<'a, Result<()>>;
    fn http(&self) -> &Http;
}

impl AccountContext for AppleAccount {
    fn service_token<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Option<String>> {
        Box::pin(async move { AppleAccount::service_token(self, name).await })
    }
    fn dsid<'a>(&'a self) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move { AppleAccount::dsid(self).await })
    }
    fn anisette_headers<'a>(&'a self) -> BoxFuture<'a, Result<BTreeMap<String, String>>> {
        Box::pin(async move { AppleAccount::anisette_headers(self).await })
    }
    fn refresh_session<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { AppleAccount::refresh_session(self).await })
    }
    fn http(&self) -> &Http {
        AppleAccount::http(self)
    }
}

/// One report of where an accessory was seen (the host's domain type).
#[derive(Debug, Clone)]
pub struct LocationReport {
    pub accessory_id: String,
    pub latitude: f64,
    pub longitude: f64,
    pub observed_at: OffsetDateTime,
    pub horizontal_accuracy_meters: Option<f64>,
    pub metadata: BTreeMap<String, String>,
}

impl LocationReport {
    /// Coordinates are finite and on Earth, the timestamp is not in the future (clock skew allowed).
    pub fn is_valid(&self, now: OffsetDateTime) -> bool {
        self.latitude.is_finite()
            && self.longitude.is_finite()
            && (-90.0..=90.0).contains(&self.latitude)
            && (-180.0..=180.0).contains(&self.longitude)
            && !(self.latitude == 0.0 && self.longitude == 0.0)
            && self.observed_at < now + TimeDuration::seconds(300)
            && self
                .horizontal_accuracy_meters
                .is_none_or(|a| a.is_finite() && a >= 0.0)
    }
}

/// What a fetch produced.
#[derive(Debug, Clone, Default)]
pub struct ReportFetchResult {
    pub reports: Vec<LocationReport>,
    pub requests: usize,
    pub undecryptable: usize,
    pub invalid: usize,
    pub unknown_key: usize,
    pub empty_response: bool,
    pub alignment_moved: bool,
}

type Clock = Box<dyn Fn() -> OffsetDateTime + Send + Sync>;

/// The fetcher. Holds no state between calls.
pub struct ReportClient<'a> {
    account: &'a dyn AccountContext,
    endpoint: String,
    window: TimeDuration,
    clock: Clock,
    /// A hard cap on the number of `fetch` requests one rolling-key walk may send. `None` matches the
    /// Python (walk to the window's lower bound); the live CLI sets a small one so a stale alignment
    /// cannot turn one accessory into many requests.
    max_requests: Option<usize>,
    user_agent: Option<String>,
}

impl<'a> ReportClient<'a> {
    pub fn new(account: &'a dyn AccountContext) -> Self {
        ReportClient {
            account,
            endpoint: ENDPOINT.to_string(),
            window: TimeDuration::days(7),
            clock: Box::new(OffsetDateTime::now_utc),
            max_requests: None,
            user_agent: Some(REPORT_USER_AGENT.to_string()),
        }
    }

    /// Override the report `User-Agent` (`None` sends none).
    pub fn with_user_agent(mut self, user_agent: Option<String>) -> Self {
        self.user_agent = user_agent;
        self
    }

    /// Cap the walk at `n` requests and return what was gathered (`None` to match the Python).
    pub fn with_max_requests(mut self, n: Option<usize>) -> Self {
        self.max_requests = n;
        self
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    pub fn with_clock(mut self, clock: impl Fn() -> OffsetDateTime + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    pub fn with_window(mut self, window: TimeDuration) -> Self {
        self.window = window;
        self
    }

    /// Newest report of `accessory` in the window, or `None`.
    pub async fn fetch_location(&self, accessory: &AccessoryKeys) -> Result<Option<LocationReport>> {
        Ok(self.fetch_location_history(accessory, true).await?.reports.last().cloned())
    }

    /// Reports of a rolling accessory; the newest batch when `only_latest`, everything otherwise.
    pub async fn fetch_location_history(
        &self,
        accessory: &AccessoryKeys,
        only_latest: bool,
    ) -> Result<ReportFetchResult> {
        let now = (self.clock)();
        let start = now - self.window;
        let accessory_id = accessory.id();

        let mut key_to_ind: HashMap<Vec<u8>, BTreeSet<i32>> = HashMap::new();
        let mut id_to_key: HashMap<String, KeyPair> = HashMap::new();
        let mut cur_primary: BTreeSet<String> = BTreeSet::new();
        let mut cur_secondary: BTreeSet<String> = BTreeSet::new();
        let mut found: Vec<(DecryptedReport, KeyPairType)> = Vec::new();
        let mut found_seen: HashSet<(Vec<u8>, i64, i32, i32)> = HashSet::new();
        let mut cur_index = accessory.max_index(now);
        let mut requests = 0usize;
        let mut undecryptable = 0usize;
        let mut unknown_key = 0usize;
        let mut moved = false;
        let mut empty = false;

        // A closure cannot easily borrow all of the above mutably together in async code, so the
        // flush body is inlined in a helper macro-like block.
        macro_rules! flush {
            () => {{
                requests += 1;
                match self
                    .fetch_raw_or_empty(&[KeyIds {
                        primary: cur_primary.iter().cloned().collect(),
                        secondary: cur_secondary.iter().cloned().collect(),
                    }])
                    .await
                {
                    Ok(raw) => {
                        for report in &raw {
                            let id = b64(&report.hashed_adv_key);
                            let Some(key) = id_to_key.get(&id) else {
                                unknown_key += 1;
                                continue;
                            };
                            let decrypted = match report.decrypt(key) {
                                Ok(d) => d,
                                Err(_) => {
                                    undecryptable += 1;
                                    continue;
                                }
                            };
                            let lowest = *key_to_ind
                                .get(report.hashed_adv_key.as_slice())
                                .and_then(|s| s.iter().next())
                                .unwrap_or(&0);
                            if accessory.update_alignment(
                                OffsetDateTime::from_unix_timestamp(decrypted.timestamp).unwrap_or(now),
                                lowest,
                            ) {
                                moved = true;
                            }
                            let dedup = (
                                decrypted.hashed_adv_key.clone(),
                                decrypted.timestamp,
                                decrypted.latitude_micro,
                                decrypted.longitude_micro,
                            );
                            if found_seen.insert(dedup) {
                                found.push((decrypted, key.key_type()));
                            }
                        }
                        cur_primary.clear();
                        cur_secondary.clear();
                        true
                    }
                    Err(FetchFailure::Empty) => {
                        empty = true;
                        false
                    }
                    Err(FetchFailure::Error(e)) => return Err(e),
                }
            }};
        }

        loop {
            if cur_index < accessory.min_index(start) {
                break;
            }
            let batch = accessory.keys_at(cur_index)?;
            let new_primary: BTreeSet<String> = batch
                .iter()
                .filter(|k| k.key_type() == KeyPairType::Primary)
                .map(|k| k.hashed_adv_key_b64())
                .collect();
            let new_secondary: BTreeSet<String> = batch
                .iter()
                .filter(|k| k.key_type() != KeyPairType::Primary)
                .map(|k| k.hashed_adv_key_b64())
                .collect();

            let over_primary = cur_primary.union(&new_primary).count() > MAX_IDS;
            let over_secondary = cur_secondary.union(&new_secondary).count() > MAX_IDS;
            if over_primary || over_secondary {
                if !flush!() {
                    break;
                }
                if only_latest && !found.is_empty() {
                    break;
                }
                if self.max_requests.is_some_and(|m| requests >= m) {
                    break;
                }
            }

            for key in &batch {
                key_to_ind.entry(key.hashed_adv_key_bytes().to_vec()).or_default().insert(cur_index);
                id_to_key.insert(key.hashed_adv_key_b64(), key.clone());
            }
            cur_primary.extend(new_primary);
            cur_secondary.extend(new_secondary);
            cur_index -= 1;
        }

        if (!cur_primary.is_empty() || !cur_secondary.is_empty())
            && !empty
            && !self.max_requests.is_some_and(|m| requests >= m)
        {
            flush!();
        }

        Ok(self.result(found, requests, undecryptable, unknown_key, empty, moved, &accessory_id, now))
    }

    /// `fetch_location_history` for several accessories: each is queried in turn.
    pub async fn fetch_location_histories(
        &self,
        accessories: &[AccessoryKeys],
        only_latest: bool,
    ) -> Result<Vec<(String, ReportFetchResult)>> {
        let mut out = Vec::new();
        for a in accessories {
            out.push((a.id(), self.fetch_location_history(a, only_latest).await?));
        }
        Ok(out)
    }

    /// One `fetch` entry per key, all as primary ids, decrypted with the key itself.
    pub async fn fetch_key_history(&self, keys: &[KeyPair]) -> Result<Vec<(KeyPair, ReportFetchResult)>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let now = (self.clock)();
        let devices: Vec<KeyIds> = keys
            .iter()
            .map(|k| KeyIds { primary: vec![k.hashed_adv_key_b64()], secondary: Vec::new() })
            .collect();
        let raw = match self.fetch_raw_or_empty(&devices).await {
            Ok(raw) => raw,
            Err(FetchFailure::Empty) | Err(FetchFailure::Error(_)) => Vec::new(),
        };
        let mut out = Vec::new();
        for key in keys {
            let id = key.name().unwrap_or(&key.hashed_adv_key_b64()).to_string();
            let mut found: Vec<DecryptedReport> = Vec::new();
            let mut undecryptable = 0;
            for report in raw.iter().filter(|r| r.can_decrypt(key)) {
                match report.decrypt(key) {
                    Ok(d) => found.push(d),
                    Err(_) => undecryptable += 1,
                }
            }
            found.sort_by_key(|r| r.timestamp);
            let sorted_len = found.len();
            let mapped: Vec<LocationReport> = found
                .into_iter()
                .map(|r| self.to_domain(&r, &id, key.key_type()))
                .filter(|r| r.is_valid(now))
                .collect();
            let invalid = sorted_len - mapped.len();
            out.push((
                key.clone(),
                ReportFetchResult {
                    reports: mapped,
                    requests: 1,
                    undecryptable,
                    invalid,
                    ..Default::default()
                },
            ));
        }
        Ok(out)
    }

    /// The raw call: one request (plus empty-body retries) for `devices`, undecrypted.
    pub async fn fetch_raw(&self, devices: &[KeyIds]) -> Result<Vec<EncryptedReport>> {
        match self.fetch_raw_or_empty(devices).await {
            Ok(raw) => Ok(raw),
            Err(FetchFailure::Empty) => Err(Error::ReportsUnavailable(
                "Apple answered the report request with an empty body repeatedly (FindMy.py#185).".into(),
            )),
            Err(FetchFailure::Error(e)) => Err(e),
        }
    }

    async fn fetch_raw_or_empty(
        &self,
        devices: &[KeyIds],
    ) -> std::result::Result<Vec<EncryptedReport>, FetchFailure> {
        let now = (self.clock)();
        let start_ms = (now - self.window).unix_timestamp() * 1000;
        let end_ms = now.unix_timestamp() * 1000;
        let fetch: Vec<Value> = devices
            .iter()
            .map(|d| {
                json!({
                    "ownedDeviceIds": [],
                    "keyType": 1,
                    "startDate": start_ms,
                    "startDateSecondary": start_ms,
                    "endDate": end_ms,
                    "primaryIds": d.primary,
                    "secondaryIds": d.secondary,
                })
            })
            .collect();
        let body = json!({
            "clientContext": {
                "clientBundleIdentifier": "com.apple.icloud.searchpartyuseragent",
                "policy": "foregroundClient",
            },
            "fetch": fetch,
        })
        .to_string();

        let mut answer = self.post(&body).await?;
        if answer.code == 401 {
            if self.account.refresh_session().await.is_ok() {
                answer = self.post(&body).await?;
            }
        }
        self.parse(&answer)
    }

    /// One POST, retrying an empty 200 up to 5 times at 2, 4, ... 10 s (FindMy.py#185).
    async fn post(&self, body: &str) -> std::result::Result<Answer, FetchFailure> {
        let token = self
            .account
            .service_token("searchPartyToken")
            .await
            .ok_or_else(|| FetchFailure::Error(Error::Authentication("No search-party token: sign in again.".into())))?;
        let dsid = self.account.dsid().await.map_err(FetchFailure::Error)?;
        let authorization = basic_auth(&dsid, &token);
        let mut retry = 1u32;
        loop {
            let answer = self.send(body, &authorization).await?;
            if answer.code != 200 || !answer.body.trim().is_empty() {
                return Ok(answer);
            }
            if retry > MAX_EMPTY_RETRIES {
                return Err(FetchFailure::Empty);
            }
            tokio::time::sleep(StdDuration::from_millis(2000 * retry as u64)).await;
            retry += 1;
        }
    }

    async fn send(&self, body: &str, authorization: &str) -> std::result::Result<Answer, FetchFailure> {
        let headers = self.account.anisette_headers().await.map_err(FetchFailure::Error)?;
        let mut request_headers: Vec<(String, String)> =
            vec![("Authorization".into(), authorization.into()), ("Content-Type".into(), "application/json".into())];
        if let Some(user_agent) = &self.user_agent {
            request_headers.push(("User-Agent".into(), user_agent.clone()));
        }
        for (k, v) in headers {
            request_headers.push((k, v));
        }
        let response = self
            .account
            .http()
            .send(
                reqwest::Method::POST,
                &self.endpoint,
                &request_headers,
                Some(body.as_bytes().to_vec()),
                None,
            )
            .await
            .map_err(FetchFailure::Error)?;
        Ok(Answer {
            code: response.status,
            body: response.text(),
            retry_after: response.headers.get("Retry-After").and_then(|v| v.to_str().ok()).map(str::to_string),
        })
    }

    fn parse(&self, answer: &Answer) -> std::result::Result<Vec<EncryptedReport>, FetchFailure> {
        let json: Option<Value> = serde_json::from_str(&answer.body).ok();
        match answer.code {
            401 => return Err(FetchFailure::Error(Error::Authentication("Apple rejected the report request: sign in again.".into()))),
            429 => {
                let wait = answer
                    .retry_after
                    .as_deref()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .map(|s| format!(" Apple asked for {s} s."))
                    .unwrap_or_default();
                return Err(FetchFailure::Error(Error::Throttled(format!(
                    "Apple is rate-limiting report requests (HTTP 429).{wait}"
                ))));
            }
            code if code >= 500 => {
                return Err(FetchFailure::Error(Error::Backend(format!(
                    "Apple's report service is unavailable (HTTP {code})."
                ))));
            }
            _ => {}
        }
        if json.is_none() && answer.code < 400 {
            return Err(FetchFailure::Error(Error::Backend("Apple's report answer is not JSON.".into())));
        }
        let block = json.as_ref().and_then(|j| j.get("acsnLocations"));
        let status = block.and_then(|b| b.get("statusCode")).and_then(|v| v.as_str().map(str::to_string).or_else(|| v.as_i64().map(|i| i.to_string())));
        if answer.code >= 400 || status.as_deref() != Some("200") {
            let apple = json
                .as_ref()
                .and_then(|j| j.get("statusCode"))
                .map(value_to_string)
                .or(status);
            return Err(FetchFailure::Error(Error::Rejected {
                http: Some(answer.code),
                ec: apple.as_deref().and_then(|s| s.parse().ok()),
                message: format!(
                    "Apple's report service refused the request (HTTP {}, status {}).",
                    answer.code,
                    apple.as_deref().unwrap_or("none")
                ),
            }));
        }
        let mut out = Vec::new();
        let payloads = block.and_then(|b| b.get("locationPayload")).and_then(|v| v.as_array());
        for entry in payloads.into_iter().flatten() {
            let Some(id) = entry.get("id").and_then(|v| v.as_str()).and_then(b64_decode) else {
                return Err(FetchFailure::Error(Error::Backend("Unexpected shape of the report answer.".into())));
            };
            let infos = entry.get("locationInfo").and_then(|v| v.as_array());
            for info in infos.into_iter().flatten() {
                let Some(payload) = info.as_str().and_then(b64_decode) else {
                    return Err(FetchFailure::Error(Error::Backend("Unexpected encoding in the report answer.".into())));
                };
                out.push(EncryptedReport::new(payload, id.clone()));
            }
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn result(
        &self,
        found: Vec<(DecryptedReport, KeyPairType)>,
        requests: usize,
        undecryptable: usize,
        unknown_key: usize,
        empty: bool,
        moved: bool,
        accessory_id: &str,
        now: OffsetDateTime,
    ) -> ReportFetchResult {
        let mut sorted = found;
        sorted.sort_by_key(|(r, _)| r.timestamp);
        let total = sorted.len();
        let reports: Vec<LocationReport> = sorted
            .iter()
            .map(|(r, t)| self.to_domain(r, accessory_id, *t))
            .filter(|r| r.is_valid(now))
            .collect();
        ReportFetchResult {
            invalid: total - reports.len(),
            reports,
            requests,
            undecryptable,
            unknown_key,
            empty_response: empty,
            alignment_moved: moved,
        }
    }

    fn to_domain(&self, r: &DecryptedReport, accessory_id: &str, key_type: KeyPairType) -> LocationReport {
        let mut metadata = BTreeMap::new();
        metadata.insert("source".into(), "apple-findmy".into());
        metadata.insert("confidence".into(), r.confidence.to_string());
        metadata.insert("status".into(), r.status.to_string());
        metadata.insert(
            "keyType".into(),
            match key_type {
                KeyPairType::Primary => "primary",
                KeyPairType::Secondary => "secondary",
                KeyPairType::Unknown => "unknown",
            }
            .into(),
        );
        LocationReport {
            accessory_id: accessory_id.to_string(),
            latitude: r.latitude(),
            longitude: r.longitude(),
            observed_at: OffsetDateTime::from_unix_timestamp(r.timestamp).unwrap_or(now_placeholder()),
            horizontal_accuracy_meters: Some(r.horizontal_accuracy as f64),
            metadata,
        }
    }
}

fn now_placeholder() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn basic_auth(user: &str, password: &str) -> String {
    format!("Basic {}", b64(format!("{user}:{password}").as_bytes()))
}

struct Answer {
    code: u16,
    body: String,
    retry_after: Option<String>,
}

enum FetchFailure {
    Empty,
    Error(Error),
}

#[cfg(test)]
mod basic_auth_tests {
    #[test]
    fn authorization_carries_the_basic_scheme() {
        assert_eq!(super::basic_auth("user", "pass"), "Basic dXNlcjpwYXNz");
    }
}
