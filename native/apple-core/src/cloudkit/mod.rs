//! CloudKit's client protocol: the narrow `CloudKitApi` seam the BeaconStore and the keychain trust
//! circle talk through, plus the wire constants (port of `apple/cloudkit/CloudKitApi.kt` and
//! `CloudKitConstants.kt`, which follow `findmy/cloudkit/constants.py`).
//!
//! The concrete `CloudKitClient` (HTTP + protobuf request framing) and the `BeaconStore` read path
//! are the remaining part of phase 3; the trait and constants here are the boundary the keychain
//! piece codes against, so the two can be built independently.

use std::collections::BTreeMap;

use apple_proto::cloudkit::{RecordChange, ZoneSummary};

use crate::error::Result;

pub mod beacons;
pub mod discover;
pub mod client;
pub mod der;
pub mod pcs;
pub mod records;
pub mod servicekeys;

pub mod constants {
    pub const SEARCHPARTY_CONTAINER: &str = "com.apple.icloud.searchparty";
    pub const SEARCHPARTY_BUNDLE: &str = "com.apple.icloud.searchpartyd";
    pub const BEACON_STORE_ZONE: &str = "BeaconStore";
    /// The keychain container: the trust circle and the keychain item views live here.
    pub const KEYCHAIN_CONTAINER: &str = "com.apple.security.keychain";
    pub const CUTTLEFISH_BUNDLE: &str = "com.apple.security.cuttlefish";
    pub const CUTTLEFISH_SERVICE: &str = "Cuttlefish";

    /// Opening a container goes to the gateway; operations go to the URLs it hands back.
    pub const CK_APP_INIT_URL: &str = "https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit";

    pub const PATH_ZONE_RETRIEVE: &str = "/api/client/zone/retrieve";
    pub const PATH_RECORD_SYNC: &str = "/api/client/record/sync";
    pub const PATH_CODE_INVOKE: &str = "/api/client/code/invoke";

    pub const PROTOBUF_CONTENT_TYPE: &str = "application/x-protobuf; \
desc=\"https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc\"; \
messageType=RequestOperation; delimited=true";

    pub const SYNC_STATUS_COMPLETE: i32 = 3;
}

/// Which operation a request is; the number is also the `RequestOperation` field carrying it.
pub mod operation_type {
    pub const ZONE_RETRIEVE: i32 = 201;
    pub const RECORD_RETRIEVE_CHANGES: i32 = 213;
    pub const FUNCTION_INVOKE: i32 = 1101;
}

pub mod result_code {
    pub const SUCCESS: i32 = 1;
    pub const PARTIAL: i32 = 2;
    pub const FAILURE: i32 = 3;
    pub const INDETERMINATE: i32 = 4;
}

/// Client-fault codes as far as they are known (`ClientErrorCode`).
pub mod client_error_code {
    pub const BAD_SYNTAX: i32 = 4;
    pub const FORBIDDEN: i32 = 5;
    pub const THROTTLED: i32 = 6;
    pub const NOT_SUPPORTED: i32 = 8;
    pub const EXISTS: i32 = 9;
    pub const BAD_AUTH_TOKEN: i32 = 11;
    pub const NEEDS_AUTHENTICATION: i32 = 12;

    pub fn name(code: i32) -> Option<&'static str> {
        match code {
            BAD_SYNTAX => Some("BAD_SYNTAX"),
            FORBIDDEN => Some("FORBIDDEN"),
            THROTTLED => Some("THROTTLED"),
            NOT_SUPPORTED => Some("NOT_SUPPORTED"),
            EXISTS => Some("EXISTS"),
            BAD_AUTH_TOKEN => Some("BAD_AUTH_TOKEN"),
            NEEDS_AUTHENTICATION => Some("NEEDS_AUTHENTICATION"),
            _ => None,
        }
    }
}

/// What a field's PLAINTEXT is (not what is on the wire).
pub mod value_type {
    pub const BYTES: i32 = 1;
    pub const DATE: i32 = 2;
    pub const STRING: i32 = 3;
    pub const INT64: i32 = 7;
    pub const DOUBLE: i32 = 8;
    pub const STRING_LIST: i32 = 15;
    pub const ENCRYPTED_BYTES: i32 = 20;
}

/// Record types of the BeaconStore zone; wire strings, so an unlisted one passes through.
pub mod record_type {
    pub const MASTER_BEACON: &str = "MasterBeaconRecord";
    pub const BEACON_NAMING: &str = "BeaconNamingRecord";
    pub const KEY_ALIGNMENT: &str = "KeyAlignmentRecord";
    pub const SAFE_LOCATION: &str = "SafeLocation";
}

/// Where CloudKit lives for this account (iCloud partitions accounts across numbered hosts).
#[derive(Debug, Clone, Default)]
pub struct CloudKitContainerInfo {
    pub user_id: String,
    pub database_url: Option<String>,
    pub database_gateway_url: Option<String>,
    pub code_gateway_url: Option<String>,
    pub share_gateway_url: Option<String>,
    pub raw: BTreeMap<String, serde_json::Value>,
}

impl CloudKitContainerInfo {
    /// The account's iCloud partition, as the bare number of a `p<N>-` host prefix.
    pub fn partition(&self) -> Option<String> {
        let urls = [self.database_url.as_deref(), self.raw.get("cloudKitShareUrl").and_then(|v| v.as_str())];
        for url in urls.into_iter().flatten() {
            let host = url.split("://").nth(1).unwrap_or(url).split('/').next().unwrap_or("");
            if let Some(rest) = host.strip_prefix('p') {
                if let Some((candidate, _)) = rest.split_once('-') {
                    if !candidate.is_empty() && candidate.chars().all(|c| c.is_ascii_digit()) {
                        return Some(candidate.to_string());
                    }
                }
            }
        }
        None
    }
}

/// One page of record changes, the token that continues from it, and its status.
#[derive(Debug, Clone, Default)]
pub struct RecordSyncPage {
    pub changes: Vec<RecordChange>,
    pub continuation_token: Option<Vec<u8>>,
    pub status: Option<i32>,
}

impl RecordSyncPage {
    pub const SYNC_STATUS_COMPLETE: i32 = constants::SYNC_STATUS_COMPLETE;

    /// A page with changes can still be the last; an empty page is not the signal.
    pub fn complete(&self) -> bool {
        self.status == Some(Self::SYNC_STATUS_COMPLETE)
    }
}

/// The read-only CloudKit subset the app uses. `record_save` is deliberately absent.
pub trait CloudKitApi: Send + Sync {
    fn open_container<'a>(&'a self, refresh: bool) -> crate::login::BoxFuture<'a, Result<CloudKitContainerInfo>>;

    fn zone_retrieve<'a>(&'a self) -> crate::login::BoxFuture<'a, Result<Vec<ZoneSummary>>>;

    fn record_sync<'a>(
        &'a self,
        zone_name: &'a str,
        continuation_token: Option<Vec<u8>>,
        max_changes: Option<i32>,
    ) -> crate::login::BoxFuture<'a, Result<RecordSyncPage>>;

    /// Calls a server-side function and returns its serialised result (how Cuttlefish and securityd
    /// are reached).
    fn function_invoke<'a>(
        &'a self,
        service: &'a str,
        name: &'a str,
        parameters: Vec<u8>,
    ) -> crate::login::BoxFuture<'a, Result<Vec<u8>>>;

    /// Every record change in a zone, page by page until the server says the zone is fully synced.
    fn iter_records<'a>(
        &'a self,
        zone_name: &'a str,
        continuation_token: Option<Vec<u8>>,
        max_pages: usize,
    ) -> crate::login::BoxFuture<'a, Result<Vec<RecordChange>>> {
        Box::pin(async move {
            let mut out = Vec::new();
            let mut token = continuation_token;
            for _ in 0..max_pages {
                let page = self.record_sync(zone_name, token.clone(), None).await?;
                out.extend(page.changes.iter().cloned());
                if page.complete() {
                    return Ok(out);
                }
                match page.continuation_token {
                    Some(next) if token.as_ref() != Some(&next) => token = Some(next),
                    _ => return Ok(out),
                }
            }
            Ok(out)
        })
    }
}
