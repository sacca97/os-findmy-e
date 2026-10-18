//! Cuttlefish: the server side of Apple's keychain trust-circle protocol (port of
//! `findmy/keychain/cuttlefish.py`, the read-only half).
//!
//! Cuttlefish is not a service of its own; it is invoked as a server-side function through the keychain
//! CloudKit container. This answers "which bottles could I recover from" and "which shares is a peer
//! entitled to" -- both create nothing and need no passcode.

use apple_proto::cuttlefish::{EscrowData, FetchViableBottlesRequest, FetchViableBottlesResponse};
use prost::Message;

use crate::cloudkit::client::CloudKitClient;
use crate::error::{Error, Result};

pub const METHOD_FETCH_VIABLE_BOTTLES: &str = "fetchViableBottles";
pub const VIABLE_BOTTLES_FILTER: u32 = 1;

fn cuttlefish_error(message: impl Into<String>) -> Error {
    Error::Backend(message.into())
}

/// Which bottles Cuttlefish considers usable.
#[derive(Debug, Clone, Default)]
pub struct ViableBottles {
    /// Bottle identifiers that can be recovered from (they join to an escrow record's label).
    pub valid: Vec<String>,
    /// How many bottles exist in a not-fully-usable state.
    pub partial_count: usize,
    /// The valid entries in full, each carrying its sealed bottle.
    pub entries: Vec<EscrowData>,
}

/// Ask which bottles this account could be recovered from.
pub async fn fetch_viable_bottles(client: &dyn crate::cloudkit::CloudKitApi) -> Result<ViableBottles> {
    let request = FetchViableBottlesRequest { filter: Some(VIABLE_BOTTLES_FILTER), metrics: Some(Vec::new()) };
    let serialized = client
        .function_invoke(crate::cloudkit::constants::CUTTLEFISH_SERVICE, METHOD_FETCH_VIABLE_BOTTLES, request.encode_to_vec())
        .await?;
    let response = FetchViableBottlesResponse::decode(serialized.as_slice()).map_err(|e| {
        cuttlefish_error(format!(
            "CloudKit accepted the call but its result did not decode as a {METHOD_FETCH_VIABLE_BOTTLES} response ({e}). The inner message layer is what is wrong, not the CloudKit envelope."
        ))
    })?;
    let entries: Vec<EscrowData> = response.valid.into_iter().filter(|entry| entry.id.as_deref().map(|id| !id.is_empty()).unwrap_or(false)).collect();
    let valid: Vec<String> = entries.iter().filter_map(|entry| entry.id.clone()).collect();
    Ok(ViableBottles { valid, partial_count: response.partial.len(), entries })
}

/// A CloudKit client pointed at the keychain container (where the trust circle lives).
pub fn make_cuttlefish_client(account: std::sync::Arc<dyn crate::cloudkit::client::CloudKitAccount>) -> CloudKitClient {
    CloudKitClient::new(account)
        .with_container(crate::cloudkit::constants::KEYCHAIN_CONTAINER)
        .with_bundle(crate::cloudkit::constants::CUTTLEFISH_BUNDLE)
}

/// A CloudKit client for keychain item zones (same container, the `securityd` bundle).
pub fn make_securityd_client(account: std::sync::Arc<dyn crate::cloudkit::client::CloudKitAccount>) -> CloudKitClient {
    CloudKitClient::new(account)
        .with_container(crate::cloudkit::constants::KEYCHAIN_CONTAINER)
        .with_bundle("com.apple.securityd")
}
