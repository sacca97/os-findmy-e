//! The keychain session facade (port of `findmy/keychain/session.py`, the read path).
//!
//! `recovery_options` lists what can be recovered from, `recover` opens a record with one passcode guess,
//! `key_shares` and `pcs_keys` read the keychain view keys. Nothing here writes: `join` is not ported.

use std::sync::Arc;

use apple_proto::cuttlefish::{Bottle, OtBottle};
use prost::Message;

use crate::cloudkit::client::{CloudKitAccount, CloudKitClient};
use crate::cloudkit::CloudKitApi;
use crate::error::{Error, Result};
use crate::keychain::bottle::{find_bottle_keys, open_bottle, BottleKeys, OpenedBottle};
use crate::keychain::cuttlefish::{fetch_viable_bottles, make_cuttlefish_client, make_securityd_client, ViableBottles};
use crate::keychain::escrow::{escrow_host, join_recovery_options, EscrowAccount, EscrowCommands, EscrowProxy, EscrowRecord, RecoveryOptions};
use crate::keychain::items::{fetch_view, payload_of, readable_items, service_key_item, VIEW_MANATEE, VIEW_PROTECTED_CLOUD_STORAGE};
use crate::keychain::peers::{fetch_peer_directory, PeerDirectory};
use crate::keychain::recovery::recover_bottled_peer;
use crate::keychain::shares::{fetch_recoverable_shares, unwrap_share, KeyShare, ViewKeyring};
use crate::login::BoxFuture;

const ENTROPY_FIELD: &str = "BottledPeerEntropy";

fn session_error(message: impl Into<String>) -> Error {
    Error::Backend(message.into())
}

/// What the keychain session needs from a signed-in account (CloudKit + escrow + the PET/adsid).
pub trait KeychainAccount: CloudKitAccount + EscrowAccount {
    fn adsid<'a>(&'a self) -> BoxFuture<'a, String>;
    /// The Apple ID the escrow proxy authenticates as (sync on the account, so captured here).
    fn account_name<'a>(&'a self) -> BoxFuture<'a, String>;
    fn request_pet<'a>(&'a self) -> BoxFuture<'a, Result<String>>;
}

impl KeychainAccount for crate::login::account::AppleAccount {
    fn adsid<'a>(&'a self) -> BoxFuture<'a, String> {
        Box::pin(async move { crate::login::account::AppleAccount::adsid(self).await })
    }
    fn account_name<'a>(&'a self) -> BoxFuture<'a, String> {
        Box::pin(async move { crate::login::account::AppleAccount::account_name(self).await })
    }
    fn request_pet<'a>(&'a self) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move { crate::login::account::AppleAccount::request_pet(self).await })
    }
}

/// A recovered peer, opened: a device's identity from the trust circle.
pub struct RecoveredPeer {
    pub record: EscrowRecord,
    pub fields: BTreeMap<String, crate::plist::Value>,
    pub salt: String,
    pub keys: BottleKeys,
    pub bottle: OpenedBottle,
    pub cuttlefish_peer_id: Option<String>,
}

impl RecoveredPeer {
    pub fn peer_id(&self) -> String {
        self.cuttlefish_peer_id.clone().unwrap_or_else(|| self.record.peer_id())
    }

    pub fn encryption_key(&self) -> Result<p384::SecretKey> {
        self.bottle.encryption()
    }
}

use std::collections::BTreeMap;

/// A live keychain session (read-only).
pub struct KeychainSession {
    account: Arc<dyn KeychainAccount>,
    cuttlefish: Arc<dyn CloudKitApi>,
    securityd: Arc<dyn CloudKitApi>,
    escrow: Arc<dyn EscrowCommands>,
    partition: String,
    /// A PET lasts about five minutes; renew it before an exchange that may outlive it (the Python's
    /// `_renew_token_if_stale`, at 240 s).
    pet_obtained_at: std::sync::Mutex<std::time::Instant>,
    options: tokio::sync::Mutex<Option<RecoveryOptions>>,
    bottles: tokio::sync::Mutex<Option<ViableBottles>>,
    peers: tokio::sync::Mutex<Option<PeerDirectory>>,
}

impl KeychainSession {
    pub async fn open(account: Arc<dyn KeychainAccount>) -> Result<KeychainSession> {
        let cloudkit: Arc<dyn CloudKitAccount> = account.clone();
        let cloudkit = CloudKitClient::new(cloudkit);
        let info = cloudkit.open_container(false).await?;
        let partition = info
            .partition()
            .ok_or_else(|| session_error("The container returned no partitioned URL, so the escrow host cannot be derived"))?;
        let pet = account.request_pet().await?;
        let account_name = account.account_name().await;
        let proxy = EscrowProxy::new(account.clone(), escrow_host(&partition), pet, account_name)?;
        let cuttlefish: Arc<dyn CloudKitApi> = Arc::new(make_cuttlefish_client(account.clone()));
        let securityd: Arc<dyn CloudKitApi> = Arc::new(make_securityd_client(account.clone()));
        Ok(KeychainSession {
            account,
            cuttlefish,
            securityd,
            escrow: Arc::new(proxy),
            partition,
            pet_obtained_at: std::sync::Mutex::new(std::time::Instant::now()),
            options: tokio::sync::Mutex::new(None),
            bottles: tokio::sync::Mutex::new(None),
            peers: tokio::sync::Mutex::new(None),
        })
    }

    /// Build a session from already-constructed backends (tests, and hosts that own their clients).
    pub fn from_parts(
        account: Arc<dyn KeychainAccount>,
        cuttlefish: Arc<dyn CloudKitApi>,
        securityd: Arc<dyn CloudKitApi>,
        escrow: Arc<dyn EscrowCommands>,
        partition: String,
    ) -> KeychainSession {
        KeychainSession {
            account,
            cuttlefish,
            securityd,
            escrow,
            partition,
            pet_obtained_at: std::sync::Mutex::new(std::time::Instant::now()),
            options: tokio::sync::Mutex::new(None),
            bottles: tokio::sync::Mutex::new(None),
            peers: tokio::sync::Mutex::new(None),
        }
    }

    /// Renew the escrow PET if it is near expiry (one authentication), as the Python does.
    async fn renew_pet_if_stale(&self) -> Result<()> {
        let stale = self
            .pet_obtained_at
            .lock()
            .map(|t| t.elapsed() >= std::time::Duration::from_secs(240))
            .unwrap_or(false);
        if !stale {
            return Ok(());
        }
        let pet = self.account.request_pet().await?;
        self.escrow.replace_pet(&pet).await?;
        if let Ok(mut at) = self.pet_obtained_at.lock() {
            *at = std::time::Instant::now();
        }
        Ok(())
    }

    pub fn partition(&self) -> &str {
        &self.partition
    }

    pub async fn recovery_options(&self) -> Result<RecoveryOptions> {
        {
            let guard = self.options.lock().await;
            if let Some(options) = guard.as_ref() {
                return Ok(options.clone());
            }
        }
        self.renew_pet_if_stale().await?;
        let bottles = fetch_viable_bottles(self.cuttlefish.as_ref()).await?;
        let listing = self.escrow.list_records().await?;
        let options = join_recovery_options(&listing, &bottles.valid);
        *self.bottles.lock().await = Some(bottles);
        *self.options.lock().await = Some(options.clone());
        Ok(options)
    }

    pub async fn peer_directory(&self) -> Result<PeerDirectory> {
        {
            let guard = self.peers.lock().await;
            if let Some(peers) = guard.as_ref() {
                return Ok(peers.clone());
            }
        }
        let directory = fetch_peer_directory(self.cuttlefish.as_ref(), None, 50).await?;
        *self.peers.lock().await = Some(directory.clone());
        Ok(directory)
    }

    /// Recover a peer's identity from an escrow record; the passcode is used once and not retained.
    pub async fn recover(&self, record: &EscrowRecord, passcode: &str) -> Result<RecoveredPeer> {
        self.renew_pet_if_stale().await?;
        let options = self.recovery_options().await?;
        if !options.recoverable.iter().any(|r| r.label == record.label) {
            return Err(session_error(format!(
                "{} is not among the records this session found recoverable. Recovering from a record whose bottle is not usable cannot succeed.",
                record.label
            )));
        }
        let material = recover_bottled_peer(self.escrow.as_ref(), record, passcode).await?;
        let fields = crate::plist::parse_dict(&material)?;
        let entropy = fields
            .get(ENTROPY_FIELD)
            .and_then(|v| v.as_data())
            .ok_or_else(|| session_error(format!("The recovered material carries no {ENTROPY_FIELD}")))?
            .to_vec();

        let sealed = {
            let guard = self.bottles.lock().await;
            guard
                .as_ref()
                .and_then(|b| b.entries.iter().find(|e| e.id.as_deref() == Some(record.label.as_str())))
                .and_then(|e| e.bottle.clone())
                .ok_or_else(|| session_error(format!("The trust-circle service listed {} as viable but returned no sealed contents for it", record.label)))?
        };
        if sealed.bottle.is_none() {
            return Err(session_error(format!("{} carries no sealed contents to open", record.label)));
        }
        let inner = OtBottle::decode(sealed.bottle.clone().unwrap_or_default().as_slice())
            .map_err(|e| session_error(format!("A bottle's sealed contents did not decode: {e}")))?;

        let directory = self.peer_directory().await?;
        let addressable = addressable_peer_id(&directory, &[sealed.peer_id.clone().unwrap_or_default(), inner.peer_id.clone().unwrap_or_default()]);
        let sponsor = addressable.as_deref().and_then(|id| directory.get(id));

        let adsid = self.account.adsid().await;
        let dsid = self.account.dsid().await.unwrap_or_default();
        let (keys, salt) = find_bottle_keys(
            &entropy,
            &[adsid, dsid],
            inner.escrowed_signing_key.as_deref().unwrap_or(&[]),
            inner.escrowed_encryption_key.as_deref().unwrap_or(&[]),
        )?;
        let sponsor_public = sponsor.and_then(|p| p.signing_public_key()).and_then(public_from);
        let bottle = open_bottle(&sealed, &keys, true, sponsor_public.as_ref())?;
        Ok(RecoveredPeer {
            record: record.clone(),
            fields,
            salt,
            keys,
            bottle,
            cuttlefish_peer_id: addressable,
        })
    }

    pub async fn key_shares(&self, peer: &RecoveredPeer) -> Result<Vec<KeyShare>> {
        let directory = self.peer_directory().await?;
        let entries = fetch_recoverable_shares(self.cuttlefish.as_ref(), &peer.peer_id()).await?;
        let encryption_key = peer.encryption_key()?;
        let signing_key = peer.bottle.signing().ok();
        let mut candidates: Vec<(&str, &p384::SecretKey)> = vec![("encryption", &encryption_key)];
        if let Some(signing) = &signing_key {
            candidates.push(("signing", signing));
        }
        Ok(entries
            .iter()
            .map(|entry| unwrap_share(entry, &candidates, Some(&directory), Some(&peer.peer_id())))
            .collect())
    }

    pub async fn pcs_keys(&self, peer: &RecoveredPeer) -> Result<Vec<crate::cloudkit::pcs::PcsKey>> {
        let shares = self.key_shares(peer).await?;
        let mut keys = Vec::new();
        for view in [VIEW_MANATEE, VIEW_PROTECTED_CLOUD_STORAGE] {
            keys.extend(self.pcs_keys_in(&shares, view).await.unwrap_or_default());
        }
        Ok(keys)
    }

    async fn pcs_keys_in(
        &self,
        shares: &[KeyShare],
        view: &str,
    ) -> Result<Vec<crate::cloudkit::pcs::PcsKey>> {
        let keyring: &ViewKeyring = shares
            .iter()
            .find(|s| s.service == view && !s.view_keys.is_empty())
            .map(|s| &s.view_keys)
            .ok_or_else(|| session_error(format!("No keys were recovered for the {view:?} view")))?;
        let contents = fetch_view(self.securityd.as_ref(), view, None).await?;
        let mut keys = Vec::new();
        for item in readable_items(&contents, keyring).values() {
            if let Ok(payload) = payload_of(item) {
                if let Ok(found) = crate::cloudkit::servicekeys::keys_from_der(&payload) {
                    keys.extend(found);
                }
            }
        }
        Ok(keys)
    }

    /// The whole Stage 3 read path in one call: recover the peer and read its PCS keys.
    pub async fn recover_service_keys(&self, record: &EscrowRecord, passcode: &str) -> Result<Vec<crate::cloudkit::pcs::PcsKey>> {
        let peer = self.recover(record, passcode).await?;
        self.pcs_keys(&peer).await
    }

    /// Read the service key item for one view (used by callers that want the item itself).
    pub async fn service_key_item(&self, peer: &RecoveredPeer, view: &str) -> Result<BTreeMap<String, crate::plist::Value>> {
        let shares = self.key_shares(peer).await?;
        let keyring = shares
            .iter()
            .find(|s| s.service == view && !s.view_keys.is_empty())
            .map(|s| s.view_keys.clone())
            .ok_or_else(|| session_error(format!("No keys were recovered for the {view:?} view")))?;
        let contents = fetch_view(self.securityd.as_ref(), view, None).await?;
        service_key_item(&contents, &keyring)
    }
}

/// The most authoritative of a bottle's peer ids that the circle actually contains.
pub fn addressable_peer_id(directory: &PeerDirectory, candidates: &[String]) -> Option<String> {
    candidates
        .iter()
        .find(|c| !c.is_empty() && directory.contains(c))
        .or_else(|| candidates.iter().find(|c| !c.is_empty()))
        .cloned()
}

fn public_from(_key: crate::keychain::peers::PublicKey) -> Option<p384::PublicKey> {
    // The peer's signing key is loaded as an enum; the bottle's sponsor signature uses P-384.
    match _key {
        crate::keychain::peers::PublicKey::P384(point) => p384::PublicKey::from_sec1_bytes(&point).ok(),
        _ => None,
    }
}

/// Keep `Bottle` referenced for callers that want the raw sealed struct.
pub type SealedBottle = Bottle;
