//! The facade the host uses: one signed-in account plus the state blob it must persist.
//!
//! State is host-stored. [`OpenFinderSession::save_state`] returns a JSON blob (the signed-in session,
//! no password and no PET); the host keeps it in Keystore-backed storage and hands it back to
//! [`OpenFinderSession::restore`]. Each mutating call reports whether the state changed so the host knows
//! when to re-save it.

use std::sync::Arc;

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::gsa::GsaClient;
use crate::http::Http;
use crate::login::account::{AppleAccount, SavedSession};
use crate::login::device::{LoginDevice, LoginEndpoints, LoginResult, LoginState, SecondFactorMethod};
use crate::login::AnisetteSource;

/// What the host must tell the library to build an account: the machine's pair (which must match the
/// Anisette source's), the serial, the client info of the machine file, and the host UUID.
#[derive(Debug, Clone)]
pub struct LoginConfig {
    pub local_user_uuid: String,
    pub device_id: String,
    pub serial: Option<String>,
    pub client_info: String,
    pub host_uuid: Vec<u8>,
}

impl LoginConfig {
    pub fn device(&self) -> Result<LoginDevice> {
        LoginDevice::new(
            self.local_user_uuid.clone(),
            self.device_id.clone(),
            self.serial.clone(),
            &self.client_info,
            &self.host_uuid,
        )
    }
}

/// The provisioning operations the session needs from the machine (CoreADI under Unicorn, or a
/// test double). `provisioning_begin` returns `(cpim, session)`; `provisioning_finish` stores the
/// PTM/TK and routing.
pub trait MachineProvisioner: Send + Sync {
    fn provisioning_begin(&self, ds_id: i64, spim: &[u8]) -> Result<(Vec<u8>, u32)>;
    fn provisioning_finish(&self, ds_id: i64, session: u32, ptm: &[u8], tk: &[u8], routing: i64) -> Result<()>;
}

/// Provisions a fresh machine through Grand Slam. The host persists the machine store afterwards.
pub async fn provision_machine(
    gsa: &mut GsaClient,
    provisioner: &dyn MachineProvisioner,
    ds_id: i64,
) -> Result<i64> {
    gsa.load_url_bag().await?;
    let spim = gsa.start_provisioning().await?;
    let (cpim, session) = provisioner.provisioning_begin(ds_id, &spim)?;
    let result = gsa.finish_provisioning(&cpim).await?;
    provisioner.provisioning_finish(ds_id, session, &result.ptm, &result.tk, result.routing)?;
    Ok(result.routing)
}

/// Answers Apple's resync through Grand Slam, against the machine's stored routing.
pub async fn resync_machine(
    gsa: &mut GsaClient,
    machine: &dyn MachineSyncer,
    ds_id: i64,
    sim_b64: &str,
) -> Result<()> {
    let sim = crate::util::b64_decode(sim_b64)
        .ok_or_else(|| Error::Backend("the resync SIM is not base64".into()))?;
    let (mid, srm) = machine.sync(ds_id, &sim)?;
    let verdict = gsa
        .sync_machine(&crate::util::b64(&mid), &crate::util::b64(&srm), None)
        .await?;
    let status = verdict.get("Status").and_then(|v| v.as_dict());
    let ec = status.and_then(|s| s.get("ec")).and_then(|v| v.as_i64());
    if ec == Some(0) {
        Ok(())
    } else {
        let em = status
            .and_then(|s| s.get("em"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        Err(Error::Rejected {
            http: Some(200),
            ec,
            message: format!("Apple did not accept the machine's resync ({em})"),
        })
    }
}

/// The machine side of a resync.
pub trait MachineSyncer: Send + Sync {
    fn sync(&self, ds_id: i64, sim: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
}

/// A signed-in session. Constructed once per account; `AppleAccount` holds the live state.
pub struct OpenFinderSession {
    account: Arc<AppleAccount>,
}

impl OpenFinderSession {
    pub fn new(
        config: LoginConfig,
        anisette: Arc<dyn AnisetteSource>,
        endpoints: LoginEndpoints,
        http: Http,
    ) -> Result<OpenFinderSession> {
        let device = config.device()?;
        Ok(OpenFinderSession { account: Arc::new(AppleAccount::new(device, anisette, endpoints, http)) })
    }

    /// Restores a session from a state blob saved by [`OpenFinderSession::save_state`].
    pub fn restore(
        state: &str,
        config: LoginConfig,
        anisette: Arc<dyn AnisetteSource>,
        endpoints: LoginEndpoints,
        http: Http,
    ) -> Result<OpenFinderSession> {
        let saved = state_session(state)?;
        let device = config.device()?;
        let account = match saved {
            Some(saved) => AppleAccount::restore(saved, device, anisette, endpoints, http)?,
            None => AppleAccount::new(device, anisette, endpoints, http),
        };
        Ok(OpenFinderSession { account: Arc::new(account) })
    }

    pub fn account(&self) -> &AppleAccount {
        &self.account
    }

    /// The shared account, for the facades that take an `Arc` (reports, CloudKit, keychain).
    pub fn account_arc(&self) -> Arc<AppleAccount> {
        self.account.clone()
    }

    pub async fn login_state(&self) -> LoginState {
        self.account.login_state().await
    }

    pub async fn login(
        &self,
        username: &str,
        password: &mut [u8],
        list_phone_numbers: bool,
    ) -> Result<LoginResult> {
        self.account.login(username, password, list_phone_numbers).await
    }

    pub async fn second_factor_methods(&self) -> Result<Vec<SecondFactorMethod>> {
        self.account.second_factor_methods().await
    }

    pub async fn request_sms_code(&self, phone_number_id: i64) -> Result<()> {
        self.account.request_sms_code(phone_number_id).await
    }

    pub async fn submit_sms_code(&self, phone_number_id: i64, code: &str) -> Result<LoginResult> {
        self.account.submit_sms_code(phone_number_id, code).await
    }

    pub async fn request_trusted_device_code(&self) -> Result<()> {
        self.account.request_trusted_device_code().await
    }

    pub async fn submit_trusted_device_code(&self, code: &str) -> Result<LoginResult> {
        self.account.submit_trusted_device_code(code).await
    }

    pub async fn request_pet(&self) -> Result<String> {
        self.account.request_pet().await
    }

    pub async fn refresh_session(&self) -> Result<()> {
        self.account.refresh_session().await
    }

    pub async fn provide_password(&self, password: &mut [u8]) {
        self.account.provide_password(password).await
    }

    /// The state blob the host must persist (Keystore-encrypted). No password, no PET.
    pub async fn save_state(&self) -> Result<String> {
        let session = if self.account.login_state().await == LoginState::LoggedIn {
            Some(self.account.snapshot().await?.to_json())
        } else {
            None
        };
        Ok(json!({"version": 1, "session": session}).to_string())
    }
}

fn state_session(state: &str) -> Result<Option<SavedSession>> {
    let doc: Value = serde_json::from_str(state)
        .map_err(|_| Error::State("the state blob is not JSON".into()))?;
    match doc.get("session") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(SavedSession::from_json(s)?)),
        Some(_) => Err(Error::State("the state blob has a bad session".into())),
    }
}

/// Redacts secrets in a debug rendering of a session. Kept here so the FFI never logs a token.
impl std::fmt::Debug for OpenFinderSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenFinderSession").field("account", &"<redacted>").finish()
    }
}

/// A password buffer wrapper for hosts that keep the password as bytes.
pub fn zeroize_password(password: &mut [u8]) {
    use zeroize::Zeroize;
    password.zeroize();
}

/// Re-export for the FFI.
pub type Password = Zeroizing<Vec<u8>>;
