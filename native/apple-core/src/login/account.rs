//! The signed-in account state machine (port of `findmy.reports.account.AsyncAppleAccount` and
//! `apple/login/AppleAccount.kt`).
//!
//! Deliberate differences from the Python, each small and matching the Kotlin:
//!  * the password itself is never held: only SHA-256(password) is kept in memory (enough for both
//!    `s2k` variants), and the caller's buffer is zeroed. A restored session cannot renew a PET or
//!    re-authenticate until [`AppleAccount::provide_password`] is called;
//!  * the caller lists the second-factor methods itself, and a failed phone-number fetch does not
//!    hide the trusted-device method;
//!  * the trusted-device `validate` reply's `ec` is checked;
//!  * a failed [`AppleAccount::refresh_session`] leaves the previous signed-in state in place.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::json;
use zeroize::Zeroizing;
use zeroize::Zeroize;

use crate::error::{Error, GrandSlamStep, Result};
use crate::http::Http;
use crate::login::crypto::{self, S2K, S2K_FO};
use crate::login::device::{
    AccountInfo, LoginDevice, LoginEndpoints, LoginResult, LoginState, SecondFactorMethod,
};
use crate::login::messages;
use crate::login::srp::{random_ephemeral, SrpClient};
use crate::login::AnisetteSource;
use crate::plist::{self, Value};

const TRUSTED_DEVICE_AU: &str = "trustedDeviceSecondaryAuth";

/// A future boxed so [`AnisetteSource`] can be used behind a trait object.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// The signed-in state to persist; holds credentials, so it is redacted in `Debug`.
#[derive(Clone)]
pub struct SavedSession {
    pub username: String,
    pub local_user_uuid: String,
    pub device_id: String,
    pub cloud_kit_device_uuid: String,
    pub account_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub dsid: String,
    pub adsid: Option<String>,
    pub idms_hb: Option<String>,
    pub service_tokens: BTreeMap<String, String>,
    pub saved_at: i64,
}

impl std::fmt::Debug for SavedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SavedSession")
            .field("username", &self.username)
            .field("dsid", &"<redacted>")
            .field("tokens", &self.service_tokens.keys().collect::<Vec<_>>())
            .field("saved_at", &self.saved_at)
            .finish()
    }
}

impl SavedSession {
    pub const VERSION: i64 = 1;

    /// The same JSON shape as `apple/login/SessionStore.kt`.
    pub fn to_json(&self) -> String {
        let mut tokens = serde_json::Map::new();
        for (k, v) in &self.service_tokens {
            tokens.insert(k.clone(), json!(v));
        }
        let mut info = serde_json::Map::new();
        if let Some(v) = &self.account_name {
            info.insert("account_name".into(), json!(v));
        }
        if let Some(v) = &self.first_name {
            info.insert("first_name".into(), json!(v));
        }
        if let Some(v) = &self.last_name {
            info.insert("last_name".into(), json!(v));
        }
        let mut login = serde_json::Map::new();
        login.insert("dsid".into(), json!(self.dsid));
        if let Some(v) = &self.adsid {
            login.insert("adsid".into(), json!(v));
        }
        if let Some(v) = &self.idms_hb {
            login.insert("idms_hb".into(), json!(v));
        }
        login.insert("tokens".into(), serde_json::Value::Object(tokens));
        let doc = json!({
            "version": Self::VERSION,
            "username": self.username,
            "ids": {
                "uid": self.local_user_uuid,
                "devid": self.device_id,
                "cloudkit_device_uuid": self.cloud_kit_device_uuid,
            },
            "info": serde_json::Value::Object(info),
            "login": serde_json::Value::Object(login),
            "saved_at": self.saved_at,
        });
        doc.to_string()
    }

    pub fn from_json(text: &str) -> Result<SavedSession> {
        let doc: serde_json::Value =
            serde_json::from_str(text).map_err(|_| Error::Backend("not a saved session".into()))?;
        if doc.get("version").and_then(|v| v.as_i64()) != Some(Self::VERSION) {
            return Err(Error::Backend("unsupported saved-session version".into()));
        }
        let s = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let ids = &doc["ids"];
        let info = &doc["info"];
        let login = &doc["login"];
        let mut tokens = BTreeMap::new();
        if let Some(obj) = login.get("tokens").and_then(|t| t.as_object()) {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    tokens.insert(k.clone(), s.to_string());
                }
            }
        }
        Ok(SavedSession {
            username: s(&doc, "username").ok_or_else(|| Error::Backend("not a saved session".into()))?,
            local_user_uuid: s(ids, "uid").ok_or_else(|| Error::Backend("not a saved session".into()))?,
            device_id: s(ids, "devid").ok_or_else(|| Error::Backend("not a saved session".into()))?,
            cloud_kit_device_uuid: s(ids, "cloudkit_device_uuid")
                .ok_or_else(|| Error::Backend("not a saved session".into()))?,
            account_name: s(info, "account_name"),
            first_name: s(info, "first_name"),
            last_name: s(info, "last_name"),
            dsid: s(login, "dsid").ok_or_else(|| Error::Backend("not a saved session".into()))?,
            adsid: s(login, "adsid"),
            idms_hb: s(login, "idms_hb"),
            service_tokens: tokens,
            saved_at: doc.get("saved_at").and_then(|v| v.as_i64()).unwrap_or(0),
        })
    }

    pub fn older_than(&self, age_seconds: i64, now: i64) -> bool {
        self.saved_at + age_seconds < now
    }
}

#[derive(Clone, Default)]
struct StateData {
    adsid: Option<String>,
    idms_token: Option<String>,
    idms_pet: Option<String>,
    idms_hb: Option<String>,
    dsid: Option<String>,
    tokens: BTreeMap<String, String>,
    obtained_at: Option<i64>,
}

#[derive(Clone)]
struct Session {
    state: LoginState,
    data: StateData,
    info: Option<AccountInfo>,
}

impl Default for Session {
    fn default() -> Self {
        Session { state: LoginState::LoggedOut, data: StateData::default(), info: None }
    }
}

struct Inner {
    session: Session,
    username: Option<String>,
    password_digest: Option<Zeroizing<[u8; 32]>>,
}

/// The account client. All stateful calls take the internal lock; the live session is swapped as one
/// value, so a reader never sees a half-updated session.
pub struct AppleAccount {
    device: LoginDevice,
    anisette: Arc<dyn AnisetteSource>,
    endpoints: LoginEndpoints,
    http: Http,
    ephemeral: Box<dyn Fn() -> Vec<u8> + Send + Sync>,
    inner: tokio::sync::Mutex<Inner>,
}

impl AppleAccount {
    pub fn new(
        device: LoginDevice,
        anisette: Arc<dyn AnisetteSource>,
        endpoints: LoginEndpoints,
        http: Http,
    ) -> AppleAccount {
        AppleAccount {
            device,
            anisette,
            endpoints,
            http,
            ephemeral: Box::new(|| random_ephemeral().to_vec()),
            inner: tokio::sync::Mutex::new(Inner {
                session: Session::default(),
                username: None,
                password_digest: None,
            }),
        }
    }

    /// Fix the SRP ephemeral `a` (tests).
    pub fn with_ephemeral(mut self, f: impl Fn() -> Vec<u8> + Send + Sync + 'static) -> Self {
        self.ephemeral = Box::new(f);
        self
    }

    /// Restore a saved session on this machine, with no request to Apple. Refuses a session saved on
    /// a different machine.
    pub fn restore(
        saved: SavedSession,
        device: LoginDevice,
        anisette: Arc<dyn AnisetteSource>,
        endpoints: LoginEndpoints,
        http: Http,
    ) -> Result<AppleAccount> {
        if saved.device_id != device.device_id || saved.local_user_uuid != device.local_user_uuid {
            return Err(Error::Authentication(
                "the saved sign-in belongs to a different machine. Sign in again.".into(),
            ));
        }
        let mut account = AppleAccount::new(device, anisette, endpoints, http);
        let info = AccountInfo {
            account_name: saved.account_name.clone(),
            first_name: saved.first_name.clone(),
            last_name: saved.last_name.clone(),
            trusted_device_2fa: false,
        };
        account.inner = tokio::sync::Mutex::new(Inner {
            session: Session {
                state: LoginState::LoggedIn,
                data: StateData {
                    adsid: saved.adsid.clone(),
                    idms_hb: saved.idms_hb.clone(),
                    dsid: Some(saved.dsid.clone()),
                    tokens: saved.service_tokens.clone(),
                    obtained_at: Some(saved.saved_at),
                    ..Default::default()
                },
                info: Some(info),
            },
            username: Some(saved.username.clone()),
            password_digest: None,
        });
        Ok(account)
    }

    pub async fn login_state(&self) -> LoginState {
        self.inner.lock().await.session.state
    }

    pub async fn account_name(&self) -> String {
        let inner = self.inner.lock().await;
        inner
            .session
            .info
            .as_ref()
            .and_then(|i| i.account_name.clone())
            .or_else(|| inner.username.clone())
            .unwrap_or_default()
    }

    pub async fn account_info(&self) -> Option<AccountInfo> {
        self.inner.lock().await.session.info.clone()
    }

    pub async fn dsid(&self) -> Result<String> {
        self.inner
            .lock()
            .await
            .session
            .data
            .dsid
            .clone()
            .ok_or_else(|| Error::State("not signed in: no dsid".into()))
    }

    pub async fn adsid(&self) -> String {
        self.inner.lock().await.session.data.adsid.clone().unwrap_or_default()
    }

    pub async fn service_token(&self, name: &str) -> Option<String> {
        let inner = self.inner.lock().await;
        if inner.session.state == LoginState::LoggedIn {
            inner.session.data.tokens.get(name).cloned()
        } else {
            None
        }
    }

    pub async fn service_token_names(&self) -> Vec<String> {
        self.inner.lock().await.session.data.tokens.keys().cloned().collect()
    }

    /// The login Anisette set, without a client info (each endpoint names its own daemon).
    pub async fn anisette_headers(&self) -> Result<BTreeMap<String, String>> {
        self.anisette.headers().await
    }

    /// `get_2fa_methods`: the trusted-device push when `au` offered it, then every trusted phone number.
    pub async fn second_factor_methods(&self) -> Result<Vec<SecondFactorMethod>> {
        let guard = self.inner.lock().await;
        self.require_state(&guard.session, &[LoginState::Require2fa])?;
        self.list_methods(&guard.session, true).await
    }

    pub async fn request_sms_code(&self, phone_number_id: i64) -> Result<()> {
        let guard = self.inner.lock().await;
        self.require_state(&guard.session, &[LoginState::Require2fa])?;
        let body = messages::sms_request_body(phone_number_id);
        self.two_factor_request(&guard.session, "PUT", &self.endpoints.sms_request, Some(body.as_bytes().to_vec()), &[]).await?;
        Ok(())
    }

    pub async fn submit_sms_code(&self, phone_number_id: i64, code: &str) -> Result<LoginResult> {
        let mut guard = self.inner.lock().await;
        self.require_state(&guard.session, &[LoginState::Require2fa])?;
        let body = messages::sms_submit_body(phone_number_id, &checked_code(code)?);
        self.two_factor_request(&guard.session, "POST", &self.endpoints.sms_submit, Some(body.as_bytes().to_vec()), &[]).await?;
        self.finish_second_factor(&mut guard).await
    }

    pub async fn request_trusted_device_code(&self) -> Result<()> {
        let guard = self.inner.lock().await;
        self.require_state(&guard.session, &[LoginState::Require2fa])?;
        self.two_factor_request(&guard.session, "GET", &self.endpoints.trusted_device_request, None, &plist_negotiation()).await?;
        Ok(())
    }

    pub async fn submit_trusted_device_code(&self, code: &str) -> Result<LoginResult> {
        let mut guard = self.inner.lock().await;
        self.require_state(&guard.session, &[LoginState::Require2fa])?;
        let mut extra = vec![("security-code".to_string(), checked_code(code)?)];
        extra.extend(plist_negotiation());
        let body = self
            .two_factor_request(&guard.session, "GET", &self.endpoints.trusted_device_submit, None, &extra)
            .await?;
        validate_reply_status(&body)?;
        self.finish_second_factor(&mut guard).await
    }

    /// `complete_login`: repeat the delegate exchange after it failed once authentication succeeded.
    pub async fn complete_login(&self) -> Result<LoginResult> {
        let mut guard = self.inner.lock().await;
        self.require_state(&guard.session, &[LoginState::Authenticated])?;
        let username = guard.username.clone().unwrap_or_default();
        let session = self.login_mobileme(&username, &guard.session).await?;
        guard.session = session;
        Ok(LoginResult::SignedIn)
    }

    /// Authenticate again and repeat the delegate exchange (for a service that answered 401). The live
    /// session is replaced only when both succeed.
    pub async fn refresh_session(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        self.require_state(&guard.session, &[LoginState::LoggedIn])?;
        let (username, digest) = self.credentials(&guard, "sign in again")?;
        let fresh = self.authenticate(&username, &digest).await?;
        if fresh.state != LoginState::Authenticated {
            return Err(Error::Authentication(
                "Apple asks for a second factor again. Sign in again.".into(),
            ));
        }
        let logged_in = self.login_mobileme(&username, &fresh).await?;
        guard.session = logged_in;
        Ok(())
    }

    /// A fresh PET (`request_pet`). Every call is a real SRP exchange; the live session is untouched.
    pub async fn request_pet(&self) -> Result<String> {
        let mut guard = self.inner.lock().await;
        self.require_state(&guard.session, &[LoginState::LoggedIn])?;
        let (username, digest) = self.credentials(&guard, "renew the PET")?;
        let fresh = self.authenticate(&username, &digest).await?;
        if fresh.state != LoginState::Authenticated {
            return Err(Error::Authentication(
                "Apple asked for a second factor to renew the PET, so none was issued. Sign in again."
                    .into(),
            ));
        }
        let pet = fresh
            .data
            .idms_pet
            .clone()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| Error::Backend("re-authentication succeeded but returned no PET".into()))?;
        if guard.session.data.adsid.is_none() && fresh.data.adsid.is_some() {
            guard.session.data.adsid = fresh.data.adsid.clone();
        }
        Ok(pet)
    }

    /// Signs in. The password buffer is zeroed; only its digest is kept, in memory.
    pub async fn login(
        &self,
        username: &str,
        password: &mut [u8],
        list_phone_numbers: bool,
    ) -> Result<LoginResult> {
        let digest = Zeroizing::new(crypto::password_digest(password));
        password.zeroize();
        let mut guard = self.inner.lock().await;
        self.require_state(&guard.session, &[LoginState::LoggedOut])?;
        guard.username = Some(username.to_string());
        guard.password_digest = Some(digest.clone());
        let result = async {
            let session = self.authenticate(username, &digest).await?;
            guard.session = session;
            if guard.session.state == LoginState::Require2fa {
                let methods = self.list_methods(&guard.session, list_phone_numbers).await?;
                return Ok(LoginResult::SecondFactorRequired(methods));
            }
            let logged_in = self.login_mobileme(username, &guard.session).await?;
            guard.session = logged_in;
            Ok(LoginResult::SignedIn)
        }
        .await;
        if result.is_err() && guard.session.state == LoginState::LoggedOut {
            guard.password_digest = None;
        }
        result
    }

    /// Holds the password (as its digest) for PET renewal and re-authentication of a restored session.
    pub async fn provide_password(&self, password: &mut [u8]) {
        let digest = Zeroizing::new(crypto::password_digest(password));
        password.zeroize();
        let mut guard = self.inner.lock().await;
        guard.password_digest = Some(digest);
    }

    pub async fn forget_password(&self) {
        self.inner.lock().await.password_digest = None;
    }

    pub async fn has_password(&self) -> bool {
        self.inner.lock().await.password_digest.is_some()
    }

    /// The signed-in state to persist. No password, no PET.
    pub async fn snapshot(&self) -> Result<SavedSession> {
        let guard = self.inner.lock().await;
        let s = &guard.session;
        if s.state != LoginState::LoggedIn {
            return Err(Error::State(format!("invalid login state: {:?}", s.state)));
        }
        let now = now_secs();
        Ok(SavedSession {
            username: guard.username.clone().unwrap_or_default(),
            local_user_uuid: self.device.local_user_uuid.clone(),
            device_id: self.device.device_id.clone(),
            cloud_kit_device_uuid: self.device.cloud_kit_device_uuid.clone(),
            account_name: s.info.as_ref().and_then(|i| i.account_name.clone()),
            first_name: s.info.as_ref().and_then(|i| i.first_name.clone()),
            last_name: s.info.as_ref().and_then(|i| i.last_name.clone()),
            dsid: s.data.dsid.clone().unwrap_or_default(),
            adsid: s.data.adsid.clone(),
            idms_hb: s.data.idms_hb.clone(),
            service_tokens: s.data.tokens.clone(),
            saved_at: s.data.obtained_at.unwrap_or(now),
        })
    }

    /// The device this account speaks as.
    pub fn device(&self) -> &LoginDevice {
        &self.device
    }

    /// The HTTP client (used by the report fetcher).
    pub fn http(&self) -> &Http {
        &self.http
    }

    // -- internals -------------------------------------------------------------------------------

    fn require_state(&self, session: &Session, allowed: &[LoginState]) -> Result<()> {
        if allowed.contains(&session.state) {
            Ok(())
        } else {
            Err(Error::State(format!(
                "invalid login state {:?}, expected one of {allowed:?}",
                session.state
            )))
        }
    }

    fn credentials(&self, inner: &Inner, for_what: &str) -> Result<(String, Zeroizing<[u8; 32]>)> {
        let username = inner
            .username
            .clone()
            .ok_or_else(|| Error::State("no username".into()))?;
        let digest = inner.password_digest.clone().ok_or_else(|| {
            Error::Authentication(format!(
                "the password is needed to {for_what}: this session was restored without it."
            ))
        })?;
        Ok((username, digest))
    }

    /// `_gsa_authenticate`: SRP init/complete, `spd`, and the second-factor verdict.
    async fn authenticate(&self, username: &str, digest: &[u8; 32]) -> Result<Session> {
        let mut srp = SrpClient::new(username, &(self.ephemeral)());
        let mut params: BTreeMap<String, Value> = BTreeMap::new();
        params.insert("A2k".into(), Value::Data(srp.public_a()));
        params.insert("u".into(), Value::String(username.into()));
        params.insert(
            "ps".into(),
            Value::Array(vec![Value::String(S2K.into()), Value::String(S2K_FO.into())]),
        );
        params.insert("o".into(), Value::String("init".into()));
        let r = self.gsa_request(&params).await?;
        let status = check_status(&r, GrandSlamStep::Init)?;
        let _ = status;
        let sp = r.get("sp").and_then(|v| v.as_str()).unwrap_or("");
        if sp != S2K && sp != S2K_FO {
            return Err(Error::Backend(format!(
                "this implementation only supports s2k and s2k_fo; the server chose {}",
                if sp.is_empty() { "nothing" } else { sp }
            )));
        }
        let salt = r
            .get("s")
            .and_then(|v| v.as_data())
            .ok_or_else(|| Error::Backend("the init reply has no salt".into()))?
            .to_vec();
        let server_b = r
            .get("B")
            .and_then(|v| v.as_data())
            .ok_or_else(|| Error::Backend("the init reply has no B".into()))?
            .to_vec();
        let iterations = r
            .get("i")
            .and_then(|v| v.as_i64())
            .filter(|i| *i > 0)
            .ok_or_else(|| Error::Backend("the init reply has no iteration count".into()))?
            as u32;
        let c = r
            .get("c")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Backend("the init reply has no continuation".into()))?
            .to_string();

        let mut p = crypto::derive_password(digest, &salt, iterations, sp)?;
        let m1 = srp.process_challenge(&salt, &server_b, &p);
        p.zeroize();
        let m1 = m1.ok_or_else(|| Error::Backend("failed to process challenge".into()))?;

        let mut complete: BTreeMap<String, Value> = BTreeMap::new();
        complete.insert("c".into(), Value::String(c));
        complete.insert("M1".into(), Value::Data(m1));
        complete.insert("u".into(), Value::String(username.into()));
        complete.insert("o".into(), Value::String("complete".into()));
        let r2 = self.gsa_request(&complete).await?;
        let status = check_status(&r2, GrandSlamStep::Complete)?;
        let m2 = r2.get("M2").and_then(|v| v.as_data());
        if !srp.verify_session(m2) {
            return Err(Error::Backend("failed to verify session: Apple's proof did not match".into()));
        }
        let session_key = *srp
            .session_key()
            .ok_or_else(|| Error::Backend("failed to verify session: no key".into()))?;
        let spd_raw = r2
            .get("spd")
            .and_then(|v| v.as_data())
            .ok_or_else(|| Error::Backend("the complete reply has no spd".into()))?;
        let plaintext = crypto::decrypt_spd(&session_key, spd_raw)?;
        let spd = plist::parse_dict(&crypto::with_plist_prolog(&plaintext))?;

        let mut au = status.get("au").and_then(|v| v.as_str()).map(str::to_string);
        if au.is_none() && status.get("hsc").and_then(|v| v.as_i64()) == Some(409) {
            au = Some(TRUSTED_DEVICE_AU.to_string());
        }
        let str_at = |k: &str| spd.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let info = AccountInfo {
            account_name: str_at("acname"),
            first_name: str_at("fn"),
            last_name: str_at("ln"),
            trusted_device_2fa: au.as_deref() == Some(TRUSTED_DEVICE_AU),
        };
        let adsid = str_at("adsid")
            .ok_or_else(|| Error::Backend("the session payload has no adsid".into()))?;

        match au.as_deref() {
            Some("secondaryAuth") | Some(TRUSTED_DEVICE_AU) => {
                let idms = str_at("GsIdmsToken")
                    .ok_or_else(|| Error::Backend("the session payload has no GsIdmsToken".into()))?;
                Ok(Session {
                    state: LoginState::Require2fa,
                    data: StateData {
                        adsid: Some(adsid),
                        idms_token: Some(idms),
                        ..Default::default()
                    },
                    info: Some(info),
                })
            }
            None => {
                let t = spd.get("t").and_then(|v| v.as_dict());
                let token = |name: &str| {
                    t.and_then(|t| t.get(name))
                        .and_then(|v| v.get("token"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                };
                Ok(Session {
                    state: LoginState::Authenticated,
                    data: StateData {
                        adsid: Some(adsid),
                        idms_pet: Some(token("com.apple.gs.idms.pet")),
                        idms_hb: Some(token("com.apple.gs.idms.hb")),
                        ..Default::default()
                    },
                    info: Some(info),
                })
            }
            Some(other) => Err(Error::Backend(format!("unknown auth value: {other}"))),
        }
    }

    /// `_gsa_request` with the auto-resync: a 434 carrying a SIM is answered once with fresh Anisette.
    async fn gsa_request(&self, parameters: &BTreeMap<String, Value>) -> Result<BTreeMap<String, Value>> {
        let first = self.gsa_exchange(parameters).await?;
        let Some(sim) = first.sim.clone() else {
            return Ok(first.response);
        };
        if !first.wants_resync {
            return Ok(first.response);
        }
        self.anisette.resync(&sim).await?;
        Ok(self.gsa_exchange(parameters).await?.response)
    }

    async fn gsa_exchange(&self, parameters: &BTreeMap<String, Value>) -> Result<GsaReply> {
        let anisette = self.anisette.headers().await?;
        let body = messages::gsa_body(parameters, &messages::cpd(&anisette));
        let headers = messages::gsa_headers(&self.device.identity);
        let reply = self.send("POST", &self.endpoints.gsa, &headers, Some(body), None, None).await?;
        let header_sim = reply.header("X-Apple-I-MD-DATA").map(str::to_string);
        if reply.code == 434 && header_sim.is_some() {
            return Ok(GsaReply {
                response: BTreeMap::new(),
                wants_resync: true,
                sim: header_sim,
            });
        }
        if !(200..300).contains(&reply.code) {
            if reply.code == 434 {
                if let Some(response) = parse_gsa(&reply.body) {
                    if let Some(sim) = sim_of(&response) {
                        return Ok(GsaReply { response, wants_resync: true, sim: Some(sim) });
                    }
                }
            }
            return Err(self.http_failure(&reply, "The Grand Slam request"));
        }
        let response = parse_gsa(&reply.body)
            .ok_or_else(|| Error::Backend("the Grand Slam reply is not a property list with a Response".into()))?;
        let sim = sim_of(&response).or(header_sim);
        let wants_resync = response
            .get("Status")
            .and_then(|s| s.get("hsc"))
            .and_then(|v| v.as_i64())
            == Some(434)
            && sim.is_some();
        Ok(GsaReply { response, wants_resync, sim })
    }

    /// `_login_mobileme`: exchange the PET of an AUTHENTICATED session for the service tokens.
    async fn login_mobileme(&self, username: &str, from: &Session) -> Result<Session> {
        let adsid = from
            .data
            .adsid
            .clone()
            .ok_or_else(|| Error::Backend("no adsid to log into the delegate with".into()))?;
        let pet = from.data.idms_pet.clone().unwrap_or_default();
        let anisette = self.anisette.headers().await?;
        let headers = messages::login_delegates_headers(&self.device.identity, &adsid, &anisette);
        let body = messages::login_delegates_body(username, &pet, &self.device.local_user_uuid);
        let reply = self
            .send(
                "POST",
                &self.endpoints.login_delegates,
                &headers,
                Some(body),
                Some("application/octet-stream"),
                Some((username.to_string(), pet.clone())),
            )
            .await?;
        if reply.code == 429 {
            return Err(self.http_failure(&reply, "The delegate request"));
        }
        let plist = match plist::parse_dict(&reply.body) {
            Ok(p) => p,
            Err(_) => {
                if !(200..300).contains(&reply.code) {
                    return Err(self.http_failure(&reply, "The delegate request"));
                }
                return Err(Error::Backend("the delegate reply is not a property list".into()));
            }
        };
        let localized_error = plist.get("localizedError").and_then(|v| v.as_str());
        let status = plist.get("status");
        let failed = localized_error.is_some()
            || status.is_some_and(|s| s.as_i64() != Some(0));
        let mobileme = plist.get("delegates").and_then(|d| d.get("com.apple.mobileme"));
        let service_data = mobileme.and_then(|m| m.get("service-data")).and_then(|s| s.as_dict());
        if failed || service_data.is_none() {
            return Err(delegate_error(
                reply.code,
                localized_error,
                plist.get("description").and_then(|v| v.as_str()),
                if failed { status } else { mobileme.and_then(|m| m.get("status")) },
                mobileme.and_then(|m| m.get("status-message")).and_then(|v| v.as_str()),
            ));
        }
        let service_data = service_data.expect("checked above");
        let dsid = plist
            .get("dsid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Backend("the delegate reply has no dsid".into()))?
            .to_string();
        let mut tokens = BTreeMap::new();
        if let Some(t) = service_data.get("tokens").and_then(|v| v.as_dict()) {
            for (k, v) in t {
                if let Some(s) = v.as_str() {
                    tokens.insert(k.clone(), s.to_string());
                }
            }
        }
        Ok(Session {
            state: LoginState::LoggedIn,
            data: StateData {
                adsid: Some(adsid),
                idms_hb: from.data.idms_hb.clone(),
                dsid: Some(dsid),
                tokens,
                obtained_at: Some(now_secs()),
                ..Default::default()
            },
            info: from.info.clone(),
        })
    }

    async fn list_methods(&self, session: &Session, list_phone_numbers: bool) -> Result<Vec<SecondFactorMethod>> {
        let Some(info) = session.info.as_ref() else {
            return Ok(Vec::new());
        };
        let mut methods = Vec::new();
        if info.trusted_device_2fa {
            methods.push(SecondFactorMethod::TrustedDevice);
        }
        if !list_phone_numbers {
            return Ok(methods);
        }
        match self
            .two_factor_request(session, "GET", &self.endpoints.two_factor_methods, None, &[])
            .await
        {
            Ok(body) => match messages::extract_phone_numbers(&body) {
                Ok(mut phones) => methods.append(&mut phones),
                Err(_) => { /* no boot_args element: carry on with what we have */ }
            },
            Err(e @ Error::Throttled(_)) => return Err(e),
            Err(_) if !methods.is_empty() => { /* the push needs no phone number */ }
            Err(e) => return Err(e),
        }
        Ok(methods)
    }

    async fn two_factor_request(
        &self,
        session: &Session,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
        extra: &[(String, String)],
    ) -> Result<String> {
        let adsid = session
            .data
            .adsid
            .clone()
            .ok_or_else(|| Error::Backend("no adsid for the two-factor request".into()))?;
        let idms = session
            .data
            .idms_token
            .clone()
            .ok_or_else(|| Error::Backend("no identity token for the two-factor request".into()))?;
        let anisette = self.anisette.headers().await?;
        let headers = messages::two_factor_headers(
            &self.device.identity,
            &crypto::identity_token(&adsid, &idms),
            &anisette,
            extra,
        );
        let reply = self.send(method, url, &headers, body, Some("application/json"), None).await?;
        if !(200..300).contains(&reply.code) {
            return Err(self.http_failure(&reply, "The two-factor request"));
        }
        Ok(reply.text())
    }

    async fn finish_second_factor(&self, guard: &mut tokio::sync::MutexGuard<'_, Inner>) -> Result<LoginResult> {
        let (username, digest) = self.credentials(guard, "sign in again")?;
        let fresh = self.authenticate(&username, &digest).await?;
        if fresh.state != LoginState::Authenticated {
            if fresh.state == LoginState::Require2fa {
                guard.session = fresh;
            }
            return Err(Error::Authentication(
                "Apple still asks for a second factor after the code was submitted; the code was probably not accepted."
                    .into(),
            ));
        }
        guard.session = fresh.clone();
        let logged_in = self.login_mobileme(&username, &fresh).await?;
        guard.session = logged_in;
        Ok(LoginResult::SignedIn)
    }

    async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
        basic_auth: Option<(String, String)>,
    ) -> Result<Reply> {
        let mut headers = headers.to_vec();
        if let Some(ct) = content_type {
            headers.push(("Content-Type".into(), ct.into()));
        }
        let method = match method {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            other => return Err(Error::State(format!("unsupported HTTP method {other}"))),
        };
        let basic = basic_auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
        self.http.send(method, url, &headers, body, basic).await.map(Reply::from)
    }

    fn http_failure(&self, reply: &Reply, what: &str) -> Error {
        if reply.code == 429 {
            return Error::Throttled(
                "Apple answered HTTP 429: usually an inconsistent request or connection state \
                 (for example a reused connection), not a rate limit; retrying is safe."
                    .into(),
            );
        }
        let wait = reply
            .header("Retry-After")
            .and_then(retry_after_seconds)
            .map(|s| format!(" Apple asked to wait {s} s before trying again."))
            .unwrap_or_default();
        Error::Rejected {
            http: Some(reply.code),
            ec: None,
            message: format!("{what} was refused with HTTP {}.{wait}", reply.code),
        }
    }
}

struct GsaReply {
    response: BTreeMap<String, Value>,
    wants_resync: bool,
    sim: Option<String>,
}

struct Reply {
    code: u16,
    body: Vec<u8>,
    headers: reqwest::header::HeaderMap,
    #[allow(dead_code)]
    host: String,
}

impl Reply {
    fn from(r: crate::http::Response) -> Reply {
        Reply { code: r.status, body: r.body, headers: r.headers, host: r.host }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn parse_gsa(body: &[u8]) -> Option<BTreeMap<String, Value>> {
    let plist = plist::parse_dict(body).ok()?;
    plist.get("Response").and_then(|v| v.as_dict()).cloned()
}

fn sim_of(response: &BTreeMap<String, Value>) -> Option<String> {
    response
        .get("Status")
        .and_then(|s| s.get("X-Apple-I-MD-DATA"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn check_status(
    response: &BTreeMap<String, Value>,
    step: GrandSlamStep,
) -> Result<BTreeMap<String, Value>> {
    let status = response
        .get("Status")
        .and_then(|v| v.as_dict())
        .ok_or_else(|| {
            Error::Backend(format!(
                "{}: the reply has no Status",
                match step {
                    GrandSlamStep::Init => "Email verification failed",
                    GrandSlamStep::Complete => "Password authentication failed",
                }
            ))
        })?;
    let ec = status.get("ec").and_then(|v| v.as_i64());
    if ec == Some(0) {
        return Ok(status.clone());
    }
    Err(Error::GrandSlamRefused {
        step,
        ec,
        em: status.get("em").and_then(|v| v.as_str()).map(str::to_string),
    })
}

fn delegate_error(
    http: u16,
    localized_error: Option<&str>,
    description: Option<&str>,
    status: Option<&Value>,
    status_message: Option<&str>,
) -> Error {
    let mut said: Vec<String> = Vec::new();
    if let Some(v) = localized_error {
        said.push(format!("localizedError={v}"));
    }
    if let Some(v) = description {
        said.push(format!("description={v}"));
    }
    if let Some(v) = status {
        said.push(format!("status={}", v.as_i64().map(|i| i.to_string()).unwrap_or_default()));
    }
    if let Some(v) = status_message {
        said.push(format!("status-message={v}"));
    }
    let said = if said.is_empty() { "nothing about why".to_string() } else { said.join(", ") };
    if localized_error == Some("UNAUTHORIZED") {
        return Error::Authentication(format!(
            "The com.apple.mobileme delegate refused the credential ({said}); usually an expired PET. Sign in again."
        ));
    }
    let remedy = if localized_error.is_some() {
        "If the account has unaccepted iCloud terms, accepting them is the remedy."
    } else {
        "No localizedError came back, so this is not the terms channel: the delegate refused the account itself (reported for Apple IDs never used on an Apple device)."
    };
    Error::Rejected {
        http: Some(http),
        ec: status.and_then(|v| v.as_i64()),
        message: format!("The com.apple.mobileme delegate request failed, reporting {said}. {remedy}"),
    }
}

fn validate_reply_status(body: &str) -> Result<()> {
    let Ok(plist) = plist::parse_dict(body.as_bytes()) else {
        return Ok(());
    };
    let response = plist.get("Response").and_then(|v| v.as_dict()).unwrap_or(&plist);
    let status = response
        .get("Status")
        .and_then(|v| v.as_dict())
        .unwrap_or(response);
    let Some(ec) = status.get("ec").and_then(|v| v.as_i64()) else {
        return Ok(());
    };
    if ec != 0 {
        let em = status.get("em").and_then(|v| v.as_str()).unwrap_or("");
        return Err(Error::Rejected {
            http: Some(200),
            ec: Some(ec),
            message: format!("The code was not accepted: {em} (ec {ec})"),
        });
    }
    Ok(())
}

fn plist_negotiation() -> Vec<(String, String)> {
    vec![
        ("Content-Type".into(), "text/x-xml-plist".into()),
        ("Accept".into(), "text/x-xml-plist".into()),
    ]
}

fn checked_code(code: &str) -> Result<String> {
    let c = code.trim();
    if c.is_empty() || c.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(Error::State("not a verification code".into()));
    }
    Ok(c.to_string())
}

fn retry_after_seconds(raw: &str) -> Option<i64> {
    let v = raw.trim();
    if v.is_empty() {
        return None;
    }
    if v.chars().all(|c| c.is_ascii_digit()) {
        return v.parse().ok();
    }
    let at = httpdate::parse_http_date(v).ok()?;
    let at = at.duration_since(std::time::UNIX_EPOCH).ok()?;
    let now = now_secs();
    Some((at.as_secs() as i64 - now).max(0))
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod grand_slam_status_tests {
    use super::*;

    fn response(ec: Option<i64>, em: Option<&str>) -> BTreeMap<String, Value> {
        let mut status = BTreeMap::new();
        if let Some(ec) = ec {
            status.insert("ec".into(), Value::Integer(ec));
        }
        if let Some(em) = em {
            status.insert("em".into(), Value::String(em.into()));
        }
        BTreeMap::from([("Status".into(), Value::Dict(status))])
    }

    #[test]
    fn init_refusal_keeps_apple_fields_and_marks_before_password() {
        let error = check_status(
            &response(
                Some(-22421),
                Some("This action cannot be completed at this time."),
            ),
            GrandSlamStep::Init,
        )
        .unwrap_err();

        assert_eq!(
            error,
            Error::GrandSlamRefused {
                step: GrandSlamStep::Init,
                ec: Some(-22421),
                em: Some("This action cannot be completed at this time.".into()),
            }
        );
        assert!(GrandSlamStep::Init.before_password());
        assert!(error.to_string().contains("ec=-22421"));
    }

    #[test]
    fn complete_refusal_keeps_the_phase_even_for_bad_credentials_code() {
        let error = check_status(
            &response(Some(-22406), Some("Your Apple ID or password was incorrect.")),
            GrandSlamStep::Complete,
        )
        .unwrap_err();

        assert_eq!(
            error,
            Error::GrandSlamRefused {
                step: GrandSlamStep::Complete,
                ec: Some(-22406),
                em: Some("Your Apple ID or password was incorrect.".into()),
            }
        );
        assert!(!GrandSlamStep::Complete.before_password());
        assert!(error.to_string().contains("machine it no longer accepts"));
    }

    #[test]
    fn bad_credentials_code_at_init_is_not_a_password_verdict() {
        let error = check_status(
            &response(Some(-22406), Some("Your Apple ID or password was incorrect.")),
            GrandSlamStep::Init,
        )
        .unwrap_err();

        assert_eq!(
            error,
            Error::GrandSlamRefused {
                step: GrandSlamStep::Init,
                ec: Some(-22406),
                em: Some("Your Apple ID or password was incorrect.".into()),
            }
        );
        assert!(GrandSlamStep::Init.before_password());
        assert!(error.to_string().contains("password was not sent"));
    }

    #[test]
    fn missing_em_or_ec_does_not_hide_a_refusal() {
        let error = check_status(&response(Some(-1), None), GrandSlamStep::Init).unwrap_err();
        assert_eq!(
            error,
            Error::GrandSlamRefused {
                step: GrandSlamStep::Init,
                ec: Some(-1),
                em: None,
            }
        );
        assert!(error.to_string().contains("no message"));

        let missing_code = check_status(&response(None, None), GrandSlamStep::Complete).unwrap_err();
        assert_eq!(
            missing_code,
            Error::GrandSlamRefused {
                step: GrandSlamStep::Complete,
                ec: None,
                em: None,
            }
        );
    }
}
