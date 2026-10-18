//! A C ABI (and, behind the `jni` feature, JNI entry points) over `apple-core`.
//!
//! The host registers two synchronous callbacks at open time so the library can ask for the machine's
//! Anisette headers and for a resync answer; the host owns the CoreADI machine and its store. All
//! other state travels as a JSON blob the host persists (Keystore-encrypted): see
//! [`apple_core::session`].
//!
//! ```c
//! char* on_headers(void* user);                  // JSON object of headers, host frees
//! int   on_resync(void* user, const char* sim);   // 0 on success
//! openfinder_handle* h = openfinder_open(config_json, on_headers, on_resync, user);
//! char* r = openfinder_call(h, "{\"cmd\":\"login\",...}");  // openfinder_string_free(r)
//! openfinder_close(h);
//! ```
//!
//! [`openfinder_open_machine`] is the mode where the library owns the CoreADI machine itself (the
//! `.so` contains `adi-core`), so no Anisette callbacks are needed.

#[cfg(feature = "jni")]
mod jni;

use std::collections::BTreeMap;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;

use apple_core::anisette::{provision_new_machine, CoreAdiAnisette, MachineFile, DS_ID};
use apple_core::error::{Error, Result};
use apple_core::http::Http;
use apple_core::login::device::{LoginEndpoints, LoginResult, LoginState, SecondFactorMethod};
use apple_core::keychain::session::KeychainSession;
use apple_core::login::{AnisetteSource, BoxFuture};
use apple_core::reports::client::{AccountContext, ReportClient};
use apple_core::reports::keys::AccessoryKeys;
use apple_core::session::{OpenFinderSession, LoginConfig};
use base64::Engine as _;
use serde_json::{json, Value};
use zeroize::Zeroize;

/// Host callback: returns a NUL-terminated JSON object of Anisette headers (the host frees it), or
/// NULL on failure.
pub type OpenfinderHeadersFn = extern "C" fn(user: *mut c_void) -> *mut c_char;

/// Host callback: answers a resync SIM (base64). Returns 0 on success.
pub type OpenfinderResyncFn = extern "C" fn(user: *mut c_void, sim_b64: *const c_char) -> c_int;

/// An [`AnisetteSource`] that calls back into the host. The host guarantees the callbacks are
/// thread-safe and that `user` outlives the handle.
struct CallbackAnisette {
    headers_fn: OpenfinderHeadersFn,
    resync_fn: Option<OpenfinderResyncFn>,
    user: *mut c_void,
}

unsafe impl Send for CallbackAnisette {}
unsafe impl Sync for CallbackAnisette {}

impl AnisetteSource for CallbackAnisette {
    fn headers(&self) -> BoxFuture<'_, Result<BTreeMap<String, String>>> {
        let result = (|| {
            let raw = (self.headers_fn)(self.user);
            if raw.is_null() {
                return Err(Error::Backend("the host returned no Anisette headers".into()));
            }
            let text = unsafe { CStr::from_ptr(raw) }
                .to_str()
                .map_err(|_| Error::Backend("the Anisette headers are not UTF-8".into()))?;
            let value: Value = serde_json::from_str(text)
                .map_err(|_| Error::Backend("the Anisette headers are not JSON".into()))?;
            let mut out = BTreeMap::new();
            if let Some(obj) = value.as_object() {
                for (k, v) in obj {
                    if let Some(s) = v.as_str() {
                        out.insert(k.clone(), s.to_string());
                    }
                }
            }
            if out.is_empty() {
                return Err(Error::Backend("the host returned empty Anisette headers".into()));
            }
            Ok(out)
        })();
        Box::pin(async move { result })
    }

    fn resync<'a>(&'a self, sim: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let Some(f) = self.resync_fn else {
                return Err(Error::Backend("the host registered no resync callback".into()));
            };
            let sim = CString::new(sim).map_err(|_| Error::Backend("bad SIM".into()))?;
            let rc = f(self.user, sim.as_ptr());
            if rc == 0 {
                Ok(())
            } else {
                Err(Error::Rejected {
                    http: Some(200),
                    ec: None,
                    message: "the host refused the machine's resync".into(),
                })
            }
        })
    }
}

pub struct Handle {
    session: OpenFinderSession,
    runtime: tokio::runtime::Runtime,
    machine: Option<Arc<CoreAdiAnisette>>,
}

fn error_json(e: &Error) -> Value {
    let kind = match e {
        Error::Network(_) => "network",
        Error::Authentication(_) => "authentication",
        Error::GrandSlamRefused { .. } => "grand_slam_refused",
        Error::Rejected { .. } => "rejected",
        Error::Throttled(_) => "throttled",
        Error::Backend(_) => "backend",
        Error::ReportsUnavailable(_) => "reports_unavailable",
        Error::NotImplemented(_) => "not_implemented",
        Error::State(_) => "state",
    };
    let (http, ec) = match e {
        Error::Rejected { http, ec, .. } => (*http, *ec),
        _ => (None, None),
    };
    let mut v = json!({"kind": kind, "message": e.to_string()});
    if let Some(http) = http {
        v["http"] = json!(http);
    }
    if let Some(ec) = ec {
        v["ec"] = json!(ec);
    }
    if let Error::GrandSlamRefused { step, ec, em } = e {
        v["step"] = json!(step.as_str());
        v["before_password"] = json!(step.before_password());
        v["ec"] = json!(ec);
        v["em"] = json!(em);
    }
    v
}

#[cfg(test)]
mod error_json_tests {
    use super::*;

    #[test]
    fn grand_slam_refusal_exports_its_step_and_optional_status() {
        let value = error_json(&Error::GrandSlamRefused {
            step: apple_core::GrandSlamStep::Init,
            ec: Some(-22421),
            em: None,
        });

        assert_eq!(value["kind"], "grand_slam_refused");
        assert_eq!(value["step"], "init");
        assert_eq!(value["before_password"], true);
        assert_eq!(value["ec"], -22421);
        assert!(value["em"].is_null());
    }
}

fn ok_json() -> Value {
    json!({"ok": true})
}

fn internal_error(message: impl Into<String>) -> *mut c_char {
    into_c_string(json!({"ok": false, "error": {"kind": "backend", "message": message.into()}}).to_string())
}

fn into_c_string(s: String) -> *mut c_char {
    CString::new(s).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

/// Loads the library and registers the host's Anisette callbacks. Returns NULL on a bad config.
///
/// # Safety
/// `config_json` must be a valid NUL-terminated UTF-8 string; `user` must stay valid until close.
#[no_mangle]
pub unsafe extern "C" fn openfinder_open(
    config_json: *const c_char,
    headers_fn: Option<OpenfinderHeadersFn>,
    resync_fn: Option<OpenfinderResyncFn>,
    user: *mut c_void,
) -> *mut Handle {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(headers_fn) = headers_fn else {
            return Err(Error::Backend("no Anisette headers callback".into()));
        };
        if config_json.is_null() {
            return Err(Error::State("no config".into()));
        }
        let text = CStr::from_ptr(config_json)
            .to_str()
            .map_err(|_| Error::State("the config is not UTF-8".into()))?;
        let config: Value =
            serde_json::from_str(text).map_err(|_| Error::State("the config is not JSON".into()))?;
        let s = |k: &str| config.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let host_uuid = s("host_uuid_b64")
            .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
            .unwrap_or_default();
        let login_config = LoginConfig {
            local_user_uuid: s("uid").ok_or_else(|| Error::State("config lacks uid".into()))?,
            device_id: s("devid").ok_or_else(|| Error::State("config lacks devid".into()))?,
            serial: s("serial"),
            client_info: s("client_info")
                .ok_or_else(|| Error::State("config lacks client_info".into()))?,
            host_uuid,
        };
        let anisette = Arc::new(CallbackAnisette { headers_fn, resync_fn, user });
        let timeout = config
            .get("timeout_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(30);
        let http = Http::new(Duration::from_secs(timeout))?;
        let endpoints = match s("origin") {
            Some(origin) => LoginEndpoints::under(&origin, Default::default()),
            None => LoginEndpoints::default(),
        };
        let session = OpenFinderSession::new(login_config, anisette, endpoints, http)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .map_err(|e| Error::Backend(format!("runtime: {e}")))?;
        Ok::<Handle, Error>(Handle { session, runtime, machine: None })
    }));
    match result {
        Ok(Ok(handle)) => Box::into_raw(Box::new(handle)),
        _ => std::ptr::null_mut(),
    }
}

/// Opens a session that owns the CoreADI machine itself: the image runs in this `.so`, and the
/// machine file (host UUID + identity + store) is the credential. The host persists the store with the
/// `export_store` command after any call that can change it.
///
/// # Safety
/// `machine_json` must be a valid NUL-terminated UTF-8 string; `image` must point to `image_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn openfinder_open_machine(
    machine_json: *const c_char,
    image: *const u8,
    image_len: usize,
) -> *mut Handle {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if machine_json.is_null() || image.is_null() || image_len == 0 {
            return Err(Error::State("no machine file or CoreADI image".into()));
        }
        let text = CStr::from_ptr(machine_json)
            .to_str()
            .map_err(|_| Error::State("the machine file is not UTF-8".into()))?;
        let machine = MachineFile::parse(text)?;
        // The host's timezone/locale are not part of the provisioned machine; the host passes them
        // beside it (the validated Python sent the host's, per BaseAnisetteProvider).
        let host = serde_json::from_str::<Value>(text).ok();
        let host_str = |k: &str| host.as_ref().and_then(|v| v.get(k)).and_then(|v| v.as_str()).map(str::to_string);
        let machine_bytes = std::slice::from_raw_parts(image, image_len).to_vec();
        let http = Http::new(Duration::from_secs(30))?;
        let mut anisette = CoreAdiAnisette::new(&machine_bytes, &machine, http.clone())?;
        if let (Some(timezone), Some(locale)) = (host_str("timezone"), host_str("locale")) {
            anisette = anisette.with_host_locale(timezone, locale);
        }
        let anisette = Arc::new(anisette);
        let config = machine.login_config()?;
        let session = match host_str("state") {
            Some(state) => OpenFinderSession::restore(&state, config, anisette.clone(), LoginEndpoints::default(), http)?,
            None => OpenFinderSession::new(config, anisette.clone(), LoginEndpoints::default(), http)?,
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .map_err(|e| Error::Backend(format!("runtime: {e}")))?;
        Ok::<Handle, Error>(Handle { session, runtime, machine: Some(anisette) })
    }));
    match result {
        Ok(Ok(handle)) => Box::into_raw(Box::new(handle)),
        _ => std::ptr::null_mut(),
    }
}

/// Runs one command. The returned string is owned by the library; free it with [`openfinder_string_free`].
///
/// # Safety
/// `handle` must come from `openfinder_open`; `request_json` a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn openfinder_call(handle: *mut Handle, request_json: *const c_char) -> *mut c_char {
    if handle.is_null() || request_json.is_null() {
        return internal_error("null handle or request");
    }
    let request = match CStr::from_ptr(request_json).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return internal_error("the request is not UTF-8"),
    };
    let h = &*handle;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        h.runtime.block_on(async {
            let mut response = dispatch(h, &request).await?;
            // Commands that talk to Apple advance the machine store and may change the session: hand both back.
            let cmd = serde_json::from_str::<Value>(&request).ok()
                .and_then(|v| v.get("cmd").and_then(|c| c.as_str()).map(str::to_string)).unwrap_or_default();
            if response.get("state").is_none()
                && matches!(cmd.as_str(), "login" | "submit_sms" | "submit_trusted_device" | "request_sms"
                    | "request_trusted_device" | "refresh" | "request_pet" | "provision")
            {
                response = with_state(h, response).await;
            }
            Ok::<Value, Error>(response)
        })
    }));
    match outcome {
        Ok(Ok(response)) => into_c_string(response.to_string()),
        Ok(Err(e)) => into_c_string(json!({"ok": false, "error": error_json(&e)}).to_string()),
        Err(_) => internal_error("internal panic"),
    }
}

async fn dispatch(handle: &Handle, request: &str) -> Result<Value> {
    let session = &handle.session;
    let req: Value = serde_json::from_str(request).map_err(|_| Error::State("the request is not JSON".into()))?;
    let cmd = req.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
    match cmd {
        "login" => {
            let username = string_field(&req, "username")?;
            let mut password = password_field(&req)?;
            let list = req.get("list_phone_numbers").and_then(|v| v.as_bool()).unwrap_or(true);
            let result = session.login(&username, &mut password, list).await;
            password.zeroize();
            login_result_json(result?)
        }
        "2fa_methods" => {
            let methods = session.second_factor_methods().await?;
            Ok(json!({"ok": true, "methods": methods_json(&methods)}))
        }
        "request_sms" => {
            let id = req.get("id").and_then(|v| v.as_i64()).ok_or_else(|| Error::State("missing id".into()))?;
            session.request_sms_code(id).await?;
            Ok(ok_json())
        }
        "submit_sms" => {
            let id = req.get("id").and_then(|v| v.as_i64()).ok_or_else(|| Error::State("missing id".into()))?;
            let code = string_field(&req, "code")?;
            login_result_json(session.submit_sms_code(id, &code).await?)
        }
        "request_trusted_device" => {
            session.request_trusted_device_code().await?;
            Ok(ok_json())
        }
        "submit_trusted_device" => {
            let code = string_field(&req, "code")?;
            login_result_json(session.submit_trusted_device_code(&code).await?)
        }
        "request_pet" => {
            let pet = session.request_pet().await?;
            Ok(json!({"ok": true, "pet": pet}))
        }
        "refresh" => {
            session.refresh_session().await?;
            Ok(json!({"ok": true, "state_changed": true}))
        }
        "provide_password" => {
            let mut password = password_field(&req)?;
            session.provide_password(&mut password).await;
            password.zeroize();
            Ok(ok_json())
        }
        "save_state" => {
            let state = session.save_state().await?;
            Ok(json!({"ok": true, "state": state}))
        }
        "status" => Ok(json!({
            "ok": true,
            "login_state": login_state_name(session.login_state().await),
            "machine": handle.machine.is_some(),
            "has_password": session.account().has_password().await,
        })),
        "provision" => {
            let machine = handle
                .machine
                .as_ref()
                .ok_or_else(|| Error::State("this handle was opened without a CoreADI machine".into()))?;
            let routing = provision_new_machine(machine, DS_ID).await?;
            Ok(json!({"ok": true, "state_changed": true, "routing": routing}))
        }
        "export_store" => {
            let machine = handle
                .machine
                .as_ref()
                .ok_or_else(|| Error::State("this handle was opened without a CoreADI machine".into()))?;
            let store = machine.export_store()?;
            Ok(json!({"ok": true, "store_export_b64": base64::engine::general_purpose::STANDARD.encode(store)}))
        }
        "import_store" => {
            let machine = handle
                .machine
                .as_ref()
                .ok_or_else(|| Error::State("this handle was opened without a CoreADI machine".into()))?;
            let b64 = string_field(&req, "store_export_b64")?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|_| Error::State("store_export_b64 is not base64".into()))?;
            machine.import_store(&bytes)?;
            Ok(json!({"ok": true, "state_changed": true}))
        }
        "fetch_reports" => {
            let entries = req.get("accessories").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let max: usize = req.get("max_requests").and_then(|v| v.as_u64()).unwrap_or(6) as usize;
            let client = ReportClient::new(session.account() as &dyn AccountContext).with_max_requests(Some(max));
            let mut out = Vec::new();
            for entry in &entries {
                let accessory = AccessoryKeys::from_json(entry).map_err(|e| Error::State(e.to_string()))?;
                let result = client.fetch_location_history(&accessory, true).await?;
                let reports: Vec<Value> = result
                    .reports
                    .iter()
                    .map(|r| json!({
                        "lat": r.latitude, "lon": r.longitude,
                        "observed_at": r.observed_at.unix_timestamp(),
                        "accuracy": r.horizontal_accuracy_meters,
                    }))
                    .collect();
                out.push(json!({
                    "id": accessory.id(), "reports": reports, "requests": result.requests,
                    "undecryptable": result.undecryptable, "invalid": result.invalid,
                    "unknown_key": result.unknown_key, "empty_response": result.empty_response,
                    "accessory": accessory.to_json(),
                }));
            }
            Ok(with_state(handle, json!({"ok": true, "results": out})).await)
        }
        "recovery_options" => {
            if let Some(b64) = req.get("password_b64").and_then(|v| v.as_str()) {
                let mut password = base64::engine::general_purpose::STANDARD
                    .decode(b64).map_err(|_| Error::State("the password is not base64".into()))?;
                session.provide_password(&mut password).await;
                password.zeroize();
            }
            let keychain = KeychainSession::open(session.account_arc()).await?;
            let options = keychain.recovery_options().await?;
            let records: Vec<Value> = options.recoverable.iter().enumerate()
                .map(|(i, r)| json!({"index": i, "description": r.describe(), "name": r.device_name, "model": r.device_model}))
                .collect();
            Ok(with_state(handle, json!({"ok": true, "records": records})).await)
        }
        // Recovers the PCS keys with ONE passcode guess (never retried), reads the BeaconStore and returns the
        // owner's accessories. The keys exist only inside this call.
        "discover" => {
            let index = req.get("index").and_then(|v| v.as_u64()).ok_or_else(|| Error::State("missing index".into()))? as usize;
            let b64 = string_field(&req, "passcode_b64")?;
            let mut passcode = base64::engine::general_purpose::STANDARD
                .decode(b64).map_err(|_| Error::State("the passcode is not base64".into()))?;
            let pass_str = String::from_utf8(passcode.clone()).map_err(|_| Error::State("the passcode is not UTF-8".into()));
            passcode.zeroize();
            let mut pass_str = pass_str?;
            if let Some(b64) = req.get("password_b64").and_then(|v| v.as_str()) {
                let mut password = base64::engine::general_purpose::STANDARD
                    .decode(b64).map_err(|_| Error::State("the password is not base64".into()))?;
                session.provide_password(&mut password).await;
                password.zeroize();
            }
            let keychain = KeychainSession::open(session.account_arc()).await?;
            let options = keychain.recovery_options().await?;
            let record = options.recoverable.get(index).cloned().ok_or_else(|| Error::State("no such record".into()));
            let keys = match record {
                Ok(record) => keychain.recover_service_keys(&record, &pass_str).await,
                Err(e) => Err(e),
            };
            pass_str.zeroize();
            let keys = keys?;
            let found = apple_core::cloudkit::discover::fetch_accessories(session.account_arc(), &keys).await?;
            let mut tags = Vec::new();
            for a in &found {
                if let Ok(keys) = AccessoryKeys::new(
                    a.master_key.clone(), a.skn.clone(), a.sks.clone(), a.paired_at, a.name.clone(), a.model.clone(),
                    Some(a.identifier.clone()), a.group_identifier.clone(), a.serial_number.clone(),
                    a.alignment_date, a.alignment_index.map(|i| i as i32),
                ) {
                    tags.push(keys.to_json());
                }
            }
            Ok(with_state(handle, json!({"ok": true, "accessories": tags})).await)
        }
        other => Err(Error::NotImplemented(format!("unknown command {other}"))),
    }
}

/// Adds what the host must persist after a call that touched Apple: the session blob and, when the
/// library owns the machine, its store (Anisette headers advance it).
async fn with_state(handle: &Handle, mut response: Value) -> Value {
    if let Ok(state) = handle.session.save_state().await {
        response["state"] = json!(state);
    }
    if let Some(machine) = &handle.machine {
        if let Ok(store) = machine.export_store() {
            response["store_export_b64"] = json!(base64::engine::general_purpose::STANDARD.encode(store));
        }
    }
    response["state_changed"] = json!(true);
    response
}

fn string_field(v: &Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .ok_or_else(|| Error::State(format!("missing {key}")))
}

fn password_field(v: &Value) -> Result<Vec<u8>> {
    let b64 = v
        .get("password_b64")
        .and_then(|x| x.as_str())
        .ok_or_else(|| Error::State("missing password_b64".into()))?;
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| Error::State("the password is not base64".into()))
}

fn login_state_name(state: LoginState) -> &'static str {
    match state {
        LoginState::LoggedOut => "logged_out",
        LoginState::Require2fa => "require_2fa",
        LoginState::Authenticated => "authenticated",
        LoginState::LoggedIn => "logged_in",
    }
}

fn methods_json(methods: &[SecondFactorMethod]) -> Vec<Value> {
    methods
        .iter()
        .map(|m| match m {
            SecondFactorMethod::TrustedDevice => json!({"kind": "trusted_device"}),
            SecondFactorMethod::Sms { phone_number_id, phone_number } => {
                json!({"kind": "sms", "id": phone_number_id, "number": phone_number})
            }
        })
        .collect()
}

fn login_result_json(result: LoginResult) -> Result<Value> {
    Ok(match result {
        LoginResult::SignedIn => json!({"ok": true, "state_changed": true, "result": "signed_in"}),
        LoginResult::SecondFactorRequired(methods) => json!({
            "ok": true,
            "state_changed": true,
            "result": "second_factor_required",
            "methods": methods_json(&methods),
        }),
    })
}

/// Frees a string returned by [`openfinder_call`].
///
/// # Safety
/// `s` must be a pointer returned by `openfinder_call` (or NULL).
#[no_mangle]
pub unsafe extern "C" fn openfinder_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Closes a handle.
///
/// # Safety
/// `handle` must come from `openfinder_open` and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn openfinder_close(handle: *mut Handle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// The library version.
#[no_mangle]
pub extern "C" fn openfinder_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}
