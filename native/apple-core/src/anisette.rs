//! The machine side of the protocol: the `.machine.json` file format and the CoreADI-backed
//! Anisette source (port of `app/android/.../anisette/{MachineFile,CoreAdiAnisetteProvider}.kt`).
//!
//! The CoreADI engine (`adi-core`) is used directly, so there is no JNI hop between Anisette and the
//! protocol code. `CoreAdiAnisette` is the `AnisetteSource` the login consumes, the resync target,
//! and the provisioner. Secrets here are never logged.

use std::collections::BTreeMap;
use std::sync::Arc;

use adi_core::capi::Handle;
use adi_core::CoreAdi;
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::gsa::{GsaClient, GsaDevice, DEFAULT_CLIENT_INFO};
use crate::http::Http;
use crate::login::{AnisetteSource, BoxFuture};
use crate::session::{MachineProvisioner, MachineSyncer};
use crate::util::{b64, b64_decode, now_utc};

/// Apple's "no account" pseudo-DSID the Anisette and provisioning calls use.
pub const DS_ID: i64 = -2;

/// Who the machine says it is to Apple's servers.
#[derive(Debug, Clone)]
pub struct MachineIdentity {
    pub device_id: String,
    pub local_user_uuid: String,
    pub client_info: String,
    pub serial: Option<String>,
    pub routing: Option<i64>,
    pub provisioned_at: Option<f64>,
}

/// A provisioned machine, as exchanged in `.machine.json` files. It is a credential: the host UUID and
/// store together are the machine Apple knows. `Debug` redacts it.
#[derive(Clone)]
pub struct MachineFile {
    pub host_uuid: [u8; 16],
    pub identity: MachineIdentity,
    /// The `CoreAdi.exportStore()` format; replaced after every call that changes the store.
    pub store_export: Vec<u8>,
}

impl std::fmt::Debug for MachineFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MachineFile(<redacted>)")
    }
}

impl MachineFile {
    pub fn to_json(&self) -> String {
        let mut id = json!({
            "device_id": self.identity.device_id,
            "local_user_uuid": self.identity.local_user_uuid,
            "client_info": self.identity.client_info,
        });
        if let Some(serial) = &self.identity.serial {
            id["serial"] = json!(serial);
        }
        if let Some(routing) = self.identity.routing {
            id["routing"] = json!(routing);
        }
        if let Some(provisioned_at) = self.identity.provisioned_at {
            id["provisioned_at"] = json!(provisioned_at);
        }
        json!({
            "version": 1,
            "host_uuid": crate::util::hex(&self.host_uuid),
            "identity": id,
            "store_export_b64": b64(&self.store_export),
        })
        .to_string()
    }

    /// Parses a machine file; the error message never contains file contents.
    pub fn parse(text: &str) -> Result<MachineFile> {
        let doc: Value = serde_json::from_str(text).map_err(|_| bad_machine())?;
        if doc.get("version").and_then(|v| v.as_i64()) != Some(1) {
            return Err(Error::State("Unsupported machine file version".into()));
        }
        let hex = doc.get("host_uuid").and_then(|v| v.as_str()).ok_or_else(bad_machine)?;
        if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::State("host_uuid must be 32 hex characters".into()));
        }
        let mut host_uuid = [0u8; 16];
        for i in 0..16 {
            host_uuid[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| bad_machine())?;
        }
        let id = doc.get("identity").ok_or_else(bad_machine)?;
        let s = |k: &str| id.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let identity = MachineIdentity {
            device_id: s("device_id").ok_or_else(bad_machine)?,
            local_user_uuid: s("local_user_uuid").ok_or_else(bad_machine)?,
            client_info: s("client_info").unwrap_or_else(|| DEFAULT_CLIENT_INFO.to_string()),
            serial: s("serial").filter(|v| !v.is_empty()),
            routing: id.get("routing").and_then(|v| v.as_i64()),
            provisioned_at: id.get("provisioned_at").and_then(|v| v.as_f64()),
        };
        let store_export = doc
            .get("store_export_b64")
            .and_then(|v| v.as_str())
            .and_then(b64_decode)
            .ok_or_else(|| Error::State("store_export_b64 is not valid base64".into()))?;
        Ok(MachineFile { host_uuid, identity, store_export })
    }

    /// The login device derived from this machine (the CloudKit UUID comes from the host UUID).
    pub fn login_config(&self) -> Result<crate::session::LoginConfig> {
        Ok(crate::session::LoginConfig {
            local_user_uuid: self.identity.local_user_uuid.clone(),
            device_id: self.identity.device_id.clone(),
            serial: self.identity.serial.clone(),
            client_info: self.identity.client_info.clone(),
            host_uuid: self.host_uuid.to_vec(),
        })
    }
}

fn bad_machine() -> Error {
    Error::State("Not a valid machine file".into())
}

/// The host's locale (`en_US`), from `LC_ALL`/`LC_MESSAGES`/`LANG`, as the Python's
/// `BaseAnisetteProvider.locale` does.
pub fn host_locale() -> String {
    locale_from_env(|k| std::env::var(k).ok())
}

fn locale_from_env(get: impl Fn(&str) -> Option<String>) -> String {
    for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Some(value) = get(key) {
            let value = value.split(':').next().unwrap_or("").split('.').next().unwrap_or("").trim();
            if !value.is_empty() && value != "C" && value != "POSIX" {
                return value.to_string();
            }
        }
    }
    "en_US".to_string()
}

/// The host's timezone abbreviation, as the Python's `BaseAnisetteProvider.timezone` does
/// (`str(datetime.now().astimezone().tzinfo)`). `TZ` is used when it is a bare abbreviation; hosts that
/// know their timezone (Android) should pass it explicitly rather than rely on this.
pub fn host_timezone() -> String {
    timezone_from_env(|k| std::env::var(k).ok())
}

fn timezone_from_env(get: impl Fn(&str) -> Option<String>) -> String {
    if let Some(tz) = get("TZ") {
        let tz = tz.trim();
        if !tz.is_empty() && !tz.contains('/') {
            return tz.to_string();
        }
    }
    "UTC".to_string()
}

/// Anisette from the emulated Mac CoreADI. Holds the engine (one session per call) and the machine's
/// identity; the login's `AnisetteSource`, the resync target and the provisioner.
///
/// The `X-Apple-I-TimeZone`/`loc`/`X-Apple-Locale` headers describe the **host**, not the machine, and
/// the validated Python sent the host's values (the library's `BaseAnisetteProvider.timezone`/`locale`);
/// use [`CoreAdiAnisette::with_host_locale`] to supply them, or the OS defaults apply.
pub struct CoreAdiAnisette {
    adi: Handle,
    identity: MachineIdentity,
    http: Http,
    timezone: String,
    locale: String,
}

impl CoreAdiAnisette {
    /// Loads a registered CoreADI build and installs the machine's store and host UUID.
    ///
    /// The emulated clock is left at its real default. Pinning it would make the OTP a constant and
    /// Apple would accept the machine for only about 60 s (`EVIDENCE.md` sections 8 and 9); the
    /// frozen clock exists only for `adi-cli`/`native/compare.sh` byte-for-byte tests.
    pub fn new(image: &[u8], machine: &MachineFile, http: Http) -> Result<CoreAdiAnisette> {
        let mut adi = CoreAdi::new(image).map_err(adi_error)?;
        adi.set_host_uuid(machine.host_uuid);
        for (name, data) in import_store(&machine.store_export)? {
            adi.store_put(&name, &data);
        }
        Ok(CoreAdiAnisette {
            adi: Handle::new(adi),
            identity: machine.identity.clone(),
            http,
            timezone: host_timezone(),
            locale: host_locale(),
        })
    }

    /// Set the host's timezone abbreviation and locale (what `X-Apple-I-TimeZone`/`loc`/`X-Apple-Locale`
    /// carry). The host knows these; the OS defaults are only a fallback.
    pub fn with_host_locale(mut self, timezone: impl Into<String>, locale: impl Into<String>) -> Self {
        self.timezone = timezone.into();
        self.locale = locale.into();
        self
    }

    pub fn identity(&self) -> &MachineIdentity {
        &self.identity
    }

    /// The machine's store in `CoreAdi.exportStore()` format; persist it after every mutating call.
    pub fn export_store(&self) -> Result<Vec<u8>> {
        let guard = self.adi.lock().map_err(|_| Error::Backend("the CoreADI handle is poisoned".into()))?;
        Ok(export_store(&guard.store_files()))
    }

    /// Replaces the store (for a host that just imported a machine).
    pub fn import_store(&self, bytes: &[u8]) -> Result<()> {
        let files = import_store(bytes)?;
        let mut guard = self.adi.lock().map_err(|_| Error::Backend("the CoreADI handle is poisoned".into()))?;
        for (name, data) in files {
            guard.store_put(&name, &data);
        }
        Ok(())
    }

    fn gsa_device(&self) -> GsaDevice {
        GsaDevice {
            unique_device_id: self.identity.device_id.clone(),
            client_info: self.identity.client_info.clone(),
            local_user_uuid: self.identity.local_user_uuid.clone(),
            serial: self.identity.serial.clone(),
        }
    }

    /// The raw Anisette header set `tools/machoadi/mac_anisette.py headers()` produces: timezone UTC, no
    /// `loc`, and it **does** carry `X-MMe-Client-Info`. The credential-free machine probe (`resync.py`,
    /// `gsa_init.py`) sends this shape; the login uses [`CoreAdiAnisette::provider_headers`] instead.
    pub fn raw_headers(&self) -> Result<BTreeMap<String, String>> {
        let mut guard = self.adi.lock().map_err(|_| Error::Backend("the CoreADI handle is poisoned".into()))?;
        let headers = guard.headers(DS_ID).map_err(adi_error)?;
        let mut out = BTreeMap::new();
        out.insert("X-Apple-I-Client-Time".into(), now_utc());
        out.insert("X-Apple-I-MD".into(), b64(&headers.otp));
        out.insert("X-Apple-I-MD-LU".into(), b64(self.identity.local_user_uuid.as_bytes()));
        out.insert("X-Apple-I-MD-M".into(), b64(&headers.mid));
        out.insert("X-Apple-I-MD-RINFO".into(), headers.routing.to_string());
        if let Some(serial) = &self.identity.serial {
            out.insert("X-Apple-I-SRL-NO".into(), serial.clone());
        }
        out.insert("X-Apple-I-TimeZone".into(), "UTC".into());
        out.insert("X-Apple-Locale".into(), self.locale.clone());
        out.insert("X-MMe-Client-Info".into(), self.identity.client_info.clone());
        out.insert("X-Mme-Device-Id".into(), self.identity.device_id.clone());
        Ok(out)
    }

    /// The current Anisette header set for one request, exactly the keys the login composes.
    pub fn provider_headers(&self) -> Result<BTreeMap<String, String>> {
        let mut guard = self.adi.lock().map_err(|_| Error::Backend("the CoreADI handle is poisoned".into()))?;
        let headers = guard.headers(DS_ID).map_err(adi_error)?;
        let mut out = BTreeMap::new();
        out.insert("X-Apple-I-Client-Time".into(), now_utc());
        out.insert("X-Apple-I-TimeZone".into(), self.timezone.clone());
        out.insert("loc".into(), self.locale.clone());
        out.insert("X-Apple-Locale".into(), self.locale.clone());
        out.insert("X-Apple-I-MD".into(), b64(&headers.otp));
        out.insert("X-Apple-I-MD-LU".into(), b64(self.identity.local_user_uuid.as_bytes()));
        out.insert("X-Apple-I-MD-M".into(), b64(&headers.mid));
        out.insert("X-Apple-I-MD-RINFO".into(), headers.routing.to_string());
        // The library's `get_headers` does `str(device_id).upper()`; the raw set does not.
        out.insert("X-Mme-Device-Id".into(), self.identity.device_id.to_uppercase());
        if let Some(serial) = &self.identity.serial {
            out.insert("X-Apple-I-SRL-NO".into(), serial.clone());
        }
        // No `X-MMe-Client-Info`: the Python's `get_headers` omits it (only `with_client_info` adds it), and
        // every endpoint (Grand Slam, the delegate, 2FA, reports) sets its own daemon's. The raw
        // provisioning composition in the Kotlin keeps it; the login view strips it.
        Ok(out)
    }
}

impl AnisetteSource for CoreAdiAnisette {
    fn headers(&self) -> BoxFuture<'_, Result<BTreeMap<String, String>>> {
        let result = self.provider_headers();
        Box::pin(async move { result })
    }

    fn resync<'a>(&'a self, sim: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let sim_bytes = b64_decode(sim).ok_or_else(|| Error::Backend("the resync SIM is not base64".into()))?;
            let (mid, srm) = {
                let mut guard = self.adi.lock().map_err(|_| Error::Backend("the CoreADI handle is poisoned".into()))?;
                guard.sync(DS_ID, &sim_bytes).map_err(adi_error)?
            };
            let mut gsa = GsaClient::new(self.gsa_device(), self.http.clone());
            gsa.load_url_bag().await?;
            let verdict = gsa
                .sync_machine(&b64(&mid), &b64(&srm), self.identity.routing)
                .await?;
            let status = verdict.get("Status").and_then(|v| v.as_dict());
            let ec = status.and_then(|s| s.get("ec")).and_then(|v| v.as_i64());
            if ec == Some(0) {
                Ok(())
            } else {
                let em = status.and_then(|s| s.get("em")).and_then(|v| v.as_str()).unwrap_or("");
                Err(Error::Rejected {
                    http: Some(200),
                    ec,
                    message: format!("Apple did not accept the machine's resync ({em})"),
                })
            }
        })
    }
}

impl MachineProvisioner for CoreAdiAnisette {
    fn provisioning_begin(&self, _ds_id: i64, spim: &[u8]) -> Result<(Vec<u8>, u32)> {
        let mut guard = self.adi.lock().map_err(|_| Error::Backend("the CoreADI handle is poisoned".into()))?;
        guard.provisioning_begin(DS_ID, spim).map_err(adi_error)
    }

    fn provisioning_finish(&self, _ds_id: i64, session: u32, ptm: &[u8], tk: &[u8], routing: i64) -> Result<()> {
        let mut guard = self.adi.lock().map_err(|_| Error::Backend("the CoreADI handle is poisoned".into()))?;
        guard
            .provisioning_finish(DS_ID, session, ptm, tk, routing.max(0) as u64)
            .map_err(adi_error)
    }
}

impl MachineSyncer for CoreAdiAnisette {
    fn sync(&self, _ds_id: i64, sim: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut guard = self.adi.lock().map_err(|_| Error::Backend("the CoreADI handle is poisoned".into()))?;
        guard.sync(DS_ID, sim).map_err(adi_error)
    }
}

/// Provisions a fresh machine through Grand Slam and returns the routing value. The caller persists the
/// machine store afterwards.
pub async fn provision_new_machine(
    anisette: &Arc<CoreAdiAnisette>,
    ds_id: i64,
) -> Result<i64> {
    let mut gsa = GsaClient::new(anisette.gsa_device(), anisette.http.clone());
    crate::session::provision_machine(&mut gsa, anisette.as_ref(), ds_id).await
}

fn adi_error(e: adi_core::Error) -> Error {
    match e {
        adi_core::Error::NotProvisioned => {
            Error::Authentication("The machine in the store is not provisioned. Import a provisioned machine file.".into())
        }
        adi_core::Error::AlreadyProvisioned => Error::State("The machine is already provisioned.".into()),
        other => Error::Backend(format!("Anisette failed: {other}")),
    }
}

/// `CoreAdi.exportStore()`: `[u16 name-len][name][u32 data-len][data]...`.
pub fn export_store(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in files {
        out.extend((name.len() as u16).to_be_bytes());
        out.extend(name.as_bytes());
        out.extend((data.len() as u32).to_be_bytes());
        out.extend(data);
    }
    out
}

/// Parses what [`export_store`] produced.
pub fn import_store(mut data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    let bad = || Error::State("malformed store export".into());
    while !data.is_empty() {
        let name_len = u16::from_be_bytes(data.get(..2).ok_or_else(bad)?.try_into().unwrap()) as usize;
        let name = std::str::from_utf8(data.get(2..2 + name_len).ok_or_else(bad)?)
            .map_err(|_| bad())?
            .to_string();
        let data_len =
            u32::from_be_bytes(data.get(2 + name_len..6 + name_len).ok_or_else(bad)?.try_into().unwrap()) as usize;
        let payload = data.get(6 + name_len..6 + name_len + data_len).ok_or_else(bad)?.to_vec();
        out.push((name, payload));
        data = &data[6 + name_len + data_len..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{locale_from_env, timezone_from_env};

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn locale_comes_from_the_host() {
        assert_eq!(locale_from_env(env(&[("LANG", "it_IT.UTF-8")])), "it_IT");
        assert_eq!(locale_from_env(env(&[("LC_ALL", "de_DE.UTF-8"), ("LANG", "it_IT")])), "de_DE");
        // C/POSIX is not a locale to send; fall through.
        assert_eq!(locale_from_env(env(&[("LC_ALL", "C"), ("LANG", "fr_FR.UTF-8")])), "fr_FR");
        assert_eq!(locale_from_env(env(&[("LC_ALL", "C")])), "en_US");
        assert_eq!(locale_from_env(env(&[])), "en_US");
    }

    #[test]
    fn timezone_comes_from_the_host() {
        assert_eq!(timezone_from_env(env(&[("TZ", "CEST")])), "CEST");
        // An IANA name is not the abbreviation Apple's clients send.
        assert_eq!(timezone_from_env(env(&[("TZ", "Europe/Rome")])), "UTC");
        assert_eq!(timezone_from_env(env(&[])), "UTC");
    }
}
