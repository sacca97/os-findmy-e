//! Login: SRP, GSA password derivation, the 2FA flow, service tokens and the PET.
//!
//! The password is never held; only its SHA-256 digest is, in memory, and the caller's buffer is
//! zeroed. [`AnisetteSource`] is the one thing the account needs from the machine (the Anisette
//! header set and the resync answer); the app supplies a CoreADI-backed implementation and tests a
//! fake.

pub mod account;
pub mod crypto;
pub mod device;
pub mod messages;
pub mod srp;

use std::collections::BTreeMap;

use crate::error::Result;

pub use account::{AppleAccount, BoxFuture, SavedSession};
pub use device::{
    bundles, AccountInfo, DeviceIdentity, LoginDevice, LoginEndpoints, LoginResult, LoginState,
    SecondFactorMethod,
};

/// Anisette as the login consumes it (the part of `BaseAnisetteProvider` the account reads, plus the
/// resync). Values are secrets: never log them.
pub trait AnisetteSource: Send + Sync {
    /// The header set for ONE request, exactly these keys: `X-Apple-I-Client-Time`,
    /// `X-Apple-I-TimeZone`, `loc`, `X-Apple-Locale`, `X-Apple-I-MD`, `X-Apple-I-MD-LU`,
    /// `X-Apple-I-MD-M`, `X-Apple-I-MD-RINFO`, `X-Mme-Device-Id` and `X-Apple-I-SRL-NO`. No client
    /// info: each endpoint sets its own.
    fn headers(&self) -> BoxFuture<'_, Result<BTreeMap<String, String>>>;

    /// Answers Apple's resync request (hsc 434 carrying `X-Apple-I-MD-DATA`, the base64 `sim`).
    fn resync<'a>(&'a self, sim: &'a str) -> BoxFuture<'a, Result<()>>;
}

/// The login's Anisette header set, composed from what a CoreADI-backed provider returns. The
/// differences, each matching the Python: `loc` is added beside `X-Apple-Locale`, the device id is
/// uppercased, and the client info is dropped.
pub fn login_anisette_headers(
    provider: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let need = |k: &str| {
        provider
            .get(k)
            .cloned()
            .ok_or_else(|| crate::Error::Backend(format!("Anisette headers lack {k}")))
    };
    let locale = provider
        .get("X-Apple-Locale")
        .cloned()
        .unwrap_or_else(|| "en_US".to_string());
    let mut out = BTreeMap::new();
    out.insert("X-Apple-I-Client-Time".into(), need("X-Apple-I-Client-Time")?);
    out.insert(
        "X-Apple-I-TimeZone".into(),
        provider.get("X-Apple-I-TimeZone").cloned().unwrap_or_else(|| "UTC".to_string()),
    );
    out.insert("loc".into(), locale.clone());
    out.insert("X-Apple-Locale".into(), locale);
    out.insert("X-Apple-I-MD".into(), need("X-Apple-I-MD")?);
    out.insert("X-Apple-I-MD-LU".into(), need("X-Apple-I-MD-LU")?);
    out.insert("X-Apple-I-MD-M".into(), need("X-Apple-I-MD-M")?);
    out.insert("X-Apple-I-MD-RINFO".into(), need("X-Apple-I-MD-RINFO")?);
    out.insert("X-Mme-Device-Id".into(), need("X-Mme-Device-Id")?.to_uppercase());
    if let Some(serial) = provider.get("X-Apple-I-SRL-NO") {
        out.insert("X-Apple-I-SRL-NO".into(), serial.clone());
    }
    Ok(out)
}
