//! The device a client claims to be, the endpoints it calls and the small value types of the login
//! (port of `apple/login/LoginDevice.kt` and `findmy.reports.anisette.DeviceIdentity`).

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, Result};
use crate::login::crypto;

/// The six values that describe one real macOS release and move together. Every client-info string
/// and user agent is composed from here so no two requests contradict each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub model: String,
    pub os_name: String,
    pub os_version: String,
    pub os_build: String,
    pub cfnetwork: String,
    pub darwin: String,
}

impl DeviceIdentity {
    /// `<model> <os;version;build>`, the prefix every client-info string starts with.
    pub fn platform(&self) -> String {
        format!("<{}> <{};{};{}>", self.model, self.os_name, self.os_version, self.os_build)
    }

    pub fn client_info(&self, bundle: &str) -> String {
        format!("{} <{}>", self.platform(), bundle)
    }

    pub fn user_agent(&self, product: &str) -> String {
        format!("{product} CFNetwork/{} Darwin/{}", self.cfnetwork, self.darwin)
    }

    /// `tools/machoadi/provider.py` `IDENTITY`: the release `mac_anisette.py` provisions under.
    pub fn mac_13_1() -> DeviceIdentity {
        DeviceIdentity {
            model: "MacBookPro13,2".into(),
            os_name: "macOS".into(),
            os_version: "13.1".into(),
            os_build: "22C65".into(),
            cfnetwork: "1404.0.5".into(),
            darwin: "22.2.0".into(),
        }
    }

    /// The identity behind a client-info string such as the machine file's
    /// `<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>`. An unknown
    /// release is refused rather than guessed.
    pub fn from_client_info(client_info: &str) -> Result<DeviceIdentity> {
        let groups: Vec<String> = angle_groups(client_info);
        if groups.len() < 2 {
            return Err(Error::Backend("client info has no <model> <os;version;build> prefix".into()));
        }
        let os: Vec<&str> = groups[1].split(';').collect();
        if os.len() != 3 {
            return Err(Error::Backend("client info OS group is not os;version;build".into()));
        }
        let (cf, darwin) = releases()
            .get(&(os[0].to_string(), os[1].to_string(), os[2].to_string()))
            .cloned()
            .ok_or_else(|| {
                Error::Backend(format!(
                    "unknown release {} {} ({}): add its CFNetwork/Darwin versions",
                    os[0], os[1], os[2]
                ))
            })?;
        Ok(DeviceIdentity {
            model: groups[0].clone(),
            os_name: os[0].into(),
            os_version: os[1].into(),
            os_build: os[2].into(),
            cfnetwork: cf,
            darwin,
        })
    }
}

fn angle_groups(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find('<') {
        let after = &rest[start + 1..];
        match after.find('>') {
            Some(end) => {
                out.push(after[..end].to_string());
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    out
}

fn releases() -> BTreeMap<(String, String, String), (String, String)> {
    let mut m = BTreeMap::new();
    m.insert(
        ("macOS".into(), "13.1".into(), "22C65".into()),
        ("1404.0.5".into(), "22.2.0".into()),
    );
    m.insert(
        ("macOS".into(), "13.4.1".into(), "22F8".into()),
        ("1408.0.4".into(), "22.5.0".into()),
    );
    m
}

/// The bundles and agents the login speaks as (constants of `findmy.reports.account` and `anisette`).
pub mod bundles {
    /// Grand Slam (`client_akd`).
    pub const AKD: &str = "com.apple.AuthKit/1 (com.apple.akd/1.0)";
    /// The library's `client`, used on the two-factor endpoints and as the account's client info.
    pub const XCODE: &str = "com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)";
    /// The mobileme delegate is logged into by accountsd.
    pub const ACCOUNTSD: &str = "com.apple.AOSKit/282 (com.apple.accountsd/113)";
    pub const ICLOUD_HELPER: &str = "com.apple.iCloudHelper/282";
    /// Deliberately not composed from the identity (Python `_GSA_USER_AGENT`).
    pub const GSA_USER_AGENT: &str = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";
    /// Two-factor requests: Apple's Xcode-flavoured values.
    pub const TWO_FACTOR_USER_AGENT: &str = "Xcode";
    pub const TWO_FACTOR_APP_INFO: &str = "com.apple.gs.xcode.auth";
    pub const TWO_FACTOR_XCODE_VERSION: &str = "11.2 (11B41)";
}

/// Everything about this installation the login needs besides Anisette. Must use the same `uid`/`devid`
/// pair the Anisette source sends.
#[derive(Debug, Clone)]
pub struct LoginDevice {
    pub local_user_uuid: String,
    pub device_id: String,
    pub serial: Option<String>,
    pub identity: DeviceIdentity,
    pub cloud_kit_device_uuid: String,
}

impl LoginDevice {
    /// Builds the login device from a machine's stored identity.
    pub fn new(
        local_user_uuid: String,
        device_id: String,
        serial: Option<String>,
        client_info: &str,
        host_uuid: &[u8],
    ) -> Result<LoginDevice> {
        let identity = DeviceIdentity::from_client_info(client_info)?;
        let cloud_kit_device_uuid = LoginDevice::cloud_kit_uuid(&device_id, host_uuid)?;
        Ok(LoginDevice { local_user_uuid, device_id, serial, identity, cloud_kit_device_uuid })
    }

    /// A real UUID for CloudKit: `device_id` itself when it is one, else the machine's host UUID,
    /// dashed and uppercase.
    pub fn cloud_kit_uuid(device_id: &str, host_uuid: &[u8]) -> Result<String> {
        if device_id.len() == 36 {
            if let Some(u) = parse_uuid(device_id) {
                return Ok(u);
            }
        }
        if host_uuid.len() != 16 {
            return Err(Error::Backend(
                "the device id is not a UUID and no host UUID is known".into(),
            ));
        }
        let h = crypto::hex(host_uuid);
        Ok(format!(
            "{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32]
        )
        .to_uppercase())
    }
}

fn parse_uuid(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return None;
    }
    let lens = [8, 4, 4, 4, 12];
    for (p, l) in parts.iter().zip(lens) {
        if p.len() != l || !p.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
    }
    Some(s.to_uppercase())
}

/// Where the login sends its requests. Defaults are Apple's; tests point them at a local server.
#[derive(Debug, Clone)]
pub struct LoginEndpoints {
    pub gsa: String,
    pub login_delegates: String,
    pub two_factor_methods: String,
    pub sms_request: String,
    pub sms_submit: String,
    pub trusted_device_request: String,
    pub trusted_device_submit: String,
    /// Hosts that refuse a second request on a connection they already answered.
    pub no_connection_reuse_hosts: BTreeSet<String>,
    /// Hosts the shared cooldown guards.
    pub cooldown_hosts: BTreeSet<String>,
}

impl Default for LoginEndpoints {
    fn default() -> Self {
        LoginEndpoints {
            gsa: "https://gsa.apple.com/grandslam/GsService2".into(),
            login_delegates: "https://setup.icloud.com/setup/iosbuddy/loginDelegates".into(),
            two_factor_methods: "https://gsa.apple.com/auth".into(),
            sms_request: "https://gsa.apple.com/auth/verify/phone".into(),
            sms_submit: "https://gsa.apple.com/auth/verify/phone/securitycode".into(),
            trusted_device_request: "https://gsa.apple.com/auth/verify/trusteddevice".into(),
            trusted_device_submit: "https://gsa.apple.com/grandslam/GsService2/validate".into(),
            no_connection_reuse_hosts: BTreeSet::from(["gsa.apple.com".to_string()]),
            cooldown_hosts: BTreeSet::from(["gsa.apple.com".to_string()]),
        }
    }
}

impl LoginEndpoints {
    /// Apple's paths under another origin (for tests).
    pub fn under(origin: &str, no_reuse: BTreeSet<String>) -> Self {
        let o = origin.trim_end_matches('/');
        LoginEndpoints {
            gsa: format!("{o}/grandslam/GsService2"),
            login_delegates: format!("{o}/setup/iosbuddy/loginDelegates"),
            two_factor_methods: format!("{o}/auth"),
            sms_request: format!("{o}/auth/verify/phone"),
            sms_submit: format!("{o}/auth/verify/phone/securitycode"),
            trusted_device_request: format!("{o}/auth/verify/trusteddevice"),
            trusted_device_submit: format!("{o}/grandslam/GsService2/validate"),
            no_connection_reuse_hosts: no_reuse.clone(),
            cooldown_hosts: no_reuse,
        }
    }
}

/// Python's `LoginState`, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginState {
    LoggedOut,
    Require2fa,
    Authenticated,
    LoggedIn,
}

/// What `spd` says about the account holder (`_AccountInfo`).
#[derive(Debug, Clone, Default)]
pub struct AccountInfo {
    pub account_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub trusted_device_2fa: bool,
}

/// What a login attempt ended in.
#[derive(Debug, Clone)]
pub enum LoginResult {
    SignedIn,
    SecondFactorRequired(Vec<SecondFactorMethod>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecondFactorMethod {
    /// A code pushed to the account's other Apple devices.
    TrustedDevice,
    /// A code by SMS to a trusted number; the string is Apple's masked display form.
    Sms { phone_number_id: i64, phone_number: String },
}
