//! Request bodies and header sets of the login, as `AsyncAppleAccount` composes them
//! (`_gsa_request`, `_login_mobileme`, `_sms_2fa_request`, `get_cpd`, `get_headers`), and the parsing
//! of the 2FA page. Pure functions: the oracle tests compare them with the Python's output.

use std::collections::BTreeMap;

use regex::Regex;

use crate::error::{Error, Result};
use crate::login::device::{bundles, DeviceIdentity};
use crate::login::SecondFactorMethod;
use crate::plist::{self, Value};

/// `get_cpd`: Python's five capability flags plus the Anisette set.
pub fn cpd(anisette: &BTreeMap<String, String>) -> BTreeMap<String, Value> {
    let mut d: BTreeMap<String, Value> = BTreeMap::new();
    d.insert("bootstrap".into(), Value::Boolean(true));
    d.insert("icscrec".into(), Value::Boolean(true));
    d.insert("pbe".into(), Value::Boolean(false));
    d.insert("prkgen".into(), Value::Boolean(true));
    d.insert("svct".into(), Value::String("iCloud".into()));
    for (k, v) in anisette {
        d.insert(k.clone(), Value::String(v.clone()));
    }
    d
}

/// The GsService2 envelope: `{Header: {Version: 1.0.1}, Request: {cpd, ...parameters}}` as an XML plist.
pub fn gsa_body(parameters: &BTreeMap<String, Value>, cpd: &BTreeMap<String, Value>) -> Vec<u8> {
    let mut request: BTreeMap<String, Value> = BTreeMap::new();
    request.insert("cpd".into(), Value::Dict(cpd.clone()));
    for (k, v) in parameters {
        request.insert(k.clone(), v.clone());
    }
    let mut header = BTreeMap::new();
    header.insert("Version".into(), Value::String("1.0.1".into()));
    plist::to_xml(&plist::dict([
        ("Header", Value::Dict(header)),
        ("Request", Value::Dict(request)),
    ]))
}

/// GsService2 headers. Anisette travels in `cpd`, not here.
pub fn gsa_headers(identity: &DeviceIdentity) -> Vec<(String, String)> {
    vec![
        ("Content-Type".into(), "text/x-xml-plist".into()),
        ("Accept".into(), "*/*".into()),
        ("User-Agent".into(), bundles::GSA_USER_AGENT.into()),
        ("X-MMe-Client-Info".into(), identity.client_info(bundles::AKD)),
    ]
}

/// The legacy (no validation data) delegate request body. `client-id` is the local user uuid.
pub fn login_delegates_body(username: &str, pet: &str, local_user_uuid: &str) -> Vec<u8> {
    let mut delegates = BTreeMap::new();
    delegates.insert("com.apple.mobileme".to_string(), Value::Dict(BTreeMap::new()));
    plist::to_xml(&plist::dict([
        ("apple-id", Value::String(username.into())),
        ("delegates", Value::Dict(delegates)),
        ("password", Value::String(pet.into())),
        ("client-id", Value::String(local_user_uuid.into())),
    ]))
}

pub fn login_delegates_headers(
    identity: &DeviceIdentity,
    adsid: &str,
    anisette: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    let mut headers = vec![
        ("X-Apple-ADSID".into(), adsid.into()),
        ("User-Agent".into(), identity.user_agent(bundles::ICLOUD_HELPER)),
        ("X-Mme-Client-Info".into(), identity.client_info(bundles::ACCOUNTSD)),
    ];
    for (k, v) in without_client_info(anisette) {
        headers.push((k, v));
    }
    headers
}

/// `_sms_2fa_request`'s header set: the endpoint's own, the Xcode identity, the token and Anisette
/// with client info.
pub fn two_factor_headers(
    identity: &DeviceIdentity,
    identity_token: &str,
    anisette: &BTreeMap<String, String>,
    extra: &[(String, String)],
) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = extra.to_vec();
    headers.push(("User-Agent".into(), bundles::TWO_FACTOR_USER_AGENT.into()));
    headers.push(("Accept-Language".into(), "en-us".into()));
    headers.push(("X-Apple-Identity-Token".into(), identity_token.into()));
    for (k, v) in without_client_info(anisette) {
        headers.push((k, v));
    }
    headers.push(("X-Mme-Client-Info".into(), identity.client_info(bundles::XCODE)));
    headers.push(("X-Apple-App-Info".into(), bundles::TWO_FACTOR_APP_INFO.into()));
    headers.push(("X-Xcode-Version".into(), bundles::TWO_FACTOR_XCODE_VERSION.into()));
    headers
}

/// `{"phoneNumber": {"id": N}, "mode": "sms"}`, byte-for-byte as Python's `json.dumps`.
pub fn sms_request_body(phone_number_id: i64) -> String {
    format!(r#"{{"phoneNumber": {{"id": {phone_number_id}}}, "mode": "sms"}}"#)
}

pub fn sms_submit_body(phone_number_id: i64, code: &str) -> String {
    format!(
        r#"{{"phoneNumber": {{"id": {phone_number_id}}}, "securityCode": {{"code": {}}}, "mode": "sms"}}"#,
        py_json_string(code)
    )
}

/// `_extract_phone_numbers`: the JSON in `<script class="boot_args">` of the `/auth` page, then
/// `direct.phoneNumberVerification.trustedPhoneNumbers`.
pub fn extract_phone_numbers(html: &str) -> Result<Vec<SecondFactorMethod>> {
    let script_re = Regex::new(r"(?is)<script\b([^>]*)>(.*?)</script\s*>").unwrap();
    let class_re = Regex::new(r#"(?i)\bclass\s*=\s*("([^"]*)"|'([^']*)')"#).unwrap();
    let mut body = None;
    for caps in script_re.captures_iter(html) {
        let attrs = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let class = class_re
            .captures(attrs)
            .map(|c| c.get(2).or_else(|| c.get(3)).map(|m| m.as_str()).unwrap_or(""))
            .unwrap_or("");
        if class.split_whitespace().any(|c| c == "boot_args") {
            body = caps.get(2).map(|m| m.as_str().to_string());
            break;
        }
    }
    let body = body.ok_or_else(|| {
        Error::Backend("could not find HTML element containing phone numbers".into())
    })?;
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|_| Error::Backend("the phone-number element is not JSON".into()))?;
    let numbers = json
        .get("direct")
        .and_then(|d| d.get("phoneNumberVerification"))
        .and_then(|p| p.get("trustedPhoneNumbers"))
        .and_then(|n| n.as_array());
    let Some(numbers) = numbers else {
        return Ok(Vec::new());
    };
    Ok(numbers
        .iter()
        .filter_map(|n| {
            let id = match n.get("id") {
                Some(serde_json::Value::Number(num)) => num.as_i64().filter(|v| *v != 0).unwrap_or(-1),
                _ => -1,
            };
            let number = n
                .get("numberWithDialCode")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("-")
                .to_string();
            Some(SecondFactorMethod::Sms { phone_number_id: id, phone_number: number })
        })
        .collect())
}

/// Anisette must not bring a client info of its own: each endpoint names its daemon.
pub fn without_client_info(h: &BTreeMap<String, String>) -> Vec<(String, String)> {
    h.iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("X-MMe-Client-Info"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// A JSON string literal as Python's `json.dumps` (ensure_ascii) writes it.
pub fn py_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
