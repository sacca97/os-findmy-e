//! Asserts the credential-free machine probe composes exactly the request the Python probe sends
//! (`app/tools/oracle/probe_vectors.py`). No Apple contact.

use apple_core::login::device::DeviceIdentity;
use apple_core::login::messages;
use apple_core::plist::Value;
use serde_json::Value as Json;

fn fixture(name: &str) -> Json {
    let path = format!(
        "{}/../../app/android/app/src/test/resources/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn hexvec(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn b64(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

#[test]
fn probe_request_matches_the_python() {
    let d = fixture("probe/init.json");
    let anisette: std::collections::BTreeMap<String, String> = d["anisette"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .collect();

    // The cpd the probe sends is the raw Anisette set plus the five capability flags, including
    // `X-MMe-Client-Info` and with no `loc`.
    let cpd = messages::cpd(&anisette);
    assert!(cpd.contains_key("X-MMe-Client-Info"), "the probe cpd carries the client info");
    assert!(!cpd.contains_key("loc"), "the probe cpd does not carry `loc`");

    let mut params: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    params.insert("A2k".into(), Value::Data(hexvec(d["a2k"].as_str().unwrap())));
    params.insert("u".into(), Value::String(d["username"].as_str().unwrap().into()));
    params.insert("ps".into(), Value::Array(vec![Value::String("s2k".into()), Value::String("s2k_fo".into())]));
    params.insert("o".into(), Value::String("init".into()));
    let body = messages::gsa_body(&params, &cpd);
    assert_eq!(body, b64(d["body"].as_str().unwrap()), "probe request body");

    let identity = DeviceIdentity::mac_13_1();
    let headers: std::collections::BTreeMap<String, String> = messages::gsa_headers(&identity).into_iter().collect();
    let expected = d["headers"].as_object().unwrap();
    for (k, v) in expected {
        assert_eq!(headers.get(k).map(String::as_str), Some(v.as_str().unwrap()), "header {k}");
    }
}
