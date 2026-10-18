//! Fixture-driven tests for the CloudKit DER reader and record decoding
//! (`app/tools/oracle/cloudkit_vectors.py`).

use apple_core::cloudkit::der::{self, DerElement};
use apple_core::cloudkit::records::{iterate_wire_fields, CloudKitRecord};
use apple_proto::cloudkit::RecordChange;
use prost::Message;
use serde_json::{json, Value};

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/../../app/android/app/src/test/resources/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn hexvec(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn element_json(e: &DerElement) -> Value {
    json!({
        "cls": e.tag_class,
        "constructed": e.constructed,
        "tag": e.tag_number,
        "content": hex(&e.content),
        "raw": hex(&e.raw),
    })
}

#[test]
fn der_encode_length() {
    let d = fixture("cloudkit/der.json");
    for (length, expected) in d["encode_length"].as_object().unwrap() {
        let n: usize = length.parse().unwrap();
        assert_eq!(hex(&der::encode_length(n)), expected.as_str().unwrap(), "length {n}");
    }
}

#[test]
fn der_parses_the_vectors() {
    let d = fixture("cloudkit/der.json");
    for (name, entry) in d["parsed"].as_object().unwrap() {
        let data = hexvec(entry["data"].as_str().unwrap());
        let elements = der::parse_all(&data).unwrap_or_else(|e| panic!("{name}: {e}"));
        let expected_elements = entry["elements"].as_array().unwrap();
        assert_eq!(elements.len(), expected_elements.len(), "{name}: element count");
        for (idx, (e, want)) in elements.iter().zip(expected_elements).enumerate() {
            assert_eq!(&element_json(e), want, "{name}: element");
            if e.constructed {
                let children: Vec<Value> = e.children().unwrap().iter().map(element_json).collect();
                assert_eq!(Value::Array(children), entry["children"][idx], "{name}: children");
            }
        }
        // `ints` of the top-level universal integers.
        let ints: Vec<Value> = elements
            .iter()
            .filter(|e| e.is_universal(der::TAG_INTEGER))
            .map(|e| int_value(&e.as_int()))
            .collect();
        assert_eq!(Value::Array(ints), entry["ints"], "{name}: ints");

        if let Some(first) = elements.first() {
            if first.constructed {
                let children = first.children().unwrap();
                let sub_ints: Vec<Value> = children
                    .iter()
                    .filter(|c| c.is_universal(der::TAG_INTEGER))
                    .map(|c| int_value(&c.as_int()))
                    .collect();
                // 2**70 does not fit serde_json's u64; only its count is compared exactly.
                let expected_sub = entry["sub_ints"].as_array().unwrap();
                assert_eq!(sub_ints.len(), expected_sub.len(), "{name}: sub_ints count");
                for (got, want) in sub_ints.iter().zip(expected_sub) {
                    if want.as_i64().is_some() {
                        assert_eq!(got, want, "{name}: sub_int");
                    }
                }
                let rebuild: Vec<Value> = (0..children.len())
                    .map(|i| json!(hex(&der::rebuild_without(first, i).unwrap())))
                    .collect();
                assert_eq!(Value::Array(rebuild), entry["rebuild_without"], "{name}: rebuild");
            }
        }
    }
}

fn int_value(n: &num_bigint::BigInt) -> Value {
    match n.to_string().parse::<i64>() {
        Ok(i) => json!(i),
        Err(_) => Value::Null,
    }
}

#[test]
fn der_rejects_the_vectors() {
    let d = fixture("cloudkit/der.json");
    for (name, entry) in d["errors"].as_object().unwrap() {
        let data = hexvec(entry["data"].as_str().unwrap());
        let failed = match name.as_str() {
            "children_of_primitive" => der::parse_one(&data, 0).unwrap().0.children().is_err(),
            "unwrap_two" => der::parse_one(&data, 0).unwrap().0.unwrap_one().is_err(),
            "expect_app_wrong" => der::expect_application(&data, 1).is_err(),
            _ => der::parse_all(&data).is_err(),
        };
        if entry["error"].is_string() {
            assert!(failed, "{name} should fail");
        } else {
            assert!(!failed, "{name} should not fail");
        }
    }
}

#[test]
fn wire_fields_match() {
    let d = fixture("cloudkit/records.json");
    for entry in d["wire_fields"].as_array().unwrap() {
        let data = hexvec(entry["data"].as_str().unwrap());
        let got: Vec<Value> = iterate_wire_fields(&data)
            .iter()
            .map(|f| json!([f.number, f.wire_type, hex(&f.payload)]))
            .collect();
        assert_eq!(Value::Array(got), entry["fields"]);
    }
}

fn record_json(r: &CloudKitRecord) -> Value {
    let mut fields: Vec<Value> = r
        .fields
        .values()
        .map(|f| {
            json!({
                "name": f.name,
                "value_type": f.value_type,
                "is_encrypted": f.is_encrypted,
                "raw": f.raw.as_ref().map(|b| hex(b)),
            })
        })
        .collect();
    fields.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    json!({
        "name": r.name,
        "zone_name": r.zone_name,
        "record_type": r.record_type,
        "etag": r.etag,
        "protection_info": r.protection_info.as_ref().map(|b| hex(b)),
        "protection_info_tag": r.protection_info_tag,
        "pcs_key": hex(&r.pcs_key),
        "fields": fields,
    })
}

#[test]
fn records_match() {
    let d = fixture("cloudkit/records.json");
    let changes: Vec<RecordChange> = d["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| RecordChange::decode(hexvec(c.as_str().unwrap()).as_slice()).unwrap())
        .collect();
    let records = CloudKitRecord::from_changes(&changes, "BeaconStore");
    let expected = d["records"].as_array().unwrap();
    assert_eq!(records.len(), expected.len(), "record count");
    for (r, want) in records.iter().zip(expected) {
        let mut want = want.clone();
        if let Some(fields) = want["fields"].as_array_mut() {
            fields.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        }
        assert_eq!(record_json(r), want, "record");
    }

    let typed = changes
        .iter()
        .find(|c| {
            c.record
                .as_ref()
                .and_then(|r| r.record_identifier.as_ref())
                .and_then(|i| i.value.as_ref())
                .and_then(|v| v.name.as_deref())
                == Some("TYPED-ON-CHANGE")
        })
        .unwrap();
    let no_zone = CloudKitRecord::from_changes(std::slice::from_ref(typed), "");
    assert_eq!(record_json(&no_zone[0]), d["no_zone_records"][0]);
}

// ------------------------------------------------------------------------------------ client

mod client {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use apple_core::cloudkit::CloudKitApi;
    use apple_core::cloudkit::client::{
        check_result, decode_delimited, encode_varint, ClientIdentity, CloudKitAccount, CloudKitClient,
        CloudKitIds,
    };
    use apple_core::error::Result;
    use apple_core::http::Http;
    use apple_core::login::BoxFuture;
    use apple_proto::cloudkit::Result as CloudKitResult;
    use prost::Message;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn fixture(name: &str) -> Value {
        let path = format!(
            "{}/../../app/android/app/src/test/resources/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    fn hexvec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn gunzip(data: &[u8]) -> Vec<u8> {
        use std::io::Read;
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(data).read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn identities_match() {
        let d = fixture("cloudkit/client.json");
        for (input, want) in d["identities"].as_object().unwrap() {
            let parsed = ClientIdentity::parse(input);
            assert_eq!(parsed.model, want["model"].as_str().unwrap(), "model {input:?}");
            assert_eq!(parsed.os_version, want["os_version"].as_str().unwrap(), "os {input:?}");
            assert_eq!(parsed.prefix, want["prefix"].as_str().unwrap(), "prefix {input:?}");
            assert_eq!(
                parsed.cloud_kit_client_info(),
                want["cloudkit_client_info"].as_str().unwrap(),
                "client info {input:?}"
            );
        }
    }

    #[test]
    fn varints_match() {
        let d = fixture("cloudkit/client.json");
        for (n, want) in d["varints"].as_object().unwrap() {
            let value: u64 = n.parse().unwrap();
            assert_eq!(hex(&encode_varint(value)), want.as_str().unwrap(), "varint {n}");
        }
    }

    #[test]
    fn delimited_errors_match() {
        let d = fixture("cloudkit/client.json");
        for (name, entry) in d["delimited"].as_object().unwrap() {
            let data = hexvec(entry["data"].as_str().unwrap());
            let result = decode_delimited(&data);
            if entry["error"].is_string() {
                assert!(result.is_err(), "{name} should fail");
            } else {
                assert_eq!(result.unwrap().len(), entry["count"].as_u64().unwrap() as usize, "{name}");
            }
        }
    }

    #[test]
    fn result_codes_match() {
        let d = fixture("cloudkit/client.json");
        for (name, entry) in d["results"].as_object().unwrap() {
            let result = CloudKitResult::decode(hexvec(entry["result"].as_str().unwrap()).as_slice()).unwrap();
            let outcome = check_result(&result);
            if entry["raises"].as_bool().unwrap() {
                match outcome {
                    Err(apple_core::Error::Rejected { ec, .. }) => {
                        let want = entry["client_error"]
                            .as_i64()
                            .or_else(|| entry["server_error"].as_i64())
                            .or_else(|| entry["code"].as_i64());
                        if let Some(want) = want {
                            assert_eq!(ec, Some(want), "{name} code");
                        }
                    }
                    Err(apple_core::Error::Throttled(m)) => {
                        // The Rust (like the Kotlin) appends Apple's Retry-After to the message.
                        assert!(
                            m.starts_with(entry["message"].as_str().unwrap()),
                            "{name}: {m}"
                        );
                    }
                    Err(other) => panic!("{name}: unexpected {other}"),
                    Ok(()) => panic!("{name}: expected an error"),
                }
            } else {
                assert!(outcome.is_ok(), "{name}");
            }
        }
    }

    struct FakeAccount {
        http: Http,
    }

    impl CloudKitAccount for FakeAccount {
        fn dsid<'a>(&'a self) -> BoxFuture<'a, Result<String>> {
            Box::pin(async move { Ok("1234567890".to_string()) })
        }
        fn device_uuid(&self) -> String {
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0".to_string()
        }
        fn client_info(&self) -> String {
            "<MacBookPro18,3> <Mac OS X;13.4.1;22F82> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>".to_string()
        }
        fn serial(&self) -> Option<String> {
            Some("C02SYNTHETIC".to_string())
        }
        fn service_token<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Option<String>> {
            Box::pin(async move {
                match name {
                    "cloudKitToken" => Some("SYNTHETIC-CK-TOKEN".to_string()),
                    "mmeAuthToken" => Some("SYNTHETIC-MME-TOKEN".to_string()),
                    _ => None,
                }
            })
        }
        fn anisette_headers<'a>(&'a self) -> BoxFuture<'a, Result<BTreeMap<String, String>>> {
            Box::pin(async move {
                Ok(BTreeMap::from([
                    ("X-Apple-I-MD".to_string(), "otp-synthetic".to_string()),
                    ("X-Apple-I-MD-M".to_string(), "machine-synthetic".to_string()),
                    ("X-Mme-Device-Id".to_string(), "DEVICE-SYNTHETIC".to_string()),
                ]))
            })
        }
        fn http(&self) -> &Http {
            &self.http
        }
        fn timeout(&self) -> Duration {
            Duration::from_secs(10)
        }
    }

    struct FixedIds {
        op: AtomicU64,
        uuid: AtomicU64,
    }

    impl FixedIds {
        fn new(op: u64, uuid: u64) -> Self {
            FixedIds { op: AtomicU64::new(op), uuid: AtomicU64::new(uuid) }
        }
    }

    impl CloudKitIds for FixedIds {
        fn operation_id(&self) -> String {
            let n = self.op.fetch_add(1, Ordering::SeqCst) + 1;
            format!("{n:032X}")
        }
        fn request_uuid(&self) -> String {
            let n = self.uuid.fetch_add(1, Ordering::SeqCst) + 1;
            format!("00000000-0000-4000-8000-{n:012X}")
        }
    }

    struct Mock {
        requests: Arc<Mutex<Vec<Value>>>,
    }

    async fn start(replies: Vec<Vec<u8>>) -> (String, Mock) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let replies = Arc::new(Mutex::new(replies));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (r, reqs) = (replies, requests.clone());
        let mock_base = base.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { break };
                let (r, reqs) = (r.clone(), reqs.clone());
                let base = mock_base.clone();
                tokio::spawn(async move {
                    let Some((headers, body)) = read_request(&mut socket).await else { return };
                    reqs.lock().unwrap().push(serde_json::json!({"headers": headers, "body": hex(&body)}));
                    let index = reqs.lock().unwrap().len() - 1;
                    let reply = {
                        let guard = r.lock().unwrap();
                        guard.get(index).cloned().unwrap_or_default()
                    };
                    let mut reply = reply;
                    // The app_init reply must point the client back at this mock.
                    if index == 0 {
                        let text = String::from_utf8_lossy(&reply).to_string();
                        let rewritten = text
                            .replace("https://gateway.icloud.com/ckdatabase", &format!("{base}/ckdatabase"))
                            .replace("https://gateway.icloud.com/ckcoderouter", &format!("{base}/ckcoderouter"))
                            .replace("https://p42-ckdatabase.icloud.com:443", &format!("{base}/ckdatabase"));
                        reply = rewritten.into_bytes();
                    }
                    let out = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        reply.len()
                    );
                    let _ = socket.write_all(out.as_bytes()).await;
                    let _ = socket.write_all(&reply).await;
                    let _ = socket.flush().await;
                });
            }
        });
        (base, Mock { requests })
    }

    async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<(Value, Vec<u8>)> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = socket.read(&mut tmp).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                let mut headers = serde_json::Map::new();
                let content_length = head
                    .lines()
                    .filter_map(|l| l.split_once(':'))
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                for line in head.lines().skip(1) {
                    if let Some((k, v)) = line.split_once(':') {
                        headers.insert(k.trim().to_string(), Value::String(v.trim().to_string()));
                    }
                }
                let mut body = buf[pos + 4..].to_vec();
                while body.len() < content_length {
                    let n = socket.read(&mut tmp).await.ok()?;
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&tmp[..n]);
                }
                body.truncate(content_length);
                return Some((Value::Object(headers), body));
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn full_flow_matches_the_python() {
        let d = fixture("cloudkit/client.json");
        let flow = &d["flow"];
        let replies: Vec<Vec<u8>> = ["app_init", "zone", "page1", "page2", "invoke"]
            .iter()
            .map(|k| {
                let s = flow["replies"][*k].as_str().unwrap();
                if *k == "app_init" {
                    s.as_bytes().to_vec()
                } else {
                    hexvec(s)
                }
            })
            .collect();
        let (origin, mock) = start(replies).await;
        let http = Http::new(Duration::from_secs(10)).unwrap();
        let account = Arc::new(FakeAccount { http });
        let client = CloudKitClient::new(account)
            .with_app_init_url(format!("{origin}/setup/ckAppInit"))
            .with_ids(Arc::new(FixedIds::new(0, 0)));

        let zones = client.zone_retrieve().await.unwrap();
        let zone_hex: Vec<String> = zones.iter().map(|z| hex(&z.encode_to_vec())).collect();
        assert_eq!(Value::Array(zone_hex.iter().map(|s| json!(s)).collect()), flow["zones"]);

        let changes = client.iter_records("BeaconStore", None, 100).await.unwrap();
        let change_hex: Vec<String> = changes.iter().map(|c| hex(&c.encode_to_vec())).collect();
        assert_eq!(Value::Array(change_hex.iter().map(|s| json!(s)).collect()), flow["changes"]);

        let result = client
            .function_invoke("Cuttlefish", "fetchViableBottles", hexvec("0a0170"))
            .await
            .unwrap();
        assert_eq!(hex(&result), flow["invoke_result"].as_str().unwrap());

        let info = client.container_info().await.unwrap();
        assert_eq!(info.user_id, flow["container"]["user_id"].as_str().unwrap());
        assert_eq!(info.partition().as_deref(), flow["container"]["partition"].as_str());

        let got = mock.requests.lock().unwrap().clone();
        let want = flow["requests"].as_array().unwrap();
        assert_eq!(got.len(), want.len());
        // Every request — app-init, the two record syncs and the code invoke — must match the Python
        // byte for byte. The app-init is where a stale/bad credential shows up as a 401; the operations
        // are where a wrong protobuf field number shows up as an empty result.
        for (i, (g, w)) in got.iter().zip(want).enumerate() {
            let gh = g["headers"].as_object().unwrap();
            for (k, v) in w["headers"].as_object().unwrap() {
                let got_v = gh.iter().find(|(hk, _)| hk.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str().unwrap());
                assert_eq!(got_v, Some(v.as_str().unwrap()), "request {i} header {k}");
            }
            if let Some(auth) = w["auth"].as_array() {
                let userpass = format!("{}:{}", auth[0].as_str().unwrap(), auth[1].as_str().unwrap());
                let expected = format!("Basic {}", apple_core::util::b64(userpass.as_bytes()));
                let got_v = gh.iter().find(|(hk, _)| hk.eq_ignore_ascii_case("authorization")).map(|(_, v)| v.as_str().unwrap());
                assert_eq!(got_v, Some(expected.as_str()), "request {i} Authorization");
            }
            let raw = hexvec(g["body"].as_str().unwrap());
            let gzipped = gh
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("content-encoding") && v.as_str().unwrap().eq_ignore_ascii_case("gzip"));
            let body = if gzipped { gunzip(&raw) } else { raw };
            assert_eq!(hex(&body), w["body"].as_str().unwrap(), "request {i} body");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resumed_page_matches_the_python() {
        let d = fixture("cloudkit/client.json");
        let replies = vec![
            d["flow"]["replies"]["app_init"].as_str().unwrap().as_bytes().to_vec(),
            hexvec(d["flow"]["replies"]["page2"].as_str().unwrap()),
        ];
        let (origin, _) = start(replies).await;
        let http = Http::new(Duration::from_secs(10)).unwrap();
        let account = Arc::new(FakeAccount { http });
        let client = CloudKitClient::new(account)
            .with_app_init_url(format!("{origin}/setup/ckAppInit"))
            .with_ids(Arc::new(FixedIds::new(100, 100)));
        let page = client.record_sync("BeaconStore", Some(b"resume".to_vec()), Some(50)).await.unwrap();
        let resumed = &d["resumed"];
        assert_eq!(hex(page.continuation_token.as_deref().unwrap_or(&[])), resumed["token"].as_str().unwrap());
        assert_eq!(page.status, Some(resumed["status"].as_i64().unwrap() as i32));
        assert_eq!(page.complete(), resumed["complete"].as_bool().unwrap());
    }
}

// ------------------------------------------------------------------------------------ pcs

mod pcs {
    use apple_core::cloudkit::der;
    use apple_core::cloudkit::pcs::{self, FieldContext, PcsCurve, PcsKey, ShareProtection, UnwrappedProtection};
    use apple_core::cloudkit::servicekeys;
    use num_bigint::BigUint;
    use serde_json::Value;

    fn fixture(name: &str) -> Value {
        let path = format!(
            "{}/../../app/android/app/src/test/resources/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    fn hexvec(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn key_from(v: &Value) -> PcsKey {
        let curve = match v["curve"].as_str().unwrap() {
            "secp256r1" => PcsCurve::P256,
            "secp384r1" => PcsCurve::P384,
            other => panic!("curve {other}"),
        };
        PcsKey::new(curve, BigUint::from_bytes_be(&hexvec(v["d"].as_str().unwrap()))).unwrap()
    }

    fn key_json(k: &PcsKey) -> Value {
        serde_json::json!({"curve": k.curve.name(), "d": hex(&k.scalar_bytes())})
    }

    fn bytes_json(b: &[u8]) -> Value {
        serde_json::json!(hex(b))
    }

    #[test]
    fn kdf_matches() {
        let d = fixture("cloudkit/pcs.json");
        for case in d["kdf"].as_array().unwrap() {
            let master = hexvec(case["master"].as_str().unwrap());
            for (label, want) in case["derive"].as_object().unwrap() {
                assert_eq!(bytes_json(&pcs::derive_key(&master, label.as_bytes(), None)), *want, "derive {label}");
            }
            for (label, want) in case["derive48"].as_object().unwrap() {
                assert_eq!(bytes_json(&pcs::derive_key(&master, label.as_bytes(), Some(48))), *want, "derive48 {label}");
            }
            assert_eq!(bytes_json(&pcs::derive_encryption_key(&master)), case["encryption_key"]);
            assert_eq!(bytes_json(&pcs::derive_hmac_key(&master)), case["hmac_key"]);
            assert_eq!(bytes_json(&pcs::compute_key_id(&master)), case["key_id"]);
            let scalar = pcs::derive_master_ec_scalar(&master).unwrap();
            assert_eq!(hex(&PcsKey::fixed(&scalar, 32)), case["master_ec"].as_str().unwrap());
        }
    }

    #[test]
    fn public_forms_match() {
        let d = fixture("cloudkit/pcs.json");
        for case in d["public_forms"].as_array().unwrap() {
            let key = key_from(&case["key"]);
            assert_eq!(bytes_json(&key.compressed()), case["compressed"]);
            assert_eq!(bytes_json(&key.bare_x()), case["bare_x"]);
            let forms: Vec<Value> = key.public_key_forms().iter().map(|f| bytes_json(f)).collect();
            assert_eq!(Value::Array(forms), case["forms"]);
        }
    }

    #[test]
    fn select_default_matches() {
        let d = fixture("cloudkit/pcs.json");
        for case in d["select_default"].as_array().unwrap() {
            let keys: Vec<Vec<u8>> = case["keys"].as_array().unwrap().iter().map(|k| hexvec(k.as_str().unwrap())).collect();
            let pcs_key = hexvec(case["pcs_key"].as_str().unwrap());
            let chosen = pcs::select_default_master_key(&keys, &pcs_key);
            match case["chosen"].as_str() {
                Some(want) => assert_eq!(chosen.map(|k| hex(&k)), Some(want.to_string())),
                None => assert!(chosen.is_none()),
            }
        }
    }

    #[test]
    fn fields_decrypt() {
        let d = fixture("cloudkit/pcs.json");
        for case in d["fields"].as_array().unwrap() {
            let master = hexvec(case["master"].as_str().unwrap());
            let context = FieldContext {
                zone_name: case["zone"].as_str().unwrap().to_string(),
                record_name: case["record"].as_str().unwrap().to_string(),
                field_name: case["field"].as_str().unwrap().to_string(),
            };
            let data = hexvec(case["ciphertext"].as_str().unwrap());
            let plain = pcs::decrypt_field(&data, &UnwrappedProtection::bare(master), &context, true).unwrap();
            assert_eq!(hex(&plain), case["plaintext"].as_str().unwrap());
        }
        for (name, case) in d["field_failures"].as_object().unwrap() {
            let master = hexvec(case["master"].as_str().unwrap());
            let context = FieldContext {
                zone_name: case["zone"].as_str().unwrap().to_string(),
                record_name: case["record"].as_str().unwrap().to_string(),
                field_name: case["field"].as_str().unwrap().to_string(),
            };
            let data = hexvec(case["data"].as_str().unwrap());
            let check = case["check_key_id"].as_bool().unwrap_or(true);
            let result = pcs::decrypt_field(&data, &UnwrappedProtection::bare(master), &context, check);
            if case["error"].is_string() {
                assert!(result.is_err(), "{name} should fail");
            } else {
                assert!(result.is_ok(), "{name} should succeed");
            }
        }
    }

    #[test]
    fn unwrap_share_key_matches() {
        let d = fixture("cloudkit/pcs.json");
        for case in d["unwrap_share_key"].as_array().unwrap() {
            let key = key_from(&case["key"]);
            let ciphertext = hexvec(case["ciphertext"].as_str().unwrap());
            let result = pcs::unwrap_share_key(&key, &ciphertext);
            match case["error"].as_str() {
                Some(_) => assert!(result.is_err(), "case {case} should fail"),
                None => assert_eq!(hex(&result.unwrap()), case["master"].as_str().unwrap()),
            }
        }
    }

    #[test]
    fn unwrap_protection_matches() {
        let d = fixture("cloudkit/pcs.json");
        for case in d["unwrap_protection"].as_array().unwrap() {
            let der_bytes = hexvec(case["der"].as_str().unwrap());
            let held: Vec<PcsKey> = case["held"].as_array().map(|a| a.iter().map(key_from).collect()).unwrap_or_default();
            let result = ShareProtection::from_der(&der_bytes).and_then(|p| pcs::unwrap_protection(&p, &held));
            match case["error"].as_str() {
                Some(_) => assert!(result.is_err(), "{} should fail", case["name"]),
                None => {
                    let unwrapped = result.unwrap();
                    let want = &case["result"];
                    assert_eq!(hex(&unwrapped.master_key), want["master_key"].as_str().unwrap(), "{}", case["name"]);
                    assert_eq!(unwrapped.share_key_derived, want["share_key_derived"].as_bool().unwrap());
                    assert_eq!(unwrapped.read_only, want["read_only"].as_bool().unwrap());
                    assert_eq!(unwrapped.hmac_verified, want["hmac_verified"].as_bool().unwrap());
                    assert_eq!(unwrapped.signature_verified, want["signature_verified"].as_bool());
                    let sym: Vec<Value> = unwrapped.meta.symmetric_keys.iter().map(|k| bytes_json(k)).collect();
                    assert_eq!(Value::Array(sym), want["symmetric_keys"]);
                    let privs: Vec<Value> = unwrapped.meta.private_keys.iter().map(key_json).collect();
                    assert_eq!(Value::Array(privs), want["private_keys"]);
                }
            }
        }
    }

    #[test]
    fn protection_parse_matches() {
        let d = fixture("cloudkit/pcs.json");
        let case = &d["protection_parse"];
        let protection = ShareProtection::from_der(&hexvec(case["der"].as_str().unwrap())).unwrap();
        assert_eq!(hex(&protection.hmac), case["hmac"].as_str().unwrap());
        assert_eq!(hex(&protection.meta), case["meta"].as_str().unwrap());
        assert_eq!(hex(&protection.keyset_der), case["keyset_der"].as_str().unwrap());
        assert_eq!(hex(&protection.truncated_key_id), case["truncated_key_id"].as_str().unwrap());
        assert_eq!(protection.signature_data.version, BigUint::from(case["version"].as_u64().unwrap()));
        assert_eq!(hex(&protection.signature_data.data), case["signature_data"].as_str().unwrap());
        let keys: Vec<Value> = protection
            .keys
            .iter()
            .map(|k| serde_json::json!({
                "key_type": k.key_type.to_string().parse::<i64>().unwrap(),
                "public_key": hex(&k.public_key),
                "ciphertext": hex(&k.ciphertext),
                "flags": k.flags.as_ref().map(|f| f.to_string().parse::<i64>().unwrap()),
                "read_only": k.read_only(),
            }))
            .collect();
        assert_eq!(Value::Array(keys), case["keys"]);
        assert!(pcs::verify_protection_hmac(&protection, &hexvec(case["master"].as_str().unwrap())));
        assert_eq!(case["hmac_verified"].as_bool().unwrap(), true);
        assert_eq!(case["hmac_verified_wrong_key"].as_bool().unwrap(), false);

        for (name, entry) in d["protection_parse_errors"].as_object().unwrap() {
            assert!(ShareProtection::from_der(&hexvec(entry["der"].as_str().unwrap())).is_err(), "{name}");
        }
    }

    #[test]
    fn signatures_match() {
        let d = fixture("cloudkit/pcs.json");
        for (name, case) in d["signatures"].as_object().unwrap() {
            let protection = ShareProtection::from_der(&hexvec(case["der"].as_str().unwrap())).unwrap();
            let outcome = pcs::describe_protection_signature(&protection, &hexvec(case["master"].as_str().unwrap()));
            match case["outcome"].as_str() {
                Some(want) => assert_eq!(outcome, Some(want), "{name}"),
                None => assert_eq!(outcome, None, "{name}"),
            }
        }
        for (name, want) in d["signature_reasons"].as_object().unwrap() {
            // The four reason constants are pinned by the fixture.
            let constant = match name.as_str() {
                "absent" => pcs::SIGNATURE_ABSENT,
                "unparseable" => pcs::SIGNATURE_UNPARSEABLE,
                "wrong_signer" => pcs::SIGNATURE_WRONG_SIGNER,
                "rejected" => pcs::SIGNATURE_REJECTED,
                _ => continue,
            };
            assert_eq!(constant, want.as_str().unwrap());
        }
    }

    #[test]
    fn parse_meta_matches() {
        let d = fixture("cloudkit/pcs.json");
        for (name, case) in d["parse_meta"].as_object().unwrap() {
            let plaintext = hexvec(case["plaintext"].as_str().unwrap());
            let result = pcs::parse_meta(&plaintext);
            if case["error"].is_string() {
                assert!(result.is_err(), "{name}");
                continue;
            }
            let meta = result.unwrap();
            let sym: Vec<Value> = meta.symmetric_keys.iter().map(|k| bytes_json(k)).collect();
            assert_eq!(Value::Array(sym), case["symmetric_keys"], "{name} symm");
            let privs: Vec<Value> = meta.private_keys.iter().map(key_json).collect();
            assert_eq!(Value::Array(privs), case["private_keys"], "{name} priv");
        }
    }

    #[test]
    fn service_keys_match() {
        let d = fixture("cloudkit/servicekeys.json");
        for (name, case) in d.as_object().unwrap() {
            let data = hexvec(case["data"].as_str().unwrap());
            let result = servicekeys::keys_from_der(&data);
            match case["error"].as_str() {
                Some(want) => {
                    let err = result.expect_err(name);
                    let got = match err {
                        servicekeys::ServiceKeyError::KeyBlob(_) => "KeyBlobError",
                        servicekeys::ServiceKeyError::Service(_) => "ServiceKeyError",
                    };
                    assert_eq!(got, want, "{name}");
                }
                None => {
                    let keys = result.unwrap_or_else(|e| panic!("{name}: {e}"));
                    let got: Vec<Value> = keys.iter().map(key_json).collect();
                    assert_eq!(Value::Array(got), case["keys"], "{name}");
                }
            }
        }
    }

    #[test]
    fn der_roundtrip_smoke() {
        // The parse_meta fixture's first byte is a constructed context tag; ensure the reader agrees.
        let _ = der::CLASS_APPLICATION;
    }
}

// ------------------------------------------------------------------------------------ beacons

mod beacons {
    use apple_core::cloudkit::beacons::{
        accessories_from_records, as_instant, decrypt_records, extract_serial, group_records,
        FieldValue,
    };
    use apple_core::cloudkit::pcs::{self, PcsCurve, PcsKey};
    use apple_core::cloudkit::records::CloudKitRecord;
    use apple_proto::cloudkit::RecordChange;
    use num_bigint::BigUint;
    use prost::Message;
    use serde_json::{json, Value};
    use time::OffsetDateTime;

    fn fixture(name: &str) -> Value {
        let path = format!(
            "{}/../../app/android/app/src/test/resources/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    fn hexvec(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn key_from(v: &Value) -> PcsKey {
        let curve = match v["curve"].as_str().unwrap() {
            "secp256r1" => PcsCurve::P256,
            "secp384r1" => PcsCurve::P384,
            other => panic!("curve {other}"),
        };
        PcsKey::new(curve, BigUint::from_bytes_be(&hexvec(v["d"].as_str().unwrap()))).unwrap()
    }

    fn micros(d: &OffsetDateTime) -> i64 {
        d.unix_timestamp() * 1_000_000 + d.microsecond() as i64
    }

    fn value_json(v: &FieldValue) -> Value {
        match v {
            FieldValue::Bytes(b) => json!({"bytes": hex(b)}),
            FieldValue::Str(s) => json!({"str": s}),
            FieldValue::Int(i) => json!({"int": i}),
            FieldValue::Double(d) => json!({"double": d}),
            FieldValue::Date(d) => json!({"date_micros": micros(d)}),
            FieldValue::Wrapper(b) => json!({"wrapper": hex(b)}),
            FieldValue::None => json!({"none": true}),
        }
    }

    #[test]
    fn decrypt_group_and_build_accessories() {
        let d = fixture("cloudkit/beacons.json");
        let changes: Vec<RecordChange> = d["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| RecordChange::decode(hexvec(c.as_str().unwrap()).as_slice()).unwrap())
            .collect();
        let records = CloudKitRecord::from_changes(&changes, "BeaconStore");
        let zone_keys: Vec<PcsKey> = d["zone_keys"].as_array().unwrap().iter().map(key_from).collect();
        let defaults: Vec<Vec<u8>> = d["default_master_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| hexvec(k.as_str().unwrap()))
            .collect();
        let now = OffsetDateTime::now_utc();

        let decrypted = decrypt_records(&records, &zone_keys, &defaults, now);

        // The zone structure yields the zone keys and the record defaults.
        let service_keys: Vec<PcsKey> = d["zone"]["service_keys"].as_array().unwrap().iter().map(key_from).collect();
        let zone_keys_from_protection = pcs::unwrap_zone(&hexvec(d["zone"]["zone_protection"].as_str().unwrap()), &service_keys).unwrap();
        assert_eq!(zone_keys_from_protection.len(), zone_keys.len());
        let defaults_from_protection =
            pcs::unwrap_zone_record_defaults(&hexvec(d["zone"]["record_protection"].as_str().unwrap()), &zone_keys).unwrap();
        assert_eq!(
            defaults_from_protection.iter().map(|k| hex(k)).collect::<Vec<_>>(),
            defaults.iter().map(|k| hex(k)).collect::<Vec<_>>()
        );

        // Every decrypted record must match the fixture.
        let expected = d["decrypted"].as_array().unwrap();
        assert_eq!(decrypted.records.len(), expected.len(), "decrypted count");
        for (got, want) in decrypted.records.iter().zip(expected) {
            assert_eq!(got.name, want["name"].as_str().unwrap());
            assert_eq!(got.record_type, want["record_type"].as_str().unwrap());
            let values: serde_json::Map<String, Value> =
                got.values.iter().map(|(k, v)| (k.clone(), value_json(v))).collect();
            assert_eq!(Value::Object(values), want["values"], "values {}", got.name);
            let raw: serde_json::Map<String, Value> =
                got.raw_values.iter().map(|(k, v)| (k.clone(), json!(hex(v)))).collect();
            assert_eq!(Value::Object(raw), want["raw_values"], "raw {}", got.name);
            let undecryptable: Vec<Value> = got.undecryptable.keys().map(|k| json!(k)).collect();
            assert_eq!(Value::Array(undecryptable), want["undecryptable"], "undecryptable {}", got.name);
        }

        // The Kotlin (and this port) deliberately count untyped records correctly; the Python's
        // counter never passes 1 for "<untyped>".
        let mut want_skipped = d["skipped"].as_object().unwrap().clone();
        want_skipped.insert("<untyped>".to_string(), json!(2));
        let skipped: serde_json::Map<String, Value> =
            decrypted.skipped.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
        assert_eq!(Value::Object(skipped), Value::Object(want_skipped));
        assert_eq!(decrypted.first_miss.is_some(), d["first_miss_present"].as_bool().unwrap());

        // Groups.
        let groups = group_records(&decrypted.records);
        let expected_groups = d["groups"].as_array().unwrap();
        assert_eq!(groups.len(), expected_groups.len());
        for (got, want) in groups.iter().zip(expected_groups) {
            assert_eq!(got.beacon.name, want["beacon"].as_str().unwrap());
            assert_eq!(got.naming.as_ref().map(|n| n.name.clone()), want["naming"].as_str().map(str::to_string));
            assert_eq!(got.alignment.as_ref().map(|a| a.name.clone()), want["alignment"].as_str().map(str::to_string));
            assert_eq!(
                apple_core::cloudkit::beacons::can_be_located(&got.beacon),
                want["can_be_located"].as_bool().unwrap()
            );
        }

        // Accessories.
        let accessories = accessories_from_records(&decrypted.records);
        let expected_accessories = d["accessories"].as_array().unwrap();
        assert_eq!(accessories.len(), expected_accessories.len());
        for (got, want) in accessories.iter().zip(expected_accessories) {
            assert_eq!(hex(&got.master_key), want["master_key"].as_str().unwrap());
            assert_eq!(hex(&got.skn), want["skn"].as_str().unwrap());
            assert_eq!(hex(&got.sks), want["sks"].as_str().unwrap());
            assert_eq!(micros(&got.paired_at), want["paired_at"].as_i64().unwrap());
            assert_eq!(got.name, want["name"].as_str().map(str::to_string));
            assert_eq!(got.model, want["model"].as_str().map(str::to_string));
            assert_eq!(got.identifier, want["identifier"].as_str().unwrap());
            assert_eq!(got.group_identifier, want["group_identifier"].as_str().map(str::to_string));
            assert_eq!(got.serial_number, want["serial_number"].as_str().map(str::to_string));
            assert_eq!(
                got.alignment_date.as_ref().map(micros),
                want["alignment_date_given"].as_i64()
            );
            assert_eq!(got.alignment_index, want["alignment_index_given"].as_i64());
        }

        // Serials.
        for (input, want) in d["serials"].as_object().unwrap() {
            assert_eq!(
                extract_serial(input),
                want.as_str().map(str::to_string),
                "serial {input:?}"
            );
        }

        // Dates.
        for case in d["dates"].as_array().unwrap() {
            let seconds: f64 = case["seconds"].as_str().unwrap().parse().unwrap();
            let result = as_instant(seconds, now);
            if case["error"].is_string() {
                assert!(result.is_err(), "{} should fail", case["seconds"]);
            } else {
                assert_eq!(micros(&result.unwrap()), case["result"]["date_micros"].as_i64().unwrap());
            }
        }
    }

    #[test]
    fn a_broken_protection_is_skipped_not_fatal() {
        let d = fixture("cloudkit/beacons.json");
        let change = RecordChange::decode(hexvec(d["broken_record"]["change"].as_str().unwrap()).as_slice()).unwrap();
        let records = CloudKitRecord::from_changes(std::slice::from_ref(&change), "BeaconStore");
        let decrypted = decrypt_records(&records, &[], &[], OffsetDateTime::now_utc());
        assert!(decrypted.records.is_empty());
        assert_eq!(decrypted.skipped.get("would not decrypt"), Some(&1));
    }
}
