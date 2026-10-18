//! The GSA `MidService` requests must match the Python's (`app/tools/oracle/gsa_vectors.py`). Offline: a
//! mock server serves the URL bag and the four replies, and records every request.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use apple_core::gsa::{GsaClient, GsaDevice};
use apple_core::http::Http;
use base64::Engine as _;
use serde_json::{json, Value as Json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn fixture(name: &str) -> Json {
    let path = format!(
        "{}/../../app/android/app/src/test/resources/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

fn hexvec(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[derive(Clone)]
struct Received {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn start() -> (String, Arc<Mutex<Vec<Received>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = format!("http://{addr}");
    let received = Arc::new(Mutex::new(Vec::new()));
    let sink = received.clone();
    let server_origin = origin.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { break };
            let sink = sink.clone();
            let origin = server_origin.clone();
            tokio::spawn(async move {
                let Some((method, path, headers, body)) = read_request(&mut socket).await else { return };
                sink.lock().unwrap().push(Received { method, path: path.clone(), headers, body });
                let response = if path.ends_with("/lookup") {
                    plist_string(&json!({"urls": {
                        "midStartProvisioning": format!("{origin}/grandslam/MidService/midStartProvisioning"),
                        "midFinishProvisioning": format!("{origin}/grandslam/MidService/midFinishProvisioning"),
                        "midSyncMachine": format!("{origin}/grandslam/MidService/midSyncMachine"),
                    }}))
                } else if path.ends_with("midStartProvisioning") {
                    plist_string(&json!({"Response": {"spim": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v"}}))
                } else if path.ends_with("midFinishProvisioning") {
                    plist_string(&json!({"Response": {
                        "ptm": "AAECAwQFBgcICQoLDA0ODw==",
                        "tk": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                        "X-Apple-I-MD-RINFO": 84215045}}))
                } else {
                    plist_string(&json!({"Response": {"Status": {"ec": 0}}}))
                };
                let out = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/x-apple-plst\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                );
                let _ = socket.write_all(out.as_bytes()).await;
                let _ = socket.write_all(&response).await;
                let _ = socket.flush().await;
            });
        }
    });
    (origin, received)
}

fn plist_string(v: &Json) -> Vec<u8> {
    apple_core::plist::to_xml(&apple_core::keychain::escrow::json_to_plist(v))
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<(String, String, Vec<(String, String)>, Vec<u8>)> {
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
            let mut lines = head.lines();
            let mut request = lines.next()?.split_whitespace();
            let method = request.next()?.to_string();
            let path = request.next()?.to_string();
            let mut headers = Vec::new();
            let mut content_length = 0usize;
            for line in lines {
                if let Some((k, v)) = line.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                    headers.push((k.trim().to_string(), v.trim().to_string()));
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
            return Some((method, path, headers, body));
        }
    }
}

fn same_plist(got: &[u8], want_b64: &str) -> bool {
    if want_b64.is_empty() {
        return got.is_empty();
    }
    let got = apple_core::plist::parse_dict(got);
    let want = apple_core::plist::parse_dict(&b64(want_b64));
    matches!((got, want), (Ok(g), Ok(w)) if g == w)
}

#[tokio::test(flavor = "multi_thread")]
async fn midservice_requests_match_the_python() {
    let d = fixture("gsa/requests.json");
    let (origin, received) = start().await;
    let device = GsaDevice {
        unique_device_id: d["device"]["unique_device_id"].as_str().unwrap().to_string(),
        client_info: d["device"]["client_info"].as_str().unwrap().to_string(),
        local_user_uuid: d["device"]["local_user_uuid"].as_str().unwrap().to_string(),
        serial: Some(d["device"]["serial"].as_str().unwrap().to_string()),
    };
    let http = Http::new(Duration::from_secs(5)).unwrap();
    let mut client = GsaClient::new(device, http).with_lookup_url(format!("{origin}/grandslam/GsService2/lookup"));

    let bag = client.load_url_bag().await.unwrap();
    assert!(bag.contains_key("midStartProvisioning"));
    assert_eq!(client.start_provisioning().await.unwrap(), hexvec(d["spim"].as_str().unwrap()));
    let cpim = hexvec(d["cpim"].as_str().unwrap());
    let result = client.finish_provisioning(&cpim).await.unwrap();
    assert_eq!(result.ptm, hexvec(d["ptm"].as_str().unwrap()));
    assert_eq!(result.tk, hexvec(d["tk"].as_str().unwrap()));
    assert_eq!(result.routing, 84215045);
    client.sync_machine(d["mid"].as_str().unwrap(), d["srm"].as_str().unwrap(), Some(84215045)).await.unwrap();

    let got = received.lock().unwrap().clone();
    let expected = d["requests"].as_array().unwrap();
    assert_eq!(got.len(), expected.len(), "request count");
    for (i, (g, w)) in got.iter().zip(expected).enumerate() {
        let expected_path = w["url"].as_str().unwrap().split("://").nth(1).unwrap().split_once('/').map(|(_, p)| format!("/{p}")).unwrap();
        assert_eq!(g.method, w["method"].as_str().unwrap(), "request {i} method");
        assert_eq!(g.path, expected_path, "request {i} path");
        assert!(same_plist(&g.body, w["body"].as_str().unwrap()), "request {i} body");
        for (k, v) in w["headers"].as_object().unwrap() {
            // `Connection` is transport, `X-Apple-I-Client-Time` is the clock; both are ignored.
            if k.eq_ignore_ascii_case("connection") || k.eq_ignore_ascii_case("x-apple-i-client-time") {
                continue;
            }
            let got = g.headers.iter().find(|(hk, _)| hk.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str());
            assert_eq!(got, Some(v.as_str().unwrap()), "request {i} header {k}");
        }
    }
}
