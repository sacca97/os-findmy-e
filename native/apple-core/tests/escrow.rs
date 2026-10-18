//! The escrow-proxy requests must match the Python's exactly (`app/tools/oracle/escrow_vectors.py`).
//! Offline: a mock server records the requests and serves a success plist.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apple_core::http::Http;
use apple_core::keychain::escrow::{EscrowAccount, EscrowProxy};
use apple_core::login::BoxFuture;
use base64::Engine as _;
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

struct FakeAccount {
    http: Http,
    anisette: BTreeMap<String, String>,
}

impl EscrowAccount for FakeAccount {
    fn client_info(&self, bundle: &str) -> String {
        format!("<MacBookPro13,2> <macOS;13.1;22C65> <{bundle}>")
    }
    fn user_agent(&self, product: &str) -> String {
        format!("{product} CFNetwork/1404.0.5 Darwin/22.2.0")
    }
    fn timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    fn anisette_headers<'a>(&'a self) -> BoxFuture<'a, apple_core::Result<BTreeMap<String, String>>> {
        let headers = self.anisette.clone();
        Box::pin(async move { Ok(headers) })
    }
    fn http(&self) -> &Http {
        &self.http
    }
}

#[derive(Clone)]
struct Received {
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn start() -> (String, Arc<Mutex<Vec<Received>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let sink = received.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { break };
            let sink = sink.clone();
            tokio::spawn(async move {
                let Some((path, headers, body)) = read_request(&mut socket).await else { return };
                sink.lock().unwrap().push(Received { path, headers, body });
                let plist = apple_core::plist::to_xml(&apple_core::plist::dict([
                    ("success", apple_core::plist::Value::Boolean(true)),
                    ("metadataList", apple_core::plist::Value::Array(vec![])),
                    ("respBlob", apple_core::plist::Value::String(String::new())),
                    ("dsid", apple_core::plist::Value::String("1234567890".into())),
                ]));
                let out = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/x-apple-plst\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    plist.len()
                );
                let _ = socket.write_all(out.as_bytes()).await;
                let _ = socket.write_all(&plist).await;
                let _ = socket.flush().await;
            });
        }
    });
    (format!("http://{addr}"), received)
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<(String, Vec<(String, String)>, Vec<u8>)> {
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
            let path = lines.next()?.split_whitespace().nth(1)?.to_string();
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
            return Some((path, headers, body));
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn escrow_requests_match_the_python() {
    let d = fixture("escrow/requests.json");
    let anisette: BTreeMap<String, String> = d["anisette"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .collect();

    let (origin, received) = start().await;
    let account = Arc::new(FakeAccount { http: Http::new(Duration::from_secs(5)).unwrap(), anisette });
    let proxy = EscrowProxy::new(account, origin, d["pet"].as_str().unwrap().to_string(), "synthetic@example.invalid".to_string()).unwrap();

    proxy.list_records().await.unwrap();
    proxy
        .srp_init(d["label"].as_str().unwrap(), &(0u8..64).collect::<Vec<u8>>(), d["transaction"].as_str().unwrap())
        .await
        .unwrap();
    proxy
        .recover(
            d["label"].as_str().unwrap(),
            &(0u8..32).collect::<Vec<u8>>(),
            d["transaction"].as_str().unwrap(),
            Some("1234567890"),
        )
        .await
        .unwrap();

    let got = received.lock().unwrap().clone();
    let expected = d["requests"].as_array().unwrap();
    assert_eq!(got.len(), expected.len(), "request count");
    let _ = json!({});
    for (i, (g, w)) in got.iter().zip(expected).enumerate() {
        let expected_path = w["url"].as_str().unwrap().split("://").nth(1).unwrap().split_once('/').map(|(_, p)| format!("/{p}")).unwrap();
        assert_eq!(g.path, expected_path, "request {i} path");
        // The `transactionUUID` is freshly random on both sides; compare everything else exactly.
        let mut got_plist = apple_core::plist::parse_dict(&g.body).unwrap();
        got_plist.remove("transactionUUID");
        let mut want_plist =
            apple_core::plist::parse_dict(&base64::engine::general_purpose::STANDARD.decode(w["body"].as_str().unwrap()).unwrap()).unwrap();
        want_plist.remove("transactionUUID");
        assert_eq!(got_plist, want_plist, "request {i} body");
        // Basic auth `account_name:PET`.
        let expected_auth = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("synthetic@example.invalid:SYNTHETIC-PET")
        );
        let auth = g.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("authorization")).map(|(_, v)| v.clone());
        assert_eq!(auth.as_deref(), Some(expected_auth.as_str()), "request {i} auth");
        for (k, v) in w["headers"].as_object().unwrap() {
            let got = g.headers.iter().find(|(hk, _)| hk.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str());
            assert_eq!(got, Some(v.as_str().unwrap()), "request {i} header {k}");
        }
    }
}
