//! The Rust-native HTTP client. TLS is `rustls` with the bundled web roots **plus** Apple's 2006
//! "Apple Root CA" (which `gsa.apple.com` chains to and most stores lack), checked against its
//! SHA-256 before it is trusted. Verification stays on.
//!
//! Two clients, as the Python/Kotlin do: a pooled default, and an unpooled HTTP/1.1 one for
//! `gsa.apple.com` (a pooled `complete` after `init` was measured to be answered 429). Nothing here
//! depends on Android's certificate APIs, so the same code runs on a desktop.

use std::time::Duration;

use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Apple Root CA, serial 2, valid 2006-2035 (<https://www.apple.com/appleca/>).
pub const APPLE_ROOT_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
UKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----
";

/// SHA-256 of the DER of [`APPLE_ROOT_CA_PEM`].
pub const APPLE_ROOT_CA_SHA256: &str = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024";

/// The PEM body as DER, after checking it hashes to [`APPLE_ROOT_CA_SHA256`].
pub fn verified_apple_root_der() -> Result<Vec<u8>> {
    let body: String = APPLE_ROOT_CA_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|_| Error::Backend("the bundled Apple root is not base64".into()))?;
    let digest = hex(&Sha256::digest(&der));
    if digest != APPLE_ROOT_CA_SHA256 {
        return Err(Error::Backend(format!(
            "the bundled Apple root hashes to {digest}, not {APPLE_ROOT_CA_SHA256}; refusing to trust it"
        )));
    }
    Ok(der)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A response, with its body already read.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub body: Vec<u8>,
    /// The host the request went to (for error messages).
    pub host: String,
}

impl Response {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Hosts that answer 429 to a second request on a connection they already answered: `gsa.apple.com` (measured, init then
/// complete) and the escrow proxy `p<partition>-escrowproxy.icloud.com`, whose passcode recovery is the same shape
/// (`srp_init` then `recover` on one host). Requests to them get a fresh connection each and `Connection: close`.
pub fn no_reuse_host(host: &str) -> bool {
    let host = host.split(':').next().unwrap_or(host); // `host_of` keeps the port: "p25-escrowproxy.icloud.com:443"
    host == "gsa.apple.com" || (host.ends_with("-escrowproxy.icloud.com") && host.starts_with('p'))
}

/// The default and unpooled clients. Construction is cheap enough to do once per facade.
#[derive(Clone)]
pub struct Http {
    default: reqwest::Client,
    unpooled: reqwest::Client,
    /// `unpooled` without following redirects (the provisioning `GsService2/lookup`, as `GsaClient`).
    provisioning: reqwest::Client,
}

impl Http {
    pub fn new(timeout: Duration) -> Result<Http> {
        let root = reqwest::Certificate::from_der(&verified_apple_root_der()?)
            .map_err(|e| Error::Backend(format!("Apple root certificate: {e}")))?;
        let default = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(10))
            .add_root_certificate(root.clone())
            .build()
            .map_err(|e| Error::Backend(format!("HTTP client: {e}")))?;
        let unpooled = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(0)
            .http1_only()
            .add_root_certificate(root.clone())
            .build()
            .map_err(|e| Error::Backend(format!("HTTP client: {e}")))?;
        let provisioning = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(0)
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(root)
            .build()
            .map_err(|e| Error::Backend(format!("HTTP client: {e}")))?;
        Ok(Http { default, unpooled, provisioning })
    }

    /// A client suitable for `host`.
    pub fn for_host(&self, host: &str) -> &reqwest::Client {
        if no_reuse_host(host) {
            &self.unpooled
        } else {
            &self.default
        }
    }

    pub fn provisioning_client(&self) -> &reqwest::Client {
        &self.provisioning
    }

    /// One request through the provisioning client (HTTP/1.1, no reuse, no redirects), whose body
    /// defaults to `application/x-www-form-urlencoded` because AuthKit sends an XML plist that way.
    pub async fn provisioning_send(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<Response> {
        let host = host_of(url);
        let method = if body.is_some() { reqwest::Method::POST } else { reqwest::Method::GET };
        let mut builder = self.provisioning.request(method, url).header(reqwest::header::CONNECTION, "close");
        for (k, v) in headers {
            builder = builder.header(k, v);
        }
        if let Some(b) = body {
            builder = builder
                .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(b);
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| Error::Network(format!("{host}: {e}")))?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::Network(format!("{host}: {e}")))?
            .to_vec();
        Ok(Response { status, headers, body, host })
    }

    pub fn default_client(&self) -> &reqwest::Client {
        &self.default
    }

    /// One request. `headers` are set on top of the client defaults; a `Content-Type` header is put
    /// on the body itself (so a caller never has to pass a media type separately).
    pub async fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
        basic_auth: Option<(&str, &str)>,
    ) -> Result<Response> {
        let host = host_of(url);
        let client = self.for_host(&host);
        let mut builder = client.request(method, url);
        if no_reuse_host(&host) {
            // As FindMy.py's `TCPConnector(force_close=True)`: the connection ends with this response.
            builder = builder.header(reqwest::header::CONNECTION, "close");
        }
        for (k, v) in headers {
            builder = builder.header(k, v);
        }
        if let Some((u, p)) = basic_auth {
            builder = builder.basic_auth(u, Some(p));
        }
        if let Some(b) = body {
            builder = builder.body(b);
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| Error::Network(format!("{host}: {e}")))?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::Network(format!("{host}: {e}")))?
            .to_vec();
        Ok(Response { status, headers, body, host })
    }
}

pub fn host_of(url: &str) -> String {
    url.split("://")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .unwrap_or(url)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gsa_and_the_escrow_proxy_get_no_connection_reuse() {
        assert!(no_reuse_host("gsa.apple.com"));
        assert!(no_reuse_host("p25-escrowproxy.icloud.com"));
        assert!(no_reuse_host("p25-escrowproxy.icloud.com:443"));
        assert!(!no_reuse_host("gateway.icloud.com"));
        assert!(!no_reuse_host("setup.icloud.com"));
        assert!(!no_reuse_host("evil-escrowproxy.icloud.com.example.org"));
    }

    #[test]
    fn the_bundled_root_matches_its_hash() {
        assert!(verified_apple_root_der().is_ok());
    }

    /// A loopback HTTP/1.1 server that, like `gsa.apple.com`'s edge, answers 429 to a second request on a connection it
    /// already answered. Returns its URL and how many TCP connections it accepted.
    async fn reuse_refusing_server() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/x", listener.local_addr().unwrap());
        let accepted = std::sync::Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut served = 0;
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                        let status = if served == 0 { "200 OK" } else { "429 Too Many Requests" };
                        served += 1;
                        let reply = format!("HTTP/1.1 {status}\r\nContent-Length: 2\r\n\r\nok");
                        if sock.write_all(reply.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (url, accepted)
    }

    async fn two_requests(client: &reqwest::Client) -> (u16, u16) {
        let (url, accepted) = reuse_refusing_server().await;
        let a = client.post(&url).body("init").send().await.unwrap().status().as_u16();
        let b = client.post(&url).body("complete").send().await.unwrap().status().as_u16();
        let _ = accepted;
        (a, b)
    }

    /// Through `Http::send`/`provisioning_send` themselves (not just the client): two requests, two connections.
    #[tokio::test]
    async fn send_opens_a_new_connection_per_request_for_gsa_paths() {
        use std::sync::atomic::Ordering;
        let http = Http::new(Duration::from_secs(5)).unwrap();
        let (url, accepted) = reuse_refusing_server().await;
        for body in ["init", "complete"] {
            let r = http.provisioning_send(&url, vec![], Some(body.as_bytes().to_vec())).await.unwrap();
            assert_eq!(r.status, 200, "provisioning_send {body}");
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn gsa_clients_never_reuse_a_connection() {
        let http = Http::new(Duration::from_secs(5)).unwrap();
        for _ in 0..5 {
            assert_eq!(two_requests(http.for_host("gsa.apple.com")).await, (200, 200), "unpooled");
            assert_eq!(two_requests(http.provisioning_client()).await, (200, 200), "provisioning");
        }
    }

    /// Control: the pooled default client does reuse, so the server above really does reproduce the failure.
    #[tokio::test]
    async fn the_pooled_client_would_hit_the_429() {
        let http = Http::new(Duration::from_secs(5)).unwrap();
        assert_eq!(two_requests(http.default_client()).await, (200, 429));
    }
}
