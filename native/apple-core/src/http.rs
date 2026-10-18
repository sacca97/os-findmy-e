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
        // gsa.apple.com refuses a second request on an already-answered connection.
        if host == "gsa.apple.com" {
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
        let mut builder = self.provisioning.request(method, url);
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
    fn the_bundled_root_matches_its_hash() {
        assert!(verified_apple_root_der().is_ok());
    }
}
