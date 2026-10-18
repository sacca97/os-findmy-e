//! Grand Slam password derivation and session-payload decryption (port of
//! `findmy.util.crypto.encrypt_password` and `decrypt_spd_aes_cbc`, plus `util.parsers.decode_plist`'s
//! prolog rule, and `apple/login/GsaCrypto.kt`).
//!
//! The password digest is password-equivalent and is never persisted; the caller holds it in a
//! [`zeroize::Zeroizing`] buffer and this module never logs it.

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const S2K: &str = "s2k";
pub const S2K_FO: &str = "s2k_fo";

type HmacSha256 = Hmac<Sha256>;

/// SHA-256 of the UTF-8 password. The caller is responsible for zeroing the password itself.
pub fn password_digest(password: &[u8]) -> [u8; 32] {
    Sha256::digest(password).into()
}

/// The SRP password `P` from the password digest: PBKDF2-HMAC-SHA256 over the digest (`s2k`) or over
/// its lowercase hex text (`s2k_fo`), 32 bytes. Done over raw bytes so a binary input is not mangled.
pub fn derive_password(digest: &[u8], salt: &[u8], iterations: u32, protocol: &str) -> Result<Vec<u8>> {
    if protocol != S2K && protocol != S2K_FO {
        return Err(Error::Backend(format!("unsupported password protocol {protocol}")));
    }
    let input: Zeroizing<Vec<u8>> = if protocol == S2K_FO {
        Zeroizing::new(hex(digest).into_bytes())
    } else {
        Zeroizing::new(digest.to_vec())
    };
    let mut out = vec![0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(&input, salt, iterations, &mut out);
    Ok(out)
}

/// Decrypts `spd` with keys HMAC-derived from the SRP session key: AES-256-CBC, PKCS#7.
pub fn decrypt_spd(session_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let key = hmac_sha256(session_key, b"extra data key:");
    let iv_full = hmac_sha256(session_key, b"extra data iv:");
    let cipher = cbc::Decryptor::<Aes256>::new((&key).into(), (&iv_full[..16]).into());
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|_| Error::Authentication("the session payload could not be decrypted".into()))
}

/// `decode_plist`: an XML plist missing its prolog gets Python's prolog prepended before parsing.
pub fn with_plist_prolog(data: &[u8]) -> Vec<u8> {
    if data.len() >= 5 && &data[..5] == b"<?xml" {
        return data.to_vec();
    }
    let mut out = PLIST_PROLOG.to_vec();
    out.extend_from_slice(data);
    out
}

const PLIST_PROLOG: &[u8] = b"<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>";

/// `X-Apple-Identity-Token`: base64(adsid ":" GsIdmsToken). A credential.
pub fn identity_token(adsid: &str, idms_token: &str) -> String {
    crate::util::b64(format!("{adsid}:{idms_token}").as_bytes())
}

pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
