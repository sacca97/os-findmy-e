//! Recovering a bottled peer from an escrow record with a device passcode (port of
//! `findmy/keychain/recovery.py`).
//!
//! The SRP exchange and the two blob layers are offline and deterministic given the challenge and the
//! passcode. The passcode here is used twice (SRP password and PBKDF2 input) and is never retained.

use aes::Aes256;
use base64::Engine as _;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::keychain::escrow::{build_keyvault_message, split_keyvault_message, KeyVaultSection};

/// §6.2: the header of an `srp_init` reply is two 32-bit values then a 16-byte request id.
pub const SRP_INIT_HEADER_LENGTH: usize = 24;
pub const SRP_INIT_SECTIONS: usize = 3;
/// §6.3: the two values rewritten into that header before it is sent back.
pub const RECOVERY_MAGIC: u32 = 165;
pub const RECOVERY_CLUB_TYPE: i64 = 1;
/// §6.3: the exchange token's section occupies twenty bytes.
pub const EXCHANGE_TOKEN_FOOTPRINT: usize = 20;
/// §6.4: the reply header is longer when a club type is in play.
pub const RECOVER_HEADER_LENGTH: usize = 24;
pub const RECOVER_HEADER_LENGTH_CLUB: usize = 40;
pub const RECOVER_SECTIONS: usize = 3;
/// §6.5: the innermost blob.
pub const INNER_HEADER_LENGTH: usize = 16;
pub const INNER_SECTIONS: usize = 6;
pub const INNER_KEY_LENGTH: usize = 16;
pub const INNER_IV_LENGTH: usize = 16;
pub const BLOB_VERSION_CBC: i64 = 0;
pub const BLOB_VERSION_UNKNOWN: i64 = 1;
pub const BLOB_VERSION_GCM: i64 = 2;
pub const GCM_NONCE_LENGTH: usize = 16;
pub const GCM_TAG_LENGTH: usize = 16;

fn recovery_error(message: impl Into<String>) -> Error {
    Error::Backend(message.into())
}

/// Read a blob from a property-list response: base64 text, or raw bytes.
pub fn blob_bytes(value: &serde_json::Value) -> Result<Vec<u8>> {
    match value {
        serde_json::Value::String(s) => base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| recovery_error(format!("a blob is a string but not valid base64: {e}"))),
        serde_json::Value::Null => Err(recovery_error("a blob is missing")),
        other => Err(recovery_error(format!("a blob is {other}, which is neither bytes nor base64 text"))),
    }
}

/// What the escrow proxy answers `srp_init` with.
#[derive(Debug, Clone)]
pub struct RecoveryChallenge {
    pub label: String,
    pub transaction_id: String,
    pub prefix: Vec<u8>,
    pub header: Vec<u8>,
    pub exchange_token: Vec<u8>,
    pub salt: Vec<u8>,
    pub server_public: Vec<u8>,
    pub dsid: String,
    pub club_type_id: Option<i64>,
}

pub fn parse_challenge(response: &serde_json::Value, label: &str, transaction_id: &str) -> Result<RecoveryChallenge> {
    let blob = response.get("respBlob").filter(|v| !v.is_null()).ok_or_else(|| recovery_error("srp_init returned no respBlob"))?;
    let dsid = response
        .get("dsid")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| recovery_error("srp_init returned no dsid, which is the SRP identity"))?;
    let (prefix, header, sections) = split_keyvault_message(&blob_bytes(blob)?, SRP_INIT_HEADER_LENGTH, SRP_INIT_SECTIONS)?;
    Ok(RecoveryChallenge {
        label: label.to_string(),
        transaction_id: transaction_id.to_string(),
        prefix,
        header,
        exchange_token: sections[0].clone(),
        salt: sections[1].clone(),
        server_public: sections[2].clone(),
        dsid: dsid.to_string(),
        club_type_id: response.get("clubTypeID").and_then(|v| v.as_i64()),
    })
}

/// Frame an SRP proof the way the `recover` command expects it.
pub fn build_recovery_proof(challenge: &RecoveryChallenge, proof: &[u8]) -> Result<Vec<u8>> {
    let mut header = challenge.header.clone();
    header[0..4].copy_from_slice(&RECOVERY_MAGIC.to_be_bytes());
    header[4..8].copy_from_slice(
        &(if challenge.club_type_id == Some(RECOVERY_CLUB_TYPE) { 2u32 } else { 0u32 }).to_be_bytes(),
    );
    build_keyvault_message(
        &header,
        &[KeyVaultSection::with_footprint(challenge.exchange_token.clone(), EXCHANGE_TOKEN_FOOTPRINT), KeyVaultSection::new(proof.to_vec())],
    )
}

/// Decrypt the outer blob a successful `recover` returns.
pub fn unwrap_outer_blob(blob: &[u8], session_key: &[u8], club_type_id: Option<i64>) -> Result<Vec<u8>> {
    let header_length = if club_type_id == Some(RECOVERY_CLUB_TYPE) {
        RECOVER_HEADER_LENGTH_CLUB
    } else {
        RECOVER_HEADER_LENGTH
    };
    let (header, sections) = crate::keychain::escrow::parse_keyvault_message(blob, header_length, RECOVER_SECTIONS)?;
    let version = u32::from_be_bytes(header[4..8].try_into().unwrap()) as i64;
    let iv = &sections[1];
    let ciphertext = &sections[2];

    if version == BLOB_VERSION_CBC {
        let plaintext = aes_cbc_decrypt(session_key, iv, ciphertext)?;
        return Ok(strip_padding(&plaintext));
    }
    if version == BLOB_VERSION_GCM {
        if iv.len() != GCM_NONCE_LENGTH {
            tracing::warn!("Expected a {GCM_NONCE_LENGTH}-byte GCM nonce, got {}", iv.len());
        }
        if ciphertext.len() < GCM_TAG_LENGTH {
            return Err(recovery_error("The outer GCM blob is shorter than its tag"));
        }
        let (body, tag) = ciphertext.split_at(ciphertext.len() - GCM_TAG_LENGTH);
        return crate::crypto::aes_gcm_decrypt(session_key, iv, &[], body, tag)
            .map_err(|_| recovery_error("Outer blob failed to authenticate under the SRP session key"));
    }
    if version == BLOB_VERSION_UNKNOWN {
        return Err(recovery_error(
            "The outer blob announces version 1, which this specification does not describe. Refusing rather than guessing at a cipher.",
        ));
    }
    Err(recovery_error(format!("The outer blob announces unknown version {version}")))
}

/// Decrypt the innermost blob, which is where the passcode is spent a second time.
pub fn unwrap_inner_blob(blob: &[u8], passcode: &str) -> Result<Vec<u8>> {
    let (header, sections) = crate::keychain::escrow::parse_keyvault_message(blob, INNER_HEADER_LENGTH, INNER_SECTIONS)?;
    let iterations = u32::from_be_bytes(header[8..12].try_into().unwrap());
    if iterations == 0 {
        return Err(recovery_error(format!(
            "The inner blob asks for {iterations} PBKDF2 iterations, which cannot be right"
        )));
    }
    let salt = &sections[1];
    let mut derived = [0u8; INNER_KEY_LENGTH];
    pbkdf2::pbkdf2_hmac::<Sha256>(passcode.as_bytes(), salt, iterations, &mut derived);

    let plaintext = aes_cbc_decrypt(&derived, &salt[..INNER_IV_LENGTH], &sections[3])?;
    Ok(strip_padding(&plaintext))
}

/// Remove PKCS#7 padding if it is there, and leave the data alone if it is not.
pub fn strip_padding(plaintext: &[u8]) -> Vec<u8> {
    let Some(&last) = plaintext.last() else { return plaintext.to_vec() };
    let padding = last as usize;
    if padding == 0 || padding > 16 || padding > plaintext.len() {
        return plaintext.to_vec();
    }
    if plaintext[plaintext.len() - padding..].iter().all(|b| *b as usize == padding) {
        plaintext[..plaintext.len() - padding].to_vec()
    } else {
        plaintext.to_vec()
    }
}

/// AES-CBC decryption with no unpadding (the padding scheme is not stated, so callers strip it).
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        return Err(recovery_error("CBC ciphertext is not a multiple of the block size"));
    }
    let mut buf = data.to_vec();
    match key.len() {
        16 => {
            let mut decryptor = cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into());
            for chunk in buf.chunks_exact_mut(16) {
                decryptor.decrypt_block_mut(aes::Block::from_mut_slice(chunk));
            }
        }
        32 => {
            let mut decryptor = cbc::Decryptor::<Aes256>::new(key.into(), iv.into());
            for chunk in buf.chunks_exact_mut(16) {
                decryptor.decrypt_block_mut(aes::Block::from_mut_slice(chunk));
            }
        }
        _ => return Err(recovery_error("AES key must be 16 or 32 bytes")),
    }
    Ok(buf)
}

/// Recover the sealed material an escrow record holds (`recover_bottled_peer`).
///
/// The passcode is used twice: once as the SRP password and again as a PBKDF2 input. It is not stored or
/// retained past this call. A wrong passcode and a mis-parameterised SRP exchange fail identically.
pub async fn recover_bottled_peer(
    proxy: &dyn crate::keychain::escrow::EscrowCommands,
    record: &crate::keychain::escrow::EscrowRecord,
    passcode: &str,
) -> Result<Vec<u8>> {
    use crate::login::srp::SrpClient;

    if !record.is_recovery_candidate() {
        return Err(recovery_error(format!(
            "{} carries no bottle, so there is nothing to recover from it.",
            record.label
        )));
    }
    if passcode.is_empty() {
        return Err(recovery_error("A passcode is required; the escrowed material is encrypted under it"));
    }

    let transaction_id = upper_uuid();
    use rand::RngCore;
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let mut padded = vec![0u8; 256 - 32];
    padded.extend_from_slice(&secret);

    let mut srp = SrpClient::new_standard("", &padded);
    let client_public = srp.public_a();

    let response = proxy.srp_init(&record.label, &client_public, &transaction_id).await?;
    let challenge = parse_challenge(&response, &record.label, &transaction_id)?;
    srp.set_username(challenge.dsid.clone());

    let proof = srp
        .process_challenge(&challenge.salt, &challenge.server_public, passcode.as_bytes())
        .ok_or_else(|| recovery_error("Could not compute an SRP proof from the challenge"))?;

    let response = proxy
        .recover(&record.label, &build_recovery_proof(&challenge, &proof)?, &transaction_id, Some(&challenge.dsid))
        .await
        .map_err(|e| recovery_error(format!("{e}. The passcode or the exchange is wrong; the two are indistinguishable here.")))?;

    let blob = response
        .get("respBlob")
        .filter(|v| !v.is_null())
        .ok_or_else(|| recovery_error("recover returned no respBlob"))
        .and_then(blob_bytes)?;

    let header_length = if challenge.club_type_id == Some(RECOVERY_CLUB_TYPE) {
        RECOVER_HEADER_LENGTH_CLUB
    } else {
        RECOVER_HEADER_LENGTH
    };
    let (_, _, sections) = split_keyvault_message(&blob, header_length, RECOVER_SECTIONS)?;
    if !srp.verify_session(Some(&sections[0])) {
        return Err(recovery_error(
            "The escrow proxy's proof did not verify. Either the passcode is wrong or this exchange is mis-parameterised; the two are indistinguishable here.",
        ));
    }
    let session_key = srp.session_key().ok_or_else(|| recovery_error("SRP produced no session key"))?;

    let outer = unwrap_outer_blob(&blob, session_key, challenge.club_type_id)?;
    unwrap_inner_blob(&outer, passcode)
}

fn upper_uuid() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}
