//! Small shared cryptographic helpers: AES-GCM decryption with an arbitrary IV length and tag
//! length (the protocol uses 12-byte tags in PCS fields and 16-byte tags in bottles, and IVs that
//! are not the 12-byte default).

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes::Aes256;

use crate::error::{Error, Result};

fn gcm_error(message: impl Into<String>) -> Error {
    Error::Backend(message.into())
}

fn aes128_encrypt_block(key: &[u8], block: &mut [u8; 16]) {
    let cipher = Aes128::new_from_slice(key).expect("AES-128 key");
    let mut b = aes::Block::clone_from_slice(block);
    cipher.encrypt_block(&mut b);
    block.copy_from_slice(&b);
}

fn aes256_encrypt_block(key: &[u8], block: &mut [u8; 16]) {
    let cipher = Aes256::new_from_slice(key).expect("AES-256 key");
    let mut b = aes::Block::clone_from_slice(block);
    cipher.encrypt_block(&mut b);
    block.copy_from_slice(&b);
}

fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> u128 {
    let mut len = [0u8; 16];
    len[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    // AAD and ciphertext are padded to block boundaries SEPARATELY, then the length block.
    let mut blocks = pad16(aad);
    blocks.extend_from_slice(&pad16(ciphertext));
    blocks.extend_from_slice(&len);
    ghash_raw(h, &blocks)
}

/// The raw GHASH function over an already-padded message (no length block of its own).
fn ghash_raw(h: &[u8; 16], data: &[u8]) -> u128 {
    use ghash::{GHash, Key};
    use universal_hash::{KeyInit, UniversalHash};
    let mut g = GHash::new(Key::from_slice(h));
    let blocks: Vec<ghash::Block> = data.chunks(16).map(|c| *ghash::Block::from_slice(c)).collect();
    g.update(&blocks);
    let out: [u8; 16] = g.finalize().into();
    u128::from_be_bytes(out)
}

fn pad16(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    while out.len() % 16 != 0 {
        out.push(0);
    }
    out
}

/// The GCM counter block `J0` for any IV length, per NIST SP 800-38D.
fn j0(h: &[u8; 16], iv: &[u8]) -> [u8; 16] {
    if iv.len() == 12 {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        j0
    } else {
        // GHASH_H(IV || 0^(s+64) || [len(IV)]_64), s = 128*ceil(len(IV)/128) - len(IV).
        let s = (16 - iv.len() % 16) % 16;
        let mut data = iv.to_vec();
        data.extend(std::iter::repeat(0).take(s + 8));
        data.extend_from_slice(&((iv.len() as u64) * 8).to_be_bytes());
        ghash_raw(h, &pad16(&data)).to_be_bytes()
    }
}

fn inc32(block: &mut [u8; 16]) {
    let counter = u32::from_be_bytes(block[12..16].try_into().unwrap()).wrapping_add(1);
    block[12..16].copy_from_slice(&counter.to_be_bytes());
}

/// AES-GCM decryption with a detached tag of any length (PCS uses 12 bytes, bottles 16) and any IV
/// length. `ciphertext` does not include the tag.
pub fn aes_gcm_decrypt(key: &[u8], iv: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    if tag.is_empty() || tag.len() > 16 {
        return Err(gcm_error("bad GCM tag length"));
    }
    let encrypt = |key: &[u8], block: &mut [u8; 16]| match key.len() {
        16 => aes128_encrypt_block(key, block),
        32 => aes256_encrypt_block(key, block),
        _ => panic!("AES key must be 16 or 32 bytes"),
    };
    let mut h_block = [0u8; 16];
    encrypt(key, &mut h_block);
    let j0 = j0(&h_block, iv);
    let s = ghash(&h_block, aad, ciphertext);
    let mut mask = j0;
    encrypt(key, &mut mask);
    let expected = (u128::from_be_bytes(mask) ^ s).to_be_bytes();
    if !constant_time_eq(&expected[..tag.len()], tag) {
        return Err(gcm_error("authentication failed"));
    }

    let mut out = Vec::with_capacity(ciphertext.len());
    let mut counter = j0;
    for chunk in ciphertext.chunks(16) {
        inc32(&mut counter);
        let mut keystream = counter;
        encrypt(key, &mut keystream);
        for (i, byte) in chunk.iter().enumerate() {
            out.push(byte ^ keystream[i]);
        }
    }
    Ok(out)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}
