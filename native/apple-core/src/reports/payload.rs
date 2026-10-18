//! A location report as Apple returns it (port of `findmy.reports.LocationReport` up to `decrypt`).
//!
//! Layout: `timestamp(4, seconds since 2001-01-01, big-endian) | [extra(1) only in the 89-byte macOS
//! 14+ form] | confidence(1) | ephemeral point(57: 04 || x || y) | AES-GCM ciphertext(10) | tag(16)`.
//! The AES key and 16-byte IV are `SHA-256(ECDH(x) || 00000001 || point)` split 16/16; the 10
//! plaintext bytes are `latitude(i32) | longitude(i32) | accuracy(u8) | status(u8)`, in 1e-7 degrees.

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::reports::crypto;
use crate::reports::keys::KeyPair;

/// `60 * 60 * 24 * 11323`: 2001-01-01T00:00:00Z in Unix seconds.
pub const APPLE_EPOCH_OFFSET: i64 = 978_307_200;

pub struct EncryptedReport {
    pub payload: Vec<u8>,
    pub hashed_adv_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedReport {
    pub timestamp: i64,
    pub confidence: i32,
    pub latitude_micro: i32,
    pub longitude_micro: i32,
    pub horizontal_accuracy: u8,
    pub status: u8,
    pub hashed_adv_key: Vec<u8>,
}

impl DecryptedReport {
    pub fn latitude(&self) -> f64 {
        self.latitude_micro as f64 / 1.0E7
    }

    pub fn longitude(&self) -> f64 {
        self.longitude_micro as f64 / 1.0E7
    }
}

impl EncryptedReport {
    pub fn new(payload: Vec<u8>, hashed_adv_key: Vec<u8>) -> Self {
        EncryptedReport { payload, hashed_adv_key }
    }

    pub fn timestamp(&self) -> Option<i64> {
        if self.payload.len() < 4 {
            return None;
        }
        let secs = u32::from_be_bytes(self.payload[0..4].try_into().unwrap()) as i64;
        Some(secs + APPLE_EPOCH_OFFSET)
    }

    pub fn confidence(&self) -> Option<i32> {
        if self.payload.len() == 88 {
            Some(self.payload[4] as i32)
        } else if self.payload.len() > 5 {
            Some(self.payload[5] as i32)
        } else {
            None
        }
    }

    pub fn can_decrypt(&self, key: &KeyPair) -> bool {
        key.hashed_adv_key_bytes() == self.hashed_adv_key
    }

    pub fn decrypt(&self, key: &KeyPair) -> Result<DecryptedReport> {
        if !self.can_decrypt(key) {
            return Err(Error::Backend("wrong key for this report".into()));
        }
        let mut enc = if self.payload.len() >= 4 {
            self.payload[4..].to_vec()
        } else {
            Vec::new()
        };
        // macOS 14+ reports carry one more byte in front (FindMyFlipper#61).
        if enc.len() == 85 {
            enc = enc[1..].to_vec();
        }
        if enc.len() != 84 {
            return Err(Error::Backend("unexpected report size".into()));
        }
        let ephemeral = &enc[1..58];
        let shared = key.dh_exchange(ephemeral)?;
        let mut h = Sha256::new();
        h.update(&shared);
        h.update([0u8, 0, 0, 1]);
        h.update(ephemeral);
        let symmetric = h.finalize();
        let mut ciphertext_and_tag = enc[58..68].to_vec();
        ciphertext_and_tag.extend_from_slice(&enc[68..84]);
        let plain = crypto::aes_gcm_decrypt(&symmetric[0..16], &symmetric[16..32], &ciphertext_and_tag)?;
        let timestamp = self.timestamp().ok_or_else(|| Error::Backend("unexpected report size".into()))?;
        let confidence = self.confidence().ok_or_else(|| Error::Backend("unexpected report size".into()))?;
        let latitude_micro = i32::from_be_bytes(plain[0..4].try_into().unwrap());
        let longitude_micro = i32::from_be_bytes(plain[4..8].try_into().unwrap());
        Ok(DecryptedReport {
            timestamp,
            confidence,
            latitude_micro,
            longitude_micro,
            horizontal_accuracy: plain[8],
            status: plain[9],
            hashed_adv_key: self.hashed_adv_key.clone(),
        })
    }
}
