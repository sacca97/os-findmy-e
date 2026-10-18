//! Reports: accessory key derivation, the alignment bookkeeping, the report fetch and decryption.
//!
//! Ports `findmy.accessory`, `findmy.keys` and `findmy.reports` as far as fetching and decrypting
//! locations requires; the Kotlin is `apple/reports/`.

pub mod client;
pub mod crypto;
pub mod keys;
pub mod payload;

pub use client::{AccountContext, KeyIds, LocationReport, ReportClient, ReportFetchResult};
pub use keys::{AccessoryKeys, KeyPair, KeyPairType};
pub use payload::{DecryptedReport, EncryptedReport};
