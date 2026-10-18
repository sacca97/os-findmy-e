//! The Apple-side Find My protocol, in Rust. One crate, one module per area: `http`, `plist`,
//! `gsa` (provisioning, resync), `login` (SRP, 2FA, tokens, PET), `reports` (key derivation,
//! fetch, decryption), `cloudkit`, `keychain` (read-only escrow recovery) and `session` (the
//! facade the host uses).
//!
//! State is host-stored: no call here persists anything; see [`session`].

pub mod anisette;
pub mod cloudkit;
pub mod crypto;
pub mod error;
pub mod gsa;
pub mod http;
pub mod keychain;
pub mod login;
pub mod plist;
pub mod reports;
pub mod session;
pub mod util;

pub use error::{Error, GrandSlamStep, Result};
