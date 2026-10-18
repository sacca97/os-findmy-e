//! Read-only keychain (escrow) recovery: `findmy/keychain/`, `apple/keychain/`.
//!
//! # Read-only by policy
//!
//! Escrow recovery yields the keychain **view keys**, which can decrypt **any** keychain item
//! (passwords, Wi-Fi keys), not only tags. They are the most sensitive material in the app: hold
//! them briefly, zero them after use, never log or persist them. Only the derived tag keys are
//! persisted (by the reports piece). The flow reads only BeaconStore records.
//!
//! `join` (adding a peer to the keychain circle) is **irreversible** and must never be ported or
//! called. Writes (renaming, saving records) are not ported either.
//!
//! # Status
//!
//! The self-contained cryptography of the recovery is ported and tested offline in [`bottle`]:
//! deriving a bottled peer's three keys, matching them against the escrowed ones, parsing a peer's
//! private key, and opening a bottle (HKDF-SHA384, the P-384 extra-random-bits scalar, AES-256-GCM
//! with a detached tag, and both signatures).
//!
//! The network sequence that produces the entropy and the view keys is the remaining part of phase 3:
//! the escrow proxy (`findmy/keychain/escrow.py`), Cuttlefish (`cuttlefish.py`), the key shares
//! (`shares.py`), the keychain view items (`items.py`), the peer directory (`peers.py`) and the
//! session facade (`session.py`). They need `CloudKitApi::function_invoke` ([`crate::cloudkit`]) and
//! the primitives already in `cloudkit::pcs` / `cloudkit::servicekeys`.

pub mod bottle;
pub mod cuttlefish;
pub mod escrow;
pub mod items;
pub mod peers;
pub mod recovery;
pub mod shares;
pub mod session;

use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// The one passcode guess the recovery sends to Apple's escrow proxy. Held briefly and zeroed.
pub type Passcode = Zeroizing<Vec<u8>>;

/// Recovered keychain view keys. Never persisted; zero them after the tag keys are derived.
pub struct ViewKeys {
    pub keys: Zeroizing<Vec<u8>>,
}

/// The read-only recovery operation.
pub trait KeychainRecovery: Send + Sync {
    /// Recovers the keychain view keys with one passcode guess. Never retries automatically.
    fn recover_view_keys<'a>(
        &'a self,
        passcode: &'a Passcode,
    ) -> crate::login::BoxFuture<'a, Result<ViewKeys>>;
}

/// The default implementation: not ported yet, so it refuses rather than guessing at the protocol.
pub struct NotImplementedKeychain;

impl KeychainRecovery for NotImplementedKeychain {
    fn recover_view_keys<'a>(
        &'a self,
        _passcode: &'a Passcode,
    ) -> crate::login::BoxFuture<'a, Result<ViewKeys>> {
        Box::pin(async move {
            Err(Error::NotImplemented(
                "keychain escrow recovery is not ported yet; see native/apple-core/src/keychain".into(),
            ))
        })
    }
}
