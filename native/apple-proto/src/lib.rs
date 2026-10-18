//! Generated protobuf types for CloudKit (`cloudkit.proto`) and Cuttlefish (`cuttlefish.proto`).
//!
//! The `.proto` files are copies of `app/proto/*.proto`, authored from the OpenTagViewer protocol
//! specification (see the provenance note at the top of each file). Both use proto2 so that fields
//! explicitly set to their default value are still serialised, which the protocol needs (S4 §3.3).

/// CloudKit client protocol: `findmy.cloudkit`.
pub mod cloudkit {
    include!(concat!(env!("OUT_DIR"), "/findmy.cloudkit.rs"));
}

/// Apple's keychain trust-circle protocol: `findmy.cuttlefish`.
pub mod cuttlefish {
    include!(concat!(env!("OUT_DIR"), "/findmy.cuttlefish.rs"));
}
