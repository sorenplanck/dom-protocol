//! `btc` adapter — the Bitcoin leg of DOM Interop (Annex M v3.2, F5).
//!
//! This crate implements the Bitcoin side of a DOM↔BTC settlement:
//! canonical types and the DOMBTC wire codec (M.1/M.3/M.4/M.5), the
//! Taproot contract and templates (M.2/M.3), the MuSig2 2-of-2 adaptor
//! rounds (M.6), observation and evidence (M.9) — in the mandatory build
//! order of M.17.
//!
//! Boundary invariants inherited from the Foundation Document:
//! - I9: chain evidence is only interpreted here; the core consumes only
//!   `VerifiedOutcome`.
//! - I10: an unknown capability or divergent version fails closed.
//! - I11: a reorg is an observable event, never a panic.
//!
//! Secret material (`t`, session_secrand, secnonce, shares, seeds) never
//! appears in `Debug`, `Display`, errors, logs or persisted bytes of this
//! crate (M.10.1, M.21).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod codec;
pub mod error;
pub mod roster;
pub mod scalar;
pub mod templates;
pub mod timelock;
pub mod types;

// The Taproot contract construction needs the pinned crypto backend
// (KeyAgg + TapTweak), and the sighash needs the audited `bitcoin` crate;
// both are gated on the feature that pulls those in. The pure-Rust
// codec/types/timelock/templates above build without it.
#[cfg(feature = "real-bitcoin-crypto")]
pub mod rounds;
#[cfg(feature = "real-bitcoin-crypto")]
pub mod sighash;
#[cfg(feature = "real-bitcoin-crypto")]
pub mod taproot;
