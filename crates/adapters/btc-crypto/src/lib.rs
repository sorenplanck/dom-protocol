//! Safe cryptographic backend of the Bitcoin leg (Annex M v3.2, M.1.2).
//!
//! The single place in the F5 stack that wraps the pinned secp256k1-zkp
//! FFI. `unsafe` lives only here, isolated to the smallest surface with a
//! SAFETY contract on every block; everything above is
//! `#![forbid(unsafe_code)]` and consumes only the safe API below.
//!
//! Self-verification discipline (M.1.2): FFI success is never treated as
//! cryptographic proof — every partial is verified, the pre-signature is
//! proved non-final, the adapted signature is BIP340-verified, and the
//! extracted secret is checked against `t·G == T`.

mod context;
mod error;
mod keyagg;
mod musig;
mod primitives;

pub use context::SecpContext;
pub use error::BtcCryptoError;
pub use keyagg::{KeyAggContext, Parity, TaprootTweak};
pub use musig::{MusigSession, NonceParity, PublicNonce, SecNonce};
