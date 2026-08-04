//! Phase 1 integration boundary for DOM Scriptless Contracts.
//!
//! This bootstrap contains no cryptographic or vault implementation and exposes
//! no provisional production API. Curve arithmetic, point parsing, challenges,
//! Schnorr signing, canonical serialization, hashing and verification will be
//! imported from the authoritative DOM crates after the normative inputs and
//! frozen vectors satisfy Gate G1.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
