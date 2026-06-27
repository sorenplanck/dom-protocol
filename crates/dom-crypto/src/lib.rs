//! # dom-crypto
//!
//! Cryptographic primitives for the DOM protocol.
//! RFC-0001, RFC-0009: secp256k1, Blake2b-256, Schnorr, H generator, Pedersen.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod h_generator;
pub mod hash;
pub mod keys;
pub mod pedersen;
pub mod schnorr;

// Single source of truth for the SEC1<->zkp commitment encoding bridge, shared
// by the borromean (`bulletproof`) and standard-Bulletproof (`bulletproof_bp`)
// paths. Crate-private.
mod sec1_zkp_bridge;

pub use dom_core::Hash256;
pub use h_generator::{derive_h_generator, h_compressed, verify_h_matches_derivation};
pub use hash::{blake2b_256, blake2b_256_tagged, DomHasher};
pub use keys::{PublicKey, Scalar, SecretKey};
pub use pedersen::{verify_block_balance_equation, BlindingFactor, BlindingFactorOrZero};
pub use schnorr::{
    schnorr_add_public_keys, schnorr_aggregate_sigs, schnorr_challenge, schnorr_partial_sign,
    schnorr_sign, schnorr_verify, PartialSig, SchnorrSignature,
};
pub mod bulletproof;
pub use bulletproof::{prove as bp_prove, verify as bp_verify, RangeProof};

// Standard-Bulletproof backend, exported under distinct `bp2_*` names so it
// cannot be confused with the borromean `bp_prove`/`bp_verify`.
mod bulletproof_bp;
#[cfg(feature = "test-helpers")]
#[doc(hidden)]
pub use bulletproof_bp::bp2_test_only_prove_legacy_single_with_nonce;
/// Standard-Bulletproof (grin backend) range-proof prove/verify, exported as
/// `bp2_prove`/`bp2_verify` (+ `bp2_prove_with_nonce` for deterministic-nonce
/// proofs, e.g. genesis). Parallel to the borromean `bp_prove`/`bp_verify`;
/// produces 739-byte bounded aggregate proofs bound to H_DOM and is wired into
/// consensus as the live standard-Bulletproof path.
pub use bulletproof_bp::{
    bp_prove as bp2_prove, bp_prove_with_nonce as bp2_prove_with_nonce, bp_verify as bp2_verify,
};
