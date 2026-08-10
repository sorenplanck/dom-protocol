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

// Single source of truth for the SEC1<->zkp commitment encoding bridge used by
// the final bounded aggregate range-proof backend. Crate-private.
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
mod bulletproof_bp;
#[cfg(kani)]
mod kani_invariants;
pub mod range_proof;
pub mod recovery;
#[cfg(feature = "test-helpers")]
#[doc(hidden)]
pub use bulletproof_bp::bp2_test_only_prove_legacy_single_with_nonce;
pub use range_proof::{
    prove as range_proof_prove, prove_bytes as range_proof_prove_bytes,
    prove_bytes_with_extra_commit as range_proof_prove_bytes_with_extra_commit,
    prove_bytes_with_nonce as range_proof_prove_bytes_with_nonce,
    prove_with_nonce as range_proof_prove_with_nonce, verify as range_proof_verify,
    verify_with_extra_commit as range_proof_verify_with_extra_commit, RangeProof,
    MAX_PROVABLE_VALUE, RANGE_PROOF_SERIALIZATION_VERSION, RANGE_PROOF_SIZE,
};

/// Compatibility alias for the final range-proof byte prover.
pub use range_proof::prove_bytes as bp2_prove;
/// Compatibility alias for the final deterministic range-proof byte prover.
pub use range_proof::prove_bytes_with_nonce as bp2_prove_with_nonce;
/// Compatibility alias for the final range-proof verifier.
pub use range_proof::verify as bp2_verify;
