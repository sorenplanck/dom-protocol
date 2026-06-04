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
