//! # dom-crypto
//!
//! Cryptographic primitives for the DOM protocol.
//! RFC-0001, RFC-0009: secp256k1, Blake2b-256, Schnorr, H generator, Pedersen.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod hash;
pub mod keys;
pub mod schnorr;
pub mod h_generator;
pub mod pedersen;

pub use hash::{blake2b_256, blake2b_256_tagged, DomHasher};
pub use keys::{PublicKey, SecretKey, Scalar};
pub use schnorr::{SchnorrSignature, schnorr_challenge, schnorr_sign, schnorr_verify};
pub use h_generator::{derive_h_generator, verify_h_matches_derivation, h_compressed};
pub use pedersen::BlindingFactorOrZero;
pub mod bulletproof;
pub use bulletproof::{prove as bp_prove, verify as bp_verify, RangeProof};
