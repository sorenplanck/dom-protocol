//! # dom-test-vectors
//!
//! Deterministic test vector generation and verification for DOM.
//!
//! All vectors in this crate MUST be:
//! - Reproducible across platforms
//! - Architecture-independent
//! - Generated from the reference implementation
//! - Independently verified before testnet launch
//!
//! ## Vector Categories
//!
//! - Serialization: encoding/decoding of all primitive types
//! - PMMR: roots for 0,1,2,3,4,7,8,15,16 leaf counts
//! - Hash: tagged Blake2b-256 for all domain tags
//! - ASERT: edge cases (RELEASE BLOCKER — table not finalized)
//! - Consensus constants: compile-time verification

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod constants_vectors;
pub mod hash_vectors;
pub mod pmmr_vectors;
pub mod serialization_vectors;
