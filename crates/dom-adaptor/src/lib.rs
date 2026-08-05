//! Production cryptographic boundary for DOM Scriptless Contracts.
//!
//! The crate reuses DOM's authoritative hash, canonical point/scalar parsers,
//! challenge, arithmetic, and verifier. It does not derive secret nonces: the
//! two-nonce KDF remains blocked pending a frozen independent specification.
//! Persistence and nonce lifecycle policy belong to the `NonceVault` boundary
//! and are not implemented by this G1a module.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod adaptor;
mod error;
mod messages;
mod transcript;

pub use adaptor::{AdaptorPreSignatureV1, AdaptorSecret};
pub use error::{AdaptorError, Result};
pub use messages::{NonceCommitmentV1, NonceRevealV1, PartialSignatureV1, PurposeV1};
pub use transcript::{
    binding_factor_v1, nonce_commitment_hash_v1, BindingContextV1, BindingFactorV1,
    ParticipantPublicNoncesV1,
};
