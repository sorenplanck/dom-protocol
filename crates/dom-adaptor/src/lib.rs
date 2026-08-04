//! Production cryptographic boundary for DOM Scriptless Contracts.
//!
//! The crate reuses DOM's authoritative hash, canonical point/scalar parsers,
//! challenge, arithmetic, and verifier. NAR-001 ratifies the canonical context
//! and secret two-nonce derivation implemented here with opaque, one-shot
//! ownership. Persistence and nonce lifecycle policy belong to the G1b
//! `NonceVault` boundary and are not implemented by this G1a module.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod adaptor;
mod context;
mod error;
mod messages;
mod nonce;
mod permit;
mod session;
mod transcript;

pub use adaptor::{AdaptorPreSignatureV1, AdaptorSecret, CoreAdaptorPreSignatureV1};
pub use context::{DirectionV1, SessionContextInputsV1, SessionContextV1, SigningPhaseV1};
pub use error::{AdaptorError, Result};
pub use messages::{NonceCommitmentV1, NonceRevealV1, PartialSignatureV1, PurposeV1};
pub use nonce::{
    aggregate_partial_signatures_v1, aggregate_public_nonces_v1, finalize_plain_signature_v1,
    PublicNoncePairV1,
};
pub use permit::{exposure_outbound_digest_v1, validate_exposure_permit_record_v1, ExposureKindV1};
pub use session::{
    advance_transcript_hash_v1, canonical_template_v1, generate_session_id_v1,
    initial_transcript_hash_v1, session_message_digest_v1, ContractKindV1, ParticipantIdentityV1,
    ParticipantRosterV1, SessionIdRegistryV1, TrustedChainIdV1,
};
pub use transcript::{
    binding_factor_v1, nonce_commitment_hash_v1, BindingContextV1, BindingFactorV1,
    ParticipantPublicNoncesV1,
};
