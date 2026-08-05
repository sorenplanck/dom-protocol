//! Integrated cryptographic and durable-authority boundary for DOM Scriptless Contracts.
//!
//! The crate reuses DOM's authoritative hash, canonical point/scalar parsers,
//! challenge, arithmetic, and verifier. NAR-001 ratifies the canonical context
//! and secret two-nonce derivation implemented here with opaque, one-shot
//! ownership. This crate also owns the storage-independent Nonce Vault
//! contract; durable implementations belong to wallet software and must fail
//! closed when witness or rollback evidence is incomplete.
//!
//! Default downstream code cannot import a reusable secret nonce owner:
//!
//! ```compile_fail
//! use dom_adaptor::SecretNoncePairV1;
//! ```
//!
//! It cannot call deterministic/raw nonce derivation or raw reveal/signing:
//!
//! ```compile_fail
//! use dom_adaptor::{derive_secret_nonce_pair_v1, raw_nonce_reveal_v1,
//!     raw_partial_sign_v1};
//! ```
//!
//! Durable request identifiers cannot be supplied by the application:
//!
//! ```compile_fail
//! use dom_adaptor::ReservationRequestV1;
//! let _request = ReservationRequestV1 { /* private fields */ };
//! ```
//!
//! Prepared and authorized values have no public constructors. Parsing a
//! 252-byte durable record never yields either capability:
//!
//! ```compile_fail
//! use dom_adaptor::{AuthorizedExposureV1, PreparedExposureV1};
//! let prepared = PreparedExposureV1(/* private */);
//! let authorized = AuthorizedExposureV1::from_persisted(prepared);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod adaptor;
mod context;
mod error;
mod messages;
mod nonce;
mod nonce_secret_record;
mod nonce_vault;
mod permit;
mod session;
mod transcript;
mod vault_signer;

pub use adaptor::{AdaptorPreSignatureV1, AdaptorSecret, CoreAdaptorPreSignatureV1};
pub use context::{DirectionV1, SessionContextInputsV1, SessionContextV1, SigningPhaseV1};
pub use error::{AdaptorError, Result};
pub use messages::{NonceCommitmentV1, NonceRevealV1, PartialSignatureV1, PurposeV1};
pub use nonce::{
    aggregate_partial_signatures_v1, aggregate_public_nonces_v1, finalize_plain_signature_v1,
    PublicNoncePairV1,
};
pub use nonce_secret_record::NonceSecretTransferV1;
pub use nonce_vault::{
    AbortReasonV1, AuthorizedExposureV1, BudgetScope, CounterpartyBucket, ExposureBytes,
    ExposurePermitBindingV1, IdempotencyKey, NonceReservation, NonceVaultError, NonceVaultV1,
    ParticipantId, PermitIdV1, PreparedExposureV1, Purpose, ReservationIntentV1,
    ReservationNonceId, ReservationRequestV1, ReservationState, RestoreState, SecretOpenStageV1,
    SessionId, TemplateHash, TerminalReservationV1, VaultExportedArtifactV1, VaultKeyId,
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
pub use vault_signer::{
    CommitmentExportedV1, PartialExportedTerminalV1, ReservedNonceV1, RevealExportedV1,
    VaultBackedSignerError, VaultBackedSignerV1,
};
