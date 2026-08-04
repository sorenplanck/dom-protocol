//! DOM Scriptless Contracts integration boundaries.
//!
//! Cryptographic operations remain owned by DOM's authoritative cryptographic
//! crates. This crate also owns the storage-independent Nonce Vault contract;
//! durable implementations belong to wallet software and must fail closed when
//! witness or rollback evidence is incomplete.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod nonce_vault;

pub use nonce_vault::{
    AbortRequest, BudgetScope, CommitPublicMaterialRequest, ConsumeReason, ConsumeRequest,
    CounterpartyBucket, ExposureAuthorizationRequest, ExposureBytes, ExposureKindV1,
    ExposurePermitBindingV1, IdempotencyKey, NonceReservation, NonceVault, NonceVaultError,
    ParticipantId, Purpose, PurposeV1, ReservationNonceId, ReservationRequest, ReservationState,
    RestoreState, RetryRequest, SessionId, TemplateHash, VaultExposurePermit, VaultKeyId,
    VaultReceipt,
};
