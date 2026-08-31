//! Participant-separated, durable Bitcoin actuation for DOM interoperability.
//!
//! The production boundary in this crate never owns both parties' claim keys.
//! Each process holds one route-scoped participant authority, while exact
//! transaction bytes remain in an owner-only durable custody store.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod extraction;
mod model;
mod rpc;
mod signer;
mod store;

pub use extraction::{
    extract_revealed_secret_from_confirmed_claim, extract_revealed_secret_from_confirmed_lookup,
    BitcoinClaimExtractionContextV1, BITCOIN_CLAIM_EXTRACTION_CONTEXT_V1_BYTES,
};

pub use model::{
    BitcoinActionV1, BitcoinActuationScopeAuthorizationV1, BitcoinActuationScopeV1,
    BitcoinBroadcastReceiptV1, BitcoinDurableOperationViewV1, BitcoinFeeBumpPolicyV1,
    BitcoinFundingCustodyViewV1, BitcoinLegV1, BitcoinOperationBindingViewV1,
    BitcoinOperationKindV1, BitcoinOperationLocatorV1, BitcoinOperationStageV1,
    BitcoinOperationViewV1, BitcoinOutpointV1, BitcoinPortCallJournalStatusV1,
    BitcoinPortCallKeyV1, BitcoinPortCallKindV1, BitcoinPortCallOutcomeV1, BitcoinReconciliationV1,
    BitcoinStorageLeaseStatusV1, ExactBitcoinTransactionV1, BITCOIN_PORT_CALL_OUTCOME_V1_BYTES,
};
pub use rpc::{
    BitcoinRpcBroadcastV1, BitcoinRpcErrorV1, BitcoinRpcLookupV1, BitcoinRpcTransactionV1,
    BitcoinRpcV1,
};
#[cfg(feature = "rpc-http")]
pub use rpc::{HttpBitcoinCoreRpcConfigV1, HttpBitcoinCoreRpcV1};
pub use signer::{
    BitcoinAdaptorSecretV1, BitcoinClaimSessionV1, BitcoinLocalPartialV1, BitcoinLocalPubNonceV1,
    BitcoinParticipantClaimAuthorityRequestV1, BitcoinParticipantClaimAuthorityV1,
    BitcoinParticipantRoleV1, BitcoinPreSignatureV1,
};
pub use store::{
    BitcoinClaimSigningContextV1, BitcoinParticipantNonceVaultV1, DurableBitcoinActuatorV1,
};

/// Fail-closed Bitcoin actuator result.
pub type Result<T> = core::result::Result<T, BitcoinActuatorErrorV1>;

/// Canonical commitment to the exact registry-resolved Bitcoin deployment
/// facts used in every actuator scope.
pub fn resolved_bitcoin_deployment_digest_v1(
    deployment: &deployment_registry::ResolvedBitcoinDeploymentV1,
) -> Result<[u8; 32]> {
    model::resolved_deployment_digest(deployment)
}

/// Named failures emitted by the participant-separated Bitcoin actuator.
#[derive(Debug, thiserror::Error)]
pub enum BitcoinActuatorErrorV1 {
    /// A route, effect, action, registry or fencing scope was invalid.
    #[error("invalid Bitcoin actuation scope")]
    InvalidScope,
    /// An exact transaction is malformed, non-canonical or outside bounds.
    #[error("invalid Bitcoin transaction")]
    InvalidTransaction,
    /// Transaction bytes or identity differ from the authorized intent.
    #[error("Bitcoin transaction does not match authorized intent")]
    TransactionMismatch,
    /// A replacement changed protected semantics or violated fee policy.
    #[error("unsafe Bitcoin fee replacement")]
    UnsafeReplacement,
    /// Explicit creation targeted an existing durable database.
    #[error("Bitcoin actuator database already exists")]
    DatabasePresent,
    /// Production reopen targeted a missing durable database.
    #[error("Bitcoin actuator database is missing")]
    DatabaseMissing,
    /// Provisioning stopped after publishing part of the durable authority.
    #[error("Bitcoin actuator database creation is incomplete")]
    CreationIncomplete,
    /// Database or parent is not the exact owner-only storage authority.
    #[error("invalid Bitcoin actuator storage authority")]
    InvalidStorageAuthority,
    /// Durable SQLite storage failed.
    #[error("Bitcoin actuator durable storage unavailable")]
    Storage(#[from] rusqlite::Error),
    /// Stored schema, commitment or lifecycle state is contradictory.
    #[error("corrupt or unsupported Bitcoin actuator state")]
    CorruptState,
    /// Another live process owns the Bitcoin actuator authority.
    #[error("Bitcoin actuator authority lease is already held")]
    LeaseHeld,
    /// A supplied capability has a stale or future fencing epoch.
    #[error("stale Bitcoin actuator fencing capability")]
    StaleFencing,
    /// Time rolled backwards, a duration was zero, or arithmetic overflowed.
    #[error("invalid Bitcoin actuator time")]
    InvalidTime,
    /// The requested effect does not exist.
    #[error("Bitcoin actuator effect not found")]
    EffectNotFound,
    /// An idempotent identity was reused with different immutable facts.
    #[error("Bitcoin actuator idempotency conflict")]
    IdempotencyConflict,
    /// The requested lifecycle mutation is illegal at the current stage.
    #[error("invalid Bitcoin actuator lifecycle transition")]
    InvalidState,
    /// Claim/refund mutual exclusion was already committed to another terminal.
    #[error("conflicting Bitcoin terminal already selected")]
    TerminalConflict,
    /// A send-attempted transaction is absent and remains ambiguous.
    #[error("Bitcoin transaction externalization is ambiguous")]
    ExternalizationAmbiguous,
    /// Takeover requires an explicit live-node reconciliation first.
    #[error("Bitcoin actuator takeover reconciliation required")]
    ReconciliationRequired,
    /// The live node returned unavailable or malformed evidence.
    #[error("Bitcoin RPC authority failed")]
    Rpc(#[from] BitcoinRpcErrorV1),
    /// The live node belongs to another authenticated network/deployment.
    #[error("Bitcoin RPC network identity mismatch")]
    RpcScopeMismatch,
    /// A local participant key or claim transcript disagrees with frozen terms.
    #[error("Bitcoin participant claim authority mismatch")]
    ClaimAuthorityMismatch,
    /// Durable nonce custody refused the claim signing transition.
    #[error("Bitcoin claim nonce custody refused the transition")]
    ClaimNonceCustody,
    /// Cryptographic verification or adaptor signing failed closed.
    #[error("Bitcoin claim cryptography refused the transition")]
    ClaimCryptography,
    /// The exact funding capability did not prove a durable refund.
    #[error("Bitcoin funding refund is not durably armed")]
    FundingNotArmed,
    /// The existing btc-live authority refused funding lifecycle actuation.
    #[error("Bitcoin live funding authority refused the transition")]
    LiveFunding,
}
