//! Durable, scoped EIP-1559 transaction authority for DOM interoperability.
//!
//! This crate deliberately owns no signing key and stores no endpoint or
//! credential. It validates authenticated EVM calls, reserves account nonces,
//! persists signed raw transactions before broadcast and exposes signing and
//! RPC only through action-specific authority traits.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod model;
mod rpc;
mod store;
mod transaction;

pub use model::{
    BroadcastDispositionV1, BroadcastOutcomeV1, Digest32, Eip1559SignatureV1,
    Eip1559SigningRequestV1, EvmActuatorLeaseV1, EvmAddressV1, EvmAttemptViewV1, EvmClaimSecretV1,
    EvmFeesV1, EvmObservationMutationRequestV1, EvmOperationBindingViewV1, EvmOperationKindV1,
    EvmOperationMutationRequestV1, EvmOperationPreparationRequestV1, EvmOperationViewV1,
    EvmRefundAuthorizationViewV1, EvmRetainedMutationKindV1, EvmSignerRoleV1, EvmTxStageV1,
    LeaseAcquireOutcomeV1, MutationOutcomeV1, MutationStatusV1, NonceSnapshotV1,
    ReconciliationKindV1, RemoteEvmActionCustodyAcquireOutcomeV1, RemoteEvmActionCustodyV1,
    RemoteEvmActionMutationRequestV1, RemoteEvmActionRequestInputV1, RemoteEvmActionRequestV1,
    RemoteEvmObservationMutationRequestV1, RemoteEvmOperationCustodyResumeInputV1,
    RemoteEvmSignedActionV1, ScopedEip1559SignerV1, ScopedEvmClaimV1, ScopedEvmOpenV1,
    ScopedEvmRefundV1, SignerRefusalV1,
};
pub use rpc::{
    EvmRpcErrorV1, EvmRpcV1, RpcAllowanceV1, RpcFinalizedTimeV1, RpcLogV1, RpcPendingNonceV1,
    RpcReceiptLookupV1, RpcReceiptV1, RpcTransactionLookupV1, RpcTransactionV1,
    MAX_RPC_RESPONSE_BYTES_V1,
};
#[cfg(feature = "rpc-http")]
pub use rpc::{HttpEvmRpcTimeoutsV1, HttpEvmRpcV1};
pub use store::DurableEvmActuatorV1;
pub use transaction::{
    remote_claim_unsigned_call_digest_v1, remote_open_unsigned_call_digest_v1,
    remote_refund_unsigned_call_digest_v1, remote_signed_raw_digest_v1,
};

/// Fail-closed actuator result.
pub type Result<T> = core::result::Result<T, EvmActuatorErrorV1>;

/// All named durable EVM actuator refusals.
#[derive(Debug, thiserror::Error)]
pub enum EvmActuatorErrorV1 {
    /// A route/effect/deployment capability contains a zero or invalid field.
    #[error("invalid EVM actuation scope")]
    InvalidScope,
    /// The unsigned call disagrees with authenticated deployment or ABI facts.
    #[error("unsigned EVM call does not match authenticated scope")]
    CallScopeMismatch,
    /// Fee tuple is zero, internally inconsistent or exceeds policy.
    #[error("invalid EIP-1559 fee policy")]
    InvalidFeePolicy,
    /// Typed transaction fields are invalid or outside frozen bounds.
    #[error("invalid EIP-1559 transaction")]
    InvalidTransaction,
    /// Recoverable signature is malformed or has invalid parity/scalars.
    #[error("invalid EIP-1559 signature")]
    InvalidSignature,
    /// Signature uses the malleable high-s form.
    #[error("EIP-1559 signature is not low-s")]
    HighSignatureS,
    /// Signature does not recover the authenticated account for this action.
    #[error("EIP-1559 signature recovered the wrong authenticated account")]
    WrongSigner,
    /// Claim scalar is zero, outside the secp256k1 scalar field or does not
    /// open the adaptor address committed by the lock.
    #[error("invalid EVM claim secret")]
    InvalidClaimSecret,
    /// A bounded field or arithmetic operation exceeded its limit.
    #[error("EVM actuator bound exceeded")]
    BoundExceeded,
    /// Explicit creation targeted an existing database.
    #[error("EVM actuator database already exists")]
    DatabasePresent,
    /// Production open targeted a missing database.
    #[error("EVM actuator database is missing")]
    DatabaseMissing,
    /// Production open found an authenticated empty prefix of interrupted
    /// explicit creation. Only `resume_create_production` may complete it.
    #[error("EVM actuator database creation is incomplete")]
    CreationIncomplete,
    /// Another process currently owns the durable EVM actuator authority.
    #[error("EVM actuator process authority is already locked")]
    ProcessLocked,
    /// Production durable storage is supported only on Linux, where retained
    /// inode identity and process locks can be enforced.
    #[error("EVM actuator production storage requires Linux")]
    LinuxRequired,
    /// Database or parent directory is not an owner-only regular authority.
    #[error("invalid EVM actuator storage authority")]
    InvalidStorageAuthority,
    /// Durable SQLite operation failed.
    #[error("EVM actuator durable storage unavailable")]
    Storage(#[from] rusqlite::Error),
    /// Stored schema, row commitment or state transition is impossible.
    #[error("corrupt or unsupported EVM actuator state")]
    CorruptState,
    /// Another live owner holds the account authority.
    #[error("EVM account authority lease is already held")]
    LeaseHeld,
    /// Lease is expired, superseded or otherwise stale.
    #[error("stale EVM account authority fencing capability")]
    StaleFencing,
    /// Time or lease duration is zero, rolled back or overflowed.
    #[error("invalid EVM actuator time or lease bound")]
    InvalidTime,
    /// RPC chain id, genesis or runtime code disagrees with registry facts.
    #[error("EVM RPC preflight does not match authenticated deployment")]
    RpcScopeMismatch,
    /// A required RPC operation failed outside a send-ambiguity boundary.
    #[error("EVM RPC authority refused observation")]
    Rpc(#[from] EvmRpcErrorV1),
    /// No evidence-bound pending nonce has been recorded.
    #[error("pending account nonce observation is missing")]
    MissingNonceObservation,
    /// Pending nonce or allowance evidence is outside its validity window.
    #[error("EVM observation is stale")]
    StaleObservation,
    /// Expected observation/allocation/operation revision changed concurrently.
    #[error("EVM actuator revision conflict")]
    RevisionConflict,
    /// ERC-20 open has no sufficient finalized allowance evidence.
    #[error("ERC-20 allowance is absent or insufficient")]
    AllowanceRequired,
    /// A canonical finalized block timestamp has not reached the lock deadline.
    #[error("EVM refund deadline has not been reached")]
    RefundDeadlineNotReached,
    /// A successful terminal receipt omitted or contradicted the exact
    /// `Claimed`/`Refunded` event committed by the operation.
    #[error("EVM terminal receipt event does not match the operation")]
    TerminalEventMismatch,
    /// Stable operation identity does not exist.
    #[error("EVM operation not found")]
    OperationNotFound,
    /// Operation exists under different immutable bytes or scope.
    #[error("EVM operation idempotency conflict")]
    IdempotencyConflict,
    /// Requested mutation is not legal in the current lifecycle state.
    #[error("invalid EVM operation state transition")]
    InvalidState,
    /// An old-fence operation requires explicit takeover reconciliation.
    #[error("EVM operation requires takeover reconciliation")]
    ReconciliationRequired,
    /// Reconciliation did not prove a state safe to adopt or retry.
    #[error("EVM takeover remains ambiguous")]
    ReconciliationUnknown,
    /// RPC returned a transaction or receipt that differs from persisted bytes.
    #[error("EVM RPC observation does not match persisted transaction")]
    ObservationMismatch,
    /// A successful final state was requested for a reverted receipt.
    #[error("EVM transaction execution reverted")]
    TransactionReverted,
    /// Replacement changed immutable fields, failed to increase fees or exceeded caps.
    #[error("invalid EIP-1559 replacement")]
    InvalidReplacement,
    /// External signer refused the exact scoped request.
    #[error("scoped EIP-1559 signer refused request")]
    Signer(#[from] SignerRefusalV1),
}
