//! Durable coordinator for the DOM and counterparty faces of one settlement.
//!
//! The coordinator stores only canonical plans, public transaction identities,
//! commitments and chain-evidence digests. Exact transaction bytes and every
//! key/share/nonce/scalar remain inside the existing face-specific actuators.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod codec;
mod model;
mod store;

pub use codec::CanonicalSettlementPlanV1;
pub use model::{
    AggregateExternalizationReceiptV1, AggregateFinalityV1, AggregateReorgV1, AggregateStageV1,
    AuthenticatedCoordinatorExposureV1, ChildAuthorityRefusalV1, ChildDispatchRequestV1,
    ChildExecutionOutcomeV1, ChildExposureV1, ChildExternalizationReceiptV1,
    ChildObservationOutcomeV1, ChildObservationRequestV1, ChildProgressViewV1,
    ChildPublicExposureV1, ChildReconciliationOutcomeV1, ChildReconciliationRequestV1,
    ChildStageV1, CompositeSettlementPlanV1, CoordinatorDriveOutcomeV1, CoordinatorLeaseAcquireV1,
    CoordinatorLeaseV1, CoordinatorObservationOutcomeV1, CustodyTakeoverStatusV1,
    DeferredChildMaterializationCapabilityV1, DeferredChildMaterializationResultV1,
    DeferredSettlementChildV1, Digest32, PartialCustodyProgressV1, PendingChildCallV1,
    PendingChildReconciliationV1, PlanAuthorityRefusalV1, PlanAuthorizationRequestV1,
    PlanAuthorizationV1, SecretRequirementV1, SettlementActionV1, SettlementChildAuthorityV1,
    SettlementChildObserverV1, SettlementChildPlanV1, SettlementChildrenV1,
    SettlementDeferredChildAuthorityV1, SettlementFaceV1, SettlementLegV1,
    SettlementPlanAuthorityV1, SettlementPlanBindingsV1, SettlementPlanViewV1,
    StoredSettlementPlanV1, MAX_SETTLEMENT_CHILDREN_V1,
};
pub use store::DurableSettlementCoordinatorV1;

/// Fail-closed coordinator result.
pub type Result<T> = core::result::Result<T, CoordinatorErrorV1>;

/// Named coordinator failures. Display strings deliberately omit paths,
/// endpoints, SQL diagnostics and retained public identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CoordinatorErrorV1 {
    /// Plan shape, child order or exposure policy is invalid.
    #[error("invalid settlement coordinator plan")]
    InvalidPlan,
    /// Canonical bytes contain an unknown version/tag, invalid value or tail.
    #[error("invalid canonical settlement coordinator material")]
    InvalidCanonicalMaterial,
    /// Plan authorization is wrong-authority, stale or bound to other bytes.
    #[error("invalid settlement plan authorization")]
    InvalidPlanAuthorization,
    /// The external plan authority refused the exact request.
    #[error("settlement plan authority refused")]
    PlanAuthorityRefused,
    /// Explicit creation targeted an existing path.
    #[error("settlement coordinator database already exists")]
    DatabasePresent,
    /// Production reopen targeted a missing path.
    #[error("settlement coordinator database is missing")]
    DatabaseMissing,
    /// The exact owner-only create prefix is incomplete and may be resumed
    /// only under an already durable external provisioning journal entry.
    #[error("settlement coordinator database creation is incomplete")]
    CreationIncomplete,
    /// Filesystem owner, mode, path, links or process lock are invalid.
    #[error("invalid settlement coordinator storage authority")]
    InvalidStorageAuthority,
    /// SQLite or filesystem storage was unavailable.
    #[error("settlement coordinator storage unavailable")]
    StorageUnavailable,
    /// Stored schema/version is unsupported.
    #[error("unsupported settlement coordinator database format")]
    UnsupportedFormat,
    /// Persisted rows, commitments or journal history disagree.
    #[error("corrupt settlement coordinator state")]
    CorruptState,
    /// Stable plan or route effect is unknown.
    #[error("settlement coordinator plan not found")]
    PlanNotFound,
    /// Same semantic/idempotency identity was reused with different bytes.
    #[error("settlement coordinator idempotency conflict")]
    IdempotencyConflict,
    /// A conflicting duplicate permanently failed the stored plan closed.
    #[error("settlement coordinator plan failed closed")]
    FailedClosed,
    /// Another live owner holds the plan.
    #[error("settlement coordinator lease is held")]
    LeaseHeld,
    /// Lease identity or coordinator/route fencing generation is stale.
    #[error("stale settlement coordinator fencing capability")]
    StaleFencing,
    /// Lease expired before the requested transition.
    #[error("settlement coordinator lease expired")]
    LeaseExpired,
    /// Time, duration, counter or bounded value is invalid.
    #[error("invalid settlement coordinator bound")]
    InvalidBound,
    /// Requested lifecycle transition is not currently legal.
    #[error("invalid settlement coordinator state transition")]
    InvalidState,
    /// A child authority returned fields that disagree with the plan.
    #[error("settlement child authority receipt mismatch")]
    ChildReceiptMismatch,
    /// A child call remains ambiguous and requires exact reconciliation.
    #[error("settlement child externalization remains ambiguous")]
    ReconciliationRequired,
    /// External child authority refused or became unavailable.
    #[error("settlement child authority refused")]
    ChildAuthorityRefused,
    /// Chain observation authority refused or became unavailable.
    #[error("settlement child observer refused")]
    ChildObserverRefused,
}
