//! Authenticated, durable cross-chain time anchors for composed DOM routes.
//!
//! This crate never converts a deadline from a local clock estimate. A V2
//! ladder proof exists only after two independent threshold checks:
//!
//! - a route policy is reconstructed from a signed deployment registry and
//!   binds the exact route terms, chain identities and timing bounds; and
//! - fresh signed evidence revalidates fixed canonical checkpoints on every
//!   participating chain.
//!
//! Native deadlines are projected to conservative absolute-second intervals.
//! The only accepted inequality is `upstream.earliest >= downstream.latest +
//! margin`. The durable authority detects trusted-clock rollback, evidence
//! rollback/equivocation, restart capability reuse and anchor replacement.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod codec;
mod pre_f6;
mod signed;
mod store;
mod types;

pub use pre_f6::{
    CurrentPreF6NegotiationTimeV2, DurablePreF6TimeStoreV2, PreF6CanonicalCheckpointV2,
    PreF6TimeEvidenceV2, PreF6TimeInstallOutcomeV2, PreF6TimePolicyLimitsV2, PreF6TimePolicyV2,
    PreF6TimeScopeRequestV2, PreF6TimeScopeV2, PreF6TimeSignatureV2, SignedPreF6TimeEvidenceV2,
};
pub use signed::{SignedRouteTimeEvidenceV2, SignedRouteTimePolicyV2, TimeAnchorSignatureV2};
pub use store::{
    DurableRouteTimeAnchorStoreV2, EvidenceInstallOutcomeV2, PolicyInstallOutcomeV2,
    RouteTimeAnchorStoreConfigV2, RouteTimeEvidenceVerificationContextV2,
    RouteTimePolicyVerificationContextV2,
};
pub use types::{
    resolved_dom_profile_digest_v1, route_scope_digest, CanonicalAnchorObservationV2,
    CanonicalCheckpointObservationV2, CanonicalTimeCheckpointV2, CanonicalTimeRangeV2,
    CanonicalTipObservationV2, CheckpointBindingV2, CheckpointRoleV2, ClockKindV2,
    CurrentRouteTimeLadderV2, DeadlineIntervalV2, FrozenRouteTimeCheckpointV2,
    FrozenRouteTimeProofCheckpointV2, LadderIntervalProofV2, RouteTimeEvidenceV2,
    RouteTimePolicyLimitsV2, RouteTimePolicyV2, VerifiedFrozenRouteTimeLadderV2,
    VerifiedRouteTimeLadderV2, BTC_MTP_SAMPLE_INTERVALS_V2, MAX_TIME_ANCHOR_AUTHORITIES_V2,
};

/// Domain separator for the canonical V2 route scope.
pub const ROUTE_TIME_SCOPE_DOMAIN_V2: &[u8] = b"DOM-INTEROP/ROUTE-TIME-SCOPE/V2\0";
/// Domain separator for a canonical route time policy.
pub const ROUTE_TIME_POLICY_DOMAIN_V2: &[u8] = b"DOM-INTEROP/ROUTE-TIME-POLICY/V2\0";
/// Domain separator for canonical live time evidence.
pub const ROUTE_TIME_EVIDENCE_DOMAIN_V2: &[u8] = b"DOM-INTEROP/ROUTE-TIME-EVIDENCE/V2\0";
/// Domain separator for an issued worst-case ladder proof.
pub const ROUTE_TIME_LADDER_DOMAIN_V2: &[u8] = b"DOM-INTEROP/ROUTE-TIME-LADDER/V2\0";
/// Domain separator for pinned time-authority sets.
pub const ROUTE_TIME_AUTHORITY_SET_DOMAIN_V2: &[u8] = b"DOM-INTEROP/ROUTE-TIME-AUTHORITY-SET/V2\0";

/// Frozen canonical format version. V1 route composition remains unchanged.
pub const ROUTE_TIME_VERSION_V2: u16 = 2;

/// Named, fail-closed failures of the cross-chain time authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RouteTimeAnchorErrorV2 {
    /// One of the two settlement terms objects is invalid.
    #[error("invalid settlement terms")]
    InvalidTerms,
    /// The route topology or native timelock kind is not supported by V2.
    #[error("unsupported cross-chain time topology")]
    UnsupportedTopology,
    /// Public mainnet use has not been ratified for this authority.
    #[error("mainnet time anchors are disabled")]
    MainnetDisabled,
    /// Policy facts do not exactly match the authenticated registry or terms.
    #[error("time policy does not match authenticated registry")]
    RegistryMismatch,
    /// A policy field, lifetime or safety bound is invalid.
    #[error("invalid route time policy")]
    InvalidPolicy,
    /// Canonical checkpoint evidence is incomplete or contradictory.
    #[error("invalid canonical time evidence")]
    InvalidEvidence,
    /// A canonical encoding is malformed, alternate or has trailing bytes.
    #[error("non-canonical route time encoding")]
    NonCanonicalEncoding,
    /// A defensive count or byte bound was exceeded.
    #[error("route time bound exceeded")]
    BoundExceeded,
    /// A configured BIP340 authority set is malformed.
    #[error("invalid route time authority set")]
    InvalidAuthoritySet,
    /// A signature is malformed, duplicated or cryptographically invalid.
    #[error("invalid route time signature")]
    InvalidSignature,
    /// Too few independent signatures authenticated the object.
    #[error("route time signature threshold not met")]
    ThresholdNotMet,
    /// Checked integer arithmetic failed.
    #[error("route time arithmetic overflow")]
    Overflow,
    /// The trusted wall clock moved below its durable high-water mark.
    #[error("trusted clock rollback")]
    ClockRollback,
    /// The signed policy is not yet valid or has expired.
    #[error("route time policy expired or not yet valid")]
    PolicyExpired,
    /// Evidence was signed in the future relative to the trusted clock.
    #[error("route time evidence is from the future")]
    EvidenceFromFuture,
    /// Evidence exceeded its signed freshness window.
    #[error("route time evidence is stale")]
    EvidenceStale,
    /// A checkpoint is too old or too far ahead of signed observation time.
    #[error("canonical checkpoint is stale")]
    AnchorStale,
    /// A signed revalidation changed or invalidated a frozen checkpoint.
    #[error("canonical checkpoint was invalidated by reorg or replacement")]
    AnchorReorged,
    /// A lower sequence/time or same sequence with different bytes was seen.
    #[error("route time evidence rollback or equivocation")]
    EvidenceRollback,
    /// A native deadline may already have matured.
    #[error("route deadline has passed")]
    DeadlinePassed,
    /// Conservative projection produced no possible time interval.
    #[error("impossible route deadline interval")]
    ImpossibleInterval,
    /// The worst-case upstream/downstream inequality does not hold.
    #[error("unsafe worst-case composed time window")]
    UnsafeWindow,
    /// A route-scoped store already exists at the requested path.
    #[error("route time database already exists")]
    DatabasePresent,
    /// Production reopen targeted a missing route-scoped store.
    #[error("route time database is missing")]
    DatabaseMissing,
    /// The exact create lock and pristine SQLite prefix exist, but the schema
    /// transaction has not committed. Only an external provisioning journal
    /// in `Started` state may authorize strict create resumption.
    #[error("route time database creation is incomplete")]
    CreationIncomplete,
    /// Filesystem ownership, mode, links or canonical path are unsafe.
    #[error("invalid route time storage authority")]
    InvalidStorageAuthority,
    /// SQLite or the underlying filesystem is unavailable.
    #[error("route time storage unavailable")]
    StorageUnavailable,
    /// Schema, retained bytes or denormalized commitments are corrupt.
    #[error("corrupt or unsupported route time state")]
    CorruptState,
    /// This route store already froze a different policy.
    #[error("conflicting route time policy")]
    PolicyConflict,
    /// A proof belongs to an earlier process opening or no longer-current state.
    #[error("stale route time capability")]
    StaleCapability,
    /// The admission checkpoint is absent from this store's authenticated
    /// monotonic evidence ancestry.
    #[error("frozen route time checkpoint is not in durable ancestry")]
    FrozenCheckpointMismatch,
    /// Hash initialization or finalization failed.
    #[error("route time digest failure")]
    DigestFailure,
}

/// Result alias for the V2 time authority.
pub type Result<T> = core::result::Result<T, RouteTimeAnchorErrorV2>;
