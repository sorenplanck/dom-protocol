//! Durable ownership and dispatch of one route.
//!
//! The supervisor owns the route store and its exact lease/fencing generation.
//! It is deliberately not a signer or chain client.  Typed authorities receive
//! a narrow, move-only capability for one claimed attempt, and a broadcast is
//! recorded only through `ActionExternalized`, which advances the route and
//! closes the outbox row atomically.

use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(feature = "development", feature = "simulation", test))]
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use crate::admission::AuthenticatedRouteAdmissionV1;
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use route_executor::{
    derive_effect_id_v1, ActionIntentV1, ActionKindV1, ActionStateV1,
    ClaimedExternalCustodyEffectV1, ClaimedRouteEffectV1, ClaimedRouteTimerV1, ClaimedRouteWorkV1,
    CommitOutcomeV1, CompletionOutcomeV1, Digest32, DurableRouteStoreV1, EffectDispatchV1,
    EffectIdV1, EffectPriorityV1, EventIdV1, ExposureSourceV1, FrozenBindingsV1, HealthStateV1,
    LegIdV1, PublicExposureV1, RefundBindingsV1, RouteEventV1, RouteIdV1, RouteJournalEntryV1,
    RouteLeaseV1, RouteSecretRetirementCapabilityV1, RouteSnapshotV1, RouteStoreErrorV1,
    SecretVisibilityV1, TimerIdV1, TimerKindV1,
};

const MAX_LEASE_DURATION_MS: u64 = 86_400_000;
const MAX_QUEUE_BATCH: usize = 64;
const CAPABILITY_ATTEMPT_DOMAIN: &[u8] = b"DOM-INTEROPD/SIGNER-CAPABILITY-ATTEMPT/V2\0";
const EXTERNALIZED_EVENT_DOMAIN: &[u8] = b"DOM-INTEROPD/ACTION-EXTERNALIZED-EVENT/V1\0";
const CUSTODY_PROGRESS_EVENT_DOMAIN: &[u8] = b"DOM-INTEROPD/CUSTODY-PROGRESS-EVENT/V1\0";
const TIMER_EVENT_DOMAIN: &[u8] = b"DOM-INTEROPD/TIMER-EVENT/V1\0";
const REAUTHORIZE_EVENT_DOMAIN: &[u8] = b"DOM-INTEROPD/REAUTHORIZE-EVENT/V1\0";
const ZERO_DIGEST: Digest32 = [0; 32];

/// Trusted millisecond clock used for route and dispatch leases.
pub trait Clock: Send + Sync {
    /// Returns milliseconds since the Unix epoch.  Zero and rollback are
    /// rejected by the supervisor at security-sensitive boundaries.
    fn now_unix_ms(&self) -> Result<u64, ClockErrorV1>;
}

/// Clock failure without platform/path details.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClockErrorV1 {
    /// The platform clock was before the Unix epoch or outside `u64`.
    #[error("system clock is outside the supported Unix-millisecond range")]
    UnsupportedSystemTime,
    /// A manual clock was set to zero.
    #[error("manual clock value must be nonzero")]
    InvalidManualTime,
    /// A manual clock advance overflowed.
    #[error("manual clock overflow")]
    ManualClockOverflow,
}

/// Production wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClockV1;

impl Clock for SystemClockV1 {
    fn now_unix_ms(&self) -> Result<u64, ClockErrorV1> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockErrorV1::UnsupportedSystemTime)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| ClockErrorV1::UnsupportedSystemTime)
    }
}

/// Explicit manual clock for deterministic tests and the simulation build.
/// Production assembly must use [`SystemClockV1`].
#[derive(Clone, Debug)]
#[cfg(any(feature = "development", feature = "simulation", test))]
pub struct ManualClockV1 {
    now_unix_ms: Arc<AtomicU64>,
}

#[cfg(any(feature = "development", feature = "simulation", test))]
impl ManualClockV1 {
    /// Creates a nonzero manual clock.
    pub fn new(now_unix_ms: u64) -> Result<Self, ClockErrorV1> {
        if now_unix_ms == 0 {
            return Err(ClockErrorV1::InvalidManualTime);
        }
        Ok(Self {
            now_unix_ms: Arc::new(AtomicU64::new(now_unix_ms)),
        })
    }

    /// Sets an exact nonzero time.
    pub fn set(&self, now_unix_ms: u64) -> Result<(), ClockErrorV1> {
        if now_unix_ms == 0 {
            return Err(ClockErrorV1::InvalidManualTime);
        }
        self.now_unix_ms.store(now_unix_ms, Ordering::SeqCst);
        Ok(())
    }

    /// Advances the clock without wrapping.
    pub fn advance(&self, delta_ms: u64) -> Result<u64, ClockErrorV1> {
        self.now_unix_ms
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(delta_ms)
            })
            .map(|prior| prior + delta_ms)
            .map_err(|_| ClockErrorV1::ManualClockOverflow)
    }
}

#[cfg(any(feature = "development", feature = "simulation", test))]
impl Clock for ManualClockV1 {
    fn now_unix_ms(&self) -> Result<u64, ClockErrorV1> {
        let now = self.now_unix_ms.load(Ordering::SeqCst);
        if now == 0 {
            Err(ClockErrorV1::InvalidManualTime)
        } else {
            Ok(now)
        }
    }
}

/// Defensive supervisor bounds.  `dispatch_lease_ms <= renew_before_ms`
/// guarantees a full dispatch window whenever renewal is not yet required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteSupervisorConfigV1 {
    lease_duration_ms: u64,
    renew_before_ms: u64,
    dispatch_lease_ms: u64,
    per_queue_batch_limit: usize,
}

impl RouteSupervisorConfigV1 {
    /// Validates lease, renewal, dispatch and per-queue batch bounds.
    pub fn new(
        lease_duration_ms: u64,
        renew_before_ms: u64,
        dispatch_lease_ms: u64,
        per_queue_batch_limit: usize,
    ) -> Result<Self, RouteSupervisorErrorV1> {
        if lease_duration_ms == 0
            || lease_duration_ms > MAX_LEASE_DURATION_MS
            || renew_before_ms == 0
            || renew_before_ms >= lease_duration_ms
            || dispatch_lease_ms == 0
            || dispatch_lease_ms > renew_before_ms
            || per_queue_batch_limit == 0
            || per_queue_batch_limit > MAX_QUEUE_BATCH
        {
            return Err(RouteSupervisorErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            lease_duration_ms,
            renew_before_ms,
            dispatch_lease_ms,
            per_queue_batch_limit,
        })
    }

    /// Route ownership lease duration.
    pub const fn lease_duration_ms(&self) -> u64 {
        self.lease_duration_ms
    }

    /// Remaining lifetime at which the lease is renewed.
    pub const fn renew_before_ms(&self) -> u64 {
        self.renew_before_ms
    }

    /// Per-item worker dispatch lease.
    pub const fn dispatch_lease_ms(&self) -> u64 {
        self.dispatch_lease_ms
    }

    /// Maximum claimed items from each effect class or timer queue per tick.
    pub const fn per_queue_batch_limit(&self) -> usize {
        self.per_queue_batch_limit
    }
}

/// Read-only ownership status.  Unlike `route_executor::RouteLeaseV1`, this
/// view omits the owner token and cannot be passed to low-level store writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteLeaseStatusV1 {
    route_id: RouteIdV1,
    fencing_epoch: u64,
    lease_until_unix_ms: u64,
}

impl RouteLeaseStatusV1 {
    /// Route held by this supervisor.
    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }
    /// Current monotonic fencing generation.
    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch
    }
    /// Absolute route-lease expiry in Unix milliseconds.
    pub const fn lease_until_unix_ms(&self) -> u64 {
        self.lease_until_unix_ms
    }
}

/// Redacted refusal returned by a typed action/timer/reconciliation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthorityRefusalV1 {
    /// Authority or its backing service is temporarily unavailable.
    #[error("authority temporarily unavailable")]
    Unavailable,
    /// Authority rejected the exact scoped request.
    #[error("authority rejected scoped request")]
    Refused,
    /// Authority detected inconsistent durable state or an invalid receipt.
    #[error("authority state is inconsistent")]
    Inconsistent,
}

// Sibling production-composition modules may name the seal, while crates
// outside `dom-interopd` still cannot implement production authorities.
pub(crate) mod authority_seal {
    /// Production supervisor authorities are implemented only inside the
    /// composition-root crate. External crates cannot name this module.
    pub trait Sealed {}

    /// Laboratory builds deliberately allow deterministic test/simulation
    /// authorities. This blanket implementation is absent from production.
    #[cfg(any(feature = "development", feature = "simulation", test))]
    impl<T> Sealed for T {}
}

/// Immutable request presented to the authority that proves both refund exits
/// are durably armed.  The authority owns the underlying presigned artifacts;
/// only their public commitments may cross this boundary.
pub struct RefundArmingRequestV1<'a> {
    route_id: RouteIdV1,
    event_id: EventIdV1,
    fencing_epoch: u64,
    bindings: &'a FrozenBindingsV1,
    snapshot: &'a RouteSnapshotV1,
}

impl core::fmt::Debug for RefundArmingRequestV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RefundArmingRequestV1")
            .field("route_id", &self.route_id)
            .field("event_id", &self.event_id)
            .field("fencing_epoch", &self.fencing_epoch)
            .field("snapshot_revision", &self.snapshot.revision)
            .field("bindings", &self.bindings)
            .finish()
    }
}

impl<'a> RefundArmingRequestV1<'a> {
    /// Route identity held by the supervisor.
    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }
    /// Caller-provided durable idempotency identity.
    pub const fn event_id(&self) -> EventIdV1 {
        self.event_id
    }
    /// Current route fencing generation.
    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch
    }
    /// Authenticated frozen route bindings.
    pub const fn bindings(&self) -> &'a FrozenBindingsV1 {
        self.bindings
    }
    /// Exact snapshot revision against which the response will be committed.
    pub const fn snapshot(&self) -> &'a RouteSnapshotV1 {
        self.snapshot
    }
}

/// Authority that constructs and durably retains both refund paths before any
/// funding action can be authorized.
pub trait RefundArmingAuthority: authority_seal::Sealed {
    /// Returns only the commitments to the exact durable refund artifacts.
    fn arm_refunds(
        &mut self,
        request: RefundArmingRequestV1<'_>,
    ) -> Result<RefundBindingsV1, AuthorityRefusalV1>;
}

/// Immutable request for one exact economic action.  An implementation is a
/// route planner/custody authority, not a generic transaction constructor.
pub struct RouteActionAuthorizationRequestV1<'a> {
    route_id: RouteIdV1,
    event_id: EventIdV1,
    fencing_epoch: u64,
    leg: LegIdV1,
    action: ActionKindV1,
    bindings: &'a FrozenBindingsV1,
    snapshot: &'a RouteSnapshotV1,
}

impl core::fmt::Debug for RouteActionAuthorizationRequestV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RouteActionAuthorizationRequestV1")
            .field("route_id", &self.route_id)
            .field("event_id", &self.event_id)
            .field("fencing_epoch", &self.fencing_epoch)
            .field("leg", &self.leg)
            .field("action", &self.action)
            .field("snapshot_revision", &self.snapshot.revision)
            .field("bindings", &self.bindings)
            .finish()
    }
}

impl<'a> RouteActionAuthorizationRequestV1<'a> {
    /// Route identity held by the supervisor.
    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }
    /// Caller-provided durable idempotency identity.
    pub const fn event_id(&self) -> EventIdV1 {
        self.event_id
    }
    /// Current route fencing generation.
    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch
    }
    /// Exact requested route leg.
    pub const fn leg(&self) -> LegIdV1 {
        self.leg
    }
    /// Exact requested economic action.
    pub const fn action(&self) -> ActionKindV1 {
        self.action
    }
    /// Authenticated frozen route bindings.
    pub const fn bindings(&self) -> &'a FrozenBindingsV1 {
        self.bindings
    }
    /// Exact snapshot revision against which the response will be committed.
    pub const fn snapshot(&self) -> &'a RouteSnapshotV1 {
        self.snapshot
    }
}

/// Authority that authorizes the immutable intent for one requested route
/// action.  The supervisor rejects a response for another leg or action.
pub trait RouteActionAuthority: authority_seal::Sealed {
    /// Produces the exact intent that will be atomically committed to outbox.
    fn authorize_route_action(
        &mut self,
        request: RouteActionAuthorizationRequestV1<'_>,
    ) -> Result<ActionIntentV1, AuthorityRefusalV1>;
}

/// Exact public chain fact an observer is asked to verify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainObservationQueryV1 {
    /// Verify finality of one already externalized action.
    Finality {
        /// Route leg whose transaction is queried.
        leg: LegIdV1,
        /// Economic action whose transaction is queried.
        action: ActionKindV1,
        /// Exact public transaction identity.
        transaction_id: Digest32,
    },
    /// Verify that a previously final observation was invalidated by reorg.
    Invalidation {
        /// Route leg whose transaction is queried.
        leg: LegIdV1,
        /// Economic action whose transaction is queried.
        action: ActionKindV1,
        /// Exact public transaction identity.
        transaction_id: Digest32,
    },
    /// Verify an independently observed route-secret exposure.
    SecretExposure {
        /// Frozen chain/profile identity.
        chain_id: Digest32,
        /// Exact public transaction identity.
        transaction_id: Digest32,
    },
}

/// Evidence returned by a chain observer.  Identity fields live in the query,
/// so an authority cannot silently substitute another leg/action/transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifiedChainObservationV1 {
    /// Evidence that the queried action satisfies the frozen finality policy.
    Finality {
        /// Commitment to the accepted finality proof.
        evidence_digest: Digest32,
    },
    /// Evidence that invalidates the queried prior finality proof.
    Invalidation {
        /// Commitment to the accepted reorg proof.
        reorg_evidence_digest: Digest32,
    },
    /// Evidence of independently observed public secret exposure.
    SecretExposure {
        /// Observation source; `Externalized` is reserved to action receipts.
        source: ExposureSourceV1,
        /// Commitment to the exact observation/extraction evidence.
        evidence_digest: Digest32,
        /// Local time at which the authority observed the public fact.
        observed_at_unix_ms: u64,
    },
}

/// Immutable chain-observation request scoped to one route revision.
pub struct ChainObservationRequestV1<'a> {
    route_id: RouteIdV1,
    event_id: EventIdV1,
    fencing_epoch: u64,
    query: ChainObservationQueryV1,
    bindings: &'a FrozenBindingsV1,
    snapshot: &'a RouteSnapshotV1,
}

impl core::fmt::Debug for ChainObservationRequestV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ChainObservationRequestV1")
            .field("route_id", &self.route_id)
            .field("event_id", &self.event_id)
            .field("fencing_epoch", &self.fencing_epoch)
            .field("query", &self.query)
            .field("snapshot_revision", &self.snapshot.revision)
            .field("bindings", &self.bindings)
            .finish()
    }
}

impl<'a> ChainObservationRequestV1<'a> {
    /// Route identity held by the supervisor.
    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }
    /// Caller-provided durable idempotency identity.
    pub const fn event_id(&self) -> EventIdV1 {
        self.event_id
    }
    /// Current route fencing generation.
    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch
    }
    /// Exact public fact to verify.
    pub const fn query(&self) -> ChainObservationQueryV1 {
        self.query
    }
    /// Authenticated frozen route bindings.
    pub const fn bindings(&self) -> &'a FrozenBindingsV1 {
        self.bindings
    }
    /// Exact snapshot revision against which the response will be committed.
    pub const fn snapshot(&self) -> &'a RouteSnapshotV1 {
        self.snapshot
    }
}

/// Chain observer/finality authority bound to authenticated chain profiles.
pub trait ChainObservationAuthority: authority_seal::Sealed {
    /// Verifies one exact query and returns evidence without changing identity.
    fn verify_chain_observation(
        &mut self,
        request: ChainObservationRequestV1<'_>,
    ) -> Result<VerifiedChainObservationV1, AuthorityRefusalV1>;
}

/// Public-only coordinator progress that the parent route already journaled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcknowledgedCustodyProgressV1 {
    progress_evidence_digest: Digest32,
    exposure: Option<PublicExposureV1>,
}

impl AcknowledgedCustodyProgressV1 {
    /// Exact coordinator-prefix commitment already journaled by the route.
    pub const fn progress_evidence_digest(&self) -> Digest32 {
        self.progress_evidence_digest
    }

    /// Exact child exposure already journaled with that prefix, when present.
    pub const fn exposure(&self) -> Option<&PublicExposureV1> {
        self.exposure.as_ref()
    }
}

/// Move-only signer/custody permission for one exact claimed delivery attempt.
///
/// The acknowledged progress fields are derived only from the authenticated
/// route journal. They let a two-face coordinator distinguish a lost partial
/// receipt from progress that the parent route has already committed, without
/// receiving any scalar or secret-bearing bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct SignerCapabilityV1 {
    route_id: RouteIdV1,
    effect_id: EffectIdV1,
    leg: LegIdV1,
    action: ActionKindV1,
    semantic_digest: Digest32,
    terms_digest: Digest32,
    profile_bundle_digest: Digest32,
    deployment_bundle_digest: Digest32,
    fencing_epoch: u64,
    dispatch_digest: Digest32,
    expires_at_unix_ms: u64,
    attempt: u64,
    one_shot_attempt_id: Digest32,
    expected_transaction_id: Option<Digest32>,
    contains_route_secret: bool,
    acknowledged_custody_progress: Option<AcknowledgedCustodyProgressV1>,
    route_first_public_exposure: Option<PublicExposureV1>,
}

impl SignerCapabilityV1 {
    /// Route identity.
    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }
    /// Exact durable effect identity.
    pub const fn effect_id(&self) -> EffectIdV1 {
        self.effect_id
    }
    /// Target route leg.
    pub const fn leg(&self) -> LegIdV1 {
        self.leg
    }
    /// Exact economic action.
    pub const fn action(&self) -> ActionKindV1 {
        self.action
    }
    /// Semantic retry commitment.
    pub const fn semantic_digest(&self) -> Digest32 {
        self.semantic_digest
    }
    /// Frozen terms commitment.
    pub const fn terms_digest(&self) -> Digest32 {
        self.terms_digest
    }
    /// Frozen chain-profile bundle commitment.
    pub const fn profile_bundle_digest(&self) -> Digest32 {
        self.profile_bundle_digest
    }
    /// Frozen deployment bundle commitment.
    pub const fn deployment_bundle_digest(&self) -> Digest32 {
        self.deployment_bundle_digest
    }
    /// Current route fencing generation.
    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch
    }
    /// Digest of the exact runner payload or external custody descriptor.
    pub const fn dispatch_digest(&self) -> Digest32 {
        self.dispatch_digest
    }
    /// Attempt capability expiry, never beyond the route lease.
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
    /// Durable delivery attempt number.
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }
    /// Unique move-only attempt token an authority must consume once.
    pub const fn one_shot_attempt_id(&self) -> Digest32 {
        self.one_shot_attempt_id
    }
    /// Expected public transaction identity for externally custodied actions.
    pub const fn expected_transaction_id(&self) -> Option<Digest32> {
        self.expected_transaction_id
    }
    /// Whether externalization necessarily reveals the route scalar.
    pub const fn contains_route_secret(&self) -> bool {
        self.contains_route_secret
    }

    /// Coordinator prefix that this route has already committed, if any.
    pub const fn acknowledged_custody_progress(&self) -> Option<&AcknowledgedCustodyProgressV1> {
        self.acknowledged_custody_progress.as_ref()
    }

    /// First irreversible exposure currently recognized by the route.
    pub const fn route_first_public_exposure(&self) -> Option<&PublicExposureV1> {
        self.route_first_public_exposure.as_ref()
    }
}

/// Typed runner request.  Payload bytes are separate from the capability and
/// are committed by its `dispatch_digest`; this is not a generic `sign(bytes)`
/// API.
pub struct RunnerActionRequestV1<'a> {
    capability: SignerCapabilityV1,
    payload: &'a [u8],
}

impl core::fmt::Debug for RunnerActionRequestV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RunnerActionRequestV1")
            .field("capability", &self.capability)
            .field("payload", &"[redacted]")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl<'a> RunnerActionRequestV1<'a> {
    /// Move-only scoped capability.
    pub const fn capability(&self) -> &SignerCapabilityV1 {
        &self.capability
    }
    /// Exact safe runner bytes whose digest is in the capability.
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// Typed external-custody request.  It has no transaction bytes or scalar.
#[derive(Debug)]
pub struct ExternalCustodyActionRequestV1 {
    capability: SignerCapabilityV1,
}

impl ExternalCustodyActionRequestV1 {
    /// Move-only scoped capability.
    pub const fn capability(&self) -> &SignerCapabilityV1 {
        &self.capability
    }
}

/// Public receipt returned after an idempotent externalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionExternalizationReceiptV1 {
    transaction_id: Digest32,
    secret_exposure: Option<(Digest32, Digest32)>,
}

impl ActionExternalizationReceiptV1 {
    /// Receipt for an action that does not reveal the route scalar.
    pub const fn public(transaction_id: Digest32) -> Self {
        Self {
            transaction_id,
            secret_exposure: None,
        }
    }

    /// Receipt for an action whose exact externalization makes the route
    /// scalar public.  Arguments are public chain id and evidence digest.
    pub const fn secret_revealing(
        transaction_id: Digest32,
        chain_id: Digest32,
        evidence_digest: Digest32,
    ) -> Self {
        Self {
            transaction_id,
            secret_exposure: Some((chain_id, evidence_digest)),
        }
    }

    /// Public transaction identity.
    pub const fn transaction_id(&self) -> Digest32 {
        self.transaction_id
    }

    /// Aggregate action identity. For a two-face custody action this is the
    /// coordinator identity frozen in the route effect, not either child
    /// chain transaction that may have exposed the scalar earlier.
    pub const fn aggregate_action_id(&self) -> Digest32 {
        self.transaction_id
    }
}

/// Result of advancing one externally-custodied aggregate action.
///
/// Partial progress is journaled without closing the route effect. `Unknown`
/// deliberately retains the dispatch lease because the authority could not
/// prove whether its current child call left custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CustodyDispatchOutcomeV1 {
    /// Every required child left custody and the aggregate receipt is final.
    AggregateExternalized(ActionExternalizationReceiptV1),
    /// A durable proper prefix left custody, while at least one required child
    /// remains. The optional exposure is the real child-chain transaction,
    /// never the aggregate action identity.
    PartialProgress {
        /// Commitment to the coordinator's durable prefix and child receipts.
        progress_evidence_digest: Digest32,
        /// Irreversible public exposure caused by this prefix, when present.
        exposure: Option<PublicExposureV1>,
    },
    /// The authority cannot yet prove externalization or non-externalization.
    Unknown,
}

/// Authority for bounded runner payload effects.
pub trait RunnerActionAuthority: authority_seal::Sealed {
    /// Idempotently externalizes one typed action.  It must never dispatch a
    /// different transaction for a retry of the same effect/dispatch digest.
    fn externalize_runner_action(
        &mut self,
        request: RunnerActionRequestV1<'_>,
    ) -> Result<ActionExternalizationReceiptV1, AuthorityRefusalV1>;
}

/// Authority that owns secret-bearing or otherwise external-custodied bytes.
pub trait ExternalCustodyAuthority: authority_seal::Sealed {
    /// Idempotently externalizes the externally retained descriptor selected
    /// by the capability.  No secret-bearing bytes cross this interface.
    fn externalize_custodied_action(
        &mut self,
        request: ExternalCustodyActionRequestV1,
    ) -> Result<CustodyDispatchOutcomeV1, AuthorityRefusalV1>;
}

/// Typed, move-only due-timer request.
#[derive(Debug)]
pub struct TimerDispatchV1 {
    route_id: RouteIdV1,
    timer_id: TimerIdV1,
    kind: TimerKindV1,
    deadline_unix_ms: u64,
    context_digest: Digest32,
    scheduling_fence: u64,
    current_fence: u64,
    attempt: u64,
    event_id: EventIdV1,
}

impl TimerDispatchV1 {
    /// Route identity.
    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }
    /// Exact timer identity.
    pub const fn timer_id(&self) -> TimerIdV1 {
        self.timer_id
    }
    /// Timer class.
    pub const fn kind(&self) -> TimerKindV1 {
        self.kind
    }
    /// Frozen due time.
    pub const fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }
    /// Public timer context commitment.
    pub const fn context_digest(&self) -> Digest32 {
        self.context_digest
    }
    /// Fence that originally scheduled this internal wakeup.
    pub const fn scheduling_fence(&self) -> u64 {
        self.scheduling_fence
    }
    /// Current route owner fence.
    pub const fn current_fence(&self) -> u64 {
        self.current_fence
    }
    /// Durable timer delivery attempt.
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }
    /// Deterministic idempotency key for the event returned by the authority.
    pub const fn event_id(&self) -> EventIdV1 {
        self.event_id
    }
}

/// Notice issued after the timer event committed but before timer completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerEventCommitV1 {
    /// Timer that produced the event.
    pub timer_id: TimerIdV1,
    /// Deterministic event id.
    pub event_id: EventIdV1,
    /// Resulting route revision.
    pub revision: u64,
    /// Whether this was an exact retry of a previously committed event.
    pub duplicate: bool,
}

/// Authority that maps a due timer to one deterministic route event.
pub trait TimerAuthority: authority_seal::Sealed {
    /// Return the same canonical event for every delivery of a timer.  The
    /// fixed event id makes a changed result fail as an idempotency conflict.
    fn event_for_due_timer(
        &mut self,
        timer: TimerDispatchV1,
    ) -> Result<RouteEventV1, AuthorityRefusalV1>;

    /// Optional durable acknowledgement barrier after event commit and before
    /// timer completion.  A failure leaves the timer pending, exercising the
    /// exact restart-safe event-then-complete protocol.
    fn event_committed(&mut self, _commit: TimerEventCommitV1) -> Result<(), AuthorityRefusalV1> {
        Ok(())
    }
}

/// Immutable reconciliation request for a committed action stranded under an
/// older fencing generation.
pub struct ReconciliationRequestV1<'a> {
    route_id: RouteIdV1,
    effect_id: EffectIdV1,
    prior_fence: u64,
    current_fence: u64,
    bindings: &'a FrozenBindingsV1,
    intent: &'a ActionIntentV1,
    dispatch_digest: Digest32,
    expected_transaction_id: Option<Digest32>,
}

impl core::fmt::Debug for ReconciliationRequestV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ReconciliationRequestV1")
            .field("route_id", &self.route_id)
            .field("effect_id", &self.effect_id)
            .field("prior_fence", &self.prior_fence)
            .field("current_fence", &self.current_fence)
            .field("dispatch_digest", &self.dispatch_digest)
            .field("expected_transaction_id", &self.expected_transaction_id)
            .finish_non_exhaustive()
    }
}

impl<'a> ReconciliationRequestV1<'a> {
    /// Route identity.
    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }
    /// Stranded effect identity.
    pub const fn effect_id(&self) -> EffectIdV1 {
        self.effect_id
    }
    /// Fence that authorized the stranded action.
    pub const fn prior_fence(&self) -> u64 {
        self.prior_fence
    }
    /// Fence held by this supervisor.
    pub const fn current_fence(&self) -> u64 {
        self.current_fence
    }
    /// Frozen route bindings.
    pub const fn bindings(&self) -> &'a FrozenBindingsV1 {
        self.bindings
    }
    /// Exact store-authenticated intent.  Runner bytes are bounded safe bytes;
    /// external custody still exposes commitments only.
    pub const fn intent(&self) -> &'a ActionIntentV1 {
        self.intent
    }
    /// Digest of dispatch bytes or custody descriptor.
    pub const fn dispatch_digest(&self) -> Digest32 {
        self.dispatch_digest
    }
    /// Public expected transaction identity, when frozen before dispatch.
    pub const fn expected_transaction_id(&self) -> Option<Digest32> {
        self.expected_transaction_id
    }
}

/// Closed reconciliation result.  `Unknown` never authorizes dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TakeoverReconciliationOutcomeV1 {
    /// Authority proves that the old action already left custody.
    Externalized(ActionExternalizationReceiptV1),
    /// Authority proves no externalization and returns the exact same intent
    /// plus a nonzero public evidence commitment.
    ProvenNotExternalized {
        /// Exact recovered intent; any difference fails closed.
        intent: ActionIntentV1,
        /// Durable non-externalization evidence commitment.
        evidence_digest: Digest32,
    },
    /// An external-custody authority proves that only a non-secret prefix of
    /// the exact aggregate action left custody. The route may re-fence the
    /// same descriptor and resume its remaining children, but may not mark
    /// the aggregate action externalized yet.
    SafeToResumeCustody {
        /// Exact recovered intent; any difference fails closed.
        intent: ActionIntentV1,
        /// Durable partial-progress/no-secret-exposure evidence commitment.
        evidence_digest: Digest32,
    },
    /// A secret-bearing child of an aggregate custody action left custody,
    /// but the aggregate is not complete. The supervisor must journal the
    /// real exposure before re-fencing the still-committed aggregate effect.
    SecretPublicPartialCustody {
        /// Exact recovered intent; any difference fails closed.
        intent: ActionIntentV1,
        /// Durable coordinator prefix/receipt evidence commitment.
        progress_evidence_digest: Digest32,
        /// Exact public child-chain exposure retained by the coordinator.
        exposure: PublicExposureV1,
    },
    /// Evidence is insufficient.  The old action stays non-dispatchable.
    Unknown,
}

/// Authority used only for stale-fence takeover recovery.
pub trait TakeoverReconciliationAuthority: authority_seal::Sealed {
    /// Reconciles an exact old-fence committed action without dispatching it.
    fn reconcile_committed_action(
        &mut self,
        request: ReconciliationRequestV1<'_>,
    ) -> Result<TakeoverReconciliationOutcomeV1, AuthorityRefusalV1>;
}

/// Terminal lifecycle authority for the encrypted public-scalar recovery
/// record.
///
/// The capability is move-only and can be minted only by the authenticated
/// route Store after replay proves a public route, both legs terminal and no
/// open funds. Implementations receive no caller-shaped terminal flags or
/// digests.
pub trait RouteSecretRetirementAuthority: authority_seal::Sealed {
    /// Idempotently retire the exact route-secret seal authorized by the
    /// terminal journal replay.
    fn retire_route_secret(
        &mut self,
        capability: RouteSecretRetirementCapabilityV1,
    ) -> Result<(), AuthorityRefusalV1>;
}

/// Per-tick durable progress counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RouteSupervisorTickReportV1 {
    /// Whether the route lease was renewed before work.
    pub lease_renewed: bool,
    /// Secret-public urgent effects externalized.
    pub urgent_externalized: usize,
    /// Non-urgent runner effects externalized.
    pub runner_externalized: usize,
    /// Non-urgent custody effects externalized.
    pub custody_externalized: usize,
    /// Custody calls that durably advanced only a proper aggregate prefix.
    pub custody_partial_progress: usize,
    /// Custody calls that replayed an already journaled proper prefix.
    pub custody_progress_unchanged: usize,
    /// Custody calls whose current externalization status remains ambiguous.
    pub custody_unknown: usize,
    /// Due timer events committed and timers completed.
    pub timers_completed: usize,
    /// Timer events recognized as exact durable duplicates.
    pub duplicate_timer_events: usize,
    /// Urgent work was already dispatch-leased elsewhere/by a prior attempt.
    pub urgent_in_flight: bool,
    /// An urgent claim is committed under an older fencing generation and
    /// must pass takeover reconciliation before any other work may run.
    pub takeover_reconciliation_required: bool,
}

/// Takeover reconciliation counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TakeoverReconciliationReportV1 {
    /// Old actions proven already externalized.
    pub externalized: usize,
    /// Old actions safely reauthorized under this fence.
    pub reauthorized: usize,
    /// Partially externalized custody actions safely resumed under this fence.
    pub partial_custody_resumed: usize,
    /// Partially externalized custody actions whose secret exposure was
    /// journaled before the aggregate was safely resumed.
    pub partial_secret_custody_resumed: usize,
    /// Old actions kept inert because evidence was inconclusive.
    pub unknown: usize,
}

/// Supervisor failure.  No authority error contains keys, route scalar or
/// payload bytes.
#[derive(Debug, thiserror::Error)]
pub enum RouteSupervisorErrorV1 {
    /// Invalid duration, renewal or batch configuration.
    #[error("invalid route supervisor configuration")]
    InvalidConfiguration,
    /// Clock failed or returned a non-monotonic value for this supervisor.
    #[error("route supervisor clock refused operation")]
    Clock(#[from] ClockErrorV1),
    /// Durable route store rejected the operation.
    #[error("route supervisor store: {0}")]
    Store(#[from] RouteStoreErrorV1),
    /// The sole production route-store opening is currently borrowed by a
    /// sibling typed authority. No database operation was attempted and the
    /// caller may retry the same durable step.
    #[error("route supervisor store authority is temporarily busy")]
    StoreAuthorityBusy,
    /// Authenticated admission belongs to another route.
    #[error("authenticated route admission is outside supervisor scope")]
    AdmissionScopeMismatch,
    /// Refund authority refused the exact route revision.
    #[error("refund arming authority: {0}")]
    RefundAuthority(AuthorityRefusalV1),
    /// Route action authority refused the exact requested action.
    #[error("route action authority: {0}")]
    RouteActionAuthority(AuthorityRefusalV1),
    /// Chain observation authority refused the exact public query.
    #[error("chain observation authority: {0}")]
    ChainObservationAuthority(AuthorityRefusalV1),
    /// A typed authority returned a different class or target than requested.
    #[error("typed authority response does not match its scoped request")]
    InvalidAuthorityResponse,
    /// Runner authority refused the exact action.
    #[error("runner action authority: {0}")]
    RunnerAuthority(AuthorityRefusalV1),
    /// External custody authority refused the exact action.
    #[error("external custody authority: {0}")]
    ExternalCustodyAuthority(AuthorityRefusalV1),
    /// Timer authority refused the exact wakeup.
    #[error("timer authority: {0}")]
    TimerAuthority(AuthorityRefusalV1),
    /// Takeover reconciler refused the exact stale action.
    #[error("takeover reconciliation authority: {0}")]
    ReconciliationAuthority(AuthorityRefusalV1),
    /// A claimed effect exists without frozen route bindings.
    #[error("claimed action has no frozen bindings")]
    MissingFrozenBindings,
    /// Authority receipt was empty or had the wrong exposure shape.
    #[error("invalid action externalization receipt")]
    InvalidExternalizationReceipt,
    /// Receipt transaction differs from the immutable expected transaction.
    #[error("externalization receipt transaction mismatch")]
    ExpectedTransactionMismatch,
    /// A timer authority returned an event class owned by another authority or
    /// unsafe for a preclaimed timer batch.
    #[error("timer authority returned an impermissible event")]
    InvalidTimerEvent,
    /// Reconciler changed the store-authenticated intent or returned no proof.
    #[error("takeover reconciliation proof does not match committed intent")]
    InvalidReconciliationProof,
    /// Trusted clock moved backwards during this supervisor lifetime.
    #[error("route supervisor clock moved backwards")]
    ClockRollback,
}

#[derive(Debug)]
enum ClaimedWorkV1 {
    Runner(ClaimedRouteEffectV1),
    Custody(ClaimedExternalCustodyEffectV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CustodyDispatchDispositionV1 {
    AggregateExternalized,
    PartialProgress,
    ProgressUnchanged,
    Unknown,
}

impl ClaimedWorkV1 {
    fn priority(&self) -> EffectPriorityV1 {
        match self {
            Self::Runner(claimed) => claimed.effect.priority,
            Self::Custody(claimed) => claimed.priority,
        }
    }

    fn effect_id(&self) -> EffectIdV1 {
        match self {
            Self::Runner(claimed) => claimed.effect.effect_id,
            Self::Custody(claimed) => claimed.effect_id,
        }
    }
}

/// Durable supervisor for exactly one route and one current fencing epoch.
///
/// Raw reducer events deliberately have no public submission boundary; callers
/// must use admission, refund, action, observation, operator or timer methods.
///
/// ```compile_fail
/// use dom_interopd::{Clock, RouteSupervisorV1};
/// use route_executor::RouteEventV1;
///
/// fn bypass<C: Clock>(supervisor: &mut RouteSupervisorV1<C>, event: &RouteEventV1) {
///     supervisor.submit_event([7; 32], event).unwrap();
/// }
/// ```
struct SignerCapabilityRequestV1 {
    effect_id: EffectIdV1,
    leg: LegIdV1,
    action: ActionKindV1,
    priority: EffectPriorityV1,
    semantic_digest: Digest32,
    fencing_epoch: u64,
    dispatch_digest: Digest32,
    attempt: u64,
    expires_at_unix_ms: u64,
    expected_transaction_id: Option<Digest32>,
    contains_route_secret: bool,
    acknowledged_custody_progress: Option<AcknowledgedCustodyProgressV1>,
}

/// Exact route-store operations owned by the supervisor. This surface is
/// crate-private so production can share one physical opening with typed
/// terminal-proof handles without exposing the raw SQLite authority.
pub(crate) trait RouteSupervisorStoreAuthorityV1 {
    fn acquire_route_lease(
        &mut self,
        route_id: RouteIdV1,
        owner_id: Digest32,
        now_unix_ms: u64,
        duration_ms: u64,
    ) -> Result<RouteLeaseV1, RouteSupervisorErrorV1>;

    fn load_snapshot(&self, route_id: RouteIdV1)
        -> Result<RouteSnapshotV1, RouteSupervisorErrorV1>;

    fn journal(
        &self,
        route_id: RouteIdV1,
    ) -> Result<Vec<RouteJournalEntryV1>, RouteSupervisorErrorV1>;

    fn pending_effect_count(&self, route_id: RouteIdV1) -> Result<u64, RouteSupervisorErrorV1>;

    fn active_timer_count(&self, route_id: RouteIdV1) -> Result<u64, RouteSupervisorErrorV1>;

    fn mint_route_secret_retirement_capability(
        &self,
        route_id: RouteIdV1,
    ) -> Result<RouteSecretRetirementCapabilityV1, RouteSupervisorErrorV1>;

    fn renew_lease(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        duration_ms: u64,
    ) -> Result<RouteLeaseV1, RouteSupervisorErrorV1>;

    fn apply_event(
        &mut self,
        lease: RouteLeaseV1,
        expected_revision: u64,
        event_id: EventIdV1,
        event: &RouteEventV1,
        now_unix_ms: u64,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1>;

    fn claim_due_timers(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ClaimedRouteTimerV1>, RouteSupervisorErrorV1>;

    fn claim_external_custody_effect_by_id(
        &mut self,
        lease: RouteLeaseV1,
        effect_id: EffectIdV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
    ) -> Result<Option<ClaimedExternalCustodyEffectV1>, RouteSupervisorErrorV1>;

    fn claim_next_effect(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
    ) -> Result<Option<ClaimedRouteWorkV1>, RouteSupervisorErrorV1>;

    fn committed_action_intent(
        &mut self,
        lease: RouteLeaseV1,
        effect_id: EffectIdV1,
        now_unix_ms: u64,
    ) -> Result<ActionIntentV1, RouteSupervisorErrorV1>;

    fn claim_effects(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ClaimedRouteEffectV1>, RouteSupervisorErrorV1>;

    fn claim_external_custody_effects(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ClaimedExternalCustodyEffectV1>, RouteSupervisorErrorV1>;

    fn complete_timer(
        &mut self,
        lease: RouteLeaseV1,
        timer_id: TimerIdV1,
        timer_hash: Digest32,
        now_unix_ms: u64,
    ) -> Result<CompletionOutcomeV1, RouteSupervisorErrorV1>;
}

struct ExclusiveRouteSupervisorStoreAuthorityV1 {
    store: DurableRouteStoreV1,
}

impl RouteSupervisorStoreAuthorityV1 for ExclusiveRouteSupervisorStoreAuthorityV1 {
    fn acquire_route_lease(
        &mut self,
        route_id: RouteIdV1,
        owner_id: Digest32,
        now_unix_ms: u64,
        duration_ms: u64,
    ) -> Result<RouteLeaseV1, RouteSupervisorErrorV1> {
        Ok(self
            .store
            .acquire_lease(route_id, owner_id, now_unix_ms, duration_ms)?
            .lease())
    }

    fn load_snapshot(
        &self,
        route_id: RouteIdV1,
    ) -> Result<RouteSnapshotV1, RouteSupervisorErrorV1> {
        Ok(self.store.load_snapshot(route_id)?)
    }

    fn journal(
        &self,
        route_id: RouteIdV1,
    ) -> Result<Vec<RouteJournalEntryV1>, RouteSupervisorErrorV1> {
        Ok(self.store.journal(route_id)?)
    }

    fn pending_effect_count(&self, route_id: RouteIdV1) -> Result<u64, RouteSupervisorErrorV1> {
        Ok(self.store.pending_effect_count(route_id)?)
    }

    fn active_timer_count(&self, route_id: RouteIdV1) -> Result<u64, RouteSupervisorErrorV1> {
        Ok(self.store.active_timer_count(route_id)?)
    }

    fn mint_route_secret_retirement_capability(
        &self,
        route_id: RouteIdV1,
    ) -> Result<RouteSecretRetirementCapabilityV1, RouteSupervisorErrorV1> {
        Ok(self
            .store
            .mint_route_secret_retirement_capability_v1(route_id)?)
    }

    fn renew_lease(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        duration_ms: u64,
    ) -> Result<RouteLeaseV1, RouteSupervisorErrorV1> {
        Ok(self.store.renew_lease(lease, now_unix_ms, duration_ms)?)
    }

    fn apply_event(
        &mut self,
        lease: RouteLeaseV1,
        expected_revision: u64,
        event_id: EventIdV1,
        event: &RouteEventV1,
        now_unix_ms: u64,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1> {
        Ok(self
            .store
            .apply_event(lease, expected_revision, event_id, event, now_unix_ms)?)
    }

    fn claim_due_timers(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ClaimedRouteTimerV1>, RouteSupervisorErrorV1> {
        Ok(self
            .store
            .claim_due_timers(lease, now_unix_ms, dispatch_lease_ms, limit)?)
    }

    fn claim_external_custody_effect_by_id(
        &mut self,
        lease: RouteLeaseV1,
        effect_id: EffectIdV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
    ) -> Result<Option<ClaimedExternalCustodyEffectV1>, RouteSupervisorErrorV1> {
        Ok(self.store.claim_external_custody_effect_by_id(
            lease,
            effect_id,
            now_unix_ms,
            dispatch_lease_ms,
        )?)
    }

    fn claim_next_effect(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
    ) -> Result<Option<ClaimedRouteWorkV1>, RouteSupervisorErrorV1> {
        Ok(self
            .store
            .claim_next_effect(lease, now_unix_ms, dispatch_lease_ms)?)
    }

    fn committed_action_intent(
        &mut self,
        lease: RouteLeaseV1,
        effect_id: EffectIdV1,
        now_unix_ms: u64,
    ) -> Result<ActionIntentV1, RouteSupervisorErrorV1> {
        Ok(self
            .store
            .committed_action_intent(lease, effect_id, now_unix_ms)?)
    }

    fn claim_effects(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ClaimedRouteEffectV1>, RouteSupervisorErrorV1> {
        Ok(self
            .store
            .claim_effects(lease, now_unix_ms, dispatch_lease_ms, limit)?)
    }

    fn claim_external_custody_effects(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ClaimedExternalCustodyEffectV1>, RouteSupervisorErrorV1> {
        Ok(self.store.claim_external_custody_effects(
            lease,
            now_unix_ms,
            dispatch_lease_ms,
            limit,
        )?)
    }

    fn complete_timer(
        &mut self,
        lease: RouteLeaseV1,
        timer_id: TimerIdV1,
        timer_hash: Digest32,
        now_unix_ms: u64,
    ) -> Result<CompletionOutcomeV1, RouteSupervisorErrorV1> {
        Ok(self
            .store
            .complete_timer(lease, timer_id, timer_hash, now_unix_ms)?)
    }
}

pub struct RouteSupervisorV1<C: Clock> {
    store: Box<dyn RouteSupervisorStoreAuthorityV1>,
    lease: RouteLeaseV1,
    config: RouteSupervisorConfigV1,
    clock: C,
    last_now_unix_ms: u64,
}

impl<C: Clock> core::fmt::Debug for RouteSupervisorV1<C> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RouteSupervisorV1")
            .field("route_id", &self.lease.route_id)
            .field("fencing_epoch", &self.lease.fencing_epoch)
            .field("lease_until_unix_ms", &self.lease.lease_until_unix_ms)
            .finish_non_exhaustive()
    }
}

impl<C: Clock> RouteSupervisorV1<C> {
    /// Acquires or idempotently resumes ownership of one existing route.
    ///
    /// This constructor is a composition-root trust boundary: the caller must
    /// transfer the sole production writer handle here and must not disclose
    /// the database path or owner identity to plugins/untrusted components.
    /// Low-level `route-executor` store code is part of the daemon TCB, not an
    /// authorization API for in-process extensions.
    pub fn acquire(
        store: DurableRouteStoreV1,
        route_id: RouteIdV1,
        owner_id: Digest32,
        config: RouteSupervisorConfigV1,
        clock: C,
    ) -> Result<Self, RouteSupervisorErrorV1> {
        Self::acquire_with_authority(
            Box::new(ExclusiveRouteSupervisorStoreAuthorityV1 { store }),
            route_id,
            owner_id,
            config,
            clock,
        )
    }

    /// Acquires production supervision through a purpose-specific handle that
    /// shares the sole physical store opening with terminal proof producers.
    #[cfg(feature = "production")]
    pub(crate) fn acquire_production_route_store(
        store: crate::production_f6::terminal_release::ProductionRouteStoreRuntimeAuthorityV2,
        route_id: RouteIdV1,
        owner_id: Digest32,
        config: RouteSupervisorConfigV1,
        clock: C,
    ) -> Result<Self, RouteSupervisorErrorV1> {
        Self::acquire_with_authority(Box::new(store), route_id, owner_id, config, clock)
    }

    fn acquire_with_authority(
        mut store: Box<dyn RouteSupervisorStoreAuthorityV1>,
        route_id: RouteIdV1,
        owner_id: Digest32,
        config: RouteSupervisorConfigV1,
        clock: C,
    ) -> Result<Self, RouteSupervisorErrorV1> {
        if route_id == ZERO_DIGEST || owner_id == ZERO_DIGEST {
            return Err(RouteSupervisorErrorV1::InvalidConfiguration);
        }
        let now = clock.now_unix_ms()?;
        if now == 0 {
            return Err(RouteSupervisorErrorV1::Clock(
                ClockErrorV1::InvalidManualTime,
            ));
        }
        let lease = store.acquire_route_lease(route_id, owner_id, now, config.lease_duration_ms)?;
        Ok(Self {
            store,
            lease,
            config,
            clock,
            last_now_unix_ms: now,
        })
    }

    /// Current read-only route/fence status.  The writable owner token never
    /// leaves the supervisor.
    pub const fn lease_status(&self) -> RouteLeaseStatusV1 {
        RouteLeaseStatusV1 {
            route_id: self.lease.route_id,
            fencing_epoch: self.lease.fencing_epoch,
            lease_until_unix_ms: self.lease.lease_until_unix_ms,
        }
    }

    /// Defensive scheduling bounds retained by this supervisor.
    pub const fn config(&self) -> RouteSupervisorConfigV1 {
        self.config
    }

    /// Current route snapshot.
    pub fn snapshot(&self) -> Result<RouteSnapshotV1, RouteSupervisorErrorV1> {
        Ok(self.store.load_snapshot(self.lease.route_id)?)
    }

    /// Verified public route journal, primarily for recovery/diagnostics.
    pub fn journal(&self) -> Result<Vec<RouteJournalEntryV1>, RouteSupervisorErrorV1> {
        Ok(self.store.journal(self.lease.route_id)?)
    }

    /// Number of pending outbox rows across fencing generations.
    pub fn pending_effect_count(&self) -> Result<u64, RouteSupervisorErrorV1> {
        Ok(self.store.pending_effect_count(self.lease.route_id)?)
    }

    /// Number of active timers across fencing generations.
    pub fn active_timer_count(&self) -> Result<u64, RouteSupervisorErrorV1> {
        Ok(self.store.active_timer_count(self.lease.route_id)?)
    }

    /// Mint the move-only terminal proof used to retire this route's encrypted
    /// public-scalar recovery record. The Store replays and authenticates the
    /// complete route journal on every call.
    pub(crate) fn mint_route_secret_retirement_capability(
        &self,
    ) -> Result<RouteSecretRetirementCapabilityV1, RouteSupervisorErrorV1> {
        self.store
            .mint_route_secret_retirement_capability(self.lease.route_id)
    }

    /// Explicitly renews the exact current lease without changing its fence.
    pub fn renew(&mut self) -> Result<RouteLeaseStatusV1, RouteSupervisorErrorV1> {
        let now = self.trusted_now()?;
        self.lease = self
            .store
            .renew_lease(self.lease, now, self.config.lease_duration_ms)?;
        Ok(self.lease_status())
    }

    /// Freezes terms only from a route-scoped authenticated registry
    /// capability.  A capability admitted for another route is refused.
    pub fn admit_route(
        &mut self,
        event_id: EventIdV1,
        admission: &AuthenticatedRouteAdmissionV1,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1> {
        if admission.route_id() != self.lease.route_id {
            return Err(RouteSupervisorErrorV1::AdmissionScopeMismatch);
        }
        let now = self.trusted_now()?;
        self.maybe_renew_at(now)?;
        let snapshot = self.store.load_snapshot(self.lease.route_id)?;
        let event = RouteEventV1::FreezeTerms(admission.frozen_bindings().clone());
        self.submit_event_at_revision(event_id, &event, snapshot.revision, now)
    }

    /// Arms both refund exits through their dedicated durable authority.
    pub fn arm_refunds<A: RefundArmingAuthority>(
        &mut self,
        event_id: EventIdV1,
        authority: &mut A,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1> {
        let now = self.trusted_now()?;
        self.maybe_renew_at(now)?;
        let snapshot = self.store.load_snapshot(self.lease.route_id)?;
        let bindings = snapshot
            .bindings
            .as_ref()
            .ok_or(RouteSupervisorErrorV1::MissingFrozenBindings)?;
        let refunds = authority
            .arm_refunds(RefundArmingRequestV1 {
                route_id: self.lease.route_id,
                event_id,
                fencing_epoch: self.lease.fencing_epoch,
                bindings,
                snapshot: &snapshot,
            })
            .map_err(RouteSupervisorErrorV1::RefundAuthority)?;
        let completed_at = self.trusted_now()?;
        self.maybe_renew_at(completed_at)?;
        self.submit_event_at_revision(
            event_id,
            &RouteEventV1::ArmRefunds(refunds),
            snapshot.revision,
            completed_at,
        )
    }

    /// Authorizes one exact economic action through the route planner/custody
    /// authority and atomically commits its immutable outbox intent.
    pub fn authorize_action<A: RouteActionAuthority>(
        &mut self,
        event_id: EventIdV1,
        leg: LegIdV1,
        action: ActionKindV1,
        authority: &mut A,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1> {
        let now = self.trusted_now()?;
        self.maybe_renew_at(now)?;
        let snapshot = self.store.load_snapshot(self.lease.route_id)?;
        let bindings = snapshot
            .bindings
            .as_ref()
            .ok_or(RouteSupervisorErrorV1::MissingFrozenBindings)?;
        let intent = authority
            .authorize_route_action(RouteActionAuthorizationRequestV1 {
                route_id: self.lease.route_id,
                event_id,
                fencing_epoch: self.lease.fencing_epoch,
                leg,
                action,
                bindings,
                snapshot: &snapshot,
            })
            .map_err(RouteSupervisorErrorV1::RouteActionAuthority)?;
        if intent.leg != leg || intent.kind != action {
            return Err(RouteSupervisorErrorV1::InvalidAuthorityResponse);
        }
        let completed_at = self.trusted_now()?;
        self.maybe_renew_at(completed_at)?;
        self.submit_event_at_revision(
            event_id,
            &RouteEventV1::CommitAction(intent),
            snapshot.revision,
            completed_at,
        )
    }

    /// Records finality, reorg invalidation or independent public-secret
    /// evidence only after a typed chain authority verifies the exact query.
    pub fn record_chain_observation<A: ChainObservationAuthority>(
        &mut self,
        event_id: EventIdV1,
        query: ChainObservationQueryV1,
        authority: &mut A,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1> {
        if !observation_query_is_well_formed(query) {
            return Err(RouteSupervisorErrorV1::InvalidAuthorityResponse);
        }
        let now = self.trusted_now()?;
        self.maybe_renew_at(now)?;
        let snapshot = self.store.load_snapshot(self.lease.route_id)?;
        let bindings = snapshot
            .bindings
            .as_ref()
            .ok_or(RouteSupervisorErrorV1::MissingFrozenBindings)?;
        let verified = authority
            .verify_chain_observation(ChainObservationRequestV1 {
                route_id: self.lease.route_id,
                event_id,
                fencing_epoch: self.lease.fencing_epoch,
                query,
                bindings,
                snapshot: &snapshot,
            })
            .map_err(RouteSupervisorErrorV1::ChainObservationAuthority)?;
        let completed_at = self.trusted_now()?;
        self.maybe_renew_at(completed_at)?;
        let event = verified_observation_event(query, verified, completed_at)?;
        self.submit_event_at_revision(event_id, &event, snapshot.revision, completed_at)
    }

    /// Applies an explicit operator health transition.  This cannot encode an
    /// economic, admission, finality or externalization event.
    pub fn set_health(
        &mut self,
        event_id: EventIdV1,
        target: HealthStateV1,
        reason_digest: Digest32,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1> {
        self.submit_operational_event(
            event_id,
            &RouteEventV1::SetHealth {
                target,
                reason_digest,
            },
        )
    }

    /// Schedules one explicit durable internal wakeup.
    pub fn schedule_timer(
        &mut self,
        event_id: EventIdV1,
        kind: TimerKindV1,
        deadline_unix_ms: u64,
        context_digest: Digest32,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1> {
        self.submit_operational_event(
            event_id,
            &RouteEventV1::ScheduleTimer {
                kind,
                deadline_unix_ms,
                context_digest,
            },
        )
    }

    /// Cancels one known active internal wakeup.
    pub fn cancel_timer(
        &mut self,
        event_id: EventIdV1,
        timer_id: TimerIdV1,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1> {
        self.submit_operational_event(event_id, &RouteEventV1::CancelTimer { timer_id })
    }

    /// Terminates an entirely unfunded route with a public reason commitment.
    pub fn abort_unfunded(
        &mut self,
        event_id: EventIdV1,
        reason_digest: Digest32,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1> {
        self.submit_operational_event(event_id, &RouteEventV1::AbortUnfunded { reason_digest })
    }

    /// Dispatches at most one due timer and never claims an economic effect.
    ///
    /// This narrow primitive lets the production driver enforce a structural
    /// one-authority-call boundary. A timer event is committed before its
    /// completion exactly as in [`Self::tick`], but later timers and both
    /// outbox classes remain untouched for a subsequent drive step.
    pub fn dispatch_one_due_timer<T: TimerAuthority>(
        &mut self,
        timers: &mut T,
    ) -> Result<RouteSupervisorTickReportV1, RouteSupervisorErrorV1> {
        let now = self.trusted_now()?;
        let renewed = self.maybe_renew_at(now)?;
        let mut report = RouteSupervisorTickReportV1 {
            lease_renewed: renewed,
            ..RouteSupervisorTickReportV1::default()
        };
        let snapshot = self.store.load_snapshot(self.lease.route_id)?;
        if let Some(reference) = committed_urgent_claim(&snapshot) {
            if reference.fencing_epoch > self.lease.fencing_epoch {
                return Err(RouteSupervisorErrorV1::Store(
                    RouteStoreErrorV1::CorruptState,
                ));
            }
            if reference.fencing_epoch < self.lease.fencing_epoch {
                report.takeover_reconciliation_required = true;
            }
            // A committed urgent claim blocks timers. It is deliberately not
            // claimed here because this method has no custody authority.
            return Ok(report);
        }
        let claimed =
            self.store
                .claim_due_timers(self.lease, now, self.config.dispatch_lease_ms, 1)?;
        if let Some(timer) = claimed.into_iter().next() {
            self.dispatch_timer(timer, timers, &mut report)?;
        }
        Ok(report)
    }

    /// Dispatches at most one economic effect and never claims a timer.
    ///
    /// Runner and external-custody rows are selected together, inside one
    /// store transaction and in the same priority order as the full scheduler.
    /// Therefore this method cannot lease one row from each class before
    /// invoking only one authority.
    pub fn dispatch_one_effect<R, E>(
        &mut self,
        runner: &mut R,
        external_custody: &mut E,
    ) -> Result<RouteSupervisorTickReportV1, RouteSupervisorErrorV1>
    where
        R: RunnerActionAuthority,
        E: ExternalCustodyAuthority,
    {
        let now = self.trusted_now()?;
        let renewed = self.maybe_renew_at(now)?;
        let mut report = RouteSupervisorTickReportV1 {
            lease_renewed: renewed,
            ..RouteSupervisorTickReportV1::default()
        };
        let snapshot = self.store.load_snapshot(self.lease.route_id)?;
        if let Some(reference) = committed_urgent_claim(&snapshot) {
            if reference.fencing_epoch > self.lease.fencing_epoch {
                return Err(RouteSupervisorErrorV1::Store(
                    RouteStoreErrorV1::CorruptState,
                ));
            }
            if reference.fencing_epoch < self.lease.fencing_epoch {
                report.takeover_reconciliation_required = true;
                return Ok(report);
            }
            let claimed = self.store.claim_external_custody_effect_by_id(
                self.lease,
                reference.effect_id,
                now,
                self.config.dispatch_lease_ms,
            )?;
            if let Some(item) = claimed {
                if item.priority != EffectPriorityV1::SecretPublicUrgent {
                    return Err(RouteSupervisorErrorV1::Store(
                        RouteStoreErrorV1::CorruptState,
                    ));
                }
                let disposition = self.dispatch_custody(item, external_custody)?;
                record_custody_dispatch_report(&mut report, true, disposition);
            } else {
                report.urgent_in_flight = true;
            }
            return Ok(report);
        }
        match self
            .store
            .claim_next_effect(self.lease, now, self.config.dispatch_lease_ms)?
        {
            Some(ClaimedRouteWorkV1::Runner(claimed)) => {
                let urgent = claimed.effect.priority == EffectPriorityV1::SecretPublicUrgent;
                self.dispatch_runner(claimed, runner)?;
                if urgent {
                    report.urgent_externalized = 1;
                } else {
                    report.runner_externalized = 1;
                }
            }
            Some(ClaimedRouteWorkV1::ExternalCustody(claimed)) => {
                let urgent = claimed.priority == EffectPriorityV1::SecretPublicUrgent;
                let disposition = self.dispatch_custody(claimed, external_custody)?;
                record_custody_dispatch_report(&mut report, urgent, disposition);
            }
            None => {}
        }
        Ok(report)
    }

    /// Executes one bounded scheduling pass.  A committed secret-public
    /// upstream claim is the only work allowed ahead of due timers.  Otherwise
    /// timers commit their deterministic events first, then runner and custody
    /// queues are merged by priority.
    pub fn tick<R, E, T>(
        &mut self,
        runner: &mut R,
        external_custody: &mut E,
        timers: &mut T,
    ) -> Result<RouteSupervisorTickReportV1, RouteSupervisorErrorV1>
    where
        R: RunnerActionAuthority,
        E: ExternalCustodyAuthority,
        T: TimerAuthority,
    {
        let now = self.trusted_now()?;
        let renewed = self.maybe_renew_at(now)?;
        let mut report = RouteSupervisorTickReportV1 {
            lease_renewed: renewed,
            ..RouteSupervisorTickReportV1::default()
        };
        let snapshot = self.store.load_snapshot(self.lease.route_id)?;
        if let Some(reference) = committed_urgent_claim(&snapshot) {
            if reference.fencing_epoch > self.lease.fencing_epoch {
                return Err(RouteSupervisorErrorV1::Store(
                    RouteStoreErrorV1::CorruptState,
                ));
            }
            if reference.fencing_epoch < self.lease.fencing_epoch {
                report.takeover_reconciliation_required = true;
                return Ok(report);
            }
            let claimed = self.store.claim_external_custody_effect_by_id(
                self.lease,
                reference.effect_id,
                now,
                self.config.dispatch_lease_ms,
            )?;
            if let Some(item) = claimed {
                if item.priority != EffectPriorityV1::SecretPublicUrgent {
                    return Err(RouteSupervisorErrorV1::Store(
                        RouteStoreErrorV1::CorruptState,
                    ));
                }
                let disposition = self.dispatch_custody(item, external_custody)?;
                record_custody_dispatch_report(&mut report, true, disposition);
            } else {
                report.urgent_in_flight = true;
            }
            // No due timer or lower-priority action can overtake a committed
            // urgent claim, and exact-id claiming cannot lease either class.
            return Ok(report);
        }

        self.dispatch_due_timers(timers, &mut report)?;
        let mut work = self.claim_merged_effects()?;
        work.sort_by(|left, right| {
            priority_rank(right.priority())
                .cmp(&priority_rank(left.priority()))
                .then_with(|| left.effect_id().cmp(&right.effect_id()))
        });
        for item in work {
            match item {
                ClaimedWorkV1::Runner(claimed) => {
                    let urgent = claimed.effect.priority == EffectPriorityV1::SecretPublicUrgent;
                    self.dispatch_runner(claimed, runner)?;
                    if urgent {
                        report.urgent_externalized += 1;
                    } else {
                        report.runner_externalized += 1;
                    }
                }
                ClaimedWorkV1::Custody(claimed) => {
                    let urgent = claimed.priority == EffectPriorityV1::SecretPublicUrgent;
                    let contains_route_secret = claimed.contains_route_secret;
                    let disposition = self.dispatch_custody(claimed, external_custody)?;
                    record_custody_dispatch_report(&mut report, urgent, disposition);
                    if contains_route_secret
                        || disposition != CustodyDispatchDispositionV1::AggregateExternalized
                    {
                        // A secret-bearing completion or any incomplete
                        // aggregate must yield immediately so newly urgent
                        // work cannot be overtaken by a preclaimed batch.
                        break;
                    }
                }
            }
        }
        Ok(report)
    }

    /// Reconciles old-fence committed actions after takeover.  The supervisor
    /// never claims or blindly replays them.  It first asks the route store for
    /// the exact active intent and accepts only an externalization proof, an
    /// exact non-externalization proof followed by re-fencing, or `Unknown`.
    pub fn reconcile_takeover<A: TakeoverReconciliationAuthority>(
        &mut self,
        authority: &mut A,
    ) -> Result<TakeoverReconciliationReportV1, RouteSupervisorErrorV1> {
        let now = self.trusted_now()?;
        self.maybe_renew_at(now)?;
        let snapshot = self.store.load_snapshot(self.lease.route_id)?;
        let stale = stale_committed_actions(&snapshot, self.lease.fencing_epoch)?;
        if stale.is_empty() {
            return Ok(TakeoverReconciliationReportV1::default());
        }
        let bindings = snapshot
            .bindings
            .clone()
            .ok_or(RouteSupervisorErrorV1::MissingFrozenBindings)?;
        let mut report = TakeoverReconciliationReportV1::default();
        for (leg, action, reference) in stale.into_iter().take(self.config.per_queue_batch_limit) {
            let intent_now = self.trusted_now()?;
            self.maybe_renew_at(intent_now)?;
            let intent =
                self.store
                    .committed_action_intent(self.lease, reference.effect_id, intent_now)?;
            if intent.leg != leg
                || intent.kind != action
                || intent.semantic_digest != reference.semantic_digest
                || intent.contains_route_secret != reference.contains_route_secret
            {
                return Err(RouteSupervisorErrorV1::InvalidReconciliationProof);
            }
            let (dispatch_digest, expected_transaction_id) = dispatch_binding(&intent.dispatch);
            let outcome = authority
                .reconcile_committed_action(ReconciliationRequestV1 {
                    route_id: self.lease.route_id,
                    effect_id: reference.effect_id,
                    prior_fence: reference.fencing_epoch,
                    current_fence: self.lease.fencing_epoch,
                    bindings: &bindings,
                    intent: &intent,
                    dispatch_digest,
                    expected_transaction_id,
                })
                .map_err(RouteSupervisorErrorV1::ReconciliationAuthority)?;
            match outcome {
                TakeoverReconciliationOutcomeV1::Externalized(receipt) => {
                    self.record_externalization(
                        reference.effect_id,
                        leg,
                        action,
                        reference.contains_route_secret,
                        expected_transaction_id,
                        receipt,
                    )?;
                    report.externalized += 1;
                }
                TakeoverReconciliationOutcomeV1::ProvenNotExternalized {
                    intent: proven,
                    evidence_digest,
                } => {
                    if proven != intent || evidence_digest == ZERO_DIGEST {
                        return Err(RouteSupervisorErrorV1::InvalidReconciliationProof);
                    }
                    let event = RouteEventV1::ReauthorizeCommittedAction {
                        prior_effect_id: reference.effect_id,
                        non_externalization_evidence_digest: evidence_digest,
                        intent: proven,
                    };
                    let event_id = reauthorize_event_id(
                        self.lease.route_id,
                        reference.effect_id,
                        self.lease.fencing_epoch,
                    )?;
                    self.submit_supervisor_event(event_id, &event)?;
                    report.reauthorized += 1;
                }
                TakeoverReconciliationOutcomeV1::SafeToResumeCustody {
                    intent: proven,
                    evidence_digest,
                } => {
                    if proven != intent
                        || evidence_digest == ZERO_DIGEST
                        || !matches!(proven.dispatch, EffectDispatchV1::ExternalCustody { .. })
                    {
                        return Err(RouteSupervisorErrorV1::InvalidReconciliationProof);
                    }
                    let event = RouteEventV1::ReauthorizePartiallyExternalizedCustody {
                        prior_effect_id: reference.effect_id,
                        partial_externalization_evidence_digest: evidence_digest,
                        intent: proven,
                    };
                    let event_id = reauthorize_event_id(
                        self.lease.route_id,
                        reference.effect_id,
                        self.lease.fencing_epoch,
                    )?;
                    self.submit_supervisor_event(event_id, &event)?;
                    report.partial_custody_resumed += 1;
                }
                TakeoverReconciliationOutcomeV1::SecretPublicPartialCustody {
                    intent: proven,
                    progress_evidence_digest,
                    exposure,
                } => {
                    let progress_now = self.trusted_now()?;
                    if proven != intent
                        || !proven.contains_route_secret
                        || !matches!(proven.dispatch, EffectDispatchV1::ExternalCustody { .. })
                    {
                        return Err(RouteSupervisorErrorV1::InvalidReconciliationProof);
                    }
                    validate_partial_custody_progress(
                        true,
                        progress_evidence_digest,
                        Some(&exposure),
                        progress_now,
                    )?;
                    let progress_event = RouteEventV1::CustodyProgressRecorded {
                        leg,
                        kind: action,
                        effect_id: reference.effect_id,
                        progress_evidence_digest,
                        exposure: Some(exposure),
                    };
                    let progress_event_id = custody_progress_event_id(
                        self.lease.route_id,
                        reference.effect_id,
                        progress_evidence_digest,
                    )?;
                    self.submit_supervisor_event(progress_event_id, &progress_event)?;

                    let event = RouteEventV1::ReauthorizePartiallyExternalizedCustody {
                        prior_effect_id: reference.effect_id,
                        partial_externalization_evidence_digest: progress_evidence_digest,
                        intent: proven,
                    };
                    let event_id = reauthorize_event_id(
                        self.lease.route_id,
                        reference.effect_id,
                        self.lease.fencing_epoch,
                    )?;
                    self.submit_supervisor_event(event_id, &event)?;
                    report.partial_secret_custody_resumed += 1;
                }
                TakeoverReconciliationOutcomeV1::Unknown => report.unknown += 1,
            }
        }
        Ok(report)
    }

    fn trusted_now(&mut self) -> Result<u64, RouteSupervisorErrorV1> {
        let now = self.clock.now_unix_ms()?;
        if now == 0 {
            return Err(RouteSupervisorErrorV1::Clock(
                ClockErrorV1::InvalidManualTime,
            ));
        }
        if now < self.last_now_unix_ms {
            return Err(RouteSupervisorErrorV1::ClockRollback);
        }
        self.last_now_unix_ms = now;
        Ok(now)
    }

    fn maybe_renew_at(&mut self, now: u64) -> Result<bool, RouteSupervisorErrorV1> {
        let remaining = self.lease.lease_until_unix_ms.saturating_sub(now);
        if remaining <= self.config.renew_before_ms {
            self.lease = self
                .store
                .renew_lease(self.lease, now, self.config.lease_duration_ms)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn submit_event_at_revision(
        &mut self,
        event_id: EventIdV1,
        event: &RouteEventV1,
        expected_revision: u64,
        now: u64,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1> {
        Ok(self
            .store
            .apply_event(self.lease, expected_revision, event_id, event, now)?)
    }

    fn submit_fresh_event(
        &mut self,
        event_id: EventIdV1,
        event: &RouteEventV1,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1> {
        let now = self.trusted_now()?;
        self.maybe_renew_at(now)?;
        let snapshot = self.store.load_snapshot(self.lease.route_id)?;
        self.submit_event_at_revision(event_id, event, snapshot.revision, now)
    }

    fn submit_operational_event(
        &mut self,
        event_id: EventIdV1,
        event: &RouteEventV1,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1> {
        debug_assert!(matches!(
            event,
            RouteEventV1::SetHealth { .. }
                | RouteEventV1::ScheduleTimer { .. }
                | RouteEventV1::CancelTimer { .. }
                | RouteEventV1::AbortUnfunded { .. }
        ));
        self.submit_fresh_event(event_id, event)
    }

    fn submit_supervisor_event(
        &mut self,
        event_id: EventIdV1,
        event: &RouteEventV1,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1> {
        debug_assert!(matches!(
            event,
            RouteEventV1::ActionExternalized { .. }
                | RouteEventV1::CustodyProgressRecorded { .. }
                | RouteEventV1::ReauthorizeCommittedAction { .. }
                | RouteEventV1::ReauthorizePartiallyExternalizedCustody { .. }
        ));
        self.submit_fresh_event(event_id, event)
    }

    fn claim_merged_effects(&mut self) -> Result<Vec<ClaimedWorkV1>, RouteSupervisorErrorV1> {
        let now = self.trusted_now()?;
        self.maybe_renew_at(now)?;
        let runners = self.store.claim_effects(
            self.lease,
            now,
            self.config.dispatch_lease_ms,
            self.config.per_queue_batch_limit,
        )?;
        let custody = self.store.claim_external_custody_effects(
            self.lease,
            now,
            self.config.dispatch_lease_ms,
            self.config.per_queue_batch_limit,
        )?;
        let mut merged = Vec::with_capacity(runners.len() + custody.len());
        merged.extend(runners.into_iter().map(ClaimedWorkV1::Runner));
        merged.extend(custody.into_iter().map(ClaimedWorkV1::Custody));
        Ok(merged)
    }

    fn dispatch_runner<R: RunnerActionAuthority>(
        &mut self,
        claimed: ClaimedRouteEffectV1,
        authority: &mut R,
    ) -> Result<(), RouteSupervisorErrorV1> {
        let payload = match &claimed.effect.dispatch {
            EffectDispatchV1::RunnerPayload {
                payload,
                payload_digest,
            } => {
                if *payload_digest == ZERO_DIGEST || claimed.effect.contains_route_secret {
                    return Err(RouteSupervisorErrorV1::InvalidExternalizationReceipt);
                }
                payload.as_slice()
            }
            EffectDispatchV1::ExternalCustody { .. } => {
                return Err(RouteSupervisorErrorV1::InvalidExternalizationReceipt)
            }
        };
        let capability = self.runner_capability(&claimed)?;
        let receipt = authority
            .externalize_runner_action(RunnerActionRequestV1 {
                capability,
                payload,
            })
            .map_err(RouteSupervisorErrorV1::RunnerAuthority)?;
        self.record_externalization(
            claimed.effect.effect_id,
            claimed.effect.leg,
            claimed.effect.kind,
            claimed.effect.contains_route_secret,
            None,
            receipt,
        )
    }

    fn dispatch_custody<E: ExternalCustodyAuthority>(
        &mut self,
        claimed: ClaimedExternalCustodyEffectV1,
        authority: &mut E,
    ) -> Result<CustodyDispatchDispositionV1, RouteSupervisorErrorV1> {
        let expected = claimed.transaction_id;
        let capability = self.custody_capability(&claimed)?;
        let outcome = authority
            .externalize_custodied_action(ExternalCustodyActionRequestV1 { capability })
            .map_err(RouteSupervisorErrorV1::ExternalCustodyAuthority)?;
        match outcome {
            CustodyDispatchOutcomeV1::AggregateExternalized(receipt) => {
                self.record_externalization(
                    claimed.effect_id,
                    claimed.leg,
                    claimed.kind,
                    claimed.contains_route_secret,
                    Some(expected),
                    receipt,
                )?;
                Ok(CustodyDispatchDispositionV1::AggregateExternalized)
            }
            CustodyDispatchOutcomeV1::PartialProgress {
                progress_evidence_digest,
                exposure,
            } => self.record_partial_custody_progress(&claimed, progress_evidence_digest, exposure),
            CustodyDispatchOutcomeV1::Unknown => Ok(CustodyDispatchDispositionV1::Unknown),
        }
    }

    fn runner_capability(
        &self,
        claimed: &ClaimedRouteEffectV1,
    ) -> Result<SignerCapabilityV1, RouteSupervisorErrorV1> {
        let dispatch_digest = match &claimed.effect.dispatch {
            EffectDispatchV1::RunnerPayload { payload_digest, .. } => *payload_digest,
            EffectDispatchV1::ExternalCustody { .. } => {
                return Err(RouteSupervisorErrorV1::InvalidExternalizationReceipt)
            }
        };
        self.build_capability(SignerCapabilityRequestV1 {
            effect_id: claimed.effect.effect_id,
            leg: claimed.effect.leg,
            action: claimed.effect.kind,
            priority: claimed.effect.priority,
            semantic_digest: claimed.effect.semantic_digest,
            fencing_epoch: claimed.effect.fencing_epoch,
            dispatch_digest,
            attempt: claimed.attempts,
            expires_at_unix_ms: claimed.dispatch_lease_until_unix_ms,
            expected_transaction_id: None,
            contains_route_secret: claimed.effect.contains_route_secret,
            acknowledged_custody_progress: None,
        })
    }

    fn custody_capability(
        &self,
        claimed: &ClaimedExternalCustodyEffectV1,
    ) -> Result<SignerCapabilityV1, RouteSupervisorErrorV1> {
        let acknowledged_progress = self.acknowledged_custody_progress(claimed)?;
        self.build_capability(SignerCapabilityRequestV1 {
            effect_id: claimed.effect_id,
            leg: claimed.leg,
            action: claimed.kind,
            priority: claimed.priority,
            semantic_digest: claimed.semantic_digest,
            fencing_epoch: claimed.fencing_epoch,
            dispatch_digest: claimed.custody_digest,
            attempt: claimed.attempts,
            expires_at_unix_ms: claimed.dispatch_lease_until_unix_ms,
            expected_transaction_id: Some(claimed.transaction_id),
            contains_route_secret: claimed.contains_route_secret,
            acknowledged_custody_progress: acknowledged_progress,
        })
    }

    fn build_capability(
        &self,
        request: SignerCapabilityRequestV1,
    ) -> Result<SignerCapabilityV1, RouteSupervisorErrorV1> {
        let SignerCapabilityRequestV1 {
            effect_id,
            leg,
            action,
            priority,
            semantic_digest,
            fencing_epoch,
            dispatch_digest,
            attempt,
            expires_at_unix_ms,
            expected_transaction_id,
            contains_route_secret,
            acknowledged_custody_progress,
        } = request;
        if fencing_epoch != self.lease.fencing_epoch
            || attempt == 0
            || dispatch_digest == ZERO_DIGEST
            || expires_at_unix_ms > self.lease.lease_until_unix_ms
        {
            return Err(RouteSupervisorErrorV1::InvalidExternalizationReceipt);
        }
        let snapshot = self.store.load_snapshot(self.lease.route_id)?;
        let bindings = snapshot
            .bindings
            .ok_or(RouteSupervisorErrorV1::MissingFrozenBindings)?;
        if acknowledged_custody_progress
            .as_ref()
            .and_then(AcknowledgedCustodyProgressV1::exposure)
            .is_some()
            && matches!(snapshot.secret_visibility, SecretVisibilityV1::Private)
        {
            return Err(RouteSupervisorErrorV1::Store(
                RouteStoreErrorV1::CorruptState,
            ));
        }
        let route_first_public_exposure = match &snapshot.secret_visibility {
            SecretVisibilityV1::Private => None,
            SecretVisibilityV1::Public { first_exposure } => Some(first_exposure.clone()),
        };
        let attempt_id = capability_attempt_id(CapabilityAttemptBindingV1 {
            route_id: self.lease.route_id,
            effect_id,
            leg,
            action,
            priority,
            contains_route_secret,
            bindings: &bindings,
            fence: fencing_epoch,
            attempt,
            semantic_digest,
            dispatch_digest,
            expires_at_unix_ms,
            expected_transaction_id,
            acknowledged_custody_progress: acknowledged_custody_progress.as_ref(),
            route_first_public_exposure: route_first_public_exposure.as_ref(),
        })?;
        Ok(SignerCapabilityV1 {
            route_id: self.lease.route_id,
            effect_id,
            leg,
            action,
            semantic_digest,
            terms_digest: bindings.terms_digest,
            profile_bundle_digest: bindings.profile_bundle_digest,
            deployment_bundle_digest: bindings.deployment_bundle_digest,
            fencing_epoch,
            dispatch_digest,
            expires_at_unix_ms,
            attempt,
            one_shot_attempt_id: attempt_id,
            expected_transaction_id,
            contains_route_secret,
            acknowledged_custody_progress,
            route_first_public_exposure,
        })
    }

    fn acknowledged_custody_progress(
        &self,
        claimed: &ClaimedExternalCustodyEffectV1,
    ) -> Result<Option<AcknowledgedCustodyProgressV1>, RouteSupervisorErrorV1> {
        let journal = self.store.journal(self.lease.route_id)?;
        acknowledged_custody_progress_from_journal(
            self.lease.route_id,
            claimed.effect_id,
            claimed.leg,
            claimed.kind,
            &journal,
        )
    }

    fn record_externalization(
        &mut self,
        effect_id: EffectIdV1,
        leg: LegIdV1,
        action: ActionKindV1,
        contains_route_secret: bool,
        expected_transaction_id: Option<Digest32>,
        receipt: ActionExternalizationReceiptV1,
    ) -> Result<(), RouteSupervisorErrorV1> {
        if receipt.transaction_id == ZERO_DIGEST {
            return Err(RouteSupervisorErrorV1::InvalidExternalizationReceipt);
        }
        if expected_transaction_id.is_some_and(|expected| expected != receipt.transaction_id) {
            return Err(RouteSupervisorErrorV1::ExpectedTransactionMismatch);
        }
        let now = self.trusted_now()?;
        let snapshot = self.store.load_snapshot(self.lease.route_id)?;
        let secret_already_public = matches!(
            snapshot.secret_visibility,
            SecretVisibilityV1::Public { .. }
        );
        let exposure = match (
            contains_route_secret,
            secret_already_public,
            receipt.secret_exposure,
        ) {
            (false, _, None) => None,
            (true, true, None) => None,
            (true, _, Some((chain_id, evidence_digest)))
                if chain_id != ZERO_DIGEST && evidence_digest != ZERO_DIGEST =>
            {
                Some(PublicExposureV1 {
                    source: ExposureSourceV1::Externalized,
                    chain_id,
                    transaction_id: receipt.transaction_id,
                    evidence_digest,
                    observed_at_unix_ms: now,
                })
            }
            _ => return Err(RouteSupervisorErrorV1::InvalidExternalizationReceipt),
        };
        let event = RouteEventV1::ActionExternalized {
            leg,
            kind: action,
            effect_id,
            transaction_id: receipt.transaction_id,
            exposure,
        };
        let event_id = externalized_event_id(self.lease.route_id, effect_id)?;
        self.maybe_renew_at(now)?;
        let fresh = self.store.load_snapshot(self.lease.route_id)?;
        self.submit_event_at_revision(event_id, &event, fresh.revision, now)?;
        Ok(())
    }

    fn record_partial_custody_progress(
        &mut self,
        claimed: &ClaimedExternalCustodyEffectV1,
        progress_evidence_digest: Digest32,
        exposure: Option<PublicExposureV1>,
    ) -> Result<CustodyDispatchDispositionV1, RouteSupervisorErrorV1> {
        let now = self.trusted_now()?;
        validate_partial_custody_progress(
            claimed.contains_route_secret,
            progress_evidence_digest,
            exposure.as_ref(),
            now,
        )?;
        let event = RouteEventV1::CustodyProgressRecorded {
            leg: claimed.leg,
            kind: claimed.kind,
            effect_id: claimed.effect_id,
            progress_evidence_digest,
            exposure,
        };
        let event_id = custody_progress_event_id(
            self.lease.route_id,
            claimed.effect_id,
            progress_evidence_digest,
        )?;
        self.maybe_renew_at(now)?;
        let snapshot = self.store.load_snapshot(self.lease.route_id)?;
        match self.submit_event_at_revision(event_id, &event, snapshot.revision, now)? {
            CommitOutcomeV1::Committed { .. } => Ok(CustodyDispatchDispositionV1::PartialProgress),
            CommitOutcomeV1::DuplicateSameBytes { .. } => {
                Ok(CustodyDispatchDispositionV1::ProgressUnchanged)
            }
        }
    }

    fn dispatch_due_timers<T: TimerAuthority>(
        &mut self,
        authority: &mut T,
        report: &mut RouteSupervisorTickReportV1,
    ) -> Result<(), RouteSupervisorErrorV1> {
        let now = self.trusted_now()?;
        self.maybe_renew_at(now)?;
        let claimed = self.store.claim_due_timers(
            self.lease,
            now,
            self.config.dispatch_lease_ms,
            self.config.per_queue_batch_limit,
        )?;
        for claimed in claimed {
            self.dispatch_timer(claimed, authority, report)?;
            let snapshot = self.store.load_snapshot(self.lease.route_id)?;
            if committed_urgent_claim(&snapshot).is_some() || snapshot.aborted_unfunded {
                // A timer may deterministically authorize the urgent upstream
                // claim.  Already-leased later timers wait; the merged effect
                // pass below dispatches the new urgent action immediately.
                break;
            }
        }
        Ok(())
    }

    fn dispatch_timer<T: TimerAuthority>(
        &mut self,
        claimed: ClaimedRouteTimerV1,
        authority: &mut T,
        report: &mut RouteSupervisorTickReportV1,
    ) -> Result<(), RouteSupervisorErrorV1> {
        let event_id = timer_event_id(
            claimed.timer.route_id,
            claimed.timer.timer_id,
            claimed.timer_hash,
        )?;
        let snapshot = self.store.load_snapshot(self.lease.route_id)?;
        let event = authority
            .event_for_due_timer(TimerDispatchV1 {
                route_id: claimed.timer.route_id,
                timer_id: claimed.timer.timer_id,
                kind: claimed.timer.kind,
                deadline_unix_ms: claimed.timer.deadline_unix_ms,
                context_digest: claimed.timer.context_digest,
                scheduling_fence: claimed.timer.fencing_epoch,
                current_fence: self.lease.fencing_epoch,
                attempt: claimed.attempts,
                event_id,
            })
            .map_err(RouteSupervisorErrorV1::TimerAuthority)?;
        if !timer_event_is_permitted(&event) {
            return Err(RouteSupervisorErrorV1::InvalidTimerEvent);
        }
        let now = self.trusted_now()?;
        self.maybe_renew_at(now)?;
        let outcome = self.submit_event_at_revision(event_id, &event, snapshot.revision, now)?;
        let (revision, duplicate) = match outcome {
            CommitOutcomeV1::Committed { revision, .. } => (revision, false),
            CommitOutcomeV1::DuplicateSameBytes { revision } => (revision, true),
        };
        authority
            .event_committed(TimerEventCommitV1 {
                timer_id: claimed.timer.timer_id,
                event_id,
                revision,
                duplicate,
            })
            .map_err(RouteSupervisorErrorV1::TimerAuthority)?;
        let now = self.trusted_now()?;
        self.maybe_renew_at(now)?;
        match self.store.complete_timer(
            self.lease,
            claimed.timer.timer_id,
            claimed.timer_hash,
            now,
        )? {
            CompletionOutcomeV1::Completed | CompletionOutcomeV1::AlreadyCompleted => {}
        }
        report.timers_completed += 1;
        if duplicate {
            report.duplicate_timer_events += 1;
        }
        Ok(())
    }
}

fn committed_urgent_claim(
    snapshot: &RouteSnapshotV1,
) -> Option<&route_executor::EffectReferenceV1> {
    if !matches!(
        snapshot.secret_visibility,
        SecretVisibilityV1::Public { .. }
    ) {
        return None;
    }
    match &snapshot.upstream.claim {
        ActionStateV1::Committed(reference) => Some(reference),
        _ => None,
    }
}

fn validate_partial_custody_progress(
    contains_route_secret: bool,
    progress_evidence_digest: Digest32,
    exposure: Option<&PublicExposureV1>,
    now_unix_ms: u64,
) -> Result<(), RouteSupervisorErrorV1> {
    if progress_evidence_digest == ZERO_DIGEST {
        return Err(RouteSupervisorErrorV1::InvalidExternalizationReceipt);
    }
    if let Some(exposure) = exposure {
        if !contains_route_secret
            || exposure.source != ExposureSourceV1::Externalized
            || exposure.chain_id == ZERO_DIGEST
            || exposure.transaction_id == ZERO_DIGEST
            || exposure.evidence_digest == ZERO_DIGEST
            || exposure.observed_at_unix_ms == 0
            || exposure.observed_at_unix_ms > now_unix_ms
        {
            return Err(RouteSupervisorErrorV1::InvalidExternalizationReceipt);
        }
    }
    Ok(())
}

fn record_custody_dispatch_report(
    report: &mut RouteSupervisorTickReportV1,
    urgent: bool,
    disposition: CustodyDispatchDispositionV1,
) {
    match disposition {
        CustodyDispatchDispositionV1::AggregateExternalized if urgent => {
            report.urgent_externalized += 1;
        }
        CustodyDispatchDispositionV1::AggregateExternalized => {
            report.custody_externalized += 1;
        }
        CustodyDispatchDispositionV1::PartialProgress => {
            report.custody_partial_progress += 1;
        }
        CustodyDispatchDispositionV1::ProgressUnchanged => {
            report.custody_progress_unchanged += 1;
        }
        CustodyDispatchDispositionV1::Unknown => {
            report.custody_unknown += 1;
            if urgent {
                report.urgent_in_flight = true;
            }
        }
    }
}

fn observation_query_is_well_formed(query: ChainObservationQueryV1) -> bool {
    match query {
        ChainObservationQueryV1::Finality { transaction_id, .. }
        | ChainObservationQueryV1::Invalidation { transaction_id, .. } => {
            transaction_id != ZERO_DIGEST
        }
        ChainObservationQueryV1::SecretExposure {
            chain_id,
            transaction_id,
        } => chain_id != ZERO_DIGEST && transaction_id != ZERO_DIGEST,
    }
}

fn verified_observation_event(
    query: ChainObservationQueryV1,
    verified: VerifiedChainObservationV1,
    now_unix_ms: u64,
) -> Result<RouteEventV1, RouteSupervisorErrorV1> {
    match (query, verified) {
        (
            ChainObservationQueryV1::Finality {
                leg,
                action,
                transaction_id,
            },
            VerifiedChainObservationV1::Finality { evidence_digest },
        ) if evidence_digest != ZERO_DIGEST => Ok(RouteEventV1::ActionFinalized {
            leg,
            kind: action,
            transaction_id,
            evidence_digest,
        }),
        (
            ChainObservationQueryV1::Invalidation {
                leg,
                action,
                transaction_id,
            },
            VerifiedChainObservationV1::Invalidation {
                reorg_evidence_digest,
            },
        ) if reorg_evidence_digest != ZERO_DIGEST => Ok(RouteEventV1::ObservationInvalidated {
            leg,
            kind: action,
            transaction_id,
            reorg_evidence_digest,
        }),
        (
            ChainObservationQueryV1::SecretExposure {
                chain_id,
                transaction_id,
            },
            VerifiedChainObservationV1::SecretExposure {
                source,
                evidence_digest,
                observed_at_unix_ms,
            },
        ) if source != ExposureSourceV1::Externalized
            && evidence_digest != ZERO_DIGEST
            && observed_at_unix_ms != 0
            && observed_at_unix_ms <= now_unix_ms =>
        {
            Ok(RouteEventV1::SecretObserved(PublicExposureV1 {
                source,
                chain_id,
                transaction_id,
                evidence_digest,
                observed_at_unix_ms,
            }))
        }
        _ => Err(RouteSupervisorErrorV1::InvalidAuthorityResponse),
    }
}

fn timer_event_is_permitted(event: &RouteEventV1) -> bool {
    match event {
        // A timer may modify only internal scheduling/health or abort an
        // entirely unfunded route. Economic actions and chain facts remain
        // owned by their dedicated typed authorities.
        RouteEventV1::SetHealth { .. }
        | RouteEventV1::ScheduleTimer { .. }
        | RouteEventV1::AbortUnfunded { .. } => true,
        // A batch is claimed before any event is applied.  Letting one claimed
        // timer cancel another would otherwise leave the second stale item in
        // memory and able to fire.  Cancellation enters through the explicit
        // operational method.
        RouteEventV1::CancelTimer { .. } => false,
        RouteEventV1::FreezeTerms(_)
        | RouteEventV1::FreezeTermsV2(_)
        | RouteEventV1::ArmRefunds(_)
        | RouteEventV1::CommitAction(_)
        | RouteEventV1::ReauthorizeCommittedAction { .. }
        | RouteEventV1::ReauthorizePartiallyExternalizedCustody { .. }
        | RouteEventV1::CustodyProgressRecorded { .. }
        | RouteEventV1::ActionExternalized { .. }
        | RouteEventV1::ActionFinalized { .. }
        | RouteEventV1::ObservationInvalidated { .. }
        | RouteEventV1::SecretObserved(_) => false,
    }
}

fn stale_committed_actions(
    snapshot: &RouteSnapshotV1,
    current_fence: u64,
) -> Result<Vec<(LegIdV1, ActionKindV1, route_executor::EffectReferenceV1)>, RouteSupervisorErrorV1>
{
    let mut stale = Vec::new();
    for leg in [LegIdV1::Upstream, LegIdV1::Downstream] {
        for action in [
            ActionKindV1::Funding,
            ActionKindV1::Claim,
            ActionKindV1::Refund,
        ] {
            if let ActionStateV1::Committed(reference) = snapshot.leg(leg).action(action) {
                if reference.fencing_epoch > current_fence {
                    return Err(RouteSupervisorErrorV1::Store(
                        RouteStoreErrorV1::CorruptState,
                    ));
                }
                if reference.fencing_epoch < current_fence {
                    stale.push((leg, action, reference.clone()));
                }
            }
        }
    }
    Ok(stale)
}

fn dispatch_binding(dispatch: &EffectDispatchV1) -> (Digest32, Option<Digest32>) {
    match dispatch {
        EffectDispatchV1::RunnerPayload { payload_digest, .. } => (*payload_digest, None),
        EffectDispatchV1::ExternalCustody {
            custody_digest,
            transaction_id,
        } => (*custody_digest, Some(*transaction_id)),
    }
}

fn priority_rank(priority: EffectPriorityV1) -> u8 {
    match priority {
        EffectPriorityV1::Normal => 0,
        EffectPriorityV1::Recovery => 1,
        EffectPriorityV1::SecretPublicUrgent => 2,
    }
}

struct CapabilityAttemptBindingV1<'a> {
    route_id: RouteIdV1,
    effect_id: EffectIdV1,
    leg: LegIdV1,
    action: ActionKindV1,
    priority: EffectPriorityV1,
    contains_route_secret: bool,
    bindings: &'a FrozenBindingsV1,
    fence: u64,
    attempt: u64,
    semantic_digest: Digest32,
    dispatch_digest: Digest32,
    expires_at_unix_ms: u64,
    expected_transaction_id: Option<Digest32>,
    acknowledged_custody_progress: Option<&'a AcknowledgedCustodyProgressV1>,
    route_first_public_exposure: Option<&'a PublicExposureV1>,
}

fn capability_attempt_id(
    binding: CapabilityAttemptBindingV1<'_>,
) -> Result<Digest32, RouteSupervisorErrorV1> {
    let CapabilityAttemptBindingV1 {
        route_id,
        effect_id,
        leg,
        action,
        priority,
        contains_route_secret,
        bindings,
        fence,
        attempt,
        semantic_digest,
        dispatch_digest,
        expires_at_unix_ms,
        expected_transaction_id,
        acknowledged_custody_progress,
        route_first_public_exposure,
    } = binding;
    let leg_tag = [match leg {
        LegIdV1::Upstream => 0,
        LegIdV1::Downstream => 1,
    }];
    let action_tag = [match action {
        ActionKindV1::Funding => 0,
        ActionKindV1::Claim => 1,
        ActionKindV1::Refund => 2,
    }];
    let secret_tag = [u8::from(contains_route_secret)];
    let priority_tag = [priority_rank(priority)];
    let expected_tag = [u8::from(expected_transaction_id.is_some())];
    let expected = expected_transaction_id.unwrap_or(ZERO_DIGEST);
    let progress_tag = [u8::from(acknowledged_custody_progress.is_some())];
    let progress_digest = acknowledged_custody_progress
        .map(AcknowledgedCustodyProgressV1::progress_evidence_digest)
        .unwrap_or(ZERO_DIGEST);
    let progress_exposure =
        acknowledged_custody_progress.and_then(AcknowledgedCustodyProgressV1::exposure);
    let progress_exposure_bytes = encode_public_exposure_binding(progress_exposure);
    let route_exposure_bytes = encode_public_exposure_binding(route_first_public_exposure);
    domain_digest(
        CAPABILITY_ATTEMPT_DOMAIN,
        &[
            &route_id,
            &effect_id,
            &leg_tag,
            &action_tag,
            &priority_tag,
            &secret_tag,
            &bindings.terms_digest,
            &bindings.profile_bundle_digest,
            &bindings.deployment_bundle_digest,
            &fence.to_be_bytes(),
            &attempt.to_be_bytes(),
            &semantic_digest,
            &dispatch_digest,
            &expires_at_unix_ms.to_be_bytes(),
            &expected_tag,
            &expected,
            &progress_tag,
            &progress_digest,
            &progress_exposure_bytes,
            &route_exposure_bytes,
        ],
    )
}

fn encode_public_exposure_binding(exposure: Option<&PublicExposureV1>) -> [u8; 106] {
    let mut encoded = [0_u8; 106];
    let Some(exposure) = exposure else {
        return encoded;
    };
    encoded[0] = 1;
    encoded[1] = match exposure.source {
        ExposureSourceV1::Mempool => 0,
        ExposureSourceV1::Externalized => 1,
        ExposureSourceV1::Block => 2,
        ExposureSourceV1::PeerEvidence => 3,
    };
    encoded[2..34].copy_from_slice(&exposure.chain_id);
    encoded[34..66].copy_from_slice(&exposure.transaction_id);
    encoded[66..98].copy_from_slice(&exposure.evidence_digest);
    encoded[98..106].copy_from_slice(&exposure.observed_at_unix_ms.to_be_bytes());
    encoded
}

fn acknowledged_custody_progress_from_journal(
    route_id: RouteIdV1,
    current_effect_id: EffectIdV1,
    leg: LegIdV1,
    action: ActionKindV1,
    journal: &[RouteJournalEntryV1],
) -> Result<Option<AcknowledgedCustodyProgressV1>, RouteSupervisorErrorV1> {
    let corrupt = || RouteSupervisorErrorV1::Store(RouteStoreErrorV1::CorruptState);
    let mut lineage_effect_id = current_effect_id;
    let mut expected_progress_digest = None;

    for entry in journal.iter().rev() {
        match &entry.event {
            RouteEventV1::CustodyProgressRecorded {
                leg: event_leg,
                kind,
                effect_id,
                progress_evidence_digest,
                exposure,
            } if *event_leg == leg && *kind == action && *effect_id == lineage_effect_id => {
                if expected_progress_digest
                    .is_some_and(|expected| expected != *progress_evidence_digest)
                {
                    return Err(corrupt());
                }
                return Ok(Some(AcknowledgedCustodyProgressV1 {
                    progress_evidence_digest: *progress_evidence_digest,
                    exposure: exposure.clone(),
                }));
            }
            RouteEventV1::ReauthorizePartiallyExternalizedCustody {
                prior_effect_id,
                partial_externalization_evidence_digest,
                intent,
            } if intent.leg == leg && intent.kind == action => {
                let derived = derive_effect_id_v1(
                    route_id,
                    entry.event_id,
                    entry.fencing_epoch,
                    leg,
                    action,
                    intent.semantic_digest,
                );
                if derived == lineage_effect_id {
                    if !intent.contains_route_secret {
                        return Ok(Some(AcknowledgedCustodyProgressV1 {
                            progress_evidence_digest: *partial_externalization_evidence_digest,
                            exposure: None,
                        }));
                    }
                    if expected_progress_digest.is_some_and(|expected| {
                        expected != *partial_externalization_evidence_digest
                    }) {
                        return Err(corrupt());
                    }
                    expected_progress_digest = Some(*partial_externalization_evidence_digest);
                    lineage_effect_id = *prior_effect_id;
                }
            }
            RouteEventV1::ReauthorizeCommittedAction {
                prior_effect_id: _,
                intent,
                ..
            } if intent.leg == leg && intent.kind == action => {
                let derived = derive_effect_id_v1(
                    route_id,
                    entry.event_id,
                    entry.fencing_epoch,
                    leg,
                    action,
                    intent.semantic_digest,
                );
                if derived == lineage_effect_id {
                    if expected_progress_digest.is_some() {
                        return Err(corrupt());
                    }
                    return Ok(None);
                }
            }
            RouteEventV1::CommitAction(intent) if intent.leg == leg && intent.kind == action => {
                let derived = derive_effect_id_v1(
                    route_id,
                    entry.event_id,
                    entry.fencing_epoch,
                    leg,
                    action,
                    intent.semantic_digest,
                );
                if derived == lineage_effect_id {
                    if let Some(progress_evidence_digest) = expected_progress_digest {
                        return Ok(Some(AcknowledgedCustodyProgressV1 {
                            progress_evidence_digest,
                            exposure: None,
                        }));
                    }
                    return Ok(None);
                }
            }
            RouteEventV1::ActionExternalized {
                leg: event_leg,
                kind,
                effect_id,
                ..
            } if *event_leg == leg && *kind == action && *effect_id == lineage_effect_id => {
                return Err(corrupt());
            }
            _ => {}
        }
    }
    Err(corrupt())
}

fn externalized_event_id(
    route_id: RouteIdV1,
    effect_id: EffectIdV1,
) -> Result<EventIdV1, RouteSupervisorErrorV1> {
    domain_digest(EXTERNALIZED_EVENT_DOMAIN, &[&route_id, &effect_id])
}

fn custody_progress_event_id(
    route_id: RouteIdV1,
    effect_id: EffectIdV1,
    progress_evidence_digest: Digest32,
) -> Result<EventIdV1, RouteSupervisorErrorV1> {
    domain_digest(
        CUSTODY_PROGRESS_EVENT_DOMAIN,
        &[&route_id, &effect_id, &progress_evidence_digest],
    )
}

fn timer_event_id(
    route_id: RouteIdV1,
    timer_id: TimerIdV1,
    timer_hash: Digest32,
) -> Result<EventIdV1, RouteSupervisorErrorV1> {
    domain_digest(TIMER_EVENT_DOMAIN, &[&route_id, &timer_id, &timer_hash])
}

fn reauthorize_event_id(
    route_id: RouteIdV1,
    prior_effect_id: EffectIdV1,
    current_fence: u64,
) -> Result<EventIdV1, RouteSupervisorErrorV1> {
    domain_digest(
        REAUTHORIZE_EVENT_DOMAIN,
        &[&route_id, &prior_effect_id, &current_fence.to_be_bytes()],
    )
}

fn domain_digest(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, RouteSupervisorErrorV1> {
    let mut hasher =
        Blake2bVar::new(32).map_err(|_| RouteSupervisorErrorV1::InvalidConfiguration)?;
    hasher.update(domain);
    for part in parts {
        let length =
            u64::try_from(part.len()).map_err(|_| RouteSupervisorErrorV1::InvalidConfiguration)?;
        hasher.update(&length.to_be_bytes());
        hasher.update(part);
    }
    let mut digest = [0; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| RouteSupervisorErrorV1::InvalidConfiguration)?;
    if digest == ZERO_DIGEST {
        return Err(RouteSupervisorErrorV1::InvalidConfiguration);
    }
    Ok(digest)
}

#[cfg(test)]
mod capability_attempt_tests {
    use super::*;

    fn attempt_id(priority: EffectPriorityV1) -> Result<Digest32, RouteSupervisorErrorV1> {
        let bindings = FrozenBindingsV1 {
            terms_digest: [0x31; 32],
            profile_bundle_digest: [0x32; 32],
            deployment_bundle_digest: [0x33; 32],
        };
        capability_attempt_id(CapabilityAttemptBindingV1 {
            route_id: [0x11; 32],
            effect_id: [0x12; 32],
            leg: LegIdV1::Upstream,
            action: ActionKindV1::Claim,
            priority,
            contains_route_secret: true,
            bindings: &bindings,
            fence: 7,
            attempt: 3,
            semantic_digest: [0x41; 32],
            dispatch_digest: [0x42; 32],
            expires_at_unix_ms: 90_000,
            expected_transaction_id: Some([0x43; 32]),
            acknowledged_custody_progress: None,
            route_first_public_exposure: None,
        })
    }

    #[test]
    fn priority_is_bound_into_one_shot_attempt_identity() -> Result<(), RouteSupervisorErrorV1> {
        let normal = attempt_id(EffectPriorityV1::Normal)?;
        let recovery = attempt_id(EffectPriorityV1::Recovery)?;
        let urgent = attempt_id(EffectPriorityV1::SecretPublicUrgent)?;
        assert_ne!(normal, recovery);
        assert_ne!(normal, urgent);
        assert_ne!(recovery, urgent);
        Ok(())
    }
}
