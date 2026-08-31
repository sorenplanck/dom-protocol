//! Durable, effect-declarative orchestration for a composed DOM route.
//!
//! The crate deliberately contains no chain client and no signer.  A pure
//! reducer decides state transitions and emits effect intents; the durable
//! store commits the resulting snapshot, journal entry, outbox entries and
//! timers in one SQLite transaction before any worker can dispatch an effect.

#![forbid(unsafe_code)]

mod codec;
mod model;
mod reducer;
mod store;

pub use codec::{digest_bytes_v1, CanonicalCodecV1, CodecErrorV1, MAX_CANONICAL_BYTES_V1};
pub use model::{
    ActionIntentV1, ActionKindV1, ActionProgressV1, ActionStateV1, CoordinationPhaseV1, Digest32,
    EffectDispatchV1, EffectIdV1, EffectPriorityV1, EffectReferenceV1, EventIdV1, ExposureSourceV1,
    FrozenBindingsV1, FrozenRouteAdmissionCheckpointV2, FrozenRouteTimeFactsV2, HealthStateV1,
    LegIdV1, LegSnapshotV1, PublicExposureV1, RefundBindingsV1, RouteDecisionV1, RouteEffectV1,
    RouteEventV1, RouteIdV1, RouteInventoryReleaseCapabilityV1, RouteInventoryReleaseDispositionV1,
    RouteSecretRetirementCapabilityV1, RouteSnapshotV1, RouteTimerMutationV1, RouteTimerV1,
    SecretVisibilityV1, TimerIdV1, TimerKindV1, MAX_EFFECT_PAYLOAD_BYTES_V1,
};
pub use reducer::{derive_effect_id_v1, reduce_route_v1, ReduceErrorV1};
pub use store::{
    ClaimedExternalCustodyEffectV1, ClaimedRouteEffectV1, ClaimedRouteTimerV1, ClaimedRouteWorkV1,
    CommitOutcomeV1, CompletionOutcomeV1, DurableRouteStoreV1, LeaseAcquireOutcomeV1,
    RouteJournalEntryV1, RouteLeaseV1, RouteStoreErrorV1,
};
