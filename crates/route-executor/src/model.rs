//! Public route model.  It contains only public identifiers, commitments and
//! bounded effect bytes; private keys, shares, nonces and the route scalar are
//! intentionally unrepresentable.

use crate::codec::{CanonicalCodecV1, CodecErrorV1};

/// A fixed-size public digest or identifier.
pub type Digest32 = [u8; 32];
/// Stable route identifier.
pub type RouteIdV1 = Digest32;
/// Stable event idempotency key.
pub type EventIdV1 = Digest32;
/// Deterministic outbox effect identifier.
pub type EffectIdV1 = Digest32;
/// Deterministic timer identifier.
pub type TimerIdV1 = Digest32;

/// Maximum exact runner payload retained by the route store.
pub const MAX_EFFECT_PAYLOAD_BYTES_V1: usize = 65_536;

/// High-level route coordination phase.  Leg, secret and health progress are
/// separate dimensions and must not be inferred from this enum alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinationPhaseV1 {
    /// Terms have not yet been frozen.
    Negotiating,
    /// Terms, profiles and deployments are frozen.
    TermsFrozen,
    /// Both refunds are durably armed.
    RefundsArmed,
    /// At least one funding action is in progress.
    Funding,
    /// Claim or refund settlement is in progress.
    Settling,
    /// Unsafe progress is stopped while exits remain available.
    Recovery,
    /// Both legs have terminal economic outcomes, or an unfunded route aborted.
    Terminal,
}

/// Route health is independent of economic progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthStateV1 {
    /// New work and recovery work may progress.
    Running,
    /// Observation is impaired; new funding is prohibited.
    Degraded,
    /// Only reconciliation, claim and refund work may progress.
    RecoveryOnly,
    /// An operator decision is needed, but already-authorized exits stay live.
    ManualIntervention,
}

impl HealthStateV1 {
    /// Whether this state disables unsafe/new economic progress.
    pub fn restricts_to_recovery(self) -> bool {
        self != Self::Running
    }
}

/// Upstream or downstream leg of a composed route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegIdV1 {
    /// The leg funded first and claimed after the route secret is public.
    Upstream,
    /// The leg funded second and whose claim normally exposes the secret.
    Downstream,
}

/// External economic action associated with one leg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionKindV1 {
    /// Transfer funds into the conditional lock.
    Funding,
    /// Spend through the success/claim path.
    Claim,
    /// Spend through the timeout/refund path.
    Refund,
}

/// Progress of one action, useful for scheduling and invariant checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionProgressV1 {
    /// No effect was committed.
    NotPrepared,
    /// The effect was committed atomically to the outbox.
    Committed,
    /// Bytes or an externally-custodied action left the authority.
    Externalized,
    /// A canonical finality policy accepted the action.
    Final,
}

/// Commitment retained in a snapshot for an action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectReferenceV1 {
    /// Deterministic outbox identity.
    pub effect_id: EffectIdV1,
    /// Route fencing generation that created the effect.
    pub fencing_epoch: u64,
    /// Commitment to the action's full semantics.
    pub semantic_digest: Digest32,
    /// Whether the action contains or necessarily reveals the route scalar.
    pub contains_route_secret: bool,
    /// Public transaction identity known before dispatch, for external custody.
    pub expected_transaction_id: Option<Digest32>,
}

/// Durable progress for one funding, claim or refund action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionStateV1 {
    /// No action has been authorized.
    NotPrepared,
    /// The exact action or custody commitment is in the durable outbox.
    Committed(EffectReferenceV1),
    /// The action was handed to an external system or broadcast.
    Externalized {
        /// Immutable effect commitment.
        effect: EffectReferenceV1,
        /// Public chain transaction identifier.
        transaction_id: Digest32,
    },
    /// The action reached the frozen finality policy.
    Final {
        /// Immutable effect commitment.
        effect: EffectReferenceV1,
        /// Public chain transaction identifier.
        transaction_id: Digest32,
        /// Commitment to the finality evidence, not free-form interpretation.
        evidence_digest: Digest32,
    },
    /// A previously final observation was invalidated by a reorg.  Keeping
    /// both evidence commitments distinguishes a valid recovery snapshot from
    /// an impossible route that funded downstream without upstream ever being
    /// final.
    FinalityInvalidated {
        /// Immutable effect commitment.
        effect: EffectReferenceV1,
        /// Public chain transaction identifier.
        transaction_id: Digest32,
        /// Evidence that had previously satisfied finality.
        prior_evidence_digest: Digest32,
        /// Evidence that invalidated the prior canonical observation.
        reorg_evidence_digest: Digest32,
    },
}

impl ActionStateV1 {
    /// Return the compact progress tag.
    pub fn progress(&self) -> ActionProgressV1 {
        match self {
            Self::NotPrepared => ActionProgressV1::NotPrepared,
            Self::Committed(_) => ActionProgressV1::Committed,
            Self::Externalized { .. } | Self::FinalityInvalidated { .. } => {
                ActionProgressV1::Externalized
            }
            Self::Final { .. } => ActionProgressV1::Final,
        }
    }

    /// Return the effect reference once an action exists.
    pub fn effect(&self) -> Option<&EffectReferenceV1> {
        match self {
            Self::NotPrepared => None,
            Self::Committed(effect)
            | Self::Externalized { effect, .. }
            | Self::Final { effect, .. }
            | Self::FinalityInvalidated { effect, .. } => Some(effect),
        }
    }

    /// Return the chain transaction id once the action was externalized.
    pub fn transaction_id(&self) -> Option<Digest32> {
        match self {
            Self::Externalized { transaction_id, .. }
            | Self::Final { transaction_id, .. }
            | Self::FinalityInvalidated { transaction_id, .. } => Some(*transaction_id),
            Self::NotPrepared | Self::Committed(_) => None,
        }
    }
}

/// Independent action state for one leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegSnapshotV1 {
    /// Funding path state.
    pub funding: ActionStateV1,
    /// Claim path state.
    pub claim: ActionStateV1,
    /// Refund path state.
    pub refund: ActionStateV1,
}

impl LegSnapshotV1 {
    /// Construct an untouched leg.
    pub fn idle() -> Self {
        Self {
            funding: ActionStateV1::NotPrepared,
            claim: ActionStateV1::NotPrepared,
            refund: ActionStateV1::NotPrepared,
        }
    }

    /// Whether the leg has a reconciled final outcome.
    pub fn is_terminal(&self) -> bool {
        self.claim.progress() == ActionProgressV1::Final
            || self.refund.progress() == ActionProgressV1::Final
    }

    /// Whether committed/broadcast funding still requires claim or refund.
    pub fn has_open_funds(&self) -> bool {
        self.funding.progress() != ActionProgressV1::NotPrepared && !self.is_terminal()
    }

    /// Select an action state by kind.
    pub fn action(&self, kind: ActionKindV1) -> &ActionStateV1 {
        match kind {
            ActionKindV1::Funding => &self.funding,
            ActionKindV1::Claim => &self.claim,
            ActionKindV1::Refund => &self.refund,
        }
    }

    pub(crate) fn action_mut(&mut self, kind: ActionKindV1) -> &mut ActionStateV1 {
        match kind {
            ActionKindV1::Funding => &mut self.funding,
            ActionKindV1::Claim => &mut self.claim,
            ActionKindV1::Refund => &mut self.refund,
        }
    }
}

/// Source of the first irreversible public exposure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExposureSourceV1 {
    /// Seen in a chain mempool.
    Mempool,
    /// Handed to an external custody/broadcast authority.
    Externalized,
    /// Seen in a block.
    Block,
    /// Authenticated counterparty evidence.
    PeerEvidence,
}

/// Public-only description of the first exposure.  It intentionally contains
/// no scalar or secret-bearing bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicExposureV1 {
    /// How the exposure was first learned.
    pub source: ExposureSourceV1,
    /// Frozen chain/profile identity.
    pub chain_id: Digest32,
    /// Public transaction identity.
    pub transaction_id: Digest32,
    /// Commitment to the exact evidence used.
    pub evidence_digest: Digest32,
    /// Caller-supplied observation time.
    pub observed_at_unix_ms: u64,
}

/// Irreversible visibility dimension for the route secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretVisibilityV1 {
    /// No evidence shows that the route scalar became public.
    Private,
    /// Public knowledge is irreversible, even after a reorg.
    Public {
        /// First known exposure; later evidence never overwrites it.
        first_exposure: PublicExposureV1,
    },
}

/// Digests frozen before refund construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenBindingsV1 {
    /// Canonical route terms digest.
    pub terms_digest: Digest32,
    /// Canonical chain-profile bundle digest.
    pub profile_bundle_digest: Digest32,
    /// Canonical deployment bundle digest.
    pub deployment_bundle_digest: Digest32,
}

/// Exact public time facts consumed by the original V2 route admission.
///
/// These fields are a historical checkpoint only. They do not represent a
/// current funding capability and contain no process-opening or store-revision
/// value that could be replayed as one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrozenRouteTimeFactsV2 {
    /// Ordered upstream/downstream settlement-terms scope.
    pub route_scope_digest: Digest32,
    /// Threshold-authenticated static time-policy digest.
    pub policy_digest: Digest32,
    /// Threshold-authenticated evidence digest used at admission.
    pub evidence_digest: Digest32,
    /// Exact conservative ladder-proof digest consumed by the composer.
    pub proof_digest: Digest32,
    /// Monotonic sequence of the admitted evidence row.
    pub evidence_sequence: u64,
    /// Trusted second at which the admitted ladder proof was issued.
    pub issued_at_seconds: u64,
    /// Exclusive validity boundary of the admitted ladder proof.
    pub valid_until_seconds: u64,
    /// Trusted second at which admission consumed the proof.
    pub validated_at_seconds: u64,
}

/// Canonical, secret-free checkpoint journaled with a production V2 freeze.
///
/// `route-executor` treats every field as fixed bytes or integers and has no
/// dependency on the registry, time authority, participant binding, composer
/// or admission crates. The composition root converts these facts back into
/// their typed authorities and reauthenticates them during recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenRouteAdmissionCheckpointV2 {
    /// DOM interoperability network identity.
    pub network_id: Digest32,
    /// Route whose journal owns this checkpoint.
    pub route_id: RouteIdV1,
    /// Exact reducer bindings produced by authenticated admission.
    pub bindings: FrozenBindingsV1,
    /// Original authenticated `ComposedBindingV2` digest.
    pub composition_v2_digest: Digest32,
    /// Exact authenticated registry epoch used by admission.
    pub registry_epoch: u64,
    /// Threshold-authenticated registry manifest digest.
    pub registry_manifest_digest: Digest32,
    /// Canonical upstream settlement terms digest.
    pub upstream_terms_digest: Digest32,
    /// Canonical downstream settlement terms digest.
    pub downstream_terms_digest: Digest32,
    /// Upstream Relay/participant roster snapshot.
    pub upstream_roster_snapshot: Digest32,
    /// Downstream Relay/participant roster snapshot.
    pub downstream_roster_snapshot: Digest32,
    /// Canonical participant-account proof bundle digest.
    pub participant_bindings_digest: Digest32,
    /// Canonical two-settlement Relay roster bundle digest.
    pub relay_binding_digest: Digest32,
    /// Registry BIP340 authority-set digest.
    pub registry_authority_set_digest: Digest32,
    /// Independent time-policy BIP340 authority-set digest.
    pub time_policy_authority_set_digest: Digest32,
    /// Independent time-evidence BIP340 authority-set digest.
    pub time_evidence_authority_set_digest: Digest32,
    /// Full historical time admission facts.
    pub time: FrozenRouteTimeFactsV2,
}

/// Commitments proving that both exits were armed before funding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefundBindingsV1 {
    /// Upstream refund commitment.
    pub upstream_refund_digest: Digest32,
    /// Downstream refund commitment.
    pub downstream_refund_digest: Digest32,
}

/// Full multidimensional, replayable route snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSnapshotV1 {
    /// Route identity.
    pub route_id: RouteIdV1,
    /// CAS revision, incremented exactly once per accepted event.
    pub revision: u64,
    /// Derived coordination phase.
    pub coordination: CoordinationPhaseV1,
    /// Independent upstream state.
    pub upstream: LegSnapshotV1,
    /// Independent downstream state.
    pub downstream: LegSnapshotV1,
    /// Irreversible secret visibility.
    pub secret_visibility: SecretVisibilityV1,
    /// Operational health/recovery lane.
    pub health: HealthStateV1,
    /// Frozen route/profile/deployment binding.
    pub bindings: Option<FrozenBindingsV1>,
    /// Both refund commitments.
    pub refunds: Option<RefundBindingsV1>,
    /// Whether an entirely unfunded route was aborted.
    pub aborted_unfunded: bool,
    /// Sequence of the last accepted journal event.
    pub last_event_sequence: u64,
    /// Digest of the last canonical event bytes.
    pub last_event_digest: Digest32,
}

/// Opaque proof that the authenticated route journal no longer needs its
/// public-scalar recovery record.
///
/// This capability has no public constructor, codec, `Clone`, or `Copy`.
/// [`crate::DurableRouteStoreV1`] mints it only after replaying the complete
/// journal, authenticating the production V2 admission checkpoint, and
/// proving both funded legs terminal with no open funds. Its getters expose
/// only public commitments needed by the independently locked secret vault.
pub struct RouteSecretRetirementCapabilityV1 {
    route_id: RouteIdV1,
    composition_v2_digest: Digest32,
    first_exposure: PublicExposureV1,
    revision: u64,
    snapshot_digest: Digest32,
    last_event_digest: Digest32,
    journal_head_digest: Digest32,
    admission_checkpoint_digest: Digest32,
}

pub(crate) struct AuthenticatedRouteSecretRetirementFactsV1 {
    pub route_id: RouteIdV1,
    pub composition_v2_digest: Digest32,
    pub first_exposure: PublicExposureV1,
    pub revision: u64,
    pub snapshot_digest: Digest32,
    pub last_event_digest: Digest32,
    pub journal_head_digest: Digest32,
    pub admission_checkpoint_digest: Digest32,
}

impl RouteSecretRetirementCapabilityV1 {
    pub(crate) fn from_authenticated_replay(
        facts: AuthenticatedRouteSecretRetirementFactsV1,
    ) -> Result<Self, CodecErrorV1> {
        validate_exposure(&facts.first_exposure)?;
        validate_nonzero_many(&[
            facts.route_id,
            facts.composition_v2_digest,
            facts.snapshot_digest,
            facts.last_event_digest,
            facts.journal_head_digest,
            facts.admission_checkpoint_digest,
        ])?;
        if facts.revision == 0 || facts.first_exposure.observed_at_unix_ms == 0 {
            return Err(CodecErrorV1::InvalidValue);
        }
        Ok(Self {
            route_id: facts.route_id,
            composition_v2_digest: facts.composition_v2_digest,
            first_exposure: facts.first_exposure,
            revision: facts.revision,
            snapshot_digest: facts.snapshot_digest,
            last_event_digest: facts.last_event_digest,
            journal_head_digest: facts.journal_head_digest,
            admission_checkpoint_digest: facts.admission_checkpoint_digest,
        })
    }

    /// Exact route proven terminal by journal replay.
    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }

    /// Authenticated `ComposedBindingV2` digest from the admission checkpoint.
    pub const fn composition_v2_digest(&self) -> Digest32 {
        self.composition_v2_digest
    }

    /// Immutable first public exposure retained by the route reducer.
    pub const fn first_exposure(&self) -> &PublicExposureV1 {
        &self.first_exposure
    }

    /// Final replayed route revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Digest of the final canonical snapshot bytes.
    pub const fn snapshot_digest(&self) -> Digest32 {
        self.snapshot_digest
    }

    /// Digest of the final canonical event bytes.
    pub const fn last_event_digest(&self) -> Digest32 {
        self.last_event_digest
    }

    /// Authenticated head of the complete journal hash chain.
    pub const fn journal_head_digest(&self) -> Digest32 {
        self.journal_head_digest
    }

    /// Digest of the exact V2 admission checkpoint found during replay.
    pub const fn admission_checkpoint_digest(&self) -> Digest32 {
        self.admission_checkpoint_digest
    }
}

impl core::fmt::Debug for RouteSecretRetirementCapabilityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RouteSecretRetirementCapabilityV1([authenticated commitments])")
    }
}

/// Authenticated terminal class that permits releasing route-scoped solver
/// inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteInventoryReleaseDispositionV1 {
    /// Both legs reached a reconciled claim or refund finality outcome.
    BothLegsTerminal,
    /// The route was explicitly aborted before either funding action began.
    AbortedUnfunded,
}

/// Opaque proof that replay of one production V2 route authorizes inventory
/// release.
///
/// The capability has no public constructor, codec, `Clone`, or `Copy`.
/// [`crate::DurableRouteStoreV1`] mints it only from the complete authenticated
/// journal after proving there are no open funds. Unlike secret retirement,
/// it deliberately supports both a two-leg terminal settlement and an
/// explicit unfunded abort.
pub struct RouteInventoryReleaseCapabilityV1 {
    route_id: RouteIdV1,
    composition_v2_digest: Digest32,
    disposition: RouteInventoryReleaseDispositionV1,
    revision: u64,
    snapshot_digest: Digest32,
    last_event_digest: Digest32,
    journal_head_digest: Digest32,
    admission_checkpoint_digest: Digest32,
    release_evidence_digest: Digest32,
}

pub(crate) struct AuthenticatedRouteInventoryReleaseFactsV1 {
    pub route_id: RouteIdV1,
    pub composition_v2_digest: Digest32,
    pub disposition: RouteInventoryReleaseDispositionV1,
    pub revision: u64,
    pub snapshot_digest: Digest32,
    pub last_event_digest: Digest32,
    pub journal_head_digest: Digest32,
    pub admission_checkpoint_digest: Digest32,
    pub release_evidence_digest: Digest32,
}

impl RouteInventoryReleaseCapabilityV1 {
    pub(crate) fn from_authenticated_replay(
        facts: AuthenticatedRouteInventoryReleaseFactsV1,
    ) -> Result<Self, CodecErrorV1> {
        validate_nonzero_many(&[
            facts.route_id,
            facts.composition_v2_digest,
            facts.snapshot_digest,
            facts.last_event_digest,
            facts.journal_head_digest,
            facts.admission_checkpoint_digest,
            facts.release_evidence_digest,
        ])?;
        if facts.revision == 0 {
            return Err(CodecErrorV1::InvalidValue);
        }
        Ok(Self {
            route_id: facts.route_id,
            composition_v2_digest: facts.composition_v2_digest,
            disposition: facts.disposition,
            revision: facts.revision,
            snapshot_digest: facts.snapshot_digest,
            last_event_digest: facts.last_event_digest,
            journal_head_digest: facts.journal_head_digest,
            admission_checkpoint_digest: facts.admission_checkpoint_digest,
            release_evidence_digest: facts.release_evidence_digest,
        })
    }

    /// Exact route whose complete journal was replayed.
    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }

    /// Authenticated `ComposedBindingV2` digest from the admission checkpoint.
    pub const fn composition_v2_digest(&self) -> Digest32 {
        self.composition_v2_digest
    }

    /// Exact terminal class proven by replay.
    pub const fn disposition(&self) -> RouteInventoryReleaseDispositionV1 {
        self.disposition
    }

    /// Final replayed route revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Digest of the final canonical snapshot bytes.
    pub const fn snapshot_digest(&self) -> Digest32 {
        self.snapshot_digest
    }

    /// Digest of the final canonical event bytes.
    pub const fn last_event_digest(&self) -> Digest32 {
        self.last_event_digest
    }

    /// Authenticated head of the complete journal hash chain.
    pub const fn journal_head_digest(&self) -> Digest32 {
        self.journal_head_digest
    }

    /// Digest of the exact V2 admission checkpoint found during replay.
    pub const fn admission_checkpoint_digest(&self) -> Digest32 {
        self.admission_checkpoint_digest
    }

    /// Domain-separated evidence consumed by the inventory authority.
    pub const fn release_evidence_digest(&self) -> Digest32 {
        self.release_evidence_digest
    }
}

impl RouteSnapshotV1 {
    /// Construct the only permitted initial route snapshot.
    pub fn new(route_id: RouteIdV1) -> Result<Self, CodecErrorV1> {
        if is_zero(&route_id) {
            return Err(CodecErrorV1::InvalidValue);
        }
        Ok(Self {
            route_id,
            revision: 0,
            coordination: CoordinationPhaseV1::Negotiating,
            upstream: LegSnapshotV1::idle(),
            downstream: LegSnapshotV1::idle(),
            secret_visibility: SecretVisibilityV1::Private,
            health: HealthStateV1::Running,
            bindings: None,
            refunds: None,
            aborted_unfunded: false,
            last_event_sequence: 0,
            last_event_digest: [0; 32],
        })
    }

    /// Whether either leg still carries committed economic authority/funds.
    pub fn has_open_funds(&self) -> bool {
        self.upstream.has_open_funds() || self.downstream.has_open_funds()
    }

    /// Whether public secret knowledge requires urgent upstream recovery.
    pub fn secret_public_but_upstream_unclaimed(&self) -> bool {
        matches!(self.secret_visibility, SecretVisibilityV1::Public { .. })
            && self.upstream.claim.progress() != ActionProgressV1::Final
            && self.upstream.has_open_funds()
    }

    /// Return one leg.
    pub fn leg(&self, leg: LegIdV1) -> &LegSnapshotV1 {
        match leg {
            LegIdV1::Upstream => &self.upstream,
            LegIdV1::Downstream => &self.downstream,
        }
    }

    pub(crate) fn leg_mut(&mut self, leg: LegIdV1) -> &mut LegSnapshotV1 {
        match leg {
            LegIdV1::Upstream => &mut self.upstream,
            LegIdV1::Downstream => &mut self.downstream,
        }
    }

    pub(crate) fn recompute_coordination(&mut self) {
        self.coordination = if self.aborted_unfunded
            || (self.upstream.is_terminal() && self.downstream.is_terminal())
        {
            CoordinationPhaseV1::Terminal
        } else if self.health.restricts_to_recovery() && self.has_open_funds() {
            CoordinationPhaseV1::Recovery
        } else if self.upstream.claim.progress() != ActionProgressV1::NotPrepared
            || self.downstream.claim.progress() != ActionProgressV1::NotPrepared
            || self.upstream.refund.progress() != ActionProgressV1::NotPrepared
            || self.downstream.refund.progress() != ActionProgressV1::NotPrepared
            || matches!(self.secret_visibility, SecretVisibilityV1::Public { .. })
        {
            CoordinationPhaseV1::Settling
        } else if self.upstream.funding.progress() != ActionProgressV1::NotPrepared
            || self.downstream.funding.progress() != ActionProgressV1::NotPrepared
        {
            CoordinationPhaseV1::Funding
        } else if self.refunds.is_some() {
            CoordinationPhaseV1::RefundsArmed
        } else if self.bindings.is_some() {
            CoordinationPhaseV1::TermsFrozen
        } else {
            CoordinationPhaseV1::Negotiating
        };
    }

    pub(crate) fn validate(&self) -> Result<(), CodecErrorV1> {
        if is_zero(&self.route_id) {
            return Err(CodecErrorV1::InvalidValue);
        }
        if self.revision != self.last_event_sequence {
            return Err(CodecErrorV1::InvalidValue);
        }
        if self.revision == 0 && !is_zero(&self.last_event_digest) {
            return Err(CodecErrorV1::InvalidValue);
        }
        if self.refunds.is_some() && self.bindings.is_none() {
            return Err(CodecErrorV1::InvalidValue);
        }
        let actions = [
            &self.upstream.funding,
            &self.upstream.claim,
            &self.upstream.refund,
            &self.downstream.funding,
            &self.downstream.claim,
            &self.downstream.refund,
        ];
        let any_action = actions
            .iter()
            .any(|state| state.progress() != ActionProgressV1::NotPrepared);
        if any_action && self.refunds.is_none() {
            return Err(CodecErrorV1::InvalidValue);
        }
        if self.aborted_unfunded
            && (self.has_open_funds()
                || !matches!(self.secret_visibility, SecretVisibilityV1::Private))
        {
            return Err(CodecErrorV1::InvalidValue);
        }
        validate_leg(&self.upstream)?;
        validate_leg(&self.downstream)?;
        validate_action_purpose(&self.upstream.funding, ActionKindV1::Funding)?;
        validate_action_purpose(&self.upstream.claim, ActionKindV1::Claim)?;
        validate_action_purpose(&self.upstream.refund, ActionKindV1::Refund)?;
        validate_action_purpose(&self.downstream.funding, ActionKindV1::Funding)?;
        validate_action_purpose(&self.downstream.claim, ActionKindV1::Claim)?;
        validate_action_purpose(&self.downstream.refund, ActionKindV1::Refund)?;
        let downstream_started =
            self.downstream.funding.progress() != ActionProgressV1::NotPrepared;
        let upstream_was_final = matches!(
            self.upstream.funding,
            ActionStateV1::Final { .. } | ActionStateV1::FinalityInvalidated { .. }
        );
        if downstream_started && !upstream_was_final {
            return Err(CodecErrorV1::InvalidValue);
        }
        if actions
            .iter()
            .any(|state| matches!(state, ActionStateV1::FinalityInvalidated { .. }))
            && !self.health.restricts_to_recovery()
        {
            return Err(CodecErrorV1::InvalidValue);
        }
        for leg in [&self.upstream, &self.downstream] {
            if leg.refund.progress() != ActionProgressV1::NotPrepared
                && !matches!(
                    leg.funding.progress(),
                    ActionProgressV1::Externalized | ActionProgressV1::Final
                )
            {
                return Err(CodecErrorV1::InvalidValue);
            }
            if leg.claim.progress() != ActionProgressV1::NotPrepared
                && !matches!(
                    leg.funding,
                    ActionStateV1::Final { .. } | ActionStateV1::FinalityInvalidated { .. }
                )
            {
                return Err(CodecErrorV1::InvalidValue);
            }
        }
        if self.upstream.claim.progress() != ActionProgressV1::NotPrepared
            && !matches!(self.secret_visibility, SecretVisibilityV1::Public { .. })
        {
            return Err(CodecErrorV1::InvalidValue);
        }
        let externalized_secret_action =
            [&self.upstream.claim, &self.downstream.claim]
                .iter()
                .any(|state| {
                    matches!(
                        state.progress(),
                        ActionProgressV1::Externalized | ActionProgressV1::Final
                    )
                });
        if externalized_secret_action
            && !matches!(self.secret_visibility, SecretVisibilityV1::Public { .. })
        {
            return Err(CodecErrorV1::InvalidValue);
        }
        validate_secret(&self.secret_visibility)?;
        if let Some(bindings) = &self.bindings {
            validate_nonzero_many(&[
                bindings.terms_digest,
                bindings.profile_bundle_digest,
                bindings.deployment_bundle_digest,
            ])?;
        }
        if let Some(refunds) = &self.refunds {
            validate_nonzero_many(&[
                refunds.upstream_refund_digest,
                refunds.downstream_refund_digest,
            ])?;
        }
        let mut expected = self.clone();
        expected.recompute_coordination();
        if expected.coordination != self.coordination {
            return Err(CodecErrorV1::InvalidValue);
        }
        Ok(())
    }
}

/// Exact dispatch material or an external-custody commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectDispatchV1 {
    /// Exact bytes safe for the generic route outbox to retain and resend.
    RunnerPayload {
        /// Exact immutable bytes.
        payload: Vec<u8>,
        /// Digest checked on every decode and completion.
        payload_digest: Digest32,
    },
    /// Secret-bearing or externally-owned action.  No bytes are retained.
    ExternalCustody {
        /// Commitment to the exact externally retained descriptor/bytes.
        custody_digest: Digest32,
        /// Public transaction identity known by the external authority.
        transaction_id: Digest32,
    },
}

/// Action requested by a reducer event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionIntentV1 {
    /// Target route leg.
    pub leg: LegIdV1,
    /// Economic action.
    pub kind: ActionKindV1,
    /// Commitment to semantic fields that retries must preserve.
    pub semantic_digest: Digest32,
    /// Whether the action contains or reveals the route scalar.
    pub contains_route_secret: bool,
    /// Dispatch boundary.
    pub dispatch: EffectDispatchV1,
}

/// Timer class persisted with the transition that requested it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerKindV1 {
    /// Economic deadline/recovery wakeup.
    Deadline,
    /// Retry wakeup for a committed effect.
    Retry,
    /// Observer reconciliation wakeup.
    Reconcile,
}

/// Input event accepted by the pure reducer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteEventV1 {
    /// Freeze all terms and operational profile bindings.
    FreezeTerms(FrozenBindingsV1),
    /// Freeze a production V2 admission and its exact authenticated public
    /// checkpoint in the same journal event.
    FreezeTermsV2(Box<FrozenRouteAdmissionCheckpointV2>),
    /// Record both durable refund commitments.
    ArmRefunds(RefundBindingsV1),
    /// Atomically authorize an action and create its outbox row.
    CommitAction(ActionIntentV1),
    /// Reissue an unexternalized committed action under a newer fencing
    /// generation after authority-specific reconciliation proved that the old
    /// generation did not submit it.  The store atomically supersedes the old
    /// outbox row and verifies byte-for-byte dispatch equivalence.
    ReauthorizeCommittedAction {
        /// Effect stranded under the previous fencing generation.
        prior_effect_id: EffectIdV1,
        /// Commitment to non-externalization reconciliation evidence.
        non_externalization_evidence_digest: Digest32,
        /// Exact same semantic action and dispatch material.
        intent: ActionIntentV1,
    },
    /// Reissue an externally custodied action after its authority proves that
    /// only a non-secret prefix was externalized under the previous fencing
    /// generation. The aggregate action remains committed until every
    /// required child has left custody.
    ReauthorizePartiallyExternalizedCustody {
        /// Effect stranded under the previous fencing generation.
        prior_effect_id: EffectIdV1,
        /// Commitment to the authenticated partial-progress proof.
        partial_externalization_evidence_digest: Digest32,
        /// Exact same semantic action and external-custody descriptor.
        intent: ActionIntentV1,
    },
    /// Record durable progress made by one externally-custodied aggregate
    /// action without claiming that every required child was externalized.
    /// The action and its outbox row remain committed. When a child made the
    /// route scalar public, `exposure` records that irreversible fact now.
    CustodyProgressRecorded {
        /// Leg whose aggregate custody action made progress.
        leg: LegIdV1,
        /// Aggregate action kind.
        kind: ActionKindV1,
        /// Exact committed aggregate effect.
        effect_id: EffectIdV1,
        /// Commitment to the coordinator's durable child-prefix evidence.
        progress_evidence_digest: Digest32,
        /// First or additional public exposure produced by this child prefix.
        exposure: Option<PublicExposureV1>,
    },
    /// Record that a previously committed action left local custody.
    ActionExternalized {
        /// Leg whose action left custody.
        leg: LegIdV1,
        /// Action kind.
        kind: ActionKindV1,
        /// Exact committed effect id.
        effect_id: EffectIdV1,
        /// Public chain transaction identity.
        transaction_id: Digest32,
        /// Required when this is the first secret-bearing externalization.
        exposure: Option<PublicExposureV1>,
    },
    /// Record finality under the frozen chain profile.
    ActionFinalized {
        /// Leg whose action finalized.
        leg: LegIdV1,
        /// Action kind.
        kind: ActionKindV1,
        /// Exact public transaction identity.
        transaction_id: Digest32,
        /// Commitment to the accepted evidence.
        evidence_digest: Digest32,
    },
    /// Invalidate finality after a reorg; public secret knowledge is unchanged.
    ObservationInvalidated {
        /// Affected leg.
        leg: LegIdV1,
        /// Affected action.
        kind: ActionKindV1,
        /// Transaction whose finality was invalidated.
        transaction_id: Digest32,
        /// Commitment to reorg evidence.
        reorg_evidence_digest: Digest32,
    },
    /// Record an independently observed public exposure.
    SecretObserved(PublicExposureV1),
    /// Change operational health without discarding exit authority.
    SetHealth {
        /// Requested health state.
        target: HealthStateV1,
        /// Public reason commitment.
        reason_digest: Digest32,
    },
    /// Atomically create a durable timer.
    ScheduleTimer {
        /// Timer class.
        kind: TimerKindV1,
        /// Absolute caller-supplied wakeup time.
        deadline_unix_ms: u64,
        /// Commitment to the recovery/retry context.
        context_digest: Digest32,
    },
    /// Atomically cancel a known active timer.
    CancelTimer {
        /// Deterministic timer id.
        timer_id: TimerIdV1,
    },
    /// Terminate only when no funding authority/funds are open.
    AbortUnfunded {
        /// Public reason commitment.
        reason_digest: Digest32,
    },
}

/// Outbox priority.  Secret-public upstream claim outranks all normal work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectPriorityV1 {
    /// Ordinary route work.
    Normal,
    /// Claim/refund work required to recover funds.
    Recovery,
    /// Public secret with upstream not yet claimed.
    SecretPublicUrgent,
}

/// Exact declarative effect produced by a committed event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEffectV1 {
    /// Route identity.
    pub route_id: RouteIdV1,
    /// Deterministic idempotency identity.
    pub effect_id: EffectIdV1,
    /// Fencing generation that authorized it.
    pub fencing_epoch: u64,
    /// Target leg.
    pub leg: LegIdV1,
    /// Economic action.
    pub kind: ActionKindV1,
    /// Dispatch priority.
    pub priority: EffectPriorityV1,
    /// Semantic retry identity.
    pub semantic_digest: Digest32,
    /// Whether the externally held bytes contain/reveal the route scalar.
    pub contains_route_secret: bool,
    /// Exact safe bytes or external custody commitment.
    pub dispatch: EffectDispatchV1,
}

/// One durable timer generated by an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteTimerV1 {
    /// Route identity.
    pub route_id: RouteIdV1,
    /// Deterministic timer identity.
    pub timer_id: TimerIdV1,
    /// Fencing generation that scheduled it.
    pub fencing_epoch: u64,
    /// Timer class.
    pub kind: TimerKindV1,
    /// Absolute wakeup time.
    pub deadline_unix_ms: u64,
    /// Public context commitment.
    pub context_digest: Digest32,
}

/// Atomic timer mutation accompanying a route transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteTimerMutationV1 {
    /// Insert one active timer.
    Schedule(RouteTimerV1),
    /// Cancel one existing active timer.
    Cancel {
        /// Exact timer id.
        timer_id: TimerIdV1,
    },
}

/// Pure reducer output, persisted as one unit by the durable store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteDecisionV1 {
    /// Resulting route snapshot.
    pub snapshot: RouteSnapshotV1,
    /// New external effects, normally zero or one per event.
    pub effects: Vec<RouteEffectV1>,
    /// Old pending effects that must become non-dispatchable in the same
    /// transaction that creates their replacement.
    pub superseded_effects: Vec<EffectIdV1>,
    /// Timer insertions/cancellations.
    pub timers: Vec<RouteTimerMutationV1>,
}

pub(crate) fn validate_digest(value: &Digest32) -> Result<(), CodecErrorV1> {
    if is_zero(value) {
        Err(CodecErrorV1::InvalidValue)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_effect_dispatch(
    dispatch: &EffectDispatchV1,
    contains_route_secret: bool,
) -> Result<(), CodecErrorV1> {
    match dispatch {
        EffectDispatchV1::RunnerPayload {
            payload,
            payload_digest,
        } => {
            if contains_route_secret
                || payload.is_empty()
                || payload.len() > MAX_EFFECT_PAYLOAD_BYTES_V1
                || crate::codec::digest_v1(payload) != *payload_digest
            {
                return Err(CodecErrorV1::InvalidValue);
            }
        }
        EffectDispatchV1::ExternalCustody {
            custody_digest,
            transaction_id,
        } => validate_nonzero_many(&[*custody_digest, *transaction_id])?,
    }
    Ok(())
}

pub(crate) fn validate_effect_reference(reference: &EffectReferenceV1) -> Result<(), CodecErrorV1> {
    if reference.fencing_epoch == 0 {
        return Err(CodecErrorV1::InvalidValue);
    }
    validate_nonzero_many(&[reference.effect_id, reference.semantic_digest])?;
    if let Some(transaction_id) = reference.expected_transaction_id {
        validate_digest(&transaction_id)?;
    }
    Ok(())
}

pub(crate) fn validate_exposure(exposure: &PublicExposureV1) -> Result<(), CodecErrorV1> {
    validate_nonzero_many(&[
        exposure.chain_id,
        exposure.transaction_id,
        exposure.evidence_digest,
    ])
}

pub(crate) fn validate_event(event: &RouteEventV1) -> Result<(), CodecErrorV1> {
    match event {
        RouteEventV1::FreezeTerms(value) => validate_nonzero_many(&[
            value.terms_digest,
            value.profile_bundle_digest,
            value.deployment_bundle_digest,
        ]),
        RouteEventV1::FreezeTermsV2(value) => validate_frozen_admission_checkpoint_v2(value),
        RouteEventV1::ArmRefunds(value) => {
            validate_nonzero_many(&[value.upstream_refund_digest, value.downstream_refund_digest])
        }
        RouteEventV1::CommitAction(intent) => {
            validate_digest(&intent.semantic_digest)?;
            validate_effect_dispatch(&intent.dispatch, intent.contains_route_secret)
        }
        RouteEventV1::ReauthorizeCommittedAction {
            prior_effect_id,
            non_externalization_evidence_digest,
            intent,
        } => {
            validate_nonzero_many(&[
                *prior_effect_id,
                *non_externalization_evidence_digest,
                intent.semantic_digest,
            ])?;
            validate_effect_dispatch(&intent.dispatch, intent.contains_route_secret)
        }
        RouteEventV1::ReauthorizePartiallyExternalizedCustody {
            prior_effect_id,
            partial_externalization_evidence_digest,
            intent,
        } => {
            validate_nonzero_many(&[
                *prior_effect_id,
                *partial_externalization_evidence_digest,
                intent.semantic_digest,
            ])?;
            if !matches!(intent.dispatch, EffectDispatchV1::ExternalCustody { .. }) {
                return Err(CodecErrorV1::InvalidValue);
            }
            validate_effect_dispatch(&intent.dispatch, intent.contains_route_secret)
        }
        RouteEventV1::CustodyProgressRecorded {
            effect_id,
            progress_evidence_digest,
            exposure,
            ..
        } => {
            validate_nonzero_many(&[*effect_id, *progress_evidence_digest])?;
            if let Some(value) = exposure {
                validate_exposure(value)?;
                if value.source != ExposureSourceV1::Externalized {
                    return Err(CodecErrorV1::InvalidValue);
                }
            }
            Ok(())
        }
        RouteEventV1::ActionExternalized {
            effect_id,
            transaction_id,
            exposure,
            ..
        } => {
            validate_nonzero_many(&[*effect_id, *transaction_id])?;
            if let Some(value) = exposure {
                validate_exposure(value)?;
                if value.transaction_id != *transaction_id {
                    return Err(CodecErrorV1::InvalidValue);
                }
            }
            Ok(())
        }
        RouteEventV1::ActionFinalized {
            transaction_id,
            evidence_digest,
            ..
        } => validate_nonzero_many(&[*transaction_id, *evidence_digest]),
        RouteEventV1::ObservationInvalidated {
            transaction_id,
            reorg_evidence_digest,
            ..
        } => validate_nonzero_many(&[*transaction_id, *reorg_evidence_digest]),
        RouteEventV1::SecretObserved(exposure) => validate_exposure(exposure),
        RouteEventV1::SetHealth { reason_digest, .. }
        | RouteEventV1::AbortUnfunded { reason_digest } => validate_digest(reason_digest),
        RouteEventV1::ScheduleTimer {
            deadline_unix_ms,
            context_digest,
            ..
        } => {
            if *deadline_unix_ms == 0 {
                return Err(CodecErrorV1::InvalidValue);
            }
            validate_digest(context_digest)
        }
        RouteEventV1::CancelTimer { timer_id } => validate_digest(timer_id),
    }
}

pub(crate) fn validate_frozen_admission_checkpoint_v2(
    value: &FrozenRouteAdmissionCheckpointV2,
) -> Result<(), CodecErrorV1> {
    validate_nonzero_many(&[
        value.network_id,
        value.route_id,
        value.bindings.terms_digest,
        value.bindings.profile_bundle_digest,
        value.bindings.deployment_bundle_digest,
        value.composition_v2_digest,
        value.registry_manifest_digest,
        value.upstream_terms_digest,
        value.downstream_terms_digest,
        value.upstream_roster_snapshot,
        value.downstream_roster_snapshot,
        value.participant_bindings_digest,
        value.relay_binding_digest,
        value.registry_authority_set_digest,
        value.time_policy_authority_set_digest,
        value.time_evidence_authority_set_digest,
        value.time.route_scope_digest,
        value.time.policy_digest,
        value.time.evidence_digest,
        value.time.proof_digest,
    ])?;
    if value.registry_epoch == 0
        || value.time.evidence_sequence == 0
        || value.time.issued_at_seconds == 0
        || value.time.issued_at_seconds > value.time.validated_at_seconds
        || value.time.validated_at_seconds >= value.time.valid_until_seconds
        || value.bindings.deployment_bundle_digest != value.registry_manifest_digest
        || value.upstream_terms_digest == value.downstream_terms_digest
        || value.upstream_roster_snapshot == value.downstream_roster_snapshot
        || value.registry_authority_set_digest == value.time_policy_authority_set_digest
        || value.registry_authority_set_digest == value.time_evidence_authority_set_digest
        || value.time_policy_authority_set_digest == value.time_evidence_authority_set_digest
    {
        return Err(CodecErrorV1::InvalidValue);
    }
    Ok(())
}

pub(crate) fn validate_effect(effect: &RouteEffectV1) -> Result<(), CodecErrorV1> {
    if effect.fencing_epoch == 0 {
        return Err(CodecErrorV1::InvalidValue);
    }
    validate_nonzero_many(&[effect.route_id, effect.effect_id, effect.semantic_digest])?;
    validate_effect_dispatch(&effect.dispatch, effect.contains_route_secret)
}

pub(crate) fn validate_timer(timer: &RouteTimerV1) -> Result<(), CodecErrorV1> {
    if timer.fencing_epoch == 0 || timer.deadline_unix_ms == 0 {
        return Err(CodecErrorV1::InvalidValue);
    }
    validate_nonzero_many(&[timer.route_id, timer.timer_id, timer.context_digest])
}

fn validate_leg(leg: &LegSnapshotV1) -> Result<(), CodecErrorV1> {
    validate_action_state(&leg.funding)?;
    validate_action_state(&leg.claim)?;
    validate_action_state(&leg.refund)?;
    if leg.claim.progress() != ActionProgressV1::NotPrepared
        && leg.refund.progress() != ActionProgressV1::NotPrepared
    {
        return Err(CodecErrorV1::InvalidValue);
    }
    if (leg.claim.progress() != ActionProgressV1::NotPrepared
        || leg.refund.progress() != ActionProgressV1::NotPrepared)
        && leg.funding.progress() == ActionProgressV1::NotPrepared
    {
        return Err(CodecErrorV1::InvalidValue);
    }
    Ok(())
}

fn validate_action_state(state: &ActionStateV1) -> Result<(), CodecErrorV1> {
    match state {
        ActionStateV1::NotPrepared => Ok(()),
        ActionStateV1::Committed(reference) => validate_effect_reference(reference),
        ActionStateV1::Externalized {
            effect,
            transaction_id,
        } => {
            validate_effect_reference(effect)?;
            validate_digest(transaction_id)?;
            if let Some(expected) = effect.expected_transaction_id {
                if expected != *transaction_id {
                    return Err(CodecErrorV1::InvalidValue);
                }
            }
            Ok(())
        }
        ActionStateV1::Final {
            effect,
            transaction_id,
            evidence_digest,
        } => {
            validate_effect_reference(effect)?;
            validate_nonzero_many(&[*transaction_id, *evidence_digest])?;
            if let Some(expected) = effect.expected_transaction_id {
                if expected != *transaction_id {
                    return Err(CodecErrorV1::InvalidValue);
                }
            }
            Ok(())
        }
        ActionStateV1::FinalityInvalidated {
            effect,
            transaction_id,
            prior_evidence_digest,
            reorg_evidence_digest,
        } => {
            validate_effect_reference(effect)?;
            validate_nonzero_many(&[
                *transaction_id,
                *prior_evidence_digest,
                *reorg_evidence_digest,
            ])?;
            if let Some(expected) = effect.expected_transaction_id {
                if expected != *transaction_id {
                    return Err(CodecErrorV1::InvalidValue);
                }
            }
            Ok(())
        }
    }
}

fn validate_action_purpose(state: &ActionStateV1, kind: ActionKindV1) -> Result<(), CodecErrorV1> {
    let Some(effect) = state.effect() else {
        return Ok(());
    };
    match kind {
        ActionKindV1::Claim if !effect.contains_route_secret => Err(CodecErrorV1::InvalidValue),
        ActionKindV1::Funding | ActionKindV1::Refund if effect.contains_route_secret => {
            Err(CodecErrorV1::InvalidValue)
        }
        ActionKindV1::Claim | ActionKindV1::Funding | ActionKindV1::Refund => Ok(()),
    }
}

fn validate_secret(secret: &SecretVisibilityV1) -> Result<(), CodecErrorV1> {
    match secret {
        SecretVisibilityV1::Private => Ok(()),
        SecretVisibilityV1::Public { first_exposure } => validate_exposure(first_exposure),
    }
}

fn validate_nonzero_many(values: &[Digest32]) -> Result<(), CodecErrorV1> {
    if values.iter().any(is_zero) {
        Err(CodecErrorV1::InvalidValue)
    } else {
        Ok(())
    }
}

fn is_zero(value: &Digest32) -> bool {
    value.iter().all(|byte| *byte == 0)
}

// Keep rustdoc aware that these types implement the public codec in codec.rs.
const _: fn() = || {
    fn assert_codec<T: CanonicalCodecV1>() {}
    assert_codec::<RouteSnapshotV1>();
    assert_codec::<RouteEventV1>();
    assert_codec::<RouteEffectV1>();
    assert_codec::<RouteTimerV1>();
};
