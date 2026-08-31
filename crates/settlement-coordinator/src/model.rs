//! Canonical, secret-free model for one two-face settlement action.

use crate::{CoordinatorErrorV1, Result};

/// Fixed-size public commitment used by the coordinator.
pub type Digest32 = [u8; 32];

pub(crate) const ZERO_DIGEST: Digest32 = [0; 32];
/// Maximum number of external children in one aggregate action.
pub const MAX_SETTLEMENT_CHILDREN_V1: usize = 2;

/// Upstream or downstream settlement in the composed route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementLegV1 {
    /// User input-side settlement.
    Upstream,
    /// User output-side settlement whose claim normally reveals the scalar.
    Downstream,
}

impl SettlementLegV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Upstream => 1,
            Self::Downstream => 2,
        }
    }

    pub(crate) fn from_tag(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Upstream),
            2 => Ok(Self::Downstream),
            _ => Err(CoordinatorErrorV1::InvalidCanonicalMaterial),
        }
    }
}

/// Economic action coordinated across both settlement faces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementActionV1 {
    /// Externalize both funding locks.
    Funding,
    /// Claim both locks in the direction ratified by the settlement terms.
    Claim,
    /// Refund both locks after their authenticated deadlines.
    Refund,
}

impl SettlementActionV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Funding => 1,
            Self::Claim => 2,
            Self::Refund => 3,
        }
    }

    pub(crate) fn from_tag(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Funding),
            2 => Ok(Self::Claim),
            3 => Ok(Self::Refund),
            _ => Err(CoordinatorErrorV1::InvalidCanonicalMaterial),
        }
    }
}

/// Exact settlement face that owns one external child action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementFaceV1 {
    /// DOM scriptless-contract face.
    Dom,
    /// EVM condition-lock face.
    Evm,
    /// Bitcoin Taproot/scriptless face.
    Bitcoin,
}

impl SettlementFaceV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Dom => 1,
            Self::Evm => 2,
            Self::Bitcoin => 3,
        }
    }

    pub(crate) fn from_tag(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Dom),
            2 => Ok(Self::Evm),
            3 => Ok(Self::Bitcoin),
            _ => Err(CoordinatorErrorV1::InvalidCanonicalMaterial),
        }
    }

    pub(crate) const fn is_counterparty(self) -> bool {
        matches!(self, Self::Evm | Self::Bitcoin)
    }
}

/// Route-secret precondition for an aggregate action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretRequirementV1 {
    /// Funding/refund contains no route-secret-bearing child.
    None,
    /// Exactly one child is the first irreversible public exposure.
    FirstExposureRequired,
    /// The route already proved the scalar public before this action starts.
    AlreadyPublic,
}

impl SecretRequirementV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::None => 1,
            Self::FirstExposureRequired => 2,
            Self::AlreadyPublic => 3,
        }
    }

    pub(crate) fn from_tag(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::None),
            2 => Ok(Self::FirstExposureRequired),
            3 => Ok(Self::AlreadyPublic),
            _ => Err(CoordinatorErrorV1::InvalidCanonicalMaterial),
        }
    }
}

/// Secret-exposure role of one child in the immutable action order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildExposureV1 {
    /// Child cannot reveal the route scalar.
    NonSecret,
    /// This child is the first transaction that can make the scalar public.
    FirstSecretExposure,
    /// Child uses a scalar that the route already treats as public.
    UsesPublicSecret,
}

impl ChildExposureV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::NonSecret => 1,
            Self::FirstSecretExposure => 2,
            Self::UsesPublicSecret => 3,
        }
    }

    pub(crate) fn from_tag(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::NonSecret),
            2 => Ok(Self::FirstSecretExposure),
            3 => Ok(Self::UsesPublicSecret),
            _ => Err(CoordinatorErrorV1::InvalidCanonicalMaterial),
        }
    }
}

/// Authenticated immutable facts shared by both children.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementPlanBindingsV1 {
    /// Composed-route identity.
    pub route_id: Digest32,
    /// Exact route outbox effect represented by the aggregate action.
    pub effect_id: Digest32,
    /// Frozen single-settlement identity from `SettlementTermsV1`.
    pub settlement_id: Digest32,
    /// Position in the composed route.
    pub leg: SettlementLegV1,
    /// Economic action.
    pub action: SettlementActionV1,
    /// Route fencing epoch that authorized this plan version.
    pub fencing_epoch: u64,
    /// Semantic retry commitment from the route effect.
    pub semantic_digest: Digest32,
    /// Frozen settlement terms digest.
    pub terms_digest: Digest32,
    /// Threshold-authenticated deployment-registry manifest digest.
    pub registry_digest: Digest32,
    /// Authenticated DOM chain/consensus profile digest.
    pub dom_profile_digest: Digest32,
    /// Authenticated DOM deployment digest.
    pub dom_deployment_digest: Digest32,
    /// Authenticated counterparty chain profile digest.
    pub counterparty_profile_digest: Digest32,
    /// Authenticated counterparty deployment digest.
    pub counterparty_deployment_digest: Digest32,
}

impl SettlementPlanBindingsV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_nonzero_many(&[
            self.route_id,
            self.effect_id,
            self.settlement_id,
            self.semantic_digest,
            self.terms_digest,
            self.registry_digest,
            self.dom_profile_digest,
            self.dom_deployment_digest,
            self.counterparty_profile_digest,
            self.counterparty_deployment_digest,
        ])?;
        if self.fencing_epoch == 0 {
            return Err(CoordinatorErrorV1::InvalidPlan);
        }
        Ok(())
    }
}

/// One exact child transaction descriptor. It contains commitments only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementChildPlanV1 {
    /// Authority/chain face that must externalize this child.
    pub face: SettlementFaceV1,
    /// Route-secret role of this child.
    pub exposure: ChildExposureV1,
    /// Authenticated chain identity.
    pub chain_id: Digest32,
    /// Exact public chain transaction identity expected from the actuator.
    pub expected_transaction_id: Digest32,
    /// Commitment to the exact child transaction semantics.
    pub intent_digest: Digest32,
    /// Commitment to the actuator's retained exact bytes/descriptor.
    pub custody_digest: Digest32,
}

/// Secret-free commitment for a child that must not be materialized before
/// the first-exposure child has made the route scalar public.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeferredSettlementChildV1 {
    /// Exact counterparty face to materialize after the public transition.
    pub face: SettlementFaceV1,
    /// Authenticated chain identity.
    pub chain_id: Digest32,
    /// Composed-route scope commitment.
    pub route_scope_digest: Digest32,
    /// Exact composition commitment.
    pub composition_digest: Digest32,
    /// Authenticated final-claim role plan.
    pub role_plan_digest: Digest32,
    /// Exact secret-source scope for this leg.
    pub source_scope_digest: Digest32,
    /// Pinned identity of the sole materialization authority allowed to turn
    /// this descriptor into retained child facts.
    pub materializer_authority_id: Digest32,
}

impl DeferredSettlementChildV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        if !self.face.is_counterparty() {
            return Err(CoordinatorErrorV1::InvalidPlan);
        }
        validate_nonzero_many(&[
            self.chain_id,
            self.route_scope_digest,
            self.composition_digest,
            self.role_plan_digest,
            self.source_scope_digest,
            self.materializer_authority_id,
        ])
    }
}

/// Exact child layout retained by one aggregate action.  The staged form is
/// legal only for a private downstream claim and deliberately has no
/// transaction, intent, or custody identity for its second child.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SettlementChildrenV1 {
    /// Both children were safely materialized before installation.
    Materialized([SettlementChildPlanV1; MAX_SETTLEMENT_CHILDREN_V1]),
    /// Only the first-exposure child exists; the second is a secret-free
    /// authenticated descriptor awaiting a public-secret capability.
    FirstExposureStaged {
        /// Exact DOM child that can be prepared and dispatched while `t`
        /// remains private.
        first: SettlementChildPlanV1,
        /// Secret-free counterparty descriptor pinned to its materializer.
        deferred: DeferredSettlementChildV1,
    },
}

impl SettlementChildPlanV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_nonzero_many(&[
            self.chain_id,
            self.expected_transaction_id,
            self.intent_digest,
            self.custody_digest,
        ])
    }
}

/// Strict two-child plan, ordered exactly as externalization is permitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositeSettlementPlanV1 {
    bindings: SettlementPlanBindingsV1,
    secret_requirement: SecretRequirementV1,
    preexisting_secret_evidence_digest: Option<Digest32>,
    children: SettlementChildrenV1,
}

impl CompositeSettlementPlanV1 {
    /// Builds a strict DOM + EVM/Bitcoin action plan.
    pub fn new(
        bindings: SettlementPlanBindingsV1,
        secret_requirement: SecretRequirementV1,
        preexisting_secret_evidence_digest: Option<Digest32>,
        children: [SettlementChildPlanV1; MAX_SETTLEMENT_CHILDREN_V1],
    ) -> Result<Self> {
        let plan = Self {
            bindings,
            secret_requirement,
            preexisting_secret_evidence_digest,
            children: SettlementChildrenV1::Materialized(children),
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Builds a downstream private-claim plan whose second child cannot be
    /// materialized until the coordinator authenticates the first exposure.
    pub fn new_first_exposure_staged(
        bindings: SettlementPlanBindingsV1,
        first: SettlementChildPlanV1,
        deferred: DeferredSettlementChildV1,
    ) -> Result<Self> {
        let plan = Self {
            bindings,
            secret_requirement: SecretRequirementV1::FirstExposureRequired,
            preexisting_secret_evidence_digest: None,
            children: SettlementChildrenV1::FirstExposureStaged { first, deferred },
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Immutable route/effect/deployment bindings.
    pub const fn bindings(&self) -> &SettlementPlanBindingsV1 {
        &self.bindings
    }

    /// Route-secret precondition.
    pub const fn secret_requirement(&self) -> SecretRequirementV1 {
        self.secret_requirement
    }

    /// Evidence that the scalar was already public, when required.
    pub const fn preexisting_secret_evidence_digest(&self) -> Option<Digest32> {
        self.preexisting_secret_evidence_digest
    }

    /// Exact immutable child order.
    pub const fn child_layout(&self) -> &SettlementChildrenV1 {
        &self.children
    }

    /// Returns one exact materialized child, or `None` while the second child
    /// is intentionally deferred.
    pub fn materialized_child(&self, index: usize) -> Option<&SettlementChildPlanV1> {
        match &self.children {
            SettlementChildrenV1::Materialized(children) => children.get(index),
            SettlementChildrenV1::FirstExposureStaged { first, .. } if index == 0 => Some(first),
            SettlementChildrenV1::FirstExposureStaged { .. } => None,
        }
    }

    /// Returns both exact children only when materialization was safe before
    /// installation. Staged plans fail closed until the second child is
    /// durably materialized through its capability.
    pub fn materialized_children(
        &self,
    ) -> Result<&[SettlementChildPlanV1; MAX_SETTLEMENT_CHILDREN_V1]> {
        match &self.children {
            SettlementChildrenV1::Materialized(children) => Ok(children),
            SettlementChildrenV1::FirstExposureStaged { .. } => {
                Err(CoordinatorErrorV1::InvalidState)
            }
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.bindings.validate()?;
        match &self.children {
            SettlementChildrenV1::Materialized(children) => {
                for child in children {
                    child.validate()?;
                }
                let dom_count = children
                    .iter()
                    .filter(|child| child.face == SettlementFaceV1::Dom)
                    .count();
                let counterparty_count = children
                    .iter()
                    .filter(|child| child.face.is_counterparty())
                    .count();
                if dom_count != 1
                    || counterparty_count != 1
                    || children[0].face == children[1].face
                    || children[0].chain_id == children[1].chain_id
                    || children[0].intent_digest == children[1].intent_digest
                    || children[0].custody_digest == children[1].custody_digest
                {
                    return Err(CoordinatorErrorV1::InvalidPlan);
                }
            }
            SettlementChildrenV1::FirstExposureStaged { first, deferred } => {
                first.validate()?;
                deferred.validate()?;
                if self.bindings.action != SettlementActionV1::Claim
                    || self.secret_requirement != SecretRequirementV1::FirstExposureRequired
                    || self.preexisting_secret_evidence_digest.is_some()
                    || first.face != SettlementFaceV1::Dom
                    || first.exposure != ChildExposureV1::FirstSecretExposure
                    || deferred.face == first.face
                    || deferred.chain_id == first.chain_id
                {
                    return Err(CoordinatorErrorV1::InvalidPlan);
                }
                return Ok(());
            }
        }

        let children = self.materialized_children()?;
        match (self.bindings.action, self.secret_requirement) {
            (
                SettlementActionV1::Funding | SettlementActionV1::Refund,
                SecretRequirementV1::None,
            ) if self.preexisting_secret_evidence_digest.is_none()
                && children
                    .iter()
                    .all(|child| child.exposure == ChildExposureV1::NonSecret) =>
            {
                Ok(())
            }
            (SettlementActionV1::Claim, SecretRequirementV1::FirstExposureRequired)
                if self.preexisting_secret_evidence_digest.is_none()
                    && children[0].exposure == ChildExposureV1::FirstSecretExposure
                    && children[1].exposure == ChildExposureV1::UsesPublicSecret =>
            {
                Ok(())
            }
            (SettlementActionV1::Claim, SecretRequirementV1::AlreadyPublic)
                if self
                    .preexisting_secret_evidence_digest
                    .is_some_and(|digest| digest != ZERO_DIGEST)
                    && children
                        .iter()
                        .all(|child| child.exposure == ChildExposureV1::UsesPublicSecret) =>
            {
                Ok(())
            }
            _ => Err(CoordinatorErrorV1::InvalidPlan),
        }
    }
}

/// Immutable request passed to the deployment/route plan authority.
pub struct PlanAuthorizationRequestV1<'plan> {
    pub(crate) plan: &'plan CompositeSettlementPlanV1,
    pub(crate) plan_digest: Digest32,
}

impl core::fmt::Debug for PlanAuthorizationRequestV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PlanAuthorizationRequestV1")
            .field("route_id", &self.plan.bindings.route_id)
            .field("effect_id", &self.plan.bindings.effect_id)
            .field("plan_digest", &self.plan_digest)
            .finish_non_exhaustive()
    }
}

impl<'plan> PlanAuthorizationRequestV1<'plan> {
    /// Exact plan awaiting authentication.
    pub const fn plan(&self) -> &'plan CompositeSettlementPlanV1 {
        self.plan
    }

    /// Canonical plan digest calculated by the coordinator.
    pub const fn plan_digest(&self) -> Digest32 {
        self.plan_digest
    }
}

/// Authorization returned by a route/deployment-aware plan authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanAuthorizationV1 {
    authority_id: Digest32,
    plan_digest: Digest32,
    evidence_digest: Digest32,
    valid_until_unix_ms: u64,
}

impl PlanAuthorizationV1 {
    /// Constructs a public authorization proof; the store still pins and
    /// verifies the authority identity, exact plan digest and expiry.
    pub fn new(
        authority_id: Digest32,
        plan_digest: Digest32,
        evidence_digest: Digest32,
        valid_until_unix_ms: u64,
    ) -> Result<Self> {
        validate_nonzero_many(&[authority_id, plan_digest, evidence_digest])?;
        if valid_until_unix_ms == 0 {
            return Err(CoordinatorErrorV1::InvalidPlanAuthorization);
        }
        Ok(Self {
            authority_id,
            plan_digest,
            evidence_digest,
            valid_until_unix_ms,
        })
    }

    /// Identity of the authority that authenticated this exact plan.
    ///
    /// Composition-root wrappers may preserve this value while adding a
    /// second, domain-separated authorization commitment.
    pub const fn authority_id(self) -> Digest32 {
        self.authority_id
    }

    /// Exact canonical plan digest authenticated by the authority.
    pub const fn plan_digest(self) -> Digest32 {
        self.plan_digest
    }

    /// Public commitment to the authority's authentication evidence.
    pub const fn evidence_digest(self) -> Digest32 {
        self.evidence_digest
    }

    /// Inclusive expiry of this authorization in trusted Unix milliseconds.
    pub const fn valid_until_unix_ms(self) -> u64 {
        self.valid_until_unix_ms
    }
}

/// Plan-authentication refusal without credential or signature bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PlanAuthorityRefusalV1 {
    /// Authentication or policy rejected the exact plan.
    #[error("settlement plan authority refused authorization")]
    Refused,
    /// The authenticated authority is temporarily unavailable.
    #[error("settlement plan authority unavailable")]
    Unavailable,
    /// The authority detected conflicting prior authorization.
    #[error("settlement plan authority detected a conflict")]
    Conflict,
}

/// Narrow authority for one canonical settlement plan. It is not a generic
/// signing interface and receives no transaction bytes or secret material.
pub trait SettlementPlanAuthorityV1 {
    /// Authenticate the exact route/deployment-bound plan.
    fn authorize_plan(
        &mut self,
        request: PlanAuthorizationRequestV1<'_>,
    ) -> core::result::Result<PlanAuthorizationV1, PlanAuthorityRefusalV1>;
}

/// Durable aggregate lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateStageV1 {
    /// At least one required child remains locally custodied.
    Active,
    /// Both required child transactions left custody.
    Externalized,
    /// Both child transactions satisfy their authenticated finality policies.
    Final,
    /// Aggregate finality was invalidated by at least one child reorg.
    FinalityInvalidated,
    /// A durable duplicate/equivocation or corruption forced terminal refusal.
    FailedClosed,
}

/// Durable lifecycle of one exact child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildStageV1 {
    /// No transaction exists yet; an authenticated descriptor awaits the
    /// durable public-secret transition.
    Deferred,
    /// No external call has been authorized.
    Planned,
    /// A byte-identical child call was persisted before invoking authority.
    CallPending,
    /// Exact expected transaction left custody.
    Externalized,
    /// Exact expected transaction reached authenticated finality.
    Final,
    /// Earlier finality was invalidated by reorg evidence.
    FinalityInvalidated,
}

/// Public, secret-free view of one child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildProgressViewV1 {
    /// Zero-based immutable plan index.
    pub child_index: u8,
    /// Settlement face.
    pub face: SettlementFaceV1,
    /// Exposure classification.
    pub exposure: ChildExposureV1,
    /// Current durable lifecycle.
    pub stage: ChildStageV1,
    /// Number of persisted externalization calls.
    pub call_attempts: u64,
    /// Exact expected/observed transaction identity.
    pub transaction_id: Option<Digest32>,
    /// Last externalization evidence commitment, when present.
    pub externalization_evidence_digest: Option<Digest32>,
    /// Active finality evidence commitment, when present.
    pub finality_evidence_digest: Option<Digest32>,
    /// Last finality-invalidation evidence commitment, when present.
    pub reorg_evidence_digest: Option<Digest32>,
}

/// Public, revalidated aggregate plan view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementPlanViewV1 {
    /// Stable semantic plan identity; unchanged across re-fencing.
    pub plan_id: Digest32,
    /// Digest of the current canonical plan version, including effect/fence.
    pub plan_digest: Digest32,
    /// Current route effect identity.
    pub effect_id: Digest32,
    /// Current route fencing generation.
    pub fencing_epoch: u64,
    /// Current aggregate lifecycle.
    pub stage: AggregateStageV1,
    /// Current materialized revision/journal sequence.
    pub revision: u64,
    /// Synthetic public identity of the whole two-child action.
    pub aggregate_action_id: Digest32,
    /// Commitment to both external-custody child descriptors.
    pub aggregate_custody_digest: Digest32,
    /// Number of children durably externalized as a contiguous prefix.
    pub completed_prefix: u8,
    /// Ordered child views.
    pub children: [ChildProgressViewV1; MAX_SETTLEMENT_CHILDREN_V1],
}

/// Fully revalidated, secret-free plan and its current durable view. This is
/// returned only by indexed lookups; the store never exposes enumeration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSettlementPlanV1 {
    pub(crate) plan: CompositeSettlementPlanV1,
    pub(crate) view: SettlementPlanViewV1,
}

impl StoredSettlementPlanV1 {
    /// Current canonical plan version, including its current effect and fence.
    pub const fn plan(&self) -> &CompositeSettlementPlanV1 {
        &self.plan
    }

    /// Current fully audited lifecycle view.
    pub const fn view(&self) -> &SettlementPlanViewV1 {
        &self.view
    }
}

/// Lease/fencing capability for one stored plan.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CoordinatorLeaseV1 {
    pub(crate) plan_id: Digest32,
    pub(crate) owner_id: Digest32,
    pub(crate) route_fencing_epoch: u64,
    pub(crate) coordinator_fencing_epoch: u64,
    pub(crate) lease_until_unix_ms: u64,
}

impl core::fmt::Debug for CoordinatorLeaseV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CoordinatorLeaseV1")
            .field("plan_id", &self.plan_id)
            .field("owner_id", &"<redacted owner>")
            .field("route_fencing_epoch", &self.route_fencing_epoch)
            .field("coordinator_fencing_epoch", &self.coordinator_fencing_epoch)
            .field("lease_until_unix_ms", &self.lease_until_unix_ms)
            .finish()
    }
}

impl CoordinatorLeaseV1 {
    /// Stable semantic plan identity.
    pub const fn plan_id(self) -> Digest32 {
        self.plan_id
    }

    /// Route fencing generation currently driving the coordinator.
    pub const fn route_fencing_epoch(self) -> u64 {
        self.route_fencing_epoch
    }

    /// Monotonic coordinator-store fencing generation.
    pub const fn coordinator_fencing_epoch(self) -> u64 {
        self.coordinator_fencing_epoch
    }

    /// Absolute lease expiry.
    pub const fn lease_until_unix_ms(self) -> u64 {
        self.lease_until_unix_ms
    }
}

/// Lease acquisition classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorLeaseAcquireV1 {
    /// A new coordinator fencing generation was acquired.
    Acquired(CoordinatorLeaseV1),
    /// The same owner already held the live generation.
    AlreadyOwned(CoordinatorLeaseV1),
}

impl CoordinatorLeaseAcquireV1 {
    /// Returns the lease in either successful case.
    pub const fn lease(self) -> CoordinatorLeaseV1 {
        match self {
            Self::Acquired(lease) | Self::AlreadyOwned(lease) => lease,
        }
    }
}

/// Exact persisted request for one child authority call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildDispatchRequestV1 {
    pub(crate) plan_id: Digest32,
    pub(crate) plan_digest: Digest32,
    pub(crate) aggregate_action_id: Digest32,
    pub(crate) aggregate_custody_digest: Digest32,
    pub(crate) route_id: Digest32,
    pub(crate) effect_id: Digest32,
    pub(crate) settlement_id: Digest32,
    pub(crate) leg: SettlementLegV1,
    pub(crate) action: SettlementActionV1,
    pub(crate) semantic_digest: Digest32,
    pub(crate) terms_digest: Digest32,
    pub(crate) registry_digest: Digest32,
    pub(crate) profile_digest: Digest32,
    pub(crate) deployment_digest: Digest32,
    pub(crate) route_fencing_epoch: u64,
    pub(crate) coordinator_fencing_epoch: u64,
    pub(crate) child_index: u8,
    pub(crate) face: SettlementFaceV1,
    pub(crate) exposure: ChildExposureV1,
    pub(crate) chain_id: Digest32,
    pub(crate) expected_transaction_id: Digest32,
    pub(crate) intent_digest: Digest32,
    pub(crate) custody_digest: Digest32,
    pub(crate) attempt: u64,
    pub(crate) attempt_id: Digest32,
}

impl ChildDispatchRequestV1 {
    /// Stable semantic plan identity.
    pub const fn plan_id(&self) -> Digest32 {
        self.plan_id
    }
    /// Current canonical plan version digest.
    pub const fn plan_digest(&self) -> Digest32 {
        self.plan_digest
    }
    /// Synthetic aggregate action identity expected by the route wrapper.
    pub const fn aggregate_action_id(&self) -> Digest32 {
        self.aggregate_action_id
    }
    /// Aggregate external-custody commitment.
    pub const fn aggregate_custody_digest(&self) -> Digest32 {
        self.aggregate_custody_digest
    }
    /// Route identity.
    pub const fn route_id(&self) -> Digest32 {
        self.route_id
    }
    /// Current route effect identity.
    pub const fn effect_id(&self) -> Digest32 {
        self.effect_id
    }
    /// Single settlement identity.
    pub const fn settlement_id(&self) -> Digest32 {
        self.settlement_id
    }
    /// Composed-route leg.
    pub const fn leg(&self) -> SettlementLegV1 {
        self.leg
    }
    /// Economic action.
    pub const fn action(&self) -> SettlementActionV1 {
        self.action
    }
    /// Route semantic commitment.
    pub const fn semantic_digest(&self) -> Digest32 {
        self.semantic_digest
    }
    /// Frozen terms commitment.
    pub const fn terms_digest(&self) -> Digest32 {
        self.terms_digest
    }
    /// Authenticated registry commitment.
    pub const fn registry_digest(&self) -> Digest32 {
        self.registry_digest
    }
    /// Authenticated profile of the exact child chain.
    pub const fn profile_digest(&self) -> Digest32 {
        self.profile_digest
    }
    /// Authenticated deployment of the exact child face.
    pub const fn deployment_digest(&self) -> Digest32 {
        self.deployment_digest
    }
    /// Current route fencing generation.
    pub const fn route_fencing_epoch(&self) -> u64 {
        self.route_fencing_epoch
    }
    /// Current coordinator-store fencing generation.
    pub const fn coordinator_fencing_epoch(&self) -> u64 {
        self.coordinator_fencing_epoch
    }
    /// Zero-based immutable child index.
    pub const fn child_index(&self) -> u8 {
        self.child_index
    }
    /// Child settlement face.
    pub const fn face(&self) -> SettlementFaceV1 {
        self.face
    }
    /// Child exposure role.
    pub const fn exposure(&self) -> ChildExposureV1 {
        self.exposure
    }
    /// Authenticated child chain identity.
    pub const fn chain_id(&self) -> Digest32 {
        self.chain_id
    }
    /// Exact transaction expected from the actuator.
    pub const fn expected_transaction_id(&self) -> Digest32 {
        self.expected_transaction_id
    }
    /// Child semantic transaction commitment.
    pub const fn intent_digest(&self) -> Digest32 {
        self.intent_digest
    }
    /// Child exact-byte/descriptor custody commitment.
    pub const fn custody_digest(&self) -> Digest32 {
        self.custody_digest
    }
    /// Persisted delivery attempt.
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }
    /// Deterministic idempotency identity for this exact authority call.
    pub const fn attempt_id(&self) -> Digest32 {
        self.attempt_id
    }
}

/// Move-only token proving the child call intent is already durable.
pub struct PendingChildCallV1 {
    pub(crate) request: ChildDispatchRequestV1,
    pub(crate) call_record_digest: Digest32,
}

impl core::fmt::Debug for PendingChildCallV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PendingChildCallV1")
            .field("request", &self.request)
            .field("call_record_digest", &self.call_record_digest)
            .finish()
    }
}

impl PendingChildCallV1 {
    /// Borrow the exact public request for the child authority.
    pub const fn request(&self) -> &ChildDispatchRequestV1 {
        &self.request
    }
}

/// Child authority refusal. Any failure after a persisted call remains
/// ambiguous until the same attempt or an explicit reconciliation resolves it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ChildAuthorityRefusalV1 {
    /// Authority is temporarily unavailable.
    #[error("settlement child authority unavailable")]
    Unavailable,
    /// Authority policy refused the exact child.
    #[error("settlement child authority refused the exact action")]
    Refused,
    /// Authority retained state conflicts with this idempotency request.
    #[error("settlement child authority detected a conflict")]
    Conflict,
}

/// Receipt for one exact child leaving custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildExternalizationReceiptV1 {
    /// Stable plan identity.
    pub plan_id: Digest32,
    /// Exact child index.
    pub child_index: u8,
    /// Exact child face.
    pub face: SettlementFaceV1,
    /// Authenticated chain identity.
    pub chain_id: Digest32,
    /// Exact transaction identity expected by the plan.
    pub transaction_id: Digest32,
    /// Exact child semantic commitment.
    pub intent_digest: Digest32,
    /// Exact child custody commitment.
    pub custody_digest: Digest32,
    /// Evidence that the exact transaction crossed the actuator boundary.
    pub externalization_evidence_digest: Digest32,
    /// Evidence of first public route-secret exposure, required only for the
    /// child marked `FirstSecretExposure`.
    pub first_exposure_evidence_digest: Option<Digest32>,
}

/// Outcome of one exact child call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildExecutionOutcomeV1 {
    /// Exact transaction left custody.
    Externalized(ChildExternalizationReceiptV1),
    /// Authority proves this call returned before any externalization.
    RetryableBeforeExternalization {
        /// Nonzero public evidence commitment.
        evidence_digest: Digest32,
    },
    /// Externalization cannot be proved or disproved; the same attempt must be
    /// reconciled and no later child may run.
    Unknown {
        /// Nonzero ambiguity/reconciliation evidence commitment.
        evidence_digest: Digest32,
    },
}

/// Narrow child authority. Exact transaction bytes, keys, shares, nonces and
/// scalars remain in the face-specific actuator and never cross this trait.
pub trait SettlementChildAuthorityV1 {
    /// Idempotently progresses exactly one persisted child call.
    fn externalize_child(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> core::result::Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1>;

    /// Reconciles one exact pending call at the current or a newer route
    /// fence without dispatching a different transaction.
    fn reconcile_child(
        &mut self,
        request: &ChildReconciliationRequestV1,
    ) -> core::result::Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1>;
}

/// Move-only proof that the coordinator durably committed a deferred-child
/// materialization attempt after authenticating the first public exposure.
pub struct DeferredChildMaterializationCapabilityV1 {
    pub(crate) route_id: Digest32,
    pub(crate) plan_id: Digest32,
    pub(crate) plan_digest: Digest32,
    pub(crate) attempt_id: Digest32,
    pub(crate) bindings: SettlementPlanBindingsV1,
    pub(crate) descriptor: DeferredSettlementChildV1,
    pub(crate) exposure: ChildPublicExposureV1,
}

/// Exact result returned by the pinned deferred-child authority.  The
/// coordinator revalidates both the authority identity and every child fact
/// before committing it.
pub struct DeferredChildMaterializationResultV1 {
    authority_id: Digest32,
    attempt_id: Digest32,
    child: SettlementChildPlanV1,
}

impl DeferredChildMaterializationResultV1 {
    /// Completes the exact move-only capability consumed by the authority.
    /// An unscoped caller cannot manufacture a result because construction
    /// requires the coordinator-minted capability itself.
    pub fn complete(
        capability: DeferredChildMaterializationCapabilityV1,
        authority_id: Digest32,
        child: SettlementChildPlanV1,
    ) -> Result<Self> {
        validate_nonzero_many(&[authority_id, capability.attempt_id])?;
        if authority_id != capability.descriptor.materializer_authority_id {
            return Err(CoordinatorErrorV1::InvalidPlanAuthorization);
        }
        child.validate()?;
        Ok(Self {
            authority_id,
            attempt_id: capability.attempt_id,
            child,
        })
    }

    /// Identity of the authority that produced the retained child.
    pub const fn authority_id(&self) -> Digest32 {
        self.authority_id
    }

    /// Durable attempt consumed to produce this result.
    pub const fn attempt_id(&self) -> Digest32 {
        self.attempt_id
    }

    /// Exact retained child facts.
    pub const fn child(&self) -> &SettlementChildPlanV1 {
        &self.child
    }

    pub(crate) fn into_child(self) -> SettlementChildPlanV1 {
        self.child
    }
}

impl DeferredChildMaterializationCapabilityV1 {
    /// Authenticated route identity.
    pub const fn route_id(&self) -> Digest32 {
        self.route_id
    }

    /// Stable coordinator plan identity.
    pub const fn plan_id(&self) -> Digest32 {
        self.plan_id
    }

    /// Immutable authorized plan digest.
    pub const fn plan_digest(&self) -> Digest32 {
        self.plan_digest
    }

    /// Idempotent durable materialization attempt identity.
    pub const fn attempt_id(&self) -> Digest32 {
        self.attempt_id
    }

    /// Immutable route/settlement/action/fence and deployment commitments
    /// authenticated by the original plan authority.
    pub const fn bindings(&self) -> &SettlementPlanBindingsV1 {
        &self.bindings
    }

    /// Secret-free exact deferred descriptor.
    pub const fn descriptor(&self) -> &DeferredSettlementChildV1 {
        &self.descriptor
    }

    /// Authenticated first public exposure that unlocked this attempt.
    pub const fn exposure(&self) -> &ChildPublicExposureV1 {
        &self.exposure
    }
}

/// Owner-only authority that consumes a durable deferred capability and
/// returns the exact child retained by the face actuator.
pub trait SettlementDeferredChildAuthorityV1 {
    /// Stable identity pinned by the immutable deferred descriptor.
    fn authority_id(&self) -> Digest32;

    /// Materializes without broadcasting; the coordinator persists the exact
    /// result before a later drive may dispatch it.
    fn materialize_deferred_child(
        &mut self,
        capability: DeferredChildMaterializationCapabilityV1,
    ) -> core::result::Result<DeferredChildMaterializationResultV1, ChildAuthorityRefusalV1>;
}

/// Public-only first exposure retained from one child receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildPublicExposureV1 {
    /// Child that first exposed the scalar.
    pub child_index: u8,
    /// Authenticated chain where exposure occurred.
    pub chain_id: Digest32,
    /// Real chain transaction that exposed the scalar.
    pub transaction_id: Digest32,
    /// Commitment to extraction/externalization evidence.
    pub evidence_digest: Digest32,
    /// Trusted local time retained when the coordinator first committed the
    /// public exposure. Replays must return this exact value.
    pub observed_at_unix_ms: u64,
}

/// Move-only proof of the exact first public exposure retained by an audited
/// coordinator plan.
///
/// There is no public constructor, codec, `Clone`, or `Copy`.  The durable
/// coordinator mints this value only after revalidating the complete plan,
/// children, versions, call records and journal, and after reading the first
/// exposure back from that same authenticated plan row.  It is the narrow
/// authority that permits a caller to recover an already-fsynced route-secret
/// seal while the parent route journal is still at the pre-`Public` crash cut.
pub struct AuthenticatedCoordinatorExposureV1 {
    route_id: Digest32,
    plan_id: Digest32,
    settlement_id: Digest32,
    plan_digest: Digest32,
    plan_revision: u64,
    journal_head: Digest32,
    exposure: ChildPublicExposureV1,
}

impl core::fmt::Debug for AuthenticatedCoordinatorExposureV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthenticatedCoordinatorExposureV1")
            .field("route_id", &self.route_id)
            .field("plan_id", &self.plan_id)
            .field("settlement_id", &self.settlement_id)
            .field("plan_digest", &self.plan_digest)
            .field("plan_revision", &self.plan_revision)
            .field("journal_head", &self.journal_head)
            .field("exposure", &self.exposure)
            .finish()
    }
}

impl AuthenticatedCoordinatorExposureV1 {
    pub(crate) fn from_audited_plan(
        route_id: Digest32,
        plan_id: Digest32,
        settlement_id: Digest32,
        plan_digest: Digest32,
        plan_revision: u64,
        journal_head: Digest32,
        exposure: ChildPublicExposureV1,
    ) -> Result<Self> {
        validate_nonzero_many(&[
            route_id,
            plan_id,
            settlement_id,
            plan_digest,
            journal_head,
            exposure.chain_id,
            exposure.transaction_id,
            exposure.evidence_digest,
        ])?;
        if plan_revision == 0
            || usize::from(exposure.child_index) >= MAX_SETTLEMENT_CHILDREN_V1
            || exposure.observed_at_unix_ms == 0
        {
            return Err(CoordinatorErrorV1::InvalidPlan);
        }
        Ok(Self {
            route_id,
            plan_id,
            settlement_id,
            plan_digest,
            plan_revision,
            journal_head,
            exposure,
        })
    }

    /// Route identity authenticated by the coordinator plan.
    pub const fn route_id(&self) -> Digest32 {
        self.route_id
    }

    /// Stable coordinator plan identity.
    pub const fn plan_id(&self) -> Digest32 {
        self.plan_id
    }

    /// Settlement identity whose first child exposed the scalar.
    pub const fn settlement_id(&self) -> Digest32 {
        self.settlement_id
    }

    /// Current fully audited plan-version digest.
    pub const fn plan_digest(&self) -> Digest32 {
        self.plan_digest
    }

    /// Audited coordinator revision that retained the exposure.
    pub const fn plan_revision(&self) -> u64 {
        self.plan_revision
    }

    /// Audited coordinator journal head at that revision.
    pub const fn journal_head(&self) -> Digest32 {
        self.journal_head
    }

    /// Exact first public exposure read from the authenticated plan row.
    pub const fn exposure(&self) -> &ChildPublicExposureV1 {
        &self.exposure
    }
}

/// Durable partial aggregate progress. This never closes the route effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartialCustodyProgressV1 {
    /// Stable plan identity.
    pub plan_id: Digest32,
    /// Synthetic aggregate action identity.
    pub aggregate_action_id: Digest32,
    /// Aggregate custody commitment.
    pub aggregate_custody_digest: Digest32,
    /// Number of externalized children in the strict prefix.
    pub completed_prefix: u8,
    /// Commitment to all durable prefix receipts and journal state.
    pub progress_evidence_digest: Digest32,
    /// Exact first public exposure, if it occurred in this prefix.
    pub exposure: Option<ChildPublicExposureV1>,
}

/// Receipt emitted only after every required child left custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateExternalizationReceiptV1 {
    /// Stable plan identity.
    pub plan_id: Digest32,
    /// Synthetic public identity of the two-child economic action.
    pub aggregate_action_id: Digest32,
    /// Commitment to both exact child custody descriptors.
    pub aggregate_custody_digest: Digest32,
    /// Commitment to both exact child externalization receipts.
    pub child_receipts_digest: Digest32,
    /// First public exposure caused by this aggregate, when applicable.
    pub first_exposure: Option<ChildPublicExposureV1>,
}

/// Result of one coordinator drive call. At most one child authority was
/// invoked to produce any variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorDriveOutcomeV1 {
    /// Authority proved no externalization; a new attempt may be scheduled.
    Waiting {
        /// Nonzero proof/diagnostic commitment.
        evidence_digest: Digest32,
    },
    /// A child call remains ambiguous and blocks all later children.
    Unknown {
        /// Nonzero ambiguity commitment.
        evidence_digest: Digest32,
    },
    /// A strict prefix left custody but the aggregate is not complete.
    PartialProgress(PartialCustodyProgressV1),
    /// Both required children left custody.
    AggregateExternalized(AggregateExternalizationReceiptV1),
}

/// Reconciliation request for one exact pending child call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildReconciliationRequestV1 {
    /// Original byte-identical dispatch request.
    pub dispatch: ChildDispatchRequestV1,
    /// Current route fencing generation performing reconciliation.
    pub current_route_fencing_epoch: u64,
    /// Current coordinator-store fencing generation.
    pub current_coordinator_fencing_epoch: u64,
    /// Deterministic reconciliation call identity.
    pub reconciliation_attempt_id: Digest32,
}

/// Explicit child reconciliation result at the current or a newer fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildReconciliationOutcomeV1 {
    /// Exact expected child transaction already left custody.
    Externalized(ChildExternalizationReceiptV1),
    /// Authority proves nothing crossed its external boundary.
    ProvenNotExternalized {
        /// Nonzero authenticated evidence commitment.
        evidence_digest: Digest32,
    },
    /// Evidence is insufficient; the child remains inert.
    Unknown {
        /// Nonzero ambiguity evidence commitment.
        evidence_digest: Digest32,
    },
}

/// Move-only token proving reconciliation intent is durable.
pub struct PendingChildReconciliationV1 {
    pub(crate) request: ChildReconciliationRequestV1,
    pub(crate) reconciliation_record_digest: Digest32,
}

impl core::fmt::Debug for PendingChildReconciliationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PendingChildReconciliationV1")
            .field("request", &self.request)
            .field(
                "reconciliation_record_digest",
                &self.reconciliation_record_digest,
            )
            .finish()
    }
}

impl PendingChildReconciliationV1 {
    /// Borrow the exact public reconciliation request.
    pub const fn request(&self) -> &ChildReconciliationRequestV1 {
        &self.request
    }
}

/// Takeover classification of the aggregate custody effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyTakeoverStatusV1 {
    /// No child left custody and no call remains ambiguous.
    NothingExternalized {
        /// Store/journal proof commitment.
        evidence_digest: Digest32,
    },
    /// A strict prefix left custody without causing first public exposure in
    /// this aggregate. The route may already have recorded the secret public.
    SafeToResumeCustody(PartialCustodyProgressV1),
    /// First exposure is durable but the aggregate is incomplete. The route
    /// must persist `SecretObserved` and re-fence without closing the action.
    SecretPublicPartial(PartialCustodyProgressV1),
    /// Every required child already left custody.
    AggregateExternalized(AggregateExternalizationReceiptV1),
    /// A pending call or contradictory evidence prevents safe classification.
    Unknown {
        /// Nonzero current progress/ambiguity commitment.
        evidence_digest: Digest32,
    },
}

/// Chain-observation request for one externalized child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildObservationRequestV1 {
    /// Stable plan identity.
    pub plan_id: Digest32,
    /// Current canonical plan digest.
    pub plan_digest: Digest32,
    /// Composed route that owns the observed child.
    pub route_id: Digest32,
    /// Exact route effect represented by this plan version.
    pub effect_id: Digest32,
    /// Frozen single-settlement identity.
    pub settlement_id: Digest32,
    /// Position of the settlement in the composed route.
    pub leg: SettlementLegV1,
    /// Economic action whose transaction is being observed.
    pub action: SettlementActionV1,
    /// Route semantic retry commitment.
    pub semantic_digest: Digest32,
    /// Current route fencing generation.
    pub route_fencing_epoch: u64,
    /// Frozen settlement terms commitment.
    pub terms_digest: Digest32,
    /// Authenticated deployment-registry commitment.
    pub registry_digest: Digest32,
    /// Authenticated profile of the child chain.
    pub profile_digest: Digest32,
    /// Authenticated deployment of the child face.
    pub deployment_digest: Digest32,
    /// Child index.
    pub child_index: u8,
    /// Child face.
    pub face: SettlementFaceV1,
    /// Route-secret role of this exact child.
    pub exposure: ChildExposureV1,
    /// Authenticated chain identity.
    pub chain_id: Digest32,
    /// Exact externalized transaction identity.
    pub transaction_id: Digest32,
    /// Commitment to the exact child transaction semantics.
    pub intent_digest: Digest32,
    /// Durable actuator operation/descriptor locator. Production ports must
    /// require this to equal their preinstalled operation identity.
    pub custody_digest: Digest32,
    /// Current active finality evidence, if this is a reorg/re-finality poll.
    pub prior_finality_evidence_digest: Option<Digest32>,
    /// Deterministic observation idempotency identity.
    pub observation_attempt_id: Digest32,
}

/// Verified child observation returned by a chain-specific observer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildObservationOutcomeV1 {
    /// Exact child has not reached finality yet.
    Pending {
        /// Nonzero observation evidence commitment.
        evidence_digest: Digest32,
    },
    /// Exact child reached authenticated finality.
    Final {
        /// Nonzero canonical/finality evidence commitment.
        evidence_digest: Digest32,
    },
    /// A previously final child is no longer canonical/final.
    FinalityInvalidated {
        /// Must equal the active prior finality evidence in the request.
        prior_finality_evidence_digest: Digest32,
        /// Nonzero reorg evidence commitment.
        reorg_evidence_digest: Digest32,
    },
}

/// Narrow chain observer for one exact child transaction.
pub trait SettlementChildObserverV1 {
    /// Verify pending/final/reorg state without returning raw evidence bytes.
    fn observe_child(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> core::result::Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1>;
}

/// Aggregate finality proof emitted only when both children are final.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateFinalityV1 {
    /// Stable plan identity.
    pub plan_id: Digest32,
    /// Synthetic aggregate action identity.
    pub aggregate_action_id: Digest32,
    /// Commitment to both active child finality proofs.
    pub evidence_digest: Digest32,
}

/// Aggregate reorg proof emitted when any prior child finality is invalidated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateReorgV1 {
    /// Stable plan identity.
    pub plan_id: Digest32,
    /// Synthetic aggregate action identity.
    pub aggregate_action_id: Digest32,
    /// Commitment to the invalidated aggregate and child reorg proof.
    pub evidence_digest: Digest32,
}

/// Result of one observer call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorObservationOutcomeV1 {
    /// No aggregate state transition occurred.
    Pending {
        /// Child observation evidence commitment.
        evidence_digest: Digest32,
    },
    /// One child became final but the other has not.
    ChildFinalized {
        /// Child index.
        child_index: u8,
        /// Child finality evidence commitment.
        evidence_digest: Digest32,
    },
    /// Both children are now final.
    AggregateFinal(AggregateFinalityV1),
    /// Prior aggregate finality was invalidated.
    AggregateInvalidated(AggregateReorgV1),
}

pub(crate) fn validate_nonzero_many(values: &[Digest32]) -> Result<()> {
    if values.contains(&ZERO_DIGEST) {
        return Err(CoordinatorErrorV1::InvalidPlan);
    }
    Ok(())
}

#[cfg(test)]
mod capability_surface_tests {
    use static_assertions::assert_not_impl_any;

    use super::{DeferredChildMaterializationCapabilityV1, DeferredChildMaterializationResultV1};

    assert_not_impl_any!(DeferredChildMaterializationCapabilityV1: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(DeferredChildMaterializationResultV1: Clone, Copy, core::fmt::Debug);
}
