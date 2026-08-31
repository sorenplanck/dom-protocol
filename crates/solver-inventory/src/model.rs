use f6_engine::v2::BindingEventV2;
use f6_engine::BindingEventV1;
use rfq::v2::{F6V2Refusal, QuoteV2, RfqV2, SettlementPositionV2};
use rfq::{AssetId, ChainId, ParticipantId};
use solver::BondFactsV1;
use uspe::objects::AssurancePolicyV1;

/// A public 32-byte identifier or evidence commitment.
pub type Digest32 = [u8; 32];

/// Maximum allocations one quote reservation may atomically hold.
pub const MAX_RESERVATION_ALLOCATIONS_V1: usize = 8;

/// One solver-owned inventory account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InventoryKeyV1 {
    /// Frozen chain registry identifier.
    pub chain_id: ChainId,
    /// Frozen asset registry identifier.
    pub asset_id: AssetId,
    /// Participant whose custody authority owns the balance.
    pub authority_id: ParticipantId,
}

/// Why an amount is held by a reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InventoryPurposeV1 {
    /// Asset the solver must deliver to the user.
    SettlementOutput,
    /// Collateral backing the F4/F6 bond reservation.
    BondCollateral,
}

/// How a chain observer relates an observation to the preceding snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InventoryObservationKindV1 {
    /// Canonical forward progress, or a same-anchor balance refresh.
    Forward,
    /// A canonicality change invalidated prior evidence.
    Reorg {
        /// First height invalidated by the reorg.
        invalidated_from_height: u64,
        /// Commitment to the observer's reorg evidence.
        reorg_evidence_digest: Digest32,
    },
}

/// A public, chain-derived view of one inventory account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryObservationV1 {
    /// Account observed.
    pub key: InventoryKeyV1,
    /// Spendable amount proven by this observation.
    pub spendable_amount: u128,
    /// Canonical finalized height or equivalent monotonically interpreted
    /// chain position.
    pub canonical_height: u64,
    /// Canonical anchor/block commitment at `canonical_height`.
    pub canonical_anchor_digest: Digest32,
    /// Commitment to the exact evidence checked by the observer.
    pub evidence_digest: Digest32,
    /// Authenticated deployment-registry manifest used by the observer.
    pub registry_manifest_digest: Digest32,
    /// Authenticated chain-profile bundle used by the observer.
    pub profile_bundle_digest: Digest32,
    /// Authenticated binding for this exact chain/asset.
    pub asset_binding_digest: Digest32,
    /// Time at which the observation was produced.
    pub observed_at_unix_ms: u64,
    /// Absolute time after which new quote authority may not rely on it.
    pub valid_until_unix_ms: u64,
    /// Highest per-account consumption sequence whose spend is reflected in
    /// `spendable_amount` and committed by `evidence_digest`.
    pub acknowledged_consumption_sequence: u64,
    /// Forward progress or an explicit reorg.
    pub kind: InventoryObservationKindV1,
}

/// Persisted, reconciled inventory snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventorySnapshotV1 {
    /// Account represented by the snapshot.
    pub key: InventoryKeyV1,
    /// CAS revision, starting at one.
    pub revision: u64,
    /// Spendable amount reported by the authoritative observer.
    pub spendable_amount: u128,
    /// Amount currently encumbered by reservations or unacknowledged spends.
    pub encumbered_amount: u128,
    /// `encumbered_amount - spendable_amount`, or zero.
    pub deficit_amount: u128,
    /// Canonical height of the evidence.
    pub canonical_height: u64,
    /// Canonical anchor commitment.
    pub canonical_anchor_digest: Digest32,
    /// Exact evidence commitment.
    pub evidence_digest: Digest32,
    /// Registry manifest commitment.
    pub registry_manifest_digest: Digest32,
    /// Profile bundle commitment.
    pub profile_bundle_digest: Digest32,
    /// Exact asset binding commitment.
    pub asset_binding_digest: Digest32,
    /// Observation time.
    pub observed_at_unix_ms: u64,
    /// Staleness cutoff.
    pub valid_until_unix_ms: u64,
    /// Highest issued consumption sequence.
    pub issued_consumption_sequence: u64,
    /// Highest consumption sequence explicitly reflected by the observer.
    pub acknowledged_consumption_sequence: u64,
}

impl InventorySnapshotV1 {
    /// Reference a snapshot without copying its mutable balance totals.
    pub fn reference(&self) -> InventorySnapshotRefV1 {
        InventorySnapshotRefV1 {
            key: self.key,
            revision: self.revision,
            canonical_height: self.canonical_height,
            evidence_digest: self.evidence_digest,
            asset_binding_digest: self.asset_binding_digest,
        }
    }

    /// Whether the snapshot is usable for issuing new quote authority.
    pub fn is_fresh_and_solvent(&self, now_unix_ms: u64) -> bool {
        now_unix_ms <= self.valid_until_unix_ms && self.deficit_amount == 0
    }
}

/// Immutable version reference supplied with one allocation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InventorySnapshotRefV1 {
    /// Account to reserve.
    pub key: InventoryKeyV1,
    /// Exact snapshot CAS revision used for the decision.
    pub revision: u64,
    /// Height carried by that revision.
    pub canonical_height: u64,
    /// Evidence digest carried by that revision.
    pub evidence_digest: Digest32,
    /// Asset binding carried by that revision.
    pub asset_binding_digest: Digest32,
}

/// One amount requested from a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryAllocationRequestV1 {
    /// Snapshot being relied upon.
    pub snapshot: InventorySnapshotRefV1,
    /// Settlement output or bond collateral.
    pub purpose: InventoryPurposeV1,
    /// Amount in the asset's smallest unit.
    pub amount: u128,
}

/// Exact authenticated F4 policy facts required to allocate bond inventory.
///
/// Fields are private so reservation code cannot substitute an arbitrary
/// chain, asset, unit binding or amount after the canonical policy hash was
/// checked. The value carries public commitments only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BondInventoryPolicyCapabilityV1 {
    pub(crate) policy_hash: Digest32,
    pub(crate) policy_version: u32,
    pub(crate) bond_key: InventoryKeyV1,
    pub(crate) bond_asset_binding_digest: Digest32,
    pub(crate) required_collateral: u128,
}

impl BondInventoryPolicyCapabilityV1 {
    /// Authenticates canonical F4 policy bytes against the route-provided hash
    /// and binds its exact collateral account and registry asset definition.
    pub fn authenticate(
        policy: &AssurancePolicyV1,
        expected_policy_hash: Digest32,
        solver_id: ParticipantId,
        bond_asset_binding_digest: Digest32,
    ) -> Result<Self, BondInventoryPolicyRefusalV1> {
        if expected_policy_hash == [0; 32]
            || solver_id.0 == [0; 32]
            || bond_asset_binding_digest == [0; 32]
            || policy.bond_chain_id.0 == [0; 32]
            || policy.bond_asset.0 == [0; 32]
            || policy
                .policy_hash()
                .map_err(|_| BondInventoryPolicyRefusalV1)?
                != expected_policy_hash
        {
            return Err(BondInventoryPolicyRefusalV1);
        }
        Ok(Self {
            policy_hash: expected_policy_hash,
            policy_version: policy.version,
            bond_key: InventoryKeyV1 {
                chain_id: policy.bond_chain_id,
                asset_id: policy.bond_asset,
                authority_id: solver_id,
            },
            bond_asset_binding_digest,
            required_collateral: policy.required_collateral,
        })
    }

    /// Canonical F4 policy commitment.
    pub const fn policy_hash(&self) -> Digest32 {
        self.policy_hash
    }

    /// Exact policy structure version carried by the quote.
    pub const fn policy_version(&self) -> u32 {
        self.policy_version
    }

    /// Exact solver-owned chain and asset account allowed for collateral.
    pub const fn bond_key(&self) -> InventoryKeyV1 {
        self.bond_key
    }

    /// Registry commitment that includes the collateral asset's unit/decimals.
    pub const fn bond_asset_binding_digest(&self) -> Digest32 {
        self.bond_asset_binding_digest
    }

    /// Required collateral in the exact bound asset's smallest unit.
    pub const fn required_collateral(&self) -> u128 {
        self.required_collateral
    }
}

/// Canonical assurance policy could not be bound to the supplied authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid bond inventory policy authority")]
pub struct BondInventoryPolicyRefusalV1;

/// Inputs that bind an inventory reservation to a signed F6 quote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveQuoteRequestV1 {
    /// One-shot identifier. It must equal the quote's F6 bond reservation id.
    pub reservation_id: Digest32,
    /// Route-executor route identifier.
    pub route_id: Digest32,
    /// Frozen pre-acceptance terms/context commitment.
    pub terms_context_digest: Digest32,
    /// Authenticated registry manifest commitment.
    pub registry_manifest_digest: Digest32,
    /// Authenticated profile bundle commitment.
    pub profile_bundle_digest: Digest32,
    /// Canonical F4 policy and exact collateral asset authority.
    pub bond_policy: BondInventoryPolicyCapabilityV1,
    /// Local reservation expiry in UNIX milliseconds.
    pub expires_at_unix_ms: u64,
    /// Canonically ordered exclusive allocations.
    pub allocations: Vec<InventoryAllocationRequestV1>,
}

/// Authenticated V2 reservation request. Composition scope is derived from
/// the exact RFQ and quote; callers cannot provide a duplicate digest/position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveQuoteRequestV2 {
    pub(crate) base: ReserveQuoteRequestV1,
    pub(crate) composition_id: Digest32,
    pub(crate) position: SettlementPositionV2,
}

impl ReserveQuoteRequestV2 {
    /// Binds the existing inventory request material to one exact V2 RFQ and
    /// quote. All deeper balance/policy checks remain inside the durable store.
    pub fn authenticate(
        base: ReserveQuoteRequestV1,
        rfq: &RfqV2,
        quote: &QuoteV2,
    ) -> Result<Self, F6V2Refusal> {
        rfq.validate()?;
        quote.validate()?;
        if quote.rfq_id != rfq.rfq_id
            || quote.route != rfq.route
            || quote.bond_reservation_id != base.reservation_id
        {
            return Err(F6V2Refusal::BindingMismatch);
        }
        Ok(Self {
            base,
            composition_id: rfq.route.composition_id,
            position: rfq.route.position,
        })
    }

    /// Exact route-executor route pinned by the inventory request.
    pub fn route_id(&self) -> Digest32 {
        self.base.route_id
    }

    /// Frozen terms-context commitment.
    pub fn terms_context_digest(&self) -> Digest32 {
        self.base.terms_context_digest
    }

    /// Authenticated deployment-registry commitment.
    pub fn registry_manifest_digest(&self) -> Digest32 {
        self.base.registry_manifest_digest
    }

    /// Authenticated production-profile bundle commitment.
    pub fn profile_bundle_digest(&self) -> Digest32 {
        self.base.profile_bundle_digest
    }

    /// Exact exclusive reservation identifier.
    pub fn reservation_id(&self) -> Digest32 {
        self.base.reservation_id
    }

    /// Canonical F4 assurance-policy commitment.
    pub fn bond_policy_hash(&self) -> Digest32 {
        self.base.bond_policy.policy_hash
    }

    /// Registry commitment for the exact collateral asset definition.
    pub fn bond_asset_binding_digest(&self) -> Digest32 {
        self.base.bond_policy.bond_asset_binding_digest
    }
}

/// Allocation embedded in a capability issued by the durable authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryAllocationCapabilityV1 {
    /// Account holding the amount.
    pub key: InventoryKeyV1,
    /// Settlement output or bond collateral.
    pub purpose: InventoryPurposeV1,
    /// Exclusively reserved amount.
    pub amount: u128,
    /// Snapshot that authorized the reservation.
    pub reserved_snapshot: InventorySnapshotRefV1,
}

/// Capability proving that a quote has exclusive, observed own inventory.
///
/// Fields are private so only a successful durable reservation can construct
/// this value. It contains public commitments only, never a credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteInventoryCapabilityV1 {
    pub(crate) reservation_id: Digest32,
    pub(crate) route_id: Digest32,
    pub(crate) rfq_id: Digest32,
    pub(crate) quote_id: Digest32,
    pub(crate) solver_id: ParticipantId,
    pub(crate) terms_context_digest: Digest32,
    pub(crate) registry_manifest_digest: Digest32,
    pub(crate) profile_bundle_digest: Digest32,
    pub(crate) bond_policy_hash: Digest32,
    pub(crate) bond_policy_version: u32,
    pub(crate) bond_key: InventoryKeyV1,
    pub(crate) bond_asset_binding_digest: Digest32,
    pub(crate) required_bond_amount: u128,
    pub(crate) expires_at_unix_ms: u64,
    pub(crate) reservation_revision: u64,
    pub(crate) reservation_digest: Digest32,
    pub(crate) allocations: Vec<InventoryAllocationCapabilityV1>,
}

impl QuoteInventoryCapabilityV1 {
    /// One-shot reservation identifier.
    pub fn reservation_id(&self) -> Digest32 {
        self.reservation_id
    }

    /// Route bound to the inventory.
    pub fn route_id(&self) -> Digest32 {
        self.route_id
    }

    /// RFQ bound to the inventory.
    pub fn rfq_id(&self) -> Digest32 {
        self.rfq_id
    }

    /// Signed quote bound to the inventory.
    pub fn quote_id(&self) -> Digest32 {
        self.quote_id
    }

    /// Solver/custody authority owning the inventory.
    pub fn solver_id(&self) -> ParticipantId {
        self.solver_id
    }

    /// Frozen pre-acceptance terms context.
    pub fn terms_context_digest(&self) -> Digest32 {
        self.terms_context_digest
    }

    /// Registry manifest commitment used by every allocation.
    pub fn registry_manifest_digest(&self) -> Digest32 {
        self.registry_manifest_digest
    }

    /// Profile bundle commitment used by every allocation.
    pub fn profile_bundle_digest(&self) -> Digest32 {
        self.profile_bundle_digest
    }

    /// Canonical F4 assurance policy commitment.
    pub fn bond_policy_hash(&self) -> Digest32 {
        self.bond_policy_hash
    }

    /// Bond policy version carried by the F6 quote.
    pub fn bond_policy_version(&self) -> u32 {
        self.bond_policy_version
    }

    /// Exact collateral chain, asset and solver authority.
    pub fn bond_key(&self) -> InventoryKeyV1 {
        self.bond_key
    }

    /// Registry commitment including collateral unit/decimals.
    pub fn bond_asset_binding_digest(&self) -> Digest32 {
        self.bond_asset_binding_digest
    }

    /// Minimum collateral proven reserved.
    pub fn required_bond_amount(&self) -> u128 {
        self.required_bond_amount
    }

    /// Local quote-reservation expiry.
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// Reservation CAS revision at capability issuance.
    pub fn reservation_revision(&self) -> u64 {
        self.reservation_revision
    }

    /// Canonical commitment to the reservation and every allocation.
    pub fn reservation_digest(&self) -> Digest32 {
        self.reservation_digest
    }

    /// Exact allocations backing the quote.
    pub fn allocations(&self) -> &[InventoryAllocationCapabilityV1] {
        &self.allocations
    }

    /// F4 bond facts accepted by the existing reference solver.
    pub fn bond_facts(&self) -> BondFactsV1 {
        BondFactsV1 {
            reservation_id: self.reservation_id,
            policy_version: self.bond_policy_version,
        }
    }

    /// Exact reservation event consumed by the existing F6 binding ledger.
    pub fn f6_reservation_event(&self) -> BindingEventV1 {
        BindingEventV1::Reserved {
            reservation_id: self.reservation_id,
            rfq_id: self.rfq_id,
            quote_id: self.quote_id,
            solver: self.solver_id,
        }
    }
}

/// Move-only proof that one V2 quote has exclusive observed inventory.
pub struct QuoteInventoryCapabilityV2 {
    pub(crate) quote: QuoteInventoryCapabilityV1,
    pub(crate) composition_id: Digest32,
    pub(crate) position: SettlementPositionV2,
}

impl core::fmt::Debug for QuoteInventoryCapabilityV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("QuoteInventoryCapabilityV2([authority redacted])")
    }
}

impl QuoteInventoryCapabilityV2 {
    /// Exact reservation identifier.
    pub fn reservation_id(&self) -> Digest32 {
        self.quote.reservation_id
    }

    /// Exact linked composition.
    pub fn composition_id(&self) -> Digest32 {
        self.composition_id
    }

    /// Exact settlement position.
    pub fn position(&self) -> SettlementPositionV2 {
        self.position
    }

    /// Exact RFQ identifier.
    pub fn rfq_id(&self) -> Digest32 {
        self.quote.rfq_id
    }

    /// Exact signed quote identifier.
    pub fn quote_id(&self) -> Digest32 {
        self.quote.quote_id
    }

    /// Solver owning the observed inventory.
    pub fn solver_id(&self) -> ParticipantId {
        self.quote.solver_id
    }

    /// Route-executor route bound to this reservation.
    pub fn route_id(&self) -> Digest32 {
        self.quote.route_id
    }

    /// Frozen pre-acceptance terms context.
    pub fn terms_context_digest(&self) -> Digest32 {
        self.quote.terms_context_digest
    }

    /// Exact registry manifest commitment.
    pub fn registry_manifest_digest(&self) -> Digest32 {
        self.quote.registry_manifest_digest
    }

    /// Exact profile bundle commitment.
    pub fn profile_bundle_digest(&self) -> Digest32 {
        self.quote.profile_bundle_digest
    }

    /// Exact F4 assurance policy hash.
    pub fn bond_policy_hash(&self) -> Digest32 {
        self.quote.bond_policy_hash
    }

    /// Exact F4 policy version.
    pub fn bond_policy_version(&self) -> u32 {
        self.quote.bond_policy_version
    }

    /// Exact collateral account.
    pub fn bond_key(&self) -> InventoryKeyV1 {
        self.quote.bond_key
    }

    /// Exact collateral asset profile binding.
    pub fn bond_asset_binding_digest(&self) -> Digest32 {
        self.quote.bond_asset_binding_digest
    }

    /// Minimum collateral proven reserved.
    pub fn required_bond_amount(&self) -> u128 {
        self.quote.required_bond_amount
    }

    /// Reservation expiry in trusted local lease time.
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.quote.expires_at_unix_ms
    }

    /// Exact observed allocations.
    pub fn allocations(&self) -> &[InventoryAllocationCapabilityV1] {
        &self.quote.allocations
    }

    /// Durable reservation revision.
    pub fn reservation_revision(&self) -> u64 {
        self.quote.reservation_revision
    }

    /// Canonical durable reservation commitment.
    pub fn reservation_digest(&self) -> Digest32 {
        self.quote.reservation_digest
    }

    /// Derives the exact V2 ledger event solely from durable capability bytes.
    pub fn f6_reservation_event(&self) -> BindingEventV2 {
        BindingEventV2::Reserved {
            composition_id: self.composition_id,
            position: self.position,
            reservation_id: self.quote.reservation_id,
            rfq_id: self.quote.rfq_id,
            quote_id: self.quote.quote_id,
            solver: self.quote.solver_id,
        }
    }
}

/// Capability for a selected quote whose accepted F6 terms are durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedInventoryCapabilityV1 {
    pub(crate) quote: QuoteInventoryCapabilityV1,
    pub(crate) accepted_terms_digest: Digest32,
    pub(crate) binding_evidence_digest: Digest32,
    pub(crate) execution_fencing_epoch: u64,
    pub(crate) reservation_revision: u64,
    pub(crate) reservation_digest: Digest32,
}

/// Move-only V2 execution authority recovered from one exact committed
/// composition position.
pub struct CommittedInventoryCapabilityV2 {
    pub(crate) quote: QuoteInventoryCapabilityV2,
    pub(crate) accepted_terms_digest: Digest32,
    pub(crate) binding_evidence_digest: Digest32,
    pub(crate) execution_fencing_epoch: u64,
    pub(crate) reservation_revision: u64,
    pub(crate) reservation_digest: Digest32,
}

impl core::fmt::Debug for CommittedInventoryCapabilityV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CommittedInventoryCapabilityV2([authority redacted])")
    }
}

impl CommittedInventoryCapabilityV2 {
    /// Underlying exact V2 quote reservation.
    pub fn quote_capability(&self) -> &QuoteInventoryCapabilityV2 {
        &self.quote
    }

    /// Accepted canonical V2 terms digest.
    pub fn accepted_terms_digest(&self) -> Digest32 {
        self.accepted_terms_digest
    }

    /// Authenticated binding evidence commitment.
    pub fn binding_evidence_digest(&self) -> Digest32 {
        self.binding_evidence_digest
    }

    /// Execution fencing generation.
    pub fn execution_fencing_epoch(&self) -> u64 {
        self.execution_fencing_epoch
    }

    /// Current durable reservation revision.
    pub fn reservation_revision(&self) -> u64 {
        self.reservation_revision
    }

    /// Current canonical reservation digest.
    pub fn reservation_digest(&self) -> Digest32 {
        self.reservation_digest
    }
}

impl CommittedInventoryCapabilityV1 {
    /// Underlying quote inventory proof.
    pub fn quote_capability(&self) -> &QuoteInventoryCapabilityV1 {
        &self.quote
    }

    /// Journal-sourced accepted F6 terms hash.
    pub fn accepted_terms_digest(&self) -> Digest32 {
        self.accepted_terms_digest
    }

    /// Commitment to the F6 binding evidence used at commit.
    pub fn binding_evidence_digest(&self) -> Digest32 {
        self.binding_evidence_digest
    }

    /// Fencing generation an actuator must enforce.
    pub fn execution_fencing_epoch(&self) -> u64 {
        self.execution_fencing_epoch
    }

    /// Current reservation CAS revision.
    pub fn reservation_revision(&self) -> u64 {
        self.reservation_revision
    }

    /// Commitment to the committed reservation state.
    pub fn reservation_digest(&self) -> Digest32 {
        self.reservation_digest
    }
}

/// Lifecycle of an exclusive reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationStateV1 {
    /// Quote may be offered; capacity is held until expiry/release.
    Reserved,
    /// The real F6 journal accepted terms and execution is authorized.
    Committed,
    /// Finalized execution evidence consumed the allocation.
    Consumed,
    /// Capacity was explicitly released or an unselected quote expired.
    Released,
}

/// Read-only public reservation state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationViewV1 {
    /// Reservation identity.
    pub reservation_id: Digest32,
    /// Owning authority.
    pub authority_id: ParticipantId,
    /// Route identity.
    pub route_id: Digest32,
    /// RFQ identity.
    pub rfq_id: Digest32,
    /// Quote identity.
    pub quote_id: Digest32,
    /// Current lifecycle state.
    pub state: ReservationStateV1,
    /// CAS revision.
    pub revision: u64,
    /// Local expiry.
    pub expires_at_unix_ms: u64,
    /// Accepted F6 terms after commit.
    pub accepted_terms_digest: Option<Digest32>,
    /// Current execution fencing generation, if committed.
    pub execution_fencing_epoch: Option<u64>,
    /// Canonical state commitment.
    pub reservation_digest: Digest32,
}

/// Whether a mutation was new or an exact idempotent replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationStatusV1 {
    /// The transaction changed durable state.
    Applied,
    /// The same operation id and exact request commitment was already durable.
    DuplicateSameBytes,
}

/// Minimal durable acknowledgement for a mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MutationOutcomeV1 {
    /// Applied or exact duplicate.
    pub status: MutationStatusV1,
    /// Revision produced by the original operation.
    pub revision: u64,
}

/// A consumed allocation still deducted until an observer explicitly
/// acknowledges its sequence in a newer evidence snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingConsumptionV1 {
    /// Inventory account awaiting reconciliation.
    pub key: InventoryKeyV1,
    /// Reservation that spent the amount.
    pub reservation_id: Digest32,
    /// Public execution identity.
    pub execution_id: Digest32,
    /// Execution evidence commitment.
    pub execution_evidence_digest: Digest32,
    /// Amount pending observer acknowledgement.
    pub amount: u128,
    /// Per-account monotonic consumption sequence.
    pub consumption_sequence: u64,
}

/// Request passed to a participant-owned observer implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryObserverRequestV1 {
    /// Account to observe.
    pub key: InventoryKeyV1,
    /// Current durable snapshot, if this is not the first observation.
    pub current: Option<InventorySnapshotV1>,
    /// Finalized consumptions not yet reflected by the current snapshot.
    pub pending_consumptions: Vec<PendingConsumptionV1>,
}

/// Chain observation boundary. Implementations own RPC credentials and never
/// place them in the inventory store.
pub trait InventoryObserverV1 {
    /// Implementation-specific named error.
    type Error;

    /// Produce one evidence-bound snapshot for the requested account.
    fn observe(
        &mut self,
        request: &InventoryObserverRequestV1,
    ) -> Result<InventoryObservationV1, Self::Error>;
}

/// Public evidence returned by a capability-scoped custody actuator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryExecutionV1 {
    /// Reservation executed.
    pub reservation_id: Digest32,
    /// Fencing epoch the actuator enforced.
    pub execution_fencing_epoch: u64,
    /// Public transaction/execution identity.
    pub execution_id: Digest32,
    /// Commitment to finalized execution evidence.
    pub evidence_digest: Digest32,
    /// Finalized chain height or equivalent evidence position.
    pub finalized_height: u64,
}

/// Exact idempotent mutation boundary shared by durable reservation actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryMutationContextV1 {
    /// Current durable reservation revision expected by the caller.
    pub expected_revision: u64,
    /// One-shot operation identifier whose byte-equivalent replay is allowed.
    pub operation_id: Digest32,
    /// Monotonic operation time in UNIX milliseconds.
    pub now_unix_ms: u64,
}

/// Result of reconciling a previously issued execution capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InventoryReconciliationV1 {
    /// Evidence proves the exact capability was not externalized.
    NotExecuted {
        /// Commitment to non-execution evidence.
        evidence_digest: Digest32,
    },
    /// The exact execution already finalized.
    Executed(InventoryExecutionV1),
    /// External state cannot currently prove either outcome.
    Unknown {
        /// Commitment to the ambiguous observation.
        evidence_digest: Digest32,
    },
}

/// Participant-owned execution boundary. Implementations must be idempotent
/// by reservation digest and enforce the monotonic execution fencing epoch.
pub trait InventoryActuatorV1 {
    /// Implementation-specific named error.
    type Error;

    /// Reconcile before retrying or re-fencing a committed capability.
    fn reconcile(
        &mut self,
        capability: &CommittedInventoryCapabilityV1,
    ) -> Result<InventoryReconciliationV1, Self::Error>;

    /// Execute only the exact committed capability.
    fn execute(
        &mut self,
        capability: &CommittedInventoryCapabilityV1,
    ) -> Result<InventoryExecutionV1, Self::Error>;
}

/// Participant-owned V2 execution boundary. It consumes an exact
/// composition-scoped committed capability.
pub trait InventoryActuatorV2 {
    /// Implementation-specific named error.
    type Error;

    /// Reconcile before retrying or re-fencing a V2 capability.
    fn reconcile(
        &mut self,
        capability: &CommittedInventoryCapabilityV2,
    ) -> Result<InventoryReconciliationV1, Self::Error>;

    /// Execute only the exact committed V2 capability.
    fn execute(
        &mut self,
        capability: &CommittedInventoryCapabilityV2,
    ) -> Result<InventoryExecutionV1, Self::Error>;
}
