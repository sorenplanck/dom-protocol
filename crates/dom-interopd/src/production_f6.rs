//! Production F6 V2 authority for one solver-owned DOM-centred settlement.
//!
//! V1 payloads remain decodable by the protocol crates, but this production
//! boundary accepts only the chain-scoped V2 wire. Every reserve, selection
//! and acceptance re-proves current solver status and RFQ-scoped DOM time;
//! neither capability is cached across an operation.

pub(crate) mod candidate_attestation;
pub(crate) mod terminal_release;
pub(crate) mod terms;

use std::cell::{Cell, Ref, RefCell, RefMut};
use std::collections::BTreeSet;
use std::path::Path;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use btc_crypto::SecpContext;
use deployment_registry::AuthoritySetV1;
use f6_engine::candidate_book::{
    verify_candidate_quote_delivery_v2, BondReservationAttestationRequestV2, CandidateBookErrorV2,
    CandidateBookScopeV2, CandidateBookStoreLogV2, CandidateQuoteDeliveryV2,
    CandidateVerificationAuthoritiesV2, DurableCandidateBookV2,
};
use f6_engine::v2::{BindingEventV2, DurableBindingV2, EngineErrorV2, StoreLogV2};
use kaystra_core::types::{ChainId, Digest32, ParticipantId};
use relay::auth::{verify_roster_signature, RosterRegistryV1};
use relay::SenderRoleV1;
use rfq::selection::CandidateFactsV1;
use rfq::v2::{
    admissibility_v2, select_winner_with_authority_digest_v2, AcceptanceV2, NegotiationClockV2,
    QuoteV2, RefundFaceV2, RfqV2, SelectionV2, SettlementPositionV2, TermsBindingV2,
};
use route_time_anchor::{CurrentPreF6NegotiationTimeV2, DurablePreF6TimeStoreV2};
use route_transport::{
    DurableInboxError, DurablePayloadCommitV1, DurablePayloadDispositionV1, F6PayloadDeliveryV1,
    F6TransportPortV1, RouteWireContextV1,
};
use solver_inventory::{
    CommittedInventoryCapabilityV2, DurableInventoryStoreV1, InventoryLeaseV1,
    InventoryMutationContextV1, InventoryPurposeV1, InventoryStoreErrorV1, MutationOutcomeV1,
    QuoteInventoryCapabilityV2, ReservationStateV1, ReserveQuoteRequestV2,
};
use solver_status::{
    CurrentActiveSignedSolverStatusV1, CurrentActiveSolverStatusV1, DurableSolverStatusStoreV1,
};
use store::{ProductionStoreBindingV1, Store};

const ZERO_DIGEST: Digest32 = [0; 32];
const LOG_BINDING_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-LOG/V2\0";
const RECEIPT_BINDING_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-RECEIPTS/V2\0";
const RECEIPT_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-DELIVERY/V2\0";
const OPERATION_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-OPERATION/V2\0";
const TERMS_CONTEXT_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-TERMS-CONTEXT/V2\0";
const OUTBOUND_QUOTE_RECEIPT_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-OUTBOUND-QUOTE-RECEIPT/V2\0";
const PREPARED_STORE_DOMAIN_V2: &[u8] = b"DOM-INTEROP/INTEROPD/F6-PREPARED-STORE/V2\0";
const RFQ_NAMESPACE: &[u8] = b"interopd-f6-rfq-v2";
const QUOTE_NAMESPACE: &[u8] = b"interopd-f6-quote-v2";
const TERMS_NAMESPACE: &[u8] = b"interopd-f6-terms-v2";
const DELIVERY_NAMESPACE: &[u8] = b"interopd-f6-delivery-v2";
const OUTBOUND_QUOTE_RECEIPT_MAGIC: &[u8; 8] = b"DOMF6OQ2";
const OUTBOUND_QUOTE_RECEIPT_KIND: u16 = 0xF621;
const OUTBOUND_QUOTE_RECEIPT_VERSION: u16 = 2;
const MAX_OUTBOUND_QUOTE_REVISIONS: usize = 256;
const MAX_OUTBOUND_QUOTE_DELIVERY_BYTES: usize = 12_288;
#[expect(
    dead_code,
    reason = "retained surface not yet wired by the stage-7 composition root"
)]
const MAX_F6_INVENTORY_LEASE_DURATION_MS: u64 = 86_400_000;

/// Exact files jointly provisioned for one F6 V2 position.
#[derive(Clone, Copy, Debug)]
pub struct ProductionF6PathsV2<'path> {
    /// Append-only F6 V2 binding journal.
    pub binding_log: &'path Path,
    /// Strict opaque receipt authority.
    pub receipt_store: &'path Path,
    /// Threshold-authenticated remote candidate journal.
    pub candidate_book: &'path Path,
}

/// Stage-11 bindings of the three empty prefixes provisioned before an RFQ
/// fixes this position's final F6 store bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionF6PreparedBindingsV2 {
    binding_log: Digest32,
    receipt_store: Digest32,
    candidate_book: Digest32,
}

impl ProductionF6PreparedBindingsV2 {
    pub(crate) fn new(
        binding_log: Digest32,
        receipt_store: Digest32,
        candidate_book: Digest32,
    ) -> Result<Self, ProductionF6ErrorV2> {
        if [binding_log, receipt_store, candidate_book].contains(&ZERO_DIGEST)
            || binding_log == receipt_store
            || binding_log == candidate_book
            || receipt_store == candidate_book
        {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        Ok(Self {
            binding_log,
            receipt_store,
            candidate_book,
        })
    }

    /// Derives the three distinct Stage-11 prefix bindings from the exact V6+
    /// provisioning identity and authenticated route/composition scope.
    pub(crate) fn derive_stage11(
        provisioning_binding: Digest32,
        route_id: Digest32,
        composition_v2_digest: Digest32,
        position: SettlementPositionV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        if [provisioning_binding, route_id, composition_v2_digest].contains(&ZERO_DIGEST) {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        let derive = |role: u8| {
            digest_parts(&[
                PREPARED_STORE_DOMAIN_V2,
                &provisioning_binding,
                &route_id,
                &composition_v2_digest,
                &[position as u8],
                &[role],
            ])
        };
        Self::new(derive(1)?, derive(2)?, derive(3)?)
    }

    /// Publishes or exactly resumes all three empty prefixes in fixed order.
    /// A caller may invoke this only while the global Stage-11 journal is
    /// `Started`; each member is independently idempotent after a crash.
    pub(crate) fn prepare_stage11(
        self,
        paths: ProductionF6PathsV2<'_>,
    ) -> Result<(), ProductionF6ErrorV2> {
        let binding_log = ProductionStoreBindingV1::new(self.binding_log)
            .map_err(|_| ProductionF6ErrorV2::Binding)?;
        Store::prepare_resume_create_production(paths.binding_log, binding_log)
            .map_err(|_| ProductionF6ErrorV2::Binding)?;
        let receipt_store = ProductionStoreBindingV1::new(self.receipt_store)
            .map_err(|_| ProductionF6ErrorV2::Receipt)?;
        Store::prepare_resume_create_production(paths.receipt_store, receipt_store)
            .map_err(|_| ProductionF6ErrorV2::Receipt)?;
        let candidate_book = ProductionStoreBindingV1::new(self.candidate_book)
            .map_err(|_| ProductionF6ErrorV2::Binding)?;
        Store::prepare_resume_create_production(paths.candidate_book, candidate_book)
            .map_err(|_| ProductionF6ErrorV2::Binding)
    }
}

/// Authenticated registry/profile/economic authority pins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionF6PinsV2 {
    /// Durable inventory store binding.
    pub inventory_binding_digest: Digest32,
    /// Authenticated deployment registry.
    pub registry_digest: Digest32,
    /// Monotonic deployment registry epoch.
    pub registry_epoch: u64,
    /// Complete production profile bundle.
    pub profile_bundle_digest: Digest32,
    /// Exact F4 assurance policy.
    pub bond_policy_hash: Digest32,
    /// Exact collateral asset/unit binding.
    pub bond_asset_binding_digest: Digest32,
    /// Required collateral from the authenticated F4 assurance policy.
    pub required_collateral: u128,
    /// Exact threshold authority set for remote reservation attestations.
    pub bond_attestation_authority_set_digest: Digest32,
    /// Independent threshold set for remote solver operational status.
    pub remote_status_authority_set_digest: Digest32,
    /// Exact solver-status store scope.
    pub solver_status_scope_digest: Digest32,
    /// Exact RFQ-scoped pre-F6 time scope.
    pub pre_f6_time_scope_digest: Digest32,
}

/// Frozen identity of one solver-owned F6 V2 position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionSolverF6BindingV2 {
    wire: RouteWireContextV1,
    rfq_id: Digest32,
    composition_id: Digest32,
    position: SettlementPositionV2,
    initiator: ParticipantId,
    solver: ParticipantId,
    dom_chain_id: ChainId,
    negotiation_clock: NegotiationClockV2,
    pins: ProductionF6PinsV2,
}

impl ProductionSolverF6BindingV2 {
    /// Freezes one authenticated Relay flow and one linked settlement RFQ.
    pub fn new(
        wire: RouteWireContextV1,
        rfq: &RfqV2,
        solver: ParticipantId,
        dom_chain_id: ChainId,
        pins: ProductionF6PinsV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        rfq.validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidBinding)?;
        let value = Self {
            wire,
            rfq_id: rfq.rfq_id,
            composition_id: rfq.route.composition_id,
            position: rfq.route.position,
            initiator: rfq.initiator,
            solver,
            dom_chain_id,
            negotiation_clock: rfq.negotiation_clock,
            pins,
        };
        value.validate()?;
        if rfq.session_id != wire.session_id {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        Ok(value)
    }

    fn validate(self) -> Result<(), ProductionF6ErrorV2> {
        self.negotiation_clock
            .validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidBinding)?;
        if [
            self.wire.network_id,
            self.wire.session_id,
            self.wire.route_id,
            self.wire.roster_snapshot,
            self.rfq_id,
            self.composition_id,
            self.initiator.0,
            self.solver.0,
            self.dom_chain_id.0,
            self.pins.inventory_binding_digest,
            self.pins.registry_digest,
            self.pins.profile_bundle_digest,
            self.pins.bond_policy_hash,
            self.pins.bond_asset_binding_digest,
            self.pins.bond_attestation_authority_set_digest,
            self.pins.remote_status_authority_set_digest,
            self.pins.solver_status_scope_digest,
            self.pins.pre_f6_time_scope_digest,
        ]
        .contains(&ZERO_DIGEST)
            || self.wire.policy_version == 0
            || self.pins.registry_epoch == 0
            || self.pins.required_collateral == 0
            || self.initiator == self.solver
            || self.negotiation_clock.chain_id != self.dom_chain_id
        {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        Ok(())
    }

    /// Reconstructs this exact binding from an authenticated Relay RFQ.
    /// Kept crate-private so activation code can validate a restart delivery
    /// without exposing the frozen production pins as caller-shaped fields.
    pub(crate) fn authenticates_pending_rfq(
        self,
        wire: RouteWireContextV1,
        rfq: &RfqV2,
        solver: ParticipantId,
        dom_chain_id: ChainId,
    ) -> bool {
        Self::new(wire, rfq, solver, dom_chain_id, self.pins)
            .is_ok_and(|reconstructed| reconstructed == self)
    }

    fn authority_digest(self, domain: &[u8]) -> Result<Digest32, ProductionF6ErrorV2> {
        digest_parts(&[
            domain,
            &self.wire.network_id,
            &self.wire.session_id,
            &self.wire.route_id,
            &self.wire.roster_snapshot,
            &self.wire.policy_version.to_be_bytes(),
            &self.rfq_id,
            &self.composition_id,
            &[self.position as u8],
            &self.initiator.0,
            &self.solver.0,
            &self.dom_chain_id.0,
            &self.negotiation_clock.chain_id.0,
            &self.negotiation_clock.profile_digest,
            &self.negotiation_clock.authority_scope,
            &[self.negotiation_clock.kind as u8],
            &self.pins.inventory_binding_digest,
            &self.pins.registry_digest,
            &self.pins.registry_epoch.to_be_bytes(),
            &self.pins.profile_bundle_digest,
            &self.pins.bond_policy_hash,
            &self.pins.bond_asset_binding_digest,
            &self.pins.required_collateral.to_be_bytes(),
            &self.pins.bond_attestation_authority_set_digest,
            &self.pins.remote_status_authority_set_digest,
            &self.pins.solver_status_scope_digest,
            &self.pins.pre_f6_time_scope_digest,
        ])
    }
}

pub(crate) mod source_seal {
    pub trait Sealed {}
}

/// Adapter-owned terms authority. Implementations live inside the production
/// composition crate and must derive faces from real durable chain artifacts.
pub(crate) trait ProductionF6TermsAuthorityV2: source_seal::Sealed {
    fn authenticate_terms(
        &mut self,
        binding: &ProductionSolverF6BindingV2,
        rfq: &RfqV2,
        quote: &QuoteV2,
    ) -> Result<AuthenticatedF6TermsV2, ProductionF6ErrorV2>;
}

/// Route-store terminal authority for inventory release.
pub(crate) trait ProductionF6TerminalAuthorityV2: source_seal::Sealed {
    fn prove_terminal_release(
        &mut self,
        binding: &ProductionSolverF6BindingV2,
        reservation_id: Digest32,
    ) -> Result<TerminalInventoryReleaseV2, ProductionF6ErrorV2>;
}

/// Independent threshold authority that turns a real local reservation and
/// current status capability into a remotely verifiable quote delivery.
pub(crate) trait ProductionF6CandidateAttestationAuthorityV2: source_seal::Sealed {
    fn signed_candidate_history(
        &mut self,
        binding: &ProductionSolverF6BindingV2,
    ) -> Result<Vec<CandidateQuoteDeliveryV2>, ProductionF6ErrorV2>;

    fn attest_local_candidate(
        &mut self,
        binding: &ProductionSolverF6BindingV2,
        quote: &QuoteV2,
        inventory: &QuoteInventoryCapabilityV2,
        status: &CurrentActiveSignedSolverStatusV1,
        trusted_now_seconds: u64,
    ) -> Result<CandidateQuoteDeliveryV2, ProductionF6ErrorV2>;
}

/// Adapter-authenticated refund/payout faces. No public constructor or codec.
pub(crate) struct AuthenticatedF6TermsV2 {
    terms: TermsBindingV2,
    evidence_digest: Digest32,
    evidence_revision: u64,
}

impl AuthenticatedF6TermsV2 {
    /// Builds terms only through the V2 cross-object validator.
    pub(crate) fn from_adapter_faces(
        rfq: &RfqV2,
        quote: &QuoteV2,
        faces: [RefundFaceV2; 2],
        evidence_digest: Digest32,
        evidence_revision: u64,
    ) -> Result<Self, ProductionF6ErrorV2> {
        if evidence_digest == ZERO_DIGEST || evidence_revision == 0 {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        let terms = TermsBindingV2::from_parts(rfq, quote, faces)
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        Ok(Self {
            terms,
            evidence_digest,
            evidence_revision,
        })
    }
}

impl core::fmt::Debug for AuthenticatedF6TermsV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedF6TermsV2([authority redacted])")
    }
}

/// Move-only route-terminal inventory release proof.
pub(crate) struct TerminalInventoryReleaseV2 {
    composition_id: Digest32,
    position: SettlementPositionV2,
    rfq_id: Digest32,
    reservation_id: Digest32,
    evidence_digest: Digest32,
    terminal_revision: u64,
    fencing_epoch: u64,
}

impl core::fmt::Debug for TerminalInventoryReleaseV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("TerminalInventoryReleaseV2([authority redacted])")
    }
}

/// Production sources that cannot be replaced by public boolean/digest input.
pub(crate) struct ProductionF6SourcesV2 {
    terms: Box<dyn ProductionF6TermsAuthorityV2>,
    terminal: Box<dyn ProductionF6TerminalAuthorityV2>,
    candidate_attestation: Box<dyn ProductionF6CandidateAttestationAuthorityV2>,
}

impl ProductionF6SourcesV2 {
    pub(crate) fn new(
        terms: Box<dyn ProductionF6TermsAuthorityV2>,
        terminal: Box<dyn ProductionF6TerminalAuthorityV2>,
        candidate_attestation: Box<dyn ProductionF6CandidateAttestationAuthorityV2>,
    ) -> Self {
        Self {
            terms,
            terminal,
            candidate_attestation,
        }
    }
}

/// Redacted F6 V2 production failures.
#[derive(Debug, thiserror::Error)]
pub enum ProductionF6ErrorV2 {
    /// Immutable route, registry, profile or authority scope mismatch.
    #[error("invalid F6 V2 production binding")]
    InvalidBinding,
    /// Payload is noncanonical, V1, transplanted or out of order.
    #[error("invalid F6 V2 payload")]
    InvalidPayload,
    /// Authenticated sender role cannot perform the transition.
    #[error("F6 V2 sender role refused")]
    WrongRole,
    /// F6 binding journal refused or is inconsistent.
    #[error("F6 V2 binding unavailable or inconsistent")]
    Binding,
    /// Inventory authority refused or is inconsistent.
    #[error("F6 V2 inventory unavailable or inconsistent")]
    Inventory,
    /// Status authority is absent, stale, suspended or inconsistent.
    #[error("F6 V2 solver status unavailable")]
    StatusUnavailable,
    /// The purpose-limited threshold signer set is unavailable.
    #[error("F6 V2 candidate attestation authority unavailable")]
    CandidateAttestationUnavailable,
    /// A signer response, durable intent or signed result was inconsistent.
    #[error("invalid F6 V2 candidate attestation authority response")]
    InvalidCandidateAttestation,
    /// Pre-F6 time authority is absent, stale or inconsistent.
    #[error("F6 V2 negotiation time unavailable")]
    TimeUnavailable,
    /// Adapter-owned refund/payout facts are not durable/authenticated.
    #[error("F6 V2 terms unavailable")]
    TermsUnavailable,
    /// Adapter/store returned malformed or transplanted terms evidence.
    #[error("invalid F6 V2 terms evidence")]
    InvalidTerms,
    /// The route has not yet proven a terminal/no-open-funds disposition.
    #[error("F6 V2 terminal inventory release unavailable")]
    TerminalUnavailable,
    /// Receipt authority refused or is inconsistent.
    #[error("F6 V2 receipt unavailable or inconsistent")]
    Receipt,
    /// Host trusted wall boundary failed.
    #[error("F6 V2 trusted wall unavailable")]
    ClockUnavailable,
}

/// Private physical owner. Only this type exposes the consuming split; the
/// emitted handles cannot be split again.
struct SharedF6PhysicalAuthorityOwnerV2<Authority>(Authority);

/// Move-only view of one physical durable authority.
struct SharedF6PhysicalAuthorityHandleV2<Authority>(Rc<RefCell<Authority>>);

#[derive(Clone, Copy, Debug)]
struct SharedF6BorrowUnavailableV2;

impl<Authority> SharedF6PhysicalAuthorityOwnerV2<Authority> {
    fn new(authority: Authority) -> Self {
        Self(authority)
    }

    fn into_two(
        self,
    ) -> (
        SharedF6PhysicalAuthorityHandleV2<Authority>,
        SharedF6PhysicalAuthorityHandleV2<Authority>,
    ) {
        let authority = Rc::new(RefCell::new(self.0));
        (
            SharedF6PhysicalAuthorityHandleV2(Rc::clone(&authority)),
            SharedF6PhysicalAuthorityHandleV2(authority),
        )
    }
}

impl<Authority> SharedF6PhysicalAuthorityHandleV2<Authority> {
    fn try_borrow(&self) -> Result<Ref<'_, Authority>, SharedF6BorrowUnavailableV2> {
        self.0.try_borrow().map_err(|_| SharedF6BorrowUnavailableV2)
    }

    fn try_borrow_mut(&self) -> Result<RefMut<'_, Authority>, SharedF6BorrowUnavailableV2> {
        self.0
            .try_borrow_mut()
            .map_err(|_| SharedF6BorrowUnavailableV2)
    }

    #[cfg(test)]
    fn same_physical_authority(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }

    #[cfg(test)]
    fn physical_owner_count(&self) -> usize {
        Rc::strong_count(&self.0)
    }
}

/// The sole physical owner of the durable authorities shared by the two F6
/// positions of one DOM-centred composition.
///
/// Consuming this owner is the only production path that can create leg
/// handles. The handles are deliberately move-only: cloning an `Rc` remains
/// an implementation detail and cannot mint another economic authority.
pub(crate) struct ProductionF6SharedAuthorityOwnerV2 {
    inventory: SharedF6PhysicalAuthorityOwnerV2<DurableInventoryStoreV1>,
    upstream_status: DurableSolverStatusStoreV1,
    downstream_status: DurableSolverStatusStoreV1,
    upstream_pre_f6_time: DurablePreF6TimeStoreV2,
    downstream_pre_f6_time: DurablePreF6TimeStoreV2,
    inventory_lease: InventoryLeaseV1,
    inventory_owner_id: Digest32,
    inventory_lease_duration_ms: u64,
}

impl core::fmt::Debug for ProductionF6SharedAuthorityOwnerV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionF6SharedAuthorityOwnerV2([authorities redacted])")
    }
}

/// One non-cloneable, position-bound view of the sole physical F6 stores.
pub(crate) struct ProductionF6LegSharedAuthoritiesV2 {
    inventory: SharedF6PhysicalAuthorityHandleV2<DurableInventoryStoreV1>,
    status: SharedF6PhysicalAuthorityHandleV2<DurableSolverStatusStoreV1>,
    pre_f6_time: ProductionF6LegPreF6TimeAuthorityV2,
    inventory_lease: ProductionF6LegInventoryLeaseV2,
}

/// Move-only position binding for the underlying inventory process lease.
/// The upstream and downstream wrappers are distinct values even though the
/// physical inventory authority is opened and fenced only once.
struct ProductionF6LegInventoryLeaseV2 {
    lease: Rc<Cell<InventoryLeaseV1>>,
    position: SettlementPositionV2,
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    solver: ParticipantId,
    owner_id: Digest32,
    duration_ms: u64,
}

/// Move-only RFQ/position-bound time store. Unlike solver inventory and
/// status, pre-F6 time scope includes the RFQ, so each leg must retain its own
/// exact physical store rather than sharing one cell.
struct ProductionF6LegPreF6TimeAuthorityV2 {
    authority: DurablePreF6TimeStoreV2,
    position: SettlementPositionV2,
}

impl core::fmt::Debug for ProductionF6LegSharedAuthoritiesV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionF6LegSharedAuthoritiesV2([authorities redacted])")
    }
}

impl ProductionF6SharedAuthorityOwnerV2 {
    /// Takes ownership of exactly one physical opening of each durable store.
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
    )]
    pub(crate) fn new(
        inventory: DurableInventoryStoreV1,
        inventory_lease: InventoryLeaseV1,
        inventory_owner_id: Digest32,
        inventory_lease_duration_ms: u64,
        upstream_status: DurableSolverStatusStoreV1,
        downstream_status: DurableSolverStatusStoreV1,
        upstream_pre_f6_time: DurablePreF6TimeStoreV2,
        downstream_pre_f6_time: DurablePreF6TimeStoreV2,
    ) -> Self {
        Self {
            inventory: SharedF6PhysicalAuthorityOwnerV2::new(inventory),
            upstream_status,
            downstream_status,
            upstream_pre_f6_time,
            downstream_pre_f6_time,
            inventory_lease,
            inventory_owner_id,
            inventory_lease_duration_ms,
        }
    }

    /// Consumes the physical owner and emits exactly one upstream and one
    /// downstream handle. Each handle carries its own move-only position
    /// lease wrapper around the single inventory process lease.
    pub(crate) fn into_two_legs(
        self,
    ) -> (
        ProductionF6LegSharedAuthoritiesV2,
        ProductionF6LegSharedAuthoritiesV2,
    ) {
        let (upstream_inventory, downstream_inventory) = self.inventory.into_two();
        let inventory_lease = Rc::new(Cell::new(self.inventory_lease));
        let downstream = ProductionF6LegSharedAuthoritiesV2 {
            inventory: downstream_inventory,
            status: SharedF6PhysicalAuthorityHandleV2(Rc::new(RefCell::new(
                self.downstream_status,
            ))),
            pre_f6_time: ProductionF6LegPreF6TimeAuthorityV2 {
                authority: self.downstream_pre_f6_time,
                position: SettlementPositionV2::Downstream,
            },
            inventory_lease: ProductionF6LegInventoryLeaseV2 {
                lease: Rc::clone(&inventory_lease),
                position: SettlementPositionV2::Downstream,
                solver: self.inventory_lease.authority_id,
                owner_id: self.inventory_owner_id,
                duration_ms: self.inventory_lease_duration_ms,
            },
        };
        let upstream = ProductionF6LegSharedAuthoritiesV2 {
            inventory: upstream_inventory,
            status: SharedF6PhysicalAuthorityHandleV2(Rc::new(RefCell::new(self.upstream_status))),
            pre_f6_time: ProductionF6LegPreF6TimeAuthorityV2 {
                authority: self.upstream_pre_f6_time,
                position: SettlementPositionV2::Upstream,
            },
            inventory_lease: ProductionF6LegInventoryLeaseV2 {
                lease: inventory_lease,
                position: SettlementPositionV2::Upstream,
                solver: self.inventory_lease.authority_id,
                owner_id: self.inventory_owner_id,
                duration_ms: self.inventory_lease_duration_ms,
            },
        };
        (upstream, downstream)
    }
}

impl ProductionF6LegSharedAuthoritiesV2 {
    fn inventory(&self) -> Result<Ref<'_, DurableInventoryStoreV1>, ProductionF6ErrorV2> {
        self.inventory
            .try_borrow()
            .map_err(|_| ProductionF6ErrorV2::Inventory)
    }

    fn inventory_mut(&self) -> Result<RefMut<'_, DurableInventoryStoreV1>, ProductionF6ErrorV2> {
        self.inventory
            .try_borrow_mut()
            .map_err(|_| ProductionF6ErrorV2::Inventory)
    }

    fn status(&self) -> Result<Ref<'_, DurableSolverStatusStoreV1>, ProductionF6ErrorV2> {
        self.status
            .try_borrow()
            .map_err(|_| ProductionF6ErrorV2::StatusUnavailable)
    }

    fn status_mut(&self) -> Result<RefMut<'_, DurableSolverStatusStoreV1>, ProductionF6ErrorV2> {
        self.status
            .try_borrow_mut()
            .map_err(|_| ProductionF6ErrorV2::StatusUnavailable)
    }

    fn pre_f6_time(&self) -> &DurablePreF6TimeStoreV2 {
        &self.pre_f6_time.authority
    }

    fn pre_f6_time_mut(&mut self) -> &mut DurablePreF6TimeStoreV2 {
        &mut self.pre_f6_time.authority
    }

    fn inventory_lease(&self) -> InventoryLeaseV1 {
        self.inventory_lease.lease.get()
    }

    /// Renews only the retained exact solver/owner lease. The runtime cannot
    /// substitute an identity, fencing generation, duration, or wall time.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    fn renew_inventory_lease_at(&self, now_unix_ms: u64) -> Result<(), ProductionF6ErrorV2> {
        let mut inventory = self.inventory_mut()?;
        renew_exact_inventory_lease_at(
            &mut inventory,
            &self.inventory_lease.lease,
            self.inventory_lease.solver,
            self.inventory_lease.owner_id,
            self.inventory_lease.duration_ms,
            now_unix_ms,
        )
    }

    fn position(&self) -> SettlementPositionV2 {
        self.inventory_lease.position
    }

    fn time_position(&self) -> SettlementPositionV2 {
        self.pre_f6_time.position
    }
}

#[expect(
    dead_code,
    reason = "retained surface not yet wired by the stage-7 composition root"
)]
fn renew_exact_inventory_lease_at(
    inventory: &mut DurableInventoryStoreV1,
    retained_lease: &Cell<InventoryLeaseV1>,
    authenticated_solver: ParticipantId,
    owner_id: Digest32,
    duration_ms: u64,
    now_unix_ms: u64,
) -> Result<(), ProductionF6ErrorV2> {
    let current = retained_lease.get();
    if now_unix_ms == 0
        || duration_ms == 0
        || duration_ms > MAX_F6_INVENTORY_LEASE_DURATION_MS
        || authenticated_solver.0 == ZERO_DIGEST
        || owner_id == ZERO_DIGEST
        || current.authority_id != authenticated_solver
        || current.owner_id != owner_id
        || current.fencing_epoch == 0
    {
        return Err(ProductionF6ErrorV2::InvalidBinding);
    }
    let renewed = inventory
        .renew_lease(current, now_unix_ms, duration_ms)
        .map_err(map_inventory)?;
    let expected_until = now_unix_ms
        .checked_add(duration_ms)
        .ok_or(ProductionF6ErrorV2::InvalidBinding)?;
    if renewed.authority_id != current.authority_id
        || renewed.owner_id != current.owner_id
        || renewed.fencing_epoch != current.fencing_epoch
        || renewed.lease_until_unix_ms != expected_until
    {
        return Err(ProductionF6ErrorV2::Inventory);
    }
    retained_lease.set(renewed);
    Ok(())
}

/// Move-only proof that quote bytes are backed by exclusive inventory and a
/// matching durable F6 V2 reservation event.
pub struct ReservedProductionF6QuoteV2 {
    capability: QuoteInventoryCapabilityV2,
    payload: Vec<u8>,
}

/// Move-only, exact production selection authority combining the local
/// inventory capability with every threshold-authenticated remote candidate.
struct ProductionCandidateAuthorityV2 {
    candidates: Vec<(QuoteV2, CandidateFactsV1)>,
    snapshot_digest: Digest32,
}

#[derive(Clone, Copy)]
struct LocalCandidateExpectationV2 {
    required_collateral: u128,
    reserved_collateral: u128,
    reservation_state_digest: Digest32,
    bond_asset_binding_digest: Digest32,
    status_statement_digest: Digest32,
    status_source_evidence_digest: Digest32,
    status_epoch: u64,
    status_observed_at_seconds: u64,
    status_valid_until_seconds: u64,
}

impl core::fmt::Debug for ProductionCandidateAuthorityV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionCandidateAuthorityV2")
            .field("candidate_count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for ReservedProductionF6QuoteV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ReservedProductionF6QuoteV2([authority redacted])")
    }
}

impl ReservedProductionF6QuoteV2 {
    /// Exact reserved quote identifier.
    pub fn quote_id(&self) -> Digest32 {
        self.capability.quote_id()
    }

    /// Canonical outbound V2 quote bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Move-only committed execution authority.
pub struct ProductionF6ExecutionAuthorityV2 {
    /// Inventory capability consumed by the chain-specific actuator boundary.
    pub capability: CommittedInventoryCapabilityV2,
}

impl core::fmt::Debug for ProductionF6ExecutionAuthorityV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionF6ExecutionAuthorityV2([authority redacted])")
    }
}

#[derive(Clone, Copy)]
struct TrustedWallObservationV2 {
    seconds: u64,
    milliseconds: u64,
}

fn observe_trusted_wall() -> Result<TrustedWallObservationV2, ProductionF6ErrorV2> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProductionF6ErrorV2::ClockUnavailable)?;
    let seconds = elapsed.as_secs();
    let milliseconds =
        u64::try_from(elapsed.as_millis()).map_err(|_| ProductionF6ErrorV2::ClockUnavailable)?;
    if seconds == 0 || milliseconds == 0 {
        return Err(ProductionF6ErrorV2::ClockUnavailable);
    }
    Ok(TrustedWallObservationV2 {
        seconds,
        milliseconds,
    })
}

/// Concrete V2 composition authority. Status/time stores and the secp context
/// are retained physically for its whole lifetime.
pub struct ProductionSolverF6AuthorityV2 {
    binding: ProductionSolverF6BindingV2,
    binding_log: DurableBindingV2<StoreLogV2>,
    receipts: Store,
    shared: ProductionF6LegSharedAuthoritiesV2,
    candidate_book: DurableCandidateBookV2<CandidateBookStoreLogV2>,
    bond_attestation_authorities: AuthoritySetV1,
    remote_status_authorities: AuthoritySetV1,
    secp: SecpContext,
    rosters: RosterRegistryV1,
    sources: ProductionF6SourcesV2,
}

impl core::fmt::Debug for ProductionSolverF6AuthorityV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionSolverF6AuthorityV2([authorities redacted])")
    }
}

/// Constructor materials shared by strict create/open/resume paths.
pub(crate) struct ProductionF6AuthoritiesV2 {
    pub shared: ProductionF6LegSharedAuthoritiesV2,
    pub bond_attestation_authorities: AuthoritySetV1,
    pub remote_status_authorities: AuthoritySetV1,
    pub secp: SecpContext,
    pub rosters: RosterRegistryV1,
    pub sources: ProductionF6SourcesV2,
}

#[derive(Clone, Copy)]
enum OpenModeV2 {
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    Create,
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    Open,
    Resume,
    Prepared(ProductionF6PreparedBindingsV2),
}

#[derive(Clone, Copy)]
enum RequiredF6ReceiptV2 {
    Rfq,
    LocalEconomicAuthority,
}

impl ProductionSolverF6AuthorityV2 {
    /// Extends the retained inventory lease using fresh local wall time and
    /// the owner/duration fixed when the authenticated pair factory was built.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn renew_inventory_lease(&mut self) -> Result<(), ProductionF6ErrorV2> {
        let wall = observe_trusted_wall()?;
        self.shared.renew_inventory_lease_at(wall.milliseconds)
    }

    /// Creates both empty local F6 authorities after a global provisioning
    /// journal has durably authorized the step.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) fn create_production(
        paths: ProductionF6PathsV2<'_>,
        binding: ProductionSolverF6BindingV2,
        authorities: ProductionF6AuthoritiesV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        Self::open_with_mode(paths, binding, authorities, OpenModeV2::Create)
    }

    /// Opens two already complete F6 authorities; it never creates/migrates.
    pub(crate) fn open_existing(
        paths: ProductionF6PathsV2<'_>,
        binding: ProductionSolverF6BindingV2,
        authorities: ProductionF6AuthoritiesV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        Self::open_with_mode(paths, binding, authorities, OpenModeV2::Open)
    }

    /// Resumes only a globally journaled pristine creation prefix.
    pub(crate) fn resume_create_production(
        paths: ProductionF6PathsV2<'_>,
        binding: ProductionSolverF6BindingV2,
        authorities: ProductionF6AuthoritiesV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        Self::open_with_mode(paths, binding, authorities, OpenModeV2::Resume)
    }

    /// Opens retained F6 state or completes the exact Stage-11 prefixes after
    /// the authenticated RFQ has fixed the final store bindings.
    pub(crate) fn open_or_resume_prepared_production(
        paths: ProductionF6PathsV2<'_>,
        prepared: ProductionF6PreparedBindingsV2,
        binding: ProductionSolverF6BindingV2,
        authorities: ProductionF6AuthoritiesV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        Self::open_with_mode(paths, binding, authorities, OpenModeV2::Prepared(prepared))
    }

    fn open_with_mode(
        paths: ProductionF6PathsV2<'_>,
        binding: ProductionSolverF6BindingV2,
        authorities: ProductionF6AuthoritiesV2,
        mode: OpenModeV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        binding.validate()?;
        {
            let inventory = authorities.shared.inventory()?;
            validate_inventory(binding, &inventory, authorities.shared.inventory_lease())?;
        }
        validate_roster(binding, &authorities.rosters)?;
        if authorities
            .shared
            .status()?
            .scope_digest()
            .map_err(|_| ProductionF6ErrorV2::StatusUnavailable)?
            != binding.pins.solver_status_scope_digest
        {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        let (pre_f6_scope, pre_f6_clock) = {
            let pre_f6_time = authorities.shared.pre_f6_time();
            (pre_f6_time.scope_digest(), pre_f6_time.negotiation_clock())
        };
        let log_binding = binding.authority_digest(LOG_BINDING_DOMAIN)?;
        let log = after_exact_leg_time_preflight(
            binding,
            authorities.shared.position(),
            authorities.shared.time_position(),
            pre_f6_scope,
            pre_f6_clock,
            || {
                match mode {
                    OpenModeV2::Create => {
                        StoreLogV2::create_production(paths.binding_log, log_binding)
                    }
                    OpenModeV2::Open => StoreLogV2::open_production(paths.binding_log, log_binding),
                    OpenModeV2::Resume => {
                        StoreLogV2::resume_create_production(paths.binding_log, log_binding)
                    }
                    OpenModeV2::Prepared(prepared) => {
                        StoreLogV2::open_or_resume_prepared_production(
                            paths.binding_log,
                            prepared.binding_log,
                            log_binding,
                        )
                    }
                }
                .map_err(|_| ProductionF6ErrorV2::Binding)
            },
        )?;
        let binding_log = DurableBindingV2::open(log).map_err(map_engine)?;
        let receipt_binding =
            ProductionStoreBindingV1::new(binding.authority_digest(RECEIPT_BINDING_DOMAIN)?)
                .map_err(|_| ProductionF6ErrorV2::Receipt)?;
        let receipts = match mode {
            OpenModeV2::Create => Store::create_production(paths.receipt_store, receipt_binding),
            OpenModeV2::Open => Store::open_production(paths.receipt_store, receipt_binding),
            OpenModeV2::Resume => {
                Store::resume_create_production(paths.receipt_store, receipt_binding)
            }
            OpenModeV2::Prepared(prepared) => {
                let preparation = ProductionStoreBindingV1::new(prepared.receipt_store)
                    .map_err(|_| ProductionF6ErrorV2::Receipt)?;
                Store::open_or_resume_prepared_production(
                    paths.receipt_store,
                    preparation,
                    receipt_binding,
                )
            }
        }
        .map_err(|_| ProductionF6ErrorV2::Receipt)?;
        let candidate_scope = candidate_scope(binding);
        let candidate_log = match mode {
            OpenModeV2::Create => {
                CandidateBookStoreLogV2::create_production(paths.candidate_book, candidate_scope)
            }
            OpenModeV2::Open => {
                CandidateBookStoreLogV2::open_production(paths.candidate_book, candidate_scope)
            }
            OpenModeV2::Resume => CandidateBookStoreLogV2::resume_create_production(
                paths.candidate_book,
                candidate_scope,
            ),
            OpenModeV2::Prepared(prepared) => {
                CandidateBookStoreLogV2::open_or_resume_prepared_production(
                    paths.candidate_book,
                    prepared.candidate_book,
                    candidate_scope,
                )
            }
        }
        .map_err(map_candidate)?;
        let candidate_verifiers = CandidateVerificationAuthoritiesV2::new(
            &authorities.bond_attestation_authorities,
            &authorities.remote_status_authorities,
            &authorities.secp,
            &authorities.rosters,
        );
        let candidate_book =
            DurableCandidateBookV2::open(candidate_log, candidate_scope, &candidate_verifiers)
                .map_err(map_candidate)?;
        Ok(Self {
            binding,
            binding_log,
            receipts,
            shared: authorities.shared,
            candidate_book,
            bond_attestation_authorities: authorities.bond_attestation_authorities,
            remote_status_authorities: authorities.remote_status_authorities,
            secp: authorities.secp,
            rosters: authorities.rosters,
            sources: authorities.sources,
        })
    }

    /// Reserves real observed inventory, appends the matching V2 reservation,
    /// and only then releases canonical quote bytes.
    pub fn reserve_quote(
        &mut self,
        operation_id: Digest32,
        quote: QuoteV2,
        request: &ReserveQuoteRequestV2,
    ) -> Result<ReservedProductionF6QuoteV2, ProductionF6ErrorV2> {
        let wall = observe_trusted_wall()?;
        let rfq = self.load_rfq()?;
        let (status_evidence, current) = self.prove_live_authorities(&rfq, wall.seconds)?;
        let status = status_evidence.capability();
        validate_quote_request(self.binding, &rfq, &quote, request)?;
        validate_status(self.binding, status)?;
        validate_time(self.binding, &rfq, &current)?;
        let member = solver_member(self.binding, &self.rosters)?;
        let solver_xonly_key = member.xonly_key;
        let solver_registered = member.role == SenderRoleV1::Solver;
        verify_roster_signature(&solver_xonly_key, &quote.quote_id, &quote.solver_signature)
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        let provisional = candidate_facts(request, true, true, solver_registered)?;
        admissibility_v2(
            &rfq,
            &quote,
            &provisional,
            self.binding.dom_chain_id,
            current.observation(),
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        let rfq_id = self.binding.rfq_id;
        let inventory_lease = self.shared.inventory_lease();
        let receipts = &mut self.receipts;
        let shared = &self.shared;
        persist_quote_intent_before_inventory(receipts, rfq_id, &quote, || {
            shared
                .inventory_mut()?
                .reserve_quote_v2(
                    inventory_lease,
                    operation_id,
                    &quote,
                    request,
                    wall.milliseconds,
                )
                .map_err(map_inventory)
        })?;
        let capability = self
            .shared
            .inventory_mut()?
            .quote_capability_v2(
                self.shared.inventory_lease(),
                quote.bond_reservation_id,
                wall.milliseconds,
            )
            .map_err(map_inventory)?;
        validate_capability(self.binding, &rfq, &quote, &capability)?;
        let actual = facts_from_capability(&capability, solver_registered)?;
        admissibility_v2(
            &rfq,
            &quote,
            &actual,
            self.binding.dom_chain_id,
            current.observation(),
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        if !self.binding_log.ledger().reservation_backs(
            quote.bond_reservation_id,
            self.binding.composition_id,
            self.binding.position,
            self.binding.rfq_id,
            quote.quote_id,
            quote.solver,
        ) {
            self.binding_log
                .apply(&capability.f6_reservation_event())
                .map_err(map_engine)?;
        }
        let delivery = self.sources.candidate_attestation.attest_local_candidate(
            &self.binding,
            &quote,
            &capability,
            &status_evidence,
            wall.seconds,
        )?;
        if delivery.quote() != quote {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        verify_candidate_quote_delivery_v2(
            &delivery,
            candidate_scope(self.binding),
            &self.bond_attestation_authorities,
            &self.remote_status_authorities,
            &self.secp,
            wall.seconds,
        )
        .map_err(map_candidate)?;
        validate_local_candidate_delivery(
            self.binding,
            &quote,
            &delivery,
            local_candidate_expectation(&capability, status)?,
        )?;
        let payload = delivery.canonical_bytes().map_err(map_candidate)?;
        let history = self
            .sources
            .candidate_attestation
            .signed_candidate_history(&self.binding)?;
        validate_signed_candidate_history_head(&history, &payload)?;
        // Every node must select from the same complete authority snapshot.
        // Verify and recover the whole signed chain before materializing any
        // derived receipt. A crash after CandidateBook append is recovered by
        // exact-prefix replay; no expired predecessor is resurrected through
        // normal admission.
        let candidate_book = &mut self.candidate_book;
        let authorities = CandidateVerificationAuthoritiesV2::new(
            &self.bond_attestation_authorities,
            &self.remote_status_authorities,
            &self.secp,
            &self.rosters,
        );
        recover_candidate_history_before_receipts(
            &mut self.receipts,
            self.binding,
            &history,
            || {
                candidate_book
                    .recover_signed_history(&history, &authorities, wall.seconds)
                    .map_err(map_candidate)
            },
        )?;
        Ok(ReservedProductionF6QuoteV2 {
            capability,
            payload,
        })
    }

    /// Recovers execution authority only after F6 and inventory both replay
    /// the exact accepted V2 binding.
    pub fn execution_authority(
        &mut self,
    ) -> Result<ProductionF6ExecutionAuthorityV2, ProductionF6ErrorV2> {
        let wall = observe_trusted_wall()?;
        let quote = self.load_local_quote(wall.milliseconds)?;
        let capability = self
            .shared
            .inventory_mut()?
            .committed_capability_v2(
                self.shared.inventory_lease(),
                quote.bond_reservation_id,
                wall.milliseconds,
            )
            .map_err(map_inventory)?;
        Ok(ProductionF6ExecutionAuthorityV2 { capability })
    }

    /// Releases a reservation only from an opaque route-terminal proof.
    pub fn release_terminal_inventory(
        &mut self,
        operation_id: Digest32,
    ) -> Result<MutationOutcomeV1, ProductionF6ErrorV2> {
        let wall = observe_trusted_wall()?;
        let quote = self.load_local_quote(wall.milliseconds)?;
        let proof = self
            .sources
            .terminal
            .prove_terminal_release(&self.binding, quote.bond_reservation_id)?;
        if proof.composition_id != self.binding.composition_id
            || proof.position != self.binding.position
            || proof.rfq_id != self.binding.rfq_id
            || proof.reservation_id != quote.bond_reservation_id
            || proof.evidence_digest == ZERO_DIGEST
            || proof.terminal_revision == 0
            || proof.fencing_epoch != self.shared.inventory_lease().fencing_epoch
        {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        let view = self
            .shared
            .inventory_mut()?
            .load_reservation(quote.bond_reservation_id)
            .map_err(map_inventory)?;
        let outcome = self
            .shared
            .inventory_mut()?
            .release_reservation(
                self.shared.inventory_lease(),
                view.revision,
                operation_id,
                quote.bond_reservation_id,
                proof.evidence_digest,
                wall.milliseconds,
            )
            .map_err(map_inventory)?;
        self.release_binding_if_active(&quote)?;
        Ok(outcome)
    }

    fn prove_live_authorities(
        &mut self,
        rfq: &RfqV2,
        trusted_now_seconds: u64,
    ) -> Result<
        (
            CurrentActiveSignedSolverStatusV1,
            CurrentPreF6NegotiationTimeV2,
        ),
        ProductionF6ErrorV2,
    > {
        let status = self
            .shared
            .status_mut()?
            .prove_current_active_signed(&self.secp, trusted_now_seconds)
            .map_err(|_| ProductionF6ErrorV2::StatusUnavailable)?;
        let time = self
            .shared
            .pre_f6_time_mut()
            .prove_current_pre_f6_time(&self.secp, trusted_now_seconds)
            .map_err(|_| ProductionF6ErrorV2::TimeUnavailable)?;
        validate_status(self.binding, status.capability())?;
        validate_time(self.binding, rfq, &time)?;
        Ok((status, time))
    }

    fn load_rfq(&self) -> Result<RfqV2, ProductionF6ErrorV2> {
        let bytes = load_required_f6_receipt(
            &self.receipts,
            RFQ_NAMESPACE,
            self.binding.rfq_id,
            RequiredF6ReceiptV2::Rfq,
        )?;
        let rfq = RfqV2::decode(&bytes).map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        validate_rfq(self.binding, &rfq)?;
        Ok(rfq)
    }

    fn load_local_quote(&mut self, now_ms: u64) -> Result<QuoteV2, ProductionF6ErrorV2> {
        let bytes = load_required_f6_receipt(
            &self.receipts,
            QUOTE_NAMESPACE,
            self.binding.rfq_id,
            RequiredF6ReceiptV2::LocalEconomicAuthority,
        )?;
        let quote = QuoteV2::decode(&bytes).map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        let rfq = self.load_rfq()?;
        let view = self
            .shared
            .inventory_mut()?
            .load_reservation(quote.bond_reservation_id)
            .map_err(map_inventory)?;
        match view.state {
            ReservationStateV1::Reserved => {
                let capability = self
                    .shared
                    .inventory_mut()?
                    .quote_capability_v2(
                        self.shared.inventory_lease(),
                        quote.bond_reservation_id,
                        now_ms,
                    )
                    .map_err(map_inventory)?;
                validate_capability(self.binding, &rfq, &quote, &capability)?;
            }
            ReservationStateV1::Committed => {
                let capability = self
                    .shared
                    .inventory_mut()?
                    .committed_capability_v2(
                        self.shared.inventory_lease(),
                        quote.bond_reservation_id,
                        now_ms,
                    )
                    .map_err(map_inventory)?;
                validate_capability(self.binding, &rfq, &quote, capability.quote_capability())?;
            }
            ReservationStateV1::Consumed | ReservationStateV1::Released => {
                return Err(ProductionF6ErrorV2::Inventory);
            }
        }
        Ok(quote)
    }

    fn prove_candidate_authority(
        &mut self,
        rfq: &RfqV2,
        status: &CurrentActiveSolverStatusV1,
        wall: TrustedWallObservationV2,
    ) -> Result<ProductionCandidateAuthorityV2, ProductionF6ErrorV2> {
        let quote = self.load_local_quote(wall.milliseconds)?;
        let view = self
            .shared
            .inventory_mut()?
            .load_reservation(quote.bond_reservation_id)
            .map_err(map_inventory)?;
        let (local_facts, local_expectation) = match view.state {
            ReservationStateV1::Reserved => {
                let capability = self
                    .shared
                    .inventory_mut()?
                    .quote_capability_v2(
                        self.shared.inventory_lease(),
                        quote.bond_reservation_id,
                        wall.milliseconds,
                    )
                    .map_err(map_inventory)?;
                validate_capability(self.binding, rfq, &quote, &capability)?;
                let facts = facts_from_capability(&capability, true)?;
                let expectation = local_candidate_expectation(&capability, status)?;
                (facts, expectation)
            }
            ReservationStateV1::Committed => {
                let capability = self
                    .shared
                    .inventory_mut()?
                    .committed_capability_v2(
                        self.shared.inventory_lease(),
                        quote.bond_reservation_id,
                        wall.milliseconds,
                    )
                    .map_err(map_inventory)?;
                validate_capability(self.binding, rfq, &quote, capability.quote_capability())?;
                let facts = facts_from_capability(capability.quote_capability(), true)?;
                let expectation =
                    local_candidate_expectation(capability.quote_capability(), status)?;
                (facts, expectation)
            }
            ReservationStateV1::Consumed | ReservationStateV1::Released => {
                return Err(ProductionF6ErrorV2::Inventory);
            }
        };
        let local_delivery = self.load_local_candidate_delivery()?;
        if local_delivery.quote() != quote {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        verify_candidate_quote_delivery_v2(
            &local_delivery,
            candidate_scope(self.binding),
            &self.bond_attestation_authorities,
            &self.remote_status_authorities,
            &self.secp,
            wall.seconds,
        )
        .map_err(map_candidate)?;
        validate_local_candidate_delivery(
            self.binding,
            &quote,
            &local_delivery,
            local_expectation,
        )?;
        let global = self
            .candidate_book
            .prove_current_candidates(wall.seconds)
            .map_err(map_candidate)?;
        if global.scope() != candidate_scope(self.binding) || global.inputs_digest() == ZERO_DIGEST
        {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        if global.revision() == 0 {
            return Err(ProductionF6ErrorV2::Inventory);
        }
        let candidates = global.candidates().to_vec();
        let mut quote_ids = BTreeSet::new();
        let mut solvers = BTreeSet::new();
        let mut reservations = BTreeSet::new();
        let mut local_matches = 0usize;
        for (candidate, _) in &candidates {
            if !quote_ids.insert(candidate.quote_id)
                || !solvers.insert(candidate.solver)
                || !reservations.insert(candidate.bond_reservation_id)
            {
                return Err(ProductionF6ErrorV2::InvalidPayload);
            }
            if candidate.quote_id == quote.quote_id {
                local_matches = local_matches
                    .checked_add(1)
                    .ok_or(ProductionF6ErrorV2::InvalidPayload)?;
            }
        }
        let local_book_entry = candidates
            .iter()
            .find(|candidate| candidate.0.quote_id == quote.quote_id)
            .ok_or(ProductionF6ErrorV2::Inventory)?;
        if local_matches != 1 || local_book_entry.0 != quote || local_book_entry.1 != local_facts {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        Ok(ProductionCandidateAuthorityV2 {
            candidates,
            snapshot_digest: global.inputs_digest(),
        })
    }

    fn load_local_candidate_delivery(
        &self,
    ) -> Result<CandidateQuoteDeliveryV2, ProductionF6ErrorV2> {
        read_outbound_quote_receipt_head(&self.receipts, self.binding)?
            .ok_or(ProductionF6ErrorV2::Inventory)
    }

    fn load_or_authenticate_terms(
        &mut self,
        rfq: &RfqV2,
        quote: &QuoteV2,
    ) -> Result<TermsBindingV2, ProductionF6ErrorV2> {
        if let Some(bytes) = self
            .receipts
            .opaque(TERMS_NAMESPACE, &self.binding.rfq_id)
            .map_err(|_| ProductionF6ErrorV2::Receipt)?
        {
            return decode_terms_record(self.binding, quote, &bytes);
        }
        let authenticated = self
            .sources
            .terms
            .authenticate_terms(&self.binding, rfq, quote)?;
        validate_authenticated_terms(self.binding, rfq, quote, &authenticated)?;
        let record = encode_terms_record(self.binding, &authenticated)?;
        self.receipts
            .put_opaque(TERMS_NAMESPACE, &self.binding.rfq_id, &record)
            .map_err(|_| ProductionF6ErrorV2::Receipt)?;
        decode_terms_record(self.binding, quote, &record)
    }

    fn accept_authenticated(
        &mut self,
        delivery: &F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, ProductionF6ErrorV2> {
        let applied = delivery_record(delivery, DurablePayloadDispositionV1::Applied)?;
        let failed = delivery_record(delivery, DurablePayloadDispositionV1::FailedClosed)?;
        if let Some(existing) = self
            .receipts
            .opaque(DELIVERY_NAMESPACE, delivery.envelope_digest())
            .map_err(|_| ProductionF6ErrorV2::Receipt)?
        {
            if existing == applied {
                return durable_commit(&existing, DurablePayloadDispositionV1::Applied, true);
            }
            if existing == failed {
                return durable_commit(&existing, DurablePayloadDispositionV1::FailedClosed, true);
            }
            return Err(ProductionF6ErrorV2::Receipt);
        }
        self.apply_delivery(delivery)?;
        self.receipts
            .put_opaque(DELIVERY_NAMESPACE, delivery.envelope_digest(), &applied)
            .map_err(|_| ProductionF6ErrorV2::Receipt)?;
        durable_commit(&applied, DurablePayloadDispositionV1::Applied, false)
    }

    fn apply_delivery(
        &mut self,
        delivery: &F6PayloadDeliveryV1<'_>,
    ) -> Result<(), ProductionF6ErrorV2> {
        use relay::auth::message_type;
        match delivery.message_type() {
            message_type::RFQ => {
                if delivery.sender_id() != self.binding.initiator {
                    return Err(ProductionF6ErrorV2::WrongRole);
                }
                let rfq = RfqV2::decode(delivery.payload())
                    .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
                validate_rfq(self.binding, &rfq)?;
                self.receipts
                    .put_opaque(RFQ_NAMESPACE, &self.binding.rfq_id, delivery.payload())
                    .map_err(|_| ProductionF6ErrorV2::Receipt)?;
                Ok(())
            }
            message_type::QUOTE => {
                if self
                    .binding_log
                    .ledger()
                    .selection(
                        self.binding.composition_id,
                        self.binding.position,
                        self.binding.rfq_id,
                    )
                    .is_some()
                {
                    return Err(ProductionF6ErrorV2::InvalidPayload);
                }
                let rfq = self.load_rfq()?;
                let wall = observe_trusted_wall()?;
                let (_, current) = self.prove_live_authorities(&rfq, wall.seconds)?;
                let candidate =
                    CandidateQuoteDeliveryV2::decode(delivery.payload()).map_err(map_candidate)?;
                let quote = candidate.quote();
                if delivery.sender_id() != quote.solver || quote.solver == self.binding.solver {
                    return Err(ProductionF6ErrorV2::WrongRole);
                }
                // CandidateBook scope authenticates composition/position/RFQ,
                // but production must also reject a foreign route/economics
                // before it consumes durable book capacity. Verify the exact
                // delivery first, then derive facts only from that verified
                // attestation and apply the complete RFQ admissibility rule.
                verify_candidate_quote_delivery_v2(
                    &candidate,
                    candidate_scope(self.binding),
                    &self.bond_attestation_authorities,
                    &self.remote_status_authorities,
                    &self.secp,
                    wall.seconds,
                )
                .map_err(map_candidate)?;
                let remote_request = candidate
                    .attestation()
                    .attestation()
                    .map_err(map_candidate)?
                    .request();
                let candidate_verifiers = CandidateVerificationAuthoritiesV2::new(
                    &self.bond_attestation_authorities,
                    &self.remote_status_authorities,
                    &self.secp,
                    &self.rosters,
                );
                validate_and_admit_remote_candidate(
                    &rfq,
                    &quote,
                    remote_request,
                    self.binding.dom_chain_id,
                    current.observation(),
                    || {
                        self.candidate_book
                            .admit_remote(&candidate, &candidate_verifiers, wall.seconds)
                            .map_err(map_candidate)
                    },
                )?;
                Ok(())
            }
            message_type::SELECTION => self.accept_selection(delivery),
            message_type::ACCEPTANCE => self.accept_acceptance(delivery),
            _ => Err(ProductionF6ErrorV2::InvalidPayload),
        }
    }

    fn accept_selection(
        &mut self,
        delivery: &F6PayloadDeliveryV1<'_>,
    ) -> Result<(), ProductionF6ErrorV2> {
        if delivery.sender_id() != self.binding.initiator {
            return Err(ProductionF6ErrorV2::WrongRole);
        }
        let wall = observe_trusted_wall()?;
        let rfq = self.load_rfq()?;
        let (status_evidence, current) = self.prove_live_authorities(&rfq, wall.seconds)?;
        let candidates =
            self.prove_candidate_authority(&rfq, status_evidence.capability(), wall)?;
        let selection = SelectionV2::decode(delivery.payload())
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        let quote_ids: Vec<Digest32> = candidates
            .candidates
            .iter()
            .map(|candidate| candidate.0.quote_id)
            .collect();
        selection
            .validate_against_authority_snapshot(&rfq, &quote_ids, candidates.snapshot_digest)
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        let expected = select_winner_with_authority_digest_v2(
            &rfq,
            &candidates.candidates,
            self.binding.dom_chain_id,
            current.observation(),
            candidates.snapshot_digest,
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        if expected.selection != selection {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        match self.binding_log.ledger().selection(
            self.binding.composition_id,
            self.binding.position,
            self.binding.rfq_id,
        ) {
            Some(existing)
                if existing.winning_quote == selection.winning_quote
                    && existing.inputs_digest == selection.inputs_digest =>
            {
                Ok(())
            }
            Some(_) => Err(ProductionF6ErrorV2::Binding),
            None => self
                .binding_log
                .apply(&BindingEventV2::Selected {
                    composition_id: self.binding.composition_id,
                    position: self.binding.position,
                    rfq_id: self.binding.rfq_id,
                    winning_quote: selection.winning_quote,
                    inputs_digest: selection.inputs_digest,
                })
                .map_err(map_engine),
        }
    }

    fn accept_acceptance(
        &mut self,
        delivery: &F6PayloadDeliveryV1<'_>,
    ) -> Result<(), ProductionF6ErrorV2> {
        if delivery.sender_id() != self.binding.initiator {
            return Err(ProductionF6ErrorV2::WrongRole);
        }
        let wall = observe_trusted_wall()?;
        let rfq = self.load_rfq()?;
        let (status_evidence, current) = self.prove_live_authorities(&rfq, wall.seconds)?;
        let quote = self.load_local_quote(wall.milliseconds)?;
        let candidates =
            self.prove_candidate_authority(&rfq, status_evidence.capability(), wall)?;
        let acceptance = AcceptanceV2::decode(delivery.payload())
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        if acceptance.accepted_by != self.binding.initiator {
            return Err(ProductionF6ErrorV2::WrongRole);
        }
        let selected = self
            .binding_log
            .ledger()
            .selection(
                self.binding.composition_id,
                self.binding.position,
                self.binding.rfq_id,
            )
            .ok_or(ProductionF6ErrorV2::Binding)?;
        let expected = select_winner_with_authority_digest_v2(
            &rfq,
            &candidates.candidates,
            self.binding.dom_chain_id,
            current.observation(),
            candidates.snapshot_digest,
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        validate_current_local_selection(
            quote.quote_id,
            candidates.snapshot_digest,
            selected.winning_quote,
            selected.inputs_digest,
            &expected.selection,
        )?;
        // Adapter authentication can consult wallets/chains and persist its
        // own durable evidence. Never invoke that authority for a solver that
        // did not win the exact still-current candidate snapshot.
        let terms = self.load_or_authenticate_terms(&rfq, &quote)?;
        acceptance
            .validate_against(&terms)
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        if self
            .binding_log
            .ledger()
            .binding(
                self.binding.composition_id,
                self.binding.position,
                self.binding.rfq_id,
            )
            .is_none()
        {
            self.binding_log
                .apply(&BindingEventV2::Bound {
                    composition_id: self.binding.composition_id,
                    position: self.binding.position,
                    rfq_id: self.binding.rfq_id,
                    quote_id: quote.quote_id,
                    solver: quote.solver,
                    accepted_by: acceptance.accepted_by,
                    reservation_id: quote.bond_reservation_id,
                    terms_hash: acceptance.terms_hash,
                })
                .map_err(map_engine)?;
        }
        let view = self
            .shared
            .inventory_mut()?
            .load_reservation(quote.bond_reservation_id)
            .map_err(map_inventory)?;
        match view.state {
            ReservationStateV1::Reserved => {
                self.shared
                    .inventory_mut()?
                    .commit_from_f6_v2(
                        self.shared.inventory_lease(),
                        InventoryMutationContextV1 {
                            expected_revision: view.revision,
                            operation_id: operation_digest(
                                b"BIND",
                                *delivery.envelope_digest(),
                                delivery.sequence(),
                            )?,
                            now_unix_ms: wall.milliseconds,
                        },
                        quote.bond_reservation_id,
                        &self.binding_log,
                    )
                    .map_err(map_inventory)?;
            }
            ReservationStateV1::Committed
                if view.accepted_terms_digest == Some(acceptance.terms_hash)
                    && view.execution_fencing_epoch
                        == Some(self.shared.inventory_lease().fencing_epoch) => {}
            _ => return Err(ProductionF6ErrorV2::Inventory),
        }
        Ok(())
    }

    fn release_binding_if_active(&mut self, quote: &QuoteV2) -> Result<(), ProductionF6ErrorV2> {
        if self.binding_log.ledger().reservation_backs(
            quote.bond_reservation_id,
            self.binding.composition_id,
            self.binding.position,
            self.binding.rfq_id,
            quote.quote_id,
            quote.solver,
        ) {
            self.binding_log
                .apply(&BindingEventV2::Released {
                    composition_id: self.binding.composition_id,
                    position: self.binding.position,
                    reservation_id: quote.bond_reservation_id,
                    rfq_id: quote.rfq_id,
                    quote_id: quote.quote_id,
                    solver: quote.solver,
                })
                .map_err(map_engine)?;
        }
        Ok(())
    }

    fn fail_closed_delivery(
        &mut self,
        delivery: &F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, ProductionF6ErrorV2> {
        let record = delivery_record(delivery, DurablePayloadDispositionV1::FailedClosed)?;
        self.receipts
            .put_opaque(DELIVERY_NAMESPACE, delivery.envelope_digest(), &record)
            .map_err(|_| ProductionF6ErrorV2::Receipt)?;
        durable_commit(&record, DurablePayloadDispositionV1::FailedClosed, false)
    }
}

impl F6TransportPortV1 for ProductionSolverF6AuthorityV2 {
    type Error = ProductionF6ErrorV2;

    fn accept_f6(
        &mut self,
        delivery: F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        match self.accept_authenticated(&delivery) {
            Ok(commit) => Ok(commit),
            Err(error) if is_permanent_f6_refusal(&error) => self.fail_closed_delivery(&delivery),
            Err(error) => Err(error),
        }
    }
}

fn is_permanent_f6_refusal(error: &ProductionF6ErrorV2) -> bool {
    matches!(
        error,
        ProductionF6ErrorV2::InvalidBinding
            | ProductionF6ErrorV2::InvalidPayload
            | ProductionF6ErrorV2::InvalidCandidateAttestation
            | ProductionF6ErrorV2::WrongRole
            | ProductionF6ErrorV2::InvalidTerms
    )
}

fn candidate_scope(binding: ProductionSolverF6BindingV2) -> CandidateBookScopeV2 {
    CandidateBookScopeV2 {
        network_id: binding.wire.network_id,
        composition_id: binding.composition_id,
        position: binding.position,
        rfq_id: binding.rfq_id,
        roster_snapshot: binding.wire.roster_snapshot,
        bond_policy_hash: binding.pins.bond_policy_hash,
        registry_digest: binding.pins.registry_digest,
        registry_epoch: binding.pins.registry_epoch,
        bond_asset_binding_digest: binding.pins.bond_asset_binding_digest,
        required_collateral: binding.pins.required_collateral,
        authority_set_digest: binding.pins.bond_attestation_authority_set_digest,
        status_authority_set_digest: binding.pins.remote_status_authority_set_digest,
    }
}

fn validate_inventory(
    binding: ProductionSolverF6BindingV2,
    inventory: &DurableInventoryStoreV1,
    lease: InventoryLeaseV1,
) -> Result<(), ProductionF6ErrorV2> {
    if inventory.binding_digest() != binding.pins.inventory_binding_digest
        || lease.authority_id != binding.solver
        || lease.owner_id == ZERO_DIGEST
        || lease.fencing_epoch == 0
        || lease.lease_until_unix_ms == 0
    {
        return Err(ProductionF6ErrorV2::InvalidBinding);
    }
    Ok(())
}

fn validate_leg_position(
    binding: ProductionSolverF6BindingV2,
    inventory_position: SettlementPositionV2,
    time_position: SettlementPositionV2,
) -> Result<(), ProductionF6ErrorV2> {
    if binding.position != inventory_position || binding.position != time_position {
        return Err(ProductionF6ErrorV2::InvalidBinding);
    }
    Ok(())
}

fn validate_pre_f6_authority(
    binding: ProductionSolverF6BindingV2,
    scope_digest: Digest32,
    negotiation_clock: NegotiationClockV2,
) -> Result<(), ProductionF6ErrorV2> {
    if scope_digest != binding.pins.pre_f6_time_scope_digest
        || negotiation_clock != binding.negotiation_clock
    {
        return Err(ProductionF6ErrorV2::InvalidBinding);
    }
    Ok(())
}

fn after_exact_leg_time_preflight<Output, Effect>(
    binding: ProductionSolverF6BindingV2,
    inventory_position: SettlementPositionV2,
    time_position: SettlementPositionV2,
    time_scope_digest: Digest32,
    negotiation_clock: NegotiationClockV2,
    effect: Effect,
) -> Result<Output, ProductionF6ErrorV2>
where
    Effect: FnOnce() -> Result<Output, ProductionF6ErrorV2>,
{
    validate_leg_position(binding, inventory_position, time_position)?;
    validate_pre_f6_authority(binding, time_scope_digest, negotiation_clock)?;
    effect()
}

fn validate_current_local_selection(
    local_quote_id: Digest32,
    candidate_snapshot_digest: Digest32,
    selected_winner: Digest32,
    selected_inputs_digest: Digest32,
    recomputed: &SelectionV2,
) -> Result<(), ProductionF6ErrorV2> {
    if selected_winner != local_quote_id
        || selected_inputs_digest != candidate_snapshot_digest
        || recomputed.winning_quote != selected_winner
        || recomputed.inputs_digest != selected_inputs_digest
    {
        return Err(ProductionF6ErrorV2::Binding);
    }
    Ok(())
}

fn validate_roster(
    binding: ProductionSolverF6BindingV2,
    rosters: &RosterRegistryV1,
) -> Result<(), ProductionF6ErrorV2> {
    let snapshot = rosters
        .snapshot(&binding.wire.roster_snapshot)
        .ok_or(ProductionF6ErrorV2::InvalidBinding)?;
    let initiator = snapshot
        .member(&binding.initiator)
        .ok_or(ProductionF6ErrorV2::InvalidBinding)?;
    let solver = snapshot
        .member(&binding.solver)
        .ok_or(ProductionF6ErrorV2::InvalidBinding)?;
    if initiator.role != SenderRoleV1::Initiator || solver.role != SenderRoleV1::Solver {
        return Err(ProductionF6ErrorV2::InvalidBinding);
    }
    Ok(())
}

fn solver_member(
    binding: ProductionSolverF6BindingV2,
    rosters: &RosterRegistryV1,
) -> Result<&relay::auth::RosterMemberV1, ProductionF6ErrorV2> {
    rosters
        .snapshot(&binding.wire.roster_snapshot)
        .and_then(|snapshot| snapshot.member(&binding.solver))
        .ok_or(ProductionF6ErrorV2::InvalidBinding)
}

fn validate_rfq(
    binding: ProductionSolverF6BindingV2,
    rfq: &RfqV2,
) -> Result<(), ProductionF6ErrorV2> {
    rfq.validate()
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
    if rfq.rfq_id != binding.rfq_id
        || rfq.route.composition_id != binding.composition_id
        || rfq.route.position != binding.position
        || rfq.initiator != binding.initiator
        || rfq.session_id != binding.wire.session_id
        || rfq.policy_version != binding.wire.policy_version
        || rfq.negotiation_clock != binding.negotiation_clock
    {
        return Err(ProductionF6ErrorV2::InvalidPayload);
    }
    Ok(())
}

fn validate_status(
    binding: ProductionSolverF6BindingV2,
    status: &CurrentActiveSolverStatusV1,
) -> Result<(), ProductionF6ErrorV2> {
    if status.scope_digest() != binding.pins.solver_status_scope_digest
        || status.solver_id() != binding.solver
        || status.statement_digest() == ZERO_DIGEST
        || status.source_evidence_digest() == ZERO_DIGEST
        || status.status_epoch() == 0
        || status.store_revision() == 0
        || status.observed_at_seconds() >= status.valid_until_seconds()
    {
        return Err(ProductionF6ErrorV2::StatusUnavailable);
    }
    Ok(())
}

fn validate_time(
    binding: ProductionSolverF6BindingV2,
    rfq: &RfqV2,
    current: &CurrentPreF6NegotiationTimeV2,
) -> Result<(), ProductionF6ErrorV2> {
    if current.scope_digest() != binding.pins.pre_f6_time_scope_digest
        || current.negotiation_clock() != rfq.negotiation_clock
        || current.evidence_digest() == ZERO_DIGEST
        || current.evidence_sequence() == 0
        || current.store_revision() == 0
        || current.issued_at_seconds() >= current.valid_until_seconds()
        || current.observation().validate().is_err()
    {
        return Err(ProductionF6ErrorV2::TimeUnavailable);
    }
    Ok(())
}

fn validate_quote_request(
    binding: ProductionSolverF6BindingV2,
    rfq: &RfqV2,
    quote: &QuoteV2,
    request: &ReserveQuoteRequestV2,
) -> Result<(), ProductionF6ErrorV2> {
    quote
        .validate()
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
    if quote.rfq_id != binding.rfq_id
        || quote.route != rfq.route
        || quote.solver != binding.solver
        || request.reservation_id() != quote.bond_reservation_id
        || request.route_id() != binding.wire.route_id
        || request.registry_manifest_digest() != binding.pins.registry_digest
        || request.profile_bundle_digest() != binding.pins.profile_bundle_digest
        || request.bond_policy_hash() != binding.pins.bond_policy_hash
        || request.bond_asset_binding_digest() != binding.pins.bond_asset_binding_digest
        || request.terms_context_digest() != terms_context_digest(binding, rfq)?
    {
        return Err(ProductionF6ErrorV2::InvalidBinding);
    }
    Ok(())
}

fn candidate_facts(
    request: &ReserveQuoteRequestV2,
    reserved: bool,
    active: bool,
    registered: bool,
) -> Result<CandidateFactsV1, ProductionF6ErrorV2> {
    if request.bond_policy_hash() == ZERO_DIGEST {
        return Err(ProductionF6ErrorV2::InvalidBinding);
    }
    Ok(CandidateFactsV1 {
        solver_registered: registered,
        signature_valid: true,
        bond_reserved_exclusive: reserved,
        exposure_covered: reserved,
        coverage_excess: 0,
        solver_active: active,
        policy_version_accepted: true,
    })
}

fn validate_authenticated_remote_candidate(
    rfq: &RfqV2,
    quote: &QuoteV2,
    request: BondReservationAttestationRequestV2,
    dom_chain_id: ChainId,
    current: rfq::v2::NegotiationObservationV2,
) -> Result<(), ProductionF6ErrorV2> {
    let facts = CandidateFactsV1 {
        solver_registered: true,
        signature_valid: true,
        bond_reserved_exclusive: true,
        exposure_covered: true,
        coverage_excess: request
            .reserved_collateral
            .checked_sub(request.required_collateral)
            .ok_or(ProductionF6ErrorV2::InvalidPayload)?,
        solver_active: true,
        policy_version_accepted: true,
    };
    admissibility_v2(rfq, quote, &facts, dom_chain_id, current)
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)
}

fn validate_and_admit_remote_candidate<Admit, Outcome>(
    rfq: &RfqV2,
    quote: &QuoteV2,
    request: BondReservationAttestationRequestV2,
    dom_chain_id: ChainId,
    current: rfq::v2::NegotiationObservationV2,
    admit: Admit,
) -> Result<Outcome, ProductionF6ErrorV2>
where
    Admit: FnOnce() -> Result<Outcome, ProductionF6ErrorV2>,
{
    validate_authenticated_remote_candidate(rfq, quote, request, dom_chain_id, current)?;
    admit()
}

fn persist_exact_quote_intent(
    receipts: &mut Store,
    rfq_id: Digest32,
    quote: &QuoteV2,
) -> Result<(), ProductionF6ErrorV2> {
    let bytes = quote
        .canonical_bytes()
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
    if let Some(existing) = receipts
        .opaque(QUOTE_NAMESPACE, &rfq_id)
        .map_err(|_| ProductionF6ErrorV2::Receipt)?
    {
        if existing != bytes {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        return Ok(());
    }
    receipts
        .put_opaque(QUOTE_NAMESPACE, &rfq_id, &bytes)
        .map_err(|_| ProductionF6ErrorV2::Receipt)
}

fn persist_quote_intent_before_inventory<Reserve, Outcome>(
    receipts: &mut Store,
    rfq_id: Digest32,
    quote: &QuoteV2,
    reserve: Reserve,
) -> Result<Outcome, ProductionF6ErrorV2>
where
    Reserve: FnOnce() -> Result<Outcome, ProductionF6ErrorV2>,
{
    persist_exact_quote_intent(receipts, rfq_id, quote)?;
    reserve()
}

fn persist_outbound_quote_receipt(
    receipts: &mut Store,
    binding: ProductionSolverF6BindingV2,
    delivery: &CandidateQuoteDeliveryV2,
) -> Result<(), ProductionF6ErrorV2> {
    let current = read_outbound_quote_receipt_head(receipts, binding)?;
    let delivery_bytes = delivery.canonical_bytes().map_err(map_candidate)?;
    validate_outbound_quote_receipt_scope(binding, delivery)?;
    if let Some(existing) = current.as_ref() {
        let existing_bytes = existing.canonical_bytes().map_err(map_candidate)?;
        if existing_bytes == delivery_bytes {
            return Ok(());
        }
        let old_attestation = existing
            .attestation()
            .attestation()
            .map_err(map_candidate)?;
        let next_attestation = delivery
            .attestation()
            .attestation()
            .map_err(map_candidate)?;
        let previous_digest = old_attestation
            .attestation_digest()
            .map_err(map_candidate)?;
        if delivery.quote() != existing.quote()
            || next_attestation.request().sequence
                != old_attestation
                    .request()
                    .sequence
                    .checked_add(1)
                    .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?
            || next_attestation.request().previous_attestation_digest != previous_digest
        {
            return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
        }
    } else {
        let request = delivery
            .attestation()
            .attestation()
            .map_err(map_candidate)?
            .request();
        if request.sequence != 1 || request.previous_attestation_digest != ZERO_DIGEST {
            return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
        }
    }
    let record = encode_outbound_quote_receipt(binding, delivery)?;
    let expected_physical_sequence = u64::try_from(
        receipts
            .read_journal()
            .map_err(|_| ProductionF6ErrorV2::Receipt)?
            .len(),
    )
    .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?
    .checked_add(1)
    .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let physical_sequence = receipts
        .append_journal(OUTBOUND_QUOTE_RECEIPT_KIND, &record)
        .map_err(|_| ProductionF6ErrorV2::Receipt)?;
    if physical_sequence != expected_physical_sequence {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    Ok(())
}

fn recover_candidate_history_before_receipts<Recover>(
    receipts: &mut Store,
    binding: ProductionSolverF6BindingV2,
    history: &[CandidateQuoteDeliveryV2],
    recover: Recover,
) -> Result<(), ProductionF6ErrorV2>
where
    Recover: FnOnce() -> Result<(), ProductionF6ErrorV2>,
{
    recover()?;
    for historical in history {
        persist_outbound_quote_receipt(receipts, binding, historical)?;
    }
    Ok(())
}

fn validate_signed_candidate_history_head(
    history: &[CandidateQuoteDeliveryV2],
    expected_head: &[u8],
) -> Result<(), ProductionF6ErrorV2> {
    if history.is_empty()
        || history.len() > MAX_OUTBOUND_QUOTE_REVISIONS
        || history
            .last()
            .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?
            .canonical_bytes()
            .map_err(map_candidate)?
            != expected_head
    {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    Ok(())
}

fn read_outbound_quote_receipt_head(
    receipts: &Store,
    binding: ProductionSolverF6BindingV2,
) -> Result<Option<CandidateQuoteDeliveryV2>, ProductionF6ErrorV2> {
    let journal = receipts
        .read_journal()
        .map_err(|_| ProductionF6ErrorV2::Receipt)?;
    if journal.len() > MAX_OUTBOUND_QUOTE_REVISIONS {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let mut head: Option<CandidateQuoteDeliveryV2> = None;
    for (index, record) in journal.iter().enumerate() {
        let expected_physical = u64::try_from(index)
            .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?
            .checked_add(1)
            .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?;
        if record.sequence != expected_physical || record.kind != OUTBOUND_QUOTE_RECEIPT_KIND {
            return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
        }
        let delivery = decode_outbound_quote_receipt(binding, &record.payload)?;
        validate_outbound_quote_receipt_scope(binding, &delivery)?;
        let request = delivery
            .attestation()
            .attestation()
            .map_err(map_candidate)?
            .request();
        match head.as_ref() {
            Some(previous) => {
                let previous_attestation = previous
                    .attestation()
                    .attestation()
                    .map_err(map_candidate)?;
                let previous_digest = previous_attestation
                    .attestation_digest()
                    .map_err(map_candidate)?;
                if delivery.quote() != previous.quote()
                    || request.sequence
                        != previous_attestation
                            .request()
                            .sequence
                            .checked_add(1)
                            .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?
                    || request.previous_attestation_digest != previous_digest
                {
                    return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
                }
            }
            None => {
                if request.sequence != 1 || request.previous_attestation_digest != ZERO_DIGEST {
                    return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
                }
            }
        }
        head = Some(delivery);
    }
    Ok(head)
}

fn validate_outbound_quote_receipt_scope(
    binding: ProductionSolverF6BindingV2,
    delivery: &CandidateQuoteDeliveryV2,
) -> Result<(), ProductionF6ErrorV2> {
    let request = delivery
        .attestation()
        .attestation()
        .map_err(map_candidate)?
        .request();
    if delivery.quote().rfq_id != binding.rfq_id
        || delivery.quote().solver != binding.solver
        || delivery.quote().route.composition_id != binding.composition_id
        || delivery.quote().route.position != binding.position
        || request.network_id != binding.wire.network_id
        || request.rfq_id != binding.rfq_id
        || request.composition_id != binding.composition_id
        || request.position != binding.position
        || request.quote_id != delivery.quote().quote_id
        || request.solver != binding.solver
    {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    Ok(())
}

fn encode_outbound_quote_receipt(
    binding: ProductionSolverF6BindingV2,
    delivery: &CandidateQuoteDeliveryV2,
) -> Result<Vec<u8>, ProductionF6ErrorV2> {
    let delivery = delivery.canonical_bytes().map_err(map_candidate)?;
    if delivery.is_empty() || delivery.len() > MAX_OUTBOUND_QUOTE_DELIVERY_BYTES {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(OUTBOUND_QUOTE_RECEIPT_MAGIC);
    bytes.extend_from_slice(&OUTBOUND_QUOTE_RECEIPT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&binding.authority_digest(OUTBOUND_QUOTE_RECEIPT_DOMAIN)?);
    bytes.extend_from_slice(&binding.rfq_id);
    bytes.extend_from_slice(
        &u32::try_from(delivery.len())
            .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&delivery);
    let digest = digest_parts(&[OUTBOUND_QUOTE_RECEIPT_DOMAIN, &bytes])?;
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn decode_outbound_quote_receipt(
    binding: ProductionSolverF6BindingV2,
    bytes: &[u8],
) -> Result<CandidateQuoteDeliveryV2, ProductionF6ErrorV2> {
    const FIXED_BODY: usize = 8 + 2 + 32 + 32 + 4;
    if bytes.len() < FIXED_BODY + 32
        || bytes.get(..8) != Some(OUTBOUND_QUOTE_RECEIPT_MAGIC.as_slice())
    {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let body_end = bytes
        .len()
        .checked_sub(32)
        .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let body = bytes
        .get(..body_end)
        .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let stored_digest = bytes
        .get(body_end..)
        .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    if stored_digest != digest_parts(&[OUTBOUND_QUOTE_RECEIPT_DOMAIN, body])?.as_slice()
        || bytes.get(8..10) != Some(OUTBOUND_QUOTE_RECEIPT_VERSION.to_be_bytes().as_slice())
        || bytes.get(10..42)
            != Some(
                binding
                    .authority_digest(OUTBOUND_QUOTE_RECEIPT_DOMAIN)?
                    .as_slice(),
            )
        || bytes.get(42..74) != Some(binding.rfq_id.as_slice())
    {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let length = usize::try_from(u32::from_be_bytes(
        bytes
            .get(74..78)
            .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?
            .try_into()
            .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?,
    ))
    .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    if length == 0
        || length > MAX_OUTBOUND_QUOTE_DELIVERY_BYTES
        || FIXED_BODY
            .checked_add(length)
            .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?
            != body_end
    {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let delivery_bytes = bytes
        .get(FIXED_BODY..body_end)
        .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let delivery = CandidateQuoteDeliveryV2::decode(delivery_bytes).map_err(map_candidate)?;
    if encode_outbound_quote_receipt(binding, &delivery)?.as_slice() != bytes {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    Ok(delivery)
}

fn load_required_f6_receipt(
    receipts: &Store,
    namespace: &[u8],
    key: Digest32,
    kind: RequiredF6ReceiptV2,
) -> Result<Vec<u8>, ProductionF6ErrorV2> {
    match receipts
        .opaque(namespace, &key)
        .map_err(|_| ProductionF6ErrorV2::Receipt)?
    {
        Some(bytes) => Ok(bytes),
        None => Err(match kind {
            RequiredF6ReceiptV2::Rfq => ProductionF6ErrorV2::Binding,
            RequiredF6ReceiptV2::LocalEconomicAuthority => ProductionF6ErrorV2::Inventory,
        }),
    }
}

fn facts_from_capability(
    capability: &QuoteInventoryCapabilityV2,
    registered: bool,
) -> Result<CandidateFactsV1, ProductionF6ErrorV2> {
    let bond_total = bond_collateral_total(capability)?;
    let coverage_excess = bond_total
        .checked_sub(capability.required_bond_amount())
        .ok_or(ProductionF6ErrorV2::Inventory)?;
    if capability.bond_policy_hash() == ZERO_DIGEST {
        return Err(ProductionF6ErrorV2::InvalidBinding);
    }
    Ok(CandidateFactsV1 {
        solver_registered: registered,
        signature_valid: true,
        bond_reserved_exclusive: true,
        exposure_covered: true,
        coverage_excess,
        solver_active: true,
        policy_version_accepted: true,
    })
}

fn bond_collateral_total(
    capability: &QuoteInventoryCapabilityV2,
) -> Result<u128, ProductionF6ErrorV2> {
    capability
        .allocations()
        .iter()
        .filter(|allocation| allocation.purpose == InventoryPurposeV1::BondCollateral)
        .try_fold(0u128, |total, allocation| {
            total
                .checked_add(allocation.amount)
                .ok_or(ProductionF6ErrorV2::Inventory)
        })
}

fn local_candidate_expectation(
    capability: &QuoteInventoryCapabilityV2,
    status: &CurrentActiveSolverStatusV1,
) -> Result<LocalCandidateExpectationV2, ProductionF6ErrorV2> {
    Ok(LocalCandidateExpectationV2 {
        required_collateral: capability.required_bond_amount(),
        reserved_collateral: bond_collateral_total(capability)?,
        reservation_state_digest: capability.reservation_digest(),
        bond_asset_binding_digest: capability.bond_asset_binding_digest(),
        status_statement_digest: status.statement_digest(),
        status_source_evidence_digest: status.source_evidence_digest(),
        status_epoch: status.status_epoch(),
        status_observed_at_seconds: status.observed_at_seconds(),
        status_valid_until_seconds: status.valid_until_seconds(),
    })
}

fn validate_local_candidate_delivery(
    binding: ProductionSolverF6BindingV2,
    quote: &QuoteV2,
    delivery: &CandidateQuoteDeliveryV2,
    expected: LocalCandidateExpectationV2,
) -> Result<(), ProductionF6ErrorV2> {
    let attestation = delivery
        .attestation()
        .attestation()
        .map_err(map_candidate)?;
    let request = attestation.request();
    let status = delivery
        .status()
        .statement()
        .map_err(|_| ProductionF6ErrorV2::StatusUnavailable)?;
    let status_digest = status
        .statement_digest()
        .map_err(|_| ProductionF6ErrorV2::StatusUnavailable)?;
    if delivery.quote() != *quote
        || request.quote_id != quote.quote_id
        || request.reservation_id != quote.bond_reservation_id
        || request.solver != binding.solver
        || request.required_collateral != expected.required_collateral
        || request.reserved_collateral != expected.reserved_collateral
        || request.reservation_state_digest != expected.reservation_state_digest
        || request.bond_asset_binding_digest != expected.bond_asset_binding_digest
        || request.bond_asset_binding_digest != binding.pins.bond_asset_binding_digest
        || request.solver_status_statement_digest != expected.status_statement_digest
        || request.solver_status_epoch != expected.status_epoch
        || request.solver_status_valid_until_seconds != expected.status_valid_until_seconds
        || status_digest != expected.status_statement_digest
        || status.source_evidence_digest() != expected.status_source_evidence_digest
        || status.status_epoch() != expected.status_epoch
        || status.observed_at_seconds() != expected.status_observed_at_seconds
        || status.valid_until_seconds() != expected.status_valid_until_seconds
    {
        return Err(ProductionF6ErrorV2::InvalidPayload);
    }
    Ok(())
}

fn validate_capability(
    binding: ProductionSolverF6BindingV2,
    rfq: &RfqV2,
    quote: &QuoteV2,
    capability: &QuoteInventoryCapabilityV2,
) -> Result<(), ProductionF6ErrorV2> {
    if capability.composition_id() != binding.composition_id
        || capability.position() != binding.position
        || capability.route_id() != binding.wire.route_id
        || capability.rfq_id() != rfq.rfq_id
        || capability.quote_id() != quote.quote_id
        || capability.solver_id() != binding.solver
        || capability.reservation_id() != quote.bond_reservation_id
        || capability.registry_manifest_digest() != binding.pins.registry_digest
        || capability.profile_bundle_digest() != binding.pins.profile_bundle_digest
        || capability.bond_policy_hash() != binding.pins.bond_policy_hash
        || capability.bond_asset_binding_digest() != binding.pins.bond_asset_binding_digest
        || capability.reservation_revision() == 0
        || capability.reservation_digest() == ZERO_DIGEST
    {
        return Err(ProductionF6ErrorV2::Inventory);
    }
    Ok(())
}

fn validate_authenticated_terms(
    binding: ProductionSolverF6BindingV2,
    rfq: &RfqV2,
    quote: &QuoteV2,
    authenticated: &AuthenticatedF6TermsV2,
) -> Result<(), ProductionF6ErrorV2> {
    if authenticated.evidence_digest == ZERO_DIGEST || authenticated.evidence_revision == 0 {
        return Err(ProductionF6ErrorV2::InvalidTerms);
    }
    let reconstructed = TermsBindingV2::from_parts(rfq, quote, authenticated.terms.faces)
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
    if reconstructed != authenticated.terms
        || reconstructed.route.composition_id != binding.composition_id
        || reconstructed.route.position != binding.position
    {
        return Err(ProductionF6ErrorV2::InvalidTerms);
    }
    Ok(())
}

fn encode_terms_record(
    binding: ProductionSolverF6BindingV2,
    authenticated: &AuthenticatedF6TermsV2,
) -> Result<Vec<u8>, ProductionF6ErrorV2> {
    let terms = authenticated
        .terms
        .canonical_bytes()
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
    let length = u32::try_from(terms.len()).map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
    let mut record = Vec::with_capacity(4 + terms.len() + 32 + 8 + 32);
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(&terms);
    record.extend_from_slice(&authenticated.evidence_digest);
    record.extend_from_slice(&authenticated.evidence_revision.to_be_bytes());
    let digest = digest_parts(&[&binding.authority_digest(TERMS_CONTEXT_DOMAIN)?, &record])?;
    record.extend_from_slice(&digest);
    Ok(record)
}

fn decode_terms_record(
    binding: ProductionSolverF6BindingV2,
    quote: &QuoteV2,
    record: &[u8],
) -> Result<TermsBindingV2, ProductionF6ErrorV2> {
    let length_bytes: [u8; 4] = record
        .get(..4)
        .ok_or(ProductionF6ErrorV2::InvalidTerms)?
        .try_into()
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
    let terms_end = 4usize
        .checked_add(length)
        .ok_or(ProductionF6ErrorV2::InvalidTerms)?;
    let prefix_end = terms_end
        .checked_add(40)
        .ok_or(ProductionF6ErrorV2::InvalidTerms)?;
    if record.len() != prefix_end + 32 {
        return Err(ProductionF6ErrorV2::InvalidTerms);
    }
    let expected = digest_parts(&[
        &binding.authority_digest(TERMS_CONTEXT_DOMAIN)?,
        record
            .get(..prefix_end)
            .ok_or(ProductionF6ErrorV2::InvalidTerms)?,
    ])?;
    if record.get(prefix_end..) != Some(expected.as_slice())
        || record.get(terms_end..terms_end + 32) == Some(ZERO_DIGEST.as_slice())
    {
        return Err(ProductionF6ErrorV2::InvalidTerms);
    }
    let revision = u64::from_be_bytes(
        record
            .get(terms_end + 32..prefix_end)
            .ok_or(ProductionF6ErrorV2::InvalidTerms)?
            .try_into()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?,
    );
    if revision == 0 {
        return Err(ProductionF6ErrorV2::InvalidTerms);
    }
    let terms = TermsBindingV2::decode(
        record
            .get(4..terms_end)
            .ok_or(ProductionF6ErrorV2::InvalidTerms)?,
    )
    .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
    if terms.quote_id != quote.quote_id
        || terms.rfq_id != binding.rfq_id
        || terms.route.composition_id != binding.composition_id
        || terms.route.position != binding.position
    {
        return Err(ProductionF6ErrorV2::InvalidTerms);
    }
    Ok(terms)
}

fn terms_context_digest(
    binding: ProductionSolverF6BindingV2,
    rfq: &RfqV2,
) -> Result<Digest32, ProductionF6ErrorV2> {
    let rfq_bytes = rfq
        .canonical_bytes()
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
    digest_parts(&[
        TERMS_CONTEXT_DOMAIN,
        &binding.wire.route_id,
        &binding.pins.registry_digest,
        &binding.pins.registry_epoch.to_be_bytes(),
        &binding.pins.profile_bundle_digest,
        &binding.pins.bond_policy_hash,
        &rfq_bytes,
    ])
}

fn delivery_record(
    delivery: &F6PayloadDeliveryV1<'_>,
    disposition: DurablePayloadDispositionV1,
) -> Result<Vec<u8>, ProductionF6ErrorV2> {
    let payload_digest = digest_parts(&[delivery.payload()])?;
    let mut record = Vec::with_capacity(32 * 4 + 8 + 2 + 1);
    record.extend_from_slice(RECEIPT_DOMAIN);
    record.extend_from_slice(&delivery.sender_id().0);
    record.extend_from_slice(&delivery.sequence().to_be_bytes());
    record.extend_from_slice(&delivery.message_type().to_be_bytes());
    record.extend_from_slice(delivery.envelope_digest());
    record.extend_from_slice(&payload_digest);
    record.push(match disposition {
        DurablePayloadDispositionV1::Applied => 1,
        DurablePayloadDispositionV1::FailedClosed => 2,
    });
    let digest = digest_parts(&[&record])?;
    record.extend_from_slice(&digest);
    Ok(record)
}

fn durable_commit(
    record: &[u8],
    disposition: DurablePayloadDispositionV1,
    duplicate: bool,
) -> Result<DurablePayloadCommitV1, ProductionF6ErrorV2> {
    DurablePayloadCommitV1::new(disposition, digest_parts(&[record])?, duplicate).map_err(map_inbox)
}

fn operation_digest(
    tag: &[u8],
    envelope_digest: Digest32,
    sequence: u64,
) -> Result<Digest32, ProductionF6ErrorV2> {
    digest_parts(&[
        OPERATION_DOMAIN,
        tag,
        &envelope_digest,
        &sequence.to_be_bytes(),
    ])
}

fn digest_parts(parts: &[&[u8]]) -> Result<Digest32, ProductionF6ErrorV2> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| ProductionF6ErrorV2::InvalidBinding)?;
    for part in parts {
        let length = u64::try_from(part.len()).map_err(|_| ProductionF6ErrorV2::InvalidBinding)?;
        hasher.update(&length.to_be_bytes());
        hasher.update(part);
    }
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| ProductionF6ErrorV2::InvalidBinding)?;
    Ok(output)
}

fn map_engine(_: EngineErrorV2) -> ProductionF6ErrorV2 {
    ProductionF6ErrorV2::Binding
}

fn map_inventory(_: InventoryStoreErrorV1) -> ProductionF6ErrorV2 {
    ProductionF6ErrorV2::Inventory
}

fn map_candidate(error: CandidateBookErrorV2) -> ProductionF6ErrorV2 {
    match error {
        CandidateBookErrorV2::Storage | CandidateBookErrorV2::Arithmetic => {
            ProductionF6ErrorV2::Binding
        }
        CandidateBookErrorV2::InvalidAttestation
        | CandidateBookErrorV2::NonCanonical
        | CandidateBookErrorV2::InvalidAuthority
        | CandidateBookErrorV2::ThresholdNotMet
        | CandidateBookErrorV2::Stale
        | CandidateBookErrorV2::ScopeMismatch
        | CandidateBookErrorV2::SolverIdentity
        | CandidateBookErrorV2::Equivocation
        | CandidateBookErrorV2::BoundExceeded => ProductionF6ErrorV2::InvalidPayload,
    }
}

fn map_inbox(_: DurableInboxError) -> ProductionF6ErrorV2 {
    ProductionF6ErrorV2::Receipt
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use adapter_btc::timelock::ChainTimingBoundsV1;
    use chain_profile::{ChainKindV1, ChainProfileV1};
    use deployment_registry::{
        AssetBindingV1, AssetRepresentationV1, ChainDeploymentV1, DomDeploymentV1, DomNetworkV1,
        DomRuntimeIdentityV1, EvmDeploymentV1, RegistryChainProfileV1, RegistryManifestV1,
        RegistrySignatureV1, RegistryValidationPolicyV1, ResolvedRegistryV1, SignedRegistryV1,
    };
    use dom_consensus::derive_chain_id;
    use dom_core::configured_genesis_hash_for_network_magic;
    use f6_engine::candidate_book::{
        bond_reservation_authority_set_digest_v2, candidate_status_authority_set_digest_v2,
        BondReservationAttestationRequestV2, BondReservationAttestationV2,
        BondReservationSignatureV2, SignedBondReservationAttestationV2,
    };
    use kaystra_core::types::FinalityPolicyV1;
    use relay::auth::{RosterMemberV1, RosterSnapshotV1};
    use rfq::v2::{
        NativeClockKindV2, NegotiationClockV2, NegotiationInstantV2, QuoteProposalV2, RfqRequestV2,
        RouteV2,
    };
    use rfq::{AssetId, FeeLimitV1, LegDirectionV1, PolicyId, RfqModeV1, RouteLegV1};
    use route_time_anchor::{
        resolved_dom_profile_digest_v1, PreF6TimePolicyLimitsV2, PreF6TimePolicyV2,
        PreF6TimeScopeRequestV2, PreF6TimeScopeV2,
    };
    use solver_status::{
        SignedSolverStatusV1, SolverOperationalStateV1, SolverStatusObservationV1,
        SolverStatusScopeV1, SolverStatusSignatureV1, SolverStatusStatementV1,
    };
    use solver_status::{SolverStatusFreshnessPolicyV1, SolverStatusStoreConfigV1};
    use static_assertions::assert_not_impl_any;

    use super::*;

    assert_not_impl_any!(ReservedProductionF6QuoteV2: Clone, Copy);
    assert_not_impl_any!(ProductionF6ExecutionAuthorityV2: Clone, Copy);
    assert_not_impl_any!(ProductionSolverF6AuthorityV2: Clone, Copy);
    assert_not_impl_any!(ProductionF6SharedAuthorityOwnerV2: Clone, Copy);
    assert_not_impl_any!(ProductionF6LegSharedAuthoritiesV2: Clone, Copy);
    assert_not_impl_any!(ProductionF6LegInventoryLeaseV2: Clone, Copy);
    assert_not_impl_any!(ProductionF6LegPreF6TimeAuthorityV2: Clone, Copy);
    assert_not_impl_any!(SharedF6PhysicalAuthorityOwnerV2<u8>: Clone, Copy);
    assert_not_impl_any!(SharedF6PhysicalAuthorityHandleV2<u8>: Clone, Copy);
    assert_not_impl_any!(AuthenticatedF6TermsV2: Clone, Copy);
    assert_not_impl_any!(TerminalInventoryReleaseV2: Clone, Copy);

    #[test]
    fn stage11_prepared_f6_prefixes_are_exact_replayable_and_position_bound(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let binding_log = directory.path().join("binding.sqlite3");
        let receipt_store = directory.path().join("receipts.sqlite3");
        let candidate_book = directory.path().join("candidates.sqlite3");
        let paths = ProductionF6PathsV2 {
            binding_log: &binding_log,
            receipt_store: &receipt_store,
            candidate_book: &candidate_book,
        };
        let prepared = ProductionF6PreparedBindingsV2::derive_stage11(
            [0xa1; 32],
            [0xb1; 32],
            [0xc1; 32],
            SettlementPositionV2::Upstream,
        )?;
        prepared.prepare_stage11(paths)?;
        prepared.prepare_stage11(paths)?;
        for path in [
            binding_log.as_path(),
            receipt_store.as_path(),
            candidate_book.as_path(),
        ] {
            assert!(
                !path.exists(),
                "Stage11 must not invent a final RFQ-bound database"
            );
            let mut sidecar = path.as_os_str().to_os_string();
            sidecar.push(".prepare");
            assert!(std::path::PathBuf::from(sidecar).is_file());
        }
        let downstream = ProductionF6PreparedBindingsV2::derive_stage11(
            [0xa1; 32],
            [0xb1; 32],
            [0xc1; 32],
            SettlementPositionV2::Downstream,
        )?;
        assert_ne!(prepared, downstream);
        assert!(downstream.prepare_stage11(paths).is_err());
        Ok(())
    }

    struct UnreachableTermsV2;
    struct UnreachableTerminalV2;
    struct UnreachableCandidateAttestationV2;

    impl source_seal::Sealed for UnreachableTermsV2 {}
    impl source_seal::Sealed for UnreachableTerminalV2 {}
    impl source_seal::Sealed for UnreachableCandidateAttestationV2 {}

    impl ProductionF6TermsAuthorityV2 for UnreachableTermsV2 {
        fn authenticate_terms(
            &mut self,
            _binding: &ProductionSolverF6BindingV2,
            _rfq: &RfqV2,
            _quote: &QuoteV2,
        ) -> Result<AuthenticatedF6TermsV2, ProductionF6ErrorV2> {
            Err(ProductionF6ErrorV2::TermsUnavailable)
        }
    }

    impl ProductionF6TerminalAuthorityV2 for UnreachableTerminalV2 {
        fn prove_terminal_release(
            &mut self,
            _binding: &ProductionSolverF6BindingV2,
            _reservation_id: Digest32,
        ) -> Result<TerminalInventoryReleaseV2, ProductionF6ErrorV2> {
            Err(ProductionF6ErrorV2::InvalidBinding)
        }
    }

    impl ProductionF6CandidateAttestationAuthorityV2 for UnreachableCandidateAttestationV2 {
        fn signed_candidate_history(
            &mut self,
            _binding: &ProductionSolverF6BindingV2,
        ) -> Result<Vec<CandidateQuoteDeliveryV2>, ProductionF6ErrorV2> {
            Err(ProductionF6ErrorV2::InvalidPayload)
        }

        fn attest_local_candidate(
            &mut self,
            _binding: &ProductionSolverF6BindingV2,
            _quote: &QuoteV2,
            _inventory: &QuoteInventoryCapabilityV2,
            _status: &CurrentActiveSignedSolverStatusV1,
            _trusted_now_seconds: u64,
        ) -> Result<CandidateQuoteDeliveryV2, ProductionF6ErrorV2> {
            Err(ProductionF6ErrorV2::InvalidPayload)
        }
    }

    fn unreachable_sources() -> ProductionF6SourcesV2 {
        ProductionF6SourcesV2::new(
            Box::new(UnreachableTermsV2),
            Box::new(UnreachableTerminalV2),
            Box::new(UnreachableCandidateAttestationV2),
        )
    }

    #[test]
    fn one_physical_authority_yields_two_move_only_legs_and_busy_borrow_fails_closed(
    ) -> Result<(), &'static str> {
        let physical = SharedF6PhysicalAuthorityOwnerV2::new(7u64);
        let (upstream, downstream) = physical.into_two();
        assert!(upstream.same_physical_authority(&downstream));
        assert_eq!(upstream.physical_owner_count(), 2);
        assert_eq!(downstream.physical_owner_count(), 2);

        let mut upstream_guard = upstream
            .try_borrow_mut()
            .map_err(|_| "first leg must borrow")?;
        *upstream_guard = 9;
        assert!(downstream.try_borrow().is_err());
        assert!(downstream.try_borrow_mut().is_err());
        drop(upstream_guard);

        assert_eq!(
            *downstream
                .try_borrow()
                .map_err(|_| "borrow must be released")?,
            9
        );
        drop(upstream);
        assert_eq!(downstream.physical_owner_count(), 1);
        Ok(())
    }

    #[test]
    fn position_bound_inventory_lease_refuses_cross_leg_transplant() {
        let clock = NegotiationClockV2 {
            chain_id: ChainId([0x31; 32]),
            profile_digest: [0x32; 32],
            authority_scope: [0x33; 32],
            kind: NativeClockKindV2::BlockHeight,
        };
        let upstream_binding = binding_for_test(clock);
        assert_eq!(upstream_binding.position, SettlementPositionV2::Upstream);
        assert!(validate_leg_position(
            upstream_binding,
            SettlementPositionV2::Upstream,
            SettlementPositionV2::Upstream,
        )
        .is_ok());
        assert!(matches!(
            validate_leg_position(
                upstream_binding,
                SettlementPositionV2::Downstream,
                SettlementPositionV2::Upstream,
            ),
            Err(ProductionF6ErrorV2::InvalidBinding)
        ));
        assert!(matches!(
            validate_leg_position(
                upstream_binding,
                SettlementPositionV2::Upstream,
                SettlementPositionV2::Downstream,
            ),
            Err(ProductionF6ErrorV2::InvalidBinding)
        ));

        let raw = InventoryLeaseV1 {
            authority_id: upstream_binding.solver,
            owner_id: [0x34; 32],
            fencing_epoch: 7,
            lease_until_unix_ms: 1_000,
        };
        let shared_lease = Rc::new(Cell::new(raw));
        let upstream_lease = ProductionF6LegInventoryLeaseV2 {
            lease: Rc::clone(&shared_lease),
            position: SettlementPositionV2::Upstream,
            solver: raw.authority_id,
            owner_id: raw.owner_id,
            duration_ms: 1_000,
        };
        let downstream_lease = ProductionF6LegInventoryLeaseV2 {
            lease: shared_lease,
            position: SettlementPositionV2::Downstream,
            solver: raw.authority_id,
            owner_id: raw.owner_id,
            duration_ms: 1_000,
        };
        assert_eq!(upstream_lease.lease.get(), downstream_lease.lease.get());
        assert!(Rc::ptr_eq(&upstream_lease.lease, &downstream_lease.lease));
        assert_ne!(upstream_lease.position, downstream_lease.position);
    }

    #[test]
    fn exact_inventory_lease_renewal_preserves_epoch_and_rejects_identity_substitution(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let binding = [0x35; 32];
        let solver = ParticipantId([0x36; 32]);
        let owner = [0x37; 32];
        let mut inventory =
            DurableInventoryStoreV1::create(&directory.path().join("inventory.sqlite3"), binding)?;
        let initial = inventory
            .acquire_lease(solver, owner, 1_000, 10_000)?
            .lease();
        let retained = Cell::new(initial);

        assert!(matches!(
            renew_exact_inventory_lease_at(
                &mut inventory,
                &retained,
                ParticipantId([0x38; 32]),
                owner,
                2_000,
                2_000,
            ),
            Err(ProductionF6ErrorV2::InvalidBinding)
        ));
        assert!(matches!(
            renew_exact_inventory_lease_at(
                &mut inventory,
                &retained,
                solver,
                [0x39; 32],
                2_000,
                2_000,
            ),
            Err(ProductionF6ErrorV2::InvalidBinding)
        ));
        assert_eq!(retained.get(), initial);

        renew_exact_inventory_lease_at(&mut inventory, &retained, solver, owner, 2_000, 2_000)?;
        let renewed = retained.get();
        assert_eq!(renewed.authority_id, solver);
        assert_eq!(renewed.owner_id, owner);
        assert_eq!(renewed.fencing_epoch, initial.fencing_epoch);
        assert_eq!(renewed.lease_until_unix_ms, 4_000);
        Ok(())
    }

    #[test]
    fn expired_inventory_lease_renewal_fails_before_persistent_or_retained_mutation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let binding = [0x3a; 32];
        let solver = ParticipantId([0x3b; 32]);
        let owner = [0x3c; 32];
        let mut inventory =
            DurableInventoryStoreV1::create(&directory.path().join("inventory.sqlite3"), binding)?;
        let expired = inventory.acquire_lease(solver, owner, 1_000, 100)?.lease();
        let retained = Cell::new(expired);

        assert!(matches!(
            renew_exact_inventory_lease_at(&mut inventory, &retained, solver, owner, 1_000, 1_101,),
            Err(ProductionF6ErrorV2::Inventory)
        ));
        assert_eq!(retained.get(), expired);

        let takeover = inventory
            .acquire_lease(solver, [0x3d; 32], 1_101, 1_000)?
            .lease();
        assert_eq!(takeover.fencing_epoch, expired.fencing_epoch + 1);
        assert_eq!(takeover.owner_id, [0x3d; 32]);
        Ok(())
    }

    #[test]
    fn swapped_leg_time_authority_is_refused_before_any_f6_store_effect() {
        let upstream_clock = NegotiationClockV2 {
            chain_id: ChainId([0x41; 32]),
            profile_digest: [0x42; 32],
            authority_scope: [0x43; 32],
            kind: NativeClockKindV2::BlockHeight,
        };
        let upstream_binding = binding_for_test(upstream_clock);
        let downstream_clock = NegotiationClockV2 {
            authority_scope: [0x44; 32],
            ..upstream_clock
        };
        let binding_log_touched = Cell::new(false);
        let receipt_store_touched = Cell::new(false);
        let candidate_book_touched = Cell::new(false);
        let refused = after_exact_leg_time_preflight(
            upstream_binding,
            SettlementPositionV2::Upstream,
            SettlementPositionV2::Downstream,
            downstream_clock.authority_scope,
            downstream_clock,
            || {
                binding_log_touched.set(true);
                receipt_store_touched.set(true);
                candidate_book_touched.set(true);
                Ok(())
            },
        );
        assert!(matches!(refused, Err(ProductionF6ErrorV2::InvalidBinding)));
        assert!(!binding_log_touched.get());
        assert!(!receipt_store_touched.get());
        assert!(!candidate_book_touched.get());

        let valid_effects = Cell::new(0u8);
        let accepted = after_exact_leg_time_preflight(
            upstream_binding,
            SettlementPositionV2::Upstream,
            SettlementPositionV2::Upstream,
            upstream_binding.pins.pre_f6_time_scope_digest,
            upstream_clock,
            || {
                valid_effects.set(1);
                Ok(())
            },
        );
        assert!(accepted.is_ok());
        assert_eq!(valid_effects.get(), 1);
    }

    #[test]
    fn pre_f6_scope_kat_is_not_the_embedded_clock_authority_scope(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let clock = NegotiationClockV2 {
            chain_id: ChainId([0x51; 32]),
            profile_digest: [0x52; 32],
            authority_scope: [0x53; 32],
            kind: NativeClockKindV2::BlockHeight,
        };
        let scope = PreF6TimeScopeV2::new(PreF6TimeScopeRequestV2 {
            network_id: [0x54; 32],
            session_id: [0x55; 32],
            route_id: [0x56; 32],
            composition_id: [0x57; 32],
            rfq_id: [0x58; 32],
            negotiation_clock: clock,
            registry_digest: [0x59; 32],
            registry_epoch: 3,
            profile_bundle_digest: [0x5a; 32],
        })?;
        assert_ne!(scope.scope_digest(), clock.authority_scope);
        let mut binding = binding_for_test(clock);
        binding.pins.pre_f6_time_scope_digest = scope.scope_digest();
        assert!(binding.validate().is_ok());
        validate_pre_f6_authority(binding, scope.scope_digest(), clock)?;
        Ok(())
    }

    #[test]
    fn physical_f6_create_refuses_swapped_time_stores_without_creating_any_target(
    ) -> Result<(), Box<dyn std::error::Error>> {
        run_physical_f6_create_case(true)?;
        run_physical_f6_create_case(false)?;
        Ok(())
    }

    fn run_physical_f6_create_case(swapped: bool) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let sources = directory.path().join("sources");
        let targets = directory.path().join("f6-targets");
        fs::create_dir(&sources)?;
        fs::create_dir(&targets)?;
        fs::set_permissions(&sources, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&targets, fs::Permissions::from_mode(0o700))?;

        let secp = SecpContext::new(&[0x61; 32]);
        let (registry, registry_authorities) = physical_registry(&secp)?;
        let manifest = registry.manifest();
        let solver = ParticipantId([0x62; 32]);
        let initiator = ParticipantId([0x63; 32]);
        let inventory_binding = [0x64; 32];
        let mut inventory =
            DurableInventoryStoreV1::create(&sources.join("inventory.sqlite3"), inventory_binding)?;
        let inventory_lease = inventory
            .acquire_lease(solver, [0x65; 32], 1_000, 10_000)?
            .lease();

        let status_scope = SolverStatusScopeV1 {
            network_id: manifest.network_id,
            registry_digest: registry.manifest_digest(),
            registry_epoch: manifest.epoch,
            roster_snapshot: [0x66; 32],
            solver_id: solver,
        };
        let status_config = SolverStatusStoreConfigV1::new(
            status_scope,
            &registry_authorities,
            &secp,
            SolverStatusFreshnessPolicyV1 {
                max_status_lifetime_seconds: 60,
            },
        )?;
        let upstream_status = DurableSolverStatusStoreV1::create_production(
            &sources.join("upstream-status.sqlite3"),
            status_config,
            registry_authorities.clone(),
            &secp,
        )?;
        let downstream_status = DurableSolverStatusStoreV1::create_production(
            &sources.join("downstream-status.sqlite3"),
            status_config,
            registry_authorities.clone(),
            &secp,
        )?;
        let status_scope_digest = upstream_status.scope_digest()?;
        assert_eq!(downstream_status.scope_digest()?, status_scope_digest);

        let upstream_clock = NegotiationClockV2 {
            chain_id: manifest.dom.chain_id,
            profile_digest: resolved_dom_profile_digest_v1(&registry)?,
            authority_scope: [0x67; 32],
            kind: NativeClockKindV2::BlockHeight,
        };
        let downstream_clock = NegotiationClockV2 {
            authority_scope: [0x68; 32],
            ..upstream_clock
        };
        let upstream_policy = physical_pre_f6_policy(
            &registry,
            [0x69; 32],
            SettlementPositionV2::Upstream,
            upstream_clock,
        )?;
        let downstream_policy = physical_pre_f6_policy(
            &registry,
            [0x6a; 32],
            SettlementPositionV2::Downstream,
            downstream_clock,
        )?;
        assert_ne!(
            upstream_policy.scope().scope_digest(),
            upstream_clock.authority_scope
        );
        assert_ne!(
            downstream_policy.scope().scope_digest(),
            downstream_clock.authority_scope
        );
        let upstream_time = DurablePreF6TimeStoreV2::create_production(
            &sources.join("upstream-time.sqlite3"),
            upstream_policy,
            registry_authorities.clone(),
            &secp,
        )?;
        let downstream_time = DurablePreF6TimeStoreV2::create_production(
            &sources.join("downstream-time.sqlite3"),
            downstream_policy,
            registry_authorities.clone(),
            &secp,
        )?;

        let owner = if swapped {
            ProductionF6SharedAuthorityOwnerV2::new(
                inventory,
                inventory_lease,
                [0x65; 32],
                10_000,
                upstream_status,
                downstream_status,
                downstream_time,
                upstream_time,
            )
        } else {
            ProductionF6SharedAuthorityOwnerV2::new(
                inventory,
                inventory_lease,
                [0x65; 32],
                10_000,
                upstream_status,
                downstream_status,
                upstream_time,
                downstream_time,
            )
        };
        let (upstream_shared, downstream_shared) = owner.into_two_legs();

        let solver_key = secp.xonly_public_key(&[0x6b; 32])?;
        let initiator_key = secp.xonly_public_key(&[0x6c; 32])?;
        let rosters = RosterRegistryV1::new().with_snapshot(
            status_scope.roster_snapshot,
            RosterSnapshotV1::new()
                .with_member(
                    initiator,
                    RosterMemberV1 {
                        xonly_key: initiator_key,
                        role: SenderRoleV1::Initiator,
                    },
                )
                .with_member(
                    solver,
                    RosterMemberV1 {
                        xonly_key: solver_key,
                        role: SenderRoleV1::Solver,
                    },
                ),
        );
        let bond_authorities = AuthoritySetV1::new(
            2,
            vec![
                secp.xonly_public_key(&[0x91; 32])?,
                secp.xonly_public_key(&[0x92; 32])?,
            ],
        )?;
        let status_authorities = AuthoritySetV1::new(
            2,
            vec![
                secp.xonly_public_key(&[0x93; 32])?,
                secp.xonly_public_key(&[0x94; 32])?,
            ],
        )?;
        assert!(bond_authorities
            .xonly_keys()
            .iter()
            .all(|key| !status_authorities.xonly_keys().contains(key)));
        let binding =
            ProductionSolverF6BindingV2 {
                wire: RouteWireContextV1 {
                    network_id: manifest.network_id,
                    session_id: [0x6d; 32],
                    route_id: [0x6e; 32],
                    roster_snapshot: status_scope.roster_snapshot,
                    policy_version: 3,
                },
                rfq_id: upstream_policy.scope().rfq_id(),
                composition_id: upstream_policy.scope().composition_id(),
                position: SettlementPositionV2::Upstream,
                initiator,
                solver,
                dom_chain_id: manifest.dom.chain_id,
                negotiation_clock: upstream_clock,
                pins: ProductionF6PinsV2 {
                    inventory_binding_digest: inventory_binding,
                    registry_digest: registry.manifest_digest(),
                    registry_epoch: manifest.epoch,
                    profile_bundle_digest: upstream_policy.scope().profile_bundle_digest(),
                    bond_policy_hash: [0x6f; 32],
                    bond_asset_binding_digest: [0x70; 32],
                    required_collateral: 10,
                    bond_attestation_authority_set_digest:
                        bond_reservation_authority_set_digest_v2(&bond_authorities, &secp)?,
                    remote_status_authority_set_digest: candidate_status_authority_set_digest_v2(
                        &status_authorities,
                        &secp,
                    )?,
                    solver_status_scope_digest: status_scope_digest,
                    pre_f6_time_scope_digest: upstream_policy.scope().scope_digest(),
                },
            };
        assert!(binding.validate().is_ok());
        let binding_log = targets.join("binding.log");
        let receipt_store = targets.join("receipts.sqlite3");
        let candidate_book = targets.join("candidate.log");
        let result = ProductionSolverF6AuthorityV2::create_production(
            ProductionF6PathsV2 {
                binding_log: &binding_log,
                receipt_store: &receipt_store,
                candidate_book: &candidate_book,
            },
            binding,
            ProductionF6AuthoritiesV2 {
                shared: upstream_shared,
                bond_attestation_authorities: bond_authorities,
                remote_status_authorities: status_authorities,
                secp,
                rosters,
                sources: unreachable_sources(),
            },
        );

        if swapped {
            assert!(matches!(result, Err(ProductionF6ErrorV2::InvalidBinding)));
            assert!(!binding_log.exists());
            assert!(!receipt_store.exists());
            assert!(!candidate_book.exists());
            let entries = fs::read_dir(&targets)?.collect::<Result<Vec<_>, _>>()?;
            assert!(entries.is_empty());
        } else {
            assert!(
                result.is_ok(),
                "unexpected create refusal: {:?}",
                result.err()
            );
            assert!(binding_log.exists());
            assert!(receipt_store.exists());
            assert!(candidate_book.exists());
        }
        drop(downstream_shared);
        Ok(())
    }

    fn physical_pre_f6_policy(
        registry: &ResolvedRegistryV1,
        rfq_id: Digest32,
        position: SettlementPositionV2,
        negotiation_clock: NegotiationClockV2,
    ) -> Result<PreF6TimePolicyV2, Box<dyn std::error::Error>> {
        let position_tag = match position {
            SettlementPositionV2::Upstream => 0x71,
            SettlementPositionV2::Downstream => 0x72,
        };
        let scope = PreF6TimeScopeV2::new(PreF6TimeScopeRequestV2 {
            network_id: registry.manifest().network_id,
            session_id: [0x6d; 32],
            route_id: [0x6e; 32],
            composition_id: [0x73; 32],
            rfq_id,
            negotiation_clock,
            registry_digest: registry.manifest_digest(),
            registry_epoch: registry.manifest().epoch,
            profile_bundle_digest: [position_tag; 32],
        })?;
        Ok(PreF6TimePolicyV2::from_registry(
            scope,
            registry,
            PreF6TimePolicyLimitsV2 {
                valid_from_seconds: 900_000,
                expires_at_seconds: 4_000_000,
                max_evidence_age_seconds: 300,
            },
        )?)
    }

    fn physical_registry(
        secp: &SecpContext,
    ) -> Result<(ResolvedRegistryV1, AuthoritySetV1), Box<dyn std::error::Error>> {
        let dom_network = DomNetworkV1::Regtest;
        let network_magic = dom_network.canonical_magic();
        let genesis = configured_genesis_hash_for_network_magic(network_magic)?;
        let dom_chain_id = ChainId(*derive_chain_id(network_magic, &genesis).as_bytes());
        let finality = FinalityPolicyV1 {
            min_confirmations: 2,
            max_reorg_depth: 3,
        };
        let timing = ChainTimingBoundsV1 {
            min_block_seconds: 1,
            max_block_seconds: 2,
            max_reorg_seconds: 20,
            observation_seconds: 2,
            broadcast_seconds: 2,
        };
        let dom_asset = AssetId([0x81; 32]);
        let evm_chain_id = ChainId([0x82; 32]);
        let evm_asset = AssetId([0x83; 32]);
        let mut manifest = RegistryManifestV1 {
            network_id: [0x84; 32],
            epoch: 7,
            valid_from: 800_000,
            expires_at: 5_000_000,
            dom: DomDeploymentV1 {
                chain_id: dom_chain_id,
                genesis_hash: *genesis.as_bytes(),
                runtime_identity: DomRuntimeIdentityV1::pinned(dom_network),
                consensus_rules_digest: [0x85; 32],
                scriptless_api_version: 1,
                timing,
                finality,
                native_asset: dom_asset,
            },
            chains: vec![RegistryChainProfileV1 {
                profile: ChainProfileV1 {
                    chain_id: evm_chain_id,
                    kind: ChainKindV1::Evm {
                        evm_chain_id: 31_337,
                        native_lock_contract: [0x86; 20],
                        native_code_hash: [0x87; 32],
                        erc20_lock_contract: None,
                    },
                    timing,
                    finality,
                    native_asset: evm_asset,
                    allowed_assets: Vec::new(),
                },
                deployment: ChainDeploymentV1::Evm(EvmDeploymentV1 {
                    genesis_hash: [0x88; 32],
                    native_start_block: 10,
                    erc20_start_block: None,
                    abi_digest: [0x89; 32],
                    compiler_digest: [0x8a; 32],
                    source_digest: [0x8b; 32],
                    deployment_digest: [0x8c; 32],
                    finalized_tag_required: true,
                    page_size: 256,
                    gas_limit_hint: 300_000,
                    max_fee_per_gas: 100_000_000_000,
                    max_priority_fee_per_gas: 2_000_000_000,
                }),
            }],
            assets: vec![
                AssetBindingV1 {
                    chain_id: dom_chain_id,
                    asset_id: dom_asset,
                    decimals: 9,
                    representation: AssetRepresentationV1::Native,
                },
                AssetBindingV1 {
                    chain_id: evm_chain_id,
                    asset_id: evm_asset,
                    decimals: 18,
                    representation: AssetRepresentationV1::Native,
                },
            ],
        };
        manifest
            .assets
            .sort_by_key(|asset| (asset.chain_id.0, asset.asset_id.0));
        let registry_secret = [0x8d; 32];
        let registry_key = secp.xonly_public_key(&registry_secret)?;
        let authorities = AuthoritySetV1::new(1, vec![registry_key])?;
        let digest = manifest.manifest_digest()?;
        let (signature, _) = secp.sign_bip340(&registry_secret, &digest, &[0x8e; 32])?;
        let signed = SignedRegistryV1::new(
            &manifest,
            vec![RegistrySignatureV1 {
                signer_index: 0,
                signature,
            }],
        )?;
        let registry = signed.verify(
            &authorities,
            secp,
            RegistryValidationPolicyV1 {
                now_seconds: 1_000_000,
                expected_network_id: manifest.network_id,
                minimum_epoch: manifest.epoch,
            },
        )?;
        Ok((registry, authorities))
    }

    #[test]
    fn v1_bytes_are_not_v2_payloads() {
        assert!(RfqV2::decode(b"DOMRFQV1").is_err());
        assert!(QuoteV2::decode(b"DOMQUTV1").is_err());
        assert!(AcceptanceV2::decode(b"DOMACPV1").is_err());
        assert!(SelectionV2::decode(b"DOMSELV1").is_err());
    }

    #[test]
    fn receipt_binds_sender_sequence_kind_envelope_payload_and_disposition(
    ) -> Result<(), ProductionF6ErrorV2> {
        let base = digest_parts(&[
            RECEIPT_DOMAIN,
            &[1; 32],
            &1u64.to_be_bytes(),
            &1u16.to_be_bytes(),
            &[2; 32],
            &[3; 32],
            &[1],
        ])?;
        for changed in [
            digest_parts(&[
                RECEIPT_DOMAIN,
                &[4; 32],
                &1u64.to_be_bytes(),
                &1u16.to_be_bytes(),
                &[2; 32],
                &[3; 32],
                &[1],
            ])?,
            digest_parts(&[
                RECEIPT_DOMAIN,
                &[1; 32],
                &2u64.to_be_bytes(),
                &1u16.to_be_bytes(),
                &[2; 32],
                &[3; 32],
                &[1],
            ])?,
            digest_parts(&[
                RECEIPT_DOMAIN,
                &[1; 32],
                &1u64.to_be_bytes(),
                &2u16.to_be_bytes(),
                &[2; 32],
                &[3; 32],
                &[1],
            ])?,
            digest_parts(&[
                RECEIPT_DOMAIN,
                &[1; 32],
                &1u64.to_be_bytes(),
                &1u16.to_be_bytes(),
                &[5; 32],
                &[3; 32],
                &[1],
            ])?,
            digest_parts(&[
                RECEIPT_DOMAIN,
                &[1; 32],
                &1u64.to_be_bytes(),
                &1u16.to_be_bytes(),
                &[2; 32],
                &[6; 32],
                &[1],
            ])?,
            digest_parts(&[
                RECEIPT_DOMAIN,
                &[1; 32],
                &1u64.to_be_bytes(),
                &1u16.to_be_bytes(),
                &[2; 32],
                &[3; 32],
                &[2],
            ])?,
        ] {
            assert_ne!(base, changed);
        }
        Ok(())
    }

    #[test]
    fn pre_f6_authority_and_current_selection_are_exactly_bound() -> Result<(), ProductionF6ErrorV2>
    {
        let clock = NegotiationClockV2 {
            chain_id: ChainId([0x61; 32]),
            profile_digest: [0x62; 32],
            authority_scope: [0x63; 32],
            kind: NativeClockKindV2::BlockHeight,
        };
        let binding = binding_for_test(clock);
        validate_pre_f6_authority(binding, binding.pins.pre_f6_time_scope_digest, clock)?;
        assert!(matches!(
            validate_pre_f6_authority(binding, [0x64; 32], clock),
            Err(ProductionF6ErrorV2::InvalidBinding)
        ));
        assert!(matches!(
            validate_pre_f6_authority(
                binding,
                binding.pins.pre_f6_time_scope_digest,
                NegotiationClockV2 {
                    profile_digest: [0x65; 32],
                    ..clock
                },
            ),
            Err(ProductionF6ErrorV2::InvalidBinding)
        ));

        let selection = SelectionV2 {
            rfq_id: binding.rfq_id,
            composition_id: binding.composition_id,
            position: binding.position,
            winning_quote: [0x66; 32],
            inputs_digest: [0x67; 32],
        };
        validate_current_local_selection(
            selection.winning_quote,
            selection.inputs_digest,
            selection.winning_quote,
            selection.inputs_digest,
            &selection,
        )?;
        for result in [
            validate_current_local_selection(
                [0x68; 32],
                selection.inputs_digest,
                selection.winning_quote,
                selection.inputs_digest,
                &selection,
            ),
            validate_current_local_selection(
                selection.winning_quote,
                [0x69; 32],
                selection.winning_quote,
                selection.inputs_digest,
                &selection,
            ),
            validate_current_local_selection(
                selection.winning_quote,
                selection.inputs_digest,
                [0x6a; 32],
                selection.inputs_digest,
                &selection,
            ),
        ] {
            assert!(matches!(result, Err(ProductionF6ErrorV2::Binding)));
        }
        Ok(())
    }

    #[test]
    fn authenticated_remote_candidate_is_refused_before_book_for_route_economics_or_time(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let clock = NegotiationClockV2 {
            chain_id: ChainId([0x71; 32]),
            profile_digest: [0x72; 32],
            authority_scope: [0x73; 32],
            kind: NativeClockKindV2::BlockHeight,
        };
        let route = RouteV2 {
            composition_id: [0x74; 32],
            position: SettlementPositionV2::Upstream,
            legs: [
                RouteLegV1 {
                    chain_id: ChainId([0x75; 32]),
                    asset: AssetId([0x76; 32]),
                    direction: LegDirectionV1::UserGives,
                },
                RouteLegV1 {
                    chain_id: clock.chain_id,
                    asset: AssetId([0x77; 32]),
                    direction: LegDirectionV1::UserReceives,
                },
            ],
        };
        let rfq = RfqV2::create(RfqRequestV2 {
            initiator: ParticipantId([0x78; 32]),
            route,
            mode: RfqModeV1::ExactIn {
                input_amount: 100,
                minimum_output: 90,
            },
            fee_limit: FeeLimitV1 {
                dom_max: 4,
                counterparty_max: 6,
            },
            negotiation_clock: clock,
            quote_deadline: NegotiationInstantV2 {
                clock,
                value: 1_100,
            },
            assurance_policy_ref: PolicyId([0x79; 32]),
            policy_version: 3,
            session_id: [0x7a; 32],
        })?;
        let quote = QuoteV2::create(QuoteProposalV2 {
            rfq_id: rfq.rfq_id,
            solver: ParticipantId([0x7b; 32]),
            route,
            net_output: 95,
            total_input: 100,
            total_fee: 5,
            execution_deadline: NegotiationInstantV2 {
                clock,
                value: 1_080,
            },
            bond_reservation_id: [0x7c; 32],
            bond_policy_version: 3,
            expiry: NegotiationInstantV2 {
                clock,
                value: 1_050,
            },
            solver_signature: [0x7d; 64],
        })?;
        let request = remote_request_for_test(&rfq, &quote);
        let current = rfq::v2::NegotiationObservationV2 {
            clock,
            value: 1_000,
        };
        validate_authenticated_remote_candidate(&rfq, &quote, request, clock.chain_id, current)?;

        let foreign_route = RouteV2 {
            legs: [
                RouteLegV1 {
                    asset: AssetId([0x7e; 32]),
                    ..route.legs[0]
                },
                route.legs[1],
            ],
            ..route
        };
        let foreign_quote = QuoteV2::create(QuoteProposalV2 {
            route: foreign_route,
            ..quote_proposal_for_test(&rfq, quote)
        })?;
        let book_admission_called = Cell::new(false);
        assert!(matches!(
            validate_and_admit_remote_candidate(
                &rfq,
                &foreign_quote,
                BondReservationAttestationRequestV2 {
                    quote_id: foreign_quote.quote_id,
                    ..request
                },
                clock.chain_id,
                current,
                || {
                    book_admission_called.set(true);
                    Ok(())
                },
            ),
            Err(ProductionF6ErrorV2::InvalidPayload)
        ));
        assert!(!book_admission_called.get());
        let underpriced_quote = QuoteV2::create(QuoteProposalV2 {
            net_output: 89,
            ..quote_proposal_for_test(&rfq, quote)
        })?;
        assert!(matches!(
            validate_authenticated_remote_candidate(
                &rfq,
                &underpriced_quote,
                BondReservationAttestationRequestV2 {
                    quote_id: underpriced_quote.quote_id,
                    ..request
                },
                clock.chain_id,
                current,
            ),
            Err(ProductionF6ErrorV2::InvalidPayload)
        ));
        assert!(matches!(
            validate_authenticated_remote_candidate(
                &rfq,
                &quote,
                BondReservationAttestationRequestV2 {
                    reserved_collateral: request.required_collateral - 1,
                    ..request
                },
                clock.chain_id,
                current,
            ),
            Err(ProductionF6ErrorV2::InvalidPayload)
        ));
        assert!(matches!(
            validate_authenticated_remote_candidate(
                &rfq,
                &quote,
                request,
                clock.chain_id,
                rfq::v2::NegotiationObservationV2 {
                    value: 1_051,
                    ..current
                },
            ),
            Err(ProductionF6ErrorV2::InvalidPayload)
        ));
        Ok(())
    }

    #[test]
    fn quote_intent_is_durable_before_inventory_and_restart_refuses_substitution(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("f6-receipts.sqlite3");
        let store_binding = ProductionStoreBindingV1::new([0xa1; 32])?;
        let quote = quote_for_intent_test(95)?;
        let mut receipts = Store::create_production(&path, store_binding)?;
        for (kind, expected) in [
            (RequiredF6ReceiptV2::Rfq, ProductionF6ErrorV2::Binding),
            (
                RequiredF6ReceiptV2::LocalEconomicAuthority,
                ProductionF6ErrorV2::Inventory,
            ),
        ] {
            let missing = load_required_f6_receipt(
                &receipts,
                b"test-missing-f6-prerequisite",
                quote.rfq_id,
                kind,
            );
            assert!(matches!(
                (&missing, &expected),
                (
                    Err(ProductionF6ErrorV2::Binding),
                    ProductionF6ErrorV2::Binding
                ) | (
                    Err(ProductionF6ErrorV2::Inventory),
                    ProductionF6ErrorV2::Inventory
                )
            ));
            assert!(!is_permanent_f6_refusal(&expected));
        }
        for permanent in [
            map_candidate(CandidateBookErrorV2::InvalidAuthority),
            map_candidate(CandidateBookErrorV2::Stale),
            ProductionF6ErrorV2::InvalidPayload,
            ProductionF6ErrorV2::WrongRole,
            ProductionF6ErrorV2::InvalidTerms,
        ] {
            assert!(is_permanent_f6_refusal(&permanent));
        }
        assert!(!is_permanent_f6_refusal(
            &ProductionF6ErrorV2::TermsUnavailable
        ));
        let inventory_called = Cell::new(false);
        assert!(matches!(
            persist_quote_intent_before_inventory(&mut receipts, quote.rfq_id, &quote, || {
                inventory_called.set(true);
                Err::<(), _>(ProductionF6ErrorV2::Inventory)
            },),
            Err(ProductionF6ErrorV2::Inventory)
        ));
        assert!(inventory_called.get());
        drop(receipts);

        // This is the crash/restart boundary immediately after quote intent
        // publication and before inventory reservation.
        let mut reopened = Store::open_production(&path, store_binding)?;
        persist_exact_quote_intent(&mut reopened, quote.rfq_id, &quote)?;
        let substituted = quote_for_intent_test(96)?;
        assert_eq!(substituted.rfq_id, quote.rfq_id);
        assert_ne!(substituted.quote_id, quote.quote_id);
        assert!(matches!(
            persist_exact_quote_intent(&mut reopened, quote.rfq_id, &substituted),
            Err(ProductionF6ErrorV2::InvalidPayload)
        ));
        Ok(())
    }

    #[test]
    fn local_outbound_attestation_is_exactly_bound_to_inventory_and_status(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let solver = ParticipantId([0x51; 32]);
        let clock = NegotiationClockV2 {
            chain_id: rfq::ChainId([0xd0; 32]),
            profile_digest: [0x31; 32],
            authority_scope: [0x32; 32],
            kind: NativeClockKindV2::BlockHeight,
        };
        let route = RouteV2 {
            composition_id: [0x41; 32],
            position: SettlementPositionV2::Upstream,
            legs: [
                RouteLegV1 {
                    chain_id: rfq::ChainId([0xe1; 32]),
                    asset: AssetId([0xe2; 32]),
                    direction: LegDirectionV1::UserGives,
                },
                RouteLegV1 {
                    chain_id: clock.chain_id,
                    asset: AssetId([0xd2; 32]),
                    direction: LegDirectionV1::UserReceives,
                },
            ],
        };
        let quote = QuoteV2::create(QuoteProposalV2 {
            rfq_id: [0x42; 32],
            solver,
            route,
            net_output: 95,
            total_input: 100,
            total_fee: 5,
            execution_deadline: NegotiationInstantV2 {
                clock,
                value: 1_080,
            },
            bond_reservation_id: [0x52; 32],
            bond_policy_version: 3,
            expiry: NegotiationInstantV2 {
                clock,
                value: 1_050,
            },
            solver_signature: [0x53; 64],
        })?;
        let status = SolverStatusStatementV1::new(
            SolverStatusScopeV1 {
                network_id: [0x11; 32],
                registry_digest: [0x12; 32],
                registry_epoch: 4,
                roster_snapshot: [0x13; 32],
                solver_id: solver,
            },
            SolverStatusObservationV1 {
                status_epoch: 5,
                source_evidence_digest: [0x14; 32],
                state: SolverOperationalStateV1::Active,
                observed_at_seconds: 100,
                valid_until_seconds: 180,
            },
        )?;
        let signed_status = SignedSolverStatusV1::new(
            status,
            vec![SolverStatusSignatureV1 {
                signer_index: 0,
                signature: [0x15; 64],
            }],
        )?;
        let request = BondReservationAttestationRequestV2 {
            network_id: [0x11; 32],
            composition_id: route.composition_id,
            position: route.position,
            rfq_id: quote.rfq_id,
            quote_id: quote.quote_id,
            solver,
            reservation_id: quote.bond_reservation_id,
            bond_policy_hash: [0x16; 32],
            registry_digest: [0x12; 32],
            registry_epoch: 4,
            bond_asset_binding_digest: [0x17; 32],
            required_collateral: 10,
            reserved_collateral: 12,
            reservation_state_digest: [0x18; 32],
            source_evidence_digest: [0x19; 32],
            solver_status_statement_digest: status.statement_digest()?,
            solver_status_epoch: status.status_epoch(),
            solver_status_valid_until_seconds: status.valid_until_seconds(),
            observed_at_seconds: 100,
            valid_until_seconds: 170,
            sequence: 1,
            previous_attestation_digest: ZERO_DIGEST,
        };
        let delivery = candidate_delivery_for_test(quote, request, signed_status.clone())?;
        let binding = ProductionSolverF6BindingV2 {
            wire: RouteWireContextV1 {
                network_id: request.network_id,
                session_id: [0x21; 32],
                route_id: [0x22; 32],
                roster_snapshot: [0x13; 32],
                policy_version: 3,
            },
            rfq_id: quote.rfq_id,
            composition_id: route.composition_id,
            position: route.position,
            initiator: ParticipantId([0x23; 32]),
            solver,
            dom_chain_id: clock.chain_id,
            negotiation_clock: clock,
            pins: ProductionF6PinsV2 {
                inventory_binding_digest: [0x24; 32],
                registry_digest: request.registry_digest,
                registry_epoch: request.registry_epoch,
                profile_bundle_digest: [0x25; 32],
                bond_policy_hash: request.bond_policy_hash,
                bond_asset_binding_digest: request.bond_asset_binding_digest,
                required_collateral: request.required_collateral,
                bond_attestation_authority_set_digest: [0x26; 32],
                remote_status_authority_set_digest: [0x27; 32],
                solver_status_scope_digest: [0x28; 32],
                pre_f6_time_scope_digest: [0x29; 32],
            },
        };
        let expected = LocalCandidateExpectationV2 {
            required_collateral: request.required_collateral,
            reserved_collateral: request.reserved_collateral,
            reservation_state_digest: request.reservation_state_digest,
            bond_asset_binding_digest: request.bond_asset_binding_digest,
            status_statement_digest: request.solver_status_statement_digest,
            status_source_evidence_digest: status.source_evidence_digest(),
            status_epoch: status.status_epoch(),
            status_observed_at_seconds: status.observed_at_seconds(),
            status_valid_until_seconds: status.valid_until_seconds(),
        };
        validate_local_candidate_delivery(binding, &quote, &delivery, expected)?;
        for changed in [
            LocalCandidateExpectationV2 {
                required_collateral: 11,
                ..expected
            },
            LocalCandidateExpectationV2 {
                reserved_collateral: 13,
                ..expected
            },
            LocalCandidateExpectationV2 {
                reservation_state_digest: [0x31; 32],
                ..expected
            },
            LocalCandidateExpectationV2 {
                bond_asset_binding_digest: [0x32; 32],
                ..expected
            },
            LocalCandidateExpectationV2 {
                status_statement_digest: [0x33; 32],
                ..expected
            },
            LocalCandidateExpectationV2 {
                status_source_evidence_digest: [0x34; 32],
                ..expected
            },
            LocalCandidateExpectationV2 {
                status_epoch: 6,
                ..expected
            },
            LocalCandidateExpectationV2 {
                status_observed_at_seconds: 101,
                ..expected
            },
            LocalCandidateExpectationV2 {
                status_valid_until_seconds: 181,
                ..expected
            },
        ] {
            assert!(matches!(
                validate_local_candidate_delivery(binding, &quote, &delivery, changed),
                Err(ProductionF6ErrorV2::InvalidPayload)
            ));
        }

        let wrong_asset = candidate_delivery_for_test(
            quote,
            BondReservationAttestationRequestV2 {
                bond_asset_binding_digest: [0x35; 32],
                ..request
            },
            signed_status.clone(),
        )?;
        assert!(matches!(
            validate_local_candidate_delivery(binding, &quote, &wrong_asset, expected),
            Err(ProductionF6ErrorV2::InvalidPayload)
        ));

        let first_digest = delivery.attestation().attestation()?.attestation_digest()?;
        let refreshed = candidate_delivery_for_test(
            quote,
            BondReservationAttestationRequestV2 {
                reservation_state_digest: [0x37; 32],
                source_evidence_digest: [0x38; 32],
                observed_at_seconds: 120,
                valid_until_seconds: 175,
                sequence: 2,
                previous_attestation_digest: first_digest,
                ..request
            },
            signed_status,
        )?;
        let first_payload = delivery.canonical_bytes()?;
        validate_signed_candidate_history_head(core::slice::from_ref(&delivery), &first_payload)?;
        assert!(matches!(
            validate_signed_candidate_history_head(&[], &first_payload),
            Err(ProductionF6ErrorV2::InvalidCandidateAttestation)
        ));
        assert!(matches!(
            validate_signed_candidate_history_head(
                core::slice::from_ref(&refreshed),
                &first_payload
            ),
            Err(ProductionF6ErrorV2::InvalidCandidateAttestation)
        ));
        let oversized_history = vec![delivery.clone(); MAX_OUTBOUND_QUOTE_REVISIONS + 1];
        assert!(matches!(
            validate_signed_candidate_history_head(&oversized_history, &first_payload),
            Err(ProductionF6ErrorV2::InvalidCandidateAttestation)
        ));
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let receipt_path = directory.path().join("outbound-receipts.sqlite3");
        let receipt_binding =
            ProductionStoreBindingV1::new(binding.authority_digest(RECEIPT_BINDING_DOMAIN)?)?;
        let mut receipts = Store::create_production(&receipt_path, receipt_binding)?;
        assert!(matches!(
            recover_candidate_history_before_receipts(
                &mut receipts,
                binding,
                core::slice::from_ref(&delivery),
                || Err(ProductionF6ErrorV2::InvalidCandidateAttestation),
            ),
            Err(ProductionF6ErrorV2::InvalidCandidateAttestation)
        ));
        assert!(receipts.read_journal()?.is_empty());
        persist_outbound_quote_receipt(&mut receipts, binding, &delivery)?;
        persist_outbound_quote_receipt(&mut receipts, binding, &delivery)?;
        assert_eq!(receipts.read_journal()?.len(), 1);
        persist_outbound_quote_receipt(&mut receipts, binding, &refreshed)?;
        assert_eq!(receipts.read_journal()?.len(), 2);
        assert_eq!(
            read_outbound_quote_receipt_head(&receipts, binding)?
                .ok_or("missing receipt head")?
                .canonical_bytes()?,
            refreshed.canonical_bytes()?
        );
        assert!(matches!(
            persist_outbound_quote_receipt(&mut receipts, binding, &delivery),
            Err(ProductionF6ErrorV2::InvalidCandidateAttestation)
        ));
        drop(receipts);
        let reopened = Store::open_production(&receipt_path, receipt_binding)?;
        assert_eq!(
            read_outbound_quote_receipt_head(&reopened, binding)?
                .ok_or("missing reopened receipt head")?
                .canonical_bytes()?,
            refreshed.canonical_bytes()?
        );
        Ok(())
    }

    fn candidate_delivery_for_test(
        quote: QuoteV2,
        request: BondReservationAttestationRequestV2,
        status: SignedSolverStatusV1,
    ) -> Result<CandidateQuoteDeliveryV2, Box<dyn std::error::Error>> {
        let attestation = BondReservationAttestationV2::new(request)?;
        let signed = SignedBondReservationAttestationV2::new(
            attestation,
            vec![BondReservationSignatureV2 {
                signer_index: 0,
                signature: [0x36; 64],
            }],
        )?;
        Ok(CandidateQuoteDeliveryV2::new(quote, signed, status)?)
    }

    fn binding_for_test(clock: NegotiationClockV2) -> ProductionSolverF6BindingV2 {
        ProductionSolverF6BindingV2 {
            wire: RouteWireContextV1 {
                network_id: [0x81; 32],
                session_id: [0x82; 32],
                route_id: [0x83; 32],
                roster_snapshot: [0x84; 32],
                policy_version: 3,
            },
            rfq_id: [0x85; 32],
            composition_id: [0x86; 32],
            position: SettlementPositionV2::Upstream,
            initiator: ParticipantId([0x87; 32]),
            solver: ParticipantId([0x88; 32]),
            dom_chain_id: clock.chain_id,
            negotiation_clock: clock,
            pins: ProductionF6PinsV2 {
                inventory_binding_digest: [0x89; 32],
                registry_digest: [0x8a; 32],
                registry_epoch: 4,
                profile_bundle_digest: [0x8b; 32],
                bond_policy_hash: [0x8c; 32],
                bond_asset_binding_digest: [0x8d; 32],
                required_collateral: 10,
                bond_attestation_authority_set_digest: [0x8e; 32],
                remote_status_authority_set_digest: [0x8f; 32],
                solver_status_scope_digest: [0x90; 32],
                pre_f6_time_scope_digest: [0x91; 32],
            },
        }
    }

    fn remote_request_for_test(
        rfq: &RfqV2,
        quote: &QuoteV2,
    ) -> BondReservationAttestationRequestV2 {
        BondReservationAttestationRequestV2 {
            network_id: [0x91; 32],
            composition_id: rfq.route.composition_id,
            position: rfq.route.position,
            rfq_id: rfq.rfq_id,
            quote_id: quote.quote_id,
            solver: quote.solver,
            reservation_id: quote.bond_reservation_id,
            bond_policy_hash: [0x92; 32],
            registry_digest: [0x93; 32],
            registry_epoch: 4,
            bond_asset_binding_digest: [0x94; 32],
            required_collateral: 10,
            reserved_collateral: 12,
            reservation_state_digest: [0x95; 32],
            source_evidence_digest: [0x96; 32],
            solver_status_statement_digest: [0x97; 32],
            solver_status_epoch: 5,
            solver_status_valid_until_seconds: 2_000,
            observed_at_seconds: 900,
            valid_until_seconds: 1_500,
            sequence: 1,
            previous_attestation_digest: ZERO_DIGEST,
        }
    }

    fn quote_proposal_for_test(rfq: &RfqV2, quote: QuoteV2) -> QuoteProposalV2 {
        QuoteProposalV2 {
            rfq_id: rfq.rfq_id,
            solver: quote.solver,
            route: quote.route,
            net_output: quote.net_output,
            total_input: quote.total_input,
            total_fee: quote.total_fee,
            execution_deadline: quote.execution_deadline,
            bond_reservation_id: quote.bond_reservation_id,
            bond_policy_version: quote.bond_policy_version,
            expiry: quote.expiry,
            solver_signature: quote.solver_signature,
        }
    }

    fn quote_for_intent_test(net_output: u128) -> Result<QuoteV2, rfq::v2::F6V2Refusal> {
        let clock = NegotiationClockV2 {
            chain_id: ChainId([0xa2; 32]),
            profile_digest: [0xa3; 32],
            authority_scope: [0xa4; 32],
            kind: NativeClockKindV2::BlockHeight,
        };
        QuoteV2::create(QuoteProposalV2 {
            rfq_id: [0xa5; 32],
            solver: ParticipantId([0xa6; 32]),
            route: RouteV2 {
                composition_id: [0xa7; 32],
                position: SettlementPositionV2::Upstream,
                legs: [
                    RouteLegV1 {
                        chain_id: ChainId([0xa8; 32]),
                        asset: AssetId([0xa9; 32]),
                        direction: LegDirectionV1::UserGives,
                    },
                    RouteLegV1 {
                        chain_id: clock.chain_id,
                        asset: AssetId([0xaa; 32]),
                        direction: LegDirectionV1::UserReceives,
                    },
                ],
            },
            net_output,
            total_input: 100,
            total_fee: 5,
            execution_deadline: NegotiationInstantV2 {
                clock,
                value: 1_080,
            },
            bond_reservation_id: [0xab; 32],
            bond_policy_version: 3,
            expiry: NegotiationInstantV2 {
                clock,
                value: 1_050,
            },
            solver_signature: [0xac; 64],
        })
    }
}
