//! Concrete one-position activation of a fully authenticated F6 authority.
//!
//! This module is deliberately the last step, not an input parser. It accepts
//! only the real typed authority graph assembled by the production owner and
//! an already frozen [`ProductionSolverF6BindingV2`]. On first delivery or
//! applied-history replay it reconstructs that binding from the roster-
//! authenticated RFQ before consuming any owner or touching an F6 store.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use rfq::v2::{RfqV2, SettlementPositionV2};
use route_executor::{DurableRouteStoreV1, RouteIdV1};

use crate::production_config::{ProductionF6PathRoleV4, ValidatedProductionLayoutV1};
use crate::production_f6::terminal_release::{
    ProductionRouteStoreRuntimeAuthorityV2, ProductionRouteTerminalAuthorityOwnerV2,
    ProductionRouteTerminalAuthorityV2,
};
use crate::production_f6::{
    ProductionF6AuthoritiesV2, ProductionF6ErrorV2, ProductionF6PathsV2,
    ProductionF6PreparedBindingsV2, ProductionSolverF6AuthorityV2, ProductionSolverF6BindingV2,
};
use crate::production_f6_factory::AuthenticatedProductionF6PairBindingV7;
use crate::production_f6_lifecycle::{
    activation_seal, AuthenticatedPendingRfqV2, ProductionF6ActivationAuthorityV2,
    ProductionF6ActivationRefusalV2,
};

/// Opaque process-live proof that both F6 activation handles and the terminal
/// route-store receiver came from one exact pair split. It deliberately has no
/// public constructor, equality implementation, raw identifier or `Clone`.
pub(crate) struct ProductionF6PairProvenanceV2(Rc<()>);

impl ProductionF6PairProvenanceV2 {
    fn new() -> Self {
        Self(Rc::new(()))
    }

    fn fork(&self) -> Self {
        Self(Rc::clone(&self.0))
    }

    pub(crate) fn matches(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl core::fmt::Debug for ProductionF6PairProvenanceV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionF6PairProvenanceV2([opaque])")
    }
}

/// Exact storage operation authorized by the global provisioning journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(
    dead_code,
    reason = "retained surface not yet wired by the stage-7 composition root"
)]
pub(crate) enum ProductionF6ActivationOpenModeV2 {
    /// Every position store is absent and may be created once.
    Create,
    /// Every position store is complete and must only be reopened.
    OpenExisting,
    /// A globally journaled pristine creation prefix may be resumed.
    ResumeCreate,
    /// Stage 11 published exact empty prefixes before Relay learned the RFQ;
    /// activation opens retained state or completes those prefixes under the
    /// now-authenticated final binding.
    OpenOrResumePrepared(ProductionF6PreparedBindingsV2),
}

/// Owned V4 paths for one position. The candidate-attestation path belongs to
/// the source authority and is intentionally not accepted here: this factory
/// receives that already-open concrete producer inside `authorities.sources`.
pub(crate) struct ProductionF6ActivationPathsV2 {
    binding_log: PathBuf,
    receipt_store: PathBuf,
    candidate_book: PathBuf,
}

impl ProductionF6ActivationPathsV2 {
    /// Derives the only admitted path triple from the validated V4 layout.
    pub(crate) fn from_v4_layout(
        layout: &ValidatedProductionLayoutV1,
        position: SettlementPositionV2,
    ) -> Result<Self, ProductionF6ActivationRefusalV2> {
        let (binding_role, receipt_role, candidate_role) = match position {
            SettlementPositionV2::Upstream => (
                ProductionF6PathRoleV4::UpstreamBindingLog,
                ProductionF6PathRoleV4::UpstreamReceiptStore,
                ProductionF6PathRoleV4::UpstreamCandidateBook,
            ),
            SettlementPositionV2::Downstream => (
                ProductionF6PathRoleV4::DownstreamBindingLog,
                ProductionF6PathRoleV4::DownstreamReceiptStore,
                ProductionF6PathRoleV4::DownstreamCandidateBook,
            ),
        };
        let binding_log = layout
            .f6_path_v4(binding_role)
            .ok_or(ProductionF6ActivationRefusalV2::InvalidBinding)?
            .to_path_buf();
        let receipt_store = layout
            .f6_path_v4(receipt_role)
            .ok_or(ProductionF6ActivationRefusalV2::InvalidBinding)?
            .to_path_buf();
        let candidate_book = layout
            .f6_path_v4(candidate_role)
            .ok_or(ProductionF6ActivationRefusalV2::InvalidBinding)?
            .to_path_buf();
        if [
            binding_log.as_path(),
            receipt_store.as_path(),
            candidate_book.as_path(),
        ]
        .iter()
        .any(|path| !path.is_absolute())
            || binding_log == receipt_store
            || binding_log == candidate_book
            || receipt_store == candidate_book
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        Ok(Self {
            binding_log,
            receipt_store,
            candidate_book,
        })
    }

    fn borrowed(&self) -> ProductionF6PathsV2<'_> {
        ProductionF6PathsV2 {
            binding_log: &self.binding_log,
            receipt_store: &self.receipt_store,
            candidate_book: &self.candidate_book,
        }
    }
}

impl core::fmt::Debug for ProductionF6ActivationPathsV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionF6ActivationPathsV2([paths redacted])")
    }
}

/// Move-only, fully assembled activation factory for one F6 position.
///
/// Construction requires the concrete shared stores, current authority sets,
/// candidate signer producer, adapter terms authority and terminal route
/// authority already bundled in [`ProductionF6AuthoritiesV2`]. There is no
/// constructor taking booleans, digests, decoded files or generic signers.
pub(crate) struct ProductionReadyF6ActivationAuthorityV2 {
    binding: ProductionSolverF6BindingV2,
    solver: rfq::ParticipantId,
    dom_chain_id: rfq::ChainId,
    paths: ProductionF6ActivationPathsV2,
    mode: ProductionF6ActivationOpenModeV2,
    authorities: Option<ProductionF6AuthoritiesV2>,
    poisoned: bool,
}

impl core::fmt::Debug for ProductionReadyF6ActivationAuthorityV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionReadyF6ActivationAuthorityV2")
            .field("mode", &self.mode)
            .field("consumed", &self.authorities.is_none())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl ProductionReadyF6ActivationAuthorityV2 {
    /// Freezes the exact typed graph. The RFQ is reauthenticated on every
    /// activation attempt before this graph can be consumed.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn new(
        binding: ProductionSolverF6BindingV2,
        solver: rfq::ParticipantId,
        dom_chain_id: rfq::ChainId,
        paths: ProductionF6ActivationPathsV2,
        mode: ProductionF6ActivationOpenModeV2,
        authorities: ProductionF6AuthoritiesV2,
    ) -> Self {
        Self {
            binding,
            solver,
            dom_chain_id,
            paths,
            mode,
            authorities: Some(authorities),
            poisoned: false,
        }
    }

    fn open(
        mode: ProductionF6ActivationOpenModeV2,
        paths: ProductionF6PathsV2<'_>,
        binding: ProductionSolverF6BindingV2,
        authorities: ProductionF6AuthoritiesV2,
    ) -> Result<ProductionSolverF6AuthorityV2, ProductionF6ErrorV2> {
        match mode {
            ProductionF6ActivationOpenModeV2::Create => {
                ProductionSolverF6AuthorityV2::create_production(paths, binding, authorities)
            }
            ProductionF6ActivationOpenModeV2::OpenExisting => {
                ProductionSolverF6AuthorityV2::open_existing(paths, binding, authorities)
            }
            ProductionF6ActivationOpenModeV2::ResumeCreate => {
                ProductionSolverF6AuthorityV2::resume_create_production(paths, binding, authorities)
            }
            ProductionF6ActivationOpenModeV2::OpenOrResumePrepared(prepared) => {
                ProductionSolverF6AuthorityV2::open_or_resume_prepared_production(
                    paths,
                    prepared,
                    binding,
                    authorities,
                )
            }
        }
    }
}

impl activation_seal::Sealed for ProductionReadyF6ActivationAuthorityV2 {}

impl ProductionF6ActivationAuthorityV2 for ProductionReadyF6ActivationAuthorityV2 {
    fn activate(
        &mut self,
        pending: &AuthenticatedPendingRfqV2,
    ) -> Result<ProductionSolverF6AuthorityV2, ProductionF6ActivationRefusalV2> {
        let rfq = pending.rfq();
        if !self.binding.authenticates_pending_rfq(
            pending.wire(),
            &rfq,
            self.solver,
            self.dom_chain_id,
        ) {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        if self.poisoned {
            return Err(ProductionF6ActivationRefusalV2::Unavailable);
        }
        let authorities = self
            .authorities
            .take()
            .ok_or(ProductionF6ActivationRefusalV2::Unavailable)?;
        match Self::open(self.mode, self.paths.borrowed(), self.binding, authorities) {
            Ok(authority) => Ok(authority),
            Err(error) => {
                self.poisoned = true;
                Err(match error {
                    ProductionF6ErrorV2::InvalidBinding
                    | ProductionF6ErrorV2::InvalidPayload
                    | ProductionF6ErrorV2::WrongRole => {
                        ProductionF6ActivationRefusalV2::InvalidBinding
                    }
                    _ => ProductionF6ActivationRefusalV2::Unavailable,
                })
            }
        }
    }
}

/// All move-only material for one side of the pair activation boundary.
pub(crate) struct ProductionF6PairLegMaterialsV2 {
    position: SettlementPositionV2,
    solver: rfq::ParticipantId,
    dom_chain_id: rfq::ChainId,
    paths: ProductionF6ActivationPathsV2,
    prepared: ProductionF6PreparedBindingsV2,
}

impl ProductionF6PairLegMaterialsV2 {
    pub(crate) fn new(
        position: SettlementPositionV2,
        solver: rfq::ParticipantId,
        dom_chain_id: rfq::ChainId,
        paths: ProductionF6ActivationPathsV2,
        prepared: ProductionF6PreparedBindingsV2,
    ) -> Self {
        Self {
            position,
            solver,
            dom_chain_id,
            paths,
            prepared,
        }
    }
}

impl core::fmt::Debug for ProductionF6PairLegMaterialsV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionF6PairLegMaterialsV2")
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

/// Sole owner request for the two RFQ-dependent F6 authorities and route
/// terminal split. Grouping prevents a constructor with independently
/// reorderable route, inventory and position arguments.
pub(crate) struct ProductionF6PairActivationRequestV2 {
    pub route_store: DurableRouteStoreV1,
    pub route_id: RouteIdV1,
    pub composition_v2_digest: [u8; 32],
    pub upstream: ProductionF6PairLegMaterialsV2,
    pub downstream: ProductionF6PairLegMaterialsV2,
    pub authority_factory: Box<dyn ProductionF6PairAuthoritiesFactoryV2>,
}

pub(crate) mod pair_factory_seal {
    pub trait Sealed {}
}

/// Production-only factory retaining the external F6 authorities until both
/// roster-authenticated RFQs and both route-terminal handles exist.
pub(crate) trait ProductionF6PairAuthoritiesFactoryV2: pair_factory_seal::Sealed {
    /// Authenticates both complete Relay RFQs and derives their RFQ-scoped
    /// pins before any route-terminal handle exists. Implementations must be
    /// one-shot: a successful bind fixes the exact pair later accepted by
    /// `build_authorities` and returns the fencing generation of the inventory
    /// lease acquired only after both RFQs authenticated.
    fn bind_pair(
        &mut self,
        upstream_wire: route_transport::RouteWireContextV1,
        upstream_rfq: RfqV2,
        downstream_wire: route_transport::RouteWireContextV1,
        downstream_rfq: RfqV2,
    ) -> Result<AuthenticatedProductionF6PairBindingV7, ProductionF6ActivationRefusalV2>;

    /// Consumes the two route-terminal handles only after `bind_pair`
    /// succeeded and the caller rechecked both returned bindings against the
    /// authenticated Relay messages.
    fn build_authorities(
        &mut self,
        upstream_binding: ProductionSolverF6BindingV2,
        upstream_terminal: ProductionRouteTerminalAuthorityV2,
        downstream_binding: ProductionSolverF6BindingV2,
        downstream_terminal: ProductionRouteTerminalAuthorityV2,
    ) -> Result<
        (ProductionF6AuthoritiesV2, ProductionF6AuthoritiesV2),
        ProductionF6ActivationRefusalV2,
    >;
}

struct ProductionF6PairActivationStateV2 {
    route_store: Option<DurableRouteStoreV1>,
    route_id: RouteIdV1,
    composition_v2_digest: [u8; 32],
    upstream_solver: rfq::ParticipantId,
    downstream_solver: rfq::ParticipantId,
    dom_chain_id: rfq::ChainId,
    upstream_binding: Option<ProductionSolverF6BindingV2>,
    downstream_binding: Option<ProductionSolverF6BindingV2>,
    upstream_wire: Option<route_transport::RouteWireContextV1>,
    downstream_wire: Option<route_transport::RouteWireContextV1>,
    upstream_rfq: Option<RfqV2>,
    downstream_rfq: Option<RfqV2>,
    authority_factory: Option<Box<dyn ProductionF6PairAuthoritiesFactoryV2>>,
    upstream_ready: Option<ProductionF6AuthoritiesV2>,
    downstream_ready: Option<ProductionF6AuthoritiesV2>,
    upstream_active: bool,
    downstream_active: bool,
    runtime: Option<ProductionRouteStoreRuntimeAuthorityV2>,
    poisoned: bool,
}

/// One position's handle into the shared pair activation state. The first RFQ
/// remains pending; only the arrival of the exact complementary RFQ can split
/// the route store and make either concrete F6 authority constructible.
pub(crate) struct ProductionF6PairActivationAuthorityV2 {
    position: SettlementPositionV2,
    solver: rfq::ParticipantId,
    dom_chain_id: rfq::ChainId,
    paths: ProductionF6ActivationPathsV2,
    prepared: ProductionF6PreparedBindingsV2,
    state: Rc<RefCell<ProductionF6PairActivationStateV2>>,
    provenance: ProductionF6PairProvenanceV2,
    consumed: bool,
}

/// Purpose-limited receiver for the runtime route-store handle. It cannot
/// expose the store until both position authorities opened successfully.
pub(crate) struct ProductionF6PairRuntimeReceiverV2 {
    state: Rc<RefCell<ProductionF6PairActivationStateV2>>,
    provenance: ProductionF6PairProvenanceV2,
}

impl core::fmt::Debug for ProductionF6PairActivationAuthorityV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionF6PairActivationAuthorityV2")
            .field("position", &self.position)
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for ProductionF6PairRuntimeReceiverV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionF6PairRuntimeReceiverV2([authority redacted])")
    }
}

impl ProductionF6PairActivationRequestV2 {
    pub(crate) fn into_authorities(
        self,
    ) -> Result<
        (
            ProductionF6PairActivationAuthorityV2,
            ProductionF6PairActivationAuthorityV2,
            ProductionF6PairRuntimeReceiverV2,
        ),
        ProductionF6ActivationRefusalV2,
    > {
        if self.route_id == [0; 32]
            || self.composition_v2_digest == [0; 32]
            || self.upstream.position != SettlementPositionV2::Upstream
            || self.downstream.position != SettlementPositionV2::Downstream
            || self.upstream.dom_chain_id != self.downstream.dom_chain_id
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let state = Rc::new(RefCell::new(ProductionF6PairActivationStateV2 {
            route_store: Some(self.route_store),
            route_id: self.route_id,
            composition_v2_digest: self.composition_v2_digest,
            upstream_solver: self.upstream.solver,
            downstream_solver: self.downstream.solver,
            dom_chain_id: self.upstream.dom_chain_id,
            upstream_binding: None,
            downstream_binding: None,
            upstream_wire: None,
            downstream_wire: None,
            upstream_rfq: None,
            downstream_rfq: None,
            authority_factory: Some(self.authority_factory),
            upstream_ready: None,
            downstream_ready: None,
            upstream_active: false,
            downstream_active: false,
            runtime: None,
            poisoned: false,
        }));
        let provenance = ProductionF6PairProvenanceV2::new();
        let upstream = ProductionF6PairActivationAuthorityV2 {
            position: self.upstream.position,
            solver: self.upstream.solver,
            dom_chain_id: self.upstream.dom_chain_id,
            paths: self.upstream.paths,
            prepared: self.upstream.prepared,
            state: Rc::clone(&state),
            provenance: provenance.fork(),
            consumed: false,
        };
        let downstream = ProductionF6PairActivationAuthorityV2 {
            position: self.downstream.position,
            solver: self.downstream.solver,
            dom_chain_id: self.downstream.dom_chain_id,
            paths: self.downstream.paths,
            prepared: self.downstream.prepared,
            state: Rc::clone(&state),
            provenance: provenance.fork(),
            consumed: false,
        };
        Ok((
            upstream,
            downstream,
            ProductionF6PairRuntimeReceiverV2 { state, provenance },
        ))
    }
}

impl ProductionF6PairActivationAuthorityV2 {
    pub(crate) fn provenance(&self) -> ProductionF6PairProvenanceV2 {
        self.provenance.fork()
    }
}

impl ProductionF6PairActivationStateV2 {
    fn register(
        &mut self,
        position: SettlementPositionV2,
        wire: route_transport::RouteWireContextV1,
        rfq: RfqV2,
    ) -> Result<(), ProductionF6ActivationRefusalV2> {
        if self.poisoned {
            return Err(ProductionF6ActivationRefusalV2::Unavailable);
        }
        let (wire_slot, rfq_slot) = match position {
            SettlementPositionV2::Upstream => (&mut self.upstream_wire, &mut self.upstream_rfq),
            SettlementPositionV2::Downstream => {
                (&mut self.downstream_wire, &mut self.downstream_rfq)
            }
        };
        match (*wire_slot, *rfq_slot) {
            (Some(existing), Some(existing_rfq)) if existing == wire && existing_rfq == rfq => {}
            (Some(_), Some(_)) | (Some(_), None) | (None, Some(_)) => {
                self.poisoned = true;
                return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
            }
            (None, None) => {
                *wire_slot = Some(wire);
                *rfq_slot = Some(rfq);
            }
        }
        self.complete_pair_if_ready()
    }

    fn complete_pair_if_ready(&mut self) -> Result<(), ProductionF6ActivationRefusalV2> {
        if self.runtime.is_some() {
            return Ok(());
        }
        let Some((upstream_wire, downstream_wire, upstream_rfq, downstream_rfq)) =
            complete_pair_inputs(
                self.upstream_wire,
                self.downstream_wire,
                self.upstream_rfq,
                self.downstream_rfq,
            )
        else {
            return Ok(());
        };
        let mut factory = self
            .authority_factory
            .take()
            .ok_or(ProductionF6ActivationRefusalV2::Unavailable)?;
        let authenticated_pair =
            match factory.bind_pair(upstream_wire, upstream_rfq, downstream_wire, downstream_rfq) {
                Ok(bindings) => bindings,
                Err(error) => {
                    self.poisoned = true;
                    return Err(error);
                }
            };
        let (upstream, downstream, inventory_fencing_epoch) = authenticated_pair.into_parts();
        if !upstream.authenticates_pending_rfq(
            upstream_wire,
            &upstream_rfq,
            self.upstream_solver,
            self.dom_chain_id,
        ) || !downstream.authenticates_pending_rfq(
            downstream_wire,
            &downstream_rfq,
            self.downstream_solver,
            self.dom_chain_id,
        ) {
            self.poisoned = true;
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let store = self
            .route_store
            .take()
            .ok_or(ProductionF6ActivationRefusalV2::Unavailable)?;
        let terminal_owner = match ProductionRouteTerminalAuthorityOwnerV2::new(
            store,
            self.route_id,
            self.composition_v2_digest,
            inventory_fencing_epoch,
            upstream,
            downstream,
        ) {
            Ok(owner) => owner,
            Err(_) => {
                self.poisoned = true;
                return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
            }
        };
        let (runtime, upstream_terminal, downstream_terminal) = terminal_owner.into_handles();
        let (upstream_authorities, downstream_authorities) = match factory.build_authorities(
            upstream,
            upstream_terminal,
            downstream,
            downstream_terminal,
        ) {
            Ok(authorities) => authorities,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        self.upstream_ready = Some(upstream_authorities);
        self.downstream_ready = Some(downstream_authorities);
        self.upstream_binding = Some(upstream);
        self.downstream_binding = Some(downstream);
        self.runtime = Some(runtime);
        Ok(())
    }

    fn take_bound_authorities(
        &mut self,
        position: SettlementPositionV2,
    ) -> Result<
        (ProductionSolverF6BindingV2, ProductionF6AuthoritiesV2),
        ProductionF6ActivationRefusalV2,
    > {
        let other = match position {
            SettlementPositionV2::Upstream => SettlementPositionV2::Downstream,
            SettlementPositionV2::Downstream => SettlementPositionV2::Upstream,
        };
        let (binding_slot, authority_slot) = match position {
            SettlementPositionV2::Upstream => {
                (&mut self.upstream_binding, &mut self.upstream_ready)
            }
            SettlementPositionV2::Downstream => {
                (&mut self.downstream_binding, &mut self.downstream_ready)
            }
        };
        match (binding_slot.take(), authority_slot.take()) {
            (Some(binding), Some(authorities)) => return Ok((binding, authorities)),
            (Some(binding), None) => {
                *binding_slot = Some(binding);
                return Err(ProductionF6ActivationRefusalV2::Unavailable);
            }
            (None, Some(authorities)) => {
                *authority_slot = Some(authorities);
                return Err(ProductionF6ActivationRefusalV2::Unavailable);
            }
            (None, None) => {}
        }
        if self.runtime.is_none() {
            Err(ProductionF6ActivationRefusalV2::Awaiting(
                crate::production_f6_lifecycle::ProductionPendingAuthorityV1::AuthenticatedRfq {
                    position: other,
                },
            ))
        } else {
            Err(ProductionF6ActivationRefusalV2::Unavailable)
        }
    }

    fn mark_active(&mut self, position: SettlementPositionV2) {
        match position {
            SettlementPositionV2::Upstream => self.upstream_active = true,
            SettlementPositionV2::Downstream => self.downstream_active = true,
        }
    }
}

/// Returns pair material only when each position has both authenticated wire
/// context and decoded RFQ. Keeping the four-way gate in one function makes it
/// impossible for a one-sided delivery to reach `bind_pair` or the terminal
/// route-store split through a partial pattern match.
fn complete_pair_inputs<Wire: Copy, Rfq: Copy>(
    upstream_wire: Option<Wire>,
    downstream_wire: Option<Wire>,
    upstream_rfq: Option<Rfq>,
    downstream_rfq: Option<Rfq>,
) -> Option<(Wire, Wire, Rfq, Rfq)> {
    Some((
        upstream_wire?,
        downstream_wire?,
        upstream_rfq?,
        downstream_rfq?,
    ))
}

impl ProductionF6PairRuntimeReceiverV2 {
    pub(crate) fn matches_provenance(&self, provenance: &ProductionF6PairProvenanceV2) -> bool {
        self.provenance.matches(provenance)
    }

    pub(crate) fn take_ready(
        &mut self,
    ) -> Result<ProductionRouteStoreRuntimeAuthorityV2, ProductionF6ActivationRefusalV2> {
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
        if !state.upstream_active || !state.downstream_active {
            return Err(ProductionF6ActivationRefusalV2::Awaiting(
                crate::production_f6_lifecycle::ProductionPendingAuthorityV1::F6Activation {
                    position: if state.upstream_active {
                        SettlementPositionV2::Downstream
                    } else {
                        SettlementPositionV2::Upstream
                    },
                },
            ));
        }
        state
            .runtime
            .take()
            .ok_or(ProductionF6ActivationRefusalV2::Unavailable)
    }
}

impl activation_seal::Sealed for ProductionF6PairActivationAuthorityV2 {}

impl ProductionF6ActivationAuthorityV2 for ProductionF6PairActivationAuthorityV2 {
    fn activate(
        &mut self,
        pending: &AuthenticatedPendingRfqV2,
    ) -> Result<ProductionSolverF6AuthorityV2, ProductionF6ActivationRefusalV2> {
        if self.consumed {
            return Err(ProductionF6ActivationRefusalV2::Unavailable);
        }
        let rfq: RfqV2 = pending.rfq();
        if rfq.route.position != self.position {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let (binding, authorities) = {
            let mut state = self
                .state
                .try_borrow_mut()
                .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
            state.register(self.position, pending.wire(), rfq)?;
            state.take_bound_authorities(self.position)?
        };
        if !binding.authenticates_pending_rfq(pending.wire(), &rfq, self.solver, self.dom_chain_id)
        {
            if let Ok(mut state) = self.state.try_borrow_mut() {
                state.poisoned = true;
            }
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let authority = match ProductionSolverF6AuthorityV2::open_or_resume_prepared_production(
            self.paths.borrowed(),
            self.prepared,
            binding,
            authorities,
        ) {
            Ok(authority) => authority,
            Err(error) => {
                if let Ok(mut state) = self.state.try_borrow_mut() {
                    state.poisoned = true;
                }
                return Err(match error {
                    ProductionF6ErrorV2::InvalidBinding
                    | ProductionF6ErrorV2::InvalidPayload
                    | ProductionF6ErrorV2::WrongRole => {
                        ProductionF6ActivationRefusalV2::InvalidBinding
                    }
                    _ => ProductionF6ActivationRefusalV2::Unavailable,
                });
            }
        };
        self.state
            .try_borrow_mut()
            .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?
            .mark_active(self.position);
        self.consumed = true;
        Ok(authority)
    }
}

#[cfg(test)]
mod tests {
    use super::complete_pair_inputs;

    #[test]
    fn terminal_split_remains_unreachable_until_both_authenticated_rfq_pairs_exist() {
        assert_eq!(complete_pair_inputs(Some(1), None, Some(3), None), None);
        assert_eq!(complete_pair_inputs(Some(1), Some(2), Some(3), None), None);
        assert_eq!(complete_pair_inputs(Some(1), Some(2), None, Some(4)), None);
        assert_eq!(
            complete_pair_inputs(Some(1), Some(2), Some(3), Some(4)),
            Some((1, 2, 3, 4))
        );
    }
}
