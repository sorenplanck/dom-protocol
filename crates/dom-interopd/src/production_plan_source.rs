//! Route-bound production plan source and the public-secret handoff.
//!
//! The route journal records `SecretObserved` before this source can see a
//! public scalar: the only extraction path accepts a
//! [`RouteActionAuthorizationRequestV1`] whose authenticated snapshot already
//! says `SecretVisibilityV1::Public`. The canonical chain is always attempted
//! first. A successfully extracted scalar is sealed and fsynced in the
//! route-secret vault, reopened under every exact exposure binding, checked
//! against the V2 composition's `T`, and only then moved into the upstream
//! materializer. If a later reorg makes canonical re-extraction unavailable,
//! the exact sealed record is the only recovery fallback.
//!
//! The production settlement bridge also invokes
//! [`ProductionSettlementPlanSourceV1::seal_first_public_exposure`] on every
//! new or replayed coordinator outcome containing the first exposure, before
//! that outcome can reach the supervisor. Consequently the supervisor cannot
//! commit `SecretObserved/Public` ahead of the fsynced seal. A crash before the
//! seal leaves the coordinator receipt replayable but the route private. A
//! crash after the seal may recover that exact record while the route is still
//! private only when the durable coordinator supplies its move-only, fully
//! audited first-exposure capability. Generic caller-shaped or vault-only
//! private recovery remains forbidden. Once the route journal is `Public`, its
//! authenticated snapshot independently authorizes the same exact-record
//! recovery path.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use adapter_dom_real::{RealDomClaimConsumerV1, RealDomClaimVerifierV1, RealDomRpcRuntimeV1};
use adapter_evm::{evm_counterparty_chain_id, EvidenceKind, EvmAdapter, JsonRpc, LockTerms};
use counterparty_api::{AdapterError, RevealedSecretBytes, VerifiedOutcome};
use dom_actuator::{
    DomActuatorError, DomClaimCustodyClassificationV1, DomContractsActuatorV1, DomSessionBindingV1,
};
use dom_adaptor::TrustedChainIdV1;
use dom_scriptless_store::ContractsSessionStoreV1;
use route_composer::{ComposedBindingV2, RouteScalar};
use route_executor::{
    ActionKindV1, Digest32, FrozenBindingsV1, LegIdV1, PublicExposureV1, RouteIdV1,
    RouteSecretRetirementCapabilityV1, SecretVisibilityV1,
};
use route_secret_vault::{
    DurableRouteSecretVaultV1, RouteSecretBindingsV2, RouteSecretExposureSourceV2,
    RouteSecretExposureV2, RouteSecretSealKeyV1, RouteSecretVaultError,
};
use settlement_coordinator::{
    AuthenticatedCoordinatorExposureV1, ChildExposureV1, DeferredChildMaterializationCapabilityV1,
    DeferredChildMaterializationResultV1, SecretRequirementV1, SettlementChildPlanV1,
    SettlementChildrenV1, SettlementLegV1,
};
use zeroize::{Zeroize, Zeroizing};

use crate::production_child_btc::ProductionBitcoinPublicExtractionHandoffV1;
use crate::production_child_router::ProductionChildMaterializationRequestV1;
use crate::production_settlement::{
    ProductionSettlementPlanDraftV1, ProductionSettlementPlanSourceV1,
};
use crate::supervisor::{AuthorityRefusalV1, RouteActionAuthorizationRequestV1};

const ZERO_DIGEST: Digest32 = [0; 32];

const fn route_secret_exposure_source(
    source: route_executor::ExposureSourceV1,
) -> RouteSecretExposureSourceV2 {
    match source {
        route_executor::ExposureSourceV1::Mempool => RouteSecretExposureSourceV2::Mempool,
        route_executor::ExposureSourceV1::Externalized => RouteSecretExposureSourceV2::Externalized,
        route_executor::ExposureSourceV1::Block => RouteSecretExposureSourceV2::Block,
        route_executor::ExposureSourceV1::PeerEvidence => RouteSecretExposureSourceV2::PeerEvidence,
    }
}

/// Encrypted, fsync-before-use retention for one process's public scalars.
///
/// The sealing key remains a move-only in-memory authority. Neither this type
/// nor its debug surface exposes key or scalar bytes.
pub(crate) struct ProductionPublicSecretRetentionV1 {
    vault: DurableRouteSecretVaultV1,
    key: RouteSecretSealKeyV1,
}

enum VaultRecoveryAuthorizationV1<'authority> {
    #[expect(
        dead_code,
        reason = "EVM public-secret re-extraction surface excluded by the stage-7 composition"
    )]
    CanonicalOnly,
    AuthenticatedPublicSnapshot,
    AuthenticatedCoordinatorExposure(&'authority AuthenticatedCoordinatorExposureV1),
}

impl core::fmt::Debug for ProductionPublicSecretRetentionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionPublicSecretRetentionV1([authorities redacted])")
    }
}

impl ProductionPublicSecretRetentionV1 {
    pub(crate) const fn new(vault: DurableRouteSecretVaultV1, key: RouteSecretSealKeyV1) -> Self {
        Self { vault, key }
    }

    fn obtain_after_canonical_attempt(
        &self,
        bindings: &RouteSecretBindingsV2,
        canonical: Result<RevealedSecretBytes, AuthorityRefusalV1>,
        recovery: VaultRecoveryAuthorizationV1<'_>,
    ) -> Result<RevealedSecretBytes, AuthorityRefusalV1> {
        if let VaultRecoveryAuthorizationV1::AuthenticatedCoordinatorExposure(authority) = &recovery
        {
            let exposure = authority.exposure();
            if authority.route_id() != *bindings.route_id()
                || exposure.chain_id != *bindings.chain_id()
                || exposure.transaction_id != *bindings.tx_id()
                || exposure.evidence_digest != *bindings.exposure_evidence_digest()
                || bindings.exposure_source() != RouteSecretExposureSourceV2::Externalized
                || exposure.observed_at_unix_ms != bindings.observed_at_unix_ms()
            {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
        }
        match canonical {
            Ok(revealed) => {
                self.vault
                    .put(&self.key, bindings, revealed)
                    .map_err(map_route_secret_vault_error)?;
                self.vault
                    .read(&self.key, bindings)
                    .map_err(map_route_secret_vault_error)
            }
            Err(AuthorityRefusalV1::Unavailable)
                if matches!(
                    &recovery,
                    &VaultRecoveryAuthorizationV1::AuthenticatedPublicSnapshot
                ) =>
            {
                self.vault.read(&self.key, bindings).map_err(|error| {
                    if error == RouteSecretVaultError::NotFound {
                        // An authenticated Public snapshot can exist only
                        // after `seal_first_public_exposure` durably published
                        // this exact record. Absence here is lost/corrupt
                        // invariant state, never a transient chain outage.
                        AuthorityRefusalV1::Inconsistent
                    } else {
                        map_route_secret_vault_error(error)
                    }
                })
            }
            Err(AuthorityRefusalV1::Unavailable)
                if matches!(
                    &recovery,
                    &VaultRecoveryAuthorizationV1::AuthenticatedCoordinatorExposure(_)
                ) =>
            {
                self.vault.read(&self.key, bindings).map_err(|error| {
                    if error == RouteSecretVaultError::NotFound {
                        // The coordinator proves the exposure, not that this
                        // process completed its pre-release seal. Never turn
                        // an absent seal into a generic private fallback.
                        AuthorityRefusalV1::Inconsistent
                    } else {
                        map_route_secret_vault_error(error)
                    }
                })
            }
            Err(other) => Err(other),
        }
    }

    pub(crate) fn retire_after_authenticated_route_completion(
        &self,
        capability: &RouteSecretRetirementCapabilityV1,
    ) -> Result<(), AuthorityRefusalV1> {
        self.vault
            .retire(&self.key, capability)
            .map(|_| ())
            .map_err(map_route_secret_vault_error)
    }
}

fn map_route_secret_vault_error(error: RouteSecretVaultError) -> AuthorityRefusalV1 {
    match error {
        RouteSecretVaultError::Filesystem
        | RouteSecretVaultError::StoreBusy
        | RouteSecretVaultError::RandomFailure
        | RouteSecretVaultError::NotFound => AuthorityRefusalV1::Unavailable,
        RouteSecretVaultError::InvalidInput
        | RouteSecretVaultError::AuthenticationFailed
        | RouteSecretVaultError::Conflict
        | RouteSecretVaultError::UnsupportedSchema
        | RouteSecretVaultError::Retired => AuthorityRefusalV1::Inconsistent,
    }
}

/// Exact public observation from which a chain authority must re-extract `t`.
///
/// The request contains no scalar.  Its route and composition commitments stop
/// a source installed for one route from answering for another route that
/// happens to observe the same transaction.
pub(crate) struct ProductionPublicSecretRequestV1<'a> {
    route_id: RouteIdV1,
    composition_digest: Digest32,
    exposure: &'a PublicExposureV1,
}

impl core::fmt::Debug for ProductionPublicSecretRequestV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionPublicSecretRequestV1")
            .field("route_id", &self.route_id)
            .field("composition_digest", &self.composition_digest)
            .field("exposure", &self.exposure)
            .finish()
    }
}

impl<'a> ProductionPublicSecretRequestV1<'a> {
    pub(crate) fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }

    pub(crate) fn composition_digest(&self) -> Digest32 {
        self.composition_digest
    }

    pub(crate) const fn exposure(&self) -> &'a PublicExposureV1 {
        self.exposure
    }
}

/// Chain-specific, restart-safe re-extraction of a scalar already public.
///
/// Implementations must re-read authenticated chain evidence.  A memory cache
/// may accelerate the call but may never be its recovery authority.
pub(crate) trait ProductionPublicSecretSourceV1 {
    fn reextract_public_secret(
        &mut self,
        request: ProductionPublicSecretRequestV1<'_>,
    ) -> Result<RevealedSecretBytes, AuthorityRefusalV1>;
}

/// One exact chain's public-secret re-extraction authority.
pub(crate) trait ProductionChainPublicSecretSourceV1 {
    /// Authenticated chain identity accepted by this authority.
    fn chain_id(&self) -> Digest32;

    /// Re-extract from the exact public observation or fail closed.
    fn reextract_for_chain(
        &mut self,
        request: ProductionPublicSecretRequestV1<'_>,
    ) -> Result<RevealedSecretBytes, AuthorityRefusalV1>;
}

/// Closed, move-only handoff from the DOM child composition into the sole DOM
/// public-secret source constructor.
///
/// This type intentionally has no operation that returns or borrows its
/// `RealDomClaimConsumerV1`.  Only
/// [`ProductionDomPublicSecretSourceV1::from_dom_child_consumer_authority`]
/// can consume it, after crossing the Contracts owner's exact Store opening
/// with the route composition, leg, settlement, session and trusted-chain
/// pins.  Consequently no composition-root callsite can invoke
/// `RealDomClaimConsumerV1::consume` directly.
pub(crate) struct ProductionDomPublicSecretConsumerAuthorityV1 {
    composition_digest: Digest32,
    leg: SettlementLegV1,
    settlement_id: Digest32,
    binding: DomSessionBindingV1,
    trusted_chain_id: TrustedChainIdV1,
    consumer: RealDomClaimConsumerV1,
}

impl core::fmt::Debug for ProductionDomPublicSecretConsumerAuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionDomPublicSecretConsumerAuthorityV1([authority redacted])")
    }
}

impl ProductionDomPublicSecretConsumerAuthorityV1 {
    /// Minted only by the DOM child composition from the same shared runtime
    /// and exact per-session verifier installed in the child port.
    pub(crate) fn authenticate(
        composition_digest: Digest32,
        leg: SettlementLegV1,
        settlement_id: Digest32,
        binding: DomSessionBindingV1,
        trusted_chain_id: TrustedChainIdV1,
        runtime: Arc<RealDomRpcRuntimeV1>,
        verifier: Arc<RealDomClaimVerifierV1>,
    ) -> Result<Self, AuthorityRefusalV1> {
        let expected_identity = binding
            .expected_dom_identity()
            .map_err(map_dom_secret_source_error)?;
        if composition_digest == ZERO_DIGEST
            || settlement_id == ZERO_DIGEST
            || trusted_chain_id.as_bytes() != &binding.chain_id()
            || runtime.expected_identity() != &expected_identity
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(Self {
            composition_digest,
            leg,
            settlement_id,
            binding,
            trusted_chain_id,
            consumer: RealDomClaimConsumerV1::new(runtime, verifier),
        })
    }
}

/// Exact-scope predicate shared by the closed handoff and its adversarial
/// tests.  Production supplies a complete `DomSessionBindingV1`; the generic
/// equality parameters let tests vary every pin without manufacturing a
/// second RPC runtime, verifier, consumer, or Store.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
)]
fn exact_dom_public_secret_consumer_scope_v1<B: PartialEq, T: PartialEq>(
    retained_composition_digest: Digest32,
    retained_leg: SettlementLegV1,
    retained_settlement_id: Digest32,
    retained_binding: &B,
    retained_trusted_chain: &T,
    expected_composition_digest: Digest32,
    expected_leg: SettlementLegV1,
    expected_settlement_id: Digest32,
    expected_binding: &B,
    expected_trusted_chain: &T,
) -> bool {
    retained_composition_digest == expected_composition_digest
        && retained_leg == expected_leg
        && retained_settlement_id == expected_settlement_id
        && retained_binding == expected_binding
        && retained_trusted_chain == expected_trusted_chain
}

/// Contracts-owner request for opening one exact DOM public-secret source.
/// Route and chain identity are derived from the authenticated session binding
/// rather than accepted as independent caller-shaped values.
pub(crate) struct ProductionDomPublicSecretSourceScopeV1 {
    composition_digest: Digest32,
    leg: SettlementLegV1,
    settlement_id: Digest32,
    binding: DomSessionBindingV1,
    trusted_chain_id: TrustedChainIdV1,
}

impl ProductionDomPublicSecretSourceScopeV1 {
    pub(crate) fn authenticate(
        composition_digest: Digest32,
        leg: SettlementLegV1,
        settlement_id: Digest32,
        binding: DomSessionBindingV1,
        trusted_chain_id: TrustedChainIdV1,
    ) -> Result<Self, AuthorityRefusalV1> {
        if composition_digest == ZERO_DIGEST
            || leg != SettlementLegV1::Downstream
            || settlement_id == ZERO_DIGEST
            || trusted_chain_id.as_bytes() != &binding.chain_id()
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(Self {
            composition_digest,
            leg,
            settlement_id,
            binding,
            trusted_chain_id,
        })
    }

    pub(crate) const fn binding(&self) -> DomSessionBindingV1 {
        self.binding
    }

    pub(crate) const fn trusted_chain_id(&self) -> TrustedChainIdV1 {
        self.trusted_chain_id
    }
}

struct ProductionPendingDomPublicSecretSourceV1 {
    route_id: RouteIdV1,
    composition_digest: Digest32,
    leg: SettlementLegV1,
    #[expect(
        dead_code,
        reason = "EVM public-secret re-extraction surface excluded by the stage-7 composition"
    )]
    settlement_id: Digest32,
    chain_id: Digest32,
    store: Rc<ContractsSessionStoreV1>,
    binding: DomSessionBindingV1,
    trusted_chain_id: TrustedChainIdV1,
    consumer: RealDomClaimConsumerV1,
}

struct ProductionInstalledDomPublicSecretSourceV1 {
    route_id: RouteIdV1,
    composition_digest: Digest32,
    chain_id: Digest32,
    expected_claim_transaction_id: Digest32,
    store: Rc<ContractsSessionStoreV1>,
    binding: DomSessionBindingV1,
    trusted_chain_id: TrustedChainIdV1,
    consumer: RealDomClaimConsumerV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProductionInstalledDomChildPlanV1 {
    request: ProductionChildMaterializationRequestV1,
    plan: SettlementChildPlanV1,
}

enum ProductionLateDomSecretSlotStateV1 {
    Pending(Option<ProductionPendingDomPublicSecretSourceV1>),
    Installed {
        exact: Box<ProductionInstalledDomChildPlanV1>,
        source: ProductionInstalledDomPublicSecretSourceV1,
    },
}

struct ProductionLateDomSecretSlotV1 {
    route_id: RouteIdV1,
    composition_digest: Digest32,
    leg: SettlementLegV1,
    settlement_id: Digest32,
    chain_id: Digest32,
    binding: DomSessionBindingV1,
    trusted_chain_id: TrustedChainIdV1,
    state: RefCell<ProductionLateDomSecretSlotStateV1>,
}

/// Move-only authority retained by the settlement materializer. The exact DOM
/// claim transaction is learned only from the real child plan produced for the
/// retained `FirstSecretExposure` request.
pub(crate) struct ProductionDomPublicSecretInstallerV1 {
    shared: Rc<ProductionLateDomSecretSlotV1>,
}

/// Startup-safe DOM public-secret source. Before its paired installer accepts
/// the exact child materialization, re-extraction is deliberately unavailable.
pub(crate) struct ProductionDomPublicSecretSourceV1 {
    shared: Rc<ProductionLateDomSecretSlotV1>,
}

impl core::fmt::Debug for ProductionDomPublicSecretInstallerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionDomPublicSecretInstallerV1([authority redacted])")
    }
}

impl core::fmt::Debug for ProductionDomPublicSecretSourceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionDomPublicSecretSourceV1([authority redacted])")
    }
}

/// Restart-safe installed DOM receiver authority for one exact observed
/// `FinalClaim`.
///
/// The source retains an [`Rc`] clone of the composition root's already-open
/// Contracts Store; it cannot open a second store. Every extraction resumes
/// the Store-minted observation token, rechecks its receiver role, session,
/// authenticated chain and exact claim transaction, and only then invokes the
/// real DOM consumer. The coordinator exposure digest comes only from the
/// authenticated route snapshot. It is deliberately not accepted as a
/// constructor parameter and not compared with the Store observation digest:
/// those are distinct commitment domains. The V2 retention record binds both
/// independently verified transaction identity and the snapshot's exact
/// exposure facts.
impl ProductionDomPublicSecretSourceV1 {
    /// Called only by `ProductionContractsV1`, after it has supplied an `Rc`
    /// clone of its already-open Store. The consumer came from the same DOM
    /// child runtime and remains parked in the shared slot until installation.
    pub(crate) fn new_installable(
        store: Rc<ContractsSessionStoreV1>,
        scope: ProductionDomPublicSecretSourceScopeV1,
        authority: ProductionDomPublicSecretConsumerAuthorityV1,
    ) -> Result<(Self, ProductionDomPublicSecretInstallerV1), AuthorityRefusalV1> {
        if !exact_dom_public_secret_consumer_scope_v1(
            authority.composition_digest,
            authority.leg,
            authority.settlement_id,
            &authority.binding,
            authority.trusted_chain_id.as_bytes(),
            scope.composition_digest,
            scope.leg,
            scope.settlement_id,
            &scope.binding,
            scope.trusted_chain_id.as_bytes(),
        ) {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let ProductionDomPublicSecretConsumerAuthorityV1 {
            composition_digest,
            leg,
            settlement_id,
            binding,
            trusted_chain_id,
            consumer,
        } = authority;
        let route_id = binding.route_id();
        let chain_id = *trusted_chain_id.as_bytes();
        if [route_id, composition_digest, settlement_id, chain_id].contains(&ZERO_DIGEST)
            || leg != SettlementLegV1::Downstream
            || binding.chain_id() != chain_id
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        DomContractsActuatorV1::bind(store.as_ref(), binding)
            .map_err(map_dom_secret_source_error)?;
        let pending = ProductionPendingDomPublicSecretSourceV1 {
            route_id,
            composition_digest,
            leg,
            settlement_id,
            chain_id,
            store,
            binding,
            trusted_chain_id,
            consumer,
        };
        let shared = Rc::new(ProductionLateDomSecretSlotV1 {
            route_id,
            composition_digest,
            leg,
            settlement_id,
            chain_id,
            binding,
            trusted_chain_id,
            state: RefCell::new(ProductionLateDomSecretSlotStateV1::Pending(Some(pending))),
        });
        Ok((
            Self {
                shared: Rc::clone(&shared),
            },
            ProductionDomPublicSecretInstallerV1 { shared },
        ))
    }
}

impl ProductionPendingDomPublicSecretSourceV1 {
    #[expect(
        clippy::result_large_err,
        reason = "the refusal returns the rejected value to its owner; one-shot composition path"
    )]
    fn into_installed(
        self,
        expected_claim_transaction_id: Digest32,
    ) -> Result<ProductionInstalledDomPublicSecretSourceV1, (AuthorityRefusalV1, Self)> {
        if expected_claim_transaction_id == ZERO_DIGEST
            || self.binding.route_id() != self.route_id
            || self.binding.chain_id() != self.chain_id
            || self.leg != SettlementLegV1::Downstream
        {
            return Err((AuthorityRefusalV1::Inconsistent, self));
        }
        if let Err(error) = DomContractsActuatorV1::bind(self.store.as_ref(), self.binding) {
            return Err((map_dom_secret_source_error(error), self));
        }
        Ok(ProductionInstalledDomPublicSecretSourceV1 {
            route_id: self.route_id,
            composition_digest: self.composition_digest,
            chain_id: self.chain_id,
            expected_claim_transaction_id,
            store: self.store,
            binding: self.binding,
            trusted_chain_id: self.trusted_chain_id,
            consumer: self.consumer,
        })
    }
}

impl ProductionDomPublicSecretInstallerV1 {
    pub(crate) fn route_id(&self) -> RouteIdV1 {
        self.shared.route_id
    }

    pub(crate) fn composition_digest(&self) -> Digest32 {
        self.shared.composition_digest
    }

    pub(crate) fn leg(&self) -> SettlementLegV1 {
        self.shared.leg
    }

    pub(crate) fn settlement_id(&self) -> Digest32 {
        self.shared.settlement_id
    }

    pub(crate) fn chain_id(&self) -> Digest32 {
        self.shared.chain_id
    }

    pub(crate) fn binding(&self) -> DomSessionBindingV1 {
        self.shared.binding
    }

    pub(crate) fn trusted_chain_id(&self) -> TrustedChainIdV1 {
        self.shared.trusted_chain_id
    }

    pub(crate) fn install_from_exact_child(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        plan: &SettlementChildPlanV1,
    ) -> Result<(), AuthorityRefusalV1> {
        require_dom_installation_scope(self.shared.as_ref(), request, plan)?;
        let exact = ProductionInstalledDomChildPlanV1 {
            request: *request,
            plan: plan.clone(),
        };
        let mut state = self.shared.state.borrow_mut();
        match &mut *state {
            ProductionLateDomSecretSlotStateV1::Installed {
                exact: retained, ..
            } => {
                if retained.as_ref() == &exact {
                    Ok(())
                } else {
                    Err(AuthorityRefusalV1::Inconsistent)
                }
            }
            ProductionLateDomSecretSlotStateV1::Pending(pending_slot) => {
                let pending = pending_slot.take().ok_or(AuthorityRefusalV1::Unavailable)?;
                match pending.into_installed(plan.expected_transaction_id) {
                    Ok(source) => {
                        *state = ProductionLateDomSecretSlotStateV1::Installed {
                            exact: Box::new(exact),
                            source,
                        };
                        Ok(())
                    }
                    Err((error, restored)) => {
                        *pending_slot = Some(restored);
                        Err(error)
                    }
                }
            }
        }
    }
}

fn require_dom_installation_scope(
    retained: &ProductionLateDomSecretSlotV1,
    request: &ProductionChildMaterializationRequestV1,
    plan: &SettlementChildPlanV1,
) -> Result<(), AuthorityRefusalV1> {
    if retained.leg != SettlementLegV1::Downstream
        || retained.trusted_chain_id.as_bytes() != &retained.chain_id
        || retained.binding.route_id() != retained.route_id
        || retained.binding.chain_id() != retained.chain_id
        || retained.binding.profile_digest() != request.profile_digest
        || retained.binding.deployment_digest() != request.deployment_digest
        || request.route_id != retained.route_id
        || request.composition_digest != retained.composition_digest
        || request.leg != retained.leg
        || request.settlement_id != retained.settlement_id
        || request.action != settlement_coordinator::SettlementActionV1::Claim
        || request.exposure != ChildExposureV1::FirstSecretExposure
        || request.fencing_epoch == 0
        || [
            request.effect_id,
            request.semantic_digest,
            request.terms_digest,
            request.registry_digest,
            request.profile_digest,
            request.deployment_digest,
            request.route_scope_digest,
            request.role_plan_digest,
            request.source_scope_digest,
        ]
        .contains(&ZERO_DIGEST)
        || plan.face != settlement_coordinator::SettlementFaceV1::Dom
        || plan.exposure != ChildExposureV1::FirstSecretExposure
        || plan.chain_id != retained.chain_id
        || [
            plan.expected_transaction_id,
            plan.intent_digest,
            plan.custody_digest,
        ]
        .contains(&ZERO_DIGEST)
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(())
}

impl ProductionChainPublicSecretSourceV1 for ProductionInstalledDomPublicSecretSourceV1 {
    fn chain_id(&self) -> Digest32 {
        self.chain_id
    }

    fn reextract_for_chain(
        &mut self,
        request: ProductionPublicSecretRequestV1<'_>,
    ) -> Result<RevealedSecretBytes, AuthorityRefusalV1> {
        require_dom_public_secret_request(
            self.route_id,
            self.composition_digest,
            self.chain_id,
            self.expected_claim_transaction_id,
            &request,
        )?;
        let actuator = DomContractsActuatorV1::bind(self.store.as_ref(), self.binding)
            .map_err(map_dom_secret_source_error)?;
        match actuator
            .classify_final_claim_receiver_custody_v2(&self.trusted_chain_id)
            .map_err(map_dom_secret_source_error)?
        {
            DomClaimCustodyClassificationV1::PotentiallyExposed => {}
            DomClaimCustodyClassificationV1::Unattempted => {
                return Err(AuthorityRefusalV1::Unavailable);
            }
            DomClaimCustodyClassificationV1::Admitted => {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
        }
        let observed = actuator
            .resume_observed_final_claim_exposure_v2(&self.trusted_chain_id)
            .map_err(map_dom_secret_source_error)?;
        if observed.session_id() != &self.binding.session_id()
            || observed.chain_id() != &self.chain_id
            || observed.tx_hash() != &self.expected_claim_transaction_id
            || observed.observation_record_digest() == &ZERO_DIGEST
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        actuator
            .extract_observed_claim_secret_v2(&self.consumer, &observed)
            .map_err(map_dom_secret_source_error)
    }
}

impl ProductionChainPublicSecretSourceV1 for ProductionDomPublicSecretSourceV1 {
    fn chain_id(&self) -> Digest32 {
        self.shared.chain_id
    }

    fn reextract_for_chain(
        &mut self,
        request: ProductionPublicSecretRequestV1<'_>,
    ) -> Result<RevealedSecretBytes, AuthorityRefusalV1> {
        let mut state = self.shared.state.borrow_mut();
        match &mut *state {
            ProductionLateDomSecretSlotStateV1::Pending(_) => Err(AuthorityRefusalV1::Unavailable),
            ProductionLateDomSecretSlotStateV1::Installed { source, .. } => {
                source.reextract_for_chain(request)
            }
        }
    }
}

fn require_dom_public_secret_request(
    route_id: RouteIdV1,
    composition_digest: Digest32,
    chain_id: Digest32,
    expected_claim_transaction_id: Digest32,
    request: &ProductionPublicSecretRequestV1<'_>,
) -> Result<(), AuthorityRefusalV1> {
    let exposure = request.exposure();
    if request.route_id() != route_id
        || request.composition_digest() != composition_digest
        || exposure.chain_id != chain_id
        || exposure.transaction_id != expected_claim_transaction_id
        || exposure.evidence_digest == ZERO_DIGEST
        || exposure.observed_at_unix_ms == 0
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(())
}

fn map_dom_secret_source_error(error: DomActuatorError) -> AuthorityRefusalV1 {
    match error {
        DomActuatorError::StorageUnavailable
        | DomActuatorError::ProcessLocked
        | DomActuatorError::LeaseHeld
        | DomActuatorError::LeaseExpired
        | DomActuatorError::RevisionConflict
        | DomActuatorError::InvalidStage
        | DomActuatorError::ReconciliationRequired
        | DomActuatorError::FinalityPending
        | DomActuatorError::RpcAuthorityUnavailable
        | DomActuatorError::ContractsAuthorityUnavailable
        | DomActuatorError::CryptoAuthorityUnavailable
        | DomActuatorError::SharedOutputRecoveryIndeterminate => AuthorityRefusalV1::Unavailable,
        DomActuatorError::LinuxRequired
        | DomActuatorError::InvalidStorageAuthority
        | DomActuatorError::DatabasePresent
        | DomActuatorError::DatabaseMissing
        | DomActuatorError::CreationIncomplete
        | DomActuatorError::UnsupportedFormat
        | DomActuatorError::InvalidBinding
        | DomActuatorError::CapabilityMismatch
        | DomActuatorError::StaleFence
        | DomActuatorError::IdempotencyConflict
        | DomActuatorError::OutputReservationConflict
        | DomActuatorError::InsufficientFunds
        | DomActuatorError::WalletUnavailable
        | DomActuatorError::WalletChainMismatch
        | DomActuatorError::SecretReuseDetected
        | DomActuatorError::RefundNotArmed
        | DomActuatorError::ClaimNotPrepared
        | DomActuatorError::ReorgEvidenceRequired
        | DomActuatorError::FinalityEvidenceInvalid
        | DomActuatorError::FinalityPolicyUnsupported
        | DomActuatorError::TerminalStillCanonical
        | DomActuatorError::ReorgBeyondPolicy => AuthorityRefusalV1::Inconsistent,
    }
}

/// Restart-safe EVM extraction authority for one exact route lock.
///
/// It does not trust the adapter's process-local revealed registry. Every call
/// recollects the finalized `Claimed` evidence, checks the exact transaction
/// retained by the route, and runs the adapter's full static plus on-chain
/// verification for the one pre-registered lock before returning the redacted
/// scalar wrapper.
#[expect(
    dead_code,
    reason = "EVM public-secret re-extraction surface excluded by the stage-7 composition"
)]
pub(crate) struct ProductionEvmPublicSecretSourceV1<R: JsonRpc> {
    route_id: RouteIdV1,
    composition_digest: Digest32,
    chain_id: Digest32,
    expected_claim_transaction_id: Digest32,
    lock_id: Digest32,
    adapter: EvmAdapter<R>,
}

impl<R: JsonRpc> core::fmt::Debug for ProductionEvmPublicSecretSourceV1<R> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionEvmPublicSecretSourceV1")
            .field("route_id", &self.route_id)
            .field("composition_digest", &self.composition_digest)
            .field("chain_id", &self.chain_id)
            .field(
                "expected_claim_transaction_id",
                &self.expected_claim_transaction_id,
            )
            .field("lock_id", &self.lock_id)
            .field("adapter", &"<authority redacted>")
            .finish()
    }
}

impl<R: JsonRpc> ProductionEvmPublicSecretSourceV1<R> {
    #[expect(
        dead_code,
        reason = "EVM public-secret re-extraction surface excluded by the stage-7 composition"
    )]
    pub(crate) fn new(
        route_id: RouteIdV1,
        composition_digest: Digest32,
        expected_claim_transaction_id: Digest32,
        adapter: EvmAdapter<R>,
        lock_terms: LockTerms,
    ) -> Result<Self, AuthorityRefusalV1> {
        let chain_id = evm_counterparty_chain_id(adapter.config().chain_id).0;
        if [
            route_id,
            composition_digest,
            chain_id,
            expected_claim_transaction_id,
        ]
        .contains(&ZERO_DIGEST)
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let (_, lock_id) = adapter
            .track_lock(&lock_terms)
            .map_err(map_evm_secret_source_error)?;
        if lock_id == ZERO_DIGEST {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(Self {
            route_id,
            composition_digest,
            chain_id,
            expected_claim_transaction_id,
            lock_id,
            adapter,
        })
    }
}

impl<R: JsonRpc> ProductionChainPublicSecretSourceV1 for ProductionEvmPublicSecretSourceV1<R> {
    fn chain_id(&self) -> Digest32 {
        self.chain_id
    }

    fn reextract_for_chain(
        &mut self,
        request: ProductionPublicSecretRequestV1<'_>,
    ) -> Result<RevealedSecretBytes, AuthorityRefusalV1> {
        let exposure = request.exposure();
        if request.route_id() != self.route_id
            || request.composition_digest() != self.composition_digest
            || exposure.chain_id != self.chain_id
            || exposure.transaction_id != self.expected_claim_transaction_id
            || exposure.evidence_digest == ZERO_DIGEST
            || exposure.observed_at_unix_ms == 0
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let evidence = self
            .adapter
            .collect_evidence(&self.lock_id, EvidenceKind::Claimed)
            .map_err(map_evm_secret_source_error)?;
        if evidence.tx_hash != self.expected_claim_transaction_id
            || evidence.chain_id != self.adapter.config().chain_id
            || evidence.lock_id != self.lock_id
            || evidence.kind != EvidenceKind::Claimed
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        match self
            .adapter
            .verify_evidence_for_lock(&evidence.encode(), &self.lock_id)
            .map_err(map_evm_secret_source_error)?
        {
            VerifiedOutcome::Claimed { revealed, .. } => Ok(revealed),
            VerifiedOutcome::Funded { .. } | VerifiedOutcome::Refunded { .. } => {
                Err(AuthorityRefusalV1::Inconsistent)
            }
        }
    }
}

#[expect(
    dead_code,
    reason = "EVM public-secret re-extraction surface excluded by the stage-7 composition"
)]
fn map_evm_secret_source_error(error: AdapterError) -> AuthorityRefusalV1 {
    match error {
        AdapterError::AdapterUnavailable => AuthorityRefusalV1::Unavailable,
        // Once the route journal says the scalar is public, an absent claim is
        // not permission to fall back to another chain or scalar. It may be an
        // RPC lag or a post-exposure reorg, both of which require recovery.
        AdapterError::PreconditionUnsatisfied | AdapterError::ReorgDetected => {
            AuthorityRefusalV1::Unavailable
        }
        AdapterError::UnsupportedCapability
        | AdapterError::InvalidState
        | AdapterError::EvidenceInvalid
        | AdapterError::StaleCursor
        | AdapterError::VersionMismatch
        | AdapterError::NonCanonicalRetransmission
        | AdapterError::BoundsExceeded => AuthorityRefusalV1::Inconsistent,
    }
}

enum ProductionLateBitcoinSecretSlotStateV1 {
    Vacant,
    Installed(Box<ProductionBitcoinPublicExtractionHandoffV1>),
}

struct ProductionLateBitcoinSecretSlotV1 {
    route_id: RouteIdV1,
    composition_digest: Digest32,
    chain_id: Digest32,
    state: RefCell<ProductionLateBitcoinSecretSlotStateV1>,
}

/// Move-only installation authority retained solely by the materialization
/// owner. It accepts no caller-shaped txid: the exact id comes from both the
/// child plan and the closed handoff, and those values must agree.
pub(crate) struct ProductionBitcoinPublicSecretInstallerV1 {
    shared: Rc<ProductionLateBitcoinSecretSlotV1>,
}

/// Startup-safe Bitcoin source whose exact extraction owner is installed only
/// after fresh claim finalization and durable actuator retention.
pub(crate) struct ProductionLateBitcoinPublicSecretSourceV1 {
    shared: Rc<ProductionLateBitcoinSecretSlotV1>,
}

impl core::fmt::Debug for ProductionBitcoinPublicSecretInstallerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionBitcoinPublicSecretInstallerV1([authority redacted])")
    }
}

impl core::fmt::Debug for ProductionLateBitcoinPublicSecretSourceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionLateBitcoinPublicSecretSourceV1([authority redacted])")
    }
}

impl ProductionLateBitcoinPublicSecretSourceV1 {
    pub(crate) fn new_installable(
        route_id: RouteIdV1,
        composition_digest: Digest32,
        chain_id: Digest32,
    ) -> Result<(Self, ProductionBitcoinPublicSecretInstallerV1), AuthorityRefusalV1> {
        if [route_id, composition_digest, chain_id].contains(&ZERO_DIGEST) {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let shared = Rc::new(ProductionLateBitcoinSecretSlotV1 {
            route_id,
            composition_digest,
            chain_id,
            state: RefCell::new(ProductionLateBitcoinSecretSlotStateV1::Vacant),
        });
        Ok((
            Self {
                shared: Rc::clone(&shared),
            },
            ProductionBitcoinPublicSecretInstallerV1 { shared },
        ))
    }
}

impl ProductionBitcoinPublicSecretInstallerV1 {
    pub(crate) fn route_id(&self) -> RouteIdV1 {
        self.shared.route_id
    }

    pub(crate) fn composition_digest(&self) -> Digest32 {
        self.shared.composition_digest
    }

    pub(crate) fn chain_id(&self) -> Digest32 {
        self.shared.chain_id
    }

    /// Installs an exact claim recovered by the sole Bitcoin child at startup.
    ///
    /// No caller supplies a transaction id here. The child handoff is already
    /// bound to the retained exact transaction, prebroadcast store and Core
    /// RPC; this boundary only authenticates the immutable route scope shared
    /// with the source created before claim materialization.
    #[expect(
        clippy::result_large_err,
        reason = "the refusal returns the rejected value to its owner; one-shot composition path"
    )]
    pub(crate) fn install_recovered_exact(
        &mut self,
        handoff: ProductionBitcoinPublicExtractionHandoffV1,
    ) -> Result<
        (),
        (
            AuthorityRefusalV1,
            ProductionBitcoinPublicExtractionHandoffV1,
        ),
    > {
        if handoff.route_id() != self.shared.route_id
            || handoff.composition_digest() != self.shared.composition_digest
            || handoff.chain_id() != self.shared.chain_id
            || handoff.expected_txid() == ZERO_DIGEST
        {
            return Err((AuthorityRefusalV1::Inconsistent, handoff));
        }
        let mut state = self.shared.state.borrow_mut();
        match &*state {
            ProductionLateBitcoinSecretSlotStateV1::Vacant => {
                *state = ProductionLateBitcoinSecretSlotStateV1::Installed(Box::new(handoff));
                Ok(())
            }
            ProductionLateBitcoinSecretSlotStateV1::Installed(_) => {
                Err((AuthorityRefusalV1::Inconsistent, handoff))
            }
        }
    }

    #[expect(
        clippy::result_large_err,
        reason = "the refusal returns the rejected value to its owner; one-shot composition path"
    )]
    pub(crate) fn install_from_exact_child(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        plan: &SettlementChildPlanV1,
        handoff: ProductionBitcoinPublicExtractionHandoffV1,
    ) -> Result<
        (),
        (
            AuthorityRefusalV1,
            ProductionBitcoinPublicExtractionHandoffV1,
        ),
    > {
        if request.route_id != self.shared.route_id
            || request.composition_digest != self.shared.composition_digest
            || request.action != settlement_coordinator::SettlementActionV1::Claim
            || !matches!(
                request.exposure,
                ChildExposureV1::FirstSecretExposure | ChildExposureV1::UsesPublicSecret
            )
            || plan.face != settlement_coordinator::SettlementFaceV1::Bitcoin
            || plan.chain_id != self.shared.chain_id
            || plan.expected_transaction_id == ZERO_DIGEST
            || handoff.route_id() != self.shared.route_id
            || handoff.composition_digest() != self.shared.composition_digest
            || handoff.chain_id() != self.shared.chain_id
            || handoff.expected_txid() != plan.expected_transaction_id
        {
            return Err((AuthorityRefusalV1::Inconsistent, handoff));
        }
        let mut state = self.shared.state.borrow_mut();
        match &*state {
            ProductionLateBitcoinSecretSlotStateV1::Vacant => {
                *state = ProductionLateBitcoinSecretSlotStateV1::Installed(Box::new(handoff));
                Ok(())
            }
            ProductionLateBitcoinSecretSlotStateV1::Installed(_) => {
                Err((AuthorityRefusalV1::Inconsistent, handoff))
            }
        }
    }

    pub(crate) fn authenticate_installed_exact_child(
        &self,
        request: &ProductionChildMaterializationRequestV1,
        plan: &SettlementChildPlanV1,
    ) -> Result<(), AuthorityRefusalV1> {
        if request.route_id != self.shared.route_id
            || request.composition_digest != self.shared.composition_digest
            || request.action != settlement_coordinator::SettlementActionV1::Claim
            || plan.face != settlement_coordinator::SettlementFaceV1::Bitcoin
            || plan.chain_id != self.shared.chain_id
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let state = self.shared.state.borrow();
        match &*state {
            ProductionLateBitcoinSecretSlotStateV1::Installed(handoff)
                if handoff.expected_txid() == plan.expected_transaction_id =>
            {
                Ok(())
            }
            ProductionLateBitcoinSecretSlotStateV1::Vacant
            | ProductionLateBitcoinSecretSlotStateV1::Installed(_) => {
                Err(AuthorityRefusalV1::Inconsistent)
            }
        }
    }
}

impl ProductionChainPublicSecretSourceV1 for ProductionLateBitcoinPublicSecretSourceV1 {
    fn chain_id(&self) -> Digest32 {
        self.shared.chain_id
    }

    fn reextract_for_chain(
        &mut self,
        request: ProductionPublicSecretRequestV1<'_>,
    ) -> Result<RevealedSecretBytes, AuthorityRefusalV1> {
        let exposure = request.exposure();
        if request.route_id() != self.shared.route_id
            || request.composition_digest() != self.shared.composition_digest
            || exposure.chain_id != self.shared.chain_id
            || exposure.transaction_id == ZERO_DIGEST
            || exposure.evidence_digest == ZERO_DIGEST
            || exposure.observed_at_unix_ms == 0
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let mut state = self.shared.state.borrow_mut();
        let ProductionLateBitcoinSecretSlotStateV1::Installed(handoff) = &mut *state else {
            return Err(AuthorityRefusalV1::Unavailable);
        };
        if exposure.transaction_id != handoff.expected_txid() {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let revealed = handoff
            .extract_confirmed()
            .map_err(map_child_secret_source_refusal)?;
        let mut scalar = Zeroizing::new([0_u8; 32]);
        revealed.move_into(&mut scalar);
        Ok(RevealedSecretBytes::new(*scalar))
    }
}

fn map_child_secret_source_refusal(
    error: settlement_coordinator::ChildAuthorityRefusalV1,
) -> AuthorityRefusalV1 {
    match error {
        settlement_coordinator::ChildAuthorityRefusalV1::Unavailable
        | settlement_coordinator::ChildAuthorityRefusalV1::Refused => {
            AuthorityRefusalV1::Unavailable
        }
        settlement_coordinator::ChildAuthorityRefusalV1::Conflict => {
            AuthorityRefusalV1::Inconsistent
        }
    }
}

/// Exact-chain router for DOM, EVM and Bitcoin secret sources.
///
/// It routes by the authenticated chain digest only. Missing and duplicate
/// chain identities are refused; an exposure is never offered to a different
/// installed source as a fallback.
pub(crate) struct ProductionPublicSecretSourceRouterV1 {
    dom: Box<dyn ProductionChainPublicSecretSourceV1>,
    evm: Option<Box<dyn ProductionChainPublicSecretSourceV1>>,
    bitcoin: Option<Box<dyn ProductionChainPublicSecretSourceV1>>,
}

impl core::fmt::Debug for ProductionPublicSecretSourceRouterV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionPublicSecretSourceRouterV1([authorities redacted])")
    }
}

impl ProductionPublicSecretSourceRouterV1 {
    pub(crate) fn new<D, E, B>(
        dom: D,
        evm: Option<E>,
        bitcoin: Option<B>,
    ) -> Result<Self, AuthorityRefusalV1>
    where
        D: ProductionChainPublicSecretSourceV1 + 'static,
        E: ProductionChainPublicSecretSourceV1 + 'static,
        B: ProductionChainPublicSecretSourceV1 + 'static,
    {
        let dom_chain = dom.chain_id();
        let evm_chain = evm
            .as_ref()
            .map(ProductionChainPublicSecretSourceV1::chain_id);
        let bitcoin_chain = bitcoin
            .as_ref()
            .map(ProductionChainPublicSecretSourceV1::chain_id);
        if dom_chain == ZERO_DIGEST
            || evm_chain.is_some_and(|chain| chain == ZERO_DIGEST || chain == dom_chain)
            || bitcoin_chain.is_some_and(|chain| {
                chain == ZERO_DIGEST || chain == dom_chain || Some(chain) == evm_chain
            })
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(Self {
            dom: Box::new(dom),
            evm: evm.map(|source| Box::new(source) as Box<dyn ProductionChainPublicSecretSourceV1>),
            bitcoin: bitcoin
                .map(|source| Box::new(source) as Box<dyn ProductionChainPublicSecretSourceV1>),
        })
    }
}

impl ProductionPublicSecretSourceV1 for ProductionPublicSecretSourceRouterV1 {
    fn reextract_public_secret(
        &mut self,
        request: ProductionPublicSecretRequestV1<'_>,
    ) -> Result<RevealedSecretBytes, AuthorityRefusalV1> {
        let chain_id = request.exposure().chain_id;
        let source = if self.dom.chain_id() == chain_id {
            self.dom.as_mut()
        } else if let Some(source) = self
            .evm
            .as_mut()
            .filter(|source| source.chain_id() == chain_id)
        {
            source.as_mut()
        } else if let Some(source) = self
            .bitcoin
            .as_mut()
            .filter(|source| source.chain_id() == chain_id)
        {
            source.as_mut()
        } else {
            return Err(AuthorityRefusalV1::Refused);
        };
        if source.chain_id() != chain_id {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        source.reextract_for_chain(request)
    }
}

/// Exact chain materializer used after route and secret verification.
///
/// The scalar-bearing method is distinct so a Funding, Refund, or first
/// exposure plan cannot accidentally receive public-secret authority.  It may
/// prepare and durably retain exact child transactions, but it must not
/// broadcast them; externalization remains owned by the coordinator ports.
pub(crate) trait ProductionSettlementDraftMaterializerV1 {
    fn deferred_materializer_authority_id(&self) -> Digest32;

    fn materialize_without_preexisting_secret(
        &mut self,
        composition: &ComposedBindingV2,
        request: &RouteActionAuthorizationRequestV1<'_>,
    ) -> Result<ProductionSettlementPlanDraftV1, AuthorityRefusalV1>;

    fn materialize_with_verified_public_secret(
        &mut self,
        composition: &ComposedBindingV2,
        request: &RouteActionAuthorizationRequestV1<'_>,
        scalar: RouteScalar,
    ) -> Result<ProductionSettlementPlanDraftV1, AuthorityRefusalV1>;

    fn materialize_deferred_with_verified_public_secret(
        &mut self,
        composition: &ComposedBindingV2,
        capability: &DeferredChildMaterializationCapabilityV1,
        scalar: RouteScalar,
    ) -> Result<SettlementChildPlanV1, AuthorityRefusalV1>;
}

/// Production plan source bound to one authenticated V2 composition.
pub(crate) struct VerifiedProductionSettlementPlanSourceV1 {
    route_id: RouteIdV1,
    frozen_bindings: FrozenBindingsV1,
    composition: Rc<ComposedBindingV2>,
    secret_source: Box<dyn ProductionPublicSecretSourceV1>,
    secret_retention: ProductionPublicSecretRetentionV1,
    materializer: Box<dyn ProductionSettlementDraftMaterializerV1>,
}

impl core::fmt::Debug for VerifiedProductionSettlementPlanSourceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedProductionSettlementPlanSourceV1([authorities redacted])")
    }
}

impl VerifiedProductionSettlementPlanSourceV1 {
    pub(crate) fn new<S, M>(
        route_id: RouteIdV1,
        frozen_bindings: FrozenBindingsV1,
        composition: Rc<ComposedBindingV2>,
        secret_source: S,
        secret_retention: ProductionPublicSecretRetentionV1,
        materializer: M,
    ) -> Result<Self, AuthorityRefusalV1>
    where
        S: ProductionPublicSecretSourceV1 + 'static,
        M: ProductionSettlementDraftMaterializerV1 + 'static,
    {
        if route_id == ZERO_DIGEST
            || frozen_bindings.terms_digest == ZERO_DIGEST
            || frozen_bindings.profile_bundle_digest == ZERO_DIGEST
            || frozen_bindings.deployment_bundle_digest == ZERO_DIGEST
            || composition.binding_digest() == ZERO_DIGEST
            || materializer.deferred_materializer_authority_id() == ZERO_DIGEST
        {
            return Err(AuthorityRefusalV1::Refused);
        }
        Ok(Self {
            route_id,
            frozen_bindings,
            composition,
            secret_source: Box::new(secret_source),
            secret_retention,
            materializer: Box::new(materializer),
        })
    }

    fn require_request_scope(
        &self,
        request: &RouteActionAuthorizationRequestV1<'_>,
    ) -> Result<(), AuthorityRefusalV1> {
        if request.route_id() != self.route_id
            || request.snapshot().route_id != self.route_id
            || request.bindings() != &self.frozen_bindings
            || request.snapshot().bindings.as_ref() != Some(&self.frozen_bindings)
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(())
    }

    fn extract_verified_scalar(
        &mut self,
        exposure: &PublicExposureV1,
        recovery: VaultRecoveryAuthorizationV1<'_>,
    ) -> Result<RouteScalar, AuthorityRefusalV1> {
        if exposure.chain_id == ZERO_DIGEST
            || exposure.transaction_id == ZERO_DIGEST
            || exposure.evidence_digest == ZERO_DIGEST
            || exposure.observed_at_unix_ms == 0
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let retention_bindings = RouteSecretBindingsV2::new(
            self.route_id,
            self.composition.binding_digest(),
            RouteSecretExposureV2::new(
                exposure.chain_id,
                exposure.transaction_id,
                exposure.evidence_digest,
                route_secret_exposure_source(exposure.source),
                exposure.observed_at_unix_ms,
            )
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?,
            self.composition.adaptor_point_sec1(),
        )
        .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        if let VaultRecoveryAuthorizationV1::AuthenticatedCoordinatorExposure(authority) = &recovery
        {
            let authenticated = authority.exposure();
            if authority.route_id() != self.route_id
                || authority.settlement_id() != self.composition.downstream().settlement_id.0
                || authenticated.chain_id != exposure.chain_id
                || authenticated.transaction_id != exposure.transaction_id
                || authenticated.evidence_digest != exposure.evidence_digest
                || authenticated.observed_at_unix_ms != exposure.observed_at_unix_ms
            {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
        }
        let canonical =
            self.secret_source
                .reextract_public_secret(ProductionPublicSecretRequestV1 {
                    route_id: self.route_id,
                    composition_digest: self.composition.binding_digest(),
                    exposure,
                });
        let mut revealed = self.secret_retention.obtain_after_canonical_attempt(
            &retention_bindings,
            canonical,
            recovery,
        )?;
        let scalar_bytes = Zeroizing::new(revealed.expose_scalar_bytes());
        revealed.zeroize();
        let scalar = self
            .composition
            .verify_revealed_scalar(&scalar_bytes)
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        drop(scalar_bytes);
        Ok(scalar)
    }

    fn validate_materialized_draft(
        &self,
        request: &RouteActionAuthorizationRequestV1<'_>,
        draft: &ProductionSettlementPlanDraftV1,
    ) -> Result<(), AuthorityRefusalV1> {
        let expected_settlement = match request.leg() {
            LegIdV1::Upstream => self.composition.upstream().settlement_id.0,
            LegIdV1::Downstream => self.composition.downstream().settlement_id.0,
        };
        if draft.settlement_id != expected_settlement {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        match (
            request.action(),
            &request.snapshot().secret_visibility,
            draft.secret_requirement,
            draft.preexisting_secret_evidence_digest,
        ) {
            (ActionKindV1::Funding | ActionKindV1::Refund, _, SecretRequirementV1::None, None)
                if matches!(&draft.children, SettlementChildrenV1::Materialized(children)
                    if children.iter().all(|child| child.exposure == ChildExposureV1::NonSecret)) =>
                {}
            (
                ActionKindV1::Claim,
                SecretVisibilityV1::Private,
                SecretRequirementV1::FirstExposureRequired,
                None,
            ) if matches!(&draft.children,
                SettlementChildrenV1::FirstExposureStaged { first, .. }
                    if first.exposure == ChildExposureV1::FirstSecretExposure) => {}
            (
                ActionKindV1::Claim,
                SecretVisibilityV1::Public { first_exposure },
                SecretRequirementV1::AlreadyPublic,
                Some(evidence),
            ) if evidence == first_exposure.evidence_digest
                && matches!(&draft.children, SettlementChildrenV1::Materialized(children)
                    if children.iter().all(|child| child.exposure == ChildExposureV1::UsesPublicSecret)) =>
                {}
            _ => return Err(AuthorityRefusalV1::Inconsistent),
        }
        Ok(())
    }
}

impl ProductionSettlementPlanSourceV1 for VerifiedProductionSettlementPlanSourceV1 {
    fn deferred_materializer_authority_id(&self) -> Digest32 {
        self.materializer.deferred_materializer_authority_id()
    }

    fn draft_for_action(
        &mut self,
        request: &RouteActionAuthorizationRequestV1<'_>,
    ) -> Result<ProductionSettlementPlanDraftV1, AuthorityRefusalV1> {
        self.require_request_scope(request)?;
        let draft = match (request.action(), &request.snapshot().secret_visibility) {
            (ActionKindV1::Claim, SecretVisibilityV1::Public { first_exposure }) => {
                let scalar = self.extract_verified_scalar(
                    first_exposure,
                    VaultRecoveryAuthorizationV1::AuthenticatedPublicSnapshot,
                )?;
                self.materializer.materialize_with_verified_public_secret(
                    &self.composition,
                    request,
                    scalar,
                )?
            }
            _ => self
                .materializer
                .materialize_without_preexisting_secret(&self.composition, request)?,
        };
        self.validate_materialized_draft(request, &draft)?;
        Ok(draft)
    }

    fn seal_first_public_exposure(
        &mut self,
        authority: AuthenticatedCoordinatorExposureV1,
    ) -> Result<(), AuthorityRefusalV1> {
        if authority.route_id() != self.route_id {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let authenticated = authority.exposure();
        let exposure = PublicExposureV1 {
            source: route_executor::ExposureSourceV1::Externalized,
            chain_id: authenticated.chain_id,
            transaction_id: authenticated.transaction_id,
            evidence_digest: authenticated.evidence_digest,
            observed_at_unix_ms: authenticated.observed_at_unix_ms,
        };
        // Before the supervisor journals Public, the exact chain evidence is
        // mandatory on the first attempt. After a crash, vault recovery while
        // the route is still Private is possible only because the durable
        // coordinator minted this move-only authority from its fully audited
        // first-exposure row. No raw digest or caller-shaped boolean reaches
        // this branch.
        let verified = self.extract_verified_scalar(
            &exposure,
            VaultRecoveryAuthorizationV1::AuthenticatedCoordinatorExposure(&authority),
        )?;
        drop(verified);
        Ok(())
    }

    fn materialize_deferred_child(
        &mut self,
        capability: DeferredChildMaterializationCapabilityV1,
        route_exposure: &PublicExposureV1,
    ) -> Result<DeferredChildMaterializationResultV1, AuthorityRefusalV1> {
        let coordinator_exposure = capability.exposure();
        if capability.route_id() != self.route_id
            || capability.bindings().route_id != self.route_id
            || capability.bindings().settlement_id != self.composition.downstream().settlement_id.0
            || route_exposure.source != route_executor::ExposureSourceV1::Externalized
            || coordinator_exposure.chain_id != route_exposure.chain_id
            || coordinator_exposure.transaction_id != route_exposure.transaction_id
            || coordinator_exposure.evidence_digest != route_exposure.evidence_digest
            || coordinator_exposure.observed_at_unix_ms != route_exposure.observed_at_unix_ms
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let scalar = self.extract_verified_scalar(
            route_exposure,
            VaultRecoveryAuthorizationV1::AuthenticatedPublicSnapshot,
        )?;
        let authority_id = self.materializer.deferred_materializer_authority_id();
        let child = self
            .materializer
            .materialize_deferred_with_verified_public_secret(
                &self.composition,
                &capability,
                scalar,
            )?;
        DeferredChildMaterializationResultV1::complete(capability, authority_id, child)
            .map_err(|_| AuthorityRefusalV1::Inconsistent)
    }

    fn retire_public_secret(
        &mut self,
        capability: RouteSecretRetirementCapabilityV1,
    ) -> Result<(), AuthorityRefusalV1> {
        if capability.route_id() != self.route_id
            || capability.composition_v2_digest() != self.composition.binding_digest()
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        self.secret_retention
            .retire_after_authenticated_route_completion(&capability)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::rc::Rc;
    use std::sync::Arc;

    use cap_std::fs::Dir;
    use k256::{
        elliptic_curve::{ff::PrimeField, sec1::ToEncodedPoint},
        ProjectivePoint, Scalar,
    };
    use route_executor::ExposureSourceV1;
    use settlement_coordinator::{
        ChildAuthorityRefusalV1, ChildDispatchRequestV1, ChildExecutionOutcomeV1,
        ChildExternalizationReceiptV1, CompositeSettlementPlanV1, CoordinatorLeaseV1,
        DurableSettlementCoordinatorV1, PlanAuthorityRefusalV1, PlanAuthorizationRequestV1,
        PlanAuthorizationV1, SettlementActionV1, SettlementChildAuthorityV1, SettlementChildPlanV1,
        SettlementFaceV1, SettlementLegV1, SettlementPlanAuthorityV1, SettlementPlanBindingsV1,
    };
    use static_assertions::assert_not_impl_any;

    use super::*;

    assert_not_impl_any!(ProductionDomPublicSecretConsumerAuthorityV1: Clone, Copy);
    assert_not_impl_any!(ProductionBitcoinPublicSecretInstallerV1: Clone, Copy);
    assert_not_impl_any!(ProductionLateBitcoinPublicSecretSourceV1: Clone, Copy);

    const fn digest(tag: u8) -> Digest32 {
        [tag; 32]
    }

    #[test]
    fn public_secret_consumer_scope_refuses_every_single_pin_transplant() {
        let retained_composition = digest(40);
        let retained_leg = SettlementLegV1::Upstream;
        let retained_settlement = digest(41);
        let retained_binding = digest(42);
        let retained_trusted_chain = digest(43);
        assert!(exact_dom_public_secret_consumer_scope_v1(
            retained_composition,
            retained_leg,
            retained_settlement,
            &retained_binding,
            &retained_trusted_chain,
            retained_composition,
            retained_leg,
            retained_settlement,
            &retained_binding,
            &retained_trusted_chain,
        ));
        for transplanted in [
            exact_dom_public_secret_consumer_scope_v1(
                retained_composition,
                retained_leg,
                retained_settlement,
                &retained_binding,
                &retained_trusted_chain,
                digest(44),
                retained_leg,
                retained_settlement,
                &retained_binding,
                &retained_trusted_chain,
            ),
            exact_dom_public_secret_consumer_scope_v1(
                retained_composition,
                retained_leg,
                retained_settlement,
                &retained_binding,
                &retained_trusted_chain,
                retained_composition,
                SettlementLegV1::Downstream,
                retained_settlement,
                &retained_binding,
                &retained_trusted_chain,
            ),
            exact_dom_public_secret_consumer_scope_v1(
                retained_composition,
                retained_leg,
                retained_settlement,
                &retained_binding,
                &retained_trusted_chain,
                retained_composition,
                retained_leg,
                digest(45),
                &retained_binding,
                &retained_trusted_chain,
            ),
            exact_dom_public_secret_consumer_scope_v1(
                retained_composition,
                retained_leg,
                retained_settlement,
                &retained_binding,
                &retained_trusted_chain,
                retained_composition,
                retained_leg,
                retained_settlement,
                &digest(46),
                &retained_trusted_chain,
            ),
            exact_dom_public_secret_consumer_scope_v1(
                retained_composition,
                retained_leg,
                retained_settlement,
                &retained_binding,
                &retained_trusted_chain,
                retained_composition,
                retained_leg,
                retained_settlement,
                &retained_binding,
                &digest(47),
            ),
        ] {
            assert!(!transplanted);
        }
    }

    #[derive(Clone)]
    struct RecordingSecretSourceV1 {
        chain_id: Digest32,
        calls: Rc<RefCell<Vec<(RouteIdV1, Digest32, Digest32)>>>,
        refusal: Option<AuthorityRefusalV1>,
    }

    impl ProductionChainPublicSecretSourceV1 for RecordingSecretSourceV1 {
        fn chain_id(&self) -> Digest32 {
            self.chain_id
        }

        fn reextract_for_chain(
            &mut self,
            request: ProductionPublicSecretRequestV1<'_>,
        ) -> Result<RevealedSecretBytes, AuthorityRefusalV1> {
            self.calls.borrow_mut().push((
                request.route_id(),
                request.composition_digest(),
                request.exposure().transaction_id,
            ));
            match &self.refusal {
                Some(AuthorityRefusalV1::Refused) => Err(AuthorityRefusalV1::Refused),
                Some(AuthorityRefusalV1::Unavailable) => Err(AuthorityRefusalV1::Unavailable),
                Some(AuthorityRefusalV1::Inconsistent) => Err(AuthorityRefusalV1::Inconsistent),
                None => Ok(RevealedSecretBytes::new([0x31; 32])),
            }
        }
    }

    fn exposure(chain_id: Digest32) -> PublicExposureV1 {
        PublicExposureV1 {
            source: ExposureSourceV1::Block,
            chain_id,
            transaction_id: [0x42; 32],
            evidence_digest: [0x43; 32],
            observed_at_unix_ms: 1,
        }
    }

    fn source(
        chain_id: Digest32,
        calls: Rc<RefCell<Vec<(RouteIdV1, Digest32, Digest32)>>>,
        refusal: Option<AuthorityRefusalV1>,
    ) -> RecordingSecretSourceV1 {
        RecordingSecretSourceV1 {
            chain_id,
            calls,
            refusal,
        }
    }

    #[test]
    fn late_bitcoin_source_is_unavailable_until_exact_child_installs_once() {
        let route_id = digest(0x51);
        let composition_digest = digest(0x52);
        let chain_id = digest(0x53);
        let (mut source, installer) = ProductionLateBitcoinPublicSecretSourceV1::new_installable(
            route_id,
            composition_digest,
            chain_id,
        )
        .expect("nonzero frozen scope");
        let observed = exposure(chain_id);

        assert_eq!(installer.route_id(), route_id);
        assert_eq!(installer.composition_digest(), composition_digest);
        assert_eq!(installer.chain_id(), chain_id);
        assert!(matches!(
            source.reextract_for_chain(ProductionPublicSecretRequestV1 {
                route_id,
                composition_digest,
                exposure: &observed,
            }),
            Err(AuthorityRefusalV1::Unavailable)
        ));
        assert!(ProductionLateBitcoinPublicSecretSourceV1::new_installable(
            ZERO_DIGEST,
            composition_digest,
            chain_id,
        )
        .is_err());
    }

    #[test]
    fn dom_secret_scope_needs_no_predicted_attempt_digest_and_rejects_tx_transplants() {
        let route_id = [0x11; 32];
        let composition_digest = [0x12; 32];
        let chain_id = [0x13; 32];
        let transaction_id = [0x14; 32];
        let evidence_digest = [0x15; 32];
        let mut exact_exposure = exposure(chain_id);
        exact_exposure.transaction_id = transaction_id;
        exact_exposure.evidence_digest = evidence_digest;

        let exact = ProductionPublicSecretRequestV1 {
            route_id,
            composition_digest,
            exposure: &exact_exposure,
        };
        assert_eq!(
            require_dom_public_secret_request(
                route_id,
                composition_digest,
                chain_id,
                transaction_id,
                &exact,
            ),
            Ok(())
        );

        for (foreign_route, foreign_composition, foreign_exposure) in [
            ([0x21; 32], composition_digest, exact_exposure.clone()),
            (route_id, [0x22; 32], exact_exposure.clone()),
            (
                route_id,
                composition_digest,
                PublicExposureV1 {
                    chain_id: [0x23; 32],
                    ..exact_exposure.clone()
                },
            ),
            (
                route_id,
                composition_digest,
                PublicExposureV1 {
                    transaction_id: [0x24; 32],
                    ..exact_exposure.clone()
                },
            ),
        ] {
            let request = ProductionPublicSecretRequestV1 {
                route_id: foreign_route,
                composition_digest: foreign_composition,
                exposure: &foreign_exposure,
            };
            assert_eq!(
                require_dom_public_secret_request(
                    route_id,
                    composition_digest,
                    chain_id,
                    transaction_id,
                    &request,
                ),
                Err(AuthorityRefusalV1::Inconsistent)
            );
        }

        // The evidence commitment is authenticated by the route snapshot and
        // only becomes available after the coordinator has minted an attempt.
        // The DOM source therefore accepts either nonzero value without a
        // caller predicting `attempt_id`, while the V2 vault later binds the
        // exact value durably.
        let later_attempt_digest = PublicExposureV1 {
            evidence_digest: [0x25; 32],
            ..exact_exposure.clone()
        };
        assert_eq!(
            require_dom_public_secret_request(
                route_id,
                composition_digest,
                chain_id,
                transaction_id,
                &ProductionPublicSecretRequestV1 {
                    route_id,
                    composition_digest,
                    exposure: &later_attempt_digest,
                },
            ),
            Ok(())
        );
        let zero_evidence = PublicExposureV1 {
            evidence_digest: ZERO_DIGEST,
            ..exact_exposure
        };
        assert_eq!(
            require_dom_public_secret_request(
                route_id,
                composition_digest,
                chain_id,
                transaction_id,
                &ProductionPublicSecretRequestV1 {
                    route_id,
                    composition_digest,
                    exposure: &zero_evidence,
                },
            ),
            Err(AuthorityRefusalV1::Inconsistent)
        );
    }

    #[test]
    fn dom_secret_scope_is_byte_identical_after_restart_reconstruction() {
        let mut observed = exposure([0x31; 32]);
        observed.transaction_id = [0x32; 32];
        observed.evidence_digest = [0x33; 32];
        let before_restart = ProductionPublicSecretRequestV1 {
            route_id: [0x34; 32],
            composition_digest: [0x35; 32],
            exposure: &observed,
        };
        let retained_public_facts = (
            before_restart.route_id(),
            before_restart.composition_digest(),
            before_restart.exposure().clone(),
        );
        let after_restart = ProductionPublicSecretRequestV1 {
            route_id: retained_public_facts.0,
            composition_digest: retained_public_facts.1,
            exposure: &retained_public_facts.2,
        };
        assert_eq!(
            require_dom_public_secret_request(
                [0x34; 32],
                [0x35; 32],
                [0x31; 32],
                [0x32; 32],
                &after_restart,
            ),
            Ok(())
        );
    }

    fn retention_bindings(
        seed: u8,
        scalar: [u8; 32],
    ) -> Result<RouteSecretBindingsV2, Box<dyn std::error::Error>> {
        let parsed = Option::<Scalar>::from(Scalar::from_repr(scalar.into()))
            .ok_or("test scalar must be canonical")?;
        let point: [u8; 33] = (ProjectivePoint::GENERATOR * parsed)
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()?;
        RouteSecretBindingsV2::new(
            [seed; 32],
            [seed.wrapping_add(1); 32],
            RouteSecretExposureV2::new(
                [seed.wrapping_add(2); 32],
                [seed.wrapping_add(3); 32],
                [seed.wrapping_add(4); 32],
                RouteSecretExposureSourceV2::Externalized,
                u64::from(seed) + 1,
            )?,
            point,
        )
        .map_err(Into::into)
    }

    fn retained_parent(
        temporary: &tempfile::TempDir,
    ) -> Result<Arc<Dir>, Box<dyn std::error::Error>> {
        let file = fs::File::open(temporary.path())?;
        Ok(Arc::new(Dir::from_std_file(file)))
    }

    struct CoordinatorPlanAuthorityV1;

    impl SettlementPlanAuthorityV1 for CoordinatorPlanAuthorityV1 {
        fn authorize_plan(
            &mut self,
            request: PlanAuthorizationRequestV1<'_>,
        ) -> Result<PlanAuthorizationV1, PlanAuthorityRefusalV1> {
            PlanAuthorizationV1::new([0xA1; 32], request.plan_digest(), [0xA2; 32], 20_000)
                .map_err(|_| PlanAuthorityRefusalV1::Refused)
        }
    }

    struct FirstExposureChildAuthorityV1;

    impl SettlementChildAuthorityV1 for FirstExposureChildAuthorityV1 {
        fn externalize_child(
            &mut self,
            request: &ChildDispatchRequestV1,
        ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
            Ok(ChildExecutionOutcomeV1::Externalized(
                ChildExternalizationReceiptV1 {
                    plan_id: request.plan_id(),
                    child_index: request.child_index(),
                    face: request.face(),
                    chain_id: request.chain_id(),
                    transaction_id: request.expected_transaction_id(),
                    intent_digest: request.intent_digest(),
                    custody_digest: request.custody_digest(),
                    externalization_evidence_digest: [0xA3; 32],
                    first_exposure_evidence_digest: Some([0xA4; 32]),
                },
            ))
        }

        fn reconcile_child(
            &mut self,
            _request: &settlement_coordinator::ChildReconciliationRequestV1,
        ) -> Result<settlement_coordinator::ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1>
        {
            Err(ChildAuthorityRefusalV1::Refused)
        }
    }

    fn authenticated_coordinator_exposure(
        path: &std::path::Path,
    ) -> Result<AuthenticatedCoordinatorExposureV1, Box<dyn std::error::Error>> {
        let parent = path.parent().ok_or("coordinator fixture parent")?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        let coordinator_id = [0xB1; 32];
        let authority_id = [0xA1; 32];
        let route_id = [0xB2; 32];
        let settlement_id = [0xB3; 32];
        let mut coordinator =
            DurableSettlementCoordinatorV1::create(path, coordinator_id, authority_id, 10_000)?;
        let plan = CompositeSettlementPlanV1::new(
            SettlementPlanBindingsV1 {
                route_id,
                effect_id: [0xB4; 32],
                settlement_id,
                leg: SettlementLegV1::Downstream,
                action: SettlementActionV1::Claim,
                fencing_epoch: 1,
                semantic_digest: [0xB5; 32],
                terms_digest: [0xB6; 32],
                registry_digest: [0xB7; 32],
                dom_profile_digest: [0xB8; 32],
                dom_deployment_digest: [0xB9; 32],
                counterparty_profile_digest: [0xBA; 32],
                counterparty_deployment_digest: [0xBB; 32],
            },
            SecretRequirementV1::FirstExposureRequired,
            None,
            [
                SettlementChildPlanV1 {
                    face: SettlementFaceV1::Evm,
                    exposure: ChildExposureV1::FirstSecretExposure,
                    chain_id: [0xBC; 32],
                    expected_transaction_id: [0xBD; 32],
                    intent_digest: [0xBE; 32],
                    custody_digest: [0xBF; 32],
                },
                SettlementChildPlanV1 {
                    face: SettlementFaceV1::Dom,
                    exposure: ChildExposureV1::UsesPublicSecret,
                    chain_id: [0xC1; 32],
                    expected_transaction_id: [0xC2; 32],
                    intent_digest: [0xC3; 32],
                    custody_digest: [0xC4; 32],
                },
            ],
        )?;
        let view = coordinator.install_plan(&mut CoordinatorPlanAuthorityV1, plan, 10_001)?;
        let lease: CoordinatorLeaseV1 = coordinator
            .acquire_lease(view.plan_id, [0xC5; 32], 1, 10_002, 1_000)?
            .lease();
        let outcome = coordinator.drive_one(lease, &mut FirstExposureChildAuthorityV1, 10_003)?;
        assert!(matches!(
            outcome,
            settlement_coordinator::CoordinatorDriveOutcomeV1::PartialProgress(_)
        ));
        coordinator
            .authenticate_first_public_exposure(view.plan_id)
            .map_err(Into::into)
    }

    fn bindings_for_authenticated_exposure(
        authority: &AuthenticatedCoordinatorExposureV1,
        composition_digest: Digest32,
        scalar: [u8; 32],
    ) -> Result<RouteSecretBindingsV2, Box<dyn std::error::Error>> {
        let parsed = Option::<Scalar>::from(Scalar::from_repr(scalar.into()))
            .ok_or("test scalar must be canonical")?;
        let point: [u8; 33] = (ProjectivePoint::GENERATOR * parsed)
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()?;
        let exposure = authority.exposure();
        RouteSecretBindingsV2::new(
            authority.route_id(),
            composition_digest,
            RouteSecretExposureV2::new(
                exposure.chain_id,
                exposure.transaction_id,
                exposure.evidence_digest,
                RouteSecretExposureSourceV2::Externalized,
                exposure.observed_at_unix_ms,
            )?,
            point,
        )
        .map_err(Into::into)
    }

    #[test]
    fn retired_secret_record_is_inconsistent_not_transiently_unavailable() {
        assert_eq!(
            map_route_secret_vault_error(RouteSecretVaultError::Retired),
            AuthorityRefusalV1::Inconsistent
        );
    }

    #[test]
    fn canonical_scalar_is_fsynced_before_handoff_and_recovers_after_restart_and_reorg(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let parent = retained_parent(&temporary)?;
        let key_bytes = [0xA5; 32];
        let key = RouteSecretSealKeyV1::import(key_bytes)?;
        let vault = DurableRouteSecretVaultV1::create_production(
            Arc::clone(&parent),
            "public-route-secrets",
        )?;
        let retention = ProductionPublicSecretRetentionV1::new(vault, key);
        let scalar = [0x31; 32];
        let bindings = retention_bindings(0x21, scalar)?;

        let handed_off = retention.obtain_after_canonical_attempt(
            &bindings,
            Ok(RevealedSecretBytes::new(scalar)),
            VaultRecoveryAuthorizationV1::CanonicalOnly,
        )?;
        assert_eq!(handed_off.expose_scalar_bytes(), scalar);
        let root = temporary.path().join("public-route-secrets");
        let sealed_records = fs::read_dir(&root)?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".sealed"))
            .count();
        assert_eq!(sealed_records, 1);
        for entry in fs::read_dir(&root)? {
            let bytes = fs::read(entry?.path())?;
            assert!(!bytes.windows(scalar.len()).any(|window| window == scalar));
            assert!(!bytes
                .windows(key_bytes.len())
                .any(|window| window == key_bytes));
        }
        drop(retention);

        let key = RouteSecretSealKeyV1::import(key_bytes)?;
        let vault = DurableRouteSecretVaultV1::open_production(
            Arc::clone(&parent),
            "public-route-secrets",
            &key,
        )?;
        let retention = ProductionPublicSecretRetentionV1::new(vault, key);
        let recovered = retention.obtain_after_canonical_attempt(
            &bindings,
            Err(AuthorityRefusalV1::Unavailable),
            VaultRecoveryAuthorizationV1::AuthenticatedPublicSnapshot,
        )?;
        assert_eq!(recovered.expose_scalar_bytes(), scalar);
        Ok(())
    }

    #[test]
    fn coordinator_capability_recovers_exact_private_crash_seal_and_rejects_transplants(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let coordinator = temporary.path().join("coordinator.sqlite3");
        let authority = authenticated_coordinator_exposure(&coordinator)?;
        let parent = retained_parent(&temporary)?;
        let key_bytes = [0xD1; 32];
        let scalar = [0x31; 32];
        let composition_digest = [0xD2; 32];
        let exact = bindings_for_authenticated_exposure(&authority, composition_digest, scalar)?;
        let vault = DurableRouteSecretVaultV1::create_production(
            Arc::clone(&parent),
            "private-crash-seal",
        )?;
        let retention =
            ProductionPublicSecretRetentionV1::new(vault, RouteSecretSealKeyV1::import(key_bytes)?);

        // This is the real seal -> process-crash cut: the coordinator has
        // committed first exposure and the encrypted record is fsynced, but
        // the parent route journal has not yet committed Public.
        let initial = retention.obtain_after_canonical_attempt(
            &exact,
            Ok(RevealedSecretBytes::new(scalar)),
            VaultRecoveryAuthorizationV1::AuthenticatedCoordinatorExposure(&authority),
        )?;
        assert_eq!(initial.expose_scalar_bytes(), scalar);
        drop(initial);
        drop(retention);

        let vault = DurableRouteSecretVaultV1::open_production(
            Arc::clone(&parent),
            "private-crash-seal",
            &RouteSecretSealKeyV1::import(key_bytes)?,
        )?;
        let retention =
            ProductionPublicSecretRetentionV1::new(vault, RouteSecretSealKeyV1::import(key_bytes)?);
        for _ in 0..2 {
            let recovered = retention.obtain_after_canonical_attempt(
                &exact,
                Err(AuthorityRefusalV1::Unavailable),
                VaultRecoveryAuthorizationV1::AuthenticatedCoordinatorExposure(&authority),
            )?;
            assert_eq!(recovered.expose_scalar_bytes(), scalar);
        }

        let wrong_route = RouteSecretBindingsV2::new(
            [0xD3; 32],
            *exact.composition_digest(),
            RouteSecretExposureV2::new(
                *exact.chain_id(),
                *exact.tx_id(),
                *exact.exposure_evidence_digest(),
                exact.exposure_source(),
                exact.observed_at_unix_ms(),
            )?,
            *exact.adaptor_point_sec1(),
        )?;
        let wrong_exposure = RouteSecretBindingsV2::new(
            *exact.route_id(),
            *exact.composition_digest(),
            RouteSecretExposureV2::new(
                *exact.chain_id(),
                *exact.tx_id(),
                [0xD4; 32],
                exact.exposure_source(),
                exact.observed_at_unix_ms(),
            )?,
            *exact.adaptor_point_sec1(),
        )?;
        let wrong_composition = RouteSecretBindingsV2::new(
            *exact.route_id(),
            [0xD5; 32],
            RouteSecretExposureV2::new(
                *exact.chain_id(),
                *exact.tx_id(),
                *exact.exposure_evidence_digest(),
                exact.exposure_source(),
                exact.observed_at_unix_ms(),
            )?,
            *exact.adaptor_point_sec1(),
        )?;
        let wrong_scalar = [0x32; 32];
        let wrong_point = retention_bindings(0xD6, wrong_scalar)?;
        let wrong_adaptor_point = RouteSecretBindingsV2::new(
            *exact.route_id(),
            *exact.composition_digest(),
            RouteSecretExposureV2::new(
                *exact.chain_id(),
                *exact.tx_id(),
                *exact.exposure_evidence_digest(),
                exact.exposure_source(),
                exact.observed_at_unix_ms(),
            )?,
            *wrong_point.adaptor_point_sec1(),
        )?;

        for transplanted in [
            wrong_route,
            wrong_exposure,
            wrong_composition,
            wrong_adaptor_point,
        ] {
            assert!(matches!(
                retention.obtain_after_canonical_attempt(
                    &transplanted,
                    Err(AuthorityRefusalV1::Unavailable),
                    VaultRecoveryAuthorizationV1::AuthenticatedCoordinatorExposure(&authority),
                ),
                Err(AuthorityRefusalV1::Inconsistent)
            ));
        }
        Ok(())
    }

    #[test]
    fn coordinator_exposure_without_a_completed_seal_cannot_fabricate_private_recovery(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let authority =
            authenticated_coordinator_exposure(&temporary.path().join("coordinator.sqlite3"))?;
        let parent = retained_parent(&temporary)?;
        let vault =
            DurableRouteSecretVaultV1::create_production(parent, "missing-private-crash-seal")?;
        let retention = ProductionPublicSecretRetentionV1::new(
            vault,
            RouteSecretSealKeyV1::import([0xE1; 32])?,
        );
        let bindings = bindings_for_authenticated_exposure(&authority, [0xE2; 32], [0x31; 32])?;
        assert!(matches!(
            retention.obtain_after_canonical_attempt(
                &bindings,
                Err(AuthorityRefusalV1::Unavailable),
                VaultRecoveryAuthorizationV1::AuthenticatedCoordinatorExposure(&authority),
            ),
            Err(AuthorityRefusalV1::Inconsistent)
        ));
        Ok(())
    }

    #[test]
    fn vault_fallback_requires_exact_exposure_and_never_masks_inconsistency(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let parent = retained_parent(&temporary)?;
        let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
        let vault = DurableRouteSecretVaultV1::create_production(parent, "public-route-secrets")?;
        let retention = ProductionPublicSecretRetentionV1::new(vault, key);
        let scalar = [0x31; 32];
        let exact = retention_bindings(0x31, scalar)?;
        retention.obtain_after_canonical_attempt(
            &exact,
            Ok(RevealedSecretBytes::new(scalar)),
            VaultRecoveryAuthorizationV1::CanonicalOnly,
        )?;

        assert!(matches!(
            retention.obtain_after_canonical_attempt(
                &exact,
                Err(AuthorityRefusalV1::Unavailable),
                VaultRecoveryAuthorizationV1::CanonicalOnly,
            ),
            Err(AuthorityRefusalV1::Unavailable)
        ));

        assert!(matches!(
            retention.obtain_after_canonical_attempt(
                &exact,
                Err(AuthorityRefusalV1::Inconsistent),
                VaultRecoveryAuthorizationV1::AuthenticatedPublicSnapshot,
            ),
            Err(AuthorityRefusalV1::Inconsistent)
        ));
        let changed_exposure = RouteSecretBindingsV2::new(
            *exact.route_id(),
            *exact.composition_digest(),
            RouteSecretExposureV2::new(
                *exact.chain_id(),
                *exact.tx_id(),
                [0xE1; 32],
                exact.exposure_source(),
                exact.observed_at_unix_ms(),
            )?,
            *exact.adaptor_point_sec1(),
        )?;
        assert!(matches!(
            retention.obtain_after_canonical_attempt(
                &changed_exposure,
                Err(AuthorityRefusalV1::Unavailable),
                VaultRecoveryAuthorizationV1::AuthenticatedPublicSnapshot,
            ),
            Err(AuthorityRefusalV1::Inconsistent)
        ));
        for changed_binding in [
            RouteSecretBindingsV2::new(
                *exact.route_id(),
                *exact.composition_digest(),
                RouteSecretExposureV2::new(
                    *exact.chain_id(),
                    *exact.tx_id(),
                    *exact.exposure_evidence_digest(),
                    RouteSecretExposureSourceV2::Block,
                    exact.observed_at_unix_ms(),
                )?,
                *exact.adaptor_point_sec1(),
            )?,
            RouteSecretBindingsV2::new(
                *exact.route_id(),
                *exact.composition_digest(),
                RouteSecretExposureV2::new(
                    *exact.chain_id(),
                    *exact.tx_id(),
                    *exact.exposure_evidence_digest(),
                    exact.exposure_source(),
                    exact.observed_at_unix_ms() + 1,
                )?,
                *exact.adaptor_point_sec1(),
            )?,
        ] {
            assert!(matches!(
                retention.obtain_after_canonical_attempt(
                    &changed_binding,
                    Err(AuthorityRefusalV1::Unavailable),
                    VaultRecoveryAuthorizationV1::AuthenticatedPublicSnapshot,
                ),
                Err(AuthorityRefusalV1::Inconsistent)
            ));
        }
        Ok(())
    }

    #[test]
    fn authenticated_public_snapshot_without_its_mandatory_seal_is_inconsistent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let parent = retained_parent(&temporary)?;
        let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
        let vault = DurableRouteSecretVaultV1::create_production(parent, "public-route-secrets")?;
        let retention = ProductionPublicSecretRetentionV1::new(vault, key);
        let bindings = retention_bindings(0x41, [0x31; 32])?;

        assert!(matches!(
            retention.obtain_after_canonical_attempt(
                &bindings,
                Err(AuthorityRefusalV1::Unavailable),
                VaultRecoveryAuthorizationV1::AuthenticatedPublicSnapshot,
            ),
            Err(AuthorityRefusalV1::Inconsistent)
        ));
        Ok(())
    }

    #[test]
    fn public_secret_router_calls_only_the_exact_authenticated_chain() {
        let dom_calls = Rc::new(RefCell::new(Vec::new()));
        let evm_calls = Rc::new(RefCell::new(Vec::new()));
        let bitcoin_calls = Rc::new(RefCell::new(Vec::new()));
        let mut router = ProductionPublicSecretSourceRouterV1::new(
            source([1; 32], Rc::clone(&dom_calls), None),
            Some(source([2; 32], Rc::clone(&evm_calls), None)),
            Some(source([3; 32], Rc::clone(&bitcoin_calls), None)),
        )
        .expect("three distinct authorities");
        let observed = exposure([2; 32]);
        let secret = router
            .reextract_public_secret(ProductionPublicSecretRequestV1 {
                route_id: [4; 32],
                composition_digest: [5; 32],
                exposure: &observed,
            })
            .expect("exact EVM source");

        assert_eq!(secret.expose_scalar_bytes(), [0x31; 32]);
        assert!(dom_calls.borrow().is_empty());
        assert!(bitcoin_calls.borrow().is_empty());
        assert_eq!(
            evm_calls.borrow().as_slice(),
            &[([4; 32], [5; 32], [0x42; 32])]
        );
    }

    #[test]
    fn source_refusal_never_falls_back_to_another_chain() {
        let dom_calls = Rc::new(RefCell::new(Vec::new()));
        let evm_calls = Rc::new(RefCell::new(Vec::new()));
        let bitcoin_calls = Rc::new(RefCell::new(Vec::new()));
        let mut router = ProductionPublicSecretSourceRouterV1::new(
            source([1; 32], Rc::clone(&dom_calls), None),
            Some(source(
                [2; 32],
                Rc::clone(&evm_calls),
                Some(AuthorityRefusalV1::Unavailable),
            )),
            Some(source([3; 32], Rc::clone(&bitcoin_calls), None)),
        )
        .expect("three distinct authorities");
        let observed = exposure([2; 32]);

        assert!(matches!(
            router.reextract_public_secret(ProductionPublicSecretRequestV1 {
                route_id: [4; 32],
                composition_digest: [5; 32],
                exposure: &observed,
            }),
            Err(AuthorityRefusalV1::Unavailable)
        ));
        assert_eq!(evm_calls.borrow().len(), 1);
        assert!(dom_calls.borrow().is_empty());
        assert!(bitcoin_calls.borrow().is_empty());
    }

    #[test]
    fn public_secret_router_rejects_missing_duplicate_and_zero_chain_ids() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        assert!(ProductionPublicSecretSourceRouterV1::new(
            source([0; 32], Rc::clone(&calls), None),
            None::<RecordingSecretSourceV1>,
            Some(source([3; 32], Rc::clone(&calls), None)),
        )
        .is_err());
        assert!(ProductionPublicSecretSourceRouterV1::new(
            source([1; 32], Rc::clone(&calls), None),
            Some(source([1; 32], Rc::clone(&calls), None)),
            None::<RecordingSecretSourceV1>,
        )
        .is_err());

        let mut router = ProductionPublicSecretSourceRouterV1::new(
            source([1; 32], Rc::clone(&calls), None),
            Some(source([2; 32], Rc::clone(&calls), None)),
            None::<RecordingSecretSourceV1>,
        )
        .expect("valid installed authorities");
        let missing = exposure([9; 32]);
        assert!(matches!(
            router.reextract_public_secret(ProductionPublicSecretRequestV1 {
                route_id: [4; 32],
                composition_digest: [5; 32],
                exposure: &missing,
            }),
            Err(AuthorityRefusalV1::Refused)
        ));
        assert!(calls.borrow().is_empty());
    }
}
