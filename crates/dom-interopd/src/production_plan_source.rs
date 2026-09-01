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

use std::rc::Rc;

use adapter_dom_real::RealDomClaimConsumerV1;
use adapter_evm::{evm_counterparty_chain_id, EvidenceKind, EvmAdapter, JsonRpc, LockTerms};
use btc_actuator::{
    extract_revealed_secret_from_confirmed_lookup, BitcoinActionV1, BitcoinActuationScopeV1,
    BitcoinActuatorErrorV1, BitcoinClaimExtractionContextV1, BitcoinRpcV1,
};
use chain_profile::ChainKindV1;
use counterparty_api::{AdapterError, RevealedSecretBytes, VerifiedOutcome};
use deployment_registry::ResolvedSolanaDeploymentV1;
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
    SettlementChildrenV1,
};
use solana_escrow_wire::{EscrowStateV1, EscrowStatus};
use solana_profile::ValidatedSolanaSetup;
use solana_rpc::HttpSolanaRpc;
use solana_rpc_pool::SolanaRpcPool;
use solana_types::Commitment;
use xmr_dleq_sigma::{revealed_dom_secret_to_xmr_scalar, CrossCurvePublicClaim};
use zeroize::{Zeroize, Zeroizing};

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
    pub(crate) const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }

    pub(crate) const fn composition_digest(&self) -> Digest32 {
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

/// Restart-safe DOM receiver authority for one exact observed `FinalClaim`.
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
pub(crate) struct ProductionDomPublicSecretSourceV1 {
    route_id: RouteIdV1,
    composition_digest: Digest32,
    chain_id: Digest32,
    expected_claim_transaction_id: Digest32,
    store: Rc<ContractsSessionStoreV1>,
    binding: DomSessionBindingV1,
    trusted_chain_id: TrustedChainIdV1,
    consumer: RealDomClaimConsumerV1,
}

impl core::fmt::Debug for ProductionDomPublicSecretSourceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionDomPublicSecretSourceV1")
            .field("route_id", &self.route_id)
            .field("composition_digest", &self.composition_digest)
            .field("chain_id", &self.chain_id)
            .field(
                "expected_claim_transaction_id",
                &self.expected_claim_transaction_id,
            )
            .field("authorities", &"<redacted>")
            .finish()
    }
}

impl ProductionDomPublicSecretSourceV1 {
    pub(crate) fn new(
        route_id: RouteIdV1,
        composition_digest: Digest32,
        expected_claim_transaction_id: Digest32,
        store: Rc<ContractsSessionStoreV1>,
        binding: DomSessionBindingV1,
        trusted_chain_id: TrustedChainIdV1,
        consumer: RealDomClaimConsumerV1,
    ) -> Result<Self, AuthorityRefusalV1> {
        let chain_id = *trusted_chain_id.as_bytes();
        if [
            route_id,
            composition_digest,
            chain_id,
            expected_claim_transaction_id,
        ]
        .contains(&ZERO_DIGEST)
            || binding.route_id() != route_id
            || binding.chain_id() != chain_id
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        DomContractsActuatorV1::bind(store.as_ref(), binding)
            .map_err(map_dom_secret_source_error)?;
        Ok(Self {
            route_id,
            composition_digest,
            chain_id,
            expected_claim_transaction_id,
            store,
            binding,
            trusted_chain_id,
            consumer,
        })
    }
}

impl ProductionChainPublicSecretSourceV1 for ProductionDomPublicSecretSourceV1 {
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

/// Restart-safe Bitcoin extraction authority for one exact Taproot claim.
///
/// The RPC transaction wrapper has no raw-byte accessor. This source passes
/// the consumed lookup directly back into `btc-actuator`, where confirmation,
/// txid, witness, BIP340 and `t·G=T` are verified without making the
/// secret-bearing witness representable in the daemon.
pub(crate) struct ProductionBitcoinPublicSecretSourceV1<R: BitcoinRpcV1> {
    route_id: RouteIdV1,
    composition_digest: Digest32,
    chain_id: Digest32,
    expected_claim_transaction_id: Digest32,
    scope: BitcoinActuationScopeV1,
    extraction: BitcoinClaimExtractionContextV1,
    rpc: R,
}

impl<R: BitcoinRpcV1> core::fmt::Debug for ProductionBitcoinPublicSecretSourceV1<R> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionBitcoinPublicSecretSourceV1")
            .field("route_id", &self.route_id)
            .field("composition_digest", &self.composition_digest)
            .field("chain_id", &self.chain_id)
            .field(
                "expected_claim_transaction_id",
                &self.expected_claim_transaction_id,
            )
            .field("scope_digest", &self.scope.scope_digest())
            .field(
                "extraction_context_digest",
                &self.extraction.context_digest(),
            )
            .field("rpc", &"<authority redacted>")
            .finish()
    }
}

impl<R: BitcoinRpcV1> ProductionBitcoinPublicSecretSourceV1<R> {
    pub(crate) fn new(
        route_id: RouteIdV1,
        composition_digest: Digest32,
        chain_id: Digest32,
        expected_claim_transaction_id: Digest32,
        scope: BitcoinActuationScopeV1,
        extraction: BitcoinClaimExtractionContextV1,
        mut rpc: R,
    ) -> Result<Self, AuthorityRefusalV1> {
        if [
            route_id,
            composition_digest,
            chain_id,
            expected_claim_transaction_id,
            scope.scope_digest(),
            extraction.context_digest(),
        ]
        .contains(&ZERO_DIGEST)
            || scope.route_id() != route_id
            || scope.expected_txid() != expected_claim_transaction_id
            || scope.action() != BitcoinActionV1::Claim
            || scope.minimum_confirmations() == 0
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        rpc.verify_scope(&scope)
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        Ok(Self {
            route_id,
            composition_digest,
            chain_id,
            expected_claim_transaction_id,
            scope,
            extraction,
            rpc,
        })
    }
}

impl<R: BitcoinRpcV1> ProductionChainPublicSecretSourceV1
    for ProductionBitcoinPublicSecretSourceV1<R>
{
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
        self.rpc
            .verify_scope(&self.scope)
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        let lookup = self
            .rpc
            .lookup_exact(self.expected_claim_transaction_id)
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        extract_revealed_secret_from_confirmed_lookup(
            &self.extraction,
            self.expected_claim_transaction_id,
            self.scope.minimum_confirmations(),
            lookup,
        )
        .map_err(map_bitcoin_secret_source_error)
    }
}

fn map_bitcoin_secret_source_error(error: BitcoinActuatorErrorV1) -> AuthorityRefusalV1 {
    match error {
        BitcoinActuatorErrorV1::InvalidState
        | BitcoinActuatorErrorV1::EffectNotFound
        | BitcoinActuatorErrorV1::ExternalizationAmbiguous
        | BitcoinActuatorErrorV1::ReconciliationRequired
        | BitcoinActuatorErrorV1::Rpc(_) => AuthorityRefusalV1::Unavailable,
        BitcoinActuatorErrorV1::InvalidScope
        | BitcoinActuatorErrorV1::InvalidTransaction
        | BitcoinActuatorErrorV1::TransactionMismatch
        | BitcoinActuatorErrorV1::UnsafeReplacement
        | BitcoinActuatorErrorV1::DatabasePresent
        | BitcoinActuatorErrorV1::DatabaseMissing
        | BitcoinActuatorErrorV1::CreationIncomplete
        | BitcoinActuatorErrorV1::InvalidStorageAuthority
        | BitcoinActuatorErrorV1::Storage(_)
        | BitcoinActuatorErrorV1::CorruptState
        | BitcoinActuatorErrorV1::LeaseHeld
        | BitcoinActuatorErrorV1::StaleFencing
        | BitcoinActuatorErrorV1::InvalidTime
        | BitcoinActuatorErrorV1::IdempotencyConflict
        | BitcoinActuatorErrorV1::TerminalConflict
        | BitcoinActuatorErrorV1::RpcScopeMismatch
        | BitcoinActuatorErrorV1::ClaimAuthorityMismatch
        | BitcoinActuatorErrorV1::ClaimNonceCustody
        | BitcoinActuatorErrorV1::ClaimCryptography
        | BitcoinActuatorErrorV1::FundingNotArmed
        | BitcoinActuatorErrorV1::LiveFunding => AuthorityRefusalV1::Inconsistent,
    }
}

/// Exact expected identity of one Solana escrow claim, frozen at binding time.
///
/// Every field is a public commitment already authenticated by the DLEQ setup
/// (`ValidatedSolanaSetup`); the context exists so the extraction core can be
/// exercised against adversarial account states without a live quorum.
pub(crate) struct SolanaClaimExtractionContextV1 {
    settlement_id: Digest32,
    terms_hash: Digest32,
    setup_id: Digest32,
    funder: Digest32,
    recipient: Digest32,
    refund_recipient: Digest32,
    vault: Digest32,
    amount: u64,
    refund_after_unix: i64,
    claim: CrossCurvePublicClaim,
}

impl SolanaClaimExtractionContextV1 {
    fn from_setup(setup: &ValidatedSolanaSetup) -> Self {
        Self {
            settlement_id: setup.settlement_id(),
            terms_hash: setup.terms_hash(),
            setup_id: setup.setup_id(),
            funder: setup.funder().0,
            recipient: setup.recipient().0,
            refund_recipient: setup.refund_recipient().0,
            vault: setup.vault_pda().0,
            amount: setup.amount(),
            refund_after_unix: setup.refund_after_unix(),
            claim: setup.claim(),
        }
    }
}

/// Re-extract the revealed scalar from one exact finalized escrow state.
///
/// The program only writes `revealed_secret_be` after its own on-chain
/// `t·G_ed = claim_point_ed25519` syscall check passed inside the Claim that
/// moved the funds. This host-side pass re-verifies the scalar against BOTH
/// DLEQ-certified curve points, so a quorum answer cannot substitute a scalar
/// that satisfies only the ed25519 relation for a different secp point.
///
/// `Refunded` is a conflicting terminal outcome once the route journal says
/// the scalar is public: that is `Inconsistent`, never a silent fallback. A
/// pre-terminal status and an absent account are `Unavailable`: RPC lag, a
/// post-exposure reorg, or a post-claim `Close` that drained the state PDA all
/// require the sealed vault record for recovery, not a weaker re-read.
fn extract_solana_revealed_secret_v1(
    context: &SolanaClaimExtractionContextV1,
    state: &EscrowStateV1,
) -> Result<RevealedSecretBytes, AuthorityRefusalV1> {
    if state.settlement_id != context.settlement_id
        || state.terms_hash != context.terms_hash
        || state.setup_id != context.setup_id
        || state.funder != context.funder
        || state.recipient != context.recipient
        || state.refund_recipient != context.refund_recipient
        || state.vault != context.vault
        || state.amount != context.amount
        || state.refund_after_unix != context.refund_after_unix
        || state.dom_adaptor_point != context.claim.secp_compressed
        || state.claim_point_ed25519 != context.claim.ed_compressed
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    match state.status {
        EscrowStatus::Claimed => {}
        EscrowStatus::Refunded => return Err(AuthorityRefusalV1::Inconsistent),
        EscrowStatus::Initialized | EscrowStatus::Funded | EscrowStatus::Closed => {
            return Err(AuthorityRefusalV1::Unavailable)
        }
    }
    if state.funded_amount != 0
        || state.terminal_slot == 0
        || state.revealed_secret_be == ZERO_DIGEST
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    if revealed_dom_secret_to_xmr_scalar(state.revealed_secret_be, &context.claim).is_err() {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(RevealedSecretBytes::new(state.revealed_secret_be))
}

/// Restart-safe Solana extraction authority for one exact condition-lock claim.
///
/// The counterparty's Claim instruction is the only path that reveals the
/// scalar on the Solana chain, and the program persists it in the state PDA it
/// verified. Every call re-reads that account at finalized commitment through
/// the quorum pool and re-verifies the full escrow identity plus the
/// cross-curve relation before returning the redacted wrapper.
pub(crate) struct ProductionSolanaPublicSecretSourceV1 {
    route_id: RouteIdV1,
    composition_digest: Digest32,
    chain_id: Digest32,
    expected_claim_transaction_id: Digest32,
    context: SolanaClaimExtractionContextV1,
    state_pda: solana_types::SolanaPubkey,
    pool: SolanaRpcPool<HttpSolanaRpc>,
}

impl core::fmt::Debug for ProductionSolanaPublicSecretSourceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionSolanaPublicSecretSourceV1")
            .field("route_id", &self.route_id)
            .field("composition_digest", &self.composition_digest)
            .field("chain_id", &self.chain_id)
            .field(
                "expected_claim_transaction_id",
                &self.expected_claim_transaction_id,
            )
            .field("state_pda", &self.state_pda)
            .field("pool", &"<authority redacted>")
            .finish()
    }
}

impl ProductionSolanaPublicSecretSourceV1 {
    pub(crate) fn new(
        route_id: RouteIdV1,
        composition_digest: Digest32,
        expected_claim_transaction_id: Digest32,
        pool: SolanaRpcPool<HttpSolanaRpc>,
        setup: ValidatedSolanaSetup,
        deployment: &ResolvedSolanaDeploymentV1,
    ) -> Result<Self, AuthorityRefusalV1> {
        let pinned_program = match deployment.profile().kind {
            ChainKindV1::Solana { escrow_program, .. } => escrow_program,
            _ => return Err(AuthorityRefusalV1::Inconsistent),
        };
        let chain_id = deployment.profile().chain_id.0;
        if [
            route_id,
            composition_digest,
            chain_id,
            expected_claim_transaction_id,
        ]
        .contains(&ZERO_DIGEST)
            || setup.program_id().0 != pinned_program
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(Self {
            route_id,
            composition_digest,
            chain_id,
            expected_claim_transaction_id,
            state_pda: setup.state_pda(),
            context: SolanaClaimExtractionContextV1::from_setup(&setup),
            pool,
        })
    }
}

impl ProductionChainPublicSecretSourceV1 for ProductionSolanaPublicSecretSourceV1 {
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
        let snapshot = self
            .pool
            .account(self.state_pda, Commitment::Finalized)
            .map_err(|_| AuthorityRefusalV1::Unavailable)?
            .ok_or(AuthorityRefusalV1::Unavailable)?;
        let state =
            EscrowStateV1::decode(&snapshot.data).map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        extract_solana_revealed_secret_v1(&self.context, &state)
    }
}

/// Exact-chain router for DOM, EVM, Bitcoin and Solana secret sources.
///
/// It routes by the authenticated chain digest only. Missing and duplicate
/// chain identities are refused; an exposure is never offered to a different
/// installed source as a fallback.
///
/// Monero deliberately has no slot: a CLSAG ring signature never places the
/// scalar on the Monero chain, so a Monero-chain exposure is unextractable by
/// construction. The reveal for an XMR leg happens on the DOM chain via
/// adaptor completion and is served by the DOM source; a role plan that pins
/// the secret source to the Monero chain is refused upstream at
/// materialization, and an exposure carrying an unknown chain digest is
/// refused here.
pub(crate) struct ProductionPublicSecretSourceRouterV1 {
    dom: Box<dyn ProductionChainPublicSecretSourceV1>,
    evm: Option<Box<dyn ProductionChainPublicSecretSourceV1>>,
    bitcoin: Option<Box<dyn ProductionChainPublicSecretSourceV1>>,
    solana: Option<Box<dyn ProductionChainPublicSecretSourceV1>>,
}

impl core::fmt::Debug for ProductionPublicSecretSourceRouterV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionPublicSecretSourceRouterV1([authorities redacted])")
    }
}

impl ProductionPublicSecretSourceRouterV1 {
    pub(crate) fn new<D, E, B, S>(
        dom: D,
        evm: Option<E>,
        bitcoin: Option<B>,
        solana: Option<S>,
    ) -> Result<Self, AuthorityRefusalV1>
    where
        D: ProductionChainPublicSecretSourceV1 + 'static,
        E: ProductionChainPublicSecretSourceV1 + 'static,
        B: ProductionChainPublicSecretSourceV1 + 'static,
        S: ProductionChainPublicSecretSourceV1 + 'static,
    {
        let dom_chain = dom.chain_id();
        let evm_chain = evm
            .as_ref()
            .map(ProductionChainPublicSecretSourceV1::chain_id);
        let bitcoin_chain = bitcoin
            .as_ref()
            .map(ProductionChainPublicSecretSourceV1::chain_id);
        let solana_chain = solana
            .as_ref()
            .map(ProductionChainPublicSecretSourceV1::chain_id);
        if dom_chain == ZERO_DIGEST
            || evm_chain.is_some_and(|chain| chain == ZERO_DIGEST || chain == dom_chain)
            || bitcoin_chain.is_some_and(|chain| {
                chain == ZERO_DIGEST || chain == dom_chain || Some(chain) == evm_chain
            })
            || solana_chain.is_some_and(|chain| {
                chain == ZERO_DIGEST
                    || chain == dom_chain
                    || Some(chain) == evm_chain
                    || Some(chain) == bitcoin_chain
            })
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(Self {
            dom: Box::new(dom),
            evm: evm.map(|source| Box::new(source) as Box<dyn ProductionChainPublicSecretSourceV1>),
            bitcoin: bitcoin
                .map(|source| Box::new(source) as Box<dyn ProductionChainPublicSecretSourceV1>),
            solana: solana
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
        } else if let Some(source) = self
            .solana
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

    use super::*;

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
        let solana_calls = Rc::new(RefCell::new(Vec::new()));
        let mut router = ProductionPublicSecretSourceRouterV1::new(
            source([1; 32], Rc::clone(&dom_calls), None),
            Some(source([2; 32], Rc::clone(&evm_calls), None)),
            Some(source([3; 32], Rc::clone(&bitcoin_calls), None)),
            Some(source([6; 32], Rc::clone(&solana_calls), None)),
        )
        .expect("four distinct authorities");
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
        assert!(solana_calls.borrow().is_empty());
        assert_eq!(
            evm_calls.borrow().as_slice(),
            &[([4; 32], [5; 32], [0x42; 32])]
        );

        let solana_observed = exposure([6; 32]);
        router
            .reextract_public_secret(ProductionPublicSecretRequestV1 {
                route_id: [4; 32],
                composition_digest: [5; 32],
                exposure: &solana_observed,
            })
            .expect("exact Solana source");
        assert_eq!(
            solana_calls.borrow().as_slice(),
            &[([4; 32], [5; 32], [0x42; 32])]
        );
        assert_eq!(evm_calls.borrow().len(), 1);
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
            None::<RecordingSecretSourceV1>,
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
            None::<RecordingSecretSourceV1>,
        )
        .is_err());
        assert!(ProductionPublicSecretSourceRouterV1::new(
            source([1; 32], Rc::clone(&calls), None),
            Some(source([1; 32], Rc::clone(&calls), None)),
            None::<RecordingSecretSourceV1>,
            None::<RecordingSecretSourceV1>,
        )
        .is_err());
        // A Solana slot may not shadow any installed chain identity, nor be
        // zero.
        for duplicate in [[1u8; 32], [2; 32], [3; 32], [0; 32]] {
            assert!(ProductionPublicSecretSourceRouterV1::new(
                source([1; 32], Rc::clone(&calls), None),
                Some(source([2; 32], Rc::clone(&calls), None)),
                Some(source([3; 32], Rc::clone(&calls), None)),
                Some(source(duplicate, Rc::clone(&calls), None)),
            )
            .is_err());
        }

        let mut router = ProductionPublicSecretSourceRouterV1::new(
            source([1; 32], Rc::clone(&calls), None),
            Some(source([2; 32], Rc::clone(&calls), None)),
            None::<RecordingSecretSourceV1>,
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

    fn solana_witness() -> (Digest32, xmr_dleq_sigma::CrossCurvePublicClaim) {
        // A fixed witness inside the 252-bit domain (top nibble of the
        // little-endian high byte clear), matching the DLEQ constraints.
        let mut little_endian = [0x5Au8; 32];
        little_endian[31] = 0x05;
        let secret = xmr_dleq_sigma::CrossCurveSecret252::from_little_endian(little_endian)
            .expect("witness inside the 252-bit domain");
        let claim = secret.public_claim().expect("public claim");
        (secret.dom_secret_big_endian(), claim)
    }

    fn claimed_solana_state(
        secret_be: Digest32,
        claim: &xmr_dleq_sigma::CrossCurvePublicClaim,
    ) -> (SolanaClaimExtractionContextV1, EscrowStateV1) {
        let context = SolanaClaimExtractionContextV1 {
            settlement_id: [0x61; 32],
            terms_hash: [0x62; 32],
            setup_id: [0x63; 32],
            funder: [0x64; 32],
            recipient: [0x65; 32],
            refund_recipient: [0x66; 32],
            vault: [0x67; 32],
            amount: 5_000_000,
            refund_after_unix: 1_900_000_000,
            claim: *claim,
        };
        let state = EscrowStateV1 {
            status: EscrowStatus::Claimed,
            asset_kind: solana_escrow_wire::AssetKind::NativeSol,
            state_bump: 254,
            vault_bump: 253,
            authority_bump: 252,
            token_decimals: 0,
            settlement_id: context.settlement_id,
            terms_hash: context.terms_hash,
            setup_id: context.setup_id,
            funder: context.funder,
            recipient: context.recipient,
            refund_recipient: context.refund_recipient,
            token_program: [0; 32],
            mint: [0; 32],
            vault: context.vault,
            dom_adaptor_point: claim.secp_compressed,
            claim_point_ed25519: claim.ed_compressed,
            amount: context.amount,
            funded_amount: 0,
            refund_after_unix: context.refund_after_unix,
            terminal_slot: 987_654,
            revealed_secret_be: secret_be,
        };
        (context, state)
    }

    #[test]
    fn solana_extraction_returns_the_dleq_bound_scalar_from_the_claimed_state() {
        let (secret_be, claim) = solana_witness();
        let (context, state) = claimed_solana_state(secret_be, &claim);
        let revealed = extract_solana_revealed_secret_v1(&context, &state)
            .expect("exact claimed escrow state");
        assert_eq!(revealed.expose_scalar_bytes(), secret_be);
    }

    #[test]
    fn solana_extraction_maps_each_terminal_status_to_its_exact_refusal() {
        let (secret_be, claim) = solana_witness();
        let (context, base) = claimed_solana_state(secret_be, &claim);
        for (status, expected) in [
            (EscrowStatus::Initialized, AuthorityRefusalV1::Unavailable),
            (EscrowStatus::Funded, AuthorityRefusalV1::Unavailable),
            (EscrowStatus::Refunded, AuthorityRefusalV1::Inconsistent),
            (EscrowStatus::Closed, AuthorityRefusalV1::Unavailable),
        ] {
            let mut state = base;
            state.status = status;
            // Only the status is under test; keep the rest byte-identical so
            // a wrong refusal cannot hide behind an identity mismatch. The
            // pre-terminal shapes still carry the funded amount.
            if matches!(status, EscrowStatus::Initialized | EscrowStatus::Funded) {
                state.funded_amount = state.amount;
                state.terminal_slot = 0;
                state.revealed_secret_be = [0; 32];
            }
            assert_eq!(
                extract_solana_revealed_secret_v1(&context, &state).unwrap_err(),
                expected,
                "status {status:?}",
            );
        }
    }

    #[test]
    fn solana_extraction_rejects_every_single_field_transplant() {
        let (secret_be, claim) = solana_witness();
        let (context, base) = claimed_solana_state(secret_be, &claim);
        let mutations: [&dyn Fn(&mut EscrowStateV1); 12] = [
            &|state| state.settlement_id = [0xEE; 32],
            &|state| state.terms_hash = [0xEE; 32],
            &|state| state.setup_id = [0xEE; 32],
            &|state| state.funder = [0xEE; 32],
            &|state| state.recipient = [0xEE; 32],
            &|state| state.refund_recipient = [0xEE; 32],
            &|state| state.vault = [0xEE; 32],
            &|state| state.amount ^= 1,
            &|state| state.refund_after_unix ^= 1,
            &|state| state.dom_adaptor_point[1] ^= 1,
            &|state| state.claim_point_ed25519[0] ^= 1,
            &|state| state.funded_amount = 1,
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut state = base;
            mutate(&mut state);
            assert_eq!(
                extract_solana_revealed_secret_v1(&context, &state).unwrap_err(),
                AuthorityRefusalV1::Inconsistent,
                "mutation {index}",
            );
        }
        let mut zero_slot = base;
        zero_slot.terminal_slot = 0;
        assert_eq!(
            extract_solana_revealed_secret_v1(&context, &zero_slot).unwrap_err(),
            AuthorityRefusalV1::Inconsistent,
        );
    }

    #[test]
    fn solana_extraction_rejects_a_scalar_that_fails_either_curve_relation() {
        let (secret_be, claim) = solana_witness();
        let (context, base) = claimed_solana_state(secret_be, &claim);

        // A flipped scalar bit no longer maps to either certified point.
        let mut flipped = base;
        flipped.revealed_secret_be[7] ^= 1;
        assert_eq!(
            extract_solana_revealed_secret_v1(&context, &flipped).unwrap_err(),
            AuthorityRefusalV1::Inconsistent,
        );

        // A different valid witness satisfies its own points, not the pinned
        // claim: substitution across escrows is refused.
        let mut other_le = [0x33u8; 32];
        other_le[31] = 0x0A;
        let other = xmr_dleq_sigma::CrossCurveSecret252::from_little_endian(other_le)
            .expect("second witness");
        let mut substituted = base;
        substituted.revealed_secret_be = other.dom_secret_big_endian();
        assert_eq!(
            extract_solana_revealed_secret_v1(&context, &substituted).unwrap_err(),
            AuthorityRefusalV1::Inconsistent,
        );

        // Zero is refused before any curve work.
        let mut zeroed = base;
        zeroed.revealed_secret_be = [0; 32];
        assert_eq!(
            extract_solana_revealed_secret_v1(&context, &zeroed).unwrap_err(),
            AuthorityRefusalV1::Inconsistent,
        );
    }
}
