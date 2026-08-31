//! Public, secret-free bindings used by the DOM participant authority.

use deployment_registry::{DomRuntimeIdentityV1, ResolvedDomDeploymentV1};
use dom_adaptor::SigningShareV1;
use dom_scriptless_chain_adapter::ExpectedDomIdentityV1;
use thiserror::Error;

/// A fixed-width public digest.
pub type Digest32 = [u8; 32];

/// Failure at the participant-scoped DOM authority boundary.
///
/// Error strings deliberately omit paths, wallet material and protocol
/// payloads so they are safe to surface through an operator API.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DomActuatorError {
    /// The production authority is only available on Linux.
    #[error("DOM production authority requires Linux")]
    LinuxRequired,
    /// Durable public metadata could not be read or atomically written.
    #[error("DOM actuator storage unavailable")]
    StorageUnavailable,
    /// The configured directory, file owner, mode, link or canonical path is unsafe.
    #[error("invalid DOM actuator storage authority")]
    InvalidStorageAuthority,
    /// Creation would replace an existing database.
    #[error("DOM actuator database already exists")]
    DatabasePresent,
    /// Reopening was requested for an absent database.
    #[error("DOM actuator database is missing")]
    DatabaseMissing,
    /// The exact owner-only create prefix is incomplete and may be resumed
    /// only under an already durable external provisioning journal entry.
    #[error("DOM actuator database creation is incomplete")]
    CreationIncomplete,
    /// The database schema or safety pragmas are not the exact supported version.
    #[error("unsupported DOM actuator database format")]
    UnsupportedFormat,
    /// Another process retains the exclusive actuator lock.
    #[error("DOM actuator process lock is held")]
    ProcessLocked,
    /// A zero, malformed or mutually inconsistent public binding was supplied.
    #[error("invalid DOM actuator binding")]
    InvalidBinding,
    /// The request does not match the route/session/participant/deployment binding.
    #[error("DOM actuator capability scope mismatch")]
    CapabilityMismatch,
    /// Another live owner holds the participant authority.
    #[error("DOM participant lease is held")]
    LeaseHeld,
    /// The fencing generation no longer owns the participant authority.
    #[error("stale DOM participant fencing generation")]
    StaleFence,
    /// The exact lease has expired.
    #[error("DOM participant lease expired")]
    LeaseExpired,
    /// The session revision changed before the requested operation was committed.
    #[error("DOM actuator revision conflict")]
    RevisionConflict,
    /// The same effect identifier was reused for different action material.
    #[error("DOM actuator idempotency conflict")]
    IdempotencyConflict,
    /// The requested action is not legal in the durable session stage.
    #[error("invalid DOM actuator session stage")]
    InvalidStage,
    /// An output is already reserved by another live route.
    #[error("DOM wallet output already reserved")]
    OutputReservationConflict,
    /// The wallet has insufficient confirmed and mature value.
    #[error("insufficient DOM wallet funds")]
    InsufficientFunds,
    /// The encrypted participant wallet could not be opened or persisted.
    #[error("DOM participant wallet unavailable")]
    WalletUnavailable,
    /// The wallet belongs to a different DOM chain.
    #[error("DOM participant wallet chain mismatch")]
    WalletChainMismatch,
    /// A public nonce/share binding was already consumed by another effect.
    #[error("DOM nonce or share reuse detected")]
    SecretReuseDetected,
    /// Funding was requested before a fully signed refund was durable.
    #[error("DOM funding refused because refund is not durably presigned")]
    RefundNotArmed,
    /// Funding was requested before the claim adaptor pre-signature was durable.
    #[error("DOM funding refused because claim adaptor is not durably prepared")]
    ClaimNotPrepared,
    /// Takeover found an old prepared external action whose outcome is unknown.
    #[error("DOM action reconciliation required before takeover")]
    ReconciliationRequired,
    /// A reorg transition lacked exact public evidence.
    #[error("DOM reorg evidence required")]
    ReorgEvidenceRequired,
    /// Canonical terminal evidence did not match the exact retained transaction.
    #[error("invalid DOM terminal finality evidence")]
    FinalityEvidenceInvalid,
    /// The exact transaction is absent or below the frozen confirmation depth.
    #[error("DOM terminal finality is pending")]
    FinalityPending,
    /// The authenticated finality policy exceeds the real runtime's bounded support.
    #[error("unsupported DOM finality policy")]
    FinalityPolicyUnsupported,
    /// Reconciliation found the exact terminal transaction still canonical.
    #[error("DOM terminal transaction remains canonical")]
    TerminalStillCanonical,
    /// The observed DOM fork exceeds the authenticated recovery window.
    #[error("DOM reorganization exceeds authenticated policy")]
    ReorgBeyondPolicy,
    /// The configured production node/RPC authority is unavailable.
    #[error("DOM production RPC authority unavailable")]
    RpcAuthorityUnavailable,
    /// The retained Scriptless Contracts store refused the operation.
    #[error("DOM Contracts authority unavailable")]
    ContractsAuthorityUnavailable,
    /// The retained cryptographic vault refused the operation.
    #[error("DOM cryptographic authority unavailable")]
    CryptoAuthorityUnavailable,
    /// Restart could not prove whether the shared-output share was never
    /// created or whether its retained namespace is inconsistent.
    #[error("DOM shared-output recovery state is indeterminate")]
    SharedOutputRecoveryIndeterminate,
}

/// Result type used by this crate.
pub type DomActuatorResult<T> = Result<T, DomActuatorError>;

/// Opaque local signing share minted only by this participant's wallet authority.
///
/// It has no constructor, codec, raw accessor, `Clone` or `Debug`. The only
/// consuming path feeds the retained Contracts signer.
pub struct DomParticipantSigningShareV1 {
    binding: DomSessionBindingV1,
    share: SigningShareV1,
}

impl DomParticipantSigningShareV1 {
    pub(crate) const fn new(binding: DomSessionBindingV1, share: SigningShareV1) -> Self {
        Self { binding, share }
    }

    pub(crate) fn into_inner_for_binding(
        self,
        expected: DomSessionBindingV1,
    ) -> DomActuatorResult<SigningShareV1> {
        if self.binding != expected {
            return Err(DomActuatorError::InvalidBinding);
        }
        Ok(self.share)
    }
}

/// One participant identity owned by one actuator instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomParticipantV1 {
    participant_id: Digest32,
    protocol_index: u8,
}

impl DomParticipantV1 {
    /// Construct one member of the frozen two-party roster.
    pub fn new(participant_id: Digest32, protocol_index: u8) -> DomActuatorResult<Self> {
        if participant_id == [0; 32] || protocol_index > 1 {
            return Err(DomActuatorError::InvalidBinding);
        }
        Ok(Self {
            participant_id,
            protocol_index,
        })
    }

    /// Public participant identifier.
    pub const fn participant_id(self) -> Digest32 {
        self.participant_id
    }

    /// Participant position in the canonical two-party roster.
    pub const fn protocol_index(self) -> u8 {
        self.protocol_index
    }
}

/// Authenticated, immutable DOM deployment and participant binding for a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomSessionBindingV1 {
    route_id: Digest32,
    session_id: Digest32,
    participant: DomParticipantV1,
    chain_id: Digest32,
    genesis_hash: Digest32,
    runtime_identity: DomRuntimeIdentityV1,
    terms_digest: Digest32,
    profile_digest: Digest32,
    deployment_digest: Digest32,
    asset_binding_digest: Digest32,
    registry_epoch: u64,
    min_confirmations: u32,
    max_reorg_depth: u32,
}

/// Exact authenticated fields reconstructed from one retained session row.
///
/// This crate-private material keeps persistence reconstruction explicit while
/// preventing a long positional constructor from swapping adjacent digests.
pub(crate) struct StoredDomSessionBindingPartsV1 {
    pub(crate) route_id: Digest32,
    pub(crate) session_id: Digest32,
    pub(crate) participant: DomParticipantV1,
    pub(crate) chain_id: Digest32,
    pub(crate) genesis_hash: Digest32,
    pub(crate) runtime_identity: DomRuntimeIdentityV1,
    pub(crate) terms_digest: Digest32,
    pub(crate) profile_digest: Digest32,
    pub(crate) deployment_digest: Digest32,
    pub(crate) asset_binding_digest: Digest32,
    pub(crate) registry_epoch: u64,
    pub(crate) min_confirmations: u32,
    pub(crate) max_reorg_depth: u32,
}

impl DomSessionBindingV1 {
    /// Freeze a session against a DOM capability resolved from a verified registry.
    ///
    /// DOM has no separately encoded generic chain profile today, so the
    /// authenticated consensus-rules digest is the profile digest.  The
    /// manifest digest is the deployment digest and pins every DOM deployment
    /// fact together with its registry epoch.
    pub fn from_resolved_deployment(
        route_id: Digest32,
        session_id: Digest32,
        participant: DomParticipantV1,
        terms_digest: Digest32,
        resolved: ResolvedDomDeploymentV1,
    ) -> DomActuatorResult<Self> {
        let deployment = resolved.deployment();
        let binding = Self {
            route_id,
            session_id,
            participant,
            chain_id: deployment.chain_id.0,
            genesis_hash: deployment.genesis_hash,
            runtime_identity: deployment.runtime_identity,
            terms_digest,
            profile_digest: deployment.consensus_rules_digest,
            deployment_digest: resolved.registry_digest(),
            asset_binding_digest: resolved.native_asset_binding_digest(),
            registry_epoch: resolved.registry_epoch(),
            min_confirmations: deployment.finality.min_confirmations,
            max_reorg_depth: deployment.finality.max_reorg_depth,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub(crate) fn from_parts_for_store(
        parts: StoredDomSessionBindingPartsV1,
    ) -> DomActuatorResult<Self> {
        let StoredDomSessionBindingPartsV1 {
            route_id,
            session_id,
            participant,
            chain_id,
            genesis_hash,
            runtime_identity,
            terms_digest,
            profile_digest,
            deployment_digest,
            asset_binding_digest,
            registry_epoch,
            min_confirmations,
            max_reorg_depth,
        } = parts;
        let binding = Self {
            route_id,
            session_id,
            participant,
            chain_id,
            genesis_hash,
            runtime_identity,
            terms_digest,
            profile_digest,
            deployment_digest,
            asset_binding_digest,
            registry_epoch,
            min_confirmations,
            max_reorg_depth,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub(crate) fn validate(self) -> DomActuatorResult<()> {
        if self.route_id == [0; 32]
            || self.session_id == [0; 32]
            || self.chain_id == [0; 32]
            || self.genesis_hash == [0; 32]
            || self.runtime_identity.network_magic == 0
            || self.runtime_identity.protocol_version == 0
            || self.runtime_identity.range_proof_serialization_version == 0
            || self.terms_digest == [0; 32]
            || self.profile_digest == [0; 32]
            || self.deployment_digest == [0; 32]
            || self.asset_binding_digest == [0; 32]
            || self.registry_epoch == 0
            || self.min_confirmations == 0
            || self.max_reorg_depth < self.min_confirmations
        {
            return Err(DomActuatorError::InvalidBinding);
        }
        Ok(())
    }

    /// Route identifier.
    pub const fn route_id(self) -> Digest32 {
        self.route_id
    }

    /// Scriptless Contracts session identifier.
    pub const fn session_id(self) -> Digest32 {
        self.session_id
    }

    /// Sole local participant controlled by this authority.
    pub const fn participant(self) -> DomParticipantV1 {
        self.participant
    }

    /// Authenticated DOM chain identifier.
    pub const fn chain_id(self) -> Digest32 {
        self.chain_id
    }

    /// Canonical DOM genesis authenticated by the deployment registry.
    pub const fn genesis_hash(self) -> Digest32 {
        self.genesis_hash
    }

    /// Registry-authenticated DOM network/protocol/rangeproof identity.
    pub const fn runtime_identity(self) -> DomRuntimeIdentityV1 {
        self.runtime_identity
    }

    /// Construct the only real-node identity accepted for this session.
    ///
    /// The chain adapter validates the label, startup-safe compiled genesis,
    /// derived chain id and exact wire versions as one closed identity.
    pub fn expected_dom_identity(self) -> DomActuatorResult<ExpectedDomIdentityV1> {
        let expected = ExpectedDomIdentityV1 {
            network: self.runtime_identity.network.label().to_owned(),
            network_magic: self.runtime_identity.network_magic,
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            protocol_version: self.runtime_identity.protocol_version,
            range_proof_serialization_version: self
                .runtime_identity
                .range_proof_serialization_version,
        };
        expected
            .validate()
            .map_err(|_| DomActuatorError::InvalidBinding)?;
        Ok(expected)
    }

    /// Frozen settlement terms digest.
    pub const fn terms_digest(self) -> Digest32 {
        self.terms_digest
    }

    /// Authenticated DOM consensus/profile digest.
    pub const fn profile_digest(self) -> Digest32 {
        self.profile_digest
    }

    /// Authenticated deployment-manifest digest.
    pub const fn deployment_digest(self) -> Digest32 {
        self.deployment_digest
    }

    /// Authenticated native-asset binding digest.
    pub const fn asset_binding_digest(self) -> Digest32 {
        self.asset_binding_digest
    }

    /// Registry epoch frozen by this session.
    pub const fn registry_epoch(self) -> u64 {
        self.registry_epoch
    }

    /// Minimum canonical confirmation depth authenticated by the registry.
    pub const fn min_confirmations(self) -> u32 {
        self.min_confirmations
    }

    /// Maximum reorg depth covered by the authenticated recovery policy.
    pub const fn max_reorg_depth(self) -> u32 {
        self.max_reorg_depth
    }
}

/// Closed set of effects a DOM participant authority may perform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DomActionV1 {
    /// Exclusively reserve mature wallet outputs.
    ReserveOutputs = 1,
    /// Publish this participant's shared-output commitment contribution.
    ContributeSharedOutput = 2,
    /// Participate in the collaborative Bulletproof protocol.
    CollaborativeBulletproof = 3,
    /// Produce this participant's refund signing artifacts.
    PresignRefund = 4,
    /// Produce this participant's claim adaptor signing artifacts.
    PresignClaimAdaptor = 5,
    /// Externalize the exact funding transaction.
    BroadcastFunding = 6,
    /// Externalize the exact claim transaction.
    BroadcastClaim = 7,
    /// Externalize the exact refund transaction.
    BroadcastRefund = 8,
    /// Reconcile an ambiguous action or a canonical-chain change.
    Reconcile = 9,
    /// Release wallet outputs after a safe terminal or proven-unexternalized path.
    ReleaseOutputs = 10,
}

impl DomActionV1 {
    pub(crate) const fn tag(self) -> u8 {
        self as u8
    }

    pub(crate) const fn consumes_unique_secret_binding(self) -> bool {
        matches!(
            self,
            Self::ContributeSharedOutput
                | Self::CollaborativeBulletproof
                | Self::PresignRefund
                | Self::PresignClaimAdaptor
        )
    }
}

/// Route-secret role of one DOM settlement child.
///
/// This mirrors only the public coordinator classification needed by the
/// actuator.  It deliberately carries no scalar, adaptor material or claim
/// bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DomSettlementChildExposureV1 {
    /// Funding/refund, or another child that cannot reveal the route scalar.
    NonSecret = 1,
    /// This exact claim is the first irreversible public scalar exposure.
    FirstSecretExposure = 2,
    /// This exact claim uses a scalar the route already treats as public.
    UsesPublicSecret = 3,
}

impl DomSettlementChildExposureV1 {
    pub(crate) const fn tag(self) -> u8 {
        self as u8
    }

    pub(crate) fn decode(value: i64) -> DomActuatorResult<Self> {
        match value {
            1 => Ok(Self::NonSecret),
            2 => Ok(Self::FirstSecretExposure),
            3 => Ok(Self::UsesPublicSecret),
            _ => Err(DomActuatorError::UnsupportedFormat),
        }
    }
}

/// Public operation commitments to freeze beside an authenticated exact DOM
/// transaction locator.
///
/// The transaction identity is intentionally absent: only
/// `DomContractsActuatorV1` may supply it, after reauthenticating the retained
/// Contracts outbox (or the V2 final-claim custody pair).  The caller supplies
/// only coordinator commitments that the future settlement-child port must
/// compare byte-for-byte on dispatch, reconciliation and observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomSettlementChildBindingRequestV1 {
    scope: ScopedDomActionV1,
    semantic_digest: Digest32,
    registry_digest: Digest32,
    intent_digest: Digest32,
    custody_digest: Digest32,
    exposure: DomSettlementChildExposureV1,
}

impl DomSettlementChildBindingRequestV1 {
    /// Construct public binding material for one already-retained exact DOM
    /// funding, V2 final claim, or refund transaction.
    pub fn new(
        scope: ScopedDomActionV1,
        semantic_digest: Digest32,
        registry_digest: Digest32,
        intent_digest: Digest32,
        custody_digest: Digest32,
        exposure: DomSettlementChildExposureV1,
    ) -> DomActuatorResult<Self> {
        let request = Self {
            scope,
            semantic_digest,
            registry_digest,
            intent_digest,
            custody_digest,
            exposure,
        };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn validate(self) -> DomActuatorResult<()> {
        self.scope.binding().validate()?;
        if [
            self.semantic_digest,
            self.registry_digest,
            self.intent_digest,
            self.custody_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(DomActuatorError::InvalidBinding);
        }
        let exposure_is_valid = match self.scope.action() {
            DomActionV1::BroadcastFunding | DomActionV1::BroadcastRefund => {
                self.exposure == DomSettlementChildExposureV1::NonSecret
            }
            DomActionV1::BroadcastClaim => matches!(
                self.exposure,
                DomSettlementChildExposureV1::FirstSecretExposure
                    | DomSettlementChildExposureV1::UsesPublicSecret
            ),
            _ => false,
        };
        if !exposure_is_valid {
            return Err(DomActuatorError::InvalidBinding);
        }
        Ok(())
    }

    /// Exact session/effect/action scope already authorized by this actuator.
    pub const fn scope(self) -> ScopedDomActionV1 {
        self.scope
    }

    /// Route semantic retry commitment.
    pub const fn semantic_digest(self) -> Digest32 {
        self.semantic_digest
    }

    /// Threshold-authenticated deployment-registry commitment.
    pub const fn registry_digest(self) -> Digest32 {
        self.registry_digest
    }

    /// Commitment to the exact DOM child transaction semantics.
    pub const fn intent_digest(self) -> Digest32 {
        self.intent_digest
    }

    /// Stable locator committed by the settlement coordinator.
    pub const fn custody_digest(self) -> Digest32 {
        self.custody_digest
    }

    /// Route-secret role of this exact child.
    pub const fn exposure(self) -> DomSettlementChildExposureV1 {
        self.exposure
    }
}

/// Exact public locator for one authenticated retained DOM child operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomSettlementChildLocatorV1 {
    pub(crate) effect_id: Digest32,
    pub(crate) binding_record_digest: Digest32,
    pub(crate) custody_digest: Digest32,
}

impl DomSettlementChildLocatorV1 {
    /// Route-executor effect owning the retained transaction.
    pub const fn effect_id(self) -> Digest32 {
        self.effect_id
    }

    /// Commitment to the immutable coordinator/session/transaction binding row.
    pub const fn binding_record_digest(self) -> Digest32 {
        self.binding_record_digest
    }

    /// Coordinator-facing stable custody locator.
    pub const fn custody_digest(self) -> Digest32 {
        self.custody_digest
    }
}

/// Atomic, lease-scoped, raw-free view of one exact DOM settlement child.
///
/// Construction is crate-private and follows reauthentication through the one
/// borrowed Contracts store.  The value has no codec and its `Debug` output is
/// redacted; only public identities and commitments have accessors.
#[derive(PartialEq, Eq)]
pub struct DomSettlementChildBindingV1 {
    pub(crate) request: DomSettlementChildBindingRequestV1,
    pub(crate) transaction_id: Digest32,
    pub(crate) operation_fencing_epoch: u64,
    pub(crate) operation_evidence_digest: Digest32,
    pub(crate) operation_authorization_digest: Digest32,
    pub(crate) locator: DomSettlementChildLocatorV1,
}

impl core::fmt::Debug for DomSettlementChildBindingV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DomSettlementChildBindingV1([redacted])")
    }
}

impl DomSettlementChildBindingV1 {
    /// Complete frozen public operation request.
    pub const fn request(&self) -> DomSettlementChildBindingRequestV1 {
        self.request
    }

    /// Exact canonical transaction identity reauthenticated from retained state.
    pub const fn transaction_id(&self) -> Digest32 {
        self.transaction_id
    }

    /// Fencing generation currently committed by the underlying action row.
    pub const fn operation_fencing_epoch(&self) -> u64 {
        self.operation_fencing_epoch
    }

    /// Evidence commitment retained when the action was authorized.
    pub const fn operation_evidence_digest(&self) -> Digest32 {
        self.operation_evidence_digest
    }

    /// Authorization commitment needed to classify current-fence vs takeover recovery.
    pub const fn operation_authorization_digest(&self) -> Digest32 {
        self.operation_authorization_digest
    }

    /// Exact durable locator for journal binding and restart recovery.
    pub const fn locator(&self) -> DomSettlementChildLocatorV1 {
        self.locator
    }
}

/// Coordinator child-port call family persisted in the actuator journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomSettlementChildPortCallKindV1 {
    /// Externalization dispatch.
    Dispatch,
    /// Explicit reconciliation of an ambiguous dispatch.
    Reconciliation,
    /// Stable chain/finality observation.
    Observation,
}

impl DomSettlementChildPortCallKindV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Dispatch => 1,
            Self::Reconciliation => 2,
            Self::Observation => 3,
        }
    }

    pub(crate) fn decode(value: i64) -> DomActuatorResult<Self> {
        match value {
            1 => Ok(Self::Dispatch),
            2 => Ok(Self::Reconciliation),
            3 => Ok(Self::Observation),
            _ => Err(DomActuatorError::UnsupportedFormat),
        }
    }
}

/// Fixed canonical size of one secret-free retained child-port outcome.
pub const DOM_SETTLEMENT_CHILD_PORT_CALL_OUTCOME_V1_BYTES: usize = 66;

/// Secret-free stable result retained before a child-port call returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomSettlementChildPortCallOutcomeV1 {
    /// Exact transaction crossed, or had already crossed, the external boundary.
    Externalized {
        /// Stable externalization evidence.
        evidence_digest: Digest32,
        /// Stable first-exposure evidence, only for the first-exposure claim.
        first_exposure_evidence_digest: Option<Digest32>,
    },
    /// Dispatch proved that retrying a new attempt is safe.
    RetryableBeforeExternalization {
        /// Stable proof that no externalization happened in this attempt.
        evidence_digest: Digest32,
    },
    /// Externalization remains ambiguous.
    Unknown {
        /// Stable ambiguity evidence.
        evidence_digest: Digest32,
    },
    /// Reconciliation proved the exact transaction was not externalized.
    ProvenNotExternalized {
        /// Stable non-externalization evidence.
        evidence_digest: Digest32,
    },
    /// The exact transaction has not reached finality.
    Pending {
        /// Stable pending-observation evidence.
        evidence_digest: Digest32,
    },
    /// The exact transaction reached authenticated finality.
    Final {
        /// Stable finality evidence.
        evidence_digest: Digest32,
    },
    /// A prior finality result was invalidated by a verified reorganization.
    FinalityInvalidated {
        /// Evidence previously returned for the final observation.
        prior_finality_evidence_digest: Digest32,
        /// Stable reorganization evidence.
        reorg_evidence_digest: Digest32,
    },
}

/// Authenticated, secret-free finality facts minted only after the real DOM
/// scanner proof and durable actuator checkpoint commit both succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomFinalityObservationV1 {
    pub(crate) transaction_id: Digest32,
    pub(crate) block_height: u64,
    pub(crate) block_hash: Digest32,
    pub(crate) evidence_digest: Digest32,
}

impl DomFinalityObservationV1 {
    /// Exact retained transaction proved final.
    pub const fn transaction_id(self) -> Digest32 {
        self.transaction_id
    }

    /// Canonical containing-block height.
    pub const fn block_height(self) -> u64 {
        self.block_height
    }

    /// Canonical containing-block hash.
    pub const fn block_hash(self) -> Digest32 {
        self.block_hash
    }

    /// Real-DOM finality evidence committed by the checkpoint.
    pub const fn evidence_digest(self) -> Digest32 {
        self.evidence_digest
    }
}

/// Authenticated result of revalidating one active DOM finality checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomFinalityRevalidationV1 {
    /// The exact transaction remains canonical under its active checkpoint.
    StillFinal(DomFinalityObservationV1),
    /// A bounded authenticated fork invalidated the exact active checkpoint.
    Invalidated {
        /// Exact retained transaction removed from the canonical branch.
        transaction_id: Digest32,
        /// Real-DOM finality evidence named by the retained checkpoint.
        prior_evidence_digest: Digest32,
        /// Canonical height named by the retained checkpoint.
        prior_block_height: u64,
        /// Canonical block named by the retained checkpoint.
        prior_block_hash: Digest32,
        /// Real-DOM bounded-fork evidence committed before return.
        reorg_evidence_digest: Digest32,
    },
}

impl DomSettlementChildPortCallOutcomeV1 {
    /// Canonical stable bytes reissued exactly after restart.
    pub fn canonical_bytes(&self) -> [u8; DOM_SETTLEMENT_CHILD_PORT_CALL_OUTCOME_V1_BYTES] {
        let (tag, primary, secondary) = match *self {
            Self::Externalized {
                evidence_digest,
                first_exposure_evidence_digest,
            } => (1, evidence_digest, first_exposure_evidence_digest),
            Self::RetryableBeforeExternalization { evidence_digest } => (2, evidence_digest, None),
            Self::Unknown { evidence_digest } => (3, evidence_digest, None),
            Self::ProvenNotExternalized { evidence_digest } => (4, evidence_digest, None),
            Self::Pending { evidence_digest } => (5, evidence_digest, None),
            Self::Final { evidence_digest } => (6, evidence_digest, None),
            Self::FinalityInvalidated {
                prior_finality_evidence_digest,
                reorg_evidence_digest,
            } => (
                7,
                prior_finality_evidence_digest,
                Some(reorg_evidence_digest),
            ),
        };
        let mut bytes = [0_u8; DOM_SETTLEMENT_CHILD_PORT_CALL_OUTCOME_V1_BYTES];
        bytes[0] = tag;
        bytes[1..33].copy_from_slice(&primary);
        if let Some(secondary) = secondary {
            bytes[33] = 1;
            bytes[34..].copy_from_slice(&secondary);
        }
        bytes
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> DomActuatorResult<Self> {
        if bytes.len() != DOM_SETTLEMENT_CHILD_PORT_CALL_OUTCOME_V1_BYTES {
            return Err(DomActuatorError::UnsupportedFormat);
        }
        let primary: Digest32 = bytes[1..33]
            .try_into()
            .map_err(|_| DomActuatorError::UnsupportedFormat)?;
        let secondary: Digest32 = bytes[34..66]
            .try_into()
            .map_err(|_| DomActuatorError::UnsupportedFormat)?;
        if primary == [0; 32] || !matches!(bytes[33], 0 | 1) {
            return Err(DomActuatorError::UnsupportedFormat);
        }
        let outcome = match (bytes[0], bytes[33]) {
            (1, 0) if secondary == [0; 32] => Self::Externalized {
                evidence_digest: primary,
                first_exposure_evidence_digest: None,
            },
            (1, 1) if secondary != [0; 32] => Self::Externalized {
                evidence_digest: primary,
                first_exposure_evidence_digest: Some(secondary),
            },
            (2, 0) if secondary == [0; 32] => Self::RetryableBeforeExternalization {
                evidence_digest: primary,
            },
            (3, 0) if secondary == [0; 32] => Self::Unknown {
                evidence_digest: primary,
            },
            (4, 0) if secondary == [0; 32] => Self::ProvenNotExternalized {
                evidence_digest: primary,
            },
            (5, 0) if secondary == [0; 32] => Self::Pending {
                evidence_digest: primary,
            },
            (6, 0) if secondary == [0; 32] => Self::Final {
                evidence_digest: primary,
            },
            (7, 1) if secondary != [0; 32] => Self::FinalityInvalidated {
                prior_finality_evidence_digest: primary,
                reorg_evidence_digest: secondary,
            },
            _ => return Err(DomActuatorError::UnsupportedFormat),
        };
        if outcome.canonical_bytes() != bytes {
            return Err(DomActuatorError::UnsupportedFormat);
        }
        Ok(outcome)
    }

    pub(crate) fn validate_for(
        self,
        kind: DomSettlementChildPortCallKindV1,
    ) -> DomActuatorResult<()> {
        let valid = matches!(
            (kind, self),
            (
                DomSettlementChildPortCallKindV1::Dispatch,
                Self::Externalized { .. }
                    | Self::RetryableBeforeExternalization { .. }
                    | Self::Unknown { .. }
            ) | (
                DomSettlementChildPortCallKindV1::Reconciliation,
                Self::Externalized { .. }
                    | Self::ProvenNotExternalized { .. }
                    | Self::Unknown { .. }
            ) | (
                DomSettlementChildPortCallKindV1::Observation,
                Self::Pending { .. } | Self::Final { .. } | Self::FinalityInvalidated { .. }
            )
        );
        if !valid {
            return Err(DomActuatorError::InvalidStage);
        }
        Ok(())
    }
}

/// Immutable identity of one coordinator call and exact canonical request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomSettlementChildPortCallKeyV1 {
    pub(crate) call_kind: DomSettlementChildPortCallKindV1,
    pub(crate) coordinator_attempt_id: Digest32,
    pub(crate) request_digest: Digest32,
    pub(crate) locator: DomSettlementChildLocatorV1,
}

impl DomSettlementChildPortCallKeyV1 {
    /// Bind one exact coordinator request to an atomically reauthenticated locator.
    pub fn new(
        call_kind: DomSettlementChildPortCallKindV1,
        coordinator_attempt_id: Digest32,
        request_digest: Digest32,
        binding: &DomSettlementChildBindingV1,
    ) -> DomActuatorResult<Self> {
        if coordinator_attempt_id == [0; 32] || request_digest == [0; 32] {
            return Err(DomActuatorError::InvalidBinding);
        }
        Ok(Self {
            call_kind,
            coordinator_attempt_id,
            request_digest,
            locator: binding.locator,
        })
    }

    /// Child-port call family.
    pub const fn call_kind(self) -> DomSettlementChildPortCallKindV1 {
        self.call_kind
    }

    /// Deterministic coordinator attempt identity.
    pub const fn coordinator_attempt_id(self) -> Digest32 {
        self.coordinator_attempt_id
    }

    /// Digest of the complete canonical coordinator request.
    pub const fn request_digest(self) -> Digest32 {
        self.request_digest
    }

    /// Exact durable operation locator.
    pub const fn locator(self) -> DomSettlementChildLocatorV1 {
        self.locator
    }
}

/// Result of opening one idempotent durable child-port journal slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomSettlementChildPortCallJournalStatusV1 {
    /// The attempt is durable but no stable public result has been committed.
    Pending,
    /// The exact stable result was already committed and must be replayed.
    Committed(DomSettlementChildPortCallOutcomeV1),
}

/// Complete public scope requested for one action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopedDomActionV1 {
    binding: DomSessionBindingV1,
    effect_id: Digest32,
    action: DomActionV1,
}

impl ScopedDomActionV1 {
    /// Bind an effect and action to the exact authenticated session facts.
    pub fn new(
        binding: DomSessionBindingV1,
        effect_id: Digest32,
        action: DomActionV1,
    ) -> DomActuatorResult<Self> {
        binding.validate()?;
        if effect_id == [0; 32] {
            return Err(DomActuatorError::InvalidBinding);
        }
        Ok(Self {
            binding,
            effect_id,
            action,
        })
    }

    /// Exact session binding.
    pub const fn binding(self) -> DomSessionBindingV1 {
        self.binding
    }

    /// Route-executor effect identifier.
    pub const fn effect_id(self) -> Digest32 {
        self.effect_id
    }

    /// Closed authorized action.
    pub const fn action(self) -> DomActionV1 {
        self.action
    }
}

/// Move-only authorization returned only after the action intent is durable.
///
/// There is no public constructor, generic signing method, codec, `Clone` or
/// serialization implementation.  The authorization contains public digests
/// only; secret material remains in the wallet or retained nonce vault.
pub struct DomActuatorCapabilityV1 {
    scope: ScopedDomActionV1,
    fencing_epoch: u64,
    authorization_digest: Digest32,
    issuance: CapabilityIssuanceV1,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapabilityIssuanceV1 {
    Fresh,
    Resumed,
}

impl DomActuatorCapabilityV1 {
    pub(crate) const fn issue(
        scope: ScopedDomActionV1,
        fencing_epoch: u64,
        authorization_digest: Digest32,
        issuance: CapabilityIssuanceV1,
    ) -> Self {
        Self {
            scope,
            fencing_epoch,
            authorization_digest,
            issuance,
        }
    }

    pub(crate) const fn is_fresh(&self) -> bool {
        matches!(self.issuance, CapabilityIssuanceV1::Fresh)
    }

    pub(crate) const fn is_resumed(&self) -> bool {
        matches!(self.issuance, CapabilityIssuanceV1::Resumed)
    }

    /// Exact route/session/effect/action/deployment scope.
    pub const fn scope(&self) -> ScopedDomActionV1 {
        self.scope
    }

    /// Monotonic signer/actuator fencing generation.
    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch
    }

    /// Public commitment to the persisted authorization row.
    pub const fn authorization_digest(&self) -> Digest32 {
        self.authorization_digest
    }
}

impl core::fmt::Debug for DomActuatorCapabilityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DomActuatorCapabilityV1")
            .field("scope", &self.scope)
            .field("fencing_epoch", &self.fencing_epoch)
            .field("authorization_digest", &"<redacted capability>")
            .finish()
    }
}
