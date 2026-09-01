//! Narrow adapters to the retained Scriptless Contracts authorities.

use adapter_dom_real::{
    CanonicalDomFundingEvidenceV1, RealDomClaimConsumerV1, RealDomClaimVerifierV1, RealDomError,
    RealDomRpcRuntimeV1, VerifiedDomClaimFinalityV1, VerifiedDomClaimReorgV1,
    VerifiedDomFundingFinalityV1, VerifiedDomFundingReorgV1, VerifiedDomRefundFinalityV1,
    VerifiedDomRefundReorgV1,
};
use blake2::digest::{consts::U32, Digest};
use blake2::Blake2b;
use counterparty_api::RevealedSecretBytes;
use dom_adaptor::{
    contribute_vault_backed_blinding_share_v1, resume_vault_backed_blinding_share_after_restart_v1,
    BoundShareBackupAckV2, BpStatementV1, ContractKindV1, DirectionV1,
    OperationalM8FundingAuthorizationV2, ParticipantRosterV1,
    PendingSessionBlindingShareCapabilityV1, PurposeV1, RestartedSessionBlindingShareV1,
    ScriptlessTransactionTemplateV1, SharedBlindingRestartRequestV1, SharedBlindingVaultError,
    TrustedChainIdV1, VaultBackedSignerV1, VerifiedClaimTransactionV1,
    VerifiedM8FundingTransactionV2,
};
use dom_consensus::transaction::Transaction;
use dom_crypto::{recovery::RecoveryCapsule, PublicKey};
use dom_scriptless_chain_adapter::{
    canonical_transaction_hash_v1, ChainAdapterError, DomHttpChainAdapterV1, SubmissionReceiptV1,
};
use dom_scriptless_store::{
    AcceptedContractsSigningSessionV1, AuthenticatedOperationalBpContinuationV1,
    AuthenticatedOperationalBpFinalProofV1, AuthenticatedPostAnchorClaimPreSignatureV1,
    ConsumedClaimSigningAuthorizationV1, ConsumedClaimSigningAuthorizationV2,
    ContractsNonceVaultV1, ContractsReservationLookupCustodyV1, ContractsSessionStoreV1,
    ContractsSigningSessionAuthorityV1, DomTransactionValidationContextV1,
    ExactDomRefundBroadcasterV1, FundingBroadcastV1, InventoryError, ObservedFinalClaimExposureV2,
    OperationalM8FundingGatePreparationV2, OutboundDsc1RecoveryV1,
    PreparedOperationalFinalClaimSubmissionV2, PreparedOperationalFinalClaimTransportAuthorityV2,
    PreparedOperationalM8BackupProvenanceV2, PreparedOperationalM8FundingGateV2, RefundBroadcastV1,
    SessionRecordV1, SessionStoreError,
};
use kaystra_core::state::EvidenceRefV1;

use crate::store::{
    ClaimPersistenceSinkRequestV1, DomClaimAdmissionV1, DomClaimCustodyAuditV1,
    DomClaimCustodyClassificationV1, DomFinalClaimAdmissionV2, DomFinalClaimCustodyAuditV2,
    DomTerminalFinalityRecordV1, DomTerminalKindV1, DomTerminalReorgRecordV1,
    FinalClaimAttemptFactsV2, FinalClaimTransportAuthorityFactsV2, LatchedFinalClaimSubmissionV2,
};
use crate::{
    DomActionV1, DomActuatorCapabilityV1, DomActuatorError, DomActuatorResult, DomActuatorStoreV1,
    DomChainObservationV1, DomClaimBroadcastV1, DomFinalityObservationV1,
    DomFinalityRevalidationV1, DomLeaseV1, DomOperationDispositionV1, DomParticipantSigningShareV1,
    DomSessionBindingV1, DomSettlementChildBindingRequestV1, DomSettlementChildBindingV1,
    ScopedDomActionV1,
};

/// Concrete production signer over the retained nonce vault and Contracts journal.
pub type ContractsDomSignerV1<'store> = VaultBackedSignerV1<
    ContractsNonceVaultV1,
    ContractsReservationLookupCustodyV1<'store>,
    ContractsSigningSessionAuthorityV1,
>;

struct ExactDomRefundIdentityReaderV1;

impl ExactDomRefundBroadcasterV1 for ExactDomRefundIdentityReaderV1 {
    type Error = ChainAdapterError;
    type Receipt = [u8; 32];

    fn broadcast_exact_refund(&mut self, exact_bytes: &[u8]) -> Result<Self::Receipt, Self::Error> {
        canonical_transaction_hash_v1(exact_bytes)
    }
}

/// Linear inputs required to move one verified DOM claim into durable custody.
///
/// The request deliberately has no `Clone`, `Copy`, `Debug`, codec, or raw-byte
/// accessor. It keeps the live Contracts authorization borrowed while moving
/// both the route capability and the verified claim into the persistence call.
pub struct DomClaimPersistenceRequestV1<'authorization> {
    capability: DomActuatorCapabilityV1,
    authorization: &'authorization ConsumedClaimSigningAuthorizationV1,
    claim: VerifiedClaimTransactionV1,
    validation_height: u64,
    now_unix_ms: u64,
}

impl<'authorization> DomClaimPersistenceRequestV1<'authorization> {
    /// Bind the live Contracts authorization to the exact verified claim.
    pub const fn new(
        capability: DomActuatorCapabilityV1,
        authorization: &'authorization ConsumedClaimSigningAuthorizationV1,
        claim: VerifiedClaimTransactionV1,
        validation_height: u64,
        now_unix_ms: u64,
    ) -> Self {
        Self {
            capability,
            authorization,
            claim,
            validation_height,
            now_unix_ms,
        }
    }
}

/// Linear inputs required to move one verified DOM claim into the V2
/// `FinalClaim` exposure boundary.
///
/// Like its V1 predecessor the request has no `Clone`, `Copy`, `Debug`, codec
/// or raw-byte accessor. It keeps the live Contracts V2 authorization borrowed
/// while moving both the route capability and the verified claim into the
/// exposure call, so a single request can never authorize two exposures.
pub struct DomFinalClaimPersistenceRequestV2<'authorization> {
    capability: DomActuatorCapabilityV1,
    authorization: &'authorization ConsumedClaimSigningAuthorizationV2,
    claim: VerifiedClaimTransactionV1,
    validation_height: u64,
    now_unix_ms: u64,
}

impl<'authorization> DomFinalClaimPersistenceRequestV2<'authorization> {
    /// Bind the live Contracts V2 authorization to the exact verified claim.
    pub const fn new(
        capability: DomActuatorCapabilityV1,
        authorization: &'authorization ConsumedClaimSigningAuthorizationV2,
        claim: VerifiedClaimTransactionV1,
        validation_height: u64,
        now_unix_ms: u64,
    ) -> Self {
        Self {
            capability,
            authorization,
            claim,
            validation_height,
            now_unix_ms,
        }
    }
}

/// Opaque bundle proving both durable V2 `FinalClaim` admissions.
///
/// It carries the move-only DOM Contracts transport authority together with the
/// owner-only actuator mirror. Neither half can be reconstructed by a caller,
/// the bundle has no constructor, codec, `Clone`, `Copy` or `Debug`, and it
/// exposes no canonical claim bytes. Nothing may stage a `FinalClaim` 0x12
/// request before this bundle exists.
#[must_use = "the V2 final-claim admission bundle must be consumed by the 0x12 boundary"]
pub struct DomFinalClaimAdmissionBundleV2 {
    transport_authority: PreparedOperationalFinalClaimTransportAuthorityV2,
    admission: DomFinalClaimAdmissionV2,
}

impl DomFinalClaimAdmissionBundleV2 {
    /// Owner-only mirror of the validated economic admission.
    pub const fn admission(&self) -> &DomFinalClaimAdmissionV2 {
        &self.admission
    }

    /// Consume the bundle into the Contracts transport authority for 0x12.
    ///
    /// This is the only way the DSC1 boundary can obtain the authority, and it
    /// is reachable only once both durable records already exist.
    #[must_use]
    pub fn into_transport_authority(self) -> PreparedOperationalFinalClaimTransportAuthorityV2 {
        self.transport_authority
    }
}

/// Consume an opaque wallet-composed local share into the real retained signer.
///
/// The returned signer cannot outlive the session store. Its only signing
/// sessions are opaque handles minted or resumed by that exact store.
pub fn participant_contracts_signer_v1<'store>(
    nonce_vault: ContractsNonceVaultV1,
    session_store: &'store ContractsSessionStoreV1,
    expected_binding: DomSessionBindingV1,
    trusted_chain_id: TrustedChainIdV1,
    local_share: DomParticipantSigningShareV1,
) -> DomActuatorResult<ContractsDomSignerV1<'store>> {
    let _bound = DomContractsActuatorV1::bind(session_store, expected_binding)?;
    if trusted_chain_id.as_bytes() != &expected_binding.chain_id() {
        return Err(DomActuatorError::InvalidBinding);
    }
    let local_share = local_share.into_inner_for_binding(expected_binding)?;
    Ok(VaultBackedSignerV1::new_operational(
        nonce_vault,
        session_store.reservation_lookup_custody(),
        session_store.operational_signing_session_authority(),
        trusted_chain_id,
        local_share,
    ))
}

/// Inputs specific to one fresh, vault-backed shared-output contribution.
pub struct SharedOutputContributionRequestV1<'authority> {
    /// Authenticated chain identity for this session.
    pub trusted_chain_id: &'authority TrustedChainIdV1,
    /// Exact two-party roster frozen by the route.
    pub roster: &'authority [[u8; 32]],
    /// Participant direction in the shared output.
    pub role: DirectionV1,
    /// Retained owner-only nonce vault that seals the fresh share.
    pub nonce_vault: &'authority mut ContractsNonceVaultV1,
    /// Wall-clock value used only for the durable control transition.
    pub now_unix_ms: u64,
}

/// Inputs specific to rehydrating a vault-backed shared-output contribution.
pub struct SharedOutputRestartRequestV1<'authority> {
    /// Authenticated chain identity for this session.
    pub trusted_chain_id: &'authority TrustedChainIdV1,
    /// Exact two-party roster frozen by the route.
    pub roster: &'authority [[u8; 32]],
    /// Participant direction in the shared output.
    pub role: DirectionV1,
    /// Retained owner-only nonce vault used for authenticated recovery.
    pub nonce_vault: &'authority mut ContractsNonceVaultV1,
    /// Wall-clock value used only for the durable control transition.
    pub now_unix_ms: u64,
}

/// Authenticated material required to resume one collaborative Bulletproof.
pub struct CollaborativeBulletproofResumeRequestV1<'material> {
    /// Authenticated chain identity for this session.
    pub trusted_chain_id: TrustedChainIdV1,
    /// Exact statement retained for the round.
    pub statement: &'material BpStatementV1,
    /// Recovery capsule retained for the same round.
    pub recovery_capsule: &'material RecoveryCapsule,
    /// Wall-clock value used only for the durable control check.
    pub now_unix_ms: u64,
}

/// Complete immutable material for binding one operational signing session.
pub struct OperationalSigningSessionBindingRequestV1 {
    /// Authenticated chain identity for this session.
    pub trusted_chain_id: TrustedChainIdV1,
    /// Contract family being signed.
    pub contract_kind: ContractKindV1,
    /// Exact operational signing purpose.
    pub purpose: PurposeV1,
    /// Frozen participant roster.
    pub roster: ParticipantRosterV1,
    /// Exact transaction template consumed by the retained Store.
    pub transaction_template: Transaction,
    /// Kernel selected from the template.
    pub kernel_index: usize,
    /// Optional adaptor point for adaptor-signature rounds.
    pub adaptor_point: Option<PublicKey>,
    /// Wall-clock value used only for the durable control check.
    pub now_unix_ms: u64,
}

/// Inputs that consume one prepared M.8 gate into funding authority.
pub struct M8FundingAuthorizationIssueRequestV2<'material> {
    /// Move-only prepared M.8 funding gate.
    pub prepared: PreparedOperationalM8FundingGateV2,
    /// Exact funding transaction template.
    pub template: &'material ScriptlessTransactionTemplateV1,
    /// Exact Bulletproof statement bound to the template.
    pub statement: &'material BpStatementV1,
    /// Wall-clock value used only for the durable control check.
    pub now_unix_ms: u64,
}

/// Inputs required to adopt an exact retained refund after owner takeover.
pub struct PersistedRefundTakeoverRequestV1 {
    /// Exact refund action scope retained by the previous owner.
    pub scope: ScopedDomActionV1,
    /// Authorization digest retained with that scope.
    pub previous_authorization_digest: [u8; 32],
    /// Fresh chain context used by Contracts to revalidate the refund.
    pub current_context: DomTransactionValidationContextV1,
    /// Wall-clock value used for the new fencing transition.
    pub now_unix_ms: u64,
}

/// Owner-bound inputs for replaying one already-exposed V2 final claim.
///
/// Keeping the previous authorization identity and its exact action scope in
/// one request prevents either value from being accidentally paired with a
/// different recovery attempt at the public boundary.
pub struct SameOwnerFinalClaimRecoveryRequestV2 {
    /// Exact claim action scope retained by this process owner.
    pub scope: ScopedDomActionV1,
    /// Authorization digest committed by the expired lease.
    pub previous_authorization_digest: [u8; 32],
    /// Wall-clock value used for the owner-bound fencing transition.
    pub now_unix_ms: u64,
}

/// Participant-scoped façade over one already-open retained Contracts store.
///
/// It does not own or reproduce cryptographic state. Every operation first
/// crosses this crate's durable route/effect/fence capability and then delegates
/// to the existing non-forgeable Contracts API.
pub struct DomContractsActuatorV1<'store> {
    session_store: &'store ContractsSessionStoreV1,
    binding: DomSessionBindingV1,
}

impl core::fmt::Debug for DomContractsActuatorV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DomContractsActuatorV1([redacted])")
    }
}

impl<'store> DomContractsActuatorV1<'store> {
    /// Bind an existing retained session and reject route terms divergence.
    pub fn bind(
        session_store: &'store ContractsSessionStoreV1,
        binding: DomSessionBindingV1,
    ) -> DomActuatorResult<Self> {
        let current = session_store
            .load_session(binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        if current.session_id() != binding.session_id()
            || current.terms_hash() != binding.terms_digest()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(Self {
            session_store,
            binding,
        })
    }

    /// Authenticated current Contracts head, including restart/reorg projection.
    pub fn session_head(&self) -> DomActuatorResult<SessionRecordV1> {
        self.session_store
            .load_session(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)
    }

    /// Install a coordinator locator for the exact retained V2 funding outbox.
    ///
    /// The Contracts store recomputes the transaction identity from its
    /// byte-identical outbox; no caller-provided transaction id or bytes cross
    /// into the control store.
    pub fn bind_funding_settlement_child(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        request: DomSettlementChildBindingRequestV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomSettlementChildBindingV1> {
        self.require_settlement_child_request(request, DomActionV1::BroadcastFunding)?;
        let retained = self
            .session_store
            .resend_funding_broadcast(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let transaction_id = retained.funding_tx_hash();
        control.persist_authenticated_settlement_child_binding(
            lease,
            request,
            transaction_id,
            now_unix_ms,
        )
    }

    /// Reauthenticate one funding locator against both owner-only stores.
    pub fn funding_settlement_child_binding(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        custody_digest: [u8; 32],
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomSettlementChildBindingV1> {
        let retained = self
            .session_store
            .resend_funding_broadcast(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        self.require_settlement_child_binding(
            control,
            lease,
            custody_digest,
            DomActionV1::BroadcastFunding,
            retained.funding_tx_hash(),
            now_unix_ms,
        )
    }

    /// Install a coordinator locator for the exact retained V2 refund.
    ///
    /// Contracts first revalidates the timelock in the explicit current chain
    /// context. The opaque refund is then consumed by a local identity-only
    /// reader; canonical bytes never leave this module and no RPC occurs.
    pub fn bind_refund_settlement_child(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        request: DomSettlementChildBindingRequestV1,
        current_context: DomTransactionValidationContextV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomSettlementChildBindingV1> {
        self.require_settlement_child_request(request, DomActionV1::BroadcastRefund)?;
        let transaction_id = self.retained_refund_transaction_id(current_context)?;
        control.persist_authenticated_settlement_child_binding(
            lease,
            request,
            transaction_id,
            now_unix_ms,
        )
    }

    /// Reauthenticate one refund locator against both owner-only stores.
    pub fn refund_settlement_child_binding(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        custody_digest: [u8; 32],
        current_context: DomTransactionValidationContextV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomSettlementChildBindingV1> {
        let transaction_id = self.retained_refund_transaction_id(current_context)?;
        self.require_settlement_child_binding(
            control,
            lease,
            custody_digest,
            DomActionV1::BroadcastRefund,
            transaction_id,
            now_unix_ms,
        )
    }

    /// Install a coordinator locator for an already-latched V2 `FinalClaim`.
    ///
    /// Both the authoritative Contracts exposure lane and the owner-only mirror
    /// are reaudited before the locator is committed. Legacy V1 claim custody is
    /// never accepted by this production path.
    pub fn bind_final_claim_settlement_child_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        request: DomSettlementChildBindingRequestV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomSettlementChildBindingV1> {
        self.require_settlement_child_request(request, DomActionV1::BroadcastClaim)?;
        let transaction_id = self.retained_final_claim_transaction_id_v2(
            control,
            lease,
            trusted_chain_id,
            now_unix_ms,
        )?;
        control.persist_authenticated_settlement_child_binding(
            lease,
            request,
            transaction_id,
            now_unix_ms,
        )
    }

    /// Reauthenticate one V2 final-claim locator against both owner-only stores.
    pub fn final_claim_settlement_child_binding_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        custody_digest: [u8; 32],
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomSettlementChildBindingV1> {
        let transaction_id = self.retained_final_claim_transaction_id_v2(
            control,
            lease,
            trusted_chain_id,
            now_unix_ms,
        )?;
        self.require_settlement_child_binding(
            control,
            lease,
            custody_digest,
            DomActionV1::BroadcastClaim,
            transaction_id,
            now_unix_ms,
        )
    }

    fn require_settlement_child_request(
        &self,
        request: DomSettlementChildBindingRequestV1,
        action: DomActionV1,
    ) -> DomActuatorResult<()> {
        if request.scope().binding() != self.binding || request.scope().action() != action {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        request.validate()
    }

    fn require_settlement_child_binding(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        custody_digest: [u8; 32],
        action: DomActionV1,
        transaction_id: [u8; 32],
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomSettlementChildBindingV1> {
        let retained = control.settlement_child_binding(lease, custody_digest, now_unix_ms)?;
        if retained.request().scope().binding() != self.binding
            || retained.request().scope().action() != action
            || retained.transaction_id() != transaction_id
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(retained)
    }

    fn retained_refund_transaction_id(
        &self,
        current_context: DomTransactionValidationContextV1,
    ) -> DomActuatorResult<[u8; 32]> {
        if current_context.chain_id() != &self.binding.chain_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let refund = self
            .session_store
            .load_refund_broadcast(self.binding.session_id(), current_context)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        refund
            .dispatch_with(&mut ExactDomRefundIdentityReaderV1)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)
    }

    fn retained_final_claim_transaction_id_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<[u8; 32]> {
        let classification =
            self.classify_final_claim_custody_v2(control, lease, trusted_chain_id, now_unix_ms)?;
        if classification.is_unattempted() {
            return Err(DomActuatorError::InvalidStage);
        }
        let custody = control.audit_final_claim_custody_v2(lease, self.binding, now_unix_ms)?;
        Ok(custody.tx_hash())
    }

    /// Generate and seal this participant's fresh shared-output contribution.
    ///
    /// Fresh material is generated inside `dom-adaptor`, encrypted and backed
    /// up by `ContractsNonceVaultV1` before any public contribution is returned.
    pub fn contribute_shared_output(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        request: SharedOutputContributionRequestV1<'_>,
    ) -> DomActuatorResult<PendingSessionBlindingShareCapabilityV1> {
        let SharedOutputContributionRequestV1 {
            trusted_chain_id,
            roster,
            role,
            nonce_vault,
            now_unix_ms,
        } = request;
        self.require_live_action(
            control,
            lease,
            &capability,
            DomActionV1::ContributeSharedOutput,
            now_unix_ms,
        )?;
        if !capability.is_fresh() {
            return Err(DomActuatorError::SecretReuseDetected);
        }
        let index = usize::from(self.binding.participant().protocol_index());
        if trusted_chain_id.as_bytes() != &self.binding.chain_id()
            || roster.len() != 2
            || roster.get(index) != Some(&self.binding.participant().participant_id())
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let pending = contribute_vault_backed_blinding_share_v1(
            trusted_chain_id,
            self.binding.session_id(),
            roster,
            role,
            u16::from(self.binding.participant().protocol_index()),
            self.binding.terms_digest(),
            nonce_vault,
        )
        .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
        let receipt = pending.binding().binding_digest_v1();
        control.complete_action(lease, capability, receipt, now_unix_ms)?;
        Ok(pending)
    }

    /// Rehydrate, rather than regenerate, a shared-output contribution after restart.
    ///
    /// This path accepts only a capability reconstructed from an existing
    /// durable intent. It locates the unique encrypted share using stable
    /// public context and idempotently records the same binding receipt.
    pub fn resume_shared_output_after_restart(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        request: SharedOutputRestartRequestV1<'_>,
    ) -> DomActuatorResult<RestartedSessionBlindingShareV1> {
        let SharedOutputRestartRequestV1 {
            trusted_chain_id,
            roster,
            role,
            nonce_vault,
            now_unix_ms,
        } = request;
        if capability.scope().binding() != self.binding
            || capability.scope().action() != DomActionV1::ContributeSharedOutput
            || !capability.is_resumed()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        control.validate_retained_capability(lease, &capability, now_unix_ms)?;
        let index = usize::from(self.binding.participant().protocol_index());
        if trusted_chain_id.as_bytes() != &self.binding.chain_id()
            || roster.len() != 2
            || roster.get(index) != Some(&self.binding.participant().participant_id())
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let request = SharedBlindingRestartRequestV1::new(
            trusted_chain_id,
            self.binding.session_id(),
            roster,
            role,
            u16::from(self.binding.participant().protocol_index()),
            self.binding.terms_digest(),
        )
        .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
        let retained = resume_vault_backed_blinding_share_after_restart_v1(request, nonce_vault);
        let restarted = resume_or_retry_shared_output(retained, || {
            // The control intent may have survived a crash immediately before
            // the encrypted share was sealed. The helper invokes this closure
            // only after the vault has reauthenticated its authority, audited
            // the complete namespace and proved exact absence.
            contribute_vault_backed_blinding_share_v1(
                trusted_chain_id,
                self.binding.session_id(),
                roster,
                role,
                u16::from(self.binding.participant().protocol_index()),
                self.binding.terms_digest(),
                nonce_vault,
            )
            .map(RestartedSessionBlindingShareV1::Pending)
        })?;
        let receipt = match &restarted {
            RestartedSessionBlindingShareV1::Pending(pending) => {
                pending.binding().binding_digest_v1()
            }
            RestartedSessionBlindingShareV1::Bound { capability, .. } => {
                capability.binding().binding_digest_v1()
            }
        };
        control.complete_action(lease, capability, receipt, now_unix_ms)?;
        Ok(restarted)
    }

    /// Consume both authenticated backup acknowledgements into durable M.8 provenance.
    ///
    /// This owner-bound bridge neither recreates acknowledgement authority
    /// from disk nor issues a funding gate. Both linear inputs must belong to
    /// this exact chain, session and terms binding before they reach the Store.
    pub fn persist_operational_m8_backup_provenance_v2(
        &self,
        acknowledgements: [BoundShareBackupAckV2; 2],
    ) -> DomActuatorResult<PreparedOperationalM8BackupProvenanceV2> {
        let expected_chain_id = self.binding.chain_id();
        let expected_session_id = self.binding.session_id();
        let expected_terms_hash = self.binding.terms_digest();
        if acknowledgements.iter().any(|acknowledgement| {
            let binding = acknowledgement.binding();
            binding.chain_id() != &expected_chain_id
                || binding.session_id() != &expected_session_id
                || binding.terms_hash() != &expected_terms_hash
        }) {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        self.session_store
            .persist_operational_m8_backup_provenance_v2(acknowledgements)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)
    }

    /// Reconstruct the exact next collaborative-Bulletproof stage after restart.
    pub fn resume_collaborative_bulletproof(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        request: CollaborativeBulletproofResumeRequestV1<'_>,
    ) -> DomActuatorResult<AuthenticatedOperationalBpContinuationV1> {
        let CollaborativeBulletproofResumeRequestV1 {
            trusted_chain_id,
            statement,
            recovery_capsule,
            now_unix_ms,
        } = request;
        self.require_live_action(
            control,
            lease,
            capability,
            DomActionV1::CollaborativeBulletproof,
            now_unix_ms,
        )?;
        if trusted_chain_id.as_bytes() != &self.binding.chain_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        self.session_store
            .resume_operational_bp_continuation(
                trusted_chain_id,
                self.binding.session_id(),
                self.binding.terms_digest(),
                statement,
                recovery_capsule,
            )
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)
    }

    /// Complete the local Bulletproof action only from the Store-verified final proof.
    pub fn complete_collaborative_bulletproof(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        continuation: AuthenticatedOperationalBpContinuationV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<AuthenticatedOperationalBpFinalProofV1> {
        self.require_live_action(
            control,
            lease,
            &capability,
            DomActionV1::CollaborativeBulletproof,
            now_unix_ms,
        )?;
        if continuation.chain_id() != self.binding.chain_id()
            || continuation.session_id() != self.binding.session_id()
            || continuation.terms_hash() != self.binding.terms_digest()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let proof = continuation
            .into_final_proof()
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        control.complete_action(lease, capability, proof.proof_digest(), now_unix_ms)?;
        Ok(proof)
    }

    /// Bind a fresh real signing round to the exact Contracts journal and template.
    pub fn bind_operational_signing_session(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        request: OperationalSigningSessionBindingRequestV1,
    ) -> DomActuatorResult<AcceptedContractsSigningSessionV1> {
        let OperationalSigningSessionBindingRequestV1 {
            trusted_chain_id,
            contract_kind,
            purpose,
            roster,
            transaction_template,
            kernel_index,
            adaptor_point,
            now_unix_ms,
        } = request;
        self.require_live_action(
            control,
            lease,
            capability,
            action_for_purpose(purpose)?,
            now_unix_ms,
        )?;
        if trusted_chain_id.as_bytes() != &self.binding.chain_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        self.session_store
            .bind_operational_signing_session(
                trusted_chain_id,
                self.binding.session_id(),
                contract_kind,
                purpose,
                roster,
                transaction_template,
                kernel_index,
                adaptor_point,
            )
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)
    }

    /// Rehydrate a previously bound signing round exclusively from retained state.
    pub fn resume_operational_signing_session(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        trusted_chain_id: TrustedChainIdV1,
        purpose: PurposeV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<AcceptedContractsSigningSessionV1> {
        self.require_live_action(
            control,
            lease,
            capability,
            action_for_purpose(purpose)?,
            now_unix_ms,
        )?;
        if trusted_chain_id.as_bytes() != &self.binding.chain_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        self.session_store
            .resume_operational_signing_session(
                trusted_chain_id,
                self.binding.session_id(),
                purpose,
            )
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)
    }

    /// Persist a verified refund and M.8 gate before enabling any funding action.
    pub fn persist_verified_refund_m8_gate_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        backup: PreparedOperationalM8BackupProvenanceV2,
        request: OperationalM8FundingGatePreparationV2<'_>,
        now_unix_ms: u64,
    ) -> DomActuatorResult<PreparedOperationalM8FundingGateV2> {
        self.require_live_action(
            control,
            lease,
            &capability,
            DomActionV1::PresignRefund,
            now_unix_ms,
        )?;
        if capability.is_resumed() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let prepared = self
            .session_store
            .prepare_operational_m8_funding_gate_authority_v2(backup, request)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        control.complete_action(
            lease,
            capability,
            prepared.ready_to_fund_vote_payload(),
            now_unix_ms,
        )?;
        Ok(prepared)
    }

    /// Recover a refund action after the Contracts gate was synced but its receipt was lost.
    pub fn resume_verified_refund_m8_gate_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<PreparedOperationalM8FundingGateV2> {
        if capability.scope().binding() != self.binding
            || capability.scope().action() != DomActionV1::PresignRefund
            || !capability.is_resumed()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        control.validate_retained_capability(lease, &capability, now_unix_ms)?;
        let prepared = self
            .session_store
            .resume_operational_m8_funding_gate_authority_v2(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        control.complete_action(
            lease,
            capability,
            prepared.ready_to_fund_vote_payload(),
            now_unix_ms,
        )?;
        Ok(prepared)
    }

    /// Rehydrate the same immutable M.8 gate after restart.
    pub fn resume_m8_funding_gate_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<PreparedOperationalM8FundingGateV2> {
        self.require_live_action(
            control,
            lease,
            capability,
            DomActionV1::BroadcastFunding,
            now_unix_ms,
        )?;
        self.session_store
            .resume_operational_m8_funding_gate_authority_v2(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)
    }

    /// Consume the prepared gate into the existing one-shot funding authority.
    pub fn issue_m8_funding_authorization_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        request: M8FundingAuthorizationIssueRequestV2<'_>,
    ) -> DomActuatorResult<OperationalM8FundingAuthorizationV2> {
        let M8FundingAuthorizationIssueRequestV2 {
            prepared,
            template,
            statement,
            now_unix_ms,
        } = request;
        self.require_live_action(
            control,
            lease,
            capability,
            DomActionV1::BroadcastFunding,
            now_unix_ms,
        )?;
        let result = if capability.is_resumed() {
            self.session_store
                .resume_prepared_operational_m8_funding_authorization_v2(
                    prepared, template, statement,
                )
        } else {
            self.session_store
                .issue_prepared_operational_m8_funding_authorization_v2(
                    prepared, template, statement,
                )
        };
        result.map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)
    }

    /// Persist exact verified funding bytes before returning broadcast authority.
    pub fn persist_verified_m8_funding_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        funding: VerifiedM8FundingTransactionV2,
        now_unix_ms: u64,
    ) -> DomActuatorResult<FundingBroadcastV1> {
        self.require_live_action(
            control,
            lease,
            &capability,
            DomActionV1::BroadcastFunding,
            now_unix_ms,
        )?;
        let tx_hash = *funding.tx_hash();
        let mut sink = self.session_store.m8_funding_transaction_sink_ref_v2();
        let broadcast = funding
            .persist_with_m8_sink_v2(&mut sink)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        control.complete_action(lease, capability, tx_hash, now_unix_ms)?;
        Ok(broadcast)
    }

    /// Reload byte-identical funding after a post-persistence crash.
    pub fn resume_persisted_funding_broadcast(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<FundingBroadcastV1> {
        if capability.scope().binding() != self.binding
            || capability.scope().action() != DomActionV1::BroadcastFunding
            || !capability.is_resumed()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        control.validate_retained_capability(lease, &capability, now_unix_ms)?;
        let retransmission = self
            .session_store
            .resend_funding_broadcast(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let tx_hash = retransmission.funding_tx_hash();
        control.complete_action(lease, capability, tx_hash, now_unix_ms)?;
        Ok(retransmission.into_broadcast())
    }

    /// Adopt an exact persisted funding replay under a newer fencing epoch.
    ///
    /// The old completed control receipt is re-fenced only after Contracts
    /// reconstructs the same immutable transaction hash from its retained
    /// funding outbox. This is safe whether the old RPC call never started or
    /// reached the node: both owners can submit only byte-identical funding.
    pub fn adopt_persisted_funding_after_takeover(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        previous_authorization_digest: [u8; 32],
        now_unix_ms: u64,
    ) -> DomActuatorResult<FundingBroadcastV1> {
        if scope.binding() != self.binding || scope.action() != DomActionV1::BroadcastFunding {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let retransmission = self
            .session_store
            .resend_funding_broadcast(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let tx_hash = retransmission.funding_tx_hash();
        let capability = control.reauthorize_retained_exact_replay(
            lease,
            scope,
            previous_authorization_digest,
            tx_hash,
            now_unix_ms,
        )?;
        control.complete_action(lease, capability, tx_hash, now_unix_ms)?;
        Ok(retransmission.into_broadcast())
    }

    /// Submit the exact already-persisted funding transaction to the frozen DOM node.
    ///
    /// The linear broadcast value is the outbox authority: its bytes remain
    /// private to Contracts and are borrowed by the real adapter only for this
    /// RPC call. If the result is ambiguous, restart obtains the byte-identical
    /// retry through [`Self::resume_persisted_funding_broadcast`].
    pub fn dispatch_funding_broadcast(
        &self,
        runtime: &RealDomRpcRuntimeV1,
        broadcast: FundingBroadcastV1,
    ) -> DomActuatorResult<SubmissionReceiptV1> {
        self.require_dom_runtime_binding(runtime)?;
        let tx_hash = broadcast.funding_tx_hash();
        let retained_tx_hash = self
            .session_store
            .resend_funding_broadcast(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?
            .funding_tx_hash();
        let receipt =
            submit_after_funding_preflight(broadcast, tx_hash, retained_tx_hash, |exact| {
                runtime
                    .submit_persisted_funding(exact)
                    .map_err(|_| DomActuatorError::RpcAuthorityUnavailable)
            })?;
        if receipt.tx_hash() != tx_hash || !receipt.is_economically_admitted() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(receipt)
    }

    /// Commit funding finality only from real-scanner evidence for the exact outbox.
    ///
    /// The transaction hash is recomputed by the retained Contracts funding
    /// outbox and the observed depth must meet the registry-authenticated DOM
    /// finality policy. Exact transaction bytes are never copied into this
    /// control store.
    pub fn record_verified_funding_confirmed(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        evidence: CanonicalDomFundingEvidenceV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        let retransmission = self
            .session_store
            .resend_funding_broadcast(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        if evidence.tx_hash() != retransmission.funding_tx_hash()
            || evidence.confirmation_depth() < self.binding.min_confirmations()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let evidence_digest = funding_evidence_digest(&evidence);
        control.record_chain_observation(
            lease,
            self.binding,
            evidence_digest,
            DomChainObservationV1::FundingConfirmed,
            evidence_digest,
            now_unix_ms,
        )
    }

    /// Resolve, verify and checkpoint exact funding finality from retained V2 facts.
    ///
    /// The evidence reference may use the closed resolve shape `(chain, tx, 0,
    /// 0, 0)`. The runtime locates the transaction on one authenticated branch
    /// through its tip; neither a coordinator block locator nor shared-output
    /// facts are accepted. Absence and shallow depth return `FinalityPending`.
    pub fn observe_funding_finality(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        runtime: &RealDomRpcRuntimeV1,
        trusted_chain_id: &TrustedChainIdV1,
        evidence: &EvidenceRefV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalityObservationV1> {
        self.require_dom_runtime_binding(runtime)?;
        self.require_trusted_chain_binding(trusted_chain_id)?;
        let contract = self
            .session_store
            .real_dom_contract_facts_v2(*trusted_chain_id, self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        if contract.chain_id() != &self.binding.chain_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let finality = runtime
            .verified_funding_finality(
                evidence,
                *contract.funding_tx_hash(),
                *contract.shared_output_commitment(),
                self.binding.min_confirmations(),
                self.binding.max_reorg_depth(),
            )
            .map_err(map_finality_error)?;
        self.persist_funding_finality(control, lease, finality, now_unix_ms)
    }

    /// Revalidate the active funding checkpoint against the authenticated tip.
    ///
    /// A still-canonical transaction is returned as a typed final observation;
    /// an authenticated bounded fork is durably committed before its typed
    /// invalidation receipt is released. The exact expected transaction is
    /// reloaded from the owner-only Contracts store on every call.
    pub fn revalidate_funding_settlement_finality(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        runtime: &RealDomRpcRuntimeV1,
        trusted_chain_id: &TrustedChainIdV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalityRevalidationV1> {
        self.require_dom_runtime_binding(runtime)?;
        self.require_trusted_chain_binding(trusted_chain_id)?;
        let contract = self
            .session_store
            .real_dom_contract_facts_v2(*trusted_chain_id, self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        if contract.chain_id() != &self.binding.chain_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let retained = control.retained_terminal_checkpoint(
            lease,
            self.binding,
            DomTerminalKindV1::Funding,
            now_unix_ms,
        )?;
        if retained.kind != DomTerminalKindV1::Funding
            || retained.tx_hash != *contract.funding_tx_hash()
            || retained.minimum_confirmations != self.binding.min_confirmations()
            || retained.max_reorg_depth != self.binding.max_reorg_depth()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let reorg = match runtime.verified_funding_reorg(
            &retained.checkpoint_bytes,
            retained.tx_hash,
            retained.minimum_confirmations,
            retained.max_reorg_depth,
        ) {
            Err(RealDomError::TransactionStillCanonical) => {
                return Ok(DomFinalityRevalidationV1::StillFinal(
                    terminal_finality_observation(&retained),
                ));
            }
            Ok(reorg) => reorg,
            Err(error) => return Err(map_reorg_error(error)),
        };
        if reorg.prior_evidence_digest() != retained.evidence_digest
            || reorg.prior_block_height() != retained.block_height
            || reorg.prior_block_hash() != retained.block_hash
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let invalidated = DomFinalityRevalidationV1::Invalidated {
            transaction_id: retained.tx_hash,
            prior_evidence_digest: retained.evidence_digest,
            prior_block_height: retained.block_height,
            prior_block_hash: retained.block_hash,
            reorg_evidence_digest: reorg.evidence_digest(),
        };
        self.persist_funding_reorg(control, lease, reorg, now_unix_ms)?;
        Ok(invalidated)
    }

    /// Recover an already-committed funding invalidation after a crash.
    pub fn recover_funding_settlement_invalidation(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<Option<DomFinalityRevalidationV1>> {
        self.require_trusted_chain_binding(trusted_chain_id)?;
        let contract = self
            .session_store
            .real_dom_contract_facts_v2(*trusted_chain_id, self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let invalidation = control.retained_terminal_invalidation(
            lease,
            self.binding,
            DomTerminalKindV1::Funding,
            now_unix_ms,
        )?;
        recover_terminal_invalidation(
            invalidation,
            DomTerminalKindV1::Funding,
            *contract.funding_tx_hash(),
        )
    }

    /// Release the exact retained refund only after its real timelock validates.
    pub fn prepare_refund_broadcast(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        current_context: DomTransactionValidationContextV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<RefundBroadcastV1> {
        self.require_live_action(
            control,
            lease,
            &capability,
            DomActionV1::BroadcastRefund,
            now_unix_ms,
        )?;
        if current_context.chain_id() != &self.binding.chain_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let tx_hash = self
            .session_store
            .durable_m8_refund_tx_hash(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let broadcast = self
            .session_store
            .load_refund_broadcast(self.binding.session_id(), current_context)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        control.complete_action(lease, capability, tx_hash, now_unix_ms)?;
        Ok(broadcast)
    }

    /// Reload the exact retained refund after a post-persistence crash.
    ///
    /// The current chain context is revalidated by Contracts on every retry;
    /// this actuator never caches or reconstructs refund bytes. A capability
    /// resumed from the same completed control intent is required.
    pub fn resume_persisted_refund_broadcast(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        current_context: DomTransactionValidationContextV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<RefundBroadcastV1> {
        if capability.scope().binding() != self.binding
            || capability.scope().action() != DomActionV1::BroadcastRefund
            || !capability.is_resumed()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        control.validate_retained_capability(lease, &capability, now_unix_ms)?;
        if current_context.chain_id() != &self.binding.chain_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let tx_hash = self
            .session_store
            .durable_m8_refund_tx_hash(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let broadcast = self
            .session_store
            .load_refund_broadcast(self.binding.session_id(), current_context)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        control.complete_action(lease, capability, tx_hash, now_unix_ms)?;
        Ok(broadcast)
    }

    /// Adopt an exact persisted refund replay under a newer fencing epoch.
    ///
    /// Contracts revalidates the timelock at `current_context` and supplies
    /// both the retained transaction hash and the linear exact-byte value.
    /// No caller-shaped transaction can enter the completed-operation replay.
    pub fn adopt_persisted_refund_after_takeover(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        request: PersistedRefundTakeoverRequestV1,
    ) -> DomActuatorResult<RefundBroadcastV1> {
        let PersistedRefundTakeoverRequestV1 {
            scope,
            previous_authorization_digest,
            current_context,
            now_unix_ms,
        } = request;
        if scope.binding() != self.binding || scope.action() != DomActionV1::BroadcastRefund {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        if current_context.chain_id() != &self.binding.chain_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let tx_hash = self
            .session_store
            .durable_m8_refund_tx_hash(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let broadcast = self
            .session_store
            .load_refund_broadcast(self.binding.session_id(), current_context)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let capability = control.reauthorize_retained_exact_replay(
            lease,
            scope,
            previous_authorization_digest,
            tx_hash,
            now_unix_ms,
        )?;
        control.complete_action(lease, capability, tx_hash, now_unix_ms)?;
        Ok(broadcast)
    }

    /// Submit the exact retained refund through the frozen real-DOM adapter.
    ///
    /// Timelock and canonical transaction validation occurred before the
    /// linear value was released. An ambiguous call consumes only this
    /// process-local attempt; the exact refund remains in Contracts for a
    /// freshly validated retry.
    pub fn dispatch_refund_broadcast(
        &self,
        runtime: &RealDomRpcRuntimeV1,
        broadcast: RefundBroadcastV1,
    ) -> DomActuatorResult<SubmissionReceiptV1> {
        self.require_dom_runtime_binding(runtime)?;
        let tx_hash = self
            .session_store
            .durable_m8_refund_tx_hash(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let receipt = runtime
            .submit_persisted_refund(broadcast)
            .map_err(|_| DomActuatorError::RpcAuthorityUnavailable)?;
        if receipt.tx_hash() != tx_hash || !receipt.is_economically_admitted() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(receipt)
    }

    /// Complete post-anchor claim signing only from the reconstructed Store artifact.
    pub fn complete_post_anchor_claim_adaptor(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        pre_signature: AuthenticatedPostAnchorClaimPreSignatureV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<AuthenticatedPostAnchorClaimPreSignatureV1> {
        self.require_live_action(
            control,
            lease,
            &capability,
            DomActionV1::PresignClaimAdaptor,
            now_unix_ms,
        )?;
        if pre_signature.session_id() != &self.binding.session_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let receipt = *pre_signature.artifact_record_digest();
        control.complete_action(lease, capability, receipt, now_unix_ms)?;
        Ok(pre_signature)
    }

    /// Persist the exact route effect before an adapted claim can enter custody.
    ///
    /// The Contracts authority is revalidated against this exact Store opening;
    /// its session, terms, template and shared output are the only accepted
    /// claim facts. The resulting control capability commits the immutable
    /// issuance/consumption ancestry rather than a caller-provided digest.
    pub fn authorize_claim_broadcast(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<(DomActuatorCapabilityV1, DomOperationDispositionV1)> {
        if scope.binding() != self.binding || scope.action() != DomActionV1::BroadcastClaim {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let evidence_digest = self.revalidate_claim_authority(authorization)?;
        control.authorize_action(lease, scope, evidence_digest, None, now_unix_ms)
    }

    /// Persist an exact fully adapted claim before any node submission.
    ///
    /// The claim value exposes neither its signature nor canonical bytes. It
    /// is consumed directly into the owner-only actuator custody row, bound to
    /// this route/effect/fence and the retained template/shared output. Only a
    /// linear opaque custody handle leaves after the SQLite commit is durable;
    /// legacy V1 cannot use it to authorize a fresh node submission.
    pub fn persist_verified_claim(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        request: DomClaimPersistenceRequestV1<'_>,
    ) -> DomActuatorResult<DomClaimBroadcastV1> {
        let DomClaimPersistenceRequestV1 {
            capability,
            authorization,
            claim,
            validation_height,
            now_unix_ms,
        } = request;
        if capability.scope().binding() != self.binding
            || capability.scope().action() != DomActionV1::BroadcastClaim
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let authority_evidence_digest = self.revalidate_claim_authority(authorization)?;
        let mut sink = control.claim_persistence_sink(ClaimPersistenceSinkRequestV1 {
            lease,
            capability,
            expected_template_hash: *authorization.claim_template_hash(),
            expected_shared_output_commitment: *authorization.dom_shared_output_commitment(),
            expected_claim_authority_evidence_digest: authority_evidence_digest,
            validation_height,
            now_unix_ms,
        })?;
        claim.persist_with_claim_sink_v1(&mut sink)
    }

    fn revalidate_claim_authority(
        &self,
        authorization: &ConsumedClaimSigningAuthorizationV1,
    ) -> DomActuatorResult<[u8; 32]> {
        self.session_store
            .revalidate_consumed_post_anchor_dom_claim_signing(authorization)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        if authorization.session_id() != &self.binding.session_id()
            || authorization.terms_hash() != &self.binding.terms_digest()
            || authorization.dom_confirmation_depth() < self.binding.min_confirmations()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(claim_authority_evidence_digest(authorization))
    }

    /// Reauthenticate the public recovery disposition of retained V1 custody.
    pub fn audit_retained_claim_custody_v1(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomClaimCustodyAuditV1> {
        control.audit_retained_claim_custody_v1(lease, self.binding, now_unix_ms)
    }

    /// Reload an opaque exact-claim handle only under durable admission.
    ///
    /// Unattempted and potentially exposed legacy V1 custody fail before the
    /// exact bytes leave the owner-only control store.
    pub fn resume_persisted_claim_broadcast(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomClaimBroadcastV1> {
        if capability.scope().binding() != self.binding
            || capability.scope().action() != DomActionV1::BroadcastClaim
            || !capability.is_resumed()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        control.resume_claim_broadcast(lease, &capability, now_unix_ms)
    }

    /// Reject legacy V1 claim takeover without minting a new send authority.
    pub fn adopt_persisted_claim_after_takeover(
        &self,
        _control: &mut DomActuatorStoreV1,
        _lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        _previous_authorization_digest: [u8; 32],
        _now_unix_ms: u64,
    ) -> DomActuatorResult<DomClaimBroadcastV1> {
        if scope.binding() != self.binding || scope.action() != DomActionV1::BroadcastClaim {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Err(DomActuatorError::InvalidStage)
    }

    /// Reauthenticate an already-admitted exact legacy claim without new RPC.
    ///
    /// V4 custody without a durable economic-admission record is recovery-only:
    /// this method fails before changing the attempt latch or invoking the DOM
    /// submission endpoint. A retained admission is merely reissued; the exact
    /// bytes are not sent again and no receipt facts are manufactured.
    pub fn dispatch_claim_broadcast(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        adapter: &DomHttpChainAdapterV1,
        broadcast: DomClaimBroadcastV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomClaimAdmissionV1> {
        self.require_dom_adapter_binding(adapter)?;
        control.prepare_claim_dispatch(lease, &broadcast, now_unix_ms)
    }

    /// Reissue the exact opaque claim admission after restart or takeover.
    ///
    /// This path never reloads broadcast bytes and never submits to the node.
    /// It audits the owner-only receipt record, exact claim custody and
    /// completed operation before returning a new move-only handle suitable
    /// for the future prepared Contracts `FinalClaim` 0x12 authority. It does
    /// not write the Contracts Store pre-submit irreversible-exposure intent;
    /// that transition must already exist before dispatch and remains
    /// exclusively owned by that future 0x12 boundary.
    pub fn resume_persisted_claim_admission(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomClaimAdmissionV1> {
        control.resume_claim_admission(lease, self.binding, now_unix_ms)
    }

    /// Persist the exact V2 route effect before an adapted claim can be exposed.
    ///
    /// The Contracts V2 authority is revalidated against this exact Store
    /// opening. Unlike V1 it also freezes the canonical `FinalClaim` roles: the
    /// local participant must be the frozen `dom_claim_sender_id` and the
    /// counterparty must be the frozen `final_claim_receiver_id`. No index,
    /// direction or roster position is ever used to infer either role.
    pub fn authorize_final_claim_broadcast_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        trusted_chain_id: &TrustedChainIdV1,
        authorization: &ConsumedClaimSigningAuthorizationV2,
        now_unix_ms: u64,
    ) -> DomActuatorResult<(DomActuatorCapabilityV1, DomOperationDispositionV1)> {
        if scope.binding() != self.binding || scope.action() != DomActionV1::BroadcastClaim {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let evidence_digest =
            self.revalidate_claim_authority_v2(trusted_chain_id, authorization)?;
        control.authorize_action(lease, scope, evidence_digest, None, now_unix_ms)
    }

    /// Rehydrate the consumed post-anchor claim authority from this façade's
    /// exact Contracts Store opening.
    ///
    /// The returned value remains move-only and process-bound. It is
    /// revalidated immediately against the façade's frozen chain, session,
    /// terms and FinalClaim roles, so a composition root cannot pair an
    /// authorization from a second opening or another route with this owner.
    pub fn resume_consumed_final_claim_authority_v2(
        &self,
        trusted_chain_id: &TrustedChainIdV1,
    ) -> DomActuatorResult<ConsumedClaimSigningAuthorizationV2> {
        self.require_trusted_chain_binding(trusted_chain_id)?;
        let authorization = self
            .session_store
            .resume_consumed_post_anchor_dom_claim_signing_v2(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        self.revalidate_claim_authority_v2(trusted_chain_id, &authorization)?;
        Ok(authorization)
    }

    /// Move one exact adapted claim into Contracts custody and latch the
    /// irreversible pre-RPC exposure attempt.
    ///
    /// Ordering is normative and cannot be reordered:
    /// 1. this actuator reauthenticates the durable action binding read-only,
    ///    so a capability that is not bound to this exact revalidated authority
    ///    fails closed before any exposure marker exists;
    /// 2. the DOM Contracts store consumes the linear verified claim, persists
    ///    the exposure record and then the durable `adaptor_secret_exposed`
    ///    successor. That marker is owned exclusively by Contracts, is written
    ///    before the first submission and never regresses, not on RPC error and
    ///    not on reorg. This actuator has no API that can write it;
    /// 3. only then does this control plane latch the attempt and advance the
    ///    session to `ClaimBroadcast`, which by itself removes every refund
    ///    stage.
    ///
    /// The returned handle carries no canonical bytes and cannot be dispatched
    /// through a generic broadcaster.
    pub fn persist_final_claim_exposure_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        request: DomFinalClaimPersistenceRequestV2<'_>,
    ) -> DomActuatorResult<(
        PreparedOperationalFinalClaimSubmissionV2,
        LatchedFinalClaimSubmissionV2,
    )> {
        let DomFinalClaimPersistenceRequestV2 {
            capability,
            authorization,
            claim,
            validation_height,
            now_unix_ms,
        } = request;
        if capability.scope().binding() != self.binding
            || capability.scope().action() != DomActionV1::BroadcastClaim
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let evidence_digest =
            self.revalidate_claim_authority_v2(trusted_chain_id, authorization)?;
        control.require_prepared_final_claim_authority_v2(
            lease,
            &capability,
            evidence_digest,
            now_unix_ms,
        )?;
        let mut sink = self
            .session_store
            .operational_final_claim_intent_sink_v2(
                *trusted_chain_id,
                authorization,
                claim_action_scope_digest_v2(capability.scope(), evidence_digest),
                validation_height,
            )
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let prepared = claim
            .persist_with_claim_sink_v1(&mut sink)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let latched = self.latch_exposed_final_claim_attempt_v2(
            control,
            lease,
            &capability,
            authorization,
            &prepared,
            now_unix_ms,
        )?;
        Ok((prepared, latched))
    }

    /// Reissue the byte-identical V2 submission handle after an ambiguous send.
    ///
    /// Contracts reemits only the exact bytes already committed to the exposure
    /// record; no new claim, signature or transaction identity can be produced.
    /// A further attempt is latched before the retry leaves this process, and a
    /// session whose economic admission is already durable is refused instead of
    /// being resubmitted.
    pub fn resume_final_claim_broadcast_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        trusted_chain_id: &TrustedChainIdV1,
        authorization: &ConsumedClaimSigningAuthorizationV2,
        now_unix_ms: u64,
    ) -> DomActuatorResult<(
        PreparedOperationalFinalClaimSubmissionV2,
        LatchedFinalClaimSubmissionV2,
    )> {
        if capability.scope().binding() != self.binding
            || capability.scope().action() != DomActionV1::BroadcastClaim
            || !capability.is_resumed()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let evidence_digest =
            self.revalidate_claim_authority_v2(trusted_chain_id, authorization)?;
        control.require_prepared_final_claim_authority_v2(
            lease,
            capability,
            evidence_digest,
            now_unix_ms,
        )?;
        let prepared = self
            .session_store
            .resume_operational_final_claim_broadcast_v2(
                *trusted_chain_id,
                self.binding.session_id(),
            )
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let latched = self.latch_exposed_final_claim_attempt_v2(
            control,
            lease,
            capability,
            authorization,
            &prepared,
            now_unix_ms,
        )?;
        Ok((prepared, latched))
    }

    /// Reissue the byte-identical exposed claim after an expired lease held by
    /// the same retained process owner.
    ///
    /// The Contracts store is consulted before the control plane is
    /// re-fenced, so only its exact durable exposure can authorize this path.
    /// A current-fence retry is idempotent; an older fence is advanced only by
    /// the owner-bound control-store boundary. A foreign owner receives no
    /// replay capability even though it may still observe the public claim.
    pub fn resume_final_claim_broadcast_after_same_owner_recovery_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        request: SameOwnerFinalClaimRecoveryRequestV2,
        trusted_chain_id: &TrustedChainIdV1,
        authorization: &ConsumedClaimSigningAuthorizationV2,
    ) -> DomActuatorResult<(
        PreparedOperationalFinalClaimSubmissionV2,
        LatchedFinalClaimSubmissionV2,
    )> {
        let SameOwnerFinalClaimRecoveryRequestV2 {
            scope,
            previous_authorization_digest,
            now_unix_ms,
        } = request;
        if scope.binding() != self.binding || scope.action() != DomActionV1::BroadcastClaim {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let evidence_digest =
            self.revalidate_claim_authority_v2(trusted_chain_id, authorization)?;
        let prepared = self
            .session_store
            .resume_operational_final_claim_broadcast_v2(
                *trusted_chain_id,
                self.binding.session_id(),
            )
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let facts = self.final_claim_attempt_facts_v2(authorization, &prepared)?;
        let capability =
            match control.authorize_action(lease, scope, evidence_digest, None, now_unix_ms) {
                Ok((capability, DomOperationDispositionV1::AlreadyCompleted)) => capability,
                Ok(_) => return Err(DomActuatorError::InvalidStage),
                Err(DomActuatorError::ReconciliationRequired) => control
                    .reauthorize_same_owner_final_claim_replay_v2(
                        lease,
                        scope,
                        previous_authorization_digest,
                        &facts,
                        now_unix_ms,
                    )?,
                Err(error) => return Err(error),
            };
        let latched =
            control.latch_final_claim_attempt_v2(lease, &capability, &facts, now_unix_ms)?;
        Ok((prepared, latched))
    }

    /// Submit the exact exposed final claim to the frozen DOM node.
    ///
    /// This method deliberately borrows neither the control store nor the
    /// participant lease, so no owner-only SQLite transaction can be open while
    /// the RPC is in flight. That half is a type obligation: the borrows do not
    /// exist, so the transaction cannot.
    ///
    /// No Contracts `operation_lock` is held either — but **that half does not
    /// follow from the signature**, and this comment used to claim it did.
    /// `&self` carries `session_store: &'store ContractsSessionStoreV1`, so a
    /// call into the Store would typecheck here perfectly well. It holds
    /// because the body never makes one: `require_dom_adapter_binding` reads
    /// only the binding, and `PreparedOperationalFinalClaimSubmissionV2` owns
    /// its bytes outright, so `submit_with` hands them to the adapter without
    /// touching Store state. It is verifiable discipline over the fourteen
    /// lines below, not an obligation the compiler carries — which is exactly
    /// why a Store call added here would break the property in silence.
    ///
    /// The handle dispatches through its own concrete Contracts call; a generic
    /// broadcaster is impossible by construction, because an adversarial
    /// implementation would be able to copy the claim and publish the adaptor
    /// secret early.
    pub fn dispatch_final_claim_broadcast_v2(
        &self,
        runtime: &RealDomRpcRuntimeV1,
        prepared: &PreparedOperationalFinalClaimSubmissionV2,
        latched: &LatchedFinalClaimSubmissionV2,
    ) -> DomActuatorResult<SubmissionReceiptV1> {
        self.require_dom_runtime_binding(runtime)?;
        if prepared.session_id() != self.binding.session_id()
            || prepared.chain_id() != self.binding.chain_id()
            || latched.session_id() != self.binding.session_id()
            || latched.tx_hash() != prepared.tx_hash()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let receipt = runtime
            .submit_persisted_final_claim_v2(prepared)
            .map_err(|_| DomActuatorError::RpcAuthorityUnavailable)?;
        if receipt.tx_hash() != prepared.tx_hash() || !receipt.is_economically_admitted() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(receipt)
    }

    /// Commit both durable V2 admissions, Contracts first and mirror second.
    ///
    /// The linear submission handle and the non-forgeable node receipt are moved
    /// into the DOM Contracts store, which is the only mintable source of the
    /// `FinalClaim` transport authority. Only after that record is durable does
    /// this control plane write its owner-only mirror. A crash between the two
    /// leaves the Contracts record authoritative and the mirror is completed by
    /// a byte-identical resubmission; the mirror is never fabricated.
    pub fn commit_final_claim_admission_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        prepared: PreparedOperationalFinalClaimSubmissionV2,
        receipt: SubmissionReceiptV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalClaimAdmissionBundleV2> {
        if prepared.session_id() != self.binding.session_id()
            || prepared.chain_id() != self.binding.chain_id()
            || receipt.tx_hash() != prepared.tx_hash()
            || !receipt.is_economically_admitted()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let transport_authority = self
            .session_store
            .complete_operational_final_claim_admission_v2(prepared, receipt)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let facts = self.final_claim_transport_authority_facts_v2(&transport_authority)?;
        let admission = control.persist_final_claim_admission_receipt_v2(
            lease,
            self.binding,
            &facts,
            receipt,
            now_unix_ms,
        )?;
        Ok(DomFinalClaimAdmissionBundleV2 {
            transport_authority,
            admission,
        })
    }

    /// Reissue both durable V2 admissions after restart, without any RPC.
    pub fn resume_final_claim_admission_bundle_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalClaimAdmissionBundleV2> {
        self.require_trusted_chain_binding(trusted_chain_id)?;
        let transport_authority = self
            .session_store
            .resume_operational_final_claim_transport_authority_v2(
                *trusted_chain_id,
                self.binding.session_id(),
            )
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let facts = self.final_claim_transport_authority_facts_v2(&transport_authority)?;
        let admission =
            control.resume_final_claim_admission_v2(lease, self.binding, now_unix_ms)?;
        if admission.session_id() != facts.session_id
            || admission.dom_claim_sender_id() != facts.dom_claim_sender_id
            || admission.final_claim_receiver_id() != facts.final_claim_receiver_id
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(DomFinalClaimAdmissionBundleV2 {
            transport_authority,
            admission,
        })
    }

    /// Reauthenticate the local V2 `FinalClaim` custody mirror.
    pub fn audit_final_claim_custody_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalClaimCustodyAuditV2> {
        control.audit_final_claim_custody_v2(lease, self.binding, now_unix_ms)
    }

    /// Join the local and Contracts V2 dispositions conservatively.
    ///
    /// **Sender face.** It reads the exposure/admission lane and the owner-only
    /// mirror, both of which exist only for the participant that broadcasts the
    /// `FinalClaim`. A receiver session has neither, and asking this call about
    /// one answers about the wrong plane; use
    /// [`Self::classify_final_claim_receiver_custody_v2`] instead.
    ///
    /// The DOM Contracts store is the exposure authority: this control plane can
    /// only ever lag behind it, never lead it. The joined value is therefore the
    /// stronger of the two, and a strictly stronger *local* disposition is local
    /// corruption and fails closed instead of being reported.
    pub fn classify_final_claim_custody_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomClaimCustodyClassificationV1> {
        self.require_trusted_chain_binding(trusted_chain_id)?;
        let local = match control.audit_final_claim_custody_v2(lease, self.binding, now_unix_ms) {
            Ok(audit) => audit.classification(),
            Err(DomActuatorError::ReconciliationRequired) => {
                DomClaimCustodyClassificationV1::Unattempted
            }
            Err(error) => return Err(error),
        };
        let contracts = self.contracts_final_claim_disposition_v2(trusted_chain_id)?;
        let joined = local.join_conservative(contracts);
        if joined != contracts {
            return Err(DomActuatorError::UnsupportedFormat);
        }
        Self::require_exclusive_final_claim_role_v2(
            joined,
            self.contracts_final_claim_observation_disposition_v2(trusted_chain_id),
        )?;
        Ok(joined)
    }

    /// Proves whether the exact local FinalClaim `0x12` transport has crossed
    /// the Store commit boundary already.
    ///
    /// This is a crash-recovery disposition, not a new transport authority.
    /// A committed handle is reauthenticated against the admitted FinalClaim;
    /// an absent live outbound counts as started only when the exact durable
    /// Relay-reconciliation marker is present. A merely prepared signing
    /// request remains not started and continues through the linear admission
    /// bundle path.
    pub fn final_claim_transport_started_v2(
        &self,
        trusted_chain_id: &TrustedChainIdV1,
    ) -> DomActuatorResult<bool> {
        self.require_trusted_chain_binding(trusted_chain_id)?;
        match self
            .session_store
            .resume_outbound_dsc1(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?
        {
            OutboundDsc1RecoveryV1::SigningRequest(_) => Ok(false),
            OutboundDsc1RecoveryV1::Committed(outbound) => {
                self.session_store
                    .revalidate_committed_operational_final_claim_transport_v2(
                        *trusted_chain_id,
                        &outbound,
                    )
                    .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
                Ok(true)
            }
            OutboundDsc1RecoveryV1::None => match self
                .session_store
                .resume_reconciled_operational_final_claim_transport_v2(
                    *trusted_chain_id,
                    self.binding.session_id(),
                ) {
                Ok(_) => Ok(true),
                Err(SessionStoreError::SessionNotFound) => Ok(false),
                Err(_) => Err(DomActuatorError::ContractsAuthorityUnavailable),
            },
        }
    }

    /// Observe and durably checkpoint finality of the exact exposed V2 claim.
    ///
    /// **Sender face.** The expected transaction identity comes from
    /// `retained_final_claim_identity_v2`, which exists only once this
    /// participant latched its own exposure attempt. A receiver has no such
    /// identity and reaches this call only by mistake.
    pub fn observe_final_claim_finality_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        runtime: &RealDomRpcRuntimeV1,
        verifier: &RealDomClaimVerifierV1,
        evidence: &EvidenceRefV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        self.require_dom_runtime_binding(runtime)?;
        let claim = control.retained_final_claim_identity_v2(lease, self.binding, now_unix_ms)?;
        let finality = runtime
            .verified_claim_finality(
                verifier,
                evidence,
                claim.tx_hash,
                claim.template_hash,
                claim.shared_output_commitment,
                self.binding.min_confirmations(),
                self.binding.max_reorg_depth(),
            )
            .map_err(map_finality_error)?;
        self.persist_claim_finality(control, lease, finality, now_unix_ms)
    }

    /// Observe the exact exposed V2 claim and return its committed public facts.
    ///
    /// Unlike the compatibility disposition API, this receipt carries the
    /// canonical block locator required to bind one settlement-port result and
    /// to reauthenticate that result after restart.
    pub fn observe_final_claim_settlement_finality_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        runtime: &RealDomRpcRuntimeV1,
        verifier: &RealDomClaimVerifierV1,
        evidence: &EvidenceRefV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalityObservationV1> {
        self.require_dom_runtime_binding(runtime)?;
        let claim = control.retained_final_claim_identity_v2(lease, self.binding, now_unix_ms)?;
        let finality = runtime
            .verified_claim_finality(
                verifier,
                evidence,
                claim.tx_hash,
                claim.template_hash,
                claim.shared_output_commitment,
                self.binding.min_confirmations(),
                self.binding.max_reorg_depth(),
            )
            .map_err(map_finality_error)?;
        let observation = finality_observation(
            finality.tx_hash(),
            finality.block_height(),
            finality.block_hash(),
            finality.evidence_digest(),
        );
        self.persist_claim_finality(control, lease, finality, now_unix_ms)?;
        Ok(observation)
    }

    /// Revalidate the exposed V2 claim checkpoint and record a bounded fork.
    ///
    /// **Sender face**, for the same reason as
    /// [`Self::observe_final_claim_finality_v2`]: it reconciles against the
    /// owner-only custody mirror that only the broadcasting participant writes.
    ///
    /// A reorg never clears the Contracts exposure marker and never creates an
    /// admission; a merely exposed claim reconciles exactly like an admitted one.
    pub fn reconcile_final_claim_reorg_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        runtime: &RealDomRpcRuntimeV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        self.require_dom_runtime_binding(runtime)?;
        let custody = control.audit_final_claim_custody_v2(lease, self.binding, now_unix_ms)?;
        if custody.classification().is_unattempted() {
            return Err(DomActuatorError::InvalidStage);
        }
        let retained = control.retained_terminal_checkpoint(
            lease,
            self.binding,
            DomTerminalKindV1::Claim,
            now_unix_ms,
        )?;
        if retained.kind != DomTerminalKindV1::Claim
            || retained.tx_hash != custody.tx_hash()
            || retained.minimum_confirmations != self.binding.min_confirmations()
            || retained.max_reorg_depth != self.binding.max_reorg_depth()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let reorg = runtime
            .verified_claim_reorg(
                &retained.checkpoint_bytes,
                retained.tx_hash,
                retained.minimum_confirmations,
                retained.max_reorg_depth,
            )
            .map_err(map_reorg_error)?;
        if reorg.prior_evidence_digest() != retained.evidence_digest {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        self.persist_claim_reorg(control, lease, reorg, now_unix_ms)
    }

    /// Revalidate the exact V2 claim checkpoint and return a durable typed receipt.
    pub fn revalidate_final_claim_settlement_finality_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        runtime: &RealDomRpcRuntimeV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalityRevalidationV1> {
        self.require_dom_runtime_binding(runtime)?;
        let custody = control.audit_final_claim_custody_v2(lease, self.binding, now_unix_ms)?;
        if custody.classification().is_unattempted() {
            return Err(DomActuatorError::InvalidStage);
        }
        let retained = control.retained_terminal_checkpoint(
            lease,
            self.binding,
            DomTerminalKindV1::Claim,
            now_unix_ms,
        )?;
        if retained.kind != DomTerminalKindV1::Claim
            || retained.tx_hash != custody.tx_hash()
            || retained.minimum_confirmations != self.binding.min_confirmations()
            || retained.max_reorg_depth != self.binding.max_reorg_depth()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let reorg = match runtime.verified_claim_reorg(
            &retained.checkpoint_bytes,
            retained.tx_hash,
            retained.minimum_confirmations,
            retained.max_reorg_depth,
        ) {
            Err(RealDomError::TransactionStillCanonical) => {
                return Ok(DomFinalityRevalidationV1::StillFinal(
                    terminal_finality_observation(&retained),
                ));
            }
            Ok(reorg) => reorg,
            Err(error) => return Err(map_reorg_error(error)),
        };
        if reorg.prior_evidence_digest() != retained.evidence_digest
            || reorg.prior_block_height() != retained.block_height
            || reorg.prior_block_hash() != retained.block_hash
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let invalidated = DomFinalityRevalidationV1::Invalidated {
            transaction_id: retained.tx_hash,
            prior_evidence_digest: retained.evidence_digest,
            prior_block_height: retained.block_height,
            prior_block_hash: retained.block_hash,
            reorg_evidence_digest: reorg.evidence_digest(),
        };
        self.persist_claim_reorg(control, lease, reorg, now_unix_ms)?;
        Ok(invalidated)
    }

    /// Recover an already-committed V2 claim invalidation after a crash.
    pub fn recover_final_claim_settlement_invalidation_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<Option<DomFinalityRevalidationV1>> {
        self.require_trusted_chain_binding(trusted_chain_id)?;
        let claim = control.retained_final_claim_identity_v2(lease, self.binding, now_unix_ms)?;
        let invalidation = control.retained_terminal_invalidation(
            lease,
            self.binding,
            DomTerminalKindV1::Claim,
            now_unix_ms,
        )?;
        recover_terminal_invalidation(invalidation, DomTerminalKindV1::Claim, claim.tx_hash)
    }

    fn latch_exposed_final_claim_attempt_v2(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        authorization: &ConsumedClaimSigningAuthorizationV2,
        prepared: &PreparedOperationalFinalClaimSubmissionV2,
        now_unix_ms: u64,
    ) -> DomActuatorResult<LatchedFinalClaimSubmissionV2> {
        let facts = self.final_claim_attempt_facts_v2(authorization, prepared)?;
        control.latch_final_claim_attempt_v2(lease, capability, &facts, now_unix_ms)
    }

    fn final_claim_attempt_facts_v2(
        &self,
        authorization: &ConsumedClaimSigningAuthorizationV2,
        prepared: &PreparedOperationalFinalClaimSubmissionV2,
    ) -> DomActuatorResult<FinalClaimAttemptFactsV2> {
        if prepared.session_id() != self.binding.session_id()
            || prepared.chain_id() != self.binding.chain_id()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(FinalClaimAttemptFactsV2 {
            authority_evidence_digest: final_claim_authority_evidence_digest_v2(authorization),
            dom_claim_sender_id: *authorization.dom_claim_sender_id(),
            final_claim_receiver_id: *authorization.final_claim_receiver_id(),
            tx_hash: prepared.tx_hash(),
            template_hash: *authorization.claim_template_hash(),
            shared_output_commitment: *authorization.dom_shared_output_commitment(),
            exposure_record_digest: prepared.exposure_record_digest(),
        })
    }

    fn final_claim_transport_authority_facts_v2(
        &self,
        authority: &PreparedOperationalFinalClaimTransportAuthorityV2,
    ) -> DomActuatorResult<FinalClaimTransportAuthorityFactsV2> {
        let facts = FinalClaimTransportAuthorityFactsV2 {
            session_id: *authority.session_id(),
            dom_claim_sender_id: *authority.dom_claim_sender_id(),
            final_claim_receiver_id: *authority.final_claim_receiver_id(),
        };
        if facts.session_id != self.binding.session_id()
            || facts.dom_claim_sender_id != self.binding.participant().participant_id()
            || facts.final_claim_receiver_id == facts.dom_claim_sender_id
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(facts)
    }

    /// Probe the DOM Contracts sender disposition without collapsing failures.
    ///
    /// **Sender face.** It asks the exposure/admission lane, which a receiver
    /// session does not have; the receiver counterpart is
    /// [`Self::contracts_final_claim_observation_disposition_v2`].
    ///
    /// Only a genuinely absent record — `SessionNotFound` — may be read as
    /// "no exposure". Every other Contracts failure (busy store, quarantine,
    /// filesystem, canonical) is reported as an unavailable authority: an
    /// unreachable Contracts store must never be indistinguishable from a
    /// Contracts store that proves the claim was never exposed.
    ///
    /// The reissued handles are dropped immediately. They are reemitted from
    /// the durable records, grant no new authority and are never submitted.
    fn contracts_final_claim_disposition_v2(
        &self,
        trusted_chain_id: &TrustedChainIdV1,
    ) -> DomActuatorResult<DomClaimCustodyClassificationV1> {
        match self
            .session_store
            .resume_operational_final_claim_transport_authority_v2(
                *trusted_chain_id,
                self.binding.session_id(),
            ) {
            Ok(_admitted) => return Ok(DomClaimCustodyClassificationV1::Admitted),
            Err(SessionStoreError::SessionNotFound) => {}
            Err(SessionStoreError::InvalidTransition) => {
                if self.final_claim_transport_started_v2(trusted_chain_id)? {
                    return Ok(DomClaimCustodyClassificationV1::Admitted);
                }
                return Err(DomActuatorError::ContractsAuthorityUnavailable);
            }
            Err(_) => return Err(DomActuatorError::ContractsAuthorityUnavailable),
        }
        match self
            .session_store
            .resume_operational_final_claim_broadcast_v2(
                *trusted_chain_id,
                self.binding.session_id(),
            ) {
            Ok(_exposed) => Ok(DomClaimCustodyClassificationV1::PotentiallyExposed),
            Err(SessionStoreError::SessionNotFound) => {
                Ok(DomClaimCustodyClassificationV1::Unattempted)
            }
            Err(_) => Err(DomActuatorError::ContractsAuthorityUnavailable),
        }
    }

    /// Probe the DOM Contracts receiver disposition without erasing the
    /// Store's own error table.
    ///
    /// The Store answers four distinct conditions on this face and each one
    /// means something different. `SessionNotFound` is the only absence: no
    /// durable observation marker exists for this session. `InvalidTransition`
    /// is the frozen `FinalClaim` sender asking for a receiver token, which the
    /// Store refuses as a role error and not as a missing record.
    /// `Quarantined` is either a foreign role or a durable disagreement between
    /// the retained records, which no retry repairs. Collapsing all three into
    /// `ContractsAuthorityUnavailable` would report a role error and durable
    /// corruption as a transient outage — the same class of false negative that
    /// P1-C4 closed on the sender face — so each reaches the caller as itself.
    ///
    /// The reissued token is dropped immediately: it is reemitted from the
    /// durable record, grants no new authority and never reaches an extraction.
    fn contracts_final_claim_observation_disposition_v2(
        &self,
        trusted_chain_id: &TrustedChainIdV1,
    ) -> DomActuatorResult<DomClaimCustodyClassificationV1> {
        match self
            .session_store
            .resume_observed_final_claim_exposure_v2(*trusted_chain_id, self.binding.session_id())
        {
            Ok(_observed) => Ok(DomClaimCustodyClassificationV1::PotentiallyExposed),
            Err(error) => map_final_claim_observation_error_v2(error),
        }
    }

    /// Cross-check that the sender and receiver planes do not both claim this
    /// session's `FinalClaim`.
    ///
    /// **The primary barrier is not here.** A session is the sender or the
    /// receiver of its own `FinalClaim`, never both, and that rule is imposed
    /// inside the DOM Contracts store: minting a receiver marker on a session
    /// that already holds an exposure record is refused there, and the sender
    /// lane is refused on a session that already holds an observation marker.
    /// The Store is the only place the two records live under one durable
    /// authority, so it is the only place they can be compared atomically.
    ///
    /// This control plane reads the two planes through two separate calls, so
    /// what it can prove is strictly weaker, and this guard claims only that:
    /// the two answers it received disagree. It is a cross-plane detector, not
    /// the exclusivity invariant.
    ///
    /// **An unreadable other plane is not an error here, and the reason is not
    /// that somebody else already reported it.** Both call sites build that
    /// `Result` inside this call's own argument list and drop it here, so there
    /// is no other caller who ever saw it. The real reason is narrower: this
    /// guard can only ever produce a refusal, never an authorization, so
    /// declining to refuse on an answer it could not read leaves the Store's
    /// decision standing instead of overriding it with a verdict this plane is
    /// not entitled to reach.
    ///
    /// **What this guard consequently does not see.** Flattening those failures
    /// into `Ok(())` is silent, and under the Store's current error tables it is
    /// silent on every real session, because each face's *healthy* state is
    /// exactly what makes the other plane's probe fail:
    ///
    /// * a session holding an exposure record makes
    ///   `resume_observed_final_claim_exposure_v2` answer `Quarantined`, so the
    ///   sender face's cross-check always arrives as `Err`;
    /// * a session holding an observation marker makes the sender lane answer
    ///   `Quarantined` before it reads anything else, so the receiver face's
    ///   cross-check always arrives as `Err`;
    /// * a corrupt `DOMFCAD2` produces the same blindness from a third
    ///   direction: the sender plane fails on the admission lane it queries
    ///   first, while the receiver probe, which never touches admission,
    ///   answers `Unattempted` quite happily.
    ///
    /// The first two reach `Ok(())` through the `Err` arm below. The third
    /// reaches it through the `is_unattempted` arm instead — worth stating
    /// precisely, because the two doors are not the same door even though both
    /// are silent. The third is also the one that matters: a real disagreement
    /// between the planes goes undetected, and it goes undetected exactly when
    /// there is durable corruption, which is when a detector would be worth
    /// having.
    ///
    /// Stated plainly so nobody has to rediscover it: **the refusal branch below
    /// is not reachable through either public façade today.** It is a compiled
    /// tripwire against a future in which a probe stops failing on the other
    /// role's healthy state, not a check that is currently doing work. No
    /// invariant rests on it — the Store's barrier is atomic, under a single
    /// lock, and enforced in both directions — and that is the only reason
    /// leaving it inert is acceptable rather than a defect.
    fn require_exclusive_final_claim_role_v2(
        this_plane: DomClaimCustodyClassificationV1,
        other_plane: DomActuatorResult<DomClaimCustodyClassificationV1>,
    ) -> DomActuatorResult<()> {
        let Ok(other) = other_plane else {
            return Ok(());
        };
        if this_plane.is_unattempted() || other.is_unattempted() {
            return Ok(());
        }
        Err(DomActuatorError::UnsupportedFormat)
    }

    /// Classify this session's receiver-side V2 `FinalClaim` custody.
    ///
    /// This is the receiver counterpart of [`Self::classify_final_claim_custody_v2`]
    /// and it deliberately consults no owner-only mirror: the receiver mints no
    /// submission, latches no attempt and writes no admission, so the DOM
    /// Contracts observation marker is the whole of its durable state and there
    /// is nothing local for a conservative join to strengthen.
    ///
    /// `Admitted` is refused rather than returned. A receiver never admits
    /// economically, so that value on this face could only come from the sender
    /// lane having answered for a receiver session. The probe does not produce
    /// it today; the guard is what keeps a later widening of the probe from
    /// silently making a receiver look economically admitted.
    pub fn classify_final_claim_receiver_custody_v2(
        &self,
        trusted_chain_id: &TrustedChainIdV1,
    ) -> DomActuatorResult<DomClaimCustodyClassificationV1> {
        self.require_trusted_chain_binding(trusted_chain_id)?;
        let receiver = self.contracts_final_claim_observation_disposition_v2(trusted_chain_id)?;
        if receiver.is_admitted() {
            return Err(DomActuatorError::UnsupportedFormat);
        }
        Self::require_exclusive_final_claim_role_v2(
            receiver,
            self.contracts_final_claim_disposition_v2(trusted_chain_id),
        )?;
        Ok(receiver)
    }

    /// Extract the counterparty's now-public adaptor scalar, receiver side.
    ///
    /// The durable observation marker is not an argument this call could be
    /// talked out of. [`ObservedFinalClaimExposureV2`] has no public
    /// constructor, no codec and no `Clone`, so reaching this boundary at all
    /// requires that the DOM Contracts store already minted the marker — the
    /// irreversible exposure bit is on disk before the RPC that reveals `t` is
    /// even reachable. Extraction without a durable marker is therefore
    /// inexpressible here rather than refused at runtime.
    ///
    /// The marker itself now carries the Store-authenticated chain, session and
    /// transaction. This façade refuses a foreign marker, then derives a
    /// resolve-mode `EvidenceRefV1` from those facts alone. No caller-shaped
    /// chain, location, anchor or transaction can be transplanted after restart.
    ///
    /// # Why the `consumer` is not crossed against the binding
    ///
    /// It looks like an omission and it is not, so the reason is recorded here
    /// rather than left to be rediscovered. [`RealDomClaimConsumerV1`]
    /// (`adapters/dom-real/src/lib.rs:1325-1328`) holds two `Arc`s — the
    /// runtime and the verifier — and **carries no `session_id`**, so there is
    /// no nominal fact about a session for this call to compare against. The
    /// binding is structural instead, and it is not the marker `chain_id` check:
    /// that one does not discriminate sessions at all, because two sessions on
    /// the same DOM leg share the chain.
    ///
    /// The refusal happens one layer down, in `verify_and_extract`
    /// (`dom-real/src/lib.rs:1021-1025`), which requires the transaction to
    /// spend `contract.shared_output_commitment` and to hash to
    /// `contract.claim_template_hash` — both frozen in `RealDomContractV1`
    /// (`:297-310`) and proved non-zero in `:315-322`. A consumer built for
    /// another session carries another session's shared output, and that
    /// session's claim does not spend this one's, so the call fails with
    /// `InvalidEvidence` **before any adaptor arithmetic runs and before a
    /// single byte of `t` exists**. Behind that, `extract_revealed_secret`
    /// (`dom-leg/src/round.rs:1072-1098`) still re-runs the pre-signature, the
    /// final signature and `t·G == T` against its own frozen session before
    /// returning anything.
    ///
    /// The exact condition under which that is sufficient: the refusal is by
    /// shared-output and template identity, not by session name. Two distinct
    /// sessions have distinct funding outputs — sharing one would be a double
    /// spend of the same output, and at most one of the two claims can be
    /// canonical. If two sessions ever did share both `shared_output_commitment`
    /// and `claim_template_hash`, they would not be two sessions from the
    /// contract's point of view; they would be one contract, and substituting
    /// one consumer for the other would be a no-op.
    ///
    /// A `session_id` on the consumer was considered and deliberately not
    /// added: it would be a fourth cross-check restating what the shared output
    /// already settles, and a check that merely echoes another one is a check
    /// nobody maintains.
    pub fn extract_observed_claim_secret_v2(
        &self,
        consumer: &RealDomClaimConsumerV1,
        observed: &ObservedFinalClaimExposureV2,
    ) -> DomActuatorResult<RevealedSecretBytes> {
        if observed.session_id() != &self.binding.session_id()
            || observed.chain_id() != &self.binding.chain_id()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let evidence = EvidenceRefV1 {
            chain_id: kaystra_core::types::ChainId(*observed.chain_id()),
            tx_id: *observed.tx_hash(),
            event_index: 0,
            block_height: 0,
            block_anchor: [0; 32],
        };
        consumer.consume(&evidence).map_err(map_finality_error)
    }

    /// Persists the receiver-side observation marker before secret extraction.
    ///
    /// The verified observation is a linear capability minted by the real DOM
    /// scanner.  This façade keeps the underlying Contracts Store private while
    /// preserving its CAS boundary: callers must bind the scan to the session
    /// revision read immediately before it.  A concurrent transition consumes
    /// no fallback authority; the caller must re-observe the public claim.
    pub fn persist_observed_final_claim_exposure_v2(
        &self,
        expected_session_revision: u64,
        observation: dom_adaptor::VerifiedDomClaimObservationV1,
    ) -> DomActuatorResult<ObservedFinalClaimExposureV2> {
        self.session_store
            .revalidate_final_claim_chain_observation_v2(expected_session_revision, observation)
            .map_err(map_observed_final_claim_transition_error_v2)
    }

    /// Rehydrates the receiver-side observation token after a process crash.
    ///
    /// This returns only the Store-minted, non-cloneable token. It never
    /// refetches the chain and never materializes the adaptor scalar; the later
    /// extraction still revalidates the exact transaction through the real DOM
    /// consumer.
    pub fn resume_observed_final_claim_exposure_v2(
        &self,
        trusted_chain_id: &TrustedChainIdV1,
    ) -> DomActuatorResult<ObservedFinalClaimExposureV2> {
        self.require_trusted_chain_binding(trusted_chain_id)?;
        self.session_store
            .resume_observed_final_claim_exposure_v2(*trusted_chain_id, self.binding.session_id())
            .map_err(map_observed_final_claim_transition_error_v2)
    }

    /// Build this session's claim verifier from the Store's retained facts.
    ///
    /// This is the missing producer. `observe_claim_finality`,
    /// [`Self::observe_final_claim_finality_v2`] and their refund sibling all
    /// take `&RealDomClaimVerifierV1` and none of them could ever be called,
    /// because nothing in the workspace built one outside `adapter-dom-real`'s
    /// own tests. The verifier's argument types used to live in `dom-leg`,
    /// which this crate has no edge to and cannot name; they no longer do, so
    /// the construction belongs here, next to the binding it must answer to.
    ///
    /// # Provenance, which is the only thing this call really adds
    ///
    /// `RealDomClaimVerifierV1::from_retained_facts_v2` checks the facts
    /// against *each other* — session identity through the transcript tie-back,
    /// the template hash recomputed from the retained canonical bytes, and the
    /// pre-signature crossed against the reassembled session. It documents
    /// plainly that not one of those checks asks where the facts came from, and
    /// names its caller as the party that answers for that. This is that
    /// caller, and the answer is structural rather than promised: every fact
    /// below is read from `self.session_store`, the one physical Contracts
    /// opening this actuator is bound to, addressed by `self.binding`'s own
    /// session. No fact reaches the constructor from an argument, so there is
    /// no expression a caller can write that substitutes a peer's facts for
    /// this session's.
    ///
    /// That matters concretely: a verifier assembled from facts a peer supplied
    /// would prove that *some* claim opens *some* adaptor point, every gate
    /// would return `Ok`, and nothing downstream would notice, because every
    /// later check is against that same substituted session.
    ///
    /// # What is deliberately not rechecked
    ///
    /// The contract facts' own consistency, the retained `refund_tx_hash` and
    /// the early-share context commitment. The Store's codecs refuse to decode
    /// a record without them, so repeating them here would be a second copy of
    /// a rule with one owner, and second copies are what drift.
    ///
    /// The pre-signature transport authority is taken only for its retained
    /// `0x0f` payload and dropped immediately. It is reissued from the durable
    /// `DOMSPPS2` artifact, writes nothing, grants no new authority and never
    /// reaches a transport boundary — the same discipline as the reissued
    /// handles in [`Self::contracts_final_claim_disposition_v2`]. It is used
    /// because it is the only V2 read path to those exact bytes: the retained
    /// pre-signature is not among `RetainedClaimRoundFactsV2`'s twenty fields,
    /// and the reconstruct path mints rather than reads.
    ///
    /// # What this establishes, and what it does not
    ///
    /// It establishes that this Store retained a complete, mutually consistent
    /// Claim adaptor round for this session and that the verifier is bound to
    /// it. It establishes **nothing about the chain** — not that the funding
    /// was broadcast or confirmed, not that the claim was ever seen. That
    /// question belongs to the runtime the verifier is later handed to.
    pub fn build_retained_claim_verifier_v2(
        &self,
        trusted_chain_id: &TrustedChainIdV1,
        authorization: &ConsumedClaimSigningAuthorizationV2,
    ) -> DomActuatorResult<RealDomClaimVerifierV1> {
        // Crosses the chain against the binding and the live authorization
        // against session, terms, roles and confirmation policy before any
        // fact is read. Its evidence digest is not wanted here; the refusal is.
        let _evidence_digest =
            self.revalidate_claim_authority_v2(trusted_chain_id, authorization)?;
        let session_id = self.binding.session_id();
        let contract = self
            .session_store
            .real_dom_contract_facts_v2(*trusted_chain_id, session_id)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let round = self
            .session_store
            .retained_claim_round_facts_v2(*trusted_chain_id, session_id)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let pre_signature = self
            .session_store
            .prepare_post_anchor_dom_claim_pre_signature_transport_authority_v2(
                authorization,
                *trusted_chain_id,
            )
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        // The round and the pre-signature reach the constructor from two
        // different Store call paths — one addressed by session, one derived
        // from the authorization — and are deliberately not crossed here.
        // `from_retained_facts_v2` puts the pre-signature through
        // `pre_signature_from_wire` against the session it reassembled from the
        // round, which crosses template, reveal transcript and adaptor point at
        // once. That check has one owner and it is not this function.
        RealDomClaimVerifierV1::from_retained_facts_v2(
            &round,
            &contract,
            trusted_chain_id,
            pre_signature.pre_signature_payload(),
        )
        .map_err(map_retained_verifier_error_v2)
    }

    fn revalidate_claim_authority_v2(
        &self,
        trusted_chain_id: &TrustedChainIdV1,
        authorization: &ConsumedClaimSigningAuthorizationV2,
    ) -> DomActuatorResult<[u8; 32]> {
        self.require_trusted_chain_binding(trusted_chain_id)?;
        self.session_store
            .revalidate_consumed_post_anchor_dom_claim_signing_v2(authorization)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let local = self.binding.participant().participant_id();
        if authorization.session_id() != &self.binding.session_id()
            || authorization.terms_hash() != &self.binding.terms_digest()
            || authorization.chain_id() != &self.binding.chain_id()
            || authorization.dom_claim_sender_id() != &local
            || authorization.final_claim_receiver_id() == &local
            || authorization.dom_minimum_confirmations() != self.binding.min_confirmations()
            || authorization.dom_confirmation_depth() < self.binding.min_confirmations()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(final_claim_authority_evidence_digest_v2(authorization))
    }

    fn require_trusted_chain_binding(
        &self,
        trusted_chain_id: &TrustedChainIdV1,
    ) -> DomActuatorResult<()> {
        if trusted_chain_id.as_bytes() != &self.binding.chain_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(())
    }

    /// Observe and durably checkpoint finality of the exact retained claim.
    ///
    /// The expected tx/template/shared output come only from owner-only claim
    /// custody. The registry-authenticated confirmation and reorg policy is
    /// passed unchanged to the real scanner and crossed again before commit.
    pub fn observe_claim_finality(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        runtime: &RealDomRpcRuntimeV1,
        verifier: &RealDomClaimVerifierV1,
        evidence: &EvidenceRefV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        self.require_dom_runtime_binding(runtime)?;
        let claim = control.retained_claim_identity(lease, self.binding, now_unix_ms)?;
        let finality = runtime
            .verified_claim_finality(
                verifier,
                evidence,
                claim.tx_hash,
                claim.template_hash,
                claim.shared_output_commitment,
                self.binding.min_confirmations(),
                self.binding.max_reorg_depth(),
            )
            .map_err(map_finality_error)?;
        self.persist_claim_finality(control, lease, finality, now_unix_ms)
    }

    /// Observe and durably checkpoint finality of the exact retained refund.
    pub fn observe_refund_finality(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        runtime: &RealDomRpcRuntimeV1,
        evidence: &EvidenceRefV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        self.require_dom_runtime_binding(runtime)?;
        let finality = runtime
            .verified_contracts_refund_finality(
                self.session_store,
                self.binding.session_id(),
                evidence,
                self.binding.min_confirmations(),
                self.binding.max_reorg_depth(),
            )
            .map_err(map_finality_error)?;
        self.persist_refund_finality(control, lease, finality, now_unix_ms)
    }

    /// Observe the exact retained refund and return its committed public facts.
    pub fn observe_refund_settlement_finality(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        runtime: &RealDomRpcRuntimeV1,
        evidence: &EvidenceRefV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalityObservationV1> {
        self.require_dom_runtime_binding(runtime)?;
        let finality = runtime
            .verified_contracts_refund_finality(
                self.session_store,
                self.binding.session_id(),
                evidence,
                self.binding.min_confirmations(),
                self.binding.max_reorg_depth(),
            )
            .map_err(map_finality_error)?;
        let observation = finality_observation(
            finality.tx_hash(),
            finality.block_height(),
            finality.block_hash(),
            finality.evidence_digest(),
        );
        self.persist_refund_finality(control, lease, finality, now_unix_ms)?;
        Ok(observation)
    }

    /// Revalidate a retained claim checkpoint and record only a bounded exact fork.
    pub fn reconcile_claim_reorg(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        runtime: &RealDomRpcRuntimeV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        self.require_dom_runtime_binding(runtime)?;
        let custody = control.audit_retained_claim_custody_v1(lease, self.binding, now_unix_ms)?;
        if custody.classification().is_unattempted() {
            return Err(DomActuatorError::InvalidStage);
        }
        let retained = control.retained_terminal_checkpoint(
            lease,
            self.binding,
            DomTerminalKindV1::Claim,
            now_unix_ms,
        )?;
        if retained.kind != DomTerminalKindV1::Claim
            || retained.tx_hash != custody.tx_hash()
            || retained.minimum_confirmations != self.binding.min_confirmations()
            || retained.max_reorg_depth != self.binding.max_reorg_depth()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let reorg = runtime
            .verified_claim_reorg(
                &retained.checkpoint_bytes,
                retained.tx_hash,
                retained.minimum_confirmations,
                retained.max_reorg_depth,
            )
            .map_err(map_reorg_error)?;
        if reorg.prior_evidence_digest() != retained.evidence_digest {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        self.persist_claim_reorg(control, lease, reorg, now_unix_ms)
    }

    /// Revalidate a retained refund checkpoint and record only a bounded exact fork.
    pub fn reconcile_refund_reorg(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        runtime: &RealDomRpcRuntimeV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        self.require_dom_runtime_binding(runtime)?;
        let retained = control.retained_terminal_checkpoint(
            lease,
            self.binding,
            DomTerminalKindV1::Refund,
            now_unix_ms,
        )?;
        if retained.kind != DomTerminalKindV1::Refund
            || retained.minimum_confirmations != self.binding.min_confirmations()
            || retained.max_reorg_depth != self.binding.max_reorg_depth()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let reorg = runtime
            .verified_refund_reorg(
                &retained.checkpoint_bytes,
                retained.tx_hash,
                retained.minimum_confirmations,
                retained.max_reorg_depth,
            )
            .map_err(map_reorg_error)?;
        if reorg.prior_evidence_digest() != retained.evidence_digest {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        self.persist_refund_reorg(control, lease, reorg, now_unix_ms)
    }

    /// Revalidate the exact refund checkpoint and return a durable typed receipt.
    pub fn revalidate_refund_settlement_finality(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        runtime: &RealDomRpcRuntimeV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalityRevalidationV1> {
        self.require_dom_runtime_binding(runtime)?;
        let retained = control.retained_terminal_checkpoint(
            lease,
            self.binding,
            DomTerminalKindV1::Refund,
            now_unix_ms,
        )?;
        if retained.kind != DomTerminalKindV1::Refund
            || retained.minimum_confirmations != self.binding.min_confirmations()
            || retained.max_reorg_depth != self.binding.max_reorg_depth()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let reorg = match runtime.verified_refund_reorg(
            &retained.checkpoint_bytes,
            retained.tx_hash,
            retained.minimum_confirmations,
            retained.max_reorg_depth,
        ) {
            Err(RealDomError::TransactionStillCanonical) => {
                return Ok(DomFinalityRevalidationV1::StillFinal(
                    terminal_finality_observation(&retained),
                ));
            }
            Ok(reorg) => reorg,
            Err(error) => return Err(map_reorg_error(error)),
        };
        if reorg.prior_evidence_digest() != retained.evidence_digest
            || reorg.prior_block_height() != retained.block_height
            || reorg.prior_block_hash() != retained.block_hash
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let invalidated = DomFinalityRevalidationV1::Invalidated {
            transaction_id: retained.tx_hash,
            prior_evidence_digest: retained.evidence_digest,
            prior_block_height: retained.block_height,
            prior_block_hash: retained.block_hash,
            reorg_evidence_digest: reorg.evidence_digest(),
        };
        self.persist_refund_reorg(control, lease, reorg, now_unix_ms)?;
        Ok(invalidated)
    }

    /// Recover an already-committed refund invalidation after a crash.
    pub fn recover_refund_settlement_invalidation(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        current_context: DomTransactionValidationContextV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<Option<DomFinalityRevalidationV1>> {
        let transaction_id = self.retained_refund_transaction_id(current_context)?;
        let invalidation = control.retained_terminal_invalidation(
            lease,
            self.binding,
            DomTerminalKindV1::Refund,
            now_unix_ms,
        )?;
        recover_terminal_invalidation(invalidation, DomTerminalKindV1::Refund, transaction_id)
    }

    fn persist_funding_finality(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        finality: VerifiedDomFundingFinalityV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalityObservationV1> {
        let observation = finality_observation(
            finality.tx_hash(),
            finality.block_height(),
            finality.block_hash(),
            finality.evidence_digest(),
        );
        let record = DomTerminalFinalityRecordV1 {
            kind: DomTerminalKindV1::Funding,
            tx_hash: finality.tx_hash(),
            block_height: finality.block_height(),
            block_hash: finality.block_hash(),
            tip_height: finality.observed_tip_height(),
            tip_hash: finality.observed_tip_hash(),
            confirmation_depth: finality.confirmation_depth(),
            minimum_confirmations: finality.minimum_confirmations(),
            max_reorg_depth: finality.max_reorg_depth(),
            evidence_digest: finality.evidence_digest(),
            checkpoint_bytes: finality.recovery_checkpoint(),
        };
        control.record_terminal_finality(lease, self.binding, record, now_unix_ms)?;
        Ok(observation)
    }

    fn persist_claim_finality(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        finality: VerifiedDomClaimFinalityV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        let record = DomTerminalFinalityRecordV1 {
            kind: DomTerminalKindV1::Claim,
            tx_hash: finality.tx_hash(),
            block_height: finality.block_height(),
            block_hash: finality.block_hash(),
            tip_height: finality.observed_tip_height(),
            tip_hash: finality.observed_tip_hash(),
            confirmation_depth: finality.confirmation_depth(),
            minimum_confirmations: finality.minimum_confirmations(),
            max_reorg_depth: finality.max_reorg_depth(),
            evidence_digest: finality.evidence_digest(),
            checkpoint_bytes: finality.recovery_checkpoint(),
        };
        control.record_terminal_finality(lease, self.binding, record, now_unix_ms)
    }

    fn persist_refund_finality(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        finality: VerifiedDomRefundFinalityV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        if finality.session_id() != self.binding.session_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let record = DomTerminalFinalityRecordV1 {
            kind: DomTerminalKindV1::Refund,
            tx_hash: finality.tx_hash(),
            block_height: finality.block_height(),
            block_hash: finality.block_hash(),
            tip_height: finality.observed_tip_height(),
            tip_hash: finality.observed_tip_hash(),
            confirmation_depth: finality.confirmation_depth(),
            minimum_confirmations: finality.minimum_confirmations(),
            max_reorg_depth: finality.max_reorg_depth(),
            evidence_digest: finality.evidence_digest(),
            checkpoint_bytes: finality.recovery_checkpoint(),
        };
        control.record_terminal_finality(lease, self.binding, record, now_unix_ms)
    }

    fn persist_claim_reorg(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        reorg: VerifiedDomClaimReorgV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        control.record_terminal_reorg(
            lease,
            self.binding,
            terminal_reorg_record(DomTerminalKindV1::Claim, &reorg),
            now_unix_ms,
        )
    }

    fn persist_funding_reorg(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        reorg: VerifiedDomFundingReorgV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        control.record_terminal_reorg(
            lease,
            self.binding,
            terminal_reorg_record(DomTerminalKindV1::Funding, &reorg),
            now_unix_ms,
        )
    }

    fn persist_refund_reorg(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        reorg: VerifiedDomRefundReorgV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        control.record_terminal_reorg(
            lease,
            self.binding,
            terminal_reorg_record(DomTerminalKindV1::Refund, &reorg),
            now_unix_ms,
        )
    }

    fn require_live_action(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        action: DomActionV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<()> {
        if capability.scope().binding() != self.binding || capability.scope().action() != action {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        control.validate_live_capability(lease, capability, now_unix_ms)
    }

    fn require_dom_adapter_binding(
        &self,
        adapter: &DomHttpChainAdapterV1,
    ) -> DomActuatorResult<()> {
        let expected = self.binding.expected_dom_identity()?;
        if adapter.expected_identity() != &expected {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(())
    }

    fn require_dom_runtime_binding(&self, runtime: &RealDomRpcRuntimeV1) -> DomActuatorResult<()> {
        let expected = self.binding.expected_dom_identity()?;
        if runtime.expected_identity() != &expected {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(())
    }
}

fn submit_after_funding_preflight<Authority, Receipt>(
    authority: Authority,
    candidate_tx_hash: [u8; 32],
    retained_tx_hash: [u8; 32],
    submit: impl FnOnce(Authority) -> DomActuatorResult<Receipt>,
) -> DomActuatorResult<Receipt> {
    if candidate_tx_hash != retained_tx_hash {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    submit(authority)
}

fn finality_observation(
    transaction_id: [u8; 32],
    block_height: u64,
    block_hash: [u8; 32],
    evidence_digest: [u8; 32],
) -> DomFinalityObservationV1 {
    DomFinalityObservationV1 {
        transaction_id,
        block_height,
        block_hash,
        evidence_digest,
    }
}

fn terminal_finality_observation(
    retained: &crate::store::RetainedDomTerminalCheckpointV1,
) -> DomFinalityObservationV1 {
    finality_observation(
        retained.tx_hash,
        retained.block_height,
        retained.block_hash,
        retained.evidence_digest,
    )
}

fn recover_terminal_invalidation(
    invalidation: Option<crate::store::RetainedDomTerminalInvalidationV1>,
    expected_kind: DomTerminalKindV1,
    expected_transaction_id: [u8; 32],
) -> DomActuatorResult<Option<DomFinalityRevalidationV1>> {
    let Some(invalidation) = invalidation else {
        return Ok(None);
    };
    if invalidation.kind != expected_kind || invalidation.tx_hash != expected_transaction_id {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    Ok(Some(DomFinalityRevalidationV1::Invalidated {
        transaction_id: invalidation.tx_hash,
        prior_evidence_digest: invalidation.prior_evidence_digest,
        prior_block_height: invalidation.block_height,
        prior_block_hash: invalidation.block_hash,
        reorg_evidence_digest: invalidation.reorg_evidence_digest,
    }))
}

trait DomTerminalReorgEvidenceV1 {
    fn tx_hash(&self) -> [u8; 32];
    fn prior_evidence_digest(&self) -> [u8; 32];
    fn current_tip_height(&self) -> u64;
    fn current_tip_hash(&self) -> [u8; 32];
    fn common_ancestor_height(&self) -> u64;
    fn removed_depth(&self) -> u32;
    fn minimum_confirmations(&self) -> u32;
    fn max_reorg_depth(&self) -> u32;
    fn evidence_digest(&self) -> [u8; 32];
}

macro_rules! impl_terminal_reorg_evidence {
    ($type:ty) => {
        impl DomTerminalReorgEvidenceV1 for $type {
            fn tx_hash(&self) -> [u8; 32] {
                self.tx_hash()
            }
            fn prior_evidence_digest(&self) -> [u8; 32] {
                self.prior_evidence_digest()
            }
            fn current_tip_height(&self) -> u64 {
                self.current_tip_height()
            }
            fn current_tip_hash(&self) -> [u8; 32] {
                self.current_tip_hash()
            }
            fn common_ancestor_height(&self) -> u64 {
                self.common_ancestor_height()
            }
            fn removed_depth(&self) -> u32 {
                self.removed_depth()
            }
            fn minimum_confirmations(&self) -> u32 {
                self.minimum_confirmations()
            }
            fn max_reorg_depth(&self) -> u32 {
                self.max_reorg_depth()
            }
            fn evidence_digest(&self) -> [u8; 32] {
                self.evidence_digest()
            }
        }
    };
}

impl_terminal_reorg_evidence!(VerifiedDomFundingReorgV1);
impl_terminal_reorg_evidence!(VerifiedDomClaimReorgV1);
impl_terminal_reorg_evidence!(VerifiedDomRefundReorgV1);

fn terminal_reorg_record(
    kind: DomTerminalKindV1,
    evidence: &impl DomTerminalReorgEvidenceV1,
) -> DomTerminalReorgRecordV1 {
    DomTerminalReorgRecordV1 {
        kind,
        tx_hash: evidence.tx_hash(),
        prior_evidence_digest: evidence.prior_evidence_digest(),
        current_tip_height: evidence.current_tip_height(),
        current_tip_hash: evidence.current_tip_hash(),
        common_ancestor_height: evidence.common_ancestor_height(),
        removed_depth: evidence.removed_depth(),
        minimum_confirmations: evidence.minimum_confirmations(),
        max_reorg_depth: evidence.max_reorg_depth(),
        evidence_digest: evidence.evidence_digest(),
    }
}

/// Translate one receiver-lane Store failure without erasing its meaning.
///
/// This is a free function so the table can be proven exhaustively and armwise
/// without a durable Store in a particular state. Three of the four meaningful
/// conditions — a role error, durable corruption, and a genuinely absent
/// record — cannot be reproduced side by side from a single fixture, and a
/// mapping that only one arm ever exercises is a mapping nobody checked.
///
/// The arms are, in order: absence, which is the only condition a caller may
/// read as "never observed"; the frozen sender asking for a receiver token,
/// which is a role error and is reported as an invalid stage; a foreign role or
/// an internally inconsistent record, which no retry repairs and is reported as
/// an unsupported format; and everything else, which is a genuinely unreachable
/// authority. `Ok` is not produced here: a successful token is the caller's to
/// classify.
fn map_final_claim_observation_error_v2(
    error: SessionStoreError,
) -> DomActuatorResult<DomClaimCustodyClassificationV1> {
    match error {
        SessionStoreError::SessionNotFound => Ok(DomClaimCustodyClassificationV1::Unattempted),
        // The Store already refuses a receiver token to the frozen sender. That
        // is a role error, not an unreachable authority, and reporting it as
        // one would let a misrouted call look like an outage.
        SessionStoreError::InvalidTransition => Err(DomActuatorError::InvalidStage),
        SessionStoreError::Quarantined => Err(DomActuatorError::UnsupportedFormat),
        SessionStoreError::Filesystem
        | SessionStoreError::StoreBusy
        | SessionStoreError::Conflict
        | SessionStoreError::Canonical
        | SessionStoreError::PolicyProfile
        | SessionStoreError::InvalidDomTransaction
        | SessionStoreError::FundingAuthorityUnavailable
        | SessionStoreError::ClaimSigningAuthorityUnavailable
        | SessionStoreError::LegacyV1RecoveryOnly
        | SessionStoreError::CapacityExceeded
        | SessionStoreError::RandomFailure => Err(DomActuatorError::ContractsAuthorityUnavailable),
    }
}

/// Preserve the difference between a bad receiver transition, durable
/// corruption and a temporarily unreachable Contracts authority.
fn map_observed_final_claim_transition_error_v2(error: SessionStoreError) -> DomActuatorError {
    match error {
        SessionStoreError::SessionNotFound | SessionStoreError::InvalidTransition => {
            DomActuatorError::InvalidStage
        }
        SessionStoreError::Conflict => DomActuatorError::RevisionConflict,
        SessionStoreError::Quarantined
        | SessionStoreError::Canonical
        | SessionStoreError::PolicyProfile
        | SessionStoreError::InvalidDomTransaction
        | SessionStoreError::LegacyV1RecoveryOnly => DomActuatorError::UnsupportedFormat,
        SessionStoreError::Filesystem
        | SessionStoreError::StoreBusy
        | SessionStoreError::FundingAuthorityUnavailable
        | SessionStoreError::ClaimSigningAuthorityUnavailable
        | SessionStoreError::CapacityExceeded
        | SessionStoreError::RandomFailure => DomActuatorError::ContractsAuthorityUnavailable,
    }
}

/// Translate a failure to rebuild the verifier from this Store's own facts.
///
/// It is a separate table from [`map_finality_error`] because the question is a
/// different one. Nothing here has touched the chain yet: the facts were read
/// out of the durable record moments earlier, so a refusal means the retained
/// state does not reassemble into the round it claims to be — durable
/// inconsistency, not bad chain evidence, and `FinalityEvidenceInvalid` would
/// point an operator at the wrong subsystem entirely.
///
/// Only `Leg` and `InvalidEvidence` are reachable on this path today. The rest
/// are named rather than swept into a wildcard so that a new `RealDomError`
/// variant fails the build here instead of landing silently in whichever arm
/// happened to be last — which is exactly how `Observation` was caught.
fn map_retained_verifier_error_v2(error: RealDomError) -> DomActuatorError {
    match error {
        // The reassembly refused: the retained round, template, transcript,
        // adaptor point or pre-signature disagree with each other.
        RealDomError::Leg(_)
        | RealDomError::Observation(_)
        | RealDomError::InvalidEvidence
        | RealDomError::EvidenceNotFound
        | RealDomError::BoundsExceeded => DomActuatorError::UnsupportedFormat,
        RealDomError::Store(_) | RealDomError::LockPoisoned => {
            DomActuatorError::ContractsAuthorityUnavailable
        }
        // Unreachable on this path — no chain access, no policy evaluation and
        // no reorg reconciliation happens while reassembling retained bytes —
        // but mapped to the same answers the chain-facing table gives, so an
        // arm that becomes reachable does not change meaning as it does.
        RealDomError::Chain(_) => DomActuatorError::RpcAuthorityUnavailable,
        RealDomError::FinalityPolicyInvalid => DomActuatorError::FinalityPolicyUnsupported,
        RealDomError::ReorgBeyondPolicy => DomActuatorError::ReorgBeyondPolicy,
        RealDomError::TransactionStillCanonical => DomActuatorError::TerminalStillCanonical,
        RealDomError::InsufficientConfirmations => DomActuatorError::FinalityEvidenceInvalid,
    }
}

fn map_finality_error(error: RealDomError) -> DomActuatorError {
    match error {
        RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable)
        | RealDomError::LockPoisoned => DomActuatorError::RpcAuthorityUnavailable,
        RealDomError::Store(_) => DomActuatorError::ContractsAuthorityUnavailable,
        RealDomError::FinalityPolicyInvalid | RealDomError::BoundsExceeded => {
            DomActuatorError::FinalityPolicyUnsupported
        }
        RealDomError::ReorgBeyondPolicy => DomActuatorError::ReorgBeyondPolicy,
        RealDomError::TransactionStillCanonical => DomActuatorError::TerminalStillCanonical,
        RealDomError::EvidenceNotFound | RealDomError::InsufficientConfirmations => {
            DomActuatorError::FinalityPending
        }
        // `Observation` is a semantic contradiction between the observed claim
        // and the proved adaptor opening, so it is definitive: no retry, no
        // rescan and no fresh authority repairs it. It belongs with the other
        // evidence verdicts and never with an unavailable RPC or an unsupported
        // policy, which are the two answers an operator would retry. This is
        // the same verdict `adapter-dom-real` already reaches for the same
        // variant in `map_source_error` (`dom-real/src/lib.rs:1478-1487`); the
        // two boundaries must not disagree about whether a contradicted
        // observation is worth trying again. `EvidenceNotFound` and
        // `InsufficientConfirmations` are intentionally handled above as the
        // distinct, non-contradictory `FinalityPending` state.
        RealDomError::Chain(_)
        | RealDomError::Leg(_)
        | RealDomError::Observation(_)
        | RealDomError::InvalidEvidence => DomActuatorError::FinalityEvidenceInvalid,
    }
}

fn map_reorg_error(error: RealDomError) -> DomActuatorError {
    match error {
        RealDomError::TransactionStillCanonical => DomActuatorError::TerminalStillCanonical,
        RealDomError::ReorgBeyondPolicy => DomActuatorError::ReorgBeyondPolicy,
        other => map_finality_error(other),
    }
}

fn action_for_purpose(purpose: PurposeV1) -> DomActuatorResult<DomActionV1> {
    match purpose {
        // A refund adaptor round produces this participant's refund signing
        // artifacts, which is exactly what `PresignRefund` authorizes: the same
        // refund transaction, the same beneficiary, the same artifacts. What
        // differs is that the signature is adaptor-bound and therefore reveals
        // a witness the participant itself chose to commit, which grants no
        // additional authority over funds and so needs no additional
        // capability. The session store reaches the same conclusion: the refund
        // adaptor signs under `SessionPhaseV1::RefundSigning`, against the
        // refund template.
        PurposeV1::Refund | PurposeV1::RefundAdaptor => Ok(DomActionV1::PresignRefund),
        PurposeV1::ClaimAdaptor => Ok(DomActionV1::PresignClaimAdaptor),
        PurposeV1::Funding => Ok(DomActionV1::BroadcastFunding),
        PurposeV1::Sponsor => Err(DomActuatorError::CapabilityMismatch),
    }
}

fn funding_evidence_digest(evidence: &CanonicalDomFundingEvidenceV1) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"DOM:actuator-funding-finality-evidence:v1");
    hasher.update(evidence.tx_hash());
    hasher.update(evidence.block_hash());
    hasher.update(evidence.block_height().to_be_bytes());
    hasher.update(evidence.block_time_seconds().to_be_bytes());
    hasher.update(evidence.shared_output_commitment());
    hasher.update(evidence.observed_tip_height().to_be_bytes());
    hasher.update(evidence.observed_tip_hash());
    hasher.update(evidence.confirmation_depth().to_be_bytes());
    hasher.finalize().into()
}

fn claim_authority_evidence_digest(
    authorization: &ConsumedClaimSigningAuthorizationV1,
) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"DOM:actuator-claim-persistence-authority:v1");
    hasher.update(authorization.session_id());
    hasher.update(authorization.terms_hash());
    hasher.update(authorization.dom_shared_output_commitment());
    hasher.update(authorization.claim_template_hash());
    hasher.update(authorization.round_start_transcript_hash());
    hasher.update(authorization.adaptor_point().to_compressed_bytes());
    hasher.update(authorization.issuance_record_digest());
    hasher.update(authorization.consumption_record_digest());
    hasher.update(authorization.bound_session_revision().to_be_bytes());
    hasher.update(authorization.bound_session_record_digest());
    hasher.update(authorization.dom_confirmation_depth().to_be_bytes());
    hasher.finalize().into()
}

/// Canonical commitment to the exact revalidated V2 `FinalClaim` authority.
///
/// Beyond every V1 fact it also freezes the canonical role plan: the frozen
/// `FinalClaim` role-binding and ready-binding digests, the sender and receiver
/// participants, and the reveal-mode/secret-source tags. Two authorities that
/// differ in any of those produce different digests, so the durable action
/// intent can never be reused across roles, modes or legs.
fn final_claim_authority_evidence_digest_v2(
    authorization: &ConsumedClaimSigningAuthorizationV2,
) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"DOM:actuator-final-claim-persistence-authority:v2");
    hasher.update(authorization.session_id());
    hasher.update(authorization.settlement_id());
    hasher.update(authorization.terms_hash());
    hasher.update(authorization.chain_id());
    hasher.update(authorization.dom_shared_output_commitment());
    hasher.update(authorization.claim_template_hash());
    hasher.update(authorization.round_start_transcript_hash());
    hasher.update(authorization.adaptor_point().to_compressed_bytes());
    hasher.update(authorization.final_claim_role_binding_digest());
    hasher.update(authorization.ready_binding_digest());
    hasher.update(authorization.dom_claim_sender_id());
    hasher.update(authorization.final_claim_receiver_id());
    hasher.update([authorization.reveal_mode_tag()]);
    hasher.update([authorization.secret_source_tag()]);
    hasher.update(authorization.issuance_record_digest());
    hasher.update(authorization.consumption_record_digest());
    hasher.update(authorization.bound_session_revision().to_be_bytes());
    hasher.update(authorization.bound_session_record_digest());
    hasher.update(authorization.dom_minimum_confirmations().to_be_bytes());
    hasher.update(authorization.dom_confirmation_depth().to_be_bytes());
    hasher.finalize().into()
}

/// Opaque commitment to the durable route/effect/fence/owner action intent.
///
/// The DOM Contracts store binds its exposure record to this value. It carries
/// no bytes and cannot be inverted, so Contracts never receives caller-shaped
/// route facts, only a single commitment it stores and later reauthenticates.
fn claim_action_scope_digest_v2(scope: ScopedDomActionV1, evidence_digest: [u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"DOM:actuator-final-claim-action-scope:v2");
    hasher.update(scope.binding().route_id());
    hasher.update(scope.binding().session_id());
    hasher.update(scope.binding().participant().participant_id());
    hasher.update([scope.binding().participant().protocol_index()]);
    hasher.update(scope.effect_id());
    hasher.update([scope.action().tag()]);
    hasher.update(scope.binding().chain_id());
    hasher.update(scope.binding().terms_digest());
    hasher.update(evidence_digest);
    hasher.finalize().into()
}

fn resume_or_retry_shared_output<T>(
    retained: Result<T, SharedBlindingVaultError<InventoryError>>,
    create_fresh: impl FnOnce() -> Result<T, SharedBlindingVaultError<InventoryError>>,
) -> DomActuatorResult<T> {
    match retained {
        Ok(value) => Ok(value),
        Err(SharedBlindingVaultError::Vault(InventoryError::NoMatchingSharedBlinding)) => {
            create_fresh().map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)
        }
        // Tombstones, ambiguity, corruption and every protocol error remain
        // indistinguishable and fail closed; they never authorize replacement.
        Err(_) => Err(DomActuatorError::SharedOutputRecoveryIndeterminate),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs::File;
    use std::sync::Arc;
    use std::time::Duration;

    use cap_std::fs::Dir;
    use dom_adaptor::{ClaimObservationError, SigningShareV1};
    use dom_core::Hash256;
    use dom_scriptless_chain_adapter::BearerTokenV1;
    use dom_scriptless_crypto::{Passphrase, StorageIdsV1};
    use dom_scriptless_store::{
        BudgetPolicyProfileV1, BudgetPolicyV1, SessionChainProjectionV1, SessionIrreversibleV1,
        SessionPhaseV1, SessionRecordFieldsV1, SessionTxObservationV1, BUDGET_POLICY_LEN,
    };
    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::model::StoredDomSessionBindingPartsV1;
    use crate::store::tests::{
        advance_to_funding_confirmed, binding, claim_state_snapshot, digest, finality_record,
        mark_claim_potentially_exposed_for_test, seed_exact_claim_custody,
        seed_prepared_final_claim_v2, setup, TestContext, TestResult,
    };

    assert_not_impl_any!(DomClaimPersistenceRequestV1<'static>: Clone, Copy, core::fmt::Debug);
    // The receiver marker is what makes "extract `t` without a durable
    // observation record" inexpressible rather than merely refused. It has no
    // public constructor in the Store, and these are the other three ways a
    // caller could otherwise conjure or duplicate one.
    assert_not_impl_any!(ObservedFinalClaimExposureV2:
        Clone,
        Copy,
        Default,
        core::fmt::Debug,
        AsRef<[u8]>,
        Into<Vec<u8>>
    );
    assert_not_impl_any!(DomParticipantSigningShareV1: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(
        DomFinalClaimPersistenceRequestV2<'static>: Clone,
        Copy,
        core::fmt::Debug
    );
    assert_not_impl_any!(DomFinalClaimAdmissionBundleV2: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(DomFinalClaimAdmissionBundleV2:
        core::ops::Deref,
        AsRef<[u8]>,
        Into<Vec<u8>>
    );

    fn production_policy() -> TestResult<BudgetPolicyV1> {
        let mut bytes = [0; BUDGET_POLICY_LEN];
        bytes[..8].copy_from_slice(b"DOMNVBP1");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10] = BudgetPolicyProfileV1::ProductionRatified as u8;
        bytes[11] = 1;
        bytes[16..48].fill(0x41);
        bytes[48..56].copy_from_slice(&100_u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&50_u64.to_le_bytes());
        bytes[64..68].copy_from_slice(&10_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&25_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&3_600_u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&60_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&86_400_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&1_u64.to_le_bytes());
        let policy_digest =
            dom_crypto::blake2b_256_tagged("DOM:contracts-vault-budget-policy:v1", &bytes[..112]);
        bytes[112..].copy_from_slice(policy_digest.as_bytes());
        BudgetPolicyV1::from_bytes(&bytes).test_context("production policy")
    }

    #[test]
    fn cross_session_funding_transplant_is_refused_before_rpc_closure() {
        let rpc_called = Cell::new(false);
        let result = submit_after_funding_preflight(
            "session-b-linear-funding-authority",
            digest(0xb2),
            digest(0xa1),
            |_| {
                rpc_called.set(true);
                Ok(())
            },
        );
        assert!(matches!(result, Err(DomActuatorError::CapabilityMismatch)));
        assert!(!rpc_called.get());
    }

    fn contracts_store(
        binding: DomSessionBindingV1,
    ) -> TestResult<(tempfile::TempDir, ContractsSessionStoreV1)> {
        let directory = tempfile::tempdir().test_context("contracts tempdir")?;
        let parent = Arc::new(Dir::from_std_file(
            File::open(directory.path()).test_context("open contracts parent")?,
        ));
        let store =
            ContractsSessionStoreV1::create_production(parent, "sessions", production_policy()?)
                .test_context("create contracts store")?;
        let initial = SessionRecordV1::new(
            SessionRecordFieldsV1 {
                session_id: binding.session_id(),
                revision: 0,
                phase: SessionPhaseV1::Created,
                terms_hash: binding.terms_digest(),
                transcript_hash: digest(201),
                irreversible: SessionIrreversibleV1 {
                    any_signing_share_sent: false,
                    funding_authorized: false,
                    adaptor_secret_exposed: false,
                    nonce_epoch: 1,
                },
                chain: SessionChainProjectionV1 {
                    tip_id: digest(202),
                    tip_height: 1,
                    funding: SessionTxObservationV1::Unknown,
                    claim: SessionTxObservationV1::Unknown,
                    refund: SessionTxObservationV1::Unknown,
                },
            },
            b"sealed-dom-actuator-claim-admission-test",
        )
        .test_context("initial contracts record")?;
        store
            .create_session(&initial)
            .test_context("create session")?;
        Ok((directory, store))
    }

    fn no_rpc_submission_adapter(
        binding: DomSessionBindingV1,
    ) -> TestResult<DomHttpChainAdapterV1> {
        DomHttpChainAdapterV1::new(
            "http://127.0.0.1:1",
            binding
                .expected_dom_identity()
                .test_context("expected DOM identity")?,
            BearerTokenV1::new("must-not-be-sent".to_owned()).test_context("bearer token")?,
            Duration::from_millis(50),
            Duration::from_millis(50),
        )
        .test_context("no-RPC adapter")
    }

    #[test]
    fn contracts_actuator_and_signer_share_one_physical_store_opening() -> TestResult {
        let bound = binding(9, 10)?;
        let (contracts_directory, session_store) = contracts_store(bound)?;
        let parent = Arc::new(Dir::from_std_file(
            File::open(contracts_directory.path()).test_context("open nonce-vault parent")?,
        ));
        let passphrase = Passphrase::new(b"actuator-signer-shared-opening".to_vec())
            .test_context("nonce-vault passphrase")?;
        let nonce_vault = ContractsNonceVaultV1::create_production(
            parent,
            "nonce-vault",
            StorageIdsV1::new([0x91; 32], [0x92; 32]).test_context("distinct storage ids")?,
            &passphrase,
            production_policy()?,
        )
        .test_context("create production nonce vault")?;
        let local_share = DomParticipantSigningShareV1::new(
            bound,
            SigningShareV1::from_be_bytes([0x21; 32]).test_context("canonical signing share")?,
        );
        let actuator = DomContractsActuatorV1::bind(&session_store, bound)
            .test_context("bind shared Contracts actuator")?;
        let trusted_chain_id = TrustedChainIdV1::from_authenticated_genesis(
            bound.runtime_identity().network_magic,
            &Hash256::from_bytes(bound.genesis_hash()),
        );
        let _signer = participant_contracts_signer_v1(
            nonce_vault,
            &session_store,
            bound,
            trusted_chain_id,
            local_share,
        )
        .test_context("construct binding-scoped Contracts signer")?;
        let actuator_head = actuator
            .session_head()
            .test_context("authenticated actuator head")?;
        let direct_head = session_store
            .load_session(bound.session_id())
            .test_context("authenticated direct head")?;
        assert!(actuator_head == direct_head);
        Ok(())
    }

    #[test]
    fn contracts_signer_rejects_foreign_share_and_terms_divergence_before_construction(
    ) -> TestResult {
        let expected = binding(9, 10)?;
        let (contracts_directory, session_store) = contracts_store(expected)?;
        let parent = Arc::new(Dir::from_std_file(
            File::open(contracts_directory.path()).test_context("open nonce-vault parent")?,
        ));
        let passphrase = Passphrase::new(b"binding-scoped-signing-share".to_vec())
            .test_context("vault passphrase")?;
        let remote = DomSessionBindingV1::from_parts_for_store(StoredDomSessionBindingPartsV1 {
            route_id: expected.route_id(),
            session_id: expected.session_id(),
            participant: crate::DomParticipantV1::new(digest(77), 1)
                .test_context("remote participant")?,
            chain_id: expected.chain_id(),
            genesis_hash: expected.genesis_hash(),
            runtime_identity: expected.runtime_identity(),
            terms_digest: expected.terms_digest(),
            profile_digest: expected.profile_digest(),
            deployment_digest: expected.deployment_digest(),
            asset_binding_digest: expected.asset_binding_digest(),
            registry_epoch: expected.registry_epoch(),
            min_confirmations: expected.min_confirmations(),
            max_reorg_depth: expected.max_reorg_depth(),
        })
        .test_context("remote binding")?;
        let mismatches = [binding(8, 10)?, binding(9, 11)?, remote];
        let trusted_chain_id = TrustedChainIdV1::from_authenticated_genesis(
            expected.runtime_identity().network_magic,
            &Hash256::from_bytes(expected.genesis_hash()),
        );
        for (index, mismatched) in mismatches.into_iter().enumerate() {
            let marker = u8::try_from(index).test_context("bounded fixture index")?;
            let nonce_vault = ContractsNonceVaultV1::create_production(
                Arc::clone(&parent),
                &format!("mismatched-nonce-vault-{index}"),
                StorageIdsV1::new(
                    [0xa1_u8.wrapping_add(marker); 32],
                    [0xb1_u8.wrapping_add(marker); 32],
                )
                .test_context("distinct storage ids")?,
                &passphrase,
                production_policy()?,
            )
            .test_context("create mismatched nonce vault")?;
            let local_share = DomParticipantSigningShareV1::new(
                mismatched,
                SigningShareV1::from_be_bytes([0x31_u8.wrapping_add(marker); 32])
                    .test_context("canonical signing share")?,
            );
            assert!(matches!(
                participant_contracts_signer_v1(
                    nonce_vault,
                    &session_store,
                    expected,
                    trusted_chain_id,
                    local_share,
                ),
                Err(DomActuatorError::InvalidBinding)
            ));
        }

        let divergent_terms =
            DomSessionBindingV1::from_parts_for_store(StoredDomSessionBindingPartsV1 {
                route_id: expected.route_id(),
                session_id: expected.session_id(),
                participant: expected.participant(),
                chain_id: expected.chain_id(),
                genesis_hash: expected.genesis_hash(),
                runtime_identity: expected.runtime_identity(),
                terms_digest: digest(88),
                profile_digest: expected.profile_digest(),
                deployment_digest: expected.deployment_digest(),
                asset_binding_digest: expected.asset_binding_digest(),
                registry_epoch: expected.registry_epoch(),
                min_confirmations: expected.min_confirmations(),
                max_reorg_depth: expected.max_reorg_depth(),
            })
            .test_context("terms-divergent binding")?;
        let before = session_store
            .load_session(expected.session_id())
            .test_context("head before rejected signer")?;
        let nonce_vault = ContractsNonceVaultV1::create_production(
            Arc::clone(&parent),
            "terms-divergent-nonce-vault",
            StorageIdsV1::new([0xc1; 32], [0xc2; 32]).test_context("distinct storage ids")?,
            &passphrase,
            production_policy()?,
        )
        .test_context("create terms-divergent nonce vault")?;
        let local_share = DomParticipantSigningShareV1::new(
            divergent_terms,
            SigningShareV1::from_be_bytes([0x41; 32]).test_context("canonical signing share")?,
        );
        assert!(matches!(
            participant_contracts_signer_v1(
                nonce_vault,
                &session_store,
                divergent_terms,
                trusted_chain_id,
                local_share,
            ),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        let after = session_store
            .load_session(expected.session_id())
            .test_context("head after rejected signer")?;
        assert!(before == after);
        Ok(())
    }

    #[test]
    fn shared_output_retry_requires_authenticated_exact_absence() -> TestResult {
        let calls = Cell::new(0_u8);
        let value = resume_or_retry_shared_output::<u8>(
            Err(SharedBlindingVaultError::Vault(
                InventoryError::NoMatchingSharedBlinding,
            )),
            || {
                calls.set(calls.get() + 1);
                Ok(7)
            },
        )
        .test_context("authenticated absence permits one fresh attempt")?;
        assert_eq!(value, 7);
        assert_eq!(calls.get(), 1);

        for error in [
            InventoryError::RestoreQuarantined,
            InventoryError::Canonical,
            InventoryError::Crypto,
        ] {
            let calls = Cell::new(0_u8);
            assert_eq!(
                resume_or_retry_shared_output::<u8>(
                    Err(SharedBlindingVaultError::Vault(error)),
                    || {
                        calls.set(calls.get() + 1);
                        Ok(8)
                    },
                ),
                Err(DomActuatorError::SharedOutputRecoveryIndeterminate)
            );
            assert_eq!(calls.get(), 0, "quarantined state generated a new share");
        }

        assert_eq!(
            resume_or_retry_shared_output::<u8>(Ok(9), || {
                calls.set(calls.get() + 1);
                Ok(10)
            }),
            Ok(9)
        );
        assert_eq!(calls.get(), 1, "retained share was replaced");
        Ok(())
    }

    #[test]
    fn unattempted_claim_entrypoints_fail_before_rpc_or_state_change() -> TestResult {
        let (_control_directory, _control_path, mut control, lease) = setup()?;
        let bound = binding(1, 2)?;
        control
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut control, lease, bound)?;
        let (claim_scope, evidence, previous, broadcast) =
            seed_exact_claim_custody(&mut control, lease, bound)?;
        let (_contracts_directory, session_store) = contracts_store(bound)?;
        let actuator = DomContractsActuatorV1::bind(&session_store, bound)
            .test_context("bind contracts actuator")?;
        let audit = actuator
            .audit_retained_claim_custody_v1(&mut control, lease, 1_520)
            .test_context("reauthenticate unattempted custody")?;
        assert!(audit.classification().is_unattempted());
        assert_eq!(audit.send_attempt_count(), 0);
        assert_eq!(audit.admission_record_digest(), None);
        let (capability, disposition) = control
            .authorize_action(lease, claim_scope, evidence, None, 1_521)
            .test_context("resume completed claim intent")?;
        assert_eq!(disposition, DomOperationDispositionV1::AlreadyCompleted);
        let control_before = claim_state_snapshot(&control, bound)?;
        let contracts_before = actuator
            .session_head()
            .test_context("Contracts head before rejected entrypoints")?;

        assert!(matches!(
            actuator.resume_persisted_claim_broadcast(&mut control, lease, capability, 1_522),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(claim_state_snapshot(&control, bound)?, control_before);
        assert!(matches!(
            actuator.resume_persisted_claim_admission(&mut control, lease, 1_523),
            Err(DomActuatorError::ReconciliationRequired)
        ));
        assert_eq!(claim_state_snapshot(&control, bound)?, control_before);
        assert!(matches!(
            actuator.adopt_persisted_claim_after_takeover(
                &mut control,
                lease,
                claim_scope,
                previous,
                1_524,
            ),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(claim_state_snapshot(&control, bound)?, control_before);

        let adapter = no_rpc_submission_adapter(bound)?;
        assert!(matches!(
            actuator.dispatch_claim_broadcast(&mut control, lease, &adapter, broadcast, 1_525),
            Err(DomActuatorError::InvalidStage)
        ));
        // Any adapter access would map to `RpcAuthorityUnavailable`; the exact
        // `InvalidStage` result proves the state fence rejected first.
        assert_eq!(claim_state_snapshot(&control, bound)?, control_before);
        let contracts_after = actuator
            .session_head()
            .test_context("Contracts head after rejected entrypoints")?;
        assert!(contracts_before == contracts_after);
        Ok(())
    }

    #[test]
    fn potentially_exposed_claim_entrypoints_fail_before_rpc_or_state_change() -> TestResult {
        let (_control_directory, _control_path, mut control, lease) = setup()?;
        let bound = binding(1, 2)?;
        control
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut control, lease, bound)?;
        let (claim_scope, evidence, previous, broadcast) =
            seed_exact_claim_custody(&mut control, lease, bound)?;
        let _pending =
            mark_claim_potentially_exposed_for_test(&mut control, lease, &broadcast, 1_520)?;
        let (_contracts_directory, session_store) = contracts_store(bound)?;
        let actuator = DomContractsActuatorV1::bind(&session_store, bound)
            .test_context("bind contracts actuator")?;
        let audit = actuator
            .audit_retained_claim_custody_v1(&mut control, lease, 1_521)
            .test_context("reauthenticate potentially exposed custody")?;
        assert!(audit.classification().is_potentially_exposed());
        assert_eq!(audit.admission_record_digest(), None);
        let (capability, disposition) = control
            .authorize_action(lease, claim_scope, evidence, None, 1_522)
            .test_context("resume completed claim intent")?;
        assert_eq!(disposition, DomOperationDispositionV1::AlreadyCompleted);
        let control_before = claim_state_snapshot(&control, bound)?;
        let contracts_before = actuator
            .session_head()
            .test_context("Contracts head before rejected entrypoints")?;

        assert!(matches!(
            actuator.resume_persisted_claim_broadcast(&mut control, lease, capability, 1_523),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(claim_state_snapshot(&control, bound)?, control_before);
        assert!(matches!(
            actuator.resume_persisted_claim_admission(&mut control, lease, 1_523),
            Err(DomActuatorError::ReconciliationRequired)
        ));
        assert_eq!(claim_state_snapshot(&control, bound)?, control_before);
        assert!(matches!(
            actuator.adopt_persisted_claim_after_takeover(
                &mut control,
                lease,
                claim_scope,
                previous,
                1_524,
            ),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(claim_state_snapshot(&control, bound)?, control_before);

        let adapter = no_rpc_submission_adapter(bound)?;
        assert!(matches!(
            actuator.dispatch_claim_broadcast(&mut control, lease, &adapter, broadcast, 1_525),
            Err(DomActuatorError::InvalidStage)
        ));
        // Any adapter access would map to `RpcAuthorityUnavailable`; the exact
        // `InvalidStage` result proves the state fence rejected first.
        assert_eq!(claim_state_snapshot(&control, bound)?, control_before);
        let contracts_after = actuator
            .session_head()
            .test_context("Contracts head after rejected entrypoints")?;
        assert!(contracts_before == contracts_after);
        Ok(())
    }

    fn trusted_chain_id_for(bound: DomSessionBindingV1) -> TrustedChainIdV1 {
        TrustedChainIdV1::from_authenticated_genesis(
            bound.runtime_identity().network_magic,
            &Hash256::from_bytes(bound.genesis_hash()),
        )
    }

    fn lower_hex(value: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(value.len().saturating_mul(2));
        for byte in value {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    /// Durable-corruption injection into a real production Contracts store.
    ///
    /// The Store composes this exact name on its own writing path and reads it
    /// back through a bounded, identity-revalidated open, so a real file under
    /// that name is a real corrupt record — not a mock and not a stub. The
    /// bytes are deliberately not a valid `DOMFCEX2`/`DOMFCOB2` prefix, which
    /// is the whole point: the record is *present* and *unreadable*, which is
    /// the one state that must never be reported as absence.
    ///
    /// The returned path is the durable artefact that proves the injection
    /// happened; a run in which it was not created would take the healthy
    /// branch and be indistinguishable from a passing test that proved nothing.
    fn inject_corrupt_final_claim_record(
        directory: &tempfile::TempDir,
        bound: DomSessionBindingV1,
        suffix: &str,
    ) -> TestResult<std::path::PathBuf> {
        use std::os::unix::fs::PermissionsExt;

        let artifacts = directory.path().join("sessions").join("session-artifacts");
        let name = format!("{}{suffix}", lower_hex(&bound.session_id()));
        let path = artifacts.join(name);
        assert!(!path.exists(), "the fixture already had a durable record");
        std::fs::write(&path, [0x00_u8; 64]).test_context("inject a corrupt durable record")?;
        // Owner-only, exactly like every record the Store publishes itself, so
        // the refusal below is provably the magic/length verdict on the bytes
        // and not an incidental node-safety verdict on the mode.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .test_context("owner-only injected record")?;
        assert!(
            path.exists(),
            "corruption injection left no durable artefact"
        );
        Ok(path)
    }

    #[test]
    fn production_final_claim_v2_contracts_failure_is_never_read_as_unattempted() -> TestResult {
        // P1-C4. `SessionNotFound` is the only Contracts answer that proves the
        // claim was never exposed. A Contracts store that cannot answer must
        // never be indistinguishable from one that proves absence, because the
        // caller's next move on `Unattempted` is to expose the adaptor secret.
        let (_control_directory, _control_path, mut control, lease) = setup()?;
        let bound = binding(1, 2)?;
        control
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut control, lease, bound)?;
        let (contracts_directory, session_store) = contracts_store(bound)?;
        let actuator = DomContractsActuatorV1::bind(&session_store, bound)
            .test_context("bind contracts actuator")?;
        let trusted_chain_id = trusted_chain_id_for(bound);

        // Contrapositive first, on both faces: on a healthy store the identical
        // calls really do reach `Unattempted`, so neither refusal below can be
        // vacuous. The receiver face needs its own anchor — the claim this test
        // makes is about two error tables, so one table's before-and-after
        // would only establish half of it.
        assert_eq!(
            actuator.classify_final_claim_custody_v2(&mut control, lease, &trusted_chain_id, 1_530),
            Ok(DomClaimCustodyClassificationV1::Unattempted)
        );
        assert_eq!(
            actuator.classify_final_claim_receiver_custody_v2(&trusted_chain_id),
            Ok(DomClaimCustodyClassificationV1::Unattempted)
        );
        let contracts_before = actuator
            .session_head()
            .test_context("Contracts head before the injection")?;

        let corrupted = inject_corrupt_final_claim_record(
            &contracts_directory,
            bound,
            ".operational-final-claim-exposure-v2",
        )?;

        // The sender face collapses every non-`SessionNotFound` answer into one
        // unavailable authority, which is exactly the P1-C4 contract: it is
        // allowed to lose the distinction, and it is not allowed to lose the
        // refusal.
        assert_eq!(
            actuator.classify_final_claim_custody_v2(&mut control, lease, &trusted_chain_id, 1_531),
            Err(DomActuatorError::ContractsAuthorityUnavailable)
        );
        // The receiver face refuses on the same durable state, and refuses it
        // as something else. An unreadable record is a quarantine verdict from
        // the Store, and that face keeps it distinct from an unreachable
        // authority instead of flattening both into one operator-visible fact.
        // Two different answers to one injected corruption is the observable
        // difference between the two error tables.
        assert_eq!(
            actuator.classify_final_claim_receiver_custody_v2(&trusted_chain_id),
            Err(DomActuatorError::UnsupportedFormat)
        );

        // Nothing was written on either plane while failing closed.
        assert!(
            contracts_before
                == actuator
                    .session_head()
                    .test_context("Contracts head after the refusals")?
        );
        assert!(matches!(
            control.audit_final_claim_custody_v2(lease, bound, 1_532),
            Err(DomActuatorError::ReconciliationRequired)
        ));

        // Removing the injected record restores the proven-absence answer on
        // both faces, so the two refusals were caused by that artefact and by
        // nothing else — and, incidentally, no answer here is served from an
        // in-memory cache.
        std::fs::remove_file(&corrupted).test_context("remove the injected record")?;
        assert_eq!(
            actuator.classify_final_claim_custody_v2(&mut control, lease, &trusted_chain_id, 1_533),
            Ok(DomClaimCustodyClassificationV1::Unattempted)
        );
        assert_eq!(
            actuator.classify_final_claim_receiver_custody_v2(&trusted_chain_id),
            Ok(DomClaimCustodyClassificationV1::Unattempted)
        );
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_receiver_probe_never_collapses_the_store_error_table() -> TestResult
    {
        // The Store distinguishes a role error from durable corruption from a
        // genuinely absent record on the receiver face. Those three states
        // cannot be staged side by side from one fixture — a session cannot at
        // once be the frozen sender, hold a quarantined record and hold none —
        // so the table is proven armwise on the mapping itself, which is why
        // the mapping is a free function.
        assert_eq!(
            map_final_claim_observation_error_v2(SessionStoreError::SessionNotFound),
            Ok(DomClaimCustodyClassificationV1::Unattempted)
        );
        assert_eq!(
            map_final_claim_observation_error_v2(SessionStoreError::InvalidTransition),
            Err(DomActuatorError::InvalidStage)
        );
        assert_eq!(
            map_final_claim_observation_error_v2(SessionStoreError::Quarantined),
            Err(DomActuatorError::UnsupportedFormat)
        );
        for unavailable in [
            SessionStoreError::Filesystem,
            SessionStoreError::StoreBusy,
            SessionStoreError::Conflict,
            SessionStoreError::Canonical,
            SessionStoreError::PolicyProfile,
            SessionStoreError::InvalidDomTransaction,
            SessionStoreError::FundingAuthorityUnavailable,
            SessionStoreError::ClaimSigningAuthorityUnavailable,
            SessionStoreError::LegacyV1RecoveryOnly,
            SessionStoreError::CapacityExceeded,
            SessionStoreError::RandomFailure,
        ] {
            assert_eq!(
                map_final_claim_observation_error_v2(unavailable),
                Err(DomActuatorError::ContractsAuthorityUnavailable),
                "{unavailable:?} did not reach the caller as an unavailable authority"
            );
        }
        // The three meaningful arms are pairwise distinct, which is the whole
        // claim: a role error, durable corruption and an unreachable authority
        // must not arrive at an operator as the same fact.
        assert_ne!(
            map_final_claim_observation_error_v2(SessionStoreError::InvalidTransition),
            map_final_claim_observation_error_v2(SessionStoreError::Quarantined)
        );
        assert_ne!(
            map_final_claim_observation_error_v2(SessionStoreError::Quarantined),
            map_final_claim_observation_error_v2(SessionStoreError::Canonical)
        );
        assert_ne!(
            map_final_claim_observation_error_v2(SessionStoreError::InvalidTransition),
            map_final_claim_observation_error_v2(SessionStoreError::Canonical)
        );
        Ok(())
    }

    #[test]
    fn observed_final_claim_transition_errors_preserve_retry_semantics() -> TestResult {
        for invalid_stage in [
            SessionStoreError::SessionNotFound,
            SessionStoreError::InvalidTransition,
        ] {
            assert_eq!(
                map_observed_final_claim_transition_error_v2(invalid_stage),
                DomActuatorError::InvalidStage
            );
        }
        assert_eq!(
            map_observed_final_claim_transition_error_v2(SessionStoreError::Conflict),
            DomActuatorError::RevisionConflict
        );
        for corrupt in [
            SessionStoreError::Quarantined,
            SessionStoreError::Canonical,
            SessionStoreError::PolicyProfile,
            SessionStoreError::InvalidDomTransaction,
            SessionStoreError::LegacyV1RecoveryOnly,
        ] {
            assert_eq!(
                map_observed_final_claim_transition_error_v2(corrupt),
                DomActuatorError::UnsupportedFormat
            );
        }
        for unavailable in [
            SessionStoreError::Filesystem,
            SessionStoreError::StoreBusy,
            SessionStoreError::FundingAuthorityUnavailable,
            SessionStoreError::ClaimSigningAuthorityUnavailable,
            SessionStoreError::CapacityExceeded,
            SessionStoreError::RandomFailure,
        ] {
            assert_eq!(
                map_observed_final_claim_transition_error_v2(unavailable),
                DomActuatorError::ContractsAuthorityUnavailable
            );
        }
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_role_exclusivity_guard_refuses_only_a_two_plane_claim(
    ) -> TestResult {
        use DomClaimCustodyClassificationV1::{Admitted, PotentiallyExposed, Unattempted};

        // The barrier that makes a session sender-or-receiver lives in the DOM
        // Contracts store, which holds both records under one durable
        // authority. This guard claims only that the two answers this control
        // plane received disagree, so it must refuse exactly when both planes
        // claim the session and never otherwise.
        for this_plane in [Unattempted, PotentiallyExposed, Admitted] {
            assert_eq!(
                DomContractsActuatorV1::require_exclusive_final_claim_role_v2(
                    this_plane,
                    Ok(Unattempted)
                ),
                Ok(())
            );
            assert_eq!(
                DomContractsActuatorV1::require_exclusive_final_claim_role_v2(
                    Unattempted,
                    Ok(this_plane)
                ),
                Ok(())
            );
        }
        for (this_plane, other) in [
            (PotentiallyExposed, PotentiallyExposed),
            (PotentiallyExposed, Admitted),
            (Admitted, PotentiallyExposed),
            (Admitted, Admitted),
        ] {
            assert_eq!(
                DomContractsActuatorV1::require_exclusive_final_claim_role_v2(
                    this_plane,
                    Ok(other)
                ),
                Err(DomActuatorError::UnsupportedFormat)
            );
        }
        // An unreadable other plane never turns into a refusal here. Its own
        // probe already reported that failure as itself to its own caller, and
        // a cross-plane detector that can only refuse must not override the
        // Store's decision on an answer it could not read.
        for error in [
            DomActuatorError::ContractsAuthorityUnavailable,
            DomActuatorError::UnsupportedFormat,
            DomActuatorError::InvalidStage,
        ] {
            assert_eq!(
                DomContractsActuatorV1::require_exclusive_final_claim_role_v2(Admitted, Err(error)),
                Ok(())
            );
        }
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_receiver_extract_requires_durable_observation_marker() -> TestResult
    {
        // The compile-time half is total and is stated at the top of this
        // module: `ObservedFinalClaimExposureV2` has no public constructor and
        // no `Clone`, `Default` or codec, so `extract_observed_claim_secret_v2`
        // cannot be called at all without a marker the Store already minted.
        // A negative that passes a forged marker is therefore not a test that
        // was skipped — it is a call that does not typecheck.
        //
        // What remains testable here is the runtime half: with no durable
        // marker the receiver face reports absence rather than fabricating an
        // observation, and it keeps doing so while the local control plane
        // moves underneath it.
        let (_control_directory, _control_path, mut control, lease) = setup()?;
        let bound = binding(1, 2)?;
        control
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut control, lease, bound)?;
        let (contracts_directory, session_store) = contracts_store(bound)?;
        let actuator = DomContractsActuatorV1::bind(&session_store, bound)
            .test_context("bind contracts actuator")?;
        let trusted_chain_id = trusted_chain_id_for(bound);

        assert_eq!(
            actuator.classify_final_claim_receiver_custody_v2(&trusted_chain_id),
            Ok(DomClaimCustodyClassificationV1::Unattempted)
        );

        // A chain that is not this session's is refused before the Store is
        // consulted at all. The fixture bindings all share one genesis, so the
        // foreign chain is derived from a different genesis rather than from a
        // different session — a different session on the same chain would not
        // exercise this guard at all.
        let foreign_chain = TrustedChainIdV1::from_authenticated_genesis(
            bound.runtime_identity().network_magic,
            &Hash256::from_bytes(digest(99)),
        );
        assert_ne!(foreign_chain.as_bytes(), trusted_chain_id.as_bytes());
        assert_eq!(
            actuator.classify_final_claim_receiver_custody_v2(&foreign_chain),
            Err(DomActuatorError::CapabilityMismatch)
        );

        // An unreadable marker is a quarantine verdict, never an absence: the
        // alternative would let a receiver conclude it never observed the
        // counterparty's claim while its own durable record says otherwise,
        // and the next move on that conclusion is to treat the adaptor secret
        // as still private.
        let corrupted = inject_corrupt_final_claim_record(
            &contracts_directory,
            bound,
            ".operational-final-claim-observation-v2",
        )?;
        assert_eq!(
            actuator.classify_final_claim_receiver_custody_v2(&trusted_chain_id),
            Err(DomActuatorError::UnsupportedFormat)
        );
        std::fs::remove_file(&corrupted).test_context("remove the injected marker")?;
        assert_eq!(
            actuator.classify_final_claim_receiver_custody_v2(&trusted_chain_id),
            Ok(DomClaimCustodyClassificationV1::Unattempted)
        );
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_retained_verifier_failures_are_durable_not_chain_failures(
    ) -> TestResult {
        // `build_retained_claim_verifier_v2` reads facts out of this Store and
        // hands them straight back to a constructor. Nothing on that path has
        // touched the chain, so a refusal means the retained state does not
        // reassemble into the round it claims to be. Reporting that as bad
        // chain evidence would send an operator to rescan a node over a
        // corrupt local record.
        //
        // The table is proven on the free function: the states it separates
        // cannot be staged side by side, and reaching the call itself needs a
        // `ConsumedClaimSigningAuthorizationV2`, which has no public
        // constructor. `RealDomError` carries no `PartialEq`, so the assertions
        // compare the mapped answers rather than the inputs.
        for reassembly_failure in [
            RealDomError::InvalidEvidence,
            RealDomError::EvidenceNotFound,
            RealDomError::BoundsExceeded,
            RealDomError::Observation(ClaimObservationError::InconsistentObservation),
        ] {
            assert_eq!(
                map_retained_verifier_error_v2(reassembly_failure),
                DomActuatorError::UnsupportedFormat
            );
        }
        for unavailable in [
            RealDomError::Store(SessionStoreError::StoreBusy),
            RealDomError::Store(SessionStoreError::Quarantined),
            RealDomError::LockPoisoned,
        ] {
            assert_eq!(
                map_retained_verifier_error_v2(unavailable),
                DomActuatorError::ContractsAuthorityUnavailable
            );
        }

        // The point of a second table: the same input means something
        // different on the two paths, and the two answers differ. On the
        // chain-facing path `InvalidEvidence` is evidence that failed to match
        // a transaction; here it is a Store that disagrees with itself.
        assert_eq!(
            map_finality_error(RealDomError::InvalidEvidence),
            DomActuatorError::FinalityEvidenceInvalid
        );
        assert_eq!(
            map_finality_error(RealDomError::Observation(
                ClaimObservationError::InconsistentObservation
            )),
            DomActuatorError::FinalityEvidenceInvalid
        );
        assert_eq!(
            map_finality_error(RealDomError::EvidenceNotFound),
            DomActuatorError::FinalityPending
        );
        assert_eq!(
            map_finality_error(RealDomError::InsufficientConfirmations),
            DomActuatorError::FinalityPending
        );
        assert_ne!(
            map_retained_verifier_error_v2(RealDomError::InvalidEvidence),
            map_finality_error(RealDomError::InvalidEvidence)
        );

        // Where the two tables agree, they must agree exactly, so an arm that
        // becomes reachable later does not silently change meaning.
        assert_eq!(
            map_retained_verifier_error_v2(RealDomError::ReorgBeyondPolicy),
            map_finality_error(RealDomError::ReorgBeyondPolicy)
        );
        assert_eq!(
            map_retained_verifier_error_v2(RealDomError::TransactionStillCanonical),
            map_finality_error(RealDomError::TransactionStillCanonical)
        );
        assert_eq!(
            map_retained_verifier_error_v2(RealDomError::FinalityPolicyInvalid),
            map_finality_error(RealDomError::FinalityPolicyInvalid)
        );
        assert_eq!(
            map_retained_verifier_error_v2(RealDomError::Chain(
                ChainAdapterError::TemporarilyUnavailable
            )),
            map_finality_error(RealDomError::Chain(
                ChainAdapterError::TemporarilyUnavailable
            ))
        );

        // `RealDomError::Leg(_)` is the one reachable arm this test cannot
        // reach: `LegError` lives in `dom-leg`, which this crate has no edge to
        // and cannot name. It shares the `UnsupportedFormat` arm with the four
        // above, so the arm itself is covered; what is not covered is that
        // `Leg` routes into it, and that is left as a compile-time fact rather
        // than dressed up as a runtime one.
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_local_terminalization_never_mints_a_receiver_observation(
    ) -> TestResult {
        // The receiver-side symmetric negative of
        // `production_final_claim_v2_reorg_and_finality_never_mint_admission`.
        // That test proves a sender's terminal checkpoint never fabricates an
        // admission in the owner-only mirror. This one proves the same thing
        // across the boundary the sender test cannot see: the receiver's whole
        // durable state is the DOM Contracts observation marker, and no amount
        // of local terminalization on this control plane creates one.
        let (_control_directory, _control_path, mut control, lease) = setup()?;
        let bound = binding(1, 2)?;
        control
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut control, lease, bound)?;
        let (_contracts_directory, session_store) = contracts_store(bound)?;
        let actuator = DomContractsActuatorV1::bind(&session_store, bound)
            .test_context("bind contracts actuator")?;
        let trusted_chain_id = trusted_chain_id_for(bound);
        let (_scope, _evidence, capability, facts) =
            seed_prepared_final_claim_v2(&mut control, lease, bound)?;
        let contracts_before = actuator
            .session_head()
            .test_context("Contracts head before terminalization")?;
        assert_eq!(
            actuator.classify_final_claim_receiver_custody_v2(&trusted_chain_id),
            Ok(DomClaimCustodyClassificationV1::Unattempted)
        );

        let _latched = control
            .latch_final_claim_attempt_v2(lease, &capability, &facts, 1_540)
            .test_context("pre-RPC latch on the owner-only mirror")?;
        let checkpoint = vec![0x50; 606];
        assert_eq!(
            control
                .record_terminal_finality(
                    lease,
                    bound,
                    finality_record(DomTerminalKindV1::Claim, facts.tx_hash, &checkpoint),
                    1_541,
                )
                .test_context("terminalize the exposed claim locally")?,
            DomOperationDispositionV1::Prepared
        );

        // The local plane moved all the way to a terminal checkpoint and the
        // receiver plane did not move at all.
        assert_eq!(
            actuator.classify_final_claim_receiver_custody_v2(&trusted_chain_id),
            Ok(DomClaimCustodyClassificationV1::Unattempted)
        );
        assert!(
            contracts_before
                == actuator
                    .session_head()
                    .test_context("Contracts head after terminalization")?
        );
        // And the sender plane still reports no Contracts exposure, so the
        // conservative join refuses instead of letting the local mirror lead.
        assert_eq!(
            actuator.classify_final_claim_custody_v2(&mut control, lease, &trusted_chain_id, 1_542),
            Err(DomActuatorError::UnsupportedFormat)
        );
        Ok(())
    }

    #[test]
    fn the_refund_adaptor_purpose_maps_to_the_refund_signing_capability() {
        // A refund adaptor round produces refund signing artifacts, so it is
        // authorized by the same capability as a plain refund. Mapping it
        // anywhere else would either invent a capability or, by failing closed,
        // make cross-curve routes unreachable through the actuator.
        assert_eq!(
            action_for_purpose(PurposeV1::RefundAdaptor),
            Ok(DomActionV1::PresignRefund)
        );
        assert_eq!(
            action_for_purpose(PurposeV1::Refund),
            Ok(DomActionV1::PresignRefund)
        );
        // The claim path keeps its own capability: the two are not
        // interchangeable.
        assert_eq!(
            action_for_purpose(PurposeV1::ClaimAdaptor),
            Ok(DomActionV1::PresignClaimAdaptor)
        );
        // Sponsor stays unauthorized.
        assert_eq!(
            action_for_purpose(PurposeV1::Sponsor),
            Err(DomActuatorError::CapabilityMismatch)
        );
    }
}
