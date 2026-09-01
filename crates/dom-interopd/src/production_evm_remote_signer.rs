//! Authenticated handoff for an EVM action signed by the counterparty.
//!
//! The requesting daemon never imports the counterparty key and never wraps a
//! remote role in [`evm_actuator::ScopedEip1559SignerV1`].  It emits only the
//! public DSC1 `0x15` commitment.  A response becomes executable only after the
//! Contracts Store has authenticated and durably retained the matching `0x16`
//! and consumed it into [`PreparedEvmSignedActionImportV1`].

use blake2::{digest::Update, digest::VariableOutput, Blake2bVar};
use dom_scriptless_store::PreparedEvmSignedActionImportV1;
use dom_scriptless_transport::{
    EvmActionKindV1 as TransportActionV1, EvmActionRequestInputV1, EvmActionRequestPayloadV1,
    EvmSignerRoleV1 as TransportSignerRoleV1,
};
use evm_actuator::{
    EvmOperationKindV1, EvmSignerRoleV1, RemoteEvmActionRequestInputV1, RemoteEvmActionRequestV1,
    RemoteEvmOperationCustodyResumeInputV1, RemoteEvmSignedActionV1,
};
use settlement_coordinator::{
    ChildAuthorityRefusalV1, ChildDispatchRequestV1, ChildObservationRequestV1, SettlementActionV1,
    SettlementFaceV1, SettlementLegV1,
};

use crate::production_child_router::ProductionChildMaterializationRequestV1;

type Digest32 = [u8; 32];

const ZERO_DIGEST: Digest32 = [0; 32];
const ZERO_ADDRESS: [u8; 20] = [0; 20];
const REMOTE_ACTION_ID_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/EVM-REMOTE/ACTION-ID/V1\0";
const REMOTE_EXECUTION_PLAN_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/EVM-REMOTE/EXECUTION-PLAN/V1\0";

#[derive(Clone, Copy)]
struct CoordinatorResumePinsV1 {
    route_id: Digest32,
    effect_id: Digest32,
    settlement_id: Digest32,
    semantic_digest: Digest32,
    terms_digest: Digest32,
    registry_digest: Digest32,
    profile_digest: Digest32,
    deployment_digest: Digest32,
    owner_epoch: u64,
    face: SettlementFaceV1,
    action: SettlementActionV1,
    operation_id: Digest32,
    transaction_hash: Digest32,
}

/// Purpose-limited bridge to the one physical Contracts/Relay owner.
///
/// Production implementations are issued by `ProductionContractsV1` and can
/// only stage the exact public `0x15` request or consume its matching durable
/// `0x16` response. Test doubles remain private to this crate's test builds.
pub(crate) trait ProductionEvmRemoteTransportV1: core::fmt::Debug {
    fn stage_request(
        &mut self,
        request: &ProductionEvmRemoteRequestV1,
    ) -> Result<Digest32, ChildAuthorityRefusalV1>;

    fn take_response(
        &mut self,
        request: &ProductionEvmRemoteRequestV1,
        request_message_digest: Digest32,
    ) -> Result<Option<PreparedEvmSignedActionImportV1>, ChildAuthorityRefusalV1>;
}

/// Immutable authenticated scope for the one EVM role not owned locally.
///
/// `session_id` and `terms_digest` are retained even though the fixed `0x15`
/// body commits them transitively through `execution_plan_digest`: the outer
/// DSC1 session and the Contracts Store session head are checked directly at
/// the import boundary, and the plan digest is recomputed from the exact
/// materialization request.  This gives restart auditing both an explicit and
/// a cryptographic binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionEvmRemoteSignerBindingV1 {
    route_id: Digest32,
    session_id: Digest32,
    settlement_id: Digest32,
    terms_digest: Digest32,
    registry_digest: Digest32,
    profile_digest: Digest32,
    deployment_digest: Digest32,
    composition_digest: Digest32,
    chain_id: u64,
    contract: [u8; 20],
    signer_account: [u8; 20],
    role: EvmSignerRoleV1,
    requester_id: Digest32,
    signer_id: Digest32,
    owner_id: Digest32,
}

/// Named input for constructing an authenticated remote signer scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionEvmRemoteSignerPinsV1 {
    pub(crate) route_id: Digest32,
    pub(crate) session_id: Digest32,
    pub(crate) settlement_id: Digest32,
    pub(crate) terms_digest: Digest32,
    pub(crate) registry_digest: Digest32,
    pub(crate) profile_digest: Digest32,
    pub(crate) deployment_digest: Digest32,
    pub(crate) composition_digest: Digest32,
    pub(crate) chain_id: u64,
    pub(crate) contract: [u8; 20],
    pub(crate) signer_account: [u8; 20],
    pub(crate) role: EvmSignerRoleV1,
    pub(crate) requester_id: Digest32,
    pub(crate) signer_id: Digest32,
    pub(crate) owner_id: Digest32,
}

impl ProductionEvmRemoteSignerBindingV1 {
    pub(crate) fn new(
        pins: ProductionEvmRemoteSignerPinsV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        if [
            pins.route_id,
            pins.session_id,
            pins.settlement_id,
            pins.terms_digest,
            pins.registry_digest,
            pins.profile_digest,
            pins.deployment_digest,
            pins.composition_digest,
            pins.requester_id,
            pins.signer_id,
            pins.owner_id,
        ]
        .contains(&ZERO_DIGEST)
            || pins.chain_id == 0
            || pins.contract == ZERO_ADDRESS
            || pins.signer_account == ZERO_ADDRESS
            || pins.requester_id == pins.signer_id
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(Self {
            route_id: pins.route_id,
            session_id: pins.session_id,
            settlement_id: pins.settlement_id,
            terms_digest: pins.terms_digest,
            registry_digest: pins.registry_digest,
            profile_digest: pins.profile_digest,
            deployment_digest: pins.deployment_digest,
            composition_digest: pins.composition_digest,
            chain_id: pins.chain_id,
            contract: pins.contract,
            signer_account: pins.signer_account,
            role: pins.role,
            requester_id: pins.requester_id,
            signer_id: pins.signer_id,
            owner_id: pins.owner_id,
        })
    }

    pub(crate) const fn role(&self) -> EvmSignerRoleV1 {
        self.role
    }

    pub(crate) const fn session_id(&self) -> Digest32 {
        self.session_id
    }

    pub(crate) const fn signer_account(&self) -> [u8; 20] {
        self.signer_account
    }

    pub(crate) fn binds_local_owner(&self, owner_id: Digest32) -> bool {
        self.owner_id == owner_id
    }

    pub(crate) fn binds_contracts_owner(
        &self,
        route_id: Digest32,
        session_id: Digest32,
        requester_id: Digest32,
        signer_id: Digest32,
    ) -> bool {
        self.route_id == route_id
            && self.session_id == session_id
            && self.requester_id == requester_id
            && self.signer_id == signer_id
    }

    /// Builds the only public request that this authority accepts later.
    ///
    /// `owner_epoch` is the current durable route fencing generation.  It is
    /// part of both the action id and the wire payload, so takeover creates a
    /// different request instead of silently adopting a prior owner's answer.
    pub(crate) fn request(
        &self,
        materialization: &ProductionChildMaterializationRequestV1,
        unsigned_call_digest: Digest32,
        owner_epoch: u64,
    ) -> Result<ProductionEvmRemoteRequestV1, ChildAuthorityRefusalV1> {
        self.validate_materialization(materialization)?;
        if unsigned_call_digest == ZERO_DIGEST
            || owner_epoch == 0
            || owner_epoch != materialization.fencing_epoch
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let execution_plan_digest = execution_plan_digest(materialization, self)?;
        let action_id = remote_action_id(
            materialization,
            self.role,
            self.owner_id,
            owner_epoch,
            execution_plan_digest,
            unsigned_call_digest,
        )?;
        let payload = EvmActionRequestPayloadV1::new(EvmActionRequestInputV1 {
            action: transport_action(materialization.action),
            role: transport_role(self.role),
            owner_epoch,
            evm_chain_id: self.chain_id,
            action_id,
            route_id: self.route_id,
            settlement_id: self.settlement_id,
            composition_binding_digest: self.composition_digest,
            execution_plan_digest,
            unsigned_call_digest,
            owner_id: self.owner_id,
            requester_id: self.requester_id,
            signer_id: self.signer_id,
            contract: self.contract,
            signer_account: self.signer_account,
        })
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        Ok(ProductionEvmRemoteRequestV1 {
            payload,
            terms_digest: self.terms_digest,
            registry_digest: self.registry_digest,
            profile_digest: self.profile_digest,
            deployment_digest: self.deployment_digest,
            session_id: self.session_id,
        })
    }

    /// Consumes a Store-minted one-shot import and converts it to the actuator
    /// types only after every route/session/terms/chain/account/role binding is
    /// rechecked.  Raw bytes move directly into a zeroizing actuator value.
    pub(crate) fn authenticate_import(
        &self,
        request: &ProductionEvmRemoteRequestV1,
        prepared: PreparedEvmSignedActionImportV1,
    ) -> Result<ProductionEvmRemoteImportV1, ChildAuthorityRefusalV1> {
        let payload_bytes = request.payload.to_bytes();
        if prepared.session_id() != &self.session_id
            || prepared.action_id() != request.payload.action_id()
            || prepared.owner_id() != request.payload.owner_id()
            || prepared.owner_epoch() != request.payload.owner_epoch()
            || prepared.request_payload() != &payload_bytes
            || prepared.request_message_digest() == &ZERO_DIGEST
            || prepared.response_message_digest() == &ZERO_DIGEST
            || prepared.transaction_hash() == &ZERO_DIGEST
            || prepared.signed_raw_digest() == &ZERO_DIGEST
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let request_message_digest = *prepared.request_message_digest();
        let response_message_digest = *prepared.response_message_digest();
        let signed_raw_digest = *prepared.signed_raw_digest();
        let transaction_hash = *prepared.transaction_hash();
        let remote_request = self.authenticate_request(request, request_message_digest)?;
        let signed = RemoteEvmSignedActionV1::new(
            request_message_digest,
            signed_raw_digest,
            transaction_hash,
            prepared.into_signed_raw_transaction(),
        )
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        Ok(ProductionEvmRemoteImportV1 {
            request: remote_request,
            signed,
            response_message_digest,
            session_id: self.session_id,
            terms_digest: self.terms_digest,
        })
    }

    /// Reconstructs the exact public actuator request from a durably accepted
    /// `0x15` digest.  This is deliberately independent from the move-only
    /// `0x16` import grant: after a crash the child port can reacquire the same
    /// route/action custody and audit an already imported operation without
    /// asking the Contracts Store to release raw transaction bytes again.
    pub(crate) fn authenticate_request(
        &self,
        request: &ProductionEvmRemoteRequestV1,
        request_message_digest: Digest32,
    ) -> Result<RemoteEvmActionRequestV1, ChildAuthorityRefusalV1> {
        request.validate_against(self)?;
        if request_message_digest == ZERO_DIGEST {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        RemoteEvmActionRequestV1::new(RemoteEvmActionRequestInputV1 {
            kind: operation_kind(request.payload.action()),
            role: self.role,
            owner_id: self.owner_id,
            owner_epoch: request.payload.owner_epoch(),
            action_id: *request.payload.action_id(),
            route_id: self.route_id,
            settlement_id: self.settlement_id,
            composition_binding_digest: self.composition_digest,
            execution_plan_digest: *request.payload.execution_plan_digest(),
            unsigned_call_digest: *request.payload.unsigned_call_digest(),
            request_message_digest,
            requester_id: self.requester_id,
            signer_id: self.signer_id,
            chain_id: self.chain_id,
            contract: self.contract,
            signer_account: self.signer_account,
        })
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)
    }

    /// Rebuilds the public restart/takeover proof for a coordinator dispatch.
    ///
    /// Private signer/requester/owner pins never escape this boundary.  The
    /// actuator receives only the exact independently authenticated fields it
    /// needs to cross the coordinator plan against its durable operation and
    /// remote-custody rows.
    pub(crate) fn custody_resume_input_from_dispatch(
        &self,
        request: &ChildDispatchRequestV1,
    ) -> Result<RemoteEvmOperationCustodyResumeInputV1, ChildAuthorityRefusalV1> {
        self.custody_resume_input(CoordinatorResumePinsV1 {
            route_id: request.route_id(),
            effect_id: request.effect_id(),
            settlement_id: request.settlement_id(),
            semantic_digest: request.semantic_digest(),
            terms_digest: request.terms_digest(),
            registry_digest: request.registry_digest(),
            profile_digest: request.profile_digest(),
            deployment_digest: request.deployment_digest(),
            owner_epoch: request.route_fencing_epoch(),
            face: request.face(),
            action: request.action(),
            operation_id: request.custody_digest(),
            transaction_hash: request.expected_transaction_id(),
        })
    }

    /// Observation counterpart of [`Self::custody_resume_input_from_dispatch`].
    pub(crate) fn custody_resume_input_from_observation(
        &self,
        request: &ChildObservationRequestV1,
    ) -> Result<RemoteEvmOperationCustodyResumeInputV1, ChildAuthorityRefusalV1> {
        self.custody_resume_input(CoordinatorResumePinsV1 {
            route_id: request.route_id,
            effect_id: request.effect_id,
            settlement_id: request.settlement_id,
            semantic_digest: request.semantic_digest,
            terms_digest: request.terms_digest,
            registry_digest: request.registry_digest,
            profile_digest: request.profile_digest,
            deployment_digest: request.deployment_digest,
            owner_epoch: request.route_fencing_epoch,
            face: request.face,
            action: request.action,
            operation_id: request.custody_digest,
            transaction_hash: request.transaction_id,
        })
    }

    fn custody_resume_input(
        &self,
        pins: CoordinatorResumePinsV1,
    ) -> Result<RemoteEvmOperationCustodyResumeInputV1, ChildAuthorityRefusalV1> {
        let (kind, role) = operation_for_settlement_action(pins.action);
        if pins.face != SettlementFaceV1::Evm
            || role != self.role
            || pins.route_id != self.route_id
            || pins.settlement_id != self.settlement_id
            || pins.terms_digest != self.terms_digest
            || pins.registry_digest != self.registry_digest
            || pins.profile_digest != self.profile_digest
            || pins.deployment_digest != self.deployment_digest
            || pins.owner_epoch == 0
            || [
                pins.effect_id,
                pins.semantic_digest,
                pins.operation_id,
                pins.transaction_hash,
            ]
            .contains(&ZERO_DIGEST)
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(RemoteEvmOperationCustodyResumeInputV1 {
            operation_id: pins.operation_id,
            owner_id: self.owner_id,
            owner_epoch: pins.owner_epoch,
            route_id: pins.route_id,
            settlement_id: pins.settlement_id,
            composition_binding_digest: self.composition_digest,
            effect_id: pins.effect_id,
            semantic_digest: pins.semantic_digest,
            terms_digest: pins.terms_digest,
            registry_digest: pins.registry_digest,
            profile_digest: pins.profile_digest,
            deployment_digest: pins.deployment_digest,
            kind,
            role,
            chain_id: self.chain_id,
            contract: self.contract,
            signer_account: self.signer_account,
            transaction_hash: pins.transaction_hash,
        })
    }

    fn validate_materialization(
        &self,
        request: &ProductionChildMaterializationRequestV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let expected_role = role_for_action(request.action);
        if request.route_id != self.route_id
            || request.settlement_id != self.settlement_id
            || request.terms_digest != self.terms_digest
            || request.registry_digest != self.registry_digest
            || request.profile_digest != self.profile_digest
            || request.deployment_digest != self.deployment_digest
            || request.composition_digest != self.composition_digest
            || request.fencing_epoch == 0
            || expected_role != self.role
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }
}

/// Exact 0x15 request plus the commitments that are explicit in the outer
/// Contracts/actuator scope rather than duplicated in the fixed wire body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionEvmRemoteRequestV1 {
    payload: EvmActionRequestPayloadV1,
    terms_digest: Digest32,
    registry_digest: Digest32,
    profile_digest: Digest32,
    deployment_digest: Digest32,
    session_id: Digest32,
}

impl ProductionEvmRemoteRequestV1 {
    pub(crate) const fn session_id(&self) -> Digest32 {
        self.session_id
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) const fn action_id(&self) -> Digest32 {
        *self.payload.action_id()
    }

    pub(crate) const fn payload(&self) -> EvmActionRequestPayloadV1 {
        self.payload
    }

    pub(crate) fn payload_bytes(
        &self,
    ) -> [u8; dom_scriptless_transport::EVM_ACTION_REQUEST_PAYLOAD_LEN_V1] {
        self.payload.to_bytes()
    }

    fn validate_against(
        &self,
        binding: &ProductionEvmRemoteSignerBindingV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        if self.session_id != binding.session_id
            || self.terms_digest != binding.terms_digest
            || self.registry_digest != binding.registry_digest
            || self.profile_digest != binding.profile_digest
            || self.deployment_digest != binding.deployment_digest
            || self.payload.route_id() != &binding.route_id
            || self.payload.settlement_id() != &binding.settlement_id
            || self.payload.composition_binding_digest() != &binding.composition_digest
            || self.payload.owner_id() != &binding.owner_id
            || self.payload.requester_id() != &binding.requester_id
            || self.payload.signer_id() != &binding.signer_id
            || self.payload.evm_chain_id() != binding.chain_id
            || self.payload.contract() != &binding.contract
            || self.payload.signer_account() != &binding.signer_account
            || self.payload.role() != transport_role(binding.role)
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }
}

/// Move-only handoff into `DurableEvmActuatorV1` remote-custody APIs.
pub(crate) struct ProductionEvmRemoteImportV1 {
    request: RemoteEvmActionRequestV1,
    signed: RemoteEvmSignedActionV1,
    response_message_digest: Digest32,
    session_id: Digest32,
    terms_digest: Digest32,
}

impl core::fmt::Debug for ProductionEvmRemoteImportV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionEvmRemoteImportV1([signed transaction redacted])")
    }
}

impl ProductionEvmRemoteImportV1 {
    pub(crate) fn into_parts(self) -> (RemoteEvmActionRequestV1, RemoteEvmSignedActionV1) {
        (self.request, self.signed)
    }

    pub(crate) const fn response_message_digest(&self) -> Digest32 {
        self.response_message_digest
    }

    pub(crate) const fn session_id(&self) -> Digest32 {
        self.session_id
    }

    pub(crate) const fn terms_digest(&self) -> Digest32 {
        self.terms_digest
    }
}

fn execution_plan_digest(
    request: &ProductionChildMaterializationRequestV1,
    binding: &ProductionEvmRemoteSignerBindingV1,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let action = [settlement_action_tag(request.action)];
    let leg = [settlement_leg_tag(request.leg)];
    let exposure = [child_exposure_tag(request.exposure)];
    digest_parts(
        REMOTE_EXECUTION_PLAN_DOMAIN_V1,
        &[
            &request.route_id,
            &request.effect_id,
            &request.settlement_id,
            &binding.session_id,
            &action,
            &leg,
            &request.fencing_epoch.to_be_bytes(),
            &request.semantic_digest,
            &request.terms_digest,
            &request.registry_digest,
            &request.profile_digest,
            &request.deployment_digest,
            &request.route_scope_digest,
            &request.composition_digest,
            &request.role_plan_digest,
            &request.source_scope_digest,
            &exposure,
            &binding.chain_id.to_be_bytes(),
            &binding.contract,
            &binding.signer_account,
            &[signer_role_tag(binding.role)],
            &binding.requester_id,
            &binding.signer_id,
            &binding.owner_id,
        ],
    )
}

fn remote_action_id(
    request: &ProductionChildMaterializationRequestV1,
    role: EvmSignerRoleV1,
    owner_id: Digest32,
    owner_epoch: u64,
    execution_plan_digest: Digest32,
    unsigned_call_digest: Digest32,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let action = [settlement_action_tag(request.action)];
    let role = [signer_role_tag(role)];
    digest_parts(
        REMOTE_ACTION_ID_DOMAIN_V1,
        &[
            &request.route_id,
            &request.settlement_id,
            &request.effect_id,
            &action,
            &role,
            &owner_id,
            &owner_epoch.to_be_bytes(),
            &execution_plan_digest,
            &unsigned_call_digest,
        ],
    )
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut digest = ZERO_DIGEST;
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
    if digest == ZERO_DIGEST {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(digest)
}

const fn role_for_action(action: SettlementActionV1) -> EvmSignerRoleV1 {
    match action {
        SettlementActionV1::Funding | SettlementActionV1::Refund => EvmSignerRoleV1::Funder,
        SettlementActionV1::Claim => EvmSignerRoleV1::Beneficiary,
    }
}

const fn operation_for_settlement_action(
    action: SettlementActionV1,
) -> (EvmOperationKindV1, EvmSignerRoleV1) {
    match action {
        SettlementActionV1::Funding => (EvmOperationKindV1::Open, EvmSignerRoleV1::Funder),
        SettlementActionV1::Claim => (EvmOperationKindV1::Claim, EvmSignerRoleV1::Beneficiary),
        SettlementActionV1::Refund => (EvmOperationKindV1::Refund, EvmSignerRoleV1::Funder),
    }
}

const fn operation_kind(action: TransportActionV1) -> EvmOperationKindV1 {
    match action {
        TransportActionV1::Funding => EvmOperationKindV1::Open,
        TransportActionV1::Claim => EvmOperationKindV1::Claim,
        TransportActionV1::Refund => EvmOperationKindV1::Refund,
    }
}

const fn transport_action(action: SettlementActionV1) -> TransportActionV1 {
    match action {
        SettlementActionV1::Funding => TransportActionV1::Funding,
        SettlementActionV1::Claim => TransportActionV1::Claim,
        SettlementActionV1::Refund => TransportActionV1::Refund,
    }
}

const fn transport_role(role: EvmSignerRoleV1) -> TransportSignerRoleV1 {
    match role {
        EvmSignerRoleV1::Funder => TransportSignerRoleV1::Funder,
        EvmSignerRoleV1::Beneficiary => TransportSignerRoleV1::Beneficiary,
    }
}

const fn settlement_action_tag(action: SettlementActionV1) -> u8 {
    match action {
        SettlementActionV1::Funding => 1,
        SettlementActionV1::Claim => 2,
        SettlementActionV1::Refund => 3,
    }
}

const fn signer_role_tag(role: EvmSignerRoleV1) -> u8 {
    match role {
        EvmSignerRoleV1::Funder => 1,
        EvmSignerRoleV1::Beneficiary => 2,
    }
}

const fn settlement_leg_tag(leg: SettlementLegV1) -> u8 {
    match leg {
        SettlementLegV1::Upstream => 1,
        SettlementLegV1::Downstream => 2,
    }
}

const fn child_exposure_tag(exposure: settlement_coordinator::ChildExposureV1) -> u8 {
    match exposure {
        settlement_coordinator::ChildExposureV1::NonSecret => 1,
        settlement_coordinator::ChildExposureV1::FirstSecretExposure => 2,
        settlement_coordinator::ChildExposureV1::UsesPublicSecret => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use settlement_coordinator::ChildExposureV1;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(ProductionEvmRemoteImportV1: Clone, Copy);

    fn binding(role: EvmSignerRoleV1) -> ProductionEvmRemoteSignerBindingV1 {
        ProductionEvmRemoteSignerBindingV1::new(ProductionEvmRemoteSignerPinsV1 {
            route_id: [1; 32],
            session_id: [2; 32],
            settlement_id: [3; 32],
            terms_digest: [4; 32],
            registry_digest: [5; 32],
            profile_digest: [6; 32],
            deployment_digest: [7; 32],
            composition_digest: [8; 32],
            chain_id: 11_155_111,
            contract: [9; 20],
            signer_account: [10; 20],
            role,
            requester_id: [11; 32],
            signer_id: [12; 32],
            owner_id: [13; 32],
        })
        .expect("valid binding")
    }

    fn request(action: SettlementActionV1) -> ProductionChildMaterializationRequestV1 {
        ProductionChildMaterializationRequestV1 {
            route_id: [1; 32],
            effect_id: [14; 32],
            settlement_id: [3; 32],
            leg: SettlementLegV1::Upstream,
            action,
            fencing_epoch: 17,
            semantic_digest: [15; 32],
            terms_digest: [4; 32],
            registry_digest: [5; 32],
            profile_digest: [6; 32],
            deployment_digest: [7; 32],
            route_scope_digest: [16; 32],
            composition_digest: [8; 32],
            role_plan_digest: [17; 32],
            source_scope_digest: [18; 32],
            exposure: ChildExposureV1::NonSecret,
        }
    }

    #[test]
    fn request_pins_route_session_terms_chain_account_role_and_owner() {
        let authority = binding(EvmSignerRoleV1::Funder);
        let prepared = authority
            .request(&request(SettlementActionV1::Funding), [19; 32], 17)
            .expect("request");
        let payload = prepared.payload();
        assert_eq!(prepared.session_id(), [2; 32]);
        assert_eq!(payload.route_id(), &[1; 32]);
        assert_eq!(payload.settlement_id(), &[3; 32]);
        assert_eq!(payload.evm_chain_id(), 11_155_111);
        assert_eq!(payload.contract(), &[9; 20]);
        assert_eq!(payload.signer_account(), &[10; 20]);
        assert_eq!(payload.role(), TransportSignerRoleV1::Funder);
        assert_eq!(payload.owner_id(), &[13; 32]);
        assert_eq!(payload.owner_epoch(), 17);
        assert_eq!(
            EvmActionRequestPayloadV1::decode_exact(&prepared.payload_bytes())
                .expect("canonical request"),
            payload
        );
    }

    #[test]
    fn accepted_request_digest_rehydrates_exact_actuator_scope_after_restart() {
        let authority = binding(EvmSignerRoleV1::Funder);
        let request = authority
            .request(&request(SettlementActionV1::Funding), [19; 32], 17)
            .expect("request");
        let first = authority
            .authenticate_request(&request, [20; 32])
            .expect("first custody request");
        let resumed = authority
            .authenticate_request(&request, [20; 32])
            .expect("restart custody request");
        assert_eq!(first, resumed);
        assert_eq!(first.action_id(), request.action_id());
        assert_eq!(first.route_id(), [1; 32]);
        assert_eq!(first.request_message_digest(), [20; 32]);
        assert_eq!(first.signer_account(), [10; 20]);
        assert_eq!(first.unsigned_call_digest(), [19; 32]);
        assert_eq!(
            authority.authenticate_request(&request, ZERO_DIGEST),
            Err(ChildAuthorityRefusalV1::Conflict)
        );

        let other_authority = binding(EvmSignerRoleV1::Beneficiary);
        assert_eq!(
            other_authority.authenticate_request(&request, [20; 32]),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
    }

    #[test]
    fn every_scope_transplant_changes_or_refuses_the_request() {
        let authority = binding(EvmSignerRoleV1::Funder);
        let original = request(SettlementActionV1::Funding);
        let expected = authority.request(&original, [19; 32], 17).expect("request");
        for mutated in [
            ProductionChildMaterializationRequestV1 {
                route_id: [20; 32],
                ..original
            },
            ProductionChildMaterializationRequestV1 {
                settlement_id: [20; 32],
                ..original
            },
            ProductionChildMaterializationRequestV1 {
                terms_digest: [20; 32],
                ..original
            },
            ProductionChildMaterializationRequestV1 {
                registry_digest: [20; 32],
                ..original
            },
            ProductionChildMaterializationRequestV1 {
                profile_digest: [20; 32],
                ..original
            },
            ProductionChildMaterializationRequestV1 {
                deployment_digest: [20; 32],
                ..original
            },
            ProductionChildMaterializationRequestV1 {
                composition_digest: [20; 32],
                ..original
            },
        ] {
            assert_eq!(
                authority.request(&mutated, [19; 32], 17),
                Err(ChildAuthorityRefusalV1::Conflict)
            );
        }
        let mut changed = original;
        changed.semantic_digest = [20; 32];
        assert_ne!(
            authority.request(&changed, [19; 32], 17).expect("rebound"),
            expected
        );
        assert_eq!(
            authority.request(&original, [19; 32], 18),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
        assert_eq!(
            authority.request(&original, ZERO_DIGEST, 17),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
        assert_eq!(
            authority.request(&request(SettlementActionV1::Claim), [19; 32], 17),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
    }

    #[test]
    fn restart_resume_rebinds_exact_owner_epoch_operation_and_transaction() {
        let authority = binding(EvmSignerRoleV1::Funder);
        let pins = CoordinatorResumePinsV1 {
            route_id: [1; 32],
            effect_id: [14; 32],
            settlement_id: [3; 32],
            semantic_digest: [15; 32],
            terms_digest: [4; 32],
            registry_digest: [5; 32],
            profile_digest: [6; 32],
            deployment_digest: [7; 32],
            owner_epoch: 17,
            face: SettlementFaceV1::Evm,
            action: SettlementActionV1::Funding,
            operation_id: [21; 32],
            transaction_hash: [22; 32],
        };
        let resumed = authority.custody_resume_input(pins).expect("resume");
        assert_eq!(resumed.operation_id, [21; 32]);
        assert_eq!(resumed.owner_id, [13; 32]);
        assert_eq!(resumed.owner_epoch, 17);
        assert_eq!(resumed.route_id, [1; 32]);
        assert_eq!(resumed.settlement_id, [3; 32]);
        assert_eq!(resumed.composition_binding_digest, [8; 32]);
        assert_eq!(resumed.effect_id, [14; 32]);
        assert_eq!(resumed.semantic_digest, [15; 32]);
        assert_eq!(resumed.kind, EvmOperationKindV1::Open);
        assert_eq!(resumed.role, EvmSignerRoleV1::Funder);
        assert_eq!(resumed.chain_id, 11_155_111);
        assert_eq!(resumed.contract, [9; 20]);
        assert_eq!(resumed.signer_account, [10; 20]);
        assert_eq!(resumed.transaction_hash, [22; 32]);
        assert!(authority.binds_local_owner([13; 32]));
        assert!(!authority.binds_local_owner([23; 32]));
    }

    #[test]
    fn restart_resume_refuses_role_owner_epoch_and_plan_transplants() {
        let authority = binding(EvmSignerRoleV1::Funder);
        let pins = CoordinatorResumePinsV1 {
            route_id: [1; 32],
            effect_id: [14; 32],
            settlement_id: [3; 32],
            semantic_digest: [15; 32],
            terms_digest: [4; 32],
            registry_digest: [5; 32],
            profile_digest: [6; 32],
            deployment_digest: [7; 32],
            owner_epoch: 17,
            face: SettlementFaceV1::Evm,
            action: SettlementActionV1::Funding,
            operation_id: [21; 32],
            transaction_hash: [22; 32],
        };
        for mutated in [
            CoordinatorResumePinsV1 {
                action: SettlementActionV1::Claim,
                ..pins
            },
            CoordinatorResumePinsV1 {
                owner_epoch: 0,
                ..pins
            },
            CoordinatorResumePinsV1 {
                route_id: [23; 32],
                ..pins
            },
            CoordinatorResumePinsV1 {
                operation_id: ZERO_DIGEST,
                ..pins
            },
            CoordinatorResumePinsV1 {
                transaction_hash: ZERO_DIGEST,
                ..pins
            },
        ] {
            assert_eq!(
                authority.custody_resume_input(mutated),
                Err(ChildAuthorityRefusalV1::Conflict)
            );
        }
    }

    #[test]
    fn binding_refuses_zero_duplicate_participant_and_zero_account() {
        let base = ProductionEvmRemoteSignerPinsV1 {
            route_id: [1; 32],
            session_id: [2; 32],
            settlement_id: [3; 32],
            terms_digest: [4; 32],
            registry_digest: [5; 32],
            profile_digest: [6; 32],
            deployment_digest: [7; 32],
            composition_digest: [8; 32],
            chain_id: 1,
            contract: [9; 20],
            signer_account: [10; 20],
            role: EvmSignerRoleV1::Beneficiary,
            requester_id: [11; 32],
            signer_id: [12; 32],
            owner_id: [13; 32],
        };
        assert_eq!(
            ProductionEvmRemoteSignerBindingV1::new(ProductionEvmRemoteSignerPinsV1 {
                signer_id: base.requester_id,
                ..base
            }),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
        assert_eq!(
            ProductionEvmRemoteSignerBindingV1::new(ProductionEvmRemoteSignerPinsV1 {
                signer_account: ZERO_ADDRESS,
                ..base
            }),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
    }
}
