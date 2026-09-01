//! Canonical authenticated transport for DOM Scriptless Contracts.
//!
//! This crate implements the exact `ScriptlessMessageV1` (`DSC1`) envelope
//! from Master Specification section 8, including per-message allocation
//! limits, canonical length checks, DOM-native Schnorr authentication,
//! transcript advancement, replay/equivocation handling, and byte-identical
//! duplicate acknowledgement. It also supplies a real encrypted stream using
//! Noise XX. Noise keys are distinct from spending and transport-identity
//! signing keys; their public keys must be frozen in the negotiated session
//! terms before this channel is opened.
//!
//! No secret signing share, Bulletproof nonce, adaptor secret, or wallet seed
//! is owned by this crate. The only long-lived secret it can hold is an
//! X25519 Noise transport key. Application messages remain independently
//! authenticated by the participant's dedicated DOM Schnorr identity key.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use dom_adaptor::{DirectionV1, SigningPhaseV1};
use dom_crypto::{
    blake2b_256_tagged, schnorr_sign, schnorr_verify, PublicKey, SchnorrSignature, SecretKey,
};
use dom_scriptless_protocol::{ParticipantSetV1, PARTICIPANT_COUNT};
use dom_scriptless_store::SessionPhaseV1;
use rand_core::OsRng;
use snow::{params::NoiseParams, Builder, HandshakeState, TransportState};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read, Write};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Magic prefix of every canonical off-chain message.
pub const MESSAGE_MAGIC_V1: [u8; 4] = *b"DSC1";

/// Canonical envelope version.
pub const MESSAGE_VERSION_V1: u16 = 1;

/// Fixed bytes before the variable payload.
pub const UNSIGNED_PREFIX_LEN_V1: usize = 148;

/// Canonical DOM Schnorr signature length.
pub const IDENTITY_SIGNATURE_LEN_V1: usize = 65;

/// Fixed bytes including the signature, excluding the payload.
pub const MESSAGE_FIXED_LEN_V1: usize = UNSIGNED_PREFIX_LEN_V1 + IDENTITY_SIGNATURE_LEN_V1;

/// Global payload ceiling from Master section 8.1.
pub const GLOBAL_PAYLOAD_CAP_V1: usize = 1024 * 1024;

/// Exact byte length of the typed V1 Abort payload.
pub const ABORT_PAYLOAD_LEN_V1: usize = 32;

/// Exact byte length of a typed EVM action request (`0x15`).
pub const EVM_ACTION_REQUEST_PAYLOAD_LEN_V1: usize = 352;

/// Maximum exact signed EIP-1559 transaction retained in an EVM action
/// response (`0x16`).
pub const EVM_SIGNED_ACTION_RAW_MAX_LEN_V1: usize = 8 * 1024;

/// Fixed bytes before the variable signed transaction in an EVM action
/// response (`0x16`).
pub const EVM_SIGNED_ACTION_PAYLOAD_PREFIX_LEN_V1: usize = 452;

/// Largest accepted canonical message.
pub const MAX_MESSAGE_LEN_V1: usize = MESSAGE_FIXED_LEN_V1 + GLOBAL_PAYLOAD_CAP_V1;

/// Maximum accepted messages retained for byte-identical duplicate handling.
pub const MAX_ACCEPTED_MESSAGES_V1: usize = 256;

const MESSAGE_DIGEST_TAG_V1: &str = "DOM:scriptless-message:v1";
const TRANSCRIPT_TAG_V1: &str = "DOM:scriptless-transcript:v1";
const NOISE_PATTERN_V1: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const NOISE_PROLOGUE_PREFIX_V1: &[u8] = b"DOM:scriptless-noise:v1";
const MAX_NOISE_PLAINTEXT: usize = 65_519;
const NOISE_TAG_LEN: usize = 16;
const MAX_NOISE_HANDSHAKE_FRAME: usize = 65_535;

/// Closed Master section 8.3 message registry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum MessageTypeV1 {
    /// Initial offer.
    Offer = 0x01,
    /// Offer acceptance.
    Accept = 0x02,
    /// Commitment-share commitment.
    ShareCommit = 0x03,
    /// Commitment-share reveal and proof.
    ShareReveal = 0x04,
    /// Collaborative-proof common entropy commitment.
    BpCommonCommit = 0x05,
    /// Collaborative-proof common entropy reveal.
    BpCommonReveal = 0x06,
    /// Collaborative-proof round commitment.
    BpRoundCommit = 0x07,
    /// Collaborative-proof round-one share.
    BpRound1 = 0x08,
    /// Collaborative-proof round-two share.
    BpRound2 = 0x09,
    /// Final collaborative proof.
    BpFinal = 0x0a,
    /// Exact transaction-template commitment.
    TxTemplateCommit = 0x0b,
    /// Signing nonce commitment.
    SigNonceCommit = 0x0c,
    /// Signing nonce reveal.
    SigNonceReveal = 0x0d,
    /// Verified partial signature.
    PartialSignature = 0x0e,
    /// Adaptor pre-signature.
    AdaptorPreSignature = 0x0f,
    /// Fully signed refund transaction.
    FinalRefund = 0x10,
    /// Durable bilateral ready-to-fund acknowledgement.
    ReadyToFund = 0x11,
    /// Final claim transaction.
    FinalClaim = 0x12,
    /// Typed abort.
    Abort = 0x13,
    /// Idempotent acknowledgement.
    Ack = 0x14,
    /// Public request for a role-scoped counterparty EVM signature.
    EvmActionRequest = 0x15,
    /// Exact role-scoped signed EVM transaction answering `0x15`.
    EvmSignedAction = 0x16,
}

impl MessageTypeV1 {
    /// Per-type payload ceiling from Master section 8.3.
    #[must_use]
    pub const fn payload_cap(self) -> usize {
        match self {
            Self::Offer | Self::Accept => 8 * 1024,
            Self::ShareCommit
            | Self::BpCommonCommit
            | Self::BpCommonReveal
            | Self::BpRoundCommit
            | Self::SigNonceCommit
            | Self::ReadyToFund
            | Self::Ack => 4 * 1024,
            Self::Abort => ABORT_PAYLOAD_LEN_V1,
            Self::ShareReveal
            | Self::BpRound1
            | Self::BpRound2
            | Self::TxTemplateCommit
            | Self::SigNonceReveal
            | Self::PartialSignature
            | Self::AdaptorPreSignature => 8 * 1024,
            Self::BpFinal => 16 * 1024,
            Self::FinalRefund | Self::FinalClaim => 512 * 1024,
            Self::EvmActionRequest => EVM_ACTION_REQUEST_PAYLOAD_LEN_V1,
            Self::EvmSignedAction => {
                EVM_SIGNED_ACTION_PAYLOAD_PREFIX_LEN_V1 + EVM_SIGNED_ACTION_RAW_MAX_LEN_V1
            }
        }
    }

    fn accepts_phase(self, phase: SessionPhaseV1) -> bool {
        match self {
            Self::Offer => phase == SessionPhaseV1::Created,
            Self::Accept => phase == SessionPhaseV1::TermsCommitted,
            Self::ShareCommit => phase == SessionPhaseV1::SharesCommitted,
            Self::ShareReveal => phase == SessionPhaseV1::SharesRevealed,
            Self::BpCommonCommit => phase == SessionPhaseV1::BpCommonCommitted,
            Self::BpCommonReveal => phase == SessionPhaseV1::BpCommonEstablished,
            Self::BpRoundCommit => phase == SessionPhaseV1::BpNonceCommitted,
            Self::BpRound1 => phase == SessionPhaseV1::BpRound1Complete,
            Self::BpRound2 => phase == SessionPhaseV1::BpRound2Complete,
            Self::BpFinal => phase == SessionPhaseV1::OutputFinalized,
            Self::TxTemplateCommit => phase == SessionPhaseV1::TemplatesCommitted,
            Self::SigNonceCommit | Self::SigNonceReveal | Self::PartialSignature => {
                matches!(
                    phase,
                    SessionPhaseV1::RefundSigning
                        | SessionPhaseV1::ClaimSigning
                        | SessionPhaseV1::FundingAuthorized
                )
            }
            Self::AdaptorPreSignature => phase == SessionPhaseV1::ClaimPrepared,
            Self::FinalRefund => phase == SessionPhaseV1::RefundSigned,
            Self::ReadyToFund => matches!(
                phase,
                SessionPhaseV1::ClaimPrepared | SessionPhaseV1::FundingAuthorized
            ),
            Self::FinalClaim => phase == SessionPhaseV1::ClaimBroadcast,
            Self::Abort => phase == SessionPhaseV1::Aborted,
            Self::Ack => true,
            Self::EvmActionRequest | Self::EvmSignedAction => matches!(
                phase,
                SessionPhaseV1::RefundSigned
                    | SessionPhaseV1::FundingAuthorized
                    | SessionPhaseV1::FundingBroadcast
                    | SessionPhaseV1::FundingConfirmed
                    | SessionPhaseV1::ClaimBroadcast
                    | SessionPhaseV1::RefundEligible
                    | SessionPhaseV1::RefundBroadcast
            ),
        }
    }
}

/// Closed EVM action registry carried by DSC1 `0x15` and `0x16`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EvmActionKindV1 {
    /// Publish the exact frozen funding call.
    Funding = 1,
    /// Publish the exact frozen conditional claim call.
    Claim = 2,
    /// Publish the exact frozen timeout refund call.
    Refund = 3,
}

impl TryFrom<u8> for EvmActionKindV1 {
    type Error = TransportError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Funding),
            2 => Ok(Self::Claim),
            3 => Ok(Self::Refund),
            _ => Err(TransportError::InvalidTypedPayload),
        }
    }
}

/// Role whose independently retained EVM key may answer an action request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EvmSignerRoleV1 {
    /// Funder role, used only by funding and refund actions.
    Funder = 1,
    /// Beneficiary role, used only by claim actions.
    Beneficiary = 2,
}

impl TryFrom<u8> for EvmSignerRoleV1 {
    type Error = TransportError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Funder),
            2 => Ok(Self::Beneficiary),
            _ => Err(TransportError::InvalidTypedPayload),
        }
    }
}

fn require_evm_action_role(
    action: EvmActionKindV1,
    role: EvmSignerRoleV1,
) -> Result<(), TransportError> {
    if matches!(
        (action, role),
        (
            EvmActionKindV1::Funding | EvmActionKindV1::Refund,
            EvmSignerRoleV1::Funder
        ) | (EvmActionKindV1::Claim, EvmSignerRoleV1::Beneficiary)
    ) {
        Ok(())
    } else {
        Err(TransportError::InvalidTypedPayload)
    }
}

/// Canonical public `0x15` request for one counterparty EVM signature.
///
/// This payload contains only public identifiers, accounts, and commitments.
/// In particular it has no field capable of carrying an unsigned/raw
/// transaction, adaptor scalar, wallet secret, or signing key. It is a
/// request, not an execution authority; the remote role-scoped signer must
/// independently reconstruct and authorize the committed plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmActionRequestPayloadV1 {
    action: EvmActionKindV1,
    role: EvmSignerRoleV1,
    owner_epoch: u64,
    evm_chain_id: u64,
    action_id: [u8; 32],
    route_id: [u8; 32],
    settlement_id: [u8; 32],
    composition_binding_digest: [u8; 32],
    execution_plan_digest: [u8; 32],
    unsigned_call_digest: [u8; 32],
    owner_id: [u8; 32],
    requester_id: [u8; 32],
    signer_id: [u8; 32],
    contract: [u8; 20],
    signer_account: [u8; 20],
}

impl EvmActionRequestPayloadV1 {
    /// Construct an exact public request, rejecting empty bindings and a role
    /// that cannot authorize the selected action.
    pub fn new(input: EvmActionRequestInputV1) -> Result<Self, TransportError> {
        require_evm_action_role(input.action, input.role)?;
        if input.owner_epoch == 0
            || input.evm_chain_id == 0
            || input.action_id == [0; 32]
            || input.route_id == [0; 32]
            || input.settlement_id == [0; 32]
            || input.composition_binding_digest == [0; 32]
            || input.execution_plan_digest == [0; 32]
            || input.unsigned_call_digest == [0; 32]
            || input.owner_id == [0; 32]
            || input.requester_id == [0; 32]
            || input.signer_id == [0; 32]
            || input.contract == [0; 20]
            || input.signer_account == [0; 20]
            || input.requester_id == input.signer_id
        {
            return Err(TransportError::InvalidTypedPayload);
        }
        Ok(Self {
            action: input.action,
            role: input.role,
            owner_epoch: input.owner_epoch,
            evm_chain_id: input.evm_chain_id,
            action_id: input.action_id,
            route_id: input.route_id,
            settlement_id: input.settlement_id,
            composition_binding_digest: input.composition_binding_digest,
            execution_plan_digest: input.execution_plan_digest,
            unsigned_call_digest: input.unsigned_call_digest,
            owner_id: input.owner_id,
            requester_id: input.requester_id,
            signer_id: input.signer_id,
            contract: input.contract,
            signer_account: input.signer_account,
        })
    }

    /// Decode the complete payload without accepting extensions.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() != EVM_ACTION_REQUEST_PAYLOAD_LEN_V1 || &bytes[..4] != b"EVRQ" {
            return Err(TransportError::NonCanonicalLength);
        }
        if read_u16(&bytes[4..6])? != 1 {
            return Err(TransportError::UnsupportedVersion);
        }
        Self::new(EvmActionRequestInputV1 {
            action: EvmActionKindV1::try_from(bytes[6])?,
            role: EvmSignerRoleV1::try_from(bytes[7])?,
            owner_epoch: read_u64(&bytes[8..16])?,
            evm_chain_id: read_u64(&bytes[16..24])?,
            action_id: array_32(&bytes[24..56])?,
            route_id: array_32(&bytes[56..88])?,
            settlement_id: array_32(&bytes[88..120])?,
            composition_binding_digest: array_32(&bytes[120..152])?,
            execution_plan_digest: array_32(&bytes[152..184])?,
            unsigned_call_digest: array_32(&bytes[184..216])?,
            owner_id: array_32(&bytes[216..248])?,
            requester_id: array_32(&bytes[248..280])?,
            signer_id: array_32(&bytes[280..312])?,
            contract: bytes[312..332]
                .try_into()
                .map_err(|_| TransportError::NonCanonicalLength)?,
            signer_account: bytes[332..352]
                .try_into()
                .map_err(|_| TransportError::NonCanonicalLength)?,
        })
    }

    /// Encode the exact canonical wire payload.
    #[must_use]
    pub fn to_bytes(self) -> [u8; EVM_ACTION_REQUEST_PAYLOAD_LEN_V1] {
        let mut bytes = [0; EVM_ACTION_REQUEST_PAYLOAD_LEN_V1];
        bytes[..4].copy_from_slice(b"EVRQ");
        bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
        bytes[6] = self.action as u8;
        bytes[7] = self.role as u8;
        bytes[8..16].copy_from_slice(&self.owner_epoch.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.evm_chain_id.to_le_bytes());
        for (range, value) in [
            (24..56, self.action_id),
            (56..88, self.route_id),
            (88..120, self.settlement_id),
            (120..152, self.composition_binding_digest),
            (152..184, self.execution_plan_digest),
            (184..216, self.unsigned_call_digest),
            (216..248, self.owner_id),
            (248..280, self.requester_id),
            (280..312, self.signer_id),
        ] {
            bytes[range].copy_from_slice(&value);
        }
        bytes[312..332].copy_from_slice(&self.contract);
        bytes[332..352].copy_from_slice(&self.signer_account);
        bytes
    }

    /// Requested action.
    pub const fn action(&self) -> EvmActionKindV1 {
        self.action
    }
    /// Required signer role.
    pub const fn role(&self) -> EvmSignerRoleV1 {
        self.role
    }
    /// Durable owner epoch.
    pub const fn owner_epoch(&self) -> u64 {
        self.owner_epoch
    }
    /// EVM chain identifier.
    pub const fn evm_chain_id(&self) -> u64 {
        self.evm_chain_id
    }
    /// Stable action identifier.
    pub const fn action_id(&self) -> &[u8; 32] {
        &self.action_id
    }
    /// Route identifier.
    pub const fn route_id(&self) -> &[u8; 32] {
        &self.route_id
    }
    /// Settlement identifier.
    pub const fn settlement_id(&self) -> &[u8; 32] {
        &self.settlement_id
    }
    /// Composition binding.
    pub const fn composition_binding_digest(&self) -> &[u8; 32] {
        &self.composition_binding_digest
    }
    /// Frozen execution-plan commitment.
    pub const fn execution_plan_digest(&self) -> &[u8; 32] {
        &self.execution_plan_digest
    }
    /// Frozen unsigned-call commitment.
    pub const fn unsigned_call_digest(&self) -> &[u8; 32] {
        &self.unsigned_call_digest
    }
    /// Durable owner identifier.
    pub const fn owner_id(&self) -> &[u8; 32] {
        &self.owner_id
    }
    /// Requesting DSC1 participant.
    pub const fn requester_id(&self) -> &[u8; 32] {
        &self.requester_id
    }
    /// Requested signing participant.
    pub const fn signer_id(&self) -> &[u8; 32] {
        &self.signer_id
    }
    /// Frozen settlement contract.
    pub const fn contract(&self) -> &[u8; 20] {
        &self.contract
    }
    /// Frozen expected signer account.
    pub const fn signer_account(&self) -> &[u8; 20] {
        &self.signer_account
    }
}

/// Inputs for one canonical EVM action request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmActionRequestInputV1 {
    /// Requested action.
    pub action: EvmActionKindV1,
    /// Required signer role.
    pub role: EvmSignerRoleV1,
    /// Non-zero owner epoch.
    pub owner_epoch: u64,
    /// Non-zero EVM chain identifier.
    pub evm_chain_id: u64,
    /// Stable action identifier.
    pub action_id: [u8; 32],
    /// Route identifier.
    pub route_id: [u8; 32],
    /// Settlement identifier.
    pub settlement_id: [u8; 32],
    /// Composition binding.
    pub composition_binding_digest: [u8; 32],
    /// Frozen execution-plan commitment.
    pub execution_plan_digest: [u8; 32],
    /// Frozen unsigned-call commitment.
    pub unsigned_call_digest: [u8; 32],
    /// Durable owner identifier.
    pub owner_id: [u8; 32],
    /// Requesting DSC1 participant.
    pub requester_id: [u8; 32],
    /// Requested signing participant.
    pub signer_id: [u8; 32],
    /// Frozen settlement contract.
    pub contract: [u8; 20],
    /// Frozen expected signer account.
    pub signer_account: [u8; 20],
}

/// Canonical public `0x16` answer containing one exact signed EVM
/// transaction.
///
/// The response repeats every request binding, including owner epoch and both
/// participants, and additionally binds the exact DSC1 digest of `0x15`.
/// Therefore signed bytes cannot be transplanted to another request, route,
/// settlement, owner epoch, role, account, or execution plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmSignedActionPayloadV1 {
    request: EvmActionRequestPayloadV1,
    request_message_digest: [u8; 32],
    signed_raw_digest: [u8; 32],
    transaction_hash: [u8; 32],
    signed_raw_transaction: Vec<u8>,
}

impl EvmSignedActionPayloadV1 {
    /// Bind exact signed transaction bytes to one accepted request.
    pub fn new(
        request: EvmActionRequestPayloadV1,
        request_message_digest: [u8; 32],
        transaction_hash: [u8; 32],
        signed_raw_transaction: Vec<u8>,
    ) -> Result<Self, TransportError> {
        if request_message_digest == [0; 32]
            || transaction_hash == [0; 32]
            || signed_raw_transaction.is_empty()
            || signed_raw_transaction.len() > EVM_SIGNED_ACTION_RAW_MAX_LEN_V1
        {
            return Err(TransportError::InvalidTypedPayload);
        }
        let signed_raw_digest =
            *blake2b_256_tagged("DOM:evm-signed-action-raw:v1", &signed_raw_transaction).as_bytes();
        Ok(Self {
            request,
            request_message_digest,
            signed_raw_digest,
            transaction_hash,
            signed_raw_transaction,
        })
    }

    /// Decode the complete payload, recomputing the exact raw-byte digest.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < EVM_SIGNED_ACTION_PAYLOAD_PREFIX_LEN_V1
            || bytes.len()
                > EVM_SIGNED_ACTION_PAYLOAD_PREFIX_LEN_V1 + EVM_SIGNED_ACTION_RAW_MAX_LEN_V1
            || &bytes[..4] != b"EVRS"
        {
            return Err(TransportError::NonCanonicalLength);
        }
        if read_u16(&bytes[4..6])? != 1 {
            return Err(TransportError::UnsupportedVersion);
        }
        let request = EvmActionRequestPayloadV1::new(EvmActionRequestInputV1 {
            action: EvmActionKindV1::try_from(bytes[6])?,
            role: EvmSignerRoleV1::try_from(bytes[7])?,
            owner_epoch: read_u64(&bytes[8..16])?,
            evm_chain_id: read_u64(&bytes[16..24])?,
            action_id: array_32(&bytes[24..56])?,
            route_id: array_32(&bytes[56..88])?,
            settlement_id: array_32(&bytes[88..120])?,
            composition_binding_digest: array_32(&bytes[120..152])?,
            execution_plan_digest: array_32(&bytes[152..184])?,
            unsigned_call_digest: array_32(&bytes[184..216])?,
            owner_id: array_32(&bytes[216..248])?,
            requester_id: array_32(&bytes[248..280])?,
            signer_id: array_32(&bytes[280..312])?,
            contract: bytes[312..332]
                .try_into()
                .map_err(|_| TransportError::NonCanonicalLength)?,
            signer_account: bytes[332..352]
                .try_into()
                .map_err(|_| TransportError::NonCanonicalLength)?,
        })?;
        let request_message_digest = array_32(&bytes[352..384])?;
        let retained_raw_digest = array_32(&bytes[384..416])?;
        let transaction_hash = array_32(&bytes[416..448])?;
        let raw_len = usize::try_from(read_u32(&bytes[448..452])?)
            .map_err(|_| TransportError::LengthOverflow)?;
        let expected = EVM_SIGNED_ACTION_PAYLOAD_PREFIX_LEN_V1
            .checked_add(raw_len)
            .ok_or(TransportError::LengthOverflow)?;
        if expected != bytes.len() {
            return Err(TransportError::NonCanonicalLength);
        }
        let response = Self::new(
            request,
            request_message_digest,
            transaction_hash,
            bytes[EVM_SIGNED_ACTION_PAYLOAD_PREFIX_LEN_V1..].to_vec(),
        )?;
        if response.signed_raw_digest != retained_raw_digest {
            return Err(TransportError::InvalidTypedPayload);
        }
        Ok(response)
    }

    /// Encode exact canonical bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TransportError> {
        let raw_len = u32::try_from(self.signed_raw_transaction.len())
            .map_err(|_| TransportError::LengthOverflow)?;
        let total = EVM_SIGNED_ACTION_PAYLOAD_PREFIX_LEN_V1
            .checked_add(self.signed_raw_transaction.len())
            .ok_or(TransportError::LengthOverflow)?;
        let mut bytes = vec![0; total];
        bytes[..4].copy_from_slice(b"EVRS");
        bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
        let request_bytes = self.request.to_bytes();
        bytes[6..352].copy_from_slice(&request_bytes[6..]);
        bytes[352..384].copy_from_slice(&self.request_message_digest);
        bytes[384..416].copy_from_slice(&self.signed_raw_digest);
        bytes[416..448].copy_from_slice(&self.transaction_hash);
        bytes[448..452].copy_from_slice(&raw_len.to_le_bytes());
        bytes[452..].copy_from_slice(&self.signed_raw_transaction);
        Ok(bytes)
    }

    /// Request this response answers exactly.
    pub const fn request(&self) -> &EvmActionRequestPayloadV1 {
        &self.request
    }
    /// Exact DSC1 digest of the accepted request.
    pub const fn request_message_digest(&self) -> &[u8; 32] {
        &self.request_message_digest
    }
    /// Digest of the exact signed raw transaction.
    pub const fn signed_raw_digest(&self) -> &[u8; 32] {
        &self.signed_raw_digest
    }
    /// Signed EVM transaction hash asserted by the responder.
    pub const fn transaction_hash(&self) -> &[u8; 32] {
        &self.transaction_hash
    }
    /// Exact signed EVM transaction bytes.
    pub fn signed_raw_transaction(&self) -> &[u8] {
        &self.signed_raw_transaction
    }
}

/// Canonical public payload for a V1 [`MessageTypeV1::Abort`] message.
///
/// The single field is a non-zero digest that binds the cooperative abort to
/// its higher-layer durable decision or evidence. It is deliberately not a
/// free-form reason string and must not contain secret material. The `DSC1`
/// envelope separately binds the exact chain, session, sender, sequence and
/// predecessor transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbortPayloadV1 {
    binding_digest: [u8; ABORT_PAYLOAD_LEN_V1],
}

impl AbortPayloadV1 {
    /// Construct an Abort payload from its non-zero application binding.
    pub fn new(binding_digest: [u8; ABORT_PAYLOAD_LEN_V1]) -> Result<Self, TransportError> {
        if binding_digest == [0; ABORT_PAYLOAD_LEN_V1] {
            return Err(TransportError::ZeroPayloadCommitment);
        }
        Ok(Self { binding_digest })
    }

    /// Decode the complete type-owned payload without accepting extensions.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() != ABORT_PAYLOAD_LEN_V1 {
            return Err(TransportError::NonCanonicalLength);
        }
        let mut binding_digest = [0; ABORT_PAYLOAD_LEN_V1];
        binding_digest.copy_from_slice(bytes);
        Self::new(binding_digest)
    }

    /// Non-zero digest binding this Abort to its higher-layer authority.
    #[must_use]
    pub const fn binding_digest(&self) -> &[u8; ABORT_PAYLOAD_LEN_V1] {
        &self.binding_digest
    }

    /// Consume the typed payload and return its exact wire bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; ABORT_PAYLOAD_LEN_V1] {
        self.binding_digest
    }
}

impl TryFrom<u8> for MessageTypeV1 {
    type Error = TransportError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => Self::Offer,
            0x02 => Self::Accept,
            0x03 => Self::ShareCommit,
            0x04 => Self::ShareReveal,
            0x05 => Self::BpCommonCommit,
            0x06 => Self::BpCommonReveal,
            0x07 => Self::BpRoundCommit,
            0x08 => Self::BpRound1,
            0x09 => Self::BpRound2,
            0x0a => Self::BpFinal,
            0x0b => Self::TxTemplateCommit,
            0x0c => Self::SigNonceCommit,
            0x0d => Self::SigNonceReveal,
            0x0e => Self::PartialSignature,
            0x0f => Self::AdaptorPreSignature,
            0x10 => Self::FinalRefund,
            0x11 => Self::ReadyToFund,
            0x12 => Self::FinalClaim,
            0x13 => Self::Abort,
            0x14 => Self::Ack,
            0x15 => Self::EvmActionRequest,
            0x16 => Self::EvmSignedAction,
            _ => return Err(TransportError::UnknownMessageType),
        })
    }
}

/// Failure at the canonical message or encrypted channel boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TransportError {
    /// Fewer bytes than the fixed envelope requires.
    UnexpectedEof,
    /// Envelope magic is not `DSC1`.
    BadMagic,
    /// Envelope version is not V1.
    UnsupportedVersion,
    /// Flags contain a bit unknown to V1.
    UnknownFlags,
    /// Message type is outside the closed registry.
    UnknownMessageType,
    /// Payload exceeds its type-specific limit.
    PayloadTooLarge,
    /// Length arithmetic overflowed.
    LengthOverflow,
    /// The exact canonical length did not match.
    NonCanonicalLength,
    /// A required identifier was all zero.
    ZeroIdentifier,
    /// A required type-owned payload commitment was all zero.
    ZeroPayloadCommitment,
    /// A typed payload contains an invalid discriminator, empty binding, or
    /// inconsistent exact-byte commitment.
    InvalidTypedPayload,
    /// Chain or session context differs from the receiver.
    ContextMismatch,
    /// Sender is not in the frozen two-party roster.
    UnknownSender,
    /// Sender identity signature was malformed or invalid.
    AuthenticationFailed,
    /// The previous transcript hash forks from accepted state.
    ForkedTranscript,
    /// A future sequence left a gap.
    SequenceGap,
    /// An unknown old sequence was replayed.
    Replay,
    /// Different bytes reused one `(session, sender, sequence)` key.
    Equivocation,
    /// Message type is invalid for the proposed accepted phase.
    PhaseMismatch,
    /// Phase movement is absent from the closed topology.
    InvalidTransition,
    /// Receiver retained-state bound was exhausted.
    CapacityExceeded,
    /// Noise key material was malformed.
    InvalidNoiseKey,
    /// Noise handshake did not authenticate the frozen peer key.
    NoisePeerMismatch,
    /// Noise state machine rejected a handshake or transport record.
    NoiseFailure,
    /// Underlying stream failed.
    IoFailure,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnexpectedEof => "message is shorter than the canonical envelope",
            Self::BadMagic => "message magic is not DSC1",
            Self::UnsupportedVersion => "message version is unsupported",
            Self::UnknownFlags => "message flags are not canonical",
            Self::UnknownMessageType => "message type is outside the V1 registry",
            Self::PayloadTooLarge => "message payload exceeds its registered bound",
            Self::LengthOverflow => "message length overflow",
            Self::NonCanonicalLength => "message length is not canonical",
            Self::ZeroIdentifier => "a required identifier is zero",
            Self::ZeroPayloadCommitment => "a required payload commitment is zero",
            Self::InvalidTypedPayload => "a typed payload is not canonical",
            Self::ContextMismatch => "message chain or session context differs",
            Self::UnknownSender => "message sender is not in the session roster",
            Self::AuthenticationFailed => "message authentication failed",
            Self::ForkedTranscript => "message forks the accepted transcript",
            Self::SequenceGap => "message sequence has a gap",
            Self::Replay => "message is an unknown replay",
            Self::Equivocation => "different bytes reuse one logical message key",
            Self::PhaseMismatch => "message type does not match the accepted phase",
            Self::InvalidTransition => "phase transition is not canonical",
            Self::CapacityExceeded => "bounded receiver capacity is exhausted",
            Self::InvalidNoiseKey => "Noise key is malformed",
            Self::NoisePeerMismatch => "Noise peer key differs from frozen session terms",
            Self::NoiseFailure => "Noise state machine refused the operation",
            Self::IoFailure => "transport stream failed",
        })
    }
}

impl std::error::Error for TransportError {}

/// Canonical unsigned fields supplied before identity signing.
#[derive(Clone, Eq, PartialEq)]
pub struct UnsignedMessageV1 {
    kind: MessageTypeV1,
    chain_id: [u8; 32],
    session_id: [u8; 32],
    sender_id: [u8; 32],
    sequence: u64,
    previous_transcript_hash: [u8; 32],
    payload: Vec<u8>,
}

impl UnsignedMessageV1 {
    /// Validate bounded fields and construct an unsigned message.
    pub fn new(
        kind: MessageTypeV1,
        chain_id: [u8; 32],
        session_id: [u8; 32],
        sender_id: [u8; 32],
        sequence: u64,
        previous_transcript_hash: [u8; 32],
        payload: Vec<u8>,
    ) -> Result<Self, TransportError> {
        if chain_id == [0; 32] || session_id == [0; 32] || sender_id == [0; 32] {
            return Err(TransportError::ZeroIdentifier);
        }
        if payload.len() > kind.payload_cap() || payload.len() > GLOBAL_PAYLOAD_CAP_V1 {
            return Err(TransportError::PayloadTooLarge);
        }
        validate_registered_payload(kind, &payload)?;
        Ok(Self {
            kind,
            chain_id,
            session_id,
            sender_id,
            sequence,
            previous_transcript_hash,
            payload,
        })
    }

    /// Construct a typed V1 Abort message without accepting raw payload bytes.
    pub fn new_abort(
        chain_id: [u8; 32],
        session_id: [u8; 32],
        sender_id: [u8; 32],
        sequence: u64,
        previous_transcript_hash: [u8; 32],
        payload: AbortPayloadV1,
    ) -> Result<Self, TransportError> {
        Self::new(
            MessageTypeV1::Abort,
            chain_id,
            session_id,
            sender_id,
            sequence,
            previous_transcript_hash,
            payload.into_bytes().to_vec(),
        )
    }

    /// Construct a typed EVM action-request envelope.
    pub fn new_evm_action_request(
        chain_id: [u8; 32],
        session_id: [u8; 32],
        sender_id: [u8; 32],
        sequence: u64,
        previous_transcript_hash: [u8; 32],
        payload: EvmActionRequestPayloadV1,
    ) -> Result<Self, TransportError> {
        Self::new(
            MessageTypeV1::EvmActionRequest,
            chain_id,
            session_id,
            sender_id,
            sequence,
            previous_transcript_hash,
            payload.to_bytes().to_vec(),
        )
    }

    /// Construct a typed EVM signed-action response envelope.
    pub fn new_evm_signed_action(
        chain_id: [u8; 32],
        session_id: [u8; 32],
        sender_id: [u8; 32],
        sequence: u64,
        previous_transcript_hash: [u8; 32],
        payload: &EvmSignedActionPayloadV1,
    ) -> Result<Self, TransportError> {
        Self::new(
            MessageTypeV1::EvmSignedAction,
            chain_id,
            session_id,
            sender_id,
            sequence,
            previous_transcript_hash,
            payload.to_bytes()?,
        )
    }

    /// Registered message type.
    #[must_use]
    pub const fn kind(&self) -> MessageTypeV1 {
        self.kind
    }

    /// Canonical chain identifier.
    #[must_use]
    pub const fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }

    /// Canonical session identifier.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Canonical sender identifier.
    #[must_use]
    pub const fn sender_id(&self) -> &[u8; 32] {
        &self.sender_id
    }

    /// Monotonic sender-local sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Transcript accepted immediately before this message.
    #[must_use]
    pub const fn previous_transcript_hash(&self) -> &[u8; 32] {
        &self.previous_transcript_hash
    }

    /// Exact type-owned payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn encode(&self) -> Result<Vec<u8>, TransportError> {
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| TransportError::LengthOverflow)?;
        let total = UNSIGNED_PREFIX_LEN_V1
            .checked_add(self.payload.len())
            .ok_or(TransportError::LengthOverflow)?;
        let mut bytes = vec![0; total];
        bytes[..4].copy_from_slice(&MESSAGE_MAGIC_V1);
        bytes[4..6].copy_from_slice(&MESSAGE_VERSION_V1.to_le_bytes());
        bytes[6] = self.kind as u8;
        bytes[7] = 0;
        bytes[8..40].copy_from_slice(&self.chain_id);
        bytes[40..72].copy_from_slice(&self.session_id);
        bytes[72..104].copy_from_slice(&self.sender_id);
        bytes[104..112].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[112..144].copy_from_slice(&self.previous_transcript_hash);
        bytes[144..148].copy_from_slice(&payload_len.to_le_bytes());
        bytes[148..].copy_from_slice(&self.payload);
        Ok(bytes)
    }
}

/// Structurally canonical, identity-signed `DSC1` message.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedMessageV1 {
    unsigned: UnsignedMessageV1,
    signature: [u8; IDENTITY_SIGNATURE_LEN_V1],
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl SignedMessageV1 {
    /// Sign exact unsigned bytes with a dedicated transport-identity key.
    ///
    /// The key must be distinct from all spending shares and protocol nonces.
    /// DOM's canonical Schnorr implementation owns nonce generation,
    /// challenge framing, scalar encoding, and verification.
    pub fn sign(
        message: UnsignedMessageV1,
        identity_key: &SecretKey,
    ) -> Result<Self, TransportError> {
        let unsigned = message.encode()?;
        let digest = message_digest(&unsigned);
        let signature = schnorr_sign(identity_key, &digest, message.chain_id())
            .map_err(|_| TransportError::AuthenticationFailed)?
            .to_bytes();
        let total = unsigned
            .len()
            .checked_add(IDENTITY_SIGNATURE_LEN_V1)
            .ok_or(TransportError::LengthOverflow)?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&unsigned);
        bytes.extend_from_slice(&signature);
        Ok(Self {
            unsigned: message,
            signature,
            bytes,
            digest,
        })
    }

    /// Parse exact bytes and enforce framing and allocation bounds.
    ///
    /// This does not authenticate the sender. Call [`Self::verify_identity`]
    /// with the roster-owned public key before accepting the message.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < MESSAGE_FIXED_LEN_V1 {
            return Err(TransportError::UnexpectedEof);
        }
        if bytes[..4] != MESSAGE_MAGIC_V1 {
            return Err(TransportError::BadMagic);
        }
        if read_u16(&bytes[4..6])? != MESSAGE_VERSION_V1 {
            return Err(TransportError::UnsupportedVersion);
        }
        if bytes[7] != 0 {
            return Err(TransportError::UnknownFlags);
        }
        let kind = MessageTypeV1::try_from(bytes[6])?;
        let payload_len = usize::try_from(read_u32(&bytes[144..148])?)
            .map_err(|_| TransportError::LengthOverflow)?;
        if payload_len > kind.payload_cap() || payload_len > GLOBAL_PAYLOAD_CAP_V1 {
            return Err(TransportError::PayloadTooLarge);
        }
        let expected = MESSAGE_FIXED_LEN_V1
            .checked_add(payload_len)
            .ok_or(TransportError::LengthOverflow)?;
        if bytes.len() != expected {
            return Err(TransportError::NonCanonicalLength);
        }
        let chain_id = array_32(&bytes[8..40])?;
        let session_id = array_32(&bytes[40..72])?;
        let sender_id = array_32(&bytes[72..104])?;
        if chain_id == [0; 32] || session_id == [0; 32] || sender_id == [0; 32] {
            return Err(TransportError::ZeroIdentifier);
        }
        let sequence = read_u64(&bytes[104..112])?;
        let previous_transcript_hash = array_32(&bytes[112..144])?;
        let unsigned_len = UNSIGNED_PREFIX_LEN_V1 + payload_len;
        let payload = &bytes[UNSIGNED_PREFIX_LEN_V1..unsigned_len];
        validate_registered_payload(kind, payload)?;
        let mut signature = [0; IDENTITY_SIGNATURE_LEN_V1];
        signature.copy_from_slice(&bytes[unsigned_len..]);
        let digest = message_digest(&bytes[..unsigned_len]);
        Ok(Self {
            unsigned: UnsignedMessageV1 {
                kind,
                chain_id,
                session_id,
                sender_id,
                sequence,
                previous_transcript_hash,
                payload: payload.to_vec(),
            },
            signature,
            bytes: bytes.to_vec(),
            digest,
        })
    }

    /// Verify the canonical DOM Schnorr identity signature.
    pub fn verify_identity(&self, identity_key: &PublicKey) -> Result<(), TransportError> {
        let signature = SchnorrSignature::from_bytes(&self.signature)
            .map_err(|_| TransportError::AuthenticationFailed)?;
        match schnorr_verify(
            &signature,
            identity_key,
            self.unsigned.chain_id(),
            &self.digest,
        ) {
            Ok(true) => Ok(()),
            _ => Err(TransportError::AuthenticationFailed),
        }
    }

    /// Parsed unsigned fields.
    #[must_use]
    pub const fn unsigned(&self) -> &UnsignedMessageV1 {
        &self.unsigned
    }

    /// Exact canonical bytes, retained for byte-identical resend.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// DOM-tagged digest of the exact unsigned bytes.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// One roster participant's transport-authentication material.
#[derive(Clone, Eq, PartialEq)]
pub struct TransportParticipantV1 {
    participant_id: [u8; 32],
    identity_key: PublicKey,
    direction: DirectionV1,
}

impl TransportParticipantV1 {
    /// Bind a participant ID to its dedicated identity key and stable role.
    pub fn new(
        participant_id: [u8; 32],
        identity_key: PublicKey,
        direction: DirectionV1,
    ) -> Result<Self, TransportError> {
        if participant_id == [0; 32] {
            return Err(TransportError::ZeroIdentifier);
        }
        Ok(Self {
            participant_id,
            identity_key,
            direction,
        })
    }

    /// Participant identifier.
    #[must_use]
    pub const fn participant_id(&self) -> &[u8; 32] {
        &self.participant_id
    }
}

/// Accepted-message receipt returned identically for an exact duplicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptanceReceiptV1 {
    /// Accepted message digest.
    pub message_digest: [u8; 32],
    /// Transcript after accepting the message.
    pub transcript_hash: [u8; 32],
    /// Sender-local sequence.
    pub sequence: u64,
    /// Message registry type.
    pub kind: MessageTypeV1,
    /// Whether this call was a byte-identical redelivery.
    pub duplicate: bool,
}

#[derive(Clone)]
struct AcceptedMessageV1 {
    bytes: Vec<u8>,
    receipt: AcceptanceReceiptV1,
}

/// Bounded, authenticated, fail-closed receiver for one frozen session.
pub struct SessionReceiverV1 {
    chain_id: [u8; 32],
    session_id: [u8; 32],
    participants: [TransportParticipantV1; PARTICIPANT_COUNT],
    phase: SessionPhaseV1,
    transcript_hash: [u8; 32],
    next_sequence: BTreeMap<[u8; 32], u64>,
    accepted: BTreeMap<([u8; 32], u64), AcceptedMessageV1>,
    failed_closed: bool,
}

impl SessionReceiverV1 {
    /// Create a receiver for exactly two distinct participants.
    pub fn new(
        chain_id: [u8; 32],
        session_id: [u8; 32],
        participants: [TransportParticipantV1; PARTICIPANT_COUNT],
        phase: SessionPhaseV1,
        transcript_hash: [u8; 32],
    ) -> Result<Self, TransportError> {
        if chain_id == [0; 32] || session_id == [0; 32] {
            return Err(TransportError::ZeroIdentifier);
        }
        ParticipantSetV1::new(&[
            *participants[0].participant_id(),
            *participants[1].participant_id(),
        ])
        .map_err(|_| TransportError::UnknownSender)?;
        if participants[0].direction == participants[1].direction
            || participants[0].identity_key == participants[1].identity_key
        {
            return Err(TransportError::UnknownSender);
        }
        let mut next_sequence = BTreeMap::new();
        next_sequence.insert(*participants[0].participant_id(), 0);
        next_sequence.insert(*participants[1].participant_id(), 0);
        Ok(Self {
            chain_id,
            session_id,
            participants,
            phase,
            transcript_hash,
            next_sequence,
            accepted: BTreeMap::new(),
            failed_closed: false,
        })
    }

    /// Decode, authenticate, order, and accept one exact message.
    ///
    /// A repeated byte string returns the original receipt without repeating
    /// effects. Different bytes under the same logical key permanently fail
    /// this receiver closed. The caller supplies the phase that its validated
    /// protocol preconditions would enter; the closed phase topology and the
    /// message registry are both checked here before transcript advancement.
    pub fn accept(
        &mut self,
        bytes: &[u8],
        accepted_phase: SessionPhaseV1,
    ) -> Result<AcceptanceReceiptV1, TransportError> {
        if self.failed_closed {
            return Err(TransportError::Equivocation);
        }
        let message = SignedMessageV1::decode_exact(bytes)?;
        if message.unsigned.chain_id != self.chain_id
            || message.unsigned.session_id != self.session_id
        {
            return Err(TransportError::ContextMismatch);
        }
        let logical_key = (message.unsigned.sender_id, message.unsigned.sequence);
        if let Some(previous) = self.accepted.get(&logical_key) {
            if previous.bytes == bytes {
                let mut receipt = previous.receipt;
                receipt.duplicate = true;
                return Ok(receipt);
            }
            self.failed_closed = true;
            self.phase = SessionPhaseV1::FailedClosed;
            return Err(TransportError::Equivocation);
        }
        let participant = self
            .participants
            .iter()
            .find(|candidate| candidate.participant_id == message.unsigned.sender_id)
            .ok_or(TransportError::UnknownSender)?;
        let expected_sequence = self
            .next_sequence
            .get(&message.unsigned.sender_id)
            .copied()
            .ok_or(TransportError::UnknownSender)?;
        if message.unsigned.sequence < expected_sequence {
            return Err(TransportError::Replay);
        }
        if message.unsigned.sequence > expected_sequence {
            return Err(TransportError::SequenceGap);
        }
        if message.unsigned.previous_transcript_hash != self.transcript_hash {
            return Err(TransportError::ForkedTranscript);
        }
        if !message.unsigned.kind.accepts_phase(accepted_phase) {
            return Err(TransportError::PhaseMismatch);
        }
        if !valid_phase_movement(self.phase, accepted_phase, message.unsigned.kind) {
            return Err(TransportError::InvalidTransition);
        }
        message.verify_identity(&participant.identity_key)?;
        if self.accepted.len() >= MAX_ACCEPTED_MESSAGES_V1 {
            return Err(TransportError::CapacityExceeded);
        }
        let transcript_hash = advance_transcript(
            &self.transcript_hash,
            message.digest(),
            participant.direction,
            message.unsigned.kind,
            accepted_phase,
        );
        let next = expected_sequence
            .checked_add(1)
            .ok_or(TransportError::CapacityExceeded)?;
        self.next_sequence.insert(message.unsigned.sender_id, next);
        self.transcript_hash = transcript_hash;
        self.phase = accepted_phase;
        let receipt = AcceptanceReceiptV1 {
            message_digest: *message.digest(),
            transcript_hash,
            sequence: message.unsigned.sequence,
            kind: message.unsigned.kind,
            duplicate: false,
        };
        self.accepted.insert(
            logical_key,
            AcceptedMessageV1 {
                bytes: bytes.to_vec(),
                receipt,
            },
        );
        Ok(receipt)
    }

    /// Current accepted transcript hash.
    #[must_use]
    pub const fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }

    /// Current monotonic phase.
    #[must_use]
    pub const fn phase(&self) -> SessionPhaseV1 {
        self.phase
    }

    /// Whether equivocation permanently failed the receiver closed.
    #[must_use]
    pub const fn is_failed_closed(&self) -> bool {
        self.failed_closed
    }
}

fn valid_phase_movement(
    current: SessionPhaseV1,
    next: SessionPhaseV1,
    kind: MessageTypeV1,
) -> bool {
    if kind == MessageTypeV1::Ack {
        return next == current;
    }
    if matches!(
        kind,
        MessageTypeV1::EvmActionRequest | MessageTypeV1::EvmSignedAction
    ) {
        return next == current;
    }
    if kind == MessageTypeV1::Abort {
        return abort_is_strictly_pre_funding(current) && next == SessionPhaseV1::Aborted;
    }
    next == current || dom_scriptless_protocol::is_normative_edge(current, next)
}

const fn abort_is_strictly_pre_funding(phase: SessionPhaseV1) -> bool {
    matches!(
        phase,
        SessionPhaseV1::Created
            | SessionPhaseV1::TermsCommitted
            | SessionPhaseV1::SharesCommitted
            | SessionPhaseV1::SharesRevealed
            | SessionPhaseV1::BpCommonCommitted
            | SessionPhaseV1::BpCommonEstablished
            | SessionPhaseV1::BpNonceCommitted
            | SessionPhaseV1::BpRound1Complete
            | SessionPhaseV1::BpRound2Complete
            | SessionPhaseV1::OutputFinalized
            | SessionPhaseV1::TemplatesCommitted
            | SessionPhaseV1::RefundSigning
            | SessionPhaseV1::RefundSigned
            | SessionPhaseV1::ClaimSigning
            | SessionPhaseV1::ClaimPrepared
    )
}

fn message_digest(unsigned: &[u8]) -> [u8; 32] {
    *blake2b_256_tagged(MESSAGE_DIGEST_TAG_V1, unsigned).as_bytes()
}

fn validate_registered_payload(kind: MessageTypeV1, payload: &[u8]) -> Result<(), TransportError> {
    match kind {
        MessageTypeV1::Abort => {
            AbortPayloadV1::decode_exact(payload)?;
        }
        MessageTypeV1::EvmActionRequest => {
            EvmActionRequestPayloadV1::decode_exact(payload)?;
        }
        MessageTypeV1::EvmSignedAction => {
            EvmSignedActionPayloadV1::decode_exact(payload)?;
        }
        _ => {}
    }
    Ok(())
}

fn advance_transcript(
    previous: &[u8; 32],
    digest: &[u8; 32],
    direction: DirectionV1,
    kind: MessageTypeV1,
    phase: SessionPhaseV1,
) -> [u8; 32] {
    if kind == MessageTypeV1::Ack {
        return *previous;
    }
    let mut body = [0; 67];
    body[..32].copy_from_slice(previous);
    body[32..64].copy_from_slice(digest);
    body[64] = direction.to_byte();
    let accepted_phase = match kind {
        MessageTypeV1::SigNonceCommit => SigningPhaseV1::SigNonceCommit.to_le_bytes(),
        MessageTypeV1::SigNonceReveal => SigningPhaseV1::SigNonceReveal.to_le_bytes(),
        MessageTypeV1::PartialSignature => SigningPhaseV1::SigPartial.to_le_bytes(),
        MessageTypeV1::AdaptorPreSignature => SigningPhaseV1::SigAdapt.to_le_bytes(),
        _ => (phase as u16).to_le_bytes(),
    };
    body[65..].copy_from_slice(&accepted_phase);
    *blake2b_256_tagged(TRANSCRIPT_TAG_V1, &body).as_bytes()
}

/// Persistent Noise XX static key used only for transport encryption.
///
/// The value intentionally implements neither `Clone` nor `Debug`. Store its
/// private bytes only in the independent DOM Contracts application keystore;
/// session databases should retain the public key and an opaque Contracts
/// keystore reference. It must never share the DOM Wallet keystore or database.
pub struct NoiseStaticKeyV1 {
    secret: StaticSecret,
    public: [u8; 32],
}

impl NoiseStaticKeyV1 {
    /// Draw a new X25519 static key from the operating-system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// Restore a transport key from protected keystore bytes.
    ///
    /// Zero is rejected. This import is for persistence/restart only; protocol
    /// callers must not derive this key from a wallet seed, spending share, or
    /// deterministic session data.
    pub fn from_keystore_bytes(bytes: Zeroizing<[u8; 32]>) -> Result<Self, TransportError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(TransportError::InvalidNoiseKey);
        }
        let secret = StaticSecret::from(*bytes);
        let public = X25519PublicKey::from(&secret).to_bytes();
        Ok(Self { secret, public })
    }

    /// Public X25519 key that must be frozen in the session transport terms.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    fn private_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }
}

/// Role in the Noise XX handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoiseRoleV1 {
    /// Sends the first Noise handshake record.
    Initiator,
    /// Receives the first Noise handshake record.
    Responder,
}

/// Frozen parameters for one encrypted session channel.
pub struct NoiseSessionConfigV1<'a> {
    /// Handshake role.
    pub role: NoiseRoleV1,
    /// Canonical chain identifier.
    pub chain_id: [u8; 32],
    /// Canonical Scriptless session identifier.
    pub session_id: [u8; 32],
    /// Local independent Contracts-keystore-owned Noise static key.
    pub local_static: &'a NoiseStaticKeyV1,
    /// Peer Noise static public key frozen in negotiated terms.
    pub expected_remote_static: [u8; 32],
}

/// Encrypted, ordered, chunked application stream after authenticated Noise XX.
pub struct EncryptedTransportV1<S> {
    stream: S,
    noise: TransportState,
}

impl<S: Read + Write> EncryptedTransportV1<S> {
    /// Complete Noise XX and require the peer static key frozen in terms.
    pub fn establish(stream: S, config: NoiseSessionConfigV1<'_>) -> Result<Self, TransportError> {
        if config.chain_id == [0; 32]
            || config.session_id == [0; 32]
            || config.expected_remote_static == [0; 32]
        {
            return Err(TransportError::InvalidNoiseKey);
        }
        let params: NoiseParams = NOISE_PATTERN_V1
            .parse()
            .map_err(|_| TransportError::NoiseFailure)?;
        let private = config.local_static.private_bytes();
        let prologue = noise_prologue(&config.chain_id, &config.session_id);
        let builder = Builder::new(params)
            .local_private_key(private.as_ref())
            .prologue(&prologue);
        let handshake = match config.role {
            NoiseRoleV1::Initiator => builder.build_initiator(),
            NoiseRoleV1::Responder => builder.build_responder(),
        }
        .map_err(|_| TransportError::NoiseFailure)?;
        let (stream, handshake) = run_noise_handshake(stream, handshake, config.role)?;
        let remote = handshake
            .get_remote_static()
            .ok_or(TransportError::NoisePeerMismatch)?;
        if remote != config.expected_remote_static {
            return Err(TransportError::NoisePeerMismatch);
        }
        let noise = handshake
            .into_transport_mode()
            .map_err(|_| TransportError::NoiseFailure)?;
        Ok(Self { stream, noise })
    }

    /// Encrypt and send one complete canonical application message.
    ///
    /// Large final transaction messages are split into Noise records while
    /// retaining one application-message boundary. Noise owns per-record
    /// nonces and rejects replay/reorder cryptographically.
    pub fn send_message(&mut self, message: &[u8]) -> Result<(), TransportError> {
        if message.is_empty() || message.len() > MAX_MESSAGE_LEN_V1 {
            return Err(TransportError::NonCanonicalLength);
        }
        let chunk_count = message.len().div_ceil(MAX_NOISE_PLAINTEXT);
        let chunk_count_u16 =
            u16::try_from(chunk_count).map_err(|_| TransportError::LengthOverflow)?;
        write_all(&mut self.stream, &(message.len() as u32).to_le_bytes())?;
        write_all(&mut self.stream, &chunk_count_u16.to_le_bytes())?;
        for chunk in message.chunks(MAX_NOISE_PLAINTEXT) {
            let mut encrypted = vec![0; chunk.len() + NOISE_TAG_LEN];
            let written = self
                .noise
                .write_message(chunk, &mut encrypted)
                .map_err(|_| TransportError::NoiseFailure)?;
            encrypted.truncate(written);
            let length = u32::try_from(written).map_err(|_| TransportError::LengthOverflow)?;
            write_all(&mut self.stream, &length.to_le_bytes())?;
            write_all(&mut self.stream, &encrypted)?;
        }
        self.stream.flush().map_err(|_| TransportError::IoFailure)
    }

    /// Receive and decrypt one complete bounded application message.
    pub fn receive_message(&mut self) -> Result<Vec<u8>, TransportError> {
        let total = usize::try_from(read_stream_u32(&mut self.stream)?)
            .map_err(|_| TransportError::LengthOverflow)?;
        if total == 0 || total > MAX_MESSAGE_LEN_V1 {
            return Err(TransportError::NonCanonicalLength);
        }
        let chunks = usize::from(read_stream_u16(&mut self.stream)?);
        let expected_chunks = total.div_ceil(MAX_NOISE_PLAINTEXT);
        if chunks == 0 || chunks != expected_chunks {
            return Err(TransportError::NonCanonicalLength);
        }
        let mut plaintext = Vec::with_capacity(total);
        for _ in 0..chunks {
            let encrypted_len = usize::try_from(read_stream_u32(&mut self.stream)?)
                .map_err(|_| TransportError::LengthOverflow)?;
            if encrypted_len <= NOISE_TAG_LEN || encrypted_len > MAX_NOISE_PLAINTEXT + NOISE_TAG_LEN
            {
                return Err(TransportError::NonCanonicalLength);
            }
            let mut encrypted = vec![0; encrypted_len];
            read_exact(&mut self.stream, &mut encrypted)?;
            let mut chunk = vec![0; encrypted_len - NOISE_TAG_LEN];
            let read = self
                .noise
                .read_message(&encrypted, &mut chunk)
                .map_err(|_| TransportError::NoiseFailure)?;
            chunk.truncate(read);
            plaintext.extend_from_slice(&chunk);
            if plaintext.len() > total {
                return Err(TransportError::NonCanonicalLength);
            }
        }
        if plaintext.len() != total {
            return Err(TransportError::NonCanonicalLength);
        }
        Ok(plaintext)
    }

    /// Return the underlying stream after orderly application shutdown.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

fn run_noise_handshake<S: Read + Write>(
    mut stream: S,
    mut handshake: HandshakeState,
    role: NoiseRoleV1,
) -> Result<(S, HandshakeState), TransportError> {
    let mut buffer = vec![0; MAX_NOISE_HANDSHAKE_FRAME];
    match role {
        NoiseRoleV1::Initiator => {
            write_handshake_message(&mut stream, &mut handshake, &mut buffer)?;
            read_handshake_message(&mut stream, &mut handshake, &mut buffer)?;
            write_handshake_message(&mut stream, &mut handshake, &mut buffer)?;
        }
        NoiseRoleV1::Responder => {
            read_handshake_message(&mut stream, &mut handshake, &mut buffer)?;
            write_handshake_message(&mut stream, &mut handshake, &mut buffer)?;
            read_handshake_message(&mut stream, &mut handshake, &mut buffer)?;
        }
    }
    if !handshake.is_handshake_finished() {
        return Err(TransportError::NoiseFailure);
    }
    Ok((stream, handshake))
}

fn write_handshake_message<S: Write>(
    stream: &mut S,
    handshake: &mut HandshakeState,
    buffer: &mut [u8],
) -> Result<(), TransportError> {
    let written = handshake
        .write_message(&[], buffer)
        .map_err(|_| TransportError::NoiseFailure)?;
    let length = u16::try_from(written).map_err(|_| TransportError::LengthOverflow)?;
    write_all(stream, &length.to_le_bytes())?;
    write_all(stream, &buffer[..written])?;
    stream.flush().map_err(|_| TransportError::IoFailure)
}

fn read_handshake_message<S: Read>(
    stream: &mut S,
    handshake: &mut HandshakeState,
    buffer: &mut [u8],
) -> Result<(), TransportError> {
    let length = usize::from(read_stream_u16(stream)?);
    if length == 0 || length > MAX_NOISE_HANDSHAKE_FRAME {
        return Err(TransportError::NonCanonicalLength);
    }
    let mut encoded = vec![0; length];
    read_exact(stream, &mut encoded)?;
    handshake
        .read_message(&encoded, buffer)
        .map_err(|_| TransportError::NoiseFailure)?;
    Ok(())
}

fn noise_prologue(chain_id: &[u8; 32], session_id: &[u8; 32]) -> Vec<u8> {
    let mut prologue = Vec::with_capacity(NOISE_PROLOGUE_PREFIX_V1.len() + 64);
    prologue.extend_from_slice(NOISE_PROLOGUE_PREFIX_V1);
    prologue.extend_from_slice(chain_id);
    prologue.extend_from_slice(session_id);
    prologue
}

fn write_all<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<(), TransportError> {
    writer
        .write_all(bytes)
        .map_err(|_| TransportError::IoFailure)
}

fn read_exact<R: Read>(reader: &mut R, bytes: &mut [u8]) -> Result<(), TransportError> {
    reader
        .read_exact(bytes)
        .map_err(|_| TransportError::IoFailure)
}

fn read_stream_u16<R: Read>(reader: &mut R) -> Result<u16, TransportError> {
    let mut bytes = [0; 2];
    read_exact(reader, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_stream_u32<R: Read>(reader: &mut R) -> Result<u32, TransportError> {
    let mut bytes = [0; 4];
    read_exact(reader, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u16(bytes: &[u8]) -> Result<u16, TransportError> {
    if bytes.len() != 2 {
        return Err(TransportError::UnexpectedEof);
    }
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(bytes: &[u8]) -> Result<u32, TransportError> {
    if bytes.len() != 4 {
        return Err(TransportError::UnexpectedEof);
    }
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(bytes: &[u8]) -> Result<u64, TransportError> {
    if bytes.len() != 8 {
        return Err(TransportError::UnexpectedEof);
    }
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn array_32(bytes: &[u8]) -> Result<[u8; 32], TransportError> {
    if bytes.len() != 32 {
        return Err(TransportError::UnexpectedEof);
    }
    let mut out = [0; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::os::unix::net::UnixStream;
    use std::thread;

    fn identity(byte: u8) -> Result<SecretKey, Box<dyn Error>> {
        let mut value = [0; 32];
        value[31] = byte;
        Ok(SecretKey::from_bytes(&value)?)
    }

    fn signed(
        key: &SecretKey,
        sender: [u8; 32],
        sequence: u64,
        transcript: [u8; 32],
        kind: MessageTypeV1,
        payload: Vec<u8>,
    ) -> Result<SignedMessageV1, Box<dyn Error>> {
        Ok(SignedMessageV1::sign(
            UnsignedMessageV1::new(
                kind, [0x11; 32], [0x22; 32], sender, sequence, transcript, payload,
            )?,
            key,
        )?)
    }

    fn signed_abort(
        key: &SecretKey,
        sender: [u8; 32],
        sequence: u64,
        transcript: [u8; 32],
        binding_digest: [u8; ABORT_PAYLOAD_LEN_V1],
    ) -> Result<SignedMessageV1, Box<dyn Error>> {
        let payload = AbortPayloadV1::new(binding_digest)?;
        Ok(SignedMessageV1::sign(
            UnsignedMessageV1::new_abort(
                [0x11; 32], [0x22; 32], sender, sequence, transcript, payload,
            )?,
            key,
        )?)
    }

    fn abort_receiver(
        phase: SessionPhaseV1,
        transcript: [u8; 32],
    ) -> Result<SessionReceiverV1, Box<dyn Error>> {
        let alice_key = identity(21)?;
        let bob_key = identity(22)?;
        Ok(SessionReceiverV1::new(
            [0x11; 32],
            [0x22; 32],
            [
                TransportParticipantV1::new(
                    [0xa5; 32],
                    alice_key.public_key(),
                    DirectionV1::Initiator,
                )?,
                TransportParticipantV1::new(
                    [0xb6; 32],
                    bob_key.public_key(),
                    DirectionV1::Responder,
                )?,
            ],
            phase,
            transcript,
        )?)
    }

    fn replace_abort_payload(message: &SignedMessageV1, payload: &[u8]) -> Vec<u8> {
        assert_eq!(message.unsigned().kind(), MessageTypeV1::Abort);
        assert_eq!(message.unsigned().payload().len(), ABORT_PAYLOAD_LEN_V1);
        let signature_offset = UNSIGNED_PREFIX_LEN_V1 + ABORT_PAYLOAD_LEN_V1;
        let mut bytes = message.as_bytes()[..UNSIGNED_PREFIX_LEN_V1].to_vec();
        bytes[144..148].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&message.as_bytes()[signature_offset..]);
        bytes
    }

    fn evm_request() -> Result<EvmActionRequestPayloadV1, TransportError> {
        EvmActionRequestPayloadV1::new(EvmActionRequestInputV1 {
            action: EvmActionKindV1::Funding,
            role: EvmSignerRoleV1::Funder,
            owner_epoch: 7,
            evm_chain_id: 11_155_111,
            action_id: [0x31; 32],
            route_id: [0x32; 32],
            settlement_id: [0x33; 32],
            composition_binding_digest: [0x34; 32],
            execution_plan_digest: [0x35; 32],
            unsigned_call_digest: [0x36; 32],
            owner_id: [0x37; 32],
            requester_id: [0xa5; 32],
            signer_id: [0xb6; 32],
            contract: [0x38; 20],
            signer_account: [0x39; 20],
        })
    }

    #[test]
    fn evm_action_payloads_are_exact_bounded_and_secret_free() -> Result<(), Box<dyn Error>> {
        let request = evm_request()?;
        let request_bytes = request.to_bytes();
        assert_eq!(request_bytes.len(), EVM_ACTION_REQUEST_PAYLOAD_LEN_V1);
        assert_eq!(
            EvmActionRequestPayloadV1::decode_exact(&request_bytes)?,
            request
        );
        assert_eq!(MessageTypeV1::EvmActionRequest as u8, 0x15);
        assert_eq!(MessageTypeV1::EvmSignedAction as u8, 0x16);

        let response =
            EvmSignedActionPayloadV1::new(request, [0x41; 32], [0x42; 32], vec![0x02, 0x01, 0x03])?;
        let response_bytes = response.to_bytes()?;
        assert_eq!(
            EvmSignedActionPayloadV1::decode_exact(&response_bytes)?,
            response
        );
        assert_eq!(response.signed_raw_transaction(), [0x02, 0x01, 0x03]);

        let oversized = vec![0x02; EVM_SIGNED_ACTION_RAW_MAX_LEN_V1 + 1];
        assert_eq!(
            EvmSignedActionPayloadV1::new(request, [0x41; 32], [0x42; 32], oversized),
            Err(TransportError::InvalidTypedPayload)
        );
        let mut corrupt = response_bytes;
        *corrupt.last_mut().ok_or(TransportError::UnexpectedEof)? ^= 1;
        assert_eq!(
            EvmSignedActionPayloadV1::decode_exact(&corrupt),
            Err(TransportError::InvalidTypedPayload)
        );
        Ok(())
    }

    #[test]
    fn evm_action_exchange_advances_transcript_and_rejects_transplant() -> Result<(), Box<dyn Error>>
    {
        let alice_key = identity(21)?;
        let bob_key = identity(22)?;
        let alice_id = [0xa5; 32];
        let bob_id = [0xb6; 32];
        let initial = [0x43; 32];
        let mut receiver = SessionReceiverV1::new(
            [0x11; 32],
            [0x22; 32],
            [
                TransportParticipantV1::new(
                    alice_id,
                    alice_key.public_key(),
                    DirectionV1::Initiator,
                )?,
                TransportParticipantV1::new(bob_id, bob_key.public_key(), DirectionV1::Responder)?,
            ],
            SessionPhaseV1::RefundSigned,
            initial,
        )?;
        let request_payload = evm_request()?;
        let request = SignedMessageV1::sign(
            UnsignedMessageV1::new_evm_action_request(
                [0x11; 32],
                [0x22; 32],
                alice_id,
                0,
                initial,
                request_payload,
            )?,
            &alice_key,
        )?;
        let accepted = receiver.accept(request.as_bytes(), SessionPhaseV1::RefundSigned)?;
        assert_ne!(accepted.transcript_hash, initial);
        assert!(
            receiver
                .accept(request.as_bytes(), SessionPhaseV1::RefundSigned)?
                .duplicate
        );

        let response_payload = EvmSignedActionPayloadV1::new(
            request_payload,
            accepted.message_digest,
            [0x44; 32],
            vec![0x02, 0x45],
        )?;
        let response = SignedMessageV1::sign(
            UnsignedMessageV1::new_evm_signed_action(
                [0x11; 32],
                [0x22; 32],
                bob_id,
                0,
                accepted.transcript_hash,
                &response_payload,
            )?,
            &bob_key,
        )?;
        receiver.accept(response.as_bytes(), SessionPhaseV1::RefundSigned)?;

        let transplanted = SignedMessageV1::sign(
            UnsignedMessageV1::new_evm_signed_action(
                [0x11; 32],
                [0x22; 32],
                bob_id,
                1,
                accepted.transcript_hash,
                &response_payload,
            )?,
            &bob_key,
        )?;
        assert_eq!(
            receiver.accept(transplanted.as_bytes(), SessionPhaseV1::RefundSigned),
            Err(TransportError::ForkedTranscript)
        );
        Ok(())
    }

    #[test]
    fn abort_payload_is_exact_nonzero_and_preserves_registry_v1() -> Result<(), Box<dyn Error>> {
        let key = identity(21)?;
        let binding_digest = [0x7a; ABORT_PAYLOAD_LEN_V1];
        let payload = AbortPayloadV1::new(binding_digest)?;
        assert_eq!(payload.binding_digest(), &binding_digest);
        assert_eq!(payload.into_bytes(), binding_digest);
        assert_eq!(MessageTypeV1::Abort as u8, 0x13);
        assert_eq!(MessageTypeV1::try_from(0x13)?, MessageTypeV1::Abort);
        assert_eq!(MessageTypeV1::Abort.payload_cap(), ABORT_PAYLOAD_LEN_V1);

        let message = signed_abort(&key, [0xa5; 32], 0, [0x51; 32], binding_digest)?;
        let decoded = SignedMessageV1::decode_exact(message.as_bytes())?;
        decoded.verify_identity(&key.public_key())?;
        assert_eq!(decoded.as_bytes(), message.as_bytes());
        assert_eq!(
            AbortPayloadV1::decode_exact(decoded.unsigned().payload())?,
            payload
        );
        Ok(())
    }

    #[test]
    fn abort_payload_rejects_every_noncanonical_length_and_zero() -> Result<(), Box<dyn Error>> {
        let key = identity(21)?;
        let valid = signed_abort(&key, [0xa5; 32], 0, [0x51; 32], [0x7a; 32])?;

        for length in [0, 31, 33, 4096] {
            let payload = vec![0x7a; length];
            let envelope_error = if length > ABORT_PAYLOAD_LEN_V1 {
                TransportError::PayloadTooLarge
            } else {
                TransportError::NonCanonicalLength
            };
            assert_eq!(
                AbortPayloadV1::decode_exact(&payload),
                Err(TransportError::NonCanonicalLength)
            );
            assert_eq!(
                UnsignedMessageV1::new(
                    MessageTypeV1::Abort,
                    [0x11; 32],
                    [0x22; 32],
                    [0xa5; 32],
                    0,
                    [0x51; 32],
                    payload.clone(),
                )
                .err(),
                Some(envelope_error)
            );
            assert_eq!(
                SignedMessageV1::decode_exact(&replace_abort_payload(&valid, &payload)).err(),
                Some(envelope_error)
            );
        }

        let zero = [0; ABORT_PAYLOAD_LEN_V1];
        assert_eq!(
            AbortPayloadV1::new(zero),
            Err(TransportError::ZeroPayloadCommitment)
        );
        assert_eq!(
            AbortPayloadV1::decode_exact(&zero),
            Err(TransportError::ZeroPayloadCommitment)
        );
        assert_eq!(
            UnsignedMessageV1::new(
                MessageTypeV1::Abort,
                [0x11; 32],
                [0x22; 32],
                [0xa5; 32],
                0,
                [0x51; 32],
                zero.to_vec(),
            )
            .err(),
            Some(TransportError::ZeroPayloadCommitment)
        );
        assert_eq!(
            SignedMessageV1::decode_exact(&replace_abort_payload(&valid, &zero)).err(),
            Some(TransportError::ZeroPayloadCommitment)
        );
        Ok(())
    }

    #[test]
    fn abort_is_allowed_from_every_prefunding_phase_for_both_participants(
    ) -> Result<(), Box<dyn Error>> {
        let abortable = [
            SessionPhaseV1::Created,
            SessionPhaseV1::TermsCommitted,
            SessionPhaseV1::SharesCommitted,
            SessionPhaseV1::SharesRevealed,
            SessionPhaseV1::BpCommonCommitted,
            SessionPhaseV1::BpCommonEstablished,
            SessionPhaseV1::BpNonceCommitted,
            SessionPhaseV1::BpRound1Complete,
            SessionPhaseV1::BpRound2Complete,
            SessionPhaseV1::OutputFinalized,
            SessionPhaseV1::TemplatesCommitted,
            SessionPhaseV1::RefundSigning,
            SessionPhaseV1::RefundSigned,
            SessionPhaseV1::ClaimSigning,
            SessionPhaseV1::ClaimPrepared,
        ];
        let alice_key = identity(21)?;
        let bob_key = identity(22)?;
        for phase in abortable {
            for (key, sender, binding_byte) in
                [(&alice_key, [0xa5; 32], 0x71), (&bob_key, [0xb6; 32], 0x72)]
            {
                let initial = [phase as u16 as u8; 32];
                let mut receiver = abort_receiver(phase, initial)?;
                let abort = signed_abort(key, sender, 0, initial, [binding_byte; 32])?;
                let receipt = receiver.accept(abort.as_bytes(), SessionPhaseV1::Aborted)?;
                assert_eq!(receipt.kind, MessageTypeV1::Abort);
                assert!(!receipt.duplicate);
                assert_eq!(receiver.phase(), SessionPhaseV1::Aborted);
            }
        }
        Ok(())
    }

    #[test]
    fn abort_is_refused_from_funding_authorized_and_every_later_phase() -> Result<(), Box<dyn Error>>
    {
        let forbidden = [
            SessionPhaseV1::FundingAuthorized,
            SessionPhaseV1::FundingBroadcast,
            SessionPhaseV1::FundingConfirmed,
            SessionPhaseV1::ClaimBroadcast,
            SessionPhaseV1::RefundEligible,
            SessionPhaseV1::RefundBroadcast,
            SessionPhaseV1::Settled,
            SessionPhaseV1::Refunded,
            SessionPhaseV1::Aborted,
            SessionPhaseV1::FailedClosed,
        ];
        let alice_key = identity(21)?;
        for phase in forbidden {
            let initial = [phase as u16 as u8; 32];
            let mut receiver = abort_receiver(phase, initial)?;
            let abort = signed_abort(&alice_key, [0xa5; 32], 0, initial, [0x73; 32])?;
            assert_eq!(
                receiver.accept(abort.as_bytes(), SessionPhaseV1::Aborted),
                Err(TransportError::InvalidTransition),
                "Abort unexpectedly accepted from {phase:?}"
            );
            assert_eq!(receiver.phase(), phase);
        }
        Ok(())
    }

    #[test]
    fn abort_enforces_sender_local_sequence_and_transcript_for_both_participants(
    ) -> Result<(), Box<dyn Error>> {
        let initial = [0x51; 32];
        let alice_key = identity(21)?;
        let bob_key = identity(22)?;
        for (key, sender, binding_byte) in
            [(&alice_key, [0xa5; 32], 0x74), (&bob_key, [0xb6; 32], 0x75)]
        {
            let mut receiver = abort_receiver(SessionPhaseV1::Created, initial)?;
            let gap = signed_abort(key, sender, 1, initial, [binding_byte; 32])?;
            assert_eq!(
                receiver.accept(gap.as_bytes(), SessionPhaseV1::Aborted),
                Err(TransportError::SequenceGap)
            );
            assert_eq!(receiver.phase(), SessionPhaseV1::Created);

            let fork = signed_abort(key, sender, 0, [0x99; 32], [binding_byte; 32])?;
            assert_eq!(
                receiver.accept(fork.as_bytes(), SessionPhaseV1::Aborted),
                Err(TransportError::ForkedTranscript)
            );
            assert_eq!(receiver.phase(), SessionPhaseV1::Created);

            let wrong_destination = signed_abort(key, sender, 0, initial, [binding_byte; 32])?;
            assert_eq!(
                receiver.accept(wrong_destination.as_bytes(), SessionPhaseV1::ClaimPrepared),
                Err(TransportError::PhaseMismatch)
            );
            assert_eq!(receiver.phase(), SessionPhaseV1::Created);

            let exact = signed_abort(key, sender, 0, initial, [binding_byte; 32])?;
            receiver.accept(exact.as_bytes(), SessionPhaseV1::Aborted)?;
            assert_eq!(receiver.phase(), SessionPhaseV1::Aborted);
        }
        Ok(())
    }

    #[test]
    fn exact_codec_round_trip_and_signature() -> Result<(), Box<dyn Error>> {
        let key = identity(3)?;
        let message = signed(
            &key,
            [0x33; 32],
            7,
            [0x44; 32],
            MessageTypeV1::BpRound2,
            vec![0x55; 1024],
        )?;
        let decoded = SignedMessageV1::decode_exact(message.as_bytes())?;
        decoded.verify_identity(&key.public_key())?;
        assert!(decoded == message);
        assert_eq!(decoded.unsigned().payload(), &[0x55; 1024]);
        Ok(())
    }

    #[test]
    fn every_truncation_trailing_byte_and_registered_limit_fail_closed(
    ) -> Result<(), Box<dyn Error>> {
        let key = identity(4)?;
        let message = signed(
            &key,
            [0x34; 32],
            0,
            [0x45; 32],
            MessageTypeV1::Offer,
            vec![7; 128],
        )?;
        for end in 0..message.as_bytes().len() {
            assert!(SignedMessageV1::decode_exact(&message.as_bytes()[..end]).is_err());
        }
        let mut trailing = message.as_bytes().to_vec();
        trailing.push(0);
        assert_eq!(
            SignedMessageV1::decode_exact(&trailing).err(),
            Some(TransportError::NonCanonicalLength)
        );
        assert_eq!(
            UnsignedMessageV1::new(
                MessageTypeV1::ReadyToFund,
                [1; 32],
                [2; 32],
                [3; 32],
                0,
                [0; 32],
                vec![0; 4097],
            )
            .err(),
            Some(TransportError::PayloadTooLarge)
        );
        Ok(())
    }

    #[test]
    fn signature_mutation_and_context_substitution_fail() -> Result<(), Box<dyn Error>> {
        let key = identity(5)?;
        let other = identity(6)?;
        let message = signed(
            &key,
            [0x35; 32],
            0,
            [0x46; 32],
            MessageTypeV1::Offer,
            vec![9; 32],
        )?;
        assert_eq!(
            message.verify_identity(&other.public_key()),
            Err(TransportError::AuthenticationFailed)
        );
        let mut bytes = message.as_bytes().to_vec();
        bytes[40] ^= 1;
        let changed = SignedMessageV1::decode_exact(&bytes)?;
        assert_eq!(
            changed.verify_identity(&key.public_key()),
            Err(TransportError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn receiver_is_idempotent_and_equivocation_is_terminal() -> Result<(), Box<dyn Error>> {
        let alice_key = identity(7)?;
        let bob_key = identity(8)?;
        let alice_id = [0xa1; 32];
        let bob_id = [0xb2; 32];
        let initial = [0x51; 32];
        let mut receiver = SessionReceiverV1::new(
            [0x11; 32],
            [0x22; 32],
            [
                TransportParticipantV1::new(
                    alice_id,
                    alice_key.public_key(),
                    DirectionV1::Initiator,
                )?,
                TransportParticipantV1::new(bob_id, bob_key.public_key(), DirectionV1::Responder)?,
            ],
            SessionPhaseV1::Created,
            initial,
        )?;
        let offer = signed(
            &alice_key,
            alice_id,
            0,
            initial,
            MessageTypeV1::Offer,
            b"offer".to_vec(),
        )?;
        let first = receiver.accept(offer.as_bytes(), SessionPhaseV1::Created)?;
        let duplicate = receiver.accept(offer.as_bytes(), SessionPhaseV1::Created)?;
        assert!(!first.duplicate);
        assert!(duplicate.duplicate);
        assert_eq!(first.transcript_hash, duplicate.transcript_hash);

        let equivocation = signed(
            &alice_key,
            alice_id,
            0,
            initial,
            MessageTypeV1::Offer,
            b"different".to_vec(),
        )?;
        assert_eq!(
            receiver.accept(equivocation.as_bytes(), SessionPhaseV1::Created),
            Err(TransportError::Equivocation)
        );
        assert!(receiver.is_failed_closed());
        assert_eq!(receiver.phase(), SessionPhaseV1::FailedClosed);
        Ok(())
    }

    #[test]
    fn receiver_rejects_gap_fork_wrong_phase_and_unknown_sender() -> Result<(), Box<dyn Error>> {
        let alice_key = identity(9)?;
        let bob_key = identity(10)?;
        let outsider_key = identity(11)?;
        let alice_id = [0xa3; 32];
        let bob_id = [0xb4; 32];
        let initial = [0x52; 32];
        let mut receiver = SessionReceiverV1::new(
            [0x11; 32],
            [0x22; 32],
            [
                TransportParticipantV1::new(
                    alice_id,
                    alice_key.public_key(),
                    DirectionV1::Initiator,
                )?,
                TransportParticipantV1::new(bob_id, bob_key.public_key(), DirectionV1::Responder)?,
            ],
            SessionPhaseV1::Created,
            initial,
        )?;
        let gap = signed(
            &alice_key,
            alice_id,
            1,
            initial,
            MessageTypeV1::Offer,
            Vec::new(),
        )?;
        assert_eq!(
            receiver.accept(gap.as_bytes(), SessionPhaseV1::Created),
            Err(TransportError::SequenceGap)
        );
        let fork = signed(
            &alice_key,
            alice_id,
            0,
            [0x99; 32],
            MessageTypeV1::Offer,
            Vec::new(),
        )?;
        assert_eq!(
            receiver.accept(fork.as_bytes(), SessionPhaseV1::Created),
            Err(TransportError::ForkedTranscript)
        );
        let wrong_phase = signed(
            &alice_key,
            alice_id,
            0,
            initial,
            MessageTypeV1::Offer,
            Vec::new(),
        )?;
        assert_eq!(
            receiver.accept(wrong_phase.as_bytes(), SessionPhaseV1::TermsCommitted),
            Err(TransportError::PhaseMismatch)
        );
        let outsider = signed(
            &outsider_key,
            [0xcc; 32],
            0,
            initial,
            MessageTypeV1::Offer,
            Vec::new(),
        )?;
        assert_eq!(
            receiver.accept(outsider.as_bytes(), SessionPhaseV1::Created),
            Err(TransportError::UnknownSender)
        );
        Ok(())
    }

    #[test]
    fn noise_xx_authenticates_and_chunks_maximum_final_transaction() -> Result<(), Box<dyn Error>> {
        let alice = NoiseStaticKeyV1::generate();
        let bob = NoiseStaticKeyV1::generate();
        let alice_public = *alice.public_key();
        let bob_public = *bob.public_key();
        let (left, right) = UnixStream::pair()?;
        let responder = thread::spawn(move || -> Result<Vec<u8>, TransportError> {
            let mut channel = EncryptedTransportV1::establish(
                right,
                NoiseSessionConfigV1 {
                    role: NoiseRoleV1::Responder,
                    chain_id: [0x61; 32],
                    session_id: [0x62; 32],
                    local_static: &bob,
                    expected_remote_static: alice_public,
                },
            )?;
            let received = channel.receive_message()?;
            channel.send_message(b"ack")?;
            Ok(received)
        });
        let mut channel = EncryptedTransportV1::establish(
            left,
            NoiseSessionConfigV1 {
                role: NoiseRoleV1::Initiator,
                chain_id: [0x61; 32],
                session_id: [0x62; 32],
                local_static: &alice,
                expected_remote_static: bob_public,
            },
        )?;
        let message = vec![0x7a; MESSAGE_FIXED_LEN_V1 + 512 * 1024];
        channel.send_message(&message)?;
        assert_eq!(channel.receive_message()?, b"ack");
        let received = responder.join().map_err(|_| TransportError::IoFailure)??;
        assert_eq!(received, message);
        Ok(())
    }

    #[test]
    fn noise_session_context_and_peer_key_are_fail_closed() -> Result<(), Box<dyn Error>> {
        let alice = NoiseStaticKeyV1::generate();
        let bob = NoiseStaticKeyV1::generate();
        let wrong = NoiseStaticKeyV1::generate();
        let alice_public = *alice.public_key();
        let wrong_public = *wrong.public_key();
        let (left, right) = UnixStream::pair()?;
        let responder = thread::spawn(move || {
            EncryptedTransportV1::establish(
                right,
                NoiseSessionConfigV1 {
                    role: NoiseRoleV1::Responder,
                    chain_id: [0x71; 32],
                    session_id: [0x72; 32],
                    local_static: &bob,
                    expected_remote_static: alice_public,
                },
            )
        });
        let result = EncryptedTransportV1::establish(
            left,
            NoiseSessionConfigV1 {
                role: NoiseRoleV1::Initiator,
                chain_id: [0x71; 32],
                session_id: [0x72; 32],
                local_static: &alice,
                expected_remote_static: wrong_public,
            },
        );
        assert!(matches!(result, Err(TransportError::NoisePeerMismatch)));
        let _ = responder.join();
        Ok(())
    }
}
