//! Canonical operation inputs for retained-authority Nonce Vault computations.

use crate::{
    AdaptorError, BindingFactorV1, NonceCommitmentV1, NonceRevealV1, PurposeV1, Result,
    SessionContextV1, SigningPhaseV1, VaultComputationStageV1,
};
use dom_crypto::{blake2b_256_tagged, PublicKey};

const OPERATION_INPUT_TAG_V1: &str = "DOM:scriptless-vault-computation-input:v1";
const COMMITMENT_SET_MAGIC: &[u8; 8] = b"DOMNVCM1";
const REVEAL_SET_MAGIC: &[u8; 8] = b"DOMNVRL1";
const OPERATION_INPUT_VERSION: u16 = 1;

const COMMITMENT_SET_KIND: u8 = 0x01;
const REVEAL_SET_KIND: u8 = 0x02;
const BINDING_FACTOR_KIND: u8 = 0x03;
const AGGREGATE_NONCE_HAT_KIND: u8 = 0x04;
const AGGREGATE_SIGNING_KEY_KIND: u8 = 0x05;
const KERNEL_MESSAGE_DIGEST_KIND: u8 = 0x06;

/// Exact canonical commitment-set length for the two-party Phase 1 profile.
pub const PROTOCOL_COMMITMENT_SET_LEN: usize = 214;
/// Minimum canonical reveal-set length with an empty strict roster prefix.
pub const PROTOCOL_REVEAL_SET_MIN_LEN: usize = 12;
/// Exact size of one canonical reveal-set entry.
pub const PROTOCOL_REVEAL_ENTRY_LEN: usize = 135;

pub(crate) struct CommitmentEntryV1 {
    participant_id: [u8; 32],
    g1a_participant_index: u16,
    accepted_message_digest: [u8; 32],
    commitment: NonceCommitmentV1,
}

impl CommitmentEntryV1 {
    pub(crate) fn new(
        participant_id: [u8; 32],
        g1a_participant_index: u16,
        accepted_message_digest: [u8; 32],
        commitment: NonceCommitmentV1,
    ) -> Result<Self> {
        if participant_id == [0; 32]
            || accepted_message_digest == [0; 32]
            || g1a_participant_index > 1
            || commitment.participant_index() != g1a_participant_index
        {
            return Err(AdaptorError::InvalidContext(
                "invalid canonical commitment-set entry",
            ));
        }
        commitment.purpose().require_strict_phase1()?;
        Ok(Self {
            participant_id,
            g1a_participant_index,
            accepted_message_digest,
            commitment,
        })
    }

    fn encode_into(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.participant_id);
        output.extend_from_slice(&self.g1a_participant_index.to_le_bytes());
        output.extend_from_slice(&self.accepted_message_digest);
        output.extend_from_slice(&self.commitment.to_bytes());
    }
}

/// Validated canonical commitment set for the exact two-party Phase 1 profile.
///
/// Construction is restricted to the safe signer after it has validated the
/// accepted protocol roster and immutable DSC1 messages.
pub struct ProtocolCommitmentSetV1 {
    bytes: [u8; PROTOCOL_COMMITMENT_SET_LEN],
    purpose: PurposeV1,
}

impl ProtocolCommitmentSetV1 {
    pub(crate) fn new(entries: [CommitmentEntryV1; 2]) -> Result<Self> {
        if entries[0].participant_id >= entries[1].participant_id
            || entries[0].g1a_participant_index == entries[1].g1a_participant_index
            || entries[0].commitment.purpose() != entries[1].commitment.purpose()
        {
            return Err(AdaptorError::InvalidContext(
                "commitment set does not match the canonical two-party roster",
            ));
        }
        let purpose = entries[0].commitment.purpose();
        let mut encoded = Vec::with_capacity(PROTOCOL_COMMITMENT_SET_LEN);
        encoded.extend_from_slice(COMMITMENT_SET_MAGIC);
        encoded.extend_from_slice(&OPERATION_INPUT_VERSION.to_le_bytes());
        encoded.extend_from_slice(&2u16.to_le_bytes());
        for entry in entries {
            entry.encode_into(&mut encoded);
        }
        let bytes: [u8; PROTOCOL_COMMITMENT_SET_LEN] = encoded
            .try_into()
            .map_err(|_| AdaptorError::InvalidContext("commitment set length is not canonical"))?;
        Ok(Self { bytes, purpose })
    }

    /// Return the exact canonical commitment-set bytes.
    pub const fn as_bytes(&self) -> &[u8; PROTOCOL_COMMITMENT_SET_LEN] {
        &self.bytes
    }

    pub(crate) const fn purpose(&self) -> PurposeV1 {
        self.purpose
    }
}

pub(crate) struct RevealEntryV1 {
    participant_id: [u8; 32],
    g1a_participant_index: u16,
    accepted_message_digest: [u8; 32],
    reveal: NonceRevealV1,
}

impl RevealEntryV1 {
    pub(crate) fn new(
        participant_id: [u8; 32],
        g1a_participant_index: u16,
        accepted_message_digest: [u8; 32],
        reveal: NonceRevealV1,
    ) -> Result<Self> {
        if participant_id == [0; 32]
            || accepted_message_digest == [0; 32]
            || g1a_participant_index > 1
            || reveal.participant_index() != g1a_participant_index
        {
            return Err(AdaptorError::InvalidContext(
                "invalid canonical reveal-set entry",
            ));
        }
        reveal.purpose().require_strict_phase1()?;
        Ok(Self {
            participant_id,
            g1a_participant_index,
            accepted_message_digest,
            reveal,
        })
    }

    fn encode_into(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.participant_id);
        output.extend_from_slice(&self.g1a_participant_index.to_le_bytes());
        output.extend_from_slice(&self.accepted_message_digest);
        output.extend_from_slice(&self.reveal.to_bytes());
    }
}

/// Validated canonical strict-prefix reveal set for the two-party profile.
pub struct ProtocolRevealSetV1 {
    bytes: Vec<u8>,
    count: u16,
    purpose: Option<PurposeV1>,
}

impl ProtocolRevealSetV1 {
    pub(crate) fn new(entries: Vec<RevealEntryV1>) -> Result<Self> {
        if entries.len() > 2
            || entries
                .windows(2)
                .any(|pair| pair[0].participant_id >= pair[1].participant_id)
            || entries
                .windows(2)
                .any(|pair| pair[0].g1a_participant_index == pair[1].g1a_participant_index)
            || entries
                .windows(2)
                .any(|pair| pair[0].reveal.purpose() != pair[1].reveal.purpose())
        {
            return Err(AdaptorError::InvalidContext(
                "reveal set is not a canonical strict roster prefix",
            ));
        }
        let count = u16::try_from(entries.len())
            .map_err(|_| AdaptorError::InvalidContext("reveal count overflow"))?;
        let purpose = entries.first().map(|entry| entry.reveal.purpose());
        let mut bytes = Vec::with_capacity(
            PROTOCOL_REVEAL_SET_MIN_LEN + entries.len() * PROTOCOL_REVEAL_ENTRY_LEN,
        );
        bytes.extend_from_slice(REVEAL_SET_MAGIC);
        bytes.extend_from_slice(&OPERATION_INPUT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
        for entry in entries {
            entry.encode_into(&mut bytes);
        }
        Ok(Self {
            bytes,
            count,
            purpose,
        })
    }

    /// Return the exact canonical reveal-set bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the strict-prefix participant count.
    pub const fn count(&self) -> u16 {
        self.count
    }

    pub(crate) const fn purpose(&self) -> Option<PurposeV1> {
        self.purpose
    }
}

struct CanonicalOperationInputV1 {
    tagged_data: Vec<u8>,
    digest: [u8; 32],
}

/// Non-authoritative immutable evidence copied before a one-shot request is consumed.
pub(crate) struct VaultComputationEvidenceV1 {
    stage: VaultComputationStageV1,
    context_binding_digest: [u8; 32],
    context: SessionContextV1,
    tagged_data: Vec<u8>,
    operation_input_digest: [u8; 32],
}

impl VaultComputationEvidenceV1 {
    pub(crate) fn validated_view(&self) -> ValidatedVaultComputationViewV1<'_> {
        ValidatedVaultComputationViewV1 {
            stage: self.stage,
            reservation_context_binding_digest: &self.context_binding_digest,
            context: &self.context,
            tagged_data: &self.tagged_data,
            operation_input_digest: &self.operation_input_digest,
        }
    }
}

impl CanonicalOperationInputV1 {
    fn new(
        stage: VaultComputationStageV1,
        context_binding_digest: [u8; 32],
        context: &SessionContextV1,
        fields: &[(u8, &[u8])],
    ) -> Result<Self> {
        if context_binding_digest == [0; 32]
            || fields.len() > usize::from(u8::MAX)
            || context.participant_public_keys().len() != 2
        {
            return Err(AdaptorError::InvalidContext(
                "invalid vault computation input authority",
            ));
        }
        let context_bytes = context.to_bytes();
        if !matches!(context_bytes.len(), 245 | 278) {
            return Err(AdaptorError::InvalidContext(
                "vault computation context is outside the two-party profile",
            ));
        }
        let mut tagged_data = Vec::with_capacity(40 + context_bytes.len());
        tagged_data.extend_from_slice(&OPERATION_INPUT_VERSION.to_le_bytes());
        tagged_data.push(stage.to_byte());
        tagged_data.extend_from_slice(&context_binding_digest);
        tagged_data.extend_from_slice(
            &u32::try_from(context_bytes.len())
                .map_err(|_| AdaptorError::InvalidContext("context length overflow"))?
                .to_le_bytes(),
        );
        tagged_data.extend_from_slice(&context_bytes);
        tagged_data.push(
            u8::try_from(fields.len())
                .map_err(|_| AdaptorError::InvalidContext("field count overflow"))?,
        );
        for (kind, bytes) in fields {
            tagged_data.push(*kind);
            tagged_data.extend_from_slice(
                &u32::try_from(bytes.len())
                    .map_err(|_| AdaptorError::InvalidContext("field length overflow"))?
                    .to_le_bytes(),
            );
            tagged_data.extend_from_slice(bytes);
        }
        let digest = *blake2b_256_tagged(OPERATION_INPUT_TAG_V1, &tagged_data).as_bytes();
        if digest == [0; 32] {
            return Err(AdaptorError::InvalidTranscript(
                "zero vault computation input digest",
            ));
        }
        Ok(Self {
            tagged_data,
            digest,
        })
    }
}

/// Immutable borrowed view exposed only by an unforgeable computation request.
pub struct ValidatedVaultComputationViewV1<'a> {
    stage: VaultComputationStageV1,
    reservation_context_binding_digest: &'a [u8; 32],
    context: &'a SessionContextV1,
    tagged_data: &'a [u8],
    operation_input_digest: &'a [u8; 32],
}

impl<'a> ValidatedVaultComputationViewV1<'a> {
    /// Return the closed durable computation stage.
    pub const fn stage(&self) -> VaultComputationStageV1 {
        self.stage
    }

    /// Return the complete reservation-context binding digest.
    pub const fn reservation_context_binding_digest(&self) -> &[u8; 32] {
        self.reservation_context_binding_digest
    }

    /// Return the validated immutable stage context.
    pub const fn context(&self) -> &SessionContextV1 {
        self.context
    }

    /// Return the exact outer-H_tag data bytes.
    pub const fn tagged_data(&self) -> &[u8] {
        self.tagged_data
    }

    /// Return the authoritative operation-input digest.
    pub const fn operation_input_digest(&self) -> &[u8; 32] {
        self.operation_input_digest
    }

    /// Return the signer-owned effective retry counter.
    pub const fn effective_retry_counter(&self) -> u64 {
        self.context.retry_counter()
    }
}

/// Opaque one-shot request for the initial nonce-derivation attempt.
pub struct NonceDerivationRequestV1 {
    context_binding_digest: [u8; 32],
    context: SessionContextV1,
    operation_input: CanonicalOperationInputV1,
}

impl NonceDerivationRequestV1 {
    pub(crate) fn new(context_binding_digest: [u8; 32], context: SessionContextV1) -> Result<Self> {
        if context.signing_phase() != SigningPhaseV1::SigNonceCommit {
            return Err(AdaptorError::InvalidContext(
                "nonce derivation requires SigNonceCommit",
            ));
        }
        let operation_input = CanonicalOperationInputV1::new(
            VaultComputationStageV1::NonceDerivation,
            context_binding_digest,
            &context,
            &[],
        )?;
        Ok(Self {
            context_binding_digest,
            context,
            operation_input,
        })
    }

    /// Borrow the immutable validated request view.
    pub fn validated_view(&self) -> ValidatedVaultComputationViewV1<'_> {
        ValidatedVaultComputationViewV1 {
            stage: VaultComputationStageV1::NonceDerivation,
            reservation_context_binding_digest: &self.context_binding_digest,
            context: &self.context,
            tagged_data: &self.operation_input.tagged_data,
            operation_input_digest: &self.operation_input.digest,
        }
    }

    pub(crate) fn evidence(&self) -> VaultComputationEvidenceV1 {
        VaultComputationEvidenceV1 {
            stage: VaultComputationStageV1::NonceDerivation,
            context_binding_digest: self.context_binding_digest,
            context: self.context.clone(),
            tagged_data: self.operation_input.tagged_data.clone(),
            operation_input_digest: self.operation_input.digest,
        }
    }
}

/// Opaque one-shot request for a reveal or partial-signature computation.
pub struct StageComputationRequestV1 {
    stage: VaultComputationStageV1,
    context_binding_digest: [u8; 32],
    context: SessionContextV1,
    operation_input: CanonicalOperationInputV1,
}

impl StageComputationRequestV1 {
    pub(crate) fn new_reveal(
        context_binding_digest: [u8; 32],
        context: SessionContextV1,
        commitments: &ProtocolCommitmentSetV1,
        reveal_prefix: &ProtocolRevealSetV1,
        local_protocol_roster_index: u16,
    ) -> Result<Self> {
        if context.signing_phase() != SigningPhaseV1::SigNonceReveal
            || local_protocol_roster_index > 1
            || reveal_prefix.count() != local_protocol_roster_index
            || commitments.purpose() != context.purpose()
            || reveal_prefix
                .purpose()
                .is_some_and(|purpose| purpose != context.purpose())
        {
            return Err(AdaptorError::InvalidContext(
                "reveal computation input does not match its stage context",
            ));
        }
        let fields = [
            (COMMITMENT_SET_KIND, commitments.as_bytes().as_slice()),
            (REVEAL_SET_KIND, reveal_prefix.as_bytes()),
        ];
        Self::new(
            VaultComputationStageV1::NonceReveal,
            context_binding_digest,
            context,
            &fields,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_partial(
        context_binding_digest: [u8; 32],
        context: SessionContextV1,
        commitments: &ProtocolCommitmentSetV1,
        reveals: &ProtocolRevealSetV1,
        binding_factor: &BindingFactorV1,
        aggregate_nonce_hat: &PublicKey,
        aggregate_signing_key: &PublicKey,
        kernel_message_digest: [u8; 32],
    ) -> Result<Self> {
        if context.signing_phase() != SigningPhaseV1::SigPartial
            || reveals.count() != 2
            || commitments.purpose() != context.purpose()
            || reveals.purpose() != Some(context.purpose())
            || context.message_digest() != &kernel_message_digest
        {
            return Err(AdaptorError::InvalidContext(
                "partial computation input does not match its stage context",
            ));
        }
        let binding_factor = binding_factor.to_be_bytes();
        let aggregate_nonce_hat = aggregate_nonce_hat.to_compressed_bytes();
        let aggregate_signing_key = aggregate_signing_key.to_compressed_bytes();
        let fields = [
            (COMMITMENT_SET_KIND, commitments.as_bytes().as_slice()),
            (REVEAL_SET_KIND, reveals.as_bytes()),
            (BINDING_FACTOR_KIND, binding_factor.as_slice()),
            (AGGREGATE_NONCE_HAT_KIND, aggregate_nonce_hat.as_slice()),
            (AGGREGATE_SIGNING_KEY_KIND, aggregate_signing_key.as_slice()),
            (KERNEL_MESSAGE_DIGEST_KIND, kernel_message_digest.as_slice()),
        ];
        Self::new(
            VaultComputationStageV1::PartialAttempt,
            context_binding_digest,
            context,
            &fields,
        )
    }

    fn new(
        stage: VaultComputationStageV1,
        context_binding_digest: [u8; 32],
        context: SessionContextV1,
        fields: &[(u8, &[u8])],
    ) -> Result<Self> {
        if matches!(stage, VaultComputationStageV1::NonceDerivation) {
            return Err(AdaptorError::InvalidContext(
                "stage computation request rejects nonce derivation",
            ));
        }
        let operation_input =
            CanonicalOperationInputV1::new(stage, context_binding_digest, &context, fields)?;
        Ok(Self {
            stage,
            context_binding_digest,
            context,
            operation_input,
        })
    }

    /// Borrow the immutable validated request view.
    pub fn validated_view(&self) -> ValidatedVaultComputationViewV1<'_> {
        ValidatedVaultComputationViewV1 {
            stage: self.stage,
            reservation_context_binding_digest: &self.context_binding_digest,
            context: &self.context,
            tagged_data: &self.operation_input.tagged_data,
            operation_input_digest: &self.operation_input.digest,
        }
    }

    pub(crate) fn evidence(&self) -> VaultComputationEvidenceV1 {
        VaultComputationEvidenceV1 {
            stage: self.stage,
            context_binding_digest: self.context_binding_digest,
            context: self.context.clone(),
            tagged_data: self.operation_input.tagged_data.clone(),
            operation_input_digest: self.operation_input.digest,
        }
    }
}
