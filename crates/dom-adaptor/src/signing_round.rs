//! Authenticated DSC1 signing-round ownership and one-shot stage authorities.

use crate::vault_operation::{CommitmentEntryV1, RevealEntryV1};
use crate::{
    advance_transcript_hash_v1, aggregate_public_nonces_v1, binding_factor_v1,
    nonce_commitment_hash_v1, session_message_digest_v1, AdaptorError, BindingContextV1,
    BindingFactorV1, NonceCommitmentV1, NonceRevealV1, PartialSignatureV1,
    ParticipantPublicNoncesV1, ParticipantRosterV1, ProtocolCommitmentSetV1, ProtocolRevealSetV1,
    PurposeV1, ResendProtocolStageV1, Result, SessionContextV1, SigningPhaseV1, SigningShareV1,
    StageComputationRequestV1, TrustedChainIdV1,
};
use dom_crypto::{schnorr_verify, PublicKey, SchnorrSignature};

const ENVELOPE_PREFIX_LEN: usize = 148;
const SIGNATURE_LEN: usize = 65;
const FIXED_ENVELOPE_LEN: usize = ENVELOPE_PREFIX_LEN + SIGNATURE_LEN;
const KIND_NONCE_COMMITMENT: u8 = 0x0c;
const KIND_NONCE_REVEAL: u8 = 0x0d;
const KIND_PARTIAL_SIGNATURE: u8 = 0x0e;

/// Result of supplying one authenticated DSC1 message to the round owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptedMessageDispositionV1 {
    /// The exact message was already accepted or buffered byte-for-byte.
    Idempotent,
    /// The message is valid but waits for its canonical predecessor barrier.
    Buffered,
    /// This message, and possibly buffered successors, advanced the transcript.
    Advanced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcceptedMessageKindV1 {
    NonceCommitment,
    NonceReveal,
    PartialSignature,
}

impl AcceptedMessageKindV1 {
    fn parse(byte: u8) -> Result<Self> {
        match byte {
            KIND_NONCE_COMMITMENT => Ok(Self::NonceCommitment),
            KIND_NONCE_REVEAL => Ok(Self::NonceReveal),
            KIND_PARTIAL_SIGNATURE => Ok(Self::PartialSignature),
            _ => Err(AdaptorError::InvalidContext(
                "DSC1 signing message kind is outside the closed registry",
            )),
        }
    }

    const fn phase(self) -> SigningPhaseV1 {
        match self {
            Self::NonceCommitment => SigningPhaseV1::SigNonceCommit,
            Self::NonceReveal => SigningPhaseV1::SigNonceReveal,
            Self::PartialSignature => SigningPhaseV1::SigPartial,
        }
    }

    const fn payload_len(self) -> usize {
        match self {
            Self::NonceCommitment => NonceCommitmentV1::ENCODED_LEN,
            Self::NonceReveal => NonceRevealV1::ENCODED_LEN,
            Self::PartialSignature => PartialSignatureV1::ENCODED_LEN,
        }
    }
}

enum AcceptedPayloadV1 {
    Commitment(NonceCommitmentV1),
    Reveal(NonceRevealV1),
    Partial(PartialSignatureV1),
}

impl AcceptedPayloadV1 {
    fn purpose(&self) -> PurposeV1 {
        match self {
            Self::Commitment(value) => value.purpose(),
            Self::Reveal(value) => value.purpose(),
            Self::Partial(value) => value.purpose(),
        }
    }

    fn participant_index(&self) -> u16 {
        match self {
            Self::Commitment(value) => value.participant_index(),
            Self::Reveal(value) => value.participant_index(),
            Self::Partial(value) => value.participant_index(),
        }
    }
}

/// Immutable exact DSC1 message after canonical parsing and DOM signature verification.
pub struct ValidatedAcceptedSessionMessageV1 {
    kind: AcceptedMessageKindV1,
    chain_id: [u8; 32],
    session_id: [u8; 32],
    sender_participant_id: [u8; 32],
    sender_sequence: u64,
    previous_transcript_hash: [u8; 32],
    unsigned_envelope: Box<[u8]>,
    payload_bytes: Box<[u8]>,
    complete_bytes: Box<[u8]>,
    digest: [u8; 32],
    payload: AcceptedPayloadV1,
}

impl ValidatedAcceptedSessionMessageV1 {
    fn parse(
        bytes: &[u8],
        trusted_chain_id: &TrustedChainIdV1,
        roster: &ParticipantRosterV1,
    ) -> Result<Self> {
        if bytes.len() < FIXED_ENVELOPE_LEN
            || &bytes[..4] != b"DSC1"
            || u16::from_le_bytes([bytes[4], bytes[5]]) != 1
            || bytes[7] != 0
        {
            return Err(AdaptorError::InvalidContext(
                "invalid DSC1 signing envelope",
            ));
        }
        let kind = AcceptedMessageKindV1::parse(bytes[6])?;
        let payload_len = u32::from_le_bytes(
            bytes[144..148]
                .try_into()
                .map_err(|_| AdaptorError::InvalidContext("invalid DSC1 payload length"))?,
        ) as usize;
        let complete_len = FIXED_ENVELOPE_LEN
            .checked_add(payload_len)
            .ok_or(AdaptorError::InvalidContext("DSC1 length overflow"))?;
        if payload_len != kind.payload_len() || bytes.len() != complete_len {
            return Err(AdaptorError::InvalidLength {
                object: "DSC1 signing envelope",
                expected: FIXED_ENVELOPE_LEN + kind.payload_len(),
                actual: bytes.len(),
            });
        }

        let chain_id = exact_32(&bytes[8..40])?;
        let session_id = exact_32(&bytes[40..72])?;
        let sender_participant_id = exact_32(&bytes[72..104])?;
        let previous_transcript_hash = exact_32(&bytes[112..144])?;
        if chain_id != *trusted_chain_id.as_bytes()
            || session_id == [0; 32]
            || sender_participant_id == [0; 32]
            || previous_transcript_hash == [0; 32]
        {
            return Err(AdaptorError::InvalidContext(
                "DSC1 trusted identity or transcript binding mismatch",
            ));
        }
        let sender = roster
            .entries()
            .iter()
            .find(|entry| entry.participant_id() == &sender_participant_id)
            .ok_or(AdaptorError::InvalidContext(
                "DSC1 sender is not in the trusted roster",
            ))?;
        let sender_sequence = u64::from_le_bytes(
            bytes[104..112]
                .try_into()
                .map_err(|_| AdaptorError::InvalidContext("invalid DSC1 sender sequence"))?,
        );
        let payload_end = ENVELOPE_PREFIX_LEN + payload_len;
        let unsigned_envelope = &bytes[..payload_end];
        let payload_bytes = &bytes[ENVELOPE_PREFIX_LEN..payload_end];
        let payload = match kind {
            AcceptedMessageKindV1::NonceCommitment => {
                let value = NonceCommitmentV1::from_bytes(payload_bytes)?;
                if value.to_bytes() != payload_bytes {
                    return Err(AdaptorError::InvalidContext(
                        "noncanonical DSC1 nonce commitment",
                    ));
                }
                AcceptedPayloadV1::Commitment(value)
            }
            AcceptedMessageKindV1::NonceReveal => {
                let value = NonceRevealV1::from_bytes(payload_bytes)?;
                if value.to_bytes() != payload_bytes {
                    return Err(AdaptorError::InvalidContext(
                        "noncanonical DSC1 nonce reveal",
                    ));
                }
                AcceptedPayloadV1::Reveal(value)
            }
            AcceptedMessageKindV1::PartialSignature => {
                let value = PartialSignatureV1::from_bytes(payload_bytes)?;
                if value.to_bytes() != payload_bytes {
                    return Err(AdaptorError::InvalidContext(
                        "noncanonical DSC1 partial signature",
                    ));
                }
                AcceptedPayloadV1::Partial(value)
            }
        };
        payload.purpose().require_strict_phase1()?;
        let expected_index = roster.signing_index(&sender_participant_id)?;
        if payload.participant_index() != expected_index {
            return Err(AdaptorError::InvalidContext(
                "DSC1 payload participant index does not match the trusted roster",
            ));
        }
        let digest = session_message_digest_v1(unsigned_envelope);
        let signature = SchnorrSignature::from_bytes(&bytes[payload_end..])?;
        if !schnorr_verify(
            &signature,
            sender.identity_public_key(),
            trusted_chain_id.as_bytes(),
            &digest,
        )? {
            return Err(AdaptorError::VerificationFailed(
                "DSC1 transport identity signature",
            ));
        }
        Ok(Self {
            kind,
            chain_id,
            session_id,
            sender_participant_id,
            sender_sequence,
            previous_transcript_hash,
            unsigned_envelope: unsigned_envelope.into(),
            payload_bytes: payload_bytes.into(),
            complete_bytes: bytes.into(),
            digest,
            payload,
        })
    }

    /// Return the trusted chain identifier.
    pub const fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }
    /// Return the lifetime-unique session identifier.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
    /// Return the registered sender participant identifier.
    pub const fn sender_participant_id(&self) -> &[u8; 32] {
        &self.sender_participant_id
    }
    /// Return the exact sender sequence.
    pub const fn sender_sequence(&self) -> u64 {
        self.sender_sequence
    }
    /// Return the exact predecessor transcript hash.
    pub const fn previous_transcript_hash(&self) -> &[u8; 32] {
        &self.previous_transcript_hash
    }
    /// Return exact unsigned envelope bytes through the payload.
    pub fn unsigned_envelope(&self) -> &[u8] {
        &self.unsigned_envelope
    }
    /// Return exact canonical payload bytes.
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload_bytes
    }
    /// Return the recomputed canonical session-message digest.
    pub const fn session_message_digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Opaque trusted owner of accepted signing-round transcript state.
pub struct ValidatedSigningRoundStateV1 {
    trusted_chain_id: TrustedChainIdV1,
    base_context: SessionContextV1,
    roster: ParticipantRosterV1,
    local_protocol_index: u16,
    next_sender_sequences: [u64; 2],
    current_transcript: [u8; 32],
    commitment_transcript: Option<[u8; 32]>,
    reveal_transcript: Option<[u8; 32]>,
    pending: Vec<ValidatedAcceptedSessionMessageV1>,
    commitments: Vec<ValidatedAcceptedSessionMessageV1>,
    reveals: Vec<ValidatedAcceptedSessionMessageV1>,
    partials: Vec<ValidatedAcceptedSessionMessageV1>,
    derivation_authority_issued: bool,
    commitment_authority_issued: bool,
    reveal_authority_issued: bool,
    resend_authority_issued: [bool; 3],
    closed: bool,
}

impl ValidatedSigningRoundStateV1 {
    pub(crate) fn new(
        trusted_chain_id: TrustedChainIdV1,
        base_context: SessionContextV1,
        roster: ParticipantRosterV1,
        local_protocol_index: u16,
        signing_share: &SigningShareV1,
        next_sender_sequences: [u64; 2],
    ) -> Result<Self> {
        if trusted_chain_id.as_bytes() != base_context.chain_id()
            || base_context.signing_phase() != SigningPhaseV1::SigNonceCommit
            || base_context.retry_counter() != 0
            || roster.entries().len() != 2
            || local_protocol_index > 1
        {
            return Err(AdaptorError::InvalidContext(
                "invalid trusted signing-round derivation base",
            ));
        }
        base_context.purpose().require_strict_phase1()?;
        let local = &roster.entries()[usize::from(local_protocol_index)];
        if local.signing_public_key() != signing_share.public_key()
            || roster.signing_index(local.participant_id())? != base_context.participant_index()
        {
            return Err(AdaptorError::InvalidContext(
                "signing-round local share does not match the trusted roster",
            ));
        }
        Ok(Self {
            trusted_chain_id,
            current_transcript: *base_context.transcript_hash(),
            commitment_transcript: None,
            reveal_transcript: None,
            base_context,
            roster,
            local_protocol_index,
            next_sender_sequences,
            pending: Vec::new(),
            commitments: Vec::new(),
            reveals: Vec::new(),
            partials: Vec::new(),
            derivation_authority_issued: false,
            commitment_authority_issued: false,
            reveal_authority_issued: false,
            resend_authority_issued: [false; 3],
            closed: false,
        })
    }

    /// Parse, authenticate, buffer, and canonically advance one complete DSC1 message.
    pub fn accept_message(&mut self, bytes: &[u8]) -> Result<AcceptedMessageDispositionV1> {
        if self.closed {
            return Err(AdaptorError::InvalidTranscript("signing round is closed"));
        }
        let message =
            ValidatedAcceptedSessionMessageV1::parse(bytes, &self.trusted_chain_id, &self.roster)?;
        if message.session_id() != self.base_context.session_id()
            || message.payload.purpose() != self.base_context.purpose()
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        for existing in self
            .commitments
            .iter()
            .chain(&self.reveals)
            .chain(&self.partials)
            .chain(&self.pending)
        {
            if existing.sender_participant_id == message.sender_participant_id
                && existing.sender_sequence == message.sender_sequence
            {
                if complete_message_bytes(existing, bytes) {
                    return Ok(AcceptedMessageDispositionV1::Idempotent);
                }
                self.closed = true;
                return Err(AdaptorError::InvalidTranscript(
                    "DSC1 sender sequence equivocation",
                ));
            }
        }
        let sender_index = self
            .roster
            .entries()
            .iter()
            .position(|entry| entry.participant_id() == message.sender_participant_id())
            .ok_or(AdaptorError::AuthorizationMismatch)?;
        if message.sender_sequence < self.next_sender_sequences[sender_index] {
            self.closed = true;
            return Err(AdaptorError::InvalidTranscript(
                "DSC1 sender sequence regressed",
            ));
        }
        self.pending.push(message);
        let advanced = self.drain_ready()?;
        Ok(if advanced {
            AcceptedMessageDispositionV1::Advanced
        } else {
            AcceptedMessageDispositionV1::Buffered
        })
    }

    fn drain_ready(&mut self) -> Result<bool> {
        let mut advanced = false;
        loop {
            let (kind, protocol_index) = if self.commitments.len() < 2 {
                (
                    AcceptedMessageKindV1::NonceCommitment,
                    self.commitments.len(),
                )
            } else if self.reveals.len() < 2 {
                (AcceptedMessageKindV1::NonceReveal, self.reveals.len())
            } else if self.partials.len() < 2 {
                (AcceptedMessageKindV1::PartialSignature, self.partials.len())
            } else {
                break;
            };
            let sender_id = self.roster.entries()[protocol_index].participant_id();
            let Some(position) = self.pending.iter().position(|message| {
                message.kind == kind && message.sender_participant_id() == sender_id
            }) else {
                break;
            };
            let message = &self.pending[position];
            if message.sender_sequence != self.next_sender_sequences[protocol_index]
                || message.previous_transcript_hash != self.current_transcript
            {
                break;
            }
            let message = self.pending.remove(position);
            if let AcceptedPayloadV1::Reveal(reveal) = &message.payload {
                self.verify_reveal(protocol_index, reveal)?;
            }
            self.current_transcript = advance_transcript_hash_v1(
                &self.current_transcript,
                &message.digest,
                self.roster.entries()[protocol_index].direction(),
                kind.phase(),
            );
            self.next_sender_sequences[protocol_index] = self.next_sender_sequences[protocol_index]
                .checked_add(1)
                .ok_or(AdaptorError::InvalidTranscript("DSC1 sequence overflow"))?;
            match kind {
                AcceptedMessageKindV1::NonceCommitment => self.commitments.push(message),
                AcceptedMessageKindV1::NonceReveal => self.reveals.push(message),
                AcceptedMessageKindV1::PartialSignature => self.partials.push(message),
            }
            if self.commitments.len() == 2 && self.commitment_transcript.is_none() {
                self.commitment_transcript = Some(self.current_transcript);
            }
            if self.reveals.len() == 2 && self.reveal_transcript.is_none() {
                self.reveal_transcript = Some(self.current_transcript);
            }
            advanced = true;
        }
        Ok(advanced)
    }

    fn verify_reveal(&self, protocol_index: usize, reveal: &NonceRevealV1) -> Result<()> {
        let commitment = match &self.commitments[protocol_index].payload {
            AcceptedPayloadV1::Commitment(value) => value,
            _ => return Err(AdaptorError::InvalidTranscript("missing nonce commitment")),
        };
        let participant_id = self.roster.entries()[protocol_index].participant_id();
        let digest = nonce_commitment_hash_v1(
            self.base_context.chain_id(),
            self.base_context.session_id(),
            participant_id,
            self.base_context.purpose(),
            self.base_context.template_hash(),
            reveal.first(),
            reveal.second(),
            self.base_context.adaptor_point(),
        )?;
        if digest.as_bytes() != commitment.nonce_reveal_hash() {
            return Err(AdaptorError::InvalidTranscript(
                "nonce reveal does not match its accepted commitment",
            ));
        }
        Ok(())
    }

    /// Consume the unique derivation authority before any commitment is accepted.
    pub fn take_derivation_base(&mut self) -> Result<ValidatedDerivationBaseV1> {
        if self.derivation_authority_issued || !self.commitments.is_empty() {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        self.derivation_authority_issued = true;
        Ok(ValidatedDerivationBaseV1 {
            context: self.base_context.clone(),
            roster: self.roster.clone(),
            local_protocol_index: self.local_protocol_index,
        })
    }

    /// Consume the unique reveal authority after both commitments are accepted.
    pub fn take_commitment_round(&mut self) -> Result<ValidatedCommitmentRoundV1> {
        if self.commitment_authority_issued || self.commitments.len() != 2 {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        self.commitment_authority_issued = true;
        let commitments = self.commitment_set()?;
        let reveal_prefix = self.reveal_prefix(self.local_protocol_index as usize)?;
        let context = self.base_context.with_stage_and_transcript(
            SigningPhaseV1::SigNonceReveal,
            self.commitment_transcript
                .ok_or(AdaptorError::AuthorizationMismatch)?,
        )?;
        Ok(ValidatedCommitmentRoundV1 {
            context,
            commitments,
            reveal_prefix,
            local_protocol_index: self.local_protocol_index,
        })
    }

    /// Consume the unique partial-signing authority after both reveals are accepted.
    pub fn take_reveal_round(&mut self) -> Result<ValidatedRevealRoundV1> {
        if self.reveal_authority_issued || self.reveals.len() != 2 {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        self.reveal_authority_issued = true;
        let commitments = self.commitment_set()?;
        let reveals = self.reveal_prefix(2)?;
        let context = self.base_context.with_stage_and_transcript(
            SigningPhaseV1::SigPartial,
            self.reveal_transcript
                .ok_or(AdaptorError::AuthorizationMismatch)?,
        )?;
        let mut public_nonces = Vec::with_capacity(2);
        for message in &self.reveals {
            let reveal = match &message.payload {
                AcceptedPayloadV1::Reveal(value) => value,
                _ => return Err(AdaptorError::InvalidTranscript("missing nonce reveal")),
            };
            public_nonces.push(ParticipantPublicNoncesV1 {
                participant_index: reveal.participant_index(),
                signing_key: context.participant_public_keys()
                    [usize::from(reveal.participant_index())]
                .clone(),
                first_nonce: reveal.first().clone(),
                second_nonce: reveal.second().clone(),
            });
        }
        public_nonces.sort_by_key(|entry| entry.participant_index);
        let binding_factor = binding_factor_v1(
            &BindingContextV1 {
                chain_id: *context.chain_id(),
                session_id: *context.session_id(),
                purpose: context.purpose(),
                template_hash: *context.template_hash(),
            },
            &public_nonces,
            context.adaptor_point(),
        )?;
        let effective_nonces: Vec<PublicKey> = public_nonces
            .iter()
            .map(|entry| binding_factor.bind_public_nonces(&entry.first_nonce, &entry.second_nonce))
            .collect::<Result<_>>()?;
        let local_effective_nonce =
            effective_nonces[usize::from(context.participant_index())].clone();
        let aggregate_nonce = aggregate_public_nonces_v1(&effective_nonces)?;
        let aggregate_nonce_hat = match context.adaptor_point() {
            Some(point) => aggregate_public_nonces_v1(&[aggregate_nonce, point.clone()])?,
            None => aggregate_nonce,
        };
        let aggregate_signing_key = aggregate_public_nonces_v1(context.participant_public_keys())?;
        Ok(ValidatedRevealRoundV1 {
            context,
            commitments,
            reveals,
            binding_factor,
            local_effective_nonce,
            aggregate_nonce_hat,
            aggregate_signing_key,
        })
    }

    /// Consume current trusted protocol evidence for one exact local resend.
    pub fn authorize_local_resend(
        &mut self,
        protocol_stage: ResendProtocolStageV1,
    ) -> Result<ValidatedResendAuthorizationV1> {
        let stage_index = match protocol_stage {
            ResendProtocolStageV1::Commitment => 0,
            ResendProtocolStageV1::Reveal => 1,
            ResendProtocolStageV1::PartialSignature => 2,
        };
        if self.resend_authority_issued[stage_index] {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let local_index = usize::from(self.local_protocol_index);
        let bytes: &[u8] = match protocol_stage {
            ResendProtocolStageV1::Commitment => self
                .commitments
                .get(local_index)
                .map(ValidatedAcceptedSessionMessageV1::payload_bytes),
            ResendProtocolStageV1::Reveal => self
                .reveals
                .get(local_index)
                .map(ValidatedAcceptedSessionMessageV1::payload_bytes),
            ResendProtocolStageV1::PartialSignature => self
                .partials
                .get(local_index)
                .map(ValidatedAcceptedSessionMessageV1::payload_bytes),
        }
        .ok_or(AdaptorError::AuthorizationMismatch)?;
        let digest = crate::exposure_outbound_digest_v1(protocol_stage.exposure_kind(), bytes)?;
        self.resend_authority_issued[stage_index] = true;
        ValidatedResendAuthorizationV1::new(protocol_stage, *digest.as_bytes())
    }

    fn commitment_set(&self) -> Result<ProtocolCommitmentSetV1> {
        let mut entries = Vec::with_capacity(2);
        for (protocol_index, message) in self.commitments.iter().enumerate() {
            let commitment = match &message.payload {
                AcceptedPayloadV1::Commitment(value) => *value,
                _ => return Err(AdaptorError::InvalidTranscript("missing commitment")),
            };
            entries.push(CommitmentEntryV1::new(
                *self.roster.entries()[protocol_index].participant_id(),
                commitment.participant_index(),
                message.digest,
                commitment,
            )?);
        }
        ProtocolCommitmentSetV1::new(
            entries
                .try_into()
                .map_err(|_| AdaptorError::InvalidTranscript("incomplete commitment set"))?,
        )
    }

    fn reveal_prefix(&self, count: usize) -> Result<ProtocolRevealSetV1> {
        let mut entries = Vec::with_capacity(count);
        for (protocol_index, message) in self.reveals.iter().take(count).enumerate() {
            let reveal = match &message.payload {
                AcceptedPayloadV1::Reveal(value) => value.clone(),
                _ => return Err(AdaptorError::InvalidTranscript("missing reveal")),
            };
            entries.push(RevealEntryV1::new(
                *self.roster.entries()[protocol_index].participant_id(),
                reveal.participant_index(),
                message.digest,
                reveal,
            )?);
        }
        ProtocolRevealSetV1::new(entries)
    }
}

/// Opaque one-shot authority for fresh/resumed nonce derivation.
pub struct ValidatedDerivationBaseV1 {
    context: SessionContextV1,
    roster: ParticipantRosterV1,
    local_protocol_index: u16,
}

impl ValidatedDerivationBaseV1 {
    pub(crate) const fn context(&self) -> &SessionContextV1 {
        &self.context
    }
    pub(crate) const fn roster(&self) -> &ParticipantRosterV1 {
        &self.roster
    }
    pub(crate) const fn local_protocol_index(&self) -> u16 {
        self.local_protocol_index
    }
}

/// Opaque one-shot authority for local nonce reveal computation.
pub struct ValidatedCommitmentRoundV1 {
    context: SessionContextV1,
    commitments: ProtocolCommitmentSetV1,
    reveal_prefix: ProtocolRevealSetV1,
    local_protocol_index: u16,
}

impl ValidatedCommitmentRoundV1 {
    pub(crate) fn into_request(
        self,
        context_binding_digest: [u8; 32],
        effective_retry_counter: u64,
    ) -> Result<StageComputationRequestV1> {
        StageComputationRequestV1::new_reveal(
            context_binding_digest,
            self.context.with_retry_counter(effective_retry_counter),
            &self.commitments,
            &self.reveal_prefix,
            self.local_protocol_index,
        )
    }
}

/// Opaque one-shot authority for local participant partial-signature computation.
pub struct ValidatedRevealRoundV1 {
    context: SessionContextV1,
    commitments: ProtocolCommitmentSetV1,
    reveals: ProtocolRevealSetV1,
    binding_factor: BindingFactorV1,
    local_effective_nonce: PublicKey,
    aggregate_nonce_hat: PublicKey,
    aggregate_signing_key: PublicKey,
}

impl ValidatedRevealRoundV1 {
    pub(crate) fn into_operation(
        self,
        context_binding_digest: [u8; 32],
        effective_retry_counter: u64,
    ) -> Result<(StageComputationRequestV1, ValidatedPartialSigningInputsV1)> {
        let context = self.context.with_retry_counter(effective_retry_counter);
        let request = StageComputationRequestV1::new_partial(
            context_binding_digest,
            context.clone(),
            &self.commitments,
            &self.reveals,
            &self.binding_factor,
            &self.aggregate_nonce_hat,
            &self.aggregate_signing_key,
            *context.message_digest(),
        )?;
        Ok((
            request,
            ValidatedPartialSigningInputsV1 {
                context,
                binding_factor: self.binding_factor,
                local_effective_nonce: self.local_effective_nonce,
                aggregate_nonce_hat: self.aggregate_nonce_hat,
                aggregate_signing_key: self.aggregate_signing_key,
            },
        ))
    }
}

pub(crate) struct ValidatedPartialSigningInputsV1 {
    context: SessionContextV1,
    binding_factor: BindingFactorV1,
    local_effective_nonce: PublicKey,
    aggregate_nonce_hat: PublicKey,
    aggregate_signing_key: PublicKey,
}

impl ValidatedPartialSigningInputsV1 {
    pub(crate) const fn context(&self) -> &SessionContextV1 {
        &self.context
    }
    pub(crate) const fn binding_factor(&self) -> &BindingFactorV1 {
        &self.binding_factor
    }
    pub(crate) const fn local_effective_nonce(&self) -> &PublicKey {
        &self.local_effective_nonce
    }
    pub(crate) const fn aggregate_nonce_hat(&self) -> &PublicKey {
        &self.aggregate_nonce_hat
    }
    pub(crate) const fn aggregate_signing_key(&self) -> &PublicKey {
        &self.aggregate_signing_key
    }
}

/// Opaque one-shot protocol authority for one exact already-recorded resend.
pub struct ValidatedResendAuthorizationV1 {
    protocol_stage: ResendProtocolStageV1,
    adaptor_outbound_digest: [u8; 32],
}

impl ValidatedResendAuthorizationV1 {
    pub(crate) fn new(
        protocol_stage: ResendProtocolStageV1,
        adaptor_outbound_digest: [u8; 32],
    ) -> Result<Self> {
        if adaptor_outbound_digest == [0; 32] {
            return Err(AdaptorError::InvalidTranscript("zero resend digest"));
        }
        Ok(Self {
            protocol_stage,
            adaptor_outbound_digest,
        })
    }

    pub(crate) const fn protocol_stage(&self) -> ResendProtocolStageV1 {
        self.protocol_stage
    }
    pub(crate) const fn adaptor_outbound_digest(&self) -> &[u8; 32] {
        &self.adaptor_outbound_digest
    }
}

fn exact_32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| AdaptorError::InvalidContext("invalid DSC1 fixed field"))
}

fn complete_message_bytes(message: &ValidatedAcceptedSessionMessageV1, candidate: &[u8]) -> bool {
    candidate == message.complete_bytes.as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        initial_transcript_hash_v1, ContractKindV1, DirectionV1, ParticipantIdentityV1,
        SessionContextInputsV1,
    };
    use dom_crypto::{schnorr_sign, SecretKey};

    #[test]
    fn malformed_envelope_fails_before_payload_allocation() {
        let chain = TrustedChainIdV1::from_signed_fixture([7; 32]);
        let share_a = SigningShareV1::from_be_bytes([1; 32]).expect("share");
        let share_b = SigningShareV1::from_be_bytes([2; 32]).expect("share");
        let mut entries = vec![
            crate::ParticipantIdentityV1::new(
                &chain,
                share_a.public_key().clone(),
                share_a.public_key().clone(),
                DirectionV1::Initiator,
            )
            .expect("participant"),
            crate::ParticipantIdentityV1::new(
                &chain,
                share_b.public_key().clone(),
                share_b.public_key().clone(),
                DirectionV1::Responder,
            )
            .expect("participant"),
        ];
        entries.sort_by_key(|entry| *entry.participant_id());
        let roster = ParticipantRosterV1::new(entries).expect("roster");
        assert!(ValidatedAcceptedSessionMessageV1::parse(b"DSC1", &chain, &roster).is_err());
    }

    fn signed_envelope(
        chain: &[u8; 32],
        session: &[u8; 32],
        sender_id: &[u8; 32],
        sequence: u64,
        previous_transcript: &[u8; 32],
        kind: u8,
        payload: &[u8],
        identity_secret: &SecretKey,
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FIXED_ENVELOPE_LEN + payload.len());
        bytes.extend_from_slice(b"DSC1");
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.push(kind);
        bytes.push(0);
        bytes.extend_from_slice(chain);
        bytes.extend_from_slice(session);
        bytes.extend_from_slice(sender_id);
        bytes.extend_from_slice(&sequence.to_le_bytes());
        bytes.extend_from_slice(previous_transcript);
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);
        let digest = session_message_digest_v1(&bytes);
        let signature = schnorr_sign(identity_secret, &digest, chain).expect("transport signature");
        bytes.extend_from_slice(&signature.to_bytes());
        bytes
    }

    #[test]
    fn signed_messages_buffer_then_advance_exact_round_barriers() {
        let chain = TrustedChainIdV1::from_signed_fixture([0x41; 32]);
        let identity_secrets = [
            SecretKey::from_bytes(&[1; 32]).expect("identity secret"),
            SecretKey::from_bytes(&[2; 32]).expect("identity secret"),
        ];
        let signing_shares = [
            SigningShareV1::from_be_bytes([3; 32]).expect("signing share"),
            SigningShareV1::from_be_bytes([4; 32]).expect("signing share"),
        ];
        let mut participants = vec![
            ParticipantIdentityV1::new(
                &chain,
                identity_secrets[0].public_key(),
                signing_shares[0].public_key().clone(),
                DirectionV1::Initiator,
            )
            .expect("participant"),
            ParticipantIdentityV1::new(
                &chain,
                identity_secrets[1].public_key(),
                signing_shares[1].public_key().clone(),
                DirectionV1::Responder,
            )
            .expect("participant"),
        ];
        participants.sort_by_key(|entry| *entry.participant_id());
        let roster = ParticipantRosterV1::new(participants).expect("roster");
        let session = [0x52; 32];
        let initial =
            initial_transcript_hash_v1(&chain, &session, ContractKindV1::WitnessOrTimeout, &roster);
        let mut signing_keys: Vec<_> = roster
            .entries()
            .iter()
            .map(|entry| entry.signing_public_key().clone())
            .collect();
        signing_keys.sort_by_key(|key| key.to_compressed_bytes());
        let local_protocol_index = roster
            .entries()
            .iter()
            .position(|entry| entry.signing_public_key() == signing_shares[0].public_key())
            .expect("local protocol index");
        let local_signing_index = signing_keys
            .iter()
            .position(|key| key == signing_shares[0].public_key())
            .expect("local signing index");
        let context = SessionContextV1::new(
            SessionContextInputsV1 {
                chain_id: *chain.as_bytes(),
                session_id: session,
                purpose: PurposeV1::Refund,
                direction: roster.entries()[local_protocol_index].direction(),
                signing_phase: SigningPhaseV1::SigNonceCommit,
                template_hash: [0x63; 32],
                message_digest: [0x74; 32],
                transcript_hash: initial,
                retry_counter: 0,
                participant_public_keys: signing_keys,
                participant_index: local_signing_index as u16,
                adaptor_point: None,
            },
            &signing_shares[0],
        )
        .expect("context");
        let mut state = ValidatedSigningRoundStateV1::new(
            chain,
            context.clone(),
            roster.clone(),
            local_protocol_index as u16,
            &signing_shares[0],
            [0, 0],
        )
        .expect("round state");
        let _derivation = state.take_derivation_base().expect("derivation authority");

        let nonce_secrets = [
            (
                SigningShareV1::from_be_bytes([5; 32]).expect("nonce"),
                SigningShareV1::from_be_bytes([6; 32]).expect("nonce"),
            ),
            (
                SigningShareV1::from_be_bytes([7; 32]).expect("nonce"),
                SigningShareV1::from_be_bytes([8; 32]).expect("nonce"),
            ),
        ];
        let mut commitment_messages = Vec::new();
        let mut predecessor = initial;
        for (protocol_index, participant) in roster.entries().iter().enumerate() {
            let signing_index = roster
                .signing_index(participant.participant_id())
                .expect("signing index");
            let first = nonce_secrets[protocol_index].0.public_key();
            let second = nonce_secrets[protocol_index].1.public_key();
            let reveal_hash = nonce_commitment_hash_v1(
                context.chain_id(),
                context.session_id(),
                participant.participant_id(),
                context.purpose(),
                context.template_hash(),
                first,
                second,
                None,
            )
            .expect("commitment hash");
            let payload =
                NonceCommitmentV1::new(PurposeV1::Refund, signing_index, *reveal_hash.as_bytes())
                    .to_bytes();
            let identity_index =
                if participant.identity_public_key() == &identity_secrets[0].public_key() {
                    0
                } else {
                    1
                };
            let message = signed_envelope(
                context.chain_id(),
                context.session_id(),
                participant.participant_id(),
                0,
                &predecessor,
                KIND_NONCE_COMMITMENT,
                &payload,
                &identity_secrets[identity_index],
            );
            let digest = session_message_digest_v1(&message[..message.len() - SIGNATURE_LEN]);
            predecessor = advance_transcript_hash_v1(
                &predecessor,
                &digest,
                participant.direction(),
                SigningPhaseV1::SigNonceCommit,
            );
            commitment_messages.push(message);
        }
        assert_eq!(
            state
                .accept_message(&commitment_messages[1])
                .expect("valid early message"),
            AcceptedMessageDispositionV1::Buffered
        );
        assert_eq!(
            state
                .accept_message(&commitment_messages[0])
                .expect("barrier advance"),
            AcceptedMessageDispositionV1::Advanced
        );
        let _reveal_authority = state.take_commitment_round().expect("commitment round");

        for (protocol_index, participant) in roster.entries().iter().enumerate() {
            let signing_index = roster
                .signing_index(participant.participant_id())
                .expect("signing index");
            let payload = NonceRevealV1::new(
                PurposeV1::Refund,
                signing_index,
                nonce_secrets[protocol_index].0.public_key().clone(),
                nonce_secrets[protocol_index].1.public_key().clone(),
            )
            .to_bytes();
            let identity_index =
                if participant.identity_public_key() == &identity_secrets[0].public_key() {
                    0
                } else {
                    1
                };
            let message = signed_envelope(
                context.chain_id(),
                context.session_id(),
                participant.participant_id(),
                1,
                &predecessor,
                KIND_NONCE_REVEAL,
                &payload,
                &identity_secrets[identity_index],
            );
            let digest = session_message_digest_v1(&message[..message.len() - SIGNATURE_LEN]);
            predecessor = advance_transcript_hash_v1(
                &predecessor,
                &digest,
                participant.direction(),
                SigningPhaseV1::SigNonceReveal,
            );
            assert_eq!(
                state.accept_message(&message).expect("accepted reveal"),
                AcceptedMessageDispositionV1::Advanced
            );
        }
        let _partial_authority = state.take_reveal_round().expect("reveal round");

        let mut forged = commitment_messages[0].clone();
        *forged.last_mut().expect("signature byte") ^= 1;
        assert!(ValidatedAcceptedSessionMessageV1::parse(&forged, &chain, &roster).is_err());
    }
}
