//! Authenticated DSC1 signing-round ownership and one-shot stage authorities.

use crate::vault_operation::{CommitmentEntryV1, RevealEntryV1};
use crate::{
    advance_transcript_hash_v1, aggregate_public_nonces_v1, binding_factor_v1,
    nonce_commitment_hash_v1, session_message_digest_v1, AdaptorError, BindingContextV1,
    BindingFactorV1, NonceCommitmentV1, NonceRevealV1, PartialSignatureV1,
    ParticipantPublicNoncesV1, ParticipantRosterV1, ProtocolCommitmentSetV1, ProtocolRevealSetV1,
    PurposeV1, ResendProtocolStageV1, Result, SessionContextV1, SigningPhaseV1,
    StageComputationRequestV1, TrustedChainIdV1,
};
#[cfg(any(test, fuzzing))]
use crate::{
    canonical_template_v1, initial_transcript_hash_v1, ContractKindV1, ParticipantIdentityV1,
    SessionContextInputsV1, SigningShareV1,
};
use dom_crypto::{schnorr_verify, PublicKey, SchnorrSignature};

const ENVELOPE_PREFIX_LEN: usize = 148;
const SIGNATURE_LEN: usize = 65;
const FIXED_ENVELOPE_LEN: usize = ENVELOPE_PREFIX_LEN + SIGNATURE_LEN;
const KIND_NONCE_COMMITMENT: u8 = 0x0c;
const KIND_NONCE_REVEAL: u8 = 0x0d;
const KIND_PARTIAL_SIGNATURE: u8 = 0x0e;
const MAX_PENDING_SIGNING_MESSAGES: usize = 6;

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

    const fn sender_sequence(self) -> u64 {
        match self {
            Self::NonceCommitment => 0,
            Self::NonceReveal => 1,
            Self::PartialSignature => 2,
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

/// Test/evidence-only non-authoritative source values for a fresh signing round.
///
/// This type is deliberately absent from ordinary builds. A production
/// constructor remains blocked until a signed accepted-session authority
/// freezes session uniqueness, accepted terms, and transcript ancestry.
#[cfg(any(test, fuzzing))]
pub(crate) struct SigningRoundSessionRequestV1 {
    session_id: [u8; 32],
    contract_kind: ContractKindV1,
    purpose: PurposeV1,
    roster: ParticipantRosterV1,
    transaction_template: dom_consensus::Transaction,
    kernel_index: usize,
    adaptor_point: Option<PublicKey>,
}

#[cfg(any(test, fuzzing))]
impl SigningRoundSessionRequestV1 {
    pub(crate) fn new(
        session_id: [u8; 32],
        contract_kind: ContractKindV1,
        purpose: PurposeV1,
        roster: ParticipantRosterV1,
        transaction_template: dom_consensus::Transaction,
        kernel_index: usize,
        adaptor_point: Option<PublicKey>,
    ) -> Result<Self> {
        if session_id == [0; 32] || roster.entries().len() != 2 {
            return Err(AdaptorError::InvalidContext(
                "signing round requires a nonzero session and the two-party profile",
            ));
        }
        purpose.require_strict_phase1()?;
        if kernel_index >= transaction_template.kernels.len() {
            return Err(AdaptorError::InvalidContext(
                "signing-round kernel index is outside the transaction template",
            ));
        }
        Ok(Self {
            session_id,
            contract_kind,
            purpose,
            roster,
            transaction_template,
            kernel_index,
            adaptor_point,
        })
    }
}

/// Opaque bootstrap produced only inside the trusted signer boundary.
#[cfg(any(test, fuzzing))]
pub(crate) struct ValidatedSigningRoundBootstrapV1 {
    trusted_chain_id: TrustedChainIdV1,
    base_context: SessionContextV1,
    roster: ParticipantRosterV1,
    local_protocol_index: u16,
}

#[cfg(any(test, fuzzing))]
impl ValidatedSigningRoundBootstrapV1 {
    pub(crate) fn from_session_request(
        trusted_chain_id: TrustedChainIdV1,
        request: SigningRoundSessionRequestV1,
        signing_share: &SigningShareV1,
    ) -> Result<Self> {
        let SigningRoundSessionRequestV1 {
            session_id,
            contract_kind,
            purpose,
            roster,
            transaction_template,
            kernel_index,
            adaptor_point,
        } = request;
        if roster.entries().len() != 2
            || roster
                .entries()
                .iter()
                .filter(|entry| entry.direction() == crate::DirectionV1::Initiator)
                .count()
                != 1
            || roster
                .entries()
                .iter()
                .filter(|entry| entry.direction() == crate::DirectionV1::Responder)
                .count()
                != 1
        {
            return Err(AdaptorError::InvalidContext(
                "signing round requires one initiator and one responder",
            ));
        }
        for entry in roster.entries() {
            let recomputed = ParticipantIdentityV1::new(
                &trusted_chain_id,
                entry.identity_public_key().clone(),
                entry.signing_public_key().clone(),
                entry.direction(),
            )?;
            if recomputed.participant_id() != entry.participant_id() {
                return Err(AdaptorError::InvalidContext(
                    "participant identity does not belong to the trusted chain",
                ));
            }
        }
        let local_protocol_index = roster
            .entries()
            .iter()
            .position(|entry| entry.signing_public_key() == signing_share.public_key())
            .and_then(|index| u16::try_from(index).ok())
            .ok_or(AdaptorError::InvalidContext(
                "local signing share is absent from the protocol roster",
            ))?;
        let mut participant_public_keys: Vec<PublicKey> = roster
            .entries()
            .iter()
            .map(|entry| entry.signing_public_key().clone())
            .collect();
        participant_public_keys.sort_by_key(PublicKey::to_compressed_bytes);
        let participant_index = participant_public_keys
            .iter()
            .position(|key| key == signing_share.public_key())
            .and_then(|index| u16::try_from(index).ok())
            .ok_or(AdaptorError::InvalidContext(
                "local signing share is absent from the canonical signing roster",
            ))?;
        let aggregate_signing_key = aggregate_public_nonces_v1(&participant_public_keys)?;
        let kernel =
            transaction_template
                .kernels
                .get(kernel_index)
                .ok_or(AdaptorError::InvalidContext(
                    "signing-round kernel index is outside the transaction template",
                ))?;
        if kernel.excess.as_bytes() != &aggregate_signing_key.to_compressed_bytes() {
            return Err(AdaptorError::InvalidContext(
                "transaction kernel excess does not equal the aggregate signing key",
            ));
        }
        let (_, template_hash) = canonical_template_v1(&transaction_template)?;
        let kernel_message_digest = dom_consensus::scriptless_kernel_message_digest_v1(kernel);
        let initial_transcript =
            initial_transcript_hash_v1(&trusted_chain_id, &session_id, contract_kind, &roster);
        let local = &roster.entries()[usize::from(local_protocol_index)];
        let base_context = SessionContextV1::new(
            SessionContextInputsV1 {
                chain_id: *trusted_chain_id.as_bytes(),
                session_id,
                purpose,
                direction: local.direction(),
                signing_phase: SigningPhaseV1::SigNonceCommit,
                template_hash,
                message_digest: *kernel_message_digest.as_bytes(),
                transcript_hash: initial_transcript,
                retry_counter: 0,
                participant_public_keys,
                participant_index,
                adaptor_point,
            },
            signing_share,
        )?;
        Ok(Self {
            trusted_chain_id,
            base_context,
            roster,
            local_protocol_index,
        })
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

struct PartialPublicInputsV1 {
    context: SessionContextV1,
    binding_factor: BindingFactorV1,
    effective_nonces: Vec<PublicKey>,
    aggregate_nonce_hat: PublicKey,
    aggregate_signing_key: PublicKey,
}

impl ValidatedSigningRoundStateV1 {
    #[cfg(any(test, fuzzing))]
    pub(crate) fn from_bootstrap(
        bootstrap: ValidatedSigningRoundBootstrapV1,
        signing_share: &SigningShareV1,
    ) -> Result<Self> {
        let ValidatedSigningRoundBootstrapV1 {
            trusted_chain_id,
            base_context,
            roster,
            local_protocol_index,
        } = bootstrap;
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
            next_sender_sequences: [0, 0],
            pending: Vec::with_capacity(MAX_PENDING_SIGNING_MESSAGES),
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
        if message.sender_sequence != message.kind.sender_sequence() {
            self.closed = true;
            return Err(AdaptorError::InvalidTranscript(
                "DSC1 message kind and sender sequence disagree",
            ));
        }
        if message.sender_sequence < self.next_sender_sequences[sender_index] {
            self.closed = true;
            return Err(AdaptorError::InvalidTranscript(
                "DSC1 sender sequence regressed",
            ));
        }
        if self.pending.len() >= MAX_PENDING_SIGNING_MESSAGES {
            self.closed = true;
            return Err(AdaptorError::InvalidTranscript(
                "DSC1 pending-message bound exceeded",
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
                self.closed = true;
                return Err(AdaptorError::InvalidTranscript(
                    "DSC1 message is not the exact next sequence and transcript successor",
                ));
            }
            let message = self.pending.remove(position);
            let semantic_result = match &message.payload {
                AcceptedPayloadV1::Reveal(reveal) => self.verify_reveal(protocol_index, reveal),
                AcceptedPayloadV1::Partial(partial) => self.verify_partial(protocol_index, partial),
                AcceptedPayloadV1::Commitment(_) => Ok(()),
            };
            if let Err(error) = semantic_result {
                self.closed = true;
                return Err(error);
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

    fn verify_partial(&self, protocol_index: usize, partial: &PartialSignatureV1) -> Result<()> {
        let inputs = self.partial_public_inputs()?;
        let participant_index = partial.participant_index();
        if usize::from(participant_index) >= inputs.effective_nonces.len()
            || self
                .roster
                .signing_index(self.roster.entries()[protocol_index].participant_id())?
                != participant_index
            || !partial.verify_bound(
                inputs.context.purpose(),
                inputs.context.template_hash(),
                &inputs.effective_nonces[usize::from(participant_index)],
                &inputs.context.participant_public_keys()[usize::from(participant_index)],
                &inputs.aggregate_nonce_hat,
                &inputs.aggregate_signing_key,
                inputs.context.chain_id(),
                inputs.context.message_digest(),
            )?
        {
            return Err(AdaptorError::VerificationFailed(
                "accepted participant partial signature",
            ));
        }
        Ok(())
    }

    fn partial_public_inputs(&self) -> Result<PartialPublicInputsV1> {
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
        let aggregate_nonce = aggregate_public_nonces_v1(&effective_nonces)?;
        let aggregate_nonce_hat = match context.adaptor_point() {
            Some(point) => aggregate_public_nonces_v1(&[aggregate_nonce, point.clone()])?,
            None => aggregate_nonce,
        };
        let aggregate_signing_key = aggregate_public_nonces_v1(context.participant_public_keys())?;
        Ok(PartialPublicInputsV1 {
            context,
            binding_factor,
            effective_nonces,
            aggregate_nonce_hat,
            aggregate_signing_key,
        })
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
        let inputs = self.partial_public_inputs()?;
        let local_effective_nonce =
            inputs.effective_nonces[usize::from(inputs.context.participant_index())].clone();
        Ok(ValidatedRevealRoundV1 {
            context: inputs.context,
            commitments,
            reveals,
            binding_factor: inputs.binding_factor,
            local_effective_nonce,
            aggregate_nonce_hat: inputs.aggregate_nonce_hat,
            aggregate_signing_key: inputs.aggregate_signing_key,
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

/// Fuzz-only DSC1 parser and accepted-round transition harness.
///
/// This symbol exists only under cargo-fuzz's `cfg(fuzzing)` build and cannot
/// be enabled by a Cargo feature or resolved by a production build.
#[cfg(fuzzing)]
pub fn fuzz_dsc1_signing_round_acceptance_v1(data: &[u8]) {
    let _ = fuzz_dsc1_signing_round_acceptance_inner(data);
}

#[cfg(fuzzing)]
fn fuzz_dsc1_signing_round_acceptance_inner(data: &[u8]) -> Result<()> {
    use dom_consensus::{Transaction, TransactionKernel};
    use dom_core::{Amount, Hash256};
    use dom_crypto::pedersen::Commitment;
    use dom_crypto::{schnorr_challenge, PartialSig, SecretKey};

    let trusted_chain =
        TrustedChainIdV1::from_authenticated_genesis(0x5343_465a, &Hash256::from_bytes([0x41; 32]));
    let identity_a = SecretKey::from_bytes(&[0x11; 32])?;
    let identity_b = SecretKey::from_bytes(&[0x12; 32])?;
    let share_a = SigningShareV1::from_be_bytes([0x13; 32])?;
    let share_b = SigningShareV1::from_be_bytes([0x14; 32])?;
    let mut entries = vec![
        ParticipantIdentityV1::new(
            &trusted_chain,
            identity_a.public_key(),
            share_a.public_key().clone(),
            crate::DirectionV1::Initiator,
        )?,
        ParticipantIdentityV1::new(
            &trusted_chain,
            identity_b.public_key(),
            share_b.public_key().clone(),
            crate::DirectionV1::Responder,
        )?,
    ];
    entries.sort_by_key(|entry| *entry.participant_id());
    let roster = ParticipantRosterV1::new(entries)?;
    let mut signing_keys: Vec<_> = roster
        .entries()
        .iter()
        .map(|entry| entry.signing_public_key().clone())
        .collect();
    signing_keys.sort_by_key(PublicKey::to_compressed_bytes);
    let aggregate = aggregate_public_nonces_v1(&signing_keys)?;
    let transaction_template = Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
        kernels: vec![TransactionKernel {
            features: 0,
            fee: Amount::ZERO,
            lock_height: 0,
            excess: Commitment::from_compressed_bytes(&aggregate.to_compressed_bytes())?,
            excess_signature: [0; 65],
        }],
        offset: [0x15; 32],
    };
    let local_share = if roster.entries()[0].signing_public_key() == share_a.public_key() {
        &share_a
    } else {
        &share_b
    };
    let request = SigningRoundSessionRequestV1::new(
        [0x16; 32],
        ContractKindV1::WitnessOrTimeout,
        PurposeV1::Refund,
        roster,
        transaction_template,
        0,
        None,
    )?;
    let bootstrap = ValidatedSigningRoundBootstrapV1::from_session_request(
        trusted_chain,
        request,
        local_share,
    )?;
    let mut state = ValidatedSigningRoundStateV1::from_bootstrap(bootstrap, local_share)?;
    let selector = data.first().copied().unwrap_or(0);
    let arbitrary = data.get(1..).unwrap_or_default();
    let _ = state.accept_message(arbitrary);
    if state.closed {
        return Ok(());
    }

    let nonce_pairs = [
        (
            SigningShareV1::from_be_bytes([0x21; 32])?,
            SigningShareV1::from_be_bytes([0x22; 32])?,
        ),
        (
            SigningShareV1::from_be_bytes([0x23; 32])?,
            SigningShareV1::from_be_bytes([0x24; 32])?,
        ),
    ];
    let identity_secret = |participant: &ParticipantIdentityV1| {
        if participant.identity_public_key() == &identity_a.public_key() {
            &identity_a
        } else {
            &identity_b
        }
    };
    let mut predecessor = state.current_transcript;
    let mut commitments = Vec::with_capacity(2);
    for (protocol_index, participant) in state.roster.entries().iter().enumerate() {
        let signing_index = state.roster.signing_index(participant.participant_id())?;
        let digest = nonce_commitment_hash_v1(
            state.base_context.chain_id(),
            state.base_context.session_id(),
            participant.participant_id(),
            state.base_context.purpose(),
            state.base_context.template_hash(),
            nonce_pairs[protocol_index].0.public_key(),
            nonce_pairs[protocol_index].1.public_key(),
            state.base_context.adaptor_point(),
        )?;
        let payload = NonceCommitmentV1::new(
            state.base_context.purpose(),
            signing_index,
            *digest.as_bytes(),
        )
        .to_bytes();
        let message = fuzz_signed_envelope(
            state.base_context.chain_id(),
            state.base_context.session_id(),
            participant.participant_id(),
            0,
            &predecessor,
            KIND_NONCE_COMMITMENT,
            &payload,
            identity_secret(participant),
        )?;
        predecessor = advance_transcript_hash_v1(
            &predecessor,
            &session_message_digest_v1(&message[..message.len() - SIGNATURE_LEN]),
            participant.direction(),
            SigningPhaseV1::SigNonceCommit,
        );
        commitments.push(message);
    }
    let commitment_order = if selector & 1 == 0 { [0, 1] } else { [1, 0] };
    for index in commitment_order {
        let _ = state.accept_message(&commitments[index]);
    }
    if selector & 2 != 0 {
        let _ = state.accept_message(&commitments[0]);
    }
    if selector & 4 != 0 {
        let mut equivocation = commitments[0].clone();
        let payload_last = equivocation.len() - SIGNATURE_LEN - 1;
        equivocation[payload_last] ^= data.get(1).copied().unwrap_or(1) | 1;
        fuzz_resign_envelope(
            &mut equivocation,
            identity_secret(&state.roster.entries()[0]),
            state.base_context.chain_id(),
        )?;
        let _ = state.accept_message(&equivocation);
        return Ok(());
    }

    let mut reveals = Vec::with_capacity(2);
    for (protocol_index, participant) in state.roster.entries().iter().enumerate() {
        let signing_index = state.roster.signing_index(participant.participant_id())?;
        let (first, second) = if selector & 16 != 0 && protocol_index == 0 {
            (
                SigningShareV1::from_be_bytes([0x31; 32])?
                    .public_key()
                    .clone(),
                SigningShareV1::from_be_bytes([0x32; 32])?
                    .public_key()
                    .clone(),
            )
        } else {
            (
                nonce_pairs[protocol_index].0.public_key().clone(),
                nonce_pairs[protocol_index].1.public_key().clone(),
            )
        };
        let payload =
            NonceRevealV1::new(state.base_context.purpose(), signing_index, first, second)
                .to_bytes();
        let message = fuzz_signed_envelope(
            state.base_context.chain_id(),
            state.base_context.session_id(),
            participant.participant_id(),
            1,
            &predecessor,
            KIND_NONCE_REVEAL,
            &payload,
            identity_secret(participant),
        )?;
        predecessor = advance_transcript_hash_v1(
            &predecessor,
            &session_message_digest_v1(&message[..message.len() - SIGNATURE_LEN]),
            participant.direction(),
            SigningPhaseV1::SigNonceReveal,
        );
        reveals.push(message);
    }
    let reveal_order = if selector & 8 == 0 { [0, 1] } else { [1, 0] };
    for index in reveal_order {
        let _ = state.accept_message(&reveals[index]);
    }
    if state.closed || state.reveals.len() != 2 {
        return Ok(());
    }
    if selector & 32 != 0 {
        let _ = state.accept_message(&reveals[0]);
    }
    if selector & 64 == 0 {
        return Ok(());
    }

    let participant = &state.roster.entries()[0];
    let participant_share = if participant.signing_public_key() == share_a.public_key() {
        &share_a
    } else {
        &share_b
    };
    let inputs = state.partial_public_inputs()?;
    let challenge = schnorr_challenge(
        &inputs.aggregate_nonce_hat.to_compressed_bytes(),
        &inputs.aggregate_signing_key,
        state.base_context.chain_id(),
        state.base_context.message_digest(),
    );
    let binding = PartialSig::from_bytes(&inputs.binding_factor.to_be_bytes())?;
    let nonce_pair = crate::secret_nonce::SecretNoncePairV1::from_be_bytes(
        *nonce_pairs[0].0.as_be_bytes(),
        *nonce_pairs[0].1.as_be_bytes(),
    )?;
    let partial =
        nonce_pair.sign_bound_partial(&binding, challenge.as_bytes(), participant_share)?;
    let payload = PartialSignatureV1::new(
        state.base_context.purpose(),
        state.roster.signing_index(participant.participant_id())?,
        *state.base_context.template_hash(),
        partial,
    )
    .to_bytes();
    let mut message = fuzz_signed_envelope(
        state.base_context.chain_id(),
        state.base_context.session_id(),
        participant.participant_id(),
        2,
        &predecessor,
        KIND_PARTIAL_SIGNATURE,
        &payload,
        identity_secret(participant),
    )?;
    if selector & 128 != 0 {
        let payload_last = message.len() - SIGNATURE_LEN - 1;
        message[payload_last] ^= data.get(2).copied().unwrap_or(1) | 1;
        fuzz_resign_envelope(
            &mut message,
            identity_secret(participant),
            state.base_context.chain_id(),
        )?;
    }
    let _ = state.accept_message(&message);
    Ok(())
}

#[cfg(fuzzing)]
#[allow(clippy::too_many_arguments)]
fn fuzz_signed_envelope(
    chain_id: &[u8; 32],
    session_id: &[u8; 32],
    sender_id: &[u8; 32],
    sequence: u64,
    predecessor: &[u8; 32],
    kind: u8,
    payload: &[u8],
    identity_secret: &dom_crypto::SecretKey,
) -> Result<Vec<u8>> {
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| AdaptorError::InvalidContext("DSC1 fuzz payload length overflow"))?;
    let mut bytes = Vec::with_capacity(FIXED_ENVELOPE_LEN + payload.len());
    bytes.extend_from_slice(b"DSC1");
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.push(kind);
    bytes.push(0);
    bytes.extend_from_slice(chain_id);
    bytes.extend_from_slice(session_id);
    bytes.extend_from_slice(sender_id);
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(predecessor);
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes.extend_from_slice(payload);
    let digest = session_message_digest_v1(&bytes);
    let signature = dom_crypto::schnorr_sign(identity_secret, &digest, chain_id)?;
    bytes.extend_from_slice(&signature.to_bytes());
    Ok(bytes)
}

#[cfg(fuzzing)]
fn fuzz_resign_envelope(
    bytes: &mut [u8],
    identity_secret: &dom_crypto::SecretKey,
    chain_id: &[u8; 32],
) -> Result<()> {
    let signature_offset = bytes
        .len()
        .checked_sub(SIGNATURE_LEN)
        .ok_or(AdaptorError::InvalidContext("DSC1 fuzz envelope truncated"))?;
    let digest = session_message_digest_v1(&bytes[..signature_offset]);
    let signature = dom_crypto::schnorr_sign(identity_secret, &digest, chain_id)?;
    bytes[signature_offset..].copy_from_slice(&signature.to_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{initial_transcript_hash_v1, ContractKindV1, DirectionV1, ParticipantIdentityV1};
    use dom_consensus::{Transaction, TransactionKernel};
    use dom_core::Amount;
    use dom_crypto::pedersen::Commitment;
    use dom_crypto::{schnorr_challenge, schnorr_sign, PartialSig, SecretKey};

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

    #[allow(clippy::too_many_arguments)]
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

    fn resign_envelope(bytes: &mut [u8], identity_secret: &SecretKey, chain: &[u8; 32]) {
        let signature_offset = bytes
            .len()
            .checked_sub(SIGNATURE_LEN)
            .expect("complete test envelope");
        let digest = session_message_digest_v1(&bytes[..signature_offset]);
        let signature = schnorr_sign(identity_secret, &digest, chain).expect("transport signature");
        bytes[signature_offset..].copy_from_slice(&signature.to_bytes());
    }

    fn transaction_for_signing_keys(signing_keys: &[PublicKey]) -> Transaction {
        let aggregate = aggregate_public_nonces_v1(signing_keys).expect("aggregate signing key");
        Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            kernels: vec![TransactionKernel {
                features: 0,
                fee: Amount::ZERO,
                lock_height: 0,
                excess: Commitment::from_compressed_bytes(&aggregate.to_compressed_bytes())
                    .expect("aggregate excess"),
                excess_signature: [0; 65],
            }],
            offset: [0x2a; 32],
        }
    }

    struct CommitmentFixture {
        chain: TrustedChainIdV1,
        roster: ParticipantRosterV1,
        identity_secrets: [SecretKey; 2],
        state: ValidatedSigningRoundStateV1,
        messages: [Vec<u8>; 2],
    }

    impl CommitmentFixture {
        fn sender_secret_index(&self, message: &[u8]) -> usize {
            let sender_id: [u8; 32] = message[72..104].try_into().expect("sender ID");
            let identity_key = self
                .roster
                .entries()
                .iter()
                .find(|entry| entry.participant_id() == &sender_id)
                .expect("registered sender")
                .identity_public_key();
            self.identity_secrets
                .iter()
                .position(|secret| &secret.public_key() == identity_key)
                .expect("sender identity secret")
        }

        fn sender_secret(&self, message: &[u8]) -> &SecretKey {
            &self.identity_secrets[self.sender_secret_index(message)]
        }

        fn protocol_identity_secret(&self, protocol_index: usize) -> &SecretKey {
            let identity_key = self.roster.entries()[protocol_index].identity_public_key();
            self.identity_secrets
                .iter()
                .find(|secret| &secret.public_key() == identity_key)
                .expect("protocol identity secret")
        }
    }

    fn protocol_nonce_pair(protocol_index: usize) -> (SigningShareV1, SigningShareV1) {
        let (first, second) = match protocol_index {
            0 => ([0x15; 32], [0x16; 32]),
            1 => ([0x17; 32], [0x18; 32]),
            _ => panic!("two-party protocol index"),
        };
        (
            SigningShareV1::from_be_bytes(first).expect("first nonce"),
            SigningShareV1::from_be_bytes(second).expect("second nonce"),
        )
    }

    fn commitment_fixture() -> CommitmentFixture {
        let chain = TrustedChainIdV1::from_signed_fixture([0x31; 32]);
        let identity_secrets = [
            SecretKey::from_bytes(&[0x11; 32]).expect("identity secret"),
            SecretKey::from_bytes(&[0x12; 32]).expect("identity secret"),
        ];
        let signing_shares = [
            SigningShareV1::from_be_bytes([0x13; 32]).expect("signing share"),
            SigningShareV1::from_be_bytes([0x14; 32]).expect("signing share"),
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
        let mut signing_keys: Vec<_> = roster
            .entries()
            .iter()
            .map(|entry| entry.signing_public_key().clone())
            .collect();
        signing_keys.sort_by_key(PublicKey::to_compressed_bytes);
        let transaction = transaction_for_signing_keys(&signing_keys);
        let session_id = [0x32; 32];
        let local_share =
            if roster.entries()[0].signing_public_key() == signing_shares[0].public_key() {
                &signing_shares[0]
            } else {
                &signing_shares[1]
            };
        let request = SigningRoundSessionRequestV1::new(
            session_id,
            ContractKindV1::WitnessOrTimeout,
            PurposeV1::Refund,
            roster.clone(),
            transaction,
            0,
            None,
        )
        .expect("round request");
        let bootstrap =
            ValidatedSigningRoundBootstrapV1::from_session_request(chain, request, local_share)
                .expect("bootstrap");
        let state = ValidatedSigningRoundStateV1::from_bootstrap(bootstrap, local_share)
            .expect("round state");
        let context = state.base_context.clone();
        let nonce_secrets = [
            (
                SigningShareV1::from_be_bytes([0x15; 32]).expect("nonce"),
                SigningShareV1::from_be_bytes([0x16; 32]).expect("nonce"),
            ),
            (
                SigningShareV1::from_be_bytes([0x17; 32]).expect("nonce"),
                SigningShareV1::from_be_bytes([0x18; 32]).expect("nonce"),
            ),
        ];
        let mut predecessor = *context.transcript_hash();
        let mut messages = Vec::with_capacity(2);
        for (protocol_index, participant) in roster.entries().iter().enumerate() {
            let signing_index = roster
                .signing_index(participant.participant_id())
                .expect("signing index");
            let digest = nonce_commitment_hash_v1(
                context.chain_id(),
                context.session_id(),
                participant.participant_id(),
                context.purpose(),
                context.template_hash(),
                nonce_secrets[protocol_index].0.public_key(),
                nonce_secrets[protocol_index].1.public_key(),
                None,
            )
            .expect("commitment digest");
            let payload =
                NonceCommitmentV1::new(PurposeV1::Refund, signing_index, *digest.as_bytes())
                    .to_bytes();
            let identity_secret = identity_secrets
                .iter()
                .find(|secret| &secret.public_key() == participant.identity_public_key())
                .expect("identity secret");
            let message = signed_envelope(
                context.chain_id(),
                context.session_id(),
                participant.participant_id(),
                0,
                &predecessor,
                KIND_NONCE_COMMITMENT,
                &payload,
                identity_secret,
            );
            let message_digest =
                session_message_digest_v1(&message[..message.len() - SIGNATURE_LEN]);
            predecessor = advance_transcript_hash_v1(
                &predecessor,
                &message_digest,
                participant.direction(),
                SigningPhaseV1::SigNonceCommit,
            );
            messages.push(message);
        }
        CommitmentFixture {
            chain,
            roster,
            identity_secrets,
            state,
            messages: messages.try_into().expect("two commitment messages"),
        }
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
        let aggregate_signing_key =
            aggregate_public_nonces_v1(&signing_keys).expect("aggregate signing key");
        let transaction = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            kernels: vec![TransactionKernel {
                features: 0,
                fee: Amount::ZERO,
                lock_height: 0,
                excess: Commitment::from_compressed_bytes(
                    &aggregate_signing_key.to_compressed_bytes(),
                )
                .expect("aggregate excess"),
                excess_signature: [0; 65],
            }],
            offset: [0x19; 32],
        };
        let request = SigningRoundSessionRequestV1::new(
            session,
            ContractKindV1::WitnessOrTimeout,
            PurposeV1::Refund,
            roster.clone(),
            transaction,
            0,
            None,
        )
        .expect("round request");
        let bootstrap = ValidatedSigningRoundBootstrapV1::from_session_request(
            chain,
            request,
            &signing_shares[0],
        )
        .expect("trusted bootstrap");
        let mut state = ValidatedSigningRoundStateV1::from_bootstrap(bootstrap, &signing_shares[0])
            .expect("round state");
        let context = state.base_context.clone();
        assert_eq!(context.transcript_hash(), &initial);
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

        let inputs = state.partial_public_inputs().expect("partial inputs");
        let challenge = schnorr_challenge(
            &inputs.aggregate_nonce_hat.to_compressed_bytes(),
            &inputs.aggregate_signing_key,
            context.chain_id(),
            context.message_digest(),
        );
        let binding =
            PartialSig::from_bytes(&inputs.binding_factor.to_be_bytes()).expect("binding scalar");
        for (protocol_index, participant) in roster.entries().iter().enumerate() {
            let signing_index = roster
                .signing_index(participant.participant_id())
                .expect("signing index");
            let pair = crate::secret_nonce::SecretNoncePairV1::from_be_bytes(
                *nonce_secrets[protocol_index].0.as_be_bytes(),
                *nonce_secrets[protocol_index].1.as_be_bytes(),
            )
            .expect("nonce pair");
            let partial = pair
                .sign_bound_partial(
                    &binding,
                    challenge.as_bytes(),
                    &signing_shares[protocol_index],
                )
                .expect("partial scalar");
            let payload = PartialSignatureV1::new(
                PurposeV1::Refund,
                signing_index,
                *context.template_hash(),
                partial,
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
                2,
                &predecessor,
                KIND_PARTIAL_SIGNATURE,
                &payload,
                &identity_secrets[identity_index],
            );
            let digest = session_message_digest_v1(&message[..message.len() - SIGNATURE_LEN]);
            predecessor = advance_transcript_hash_v1(
                &predecessor,
                &digest,
                participant.direction(),
                SigningPhaseV1::SigPartial,
            );
            assert_eq!(
                state.accept_message(&message).expect("accepted partial"),
                AcceptedMessageDispositionV1::Advanced
            );
        }
        assert_eq!(state.partials.len(), 2);

        let mut forged = commitment_messages[0].clone();
        *forged.last_mut().expect("signature byte") ^= 1;
        assert!(ValidatedAcceptedSessionMessageV1::parse(&forged, &chain, &roster).is_err());
    }

    #[test]
    fn production_bootstrap_recomputes_context_and_rejects_untrusted_sources() {
        let fixture = commitment_fixture();
        let expected_initial = initial_transcript_hash_v1(
            &fixture.chain,
            fixture.state.base_context.session_id(),
            ContractKindV1::WitnessOrTimeout,
            &fixture.roster,
        );
        assert_eq!(
            fixture.state.base_context.transcript_hash(),
            &expected_initial
        );
        assert_eq!(fixture.state.next_sender_sequences, [0, 0]);

        let foreign_chain = TrustedChainIdV1::from_signed_fixture([0x61; 32]);
        let signing_share = SigningShareV1::from_be_bytes([0x13; 32]).expect("signing share");
        let signing_keys: Vec<_> = fixture
            .roster
            .entries()
            .iter()
            .map(|entry| entry.signing_public_key().clone())
            .collect();
        let request = SigningRoundSessionRequestV1::new(
            [0x62; 32],
            ContractKindV1::WitnessOrTimeout,
            PurposeV1::Refund,
            fixture.roster.clone(),
            transaction_for_signing_keys(&signing_keys),
            0,
            None,
        )
        .expect("source request");
        assert!(ValidatedSigningRoundBootstrapV1::from_session_request(
            foreign_chain,
            request,
            &signing_share,
        )
        .is_err());

        let chain = TrustedChainIdV1::from_signed_fixture([0x71; 32]);
        let identities = [
            SecretKey::from_bytes(&[0x21; 32]).expect("identity"),
            SecretKey::from_bytes(&[0x22; 32]).expect("identity"),
        ];
        let shares = [
            SigningShareV1::from_be_bytes([0x23; 32]).expect("share"),
            SigningShareV1::from_be_bytes([0x24; 32]).expect("share"),
        ];
        let mut participants = vec![
            ParticipantIdentityV1::new(
                &chain,
                identities[0].public_key(),
                shares[0].public_key().clone(),
                DirectionV1::Initiator,
            )
            .expect("participant"),
            ParticipantIdentityV1::new(
                &chain,
                identities[1].public_key(),
                shares[1].public_key().clone(),
                DirectionV1::Responder,
            )
            .expect("participant"),
        ];
        participants.sort_by_key(|entry| *entry.participant_id());
        let roster = ParticipantRosterV1::new(participants).expect("roster");
        let mut signing_keys: Vec<_> = roster
            .entries()
            .iter()
            .map(|entry| entry.signing_public_key().clone())
            .collect();
        signing_keys.sort_by_key(PublicKey::to_compressed_bytes);
        let mut wrong_transaction = transaction_for_signing_keys(&signing_keys);
        wrong_transaction.kernels[0].excess = Commitment::from_compressed_bytes(
            &SigningShareV1::from_be_bytes([0x25; 32])
                .expect("different key")
                .public_key()
                .to_compressed_bytes(),
        )
        .expect("different excess");
        let local_share = if roster.entries()[0].signing_public_key() == shares[0].public_key() {
            &shares[0]
        } else {
            &shares[1]
        };
        let request = SigningRoundSessionRequestV1::new(
            [0x72; 32],
            ContractKindV1::WitnessOrTimeout,
            PurposeV1::Refund,
            roster,
            wrong_transaction,
            0,
            None,
        )
        .expect("source request");
        assert!(ValidatedSigningRoundBootstrapV1::from_session_request(
            chain,
            request,
            local_share,
        )
        .is_err());
    }

    #[test]
    fn dsc1_header_payload_and_trailing_mutations_fail_closed() {
        let mut fixture = commitment_fixture();
        let original = fixture.messages[0].clone();
        let sender_secret_index = fixture.sender_secret_index(&original);

        for (offset, replacement) in [(0usize, b'X'), (4, 2), (6, 0xff), (7, 1)] {
            let mut mutated = original.clone();
            mutated[offset] = replacement;
            resign_envelope(
                &mut mutated,
                &fixture.identity_secrets[sender_secret_index],
                fixture.chain.as_bytes(),
            );
            assert!(fixture.state.accept_message(&mutated).is_err());
            fixture = commitment_fixture();
        }

        for offset in [8usize, 40, 72, 144, 147, 148, 149] {
            let mut mutated = fixture.messages[0].clone();
            mutated[offset] ^= 1;
            resign_envelope(
                &mut mutated,
                &fixture.identity_secrets[sender_secret_index],
                fixture.chain.as_bytes(),
            );
            assert!(fixture.state.accept_message(&mutated).is_err());
            fixture = commitment_fixture();
        }

        let mut trailing = fixture.messages[0].clone();
        trailing.push(0);
        assert!(fixture.state.accept_message(&trailing).is_err());
    }

    #[test]
    fn duplicate_is_idempotent_and_authenticated_equivocation_closes_round() {
        let mut fixture = commitment_fixture();
        assert_eq!(
            fixture
                .state
                .accept_message(&fixture.messages[0])
                .expect("first acceptance"),
            AcceptedMessageDispositionV1::Advanced,
        );
        assert_eq!(
            fixture
                .state
                .accept_message(&fixture.messages[0])
                .expect("exact duplicate"),
            AcceptedMessageDispositionV1::Idempotent,
        );

        let mut equivocation = fixture.messages[0].clone();
        equivocation[151] ^= 1;
        let identity_secret = fixture.sender_secret(&equivocation);
        resign_envelope(&mut equivocation, identity_secret, fixture.chain.as_bytes());
        assert!(fixture.state.accept_message(&equivocation).is_err());
        assert!(fixture.state.closed);
        assert!(fixture.state.accept_message(&fixture.messages[1]).is_err());
    }

    #[test]
    fn semantic_reveal_and_partial_failures_permanently_close_the_logical_slot() {
        let mut reveal_fixture = commitment_fixture();
        for message in &reveal_fixture.messages {
            assert_eq!(
                reveal_fixture
                    .state
                    .accept_message(message)
                    .expect("accepted commitment"),
                AcceptedMessageDispositionV1::Advanced,
            );
        }
        let participant = &reveal_fixture.roster.entries()[0];
        let signing_index = reveal_fixture
            .roster
            .signing_index(participant.participant_id())
            .expect("signing index");
        let predecessor = reveal_fixture.state.current_transcript;
        let wrong_pair = (
            SigningShareV1::from_be_bytes([0x21; 32]).expect("wrong nonce"),
            SigningShareV1::from_be_bytes([0x22; 32]).expect("wrong nonce"),
        );
        let wrong_reveal = NonceRevealV1::new(
            PurposeV1::Refund,
            signing_index,
            wrong_pair.0.public_key().clone(),
            wrong_pair.1.public_key().clone(),
        )
        .to_bytes();
        let wrong_message = signed_envelope(
            reveal_fixture.state.base_context.chain_id(),
            reveal_fixture.state.base_context.session_id(),
            participant.participant_id(),
            1,
            &predecessor,
            KIND_NONCE_REVEAL,
            &wrong_reveal,
            reveal_fixture.protocol_identity_secret(0),
        );
        assert!(ValidatedAcceptedSessionMessageV1::parse(
            &wrong_message,
            &reveal_fixture.chain,
            &reveal_fixture.roster,
        )
        .is_ok());
        assert!(reveal_fixture.state.accept_message(&wrong_message).is_err());
        assert!(reveal_fixture.state.closed);

        let correct_pair = protocol_nonce_pair(0);
        let correct_reveal = NonceRevealV1::new(
            PurposeV1::Refund,
            signing_index,
            correct_pair.0.public_key().clone(),
            correct_pair.1.public_key().clone(),
        )
        .to_bytes();
        let corrected_message = signed_envelope(
            reveal_fixture.state.base_context.chain_id(),
            reveal_fixture.state.base_context.session_id(),
            participant.participant_id(),
            1,
            &predecessor,
            KIND_NONCE_REVEAL,
            &correct_reveal,
            reveal_fixture.protocol_identity_secret(0),
        );
        assert!(reveal_fixture
            .state
            .accept_message(&corrected_message)
            .is_err());

        let mut partial_fixture = commitment_fixture();
        for message in &partial_fixture.messages {
            partial_fixture
                .state
                .accept_message(message)
                .expect("accepted commitment");
        }
        for protocol_index in 0..2 {
            let participant = &partial_fixture.roster.entries()[protocol_index];
            let signing_index = partial_fixture
                .roster
                .signing_index(participant.participant_id())
                .expect("signing index");
            let pair = protocol_nonce_pair(protocol_index);
            let payload = NonceRevealV1::new(
                PurposeV1::Refund,
                signing_index,
                pair.0.public_key().clone(),
                pair.1.public_key().clone(),
            )
            .to_bytes();
            let message = signed_envelope(
                partial_fixture.state.base_context.chain_id(),
                partial_fixture.state.base_context.session_id(),
                participant.participant_id(),
                1,
                &partial_fixture.state.current_transcript,
                KIND_NONCE_REVEAL,
                &payload,
                partial_fixture.protocol_identity_secret(protocol_index),
            );
            partial_fixture
                .state
                .accept_message(&message)
                .expect("accepted reveal");
        }
        let inputs = partial_fixture
            .state
            .partial_public_inputs()
            .expect("partial inputs");
        let challenge = schnorr_challenge(
            &inputs.aggregate_nonce_hat.to_compressed_bytes(),
            &inputs.aggregate_signing_key,
            partial_fixture.state.base_context.chain_id(),
            partial_fixture.state.base_context.message_digest(),
        );
        let binding =
            PartialSig::from_bytes(&inputs.binding_factor.to_be_bytes()).expect("binding scalar");
        let participant = &partial_fixture.roster.entries()[0];
        let signing_share = [[0x13; 32], [0x14; 32]]
            .into_iter()
            .map(|bytes| SigningShareV1::from_be_bytes(bytes).expect("signing share"))
            .find(|share| share.public_key() == participant.signing_public_key())
            .expect("participant signing share");
        let nonce_pair = protocol_nonce_pair(0);
        let nonce_pair = crate::secret_nonce::SecretNoncePairV1::from_be_bytes(
            *nonce_pair.0.as_be_bytes(),
            *nonce_pair.1.as_be_bytes(),
        )
        .expect("nonce pair");
        let partial = nonce_pair
            .sign_bound_partial(&binding, challenge.as_bytes(), &signing_share)
            .expect("partial scalar");
        let payload = PartialSignatureV1::new(
            PurposeV1::Refund,
            partial_fixture
                .roster
                .signing_index(participant.participant_id())
                .expect("signing index"),
            *partial_fixture.state.base_context.template_hash(),
            partial,
        )
        .to_bytes();
        let correct_message = signed_envelope(
            partial_fixture.state.base_context.chain_id(),
            partial_fixture.state.base_context.session_id(),
            participant.participant_id(),
            2,
            &partial_fixture.state.current_transcript,
            KIND_PARTIAL_SIGNATURE,
            &payload,
            partial_fixture.protocol_identity_secret(0),
        );
        let mut wrong_message = correct_message.clone();
        let scalar_last_byte = wrong_message.len() - SIGNATURE_LEN - 1;
        wrong_message[scalar_last_byte] ^= 1;
        let identity_secret = partial_fixture.sender_secret(&wrong_message);
        resign_envelope(
            &mut wrong_message,
            identity_secret,
            partial_fixture.chain.as_bytes(),
        );
        assert!(ValidatedAcceptedSessionMessageV1::parse(
            &wrong_message,
            &partial_fixture.chain,
            &partial_fixture.roster,
        )
        .is_ok());
        assert!(partial_fixture
            .state
            .accept_message(&wrong_message)
            .is_err());
        assert!(partial_fixture.state.closed);
        assert!(partial_fixture
            .state
            .accept_message(&correct_message)
            .is_err());
    }

    #[test]
    fn future_sequence_and_wrong_ancestry_are_bounded_and_close_without_deadlock() {
        let mut sequence_fixture = commitment_fixture();
        let mut future = sequence_fixture.messages[0].clone();
        future[104..112].copy_from_slice(&u64::MAX.to_le_bytes());
        let identity_secret = sequence_fixture.sender_secret(&future);
        resign_envelope(
            &mut future,
            identity_secret,
            sequence_fixture.chain.as_bytes(),
        );
        assert!(sequence_fixture.state.accept_message(&future).is_err());
        assert!(sequence_fixture.state.pending.is_empty());
        assert!(sequence_fixture.state.closed);

        let mut head_fixture = commitment_fixture();
        let mut wrong_head = head_fixture.messages[0].clone();
        wrong_head[112] ^= 1;
        let identity_secret = head_fixture.sender_secret(&wrong_head);
        resign_envelope(
            &mut wrong_head,
            identity_secret,
            head_fixture.chain.as_bytes(),
        );
        assert!(head_fixture.state.accept_message(&wrong_head).is_err());
        assert!(head_fixture.state.closed);

        let mut buffered_fixture = commitment_fixture();
        let mut wrong_successor = buffered_fixture.messages[1].clone();
        wrong_successor[112] ^= 1;
        let identity_secret = buffered_fixture.sender_secret(&wrong_successor);
        resign_envelope(
            &mut wrong_successor,
            identity_secret,
            buffered_fixture.chain.as_bytes(),
        );
        assert_eq!(
            buffered_fixture
                .state
                .accept_message(&wrong_successor)
                .expect("future slot is bounded and buffered"),
            AcceptedMessageDispositionV1::Buffered,
        );
        assert_eq!(buffered_fixture.state.pending.len(), 1);
        assert!(buffered_fixture
            .state
            .accept_message(&buffered_fixture.messages[0])
            .is_err());
        assert!(buffered_fixture.state.closed);
        assert!(buffered_fixture.state.pending.len() <= MAX_PENDING_SIGNING_MESSAGES);
    }
}
