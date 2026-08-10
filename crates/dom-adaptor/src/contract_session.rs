//! Off-chain contract session envelope, state machine, and deadline policy.
//!
//! Phase 3 of the implementation schedule. The signing-round DSC1 envelope
//! carries the three signing messages; this is the layer above it — the
//! contract choreography itself, from shared-output construction through
//! funding-with-presigned-refund to a conditional claim or a timeout refund.
//! Its job is to survive the real world: crash, restart, and a slow
//! counterparty must never lose funds or wedge an input.
//!
//! Three pieces live here, all pure logic with no clock, filesystem, or
//! network:
//!
//! - a versioned contract envelope binding session id, roles, transcript, and
//!   an anti-replay sequence (deliverable 1);
//! - a contract state machine whose transitions are ordered, each advancing a
//!   transcript that is the per-transition evidence, and which resumes from the
//!   last durable transition after a restart (deliverable 2);
//! - a deadline policy that derives the refund lock height from block-height
//!   margins rather than an arbitrary constant (deliverable 4).
//!
//! Atomic persistence of the finalized bytes (deliverable 3) and the
//! interruption matrix (gate G3) are not here: they require the Contracts
//! store's retained-capability filesystem and a running node, and are tracked
//! in the Phase 3 status record.

use crate::{
    error::exact_array, AdaptorError, ContractKindV1, DirectionV1, Result, TrustedChainIdV1,
};
use dom_crypto::blake2b_256_tagged;

const ENVELOPE_MAGIC: &[u8; 4] = b"DCS1";
const ENVELOPE_VERSION: u16 = 1;
const TRANSITION_TAG_V1: &str = "DOM:scriptless-contract-transition:v1";
const ENVELOPE_DIGEST_TAG_V1: &str = "DOM:scriptless-contract-envelope:v1";

/// Ordered stages of the V1 witness-or-timeout contract.
///
/// The order is the security order: a shared output must exist before a refund
/// can be presigned against it, and the refund must be presigned before the
/// funding is signed, so that money never enters the contract without a
/// guaranteed exit. The two terminal successes and the abort are reached only
/// from the states from which they are valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractStageV1 {
    /// Session established, roster and terms fixed; nothing built yet.
    Proposed,
    /// The collaborative shared output has been constructed (Phase 2).
    SharedOutputBuilt,
    /// The refund spending the shared output is co-signed with the height-locked
    /// kernel at `H_refund` (§7.2 step 5 — the refund precedes funding).
    RefundPresigned,
    /// The claim adaptor pre-signature is built and verified and ReadyToFund is
    /// reached (§7.2 steps 7-8). Per §7.3 the funding gate transitions from
    /// here: funding is authorized only after the claim path exists as a
    /// verified adaptor pre-signature.
    ClaimPresigned,
    /// The funding is signed and published; the contract is live.
    Funded,
    /// Terminal: claimed through the adaptor condition (Phase 5).
    ClaimedByCondition,
    /// Terminal: refunded after the timeout height (Phase 5).
    RefundedByTimeout,
    /// Terminal failure: the session aborted before funding was authorized and
    /// its reserves were released. Only reachable from a pre-funding stage
    /// (§9.3); a `Funded` contract can never reach it.
    Aborted,
}

impl ContractStageV1 {
    /// Exact registry byte.
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Proposed => 0x01,
            Self::SharedOutputBuilt => 0x02,
            Self::RefundPresigned => 0x03,
            Self::ClaimPresigned => 0x04,
            Self::Funded => 0x05,
            Self::ClaimedByCondition => 0x06,
            Self::RefundedByTimeout => 0x07,
            Self::Aborted => 0x08,
        }
    }

    /// Parse a registry byte.
    pub fn from_byte(value: u8) -> Result<Self> {
        Ok(match value {
            0x01 => Self::Proposed,
            0x02 => Self::SharedOutputBuilt,
            0x03 => Self::RefundPresigned,
            0x04 => Self::ClaimPresigned,
            0x05 => Self::Funded,
            0x06 => Self::ClaimedByCondition,
            0x07 => Self::RefundedByTimeout,
            0x08 => Self::Aborted,
            _ => {
                return Err(AdaptorError::InvalidContext(
                    "contract stage byte is outside the closed registry",
                ))
            }
        })
    }

    /// Whether this stage is terminal and admits no further transition.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ClaimedByCondition | Self::RefundedByTimeout | Self::Aborted
        )
    }

    /// Whether `next` is a permitted successor of `self`.
    ///
    /// The forward path is strictly ordered and follows the §7.2 secure order:
    /// the refund is co-signed before the claim adaptor pre-signature, which is
    /// built and verified before funding is authorized (§7.3 transitions from
    /// `ClaimPresigned`). The two terminal successes are reachable only from
    /// `Funded`. Abort releasing reserves is reachable only from the pre-funding
    /// stages: §9.3 requires abort cancels the broadcast only while funding has
    /// not been authorized, and funding is authorized at the
    /// `ClaimPresigned → Funded` transition. Once `Funded`, the value is in the
    /// on-chain shared output, so the contract cannot pretend it never existed —
    /// its only exits are the adaptor claim and the timeout refund, with the
    /// wallet in monitoring until one of them settles.
    fn permits(self, next: Self) -> bool {
        use ContractStageV1::*;
        match (self, next) {
            (Proposed, SharedOutputBuilt)
            | (SharedOutputBuilt, RefundPresigned)
            | (RefundPresigned, ClaimPresigned)
            | (ClaimPresigned, Funded)
            | (Funded, ClaimedByCondition)
            | (Funded, RefundedByTimeout) => true,
            // §9.3: abort with reserve release only before funding is
            // authorized — never from Funded or a terminal.
            (Proposed | SharedOutputBuilt | RefundPresigned | ClaimPresigned, Aborted) => true,
            _ => false,
        }
    }
}

/// A versioned off-chain contract message envelope.
///
/// It binds the trusted chain, the session, the sending role, the sequence for
/// anti-replay, the transcript the sender observed, and the target stage the
/// message drives to. The payload is opaque here: its meaning belongs to the
/// stage-specific protocol, and this layer only authenticates ordering and
/// binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractEnvelopeV1 {
    chain_id: [u8; 32],
    session_id: [u8; 32],
    sender: DirectionV1,
    contract_kind: ContractKindV1,
    sequence: u64,
    target_stage: ContractStageV1,
    previous_transcript: [u8; 32],
    payload: Vec<u8>,
}

impl ContractEnvelopeV1 {
    /// Fixed prefix length before the variable payload.
    pub const PREFIX_LEN: usize = 4 + 2 + 32 + 32 + 1 + 2 + 8 + 1 + 32 + 4;

    /// Construct an envelope, validating its trusted bindings.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: &TrustedChainIdV1,
        session_id: [u8; 32],
        sender: DirectionV1,
        contract_kind: ContractKindV1,
        sequence: u64,
        target_stage: ContractStageV1,
        previous_transcript: [u8; 32],
        payload: Vec<u8>,
    ) -> Result<Self> {
        if session_id == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "contract envelope session id must be nonzero",
            ));
        }
        if previous_transcript == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "contract envelope previous transcript must be nonzero",
            ));
        }
        if payload.len() > u32::MAX as usize {
            return Err(AdaptorError::InvalidContext(
                "contract envelope payload exceeds the length field",
            ));
        }
        Ok(Self {
            chain_id: *chain_id.as_bytes(),
            session_id,
            sender,
            contract_kind,
            sequence,
            target_stage,
            previous_transcript,
            payload,
        })
    }

    /// Serialize the exact canonical envelope bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::PREFIX_LEN + self.payload.len());
        out.extend_from_slice(ENVELOPE_MAGIC);
        out.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.session_id);
        out.push(self.sender.to_byte());
        out.extend_from_slice(&self.contract_kind.to_le_bytes());
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.push(self.target_stage.to_byte());
        out.extend_from_slice(&self.previous_transcript);
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse and bind exact envelope bytes to the trusted local chain.
    pub fn from_bytes(bytes: &[u8], trusted_chain_id: &TrustedChainIdV1) -> Result<Self> {
        if bytes.len() < Self::PREFIX_LEN {
            return Err(AdaptorError::InvalidContext(
                "contract envelope shorter than its fixed prefix",
            ));
        }
        if &bytes[..4] != ENVELOPE_MAGIC {
            return Err(AdaptorError::InvalidContext(
                "contract envelope magic mismatch",
            ));
        }
        if u16::from_le_bytes([bytes[4], bytes[5]]) != ENVELOPE_VERSION {
            return Err(AdaptorError::InvalidContext(
                "contract envelope version must be exactly V1",
            ));
        }
        let chain_id = exact_array::<32>("contract envelope chain", &bytes[6..38])?;
        if &chain_id != trusted_chain_id.as_bytes() {
            return Err(AdaptorError::InvalidContext(
                "contract envelope chain id differs from the trusted local chain",
            ));
        }
        let session_id = exact_array::<32>("contract envelope session", &bytes[38..70])?;
        if session_id == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "contract envelope session id must be nonzero",
            ));
        }
        let sender = DirectionV1::try_from(bytes[70])?;
        let contract_kind = ContractKindV1::try_from(u16::from_le_bytes([bytes[71], bytes[72]]))?;
        let sequence = u64::from_le_bytes(exact_array::<8>(
            "contract envelope sequence",
            &bytes[73..81],
        )?);
        let target_stage = ContractStageV1::from_byte(bytes[81])?;
        let previous_transcript =
            exact_array::<32>("contract envelope transcript", &bytes[82..114])?;
        if previous_transcript == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "contract envelope previous transcript must be nonzero",
            ));
        }
        let payload_len = u32::from_le_bytes(exact_array::<4>(
            "contract envelope length",
            &bytes[114..118],
        )?) as usize;
        let expected =
            Self::PREFIX_LEN
                .checked_add(payload_len)
                .ok_or(AdaptorError::InvalidContext(
                    "contract envelope length overflow",
                ))?;
        if bytes.len() != expected {
            return Err(AdaptorError::InvalidContext(
                "contract envelope trailing or missing payload bytes",
            ));
        }
        let payload = bytes[Self::PREFIX_LEN..].to_vec();
        Ok(Self {
            chain_id,
            session_id,
            sender,
            contract_kind,
            sequence,
            target_stage,
            previous_transcript,
            payload,
        })
    }

    /// The exact envelope digest, used to advance the transcript.
    pub fn digest(&self) -> [u8; 32] {
        *blake2b_256_tagged(ENVELOPE_DIGEST_TAG_V1, &self.to_bytes()).as_bytes()
    }

    /// The stage this message drives the contract to.
    pub const fn target_stage(&self) -> ContractStageV1 {
        self.target_stage
    }

    /// The sender's anti-replay sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The sending role.
    pub const fn sender(&self) -> DirectionV1 {
        self.sender
    }
}

/// The live contract state: current stage, transcript, and per-role sequences.
///
/// The transcript is the running evidence: every accepted transition folds the
/// driving envelope's digest into it, so two peers that accepted the same
/// ordered messages hold the same transcript, and a divergence is detectable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractStateV1 {
    stage: ContractStageV1,
    transcript: [u8; 32],
    initiator_sequence: u64,
    responder_sequence: u64,
}

impl ContractStateV1 {
    /// Open a fresh session in `Proposed` with its initial transcript.
    ///
    /// The initial transcript must be nonzero — it is the anchor the first
    /// envelope binds to — and is produced by the session-establishment layer.
    pub fn open(initial_transcript: [u8; 32]) -> Result<Self> {
        if initial_transcript == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "contract initial transcript must be nonzero",
            ));
        }
        Ok(Self {
            stage: ContractStageV1::Proposed,
            transcript: initial_transcript,
            initiator_sequence: 0,
            responder_sequence: 0,
        })
    }

    /// Current stage.
    pub const fn stage(&self) -> ContractStageV1 {
        self.stage
    }

    /// Current transcript.
    pub const fn transcript(&self) -> [u8; 32] {
        self.transcript
    }

    /// The next sequence expected from a given role.
    fn expected_sequence(&self, sender: DirectionV1) -> u64 {
        match sender {
            DirectionV1::Initiator => self.initiator_sequence,
            DirectionV1::Responder => self.responder_sequence,
        }
    }

    fn bump_sequence(&mut self, sender: DirectionV1) {
        match sender {
            DirectionV1::Initiator => self.initiator_sequence += 1,
            DirectionV1::Responder => self.responder_sequence += 1,
        }
    }

    /// Apply one envelope, advancing the stage and transcript if it is valid.
    ///
    /// The envelope must bind the transcript this state currently holds, use
    /// the sender's exact next sequence, and target a stage the current stage
    /// permits. Any mismatch fails closed and leaves the state untouched, so a
    /// replayed, reordered, forked, or out-of-turn message cannot advance the
    /// contract. The updated transcript is the evidence recorded for the
    /// transition.
    pub fn apply(&mut self, envelope: &ContractEnvelopeV1) -> Result<()> {
        if self.stage.is_terminal() {
            return Err(AdaptorError::InvalidContext(
                "contract state is terminal and accepts no further envelope",
            ));
        }
        if envelope.previous_transcript != self.transcript {
            return Err(AdaptorError::InvalidContext(
                "contract envelope does not bind the current transcript",
            ));
        }
        if envelope.sequence != self.expected_sequence(envelope.sender) {
            return Err(AdaptorError::InvalidContext(
                "contract envelope sequence is not the sender's next",
            ));
        }
        if !self.stage.permits(envelope.target_stage) {
            return Err(AdaptorError::InvalidContext(
                "contract envelope targets a stage the current stage does not permit",
            ));
        }
        let advanced = advance_contract_transcript_v1(
            &self.transcript,
            &envelope.digest(),
            envelope.sender,
            envelope.target_stage,
        );
        self.stage = envelope.target_stage;
        self.transcript = advanced;
        self.bump_sequence(envelope.sender);
        Ok(())
    }

    /// Reconstruct the live state from a durable checkpoint and revalidate it.
    ///
    /// After a restart the contract is resumed from the last transition that
    /// was durably recorded: its stage, transcript, and per-role sequences.
    /// A checkpoint whose stage byte or transcript is malformed fails closed
    /// rather than resuming into an ambiguous state.
    pub fn resume(
        stage: ContractStageV1,
        transcript: [u8; 32],
        initiator_sequence: u64,
        responder_sequence: u64,
    ) -> Result<Self> {
        if transcript == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "resumed contract transcript must be nonzero",
            ));
        }
        Ok(Self {
            stage,
            transcript,
            initiator_sequence,
            responder_sequence,
        })
    }
}

/// Fold one transition into the contract transcript.
fn advance_contract_transcript_v1(
    previous: &[u8; 32],
    envelope_digest: &[u8; 32],
    sender: DirectionV1,
    target_stage: ContractStageV1,
) -> [u8; 32] {
    let mut body = [0u8; 66];
    body[..32].copy_from_slice(previous);
    body[32..64].copy_from_slice(envelope_digest);
    body[64] = sender.to_byte();
    body[65] = target_stage.to_byte();
    *blake2b_256_tagged(TRANSITION_TAG_V1, &body).as_bytes()
}

/// A derived refund-deadline policy in block height.
///
/// The schedule forbids an arbitrary constant: the refund lock height must be
/// derived from block-height margins — propagation depth plus reorg depth —
/// not a magic number. This type performs that derivation and rejects a
/// degenerate (zero) margin. The concrete mainnet-measured values are an
/// external input, not fixed here.
///
/// Two distinct margins matter, and conflating them is unsafe:
///
/// - **Refund placement margin** (`propagation + reorg`): how far beyond
///   funding the refund unlocks, so the party that must fall back to the
///   timeout has time to observe and react.
/// - **Claim confirmation margin** (`claim_confirmation_blocks`): how many
///   blocks the adaptor claim needs, once published, to reach a reorg-safe
///   depth before the refund could unlock and race it (§7.2 step 10's
///   confirmation policy; §7.5). A claim that is not reorg-safe by `H_refund`
///   can be undone by a reorg while the counterparty's refund wins.
///
/// The claim confirmation margin must be strictly smaller than the refund
/// placement margin, so the safe claim window `(funding, H_refund −
/// claim_confirmation]` is non-empty. The concrete value depends on the
/// Dandelion++ stem-timing study (Cronograma Fase 5); this type does not fix it
/// but enforces the relationship that makes the window well-formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefundDeadlinePolicyV1 {
    propagation_blocks: u32,
    reorg_depth_blocks: u32,
    claim_confirmation_blocks: u32,
}

impl RefundDeadlinePolicyV1 {
    /// Construct a policy from measured margins.
    ///
    /// All three margins must be nonzero: a zero propagation or reorg allowance
    /// would place the refund unsafely close to funding, and a zero claim
    /// confirmation margin would treat an unconfirmed claim as safe. The claim
    /// confirmation margin must also be strictly less than the refund placement
    /// margin (`propagation + reorg`); otherwise the safe claim window is empty
    /// (a claim can only be published after funding confirms), which is exactly
    /// the degenerate deadline the schedule rules out.
    pub fn new(
        propagation_blocks: u32,
        reorg_depth_blocks: u32,
        claim_confirmation_blocks: u32,
    ) -> Result<Self> {
        if propagation_blocks == 0 || reorg_depth_blocks == 0 {
            return Err(AdaptorError::InvalidContext(
                "refund deadline margins must be nonzero block heights",
            ));
        }
        if claim_confirmation_blocks == 0 {
            return Err(AdaptorError::InvalidContext(
                "claim confirmation margin must be a nonzero block height",
            ));
        }
        let policy = Self {
            propagation_blocks,
            reorg_depth_blocks,
            claim_confirmation_blocks,
        };
        if u64::from(claim_confirmation_blocks) >= policy.total_margin_blocks() {
            return Err(AdaptorError::InvalidContext(
                "claim confirmation margin must be smaller than the refund placement margin, \
                 else the safe claim window is empty",
            ));
        }
        Ok(policy)
    }

    /// The refund placement margin in blocks: how far beyond funding the refund
    /// unlocks.
    pub const fn total_margin_blocks(self) -> u64 {
        self.propagation_blocks as u64 + self.reorg_depth_blocks as u64
    }

    /// The claim confirmation margin in blocks: the buffer the claim needs to
    /// reach a reorg-safe depth before the refund unlocks.
    pub const fn claim_confirmation_blocks(self) -> u64 {
        self.claim_confirmation_blocks as u64
    }

    /// Derive the refund lock height from the funding height.
    ///
    /// The refund becomes spendable at `funding_height + total_margin`, so a
    /// party that must fall back to the timeout has the full margin to observe
    /// and react before the refund unlocks. Overflow fails closed.
    pub fn refund_lock_height(self, funding_height: u64) -> Result<u64> {
        funding_height
            .checked_add(self.total_margin_blocks())
            .ok_or(AdaptorError::InvalidContext(
                "refund lock height overflows the funding height",
            ))
    }

    /// The highest block at which a claim may still be published safely.
    ///
    /// Phase 5 deliverable 3, the claim floor. Publishing the adaptor claim
    /// reveals `t` in the mempool before confirmation, and the DOM has no
    /// relative timelock, so the only protection is the margin between the claim
    /// and the refund unlock (§7.5). This returns the last claim height that
    /// still leaves the **claim confirmation margin** before `H_refund`:
    /// `refund_lock − claim_confirmation_blocks`. A claim at or below it reaches
    /// a reorg-safe depth before the refund can race it; a claim above it does
    /// not. Because the claim confirmation margin is strictly smaller than the
    /// refund placement margin (enforced in `new`), the floor is strictly above
    /// `funding_height`, so the safe window `(funding, floor]` is non-empty.
    pub fn claim_floor_height(self, refund_lock_height: u64) -> Result<u64> {
        refund_lock_height
            .checked_sub(self.claim_confirmation_blocks())
            .ok_or(AdaptorError::InvalidContext(
                "refund unlock is too low to leave the claim confirmation margin",
            ))
    }

    /// Whether a claim at `claim_height` leaves the claim confirmation margin
    /// before the refund unlocks.
    pub fn claim_is_safe(self, claim_height: u64, refund_lock_height: u64) -> Result<bool> {
        Ok(claim_height <= self.claim_floor_height(refund_lock_height)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain() -> TrustedChainIdV1 {
        TrustedChainIdV1::from_signed_fixture([0x11; 32])
    }

    fn envelope(
        sender: DirectionV1,
        sequence: u64,
        target: ContractStageV1,
        previous: [u8; 32],
    ) -> ContractEnvelopeV1 {
        ContractEnvelopeV1::new(
            &chain(),
            [0x22; 32],
            sender,
            ContractKindV1::WitnessOrTimeout,
            sequence,
            target,
            previous,
            vec![0xAB; 8],
        )
        .expect("envelope")
    }

    #[test]
    fn envelope_roundtrips_and_binds_the_trusted_chain() {
        let env = envelope(
            DirectionV1::Initiator,
            0,
            ContractStageV1::SharedOutputBuilt,
            [0x33; 32],
        );
        let bytes = env.to_bytes();
        assert_eq!(bytes.len(), ContractEnvelopeV1::PREFIX_LEN + 8);
        assert_eq!(
            ContractEnvelopeV1::from_bytes(&bytes, &chain()).expect("roundtrip"),
            env
        );
        // A different trusted chain rejects the same bytes.
        let other = TrustedChainIdV1::from_signed_fixture([0x99; 32]);
        assert!(ContractEnvelopeV1::from_bytes(&bytes, &other).is_err());
    }

    #[test]
    fn envelope_rejects_truncation_and_trailing_bytes() {
        let env = envelope(
            DirectionV1::Initiator,
            0,
            ContractStageV1::SharedOutputBuilt,
            [0x33; 32],
        );
        let bytes = env.to_bytes();
        for length in 0..bytes.len() {
            assert!(ContractEnvelopeV1::from_bytes(&bytes[..length], &chain()).is_err());
        }
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(ContractEnvelopeV1::from_bytes(&extended, &chain()).is_err());
    }

    #[test]
    fn the_ordered_happy_path_advances_to_a_terminal() {
        let mut state = ContractStateV1::open([0x33; 32]).expect("open");
        assert_eq!(state.stage(), ContractStageV1::Proposed);

        let steps = [
            (DirectionV1::Initiator, ContractStageV1::SharedOutputBuilt),
            (DirectionV1::Responder, ContractStageV1::RefundPresigned),
            (DirectionV1::Responder, ContractStageV1::ClaimPresigned),
            (DirectionV1::Initiator, ContractStageV1::Funded),
            (DirectionV1::Initiator, ContractStageV1::ClaimedByCondition),
        ];
        let mut initiator_seq = 0;
        let mut responder_seq = 0;
        for (sender, target) in steps {
            let seq = match sender {
                DirectionV1::Initiator => initiator_seq,
                DirectionV1::Responder => responder_seq,
            };
            let env = envelope(sender, seq, target, state.transcript());
            state.apply(&env).expect("valid transition");
            assert_eq!(state.stage(), target);
            match sender {
                DirectionV1::Initiator => initiator_seq += 1,
                DirectionV1::Responder => responder_seq += 1,
            }
        }
        assert!(state.stage().is_terminal());
    }

    #[test]
    fn out_of_order_stage_is_rejected_and_state_is_unchanged() {
        let mut state = ContractStateV1::open([0x33; 32]).expect("open");
        // Jump straight to Funded from Proposed.
        let env = envelope(
            DirectionV1::Initiator,
            0,
            ContractStageV1::Funded,
            state.transcript(),
        );
        assert!(state.apply(&env).is_err());
        assert_eq!(state.stage(), ContractStageV1::Proposed);
        assert_eq!(state.transcript(), [0x33; 32]);
    }

    #[test]
    fn a_replayed_envelope_does_not_advance_twice() {
        let mut state = ContractStateV1::open([0x33; 32]).expect("open");
        let env = envelope(
            DirectionV1::Initiator,
            0,
            ContractStageV1::SharedOutputBuilt,
            state.transcript(),
        );
        state.apply(&env).expect("first apply");
        // The same envelope now binds a stale transcript and a spent sequence.
        assert!(state.apply(&env).is_err());
        assert_eq!(state.stage(), ContractStageV1::SharedOutputBuilt);
    }

    #[test]
    fn a_wrong_sequence_fails_closed() {
        let mut state = ContractStateV1::open([0x33; 32]).expect("open");
        let env = envelope(
            DirectionV1::Initiator,
            5,
            ContractStageV1::SharedOutputBuilt,
            state.transcript(),
        );
        assert!(state.apply(&env).is_err());
    }

    #[test]
    fn abort_releasing_reserves_is_reachable_only_before_funding() {
        // §9.3: abort cancels the broadcast and releases reserves only while
        // funding has not been authorized — the pre-funding stages.
        for reached in [
            ContractStageV1::Proposed,
            ContractStageV1::SharedOutputBuilt,
            ContractStageV1::RefundPresigned,
        ] {
            assert!(reached.permits(ContractStageV1::Aborted));
        }
        // Once funded, the value is in the on-chain shared output: abort must
        // not pretend the contract never existed. Funded exits only to the
        // adaptor claim or the timeout refund.
        assert!(!ContractStageV1::Funded.permits(ContractStageV1::Aborted));
        assert!(ContractStageV1::Funded.permits(ContractStageV1::ClaimedByCondition));
        assert!(ContractStageV1::Funded.permits(ContractStageV1::RefundedByTimeout));
        for terminal in [
            ContractStageV1::ClaimedByCondition,
            ContractStageV1::RefundedByTimeout,
            ContractStageV1::Aborted,
        ] {
            assert!(!terminal.permits(ContractStageV1::Aborted));
        }
    }

    #[test]
    fn resume_reconstructs_the_exact_state_and_continues() {
        let mut original = ContractStateV1::open([0x33; 32]).expect("open");
        let env = envelope(
            DirectionV1::Initiator,
            0,
            ContractStageV1::SharedOutputBuilt,
            original.transcript(),
        );
        original.apply(&env).expect("apply");

        // Resume from the durable checkpoint and confirm it equals the live
        // state, then continue from it.
        let mut resumed =
            ContractStateV1::resume(original.stage(), original.transcript(), 1, 0).expect("resume");
        assert_eq!(resumed, original);

        let next = envelope(
            DirectionV1::Responder,
            0,
            ContractStageV1::RefundPresigned,
            resumed.transcript(),
        );
        resumed.apply(&next).expect("continue after resume");
        assert_eq!(resumed.stage(), ContractStageV1::RefundPresigned);
    }

    #[test]
    fn two_peers_applying_the_same_messages_agree_on_the_transcript() {
        let mut peer_a = ContractStateV1::open([0x33; 32]).expect("open");
        let mut peer_b = ContractStateV1::open([0x33; 32]).expect("open");
        let env = envelope(
            DirectionV1::Initiator,
            0,
            ContractStageV1::SharedOutputBuilt,
            [0x33; 32],
        );
        peer_a.apply(&env).expect("A");
        peer_b.apply(&env).expect("B");
        assert_eq!(peer_a.transcript(), peer_b.transcript());
    }

    #[test]
    fn stage_registry_is_closed_and_roundtrips() {
        for byte in 0u8..=u8::MAX {
            match ContractStageV1::from_byte(byte) {
                Ok(stage) => assert_eq!(stage.to_byte(), byte),
                Err(_) => assert!(!(0x01..=0x08).contains(&byte)),
            }
        }
    }

    #[test]
    fn deadline_policy_derives_a_nonzero_margin_and_rejects_degenerate_input() {
        // Every margin must be nonzero.
        assert!(RefundDeadlinePolicyV1::new(0, 6, 4).is_err());
        assert!(RefundDeadlinePolicyV1::new(6, 0, 4).is_err());
        assert!(RefundDeadlinePolicyV1::new(3, 6, 0).is_err());
        // The claim confirmation margin must be strictly smaller than the refund
        // placement margin, else the safe claim window is empty.
        assert!(RefundDeadlinePolicyV1::new(3, 6, 9).is_err());
        assert!(RefundDeadlinePolicyV1::new(3, 6, 10).is_err());

        let policy = RefundDeadlinePolicyV1::new(3, 6, 4).expect("policy");
        assert_eq!(policy.total_margin_blocks(), 9);
        assert_eq!(policy.claim_confirmation_blocks(), 4);
        assert_eq!(policy.refund_lock_height(1000).expect("lock"), 1009);
        assert!(policy.refund_lock_height(u64::MAX).is_err());
    }

    #[test]
    fn claim_floor_leaves_the_claim_confirmation_margin_and_a_nonempty_window() {
        // Refund placement margin 9 (propagation 3 + reorg 6); claim confirmation
        // margin 4. Funding at 1000 → refund unlocks at 1009 → claim floor at
        // 1009 − 4 = 1005, leaving a non-empty safe window (1000, 1005].
        let policy = RefundDeadlinePolicyV1::new(3, 6, 4).expect("policy");
        let refund = policy.refund_lock_height(1000).expect("refund");
        assert_eq!(refund, 1009);
        assert_eq!(policy.claim_floor_height(refund).expect("floor"), 1005);

        // The whole point of the fix: a real claim published after funding
        // confirms is now safe when it leaves the confirmation margin.
        assert!(policy.claim_is_safe(1001, refund).expect("safe after funding"));
        assert!(policy.claim_is_safe(1005, refund).expect("safe at floor"));
        // Above the floor the claim cannot reach a reorg-safe depth before the
        // refund unlocks.
        assert!(!policy.claim_is_safe(1006, refund).expect("unsafe above floor"));
        assert!(!policy
            .claim_is_safe(refund, refund)
            .expect("unsafe at unlock"));

        // A refund unlock below the confirmation margin has no safe claim window.
        assert!(policy.claim_floor_height(3).is_err());
    }
}
