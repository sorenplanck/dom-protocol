//! Typed durable settlement store (F2 spec §8.2, §9) over the neutral
//! `store` crate.
//!
//! This module is the binding layer: it freezes the canonical encodings
//! (event envelope, context, effect payloads), derives the deterministic
//! `effect_id`, and maps the typed [`SettlementStore`] contract onto the
//! neutral SQLite operations of `store` — which executes every accepted
//! transition as ONE `BEGIN IMMEDIATE` transaction (§8.2 steps 1–9).
//!
//! Idempotency and equivocation (spec §9):
//! - same `(settlement_id, event_id)` and same bytes → idempotent ACK;
//! - same `(settlement_id, event_id)` and different bytes → equivocation,
//!   fails closed;
//! - `effect_id = BLAKE2b-256("DOM-INTEROP/EFFECT/V1\0" || settlement_id
//!   || source_event_id || effect_kind || payload_hash)`;
//! - resend reads the payload from the outbox, never reconstructs bytes;
//! - the cursor only advances in the same transaction that persists the
//!   accepted event;
//! - a diverging `terms_hash` fails before `transition()` is called
//!   (enforced by the engine, spec §10);
//! - an unknown envelope version fails closed.
//!
//! Determinism note: every method that stamps a wall-clock column takes
//! `now_unix_ms` from the caller. The store NEVER reads the clock — the
//! failpoint and property suites (spec §13–§14) need byte-reproducible
//! runs.

use std::sync::Mutex;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use crate::state::{
    Effect, EvidenceRefV1, SettlementContext, SettlementEvent, SettlementState, Transition,
};
use crate::terms::SettlementTermsV1;
use crate::types::{ChainId, Digest32, EffectId, EvidenceId, SessionId, SettlementId};

/// Fixed-output BLAKE2b-256 (identical digest to `Blake2bVar::new(32)`,
/// but statically sized — no fallible construction in a production path).
type Blake2b256 = Blake2b<U32>;

/// Frozen protocol version of the F2 envelopes.
pub const PROTOCOL_VERSION: u16 = 1;
/// Domain of the deterministic effect identifier (spec §9).
pub const EFFECT_DOMAIN: &[u8] = b"DOM-INTEROP/EFFECT/V1\0";
/// Domain of the deterministic event identifier.
///
/// The identifier is a pure function of `(settlement_id, event)`, so the
/// SAME observation redelivered any number of times carries the same id
/// and the same bytes — an idempotent ACK at the store (spec §9) — while
/// a different economic claim about the same chain position necessarily
/// produces a different id.
pub const EVENT_ID_DOMAIN: &[u8] = b"DOM-INTEROP/EVENT-ID/V1\0";
/// Domain of the effect payload hash.
pub const EFFECT_PAYLOAD_DOMAIN: &[u8] = b"DOM-INTEROP/EFFECT-PAYLOAD/V1\0";
/// Domain of the persisted context hash.
pub const CONTEXT_DOMAIN: &[u8] = b"DOM-INTEROP/CONTEXT/V1\0";

fn blake2b_256(domain: &[u8], bytes: &[u8]) -> Digest32 {
    let digest = Blake2b256::new()
        .chain_update(domain)
        .chain_update(bytes)
        .finalize();
    digest.into()
}

/// Neutral event envelope delivered to the engine (spec §9).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EventEnvelopeV1 {
    /// Envelope version; anything but [`PROTOCOL_VERSION`] fails closed.
    pub protocol_version: u16,
    /// Settlement the event belongs to.
    pub settlement_id: SettlementId,
    /// Session binding (checked against the snapshot before transition).
    pub session_id: SessionId,
    /// A3 terms binding (checked against the snapshot before transition).
    pub terms_hash: Digest32,
    /// Chain the event was observed on.
    pub source_chain: ChainId,
    /// Event identifier — the dedupe/equivocation key.
    pub event_id: EvidenceId,
    /// Source sequence (off-chain ordering input).
    pub source_sequence: u64,
    /// The machine event.
    pub event: SettlementEvent,
}

/// One deterministic outbox effect derived from an accepted transition.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OutboxEffectV1 {
    /// Deterministic identifier (see [`EFFECT_DOMAIN`]).
    pub effect_id: EffectId,
    /// Settlement the effect belongs to.
    pub settlement_id: SettlementId,
    /// Event whose transition produced the effect.
    pub source_event_id: EvidenceId,
    /// The typed effect.
    pub kind: Effect,
    /// Hash of the canonical payload.
    pub payload_hash: Digest32,
    /// Canonical payload bytes (what the dispatcher resends verbatim).
    pub payload: Vec<u8>,
}

/// Cursor update committed atomically with the accepted event (spec §9).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CursorUpdateV1 {
    /// Chain the cursor tracks.
    pub chain_id: ChainId,
    /// Opaque scanner cursor bytes.
    pub cursor_bytes: Vec<u8>,
    /// Anchored height, when the scanner is anchored.
    pub anchor_height: Option<u64>,
    /// Anchor hash, when the scanner is anchored.
    pub anchor_hash: Option<Digest32>,
}

/// Typed snapshot: binding plus the decoded machine context.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SettlementSnapshot {
    /// Settlement identifier.
    pub settlement_id: SettlementId,
    /// Session binding frozen at creation.
    pub session_id: SessionId,
    /// A3 terms hash frozen at creation.
    pub terms_hash: Digest32,
    /// Decoded machine context.
    pub context: SettlementContext,
    /// Sequence of the last accepted journal entry.
    pub last_event_seq: u64,
}

/// Result of a commit attempt (spec §8.2/§10).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CommitResult {
    /// Durably committed at this revision.
    Committed {
        /// The resulting revision.
        revision: u64,
    },
    /// Byte-identical redelivery: idempotent ACK, nothing written.
    DuplicateSameBytes,
}

/// Result of parking evidence for reorder (spec §10).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParkResult {
    /// Parked now.
    Parked,
    /// Identical evidence already parked (idempotent).
    AlreadyParked,
}

/// One claimed outbox entry with its typed effect decoded back.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClaimedEffectV1 {
    /// Settlement the effect belongs to.
    pub settlement_id: SettlementId,
    /// Deterministic effect identifier.
    pub effect_id: EffectId,
    /// Typed effect decoded from the persisted payload.
    pub kind: Effect,
    /// Exact persisted payload bytes (resend these, never reconstruct).
    pub payload: Vec<u8>,
    /// Hash of the payload (pass back to `complete_effect`).
    pub payload_hash: Digest32,
    /// Delivery attempts including this claim.
    pub attempts: u64,
}

/// Materialized cursor of one (settlement, chain).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StoredCursor {
    /// Opaque scanner cursor bytes.
    pub cursor_bytes: Vec<u8>,
    /// Anchored height, when present.
    pub anchor_height: Option<u64>,
    /// Anchor hash, when present.
    pub anchor_hash: Option<Digest32>,
    /// Revision of the commit that last advanced this cursor.
    pub revision: u64,
}

/// Typed store failures — all fail closed.
#[derive(Debug, thiserror::Error)]
pub enum StorePortError {
    /// Neutral storage failure.
    #[error("storage: {0}")]
    Storage(#[from] store::StoreError),
    /// Envelope version is not [`PROTOCOL_VERSION`].
    #[error("unknown protocol version")]
    UnknownVersion,
    /// Same event id re-presented with different bytes (spec §9).
    #[error("equivocation: same event id, different bytes")]
    Equivocation,
    /// CAS lost: durable revision differs from the expectation.
    #[error("revision conflict")]
    RevisionConflict,
    /// Persisted context bytes do not decode to a valid context.
    #[error("corrupt persisted context")]
    CorruptContext,
    /// Persisted or received event bytes do not decode to a valid event.
    #[error("corrupt event encoding")]
    CorruptEvent,
    /// A counter or length conversion would overflow.
    #[error("counter overflow")]
    Overflow,
}

/// Result alias of this module.
pub type Result<T> = core::result::Result<T, StorePortError>;

// ---- canonical tags (frozen; a new variant demands a new version) ------

/// Stable tag of one state (also the snapshot/terminal tag).
pub fn state_tag(state: SettlementState) -> u16 {
    match state {
        SettlementState::Preparing => 1,
        SettlementState::ReadyToFund => 2,
        SettlementState::Confirming => 3,
        SettlementState::Settling => 4,
        SettlementState::Settled => 5,
        SettlementState::Refunded => 6,
    }
}

fn state_from_tag(tag: u16) -> Result<SettlementState> {
    Ok(match tag {
        1 => SettlementState::Preparing,
        2 => SettlementState::ReadyToFund,
        3 => SettlementState::Confirming,
        4 => SettlementState::Settling,
        5 => SettlementState::Settled,
        6 => SettlementState::Refunded,
        _ => return Err(StorePortError::CorruptContext),
    })
}

/// Stable tag of one event kind.
pub fn event_kind(event: &SettlementEvent) -> u16 {
    match event {
        SettlementEvent::RefundArmed => 1,
        SettlementEvent::FundingObserved { .. } => 2,
        SettlementEvent::FundingConfirmed { .. } => 3,
        SettlementEvent::FundingAbsent { .. } => 4,
        SettlementEvent::ClaimEvidenceVerified { .. } => 5,
        SettlementEvent::ClaimConfirmed { .. } => 6,
        SettlementEvent::TimelockExpired => 7,
        SettlementEvent::RefundConfirmed { .. } => 8,
        SettlementEvent::ReorgInvalidated { .. } => 9,
    }
}

/// Stable tag of one effect kind.
pub fn effect_kind(effect: &Effect) -> u16 {
    match effect {
        Effect::AuthorizeFunding => 1,
        Effect::RequestClaimConsumption { .. } => 2,
        Effect::ArmRefundPath => 3,
        Effect::RevalidateFrom { .. } => 4,
        Effect::RecordTerminalOutcome(_) => 5,
    }
}

// ---- canonical encodings (big-endian, fixed order, no omissions) -------

fn put_evidence(out: &mut Vec<u8>, ev: &EvidenceRefV1) {
    out.extend_from_slice(&ev.chain_id.0);
    out.extend_from_slice(&ev.tx_id);
    out.extend_from_slice(&ev.event_index.to_be_bytes());
    out.extend_from_slice(&ev.block_height.to_be_bytes());
    out.extend_from_slice(&ev.block_anchor);
}

fn encode_event(out: &mut Vec<u8>, event: &SettlementEvent) {
    out.extend_from_slice(&event_kind(event).to_be_bytes());
    match event {
        SettlementEvent::RefundArmed | SettlementEvent::TimelockExpired => {}
        SettlementEvent::FundingObserved { evidence }
        | SettlementEvent::FundingConfirmed { evidence }
        | SettlementEvent::ClaimEvidenceVerified { evidence }
        | SettlementEvent::ClaimConfirmed { evidence }
        | SettlementEvent::RefundConfirmed { evidence } => put_evidence(out, evidence),
        SettlementEvent::FundingAbsent { revalidation_from } => {
            out.extend_from_slice(&revalidation_from.to_be_bytes());
        }
        SettlementEvent::ReorgInvalidated {
            from_height,
            old_anchor,
        } => {
            out.extend_from_slice(&from_height.to_be_bytes());
            out.extend_from_slice(old_anchor);
        }
    }
}

/// Strict big-endian cursor: every read is bounds-checked and fails
/// closed. Shared by the envelope and context decoders.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(StorePortError::CorruptEvent)?;
        if end > self.bytes.len() {
            return Err(StorePortError::CorruptEvent);
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn take_u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn take_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn finished(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

fn take_evidence(r: &mut Reader<'_>) -> Result<EvidenceRefV1> {
    Ok(EvidenceRefV1 {
        chain_id: ChainId(r.take_array()?),
        tx_id: r.take_array()?,
        event_index: r.take_u32()?,
        block_height: r.take_u64()?,
        block_anchor: r.take_array()?,
    })
}

fn decode_event(r: &mut Reader<'_>) -> Result<SettlementEvent> {
    Ok(match r.take_u16()? {
        1 => SettlementEvent::RefundArmed,
        2 => SettlementEvent::FundingObserved {
            evidence: take_evidence(r)?,
        },
        3 => SettlementEvent::FundingConfirmed {
            evidence: take_evidence(r)?,
        },
        4 => SettlementEvent::FundingAbsent {
            revalidation_from: r.take_u64()?,
        },
        5 => SettlementEvent::ClaimEvidenceVerified {
            evidence: take_evidence(r)?,
        },
        6 => SettlementEvent::ClaimConfirmed {
            evidence: take_evidence(r)?,
        },
        7 => SettlementEvent::TimelockExpired,
        8 => SettlementEvent::RefundConfirmed {
            evidence: take_evidence(r)?,
        },
        9 => SettlementEvent::ReorgInvalidated {
            from_height: r.take_u64()?,
            old_anchor: r.take_array()?,
        },
        _ => return Err(StorePortError::CorruptEvent),
    })
}

impl EventEnvelopeV1 {
    /// Canonical envelope bytes — the exact bytes equivocation is judged
    /// on (`settlement_journal.event_bytes`).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(&self.settlement_id.0);
        out.extend_from_slice(&self.session_id.0);
        out.extend_from_slice(&self.terms_hash);
        out.extend_from_slice(&self.source_chain.0);
        out.extend_from_slice(&self.event_id.0);
        out.extend_from_slice(&self.source_sequence.to_be_bytes());
        encode_event(&mut out, &self.event);
        out
    }

    /// Strict inverse of [`Self::canonical_bytes`] (spec §9: unknown
    /// version fails closed; so do unknown event tags, truncation and
    /// trailing bytes). Used by journal replay during recovery (§13) and
    /// by the envelope fuzz target (§17).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let protocol_version = r.take_u16()?;
        if protocol_version != PROTOCOL_VERSION {
            return Err(StorePortError::UnknownVersion);
        }
        let envelope = Self {
            protocol_version,
            settlement_id: SettlementId(r.take_array()?),
            session_id: SessionId(r.take_array()?),
            terms_hash: r.take_array()?,
            source_chain: ChainId(r.take_array()?),
            event_id: EvidenceId(r.take_array()?),
            source_sequence: r.take_u64()?,
            event: decode_event(&mut r)?,
        };
        if !r.finished() {
            return Err(StorePortError::CorruptEvent);
        }
        Ok(envelope)
    }
}

/// Deterministic event identifier: `BLAKE2b-256(EVENT_ID_DOMAIN ||
/// settlement_id || canonical_event_bytes)`.
///
/// Deriving the id from the event itself is what makes redelivery an
/// idempotent ACK rather than a second economic effect: the scanner does
/// not have to remember anything, and two processes observing the same
/// chain position independently produce the same id and the same bytes.
pub fn derive_event_id(settlement_id: SettlementId, event: &SettlementEvent) -> EvidenceId {
    let mut body = Vec::with_capacity(32 + 128);
    body.extend_from_slice(&settlement_id.0);
    encode_event(&mut body, event);
    EvidenceId(blake2b_256(EVENT_ID_DOMAIN, &body))
}

/// Canonical context encoding (state tag, revision, observation, flags).
pub fn encode_context(ctx: &SettlementContext) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 8 + 9 + 2);
    out.extend_from_slice(&state_tag(ctx.state).to_be_bytes());
    out.extend_from_slice(&ctx.revision.to_be_bytes());
    match ctx.last_observed_height {
        None => out.push(0x00),
        Some(h) => {
            out.push(0x01);
            out.extend_from_slice(&h.to_be_bytes());
        }
    }
    out.push(u8::from(ctx.claim_evidence_verified));
    out.push(u8::from(ctx.refund_path_armed));
    out
}

/// Strict inverse of [`encode_context`]; fails closed on any deviation.
pub fn decode_context(bytes: &[u8]) -> Result<SettlementContext> {
    let take = |pos: &mut usize, n: usize| -> Result<&[u8]> {
        let end = pos.checked_add(n).ok_or(StorePortError::CorruptContext)?;
        if end > bytes.len() {
            return Err(StorePortError::CorruptContext);
        }
        let s = &bytes[*pos..end];
        *pos = end;
        Ok(s)
    };
    let mut pos = 0usize;
    let state = state_from_tag(u16::from_be_bytes(
        take(&mut pos, 2)?
            .try_into()
            .map_err(|_| StorePortError::CorruptContext)?,
    ))?;
    let revision = u64::from_be_bytes(
        take(&mut pos, 8)?
            .try_into()
            .map_err(|_| StorePortError::CorruptContext)?,
    );
    let last_observed_height = match take(&mut pos, 1)?[0] {
        0x00 => None,
        0x01 => Some(u64::from_be_bytes(
            take(&mut pos, 8)?
                .try_into()
                .map_err(|_| StorePortError::CorruptContext)?,
        )),
        _ => return Err(StorePortError::CorruptContext),
    };
    let claim_evidence_verified = match take(&mut pos, 1)?[0] {
        0x00 => false,
        0x01 => true,
        _ => return Err(StorePortError::CorruptContext),
    };
    let refund_path_armed = match take(&mut pos, 1)?[0] {
        0x00 => false,
        0x01 => true,
        _ => return Err(StorePortError::CorruptContext),
    };
    if pos != bytes.len() {
        return Err(StorePortError::CorruptContext);
    }
    Ok(SettlementContext {
        state,
        revision,
        last_observed_height,
        claim_evidence_verified,
        refund_path_armed,
    })
}

/// Hash of the persisted context (recovery cross-check, spec §13).
pub fn context_hash(ctx: &SettlementContext) -> Digest32 {
    blake2b_256(CONTEXT_DOMAIN, &encode_context(ctx))
}

fn encode_effect_payload(effect: &Effect) -> Vec<u8> {
    let mut out = Vec::with_capacity(150);
    out.extend_from_slice(&effect_kind(effect).to_be_bytes());
    match effect {
        Effect::AuthorizeFunding | Effect::ArmRefundPath => {}
        Effect::RequestClaimConsumption { evidence } => put_evidence(&mut out, evidence),
        Effect::RevalidateFrom { height } => out.extend_from_slice(&height.to_be_bytes()),
        Effect::RecordTerminalOutcome(state) => {
            out.extend_from_slice(&state_tag(*state).to_be_bytes())
        }
    }
    out
}

fn decode_effect_payload(bytes: &[u8]) -> Result<Effect> {
    let fail = || StorePortError::CorruptContext;
    if bytes.len() < 2 {
        return Err(fail());
    }
    let tag = u16::from_be_bytes(bytes[..2].try_into().map_err(|_| fail())?);
    let body = &bytes[2..];
    let effect = match tag {
        1 if body.is_empty() => Effect::AuthorizeFunding,
        3 if body.is_empty() => Effect::ArmRefundPath,
        2 if body.len() == 32 + 32 + 4 + 8 + 32 => {
            let chain_id = ChainId(body[..32].try_into().map_err(|_| fail())?);
            let tx_id: Digest32 = body[32..64].try_into().map_err(|_| fail())?;
            let event_index = u32::from_be_bytes(body[64..68].try_into().map_err(|_| fail())?);
            let block_height = u64::from_be_bytes(body[68..76].try_into().map_err(|_| fail())?);
            let block_anchor: Digest32 = body[76..108].try_into().map_err(|_| fail())?;
            Effect::RequestClaimConsumption {
                evidence: EvidenceRefV1 {
                    chain_id,
                    tx_id,
                    event_index,
                    block_height,
                    block_anchor,
                },
            }
        }
        4 if body.len() == 8 => Effect::RevalidateFrom {
            height: u64::from_be_bytes(body.try_into().map_err(|_| fail())?),
        },
        5 if body.len() == 2 => Effect::RecordTerminalOutcome(state_from_tag(u16::from_be_bytes(
            body.try_into().map_err(|_| fail())?,
        ))?),
        _ => return Err(fail()),
    };
    Ok(effect)
}

/// Journal identity of a spec-§11.8 refresh re-application: a
/// domain-separated digest over the original event id and the resulting
/// revision. Deterministic (crash replay re-derives the same value),
/// unique (the revision strictly increases), and unable to collide with
/// a real event id short of a hash collision.
fn refresh_event_id(event_id: &[u8; 32], resulting_revision: u64) -> [u8; 32] {
    use blake2::digest::{Update, VariableOutput};
    let mut h = blake2::Blake2bVar::new(32).expect("blake2 output size"); // I14-ALLOW: fixed-size BLAKE2 output
    h.update(b"DOM-INTEROP/F2-REFRESH/V1\0");
    h.update(event_id);
    h.update(&resulting_revision.to_be_bytes());
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("blake2 finalize"); // I14-ALLOW: fixed-size BLAKE2 output
    out
}

impl OutboxEffectV1 {
    /// Derives the deterministic outbox entry of one effect (spec §9).
    pub fn derive(
        settlement_id: SettlementId,
        source_event_id: EvidenceId,
        effect: &Effect,
    ) -> Self {
        let payload = encode_effect_payload(effect);
        let payload_hash = blake2b_256(EFFECT_PAYLOAD_DOMAIN, &payload);
        let mut preimage = Vec::with_capacity(32 + 32 + 2 + 32);
        preimage.extend_from_slice(&settlement_id.0);
        preimage.extend_from_slice(&source_event_id.0);
        preimage.extend_from_slice(&effect_kind(effect).to_be_bytes());
        preimage.extend_from_slice(&payload_hash);
        let effect_id = EffectId(blake2b_256(EFFECT_DOMAIN, &preimage));
        Self {
            effect_id,
            settlement_id,
            source_event_id,
            kind: effect.clone(),
            payload_hash,
            payload,
        }
    }
}

/// Derives the outbox entries of one accepted transition, in order.
pub fn effects_to_outbox(env: &EventEnvelopeV1, effects: &[Effect]) -> Vec<OutboxEffectV1> {
    effects
        .iter()
        .map(|e| OutboxEffectV1::derive(env.settlement_id, env.event_id, e))
        .collect()
}

// ---- the typed store contract ------------------------------------------

/// Durable settlement store (F2 spec §8.2, plus `record_late_evidence`
/// used by the engine's §10 ingest and the read APIs recovery needs).
pub trait SettlementStore: Send + Sync {
    /// Creates one settlement from validated terms. Idempotent for the
    /// byte-identical re-presentation; a diverging binding fails closed.
    fn create(&self, terms: &SettlementTermsV1, now_unix_ms: i64) -> Result<SettlementSnapshot>;

    /// Loads the snapshot, if the settlement exists.
    fn load(&self, id: SettlementId) -> Result<Option<SettlementSnapshot>>;

    /// Commits one accepted transition atomically (§8.2 steps 1–9).
    fn commit_transition(
        &self,
        expected_revision: u64,
        event: &EventEnvelopeV1,
        transition: &Transition,
        effects: &[OutboxEffectV1],
        cursor_update: Option<&CursorUpdateV1>,
        now_unix_ms: i64,
    ) -> Result<CommitResult>;

    /// Parks evidence the machine cannot accept yet (reorder, spec §10).
    fn park_evidence(
        &self,
        settlement_id: SettlementId,
        evidence_id: EvidenceId,
        evidence: &EvidenceRefV1,
    ) -> Result<ParkResult>;

    /// Claims dispatchable outbox entries (pending or expired lease).
    fn ready_outbox(
        &self,
        now_unix_ms: i64,
        lease_ms: i64,
        max: u32,
    ) -> Result<Vec<ClaimedEffectV1>>;

    /// Completes one effect after external execution, revalidating the
    /// payload hash.
    fn complete_effect(
        &self,
        effect_id: EffectId,
        expected_payload_hash: Digest32,
        now_unix_ms: i64,
    ) -> Result<()>;

    /// Records late evidence by identifier only (spec §12).
    fn record_late_evidence(
        &self,
        settlement_id: SettlementId,
        evidence_id: EvidenceId,
        terminal: SettlementState,
        now_unix_ms: i64,
    ) -> Result<()>;

    /// Marks evidence at or above `from_height` invalidated by a reorg
    /// (spec §11 step 2). Idempotent; returns the number of rows moved.
    fn invalidate_evidence_from(
        &self,
        settlement_id: SettlementId,
        from_height: u64,
    ) -> Result<usize>;

    /// Re-affirms one already-committed observation as canonical again,
    /// promoting its evidence row from invalidated back to applied (never
    /// a parked row). Called when a redelivery is acknowledged.
    fn reaffirm_evidence(
        &self,
        settlement_id: SettlementId,
        evidence_id: EvidenceId,
    ) -> Result<usize>;

    // ---- read-only accessors required by recovery (spec §13) ----------
    //
    // §8.2 freezes the mutating contract; recovery additionally has to
    // "rebuild the context from the journal and compare it with the
    // snapshot", "revalidate cursors against anchors" and "reapply parked
    // evidence" — none of which is possible without reading them back.
    // Every method below is strictly read-only.

    /// Canonical bytes already journalled for one event id, if any.
    /// Lets the caller acknowledge a redelivery before the machine is
    /// consulted (spec §9); the authoritative dedupe stays in
    /// [`SettlementStore::commit_transition`].
    fn committed_event(&self, id: SettlementId, event_id: EvidenceId) -> Result<Option<Vec<u8>>>;

    /// Frozen terms of the settlement, decoded from the persisted
    /// canonical bytes, plus the terms hash they were bound to.
    fn terms(&self, id: SettlementId) -> Result<Option<(SettlementTermsV1, Digest32)>>;

    /// Journal rows in sequence order; a gap fails closed as corruption.
    fn journal(&self, id: SettlementId) -> Result<Vec<JournalRow>>;

    /// Evidence rows with the given status, in canonical chain order.
    fn evidence(&self, id: SettlementId, status: EvidenceStatus) -> Result<Vec<StoredEvidence>>;

    /// Durable cursor of one (settlement, chain).
    fn cursor(&self, id: SettlementId, chain: ChainId) -> Result<Option<StoredCursor>>;

    /// Terminal outcome, if the settlement is finalized.
    fn terminal(&self, id: SettlementId) -> Result<Option<(SettlementState, EvidenceId, u64)>>;
}

/// Status of one durable evidence row.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvidenceStatus {
    /// Waiting for the machine to accept it (reorder, spec §10).
    Parked,
    /// Accepted by a committed transition.
    Applied,
    /// Invalidated by a reorg.
    Invalidated,
}

impl EvidenceStatus {
    fn tag(self) -> i64 {
        match self {
            Self::Parked => store::EVIDENCE_PARKED,
            Self::Applied => store::EVIDENCE_APPLIED,
            Self::Invalidated => store::EVIDENCE_INVALIDATED,
        }
    }
}

/// One durable evidence row: its identifier and the public reference.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StoredEvidence {
    /// Identifier the evidence was recorded under (equals the event id
    /// of the event that carried it).
    pub evidence_id: EvidenceId,
    /// The public chain reference. Never secret material.
    pub reference: EvidenceRefV1,
}

/// One journal row, decoded (spec §13 replay input).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct JournalRow {
    /// Sequence, contiguous from 1.
    pub seq: u64,
    /// Revision the commit expected.
    pub expected_revision: u64,
    /// Revision the commit produced.
    pub resulting_revision: u64,
    /// The decoded envelope (strict decode; corruption fails closed).
    pub envelope: EventEnvelopeV1,
    /// Hash of the context the commit produced.
    pub context_hash: Digest32,
}

/// SQLite/WAL implementation over the neutral `store` crate (ADR-A7).
pub struct SqliteSettlementStore {
    inner: Mutex<store::Store>,
}

impl core::fmt::Debug for SqliteSettlementStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SqliteSettlementStore([redacted])")
    }
}

impl SqliteSettlementStore {
    /// Opens (or creates) the database at `path`, applying migrations.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        Ok(Self {
            inner: Mutex::new(store::Store::open(path)?),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, store::Store> {
        // A poisoned mutex means another thread panicked mid-operation;
        // the transaction it held has rolled back, so the state is
        // consistent and continuing is safe.
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

fn map_commit_err(e: StorePortError) -> StorePortError {
    match e {
        StorePortError::Storage(store::StoreError::IdempotencyConflict) => {
            StorePortError::Equivocation
        }
        StorePortError::Storage(store::StoreError::RevisionConflict) => {
            StorePortError::RevisionConflict
        }
        other => other,
    }
}

fn accepted_evidence(event: &SettlementEvent) -> Option<&EvidenceRefV1> {
    match event {
        SettlementEvent::FundingObserved { evidence }
        | SettlementEvent::FundingConfirmed { evidence }
        | SettlementEvent::ClaimEvidenceVerified { evidence }
        | SettlementEvent::ClaimConfirmed { evidence }
        | SettlementEvent::RefundConfirmed { evidence } => Some(evidence),
        _ => None,
    }
}

impl SettlementStore for SqliteSettlementStore {
    fn create(&self, terms: &SettlementTermsV1, now_unix_ms: i64) -> Result<SettlementSnapshot> {
        let canonical = terms
            .canonical_bytes()
            .map_err(|_| StorePortError::CorruptContext)?;
        let terms_hash = terms
            .terms_hash()
            .map_err(|_| StorePortError::CorruptContext)?;
        let initial = SettlementContext::new();
        let row = self
            .lock()
            .f2_create(&store::SettlementCreate {
                settlement_id: terms.settlement_id.0,
                session_id: terms.session_id.0,
                terms_hash,
                canonical_terms: &canonical,
                initial_state_tag: state_tag(initial.state),
                initial_context: &encode_context(&initial),
                created_at_unix_ms: now_unix_ms,
            })
            .map_err(|e| map_commit_err(StorePortError::Storage(e)))?;
        Ok(SettlementSnapshot {
            settlement_id: terms.settlement_id,
            session_id: terms.session_id,
            terms_hash: row.terms_hash,
            context: decode_context(&row.context_bytes)?,
            last_event_seq: row.last_event_seq,
        })
    }

    fn load(&self, id: SettlementId) -> Result<Option<SettlementSnapshot>> {
        let Some(row) = self.lock().f2_load(id.0)? else {
            return Ok(None);
        };
        let context = decode_context(&row.context_bytes)?;
        // The snapshot's denormalized columns must agree with the encoded
        // context — a divergence is corruption, not a preference.
        if row.revision != context.revision || row.state_tag != state_tag(context.state) {
            return Err(StorePortError::CorruptContext);
        }
        Ok(Some(SettlementSnapshot {
            settlement_id: id,
            session_id: SessionId(row.session_id),
            terms_hash: row.terms_hash,
            context,
            last_event_seq: row.last_event_seq,
        }))
    }

    fn commit_transition(
        &self,
        expected_revision: u64,
        event: &EventEnvelopeV1,
        transition: &Transition,
        effects: &[OutboxEffectV1],
        cursor_update: Option<&CursorUpdateV1>,
        now_unix_ms: i64,
    ) -> Result<CommitResult> {
        if event.protocol_version != PROTOCOL_VERSION {
            return Err(StorePortError::UnknownVersion);
        }
        let event_bytes = event.canonical_bytes();
        let next = &transition.next;
        let outbox_rows: Vec<store::OutboxInsert<'_>> = effects
            .iter()
            .map(|e| store::OutboxInsert {
                effect_id: e.effect_id.0,
                effect_kind: effect_kind(&e.kind),
                payload: &e.payload,
                payload_hash: e.payload_hash,
            })
            .collect();
        let evidence = accepted_evidence(&event.event).map(|ev| store::EvidenceRow {
            evidence_id: event.event_id.0,
            chain_id: ev.chain_id.0,
            tx_id: ev.tx_id,
            event_index: ev.event_index,
            block_height: ev.block_height,
            block_anchor: ev.block_anchor,
            status_tag: store::EVIDENCE_APPLIED,
        });
        let cursor = cursor_update.map(|c| store::CursorUpdate {
            chain_id: c.chain_id.0,
            cursor_bytes: &c.cursor_bytes,
            anchor_height: c.anchor_height.and_then(|h| i64::try_from(h).ok()),
            anchor_hash: c.anchor_hash,
        });
        let terminal = next.state.is_terminal().then(|| store::TerminalInsert {
            outcome_tag: state_tag(next.state),
            source_event_id: event.event_id.0,
        });
        let outcome = self
            .lock()
            .f2_commit_transition(&store::SettlementCommit {
                settlement_id: event.settlement_id.0,
                event_id: event.event_id.0,
                refresh_event_id: Some(refresh_event_id(&event.event_id.0, next.revision)),
                event_kind: event_kind(&event.event),
                event_bytes: &event_bytes,
                expected_revision,
                resulting_revision: next.revision,
                state_tag: state_tag(next.state),
                context_bytes: &encode_context(next),
                context_hash: context_hash(next),
                evidence,
                cursor,
                effects: &outbox_rows,
                terminal,
                now_unix_ms,
            })
            .map_err(|e| map_commit_err(StorePortError::Storage(e)))?;
        Ok(match outcome {
            store::CommitOutcome::Committed => CommitResult::Committed {
                revision: next.revision,
            },
            store::CommitOutcome::DuplicateSameBytes => CommitResult::DuplicateSameBytes,
        })
    }

    fn park_evidence(
        &self,
        settlement_id: SettlementId,
        evidence_id: EvidenceId,
        evidence: &EvidenceRefV1,
    ) -> Result<ParkResult> {
        let mut guard = self.lock();
        let seq = guard
            .f2_load(settlement_id.0)?
            .ok_or(StorePortError::Storage(store::StoreError::NotFound))?
            .last_event_seq;
        let outcome = guard
            .f2_park_evidence(
                settlement_id.0,
                &store::EvidenceRow {
                    evidence_id: evidence_id.0,
                    chain_id: evidence.chain_id.0,
                    tx_id: evidence.tx_id,
                    event_index: evidence.event_index,
                    block_height: evidence.block_height,
                    block_anchor: evidence.block_anchor,
                    status_tag: store::EVIDENCE_PARKED,
                },
                seq,
            )
            .map_err(|e| map_commit_err(StorePortError::Storage(e)))?;
        Ok(match outcome {
            store::ParkOutcome::Parked => ParkResult::Parked,
            store::ParkOutcome::AlreadyPresent => ParkResult::AlreadyParked,
        })
    }

    fn ready_outbox(
        &self,
        now_unix_ms: i64,
        lease_ms: i64,
        max: u32,
    ) -> Result<Vec<ClaimedEffectV1>> {
        let claimed = self.lock().f2_ready_outbox(now_unix_ms, lease_ms, max)?;
        claimed
            .into_iter()
            .map(|c| {
                Ok(ClaimedEffectV1 {
                    settlement_id: SettlementId(c.settlement_id),
                    effect_id: EffectId(c.effect_id),
                    kind: decode_effect_payload(&c.payload)?,
                    payload: c.payload,
                    payload_hash: c.payload_hash,
                    attempts: c.attempts,
                })
            })
            .collect()
    }

    fn complete_effect(
        &self,
        effect_id: EffectId,
        expected_payload_hash: Digest32,
        now_unix_ms: i64,
    ) -> Result<()> {
        self.lock()
            .f2_complete_effect(effect_id.0, expected_payload_hash, now_unix_ms)
            .map_err(|e| map_commit_err(StorePortError::Storage(e)))
    }

    fn record_late_evidence(
        &self,
        settlement_id: SettlementId,
        evidence_id: EvidenceId,
        terminal: SettlementState,
        now_unix_ms: i64,
    ) -> Result<()> {
        self.lock()
            .f2_record_late_evidence(
                settlement_id.0,
                evidence_id.0,
                state_tag(terminal),
                now_unix_ms,
            )
            .map_err(StorePortError::Storage)
    }

    fn invalidate_evidence_from(
        &self,
        settlement_id: SettlementId,
        from_height: u64,
    ) -> Result<usize> {
        self.lock()
            .f2_invalidate_evidence_from(settlement_id.0, from_height)
            .map_err(StorePortError::Storage)
    }

    fn reaffirm_evidence(
        &self,
        settlement_id: SettlementId,
        evidence_id: EvidenceId,
    ) -> Result<usize> {
        self.lock()
            .f2_reaffirm_evidence(settlement_id.0, evidence_id.0)
            .map_err(StorePortError::Storage)
    }

    fn committed_event(&self, id: SettlementId, event_id: EvidenceId) -> Result<Option<Vec<u8>>> {
        Ok(self.lock().f2_journalled_event(id.0, event_id.0)?)
    }

    fn terms(&self, id: SettlementId) -> Result<Option<(SettlementTermsV1, Digest32)>> {
        let Some((canonical, terms_hash)) = self.lock().f2_terms(id.0)? else {
            return Ok(None);
        };
        // The persisted bytes are re-decoded STRICTLY and re-hashed: the
        // engine must never run under terms that the stored hash does not
        // cover (spec §20 — policy is derived from SettlementTermsV1, not
        // from loose parameters).
        let terms =
            SettlementTermsV1::decode(&canonical).map_err(|_| StorePortError::CorruptContext)?;
        if terms
            .terms_hash()
            .map_err(|_| StorePortError::CorruptContext)?
            != terms_hash
            || terms.settlement_id != id
        {
            return Err(StorePortError::CorruptContext);
        }
        Ok(Some((terms, terms_hash)))
    }

    fn journal(&self, id: SettlementId) -> Result<Vec<JournalRow>> {
        self.lock()
            .f2_read_journal(id.0)?
            .into_iter()
            .map(|row| {
                let envelope = EventEnvelopeV1::decode(&row.event_bytes)?;
                // The journal is the recovery authority: a row whose
                // stored kind disagrees with its own bytes is corruption.
                if event_kind(&envelope.event) != row.event_kind {
                    return Err(StorePortError::CorruptEvent);
                }
                Ok(JournalRow {
                    seq: row.seq,
                    expected_revision: row.expected_revision,
                    resulting_revision: row.resulting_revision,
                    envelope,
                    context_hash: row.context_hash,
                })
            })
            .collect()
    }

    fn evidence(&self, id: SettlementId, status: EvidenceStatus) -> Result<Vec<StoredEvidence>> {
        Ok(self
            .lock()
            .f2_evidence(id.0, status.tag())?
            .into_iter()
            .map(|r| StoredEvidence {
                evidence_id: EvidenceId(r.evidence_id),
                reference: EvidenceRefV1 {
                    chain_id: ChainId(r.chain_id),
                    tx_id: r.tx_id,
                    event_index: r.event_index,
                    block_height: r.block_height,
                    block_anchor: r.block_anchor,
                },
            })
            .collect())
    }

    fn cursor(&self, id: SettlementId, chain: ChainId) -> Result<Option<StoredCursor>> {
        let row = self.lock().f2_cursor(id.0, chain.0)?;
        row.map(|(cursor_bytes, height, anchor_hash, revision)| {
            let anchor_height = match height {
                None => None,
                Some(h) => Some(u64::try_from(h).map_err(|_| StorePortError::CorruptContext)?),
            };
            Ok(StoredCursor {
                cursor_bytes,
                anchor_height,
                anchor_hash,
                revision,
            })
        })
        .transpose()
    }

    fn terminal(&self, id: SettlementId) -> Result<Option<(SettlementState, EvidenceId, u64)>> {
        let Some((tag, source, revision)) = self.lock().f2_terminal(id.0)? else {
            return Ok(None);
        };
        Ok(Some((state_from_tag(tag)?, EvidenceId(source), revision)))
    }
}
