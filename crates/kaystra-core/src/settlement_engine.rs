//! Durable settlement engine (F2 spec §10–§13, build order step 9).
//!
//! The engine owns no economic authority: every decision it takes is
//! either the pure machine's ([`crate::state::transition`]) or the frozen
//! terms' ([`SettlementTermsV1`]). It contributes exactly three things:
//!
//! 1. it feeds the machine what the chain adapter observed, as canonical
//!    envelopes whose identifiers are pure functions of the observation
//!    (so redelivery is an ACK, never a second effect);
//! 2. it derives the POLICY events — finality confirmations, timelock
//!    expiry, post-reorg funding absence — from the frozen terms and the
//!    durable state, never from process memory it cannot rebuild;
//! 3. it dispatches the durable outbox and marks completion.
//!
//! # What the engine never touches
//!
//! `t`, nonces, shares and seeds never enter this module. A claim shows up
//! as [`ChainRecordV1::Claim`], which carries an [`EvidenceRefV1`] and
//! nothing else; consuming that evidence cryptographically is the job of
//! the `RequestClaimConsumption` effect at the F1 boundary (spec §16).
//!
//! # The two safety arguments worth reading before changing anything
//!
//! **Cursor.** The durable cursor means "every scan position at or below
//! this has produced its durable consequence". It therefore advances only
//! inside a committing transaction (spec §9), and never past an
//! observation whose consequence is still only in memory. There is
//! exactly one such observation kind — a refund spend awaiting finality,
//! because the frozen machine has no `RefundObserved` event to land it on
//! — so the engine holds the cursor below the lowest pending refund. Any
//! crash rescans from the durable cursor and re-derives that set.
//!
//! **Finality.** A terminal is immutable, so no terminal event may be
//! emitted from an observation that a reorg could still remove:
//! `ClaimConfirmed` and `RefundConfirmed` are emitted only once the
//! observation satisfies `min_confirmations` from the terms. Non-terminal
//! observations (`FundingObserved`, `ClaimEvidenceVerified`) commit on
//! sight, which is safe precisely because a reorg regresses them.

use crate::ingest::{EngineError as IngestError, IngestResult, ReorderBuffer};
use crate::state::{
    transition, Effect, EvidenceRefV1, SettlementContext, SettlementEvent, SettlementState,
};
use crate::store_port::{
    context_hash, derive_event_id, ClaimedEffectV1, CursorUpdateV1, EventEnvelopeV1,
    EvidenceStatus, SettlementSnapshot, SettlementStore, StorePortError, PROTOCOL_VERSION,
};
use crate::terms::SettlementTermsV1;
use crate::types::{ChainId, Digest32, SettlementId};

/// Opaque scanner position, described by the adapter that produced it.
///
/// The core never synthesizes these bytes (§4.7 keeps cursors opaque to
/// the core); it persists them and hands them back. `height` and `anchor`
/// are the adapter's own description of the same position, used for the
/// anchor revalidation of spec §11/§13.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChainCursorV1 {
    /// Opaque bytes, meaningful only to the adapter.
    pub bytes: Vec<u8>,
    /// Height this position corresponds to.
    pub height: u64,
    /// Anchor (block hash) committed at that height.
    pub anchor: Digest32,
}

/// One record produced by the chain adapter for THIS settlement.
///
/// The adapter has already verified the evidence and filtered by
/// settlement (spec §3: "the chain adapter verifies the evidence and
/// produces a neutral event"). No variant carries secret material.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ChainRecordV1 {
    /// The funding lock was observed on chain.
    Funding {
        /// Public reference to the funding inclusion.
        evidence: EvidenceRefV1,
    },
    /// A claim spend of the lock was observed and verified.
    Claim {
        /// Public reference to the claim inclusion.
        evidence: EvidenceRefV1,
    },
    /// A refund spend of the lock was observed.
    Refund {
        /// Public reference to the refund inclusion.
        evidence: EvidenceRefV1,
    },
    /// The adapter detected that its anchor no longer matches the chain.
    Reorg {
        /// First invalidated height.
        from_height: u64,
        /// Anchor of the abandoned branch.
        old_anchor: Digest32,
    },
}

/// Stable fail-closed taxonomy for a real chain observation boundary.
///
/// A simulator cannot normally produce these failures, but the F7 DOM RPC
/// adapter must never translate an unavailable node or invalid response into
/// an empty successful scan.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ChainSourceErrorV1 {
    /// The node, transport or authenticated RPC service is unavailable.
    #[error("chain source unavailable")]
    Unavailable,
    /// The response is malformed or fails canonical evidence validation.
    #[error("chain evidence invalid")]
    InvalidEvidence,
    /// The supplied cursor no longer names a canonical anchor.
    #[error("chain cursor is stale")]
    StaleCursor,
    /// A configured or protocol bound was exceeded.
    #[error("chain source bound exceeded")]
    BoundsExceeded,
    /// The observed chain/version identity differs from frozen terms.
    #[error("chain identity mismatch")]
    IdentityMismatch,
}

/// Neutral source of chain observations for one settlement.
pub trait ChainSourceV1 {
    /// Chain this source observes (must match the leg's `chain_id`).
    fn chain_id(&self) -> ChainId;
    /// Position before any block.
    fn genesis_cursor(&self) -> Result<ChainCursorV1, ChainSourceErrorV1>;
    /// Position corresponding to "everything up to `height` consumed".
    fn cursor_at(&self, height: u64) -> Result<ChainCursorV1, ChainSourceErrorV1>;
    /// Scans forward from `from`, returning the records and the position
    /// reached. On a stale anchor it must emit [`ChainRecordV1::Reorg`]
    /// and return a rewound position (spec §11).
    fn scan(
        &self,
        from: &ChainCursorV1,
    ) -> Result<(Vec<ChainRecordV1>, ChainCursorV1), ChainSourceErrorV1>;
    /// Current tip height.
    fn tip_height(&self) -> Result<u64, ChainSourceErrorV1>;
}

/// Outcome of executing one outbox effect externally.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EffectOutcome {
    /// Executed; the entry may be marked completed.
    Completed,
    /// Transient failure; the lease will bring it back byte-identical.
    RetryLater,
    /// The target refused it. The entry stays pending and is COUNTED —
    /// an effect is never silently dropped.
    Rejected,
}

/// Sink that executes outbox effects against the outside world.
pub trait EffectSinkV1 {
    /// Executes one effect. The payload handed over is exactly the bytes
    /// first persisted; the sink must never reconstruct them.
    fn execute(&mut self, effect: &ClaimedEffectV1) -> EffectOutcome;
}

/// Policy derived from the frozen terms (spec §20: never loose params).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EnginePolicyV1 {
    /// Confirmations required before an observation is final.
    pub min_confirmations: u64,
    /// Deepest reorg the policy tolerates.
    pub max_reorg_depth: u64,
    /// Height from which the refund path is executable.
    pub refund_not_before_height: u64,
}

/// Report of one [`SettlementEngine::tick`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TickReportV1 {
    /// Chain records consumed.
    pub records_seen: usize,
    /// Transitions committed.
    pub committed: usize,
    /// Byte-identical redeliveries acknowledged.
    pub duplicates: usize,
    /// Events parked for reorder.
    pub parked: usize,
    /// Events classified late (terminal already reached).
    pub late: usize,
    /// Effects claimed from the outbox.
    pub effects_dispatched: usize,
    /// Effects marked completed.
    pub effects_completed: usize,
    /// Effects the sink refused (still pending, never dropped).
    pub effects_rejected: usize,
    /// Commits lost to a concurrent writer's CAS. Not an error: the other
    /// writer's transition is durable, this one simply reloads (spec §16
    /// F2-E2E-016) and the scan redelivers what it has not consumed.
    pub conflicts: usize,
    /// State at the end of the tick.
    pub state: Option<SettlementState>,
}

/// Engine failures. Every variant is fail-closed: the engine stops rather
/// than continuing on state it cannot justify.
#[derive(Debug, thiserror::Error)]
pub enum SettlementEngineError {
    /// No settlement (or no terms) with this identifier.
    #[error("unknown settlement")]
    UnknownSettlement,
    /// The source observes a different chain than the leg's terms name.
    #[error("chain source does not match the terms")]
    ChainMismatch,
    /// The DOM leg's timelock domain is not driven by this phase.
    ///
    /// F2 drives height-based deadlines (the domain `dom-sim` and the DOM
    /// leg use). Timestamp and BTC 512-second domains arrive with their
    /// adapters in F3/F5; accepting them here would mean inventing a
    /// clock the engine does not have.
    #[error("unsupported timelock domain for the DOM leg")]
    UnsupportedTimelockDomain,
    /// Real chain observation failed. No cursor or economic state is advanced.
    #[error("chain source: {0}")]
    ChainSource(#[from] ChainSourceErrorV1),
    /// Journal replay does not reproduce the snapshot (spec §13 step 4).
    #[error("recovery divergence: {0}")]
    RecoveryDivergence(&'static str),
    /// A parked evidence row does not correspond to any event this
    /// settlement could have produced.
    #[error("unreconstructable parked evidence")]
    UnreconstructableParkedEvidence,
    /// Ingestion failure (binding mismatch, hard machine rejection...).
    #[error("ingest: {0}")]
    Ingest(#[from] IngestError),
    /// Durable store failure.
    #[error("store: {0}")]
    Store(#[from] StorePortError),
}

/// Maximum policy ingests per tick. Each one either commits (advancing
/// the machine) or is skipped, so the bound is a backstop, not a rule.
const MAX_POLICY_INGESTS_PER_TICK: usize = 16;

/// Durable settlement engine for ONE settlement.
pub struct SettlementEngine<S: SettlementStore, C: ChainSourceV1, K: EffectSinkV1> {
    store: S,
    chain: C,
    sink: K,
    settlement_id: SettlementId,
    terms: SettlementTermsV1,
    terms_hash: Digest32,
    policy: EnginePolicyV1,
    scan_cursor: ChainCursorV1,
    /// Refund spends seen but not yet final. The ONLY engine state that
    /// is not durable — see the cursor argument in the module docs.
    pending_refunds: Vec<EvidenceRefV1>,
    reorder: ReorderBuffer,
    timelock_committed: bool,
    lease_ms: i64,
    max_effects_per_tick: u32,
}

impl<S: SettlementStore, C: ChainSourceV1, K: EffectSinkV1> core::fmt::Debug
    for SettlementEngine<S, C, K>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SettlementEngine")
            .field("settlement_id", &self.settlement_id)
            .field("policy", &self.policy)
            .field("scan_height", &self.scan_cursor.height)
            .field("pending_refunds", &self.pending_refunds.len())
            .field("parked", &self.reorder.parked_len())
            .finish()
    }
}

impl<S: SettlementStore, C: ChainSourceV1, K: EffectSinkV1> SettlementEngine<S, C, K> {
    /// Opens the engine over an existing settlement and RECOVERS it
    /// (spec §13): journal replay compared with the snapshot, cursor
    /// revalidation, parked evidence reconstruction. Any divergence
    /// fails closed — there is no administrative override.
    pub fn open(
        store: S,
        chain: C,
        sink: K,
        settlement_id: SettlementId,
    ) -> Result<Self, SettlementEngineError> {
        let (terms, terms_hash) = store
            .terms(settlement_id)?
            .ok_or(SettlementEngineError::UnknownSettlement)?;
        if terms.dom_leg.chain_id != chain.chain_id() {
            return Err(SettlementEngineError::ChainMismatch);
        }
        let refund_not_before_height = match terms.dom_leg.deadline {
            crate::types::TimelockSpec::BlockHeight { value } => value,
            _ => return Err(SettlementEngineError::UnsupportedTimelockDomain),
        };
        let policy = EnginePolicyV1 {
            min_confirmations: u64::from(terms.dom_leg.finality.min_confirmations),
            max_reorg_depth: u64::from(terms.dom_leg.finality.max_reorg_depth),
            refund_not_before_height,
        };
        let scan_cursor = chain.genesis_cursor()?;
        let mut engine = Self {
            store,
            chain,
            sink,
            settlement_id,
            terms,
            terms_hash,
            policy,
            scan_cursor,
            pending_refunds: Vec::new(),
            reorder: ReorderBuffer::new(),
            timelock_committed: false,
            lease_ms: 30_000,
            max_effects_per_tick: 32,
        };
        engine.recover()?;
        Ok(engine)
    }

    /// Lease granted to a claimed effect, in milliseconds.
    pub fn with_lease_ms(mut self, lease_ms: i64) -> Self {
        self.lease_ms = lease_ms;
        self
    }

    /// Borrowed durable store (inspection; the engine keeps ownership).
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Borrowed chain source.
    pub fn chain(&self) -> &C {
        &self.chain
    }

    /// Borrowed effect sink.
    pub fn sink(&self) -> &K {
        &self.sink
    }

    /// Consumes the engine, returning its parts (used by crash tests to
    /// keep the chain and the store alive across a simulated restart).
    pub fn into_parts(self) -> (S, C, K) {
        (self.store, self.chain, self.sink)
    }

    /// Frozen terms this engine runs under.
    pub fn terms(&self) -> &SettlementTermsV1 {
        &self.terms
    }

    /// Policy derived from those terms.
    pub fn policy(&self) -> EnginePolicyV1 {
        self.policy
    }

    /// Current durable snapshot.
    pub fn snapshot(&self) -> Result<SettlementSnapshot, SettlementEngineError> {
        self.store
            .load(self.settlement_id)?
            .ok_or(SettlementEngineError::UnknownSettlement)
    }

    /// Envelopes still waiting for order.
    pub fn parked_len(&self) -> usize {
        self.reorder.parked_len()
    }

    // ---- recovery (spec §13) ------------------------------------------

    fn recover(&mut self) -> Result<(), SettlementEngineError> {
        let snapshot = self.snapshot()?;
        if snapshot.terms_hash != self.terms_hash || snapshot.session_id != self.terms.session_id {
            return Err(SettlementEngineError::RecoveryDivergence(
                "snapshot binding differs from the frozen terms",
            ));
        }

        // 1-4. Rebuild the context from the journal and compare it with
        //      the snapshot. The store already refuses a sequence gap;
        //      here the ECONOMIC content is re-derived and every recorded
        //      revision and context hash must match exactly.
        let rows = self.store.journal(self.settlement_id)?;
        let mut ctx = SettlementContext::new();
        let mut expected_seq = 0u64;
        for row in &rows {
            expected_seq += 1;
            if row.seq != expected_seq {
                return Err(SettlementEngineError::RecoveryDivergence("journal gap"));
            }
            if row.envelope.settlement_id != self.settlement_id
                || row.envelope.session_id != self.terms.session_id
                || row.envelope.terms_hash != self.terms_hash
            {
                return Err(SettlementEngineError::RecoveryDivergence(
                    "journalled envelope is bound to different terms",
                ));
            }
            if row.expected_revision != ctx.revision {
                return Err(SettlementEngineError::RecoveryDivergence(
                    "journalled expected revision is not the replayed one",
                ));
            }
            let applied = transition(ctx, &row.envelope.event).map_err(|_| {
                SettlementEngineError::RecoveryDivergence("journalled event replays as illegal")
            })?;
            if applied.next.revision != row.resulting_revision {
                return Err(SettlementEngineError::RecoveryDivergence(
                    "replayed revision differs from the journalled one",
                ));
            }
            ctx = applied.next;
            if context_hash(&ctx) != row.context_hash {
                return Err(SettlementEngineError::RecoveryDivergence(
                    "replayed context hash differs from the journalled one",
                ));
            }
            if matches!(row.envelope.event, SettlementEvent::TimelockExpired) {
                self.timelock_committed = true;
            }
        }
        if ctx != snapshot.context {
            return Err(SettlementEngineError::RecoveryDivergence(
                "journal replay does not reproduce the snapshot",
            ));
        }
        if snapshot.last_event_seq != expected_seq {
            return Err(SettlementEngineError::RecoveryDivergence(
                "snapshot sequence does not match the journal length",
            ));
        }

        // A terminal row and a terminal context are written in the same
        // transaction: one without the other is corruption.
        match self.store.terminal(self.settlement_id)? {
            Some((state, _, revision)) => {
                if !ctx.state.is_terminal() || state != ctx.state || revision != ctx.revision {
                    return Err(SettlementEngineError::RecoveryDivergence(
                        "terminal row disagrees with the replayed context",
                    ));
                }
            }
            None => {
                if ctx.state.is_terminal() {
                    return Err(SettlementEngineError::RecoveryDivergence(
                        "terminal context without a terminal row",
                    ));
                }
            }
        }

        // 5-6. Resume scanning at the durable cursor. Anchor divergence is
        //      adjudicated by the adapter on the first scan, which emits a
        //      reorg record instead of silently skipping the range.
        self.scan_cursor = match self
            .store
            .cursor(self.settlement_id, self.chain.chain_id())?
        {
            Some(stored) => match (stored.anchor_height, stored.anchor_hash) {
                (Some(height), Some(anchor)) => ChainCursorV1 {
                    bytes: stored.cursor_bytes,
                    height,
                    anchor,
                },
                _ => {
                    return Err(SettlementEngineError::RecoveryDivergence(
                        "persisted cursor has no anchor",
                    ))
                }
            },
            None => self.chain.genesis_cursor()?,
        };

        // 7. Reapply parked evidence, reconstructed from the durable rows.
        let parked = self
            .store
            .evidence(self.settlement_id, EvidenceStatus::Parked)?;
        let mut envelopes = Vec::with_capacity(parked.len());
        for row in parked {
            let event = self.invert_evidence_event(row.evidence_id, row.reference)?;
            envelopes.push(self.envelope_for(event));
        }
        self.reorder.adopt(envelopes);
        Ok(())
    }

    /// Recovers which event produced one durable evidence row.
    ///
    /// The evidence id IS the event id, and the event id is a pure
    /// function of `(settlement_id, event)`, so trying the five
    /// evidence-bearing constructors identifies the row exactly. No match
    /// means the row was not produced by this settlement's protocol —
    /// which is corruption, not something to guess around.
    fn invert_evidence_event(
        &self,
        evidence_id: crate::types::EvidenceId,
        reference: EvidenceRefV1,
    ) -> Result<SettlementEvent, SettlementEngineError> {
        let candidates = [
            SettlementEvent::FundingObserved {
                evidence: reference,
            },
            SettlementEvent::FundingConfirmed {
                evidence: reference,
            },
            SettlementEvent::ClaimEvidenceVerified {
                evidence: reference,
            },
            SettlementEvent::ClaimConfirmed {
                evidence: reference,
            },
            SettlementEvent::RefundConfirmed {
                evidence: reference,
            },
        ];
        candidates
            .into_iter()
            .find(|event| derive_event_id(self.settlement_id, event) == evidence_id)
            .ok_or(SettlementEngineError::UnreconstructableParkedEvidence)
    }

    // ---- envelopes -----------------------------------------------------

    /// Builds the canonical envelope of one event.
    ///
    /// Every field is a deterministic function of the settlement and the
    /// event — including `source_sequence`, which for chain-derived events
    /// is the block height. That determinism is what makes redelivery an
    /// idempotent ACK instead of an equivocation: two independent
    /// observers of the same chain position produce identical bytes.
    fn envelope_for(&self, event: SettlementEvent) -> EventEnvelopeV1 {
        let source_sequence = match &event {
            SettlementEvent::FundingObserved { evidence }
            | SettlementEvent::FundingConfirmed { evidence }
            | SettlementEvent::ClaimEvidenceVerified { evidence }
            | SettlementEvent::ClaimConfirmed { evidence }
            | SettlementEvent::RefundConfirmed { evidence } => evidence.block_height,
            SettlementEvent::FundingAbsent { revalidation_from } => *revalidation_from,
            SettlementEvent::ReorgInvalidated { from_height, .. } => *from_height,
            SettlementEvent::RefundArmed | SettlementEvent::TimelockExpired => 0,
        };
        EventEnvelopeV1 {
            protocol_version: PROTOCOL_VERSION,
            settlement_id: self.settlement_id,
            session_id: self.terms.session_id,
            terms_hash: self.terms_hash,
            source_chain: self.chain.chain_id(),
            event_id: derive_event_id(self.settlement_id, &event),
            source_sequence,
            event,
        }
    }

    fn cursor_update(&self, cursor: &ChainCursorV1) -> CursorUpdateV1 {
        CursorUpdateV1 {
            chain_id: self.chain.chain_id(),
            cursor_bytes: cursor.bytes.clone(),
            anchor_height: Some(cursor.height),
            anchor_hash: Some(cursor.anchor),
        }
    }

    /// Ingests one event, retrying once if a concurrent writer wins the
    /// CAS. `Ok(None)` means the race was lost twice: the other writer's
    /// transition is durable, and this engine simply continues — the
    /// cursor did not advance, so nothing is skipped.
    fn ingest(
        &mut self,
        event: SettlementEvent,
        cursor: Option<&CursorUpdateV1>,
        now_unix_ms: i64,
        report: &mut TickReportV1,
    ) -> Result<Option<IngestResult>, SettlementEngineError> {
        for attempt in 0..2 {
            let envelope = self.envelope_for(event.clone());
            match self
                .reorder
                .ingest(&self.store, envelope, cursor, now_unix_ms)
            {
                Ok(result) => {
                    match result {
                        IngestResult::Committed { .. } => report.committed += 1,
                        IngestResult::Duplicate => report.duplicates += 1,
                        IngestResult::ParkedForReorder => report.parked += 1,
                        IngestResult::LateNoEconomicEffect => report.late += 1,
                    }
                    return Ok(Some(result));
                }
                Err(IngestError::Store(StorePortError::RevisionConflict)) => {
                    report.conflicts += 1;
                    if attempt == 1 {
                        return Ok(None);
                    }
                }
                Err(other) => return Err(other.into()),
            }
        }
        Ok(None)
    }

    // ---- public drive --------------------------------------------------

    /// Arms the refund path (I5). The engine never invents this event:
    /// it is the F1 leg reporting that the pre-signed refund is durable.
    pub fn arm_refund(
        &mut self,
        now_unix_ms: i64,
    ) -> Result<Option<IngestResult>, SettlementEngineError> {
        let mut report = TickReportV1::default();
        self.ingest(SettlementEvent::RefundArmed, None, now_unix_ms, &mut report)
    }

    /// One engine step: retry parked, scan, ingest, apply policy, then
    /// dispatch the outbox. Safe to call any number of times.
    pub fn tick(&mut self, now_unix_ms: i64) -> Result<TickReportV1, SettlementEngineError> {
        let mut report = TickReportV1::default();

        // Parked events are older than anything the scan will bring.
        self.reorder.drain_parked(&self.store, now_unix_ms)?;

        let (records, scanned_to) = self.chain.scan(&self.scan_cursor)?;
        report.records_seen = records.len();

        // Index of the last record that may carry the cursor forward.
        let last_ingestible = records
            .iter()
            .rposition(|r| !matches!(r, ChainRecordV1::Refund { .. }));

        for (index, record) in records.iter().enumerate() {
            match record {
                ChainRecordV1::Reorg {
                    from_height,
                    old_anchor,
                } => {
                    // Invalidate BEFORE committing the reorg: a crash in
                    // between leaves rows invalidated and the reorg still
                    // pending, and the stale anchor makes the adapter
                    // re-emit the record — idempotent either way.
                    self.store
                        .invalidate_evidence_from(self.settlement_id, *from_height)?;
                    self.pending_refunds
                        .retain(|ev| ev.block_height < *from_height);
                    self.reorder.drop_from(*from_height);
                    self.ingest(
                        SettlementEvent::ReorgInvalidated {
                            from_height: *from_height,
                            old_anchor: *old_anchor,
                        },
                        None,
                        now_unix_ms,
                        &mut report,
                    )?;
                }
                ChainRecordV1::Funding { evidence } | ChainRecordV1::Claim { evidence } => {
                    let event = if matches!(record, ChainRecordV1::Funding { .. }) {
                        SettlementEvent::FundingObserved {
                            evidence: *evidence,
                        }
                    } else {
                        SettlementEvent::ClaimEvidenceVerified {
                            evidence: *evidence,
                        }
                    };
                    // Only the last non-refund record of the batch may
                    // advance the cursor, and only up to the safe height.
                    let cursor = if Some(index) == last_ingestible {
                        self.safe_cursor(&scanned_to)?
                            .map(|c| self.cursor_update(&c))
                    } else {
                        None
                    };
                    self.ingest(event, cursor.as_ref(), now_unix_ms, &mut report)?;
                }
                ChainRecordV1::Refund { evidence } => {
                    // Terminal on sight is forbidden: hold it until the
                    // finality policy of the frozen terms is satisfied.
                    if !self.pending_refunds.contains(evidence) {
                        self.pending_refunds.push(*evidence);
                    }
                }
            }
        }
        self.scan_cursor = scanned_to;

        self.apply_policy(now_unix_ms, &mut report)?;
        self.dispatch(now_unix_ms, &mut report)?;
        report.state = Some(self.snapshot()?.context.state);
        Ok(report)
    }

    /// Highest position whose consequences are all durable. `None` when
    /// nothing may advance (a pending refund sits at or below the floor).
    fn safe_cursor(
        &self,
        scanned_to: &ChainCursorV1,
    ) -> Result<Option<ChainCursorV1>, SettlementEngineError> {
        let lowest_pending = self
            .pending_refunds
            .iter()
            .map(|ev| ev.block_height)
            .min()
            .unwrap_or(u64::MAX);
        if lowest_pending == u64::MAX {
            return Ok(Some(scanned_to.clone()));
        }
        let Some(ceiling) = lowest_pending.checked_sub(1) else {
            return Ok(None);
        };
        if ceiling >= scanned_to.height {
            Ok(Some(scanned_to.clone()))
        } else {
            Ok(Some(self.chain.cursor_at(ceiling)?))
        }
    }

    fn is_final(&self, height: u64, tip: u64) -> bool {
        tip >= height
            && tip.saturating_sub(height).saturating_add(1) >= self.policy.min_confirmations
    }

    /// Applies the policy events derived from the frozen terms and the
    /// durable state. Re-reads the snapshot after every commit so that a
    /// funding confirmation and the claim it unblocks can both land in
    /// the same tick.
    fn apply_policy(
        &mut self,
        now_unix_ms: i64,
        report: &mut TickReportV1,
    ) -> Result<(), SettlementEngineError> {
        let tip = self.chain.tip_height()?;
        for _ in 0..MAX_POLICY_INGESTS_PER_TICK {
            let snapshot = self.snapshot()?;
            let Some(event) = self.next_policy_event(&snapshot, tip)? else {
                return Ok(());
            };
            let is_timelock = matches!(event, SettlementEvent::TimelockExpired);
            let is_refund = matches!(event, SettlementEvent::RefundConfirmed { .. });
            let refund_evidence = match &event {
                SettlementEvent::RefundConfirmed { evidence } => Some(*evidence),
                _ => None,
            };
            let Some(result) = self.ingest(event, None, now_unix_ms, report)? else {
                // Lost the CAS twice: leave the candidate for the next
                // tick rather than spinning on a contended snapshot.
                return Ok(());
            };
            match result {
                IngestResult::Committed { .. } | IngestResult::Duplicate => {
                    if is_timelock {
                        self.timelock_committed = true;
                    }
                    if let Some(evidence) = refund_evidence {
                        self.pending_refunds.retain(|ev| *ev != evidence);
                    }
                }
                IngestResult::ParkedForReorder | IngestResult::LateNoEconomicEffect => {
                    // The candidate cannot progress right now; emitting it
                    // again this tick would spin.
                    if is_timelock {
                        self.timelock_committed = true;
                    }
                    if is_refund {
                        if let Some(evidence) = refund_evidence {
                            self.pending_refunds.retain(|ev| *ev != evidence);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// First applicable policy event, in priority order: funding
    /// confirmation, post-reorg absence, claim confirmation, refund
    /// confirmation, timelock expiry.
    fn next_policy_event(
        &self,
        snapshot: &SettlementSnapshot,
        tip: u64,
    ) -> Result<Option<SettlementEvent>, SettlementEngineError> {
        let ctx = snapshot.context;
        if ctx.state.is_terminal() {
            return Ok(None);
        }

        if ctx.state == SettlementState::Confirming {
            match ctx.last_observed_height {
                Some(height) if self.is_final(height, tip) => {
                    if let Some(evidence) = self.applied_evidence_of(
                        |reference| SettlementEvent::FundingObserved {
                            evidence: reference,
                        },
                        Some(height),
                    )? {
                        return Ok(Some(SettlementEvent::FundingConfirmed { evidence }));
                    }
                }
                // Confirming with no observation exists only after a reorg
                // regressed a Settling settlement: the funding did not come
                // back, so re-arm early instead of waiting for the timelock.
                None => {
                    return Ok(Some(SettlementEvent::FundingAbsent {
                        revalidation_from: self.scan_cursor.height,
                    }))
                }
                Some(_) => {}
            }
        }

        if ctx.state == SettlementState::Settling && ctx.claim_evidence_verified {
            if let Some(evidence) = self.applied_evidence_of(
                |reference| SettlementEvent::ClaimEvidenceVerified {
                    evidence: reference,
                },
                None,
            )? {
                if self.is_final(evidence.block_height, tip) {
                    return Ok(Some(SettlementEvent::ClaimConfirmed { evidence }));
                }
            }
        }

        if let Some(evidence) = self
            .pending_refunds
            .iter()
            .find(|ev| self.is_final(ev.block_height, tip))
        {
            return Ok(Some(SettlementEvent::RefundConfirmed {
                evidence: *evidence,
            }));
        }

        if !self.timelock_committed
            && matches!(
                ctx.state,
                SettlementState::Confirming | SettlementState::Settling
            )
            && tip.saturating_add(1) >= self.policy.refund_not_before_height
        {
            return Ok(Some(SettlementEvent::TimelockExpired));
        }

        Ok(None)
    }

    /// Latest APPLIED evidence row that was produced by the event the
    /// constructor builds, optionally restricted to one height.
    fn applied_evidence_of(
        &self,
        construct: impl Fn(EvidenceRefV1) -> SettlementEvent,
        at_height: Option<u64>,
    ) -> Result<Option<EvidenceRefV1>, SettlementEngineError> {
        let rows = self
            .store
            .evidence(self.settlement_id, EvidenceStatus::Applied)?;
        Ok(rows
            .into_iter()
            .rev()
            .filter(|row| at_height.map_or(true, |h| row.reference.block_height == h))
            .find(|row| {
                derive_event_id(self.settlement_id, &construct(row.reference)) == row.evidence_id
            })
            .map(|row| row.reference))
    }

    // ---- outbox --------------------------------------------------------

    fn dispatch(
        &mut self,
        now_unix_ms: i64,
        report: &mut TickReportV1,
    ) -> Result<(), SettlementEngineError> {
        let claimed =
            self.store
                .ready_outbox(now_unix_ms, self.lease_ms, self.max_effects_per_tick)?;
        report.effects_dispatched += claimed.len();
        for effect in claimed {
            match effect.kind {
                // The "external system" of a revalidation is the engine's
                // own scanner: rewinding here is the execution, so the
                // effect completes without reaching the sink.
                Effect::RevalidateFrom { height } => {
                    let floor = height.saturating_sub(1);
                    if floor < self.scan_cursor.height {
                        self.scan_cursor = self.chain.cursor_at(floor)?;
                    }
                    self.store.complete_effect(
                        effect.effect_id,
                        effect.payload_hash,
                        now_unix_ms,
                    )?;
                    report.effects_completed += 1;
                }
                _ => match self.sink.execute(&effect) {
                    EffectOutcome::Completed => {
                        self.store.complete_effect(
                            effect.effect_id,
                            effect.payload_hash,
                            now_unix_ms,
                        )?;
                        report.effects_completed += 1;
                    }
                    EffectOutcome::RetryLater => {}
                    EffectOutcome::Rejected => report.effects_rejected += 1,
                },
            }
        }
        Ok(())
    }
}
