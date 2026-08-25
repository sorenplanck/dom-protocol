//! Event ingestion and deterministic reorder (F2 spec §10).
//!
//! [`ingest_event`] is the spec's engine algorithm, verbatim: load the
//! snapshot, check the binding (session + terms_hash) BEFORE calling
//! `transition()`, classify late evidence on terminal settlements, commit
//! accepted transitions atomically, and PARK evidence the machine cannot
//! accept yet (`IllegalEvent` / `PreconditionUnsatisfied`) instead of
//! guessing an order. A sequence gap is never filled by assumption.
//!
//! [`ReorderBuffer`] is the deterministic retry (build order §24 step 8):
//! after every commit it re-applies parked envelopes in the canonical
//! chain order `(block_height, event_index, tx_id)` until a full pass
//! makes no progress. Parking is durable (`observed_evidence`) AND the
//! cursor does not advance for a parked event, so a crash re-delivers it
//! on the next scan — the buffer is reconstructible by construction.

use crate::state::{transition, SettlementEvent, TransitionError};
use crate::store_port::{
    effects_to_outbox, CommitResult, CursorUpdateV1, EventEnvelopeV1, SettlementStore,
    StorePortError,
};

/// Result of ingesting one envelope (spec §10).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IngestResult {
    /// Transition committed at this revision.
    Committed {
        /// Resulting durable revision.
        revision: u64,
    },
    /// Byte-identical redelivery: idempotent ACK.
    Duplicate,
    /// The machine cannot accept the event yet; evidence parked durably.
    ParkedForReorder,
    /// The settlement is terminal; recorded by identifier, no economic
    /// effect (spec §12).
    LateNoEconomicEffect,
}

/// Ingestion failures — all fail closed.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// No settlement with this identifier.
    #[error("unknown settlement")]
    UnknownSettlement,
    /// Envelope session/terms binding diverges from the snapshot —
    /// checked BEFORE `transition()` runs (spec §9).
    #[error("binding mismatch")]
    BindingMismatch,
    /// The machine rejected the event in a non-parkable way (e.g.
    /// evidence mismatch, revision overflow), or the event carries no
    /// evidence to park.
    #[error("machine rejected: {0}")]
    Machine(TransitionError),
    /// Durable store failure (includes equivocation and lost CAS).
    #[error("store: {0}")]
    Store(#[from] StorePortError),
}

/// The engine algorithm of spec §10, one envelope at a time.
///
/// `cursor_update` is supplied by the CALLER, never synthesized here: the
/// cursor is the scanner's own opaque description of its position (§4.7),
/// and only the adapter that produced it may describe it. Passing `None`
/// leaves the durable cursor untouched — which is what every event that
/// does not fully consume a scan position must do.
pub fn ingest_event<S: SettlementStore>(
    store: &S,
    env: &EventEnvelopeV1,
    cursor_update: Option<&CursorUpdateV1>,
    now_unix_ms: i64,
) -> Result<IngestResult, EngineError> {
    let snapshot = store
        .load(env.settlement_id)?
        .ok_or(EngineError::UnknownSettlement)?;

    if snapshot.session_id != env.session_id || snapshot.terms_hash != env.terms_hash {
        return Err(EngineError::BindingMismatch);
    }

    // §9: the same event id with the same bytes is an idempotent ACK.
    // This is checked BEFORE the machine and before the late-evidence
    // classification, because the decision was already taken and is
    // durable — an advanced context must not turn a redelivery into an
    // illegal event, and a terminal must not turn it into late evidence.
    // The authoritative dedupe still runs inside the commit transaction.
    if let Some(bytes) = store.committed_event(env.settlement_id, env.event_id)? {
        if bytes != env.canonical_bytes() {
            return Err(EngineError::Store(StorePortError::Equivocation));
        }
        // The redelivered bytes carry the block anchor, so an identical
        // redelivery proves the very same block is canonical again: an
        // observation a reorg invalidated and that came back unchanged is
        // re-affirmed (spec §11). Rule 8 goes further: when a REORG had
        // regressed the machine, the refresh also RE-APPLIES the
        // transition — otherwise the context stays below what the
        // canonical chain again proves and later legal events strand
        // (found by the §14 durable/pure agreement property). The store
        // adjudicates which case this is INSIDE the commit transaction:
        // only a redelivery whose evidence row flips invalidated ->
        // applied re-appends; a plain duplicate still commits nothing
        // and answers DuplicateSameBytes.
        if accepted_evidence(&env.event).is_some() && !snapshot.context.state.is_terminal() {
            if let Ok(t) = transition(snapshot.context, &env.event) {
                let outbox = effects_to_outbox(env, &t.effects);
                return match store.commit_transition(
                    snapshot.context.revision,
                    env,
                    &t,
                    &outbox,
                    cursor_update,
                    now_unix_ms,
                )? {
                    CommitResult::Committed { revision } => {
                        Ok(IngestResult::Committed { revision })
                    }
                    CommitResult::DuplicateSameBytes => Ok(IngestResult::Duplicate),
                };
            }
            // The machine cannot accept the refresh from the current
            // context; the evidence row alone returns to applied, which
            // is what confirmation derivation needs (the prior
            // behavior, unchanged for this arm).
            store.reaffirm_evidence(env.settlement_id, env.event_id)?;
            return Ok(IngestResult::Duplicate);
        }
        if accepted_evidence(&env.event).is_some() {
            store.reaffirm_evidence(env.settlement_id, env.event_id)?;
        }
        return Ok(IngestResult::Duplicate);
    }

    if snapshot.context.state.is_terminal() {
        store.record_late_evidence(
            env.settlement_id,
            env.event_id,
            snapshot.context.state,
            now_unix_ms,
        )?;
        return Ok(IngestResult::LateNoEconomicEffect);
    }

    match transition(snapshot.context, &env.event) {
        Ok(t) => {
            // Spec §11 rule 2, at THIS entry point too: an accepted
            // ReorgInvalidated marks every evidence row at or above
            // from_height invalidated BEFORE the reorg commits — the
            // same ordering and idempotency argument as the engine
            // driver (a crash in between leaves rows invalidated and
            // the reorg still pending; the stale anchor makes the
            // adapter re-emit). Without this, a later byte-identical
            // redelivery of an invalidated observation cannot be told
            // apart from a plain duplicate and the §11.8 refresh never
            // fires (found by the §14 durable/pure agreement property).
            if let SettlementEvent::ReorgInvalidated { from_height, .. } = &env.event {
                store.invalidate_evidence_from(env.settlement_id, *from_height)?;
            }
            let outbox = effects_to_outbox(env, &t.effects);
            match store.commit_transition(
                snapshot.context.revision,
                env,
                &t,
                &outbox,
                cursor_update,
                now_unix_ms,
            )? {
                CommitResult::Committed { revision } => Ok(IngestResult::Committed { revision }),
                CommitResult::DuplicateSameBytes => Ok(IngestResult::Duplicate),
            }
        }
        Err(e @ (TransitionError::IllegalEvent | TransitionError::PreconditionUnsatisfied)) => {
            // Only evidence-carrying events can wait for order; the rest
            // has no chain position and is a hard rejection.
            let Some(evidence) = accepted_evidence(&env.event) else {
                return Err(EngineError::Machine(e));
            };
            store.park_evidence(env.settlement_id, env.event_id, evidence)?;
            Ok(IngestResult::ParkedForReorder)
        }
        Err(e) => Err(EngineError::Machine(e)),
    }
}

fn accepted_evidence(event: &SettlementEvent) -> Option<&crate::state::EvidenceRefV1> {
    match event {
        SettlementEvent::FundingObserved { evidence }
        | SettlementEvent::FundingConfirmed { evidence }
        | SettlementEvent::ClaimEvidenceVerified { evidence }
        | SettlementEvent::ClaimConfirmed { evidence }
        | SettlementEvent::RefundConfirmed { evidence } => Some(evidence),
        _ => None,
    }
}

/// Canonical chain order of one envelope for retry:
/// `(block_height, event_index, tx_id)` (spec §10). Envelopes without
/// evidence never enter the buffer.
fn canonical_key(env: &EventEnvelopeV1) -> Option<(u64, u32, [u8; 32])> {
    accepted_evidence(&env.event).map(|ev| (ev.block_height, ev.event_index, ev.tx_id))
}

/// Deterministic parking/retry driver (build order step 8).
///
/// Holds the parked envelopes in canonical order. The durable half of the
/// state is the store: parking wrote `observed_evidence`, and the cursor
/// never advanced past a parked event — after a crash the scanner simply
/// redelivers, and the buffer refills identically.
#[derive(Default)]
pub struct ReorderBuffer {
    parked: Vec<EventEnvelopeV1>,
}

impl core::fmt::Debug for ReorderBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReorderBuffer")
            .field("parked", &self.parked.len())
            .finish()
    }
}

impl ReorderBuffer {
    /// Empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of envelopes waiting for order.
    pub fn parked_len(&self) -> usize {
        self.parked.len()
    }

    /// Ingests one envelope; on any commit, re-applies parked envelopes
    /// in canonical order until a full pass makes no progress.
    ///
    /// Returns the result of the delivered envelope. Parked envelopes
    /// that get applied later surface only through the store (their
    /// events commit); duplicates already in the buffer are not parked
    /// twice.
    pub fn ingest<S: SettlementStore>(
        &mut self,
        store: &S,
        env: EventEnvelopeV1,
        cursor_update: Option<&CursorUpdateV1>,
        now_unix_ms: i64,
    ) -> Result<IngestResult, EngineError> {
        let result = ingest_event(store, &env, cursor_update, now_unix_ms)?;
        match result {
            IngestResult::ParkedForReorder => {
                if !self.parked.contains(&env) {
                    self.parked.push(env);
                    self.parked.sort_by_key(|e| {
                        canonical_key(e).unwrap_or((u64::MAX, u32::MAX, [0xff; 32]))
                    });
                }
            }
            IngestResult::Committed { .. } => {
                self.drain_parked(store, now_unix_ms)?;
            }
            _ => {}
        }
        Ok(result)
    }

    /// Drops parked envelopes at or above a reorged height: they sit on
    /// an abandoned branch and must not be retried (spec §11 step 2).
    pub fn drop_from(&mut self, from_height: u64) {
        self.parked
            .retain(|env| canonical_key(env).map_or(true, |(height, _, _)| height < from_height));
    }

    /// Adopts envelopes reconstructed from the durable parked rows
    /// (recovery, spec §13 step 7). Already-held envelopes are not
    /// duplicated and the canonical order is preserved.
    pub fn adopt(&mut self, envelopes: impl IntoIterator<Item = EventEnvelopeV1>) {
        for env in envelopes {
            if !self.parked.contains(&env) {
                self.parked.push(env);
            }
        }
        self.parked
            .sort_by_key(|e| canonical_key(e).unwrap_or((u64::MAX, u32::MAX, [0xff; 32])));
    }

    /// Re-applies parked envelopes in canonical order until quiescence.
    /// Call after recovery, too (spec §13 step 7).
    ///
    /// Retries never carry a cursor update: a parked event has not
    /// consumed a scan position, and applying it later must not move the
    /// scanner forward.
    pub fn drain_parked<S: SettlementStore>(
        &mut self,
        store: &S,
        now_unix_ms: i64,
    ) -> Result<(), EngineError> {
        loop {
            let mut progressed = false;
            let mut still_parked = Vec::with_capacity(self.parked.len());
            for env in std::mem::take(&mut self.parked) {
                match ingest_event(store, &env, None, now_unix_ms)? {
                    IngestResult::Committed { .. } | IngestResult::Duplicate => {
                        progressed = true;
                    }
                    IngestResult::LateNoEconomicEffect => {
                        // Terminal reached while this waited: neutral,
                        // recorded, and it leaves the buffer.
                        progressed = true;
                    }
                    IngestResult::ParkedForReorder => still_parked.push(env),
                }
            }
            self.parked = still_parked;
            if !progressed || self.parked.is_empty() {
                return Ok(());
            }
        }
    }
}
