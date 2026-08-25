//! Neutral settlement operations over the F2 core schema (F2 spec §8).
//!
//! This module is the transactional heart of the F2 store: one
//! `BEGIN IMMEDIATE` transaction per accepted transition, executing the
//! nine steps of spec §8.2 — dedupe, snapshot CAS, journal append,
//! snapshot update, evidence/cursor writes, outbox insert, terminal row,
//! commit — so that a failure, crash or `SQLITE_BUSY` before the commit
//! leaves ZERO effects visible, and a crash after the commit can only
//! duplicate the external attempt, never the bytes or the logical effect.
//!
//! Everything here is NEUTRAL: 32-byte identifiers, integer tags and
//! opaque byte payloads. The typed contract (`SettlementStore`,
//! `EventEnvelopeV1`, effect-id derivation) lives in `kaystra-core`
//! (D-005 boundary: this crate knows no DOM or settlement type).

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};

use crate::{Result, Store, StoreError};

/// Crash injection at the commit and dispatch boundaries (F2 spec §13).
///
/// Compiled ONLY under the `failpoints` feature, which is off by default,
/// is never enabled by a normal dependency, and is checked by
/// `scripts/guards.sh`. With the feature off, every `failpoint!` below
/// expands to nothing: production builds contain no hook, no branch and
/// no extra error variant.
#[cfg(feature = "failpoints")]
pub mod failpoints {
    use std::cell::Cell;

    /// The eleven boundaries of spec §13.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Failpoint {
        /// Before `BEGIN IMMEDIATE`.
        C0,
        /// After the dedupe check, before reading the snapshot.
        C1,
        /// After appending to the journal.
        C2,
        /// After the snapshot CAS.
        C3,
        /// After inserting the evidence reference / cursor.
        C4,
        /// After inserting the outbox entries.
        C5,
        /// Immediately before `COMMIT`.
        C6,
        /// Immediately after `COMMIT`.
        C7,
        /// After claiming an outbox item.
        C8,
        /// After the external effect, before marking it completed.
        C9,
        /// After marking it completed.
        C10,
    }

    thread_local! {
        static ARMED: Cell<Option<Failpoint>> = const { Cell::new(None) };
    }

    /// Arms one failpoint for the current thread. It fires ONCE: the next
    /// crossing of that boundary fails and disarms, so the retry that
    /// models the restart proceeds normally.
    pub fn arm(failpoint: Failpoint) {
        ARMED.with(|armed| armed.set(Some(failpoint)));
    }

    /// Disarms whatever is armed.
    pub fn disarm() {
        ARMED.with(|armed| armed.set(None));
    }

    /// Whether a failpoint is still waiting to fire.
    pub fn is_armed() -> bool {
        ARMED.with(|armed| armed.get().is_some())
    }

    pub(crate) fn fires(failpoint: Failpoint) -> bool {
        ARMED.with(|armed| {
            if armed.get() == Some(failpoint) {
                armed.set(None);
                true
            } else {
                false
            }
        })
    }
}

macro_rules! failpoint {
    ($id:ident) => {
        #[cfg(feature = "failpoints")]
        {
            if failpoints::fires(failpoints::Failpoint::$id) {
                return Err(StoreError::InjectedCrash);
            }
        }
    };
}

/// Promotes exactly one evidence row from invalidated back to applied.
///
/// Restricted to that single direction on purpose: a PARKED row was never
/// committed and must never be promoted by a redelivery.
const REAFFIRM_EVIDENCE_SQL: &str = "UPDATE observed_evidence SET status_tag = ?3
     WHERE settlement_id = ?1 AND evidence_id = ?2 AND status_tag = ?4";

/// Outbox status: eligible for dispatch (or lease expired).
pub const OUTBOX_PENDING: i64 = 0;
/// Outbox status: completed; never dispatched again.
pub const OUTBOX_COMPLETED: i64 = 1;

const OUTBOX_DISPATCH_RUNNER_PAYLOAD: i64 = 0;
const OUTBOX_DISPATCH_EXTERNAL_CUSTODY: i64 = 1;

/// Evidence status: parked, waiting for the machine to accept it.
pub const EVIDENCE_PARKED: i64 = 0;
/// Evidence status: accepted by a committed transition.
pub const EVIDENCE_APPLIED: i64 = 1;
/// Evidence status: invalidated by a reorg.
pub const EVIDENCE_INVALIDATED: i64 = 2;

/// Row creating one settlement: frozen terms plus the initial snapshot.
pub struct SettlementCreate<'a> {
    /// Settlement identifier (32 bytes, primary key).
    pub settlement_id: [u8; 32],
    /// Session identifier (32 bytes, unique across settlements).
    pub session_id: [u8; 32],
    /// A3 terms hash the whole settlement is bound to.
    pub terms_hash: [u8; 32],
    /// Canonical terms bytes (opaque here).
    pub canonical_terms: &'a [u8],
    /// Initial state tag of the machine.
    pub initial_state_tag: u16,
    /// Canonical encoding of the initial context (opaque here).
    pub initial_context: &'a [u8],
    /// Caller-supplied wall clock (ms). The store never reads the clock.
    pub created_at_unix_ms: i64,
}

/// Materialized snapshot row, joined with the settlement's binding.
#[derive(Clone, PartialEq, Eq)]
pub struct SettlementSnapshotRow {
    /// Session identifier bound at creation.
    pub session_id: [u8; 32],
    /// A3 terms hash bound at creation.
    pub terms_hash: [u8; 32],
    /// Durable revision (CAS key).
    pub revision: u64,
    /// State tag of the persisted context.
    pub state_tag: u16,
    /// Canonical encoding of the persisted context (opaque here).
    pub context_bytes: Vec<u8>,
    /// Sequence of the last journal entry.
    pub last_event_seq: u64,
}

impl core::fmt::Debug for SettlementSnapshotRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SettlementSnapshotRow")
            .field("revision", &self.revision)
            .field("state_tag", &self.state_tag)
            .field("last_event_seq", &self.last_event_seq)
            .field("context_bytes", &"[redacted]")
            .finish()
    }
}

/// Evidence reference row (public chain data — never secret material).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EvidenceRow {
    /// Evidence identifier (32 bytes).
    pub evidence_id: [u8; 32],
    /// Chain registry identifier.
    pub chain_id: [u8; 32],
    /// Transaction identifier on that chain.
    pub tx_id: [u8; 32],
    /// Event index inside the transaction.
    pub event_index: u32,
    /// Block height of the observation.
    pub block_height: u64,
    /// Block anchor the observation is pinned to.
    pub block_anchor: [u8; 32],
    /// Status tag ([`EVIDENCE_PARKED`], [`EVIDENCE_APPLIED`], ...).
    pub status_tag: i64,
}

/// Cursor update committed atomically with the accepted events (spec §9:
/// the cursor only advances in the same transaction).
pub struct CursorUpdate<'a> {
    /// Chain the cursor tracks.
    pub chain_id: [u8; 32],
    /// Opaque cursor bytes.
    pub cursor_bytes: &'a [u8],
    /// Anchored height, if the scanner is anchored.
    pub anchor_height: Option<i64>,
    /// Anchor hash, if the scanner is anchored.
    pub anchor_hash: Option<[u8; 32]>,
}

/// One deterministic outbox effect to insert with the commit.
pub struct OutboxInsert<'a> {
    /// Deterministic effect identifier (32 bytes).
    pub effect_id: [u8; 32],
    /// Effect kind tag.
    pub effect_kind: u16,
    /// Exact payload bytes the dispatcher must resend without
    /// reconstruction.
    pub payload: &'a [u8],
    /// Hash of the payload, revalidated on completion.
    pub payload_hash: [u8; 32],
}

/// Payload-free external custody effect inserted with one accepted transition.
///
/// The external authority named by this row remains the sole submitter.  The
/// Store persists only its commitment and public transaction identifier; it
/// never stores or returns transaction bytes and never leases this effect to
/// the generic dispatcher.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExternalCustodyInsert {
    /// Deterministic effect identifier (32 bytes).
    pub effect_id: [u8; 32],
    /// Neutral caller-defined effect kind.
    pub effect_kind: u16,
    /// Commitment to the complete external custody descriptor.
    pub custody_digest: [u8; 32],
    /// Public transaction identifier held by the external authority.
    pub transaction_id: [u8; 32],
}

/// Exact external custody effect completed with a successor transition.
///
/// Supplying this value does not attest that an external action succeeded;
/// the typed caller must possess its own non-forgeable receipt.  It lets that
/// caller bind the receipt's public identity to the row inserted by
/// [`ExternalCustodyInsert`] and close both records in one SQLite commit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExternalCustodyCompletion {
    /// Deterministic effect identifier created by the earlier transition.
    pub effect_id: [u8; 32],
    /// Original external custody commitment.
    pub custody_digest: [u8; 32],
    /// Exact public transaction identifier proven by the external receipt.
    pub transaction_id: [u8; 32],
}

/// Terminal outcome row (unique per settlement by PRIMARY KEY).
pub struct TerminalInsert {
    /// Outcome tag (terminal state).
    pub outcome_tag: u16,
    /// Event that finalized the settlement.
    pub source_event_id: [u8; 32],
}

/// The full write set of one accepted transition (spec §8.2).
pub struct SettlementCommit<'a> {
    /// Settlement the event belongs to.
    pub settlement_id: [u8; 32],
    /// Event identifier (dedupe / equivocation key).
    pub event_id: [u8; 32],
    /// Event kind tag.
    pub event_kind: u16,
    /// Canonical event bytes (equivocation is judged on these bytes).
    pub event_bytes: &'a [u8],
    /// Revision the caller loaded (CAS expectation).
    pub expected_revision: u64,
    /// Revision after the transition (machine-incremented).
    pub resulting_revision: u64,
    /// State tag after the transition.
    pub state_tag: u16,
    /// Canonical encoding of the context after the transition.
    pub context_bytes: &'a [u8],
    /// Hash of the context bytes (recovery cross-check).
    pub context_hash: [u8; 32],
    /// Evidence reference accepted by this transition, if any.
    pub evidence: Option<EvidenceRow>,
    /// Cursor update committed with this transition, if any.
    pub cursor: Option<CursorUpdate<'a>>,
    /// Effects to enqueue (visible to the dispatcher only after commit).
    pub effects: &'a [OutboxInsert<'a>],
    /// Journal identity of a §11.8 REFRESH re-application of this same
    /// event, pre-derived by the caller (domain-separated over the
    /// event id and the resulting revision, so it is deterministic
    /// across crash replay and can never collide with a real event
    /// id). Used ONLY when the commit takes the refresh path; a plain
    /// commit journals under `event_id` and ignores this.
    pub refresh_event_id: Option<[u8; 32]>,
    /// Terminal outcome, when the transition finalizes the settlement.
    pub terminal: Option<TerminalInsert>,
    /// Caller-supplied wall clock (ms).
    pub now_unix_ms: i64,
}

/// One materialized journal row (recovery replay input).
#[derive(Clone, PartialEq, Eq)]
pub struct SettlementJournalRow {
    /// Sequence, contiguous from 1.
    pub seq: u64,
    /// Revision the commit expected.
    pub expected_revision: u64,
    /// Revision the commit produced.
    pub resulting_revision: u64,
    /// Event identifier.
    pub event_id: [u8; 32],
    /// Event kind tag.
    pub event_kind: u16,
    /// Canonical event bytes.
    pub event_bytes: Vec<u8>,
    /// Hash of the context after the transition.
    pub context_hash: [u8; 32],
}

impl core::fmt::Debug for SettlementJournalRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SettlementJournalRow")
            .field("seq", &self.seq)
            .field("event_kind", &self.event_kind)
            .field("event_bytes", &"[redacted]")
            .finish()
    }
}

/// Result of a commit attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CommitOutcome {
    /// The transition was durably committed.
    Committed,
    /// The same (settlement, event) with the same bytes was already
    /// committed: idempotent ACK, nothing was written.
    DuplicateSameBytes,
}

/// One claimed outbox entry, ready for dispatch.
#[derive(Clone, PartialEq, Eq)]
pub struct ClaimedEffect {
    /// Settlement the effect belongs to.
    pub settlement_id: [u8; 32],
    /// Deterministic effect identifier.
    pub effect_id: [u8; 32],
    /// Effect kind tag.
    pub effect_kind: u16,
    /// Exact payload bytes as first persisted (resend never reconstructs).
    pub payload: Vec<u8>,
    /// Hash of the payload.
    pub payload_hash: [u8; 32],
    /// Delivery attempts so far, including this claim.
    pub attempts: u64,
}

impl core::fmt::Debug for ClaimedEffect {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClaimedEffect")
            .field("effect_kind", &self.effect_kind)
            .field("attempts", &self.attempts)
            .field("payload", &"[redacted]")
            .finish()
    }
}

/// Read-only delivery state of one exact durable outbox effect.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum F2OutboxDeliveryStatusV1 {
    /// The effect has not completed and is either unleased or covered by the
    /// retained lease metadata in [`F2OutboxEffectSummaryV1`].
    Pending,
    /// The effect was durably marked complete and has no remaining lease.
    Completed,
}

/// Dispatch authority retained for one durable effect.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum F2OutboxDispatchClassV1 {
    /// The Store retains exact bytes for lease-based runner dispatch.
    RunnerPayload,
    /// A separate authority retains the bytes and is the sole submitter.
    ExternalCustody,
}

/// Public, payload-free manifest row for one durable outbox effect.
///
/// The source journal identity lets an independent typed caller rederive its
/// own deterministic effect binding without obtaining the persisted payload.
/// Reading this value never claims, renews or clears a lease.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct F2OutboxEffectSummaryV1 {
    /// Deterministic effect identifier.
    pub effect_id: [u8; 32],
    /// Journal sequence that atomically created the effect.
    pub source_sequence: u64,
    /// Journal event identifier at [`Self::source_sequence`].
    pub source_event_id: [u8; 32],
    /// Neutral caller-defined effect kind.
    pub effect_kind: u16,
    /// Whether bytes are runner-dispatchable or retained externally.
    pub dispatch_class: F2OutboxDispatchClassV1,
    /// Persisted commitment to the exact effect payload.
    pub payload_hash: [u8; 32],
    /// Public transaction identifier for an external-custody effect.
    pub external_transaction_id: Option<[u8; 32]>,
    /// Current delivery state.
    pub status: F2OutboxDeliveryStatusV1,
    /// Number of durable lease acquisitions.
    pub attempts: u64,
    /// Retained lease deadline for a pending leased effect.
    pub lease_until_unix_ms: Option<i64>,
    /// Durable completion time for a completed effect.
    pub completed_at_unix_ms: Option<i64>,
}

/// Result of parking one piece of evidence.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParkOutcome {
    /// Parked now.
    Parked,
    /// The identical evidence row was already present (idempotent).
    AlreadyPresent,
}

#[derive(Clone, Copy)]
enum ExternalCustodyMutation<'a> {
    Insert(&'a ExternalCustodyInsert),
    Complete(&'a ExternalCustodyCompletion),
}

type StoredExternalCustody = (
    i64,
    Vec<u8>,
    [u8; 32],
    Option<[u8; 32]>,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
);

fn stored_external_custody(
    tx: &Transaction<'_>,
    settlement_id: [u8; 32],
    effect_id: [u8; 32],
) -> Result<Option<StoredExternalCustody>> {
    Ok(tx
        .query_row(
            "SELECT dispatch_class, payload_bytes, payload_hash, external_tx_id,
                    status_tag, attempts, lease_until_unix_ms, completed_at_unix_ms
             FROM durable_outbox
             WHERE settlement_id = ?1 AND effect_id = ?2",
            rusqlite::params![settlement_id, effect_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?)
}

fn valid_external_identity(
    effect_id: [u8; 32],
    custody_digest: [u8; 32],
    transaction_id: [u8; 32],
) -> bool {
    effect_id != [0; 32] && custody_digest != [0; 32] && transaction_id != [0; 32]
}

fn validate_external_row(
    stored: &StoredExternalCustody,
    custody_digest: [u8; 32],
    transaction_id: [u8; 32],
    require_completed: bool,
) -> Result<()> {
    let (dispatch_class, payload, digest, tx_id, status, attempts, lease, completed) = stored;
    if *dispatch_class != OUTBOX_DISPATCH_EXTERNAL_CUSTODY
        || !payload.is_empty()
        || *digest != custody_digest
        || *tx_id != Some(transaction_id)
        || lease.is_some()
    {
        return Err(StoreError::IdempotencyConflict);
    }
    let coherent = match (*status, *attempts, *completed, require_completed) {
        (OUTBOX_PENDING, 0, None, false) => true,
        (OUTBOX_COMPLETED, attempts, Some(_), _) if attempts >= 1 => true,
        _ => false,
    };
    if !coherent {
        return Err(StoreError::CorruptState);
    }
    Ok(())
}

fn validate_external_custody_replay(
    tx: &Transaction<'_>,
    settlement_id: [u8; 32],
    mutation: Option<ExternalCustodyMutation<'_>>,
) -> Result<()> {
    let Some(mutation) = mutation else {
        return Ok(());
    };
    let (effect_id, digest, transaction_id, require_completed) = match mutation {
        ExternalCustodyMutation::Insert(value) => (
            value.effect_id,
            value.custody_digest,
            value.transaction_id,
            false,
        ),
        ExternalCustodyMutation::Complete(value) => (
            value.effect_id,
            value.custody_digest,
            value.transaction_id,
            true,
        ),
    };
    if !valid_external_identity(effect_id, digest, transaction_id) {
        return Err(StoreError::CorruptState);
    }
    let stored = stored_external_custody(tx, settlement_id, effect_id)?
        .ok_or(StoreError::IdempotencyConflict)?;
    validate_external_row(&stored, digest, transaction_id, require_completed)
}

fn apply_external_custody_mutation(
    tx: &Transaction<'_>,
    settlement_id: [u8; 32],
    source_sequence: i64,
    now_unix_ms: i64,
    reapplying: bool,
    mutation: Option<ExternalCustodyMutation<'_>>,
) -> Result<()> {
    let Some(mutation) = mutation else {
        return Ok(());
    };
    if reapplying {
        return Err(StoreError::CorruptState);
    }
    match mutation {
        ExternalCustodyMutation::Insert(value) => {
            if !valid_external_identity(value.effect_id, value.custody_digest, value.transaction_id)
            {
                return Err(StoreError::CorruptState);
            }
            tx.execute(
                "INSERT INTO durable_outbox
                 (settlement_id, effect_id, source_seq, effect_kind, payload_bytes,
                  payload_hash, status_tag, attempts, dispatch_class, external_tx_id)
                 VALUES (?1, ?2, ?3, ?4, x'', ?5, ?6, 0, ?7, ?8)",
                rusqlite::params![
                    settlement_id,
                    value.effect_id,
                    source_sequence,
                    i64::from(value.effect_kind),
                    value.custody_digest,
                    OUTBOX_PENDING,
                    OUTBOX_DISPATCH_EXTERNAL_CUSTODY,
                    value.transaction_id,
                ],
            )?;
        }
        ExternalCustodyMutation::Complete(value) => {
            if !valid_external_identity(value.effect_id, value.custody_digest, value.transaction_id)
            {
                return Err(StoreError::CorruptState);
            }
            let stored = stored_external_custody(tx, settlement_id, value.effect_id)?
                .ok_or(StoreError::NotFound)?;
            validate_external_row(&stored, value.custody_digest, value.transaction_id, false)?;
            if stored.4 == OUTBOX_PENDING {
                let updated = tx.execute(
                    "UPDATE durable_outbox
                     SET status_tag = ?4, attempts = 1, completed_at_unix_ms = ?5
                     WHERE settlement_id = ?1 AND effect_id = ?2
                       AND payload_hash = ?3 AND dispatch_class = ?6
                       AND status_tag = ?7 AND attempts = 0
                       AND lease_until_unix_ms IS NULL
                       AND completed_at_unix_ms IS NULL",
                    rusqlite::params![
                        settlement_id,
                        value.effect_id,
                        value.custody_digest,
                        OUTBOX_COMPLETED,
                        now_unix_ms,
                        OUTBOX_DISPATCH_EXTERNAL_CUSTODY,
                        OUTBOX_PENDING,
                    ],
                )?;
                if updated != 1 {
                    return Err(StoreError::RevisionConflict);
                }
            }
        }
    }
    Ok(())
}

impl Store {
    /// Creates one settlement: terms row + initial snapshot, atomically.
    ///
    /// Idempotent for the byte-identical re-presentation (returns the
    /// existing snapshot); the same `settlement_id` with a different
    /// binding is equivocation and fails closed.
    pub fn f2_create(&mut self, req: &SettlementCreate<'_>) -> Result<SettlementSnapshotRow> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<([u8; 32], [u8; 32], Vec<u8>)> = tx
            .query_row(
                "SELECT session_id, terms_hash, canonical_terms
                 FROM settlement_terms WHERE settlement_id = ?1",
                rusqlite::params![req.settlement_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((session, hash, canonical)) = existing {
            if session != req.session_id
                || hash != req.terms_hash
                || canonical != req.canonical_terms
            {
                return Err(StoreError::IdempotencyConflict);
            }
            drop(tx);
            return self
                .f2_load(req.settlement_id)?
                .ok_or(StoreError::CorruptState);
        }
        tx.execute(
            "INSERT INTO settlement_terms
             (settlement_id, session_id, terms_hash, canonical_terms, created_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                req.settlement_id,
                req.session_id,
                req.terms_hash,
                req.canonical_terms,
                req.created_at_unix_ms
            ],
        )?;
        tx.execute(
            "INSERT INTO settlement_snapshot
             (settlement_id, revision, state_tag, context_bytes, last_event_seq, updated_at_unix_ms)
             VALUES (?1, 0, ?2, ?3, 0, ?4)",
            rusqlite::params![
                req.settlement_id,
                i64::from(req.initial_state_tag),
                req.initial_context,
                req.created_at_unix_ms
            ],
        )?;
        tx.commit()?;
        Ok(SettlementSnapshotRow {
            session_id: req.session_id,
            terms_hash: req.terms_hash,
            revision: 0,
            state_tag: req.initial_state_tag,
            context_bytes: req.initial_context.to_vec(),
            last_event_seq: 0,
        })
    }

    /// Loads the snapshot joined with the settlement's binding.
    pub fn f2_load(&self, settlement_id: [u8; 32]) -> Result<Option<SettlementSnapshotRow>> {
        let row = self
            .connection
            .query_row(
                "SELECT t.session_id, t.terms_hash, s.revision, s.state_tag,
                        s.context_bytes, s.last_event_seq
                 FROM settlement_terms t
                 JOIN settlement_snapshot s ON s.settlement_id = t.settlement_id
                 WHERE t.settlement_id = ?1",
                rusqlite::params![settlement_id],
                |row| {
                    Ok((
                        row.get::<_, [u8; 32]>(0)?,
                        row.get::<_, [u8; 32]>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((session_id, terms_hash, revision, state_tag, context_bytes, last_seq)) = row
        else {
            return Ok(None);
        };
        Ok(Some(SettlementSnapshotRow {
            session_id,
            terms_hash,
            revision: u64::try_from(revision).map_err(|_| StoreError::CorruptState)?,
            state_tag: u16::try_from(state_tag).map_err(|_| StoreError::CorruptState)?,
            context_bytes,
            last_event_seq: u64::try_from(last_seq).map_err(|_| StoreError::CorruptState)?,
        }))
    }

    /// Frozen terms of one settlement: `(canonical_bytes, terms_hash)`.
    ///
    /// The engine derives every policy (finality, timelock, fee ceiling)
    /// from these bytes instead of from loose parameters (spec §20), so a
    /// restarted process cannot run under a policy the terms never froze.
    pub fn f2_terms(&self, settlement_id: [u8; 32]) -> Result<Option<(Vec<u8>, [u8; 32])>> {
        Ok(self
            .connection
            .query_row(
                "SELECT canonical_terms, terms_hash FROM settlement_terms
                 WHERE settlement_id = ?1",
                rusqlite::params![settlement_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, [u8; 32]>(1)?)),
            )
            .optional()?)
    }

    /// Re-affirms that one already-committed observation is back on the
    /// canonical chain, promoting its evidence row from invalidated to
    /// applied. Called when a redelivery is acknowledged: the redelivered
    /// bytes include the block anchor, so an identical redelivery is proof
    /// that the very same block is canonical again. Returns the row count.
    pub fn f2_reaffirm_evidence(
        &mut self,
        settlement_id: [u8; 32],
        evidence_id: [u8; 32],
    ) -> Result<usize> {
        Ok(self.connection.execute(
            REAFFIRM_EVIDENCE_SQL,
            rusqlite::params![
                settlement_id,
                evidence_id,
                EVIDENCE_APPLIED,
                EVIDENCE_INVALIDATED
            ],
        )?)
    }

    /// Canonical bytes already journalled for one `(settlement, event)`,
    /// if that event was committed. The authoritative dedupe still runs
    /// inside `f2_commit_transition`; this read lets the caller answer a
    /// redelivery with an ACK before consulting the machine (spec §9).
    pub fn f2_journalled_event(
        &self,
        settlement_id: [u8; 32],
        event_id: [u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .connection
            .query_row(
                "SELECT event_bytes FROM settlement_journal
                 WHERE settlement_id = ?1 AND event_id = ?2",
                rusqlite::params![settlement_id, event_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?)
    }

    /// Commits one accepted transition — the nine steps of spec §8.2 in a
    /// single `BEGIN IMMEDIATE` transaction.
    pub fn f2_commit_transition(&mut self, req: &SettlementCommit<'_>) -> Result<CommitOutcome> {
        self.f2_commit_transition_inner(req, None)
    }

    /// Commits a transition and atomically creates one payload-free external
    /// custody effect.
    ///
    /// The effect is permanently excluded from [`Self::f2_ready_outbox`]. A
    /// retry accepts only the same custody digest and transaction identifier.
    pub fn f2_commit_transition_with_external_custody(
        &mut self,
        req: &SettlementCommit<'_>,
        external: &ExternalCustodyInsert,
    ) -> Result<CommitOutcome> {
        self.f2_commit_transition_inner(req, Some(ExternalCustodyMutation::Insert(external)))
    }

    /// Commits a successor transition and atomically completes one previously
    /// inserted external-custody effect.
    ///
    /// Completion records the sole external submission as attempt one. The
    /// row was never leaseable and therefore cannot have a dispatcher lease.
    pub fn f2_commit_transition_completing_external_custody(
        &mut self,
        req: &SettlementCommit<'_>,
        external: &ExternalCustodyCompletion,
    ) -> Result<CommitOutcome> {
        self.f2_commit_transition_inner(req, Some(ExternalCustodyMutation::Complete(external)))
    }

    fn f2_commit_transition_inner(
        &mut self,
        req: &SettlementCommit<'_>,
        external: Option<ExternalCustodyMutation<'_>>,
    ) -> Result<CommitOutcome> {
        failpoint!(C0);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        // 1. event_id dedupe / equivocation on the exact bytes.
        let previous: Option<Vec<u8>> = tx
            .query_row(
                "SELECT event_bytes FROM settlement_journal
                 WHERE settlement_id = ?1 AND event_id = ?2",
                rusqlite::params![req.settlement_id, req.event_id],
                |row| row.get(0),
            )
            .optional()?;
        let mut reapplying = false;
        if let Some(bytes) = previous {
            if bytes != req.event_bytes {
                return Err(StoreError::IdempotencyConflict);
            }
            // A byte-identical redelivery is the scanner re-reading the
            // CANONICAL chain, and the bytes include the block anchor —
            // so the observation is provably back on the canonical branch.
            // Re-affirm its evidence row, which a reorg may have marked
            // invalidated before the very same block was re-mined. Without
            // this, an observation that disappears and comes back
            // identically stays invalidated forever and its confirmation
            // can never be derived.
            let mut refreshed = false;
            if let Some(evidence) = &req.evidence {
                let flipped = tx.execute(
                    REAFFIRM_EVIDENCE_SQL,
                    rusqlite::params![
                        req.settlement_id,
                        evidence.evidence_id,
                        EVIDENCE_APPLIED,
                        EVIDENCE_INVALIDATED
                    ],
                )?;
                refreshed = flipped > 0;
            }
            if !refreshed {
                validate_external_custody_replay(&tx, req.settlement_id, external)?;
                tx.commit()?;
                return Ok(CommitOutcome::DuplicateSameBytes);
            }
            // Spec §11 rule 8: an identical redelivery whose evidence a
            // REORG had invalidated is an idempotent REFRESH, not a plain
            // duplicate — the machine transition the caller supplied
            // re-applies in THIS transaction, so the context recovers
            // exactly what the canonical chain again proves. The journal
            // gains a second row for the same event id (the dedupe query
            // still answers with the identical bytes); only the row flip
            // above distinguishes a refresh from a replay, and it is
            // durable, so a plain duplicate can never take this path.
            reapplying = true;
        }

        failpoint!(C1);

        // 2. snapshot must exist and match the expected revision.
        let (revision, last_seq): (i64, i64) = tx
            .query_row(
                "SELECT revision, last_event_seq FROM settlement_snapshot
                 WHERE settlement_id = ?1",
                rusqlite::params![req.settlement_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let revision = u64::try_from(revision).map_err(|_| StoreError::CorruptState)?;
        if revision != req.expected_revision {
            return Err(StoreError::RevisionConflict);
        }
        let seq = last_seq.checked_add(1).ok_or(StoreError::CounterOverflow)?;

        // 3. journal append. A §11.8 refresh re-appends the SAME event
        //    bytes under the caller-derived refresh identity: the
        //    ratified UNIQUE(settlement_id, event_id) stays intact (the
        //    original row keeps serving dedupe and equivocation), and
        //    recovery replay (§13 step 3) re-applies the identical
        //    bytes in order, reproducing exactly the refreshed context.
        let journal_event_id = if reapplying {
            req.refresh_event_id.ok_or(StoreError::CorruptState)?
        } else {
            req.event_id
        };
        tx.execute(
            "INSERT INTO settlement_journal
             (settlement_id, seq, expected_revision, resulting_revision, event_id,
              event_kind, event_bytes, context_hash, created_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                req.settlement_id,
                seq,
                i64::try_from(req.expected_revision).map_err(|_| StoreError::CounterOverflow)?,
                i64::try_from(req.resulting_revision).map_err(|_| StoreError::CounterOverflow)?,
                journal_event_id,
                i64::from(req.event_kind),
                req.event_bytes,
                req.context_hash,
                req.now_unix_ms
            ],
        )?;

        failpoint!(C2);

        // 4. snapshot CAS: the WHERE clause re-checks the revision so a
        //    racing writer loses deterministically.
        let updated = tx.execute(
            "UPDATE settlement_snapshot
             SET revision = ?3, state_tag = ?4, context_bytes = ?5,
                 last_event_seq = ?6, updated_at_unix_ms = ?7
             WHERE settlement_id = ?1 AND revision = ?2",
            rusqlite::params![
                req.settlement_id,
                i64::try_from(req.expected_revision).map_err(|_| StoreError::CounterOverflow)?,
                i64::try_from(req.resulting_revision).map_err(|_| StoreError::CounterOverflow)?,
                i64::from(req.state_tag),
                req.context_bytes,
                seq,
                req.now_unix_ms
            ],
        )?;
        if updated != 1 {
            return Err(StoreError::RevisionConflict);
        }

        failpoint!(C3);

        // 5. evidence ref / cursor, when applicable.
        if let Some(ev) = &req.evidence {
            tx.execute(
                "INSERT INTO observed_evidence
                 (settlement_id, evidence_id, chain_id, tx_id, event_index,
                  block_height, block_anchor, status_tag, first_seen_seq)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(settlement_id, evidence_id)
                 DO UPDATE SET status_tag = excluded.status_tag",
                rusqlite::params![
                    req.settlement_id,
                    ev.evidence_id,
                    ev.chain_id,
                    ev.tx_id,
                    i64::from(ev.event_index),
                    i64::try_from(ev.block_height).map_err(|_| StoreError::CounterOverflow)?,
                    ev.block_anchor,
                    ev.status_tag,
                    seq
                ],
            )?;
        }
        if let Some(cur) = &req.cursor {
            tx.execute(
                "INSERT INTO chain_cursor
                 (settlement_id, chain_id, cursor_bytes, anchor_height, anchor_hash, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(settlement_id, chain_id)
                 DO UPDATE SET cursor_bytes = excluded.cursor_bytes,
                               anchor_height = excluded.anchor_height,
                               anchor_hash = excluded.anchor_hash,
                               revision = excluded.revision",
                rusqlite::params![
                    req.settlement_id,
                    cur.chain_id,
                    cur.cursor_bytes,
                    cur.anchor_height,
                    cur.anchor_hash,
                    i64::try_from(req.resulting_revision)
                        .map_err(|_| StoreError::CounterOverflow)?
                ],
            )?;
        }

        failpoint!(C4);

        // 6. outbox inserts (deterministic IDs; the dedupe in step 1 makes
        //    a re-insert impossible, so a PK conflict here is corruption —
        //    EXCEPT on a §11.8 refresh, where the first application already
        //    inserted the same deterministic ids and rule 9 ("never
        //    executes the same effect twice") demands they NOT re-run:
        //    a refresh keeps existing outbox rows untouched.
        for effect in req.effects {
            if reapplying {
                tx.execute(
                    "INSERT INTO durable_outbox
                     (settlement_id, effect_id, source_seq, effect_kind, payload_bytes,
                      payload_hash, status_tag, attempts)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)
                     ON CONFLICT(settlement_id, effect_id) DO NOTHING",
                    rusqlite::params![
                        req.settlement_id,
                        effect.effect_id,
                        seq,
                        i64::from(effect.effect_kind),
                        effect.payload,
                        effect.payload_hash,
                        OUTBOX_PENDING
                    ],
                )?;
            } else {
                tx.execute(
                    "INSERT INTO durable_outbox
                     (settlement_id, effect_id, source_seq, effect_kind, payload_bytes,
                      payload_hash, status_tag, attempts)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
                    rusqlite::params![
                        req.settlement_id,
                        effect.effect_id,
                        seq,
                        i64::from(effect.effect_kind),
                        effect.payload,
                        effect.payload_hash,
                        OUTBOX_PENDING
                    ],
                )?;
            }
        }
        apply_external_custody_mutation(
            &tx,
            req.settlement_id,
            seq,
            req.now_unix_ms,
            reapplying,
            external,
        )?;

        failpoint!(C5);

        // 7. terminal outcome (PRIMARY KEY makes the second one impossible).
        if let Some(term) = &req.terminal {
            tx.execute(
                "INSERT INTO terminal_outcome
                 (settlement_id, outcome_tag, source_event_id, finalized_revision,
                  created_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    req.settlement_id,
                    i64::from(term.outcome_tag),
                    term.source_event_id,
                    i64::try_from(req.resulting_revision)
                        .map_err(|_| StoreError::CounterOverflow)?,
                    req.now_unix_ms
                ],
            )?;
        }

        // 8. commit — only now does anything become visible (step 9: the
        //    dispatcher reads exclusively committed rows).
        failpoint!(C6);
        tx.commit()?;
        failpoint!(C7);
        Ok(CommitOutcome::Committed)
    }

    /// Parks one piece of evidence for deterministic reordering (spec §10).
    ///
    /// Idempotent for the identical row; the same `evidence_id` with a
    /// different content is equivocation and fails closed.
    pub fn f2_park_evidence(
        &mut self,
        settlement_id: [u8; 32],
        ev: &EvidenceRow,
        first_seen_seq: u64,
    ) -> Result<ParkOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        type StoredEvidence = ([u8; 32], [u8; 32], i64, i64, [u8; 32]);
        let existing: Option<StoredEvidence> = tx
            .query_row(
                "SELECT chain_id, tx_id, event_index, block_height, block_anchor
                 FROM observed_evidence
                 WHERE settlement_id = ?1 AND evidence_id = ?2",
                rusqlite::params![settlement_id, ev.evidence_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        if let Some((chain, tx_id, index, height, anchor)) = existing {
            let same = chain == ev.chain_id
                && tx_id == ev.tx_id
                && index == i64::from(ev.event_index)
                && u64::try_from(height).ok() == Some(ev.block_height)
                && anchor == ev.block_anchor;
            return if same {
                Ok(ParkOutcome::AlreadyPresent)
            } else {
                Err(StoreError::IdempotencyConflict)
            };
        }
        tx.execute(
            "INSERT INTO observed_evidence
             (settlement_id, evidence_id, chain_id, tx_id, event_index,
              block_height, block_anchor, status_tag, first_seen_seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                settlement_id,
                ev.evidence_id,
                ev.chain_id,
                ev.tx_id,
                i64::from(ev.event_index),
                i64::try_from(ev.block_height).map_err(|_| StoreError::CounterOverflow)?,
                ev.block_anchor,
                EVIDENCE_PARKED,
                i64::try_from(first_seen_seq).map_err(|_| StoreError::CounterOverflow)?
            ],
        )?;
        tx.commit()?;
        Ok(ParkOutcome::Parked)
    }

    /// Parked evidence in canonical chain order
    /// `(block_height, event_index, tx_id)` (spec §10).
    pub fn f2_parked_evidence(&self, settlement_id: [u8; 32]) -> Result<Vec<EvidenceRow>> {
        self.f2_evidence(settlement_id, EVIDENCE_PARKED)
    }

    /// Evidence rows with one status, in canonical chain order
    /// `(block_height, event_index, tx_id)` (spec §10). Read-only:
    /// recovery and the finality policy reconstruct their working set
    /// from here instead of trusting process memory (spec §13).
    pub fn f2_evidence(
        &self,
        settlement_id: [u8; 32],
        status_tag: i64,
    ) -> Result<Vec<EvidenceRow>> {
        let mut stmt = self.connection.prepare(
            "SELECT evidence_id, chain_id, tx_id, event_index, block_height,
                    block_anchor, status_tag
             FROM observed_evidence
             WHERE settlement_id = ?1 AND status_tag = ?2
             ORDER BY block_height ASC, event_index ASC, tx_id ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![settlement_id, status_tag], |row| {
            Ok((
                row.get::<_, [u8; 32]>(0)?,
                row.get::<_, [u8; 32]>(1)?,
                row.get::<_, [u8; 32]>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, [u8; 32]>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (evidence_id, chain_id, tx_id, index, height, anchor, status) = row?;
            out.push(EvidenceRow {
                evidence_id,
                chain_id,
                tx_id,
                event_index: u32::try_from(index).map_err(|_| StoreError::CorruptState)?,
                block_height: u64::try_from(height).map_err(|_| StoreError::CorruptState)?,
                block_anchor: anchor,
                status_tag: status,
            });
        }
        Ok(out)
    }

    /// Marks every evidence row at or above `from_height` as invalidated
    /// by a reorg (spec §11 step 2), in one transaction.
    ///
    /// This is audit bookkeeping, never a safety dependency: the machine
    /// has already cleared `last_observed_height` and
    /// `claim_evidence_verified` for the affected observation, so a stale
    /// row can never produce an economic effect even if a crash lands
    /// between this call and the reorg commit. Returns the row count.
    pub fn f2_invalidate_evidence_from(
        &mut self,
        settlement_id: [u8; 32],
        from_height: u64,
    ) -> Result<usize> {
        let height = i64::try_from(from_height).map_err(|_| StoreError::CounterOverflow)?;
        let affected = self.connection.execute(
            "UPDATE observed_evidence
             SET status_tag = ?3
             WHERE settlement_id = ?1 AND block_height >= ?2 AND status_tag != ?3",
            rusqlite::params![settlement_id, height, EVIDENCE_INVALIDATED],
        )?;
        Ok(affected)
    }

    /// Claims up to `max` dispatchable outbox entries: pending, or leased
    /// with an expired lease. Each claim extends the lease and increments
    /// `attempts`; the payload returned is byte-identical to the first
    /// persistence (resend never reconstructs).
    pub fn f2_ready_outbox(
        &mut self,
        now_unix_ms: i64,
        lease_ms: i64,
        max: u32,
    ) -> Result<Vec<ClaimedEffect>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut claimed = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT settlement_id, effect_id, effect_kind, payload_bytes,
                        payload_hash, attempts
                 FROM durable_outbox
                 WHERE status_tag = ?1
                   AND dispatch_class = ?4
                   AND (lease_until_unix_ms IS NULL OR lease_until_unix_ms <= ?2)
                 ORDER BY source_seq ASC
                 LIMIT ?3",
            )?;
            let rows = stmt.query_map(
                rusqlite::params![
                    OUTBOX_PENDING,
                    now_unix_ms,
                    i64::from(max),
                    OUTBOX_DISPATCH_RUNNER_PAYLOAD
                ],
                |row| {
                    Ok((
                        row.get::<_, [u8; 32]>(0)?,
                        row.get::<_, [u8; 32]>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, [u8; 32]>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )?;
            for row in rows {
                let (settlement_id, effect_id, kind, payload, payload_hash, attempts) = row?;
                claimed.push(ClaimedEffect {
                    settlement_id,
                    effect_id,
                    effect_kind: u16::try_from(kind).map_err(|_| StoreError::CorruptState)?,
                    payload,
                    payload_hash,
                    attempts: u64::try_from(attempts)
                        .map_err(|_| StoreError::CorruptState)?
                        .checked_add(1)
                        .ok_or(StoreError::CounterOverflow)?,
                });
            }
        }
        let lease_until = now_unix_ms
            .checked_add(lease_ms)
            .ok_or(StoreError::CounterOverflow)?;
        for effect in &claimed {
            tx.execute(
                "UPDATE durable_outbox
                 SET lease_until_unix_ms = ?3, attempts = attempts + 1
                 WHERE settlement_id = ?1 AND effect_id = ?2",
                rusqlite::params![effect.settlement_id, effect.effect_id, lease_until],
            )?;
        }
        tx.commit()?;
        failpoint!(C8);
        Ok(claimed)
    }

    /// Returns the exact payload-free outbox manifest for one settlement.
    ///
    /// This is a single read-only statement over terms, snapshot, outbox and
    /// journal tables. It never claims an effect or changes lease state. A
    /// missing settlement is [`StoreError::NotFound`]; a missing snapshot,
    /// orphan source sequence, unknown status, invalid integer conversion or
    /// incoherent status/lease/completion tuple is corrupt state.
    pub fn f2_outbox_summary(
        &self,
        settlement_id: [u8; 32],
    ) -> Result<Vec<F2OutboxEffectSummaryV1>> {
        let mut statement = self.connection.prepare(
            "SELECT snapshot.last_event_seq, outbox.rowid,
                    outbox.effect_id, outbox.source_seq, outbox.effect_kind,
                    outbox.payload_hash, outbox.dispatch_class,
                    outbox.external_tx_id, outbox.status_tag, outbox.attempts,
                    outbox.lease_until_unix_ms, outbox.completed_at_unix_ms,
                    journal.seq, journal.event_id
             FROM settlement_terms AS terms
             LEFT JOIN settlement_snapshot AS snapshot
               ON snapshot.settlement_id = terms.settlement_id
             LEFT JOIN durable_outbox AS outbox
               ON outbox.settlement_id = terms.settlement_id
             LEFT JOIN settlement_journal AS journal
               ON journal.settlement_id = outbox.settlement_id
              AND journal.seq = outbox.source_seq
             WHERE terms.settlement_id = ?1
             ORDER BY outbox.source_seq ASC, outbox.effect_id ASC",
        )?;
        let mut rows = statement.query(rusqlite::params![settlement_id])?;
        let mut found_settlement = false;
        let mut summary = Vec::new();
        let mut previous_order: Option<(u64, [u8; 32])> = None;

        while let Some(row) = rows.next()? {
            found_settlement = true;
            let snapshot_last_sequence = row
                .get::<_, Option<i64>>(0)?
                .ok_or(StoreError::CorruptState)
                .and_then(|value| u64::try_from(value).map_err(|_| StoreError::CorruptState))?;
            if row.get::<_, Option<i64>>(1)?.is_none() {
                continue;
            }
            let effect_id = row
                .get::<_, Option<[u8; 32]>>(2)?
                .ok_or(StoreError::CorruptState)?;

            let source_sequence = row
                .get::<_, Option<i64>>(3)?
                .ok_or(StoreError::CorruptState)
                .and_then(|value| u64::try_from(value).map_err(|_| StoreError::CorruptState))?;
            let effect_kind = row
                .get::<_, Option<i64>>(4)?
                .ok_or(StoreError::CorruptState)
                .and_then(|value| u16::try_from(value).map_err(|_| StoreError::CorruptState))?;
            let payload_hash = row
                .get::<_, Option<[u8; 32]>>(5)?
                .ok_or(StoreError::CorruptState)?;
            let dispatch_class_tag = row
                .get::<_, Option<i64>>(6)?
                .ok_or(StoreError::CorruptState)?;
            let external_transaction_id = row.get::<_, Option<[u8; 32]>>(7)?;
            let status_tag = row
                .get::<_, Option<i64>>(8)?
                .ok_or(StoreError::CorruptState)?;
            let attempts = row
                .get::<_, Option<i64>>(9)?
                .ok_or(StoreError::CorruptState)
                .and_then(|value| u64::try_from(value).map_err(|_| StoreError::CorruptState))?;
            let lease_until_unix_ms = row.get::<_, Option<i64>>(10)?;
            let completed_at_unix_ms = row.get::<_, Option<i64>>(11)?;
            let journal_sequence = row
                .get::<_, Option<i64>>(12)?
                .ok_or(StoreError::CorruptState)
                .and_then(|value| u64::try_from(value).map_err(|_| StoreError::CorruptState))?;
            let source_event_id = row
                .get::<_, Option<[u8; 32]>>(13)?
                .ok_or(StoreError::CorruptState)?;

            if source_sequence == 0
                || source_sequence > snapshot_last_sequence
                || journal_sequence != source_sequence
                || previous_order.is_some_and(|previous| (source_sequence, effect_id) <= previous)
            {
                return Err(StoreError::CorruptState);
            }

            let dispatch_class = match (dispatch_class_tag, external_transaction_id) {
                (OUTBOX_DISPATCH_RUNNER_PAYLOAD, None) => F2OutboxDispatchClassV1::RunnerPayload,
                (OUTBOX_DISPATCH_EXTERNAL_CUSTODY, Some(transaction_id))
                    if transaction_id != [0; 32] =>
                {
                    F2OutboxDispatchClassV1::ExternalCustody
                }
                _ => return Err(StoreError::CorruptState),
            };
            let status = match (dispatch_class, status_tag) {
                (F2OutboxDispatchClassV1::RunnerPayload, OUTBOX_PENDING)
                    if completed_at_unix_ms.is_none()
                        && ((attempts == 0 && lease_until_unix_ms.is_none())
                            || (attempts > 0 && lease_until_unix_ms.is_some())) =>
                {
                    F2OutboxDeliveryStatusV1::Pending
                }
                (F2OutboxDispatchClassV1::RunnerPayload, OUTBOX_COMPLETED)
                    if completed_at_unix_ms.is_some() && lease_until_unix_ms.is_none() =>
                {
                    F2OutboxDeliveryStatusV1::Completed
                }
                (F2OutboxDispatchClassV1::ExternalCustody, OUTBOX_PENDING)
                    if attempts == 0
                        && lease_until_unix_ms.is_none()
                        && completed_at_unix_ms.is_none() =>
                {
                    F2OutboxDeliveryStatusV1::Pending
                }
                (F2OutboxDispatchClassV1::ExternalCustody, OUTBOX_COMPLETED)
                    if attempts >= 1
                        && lease_until_unix_ms.is_none()
                        && completed_at_unix_ms.is_some() =>
                {
                    F2OutboxDeliveryStatusV1::Completed
                }
                _ => return Err(StoreError::CorruptState),
            };

            previous_order = Some((source_sequence, effect_id));
            summary.push(F2OutboxEffectSummaryV1 {
                effect_id,
                source_sequence,
                source_event_id,
                effect_kind,
                dispatch_class,
                payload_hash,
                external_transaction_id,
                status,
                attempts,
                lease_until_unix_ms,
                completed_at_unix_ms,
            });
        }

        if !found_settlement {
            return Err(StoreError::NotFound);
        }
        Ok(summary)
    }

    /// Marks one effect completed, revalidating the payload hash: a
    /// mismatch means the caller executed different bytes than the outbox
    /// holds, and fails closed without marking anything.
    pub fn f2_complete_effect(
        &mut self,
        effect_id: [u8; 32],
        expected_payload_hash: [u8; 32],
        now_unix_ms: i64,
    ) -> Result<()> {
        failpoint!(C9);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<([u8; 32], i64, i64)> = tx
            .query_row(
                "SELECT payload_hash, status_tag, dispatch_class
                 FROM durable_outbox WHERE effect_id = ?1",
                rusqlite::params![effect_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (payload_hash, status, dispatch_class) = stored.ok_or(StoreError::NotFound)?;
        if payload_hash != expected_payload_hash {
            return Err(StoreError::IdempotencyConflict);
        }
        if dispatch_class != OUTBOX_DISPATCH_RUNNER_PAYLOAD {
            return Err(StoreError::IdempotencyConflict);
        }
        if status == OUTBOX_COMPLETED {
            return Ok(()); // idempotent completion
        }
        tx.execute(
            "UPDATE durable_outbox
             SET status_tag = ?2, completed_at_unix_ms = ?3, lease_until_unix_ms = NULL
             WHERE effect_id = ?1",
            rusqlite::params![effect_id, OUTBOX_COMPLETED, now_unix_ms],
        )?;
        tx.commit()?;
        failpoint!(C10);
        Ok(())
    }

    /// Records late evidence by identifier only (spec §12): terminal
    /// settlements stay terminal; the row is auditable and idempotent.
    pub fn f2_record_late_evidence(
        &mut self,
        settlement_id: [u8; 32],
        evidence_id: [u8; 32],
        terminal_tag: u16,
        now_unix_ms: i64,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT OR IGNORE INTO late_evidence
             (settlement_id, evidence_id, terminal_tag, observed_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                settlement_id,
                evidence_id,
                i64::from(terminal_tag),
                now_unix_ms
            ],
        )?;
        Ok(())
    }

    /// Late evidence recorded for one settlement, oldest first (spec §12).
    ///
    /// Returns identifiers and the terminal that was already in force when
    /// each arrived. No event bytes are stored by the recorder, so none can
    /// be returned here: the row is an audit trail, not a replay source.
    pub fn f2_late_evidence(&self, settlement_id: [u8; 32]) -> Result<Vec<([u8; 32], u16, i64)>> {
        let mut stmt = self.connection.prepare(
            "SELECT evidence_id, terminal_tag, observed_at_unix_ms
             FROM late_evidence WHERE settlement_id = ?1
             ORDER BY observed_at_unix_ms, evidence_id",
        )?;
        let rows = stmt.query_map(rusqlite::params![settlement_id], |row| {
            let evidence_id: [u8; 32] = row.get(0)?;
            let terminal_tag: i64 = row.get(1)?;
            let observed_at_unix_ms: i64 = row.get(2)?;
            Ok((evidence_id, terminal_tag as u16, observed_at_unix_ms))
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    /// Journal of one settlement, in order, with continuity validated
    /// (recovery: a gap is corruption, spec §13).
    pub fn f2_read_journal(&self, settlement_id: [u8; 32]) -> Result<Vec<SettlementJournalRow>> {
        let mut stmt = self.connection.prepare(
            "SELECT seq, expected_revision, resulting_revision, event_id,
                    event_kind, event_bytes, context_hash
             FROM settlement_journal
             WHERE settlement_id = ?1
             ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![settlement_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, [u8; 32]>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, [u8; 32]>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        let mut expected_seq: i64 = 1;
        for row in rows {
            let (seq, expected, resulting, event_id, kind, bytes, context_hash) = row?;
            if seq != expected_seq {
                return Err(StoreError::CorruptState);
            }
            out.push(SettlementJournalRow {
                seq: u64::try_from(seq).map_err(|_| StoreError::CorruptState)?,
                expected_revision: u64::try_from(expected).map_err(|_| StoreError::CorruptState)?,
                resulting_revision: u64::try_from(resulting)
                    .map_err(|_| StoreError::CorruptState)?,
                event_id,
                event_kind: u16::try_from(kind).map_err(|_| StoreError::CorruptState)?,
                event_bytes: bytes,
                context_hash,
            });
            expected_seq = expected_seq
                .checked_add(1)
                .ok_or(StoreError::CounterOverflow)?;
        }
        Ok(out)
    }

    /// Cursor of one (settlement, chain), if present.
    #[allow(clippy::type_complexity)]
    pub fn f2_cursor(
        &self,
        settlement_id: [u8; 32],
        chain_id: [u8; 32],
    ) -> Result<Option<(Vec<u8>, Option<i64>, Option<[u8; 32]>, u64)>> {
        let row = self
            .connection
            .query_row(
                "SELECT cursor_bytes, anchor_height, anchor_hash, revision
                 FROM chain_cursor WHERE settlement_id = ?1 AND chain_id = ?2",
                rusqlite::params![settlement_id, chain_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<[u8; 32]>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((bytes, height, anchor, revision)) = row else {
            return Ok(None);
        };
        Ok(Some((
            bytes,
            height,
            anchor,
            u64::try_from(revision).map_err(|_| StoreError::CorruptState)?,
        )))
    }

    /// Terminal outcome of one settlement, if finalized.
    pub fn f2_terminal(&self, settlement_id: [u8; 32]) -> Result<Option<(u16, [u8; 32], u64)>> {
        let row = self
            .connection
            .query_row(
                "SELECT outcome_tag, source_event_id, finalized_revision
                 FROM terminal_outcome WHERE settlement_id = ?1",
                rusqlite::params![settlement_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, [u8; 32]>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((tag, source, revision)) = row else {
            return Ok(None);
        };
        Ok(Some((
            u16::try_from(tag).map_err(|_| StoreError::CorruptState)?,
            source,
            u64::try_from(revision).map_err(|_| StoreError::CorruptState)?,
        )))
    }
}
