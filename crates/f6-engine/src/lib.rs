//! F6 build-order step 3 (spec v1.0.1 §4.2, §6.5; D-018): the exclusive
//! bond reservation ledger and the atomic binding transition, journaled
//! under kind 0xF601 on the ratified store.
//!
//! Discipline, inherited verbatim from the F4 `DurableAssurance`
//! precedent: the PURE ledger decides every transition; a refusal
//! appends NOTHING; an accepted transition is appended — and the append
//! commits — BEFORE its effects are visible; recovery replays every
//! frame through the same pure ledger and fails closed on a foreign
//! record kind, a revision gap, undecodable bytes or a replay
//! divergence. The §4.2 binding is atomic because it is ONE frame: a
//! crash before the append leaves no binding, a crash after it leaves
//! the complete binding, and there is no in-between to observe.
//!
//! The ledger enforces the ratified exclusivity rule (§4.1.6/8): one
//! reservation backs at most one quote, is held by one solver, and is
//! spent forever once released — capacity is never silently recycled
//! under the same identifier (the one-shot discipline of the F1 vault).
//!
//! This crate holds no key and signs nothing (the roster and BIP340
//! verification live in build-order step 5).

#![forbid(unsafe_code)]

pub mod candidate_book;
pub mod composition;
pub mod consumer;
/// Versioned F6 binding ledger for heterogeneous-clock composed routes.
pub mod v2;

use std::collections::BTreeMap;
use std::path::Path;

use kaystra_core::types::Digest32;
use rfq::selection::{
    admissibility, select_winner, AdmissibilityRefusal, CandidateFactsV1, SelectionError,
    SelectionOutcomeV1,
};
use rfq::{
    AcceptanceV1, ChainId, ParticipantId, QuoteV1, RfqV1, TermsBindingV1, TimelockSpec, ROUTE_LEGS,
};

/// The F6 journal kind on the ratified store (spec §6.5).
pub const F6_JOURNAL_KIND: u16 = 0xF601;
/// Leading magic of every binding frame.
pub const FRAME_MAGIC: &[u8; 8] = b"DOMIF6J1";
/// Frozen frame wire version. Any other version fails closed.
pub const FRAME_WIRE_VERSION: u16 = 1;
/// Hard cap on one frame (I14: bounded before allocation).
pub const MAX_FRAME_BYTES: usize = 512;
/// Hard cap on replayable history (a runaway-log backstop, far above
/// any real session).
pub const MAX_JOURNAL_FRAMES: usize = 65_536;
/// Hard cap on reservations one ledger tracks (I14).
pub const MAX_RESERVATIONS: usize = 4_096;

/// One journaled ledger event (frame payload after revision and tag).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BindingEventV1 {
    /// A solver reserves bond capacity EXCLUSIVELY for one quote
    /// (§4.1.6/8; produced at quote time, before admissibility can
    /// attest `bond_reserved_exclusive`).
    Reserved {
        /// The F4-side reservation identifier.
        reservation_id: Digest32,
        /// The RFQ the reservation quotes for.
        rfq_id: Digest32,
        /// The quote the capacity is committed to.
        quote_id: Digest32,
        /// The solver holding the reservation.
        solver: ParticipantId,
    },
    /// The §4.2 atomic binding: validation, reservation, acceptance,
    /// `terms_hash` and persistence in ONE frame.
    Bound {
        /// The accepted RFQ.
        rfq_id: Digest32,
        /// The winning quote.
        quote_id: Digest32,
        /// The solver bound to execute.
        solver: ParticipantId,
        /// Who accepted (§4.2 step 3).
        accepted_by: ParticipantId,
        /// The exclusive reservation consumed by this binding.
        reservation_id: Digest32,
        /// The ratified §4.2 terms hash.
        terms_hash: Digest32,
    },
    /// A losing or expired reservation is released. The identifier is
    /// SPENT: re-reserving under it is refused forever.
    Released {
        /// The reservation being released.
        reservation_id: Digest32,
    },
    /// The recorded §4.3 selection (build-order step 4): which quote
    /// won and the arrival-order-independent digest of the full
    /// candidate set. One selection per RFQ; binding REQUIRES it.
    Selected {
        /// The RFQ selected for.
        rfq_id: Digest32,
        /// The winning quote under the ratified order.
        winning_quote: Digest32,
        /// The candidate-set digest (I12 recomputability).
        inputs_digest: Digest32,
    },
}

/// Named refusals of the ledger (I13). A refused event appends nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum BindingRefusal {
    /// The reservation id is already ACTIVE for another quote — the
    /// §4.1.8 double-commitment.
    #[error("reservation already in use")]
    ReservationInUse,
    /// The reservation id was released earlier and is spent forever.
    #[error("reservation spent")]
    ReservationSpent,
    /// Binding or release names a reservation the ledger never saw.
    #[error("reservation unknown")]
    ReservationUnknown,
    /// The binding consumes a reservation committed to a DIFFERENT
    /// quote.
    #[error("reservation committed to another quote")]
    ReservationQuoteMismatch,
    /// The binding names a solver other than the reservation's holder.
    #[error("reservation held by another solver")]
    ReservationHolderMismatch,
    /// The RFQ is already bound; a second binding is an equivocation.
    #[error("rfq already bound")]
    RfqAlreadyBound,
    /// The binding consumes a reservation that is already bound.
    #[error("reservation already bound")]
    ReservationAlreadyBound,
    /// More reservations than [`MAX_RESERVATIONS`] (I14).
    #[error("too many reservations")]
    TooManyReservations,
    /// A second selection for an already-selected RFQ: equivocation.
    #[error("rfq already selected")]
    RfqAlreadySelected,
    /// Binding without a journaled selection for the RFQ.
    #[error("no recorded selection for this rfq")]
    BindWithoutSelection,
    /// Binding a quote other than the journaled winner.
    #[error("quote is not the recorded winner")]
    SelectionQuoteMismatch,
}

/// Durability failures (fail closed, never skippable).
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum EngineError {
    /// The pure ledger refused the event; nothing was appended.
    #[error("refused: {0}")]
    Refused(#[from] BindingRefusal),
    /// The winning quote failed §4.1 re-validation at binding time.
    #[error("inadmissible at binding: {0}")]
    Inadmissible(AdmissibilityRefusal),
    /// The ratified selection itself failed (nothing was appended).
    #[error("selection: {0}")]
    Selection(SelectionError),
    /// The terms binding could not be assembled (§4.2 step 4).
    #[error("terms: {0}")]
    Terms(rfq::RfqObjectError),
    /// The underlying log failed.
    #[error("log: {0}")]
    Log(String),
    /// A record under a kind other than [`F6_JOURNAL_KIND`].
    #[error("foreign record in the f6 journal")]
    ForeignRecord,
    /// A frame does not decode canonically.
    #[error("undecodable frame")]
    UndecodableFrame,
    /// Frame revisions are not the contiguous sequence 0..n.
    #[error("revision gap")]
    RevisionGap,
    /// A replayed frame was refused by the pure ledger: the history
    /// does not reproduce, the state is not trustworthy.
    #[error("replay divergence: {0}")]
    ReplayDivergence(BindingRefusal),
    /// More frames than [`MAX_JOURNAL_FRAMES`].
    #[error("journal too large")]
    JournalTooLarge,
    /// The two parties hold DIFFERENT bindings for one RFQ.
    #[error("binding divergence between the parties")]
    BindingDivergence,
}

type Result<T> = std::result::Result<T, EngineError>;

// ---------------------------------------------------------------------
// frame codec
// ---------------------------------------------------------------------

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Canonical frame: magic, wire version, revision, event tag, fields.
pub fn encode_frame(revision: u64, event: &BindingEventV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_FRAME_BYTES);
    out.extend_from_slice(FRAME_MAGIC);
    put_u16(&mut out, FRAME_WIRE_VERSION);
    put_u64(&mut out, revision);
    match event {
        BindingEventV1::Reserved {
            reservation_id,
            rfq_id,
            quote_id,
            solver,
        } => {
            out.push(0x01);
            out.extend_from_slice(reservation_id);
            out.extend_from_slice(rfq_id);
            out.extend_from_slice(quote_id);
            out.extend_from_slice(&solver.0);
        }
        BindingEventV1::Bound {
            rfq_id,
            quote_id,
            solver,
            accepted_by,
            reservation_id,
            terms_hash,
        } => {
            out.push(0x02);
            out.extend_from_slice(rfq_id);
            out.extend_from_slice(quote_id);
            out.extend_from_slice(&solver.0);
            out.extend_from_slice(&accepted_by.0);
            out.extend_from_slice(reservation_id);
            out.extend_from_slice(terms_hash);
        }
        BindingEventV1::Released { reservation_id } => {
            out.push(0x03);
            out.extend_from_slice(reservation_id);
        }
        BindingEventV1::Selected {
            rfq_id,
            winning_quote,
            inputs_digest,
        } => {
            out.push(0x04);
            out.extend_from_slice(rfq_id);
            out.extend_from_slice(winning_quote);
            out.extend_from_slice(inputs_digest);
        }
    }
    out
}

fn take<'a>(bytes: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = pos
        .checked_add(n)
        .filter(|&e| e <= bytes.len())
        .ok_or(EngineError::UndecodableFrame)?;
    let slice = &bytes[*pos..end];
    *pos = end;
    Ok(slice)
}

fn take_32(bytes: &[u8], pos: &mut usize) -> Result<Digest32> {
    let slice = take(bytes, pos, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}

/// Strict decoder: (revision, event). Fails closed on magic, version,
/// truncation, unknown tag, trailing bytes or an oversized frame.
pub fn decode_frame(bytes: &[u8]) -> Result<(u64, BindingEventV1)> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(EngineError::UndecodableFrame);
    }
    let mut pos = 0usize;
    if take(bytes, &mut pos, FRAME_MAGIC.len())? != FRAME_MAGIC {
        return Err(EngineError::UndecodableFrame);
    }
    let version_bytes = take(bytes, &mut pos, 2)?;
    if u16::from_be_bytes([version_bytes[0], version_bytes[1]]) != FRAME_WIRE_VERSION {
        return Err(EngineError::UndecodableFrame);
    }
    let revision_bytes = take(bytes, &mut pos, 8)?;
    let mut rev = [0u8; 8];
    rev.copy_from_slice(revision_bytes);
    let revision = u64::from_be_bytes(rev);
    let tag = take(bytes, &mut pos, 1)?[0];
    let event = match tag {
        0x01 => BindingEventV1::Reserved {
            reservation_id: take_32(bytes, &mut pos)?,
            rfq_id: take_32(bytes, &mut pos)?,
            quote_id: take_32(bytes, &mut pos)?,
            solver: ParticipantId(take_32(bytes, &mut pos)?),
        },
        0x02 => BindingEventV1::Bound {
            rfq_id: take_32(bytes, &mut pos)?,
            quote_id: take_32(bytes, &mut pos)?,
            solver: ParticipantId(take_32(bytes, &mut pos)?),
            accepted_by: ParticipantId(take_32(bytes, &mut pos)?),
            reservation_id: take_32(bytes, &mut pos)?,
            terms_hash: take_32(bytes, &mut pos)?,
        },
        0x03 => BindingEventV1::Released {
            reservation_id: take_32(bytes, &mut pos)?,
        },
        0x04 => BindingEventV1::Selected {
            rfq_id: take_32(bytes, &mut pos)?,
            winning_quote: take_32(bytes, &mut pos)?,
            inputs_digest: take_32(bytes, &mut pos)?,
        },
        _ => return Err(EngineError::UndecodableFrame),
    };
    if pos != bytes.len() {
        return Err(EngineError::UndecodableFrame);
    }
    Ok((revision, event))
}

// ---------------------------------------------------------------------
// the pure ledger
// ---------------------------------------------------------------------

/// State of one reservation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ReservationState {
    /// Reserved and available to bind exactly its committed quote.
    Active {
        rfq_id: Digest32,
        quote_id: Digest32,
        solver: ParticipantId,
    },
    /// Consumed by a binding.
    Bound,
    /// Released; the identifier is spent forever.
    Spent,
}

/// One completed binding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BoundRecordV1 {
    /// The winning quote.
    pub quote_id: Digest32,
    /// The executing solver.
    pub solver: ParticipantId,
    /// Who accepted.
    pub accepted_by: ParticipantId,
    /// The consumed reservation.
    pub reservation_id: Digest32,
    /// The ratified terms hash.
    pub terms_hash: Digest32,
}

/// The pure, replayable ledger. Every decision lives here; durability
/// wraps it and adds nothing.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct BindingLedgerV1 {
    reservations: BTreeMap<Digest32, ReservationState>,
    bindings: BTreeMap<Digest32, BoundRecordV1>,
    selections: BTreeMap<Digest32, SelectedRecordV1>,
}

/// One recorded selection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SelectedRecordV1 {
    /// The winning quote.
    pub winning_quote: Digest32,
    /// The candidate-set digest.
    pub inputs_digest: Digest32,
}

impl BindingLedgerV1 {
    /// A fresh, empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// The binding recorded for `rfq_id`, if any.
    pub fn binding(&self, rfq_id: &Digest32) -> Option<&BoundRecordV1> {
        self.bindings.get(rfq_id)
    }

    /// The selection recorded for `rfq_id`, if any.
    pub fn selection(&self, rfq_id: &Digest32) -> Option<&SelectedRecordV1> {
        self.selections.get(rfq_id)
    }

    /// Whether `reservation_id` is ACTIVE and committed to exactly
    /// (`rfq_id`, `quote_id`, `solver`) — the fact behind the §4.1.6/8
    /// admissibility attestation.
    pub fn reservation_backs(
        &self,
        reservation_id: &Digest32,
        rfq_id: &Digest32,
        quote_id: &Digest32,
        solver: &ParticipantId,
    ) -> bool {
        matches!(
            self.reservations.get(reservation_id),
            Some(ReservationState::Active {
                rfq_id: r,
                quote_id: q,
                solver: s,
            }) if r == rfq_id && q == quote_id && s == solver
        )
    }

    /// Applies one event. A refusal mutates NOTHING.
    pub fn apply(&mut self, event: &BindingEventV1) -> std::result::Result<(), BindingRefusal> {
        match event {
            BindingEventV1::Reserved {
                reservation_id,
                rfq_id,
                quote_id,
                solver,
            } => {
                match self.reservations.get(reservation_id) {
                    Some(ReservationState::Active { .. }) | Some(ReservationState::Bound) => {
                        return Err(BindingRefusal::ReservationInUse)
                    }
                    Some(ReservationState::Spent) => return Err(BindingRefusal::ReservationSpent),
                    None => {}
                }
                if self.reservations.len() >= MAX_RESERVATIONS {
                    return Err(BindingRefusal::TooManyReservations);
                }
                self.reservations.insert(
                    *reservation_id,
                    ReservationState::Active {
                        rfq_id: *rfq_id,
                        quote_id: *quote_id,
                        solver: *solver,
                    },
                );
                Ok(())
            }
            BindingEventV1::Bound {
                rfq_id,
                quote_id,
                solver,
                accepted_by,
                reservation_id,
                terms_hash,
            } => {
                if self.bindings.contains_key(rfq_id) {
                    return Err(BindingRefusal::RfqAlreadyBound);
                }
                // Step-4 rule: no binding without the journaled §4.3
                // selection, and only its recorded winner binds.
                match self.selections.get(rfq_id) {
                    None => return Err(BindingRefusal::BindWithoutSelection),
                    Some(selected) if selected.winning_quote != *quote_id => {
                        return Err(BindingRefusal::SelectionQuoteMismatch)
                    }
                    Some(_) => {}
                }
                match self.reservations.get(reservation_id) {
                    None => return Err(BindingRefusal::ReservationUnknown),
                    Some(ReservationState::Spent) => return Err(BindingRefusal::ReservationSpent),
                    Some(ReservationState::Bound) => {
                        return Err(BindingRefusal::ReservationAlreadyBound)
                    }
                    Some(ReservationState::Active {
                        rfq_id: r,
                        quote_id: q,
                        solver: s,
                    }) => {
                        if r != rfq_id || q != quote_id {
                            return Err(BindingRefusal::ReservationQuoteMismatch);
                        }
                        if s != solver {
                            return Err(BindingRefusal::ReservationHolderMismatch);
                        }
                    }
                }
                self.reservations
                    .insert(*reservation_id, ReservationState::Bound);
                self.bindings.insert(
                    *rfq_id,
                    BoundRecordV1 {
                        quote_id: *quote_id,
                        solver: *solver,
                        accepted_by: *accepted_by,
                        reservation_id: *reservation_id,
                        terms_hash: *terms_hash,
                    },
                );
                Ok(())
            }
            BindingEventV1::Released { reservation_id } => {
                match self.reservations.get(reservation_id) {
                    None => return Err(BindingRefusal::ReservationUnknown),
                    Some(ReservationState::Spent) => return Err(BindingRefusal::ReservationSpent),
                    Some(ReservationState::Bound) => {
                        return Err(BindingRefusal::ReservationAlreadyBound)
                    }
                    Some(ReservationState::Active { .. }) => {}
                }
                self.reservations
                    .insert(*reservation_id, ReservationState::Spent);
                Ok(())
            }
            BindingEventV1::Selected {
                rfq_id,
                winning_quote,
                inputs_digest,
            } => {
                if self.selections.contains_key(rfq_id) {
                    return Err(BindingRefusal::RfqAlreadySelected);
                }
                self.selections.insert(
                    *rfq_id,
                    SelectedRecordV1 {
                        winning_quote: *winning_quote,
                        inputs_digest: *inputs_digest,
                    },
                );
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------
// the durable log
// ---------------------------------------------------------------------

/// An append-only frame log — the whole durability contract of the
/// binding engine.
pub trait BindingLog {
    /// Durably appends one encoded frame. Returning means COMMITTED.
    fn append_frame(&mut self, frame: &[u8]) -> Result<()>;
    /// Every frame, in append order.
    fn frames(&self) -> Result<Vec<Vec<u8>>>;
}

/// In-memory log for the pure tests.
#[derive(Default)]
pub struct MemoryLog {
    frames: Vec<Vec<u8>>,
}

impl MemoryLog {
    /// A fresh, empty log.
    pub fn new() -> Self {
        Self::default()
    }
}

impl BindingLog for MemoryLog {
    fn append_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.frames.push(frame.to_vec());
        Ok(())
    }

    fn frames(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.frames.clone())
    }
}

/// The durable log: the ratified `store` crate, holding F6 binding
/// frames under [`F6_JOURNAL_KIND`] and nothing else. Its own instance
/// — never shared with a settlement engine's store, the F3 outbox or
/// the F4 assurance log.
pub struct StoreLog {
    store: store::Store,
}

impl StoreLog {
    /// Opens (or creates) the log at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let store = store::Store::open(path).map_err(|e| EngineError::Log(e.to_string()))?;
        Ok(Self { store })
    }

    /// Creates a strict owner-only production F6 journal.
    ///
    /// The binding is persisted by the neutral store and rechecked on every
    /// journal operation.  This constructor never falls back to the migrating
    /// development opening above.
    pub fn create_production(path: &Path, binding_digest: Digest32) -> Result<Self> {
        let binding = store::ProductionStoreBindingV1::new(binding_digest)
            .map_err(|error| EngineError::Log(error.to_string()))?;
        let store = store::Store::create_production(path, binding)
            .map_err(|error| EngineError::Log(error.to_string()))?;
        Ok(Self { store })
    }

    /// Opens one exact existing production F6 journal without creation or
    /// migration.
    pub fn open_production(path: &Path, binding_digest: Digest32) -> Result<Self> {
        let binding = store::ProductionStoreBindingV1::new(binding_digest)
            .map_err(|error| EngineError::Log(error.to_string()))?;
        let store = store::Store::open_production(path, binding)
            .map_err(|error| EngineError::Log(error.to_string()))?;
        Ok(Self { store })
    }

    /// Completes only a pristine production F6 journal whose provisioning was
    /// already started by an external durable provisioning journal.
    pub fn resume_create_production(path: &Path, binding_digest: Digest32) -> Result<Self> {
        let binding = store::ProductionStoreBindingV1::new(binding_digest)
            .map_err(|error| EngineError::Log(error.to_string()))?;
        let store = store::Store::resume_create_production(path, binding)
            .map_err(|error| EngineError::Log(error.to_string()))?;
        Ok(Self { store })
    }
}

impl BindingLog for StoreLog {
    fn append_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.store
            .append_journal(F6_JOURNAL_KIND, frame)
            .map(|_| ())
            .map_err(|e| EngineError::Log(e.to_string()))
    }

    fn frames(&self) -> Result<Vec<Vec<u8>>> {
        let entries = self
            .store
            .read_journal()
            .map_err(|e| EngineError::Log(e.to_string()))?;
        let mut out = Vec::with_capacity(entries.len().min(MAX_JOURNAL_FRAMES));
        for entry in entries {
            // The F6 log holds F6 frames and nothing else. A foreign
            // kind is corruption or misuse, never skippable.
            if entry.kind != F6_JOURNAL_KIND {
                return Err(EngineError::ForeignRecord);
            }
            out.push(entry.payload);
        }
        Ok(out)
    }
}

/// The driver: the pure ledger plus a durable history.
pub struct DurableBinding<L: BindingLog> {
    log: L,
    ledger: BindingLedgerV1,
    revision: u64,
}

impl<L: BindingLog> DurableBinding<L> {
    /// Opens the engine over `log`, replaying every frame through the
    /// pure ledger. Any irregularity fails closed.
    pub fn open(log: L) -> Result<Self> {
        let frames = log.frames()?;
        if frames.len() > MAX_JOURNAL_FRAMES {
            return Err(EngineError::JournalTooLarge);
        }
        let mut ledger = BindingLedgerV1::new();
        for (index, frame) in frames.iter().enumerate() {
            let (revision, event) = decode_frame(frame)?;
            if revision != index as u64 {
                return Err(EngineError::RevisionGap);
            }
            ledger
                .apply(&event)
                .map_err(EngineError::ReplayDivergence)?;
        }
        Ok(Self {
            revision: frames.len() as u64,
            log,
            ledger,
        })
    }

    /// The replayed ledger.
    pub fn ledger(&self) -> &BindingLedgerV1 {
        &self.ledger
    }

    /// Frames appended so far.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Applies one event: pure decision first — a refusal appends
    /// nothing — then the durable append, and only then the state
    /// advance (append-before-effects).
    pub fn apply(&mut self, event: &BindingEventV1) -> Result<()> {
        let mut next = self.ledger.clone();
        next.apply(event).map_err(EngineError::Refused)?;
        let frame = encode_frame(self.revision, event);
        self.log.append_frame(&frame)?;
        self.ledger = next;
        self.revision += 1;
        Ok(())
    }

    /// Build-order step 4: runs the REAL ratified selection
    /// (`rfq::selection::select_winner`) over the candidate book, with
    /// each candidate's reservation fact attested by THIS ledger, and
    /// journals the outcome as one `Selected` frame. A selection error
    /// appends nothing; a second selection for the RFQ refuses.
    pub fn select_and_record(
        &mut self,
        rfq: &RfqV1,
        candidates: &[(QuoteV1, CandidateFactsV1)],
        dom_chain_id: ChainId,
        now: TimelockSpec,
    ) -> Result<SelectionOutcomeV1> {
        let attested: Vec<(QuoteV1, CandidateFactsV1)> = candidates
            .iter()
            .map(|(quote, facts)| {
                let mut attested_facts = *facts;
                attested_facts.bond_reserved_exclusive = self.ledger.reservation_backs(
                    &quote.bond_reservation_id,
                    &rfq.rfq_id,
                    &quote.quote_id,
                    &quote.solver,
                );
                (*quote, attested_facts)
            })
            .collect();
        let outcome =
            select_winner(rfq, &attested, dom_chain_id, now).map_err(EngineError::Selection)?;
        self.apply(&BindingEventV1::Selected {
            rfq_id: outcome.selection.rfq_id,
            winning_quote: outcome.selection.winning_quote,
            inputs_digest: outcome.selection.inputs_digest,
        })?;
        Ok(outcome)
    }

    /// The §4.2 atomic binding of a selected quote, in the ratified
    /// order: (1) deterministic validation — full §4.1 admissibility of
    /// the winner is re-run here, with the reservation fact taken from
    /// THIS ledger, never from the caller's word; (2) the exclusive
    /// reservation is consumed; (3) acceptance; (4) the `terms_hash`;
    /// (5) persistence — all committed as ONE frame. A crash leaves
    /// either no binding or the whole binding.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_selected(
        &mut self,
        rfq: &RfqV1,
        quote: &QuoteV1,
        facts: &CandidateFactsV1,
        dom_chain_id: ChainId,
        now: TimelockSpec,
        refund_deadlines: [TimelockSpec; ROUTE_LEGS],
        payout_commitments: [Digest32; ROUTE_LEGS],
        accepted_by: ParticipantId,
    ) -> Result<AcceptanceV1> {
        // (1) Validation. The reservation attestation comes from the
        // ledger itself: a caller cannot talk this engine into binding
        // an unreserved quote.
        let mut attested = *facts;
        attested.bond_reserved_exclusive = self.ledger.reservation_backs(
            &quote.bond_reservation_id,
            &rfq.rfq_id,
            &quote.quote_id,
            &quote.solver,
        );
        admissibility(rfq, quote, &attested, dom_chain_id, now)
            .map_err(EngineError::Inadmissible)?;
        // (4) The ratified terms hash (assembly re-checks rfq/quote
        // correspondence and the timelock domain, A4).
        let binding = TermsBindingV1::from_parts(rfq, quote, refund_deadlines, payout_commitments)
            .map_err(EngineError::Terms)?;
        let terms_hash = binding.terms_hash().map_err(EngineError::Terms)?;
        // (2)+(3)+(5) One journaled transition.
        self.apply(&BindingEventV1::Bound {
            rfq_id: rfq.rfq_id,
            quote_id: quote.quote_id,
            solver: quote.solver,
            accepted_by,
            reservation_id: quote.bond_reservation_id,
            terms_hash,
        })?;
        Ok(AcceptanceV1 {
            terms_hash,
            rfq_id: rfq.rfq_id,
            quote_id: quote.quote_id,
            accepted_by,
        })
    }
}

/// §4.2 step 5: the binding exists only when BOTH parties hold it
/// durably. `Ok(true)` — both hold the SAME binding; `Ok(false)` — at
/// least one side does not hold it yet (a crash between the two
/// persists is visible here, not hidden); `Err(BindingDivergence)` —
/// the sides hold DIFFERENT bindings, which is an equivocation and
/// fails closed.
pub fn binding_complete<A: BindingLog, B: BindingLog>(
    a: &DurableBinding<A>,
    b: &DurableBinding<B>,
    rfq_id: &Digest32,
) -> Result<bool> {
    match (a.ledger().binding(rfq_id), b.ledger().binding(rfq_id)) {
        (Some(x), Some(y)) if x == y => Ok(true),
        (Some(_), Some(_)) => Err(EngineError::BindingDivergence),
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rfq::{
        AssetId, FeeLimitV1, LegDirectionV1, PolicyId, RfqModeV1, RouteLegV1, RouteV1,
        TimelockDomainV1,
    };

    const DOM: ChainId = ChainId([0xD0; 32]);

    fn ts(value: u64) -> TimelockSpec {
        TimelockSpec::TimestampSeconds { value }
    }

    fn b32(x: u8) -> [u8; 32] {
        [x; 32]
    }

    fn dom_route() -> RouteV1 {
        RouteV1 {
            legs: [
                RouteLegV1 {
                    chain_id: DOM,
                    asset: AssetId(b32(0x12)),
                    direction: LegDirectionV1::UserGives,
                },
                RouteLegV1 {
                    chain_id: ChainId([0xE7; 32]),
                    asset: AssetId(b32(0x22)),
                    direction: LegDirectionV1::UserReceives,
                },
            ],
        }
    }

    fn sample_rfq() -> RfqV1 {
        RfqV1::create(
            ParticipantId(b32(0x31)),
            dom_route(),
            RfqModeV1::ExactIn {
                input_amount: 100,
                minimum_output: 90,
            },
            FeeLimitV1 {
                dom_max: 5,
                counterparty_max: 5,
            },
            TimelockDomainV1::TimestampSeconds,
            ts(1_000),
            PolicyId(b32(0x41)),
            1,
            b32(0x51),
        )
        .unwrap()
    }

    fn sample_quote(rfq: &RfqV1, reservation: u8) -> QuoteV1 {
        QuoteV1::create(
            rfq.rfq_id,
            ParticipantId(b32(0x61)),
            rfq.route,
            95,
            100,
            4,
            ts(2_000),
            b32(reservation),
            1,
            ts(1_500),
            [reservation; 64],
        )
        .unwrap()
    }

    fn facts() -> CandidateFactsV1 {
        CandidateFactsV1 {
            solver_registered: true,
            signature_valid: true,
            bond_reserved_exclusive: true,
            exposure_covered: true,
            coverage_excess: 0,
            solver_active: true,
            policy_version_accepted: true,
        }
    }

    fn reserve_event(rfq: &RfqV1, quote: &QuoteV1) -> BindingEventV1 {
        BindingEventV1::Reserved {
            reservation_id: quote.bond_reservation_id,
            rfq_id: rfq.rfq_id,
            quote_id: quote.quote_id,
            solver: quote.solver,
        }
    }

    fn select_event(rfq: &RfqV1, winner: &QuoteV1) -> BindingEventV1 {
        BindingEventV1::Selected {
            rfq_id: rfq.rfq_id,
            winning_quote: winner.quote_id,
            inputs_digest: b32(0xAA),
        }
    }

    #[test]
    fn frame_roundtrip_and_frozen_vector() {
        let rfq = sample_rfq();
        let quote = sample_quote(&rfq, 0x71);
        let event = BindingEventV1::Bound {
            rfq_id: rfq.rfq_id,
            quote_id: quote.quote_id,
            solver: quote.solver,
            accepted_by: ParticipantId(b32(0x31)),
            reservation_id: quote.bond_reservation_id,
            terms_hash: b32(0x99),
        };
        let frame = encode_frame(7, &event);
        assert_eq!(&frame[..10], b"DOMIF6J1\x00\x01");
        assert_eq!(frame.len(), 8 + 2 + 8 + 1 + 32 * 6);
        assert_eq!(decode_frame(&frame).unwrap(), (7, event));
        // Single-byte corruption never decodes into a DIFFERENT valid
        // frame silently: it either fails or flips exactly the touched
        // field, and magic/version/tag corruption always fails.
        for i in 0..11 {
            let mut flipped = frame.clone();
            flipped[i] ^= 0x01;
            if i < 10 {
                assert!(decode_frame(&flipped).is_err(), "byte {i}");
            }
        }
        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(decode_frame(&trailing).is_err());
    }

    #[test]
    fn exclusivity_is_enforced_by_name() {
        let rfq = sample_rfq();
        let quote_a = sample_quote(&rfq, 0x71);
        let mut ledger = BindingLedgerV1::new();
        ledger.apply(&reserve_event(&rfq, &quote_a)).unwrap();

        // The same reservation for a second quote: double-commitment.
        let quote_b = sample_quote(&rfq, 0x72);
        let double = BindingEventV1::Reserved {
            reservation_id: quote_a.bond_reservation_id,
            rfq_id: rfq.rfq_id,
            quote_id: quote_b.quote_id,
            solver: quote_b.solver,
        };
        assert_eq!(
            ledger.apply(&double).unwrap_err(),
            BindingRefusal::ReservationInUse
        );

        // Released is spent forever.
        ledger
            .apply(&BindingEventV1::Released {
                reservation_id: quote_a.bond_reservation_id,
            })
            .unwrap();
        assert_eq!(
            ledger.apply(&reserve_event(&rfq, &quote_a)).unwrap_err(),
            BindingRefusal::ReservationSpent
        );
    }

    #[test]
    fn binding_requires_selection_and_the_exact_reservation() {
        let rfq = sample_rfq();
        let quote = sample_quote(&rfq, 0x71);
        let other = sample_quote(&rfq, 0x72);
        let mut ledger = BindingLedgerV1::new();
        ledger.apply(&reserve_event(&rfq, &quote)).unwrap();

        let bind_quote = BindingEventV1::Bound {
            rfq_id: rfq.rfq_id,
            quote_id: quote.quote_id,
            solver: quote.solver,
            accepted_by: ParticipantId(b32(0x31)),
            reservation_id: quote.bond_reservation_id,
            terms_hash: b32(0x99),
        };

        // Step-4 rule: no binding without the journaled selection.
        assert_eq!(
            ledger.apply(&bind_quote).unwrap_err(),
            BindingRefusal::BindWithoutSelection
        );
        ledger.apply(&select_event(&rfq, &quote)).unwrap();

        // A second selection is an equivocation.
        assert_eq!(
            ledger.apply(&select_event(&rfq, &other)).unwrap_err(),
            BindingRefusal::RfqAlreadySelected
        );

        // Binding a quote other than the recorded winner.
        let non_winner = BindingEventV1::Bound {
            rfq_id: rfq.rfq_id,
            quote_id: other.quote_id,
            solver: other.solver,
            accepted_by: ParticipantId(b32(0x31)),
            reservation_id: quote.bond_reservation_id,
            terms_hash: b32(0x99),
        };
        assert_eq!(
            ledger.apply(&non_winner).unwrap_err(),
            BindingRefusal::SelectionQuoteMismatch
        );

        // Unknown reservation.
        let unknown = BindingEventV1::Bound {
            rfq_id: rfq.rfq_id,
            quote_id: quote.quote_id,
            solver: quote.solver,
            accepted_by: ParticipantId(b32(0x31)),
            reservation_id: b32(0xEE),
            terms_hash: b32(0x99),
        };
        assert_eq!(
            ledger.apply(&unknown).unwrap_err(),
            BindingRefusal::ReservationUnknown
        );

        // The winner consuming a reservation committed to ANOTHER
        // quote is refused by the reservation check.
        let mut cross = BindingLedgerV1::new();
        cross.apply(&reserve_event(&rfq, &other)).unwrap();
        cross.apply(&select_event(&rfq, &quote)).unwrap();
        let cross_bind = BindingEventV1::Bound {
            rfq_id: rfq.rfq_id,
            quote_id: quote.quote_id,
            solver: quote.solver,
            accepted_by: ParticipantId(b32(0x31)),
            reservation_id: other.bond_reservation_id,
            terms_hash: b32(0x99),
        };
        assert_eq!(
            cross.apply(&cross_bind).unwrap_err(),
            BindingRefusal::ReservationQuoteMismatch
        );

        // A holder mismatch is refused even with the right quote id.
        let mut wrong_holder_ledger = BindingLedgerV1::new();
        wrong_holder_ledger
            .apply(&BindingEventV1::Reserved {
                reservation_id: quote.bond_reservation_id,
                rfq_id: rfq.rfq_id,
                quote_id: quote.quote_id,
                solver: ParticipantId(b32(0x77)),
            })
            .unwrap();
        wrong_holder_ledger
            .apply(&select_event(&rfq, &quote))
            .unwrap();
        assert_eq!(
            wrong_holder_ledger.apply(&bind_quote).unwrap_err(),
            BindingRefusal::ReservationHolderMismatch
        );
    }

    #[test]
    fn one_binding_per_rfq() {
        let rfq = sample_rfq();
        let quote = sample_quote(&rfq, 0x71);
        let second = sample_quote(&rfq, 0x72);
        let mut ledger = BindingLedgerV1::new();
        ledger.apply(&reserve_event(&rfq, &quote)).unwrap();
        ledger.apply(&reserve_event(&rfq, &second)).unwrap();
        ledger.apply(&select_event(&rfq, &quote)).unwrap();
        let bind = |q: &QuoteV1| BindingEventV1::Bound {
            rfq_id: rfq.rfq_id,
            quote_id: q.quote_id,
            solver: q.solver,
            accepted_by: ParticipantId(b32(0x31)),
            reservation_id: q.bond_reservation_id,
            terms_hash: b32(0x99),
        };
        ledger.apply(&bind(&quote)).unwrap();
        assert_eq!(
            ledger.apply(&bind(&second)).unwrap_err(),
            BindingRefusal::RfqAlreadyBound
        );
    }

    #[test]
    fn atomic_bind_appends_nothing_on_refusal() {
        let rfq = sample_rfq();
        let quote = sample_quote(&rfq, 0x71);
        let mut engine = DurableBinding::open(MemoryLog::new()).unwrap();

        // No reservation in the ledger: the engine's OWN attestation
        // overrides the caller's claim and the bind refuses with
        // nothing appended.
        let err = engine
            .bind_selected(
                &rfq,
                &quote,
                &facts(),
                DOM,
                ts(500),
                [ts(3_000), ts(4_000)],
                [b32(0x81), b32(0x82)],
                ParticipantId(b32(0x31)),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            EngineError::Inadmissible(AdmissibilityRefusal::BondNotReserved)
        ));
        assert_eq!(engine.revision(), 0, "a refusal appends nothing");

        // Reserve, select (through the REAL ratified selection), then
        // bind: three frames, each the commit of its own decision.
        engine.apply(&reserve_event(&rfq, &quote)).unwrap();
        let outcome = engine
            .select_and_record(&rfq, &[(quote, facts())], DOM, ts(500))
            .unwrap();
        assert_eq!(outcome.selection.winning_quote, quote.quote_id);
        let acceptance = engine
            .bind_selected(
                &rfq,
                &quote,
                &facts(),
                DOM,
                ts(500),
                [ts(3_000), ts(4_000)],
                [b32(0x81), b32(0x82)],
                ParticipantId(b32(0x31)),
            )
            .unwrap();
        assert_eq!(engine.revision(), 3);
        let record = engine.ledger().binding(&rfq.rfq_id).unwrap();
        assert_eq!(record.terms_hash, acceptance.terms_hash);
        assert_eq!(record.quote_id, quote.quote_id);
    }

    #[test]
    fn crash_at_every_transition_replays_identically_on_real_sqlite() {
        let rfq = sample_rfq();
        let quote = sample_quote(&rfq, 0x71);
        let loser = sample_quote(&rfq, 0x72);
        let events = [
            reserve_event(&rfq, &quote),
            reserve_event(&rfq, &loser),
            select_event(&rfq, &quote),
            BindingEventV1::Bound {
                rfq_id: rfq.rfq_id,
                quote_id: quote.quote_id,
                solver: quote.solver,
                accepted_by: ParticipantId(b32(0x31)),
                reservation_id: quote.bond_reservation_id,
                terms_hash: b32(0x99),
            },
            BindingEventV1::Released {
                reservation_id: loser.bond_reservation_id,
            },
        ];
        // A crash after k committed frames: reopening replays exactly
        // the reference ledger of the first k events, for EVERY k.
        for k in 0..=events.len() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("f6.sqlite");
            {
                let mut engine = DurableBinding::open(StoreLog::open(&path).unwrap()).unwrap();
                for event in &events[..k] {
                    engine.apply(event).unwrap();
                }
                // The engine is dropped here: the crash boundary.
            }
            let reopened = DurableBinding::open(StoreLog::open(&path).unwrap()).unwrap();
            let mut reference = BindingLedgerV1::new();
            for event in &events[..k] {
                reference.apply(event).unwrap();
            }
            assert_eq!(reopened.ledger(), &reference, "k={k}");
            assert_eq!(reopened.revision(), k as u64, "k={k}");
        }
    }

    #[test]
    fn selection_is_ledger_attested_and_journaled() {
        let rfq = sample_rfq();
        let quote = sample_quote(&rfq, 0x71);
        let mut engine = DurableBinding::open(MemoryLog::new()).unwrap();

        // No reservation in the ledger: the attested facts refuse every
        // candidate and the selection appends nothing.
        let err = engine
            .select_and_record(&rfq, &[(quote, facts())], DOM, ts(500))
            .unwrap_err();
        assert!(matches!(
            err,
            EngineError::Selection(rfq::selection::SelectionError::NoAdmissibleQuote)
        ));
        assert_eq!(engine.revision(), 0);

        // Reserved: the selection records and survives replay.
        engine.apply(&reserve_event(&rfq, &quote)).unwrap();
        let outcome = engine
            .select_and_record(&rfq, &[(quote, facts())], DOM, ts(500))
            .unwrap();
        assert_eq!(
            engine
                .ledger()
                .selection(&rfq.rfq_id)
                .map(|s| s.winning_quote),
            Some(outcome.selection.winning_quote)
        );

        // A second selection refuses (equivocation), appending nothing.
        let before = engine.revision();
        assert!(matches!(
            engine
                .select_and_record(&rfq, &[(quote, facts())], DOM, ts(500))
                .unwrap_err(),
            EngineError::Refused(BindingRefusal::RfqAlreadySelected)
        ));
        assert_eq!(engine.revision(), before);
    }

    #[test]
    fn foreign_kind_and_tampered_history_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f6.sqlite");
        {
            let mut raw = store::Store::open(&path).unwrap();
            raw.append_journal(0xBEEF, b"not ours").unwrap();
        }
        assert!(matches!(
            DurableBinding::open(StoreLog::open(&path).unwrap()),
            Err(EngineError::ForeignRecord)
        ));

        // A revision gap fails closed too.
        let dir2 = tempfile::tempdir().unwrap();
        let path2 = dir2.path().join("f6.sqlite");
        {
            let mut raw = store::Store::open(&path2).unwrap();
            let rfq = sample_rfq();
            let quote = sample_quote(&rfq, 0x71);
            let frame = encode_frame(3, &reserve_event(&rfq, &quote));
            raw.append_journal(F6_JOURNAL_KIND, &frame).unwrap();
        }
        assert!(matches!(
            DurableBinding::open(StoreLog::open(&path2).unwrap()),
            Err(EngineError::RevisionGap)
        ));
    }

    #[test]
    fn both_parties_completion_and_divergence() {
        let rfq = sample_rfq();
        let quote = sample_quote(&rfq, 0x71);
        let mut a = DurableBinding::open(MemoryLog::new()).unwrap();
        let mut b = DurableBinding::open(MemoryLog::new()).unwrap();
        let bind_on = |engine: &mut DurableBinding<MemoryLog>, terms: [u8; 32]| {
            engine.apply(&reserve_event(&rfq, &quote)).unwrap();
            engine.apply(&select_event(&rfq, &quote)).unwrap();
            engine
                .apply(&BindingEventV1::Bound {
                    rfq_id: rfq.rfq_id,
                    quote_id: quote.quote_id,
                    solver: quote.solver,
                    accepted_by: ParticipantId(b32(0x31)),
                    reservation_id: quote.bond_reservation_id,
                    terms_hash: terms,
                })
                .unwrap();
        };

        // Crash between the two persists: visible as incomplete.
        bind_on(&mut a, b32(0x99));
        assert!(!binding_complete(&a, &b, &rfq.rfq_id).unwrap());

        // Both persisted the same binding: complete.
        bind_on(&mut b, b32(0x99));
        assert!(binding_complete(&a, &b, &rfq.rfq_id).unwrap());

        // Divergent terms on the two sides: equivocation, fail closed.
        let mut c = DurableBinding::open(MemoryLog::new()).unwrap();
        bind_on(&mut c, b32(0x98));
        assert!(matches!(
            binding_complete(&a, &c, &rfq.rfq_id),
            Err(EngineError::BindingDivergence)
        ));
    }
}
