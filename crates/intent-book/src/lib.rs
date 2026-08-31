//! # intent-book
//!
//! The DOM intent board — INTENT_BOOK_DESIGN.md. **NOT RATIFIED.**
//!
//! This is **not** an order book: there is no resting order under custody
//! and no on-chain matching ("Isto NÃO é um order book […] É uma vitrine de
//! intenções cujo aceite continua sendo o fluxo RFQ. I1 intacto"). The
//! board is a visibility policy over the ratified RFQ flow.
//!
//! ## The cascade (design: "A cascata solver → livro [DECIDIDO]")
//!
//! 1. **Phase 1 — the solver window, 120 seconds.** Only registered
//!    professional solvers are notified.
//! 2. **Phase 2 — the public board.** Without acceptance in the window the
//!    intent publishes to everyone, and *"as cotações da fase 1 continuam
//!    válidas e competem com as novas, sob a mesma seleção ratificada"*.
//!
//! Invariants this crate enforces, quoted from the design:
//!
//! - **same content in both phases** — "A fase 1 não vê nada que a fase 2
//!   não veja — a vantagem é de tempo, nunca de informação". The board
//!   returns the identical [`IntentV1`] in both phases; only the audience
//!   differs.
//! - **quotes accumulate, never expire on a phase change** — "Só o
//!   `expiry` da própria cotação e o `quote_deadline` da intenção mandam".
//! - **one selection** — `select_winner` over EVERY admissible candidate
//!   from any phase. This crate never re-implements admissibility or
//!   ranking; it calls `rfq`.
//!
//! ## Transport (operator decision OQ-S3)
//!
//! The Relay V1 message-kind registry is CLOSED by D-019 (measured at
//! `crates/relay/src/auth.rs:297,341,375`: `RFQ | QUOTE | ACCEPTANCE |
//! SELECTION | ROUTE_TRANSPORT`, with the Solver role limited to `QUOTE |
//! ROUTE_TRANSPORT`). There is no INTENT kind and none is added: this crate
//! is a service beside the relay with its own edge, and the public phase
//! bridges into the existing RFQ flow using only those five ratified kinds.
//! Nothing here depends on `relay`.
//!
//! ## Identity (design: "Sem identificação [DECIDIDO]")
//!
//! The board carries no name, no handle, no "who" field. A negotiation is
//! addressed by an ephemeral key ([`NegotiationKey`]) that the wallet
//! derives fresh and discards; the board stores it opaquely and never links
//! two negotiations. `operator_mode` is the opt-in exception.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod config;
pub mod merit;
pub mod wire;

use kaystra_core::types::{Digest32, ParticipantId};
use merit::MeritLedger;
use rfq::selection::{select_winner, CandidateFactsV1, SelectionError, SelectionOutcomeV1};
use rfq::{QuoteV1, RfqV1};
use std::collections::BTreeMap;
use thiserror::Error;
use wire::{IntentError, IntentV1, NegotiationKey};

/// The ratified phase-1 duration — design: "janela dos solvers, 120
/// segundos", stated as a fixed product rule with no user bypass ("Regra
/// fixa do produto, sem opção de contorno pelo usuário").
pub const SOLVER_WINDOW_SECONDS: u64 = 120;

/// Which phase of the cascade an intent is in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PhaseV1 {
    /// Only privileged solvers are notified.
    PrivateSolverWindow,
    /// The intent is on the public board.
    PublicBoard,
}

/// Why the board refuses an operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum BoardRefusal {
    /// The intent failed structural or cross-object validation.
    #[error("malformed intent: {0}")]
    MalformedIntent(IntentError),
    /// No intent with that identifier.
    #[error("unknown intent")]
    UnknownIntent,
    /// An intent with that identifier already exists.
    #[error("duplicate intent")]
    DuplicateIntent,
    /// The quote names a different intent than the one addressed.
    #[error("quote does not answer this intent")]
    QuoteIntentMismatch,
    /// The quote arrived after the intent's own `quote_deadline`.
    ///
    /// Note the design invariant: a phase CHANGE never expires a quote —
    /// only the quote's own expiry and the intent's `quote_deadline` do.
    #[error("quote arrived after the intent deadline")]
    QuoteAfterDeadline,
    /// A non-privileged party tried to quote during the private window.
    #[error("solver is not privileged for the phase-1 window")]
    NotPrivilegedInWindow,
    /// The intent is already settled or withdrawn.
    #[error("intent is closed")]
    IntentClosed,
    /// Selection refused; the ratified reason is carried by `rfq`.
    #[error("selection refused")]
    Selection(SelectionError),
}

/// One quote as the board holds it: the ratified object plus the phase it
/// arrived in, which is bookkeeping for the merit ledger and never an input
/// to selection.
#[derive(Clone, Debug)]
pub struct BoardQuoteV1 {
    /// The ratified quote.
    pub quote: QuoteV1,
    /// The facts the F4/roster oracles assert about this quote.
    pub facts: CandidateFactsV1,
    /// The phase in which it arrived.
    pub arrived_in: PhaseV1,
    /// UNIX seconds of arrival.
    pub arrived_at_seconds: u64,
}

/// An intent as the board holds it.
#[derive(Clone, Debug)]
struct BoardEntry {
    intent: IntentV1,
    quotes: Vec<BoardQuoteV1>,
    closed: bool,
}

/// The intent board.
///
/// Time is supplied by the caller at every operation; the board keeps no
/// clock of its own, so its behaviour is reproducible and testable.
#[derive(Clone, Debug)]
pub struct IntentBoardV1 {
    entries: BTreeMap<Digest32, BoardEntry>,
    merit: MeritLedger,
    operator_mode: bool,
}

impl IntentBoardV1 {
    /// Start the board over an explicit merit ledger.
    ///
    /// There is no constructor that invents a merit policy: the ledger is
    /// built from [`config::MeritPolicyV1::new`], which refuses to exist
    /// without operator values (fail-closed, OQ-S4).
    pub fn new(merit: MeritLedger) -> Self {
        Self {
            entries: BTreeMap::new(),
            merit,
            operator_mode: false,
        }
    }

    /// Opt in to operator mode — design: reputation is opt-in and off by
    /// default, since the board otherwise carries no identity.
    pub fn with_operator_mode(mut self, enabled: bool) -> Self {
        self.operator_mode = enabled;
        self
    }

    /// Whether operator mode is on.
    pub fn operator_mode(&self) -> bool {
        self.operator_mode
    }

    /// The merit ledger, so the privileged list and its inputs are
    /// inspectable ("Medição publicada e auditável").
    pub fn merit(&self) -> &MeritLedger {
        &self.merit
    }

    /// Mutable access for recording responses and executions.
    pub fn merit_mut(&mut self) -> &mut MeritLedger {
        &mut self.merit
    }

    /// Publish an intent. Phase 1 starts at `intent.published_at_seconds`.
    pub fn publish(&mut self, intent: IntentV1) -> Result<(), BoardRefusal> {
        intent.validate().map_err(BoardRefusal::MalformedIntent)?;
        if self.entries.contains_key(&intent.intent_id) {
            return Err(BoardRefusal::DuplicateIntent);
        }
        self.entries.insert(
            intent.intent_id,
            BoardEntry {
                intent,
                quotes: Vec::new(),
                closed: false,
            },
        );
        Ok(())
    }

    /// The phase of an intent at `now_seconds`.
    ///
    /// The boundary is exclusive on the window side: at exactly
    /// `solver_window_end` the public board is open, so a 120-second window
    /// lasts 120 seconds and not one second more.
    pub fn phase_at(
        &self,
        intent_id: &Digest32,
        now_seconds: u64,
    ) -> Result<PhaseV1, BoardRefusal> {
        let entry = self
            .entries
            .get(intent_id)
            .ok_or(BoardRefusal::UnknownIntent)?;
        Ok(if now_seconds < entry.intent.solver_window_end_seconds() {
            PhaseV1::PrivateSolverWindow
        } else {
            PhaseV1::PublicBoard
        })
    }

    /// The intent as seen by an audience.
    ///
    /// Returns the SAME object in both phases — the phase-1 advantage is
    /// time, never information. During the private window a non-privileged
    /// caller sees nothing at all; the content it would see later is
    /// unchanged.
    pub fn view(
        &self,
        intent_id: &Digest32,
        viewer: Option<&ParticipantId>,
        now_seconds: u64,
    ) -> Result<Option<&IntentV1>, BoardRefusal> {
        let entry = self
            .entries
            .get(intent_id)
            .ok_or(BoardRefusal::UnknownIntent)?;
        match self.phase_at(intent_id, now_seconds)? {
            PhaseV1::PublicBoard => Ok(Some(&entry.intent)),
            PhaseV1::PrivateSolverWindow => {
                let privileged = viewer
                    .map(|v| self.merit.verdict(v, now_seconds).privileged)
                    .unwrap_or(false);
                Ok(if privileged {
                    Some(&entry.intent)
                } else {
                    None
                })
            }
        }
    }

    /// The intents visible on the public board at `now_seconds`.
    pub fn public_board(&self, now_seconds: u64) -> Vec<&IntentV1> {
        self.entries
            .values()
            .filter(|entry| {
                !entry.closed && now_seconds >= entry.intent.solver_window_end_seconds()
            })
            .map(|entry| &entry.intent)
            .collect()
    }

    /// Submit a quote.
    ///
    /// During the private window only a privileged solver may quote. In
    /// either phase the quote must answer this intent and arrive on or
    /// before the intent's `quote_deadline`. The arrival is recorded in the
    /// merit ledger when it lands in phase 1, which is what feeds the
    /// maintenance metric.
    pub fn submit_quote(
        &mut self,
        intent_id: &Digest32,
        quote: QuoteV1,
        facts: CandidateFactsV1,
        now_seconds: u64,
    ) -> Result<PhaseV1, BoardRefusal> {
        let phase = self.phase_at(intent_id, now_seconds)?;
        let solver = quote.solver;
        let privileged = self.merit.verdict(&solver, now_seconds).privileged;
        let entry = self
            .entries
            .get_mut(intent_id)
            .ok_or(BoardRefusal::UnknownIntent)?;
        if entry.closed {
            return Err(BoardRefusal::IntentClosed);
        }
        if quote.rfq_id != entry.intent.rfq.rfq_id {
            return Err(BoardRefusal::QuoteIntentMismatch);
        }
        if now_seconds > entry.intent.quote_deadline_seconds {
            return Err(BoardRefusal::QuoteAfterDeadline);
        }
        if phase == PhaseV1::PrivateSolverWindow && !privileged {
            return Err(BoardRefusal::NotPrivilegedInWindow);
        }
        entry.quotes.push(BoardQuoteV1 {
            quote,
            facts,
            arrived_in: phase,
            arrived_at_seconds: now_seconds,
        });
        if phase == PhaseV1::PrivateSolverWindow {
            let elapsed_millis = now_seconds
                .saturating_sub(entry.intent.published_at_seconds)
                .saturating_mul(1_000);
            self.merit.record_response(solver, elapsed_millis);
        }
        Ok(phase)
    }

    /// Every quote held for an intent, from any phase, in arrival order.
    pub fn quotes(&self, intent_id: &Digest32) -> Result<&[BoardQuoteV1], BoardRefusal> {
        Ok(&self
            .entries
            .get(intent_id)
            .ok_or(BoardRefusal::UnknownIntent)?
            .quotes)
    }

    /// Select the winner over EVERY accumulated candidate, of any phase.
    ///
    /// The board contributes no ranking of its own: it assembles the
    /// candidate set and hands it to the ratified `select_winner`. Quotes
    /// from phase 1 compete with phase-2 quotes under one selection, which
    /// is the design's third cascade invariant.
    pub fn select(
        &self,
        intent_id: &Digest32,
        dom_chain_id: kaystra_core::types::ChainId,
        now: kaystra_core::types::TimelockSpec,
    ) -> Result<SelectionOutcomeV1, BoardRefusal> {
        let entry = self
            .entries
            .get(intent_id)
            .ok_or(BoardRefusal::UnknownIntent)?;
        let candidates: Vec<(QuoteV1, CandidateFactsV1)> = entry
            .quotes
            .iter()
            .map(|held| (held.quote, held.facts))
            .collect();
        select_winner(&entry.intent.rfq, &candidates, dom_chain_id, now)
            .map_err(BoardRefusal::Selection)
    }

    /// Close an intent (accepted, withdrawn or expired).
    pub fn close(&mut self, intent_id: &Digest32) -> Result<(), BoardRefusal> {
        let entry = self
            .entries
            .get_mut(intent_id)
            .ok_or(BoardRefusal::UnknownIntent)?;
        entry.closed = true;
        Ok(())
    }

    /// The RFQ an intent carries, for the phase-2 bridge into the ratified
    /// flow. The bridge transmits it as the `RFQ` kind — one of the five
    /// D-019 kinds — with no board-specific message.
    pub fn rfq_for_bridge(&self, intent_id: &Digest32) -> Result<&RfqV1, BoardRefusal> {
        Ok(&self
            .entries
            .get(intent_id)
            .ok_or(BoardRefusal::UnknownIntent)?
            .intent
            .rfq)
    }

    /// The negotiation key of an intent — opaque to the board, never linked
    /// across intents.
    pub fn negotiation_key(&self, intent_id: &Digest32) -> Result<&NegotiationKey, BoardRefusal> {
        Ok(&self
            .entries
            .get(intent_id)
            .ok_or(BoardRefusal::UnknownIntent)?
            .intent
            .negotiation_key)
    }
}
