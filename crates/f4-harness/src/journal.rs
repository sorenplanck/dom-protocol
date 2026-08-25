//! `DurableAssurance` — the persist-before-effect driver of F4 spec §9.
//!
//! One obligation, one log, one rule: an accepted transition's frame is
//! appended — and the append COMMITS — before its effects are handed to
//! the caller. The caller executes `AuthorizeRelease`/`ExecuteSlash`
//! through the `BondAdapter`, whose artifacts are deterministic and
//! byte-identical on resend (I7), so delivery after a crash needs no
//! delivery table here: recompute, offer, and the chain acknowledges the
//! duplicate.
//!
//! Recovery does not trust the log. Every frame is re-applied through
//! the REAL `uspe::assurance_transition`, and any disagreement — wrong
//! next state, wrong effects, a gap in revisions, a frame for another
//! obligation, a foreign record kind, bytes that do not decode — fails
//! closed. A forged or corrupted journal cannot resurrect a state the
//! machine would not have reached.
//!
//! The log substrate is the ratified `store` crate (SQLite WAL,
//! `synchronous = FULL`, ADR-A7) through the narrow [`AssuranceLog`]
//! trait, exactly the F3 outbox pattern: an in-memory log for the
//! offline suites, the durable one for everything else, identical
//! semantics.

use std::collections::BTreeMap;
use std::path::Path;

use uspe::journal::{AssuranceFrameV1, FrameError, ASSURANCE_JOURNAL_KIND, MAX_FRAME_BYTES};
use uspe::{
    assurance_transition, AssuranceContext, AssuranceError, AssuranceEvent, AssuranceTransition,
};

/// Largest number of frames one obligation's log will replay. The
/// longest real history is under a dozen accepted transitions; the cap
/// exists so a hostile log cannot drive unbounded allocation (I14).
pub const MAX_JOURNAL_FRAMES: usize = 4096;

/// Journal failures. Every variant is fail-closed.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The underlying log refused or failed.
    #[error("assurance log unavailable: {0}")]
    Log(String),
    /// A record under a kind other than [`ASSURANCE_JOURNAL_KIND`].
    #[error("foreign record in the assurance log")]
    ForeignRecord,
    /// A frame that does not decode.
    #[error("corrupt assurance frame: {0}")]
    CorruptFrame(#[from] FrameError),
    /// Frame revisions are not contiguous from 1.
    #[error("assurance journal gap")]
    RevisionGap,
    /// A frame bound to a different obligation's terms hash.
    #[error("assurance log bound to a different obligation")]
    LogBindingMismatch,
    /// Replay disagreed with the real machine: the logged transition is
    /// not one the machine performs from the logged history.
    #[error("assurance journal diverges from the machine")]
    ReplayDivergence,
    /// The log holds more frames than [`MAX_JOURNAL_FRAMES`].
    #[error("assurance journal bounds exceeded")]
    BoundsExceeded,
    /// The machine refused the live event (not a journal fault).
    #[error("assurance transition refused: {0}")]
    Transition(#[from] AssuranceError),
}

/// Alias for this module's fallible results.
pub type Result<T> = core::result::Result<T, JournalError>;

/// An append-only log of assurance frames: the whole durability contract
/// the driver needs, and no more.
pub trait AssuranceLog {
    /// Appends one frame durably. On return the frame must survive a
    /// crash (the durable impl commits before returning).
    fn append_frame(&mut self, frame: &[u8]) -> Result<()>;

    /// Every frame, in append order.
    fn frames(&self) -> Result<Vec<Vec<u8>>>;
}

/// In-memory log for the offline suites. Same semantics, no durability.
#[derive(Default)]
pub struct MemoryLog {
    frames: Vec<Vec<u8>>,
}

impl MemoryLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }
}

impl AssuranceLog for MemoryLog {
    fn append_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.frames.push(frame.to_vec());
        Ok(())
    }

    fn frames(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.frames.clone())
    }
}

/// The durable log: the ratified `store` crate, holding assurance frames
/// under [`ASSURANCE_JOURNAL_KIND`] and nothing else. Its own instance —
/// never shared with a settlement engine's store or an F3 outbox log.
pub struct StoreLog {
    store: store::Store,
}

impl StoreLog {
    /// Opens (or creates) the log at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let store = store::Store::open(path).map_err(|e| JournalError::Log(e.to_string()))?;
        Ok(Self { store })
    }
}

impl AssuranceLog for StoreLog {
    fn append_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.store
            .append_journal(ASSURANCE_JOURNAL_KIND, frame)
            .map(|_| ())
            .map_err(|e| JournalError::Log(e.to_string()))
    }

    fn frames(&self) -> Result<Vec<Vec<u8>>> {
        let entries = self
            .store
            .read_journal()
            .map_err(|e| JournalError::Log(e.to_string()))?;
        let mut out = Vec::with_capacity(entries.len().min(MAX_JOURNAL_FRAMES));
        for entry in entries {
            // The assurance log holds assurance frames and nothing else.
            // A foreign kind is corruption or misuse, never skippable.
            if entry.kind != ASSURANCE_JOURNAL_KIND {
                return Err(JournalError::ForeignRecord);
            }
            out.push(entry.payload);
        }
        Ok(out)
    }
}

/// The driver: the pure machine plus a durable history.
pub struct DurableAssurance<L: AssuranceLog> {
    log: L,
    context: AssuranceContext,
    revision: u64,
}

impl<L: AssuranceLog> DurableAssurance<L> {
    /// Opens the obligation's assurance state by replaying `log` from the
    /// policy-derived initial context. Fails closed on any divergence —
    /// see the module docs.
    pub fn open(
        log: L,
        terms_hash: [u8; 32],
        compensation_cap: u128,
        bond_required: bool,
    ) -> Result<Self> {
        let mut context = AssuranceContext::new(terms_hash, compensation_cap, bond_required);
        let raw = log.frames()?;
        if raw.len() > MAX_JOURNAL_FRAMES {
            return Err(JournalError::BoundsExceeded);
        }
        // Deduplicate nothing, trust nothing: decode, check the chain of
        // revisions, re-apply every event through the real machine and
        // require byte-level agreement on what it did.
        let mut revision = 0u64;
        let mut seen: BTreeMap<u64, ()> = BTreeMap::new();
        for bytes in raw {
            if bytes.len() > MAX_FRAME_BYTES {
                return Err(JournalError::CorruptFrame(FrameError::BoundsExceeded));
            }
            let frame = AssuranceFrameV1::decode(&bytes)?;
            if frame.terms_hash != terms_hash {
                return Err(JournalError::LogBindingMismatch);
            }
            if frame.revision != revision + 1 || seen.contains_key(&frame.revision) {
                return Err(JournalError::RevisionGap);
            }
            let applied = assurance_transition(context, &frame.event).map_err(|_| {
                // The machine refuses an event the log claims it
                // accepted: the log lies.
                JournalError::ReplayDivergence
            })?;
            if applied.next.state != frame.next_state || applied.effects != frame.effects {
                return Err(JournalError::ReplayDivergence);
            }
            seen.insert(frame.revision, ());
            context = applied.next;
            revision = frame.revision;
        }
        Ok(Self {
            log,
            context,
            revision,
        })
    }

    /// Current context (state, binding, cap).
    pub fn context(&self) -> AssuranceContext {
        self.context
    }

    /// Frames appended so far.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Applies one event: pure transition, then the frame is appended —
    /// and committed — BEFORE the effects are returned. A refused event
    /// appends nothing.
    pub fn apply(&mut self, event: &AssuranceEvent) -> Result<AssuranceTransition> {
        let applied = assurance_transition(self.context, event)?;
        let frame = AssuranceFrameV1 {
            revision: self.revision + 1,
            terms_hash: self.context.terms_hash,
            event: event.clone(),
            next_state: applied.next.state,
            effects: applied.effects.clone(),
        };
        let bytes = frame.canonical_bytes()?;
        self.log.append_frame(&bytes)?;
        // Only after the durable append: the state advances and the
        // effects leave. Crash before this line = the event was never
        // accepted; crash after = recovery replays the frame.
        self.context = applied.next;
        self.revision = frame.revision;
        Ok(applied)
    }
}
