//! Output state machine (design §3) and the retention invariant **INV-RET**.
//!
//! The legal edges between [`OutputStatus`] states are the single source of
//! truth in [`OutputStatus::can_transition_to`]; every mutator routes through
//! it. The reconciler (sub-step 3B) is the only caller that will drive these
//! transitions from observed chain state — here we implement and unit-test the
//! transitions themselves.
//!
//! Transition map (design §3.1), grouped by the mutator that realizes it:
//!
//! | Mutator        | Transition IDs | Edges                                  |
//! |----------------|----------------|----------------------------------------|
//! | [`StoredOutput::confirm`]     | T1, T4, T6 | Unconfirmed/Spent/Reorged → Confirmed |
//! | [`StoredOutput::mark_spent`]  | T2, T7     | Confirmed/Reorged → Spent             |
//! | [`StoredOutput::mark_reorged`]| T3, T5     | Confirmed/Spent → Reorged             |
//!
//! `C0` (creation → `Unconfirmed`) is [`StoredOutput::new_unconfirmed`].
//! `D1` (the sole deletion) is gated by [`StoredOutput::can_delete`] and
//! performed at the store level — never by a status mutator.
//!
//! **INV-RET:** an output in `Confirmed`, `Spent`, or `Reorged` is never
//! deleted and never loses its `blinding`. No mutator here removes anything;
//! `can_transition_to` forbids any edge back into `Unconfirmed`, so once an
//! output becomes canonical it is tracked forever (only its status moves).

use crate::types::{BlockRef, OutputStatus, StoredOutput};
use thiserror::Error;

/// An illegal state transition was attempted. Returned instead of silently
/// mutating, so callers (and tests) can prove the machine rejects bad edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("illegal output transition {from:?} -> {to:?}")]
pub struct TransitionError {
    /// State the output was in.
    pub from: OutputStatus,
    /// State the transition tried to move it to.
    pub to: OutputStatus,
}

impl OutputStatus {
    /// The legal-edge table of the state machine (design §3.1). This is the one
    /// place that encodes which transitions exist; it also encodes INV-RET by
    /// admitting **no** edge whose target is `Unconfirmed`.
    pub fn can_transition_to(self, to: OutputStatus) -> bool {
        use OutputStatus::{Confirmed, Reorged, Spent, Unconfirmed};
        matches!(
            (self, to),
            // To Confirmed: T1 (from Unconfirmed), T4 (from Spent), T6 (from Reorged).
            (Unconfirmed, Confirmed)
                | (Spent, Confirmed)
                | (Reorged, Confirmed)
                // To Spent: T2 (from Confirmed), T7 (from Reorged).
                | (Confirmed, Spent)
                | (Reorged, Spent)
                // To Reorged: T3 (from Confirmed), T5 (from Spent).
                | (Confirmed, Reorged)
                | (Spent, Reorged)
        )
    }

    /// Merge precedence for the **non-destructive backup import** (design §2.7):
    /// `Unconfirmed < Reorged < Confirmed < Spent`. Higher rank = more advanced.
    ///
    /// This is a total order used **only** to decide, when a commitment exists
    /// in both the store and the backup, which status to keep — it is NOT the
    /// state-machine transition graph ([`can_transition_to`]). The import only
    /// ever *adopts a strictly higher* rank or keeps the current one; it never
    /// downgrades and never deletes (INV-RET). A stale backup therefore cannot
    /// revert the store — e.g. a current `Spent` (3) is kept against a backup's
    /// `Confirmed` (2). The mandatory post-import `reconcile` (§2.7) then
    /// re-establishes the chain-consistent status via legal transitions.
    pub fn merge_rank(self) -> u8 {
        match self {
            OutputStatus::Unconfirmed => 0,
            OutputStatus::Reorged => 1,
            OutputStatus::Confirmed => 2,
            OutputStatus::Spent => 3,
        }
    }
}

impl StoredOutput {
    /// Internal: validate against the legal-edge table, then move status and
    /// stamp `updated_at`. Never deletes, never touches `blinding`/`value`.
    fn set_status(&mut self, to: OutputStatus, now: u64) -> Result<(), TransitionError> {
        if !self.status.can_transition_to(to) {
            return Err(TransitionError {
                from: self.status,
                to,
            });
        }
        self.status = to;
        self.updated_at = now;
        Ok(())
    }

    /// Move the output to `Confirmed`, recording the confirming block.
    ///
    /// Realizes **T1** (`Unconfirmed`→`Confirmed`, first confirmation),
    /// **T4** (`Spent`→`Confirmed`, the spend reorged out) and
    /// **T6** (`Reorged`→`Confirmed`, the same tx was re-mined — kills
    /// WDSF-001). On T6 the `origin_block` is updated to the new block.
    pub fn confirm(&mut self, block: BlockRef, now: u64) -> Result<(), TransitionError> {
        self.set_status(OutputStatus::Confirmed, now)?;
        self.origin_block = Some(block);
        Ok(())
    }

    /// Move the output to `Spent` (its commitment became a canonical input).
    ///
    /// Realizes **T2** (`Confirmed`→`Spent`) and **T7** (`Reorged`→`Spent`,
    /// re-mined and already spent on the winning branch).
    pub fn mark_spent(&mut self, now: u64) -> Result<(), TransitionError> {
        self.set_status(OutputStatus::Spent, now)
    }

    /// Move the output to `Reorged` (its origin left the chain). Blinding and
    /// value are kept (INV-RET) for later re-mine recovery.
    ///
    /// Realizes **T3** (`Confirmed`→`Reorged`) and **T5** (`Spent`→`Reorged`,
    /// deep reorg where both spend and origin left the chain).
    pub fn mark_reorged(&mut self, now: u64) -> Result<(), TransitionError> {
        self.set_status(OutputStatus::Reorged, now)
    }

    /// Reserve this output as a slate input (`reserved_for`). Orthogonal to
    /// status; never implies deletion.
    pub fn reserve(&mut self, slate_hash: [u8; 32], now: u64) {
        self.reserved_for = Some(slate_hash);
        self.updated_at = now;
    }

    /// Release a reservation (on confirm/cancel of the slate).
    pub fn release_reservation(&mut self, now: u64) {
        self.reserved_for = None;
        self.updated_at = now;
    }

    /// **D1 guard.** An output may be deleted **only** while `Unconfirmed`
    /// (and, at the store layer, only once its producing slate is terminally
    /// `Canceled`/`Failed` — checked by the caller in 3B). Any output that was
    /// ever canonical (`Confirmed`/`Spent`/`Reorged`) returns `false`: this is
    /// the structural enforcement of INV-RET.
    pub fn can_delete(&self) -> bool {
        matches!(self.status, OutputStatus::Unconfirmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::OutputOrigin;

    fn block(h: u64, tag: u8) -> BlockRef {
        BlockRef {
            height: h,
            hash: [tag; 32],
        }
    }

    /// Fresh `Unconfirmed` output with a random (non-derivable) blinding —
    /// the case v1 loses. `now = 1000`.
    fn unconfirmed() -> StoredOutput {
        StoredOutput::new_unconfirmed(
            [7u8; 33],
            500,
            [9u8; 32],
            OutputOrigin::ReceiveSlate,
            false,
            None,
            1000,
        )
    }

    // Helpers that drive an output into a given starting state via legal edges.
    fn confirmed() -> StoredOutput {
        let mut o = unconfirmed();
        o.confirm(block(2, 0xAA), 1001).unwrap();
        o
    }
    fn spent() -> StoredOutput {
        let mut o = confirmed();
        o.mark_spent(1002).unwrap();
        o
    }
    fn reorged() -> StoredOutput {
        let mut o = confirmed();
        o.mark_reorged(1003).unwrap();
        o
    }

    #[test]
    fn c0_creation_starts_unconfirmed_with_blinding() {
        let o = unconfirmed();
        assert_eq!(o.status, OutputStatus::Unconfirmed);
        assert_eq!(*o.blinding, [9u8; 32]); // blinding written at C0
        assert!(o.origin_block.is_none());
    }

    #[test]
    fn t1_unconfirmed_to_confirmed_sets_origin_block() {
        let mut o = unconfirmed();
        o.confirm(block(2, 0xAA), 1001).unwrap();
        assert_eq!(o.status, OutputStatus::Confirmed);
        assert_eq!(o.origin_block, Some(block(2, 0xAA)));
        assert_eq!(o.updated_at, 1001);
    }

    #[test]
    fn t2_confirmed_to_spent() {
        let mut o = confirmed();
        o.mark_spent(1002).unwrap();
        assert_eq!(o.status, OutputStatus::Spent);
    }

    #[test]
    fn t3_confirmed_to_reorged_keeps_blinding_and_value() {
        let mut o = confirmed();
        o.mark_reorged(1003).unwrap();
        assert_eq!(o.status, OutputStatus::Reorged);
        assert_eq!(*o.blinding, [9u8; 32]); // INV-RET: blinding retained
        assert_eq!(o.value, 500);
    }

    #[test]
    fn t4_spent_to_confirmed_spend_reorg() {
        let mut o = spent();
        o.confirm(block(2, 0xAA), 1004).unwrap();
        assert_eq!(o.status, OutputStatus::Confirmed);
    }

    #[test]
    fn t5_spent_to_reorged_deep_reorg() {
        let mut o = spent();
        o.mark_reorged(1005).unwrap();
        assert_eq!(o.status, OutputStatus::Reorged);
    }

    #[test]
    fn t6_reorged_to_confirmed_remine_updates_block() {
        let mut o = reorged();
        // Same tx re-mined in a different block on the winning branch.
        o.confirm(block(3, 0xBB), 1006).unwrap();
        assert_eq!(o.status, OutputStatus::Confirmed);
        assert_eq!(o.origin_block, Some(block(3, 0xBB)));
        assert_eq!(*o.blinding, [9u8; 32]); // recovered from persisted material
    }

    #[test]
    fn t7_reorged_to_spent_remined_then_spent() {
        let mut o = reorged();
        o.mark_spent(1007).unwrap();
        assert_eq!(o.status, OutputStatus::Spent);
    }

    #[test]
    fn d1_only_unconfirmed_is_deletable() {
        assert!(unconfirmed().can_delete());
        assert!(!confirmed().can_delete());
        assert!(!spent().can_delete());
        assert!(!reorged().can_delete());
    }

    #[test]
    fn inv_ret_no_transition_returns_to_unconfirmed() {
        // No canonical state may move back to Unconfirmed.
        for from in [
            OutputStatus::Confirmed,
            OutputStatus::Spent,
            OutputStatus::Reorged,
            OutputStatus::Unconfirmed,
        ] {
            assert!(
                !from.can_transition_to(OutputStatus::Unconfirmed),
                "{from:?} must not transition back to Unconfirmed"
            );
        }
    }

    #[test]
    fn illegal_transitions_are_rejected() {
        // Unconfirmed cannot jump straight to Spent or Reorged (must confirm first).
        let mut o = unconfirmed();
        assert_eq!(
            o.mark_spent(1).unwrap_err(),
            TransitionError {
                from: OutputStatus::Unconfirmed,
                to: OutputStatus::Spent
            }
        );
        assert_eq!(o.mark_reorged(1).unwrap_err().to, OutputStatus::Reorged);
        // A rejected transition leaves the output untouched.
        assert_eq!(o.status, OutputStatus::Unconfirmed);
        assert_eq!(o.updated_at, 1000);
    }
}
