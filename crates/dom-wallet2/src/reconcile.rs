//! Status-only reconciliation (design §4) — the core that makes WDSF-001/002
//! impossible by construction.
//!
//! The key inversion (design §4.5): v1 asks *"for each thing I can derive / that
//! is pending, is it on chain?"* and loses everything it cannot derive. v2 asks
//! *"for each output I **already own and persisted**, what is its status on the
//! chain?"*. Ownership was established at local creation (`C0`) and is **never**
//! re-derived. [`reconcile`] therefore iterates the **store** and only reassigns
//! `status` (and `origin_block`); it never reconstructs the set and never deletes
//! a canonical output. The store's cardinality cannot drop on a rescan.
//!
//! ## Decoupling from transport
//! The reconciler consumes an abstract [`CanonicalView`] — the set of canonical
//! output commitments (with the block they appear in) and the set of consumed
//! input commitments, plus the tip. It does **not** know about the node or RPC;
//! a transport layer (later) is responsible only for producing [`ScanBlock`]s
//! from which a [`CanonicalView`] is built. This keeps `reconcile` unit-testable
//! in isolation.

use crate::store::OutputStore;
use crate::types::{BlockRef, OutputStatus};
use std::collections::{HashMap, HashSet};

/// One scanned canonical block: the commitments it creates and the ones it
/// consumes. Mirrors the per-height yield of v1's `ChainScanSource`
/// (`dom-wallet/src/restore.rs`), reduced to what the reconciler needs.
#[derive(Debug, Clone, Default)]
pub struct ScanBlock {
    /// Block height.
    pub height: u64,
    /// 32-byte block hash.
    pub hash: [u8; 32],
    /// Commitments of outputs created in this block.
    pub output_commitments: Vec<[u8; 33]>,
    /// Commitments consumed as inputs in this block.
    pub input_commitments: Vec<[u8; 33]>,
}

/// The abstract canonical view the reconciler reads (design §4.1).
///
/// Built by walking a contiguous scan `0..=tip` (a single pass). Holds:
/// - `CANON_OUT`: every canonical output commitment → the block where it appears;
/// - `CANON_IN`: every commitment consumed as a canonical input;
/// - `tip`: the highest block in the view (`None` if the chain is empty).
#[derive(Debug, Clone, Default)]
pub struct CanonicalView {
    canon_out: HashMap<[u8; 33], BlockRef>,
    canon_in: HashSet<[u8; 33]>,
    tip: Option<BlockRef>,
}

impl CanonicalView {
    /// An empty view (no canonical blocks). Reconciling against it moves every
    /// confirmed/spent output to `Reorged` (the whole chain vanished).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build the canonical view from a contiguous scan `0..=tip`.
    ///
    /// `blocks` are expected in ascending height order; the tip is taken as the
    /// highest-height block. Each output commitment maps to the block where it
    /// first appears (canonically a commitment appears once).
    pub fn from_blocks(blocks: &[ScanBlock]) -> Self {
        let mut canon_out: HashMap<[u8; 33], BlockRef> = HashMap::new();
        let mut canon_in: HashSet<[u8; 33]> = HashSet::new();
        let mut tip: Option<BlockRef> = None;
        for b in blocks {
            let bref = BlockRef {
                height: b.height,
                hash: b.hash,
            };
            for c in &b.output_commitments {
                canon_out.entry(*c).or_insert(bref);
            }
            for c in &b.input_commitments {
                canon_in.insert(*c);
            }
            // Highest height wins as the tip (robust to unordered input).
            let is_new_tip = match tip {
                None => true,
                Some(t) => b.height >= t.height,
            };
            if is_new_tip {
                tip = Some(bref);
            }
        }
        Self {
            canon_out,
            canon_in,
            tip,
        }
    }

    /// The block where a commitment appears as a canonical output, if any.
    pub fn output_block(&self, commitment: &[u8; 33]) -> Option<BlockRef> {
        self.canon_out.get(commitment).copied()
    }

    /// Whether a commitment was consumed as a canonical input.
    pub fn is_spent(&self, commitment: &[u8; 33]) -> bool {
        self.canon_in.contains(commitment)
    }

    /// The tip of this view (`None` for an empty chain).
    pub fn tip(&self) -> Option<BlockRef> {
        self.tip
    }
}

/// What a [`reconcile`] pass changed. The cardinality fields prove the INV-RET
/// lemma at runtime: `outputs_before == outputs_after` always.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Outputs moved to `Confirmed` (T1/T4/T6).
    pub confirmed: usize,
    /// Outputs moved to `Spent` (T2/T7).
    pub spent: usize,
    /// Outputs moved to `Reorged` (T3/T5).
    pub reorged: usize,
    /// Outputs left unchanged ("keep" arm).
    pub unchanged: usize,
    /// Store size before the pass.
    pub outputs_before: usize,
    /// Store size after the pass (equals `outputs_before` — INV-RET).
    pub outputs_after: usize,
    /// Tip the store was reconciled up to.
    pub tip: Option<BlockRef>,
}

/// Reconcile the store against a canonical view (design §4.2). **Status-only**:
/// iterates `store.outputs`, and in each arm only reassigns `status` (and
/// `origin_block`). No arm removes an output — the sole deletion path is `D1`
/// (a separate GC over `Unconfirmed` orphans), never here. `now` is the
/// caller-supplied unix timestamp for `updated_at`.
///
/// The match arms map directly onto the §3.1 transition table:
///
/// | `(status, present, spent)`              | Transition | To          |
/// |-----------------------------------------|------------|-------------|
/// | `(Unconfirmed\|Reorged, Some(b), false)`| T1, T6     | `Confirmed` |
/// | `(Confirmed\|Reorged, _, true)`         | T2, T7     | `Spent`     |
/// | `(Confirmed\|Spent, None, false)`       | T3, T5     | `Reorged`   |
/// | `(Spent, Some(b), false)`               | T4         | `Confirmed` |
/// | otherwise                               | —          | keep        |
pub fn reconcile(store: &mut OutputStore, view: &CanonicalView, now: u64) -> ReconcileReport {
    use OutputStatus::{Confirmed, Reorged, Spent, Unconfirmed};

    let outputs_before = store.len();
    let mut report = ReconcileReport {
        outputs_before,
        tip: view.tip(),
        ..Default::default()
    };

    for out in store.iter_mut() {
        let present = view.output_block(&out.commitment);
        let spent = view.is_spent(&out.commitment);

        // Every arm below is a legal edge of the §3.1 table, so the transition
        // mutators cannot fail here; `expect` documents that invariant.
        match (out.status, present, spent) {
            // Confirmation / re-confirmation after re-mine (T1, T6).
            (Unconfirmed, Some(b), false) | (Reorged, Some(b), false) => {
                out.confirm(b, now).expect("T1/T6 is a legal edge");
                report.confirmed += 1;
            }
            // Canonical spend takes priority over presence (T2, T7).
            (Confirmed, _, true) | (Reorged, _, true) => {
                out.mark_spent(now).expect("T2/T7 is a legal edge");
                report.spent += 1;
            }
            // Origin (and possibly spend) vanished from the canonical set (T3, T5).
            (Confirmed, None, false) | (Spent, None, false) => {
                out.mark_reorged(now).expect("T3/T5 is a legal edge");
                report.reorged += 1;
            }
            // Spend reorged out; the output is canonical again (T4).
            (Spent, Some(b), false) => {
                out.confirm(b, now).expect("T4 is a legal edge");
                report.confirmed += 1;
            }
            // No change.
            _ => {
                report.unchanged += 1;
            }
        }
    }

    report.outputs_after = store.len();
    // INV-RET lemma (design §4.3): status-only reconciliation never drops a row.
    debug_assert_eq!(
        report.outputs_before, report.outputs_after,
        "reconcile must not change store cardinality (INV-RET)"
    );
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OutputOrigin, StoredOutput};

    const C_R: [u8; 33] = [0xC7u8; 33];

    fn receive_output() -> StoredOutput {
        StoredOutput::new_unconfirmed(
            C_R,
            500,
            [0x9u8; 32], // random blinding, non-derivable
            OutputOrigin::ReceiveSlate,
            false,
            None,
            1000,
        )
    }

    fn block_with_output(height: u64, tag: u8, c: [u8; 33]) -> ScanBlock {
        ScanBlock {
            height,
            hash: [tag; 32],
            output_commitments: vec![c],
            input_commitments: vec![],
        }
    }

    #[test]
    fn t1_confirms_unconfirmed_output() {
        let mut store = OutputStore::new();
        store.insert(receive_output()).unwrap();
        let view = CanonicalView::from_blocks(&[block_with_output(2, 0x02, C_R)]);
        let r = reconcile(&mut store, &view, 1001);
        assert_eq!(r.confirmed, 1);
        let o = store.get(&C_R).unwrap();
        assert_eq!(o.status, OutputStatus::Confirmed);
        assert_eq!(o.origin_block.unwrap().height, 2);
    }

    #[test]
    fn t3_reorgs_confirmed_output_that_vanished_keeping_blinding() {
        let mut store = OutputStore::new();
        store.insert(receive_output()).unwrap();
        // Confirm at block 2.
        reconcile(
            &mut store,
            &CanonicalView::from_blocks(&[block_with_output(2, 0x02, C_R)]),
            1001,
        );
        // Reorg: block 2 left the chain (empty view).
        let r = reconcile(&mut store, &CanonicalView::empty(), 1002);
        assert_eq!(r.reorged, 1);
        let o = store.get(&C_R).unwrap();
        assert_eq!(o.status, OutputStatus::Reorged);
        assert_eq!(*o.blinding, [0x9u8; 32]); // INV-RET: blinding kept
    }

    #[test]
    fn t6_reconfirms_reorged_output_on_remine() {
        let mut store = OutputStore::new();
        store.insert(receive_output()).unwrap();
        reconcile(
            &mut store,
            &CanonicalView::from_blocks(&[block_with_output(2, 0x02, C_R)]),
            1001,
        );
        reconcile(&mut store, &CanonicalView::empty(), 1002); // -> Reorged
                                                              // Same tx re-mined at a different block 2'.
        let r = reconcile(
            &mut store,
            &CanonicalView::from_blocks(&[block_with_output(2, 0xB2, C_R)]),
            1003,
        );
        assert_eq!(r.confirmed, 1);
        let o = store.get(&C_R).unwrap();
        assert_eq!(o.status, OutputStatus::Confirmed);
        assert_eq!(o.origin_block.unwrap().hash, [0xB2u8; 32]);
    }

    #[test]
    fn t2_marks_spent_when_consumed_as_input() {
        let mut store = OutputStore::new();
        store.insert(receive_output()).unwrap();
        reconcile(
            &mut store,
            &CanonicalView::from_blocks(&[block_with_output(2, 0x02, C_R)]),
            1001,
        );
        // Block 3 spends c_R.
        let spend = ScanBlock {
            height: 3,
            hash: [0x03; 32],
            output_commitments: vec![],
            input_commitments: vec![C_R],
        };
        let r = reconcile(&mut store, &CanonicalView::from_blocks(&[spend]), 1002);
        assert_eq!(r.spent, 1);
        assert_eq!(store.get(&C_R).unwrap().status, OutputStatus::Spent);
    }

    #[test]
    fn t4_unspends_on_spend_reorg() {
        let mut store = OutputStore::new();
        store.insert(receive_output()).unwrap();
        // Confirm then spend.
        reconcile(
            &mut store,
            &CanonicalView::from_blocks(&[block_with_output(2, 0x02, C_R)]),
            1001,
        );
        let spend = ScanBlock {
            height: 3,
            hash: [0x03; 32],
            output_commitments: vec![],
            input_commitments: vec![C_R],
        };
        reconcile(&mut store, &CanonicalView::from_blocks(&[spend]), 1002);
        assert_eq!(store.get(&C_R).unwrap().status, OutputStatus::Spent);
        // Spend reorged out: c_R is back in the canonical output set, not spent.
        let r = reconcile(
            &mut store,
            &CanonicalView::from_blocks(&[block_with_output(2, 0x02, C_R)]),
            1003,
        );
        assert_eq!(r.confirmed, 1);
        assert_eq!(store.get(&C_R).unwrap().status, OutputStatus::Confirmed);
    }

    #[test]
    fn idempotent_keeps_confirmed_on_repeat_pass() {
        let mut store = OutputStore::new();
        store.insert(receive_output()).unwrap();
        let view = CanonicalView::from_blocks(&[block_with_output(2, 0x02, C_R)]);
        reconcile(&mut store, &view, 1001);
        let r = reconcile(&mut store, &view, 1002); // second pass, same tip
        assert_eq!(r.confirmed, 0);
        assert_eq!(r.unchanged, 1);
        assert_eq!(store.get(&C_R).unwrap().status, OutputStatus::Confirmed);
    }

    #[test]
    fn reconcile_never_changes_cardinality() {
        let mut store = OutputStore::new();
        store.insert(receive_output()).unwrap();
        let r = reconcile(&mut store, &CanonicalView::empty(), 1001);
        assert_eq!(r.outputs_before, r.outputs_after);
        assert_eq!(store.len(), 1);
    }
}
