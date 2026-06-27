//! dom-shield — state machine & merge_backup adversarial suite (FIX-025 reproducer).
//!
//! Confirm-or-dissolve of FIX-025: "a hostile/stale backup can downgrade
//! Spent->re-spend or delete a canonical output". Each test here is one attack
//! vector against the retention invariant INV-RET realized by
//! `OutputStatus::can_transition_to` / `merge_rank` / `can_delete` (state.rs)
//! and `OutputStore::merge_backup` (store.rs).
//!
//! These probe the PUBLIC behavioral surface only; they never touch production
//! logic. A RED here is a finding reported, never patched.

use dom_wallet2::{
    BlockRef, MergeReport, OutputOrigin, OutputStatus, OutputStore, StoredOutput, TransitionError,
};

const ALL: [OutputStatus; 4] = [
    OutputStatus::Unconfirmed,
    OutputStatus::Confirmed,
    OutputStatus::Spent,
    OutputStatus::Reorged,
];

fn key(tag: u8) -> [u8; 33] {
    let mut c = [0u8; 33];
    c[0] = tag;
    c
}

fn unconfirmed(tag: u8) -> StoredOutput {
    StoredOutput::new_unconfirmed(
        key(tag),
        1000,
        [tag; 32],
        OutputOrigin::Coinbase,
        false,
        None,
        1,
    )
}

fn at_status(tag: u8, status: OutputStatus) -> StoredOutput {
    let mut o = unconfirmed(tag);
    match status {
        OutputStatus::Unconfirmed => {}
        OutputStatus::Confirmed => {
            o.confirm(
                BlockRef {
                    height: 2,
                    hash: [2; 32],
                },
                2,
            )
            .unwrap();
        }
        OutputStatus::Spent => {
            o.confirm(
                BlockRef {
                    height: 2,
                    hash: [2; 32],
                },
                2,
            )
            .unwrap();
            o.mark_spent(3).unwrap();
        }
        OutputStatus::Reorged => {
            o.confirm(
                BlockRef {
                    height: 2,
                    hash: [2; 32],
                },
                2,
            )
            .unwrap();
            o.mark_reorged(3).unwrap();
        }
    }
    assert_eq!(o.status, status);
    o
}

// ── Vector A1: exhaustive (from,to) transition table — no edge targets Unconfirmed ──

#[test]
fn no_transition_edge_ever_targets_unconfirmed() {
    // INV-RET structural property: nothing returns to Unconfirmed.
    for from in ALL {
        assert!(
            !from.can_transition_to(OutputStatus::Unconfirmed),
            "ILLEGAL: {from:?} -> Unconfirmed is admitted"
        );
    }
}

#[test]
fn full_transition_table_matches_design_3_1() {
    // The 16-cell (from,to) table. The ONLY legal edges are the §3.1 set; any
    // extra admitted edge is a finding. Spent->Confirmed (T4) and Spent->Reorged
    // (T5) ARE legal (spend/origin reorg), but Spent never downgrades VALUE/loses
    // blinding — proven in the merge tests below.
    use OutputStatus::{Confirmed, Reorged, Spent, Unconfirmed};
    let legal = |from: OutputStatus, to: OutputStatus| -> bool {
        matches!(
            (from, to),
            (Unconfirmed, Confirmed)
                | (Spent, Confirmed)
                | (Reorged, Confirmed)
                | (Confirmed, Spent)
                | (Reorged, Spent)
                | (Confirmed, Reorged)
                | (Spent, Reorged)
        )
    };
    for from in ALL {
        for to in ALL {
            assert_eq!(
                from.can_transition_to(to),
                legal(from, to),
                "transition table mismatch at {from:?} -> {to:?}"
            );
        }
    }
}

#[test]
fn no_self_loop_transition_is_admitted() {
    // A self-edge would let a mutator stamp/`updated_at` a state onto itself;
    // §3.1 has no self-loops.
    for s in ALL {
        assert!(!s.can_transition_to(s), "self-loop {s:?} -> {s:?} admitted");
    }
}

#[test]
fn rejected_transition_leaves_output_completely_untouched() {
    // A refused edge must not partially mutate (status/updated_at/origin_block).
    let o = at_status(1, OutputStatus::Spent);
    let before_updated = o.updated_at;
    let before_block = o.origin_block;
    // There is no public mutator for Spent->Unconfirmed; the closest illegal
    // public attempt from Unconfirmed:
    let mut u = unconfirmed(2);
    assert_eq!(
        u.mark_spent(99).unwrap_err(),
        TransitionError {
            from: OutputStatus::Unconfirmed,
            to: OutputStatus::Spent
        }
    );
    assert_eq!(u.status, OutputStatus::Unconfirmed);
    assert_eq!(
        u.updated_at, 1,
        "updated_at must not advance on a rejected edge"
    );
    // And the Spent one is irrelevant to that attempt: untouched.
    assert_eq!(o.updated_at, before_updated);
    assert_eq!(o.origin_block, before_block);
}

// ── Vector A2: merge_rank total order ──

#[test]
fn merge_rank_is_strict_total_order_unconf_reorg_conf_spent() {
    assert!(
        OutputStatus::Unconfirmed.merge_rank() < OutputStatus::Reorged.merge_rank()
            && OutputStatus::Reorged.merge_rank() < OutputStatus::Confirmed.merge_rank()
            && OutputStatus::Confirmed.merge_rank() < OutputStatus::Spent.merge_rank(),
        "merge_rank order broke: U<R<C<S required"
    );
    // Spent is the maximum — nothing can outrank it in a merge.
    let max = ALL.iter().map(|s| s.merge_rank()).max().unwrap();
    assert_eq!(OutputStatus::Spent.merge_rank(), max);
}

// ── Vector A3: can_delete is the D1 gate — only Unconfirmed ──

#[test]
fn only_unconfirmed_is_deletable() {
    for s in ALL {
        let o = at_status(1, s);
        assert_eq!(
            o.can_delete(),
            s == OutputStatus::Unconfirmed,
            "can_delete wrong for {s:?}"
        );
    }
}

#[test]
fn store_refuses_to_remove_any_canonical_output() {
    for s in [
        OutputStatus::Confirmed,
        OutputStatus::Spent,
        OutputStatus::Reorged,
    ] {
        let mut store = OutputStore::new();
        let k = key(7);
        store.insert(at_status(7, s)).unwrap();
        let err = store.remove_if_deletable(&k).unwrap_err();
        assert_eq!(
            err,
            dom_wallet2::StoreError::NotDeletable,
            "canonical {s:?} must NOT be removable (INV-RET)"
        );
        assert_eq!(store.len(), 1, "{s:?} output was deleted — INV-RET broken");
    }
}

// ── Vector A4 (FIX-025 core): forged backup cannot downgrade / overwrite a canonical Spent ──

#[test]
fn fix025_forged_lower_rank_backup_cannot_overwrite_canonical_spent() {
    // Store holds a canonical Spent output. A hostile backup carries the SAME
    // commitment but a forged, *lower-rank* status (Confirmed) AND forged
    // value/blinding/origin_block. The merge must KEEP the Spent intact and
    // never touch its value or blinding.
    let mut store = OutputStore::new();
    let canonical = at_status(1, OutputStatus::Spent);
    let canonical_value = canonical.value;
    let canonical_blinding = *canonical.blinding;
    let canonical_block = canonical.origin_block; // Some(height:2) from the legal confirm edge
    store.insert(canonical).unwrap();

    // Forged incoming: same commitment, Confirmed (rank 2 < Spent 3), bogus value
    // 1, bogus blinding, bogus origin_block.
    let mut forged = StoredOutput::new_unconfirmed(
        key(1),
        1,          // forged value
        [0xFF; 32], // forged blinding
        OutputOrigin::Change,
        false,
        None,
        9_999,
    );
    forged
        .confirm(
            BlockRef {
                height: 99,
                hash: [0x99; 32],
            },
            9_999,
        )
        .unwrap(); // -> Confirmed

    let report: MergeReport = store.merge_backup(vec![forged]);

    assert_eq!(report.advanced, 0, "lower-rank backup must NOT advance");
    assert_eq!(report.kept, 1);
    let after = store.get(&key(1)).unwrap();
    assert_eq!(
        after.status,
        OutputStatus::Spent,
        "FIX-025: Spent downgraded!"
    );
    assert_eq!(after.value, canonical_value, "FIX-025: value overwritten!");
    assert_eq!(
        *after.blinding, canonical_blinding,
        "FIX-025: blinding overwritten!"
    );
    assert_eq!(
        after.origin_block, canonical_block,
        "FIX-025: canonical origin_block overwritten by the forged backup!"
    );
}

#[test]
fn fix025_equal_rank_backup_does_not_overwrite() {
    // Equal rank (Spent vs Spent): merge keeps, never overwrites value/blinding.
    let mut store = OutputStore::new();
    let canonical = at_status(1, OutputStatus::Spent);
    let canonical_blinding = *canonical.blinding;
    store.insert(canonical).unwrap();

    let mut forged = StoredOutput::new_unconfirmed(
        key(1),
        42,
        [0xAB; 32],
        OutputOrigin::Change,
        false,
        None,
        9_999,
    );
    forged
        .confirm(
            BlockRef {
                height: 2,
                hash: [2; 32],
            },
            9_999,
        )
        .unwrap();
    forged.mark_spent(9_999).unwrap(); // -> Spent (equal rank)

    let report = store.merge_backup(vec![forged]);
    assert_eq!(report.advanced, 0, "equal rank must not advance/overwrite");
    assert_eq!(report.kept, 1);
    let after = store.get(&key(1)).unwrap();
    assert_eq!(after.value, 1000, "equal-rank backup overwrote value");
    assert_eq!(
        *after.blinding, canonical_blinding,
        "equal-rank backup overwrote blinding"
    );
}

#[test]
fn merge_backup_never_changes_cardinality_downward() {
    // INV-RET at the merge layer: a merge can only insert (>=) — never remove.
    let mut store = OutputStore::new();
    store.insert(at_status(1, OutputStatus::Spent)).unwrap();
    store.insert(at_status(2, OutputStatus::Confirmed)).unwrap();
    let before = store.len();
    // Empty backup, then a backup that only repeats existing commitments.
    store.merge_backup(vec![]);
    assert_eq!(store.len(), before, "empty merge changed cardinality");
    store.merge_backup(vec![at_status(1, OutputStatus::Confirmed)]);
    assert_eq!(store.len(), before, "repeat merge changed cardinality");
}

#[test]
fn merge_backup_advances_only_strictly_higher_rank() {
    // The legitimate direction: store Unconfirmed, backup Confirmed -> advance.
    let mut store = OutputStore::new();
    store.insert(unconfirmed(1)).unwrap();
    let mut adv = unconfirmed(1);
    adv.confirm(
        BlockRef {
            height: 5,
            hash: [5; 32],
        },
        10,
    )
    .unwrap();
    let report = store.merge_backup(vec![adv]);
    assert_eq!(report.advanced, 1);
    assert_eq!(store.get(&key(1)).unwrap().status, OutputStatus::Confirmed);
}
