//! dom-shield — property tests for the funds-safety invariants of dom-wallet2.
//!
//! Vectors:
//! - INV-RET (reconcile never drops a row): `reconcile` is status-only; its
//!   cardinality guard in src is a `debug_assert_eq!` (release-stripped). This
//!   asserts `outputs_before == outputs_after == store.len()` with a REAL assert
//!   so the invariant holds in release too, across randomized stores + views.
//! - merge_rank total order: a randomized total-order property (antisymmetry,
//!   transitivity, Spent maximal) over `OutputStatus::merge_rank`.
//! - merge_backup never deletes / never downgrades a higher-rank local status.
//! - select_inputs u64-sum: a store whose spendable values sum near `u64::MAX`
//!   must not panic on overflow in `create_send`'s coin selection.

use dom_wallet2::{
    create_send, reconcile, BlockRef, CanonicalView, Network, OutputOrigin, OutputStatus,
    OutputStore, PaymentError, ScanBlock, StoredOutput, WalletV2State,
};
use proptest::prelude::*;

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

/// Build an output already driven (via legal edges) into `status`.
fn output_at(tag: u8, value: u64, status: OutputStatus) -> StoredOutput {
    let mut o = StoredOutput::new_unconfirmed(
        key(tag),
        value,
        [tag; 32],
        OutputOrigin::ReceiveSlate,
        false,
        None,
        1,
    );
    match status {
        OutputStatus::Unconfirmed => {}
        OutputStatus::Confirmed => {
            o.confirm(
                BlockRef {
                    height: 1,
                    hash: [1; 32],
                },
                2,
            )
            .unwrap();
        }
        OutputStatus::Spent => {
            o.confirm(
                BlockRef {
                    height: 1,
                    hash: [1; 32],
                },
                2,
            )
            .unwrap();
            o.mark_spent(3).unwrap();
        }
        OutputStatus::Reorged => {
            o.confirm(
                BlockRef {
                    height: 1,
                    hash: [1; 32],
                },
                2,
            )
            .unwrap();
            o.mark_reorged(3).unwrap();
        }
    }
    o
}

fn status_strategy() -> impl Strategy<Value = OutputStatus> {
    (0usize..4).prop_map(|i| ALL[i])
}

proptest! {
    /// INV-RET: a reconcile pass against ANY view never changes store cardinality.
    /// Real assert (independent of the src debug_assert).
    #[test]
    fn reconcile_never_drops_a_row(
        // up to 12 distinct outputs (unique tag = unique commitment), each at a
        // random starting status.
        specs in proptest::collection::vec((1u8..200, 0u64..1_000_000, status_strategy()), 0..12),
        // a random canonical view: some commitments present, some spent.
        present in proptest::collection::vec(1u8..200, 0..16),
        spent in proptest::collection::vec(1u8..200, 0..16),
        tip_h in 0u64..100,
    ) {
        let mut store = OutputStore::new();
        // tag -> the status actually inserted (first occurrence wins; commitment
        // is the primary key so a repeated tag is one output).
        let mut inserted: std::collections::HashMap<u8, OutputStatus> =
            std::collections::HashMap::new();
        for (tag, value, status) in &specs {
            if !inserted.contains_key(tag) {
                store.insert(output_at(*tag, *value, *status)).unwrap();
                inserted.insert(*tag, *status);
            }
        }
        let before = store.len();

        let block = ScanBlock {
            height: tip_h,
            hash: [tip_h as u8; 32],
            output_commitments: present.iter().map(|t| key(*t)).collect(),
            input_commitments: spent.iter().map(|t| key(*t)).collect(),
        };
        let view = CanonicalView::from_blocks(&[block]);
        let report = reconcile(&mut store, &view, 999);

        prop_assert_eq!(report.outputs_before, before);
        prop_assert_eq!(report.outputs_after, before, "INV-RET: reconcile dropped a row");
        prop_assert_eq!(store.len(), before, "INV-RET: store cardinality changed");
        // No output may end Unconfirmed if it was INSERTED as canonical (no edge
        // to U). Use the actually-inserted status, not every (possibly duplicate)
        // spec.
        for (tag, start) in &inserted {
            if *start != OutputStatus::Unconfirmed {
                if let Some(o) = store.get(&key(*tag)) {
                    prop_assert_ne!(o.status, OutputStatus::Unconfirmed,
                        "canonical output reverted to Unconfirmed");
                }
            }
        }
    }

    /// merge_rank is a strict total order with Spent maximal.
    #[test]
    fn merge_rank_total_order(a in status_strategy(), b in status_strategy(), c in status_strategy()) {
        let (ra, rb, rc) = (a.merge_rank(), b.merge_rank(), c.merge_rank());
        // Antisymmetry / determinism: equal status -> equal rank.
        if a == b { prop_assert_eq!(ra, rb); }
        // Transitivity of <.
        if ra < rb && rb < rc { prop_assert!(ra < rc); }
        // Spent is the unique maximum.
        prop_assert!(OutputStatus::Spent.merge_rank() >= ra);
        if a != OutputStatus::Spent {
            prop_assert!(OutputStatus::Spent.merge_rank() > ra);
        }
    }

    /// merge_backup never deletes and never downgrades a strictly-higher local rank.
    #[test]
    fn merge_backup_preserves_higher_local_rank(
        local in status_strategy(),
        incoming in status_strategy(),
    ) {
        let mut store = OutputStore::new();
        store.insert(output_at(1, 500, local)).unwrap();
        let before_len = store.len();
        let local_rank = local.merge_rank();

        store.merge_backup(vec![output_at(1, 777, incoming)]);

        prop_assert_eq!(store.len(), before_len, "merge_backup changed cardinality");
        let after = store.get(&key(1)).unwrap();
        // Final rank is max(local, incoming) — never below the local rank.
        prop_assert!(
            after.status.merge_rank() >= local_rank,
            "merge_backup downgraded a local status"
        );
    }
}

/// select_inputs sums candidate values into a u64. A store whose spendable set
/// sums above u64::MAX must not panic. (`create_send`'s `select_inputs` does
/// `candidates.iter().map(|o| o.value).sum::<u64>()`.)
#[test]
fn select_inputs_u64_sum_does_not_panic_on_overflow() {
    let mut state = WalletV2State::new(Network::Regtest, [0u8; 32]);
    state.meta.last_reconciled_tip = 1000;
    // Two confirmed, mature, non-coinbase outputs each near u64::MAX so their
    // sum overflows u64. They must be valid commitments for nothing downstream —
    // we only exercise the selection sum, which runs before any crypto when
    // `need` is small enough to be covered by the first candidate. Use a need
    // that forces the sum to be computed over all candidates.
    let big = u64::MAX - 10;
    state.outputs.insert(make_confirmed(1, big)).unwrap();
    state.outputs.insert(make_confirmed(2, big)).unwrap();

    // need larger than any single output but the total overflows u64.
    // `select_inputs` computes `total: u64 = ...sum()`; in debug this panics on
    // overflow if unguarded. The call must return Err/Ok, never panic.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        create_send(&mut state, big, 5, 2000)
    }));
    assert!(
        result.is_ok(),
        "PANIC: select_inputs overflowed the u64 value sum (DoS / crash)"
    );
    // Whatever the Result is, it must be a typed outcome (not a panic).
    match result.unwrap() {
        Ok(_) | Err(PaymentError::InsufficientFunds { .. }) | Err(PaymentError::AmountOverflow) => {
        }
        Err(other) => {
            // Any other typed error is fine too — the point is "no panic".
            let _ = other;
        }
    }
}

/// Build a confirmed, mature, non-coinbase output with an arbitrary (not
/// crypto-valid) commitment — selection only reads `value`/`status`/flags.
fn make_confirmed(tag: u8, value: u64) -> StoredOutput {
    let mut o = StoredOutput::new_unconfirmed(
        key(tag),
        value,
        [tag; 32],
        OutputOrigin::ReceiveSlate,
        false,
        None,
        1,
    );
    o.confirm(
        BlockRef {
            height: 1,
            hash: [1; 32],
        },
        2,
    )
    .unwrap();
    o
}
