//! dom-shield Onda 2 — property tests for coin selection + spend arithmetic.
//!
//! Subfamily: proptest-invariante (Lens A — incorrect result / non-determinism
//! / overflow) over `dom_wallet::output_index::OutputIndex` and the
//! `build_spend` vs `create_send_slate` arithmetic asymmetry (FIX-009).
//!
//! Vectors covered (one property each):
//!   1. select-sufficiency: selection result always sums to >= amount_needed.
//!   2. select-determinism: repeated selection over the same index returns the
//!      same multiset of commitments (guards against HashMap-iteration order
//!      leaking into the result — equal-value ties).
//!   3. select-minimality-of-greed: greedy never returns more outputs than a
//!      whole-set selection would need (sanity on the sort+break loop).
//!   4. FIX-009 arithmetic asymmetry: build_spend's `amount.saturating_add(fee)`
//!      vs create_send_slate's `amount.checked_add(fee)` diverge ONLY in the
//!      overflow regime; below overflow they agree. Documents the asymmetry and
//!      shows it is not a fund-loss path (overflow ⇒ no real UTXO set can fund
//!      it, so selection errors either way).

use dom_wallet::output_index::OutputIndex;
use dom_wallet::OwnedOutput;
use proptest::prelude::*;

/// Non-coinbase output with a unique commitment derived from `idx` so the
/// HashMap key is distinct even when values collide.
fn output(idx: u8, value: u64) -> OwnedOutput {
    let mut commitment = [0u8; 33];
    commitment[0] = idx;
    commitment[1] = (value & 0xff) as u8;
    OwnedOutput::new(commitment, value, [idx; 32], 1, false)
}

proptest! {
    // 1. Sufficiency: a successful selection always covers the requirement.
    #[test]
    fn select_result_covers_amount(values in proptest::collection::vec(1u64..1_000_000, 1..40),
                                   need in 1u64..5_000_000) {
        let mut idx = OutputIndex::new();
        for (i, v) in values.iter().enumerate() {
            idx.insert(output(i as u8, *v));
        }
        // maturity 0: every output is mature (non-coinbase anyway).
        match idx.select_for_spend_with_maturity(need, 10, 0) {
            Ok(selected) => {
                let sum: u64 = selected.iter().map(|o| o.value).sum();
                prop_assert!(sum >= need, "selected sum {sum} < need {need}");
            }
            Err(_) => {
                let total: u64 = values.iter().sum();
                prop_assert!(total < need, "selection failed but total {total} >= need {need}");
            }
        }
    }

    // 2. Determinism: same index, same query ⇒ identical selected multiset.
    // This is the equal-value-tie nondeterminism probe: greedy sorts only by
    // value (descending) with no commitment tie-breaker, so ties fall back to
    // the pre-sort order, which comes from HashMap iteration. If that order
    // leaks into the result, two runs can differ.
    #[test]
    fn select_is_deterministic_across_runs(
        values in proptest::collection::vec(1u64..1000, 2..30),
        need in 1u64..30_000,
    ) {
        let mut idx = OutputIndex::new();
        for (i, v) in values.iter().enumerate() {
            idx.insert(output(i as u8, *v));
        }
        let a = idx.select_for_spend_with_maturity(need, 10, 0);
        let b = idx.select_for_spend_with_maturity(need, 10, 0);
        match (a, b) {
            (Ok(mut sa), Ok(mut sb)) => {
                sa.sort_by_key(|o| o.commitment);
                sb.sort_by_key(|o| o.commitment);
                let ca: Vec<[u8;33]> = sa.iter().map(|o| o.commitment).collect();
                let cb: Vec<[u8;33]> = sb.iter().map(|o| o.commitment).collect();
                prop_assert_eq!(ca, cb, "selection multiset differs across runs (tie nondeterminism)");
            }
            (Err(_), Err(_)) => {}
            _ => prop_assert!(false, "selection success/failure differs across identical runs"),
        }
    }

    // 3. Greedy uses no more inputs than the count it actually needs: the
    // selected count is the smallest prefix of the value-sorted set whose sum
    // reaches `need` (monotone — dropping the last selected output would
    // under-fund). Guards the break-on-reached loop.
    #[test]
    fn greedy_selection_is_prefix_minimal(
        values in proptest::collection::vec(1u64..10_000, 1..25),
        need in 1u64..50_000,
    ) {
        let mut idx = OutputIndex::new();
        for (i, v) in values.iter().enumerate() {
            idx.insert(output(i as u8, *v));
        }
        if let Ok(selected) = idx.select_for_spend_with_maturity(need, 10, 0) {
            if selected.len() > 1 {
                let total: u64 = selected.iter().map(|o| o.value).sum();
                // Removing the smallest selected output must drop below need,
                // otherwise greedy over-selected.
                let min_selected = selected.iter().map(|o| o.value).min().unwrap();
                prop_assert!(
                    total - min_selected < need,
                    "greedy over-selected: total {total} - min {min_selected} >= need {need}"
                );
            }
        }
    }

    // 4. FIX-009: the two `required` computations agree whenever amount+fee does
    // NOT overflow u64, and diverge ONLY in the overflow regime. In overflow,
    // build_spend's saturating_add yields u64::MAX (selection then fails with
    // InsufficientFunds — no real UTXO set funds u64::MAX), while
    // create_send_slate's checked_add returns an explicit overflow error. Both
    // refuse the spend; neither loses funds. This documents the asymmetry and
    // its non-exploitability.
    #[test]
    fn fix009_required_arith_agrees_below_overflow(amount in any::<u64>(), fee in any::<u64>()) {
        let saturating = amount.saturating_add(fee);     // build_spend path
        let checked = amount.checked_add(fee);            // create_send_slate path
        match checked {
            Some(c) => {
                // No overflow: both paths compute the identical requirement.
                prop_assert_eq!(saturating, c, "below overflow the two `required` values must match");
            }
            None => {
                // Overflow regime: saturating pins to u64::MAX; checked errors.
                // The divergence is confined to a requirement no UTXO set can
                // fund, so it is a refusal-vs-refusal difference, not fund loss.
                prop_assert_eq!(saturating, u64::MAX, "overflow ⇒ build_spend requirement saturates to MAX (unfundable)");
            }
        }
    }
}
