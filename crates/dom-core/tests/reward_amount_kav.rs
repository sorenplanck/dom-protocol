//! dom-shield — monetary-policy KAV + invariants for dom-core.
//!
//! Subfamilies:
//! - KAV-conformância: reward schedule recomputed independently from the
//!   documented integer recurrence reward(n)=(reward(n-1)*67)/100, and
//!   `block_reward(height)` checked at every halving boundary against it.
//! - KAV-negativo: `Amount::from_noms(> MAX_SUPPLY)` rejected.
//! - KAV-drift-congelado: digest (sum + count + tail) of the reward table.
//! - proptest-invariante: Amount checked_add overflow + supply cap; reward
//!   halving-boundary law over all epochs.
//!
//! Public API only. No production logic changed.

use dom_core::{block_reward, Amount, BlockHeight};
use dom_core::{
    BLOCK_REWARD_TABLE, COIN_UNIT, HALVING_EPOCHS, HALVING_INTERVAL, INITIAL_BLOCK_REWARD,
    MAX_SUPPLY_NOMS,
};
use proptest::prelude::*;

/// Independently recompute the reward schedule from the documented integer
/// recurrence. This is the authority; `BLOCK_REWARD_TABLE` is the artifact.
fn recompute_schedule() -> [u64; 55] {
    let mut t = [0u64; 55];
    let mut r: u64 = INITIAL_BLOCK_REWARD;
    for slot in t.iter_mut() {
        *slot = r;
        // reward(n) = (reward(n-1) * 67) / 100, integer floor.
        r = (r.checked_mul(67).expect("no overflow in schedule")) / 100;
    }
    t
}

// ── KAV-conformância ─────────────────────────────────────────────────────────

/// KAV. The pinned `BLOCK_REWARD_TABLE` must equal the independently recomputed
/// recurrence, slot for slot, including the terminal 0 at epoch 54.
#[test]
fn reward_table_matches_independent_recurrence() {
    let expected = recompute_schedule();
    assert_eq!(
        BLOCK_REWARD_TABLE.len(),
        expected.len(),
        "table length must be 55 epochs"
    );
    for (i, (&got, &want)) in BLOCK_REWARD_TABLE.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "BLOCK_REWARD_TABLE[{i}] != recurrence value");
    }
    assert_eq!(expected[0], 33 * COIN_UNIT, "epoch 0 must be 33 DOM");
    assert_eq!(expected[54], 0, "epoch 54 must floor to 0");
}

/// KAV. `block_reward(height)` at EVERY halving boundary (k * HALVING_INTERVAL)
/// must equal the recomputed schedule[k], and 0 for k >= HALVING_EPOCHS.
#[test]
fn block_reward_at_every_halving_boundary() {
    let schedule = recompute_schedule();
    for k in 0u64..(HALVING_EPOCHS as u64) {
        let h = BlockHeight(k.checked_mul(HALVING_INTERVAL).unwrap());
        assert_eq!(
            block_reward(h).noms(),
            schedule[k as usize],
            "block_reward at epoch boundary {k} must equal schedule[{k}]"
        );
    }
    // First height of an exhausted epoch and far beyond -> 0.
    let exhausted = BlockHeight(
        (HALVING_EPOCHS as u64)
            .checked_mul(HALVING_INTERVAL)
            .unwrap(),
    );
    assert_eq!(
        block_reward(exhausted).noms(),
        0,
        "post-schedule reward is 0"
    );
    assert_eq!(
        block_reward(BlockHeight(u64::MAX)).noms(),
        0,
        "max height reward is 0"
    );
}

/// KAV. MAX_SUPPLY_NOMS must equal the sum over all epochs, with the
/// economically empty height zero excluded from the first reward epoch.
#[test]
fn max_supply_matches_independent_sum() {
    let schedule = recompute_schedule();
    let mut total: u64 = 0;
    for (epoch, r) in schedule.into_iter().enumerate() {
        let blocks = if epoch == 0 {
            HALVING_INTERVAL - 1
        } else {
            HALVING_INTERVAL
        };
        total = total
            .checked_add(r.checked_mul(blocks).unwrap())
            .expect("supply sum must not overflow");
    }
    assert_eq!(
        total, MAX_SUPPLY_NOMS,
        "recomputed supply != MAX_SUPPLY_NOMS"
    );
    assert_eq!(MAX_SUPPLY_NOMS, 3_299_996_676_900_000);
}

// ── KAV-drift-congelado ──────────────────────────────────────────────────────

/// KAV-drift. A compact digest of the reward table (sum, len, first, last,
/// midpoint). Any silent edit to a table entry changes one of these. Cheaper
/// and more legible than freezing all 55 literals (which the recurrence KAV
/// already pins exactly).
#[test]
fn reward_table_frozen_digest() {
    let sum: u128 = BLOCK_REWARD_TABLE.iter().map(|&x| x as u128).sum();
    assert_eq!(
        sum, 9_999_999_930,
        "frozen: sum of per-epoch rewards (noms)"
    );
    assert_eq!(BLOCK_REWARD_TABLE.len(), 55);
    assert_eq!(BLOCK_REWARD_TABLE[0], 3_300_000_000);
    assert_eq!(BLOCK_REWARD_TABLE[27], 66_454);
    assert_eq!(BLOCK_REWARD_TABLE[54], 0);
}

// ── KAV-negativo ─────────────────────────────────────────────────────────────

/// KAV-negativo. `Amount::from_noms` must reject any value strictly above
/// MAX_SUPPLY_NOMS and accept exactly MAX_SUPPLY_NOMS.
#[test]
fn amount_from_noms_rejects_above_max_supply() {
    assert!(
        Amount::from_noms(MAX_SUPPLY_NOMS).is_ok(),
        "exactly MAX_SUPPLY must be accepted"
    );
    assert!(
        Amount::from_noms(MAX_SUPPLY_NOMS + 1).is_err(),
        "MAX_SUPPLY + 1 must be rejected"
    );
    assert!(
        Amount::from_noms(u64::MAX).is_err(),
        "u64::MAX must be rejected"
    );
}

// ── proptest-invariante ──────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Invariant. `from_noms` accepts iff value <= MAX_SUPPLY_NOMS.
    #[test]
    fn amount_from_noms_cap_is_exact(n in any::<u64>()) {
        let res = Amount::from_noms(n);
        if n <= MAX_SUPPLY_NOMS {
            prop_assert!(res.is_ok());
            prop_assert_eq!(res.unwrap().noms(), n);
        } else {
            prop_assert!(res.is_err());
        }
    }

    /// Invariant. `checked_add` never produces a value above MAX_SUPPLY and
    /// never wraps: it errors exactly when (a+b) overflows u64 OR exceeds the
    /// supply cap.
    #[test]
    fn amount_checked_add_caps_and_never_wraps(
        a in 0u64..=MAX_SUPPLY_NOMS,
        b in 0u64..=MAX_SUPPLY_NOMS,
    ) {
        let aa = Amount::from_noms(a).unwrap();
        let bb = Amount::from_noms(b).unwrap();
        let res = aa.checked_add(bb);
        let sum = a.checked_add(b);
        match sum {
            Some(s) if s <= MAX_SUPPLY_NOMS => {
                prop_assert_eq!(res.unwrap().noms(), s);
            }
            _ => {
                prop_assert!(res.is_err(), "over-cap / overflow add must error, never wrap");
            }
        }
    }

    /// Invariant. For ANY height, block_reward equals the schedule entry for
    /// that height's epoch (or 0 past the schedule). Drives the full halving
    /// law, not just boundaries.
    #[test]
    fn block_reward_follows_epoch_schedule(h in any::<u64>()) {
        let schedule = recompute_schedule();
        let epoch = h / HALVING_INTERVAL;
        let expected = if epoch >= HALVING_EPOCHS as u64 {
            0
        } else {
            schedule[epoch as usize]
        };
        prop_assert_eq!(block_reward(BlockHeight(h)).noms(), expected);
    }

    /// Invariant (halving-boundary law). reward(k*INTERVAL) == TABLE[k] for all
    /// in-range k, exactly as the task specifies.
    #[test]
    fn reward_at_boundary_equals_table(k in 0u64..(HALVING_EPOCHS as u64)) {
        let h = BlockHeight(k * HALVING_INTERVAL);
        prop_assert_eq!(block_reward(h).noms(), BLOCK_REWARD_TABLE[k as usize]);
    }
}
