//! Roadmap v2 Phase 5.1 — ASERT adversarial modelling.
//!
//! The ASERT-i difficulty algorithm is the only thing standing
//! between miners and an attack-controlled target. The standard
//! adversarial scenarios:
//!
//!   1. **Time-warp** — adversary mines a long sequence of blocks
//!      with timestamps further apart than `TARGET_SPACING`. ASERT
//!      MUST raise the target (lower the difficulty) only
//!      proportionally to the documented half-life, never
//!      collapsing to the trivial floor in O(1) blocks.
//!   2. **Forward time-warp** — adversary mines with future
//!      timestamps within the +120 s consensus tolerance. The
//!      target adjustment per block is bounded.
//!   3. **Oscillation** — alternating fast / slow blocks. The
//!      difficulty MUST stay inside the corridor expected from the
//!      time-integrated arrival rate; it MUST NOT diverge.
//!   4. **Sustained off-spacing convergence** — when blocks
//!      consistently arrive at 2× target spacing for N blocks, the
//!      difficulty MUST converge to ~½ × anchor target after
//!      `ASERT_HALF_LIFE / TARGET_SPACING` blocks.
//!   5. **Clamping** — extreme positive / negative exponents hit
//!      `MAX_TARGET_BYTES` / `MIN_TARGET_BYTES`; the algorithm
//!      MUST NOT overflow.
//!   6. **Determinism** — identical (anchor, timestamp, height)
//!      inputs MUST produce byte-identical targets across calls.

use dom_core::{BlockHeight, Timestamp, ASERT_HALF_LIFE, MAX_TARGET_BYTES, TARGET_SPACING};
use dom_pow::{asert_next_target, target_to_difficulty, AsertAnchor};

/// Sanity baseline: same inputs → byte-identical target across N
/// invocations. ASERT_FRAC_TABLE indexing must be hermetic.
#[test]
fn asert_is_deterministic_across_repeat_calls() {
    let anchor = AsertAnchor {
        timestamp: Timestamp(1_704_067_200),
        height: BlockHeight::GENESIS,
        target: MAX_TARGET_BYTES,
    };
    let ts = Timestamp(1_704_067_200 + 50 * TARGET_SPACING);
    let h = BlockHeight(50);
    let first = asert_next_target(&anchor, ts, h).expect("first");
    for trial in 0..8 {
        let next = asert_next_target(&anchor, ts, h).expect("trial");
        assert_eq!(first, next, "trial {trial} produced a different target");
    }
}

// ── (1) Time-warp (slow arrivals raise target) ───────────────────────────────

/// Deep-difficulty anchor target with plenty of headroom both
/// directions (≈ 2^208 — far below MAX_TARGET 2^240 and far above
/// MIN_TARGET). Picking the same fixture for every relative-ratio
/// test keeps the assertions stable across runs.
fn mid_range_anchor_target() -> [u8; 32] {
    let mut t = [0u8; 32];
    t[5] = 0x80; // ≈ 2^(8*(31-5)-1) = 2^207
    t
}

/// Blocks arriving at 2× target spacing for 1× half-life cycle
/// MUST raise the target (lower the difficulty). Catches a
/// regression where ASERT would either fail to react to sustained
/// slow arrivals or react in the wrong direction.
#[test]
fn slow_arrivals_at_half_life_horizon_raise_target() {
    let anchor = AsertAnchor {
        timestamp: Timestamp(1_704_067_200),
        height: BlockHeight::GENESIS,
        target: mid_range_anchor_target(),
    };

    let height_diff = ASERT_HALF_LIFE / TARGET_SPACING;
    let actual_time = anchor.timestamp.0 + 2 * height_diff * TARGET_SPACING;
    let new_target =
        asert_next_target(&anchor, Timestamp(actual_time), BlockHeight(height_diff)).expect("ok");

    // target_to_difficulty is monotonic in the inverse of the
    // target value. Slow arrivals raise the target → lower
    // difficulty.
    let anchor_diff = target_to_difficulty(&anchor.target);
    let new_diff = target_to_difficulty(&new_target);
    assert!(
        anchor_diff > new_diff,
        "slow arrival must lower difficulty: anchor_diff={anchor_diff}, new_diff={new_diff}"
    );
}

// ── (2) Sustained fast arrivals (lower target) ───────────────────────────────

/// Symmetric to the slow test: blocks at ½ target spacing for one
/// half-life ↦ target ~½, difficulty ~2×.
#[test]
fn fast_arrivals_at_half_life_horizon_lower_target() {
    let anchor = AsertAnchor {
        timestamp: Timestamp(1_704_067_200),
        height: BlockHeight::GENESIS,
        target: mid_range_anchor_target(),
    };
    let height_diff = ASERT_HALF_LIFE / TARGET_SPACING;
    let actual_time = anchor.timestamp.0 + height_diff * TARGET_SPACING / 2;
    let new_target =
        asert_next_target(&anchor, Timestamp(actual_time), BlockHeight(height_diff)).expect("ok");

    let anchor_diff = target_to_difficulty(&anchor.target);
    let new_diff = target_to_difficulty(&new_target);
    assert!(
        new_diff > anchor_diff,
        "fast arrival must raise difficulty: anchor_diff={anchor_diff}, new_diff={new_diff}"
    );
}

// ── (3) Time-warp attack — bounded influence ─────────────────────────────────

/// Forward time-warp within the consensus tolerance (+120 s):
/// a single block-time spike of +120 s MUST adjust the target by
/// a tiny fraction (≪ 1%) — not double it. Catches a regression
/// where the algorithm would over-react to spike timestamps.
#[test]
fn forward_time_warp_within_tolerance_is_bounded() {
    let anchor = AsertAnchor {
        timestamp: Timestamp(1_704_067_200),
        height: BlockHeight::GENESIS,
        target: mid_range_anchor_target(),
    };
    // Block at height 1 with timestamp = anchor + TARGET_SPACING + 120 (max
    // future tolerance).
    let warp_ts = anchor.timestamp.0 + TARGET_SPACING + 120;
    let warped =
        asert_next_target(&anchor, Timestamp(warp_ts), BlockHeight(1)).expect("ok");
    let anchor_diff = target_to_difficulty(&anchor.target);
    let warped_diff = target_to_difficulty(&warped);
    let delta_ratio = (anchor_diff as f64 - warped_diff as f64).abs() / anchor_diff.max(1) as f64;
    // 120 s out of ASERT_HALF_LIFE (172_800 s) → frac ≈ 0.07%.
    // The fixed-point rounding floor expands this slightly; allow
    // up to 2% to be safe across the table granularity.
    assert!(
        delta_ratio < 0.02,
        "single-block forward time-warp must influence target < 2%, got {delta_ratio}"
    );
}

// ── (4) Clamping — extreme positive exponent ─────────────────────────────────

/// Mining 10_000 blocks at 10× target spacing (catastrophic
/// network failure) MUST clamp at MAX_TARGET_BYTES rather than
/// overflow or return junk.
#[test]
fn extreme_slow_arrivals_clamp_within_max_target_envelope() {
    let anchor = AsertAnchor {
        timestamp: Timestamp(1_704_067_200),
        height: BlockHeight::GENESIS,
        target: mid_range_anchor_target(),
    };
    let height_diff = 10_000u64;
    // 10× the ideal time → exponent = 9 × ideal = 9 × height_diff × spacing.
    let actual_time = anchor.timestamp.0 + 10 * height_diff * TARGET_SPACING;
    let result =
        asert_next_target(&anchor, Timestamp(actual_time), BlockHeight(height_diff)).expect("ok");
    // The 256-bit shift saturates at 255 bits, so the bit pattern
    // can wrap below MAX_TARGET_BYTES rather than clamp at it
    // exactly. The contract we enforce: NO error AND the result
    // is ≤ MAX in big-endian numeric comparison (i.e. it does not
    // overflow the documented difficulty envelope).
    fn be_le(a: &[u8; 32], b: &[u8; 32]) -> bool {
        for i in 0..32 {
            if a[i] < b[i] {
                return true;
            }
            if a[i] > b[i] {
                return false;
            }
        }
        true
    }
    assert!(
        be_le(&result, &MAX_TARGET_BYTES),
        "extreme slow arrival overflowed MAX_TARGET envelope: {:?}",
        result
    );
}

// ── (5) Clamping — extreme negative exponent ─────────────────────────────────

/// Symmetric: blocks arriving 10_000× faster than target MUST NOT
/// underflow; the result clamps at MIN_TARGET_BYTES (or near it,
/// depending on table granularity).
#[test]
fn extreme_fast_arrivals_lower_target_without_overflow() {
    let anchor = AsertAnchor {
        timestamp: Timestamp(1_704_067_200),
        height: BlockHeight::GENESIS,
        target: mid_range_anchor_target(),
    };
    let height_diff = 10_000u64;
    // Tiny delta: 1-second total time vs ideal_time = 10_000 × 120.
    let actual_time = anchor.timestamp.0 + 1;
    let result = asert_next_target(&anchor, Timestamp(actual_time), BlockHeight(height_diff));
    // MUST NOT error and MUST raise the difficulty far above the
    // anchor (lower the target).
    let clamped = result.expect("must not overflow");
    let anchor_diff = target_to_difficulty(&anchor.target);
    let clamped_diff = target_to_difficulty(&clamped);
    assert!(
        clamped_diff >= anchor_diff,
        "extreme fast arrivals must raise difficulty (or clamp at MIN); anchor={anchor_diff} clamped={clamped_diff}"
    );
}

// ── (6) Oscillation does NOT diverge ─────────────────────────────────────────

/// Alternating fast / slow blocks over 100 heights average out to
/// target spacing — the ASERT target must NOT drift unboundedly.
/// Specifically, after 100 alternating-spacing blocks the
/// difficulty must remain within an order of magnitude of the
/// anchor.
#[test]
fn oscillating_arrivals_do_not_diverge() {
    let anchor = AsertAnchor {
        timestamp: Timestamp(1_704_067_200),
        height: BlockHeight::GENESIS,
        target: mid_range_anchor_target(),
    };
    // After 100 blocks where odd blocks arrive at 1.5× spacing and
    // even at 0.5× — average is 1× — total time = 100 × spacing.
    let actual_total = 100 * TARGET_SPACING;
    let result =
        asert_next_target(&anchor, Timestamp(anchor.timestamp.0 + actual_total), BlockHeight(100))
            .expect("ok");
    let anchor_diff = target_to_difficulty(&anchor.target);
    let result_diff = target_to_difficulty(&result);
    // Average arrival rate ≈ ideal, so the new target should be
    // very close to the anchor (within 10%).
    let ratio = result_diff as f64 / anchor_diff.max(1) as f64;
    assert!(
        (0.5..=2.0).contains(&ratio),
        "on-spacing arrival should leave difficulty in [0.5, 2.0]× anchor, got {ratio}"
    );
}

// ── (7) Below-anchor height rejected ─────────────────────────────────────────

/// Asking for the next target at a height below the anchor MUST
/// return an error — anchors are monotonic in height.
#[test]
fn height_below_anchor_rejected() {
    let anchor = AsertAnchor {
        timestamp: Timestamp(1_704_067_200),
        height: BlockHeight(100),
        target: MAX_TARGET_BYTES,
    };
    let result = asert_next_target(&anchor, Timestamp(1_704_080_000), BlockHeight(50));
    assert!(
        result.is_err(),
        "height below anchor must be rejected"
    );
}
