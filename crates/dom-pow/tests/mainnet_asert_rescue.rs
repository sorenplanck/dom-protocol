//! Regression coverage for the mainnet ASERT rescue at height 4849.
//!
//! These tests model a small RandomX network whose hashrate disappears and
//! later returns abruptly.  They deliberately use only the public consensus
//! helpers, so a miner and a validator exercise identical target selection.

use dom_core::{BlockHeight, Timestamp, NETWORK_MAGIC_MAINNET, TARGET_SPACING};
use dom_pow::{
    asert_anchor_for_network_height, compute_expected_target, pow_params_for_network_at_height,
    target_to_difficulty_for_network_height, CompactTarget, MAINNET_ASERT_RESCUE_HEIGHT,
    MAINNET_ASERT_RESCUE_MAX_COMPACT_TARGET,
};
use primitive_types::U256;

fn value(target: [u8; 32]) -> U256 {
    U256::from_big_endian(&target)
}

#[test]
fn rescue_is_height_gated_and_preserves_pre_activation_history() {
    let before = BlockHeight(MAINNET_ASERT_RESCUE_HEIGHT - 1);
    let after = BlockHeight(MAINNET_ASERT_RESCUE_HEIGHT);
    let old = pow_params_for_network_at_height(NETWORK_MAGIC_MAINNET, before).unwrap();
    let new = pow_params_for_network_at_height(NETWORK_MAGIC_MAINNET, after).unwrap();

    assert_eq!(old.max_compact_target, old.genesis_target_compact);
    assert_eq!(
        new.max_compact_target,
        MAINNET_ASERT_RESCUE_MAX_COMPACT_TARGET
    );
    assert_eq!(new.half_life, TARGET_SPACING * 10);
    assert_eq!(
        asert_anchor_for_network_height(NETWORK_MAGIC_MAINNET, after)
            .unwrap()
            .height
            .0,
        before.0
    );
}

#[test]
fn one_hour_without_a_block_relaxes_enough_to_restart_a_small_network() {
    let height = BlockHeight(MAINNET_ASERT_RESCUE_HEIGHT);
    let anchor = asert_anchor_for_network_height(NETWORK_MAGIC_MAINNET, height).unwrap();
    let baseline = anchor.target;
    // One normal spacing plus one hour of no block: exponent is exactly three
    // rescue half-lives, so target grows by about 8x before compact rounding.
    let delayed = compute_expected_target(
        NETWORK_MAGIC_MAINNET,
        Timestamp(anchor.timestamp.0 + TARGET_SPACING + 3 * TARGET_SPACING * 10),
        height,
    )
    .unwrap();

    assert!(
        value(delayed) >= value(baseline) * U256::from(7u8),
        "one-hour target must be about 8x easier: baseline={} delayed={} max={}",
        value(baseline),
        value(delayed),
        value(
            CompactTarget(MAINNET_ASERT_RESCUE_MAX_COMPACT_TARGET)
                .to_target()
                .unwrap()
        )
    );
    assert!(
        value(delayed)
            <= value(
                CompactTarget(MAINNET_ASERT_RESCUE_MAX_COMPACT_TARGET)
                    .to_target()
                    .unwrap()
            )
    );
    assert!(
        target_to_difficulty_for_network_height(NETWORK_MAGIC_MAINNET, height, &delayed).unwrap()
            >= 16,
        "post-rescue total-work accounting must use the wider target envelope"
    );
}

#[test]
fn abrupt_hashrate_exit_then_return_converges_without_a_manual_reset() {
    let first = BlockHeight(MAINNET_ASERT_RESCUE_HEIGHT);
    let anchor = asert_anchor_for_network_height(NETWORK_MAGIC_MAINNET, first).unwrap();
    let baseline = anchor.target;

    // Hashrate exits: the first block is one hour late.
    let late_time = anchor.timestamp.0 + TARGET_SPACING + 3 * TARGET_SPACING * 10;
    let after_exit =
        compute_expected_target(NETWORK_MAGIC_MAINNET, Timestamp(late_time), first).unwrap();
    assert!(value(after_exit) > value(baseline));

    // Hashrate returns: 30 rapid blocks make cumulative elapsed time only 30 s
    // ahead of the ideal schedule.  ASERT returns close to baseline rather
    // than remaining at the easy floor or requiring an operator intervention.
    let return_height = BlockHeight(first.0 + 30);
    let after_return = compute_expected_target(
        NETWORK_MAGIC_MAINNET,
        Timestamp(late_time + 30),
        return_height,
    )
    .unwrap();
    assert!(value(after_return) >= value(baseline));
    assert!(value(after_return) <= value(baseline) * U256::from(2u8));
}

#[test]
fn abrupt_hashrate_entry_hardens_instead_of_sticking_to_the_easy_floor() {
    let first = BlockHeight(MAINNET_ASERT_RESCUE_HEIGHT);
    let anchor = asert_anchor_for_network_height(NETWORK_MAGIC_MAINNET, first).unwrap();
    let burst_height = BlockHeight(first.0 + 20);
    // Twenty blocks arrive in 20 seconds rather than 40 minutes.
    let target = compute_expected_target(
        NETWORK_MAGIC_MAINNET,
        Timestamp(anchor.timestamp.0 + 20),
        burst_height,
    )
    .unwrap();
    assert!(value(target) < value(anchor.target));
}
