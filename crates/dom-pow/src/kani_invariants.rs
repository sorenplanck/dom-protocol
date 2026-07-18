//! Kani proofs for PoW boundary decisions and the RandomX seed schedule.

use crate::{
    classify_asert_exponent_seconds, classify_compact_target, classify_pow_validation_mode,
    hash_meets_target, randomx_seed_height, AsertExponentClassification,
    CompactTargetClassification, PowModeClassification, RANDOMX_SEED_INTERVAL, RANDOMX_SEED_OFFSET,
};
use dom_core::{
    NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET, TARGET_SPACING,
};

#[kani::proof]
fn randomx_seed_height_matches_the_rfc_schedule_for_every_height() {
    let height: u64 = kani::any();
    let epoch = height / RANDOMX_SEED_INTERVAL;
    let expected = if epoch == 0 {
        0
    } else {
        epoch * RANDOMX_SEED_INTERVAL - RANDOMX_SEED_OFFSET
    };
    kani::assert(
        randomx_seed_height(height) == expected,
        "the seed height must match RFC-0011 for every u64 height",
    );
}

#[kani::proof]
fn nonzero_randomx_epochs_always_select_an_earlier_seed() {
    let height: u64 = kani::any();
    kani::assume(height >= RANDOMX_SEED_INTERVAL);
    let seed_height = randomx_seed_height(height);
    kani::assert(
        seed_height < height,
        "the seed must precede its candidate block",
    );
    kani::assert(
        seed_height % RANDOMX_SEED_INTERVAL == RANDOMX_SEED_INTERVAL - RANDOMX_SEED_OFFSET,
        "every nonzero epoch seed must use the frozen offset",
    );
}

#[kani::proof]
fn target_acceptance_is_exactly_inclusive_big_endian_order() {
    let hash: [u8; 32] = kani::any();
    let target: [u8; 32] = kani::any();
    kani::assert(
        hash_meets_target(&hash, &target) == (hash <= target),
        "PoW acceptance must be exactly hash <= target",
    );
}

#[kani::proof]
fn compact_target_frontier_classification_is_exact_for_every_u32() {
    let bits: u32 = kani::any();
    let expected = if bits & 0x007f_ffff == 0 {
        CompactTargetClassification::Zero
    } else if bits & 0x0080_0000 != 0 {
        CompactTargetClassification::Negative
    } else if bits >> 24 > 32 {
        CompactTargetClassification::ExponentTooLarge
    } else {
        CompactTargetClassification::Candidate
    };
    kani::assert(
        classify_compact_target(bits) == expected,
        "compact target shape classification must be exact",
    );
}

#[kani::proof]
fn asert_protocol_exponent_is_exact_over_all_timestamps_and_heights() {
    let anchor_timestamp: u64 = kani::any();
    let block_timestamp: u64 = kani::any();
    let anchor_height: u64 = kani::any();
    let block_height: u64 = kani::any();
    let expected = match block_height.checked_sub(anchor_height) {
        None => AsertExponentClassification::HeightBeforeAnchor,
        Some(height_diff) => AsertExponentClassification::Valid(
            (i128::from(block_timestamp) - i128::from(anchor_timestamp))
                - i128::from(height_diff) * i128::from(TARGET_SPACING),
        ),
    };
    kani::assert(
        classify_asert_exponent_seconds(
            anchor_timestamp,
            block_timestamp,
            anchor_height,
            block_height,
            TARGET_SPACING,
        ) == expected,
        "the protocol ASERT exponent must not wrap or sign-invert",
    );
}

#[kani::proof]
fn pow_mode_selection_is_exact_and_unknown_networks_fail_closed() {
    let network: u32 = kani::any();
    let test_mode: bool = kani::any();
    let fast_requested: bool = kani::any();
    let known = network == NETWORK_MAGIC_MAINNET
        || network == NETWORK_MAGIC_TESTNET
        || network == NETWORK_MAGIC_REGTEST;
    let expected = if !known {
        PowModeClassification::RejectUnknown
    } else if test_mode || network == NETWORK_MAGIC_REGTEST {
        PowModeClassification::FastDevOnly
    } else if fast_requested {
        PowModeClassification::RejectFastPublic
    } else {
        PowModeClassification::RandomX
    };
    kani::assert(
        classify_pow_validation_mode(network, test_mode, fast_requested) == expected,
        "PoW mode selection must be exact and fail closed for unknown networks",
    );
}
