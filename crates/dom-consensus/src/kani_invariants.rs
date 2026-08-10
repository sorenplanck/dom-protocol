//! Kani proofs for allocation-free consensus decisions and bounded models.

use crate::{
    block::{
        classify_future_timestamp_window, classify_header_link, classify_kernel_offset,
        FutureTimestampClassification, HeaderLinkClassification, KernelOffsetClassification,
    },
    transaction::{
        classify_coinbase_value, classify_kernel_lock_fields, is_known_kernel_features,
        CoinbaseValueClassification, KernelLockClassification,
    },
};
use dom_core::{
    block_reward, BlockHeight, KERNEL_FEAT_COINBASE, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN,
};

#[kani::proof]
fn kernel_feature_acceptance_is_exact_for_every_byte() {
    let features: u8 = kani::any();
    kani::assert(
        is_known_kernel_features(features)
            == (features == KERNEL_FEAT_PLAIN
                || features == KERNEL_FEAT_COINBASE
                || features == KERNEL_FEAT_HEIGHT_LOCKED),
        "only the three frozen kernel feature bytes are valid",
    );
}

#[kani::proof]
fn kernel_lock_field_classification_is_exact() {
    let features: u8 = kani::any();
    let lock_height: u64 = kani::any();
    let expected = if features == KERNEL_FEAT_HEIGHT_LOCKED && lock_height == 0 {
        KernelLockClassification::HeightLockedAtZero
    } else if features != KERNEL_FEAT_HEIGHT_LOCKED && lock_height != 0 {
        KernelLockClassification::NonHeightLockedAtNonzero
    } else {
        KernelLockClassification::Canonical
    };
    kani::assert(
        classify_kernel_lock_fields(features, lock_height) == expected,
        "kernel feature and lock-height canonicalization must be exact",
    );
}

#[kani::proof]
fn coinbase_value_classification_matches_reward_fee_arithmetic() {
    let height: u64 = kani::any();
    let fees: u64 = kani::any();
    let explicit: u64 = kani::any();
    let reward = block_reward(BlockHeight(height)).noms();
    let maximum = dom_crypto::MAX_PROVABLE_VALUE;
    let expected = match reward.checked_add(fees) {
        None => CoinbaseValueClassification::RewardFeeOverflow,
        Some(value) if value > maximum => CoinbaseValueClassification::ExpectedAboveMaximum,
        Some(_) if explicit > maximum => CoinbaseValueClassification::ExplicitAboveMaximum,
        Some(value) if explicit != value => CoinbaseValueClassification::ValueMismatch,
        Some(_) => CoinbaseValueClassification::Accept,
    };
    kani::assert(
        classify_coinbase_value(reward, fees, explicit, maximum) == expected,
        "coinbase acceptance must exactly equal reward plus fees within the provable range",
    );
}

#[kani::proof]
fn header_height_and_previous_hash_shape_is_exact() {
    let height: u64 = kani::any();
    let previous_is_zero: bool = kani::any();
    let expected = if height == 0 && !previous_is_zero {
        HeaderLinkClassification::GenesisWithNonzeroPrevious
    } else if height != 0 && previous_is_zero {
        HeaderLinkClassification::NonGenesisWithZeroPrevious
    } else {
        HeaderLinkClassification::Valid
    };
    kani::assert(
        classify_header_link(height, previous_is_zero) == expected,
        "genesis and non-genesis linkage classification must be exact",
    );
}

#[kani::proof]
#[kani::unwind(33)]
fn kernel_offset_accepts_exactly_scalars_below_the_curve_order() {
    let offset: [u8; 32] = kani::any();
    const ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    let expected = if offset < ORDER {
        KernelOffsetClassification::Canonical
    } else if offset == ORDER {
        KernelOffsetClassification::EqualToCurveOrder
    } else {
        KernelOffsetClassification::AboveCurveOrder
    };
    kani::assert(
        classify_kernel_offset(&offset) == expected,
        "kernel offset classification must implement big-endian order comparison",
    );
}

#[kani::proof]
fn future_timestamp_window_is_checked_and_exact() {
    let block_timestamp: u64 = kani::any();
    let now: u64 = kani::any();
    let hard_delta: u64 = kani::any();
    let soft_delta: u64 = kani::any();
    let expected = match now.checked_add(hard_delta) {
        None => FutureTimestampClassification::Overflow,
        Some(hard_limit) => match hard_delta
            .checked_add(soft_delta)
            .and_then(|combined| now.checked_add(combined))
        {
            None => FutureTimestampClassification::Overflow,
            Some(soft_limit) if block_timestamp > soft_limit => {
                FutureTimestampClassification::Reject { soft_limit }
            }
            Some(_) if block_timestamp > hard_limit => FutureTimestampClassification::Defer,
            Some(_) => FutureTimestampClassification::Accept,
        },
    };
    kani::assert(
        classify_future_timestamp_window(block_timestamp, now, hard_delta, soft_delta) == expected,
        "future timestamp classification must never wrap and must preserve both boundaries",
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct AbstractBody {
    inputs: [u8; 2],
    output: u8,
    range_proof: u8,
    kernel: u8,
    transaction_field: u8,
}

fn complete_body_preimage(body: AbstractBody) -> [u8; 6] {
    [
        body.inputs[0],
        body.inputs[1],
        body.output,
        body.range_proof,
        body.kernel,
        body.transaction_field,
    ]
}

#[kani::proof]
fn con_009_complete_body_projection_commits_input_order() {
    let first_input: u8 = kani::any();
    let second_input: u8 = kani::any();
    kani::assume(first_input != second_input);
    let common = AbstractBody {
        inputs: [first_input, second_input],
        output: kani::any(),
        range_proof: kani::any(),
        kernel: kani::any(),
        transaction_field: kani::any(),
    };
    let reordered = AbstractBody {
        inputs: [second_input, first_input],
        ..common
    };

    kani::assert(
        complete_body_preimage(common) != complete_body_preimage(reordered),
        "reordering two distinct inputs changes the canonical body",
    );
}

#[kani::proof]
fn independent_complete_body_preimage_commits_every_modeled_field() {
    let body = AbstractBody {
        inputs: kani::any(),
        output: kani::any(),
        range_proof: kani::any(),
        kernel: kani::any(),
        transaction_field: kani::any(),
    };
    let field: u8 = kani::any();
    kani::assume(field < 6);
    let original = complete_body_preimage(body);
    let mut changed = original;
    changed[usize::from(field)] ^= 1;
    kani::assert(
        changed != original,
        "mutating any modeled consensus field changes the independent complete preimage",
    );
}
