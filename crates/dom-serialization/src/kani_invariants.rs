//! Kani proofs for canonical serialization arithmetic frontiers.

use crate::{
    classify_list_budget, classify_read_advance, length_within_limit, ListBudget, ReadAdvance,
};

#[kani::proof]
fn reader_advance_accepts_exactly_nonoverflowing_in_bounds_ranges() {
    let data_len: usize = kani::any();
    let position: usize = kani::any();
    let count: usize = kani::any();
    let result = classify_read_advance(data_len, position, count);

    match position.checked_add(count) {
        None => kani::assert(
            result == ReadAdvance::Overflow,
            "overflowing cursor arithmetic must be rejected",
        ),
        Some(end) if end > data_len => kani::assert(
            result == ReadAdvance::OutOfBounds,
            "out-of-bounds cursor arithmetic must be rejected",
        ),
        Some(end) => kani::assert(
            result == ReadAdvance::End(end),
            "only an in-bounds cursor advance may be accepted",
        ),
    }
}

#[kani::proof]
fn collection_length_predicate_is_exact_for_every_usize_pair() {
    let declared: usize = kani::any();
    let limit: usize = kani::any();
    kani::assert(
        length_within_limit(declared, limit) == (declared <= limit),
        "collection length acceptance must exactly equal its protocol cap",
    );
}

#[kani::proof]
fn zero_size_list_items_are_always_rejected() {
    let count: usize = kani::any();
    let remaining: usize = kani::any();
    kani::assert(
        classify_list_budget(count, 0, remaining) == ListBudget::ZeroItemSize,
        "zero-size list items must be rejected",
    );
}

#[kani::proof]
fn list_minimum_budget_is_exact_within_the_protocol_message_domain() {
    let count: usize = kani::any();
    let minimum_item_size: usize = kani::any();
    let remaining: usize = kani::any();
    kani::assume(count <= dom_core::MAX_BLOCK_TXS);
    kani::assume(minimum_item_size > 0);
    // Every production `read_list` element type is at most 115 bytes at its
    // canonical minimum (TransactionKernel). Keep 128 as an explicit rounded
    // proof bound; larger synthetic test types exercise the overflow path
    // dynamically.
    kani::assume(minimum_item_size <= 128);

    let required = count
        .checked_mul(minimum_item_size)
        .expect("the explicit Core list bounds exclude usize overflow");
    let result = classify_list_budget(count, minimum_item_size, remaining);
    if required > remaining {
        kani::assert(
            result == ListBudget::Insufficient,
            "a list larger than the remaining input must be rejected",
        );
    } else {
        kani::assert(
            result == ListBudget::Valid(required),
            "an in-bounds list budget must retain its exact byte count",
        );
    }
}

#[kani::proof]
fn fixed_width_little_endian_roundtrips_are_lossless() {
    let value16: u16 = kani::any();
    let value32: u32 = kani::any();
    let value64: u64 = kani::any();
    let value128: u128 = kani::any();

    kani::assert(
        u16::from_le_bytes(value16.to_le_bytes()) == value16,
        "u16 little-endian roundtrip must be exact",
    );
    kani::assert(
        u32::from_le_bytes(value32.to_le_bytes()) == value32,
        "u32 little-endian roundtrip must be exact",
    );
    kani::assert(
        u64::from_le_bytes(value64.to_le_bytes()) == value64,
        "u64 little-endian roundtrip must be exact",
    );
    kani::assert(
        u128::from_le_bytes(value128.to_le_bytes()) == value128,
        "u128 little-endian roundtrip must be exact",
    );
}
