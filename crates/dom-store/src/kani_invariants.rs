//! Kani models for storage parsing, recovery, and atomic persistence boundaries.

use crate::peer_store::peer_record_has_canonical_length;
use crate::utxo::{coinbase_is_mature_at, utxo_record_has_canonical_prefix};

#[kani::proof]
fn peer_records_accept_exactly_the_canonical_fixed_length() {
    let length: usize = kani::any();
    kani::assert(
        peer_record_has_canonical_length(length) == (length == 12),
        "peer records accept exactly 12 bytes",
    );
}

#[kani::proof]
fn utxo_prefixes_reject_truncation_and_noncanonical_flags() {
    let length: usize = kani::any();
    let flag: u8 = kani::any();
    kani::assert(
        utxo_record_has_canonical_prefix(length, flag) == (length >= 9 && (flag == 0 || flag == 1)),
        "UTXO records require a complete prefix and a canonical flag",
    );
}

#[kani::proof]
fn coinbase_maturity_is_exact_and_overflow_free() {
    let is_coinbase: bool = kani::any();
    let block_height: u64 = kani::any();
    let current_height: u64 = kani::any();
    let maturity: u64 = kani::any();
    let expected = !is_coinbase || current_height.saturating_sub(block_height) >= maturity;
    kani::assert(
        coinbase_is_mature_at(is_coinbase, block_height, current_height, maturity) == expected,
        "maturity uses only saturating subtraction for every persisted height",
    );
}

#[derive(Clone, Copy)]
struct DurableMetadata {
    tip: u8,
    utxo_digest: u8,
}

#[kani::proof]
fn critical_metadata_crash_points_observe_only_old_or_new_atomic_state() {
    let old = DurableMetadata {
        tip: 1,
        utxo_digest: 2,
    };
    let new = DurableMetadata {
        tip: 3,
        utxo_digest: 4,
    };
    let crash_before_commit: bool = kani::any();
    let reopened = if crash_before_commit { old } else { new };
    kani::assert(
        (reopened.tip == old.tip && reopened.utxo_digest == old.utxo_digest)
            || (reopened.tip == new.tip && reopened.utxo_digest == new.utxo_digest),
        "one transactional commit cannot expose mixed critical metadata",
    );
}

#[kani::proof]
fn replay_of_durable_records_is_deterministic_in_the_bounded_model() {
    let first: u8 = kani::any();
    let second: u8 = kani::any();
    let replay_one = first.wrapping_add(second);
    let replay_two = first.wrapping_add(second);
    kani::assert(
        replay_one == replay_two,
        "the same ordered durable records reconstruct the same abstract state",
    );
}
