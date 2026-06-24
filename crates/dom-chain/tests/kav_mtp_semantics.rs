//! dom-shield KAV-conformância — median-time-past (MTP) semantics vs the
//! Bitcoin reference rule.
//!
//! Attack vector (Lens A: non-conformance with spec): MTP is a consensus rule.
//! Bitcoin's rule (BIP-113 lineage) is: a block's timestamp must be STRICTLY
//! GREATER than the median of the previous 11 block timestamps. Two failure
//! modes silently fork a chain:
//!   1. off-by-one in the median index (window 11 → median is the 6th smallest,
//!      i.e. sorted index 5), and
//!   2. comparison strictness (`>` vs `>=`): accepting equal-to-median blocks
//!      would diverge from a node that rejects them.
//! Plus the early-chain rule: with fewer than 11 ancestors the rule is a no-op.
//!
//! These are known-answer vectors over the production validator
//! `dom_consensus::block::validate_median_time_past`, exercising the exact rule
//! dom-chain wires into connect_block / IBD via `get_recent_timestamps` and
//! `collect_ibd_ancestor_timestamps`. They are NOT covered by the existing
//! difficulty_adjustment.rs MTP test, which only checks one violating case
//! through `validate_header_only` (a single rejecting sample, no median-index
//! or boundary KAV).

use dom_consensus::block::{validate_median_time_past, BlockHeader, ProofOfWork};
use dom_core::{BlockHeight, DomError, Hash256, Timestamp, MEDIAN_TIME_WINDOW, PROTOCOL_VERSION};
use dom_pow::CompactTarget;
use primitive_types::U256;

fn header_at(ts: u64) -> BlockHeader {
    BlockHeader {
        version: PROTOCOL_VERSION,
        height: BlockHeight(100),
        prev_hash: Hash256::ZERO,
        timestamp: Timestamp(ts),
        output_root: Hash256::ZERO,
        kernel_root: Hash256::ZERO,
        rangeproof_root: Hash256::ZERO,
        total_kernel_offset: [0u8; 32],
        target: CompactTarget(0x1f00_ffff),
        total_difficulty: U256::one(),
        pow: ProofOfWork {
            nonce: 0,
            randomx_hash: Hash256::ZERO,
        },
    }
}

fn ts(values: &[u64]) -> Vec<Timestamp> {
    values.iter().copied().map(Timestamp).collect()
}

#[test]
fn mtp_window_is_eleven() {
    // The reference window MUST be 11. If this constant moves, every vector
    // below is computing a different median than a peer on the old constant.
    assert_eq!(MEDIAN_TIME_WINDOW, 11);
}

#[test]
fn mtp_median_is_sorted_index_five() {
    // KAV: 11 ancestors with a known multiset. Sorted ascending, the median is
    // index 5 (the 6th value). Choose values so the *insertion order* differs
    // from sorted order, proving the validator sorts internally.
    // unsorted: 10 100 20 90 30 80 40 70 50 60 55
    // sorted:   10 20 30 40 50 55 60 70 80 90 100  -> median (idx 5) = 55
    let ancestors = ts(&[10, 100, 20, 90, 30, 80, 40, 70, 50, 60, 55]);

    // timestamp == median (55) must be REJECTED (strict greater-than).
    let err = validate_median_time_past(&header_at(55), &ancestors)
        .expect_err("timestamp equal to median must be rejected");
    assert!(matches!(err, DomError::Invalid(_)), "got {err:?}");

    // timestamp == median + 1 (56) must be ACCEPTED.
    validate_median_time_past(&header_at(56), &ancestors)
        .expect("median + 1 must be accepted");

    // timestamp below median (54) must be REJECTED.
    let err = validate_median_time_past(&header_at(54), &ancestors)
        .expect_err("below median must be rejected");
    assert!(matches!(err, DomError::Invalid(_)), "got {err:?}");
}

#[test]
fn mtp_strict_greater_than_boundary() {
    // All-equal ancestors: median == 1000. Boundary KAV around strictness.
    let ancestors = ts(&[1000; 11]);
    assert!(
        validate_median_time_past(&header_at(1000), &ancestors).is_err(),
        "== median must reject (Bitcoin uses strict >)"
    );
    assert!(
        validate_median_time_past(&header_at(999), &ancestors).is_err(),
        "< median must reject"
    );
    assert!(
        validate_median_time_past(&header_at(1001), &ancestors).is_ok(),
        "> median must accept"
    );
}

#[test]
fn mtp_uses_only_first_eleven_ancestors() {
    // Supplying MORE than 11 ancestors must not change the median: the rule
    // takes the first 11 in the provided (newest-first) order. Here the first
    // 11 are all 500 (median 500); trailing entries are huge and must be
    // ignored. A bug that median-ed all entries would shift the answer.
    let mut ancestors = ts(&[500; 11]);
    ancestors.extend(ts(&[9_000_000; 20]));
    assert!(
        validate_median_time_past(&header_at(501), &ancestors).is_ok(),
        "501 > median(500) must accept; trailing ancestors must be ignored"
    );
    assert!(
        validate_median_time_past(&header_at(500), &ancestors).is_err(),
        "== median(500) must reject; trailing ancestors must be ignored"
    );
}

#[test]
fn mtp_insufficient_ancestors_is_noop() {
    // Bitcoin/early-chain rule: with fewer than 11 ancestors MTP is not yet
    // enforced. A timestamp of 0 (far below any ancestor) MUST still pass.
    for n in 0..MEDIAN_TIME_WINDOW {
        let ancestors = ts(&vec![1_000_000u64; n]);
        validate_median_time_past(&header_at(0), &ancestors).unwrap_or_else(|e| {
            panic!("with {n} (<11) ancestors MTP must be a no-op, got {e:?}")
        });
    }
}

#[test]
fn mtp_even_padding_does_not_change_median_index() {
    // Differential against a naive "average" or "len/2 on a sorted dedup"
    // implementation. Duplicates in the window must be counted with
    // multiplicity. multiset: ten 1s and one 100 -> sorted idx 5 == 1.
    let ancestors = ts(&[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 100]);
    assert!(
        validate_median_time_past(&header_at(2), &ancestors).is_ok(),
        "median must be 1 (multiplicity counted); 2 > 1 accepts"
    );
    assert!(
        validate_median_time_past(&header_at(1), &ancestors).is_err(),
        "median must be 1; == 1 rejects"
    );
}
