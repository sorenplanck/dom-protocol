//! dom-shield proptest-invariante — order/boundary invariants of the
//! publicly reachable chain surfaces.
//!
//! Vectors (Lens A: non-determinism, incorrect-result):
//!  - MTP must be a pure function of the ancestor timestamp MULTISET, not of
//!    arrival order. Two peers feeding the same 11 timestamps in different
//!    orders must reach the same accept/reject verdict, else MTP is a
//!    consensus-divergence (non-determinism) lever.
//!  - `is_synced` is a monotone threshold: it is true iff
//!    tip_height + SYNC_SLACK >= best_peer_height. Pin the exact boundary and
//!    monotonicity so a refactor cannot silently change when a node declares
//!    itself synced (which gates exiting IBD).
//!  - `PersistedIbdState` must round-trip bit-exactly for every snapshot that
//!    satisfies the state-machine invariants the serializer/deserializer agree
//!    on (monotone heights, retry cap, single-direction cursors). Corrupted
//!    persisted state is covered separately (ibd_directed_corruption.rs); this
//!    is the F4 "valid in → identical out" half.
//!
//! NOTE (anti-theater): the prompt also lists `apply_disconnect` UTXO
//! resurrection and `apply_connect` kernel/output uniqueness as proptest
//! candidates. Those functions are PRIVATE to chain_state.rs and only reachable
//! through `promote_heavier_known_tip`, whose UTXO-resurrection and
//! kernel/output-uniqueness behavior is already exercised end-to-end by
//! reorg_equivalence.rs and block_validation_ingress_adversarial.rs. Re-deriving
//! a property harness through the full reorg machinery would duplicate those
//! fixtures without covering a new door, so it is intentionally omitted here.

mod common;

use common::open_test_chain;
use dom_consensus::block::{validate_median_time_past, BlockHeader, ProofOfWork};
use dom_core::{BlockHeight, Hash256, Timestamp, MEDIAN_TIME_WINDOW, PROTOCOL_VERSION};
use dom_chain::{ChainState, IbdInterruption, IbdPhase, PersistedIbdState};
use dom_pow::CompactTarget;
use dom_serialization::{DomDeserialize, DomSerialize};
use primitive_types::U256;
use proptest::prelude::*;
use tempfile::TempDir;

fn fresh_chain() -> (TempDir, ChainState) {
    let dir = TempDir::new().expect("tempdir");
    let chain = open_test_chain(
        dir.path(),
        Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        dom_core::NETWORK_MAGIC_REGTEST,
    )
    .expect("chain open");
    (dir, chain)
}

fn header_at(ts: u64) -> BlockHeader {
    BlockHeader {
        version: PROTOCOL_VERSION,
        height: BlockHeight(50),
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

proptest! {
    /// MTP verdict is invariant under permutation of the ancestor window.
    ///
    /// The validator takes the FIRST `MEDIAN_TIME_WINDOW` ancestors in the
    /// supplied order, then sorts them to take the median. With exactly
    /// MEDIAN_TIME_WINDOW ancestors, any permutation selects the same window, so
    /// the median — and thus the verdict — must be permutation-invariant. (With
    /// MORE than 11 supplied, permutation legitimately changes WHICH 11 are
    /// taken; that is a documented property of the caller's ordering contract,
    /// not of the median itself, so the window is pinned to exactly 11 here.)
    #[test]
    fn mtp_verdict_is_permutation_invariant(
        mut ts in proptest::collection::vec(0u64..1_000_000, MEDIAN_TIME_WINDOW..=MEDIAN_TIME_WINDOW),
        header_ts in 0u64..1_000_000,
        seed in any::<u64>(),
    ) {
        let original: Vec<Timestamp> = ts.iter().copied().map(Timestamp).collect();
        let verdict_a = validate_median_time_past(&header_at(header_ts), &original).is_ok();

        // Deterministic shuffle driven by `seed` (no external rng dependency).
        let mut s = seed | 1;
        for i in (1..ts.len()).rev() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (s >> 33) as usize % (i + 1);
            ts.swap(i, j);
        }
        let shuffled: Vec<Timestamp> = ts.iter().copied().map(Timestamp).collect();
        let verdict_b = validate_median_time_past(&header_at(header_ts), &shuffled).is_ok();

        prop_assert_eq!(verdict_a, verdict_b, "MTP verdict must not depend on ancestor order");
    }

    /// Real `ChainState::is_synced`: true iff tip_height + 10 >= best, and
    /// monotone in tip_height. Drives the actual production method (not a
    /// reimplementation) by setting the public tip_height field.
    #[test]
    fn is_synced_matches_threshold(
        tip in 0u64..1_000_000,
        best in 0u64..1_000_000,
    ) {
        let (_dir, mut chain) = fresh_chain();
        chain.tip_height = BlockHeight(tip);
        let synced = chain.is_synced(best);

        // Exact boundary: at-or-within-10-of best is synced; further is not.
        prop_assert_eq!(synced, tip.saturating_add(10) >= best);
        if best > tip.saturating_add(10) {
            prop_assert!(!synced, "more than 10 behind must not be synced");
        }
        // Monotonicity: a higher tip never goes from synced to not-synced.
        chain.tip_height = BlockHeight(tip.saturating_add(1));
        if synced {
            prop_assert!(chain.is_synced(best), "raising tip must preserve synced");
        }
    }

    /// Any snapshot satisfying the state-machine invariants round-trips bit-exact.
    #[test]
    fn persisted_ibd_state_roundtrips(
        start in 0u64..10_000,
        gap_lp in 0u64..2_000,
        gap_blocks in 0u64..2_000,
        gap_headers in 0u64..2_000,
        best in 0u64..50_000,
        retry in 0u8..=3,
        n_blocks in 0usize..40,
        n_headers in 0usize..40,
        use_blocks in any::<bool>(),
        header_h in 0u64..50_000,
    ) {
        // Enforce monotone heights: start <= last_progress <= blocks <= headers.
        let last_progress = start + gap_lp;
        let blocks = last_progress + gap_blocks;
        let headers = blocks + gap_headers;

        // Single-direction queue invariant (is_round_resumable / serializer):
        // at most one of the two queues is non-empty in a resumable snapshot,
        // and the chosen cursor is within [0, len].
        let (pending_blocks, pending_headers, block_cursor, header_cursor) = if use_blocks {
            let blocks_q: Vec<[u8; 32]> = (0..n_blocks).map(|i| [i as u8; 32]).collect();
            let bc = blocks_q.len() as u32; // cursor == len is valid (<=)
            (blocks_q, Vec::new(), bc, 0u32)
        } else {
            let headers_q: Vec<Vec<u8>> = (0..n_headers).map(|i| vec![i as u8; 8]).collect();
            let hc = headers_q.len() as u32;
            (Vec::new(), headers_q, 0u32, hc)
        };

        let snapshot = PersistedIbdState {
            phase: IbdPhase::BlockSync,
            peer_addr: "127.0.0.1:33369".into(),
            start_height: start,
            best_peer_height: best,
            headers_height: headers,
            blocks_height: blocks,
            last_progress_height: last_progress,
            checkpoint_tip_hash: [0x5A; 32],
            retry_attempts: retry,
            last_interruption: Some(IbdInterruption::Timeout),
            pending_blocks,
            pending_headers,
            block_cursor,
            header_cursor,
            header_cursor_height: header_h,
        };

        let bytes = snapshot.to_bytes().expect("serialize");
        let decoded = PersistedIbdState::from_bytes(&bytes).expect("decode valid snapshot");
        prop_assert_eq!(decoded, snapshot);
    }
}
