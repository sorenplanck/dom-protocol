//! Roadmap v2 Phase 4.1 — IBD adversarial replay framework.
//!
//! `IbdState` is the state machine driving Initial Block Download.
//! It receives header batches from peers and gates the transition
//! from "request more headers" to "download full blocks". A
//! malicious peer can attempt:
//!
//!   1. **Replay attack** — resend a previously-accepted header
//!      batch verbatim.
//!   2. **Gap attack** — submit headers whose `height` jumps over
//!      the next-expected value.
//!   3. **Backwards attack** — submit headers below
//!      `headers_height`.
//!   4. **Out-of-order interleave** — submit a batch that is
//!      internally non-contiguous.
//!   5. **Stale archive flood** — submit an entire historical chain
//!      already accepted, hoping the receiver dedupes by hash but
//!      not by height.
//!   6. **Empty-batch ping** — send `vec![]` repeatedly without
//!      making progress; the state machine MUST NOT advance.
//!   7. **Memory growth via accumulated pending_blocks** — feed
//!      successive valid batches and verify `pending_blocks` is
//!      bounded by the upstream per-message cap (the wire layer
//!      already enforces `MAX_HEADERS_PER_MSG`, but the chain layer
//!      must not blow up if a future refactor loosens it).
//!
//! `IbdState::process_headers` enforces height continuity in a
//! single byte-compare loop (see ibd.rs:82-89). Each test below
//! pins one of the adversarial patterns and asserts the expected
//! outcome.

use dom_chain::ibd::{IbdAction, IbdPhase, IbdState};
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_core::{BlockHeight, Hash256, Timestamp, PROTOCOL_VERSION};
use dom_pow::CompactTarget;
use primitive_types::U256;

fn synth_header(height: u64) -> BlockHeader {
    BlockHeader {
        version: PROTOCOL_VERSION,
        height: BlockHeight(height),
        prev_hash: Hash256::ZERO,
        timestamp: Timestamp(1_704_067_200 + height),
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

fn batch(start: u64, count: u64) -> Vec<BlockHeader> {
    (0..count).map(|i| synth_header(start + i)).collect()
}

// ── (1) Replay attack ────────────────────────────────────────────────────────

/// Resubmitting a batch of headers that the state machine has
/// already accepted MUST fail the continuity check. The second
/// submission's first header height equals the prior first header
/// height, which is < headers_height + 1, so the gap check rejects
/// it immediately.
#[test]
fn replay_of_accepted_batch_rejected_at_continuity_check() {
    let mut ibd = IbdState::new(0, 100);
    ibd.process_headers(batch(1, 10), Timestamp(0))
        .expect("first batch accepts");
    assert_eq!(ibd.headers_height, 10);

    // Same batch again — the first header (height=1) violates
    // continuity (last_height is now 10).
    let err = ibd
        .process_headers(batch(1, 10), Timestamp(0))
        .expect_err("replay must fail continuity check");
    let msg = format!("{err}");
    assert!(
        msg.contains("header gap"),
        "rejection should cite header gap; got: {msg}"
    );
    // State unchanged on rejection.
    assert_eq!(ibd.headers_height, 10);
    assert_eq!(ibd.pending_blocks.len(), 10);
}

// ── (2) Gap attack ───────────────────────────────────────────────────────────

/// Submitting headers whose first height jumps over the
/// next-expected (e.g. peer hands us 50..=100 instead of 11..=60)
/// MUST be rejected and the state MUST be unchanged.
#[test]
fn forward_gap_batch_rejected() {
    let mut ibd = IbdState::new(0, 1000);
    ibd.process_headers(batch(1, 10), Timestamp(0))
        .expect("first 10 accept");
    let err = ibd
        .process_headers(batch(50, 50), Timestamp(0))
        .expect_err("forward gap must reject");
    assert!(format!("{err}").contains("header gap"));
    assert_eq!(ibd.headers_height, 10);
    assert_eq!(ibd.pending_blocks.len(), 10);
}

// ── (3) Backwards attack ─────────────────────────────────────────────────────

/// Headers whose height is below `headers_height` MUST be rejected.
/// `IbdState::process_headers` enforces `height == last_height + 1`,
/// so a backwards batch (height=5 after we're at 10) fails.
#[test]
fn backwards_batch_rejected() {
    let mut ibd = IbdState::new(0, 1000);
    ibd.process_headers(batch(1, 10), Timestamp(0)).unwrap();
    let err = ibd
        .process_headers(batch(5, 3), Timestamp(0))
        .expect_err("backwards batch must reject");
    assert!(format!("{err}").contains("header gap"));
    assert_eq!(ibd.headers_height, 10);
}

// ── (4) Out-of-order interleave ──────────────────────────────────────────────

/// A single batch that is internally non-contiguous (e.g.
/// [height=1, 2, 4, 3, 5]) MUST be rejected on the first gap.
#[test]
fn internally_non_contiguous_batch_rejected() {
    let mut ibd = IbdState::new(0, 1000);
    let bad_batch = vec![
        synth_header(1),
        synth_header(2),
        synth_header(4), // gap!
        synth_header(3),
        synth_header(5),
    ];
    let err = ibd
        .process_headers(bad_batch, Timestamp(0))
        .expect_err("internal gap must reject");
    assert!(format!("{err}").contains("header gap"));
    // State MUST NOT have advanced — the rejection happened
    // mid-batch and the per-batch update is conceptually atomic
    // (last_height is only assigned on the post-loop write to
    // self.headers_height). Verify accordingly.
    assert_eq!(ibd.headers_height, 0);
    assert_eq!(ibd.pending_blocks.len(), 0);
}

// ── (5) Stale archive flood ──────────────────────────────────────────────────

/// A "stale archive" attack — peer sends batches we've already
/// accepted, hoping to balloon pending_blocks. The continuity
/// check fails on the first stale header so pending_blocks does
/// NOT grow.
#[test]
fn stale_archive_does_not_accumulate_pending_blocks() {
    let mut ibd = IbdState::new(0, 1000);
    // Accept 50 headers.
    ibd.process_headers(batch(1, 50), Timestamp(0)).unwrap();
    assert_eq!(ibd.pending_blocks.len(), 50);

    // Attacker resends the first 30 every iteration.
    for _ in 0..10 {
        let _ = ibd.process_headers(batch(1, 30), Timestamp(0));
    }
    // pending_blocks did not grow past the legitimate 50.
    assert_eq!(ibd.pending_blocks.len(), 50);
    assert_eq!(ibd.headers_height, 50);
}

// ── (6) Empty-batch ping ─────────────────────────────────────────────────────

/// Repeated empty batches MUST NOT advance state past the legitimate
/// caught-up point.
#[test]
fn repeated_empty_batches_request_more_headers() {
    let mut ibd = IbdState::new(0, 100);
    let action = ibd.process_headers(vec![], Timestamp(0)).unwrap();
    matches!(action, IbdAction::RequestMoreHeaders(_));
    for _ in 0..10 {
        let action = ibd.process_headers(vec![], Timestamp(0)).unwrap();
        match action {
            IbdAction::RequestMoreHeaders(h) => assert_eq!(h, 0),
            other => panic!("empty batch must request more headers; got {other:?}"),
        }
    }
    assert_eq!(ibd.headers_height, 0);
}

/// Empty batch from a peer who's also at our tip transitions us to
/// the block-download phase (correct happy-path behaviour).
#[test]
fn empty_batch_with_peer_at_our_tip_starts_block_download() {
    let mut ibd = IbdState::new(100, 100);
    // Already complete — but force into Headers phase to exercise
    // the transition.
    ibd.phase = IbdPhase::Headers;
    ibd.headers_height = 100;
    let action = ibd.process_headers(vec![], Timestamp(0)).unwrap();
    assert!(matches!(action, IbdAction::StartBlockDownload));
}

// ── (7) Memory growth bound ──────────────────────────────────────────────────

/// Successive *valid* batches accumulate into `pending_blocks` —
/// that's the design — but only by the legitimate amount the peer
/// has actually been allowed to send. With the wire layer's
/// `MAX_HEADERS_PER_MSG = 2000` cap, 5 successive valid batches
/// would top out at 10_000 pending hashes. Pin the bookkeeping here
/// so a future refactor that loses track of `drain_pending_blocks`
/// is caught.
#[test]
fn legitimate_batches_accumulate_then_drain_correctly() {
    let mut ibd = IbdState::new(0, 10_000);
    for batch_idx in 0..5u64 {
        let start = batch_idx * 2000 + 1;
        ibd.process_headers(batch(start, 2000), Timestamp(0))
            .unwrap();
    }
    assert_eq!(ibd.headers_height, 10_000);
    assert_eq!(ibd.pending_blocks.len(), 10_000);

    // Draining 1000 at a time across 10 rounds empties the queue
    // without losing any hash.
    let mut drained_total = 0usize;
    for _ in 0..10 {
        let drained = ibd.drain_pending_blocks(1000);
        drained_total += drained.len();
    }
    assert_eq!(drained_total, 10_000);
    assert_eq!(ibd.pending_blocks.len(), 0);
    // Idempotent: drain on empty returns empty.
    assert!(ibd.drain_pending_blocks(1000).is_empty());
}

// ── (8) State transition correctness ─────────────────────────────────────────

/// When `headers_height` reaches `best_peer_height`, the next batch
/// (even a partial one that closes the gap exactly) MUST transition
/// the phase to `Blocks` and emit `StartBlockDownload`.
#[test]
fn catching_up_transitions_to_block_download() {
    let mut ibd = IbdState::new(0, 50);
    let action = ibd.process_headers(batch(1, 50), Timestamp(0)).unwrap();
    assert!(matches!(action, IbdAction::StartBlockDownload));
    assert_eq!(ibd.phase, IbdPhase::Blocks);
}

/// `mark_block_committed` advances `blocks_height` monotonically and
/// MUST NOT regress when given a stale height (e.g. a delayed peer
/// response for an earlier block).
#[test]
fn mark_block_committed_is_monotonic() {
    let mut ibd = IbdState::new(0, 100);
    ibd.process_headers(batch(1, 100), Timestamp(0)).unwrap();
    ibd.mark_block_committed(50);
    assert_eq!(ibd.blocks_height, 50);
    // Stale commit — must NOT regress.
    ibd.mark_block_committed(30);
    assert_eq!(ibd.blocks_height, 50);
    // Higher commit — advances.
    ibd.mark_block_committed(100);
    assert_eq!(ibd.blocks_height, 100);
    assert!(ibd.is_complete());
}
