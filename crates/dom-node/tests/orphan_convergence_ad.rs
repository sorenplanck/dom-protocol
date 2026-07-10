//! Orphan-convergence regression tests (fix parts A + D), component level.
//!
//! # The gap these tests reproduce
//!
//! Under an orphan burst / adversary two independent bounds interacted badly:
//!
//!   1. The runtime orphan pool ([`RuntimeOrphanPool`]) is a bounded FIFO. When
//!      a burst of legitimate child blocks (all waiting on the *same* still-missing
//!      parent `P`) exceeds `max_total`, the oldest buffered children are EVICTED.
//!      So when `P` finally arrived there was nothing left buffered to re-feed.
//!
//!   2. The missing-block tracker ([`MissingBlockTracker`]) used to GIVE UP
//!      re-requesting a missing parent after a fixed `max_attempts`. Once that
//!      budget was exhausted `P` was dropped from the tracked set entirely.
//!
//! Combined: the buffered children were evicted (bound 1) AND the parent was no
//! longer being re-requested nor tracked (bound 2). When the true `P` eventually
//! showed up, nothing was buffered and nothing pulled it in — the subtree never
//! converged. It was permanently stranded.
//!
//! # Why these tests prove convergence
//!
//! Part A changed the tracker's contract: a genuinely-missing parent is NEVER
//! dropped for an attempt count. It is re-requested FOREVER with exponential
//! backoff capped at a ceiling (anti-DoS). Therefore, even after the pool has
//! FIFO-evicted every buffered child, `P` remains tracked and keeps being
//! re-requested until it arrives; on arrival `resolve(&P)` yields the dependents
//! so the node re-fetches/re-feeds the evicted subtree (via persistent re-request
//! and, at the network level, the active-resync/IBD path of part D — not exercised
//! here because the existing IBD path is already proven).
//!
//! `test 1` reproduces the eviction (the gap) and then proves the tracker pursues
//! `P` to resolution instead of abandoning it. `test 2` pins the anti-DoS bound
//! (re-request is persistent yet rate-limited — never a per-round flood, never
//! unbounded). `test 3` is the positive no-regression path: a normal single
//! orphan whose parent arrives promptly converges immediately with no eviction
//! and no leftover state.
//!
//! Everything here is deterministic: no sleep, no wall-clock, no randomness. The
//! only clock is the tracker's explicit monotonic round counter.

use dom_node::missing_block_tracker::{MissingBlockTracker, NoteOutcome};
use dom_node::orphan_pool::{OrphanBlock, OrphanInsertOutcome, RuntimeOrphanPool};

/// Deterministic distinct 32-byte hash from a small seed.
fn h(seed: u8) -> [u8; 32] {
    let mut x = [0u8; 32];
    x[0] = seed;
    x
}

/// Construct an orphan child with `body_len` bytes of body (fields are `pub`).
fn child_of(child: u8, parent: [u8; 32], height: u64, body_len: usize) -> OrphanBlock {
    OrphanBlock {
        block_hash: h(child),
        parent_hash: parent,
        height,
        block_bytes: vec![child; body_len],
    }
}

/// THE GAP + CONVERGENCE PROOF.
///
/// A burst of legitimate children all waiting on the same missing parent `P`
/// overflows the small orphan pool and FIFO-evicts real children (the gap). The
/// tracker, however, keeps `P` tracked and re-requests it persistently (part A),
/// so when `P` finally arrives it still yields the dependent subtree — proving
/// the subtree converges instead of being stranded.
#[test]
fn burst_evicts_children_but_parent_reconverges_via_persistent_rerequest() {
    let parent = h(0xAA);

    // Small total cap forces eviction; generous per-parent cap so ONLY the total
    // cap (FIFO eviction) bites, not the per-parent rejection path.
    let mut pool = RuntimeOrphanPool::new(4, 32);

    // Burst of 12 distinct legitimate children, all children of the missing P.
    let mut eviction_seen = false;
    for i in 1u8..=12 {
        let outcome = pool.insert(child_of(i, parent, i as u64, 16));
        match outcome {
            OrphanInsertOutcome::EvictedOldest => eviction_seen = true,
            OrphanInsertOutcome::Inserted => {}
            other => panic!(
                "unexpected insert outcome {:?} for child {} — the per-parent/byte \
                 limits should not fire in this scenario",
                other, i
            ),
        }
    }

    // The gap: legitimate children were evicted by FIFO; the pool is capped.
    assert!(
        eviction_seen,
        "expected at least one EvictedOldest — the burst must overflow max_total=4"
    );
    assert!(
        pool.len() <= 4,
        "pool must stay within max_total=4, got len={}",
        pool.len()
    );

    // The tracker learns P is missing from every rejected child. base=2 backoff,
    // ceiling=8 (anti-DoS cap), max_batch=16.
    let mut tracker = MissingBlockTracker::new(2, 8, 16);
    for i in 1u8..=12 {
        tracker.note_orphan(h(i), parent, Some(i as u64));
    }
    assert!(tracker.is_missing(&parent), "P must be tracked as missing");
    assert_eq!(
        tracker.missing_len(),
        1,
        "all 12 children share the one parent P — exactly one missing entry"
    );

    // Simulate MANY re-request rounds — far beyond any old fixed attempt budget.
    // Advance the tracker clock each round and count how often P is re-requested.
    let rounds = 50u64;
    let mut times_requested = 0usize;
    for _ in 0..rounds {
        let r = tracker.advance_round();
        let batch = tracker.next_request_batch(r);
        if batch.contains(&parent) {
            times_requested += 1;
        }
    }

    // Core part-A fix: P was NEVER dropped. The OLD tracker would have abandoned
    // it after max_attempts and stranded the evicted subtree forever.
    assert!(
        tracker.is_missing(&parent),
        "P must still be tracked after {} rounds — a known-missing parent is never dropped",
        rounds
    );
    // Persistent yet rate-limited: re-requested several times, but backoff throttles
    // it so it is NOT emitted every single round (no flood).
    assert!(
        times_requested >= 3,
        "P must be re-requested persistently (>=3), got {}",
        times_requested
    );
    assert!(
        times_requested < rounds as usize,
        "backoff must throttle re-requests below one-per-round, got {} in {} rounds",
        times_requested,
        rounds
    );

    // Convergence: the true parent P finally arrives. resolve() clears it and
    // returns the dependents the node re-feeds / re-fetches (the evicted subtree
    // is pulled back in via persistent re-request / IBD).
    let dependents = tracker.resolve(&parent);
    assert!(
        !dependents.is_empty(),
        "resolving P must return the dependent orphans waiting on it"
    );
    assert!(
        !tracker.is_missing(&parent),
        "P is no longer missing once resolved"
    );

    // And it is no longer re-requested — the hole is closed.
    let next_round = tracker.advance_round();
    assert!(
        !tracker.next_request_batch(next_round).contains(&parent),
        "resolved parent must not be re-requested again — convergence reached"
    );
}

/// ANTI-DoS PROPERTY: exponential backoff grows then saturates at the ceiling,
/// so persistent re-request is never a per-round flood and never unbounded.
#[test]
fn exponential_backoff_is_capped_so_rerequest_never_floods() {
    let base = 2u64;
    let ceiling = 8u64;
    let mut tracker = MissingBlockTracker::new(base, ceiling, 16);
    tracker.note_orphan(h(0xC1), h(0x07), Some(7));
    let parent = h(0x07);

    // Drive many advancing rounds, recording every round P is actually emitted.
    let mut emit_rounds: Vec<u64> = Vec::new();
    for _ in 0..60 {
        let r = tracker.advance_round();
        if tracker.next_request_batch(r).contains(&parent) {
            emit_rounds.push(r);
        }
    }

    // Need enough emissions to observe the growth-then-saturation profile.
    assert!(
        emit_rounds.len() >= 5,
        "expected multiple emissions to observe backoff growth, got {:?}",
        emit_rounds
    );

    // Gaps between successive emissions: base(2), then double(4), then capped(8..).
    let gaps: Vec<u64> = emit_rounds.windows(2).map(|w| w[1] - w[0]).collect();

    assert_eq!(
        gaps[0], base,
        "first re-request gap must equal base backoff"
    );
    assert_eq!(gaps[1], base * 2, "second gap must double (exponential)");
    assert_eq!(gaps[2], ceiling, "third gap reaches the ceiling");
    for (i, &g) in gaps.iter().enumerate() {
        // Never a per-round flood, never below-base, never above the ceiling.
        assert!(
            g >= base && g <= ceiling,
            "gap[{}] = {} out of bounds [{}, {}] — flood or unbounded backoff",
            i,
            g,
            base,
            ceiling
        );
    }
    // Once saturated it STAYS at the ceiling (bounded forever).
    for (i, &g) in gaps.iter().enumerate().skip(2) {
        assert_eq!(
            g, ceiling,
            "gap[{}] = {} must stay capped at the ceiling {}",
            i, g, ceiling
        );
    }

    // Still tracked — capped backoff means re-request forever, never abandoned.
    assert!(tracker.is_missing(&parent));
}

/// POSITIVE / NO-REGRESSION: a single orphan whose parent arrives promptly
/// converges immediately, with no eviction and no leftover state.
#[test]
fn normal_orphan_operation_parent_arrives_promptly() {
    let parent = h(0x01);
    let child = h(0x02);

    // Ample caps — nothing should be evicted or rejected on the normal path.
    let mut pool = RuntimeOrphanPool::new(1024, 32);
    assert_eq!(
        pool.insert(child_of(0x02, parent, 2, 16)),
        OrphanInsertOutcome::Inserted,
        "single orphan child must be inserted cleanly"
    );
    assert_eq!(pool.len(), 1, "exactly one buffered orphan, no eviction");

    let mut tracker = MissingBlockTracker::new(2, 64, 16);
    assert_eq!(
        tracker.note_orphan(child, parent, Some(1)),
        NoteOutcome::NewlyMissing,
        "the parent is newly discovered missing"
    );
    assert!(
        tracker.next_request_batch(0).contains(&parent),
        "a newly-missing parent is requested immediately"
    );

    // Parent arrives promptly: the pool releases exactly the buffered child and
    // the tracker drains exactly the one dependent — no leftover state anywhere.
    let taken = pool.take_children(&parent);
    assert_eq!(taken.len(), 1, "exactly the one buffered child is released");
    assert_eq!(taken[0].block_hash, child);
    assert!(pool.is_empty(), "pool fully drained after parent arrival");

    let drained = tracker.resolve(&parent);
    assert_eq!(drained, vec![child], "tracker drains the one dependent");
    assert!(
        !tracker.is_missing(&parent),
        "parent no longer missing — normal path converged with no residue"
    );
    assert_eq!(tracker.missing_len(), 0);
}
