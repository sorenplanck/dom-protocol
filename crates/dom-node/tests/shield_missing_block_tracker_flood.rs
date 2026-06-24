//! dom-shield — missing_block_tracker dependents-flood DoS (IBD/orphan sub-area).
//!
//! `MissingBlockTracker::note_orphan` records each (orphan -> parent) edge into
//! `dependents: BTreeMap<[u8;32], BTreeSet<[u8;32]>>` with:
//!     self.dependents.entry(parent).or_default().insert(orphan);
//! There is NO cap on:
//!   (a) the number of distinct dependents stored per parent, nor
//!   (b) the number of distinct parents tracked.
//! `next_request_batch` is bounded by `max_batch` (request storm control), and
//! `orphan_pool` separately bounds the stored block BYTES — but the tracker's
//! `dependents` map holds 32-byte hashes with no limit. A peer that streams
//! orphan blocks each pointing at a unique fabricated parent forces the tracker
//! to retain one BTreeSet entry per orphan indefinitely (parents never arrive),
//! and `resolve()` of a fake parent is never called -> unbounded growth.
//!
//! Technique: directed flood + invariant assertion that growth is linear and
//! unbounded (no eviction). This CONFIRMS an uncapped-memory amplification on
//! the tracker side; the mitigation today is the *upstream* `orphan_pool` cap
//! on block bytes, not a cap on the tracker's edge set. Recorded as a finding
//! for human decision (adding a cap touches behaviour / is a fix, not a test).
//!
//! Existing in-src tests cover: dedup, ordering, backoff, max_attempts drop,
//! and batch bound. NONE assert the dependents-map memory bound — this does.

use dom_node::missing_block_tracker::{MissingBlockTracker, NoteOutcome};

/// Distinct orphans against ONE parent accumulate without bound: the per-parent
/// dependents set grows 1:1 with the flood and is never evicted.
#[test]
fn dependents_per_parent_are_uncapped() {
    let mut t = MissingBlockTracker::new(3, 1, 16);
    let parent = [0xAAu8; 32];

    let flood = 50_000usize;
    for i in 0..flood {
        let mut orphan = [0u8; 32];
        orphan[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        let outcome = t.note_orphan(orphan, parent, Some(100));
        // First note registers the parent as missing; the rest are AlreadyMissing
        // but STILL append a dependent edge.
        if i == 0 {
            assert_eq!(outcome, NoteOutcome::NewlyMissing);
        } else {
            assert_eq!(outcome, NoteOutcome::AlreadyMissing);
        }
    }

    // All `flood` distinct orphans are retained against the single parent.
    let deps = t.dependents_of(&parent);
    assert_eq!(
        deps.len(),
        flood,
        "per-parent dependents set is uncapped — grows 1:1 with the flood"
    );
    // The missing-parent count stays 1 (request storm IS bounded) — proving the
    // unboundedness is specifically in the dependents map, not the request set.
    assert_eq!(t.missing_len(), 1);
}

/// Distinct fabricated parents also accumulate without bound: one orphan each,
/// none ever resolved, the missing-parent set grows linearly.
#[test]
fn distinct_fake_parents_are_uncapped() {
    let mut t = MissingBlockTracker::new(3, 1, 16);
    let flood = 50_000usize;
    for i in 0..flood {
        let mut parent = [0u8; 32];
        parent[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        let orphan = [0xBBu8; 32];
        t.note_orphan(orphan, parent, Some(i as u64));
    }
    assert_eq!(
        t.missing_len(),
        flood,
        "distinct fabricated parents accumulate without eviction"
    );
}

/// Sanity counter-test: the REQUEST batch IS bounded (max_batch), so the DoS is
/// memory-only (no request-storm amplification). This isolates the finding.
#[test]
fn request_batch_is_bounded_even_under_parent_flood() {
    let max_batch = 8usize;
    let mut t = MissingBlockTracker::new(3, 1, max_batch);
    for i in 0..1000u64 {
        let mut parent = [0u8; 32];
        parent[0..8].copy_from_slice(&i.to_le_bytes());
        t.note_orphan([0xCCu8; 32], parent, Some(i));
    }
    let batch = t.next_request_batch(1);
    assert!(
        batch.len() <= max_batch,
        "request batch must stay within max_batch ({} > {max_batch})",
        batch.len()
    );
}
