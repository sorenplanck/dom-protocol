//! dom-shield — missing_block_tracker dependents-flood DoS (IBD/orphan sub-area).
//!
//! Regression: the tracker now caps both distinct missing parents and
//! dependents per parent, so orphan floods stay memory-bounded.
//!
//! Existing in-src tests cover: dedup, ordering, backoff, max_attempts drop,
//! and batch bound. NONE assert the dependents-map memory bound — this does.

use dom_node::missing_block_tracker::{MissingBlockTracker, NoteOutcome};

const MAX_DEPENDENTS_PER_PARENT: usize = 256;
const MAX_TRACKED_MISSING_PARENTS: usize = 4096;

/// Distinct orphans against ONE parent are capped: the per-parent dependents
/// set stops growing after the configured bound.
#[test]
fn dependents_per_parent_are_capped() {
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

    let deps = t.dependents_of(&parent);
    assert_eq!(
        deps.len(),
        MAX_DEPENDENTS_PER_PARENT,
        "per-parent dependents set must stay capped under flood"
    );
    assert_eq!(t.missing_len(), 1);
}

/// Distinct fabricated parents are capped so the missing-parent set cannot grow
/// without bound.
#[test]
fn distinct_fake_parents_are_capped() {
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
        MAX_TRACKED_MISSING_PARENTS,
        "distinct fabricated parents must stop at the configured cap"
    );
}

/// Sanity counter-test: request batching remains bounded independently of the
/// memory caps.
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
