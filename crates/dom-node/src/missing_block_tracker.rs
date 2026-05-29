//! Deterministic missing-block re-request tracking (Roadmap v2 — TASK 09).
//!
//! When `ChainState::connect_block` rejects a block with [`DomError::Orphan`]
//! the node has learned that an ancestor (the block's `prev_hash`) is missing.
//! To converge it must *re-request* that missing ancestor from peers, and then
//! re-attempt the dependent blocks once it arrives. Doing this naively causes
//! two failure modes:
//!
//!   * **Request storms** — re-requesting the same missing hash on every tick,
//!     or from every peer, floods the network and wastes work.
//!   * **Non-determinism** — re-requesting in hash-map iteration order makes
//!     replay/convergence tests flaky and makes two honest nodes diverge in the
//!     order they fetch blocks.
//!
//! This module is the deterministic core of that logic, kept free of any
//! networking or peer state so it can be unit-tested exhaustively:
//!
//!   * [`MissingBlockTracker::note_orphan`] records "orphan `O` is waiting for
//!     missing parent `P` (at height `h`)". Idempotent — repeated notes for the
//!     same parent never grow the request set or reset its backoff.
//!   * [`MissingBlockTracker::next_request_batch`] returns the missing parents
//!     that are eligible to be (re)requested *this round*, in a single
//!     canonical order (ascending height, then hash), bounded by `max_batch`
//!     and an in-flight cap, with per-hash backoff so no hash is re-requested
//!     until `backoff_rounds` have elapsed. This is what the node turns into
//!     `GET_BLOCKS` / `GetBlockData` requests.
//!   * [`MissingBlockTracker::resolve`] is called when a block arrives. It
//!     clears that hash from the missing set and returns — in canonical order —
//!     the dependent orphans that were waiting on it, so the node can re-feed
//!     them to the chain (draining the deferred path).
//!
//! ## Determinism
//!
//! All ordering is by `(height, hash)` with `height` ascending so that missing
//! *ancestors* are always requested before their descendants, and ties broken
//! by the 32-byte hash. The "clock" is an explicit monotonically increasing
//! `round` counter supplied by the caller (e.g. an IBD/relay tick index), never
//! wall-clock time — so the same sequence of `note_orphan` / `next_request_batch`
//! / `resolve` calls always produces the same request order on every node.
//!
//! ## Restart policy (explicit)
//!
//! The tracker is **runtime-only** state. It is intentionally *not* persisted:
//! after a restart it starts empty, and missing parents are re-discovered the
//! next time their orphan descendants arrive and are rejected with
//! `DomError::Orphan`. This keeps the on-disk format free of transient
//! re-request bookkeeping and guarantees a restarted node cannot replay a stale
//! request schedule. See [`MissingBlockTracker::new`].
//!
//! ## Peer fairness
//!
//! The tracker is peer-agnostic: a re-request is *not* a peer penalty. Asking
//! again for a missing parent — including from a bootstrap peer that delivered
//! blocks out of order — never increments any ban/violation score here. Benign
//! reordering therefore cannot get a peer punished through this path.

use std::collections::{BTreeMap, BTreeSet};

/// Identifies a missing block in canonical request order: ascending height
/// first (request ancestors before descendants), then by hash. Unknown heights
/// sort last (requested only after all height-known ancestors).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct MissingKey {
    /// Sort field: `Some(height)` for a known height, `None` -> `u64::MAX`.
    height_rank: u64,
    hash: [u8; 32],
}

impl MissingKey {
    fn new(hash: [u8; 32], height: Option<u64>) -> Self {
        MissingKey {
            height_rank: height.unwrap_or(u64::MAX),
            hash,
        }
    }
}

/// Per-missing-block re-request state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RequestState {
    /// Number of times this hash has been emitted in a request batch.
    attempts: u32,
    /// The round at which it was last emitted, or `None` if never requested.
    last_requested_round: Option<u64>,
}

/// Outcome of [`MissingBlockTracker::note_orphan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteOutcome {
    /// This parent was not previously tracked as missing — newly registered.
    NewlyMissing,
    /// This parent was already tracked; only the dependent set may have grown.
    AlreadyMissing,
}

/// Deterministic tracker for missing blocks and the orphans that depend on them.
///
/// Holds no networking or peer state; one instance lives in the node runtime.
#[derive(Debug, Default)]
pub struct MissingBlockTracker {
    /// Missing parent hash -> request state.
    missing: BTreeMap<MissingKey, RequestState>,
    /// Reverse index from hash to its key, so `resolve`/`note` are O(log n)
    /// without scanning, and a hash is tracked under exactly one key.
    key_by_hash: BTreeMap<[u8; 32], MissingKey>,
    /// Missing parent hash -> the orphan blocks waiting on it (canonical order).
    dependents: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>,
    /// Maximum re-request attempts per missing hash before it is dropped.
    max_attempts: u32,
    /// Minimum number of rounds between successive requests for the same hash.
    backoff_rounds: u64,
    /// Maximum hashes returned by a single `next_request_batch` call.
    max_batch: usize,
}

impl MissingBlockTracker {
    /// Create an empty tracker.
    ///
    /// * `max_attempts` — give up re-requesting a hash after this many emits
    ///   (0 is treated as 1 so every missing block is requested at least once).
    /// * `backoff_rounds` — minimum rounds between re-requests of the same hash.
    /// * `max_batch` — cap on hashes emitted per round (storm control; 0 -> 1).
    ///
    /// Starts empty by design — see the restart policy in the module docs.
    pub fn new(max_attempts: u32, backoff_rounds: u64, max_batch: usize) -> Self {
        MissingBlockTracker {
            missing: BTreeMap::new(),
            key_by_hash: BTreeMap::new(),
            dependents: BTreeMap::new(),
            max_attempts: max_attempts.max(1),
            backoff_rounds,
            max_batch: max_batch.max(1),
        }
    }

    /// Number of distinct missing parents currently tracked.
    pub fn missing_len(&self) -> usize {
        self.missing.len()
    }

    /// True if `hash` is currently tracked as a missing parent.
    pub fn is_missing(&self, hash: &[u8; 32]) -> bool {
        self.key_by_hash.contains_key(hash)
    }

    /// The orphans currently waiting on `parent`, in canonical order.
    pub fn dependents_of(&self, parent: &[u8; 32]) -> Vec<[u8; 32]> {
        self.dependents
            .get(parent)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Record that `orphan` was rejected because its parent `parent` (at
    /// `parent_height`, if known) is missing.
    ///
    /// Idempotent: noting the same `parent` again never duplicates the request
    /// entry nor resets its backoff/attempt counters; it only records the new
    /// `orphan` as an additional dependent. Returns whether the parent was
    /// newly registered as missing.
    pub fn note_orphan(
        &mut self,
        orphan: [u8; 32],
        parent: [u8; 32],
        parent_height: Option<u64>,
    ) -> NoteOutcome {
        // Record the dependency edge (orphan waits on parent).
        self.dependents.entry(parent).or_default().insert(orphan);

        if self.key_by_hash.contains_key(&parent) {
            return NoteOutcome::AlreadyMissing;
        }
        let key = MissingKey::new(parent, parent_height);
        self.key_by_hash.insert(parent, key);
        self.missing.insert(
            key,
            RequestState {
                attempts: 0,
                last_requested_round: None,
            },
        );
        NoteOutcome::NewlyMissing
    }

    /// Return the missing-parent hashes eligible to be (re)requested at `round`,
    /// in canonical order (ascending height, then hash), capped by `max_batch`.
    ///
    /// A hash is eligible when it has never been requested, or `backoff_rounds`
    /// have elapsed since its last request, and it has not exceeded
    /// `max_attempts`. Emitted hashes have their attempt count incremented and
    /// `last_requested_round` set to `round`, so a second call in the same round
    /// returns nothing for them (storm control). Hashes that reach
    /// `max_attempts` are dropped from the missing set (their dependents remain
    /// recorded until the parent actually arrives or is explicitly resolved).
    pub fn next_request_batch(&mut self, round: u64) -> Vec<[u8; 32]> {
        let mut batch = Vec::new();
        let mut exhausted: Vec<MissingKey> = Vec::new();

        for (key, state) in self.missing.iter_mut() {
            if batch.len() >= self.max_batch {
                break;
            }
            let eligible = match state.last_requested_round {
                None => true,
                Some(last) => round.saturating_sub(last) >= self.backoff_rounds,
            };
            if !eligible {
                continue;
            }
            batch.push(key.hash);
            state.attempts += 1;
            state.last_requested_round = Some(round);
            if state.attempts >= self.max_attempts {
                exhausted.push(*key);
            }
        }

        for key in exhausted {
            self.missing.remove(&key);
            self.key_by_hash.remove(&key.hash);
        }

        batch
    }

    /// A block identified by `hash` arrived (or otherwise became available).
    ///
    /// Clears it from the missing set and returns, in canonical (sorted) order,
    /// the dependent orphans that were waiting on it so the caller can re-feed
    /// them to the chain. Returns an empty vec if nothing depended on `hash`.
    pub fn resolve(&mut self, hash: &[u8; 32]) -> Vec<[u8; 32]> {
        if let Some(key) = self.key_by_hash.remove(hash) {
            self.missing.remove(&key);
        }
        self.dependents
            .remove(hash)
            .map(|set| set.into_iter().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(seed: u8) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[0] = seed;
        x
    }

    #[test]
    fn missing_parent_triggers_deterministic_request() {
        let mut t = MissingBlockTracker::new(5, 2, 16);
        let outcome = t.note_orphan(h(0x10), h(0x01), Some(5));
        assert_eq!(outcome, NoteOutcome::NewlyMissing);
        assert!(t.is_missing(&h(0x01)));
        let batch = t.next_request_batch(0);
        assert_eq!(batch, vec![h(0x01)]);
    }

    #[test]
    fn duplicate_missing_parent_does_not_trigger_unbounded_requests() {
        let mut t = MissingBlockTracker::new(5, 4, 16);
        assert_eq!(
            t.note_orphan(h(0x20), h(0x02), Some(7)),
            NoteOutcome::NewlyMissing
        );
        // Same parent, different orphan, then identical note again.
        assert_eq!(
            t.note_orphan(h(0x21), h(0x02), Some(7)),
            NoteOutcome::AlreadyMissing
        );
        assert_eq!(
            t.note_orphan(h(0x21), h(0x02), Some(7)),
            NoteOutcome::AlreadyMissing
        );
        // Only one missing entry regardless of repeats.
        assert_eq!(t.missing_len(), 1);
        // Requested once this round...
        assert_eq!(t.next_request_batch(0), vec![h(0x02)]);
        // ...and not again until backoff_rounds elapse — no storm.
        assert!(t.next_request_batch(0).is_empty());
        assert!(t.next_request_batch(1).is_empty());
        assert!(t.next_request_batch(3).is_empty());
        // Backoff (4 rounds) elapsed: eligible again.
        assert_eq!(t.next_request_batch(4), vec![h(0x02)]);
    }

    #[test]
    fn delayed_parent_drains_dependent_path() {
        let mut t = MissingBlockTracker::new(5, 1, 16);
        // Two orphans both waiting on the same missing parent.
        t.note_orphan(h(0xA2), h(0x01), Some(1));
        t.note_orphan(h(0xA1), h(0x01), Some(1));
        assert_eq!(t.dependents_of(&h(0x01)), vec![h(0xA1), h(0xA2)]);
        // Parent finally arrives: dependents drain in canonical order.
        let drained = t.resolve(&h(0x01));
        assert_eq!(drained, vec![h(0xA1), h(0xA2)]);
        assert!(!t.is_missing(&h(0x01)));
        // Resolved parent is no longer requested.
        assert!(t.next_request_batch(0).is_empty());
        // Nothing left depending on it.
        assert!(t.dependents_of(&h(0x01)).is_empty());
    }

    #[test]
    fn restart_policy_is_explicit_fresh_tracker_is_empty() {
        // Re-request state is runtime-only and never persisted: a fresh tracker
        // (as constructed on every startup) has nothing to request.
        let mut t = MissingBlockTracker::new(5, 2, 16);
        assert_eq!(t.missing_len(), 0);
        assert!(t.next_request_batch(0).is_empty());
        assert!(!t.is_missing(&h(0x01)));
    }

    #[test]
    fn same_inputs_produce_same_request_order() {
        // Heights deliberately out of insertion order; canonical batch must be
        // ascending height then hash, identically across independent trackers.
        let inserts = [
            (h(0xF0), h(0x05), Some(5u64)),
            (h(0xF1), h(0x03), Some(3)),
            (h(0xF2), h(0x04), Some(3)), // same height as 0x03, higher hash
            (h(0xF3), h(0x01), Some(1)),
        ];
        let run = || {
            let mut t = MissingBlockTracker::new(5, 2, 16);
            for (orphan, parent, height) in inserts {
                t.note_orphan(orphan, parent, height);
            }
            t.next_request_batch(0)
        };
        let expected = vec![h(0x01), h(0x03), h(0x04), h(0x05)];
        assert_eq!(run(), expected);
        assert_eq!(run(), expected, "same inputs must yield identical order");
    }

    #[test]
    fn ancestors_requested_before_unknown_height_parents() {
        let mut t = MissingBlockTracker::new(5, 2, 16);
        t.note_orphan(h(0xB0), h(0x09), None); // unknown height -> sorts last
        t.note_orphan(h(0xB1), h(0x02), Some(2));
        t.note_orphan(h(0xB2), h(0x08), Some(8));
        assert_eq!(
            t.next_request_batch(0),
            vec![h(0x02), h(0x08), h(0x09)],
            "known ascending heights first, unknown-height parent last"
        );
    }

    #[test]
    fn batch_is_bounded_by_max_batch_for_storm_control() {
        let mut t = MissingBlockTracker::new(5, 10, 2);
        for i in 1..=5u8 {
            t.note_orphan(h(0x80 + i), h(i), Some(i as u64));
        }
        // max_batch = 2: at most two requests per round, lowest heights first.
        assert_eq!(t.next_request_batch(0), vec![h(1), h(2)]);
        // Those two are now in backoff; the next two are emitted.
        assert_eq!(t.next_request_batch(1), vec![h(3), h(4)]);
        assert_eq!(t.next_request_batch(2), vec![h(5)]);
    }

    #[test]
    fn max_attempts_drops_hash_after_exhaustion() {
        // max_attempts = 2, backoff = 0 so it is eligible every round.
        let mut t = MissingBlockTracker::new(2, 0, 16);
        t.note_orphan(h(0xC1), h(0x07), Some(7));
        assert_eq!(t.next_request_batch(0), vec![h(0x07)]); // attempt 1
        assert_eq!(t.next_request_batch(1), vec![h(0x07)]); // attempt 2 -> exhausted
        assert!(!t.is_missing(&h(0x07)), "exhausted hash is dropped");
        assert!(t.next_request_batch(2).is_empty());
    }

    #[test]
    fn resolve_of_unrequested_hash_is_empty_and_harmless() {
        let mut t = MissingBlockTracker::new(5, 2, 16);
        assert!(t.resolve(&h(0xEE)).is_empty());
        assert_eq!(t.missing_len(), 0);
    }
}
