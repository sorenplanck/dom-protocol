//! Deterministic missing-block re-request tracking (Roadmap v2 — TASK 09).
//!
//! When `ChainState::connect_block` rejects a block with `DomError::Orphan`
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
//!     canonical order (ascending height, then hash), bounded by `max_batch`,
//!     with per-hash **exponential backoff** (base doubling each attempt, capped
//!     at a ceiling) so no hash is re-requested until its current backoff has
//!     elapsed. This is what the node turns into `GetBlockData` requests.
//!
//! ## Persistent re-request (FIX orphan-convergence, part A)
//!
//! A parent that is genuinely missing — it was referenced by a real orphan
//! block a peer delivered — is **never abandoned**. Earlier this tracker dropped
//! a hash after a fixed `max_attempts`, so under a burst that evicted the
//! buffered orphan child *and* exhausted the re-request budget, the subtree
//! could never converge when the parent finally arrived. Now a known-missing
//! parent stays tracked and is re-requested forever, but the interval grows
//! exponentially up to `max_backoff_rounds`. That ceiling is the anti-DoS
//! bound: each hash is asked at most once per `max_backoff_rounds`, so a large
//! orphan graph cannot turn persistent re-request into a flood. The hard
//! convergence guarantee for holes that exceed the memory caps below lives in
//! the node's active-resync path (part D), which rebuilds the gap via IBD.
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

/// Memory bound on distinct missing parents held for re-request. Reaching it
/// means a new missing parent is not registered here — but it is NOT lost to
/// convergence: the node's active-resync path (part D) rebuilds any hole via
/// IBD once it observes a peer ahead of our tip. This cap only bounds the
/// per-hash re-request bookkeeping, never correctness.
const MAX_TRACKED_MISSING_PARENTS: usize = 4096;
/// Memory bound on orphans recorded as waiting on a single parent. Extra
/// dependents beyond this are not recorded here; they still re-converge once
/// the parent's subtree is filled (re-request part A) or rebuilt via IBD
/// (active resync, part D), so the cap never blocks convergence.
const MAX_DEPENDENTS_PER_PARENT: usize = 256;

/// Ceiling on the exponential-backoff doubling exponent, so `1 << shift` cannot
/// overflow and the interval saturates cleanly at `max_backoff_rounds`.
const BACKOFF_SHIFT_CAP: u32 = 20;

/// Exponential backoff interval (in rounds) for a hash requested `attempts`
/// times: `base` after the first request, doubling each subsequent attempt,
/// hard-capped at `ceiling`. Always at least 1 so a requested hash is never
/// re-emitted in the same round.
fn backoff_interval(base: u64, ceiling: u64, attempts: u32) -> u64 {
    let shift = attempts.saturating_sub(1).min(BACKOFF_SHIFT_CAP);
    let interval = base.saturating_mul(1u64 << shift);
    interval.min(ceiling.max(1)).max(1)
}

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
    /// First-request backoff interval, in rounds. The interval doubles each
    /// subsequent attempt up to `max_backoff_rounds`.
    base_backoff_rounds: u64,
    /// Hard ceiling on the per-hash re-request interval (rounds). Bounds the
    /// request rate of a never-abandoned parent (anti-DoS).
    max_backoff_rounds: u64,
    /// Maximum hashes returned by a single `next_request_batch` call.
    max_batch: usize,
    /// Monotonic re-request clock. Advanced by [`Self::advance_round`] on the
    /// node's periodic re-request tick (a fixed cadence), never by orphan
    /// arrival — so an orphan burst cannot shrink the effective backoff and turn
    /// re-request into a storm.
    round: u64,
}

impl MissingBlockTracker {
    /// Create an empty tracker.
    ///
    /// * `base_backoff_rounds` — rounds before the *first* re-request of a hash;
    ///   the interval then doubles each attempt (0 -> 1).
    /// * `max_backoff_rounds` — ceiling on the per-hash re-request interval, so a
    ///   never-abandoned parent is asked at most once per this many rounds
    ///   (anti-DoS bound; 0 -> 1).
    /// * `max_batch` — cap on hashes emitted per round (storm control; 0 -> 1).
    ///
    /// A known-missing parent is **never dropped for exceeding an attempt count**
    /// (part A): it is re-requested indefinitely with the capped exponential
    /// backoff above. Starts empty by design — see the restart policy in the
    /// module docs.
    pub fn new(base_backoff_rounds: u64, max_backoff_rounds: u64, max_batch: usize) -> Self {
        MissingBlockTracker {
            missing: BTreeMap::new(),
            key_by_hash: BTreeMap::new(),
            dependents: BTreeMap::new(),
            base_backoff_rounds: base_backoff_rounds.max(1),
            max_backoff_rounds: max_backoff_rounds.max(1),
            max_batch: max_batch.max(1),
            round: 0,
        }
    }

    /// The current re-request clock value, without advancing it. Used at orphan
    /// ingress to request a newly-missing parent immediately (it has never been
    /// requested, so it is eligible at any round) without perturbing the backoff
    /// cadence of already-tracked parents.
    pub fn current_round(&self) -> u64 {
        self.round
    }

    /// Advance the re-request clock by one tick and return the new value. Called
    /// on the node's periodic re-request tick; this is the only thing that moves
    /// backoff forward, keeping the cadence independent of orphan-arrival rate.
    pub fn advance_round(&mut self) -> u64 {
        self.round = self.round.saturating_add(1);
        self.round
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
        if self.key_by_hash.contains_key(&parent) {
            let dependents = self.dependents.entry(parent).or_default();
            if dependents.len() < MAX_DEPENDENTS_PER_PARENT {
                dependents.insert(orphan);
            }
            return NoteOutcome::AlreadyMissing;
        }
        if self.missing.len() >= MAX_TRACKED_MISSING_PARENTS {
            return NoteOutcome::AlreadyMissing;
        }
        let mut dependents = BTreeSet::new();
        dependents.insert(orphan);
        self.dependents.insert(parent, dependents);
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
    /// A hash is eligible when it has never been requested, or its current
    /// exponential-backoff interval has elapsed since
    /// its last request. Emitted hashes have their attempt count incremented and
    /// `last_requested_round` set to `round`, so a second call in the same round
    /// returns nothing for them (storm control).
    ///
    /// **A known-missing parent is never dropped here** — no attempt ceiling
    /// abandons it (part A). It stays tracked and eligible again once its
    /// (growing, capped) backoff elapses, until [`Self::resolve`] clears it on
    /// the parent's arrival. This is what guarantees a subtree still converges
    /// after its buffered orphan child was evicted under load.
    pub fn next_request_batch(&mut self, round: u64) -> Vec<[u8; 32]> {
        let base = self.base_backoff_rounds;
        let ceiling = self.max_backoff_rounds;
        let max_batch = self.max_batch;
        let mut batch = Vec::new();

        for (key, state) in self.missing.iter_mut() {
            if batch.len() >= max_batch {
                break;
            }
            let eligible = match state.last_requested_round {
                None => true,
                Some(last) => {
                    round.saturating_sub(last) >= backoff_interval(base, ceiling, state.attempts)
                }
            };
            if !eligible {
                continue;
            }
            batch.push(key.hash);
            state.attempts = state.attempts.saturating_add(1);
            state.last_requested_round = Some(round);
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
        let mut t = MissingBlockTracker::new(2, 64, 16);
        let outcome = t.note_orphan(h(0x10), h(0x01), Some(5));
        assert_eq!(outcome, NoteOutcome::NewlyMissing);
        assert!(t.is_missing(&h(0x01)));
        let batch = t.next_request_batch(0);
        assert_eq!(batch, vec![h(0x01)]);
    }

    #[test]
    fn duplicate_missing_parent_does_not_trigger_unbounded_requests() {
        let mut t = MissingBlockTracker::new(4, 64, 16);
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
        let mut t = MissingBlockTracker::new(1, 64, 16);
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
        let mut t = MissingBlockTracker::new(2, 64, 16);
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
            let mut t = MissingBlockTracker::new(2, 64, 16);
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
        let mut t = MissingBlockTracker::new(2, 64, 16);
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
        let mut t = MissingBlockTracker::new(10, 64, 2);
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
    fn known_parent_is_never_dropped_and_backs_off_exponentially() {
        // Part A: a known-missing parent is re-requested forever, with the
        // interval doubling each attempt up to the ceiling. It is NEVER dropped
        // for an attempt count — the old "give up after max_attempts" behavior
        // that could strand an evicted subtree is gone.
        let base = 2u64;
        let ceiling = 16u64;
        let mut t = MissingBlockTracker::new(base, ceiling, 16);
        t.note_orphan(h(0xC1), h(0x07), Some(7));

        // First request at round 0 (never requested -> eligible). attempts -> 1.
        assert_eq!(t.next_request_batch(0), vec![h(0x07)]);
        // Backoff after attempt 1 = base * 2^0 = 2 rounds: not eligible at 1,
        // eligible again at 2. attempts -> 2.
        assert!(t.next_request_batch(1).is_empty());
        assert_eq!(t.next_request_batch(2), vec![h(0x07)]);
        // Backoff after attempt 2 = base * 2^1 = 4 rounds: eligible at 2+4 = 6.
        assert!(t.next_request_batch(5).is_empty());
        assert_eq!(t.next_request_batch(6), vec![h(0x07)]);
        // After many attempts the interval saturates at the ceiling (16), and
        // the hash is STILL tracked and STILL re-requested — never abandoned.
        let mut round = 6u64;
        for _ in 0..20 {
            round += ceiling; // always at least one ceiling-interval later
            assert_eq!(
                t.next_request_batch(round),
                vec![h(0x07)],
                "known parent must keep being re-requested indefinitely"
            );
        }
        assert!(t.is_missing(&h(0x07)), "known parent is never dropped");
    }

    #[test]
    fn backoff_interval_doubles_then_saturates_at_ceiling() {
        // attempts 0 (never requested) is treated as immediately eligible by
        // next_request_batch; the interval formula covers attempts >= 1.
        assert_eq!(backoff_interval(2, 16, 1), 2); // base * 2^0
        assert_eq!(backoff_interval(2, 16, 2), 4); // base * 2^1
        assert_eq!(backoff_interval(2, 16, 3), 8); // base * 2^2
        assert_eq!(backoff_interval(2, 16, 4), 16); // base * 2^3 = 16, at ceiling
        assert_eq!(backoff_interval(2, 16, 5), 16); // saturated at ceiling
        assert_eq!(backoff_interval(2, 16, 1000), 16); // no overflow, still capped
    }

    #[test]
    fn resolve_of_unrequested_hash_is_empty_and_harmless() {
        let mut t = MissingBlockTracker::new(2, 64, 16);
        assert!(t.resolve(&h(0xEE)).is_empty());
        assert_eq!(t.missing_len(), 0);
    }

    #[test]
    fn distinct_missing_parents_are_capped() {
        let mut t = MissingBlockTracker::new(1, 64, 16);
        for i in 0..(MAX_TRACKED_MISSING_PARENTS + 100) {
            let mut parent = [0u8; 32];
            parent[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            t.note_orphan([0xBBu8; 32], parent, Some(i as u64));
        }
        assert_eq!(t.missing_len(), MAX_TRACKED_MISSING_PARENTS);
    }

    #[test]
    fn dependents_per_parent_are_capped() {
        let mut t = MissingBlockTracker::new(1, 64, 16);
        let parent = h(0xAA);
        for i in 0..(MAX_DEPENDENTS_PER_PARENT + 100) {
            let mut orphan = [0u8; 32];
            orphan[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            t.note_orphan(orphan, parent, Some(100));
        }
        assert_eq!(t.dependents_of(&parent).len(), MAX_DEPENDENTS_PER_PARENT);
    }
}
