//! Canonical runtime lock ordering for the DOM node (Roadmap v2 — TASK 18).
//!
//! The node guards five long-lived subsystems behind `tokio::sync::Mutex`
//! (see [`crate::node::DomNode`]): the peer manager, the chain state, the
//! mempool, the Dandelion++ router, and the optional wallet. Any execution
//! path that needs more than one of these locks *held simultaneously* must
//! acquire them in a single, globally agreed order. If two paths acquire the
//! same pair of locks in opposite orders they can deadlock under contention
//! (classic lock-order inversion).
//!
//! This module pins that canonical order as data ([`LockClass`]) and provides
//! a deterministic checker ([`LockOrderTracker`]) plus a debug assertion
//! helper ([`debug_assert_acquire`]) that callers can use at each acquisition
//! site to prove — in debug and test builds — that the canonical order is
//! respected. It deliberately contains no `unsafe` and no global mutable
//! state: a tracker models the locks held by exactly one execution context.
//!
//! ## Canonical acquisition order
//!
//! Acquire in *strictly increasing* [`LockClass::rank`] order:
//!
//! 1. [`LockClass::Peers`]    — `DomNode::peers`
//! 2. [`LockClass::Chain`]    — `DomNode::chain`
//! 3. [`LockClass::Mempool`]  — `DomNode::mempool`
//! 4. [`LockClass::Dandelion`]— `DomNode::dandelion`
//! 5. [`LockClass::Wallet`]   — `DomNode::wallet`
//!
//! This order was chosen to match the acquisition sequences already present
//! in `node.rs` so that adopting it requires no behavioural change:
//!
//! * **Peer persistence** (`persist_peer_rotation_state`,
//!   `persist_peer_reputation_state`, `advance_peer_rotation_cooldowns`)
//!   reads `peers` then writes through `chain.store` — i.e. `Peers` before
//!   `Chain`. (Today each guard is dropped before the next is taken; the
//!   canonical order keeps the relative ordering correct should they ever be
//!   held together.)
//! * **Block connect / mempool reconciliation**
//!   (`reconcile_mempool_after_connect`, `purge_mempool_confirmed_inputs`,
//!   the future-block drain, the relay/`message_loop` block path) touches
//!   `chain` then `mempool` — i.e. `Chain` before `Mempool`.
//! * **Dandelion stem-timeout promotion** touches `dandelion` then `mempool`
//!   for read-back; `Mempool` is ranked before `Dandelion` so that the
//!   block-connect path (`Chain` → `Mempool`) and the stem path never invert
//!   the `Mempool`/`Dandelion` pair — the stem path must take `Mempool`
//!   first if it ever needs both.
//! * **Wallet** application of a canonical block (`message_loop` wallet scan)
//!   happens after the `chain`/`mempool` work for that block, so `Wallet` is
//!   ranked last.
//!
//! ## IBD / block / mempool / wallet ordering (documented contract)
//!
//! * Initial Block Download and steady-state block connection both run under
//!   `Chain` and, when reconciling, take `Mempool` second — never the reverse.
//! * Wallet rescans run last (`Wallet` highest rank) and must not re-enter
//!   `Chain`/`Mempool` while held.
//! * Peer bookkeeping runs first (`Peers` lowest rank); persisting it through
//!   the store takes `Chain` second.

/// A lockable node subsystem, ordered by its canonical acquisition rank.
///
/// Lower discriminant == acquired earlier. Two locks may only be held at the
/// same time if they are taken in strictly increasing rank order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum LockClass {
    /// `DomNode::peers` — peer manager / rotation / reputation.
    Peers = 0,
    /// `DomNode::chain` — chain state and the backing store.
    Chain = 1,
    /// `DomNode::mempool` — transaction mempool.
    Mempool = 2,
    /// `DomNode::dandelion` — Dandelion++ stem/fluff router.
    Dandelion = 3,
    /// `DomNode::wallet` — optional mining/scan wallet.
    Wallet = 4,
}

impl LockClass {
    /// The canonical acquisition order, lowest rank first.
    pub const CANONICAL_ORDER: [LockClass; 5] = [
        LockClass::Peers,
        LockClass::Chain,
        LockClass::Mempool,
        LockClass::Dandelion,
        LockClass::Wallet,
    ];

    /// Canonical rank. Locks must be acquired in strictly increasing rank.
    #[inline]
    pub const fn rank(self) -> u8 {
        self as u8
    }
}

/// A rejected lock acquisition: taking `attempted` while `already_held` is held
/// would violate the canonical order (`attempted` ranks at or below a held lock).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockOrderViolation {
    /// The lock the caller tried to acquire.
    pub attempted: LockClass,
    /// A currently-held lock whose rank is >= `attempted`'s rank.
    pub already_held: LockClass,
}

impl std::fmt::Display for LockOrderViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "lock-order violation: tried to acquire {:?} (rank {}) while holding {:?} (rank {}); \
             canonical order requires strictly increasing rank",
            self.attempted,
            self.attempted.rank(),
            self.already_held,
            self.already_held.rank(),
        )
    }
}

impl std::error::Error for LockOrderViolation {}

/// Tracks the lock classes held by a single execution context and rejects any
/// acquisition that would break the canonical order.
///
/// This models exactly one task / call stack. It is intentionally *not* a
/// global: callers that want runtime enforcement keep one tracker per task and
/// call [`LockOrderTracker::acquire`] / [`LockOrderTracker::release`] around
/// the real `Mutex::lock().await` calls (typically behind `debug_assert`).
#[derive(Debug, Default, Clone)]
pub struct LockOrderTracker {
    held: Vec<LockClass>,
}

impl LockOrderTracker {
    /// A tracker holding no locks.
    pub fn new() -> Self {
        Self { held: Vec::new() }
    }

    /// The locks currently held, in acquisition order.
    pub fn held(&self) -> &[LockClass] {
        &self.held
    }

    /// True if `class` is currently held by this context.
    pub fn holds(&self, class: LockClass) -> bool {
        self.held.contains(&class)
    }

    /// Record acquisition of `class`, returning an error if doing so would
    /// violate the canonical order.
    ///
    /// Acquisition is rejected when the highest-ranked currently-held lock has
    /// a rank greater than or equal to `class`'s rank. Equal rank is rejected
    /// because re-acquiring an already-held subsystem lock would self-deadlock
    /// a non-reentrant `tokio::sync::Mutex`.
    pub fn acquire(&mut self, class: LockClass) -> Result<(), LockOrderViolation> {
        if let Some(&top) = self.held.last() {
            if class.rank() <= top.rank() {
                return Err(LockOrderViolation {
                    attempted: class,
                    already_held: top,
                });
            }
        }
        self.held.push(class);
        Ok(())
    }

    /// Record release of `class`. Releases need not be ordered; any held copy
    /// is removed. Returns `true` if `class` was held.
    pub fn release(&mut self, class: LockClass) -> bool {
        if let Some(pos) = self.held.iter().rposition(|&c| c == class) {
            self.held.remove(pos);
            true
        } else {
            false
        }
    }
}

/// Whether `sequence` is a legal simultaneous-acquisition order: strictly
/// increasing canonical rank with no repeats.
pub fn is_canonical_acquisition(sequence: &[LockClass]) -> bool {
    let mut tracker = LockOrderTracker::new();
    sequence.iter().all(|&c| tracker.acquire(c).is_ok())
}

/// Debug-only assertion helper for use at real acquisition sites:
/// `debug_assert_acquire(&mut tracker, LockClass::Mempool);`
///
/// Panics in debug/test builds on a canonical-order violation; compiles to a
/// no-op tracker push in release builds. Callers must still
/// [`LockOrderTracker::release`] on drop.
#[inline]
pub fn debug_assert_acquire(tracker: &mut LockOrderTracker, class: LockClass) {
    match tracker.acquire(class) {
        Ok(()) => {}
        Err(violation) => {
            debug_assert!(false, "{violation}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_order_canonical_ranks_are_strictly_increasing() {
        let ranks: Vec<u8> = LockClass::CANONICAL_ORDER
            .iter()
            .map(|c| c.rank())
            .collect();
        assert_eq!(ranks, vec![0, 1, 2, 3, 4]);
        for pair in LockClass::CANONICAL_ORDER.windows(2) {
            assert!(pair[0].rank() < pair[1].rank());
        }
    }

    #[test]
    fn lock_order_full_canonical_sequence_is_accepted() {
        assert!(is_canonical_acquisition(&LockClass::CANONICAL_ORDER));
        let mut tracker = LockOrderTracker::new();
        for &class in &LockClass::CANONICAL_ORDER {
            tracker
                .acquire(class)
                .expect("canonical order must be accepted");
        }
        assert_eq!(tracker.held(), &LockClass::CANONICAL_ORDER);
    }

    #[test]
    fn lock_order_documented_runtime_subsequences_are_accepted() {
        // peer persistence: Peers -> Chain
        assert!(is_canonical_acquisition(&[
            LockClass::Peers,
            LockClass::Chain
        ]));
        // block connect / reconcile: Chain -> Mempool
        assert!(is_canonical_acquisition(&[
            LockClass::Chain,
            LockClass::Mempool
        ]));
        // stem path needing both must take Mempool before Dandelion
        assert!(is_canonical_acquisition(&[
            LockClass::Mempool,
            LockClass::Dandelion
        ]));
        // wallet scan after chain/mempool
        assert!(is_canonical_acquisition(&[
            LockClass::Chain,
            LockClass::Mempool,
            LockClass::Wallet
        ]));
    }

    #[test]
    fn lock_order_inverted_pair_is_rejected() {
        // Chain -> Peers inverts the canonical Peers -> Chain.
        let mut tracker = LockOrderTracker::new();
        tracker.acquire(LockClass::Chain).expect("chain first ok");
        let err = tracker
            .acquire(LockClass::Peers)
            .expect_err("acquiring lower-ranked Peers while holding Chain must be rejected");
        assert_eq!(err.attempted, LockClass::Peers);
        assert_eq!(err.already_held, LockClass::Chain);
        assert!(!is_canonical_acquisition(&[
            LockClass::Chain,
            LockClass::Peers
        ]));
    }

    #[test]
    fn lock_order_mempool_before_chain_is_rejected() {
        // The dangerous inversion of the block-connect path.
        assert!(!is_canonical_acquisition(&[
            LockClass::Mempool,
            LockClass::Chain
        ]));
    }

    #[test]
    fn lock_order_reacquiring_same_class_is_rejected() {
        // tokio::sync::Mutex is not reentrant; re-taking a held class would
        // self-deadlock, so equal rank is rejected too.
        let mut tracker = LockOrderTracker::new();
        tracker.acquire(LockClass::Chain).expect("first ok");
        let err = tracker
            .acquire(LockClass::Chain)
            .expect_err("re-acquiring a held class must be rejected");
        assert_eq!(err.attempted, LockClass::Chain);
        assert_eq!(err.already_held, LockClass::Chain);
    }

    #[test]
    fn lock_order_release_allows_reacquisition_in_order() {
        // The reconcile pattern: Chain (drop) Mempool (drop) Chain again.
        let mut tracker = LockOrderTracker::new();
        tracker.acquire(LockClass::Chain).expect("chain ok");
        assert!(tracker.release(LockClass::Chain));
        tracker.acquire(LockClass::Mempool).expect("mempool ok");
        assert!(tracker.release(LockClass::Mempool));
        tracker
            .acquire(LockClass::Chain)
            .expect("chain reacquire after full release is fine");
        assert_eq!(tracker.held(), &[LockClass::Chain]);
    }

    #[test]
    fn lock_order_release_of_unheld_class_is_false() {
        let mut tracker = LockOrderTracker::new();
        assert!(!tracker.release(LockClass::Wallet));
    }

    #[test]
    fn lock_order_debug_assert_acquire_pushes_on_success() {
        let mut tracker = LockOrderTracker::new();
        debug_assert_acquire(&mut tracker, LockClass::Peers);
        debug_assert_acquire(&mut tracker, LockClass::Chain);
        assert_eq!(tracker.held(), &[LockClass::Peers, LockClass::Chain]);
    }
}
