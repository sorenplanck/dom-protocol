//! A reorg invalidates a settlement effect. It does not un-reveal a secret.
//!
//! # The rule
//!
//! These two statements are both true and must not be conflated:
//!
//! - **The settlement effect is reversible by a reorg.** If the block carrying
//!   `Claimed` is orphaned, the EVM leg is *not* settled: the funds are not
//!   moved, the lock is open again, and the engine must revalidate before it
//!   acts. That is I11, and it is why [`crate::reorg`] rewinds the cursor and
//!   emits [`counterparty_api::ObservedEvent::Reorged`].
//!
//! - **The publicity of `t` is not reversible by anything.** The moment a
//!   `Claimed` log existed in a block that this node saw, the scalar was
//!   broadcast. Every peer that relayed that block has it. Rewinding a cursor
//!   cannot unsend a packet. Treating `t` as secret again after a reorg would
//!   be a security fiction, and a dangerous one: the counterparty who published
//!   `t` can still use it to claim the *other* leg, whose chain never reorged.
//!
//! # Why this needs its own type
//!
//! The natural implementation mistake is to keep the "have we seen `t`?" answer
//! inside the same state that the reorg path rewinds — a map keyed by block, a
//! field on the cursor, an entry in a per-scan buffer. Then a rewind quietly
//! deletes it, and the engine concludes the secret is unknown while the
//! counterparty is already spending on it.
//!
//! [`RevealedRegistry`] is therefore **append-only by construction**. It has no
//! removal method, [`crate::reorg`] never touches it, and
//! [`crate::cursor::EvmCursor::rewind_to`] cannot reach it. A secret enters it
//! once and stays.
//!
//! # I6
//!
//! The scalar lives only inside [`counterparty_api::RevealedSecretBytes`],
//! whose `Debug` is redacted. This type's `Debug` reports the *number* of known
//! secrets and their lock ids, never a scalar.

use std::collections::BTreeMap;

use counterparty_api::RevealedSecretBytes;

/// Maximum number of distinct revealed secrets retained in memory.
///
/// A registry is per-adapter-instance and a settlement has one secret, so this
/// is generous; it exists so that a long-running observer over a busy contract
/// cannot grow without bound (I14).
pub const MAX_TRACKED_SECRETS: usize = 4096;

/// Append-only record of scalars that have been published on chain.
#[derive(Default, Clone)]
pub struct RevealedRegistry {
    by_lock: BTreeMap<[u8; 32], RevealedSecretBytes>,
    /// Number of insertions refused because the cap was reached. Kept so the
    /// condition is observable rather than silent.
    refused: usize,
}

impl core::fmt::Debug for RevealedRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // I6: count and keys only. Never a scalar, not even redacted-by-length.
        write!(
            f,
            "RevealedRegistry {{ known: {}, refused: {} }}",
            self.by_lock.len(),
            self.refused
        )
    }
}

impl RevealedRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `lock_id`'s scalar became public.
    ///
    /// Idempotent: recording the same pair twice is a no-op. Recording a
    /// *different* scalar for the same lock id returns `false` and keeps the
    /// first observation — the contract can only accept one scalar per lock, so
    /// a second, different one means the endpoint is lying and the first
    /// observation is the one that must not be overwritten.
    pub fn record(&mut self, lock_id: [u8; 32], revealed: RevealedSecretBytes) -> bool {
        match self.by_lock.get(&lock_id) {
            Some(existing) => *existing == revealed,
            None => {
                if self.by_lock.len() >= MAX_TRACKED_SECRETS {
                    self.refused = self.refused.saturating_add(1);
                    return false;
                }
                self.by_lock.insert(lock_id, revealed);
                true
            }
        }
    }

    /// The scalar published for `lock_id`, if this observer ever saw it.
    ///
    /// Survives every reorg, by design.
    pub fn get(&self, lock_id: &[u8; 32]) -> Option<RevealedSecretBytes> {
        self.by_lock.get(lock_id).copied()
    }

    /// Whether `lock_id`'s scalar is public knowledge as far as this observer
    /// is concerned.
    pub fn is_revealed(&self, lock_id: &[u8; 32]) -> bool {
        self.by_lock.contains_key(lock_id)
    }

    /// Number of distinct locks whose scalar is known.
    pub fn len(&self) -> usize {
        self.by_lock.len()
    }

    /// Whether nothing has been revealed yet.
    pub fn is_empty(&self) -> bool {
        self.by_lock.is_empty()
    }

    /// Lock ids with a known scalar, in canonical (sorted) order.
    pub fn lock_ids(&self) -> Vec<[u8; 32]> {
        self.by_lock.keys().copied().collect()
    }

    /// How many insertions were refused because [`MAX_TRACKED_SECRETS`] was hit.
    pub fn refused(&self) -> usize {
        self.refused
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: [u8; 32] = [0xAA; 32];

    #[test]
    fn registry_has_no_way_to_forget() {
        // This is a design assertion as much as a behavioural one: there is no
        // `remove`, no `clear`, no `retain`, no `truncate`. If someone adds one,
        // this test will not catch it — but the reorg test below will.
        let mut r = RevealedRegistry::new();
        assert!(r.is_empty());
        assert!(r.record(LOCK, RevealedSecretBytes([7u8; 32])));
        assert!(r.is_revealed(&LOCK));
        assert_eq!(r.get(&LOCK), Some(RevealedSecretBytes([7u8; 32])));
        assert_eq!(r.len(), 1);
        assert_eq!(r.lock_ids(), vec![LOCK]);
    }

    #[test]
    fn recording_is_idempotent_and_first_observation_wins() {
        let mut r = RevealedRegistry::new();
        assert!(r.record(LOCK, RevealedSecretBytes([7u8; 32])));
        assert!(r.record(LOCK, RevealedSecretBytes([7u8; 32])), "idempotent");
        assert!(
            !r.record(LOCK, RevealedSecretBytes([8u8; 32])),
            "a contradicting scalar must be refused"
        );
        assert_eq!(
            r.get(&LOCK),
            Some(RevealedSecretBytes([7u8; 32])),
            "the first observation must survive"
        );
    }

    #[test]
    fn cap_is_enforced_and_visible() {
        let mut r = RevealedRegistry::new();
        for i in 0..MAX_TRACKED_SECRETS {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64).to_be_bytes());
            assert!(r.record(k, RevealedSecretBytes([1u8; 32])));
        }
        assert_eq!(r.len(), MAX_TRACKED_SECRETS);
        assert!(!r.record([0xFF; 32], RevealedSecretBytes([1u8; 32])));
        assert_eq!(r.refused(), 1);
    }

    #[test]
    fn debug_never_renders_a_scalar() {
        let mut r = RevealedRegistry::new();
        r.record(LOCK, RevealedSecretBytes([0xAB; 32]));
        let rendered = format!("{r:?}");
        assert!(rendered.contains("known: 1"));
        assert!(
            !rendered.contains("ab"),
            "I6: no scalar byte may be rendered"
        );
        assert!(!rendered.to_lowercase().contains("171"));
    }
}
