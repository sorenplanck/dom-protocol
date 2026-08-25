//! Reorg detection, common-ancestor search and idempotent rewind (I11).
//!
//! # What a reorg is, here
//!
//! The cursor carries one anchor: the hash of the block just below
//! `next_from_block`. Before scanning anything, the adapter asks the chain for
//! the header at that height. Three outcomes:
//!
//! - same hash → the chain we scanned is still the chain we are on: continue;
//! - different hash, or the block is simply gone → the chain we scanned is no
//!   longer the chain we are on: find the common ancestor, rewind, and report
//!   [`counterparty_api::ObservedEvent::Reorged`];
//! - the endpoint cannot answer → unavailability, not a reorg.
//!
//! # Finding the common ancestor with one anchor
//!
//! One stored hash is not enough to *locate* an ancestor by comparison, so the
//! adapter also keeps a bounded, in-memory ring of `(height, hash)` pairs for
//! the blocks it has actually looked at ([`KnownHeaders`]). That ring is not
//! persisted, which makes the rule set four cases rather than two:
//!
//! 1. the anchor still matches → continuous;
//! 2. the anchor is broken and the ring contains a lower height whose hash the
//!    chain still confirms → that height is the common ancestor. The walk
//!    *skips* heights the ring has no belief about (the ring is sparse: it
//!    holds the blocks that were actually fetched), so the ancestor it names
//!    may be lower than the true fork point. Lower is the safe direction: it
//!    over-reports invalidation and replays more, never less;
//! 3. the anchor is broken and the ring is **empty** — a fresh process reading
//!    a persisted cursor. There is no evidence at all about where the fork is,
//!    so the adapter takes the largest action its declared policy allows: it
//!    rewinds by the full `max_reorg_depth` (clamped to the deployment floor)
//!    and replays that whole window. It deliberately does **not** rewind by one
//!    block and adopt the new chain's hash there, which is the tempting
//!    implementation and is *wrong*: it would silently declare continuity for a
//!    fork that started further down, under-reporting the invalidation;
//! 4. the anchor is broken, the ring is non-empty, and no retained height is
//!    confirmed within `max_reorg_depth` (or the search would go below the
//!    deployment floor) → the reorg is deeper than either the declared
//!    tolerance or the validated history. The adapter cannot name an ancestor
//!    honestly, so it fails closed with [`AdapterError::ReorgDetected`].
//!
//! Case 3 and case 4 differ because the evidence differs. In case 4 we have
//! positive evidence that our validated history was orphaned and we must not
//! pretend otherwise. In case 3 we have no evidence whatsoever, and refusing to
//! act would strand the observer permanently on a cursor it can never advance.
//!
//! # Rewind is idempotent — and does not touch secrets
//!
//! Rewinding only moves `next_from_block`, the anchor and `emitted_high_water`.
//! Re-scanning a range yields exactly the same events for the same chain state,
//! so a rewind followed by a replay is idempotent. What a rewind must **not**
//! do is forget a revealed scalar; that lives in [`crate::revealed`], which
//! nothing in this module can reach.

use std::collections::BTreeMap;

use counterparty_api::AdapterError;

use crate::cursor::EvmCursor;
use crate::error::Result;
use crate::rpc::{EthClient, JsonRpc, RpcBlockHeader};

/// Hard ceiling on `max_reorg_depth`, and on the retained header ring.
///
/// Well past any reorg post-Merge Ethereum can produce below the finalized
/// checkpoint (which is where this adapter scans), and small enough that the
/// ring can never become an allocation problem (I14).
pub const MAX_REORG_DEPTH_CEILING: u32 = 512;

/// Anything the adapter can ask for a header from.
pub trait HeaderSource {
    /// Header at `height`, or `None` when the chain is shorter than that.
    fn header_at(&self, height: u64) -> Result<Option<RpcBlockHeader>>;
}

/// [`HeaderSource`] backed by a JSON-RPC endpoint.
pub struct RpcHeaders<'r, R: JsonRpc + ?Sized> {
    rpc: &'r R,
}

impl<'r, R: JsonRpc + ?Sized> RpcHeaders<'r, R> {
    /// Wraps a transport.
    pub fn new(rpc: &'r R) -> Self {
        Self { rpc }
    }
}

impl<R: JsonRpc + ?Sized> HeaderSource for RpcHeaders<'_, R> {
    fn header_at(&self, height: u64) -> Result<Option<RpcBlockHeader>> {
        EthClient::new(self.rpc).block_by_number(height)
    }
}

/// Bounded memory of block hashes this observer has actually seen.
#[derive(Clone, Debug, Default)]
pub struct KnownHeaders {
    by_height: BTreeMap<u64, [u8; 32]>,
    cap: usize,
}

impl KnownHeaders {
    /// A ring retaining at most `cap` heights (clamped to
    /// [`MAX_REORG_DEPTH_CEILING`]).
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            by_height: BTreeMap::new(),
            cap: cap.clamp(1, MAX_REORG_DEPTH_CEILING as usize),
        }
    }

    /// Records a belief, evicting the oldest height when full.
    pub fn record(&mut self, height: u64, hash: [u8; 32]) {
        self.by_height.insert(height, hash);
        while self.by_height.len() > self.cap {
            let Some(oldest) = self.by_height.keys().next().copied() else {
                break;
            };
            self.by_height.remove(&oldest);
        }
    }

    /// The hash this observer believes is at `height`.
    pub fn get(&self, height: u64) -> Option<[u8; 32]> {
        self.by_height.get(&height).copied()
    }

    /// Lowest retained height.
    pub fn oldest(&self) -> Option<u64> {
        self.by_height.keys().next().copied()
    }

    /// Highest retained height.
    pub fn newest(&self) -> Option<u64> {
        self.by_height.keys().next_back().copied()
    }

    /// Drops every belief strictly above `height` — used after a rewind so the
    /// observer stops asserting things about the orphaned segment.
    pub fn truncate_above(&mut self, height: u64) {
        let doomed: Vec<u64> = self
            .by_height
            .range(height.saturating_add(1)..)
            .map(|(h, _)| *h)
            .collect();
        for h in doomed {
            self.by_height.remove(&h);
        }
    }

    /// Number of retained heights.
    pub fn len(&self) -> usize {
        self.by_height.len()
    }

    /// Whether nothing is retained.
    pub fn is_empty(&self) -> bool {
        self.by_height.is_empty()
    }
}

/// Result of a continuity check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReorgOutcome {
    /// The chain still contains the block the cursor is anchored to.
    Continuous,
    /// The anchor is gone. Everything from `from_height` upwards is invalid,
    /// and scanning must resume at `from_height`.
    Reorg {
        /// First invalidated height; also the next block to re-scan.
        from_height: u64,
        /// Hash of `from_height - 1`, the new anchor. All-zero when the rewind
        /// reached the deployment floor and there is nothing to anchor to.
        anchor: [u8; 32],
    },
}

/// Checks whether the cursor's anchor is still on the canonical chain.
///
/// `floor` is the deployment's start block: the rewind never resumes below it.
pub fn detect<H: HeaderSource + ?Sized>(
    headers: &H,
    known: &KnownHeaders,
    cursor: &EvmCursor,
    floor: u64,
    max_reorg_depth: u32,
) -> Result<ReorgOutcome> {
    let Some(last_h) = cursor.last_seen_height() else {
        // No anchor: nothing has been scanned yet, so nothing can be orphaned.
        return Ok(ReorgOutcome::Continuous);
    };
    if let Some(h) = headers.header_at(last_h)? {
        if h.hash == cursor.last_seen_block_hash {
            return Ok(ReorgOutcome::Continuous);
        }
    }
    if max_reorg_depth == 0 || max_reorg_depth > MAX_REORG_DEPTH_CEILING {
        return Err(AdapterError::ReorgDetected);
    }
    let (from_height, anchor) = if known.is_empty() {
        conservative_rewind(headers, last_h, floor, max_reorg_depth)?
    } else {
        confirmed_ancestor(headers, known, last_h, floor, max_reorg_depth)?
    };
    Ok(ReorgOutcome::Reorg {
        from_height,
        anchor,
    })
}

/// Case 3: no retained history. Rewind by the full declared tolerance.
fn conservative_rewind<H: HeaderSource + ?Sized>(
    headers: &H,
    last_h: u64,
    floor: u64,
    max_reorg_depth: u32,
) -> Result<(u64, [u8; 32])> {
    let target_last = last_h.saturating_sub(u64::from(max_reorg_depth));
    if target_last < floor {
        // The whole scan window is suspect: replay it from the floor, with no
        // anchor (there is nothing below the floor we are willing to trust).
        return Ok((floor, [0u8; 32]));
    }
    match headers.header_at(target_last)? {
        Some(h) => Ok((target_last.saturating_add(1), h.hash)),
        // The chain is shorter than our conservative target: replay everything.
        None => Ok((floor, [0u8; 32])),
    }
}

/// Case 2/4: walk down through the heights we actually validated.
fn confirmed_ancestor<H: HeaderSource + ?Sized>(
    headers: &H,
    known: &KnownHeaders,
    last_h: u64,
    floor: u64,
    max_reorg_depth: u32,
) -> Result<(u64, [u8; 32])> {
    for depth in 1..=u64::from(max_reorg_depth) {
        let Some(g) = last_h.checked_sub(depth) else {
            return Err(AdapterError::ReorgDetected);
        };
        if g.saturating_add(1) < floor {
            // Resuming below the deployment floor is not a rewind, it is a
            // reset, and that is the caller's decision to make.
            return Err(AdapterError::ReorgDetected);
        }
        // Heights we have no belief about are skipped, never adopted: adopting
        // one would declare continuity we cannot back up.
        let Some(expected) = known.get(g) else {
            continue;
        };
        if let Some(h) = headers.header_at(g)? {
            if h.hash == expected {
                return Ok((g.saturating_add(1), h.hash));
            }
        }
    }
    // Deeper than the configured tolerance, or than the validated history.
    Err(AdapterError::ReorgDetected)
}

/// Applies a rewind: moves the cursor back and drops every belief above the
/// resume point.
///
/// Idempotent: applying the same outcome twice yields the same cursor and the
/// same ring.
pub fn apply_rewind(
    cursor: &EvmCursor,
    known: &mut KnownHeaders,
    from_height: u64,
    anchor: [u8; 32],
) -> EvmCursor {
    if anchor == [0u8; 32] {
        // A full rewind to the floor drops every belief: nothing above it was
        // validated on the chain we are now on.
        *known = KnownHeaders::with_capacity(known.cap);
    } else {
        let last = from_height.saturating_sub(1);
        known.truncate_above(last);
        known.record(last, anchor);
    }
    cursor.rewind_to(from_height, anchor)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic header oracle: `hash = keccak(fork_tag || height)`.
    struct FakeChain {
        height: u64,
        fork_at: u64,
        fork_tag: u8,
    }

    impl FakeChain {
        fn hash(&self, h: u64) -> [u8; 32] {
            let tag = if h >= self.fork_at { self.fork_tag } else { 0 };
            let mut pre = [0u8; 9];
            pre[0] = tag;
            pre[1..].copy_from_slice(&h.to_be_bytes());
            crate::abi::keccak256(&pre)
        }
    }

    impl HeaderSource for FakeChain {
        fn header_at(&self, height: u64) -> Result<Option<RpcBlockHeader>> {
            if height > self.height {
                return Ok(None);
            }
            Ok(Some(RpcBlockHeader {
                number: height,
                hash: self.hash(height),
                parent_hash: if height == 0 {
                    [0u8; 32]
                } else {
                    self.hash(height - 1)
                },
            }))
        }
    }

    fn cursor_at(chain: &FakeChain, h: u64) -> EvmCursor {
        let mut c = EvmCursor::fresh(1, [0xC0; 20], 0);
        c.next_from_block = h + 1;
        c.last_seen_block_hash = chain.hash(h);
        c
    }

    fn ring_up_to(chain: &FakeChain, from: u64, to: u64) -> KnownHeaders {
        let mut k = KnownHeaders::with_capacity(64);
        for h in from..=to {
            k.record(h, chain.hash(h));
        }
        k
    }

    #[test]
    fn continuous_chain_is_continuous() {
        let chain = FakeChain {
            height: 20,
            fork_at: u64::MAX,
            fork_tag: 0,
        };
        let c = cursor_at(&chain, 10);
        let k = ring_up_to(&chain, 0, 10);
        assert_eq!(detect(&chain, &k, &c, 0, 64), Ok(ReorgOutcome::Continuous));
    }

    #[test]
    fn fresh_cursor_without_anchor_is_continuous() {
        let chain = FakeChain {
            height: 20,
            fork_at: u64::MAX,
            fork_tag: 0,
        };
        let c = EvmCursor::fresh(1, [0xC0; 20], 0);
        let k = KnownHeaders::with_capacity(8);
        assert_eq!(detect(&chain, &k, &c, 0, 64), Ok(ReorgOutcome::Continuous));
    }

    #[test]
    fn reorg_walks_to_the_common_ancestor_in_one_call() {
        let old = FakeChain {
            height: 20,
            fork_at: u64::MAX,
            fork_tag: 0,
        };
        // We scanned through 15 on the old chain and remember 0..=15.
        let c = cursor_at(&old, 15);
        let k = ring_up_to(&old, 0, 15);
        // The chain forked at 11.
        let new = FakeChain {
            height: 20,
            fork_at: 11,
            fork_tag: 0xAB,
        };
        let out = detect(&new, &k, &c, 0, 64).expect("reorg detected");
        assert_eq!(
            out,
            ReorgOutcome::Reorg {
                from_height: 11,
                anchor: new.hash(10),
            }
        );
        assert_eq!(new.hash(10), old.hash(10), "ancestor must be shared");
    }

    #[test]
    fn reorg_beyond_max_depth_fails_closed() {
        let old = FakeChain {
            height: 100,
            fork_at: u64::MAX,
            fork_tag: 0,
        };
        let c = cursor_at(&old, 90);
        let k = ring_up_to(&old, 40, 90);
        let new = FakeChain {
            height: 100,
            fork_at: 50,
            fork_tag: 0x5A,
        };
        assert_eq!(
            detect(&new, &k, &c, 0, 8),
            Err(AdapterError::ReorgDetected),
            "a 40-block reorg must not be silently absorbed by a depth-8 policy"
        );
    }

    #[test]
    fn reorg_deeper_than_retained_history_fails_closed() {
        let old = FakeChain {
            height: 100,
            fork_at: u64::MAX,
            fork_tag: 0,
        };
        let c = cursor_at(&old, 90);
        // We only remember 85..=90.
        let k = ring_up_to(&old, 85, 90);
        let new = FakeChain {
            height: 100,
            fork_at: 60,
            fork_tag: 0x5A,
        };
        assert_eq!(
            detect(&new, &k, &c, 0, 256),
            Err(AdapterError::ReorgDetected),
            "we must not name an ancestor we never validated"
        );
    }

    #[test]
    fn empty_ring_after_restart_rewinds_by_the_full_tolerance_not_by_one_block() {
        // The wrong implementation rewinds one block and adopts the new chain's
        // hash there, which declares continuity for a fork that started lower.
        // This test pins the safe behaviour: replay the whole tolerated window.
        let old = FakeChain {
            height: 60,
            fork_at: u64::MAX,
            fork_tag: 0,
        };
        let new = FakeChain {
            height: 60,
            fork_at: 41,
            fork_tag: 0x77,
        };
        let c = cursor_at(&old, 50);
        let mut k = KnownHeaders::with_capacity(64); // restarted: empty
        let out = detect(&new, &k, &c, 0, 16).expect("no hard failure");
        assert_eq!(
            out,
            ReorgOutcome::Reorg {
                from_height: 35,
                anchor: new.hash(34),
            },
            "must rewind by max_reorg_depth, well below the fork at 41"
        );
        let ReorgOutcome::Reorg {
            from_height,
            anchor,
        } = out
        else {
            panic!("expected a reorg");
        };
        let rewound = apply_rewind(&c, &mut k, from_height, anchor);
        assert_eq!(rewound.next_from_block, 35);
        assert!(
            rewound.next_from_block <= 41,
            "the resume point must be at or below the true fork"
        );
        assert_eq!(
            detect(&new, &k, &rewound, 0, 16),
            Ok(ReorgOutcome::Continuous)
        );
    }

    #[test]
    fn empty_ring_rewind_clamps_to_the_deployment_floor() {
        let old = FakeChain {
            height: 30,
            fork_at: u64::MAX,
            fork_tag: 0,
        };
        let new = FakeChain {
            height: 30,
            fork_at: 21,
            fork_tag: 0x77,
        };
        let c = cursor_at(&old, 25);
        let mut k = KnownHeaders::with_capacity(64);
        // Deployment floor at 20: rewinding by 64 would land below it, so the
        // whole scan window is replayed with no anchor at all.
        let out = detect(&new, &k, &c, 20, 64).expect("no hard failure");
        assert_eq!(
            out,
            ReorgOutcome::Reorg {
                from_height: 20,
                anchor: [0u8; 32],
            }
        );
        let ReorgOutcome::Reorg {
            from_height,
            anchor,
        } = out
        else {
            panic!("expected a reorg");
        };
        let rewound = apply_rewind(&c, &mut k, from_height, anchor);
        assert_eq!(rewound.next_from_block, 20);
        assert_eq!(rewound.last_seen_height(), None, "no anchor left");
        assert!(k.is_empty(), "a full rewind drops every belief");
        assert_eq!(
            detect(&new, &k, &rewound, 20, 64),
            Ok(ReorgOutcome::Continuous)
        );

        // With the floor at genesis the walk stops at block 0, which no reorg
        // can orphan.
        let mut k2 = KnownHeaders::with_capacity(64);
        assert_eq!(
            detect(&new, &k2, &c, 0, 64),
            Ok(ReorgOutcome::Reorg {
                from_height: 1,
                anchor: new.hash(0),
            })
        );
        let rewound = apply_rewind(&c, &mut k2, 1, new.hash(0));
        assert_eq!(rewound.next_from_block, 1);
    }

    #[test]
    fn rewind_is_idempotent() {
        let old = FakeChain {
            height: 20,
            fork_at: u64::MAX,
            fork_tag: 0,
        };
        let new = FakeChain {
            height: 20,
            fork_at: 11,
            fork_tag: 0xAB,
        };
        let c = cursor_at(&old, 15);
        let mut k1 = ring_up_to(&old, 0, 15);
        let mut k2 = k1.clone();
        let ReorgOutcome::Reorg {
            from_height,
            anchor,
        } = detect(&new, &k1, &c, 0, 64).expect("reorg")
        else {
            panic!("expected a reorg");
        };
        let once = apply_rewind(&c, &mut k1, from_height, anchor);
        let twice = apply_rewind(&once, &mut k2, from_height, anchor);
        let thrice = apply_rewind(&twice, &mut k1, from_height, anchor);
        assert_eq!(once, twice);
        assert_eq!(twice, thrice);
        assert_eq!(k1.newest(), Some(from_height - 1));
        // After the rewind the chain is continuous again.
        assert_eq!(
            detect(&new, &k1, &once, 0, 64),
            Ok(ReorgOutcome::Continuous)
        );
    }

    #[test]
    fn chain_shorter_than_the_anchor_is_a_reorg() {
        let old = FakeChain {
            height: 20,
            fork_at: u64::MAX,
            fork_tag: 0,
        };
        let c = cursor_at(&old, 18);
        let k = ring_up_to(&old, 0, 18);
        let short = FakeChain {
            height: 12,
            fork_at: u64::MAX,
            fork_tag: 0,
        };
        let out = detect(&short, &k, &c, 0, 64).expect("reorg");
        assert_eq!(
            out,
            ReorgOutcome::Reorg {
                from_height: 13,
                anchor: short.hash(12),
            }
        );
    }

    #[test]
    fn floor_stops_the_search() {
        let old = FakeChain {
            height: 100,
            fork_at: u64::MAX,
            fork_tag: 0,
        };
        let c = cursor_at(&old, 51);
        let k = ring_up_to(&old, 50, 51);
        let new = FakeChain {
            height: 100,
            fork_at: 40,
            fork_tag: 0x33,
        };
        assert_eq!(
            detect(&new, &k, &c, 50, 256),
            Err(AdapterError::ReorgDetected)
        );
    }

    #[test]
    fn zero_and_oversized_depth_policies_fail_closed() {
        let old = FakeChain {
            height: 20,
            fork_at: u64::MAX,
            fork_tag: 0,
        };
        let new = FakeChain {
            height: 20,
            fork_at: 11,
            fork_tag: 0xAB,
        };
        let c = cursor_at(&old, 15);
        let k = ring_up_to(&old, 0, 15);
        assert_eq!(detect(&new, &k, &c, 0, 0), Err(AdapterError::ReorgDetected));
        assert_eq!(
            detect(&new, &k, &c, 0, MAX_REORG_DEPTH_CEILING + 1),
            Err(AdapterError::ReorgDetected)
        );
    }

    #[test]
    fn ring_evicts_oldest_and_truncates_above() {
        let mut k = KnownHeaders::with_capacity(3);
        for h in 1..=5u64 {
            k.record(h, [h as u8; 32]);
        }
        assert_eq!(k.len(), 3);
        assert_eq!(k.oldest(), Some(3));
        assert_eq!(k.newest(), Some(5));
        assert_eq!(k.get(1), None);
        k.truncate_above(4);
        assert_eq!(k.newest(), Some(4));
        assert!(!k.is_empty());
        k.truncate_above(0);
        assert!(k.is_empty());
    }
}
