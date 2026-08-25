//! `dom-sim` — simulated DOM chain for development and testing (F1).
//!
//! DOM Interop Foundation Document v0.2.1 §4.5.
//!
//! MANDATORY DECLARATION (§4.5): dom-sim is NOT the DOM; it confers no
//! network compatibility; the swap for the real node happens in F7 under
//! the eligibility gate. This module simulates CHAIN SEMANTICS (height,
//! inclusion, confirmations, height timelock, claim/refund exclusivity,
//! dedupe, reorg); it NEVER validates cryptography — the cryptography is
//! always the real one, in `dom-leg` (I13/I15).
//!
//! Chain rules the simulator ENFORCES (because the real DOM enforces them):
//! - I4: claim and refund are mutually exclusive per lock — the second
//!   to arrive is rejected by the "chain";
//! - height timelock: a refund only enters a block starting at
//!   `not_before_height`;
//! - byte-identical dedupe (I7): resubmitting the SAME bytes returns the
//!   same tx_id without duplicating;
//! - reorg: removes blocks from the tip, returns their transactions to
//!   the mempool and is OBSERVABLE by the scanner via an anchored cursor
//!   (I11).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use counterparty_api::{ChainCursor, ObservedEvent, RevealedSecretBytes};

/// Transaction types the simulator understands.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SimTx {
    /// Funding: locks a lock.
    Lock {
        /// Lock identifier.
        lock_id: [u8; 32],
    },
    /// Claim: spends the lock revealing the secret.
    Claim {
        /// Lock identifier.
        lock_id: [u8; 32],
        /// Revealed secret (the chain only carries it; dom-leg validates it).
        revealed: [u8; 32],
    },
    /// Refund: spends the lock after the timelock.
    Refund {
        /// Lock identifier.
        lock_id: [u8; 32],
        /// Minimum inclusion height (height timelock).
        not_before_height: u64,
    },
}

impl SimTx {
    /// Lock targeted by the transaction.
    pub fn lock_id(&self) -> [u8; 32] {
        match self {
            Self::Lock { lock_id } | Self::Claim { lock_id, .. } | Self::Refund { lock_id, .. } => {
                *lock_id
            }
        }
    }

    fn is_spend(&self) -> bool {
        !matches!(self, Self::Lock { .. })
    }

    /// Deterministic canonical encoding (for tx_id and I7 dedupe).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 40);
        match self {
            Self::Lock { lock_id } => {
                out.push(0x01);
                out.extend_from_slice(lock_id);
            }
            Self::Claim { lock_id, revealed } => {
                out.push(0x02);
                out.extend_from_slice(lock_id);
                out.extend_from_slice(revealed);
            }
            Self::Refund {
                lock_id,
                not_before_height,
            } => {
                out.push(0x03);
                out.extend_from_slice(lock_id);
                out.extend_from_slice(&not_before_height.to_be_bytes());
            }
        }
        out
    }

    /// Deterministic tx_id = hash of the canonical bytes.
    pub fn tx_id(&self) -> [u8; 32] {
        fnv256(&self.canonical_bytes())
    }
}

/// Opaque artifact that accompanies a submission.
///
/// The chain TRANSPORTS these bytes and NEVER interprets them: they are
/// produced by whoever signs (on DOM, the `dom-leg` over the real pin)
/// and here they exist only as byte-for-byte identity. No rule of this
/// crate reads the content — dom-sim has no cryptography mock, and cannot
/// gain one (§4.5, I13/I15).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct OpaqueWitness(Vec<u8>);

impl OpaqueWitness {
    /// Submission without an attached artifact.
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Wraps opaque bytes already produced by another layer.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Raw bytes, for byte-identical resending (I7).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length of the artifact.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` when no artifact was attached.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::fmt::Debug for OpaqueWitness {
    /// I6: the artifact may contain not-yet-public material; only the
    /// size is printed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "OpaqueWitness(<{} bytes>)", self.0.len())
    }
}

/// Chain submission: a transaction plus the opaque witness that
/// authorizes it.
///
/// The identity (`tx_id`) covers BOTH. Swapping the witness produces a
/// DIFFERENT transaction — and, over the same lock, a conflicting spend
/// (I4), never a silent duplicate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SimSubmission {
    tx: SimTx,
    witness: OpaqueWitness,
}

impl SimSubmission {
    /// Submission with an opaque artifact attached.
    pub fn new(tx: SimTx, witness: OpaqueWitness) -> Self {
        Self { tx, witness }
    }

    /// Submission without an artifact — chain semantics only.
    pub fn bare(tx: SimTx) -> Self {
        Self {
            tx,
            witness: OpaqueWitness::empty(),
        }
    }

    /// Submitted transaction.
    pub fn tx(&self) -> &SimTx {
        &self.tx
    }

    /// Attached opaque witness.
    pub fn witness(&self) -> &OpaqueWitness {
        &self.witness
    }

    /// Canonical encoding = transaction ++ witness.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.tx.canonical_bytes();
        out.extend_from_slice(&self.witness.0);
        out
    }

    /// Deterministic tx_id over transaction ++ witness. Without a
    /// witness, it coincides with [`SimTx::tx_id`].
    pub fn tx_id(&self) -> [u8; 32] {
        fnv256(&self.canonical_bytes())
    }

    fn is_spend(&self) -> bool {
        self.tx.is_spend()
    }

    fn lock_id(&self) -> [u8; 32] {
        self.tx.lock_id()
    }
}

/// Simple deterministic hash (extended FNV-1a). NOT cryptographic —
/// stable identity within the simulator, nothing more.
fn fnv256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for lane in 0u64..4 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ (lane.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        for (i, b) in bytes.iter().enumerate() {
            h ^= u64::from(*b) ^ ((i as u64) << 32);
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        out[(lane as usize) * 8..(lane as usize + 1) * 8].copy_from_slice(&h.to_be_bytes());
    }
    out
}

/// Result of a submission.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SubmitResult {
    /// Accepted into the mempool (or already present — I7 dedupe).
    Accepted {
        /// Deterministic transaction identifier.
        tx_id: [u8; 32],
    },
    /// Rejected by the indicated chain rule.
    Rejected(RejectReason),
}

/// "Chain" rejection reasons.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RejectReason {
    /// Target lock does not exist confirmed on the chain.
    UnknownLock,
    /// Lock already spent (claim XOR refund — I4).
    AlreadySpent,
    /// Duplicate lock.
    DuplicateLock,
    /// Refund before the timelock.
    TimelockNotExpired,
    /// A conflicting spend already exists in the mempool.
    ConflictInMempool,
}

/// State of a lock on the confirmed chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockState {
    /// Never seen confirmed.
    Unknown,
    /// Funded and unspent.
    Open,
    /// Spent (by claim or refund).
    Spent,
}

/// Simulated block.
#[derive(Clone, PartialEq, Eq, Debug)]
struct SimBlock {
    height: u64,
    /// Chained deterministic anchor — lets the scanner detect a reorg by
    /// comparing the anchor saved in the cursor.
    anchor: [u8; 32],
    txs: Vec<SimSubmission>,
}

/// Simulated DOM chain, deterministic, with injectable reorg.
#[derive(Default)]
pub struct SimChain {
    blocks: Vec<SimBlock>,
    mempool: Vec<SimSubmission>,
}

impl SimChain {
    /// New empty chain (height 0 = no blocks).
    pub fn new() -> Self {
        Self::default()
    }

    /// Tip height (0 when there are no blocks).
    pub fn height(&self) -> u64 {
        self.blocks.len() as u64
    }

    fn anchor_at(&self, height: u64) -> [u8; 32] {
        if height == 0 {
            return [0u8; 32]; // genesis
        }
        self.blocks[height as usize - 1].anchor
    }

    /// State of a lock on the confirmed chain.
    pub fn lock_state(&self, lock_id: [u8; 32]) -> LockState {
        let mut state = LockState::Unknown;
        for b in &self.blocks {
            for sub in &b.txs {
                if sub.lock_id() != lock_id {
                    continue;
                }
                state = match (state, &sub.tx) {
                    (LockState::Unknown, SimTx::Lock { .. }) => LockState::Open,
                    (LockState::Open, t) if t.is_spend() => LockState::Spent,
                    (s, _) => s,
                };
            }
        }
        state
    }

    /// Opaque witness of a known transaction (in a block or in the
    /// mempool). The chain returns exactly the bytes it received —
    /// transport, never reading.
    pub fn witness_of(&self, tx_id: &[u8; 32]) -> Option<&OpaqueWitness> {
        self.blocks
            .iter()
            .flat_map(|b| b.txs.iter())
            .chain(self.mempool.iter())
            .find(|s| &s.tx_id() == tx_id)
            .map(|s| &s.witness)
    }

    fn mempool_has_conflicting_spend(&self, sub: &SimSubmission) -> bool {
        sub.is_spend()
            && self
                .mempool
                .iter()
                .any(|m| m.is_spend() && m.lock_id() == sub.lock_id() && m.tx_id() != sub.tx_id())
    }

    /// Submits a transaction without an attached artifact.
    pub fn submit(&mut self, tx: SimTx) -> SubmitResult {
        self.submit_submission(SimSubmission::bare(tx))
    }

    /// Submits a transaction with an opaque witness, applying the chain
    /// rules. The witness content is not inspected: it only enters the
    /// transaction identity (byte-exact I7 dedupe).
    pub fn submit_submission(&mut self, sub: SimSubmission) -> SubmitResult {
        let tx_id = sub.tx_id();
        // Byte-identical dedupe (I7).
        if self.mempool.iter().any(|m| m.tx_id() == tx_id) {
            return SubmitResult::Accepted { tx_id };
        }
        match &sub.tx {
            SimTx::Lock { lock_id } => {
                if self.lock_state(*lock_id) != LockState::Unknown
                    || self
                        .mempool
                        .iter()
                        .any(|m| matches!(&m.tx, SimTx::Lock { lock_id: l } if l == lock_id))
                {
                    return SubmitResult::Rejected(RejectReason::DuplicateLock);
                }
            }
            SimTx::Claim { lock_id, .. } => match self.lock_state(*lock_id) {
                LockState::Unknown => return SubmitResult::Rejected(RejectReason::UnknownLock),
                LockState::Spent => return SubmitResult::Rejected(RejectReason::AlreadySpent),
                LockState::Open => {
                    if self.mempool_has_conflicting_spend(&sub) {
                        return SubmitResult::Rejected(RejectReason::ConflictInMempool);
                    }
                }
            },
            SimTx::Refund {
                lock_id,
                not_before_height,
            } => match self.lock_state(*lock_id) {
                LockState::Unknown => return SubmitResult::Rejected(RejectReason::UnknownLock),
                LockState::Spent => return SubmitResult::Rejected(RejectReason::AlreadySpent),
                LockState::Open => {
                    // Only enters the mempool if the NEXT block can
                    // already include it (mempool policy; inclusion revalidates).
                    if self.height() + 1 < *not_before_height {
                        return SubmitResult::Rejected(RejectReason::TimelockNotExpired);
                    }
                    if self.mempool_has_conflicting_spend(&sub) {
                        return SubmitResult::Rejected(RejectReason::ConflictInMempool);
                    }
                }
            },
        }
        self.mempool.push(sub);
        SubmitResult::Accepted { tx_id }
    }

    /// Mines `n` blocks, including from the mempool what the rules allow
    /// (revalidated per block). I4 holds within the block too: the first
    /// spend of a lock wins; spends of an already-Spent lock are discarded.
    pub fn advance(&mut self, n: u64) {
        for _ in 0..n {
            let next_height = self.height() + 1;
            let pending = core::mem::take(&mut self.mempool);
            let mut included: Vec<SimSubmission> = Vec::new();
            let mut deferred: Vec<SimSubmission> = Vec::new();
            for sub in pending {
                let base_ok = match &sub.tx {
                    SimTx::Lock { lock_id } => self.lock_state(*lock_id) == LockState::Unknown,
                    SimTx::Claim { lock_id, .. } => self.lock_state(*lock_id) == LockState::Open,
                    SimTx::Refund {
                        lock_id,
                        not_before_height,
                    } => {
                        self.lock_state(*lock_id) == LockState::Open
                            && next_height >= *not_before_height
                    }
                };
                let conflicts_in_block = sub.is_spend()
                    && included
                        .iter()
                        .any(|i| i.is_spend() && i.lock_id() == sub.lock_id());
                if base_ok && !conflicts_in_block {
                    included.push(sub);
                } else if match &sub.tx {
                    // Might it still be valid in the future? (refund waiting
                    // for the height, spend of a lock still Open, lock not
                    // yet confirmed)
                    SimTx::Refund { lock_id, .. } | SimTx::Claim { lock_id, .. } => {
                        self.lock_state(*lock_id) != LockState::Spent && !conflicts_in_block
                    }
                    SimTx::Lock { lock_id } => self.lock_state(*lock_id) == LockState::Unknown,
                } {
                    deferred.push(sub);
                }
            }
            self.mempool = deferred;
            let mut anchor_input = self.anchor_at(self.height()).to_vec();
            anchor_input.extend_from_slice(&next_height.to_be_bytes());
            for sub in &included {
                anchor_input.extend_from_slice(&sub.tx_id());
            }
            self.blocks.push(SimBlock {
                height: next_height,
                anchor: fnv256(&anchor_input),
                txs: included,
            });
        }
    }

    /// Confirmations of an included transaction (1 = at the tip).
    pub fn confirmations(&self, tx_id: &[u8; 32]) -> Option<u64> {
        for b in &self.blocks {
            if b.txs.iter().any(|s| &s.tx_id() == tx_id) {
                return Some(self.height() - b.height + 1);
            }
        }
        None
    }

    /// Injects a reorg of `depth` blocks: removes them from the tip and
    /// returns their transactions to the mempool (they may or may not be
    /// re-mined).
    pub fn inject_reorg(&mut self, depth: u64) {
        let depth = depth.min(self.height());
        for _ in 0..depth {
            if let Some(b) = self.blocks.pop() {
                for sub in b.txs {
                    self.mempool.push(sub);
                }
            }
        }
    }

    /// Scans the chain starting at the cursor, emitting neutral events.
    ///
    /// The cursor encodes `(height, anchor)`. If the anchor does not match
    /// the current chain (reorg), it emits `Reorged { from_height }` and
    /// returns a cursor rewound by one block — successive calls converge
    /// to the common anchor and re-scan the range (I11).
    pub fn scan(&self, cursor: &ChainCursor) -> (Vec<ObservedEvent>, ChainCursor) {
        let (from, anchor) = decode_cursor(cursor);
        if from > self.height() || (from > 0 && self.anchor_at(from) != anchor) {
            let rewind = from.saturating_sub(1).min(self.height());
            let ev = vec![ObservedEvent::Reorged { from_height: from }];
            return (ev, encode_cursor(rewind, self.anchor_at(rewind)));
        }
        let mut events = Vec::new();
        let mut at = from;
        while at < self.height() {
            let b = &self.blocks[at as usize];
            for sub in &b.txs {
                events.push(match &sub.tx {
                    SimTx::Lock { lock_id } => ObservedEvent::LockOpened {
                        lock_id: *lock_id,
                        height: b.height,
                    },
                    SimTx::Claim { lock_id, revealed } => ObservedEvent::LockClaimed {
                        lock_id: *lock_id,
                        revealed: RevealedSecretBytes(*revealed),
                        height: b.height,
                    },
                    SimTx::Refund { lock_id, .. } => ObservedEvent::LockRefunded {
                        lock_id: *lock_id,
                        height: b.height,
                    },
                });
            }
            at = b.height;
        }
        (events, encode_cursor(at, self.anchor_at(at)))
    }
}

/// Kind of one detailed observation (F2 spec §9).
///
/// Deliberately WITHOUT the revealed secret: `scan_detailed` is the path
/// the F2 engine consumes, and the engine must never receive `t` (spec
/// §18). Cryptographic consumption of a claim happens at the F1 boundary
/// from the evidence reference. The secret remains available on the
/// legacy [`SimChain::scan`] path, which the F1 chain suite uses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObservedKind {
    /// A lock was opened (funding).
    LockOpened,
    /// A lock was claimed (the spend that reveals the secret on chain).
    LockClaimed,
    /// A lock was refunded.
    LockRefunded,
}

/// One observation with its full, verifiable chain position.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ObservedRecord {
    /// What happened.
    pub kind: ObservedKind,
    /// Lock the observation belongs to.
    pub lock_id: [u8; 32],
    /// Transaction identifier of the inclusion.
    pub tx_id: [u8; 32],
    /// Index of the transaction inside its block.
    pub event_index: u32,
    /// Height of the block carrying it.
    pub block_height: u64,
    /// Anchor of that block (reorg detection).
    pub block_anchor: [u8; 32],
}

/// Detailed scan output: an observation, or the adapter's own detection
/// that the position it held is no longer on the canonical chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DetailedRecord {
    /// One observation with its chain position.
    Observed(ObservedRecord),
    /// The cursor's anchor no longer matches the chain (spec §11).
    Reorged {
        /// First invalidated height.
        from_height: u64,
        /// Anchor of the abandoned branch, as held in the cursor.
        old_anchor: [u8; 32],
    },
}

impl SimChain {
    /// Anchor committed at `height`, or `None` beyond the tip. Total by
    /// construction: no height can panic this accessor.
    pub fn anchor_of(&self, height: u64) -> Option<[u8; 32]> {
        if height == 0 {
            return Some([0u8; 32]);
        }
        let index = usize::try_from(height).ok()?.checked_sub(1)?;
        self.blocks.get(index).map(|b| b.anchor)
    }

    /// Position of an included transaction on the CANONICAL chain, if it
    /// is there: `(height, anchor, index)`. Used by the evidence
    /// verification at the adapter boundary — a reference that no longer
    /// resolves is evidence that no longer exists.
    pub fn inclusion_of(&self, tx_id: &[u8; 32]) -> Option<(u64, [u8; 32], u32)> {
        for block in &self.blocks {
            for (index, sub) in block.txs.iter().enumerate() {
                if &sub.tx_id() == tx_id {
                    return u32::try_from(index)
                        .ok()
                        .map(|index| (block.height, block.anchor, index));
                }
            }
        }
        None
    }

    /// Detailed scan for the F2 engine: same traversal and the same reorg
    /// semantics as [`SimChain::scan`], but every observation carries its
    /// verifiable position `(tx_id, index, height, anchor)` and no secret.
    pub fn scan_detailed(&self, cursor: &ChainCursor) -> (Vec<DetailedRecord>, ChainCursor) {
        let (from, anchor) = decode_cursor(cursor);
        let current = self.anchor_of(from);
        if current != Some(anchor) {
            // Either the cursor is beyond the tip or its anchor belongs to
            // an abandoned branch: report the reorg and rewind one block,
            // converging to the common ancestor across successive calls.
            let rewind = from.saturating_sub(1).min(self.height());
            let record = DetailedRecord::Reorged {
                from_height: from,
                old_anchor: anchor,
            };
            return (
                vec![record],
                encode_cursor(rewind, self.anchor_of(rewind).unwrap_or([0u8; 32])),
            );
        }
        let mut records = Vec::new();
        let mut at = from;
        while at < self.height() {
            let Some(block) = self.blocks.get(at as usize) else {
                break;
            };
            for (index, sub) in block.txs.iter().enumerate() {
                let kind = match &sub.tx {
                    SimTx::Lock { .. } => ObservedKind::LockOpened,
                    SimTx::Claim { .. } => ObservedKind::LockClaimed,
                    SimTx::Refund { .. } => ObservedKind::LockRefunded,
                };
                let Ok(event_index) = u32::try_from(index) else {
                    // A block with more than u32::MAX transactions cannot
                    // be described canonically: stop instead of lying.
                    return (records, encode_cursor(at, block.anchor));
                };
                records.push(DetailedRecord::Observed(ObservedRecord {
                    kind,
                    lock_id: sub.lock_id(),
                    tx_id: sub.tx_id(),
                    event_index,
                    block_height: block.height,
                    block_anchor: block.anchor,
                }));
            }
            at = block.height;
        }
        (
            records,
            encode_cursor(at, self.anchor_of(at).unwrap_or([0u8; 32])),
        )
    }
}

/// Encodes the `(height, anchor)` cursor in the neutral API's opaque format.
pub fn encode_cursor(height: u64, anchor: [u8; 32]) -> ChainCursor {
    let mut v = Vec::with_capacity(40);
    v.extend_from_slice(&height.to_be_bytes());
    v.extend_from_slice(&anchor);
    ChainCursor(v)
}

/// Height encoded in a cursor produced by [`SimChain::scan`].
///
/// The cursor is opaque to the CORE (§4.7); for the adapter that produced
/// it, it is readable — that is how a scanner knows up to where the
/// observations it derived remain valid after a reorg (I11).
pub fn cursor_height(cursor: &ChainCursor) -> u64 {
    decode_cursor(cursor).0
}

fn decode_cursor(c: &ChainCursor) -> (u64, [u8; 32]) {
    if c.0.len() != 40 {
        return (0, [0u8; 32]); // empty cursor => scan from zero
    }
    let mut h = [0u8; 8];
    h.copy_from_slice(&c.0[..8]);
    let mut a = [0u8; 32];
    a.copy_from_slice(&c.0[8..]);
    (u64::from_be_bytes(h), a)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: [u8; 32] = [0xAA; 32];
    const SECRET: [u8; 32] = [0x77; 32];

    fn funded_chain() -> (SimChain, [u8; 32]) {
        let mut c = SimChain::new();
        let SubmitResult::Accepted { tx_id } = c.submit(SimTx::Lock { lock_id: LOCK }) else {
            panic!("lock rejected");
        };
        c.advance(1);
        (c, tx_id)
    }

    #[test]
    fn claim_and_refund_are_mutually_exclusive_on_chain() {
        // I4 enforced by the chain: once the claim is confirmed, the refund is rejected.
        let (mut c, _) = funded_chain();
        assert!(matches!(
            c.submit(SimTx::Claim {
                lock_id: LOCK,
                revealed: SECRET
            }),
            SubmitResult::Accepted { .. }
        ));
        c.advance(1);
        assert_eq!(
            c.submit(SimTx::Refund {
                lock_id: LOCK,
                not_before_height: 0
            }),
            SubmitResult::Rejected(RejectReason::AlreadySpent)
        );
        // And vice-versa on a fresh chain.
        let (mut c2, _) = funded_chain();
        c2.submit(SimTx::Refund {
            lock_id: LOCK,
            not_before_height: 0,
        });
        c2.advance(1);
        assert_eq!(
            c2.submit(SimTx::Claim {
                lock_id: LOCK,
                revealed: SECRET
            }),
            SubmitResult::Rejected(RejectReason::AlreadySpent)
        );
    }

    #[test]
    fn conflicting_spends_cannot_coexist_in_mempool() {
        let (mut c, _) = funded_chain();
        assert!(matches!(
            c.submit(SimTx::Claim {
                lock_id: LOCK,
                revealed: SECRET
            }),
            SubmitResult::Accepted { .. }
        ));
        assert_eq!(
            c.submit(SimTx::Refund {
                lock_id: LOCK,
                not_before_height: 0
            }),
            SubmitResult::Rejected(RejectReason::ConflictInMempool)
        );
    }

    #[test]
    fn refund_respects_height_timelock() {
        let (mut c, _) = funded_chain(); // height 1
        assert_eq!(
            c.submit(SimTx::Refund {
                lock_id: LOCK,
                not_before_height: 5
            }),
            SubmitResult::Rejected(RejectReason::TimelockNotExpired)
        );
        c.advance(3); // height 4; next block = 5
        assert!(matches!(
            c.submit(SimTx::Refund {
                lock_id: LOCK,
                not_before_height: 5
            }),
            SubmitResult::Accepted { .. }
        ));
        c.advance(1);
        assert_eq!(c.lock_state(LOCK), LockState::Spent);
    }

    #[test]
    fn deferred_refund_waits_in_mempool_until_height() {
        // Accepted into the mempool (does the next block satisfy? no:
        // 6 > 5) — so we test the deferral path AT INCLUSION: submitted
        // when the next block is 5 with not_before 6 it is rejected; when
        // the next is 6, it enters and is included.
        let (mut c, _) = funded_chain(); // height 1
        c.advance(3); // height 4 (next block 5)
        assert_eq!(
            c.submit(SimTx::Refund {
                lock_id: LOCK,
                not_before_height: 6
            }),
            SubmitResult::Rejected(RejectReason::TimelockNotExpired)
        );
        c.advance(1); // height 5 (next 6)
        assert!(matches!(
            c.submit(SimTx::Refund {
                lock_id: LOCK,
                not_before_height: 6
            }),
            SubmitResult::Accepted { .. }
        ));
        c.advance(1);
        assert_eq!(c.lock_state(LOCK), LockState::Spent);
    }

    #[test]
    fn byte_identical_resubmission_is_deduplicated() {
        // I7: same bytes => same tx_id, without duplicating.
        let mut c = SimChain::new();
        let a = c.submit(SimTx::Lock { lock_id: LOCK });
        let b = c.submit(SimTx::Lock { lock_id: LOCK });
        assert_eq!(a, b);
        c.advance(1);
        let (ev, _) = c.scan(&ChainCursor::default());
        assert_eq!(ev.len(), 1, "dedupe failed: duplicate lock in the block");
    }

    #[test]
    fn confirmations_grow_with_height() {
        let (mut c, funding_tx) = funded_chain();
        assert_eq!(c.confirmations(&funding_tx), Some(1));
        c.advance(4);
        assert_eq!(c.confirmations(&funding_tx), Some(5));
        assert_eq!(c.confirmations(&[0u8; 32]), None);
    }

    #[test]
    fn scan_emits_neutral_events_and_is_idempotent_per_cursor() {
        let (mut c, _) = funded_chain();
        c.submit(SimTx::Claim {
            lock_id: LOCK,
            revealed: SECRET,
        });
        c.advance(1);
        let (ev1, cur1) = c.scan(&ChainCursor::default());
        assert_eq!(ev1.len(), 2);
        assert!(matches!(
            ev1[0],
            ObservedEvent::LockOpened { height: 1, .. }
        ));
        assert!(matches!(
            ev1[1],
            ObservedEvent::LockClaimed {
                revealed: RevealedSecretBytes(SECRET),
                height: 2,
                ..
            }
        ));
        // Same cursor => same events (determinism/idempotency).
        let (ev1b, _) = c.scan(&ChainCursor::default());
        assert_eq!(ev1, ev1b);
        // Advanced cursor => nothing new.
        let (ev2, _) = c.scan(&cur1);
        assert!(ev2.is_empty());
    }

    #[test]
    fn reorg_is_observable_and_scanner_recovers() {
        let (mut c, _) = funded_chain();
        c.submit(SimTx::Claim {
            lock_id: LOCK,
            revealed: SECRET,
        });
        c.advance(1);
        let (_, cursor_at_2) = c.scan(&ChainCursor::default());

        c.inject_reorg(1); // drops block 2 (claim goes back to the mempool)
        assert_eq!(c.height(), 1);

        let (ev, rewound) = c.scan(&cursor_at_2);
        assert_eq!(ev, vec![ObservedEvent::Reorged { from_height: 2 }]);

        // New reality: the claim is re-mined in the new block 2.
        c.advance(1);
        let (ev2, _) = c.scan(&rewound);
        assert!(
            ev2.iter()
                .any(|e| matches!(e, ObservedEvent::LockClaimed { height: 2, .. })),
            "post-reorg re-scan did not re-find the claim: {ev2:?}"
        );
    }

    #[test]
    fn deep_reorg_scanner_converges_by_iteration() {
        // 3-block reorg with the cursor at the old tip: the scanner
        // rewinds one block per call until it re-finds a valid anchor,
        // and then re-scans.
        let (mut c, _) = funded_chain(); // block 1
        c.advance(3); // blocks 2..4 empty
        let (_, tip_cursor) = c.scan(&ChainCursor::default()); // height 4
        c.inject_reorg(3); // back to height 1
        let mut cursor = tip_cursor;
        let mut reorg_events = 0;
        for _ in 0..8 {
            let (ev, next) = c.scan(&cursor);
            if ev
                .iter()
                .any(|e| matches!(e, ObservedEvent::Reorged { .. }))
            {
                reorg_events += 1;
                cursor = next;
            } else {
                cursor = next;
                break;
            }
        }
        assert!(reorg_events >= 1);
        // Converged: a new scan from the final cursor is empty and stable.
        let (ev, _) = c.scan(&cursor);
        assert!(ev.is_empty(), "did not converge: {ev:?}");
    }

    #[test]
    fn reorg_returns_spend_to_mempool_and_blocks_rival_spend() {
        // A confirmed claim falls due to a reorg; a rival refund is
        // rejected for conflicting with the claim that returned to the
        // mempool; re-mining preserves the claim. (The USER's protection
        // against a flip is the engine's FinalityPolicy — the chain merely
        // stays consistent.)
        let (mut c, _) = funded_chain();
        c.advance(4); // height 5
        c.submit(SimTx::Claim {
            lock_id: LOCK,
            revealed: SECRET,
        });
        c.advance(1); // claim at height 6
        c.inject_reorg(1);
        assert_eq!(
            c.submit(SimTx::Refund {
                lock_id: LOCK,
                not_before_height: 6
            }),
            SubmitResult::Rejected(RejectReason::ConflictInMempool)
        );
        c.advance(1);
        assert_eq!(c.lock_state(LOCK), LockState::Spent);
        let (ev, _) = c.scan(&ChainCursor::default());
        let claims = ev
            .iter()
            .filter(|e| matches!(e, ObservedEvent::LockClaimed { .. }))
            .count();
        let refunds = ev
            .iter()
            .filter(|e| matches!(e, ObservedEvent::LockRefunded { .. }))
            .count();
        assert_eq!((claims, refunds), (1, 0), "I4 violated post-reorg");
    }

    #[test]
    fn opaque_witness_is_transported_verbatim_and_never_interpreted() {
        // The chain returns the SAME bytes it received and the chain
        // semantics are identical to a submission without an artifact:
        // dom-sim transports, it does not read (I13/I15).
        let artifact: Vec<u8> = (0u16..162).map(|i| (i % 251) as u8).collect();
        let mut c = SimChain::new();
        let sub = SimSubmission::new(
            SimTx::Lock { lock_id: LOCK },
            OpaqueWitness::new(artifact.clone()),
        );
        let SubmitResult::Accepted { tx_id } = c.submit_submission(sub) else {
            panic!("lock with artifact rejected");
        };
        c.advance(1);
        assert_eq!(
            c.witness_of(&tx_id).map(OpaqueWitness::as_bytes),
            Some(artifact.as_slice()),
            "artifact did not survive byte for byte"
        );
        assert_eq!(c.lock_state(LOCK), LockState::Open);

        let mut bare = SimChain::new();
        bare.submit(SimTx::Lock { lock_id: LOCK });
        bare.advance(1);
        assert_eq!(
            c.scan(&ChainCursor::default()).0,
            bare.scan(&ChainCursor::default()).0,
            "the artifact content changed the observed semantics"
        );
    }

    #[test]
    fn witness_is_part_of_transaction_identity() {
        // Same transaction with different artifacts = different
        // transactions; with the SAME artifact, byte-exact dedupe (I7).
        let tx = SimTx::Claim {
            lock_id: LOCK,
            revealed: SECRET,
        };
        let a = SimSubmission::new(tx.clone(), OpaqueWitness::new(vec![1, 2, 3]));
        let b = SimSubmission::new(tx.clone(), OpaqueWitness::new(vec![1, 2, 4]));
        assert_ne!(a.tx_id(), b.tx_id());
        assert_eq!(a.tx_id(), a.clone().tx_id());
        // Without an artifact, the identity coincides with the bare transaction's.
        assert_eq!(SimSubmission::bare(tx.clone()).tx_id(), tx.tx_id());

        let (mut c, _) = funded_chain();
        assert_eq!(c.submit_submission(a.clone()), c.submit_submission(a));
        c.advance(1);
        let claims = c
            .scan(&ChainCursor::default())
            .0
            .iter()
            .filter(|e| matches!(e, ObservedEvent::LockClaimed { .. }))
            .count();
        assert_eq!(claims, 1, "dedupe by artifact failed");
    }

    #[test]
    fn same_spend_with_a_different_witness_is_a_conflict_not_a_duplicate() {
        // Witness malleability must not become a double spend: the second
        // is rejected as a conflict (I4).
        let (mut c, _) = funded_chain();
        let tx = SimTx::Claim {
            lock_id: LOCK,
            revealed: SECRET,
        };
        assert!(matches!(
            c.submit_submission(SimSubmission::new(
                tx.clone(),
                OpaqueWitness::new(vec![0xAA])
            )),
            SubmitResult::Accepted { .. }
        ));
        assert_eq!(
            c.submit_submission(SimSubmission::new(tx, OpaqueWitness::new(vec![0xBB]))),
            SubmitResult::Rejected(RejectReason::ConflictInMempool)
        );
        c.advance(1);
        assert_eq!(c.lock_state(LOCK), LockState::Spent);
    }

    #[test]
    fn witness_debug_never_leaks_the_artifact() {
        let w = OpaqueWitness::new(vec![0x5E; 64]);
        let rendered = format!("{w:?}");
        assert_eq!(rendered, "OpaqueWitness(<64 bytes>)");
        assert!(!rendered.contains("5e"), "I6");
    }

    #[test]
    fn cursor_height_reads_back_the_scan_position() {
        let (mut c, _) = funded_chain();
        c.advance(3);
        let (_, cursor) = c.scan(&ChainCursor::default());
        assert_eq!(cursor_height(&cursor), c.height());
        assert_eq!(cursor_height(&ChainCursor::default()), 0);
        assert_eq!(
            cursor_height(&ChainCursor(vec![0xFF; 7])),
            0,
            "short cursor"
        );
    }

    #[test]
    fn unknown_lock_spends_are_rejected() {
        let mut c = SimChain::new();
        assert_eq!(
            c.submit(SimTx::Claim {
                lock_id: [1u8; 32],
                revealed: SECRET
            }),
            SubmitResult::Rejected(RejectReason::UnknownLock)
        );
        assert_eq!(
            c.submit(SimTx::Refund {
                lock_id: [1u8; 32],
                not_before_height: 0
            }),
            SubmitResult::Rejected(RejectReason::UnknownLock)
        );
    }

    #[test]
    fn deterministic_tx_ids_and_anchors() {
        let a = SimTx::Claim {
            lock_id: LOCK,
            revealed: SECRET,
        };
        assert_eq!(a.tx_id(), a.clone().tx_id());
        let mut c1 = SimChain::new();
        let mut c2 = SimChain::new();
        for c in [&mut c1, &mut c2] {
            c.submit(SimTx::Lock { lock_id: LOCK });
            c.advance(2);
        }
        assert_eq!(c1.anchor_at(2), c2.anchor_at(2), "deterministic anchors");
        assert_ne!(c1.anchor_at(1), c1.anchor_at(2));
    }
}
