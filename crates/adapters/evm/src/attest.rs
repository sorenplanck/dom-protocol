//! Independent attestation of a settlement log.
//!
//! # Why `eth_getLogs` is never enough
//!
//! `eth_getLogs` is a *query*, not a proof. Its answer is a JSON array the
//! endpoint composed; nothing in it is self-authenticating and nothing in it is
//! cross-checked by the endpoint against anything else. A proxy, a cache, a
//! misconfigured archive node or a hostile provider can return a perfectly
//! well-formed log for a transaction that reverted, for a transaction that does
//! not exist, for a block that was orphaned, or for a block that is not final.
//! Every one of those shapes decodes cleanly.
//!
//! So a log that arrived through `eth_getLogs` is treated here as nothing more
//! than a *claim about where to look*. Accepting the settlement it describes
//! requires the endpoint to corroborate it through four other, independently
//! fetched objects, each of which must agree with the log and with each other:
//!
//! | source | fetched with | what it must prove |
//! |---|---|---|
//! | receipt | `eth_getTransactionReceipt` | the transaction succeeded (`status == 1`) **and the receipt itself carries this log at this `logIndex`** |
//! | transaction | `eth_getTransactionByHash` | the transaction exists, is mined in the same block, and was sent **to the configured contract** |
//! | block | `eth_getBlockByNumber` | the canonical chain at that height carries exactly the block hash the log claims |
//! | finalized head | `eth_getBlockByNumber("finalized")` | the block is at or below the finalized head **and hash-links up to it** |
//!
//! Any single one of them failing rejects the settlement. That is the
//! difference between "the endpoint told me" and "the chain shows me".
//!
//! # Ancestry is always a chain of parent hashes. There is no other form.
//!
//! A block can sit below the finalized height and still be on a fork: the
//! canonical chain moved and the block was orphaned, but its height did not
//! change. **Height alone therefore proves nothing**, and neither does asking
//! the endpoint's canonical index — that is the endpoint answering a question
//! about itself.
//!
//! An earlier version of this module said exactly that and then, past a walk
//! budget, fell back to two canonical-index questions. An adversarial audit
//! measured the consequence: with an endpoint exhibiting *no* parent linkage at
//! all, a gap of 3 blocks was refused and a gap of 25 attested a full
//! settlement. The attacker's cost was waiting. Worse,
//! [`crate::evidence::EvmEvidence::verify_onchain`] re-attests against the
//! *current* finalized head, so the weak path became the only path as stored
//! evidence aged. `tests/audit_ancestry_p1.rs` is that proof, kept.
//!
//! Round 2 of the same audit found the replacement narrowed rather than closed
//! (`tests/audit_ancestry_p2.rs`, kept and no longer `#[ignore]`d). Three
//! separate holes, all of the same shape — *something other than a followed
//! parent hash was allowed to stand in for one*:
//!
//! - an "anchored" proof whose two ends both came out of the record being
//!   verified, so at gap 0 it compared a hash to itself and at any gap it
//!   proved only that some fork was internally linked;
//! - `verify_onchain` forgiving [`RejectReason::AncestryProofTooDeep`] from the
//!   head-side walk, which made *waiting* — 256 blocks of it — buy acceptance;
//! - a [`VerifiedChain`] keyed by height with no identity of the chain its
//!   links belonged to, so a warm observer answered "ancestor" about a head it
//!   had never been linked to, in zero round trips.
//!
//! The rule now has no exception: **[`verify_finalized_ancestry`] returns `Ok`
//! only after following `parentHash` from a finalized block down to the
//! observation, one hash-addressed lookup per block.** When the gap is larger
//! than a single call may walk, it returns
//! [`RejectReason::AncestryProofTooDeep`] — a refusal, not a weaker answer.
//!
//! Three things keep that affordable, and none of them is a shortcut:
//!
//! 1. **A verified chain with an identity** ([`VerifiedChain`]). Every link the
//!    walk follows is recorded, *together with the finalized head those links
//!    were proved to descend from*. Finality does not revert, so a block once
//!    proved to be on the finalized chain stays proved; re-asking is free. But
//!    a link is only a proof *relative to that head*, so before any cached
//!    answer is given the chain is **reconciled** with the head the caller is
//!    asking about: the new head must be followed, hash by hash, down onto the
//!    head the chain already holds. A head that contradicts it is
//!    [`RejectReason::NotFinalizedAncestor`]; a head too far ahead to follow
//!    empties the chain and re-roots it, because forgetting a proof un-proves
//!    nothing while *reusing* one across chains proves nothing.
//! 2. **Bounded batches** ([`extend_verified_chain`]). A caller that must reach
//!    far back — a cold process replaying deep history — extends the verified
//!    chain [`MAX_ANCESTRY_WALK`] links at a time. Total work equals the real
//!    gap, work *per call* stays bounded, and every link is real. Progress is
//!    tracked by [`VerifiedChain::frontier`], which is never evicted, so
//!    batching still converges past [`MAX_VERIFIED_CHAIN`] links.
//! 3. **A deep proof with an explicit ceiling**
//!    ([`verify_finalized_ancestry_deep`]). Evidence verification cannot ask a
//!    caller to loop, so it closes the gap itself, in the same bounded batches,
//!    up to [`MAX_ANCESTRY_TOTAL`] links — and then **refuses**. That ceiling is
//!    a stated liveness bound, not a weaker check: past it the answer is
//!    [`AdapterError::BoundsExceeded`], never `Ok`.
//!
//! # Classification: absence, contradiction, and unavailability
//!
//! Inside an ancestry proof every lookup is of a hash the endpoint has
//! *already vouched for* — the finalized head it just named, or a parent named
//! in a header it just served. Failing to produce one of those is the endpoint
//! contradicting itself, not lagging, and is
//! [`RejectReason::NotFinalizedAncestor`]. A node that is merely behind fails
//! earlier and differently: at the height-addressed lookup in step 3, as
//! [`RejectReason::BlockMissing`] → `AdapterUnavailable`. One rule, one
//! classification, and a briefly desynced node never produces a spurious
//! reorg.
//!
//! Transport failure and malformed answers are separated too
//! ([`RejectReason::Transport`] vs [`RejectReason::MalformedAnswer`]): a dead
//! socket and a lying endpoint are different operational facts.
//!
//! # No economic effect before finality
//!
//! [`attest_settlement_log`] refuses anything above the finalized head before
//! it looks at anything else, and the callers ([`crate::adapter`],
//! [`crate::evidence`]) run it before an event or a
//! [`counterparty_api::VerifiedOutcome`] is produced. There is no path in this
//! crate that surfaces a settlement without it.

use std::collections::BTreeMap;

use counterparty_api::AdapterError;

use crate::error::RejectReason;
use crate::finality::FinalizedHead;
use crate::rpc::{EthClient, JsonRpc, RpcBlockHeader, RpcLog, RpcReceipt, RpcTransaction};

/// Maximum number of hash-linked steps one ancestry proof will take.
///
/// A round-trip budget, not a safety parameter: exceeding it is a refusal
/// ([`RejectReason::AncestryProofTooDeep`]), never a weaker check. 256 blocks is
/// roughly 51 minutes of Ethereum, comfortably past the ~13-minute finality lag
/// this adapter is normally observing across.
pub const MAX_ANCESTRY_WALK: u64 = 256;

/// Maximum number of `(height, hash)` links [`VerifiedChain`] retains.
///
/// Capped so the cache can never become an allocation lever (I14). Eviction
/// costs a re-walk and nothing else: dropping a proof does not un-prove
/// anything, it only forgets the shortcut.
///
/// [`VerifiedChain::with_capacity`] is public, so this cap is enforced by
/// clamping the requested capacity **before** anything is allocated — a caller
/// asking for `usize::MAX` gets this number, not an allocation lever.
pub const MAX_VERIFIED_CHAIN: usize = 4096;

/// Total number of hash-linked steps one *self-closing* proof may take.
///
/// Two paths need to close a gap without asking their caller to loop:
///
/// - [`verify_finalized_ancestry_deep`], which is how
///   [`crate::evidence::EvmEvidence::verify_onchain`] proves that a stored
///   observation still descends from the **current** finalized head;
/// - reconciling a [`VerifiedChain`] with a head that has moved on since its
///   links were proved.
///
/// Both do the work in [`MAX_ANCESTRY_WALK`]-sized batches and both stop here.
/// This is a *liveness* ceiling, stated rather than hidden: beyond it the
/// answer is [`RejectReason::AncestryProofTooDeep`] →
/// [`AdapterError::BoundsExceeded`], and never a weaker form of `Ok`.
/// [`crate::adapter::EvmAdapter::collect_evidence`] refuses to mint evidence
/// whose gap exceeds it, so nothing this crate produces is unverifiable by
/// construction.
pub const MAX_ANCESTRY_TOTAL: u64 = MAX_VERIFIED_CHAIN as u64;

/// Everything the attestation fetched, kept so callers do not have to ask
/// again for what has already been proved.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Attestation {
    /// The receipt, fetched with `eth_getTransactionReceipt`.
    pub receipt: RpcReceipt,
    /// The transaction, fetched with `eth_getTransactionByHash`.
    pub transaction: RpcTransaction,
    /// The canonical block header at the log's height.
    pub block: RpcBlockHeader,
}

/// Result alias for the attestation path, which reports precise reasons.
pub type Attested<T> = core::result::Result<T, RejectReason>;

/// Maps an RPC-layer failure onto a rejection reason, keeping "could not reach
/// the endpoint" apart from "the endpoint answered nonsense".
fn classify(e: AdapterError) -> RejectReason {
    match e {
        AdapterError::AdapterUnavailable => RejectReason::Transport,
        _ => RejectReason::MalformedAnswer,
    }
}

// ---------------------------------------------------------------------------
// the verified chain
// ---------------------------------------------------------------------------

/// Blocks proved — by following parent hashes — to lie on **one** finalized
/// chain, together with the identity of that chain.
///
/// # Why caching a proof is sound
///
/// A finalized block does not revert; that is the whole content of A4-EVM, and
/// it is the assumption every other part of this adapter already rests on. So
/// "block `h` on the finalized chain has hash `x`" is a permanent fact once
/// established, and re-deriving it would cost round trips to learn nothing.
///
/// # Why a height and a hash are not enough — and what the identity is
///
/// A link is only a proof *relative to the finalized head it was followed down
/// from*. Round 2 of the audit showed what happens when that is forgotten: an
/// observer proved links against chain A's head, was then handed chain B's head
/// — taller, disjoint, sharing only genesis — and answered "yes, ancestor"
/// about one of A's blocks with no round trip at all, because a taller head
/// never collides with a height the chain already holds.
///
/// So the chain carries an [`anchor`](Self::anchor): the finalized head every
/// retained link has been proved to descend from. Every entry point reconciles
/// it before answering (see [`verify_finalized_ancestry_cached`]), and
/// reconciliation is itself a followed chain of parent hashes.
///
/// # What it may never do
///
/// Invent a link. Entries are only ever added one per followed `parentHash`,
/// and a disagreement with an existing entry — or with the anchor, or with the
/// frontier — is a hard [`RejectReason::NotFinalizedAncestor`] rather than an
/// overwrite: two contradictory hashes at one height on a *finalized* chain
/// means one of the answers was a lie, and neither may be believed afterwards.
#[derive(Clone, Debug)]
pub struct VerifiedChain {
    /// The finalized head every retained link has been proved to descend from.
    /// This is the chain's identity; it is never evicted.
    anchor: Option<(u64, [u8; 32])>,
    /// The lowest link ever proved on this chain. Never evicted, so bounded
    /// batching keeps making net progress past `cap` links.
    frontier: Option<(u64, [u8; 32])>,
    by_height: BTreeMap<u64, [u8; 32]>,
    cap: usize,
}

impl Default for VerifiedChain {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifiedChain {
    /// An empty chain with the default cap.
    pub fn new() -> Self {
        Self::with_capacity(MAX_VERIFIED_CHAIN)
    }

    /// An empty chain retaining at most `cap` links.
    ///
    /// `cap` is clamped into `1..=MAX_VERIFIED_CHAIN` **before** the map is
    /// built. This constructor is public, so without the clamp it would be an
    /// I14 allocation lever: a caller naming `usize::MAX` would get a cache
    /// that grows one link per followed block with no ceiling at all.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            anchor: None,
            frontier: None,
            by_height: BTreeMap::new(),
            cap: cap.clamp(1, MAX_VERIFIED_CHAIN),
        }
    }

    /// The proved hash at `height`, if this chain still knows it.
    ///
    /// The anchor and the frontier are proved links too, and neither is
    /// evictable, so both answer here.
    pub fn get(&self, height: u64) -> Option<[u8; 32]> {
        if let Some(x) = self.by_height.get(&height) {
            return Some(*x);
        }
        if let Some((h, x)) = self.anchor {
            if h == height {
                return Some(x);
            }
        }
        if let Some((h, x)) = self.frontier {
            if h == height {
                return Some(x);
            }
        }
        None
    }

    /// Number of retained links, excluding the anchor and the frontier.
    pub fn len(&self) -> usize {
        self.by_height.len()
    }

    /// Whether no link is retained.
    pub fn is_empty(&self) -> bool {
        self.by_height.is_empty()
    }

    /// The finalized head this chain's links were proved to descend from.
    ///
    /// `None` on a fresh chain: it has no identity until it is first
    /// reconciled with a head.
    pub fn anchor(&self) -> Option<(u64, [u8; 32])> {
        self.anchor
    }

    /// The lowest link ever proved on this chain, evicted or not.
    ///
    /// This is the floor a further walk starts from, and the reason bounded
    /// batching converges: eviction can drop the retained window, but it can
    /// never drop the record of how far down the proof has already reached.
    pub fn frontier(&self) -> Option<(u64, [u8; 32])> {
        self.frontier
    }

    /// Lowest **retained** link, if any. Differs from [`Self::frontier`] once
    /// eviction has begun.
    pub fn lowest(&self) -> Option<(u64, [u8; 32])> {
        self.by_height.iter().next().map(|(h, x)| (*h, *x))
    }

    /// The lowest proved block at or above `height`.
    ///
    /// This is the cheapest place to start a downward walk towards `height`:
    /// everything above it is already proved, so only the delta is left. It
    /// must never answer *below* `height` — a walk started below its target
    /// takes no steps at all and would leave the target unproved.
    fn lowest_at_or_above(&self, height: u64) -> Option<(u64, [u8; 32])> {
        if let Some((h, x)) = self.frontier {
            if h >= height {
                return Some((h, x));
            }
        }
        if let Some(found) = self.by_height.range(height..).next().map(|(h, x)| (*h, *x)) {
            return Some(found);
        }
        match self.anchor {
            Some((h, x)) if h >= height => Some((h, x)),
            _ => None,
        }
    }

    /// Records one proved link. A contradiction is fatal, never an overwrite.
    fn record(&mut self, height: u64, hash: [u8; 32]) -> Attested<()> {
        if let Some(known) = self.get(height) {
            if known != hash {
                return Err(RejectReason::NotFinalizedAncestor);
            }
            return Ok(());
        }
        self.by_height.insert(height, hash);
        match self.frontier {
            Some((h, _)) if h <= height => {}
            _ => self.frontier = Some((height, hash)),
        }
        while self.by_height.len() > self.cap {
            let (Some(lo), Some(hi)) = (
                self.by_height.keys().next().copied(),
                self.by_height.keys().next_back().copied(),
            ) else {
                break;
            };
            if lo == hi {
                break;
            }
            // Evict the end *farther from the link just added*, never the link
            // just added. A live observer walking near the head keeps its
            // recent window; a cold observer batching downwards keeps its low
            // one, which is what stops the batching from evicting its own
            // progress and never converging. An evicted link costs a re-walk
            // and nothing else.
            let victim = if height.saturating_sub(lo) >= hi.saturating_sub(height) {
                lo
            } else {
                hi
            };
            self.by_height.remove(&victim);
        }
        Ok(())
    }

    /// Forgets every link and re-roots the chain on `finalized`.
    ///
    /// Only ever used when the new head is too far ahead to be followed down
    /// onto the anchor. Dropping proofs is always safe — it un-proves nothing,
    /// it only costs a re-walk — whereas keeping links whose relation to the
    /// current head is unknown is exactly the hole this type now closes.
    fn reset_to(&mut self, finalized: &FinalizedHead) {
        self.by_height.clear();
        self.frontier = None;
        self.anchor = Some((finalized.height, finalized.hash));
    }
}

// ---------------------------------------------------------------------------
// ancestry
// ---------------------------------------------------------------------------

/// Follows `parentHash` from `(from_height, from_hash)` down to `to_height` and
/// requires the walk to land on `to_hash`.
///
/// This is the **linkage primitive**, and it is important to be precise about
/// what it does and does not establish. It proves that `to_hash` is an ancestor
/// of `from_hash` *within whatever chain the endpoint served*. It says nothing
/// at all about whether that chain is the canonical, finalized one: an orphaned
/// fork is internally hash-linked too, and at `from_height == to_height` there
/// is nothing to follow, so the answer is a hash equality and no round trip.
///
/// It is therefore never sufficient on its own to accept a settlement. Round 2
/// of the audit found exactly that mistake — an "anchored proof" whose two ends
/// both came out of the record being verified, which at gap 0 compared a hash
/// to itself and otherwise re-proved that the attacker's fork was internally
/// consistent. Canonicity comes from
/// [`verify_finalized_ancestry`] and friends, whose upper end is the finalized
/// head the endpoint just named, not a value the caller supplied.
///
/// Every lookup is hash-addressed, so the endpoint cannot answer about a
/// different chain without contradicting a hash it already served. A parent it
/// cannot produce is such a contradiction, and is
/// [`RejectReason::NotFinalizedAncestor`]; so is a header served under a hash
/// that then reports a different `number`.
pub fn prove_hash_link<R: JsonRpc + ?Sized>(
    rpc: &R,
    from_height: u64,
    from_hash: &[u8; 32],
    to_height: u64,
    to_hash: &[u8; 32],
) -> Attested<()> {
    if to_height > from_height {
        return Err(RejectReason::AboveFinalizedHead);
    }
    if to_height == from_height {
        return if from_hash == to_hash {
            Ok(())
        } else {
            Err(RejectReason::NotFinalizedAncestor)
        };
    }
    if from_height.saturating_sub(to_height) > MAX_ANCESTRY_WALK {
        return Err(RejectReason::AncestryProofTooDeep);
    }

    let client = EthClient::new(rpc);
    let mut cursor = *from_hash;
    let mut at = from_height;
    while at > to_height {
        let header = match client.block_by_hash(&cursor).map_err(classify)? {
            Some(h) => h,
            // The endpoint served a header naming this parent and now cannot
            // produce it: a self-contradiction, not a lag.
            None => return Err(RejectReason::NotFinalizedAncestor),
        };
        if header.number != at {
            return Err(RejectReason::NotFinalizedAncestor);
        }
        cursor = header.parent_hash;
        at = at.saturating_sub(1);
    }
    if &cursor != to_hash {
        return Err(RejectReason::NotFinalizedAncestor);
    }
    Ok(())
}

/// Proves that `(height, hash)` is — or is an ancestor of — the finalized head,
/// with no cache.
///
/// Equivalent to [`verify_finalized_ancestry_cached`] against a fresh
/// [`VerifiedChain`]. Every link is walked.
pub fn verify_finalized_ancestry<R: JsonRpc + ?Sized>(
    rpc: &R,
    height: u64,
    hash: &[u8; 32],
    finalized: &FinalizedHead,
) -> Attested<()> {
    let mut chain = VerifiedChain::new();
    verify_finalized_ancestry_cached(rpc, height, hash, finalized, &mut chain)
}

/// Proves that `(height, hash)` is — or is an ancestor of — the finalized head,
/// recording every followed link in `chain` and starting from the lowest link
/// already proved.
///
/// `chain` is reconciled with `finalized` first (see
/// [`reconcile_anchor`]), so a cached answer is only ever given about a head the
/// cached links have been *followed down onto*. Without that step a warm
/// observer answers about a chain it has never seen — round 2 of the audit,
/// finding 3.
///
/// Returns [`RejectReason::AncestryProofTooDeep`] when the remaining gap is
/// wider than [`MAX_ANCESTRY_WALK`]. It never answers a weaker question
/// instead; see [`extend_verified_chain`] for how a caller closes a wide gap
/// and [`verify_finalized_ancestry_deep`] for the form that closes it itself.
pub fn verify_finalized_ancestry_cached<R: JsonRpc + ?Sized>(
    rpc: &R,
    height: u64,
    hash: &[u8; 32],
    finalized: &FinalizedHead,
    chain: &mut VerifiedChain,
) -> Attested<()> {
    if height > finalized.height {
        return Err(RejectReason::AboveFinalizedHead);
    }
    // The head is the root this proof hangs from, and the identity of the chain
    // every cached link belongs to. Reconciling also catches an endpoint that
    // answers the `finalized` tag differently across calls: that is a
    // contradiction on a chain that cannot revert.
    reconcile_anchor(rpc, finalized, chain)?;

    if let Some(known) = chain.get(height) {
        return if known == *hash {
            Ok(())
        } else {
            Err(RejectReason::NotFinalizedAncestor)
        };
    }

    // Start from the lowest block already proved to be on the finalized chain
    // at or above the target: everything above it is settled, so only the delta
    // needs walking. The anchor was just set, so this is always `Some`.
    let (start_height, start_hash) = chain
        .lowest_at_or_above(height)
        .ok_or(RejectReason::NotFinalizedAncestor)?;

    walk_and_record(
        rpc,
        start_height,
        start_hash,
        height,
        chain,
        MAX_ANCESTRY_WALK,
    )?;

    match chain.get(height) {
        Some(proved) if proved == *hash => Ok(()),
        _ => Err(RejectReason::NotFinalizedAncestor),
    }
}

/// Proves ancestry, closing a gap wider than one walk **itself**, in the same
/// bounded batches a caller would have used.
///
/// This is the form evidence verification needs: it cannot hand a "call me
/// again" back to whoever asked whether a settlement is real. It follows at most
/// [`MAX_ANCESTRY_TOTAL`] links and then refuses with
/// [`RejectReason::AncestryProofTooDeep`]. It also refuses if a batch fails to
/// lower the frontier, so it can never spin.
///
/// The ceiling is a liveness bound and is stated as one: past it this returns a
/// refusal, never `Ok`.
pub fn verify_finalized_ancestry_deep<R: JsonRpc + ?Sized>(
    rpc: &R,
    height: u64,
    hash: &[u8; 32],
    finalized: &FinalizedHead,
    chain: &mut VerifiedChain,
) -> Attested<()> {
    let mut spent = 0u64;
    loop {
        // Each attempt resumes from the frontier the previous one left behind,
        // so the batches compose into one walk with no link skipped.
        let before = chain.frontier().map(|(h, _)| h).unwrap_or(finalized.height);
        match verify_finalized_ancestry_cached(rpc, height, hash, finalized, chain) {
            Err(RejectReason::AncestryProofTooDeep) => {}
            settled => return settled,
        }
        let after = chain.frontier().map(|(h, _)| h).unwrap_or(before);
        if after >= before {
            // A batch that lowers nothing will never lower anything. Refuse
            // rather than loop; the caller gets a bound, not a hang.
            return Err(RejectReason::AncestryProofTooDeep);
        }
        // Counted in links actually followed, so the ceiling means the same
        // thing on a cold chain and on a warm one.
        spent = spent.saturating_add(before.saturating_sub(after));
        if spent >= MAX_ANCESTRY_TOTAL {
            return Err(RejectReason::AncestryProofTooDeep);
        }
    }
}

/// Reconciles `chain` with the finalized head the caller is asking about.
///
/// A cached link is a proof *relative to the head it was followed down from*.
/// So before any cached answer may be given, the head in hand and the head the
/// chain already holds must be shown to be the same chain, and the only way to
/// show that is to follow the links between them.
///
/// | relation to the anchor | what happens |
/// |---|---|
/// | no anchor yet | the head becomes the anchor; nothing is cached yet, so nothing is being vouched for |
/// | same height | the hashes must be equal, or a finalized chain has two blocks at one height — [`RejectReason::NotFinalizedAncestor`] |
/// | below the anchor | it must be a link we already proved; if it is unknown, this endpoint is behind what we already proved final, which is [`RejectReason::BlockMissing`] → unavailability, not a fork |
/// | above the anchor, within [`MAX_ANCESTRY_TOTAL`] | followed hash by hash down onto the anchor; a mismatch anywhere is a contradiction |
/// | further above | the chain is emptied and re-rooted on the new head |
///
/// The last row is safe because forgetting a proof un-proves nothing: the next
/// question is then answered by a fresh walk from the new head. What would
/// *not* be safe — and is what finding 3 exploited — is keeping links whose
/// relation to the head in hand is unknown.
fn reconcile_anchor<R: JsonRpc + ?Sized>(
    rpc: &R,
    finalized: &FinalizedHead,
    chain: &mut VerifiedChain,
) -> Attested<()> {
    let Some((anchor_height, anchor_hash)) = chain.anchor() else {
        chain.anchor = Some((finalized.height, finalized.hash));
        return Ok(());
    };
    if finalized.height == anchor_height {
        return if finalized.hash == anchor_hash {
            Ok(())
        } else {
            Err(RejectReason::NotFinalizedAncestor)
        };
    }
    if finalized.height < anchor_height {
        return match chain.get(finalized.height) {
            Some(known) if known == finalized.hash => Ok(()),
            Some(_) => Err(RejectReason::NotFinalizedAncestor),
            None => Err(RejectReason::BlockMissing),
        };
    }
    if finalized.height.saturating_sub(anchor_height) > MAX_ANCESTRY_TOTAL {
        chain.reset_to(finalized);
        return Ok(());
    }
    // `walk_and_record` records the link it lands on, and `record` compares it
    // against what the chain already holds — the anchor included. **That
    // comparison is the reconciliation**: there is deliberately no second check
    // after the walk, because a check that re-reads the anchor would still pass
    // if the recording were ever dropped, and would hide exactly the bug it
    // looks like it is guarding against.
    walk_and_record(
        rpc,
        finalized.height,
        finalized.hash,
        anchor_height,
        chain,
        MAX_ANCESTRY_TOTAL,
    )?;
    chain.anchor = Some((finalized.height, finalized.hash));
    Ok(())
}

/// Walks down from `(at, cursor)` towards `target`, recording each followed
/// link. Stops with [`RejectReason::AncestryProofTooDeep`] once `budget` steps
/// are spent — the links already recorded stay recorded, so a later call
/// resumes from where this one stopped.
fn walk_and_record<R: JsonRpc + ?Sized>(
    rpc: &R,
    mut at: u64,
    mut cursor: [u8; 32],
    target: u64,
    chain: &mut VerifiedChain,
    budget: u64,
) -> Attested<()> {
    let client = EthClient::new(rpc);
    let mut steps = 0u64;
    while at > target {
        if steps >= budget {
            return Err(RejectReason::AncestryProofTooDeep);
        }
        let header = match client.block_by_hash(&cursor).map_err(classify)? {
            Some(h) => h,
            None => return Err(RejectReason::NotFinalizedAncestor),
        };
        if header.number != at {
            return Err(RejectReason::NotFinalizedAncestor);
        }
        cursor = header.parent_hash;
        at = at.saturating_sub(1);
        steps = steps.saturating_add(1);
        chain.record(at, cursor)?;
    }
    Ok(())
}

/// Extends `chain` downwards by at most [`MAX_ANCESTRY_WALK`] proved links,
/// towards `target_height`.
///
/// The escape hatch for a gap wider than one proof may walk: call it until it
/// reports having reached `target_height`. Work per call is bounded, total work
/// is the real gap, and **every link it records was followed hash by hash** —
/// which is the property [`RejectReason::AncestryProofTooDeep`] exists to
/// protect.
///
/// Progress is measured by [`VerifiedChain::frontier`], not by the retained
/// window, so batching converges even past [`MAX_VERIFIED_CHAIN`] links: it is
/// the *record of how far down the walk reached* that must survive eviction,
/// not the links themselves.
///
/// Returns the lowest height now proved. That number is the caller's loop
/// condition, so it is read back out of the chain rather than assumed.
pub fn extend_verified_chain<R: JsonRpc + ?Sized>(
    rpc: &R,
    target_height: u64,
    finalized: &FinalizedHead,
    chain: &mut VerifiedChain,
) -> Attested<u64> {
    reconcile_anchor(rpc, finalized, chain)?;
    let (at, cursor) = chain
        .frontier()
        .or_else(|| chain.anchor())
        .unwrap_or((finalized.height, finalized.hash));
    if at <= target_height {
        return Ok(at);
    }
    match walk_and_record(rpc, at, cursor, target_height, chain, MAX_ANCESTRY_WALK) {
        // Budget spent: progress was still made and persisted.
        Ok(()) | Err(RejectReason::AncestryProofTooDeep) => {}
        Err(other) => return Err(other),
    }
    Ok(chain.frontier().map(|(h, _)| h).unwrap_or(at))
}

// ---------------------------------------------------------------------------
// settlement attestation
// ---------------------------------------------------------------------------

/// Corroborates one settlement log against independently fetched receipt,
/// transaction, block and finalized ancestry, with no cache.
pub fn attest_settlement_log<R: JsonRpc + ?Sized>(
    rpc: &R,
    contract: &[u8; 20],
    log: &RpcLog,
    finalized: &FinalizedHead,
) -> Attested<Attestation> {
    let mut chain = VerifiedChain::new();
    attest_settlement_log_cached(rpc, contract, log, finalized, &mut chain)
}

/// Corroborates one settlement log, reusing and extending an already-proved
/// [`VerifiedChain`].
///
/// `log` is whatever `eth_getLogs` produced; nothing about it is believed. The
/// caller must still decode and interpret it (see
/// [`crate::evidence::decode_settlement_log`]) — this function establishes that
/// the log is *really there, really succeeded, and is really final*.
pub fn attest_settlement_log_cached<R: JsonRpc + ?Sized>(
    rpc: &R,
    contract: &[u8; 20],
    log: &RpcLog,
    finalized: &FinalizedHead,
    chain: &mut VerifiedChain,
) -> Attested<Attestation> {
    // 0. Finality first. Nothing below this line may run for a block that could
    //    still be reorged out: no economic effect before finality, absolutely.
    if log.block_number > finalized.height {
        return Err(RejectReason::AboveFinalizedHead);
    }
    // A log the endpoint itself marks as orphaned, or that names another
    // emitter, is refused before a single round trip is spent on it.
    if log.removed {
        return Err(RejectReason::LogMarkedRemoved);
    }
    if &log.address != contract {
        return Err(RejectReason::LogEmitterMismatch);
    }

    let client = EthClient::new(rpc);

    // 1. The receipt, fetched independently of the log.
    let receipt = client
        .receipt(&log.tx_hash)
        .map_err(classify)?
        .ok_or(RejectReason::ReceiptMissing)?;
    if receipt.status != 1 {
        return Err(RejectReason::ReceiptReverted);
    }
    if receipt.tx_hash != log.tx_hash {
        return Err(RejectReason::ReceiptInconsistent);
    }
    if receipt.block_number != log.block_number {
        return Err(RejectReason::ReceiptInconsistent);
    }
    if receipt.block_hash != log.block_hash {
        return Err(RejectReason::ReceiptInconsistent);
    }
    // The log must be *in* the receipt, at the index it claims, and must be the
    // same log. This is the check that makes a fabricated `eth_getLogs` entry
    // useless: the receipt is the node's own record of what the transaction
    // emitted, and `topics` is where `lockId`, `binding` and the indexed party
    // live — everything the decoder goes on to interpret.
    let in_receipt = receipt
        .log_at(log.log_index)
        .ok_or(RejectReason::LogAbsentFromReceipt)?;
    if in_receipt.address != log.address {
        return Err(RejectReason::LogAbsentFromReceipt);
    }
    if in_receipt.topics != log.topics {
        return Err(RejectReason::LogAbsentFromReceipt);
    }
    if in_receipt.data != log.data {
        return Err(RejectReason::LogAbsentFromReceipt);
    }
    if in_receipt.tx_hash != log.tx_hash {
        return Err(RejectReason::LogAbsentFromReceipt);
    }
    if in_receipt.block_hash != log.block_hash {
        return Err(RejectReason::LogAbsentFromReceipt);
    }
    if in_receipt.block_number != log.block_number {
        return Err(RejectReason::LogAbsentFromReceipt);
    }
    if in_receipt.removed {
        return Err(RejectReason::LogAbsentFromReceipt);
    }

    // 2. The transaction, fetched independently of the receipt.
    let transaction = client
        .transaction(&log.tx_hash)
        .map_err(classify)?
        .ok_or(RejectReason::TransactionMissing)?;
    if transaction.hash != receipt.tx_hash {
        return Err(RejectReason::TransactionInconsistent);
    }
    // Includes the pending case: a transaction with no block cannot have
    // produced a finalized log.
    if transaction.block_hash != Some(receipt.block_hash) {
        return Err(RejectReason::TransactionInconsistent);
    }
    if transaction.block_number != Some(receipt.block_number) {
        return Err(RejectReason::TransactionInconsistent);
    }
    if transaction.to != Some(*contract) {
        // A settlement log can only come from a call into the lock contract. A
        // contract creation (`to == null`) or a call to anything else means the
        // log was attributed to the wrong transaction.
        return Err(RejectReason::TransactionNotToContract);
    }

    // 3. The block, fetched independently, and canonical at that height.
    //    This is the height-addressed lookup, so a node that simply has not
    //    synced this far answers `null` here — unavailability, not a fork.
    let block = client
        .block_by_number(log.block_number)
        .map_err(classify)?
        .ok_or(RejectReason::BlockMissing)?;
    if block.hash != log.block_hash {
        return Err(RejectReason::NotCanonical);
    }

    // 4. Finalized ancestry: hash-linked, at any gap, or refused.
    verify_finalized_ancestry_cached(rpc, log.block_number, &log.block_hash, finalized, chain)?;

    Ok(Attestation {
        receipt,
        transaction,
        block,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::event_topic0;
    use crate::abi::SIG_CLAIMED;
    use crate::mock::{Faults, MockChain};

    const CONTRACT: [u8; 20] = [0xC0; 20];

    /// A chain with one `Claimed` log at height 2, finalized at the tip.
    fn chain_with_a_claim() -> (MockChain, RpcLog, FinalizedHead) {
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(2);
        c.push_claimed([1u8; 32], [2u8; 32], [3u8; 20], [4u8; 32])
            .expect("log appended");
        c.set_finalized(2);
        let log = EthClient::new(&c)
            .logs(0, 2, &CONTRACT, &[event_topic0(SIG_CLAIMED)])
            .expect("logs")
            .first()
            .cloned()
            .expect("one log");
        let head = crate::finality::fetch_finalized(&c).expect("finalized");
        (c, log, head)
    }

    #[test]
    fn a_fully_corroborated_log_is_attested() {
        let (c, log, head) = chain_with_a_claim();
        let a = attest_settlement_log(&c, &CONTRACT, &log, &head).expect("attested");
        assert_eq!(a.receipt.status, 1);
        assert_eq!(a.transaction.to, Some(CONTRACT));
        assert_eq!(a.block.hash, log.block_hash);
    }

    #[test]
    fn finality_is_checked_before_any_round_trip_is_spent() {
        let (c, log, _) = chain_with_a_claim();
        let low = FinalizedHead {
            height: log.block_number.saturating_sub(1),
            hash: c.block_hash(log.block_number - 1).expect("block"),
        };
        assert_eq!(
            attest_settlement_log(&c, &CONTRACT, &log, &low),
            Err(RejectReason::AboveFinalizedHead)
        );
    }

    #[test]
    fn a_transport_failure_is_never_a_verdict() {
        let (c, log, head) = chain_with_a_claim();
        let dead = c.with_faults(Faults {
            break_transport: true,
            ..Faults::default()
        });
        assert_eq!(
            attest_settlement_log(&dead, &CONTRACT, &log, &head),
            Err(RejectReason::Transport)
        );
    }

    #[test]
    fn a_malformed_answer_is_not_reported_as_a_dead_socket() {
        let (c, log, head) = chain_with_a_claim();
        let garbage = c.with_faults(Faults {
            garbage_results: true,
            ..Faults::default()
        });
        let reason =
            attest_settlement_log(&garbage, &CONTRACT, &log, &head).expect_err("must reject");
        assert_eq!(reason, RejectReason::MalformedAnswer);
        assert_ne!(reason, RejectReason::Transport);
    }

    #[test]
    fn a_log_from_a_foreign_emitter_never_reaches_the_chain() {
        let (c, mut log, head) = chain_with_a_claim();
        log.address = [0xDE; 20];
        assert_eq!(
            attest_settlement_log(&c, &CONTRACT, &log, &head),
            Err(RejectReason::LogEmitterMismatch)
        );
    }

    #[test]
    fn a_log_the_endpoint_marks_removed_is_never_attested() {
        let (c, mut log, head) = chain_with_a_claim();
        log.removed = true;
        assert_eq!(
            attest_settlement_log(&c, &CONTRACT, &log, &head),
            Err(RejectReason::LogMarkedRemoved)
        );
    }

    #[test]
    fn ancestry_accepts_the_finalized_head_itself() {
        let (c, _, head) = chain_with_a_claim();
        assert_eq!(
            verify_finalized_ancestry(&c, head.height, &head.hash, &head),
            Ok(())
        );
        assert_eq!(
            verify_finalized_ancestry(&c, head.height, &[0xAB; 32], &head),
            Err(RejectReason::NotFinalizedAncestor)
        );
    }

    #[test]
    fn ancestry_walks_parent_hashes_at_every_depth() {
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(8);
        c.set_finalized(8);
        let head = crate::finality::fetch_finalized(&c).expect("finalized");
        for h in 0..8u64 {
            assert_eq!(
                verify_finalized_ancestry(&c, h, &c.block_hash(h).expect("block"), &head),
                Ok(()),
                "block {h} must be an ancestor of the finalized head"
            );
        }
        assert_eq!(
            verify_finalized_ancestry(&c, 4, &[0x77; 32], &head),
            Err(RejectReason::NotFinalizedAncestor)
        );
    }

    #[test]
    fn broken_parent_linkage_breaks_ancestry_at_every_depth() {
        // The P1 regression, in miniature: the same endpoint fault must be
        // refused inside *and* outside any walk budget. The old defect was that
        // beyond the budget the fault stopped being visible at all.
        for gap in [1u64, 4, MAX_ANCESTRY_WALK - 1, MAX_ANCESTRY_WALK + 5] {
            let tip = gap + 1;
            let mut c = MockChain::new(31337, CONTRACT).with_blocks(tip);
            c.set_finalized(tip);
            let head = crate::finality::fetch_finalized(&c).expect("finalized");
            let target = c.block_hash(tip - gap).expect("block");

            // An honest endpoint is accepted within the budget and refused —
            // not weakened — beyond it.
            let control = verify_finalized_ancestry(&c, tip - gap, &target, &head);
            if gap <= MAX_ANCESTRY_WALK {
                assert_eq!(control, Ok(()), "honest control at gap {gap}");
            } else {
                assert_eq!(
                    control,
                    Err(RejectReason::AncestryProofTooDeep),
                    "beyond the budget an honest chain is refused, never guessed"
                );
            }

            // The dishonest endpoint is refused at every gap, and always for
            // the *ancestry* reason: the walk starts at the head and the very
            // first parent it names cannot be produced, so the budget never
            // comes into it.
            let orphaned = c.with_faults(Faults {
                orphan_parent_linkage: true,
                ..Faults::default()
            });
            assert_eq!(
                verify_finalized_ancestry(&orphaned, tip - gap, &target, &head),
                Err(RejectReason::NotFinalizedAncestor),
                "gap {gap}: a head that cannot be linked to the observation \
                 proves nothing, at any depth"
            );
        }
    }

    #[test]
    fn a_gap_wider_than_the_budget_is_refused_not_weakened() {
        let tip = MAX_ANCESTRY_WALK * 2;
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(tip);
        c.set_finalized(tip);
        let head = crate::finality::fetch_finalized(&c).expect("finalized");
        let target = c.block_hash(0).expect("genesis");
        assert_eq!(
            verify_finalized_ancestry(&c, 0, &target, &head),
            Err(RejectReason::AncestryProofTooDeep),
            "an honest chain too deep to walk in one call is refused, not guessed"
        );
        assert_eq!(
            AdapterError::from(RejectReason::AncestryProofTooDeep),
            AdapterError::BoundsExceeded
        );
    }

    #[test]
    fn bounded_batches_close_a_gap_the_budget_refuses() {
        let tip = MAX_ANCESTRY_WALK * 2 + 5;
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(tip);
        c.set_finalized(tip);
        let head = crate::finality::fetch_finalized(&c).expect("finalized");
        let target = c.block_hash(0).expect("genesis");

        let mut chain = VerifiedChain::new();
        assert_eq!(
            verify_finalized_ancestry_cached(&c, 0, &target, &head, &mut chain),
            Err(RejectReason::AncestryProofTooDeep)
        );
        // Each batch is bounded; progress persists across calls.
        let mut rounds = 0;
        loop {
            let lowest = extend_verified_chain(&c, 0, &head, &mut chain).expect("batch");
            rounds += 1;
            assert!(rounds < 16, "batching must converge");
            if lowest == 0 {
                break;
            }
        }
        assert_eq!(
            verify_finalized_ancestry_cached(&c, 0, &target, &head, &mut chain),
            Ok(()),
            "every link was followed hash by hash, just across several calls"
        );
        // And the batched proof is still a proof: a wrong hash is refused.
        assert_eq!(
            verify_finalized_ancestry_cached(&c, 0, &[0x99; 32], &head, &mut chain),
            Err(RejectReason::NotFinalizedAncestor)
        );
    }

    #[test]
    fn a_proved_link_makes_the_next_proof_free_but_never_invents_one() {
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(10);
        c.set_finalized(10);
        let head = crate::finality::fetch_finalized(&c).expect("finalized");
        let mut chain = VerifiedChain::new();
        let target = c.block_hash(3).expect("block");
        assert_eq!(
            verify_finalized_ancestry_cached(&c, 3, &target, &head, &mut chain),
            Ok(())
        );
        assert!(chain.len() >= 7, "every followed link is recorded");
        // A different hash at a proved height is refused from the cache alone.
        assert_eq!(
            verify_finalized_ancestry_cached(&c, 3, &[0x01; 32], &head, &mut chain),
            Err(RejectReason::NotFinalizedAncestor)
        );
    }

    #[test]
    fn the_verified_chain_refuses_to_hold_two_hashes_for_one_height() {
        let mut chain = VerifiedChain::with_capacity(8);
        assert_eq!(chain.record(5, [1u8; 32]), Ok(()));
        assert_eq!(chain.record(5, [1u8; 32]), Ok(()), "idempotent");
        assert_eq!(
            chain.record(5, [2u8; 32]),
            Err(RejectReason::NotFinalizedAncestor),
            "a finalized chain cannot carry two blocks at one height"
        );
        assert_eq!(chain.get(5), Some([1u8; 32]));
    }

    #[test]
    fn the_verified_chain_is_capped() {
        let mut chain = VerifiedChain::with_capacity(4);
        for h in 0..32u64 {
            chain.record(h, [h as u8; 32]).expect("record");
        }
        assert_eq!(chain.len(), 4);
        assert_eq!(chain.lowest().map(|(h, _)| h), Some(28));
        assert!(VerifiedChain::with_capacity(0).is_empty());
    }

    #[test]
    fn an_endpoint_that_changes_its_finalized_answer_is_caught() {
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(6);
        c.set_finalized(6);
        let head = crate::finality::fetch_finalized(&c).expect("finalized");
        let mut chain = VerifiedChain::new();
        assert_eq!(
            verify_finalized_ancestry_cached(
                &c,
                6,
                &c.block_hash(6).expect("block"),
                &head,
                &mut chain
            ),
            Ok(())
        );
        // The same height, a different "finalized" hash: a finalized chain
        // cannot have changed there.
        let liar = FinalizedHead {
            height: head.height,
            hash: [0xF0; 32],
        };
        assert_eq!(
            verify_finalized_ancestry_cached(&c, 6, &liar.hash, &liar, &mut chain),
            Err(RejectReason::NotFinalizedAncestor)
        );
    }

    #[test]
    fn a_hash_link_is_proved_from_the_anchor_the_caller_names() {
        // The shape `verify_onchain` relies on: both endpoints of the walk come
        // from the evidence, so its cost never grows with the evidence's age.
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(12);
        c.set_finalized(12);
        let anchor = c.block_hash(9).expect("block");
        let target = c.block_hash(5).expect("block");
        assert_eq!(prove_hash_link(&c, 9, &anchor, 5, &target), Ok(()));
        assert_eq!(prove_hash_link(&c, 9, &anchor, 9, &anchor), Ok(()));
        assert_eq!(
            prove_hash_link(&c, 9, &anchor, 5, &[0x42; 32]),
            Err(RejectReason::NotFinalizedAncestor)
        );
        assert_eq!(
            prove_hash_link(&c, 5, &target, 9, &anchor),
            Err(RejectReason::AboveFinalizedHead)
        );
        let orphaned = c.with_faults(Faults {
            orphan_parent_linkage: true,
            ..Faults::default()
        });
        assert_eq!(
            prove_hash_link(&orphaned, 9, &anchor, 5, &target),
            Err(RejectReason::NotFinalizedAncestor)
        );
    }

    // -----------------------------------------------------------------------
    // the chain's identity (audit round 2, finding 3)
    // -----------------------------------------------------------------------

    /// Two chains sharing only genesis: `a` is `tip_a` tall, `b` is `tip_b`.
    fn forked_pair(tip_a: u64, tip_b: u64) -> (MockChain, MockChain) {
        let mut a = MockChain::new(31337, CONTRACT).with_blocks(tip_a);
        a.set_finalized(tip_a);
        let mut b = a.clone();
        b.reorg(b.height());
        while b.height() < tip_b {
            b.push_block();
        }
        b.set_finalized(b.height());
        (a, b)
    }

    #[test]
    fn the_chain_takes_its_identity_from_the_head_it_was_proved_against() {
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(6);
        c.set_finalized(6);
        let head = crate::finality::fetch_finalized(&c).expect("finalized");
        let mut chain = VerifiedChain::new();
        assert_eq!(chain.anchor(), None, "a fresh chain vouches for nothing");
        assert_eq!(
            verify_finalized_ancestry_cached(
                &c,
                2,
                &c.block_hash(2).expect("block"),
                &head,
                &mut chain
            ),
            Ok(())
        );
        assert_eq!(chain.anchor(), Some((head.height, head.hash)));
        assert_eq!(
            chain.get(head.height),
            Some(head.hash),
            "the anchor is a proved link and answers like one"
        );
    }

    #[test]
    fn a_head_the_chain_was_never_linked_to_is_not_answered_out_of_it() {
        // Prove links against A's head; then present B's head — taller,
        // disjoint, sharing only genesis — and ask about one of A's blocks.
        // Before the anchor existed this answered `Ok` in zero round trips,
        // because `record` only collides at a height already held and a taller
        // head never collides.
        let (a, b) = forked_pair(10, 40);
        let head_a = crate::finality::fetch_finalized(&a).expect("finalized");
        let head_b = crate::finality::fetch_finalized(&b).expect("finalized");
        let a3 = a.block_hash(3).expect("block");
        assert_ne!(b.block_hash(3), Some(a3), "fixture: B really is a fork");

        let mut chain = VerifiedChain::new();
        assert_eq!(
            verify_finalized_ancestry_cached(&a, 3, &a3, &head_a, &mut chain),
            Ok(())
        );
        assert_eq!(
            verify_finalized_ancestry_cached(&b, 3, &a3, &head_b, &mut chain),
            Err(RejectReason::NotFinalizedAncestor),
            "the reconciliation walk lands on B's block at A's anchor height"
        );
    }

    #[test]
    fn a_contradiction_met_while_walking_is_fatal_not_swallowed() {
        // The same shape, isolated: the reconciliation walk crosses a height
        // the chain already holds. `record` is the comparison, so swallowing
        // its error is exactly as bad as not walking at all.
        let (a, b) = forked_pair(4, 12);
        let head_a = crate::finality::fetch_finalized(&a).expect("finalized");
        let head_b = crate::finality::fetch_finalized(&b).expect("finalized");
        let a2 = a.block_hash(2).expect("block");
        let mut chain = VerifiedChain::new();
        assert_eq!(
            verify_finalized_ancestry_cached(&a, 2, &a2, &head_a, &mut chain),
            Ok(())
        );
        assert_eq!(
            verify_finalized_ancestry_cached(&b, 2, &a2, &head_b, &mut chain),
            Err(RejectReason::NotFinalizedAncestor)
        );
        // ... and it stays refused: the chain does not quietly re-root itself
        // onto the liar and answer differently next time.
        assert_eq!(
            verify_finalized_ancestry_cached(&b, 2, &a2, &head_b, &mut chain),
            Err(RejectReason::NotFinalizedAncestor)
        );
    }

    #[test]
    fn a_head_too_far_ahead_re_roots_the_chain_instead_of_reusing_it() {
        // Past `MAX_ANCESTRY_TOTAL` the connection cannot be followed at all.
        // Keeping the links would be finding 3 again; the chain therefore
        // forgets them, and the next question is answered by a fresh walk from
        // the new head — which for a deep target is a refusal, never an `Ok`.
        let (a, b) = forked_pair(10, MAX_ANCESTRY_TOTAL + 20);
        let head_a = crate::finality::fetch_finalized(&a).expect("finalized");
        let head_b = crate::finality::fetch_finalized(&b).expect("finalized");
        let a3 = a.block_hash(3).expect("block");
        let mut chain = VerifiedChain::new();
        assert_eq!(
            verify_finalized_ancestry_cached(&a, 3, &a3, &head_a, &mut chain),
            Ok(())
        );
        assert_eq!(
            verify_finalized_ancestry_cached(&b, 3, &a3, &head_b, &mut chain),
            Err(RejectReason::AncestryProofTooDeep),
            "re-rooted, so the cached links no longer answer for anything"
        );
        assert_eq!(chain.anchor(), Some((head_b.height, head_b.hash)));
        assert_eq!(chain.get(3), None, "the forgotten links really are gone");
    }

    #[test]
    fn a_head_below_the_anchor_is_matched_against_a_proved_link_or_refused() {
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(10);
        c.set_finalized(10);
        let head = crate::finality::fetch_finalized(&c).expect("finalized");
        let mut chain = VerifiedChain::new();
        assert_eq!(
            verify_finalized_ancestry_cached(
                &c,
                6,
                &c.block_hash(6).expect("block"),
                &head,
                &mut chain
            ),
            Ok(())
        );
        // A head that moved *backwards* onto a link we already proved is the
        // same chain, merely a lagging answer.
        let behind = FinalizedHead {
            height: 8,
            hash: c.block_hash(8).expect("block"),
        };
        assert_eq!(
            verify_finalized_ancestry_cached(
                &c,
                6,
                &c.block_hash(6).expect("block"),
                &behind,
                &mut chain
            ),
            Ok(())
        );
        // A head that moved backwards onto a *different* block at a height we
        // proved final is a contradiction.
        let liar = FinalizedHead {
            height: 8,
            hash: [0xB8; 32],
        };
        assert_eq!(
            verify_finalized_ancestry_cached(
                &c,
                6,
                &c.block_hash(6).expect("block"),
                &liar,
                &mut chain
            ),
            Err(RejectReason::NotFinalizedAncestor)
        );
        // A head below everything we hold cannot be checked at all: that is an
        // endpoint behind what we already proved final, which is
        // unavailability rather than a verdict about the settlement.
        let far_behind = FinalizedHead {
            height: 2,
            hash: c.block_hash(2).expect("block"),
        };
        assert_eq!(
            verify_finalized_ancestry_cached(
                &c,
                1,
                &c.block_hash(1).expect("block"),
                &far_behind,
                &mut chain
            ),
            Err(RejectReason::BlockMissing)
        );
        assert_eq!(
            AdapterError::from(RejectReason::BlockMissing),
            AdapterError::AdapterUnavailable
        );
    }

    // -----------------------------------------------------------------------
    // the deep proof and its stated ceiling
    // -----------------------------------------------------------------------

    #[test]
    fn a_deep_proof_closes_a_gap_one_walk_refuses_and_still_refuses_a_lie() {
        let tip = MAX_ANCESTRY_WALK * 3 + 7;
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(tip);
        c.set_finalized(tip);
        let head = crate::finality::fetch_finalized(&c).expect("finalized");
        let genesis = c.block_hash(0).expect("genesis");

        // One call cannot walk it ...
        assert_eq!(
            verify_finalized_ancestry(&c, 0, &genesis, &head),
            Err(RejectReason::AncestryProofTooDeep)
        );
        // ... the deep form closes it in batches, every link followed.
        let mut chain = VerifiedChain::new();
        assert_eq!(
            verify_finalized_ancestry_deep(&c, 0, &genesis, &head, &mut chain),
            Ok(())
        );
        // And it is still a proof: a wrong hash at the same height is refused.
        let mut other = VerifiedChain::new();
        assert_eq!(
            verify_finalized_ancestry_deep(&c, 0, &[0x99; 32], &head, &mut other),
            Err(RejectReason::NotFinalizedAncestor)
        );
        // An endpoint that cannot exhibit the linkage is refused, not batched
        // around.
        let orphaned = c.with_faults(Faults {
            orphan_parent_linkage: true,
            ..Faults::default()
        });
        let mut third = VerifiedChain::new();
        assert_eq!(
            verify_finalized_ancestry_deep(&orphaned, 0, &genesis, &head, &mut third),
            Err(RejectReason::NotFinalizedAncestor)
        );
    }

    #[test]
    fn a_deep_proof_stops_at_its_stated_ceiling() {
        let tip = MAX_ANCESTRY_TOTAL + MAX_ANCESTRY_WALK;
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(tip);
        c.set_finalized(tip);
        let head = crate::finality::fetch_finalized(&c).expect("finalized");
        let genesis = c.block_hash(0).expect("genesis");
        let mut chain = VerifiedChain::new();
        assert_eq!(
            verify_finalized_ancestry_deep(&c, 0, &genesis, &head, &mut chain),
            Err(RejectReason::AncestryProofTooDeep),
            "the ceiling is a refusal, never a weaker Ok"
        );
        // Exactly at the ceiling it still succeeds, so the refusal is the
        // bound and not a blanket failure.
        let at_ceiling = tip.saturating_sub(MAX_ANCESTRY_TOTAL);
        let mut inside = VerifiedChain::new();
        assert_eq!(
            verify_finalized_ancestry_deep(
                &c,
                at_ceiling,
                &c.block_hash(at_ceiling).expect("block"),
                &head,
                &mut inside
            ),
            Ok(())
        );
    }

    // -----------------------------------------------------------------------
    // batching: bounded work, real progress
    // -----------------------------------------------------------------------

    #[test]
    fn extend_verified_chain_reports_only_the_progress_it_made() {
        let tip = MAX_ANCESTRY_WALK * 3;
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(tip);
        c.set_finalized(tip);
        let head = crate::finality::fetch_finalized(&c).expect("finalized");
        let mut chain = VerifiedChain::new();
        // A caller loops on this number. A batch that reported the height it
        // was *asked* for rather than the one it *reached* would send the
        // caller away believing in a proof nobody made.
        let mut expected = tip;
        for round in 1..=3u64 {
            expected = expected.saturating_sub(MAX_ANCESTRY_WALK);
            assert_eq!(
                extend_verified_chain(&c, 0, &head, &mut chain),
                Ok(expected),
                "round {round} reached exactly one budget further down"
            );
            assert_eq!(chain.frontier().map(|(h, _)| h), Some(expected));
        }
        assert_eq!(extend_verified_chain(&c, 0, &head, &mut chain), Ok(0));
    }

    #[test]
    fn extending_the_chain_reconciles_the_head_it_is_given() {
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(8);
        c.set_finalized(8);
        let head = crate::finality::fetch_finalized(&c).expect("finalized");
        let mut chain = VerifiedChain::new();
        assert_eq!(extend_verified_chain(&c, 0, &head, &mut chain), Ok(0));
        let liar = FinalizedHead {
            height: head.height,
            hash: [0xF0; 32],
        };
        assert_eq!(
            extend_verified_chain(&c, 0, &liar, &mut chain),
            Err(RejectReason::NotFinalizedAncestor),
            "a second, different answer at a finalized height is a contradiction"
        );
    }

    #[test]
    fn batching_still_converges_once_eviction_has_begun() {
        // The retained window is four links; the walk is ten times that. What
        // must survive eviction is not the links but the *record of how far
        // down the walk reached* — otherwise every batch evicts the progress
        // the previous one made and the loop never terminates.
        let tip = 40u64;
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(tip);
        c.set_finalized(tip);
        let head = crate::finality::fetch_finalized(&c).expect("finalized");
        let genesis = c.block_hash(0).expect("genesis");
        let mut chain = VerifiedChain::with_capacity(4);
        let mut rounds = 0;
        loop {
            let lowest = extend_verified_chain(&c, 0, &head, &mut chain).expect("batch");
            rounds += 1;
            assert!(rounds < 8, "batching must converge under eviction");
            if lowest == 0 {
                break;
            }
        }
        assert_eq!(chain.len(), 4, "the retention cap still holds");
        assert_eq!(chain.frontier(), Some((0, genesis)));
        assert_eq!(
            verify_finalized_ancestry_cached(&c, 0, &genesis, &head, &mut chain),
            Ok(())
        );
        assert_eq!(
            verify_finalized_ancestry_cached(&c, 0, &[0x99; 32], &head, &mut chain),
            Err(RejectReason::NotFinalizedAncestor)
        );
    }

    #[test]
    fn a_walk_starts_at_or_above_its_target_never_below() {
        // Eviction plus a preserved frontier makes the retained window
        // non-contiguous: the frontier can sit below the target while the only
        // *usable* starting point sits above it. A walk started below its
        // target takes no steps at all, so the target comes back unproved even
        // though the endpoint is perfectly honest.
        let mut c = MockChain::new(31337, CONTRACT).with_blocks(12);
        c.set_finalized(12);
        let head = crate::finality::fetch_finalized(&c).expect("finalized");
        let mut chain = VerifiedChain::new();
        chain
            .record(1, c.block_hash(1).expect("block"))
            .expect("low link");
        chain
            .record(9, c.block_hash(9).expect("block"))
            .expect("high link");
        assert_eq!(chain.frontier().map(|(h, _)| h), Some(1));
        assert_eq!(chain.lowest_at_or_above(5).map(|(h, _)| h), Some(9));

        assert_eq!(
            verify_finalized_ancestry_cached(
                &c,
                5,
                &c.block_hash(5).expect("block"),
                &head,
                &mut chain
            ),
            Ok(()),
            "the walk must start at 9 — the lowest proved link at or above 5"
        );
    }

    #[test]
    fn with_capacity_clamps_before_it_allocates() {
        // `with_capacity` is public, so an unclamped cap is an I14 allocation
        // lever: one retained link per followed block, with no ceiling.
        let mut chain = VerifiedChain::with_capacity(usize::MAX);
        for h in 0..(MAX_VERIFIED_CHAIN as u64 + 64) {
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&h.to_be_bytes());
            chain.record(h, hash).expect("record");
        }
        assert_eq!(chain.len(), MAX_VERIFIED_CHAIN);
        assert_eq!(VerifiedChain::with_capacity(0).len(), 0);
        let mut one = VerifiedChain::with_capacity(0);
        one.record(1, [1u8; 32]).expect("record");
        one.record(2, [2u8; 32]).expect("record");
        assert_eq!(one.len(), 1, "a zero request is clamped up to one, not off");
    }
}
