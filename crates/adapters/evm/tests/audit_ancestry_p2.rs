//! ADVERSARIAL AUDIT PROOF, round 2 — kept as a regression suite.
//!
//! **When it was written this file FAILED, and that was the point** — it is the
//! same kind of artefact as `audit_ancestry_p1.rs`: each test asserts the
//! property the module's own documentation promises, so a red test *was* the
//! finding. Six of the eight failed. Every assertion below is unchanged; what
//! changed is the code, so all eight now run in the default gate with no
//! `#[ignore]`. Where a comment describes the defect in the present tense it is
//! describing what the assertion is *for*, not what the crate still does — the
//! fixes are documented in `crate::attest`, `crate::evidence` and
//! `crate::adapter`.
//!
//! Round 1 found: `verify_onchain` concluded ancestry from block *height* alone
//! once the gap exceeded the walk budget (then 16). The claimed fix — "real hash
//! linkage at any gap; `verify_onchain` no longer takes a weak path" — moved the
//! budget to [`MAX_ANCESTRY_WALK`] = 256 and added an "anchored" proof
//! (`prove_hash_link`) whose two ends both come from the evidence record.
//!
//! What survives:
//!
//! 1. `verify_onchain` still *swallows* `AncestryProofTooDeep` from the
//!    head-side attestation (`evidence.rs:436-440`). Past 256 blocks the only
//!    thing tying the observation to the current head is `eth_getBlockByNumber`
//!    — the canonical-index question `attest.rs:28-34` says proves nothing. The
//!    attacker's cost is still waiting; the price went from 16 blocks to 256.
//! 2. The anchored walk is vacuous at anchor gap 0, and when it does run it only
//!    re-proves that the *orphaned fork* is internally linked.
//! 3. `VerifiedChain` is keyed by height with no chain identity, so a warm
//!    observer needs no waiting at all.
//!
//! Every test drives the deterministic in-crate mock; nothing here touches a
//! network.
//!
//! Run: `cargo test -p adapter-evm --all-features --locked --test audit_ancestry_p2`

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use adapter_evm::attest::{
    prove_hash_link, verify_finalized_ancestry, verify_finalized_ancestry_cached, MAX_ANCESTRY_WALK,
};
use adapter_evm::evidence::EvidenceKind;
use adapter_evm::finality::fetch_finalized;
use adapter_evm::mock::MockChain;
use adapter_evm::rpc::JsonRpc;
use adapter_evm::{EvmAdapter, RejectReason, VerifiedChain};
use common::{scenario, Scenario};
use counterparty_api::AdapterError;
use serde_json::Value;

// ---------------------------------------------------------------------------
// an endpoint whose *height index* is stale, and nothing else
// ---------------------------------------------------------------------------

/// Two chains behind one JSON-RPC endpoint.
///
/// * `canon` is the chain the endpoint's `finalized` tag names.
/// * `fork` is an orphaned chain that carries the settlement.
///
/// The endpoint is honest about every hash-addressed lookup: a real archive
/// node happily serves an orphaned block by hash, so `eth_getBlockByHash`
/// answering for `fork` is *normal behaviour*, not a lie. The endpoint tells
/// exactly one lie, and it tells it only through the **canonical height
/// index**: at `stale` heights `eth_getBlockByNumber` still answers from
/// `fork`. That models a lagging proxy, a node whose index was not rewritten
/// after a deep reorg, or a hostile provider — all of which `attest.rs:28-34`
/// declares must not be believed:
///
/// > Height alone therefore proves nothing, and neither does asking the
/// > endpoint's canonical index — that is the endpoint answering a question
/// > about itself.
struct StaleIndex {
    fork: MockChain,
    /// `(canonical chain, heights whose number-index is stale)`, swappable so a
    /// test can let an observer warm its cache before the provider changes its
    /// mind.
    state: Mutex<(MockChain, Vec<u64>)>,
    by_hash_calls: AtomicUsize,
}

impl StaleIndex {
    fn new(fork: MockChain, canon: MockChain, stale: Vec<u64>) -> Self {
        Self {
            fork,
            state: Mutex::new((canon, stale)),
            by_hash_calls: AtomicUsize::new(0),
        }
    }

    /// An endpoint that is telling the whole truth: one chain, no stale index.
    fn honest(fork: MockChain) -> Self {
        let canon = fork.clone();
        Self::new(fork, canon, Vec::new())
    }

    /// The provider changes what it calls canonical.
    fn switch(&self, canon: MockChain, stale: Vec<u64>) {
        *self.state.lock().expect("endpoint lock") = (canon, stale);
    }
}

/// `EvmAdapter` takes its transport by value; this shares one.
#[derive(Clone)]
struct Shared(Arc<StaleIndex>);

impl JsonRpc for Shared {
    fn call(&self, method: &str, params: Value) -> Result<Value, AdapterError> {
        self.0.call(method, params)
    }
}

fn tag_of(params: &Value) -> Option<String> {
    params.get(0)?.as_str().map(|s| s.to_string())
}

fn height_of(tag: &str) -> Option<u64> {
    u64::from_str_radix(tag.strip_prefix("0x")?, 16).ok()
}

impl JsonRpc for StaleIndex {
    fn call(&self, method: &str, params: Value) -> Result<Value, AdapterError> {
        let guard = self.state.lock().map_err(|_| AdapterError::InvalidState)?;
        let (canon, stale) = &*guard;
        match method {
            "eth_getBlockByNumber" => {
                let tag = tag_of(&params).ok_or(AdapterError::AdapterUnavailable)?;
                match height_of(&tag) {
                    // A height-addressed lookup at a stale height: the index
                    // still points at the orphaned chain.
                    Some(h) if stale.contains(&h) => self.fork.call(method, params),
                    Some(_) => canon.call(method, params),
                    // "finalized" / "latest": the endpoint is fully up to date.
                    None => canon.call(method, params),
                }
            }
            "eth_getBlockByHash" => {
                self.by_hash_calls.fetch_add(1, Ordering::Relaxed);
                // Archive semantics: whoever has the block, answers.
                let from_fork = self.fork.call(method, params.clone())?;
                if from_fork.is_null() {
                    canon.call(method, params)
                } else {
                    Ok(from_fork)
                }
            }
            // Receipts, transactions, logs, chain id and code: the settlement
            // really did happen on `fork`, so `fork` answers.
            _ => self.fork.call(method, params),
        }
    }
}

/// A settled scenario: lock opened, claimed, and `extra` further blocks, all
/// finalized. Returns the scenario and the collected evidence.
fn settled_with_gap(seed: u8, extra: u64) -> (Scenario, adapter_evm::EvmEvidence) {
    let s = scenario(seed);
    s.mine_open();
    s.mine_claim();
    s.mine(extra);
    s.finalize_tip();
    let a = s.adapter();
    a.track_lock(&s.terms).expect("register the lock");
    let e = a
        .collect_evidence(&s.lock_id, EvidenceKind::Claimed)
        .expect("evidence collected on the honest chain");
    (s, e)
}

/// Builds the orphaning chain: same genesis, diverging from height 1, `tip`
/// blocks tall, finalized at its tip. It carries no settlement at all.
fn orphaning_chain(fork: &MockChain, tip: u64) -> MockChain {
    let mut canon = fork.clone();
    canon.reorg(canon.height()); // fork at genesis; every later hash differs
    while canon.height() < tip {
        canon.push_block();
    }
    canon.set_finalized(canon.height());
    canon
}

// ---------------------------------------------------------------------------
// FINDING 1 — the round-1 defect's shape survives: waiting still buys
// acceptance, the threshold merely moved from 16 to MAX_ANCESTRY_WALK.
// ---------------------------------------------------------------------------

/// One endpoint, one lie, two ages.
///
/// The settlement block is on an orphaned fork. The endpoint's canonical height
/// index still vouches for it (the "endpoint answering a question about itself"
/// the module forbids); everything else it says is internally consistent, and
/// every hash-addressed answer it gives is truthful.
///
/// * While the current finalized head is within [`MAX_ANCESTRY_WALK`] of the
///   observation, the head-side walk runs to completion, lands on a different
///   hash, and the evidence is refused. Correct.
/// * Once the head is further away than the budget, the head-side walk gives up
///   with `AncestryProofTooDeep`, `verify_onchain` **swallows that**
///   (`evidence.rs:436-440`), and the anchored walk only re-proves linkage
///   *inside the orphaned fork*. The evidence is accepted.
///
/// The attacker's cost is still exactly what round 1 said it was: waiting.
fn stale_index_verdicts(
    gap_in_evidence: u64,
    seed: u8,
) -> (
    u64,
    Result<counterparty_api::VerifiedOutcome, AdapterError>,
    u64,
    Result<counterparty_api::VerifiedOutcome, AdapterError>,
    RejectReason,
) {
    let (s, e) = settled_with_gap(seed, gap_in_evidence);
    assert_eq!(
        e.finalized_height - e.block_number,
        gap_in_evidence,
        "fixture: the evidence's own anchored gap"
    );
    let fork = s.chain.with(|c| c.clone());
    let stale = vec![e.block_number, e.finalized_height];
    let bytes = e.encode();

    // The log exactly as `eth_getLogs` serves it, for the mechanism assertion.
    let log = adapter_evm::rpc::EthClient::new(&fork)
        .logs(
            0,
            fork.height(),
            &s.cfg.contract,
            &[adapter_evm::abi::event_topic0(
                adapter_evm::abi::SIG_CLAIMED,
            )],
        )
        .expect("logs")
        .into_iter()
        .next()
        .expect("one Claimed log");

    // -- fresh: head within the budget of the observation -------------------
    let near_tip = e.block_number + MAX_ANCESTRY_WALK - 1;
    let near = StaleIndex::new(
        fork.clone(),
        orphaning_chain(&fork, near_tip),
        stale.clone(),
    );
    let near_verdict = EvmAdapter::new(s.cfg, near)
        .expect("valid configuration")
        .verify_evidence_blocking(&bytes);

    // -- aged: head one block past the budget -------------------------------
    let far_tip = e.block_number + MAX_ANCESTRY_WALK + 1;
    let far_canon = orphaning_chain(&fork, far_tip);
    let far_head = fetch_finalized(&far_canon).expect("finalized");
    let far = StaleIndex::new(fork.clone(), far_canon, stale.clone());
    // The mechanism: the head-side attestation gives up rather than refusing.
    let mechanism =
        adapter_evm::attest::attest_settlement_log(&far, &s.cfg.contract, &log, &far_head)
            .expect_err("the head-side walk cannot reach the observation");
    let far_verdict = EvmAdapter::new(s.cfg, far)
        .expect("valid configuration")
        .verify_evidence_blocking(&bytes);

    (
        near_tip - e.block_number,
        near_verdict,
        far_tip - e.block_number,
        far_verdict,
        mechanism,
    )
}

fn assert_stale_index_is_refused_at_both_ages(gap_in_evidence: u64, seed: u8) {
    let (near_gap, near, far_gap, far, mechanism) = stale_index_verdicts(gap_in_evidence, seed);
    assert_eq!(
        near,
        Err(AdapterError::ReorgDetected),
        "control (anchored gap {gap_in_evidence}): at a head gap of {near_gap} \
         the head-side walk sees the orphaning and refuses",
    );
    assert_eq!(
        mechanism,
        RejectReason::AncestryProofTooDeep,
        "mechanism: at a head gap of {far_gap} the head-side attestation gives \
         up instead of refusing, and evidence.rs:436-440 forgives exactly that",
    );
    assert_eq!(
        far,
        Err(AdapterError::ReorgDetected),
        "P1 (anchored gap {gap_in_evidence}): the SAME endpoint telling the SAME \
         lie is refused at a head gap of {near_gap} and accepted at a head gap \
         of {far_gap} (verdict {far:?}). Past MAX_ANCESTRY_WALK the only thing \
         still vouching for the observation's canonicity is \
         eth_getBlockByNumber — the canonical-index question attest.rs:28-34 \
         says proves nothing. The anchored walk re-proves linkage inside the \
         orphaned fork, which every orphaned fork also has.",
    );
}

/// Anchored gap 0 — the evidence's own checkpoint *is* its own block, so the
/// "proof that does not decay" is a hash equality and no round trip at all.
#[test]
fn p1_shape_survives_at_anchor_gap_zero() {
    assert_stale_index_is_refused_at_both_ages(0, 151);
}

/// Anchored gap 2 — the anchored walk really runs, and still proves only that
/// the orphaned fork is internally linked.
#[test]
fn p1_shape_survives_even_when_the_anchored_walk_runs() {
    assert_stale_index_is_refused_at_both_ages(2, 152);
}

/// The same finding, isolated from the evidence path: an aged observation's
/// canonicity is decided by *two* `eth_getBlockByNumber` answers and nothing
/// else, because the anchored proof at gap 0 makes no round trip at all.
#[test]
fn the_anchored_proof_is_vacuous_at_gap_zero_and_costs_no_round_trip() {
    let dead = MockChain::new(31337, [0xC0; 20]).breaking_transport();
    assert_eq!(
        prove_hash_link(&dead, 42, &[0xAA; 32], 42, &[0xAA; 32]),
        Ok(()),
        "gap 0 short-circuits before the transport is touched",
    );
    // And `collect_evidence` really does mint gap-0 evidence whenever the
    // settlement lands in the finalized block itself.
    let (_s, e) = settled_with_gap(19, 0);
    assert_eq!(e.finalized_height, e.block_number);
}

// ---------------------------------------------------------------------------
// FINDING 2 — the ancestry cache answers "yes, ancestor" about a finalized head
// it has never been linked to, with zero round trips.
// ---------------------------------------------------------------------------

/// `VerifiedChain` is keyed by height only and carries no identity of the chain
/// the links belong to. `verify_finalized_ancestry_cached` records the head it
/// is given (which only collides if that exact height is already held) and then
/// answers straight out of the cache.
///
/// So: prove some links against chain A's head, then present chain B's head —
/// taller, disjoint, sharing only genesis — and ask about one of A's blocks.
/// The answer is `Ok`, and not one JSON-RPC call is made.
#[test]
fn the_verified_chain_vouches_for_a_head_it_never_linked_to() {
    let a = MockChain::new(31337, [0xC0; 20])
        .with_blocks(10)
        .finalize(10);
    let head_a = fetch_finalized(&a).expect("finalized");
    let a3 = a.block_hash(3).expect("block 3");

    let mut cache = VerifiedChain::new();
    assert_eq!(
        verify_finalized_ancestry_cached(&a, 3, &a3, &head_a, &mut cache),
        Ok(()),
        "honestly proved against chain A"
    );

    // Chain B: same genesis, everything above it different, and taller.
    let mut b = a.clone();
    b.reorg(b.height());
    while b.height() < 500 {
        b.push_block();
    }
    b.set_finalized(b.height());
    let head_b = fetch_finalized(&b).expect("finalized");
    assert_ne!(b.block_hash(3), Some(a3), "fixture: B really is a fork");

    let counted = Counting::new(b);
    let verdict = verify_finalized_ancestry_cached(&counted, 3, &a3, &head_b, &mut cache);

    assert_eq!(
        verdict,
        Err(RejectReason::NotFinalizedAncestor),
        "the cache concluded `ancestor of {}` for a block that is not on that \
         chain at all, in {} round trips (verdict {verdict:?}). \
         VerifiedChain::record only detects a contradiction when the new head \
         lands on a height it already holds; a taller head never collides.",
        head_b.height,
        counted.calls(),
    );
}

/// ... and the same hole is reachable through the adapter, **without waiting**.
///
/// The 256-block wait that Finding 1 needs is only needed by a *cold* verifier.
/// An observer that has already walked a stretch of chain keeps those links in
/// `ObserverState::verified` for its whole lifetime, and
/// `attest_settlement_log_cached` short-circuits step 4 on a cache hit. So once
/// the provider switches which chain it calls canonical, the warm observer
/// attests a settlement on the abandoned chain at a head gap of ten blocks —
/// while a freshly-started observer, same endpoint, same instant, refuses it.
///
/// The event carries the revealed scalar, so this is an economic effect taken
/// on a block the observer cannot link to the head it just read.
#[test]
fn a_warm_observer_attests_what_a_cold_one_refuses_at_the_same_instant() {
    let s = scenario(88);
    let open_h = s.mine_open();
    let claim_h = s.mine_claim();
    s.mine(2);
    s.finalize_tip();
    let fork = s.chain.with(|c| c.clone());

    let endpoint = Arc::new(StaleIndex::honest(fork.clone()));
    let warm = EvmAdapter::new(s.cfg, Shared(endpoint.clone())).expect("valid configuration");
    warm.track_lock(&s.terms).expect("register the lock");
    // Warm the cache the way the crate documents, on the chain that was
    // canonical at the time. No event is surfaced by this.
    warm.extend_verified_ancestry(0).expect("batch");
    assert!(warm.verified_links().expect("links") > 0);

    // The provider now calls a different chain canonical; its height index is
    // stale only at the settlement's height.
    let canon = orphaning_chain(&fork, claim_h + 10);
    endpoint.switch(canon, vec![open_h, claim_h]);

    let cold = EvmAdapter::new(s.cfg, Shared(endpoint.clone())).expect("valid configuration");
    cold.track_lock(&s.terms).expect("register the lock");
    let cold_verdict = cold.observe_blocking(&counterparty_api::ChainCursor::default(), 64);
    assert!(
        cold_verdict.is_err(),
        "control: a cold observer walks the head down to the settlement, sees a \
         different hash, and refuses — got {cold_verdict:?}",
    );

    let warm_verdict = warm.observe_blocking(&counterparty_api::ChainCursor::default(), 64);
    assert!(
        warm_verdict.is_err(),
        "P1, no waiting required: the warm observer surfaced {} event(s) for a \
         settlement on the abandoned chain at a head gap of 10 blocks, because \
         VerifiedChain answered step 4 out of a proof made against a head that \
         no longer exists. Cold verdict on the same endpoint at the same \
         instant: {cold_verdict:?}",
        warm_verdict.map(|(e, _)| e.len()).unwrap_or(0),
    );
}

/// Counts JSON-RPC calls so "the answer came from the cache" is provable.
struct Counting<R: JsonRpc> {
    inner: R,
    calls: AtomicUsize,
}

impl<R: JsonRpc> Counting<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl<R: JsonRpc> JsonRpc for Counting<R> {
    fn call(&self, method: &str, params: Value) -> Result<Value, AdapterError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.call(method, params)
    }
}

// ---------------------------------------------------------------------------
// FINDING 3 — evidence that can be collected but never verified.
// ---------------------------------------------------------------------------

/// `collect_evidence` has an escape hatch for a wide gap
/// (`extend_verified_ancestry`, which feeds the observer's `VerifiedChain`).
/// `verify_onchain`'s anchored walk has none: `prove_hash_link` is stateless and
/// refuses outright once `finalized_height - block_number > MAX_ANCESTRY_WALK`.
///
/// A cold observer replaying deep history therefore mints evidence that **no
/// process, including itself, can ever verify**.
#[test]
fn evidence_can_be_minted_with_an_anchor_gap_no_verifier_can_walk() {
    let s = scenario(23);
    s.mine_open();
    let claim_h = s.mine_claim();
    s.mine(MAX_ANCESTRY_WALK + 8);
    s.finalize_tip();

    let a = s.adapter();
    a.track_lock(&s.terms).expect("register the lock");

    // Close the gap the way the crate documents: bounded batches.
    let mut rounds = 0;
    loop {
        let lowest = a.extend_verified_ancestry(claim_h).expect("batch");
        rounds += 1;
        assert!(rounds < 16, "batching must converge");
        if lowest <= claim_h {
            break;
        }
    }

    let e = a
        .collect_evidence(&s.lock_id, EvidenceKind::Claimed)
        .expect("collection succeeds through the documented escape hatch");
    assert!(
        e.finalized_height - e.block_number > MAX_ANCESTRY_WALK,
        "fixture: the anchored gap is wider than one walk"
    );
    let bytes = e.encode();

    assert_eq!(
        a.verify_evidence_blocking(&bytes),
        Ok(counterparty_api::VerifiedOutcome::Claimed {
            revealed: counterparty_api::RevealedSecretBytes(s.secret),
            height: e.block_number,
        }),
        "evidence the crate's own collection path produced is permanently \
         unverifiable: prove_hash_link refuses the anchored gap and there is no \
         batched form of it",
    );
}

// ---------------------------------------------------------------------------
// FINDING 4 — the verification path never asks the endpoint which chain it is.
// ---------------------------------------------------------------------------

/// `observe` (adapter.rs:557) and `collect_evidence` (adapter.rs:897) both run
/// [`EvmAdapter::preflight`], which is the crate's only comparison against
/// something that did not come out of the chain-state answers themselves: the
/// configured `chain_id` and the configured deployed-bytecode hash.
///
/// `verify_evidence_blocking` does not. `verify_static` only compares the
/// evidence blob's own `chain_id` / `code_hash` fields against the config — a
/// self-consistency check on the blob, not on the endpoint. So the whole
/// on-chain half of verification can run against an endpoint that openly says
/// it is a different chain running different bytecode, and still return
/// `Claimed`.
#[test]
fn verification_never_asks_the_endpoint_which_chain_it_is() {
    let (s, e) = settled_with_gap(64, 2);
    let bytes = e.encode();
    let a = s.adapter();
    assert!(a.verify_evidence_blocking(&bytes).is_ok(), "control");

    // The endpoint now says, out loud, that it is a different chain running
    // different bytecode. Its blocks, receipts and logs are unchanged.
    s.chain.set_faults(adapter_evm::mock::Faults {
        wrong_chain_id: true,
        wrong_code: true,
        ..adapter_evm::mock::Faults::default()
    });
    assert_eq!(
        a.preflight(),
        Err(AdapterError::EvidenceInvalid),
        "preflight does catch it — it is simply never run on this path"
    );
    let verdict = a.verify_evidence_blocking(&bytes);
    assert_eq!(
        verdict,
        Err(AdapterError::EvidenceInvalid),
        "verify_evidence_blocking (adapter.rs:965-971) skips preflight, so \
         every block, receipt and log it believed came from an endpoint it \
         never asked to identify itself (verdict {verdict:?})",
    );
}

// ---------------------------------------------------------------------------
// boundary table — gap 0, 1, budget, budget+1, above the head
// ---------------------------------------------------------------------------

#[test]
fn ancestry_boundaries_are_exact_and_fail_closed() {
    let tip = MAX_ANCESTRY_WALK + 4;
    let mut c = MockChain::new(31337, [0xC0; 20]).with_blocks(tip);
    c.set_finalized(tip);
    let head = fetch_finalized(&c).expect("finalized");
    let at = |h: u64| c.block_hash(h).expect("block");

    // gap 0: the head itself.
    assert_eq!(verify_finalized_ancestry(&c, tip, &at(tip), &head), Ok(()));
    assert_eq!(
        verify_finalized_ancestry(&c, tip, &[0x11; 32], &head),
        Err(RejectReason::NotFinalizedAncestor)
    );
    // gap 1.
    assert_eq!(
        verify_finalized_ancestry(&c, tip - 1, &at(tip - 1), &head),
        Ok(())
    );
    // exactly the budget.
    assert_eq!(
        verify_finalized_ancestry(
            &c,
            tip - MAX_ANCESTRY_WALK,
            &at(tip - MAX_ANCESTRY_WALK),
            &head
        ),
        Ok(()),
        "a gap of exactly MAX_ANCESTRY_WALK is walkable"
    );
    // one past the budget: a refusal, never a weaker answer.
    assert_eq!(
        verify_finalized_ancestry(
            &c,
            tip - MAX_ANCESTRY_WALK - 1,
            &at(tip - MAX_ANCESTRY_WALK - 1),
            &head
        ),
        Err(RejectReason::AncestryProofTooDeep)
    );
    // above the head.
    assert_eq!(
        verify_finalized_ancestry(&c, tip + 1, &at(tip), &head),
        Err(RejectReason::AboveFinalizedHead)
    );
    // prove_hash_link agrees on every boundary.
    assert_eq!(prove_hash_link(&c, tip, &at(tip), tip, &at(tip)), Ok(()));
    assert_eq!(
        prove_hash_link(
            &c,
            tip,
            &at(tip),
            tip - MAX_ANCESTRY_WALK,
            &at(tip - MAX_ANCESTRY_WALK)
        ),
        Ok(())
    );
    assert_eq!(
        prove_hash_link(
            &c,
            tip,
            &at(tip),
            tip - MAX_ANCESTRY_WALK - 1,
            &at(tip - MAX_ANCESTRY_WALK - 1)
        ),
        Err(RejectReason::AncestryProofTooDeep)
    );
    assert_eq!(
        prove_hash_link(&c, tip - 1, &at(tip - 1), tip, &at(tip)),
        Err(RejectReason::AboveFinalizedHead)
    );
}
