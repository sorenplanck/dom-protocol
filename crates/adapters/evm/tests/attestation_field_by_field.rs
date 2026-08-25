//! One test per individual check in `attest.rs`, each written to fail if that
//! single check is deleted.
//!
//! # Why this file exists
//!
//! `tests/attestation.rs` claims that each of its tests pins a specific
//! rejection reason "so a future change that widens acceptance cannot pass by
//! silently swapping one failure for another". An adversarial audit measured
//! that claim by deleting each check in `attest.rs` one at a time: **17 of 20
//! deletions were not caught by the whole suite.** Among the survivors were the
//! receipt log's `topics` comparison — which carries `lockId`, `binding` and the
//! indexed party, i.e. everything the decoder goes on to interpret — the
//! receipt log's `address` and `removed`, and the entire step-0 finality gate.
//!
//! The reason they survived is that the mock's `Faults` are coarse:
//! `receipt_block_mismatch` moves the block *number* and the block *hash*
//! together, so whichever check runs first hides the other; a fault that
//! corrupts a whole log hides which field mattered. A test suite built only out
//! of coarse faults measures "something rejected this", not "this check
//! rejected this".
//!
//! So every test here corrupts exactly **one field of one answer**, through the
//! `Rewrite` interposer, and asserts the exact reason. Deleting the
//! corresponding check makes the test fail — which is the only sense in which a
//! check can be said to be tested.
//!
//! Two properties are observable only as work *not* done, and use a call
//! counter: the finality gate must run before any round trip, and the ancestry
//! walk must stop at the first link the endpoint cannot produce.

mod common;

use adapter_evm::abi::{event_topic0, SIG_CLAIMED};
use adapter_evm::attest::{
    attest_settlement_log, prove_hash_link, verify_finalized_ancestry, MAX_ANCESTRY_WALK,
};
use adapter_evm::finality::{fetch_finalized, FinalizedHead};
use adapter_evm::mock::{Faults, MockChain};
use adapter_evm::rpc::{EthClient, RpcLog};
use adapter_evm::RejectReason;
use common::{
    alien_address, alien_word, block_by_hash_field, receipt_field, receipt_log_field, scenario,
    transaction_field, Counted, Scenario,
};
use counterparty_api::ChainCursor;
use serde_json::json;

const CONTRACT: [u8; 20] = [0xC0; 20];

fn settled() -> Scenario {
    let s = scenario(151);
    s.mine_open();
    s.mine_claim();
    s.mine(2);
    s.finalize_tip();
    s
}

fn claim_log(s: &Scenario) -> RpcLog {
    EthClient::new(&s.chain)
        .logs(0, s.height(), &s.cfg.contract, &[event_topic0(SIG_CLAIMED)])
        .expect("eth_getLogs answered")
        .into_iter()
        .next()
        .expect("one Claimed log")
}

fn head(s: &Scenario) -> FinalizedHead {
    fetch_finalized(&s.chain).expect("the mock serves the finalized tag")
}

/// Sanity: the interposer itself changes nothing when it rewrites nothing.
#[test]
fn the_unmodified_baseline_attests() {
    let s = settled();
    let log = claim_log(&s);
    let rpc = receipt_field(s.chain.clone(), "unrelated", Some(json!("x")));
    assert!(attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)).is_ok());
}

// ---------------------------------------------------------------------------
// step 0 — the finality gate, and the fact that it is *first*
// ---------------------------------------------------------------------------

/// The gate must reject before a single round trip is spent. Asserting only
/// "it was rejected" cannot distinguish the gate from the ancestry check, which
/// reports the same reason several RPC calls later — which is exactly why
/// deleting the gate went unnoticed.
#[test]
fn a_log_above_the_finalized_head_costs_no_round_trips() {
    let s = settled();
    let log = claim_log(&s);
    let below = FinalizedHead {
        height: log.block_number - 1,
        hash: s
            .chain
            .with(|c| c.block_hash(log.block_number - 1).expect("block")),
    };
    let rpc = Counted::new(s.chain.clone());
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &below),
        Err(RejectReason::AboveFinalizedHead)
    );
    assert_eq!(
        rpc.count(),
        0,
        "nothing may be asked about a block that is not final yet"
    );
}

/// The boundary is `>`, not `>=`: a log exactly at the finalized height is
/// final, and a log exactly one above it is not.
#[test]
fn the_finality_boundary_is_exact() {
    let s = settled();
    let log = claim_log(&s);

    let exactly = FinalizedHead {
        height: log.block_number,
        hash: log.block_hash,
    };
    assert!(
        attest_settlement_log(&s.chain, &s.cfg.contract, &log, &exactly).is_ok(),
        "a log in the finalized block itself is final"
    );

    let one_short = FinalizedHead {
        height: log.block_number - 1,
        hash: s
            .chain
            .with(|c| c.block_hash(log.block_number - 1).expect("block")),
    };
    let rpc = Counted::new(s.chain.clone());
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &one_short),
        Err(RejectReason::AboveFinalizedHead),
        "one block above the head is one block too many"
    );
    assert_eq!(rpc.count(), 0);
}

// ---------------------------------------------------------------------------
// the receipt's own fields, one at a time
// ---------------------------------------------------------------------------

#[test]
fn a_receipt_for_a_different_transaction_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let rpc = receipt_field(s.chain.clone(), "transactionHash", Some(alien_word(0xA1)));
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::ReceiptInconsistent)
    );
}

#[test]
fn a_receipt_naming_a_different_block_number_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    // Only the number moves; the hash still matches, so this isolates the
    // number comparison from the hash comparison.
    let rpc = receipt_field(s.chain.clone(), "blockNumber", Some(json!("0x7b")));
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::ReceiptInconsistent)
    );
}

#[test]
fn a_receipt_naming_a_different_block_hash_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    // Only the hash moves; the number still matches.
    let rpc = receipt_field(s.chain.clone(), "blockHash", Some(alien_word(0xB2)));
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::ReceiptInconsistent)
    );
}

// ---------------------------------------------------------------------------
// the log *inside* the receipt, one field at a time
// ---------------------------------------------------------------------------

#[test]
fn a_receipt_log_emitted_by_another_address_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let rpc = receipt_log_field(s.chain.clone(), "address", Some(alien_address(0xDE)));
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::LogAbsentFromReceipt),
        "the receipt's copy must be the same log, not merely a log"
    );
}

/// The one the audit called out by name: `topics` carries `lockId`, `binding`
/// and the indexed party. If the receipt's copy may disagree here, the receipt
/// corroborates nothing that the decoder actually uses.
#[test]
fn a_receipt_log_with_different_topics_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let rpc = receipt_log_field(
        s.chain.clone(),
        "topics",
        Some(json!([
            alien_word(0x01),
            alien_word(0x02),
            alien_word(0x03),
            alien_word(0x04),
        ])),
    );
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::LogAbsentFromReceipt)
    );
}

/// The same check, aimed at the two topics that decide *which lock* the event
/// is about: swapping only `lockId` (topic 1) must be refused.
#[test]
fn a_receipt_log_whose_lock_id_topic_differs_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let mut topics: Vec<serde_json::Value> = log
        .topics
        .iter()
        .map(|t| json!(format!("0x{}", hex::encode(t))))
        .collect();
    topics[1] = alien_word(0x5A);
    let rpc = receipt_log_field(s.chain.clone(), "topics", Some(json!(topics)));
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::LogAbsentFromReceipt),
        "a receipt that names a different lock is not this log's receipt"
    );
}

#[test]
fn a_receipt_log_attributed_to_another_transaction_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let rpc = receipt_log_field(s.chain.clone(), "transactionHash", Some(alien_word(0xC3)));
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::LogAbsentFromReceipt)
    );
}

#[test]
fn a_receipt_log_placed_in_another_block_hash_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let rpc = receipt_log_field(s.chain.clone(), "blockHash", Some(alien_word(0xD4)));
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::LogAbsentFromReceipt)
    );
}

#[test]
fn a_receipt_log_placed_at_another_block_number_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let rpc = receipt_log_field(s.chain.clone(), "blockNumber", Some(json!("0x7b")));
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::LogAbsentFromReceipt)
    );
}

#[test]
fn a_receipt_log_the_endpoint_marks_removed_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let rpc = receipt_log_field(s.chain.clone(), "removed", Some(json!(true)));
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::LogAbsentFromReceipt),
        "an orphaned entry in the receipt is not corroboration"
    );
}

// ---------------------------------------------------------------------------
// the transaction, one field at a time
// ---------------------------------------------------------------------------

#[test]
fn a_transaction_with_a_different_hash_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let rpc = transaction_field(s.chain.clone(), "hash", Some(alien_word(0xE5)));
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::TransactionInconsistent)
    );
}

#[test]
fn a_transaction_in_a_different_block_hash_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let rpc = transaction_field(s.chain.clone(), "blockHash", Some(alien_word(0xF6)));
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::TransactionInconsistent)
    );
}

#[test]
fn a_transaction_at_a_different_block_number_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let rpc = transaction_field(s.chain.clone(), "blockNumber", Some(json!("0x7b")));
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::TransactionInconsistent)
    );
}

// ---------------------------------------------------------------------------
// a stranger's logs must not cost this observer anything
// ---------------------------------------------------------------------------

/// A `ConditionLockV2` deployment is shared: anyone may open a lock on it, and
/// every such `LockOpened` lands in this observer's `eth_getLogs` page. Deciding
/// that a log belongs to somebody else is pure — a binding derivation and a map
/// lookup — so it must happen *before* the attestation spends round trips.
///
/// Otherwise a stranger fills blocks with `LockOpened` logs and each one costs
/// this observer a receipt, a transaction, a block and an ancestry walk, none
/// of which the event budget ever restrains, because none of them produce an
/// event.
#[test]
fn a_third_partys_logs_cost_no_round_trips() {
    /// Observes a scenario through a call counter and reports
    /// `(events, rpc calls)`.
    fn observe_counting(s: &Scenario) -> (usize, usize) {
        let rpc = Counted::new(s.chain.clone());
        let counter = rpc.counter();
        let adapter = adapter_evm::EvmAdapter::new(s.cfg, rpc).expect("valid configuration");
        let (events, _) = adapter
            .observe_blocking(&ChainCursor::default(), 64)
            .expect("observe");
        (
            events.len(),
            counter.load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    // Baseline: our two logs, then twenty empty blocks.
    let clean = scenario(211);
    clean.mine_open();
    clean.mine_claim();
    clean.mine(20);
    clean.finalize_tip();
    let (clean_events, clean_calls) = observe_counting(&clean);

    // Identical, except the twenty blocks each carry a stranger's `LockOpened`
    // on the same deployment.
    let crowded = scenario(211);
    crowded.mine_open();
    crowded.mine_claim();
    for _ in 0..20 {
        crowded.mine_foreign_open();
    }
    crowded.finalize_tip();
    let (crowded_events, crowded_calls) = observe_counting(&crowded);

    assert_eq!(
        clean_events, crowded_events,
        "a stranger's locks must not change what is observed"
    );

    // Attesting one log costs at least four round trips: a receipt, a
    // transaction, a height-addressed block and one or more ancestry lookups.
    // Twenty attested strangers would therefore add eighty or more.
    //
    // Filtering them first leaves only the one header the scan fetches for any
    // block that contains logs at all — bookkeeping it does for its reorg
    // anchor, and which no attacker can inflate beyond one per block. So the
    // marginal cost of a stranger's lock is 1, not 4+, and this bound separates
    // the two by a factor of four.
    let marginal = crowded_calls.saturating_sub(clean_calls);
    assert!(
        marginal <= 20,
        "twenty foreign locks added {marginal} RPC calls \
         ({clean_calls} -> {crowded_calls}): at more than one apiece they are \
         being attested before they are filtered"
    );
}

/// A block whose events do not fit the caller's budget must be left **whole**
/// for the next call, and must cost nothing in the meantime.
///
/// Both halves matter. Truncating the block would advance the cursor past logs
/// that were never reported, losing them; attesting them and then discarding
/// them would pay for round trips the budget exists to prevent.
#[test]
fn a_block_that_does_not_fit_the_budget_is_neither_split_nor_paid_for() {
    let s = scenario(223);
    s.mine_open();
    // One block carrying three of *our* claims.
    let crowded_height = s.chain.with_mut(|c| {
        let h = c.push_block();
        for _ in 0..3 {
            c.push_claimed(
                s.lock_id,
                s.binding,
                adapter_evm::adapter::test_support::FIXTURE_BENEFICIARY,
                s.secret,
            )
            .expect("log appended");
        }
        h
    });
    s.finalize_tip();

    // Budget of two: the opening block fits, the three-claim block does not.
    let rpc = Counted::new(s.chain.clone());
    let counter = rpc.counter();
    let a = adapter_evm::EvmAdapter::new(s.cfg, rpc).expect("valid configuration");
    let (events, cursor) = a
        .observe_blocking(&ChainCursor::default(), 2)
        .expect("observe");
    let after_first = counter.load(std::sync::atomic::Ordering::Relaxed);

    assert_eq!(events.len(), 1, "only the opening block fitted");
    let decoded = adapter_evm::EvmCursor::decode(&cursor, s.cfg.chain_id, &s.cfg.contract, 0)
        .expect("cursor decodes");
    assert!(
        decoded.next_from_block <= crowded_height,
        "the cursor must not advance past a block whose events were not \
         delivered: it points at {} but the crowded block is {crowded_height}",
        decoded.next_from_block
    );

    // Nothing in the deferred block was attested: four round trips per claim
    // would have been spent for events that were never returned.
    assert!(
        after_first < 12,
        "the deferred block cost {after_first} calls in total; its three claims \
         are being attested before the budget is consulted"
    );

    // And with room, the same block is delivered whole — nothing was lost.
    let (rest, _) = a.observe_blocking(&cursor, 64).expect("observe");
    assert_eq!(rest.len(), 3, "the deferred block arrives entire");
}

/// The hard ceiling is not the caller's budget: `MAX_EVENTS_PER_OBSERVE` is the
/// neutral API's own cap, and a single block that cannot be delivered inside it
/// must fail closed rather than be truncated. Truncation here would silently
/// drop settlements.
#[test]
fn a_single_block_beyond_the_hard_ceiling_fails_closed() {
    let over = counterparty_api::MAX_EVENTS_PER_OBSERVE + 1;
    let s = scenario(227);
    // No `LockOpened`: the lock is registered directly, so the crowded block is
    // the first one carrying any of our events and `already` is zero there.
    s.chain.with_mut(|c| {
        c.push_block();
        for _ in 0..over {
            c.push_claimed(
                s.lock_id,
                s.binding,
                adapter_evm::adapter::test_support::FIXTURE_BENEFICIARY,
                s.secret,
            )
            .expect("log appended");
        }
    });
    s.finalize_tip();

    let a = s.adapter();
    a.track_lock(&s.terms).expect("register the lock");
    assert_eq!(
        a.observe_blocking(&ChainCursor::default(), usize::MAX),
        Err(counterparty_api::AdapterError::BoundsExceeded),
        "a block of {over} events cannot be delivered within the neutral cap, \
         and must not be quietly cut down to fit"
    );
}

// ---------------------------------------------------------------------------
// ancestry: the guards inside the walk
// ---------------------------------------------------------------------------

/// `verify_finalized_ancestry` has its own above-head gate, and it must report
/// *that*, not the "no ancestor" it would otherwise fall through to.
#[test]
fn ancestry_above_the_finalized_head_is_its_own_refusal() {
    let mut c = MockChain::new(31337, CONTRACT).with_blocks(6);
    c.set_finalized(4);
    let h = fetch_finalized(&c).expect("finalized");
    assert_eq!(
        verify_finalized_ancestry(&c, 5, &c.block_hash(5).expect("block"), &h),
        Err(RejectReason::AboveFinalizedHead),
        "above the head is not the same fact as off the chain"
    );
}

/// A header served for a hash must be the header of the block the walk is
/// standing on. An endpoint that answers with the right hash but the wrong
/// height is lying about the shape of the chain.
#[test]
fn a_walk_step_whose_height_disagrees_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let rpc = block_by_hash_field(s.chain.clone(), "number", Some(json!("0x270f")));
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::NotFinalizedAncestor)
    );
}

/// The walk must stop at the first parent the endpoint cannot produce. A walk
/// that shrugged and carried on would reach the same verdict here by accident,
/// so the property is asserted as bounded work, which is what it protects.
#[test]
fn a_walk_stops_at_the_first_link_the_endpoint_cannot_produce() {
    let mut c = MockChain::new(31337, CONTRACT).with_blocks(12);
    c.set_finalized(12);
    let h = fetch_finalized(&c).expect("finalized");
    let target = c.block_hash(2).expect("block");
    let orphaned = c.with_faults(Faults {
        orphan_parent_linkage: true,
        ..Faults::default()
    });
    let rpc = Counted::new(orphaned);
    assert_eq!(
        prove_hash_link(&rpc, 12, &h.hash, 2, &target),
        Err(RejectReason::NotFinalizedAncestor)
    );
    assert_eq!(
        rpc.count(),
        2,
        "one lookup to read the head's header, one to discover its parent does \
         not exist — and then the walk stops, rather than grinding down ten \
         more blocks on an endpoint that has already contradicted itself"
    );
}

// ---------------------------------------------------------------------------
// what the endpoint says about itself must be what was asked for
// ---------------------------------------------------------------------------

/// A hash-addressed lookup that answers with a *different* hash has destroyed
/// the only thing that made the lookup meaningful. Without this check the
/// ancestry walk would follow whatever chain the endpoint felt like serving.
#[test]
fn a_block_by_hash_answer_carrying_another_hash_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let rpc = block_by_hash_field(s.chain.clone(), "hash", Some(alien_word(0x3C)));
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::MalformedAnswer),
        "an endpoint answering about a block nobody asked for is malformed"
    );
}

/// The same for the height-addressed lookup: an answer at the wrong height
/// cannot establish what is canonical at the right one.
#[test]
fn a_block_by_number_answer_carrying_another_height_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let target = log.block_number;
    let rpc = common::Rewrite::new(s.chain.clone(), move |method, params, mut v| {
        // Only the numeric lookup of the log's own block; leave the
        // `finalized` tag alone so the head is still honest.
        let asked_for_the_block = params
            .get(0)
            .and_then(|p| p.as_str())
            .is_some_and(|t| t == format!("0x{target:x}"));
        if method == "eth_getBlockByNumber" && asked_for_the_block {
            if let Some(o) = v.as_object_mut() {
                o.insert("number".into(), json!("0x270f"));
            }
        }
        v
    });
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::MalformedAnswer)
    );
}

// ---------------------------------------------------------------------------
// prove_hash_link: the anchored walk evidence verification relies on
// ---------------------------------------------------------------------------

#[test]
fn an_anchored_walk_of_zero_length_still_compares_the_hash() {
    let mut c = MockChain::new(31337, CONTRACT).with_blocks(6);
    c.set_finalized(6);
    let at_four = c.block_hash(4).expect("block");
    assert_eq!(prove_hash_link(&c, 4, &at_four, 4, &at_four), Ok(()));
    assert_eq!(
        prove_hash_link(&c, 4, &at_four, 4, &[0x9E; 32]),
        Err(RejectReason::NotFinalizedAncestor),
        "same height is not the same block"
    );
}

#[test]
fn an_anchored_walk_refuses_a_gap_wider_than_the_budget() {
    let tip = MAX_ANCESTRY_WALK * 2;
    let mut c = MockChain::new(31337, CONTRACT).with_blocks(tip);
    c.set_finalized(tip);
    let anchor = c.block_hash(tip).expect("tip");
    let target = c.block_hash(0).expect("genesis");
    assert_eq!(
        prove_hash_link(&c, tip, &anchor, 0, &target),
        Err(RejectReason::AncestryProofTooDeep),
        "the anchored walk is bounded too; it refuses rather than grinding"
    );
    // And just inside the budget it succeeds, so the refusal is the bound and
    // not a blanket failure.
    let near = c.block_hash(tip - MAX_ANCESTRY_WALK).expect("block");
    assert_eq!(
        prove_hash_link(&c, tip, &anchor, tip - MAX_ANCESTRY_WALK, &near),
        Ok(())
    );
}

/// The height check on the *anchored* walk, which has its own copy of it.
///
/// `walk_and_record`'s twin is covered by
/// `a_walk_step_whose_height_disagrees_is_rejected`; this one was not, and an
/// endpoint that serves a header under the right hash while reporting a
/// different `number` is lying about the shape of the chain. Without the check
/// the walk counts steps it never took: it would decrement its cursor once per
/// answer regardless of where the answer actually sits, and land wherever the
/// endpoint steered it.
#[test]
fn an_anchored_walk_step_whose_height_disagrees_is_rejected() {
    let mut c = MockChain::new(31337, CONTRACT).with_blocks(6);
    c.set_finalized(6);
    let anchor = c.block_hash(6).expect("tip");
    let target = c.block_hash(2).expect("block");
    let shared = common::SharedChain::new(c);
    // Control: the honest endpoint links the two.
    assert_eq!(prove_hash_link(&shared, 6, &anchor, 2, &target), Ok(()));
    let rpc = block_by_hash_field(shared, "number", Some(json!("0x270f")));
    assert_eq!(
        prove_hash_link(&rpc, 6, &anchor, 2, &target),
        Err(RejectReason::NotFinalizedAncestor)
    );
}
