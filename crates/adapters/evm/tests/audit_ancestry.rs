//! AUDIT (adversarial), now a regression pin: what the ancestry check accepts
//! beyond the walk budget.
//!
//! # History — read this before changing an assertion here
//!
//! These tests were written to *demonstrate a weakness*. The header they
//! carried said:
//!
//! > They assert the current (weak) behaviour so that the finding is
//! > reproducible; if the fallback is ever hardened these tests will fail,
//! > which is the point.
//!
//! The fallback was hardened, so they failed, so they have been inverted —
//! exactly as their author intended. **Every test name is unchanged**, and each
//! one now asserts the property whose absence it originally proved. Inverting a
//! tripwire once the trap it guards has been sprung is the whole purpose of a
//! tripwire; weakening one would be replacing an assertion with a looser one,
//! which has not been done anywhere in this file.
//!
//! The defect, for the record: past `MAX_ANCESTRY_WALK` the check asked two
//! questions — one comparing the endpoint's `finalized` answer against the
//! endpoint's own `finalized` answer, one already asked at step 3 of
//! `attest_settlement_log` — and neither established a parent link. An endpoint
//! exhibiting *no* linkage at all was refused at gap 3 and believed at gap 25.
//!
//! The fix: ancestry is a followed chain of parent hashes at every depth, or it
//! is a refusal (`AncestryProofTooDeep`). There is no third answer. See
//! `adapter_evm::attest`.

mod common;

use adapter_evm::abi::{event_topic0, SIG_CLAIMED};
use adapter_evm::attest::{attest_settlement_log, verify_finalized_ancestry, MAX_ANCESTRY_WALK};
use adapter_evm::finality::fetch_finalized;
use adapter_evm::mock::{Faults, MockChain};
use adapter_evm::rpc::{EthClient, RpcLog};
use adapter_evm::RejectReason;
use common::{scenario, Scenario};

const CONTRACT: [u8; 20] = [0xC0; 20];

fn orphaned() -> Faults {
    Faults {
        orphan_parent_linkage: true,
        ..Faults::default()
    }
}

/// The *same* endpoint misbehaviour — "no chain of parent hashes reaches down
/// to the observation" — must be refused inside the walk budget **and** outside
/// it. Waiting 17 blocks used to buy an attacker acceptance; it now buys
/// nothing.
#[test]
fn audit_orphan_linkage_is_refused_within_the_budget_and_accepted_beyond_it() {
    // Inside the budget: the hash-linked walk runs and refuses.
    let near = MockChain::new(31337, CONTRACT).with_blocks(4).finalize(4);
    let near_head = fetch_finalized(&near).expect("finalized");
    let near_target = near.block_hash(1).expect("block 1");
    let near_bad = near.with_faults(orphaned());
    assert_eq!(
        verify_finalized_ancestry(&near_bad, 1, &near_target, &near_head),
        Err(RejectReason::NotFinalizedAncestor),
        "gap 3 <= MAX_ANCESTRY_WALK: the walk catches it"
    );

    // Outside the budget: identical fault, identical question, and now the
    // identical answer. The walk still starts at the finalized head, so the
    // very first parent the endpoint cannot produce ends it.
    let far_h = MAX_ANCESTRY_WALK + 10;
    let far = MockChain::new(31337, CONTRACT)
        .with_blocks(far_h)
        .finalize(far_h);
    let far_head = fetch_finalized(&far).expect("finalized");
    let far_target = far.block_hash(1).expect("block 1");
    let far_bad = far.clone().with_faults(orphaned());
    assert_eq!(
        verify_finalized_ancestry(&far_bad, 1, &far_target, &far_head),
        Err(RejectReason::NotFinalizedAncestor),
        "FIXED: ancestry no longer degrades to 'canonical at that height'"
    );

    // And the honest chain at that depth is refused too — for the *other*
    // reason. A gap wider than one call may walk is a bounded-work refusal,
    // never a weaker check.
    assert_eq!(
        verify_finalized_ancestry(&far, 1, &far_target, &far_head),
        Err(RejectReason::AncestryProofTooDeep),
        "an unwalkable gap is refused with its own distinguishable reason"
    );
}

fn claim_log(s: &Scenario) -> RpcLog {
    EthClient::new(&s.chain)
        .logs(0, s.height(), &s.cfg.contract, &[event_topic0(SIG_CLAIMED)])
        .expect("eth_getLogs answered")
        .into_iter()
        .next()
        .expect("one Claimed log")
}

/// End to end: a settlement log whose block provably does not descend from the
/// finalized head must never be attested, however wide the gap.
#[test]
fn audit_attestation_accepts_a_non_descending_block_beyond_the_walk_budget() {
    // Same shape as tests/attestation.rs::settled(), but deeper.
    let s = scenario(151);
    s.mine_open();
    let claim_h = s.mine_claim();
    s.mine(MAX_ANCESTRY_WALK + 4);
    s.finalize_tip();
    let log = claim_log(&s);
    let h = fetch_finalized(&s.chain).expect("finalized");
    assert!(
        h.height.saturating_sub(log.block_number) > MAX_ANCESTRY_WALK,
        "the scenario must sit beyond the walk budget"
    );
    assert_eq!(log.block_number, claim_h);

    // The very fault tests/attestation.rs uses to prove
    // `NotFinalizedAncestor` — "no chain of parent hashes reaches anything".
    s.chain.set_faults(orphaned());
    assert_eq!(
        attest_settlement_log(&s.chain, &s.cfg.contract, &log, &h),
        Err(RejectReason::NotFinalizedAncestor),
        "FIXED: an endpoint that can show no parent linkage attests nothing, \
         at any depth"
    );
}

/// The shallow-gap control for the test above: the identical fault on the
/// identical scenario is caught when the gap is small. It is now caught at
/// every gap, but the control is kept — it is what makes the pair meaningful.
#[test]
fn audit_the_same_scenario_within_the_budget_is_caught() {
    let s = scenario(151);
    s.mine_open();
    s.mine_claim();
    s.mine(2);
    s.finalize_tip();
    let log = claim_log(&s);
    let h = fetch_finalized(&s.chain).expect("finalized");
    s.chain.set_faults(orphaned());
    assert_eq!(
        attest_settlement_log(&s.chain, &s.cfg.contract, &log, &h),
        Err(RejectReason::NotFinalizedAncestor)
    );
}
