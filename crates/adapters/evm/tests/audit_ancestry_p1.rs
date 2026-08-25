//! ADVERSARIAL AUDIT PROOF (P1) — the >16-block ancestry path accepts a block
//! that provably does not descend from the finalized head.
//!
//! Companion to `audit_ancestry.rs`, which pins the *current* behaviour. This
//! file asserts the behaviour the module's own documentation promises, so it
//! FAILS against the code as it stands. That is the point: a proof, not a
//! description.
//!
//! `attest.rs:28-32` states the rule:
//!
//! > A block can sit below the finalized height and still be on a fork ...
//! > Height alone therefore proves nothing.
//!
//! Beyond `MAX_ANCESTRY_WALK` (16) the bounded fallback does exactly two
//! things (`attest.rs:215-234`):
//!
//! 1. asks the endpoint whether the block at the finalized height has the
//!    finalized hash — comparing the endpoint's answer with the endpoint's
//!    own answer from `finality.rs:87`;
//! 2. asks whether the block at the observation's height has the observation's
//!    hash — which `attest_settlement_log` already asked at step 3
//!    (`attest.rs:170-176`).
//!
//! Neither establishes a parent link. So beyond block 16 the attestation is
//! "height alone", the thing the header says proves nothing.
//!
//! The attacker's cost is waiting ~3.5 minutes on Ethereum. Worse,
//! `EvmEvidence::verify_onchain` (`evidence.rs:400`) re-attests stored evidence
//! against the *current* finalized head, so every re-verification more than 16
//! blocks after collection takes the weak path unconditionally.

mod common;

use adapter_evm::abi::{event_topic0, SIG_CLAIMED};
use adapter_evm::attest::{attest_settlement_log, verify_finalized_ancestry, MAX_ANCESTRY_WALK};
use adapter_evm::finality::fetch_finalized;
use adapter_evm::mock::{Faults, MockChain};
use adapter_evm::rpc::{EthClient, RpcLog};
use adapter_evm::RejectReason;
use common::{scenario, Scenario};

const CONTRACT: [u8; 20] = [0xC0; 20];

/// The endpoint can show no chain of parent hashes at all.
fn orphaned() -> Faults {
    Faults {
        orphan_parent_linkage: true,
        ..Faults::default()
    }
}

fn claim_log(s: &Scenario) -> RpcLog {
    EthClient::new(&s.chain)
        .logs(0, s.height(), &s.cfg.contract, &[event_topic0(SIG_CLAIMED)])
        .expect("eth_getLogs answered")
        .into_iter()
        .next()
        .expect("one Claimed log")
}

#[test]
fn ancestry_must_not_weaken_once_the_gap_exceeds_the_walk_budget() {
    // Control: inside the budget the hash-linked walk refuses this endpoint.
    let near = MockChain::new(31337, CONTRACT).with_blocks(4).finalize(4);
    let near_head = fetch_finalized(&near).expect("finalized");
    let near_target = near.block_hash(1).expect("block 1");
    assert_eq!(
        verify_finalized_ancestry(&near.with_faults(orphaned()), 1, &near_target, &near_head),
        Err(RejectReason::NotFinalizedAncestor),
        "control: gap 3 is inside the budget and the walk catches it",
    );

    // The finding: identical endpoint, identical fault, deeper block.
    let far_height = MAX_ANCESTRY_WALK + 10;
    let far = MockChain::new(31337, CONTRACT)
        .with_blocks(far_height)
        .finalize(far_height);
    let far_head = fetch_finalized(&far).expect("finalized");
    let far_target = far.block_hash(1).expect("block 1");
    let outcome =
        verify_finalized_ancestry(&far.with_faults(orphaned()), 1, &far_target, &far_head);

    assert_eq!(
        outcome,
        Err(RejectReason::NotFinalizedAncestor),
        "P1: at gap {} the endpoint can exhibit NO parent linkage between the \
         finalized head and the observation, and ancestry is accepted anyway \
         (got {outcome:?}). attest.rs:215-234 degrades to two questions, one \
         self-referential and one already asked at attest.rs:170-176.",
        far_height - 1,
    );
}

#[test]
fn a_settlement_log_on_an_unlinked_block_must_never_attest_at_any_depth() {
    let s = scenario(151);
    s.mine_open();
    let claim_height = s.mine_claim();
    s.mine(MAX_ANCESTRY_WALK + 4);
    s.finalize_tip();

    let log = claim_log(&s);
    assert_eq!(log.block_number, claim_height);
    let head = fetch_finalized(&s.chain).expect("finalized");
    assert!(
        head.height.saturating_sub(log.block_number) > MAX_ANCESTRY_WALK,
        "precondition: the observation sits beyond the walk budget",
    );

    // Exactly the fault tests/attestation.rs uses to prove
    // `NotFinalizedAncestor` at shallow depth.
    s.chain.set_faults(orphaned());
    let attested = attest_settlement_log(&s.chain, &s.cfg.contract, &log, &head);

    assert_eq!(
        attested.err(),
        Some(RejectReason::NotFinalizedAncestor),
        "P1: a full settlement attestation succeeded for a block the endpoint \
         cannot link to the finalized head by any parent hash. \
         tests/attestation.rs:326 proves this rejection only for a 4-block \
         chain; the property does not hold beyond MAX_ANCESTRY_WALK.",
    );
}
