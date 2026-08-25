//! Lacuna 5: an `eth_getLogs` answer is never sufficient on its own.
//!
//! Every test here starts from a log that is **well-formed and really returned
//! by `eth_getLogs`** — it decodes, it names the right emitter, it carries the
//! right topics and the right payload — and then breaks exactly one of the
//! independent corroborations the adapter requires. Each test asserts the
//! specific rejection reason ([`RejectReason`]) *and* the neutral error the
//! adapter surfaces, so a future change that widens acceptance cannot pass by
//! silently swapping one failure for another.
//!
//! The suite is offline: the "chain" is the deterministic in-crate mock.

mod common;

use adapter_evm::abi::{event_topic0, SIG_CLAIMED};
use adapter_evm::attest::{attest_settlement_log, verify_finalized_ancestry, MAX_ANCESTRY_WALK};
use adapter_evm::evidence::{decode_settlement_log, EvidenceKind};
use adapter_evm::finality::{fetch_finalized, fetch_finalized_checked, FinalizedHead};
use adapter_evm::mock::Faults;
use adapter_evm::rpc::{EthClient, RpcLog};
use adapter_evm::{EvmAdapter, RejectReason};
use common::{scenario, Rewrite, Scenario, SharedChain};
use counterparty_api::{AdapterError, ChainCursor};

/// The scenario every rejection test starts from: a lock opened at height 1, a
/// claim at height 2, two further blocks so the settlement sits strictly
/// *below* the finalized head (which is what makes the ancestry relation
/// non-trivial), and the whole thing finalized.
fn settled() -> Scenario {
    let s = scenario(151);
    s.mine_open();
    s.mine_claim();
    s.mine(2);
    s.finalize_tip();
    s
}

/// The `Claimed` log exactly as `eth_getLogs` serves it.
fn claim_log(s: &Scenario) -> RpcLog {
    EthClient::new(&s.chain)
        .logs(0, s.height(), &s.cfg.contract, &[event_topic0(SIG_CLAIMED)])
        .expect("eth_getLogs answered")
        .into_iter()
        .next()
        .expect("the scenario mined exactly one Claimed log")
}

fn head(s: &Scenario) -> FinalizedHead {
    fetch_finalized(&s.chain).expect("the mock serves the finalized tag")
}

fn adapter(s: &Scenario) -> EvmAdapter<SharedChain> {
    let a = s.adapter();
    a.track_lock(&s.terms).expect("register the lock");
    a
}

/// Applies a fault, then reports what the attestation and the adapter each say
/// about the *same* well-formed log.
fn reject_with(faults: Faults) -> (RejectReason, AdapterError) {
    let s = settled();
    // The log is captured from a clean endpoint: it is genuinely well formed.
    let log = claim_log(&s);
    let h = head(&s);
    decode_settlement_log(&log, &s.cfg.contract).expect("the log itself is well formed");

    s.chain.set_faults(faults);
    let reason = attest_settlement_log(&s.chain, &s.cfg.contract, &log, &h)
        .expect_err("the log must not be attested");
    let neutral = adapter(&s)
        .observe_blocking(&ChainCursor::default(), 64)
        .expect_err("the adapter must not surface the settlement");
    (reason, neutral)
}

// ---------------------------------------------------------------------------
// the umbrella property
// ---------------------------------------------------------------------------

#[test]
fn a_bare_get_logs_answer_is_never_sufficient_on_its_own() {
    // Each of these leaves `eth_getLogs` answering with a perfectly good log
    // and breaks only a corroboration. None of them may be accepted.
    let breakages: Vec<(&str, Faults)> = vec![
        (
            "no receipt",
            Faults {
                receipt_missing: true,
                ..Faults::default()
            },
        ),
        (
            "reverted receipt",
            Faults {
                receipt_reverted: true,
                ..Faults::default()
            },
        ),
        (
            "receipt in another block",
            Faults {
                receipt_block_mismatch: true,
                ..Faults::default()
            },
        ),
        (
            "receipt without the log",
            Faults {
                receipt_logs_empty: true,
                ..Faults::default()
            },
        ),
        (
            "receipt log at another index",
            Faults {
                receipt_log_index_shifted: true,
                ..Faults::default()
            },
        ),
        (
            "receipt log with another payload",
            Faults {
                receipt_log_tampered: true,
                ..Faults::default()
            },
        ),
        (
            "no transaction",
            Faults {
                transaction_missing: true,
                ..Faults::default()
            },
        ),
        (
            "transaction in another block",
            Faults {
                transaction_block_mismatch: true,
                ..Faults::default()
            },
        ),
        (
            "transaction still pending",
            Faults {
                transaction_pending: true,
                ..Faults::default()
            },
        ),
        (
            "transaction to another address",
            Faults {
                transaction_to_foreign: true,
                ..Faults::default()
            },
        ),
        (
            "another block at that height",
            Faults {
                divergent_canonical_block_hash: true,
                ..Faults::default()
            },
        ),
        (
            "no ancestry from the finalized head",
            Faults {
                orphan_parent_linkage: true,
                ..Faults::default()
            },
        ),
        (
            "no finalized tag",
            Faults {
                finalized_null: true,
                ..Faults::default()
            },
        ),
    ];
    for (name, faults) in breakages {
        let s = settled();
        let log = claim_log(&s);
        decode_settlement_log(&log, &s.cfg.contract)
            .unwrap_or_else(|_| panic!("'{name}': the log itself must be well formed"));
        s.chain.set_faults(faults);
        assert!(
            adapter(&s)
                .observe_blocking(&ChainCursor::default(), 64)
                .is_err(),
            "'{name}': a well-formed eth_getLogs answer was accepted on its own"
        );
    }
}

// ---------------------------------------------------------------------------
// one test per rejection reason
// ---------------------------------------------------------------------------

#[test]
fn a_log_whose_receipt_is_missing_is_rejected() {
    let (reason, neutral) = reject_with(Faults {
        receipt_missing: true,
        ..Faults::default()
    });
    assert_eq!(reason, RejectReason::ReceiptMissing);
    assert_eq!(neutral, AdapterError::EvidenceInvalid);
}

#[test]
fn a_log_whose_receipt_reverted_is_rejected() {
    let (reason, neutral) = reject_with(Faults {
        receipt_reverted: true,
        ..Faults::default()
    });
    assert_eq!(
        reason,
        RejectReason::ReceiptReverted,
        "status != 1 means the transaction produced no state change at all"
    );
    assert_eq!(neutral, AdapterError::EvidenceInvalid);
}

#[test]
fn a_log_whose_receipt_points_at_another_block_is_rejected() {
    let (reason, neutral) = reject_with(Faults {
        receipt_block_mismatch: true,
        ..Faults::default()
    });
    assert_eq!(reason, RejectReason::ReceiptInconsistent);
    assert_eq!(neutral, AdapterError::EvidenceInvalid);
}

#[test]
fn a_log_absent_from_its_own_receipt_is_rejected() {
    let (reason, neutral) = reject_with(Faults {
        receipt_logs_empty: true,
        ..Faults::default()
    });
    assert_eq!(
        reason,
        RejectReason::LogAbsentFromReceipt,
        "the receipt is the node's own record of what the transaction emitted"
    );
    assert_eq!(neutral, AdapterError::EvidenceInvalid);
}

#[test]
fn a_log_at_the_wrong_index_in_its_receipt_is_rejected() {
    let (reason, neutral) = reject_with(Faults {
        receipt_log_index_shifted: true,
        ..Faults::default()
    });
    assert_eq!(reason, RejectReason::LogAbsentFromReceipt);
    assert_eq!(neutral, AdapterError::EvidenceInvalid);
}

#[test]
fn a_log_whose_receipt_copy_says_something_else_is_rejected() {
    let (reason, neutral) = reject_with(Faults {
        receipt_log_tampered: true,
        ..Faults::default()
    });
    assert_eq!(
        reason,
        RejectReason::LogAbsentFromReceipt,
        "presence at the right index is not enough: it must be the same log"
    );
    assert_eq!(neutral, AdapterError::EvidenceInvalid);
}

#[test]
fn a_log_whose_transaction_is_missing_is_rejected() {
    let (reason, neutral) = reject_with(Faults {
        transaction_missing: true,
        ..Faults::default()
    });
    assert_eq!(reason, RejectReason::TransactionMissing);
    assert_eq!(neutral, AdapterError::EvidenceInvalid);
}

#[test]
fn a_log_whose_transaction_disagrees_with_the_receipt_is_rejected() {
    let (reason, neutral) = reject_with(Faults {
        transaction_block_mismatch: true,
        ..Faults::default()
    });
    assert_eq!(reason, RejectReason::TransactionInconsistent);
    assert_eq!(neutral, AdapterError::EvidenceInvalid);
}

#[test]
fn a_log_whose_transaction_is_still_pending_is_rejected() {
    let (reason, neutral) = reject_with(Faults {
        transaction_pending: true,
        ..Faults::default()
    });
    assert_eq!(
        reason,
        RejectReason::TransactionInconsistent,
        "a transaction with no block cannot have produced a finalized log"
    );
    assert_eq!(neutral, AdapterError::EvidenceInvalid);
}

#[test]
fn a_log_whose_transaction_targets_another_address_is_rejected() {
    let (reason, neutral) = reject_with(Faults {
        transaction_to_foreign: true,
        ..Faults::default()
    });
    assert_eq!(reason, RejectReason::TransactionNotToContract);
    assert_eq!(neutral, AdapterError::EvidenceInvalid);
}

#[test]
fn a_log_whose_block_hash_disagrees_with_the_canonical_chain_is_rejected() {
    let (reason, neutral) = reject_with(Faults {
        divergent_canonical_block_hash: true,
        ..Faults::default()
    });
    assert_eq!(
        reason,
        RejectReason::NotCanonical,
        "the canonical chain carries a different block at that height"
    );
    assert_eq!(neutral, AdapterError::ReorgDetected);
}

#[test]
fn a_log_that_does_not_descend_from_the_finalized_head_is_rejected() {
    let (reason, neutral) = reject_with(Faults {
        orphan_parent_linkage: true,
        ..Faults::default()
    });
    assert_eq!(
        reason,
        RejectReason::NotFinalizedAncestor,
        "below the finalized height is not the same as descended from it"
    );
    assert_eq!(neutral, AdapterError::ReorgDetected);
}

#[test]
fn a_log_marked_removed_by_the_endpoint_is_rejected() {
    let s = settled();
    let mut log = claim_log(&s);
    log.removed = true;
    assert_eq!(
        attest_settlement_log(&s.chain, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::LogMarkedRemoved)
    );
    s.chain.set_faults(Faults {
        mark_logs_removed: true,
        ..Faults::default()
    });
    assert_eq!(
        adapter(&s).observe_blocking(&ChainCursor::default(), 64),
        Err(AdapterError::EvidenceInvalid)
    );
}

#[test]
fn a_log_from_a_foreign_emitter_is_rejected() {
    let s = settled();
    let mut log = claim_log(&s);
    log.address = [0xDE; 20];
    assert_eq!(
        attest_settlement_log(&s.chain, &s.cfg.contract, &log, &head(&s)),
        Err(RejectReason::LogEmitterMismatch)
    );
    s.chain.set_faults(Faults {
        wrong_emitter: true,
        ..Faults::default()
    });
    assert_eq!(
        adapter(&s).observe_blocking(&ChainCursor::default(), 64),
        Err(AdapterError::EvidenceInvalid)
    );
}

#[test]
fn a_log_above_the_finalized_head_is_rejected() {
    let s = scenario(157);
    s.mine_open();
    let claim_h = s.mine_claim();
    // Finalize *below* the claim: the log exists, is well formed, and is not
    // final.
    s.finalize(claim_h - 1);
    let log = claim_log(&s);
    let h = head(&s);
    assert!(log.block_number > h.height);

    assert_eq!(
        attest_settlement_log(&s.chain, &s.cfg.contract, &log, &h),
        Err(RejectReason::AboveFinalizedHead),
        "no economic effect before finality, ever"
    );
    assert_eq!(
        AdapterError::from(RejectReason::AboveFinalizedHead),
        AdapterError::PreconditionUnsatisfied
    );

    // At the adapter boundary the claim is simply never surfaced.
    let (events, _) = adapter(&s)
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observation succeeds, it just sees nothing final");
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, counterparty_api::ObservedEvent::LockClaimed { .. })),
        "a claim above the finalized head leaked out"
    );
    // Evidence cannot be collected for it either.
    assert_eq!(
        adapter(&s).collect_evidence(&s.lock_id, EvidenceKind::Claimed),
        Err(AdapterError::PreconditionUnsatisfied)
    );
}

#[test]
fn an_endpoint_that_cannot_serve_the_finalized_tag_is_blocked_external() {
    let s = settled();
    s.chain.set_faults(Faults {
        finalized_null: true,
        ..Faults::default()
    });

    let reason = fetch_finalized_checked(&s.chain).expect_err("the tag is unavailable");
    assert_eq!(reason, RejectReason::FinalizedTagUnavailable);
    assert!(
        reason.is_finalized_tag_unavailable(),
        "the caller must be able to report BLOCKED_EXTERNAL for exactly this"
    );
    assert_eq!(
        AdapterError::from(reason),
        AdapterError::AdapterUnavailable,
        "the neutral verdict stays fail-closed; no fallback to a confirmation count"
    );

    let a = adapter(&s);
    assert_eq!(a.finalized_head_checked(), Err(reason));
    assert_eq!(
        a.observe_blocking(&ChainCursor::default(), 64),
        Err(AdapterError::AdapterUnavailable)
    );
}

#[test]
fn a_dead_transport_is_reported_as_a_transport_failure_not_as_a_verdict() {
    let s = settled();
    let log = claim_log(&s);
    let h = head(&s);
    s.chain.set_faults(Faults {
        break_transport: true,
        ..Faults::default()
    });
    assert_eq!(
        attest_settlement_log(&s.chain, &s.cfg.contract, &log, &h),
        Err(RejectReason::Transport)
    );
    // And the finalized-tag probe distinguishes "unreachable" from "unsupported".
    let reason = fetch_finalized_checked(&s.chain).expect_err("transport is down");
    assert_eq!(reason, RejectReason::FinalizedTagTransportFailure);
    assert!(!reason.is_finalized_tag_unavailable());
    assert_eq!(
        adapter(&s).observe_blocking(&ChainCursor::default(), 64),
        Err(AdapterError::AdapterUnavailable)
    );
}

#[test]
fn an_ancestry_check_that_cannot_reach_a_block_is_rejected() {
    let s = settled();
    // A finalized head the endpoint cannot produce. Every lookup inside an
    // ancestry proof is of a hash the endpoint already vouched for, so failing
    // to produce one is the endpoint contradicting itself — not a lag.
    let phantom = FinalizedHead {
        height: s.height(),
        hash: [0x5E; 32],
    };
    assert_eq!(
        verify_finalized_ancestry(
            &s.chain,
            0,
            &s.chain.with(|c| c.block_hash(0).expect("genesis")),
            &phantom,
        ),
        Err(RejectReason::NotFinalizedAncestor),
    );
    assert_eq!(
        AdapterError::from(RejectReason::NotFinalizedAncestor),
        AdapterError::ReorgDetected,
    );
}

/// The other half of the classification rule, pinned so the two cannot drift
/// back together: a node that is merely *behind* fails at the height-addressed
/// lookup, and that is unavailability rather than a fork. Getting this backwards
/// makes a briefly desynced node look like a reorg.
#[test]
fn a_node_that_has_not_synced_the_height_is_unavailable_not_a_reorg() {
    let s = settled();
    let log = claim_log(&s);
    // Truthful finalized head, but the endpoint answers `null` for the
    // height-addressed lookup of the log's own block.
    let h = head(&s);
    let target = log.block_number;
    let rpc = Rewrite::new(s.chain.clone(), move |method, params, value| {
        if method == "eth_getBlockByNumber"
            && params
                .get(0)
                .and_then(|p| p.as_str())
                .is_some_and(|t| t == format!("0x{target:x}"))
        {
            return serde_json::Value::Null;
        }
        value
    });
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &h),
        Err(RejectReason::BlockMissing),
    );
    assert_eq!(
        AdapterError::from(RejectReason::BlockMissing),
        AdapterError::AdapterUnavailable,
        "a lagging node must never be reported as a fork"
    );
}

/// An honest chain whose gap exceeds one call's walk budget is **refused**, and
/// the refusal is distinguishable from every verdict about the settlement.
#[test]
fn an_ancestry_gap_wider_than_the_budget_is_refused_with_its_own_reason() {
    let s = scenario(163);
    s.mine_open();
    s.mine_claim();
    s.mine(MAX_ANCESTRY_WALK + 4);
    s.finalize_tip();
    let log = claim_log(&s);
    let h = head(&s);
    assert!(h.height - log.block_number > MAX_ANCESTRY_WALK);

    assert_eq!(
        attest_settlement_log(&s.chain, &s.cfg.contract, &log, &h),
        Err(RejectReason::AncestryProofTooDeep),
        "no weaker question is asked in place of the walk"
    );
    assert_eq!(
        AdapterError::from(RejectReason::AncestryProofTooDeep),
        AdapterError::BoundsExceeded,
    );
}

/// ... and the refusal has a way out that is still a proof: bounded batches.
#[test]
fn bounded_batches_let_a_deep_observation_be_proved_link_by_link() {
    let s = scenario(167);
    s.mine_open();
    s.mine_claim();
    s.mine(MAX_ANCESTRY_WALK + 4);
    s.finalize_tip();
    let log = claim_log(&s);
    let a = adapter(&s);

    assert_eq!(
        a.observe_blocking(&ChainCursor::default(), 64),
        Err(AdapterError::BoundsExceeded),
        "the gap is deeper than one call may walk"
    );

    let mut rounds = 0;
    loop {
        let lowest = a
            .extend_verified_ancestry(log.block_number)
            .expect("bounded batch");
        rounds += 1;
        assert!(rounds < 16, "batching must converge");
        if lowest <= log.block_number {
            break;
        }
    }
    assert!(a.verified_links().expect("state") > MAX_ANCESTRY_WALK as usize);

    let (events, _) = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("every link is now proved");
    assert_eq!(events.len(), 2, "open + claim");

    // The batched proof is a proof, not an assumption: a dishonest endpoint is
    // still refused for anything it has not already shown.
    let fresh = adapter(&s);
    s.chain.set_faults(Faults {
        orphan_parent_linkage: true,
        ..Faults::default()
    });
    assert_eq!(
        fresh.extend_verified_ancestry(log.block_number),
        Err(AdapterError::ReorgDetected),
        "batches follow parent hashes; an endpoint with none gets nowhere"
    );
}

// ---------------------------------------------------------------------------
// the corroborations do not break the honest path
// ---------------------------------------------------------------------------

#[test]
fn an_uncorrupted_settlement_still_attests_and_still_surfaces() {
    let s = settled();
    let log = claim_log(&s);
    let a = attest_settlement_log(&s.chain, &s.cfg.contract, &log, &head(&s))
        .expect("an honest endpoint corroborates its own log");
    assert_eq!(a.receipt.status, 1);
    assert_eq!(a.receipt.log_at(log.log_index), Some(&log));
    assert_eq!(a.transaction.to, Some(s.cfg.contract));
    assert_eq!(a.transaction.block_hash, Some(log.block_hash));
    assert_eq!(a.block.hash, log.block_hash);

    let (events, _) = adapter(&s)
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    assert_eq!(events.len(), 2, "open + claim, both fully corroborated");
}

#[test]
fn evidence_collection_and_verification_both_require_the_corroborations() {
    let s = settled();
    let a = adapter(&s);
    let _ = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    let good = a
        .collect_evidence(&s.lock_id, EvidenceKind::Claimed)
        .expect("evidence")
        .encode();
    assert!(a.verify_evidence_blocking(&good).is_ok());

    // Break one corroboration at a time; both collection and verification of
    // *already collected* evidence must stop working. These three are re-fetched
    // and re-compared on every call, so a warm observer catches them too.
    for faults in [
        Faults {
            receipt_logs_empty: true,
            ..Faults::default()
        },
        Faults {
            transaction_to_foreign: true,
            ..Faults::default()
        },
        Faults {
            divergent_canonical_block_hash: true,
            ..Faults::default()
        },
    ] {
        s.chain.set_faults(faults);
        assert!(
            a.collect_evidence(&s.lock_id, EvidenceKind::Claimed)
                .is_err(),
            "evidence was collected from an uncorroborated log: {faults:?}"
        );
        assert!(
            a.verify_evidence_blocking(&good).is_err(),
            "evidence verified against an uncorroborated log: {faults:?}"
        );
        s.chain.set_faults(Faults::default());
    }

    // Ancestry is the one corroboration a *warm* observer does not re-walk: the
    // link was already followed hash by hash during `observe`, and a finalized
    // block does not stop being finalized. Caching that proof is sound — but it
    // must be a memory of a proof, never a substitute for one, so a fresh
    // observer with the same endpoint still has to earn it and still fails.
    s.chain.set_faults(Faults {
        orphan_parent_linkage: true,
        ..Faults::default()
    });
    let cold = adapter(&s);
    assert_eq!(
        cold.collect_evidence(&s.lock_id, EvidenceKind::Claimed),
        Err(AdapterError::ReorgDetected),
        "an observer that has proved nothing yet must prove the ancestry"
    );
    // And verification never takes the cached path at all: `verify_onchain`
    // keeps its own, fresh `VerifiedChain` and walks from the head the endpoint
    // names on *this* call, every single time. A verifier that answered out of
    // a proof it made earlier for something else would be doing what round 2 of
    // the audit caught the observer doing.
    assert_eq!(
        a.verify_evidence_blocking(&good),
        Err(AdapterError::ReorgDetected),
        "verify_onchain must re-walk the link on every call, warm cache or not"
    );
    s.chain.set_faults(Faults::default());

    // ... and the honest endpoint still verifies afterwards.
    assert!(a.verify_evidence_blocking(&good).is_ok());
}

// ---------------------------------------------------------------------------
// evidence must not decay
// ---------------------------------------------------------------------------

/// Evidence that has aged far past the walk budget must still re-verify, and
/// must still be re-verified by a **hash-linked** proof — not by the endpoint's
/// canonical index, which is the shortcut this whole design exists to refuse.
///
/// Round 1 achieved that with a proof anchored on the checkpoint recorded in
/// the evidence — both ends out of the record, so its cost was fixed for ever.
/// Round 2 of the audit showed that proof is vacuous: at gap 0 it compares a
/// hash to itself, and otherwise it re-proves that the attacker's own fork is
/// internally linked. So the walk is rooted in the endpoint's current head
/// again, and the growing cost is paid in bounded batches up to
/// `MAX_ANCESTRY_TOTAL` links. That ceiling is the liveness price of the fix,
/// and it is a stated bound: past it the answer is `BoundsExceeded`, and a
/// long-lived verifier avoids it with `verify_onchain_cached`.
#[test]
fn evidence_that_has_aged_past_the_walk_budget_still_verifies() {
    let s = settled();
    let a = adapter(&s);
    let _ = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    let aged = a
        .collect_evidence(&s.lock_id, EvidenceKind::Claimed)
        .expect("evidence")
        .encode();
    assert!(a.verify_evidence_blocking(&aged).is_ok(), "fresh");

    // Time passes: the finalized head moves far beyond anything one call may
    // walk back from.
    s.mine(MAX_ANCESTRY_WALK * 2);
    s.finalize_tip();

    assert!(
        a.verify_evidence_blocking(&aged).is_ok(),
        "evidence that can never be re-verified is its own defect"
    );
    // A brand-new process, with nothing cached, must reach the same verdict:
    // the anchor travels inside the evidence, not in the observer's memory.
    let cold = s.adapter();
    assert!(cold.verify_evidence_blocking(&aged).is_ok());
}

/// ... and "still verifies" must not mean "stopped checking". The same aged
/// evidence, against an endpoint that can exhibit no parent linkage, must fail
/// — proving the anchored walk really ran.
#[test]
fn aged_evidence_is_still_refused_when_the_anchor_cannot_be_linked() {
    let s = settled();
    let a = adapter(&s);
    let _ = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    let aged = a
        .collect_evidence(&s.lock_id, EvidenceKind::Claimed)
        .expect("evidence")
        .encode();
    s.mine(MAX_ANCESTRY_WALK * 2);
    s.finalize_tip();
    assert!(a.verify_evidence_blocking(&aged).is_ok());

    s.chain.set_faults(Faults {
        orphan_parent_linkage: true,
        ..Faults::default()
    });
    assert_eq!(
        a.verify_evidence_blocking(&aged),
        Err(AdapterError::ReorgDetected),
        "aged evidence is re-proved, not merely re-read"
    );
}

/// A break placed deliberately out of reach of a single walk budget.
///
/// This test was written when the head-side walk was allowed to give up on an
/// aged record (`AncestryProofTooDeep` was forgiven) and the only thing that
/// could see a break just below the recorded checkpoint was the anchored walk.
/// The forgiveness is gone and the anchored walk with it: the head-side walk
/// now closes the whole distance in bounded batches, so it reaches this break
/// itself. The assertion is unchanged, and it is still the assertion that
/// matters — aged evidence with a broken link must be refused, whichever part
/// of the machinery notices.
#[test]
fn aged_evidence_is_refused_when_only_the_anchored_walk_can_see_the_break() {
    let s = settled();
    let a = adapter(&s);
    let _ = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    let evidence = a
        .collect_evidence(&s.lock_id, EvidenceKind::Claimed)
        .expect("evidence");
    let bytes = evidence.encode();

    // Push the current head far past the walk budget.
    s.mine(MAX_ANCESTRY_WALK * 2);
    s.finalize_tip();
    assert!(
        s.adapter().verify_evidence_blocking(&bytes).is_ok(),
        "control: aged but honest evidence verifies"
    );

    // The one block the anchored walk must traverse and the head-side walk
    // never reaches. The walk steps from the checkpoint down *to* the
    // observation, so the hashes it asks for are those strictly above it.
    assert!(evidence.finalized_height > evidence.block_number + 1);
    let broken = s
        .chain
        .with(|c| c.block_hash(evidence.block_number + 1).expect("block"));
    let rpc = Rewrite::new(s.chain.clone(), move |method, params, value| {
        if method == "eth_getBlockByHash"
            && params
                .get(0)
                .and_then(|p| p.as_str())
                .is_some_and(|h| h.eq_ignore_ascii_case(&format!("0x{}", hex::encode(broken))))
        {
            return serde_json::Value::Null;
        }
        value
    });
    let observer = EvmAdapter::new(s.cfg, rpc).expect("valid configuration");
    assert_eq!(
        observer.verify_evidence_blocking(&bytes),
        Err(AdapterError::ReorgDetected),
        "the anchored walk is what proves ancestry once the head-side walk is \
         allowed to give up; without it, aged evidence proves nothing"
    );
}
