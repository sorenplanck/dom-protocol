//! AUDIT (adversarial): a forging endpoint that rewrites *only* the receipt or
//! the transaction JSON, to probe the corroboration checks field by field.
//!
//! The mock's `Faults` can only produce the shapes it was written for. This file
//! interposes on the JSON-RPC boundary so arbitrary shapes can be served.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use adapter_evm::abi::{event_topic0, SIG_CLAIMED};
use adapter_evm::attest::{attest_settlement_log, verify_finalized_ancestry, MAX_ANCESTRY_WALK};
use adapter_evm::finality::{fetch_finalized, FinalizedHead};
use adapter_evm::rpc::{EthClient, JsonRpc, RpcLog};
use adapter_evm::RejectReason;
use common::{scenario, Scenario, SharedChain};
use counterparty_api::AdapterError;
use serde_json::{json, Value};

/// A JSON-RPC endpoint that answers honestly and then rewrites the answer.
struct Forge<F> {
    inner: SharedChain,
    rewrite: F,
    calls: Arc<AtomicUsize>,
}

impl<F> Forge<F>
where
    F: Fn(&str, Value) -> Value + Send + Sync,
{
    fn new(inner: SharedChain, rewrite: F) -> Self {
        Self {
            inner,
            rewrite,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl<F> JsonRpc for Forge<F>
where
    F: Fn(&str, Value) -> Value + Send + Sync,
{
    fn call(&self, method: &str, params: Value) -> Result<Value, AdapterError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let v = self.inner.call(method, params)?;
        Ok((self.rewrite)(method, v))
    }
}

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

/// A syntactically valid but bogus receipt log entry at `log_index`.
fn decoy(log_index: u64, address: &str) -> Value {
    json!({
        "address": address,
        "topics": [format!("0x{}", "ee".repeat(32))],
        "data": "0x",
        "blockNumber": "0x1",
        "blockHash": format!("0x{}", "11".repeat(32)),
        "transactionHash": format!("0x{}", "22".repeat(32)),
        "logIndex": format!("0x{log_index:x}"),
        "removed": false,
    })
}

// ---------------------------------------------------------------------------
// receipt `logs` array manipulation
// ---------------------------------------------------------------------------

/// The honest baseline, through the interposer, so every negative below is
/// known to differ only by the rewrite.
#[test]
fn audit_baseline_through_the_interposer_still_attests() {
    let s = settled();
    let log = claim_log(&s);
    let h = fetch_finalized(&s.chain).expect("finalized");
    let rpc = Forge::new(s.chain.clone(), |_, v| v);
    assert!(attest_settlement_log(&rpc, &s.cfg.contract, &log, &h).is_ok());
}

/// A decoy sharing the real log's `logIndex`, placed *first*: `log_at` takes the
/// first match, so the decoy shadows the real entry and the attestation must
/// fail closed.
#[test]
fn audit_a_shadowing_decoy_at_the_same_log_index_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let h = fetch_finalized(&s.chain).expect("finalized");
    let idx = u64::from(log.log_index);
    let rpc = Forge::new(s.chain.clone(), move |m, mut v| {
        if m == "eth_getTransactionReceipt" {
            if let Some(logs) = v.get_mut("logs").and_then(|l| l.as_array_mut()) {
                if !logs.is_empty() {
                    logs.insert(0, decoy(idx, &format!("0x{}", "c0".repeat(20))));
                }
            }
        }
        v
    });
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &h),
        Err(RejectReason::LogAbsentFromReceipt)
    );
}

/// Padding, reordering and duplication around the real entry do **not** break
/// attestation: the lookup is by `logIndex`, not by position. This is correct
/// (EVM `logIndex` is block-scoped) but it is worth pinning explicitly, because
/// it means the receipt's array *order* is never validated.
#[test]
fn audit_padding_reordering_and_duplication_around_the_real_entry_still_attest() {
    let s = settled();
    let log = claim_log(&s);
    let h = fetch_finalized(&s.chain).expect("finalized");
    let idx = u64::from(log.log_index);
    let rpc = Forge::new(s.chain.clone(), move |m, mut v| {
        if m == "eth_getTransactionReceipt" {
            if let Some(logs) = v.get_mut("logs").and_then(|l| l.as_array_mut()) {
                let real = logs.first().cloned();
                logs.clear();
                logs.push(decoy(idx + 1, &format!("0x{}", "de".repeat(20))));
                logs.push(decoy(idx + 2, &format!("0x{}", "de".repeat(20))));
                if let Some(r) = real {
                    logs.push(r.clone());
                    logs.push(r); // exact duplicate, same logIndex
                }
                logs.push(decoy(idx + 3, &format!("0x{}", "de".repeat(20))));
            }
        }
        v
    });
    assert!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &h).is_ok(),
        "position and array order are not part of the corroboration"
    );
}

/// A receipt whose `logs` array is emptied: rejected.
#[test]
fn audit_an_emptied_receipt_logs_array_is_rejected() {
    let s = settled();
    let log = claim_log(&s);
    let h = fetch_finalized(&s.chain).expect("finalized");
    let rpc = Forge::new(s.chain.clone(), |m, mut v| {
        if m == "eth_getTransactionReceipt" {
            if let Some(o) = v.as_object_mut() {
                o.insert("logs".into(), json!([]));
            }
        }
        v
    });
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &h),
        Err(RejectReason::LogAbsentFromReceipt)
    );
}

/// WAS A FINDING, NOW A PIN (classification): a receipt that is *structurally
/// malformed* — here, its log entry omits the mandatory `removed` member — used
/// to be reported as `Transport`, indistinguishable from a dead socket. It now
/// has its own reason, `MalformedAnswer`, so an operator can tell "your provider
/// is unreachable" from "your provider is answering nonsense".
///
/// The neutral verdict is still `AdapterUnavailable`, and deliberately so:
/// nothing can be *decided* from an answer that could not be parsed, so the
/// fail-closed outcome is unchanged. What changed is that the reason survives.
#[test]
fn audit_a_structurally_malformed_receipt_is_classified_as_transport() {
    let s = settled();
    let log = claim_log(&s);
    let h = fetch_finalized(&s.chain).expect("finalized");
    let rpc = Forge::new(s.chain.clone(), |m, mut v| {
        if m == "eth_getTransactionReceipt" {
            if let Some(logs) = v.get_mut("logs").and_then(|l| l.as_array_mut()) {
                for l in logs.iter_mut() {
                    if let Some(o) = l.as_object_mut() {
                        o.remove("removed");
                    }
                }
            }
        }
        v
    });
    let got = attest_settlement_log(&rpc, &s.cfg.contract, &log, &h);
    assert_eq!(
        got,
        Err(RejectReason::MalformedAnswer),
        "FIXED: a malformed answer is no longer reported as a dead socket"
    );
    assert_ne!(got, Err(RejectReason::Transport));
    assert_eq!(
        AdapterError::from(RejectReason::MalformedAnswer),
        AdapterError::AdapterUnavailable,
        "the neutral verdict stays fail-closed: an unparseable answer decides nothing"
    );
}

/// Same shape, one level up: a receipt that omits `status` entirely.
#[test]
fn audit_a_receipt_without_status_is_also_classified_as_transport() {
    let s = settled();
    let log = claim_log(&s);
    let h = fetch_finalized(&s.chain).expect("finalized");
    let rpc = Forge::new(s.chain.clone(), |m, mut v| {
        if m == "eth_getTransactionReceipt" {
            if let Some(o) = v.as_object_mut() {
                o.remove("status");
            }
        }
        v
    });
    assert_eq!(
        attest_settlement_log(&rpc, &s.cfg.contract, &log, &h),
        Err(RejectReason::MalformedAnswer),
        "a pre-Byzantium / hostile receipt is a malformed answer, not a dead socket"
    );
}

// ---------------------------------------------------------------------------
// transaction fields that are never compared
// ---------------------------------------------------------------------------

/// `from`, `value`, `input`, `nonce` and `transactionIndex` are not parsed and
/// not compared. Rewriting them all to nonsense changes nothing. (Not a
/// vulnerability on its own — the receipt anchors the emission — but it bounds
/// what "the transaction corroborates the log" actually means.)
#[test]
fn audit_transaction_from_value_input_and_nonce_are_never_compared() {
    let s = settled();
    let log = claim_log(&s);
    let h = fetch_finalized(&s.chain).expect("finalized");
    let rpc = Forge::new(s.chain.clone(), |m, mut v| {
        if m == "eth_getTransactionByHash" {
            if let Some(o) = v.as_object_mut() {
                o.insert("from".into(), json!(format!("0x{}", "ba".repeat(20))));
                o.insert("value".into(), json!("0xdeadbeef"));
                o.insert("input".into(), json!("0xdeadbeef"));
                o.insert("nonce".into(), json!("0x7fffffff"));
                o.insert("transactionIndex".into(), json!("0x99"));
            }
        }
        v
    });
    assert!(attest_settlement_log(&rpc, &s.cfg.contract, &log, &h).is_ok());
}

// ---------------------------------------------------------------------------
// how much the >16 fallback actually costs the endpoint
// ---------------------------------------------------------------------------

/// WAS A FINDING, NOW A PIN (cost model). This test used to measure the
/// degradation: beyond the budget the check cost *two* height-addressed lookups,
/// one re-asking what step 3 had already asked and one comparing the endpoint's
/// `finalized` answer with its own. Two calls bought acceptance of an
/// arbitrarily deep, entirely unlinked block.
///
/// The cost model is now uniform and is what makes the guarantee real: **one
/// hash-addressed lookup per block of gap, at every depth**, and a refusal —
/// never a cheaper answer — once a single call's budget is spent. The count is
/// asserted exactly, because "how many links did you actually follow?" is the
/// question the finding turned on.
#[test]
fn audit_the_fallback_costs_two_calls_and_asks_nothing_new() {
    let s = scenario(11);
    s.mine(MAX_ANCESTRY_WALK + 10);
    s.finalize_tip();
    let head: FinalizedHead = fetch_finalized(&s.chain).expect("finalized");
    let target = s.chain.with(|c| c.block_hash(1).expect("block 1"));

    let rpc = Forge::new(s.chain.clone(), |_, v| v);
    let counter = rpc.calls.clone();
    assert_eq!(
        verify_finalized_ancestry(&rpc, 1, &target, &head),
        Err(RejectReason::AncestryProofTooDeep),
        "FIXED: no two-call shortcut past the budget"
    );
    assert_eq!(
        counter.load(Ordering::Relaxed),
        MAX_ANCESTRY_WALK as usize,
        "the budget is spent on real links before the refusal, not saved by \
         asking something cheaper"
    );

    // The same question inside the budget costs one lookup per block of gap —
    // unchanged, and now the only cost model there is.
    let near = scenario(12);
    near.mine(4);
    near.finalize_tip();
    let near_head = fetch_finalized(&near.chain).expect("finalized");
    let near_target = near.chain.with(|c| c.block_hash(1).expect("block 1"));
    let near_rpc = Forge::new(near.chain.clone(), |_, v| v);
    let near_counter = near_rpc.calls.clone();
    assert_eq!(
        verify_finalized_ancestry(&near_rpc, 1, &near_target, &near_head),
        Ok(())
    );
    assert_eq!(near_counter.load(Ordering::Relaxed), 3);
}
