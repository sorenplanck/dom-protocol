//! F4 spec §12 item 3: the slash path on Sepolia — a compensation
//! executed on a public testnet with NO privileged action anywhere.
//!
//! Driven by `./scripts/f4_sepolia_slash.sh` (in CI, the `f4-sepolia`
//! workflow): it deploys/locates the audited `ConditionLockV2`, exports
//! the `F4_SEPOLIA_*` environment and runs this one scenario. Without
//! the environment the test prints the NOTHING-VERIFIED marker and the
//! script fails the run.
//!
//! One funded account plays every party the flow needs — solver
//! (funder), settlement counterparty, and protected party (bond
//! beneficiary). That collapses no security boundary the CONTRACT
//! enforces: `claim` still checks `msg.sender == beneficiary`, `refund`
//! still pays only the funder, and the permissionless-release
//! demonstration with three distinct accounts lives in the Anvil suite.
//! What THIS run proves is the §12 sentence: on a public network, with
//! real finality, the failure evidence verifies end to end and the
//! protected party compensates itself with the publicly revealed scalar
//! — no operator, no arbiter, no admin key.
//!
//! Real finality is the cost: two bounded waits for Sepolia's
//! `finalized` tag (~13 min each, bounded at 40). The deadlines are
//! sized so the §7.2 slash-execution margin dwarfs the worst-case wait.

#![cfg(feature = "rpc-http")]

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::process::Command;

use adapter_evm::abi::{keccak256, selector, word_bytes32, word_u256, SIG_CLAIM, SIG_OPEN};
use adapter_evm::adapter::{encode_open_calldata, UNSIGNED_CALL_VERSION};
use adapter_evm::binding::{
    adaptor_address_of_scalar, adaptor_point_of_scalar, derive_binding, derive_lock_id, Direction,
};
use adapter_evm::evidence::amount_word;
use adapter_evm::rpc::{HttpJsonRpc, JsonRpc};
use adapter_evm::{EvidenceKind, EvmAdapter, EvmAdapterConfig, LockTerms, UnsignedEvmCall};
use counterparty_api::{AdaptorPointBytes, ChainCursor};
use f4_harness::journal::{DurableAssurance, StoreLog};
use f4_harness::{
    BondBroadcaster, BondClock, BondDeployment, BondError, EvmBondAdapter, RevealedScalarVerifier,
};
use serde_json::{json, Value};
use uspe::bond::{BondAdapter, BondEvent, BroadcastOutcome};
use uspe::evidence::{EvidenceVerdict, EvidenceVerifier};
use uspe::objects::{
    AssetId, AssurancePolicyV1, ChainId, EvidenceRuleV1, PolicyId, SettlementId, TerminalPolicyV1,
    TimelockSpec, POLICY_STRUCT_VERSION,
};
use uspe::{AssuranceEffect, AssuranceEvent, AssuranceState};

const NOTHING_VERIFIED: &str = "SKIPPED — NOTHING WAS VERIFIED";
const SEPOLIA_CHAIN_ID: u64 = 11_155_111;
const FINALITY_POLL_SECS: u64 = 15;
const FINALITY_POLLS: u64 = 160; // 40 minutes, bounded
const COLLATERAL: u128 = 2; // wei of dust; the semantics, not the sum
const CAP: u128 = 3;
const SETTLEMENT_AMOUNT: u128 = 1;

struct Env {
    rpc_url: String,
    cast: String,
    contract: [u8; 20],
    account: [u8; 20],
    key: String,
    evidence_dir: std::path::PathBuf,
}

fn env() -> Option<Env> {
    let Ok(rpc_url) = std::env::var("F4_SEPOLIA_RPC") else {
        println!(
            "\n============================================================\n\
             {NOTHING_VERIFIED}\n\
             F4_SEPOLIA_RPC is not set, so the Sepolia slash did not run.\n\
             Run ./scripts/f4_sepolia_slash.sh, which exports everything.\n\
             ============================================================\n"
        );
        return None;
    };
    let contract = parse_address(&std::env::var("F4_SEPOLIA_LOCK").expect("F4_SEPOLIA_LOCK"))
        .expect("F4_SEPOLIA_LOCK is an address");
    let account = parse_address(&std::env::var("F4_SEPOLIA_ACCOUNT").expect("F4_SEPOLIA_ACCOUNT"))
        .expect("F4_SEPOLIA_ACCOUNT is an address");
    let key = std::env::var("F4_SEPOLIA_KEY").expect("F4_SEPOLIA_KEY");
    let cast = std::env::var("F4_CAST").unwrap_or_else(|_| "cast".to_string());
    let evidence_dir = std::path::PathBuf::from(
        std::env::var("F4_SEPOLIA_EVIDENCE_DIR")
            .unwrap_or_else(|_| "artifacts/sepolia".to_string()),
    );
    let rpc = HttpJsonRpc::new(rpc_url.clone(), 30);
    let id = rpc
        .call("eth_chainId", json!([]))
        .ok()
        .and_then(|v| parse_quantity(&v))
        .expect("eth_chainId answers");
    assert_eq!(
        id, SEPOLIA_CHAIN_ID,
        "this driver runs on Sepolia and nothing else; there is no override \
         flag, because a flag is how a mainnet accident happens"
    );
    Some(Env {
        rpc_url,
        cast,
        contract,
        account,
        key,
        evidence_dir,
    })
}

fn parse_address(s: &str) -> Option<[u8; 20]> {
    let h = s.strip_prefix("0x")?;
    if h.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn parse_quantity(v: &Value) -> Option<u64> {
    u64::from_str_radix(v.as_str()?.strip_prefix("0x")?, 16).ok()
}

fn hex0x(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Read-only RPC call with a bounded retry on TRANSIENT failure — the
/// same discipline as the bounded finality wait, applied to single
/// reads. A hosted endpoint may hiccup on any one of hundreds of round
/// trips (the first F3 Sepolia gate run died on exactly one); retrying
/// a read weakens no assertion, and an endpoint that stays down still
/// fails the run.
///
/// Exponential backoff, not a fixed delay: gate runs #3 and #4
/// (2026-08-10) both died against endpoint outages LONGER than the old
/// flat 8x15s window — #4's retries ran the full two minutes, correctly
/// spaced, and the endpoint stayed down past the last one. Ten attempts
/// backing off 15s -> 120s tolerate an outage of ~13 minutes,
/// proportionate to the 40-minute bound one finality wait already gets,
/// and still strictly bounded.
const RPC_READ_RETRIES: u32 = 10;
const RPC_READ_RETRY_BASE_SECS: u64 = 15;
const RPC_READ_RETRY_CAP_SECS: u64 = 120;

fn rpc_read_backoff(attempt: u32) -> std::time::Duration {
    let secs = RPC_READ_RETRY_BASE_SECS
        .saturating_mul(1u64 << attempt.min(3))
        .min(RPC_READ_RETRY_CAP_SECS);
    std::time::Duration::from_secs(secs)
}

fn rpc_read(rpc: &HttpJsonRpc, what: &str, method: &str, params: Value) -> Value {
    let mut last = None;
    for attempt in 0..RPC_READ_RETRIES {
        match rpc.call(method, params.clone()) {
            Ok(v) => return v,
            Err(err) => {
                let delay = rpc_read_backoff(attempt);
                println!(
                    "  transient          {what} failed ({err:?}), retry {}/{} in {}s",
                    attempt + 1,
                    RPC_READ_RETRIES,
                    delay.as_secs()
                );
                last = Some(err);
                std::thread::sleep(delay);
            }
        }
    }
    panic!("{what}: the endpoint failed {RPC_READ_RETRIES} consecutive reads: {last:?}");
}

/// Same bounded-retry discipline for read-only ADAPTER operations
/// (`observe`, `collect_evidence`, `verify`): each is an idempotent read
/// over already-finalized chain state, so retrying weakens no assertion.
/// The verifier's frozen mapping is untouched by this: a deterministic
/// disproof returns `Ok(Invalid)` on the first call and is never
/// retried; only the Err arm — chain corroboration unavailable, which
/// is exactly the transient class that killed gate run #3 — retries,
/// and an endpoint that stays down still fails the run.
fn retry_read<T, E: std::fmt::Debug>(what: &str, mut op: impl FnMut() -> Result<T, E>) -> T {
    let mut last = None;
    for attempt in 0..RPC_READ_RETRIES {
        match op() {
            Ok(v) => return v,
            Err(err) => {
                let delay = rpc_read_backoff(attempt);
                println!(
                    "  transient          {what} failed ({err:?}), retry {}/{} in {}s",
                    attempt + 1,
                    RPC_READ_RETRIES,
                    delay.as_secs()
                );
                last = Some(err);
                std::thread::sleep(delay);
            }
        }
    }
    panic!("{what}: failed {RPC_READ_RETRIES} consecutive attempts: {last:?}");
}

struct Chain {
    rpc: HttpJsonRpc,
}

impl Chain {
    fn new(e: &Env) -> Self {
        Self {
            rpc: HttpJsonRpc::new(e.rpc_url.clone(), 30),
        }
    }
    fn block_number(&self) -> u64 {
        parse_quantity(&rpc_read(&self.rpc, "head", "eth_blockNumber", json!([])))
            .expect("head number")
    }
    fn finalized(&self) -> u64 {
        // Inside the poll loop a failed read is just "no progress yet";
        // the loop's own bound is the retry discipline here.
        self.rpc
            .call("eth_getBlockByNumber", json!(["finalized", false]))
            .ok()
            .and_then(|v| v.get("number").and_then(parse_quantity))
            .unwrap_or(0)
    }
    fn timestamp(&self) -> u64 {
        let v = rpc_read(
            &self.rpc,
            "latest block",
            "eth_getBlockByNumber",
            json!(["latest", false]),
        );
        v.get("timestamp")
            .and_then(parse_quantity)
            .expect("timestamp")
    }
    /// Bounded wait for the `finalized` tag to pass `target`. Real
    /// Ethereum finality (~two epochs); every poll reports progress.
    fn wait_finalized(&self, target: u64) {
        for poll in 0..FINALITY_POLLS {
            let f = self.finalized();
            if f >= target {
                println!("  finalized          #{f} >= {target}");
                return;
            }
            println!(
                "  waiting            finalized #{f} < {target} \
                 ({}s of {}s)",
                poll * FINALITY_POLL_SECS,
                FINALITY_POLLS * FINALITY_POLL_SECS
            );
            std::thread::sleep(std::time::Duration::from_secs(FINALITY_POLL_SECS));
        }
        panic!(
            "block {target} did not finalize within the bounded wait. External \
             blocker (the network), not a defect; do not weaken the finality rule."
        );
    }
}

struct LiveClock {
    rpc: HttpJsonRpc,
}

impl BondClock for LiveClock {
    fn now_timestamp(&self) -> f4_harness::Result<u64> {
        let v = self
            .rpc
            .call("eth_getBlockByNumber", json!(["latest", false]))
            .map_err(BondError::Adapter)?;
        v.get("timestamp")
            .and_then(parse_quantity)
            .ok_or(BondError::Adapter(
                counterparty_api::AdapterError::AdapterUnavailable,
            ))
    }
}

/// `cast send` with the one funded key. The URL and the key are never
/// printed; receipts are.
fn cast_send(e: &Env, call: &UnsignedEvmCall) -> String {
    let value_dec = u128::from_be_bytes(call.value[16..].try_into().expect("16 bytes")).to_string();
    let out = Command::new(&e.cast)
        .args([
            "send",
            &hex0x(&call.to),
            "--rpc-url",
            &e.rpc_url,
            "--private-key",
            &e.key,
            "--value",
            &value_dec,
            "--json",
            &hex0x(&call.calldata),
        ])
        .output()
        .expect("cast send spawns");
    assert!(
        out.status.success(),
        "cast send failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("cast --json parses");
    let tx = v
        .get("transactionHash")
        .and_then(|h| h.as_str())
        .expect("transactionHash")
        .to_string();
    assert_eq!(
        v.get("status").and_then(|s| s.as_str()),
        Some("0x1"),
        "transaction {tx} reverted"
    );
    tx
}

/// One-account broadcaster with the I7 discipline.
struct SoloBroadcaster<'a> {
    e: &'a Env,
    seen: RefCell<BTreeSet<Vec<u8>>>,
    txs: RefCell<Vec<(&'static str, String)>>,
}

impl<'a> SoloBroadcaster<'a> {
    fn new(e: &'a Env) -> Self {
        Self {
            e,
            seen: RefCell::new(BTreeSet::new()),
            txs: RefCell::new(Vec::new()),
        }
    }
}

impl BondBroadcaster for &SoloBroadcaster<'_> {
    fn broadcast(&self, call: &UnsignedEvmCall) -> f4_harness::Result<BroadcastOutcome> {
        let bytes = call.encode();
        if !self.seen.borrow_mut().insert(bytes) {
            return Ok(BroadcastOutcome::Duplicate);
        }
        let sel: [u8; 4] = call.calldata[..4].try_into().expect("selector");
        let what = if sel == selector(SIG_OPEN) {
            "bond-open"
        } else if sel == selector(SIG_CLAIM) {
            "bond-slash"
        } else {
            "bond-refund"
        };
        let tx = cast_send(self.e, call);
        self.txs.borrow_mut().push((what, tx));
        Ok(BroadcastOutcome::Accepted)
    }
}

fn seed_word(seed: u16, tag: u8) -> [u8; 32] {
    let mut pre = [0u8; 8];
    pre[..2].copy_from_slice(&seed.to_be_bytes());
    pre[7] = tag;
    keccak256(&pre)
}

/// The one §12 scenario. Two finality waits; every other second is
/// machine work against the durable journal.
#[test]
fn sepolia_slash_compensates_without_any_privileged_action() {
    let Some(e) = env() else { return };
    let chain = Chain::new(&e);
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("assurance-sepolia.sqlite");

    // A fresh seed per dispatch: the lock ids must not collide with any
    // earlier run against the same deployment. Derived from the head
    // block — external state, not a clock the harness owns.
    let seed = (chain.block_number() % u64::from(u16::MAX)) as u16;
    let mut secret = seed_word(seed, 0xEE);
    secret[0] = 0;
    let now = chain.timestamp();

    let session_id = seed_word(seed, 0x01);
    let terms_hash = seed_word(seed, 0x02);
    let participants_hash = seed_word(seed, 0x03);
    let code_hash = {
        let rpc = HttpJsonRpc::new(e.rpc_url.clone(), 30);
        let code = rpc
            .call("eth_getCode", json!([hex0x(&e.contract), "latest"]))
            .expect("eth_getCode");
        let bytes: Vec<u8> = code
            .as_str()
            .and_then(|s| {
                let h = s.strip_prefix("0x")?;
                (0..h.len() / 2)
                    .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok())
                    .collect()
            })
            .expect("deployed code");
        keccak256(&bytes)
    };

    let settlement_terms = LockTerms {
        dom_chain_id: seed_word(seed, 0x04),
        direction: Direction::EvmToDom.as_u8(),
        session_id,
        terms_hash,
        participants_hash,
        asset: [0u8; 20],
        amount: amount_word(SETTLEMENT_AMOUNT),
        beneficiary: e.account,
        adaptor_address: adaptor_address_of_scalar(&secret).expect("canonical"),
        deadline: now + 14_400,
    };
    let settlement_binding =
        derive_binding(SEPOLIA_CHAIN_ID, &e.contract, &settlement_terms).expect("binding");
    let settlement_lock_id = derive_lock_id(&settlement_binding, &e.account).expect("lock id");
    let settlement_cfg = EvmAdapterConfig {
        chain_id: SEPOLIA_CHAIN_ID,
        contract: e.contract,
        expected_code_hash: code_hash,
        dom_chain_id: settlement_terms.dom_chain_id,
        direction: Direction::EvmToDom,
        session_id,
        terms_hash,
        participants_hash,
        asset: [0u8; 20],
        beneficiary: e.account,
        funder: e.account,
        start_block: chain.finalized().saturating_sub(64),
        // 8, not 512: hosted Sepolia endpoints cap eth_getLogs ranges
        // (gate runs #3-#5 all died INSTANTLY at the first observe —
        // an error response, not a timeout — while every small read
        // succeeded; the F3 harness observed fine on this endpoint
        // with 8-block pages, and Anvil masks the cap entirely).
        // Small pages also keep the validated-header ring dense, which
        // is strictly better for reorg reconciliation — the same
        // rationale the F3 config records.
        page_size: 8,
        max_reorg_depth: 96,
        gas_limit_hint: 300_000,
    };

    let policy = AssurancePolicyV1 {
        policy_id: PolicyId(seed_word(seed, 0x10)),
        version: POLICY_STRUCT_VERSION,
        protected_settlement: SettlementId(session_id),
        terms_hash,
        bond_chain_id: ChainId(seed_word(seed, 0x11)),
        bond_asset: AssetId([0u8; 32]),
        required_collateral: COLLATERAL,
        compensation_cap: CAP,
        // Sized so the slash margin dwarfs two worst-case finality waits.
        collateral_deadline: TimelockSpec::TimestampSeconds { value: now + 3_600 },
        claim_deadline: TimelockSpec::TimestampSeconds { value: now + 5_400 },
        evidence_deadline: TimelockSpec::TimestampSeconds { value: now + 7_200 },
        bond_release_deadline: TimelockSpec::TimestampSeconds {
            value: now + 10_800,
        },
        evidence_rule: EvidenceRuleV1::RevealedScalarClaim {
            adaptor_point: AdaptorPointBytes(adaptor_point_of_scalar(&secret).expect("canonical")),
        },
        terminal_policy: TerminalPolicyV1::ConservativeRelease,
    };
    let deployment = BondDeployment {
        chain_id: SEPOLIA_CHAIN_ID,
        contract: e.contract,
        expected_code_hash: code_hash,
        dom_chain_id: settlement_terms.dom_chain_id,
        direction: Direction::EvmToDom,
        participants_hash,
        asset: [0u8; 20],
        funder: e.account,
        beneficiary: e.account,
        start_block: settlement_cfg.start_block,
        // 8, not 512: hosted Sepolia endpoints cap eth_getLogs ranges
        // (gate runs #3-#5 all died INSTANTLY at the first observe —
        // an error response, not a timeout — while every small read
        // succeeded; the F3 harness observed fine on this endpoint
        // with 8-block pages, and Anvil masks the cap entirely).
        // Small pages also keep the validated-header ring dense, which
        // is strictly better for reorg reconciliation — the same
        // rationale the F3 config records.
        page_size: 8,
        max_reorg_depth: 96,
        gas_limit_hint: 300_000,
    };

    let recover = || {
        DurableAssurance::open(
            StoreLog::open(&db).expect("open store"),
            terms_hash,
            CAP,
            true,
        )
        .expect("recover from the file alone")
    };

    // -- every setup transaction FIRST, then one finality wait ----------
    println!("== transactions ==");
    let broadcaster = SoloBroadcaster::new(&e);
    let mut bond = EvmBondAdapter::new(
        &policy,
        deployment,
        HttpJsonRpc::new(e.rpc_url.clone(), 30),
        &broadcaster,
        LiveClock {
            rpc: HttpJsonRpc::new(e.rpc_url.clone(), 30),
        },
    )
    .expect("bond adapter");
    bond.submit_bond(&policy).expect("bond open");

    let settlement_open = UnsignedEvmCall {
        version: UNSIGNED_CALL_VERSION,
        chain_id: SEPOLIA_CHAIN_ID,
        to: e.contract,
        value: amount_word(SETTLEMENT_AMOUNT),
        gas_limit_hint: 300_000,
        lock_id: settlement_lock_id,
        binding: settlement_binding,
        calldata: encode_open_calldata(&settlement_terms).expect("open calldata"),
    };
    let settlement_open_tx = cast_send(&e, &settlement_open);
    println!("  settlement open    {settlement_open_tx}");

    let mut claim_calldata = Vec::with_capacity(4 + 64);
    claim_calldata.extend_from_slice(&selector(SIG_CLAIM));
    claim_calldata.extend_from_slice(&word_bytes32(settlement_lock_id));
    claim_calldata.extend_from_slice(&word_u256(secret));
    let settlement_claim = UnsignedEvmCall {
        version: UNSIGNED_CALL_VERSION,
        chain_id: SEPOLIA_CHAIN_ID,
        to: e.contract,
        value: [0u8; 32],
        gas_limit_hint: 300_000,
        lock_id: settlement_lock_id,
        binding: settlement_binding,
        calldata: claim_calldata,
    };
    let settlement_claim_tx = cast_send(&e, &settlement_claim);
    println!("  settlement claim   {settlement_claim_tx} (t is now public)");

    let head = chain.block_number();
    println!("== finality wait 1/2 (bond open + settlement claim) ==");
    chain.wait_finalized(head);

    // Scan-window diagnostic, printed into the gate evidence BEFORE the
    // first observe: a range-capped endpoint answers the single-block
    // probe and errors the window probe; a genuinely unavailable one
    // fails both. Gate runs #3-#5 died at this exact spot with the
    // cause swallowed into AdapterUnavailable — never again.
    {
        let finalized_now = chain.finalized();
        let from = deployment.start_block;
        for (label, a, b) in [
            ("single-block", from, from),
            ("full-window", from, finalized_now),
        ] {
            let outcome = chain.rpc.call(
                "eth_getLogs",
                json!([{
                    "fromBlock": format!("{a:#x}"),
                    "toBlock": format!("{b:#x}"),
                    "address": hex0x(&e.contract),
                }]),
            );
            match outcome {
                Ok(v) => println!(
                    "  probe              eth_getLogs {label} [{a},{b}]: ok, {} logs",
                    v.as_array().map_or(0, |l| l.len())
                ),
                Err(err) => {
                    println!("  probe              eth_getLogs {label} [{a},{b}]: ERR {err:?}")
                }
            }
        }
    }

    // -- the machine walks the failure, crash-recovering throughout -----
    let seen = {
        let mut cursor = ChainCursor::default();
        let mut all = Vec::new();
        loop {
            let obs = retry_read("bond.observe", || bond.observe(&cursor));
            let done = obs.events.is_empty();
            all.extend(obs.events);
            cursor = obs.cursor;
            if done {
                break all;
            }
        }
    };
    assert!(
        seen.iter()
            .any(|ev| matches!(ev, BondEvent::CollateralLocked { .. })),
        "the finalized chain shows the bond lock"
    );
    recover()
        .apply(&AssuranceEvent::BondLockObserved)
        .expect("BondLockObserved");
    recover()
        .apply(&AssuranceEvent::CollateralVerified { terms_hash })
        .expect("CollateralVerified");
    recover()
        .apply(&AssuranceEvent::ObligationFailed)
        .expect("ObligationFailed");
    recover()
        .apply(&AssuranceEvent::CompensationClaimed { terms_hash })
        .expect("CompensationClaimed");

    let evidence = {
        let adapter = EvmAdapter::new(settlement_cfg, HttpJsonRpc::new(e.rpc_url.clone(), 30))
            .expect("settlement adapter");
        adapter
            .track_lock(&settlement_terms)
            .expect("track settlement lock");
        retry_read("collect_evidence(Claimed)", || {
            adapter.collect_evidence(&settlement_lock_id, EvidenceKind::Claimed)
        })
        .encode()
    };
    let verifier = RevealedScalarVerifier::new(
        &policy,
        settlement_cfg,
        HttpJsonRpc::new(e.rpc_url.clone(), 30),
    )
    .expect("verifier");
    // `verify` errors ONLY on chain-corroboration failure (the frozen
    // mapping: deterministic disproofs are verdicts, never errors), so
    // the retry re-asks an unavailable endpoint and cannot flip any
    // verdict.
    let verify_now = TimelockSpec::TimestampSeconds {
        value: chain.timestamp(),
    };
    let revealed = match retry_read("verifier.verify", || {
        verifier.verify(&policy, &evidence, verify_now)
    }) {
        EvidenceVerdict::Valid { revealed, .. } => {
            assert_eq!(
                revealed.expose_scalar_bytes(),
                secret,
                "Sepolia revealed exactly t"
            );
            revealed
        }
        other => panic!("the real claim must verify, got {other:?}"),
    };
    {
        let mut driver = recover();
        let t = driver
            .apply(&AssuranceEvent::EvidenceVerified { valid: true })
            .expect("EvidenceVerified");
        assert!(t.effects.contains(&AssuranceEffect::ExecuteSlash));
    }

    // -- the slash, then the second finality wait -----------------------
    let lock_id = bond.bond_lock_id();
    assert_eq!(
        bond.submit_slash(&lock_id, &revealed).expect("slash"),
        BroadcastOutcome::Accepted
    );
    let head = chain.block_number();
    println!("== finality wait 2/2 (the slash) ==");
    chain.wait_finalized(head);

    let seen = {
        let mut cursor = ChainCursor::default();
        let mut all = Vec::new();
        loop {
            let obs = retry_read("bond.observe", || bond.observe(&cursor));
            let done = obs.events.is_empty();
            all.extend(obs.events);
            cursor = obs.cursor;
            if done {
                break all;
            }
        }
    };
    let republished = seen.iter().find_map(|ev| match ev {
        BondEvent::BondClaimed { revealed, .. } => Some(revealed.expose_scalar_bytes()),
        _ => None,
    });
    assert_eq!(
        republished,
        Some(secret),
        "the finalized slash republished t"
    );

    let terminal = {
        let mut driver = recover();
        driver
            .apply(&AssuranceEvent::CompensationConfirmed { amount: COLLATERAL })
            .expect("CompensationConfirmed")
            .next
            .state
    };
    assert_eq!(terminal, AssuranceState::Compensated);
    assert_eq!(recover().context().state, AssuranceState::Compensated);

    // -- evidence record -------------------------------------------------
    let txs = broadcaster.txs.borrow().clone();
    let bond_open_tx = txs
        .iter()
        .find(|(w, _)| *w == "bond-open")
        .expect("bond open tx")
        .1
        .clone();
    let bond_slash_tx = txs
        .iter()
        .find(|(w, _)| *w == "bond-slash")
        .expect("slash tx")
        .1
        .clone();
    std::fs::create_dir_all(&e.evidence_dir).expect("evidence dir");
    let record = json!({
        "gate": "G-F4",
        "scenario": "sepolia_slash_compensates_without_any_privileged_action",
        "chainId": SEPOLIA_CHAIN_ID,
        "contract": hex0x(&e.contract),
        "bondLockId": hex0x(&lock_id),
        "settlementLockId": hex0x(&settlement_lock_id),
        "transactions": {
            "bondOpen": bond_open_tx,
            "settlementOpen": settlement_open_tx,
            "settlementClaim": settlement_claim_tx,
            "bondSlash": bond_slash_tx,
        },
        "terminal": "Compensated",
        "journalRevisions": 6,
        "privilegedActions": 0,
    });
    let path = e.evidence_dir.join("f4-slash-evidence.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&record).expect("json"))
        .expect("write evidence");

    println!("== G-F4 Sepolia slash ==");
    println!("  bond open          {bond_open_tx}");
    println!("  settlement open    {settlement_open_tx}");
    println!("  settlement claim   {settlement_claim_tx}");
    println!("  bond slash         {bond_slash_tx}");
    println!("  terminal           Compensated");
    println!("  evidence           {}", path.display());
}
