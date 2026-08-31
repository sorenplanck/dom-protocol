//! F4 spec §11 adversarial suite + the §12 Anvil half, on a REAL node.
//!
//! Same environment contract as the F3 suite: `./scripts/e2e_anvil.sh`
//! starts Anvil, deploys the audited `ConditionLockV2` and exports the
//! `F3_ANVIL_*` variables (one deployment serves both phases — the bond
//! IS a `ConditionLockV2` lock, D-F4.3). Without the environment every
//! test prints the NOTHING-VERIFIED marker and the wrapper script fails
//! the run; a skip is never a pass.
//!
//! Roles are three DISTINCT accounts, which is what lets this suite
//! prove I12 mechanically:
//! - the SOLVER (env account) posts the collateral;
//! - the PROTECTED PARTY (Anvil dev account #1) executes the slash —
//!   the only address the contract lets claim;
//! - a THIRD PARTY (Anvil dev account #2) executes the release — anyone
//!   may, the destination is always the funder.
//!
//! The dev keys are the universal, public Anvil development keys; they
//! sign in a separate `cast` process, never inside the harness.
//!
//! This suite drives a development node ONLY (chain id 31337): the
//! role-splitting depends on the public dev accounts. The §12 slash on
//! Sepolia has its own workflow.

#![cfg(feature = "rpc-http")]

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::process::Command;

use adapter_evm::abi::{
    event_topic0, keccak256, selector, word_bytes32, word_u256, SIG_CLAIM, SIG_LOCK_OPENED,
    SIG_OPEN,
};
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
const DEV_CHAIN_ID: u64 = 31337;
const FINALITY_BLOCKS: u64 = 70;
const COLLATERAL: u128 = 1_000_000_000_000_000; // 0.001 ether
const CAP: u128 = 2_000_000_000_000_000;
const SETTLEMENT_AMOUNT: u128 = 500_000_000_000_000;

/// Anvil development account #1: the protected party (bond beneficiary).
const BENEFICIARY: [u8; 20] = [
    0x70, 0x99, 0x79, 0x70, 0xC5, 0x18, 0x12, 0xdc, 0x3A, 0x01, 0x0C, 0x7d, 0x01, 0xb5, 0x0e, 0x0d,
    0x17, 0xdc, 0x79, 0xC8,
];
const BENEFICIARY_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
/// Anvil development account #2: the uninvolved third party.
const THIRD_PARTY_KEY: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

struct Env {
    rpc_url: String,
    cast: String,
    contract: [u8; 20],
    account: [u8; 20],
    key: String,
}

fn env() -> Option<Env> {
    let Ok(rpc_url) = std::env::var("F3_ANVIL_RPC") else {
        println!(
            "\n============================================================\n\
             {NOTHING_VERIFIED}\n\
             F3_ANVIL_RPC is not set, so no F4 Anvil scenario ran.\n\
             Run ./scripts/e2e_anvil.sh, which exports the environment.\n\
             ============================================================\n"
        );
        return None;
    };
    let contract = parse_address(&std::env::var("F3_ANVIL_LOCK").expect("F3_ANVIL_LOCK"))
        .expect("F3_ANVIL_LOCK is an address");
    let account = parse_address(&std::env::var("F3_ANVIL_ACCOUNT").expect("F3_ANVIL_ACCOUNT"))
        .expect("F3_ANVIL_ACCOUNT is an address");
    let key = std::env::var("F3_ANVIL_KEY").expect("F3_ANVIL_KEY");
    let cast = std::env::var("F3_CAST").unwrap_or_else(|_| "cast".to_string());
    let e = Env {
        rpc_url,
        cast,
        contract,
        account,
        key,
    };
    // Dev node only: the role-splitting uses the public dev accounts.
    let rpc = HttpJsonRpc::new(e.rpc_url.clone(), 20);
    let id = rpc
        .call("eth_chainId", json!([]))
        .ok()
        .and_then(|v| parse_quantity(&v))
        .expect("eth_chainId");
    assert_eq!(
        id, DEV_CHAIN_ID,
        "the F4 adversarial suite drives a local Anvil only; the Sepolia slash \
         has its own workflow"
    );
    Some(e)
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

// ---------------------------------------------------------------------------
// chain control (dev-node cheat methods)
// ---------------------------------------------------------------------------

struct Anvil {
    rpc: HttpJsonRpc,
}

impl Anvil {
    fn new(e: &Env) -> Self {
        Self {
            rpc: HttpJsonRpc::new(e.rpc_url.clone(), 20),
        }
    }
    fn mine(&self, n: u64) {
        self.rpc
            .call("anvil_mine", json!([format!("0x{n:x}")]))
            .expect("anvil_mine");
    }
    fn advance_to_finality(&self) {
        self.mine(FINALITY_BLOCKS);
    }
    fn timestamp(&self) -> u64 {
        let v = self
            .rpc
            .call("eth_getBlockByNumber", json!(["latest", false]))
            .expect("latest block");
        v.get("timestamp")
            .and_then(parse_quantity)
            .expect("timestamp")
    }
    fn warp_past(&self, deadline: u64) {
        let now = self.timestamp();
        if now <= deadline {
            self.rpc
                .call("evm_increaseTime", json!([deadline - now + 2]))
                .expect("evm_increaseTime");
        }
        self.mine(1);
    }
    fn snapshot(&self) -> Value {
        self.rpc.call("evm_snapshot", json!([])).expect("snapshot")
    }
    fn revert(&self, snap: &Value) {
        let ok = self.rpc.call("evm_revert", json!([snap])).expect("revert");
        assert_eq!(ok, json!(true), "evm_revert refused the snapshot");
    }
}

/// The bond chain's clock is the chain's own clock.
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

// ---------------------------------------------------------------------------
// the signing boundary: `cast send`, one key per ROLE
// ---------------------------------------------------------------------------

fn cast_send(e: &Env, key: &str, call: &UnsignedEvmCall, expect_success: bool) -> Option<String> {
    let value_dec = u128::from_be_bytes(call.value[16..].try_into().expect("16 bytes")).to_string();
    let out = Command::new(&e.cast)
        .args([
            "send",
            &hex0x(&call.to),
            "--rpc-url",
            &e.rpc_url,
            "--private-key",
            key,
            "--value",
            &value_dec,
            "--json",
            &hex0x(&call.calldata),
        ])
        .output()
        .expect("cast send spawns");
    if !expect_success {
        assert!(
            !out.status.success(),
            "a transaction that must revert was accepted: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        return None;
    }
    assert!(
        out.status.success(),
        "cast send failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("cast --json output parses");
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
    Some(tx)
}

/// Routes each artifact to the key of the actor who would really send it:
/// `open` = the solver, `claim` = the protected party, `refund` = the
/// third party. Byte-identical resend is deduped (I7); divergent bytes
/// for the same intent would be equivocation and panic.
type IntentMap = std::collections::BTreeMap<(u8, [u8; 32]), Vec<u8>>;

struct RoleBroadcaster<'a> {
    e: &'a Env,
    seen: RefCell<BTreeSet<Vec<u8>>>,
    intents: RefCell<IntentMap>,
    txs: RefCell<Vec<(&'static str, String)>>,
}

impl<'a> RoleBroadcaster<'a> {
    fn new(e: &'a Env) -> Self {
        Self {
            e,
            seen: RefCell::new(BTreeSet::new()),
            intents: RefCell::new(std::collections::BTreeMap::new()),
            txs: RefCell::new(Vec::new()),
        }
    }
    fn txs(&self) -> Vec<(&'static str, String)> {
        self.txs.borrow().clone()
    }
}

impl BondBroadcaster for &RoleBroadcaster<'_> {
    fn broadcast(&self, call: &UnsignedEvmCall) -> f4_harness::Result<BroadcastOutcome> {
        let sel: [u8; 4] = call.calldata[..4].try_into().expect("selector");
        let (role, key, tag) = if sel == selector(SIG_OPEN) {
            ("open", self.e.key.as_str(), 1u8)
        } else if sel == selector(SIG_CLAIM) {
            ("slash", BENEFICIARY_KEY, 2)
        } else {
            ("release", THIRD_PARTY_KEY, 3)
        };
        let bytes = call.encode();
        // I7: the same intent must always produce the same bytes.
        let mut intents = self.intents.borrow_mut();
        if let Some(previous) = intents.get(&(tag, call.lock_id)) {
            assert_eq!(
                previous, &bytes,
                "EQUIVOCATION: one intent produced two different artifacts"
            );
        } else {
            intents.insert((tag, call.lock_id), bytes.clone());
        }
        if !self.seen.borrow_mut().insert(bytes) {
            return Ok(BroadcastOutcome::Duplicate);
        }
        let tx = cast_send(self.e, key, call, true).expect("accepted");
        self.txs.borrow_mut().push((role, tx));
        Ok(BroadcastOutcome::Accepted)
    }
}

// ---------------------------------------------------------------------------
// fixtures: one settlement lock (whose claim reveals t), one bond lock
// ---------------------------------------------------------------------------

fn seed_word(seed: u16, tag: u8) -> [u8; 32] {
    let mut pre = [0u8; 8];
    pre[..2].copy_from_slice(&seed.to_be_bytes());
    pre[7] = tag;
    keccak256(&pre)
}

fn scalar(seed: u16) -> [u8; 32] {
    let mut t = seed_word(seed, 0xEE);
    t[0] = 0; // comfortably below the group order
    t
}

struct Rig {
    policy: AssurancePolicyV1,
    deployment: BondDeployment,
    settlement_terms: LockTerms,
    settlement_lock_id: [u8; 32],
    settlement_binding: [u8; 32],
    settlement_cfg: EvmAdapterConfig,
    secret: [u8; 32],
    db: std::path::PathBuf,
}

fn code_hash_of(e: &Env) -> [u8; 32] {
    let rpc = HttpJsonRpc::new(e.rpc_url.clone(), 20);
    let code = rpc
        .call("eth_getCode", json!([hex0x(&e.contract), "latest"]))
        .expect("eth_getCode");
    let bytes = code.as_str().and_then(|s| {
        let h = s.strip_prefix("0x")?;
        (0..h.len() / 2)
            .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok())
            .collect::<Option<Vec<u8>>>()
    });
    keccak256(&bytes.expect("deployed code"))
}

fn rig(e: &Env, seed: u16, dir: &tempfile::TempDir) -> Rig {
    let anvil = Anvil::new(e);
    let now = anvil.timestamp();
    let code_hash = code_hash_of(e);
    let secret = scalar(seed);

    // The SETTLEMENT leg: the lock whose claim by the counterparty
    // reveals t. Its own session identity, funded by the env account.
    let session_id = seed_word(seed, 0x01);
    let terms_hash = seed_word(seed, 0x02);
    let participants_hash = seed_word(seed, 0x03);
    let settlement_terms = LockTerms {
        dom_chain_id: seed_word(seed, 0x04),
        direction: Direction::EvmToDom.as_u8(),
        session_id,
        terms_hash,
        participants_hash,
        asset: [0u8; 20],
        amount: amount_word(SETTLEMENT_AMOUNT),
        beneficiary: e.account, // the counterparty being paid on this leg
        adaptor_address: adaptor_address_of_scalar(&secret).expect("canonical"),
        deadline: now + 86_400,
    };
    let settlement_binding =
        derive_binding(DEV_CHAIN_ID, &e.contract, &settlement_terms).expect("binding");
    let settlement_lock_id = derive_lock_id(&settlement_binding, &e.account).expect("lock id");
    let settlement_cfg = EvmAdapterConfig {
        chain_id: DEV_CHAIN_ID,
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
        start_block: 0,
        page_size: 512,
        max_reorg_depth: 64,
        gas_limit_hint: 300_000,
    };

    // The BOND: deadlines from the node's own clock, wide slash margin.
    let policy = AssurancePolicyV1 {
        policy_id: PolicyId(seed_word(seed, 0x10)),
        version: POLICY_STRUCT_VERSION,
        protected_settlement: SettlementId(session_id),
        terms_hash,
        bond_chain_id: ChainId(seed_word(seed, 0x11)),
        bond_asset: AssetId([0u8; 32]),
        required_collateral: COLLATERAL,
        compensation_cap: CAP,
        collateral_deadline: TimelockSpec::TimestampSeconds { value: now + 600 },
        claim_deadline: TimelockSpec::TimestampSeconds { value: now + 1_200 },
        evidence_deadline: TimelockSpec::TimestampSeconds { value: now + 1_800 },
        bond_release_deadline: TimelockSpec::TimestampSeconds { value: now + 3_600 },
        evidence_rule: EvidenceRuleV1::RevealedScalarClaim {
            adaptor_point: AdaptorPointBytes(adaptor_point_of_scalar(&secret).expect("canonical")),
        },
        terminal_policy: TerminalPolicyV1::ConservativeRelease,
    };
    let deployment = BondDeployment {
        chain_id: DEV_CHAIN_ID,
        contract: e.contract,
        expected_code_hash: code_hash,
        dom_chain_id: settlement_terms.dom_chain_id,
        direction: Direction::EvmToDom,
        participants_hash,
        asset: [0u8; 20],
        funder: e.account,
        beneficiary: BENEFICIARY,
        start_block: 0,
        page_size: 512,
        max_reorg_depth: 64,
        gas_limit_hint: 300_000,
    };
    Rig {
        policy,
        deployment,
        settlement_terms,
        settlement_lock_id,
        settlement_binding,
        settlement_cfg,
        secret,
        db: dir.path().join(format!("assurance-{seed}.sqlite")),
    }
}

impl Rig {
    fn bond<'a>(
        &self,
        e: &Env,
        broadcaster: &'a RoleBroadcaster<'a>,
    ) -> EvmBondAdapter<HttpJsonRpc, &'a RoleBroadcaster<'a>, LiveClock> {
        EvmBondAdapter::new(
            &self.policy,
            self.deployment,
            HttpJsonRpc::new(e.rpc_url.clone(), 20),
            broadcaster,
            LiveClock {
                rpc: HttpJsonRpc::new(e.rpc_url.clone(), 20),
            },
        )
        .expect("valid policy and deployment")
    }

    /// A fresh driver from the SQLite file alone: the crash boundary.
    fn recover(&self) -> DurableAssurance<StoreLog> {
        DurableAssurance::open(
            StoreLog::open(&self.db).expect("open store"),
            self.policy.terms_hash,
            self.policy.compensation_cap,
            true,
        )
        .expect("recover from the file alone")
    }

    /// Opens the settlement lock and claims it with the secret: the
    /// counterparty's own on-chain act that publishes t.
    fn counterparty_claims_settlement(&self, e: &Env) -> String {
        let open = UnsignedEvmCall {
            version: UNSIGNED_CALL_VERSION,
            chain_id: DEV_CHAIN_ID,
            to: e.contract,
            value: amount_word(SETTLEMENT_AMOUNT),
            gas_limit_hint: 300_000,
            lock_id: self.settlement_lock_id,
            binding: self.settlement_binding,
            calldata: encode_open_calldata(&self.settlement_terms).expect("open calldata"),
        };
        cast_send(e, &e.key, &open, true).expect("settlement open");
        Anvil::new(e).mine(1);
        let mut calldata = Vec::with_capacity(4 + 64);
        calldata.extend_from_slice(&selector(SIG_CLAIM));
        calldata.extend_from_slice(&word_bytes32(self.settlement_lock_id));
        calldata.extend_from_slice(&word_u256(self.secret));
        let claim = UnsignedEvmCall {
            version: UNSIGNED_CALL_VERSION,
            chain_id: DEV_CHAIN_ID,
            to: e.contract,
            value: [0u8; 32],
            gas_limit_hint: 300_000,
            lock_id: self.settlement_lock_id,
            binding: self.settlement_binding,
            calldata,
        };
        // The settlement beneficiary is the env account.
        cast_send(e, &e.key, &claim, true).expect("settlement claim reveals t")
    }

    fn settlement_evidence(&self, e: &Env) -> Vec<u8> {
        let adapter = EvmAdapter::new(self.settlement_cfg, HttpJsonRpc::new(e.rpc_url.clone(), 20))
            .expect("settlement adapter");
        adapter
            .track_lock(&self.settlement_terms)
            .expect("track settlement lock");
        adapter
            .collect_evidence(&self.settlement_lock_id, EvidenceKind::Claimed)
            .expect("claimed evidence")
            .encode()
    }

    fn bond_funded_is_real(&self, e: &Env, bond_lock_id: &[u8; 32]) {
        // Collateral verification: the bond's own LockOpened, attested by
        // the adapter up to finality.
        let broadcaster = RoleBroadcaster::new(e);
        let bond = self.bond(e, &broadcaster);
        let evidence = bond
            .chain_adapter()
            .collect_evidence(bond_lock_id, EvidenceKind::Funded)
            .expect("bond funded evidence");
        let outcome = bond
            .chain_adapter()
            .verify_evidence_blocking(&evidence.encode())
            .expect("bond funding verifies");
        assert!(matches!(
            outcome,
            counterparty_api::VerifiedOutcome::Funded { .. }
        ));
    }
}

fn observe_all(
    bond: &mut EvmBondAdapter<HttpJsonRpc, &RoleBroadcaster<'_>, LiveClock>,
) -> Vec<BondEvent> {
    let mut cursor = ChainCursor::default();
    let mut out = Vec::new();
    loop {
        let obs = bond.observe(&cursor).expect("observe");
        let done = obs.events.is_empty();
        out.extend(obs.events);
        cursor = obs.cursor;
        if done {
            return out;
        }
    }
}

// ---------------------------------------------------------------------------
// scenarios
// ---------------------------------------------------------------------------

/// §11 core + §12 item 3's Anvil rehearsal: the full slash path with a
/// process crash between EVERY machine transition, on the real contract,
/// with the real store, ending in a real compensation the protected
/// party executed with the publicly revealed scalar.
#[test]
fn anvil_slash_path_survives_a_crash_at_every_transition() {
    let Some(e) = env() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rig(&e, 0x41, &dir);
    let anvil = Anvil::new(&e);
    let terms = r.policy.terms_hash;

    // -- open the bond (solver), then crash --
    {
        let broadcaster = RoleBroadcaster::new(&e);
        let mut bond = r.bond(&e, &broadcaster);
        assert_eq!(
            bond.submit_bond(&r.policy).expect("bond open"),
            BroadcastOutcome::Accepted
        );
        anvil.advance_to_finality();
        let seen = observe_all(&mut bond);
        assert!(seen
            .iter()
            .any(|ev| matches!(ev, BondEvent::CollateralLocked { .. })));
        let mut driver = r.recover();
        driver
            .apply(&AssuranceEvent::BondLockObserved)
            .expect("BondLockObserved");
    }

    // -- verify the collateral (adapter attestation), then crash --
    {
        let broadcaster = RoleBroadcaster::new(&e);
        let bond = r.bond(&e, &broadcaster);
        r.bond_funded_is_real(&e, &bond.bond_lock_id());
        let mut driver = r.recover();
        let t = driver
            .apply(&AssuranceEvent::CollateralVerified { terms_hash: terms })
            .expect("CollateralVerified");
        assert!(t
            .effects
            .iter()
            .any(|x| matches!(x, AssuranceEffect::IssueCertificate { .. })));
    }

    // -- the counterparty claims the settlement leg, revealing t --
    let settlement_claim_tx = r.counterparty_claims_settlement(&e);
    anvil.advance_to_finality();

    // -- the obligation failed; the protected party claims; crash each --
    {
        let mut driver = r.recover();
        driver
            .apply(&AssuranceEvent::ObligationFailed)
            .expect("ObligationFailed");
    }
    {
        let mut driver = r.recover();
        driver
            .apply(&AssuranceEvent::CompensationClaimed { terms_hash: terms })
            .expect("CompensationClaimed");
    }

    // -- the evidence: the REAL claim, verified end to end --
    let revealed = {
        let verifier = RevealedScalarVerifier::new(
            &r.policy,
            r.settlement_cfg,
            HttpJsonRpc::new(e.rpc_url.clone(), 20),
        )
        .expect("verifier");
        let now = TimelockSpec::TimestampSeconds {
            value: anvil.timestamp(),
        };
        match verifier
            .verify(&r.policy, &r.settlement_evidence(&e), now)
            .expect("decidable")
        {
            EvidenceVerdict::Valid { revealed, .. } => {
                assert_eq!(
                    revealed.expose_scalar_bytes(),
                    r.secret,
                    "the chain revealed exactly t"
                );
                revealed
            }
            other => panic!("the real claim must verify, got {other:?}"),
        }
    };
    {
        let mut driver = r.recover();
        let t = driver
            .apply(&AssuranceEvent::EvidenceVerified { valid: true })
            .expect("EvidenceVerified");
        assert!(t.effects.contains(&AssuranceEffect::ExecuteSlash));
        assert_eq!(t.next.state, AssuranceState::Slashed);
    }

    // -- the slash: the protected party spends the bond with t --
    let slash_tx = {
        let broadcaster = RoleBroadcaster::new(&e);
        let mut bond = r.bond(&e, &broadcaster);
        let lock_id = bond.bond_lock_id();
        assert_eq!(
            bond.submit_slash(&lock_id, &revealed).expect("slash"),
            BroadcastOutcome::Accepted
        );
        // Byte-identical resend after a simulated redelivery: deduped.
        assert_eq!(
            bond.submit_slash(&lock_id, &revealed).expect("resend"),
            BroadcastOutcome::Duplicate
        );
        anvil.advance_to_finality();
        let seen = observe_all(&mut bond);
        let claimed = seen.iter().find_map(|ev| match ev {
            BondEvent::BondClaimed { revealed, .. } => Some(revealed.expose_scalar_bytes()),
            _ => None,
        });
        assert_eq!(claimed, Some(r.secret), "the bond claim republished t");
        broadcaster
            .txs()
            .into_iter()
            .find(|(role, _)| *role == "slash")
            .expect("slash tx recorded")
            .1
    };

    // -- confirmation: terminal Compensated, cap respected --
    {
        let mut driver = r.recover();
        let over = driver.apply(&AssuranceEvent::CompensationConfirmed { amount: CAP + 1 });
        assert!(over.is_err(), "over-cap confirmation must refuse");
        let t = driver
            .apply(&AssuranceEvent::CompensationConfirmed { amount: COLLATERAL })
            .expect("CompensationConfirmed");
        assert_eq!(t.next.state, AssuranceState::Compensated);
    }
    let driver = r.recover();
    assert_eq!(driver.context().state, AssuranceState::Compensated);
    assert_eq!(driver.revision(), 6);

    // -- late evidence after the terminal: refused, nothing journaled --
    {
        let mut driver = r.recover();
        assert!(driver
            .apply(&AssuranceEvent::EvidenceVerified { valid: true })
            .is_err());
        assert_eq!(driver.revision(), 6);
    }

    // -- secret scan: neither t nor any signing key in the durable log --
    let db_bytes = {
        let mut all = Vec::new();
        for suffix in ["", "-wal", "-shm"] {
            if let Ok(mut c) = std::fs::read(format!("{}{suffix}", r.db.display())) {
                all.append(&mut c);
            }
        }
        all
    };
    let contains = |hay: &[u8], needle: &[u8]| {
        !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
    };
    assert!(
        !contains(&db_bytes, &r.secret),
        "the journal must not carry the scalar"
    );
    for key_hex in [e.key.as_str(), BENEFICIARY_KEY, THIRD_PARTY_KEY] {
        let raw: Vec<u8> = {
            let h = key_hex.strip_prefix("0x").unwrap_or(key_hex);
            (0..h.len() / 2)
                .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).expect("hex"))
                .collect()
        };
        assert!(
            !contains(&db_bytes, &raw),
            "a signing key leaked into the journal"
        );
    }

    println!("  settlement claim   {settlement_claim_tx}");
    println!("  bond slash         {slash_tx}");
    println!("  terminal           Compensated (revision 6, crash between every transition)");
}

/// §12.4, literally, on the REAL deployed contract (D-024 completion):
/// cap and binding refusals exercised against the live `ConditionLockV2`
/// — and proven to TOUCH NOTHING.
///
/// The eight ratified checks, in order:
///  1. `required_collateral > compensation_cap` is refused BEFORE any
///     broadcast (at adapter construction — no transaction is built);
///  2. the refusal produces ZERO transactions and no `LockOpened`;
///  3. collateral/certificate with a divergent `terms_hash` is refused
///     BY NAME (`TermsMismatch`, at the verifier binding and at the
///     machine);
///  4. evidence/claim bound to other terms produces NO `ExecuteSlash`;
///  5. no refusal modifies the journal (revision unchanged, re-proved
///     from the file alone);
///  6. no refusal modifies the contract state (nonce, code, log count
///     and balance all unchanged across every refusal);
///  7. wrong scalar still reverts on chain — proven by its own test,
///     `anvil_wrong_scalar_slash_reverts_on_chain`, in this same run;
///  8. correct cap and binding still allow the positive path — the same
///     rig that refused everything above then opens the bond for real.
///
/// The manifest lines this test prints (`manifest:` prefix) are
/// collected by `scripts/e2e_anvil.sh` into the run's manifest file.
#[test]
fn anvil_cap_and_binding_refusals_touch_nothing() {
    let Some(e) = env() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rig(&e, 0x51, &dir);
    let anvil = Anvil::new(&e);
    let rpc = HttpJsonRpc::new(e.rpc_url.clone(), 20);

    // ---- the contract-state baseline the refusals must not move ----
    let nonce_of = |who: &[u8; 20]| -> u64 {
        parse_quantity(
            &rpc.call("eth_getTransactionCount", json!([hex0x(who), "latest"]))
                .expect("nonce"),
        )
        .expect("nonce quantity")
    };
    let lock_opened_count = || -> usize {
        // The whole chain history of this dev node fits one query.
        let head = parse_quantity(&rpc.call("eth_blockNumber", json!([])).expect("head"))
            .expect("head quantity");
        rpc.call(
            "eth_getLogs",
            json!([{
                "fromBlock": "0x0",
                "toBlock": format!("0x{head:x}"),
                "address": hex0x(&e.contract),
                "topics": [hex0x(&event_topic0(SIG_LOCK_OPENED))],
            }]),
        )
        .expect("logs")
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0)
    };
    let contract_balance = || -> String {
        rpc.call("eth_getBalance", json!([hex0x(&e.contract), "latest"]))
            .expect("balance")
            .as_str()
            .expect("hex balance")
            .to_string()
    };
    let code_before = code_hash_of(&e);
    let nonce_before = nonce_of(&e.account);
    let opened_before = lock_opened_count();
    let balance_before = contract_balance();

    // ---- check 1: over-cap refused before broadcast -----------------
    // `AssurancePolicyV1` is `Copy`, so this binding is an independent
    // value and the over-cap mutation below cannot reach the rig's policy.
    let mut over_cap = r.policy;
    over_cap.required_collateral = over_cap.compensation_cap + 1;
    let broadcaster = RoleBroadcaster::new(&e);
    let refusal = EvmBondAdapter::new(
        &over_cap,
        r.deployment,
        HttpJsonRpc::new(e.rpc_url.clone(), 20),
        &broadcaster,
        LiveClock {
            rpc: HttpJsonRpc::new(e.rpc_url.clone(), 20),
        },
    )
    .err()
    .expect("required_collateral > compensation_cap must refuse");
    assert!(
        matches!(refusal, BondError::Policy(_)),
        "the refusal must be the policy's own named rule, got {refusal:?}"
    );
    println!("manifest: refusal over-cap-open = {refusal}");

    // ---- check 2: zero transactions, no LockOpened ------------------
    assert!(
        broadcaster.txs().is_empty(),
        "the over-cap refusal broadcast something"
    );
    anvil.mine(1);
    assert_eq!(nonce_of(&e.account), nonce_before, "a transaction was sent");
    assert_eq!(lock_opened_count(), opened_before, "a LockOpened appeared");

    // ---- check 3: divergent terms_hash refused by name --------------
    // (a) at the verifier binding: a settlement surface whose terms
    // do not match the policy's is refused at CONSTRUCTION.
    let mut foreign_cfg = r.settlement_cfg;
    foreign_cfg.terms_hash = seed_word(0x51, 0xEE);
    let verifier_refusal = RevealedScalarVerifier::new(
        &r.policy,
        foreign_cfg,
        HttpJsonRpc::new(e.rpc_url.clone(), 20),
    )
    .err()
    .expect("a divergent terms_hash must refuse the verifier binding");
    println!("manifest: refusal verifier-terms-binding = {verifier_refusal}");

    // (b) at the machine: collateral certified against other terms.
    let journal_revision_before = {
        let mut driver = r.recover();
        driver
            .apply(&AssuranceEvent::BondLockObserved)
            .expect("BondLockObserved");
        driver.revision()
    };
    {
        let mut driver = r.recover();
        let err = driver
            .apply(&AssuranceEvent::CollateralVerified {
                terms_hash: seed_word(0x51, 0xEE),
            })
            .expect_err("divergent collateral terms must refuse");
        assert!(
            matches!(
                err,
                f4_harness::journal::JournalError::Transition(uspe::AssuranceError::TermsMismatch)
            ),
            "expected the named TermsMismatch, got {err:?}"
        );
        println!("manifest: refusal collateral-terms = {err}");
    }

    // ---- check 4: foreign-terms claim yields no ExecuteSlash --------
    {
        let mut driver = r.recover();
        driver
            .apply(&AssuranceEvent::CollateralVerified {
                terms_hash: r.policy.terms_hash,
            })
            .expect("the RIGHT terms are accepted");
        driver
            .apply(&AssuranceEvent::ObligationFailed)
            .expect("ObligationFailed");
        let err = driver
            .apply(&AssuranceEvent::CompensationClaimed {
                terms_hash: seed_word(0x51, 0xEE),
            })
            .expect_err("a claim bound to other terms must refuse");
        assert!(matches!(
            err,
            f4_harness::journal::JournalError::Transition(uspe::AssuranceError::TermsMismatch)
        ));
        println!("manifest: refusal claim-terms = {err}");
    }
    let journal_after_refusals = {
        let driver = r.recover();
        (driver.revision(), driver.context().state)
    };
    // The two ACCEPTED transitions above moved the journal to revision
    // 3 (BondLockObserved, CollateralVerified, ObligationFailed); the
    // REFUSED ones moved nothing, and no ExecuteSlash was ever emitted
    // — the machine is not in Slashed and no slash was broadcast.
    assert_eq!(journal_after_refusals.0, journal_revision_before + 2);
    assert_ne!(journal_after_refusals.1, AssuranceState::Slashed);
    assert_ne!(journal_after_refusals.1, AssuranceState::Compensated);

    // ---- check 5: refusals modified no journal (file re-read) -------
    {
        let driver = r.recover();
        assert_eq!(
            driver.revision(),
            journal_after_refusals.0,
            "a refusal reached the durable journal"
        );
    }

    // ---- check 6: refusals modified no contract state ---------------
    anvil.mine(1);
    assert_eq!(code_hash_of(&e), code_before, "the contract code changed");
    assert_eq!(nonce_of(&e.account), nonce_before, "a transaction was sent");
    assert_eq!(lock_opened_count(), opened_before, "a lock appeared");
    assert_eq!(contract_balance(), balance_before, "value moved");
    println!("manifest: tx-count-during-refusals = 0");

    // ---- check 8: the SAME rig's correct policy still opens ---------
    // (check 7 — wrong scalar reverting on chain — is its own test in
    // this same run: anvil_wrong_scalar_slash_reverts_on_chain.)
    {
        let broadcaster = RoleBroadcaster::new(&e);
        let mut bond = r.bond(&e, &broadcaster);
        assert_eq!(
            bond.submit_bond(&r.policy).expect("the valid bond opens"),
            BroadcastOutcome::Accepted
        );
        anvil.advance_to_finality();
        let seen = observe_all(&mut bond);
        assert!(
            seen.iter()
                .any(|ev| matches!(ev, BondEvent::CollateralLocked { .. })),
            "the positive path must still work after every refusal"
        );
        assert_eq!(broadcaster.txs().len(), 1, "exactly the open, no more");
        assert_eq!(nonce_of(&e.account), nonce_before + 1);
        assert_eq!(lock_opened_count(), opened_before + 1);
    }
    let driver = r.recover();
    println!(
        "manifest: journal-terminal = {:?} revision = {}",
        driver.context().state,
        driver.revision()
    );
}

/// §11 + I12: the release path, executed by an UNINVOLVED third party
/// after the deadline. The timeout needs nobody's cooperation.
#[test]
fn anvil_release_path_is_executed_by_a_third_party() {
    let Some(e) = env() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rig(&e, 0x42, &dir);
    let anvil = Anvil::new(&e);
    let terms = r.policy.terms_hash;

    let broadcaster = RoleBroadcaster::new(&e);
    let mut bond = r.bond(&e, &broadcaster);
    bond.submit_bond(&r.policy).expect("bond open");
    anvil.advance_to_finality();

    let mut driver = r.recover();
    driver
        .apply(&AssuranceEvent::BondLockObserved)
        .expect("observed");
    driver
        .apply(&AssuranceEvent::CollateralVerified { terms_hash: terms })
        .expect("verified");
    let t = driver
        .apply(&AssuranceEvent::ObligationSettled)
        .expect("settled");
    assert!(t.effects.contains(&AssuranceEffect::AuthorizeRelease));

    // Before the deadline the release refuses; after it, anyone executes.
    let lock_id = bond.bond_lock_id();
    assert!(matches!(
        bond.submit_release(&lock_id),
        Err(BondError::DeadlineNotReached)
    ));
    let TimelockSpec::TimestampSeconds { value: deadline } = r.policy.bond_release_deadline else {
        unreachable!("EVM policy is timestamped")
    };
    anvil.warp_past(deadline);
    assert_eq!(
        bond.submit_release(&lock_id).expect("release"),
        BroadcastOutcome::Accepted
    );
    anvil.advance_to_finality();
    let seen = observe_all(&mut bond);
    assert!(seen
        .iter()
        .any(|ev| matches!(ev, BondEvent::BondRefunded { .. })));
    let release_tx = broadcaster
        .txs()
        .into_iter()
        .find(|(role, _)| *role == "release")
        .expect("release tx")
        .1;

    driver
        .apply(&AssuranceEvent::ReleaseConfirmed)
        .expect("confirmed");
    assert_eq!(driver.context().state, AssuranceState::Released);
    println!("  third-party release {release_tx}");
    println!("  terminal            Released");
}

/// D-F4.5 on the real contract: collateral that is never certified goes
/// back by pure timeout — the TIMEOUT_SAFE hole the model checker found,
/// closed end to end.
#[test]
fn anvil_uncertified_collateral_releases_by_timeout() {
    let Some(e) = env() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rig(&e, 0x43, &dir);
    let anvil = Anvil::new(&e);

    let broadcaster = RoleBroadcaster::new(&e);
    let mut bond = r.bond(&e, &broadcaster);
    bond.submit_bond(&r.policy).expect("bond open");
    anvil.advance_to_finality();

    let mut driver = r.recover();
    driver
        .apply(&AssuranceEvent::BondLockObserved)
        .expect("observed");
    // No CollateralVerified ever arrives.
    let t = driver
        .apply(&AssuranceEvent::CollateralDeadlineExpired)
        .expect("collateral deadline");
    assert!(t.effects.contains(&AssuranceEffect::AuthorizeRelease));

    let TimelockSpec::TimestampSeconds { value: deadline } = r.policy.bond_release_deadline else {
        unreachable!()
    };
    anvil.warp_past(deadline);
    let lock_id = bond.bond_lock_id();
    bond.submit_release(&lock_id).expect("release");
    anvil.advance_to_finality();
    assert!(observe_all(&mut bond)
        .iter()
        .any(|ev| matches!(ev, BondEvent::BondRefunded { .. })));
    driver
        .apply(&AssuranceEvent::ReleaseConfirmed)
        .expect("confirmed");
    assert_eq!(driver.context().state, AssuranceState::Released);
    println!("  terminal            Released (uncertified collateral, D-F4.5)");
}

/// §11 reorg: a reorg that swallows the settlement claim makes its
/// evidence UNDECIDABLE — an error, never `Invalid`, never `Valid`.
#[test]
fn anvil_reorg_across_the_claim_is_undecidable_not_a_verdict() {
    let Some(e) = env() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rig(&e, 0x44, &dir);
    let anvil = Anvil::new(&e);

    let snap = anvil.snapshot();
    r.counterparty_claims_settlement(&e);
    anvil.advance_to_finality();
    let evidence = r.settlement_evidence(&e);

    // The reorg: the chain the evidence talks about no longer exists.
    anvil.revert(&snap);
    anvil.mine(2);

    let verifier = RevealedScalarVerifier::new(
        &r.policy,
        r.settlement_cfg,
        HttpJsonRpc::new(e.rpc_url.clone(), 20),
    )
    .expect("verifier");
    let now = TimelockSpec::TimestampSeconds {
        value: anvil.timestamp(),
    };
    match verifier.verify(&r.policy, &evidence, now) {
        Err(_) => {} // undecidable: correct
        Ok(EvidenceVerdict::Valid { .. }) => {
            panic!("evidence from a reorged-away chain verified as Valid")
        }
        Ok(EvidenceVerdict::Invalid(reason)) => panic!(
            "a reorg produced a VERDICT ({reason:?}) — it must stay undecidable, \
             or a reorg window could burn a legitimate claim"
        ),
    }
    println!("  reorged evidence    undecidable (Err), as required");
}

/// Defense in depth: the contract itself refuses a wrong-scalar claim,
/// independently of the adapter's precheck.
#[test]
fn anvil_wrong_scalar_slash_reverts_on_chain() {
    let Some(e) = env() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rig(&e, 0x45, &dir);
    let anvil = Anvil::new(&e);

    let broadcaster = RoleBroadcaster::new(&e);
    let mut bond = r.bond(&e, &broadcaster);
    bond.submit_bond(&r.policy).expect("bond open");
    anvil.mine(1);

    let mut wrong = r.secret;
    wrong[31] ^= 0x01;
    // The adapter refuses first (proven in the mock suite). Here the RAW
    // transaction goes straight to the chain, and the CONTRACT refuses.
    let mut calldata = Vec::with_capacity(4 + 64);
    calldata.extend_from_slice(&selector(SIG_CLAIM));
    calldata.extend_from_slice(&word_bytes32(bond.bond_lock_id()));
    calldata.extend_from_slice(&word_u256(wrong));
    let raw = UnsignedEvmCall {
        version: UNSIGNED_CALL_VERSION,
        chain_id: DEV_CHAIN_ID,
        to: e.contract,
        value: [0u8; 32],
        gas_limit_hint: 300_000,
        lock_id: bond.bond_lock_id(),
        binding: bond.bond_binding(),
        calldata,
    };
    cast_send(&e, BENEFICIARY_KEY, &raw, false);
    println!("  wrong-scalar claim  reverted on chain (defense in depth)");
}
