//! Gate G-F3, on-chain half, under the **B-DOM** composition: the real
//! `ConditionLockV2`, on a real EVM, driven at the **driver level** by
//! [`f3_harness::EvmChainPort`], with `dom-sim` as the DOM leg.
//!
//! MANDATORY DECLARATION (Foundation §4.5): *dom-sim is not the DOM; it confers
//! no network compatibility; the swap for the real node happens in F7 under its
//! eligibility gate.* What G-F3 requires to be real is the **EVM** side, and
//! here it is: real bytecode, real transactions, `t` taken from a real on-chain
//! `Claimed` log.
//!
//! # How this differs from the v0.5 suite, and why
//!
//! The v0.5 gate composed `EvmChainPort` as the engine's `ChainPort`: the
//! engine drove the EVM leg. `main`'s ratified §24 `SettlementEngine` binds its
//! `ChainSourceV1` to `terms.dom_leg` and requires a `BlockHeight` deadline, so
//! it models the DOM leg and only the DOM leg — the B-DOM finding in
//! `docs/normative/F3-F5-RECONCILIATION-PLAN.md`. Three consequences for this
//! file:
//!
//! - every scenario that used to run `Engine::start`/`Engine::recover` +
//!   `tick()` over the EVM leg now drives the same steps directly through the
//!   driver (`submit_funding`/`observe`/`submit_claim`/`submit_refund`); what
//!   is asserted is the observable chain facts — finalized events, the
//!   revealed scalar, canonical evidence — not an engine state that no longer
//!   exists on this leg;
//! - the DOM leg of a direction test is the reused F2
//!   [`f3_harness::SimSettlementChain`], funded through the engine-shaped
//!   effect door ([`f3_harness::SimEffectSink`]), exactly as the offline
//!   `g_f3` suite does;
//! - the v0.5 height→timestamp refund bridge is gone, because under B-DOM no
//!   block-height instruction ever crosses onto the timestamp chain. The
//!   refund scenarios assert the timestamp-domain margins directly against
//!   the contract's own deadline; the domain machinery itself is exercised in
//!   `src/timelock.rs`.
//!
//! No validation was dropped anywhere else: finality before fact, scalar
//! canonicity, `address(t·G)`, `binding`/`lockId` re-derivation, the margins,
//! the gas findings, the reorg discipline and the crash discipline all survive
//! below.
//!
//! # How to run
//!
//! ```text
//! ./scripts/e2e_anvil.sh
//! ```
//!
//! # `#[ignore]`, and the skip that must never look like a pass
//!
//! Every test here is `#[ignore]`d, because it needs a node the default gate
//! does not have. That is the whole of the exception; it is not a licence to
//! do nothing quietly.
//!
//! A run is *requested* by setting `F3_ANVIL_RPC`. Before that, each scenario
//! prints a loud [`NOTHING_VERIFIED`] banner and returns — the offline suite is
//! unaffected. **After** it, nothing may skip: a missing variable, an
//! unparseable address, an endpoint that does not answer, or a contract
//! address with no code all panic and name themselves. An operator who
//! exported the variable and then lost the node must see red.
//!
//! The two remaining skips — the reorg and refund scenarios against a
//! non-development node, which genuinely cannot roll back or jump their clock
//! — print the same [`NOTHING_VERIFIED`] marker, and `scripts/e2e_anvil.sh`
//! fails the run if the marker appears at all. That script additionally
//! asserts that all eleven scenarios ran, *by name*, because "the suite is
//! green" has already meant "the suite lost a test" twice in this project.
//!
//! # Anvil's finality semantics — handled, not weakened
//!
//! The adapter's A4-EVM rule is absolute: finality is the `finalized` tag and
//! there is no fallback. Stock Anvil **does** implement it — measured on the
//! Anvil shipped here (1.7.1): `safe = latest - 32` and
//! `finalized = latest - 64`, i.e. real two-epoch semantics rather than an
//! alias for `latest`. So no test seam and no relaxation of the production rule
//! is needed: the harness simply mines [`FINALITY_BLOCKS`] blocks after each
//! transaction (`anvil_mine`, instant) and then observes. If a future Anvil
//! stopped serving the tag, the adapter would report
//! `AdapterError::AdapterUnavailable` and these tests would fail — which is the
//! correct outcome, not something to work around.
//!
//! Reorgs use `evm_snapshot` / `evm_revert`, not `anvil_reorg`. Measured on
//! the same Anvil: `anvil_reorg(depth)` re-mines the tip but leaves the
//! re-mined range's account state empty — after `anvil_reorg(71)` the
//! deployment's `eth_getCode` at `latest` answers `0x`, so the adapter's
//! codehash preflight fails and nothing about reorg handling can be exercised.
//! Snapshot/revert rolls the chain back with its state intact, which is what a
//! reorg actually looks like. The rollback deliberately goes *below* the
//! finalized checkpoint — something real Ethereum would not do, and exactly the
//! hostile case the adapter's rewind logic exists for.
//!
//! # Where the DOM-side cryptography lives
//!
//! **Not here.** In the default build `dom-leg` compiles without the pinned
//! backend and every cryptographic operation refuses with the **named**
//! refusal `CryptoBackendDisabled`; the direction scenarios below are gated to
//! that build and assert the exact refusal, never a wildcard. The wire
//! boundary (`adapt_claim_from_wire`/`extract_revealed_secret`) is identical
//! in both builds, so nothing here is shaped around a feature-only surface.
//! The positive halves — a real adaptation and a real byte-equal extraction —
//! run against the frozen SCAD0 corpus in `dom-leg`'s own conformance suite at
//! the pin.
//!
//! # The signing boundary
//!
//! Nothing in `adapter-evm` or `f3-harness` signs. The adapter emits an
//! [`UnsignedEvmCall`]; [`CastBroadcaster`] hands those exact bytes to
//! `cast send --private-key <anvil dev key>`. The key is a well-known public
//! development key — it is not a secret — and it is still never printed,
//! echoed or written anywhere by this file.

#![cfg(feature = "rpc-http")]

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::process::Command;

use adapter_evm::abi::{
    concat_words, event_topic0, selector, word_address, word_u128, SIG_CLAIM, SIG_CLAIMED,
    SIG_LOCK_OPENED, SIG_OPEN, SIG_PAYOUT_DEFERRED, SIG_REFUND, SIG_REFUNDED, SIG_WITHDRAWAL,
};
use adapter_evm::binding::{
    adaptor_address_of_scalar, adaptor_point_of_scalar, Direction, LockTerms,
};
use adapter_evm::rpc::{EthClient, HttpJsonRpc, JsonRpc};
use adapter_evm::{EvidenceKind, EvmAdapterConfig, UnsignedEvmCall};
use counterparty_api::{
    AdaptorPointBytes, ChainCursor, NeutralTerms, ObservedEvent, RevealedSecretBytes,
    VerifiedOutcome,
};
use f3_harness::gas::{
    settlement_gas_limit, ERC20_CLAIM_ESTIMATED_GAS, ERC20_CLAIM_PUSH_GAS,
    ERC20_SETTLEMENT_GAS_LIMIT, NATIVE_CLAIM_ESTIMATED_GAS, NATIVE_CLAIM_PUSH_GAS,
    NATIVE_SETTLEMENT_GAS_LIMIT,
};
use f3_harness::{
    build_claim_call, BroadcastOutcome, Broadcaster, ChainClock, EvmChainPort, EvmDeployment,
    EvmPortConfig, HarnessError, MemoryLog, Outbox, SharedRpc, TimelockError, TimelockPoint,
    TimelockPolicy,
};
use serde_json::{json, Value};

// The DOM seam and the dom-sim leg are only driven in the build where
// `dom-leg` has no cryptographic backend; see the direction scenarios below.
#[cfg(not(feature = "real-dom-adaptor"))]
use adapter_dom_sim::LockState;
#[cfg(not(feature = "real-dom-adaptor"))]
use dom_leg::{
    pre_signature_layout as layout, DomLegSession, LegError, PreSignatureBytes, SessionBindings,
};
#[cfg(not(feature = "real-dom-adaptor"))]
use f3_harness::{
    dom_to_evm, evm_to_dom, DomToEvmInput, EvmToDomInput, SimEffectSink, SimSettlementChain,
};
#[cfg(not(feature = "real-dom-adaptor"))]
use kaystra_core::store_port::ClaimedEffectV1;
#[cfg(not(feature = "real-dom-adaptor"))]
use kaystra_core::types::{ChainId, EffectId, SettlementId};
#[cfg(not(feature = "real-dom-adaptor"))]
use kaystra_core::{Effect, EffectOutcome, EffectSinkV1};

/// Blocks Anvil needs above a transaction before its block is `finalized`.
///
/// Measured, not guessed: Anvil answers `finalized` with `latest - 64`. Six
/// extra blocks of headroom absorb the block the transaction itself mines.
const FINALITY_BLOCKS: u64 = 70;

/// How long to wait between `finalized` polls on a network that cannot be
/// mined (Sepolia). One slot is 12 s; polling every 15 s is polite.
const FINALITY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Bound on that wait: 160 polls ≈ 40 minutes, comfortably more than the ~13
/// minutes Sepolia finality normally takes and still a bound rather than a
/// hang.
const FINALITY_WAIT_POLLS: usize = 160;

/// Amount locked in each scenario, in wei (0.001 ETH).
const AMOUNT: u128 = 1_000_000_000_000_000;

#[cfg(not(feature = "real-dom-adaptor"))]
const TEMPLATE_HASH: [u8; 32] = [0xA1; 32];
#[cfg(not(feature = "real-dom-adaptor"))]
const TRANSCRIPT_HASH: [u8; 32] = [0xB2; 32];

// ---------------------------------------------------------------------------
// environment
// ---------------------------------------------------------------------------

/// The one string in this file that may ever stand for "this scenario did not
/// run".
///
/// Every skip prints it, and `scripts/e2e_anvil.sh` fails the whole run if it
/// appears anywhere in the output. That coupling is the point: a skip must be
/// incapable of being read as a pass.
const NOTHING_VERIFIED: &str = "SKIPPED — NOTHING WAS VERIFIED";

/// Chain ids this harness is allowed to drive: a local Anvil, and Sepolia
/// through `scripts/sepolia.sh`. Anything else — an L1 mainnet above all — is
/// refused, and there is no override.
const ALLOWED_CHAIN_IDS: [u64; 2] = [31337, 11155111];

struct Env {
    rpc_url: String,
    cast: String,
    /// Chain id the endpoint reported, read once and re-used, so every banner
    /// states the chain it actually ran against rather than a constant.
    chain_id: u64,
    /// `ConditionLockV2` — the native-ETH deployment.
    contract: [u8; 20],
    /// `ConditionLockERC20V2` — the token deployment.
    erc20_contract: Option<[u8; 20]>,
    /// A plain, well-behaved ERC-20 whose payout push succeeds.
    token: Option<[u8; 20]>,
    /// An honest but expensive ERC-20 whose payout push exceeds the stipend and
    /// therefore degrades to a pull credit.
    heavy_token: Option<[u8; 20]>,
    account: [u8; 20],
    key: String,
}

/// Reads the environment the wrapper script exports.
///
/// Exactly three outcomes, and only the first is quiet:
///
/// 1. **`F3_ANVIL_RPC` unset** — nobody asked for a live run. A loud
///    [`NOTHING_VERIFIED`] banner is printed and the caller returns without
///    asserting anything, so the default offline suite is unaffected.
/// 2. **`F3_ANVIL_RPC` set and everything else in order** — the [`Env`].
/// 3. **`F3_ANVIL_RPC` set and anything else wrong** — **panic**.
///
/// The third case is the one that matters, and it used to be case 1. Every
/// other variable was read with `?`, so an operator who exported the RPC URL
/// and then lost the node, or mistyped the lock address, or pointed the run at
/// a chain where nothing had been deployed, got eleven green `ok` lines with
/// nothing behind them. Setting `F3_ANVIL_RPC` is a declaration that a live run
/// is wanted; from that moment on, anything that stops the scenario from
/// running is a failure of the run.
fn env() -> Option<Env> {
    let Ok(rpc_url) = std::env::var("F3_ANVIL_RPC") else {
        println!(
            "\n\
             ============================================================\n\
             {NOTHING_VERIFIED}\n\
             F3_ANVIL_RPC is not set, so no Anvil end-to-end scenario ran.\n\
             This is NOT a pass: nothing on this path was exercised.\n\
             Run ./scripts/e2e_anvil.sh, which starts a node, deploys the\n\
             contracts and exports the whole environment.\n\
             ============================================================\n"
        );
        return None;
    };
    Some(live_env(rpc_url))
}

/// Case 2/3 of [`env`]: every remaining requirement, each with its own named
/// failure.
fn live_env(rpc_url: String) -> Env {
    let contract = required_address("F3_ANVIL_LOCK");
    let account = required_address("F3_ANVIL_ACCOUNT");
    let key = required_var("F3_ANVIL_KEY");
    let cast = std::env::var("F3_CAST").unwrap_or_else(|_| "cast".to_string());

    let rpc = SharedRpc::new(HttpJsonRpc::new(rpc_url.clone(), 20));
    let shown = redacted(&rpc_url);
    let chain_id = match EthClient::new(&rpc).chain_id() {
        Ok(id) => id,
        Err(err) => panic!(
            "F3_ANVIL_RPC is set to {shown}, so a live run was requested, but the \
             endpoint did not answer eth_chainId: {err:?}. There is no node to run \
             against — that is a FAILURE of this run, not a reason to skip it. Start \
             one with ./scripts/e2e_anvil.sh."
        ),
    };
    assert!(
        ALLOWED_CHAIN_IDS.contains(&chain_id),
        "the endpoint at {shown} reports chain id {chain_id}. This harness drives a \
         local Anvil (31337) or Sepolia (11155111) and nothing else; there is no \
         override flag, because a flag is how a mainnet accident happens."
    );
    require_code(&rpc, "F3_ANVIL_LOCK", &contract);

    Env {
        rpc_url,
        cast,
        chain_id,
        contract,
        erc20_contract: optional_address(&rpc, "F3_ANVIL_ERC20_LOCK"),
        token: optional_address(&rpc, "F3_ANVIL_TOKEN"),
        heavy_token: optional_address(&rpc, "F3_ANVIL_HEAVY_TOKEN"),
        account,
        key,
    }
}

/// Scheme and host of an endpoint URL, with the path and query dropped.
///
/// A hosted Sepolia endpoint is usually `https://<provider>/v2/<api-key>`: the
/// path IS a credential. These messages end up in `artifacts/sepolia/run.log`
/// and in gate reports, so the URL is never rendered whole.
fn redacted(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let host = rest.split('/').next().unwrap_or(rest);
            if rest.len() > host.len() {
                format!("{scheme}://{host}/… (path redacted)")
            } else {
                format!("{scheme}://{host}")
            }
        }
        None => "<endpoint>".to_string(),
    }
}

/// A variable that must be present and non-empty in a live run.
fn required_var(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => panic!(
            "F3_ANVIL_RPC is set, so this is a live run, but {name} is missing or \
             empty. The wrapper script ./scripts/e2e_anvil.sh exports every variable \
             this harness needs; a half-configured environment is a failure, not a skip."
        ),
    }
}

/// A variable that must be present and must parse as an address.
fn required_address(name: &str) -> [u8; 20] {
    let raw = required_var(name);
    parse_address(&raw).unwrap_or_else(|| {
        panic!("{name} is set to {raw:?}, which is not a 20-byte 0x-prefixed address")
    })
}

/// An address that a given run may legitimately not have — but which, when it
/// is set, must be real. A set-but-wrong value is a configuration error and is
/// reported as one.
fn optional_address(rpc: &SharedRpc<HttpJsonRpc>, name: &str) -> Option<[u8; 20]> {
    let raw = std::env::var(name).ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    let address = parse_address(&raw).unwrap_or_else(|| {
        panic!("{name} is set to {raw:?}, which is not a 20-byte 0x-prefixed address")
    });
    require_code(rpc, name, &address);
    Some(address)
}

/// The address must actually hold code.
///
/// A deployment that is not there — a restarted node, a stale address, a
/// deployment that landed on another chain — is exactly the shape of "the
/// operator set the variable and the world moved underneath them", and it must
/// be red.
fn require_code(rpc: &SharedRpc<HttpJsonRpc>, name: &str, address: &[u8; 20]) {
    let answer = rpc.call("eth_getCode", json!([hex0x(address), "latest"]));
    let code = match &answer {
        Ok(Value::String(code)) => code.as_str(),
        other => panic!(
            "{name} = {}: the endpoint did not answer eth_getCode ({other:?}). A live \
             run cannot proceed without reading the deployment it was pointed at.",
            hex0x(address)
        ),
    };
    assert!(
        code.len() > 2,
        "{name} = {} holds no code at `latest`. The deployment this run was pointed \
         at does not exist: re-run ./scripts/e2e_anvil.sh so the contracts are \
         deployed and the addresses exported together.",
        hex0x(address)
    );
}

/// The ERC-20 half of the environment.
///
/// Deliberately not an `Option`: the wrapper script deploys both tokens on
/// every run, so their absence during a live run means the deployment step did
/// not do what it claims. Returning `None` here is what let three ERC-20
/// scenarios print a line and pass.
fn erc20_env(e: &Env) -> ([u8; 20], [u8; 20], [u8; 20]) {
    match (e.erc20_contract, e.token, e.heavy_token) {
        (Some(lock), Some(token), Some(heavy)) => (lock, token, heavy),
        _ => {
            let missing: Vec<&str> = [
                ("F3_ANVIL_ERC20_LOCK", e.erc20_contract.is_none()),
                ("F3_ANVIL_TOKEN", e.token.is_none()),
                ("F3_ANVIL_HEAVY_TOKEN", e.heavy_token.is_none()),
            ]
            .into_iter()
            .filter_map(|(name, absent)| absent.then_some(name))
            .collect();
            panic!(
                "the ERC-20 scenarios need a token deployment and {missing:?} \
                 {} not set. ./scripts/e2e_anvil.sh deploys MockERC20 and HeavyToken \
                 and exports all three; running these scenarios without them verifies \
                 nothing, so this is a failure rather than a skip.",
                if missing.len() == 1 { "is" } else { "are" }
            )
        }
    }
}

/// The one skip left besides an unset `F3_ANVIL_RPC`, and it is just as loud.
///
/// `evm_snapshot`/`evm_revert` and `evm_increaseTime` are development-node
/// capabilities: a public network genuinely cannot roll back or jump its clock.
/// Those scenarios are *not applicable* against Sepolia rather than failing —
/// but they still print [`NOTHING_VERIFIED`], and `scripts/e2e_anvil.sh`, which
/// always drives a real Anvil, treats the marker as a failure.
fn skip_not_a_dev_node(scenario: &str, capability: &str) {
    println!(
        "\n\
         ============================================================\n\
         {NOTHING_VERIFIED}\n\
         {scenario}: the endpoint is not a development node, so `{capability}`\n\
         is unavailable and this scenario could not be exercised at all.\n\
         ============================================================\n"
    );
}

fn parse_address(s: &str) -> Option<[u8; 20]> {
    let body = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if body.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, pair) in body.as_bytes().chunks_exact(2).enumerate() {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

fn hex0x(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Minimal-width hex quantity, for `--value`.
/// `cast send --value` takes a DECIMAL quantity: Foundry 1.5.x rejects a
/// `0x` hex value outright ("digit 33 is out of range for base 16", as a
/// live probe against 1.5.1 shows), while decimal works on every version
/// this project has driven. The F4 harness always passed decimal; this
/// one now does too. Settlement amounts are u128 by construction, so the
/// upper 16 bytes must be zero — asserted, never truncated.
fn decimal_quantity(word: &[u8; 32]) -> String {
    assert!(
        word[..16].iter().all(|b| *b == 0),
        "a settlement value exceeded u128"
    );
    u128::from_be_bytes(word[16..].try_into().expect("16 bytes")).to_string()
}

// ---------------------------------------------------------------------------
// chain control (anvil cheat methods, through the same transport)
// ---------------------------------------------------------------------------

/// Read-only RPC call with a bounded retry on TRANSIENT failure.
///
/// On a public network a multi-hour run makes hundreds of round trips, and
/// a hosted endpoint is allowed to hiccup on any one of them — the first
/// Sepolia gate run died on exactly one `eth_getLogs` that failed AFTER the
/// on-chain extraction had already succeeded. Retrying a failed READ with a
/// bound weakens nothing: every assertion about the answer is unchanged,
/// and an endpoint that stays down still fails the run. This is the same
/// discipline as the bounded finality wait, applied to single reads.
///
/// Exponential backoff, not a fixed delay: the 2026-08-10 gate run died
/// when the endpoint stayed down for over two minutes — longer than the
/// old 8x15s flat window — and recovered soon after (the next direction
/// test passed clean). Ten attempts backing off 15s -> 120s tolerate an
/// outage of ~13 minutes, proportionate to the 40-minute bound already
/// granted to one finality wait, and still strictly bounded.
const RPC_READ_RETRIES: u32 = 10;
const RPC_READ_RETRY_BASE_SECS: u64 = 15;
const RPC_READ_RETRY_CAP_SECS: u64 = 120;

fn rpc_read_backoff(attempt: u32) -> std::time::Duration {
    let secs = RPC_READ_RETRY_BASE_SECS
        .saturating_mul(1u64 << attempt.min(3))
        .min(RPC_READ_RETRY_CAP_SECS);
    std::time::Duration::from_secs(secs)
}

fn rpc_read(rpc: &SharedRpc<HttpJsonRpc>, what: &str, method: &str, params: Value) -> Value {
    let mut last = None;
    for attempt in 0..RPC_READ_RETRIES {
        match rpc.call(method, params.clone()) {
            Ok(v) => return v,
            Err(err) => {
                let delay = rpc_read_backoff(attempt);
                println!(
                    "  transient          {what} failed ({err:?}), retry \
                     {}/{} in {}s",
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

struct Anvil<'a> {
    rpc: &'a SharedRpc<HttpJsonRpc>,
}

impl Anvil<'_> {
    /// Whether this endpoint is a development node we may drive.
    ///
    /// Probed with `anvil_nodeInfo`, which is read-only and which a public
    /// network does not serve. On a public network the harness cannot mine and
    /// must simply wait for finality — see [`Anvil::advance_to_finality`].
    fn is_dev_node(&self) -> bool {
        self.rpc.call("anvil_nodeInfo", json!([])).is_ok()
    }

    fn mine(&self, n: u64) {
        self.rpc
            .call("anvil_mine", json!([format!("0x{n:x}")]))
            .expect("anvil_mine");
    }

    fn block_number(&self) -> u64 {
        let v = rpc_read(self.rpc, "eth_blockNumber", "eth_blockNumber", json!([]));
        parse_quantity(&v).expect("block number")
    }

    fn finalized(&self) -> u64 {
        let v = rpc_read(
            self.rpc,
            "finalized tag",
            "eth_getBlockByNumber",
            json!(["finalized", false]),
        );
        parse_quantity(v.get("number").expect("number")).expect("quantity")
    }

    fn timestamp(&self) -> u64 {
        let v = rpc_read(
            self.rpc,
            "latest block",
            "eth_getBlockByNumber",
            json!(["latest", false]),
        );
        parse_quantity(v.get("timestamp").expect("timestamp")).expect("quantity")
    }

    fn block_hash(&self, height: u64) -> String {
        let v = rpc_read(
            self.rpc,
            "block by number",
            "eth_getBlockByNumber",
            json!([format!("0x{height:x}"), false]),
        );
        v.get("hash")
            .and_then(|h| h.as_str())
            .unwrap_or("<none>")
            .to_string()
    }

    /// Takes a state snapshot the chain can be rolled back to.
    ///
    /// `evm_snapshot` / `evm_revert` rather than `anvil_reorg`, and the reason
    /// is measured rather than stylistic: on the Anvil shipped here (1.7.1),
    /// `anvil_reorg` re-mines the tip but leaves the account state of the
    /// re-mined range empty — after `anvil_reorg(71)` the deployment's
    /// `eth_getCode` at `latest` answers `0x`, so the adapter's codehash
    /// preflight fails and no reorg can be exercised at all. Snapshot/revert
    /// rolls the chain back with its state intact, which is what a reorg
    /// actually looks like.
    fn snapshot(&self) -> Value {
        self.rpc
            .call("evm_snapshot", json!([]))
            .expect("evm_snapshot")
    }

    fn revert(&self, snap: &Value) {
        let ok = self
            .rpc
            .call("evm_revert", json!([snap]))
            .expect("evm_revert");
        assert_eq!(ok, json!(true), "evm_revert refused the snapshot");
    }

    fn increase_time(&self, secs: u64) {
        self.rpc
            .call("evm_increaseTime", json!([secs]))
            .expect("evm_increaseTime");
        self.rpc.call("evm_mine", json!([])).expect("evm_mine");
    }

    /// Makes the current head finalized, so everything submitted so far is
    /// observable at all.
    ///
    /// On a development node this is one instant `anvil_mine`. On a public
    /// network — the same tests run against Sepolia by `scripts/sepolia_e2e.sh`
    /// — nothing can be mined and there is nothing to do but wait: finality
    /// there is two epochs, about thirteen minutes. That wait is the real cost
    /// of the A4-EVM rule and the harness pays it rather than weakening it.
    fn advance_to_finality(&self) {
        let target = self.block_number();
        if self.is_dev_node() {
            self.mine(FINALITY_BLOCKS);
            assert!(
                self.finalized() >= target,
                "the development node did not finalize the head after mining"
            );
            return;
        }
        // A silent fifteen-minute block is indistinguishable from a hang, and
        // an operator watching a public-network run has no other signal, so
        // every poll says where it is and how much of the bound is left.
        let budget = FINALITY_POLL_INTERVAL.as_secs() * FINALITY_WAIT_POLLS as u64;
        println!(
            "  waiting for        block {target} to finalize (public network; \
             two epochs, ~13 min; bound {}m)",
            budget / 60
        );
        for poll in 0..FINALITY_WAIT_POLLS {
            let finalized = self.finalized();
            if finalized >= target {
                println!("  finalized          #{finalized} >= block {target}");
                return;
            }
            let waited = FINALITY_POLL_INTERVAL.as_secs() * poll as u64;
            println!(
                "  waiting            finalized #{finalized} < block {target} \
                 ({}m{:02}s of {}m)",
                waited / 60,
                waited % 60,
                budget / 60
            );
            std::thread::sleep(FINALITY_POLL_INTERVAL);
        }
        panic!(
            "block {target} did not finalize within the bounded wait of {}m. This is \
             an external blocker (the network did not finalize), not a defect in the \
             settlement: do not work around it by weakening the finality rule.",
            budget / 60
        );
    }
}

fn parse_quantity(v: &Value) -> Option<u64> {
    let s = v.as_str()?;
    u64::from_str_radix(s.strip_prefix("0x")?, 16).ok()
}

/// The chain's own clock, as the EVM leg's timelock domain requires.
struct AnvilClock<'a> {
    rpc: &'a SharedRpc<HttpJsonRpc>,
}

impl ChainClock for AnvilClock<'_> {
    fn now(&self) -> Result<TimelockPoint, HarnessError> {
        let v = self
            .rpc
            .call("eth_getBlockByNumber", json!(["latest", false]))
            .map_err(HarnessError::Adapter)?;
        let ts = v
            .get("timestamp")
            .and_then(parse_quantity)
            .ok_or(HarnessError::Misconfigured)?;
        Ok(TimelockPoint::timestamp(ts))
    }
}

// ---------------------------------------------------------------------------
// the signing boundary
// ---------------------------------------------------------------------------

/// Where the unsigned artifact meets a key — outside the adapter, outside the
/// harness, in a separate process.
///
/// The bytes handed to `cast send` are exactly the bytes the outbox holds. That
/// is the whole demonstration: the artifact `adapter-evm` produced is a real,
/// broadcastable Ethereum transaction, and nothing that produced it ever saw a
/// key.
struct CastBroadcaster {
    cast: String,
    rpc_url: String,
    key: String,
    seen: RefCell<BTreeSet<(u8, [u8; 32])>>,
    receipts: RefCell<Vec<Receipt>>,
}

#[derive(Clone, Debug)]
struct Receipt {
    what: &'static str,
    tx_hash: String,
    block_hash: String,
    block_number: u64,
}

impl CastBroadcaster {
    fn new(e: &Env) -> Self {
        Self {
            cast: e.cast.clone(),
            rpc_url: e.rpc_url.clone(),
            key: e.key.clone(),
            seen: RefCell::new(BTreeSet::new()),
            receipts: RefCell::new(Vec::new()),
        }
    }

    fn receipts(&self) -> Vec<Receipt> {
        self.receipts.borrow().clone()
    }

    fn last(&self) -> Receipt {
        self.receipts
            .borrow()
            .last()
            .cloned()
            .expect("at least one receipt")
    }

    fn tag(call: &UnsignedEvmCall) -> (u8, &'static str) {
        let head = &call.calldata[..4];
        if head == selector(SIG_OPEN) {
            (1, "open")
        } else if head == selector(SIG_CLAIM) {
            (2, "claim")
        } else if head == selector(SIG_REFUND) {
            (3, "refund")
        } else {
            (0, "unknown")
        }
    }
}

impl Broadcaster for CastBroadcaster {
    fn broadcast(&self, call: &UnsignedEvmCall) -> Result<BroadcastOutcome, HarnessError> {
        let (tag, what) = Self::tag(call);
        if tag == 0 {
            return Err(HarnessError::Misconfigured);
        }
        if self.seen.borrow().contains(&(tag, call.lock_id)) {
            return Ok(BroadcastOutcome::Duplicate);
        }
        let value = if call.value == [0u8; 32] {
            None
        } else {
            Some(decimal_quantity(&call.value))
        };
        // The gas limit comes from the artifact's own hint. The ERC-20 payout
        // path has a `gasleft()` floor of 200k below which it skips the push
        // entirely, so leaving the limit to estimation would let the estimator
        // silently choose which branch runs. Passing the hint makes the branch
        // a property of the settlement's configuration, not of a search.
        let receipt = cast_send(
            &self.cast,
            &self.rpc_url,
            &self.key,
            what,
            &call.to,
            &call.calldata,
            value.as_deref(),
            Some(call.gas_limit_hint),
        )
        .ok_or(HarnessError::BroadcastRefused)?;
        self.seen.borrow_mut().insert((tag, call.lock_id));
        self.receipts.borrow_mut().push(receipt);
        Ok(BroadcastOutcome::Accepted)
    }
}

/// Like [`cast_send`], but a reverted transaction is a result rather than a
/// panic. Used only by the gas-threshold probe, where a limit too low to
/// complete at all is one of the answers being searched for.
#[allow(clippy::too_many_arguments)]
fn try_cast_send(
    cast: &str,
    rpc_url: &str,
    key: &str,
    to: &[u8; 20],
    calldata: &[u8],
    gas_limit: u64,
) -> Option<bool> {
    let args: Vec<String> = vec![
        "send".into(),
        hex0x(to),
        hex0x(calldata),
        "--rpc-url".into(),
        rpc_url.to_string(),
        "--private-key".into(),
        key.to_string(),
        "--json".into(),
        "--gas-limit".into(),
        gas_limit.to_string(),
    ];
    let out = Command::new(cast).args(&args).output().ok()?;
    if !out.status.success() {
        return Some(false);
    }
    let parsed: Value = serde_json::from_slice(&out.stdout).ok()?;
    let status = parsed
        .get("status")
        .and_then(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        })
        .unwrap_or_default();
    Some(status == "0x1" || status == "1")
}

/// Signs and broadcasts one call with `cast send`, and returns its receipt.
///
/// Used both by [`CastBroadcaster`] — for the artifacts the adapter produced —
/// and directly by the ERC-20 scenarios for the calls that are *not* settlement
/// artifacts at all: `approve`, `withdraw`, `withdrawAmount`. Keeping those out
/// of the broadcaster is deliberate: the outbox exists for settlement
/// submissions, and putting a token approval in it would blur what an
/// idempotency key means.
///
/// The key is one argument of a child process and is never rendered anywhere;
/// `cast`'s own stderr is not surfaced because it can echo the command line.
#[allow(clippy::too_many_arguments)]
fn cast_send(
    cast: &str,
    rpc_url: &str,
    key: &str,
    what: &'static str,
    to: &[u8; 20],
    calldata: &[u8],
    value: Option<&str>,
    gas_limit: Option<u64>,
) -> Option<Receipt> {
    let mut args: Vec<String> = vec![
        "send".into(),
        hex0x(to),
        hex0x(calldata),
        "--rpc-url".into(),
        rpc_url.to_string(),
        "--private-key".into(),
        key.to_string(),
        "--json".into(),
    ];
    if let Some(v) = value {
        args.push("--value".into());
        args.push(v.to_string());
    }
    if let Some(g) = gas_limit {
        args.push("--gas-limit".into());
        args.push(g.to_string());
    }
    let out = Command::new(cast).args(&args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let parsed: Value = serde_json::from_slice(&out.stdout).ok()?;
    let status = parsed
        .get("status")
        .and_then(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        })
        .unwrap_or_default();
    assert!(
        status == "0x1" || status == "1",
        "the {what} transaction reverted on chain"
    );
    Some(Receipt {
        what,
        tx_hash: parsed
            .get("transactionHash")
            .and_then(|v| v.as_str())
            .unwrap_or("<none>")
            .to_string(),
        block_hash: parsed
            .get("blockHash")
            .and_then(|v| v.as_str())
            .unwrap_or("<none>")
            .to_string(),
        block_number: parsed
            .get("blockNumber")
            .and_then(|v| {
                v.as_str()
                    .and_then(|s| {
                        u64::from_str_radix(s.trim_start_matches("0x"), 16)
                            .ok()
                            .or_else(|| s.parse().ok())
                    })
                    .or_else(|| v.as_u64())
            })
            .unwrap_or_default(),
    })
}

// ---------------------------------------------------------------------------
// settlement fixtures
// ---------------------------------------------------------------------------

/// A 32-byte value that differs for every seed, so two settlements in one run
/// can never share a `binding`.
fn seed_word(seed: u16, tag: u8) -> [u8; 32] {
    let [hi, lo] = seed.to_be_bytes();
    let mut w = [lo ^ tag; 32];
    w[0] = hi ^ tag;
    w[1] = lo ^ tag;
    w[2] = tag;
    w
}

/// A canonical scalar derived from a session seed. Distinct seeds give distinct
/// scalars, hence distinct adaptor addresses, hence distinct `lockId`s.
fn scalar(seed: u16) -> [u8; 32] {
    let [hi, lo] = seed.to_be_bytes();
    let mut t = [0u8; 32];
    t[31] = lo.max(1);
    t[30] = hi;
    t[11] = lo;
    t[19] = lo ^ 0x5A;
    t[20] = hi ^ 0xA5;
    t
}

// ---------------------------------------------------------------------------
// the DOM leg of a direction test (offline build: the named refusal)
// ---------------------------------------------------------------------------
//
// On this trunk there is exactly one offline configuration: `dom-leg` without
// the pinned backend. There is no valid pre-signature anywhere, so the DOM leg
// must refuse — with a *named* refusal, never a wildcard. The direction
// scenarios are gated to that build rather than dual-built, because `main`'s
// real `dom-leg` cannot construct a session without a full 2-of-2 round —
// there is no "session with no signing key" to drive the negative against.
// The wire boundary the routes call is byte-identical in both builds, so what
// is proved here about the routes holds in both; the positive halves (a real
// adaptation, a real byte-equal extraction) live at the pin (SCAD0) in
// `dom-leg`'s own conformance suite.

/// The DOM-side material one direction test drives, and what it is entitled to
/// assert: the routes reach the seam, and the seam refuses **by name**.
#[cfg(not(feature = "real-dom-adaptor"))]
struct DomLegFixture {
    /// The scalar both legs commit to.
    t: [u8; 32],
    /// The DOM-leg session: right bindings, no backend behind them.
    session: DomLegSession,
    /// A pre-signature frame committing to `T = t·G`.
    pre: PreSignatureBytes,
    /// Not a signature and not pretending to be one: with no valid
    /// pre-signature there is nothing for the verifier to accept, and the
    /// route must refuse before it could matter.
    final_signature: Vec<u8>,
}

/// The **exact** refusal this build's `dom-leg` produces: the backend is not
/// compiled in, and the leg says so. Named rather than matched with a
/// wildcard, so a change of reason is a test failure, not a silent pass.
#[cfg(not(feature = "real-dom-adaptor"))]
fn refusal_of_the_backendless_leg() -> HarnessError {
    HarnessError::DomLeg(LegError::CryptoBackendDisabled)
}

/// A session with the right bindings and no backend behind it. `0x02` is the
/// canonical `ClaimAdaptor` purpose byte; without the pin it enables nothing.
#[cfg(not(feature = "real-dom-adaptor"))]
fn session() -> DomLegSession {
    DomLegSession::new(SessionBindings {
        chain_id: [0x11; 32],
        claim_template_hash: TEMPLATE_HASH,
        transcript_hash: TRANSCRIPT_HASH,
        purpose_byte: 0x02,
    })
}

/// A pre-signature frame committing to `T = t·G` and to this session.
///
/// Only the *frame* is built here; nothing cryptographic is simulated. The
/// nonce and scalar fields are opaque filler, and every operation that would
/// have to interpret them is delegated to `dom-leg`, which refuses.
#[cfg(not(feature = "real-dom-adaptor"))]
fn pre_signature_for(t: &[u8; 32]) -> PreSignatureBytes {
    let mut buf = [0u8; layout::ENCODED_LEN];
    buf[layout::CLAIM_TEMPLATE_HASH].copy_from_slice(&TEMPLATE_HASH);
    buf[layout::ADAPTOR_POINT].copy_from_slice(&adaptor_point_of_scalar(t).expect("canonical"));
    buf[layout::AGGREGATE_NONCE_HAT].fill(0x04);
    buf[layout::SCALAR_HAT].fill(0x05);
    buf[layout::TRANSCRIPT_HASH].copy_from_slice(&TRANSCRIPT_HASH);
    PreSignatureBytes::from_slice(&buf).expect("fixed length frame")
}

/// The DOM-leg material for a settlement.
#[cfg(not(feature = "real-dom-adaptor"))]
fn dom_leg_fixture(seed: u16) -> DomLegFixture {
    let t = scalar(seed);
    DomLegFixture {
        t,
        session: session(),
        pre: pre_signature_for(&t),
        final_signature: vec![0u8; 65],
    }
}

#[cfg(not(feature = "real-dom-adaptor"))]
impl DomLegFixture {
    /// Checks the EVM→DOM outcome and hands back the authorisation, if any.
    ///
    /// In this build there can be none: the backendless leg refuses, by name.
    /// A route that stopped anywhere *before* the seam would surface a
    /// different error, and this assertion would catch it.
    fn check_evm_to_dom(
        &self,
        out: f3_harness::Result<f3_harness::DomClaimAuthorisation>,
    ) -> Option<f3_harness::DomClaimAuthorisation> {
        assert_eq!(
            out.err(),
            Some(refusal_of_the_backendless_leg()),
            "the refusal must be exactly the one the backendless leg produces"
        );
        println!("  dom leg            REFUSED, by name (no cryptographic backend in this build)");
        None
    }

    /// Checks the DOM→EVM outcome and hands back the claim call, if any.
    ///
    /// See [`DomLegFixture::check_evm_to_dom`]: in this build the answer is
    /// always the named refusal, and anything else is a failure.
    fn check_dom_to_evm(
        &self,
        out: f3_harness::Result<UnsignedEvmCall>,
    ) -> Option<UnsignedEvmCall> {
        assert_eq!(
            out.err(),
            Some(refusal_of_the_backendless_leg()),
            "the refusal must be exactly the one the backendless leg produces"
        );
        println!("  dom leg recovery   REFUSED, by name (no cryptographic backend in this build)");
        None
    }
}

/// Opens the DOM lock on a real dom-sim chain by driving the reused G-F2 sink
/// with the engine's own funding effect — the only door to a lock.
///
/// B-DOM: `DomSimPort` is gone with the old engine composition; the DOM leg is
/// the very `SimSettlementChain`/`SimEffectSink` pair the ratified G-F2
/// harness drives, reused verbatim.
#[cfg(not(feature = "real-dom-adaptor"))]
fn open_dom_lock(lock_id: [u8; 32]) -> SimSettlementChain {
    let dom = SimSettlementChain::new(ChainId([0xAD; 32]), lock_id);
    let mut sink = SimEffectSink::new(dom.clone(), u64::MAX);
    let outcome = sink.execute(&ClaimedEffectV1 {
        settlement_id: SettlementId(lock_id),
        effect_id: EffectId([0x0E; 32]),
        kind: Effect::AuthorizeFunding,
        payload: Vec::new(),
        payload_hash: [0u8; 32],
        attempts: 0,
    });
    assert_eq!(outcome, EffectOutcome::Completed, "funding submitted");
    dom.advance(1);
    assert_eq!(dom.lock_state(), LockState::Open);
    dom
}

/// One settlement, wired to a real deployment.
struct Rig {
    rpc: SharedRpc<HttpJsonRpc>,
    cfg: EvmAdapterConfig,
    terms: LockTerms,
    t: [u8; 32],
}

impl Rig {
    /// A settlement on the native-ETH deployment.
    fn new(e: &Env, session_seed: u16, direction: Direction, deadline_from_now: u64) -> Self {
        Self::on(
            e,
            e.contract,
            [0u8; 20],
            session_seed,
            direction,
            deadline_from_now,
            NATIVE_SETTLEMENT_GAS_LIMIT,
        )
    }

    /// A settlement on an arbitrary deployment and asset.
    ///
    /// `asset == address(0)` selects the native contract's shape; anything else
    /// selects the ERC-20 contract's, where `open` carries no `msg.value` and
    /// the token is moved by `transferFrom`.
    #[allow(clippy::too_many_arguments)]
    fn on(
        e: &Env,
        contract: [u8; 20],
        asset: [u8; 20],
        session_seed: u16,
        direction: Direction,
        deadline_from_now: u64,
        gas_limit_hint: u64,
    ) -> Self {
        let rpc = SharedRpc::new(HttpJsonRpc::new(e.rpc_url.clone(), 20));
        let chain_id = EthClient::new(&rpc).chain_id().expect("chain id");
        assert_eq!(
            chain_id, e.chain_id,
            "the endpoint changed chain id underneath the run"
        );
        assert!(
            ALLOWED_CHAIN_IDS.contains(&chain_id),
            "this harness drives a local Anvil (31337) or Sepolia (11155111); the \
             endpoint reports chain id {chain_id} and there is no override"
        );
        let anvil = Anvil { rpc: &rpc };
        // The adapter reads `eth_getCode` at the **finalized** tag on purpose:
        // the codehash it pins must be the one the finalized chain agrees on.
        // So the deployment has to be finalized before anything can bind to it.
        // On a development node that is one instant `anvil_mine`; on a public
        // network the deployment simply has to be old enough, and saying so is
        // better than silently waiting a quarter of an hour.
        let code_hash = match EthClient::new(&rpc).code_hash(&contract) {
            Ok(h) => h,
            Err(_) if anvil.is_dev_node() => {
                anvil.mine(FINALITY_BLOCKS);
                EthClient::new(&rpc)
                    .code_hash(&contract)
                    .expect("the deployment must have finalized code")
            }
            Err(err) => panic!(
                "no finalized code at {}: {err:?} — the deployment must be \
                 finalized before the harness can bind to it",
                hex0x(&contract)
            ),
        };
        let start_block = anvil.block_number();
        let now = anvil.timestamp();
        let t = scalar(session_seed);
        let cfg = EvmAdapterConfig {
            chain_id,
            contract,
            expected_code_hash: code_hash,
            dom_chain_id: [0x11; 32],
            direction,
            session_id: seed_word(session_seed, 0x00),
            terms_hash: seed_word(session_seed, 0xFF),
            participants_hash: [0x44; 32],
            asset,
            beneficiary: e.account,
            funder: e.account,
            start_block,
            // Small pages keep the adapter's validated-header ring dense, which
            // is what lets it name a common ancestor after a deep reorg.
            page_size: 8,
            max_reorg_depth: 256,
            gas_limit_hint,
        };
        let terms = LockTerms {
            dom_chain_id: cfg.dom_chain_id,
            direction: direction.as_u8(),
            session_id: cfg.session_id,
            terms_hash: cfg.terms_hash,
            participants_hash: cfg.participants_hash,
            asset: cfg.asset,
            amount: word_u128(AMOUNT),
            beneficiary: cfg.beneficiary,
            adaptor_address: adaptor_address_of_scalar(&t).expect("canonical"),
            deadline: now + deadline_from_now,
        };
        Self { rpc, cfg, terms, t }
    }

    /// Rebinds the settlement to a different scalar, before anything is opened.
    ///
    /// The direction tests need the EVM lock to commit to `address(t·G)` for
    /// the *same* `t` the DOM pre-signature commits to.
    #[cfg(not(feature = "real-dom-adaptor"))]
    fn with_scalar(mut self, t: [u8; 32]) -> Self {
        self.t = t;
        self.terms.adaptor_address = adaptor_address_of_scalar(&t).expect("canonical scalar");
        self
    }

    fn deployment(&self) -> EvmDeployment {
        EvmDeployment {
            chain_id: self.cfg.chain_id,
            contract: self.cfg.contract,
            funder: self.cfg.funder,
            gas_limit_hint: self.cfg.gas_limit_hint,
        }
    }

    fn neutral(&self) -> NeutralTerms {
        NeutralTerms {
            terms_hash: self.cfg.terms_hash,
            settlement_id: self.cfg.session_id,
            amount: AMOUNT,
            deadline: self.terms.deadline,
        }
    }

    /// B-DOM: there is no `engine_height_bridge` — the refund is governed by
    /// the contract's own timestamp deadline plus the [`TimelockPolicy::evm`]
    /// margins, and no block-height instruction ever crosses onto this chain.
    fn port_config(&self) -> EvmPortConfig {
        EvmPortConfig {
            deployment: self.deployment(),
            neutral: self.neutral(),
            adaptor_point: AdaptorPointBytes(adaptor_point_of_scalar(&self.t).expect("canonical")),
            terms: self.terms,
            timelock: TimelockPolicy::evm(),
        }
    }

    fn anvil(&self) -> Anvil<'_> {
        Anvil { rpc: &self.rpc }
    }
}

type AnvilPort<'a> = EvmChainPort<HttpJsonRpc, CastBroadcaster, AnvilClock<'a>, MemoryLog>;

fn build_port<'a>(
    rig: &'a Rig,
    outbox: Outbox<MemoryLog>,
    broadcaster: CastBroadcaster,
) -> AnvilPort<'a> {
    EvmChainPort::new(
        rig.port_config(),
        rig.cfg,
        rig.rpc.clone(),
        outbox,
        broadcaster,
        AnvilClock { rpc: &rig.rpc },
    )
    .expect("well-formed port configuration")
}

fn empty_outbox() -> Outbox<MemoryLog> {
    Outbox::recover(MemoryLog::new()).expect("empty log")
}

fn banner(title: &str, rig: &Rig, lock_id: &[u8; 32], binding: &[u8; 32]) {
    let a = rig.anvil();
    println!("=== {title} ===");
    println!("  chainId            {}", rig.cfg.chain_id);
    println!("  contract           {}", hex0x(&rig.cfg.contract));
    println!(
        "  codehash           {}",
        hex0x(&rig.cfg.expected_code_hash)
    );
    println!("  direction          {:?}", rig.cfg.direction);
    println!("  sessionId          {}", hex0x(&rig.cfg.session_id));
    println!("  binding            {}", hex0x(binding));
    println!("  lockId             {}", hex0x(lock_id));
    println!("  adaptorAddress     {}", hex0x(&rig.terms.adaptor_address));
    println!("  deadline           {}", rig.terms.deadline);
    println!("  start block        {}", rig.cfg.start_block);
    println!(
        "  latest / finalized {} / {}",
        a.block_number(),
        a.finalized()
    );
}

fn report(tag: &str, r: &Receipt) {
    println!(
        "  {tag:<18} tx {} in block {} ({})",
        r.tx_hash, r.block_number, r.block_hash
    );
}

// ---------------------------------------------------------------------------
// 1. EVM -> DOM, against the real contract
// ---------------------------------------------------------------------------

#[test]
#[cfg(not(feature = "real-dom-adaptor"))]
#[ignore = "needs a running Anvil; run ./scripts/e2e_anvil.sh"]
fn anvil_evm_to_dom_direction() {
    let Some(e) = env() else {
        return;
    };
    let dom_leg = dom_leg_fixture(0x21);
    let rig = Rig::new(&e, 0x21, Direction::EvmToDom, 86_400).with_scalar(dom_leg.t);
    let anvil = rig.anvil();
    let mut port = build_port(&rig, empty_outbox(), CastBroadcaster::new(&e));
    let (binding, lock_id) = port.identity().expect("derivation");
    banner(
        "G-F3 / EVM->DOM / real ConditionLockV2",
        &rig,
        &lock_id,
        &binding,
    );

    // --- fund the EVM leg with the adapter's unsigned artifact -------------
    // B-DOM: driver-level, not engine-level — the ratified engine models the
    // DOM leg only, so the EVM leg is driven directly through the port.
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    report("open", &port.broadcaster().last());
    anvil.advance_to_finality();

    let (events, cursor) = port.observe(&ChainCursor::default());
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, ObservedEvent::LockOpened { .. })),
        "the finalized LockOpened must be observed: {events:?}"
    );

    // --- the counterparty claims on the EVM leg, publishing `t` -----------
    // The claim artifact is built by the harness and signed outside it.
    let claim = build_claim_call(&rig.deployment(), lock_id, binding, &rig.t).expect("claim call");
    assert_eq!(
        port.submit_claim(&claim).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    let claim_receipt = port.broadcaster().last();
    report("claim", &claim_receipt);
    anvil.advance_to_finality();

    let (events, _) = port.observe(&cursor);
    let revealed = events
        .iter()
        .find_map(|ev| match ev {
            ObservedEvent::LockClaimed { revealed, .. } => Some(*revealed),
            _ => None,
        })
        .expect("the finalized Claimed log must be observed");
    assert_eq!(
        revealed.0, rig.t,
        "`t` must come back byte-identical out of a real on-chain log"
    );
    println!("  t extracted from   a real on-chain Claimed log (value redacted)");

    // The native push must actually have fired. With an estimator-chosen limit
    // it would not have — see `f3_harness::gas` — so this assertion is what
    // keeps the native leg's happy path honest as well.
    let deferred = logs_by_topic0(
        &rig.rpc,
        &rig.cfg.contract,
        event_topic0(SIG_PAYOUT_DEFERRED),
        rig.cfg.start_block,
        anvil.block_number(),
    );
    assert!(
        deferred.is_empty(),
        "the native payout must have been pushed, not deferred: {deferred:?}"
    );
    assert_eq!(
        pending_credit(&rig.rpc, &rig.cfg.contract, &e.account, &[0u8; 20]),
        [0u8; 32],
        "a pushed native payout books no pull credit"
    );
    println!("  PayoutDeferred     none (native push delivered at the pinned limit)");

    // --- canonical evidence, verified against the chain -------------------
    let evidence = port
        .adapter()
        .collect_evidence(&lock_id, EvidenceKind::Claimed)
        .expect("evidence");
    println!(
        "  evidence           block {} tx {} finalized {}",
        evidence.block_number,
        hex0x(&evidence.tx_hash),
        evidence.finalized_height
    );
    let outcome = pollster::block_on(async {
        use counterparty_api::CounterpartyAdapter;
        port.adapter().verify_evidence(&evidence.encode()).await
    })
    .expect("evidence must verify");
    assert!(matches!(outcome, VerifiedOutcome::Claimed { .. }));

    // --- the DOM leg: fund it on dom-sim, then run the route --------------
    // The DOM leg is the reused F2 sim chain, and the only door to an open
    // lock is the engine-shaped funding effect through `SimEffectSink`.
    let dom = open_dom_lock(lock_id);

    let dom_policy = TimelockPolicy::dom_sim();
    let out = evm_to_dom(
        &dom_leg.session,
        &dom_policy,
        &EvmToDomInput {
            deployment: rig.deployment(),
            terms: rig.terms,
            observed_lock_id: lock_id,
            observed_binding: binding,
            observed_height: evidence.block_number,
            finalized_height: evidence.finalized_height,
            revealed,
            pre_signature: &dom_leg.pre,
            dom_now: TimelockPoint::height(dom.height()),
            dom_deadline: TimelockPoint::height(dom.height() + dom_policy.total_margin() + 10),
        },
    );

    match dom_leg.check_evm_to_dom(out) {
        // The DOM leg adapted the pre-signature: the authorised claim settles
        // the DOM leg, and nothing else could have. (Unreachable in this
        // build — kept so the authorised path has exactly one shape.)
        Some(authorisation) => {
            assert!(
                matches!(
                    f3_harness::submit_dom_claim(&dom, &authorisation, &revealed),
                    adapter_dom_sim::SubmitResult::Accepted { .. }
                ),
                "an authorised DOM claim must reach the DOM leg"
            );
            dom.advance(2);
            assert_eq!(dom.lock_state(), LockState::Spent);
            println!("  dom-sim lock       Spent (settled by the authorised DOM claim)");
        }
        // FAIL-CLOSED: no authorisation, so no DOM claim can be submitted —
        // `submit_dom_claim` is unreachable without one. The lock staying
        // Open is the same fact the v0.5 suite read off the DOM scan.
        None => {
            dom.advance(2);
            assert_eq!(
                dom.lock_state(),
                LockState::Open,
                "no DOM claim may exist without an authorisation"
            );
            println!("  dom-sim lock       still Open (nothing settled without the DOM leg)");
        }
    }
}

// ---------------------------------------------------------------------------
// 2. DOM -> EVM, against the real contract
// ---------------------------------------------------------------------------

#[test]
#[cfg(not(feature = "real-dom-adaptor"))]
#[ignore = "needs a running Anvil; run ./scripts/e2e_anvil.sh"]
fn anvil_dom_to_evm_direction() {
    let Some(e) = env() else {
        return;
    };
    let dom_leg = dom_leg_fixture(0x33);
    let rig = Rig::new(&e, 0x33, Direction::DomToEvm, 86_400).with_scalar(dom_leg.t);
    let anvil = rig.anvil();
    let mut port = build_port(&rig, empty_outbox(), CastBroadcaster::new(&e));
    let (binding, lock_id) = port.identity().expect("derivation");
    banner(
        "G-F3 / DOM->EVM / real ConditionLockV2",
        &rig,
        &lock_id,
        &binding,
    );

    // --- the DOM leg is claimed first (dom-sim chain semantics) -----------
    // The spent lock is the same fact the v0.5 suite read off the DOM scan.
    let dom = open_dom_lock(lock_id);
    assert!(
        matches!(
            dom.submit_claim(rig.t),
            adapter_dom_sim::SubmitResult::Accepted { .. }
        ),
        "the DOM claim must be accepted by the sim chain"
    );
    dom.advance(1);
    assert_eq!(
        dom.lock_state(),
        LockState::Spent,
        "the DOM lock must be spent before the DOM->EVM route runs"
    );
    println!("  dom-sim leg        claimed (chain semantics only, no cryptography)");

    // --- the EVM leg is funded, so there is something to claim ------------
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    report("open", &port.broadcaster().last());
    anvil.advance_to_finality();
    let (events, cursor) = port.observe(&ChainCursor::default());
    assert!(events
        .iter()
        .any(|ev| matches!(ev, ObservedEvent::LockOpened { .. })));

    // --- the route: recover the scalar, then claim ------------------------
    let out = dom_to_evm(
        &dom_leg.session,
        &TimelockPolicy::evm(),
        &DomToEvmInput {
            deployment: rig.deployment(),
            terms: rig.terms,
            pre_signature: &dom_leg.pre,
            final_signature: &dom_leg.final_signature,
            evm_now: TimelockPoint::timestamp(anvil.timestamp()),
        },
    );

    // When the DOM leg recovered the scalar, the artifact broadcast below is
    // the very one the route produced — nothing is rebuilt from a value this
    // test happens to hold. When it refused, no artifact exists and the
    // remainder of the direction is exercised with the test's own scalar,
    // which is NOT a stand-in for a successful recovery: the named refusal
    // above is what the gate rests on.
    let claim = match dom_leg.check_dom_to_evm(out) {
        Some(call) => {
            assert_eq!(call.lock_id, lock_id, "the route's artifact is this lock's");
            assert_eq!(call.binding, binding);
            call
        }
        None => build_claim_call(&rig.deployment(), lock_id, binding, &rig.t).expect("claim call"),
    };
    assert_eq!(
        port.submit_claim(&claim).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    report("claim", &port.broadcaster().last());
    anvil.advance_to_finality();
    let (events, _) = port.observe(&cursor);
    let revealed = events
        .iter()
        .find_map(|ev| match ev {
            ObservedEvent::LockClaimed { revealed, .. } => Some(*revealed),
            _ => None,
        })
        .expect("the finalized Claimed log must be observed");
    assert_eq!(revealed.0, rig.t);
    assert_eq!(
        port.revealed_secret(&lock_id).expect("registry"),
        Some(RevealedSecretBytes(rig.t))
    );
}

// ---------------------------------------------------------------------------
// 3. reorg
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs a running Anvil; run ./scripts/e2e_anvil.sh"]
fn anvil_reorg_rewinds_to_the_common_ancestor_and_t_stays_known() {
    let Some(e) = env() else {
        return;
    };
    let rig = Rig::new(&e, 0x45, Direction::EvmToDom, 86_400);
    let anvil = rig.anvil();
    if !anvil.is_dev_node() {
        // Rolling the chain back is a development-node capability. On a public
        // network this scenario is not skipped quietly, it is reported as not
        // applicable.
        skip_not_a_dev_node("G-F3 / reorg", "evm_snapshot/evm_revert");
        return;
    }
    let mut port = build_port(&rig, empty_outbox(), CastBroadcaster::new(&e));
    let (binding, lock_id) = port.identity().expect("derivation");
    banner("G-F3 / reorg", &rig, &lock_id, &binding);

    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    report("open", &port.broadcaster().last());
    anvil.advance_to_finality();
    let (_, cursor) = port.observe(&ChainCursor::default());

    // The fork point: everything from here up is what the reorg will orphan.
    let fork_height = anvil.block_number();
    let snapshot = anvil.snapshot();
    println!("  fork point         block {fork_height}");

    let claim = build_claim_call(&rig.deployment(), lock_id, binding, &rig.t).expect("claim call");
    port.submit_claim(&claim).expect("broadcast");
    let claim_receipt = port.broadcaster().last();
    report("claim", &claim_receipt);
    anvil.advance_to_finality();
    let (events, cursor) = port.observe(&cursor);
    assert!(events
        .iter()
        .any(|ev| matches!(ev, ObservedEvent::LockClaimed { .. })));
    assert_eq!(
        port.revealed_secret(&lock_id).expect("registry"),
        Some(RevealedSecretBytes(rig.t)),
        "the scalar must be known before the reorg"
    );

    // Orphan the claim's block — which sits *below* Anvil's finalized
    // checkpoint. Real Ethereum would not do that; the adapter has to cope
    // honestly with an endpoint that does.
    let orphaned_latest = anvil.block_number();
    let old_hash = claim_receipt.block_hash.clone();
    println!(
        "  reverting          {orphaned_latest} -> {fork_height} (claim block {}, finalized {})",
        claim_receipt.block_number,
        anvil.finalized()
    );
    anvil.revert(&snapshot);
    assert_eq!(anvil.block_number(), fork_height);
    // Rebuild a longer chain on the other fork, so the observer's anchor is
    // both orphaned and below the new finalized checkpoint.
    anvil.mine(orphaned_latest - fork_height + FINALITY_BLOCKS);
    let new_hash = anvil.block_hash(claim_receipt.block_number);
    assert_ne!(
        old_hash, new_hash,
        "the claim's block must have been re-mined"
    );
    println!("  claim block hash   {old_hash} -> {new_hash}");

    let (events, rewound) = port.observe(&cursor);
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, ObservedEvent::Reorged { .. })),
        "the adapter must report the reorg rather than swallow it: {events:?} \
         (last error {:?})",
        port.last_error()
    );
    let from_height = events
        .iter()
        .find_map(|ev| match ev {
            ObservedEvent::Reorged { from_height } => Some(*from_height),
            _ => None,
        })
        .expect("a reorg event");
    println!("  common ancestor    rewound to resume at block {from_height}");
    assert!(
        from_height <= claim_receipt.block_number,
        "the rewind must reach at or below the orphaned block"
    );
    assert_ne!(rewound, cursor, "the cursor must be rewound");

    // I11: the settlement effect is gone; the publicity of `t` is not.
    assert_eq!(
        port.revealed_secret(&lock_id).expect("registry"),
        Some(RevealedSecretBytes(rig.t)),
        "a reorg must never un-reveal a scalar"
    );
    anvil.advance_to_finality();
    let (events, _) = port.observe(&rewound);
    assert!(
        !events
            .iter()
            .any(|ev| matches!(ev, ObservedEvent::LockClaimed { .. })),
        "the orphaned claim must not reappear: {events:?}"
    );
    assert_eq!(
        port.revealed_secret(&lock_id).expect("registry"),
        Some(RevealedSecretBytes(rig.t))
    );
    println!("  after replay       claim gone, t still known");
}

// ---------------------------------------------------------------------------
// 4. crash recovery
// ---------------------------------------------------------------------------

/// One settlement, optionally interrupted by a crash between funding and
/// claim, returning (finalized claim observed with this settlement's `t` and
/// the scalar captured, claim evidence collectible).
///
/// B-DOM RE-SCOPE: the v0.5 suite drove this scenario through
/// `Engine::start`/`Engine::recover` + `tick()` with the EVM port as the
/// engine's `ChainPort`, and compared `SettlementState`s across the crash.
/// `main`'s ratified §24 engine models the DOM leg only (the B-DOM finding in
/// `docs/normative/F3-F5-RECONCILIATION-PLAN.md`), so the EVM leg is driven
/// directly and what is compared across the crash is the observable chain
/// facts: everything durable — the outbox log and the chain itself — comes
/// back; the adapter's in-memory knowledge is rebuilt from the configured
/// terms, and the cursor legitimately dies with the process and is rebuilt by
/// rescanning from genesis. The engine-state comparison had no EVM-side
/// content beyond these facts, and they all survive below.
fn run_anvil_scenario(e: &Env, seed: u16, crash: bool) -> (bool, bool) {
    let rig = Rig::new(e, seed, Direction::EvmToDom, 86_400);
    let anvil = rig.anvil();
    let mut port = build_port(&rig, empty_outbox(), CastBroadcaster::new(e));
    let (binding, lock_id) = port.identity().expect("derivation");
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    anvil.advance_to_finality();
    let (events, mut cursor) = port.observe(&ChainCursor::default());
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, ObservedEvent::LockOpened { .. })),
        "the finalized LockOpened must be observed: {events:?}"
    );

    if crash {
        // The process dies. The chain does not. Everything durable comes back;
        // the outbox is replayed from its log, the adapter's in-memory
        // knowledge is rebuilt from the configured terms, and the in-memory
        // cursor is rebuilt by rescanning from genesis.
        let (outbox, broadcaster, _clock) = port.into_parts();
        let outbox = Outbox::recover(outbox.into_log()).expect("durable replay");
        port = build_port(&rig, outbox, broadcaster);
        cursor = ChainCursor::default();
        // I7: recovery must never fund the lock twice. The replayed record is
        // resent byte-identical and deduplicated, not recomputed.
        assert!(
            matches!(
                port.submit_funding(lock_id).expect("resend"),
                BroadcastOutcome::Accepted | BroadcastOutcome::Duplicate
            ),
            "a resend after recovery must be safe"
        );
        let (_, next) = port.observe(&cursor);
        cursor = next;
    }

    // The claim goes through the port the driver owns, so it goes through the
    // same outbox.
    let claim = build_claim_call(&rig.deployment(), lock_id, binding, &rig.t).expect("claim call");
    assert_eq!(
        port.submit_claim(&claim).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    anvil.advance_to_finality();
    let mut claim_observed = false;
    for _ in 0..3 {
        let (events, next) = port.observe(&cursor);
        cursor = next;
        if events.iter().any(
            |ev| matches!(ev, ObservedEvent::LockClaimed { revealed, .. } if revealed.0 == rig.t),
        ) {
            claim_observed = true;
        }
    }
    let secret_captured = port.revealed_secret(&lock_id).expect("registry").is_some();
    let evidence_ok = port
        .adapter()
        .collect_evidence(&lock_id, EvidenceKind::Claimed)
        .is_ok();
    (claim_observed && secret_captured, evidence_ok)
}

#[test]
#[ignore = "needs a running Anvil; run ./scripts/e2e_anvil.sh"]
fn anvil_engine_crash_recovers_to_the_same_outcome() {
    // The name survives from the v0.5 suite (the wrapper script asserts every
    // scenario ran, by name); the "engine" whose crash is recovered is now the
    // EVM-leg driver — see `run_anvil_scenario` for the B-DOM re-scope.
    let Some(e) = env() else {
        return;
    };
    println!("=== G-F3 / driver crash on Anvil ===");
    // Two settlements rather than one replayed twice: the chain is real and
    // append-only, so the no-crash baseline and the crashed run each need their
    // own lock. The scalars therefore differ, and what is compared is the
    // outcome and *whether* the scalar was captured — never the scalar itself
    // (I6: it is not printed and not compared by value across runs).
    let baseline = run_anvil_scenario(&e, 0x57, false);
    println!(
        "  baseline           claim observed: {}, evidence collectible: {}",
        baseline.0, baseline.1
    );
    let crashed = run_anvil_scenario(&e, 0x69, true);
    println!(
        "  after crash        claim observed: {}, evidence collectible: {}",
        crashed.0, crashed.1
    );
    assert!(
        baseline.0,
        "the baseline settlement must observe its finalized claim and capture the scalar"
    );
    assert_eq!(baseline.0, crashed.0, "the crash changed the outcome");
    assert_eq!(
        baseline.1, crashed.1,
        "the crash changed whether the claim evidence is collectible"
    );
    assert!(crashed.1);
}

// ---------------------------------------------------------------------------
// 5. refund by deadline
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs a running Anvil; run ./scripts/e2e_anvil.sh"]
fn anvil_refund_by_deadline() {
    let Some(e) = env() else {
        return;
    };
    // B-DOM RE-SCOPE: the v0.5 scenario declared a `DeclaredDomainBridge` so
    // the engine's block-height refund instruction could be translated onto
    // the timestamp chain, and asserted the port refused without one. Under
    // B-DOM no height instruction ever crosses onto this chain, so the bridge
    // and its declaration mechanics are gone; what survives — unchanged — is
    // the margin/deadline discipline asserted below: the refund is refused,
    // by name, until the contract's own timestamp deadline is *safely* past,
    // and the contract itself enforces the deadline independently.
    let rig = Rig::new(&e, 0x7B, Direction::EvmToDom, 600);
    let anvil = rig.anvil();
    if !anvil.is_dev_node() {
        // `evm_increaseTime` is a development-node capability. Against a public
        // network the deadline has to be waited out for real, which is a
        // different (much longer) scenario than this one — and it is the one
        // `scripts/sepolia.sh` drives directly with `cast`.
        skip_not_a_dev_node("G-F3 / refund by deadline", "evm_increaseTime");
        return;
    }
    let mut port = build_port(&rig, empty_outbox(), CastBroadcaster::new(&e));
    let (binding, lock_id) = port.identity().expect("derivation");
    banner("G-F3 / refund by deadline", &rig, &lock_id, &binding);

    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    report("open", &port.broadcaster().last());
    anvil.advance_to_finality();
    let (events, cursor) = port.observe(&ChainCursor::default());
    assert!(events
        .iter()
        .any(|ev| matches!(ev, ObservedEvent::LockOpened { .. })));

    // Before the deadline the refund is refused — by the harness's margins
    // and, independently, by the contract itself.
    assert!(
        matches!(
            port.submit_refund(lock_id).unwrap_err(),
            HarnessError::Timelock(TimelockError::WindowTooNarrow { .. })
        ),
        "before the deadline the refusal is the margin, not a broadcast"
    );
    assert_eq!(port.stats().refunds_refused_for_timelock, 1);

    let p = TimelockPolicy::evm();
    let jump = 600 + p.finality_margin + p.rpc_lag_margin + 60;
    anvil.increase_time(jump);
    println!("  time advanced by   {jump}s (now {})", anvil.timestamp());

    assert_eq!(
        port.submit_refund(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    report("refund", &port.broadcaster().last());
    anvil.advance_to_finality();
    let (events, _) = port.observe(&cursor);
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, ObservedEvent::LockRefunded { .. })),
        "the finalized Refunded log must be observed: {events:?}"
    );
    println!("  refund observed    on the real contract, after the real deadline");

    for r in port.broadcaster().receipts() {
        report(r.what, &r);
    }
}

// ---------------------------------------------------------------------------
// 6. the ERC-20 leg
// ---------------------------------------------------------------------------

/// Canonical signatures of the calls the ERC-20 scenarios make that are *not*
/// settlement artifacts. Spelled out here rather than reused from
/// `adapter_evm::abi`, because the adapter deliberately knows nothing about
/// tokens or about the pull-withdrawal surface.
const SIG_ERC20_APPROVE: &str = "approve(address,uint256)";
const SIG_ERC20_BALANCE_OF: &str = "balanceOf(address)";
const SIG_PENDING_WITHDRAWALS: &str = "pendingWithdrawals(address,address)";
const SIG_WITHDRAW: &str = "withdraw(address)";
const SIG_WITHDRAW_AMOUNT: &str = "withdrawAmount(address,address,uint256)";

fn calldata(signature: &str, words: &[[u8; 32]]) -> Vec<u8> {
    let mut out = selector(signature).to_vec();
    out.extend_from_slice(&concat_words(words).expect("bounded word count"));
    out
}

/// `eth_call` returning the first 32-byte word of the result.
fn eth_call_word(rpc: &SharedRpc<HttpJsonRpc>, to: &[u8; 20], data: &[u8]) -> [u8; 32] {
    let v = rpc_read(
        rpc,
        "eth_call",
        "eth_call",
        json!([{ "to": hex0x(to), "input": hex0x(data) }, "latest"]),
    );
    let s = v.as_str().expect("hex result");
    let body = s.strip_prefix("0x").expect("0x prefix");
    assert!(body.len() >= 64, "expected at least one word, got {s}");
    let mut out = [0u8; 32];
    for (i, pair) in body.as_bytes()[..64].chunks_exact(2).enumerate() {
        let hi = char::from(pair[0]).to_digit(16).expect("hex");
        let lo = char::from(pair[1]).to_digit(16).expect("hex");
        out[i] = ((hi << 4) | lo) as u8;
    }
    out
}

/// Narrows a `uint256` word to a `u128`, refusing anything wider. Every amount
/// in this harness is far below 2^128, so a wide value means something is wrong
/// rather than something is large.
fn word_to_u128(w: &[u8; 32]) -> u128 {
    assert_eq!(&w[..16], &[0u8; 16], "value wider than u128");
    u128::from_be_bytes(w[16..].try_into().expect("16 bytes"))
}

fn token_balance(rpc: &SharedRpc<HttpJsonRpc>, token: &[u8; 20], who: &[u8; 20]) -> [u8; 32] {
    eth_call_word(
        rpc,
        token,
        &calldata(SIG_ERC20_BALANCE_OF, &[word_address(*who)]),
    )
}

fn pending_credit(
    rpc: &SharedRpc<HttpJsonRpc>,
    lock: &[u8; 20],
    who: &[u8; 20],
    asset: &[u8; 20],
) -> [u8; 32] {
    eth_call_word(
        rpc,
        lock,
        &calldata(
            SIG_PENDING_WITHDRAWALS,
            &[word_address(*who), word_address(*asset)],
        ),
    )
}

/// Block span of ONE `eth_getLogs` request in [`logs_by_topic0`].
///
/// Hosted endpoints cap the block range a single `eth_getLogs` may span,
/// and refuse anything wider — deterministically, in the same second,
/// while narrow reads on the same endpoint keep working. The F4 gate run
/// of 2026-08-10 proved it with a probe:
///
/// ```text
/// probe eth_getLogs single-block [11461550,11461550]: ok, 0 logs
/// probe eth_getLogs full-window  [11461550,11461707]: ERR AdapterUnavailable
/// ```
///
/// The adapter's own observer was paged at `page_size: 8` for that
/// reason. This raw helper was not, and on 2026-08-10 it killed the G-F3
/// Sepolia run: `anvil_evm_to_dom_direction` waited through two finality
/// windows, its `start_block .. head` span grew past the cap, and the
/// refusal that followed was not transient — so [`rpc_read`] retried it
/// ten times and spent ~16 minutes backing off before failing. (The very
/// next direction test then passed clean on the same endpoint, which is
/// how we know it was never an outage.)
///
/// Matching the adapter's page size keeps ONE constant governing every
/// log read in the harness.
const LOGS_PAGE_BLOCKS: u64 = 8;

/// Raw `eth_getLogs` for one `topic0`, used for the two events the adapter does
/// not observe (`PayoutDeferred`, `Withdrawal`).
///
/// Finding a log this way is itself a conformance check: the filter uses the
/// `topic0` computed from `adapter_evm::abi`'s pinned signature string, so a
/// drift between that string and the deployed contract would return nothing.
///
/// The range is walked in [`LOGS_PAGE_BLOCKS`] windows. Paging changes
/// nothing about what is asserted: `from ..= to` is still covered end to
/// end, in ascending order, with no block skipped and no result dropped —
/// only the number of round trips changes. Each page names its own bounds
/// in the retry message, so a future range refusal is legible as one
/// instead of being mistaken for an endpoint outage.
fn logs_by_topic0(
    rpc: &SharedRpc<HttpJsonRpc>,
    address: &[u8; 20],
    topic0: [u8; 32],
    from: u64,
    to: u64,
) -> Vec<Value> {
    let mut out = Vec::new();
    for (page_from, page_to) in log_pages(from, to) {
        let v = rpc_read(
            rpc,
            &format!("eth_getLogs [{page_from},{page_to}]"),
            "eth_getLogs",
            json!([{
                "fromBlock": format!("0x{page_from:x}"),
                "toBlock": format!("0x{page_to:x}"),
                "address": hex0x(address),
                "topics": [hex0x(&topic0)],
            }]),
        );
        if let Some(logs) = v.as_array() {
            out.extend(logs.iter().cloned());
        }
    }
    out
}

/// The inclusive page bounds covering `from ..= to`.
///
/// Split out so the walk is testable WITHOUT a node: an off-by-one here
/// would skip a block, and a skipped block does not fail loudly — it
/// makes `assert!(deferred.is_empty())` pass for the wrong reason. That
/// is the failure mode this helper exists to make impossible, so it is
/// covered by [`log_pages_cover_every_block_exactly_once`], which runs in
/// the ordinary gate and needs no network.
fn log_pages(from: u64, to: u64) -> Vec<(u64, u64)> {
    let mut pages = Vec::new();
    if from > to {
        return pages;
    }
    let mut page_from = from;
    loop {
        let page_to = page_from.saturating_add(LOGS_PAGE_BLOCKS - 1).min(to);
        pages.push((page_from, page_to));
        if page_to >= to {
            return pages;
        }
        page_from = page_to + 1;
    }
}

/// The page walk covers `from ..= to` exactly once: contiguous, ascending,
/// nothing skipped, nothing repeated, no page wider than the cap.
///
/// NOT `#[ignore]`d — it needs no node, so the ordinary gate runs it.
#[test]
fn log_pages_cover_every_block_exactly_once() {
    for (from, to) in [
        (0u64, 0u64),
        (10, 10),
        (10, 11),
        (10, 17),                 // exactly one full page
        (10, 18),                 // one full page plus one block
        (100, 330),               // the span that broke the 2026-08-10 run
        (u64::MAX - 3, u64::MAX), // no wrap at the top of the range
    ] {
        let pages = log_pages(from, to);
        assert!(!pages.is_empty(), "[{from},{to}] produced no page");
        assert_eq!(pages[0].0, from, "[{from},{to}] does not start at `from`");
        assert_eq!(
            pages[pages.len() - 1].1,
            to,
            "[{from},{to}] does not end at `to`"
        );
        for (index, (page_from, page_to)) in pages.iter().enumerate() {
            assert!(page_from <= page_to, "[{from},{to}] page {index} inverted");
            assert!(
                page_to - page_from < LOGS_PAGE_BLOCKS,
                "[{from},{to}] page {index} is wider than the cap"
            );
            if index > 0 {
                assert_eq!(
                    *page_from,
                    pages[index - 1].1 + 1,
                    "[{from},{to}] page {index} is not contiguous with its predecessor"
                );
            }
        }
    }

    // An empty range asks for nothing and must issue no request.
    assert!(log_pages(10, 9).is_empty());
}

fn log_data_word(log: &Value) -> [u8; 32] {
    let s = log.get("data").and_then(|d| d.as_str()).expect("data");
    let body = s.strip_prefix("0x").expect("0x prefix");
    assert!(body.len() >= 64, "expected at least one data word");
    let mut out = [0u8; 32];
    for (i, pair) in body.as_bytes()[..64].chunks_exact(2).enumerate() {
        let hi = char::from(pair[0]).to_digit(16).expect("hex");
        let lo = char::from(pair[1]).to_digit(16).expect("hex");
        out[i] = ((hi << 4) | lo) as u8;
    }
    out
}

/// `approve(lock, amount)` on `token`, from the funder. Not a settlement
/// artifact, so it does not go through the outbox.
fn approve(e: &Env, token: &[u8; 20], spender: &[u8; 20], amount: u128) -> Receipt {
    cast_send(
        &e.cast,
        &e.rpc_url,
        &e.key,
        "approve",
        token,
        &calldata(
            SIG_ERC20_APPROVE,
            &[word_address(*spender), word_u128(amount)],
        ),
        None,
        Some(120_000),
    )
    .expect("approve must succeed")
}

#[test]
#[ignore = "needs a running Anvil; run ./scripts/e2e_anvil.sh"]
fn anvil_erc20_open_claim_and_observe() {
    let Some(e) = env() else {
        return;
    };
    let (lock_addr, token, _) = erc20_env(&e);
    // The named limit, not an estimate: see `f3_harness::gas`. Below the
    // contract's payout floor the push is skipped and every beneficiary pays
    // for a second transaction, and the estimator would pick exactly that.
    let rig = Rig::on(
        &e,
        lock_addr,
        token,
        0x8D,
        Direction::EvmToDom,
        86_400,
        ERC20_SETTLEMENT_GAS_LIMIT,
    );
    let anvil = rig.anvil();
    let mut port = build_port(&rig, empty_outbox(), CastBroadcaster::new(&e));
    let (binding, lock_id) = port.identity().expect("derivation");
    banner(
        "G-F3 / ERC-20 / real ConditionLockERC20V2",
        &rig,
        &lock_id,
        &binding,
    );
    println!("  token             {}", hex0x(&token));

    let funder_before = token_balance(&rig.rpc, &token, &e.account);
    report("approve", &approve(&e, &token, &lock_addr, AMOUNT));

    // --- open: the artifact carries no msg.value; the token moves by transferFrom
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    let open_receipt = port.broadcaster().last();
    report("open", &open_receipt);
    let locked = token_balance(&rig.rpc, &token, &lock_addr);
    assert_eq!(
        locked,
        word_u128(AMOUNT),
        "the lock must hold exactly amount"
    );

    anvil.advance_to_finality();
    let (events, cursor) = port.observe(&ChainCursor::default());
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, ObservedEvent::LockOpened { .. })),
        "the finalized LockOpened must be observed: {events:?}"
    );

    // --- claim: publishes `t` and pushes the tokens to the beneficiary -----
    let claim = build_claim_call(&rig.deployment(), lock_id, binding, &rig.t).expect("claim call");
    assert_eq!(
        port.submit_claim(&claim).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    let claim_receipt = port.broadcaster().last();
    report("claim", &claim_receipt);
    anvil.advance_to_finality();

    let (events, _) = port.observe(&cursor);
    let revealed = events
        .iter()
        .find_map(|ev| match ev {
            ObservedEvent::LockClaimed { revealed, .. } => Some(*revealed),
            _ => None,
        })
        .expect("the finalized Claimed log must be observed");
    assert_eq!(
        revealed.0, rig.t,
        "`t` must survive a real on-chain round trip"
    );
    println!("  t observed         from a real on-chain Claimed log (value redacted)");
    println!("  finalized at obs.  {}", anvil.finalized());

    // A well-behaved token fits inside the 30k stipend, so the push delivers
    // everything: the lock ends empty, the beneficiary whole, and — under the
    // new shortfall semantics — nothing is deferred at all.
    assert_eq!(
        token_balance(&rig.rpc, &token, &lock_addr),
        [0u8; 32],
        "the lock must hold nothing after a fully delivered push"
    );
    assert_eq!(
        token_balance(&rig.rpc, &token, &e.account),
        funder_before,
        "funder == beneficiary here, so the round trip must be exactly neutral"
    );
    let deferred = logs_by_topic0(
        &rig.rpc,
        &lock_addr,
        event_topic0(SIG_PAYOUT_DEFERRED),
        open_receipt.block_number,
        anvil.block_number(),
    );
    assert!(
        deferred.is_empty(),
        "a fully delivered push must emit no PayoutDeferred: {deferred:?}"
    );
    println!("  PayoutDeferred     none (full push delivered)");

    // --- evidence -----------------------------------------------------------
    let evidence = port
        .adapter()
        .collect_evidence(&lock_id, EvidenceKind::Claimed)
        .expect("evidence");
    let outcome = pollster::block_on(async {
        use counterparty_api::CounterpartyAdapter;
        port.adapter().verify_evidence(&evidence.encode()).await
    })
    .expect("evidence must verify");
    assert!(matches!(outcome, VerifiedOutcome::Claimed { .. }));
    println!(
        "  evidence           block {} tx {} finalized {}",
        evidence.block_number,
        hex0x(&evidence.tx_hash),
        evidence.finalized_height
    );
}

#[test]
#[ignore = "needs a running Anvil; run ./scripts/e2e_anvil.sh"]
fn anvil_erc20_refund_by_deadline() {
    let Some(e) = env() else {
        return;
    };
    let (lock_addr, token, _) = erc20_env(&e);
    let rig = Rig::on(
        &e,
        lock_addr,
        token,
        0x9E,
        Direction::EvmToDom,
        600,
        ERC20_SETTLEMENT_GAS_LIMIT,
    );
    let anvil = rig.anvil();
    if !anvil.is_dev_node() {
        skip_not_a_dev_node("G-F3 / ERC-20 refund by deadline", "evm_increaseTime");
        return;
    }
    // B-DOM RE-SCOPE: as in `anvil_refund_by_deadline`, the v0.5
    // `DeclaredDomainBridge` is gone — no height instruction crosses onto the
    // timestamp chain — and the margin/deadline assertions survive unchanged.
    let mut port = build_port(&rig, empty_outbox(), CastBroadcaster::new(&e));
    let (binding, lock_id) = port.identity().expect("derivation");
    banner("G-F3 / ERC-20 refund by deadline", &rig, &lock_id, &binding);
    println!("  token             {}", hex0x(&token));

    report("approve", &approve(&e, &token, &lock_addr, AMOUNT));
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    report("open", &port.broadcaster().last());
    anvil.advance_to_finality();
    let (events, cursor) = port.observe(&ChainCursor::default());
    assert!(events
        .iter()
        .any(|ev| matches!(ev, ObservedEvent::LockOpened { .. })));

    assert!(
        matches!(
            port.submit_refund(lock_id).unwrap_err(),
            HarnessError::Timelock(TimelockError::WindowTooNarrow { .. })
        ),
        "before the deadline the refusal is the margin, not a broadcast"
    );

    let p = TimelockPolicy::evm();
    anvil.increase_time(600 + p.finality_margin + p.rpc_lag_margin + 60);
    assert_eq!(
        port.submit_refund(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    report("refund", &port.broadcaster().last());
    anvil.advance_to_finality();
    let (events, _) = port.observe(&cursor);
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, ObservedEvent::LockRefunded { .. })),
        "the finalized Refunded log must be observed: {events:?}"
    );
    assert_eq!(
        token_balance(&rig.rpc, &token, &lock_addr),
        [0u8; 32],
        "the refund must return the whole token balance to the funder"
    );
    println!("  finalized at obs.  {}", anvil.finalized());
}

#[test]
#[ignore = "needs a running Anvil; run ./scripts/e2e_anvil.sh"]
fn anvil_erc20_deferred_payout_then_withdraw_in_instalments() {
    let Some(e) = env() else {
        return;
    };
    let (lock_addr, _, heavy) = erc20_env(&e);
    // `HeavyToken` is honest but journals every transfer, so its `transfer`
    // costs far more than the contract's 30k push stipend. The push therefore
    // provably delivers nothing, the SHORTFALL — here the whole amount — is
    // booked as a pull credit, and `PayoutDeferred` carries that shortfall.
    let rig = Rig::on(
        &e,
        lock_addr,
        heavy,
        0xB4,
        Direction::EvmToDom,
        86_400,
        ERC20_SETTLEMENT_GAS_LIMIT,
    );
    let anvil = rig.anvil();
    let mut port = build_port(&rig, empty_outbox(), CastBroadcaster::new(&e));
    let (binding, lock_id) = port.identity().expect("derivation");
    banner(
        "G-F3 / ERC-20 deferred payout + withdrawal",
        &rig,
        &lock_id,
        &binding,
    );
    println!("  token (heavy)     {}", hex0x(&heavy));

    let account = e.account;
    let before = token_balance(&rig.rpc, &heavy, &account);
    report("approve", &approve(&e, &heavy, &lock_addr, AMOUNT));
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    let open_receipt = port.broadcaster().last();
    report("open", &open_receipt);
    anvil.advance_to_finality();
    let (events, cursor) = port.observe(&ChainCursor::default());
    assert!(events
        .iter()
        .any(|ev| matches!(ev, ObservedEvent::LockOpened { .. })));

    let claim = build_claim_call(&rig.deployment(), lock_id, binding, &rig.t).expect("claim call");
    assert_eq!(
        port.submit_claim(&claim).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    let claim_receipt = port.broadcaster().last();
    report("claim", &claim_receipt);
    anvil.advance_to_finality();
    let (events, _) = port.observe(&cursor);
    assert!(
        events.iter().any(|ev| matches!(
            ev,
            ObservedEvent::LockClaimed { revealed, .. } if revealed.0 == rig.t
        )),
        "the claim must still be observed even though the payout was deferred"
    );
    println!("  finalized at obs.  {}", anvil.finalized());

    // The claim succeeded and `t` is public even though no value moved: that is
    // exactly what D-002 requires.
    assert_eq!(
        word_to_u128(&token_balance(&rig.rpc, &heavy, &account)),
        word_to_u128(&before) - AMOUNT,
        "nothing may have been delivered by the push: the funder is still out \
         the whole amount"
    );

    // --- PayoutDeferred carries the SHORTFALL ------------------------------
    let deferred = logs_by_topic0(
        &rig.rpc,
        &lock_addr,
        event_topic0(SIG_PAYOUT_DEFERRED),
        open_receipt.block_number,
        anvil.block_number(),
    );
    assert_eq!(
        deferred.len(),
        1,
        "exactly one PayoutDeferred was expected: {deferred:?}"
    );
    assert_eq!(
        log_data_word(&deferred[0]),
        word_u128(AMOUNT),
        "the event must carry the shortfall, which here is the whole amount"
    );
    println!(
        "  PayoutDeferred     tx {} shortfall {AMOUNT}",
        deferred[0]
            .get("transactionHash")
            .and_then(|v| v.as_str())
            .unwrap_or("<none>")
    );
    assert_eq!(
        pending_credit(&rig.rpc, &lock_addr, &account, &heavy),
        word_u128(AMOUNT),
        "the credit must equal the shortfall"
    );

    // --- withdrawAmount: a partial instalment ------------------------------
    let instalment = AMOUNT / 4;
    let r = cast_send(
        &e.cast,
        &e.rpc_url,
        &e.key,
        "withdrawAmount",
        &lock_addr,
        &calldata(
            SIG_WITHDRAW_AMOUNT,
            &[
                word_address(heavy),
                word_address(account),
                word_u128(instalment),
            ],
        ),
        None,
        Some(300_000),
    )
    .expect("withdrawAmount must succeed");
    report("withdrawAmount", &r);
    assert_eq!(
        pending_credit(&rig.rpc, &lock_addr, &account, &heavy),
        word_u128(AMOUNT - instalment),
        "the credit must fall by exactly the instalment"
    );

    // --- withdraw: the remainder, in one go --------------------------------
    let r = cast_send(
        &e.cast,
        &e.rpc_url,
        &e.key,
        "withdraw",
        &lock_addr,
        &calldata(SIG_WITHDRAW, &[word_address(heavy)]),
        None,
        Some(300_000),
    )
    .expect("withdraw must succeed");
    report("withdraw", &r);
    assert_eq!(
        pending_credit(&rig.rpc, &lock_addr, &account, &heavy),
        [0u8; 32],
        "the credit must be fully drained"
    );
    assert_eq!(
        token_balance(&rig.rpc, &heavy, &account),
        before,
        "funder == beneficiary, so after both withdrawals the round trip is neutral"
    );
    assert_eq!(
        token_balance(&rig.rpc, &heavy, &lock_addr),
        [0u8; 32],
        "the lock must hold nothing once the credit is drained"
    );

    // Both withdrawals must be visible as `Withdrawal` logs, found by the
    // `topic0` computed from the adapter's pinned signature string.
    let withdrawals = logs_by_topic0(
        &rig.rpc,
        &lock_addr,
        event_topic0(SIG_WITHDRAWAL),
        open_receipt.block_number,
        anvil.block_number(),
    );
    assert_eq!(withdrawals.len(), 2, "two withdrawals were expected");
    assert_eq!(log_data_word(&withdrawals[0]), word_u128(instalment));
    assert_eq!(
        log_data_word(&withdrawals[1]),
        word_u128(AMOUNT - instalment)
    );
    println!("  Withdrawal logs    2 (instalment then remainder)");
}

// ---------------------------------------------------------------------------
// 7. the adapter's pinned event signatures still describe the deployed contract
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs the Foundry build output; run ./scripts/e2e_anvil.sh"]
fn anvil_pinned_signatures_still_match_the_compiled_contracts() {
    if env().is_none() {
        return;
    }
    // `adapter_evm::abi` pins five event signature strings and three function
    // signatures as *strings*, and every topic0 and selector in the system is
    // keccak of one of them. A contract change that renamed a parameter type or
    // reordered a field would leave those strings compiling happily and
    // matching nothing on chain. This reads the compiled ABI and checks the
    // strings are still there.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/out")
        .canonicalize()
        .expect("contracts/out must exist; run `forge build`");

    let mut events: BTreeSet<String> = BTreeSet::new();
    let mut functions: BTreeSet<String> = BTreeSet::new();
    for artifact in [
        "ConditionLockCoreV2.sol/ConditionLockCoreV2.json",
        "ConditionLockV2.sol/ConditionLockV2.json",
        "ConditionLockERC20V2.sol/ConditionLockERC20V2.json",
    ] {
        let path = root.join(artifact);
        let raw = std::fs::read(&path).unwrap_or_else(|_| panic!("missing artifact {path:?}"));
        let json: Value = serde_json::from_slice(&raw).expect("artifact is JSON");
        let abi = json.get("abi").and_then(|a| a.as_array()).expect("abi");
        for entry in abi {
            let kind = entry.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let Some(name) = entry.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let inputs: Vec<String> = entry
                .get("inputs")
                .and_then(|i| i.as_array())
                .map(|a| a.iter().map(canonical_abi_type).collect::<Vec<String>>())
                .unwrap_or_default();
            let sig = format!("{name}({})", inputs.join(","));
            match kind {
                "event" => {
                    events.insert(sig);
                }
                "function" => {
                    functions.insert(sig);
                }
                _ => {}
            }
        }
    }

    for sig in [
        SIG_LOCK_OPENED,
        SIG_CLAIMED,
        SIG_REFUNDED,
        SIG_PAYOUT_DEFERRED,
        SIG_WITHDRAWAL,
    ] {
        assert!(
            events.contains(sig),
            "the adapter pins the event signature `{sig}`, which the compiled \
             contracts no longer declare. Declared: {events:?}"
        );
    }
    for sig in [SIG_OPEN, SIG_CLAIM, SIG_REFUND] {
        assert!(
            functions.contains(sig),
            "the adapter pins the function signature `{sig}`, which the \
             compiled contracts no longer declare"
        );
    }
    // The scenarios above also call these; pin them the same way.
    for sig in [
        SIG_WITHDRAW,
        SIG_WITHDRAW_AMOUNT,
        "withdrawTo(address,address)",
    ] {
        assert!(
            functions.contains(sig),
            "this harness calls `{sig}`, which the compiled contracts no \
             longer declare"
        );
    }
    println!("=== G-F3 / signature conformance ===");
    println!("  events pinned      5/5 present in the compiled ABI");
    println!("  functions pinned   6/6 present in the compiled ABI");
}

/// Canonical ABI type of one parameter, flattening tuples the way a signature
/// string spells them.
fn canonical_abi_type(param: &Value) -> String {
    let ty = param.get("type").and_then(|t| t.as_str()).unwrap_or("");
    if let Some(rest) = ty.strip_prefix("tuple") {
        let inner: Vec<String> = param
            .get("components")
            .and_then(|c| c.as_array())
            .map(|a| a.iter().map(canonical_abi_type).collect())
            .unwrap_or_default();
        return format!("({}){rest}", inner.join(","));
    }
    ty.to_string()
}

// ---------------------------------------------------------------------------
// 8. gas: the estimator picks the degraded branch, so the harness does not use it
// ---------------------------------------------------------------------------

/// What one `claim` at a given gas limit actually did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ClaimProbe {
    /// The transaction succeeded (a deferred payout succeeds too — that is the
    /// whole problem).
    completed: bool,
    /// The optimistic push fired, i.e. no pull credit was booked.
    pushed: bool,
}

/// Opens a fresh lock and claims it at exactly `claim_gas`, reporting whether
/// the claim completed and whether it pushed.
///
/// A fresh lock per probe because a lock settles once; the session seed is the
/// only thing that varies, and it changes `lockId` through the binding.
fn probe_claim(
    e: &Env,
    lock_addr: [u8; 20],
    asset: [u8; 20],
    seed: u16,
    claim_gas: u64,
) -> ClaimProbe {
    let rig = Rig::on(
        e,
        lock_addr,
        asset,
        seed,
        Direction::EvmToDom,
        86_400,
        // The *open* always gets a generous limit; only the claim is probed.
        settlement_gas_limit(&asset),
    );
    let mut port = build_port(&rig, empty_outbox(), CastBroadcaster::new(e));
    let (binding, lock_id) = port.identity().expect("derivation");
    if asset != [0u8; 20] {
        approve(e, &asset, &lock_addr, AMOUNT);
    }
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );

    let credit_before = pending_credit(&rig.rpc, &lock_addr, &e.account, &asset);
    let claim = build_claim_call(&rig.deployment(), lock_id, binding, &rig.t).expect("claim call");
    let completed = try_cast_send(
        &e.cast,
        &e.rpc_url,
        &e.key,
        &lock_addr,
        &claim.calldata,
        claim_gas,
    )
    .unwrap_or(false);
    let credit_after = pending_credit(&rig.rpc, &lock_addr, &e.account, &asset);
    ClaimProbe {
        completed,
        // A push that delivered everything books no credit at all; anything
        // else moved the pull ledger.
        pushed: completed && credit_after == credit_before,
    }
}

/// The two gas figures of a `claim`, measured against deployed bytecode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Thresholds {
    /// What `eth_estimateGas` returns for the claim — i.e. what an
    /// estimator-driven caller would supply. Read directly from the node rather
    /// than searched for, because that is the quantity the finding is about.
    estimated: u64,
    /// Lowest limit at which the claim actually performs the optimistic push.
    /// Found by binary search, because no node will tell you this.
    push: u64,
}

/// Opens a fresh lock and asks the node what it would charge for the claim.
fn estimate_claim_gas(e: &Env, lock_addr: [u8; 20], asset: [u8; 20], seed: u16) -> u64 {
    let rig = Rig::on(
        e,
        lock_addr,
        asset,
        seed,
        Direction::EvmToDom,
        86_400,
        settlement_gas_limit(&asset),
    );
    let mut port = build_port(&rig, empty_outbox(), CastBroadcaster::new(e));
    let (binding, lock_id) = port.identity().expect("derivation");
    if asset != [0u8; 20] {
        approve(e, &asset, &lock_addr, AMOUNT);
    }
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    let claim = build_claim_call(&rig.deployment(), lock_id, binding, &rig.t).expect("claim call");
    rig.rpc
        .call(
            "eth_estimateGas",
            json!([{
                "from": hex0x(&e.account),
                "to": hex0x(&lock_addr),
                "input": hex0x(&claim.calldata),
            }]),
        )
        .ok()
        .as_ref()
        .and_then(parse_quantity)
        .expect("eth_estimateGas")
}

/// Binary-searches the lowest gas limit at which the claim actually pushes.
///
/// Monotone in practice: more gas can only move the contract from the deferred
/// branch to the push branch, never back. 250 gas of resolution over the search
/// range is eleven probes, and each probe is two or three real transactions.
///
/// Only the push threshold is searched for. The completion threshold is *not*:
/// a search for it is confounded by its own side effects, because every
/// succeeding probe warms and populates the `pendingWithdrawals` slot that the
/// next probe then writes more cheaply. `eth_estimateGas` answers that question
/// directly and without the confound, so it is asked instead.
fn measure_push_threshold(e: &Env, lock_addr: [u8; 20], asset: [u8; 20], seed: &mut u16) -> u64 {
    const LO: u64 = 21_000;
    const HI: u64 = 600_000;
    const RESOLUTION: u64 = 250;
    let (mut lo, mut hi) = (LO, HI);
    let top = probe_claim(e, lock_addr, asset, *seed, HI);
    *seed = seed.wrapping_add(1);
    assert!(
        top.pushed,
        "the search range must contain a limit that pushes"
    );
    while hi - lo > RESOLUTION {
        let mid = lo + (hi - lo) / 2;
        let mid = mid - (mid % RESOLUTION);
        let pushed = probe_claim(e, lock_addr, asset, *seed, mid).pushed;
        *seed = seed.wrapping_add(1);
        if pushed {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    hi
}

fn measure_thresholds(e: &Env, lock_addr: [u8; 20], asset: [u8; 20], seed_base: u16) -> Thresholds {
    let mut seed = seed_base;
    let estimated = estimate_claim_gas(e, lock_addr, asset, seed);
    seed = seed.wrapping_add(1);
    let push = measure_push_threshold(e, lock_addr, asset, &mut seed);
    assert!(
        estimated <= push,
        "an estimate that already clears the push threshold would mean the \
         finding no longer applies"
    );
    Thresholds { estimated, push }
}

#[test]
#[ignore = "needs a running Anvil; run ./scripts/e2e_anvil.sh"]
fn anvil_settlement_gas_limits_clear_the_deployed_push_threshold() {
    let Some(e) = env() else {
        return;
    };
    // Measure both legs first and report everything, then judge. A test that
    // asserts as it goes hides the second measurement behind the first
    // failure, which is exactly when you most want to see both.
    let native = measure_thresholds(&e, e.contract, [0u8; 20], 0x1000);
    let (erc20_lock, token, _) = erc20_env(&e);
    let erc20 = measure_thresholds(&e, erc20_lock, token, 0x2000);

    println!("=== G-F3 / gas thresholds measured against the deployed bytecode ===");
    println!(
        "  native   estimate {:>7} | pushes at {:>7} | gap {:>7} | pinned \
         {NATIVE_SETTLEMENT_GAS_LIMIT} | recorded {NATIVE_CLAIM_ESTIMATED_GAS}/\
         {NATIVE_CLAIM_PUSH_GAS}",
        native.estimated,
        native.push,
        native.push - native.estimated
    );
    println!(
        "  erc-20   estimate {:>7} | pushes at {:>7} | gap {:>7} | pinned \
         {ERC20_SETTLEMENT_GAS_LIMIT} | recorded {ERC20_CLAIM_ESTIMATED_GAS}/\
         {ERC20_CLAIM_PUSH_GAS}",
        erc20.estimated,
        erc20.push,
        erc20.push - erc20.estimated
    );

    assert!(
        NATIVE_SETTLEMENT_GAS_LIMIT >= native.push,
        "NATIVE_SETTLEMENT_GAS_LIMIT ({NATIVE_SETTLEMENT_GAS_LIMIT}) no longer clears the \
         deployed push threshold ({}). The contract's PAYOUT_GAS_FLOOR has outrun the \
         harness constant, and every native payout would silently degrade to pull.",
        native.push
    );
    assert_recorded(
        "native",
        native,
        NATIVE_CLAIM_ESTIMATED_GAS,
        NATIVE_CLAIM_PUSH_GAS,
    );

    assert!(
        ERC20_SETTLEMENT_GAS_LIMIT >= erc20.push,
        "ERC20_SETTLEMENT_GAS_LIMIT ({ERC20_SETTLEMENT_GAS_LIMIT}) no longer clears the \
         deployed push threshold ({}). PAYOUT_GAS_FLOOR_ERC20 has outrun the harness \
         constant, and every ERC-20 payout would silently degrade to pull.",
        erc20.push
    );
    assert_recorded(
        "erc-20",
        erc20,
        ERC20_CLAIM_ESTIMATED_GAS,
        ERC20_CLAIM_PUSH_GAS,
    );
    assert!(
        erc20.push > native.push,
        "the ERC-20 payout floor is the higher of the two by construction"
    );
}

/// The figures recorded in `f3_harness::gas` must still describe the deployed
/// bytecode.
///
/// A tolerance rather than equality, because the exact threshold moves with
/// storage warmth and with the search resolution; a drift wider than this means
/// the contract changed and the derivation needs redoing, which is precisely
/// what should fail loudly.
fn assert_recorded(leg: &str, measured: Thresholds, recorded_estimate: u64, recorded_push: u64) {
    const TOLERANCE_PERCENT: u64 = 15;
    for (what, m, r) in [
        ("estimated", measured.estimated, recorded_estimate),
        ("push", measured.push, recorded_push),
    ] {
        let (lo, hi) = (
            r * (100 - TOLERANCE_PERCENT) / 100,
            r * (100 + TOLERANCE_PERCENT) / 100,
        );
        assert!(
            m >= lo && m <= hi,
            "the {leg} {what} threshold measured {m} gas, but `f3_harness::gas` records {r}. \
             The recorded figure is stale: re-measure, re-derive the limit, and update the \
             module's table."
        );
    }
}

#[test]
#[ignore = "needs a running Anvil; run ./scripts/e2e_anvil.sh"]
fn anvil_erc20_estimated_gas_silently_degrades_to_the_pull_path() {
    let Some(e) = env() else {
        return;
    };
    let (lock_addr, token, _) = erc20_env(&e);
    // Audit finding I, reproduced against the deployed bytecode with an
    // ordinary, well-behaved token. Everything here succeeds; that is the
    // point. Nothing reverts, nothing warns, and the beneficiary silently ends
    // up owed a second transaction.
    let rig = Rig::on(
        &e,
        lock_addr,
        token,
        0xA7,
        Direction::EvmToDom,
        86_400,
        ERC20_SETTLEMENT_GAS_LIMIT,
    );
    let anvil = rig.anvil();
    let mut port = build_port(&rig, empty_outbox(), CastBroadcaster::new(&e));
    let (binding, lock_id) = port.identity().expect("derivation");
    banner(
        "G-F3 / estimator hazard (finding I) on a plain ERC-20",
        &rig,
        &lock_id,
        &binding,
    );

    approve(&e, &token, &lock_addr, AMOUNT);
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    let open_receipt = port.broadcaster().last();
    report("open", &open_receipt);

    // What an estimator-driven caller would use.
    let claim = build_claim_call(&rig.deployment(), lock_id, binding, &rig.t).expect("claim call");
    let estimated = rig
        .rpc
        .call(
            "eth_estimateGas",
            json!([{
                "from": hex0x(&e.account),
                "to": hex0x(&lock_addr),
                "input": hex0x(&claim.calldata),
            }]),
        )
        .ok()
        .as_ref()
        .and_then(parse_quantity)
        .expect("eth_estimateGas");
    println!("  eth_estimateGas    {estimated} gas (recorded {ERC20_CLAIM_ESTIMATED_GAS})");
    println!("  pinned limit       {ERC20_SETTLEMENT_GAS_LIMIT} gas");
    assert!(
        estimated < ERC20_CLAIM_PUSH_GAS,
        "finding I says the estimate lands below the push threshold; it did not \
         ({estimated} >= {ERC20_CLAIM_PUSH_GAS}), so this scenario no longer \
         describes reality and the gas module needs revisiting"
    );

    let credit_before = pending_credit(&rig.rpc, &lock_addr, &e.account, &token);
    let succeeded = try_cast_send(
        &e.cast,
        &e.rpc_url,
        &e.key,
        &lock_addr,
        &claim.calldata,
        estimated,
    )
    .expect("cast send ran");
    assert!(
        succeeded,
        "the estimate must succeed — that is precisely why the estimator picks it"
    );
    anvil.advance_to_finality();

    // The claim settled and `t` is public...
    let (events, _) = port.observe(&ChainCursor::default());
    assert!(
        events.iter().any(|ev| matches!(
            ev,
            ObservedEvent::LockClaimed { revealed, .. } if revealed.0 == rig.t
        )),
        "the claim must still be observed"
    );
    // ...but the push never fired.
    let deferred = logs_by_topic0(
        &rig.rpc,
        &lock_addr,
        event_topic0(SIG_PAYOUT_DEFERRED),
        open_receipt.block_number,
        anvil.block_number(),
    );
    assert_eq!(
        deferred.len(),
        1,
        "an estimator-sized claim must land on the deferred path: {deferred:?}"
    );
    assert_eq!(log_data_word(&deferred[0]), word_u128(AMOUNT));
    let credit_after = pending_credit(&rig.rpc, &lock_addr, &e.account, &token);
    assert_eq!(
        word_to_u128(&credit_after) - word_to_u128(&credit_before),
        AMOUNT,
        "the whole payout became a pull credit"
    );
    println!(
        "  outcome            claim SUCCEEDED, push SKIPPED, {AMOUNT} deferred to pull (tx {})",
        deferred[0]
            .get("transactionHash")
            .and_then(|v| v.as_str())
            .unwrap_or("<none>")
    );

    // The beneficiary can still get their tokens — at the cost of the second
    // transaction the push existed to avoid.
    let r = cast_send(
        &e.cast,
        &e.rpc_url,
        &e.key,
        "withdraw",
        &lock_addr,
        &calldata(SIG_WITHDRAW, &[word_address(token)]),
        None,
        Some(300_000),
    )
    .expect("withdraw must succeed");
    report("withdraw", &r);
    assert_eq!(
        pending_credit(&rig.rpc, &lock_addr, &e.account, &token),
        credit_before,
        "the credit must be drained back to where it started"
    );
    println!("  remedy             one extra transaction, every time — hence the constant");
}
