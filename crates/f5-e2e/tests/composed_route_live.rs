//! Composed cross-chain route — LEVEL 3, LIVE on two real chains.
//!
//! RATIFIED (explicit operator decision, 2026-09-02 — ratifications/
//! e13-executadas v2 §2.10). Laboratory evidence requested by the operator: the mixed
//! composed route's chain hand-off executed live. One route scalar `t`:
//!
//!   1. revealed on a REAL EVM chain (anvil) by `ConditionLockV2.claim`,
//!      whose contract verifies `address(t*G)` against the lock's committed
//!      adaptor address before publishing `t` in the `Claimed` event;
//!   2. OBSERVED from that chain (the claim receipt's event data — from this
//!      point on the test uses only the observed bytes);
//!   3. carried to a REAL Bitcoin Core regtest node: the observed scalar
//!      adapts a durable MuSig2 2-of-2 adaptor pre-signature prepared
//!      WITHOUT `t` and gated by M.8 anchor authorizations, the claim is
//!      broadcast, mined, re-fetched as exact confirmed witness bytes, and
//!      `t` extracted back through the canonical evidence consumer;
//!   4. the extracted scalar is byte-identical to the one the EVM chain
//!      published and reproduces the EVM adaptor address — one secret, both
//!      real chains.
//!
//! With level 1 (the DOM leg binds the same `T` through the pinned real
//! adaptor) and level 2 (durable engine chaining), this closes the
//! composed-route question at every layer this container can reach. The DOM
//! half of the M.8 anchors is the same explicit fixture as the F7 component
//! test (B-F7-007): a live DOM node needs the original laboratory runtime.
//!
//! The M.8 window here is calibrated SAFELY (DOM second refund at 400
//! blocks). The sibling component test's fixture window (200 blocks)
//! violates its own conservative bound and is refused by
//! `bind_and_validate_funding_anchors` with `UnsafeCrossChainWindow` — that
//! refusal is the validator working, and nothing here loosens it.
//!
//! Disclosure note: the route scalar is passed to the local `cast` process
//! that broadcasts the EVM claim. That is the protocol's own reveal —
//! `claim(lockId, t)` publishes `t` on chain by design — on a throwaway
//! chain with an ephemeral scalar. No wallet or signing secret is ever in an
//! argument, and the scalar is not printed.
//!
//! Run explicitly (needs bitcoind, bitcoin-cli, cast on PATH, a live anvil
//! at COMPOSED_EVM_RPC, and the forge artifact for ConditionLockV2):
//!
//! ```text
//! cargo test -p f5-e2e --test composed_route_live -- --ignored --nocapture
//! ```

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use adapter_btc::timelock::{
    bind_and_validate_funding_anchors, AnchoredCrossChainWindowV1, BitcoinFinalityPolicyV1,
    BitcoinFundingAnchorV1, ChainTimingBoundsV1, DomFundingAnchorV1, M8FundingAnchorsV1,
    M8TimingPolicyV1, TimelockOffsetV1,
};
use adapter_btc::types::BitcoinNetworkV1;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use btc_vault::BitcoinNonceSealKeyV1;
use counterparty_api::{AdaptorPointBytes, RevealedSecretBytes};
use f5_e2e::{
    adapt_prepared_route_claim, extract_revealed_secret_from_confirmed_claim,
    prepare_regtest_route_claim_durable_after_m8, regtest_address, verify_claim_witness,
    FundingRef,
};
use f7_anchor_authority::{verify_bitcoin_funding_evidence, VerifiedBitcoinFundingEvidenceV1};
use serde_json::Value;

const CLAIM_FEE_SAT: u64 = 2_000;

// ---------------------------------------------------------------- EVM leg --

struct EvmLeg {
    cast: String,
    rpc: String,
    key: String,
}

impl EvmLeg {
    fn from_env() -> Result<Self, String> {
        let cast = std::env::var("CAST_BIN").unwrap_or_else(|_| "cast".to_string());
        let rpc = std::env::var("COMPOSED_EVM_RPC")
            .unwrap_or_else(|_| "http://127.0.0.1:8547".to_string());
        // anvil's default funded account 0; a throwaway development key.
        let key = std::env::var("COMPOSED_EVM_KEY").unwrap_or_else(|_| {
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string()
        });
        let probe = Command::new(&cast)
            .args(["chain-id", "--rpc-url", &rpc])
            .output()
            .map_err(|error| format!("cast is unavailable: {error}"))?;
        checked_stdout(probe)?;
        Ok(Self { cast, rpc, key })
    }

    fn call(&self, arguments: &[&str]) -> Result<String, String> {
        let output = Command::new(&self.cast)
            .args(arguments)
            .args(["--rpc-url", &self.rpc])
            .output()
            .map_err(|error| format!("run cast: {error}"))?;
        checked_stdout(output)
    }

    /// `cast send` treats everything after `--create <CODE>` as SIG/ARGS, so
    /// the connection flags must precede the positional arguments.
    fn send_json(&self, arguments: &[&str]) -> Result<Value, String> {
        let output = Command::new(&self.cast)
            .arg("send")
            .args(["--rpc-url", &self.rpc, "--private-key", &self.key, "--json"])
            .args(arguments)
            .output()
            .map_err(|error| format!("run cast send: {error}"))?;
        let stdout = checked_stdout(output)?;
        serde_json::from_str(&stdout).map_err(|error| format!("cast send JSON: {error}"))
    }

    fn funder_address(&self) -> Result<String, String> {
        let output = Command::new(&self.cast)
            .args(["wallet", "address", "--private-key", &self.key])
            .output()
            .map_err(|error| format!("run cast wallet address: {error}"))?;
        checked_stdout(output)
    }
}

/// Reads the deployed bytecode for ConditionLockV2 from the forge artifact.
fn condition_lock_creation_bytecode() -> Result<String, String> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").map_err(|error| error.to_string())?;
    let artifact = PathBuf::from(manifest)
        .join("../../contracts/out/ConditionLockV2.sol/ConditionLockV2.json");
    let text = std::fs::read_to_string(&artifact)
        .map_err(|error| format!("read forge artifact {}: {error}", artifact.display()))?;
    let json: Value =
        serde_json::from_str(&text).map_err(|error| format!("artifact JSON: {error}"))?;
    json["bytecode"]["object"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "artifact has no bytecode.object".to_string())
}

// ------------------------------------------------------------- the route --

#[test]
#[ignore = "requires bitcoind + bitcoin-cli + cast on PATH, a live anvil, and the forge artifact"]
fn one_scalar_revealed_on_a_live_evm_chain_claims_a_live_bitcoin_output() {
    // -- the route scalar and its point, fixed before any chain is touched --
    let t = random_canonical_secret().expect("ephemeral route scalar");
    let big_t = point(&t);
    let evm_adaptor_address =
        adapter_evm::binding::adaptor_address(&big_t.0).expect("address of T");
    let evm_adaptor_hex = format!("0x{}", encode_hex(&evm_adaptor_address));

    // ---------------------------------------------------------- EVM side --
    let evm = EvmLeg::from_env().expect("live EVM endpoint");
    let funder = evm.funder_address().expect("funder address");

    let bytecode = condition_lock_creation_bytecode().expect("ConditionLockV2 bytecode");
    let deploy = evm
        .send_json(&["--create", &bytecode])
        .expect("deploy ConditionLockV2");
    assert_eq!(deploy["status"].as_str(), Some("0x1"), "deploy succeeded");
    let lock_contract = deploy["contractAddress"]
        .as_str()
        .expect("deployed contract address")
        .to_string();

    let deadline = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        + 86_400;
    let terms_tuple = format!(
        "(0x{dom_chain},1,0x{session},0x{terms_hash},0x{participants},0x0000000000000000000000000000000000000000,1000000000000000000,{funder},{adaptor},{deadline})",
        dom_chain = encode_hex(&[0xd0u8; 32]),
        session = encode_hex(&[0x5eu8; 32]),
        terms_hash = encode_hex(&[0x7eu8; 32]),
        participants = encode_hex(&[0xb1u8; 32]),
        funder = funder,
        adaptor = evm_adaptor_hex,
    );
    const TERMS_ABI: &str =
        "(bytes32,uint8,bytes32,bytes32,bytes32,address,uint256,address,address,uint64)";
    let derive_signature = format!("deriveLockId({TERMS_ABI},address)(bytes32)");
    let lock_id = evm
        .call(&[
            "call",
            &lock_contract,
            &derive_signature,
            &terms_tuple,
            &funder,
        ])
        .expect("deriveLockId view");

    let open_signature = format!("open({TERMS_ABI})");
    let open = evm
        .send_json(&[
            &lock_contract,
            &open_signature,
            &terms_tuple,
            "--value",
            "1000000000000000000",
        ])
        .expect("open lock bound to address(t*G)");
    assert_eq!(open["status"].as_str(), Some("0x1"), "open succeeded");

    // The claim: the protocol's reveal of t on the EVM chain.
    let t_word = format!("0x{}", encode_hex(&t.expose_scalar_bytes()));
    let claim_receipt = evm
        .send_json(&[&lock_contract, "claim(bytes32,uint256)", &lock_id, &t_word])
        .expect("claim with t");
    assert_eq!(
        claim_receipt["status"].as_str(),
        Some("0x1"),
        "EVM claim succeeded — the contract accepted address(t*G)"
    );

    // -- OBSERVE t from the chain: the Claimed event's single data word.
    // From here on the test uses only `observed`, never its local copy.
    let logs = claim_receipt["logs"].as_array().expect("claim logs");
    let mut observed_word: Option<[u8; 32]> = None;
    for log in logs {
        if log["topics"].as_array().map(Vec::len) == Some(4) {
            let data = log["data"].as_str().unwrap_or("");
            let raw = decode_hex(data.trim_start_matches("0x")).expect("event data hex");
            if raw.len() == 32 {
                observed_word = Some(raw.try_into().expect("32-byte word"));
                break;
            }
        }
    }
    let observed = RevealedSecretBytes::new(observed_word.expect("Claimed event data word"));
    assert_eq!(
        adapter_evm::binding::adaptor_address_of_scalar(&observed.expose_scalar_bytes())
            .expect("observed scalar is canonical"),
        evm_adaptor_address,
        "the observed scalar reproduces the committed EVM adaptor address"
    );

    // ------------------------------------------------------ Bitcoin side --
    let node = RegtestNode::start().expect("start isolated Bitcoin Core regtest");
    let contract_address = regtest_address();
    let miner = node.wallet(&["getnewaddress"]).expect("miner address");
    node.wallet(&["generatetoaddress", "1", &miner])
        .expect("mine wallet coinbase");
    node.wallet(&["generatetoaddress", "100", &contract_address])
        .expect("mature wallet coinbase");

    let funding_txid = node
        .wallet(&["sendtoaddress", &contract_address, "0.5"])
        .expect("fund the F7 P2TR output");
    let funding_block = node
        .wallet(&["generatetoaddress", "1", &contract_address])
        .expect("confirm funding");
    let block_hash = first_json_string(&funding_block).expect("funding block hash");
    let block: Value = parse_json(&node.cli(&["getblock", &block_hash]).expect("funding block"));
    let funding_height = block["height"].as_u64().expect("funding height");
    let funding_json: Value = parse_json(
        &node
            .cli(&["getrawtransaction", &funding_txid, "true"])
            .expect("read funding transaction"),
    );
    let contract_vout = funding_json["vout"]
        .as_array()
        .expect("funding outputs")
        .iter()
        .find(|output| output["scriptPubKey"]["address"] == contract_address)
        .expect("contract funding output");
    let vout =
        u32::try_from(contract_vout["n"].as_u64().expect("vout index")).expect("bounded vout");
    let amount_sat = btc_decimal_to_sat(&contract_vout["value"]).expect("exact sats");
    let destination_address = node.wallet(&["getnewaddress"]).expect("claim destination");
    let destination_json: Value = parse_json(
        &node
            .wallet(&["getaddressinfo", &destination_address])
            .expect("destination descriptor"),
    );
    let destination_script = decode_hex(
        destination_json["scriptPubKey"]
            .as_str()
            .expect("destination script"),
    )
    .expect("canonical destination script");

    let terms_hash = [0x73; 32];
    let funding_txid_internal = txid_internal_bytes(&funding_txid).expect("canonical txid");
    let funding_block_bytes = decode_hex(
        &node
            .cli(&["getblock", &block_hash, "0"])
            .expect("canonical funding block bytes"),
    )
    .expect("decode funding block");
    let ancestry = canonical_ancestry(&node, funding_height).expect("verified ancestry");
    let timing_policy = safe_bitcoin_timing_policy(terms_hash);
    let verified_bitcoin_funding = verify_bitcoin_funding_evidence(
        &timing_policy,
        funding_txid_internal,
        funding_height,
        &funding_block_bytes,
        &ancestry,
        &[],
    )
    .expect("Bitcoin funding block and header chain verify");
    let funding = FundingRef {
        txid: funding_txid_internal,
        vout,
        amount_sat,
    };
    let authorizations = [
        fixture_dom_anchor_authorization(&timing_policy, &verified_bitcoin_funding),
        fixture_dom_anchor_authorization(&timing_policy, &verified_bitcoin_funding),
    ];

    let vault_one = node.directory.join("signer-one.sqlite");
    let vault_two = node.directory.join("signer-two.sqlite");
    let seal_one = BitcoinNonceSealKeyV1::new([0x73; 32]).expect("seal key one");
    let seal_two = BitcoinNonceSealKeyV1::new([0x74; 32]).expect("seal key two");
    let prepared = prepare_regtest_route_claim_durable_after_m8(
        &funding,
        &destination_script,
        CLAIM_FEE_SAT,
        [0x71; 32],
        [0x72; 32],
        terms_hash,
        &big_t,
        authorizations,
        &seal_one,
        &seal_two,
        &vault_one,
        &vault_two,
    )
    .expect("prepare durable Bitcoin claim WITHOUT t");
    assert_eq!(prepared.adaptor_point(), big_t, "BTC leg binds the same T");

    // Adapt with the scalar OBSERVED on the EVM chain — the route hand-off.
    let claim = adapt_prepared_route_claim(prepared, &observed)
        .expect("the EVM-observed scalar adapts the Bitcoin claim");
    assert!(verify_claim_witness(
        &claim.claim.raw_transaction,
        &funding,
        &destination_script,
        CLAIM_FEE_SAT,
    ));
    let claim_hex = encode_hex(&claim.claim.raw_transaction);
    let claim_txid = node
        .cli(&["sendrawtransaction", &claim_hex])
        .expect("real Bitcoin mempool accepts the claim");
    node.wallet(&["generatetoaddress", "1", &contract_address])
        .expect("confirm the claim");
    let confirmed_hex = node
        .cli(&["getrawtransaction", &claim_txid, "false"])
        .expect("read exact confirmed witness-bearing claim");
    let confirmed = decode_hex(&confirmed_hex).expect("decode confirmed claim");
    assert_eq!(confirmed, claim.claim.raw_transaction);

    // Extract t back from the CONFIRMED Bitcoin witness and close the loop.
    let extracted = extract_revealed_secret_from_confirmed_claim(&claim.extraction, &confirmed)
        .expect("extract from exact confirmed evidence");
    assert_eq!(
        extracted, observed,
        "the scalar extracted from the mined Bitcoin claim is byte-identical \
         to the one the EVM chain published"
    );
    assert_eq!(
        adapter_evm::binding::adaptor_address_of_scalar(&extracted.expose_scalar_bytes())
            .expect("canonical"),
        evm_adaptor_address,
        "the Bitcoin-extracted scalar reproduces the EVM commitment"
    );

    println!("COMPOSED_ROUTE_LIVE_EVIDENCE_BEGIN");
    println!(
        "evm_chain_id={}",
        evm.call(&["chain-id"]).unwrap_or_default()
    );
    println!("evm_lock_contract={lock_contract}");
    println!("evm_lock_id={lock_id}");
    println!("evm_adaptor_address={evm_adaptor_hex}");
    println!("bitcoin_network=regtest");
    println!("bitcoin_funding_txid={funding_txid}");
    println!("bitcoin_claim_txid={claim_txid}");
    println!("bitcoin_claim_confirmed=true");
    println!("scalar_observed_on_evm_unlocked_bitcoin=true");
    println!("extracted_equals_observed=true");
    println!("COMPOSED_ROUTE_LIVE_EVIDENCE_END");
}

/// The REVERSE direction: Bitcoin reveals first, the EVM leg claims with the
/// scalar recovered from the mined Bitcoin witness.
///
/// This is not a relabelling of the forward test. The burden moves to the
/// other side: here the EVM smart contract must accept, on chain, a scalar
/// that was never published on its own chain — it was recovered by decoding a
/// confirmed Bitcoin taproot witness. If the two legs' notions of `t` differed
/// by even one bit, `ConditionLockCoreV2.claim` would revert with
/// `WrongSecret`, because it recomputes `address(t*G)` against the committed
/// adaptor address.
#[test]
#[ignore = "requires bitcoind + bitcoin-cli + cast on PATH, a live anvil, and the forge artifact"]
fn one_scalar_revealed_on_a_live_bitcoin_chain_claims_a_live_evm_lock() {
    let t = random_canonical_secret().expect("ephemeral route scalar");
    let big_t = point(&t);
    let evm_adaptor_address =
        adapter_evm::binding::adaptor_address(&big_t.0).expect("address of T");
    let evm_adaptor_hex = format!("0x{}", encode_hex(&evm_adaptor_address));

    // ------------------------------------------------------ Bitcoin first --
    let node = RegtestNode::start().expect("start isolated Bitcoin Core regtest");
    let contract_address = regtest_address();
    let miner = node.wallet(&["getnewaddress"]).expect("miner address");
    node.wallet(&["generatetoaddress", "1", &miner])
        .expect("mine wallet coinbase");
    node.wallet(&["generatetoaddress", "100", &contract_address])
        .expect("mature wallet coinbase");

    let funding_txid = node
        .wallet(&["sendtoaddress", &contract_address, "0.5"])
        .expect("fund the F7 P2TR output");
    let funding_block = node
        .wallet(&["generatetoaddress", "1", &contract_address])
        .expect("confirm funding");
    let block_hash = first_json_string(&funding_block).expect("funding block hash");
    let block: Value = parse_json(&node.cli(&["getblock", &block_hash]).expect("funding block"));
    let funding_height = block["height"].as_u64().expect("funding height");
    let funding_json: Value = parse_json(
        &node
            .cli(&["getrawtransaction", &funding_txid, "true"])
            .expect("read funding transaction"),
    );
    let contract_vout = funding_json["vout"]
        .as_array()
        .expect("funding outputs")
        .iter()
        .find(|output| output["scriptPubKey"]["address"] == contract_address)
        .expect("contract funding output");
    let vout =
        u32::try_from(contract_vout["n"].as_u64().expect("vout index")).expect("bounded vout");
    let amount_sat = btc_decimal_to_sat(&contract_vout["value"]).expect("exact sats");
    let destination_address = node.wallet(&["getnewaddress"]).expect("claim destination");
    let destination_json: Value = parse_json(
        &node
            .wallet(&["getaddressinfo", &destination_address])
            .expect("destination descriptor"),
    );
    let destination_script = decode_hex(
        destination_json["scriptPubKey"]
            .as_str()
            .expect("destination script"),
    )
    .expect("canonical destination script");

    let terms_hash = [0x73; 32];
    let funding_txid_internal = txid_internal_bytes(&funding_txid).expect("canonical txid");
    let funding_block_bytes = decode_hex(
        &node
            .cli(&["getblock", &block_hash, "0"])
            .expect("canonical funding block bytes"),
    )
    .expect("decode funding block");
    let ancestry = canonical_ancestry(&node, funding_height).expect("verified ancestry");
    let timing_policy = safe_bitcoin_timing_policy(terms_hash);
    let verified_bitcoin_funding = verify_bitcoin_funding_evidence(
        &timing_policy,
        funding_txid_internal,
        funding_height,
        &funding_block_bytes,
        &ancestry,
        &[],
    )
    .expect("Bitcoin funding block and header chain verify");
    let funding = FundingRef {
        txid: funding_txid_internal,
        vout,
        amount_sat,
    };
    let authorizations = [
        fixture_dom_anchor_authorization(&timing_policy, &verified_bitcoin_funding),
        fixture_dom_anchor_authorization(&timing_policy, &verified_bitcoin_funding),
    ];
    let vault_one = node.directory.join("signer-one.sqlite");
    let vault_two = node.directory.join("signer-two.sqlite");
    let seal_one = BitcoinNonceSealKeyV1::new([0x73; 32]).expect("seal key one");
    let seal_two = BitcoinNonceSealKeyV1::new([0x74; 32]).expect("seal key two");
    let prepared = prepare_regtest_route_claim_durable_after_m8(
        &funding,
        &destination_script,
        CLAIM_FEE_SAT,
        [0x71; 32],
        [0x72; 32],
        terms_hash,
        &big_t,
        authorizations,
        &seal_one,
        &seal_two,
        &vault_one,
        &vault_two,
    )
    .expect("prepare durable Bitcoin claim WITHOUT t");
    assert_eq!(prepared.adaptor_point(), big_t, "BTC leg binds T");

    // The holder of t claims on Bitcoin FIRST. This is the reveal.
    let claim = adapt_prepared_route_claim(prepared, &t).expect("adapt with t");
    let claim_hex = encode_hex(&claim.claim.raw_transaction);
    let claim_txid = node
        .cli(&["sendrawtransaction", &claim_hex])
        .expect("real Bitcoin mempool accepts the claim");
    node.wallet(&["generatetoaddress", "1", &contract_address])
        .expect("confirm the claim");
    let confirmed = decode_hex(
        &node
            .cli(&["getrawtransaction", &claim_txid, "false"])
            .expect("read exact confirmed witness-bearing claim"),
    )
    .expect("decode confirmed claim");
    assert_eq!(confirmed, claim.claim.raw_transaction);

    // -- OBSERVE t by decoding the CONFIRMED Bitcoin witness. From here the
    // test uses only `observed`, never its local copy of the scalar.
    let observed = extract_revealed_secret_from_confirmed_claim(&claim.extraction, &confirmed)
        .expect("extract from exact confirmed Bitcoin evidence");

    // ------------------------------------------------------- EVM second --
    let evm = EvmLeg::from_env().expect("live EVM endpoint");
    let funder = evm.funder_address().expect("funder address");
    let bytecode = condition_lock_creation_bytecode().expect("ConditionLockV2 bytecode");
    let deploy = evm
        .send_json(&["--create", &bytecode])
        .expect("deploy ConditionLockV2");
    assert_eq!(deploy["status"].as_str(), Some("0x1"), "deploy succeeded");
    let lock_contract = deploy["contractAddress"]
        .as_str()
        .expect("deployed contract address")
        .to_string();

    let deadline = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        + 86_400;
    // The lock commits to address(T) — fixed when the route was set up, before
    // anything was revealed anywhere.
    let terms_tuple = format!(
        "(0x{dom_chain},0,0x{session},0x{terms_hash_hex},0x{participants},0x0000000000000000000000000000000000000000,1000000000000000000,{funder},{adaptor},{deadline})",
        dom_chain = encode_hex(&[0xd0u8; 32]),
        session = encode_hex(&[0x5eu8; 32]),
        terms_hash_hex = encode_hex(&terms_hash),
        participants = encode_hex(&[0xb1u8; 32]),
        funder = funder,
        adaptor = evm_adaptor_hex,
    );
    const TERMS_ABI: &str =
        "(bytes32,uint8,bytes32,bytes32,bytes32,address,uint256,address,address,uint64)";
    let derive_signature = format!("deriveLockId({TERMS_ABI},address)(bytes32)");
    let lock_id = evm
        .call(&[
            "call",
            &lock_contract,
            &derive_signature,
            &terms_tuple,
            &funder,
        ])
        .expect("deriveLockId view");
    let open_signature = format!("open({TERMS_ABI})");
    let open = evm
        .send_json(&[
            &lock_contract,
            &open_signature,
            &terms_tuple,
            "--value",
            "1000000000000000000",
        ])
        .expect("open lock bound to address(t*G)");
    assert_eq!(open["status"].as_str(), Some("0x1"), "open succeeded");

    // NEGATIVE CONTROL, so the positive result below is not vacuous: a scalar
    // that is NOT the one the Bitcoin witness carried must be refused by the
    // live contract. Without this, a claim that accepted anything would look
    // exactly like a successful route hand-off.
    let mut wrong = observed.expose_scalar_bytes();
    wrong[31] ^= 0x01;
    let wrong_word = format!("0x{}", encode_hex(&wrong));
    let refused = evm.send_json(&[
        &lock_contract,
        "claim(bytes32,uint256)",
        &lock_id,
        &wrong_word,
    ]);
    let refused_on_chain = match &refused {
        // `cast` surfaces the revert as a command failure...
        Err(_) => true,
        // ...or, if it broadcast, the receipt must not be a success.
        Ok(receipt) => receipt["status"].as_str() != Some("0x1"),
    };
    assert!(
        refused_on_chain,
        "the live contract accepted a WRONG scalar — the address(t*G) check \
         is vacuous and the positive result below would prove nothing"
    );

    // The claim submits the scalar RECOVERED FROM BITCOIN. The contract
    // recomputes address(t*G) on chain and reverts unless it matches.
    let observed_word = format!("0x{}", encode_hex(&observed.expose_scalar_bytes()));
    let claim_receipt = evm
        .send_json(&[
            &lock_contract,
            "claim(bytes32,uint256)",
            &lock_id,
            &observed_word,
        ])
        .expect("claim with the Bitcoin-recovered scalar");
    assert_eq!(
        claim_receipt["status"].as_str(),
        Some("0x1"),
        "the live EVM contract accepted a scalar recovered from a mined \
         Bitcoin witness"
    );

    // The EVM chain re-published exactly that scalar in its Claimed event.
    let logs = claim_receipt["logs"].as_array().expect("claim logs");
    let mut published: Option<[u8; 32]> = None;
    for log in logs {
        if log["topics"].as_array().map(Vec::len) == Some(4) {
            let raw = decode_hex(log["data"].as_str().unwrap_or("")).expect("event data hex");
            if raw.len() == 32 {
                published = Some(raw.try_into().expect("32-byte word"));
                break;
            }
        }
    }
    assert_eq!(
        published.expect("Claimed event data word"),
        observed.expose_scalar_bytes(),
        "the EVM chain published the same scalar the Bitcoin witness carried"
    );

    println!("COMPOSED_ROUTE_LIVE_REVERSE_EVIDENCE_BEGIN");
    println!("bitcoin_network=regtest");
    println!("bitcoin_funding_txid={funding_txid}");
    println!("bitcoin_claim_txid={claim_txid}");
    println!("bitcoin_claim_confirmed=true");
    println!(
        "evm_chain_id={}",
        evm.call(&["chain-id"]).unwrap_or_default()
    );
    println!("evm_lock_contract={lock_contract}");
    println!("evm_lock_id={lock_id}");
    println!("evm_adaptor_address={evm_adaptor_hex}");
    println!("scalar_extracted_from_bitcoin_claimed_evm_lock=true");
    println!("evm_republished_equals_bitcoin_extracted=true");
    println!("COMPOSED_ROUTE_LIVE_REVERSE_EVIDENCE_END");
}

// ------------------------------------------------- M.8 policy and anchors --

/// The DOM half of the anchors is an explicit fixture (B-F7-007): this
/// container has no live DOM node. The Bitcoin half is real, verified
/// evidence from the regtest node.
fn fixture_dom_anchor_authorization(
    policy: &M8TimingPolicyV1,
    bitcoin: &VerifiedBitcoinFundingEvidenceV1,
) -> AnchoredCrossChainWindowV1 {
    let anchors = M8FundingAnchorsV1 {
        settlement_terms_hash: policy.settlement_terms_hash,
        policy_digest: policy.policy_digest().expect("policy digest"),
        dom: DomFundingAnchorV1 {
            funding_txid: [0x76; 32],
            block_hash: [0x77; 32],
            height: 50,
            block_time_seconds: bitcoin.median_time_past(),
        },
        bitcoin: BitcoinFundingAnchorV1 {
            funding_txid: bitcoin.funding_txid(),
            block_hash: bitcoin.block_hash(),
            height: bitcoin.height(),
            median_time_past: bitcoin.median_time_past(),
        },
    };
    bind_and_validate_funding_anchors(policy, &anchors).expect("valid M.8 anchored window")
}

/// A conservatively SAFE M.8 window. The Bitcoin refund matures first, and
/// the DOM refund sits far enough beyond it that
/// `validate_anchored_cross_chain_window` accepts the ordering with the
/// declared safety margin. Nothing here weakens a check: the numbers are
/// chosen so the real validator passes on its own terms.
///
/// Arithmetic, with the bounds below (max 600 s/block, margin 1800 s, and
/// the 10-interval MTP sample uncertainty the anchoring adds to a BTC height
/// lock): first refund latest = mtp + 10*600 + 10*600 = mtp + 12000; plus the
/// margin = mtp + 13800. Second refund earliest = mtp + 400*60 = mtp + 24000.
/// 13800 <= 24000, so the window is safe. The component test's 200-block DOM
/// refund gives mtp + 12000, which is NOT > 13800 and is correctly refused.
fn safe_bitcoin_timing_policy(terms_hash: [u8; 32]) -> M8TimingPolicyV1 {
    let bounds = ChainTimingBoundsV1 {
        min_block_seconds: 60,
        max_block_seconds: 600,
        max_reorg_seconds: 600,
        observation_seconds: 60,
        broadcast_seconds: 60,
    };
    M8TimingPolicyV1 {
        settlement_terms_hash: terms_hash,
        first_refund: TimelockOffsetV1::BtcBlocks { delta_blocks: 10 },
        second_refund: TimelockOffsetV1::DomBlocks { delta_blocks: 400 },
        safety_margin_seconds: 1_800,
        dom_bounds: bounds,
        btc_bounds: bounds,
        bitcoin_finality: BitcoinFinalityPolicyV1 {
            network: BitcoinNetworkV1::Regtest,
            minimum_confirmations: 1,
            maximum_reorg_depth: 1,
            require_header_chain: true,
            require_witness_commitment: true,
            policy_id: [0x75; 32],
            version: 1,
        },
    }
}

// ------------------------------------------ throwaway Bitcoin Core regtest --

struct RegtestNode {
    directory: PathBuf,
    rpc_port: u16,
}

impl RegtestNode {
    fn start() -> Result<Self, String> {
        require_program("bitcoind")?;
        require_program("bitcoin-cli")?;
        let directory = unique_directory("composed-route-regtest")?;
        let rpc_port = ephemeral_port()?;
        let p2p_port = ephemeral_port()?;
        let status = Command::new("bitcoind")
            .args([
                "-regtest",
                &format!("-datadir={}", directory.display()),
                &format!("-rpcport={rpc_port}"),
                // Bind an ephemeral P2P port: the default 18444 may already be
                // held by another regtest node on this host.
                &format!("-port={p2p_port}"),
                "-fallbackfee=0.0001",
                "-txindex=1",
                "-daemon",
            ])
            .status()
            .map_err(|error| format!("start bitcoind: {error}"))?;
        if !status.success() {
            return Err("bitcoind failed to start".to_string());
        }
        let node = Self {
            directory,
            rpc_port,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if node.cli(&["getblockchaininfo"]).is_ok() {
                node.cli(&["createwallet", "composed"])
                    .or_else(|_| node.cli(&["loadwallet", "composed"]))?;
                return Ok(node);
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err("Bitcoin Core RPC did not become ready".to_string())
    }

    fn cli(&self, arguments: &[&str]) -> Result<String, String> {
        let output = Command::new("bitcoin-cli")
            .arg("-regtest")
            .arg(format!("-datadir={}", self.directory.display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .args(arguments)
            .output()
            .map_err(|error| format!("run bitcoin-cli: {error}"))?;
        checked_stdout(output)
    }

    fn wallet(&self, arguments: &[&str]) -> Result<String, String> {
        let output = Command::new("bitcoin-cli")
            .arg("-regtest")
            .arg(format!("-datadir={}", self.directory.display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .arg("-rpcwallet=composed")
            .args(arguments)
            .output()
            .map_err(|error| format!("run wallet bitcoin-cli: {error}"))?;
        checked_stdout(output)
    }
}

impl Drop for RegtestNode {
    fn drop(&mut self) {
        let _ = self.cli(&["stop"]);
        for _ in 0..50 {
            let cookie = self.directory.join("regtest/.cookie");
            if !cookie.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        if is_safe_test_path(&self.directory) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
}

fn canonical_ancestry(node: &RegtestNode, funding_height: u64) -> Result<Vec<[u8; 80]>, String> {
    let capacity = usize::try_from(funding_height)
        .map_err(|_| "Bitcoin funding height exceeds this platform".to_string())?;
    let mut headers = Vec::with_capacity(capacity);
    for height in 0..funding_height {
        let height_text = height.to_string();
        let hash = node.cli(&["getblockhash", &height_text])?;
        let raw = decode_hex(&node.cli(&["getblockheader", &hash, "false"])?)?;
        headers.push(
            raw.try_into()
                .map_err(|_| "Bitcoin Core header is not 80 bytes".to_string())?,
        );
    }
    Ok(headers)
}

// ------------------------------------------------------------- utilities --

fn point(secret: &RevealedSecretBytes) -> AdaptorPointBytes {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&secret.expose_scalar_bytes()).expect("canonical route scalar");
    AdaptorPointBytes(PublicKey::from_secret_key(&secp, &key).serialize())
}

fn random_canonical_secret() -> Result<RevealedSecretBytes, String> {
    for _ in 0..128 {
        let mut candidate = [0_u8; 32];
        getrandom::fill(&mut candidate)
            .map_err(|error| format!("operating-system randomness failed: {error}"))?;
        if SecretKey::from_slice(&candidate).is_ok() {
            return Ok(RevealedSecretBytes::new(candidate));
        }
    }
    Err("operating-system randomness did not produce a canonical scalar".to_string())
}

fn require_program(program: &str) -> Result<(), String> {
    Command::new(program)
        .arg("--version")
        .output()
        .map(|_| ())
        .map_err(|error| format!("required {program} is unavailable: {error}"))
}

fn unique_directory(prefix: &str) -> Result<PathBuf, String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{prefix}-{}-{timestamp}", std::process::id()));
    std::fs::create_dir(&path).map_err(|error| format!("create regtest directory: {error}"))?;
    Ok(path)
}

fn ephemeral_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| error.to_string())
}

fn checked_stdout(output: Output) -> Result<String, String> {
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    String::from_utf8(output.stdout)
        .map(|stdout| stdout.trim().to_string())
        .map_err(|error| format!("non-UTF8 RPC response: {error}"))
}

fn parse_json(text: &str) -> Value {
    serde_json::from_str(text).expect("canonical JSON")
}

fn first_json_string(text: &str) -> Option<String> {
    serde_json::from_str::<Vec<String>>(text)
        .ok()
        .and_then(|values| values.into_iter().next())
}

fn btc_decimal_to_sat(value: &Value) -> Result<u64, String> {
    let decimal = value.to_string();
    let (whole, fraction) = decimal.split_once('.').unwrap_or((&decimal, ""));
    if whole.starts_with('-') || fraction.len() > 8 {
        return Err("Bitcoin amount is outside the exact nonnegative 8-decimal form".to_string());
    }
    let whole = whole
        .parse::<u64>()
        .map_err(|error| format!("invalid Bitcoin whole amount: {error}"))?;
    let mut fractional = fraction.to_string();
    // `repeat().take()` rather than `repeat_n`: the latter is stable only
    // since 1.82 and this workspace's MSRV is 1.75.
    #[allow(clippy::manual_repeat_n)]
    fractional.extend(std::iter::repeat('0').take(8 - fractional.len()));
    let fractional = fractional
        .parse::<u64>()
        .map_err(|error| format!("invalid Bitcoin fractional amount: {error}"))?;
    whole
        .checked_mul(100_000_000)
        .and_then(|satoshis| satoshis.checked_add(fractional))
        .ok_or_else(|| "Bitcoin amount overflow".to_string())
}

fn txid_internal_bytes(display: &str) -> Result<[u8; 32], String> {
    let mut bytes: [u8; 32] = decode_hex(display)?
        .try_into()
        .map_err(|_| "expected exactly 32 bytes".to_string())?;
    bytes.reverse();
    Ok(bytes)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() % 2 != 0 {
        return Err("hex has odd length".to_string());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex".to_string()),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn is_safe_test_path(path: &Path) -> bool {
    path.starts_with(std::env::temp_dir())
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("composed-route-regtest-"))
}
