//! Real Bitcoin Core regtest proof for the F7 delayed-reveal boundary.
//!
//! Run explicitly with:
//!
//! ```text
//! cargo test -p f5-e2e --test f7_bitcoin_regtest -- --ignored --nocapture
//! ```
//!
//! The test owns a throwaway `bitcoind`, prepares the MuSig2 adaptor claim
//! without `t`, adapts only after the route reveal, broadcasts it, mines it,
//! fetches the exact witness-bearing confirmed bytes, and extracts the same
//! scalar through the canonical evidence consumer. No secret is placed in a
//! process argument or printed.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use adapter_btc::timelock::{
    bind_and_validate_funding_anchors, BitcoinFinalityPolicyV1, BitcoinFundingAnchorV1,
    ChainTimingBoundsV1, DomFundingAnchorV1, M8FundingAnchorsV1, M8TimingPolicyV1,
    TimelockOffsetV1,
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

struct RegtestNode {
    directory: PathBuf,
    rpc_port: u16,
}

impl RegtestNode {
    fn start() -> Result<Self, String> {
        require_program("bitcoind")?;
        require_program("bitcoin-cli")?;
        let directory = unique_directory("f7-bitcoin-regtest")?;
        let rpc_port = ephemeral_port()?;
        let status = Command::new("bitcoind")
            .args([
                "-regtest",
                &format!("-datadir={}", directory.display()),
                &format!("-rpcport={rpc_port}"),
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
                node.cli(&["createwallet", "f7"])
                    .or_else(|_| node.cli(&["loadwallet", "f7"]))?;
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
            .arg("-rpcwallet=f7")
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

#[test]
#[ignore = "requires the installed Bitcoin Core binary and starts a real regtest node"]
fn confirmed_exact_bitcoin_claim_is_the_only_f7_secret_extraction_authority() {
    let node = RegtestNode::start().expect("start isolated Bitcoin Core regtest");
    let contract_address = regtest_address();
    let miner = node.wallet(&["getnewaddress"]).expect("miner address");
    node.wallet(&["generatetoaddress", "1", &miner])
        .expect("mine wallet coinbase");
    node.wallet(&["generatetoaddress", "100", &contract_address])
        .expect("mature wallet coinbase without wallet churn");

    let funding_txid = node
        .wallet(&["sendtoaddress", &contract_address, "0.5"])
        .expect("fund exact F7 P2TR output");
    let funding_block = node
        .wallet(&["generatetoaddress", "1", &contract_address])
        .expect("confirm funding");
    let block_hash = first_json_string(&funding_block).expect("funding block hash");
    let block: Value = parse_json(&node.cli(&["getblock", &block_hash]).expect("funding block"));
    let funding_height = block["height"].as_u64().expect("funding block height");
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
    let amount_sat = btc_decimal_to_sat(&contract_vout["value"])
        .expect("exact funding output value in satoshis");
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
    .expect("decode canonical funding block");
    let ancestry = canonical_ancestry(&node, funding_height).expect("verified ancestry input");
    let timing_policy = real_bitcoin_timing_policy(terms_hash);
    let verified_bitcoin_funding = verify_bitcoin_funding_evidence(
        &timing_policy,
        funding_txid_internal,
        funding_height,
        &funding_block_bytes,
        &ancestry,
        &[],
    )
    .expect("full Bitcoin funding block and header chain verify");
    let funding = FundingRef {
        txid: funding_txid_internal,
        vout,
        amount_sat,
    };
    let authorizations = [
        real_bitcoin_anchor_authorization(&timing_policy, &verified_bitcoin_funding),
        real_bitcoin_anchor_authorization(&timing_policy, &verified_bitcoin_funding),
    ];
    let revealed = random_canonical_secret().expect("generate an ephemeral route secret");
    let adaptor_point = point(&revealed);
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
        &adaptor_point,
        authorizations,
        &seal_one,
        &seal_two,
        &vault_one,
        &vault_two,
    )
    .expect("prepare durable claim without t");
    assert_eq!(prepared.adaptor_point(), adaptor_point);
    let claim = adapt_prepared_route_claim(prepared, &revealed)
        .expect("adapt only after the route reveals t");
    assert!(verify_claim_witness(
        &claim.claim.raw_transaction,
        &funding,
        &destination_script,
        CLAIM_FEE_SAT,
    ));
    let claim_hex = encode_hex(&claim.claim.raw_transaction);
    let claim_txid = node
        .cli(&["sendrawtransaction", &claim_hex])
        .expect("real Bitcoin mempool accepts claim");
    node.wallet(&["generatetoaddress", "1", &contract_address])
        .expect("confirm real claim");
    let confirmed_hex = node
        .cli(&["getrawtransaction", &claim_txid, "false"])
        .expect("read exact confirmed witness-bearing claim");
    let confirmed = decode_hex(&confirmed_hex).expect("decode confirmed claim");
    assert_eq!(confirmed, claim.claim.raw_transaction);
    assert_eq!(
        extract_revealed_secret_from_confirmed_claim(&claim.extraction, &confirmed)
            .expect("extract only from exact canonical confirmed evidence"),
        revealed
    );

    println!("F7_BITCOIN_REAL_EVIDENCE_BEGIN");
    println!("network=regtest");
    println!("funding_txid={funding_txid}");
    println!("funding_height={funding_height}");
    println!("claim_txid={claim_txid}");
    println!("claim_confirmed=true");
    println!("exact_witness_bytes_match=true");
    println!("extracted_t_times_g_equals_frozen_T=true");
    println!("F7_BITCOIN_REAL_EVIDENCE_END");
}

fn real_bitcoin_anchor_authorization(
    policy: &M8TimingPolicyV1,
    bitcoin: &VerifiedBitcoinFundingEvidenceV1,
) -> adapter_btc::timelock::AnchoredCrossChainWindowV1 {
    // This component test has no DOM node. Its DOM half remains an explicit
    // fixture and therefore cannot close G-F7; the combined runner uses
    // `verify_f7_route_anchor_authority` with the concrete authenticated DOM
    // scanner and consumes the resulting opaque Store authorization by value.
    let terms_hash = policy.settlement_terms_hash;
    let anchors = M8FundingAnchorsV1 {
        settlement_terms_hash: terms_hash,
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

fn real_bitcoin_timing_policy(terms_hash: [u8; 32]) -> M8TimingPolicyV1 {
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
        second_refund: TimelockOffsetV1::DomBlocks { delta_blocks: 200 },
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

fn point(secret: &RevealedSecretBytes) -> AdaptorPointBytes {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&secret.expose_scalar_bytes()).expect("canonical test scalar");
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
    serde_json::from_str(text).expect("Bitcoin Core returns canonical JSON")
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
    display_hash_internal_bytes(display)
}

fn display_hash_internal_bytes(display: &str) -> Result<[u8; 32], String> {
    let mut bytes = decode_hex_32(display)?;
    bytes.reverse();
    Ok(bytes)
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    decode_hex(value)?
        .try_into()
        .map_err(|_| "expected exactly 32 bytes".to_string())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
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
            .is_some_and(|name| name.starts_with("f7-bitcoin-regtest-"))
}
