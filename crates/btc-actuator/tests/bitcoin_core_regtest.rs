//! Explicit live gate for exact persist/broadcast/reconcile against Core.

#![cfg(all(target_os = "linux", feature = "rpc-http"))]

use std::error::Error;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use adapter_btc::timelock::ChainTimingBoundsV1;
use adapter_btc::types::BitcoinNetworkV1;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash;
use bitcoin::Network;
use btc_actuator::{
    BitcoinActionV1, BitcoinActuationScopeAuthorizationV1, BitcoinActuationScopeV1,
    BitcoinFeeBumpPolicyV1, BitcoinLegV1, BitcoinOutpointV1, BitcoinReconciliationV1,
    DurableBitcoinActuatorV1, ExactBitcoinTransactionV1, HttpBitcoinCoreRpcConfigV1,
    HttpBitcoinCoreRpcV1,
};
use btc_crypto::SecpContext;
use chain_profile::{ChainKindV1, ChainProfileV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, BitcoinDeploymentV1, ChainDeploymentV1,
    DomDeploymentV1, DomNetworkV1, DomRuntimeIdentityV1, RegistryChainProfileV1,
    RegistryManifestV1, RegistrySignatureV1, RegistryValidationPolicyV1,
    ResolvedBitcoinDeploymentV1, SignedRegistryV1,
};
use kaystra_core::types::{AssetId, ChainId, FinalityPolicyV1};
use serde_json::{json, Map, Value};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const DOM_CHAIN: ChainId = ChainId([
    0x22, 0x38, 0x4b, 0x4c, 0xbf, 0xaa, 0xe3, 0x06, 0xa7, 0xbd, 0xb2, 0x3a, 0x82, 0x24, 0x42, 0xf7,
    0xe6, 0x8f, 0xb5, 0x1f, 0x65, 0x32, 0x86, 0x97, 0xa7, 0x54, 0xa9, 0xf3, 0xab, 0xd6, 0x98, 0xe1,
]);
const DOM_GENESIS: [u8; 32] = [
    0xfd, 0xda, 0x02, 0x7e, 0x4a, 0x46, 0xdd, 0x36, 0x67, 0x17, 0xc6, 0xe0, 0xa9, 0x76, 0xbf, 0x3e,
    0x0a, 0x75, 0x12, 0xc5, 0xed, 0xf0, 0x84, 0x70, 0xb0, 0xdc, 0xa9, 0x9d, 0xde, 0xe3, 0xfe, 0x1f,
];

struct RegtestNode {
    directory: TempDir,
    rpc_port: u16,
}

impl RegtestNode {
    fn start() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let rpc_port = listener.local_addr()?.port();
        drop(listener);
        let status = Command::new("bitcoind")
            .args([
                "-regtest",
                &format!("-datadir={}", directory.path().display()),
                &format!("-rpcport={rpc_port}"),
                "-fallbackfee=0.0001",
                "-txindex=1",
                "-listen=0",
                "-daemon",
            ])
            .status()?;
        if !status.success() {
            return Err(io_error("bitcoind failed to start").into());
        }
        let node = Self {
            directory,
            rpc_port,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if node.cli(&["getblockchaininfo"]).is_ok() {
                node.cli(&["createwallet", "actuator"])?;
                return Ok(node);
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err(io_error("Bitcoin Core did not become ready").into())
    }

    fn cli(&self, arguments: &[&str]) -> TestResult<String> {
        checked_stdout(
            Command::new("bitcoin-cli")
                .arg("-regtest")
                .arg(format!("-datadir={}", self.directory.path().display()))
                .arg(format!("-rpcport={}", self.rpc_port))
                .args(arguments)
                .output()?,
        )
    }

    fn wallet(&self, arguments: &[&str]) -> TestResult<String> {
        self.wallet_named("actuator", arguments)
    }

    fn wallet_named(&self, wallet: &str, arguments: &[&str]) -> TestResult<String> {
        checked_stdout(
            Command::new("bitcoin-cli")
                .arg("-regtest")
                .arg(format!("-datadir={}", self.directory.path().display()))
                .arg(format!("-rpcport={}", self.rpc_port))
                .arg(format!("-rpcwallet={wallet}"))
                .args(arguments)
                .output()?,
        )
    }

    fn wait_for_txindex(&self) -> TestResult<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            let height: u64 = self.cli(&["getblockcount"])?.parse()?;
            let index: Value = serde_json::from_str(&self.cli(&["getindexinfo", "txindex"])?)?;
            let txindex = &index["txindex"];
            if txindex["synced"].as_bool() == Some(true)
                && txindex["best_block_height"].as_u64() == Some(height)
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err(io_error("txindex did not catch up").into())
    }
}

impl Drop for RegtestNode {
    fn drop(&mut self) {
        let _result = self.cli(&["stop"]);
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.directory.path().join("regtest/.cookie").exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(100));
        }
    }
}

fn checked_stdout(output: Output) -> TestResult<String> {
    if !output.status.success() {
        return Err(io_error("Bitcoin Core command failed").into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn io_error(message: &'static str) -> std::io::Error {
    std::io::Error::other(message)
}

fn timing() -> ChainTimingBoundsV1 {
    ChainTimingBoundsV1 {
        min_block_seconds: 5,
        max_block_seconds: 20,
        max_reorg_seconds: 200,
        observation_seconds: 30,
        broadcast_seconds: 20,
    }
}

fn finality() -> FinalityPolicyV1 {
    FinalityPolicyV1 {
        min_confirmations: 2,
        max_reorg_depth: 3,
    }
}

fn deployment() -> TestResult<ResolvedBitcoinDeploymentV1> {
    let btc_chain = ChainId([0x02; 32]);
    let dom_asset = AssetId([0x11; 32]);
    let btc_asset = AssetId([0x12; 32]);
    let manifest = RegistryManifestV1 {
        network_id: [0xf1; 32],
        epoch: 11,
        valid_from: 1_000,
        expires_at: 9_000,
        dom: DomDeploymentV1 {
            chain_id: DOM_CHAIN,
            genesis_hash: DOM_GENESIS,
            runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
            consensus_rules_digest: [0xf3; 32],
            scriptless_api_version: 1,
            timing: timing(),
            finality: finality(),
            native_asset: dom_asset,
        },
        chains: vec![RegistryChainProfileV1 {
            profile: ChainProfileV1 {
                chain_id: btc_chain,
                kind: ChainKindV1::Bitcoin {
                    network: BitcoinNetworkV1::Regtest,
                },
                timing: timing(),
                finality: finality(),
                native_asset: btc_asset,
                allowed_assets: vec![],
            },
            deployment: ChainDeploymentV1::Bitcoin(BitcoinDeploymentV1 {
                genesis_hash: genesis_block(Network::Regtest)
                    .block_hash()
                    .to_raw_hash()
                    .to_byte_array(),
                signet_challenge: vec![],
                max_fee_rate_sat_vbyte: 100,
                min_relay_fee_sat_kvb: 1_000,
            }),
        }],
        assets: vec![
            AssetBindingV1 {
                chain_id: btc_chain,
                asset_id: btc_asset,
                decimals: 8,
                representation: AssetRepresentationV1::Native,
            },
            AssetBindingV1 {
                chain_id: DOM_CHAIN,
                asset_id: dom_asset,
                decimals: 9,
                representation: AssetRepresentationV1::Native,
            },
        ],
    };
    let crypto = SecpContext::new(&[0xf4; 32]);
    let digest = manifest.manifest_digest()?;
    let (signature, public_key) = crypto.sign_bip340(&[0xf5; 32], &digest, &[0xf6; 32])?;
    let authorities = AuthoritySetV1::new(1, vec![public_key])?;
    let signed = SignedRegistryV1::new(
        &manifest,
        vec![RegistrySignatureV1 {
            signer_index: 0,
            signature,
        }],
    )?;
    let resolved = signed.verify(
        &authorities,
        &crypto,
        RegistryValidationPolicyV1 {
            now_seconds: 2_000,
            expected_network_id: [0xf1; 32],
            minimum_epoch: 11,
        },
    )?;
    Ok(resolved
        .resolve_chain(btc_chain)
        .ok_or_else(|| io_error("missing Bitcoin profile"))?
        .bitcoin_deployment_capability()?)
}

fn bitcoin_to_sat(value: &Value) -> TestResult<u64> {
    let text = value.to_string();
    let (whole, fraction) = text.split_once('.').unwrap_or((&text, ""));
    if fraction.len() > 8 {
        return Err(io_error("amount has excess precision").into());
    }
    let whole: u64 = whole.parse()?;
    let mut padded = fraction.to_owned();
    while padded.len() < 8 {
        padded.push('0');
    }
    let fraction: u64 = if padded.is_empty() {
        0
    } else {
        padded.parse()?
    };
    Ok(whole
        .checked_mul(100_000_000)
        .and_then(|amount| amount.checked_add(fraction))
        .ok_or_else(|| io_error("amount overflow"))?)
}

fn sat_to_bitcoin(value: u64) -> String {
    format!("{}.{:08}", value / 100_000_000, value % 100_000_000)
}

#[test]
#[ignore = "starts an installed Bitcoin Core regtest daemon"]
fn exact_transaction_is_persisted_broadcast_and_finalized_by_real_core() -> TestResult {
    let node = RegtestNode::start()?;
    let miner = node.wallet(&["getnewaddress"])?;
    node.cli(&["generatetoaddress", "1", &miner])?;
    node.cli(&["createwallet", "sink"])?;
    let sink = node.wallet_named("sink", &["getnewaddress"])?;
    node.cli(&["unloadwallet", "sink"])?;
    node.cli(&["generatetoaddress", "100", &sink])?;
    node.wait_for_txindex()?;
    let unspent: Value = serde_json::from_str(&node.wallet(&["listunspent"])?)?;
    let selected = unspent
        .as_array()
        .and_then(|items| items.first())
        .ok_or_else(|| io_error("missing mature coinbase"))?;
    let funding_txid = selected["txid"]
        .as_str()
        .ok_or_else(|| io_error("missing UTXO txid"))?;
    let funding_vout = selected["vout"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| io_error("invalid UTXO vout"))?;
    let funding_amount = bitcoin_to_sat(&selected["amount"])?;
    let fee_sat = 10_000;
    let destination_amount = funding_amount
        .checked_sub(fee_sat)
        .ok_or_else(|| io_error("funding amount below fee"))?;
    let destination = node.wallet(&["getnewaddress"])?;
    let inputs = json!([{
        "txid": funding_txid,
        "vout": funding_vout,
        "sequence": 4_294_967_293_u64,
    }])
    .to_string();
    let mut output_map = Map::new();
    output_map.insert(
        destination.clone(),
        serde_json::from_str(&sat_to_bitcoin(destination_amount))?,
    );
    let outputs = Value::Object(output_map).to_string();
    let unsigned = node.wallet(&["createrawtransaction", &inputs, &outputs])?;
    let signed: Value =
        serde_json::from_str(&node.wallet(&["signrawtransactionwithwallet", &unsigned])?)?;
    if signed["complete"].as_bool() != Some(true) {
        return Err(io_error("wallet did not complete transaction").into());
    }
    let raw = decode_hex(
        signed["hex"]
            .as_str()
            .ok_or_else(|| io_error("missing signed transaction"))?,
    )?;
    let transaction: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw)?;
    let input_outpoint = transaction
        .input
        .first()
        .ok_or_else(|| io_error("signed transaction has no input"))?
        .previous_output;
    let exact = ExactBitcoinTransactionV1::from_consensus_bytes(raw)?;
    let deployment = deployment()?;
    let scope = BitcoinActuationScopeV1::authorize(BitcoinActuationScopeAuthorizationV1 {
        deployment: &deployment,
        route_id: [0x71; 32],
        effect_id: [0x72; 32],
        leg: BitcoinLegV1::Downstream,
        action: BitcoinActionV1::Refund,
        fence_epoch: 1,
        terms_digest: [0x73; 32],
        expected_txid: exact.txid(),
        intent_digest: exact.intent_digest(),
        contract_outpoint: Some(BitcoinOutpointV1 {
            txid: input_outpoint.txid.to_raw_hash().to_byte_array(),
            vout: input_outpoint.vout,
        }),
        contract_amount_sat: funding_amount,
        refund_record_digest: None,
        fee_policy: BitcoinFeeBumpPolicyV1 {
            initial_fee_sat: fee_sat,
            maximum_fee_sat: 20_000,
            maximum_fee_rate_sat_vbyte: 100,
            change_vout: Some(0),
        },
        valid_until_ms: 10_000,
    })?;
    let store_path = node.directory.path().join("actuator.sqlite");
    let mut store = DurableBitcoinActuatorV1::create(&store_path, [0x74; 32])?;
    store.acquire_lease(100, 1_000)?;
    store.prepare_terminal(&scope, exact, 101)?;
    let mut rpc = HttpBitcoinCoreRpcV1::connect(HttpBitcoinCoreRpcConfigV1 {
        endpoint: format!("http://127.0.0.1:{}", node.rpc_port),
        cookie_path: node.directory.path().join("regtest/.cookie"),
    })?;
    let receipt = store.broadcast_terminal(&scope, &mut rpc, 102)?;
    assert_eq!(
        store.reconcile_terminal(&scope, &mut rpc, 103, || Ok(103))?,
        BitcoinReconciliationV1::ExactMempool
    );
    node.wallet(&["generatetoaddress", "2", &miner])?;
    node.wait_for_txindex()?;
    let block_height = node.cli(&["getblockcount"])?.parse::<u64>()? - 1;
    assert_eq!(
        store.reconcile_terminal(&scope, &mut rpc, 104, || Ok(104))?,
        BitcoinReconciliationV1::ExactFinal {
            confirmations: 2,
            block_height,
        }
    );
    let final_view = store.terminal_operation(scope.effect_id())?;
    assert_eq!(final_view.block_height, Some(block_height));
    assert!(final_view.block_hash.is_some());
    assert!(final_view.evidence_digest.is_some());
    assert_eq!(receipt.txid, scope.expected_txid());
    Ok(())
}

fn decode_hex(value: &str) -> TestResult<Vec<u8>> {
    if value.len() % 2 != 0 || !value.is_ascii() {
        return Err(io_error("invalid hex").into());
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        output.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(output)
}

fn nibble(value: u8) -> TestResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(io_error("invalid hex nibble").into()),
    }
}
