//! Cross-repository F7 proof for the final DOM Wallet Slate boundary.
//!
//! The sender is the pinned real DOM node and its canonical WalletDir. The
//! recipient is the official Wallet V3 `WalletService`, backed by that node's
//! full-fidelity remote scanner. No simulated chain, transaction, miner, or
//! recipient implementation participates in this test.

use dom_config::NodeConfig;
use dom_node::node::DomNode;
use dom_wallet::{Bip39Seed, Network as DomWalletNetwork, WalletDir};
use dom_wallet_core::WalletService;
use dom_wallet_core_protocol::CanonicalSlate;
use dom_wallet_remote_source::RemoteNodeSource;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

const TEST_LMDB_MAP_SIZE: usize = 64 << 20;
const RPC_TOKEN: &str = "f7-wallet-official-recipient-test-token";
const SENDER_PASSWORD: &str = "f7-sender-wallet-password";
const RECIPIENT_PASSWORD: &str = "f7-recipient-wallet-password";

struct FastRegtestGuard;

impl FastRegtestGuard {
    fn install() -> Self {
        std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
        Self
    }
}

impl Drop for FastRegtestGuard {
    fn drop(&mut self) {
        std::env::remove_var("DOM_REGTEST_FAST_MINING");
    }
}

struct RunningNode {
    node: Arc<DomNode>,
    task: JoinHandle<Result<(), dom_core::DomError>>,
}

fn unused_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral loopback port");
    listener.local_addr().expect("read the ephemeral address")
}

fn sender_node_config(
    data_directory: &Path,
    wallet_directory: &Path,
    p2p_address: SocketAddr,
    rpc_address: SocketAddr,
) -> NodeConfig {
    let mut config = NodeConfig::regtest();
    config.data_dir = data_directory
        .to_str()
        .expect("UTF-8 node data path")
        .to_owned();
    config.p2p_listen_addr = p2p_address.to_string();
    config.max_inbound = 2;
    config.min_outbound = 0;
    config.disable_dns_seeds = true;
    config.seed_peers.clear();
    config.mine = false;
    config.wallet_path = Some(
        wallet_directory
            .to_str()
            .expect("UTF-8 sender WalletDir path")
            .to_owned(),
    );
    config.wallet_password = Some(SENDER_PASSWORD.to_owned());
    config.rpc_listen_addr = Some(rpc_address.to_string());
    config.rpc_bearer_token = Some(RPC_TOKEN.to_owned());
    config.metrics_listen_addr = None;
    config
}

fn wait_for_rpc(client: &Client, base_url: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if client
            .get(format!("{base_url}/health"))
            .send()
            .is_ok_and(|response| response.status().is_success())
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "real DOM RPC did not become ready"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn start_node(
    runtime: &tokio::runtime::Runtime,
    config: NodeConfig,
    client: &Client,
    base_url: &str,
) -> RunningNode {
    let node = Arc::new(
        DomNode::init_with_map_size(config, TEST_LMDB_MAP_SIZE)
            .expect("initialize the pinned real DOM node"),
    );
    let task = runtime.spawn(Arc::clone(&node).run());
    wait_for_rpc(client, base_url);
    RunningNode { node, task }
}

async fn stop_node(running: RunningNode) {
    running.node.request_shutdown().await;
    tokio::time::timeout(Duration::from_secs(20), running.task)
        .await
        .expect("real DOM node shutdown deadline")
        .expect("real DOM node task join")
        .expect("real DOM node graceful shutdown");
}

fn authenticated_post(client: &Client, base_url: &str, path: &str, body: Value) -> Value {
    let response = client
        .post(format!("{base_url}{path}"))
        .bearer_auth(RPC_TOKEN)
        .json(&body)
        .send()
        .expect("send authenticated request to real DOM");
    let status = response.status();
    let bytes = response.bytes().expect("read real DOM response");
    assert!(
        status.is_success(),
        "real DOM request {path} failed with {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).expect("decode real DOM JSON response")
}

fn mempool_total(client: &Client, base_url: &str) -> u64 {
    let response = client
        .get(format!("{base_url}/mempool"))
        .send()
        .expect("query real DOM mempool");
    assert!(response.status().is_success());
    response.json::<Value>().expect("decode mempool response")["total"]
        .as_u64()
        .expect("mempool total")
}

fn decode_hex_field(value: &Value, field: &str) -> Vec<u8> {
    hex::decode(
        value[field]
            .as_str()
            .unwrap_or_else(|| panic!("missing hexadecimal field {field}")),
    )
    .unwrap_or_else(|error| panic!("decode hexadecimal field {field}: {error}"))
}

fn attach_official_recipient(base_url: &str) -> WalletService {
    let source = RemoteNodeSource::new(base_url, Some(RPC_TOKEN))
        .expect("construct the official full-fidelity remote source");
    let mut service = WalletService::default();
    service
        .start_remote_source(Arc::new(source))
        .expect("attach the official WalletService to real DOM");
    service
}

#[test]
fn official_wallet_service_crosses_real_dom_three_message_boundary_after_restarts() {
    let _fast_regtest = FastRegtestGuard::install();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("build the real-node test runtime");
    let directory = tempfile::tempdir().expect("temporary F7 test directory");
    let node_data = directory.path().join("real-dom-chain");
    let sender_wallet = directory.path().join("real-dom-sender-wallet");
    let recipient_wallet = directory.path().join("official-wallet-v3-recipient");
    let sender_seed = Bip39Seed::generate_new().expect("generate sender seed");
    drop(
        WalletDir::create_from_seed(
            &sender_wallet,
            SENDER_PASSWORD,
            DomWalletNetwork::Regtest,
            &dom_core::Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
            &sender_seed,
        )
        .expect("create canonical sender WalletDir"),
    );

    let p2p_address = unused_loopback_address();
    let rpc_address = unused_loopback_address();
    let base_url = format!("http://{rpc_address}");
    let config = sender_node_config(&node_data, &sender_wallet, p2p_address, rpc_address);
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("build loopback HTTP client");

    let running = start_node(&runtime, config.clone(), &client, &base_url);
    let mined = authenticated_post(&client, &base_url, "/regtest/mine/v1", json!({"count": 2}));
    assert_eq!(mined["start_height"].as_u64(), Some(1));
    assert_eq!(mined["end_height"].as_u64(), Some(2));
    assert_eq!(mempool_total(&client, &base_url), 0);

    let mut recipient = attach_official_recipient(&base_url);
    recipient
        .create_recoverable_for_embedded(&recipient_wallet, RECIPIENT_PASSWORD)
        .expect("create the official recipient wallet");
    recipient
        .recovery_phrase_confirmed(RECIPIENT_PASSWORD)
        .expect("complete recipient recovery ceremony");
    recipient
        .unlock(RECIPIENT_PASSWORD)
        .expect("unlock recipient wallet");

    let offer = authenticated_post(
        &client,
        &base_url,
        "/wallet/slate/v1/create",
        json!({
            "amount_noms": 40_000_000u64,
            "fee_noms": 100_000u64,
            "expires_at_height": 100u64
        }),
    );
    assert_eq!(mempool_total(&client, &base_url), 0);
    let offer_bytes = decode_hex_field(&offer, "canonical_slate_hex");
    let recipient_identity = recipient
        .embedded_core_identity()
        .expect("official recipient real-chain identity");
    let offer_text = CanonicalSlate::from_recovery_bytes(
        &offer_bytes,
        &recipient_identity,
        recipient_identity.current_tip.height,
    )
    .expect("validate the node's canonical offer in Wallet V3")
    .to_text();
    let imported = recipient
        .slate_request_import(&offer_text)
        .expect("official WalletService imports the real DOM offer");
    let slate_id = imported.slate_id.expect("recipient Slate identifier");
    recipient
        .slate_response_create(slate_id)
        .expect("official WalletService creates the recipient response");
    let response_text = recipient
        .slate_response_export(slate_id)
        .expect("official WalletService exports the recipient response")
        .text;
    let response = CanonicalSlate::from_text(
        &response_text,
        &recipient_identity,
        recipient_identity.current_tip.height,
    )
    .expect("validate official recipient response");
    let response_hex = hex::encode(response.canonical_bytes());

    runtime.block_on(stop_node(running));
    let running = start_node(&runtime, config.clone(), &client, &base_url);
    let finalized = authenticated_post(
        &client,
        &base_url,
        "/wallet/slate/v1/finalize",
        json!({"canonical_response_hex": response_hex}),
    );
    assert_eq!(mempool_total(&client, &base_url), 0);
    let finalized_bytes = decode_hex_field(&finalized, "canonical_tx_hex");
    let finalized_hash = decode_hex_field(&finalized, "tx_hash");
    assert_eq!(
        dom_crypto::blake2b_256(&finalized_bytes).as_bytes(),
        finalized_hash.as_slice()
    );

    recipient
        .close()
        .expect("close official recipient before restart");
    let mut recipient = attach_official_recipient(&base_url);
    recipient
        .open(&recipient_wallet)
        .expect("reopen official recipient after restart");
    recipient
        .unlock(RECIPIENT_PASSWORD)
        .expect("unlock restarted official recipient");
    let verified = recipient
        .transaction_finalized_verify_and_import(slate_id, &finalized_bytes)
        .expect("recipient independently verifies and persists the exact final transaction");
    assert_eq!(
        verified.transaction_hash.as_slice(),
        finalized_hash.as_slice()
    );

    let pending_key = finalized["pending_key"]
        .as_str()
        .expect("pending sender record key")
        .to_owned();
    let expected_hash = finalized["tx_hash"]
        .as_str()
        .expect("expected transaction hash")
        .to_owned();
    runtime.block_on(stop_node(running));
    let running = start_node(&runtime, config.clone(), &client, &base_url);

    // Deliberately discard the successful reply. This models an ACK lost after
    // durable admission: the retry below has only the opaque pending key and
    // expected hash, never caller-supplied transaction bytes.
    drop(authenticated_post(
        &client,
        &base_url,
        "/wallet/slate/v1/submit",
        json!({
            "pending_key_hex": pending_key,
            "expected_transaction_hash_hex": expected_hash
        }),
    ));
    assert_eq!(mempool_total(&client, &base_url), 1);

    runtime.block_on(stop_node(running));
    let running = start_node(&runtime, config, &client, &base_url);
    assert_eq!(mempool_total(&client, &base_url), 0);
    let retried = authenticated_post(
        &client,
        &base_url,
        "/wallet/slate/v1/submit",
        json!({
            "pending_key_hex": pending_key,
            "expected_transaction_hash_hex": expected_hash
        }),
    );
    assert_eq!(
        decode_hex_field(&retried, "canonical_tx_hex"),
        finalized_bytes
    );
    assert_eq!(decode_hex_field(&retried, "tx_hash"), finalized_hash);
    assert_eq!(retried["state"].as_str(), Some("new"));
    assert_eq!(mempool_total(&client, &base_url), 1);

    let already_known = authenticated_post(
        &client,
        &base_url,
        "/wallet/slate/v1/submit",
        json!({
            "pending_key_hex": pending_key,
            "expected_transaction_hash_hex": expected_hash
        }),
    );
    assert_eq!(
        decode_hex_field(&already_known, "canonical_tx_hex"),
        finalized_bytes
    );
    assert_eq!(already_known["state"].as_str(), Some("mempool"));
    assert_eq!(already_known["already_known"].as_bool(), Some(true));

    runtime.block_on(stop_node(running));
    recipient.close().expect("close official recipient cleanly");
}
