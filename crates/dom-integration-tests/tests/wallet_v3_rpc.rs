//! Deterministic node-backed Wallet V3 RPC contract test.

use dom_core::PROTOCOL_VERSION;
use dom_integration_tests::helpers::{free_local_port, mine_blocks, spawn_node, test_config};
use dom_node::node_handle::NodeHandleImpl;
use dom_rpc::{MAX_ANCESTRY_STEPS, MAX_SCAN_RANGE};
use std::sync::Arc;

struct SubmitFixture {
    relayed: bool,
}

impl dom_rpc::NodeHandle for SubmitFixture {
    fn chain_height(&self) -> u64 {
        0
    }
    fn mempool_size(&self) -> usize {
        0
    }
    fn mempool_tx_hashes(&self) -> Vec<[u8; 32]> {
        Vec::new()
    }
    fn get_mempool_tx(&self, _: &[u8; 32]) -> Option<dom_rpc::MempoolTxInfo> {
        None
    }
    fn submit_tx(&self, bytes: Vec<u8>) -> Result<dom_rpc::TxAdmission, dom_rpc::RpcError> {
        if bytes == [0] {
            return Err(dom_rpc::RpcError::Rejected("fixture rejection".into()));
        }
        Ok(dom_rpc::TxAdmission {
            tx_hash: *dom_crypto::blake2b_256(&bytes).as_bytes(),
            relayed: self.relayed,
        })
    }
    fn network(&self) -> &'static str {
        "regtest"
    }
    fn get_block_header(&self, _: &[u8; 32]) -> Option<Vec<u8>> {
        None
    }
    fn get_block_hash_at_height(&self, _: u64) -> Option<[u8; 32]> {
        None
    }
    fn get_utxo(&self, _: &[u8; 33]) -> Option<dom_rpc::UtxoInfo> {
        None
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_v3_rpc_uses_canonical_node_evidence() {
    let port = free_local_port();
    let node = spawn_node(test_config("wallet-v3-rpc", free_local_port(), false)).await;
    mine_blocks(&node, 1).await.expect("deterministic block");

    let listener = dom_rpc::bind(format!("127.0.0.1:{port}").parse().unwrap())
        .await
        .expect("bind local RPC");
    let server = tokio::spawn(dom_rpc::serve_with_token(
        Arc::new(NodeHandleImpl(node.clone())),
        listener,
        Some("wallet-v3-test-token".into()),
    ));
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");
    let identity: serde_json::Value = client
        .get(format!("{base}/chain/identity"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let (magic, genesis, canonical_genesis, tip_height, tip_hash) = {
        let chain = node.chain.lock().await;
        (
            chain.network_magic,
            *chain.genesis_hash.as_bytes(),
            chain.store.get_hash_at_height(0).unwrap().unwrap(),
            chain.tip_height.0,
            *chain.tip_hash.as_bytes(),
        )
    };
    assert_eq!(identity["rpc_api_version"], 1);
    assert_eq!(identity["protocol_version"], PROTOCOL_VERSION);
    assert_eq!(identity["network"], "regtest");
    assert_eq!(identity["network_magic"], format!("{magic:08x}"));
    assert_eq!(
        identity["chain_id"],
        hex::encode(
            dom_consensus::derive_chain_id(magic, &dom_core::Hash256::from_bytes(genesis))
                .as_bytes()
        )
    );
    assert_eq!(identity["genesis_hash"], hex::encode(canonical_genesis));
    assert_eq!(identity["tip_height"], tip_height);
    assert_eq!(identity["tip_hash"], hex::encode(tip_hash));
    assert_eq!(identity["max_scan_range"], MAX_SCAN_RANGE);

    let ancestry_url = format!("{base}/chain/ancestry?ancestor_height=0&ancestor_hash={}&descendant_height={tip_height}&descendant_hash={}&max_steps={tip_height}", hex::encode(canonical_genesis), hex::encode(tip_hash));
    let ancestry: serde_json::Value = client
        .get(ancestry_url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ancestry["canonical"], true);
    let wrong = client.get(format!("{base}/chain/ancestry?ancestor_height=0&ancestor_hash={}&descendant_height=0&descendant_hash={}&max_steps=0", "00".repeat(32), hex::encode(canonical_genesis))).send().await.unwrap();
    assert_eq!(wrong.status(), reqwest::StatusCode::OK);
    assert_eq!(
        wrong.json::<serde_json::Value>().await.unwrap()["canonical"],
        false
    );
    assert_eq!(client.get(format!("{base}/chain/ancestry?ancestor_height=0&ancestor_hash={}&descendant_height={}&descendant_hash={}&max_steps={}", hex::encode(canonical_genesis), MAX_ANCESTRY_STEPS + 1, hex::encode(tip_hash), MAX_ANCESTRY_STEPS)).send().await.unwrap().status(), reqwest::StatusCode::BAD_REQUEST);

    let scan: serde_json::Value = client
        .get(format!("{base}/chain/scan?from=0&to={tip_height}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let blocks = scan["blocks"].as_array().unwrap();
    assert!(blocks
        .windows(2)
        .all(|w| w[0]["height"].as_u64() < w[1]["height"].as_u64()));
    assert!(blocks
        .iter()
        .all(|b| b["hash"].as_str().unwrap() != "00".repeat(32)));
    let excess = blocks[0]["kernel_excesses"][0].as_str().unwrap();
    assert_eq!(
        client
            .get(format!("{base}/kernel/{excess}"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        client
            .get(format!("{base}/kernel/{}", "11".repeat(33)))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    let rejected: serde_json::Value = client
        .post(format!("{base}/tx/submit"))
        .json(&serde_json::json!({"tx_hex":"00"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rejected["accepted"], false);
    assert_eq!(rejected["relayed"], false);
    assert!(rejected.get("tx_hash").is_none() && rejected.get("error").is_some());
    server.abort();
    let _ = server.await;

    for relayed in [true, false] {
        let port = free_local_port();
        let listener = dom_rpc::bind(format!("127.0.0.1:{port}").parse().unwrap())
            .await
            .unwrap();
        let task = tokio::spawn(dom_rpc::serve_with_token(
            Arc::new(SubmitFixture { relayed }),
            listener,
            Some("submit-fixture".into()),
        ));
        let tx_hex = "ab".repeat(32);
        let response: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/tx/submit"))
            .json(&serde_json::json!({"tx_hex": tx_hex}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(response["accepted"], true);
        assert_eq!(response["relayed"], relayed);
        assert_eq!(
            response["tx_hash"],
            hex::encode(dom_crypto::blake2b_256(&[0xab; 32]).as_bytes())
        );
        if relayed {
            assert!(response.get("warning").is_none());
        } else {
            assert!(response["warning"].as_str().is_some());
        }
        task.abort();
        let _ = task.await;
    }
}
