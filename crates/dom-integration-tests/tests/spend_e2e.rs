//! End-to-end spend test (DOM Doc 8).
//!
//! Node A mines a coinbase, wallet A spends it via the `/wallet/spend` RPC,
//! Dandelion fluff propagates the transaction to node B over P2P, node B
//! includes the transaction in the next block it mines. Asserts at every
//! stage; runs on every CI invocation.
//!
//! Resource profile: `Network::Regtest` mines with the cache-only
//! RandomX VM (~256 MB per node) and `REGTEST_COINBASE_MATURITY = 1`,
//! so two miners + a spend pipeline fit comfortably under 1 GB RAM and
//! complete in well under two minutes on a developer laptop. Consensus
//! validation is *unchanged* from Mainnet/Testnet — only the PoW target
//! (trivial), coinbase maturity (1 block), and VM mode (no full dataset)
//! differ.

use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_spend_e2e_cross_node_propagation() {
    init_tracing();

    // Deterministic Bearer token so the HTTP client knows it without poking files.
    std::env::set_var("DOM_RPC_TOKEN", "spend-e2e-token");

    // ── Node A (miner + wallet + RPC) ────────────────────────────────────
    let mut config_a = test_config("spend-e2e-a", 43380, false);
    config_a.wallet_path = Some("/tmp/dom-spend-e2e-wallet-a.dom".into());
    config_a.wallet_password = Some("pw-a".into());
    config_a.rpc_listen_addr = Some("127.0.0.1:43480".into());

    let _ = std::fs::remove_file("/tmp/dom-spend-e2e-wallet-a.dom");
    let _ = std::fs::remove_dir_all("/tmp/dom-test-spend-e2e-a");

    // ── Node B (peer that should receive the tx via Dandelion fluff) ──────
    let mut config_b = test_config("spend-e2e-b", 43381, false);
    config_b.seed_peers = vec!["127.0.0.1:43380".into()];
    let _ = std::fs::remove_dir_all("/tmp/dom-test-spend-e2e-b");

    let node_a = spawn_node(config_a).await;
    let node_b = spawn_node(config_b).await;

    tokio::spawn(node_a.clone().run());
    wait_for_listener_ready("127.0.0.1:43380", 10)
        .await
        .expect("A P2P listener");
    wait_for_listener_ready("127.0.0.1:43480", 10)
        .await
        .expect("A RPC listener");
    tokio::spawn(node_b.clone().run());

    wait_for_peer_count(&node_b, 1, Duration::from_secs(35))
        .await
        .expect("node B should connect to node A");

    // ── 1. Mine two blocks on A so wallet A holds a mature coinbase.
    //       Under Network::Regtest, `REGTEST_COINBASE_MATURITY = 1` —
    //       a coinbase from block 1 is spendable once the chain reaches
    //       block 2.
    mine_blocks(&node_a, 2).await.expect("A mining failed");
    wait_for_height(&node_b, 2, Duration::from_secs(40))
        .await
        .expect("blocks should propagate A → B");

    {
        let wallet = node_a.wallet.as_ref().expect("A wallet");
        let w = wallet.lock().await;
        let chain = node_a.chain.lock().await;
        let bal = w.balance(chain.tip_height.0);
        assert!(
            bal.confirmed > 0,
            "wallet A must hold a spendable (mature) coinbase under Regtest; got {:?}",
            bal
        );
    }

    // ── 3. Generate a (commitment, blinding) for the recipient. In prod
    //       this would be wallet B over Slatepack; here both are local. ────
    let amount: u64 = 5_000_000_000; // 50 DOM in noms
    let fee: u64 = 1_000_000; // 0.01 DOM
    let recipient_blinding = BlindingFactor::random();
    let recipient_commitment = Commitment::commit(amount, &recipient_blinding);

    // ── 4. POST /wallet/spend on node A. ──────────────────────────────────
    let body = serde_json::json!({
        "recipient_commitment": hex::encode(recipient_commitment.as_bytes()),
        "recipient_blinding": hex::encode(recipient_blinding.as_bytes()),
        "amount_noms": amount,
        "fee_noms": fee,
    });

    let client = reqwest::Client::builder()
        .build()
        .expect("reqwest client");
    let resp = client
        .post("http://127.0.0.1:43480/wallet/spend")
        .bearer_auth("spend-e2e-token")
        .json(&body)
        .send()
        .await
        .expect("RPC call should reach node A");
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "POST /wallet/spend returned {status}: {body_text}"
    );
    let json: serde_json::Value =
        serde_json::from_str(&body_text).expect("response must be JSON");
    let tx_hash_hex = json["tx_hash"]
        .as_str()
        .expect("response should include tx_hash field");
    let tx_hash_bytes = hex::decode(tx_hash_hex).expect("tx_hash must be hex");
    assert_eq!(tx_hash_bytes.len(), 32, "tx_hash must be 32 bytes");
    let mut tx_hash = [0u8; 32];
    tx_hash.copy_from_slice(&tx_hash_bytes);

    println!(
        "[spend_e2e] /wallet/spend OK tx={} amount={} fee={}",
        tx_hash_hex, amount, fee
    );

    // ── 5. Verify mempool A holds the new transaction. ────────────────────
    {
        let mp = node_a.mempool.lock().await;
        assert!(
            mp.get_tx(&tx_hash).is_some(),
            "tx must be in A's mempool right after submit"
        );
    }

    // ── 6. Wait for Dandelion fluff to relay the tx to B. ─────────────────
    wait_for_mempool_count(&node_b, 1, Duration::from_secs(90))
        .await
        .expect("tx should propagate A → B via Dandelion fluff");
    {
        let mp = node_b.mempool.lock().await;
        assert!(
            mp.get_tx(&tx_hash).is_some(),
            "tx must reach B's mempool; got hashes: {:?}",
            mp.all_hashes()
        );
    }

    // ── 7. Mine on B; the spend tx must be packed into the new block. ─────
    let pre_b_height = node_b.chain.lock().await.tip_height.0;
    mine_blocks(&node_b, 1).await.expect("B mining failed");
    let post_b = node_b.chain.lock().await;
    assert_eq!(
        post_b.tip_height.0,
        pre_b_height + 1,
        "B's chain must advance by one block"
    );

    // Confirm the transaction was actually included (mempool drops it on confirm).
    let included = {
        let mp = node_b.mempool.lock().await;
        mp.get_tx(&tx_hash).is_none()
    };
    assert!(
        included,
        "spend tx must be drained from B's mempool after inclusion"
    );

    println!(
        "[spend_e2e OK] tip_a={} tip_b={} hash={}",
        node_a.chain.lock().await.tip_height.0,
        post_b.tip_height.0,
        tx_hash_hex
    );
}
