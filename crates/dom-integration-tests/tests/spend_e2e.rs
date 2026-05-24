// BLOCKED-BY-ENV: Requires VPS or 8GB+ RAM. Skipped locally on WSL <2GB free.

//! End-to-end spend test (DOM Doc 8).
//!
//! Node A mines a coinbase, wallet A spends it via the `/wallet/spend` RPC,
//! Dandelion fluff propagates the transaction to node B over P2P, node B
//! includes the transaction in the next block it mines.
//!
//! ## `#[ignore]` rationale
//!
//! Two reasons this test does not run on every CI invocation:
//!
//! 1. **Memory.** Two miners + RandomX dataset (`FLAG_FULL_MEM`, ~2.25 GB
//!    each) + chain validation + LMDB cache exceed 4 GB resident easily.
//!    The reference development VM (WSL2 with ~2 GB free) OOM-kills the
//!    process. Production / VPS runs are unaffected — this test is gated
//!    for environments that can host two mining nodes.
//! 2. **Maturity gate.** Consensus enforces `COINBASE_MATURITY = 1000`
//!    (`dom_chain::chain_state.rs:187`). Mining 1001 testnet blocks twice
//!    just to validate a spend is wall-clock prohibitive even with a
//!    permissive target. The test uses the wallet-side
//!    `__test_force_non_coinbase()` bypass to let coin selection succeed,
//!    but the second node will reject the constructed block because the
//!    on-chain UTXO entry still has `is_coinbase = true`. To run end-to-end
//!    the project must introduce `Network::Regtest` with
//!    `COINBASE_MATURITY = 1` (tracked as a separate mainnet-readiness item).
//!
//! Until both are addressed, run manually with
//! `cargo test -p dom-integration-tests --test spend_e2e -- --ignored`
//! on a host with ≥ 8 GB RAM.

use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs >=8 GB RAM and Network::Regtest (consensus maturity gate)"]
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

    // ── 1. Mine two blocks on A so wallet A holds a coinbase. ─────────────
    mine_blocks(&node_a, 2).await.expect("A mining failed");
    wait_for_height(&node_b, 2, Duration::from_secs(40))
        .await
        .expect("blocks should propagate A → B");

    // ── 2. Force-mature wallet A's coinbase (see header comment). ─────────
    {
        let wallet = node_a.wallet.as_ref().expect("A wallet");
        let mut w = wallet.lock().await;
        w.__test_force_non_coinbase();
        let chain = node_a.chain.lock().await;
        let bal = w.balance(chain.tip_height.0);
        assert!(
            bal.confirmed > 0,
            "after force-mature, wallet A must have spendable balance; got {:?}",
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
