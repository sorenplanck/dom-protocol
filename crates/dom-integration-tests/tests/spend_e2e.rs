//! End-to-end spend test (DOM Doc 8).
//!
//! Node A mines a coinbase, wallet A spends it via the `/wallet/spend` RPC,
//! Dandelion fluff propagates the transaction to node B over P2P, node B
//! includes the transaction in the next block it mines. Asserts at every
//! stage; runs on every CI invocation.
//!
//! Resource profile: `Network::Regtest` uses deterministic FastDevOnly PoW
//! and `REGTEST_COINBASE_MATURITY = 1`, so this covers the real wallet/RPC/P2P
//! path without RandomX cache churn or long nonce searches. Consensus
//! validation is unchanged from Mainnet/Testnet; only the regtest mining mode
//! and maturity window are shortened for a stable CI-sized proof.

use dom_core::Hash256;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_integration_tests::helpers::*;
use dom_wallet::{Bip39Seed, Network, WalletDir};
use std::time::Duration;

/// O nó não cria mais wallets (DOM-SEC-004): pré-cria a WalletDir
/// determinística canônica, como o CLI/desktop fazem, e solta o lock.
fn create_wallet_dir(path: &str, password: &str) {
    let _ = std::fs::remove_dir_all(path);
    let seed = Bip39Seed::generate_new().expect("seed");
    WalletDir::create_from_seed(
        std::path::Path::new(path),
        password,
        Network::Regtest,
        &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        &seed,
    )
    .expect("create wallet dir");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_spend_e2e_cross_node_propagation() {
    init_tracing();

    // Deterministic Bearer token so the HTTP client knows it without poking files.
    std::env::set_var("DOM_RPC_TOKEN", "spend-e2e-token");

    let p2p_a = free_local_port();
    let p2p_b = free_local_port();
    let rpc_a = free_local_port();
    let p2p_a_addr = format!("127.0.0.1:{p2p_a}");
    let p2p_b_addr = format!("127.0.0.1:{p2p_b}");
    let rpc_a_addr = format!("127.0.0.1:{rpc_a}");
    let wallet_path = std::env::temp_dir().join(format!(
        "dom-spend-e2e-wallet-a-{}-{}.dom",
        std::process::id(),
        rpc_a
    ));

    // ── Node A (miner + wallet + RPC) ────────────────────────────────────
    let mut config_a = test_config("spend-e2e-a", p2p_a, false);
    config_a.wallet_path = Some(wallet_path.to_string_lossy().into_owned());
    config_a.wallet_password = Some("pw-a".into());
    config_a.rpc_listen_addr = Some(rpc_a_addr.clone());

    create_wallet_dir(&wallet_path.to_string_lossy(), "pw-a");

    // ── Node B (peer that should receive the tx via Dandelion fluff) ──────
    let mut config_b = test_config("spend-e2e-b", p2p_b, false);
    config_b.seed_peers = vec![p2p_a_addr.clone()];

    let node_a = spawn_node(config_a).await;
    let node_b = spawn_node(config_b).await;

    tokio::spawn(node_a.clone().run());
    wait_for_listener_ready(&p2p_a_addr, 10)
        .await
        .expect("A P2P listener");
    wait_for_listener_ready(&rpc_a_addr, 10)
        .await
        .expect("A RPC listener");
    tokio::spawn(node_b.clone().run());
    wait_for_listener_ready(&p2p_b_addr, 10)
        .await
        .expect("B P2P listener");

    wait_for_peer_count(&node_b, 1, Duration::from_secs(35))
        .await
        .expect("node B should connect to node A");

    // ── 1. Mine three blocks on A so wallet A holds two mature coinbases.
    //       Under Network::Regtest, `REGTEST_COINBASE_MATURITY = 1` — a
    //       coinbase from height H matures at tip H+1. After 3 blocks
    //       (tip=3) the coinbases from heights 1 and 2 are mature; the
    //       one from height 3 is not. Two mature coinbases =
    //       2 × INITIAL_BLOCK_REWARD = 66 DOM, enough to cover the 50 DOM
    //       spend below + the 0.01 DOM fee. Mining 2 blocks (previous
    //       value) gives only 1 mature coinbase = 33 DOM, which fails
    //       with insufficient_funds on the /wallet/spend call.
    mine_blocks(&node_a, 3).await.expect("A mining failed");
    wait_for_height(&node_b, 3, Duration::from_secs(40))
        .await
        .expect("blocks should propagate A → B");

    {
        let wallet = node_a.wallet.as_ref().expect("A wallet");
        let w = wallet.lock().await;
        let chain = node_a.chain.lock().await;
        let bal = w.wallet().balance(chain.tip_height.0);
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

    let client = reqwest::Client::builder().build().expect("reqwest client");
    let wallet_spend_url = format!("http://{rpc_a_addr}/wallet/spend");
    let resp = client
        .post(wallet_spend_url)
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
    let json: serde_json::Value = serde_json::from_str(&body_text).expect("response must be JSON");
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

    let _ = std::fs::remove_dir_all(&wallet_path);
}
