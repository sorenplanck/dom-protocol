//! Phase 3 — means-of-exchange proof under the Bulletproof (bp2) migration.
//!
//! Proves that value transfers wallet-to-wallet through the REAL interactive
//! slate flow, with the bp2 range proof verified by consensus end-to-end, and
//! balances asserted on both sides.
//!
//! Topology: a single `Network::Regtest` node (deterministic FastDevOnly PoW,
//! coinbase maturity = 1). The node's own wallet is the sender **A** (so it
//! earns the coinbase it spends); a standalone in-memory wallet is the
//! recipient **B**. Both share the regtest genesis hash, hence the same slate
//! `chain_id`, which `receive_slate`/`finalize_slate` require.
//!
//! The flow is the production interactive slate path — NOT `build_spend`:
//!   A.create_send_slate  →  B.receive_slate  →  A.finalize_slate
//! The finalized tx is submitted in-process via the node's real submit path
//! (`NodeHandle::submit_tx`), which runs the FIRST bp2 verification on mempool
//! admission. Mining the inclusion block runs the SECOND bp2 verification
//! through `connect_block → validate_range_proofs`.
//!
//! We deliberately do NOT spawn `node.run()`: this is a single node driven by
//! manual `mine_blocks`, so `submit_tx`'s `try_lock` on chain/mempool always
//! succeeds and the test stays deterministic and fast (no #[ignore]).

use dom_core::{Hash256, GENESIS_HASH_REGTEST, INITIAL_BLOCK_REWARD};
use dom_integration_tests::helpers::*;
use dom_node::node_handle::NodeHandleImpl;
use dom_rpc::NodeHandle;
use dom_serialization::DomSerialize;
use dom_wallet::{Bip39Seed, Network, Wallet, WalletDir};
use std::time::Instant;

/// Pre-create the canonical sender WalletDir, exactly like the CLI/desktop do,
/// so the node can open it and earn (spendable) coinbase rewards.
fn create_wallet_dir(path: &std::path::Path, password: &str) {
    let _ = std::fs::remove_dir_all(path);
    let seed = Bip39Seed::generate_new().expect("seed");
    WalletDir::create_from_seed(
        path,
        password,
        Network::Regtest,
        &Hash256::from_bytes(GENESIS_HASH_REGTEST),
        &seed,
    )
    .expect("create sender wallet dir");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transfer_slate_e2e_bp2_through_consensus() {
    init_tracing();
    let started = Instant::now();

    // ── Parameters ───────────────────────────────────────────────────────────
    // K funding blocks mined by A. On regtest the block reward is constant at
    // these heights, so each of A's coinbases is worth exactly `reward`.
    const K: u64 = 3;
    let reward = INITIAL_BLOCK_REWARD; // 3_300_000_000 noms = 33 DOM
    let amount: u64 = 1_000_000_000; // 10 DOM transferred A → B
    let fee: u64 = 1_000_000; // 0.01 DOM fee
    assert!(
        amount + fee < reward,
        "a single coinbase must cover the spend"
    );

    // ── Node + sender wallet A ───────────────────────────────────────────────
    let wallet_a_path =
        std::env::temp_dir().join(format!("dom-transfer-slate-a-{}.dom", std::process::id()));
    create_wallet_dir(&wallet_a_path, "pw-a");
    let mut config = test_config("transfer-slate", free_local_port(), false);
    config.wallet_path = Some(wallet_a_path.to_string_lossy().into_owned());
    config.wallet_password = Some("pw-a".into());
    let node = spawn_node(config).await;

    // ── Recipient wallet B (standalone; same genesis ⇒ same chain_id as A) ────
    let mut wallet_b =
        Wallet::new_in_memory(Network::Regtest, &Hash256::from_bytes(GENESIS_HASH_REGTEST));

    // ── 1. Fund A: mine K blocks. A earns coinbases at heights 1..=K. ─────────
    // At tip K (regtest maturity 1), coinbases h1..h(K-1) are mature and hK is
    // immature, so A's confirmed balance is exactly (K-1)·reward.
    mine_blocks(&node, K).await.expect("funding mine");
    let bal_a0 = {
        let w = node.wallet.as_ref().expect("wallet A").lock().await;
        w.wallet().balance(K)
    };
    assert_eq!(
        bal_a0.confirmed,
        (K - 1) * reward,
        "A must hold {} mature coinbases after funding",
        K - 1
    );

    // ── 2. Interactive slate transfer A → B (the real means-of-exchange flow) ─
    // 2a. A builds the send slate: selects a mature coinbase, makes its change,
    //     and generates the bp2 proof for that change output.
    let send_slate = {
        let mut wd = node.wallet.as_ref().expect("wallet A").lock().await;
        wd.wallet_mut()
            .create_send_slate(amount, fee, K)
            .expect("create_send_slate")
    };
    // The coinbase A is spending (captured before the slate is moved into B).
    let input_commitment = *send_slate.sender_inputs[0].as_bytes();

    // 2b. B receives: generates its OWN recipient output + bp2 proof and
    //     persists the recipient blinding in its wallet state.
    let recv_slate = wallet_b
        .receive_slate(send_slate, K)
        .expect("receive_slate");
    let recipient_commitment = *recv_slate
        .recipient_output
        .as_ref()
        .expect("recipient output present")
        .commitment
        .as_bytes();

    // 2c. A finalizes: aggregates the partial Schnorr signatures into the final
    //     transaction, ready to submit.
    let finalized = {
        let mut wd = node.wallet.as_ref().expect("wallet A").lock().await;
        wd.wallet_mut()
            .finalize_slate(recv_slate, K)
            .expect("finalize_slate")
    };
    let tx = finalized.tx;
    let tx_bytes = tx.to_bytes().expect("serialize finalized tx");
    let tx_hash = *dom_crypto::blake2b_256(&tx_bytes).as_bytes();

    // ── 3. Submit to the node — FIRST bp2 verification (mempool admission) ────
    let admission = NodeHandleImpl(node.clone())
        .submit_tx(tx_bytes)
        .expect("node must accept the slate tx into the mempool (bp2 verified)");
    assert_eq!(admission.tx_hash, tx_hash, "admission hash mismatch");
    {
        let mp = node.mempool.lock().await;
        assert!(
            mp.get_tx(&tx_hash).is_some(),
            "slate tx must be in the mempool right after submit"
        );
    }

    // ── 4. Mine the inclusion block — SECOND bp2 verification ─────────────────
    //     (connect_block → validate_block_transactions → validate_range_proofs).
    mine_blocks(&node, 1).await.expect("inclusion mine");
    let tip = K + 1;
    {
        let mp = node.mempool.lock().await;
        assert!(
            mp.get_tx(&tx_hash).is_none(),
            "slate tx must be drained from the mempool once mined — i.e. consensus \
             accepted the block carrying it (bp2 verified through connect_block)"
        );
    }

    // ── 5. Consensus-level proof: the bp2-proven outputs are now canonical. ───
    {
        let chain = node.chain.lock().await;
        assert!(
            chain
                .store
                .get_utxo(&recipient_commitment)
                .ok()
                .flatten()
                .is_some(),
            "recipient output must be a live canonical UTXO (its bp2 proof passed consensus)"
        );
        assert!(
            chain
                .store
                .get_utxo(&input_commitment)
                .ok()
                .flatten()
                .is_none(),
            "the spent coinbase input must be removed from the canonical UTXO set"
        );
    }

    // ── 6. Drive canonical scans. ─────────────────────────────────────────────
    // A (= the node's wallet) was already scanned by the miner on connect
    // (apply_wallet_after_mined_connect → apply_canonical_block), so its balance
    // already reflects the spend. B is standalone and must scan the mined tx to
    // claim its received output (matched via its persisted recipient blinding).
    wallet_b
        .apply_canonical_block(core::slice::from_ref(&tx), tip)
        .expect("B canonical scan");

    // ── 7. Balances ───────────────────────────────────────────────────────────
    let bal_a = {
        let w = node.wallet.as_ref().expect("wallet A").lock().await;
        w.wallet().balance(tip)
    };
    let bal_b = wallet_b.balance(tip);

    eprintln!("[transfer_slate_e2e] reward(R)={reward} amount={amount} fee={fee} K={K}");
    eprintln!(
        "[transfer_slate_e2e] bal_A0.confirmed = {}",
        bal_a0.confirmed
    );
    eprintln!(
        "[transfer_slate_e2e] bal_A_final = confirmed={} immature={} reserved={}",
        bal_a.confirmed, bal_a.immature, bal_a.reserved
    );
    eprintln!(
        "[transfer_slate_e2e] bal_B_final = confirmed={} immature={} reserved={}",
        bal_b.confirmed, bal_b.immature, bal_b.reserved
    );

    // Recipient credited by EXACTLY the transferred amount (B started at zero).
    assert_eq!(
        bal_b.confirmed, amount,
        "B must be credited exactly the transferred amount"
    );
    assert_eq!(bal_b.immature, 0, "B's received output is not a coinbase");
    assert_eq!(bal_b.reserved, 0);

    // Sender confirmed balance = (all K matured coinbases) − amount − fee.
    // Derivation (independent of how many inputs coin-selection picked): at tip
    // K+1 every coinbase h1..hK is mature (total K·R). The tx removes input_sum
    // and returns change = input_sum − amount − fee, so the net effect on A's
    // confirmed balance is exactly −(amount + fee).
    assert_eq!(
        bal_a.confirmed,
        K * reward - amount - fee,
        "A confirmed must be K matured coinbases minus the {amount}+{fee} spend"
    );
    // The inclusion block's own coinbase is worth reward + the recouped tx fee
    // (the miner is A), and is still immature at tip K+1 — which is exactly why
    // the fee does not reappear in A's confirmed balance above.
    assert_eq!(
        bal_a.immature,
        reward + fee,
        "A's new coinbase carries base reward + recouped fee and is still immature"
    );
    assert_eq!(
        bal_a.reserved, 0,
        "the input reservation must be released once the spend is canonical"
    );

    eprintln!(
        "[transfer_slate_e2e OK] value transferred through bp2 consensus in {:?}",
        started.elapsed()
    );

    let _ = std::fs::remove_dir_all(&wallet_a_path);
}
