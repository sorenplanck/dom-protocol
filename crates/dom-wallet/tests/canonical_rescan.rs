use dom_core::BlockHeight;
use dom_crypto::Hash256;
use dom_wallet::{InMemoryChainScan, Network, ScanBlock, WalletDir, WalletRescanMode};
use tempfile::TempDir;

fn test_genesis() -> Hash256 {
    Hash256::from_bytes([0x42u8; 32])
}

fn block_hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn scan_with_blocks(blocks: Vec<ScanBlock>) -> InMemoryChainScan {
    let mut scan = InMemoryChainScan::new();
    for block in blocks {
        scan.insert(block);
    }
    scan
}

fn coinbase_scan_block(height: u64, commitment: [u8; 33]) -> ScanBlock {
    ScanBlock {
        height,
        block_hash: Some(block_hash(height as u8)),
        output_commitments: vec![commitment],
        input_commitments: vec![],
        total_fees_noms: 0,
    }
}

#[test]
fn corrupted_wallet_state_is_repaired_by_canonical_rescan() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();

    let coinbase = wd
        .wallet_mut()
        .build_coinbase(BlockHeight(1), 0)
        .expect("coinbase");
    let commitment = *coinbase.output.commitment.as_bytes();
    let scan = scan_with_blocks(vec![coinbase_scan_block(1, commitment)]);

    assert!(wd.wallet_mut().forget_output(&commitment));
    assert!(wd.wallet().outputs().all(|o| o.commitment != commitment));

    let summary = wd
        .wallet_mut()
        .rescan_canonical_chain(&scan, WalletRescanMode::Repair)
        .expect("repair rescan");
    assert!(!summary.matched_persisted);
    assert!(summary.repaired);
    assert_eq!(summary.rebuilt_outputs, 1);

    let restored = wd
        .wallet()
        .outputs()
        .find(|o| o.commitment == commitment)
        .expect("rescan must restore output");
    assert_eq!(restored.block_height, 1);
    assert_eq!(restored.block_hash, Some(block_hash(1)));
}

#[test]
fn canonical_rescan_after_reorg_removes_disconnected_output() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();

    let coinbase = wd
        .wallet_mut()
        .build_coinbase(BlockHeight(1), 0)
        .expect("coinbase");
    let commitment = *coinbase.output.commitment.as_bytes();
    let branch_a = scan_with_blocks(vec![coinbase_scan_block(1, commitment)]);
    wd.wallet_mut()
        .rescan_canonical_chain(&branch_a, WalletRescanMode::Repair)
        .expect("branch A rescan");
    assert!(wd.wallet().outputs().any(|o| o.commitment == commitment));

    let branch_b = scan_with_blocks(vec![ScanBlock {
        height: 1,
        block_hash: Some(block_hash(0xB1)),
        output_commitments: vec![[0x55; 33]],
        input_commitments: vec![],
        total_fees_noms: 0,
    }]);
    let summary = wd
        .wallet_mut()
        .rescan_canonical_chain(&branch_b, WalletRescanMode::Repair)
        .expect("branch B rescan");

    assert_eq!(summary.rebuilt_outputs, 0);
    assert!(wd.wallet().outputs().all(|o| o.commitment != commitment));
}

#[test]
fn canonical_rescan_marks_spent_outputs_and_drops_consumed_pending() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();

    let coinbase = wd
        .wallet_mut()
        .build_coinbase(BlockHeight(1), 0)
        .expect("coinbase");
    let commitment = *coinbase.output.commitment.as_bytes();
    let recipient_blinding = dom_crypto::BlindingFactor::random();
    let spend_amount = dom_core::block_reward(BlockHeight(1)).noms() - 100;
    let recipient = dom_crypto::pedersen::Commitment::commit(spend_amount, &recipient_blinding);
    let tx = wd
        .wallet_mut()
        .build_spend(recipient, recipient_blinding, spend_amount, 100, 3)
        .expect("build spend");
    let tx_hash = dom_wallet::Wallet::tracking_tx_hash(&tx).expect("tx hash");
    assert!(wd.wallet().has_pending_tx(&tx_hash));

    let scan = scan_with_blocks(vec![
        coinbase_scan_block(1, commitment),
        ScanBlock {
            height: 2,
            block_hash: Some(block_hash(2)),
            output_commitments: tx
                .outputs
                .iter()
                .map(|o| *o.commitment.as_bytes())
                .collect(),
            input_commitments: tx.inputs.iter().map(|i| *i.commitment.as_bytes()).collect(),
            total_fees_noms: 100,
        },
    ]);
    let summary = wd
        .wallet_mut()
        .rescan_canonical_chain(&scan, WalletRescanMode::Repair)
        .expect("spent rescan");

    assert_eq!(summary.spent_outputs, 1);
    assert_eq!(summary.pending_dropped, 1);
    assert!(!wd.wallet().has_pending_tx(&tx_hash));
    assert!(
        wd.wallet()
            .outputs()
            .find(|o| o.commitment == commitment)
            .expect("coinbase output")
            .spent
    );
}

#[test]
fn canonical_rescan_survives_restart_and_repeated_full_rescan_matches_digest() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();

    let coinbase = wd
        .wallet_mut()
        .build_coinbase(BlockHeight(1), 0)
        .expect("coinbase");
    let commitment = *coinbase.output.commitment.as_bytes();
    let scan = scan_with_blocks(vec![coinbase_scan_block(1, commitment)]);

    let first = wd
        .wallet_mut()
        .rescan_canonical_chain(&scan, WalletRescanMode::Repair)
        .expect("first rescan");
    let digest_after_first = wd.wallet().canonical_digest();
    assert_eq!(first.rebuilt_digest, digest_after_first);

    drop(wd);
    let mut reopened = WalletDir::open(&dir, "pw").expect("reopen");
    assert_eq!(reopened.wallet().canonical_digest(), digest_after_first);

    let compare = reopened
        .wallet_mut()
        .rescan_canonical_chain(&scan, WalletRescanMode::CompareOnly)
        .expect("compare rescan");
    assert!(compare.matched_persisted);
    assert!(!compare.repaired);

    let second = reopened
        .wallet_mut()
        .rescan_canonical_chain(&scan, WalletRescanMode::Repair)
        .expect("second rescan");
    assert!(second.matched_persisted);
    assert_eq!(second.rebuilt_digest, digest_after_first);
}
