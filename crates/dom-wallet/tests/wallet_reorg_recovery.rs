use dom_consensus::transaction::{Transaction, TransactionOutput};
use dom_core::BlockHeight;
use dom_crypto::pedersen::Commitment;
use dom_crypto::{BlindingFactor, Hash256};
use dom_wallet::{
    Bip39Seed, InMemoryChainScan, Network, OwnedOutput, ScanBlock, SeedAcceptance, Wallet,
    WalletDir, WalletReorgBlock, WalletRescanMode,
};
use tempfile::TempDir;

const PHRASE_24: &str = "abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon art";

fn test_genesis() -> Hash256 {
    Hash256::from_bytes([0x42u8; 32])
}

fn block_hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn make_output(value: u64, height: u64, is_coinbase: bool, hash: [u8; 32]) -> OwnedOutput {
    let bf = BlindingFactor::random();
    let commitment = Commitment::commit(value, &bf);
    OwnedOutput::new(
        *commitment.as_bytes(),
        value,
        *bf.as_bytes(),
        height,
        is_coinbase,
    )
    .with_block_hash(hash)
}

fn output_only_tx(commitment: Commitment) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![TransactionOutput {
            commitment,
            proof: Vec::new(),
        }],
        kernels: vec![],
        offset: [0u8; 32],
    }
}

fn reorg_block(height: u64, hash: [u8; 32], transactions: Vec<Transaction>) -> WalletReorgBlock {
    WalletReorgBlock {
        block_hash: hash,
        block_height: height,
        transactions,
    }
}

fn build_test_spend(wallet: &mut Wallet) -> Transaction {
    let recipient_blinding = BlindingFactor::random();
    let recipient_commitment = Commitment::commit(800, &recipient_blinding);
    wallet
        .build_spend(recipient_commitment, recipient_blinding, 800, 100, 1000)
        .expect("build spend")
}

#[test]
fn receive_output_reorg_removes_disconnected_block() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let seed = Bip39Seed::from_phrase(PHRASE_24, SeedAcceptance::NewWallet).unwrap();
    let mut wd =
        WalletDir::create_from_seed(&dir, "pw", Network::Regtest, &test_genesis(), &seed).unwrap();

    let request = wd.wallet_mut().create_receive_request(77).unwrap();
    let commitment_bytes: [u8; 33] = hex::decode(request.commitment_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let commitment = Commitment::from_compressed_bytes(&commitment_bytes).unwrap();
    let receive_tx = output_only_tx(commitment);
    let receive_commitment = *receive_tx.outputs[0].commitment.as_bytes();

    wd.wallet_mut()
        .apply_canonical_block_with_hash(&[receive_tx.clone()], 1, Some(block_hash(0xA1)))
        .unwrap();
    assert!(wd
        .wallet()
        .outputs()
        .any(|o| { o.commitment == receive_commitment && o.block_hash == Some(block_hash(0xA1)) }));

    wd.wallet_mut()
        .apply_canonical_reorg(
            0,
            &[reorg_block(1, block_hash(0xA1), vec![receive_tx])],
            &[],
        )
        .unwrap();

    assert!(wd
        .wallet()
        .outputs()
        .all(|o| o.commitment != receive_commitment));
    assert!(matches!(
        wd.wallet().receive_requests()[0].status,
        dom_wallet::ReceiveRequestStatus::Pending
    ));
}

#[test]
fn spend_output_reorg_restores_unspent_pending_state() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    let input = make_output(900, 1, false, block_hash(0x11));
    let input_commitment = input.commitment;
    wd.wallet_mut().add_output(input);

    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();
    wd.wallet_mut()
        .apply_canonical_block_with_hash(&[tx.clone()], 2, Some(block_hash(0xA2)))
        .unwrap();
    assert!(!wd.wallet().has_pending_tx(&tx_hash));

    wd.wallet_mut()
        .apply_canonical_reorg(
            1,
            &[reorg_block(2, block_hash(0xA2), vec![tx.clone()])],
            &[],
        )
        .unwrap();

    let restored = wd
        .wallet()
        .outputs()
        .find(|o| o.commitment == input_commitment)
        .unwrap();
    assert!(!restored.spent);
    assert_eq!(restored.reserved_for_tx, Some(tx_hash));
    assert!(wd.wallet().has_pending_tx(&tx_hash));
}

#[test]
fn coinbase_reorg_removes_disconnected_reward() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();

    let coinbase = wd.wallet_mut().build_coinbase(BlockHeight(1), 0).unwrap();
    let commitment = *coinbase.output.commitment.as_bytes();
    let coinbase_tx = output_only_tx(coinbase.output.commitment.clone());
    wd.wallet_mut()
        .apply_canonical_block_with_hash(&[coinbase_tx.clone()], 1, Some(block_hash(0xC1)))
        .unwrap();
    assert!(wd.wallet().outputs().any(|o| {
        o.commitment == commitment && o.is_coinbase && o.block_hash == Some(block_hash(0xC1))
    }));

    wd.wallet_mut()
        .apply_canonical_reorg(
            0,
            &[reorg_block(1, block_hash(0xC1), vec![coinbase_tx])],
            &[],
        )
        .unwrap();

    assert!(wd.wallet().outputs().all(|o| o.commitment != commitment));
}

#[test]
fn restart_after_wallet_reorg_preserves_rollback_state() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    let input = make_output(900, 1, false, block_hash(0x11));
    let input_commitment = input.commitment;
    wd.wallet_mut().add_output(input);

    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();
    wd.wallet_mut()
        .apply_canonical_block_with_hash(&[tx.clone()], 2, Some(block_hash(0xA2)))
        .unwrap();
    wd.wallet_mut()
        .apply_canonical_reorg(1, &[reorg_block(2, block_hash(0xA2), vec![tx])], &[])
        .unwrap();
    drop(wd);

    let reopened = WalletDir::open(&dir, "pw").unwrap();
    let restored = reopened
        .wallet()
        .outputs()
        .find(|o| o.commitment == input_commitment)
        .unwrap();
    assert!(!restored.spent);
    assert_eq!(restored.reserved_for_tx, Some(tx_hash));
    assert!(reopened.wallet().has_pending_tx(&tx_hash));
}

#[test]
fn wallet_rescan_matches_incremental_reorg_state() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();

    let branch_a_coinbase = wd.wallet_mut().build_coinbase(BlockHeight(1), 0).unwrap();
    let branch_a_commitment = *branch_a_coinbase.output.commitment.as_bytes();
    let branch_a_tx = output_only_tx(branch_a_coinbase.output.commitment.clone());
    wd.wallet_mut()
        .apply_canonical_block_with_hash(&[branch_a_tx.clone()], 1, Some(block_hash(0xA1)))
        .unwrap();

    let branch_b_coinbase = wd.wallet_mut().build_coinbase(BlockHeight(2), 0).unwrap();
    let branch_b_commitment = *branch_b_coinbase.output.commitment.as_bytes();
    let branch_b_tx = output_only_tx(branch_b_coinbase.output.commitment.clone());
    wd.wallet_mut()
        .apply_canonical_reorg(
            0,
            &[reorg_block(1, block_hash(0xA1), vec![branch_a_tx])],
            &[reorg_block(2, block_hash(0xB2), vec![branch_b_tx])],
        )
        .unwrap();
    assert!(wd
        .wallet()
        .outputs()
        .all(|o| o.commitment != branch_a_commitment));
    assert!(wd
        .wallet()
        .outputs()
        .any(|o| o.commitment == branch_b_commitment));

    let mut scan = InMemoryChainScan::new();
    scan.insert(ScanBlock {
        height: 2,
        block_hash: Some(block_hash(0xB2)),
        output_commitments: vec![branch_b_commitment],
        input_commitments: vec![],
        total_fees_noms: 0,
        tx_effects: vec![],
    });

    let summary = wd
        .wallet_mut()
        .rescan_canonical_chain(&scan, WalletRescanMode::CompareOnly)
        .unwrap();
    assert!(summary.matched_persisted);
    assert_eq!(summary.rebuilt_digest, wd.wallet().canonical_digest());
}
