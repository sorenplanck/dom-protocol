use dom_consensus::{CoinbaseTransaction, Transaction, TransactionKernel};
use dom_core::{Amount, BlockHeight, Hash256, KERNEL_FEAT_PLAIN};
use dom_wallet::{Network, WalletDir};
use tempfile::TempDir;

fn test_genesis() -> Hash256 {
    Hash256::from_bytes([0x42u8; 32])
}

fn tx_with_coinbase_output(coinbase: CoinbaseTransaction, fee: u64) -> Transaction {
    let CoinbaseTransaction { output, kernel, .. } = coinbase;
    Transaction {
        inputs: vec![],
        outputs: vec![output],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(fee).unwrap(),
            lock_height: 0,
            excess: kernel.excess,
            excess_signature: [0u8; 65],
        }],
        offset: [0u8; 32],
    }
}

fn assert_scan_recovers_coinbase_value(wallet: &mut dom_wallet::Wallet, height: u64, fees: u64) {
    let coinbase = wallet
        .build_coinbase(BlockHeight(height), fees)
        .expect("build coinbase");
    let commitment = *coinbase.output.commitment.as_bytes();
    let expected_value = dom_core::block_reward(BlockHeight(height)).noms() + fees;

    assert!(wallet.forget_output(&commitment));
    assert!(wallet.outputs().all(|o| o.commitment != commitment));

    let tx = tx_with_coinbase_output(coinbase, fees);
    wallet.scan_block(&[tx], height);

    let recovered = wallet
        .outputs()
        .find(|o| o.commitment == commitment)
        .expect("scan must recover coinbase output");
    assert_eq!(recovered.value, expected_value);
    assert!(recovered.is_coinbase);
    assert_eq!(recovered.block_height, height);
}

#[test]
fn scan_block_recovers_coinbase_without_and_with_fees() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();

    assert_scan_recovers_coinbase_value(wd.wallet_mut(), 1, 0);
    assert_scan_recovers_coinbase_value(wd.wallet_mut(), 2, 750);
}
