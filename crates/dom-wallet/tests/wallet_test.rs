use dom_consensus::{validate_balance_equation, validate_transaction_structure};
use dom_core::Hash256;
use dom_crypto::pedersen::Commitment;
use dom_crypto::BlindingFactor;
use dom_tx::InputSource;
use dom_wallet::{Network, OwnedOutput, Wallet};
use tempfile::TempDir;

fn test_genesis() -> Hash256 {
    Hash256::from_bytes([0x42u8; 32])
}

fn make_output(value: u64, height: u64, is_coinbase: bool) -> OwnedOutput {
    let bf = BlindingFactor::random();
    let commitment = Commitment::commit(value, &bf);
    OwnedOutput::new(
        *commitment.as_bytes(),
        value,
        *bf.as_bytes(),
        height,
        is_coinbase,
    )
}

#[test]
fn test_in_memory_wallet_creation() {
    let wallet = Wallet::new_in_memory(Network::Testnet, &test_genesis());
    let balance = wallet.balance(0);
    assert_eq!(balance.confirmed, 0);
    assert_eq!(balance.immature, 0);
}

#[test]
fn test_add_output_and_balance() {
    let mut wallet = Wallet::new_in_memory(Network::Testnet, &test_genesis());
    let output = make_output(1000, 50, false);
    wallet.add_output(output);
    let balance = wallet.balance(1000);
    assert_eq!(balance.confirmed, 1000);
}

#[test]
fn test_coinbase_immature() {
    let mut wallet = Wallet::new_in_memory(Network::Testnet, &test_genesis());
    let output = make_output(5000, 100, true);
    wallet.add_output(output);
    let balance = wallet.balance(500);
    assert_eq!(balance.confirmed, 0);
    assert_eq!(balance.immature, 5000);
}

#[test]
fn test_coinbase_mature() {
    let mut wallet = Wallet::new_in_memory(Network::Testnet, &test_genesis());
    let output = make_output(5000, 100, true);
    wallet.add_output(output);
    let balance = wallet.balance(1101);
    assert_eq!(balance.confirmed, 5000);
    assert_eq!(balance.immature, 0);
}

#[test]
fn test_wallet_create_and_open() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");

    let wallet = Wallet::create(&path, "password123", Network::Mainnet, &test_genesis()).unwrap();
    assert_eq!(wallet.network(), Network::Mainnet);
    drop(wallet);

    let reopened = Wallet::open(&path, "password123").unwrap();
    assert_eq!(reopened.network(), Network::Mainnet);
}

#[test]
fn test_wallet_wrong_password() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");

    Wallet::create(&path, "password123", Network::Mainnet, &test_genesis()).unwrap();

    let result = Wallet::open(&path, "wrongpass");
    assert!(result.is_err());
}

#[test]
fn test_multiple_outputs_balance() {
    let mut wallet = Wallet::new_in_memory(Network::Testnet, &test_genesis());
    wallet.add_output(make_output(1000, 50, false));
    wallet.add_output(make_output(2000, 60, false));
    wallet.add_output(make_output(3000, 70, true));

    let balance = wallet.balance(1100);
    assert_eq!(balance.confirmed, 6000);
    assert_eq!(balance.immature, 0);
}

#[test]
fn test_input_source_trait() {
    let output = make_output(1000, 50, false);
    assert_eq!(output.value(), 1000);
    assert_eq!(output.block_height(), 50);
    assert!(!output.is_coinbase());
}

#[test]
fn test_owned_output_spendable() {
    let regular = make_output(1000, 100, false);
    let coinbase = make_output(2000, 100, true);

    assert!(regular.is_spendable(200));
    assert!(!coinbase.is_spendable(200));
    assert!(coinbase.is_spendable(1101));
}

#[test]
fn test_wallet_build_spend_transaction() {
    // Use in-memory wallet to avoid serialization issues
    let mut wallet = Wallet::new_in_memory(Network::Testnet, &test_genesis());

    // Add output of exactly 900 noms (will become input)
    let output = make_output(900, 100, false);
    wallet.add_output(output);

    // Send 800 noms with 100 fee = 900 total (matches input exactly)
    let recipient_blinding = BlindingFactor::random();
    let recipient_commitment = Commitment::commit(800, &recipient_blinding);

    let tx = wallet
        .build_spend(
            recipient_commitment,
            recipient_blinding,
            800,  // amount
            100,  // fee (800 + 100 = 900 = input)
            1000, // current_height
        )
        .unwrap();

    // Verify transaction is valid
    validate_transaction_structure(&tx).unwrap();
    validate_balance_equation(&tx).unwrap();

    assert_eq!(tx.inputs.len(), 1, "should have 1 input");
    assert_eq!(tx.outputs.len(), 1, "should have 1 output");
    assert_eq!(tx.kernels.len(), 1, "should have 1 kernel");
    assert_eq!(tx.kernels[0].fee.noms(), 100, "kernel fee should be 100");
}

#[test]
fn test_wallet_spend_persists_across_reopen() {
    use dom_consensus::{validate_balance_equation, validate_transaction_structure};

    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");

    // 1. Create wallet and add output
    let mut wallet =
        Wallet::create(&path, "password123", Network::Mainnet, &test_genesis()).unwrap();

    let output = make_output(900, 100, false);
    wallet.add_output(output);

    // 2. Build spend transaction
    let recipient_blinding = BlindingFactor::random();
    let recipient_commitment = Commitment::commit(800, &recipient_blinding);

    let tx = wallet
        .build_spend(recipient_commitment, recipient_blinding, 800, 100, 1000)
        .unwrap();

    validate_transaction_structure(&tx).unwrap();
    validate_balance_equation(&tx).unwrap();

    // 3. Drop and reopen wallet
    drop(wallet);
    let reopened = Wallet::open(&path, "password123").unwrap();

    // 4. Verify balance reflects pending spend (reserved)
    let balance = reopened.balance(1000);
    assert_eq!(balance.confirmed, 0, "spent output should not be confirmed");
    assert_eq!(balance.reserved, 900, "spent output should be reserved");
}
