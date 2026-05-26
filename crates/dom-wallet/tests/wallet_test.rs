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

#[test]
fn test_canonical_block_confirms_pending_spend_after_reopen() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");

    let mut wallet =
        Wallet::create(&path, "password123", Network::Mainnet, &test_genesis()).unwrap();
    let output = make_output(900, 100, false);
    let spent_commitment = output.commitment;
    wallet.add_output(output);

    let recipient_blinding = BlindingFactor::random();
    let recipient_commitment = Commitment::commit(800, &recipient_blinding);
    let tx = wallet
        .build_spend(recipient_commitment, recipient_blinding, 800, 100, 1000)
        .unwrap();

    drop(wallet);
    let mut reopened = Wallet::open(&path, "password123").unwrap();
    let before = reopened.balance(1000);
    assert_eq!(before.reserved, 900);

    reopened.apply_canonical_block(&[tx], 1001).unwrap();

    let after = reopened.balance(1001);
    assert_eq!(after.confirmed, 0);
    assert_eq!(after.reserved, 0, "confirmed spend must clear reservation");
    let spent = reopened
        .outputs()
        .find(|output| output.commitment == spent_commitment)
        .expect("original output must remain tracked");
    assert!(
        spent.spent,
        "canonical confirmation must mark the input spent"
    );

    drop(reopened);
    let reopened_again = Wallet::open(&path, "password123").unwrap();
    let after_restart = reopened_again.balance(1001);
    assert_eq!(after_restart.reserved, 0);
    let spent = reopened_again
        .outputs()
        .find(|output| output.commitment == spent_commitment)
        .expect("original output must remain tracked");
    assert!(spent.spent, "spent marker must persist across restart");
}

#[test]
fn test_conflicting_canonical_spend_releases_unconsumed_reservations() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");

    let mut wallet =
        Wallet::create(&path, "password123", Network::Mainnet, &test_genesis()).unwrap();
    let output_a = make_output(500, 100, false);
    let output_b = make_output(400, 100, false);
    let commitment_a = output_a.commitment;
    let commitment_b = output_b.commitment;
    wallet.add_output(output_a.clone());
    wallet.add_output(output_b.clone());

    let recipient_blinding = BlindingFactor::random();
    let recipient_commitment = Commitment::commit(800, &recipient_blinding);
    let _pending = wallet
        .build_spend(recipient_commitment, recipient_blinding, 800, 100, 1000)
        .unwrap();

    let mut conflicting_wallet = Wallet::new_in_memory(Network::Mainnet, &test_genesis());
    conflicting_wallet.add_output(output_a);
    let other_blinding = BlindingFactor::random();
    let other_commitment = Commitment::commit(450, &other_blinding);
    let conflicting_tx = conflicting_wallet
        .build_spend(other_commitment, other_blinding, 450, 50, 1000)
        .unwrap();

    wallet
        .apply_canonical_block(&[conflicting_tx], 1001)
        .unwrap();

    let balance = wallet.balance(1001);
    assert_eq!(
        balance.reserved, 0,
        "conflict must clear stale reservations"
    );
    let spent_a = wallet
        .outputs()
        .find(|output| output.commitment == commitment_a)
        .expect("output A must remain tracked");
    assert!(spent_a.spent, "spent canonical input must be marked spent");
    let released_b = wallet
        .outputs()
        .find(|output| output.commitment == commitment_b)
        .expect("output B must remain tracked");
    assert!(
        !released_b.spent && released_b.reserved_for_tx.is_none(),
        "unconsumed reserved inputs must be released back to the wallet"
    );
}
