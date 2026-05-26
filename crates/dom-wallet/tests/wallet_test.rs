use dom_consensus::{validate_balance_equation, validate_transaction_structure};
use dom_core::Hash256;
use dom_crypto::pedersen::Commitment;
use dom_crypto::BlindingFactor;
use dom_tx::InputSource;
use dom_wallet::{LockState, Network, OwnedOutput, Wallet, WalletError};
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

// ════════════════════════════════════════════════════════════════════
// Lock / Unlock state machine — adversarial coverage (Phase 1.2)
//
// Invariants under test:
//   1. Lock zeroes the in-memory session; subsequent save/build_coinbase
//      operations return WalletError::Locked.
//   2. scan_block is best-effort: locked wallets skip silently (no panic,
//      no Err), preserving the relay / IBD code paths.
//   3. Unlock with wrong password is rejected by the on-disk AEAD tag
//      and leaves the wallet locked.
//   4. Unlock with correct password restores normal operation.
//   5. Lock is idempotent.
//   6. Lock does NOT mutate on-disk state — pending txs, outputs, and
//      reservations all survive a lock/unlock cycle (and survive an
//      explicit reopen, modelling restart-after-lock).
//   7. In-memory wallets (no file path) accept any password on unlock
//      because there is no ciphertext to verify against.
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_new_wallet_starts_unlocked() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");
    let w = Wallet::create(&path, "password123", Network::Mainnet, &test_genesis()).unwrap();
    assert!(w.is_unlocked());
    assert!(!w.is_locked());
    assert_eq!(w.lock_state(), LockState::Unlocked);
}

#[test]
fn test_opened_wallet_starts_unlocked() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");
    Wallet::create(&path, "password123", Network::Mainnet, &test_genesis()).unwrap();
    let w = Wallet::open(&path, "password123").unwrap();
    assert!(w.is_unlocked());
    assert_eq!(w.lock_state(), LockState::Unlocked);
}

#[test]
fn test_lock_transitions_to_locked() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");
    let mut w = Wallet::create(&path, "password123", Network::Mainnet, &test_genesis()).unwrap();
    assert!(w.is_unlocked());
    w.lock();
    assert!(w.is_locked());
    assert!(!w.is_unlocked());
    assert_eq!(w.lock_state(), LockState::Locked);
}

#[test]
fn test_lock_is_idempotent() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");
    let mut w = Wallet::create(&path, "password123", Network::Mainnet, &test_genesis()).unwrap();
    w.lock();
    w.lock(); // must not panic, must not transition anywhere
    w.lock();
    assert!(w.is_locked());
}

#[test]
fn test_save_while_locked_returns_locked_error() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");
    let mut w = Wallet::create(&path, "password123", Network::Mainnet, &test_genesis()).unwrap();
    w.lock();
    let err = w.save().expect_err("save must fail when wallet is locked");
    assert!(
        matches!(err, WalletError::Locked),
        "expected WalletError::Locked, got {err:?}"
    );
}

#[test]
fn test_build_coinbase_while_locked_returns_locked_error() {
    use dom_core::BlockHeight;
    let mut w = Wallet::new_in_memory(Network::Regtest, &test_genesis());
    w.lock();
    let err = w
        .build_coinbase(BlockHeight(0), 0)
        .expect_err("build_coinbase must fail when locked");
    assert!(
        matches!(err, WalletError::Locked),
        "expected WalletError::Locked, got {err:?}"
    );
}

#[test]
fn test_scan_block_while_locked_is_noop() {
    let mut w = Wallet::new_in_memory(Network::Regtest, &test_genesis());
    w.lock();
    // No transactions to scan — exercise the locked early-return path.
    w.scan_block(&[], 0);
    // Wallet must still be locked and must not have panicked.
    assert!(w.is_locked());
}

#[test]
fn test_unlock_with_wrong_password_is_rejected() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");
    let mut w = Wallet::create(&path, "correct_pw", Network::Mainnet, &test_genesis()).unwrap();
    w.lock();
    let err = w
        .unlock("WRONG_PW")
        .expect_err("unlock with wrong password must fail");
    assert!(
        matches!(err, WalletError::Decryption),
        "expected WalletError::Decryption, got {err:?}"
    );
    // The wallet MUST remain locked after a rejected unlock attempt.
    assert!(
        w.is_locked(),
        "rejected unlock must NOT transition to unlocked"
    );
}

#[test]
fn test_unlock_with_correct_password_restores_session() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");
    let mut w = Wallet::create(&path, "correct_pw", Network::Mainnet, &test_genesis()).unwrap();
    w.lock();
    assert!(w.is_locked());
    w.unlock("correct_pw")
        .expect("correct password must unlock");
    assert!(w.is_unlocked());
    // Now save() must succeed again (re-encrypts with a fresh salt).
    w.save().expect("save must succeed after unlock");
}

#[test]
fn test_lock_unlock_roundtrip_preserves_disk_state() {
    // Build a wallet with a pending tx; lock; unlock; verify the
    // pending tx, the reserved output, and the balance all survived.
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");

    let mut wallet =
        Wallet::create(&path, "lock_test_pw", Network::Mainnet, &test_genesis()).unwrap();

    // Add a UTXO and create a pending spend, so we have rich state to preserve.
    wallet.add_output(make_output(900, 100, false));
    let recipient_blinding = BlindingFactor::random();
    let recipient_commitment = Commitment::commit(800, &recipient_blinding);
    let _tx = wallet
        .build_spend(recipient_commitment, recipient_blinding, 800, 100, 1000)
        .unwrap();

    let balance_before = wallet.balance(1000);
    let outputs_before: Vec<_> = wallet.outputs().cloned().collect();

    // Lock the wallet.
    wallet.lock();
    assert!(wallet.is_locked());

    // Unlock with the correct password.
    wallet
        .unlock("lock_test_pw")
        .expect("correct password must unlock");
    assert!(wallet.is_unlocked());

    // Wallet state in memory is exactly preserved.
    let balance_after = wallet.balance(1000);
    let outputs_after: Vec<_> = wallet.outputs().cloned().collect();
    assert_eq!(balance_before.confirmed, balance_after.confirmed);
    assert_eq!(balance_before.reserved, balance_after.reserved);
    assert_eq!(balance_before.immature, balance_after.immature);
    assert_eq!(outputs_before.len(), outputs_after.len());
}

#[test]
fn test_locked_wallet_then_reopen_matches_pre_lock_state() {
    // Models restart-after-lock: the operator locks the wallet, the
    // process exits (drop), a new process opens the wallet with the
    // password. The recovered state must equal the pre-lock state.
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");

    let mut wallet =
        Wallet::create(&path, "restart_pw", Network::Mainnet, &test_genesis()).unwrap();
    wallet.add_output(make_output(1500, 50, false));
    wallet.save().unwrap();
    let outputs_before: Vec<_> = wallet.outputs().cloned().collect();

    wallet.lock();
    // Simulate process exit: drop the wallet while locked. Drop must
    // not flush state to disk (we already saved above).
    drop(wallet);

    // New "process" opens the wallet from disk.
    let reopened = Wallet::open(&path, "restart_pw").unwrap();
    assert!(reopened.is_unlocked()); // open always produces an unlocked wallet.
    let outputs_after: Vec<_> = reopened.outputs().cloned().collect();
    assert_eq!(outputs_before.len(), outputs_after.len());
    let total_after: u64 = outputs_after.iter().map(|o| o.value).sum();
    let total_before: u64 = outputs_before.iter().map(|o| o.value).sum();
    assert_eq!(total_before, total_after);
}

#[test]
fn test_in_memory_wallet_lock_cycle() {
    // In-memory wallets have no on-disk ciphertext, so unlock with
    // any password is accepted. The state machine still toggles.
    let mut w = Wallet::new_in_memory(Network::Regtest, &test_genesis());
    assert!(w.is_unlocked());
    w.lock();
    assert!(w.is_locked());
    w.unlock("arbitrary_password_no_verification").unwrap();
    assert!(w.is_unlocked());
}

#[test]
fn test_multiple_wrong_password_attempts_keep_locked() {
    // Locking semantics under repeated bad-password attempts: each
    // attempt is independently rejected; the wallet never accepts a
    // wrong password "by accident" across attempts.
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wallet.dat");
    let mut w = Wallet::create(&path, "right", Network::Mainnet, &test_genesis()).unwrap();
    w.lock();
    for wrong in &["", "Right", "RIGHT", "right ", " right", "rright", "rightt"] {
        let err = w.unlock(wrong).expect_err("must reject");
        assert!(matches!(err, WalletError::Decryption));
        assert!(
            w.is_locked(),
            "wallet must remain locked after wrong attempt"
        );
    }
    // Correct password still works afterwards.
    w.unlock("right").expect("correct password still accepted");
    assert!(w.is_unlocked());
}
