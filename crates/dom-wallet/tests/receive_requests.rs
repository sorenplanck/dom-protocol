use dom_core::Hash256;
use dom_wallet::{
    Bip39Seed, Network, ReceiveRequestStatus, SeedAcceptance, WalletDir, WalletError,
};
use tempfile::TempDir;

const PHRASE_24: &str = "abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon art";

fn test_genesis() -> Hash256 {
    Hash256::from_bytes([0x24u8; 32])
}

#[test]
fn same_seed_produces_same_first_receive_descriptor() {
    let temp = TempDir::new().unwrap();
    let seed = Bip39Seed::from_phrase(PHRASE_24, SeedAcceptance::NewWallet).unwrap();

    let mut first = WalletDir::create_from_seed(
        &temp.path().join("wallet_a"),
        "pw",
        Network::Regtest,
        &test_genesis(),
        &seed,
    )
    .unwrap();
    let mut second = WalletDir::create_from_seed(
        &temp.path().join("wallet_b"),
        "pw",
        Network::Regtest,
        &test_genesis(),
        &seed,
    )
    .unwrap();

    let a = first.wallet_mut().create_receive_request(42).unwrap();
    let b = second.wallet_mut().create_receive_request(42).unwrap();

    assert_eq!(a.index, 0);
    assert_eq!(b.index, 0);
    assert_eq!(a.address, b.address);
    assert_eq!(a.commitment_hex, b.commitment_hex);
    assert_eq!(a.blinding_hex, b.blinding_hex);
}

#[test]
fn receive_requests_persist_across_reopen() {
    let temp = TempDir::new().unwrap();
    let seed = Bip39Seed::from_phrase(PHRASE_24, SeedAcceptance::NewWallet).unwrap();
    let dir = temp.path().join("wallet");

    let mut wallet_dir =
        WalletDir::create_from_seed(&dir, "pw", Network::Regtest, &test_genesis(), &seed).unwrap();
    let created = wallet_dir.wallet_mut().create_receive_request(77).unwrap();
    let commitment = created.commitment_hex.clone();
    drop(wallet_dir);

    let reopened = WalletDir::open(&dir, "pw").unwrap();
    let descriptors = reopened.wallet().receive_descriptors().unwrap();
    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].commitment_hex, commitment);
    assert_eq!(descriptors[0].amount, 77);
    assert_eq!(descriptors[0].index, 0);
    assert_eq!(descriptors[0].status, ReceiveRequestStatus::Pending);
}

#[test]
fn receive_request_status_update_persists() {
    let temp = TempDir::new().unwrap();
    let seed = Bip39Seed::from_phrase(PHRASE_24, SeedAcceptance::NewWallet).unwrap();
    let dir = temp.path().join("wallet");

    let mut wallet_dir =
        WalletDir::create_from_seed(&dir, "pw", Network::Regtest, &test_genesis(), &seed).unwrap();
    let created = wallet_dir.wallet_mut().create_receive_request(88).unwrap();
    let commitment = hex::decode(&created.commitment_hex).unwrap();
    let commitment: [u8; 33] = commitment.try_into().unwrap();

    let changed = wallet_dir.wallet_mut().update_receive_request_status(
        &commitment,
        Some(ReceiveRequestStatus::Detected {
            block_height: 12,
            is_coinbase: false,
            is_mature: true,
        }),
    );
    assert!(changed.unwrap());
    drop(wallet_dir);

    let reopened = WalletDir::open(&dir, "pw").unwrap();
    let descriptors = reopened.wallet().receive_descriptors().unwrap();
    assert_eq!(descriptors.len(), 1);
    assert_eq!(
        descriptors[0].status,
        ReceiveRequestStatus::Detected {
            block_height: 12,
            is_coinbase: false,
            is_mature: true,
        }
    );
}

/// The sweep/receive settlement path: once the node reports the receive
/// commitment in the canonical UTXO set, `confirm_receive_request` must turn
/// the pending request into a SPENDABLE output — this is what credits swept
/// miner rewards to the user wallet.
#[test]
fn confirm_receive_request_credits_spendable_balance() {
    let temp = TempDir::new().unwrap();
    let seed = Bip39Seed::from_phrase(PHRASE_24, SeedAcceptance::NewWallet).unwrap();
    let dir = temp.path().join("wallet");

    let mut wallet_dir =
        WalletDir::create_from_seed(&dir, "pw", Network::Regtest, &test_genesis(), &seed).unwrap();
    let created = wallet_dir.wallet_mut().create_receive_request(5_000).unwrap();
    let commitment: [u8; 33] = hex::decode(&created.commitment_hex)
        .unwrap()
        .try_into()
        .unwrap();

    // Before confirmation the request is pending and contributes nothing.
    assert_eq!(wallet_dir.wallet().balance(100).confirmed, 0);

    let added = wallet_dir
        .wallet_mut()
        .confirm_receive_request(&commitment, 42, None)
        .unwrap();
    assert!(added, "first confirmation must record the output");

    let balance = wallet_dir.wallet().balance(100);
    assert_eq!(
        balance.confirmed, 5_000,
        "confirmed receive must be spendable balance"
    );

    // Idempotent: a second observation of the same UTXO changes nothing.
    let again = wallet_dir
        .wallet_mut()
        .confirm_receive_request(&commitment, 42, None)
        .unwrap();
    assert!(!again, "second confirmation must be a no-op");
    assert_eq!(wallet_dir.wallet().balance(100).confirmed, 5_000);

    // The settled output and request status survive a reopen.
    drop(wallet_dir);
    let reopened = WalletDir::open(&dir, "pw").unwrap();
    assert_eq!(reopened.wallet().balance(100).confirmed, 5_000);
    let descriptors = reopened.wallet().receive_descriptors().unwrap();
    assert!(matches!(
        descriptors[0].status,
        ReceiveRequestStatus::Detected { block_height: 42, .. }
    ));
}

#[test]
fn confirm_receive_request_unknown_commitment_errors() {
    let temp = TempDir::new().unwrap();
    let seed = Bip39Seed::from_phrase(PHRASE_24, SeedAcceptance::NewWallet).unwrap();
    let mut wallet_dir = WalletDir::create_from_seed(
        &temp.path().join("wallet"),
        "pw",
        Network::Regtest,
        &test_genesis(),
        &seed,
    )
    .unwrap();
    let err = wallet_dir
        .wallet_mut()
        .confirm_receive_request(&[7u8; 33], 1, None)
        .unwrap_err();
    assert!(matches!(err, WalletError::OutputNotFound(_)));
}

#[test]
fn cancel_receive_request_removes_only_pending_requests() {
    let temp = TempDir::new().unwrap();
    let seed = Bip39Seed::from_phrase(PHRASE_24, SeedAcceptance::NewWallet).unwrap();
    let dir = temp.path().join("wallet");
    let mut wallet_dir =
        WalletDir::create_from_seed(&dir, "pw", Network::Regtest, &test_genesis(), &seed).unwrap();

    // A pending request (e.g. a sweep whose spend was rejected) is removable.
    let pending = wallet_dir.wallet_mut().create_receive_request(1_000).unwrap();
    let pending_commitment: [u8; 33] = hex::decode(&pending.commitment_hex)
        .unwrap()
        .try_into()
        .unwrap();
    assert!(wallet_dir
        .wallet_mut()
        .cancel_receive_request(&pending_commitment)
        .unwrap());
    assert!(wallet_dir.wallet().receive_descriptors().unwrap().is_empty());

    // A settled request must NOT be cancellable (its output is real funds).
    let settled = wallet_dir.wallet_mut().create_receive_request(2_000).unwrap();
    let settled_commitment: [u8; 33] = hex::decode(&settled.commitment_hex)
        .unwrap()
        .try_into()
        .unwrap();
    wallet_dir
        .wallet_mut()
        .confirm_receive_request(&settled_commitment, 9, None)
        .unwrap();
    assert!(!wallet_dir
        .wallet_mut()
        .cancel_receive_request(&settled_commitment)
        .unwrap());
    assert_eq!(wallet_dir.wallet().balance(100).confirmed, 2_000);
}

#[test]
fn locked_wallet_cannot_create_receive_request() {
    let temp = TempDir::new().unwrap();
    let seed = Bip39Seed::from_phrase(PHRASE_24, SeedAcceptance::NewWallet).unwrap();
    let dir = temp.path().join("wallet");

    let mut wallet_dir =
        WalletDir::create_from_seed(&dir, "pw", Network::Regtest, &test_genesis(), &seed).unwrap();
    wallet_dir.wallet_mut().lock();
    let err = match wallet_dir.wallet_mut().create_receive_request(11) {
        Ok(_) => panic!("locked wallet must reject receive generation"),
        Err(err) => err,
    };
    assert!(matches!(err, WalletError::Locked));
}
