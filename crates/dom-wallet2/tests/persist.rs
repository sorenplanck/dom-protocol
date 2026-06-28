use dom_wallet2::{
    export_full_backup, import_full_backup, load_wallet_state, save_wallet_state, KeychainV2,
    Network, StoreMeta, WalletV2State,
};
use tempfile::TempDir;
use zeroize::Zeroizing;

const CHAIN_ID: [u8; 32] = [0x71; 32];
const SEED: [u8; 64] = [0x5e; 64];

fn state() -> WalletV2State {
    let mut state = WalletV2State::new(Network::Regtest, CHAIN_ID);
    state.keychain = KeychainV2 {
        seed_bytes: Some(Zeroizing::new(SEED)),
        seed_word_count: Some(24),
        next_change_index: 2,
        next_receive_index: 3,
        account: 0,
    };
    state.meta = StoreMeta {
        last_reconciled_tip: 9,
        last_reconciled_hash: Some([9; 32]),
    };
    state
}

#[test]
fn wallet_state_and_full_backup_round_trip_public_api() {
    let dir = TempDir::new().unwrap();
    let wallet_path = dir.path().join("wallet.dat");
    let backup_path = dir.path().join("wallet.dombak");
    let state = state();

    save_wallet_state(&state, &wallet_path, "wallet-pw").unwrap();
    let loaded = load_wallet_state(&wallet_path, "wallet-pw").unwrap();
    assert_eq!(loaded.chain_id, CHAIN_ID);
    assert_eq!(loaded.keychain.seed_bytes.as_ref().unwrap()[..], SEED[..]);
    assert_eq!(loaded.meta.last_reconciled_tip, 9);

    export_full_backup(&loaded, &backup_path, "backup-pw", 123).unwrap();
    let restored = import_full_backup(&backup_path, "backup-pw", CHAIN_ID).unwrap();
    assert_eq!(restored.chain_id, CHAIN_ID);
    assert_eq!(restored.keychain.seed_bytes.as_ref().unwrap()[..], SEED[..]);
    assert_eq!(restored.meta.last_reconciled_hash, Some([9; 32]));
}
