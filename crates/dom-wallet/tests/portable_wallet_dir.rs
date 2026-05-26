//! Portable WalletDir — adversarial coverage (Phase 1.3).
//!
//! Covers:
//!
//!   1. Layout shape after create (exact files present).
//!   2. Self-containment: no writes outside the wallet directory.
//!   3. Exclusive lockfile: concurrent open is rejected.
//!   4. Lock released on Drop.
//!   5. Move-after-write: directory rename preserves state.
//!   6. Copy-and-open: cp -r the directory, open the copy.
//!   7. Corrupted wallet.dat is rejected by AEAD.
//!   8. Missing wallet.dat is rejected.
//!   9. Missing / malformed config.json is rejected.
//!  10. Unsupported wallet schema version (V2) is rejected on open.
//!  11. Refuse-to-create over a non-empty directory.
//!  12. Wrong password is rejected (delegates to existing AEAD check).

use dom_core::Hash256;
use dom_wallet::{
    Network, WalletConfig, WalletDir, WalletError, WalletVersion, WALLET_CONFIG_NAME,
    WALLET_DAT_NAME, WALLET_LOCK_NAME,
};
use tempfile::TempDir;

fn test_genesis() -> Hash256 {
    Hash256::from_bytes([0x42u8; 32])
}

// ─────────────────────────────────────────────────────────────────
// 1. Layout shape after create.
// ─────────────────────────────────────────────────────────────────

#[test]
fn create_emits_expected_layout() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("wallet1");
    let wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();

    assert!(dir.is_dir());
    assert!(dir.join(WALLET_DAT_NAME).is_file());
    assert!(dir.join(WALLET_LOCK_NAME).is_file());
    assert!(dir.join(WALLET_CONFIG_NAME).is_file());

    // Sub-dirs are lazily-created — not yet present.
    assert!(!dir.join("backups").exists());
    assert!(!dir.join("logs").exists());

    // config metadata sanity.
    assert_eq!(wd.config().version, WalletVersion::V1);
    assert_eq!(wd.config().network, Network::Mainnet);

    drop(wd);
}

// ─────────────────────────────────────────────────────────────────
// 2. Self-containment: nothing written above the wallet directory.
// ─────────────────────────────────────────────────────────────────

#[test]
fn create_writes_nothing_outside_the_directory() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("self_contained");
    let outside_before: Vec<_> = std::fs::read_dir(temp.path())
        .unwrap()
        .filter_map(|e| e.ok().map(|d| d.path()))
        .collect();

    let _wd = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();

    let outside_after: Vec<_> = std::fs::read_dir(temp.path())
        .unwrap()
        .filter_map(|e| e.ok().map(|d| d.path()))
        .collect();

    // The only new entry inside the TempDir's root should be `dir`
    // itself. No siblings, no parent-level breadcrumbs.
    let new_entries: Vec<_> = outside_after
        .iter()
        .filter(|p| !outside_before.contains(p))
        .collect();
    assert_eq!(new_entries.len(), 1);
    assert_eq!(new_entries[0], &dir);
}

// ─────────────────────────────────────────────────────────────────
// 3. Exclusive lockfile: concurrent open is rejected.
// ─────────────────────────────────────────────────────────────────

#[test]
fn second_open_with_lock_held_is_rejected() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("locked_dir");
    let _wd1 = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();

    let err = WalletDir::open(&dir, "pw")
        .err()
        .expect("second open must fail while first holds the lock");
    match err {
        WalletError::Io(msg) => {
            assert!(msg.contains("lock"), "expected lockfile error, got: {msg}")
        }
        other => panic!("expected WalletError::Io with lock message, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────
// 4. Lock released on Drop.
// ─────────────────────────────────────────────────────────────────

#[test]
fn lock_released_on_drop_allows_reopen() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("relock");
    let wd1 = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();
    drop(wd1);
    // Reopening after Drop must succeed.
    let wd2 = WalletDir::open(&dir, "pw").expect("reopen after drop must succeed");
    assert_eq!(wd2.config().version, WalletVersion::V1);
}

// ─────────────────────────────────────────────────────────────────
// 5. Move-after-write: rename the directory, reopen.
// ─────────────────────────────────────────────────────────────────

#[test]
fn move_directory_preserves_state() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("orig_dir");
    let dst = temp.path().join("moved_dir");

    let wd = WalletDir::create(&src, "pw", Network::Mainnet, &test_genesis()).unwrap();
    let chain_id_before = *wd.wallet().chain_id();
    drop(wd);

    std::fs::rename(&src, &dst).expect("rename must succeed");

    let reopened = WalletDir::open(&dst, "pw").expect("reopen after move must succeed");
    assert_eq!(*reopened.wallet().chain_id(), chain_id_before);
    assert_eq!(reopened.path(), dst.as_path());
}

// ─────────────────────────────────────────────────────────────────
// 6. Copy-and-open: cp -r the directory, open the copy.
// ─────────────────────────────────────────────────────────────────

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

#[test]
fn copy_directory_preserves_state() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("orig_copy");
    let dst = temp.path().join("copy_of");

    let wd = WalletDir::create(&src, "pw", Network::Regtest, &test_genesis()).unwrap();
    let chain_id_before = *wd.wallet().chain_id();
    drop(wd); // release lock before copying

    copy_dir_recursive(&src, &dst).expect("cp -r must succeed");

    // The original is still openable; so is the copy. (We open one
    // at a time to honour the exclusive lock semantics — Phase 1.3
    // is per-directory, not per-process.)
    let wd_copy = WalletDir::open(&dst, "pw").expect("copy must open");
    assert_eq!(*wd_copy.wallet().chain_id(), chain_id_before);
    drop(wd_copy);

    let wd_orig = WalletDir::open(&src, "pw").expect("original must open");
    assert_eq!(*wd_orig.wallet().chain_id(), chain_id_before);
}

// ─────────────────────────────────────────────────────────────────
// 7. Corrupted wallet.dat — AEAD must reject.
// ─────────────────────────────────────────────────────────────────

#[test]
fn corrupted_wallet_dat_is_rejected() {
    use std::io::Write;
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("corrupted");
    let wd = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();
    drop(wd);

    // Tamper with the ciphertext: flip a byte well past the header
    // so the AEAD tag must catch it.
    let dat_path = dir.join(WALLET_DAT_NAME);
    let mut data = std::fs::read(&dat_path).unwrap();
    let target = data.len() - 8; // somewhere inside the ciphertext
    data[target] ^= 0xFF;
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&dat_path)
            .unwrap();
        f.write_all(&data).unwrap();
        f.sync_all().unwrap();
    }

    let err = WalletDir::open(&dir, "pw").err().expect("must reject");
    assert!(
        matches!(err, WalletError::Decryption),
        "expected Decryption error, got {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────
// 8. Missing wallet.dat is rejected.
// ─────────────────────────────────────────────────────────────────

#[test]
fn missing_wallet_dat_is_rejected() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("missing_dat");
    let wd = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();
    drop(wd);

    std::fs::remove_file(dir.join(WALLET_DAT_NAME)).unwrap();

    let err = WalletDir::open(&dir, "pw").err().expect("must reject");
    match err {
        WalletError::Io(msg) => assert!(msg.contains("missing wallet.dat"), "msg: {msg}"),
        other => panic!("expected Io error, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────
// 9. Missing / malformed config.json is rejected.
// ─────────────────────────────────────────────────────────────────

#[test]
fn missing_config_is_rejected() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("no_config");
    let wd = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();
    drop(wd);
    std::fs::remove_file(dir.join(WALLET_CONFIG_NAME)).unwrap();

    let err = WalletDir::open(&dir, "pw").err().expect("must reject");
    assert!(matches!(err, WalletError::Io(_)));
}

#[test]
fn malformed_config_is_rejected() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("bad_config");
    let wd = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();
    drop(wd);
    std::fs::write(dir.join(WALLET_CONFIG_NAME), b"not valid json{").unwrap();

    let err = WalletDir::open(&dir, "pw").err().expect("must reject");
    assert!(matches!(err, WalletError::Serialization(_)));
}

// ─────────────────────────────────────────────────────────────────
// 10. Unsupported wallet schema version (V2) is rejected on open.
// ─────────────────────────────────────────────────────────────────

#[test]
fn unsupported_v2_schema_is_rejected() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("future_schema");
    let wd = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis()).unwrap();
    let chain_id_hex = hex::encode(wd.wallet().chain_id());
    drop(wd);

    // Rewrite config.json to declare V2.
    let bumped = WalletConfig {
        version: WalletVersion::V2,
        network: Network::Regtest,
        chain_id: chain_id_hex,
        created_at: 0,
        config_format: WalletConfig::CONFIG_FORMAT_V1,
    };
    let json = serde_json::to_vec_pretty(&bumped).unwrap();
    std::fs::write(dir.join(WALLET_CONFIG_NAME), json).unwrap();

    let err = WalletDir::open(&dir, "pw").err().expect("must reject");
    match err {
        WalletError::Io(msg) => assert!(
            msg.contains("unsupported schema version") || msg.contains("V2"),
            "msg: {msg}"
        ),
        other => panic!("expected Io error, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────
// 11. Refuse-to-create over a non-empty directory.
// ─────────────────────────────────────────────────────────────────

#[test]
fn create_over_nonempty_directory_refuses() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("not_empty");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("decoy.txt"), b"something already here").unwrap();

    let err = WalletDir::create(&dir, "pw", Network::Regtest, &test_genesis())
        .err()
        .expect("must refuse");
    match err {
        WalletError::Io(msg) => assert!(msg.contains("not empty"), "msg: {msg}"),
        other => panic!("expected Io error, got {other:?}"),
    }

    // The decoy file must still exist (refusal does not partially
    // initialise the directory).
    assert!(dir.join("decoy.txt").is_file());
    assert!(!dir.join(WALLET_DAT_NAME).exists());
}

// ─────────────────────────────────────────────────────────────────
// 12. Wrong password rejected via AEAD (delegates to existing path).
// ─────────────────────────────────────────────────────────────────

#[test]
fn open_with_wrong_password_is_rejected() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("wrong_pw");
    let wd = WalletDir::create(&dir, "right", Network::Regtest, &test_genesis()).unwrap();
    drop(wd);

    let err = WalletDir::open(&dir, "wrong").err().expect("must reject");
    assert!(
        matches!(err, WalletError::Decryption),
        "expected Decryption error, got {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────
// Sanity: WalletDir handle exposes the underlying Wallet API.
// ─────────────────────────────────────────────────────────────────

#[test]
fn wallet_dir_handle_exposes_wallet_mut() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("api_check");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    // is_unlocked is inherited from the loaded Wallet — verifies
    // the WalletDir's Wallet is the one we expect.
    assert!(wd.wallet().is_unlocked());
    wd.wallet_mut().lock();
    assert!(wd.wallet().is_locked());
}
