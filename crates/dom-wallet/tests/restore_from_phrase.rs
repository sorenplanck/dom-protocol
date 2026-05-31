//! Deterministic restore — adversarial coverage (Phase 1.4).
//!
//! Each test constructs synthetic [`ScanBlock`]s using
//! seed-derived blindings directly (no node, no consensus path).
//! That mirrors what a real chain produced by a V2 wallet would
//! look like and exercises the restore logic in isolation.

use dom_core::{BlockHeight, Hash256};
use dom_crypto::pedersen::Commitment;
use dom_crypto::BlindingFactor;
use dom_wallet::{
    coinbase_blinding, restore_from_phrase, Bip39Seed, ChainScanSource, InMemoryChainScan, Network,
    RestoreError, ScanBlock, SeedAcceptance, WalletConfig, WalletVersion, WALLET_CONFIG_NAME,
    WALLET_DAT_NAME,
};
use tempfile::TempDir;

const PHRASE_24: &str = "abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon art";

const PHRASE_24_ALT: &str = "legal winner thank year wave sausage worth useful legal \
                             winner thank year wave sausage worth useful legal \
                             winner thank year wave sausage worth title";

const PHRASE_12: &str = "abandon abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon about";

fn test_genesis() -> Hash256 {
    Hash256::from_bytes([0x42u8; 32])
}

/// Build a synthetic `ScanBlock` whose coinbase output commitment is
/// what a V2 wallet built from `phrase` would produce at `height`
/// (value = `reward(height)`, no fees, with optional siblings).
fn block_with_coinbase_for(
    phrase: &str,
    height: u64,
    extra_unrelated_commitments: usize,
) -> ScanBlock {
    let seed = Bip39Seed::from_phrase(phrase, SeedAcceptance::NewWallet).unwrap();
    let root = seed.derive_root().unwrap();
    let blinding_z = coinbase_blinding(&root, height).unwrap();
    let blinding = BlindingFactor::from_bytes(*blinding_z).unwrap();
    let reward = dom_core::block_reward(BlockHeight(height)).noms();
    let commitment = Commitment::commit(reward, &blinding);
    let mut outputs = vec![*commitment.as_bytes()];
    // Add unrelated commitments (random blindings) to model real
    // multi-output blocks; they must NOT be recovered.
    for i in 0..extra_unrelated_commitments {
        let bf = BlindingFactor::random();
        let c = Commitment::commit(reward.wrapping_add(i as u64 + 1), &bf);
        outputs.push(*c.as_bytes());
    }
    ScanBlock {
        height,
        block_hash: None,
        output_commitments: outputs,
        input_commitments: vec![],
        total_fees_noms: 0,
        tx_effects: vec![],
    }
}

fn block_with_coinbase_and_fees(phrase: &str, height: u64, fees: u64) -> ScanBlock {
    let seed = Bip39Seed::from_phrase(phrase, SeedAcceptance::NewWallet).unwrap();
    let root = seed.derive_root().unwrap();
    let blinding_z = coinbase_blinding(&root, height).unwrap();
    let blinding = BlindingFactor::from_bytes(*blinding_z).unwrap();
    let value = dom_core::block_reward(BlockHeight(height)).noms() + fees;
    let commitment = Commitment::commit(value, &blinding);
    ScanBlock {
        height,
        block_hash: None,
        output_commitments: vec![*commitment.as_bytes()],
        input_commitments: vec![],
        total_fees_noms: fees,
        tx_effects: vec![],
    }
}

// ─────────────────────────────────────────────────────────────────
// 1. Empty scan ⇒ empty wallet.
// ─────────────────────────────────────────────────────────────────

#[test]
fn empty_scan_yields_empty_wallet() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("empty_restore");
    let scan = InMemoryChainScan::new();
    let r = restore_from_phrase(
        PHRASE_24,
        "pw",
        &dir,
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .expect("empty restore must succeed");
    assert_eq!(r.recovered_count, 0);
    assert_eq!(r.scanned_tip, 0);
    assert_eq!(r.wallet.outputs().count(), 0);
}

// ─────────────────────────────────────────────────────────────────
// 2. Recover coinbase outputs matching the seed.
// ─────────────────────────────────────────────────────────────────

#[test]
fn recovers_coinbases_matching_seed_across_heights() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("coinbase_restore");
    let mut scan = InMemoryChainScan::new();
    for h in [0u64, 1, 5, 42, 100] {
        scan.insert(block_with_coinbase_for(PHRASE_24, h, 2));
    }
    let r = restore_from_phrase(
        PHRASE_24,
        "pw",
        &dir,
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .unwrap();
    assert_eq!(r.recovered_count, 5, "all 5 coinbases must be recovered");
    assert_eq!(r.scanned_tip, 100);
    assert_eq!(r.wallet.outputs().count(), 5);
}

// ─────────────────────────────────────────────────────────────────
// 3. Different seed against same scan ⇒ no outputs.
// ─────────────────────────────────────────────────────────────────

#[test]
fn other_seed_does_not_recover_other_wallets_coinbases() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("other_seed");
    let mut scan = InMemoryChainScan::new();
    // Build the scan from one wallet's coinbases ...
    scan.insert(block_with_coinbase_for(PHRASE_24, 0, 0));
    scan.insert(block_with_coinbase_for(PHRASE_24, 1, 0));
    scan.insert(block_with_coinbase_for(PHRASE_24, 2, 0));
    // ... and restore using a DIFFERENT phrase.
    let r = restore_from_phrase(
        PHRASE_24_ALT,
        "pw",
        &dir,
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .unwrap();
    assert_eq!(
        r.recovered_count, 0,
        "another wallet's coinbases must not be misattributed"
    );
    assert_eq!(r.wallet.outputs().count(), 0);
}

// ─────────────────────────────────────────────────────────────────
// 4. Determinism: same phrase + same scan ⇒ same recovered set.
// ─────────────────────────────────────────────────────────────────

#[test]
fn restore_is_deterministic_across_runs() {
    let temp1 = TempDir::new().unwrap();
    let temp2 = TempDir::new().unwrap();
    let dir1 = temp1.path().join("dir_a");
    let dir2 = temp2.path().join("dir_b");
    let mut scan = InMemoryChainScan::new();
    for h in [0u64, 3, 7] {
        scan.insert(block_with_coinbase_for(PHRASE_24, h, 0));
    }
    let r1 = restore_from_phrase(
        PHRASE_24,
        "pw",
        &dir1,
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .unwrap();
    let r2 = restore_from_phrase(
        PHRASE_24,
        "pw",
        &dir2,
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .unwrap();

    assert_eq!(r1.recovered_count, r2.recovered_count);

    let mut outputs1: Vec<_> = r1.wallet.outputs().map(|o| o.commitment).collect();
    let mut outputs2: Vec<_> = r2.wallet.outputs().map(|o| o.commitment).collect();
    outputs1.sort();
    outputs2.sort();
    assert_eq!(
        outputs1, outputs2,
        "two restores from the same phrase must produce identical commitment sets"
    );
}

// ─────────────────────────────────────────────────────────────────
// 5. Truncated scan ⇒ only first N coinbases recovered.
// ─────────────────────────────────────────────────────────────────

#[test]
fn truncated_scan_recovers_only_scanned_heights() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("truncated");
    let mut scan = InMemoryChainScan::new();
    // Only heights 0 and 1 are in the scan; height 10 is missing.
    scan.insert(block_with_coinbase_for(PHRASE_24, 0, 0));
    scan.insert(block_with_coinbase_for(PHRASE_24, 1, 0));
    let r = restore_from_phrase(
        PHRASE_24,
        "pw",
        &dir,
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .unwrap();
    assert_eq!(r.recovered_count, 2);
    assert_eq!(r.scanned_tip, 1);
}

// ─────────────────────────────────────────────────────────────────
// 6. reward + fees value is also tried.
// ─────────────────────────────────────────────────────────────────

#[test]
fn reward_plus_fees_candidate_is_tried() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("with_fees");
    let mut scan = InMemoryChainScan::new();
    scan.insert(block_with_coinbase_and_fees(PHRASE_24, 7, 12_345));
    let r = restore_from_phrase(
        PHRASE_24,
        "pw",
        &dir,
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .unwrap();
    assert_eq!(
        r.recovered_count, 1,
        "coinbase with fees should be recovered via reward+fees candidate"
    );
    let owned = r.wallet.outputs().next().unwrap();
    let expected = dom_core::block_reward(BlockHeight(7)).noms() + 12_345;
    assert_eq!(owned.value, expected);
}

// ─────────────────────────────────────────────────────────────────
// 7. Phrase validation: 24 words required for restore.
// ─────────────────────────────────────────────────────────────────

#[test]
fn non_24_word_phrase_is_rejected() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("twelve");
    let scan = InMemoryChainScan::new();
    let err = restore_from_phrase(
        PHRASE_12,
        "pw",
        &dir,
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .err()
    .expect("12-word phrase must be rejected");
    assert!(
        matches!(err, RestoreError::InvalidPhrase(_)),
        "expected InvalidPhrase, got {err:?}"
    );
    // Target dir must NOT be populated on rejection.
    assert!(!dir.join(WALLET_DAT_NAME).exists());
    assert!(!dir.join(WALLET_CONFIG_NAME).exists());
}

#[test]
fn garbage_phrase_is_rejected() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("garbage");
    let scan = InMemoryChainScan::new();
    let err = restore_from_phrase(
        "not a real bip39 phrase at all nope nope nope nope nope nope nope nope nope nope \
         nope nope nope nope nope nope nope nope nope nope nope nope nope",
        "pw",
        &dir,
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .err()
    .expect("garbage phrase must be rejected");
    assert!(matches!(err, RestoreError::InvalidPhrase(_)));
}

// ─────────────────────────────────────────────────────────────────
// 8. On-disk layout after restore: V2 config + encrypted wallet.dat.
// ─────────────────────────────────────────────────────────────────

#[test]
fn restored_directory_has_v2_config_and_encrypted_dat() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("layout");
    let scan = InMemoryChainScan::new();
    let _r = restore_from_phrase(
        PHRASE_24,
        "pw",
        &dir,
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .unwrap();

    assert!(dir.join(WALLET_DAT_NAME).is_file());
    assert!(dir.join(WALLET_CONFIG_NAME).is_file());

    let config_bytes = std::fs::read(dir.join(WALLET_CONFIG_NAME)).unwrap();
    let cfg: WalletConfig = serde_json::from_slice(&config_bytes).unwrap();
    assert_eq!(
        cfg.version,
        WalletVersion::V2,
        "restored wallets must be tagged V2"
    );
    assert_eq!(cfg.network, Network::Regtest);
}

// ─────────────────────────────────────────────────────────────────
// 9. Refuse-to-overwrite a non-empty target directory.
// ─────────────────────────────────────────────────────────────────

#[test]
fn refuses_to_restore_into_non_empty_directory() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("not_empty");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("decoy.txt"), b"already here").unwrap();

    let scan = InMemoryChainScan::new();
    let err = restore_from_phrase(
        PHRASE_24,
        "pw",
        &dir,
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .err()
    .expect("must refuse");
    assert!(
        matches!(err, RestoreError::TargetNotEmpty(_)),
        "expected TargetNotEmpty, got {err:?}"
    );
    assert!(dir.join("decoy.txt").is_file(), "decoy must be preserved");
    assert!(
        !dir.join(WALLET_DAT_NAME).exists(),
        "no wallet.dat must be written on refusal"
    );
}

// ─────────────────────────────────────────────────────────────────
// 10. Restored V2 wallet reopens via WalletDir::open.
// ─────────────────────────────────────────────────────────────────

#[test]
fn restored_wallet_dir_reopens() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("openable");
    let mut scan = InMemoryChainScan::new();
    scan.insert(block_with_coinbase_for(PHRASE_24, 0, 0));
    let r = restore_from_phrase(
        PHRASE_24,
        "pw",
        &dir,
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .unwrap();
    let recovered_outputs: Vec<_> = r.wallet.outputs().map(|o| o.commitment).collect();
    drop(r); // release file handles cleanly

    let reopened = dom_wallet::WalletDir::open(&dir, "pw").expect("WalletDir::open must work");
    assert!(reopened.wallet().has_deterministic_seed());
    assert_eq!(reopened.config().version, WalletVersion::V2);
    let reopened = reopened.wallet();
    let after: Vec<_> = reopened.outputs().map(|o| o.commitment).collect();
    assert_eq!(
        recovered_outputs, after,
        "outputs must persist across restore -> open"
    );
}

// ─────────────────────────────────────────────────────────────────
// 11. Idempotency: re-running restore into a fresh dir produces the
//     same set as the first run (different output ORDER tolerated).
// ─────────────────────────────────────────────────────────────────

#[test]
fn restore_is_idempotent_into_fresh_dirs() {
    let mut scan = InMemoryChainScan::new();
    for h in [0u64, 2, 4, 6, 8] {
        scan.insert(block_with_coinbase_for(PHRASE_24, h, 1));
    }

    let temp1 = TempDir::new().unwrap();
    let temp2 = TempDir::new().unwrap();

    let r1 = restore_from_phrase(
        PHRASE_24,
        "pw",
        temp1.path(),
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .unwrap();
    let r2 = restore_from_phrase(
        PHRASE_24,
        "pw",
        temp2.path(),
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .unwrap();

    let mut s1: Vec<_> = r1
        .wallet
        .outputs()
        .map(|o| (o.commitment, o.value, o.block_height))
        .collect();
    let mut s2: Vec<_> = r2
        .wallet
        .outputs()
        .map(|o| (o.commitment, o.value, o.block_height))
        .collect();
    s1.sort();
    s2.sort();
    assert_eq!(s1, s2);
}

// ─────────────────────────────────────────────────────────────────
// 12. Scan with `block_at` returning None for some heights ⇒ skip.
// ─────────────────────────────────────────────────────────────────

#[test]
fn missing_intermediate_blocks_are_skipped() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("gaps");
    let mut scan = InMemoryChainScan::new();
    scan.insert(block_with_coinbase_for(PHRASE_24, 0, 0));
    // Skip 1, 2, 3; jump to 4.
    scan.insert(block_with_coinbase_for(PHRASE_24, 4, 0));

    let r = restore_from_phrase(
        PHRASE_24,
        "pw",
        &dir,
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .unwrap();
    assert_eq!(r.recovered_count, 2);
    assert_eq!(r.scanned_tip, 4);
}

// ─────────────────────────────────────────────────────────────────
// 13. Mismatch defence: block.height ≠ requested height is an error.
// ─────────────────────────────────────────────────────────────────

struct MisbehavingScan;

impl ChainScanSource for MisbehavingScan {
    fn tip_height(&self) -> u64 {
        1
    }
    fn block_at(&self, _height: u64) -> Result<Option<ScanBlock>, RestoreError> {
        // Always returns the same block, regardless of the requested
        // height. Restore must catch this and refuse to silently
        // pollute the wallet.
        Ok(Some(ScanBlock {
            height: 999,
            block_hash: None,
            output_commitments: vec![],
            input_commitments: vec![],
            total_fees_noms: 0,
            tx_effects: vec![],
        }))
    }
}

#[test]
fn misbehaving_scan_height_mismatch_is_rejected() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("liar");
    let scan = MisbehavingScan;
    let err = restore_from_phrase(
        PHRASE_24,
        "pw",
        &dir,
        Network::Regtest,
        &test_genesis(),
        &scan,
    )
    .err()
    .expect("must reject mismatched height");
    assert!(matches!(err, RestoreError::ScanError { .. }));
}
