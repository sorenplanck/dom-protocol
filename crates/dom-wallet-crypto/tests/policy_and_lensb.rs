//! dom-shield — dom-wallet-crypto / policy findings + Lens B (at-rest crypto).
//!
//! This crate owns the most sensitive bytes in the system (the file holding the
//! blinding factors). Lens B (Lazarus-class key extraction) is central. The
//! findings below are recorded as tests/probes; the ones that are
//! behaviourally-untestable (intermediate zeroization) are `#[ignore]` with the
//! exact source lines so the auditor sees the door even though no runtime
//! assertion can prove it from outside.
//!
//! NOTE: every finding here is RECORDED, not fixed (fixing key-derivation /
//! format / zeroization is a separate human-decision queue per the shield
//! method).

use dom_wallet_crypto::{derive_wallet_key, save_envelope, KdfParams, MAGIC_LEN};
use serde::{Deserialize, Serialize};

const TEST_MAGIC: &[u8; MAGIC_LEN] = b"DOM-TEST-ENV\0\0";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Payload {
    a: u32,
}

// ─────────────────────────── empty-password policy ───────────────────────────

/// [x][w] POLICY FINDING: `derive_wallet_key("")` is ACCEPTED. There is no
/// minimum-strength / non-empty gate — an empty password yields a valid key and
/// a fully encryptable wallet.
///
/// This is by design at this layer (the envelope is a generic primitive; UX
/// password policy belongs to dom-wallet). Recorded here as a deliberate policy
/// decision, NOT a crash: an empty-password wallet is only as strong as
/// Argon2id over a known-plaintext-password. Surfacing it makes the choice
/// visible. PRECISA DECISÃO HUMANA if a min-strength gate is ever wanted.
/// The envelope audit refuses a parent directory that is not owner-only, and a
/// fresh tempdir inherits the process umask (0o755 under the usual 022).
fn owner_only_tempdir() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("tempdir");
    #[cfg(unix)]
    std::fs::set_permissions(
        dir.path(),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .expect("owner-only tempdir");
    dir
}

#[test]
fn empty_password_is_accepted_policy() {
    let salt = [0x11u8; 32];
    let key = derive_wallet_key("", &salt, &KdfParams::OWASP_V1);
    assert!(
        key.is_ok(),
        "empty password derives a key (no min-strength gate)"
    );

    // And a full envelope round-trips under an empty password.
    let dir = owner_only_tempdir();
    let path = dir.path().join("env.dat");
    save_envelope(&path, TEST_MAGIC, 1, &Payload { a: 5 }, "").unwrap();
    let back: Payload = dom_wallet_crypto::load_envelope(&path, TEST_MAGIC, 1, "").unwrap();
    assert_eq!(back, Payload { a: 5 });
}

// ─────────────────────────────── atomic_write ────────────────────────────────

/// [x] atomic_write produces a recoverable file and leaves no `.tmp` behind on
/// the success path. This is the observable part of DOM-SEC-007.
#[test]
fn atomic_write_leaves_no_tmp_on_success() {
    let dir = owner_only_tempdir();
    let path = dir.path().join("env.dat");
    save_envelope(&path, TEST_MAGIC, 1, &Payload { a: 1 }, "pw").unwrap();
    let tmp = path.with_extension("tmp");
    assert!(path.exists(), "final file exists");
    assert!(!tmp.exists(), "temp file removed by atomic rename");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let metadata = std::fs::symlink_metadata(path).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }
}

/// The retired deterministic name is never opened, truncated, or followed.
/// This turns the former ignored static finding into an observable regression
/// test on every platform.
#[test]
fn stale_deterministic_tmp_is_not_reused() {
    let dir = owner_only_tempdir();
    let path = dir.path().join("env.dat");
    let retired = path.with_extension("tmp");
    std::fs::write(&retired, b"do-not-touch").unwrap();
    save_envelope(&path, TEST_MAGIC, 1, &Payload { a: 9 }, "pw").unwrap();
    assert_eq!(std::fs::read(&retired).unwrap(), b"do-not-touch");
    let back: Payload = dom_wallet_crypto::load_envelope(&path, TEST_MAGIC, 1, "pw").unwrap();
    assert_eq!(back, Payload { a: 9 });
}

#[cfg(unix)]
#[test]
fn retired_tmp_symlink_cannot_redirect_the_write() {
    use std::os::unix::fs::symlink;

    let dir = owner_only_tempdir();
    let path = dir.path().join("env.dat");
    let sentinel = dir.path().join("sentinel");
    let retired = path.with_extension("tmp");
    std::fs::write(&sentinel, b"sentinel").unwrap();
    symlink(&sentinel, &retired).unwrap();
    save_envelope(&path, TEST_MAGIC, 1, &Payload { a: 11 }, "pw").unwrap();
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
    assert!(std::fs::symlink_metadata(&retired)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[cfg(unix)]
#[test]
fn target_symlink_is_replaced_and_never_followed() {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    let dir = owner_only_tempdir();
    let path = dir.path().join("env.dat");
    let sentinel = dir.path().join("sentinel");
    std::fs::write(&sentinel, b"sentinel").unwrap();
    symlink(&sentinel, &path).unwrap();
    save_envelope(&path, TEST_MAGIC, 1, &Payload { a: 12 }, "pw").unwrap();
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.file_type().is_file());
    assert!(!metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
}

#[test]
fn concurrent_saves_publish_only_complete_envelopes_and_clean_staging() {
    use std::sync::{Arc, Barrier};

    let dir = owner_only_tempdir();
    let path = dir.path().join("env.dat");
    let barrier = Arc::new(Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let first_path = path.clone();
        let first_barrier = Arc::clone(&barrier);
        let first = scope.spawn(move || {
            first_barrier.wait();
            save_envelope(&first_path, TEST_MAGIC, 1, &Payload { a: 21 }, "pw")
        });
        let second_path = path.clone();
        let second_barrier = Arc::clone(&barrier);
        let second = scope.spawn(move || {
            second_barrier.wait();
            save_envelope(&second_path, TEST_MAGIC, 1, &Payload { a: 22 }, "pw")
        });
        [first.join(), second.join()]
    });
    assert!(results
        .into_iter()
        .all(|result| matches!(result, Ok(Ok(())))));
    let back: Payload = dom_wallet_crypto::load_envelope(&path, TEST_MAGIC, 1, "pw").unwrap();
    assert!(matches!(back.a, 21 | 22));
    let staging = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".dom-wallet-save-")
        })
        .count();
    assert_eq!(staging, 0);
}

// ───────────────────────────── Lens B: zeroization ───────────────────────────

/// [ignore][w] LENS B FINDING — un-zeroized key intermediate in
/// `derive_wallet_key`.
///
/// lib.rs:160  `let mut key_bytes = [0u8; 32];`   // HKDF output buffer
/// lib.rs:161  `hkdf.expand(HKDF_INFO, &mut key_bytes)`
/// lib.rs:164  `Ok(WalletKey::from_bytes(key_bytes))`  // [u8;32] is Copy
///
/// `key_bytes` is a plain `[u8; 32]` (Copy). `WalletKey::from_bytes` takes it
/// BY VALUE, which COPIES the 32 raw key bytes into the Zeroizing buffer; the
/// ORIGINAL stack array `key_bytes` is NOT zeroized and is left on the stack to
/// be overwritten only by chance. So the final wallet key exists in cleartext
/// in (at least) two places, and one of them is never wiped.
///
/// Contrast: the Argon2 `stretched` buffer (lib.rs:154) IS `Zeroizing`. The
/// HKDF output is the one un-wrapped intermediate.
///
/// WHY [ignore]: zeroization of a stack local is not observable from outside the
/// crate (no public hook, and reading freed/old stack memory is UB). This is a
/// real intermediate-leak finding provable only by source review, not by a
/// passing runtime assertion. FIX (separate queue, human decision — touches
/// key-derivation): make `key_bytes` `Zeroizing<[u8;32]>` and move via clone, or
/// have `from_bytes` take `Zeroizing`.
#[test]
#[ignore = "Lens B: HKDF key_bytes [u8;32] Copy not zeroized after move into WalletKey (lib.rs:160-164) — source-only finding"]
fn key_intermediate_left_unzeroized() {
    unreachable!("documented finding — see note");
}

/// [ignore][w] LENS B FINDING — plaintext JSON not zeroized on SAVE.
///
/// lib.rs:186  `let json = serde_json::to_vec(value)...`   // Vec<u8>, plaintext
///
/// `json` holds the full cleartext payload (the blinding factors). It is a plain
/// `Vec<u8>`, NOT `Zeroizing`, and is dropped at end of `save_envelope` without
/// being wiped — its heap buffer is freed with secrets still in it. Should be
/// `Zeroizing<Vec<u8>>` (or zeroized before drop).
///
/// WHY [ignore]: heap-zeroization-on-drop is not observable from an integration
/// test (cannot read freed memory safely). Source-only finding. FIX is a
/// separate queue (touches the secret-handling path).
#[test]
#[ignore = "Lens B: plaintext json Vec not zeroized on save (lib.rs:186) — source-only finding"]
fn plaintext_not_zeroized_on_save() {
    unreachable!("documented finding — see note");
}

/// [ignore][w] LENS B FINDING — plaintext not zeroized on LOAD.
///
/// lib.rs:250  `let plaintext = cipher.decrypt(nonce, &data[HEADER_SIZE..])...`
/// lib.rs:254  `serde_json::from_slice(&plaintext)...`   // plaintext dropped after
///
/// The decrypted `plaintext` (Vec<u8>) holds the cleartext secrets after a
/// successful unlock. It is a plain `Vec<u8>` (not `Zeroizing`) and is dropped
/// at function end without wiping — secrets linger in freed heap. Also `data`
/// (the whole file bytes incl. ciphertext) is un-zeroized, though that is less
/// sensitive (ciphertext). Should wrap `plaintext` in `Zeroizing`.
///
/// WHY [ignore]: same as above — drop-time heap wipe is not observable from a
/// passing test. Source-only finding; fix is a separate human-decision queue.
#[test]
#[ignore = "Lens B: decrypted plaintext Vec not zeroized on load (lib.rs:250-254) — source-only finding"]
fn plaintext_not_zeroized_on_load() {
    unreachable!("documented finding — see note");
}
