//! dom-shield Onda 2 — FIX-005 regression for `dom_wallet::backup`.
//!
//! Subfamily: directed/KAV (Lens B funds-safety, transport-key hygiene).
//!
//! The hardened backup format must randomize ciphertexts and reject wrong
//! passwords/tampering. This file locks those properties in.
//!
//!   (a) NO SALT  → two backups of the same (seed, password) are byte-for-byte
//!       identical. An attacker who sees two backup files can tell they protect
//!       the same secret, and the keystream `SHA256(password)` is reusable
//!       across every backup made with that password (XOR keystream reuse).
//!
//!   (b) NO MAC   → importing with the WRONG password does NOT error. It
//!       silently returns a different 32-byte value that *looks* like a valid
//!       seed. A user restoring with a typo'd password gets a plausible-but-
//!       wrong wallet with zero indication of corruption.
//!
//! These are regressions against the historical XOR-with-SHA256(password)
//! format. A passing test means the old vulnerability did not return.

use dom_wallet::backup::{export_backup_file, import_backup_file, BackupError};
use tempfile::TempDir;

/// Same seed + same password must yield different backup bytes because the
/// format carries a fresh nonce.
#[test]
fn fix005_two_backups_same_seed_password_are_randomized() {
    let dir = TempDir::new().unwrap();
    let seed = [0x42u8; 32];
    let password = "correct horse battery staple";

    let path_a = dir.path().join("a.bin");
    let path_b = dir.path().join("b.bin");
    export_backup_file(&seed, password, &path_a).unwrap();
    export_backup_file(&seed, password, &path_b).unwrap();

    let bytes_a = std::fs::read(&path_a).unwrap();
    let bytes_b = std::fs::read(&path_b).unwrap();

    assert_ne!(
        bytes_a, bytes_b,
        "backups must be randomized; two exports of the same seed/password must differ"
    );
    assert!(
        bytes_a.len() > 32,
        "backup envelope must carry nonce/tag overhead"
    );
    assert!(
        bytes_b.len() > 32,
        "backup envelope must carry nonce/tag overhead"
    );
}

/// Learning one `(seed, backup)` pair must not decrypt another backup exported
/// under the same password.
#[test]
fn fix005_one_known_pair_does_not_decrypt_another_backup() {
    let dir = TempDir::new().unwrap();
    let password = "shared-password";
    let seed1 = [0x11u8; 32];
    let seed2 = [0x99u8; 32];

    let p1 = dir.path().join("s1.bin");
    let p2 = dir.path().join("s2.bin");
    export_backup_file(&seed1, password, &p1).unwrap();
    export_backup_file(&seed2, password, &p2).unwrap();

    let c1 = std::fs::read(&p1).unwrap();
    let c2 = std::fs::read(&p2).unwrap();
    assert_ne!(
        c1, c2,
        "fresh nonces must decorrelate backups under the same password"
    );
    assert_eq!(import_backup_file(&p2, password).unwrap(), seed2);
    assert_ne!(c1, seed1, "backup bytes must not expose the seed directly");
}

/// Wrong passwords must fail authentication.
#[test]
fn fix005_wrong_password_is_rejected() {
    let dir = TempDir::new().unwrap();
    let seed = [0xABu8; 32];
    let path = dir.path().join("backup.bin");
    export_backup_file(&seed, "real-password", &path).unwrap();

    let result = import_backup_file(&path, "wrong-password");
    assert!(matches!(result, Err(BackupError::AuthenticationFailed)));
}

/// Tampering with the ciphertext must fail authentication.
#[test]
fn fix005_tampered_backup_is_rejected() {
    let dir = TempDir::new().unwrap();
    let seed = [0x07u8; 32];
    let path = dir.path().join("backup.bin");
    export_backup_file(&seed, "pw-A", &path).unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&path, bytes).unwrap();

    let result = import_backup_file(&path, "pw-A");
    assert!(matches!(result, Err(BackupError::AuthenticationFailed)));
}
