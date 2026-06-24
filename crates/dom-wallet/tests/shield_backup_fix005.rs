//! dom-shield Onda 2 — FIX-005 reproducer for `dom_wallet::backup`.
//!
//! Subfamily: directed/KAV (Lens B funds-safety, transport-key hygiene).
//!
//! `export_backup_file` derives its key as `SHA256(password)` and XORs it
//! against the 32-byte seed. There is NO salt, NO AEAD, NO integrity tag.
//! This file proves the two structural weaknesses that follow from that:
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
//! These are CONFIRMATIONS of FIX-005, not new findings. The asserts encode
//! the *observed* (insecure) behaviour so the file compiles green; the
//! security expectation each one violates is documented inline. If the backup
//! format is later hardened (salt + AEAD), these tests will go RED and must be
//! rewritten to assert the fixed behaviour.

use dom_wallet::backup::{export_backup_file, import_backup_file};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// (a) NO SALT — same seed + same password ⇒ byte-identical ciphertext.
///
/// A salted/AEAD scheme would randomise the nonce per encryption, making two
/// backups of the same secret differ. Here they are identical, and equal to
/// the deterministic `seed XOR SHA256(password)`.
#[test]
fn fix005_two_backups_same_seed_password_are_byte_identical() {
    let dir = TempDir::new().unwrap();
    let seed = [0x42u8; 32];
    let password = "correct horse battery staple";

    let path_a = dir.path().join("a.bin");
    let path_b = dir.path().join("b.bin");
    export_backup_file(&seed, password, &path_a).unwrap();
    export_backup_file(&seed, password, &path_b).unwrap();

    let bytes_a = std::fs::read(&path_a).unwrap();
    let bytes_b = std::fs::read(&path_b).unwrap();

    // CONFIRMS FIX-005(a): no salt ⇒ deterministic, identical ciphertext.
    assert_eq!(
        bytes_a, bytes_b,
        "FIX-005: backups are deterministic (no salt) — a salted scheme would differ"
    );

    // The ciphertext is exactly seed XOR SHA256(password): there is no salt,
    // no nonce, no tag mixed in. Reconstruct the keystream and verify.
    let key: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    let mut expected = [0u8; 32];
    for i in 0..32 {
        expected[i] = seed[i] ^ key[i];
    }
    assert_eq!(
        bytes_a.as_slice(),
        &expected[..],
        "FIX-005: ciphertext is a pure XOR keystream of SHA256(password) — reusable & unsalted"
    );
    // File is exactly 32 bytes: no room for a salt or MAC.
    assert_eq!(bytes_a.len(), 32, "FIX-005: 32-byte file leaves no room for salt/MAC");
}

/// (a') XOR keystream reuse across DIFFERENT seeds with the same password.
///
/// Because the keystream is `SHA256(password)` regardless of the seed, an
/// attacker who learns one (seed, backup) pair recovers the keystream and can
/// decrypt ANY other backup made with the same password:
/// `seed2 = backup2 XOR (backup1 XOR seed1)`.
#[test]
fn fix005_keystream_reuse_recovers_other_seed_under_same_password() {
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

    // Attacker who knows (seed1, c1) recovers the keystream...
    let mut keystream = [0u8; 32];
    for i in 0..32 {
        keystream[i] = c1[i] ^ seed1[i];
    }
    // ...and decrypts c2 without ever knowing the password.
    let mut recovered_seed2 = [0u8; 32];
    for i in 0..32 {
        recovered_seed2[i] = c2[i] ^ keystream[i];
    }
    // CONFIRMS FIX-005(a): single-key XOR ⇒ keystream reuse breaks all backups.
    assert_eq!(
        recovered_seed2, seed2,
        "FIX-005: one leaked (seed,backup) pair decrypts every backup sharing the password"
    );
}

/// (b) NO MAC — wrong password decrypts to a different-but-valid-looking seed
/// with NO error raised.
#[test]
fn fix005_wrong_password_silently_yields_wrong_seed_no_error() {
    let dir = TempDir::new().unwrap();
    let seed = [0xABu8; 32];
    let path = dir.path().join("backup.bin");
    export_backup_file(&seed, "real-password", &path).unwrap();

    // Import with a wrong password. A MAC/AEAD would reject this.
    let result = import_backup_file(&path, "wrong-password");

    // CONFIRMS FIX-005(b): no integrity check ⇒ Ok with garbage, not Err.
    let recovered = result.expect("FIX-005: wrong password is NOT rejected (no MAC) — returns Ok");
    assert_ne!(
        recovered, seed,
        "FIX-005: wrong password yields a different seed, silently — caller cannot tell"
    );

    // The "wrong" seed is itself a perfectly well-formed 32-byte value
    // (it would be accepted as a seed by any downstream consumer): the wallet
    // layer has no way to know it is wrong from the import alone.
    assert_eq!(recovered.len(), 32);
}

/// (b') The wrong-password output is itself a deterministic XOR of the two
/// passwords' keystreams against the seed — fully predictable, no avalanche
/// integrity. Documents that the "error" is structurally absent.
#[test]
fn fix005_wrong_password_output_is_predictable_keystream_xor() {
    let dir = TempDir::new().unwrap();
    let seed = [0x07u8; 32];
    let path = dir.path().join("backup.bin");
    export_backup_file(&seed, "pw-A", &path).unwrap();

    let recovered = import_backup_file(&path, "pw-B").unwrap();

    let key_a: [u8; 32] = Sha256::digest(b"pw-A").into();
    let key_b: [u8; 32] = Sha256::digest(b"pw-B").into();
    let mut predicted = [0u8; 32];
    for i in 0..32 {
        // import = ciphertext XOR key_b = (seed XOR key_a) XOR key_b.
        predicted[i] = seed[i] ^ key_a[i] ^ key_b[i];
    }
    // CONFIRMS FIX-005(b): wrong-password output is a deterministic function,
    // never an error — there is no integrity gate anywhere in the path.
    assert_eq!(
        recovered, predicted,
        "FIX-005: wrong-password import is a predictable keystream XOR, not a rejection"
    );
}
