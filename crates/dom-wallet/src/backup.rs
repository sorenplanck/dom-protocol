//! Wallet backup and restore using standard BIP-39.
//!
//! Uses the `bip39` crate from rust-bitcoin for full BIP-39 compliance:
//! - 2048-word standard English wordlist
//! - PBKDF2-HMAC-SHA512 key derivation (2048 iterations)
//! - 128-bit entropy with 4-bit checksum (12-word mnemonic)
//! - Compatible with Ledger, Trezor, Electrum, and other BIP-39 wallets
//!
//! Also provides simple password-encrypted backup files for full seed export.

use bip39::{Language, Mnemonic};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("bip39 error: {0}")]
    Bip39(String),

    #[error("io error: {0}")]
    Io(String),

    #[error("backup file corrupted (expected 32 bytes, got {0})")]
    Corrupted(usize),
}

impl From<bip39::Error> for BackupError {
    fn from(e: bip39::Error) -> Self {
        BackupError::Bip39(e.to_string())
    }
}

/// Generate a new random BIP-39 mnemonic (12 words, 128-bit entropy).
///
/// This uses bip39 crate's secure random generation. Returns the mnemonic
/// as a space-separated string ready for display to the user.
pub fn generate_mnemonic() -> Result<String, BackupError> {
    let mut rng = rand::thread_rng();
    let mnemonic = Mnemonic::generate_in_with(&mut rng, Language::English, 12)?;
    Ok(mnemonic.to_string())
}

/// Generate mnemonic and derive 32-byte seed (no passphrase).
///
/// Returns (mnemonic_string, seed_32_bytes).
pub fn generate_with_seed() -> Result<(String, [u8; 32]), BackupError> {
    let mut rng = rand::thread_rng();
    let mnemonic = Mnemonic::generate_in_with(&mut rng, Language::English, 12)?;
    let full_seed = mnemonic.to_seed("");

    // BIP-39 seed is 64 bytes; we use first 32 for our wallet
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&full_seed[..32]);

    Ok((mnemonic.to_string(), seed))
}

/// Restore a 32-byte seed from a BIP-39 mnemonic phrase.
///
/// Accepts standard BIP-39 phrases (12, 15, 18, 21, or 24 words).
/// Optional passphrase support per BIP-39 spec.
pub fn import_mnemonic(phrase: &str, passphrase: &str) -> Result<[u8; 32], BackupError> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase.trim())?;
    let full_seed = mnemonic.to_seed(passphrase);

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&full_seed[..32]);

    Ok(seed)
}

/// Convert a 32-byte seed into a mnemonic phrase.
///
/// NOTE: This is only useful for testing/debugging because the BIP-39
/// derivation is one-way (PBKDF2 with high iteration count). In practice,
/// you SHOULD store the mnemonic at generation time and never try to
/// recover it from a seed.
///
/// For wallet backup, use `generate_with_seed()` or `export_backup_file()`.
pub fn export_mnemonic_from_entropy(entropy_16_bytes: &[u8; 16]) -> Result<String, BackupError> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy_16_bytes)?;
    Ok(mnemonic.to_string())
}

/// Recover entropy from mnemonic (inverse of export_mnemonic_from_entropy).
pub fn entropy_from_mnemonic(phrase: &str) -> Result<[u8; 16], BackupError> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase.trim())?;
    let entropy = mnemonic.to_entropy();

    if entropy.len() != 16 {
        return Err(BackupError::InvalidMnemonic(format!(
            "expected 16 bytes entropy, got {}",
            entropy.len()
        )));
    }

    let mut result = [0u8; 16];
    result.copy_from_slice(&entropy);
    Ok(result)
}

/// Export full 32-byte seed to a password-encrypted backup file.
///
/// Uses simple XOR with SHA256(password) for transport encryption.
/// The wallet itself uses ChaCha20Poly1305 (see dom-wallet::store).
pub fn export_backup_file(
    seed: &[u8; 32],
    password: &str,
    output_path: &Path,
) -> Result<(), BackupError> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key: [u8; 32] = hasher.finalize().into();

    let mut encrypted = [0u8; 32];
    for i in 0..32 {
        encrypted[i] = seed[i] ^ key[i];
    }

    std::fs::write(output_path, encrypted).map_err(|e| BackupError::Io(e.to_string()))?;
    Ok(())
}

/// Import seed from password-encrypted backup file.
pub fn import_backup_file(backup_path: &Path, password: &str) -> Result<[u8; 32], BackupError> {
    let encrypted = std::fs::read(backup_path).map_err(|e| BackupError::Io(e.to_string()))?;
    if encrypted.len() != 32 {
        return Err(BackupError::Corrupted(encrypted.len()));
    }

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key: [u8; 32] = hasher.finalize().into();

    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = encrypted[i] ^ key[i];
    }
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_mnemonic_returns_12_words() {
        let mnemonic = generate_mnemonic().unwrap();
        let word_count = mnemonic.split_whitespace().count();
        assert_eq!(word_count, 12, "expected 12-word mnemonic");
    }

    #[test]
    fn generate_with_seed_works() {
        let (mnemonic, seed) = generate_with_seed().unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 12);
        // Seed should not be all zeros
        assert!(seed.iter().any(|&b| b != 0));
    }

    #[test]
    fn import_known_mnemonic_works() {
        // BIP-39 standard test vector
        let phrase = "abandon abandon abandon abandon abandon abandon                       abandon abandon abandon abandon abandon about";
        let seed = import_mnemonic(phrase, "").unwrap();
        // Seed should be deterministic
        let seed2 = import_mnemonic(phrase, "").unwrap();
        assert_eq!(seed, seed2);
    }

    #[test]
    fn invalid_mnemonic_rejected() {
        let phrase = "not a real mnemonic phrase at all here folks";
        assert!(import_mnemonic(phrase, "").is_err());
    }

    #[test]
    fn passphrase_changes_seed() {
        let phrase = "abandon abandon abandon abandon abandon abandon                       abandon abandon abandon abandon abandon about";
        let seed_no_pass = import_mnemonic(phrase, "").unwrap();
        let seed_with_pass = import_mnemonic(phrase, "TREZOR").unwrap();
        assert_ne!(seed_no_pass, seed_with_pass, "passphrase must change seed");
    }

    #[test]
    fn entropy_roundtrip() {
        let entropy = [0x42u8; 16];
        let mnemonic = export_mnemonic_from_entropy(&entropy).unwrap();
        let recovered = entropy_from_mnemonic(&mnemonic).unwrap();
        assert_eq!(entropy, recovered);
    }

    #[test]
    fn backup_file_roundtrip() {
        let seed = [0x99u8; 32];
        let temp = std::env::temp_dir().join("test_dom_bip39_backup.bin");
        let _ = std::fs::remove_file(&temp);

        export_backup_file(&seed, "mypassword", &temp).unwrap();
        let restored = import_backup_file(&temp, "mypassword").unwrap();

        assert_eq!(seed, restored);
        let _ = std::fs::remove_file(&temp);
    }

    #[test]
    fn wrong_password_gives_different_seed() {
        let seed = [0xAAu8; 32];
        let temp = std::env::temp_dir().join("test_dom_bip39_wrong.bin");
        let _ = std::fs::remove_file(&temp);

        export_backup_file(&seed, "correct", &temp).unwrap();
        let restored = import_backup_file(&temp, "wrong").unwrap();

        assert_ne!(seed, restored);
        let _ = std::fs::remove_file(&temp);
    }

    #[test]
    fn mnemonic_words_are_from_standard_wordlist() {
        // Verify we use real BIP-39 wordlist (first word indicator)
        let phrase = "abandon abandon abandon abandon abandon abandon                       abandon abandon abandon abandon abandon about";
        // This phrase only validates against the OFFICIAL BIP-39 list
        assert!(import_mnemonic(phrase, "").is_ok());
    }
}
