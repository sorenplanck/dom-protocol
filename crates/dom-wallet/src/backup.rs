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
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

const BACKUP_MAGIC: &[u8; 4] = b"DBK1";
const BACKUP_NONCE_LEN: usize = 12;

/// Errors that can occur during backup or restore operations.
#[derive(Debug, Error)]
pub enum BackupError {
    /// The mnemonic phrase is structurally invalid (wrong format).
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// An error from the underlying bip39 crate.
    #[error("bip39 error: {0}")]
    Bip39(String),

    /// I/O error while reading or writing a backup file.
    #[error("io error: {0}")]
    Io(String),

    /// Backup file is corrupted or has unexpected size.
    #[error("backup file corrupted (expected 32 bytes, got {0})")]
    Corrupted(usize),

    /// Backup authentication failed (wrong password or tampered file).
    #[error("backup authentication failed")]
    AuthenticationFailed,
}

impl From<bip39::Error> for BackupError {
    fn from(e: bip39::Error) -> Self {
        BackupError::Bip39(e.to_string())
    }
}

/// Generate a new random BIP-39 mnemonic (12 words, 128-bit entropy).
///
/// Uses the `bip39` crate's secure random generation. The mnemonic is
/// returned wrapped in `Zeroizing<String>` so the buffer is wiped from
/// memory when the caller drops it (Phase 2.5 secret memory hygiene).
///
/// # Errors
/// Returns [`BackupError::Bip39`] if random generation fails.
pub fn generate_mnemonic() -> Result<Zeroizing<String>, BackupError> {
    let mut rng = rand::thread_rng();
    let mnemonic = Mnemonic::generate_in_with(&mut rng, Language::English, 12)?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

/// Generate a mnemonic and derive the 32-byte seed (no passphrase).
///
/// Returns a tuple of (`mnemonic`, `seed`), each wrapped in `Zeroizing`
/// so the caller's secrets are wiped on drop (Phase 2.5). The seed is
/// the first 32 bytes of the BIP-39 64-byte seed.
///
/// # Errors
/// Returns [`BackupError::Bip39`] if random generation or derivation fails.
pub fn generate_with_seed() -> Result<(Zeroizing<String>, Zeroizing<[u8; 32]>), BackupError> {
    let mut rng = rand::thread_rng();
    let mnemonic = Mnemonic::generate_in_with(&mut rng, Language::English, 12)?;
    // Wrap the BIP-39 64-byte seed immediately so the high-32-byte
    // tail (which we discard) is also wiped on drop, not left
    // floating on the stack.
    let mut full_seed = Zeroizing::new(mnemonic.to_seed(""));

    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&full_seed[..32]);
    full_seed.fill(0);

    Ok((Zeroizing::new(mnemonic.to_string()), seed))
}

/// Restore a 32-byte seed from a BIP-39 mnemonic phrase.
///
/// Accepts standard BIP-39 phrases of 12, 15, 18, 21, or 24 words.
/// Optionally accepts a passphrase per the BIP-39 spec (empty string
/// for none). The returned seed is wrapped in `Zeroizing` (Phase 2.5).
///
/// # Arguments
/// * `phrase` - Space-separated mnemonic words from the BIP-39 English wordlist
/// * `passphrase` - Optional passphrase (BIP-39's "25th word" feature)
///
/// # Errors
/// Returns [`BackupError::Bip39`] if the phrase is invalid (bad checksum,
/// unknown words, wrong word count, etc).
pub fn import_mnemonic(phrase: &str, passphrase: &str) -> Result<Zeroizing<[u8; 32]>, BackupError> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase.trim())?;
    let mut full_seed = Zeroizing::new(mnemonic.to_seed(passphrase));

    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&full_seed[..32]);
    full_seed.fill(0);

    Ok(seed)
}

/// Convert a 16-byte entropy into a BIP-39 mnemonic phrase.
///
/// This is mostly useful for testing with known entropy values, or for
/// re-encoding entropy obtained from another source as a mnemonic.
///
/// For wallet creation, prefer [`generate_with_seed`] which uses secure
/// random generation directly.
///
/// # Errors
/// Returns [`BackupError::Bip39`] if entropy length is invalid for the
/// 12-word mnemonic format (must be exactly 16 bytes).
pub fn export_mnemonic_from_entropy(
    entropy_16_bytes: &[u8; 16],
) -> Result<Zeroizing<String>, BackupError> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy_16_bytes)?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

/// Recover the raw 16-byte entropy from a 12-word mnemonic phrase.
///
/// This is the inverse of [`export_mnemonic_from_entropy`]. Note that the
/// entropy is NOT the same as the seed: the seed requires PBKDF2 derivation
/// from the mnemonic phrase.
///
/// # Errors
/// Returns [`BackupError::Bip39`] if the phrase is invalid, or
/// [`BackupError::InvalidMnemonic`] if entropy is not exactly 16 bytes
/// (i.e., the mnemonic is not a standard 12-word phrase).
pub fn entropy_from_mnemonic(phrase: &str) -> Result<Zeroizing<[u8; 16]>, BackupError> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase.trim())?;
    let entropy = mnemonic.to_entropy();

    if entropy.len() != 16 {
        return Err(BackupError::InvalidMnemonic(format!(
            "expected 16 bytes entropy, got {}",
            entropy.len()
        )));
    }

    let mut result = Zeroizing::new([0u8; 16]);
    result.copy_from_slice(&entropy);
    Ok(result)
}

/// Export a 32-byte seed to a password-encrypted backup file.
///
/// Uses an authenticated ChaCha20Poly1305 envelope derived from SHA256(password).
/// Wrong passwords and tampering are rejected instead of silently producing a
/// different seed.
///
/// # Arguments
/// * `seed` - The 32-byte wallet seed to back up
/// * `password` - Password used to derive the XOR key via SHA256
/// * `output_path` - File path where the encrypted backup will be written
///
/// # Errors
/// Returns [`BackupError::Io`] if the file cannot be written.
pub fn export_backup_file(
    seed: &[u8; 32],
    password: &str,
    output_path: &Path,
) -> Result<(), BackupError> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key: [u8; 32] = hasher.finalize().into();
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key).map_err(|_| BackupError::AuthenticationFailed)?;
    let nonce_bytes: [u8; BACKUP_NONCE_LEN] = rand::random();
    let nonce: Nonce = nonce_bytes.into();
    let ciphertext = cipher
        .encrypt(&nonce, seed.as_slice())
        .map_err(|_| BackupError::AuthenticationFailed)?;

    let mut envelope = Vec::with_capacity(BACKUP_MAGIC.len() + BACKUP_NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(BACKUP_MAGIC);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    std::fs::write(output_path, envelope).map_err(|e| BackupError::Io(e.to_string()))?;
    Ok(())
}

/// Import a 32-byte seed from a password-encrypted backup file.
///
/// Inverse of [`export_backup_file`]. Wrong passwords and tampering fail
/// authentication instead of yielding a garbage seed.
///
/// # Errors
/// Returns [`BackupError::Io`] if the file cannot be read, or
/// [`BackupError::Corrupted`] if the file size is not 32 bytes.
pub fn import_backup_file(backup_path: &Path, password: &str) -> Result<[u8; 32], BackupError> {
    let encrypted = std::fs::read(backup_path).map_err(|e| BackupError::Io(e.to_string()))?;
    if encrypted.len() < BACKUP_MAGIC.len() + BACKUP_NONCE_LEN + 16 {
        return Err(BackupError::Corrupted(encrypted.len()));
    }
    if &encrypted[..BACKUP_MAGIC.len()] != BACKUP_MAGIC {
        return Err(BackupError::Corrupted(encrypted.len()));
    }

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key: [u8; 32] = hasher.finalize().into();
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key).map_err(|_| BackupError::AuthenticationFailed)?;
    let nonce_bytes: [u8; BACKUP_NONCE_LEN] = encrypted
        [BACKUP_MAGIC.len()..BACKUP_MAGIC.len() + BACKUP_NONCE_LEN]
        .try_into()
        .map_err(|_| BackupError::Corrupted(encrypted.len()))?;
    let nonce: Nonce = nonce_bytes.into();
    let plaintext = cipher
        .decrypt(&nonce, &encrypted[BACKUP_MAGIC.len() + BACKUP_NONCE_LEN..])
        .map_err(|_| BackupError::AuthenticationFailed)?;
    if plaintext.len() != 32 {
        return Err(BackupError::Corrupted(plaintext.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);
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
        assert!(seed.iter().any(|&b| b != 0));
    }

    #[test]
    fn import_known_mnemonic_works() {
        let phrase = "abandon abandon abandon abandon abandon abandon                       abandon abandon abandon abandon abandon about";
        let seed = import_mnemonic(phrase, "").unwrap();
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
        assert_ne!(seed_no_pass, seed_with_pass);
    }

    #[test]
    fn entropy_roundtrip() {
        let entropy = [0x42u8; 16];
        let mnemonic = export_mnemonic_from_entropy(&entropy).unwrap();
        let recovered = entropy_from_mnemonic(&mnemonic).unwrap();
        assert_eq!(entropy, *recovered);
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
    fn wrong_password_is_rejected() {
        let seed = [0xAAu8; 32];
        let temp = std::env::temp_dir().join("test_dom_bip39_wrong.bin");
        let _ = std::fs::remove_file(&temp);

        export_backup_file(&seed, "correct", &temp).unwrap();
        let err = import_backup_file(&temp, "wrong").unwrap_err();

        assert!(matches!(err, BackupError::AuthenticationFailed));
        let _ = std::fs::remove_file(&temp);
    }

    #[test]
    fn mnemonic_words_are_from_standard_wordlist() {
        let phrase = "abandon abandon abandon abandon abandon abandon                       abandon abandon abandon abandon abandon about";
        assert!(import_mnemonic(phrase, "").is_ok());
    }
}
