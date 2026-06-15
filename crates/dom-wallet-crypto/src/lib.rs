//! Shared wallet at-rest crypto: the encrypted file envelope and its key
//! derivation, extracted from `dom-wallet` v1 so that v1 and `dom-wallet2` (v2)
//! share **one audited source** instead of two diverging copies.
//!
//! This crate owns the bytes a wallet writes to disk — the file that holds the
//! blinding factors, the most sensitive secrets in the system. It contains no
//! wallet logic: only the KDF and the generic, versioned, atomically-written
//! AEAD envelope.
//!
//! ## On-disk format (unchanged from v1)
//! ```text
//! Header (64 bytes):
//!   magic    14 bytes        # caller-supplied (e.g. "DOM-WALLET-V1\0")
//!   version  u16 little-endian
//!   salt     32 bytes        # fresh per save
//!   nonce    12 bytes        # fresh per save
//!   pad       4 bytes        # zero
//! Payload: ChaCha20Poly1305( JSON(value), key = Argon2id+HKDF(password, salt) )
//! ```
//!
//! ## Key derivation
//! Argon2id (OWASP 2025 baseline: m = 64 MiB, t = 3, p = 1) → HKDF-SHA256 with
//! `info = "DOM:wallet-key:v1"`. The salt is the per-save 32-byte random value
//! from the header, so every save re-derives the key under a fresh salt.
//!
//! ## Durability (DOM-SEC-007)
//! Writes are atomic: temp file → `sync_all` → rename → parent-dir `sync_all`
//! (Unix). After a successful return the file survives crash / power loss.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::Sha256;
use std::fs;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

/// HKDF domain-separation info for the post-Argon2 stretch.
///
/// MUST NOT change without a wallet format-version bump — any alteration
/// silently invalidates all existing wallets.
const HKDF_INFO: &[u8] = b"DOM:wallet-key:v1";

/// Length of the magic field in the header.
pub const MAGIC_LEN: usize = 14;
/// Total header length in bytes.
pub const HEADER_SIZE: usize = 64;
/// Salt length in bytes.
pub const SALT_SIZE: usize = 32;
/// AEAD nonce length in bytes.
pub const NONCE_SIZE: usize = 12;

/// Errors from the key derivation and the file envelope.
#[derive(Debug, Error)]
pub enum EnvelopeError {
    /// Key derivation (Argon2id / HKDF) failed.
    #[error("key derivation failed: {0}")]
    Kdf(String),
    /// AEAD encryption failed.
    #[error("encryption failed")]
    Encryption,
    /// AEAD decryption failed (wrong password or tampered file).
    #[error("decryption failed")]
    Decryption,
    /// Payload (de)serialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),
    /// Filesystem error.
    #[error("io error: {0}")]
    Io(String),
    /// File is shorter than the fixed header.
    #[error("file too short")]
    FileTooShort,
    /// The magic bytes did not match the expected value.
    #[error("invalid file magic")]
    BadMagic,
    /// The on-disk version is not the expected one. An unknown version is
    /// **rejected**, never reinterpreted.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u16),
}

/// Argon2id parameters.
///
/// Pinning these as constants makes any change a deliberate, visible
/// wallet-format break instead of an accidental drift via dependency upgrades.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Time cost (number of iterations).
    pub t_cost: u32,
    /// Parallelism factor.
    pub parallelism: u32,
}

impl KdfParams {
    /// OWASP-recommended Argon2id baseline (2025): m = 64 MiB, t = 3, p = 1.
    pub const OWASP_V1: Self = Self {
        m_cost_kib: 65536,
        t_cost: 3,
        parallelism: 1,
    };
}

/// A wallet's symmetric encryption key (32 bytes).
///
/// The inner buffer is wrapped in [`Zeroizing`] so it is wiped from memory on
/// drop. The type is opaque: there is no public way to extract the raw bytes —
/// only the crate-private [`WalletKey::as_bytes`], consumed by the envelope in
/// a narrow scope.
pub struct WalletKey(Zeroizing<[u8; 32]>);

impl WalletKey {
    /// Construct from raw bytes. Crate-private — only the canonical KDF below
    /// may mint a key.
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the raw key bytes. Crate-private to limit the surface over which
    /// raw key material can be observed.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive the wallet encryption key from a password and per-wallet salt.
///
/// 1. **Argon2id stretch** (memory-hard; salt is the per-save 32-byte random).
/// 2. **HKDF-SHA256 expand** with `info = "DOM:wallet-key:v1"` to
///    domain-separate the final key.
///
/// The output is a 32-byte key suitable for use with `ChaCha20Poly1305`.
pub fn derive_wallet_key(
    password: &str,
    salt: &[u8; 32],
    params: &KdfParams,
) -> Result<WalletKey, EnvelopeError> {
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| EnvelopeError::Kdf(format!("Argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut stretched = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut stretched[..])
        .map_err(|e| EnvelopeError::Kdf(format!("Argon2id failed: {e}")))?;

    let hkdf = Hkdf::<Sha256>::new(Some(&salt[..]), &stretched[..]);
    let mut key_bytes = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut key_bytes)
        .map_err(|_| EnvelopeError::Kdf("HKDF expansion failed".into()))?;

    Ok(WalletKey::from_bytes(key_bytes))
}

/// Encrypt `value` and write it to `path` as a versioned envelope, atomically.
///
/// A fresh random salt and nonce are generated on every call. The on-disk
/// layout is byte-identical to v1's `save_wallet`.
pub fn save_envelope<T: Serialize>(
    path: &Path,
    magic: &[u8; MAGIC_LEN],
    version: u16,
    value: &T,
    password: &str,
) -> Result<(), EnvelopeError> {
    // Fresh salt + nonce for this save.
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key = derive_wallet_key(password, &salt, &KdfParams::OWASP_V1)?;

    let json =
        serde_json::to_vec(value).map_err(|e| EnvelopeError::Serialization(e.to_string()))?;

    // `from_slice` is deprecated in favor of generic-array 1.x; the audited v1
    // envelope pins generic-array 0.x, so we keep the same call (matches v1).
    #[allow(deprecated)]
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, json.as_slice())
        .map_err(|_| EnvelopeError::Encryption)?;

    // Build the 64-byte header.
    let mut header = [0u8; HEADER_SIZE];
    header[0..MAGIC_LEN].copy_from_slice(magic);
    header[14..16].copy_from_slice(&version.to_le_bytes());
    header[16..48].copy_from_slice(&salt);
    header[48..60].copy_from_slice(&nonce_bytes);
    // bytes 60..64 = padding (zero)

    let mut file_bytes = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    file_bytes.extend_from_slice(&header);
    file_bytes.extend_from_slice(&ciphertext);

    atomic_write(path, &file_bytes)
}

/// Read, verify and decrypt an envelope previously written by [`save_envelope`].
///
/// Verifies the magic and version **before** decrypting. An unknown version is
/// rejected with [`EnvelopeError::UnsupportedVersion`], never reinterpreted.
/// A wrong password or a tampered file fails with [`EnvelopeError::Decryption`].
pub fn load_envelope<T: DeserializeOwned>(
    path: &Path,
    expected_magic: &[u8; MAGIC_LEN],
    expected_version: u16,
    password: &str,
) -> Result<T, EnvelopeError> {
    let data =
        fs::read(path).map_err(|e| EnvelopeError::Io(format!("failed to read file: {e}")))?;

    if data.len() < HEADER_SIZE {
        return Err(EnvelopeError::FileTooShort);
    }
    if &data[0..MAGIC_LEN] != expected_magic {
        return Err(EnvelopeError::BadMagic);
    }
    let version = u16::from_le_bytes([data[14], data[15]]);
    if version != expected_version {
        return Err(EnvelopeError::UnsupportedVersion(version));
    }

    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&data[16..48]);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes.copy_from_slice(&data[48..60]);

    let key = derive_wallet_key(password, &salt, &KdfParams::OWASP_V1)?;
    #[allow(deprecated)]
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, &data[HEADER_SIZE..])
        .map_err(|_| EnvelopeError::Decryption)?;

    serde_json::from_slice(&plaintext).map_err(|e| EnvelopeError::Serialization(e.to_string()))
}

/// Atomic write with fsync (DOM-SEC-007): temp file → `sync_all` → rename →
/// parent-dir `sync_all` (Unix). After `Ok`, the file survives a crash.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), EnvelopeError> {
    let temp_path = path.with_extension("tmp");

    // Step 1+2: write and fsync the temp file.
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&temp_path)
            .map_err(|e| EnvelopeError::Io(format!("failed to create temp file: {e}")))?;
        f.write_all(bytes)
            .map_err(|e| EnvelopeError::Io(format!("failed to write temp file: {e}")))?;
        f.sync_all()
            .map_err(|e| EnvelopeError::Io(format!("failed to fsync temp file: {e}")))?;
        // f is dropped (closed) here.
    }

    // Step 3: atomic rename.
    fs::rename(&temp_path, path)
        .map_err(|e| EnvelopeError::Io(format!("failed to rename file atomically: {e}")))?;

    // Step 4: fsync the parent directory so the rename is durable.
    //
    // Windows: NTFS's MoveFileEx (used by std::fs::rename) is durable by
    // contract and a directory handle cannot be fsync'd; we rely on the rename.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let dir = std::fs::File::open(parent).map_err(|e| {
                EnvelopeError::Io(format!("failed to open parent dir for fsync: {e}"))
            })?;
            dir.sync_all()
                .map_err(|e| EnvelopeError::Io(format!("failed to fsync parent dir: {e}")))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    // ── KDF (moved verbatim from dom-wallet/src/unlock.rs) ──────────────────

    #[test]
    fn derive_wallet_key_is_deterministic() {
        let password = "correct horse battery staple";
        let salt = [0x42u8; 32];
        let a = derive_wallet_key(password, &salt, &KdfParams::OWASP_V1).unwrap();
        let b = derive_wallet_key(password, &salt, &KdfParams::OWASP_V1).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn derive_wallet_key_differs_per_password() {
        let salt = [0x42u8; 32];
        let a = derive_wallet_key("password_a", &salt, &KdfParams::OWASP_V1).unwrap();
        let b = derive_wallet_key("password_b", &salt, &KdfParams::OWASP_V1).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn derive_wallet_key_differs_per_salt() {
        let pw = "password";
        let salt_a = [0x01u8; 32];
        let salt_b = [0x02u8; 32];
        let a = derive_wallet_key(pw, &salt_a, &KdfParams::OWASP_V1).unwrap();
        let b = derive_wallet_key(pw, &salt_b, &KdfParams::OWASP_V1).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// Changing KDF params (even by one parameter) MUST produce a different key.
    #[test]
    fn derive_wallet_key_differs_per_params() {
        let pw = "password";
        let salt = [0x42u8; 32];
        let weaker = KdfParams {
            m_cost_kib: 8192,
            t_cost: 1,
            parallelism: 1,
        };
        let a = derive_wallet_key(pw, &salt, &KdfParams::OWASP_V1).unwrap();
        let b = derive_wallet_key(pw, &salt, &weaker).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// OWASP_V1 constants are pinned and must not drift accidentally.
    #[test]
    fn owasp_v1_params_pinned() {
        assert_eq!(KdfParams::OWASP_V1.m_cost_kib, 65536);
        assert_eq!(KdfParams::OWASP_V1.t_cost, 3);
        assert_eq!(KdfParams::OWASP_V1.parallelism, 1);
    }

    /// Re-deriving across (simulated) lock cycles is bit-identical. Adapted from
    /// the v1 `lock_unlock_cycle_is_deterministic` test, whose `UnlockedSession`
    /// ceremony stays in dom-wallet; the KDF-determinism intent is preserved
    /// here, where the raw key bytes are observable.
    #[test]
    fn derive_wallet_key_stable_across_cycles() {
        let salt = [0x33u8; 32];
        let password = "pa55w0rd";
        let key_1 = *derive_wallet_key(password, &salt, &KdfParams::OWASP_V1)
            .unwrap()
            .as_bytes();
        let key_2 = *derive_wallet_key(password, &salt, &KdfParams::OWASP_V1)
            .unwrap()
            .as_bytes();
        assert_eq!(key_1, key_2);
    }

    /// Two distinct passwords MUST produce distinct keys (wrong-password
    /// rejection relies on the AEAD key mismatch).
    #[test]
    fn wrong_password_yields_different_key() {
        let salt = [0x55u8; 32];
        let right = derive_wallet_key("correct", &salt, &KdfParams::OWASP_V1).unwrap();
        let wrong = derive_wallet_key("c0rrect", &salt, &KdfParams::OWASP_V1).unwrap();
        assert_ne!(right.as_bytes(), wrong.as_bytes());
    }

    // ── Envelope round-trip and rejections ──────────────────────────────────

    const TEST_MAGIC: &[u8; MAGIC_LEN] = b"DOM-TEST-ENV\0\0";

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Payload {
        a: u32,
        b: String,
        secret: Vec<u8>,
    }

    fn sample() -> Payload {
        Payload {
            a: 7,
            b: "hello".into(),
            secret: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn envelope_round_trips() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("env.dat");
        save_envelope(&path, TEST_MAGIC, 1, &sample(), "pw").unwrap();
        let back: Payload = load_envelope(&path, TEST_MAGIC, 1, "pw").unwrap();
        assert_eq!(back, sample());
    }

    #[test]
    fn wrong_password_is_decryption_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("env.dat");
        save_envelope(&path, TEST_MAGIC, 1, &sample(), "pw").unwrap();
        let err = load_envelope::<Payload>(&path, TEST_MAGIC, 1, "wrong").unwrap_err();
        assert!(matches!(err, EnvelopeError::Decryption), "got {err:?}");
    }

    #[test]
    fn tampered_ciphertext_is_decryption_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("env.dat");
        save_envelope(&path, TEST_MAGIC, 1, &sample(), "pw").unwrap();
        let mut data = std::fs::read(&path).unwrap();
        let n = data.len();
        data[n - 8] ^= 0xFF; // flip a byte inside the ciphertext
        std::fs::write(&path, &data).unwrap();
        let err = load_envelope::<Payload>(&path, TEST_MAGIC, 1, "pw").unwrap_err();
        assert!(matches!(err, EnvelopeError::Decryption), "got {err:?}");
    }

    #[test]
    fn bad_magic_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("env.dat");
        save_envelope(&path, TEST_MAGIC, 1, &sample(), "pw").unwrap();
        let other_magic = b"DOM-OTHER-ENV\0";
        let err = load_envelope::<Payload>(&path, other_magic, 1, "pw").unwrap_err();
        assert!(matches!(err, EnvelopeError::BadMagic), "got {err:?}");
    }

    #[test]
    fn unknown_version_is_rejected_not_reinterpreted() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("env.dat");
        save_envelope(&path, TEST_MAGIC, 1, &sample(), "pw").unwrap();
        let err = load_envelope::<Payload>(&path, TEST_MAGIC, 2, "pw").unwrap_err();
        assert!(
            matches!(err, EnvelopeError::UnsupportedVersion(1)),
            "got {err:?}"
        );
    }

    #[test]
    fn too_short_file_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("env.dat");
        std::fs::write(&path, [0u8; 10]).unwrap();
        let err = load_envelope::<Payload>(&path, TEST_MAGIC, 1, "pw").unwrap_err();
        assert!(matches!(err, EnvelopeError::FileTooShort), "got {err:?}");
    }
}
