//! Persistent encrypted wallet storage using ChaCha20Poly1305.
//!
//! File format:
//! - Header (64 bytes):
//!   - Magic: "DOM-WALLET-V1\0" (14 bytes)
//!   - Version: u16 LE (2 bytes)
//!   - Salt (32 bytes)
//!   - Nonce (12 bytes)
//!   - Padding (2 bytes)
//! - Encrypted payload (JSON-encoded WalletState)
mod serde_commitment_vec {
    use serde::{de::SeqAccess, de::Visitor, ser::SerializeSeq, Deserializer, Serializer};
    use std::fmt;
    pub fn serialize<S>(v: &Vec<[u8; 33]>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for item in v {
            seq.serialize_element(&item[..])?;
        }
        seq.end()
    }
    pub fn deserialize<'de, D>(d: D) -> Result<Vec<[u8; 33]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Vec<[u8; 33]>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "seq of 33-byte arrays")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = a.next_element::<Vec<u8>>()? {
                    if b.len() != 33 {
                        return Err(serde::de::Error::custom("expected 33 bytes"));
                    }
                    let mut arr = [0u8; 33];
                    arr.copy_from_slice(&b);
                    out.push(arr);
                }
                Ok(out)
            }
        }
        d.deserialize_seq(V)
    }
}

use crate::types::{Network, OwnedOutput, WalletError};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::debug;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"DOM-WALLET-V1\0";
const VERSION: u16 = 1;
const HEADER_SIZE: usize = 64;
const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const HKDF_INFO: &[u8] = b"DOM:wallet-key:v1";

/// Serializable wallet state (the encrypted payload).
/// Custom serializer for HashMap<[u8; 32], PendingTx>
/// JSON requires string keys, so we hex-encode the byte arrays.
mod serde_pending_txs_map {
    use super::*;
    use serde::{de::Visitor, ser::SerializeMap, Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S>(
        map: &HashMap<[u8; 32], PendingTx>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser_map = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            let hex_key = hex::encode(k);
            ser_map.serialize_entry(&hex_key, v)?;
        }
        ser_map.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<[u8; 32], PendingTx>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MapVisitor;

        impl<'de> Visitor<'de> for MapVisitor {
            type Value = HashMap<[u8; 32], PendingTx>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map with hex string keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut result = HashMap::new();
                while let Some((hex_key, value)) = map.next_entry::<String, PendingTx>()? {
                    let bytes = hex::decode(&hex_key)
                        .map_err(|e| serde::de::Error::custom(format!("invalid hex: {}", e)))?;
                    if bytes.len() != 32 {
                        return Err(serde::de::Error::custom("key must be 32 bytes"));
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    result.insert(key, value);
                }
                Ok(result)
            }
        }

        deserializer.deserialize_map(MapVisitor)
    }
}

#[derive(Serialize, Deserialize)]
/// Serializable wallet state (encrypted payload).
pub struct WalletState {
    /// Network identifier.
    pub network: Network,
    /// Chain identifier (derived from network magic + genesis hash).
    pub chain_id: [u8; 32],
    /// All wallet-owned outputs (spent and unspent).
    pub outputs: Vec<OwnedOutput>,
    /// In-flight transactions awaiting confirmation.
    #[serde(with = "serde_pending_txs_map")]
    pub pending_txs: HashMap<[u8; 32], PendingTx>,
}

/// A transaction pending confirmation.
#[derive(Serialize, Deserialize, Clone)]
pub struct PendingTx {
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Commitments of inputs being spent by this transaction.
    #[serde(with = "serde_commitment_vec")]
    pub inputs: Vec<[u8; 33]>,
}

/// Derive encryption key from password using HKDF-SHA256.
/// ⚠️  CRITICAL SECURITY LIMITATION — TESTNET/DEV ONLY
///
/// Uses HKDF-SHA256, which is INADEQUATE for password-based KDF.
/// HKDF is designed for high-entropy inputs (e.g., ECDH shared secrets),
/// NOT for low-entropy passwords. It provides NO protection against
/// GPU brute-force: a consumer GPU can test ~500M passwords/sec.
///
/// An 8-character password is brute-forced in minutes offline.
/// Any captured .wallet file is effectively cleartext.
///
/// DO NOT USE THIS WALLET FOR REAL FUNDS.
///
/// Derives the wallet encryption key from a password using Argon2id.
///
/// Parameters: m=65536 KiB (64 MiB), t=3, p=1 — OWASP recommended.
/// The stretched key is then domain-separated via HKDF-SHA256 with
/// info=`"DOM:wallet-key:v1"`.
/// The salt is the per-wallet 32-byte random salt from the file header.
pub(crate) fn derive_key(
    password: &str,
    salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    // Argon2id — OWASP recommended: m=65536 KiB (64 MiB), t=3, p=1.
    // Salt is the per-wallet 32-byte random salt from the file header.
    // Output is tagged with HKDF_INFO for domain separation after stretching.
    let params = Params::new(65536, 3, 1, Some(32))
        .map_err(|e| WalletError::Crypto(format!("Argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut stretched = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut stretched[..])
        .map_err(|e| WalletError::Crypto(format!("Argon2id failed: {e}")))?;
    // Domain-separate the stretched key with HKDF.
    let hkdf = Hkdf::<Sha256>::new(Some(&salt[..]), &stretched[..]);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(HKDF_INFO, &mut key[..])
        .map_err(|_| WalletError::Crypto("HKDF expansion failed".into()))?;
    Ok(key)
}

/// Save wallet state to encrypted file with atomic write.
///
/// Format on disk: 64-byte header (magic, version, salt, nonce) + ciphertext.
///
/// The write is atomic: data is first written to `<path>.tmp` then renamed.
/// A new random salt and nonce are generated on every call.
pub fn save_wallet(path: &Path, state: &WalletState, password: &str) -> Result<(), WalletError> {
    // Generate fresh random salt for this save (re-derives key).
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);

    // Derive encryption key from password + salt.
    let key = derive_key(password, &salt)?;

    // Generate fresh random nonce for this encryption.
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Serialize state to JSON.
    let json = serde_json::to_vec(state).map_err(|e| WalletError::Serialization(e.to_string()))?;

    // Encrypt payload.
    #[allow(deprecated)]
    let cipher_key = Key::from_slice(&key[..]);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, json.as_slice())
        .map_err(|_| WalletError::Encryption)?;

    // Build 64-byte header.
    let mut header = [0u8; HEADER_SIZE];
    header[0..14].copy_from_slice(MAGIC);
    header[14..16].copy_from_slice(&VERSION.to_le_bytes());
    header[16..48].copy_from_slice(&salt);
    header[48..60].copy_from_slice(&nonce_bytes);
    // bytes 60..64 = padding (zero)

    // Assemble final file content.
    let mut file_bytes = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    file_bytes.extend_from_slice(&header);
    file_bytes.extend_from_slice(&ciphertext);

    // Atomic write with fsync (DOM-SEC-007 fix).
    //
    // 4-step durability guarantee:
    //   1. Write to <path>.tmp
    //   2. sync_all() on temp file (data + metadata flushed to disk)
    //   3. Atomic rename to final path
    //   4. sync_all() on parent directory (rename durably recorded)
    //
    // After this returns Ok, the wallet survives any crash (power loss,
    // kernel panic, SIGKILL).
    let temp_path = path.with_extension("tmp");

    // Step 1+2: Write and fsync the file
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&temp_path)
            .map_err(|e| WalletError::Io(format!("failed to create wallet temp file: {}", e)))?;
        f.write_all(&file_bytes)
            .map_err(|e| WalletError::Io(format!("failed to write wallet temp file: {}", e)))?;
        f.sync_all()
            .map_err(|e| WalletError::Io(format!("failed to fsync wallet temp file: {}", e)))?;
        // f is dropped (closed) here
    }

    // Step 3: Atomic rename
    fs::rename(&temp_path, path)
        .map_err(|e| WalletError::Io(format!("failed to rename wallet file atomically: {}", e)))?;

    // Step 4: fsync parent directory (ensures rename is durable).
    //
    // Unix: open the directory and sync_all() to flush the rename to disk.
    // Windows: NTFS's MoveFileEx (used by std::fs::rename) is durable by
    // contract; there is no concept of "fsync a directory handle" — opening
    // a directory as a file fails with ERROR_ACCESS_DENIED (os error 5).
    // We rely on the rename itself for durability on Windows.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let dir = std::fs::File::open(parent)
                .map_err(|e| WalletError::Io(format!("failed to open wallet parent dir for fsync: {}", e)))?;
            dir.sync_all()
                .map_err(|e| WalletError::Io(format!("failed to fsync wallet parent dir: {}", e)))?;
        }
    }

    debug!("wallet saved to {:?}", path);
    Ok(())
}

/// Load and decrypt wallet state from file.
///
/// Verifies the magic bytes and version before attempting decryption.
/// Returns `WalletError::Decryption` if the password is wrong or the file is tampered.
pub fn load_wallet(path: &Path, password: &str) -> Result<WalletState, WalletError> {
    let data = fs::read(path)
        .map_err(|e| WalletError::Io(format!("failed to read wallet file: {}", e)))?;

    if data.len() < HEADER_SIZE {
        return Err(WalletError::Io("wallet file too short".into()));
    }

    // Verify magic bytes.
    if &data[0..14] != MAGIC {
        return Err(WalletError::Io("invalid wallet file magic".into()));
    }

    // Verify version.
    let version = u16::from_le_bytes([data[14], data[15]]);
    if version != VERSION {
        return Err(WalletError::Io(format!(
            "unsupported wallet version: {}",
            version
        )));
    }

    // Extract salt and nonce from header.
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&data[16..48]);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes.copy_from_slice(&data[48..60]);

    // Derive key from password + stored salt.
    let key = derive_key(password, &salt)?;

    // Decrypt payload.
    #[allow(deprecated)]
    let cipher_key = Key::from_slice(&key[..]);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = &data[HEADER_SIZE..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| WalletError::Decryption)?;

    // Deserialize JSON.
    let state: WalletState = serde_json::from_slice(&plaintext)
        .map_err(|e| WalletError::Serialization(e.to_string()))?;

    debug!("wallet loaded from {:?}", path);
    Ok(state)
}
