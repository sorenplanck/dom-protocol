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

use crate::types::{Network, OwnedOutput, ReceiveRequest, WalletError};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
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

mod serde_seed64_opt {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S>(
        seed: &Option<Zeroizing<[u8; 64]>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match seed {
            Some(bytes) => serializer.serialize_some(&bytes[..]),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Zeroizing<[u8; 64]>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        match bytes {
            Some(bytes) => {
                if bytes.len() != 64 {
                    return Err(serde::de::Error::custom("seed bytes must be 64 bytes"));
                }
                let mut array = [0u8; 64];
                array.copy_from_slice(&bytes);
                Ok(Some(Zeroizing::new(array)))
            }
            None => Ok(None),
        }
    }
}

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
    /// Deterministic fixed-amount receive requests.
    #[serde(default)]
    pub receive_requests: Vec<ReceiveRequest>,
    /// Deterministic wallet keychain metadata and encrypted seed material.
    #[serde(default)]
    pub keychain: WalletKeychainState,
}

/// Seed-backed deterministic keychain state.
///
/// The 64-byte BIP-39 seed bytes are only ever persisted inside the
/// encrypted wallet payload. The normalized mnemonic phrase itself is
/// never written to disk.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct WalletKeychainState {
    /// BIP-39 seed bytes (64 bytes) when this is a deterministic wallet.
    #[serde(
        default,
        with = "serde_seed64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub seed_bytes: Option<Zeroizing<[u8; 64]>>,
    /// Original mnemonic word count. New wallets MUST be 24.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_word_count: Option<u8>,
    /// External-chain receive cursor reserved for future `receive`.
    #[serde(default)]
    pub next_receive_index: u32,
    /// Change-chain cursor reserved for future deterministic change outputs.
    #[serde(default)]
    pub next_change_index: u32,
    /// BIP-44 account. V0 pins this to account 0.
    #[serde(default)]
    pub account: u32,
}

impl WalletKeychainState {
    /// Legacy wallets created before deterministic seed persistence.
    pub fn legacy() -> Self {
        Self::default()
    }

    /// Deterministic keychain metadata to persist for a BIP-39 wallet.
    pub fn deterministic(seed_bytes: [u8; 64], seed_word_count: usize) -> Self {
        Self {
            seed_bytes: Some(Zeroizing::new(seed_bytes)),
            seed_word_count: Some(seed_word_count as u8),
            next_receive_index: 0,
            next_change_index: 0,
            account: 0,
        }
    }

    /// Whether the wallet carries deterministic seed material.
    pub fn has_seed(&self) -> bool {
        self.seed_bytes.is_some()
    }
}

// Custom serde for a single [u8; 33] commitment (PendingChange).
mod serde_commitment33 {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&b[..])
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        let v: Vec<u8> = serde::Deserialize::deserialize(d)?;
        if v.len() != 33 {
            return Err(serde::de::Error::custom("commitment must be 33 bytes"));
        }
        let mut a = [0u8; 33];
        a.copy_from_slice(&v);
        Ok(a)
    }
}

// Custom serde for a single [u8; 32] blinding factor (PendingChange).
mod serde_blinding32 {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&b[..])
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let v: Vec<u8> = serde::Deserialize::deserialize(d)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom("blinding factor must be 32 bytes"));
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        Ok(a)
    }
}

/// Self-spend change produced by a pending transaction.
///
/// The change output uses a **random** blinding factor (unlike coinbase
/// outputs, whose blindings are re-derivable from the seed). `scan_block`
/// therefore cannot recover it. We persist the blinding here, attached to
/// the pending tx, and register the change as a spendable [`OwnedOutput`]
/// only when the tx confirms on-chain — mirroring the chain's reality.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PendingChange {
    /// Compressed 33-byte Pedersen commitment of the change output
    /// (`commit(value, blinding)` — matches the on-chain output exactly).
    #[serde(with = "serde_commitment33")]
    pub commitment: [u8; 33],
    /// Change value in noms.
    pub value: u64,
    /// 32-byte blinding factor for the change output.
    #[serde(with = "serde_blinding32")]
    pub blinding: [u8; 32],
}

/// Public sender-created slate bytes for an in-flight interactive spend.
///
/// The serialized slate contains only public data: commitments, public keys,
/// proofs, offsets, amounts, fees, and optional partial signatures. Sender
/// secrets required for finalization live in [`PendingSendSlateSecrets`].
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PendingSendSlate {
    /// Canonical `dom_tx::slate::Slate` bytes from step 1.
    pub slate_bytes: Vec<u8>,
}

/// Sender-only secrets needed to finalize an interactive slate.
///
/// These bytes are persisted only inside the encrypted wallet payload. They
/// must never be written to the plaintext journal. The sender nonce is
/// single-use and must be discarded once finalization is implemented.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PendingSendSlateSecrets {
    /// Sender excess blinding `x_S` used for the aggregate kernel key.
    #[serde(with = "serde_blinding32")]
    pub sender_excess_blinding: [u8; 32],
    /// Random sender nonce `k_S`; unique per slate and single-use.
    #[serde(with = "serde_blinding32")]
    pub sender_nonce: [u8; 32],
}

/// Public recipient-answered slate bytes for an in-flight receive.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PendingReceiveSlate {
    /// Canonical `dom_tx::slate::Slate` bytes after recipient response.
    pub slate_bytes: Vec<u8>,
}

/// Recipient-only secrets needed to spend an output received via slate.
///
/// These bytes are persisted only inside the encrypted wallet payload. They
/// must never be written to the plaintext journal or exported slate.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PendingReceiveSlateSecrets {
    /// Recipient output blinding `x_R`.
    #[serde(with = "serde_blinding32")]
    pub recipient_output_blinding: [u8; 32],
}

/// A transaction pending confirmation.
#[derive(Serialize, Deserialize, Clone)]
pub struct PendingTx {
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Commitments of inputs being spent by this transaction.
    #[serde(with = "serde_commitment_vec")]
    pub inputs: Vec<[u8; 33]>,
    /// Canonical transaction bytes for explicit rebroadcast after
    /// restart. Legacy pending entries may not have this material.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tx_bytes: Vec<u8>,
    /// Self-spend change to register as spendable once this tx
    /// confirms. `None` for exact spends (no change) and for legacy
    /// pending entries written before change tracking existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<PendingChange>,
    /// Public step-1 slate material when this pending item is an
    /// interactive send rather than a finalized transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_slate: Option<PendingSendSlate>,
    /// Encrypted sender-side slate finalization secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_slate_secrets: Option<PendingSendSlateSecrets>,
    /// Public recipient-answered slate material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive_slate: Option<PendingReceiveSlate>,
    /// Encrypted recipient-side output secret material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive_slate_secrets: Option<PendingReceiveSlateSecrets>,
}

/// Derive the wallet encryption key from a password and per-wallet salt.
///
/// Single source of truth lives in `unlock::derive_wallet_key`
/// (Argon2id m=64 MiB / t=3 / p=1, then HKDF-SHA256 with
/// `info = "DOM:wallet-key:v1"`). This shim adapts the [`WalletKey`]
/// opaque type back to a `Zeroizing<[u8; 32]>` for the AEAD layer
/// below.
///
/// Keep this shim — the call sites here predate `unlock.rs` and
/// changing them in this commit would expand the diff beyond the
/// lock-state-machine scope.
pub(crate) fn derive_key(
    password: &str,
    salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let key =
        crate::unlock::derive_wallet_key(password, salt, &crate::unlock::KdfParams::OWASP_V1)?;
    Ok(Zeroizing::new(*key.as_bytes()))
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
            let dir = std::fs::File::open(parent).map_err(|e| {
                WalletError::Io(format!("failed to open wallet parent dir for fsync: {}", e))
            })?;
            dir.sync_all().map_err(|e| {
                WalletError::Io(format!("failed to fsync wallet parent dir: {}", e))
            })?;
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
