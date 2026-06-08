//! Wallet Registry — a local, **non-sensitive** `name → vault location` map.
//!
//! Front-ends (notably the desktop wallet) let a user unlock a wallet by typing
//! a friendly name ("Carteira 1") plus the password, instead of hunting for the
//! wallet directory on disk every time. This module owns the small JSON file
//! that makes that possible.
//!
//! ## What it stores (and what it MUST NOT)
//!
//! Each [`RegistryEntry`] is **metadata only**:
//!
//! - `name` — the friendly label the user typed.
//! - `wallet_id` — an opaque, locally-generated identifier (not a key).
//! - `vault_path` — where the encrypted [`crate::wallet_dir::WalletDir`] lives.
//! - `network` — which network the wallet belongs to.
//! - `created_at` / `last_opened` — diagnostic timestamps (Unix seconds).
//!
//! The registry is a **convenience index**, not a secret store. It NEVER holds a
//! password, seed, mnemonic, recovery phrase, private key or any other wallet
//! secret. The struct simply has no field for them, so this is enforced by the
//! type — see `registry_serialization_contains_no_secret_material` below, which
//! locks the invariant in place. If the file is deleted the user can still
//! locate or restore their wallet; the real backup is always the recovery
//! phrase.
//!
//! ## Crash-safety
//!
//! [`WalletRegistry::save`] writes atomically (temp file + rename, mirroring the
//! `config.json` writer in [`crate::wallet_dir`]), so a crash mid-write can never
//! leave a half-written `registry.json`.

use std::path::Path;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Serialised-shape version of the registry file. Bumped only if the on-disk
/// JSON shape changes incompatibly.
pub const REGISTRY_FORMAT_V1: u32 = 1;

/// Errors from loading or persisting the wallet registry.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Filesystem error while reading or writing the registry file.
    #[error("registry io: {0}")]
    Io(String),
    /// The registry file could not be (de)serialised.
    #[error("registry serialization: {0}")]
    Serialization(String),
    /// The file declares a `format` this build does not understand.
    #[error("unsupported registry format {0}")]
    UnsupportedFormat(u32),
}

/// A single non-sensitive wallet profile.
///
/// SECURITY: this struct intentionally has no field for a password, seed,
/// mnemonic, recovery phrase or private key. Adding one would break the
/// registry's contract (and the serialization test).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// Friendly name the user typed, e.g. `"Carteira 1"`. Stored verbatim
    /// (trimmed); matching is case-insensitive.
    pub name: String,
    /// Opaque, locally-generated identifier. Not derived from any key.
    pub wallet_id: String,
    /// Path to the wallet directory / vault on disk.
    pub vault_path: String,
    /// Network the wallet belongs to (`"mainnet"`, `"testnet"`, `"regtest"`).
    pub network: String,
    /// Unix timestamp (seconds) of wallet creation, if known. Diagnostic only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
    /// Unix timestamp (seconds) the wallet was last opened, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_opened: Option<u64>,
}

/// The full registry: a versioned list of [`RegistryEntry`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletRegistry {
    /// On-disk format version (see [`REGISTRY_FORMAT_V1`]).
    pub format: u32,
    /// Registered wallet profiles.
    #[serde(default)]
    pub wallets: Vec<RegistryEntry>,
}

impl Default for WalletRegistry {
    fn default() -> Self {
        Self {
            format: REGISTRY_FORMAT_V1,
            wallets: Vec::new(),
        }
    }
}

/// Normalise a name for matching: trim surrounding whitespace and lowercase.
fn normalize(name: &str) -> String {
    name.trim().to_lowercase()
}

/// Generate a fresh opaque wallet identifier (16 random bytes, hex-encoded).
///
/// This is just a stable label for a registry entry; it is NOT a key and is not
/// derived from any secret.
pub fn new_wallet_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

impl WalletRegistry {
    /// Load the registry from `path`.
    ///
    /// A missing file is not an error: it yields an empty registry, so the very
    /// first run (or a deleted file) simply has no saved profiles.
    pub fn load(path: &Path) -> Result<Self, RegistryError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(e) => return Err(RegistryError::Io(format!("read registry: {e}"))),
        };
        let registry: WalletRegistry = serde_json::from_slice(&bytes)
            .map_err(|e| RegistryError::Serialization(format!("decode registry: {e}")))?;
        if registry.format != REGISTRY_FORMAT_V1 {
            return Err(RegistryError::UnsupportedFormat(registry.format));
        }
        Ok(registry)
    }

    /// Persist the registry to `path` atomically (temp file + rename).
    ///
    /// The parent directory is created if it does not exist yet.
    pub fn save(&self, path: &Path) -> Result<(), RegistryError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| RegistryError::Io(format!("create registry dir: {e}")))?;
            }
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| RegistryError::Serialization(format!("encode registry: {e}")))?;

        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "registry.json".to_string());
        let temp_path = path.with_file_name(format!("{file_name}.tmp"));
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&temp_path)
                .map_err(|e| RegistryError::Io(format!("create registry temp: {e}")))?;
            f.write_all(&json)
                .map_err(|e| RegistryError::Io(format!("write registry temp: {e}")))?;
            f.sync_all()
                .map_err(|e| RegistryError::Io(format!("fsync registry temp: {e}")))?;
        }
        std::fs::rename(&temp_path, path)
            .map_err(|e| RegistryError::Io(format!("rename registry: {e}")))?;
        Ok(())
    }

    /// Find a profile by friendly name (case-insensitive, whitespace-trimmed).
    pub fn resolve(&self, name: &str) -> Option<&RegistryEntry> {
        let key = normalize(name);
        self.wallets.iter().find(|e| normalize(&e.name) == key)
    }

    /// All registered friendly names, in insertion order.
    pub fn names(&self) -> Vec<String> {
        self.wallets.iter().map(|e| e.name.clone()).collect()
    }

    /// Insert `entry`, or update the existing profile with the same name
    /// (case-insensitive).
    ///
    /// When updating, the existing `wallet_id` is preserved (the identifier is
    /// stable for the lifetime of a profile) and so is the existing `created_at`
    /// when the incoming entry does not carry one.
    pub fn upsert(&mut self, mut entry: RegistryEntry) {
        entry.name = entry.name.trim().to_string();
        let key = normalize(&entry.name);
        if let Some(existing) = self.wallets.iter_mut().find(|e| normalize(&e.name) == key) {
            entry.wallet_id = existing.wallet_id.clone();
            if entry.created_at.is_none() {
                entry.created_at = existing.created_at;
            }
            *existing = entry;
        } else {
            self.wallets.push(entry);
        }
    }

    /// Update the `last_opened` timestamp for `name`. Returns `true` if a
    /// matching profile was found.
    pub fn touch_last_opened(&mut self, name: &str, ts: u64) -> bool {
        let key = normalize(name);
        if let Some(entry) = self.wallets.iter_mut().find(|e| normalize(&e.name) == key) {
            entry.last_opened = Some(ts);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn entry(name: &str, path: &str) -> RegistryEntry {
        RegistryEntry {
            name: name.to_string(),
            wallet_id: new_wallet_id(),
            vault_path: path.to_string(),
            network: "testnet".to_string(),
            created_at: Some(1_700_000_000),
            last_opened: None,
        }
    }

    #[test]
    fn missing_file_loads_empty_registry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does-not-exist").join("registry.json");
        let reg = WalletRegistry::load(&path).expect("missing file is not an error");
        assert_eq!(reg.format, REGISTRY_FORMAT_V1);
        assert!(reg.wallets.is_empty());
    }

    #[test]
    fn upsert_then_resolve_round_trips_through_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cfg").join("registry.json");

        let mut reg = WalletRegistry::default();
        reg.upsert(entry("Carteira 1", "/vaults/carteira-1"));
        reg.save(&path).expect("save");

        // Reload from disk and resolve the saved path by name.
        let reloaded = WalletRegistry::load(&path).expect("load");
        let found = reloaded.resolve("Carteira 1").expect("entry present");
        assert_eq!(found.vault_path, "/vaults/carteira-1");
        assert_eq!(found.network, "testnet");
    }

    #[test]
    fn resolve_is_case_insensitive_and_trims() {
        let mut reg = WalletRegistry::default();
        reg.upsert(entry("Carteira 1", "/vaults/c1"));
        assert!(reg.resolve("  carteira 1 ").is_some());
        assert!(reg.resolve("CARTEIRA 1").is_some());
        assert!(reg.resolve("Carteira 2").is_none());
    }

    #[test]
    fn unknown_name_resolves_to_none() {
        let reg = WalletRegistry::default();
        assert!(reg.resolve("Carteira 1").is_none());
    }

    #[test]
    fn upsert_updates_path_and_preserves_wallet_id() {
        let mut reg = WalletRegistry::default();
        reg.upsert(entry("Carteira 1", "/old/path"));
        let id = reg.resolve("Carteira 1").unwrap().wallet_id.clone();

        // Re-register the same name pointing at a new location.
        reg.upsert(entry("carteira 1", "/new/path"));
        assert_eq!(reg.wallets.len(), 1, "must update, not duplicate");
        let updated = reg.resolve("Carteira 1").unwrap();
        assert_eq!(updated.vault_path, "/new/path");
        assert_eq!(updated.wallet_id, id, "wallet_id must be stable");
    }

    #[test]
    fn touch_last_opened_sets_timestamp() {
        let mut reg = WalletRegistry::default();
        reg.upsert(entry("Carteira 1", "/vaults/c1"));
        assert!(reg.touch_last_opened("carteira 1", 1_700_000_123));
        assert_eq!(
            reg.resolve("Carteira 1").unwrap().last_opened,
            Some(1_700_000_123)
        );
        assert!(!reg.touch_last_opened("Carteira 2", 1));
    }

    /// SECURITY INVARIANT: the serialised registry must never carry secret
    /// material. The type has no field for it; this guards against a future
    /// field being added by mistake.
    #[test]
    fn registry_serialization_contains_no_secret_material() {
        let mut reg = WalletRegistry::default();
        reg.upsert(entry("Carteira 1", "/vaults/c1"));
        let json = serde_json::to_string(&reg).unwrap().to_lowercase();
        for forbidden in [
            "password", "seed", "mnemonic", "private", "secret", "recovery", "phrase",
        ] {
            assert!(
                !json.contains(forbidden),
                "registry JSON must not contain {forbidden:?}"
            );
        }
    }

    #[test]
    fn save_is_atomic_and_leaves_no_temp_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let mut reg = WalletRegistry::default();
        reg.upsert(entry("Carteira 1", "/vaults/c1"));
        reg.save(&path).unwrap();
        assert!(path.exists());
        assert!(
            !path.with_file_name("registry.json.tmp").exists(),
            "temp file must be renamed away"
        );
    }
}
