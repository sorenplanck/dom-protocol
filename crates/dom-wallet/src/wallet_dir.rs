//! Portable wallet directory layout.
//!
//! A `WalletDir` is a single self-contained directory holding every
//! piece of state belonging to one wallet — encrypted database, config
//! metadata, lockfile, and (lazily-created) `backups/` and `logs/`
//! sub-directories. Nothing wallet-related is ever written outside
//! the directory. This is what makes the wallet **portable**: the
//! directory can be moved between hosts, copied to a removable drive,
//! restored from an airgapped backup, or rsynced to a VPS, and the
//! reopened wallet is bit-for-bit equivalent to the original.
//!
//! ## Layout
//!
//! ```text
//! <walletdir>/
//!   wallet.dat        # encrypted state (ChaCha20Poly1305, see store.rs)
//!   wallet.lock       # advisory exclusive lockfile (fs2)
//!   config.json       # plaintext metadata: version, network, chain_id, created_at
//!   backups/          # (created on demand) operator-initiated snapshots
//!   logs/             # (created on demand) diagnostic logs
//! ```
//!
//! ## Invariants
//!
//! 1. **Self-contained.** Every wallet-related write lands inside the
//!    directory. Absolute paths are never persisted into any file
//!    here (the directory itself is the only location the OS needs
//!    to know about).
//! 2. **Single-writer.** Opening a `WalletDir` acquires an advisory
//!    exclusive lock on `wallet.lock` via `fs2::FileExt::try_lock_exclusive`.
//!    A second concurrent open in any process on the same host
//!    returns [`WalletError::Io`] without touching the encrypted
//!    state. The lock is released on `Drop`.
//! 3. **Version-tagged.** Every wallet writes a `config.json` whose
//!    `version` field declares the schema. Phase 1.3 introduces
//!    [`WalletVersion::V1`] (password-derived coinbase, matching
//!    legacy behaviour). [`WalletVersion::V2`] is reserved for the
//!    Phase 1.10 seed-derived migration and is rejected on open
//!    here until that phase ships.
//! 4. **Atomic state writes.** The encrypted `wallet.dat` is written
//!    atomically (temp + rename + fsync of file and parent dir) by
//!    the existing `store::save_wallet` path; this module does not
//!    weaken that guarantee.
//! 5. **No-network.** This module performs only local filesystem
//!    I/O. Nothing here reaches out to a node, peer, or remote
//!    service.

use crate::journal::TxJournal;
use crate::store::{save_wallet as save_wallet_file, WalletState};
use crate::types::{Network, WalletError};
use crate::wallet::Wallet;
use dom_crypto::Hash256;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Filename of the encrypted wallet state inside a wallet directory.
pub const WALLET_DAT_NAME: &str = "wallet.dat";
/// Filename of the advisory exclusive lockfile.
pub const WALLET_LOCK_NAME: &str = "wallet.lock";
/// Filename of the plaintext config metadata.
pub const WALLET_CONFIG_NAME: &str = "config.json";
/// Sub-directory name for operator-initiated backup snapshots.
pub const WALLET_BACKUPS_SUBDIR: &str = "backups";
/// Sub-directory name for diagnostic logs.
pub const WALLET_LOGS_SUBDIR: &str = "logs";

/// Wallet schema version.
///
/// - `V1`: legacy / current behaviour — coinbase blinding derived
///   from the wallet password (see `wallet::Wallet::build_coinbase`).
///   New wallets created via [`WalletDir::create`] are tagged `V1`
///   until the seed-derived migration in Phase 1.10.
/// - `V2`: seed-derived coinbase + spend output blindings via BIP-39
///   HD derivation (see `seed::coinbase_blinding`). Wired in
///   Phase 1.10. Recognised but rejected on open in Phase 1.3 so
///   wallets that haven't been migrated yet cannot accidentally be
///   opened by code that doesn't understand the new derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletVersion {
    /// Password-derived coinbase blinding. Legacy / current.
    V1,
    /// Seed-derived coinbase blinding. Reserved for Phase 1.10.
    V2,
}

impl WalletVersion {
    /// Whether this version is supported for open in the current build.
    pub fn is_supported(self) -> bool {
        matches!(self, WalletVersion::V1)
    }
}

/// Plaintext metadata stored at `<walletdir>/config.json`.
///
/// This file is intentionally **not encrypted** — it tells a recovery
/// operator (or this code) which schema is in use before any password
/// is supplied. It MUST NOT contain any secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Schema version.
    pub version: WalletVersion,
    /// Network identifier (Mainnet / Testnet / Regtest).
    pub network: Network,
    /// Chain identifier derived from `(network magic, genesis hash)`.
    /// 32 bytes hex-encoded; mismatch on open is a hard error.
    pub chain_id: String,
    /// Unix timestamp (seconds) at wallet creation. Diagnostic only.
    pub created_at: u64,
    /// Schema-format version of the `WalletConfig` itself. Bumped if
    /// this struct's serialised shape ever changes incompatibly.
    pub config_format: u32,
}

impl WalletConfig {
    /// Format-version of the config struct itself (NOT the wallet
    /// schema). Bumped on serialisation-shape changes only.
    pub const CONFIG_FORMAT_V1: u32 = 1;

    fn new_v1(network: Network, chain_id: [u8; 32]) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            version: WalletVersion::V1,
            network,
            chain_id: hex::encode(chain_id),
            created_at,
            config_format: Self::CONFIG_FORMAT_V1,
        }
    }
}

/// A handle to an opened wallet directory.
///
/// Holds the loaded [`Wallet`], the path of the directory, and the
/// lockfile `File` so that the advisory exclusive lock is released
/// when the handle drops.
pub struct WalletDir {
    path: PathBuf,
    config: WalletConfig,
    wallet: Wallet,
    /// Holds the lockfile open for the lifetime of this `WalletDir`.
    /// `fs2::FileExt::try_lock_exclusive` is released automatically
    /// when the file handle is dropped, so we don't need an explicit
    /// `unlock_exclusive()` call.
    _lockfile: File,
}

impl WalletDir {
    /// Create a brand-new wallet directory at `path`.
    ///
    /// The directory MUST NOT already exist (or, if it exists, must
    /// be empty — to avoid silently merging into someone else's
    /// state). The encrypted `wallet.dat`, plaintext `config.json`,
    /// and `wallet.lock` are written; an exclusive lock is acquired
    /// on the lockfile before any wallet state is persisted.
    pub fn create(
        path: &Path,
        password: &str,
        network: Network,
        genesis_hash: &Hash256,
    ) -> Result<Self, WalletError> {
        info!("creating wallet directory at {:?}", path);

        // Reject if a non-empty directory already lives there.
        if path.exists() {
            let mut entries = std::fs::read_dir(path)
                .map_err(|e| WalletError::Io(format!("read wallet directory: {e}")))?;
            if entries.next().is_some() {
                return Err(WalletError::Io(format!(
                    "wallet directory {:?} is not empty; refusing to overwrite",
                    path
                )));
            }
        } else {
            std::fs::create_dir_all(path)
                .map_err(|e| WalletError::Io(format!("create wallet directory: {e}")))?;
        }

        // Acquire the lockfile FIRST so any concurrent create races
        // are caught before we start writing payload state.
        let lockfile_path = path.join(WALLET_LOCK_NAME);
        let lockfile = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&lockfile_path)
            .map_err(|e| WalletError::Io(format!("create lockfile: {e}")))?;
        lockfile.try_lock_exclusive().map_err(|e| {
            WalletError::Io(format!(
                "another process already holds the wallet lock at {:?}: {e}",
                lockfile_path
            ))
        })?;

        // Compute chain_id deterministically.
        let chain_id_hash = dom_consensus::derive_chain_id(network.magic(), genesis_hash);
        let chain_id: [u8; 32] = *chain_id_hash.as_bytes();

        // Persist the encrypted wallet state.
        let dat_path = path.join(WALLET_DAT_NAME);
        let initial_state = WalletState {
            network,
            chain_id,
            outputs: Vec::new(),
            pending_txs: HashMap::new(),
        };
        save_wallet_file(&dat_path, &initial_state, password)?;

        // Persist the plaintext config.
        let config = WalletConfig::new_v1(network, chain_id);
        write_config(path, &config)?;

        // Re-open via the standard Wallet::open path so we get an
        // unlocked Wallet handle backed by the same on-disk state.
        let mut wallet = Wallet::open(&dat_path, password)?;

        // Attach the WAL journal. On `create` the file does not exist
        // yet — `TxJournal::open` is lazy and the first append will
        // materialise it inside the wallet directory.
        let journal =
            TxJournal::open(path).map_err(|e| WalletError::Io(format!("open journal: {e}")))?;
        wallet.attach_journal(journal);

        Ok(Self {
            path: path.to_path_buf(),
            config,
            wallet,
            _lockfile: lockfile,
        })
    }

    /// Open an existing wallet directory at `path`.
    ///
    /// Verifies the layout, reads `config.json`, rejects unsupported
    /// schema versions, acquires the exclusive lockfile, then opens
    /// the encrypted `wallet.dat` with `password`.
    pub fn open(path: &Path, password: &str) -> Result<Self, WalletError> {
        debug!("opening wallet directory at {:?}", path);

        if !path.is_dir() {
            return Err(WalletError::Io(format!(
                "wallet directory not found or not a directory: {:?}",
                path
            )));
        }

        let dat_path = path.join(WALLET_DAT_NAME);
        if !dat_path.is_file() {
            return Err(WalletError::Io(format!(
                "missing wallet.dat inside {:?}",
                path
            )));
        }

        let config = read_config(path)?;
        if !config.version.is_supported() {
            return Err(WalletError::Io(format!(
                "wallet directory {:?} declares unsupported schema version {:?}; \
                 this build only opens v1 wallets",
                path, config.version
            )));
        }

        // Acquire the lockfile before reading the encrypted payload.
        let lockfile_path = path.join(WALLET_LOCK_NAME);
        let lockfile = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .open(&lockfile_path)
            .map_err(|e| WalletError::Io(format!("open lockfile: {e}")))?;
        lockfile.try_lock_exclusive().map_err(|e| {
            WalletError::Io(format!(
                "another process already holds the wallet lock at {:?}: {e}",
                lockfile_path
            ))
        })?;

        let mut wallet = Wallet::open(&dat_path, password)?;

        // Defensive: verify the on-disk wallet's chain_id matches the
        // plaintext config. Mismatch means tampering or a corrupted
        // directory; refuse to proceed.
        let expected_chain_id_hex = hex::encode(wallet.chain_id());
        if expected_chain_id_hex != config.chain_id {
            return Err(WalletError::Io(format!(
                "chain_id mismatch between wallet.dat and config.json in {:?}",
                path
            )));
        }

        // Attach the WAL journal, then reconcile encrypted state
        // against it. The journal is the source of truth for tx
        // lifecycle: a crash between journal append and `save()`
        // leaves the two stores divergent, and reopen is where we
        // heal that divergence.
        let journal =
            TxJournal::open(path).map_err(|e| WalletError::Io(format!("open journal: {e}")))?;
        wallet.attach_journal(journal);
        let reconciled = wallet.reconcile_with_journal()?;
        if reconciled {
            debug!(
                "reconciled wallet state against journal at {:?}; persisting",
                path
            );
            wallet.save()?;
        }

        Ok(Self {
            path: path.to_path_buf(),
            config,
            wallet,
            _lockfile: lockfile,
        })
    }

    /// Borrow the underlying [`Wallet`].
    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// Mutably borrow the underlying [`Wallet`].
    pub fn wallet_mut(&mut self) -> &mut Wallet {
        &mut self.wallet
    }

    /// The directory on disk.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The wallet's persisted configuration metadata.
    pub fn config(&self) -> &WalletConfig {
        &self.config
    }
}

impl Drop for WalletDir {
    fn drop(&mut self) {
        // fs2's exclusive lock is released when the File handle is
        // dropped. We could call `_lockfile.unlock()` explicitly for
        // visibility but it would just duplicate the Drop behavior.
        // Logging here is a no-op on success and avoids panics during
        // unwind.
        if let Err(e) = fs2::FileExt::unlock(&self._lockfile) {
            warn!(
                "failed to release wallet lockfile cleanly at {:?}: {e}",
                self.path
            );
        }
    }
}

/// Write `config.json` atomically (temp + rename).
fn write_config(dir: &Path, config: &WalletConfig) -> Result<(), WalletError> {
    let final_path = dir.join(WALLET_CONFIG_NAME);
    let temp_path = dir.join(format!("{}.tmp", WALLET_CONFIG_NAME));
    let json = serde_json::to_vec_pretty(config)
        .map_err(|e| WalletError::Serialization(format!("config encode: {e}")))?;

    {
        use std::io::Write;
        let mut f = File::create(&temp_path)
            .map_err(|e| WalletError::Io(format!("create config temp file: {e}")))?;
        f.write_all(&json)
            .map_err(|e| WalletError::Io(format!("write config temp file: {e}")))?;
        f.sync_all()
            .map_err(|e| WalletError::Io(format!("fsync config temp file: {e}")))?;
    }
    std::fs::rename(&temp_path, &final_path)
        .map_err(|e| WalletError::Io(format!("rename config: {e}")))?;
    #[cfg(unix)]
    {
        let d = File::open(dir).map_err(|e| WalletError::Io(format!("open dir for fsync: {e}")))?;
        d.sync_all()
            .map_err(|e| WalletError::Io(format!("fsync dir: {e}")))?;
    }
    Ok(())
}

/// Read and validate `config.json`.
fn read_config(dir: &Path) -> Result<WalletConfig, WalletError> {
    let path = dir.join(WALLET_CONFIG_NAME);
    let bytes =
        std::fs::read(&path).map_err(|e| WalletError::Io(format!("read config.json: {e}")))?;
    let cfg: WalletConfig = serde_json::from_slice(&bytes)
        .map_err(|e| WalletError::Serialization(format!("config decode: {e}")))?;
    if cfg.config_format != WalletConfig::CONFIG_FORMAT_V1 {
        return Err(WalletError::Io(format!(
            "unsupported config_format {} in {:?}",
            cfg.config_format, path
        )));
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_version_v1_is_supported() {
        assert!(WalletVersion::V1.is_supported());
    }

    #[test]
    fn wallet_version_v2_not_yet_supported() {
        // V2 is reserved for Phase 1.10. Recognised in the enum so
        // serde round-trips, but `is_supported` is false until the
        // seed-derived coinbase path lands.
        assert!(!WalletVersion::V2.is_supported());
    }

    #[test]
    fn wallet_version_serde_roundtrip() {
        let json_v1 = serde_json::to_string(&WalletVersion::V1).unwrap();
        let json_v2 = serde_json::to_string(&WalletVersion::V2).unwrap();
        assert_eq!(json_v1, "\"v1\"");
        assert_eq!(json_v2, "\"v2\"");
        let r1: WalletVersion = serde_json::from_str(&json_v1).unwrap();
        let r2: WalletVersion = serde_json::from_str(&json_v2).unwrap();
        assert_eq!(r1, WalletVersion::V1);
        assert_eq!(r2, WalletVersion::V2);
    }

    #[test]
    fn config_v1_round_trips_through_serde() {
        let cfg = WalletConfig::new_v1(Network::Regtest, [0x77u8; 32]);
        let json = serde_json::to_vec(&cfg).unwrap();
        let back: WalletConfig = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.version, WalletVersion::V1);
        assert_eq!(back.network, Network::Regtest);
        assert_eq!(back.chain_id, hex::encode([0x77u8; 32]));
        assert_eq!(back.config_format, WalletConfig::CONFIG_FORMAT_V1);
    }
}
