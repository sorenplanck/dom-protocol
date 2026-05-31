//! Deterministic restore from a BIP-39 seed phrase.
//!
//! Reconstructs a V2 wallet's recoverable output set from a 24-word
//! BIP-39 phrase + a [`ChainScanSource`]. The phrase is the **sole
//! authority** for what belongs to the wallet — the wallet password
//! is only used to encrypt the resulting on-disk database, not to
//! determine ownership.
//!
//! ## Scope of recovery (V0)
//!
//! For each block height that the [`ChainScanSource`] returns, this
//! module:
//!
//!   1. Derives the deterministic coinbase blinding for that height
//!      via [`seed::coinbase_blinding`] (path
//!      `m/44'/330'/0'/1'/<height>'`).
//!   2. Computes the canonical Pedersen commitment for the candidate
//!      value (`reward` and `reward + fees`).
//!   3. Compares against every output commitment the block reports.
//!      Matches are recorded as recoverable `OwnedOutput`s.
//!
//! Non-coinbase outputs (Slatepack receives) are **not** recovered
//! here — that requires interactive blinding-factor exchange and is
//! out of scope for V0 lifecycle validation.
//!
//! ## Layering
//!
//! Restore writes the same on-disk format produced by
//! [`crate::wallet_dir::WalletDir::create_from_seed`], tags
//! `config.json` as [`WalletVersion::V2`], and persists the 64-byte
//! BIP-39 seed bytes only inside the encrypted wallet payload.
//! Reopened wallets therefore retain deterministic recovery material
//! without ever writing the mnemonic phrase itself to disk.
//!
//! ## Determinism invariants
//!
//! - Same phrase + same scan ⇒ same `OwnedOutput` set, bit-identical
//!   blinding factors. Restoring twice to different directories
//!   yields equivalent wallet state.
//! - Different phrase + same scan ⇒ no outputs recovered. Other
//!   wallets' coinbases are not mistakenly attributed to this seed.
//! - Order of `ChainScanSource::block_at` calls is monotonically
//!   ascending; no out-of-order scans are attempted.
//!
//! ## What this module does NOT do
//!
//! - It does NOT talk to a node. The [`ChainScanSource`] trait is
//!   the abstraction boundary; an RPC-backed implementation lives in
//!   Phase 1.9.
//! - It does NOT persist the seed phrase. The phrase is the
//!   operator's responsibility to back up out-of-band.
//! - It does NOT recover non-coinbase interactive receives yet.

use crate::output_index::OutputIndex;
use crate::seed::{self, Bip39Seed, SeedAcceptance, SeedError};
use crate::store::{save_wallet as save_wallet_file, WalletKeychainState, WalletState};
use crate::types::{Network, OwnedOutput, WalletError};
use crate::wallet::Wallet;
use crate::wallet_dir::{
    WalletConfig, WalletVersion, WALLET_CONFIG_NAME, WALLET_DAT_NAME, WALLET_LOCK_NAME,
};
use dom_core::BlockHeight;
use dom_crypto::pedersen::Commitment;
use dom_crypto::{BlindingFactor, Hash256};
use fs2::FileExt;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info};

/// Errors that can arise during deterministic restore.
#[derive(Debug, Error)]
pub enum RestoreError {
    /// The BIP-39 phrase failed validation (wrong word count for V2,
    /// invalid checksum, unknown words).
    #[error("invalid seed phrase: {0}")]
    InvalidPhrase(#[from] SeedError),

    /// The [`ChainScanSource`] returned an error reading a block.
    #[error("chain scan error at height {height}: {message}")]
    ScanError {
        /// Height that failed.
        height: u64,
        /// Description.
        message: String,
    },

    /// The target directory already contains files and refuses to be
    /// initialised (we never overwrite existing state).
    #[error("restore target directory {0} is not empty; refusing to overwrite")]
    TargetNotEmpty(String),

    /// Underlying wallet error (storage / encryption / I/O).
    #[error("wallet: {0}")]
    Wallet(#[from] WalletError),

    /// I/O error during directory layout creation.
    #[error("io: {0}")]
    Io(String),

    /// Serialisation error writing `config.json`.
    #[error("config encode: {0}")]
    Config(String),

    /// Cryptographic failure deriving a blinding factor.
    #[error("crypto: {0}")]
    Crypto(String),
}

/// Transaction-level canonical effects for wallet history rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTransactionEffect {
    /// Deterministic transaction hash.
    pub tx_hash: [u8; 32],
    /// Input commitments consumed by this transaction.
    pub input_commitments: Vec<[u8; 33]>,
    /// Output commitments created by this transaction.
    pub output_commitments: Vec<[u8; 33]>,
}

/// A minimal projection of an on-chain block, exposing only what the
/// restore code needs to match outputs against the seed-derived
/// coinbase blinding.
///
/// Keeping the payload tight has two effects: (1) the [`ChainScanSource`]
/// implementation can stream blocks cheaply (only commitments, no
/// proofs or kernels), and (2) Phase 1.9's RPC-backed source has a
/// small surface to translate from the node's wire format.
#[derive(Debug, Clone)]
pub struct ScanBlock {
    /// Height of the block in the canonical chain.
    pub height: u64,
    /// Canonical block hash, if the source can provide it.
    pub block_hash: Option<[u8; 32]>,
    /// All 33-byte compressed output commitments in this block.
    /// Includes coinbase and non-coinbase outputs; restore tries each
    /// against the height's candidate blinding.
    pub output_commitments: Vec<[u8; 33]>,
    /// All input commitments consumed by this block's canonical
    /// transactions. Used by wallet rescan to rebuild spent/unspent
    /// state without trusting persisted wallet flags.
    pub input_commitments: Vec<[u8; 33]>,
    /// Total transaction fees in this block (noms). Used to compute
    /// the `reward + fees` candidate value for the coinbase.
    pub total_fees_noms: u64,
    /// Optional transaction-level effects. Canonical wallet rescan
    /// uses this to rebuild transaction history without requiring
    /// private proofs, kernels, or transaction bytes.
    pub tx_effects: Vec<ScanTransactionEffect>,
}

/// Read-only access to canonical blocks for the restore walk.
///
/// Implementations MUST return blocks consistent with the canonical
/// best chain at the time of the call. If the chain reorgs while a
/// restore is in progress, the resulting wallet may include outputs
/// from blocks that have since been disconnected — callers should
/// either wait for chain stability before restoring, or perform a
/// reorg-aware refresh after the initial restore.
pub trait ChainScanSource {
    /// Current canonical tip height. The restore walks heights
    /// `0..=tip_height`.
    fn tip_height(&self) -> u64;

    /// Fetch the block at `height` if present. `Ok(None)` is
    /// reserved for the (rare) case where the chain source knows
    /// about the height but has nothing to return (pruned, gap).
    /// Errors propagate as [`RestoreError::ScanError`].
    fn block_at(&self, height: u64) -> Result<Option<ScanBlock>, RestoreError>;
}

/// In-memory [`ChainScanSource`] for tests and offline restore from
/// pre-collected blocks. Not used in production paths.
#[derive(Default, Debug, Clone)]
pub struct InMemoryChainScan {
    blocks: BTreeMap<u64, ScanBlock>,
}

impl InMemoryChainScan {
    /// Empty scan source — tip is 0, no blocks. Useful for the
    /// "empty restore" base case.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a block (replaces if `block.height` already present).
    pub fn insert(&mut self, block: ScanBlock) {
        self.blocks.insert(block.height, block);
    }

    /// Number of blocks recorded.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether the scan source has any blocks.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

impl ChainScanSource for InMemoryChainScan {
    fn tip_height(&self) -> u64 {
        // Tip is the highest recorded height, or 0 if empty (treat
        // empty as a pre-genesis chain).
        self.blocks.keys().next_back().copied().unwrap_or(0)
    }

    fn block_at(&self, height: u64) -> Result<Option<ScanBlock>, RestoreError> {
        Ok(self.blocks.get(&height).cloned())
    }
}

/// Result of a deterministic restore.
pub struct RestoredWallet {
    /// The reconstructed wallet, file-backed at the restore target.
    pub wallet: Wallet,
    /// Number of outputs recovered from the scan.
    pub recovered_count: usize,
    /// Tip height the scan covered (inclusive).
    pub scanned_tip: u64,
}

/// Reconstruct a V2 wallet at `target_dir` from a 24-word BIP-39
/// phrase, an encrypt-at-rest password, and a [`ChainScanSource`].
///
/// The phrase is the sole authority for ownership; the password
/// protects the resulting on-disk database. Walks heights
/// `0..=scan.tip_height()`, recording outputs whose commitment
/// matches `Commitment::commit(value, seed_derived_blinding)` for
/// either `value == reward(height)` or `value == reward + fees`.
///
/// Writes the wallet directory layout
/// (`wallet.dat` + `config.json` + `wallet.lock`) and acquires the
/// exclusive lockfile for the duration of the restore. The returned
/// [`Wallet`] is unlocked and ready for inspection.
///
/// The directory layout is identical to [`WalletDir::create`]'s
/// output, except `config.json.version == "v2"`. V2 wallets are not
/// yet openable through `WalletDir::open` (gated until Phase 1.10) —
/// for V0 inspection use [`Wallet::open`] on the underlying
/// `wallet.dat` path directly.
pub fn restore_from_phrase<S: ChainScanSource>(
    phrase: &str,
    password: &str,
    target_dir: &Path,
    network: Network,
    genesis_hash: &Hash256,
    scan: &S,
) -> Result<RestoredWallet, RestoreError> {
    info!("starting deterministic restore to {:?}", target_dir);

    // 1. Validate the phrase under the V2 (24-word) policy.
    let seed = Bip39Seed::from_phrase(phrase, SeedAcceptance::NewWallet)?;
    debug_assert!(
        seed.is_v2_eligible(),
        "from_phrase(_, NewWallet) should reject non-24-word phrases"
    );
    let root = seed.derive_root()?;

    // 2. Prepare the target directory (must be absent or empty).
    if target_dir.exists() {
        let mut entries = std::fs::read_dir(target_dir)
            .map_err(|e| RestoreError::Io(format!("read target dir: {e}")))?;
        if entries.next().is_some() {
            return Err(RestoreError::TargetNotEmpty(format!("{:?}", target_dir)));
        }
    } else {
        std::fs::create_dir_all(target_dir)
            .map_err(|e| RestoreError::Io(format!("create target dir: {e}")))?;
    }

    // 3. Acquire the exclusive lockfile before any writes.
    let lockfile_path = target_dir.join(WALLET_LOCK_NAME);
    let lockfile = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .open(&lockfile_path)
        .map_err(|e| RestoreError::Io(format!("create lockfile: {e}")))?;
    lockfile.try_lock_exclusive().map_err(|e| {
        RestoreError::Io(format!(
            "another process already holds the lock at {:?}: {e}",
            lockfile_path
        ))
    })?;

    // 4. Build the recovered output index by walking the scan.
    let chain_id_hash = dom_consensus::derive_chain_id(network.magic(), genesis_hash);
    let chain_id: [u8; 32] = *chain_id_hash.as_bytes();

    let scanned_tip = scan.tip_height();
    let mut outputs = OutputIndex::new();
    let mut recovered_count = 0usize;

    for height in 0..=scanned_tip {
        let Some(block) = scan.block_at(height).map_err(|e| match e {
            RestoreError::ScanError { .. } => e,
            other => RestoreError::ScanError {
                height,
                message: format!("{other}"),
            },
        })?
        else {
            continue;
        };
        if block.height != height {
            // Defensive: a misbehaving source returning a different
            // height than requested would break determinism.
            return Err(RestoreError::ScanError {
                height,
                message: format!(
                    "scan source returned block with height {} for requested {}",
                    block.height, height
                ),
            });
        }

        // 4a. Derive the candidate coinbase blinding for this height.
        let blinding_z = seed::coinbase_blinding(&root, height)?;
        let blinding = BlindingFactor::from_bytes(*blinding_z)
            .map_err(|e| RestoreError::Crypto(format!("blinding from bytes: {e}")))?;

        let reward = dom_core::block_reward(BlockHeight(height)).noms();
        let reward_with_fees = reward.checked_add(block.total_fees_noms).unwrap_or(reward);

        // 4b. Test every output commitment in the block against the
        //     two candidate values (reward, reward+fees). First match
        //     wins for that output.
        for &commitment_bytes in &block.output_commitments {
            for &value in &[reward, reward_with_fees] {
                if value == 0 {
                    continue;
                }
                let candidate = Commitment::commit(value, &blinding);
                if *candidate.as_bytes() == commitment_bytes {
                    let owned = OwnedOutput::new(
                        commitment_bytes,
                        value,
                        *blinding_z,
                        height,
                        true, // is_coinbase
                    );
                    outputs.insert(owned);
                    recovered_count += 1;
                    debug!("restore: matched coinbase at height {height} value={value}");
                    break;
                }
            }
        }
    }

    // 5. Serialise the recovered outputs to the encrypted store.
    let owned_outputs: Vec<OwnedOutput> = outputs.iter().cloned().collect();
    let state = WalletState {
        network,
        chain_id,
        outputs: owned_outputs,
        pending_txs: std::collections::HashMap::new(),
        receive_requests: Vec::new(),
        keychain: WalletKeychainState::deterministic(*seed.seed_bytes(), seed.word_count()),
    };
    let dat_path = target_dir.join(WALLET_DAT_NAME);
    save_wallet_file(&dat_path, &state, password)?;

    // 6. Write the V2 config metadata alongside.
    let cfg = build_v2_config(network, chain_id);
    write_v2_config(target_dir, &cfg)?;

    // 7. Reopen the wallet via the standard path so the returned
    //    handle is unlocked, file-backed, and identical to what a
    //    fresh open would see.
    let wallet = Wallet::open(&dat_path, password)?;

    info!(
        "restore complete: {} outputs recovered up to height {}",
        recovered_count, scanned_tip
    );

    // The lockfile is dropped here, releasing the lock. The
    // restored wallet handle takes ownership of nothing on disk —
    // future opens will re-acquire as needed.
    drop(lockfile);

    Ok(RestoredWallet {
        wallet,
        recovered_count,
        scanned_tip,
    })
}

fn build_v2_config(network: Network, chain_id: [u8; 32]) -> WalletConfig {
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    WalletConfig {
        version: WalletVersion::V2,
        network,
        chain_id: hex::encode(chain_id),
        created_at,
        config_format: WalletConfig::CONFIG_FORMAT_V1,
    }
}

fn write_v2_config(dir: &Path, config: &WalletConfig) -> Result<(), RestoreError> {
    let final_path = dir.join(WALLET_CONFIG_NAME);
    let temp_path = dir.join(format!("{}.tmp", WALLET_CONFIG_NAME));
    let json = serde_json::to_vec_pretty(config)
        .map_err(|e| RestoreError::Config(format!("encode: {e}")))?;

    {
        use std::io::Write;
        let mut f = File::create(&temp_path)
            .map_err(|e| RestoreError::Io(format!("create config temp: {e}")))?;
        f.write_all(&json)
            .map_err(|e| RestoreError::Io(format!("write config temp: {e}")))?;
        f.sync_all()
            .map_err(|e| RestoreError::Io(format!("fsync config temp: {e}")))?;
    }
    std::fs::rename(&temp_path, &final_path)
        .map_err(|e| RestoreError::Io(format!("rename config: {e}")))?;
    #[cfg(unix)]
    {
        let d =
            File::open(dir).map_err(|e| RestoreError::Io(format!("open dir for fsync: {e}")))?;
        d.sync_all()
            .map_err(|e| RestoreError::Io(format!("fsync dir: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_scan_tip_height_empty() {
        let s = InMemoryChainScan::new();
        assert_eq!(s.tip_height(), 0);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn in_memory_scan_tip_height_tracks_highest_block() {
        let mut s = InMemoryChainScan::new();
        s.insert(ScanBlock {
            height: 5,
            block_hash: None,
            output_commitments: vec![[0u8; 33]],
            input_commitments: vec![],
            total_fees_noms: 0,
            tx_effects: vec![],
        });
        s.insert(ScanBlock {
            height: 42,
            block_hash: None,
            output_commitments: vec![[1u8; 33]],
            input_commitments: vec![],
            total_fees_noms: 0,
            tx_effects: vec![],
        });
        s.insert(ScanBlock {
            height: 17,
            block_hash: None,
            output_commitments: vec![[2u8; 33]],
            input_commitments: vec![],
            total_fees_noms: 0,
            tx_effects: vec![],
        });
        assert_eq!(s.tip_height(), 42);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn in_memory_scan_block_at_returns_none_for_missing_height() {
        let mut s = InMemoryChainScan::new();
        s.insert(ScanBlock {
            height: 10,
            block_hash: None,
            output_commitments: vec![],
            input_commitments: vec![],
            total_fees_noms: 0,
            tx_effects: vec![],
        });
        assert!(s.block_at(10).unwrap().is_some());
        assert!(s.block_at(11).unwrap().is_none());
        assert!(s.block_at(0).unwrap().is_none());
    }

    #[test]
    fn v2_config_carries_version_marker() {
        let cfg = build_v2_config(Network::Regtest, [0x33u8; 32]);
        assert_eq!(cfg.version, WalletVersion::V2);
        assert_eq!(cfg.network, Network::Regtest);
        assert_eq!(cfg.chain_id, hex::encode([0x33u8; 32]));
    }
}
