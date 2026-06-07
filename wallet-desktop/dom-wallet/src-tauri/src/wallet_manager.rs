//! Wallet state manager (V1 scope).
//!
//! Wraps `dom_wallet::WalletDir` — the portable wallet directory bundling the
//! encrypted `wallet.dat`, transaction journal, backups and logs. We REUSE all
//! of it; this module exposes only the operations the V1 UI needs and keeps the
//! unlocked handle inside the Rust backend (never the frontend).
//!
//! V1 commands: create, recover, open, unlock, lock, balance, verify_password,
//! show-seed (only available transiently at creation). Send/receive/Slate are
//! V2 — deliberately NOT present here (they would be purely additive later).
//!
//! SECURITY:
//!   * The unlocked `WalletDir` lives only here, behind a `Mutex`. Seed bytes
//!     and derived keys never cross the Tauri IPC boundary.
//!   * The BIP-39 mnemonic crosses IPC exactly once, at creation, so onboarding
//!     can force the user to write it down. It is never persisted by the app.
//!   * Passwords arrive as `String`, are wrapped in `Zeroizing`, used, dropped.
//!   * Backup-before-write (Principle 4): before any state-mutating op we copy
//!     `wallet.dat` to a timestamped backup and keep the last 10.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use dom_wallet::{Bip39Seed, SeedAcceptance, WalletDir, WALLET_DAT_NAME};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::settings::NodeSettings;

/// How many timestamped backups to retain (Principle 4).
const KEEP_BACKUPS: usize = 10;

/// Balance breakdown for the dashboard, all in noms.
#[derive(Clone, Copy, serde::Serialize)]
pub struct BalanceInfo {
    pub total: u64,
    pub spendable: u64,
    pub confirmed: u64,
    pub immature: u64,
}

/// Why the wallet locked (for the `wallet://locked` event).
#[derive(Clone, Copy)]
pub enum LockReason {
    Manual,
    Timeout,
}

impl LockReason {
    pub fn as_str(self) -> &'static str {
        match self {
            LockReason::Manual => "manual",
            LockReason::Timeout => "timeout",
        }
    }
}

pub struct WalletManager {
    inner: Mutex<Option<WalletDir>>,
    /// Last activity instant (millis since process start) for auto-lock.
    last_activity: Mutex<std::time::Instant>,
    /// Memory-only owner key for sealing sidecar secrets (Slatepack keypair
    /// secrets at rest). Derived from the wallet password + a per-wallet random
    /// salt at unlock time via Argon2id, held only while unlocked, and zeroized
    /// on lock. This replaces the earlier path/network-derived key, which
    /// contained no secret material (audit W-01 / CRITICAL-01).
    owner_key: Mutex<Option<zeroize::Zeroizing<[u8; 32]>>>,
}

impl WalletManager {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
            last_activity: Mutex::new(std::time::Instant::now()),
            owner_key: Mutex::new(None),
        }
    }

    /// Record UI/command activity; resets the auto-lock countdown.
    pub async fn touch(&self) {
        *self.last_activity.lock().await = std::time::Instant::now();
    }

    /// Whether the auto-lock timeout has elapsed for the given setting.
    pub async fn idle_exceeds(&self, minutes: u32) -> bool {
        let last = *self.last_activity.lock().await;
        last.elapsed() >= std::time::Duration::from_secs(minutes as u64 * 60)
    }

    pub async fn is_open(&self) -> bool {
        self.inner.lock().await.is_some()
    }

    pub async fn is_unlocked(&self) -> bool {
        match &*self.inner.lock().await {
            Some(dir) => dir.wallet().is_unlocked(),
            None => false,
        }
    }

    /// Create a brand-new deterministic wallet from a freshly generated BIP-39
    /// seed. Returns the mnemonic ONCE so onboarding can force a write-down.
    pub async fn create_new(
        &self,
        path: &Path,
        password: &str,
        settings: &NodeSettings,
    ) -> Result<Zeroizing<String>> {
        let network = settings.wallet_network();
        let genesis = dom_core::startup_genesis_hash_for_network_magic(network.magic())
            .map_err(|e| anyhow!("genesis hash: {e}"))?;

        let seed = Bip39Seed::generate_new().map_err(|e| anyhow!("seed generation: {e}"))?;
        let phrase = Zeroizing::new(seed.phrase().to_string());

        let dir = WalletDir::create_from_seed(path, password, network, &genesis, &seed)
            .map_err(|e| anyhow!("create wallet: {e}"))?;
        let wallet_dir = dir.path().to_path_buf();
        *self.inner.lock().await = Some(dir);
        self.derive_owner_key(&wallet_dir, password).await?;
        self.touch().await;
        Ok(phrase)
    }

    /// Restore a wallet from an existing BIP-39 phrase.
    pub async fn restore_from_phrase(
        &self,
        path: &Path,
        password: &str,
        phrase: &str,
        settings: &NodeSettings,
    ) -> Result<()> {
        let network = settings.wallet_network();
        let genesis = dom_core::startup_genesis_hash_for_network_magic(network.magic())
            .map_err(|e| anyhow!("genesis hash: {e}"))?;

        let seed = Bip39Seed::from_phrase(phrase, SeedAcceptance::LegacyRestore)
            .map_err(|e| anyhow!("invalid seed phrase: {e}"))?;

        let dir = WalletDir::create_from_seed(path, password, network, &genesis, &seed)
            .map_err(|e| anyhow!("restore wallet: {e}"))?;
        let wallet_dir = dir.path().to_path_buf();
        *self.inner.lock().await = Some(dir);
        self.derive_owner_key(&wallet_dir, password).await?;
        self.touch().await;
        Ok(())
    }

    /// Open an existing wallet directory (unlocked by password).
    pub async fn open(&self, path: &Path, password: &str) -> Result<()> {
        let dir = WalletDir::open(path, password).map_err(|e| anyhow!("open wallet: {e}"))?;
        let wallet_dir = dir.path().to_path_buf();
        *self.inner.lock().await = Some(dir);
        self.derive_owner_key(&wallet_dir, password).await?;
        self.touch().await;
        Ok(())
    }

    pub async fn lock(&self) -> Result<()> {
        if let Some(dir) = &mut *self.inner.lock().await {
            dir.wallet_mut().lock();
        }
        // Drop the sidecar owner key from memory when locking.
        *self.owner_key.lock().await = None;
        Ok(())
    }

    pub async fn unlock(&self, password: &str) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;
        dir.wallet_mut()
            .unlock(password)
            .map_err(|e| anyhow!("unlock failed: {e}"))?;
        let wallet_dir = dir.path().to_path_buf();
        drop(guard);
        self.derive_owner_key(&wallet_dir, password).await?;
        self.touch().await;
        Ok(())
    }

    /// Derive and cache the in-memory sidecar owner key from the wallet password
    /// and a per-wallet random salt (stored non-secret in the sidecar). Argon2id
    /// makes guessing the password expensive even with sidecar read access.
    /// Replaces the former path/network derivation (audit W-01).
    async fn derive_owner_key(&self, wallet_dir: &Path, password: &str) -> Result<()> {
        use argon2::{Argon2, Algorithm, Params, Version};

        // Use the fail-closed loader: a CORRUPT sidecar must not silently yield
        // an empty doc here, or we would mint a fresh salt and render previously
        // sealed secrets undecryptable (audit HIGH-03 interaction with W-01).
        let mut meta = match crate::pending::V2Meta::try_load(wallet_dir) {
            Ok(m) => m,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("absent") {
                    crate::pending::V2Meta::default()
                } else {
                    return Err(anyhow!("cannot derive owner key: {msg}"));
                }
            }
        };
        let salt: [u8; 16] = match &meta.owner_key_salt {
            Some(hex_salt) => {
                let bytes = hex::decode(hex_salt)
                    .map_err(|_| anyhow!("corrupt owner_key_salt in sidecar"))?;
                let mut s = [0u8; 16];
                if bytes.len() != 16 {
                    return Err(anyhow!("owner_key_salt must be 16 bytes"));
                }
                s.copy_from_slice(&bytes);
                s
            }
            None => {
                let mut s = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut s);
                meta.owner_key_salt = Some(hex::encode(s));
                meta.save(wallet_dir)?;
                s
            }
        };

        let params = Params::new(19_456, 2, 1, Some(32))
            .map_err(|e| anyhow!("argon2 params: {e}"))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .map_err(|e| anyhow!("argon2 derive: {e}"))?;
        *self.owner_key.lock().await = Some(zeroize::Zeroizing::new(key));
        Ok(())
    }

    pub async fn balance(&self, current_height: u64) -> Result<BalanceInfo> {
        let guard = self.inner.lock().await;
        let dir = guard.as_ref().ok_or_else(|| anyhow!("no wallet open"))?;
        let b = dir.wallet().balance(current_height);
        Ok(BalanceInfo {
            total: b.total(),
            spendable: b.spendable(),
            confirmed: b.confirmed,
            immature: b.immature,
        })
    }

    /// Verify a password against the ALREADY-OPEN wallet (used for show-seed /
    /// change-password gates). Does NOT re-open the dir (that would deadlock on
    /// the exclusive wallet.lock). Returns Ok(false) for a wrong password.
    pub async fn verify_password(&self, password: &str) -> Result<bool> {
        let guard = self.inner.lock().await;
        let dir = guard.as_ref().ok_or_else(|| anyhow!("no wallet open"))?;
        Ok(dir.wallet().verify_password(password))
    }

    /// The network of the currently-open wallet, if any. Used to refuse
    /// starting the node on a mismatched network.
    pub async fn wallet_network(&self) -> Option<dom_wallet::Network> {
        self.inner
            .lock()
            .await
            .as_ref()
            .map(|d| d.wallet().network())
    }

    /// The wallet directory path, if open.
    pub async fn wallet_path(&self) -> Option<PathBuf> {
        self.inner
            .lock()
            .await
            .as_ref()
            .map(|d| d.path().to_path_buf())
    }

    /// Backup-before-write (Principle 4). Copies `<dir>/wallet.dat` to a
    /// timestamped file under the backup dir and prunes to the last 10. Call
    /// this immediately before any operation that will mutate wallet state.
    ///
    /// The dom-wallet crate writes atomically (temp + rename), so this guards
    /// against a different failure mode: a logically-bad-but-complete write. A
    /// lost blinding factor in a Mimblewimble wallet is unspendable money, so a
    /// pre-write snapshot is cheap insurance.
    pub async fn backup_before_write(&self, backup_dir: &Path) -> Result<Option<PathBuf>> {
        let guard = self.inner.lock().await;
        let Some(dir) = guard.as_ref() else {
            return Ok(None);
        };
        let dat = dir.path().join(WALLET_DAT_NAME);
        if !dat.exists() {
            return Ok(None);
        }
        std::fs::create_dir_all(backup_dir)?;
        let stamp = timestamp_now();
        let dest = backup_dir.join(format!("{WALLET_DAT_NAME}.bak.{stamp}"));
        std::fs::copy(&dat, &dest)?;
        prune_backups(backup_dir, KEEP_BACKUPS)?;
        tracing::info!("wallet backup written: {}", dest.display());
        Ok(Some(dest))
    }

    // ── V2: transaction orchestration ─────────────────────────────────────────
    // All of these delegate to the dom-wallet crate, which owns coin selection,
    // output reservation/locking, signing, and persistence. We add no crypto.

    /// Mode A step 1 (sender): build a send slate. Reserves inputs (the crate
    /// locks them and saves). Returns the serialized slate bytes + tracking hash.
    pub async fn slate_create_send(
        &self,
        amount: u64,
        fee: u64,
        current_height: u64,
    ) -> Result<(Vec<u8>, [u8; 32])> {
        use dom_serialization::DomSerialize;
        let mut guard = self.inner.lock().await;
        let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;
        let slate = dir
            .wallet_mut()
            .create_send_slate(amount, fee, current_height)
            .map_err(|e| anyhow!("create send slate: {e}"))?;
        let bytes = slate.to_bytes().map_err(|e| anyhow!("slate serialize: {e}"))?;
        // The sender's tracking hash is derived once the tx is finalized; for the
        // pending record we use the slate's deterministic identity via its bytes.
        let mut id = [0u8; 32];
        let digest = simple_digest(&bytes);
        id.copy_from_slice(&digest);
        drop(guard);
        self.touch().await;
        Ok((bytes, id))
    }

    /// Mode A step 2 (receiver): import a send slate, add our output+signature,
    /// return the responded slate bytes. The crate validates chain_id etc.
    pub async fn slate_receive(&self, slate_bytes: &[u8], current_height: u64) -> Result<Vec<u8>> {
        use dom_serialization::{DomDeserialize, DomSerialize};
        use dom_tx::slate::Slate;
        let slate = Slate::from_bytes(slate_bytes)
            .map_err(|e| anyhow!("invalid slate: {e}"))?;
        let mut guard = self.inner.lock().await;
        let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;
        let responded = dir
            .wallet_mut()
            .receive_slate(slate, current_height)
            .map_err(|e| anyhow!("receive slate: {e}"))?;
        let out = responded.to_bytes().map_err(|e| anyhow!("slate serialize: {e}"))?;
        drop(guard);
        self.touch().await;
        Ok(out)
    }

    /// Mode A step 3 (sender): finalize the responded slate into a Transaction.
    /// Returns the transaction and its tracking hash (for submit + cancel).
    pub async fn slate_finalize(
        &self,
        response_bytes: &[u8],
        current_height: u64,
    ) -> Result<(dom_consensus::transaction::Transaction, [u8; 32])> {
        use dom_serialization::DomDeserialize;
        use dom_tx::slate::Slate;
        use dom_wallet::Wallet;
        let slate = Slate::from_bytes(response_bytes)
            .map_err(|e| anyhow!("invalid response slate: {e}"))?;
        let mut guard = self.inner.lock().await;
        let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;
        let tx = dir
            .wallet_mut()
            .finalize_slate(slate, current_height)
            .map_err(|e| anyhow!("finalize slate: {e}"))?;
        let hash = Wallet::tracking_tx_hash(&tx).map_err(|e| anyhow!("tx hash: {e}"))?;
        drop(guard);
        self.touch().await;
        Ok((tx, hash))
    }

    /// Mode B (sender): build + reserve a spend directly from a recipient
    /// commitment + blinding (from a parsed DOMRR1 descriptor).
    pub async fn build_spend_to(
        &self,
        commitment_bytes: &[u8; 33],
        blinding_bytes: [u8; 32],
        amount: u64,
        fee: u64,
        current_height: u64,
    ) -> Result<(dom_consensus::transaction::Transaction, [u8; 32])> {
        use dom_crypto::pedersen::Commitment;
        use dom_crypto::BlindingFactor;
        use dom_wallet::Wallet;
        let commitment = Commitment::from_compressed_bytes(commitment_bytes)
            .map_err(|e| anyhow!("bad recipient commitment: {e}"))?;
        let blinding = BlindingFactor::from_bytes(blinding_bytes)
            .map_err(|e| anyhow!("bad recipient blinding: {e}"))?;
        let mut guard = self.inner.lock().await;
        let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;
        let tx = dir
            .wallet_mut()
            .build_spend(commitment, blinding, amount, fee, current_height)
            .map_err(|e| anyhow!("build spend: {e}"))?;
        let hash = Wallet::tracking_tx_hash(&tx).map_err(|e| anyhow!("tx hash: {e}"))?;
        drop(guard);
        self.touch().await;
        Ok((tx, hash))
    }

    /// Mode B (receiver): create a receive request descriptor (commitment +
    /// blinding) for an exact amount.
    pub async fn create_receive_request(
        &self,
        amount: u64,
    ) -> Result<dom_wallet::ReceiveRequestDescriptor> {
        let mut guard = self.inner.lock().await;
        let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;
        let desc = dir
            .wallet_mut()
            .create_receive_request(amount)
            .map_err(|e| anyhow!("create receive request: {e}"))?;
        drop(guard);
        self.touch().await;
        Ok(desc)
    }

    /// Mark a finalized tx as submitted (after a successful broadcast).
    pub async fn mark_submitted(&self, tx_hash: [u8; 32]) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;
        dir.wallet_mut()
            .mark_submitted(tx_hash)
            .map_err(|e| anyhow!("mark submitted: {e}"))
    }

    /// Cancel a tracked tx, releasing its reserved inputs (the crate unlocks and
    /// saves). Used by the cancel command and the expiry sweep.
    pub async fn cancel_tracked_tx(&self, tx_hash: [u8; 32]) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;
        dir.wallet_mut()
            .cancel_tx(tx_hash)
            .map_err(|e| anyhow!("cancel tx: {e}"))
    }

    /// Derive a stable 32-byte owner key for descriptor blinding encryption,
    /// scoped to this wallet. We do not have direct master-key access, so we
    /// derive from the wallet's network + path as a deterministic, wallet-local
    /// secret salt source.
    /// The in-memory sidecar owner key, derived from the wallet password at
    /// unlock (Argon2id over a per-wallet salt). Used to seal Slatepack keypair
    /// secrets at rest in `v2-meta.json`. Requires an unlocked wallet — fails
    /// closed otherwise, so secrets are never sealed under a weak key.
    /// (Replaces the former path/network derivation; audit W-01 / CRITICAL-01.)
    pub async fn descriptor_owner_key(&self) -> Result<[u8; 32]> {
        match &*self.owner_key.lock().await {
            Some(k) => Ok(**k),
            None => Err(anyhow!(
                "wallet must be unlocked to access the sidecar owner key"
            )),
        }
    }
}

/// A small non-cryptographic 32-byte digest used only as a local pending-record
/// id for slates that have no tracking hash yet (pre-finalize). Not used for any
/// security decision.
fn simple_digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&out);
    id
}

/// `2026-06-06T15-30-00`-style stamp (filesystem-safe, sortable).
fn timestamp_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Minimal UTC formatting without pulling chrono: days since epoch + HMS.
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}-{m:02}-{s:02}")
}

/// Howard Hinnant's days→civil-date algorithm (public domain).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Keep only the newest `keep` `wallet.dat.bak.*` files; delete the rest.
fn prune_backups(backup_dir: &Path, keep: usize) -> Result<()> {
    let prefix = format!("{WALLET_DAT_NAME}.bak.");
    let mut backups: Vec<PathBuf> = std::fs::read_dir(backup_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(&prefix))
                .unwrap_or(false)
        })
        .collect();
    // Names sort chronologically (ISO-ish stamp), so lexical sort == time sort.
    backups.sort();
    if backups.len() > keep {
        for old in &backups[..backups.len() - keep] {
            if let Err(e) = std::fs::remove_file(old) {
                tracing::warn!("failed to prune backup {}: {e}", old.display());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_date_epoch() {
        // Day 0 = 1970-01-01.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn timestamp_is_well_formed() {
        let t = timestamp_now();
        // YYYY-MM-DDTHH-MM-SS
        assert_eq!(t.len(), 19);
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[10..11], "T");
    }

    #[test]
    fn prune_keeps_newest_n() {
        let dir = std::env::temp_dir().join(format!("dom-bak-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..15 {
            let name = format!("{WALLET_DAT_NAME}.bak.2026-06-06T00-00-{i:02}");
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        prune_backups(&dir, KEEP_BACKUPS).unwrap();
        let remaining: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".bak."))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(remaining.len(), KEEP_BACKUPS);
        std::fs::remove_dir_all(&dir).ok();
    }
}
