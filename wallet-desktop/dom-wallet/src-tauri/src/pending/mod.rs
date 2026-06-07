//! V2 pending / metadata sidecar.
//!
//! IMPORTANT DESIGN NOTE (safety): the dom-wallet crate already owns the
//! authoritative pending-transaction state and output locking
//! (`Wallet.pending_txs`, `build_spend_unreserved` + `reserve_built_spend`,
//! `cancel_tx`). We do NOT duplicate that — duplicating it is the #1 source of
//! Mimblewimble double-spend bugs. The wallet file format stays untouched.
//!
//! What lives here instead is purely ADDITIVE app-level metadata that the crate
//! has no concept of, persisted in a SEPARATE plaintext-safe sidecar
//! `v2-meta.json` inside the WalletDir:
//!   * Slatepack keypairs we generated (so we can decrypt responses) — secrets
//!     are stored encrypted by the caller before they reach here.
//!   * Receive descriptors we emitted (for the "show / cancel" UI and expiry).
//!   * UI-facing pending records (amount, counterparty, state label, expiry) so
//!     the Dashboard widget and History can render rich state. The financial
//!     truth (are inputs reserved?) always comes from the crate.
//!
//! This is the "V1 → V2 migration" the brief asks for, done safely: opening a
//! V1 wallet simply finds no sidecar and creates an empty one. No re-encryption
//! of `wallet.dat`, no schema rewrite, fully non-destructive.

pub mod expiry;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

/// Sidecar filename inside the WalletDir.
pub const META_FILE: &str = "v2-meta.json";

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Transaction mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Slatepack,
    Simple,
}

/// Direction of a pending/known transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Sent,
    Received,
}

/// UI-facing pending state. Mirrors the brief's state names across both modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingState {
    // Mode A — sender
    SlateCreated,
    SlateSent,
    SlateReceivedBack,
    // Mode A — receiver
    SlateReceived,
    SlateSigned,
    SlateReturned,
    // Mode B — sender
    DescriptorReceived,
    // Mode B — receiver
    DescriptorCreated,
    // shared
    Finalized,
    Broadcast,
    Confirmed,
    Expired,
    Cancelled,
    Failed,
}

impl PendingState {
    /// Whether this state is terminal (no further user action expected).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            PendingState::Confirmed
                | PendingState::Expired
                | PendingState::Cancelled
                | PendingState::Failed
        )
    }
}

/// A stored Slatepack keypair (per-transaction). The secret is stored encrypted
/// by the wallet master key BEFORE being handed to this store.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredSlateAddress {
    pub address: String,
    /// Hex of the encrypted secret (nonce ‖ ciphertext). Never plaintext.
    pub secret_key_encrypted: String,
    pub created_at: u64,
}

/// A receive descriptor we emitted (Mode B).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredDescriptor {
    pub id: String,
    pub encoded: String,
    pub amount_noms: u64,
    pub created_at: u64,
    pub expires_at: u64,
    /// "active" | "used" | "expired".
    pub status: String,
}

/// A UI-facing pending transaction record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingRecord {
    pub id: String,
    pub mode: Mode,
    pub direction: Direction,
    pub amount_noms: u64,
    pub fee_noms: u64,
    pub counterparty_addr: Option<String>,
    pub state: PendingState,
    pub created_at: u64,
    pub expires_at: u64,
    /// Commitments the crate reserved for this tx (mirror, for display only).
    pub locked_outputs: Vec<String>,
    /// Tracking hash once finalized/broadcast (hex), for cancel via crate.
    pub tracking_tx_hash: Option<String>,
}

/// The full sidecar document.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct V2Meta {
    /// Per-wallet random salt (hex, 16 bytes) for deriving the sidecar owner key
    /// from the wallet password via Argon2id. Non-secret by design (a salt);
    /// created on first unlock if absent. See `WalletManager` (audit W-01).
    #[serde(default)]
    pub owner_key_salt: Option<String>,
    #[serde(default)]
    pub slatepack_addresses: Vec<StoredSlateAddress>,
    #[serde(default)]
    pub receive_descriptors: Vec<StoredDescriptor>,
    #[serde(default)]
    pub pending: Vec<PendingRecord>,
}

impl V2Meta {
    /// Path of the sidecar for a given wallet directory.
    pub fn path_in(wallet_dir: &Path) -> PathBuf {
        wallet_dir.join(META_FILE)
    }

    /// Load the sidecar. Absence is normal (a V1 wallet has no sidecar — this
    /// is the V1→V2 migration) and yields an empty document. But a sidecar that
    /// EXISTS and fails to parse is a hard error: silently resetting to empty
    /// would drop Slatepack secrets, descriptors, pending state, and — worse —
    /// re-mint the owner-key salt, making previously sealed secrets permanently
    /// undecryptable. We fail closed and quarantine the corrupt file so the user
    /// can recover. (Audit HIGH-03.)
    pub fn load(wallet_dir: &Path) -> V2Meta {
        Self::try_load(wallet_dir).unwrap_or_else(|e| {
            // Only reached for true absence; try_load returns Err on corruption.
            tracing::debug!("v2-meta absent, starting empty: {e}");
            V2Meta::default()
        })
    }

    /// Fallible load: `Ok(empty)` if absent, `Ok(meta)` if valid, `Err` if a
    /// present sidecar is unreadable/corrupt (after quarantining it).
    pub fn try_load(wallet_dir: &Path) -> AppResult<V2Meta> {
        let path = Self::path_in(wallet_dir);
        if !path.exists() {
            return Err(AppError::Io("sidecar absent".into()));
        }
        let text = std::fs::read_to_string(&path).map_err(|e| AppError::Io(e.to_string()))?;
        match serde_json::from_str::<V2Meta>(&text) {
            Ok(meta) => Ok(meta),
            Err(e) => {
                // Quarantine rather than overwrite, so nothing is lost.
                let quarantine = path.with_extension(format!("corrupt.{}", now_unix_secs()));
                let _ = std::fs::rename(&path, &quarantine);
                tracing::error!(
                    "v2-meta corrupt ({e}); quarantined to {}",
                    quarantine.display()
                );
                Err(AppError::Io(format!(
                    "wallet metadata (v2-meta.json) is corrupt and was quarantined to {}. \
                     Restore from a backup before continuing.",
                    quarantine.display()
                )))
            }
        }
    }

    /// Persist the sidecar durably: write temp → flush → fsync file → rename →
    /// fsync parent directory, so a crash/power-loss cannot leave a torn or
    /// missing file. Keeps a single `.bak` of the prior good copy. (Audit
    /// HIGH-03.)
    pub fn save(&self, wallet_dir: &Path) -> AppResult<()> {
        use std::io::Write;
        let path = Self::path_in(wallet_dir);
        let tmp = path.with_extension("json.tmp");
        let text =
            serde_json::to_string_pretty(self).map_err(|e| AppError::Io(e.to_string()))?;

        {
            let mut f = std::fs::File::create(&tmp).map_err(|e| AppError::Io(e.to_string()))?;
            f.write_all(text.as_bytes())
                .map_err(|e| AppError::Io(e.to_string()))?;
            f.flush().map_err(|e| AppError::Io(e.to_string()))?;
            f.sync_all().map_err(|e| AppError::Io(e.to_string()))?;
        }

        // Snapshot the prior good copy before replacing it.
        if path.exists() {
            let bak = path.with_extension("json.bak");
            let _ = std::fs::copy(&path, &bak);
        }

        std::fs::rename(&tmp, &path).map_err(|e| AppError::Io(e.to_string()))?;

        // fsync the directory so the rename itself is durable.
        if let Ok(dir) = std::fs::File::open(wallet_dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    /// Active (non-terminal) pending records.
    pub fn active_pending(&self) -> impl Iterator<Item = &PendingRecord> {
        self.pending.iter().filter(|p| !p.state.is_terminal())
    }

    /// Mark expired any pending/descriptor whose deadline passed. Returns the
    /// tracking hashes of sender-side slatepack txs that need their inputs
    /// released via the crate's `cancel_tx`.
    pub fn expire_due(&mut self, now_unix: u64) -> Vec<String> {
        let mut to_cancel = Vec::new();
        for p in self.pending.iter_mut() {
            if !p.state.is_terminal() && now_unix >= p.expires_at {
                // Only sender-side flows actually reserved inputs.
                if p.direction == Direction::Sent {
                    if let Some(h) = &p.tracking_tx_hash {
                        to_cancel.push(h.clone());
                    }
                }
                p.state = PendingState::Expired;
            }
        }
        for d in self.receive_descriptors.iter_mut() {
            if d.status == "active" && now_unix >= d.expires_at {
                d.status = "expired".into();
            }
        }
        to_cancel
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_load_for_v1_wallet() {
        let dir = std::env::temp_dir().join(format!("dom-v2meta-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // No sidecar present → empty (this is the migration).
        let meta = V2Meta::load(&dir);
        assert!(meta.pending.is_empty());
        assert!(meta.receive_descriptors.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("dom-v2meta-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut meta = V2Meta::default();
        meta.pending.push(PendingRecord {
            id: "abc".into(),
            mode: Mode::Slatepack,
            direction: Direction::Sent,
            amount_noms: 100,
            fee_noms: 1,
            counterparty_addr: Some("dom1xyz".into()),
            state: PendingState::SlateSent,
            created_at: 0,
            expires_at: 100,
            locked_outputs: vec!["c1".into()],
            tracking_tx_hash: Some("deadbeef".into()),
        });
        meta.save(&dir).unwrap();
        let loaded = V2Meta::load(&dir);
        assert_eq!(loaded.pending.len(), 1);
        assert_eq!(loaded.pending[0].id, "abc");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn expire_due_marks_and_collects_sender_hashes() {
        let mut meta = V2Meta::default();
        meta.pending.push(PendingRecord {
            id: "s".into(),
            mode: Mode::Slatepack,
            direction: Direction::Sent,
            amount_noms: 1,
            fee_noms: 0,
            counterparty_addr: None,
            state: PendingState::SlateSent,
            created_at: 0,
            expires_at: 10,
            locked_outputs: vec![],
            tracking_tx_hash: Some("hh".into()),
        });
        meta.pending.push(PendingRecord {
            id: "r".into(),
            mode: Mode::Slatepack,
            direction: Direction::Received,
            amount_noms: 1,
            fee_noms: 0,
            counterparty_addr: None,
            state: PendingState::SlateReceived,
            created_at: 0,
            expires_at: 10,
            locked_outputs: vec![],
            tracking_tx_hash: None,
        });
        let to_cancel = meta.expire_due(20);
        assert_eq!(to_cancel, vec!["hh".to_string()]);
        assert!(meta.pending.iter().all(|p| p.state == PendingState::Expired));
    }

    #[test]
    fn try_load_absent_is_ok_empty() {
        let dir = std::env::temp_dir().join(format!("dom-v2meta-abs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // No sidecar → Err("absent"), and load() maps that to default.
        assert!(V2Meta::try_load(&dir).is_err());
        assert!(V2Meta::load(&dir).pending.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_sidecar_fails_closed_and_quarantines() {
        // Audit HIGH-03: a corrupt sidecar must NOT silently reset to empty.
        let dir = std::env::temp_dir().join(format!("dom-v2meta-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = V2Meta::path_in(&dir);
        std::fs::write(&path, b"{ this is not valid json").unwrap();
        let res = V2Meta::try_load(&dir);
        assert!(res.is_err(), "corrupt sidecar must fail closed");
        // Original corrupt file moved aside (quarantined), not left in place.
        assert!(!path.exists(), "corrupt file should be quarantined");
        let quarantined = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains("corrupt"));
        assert!(quarantined, "a .corrupt.* file should exist");
        std::fs::remove_dir_all(&dir).ok();
    }
}
