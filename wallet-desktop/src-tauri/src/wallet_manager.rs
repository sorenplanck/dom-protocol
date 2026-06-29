//! Wallet state manager (engine: dom-wallet2 v2).
//!
//! Wraps `dom_wallet2::WalletV2State` — the v2 persistent store where each owned
//! output is a single `StoredOutput` whose blinding is ALWAYS persisted (the
//! property v1 lacked; see `docs/WALLET_V2_DESIGN.md`). We REUSE the whole v2
//! engine (create/restore/balance/send/receive/finalize/submit/sync) and the
//! shared `dom-wallet-keys` BIP-39 seed; this module only exposes the operations
//! the UI needs and keeps the decrypted state inside the Rust backend.
//!
//! V2 vs V1 surface, as adapted here:
//!   * The vault is a SINGLE encrypted file (`save_wallet_state`/
//!     `load_wallet_state`), not a directory. There is no in-memory lock concept
//!     in the crate: "unlocked" = the state is loaded and we hold the password
//!     (needed to re-save on every mutation); "locked" = the state/password are
//!     dropped and zeroized, the on-disk path remembered so `unlock` can reload.
//!   * Chain sync is reconciliation over the node's `GET /chain/scan` via
//!     `RpcChainSource` (a `ChainSource` + `TxSink`); submission is
//!     `submit_finalized` over the same source. Both `/chain/scan` and
//!     `/tx/submit` are the node's PUBLIC (no-bearer) routes, so the source needs
//!     no token — matching v1, the RPC calls are blocking and run inline.
//!
//! SECURITY:
//!   * The decrypted `WalletV2State` and the password live only here, behind a
//!     `Mutex`. The seed *bytes* and derived private keys never cross the Tauri
//!     IPC boundary.
//!   * The BIP-39 *mnemonic phrase* is the one exception: it crosses the IPC
//!     boundary EXACTLY ONCE, at wallet creation, so the onboarding UI can force
//!     the user to write it down (see `create_new`). It is never persisted by the
//!     frontend and the renderer scrubs it after confirmation. After creation the
//!     words are not re-derivable from the opened wallet (only the seed bytes are
//!     stored).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Result};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_tx::slate::Slate;
use dom_wallet::{Bip39Seed, Network as V1Network, SeedAcceptance};
use dom_wallet2::{
    cancel as v2_cancel, create_send as v2_create_send,
    export_full_backup as v2_export_full_backup, finalize_tracked as v2_finalize_tracked,
    import_full_backup as v2_import_full_backup, load_wallet_state, receive as v2_receive,
    restore_coinbase_from_seed, save_wallet_state,
    submit_finalized as v2_submit_finalized, ChainSource, DerivIndex, KeychainDeriver,
    Network as V2Network, OutputOrigin, OutputStatus, ReconcileReport, RpcChainSource,
    RpcSourceError, StoredOutput, SubmitError, WalletV2State,
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::settings::NodeSettings;

/// Per-request timeout for the node RPC source (mirrors v1's 10s default).
const RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// R-31(b) freshness policy: minimum gap (in blocks) between the node tip and the
/// store's `last_reconciled_tip` that forces a sync before a send. `1` means
/// "sync whenever the node is ahead at all"; a fresh store skips the scan and the
/// send pays only one cheap `tip()` round-trip.
const STALE_TIP_THRESHOLD: u64 = 1;

/// A receive descriptor flattened for the auto-sweep / UI (the crate types are
/// not all Serialize, and v2's `ReceiveRequest` is thinner than v1's descriptor).
#[derive(Clone, serde::Serialize)]
pub struct ReceiveInfo {
    pub index: u32,
    pub amount: u64,
    pub commitment_hex: String,
    // The receive blinding is DERIVABLE from the seed (unlike v1, where it was a
    // descriptor field). The auto-sweep hands it to the node's `/wallet/spend`
    // over the local, bearer-authenticated RPC so the node can build the output.
    pub blinding_hex: String,
}

/// Non-sensitive metadata about the currently-open wallet, used to populate a
/// Wallet Registry entry. Contains NO secret material — just the vault location
/// and the wallet's network.
#[derive(Clone)]
pub struct OpenWalletMeta {
    pub vault_path: String,
    pub network: String,
}

/// Balance breakdown for the dashboard, all in noms.
#[derive(Clone, Copy, serde::Serialize)]
pub struct BalanceInfo {
    pub total: u64,
    pub spendable: u64,
    pub confirmed: u64,
    pub immature: u64,
}

/// Result of a recover/sync pass, surfaced to the UI by `wallet_rescan`.
#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct RescanSummary {
    pub scanned_tip: u64,
    pub recovered: usize,
    pub confirmed: usize,
    pub spent: usize,
    pub reorged: usize,
}

#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct PendingResubmitReport {
    pub attempted: usize,
    pub submitted: usize,
    pub already_in_mempool: usize,
    pub retry_later: usize,
    pub failed: usize,
}

/// Outcome of restoring a full backup into a brand-new vault file. Carries NO
/// secret material — only non-sensitive counts and the new vault's location so
/// the UI can open it. The restored seed/blindings stay inside the saved file,
/// never crossing back over IPC.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportedSummary {
    /// Filesystem path of the freshly written vault (never the open wallet's).
    pub vault_path: String,
    /// Network of the restored wallet ("mainnet"/"testnet"/"regtest").
    pub network: String,
    /// Number of outputs recovered into the new vault.
    pub outputs: usize,
    /// Number of pending slates recovered.
    pub pending_slates: usize,
    /// Reconciliation tip carried by the backup (informational).
    pub last_reconciled_tip: u64,
}

/// A loaded, decrypted wallet plus the material needed to re-save it. The
/// password is held (zeroized on drop) because every v2 mutation persists via
/// `save_wallet_state(state, path, password)`.
struct OpenWallet {
    state: WalletV2State,
    path: PathBuf,
    password: Zeroizing<String>,
    network: V2Network,
}

impl OpenWallet {
    /// Persist the current state to disk under the held password.
    fn save(&self) -> Result<()> {
        save_wallet_state(&self.state, &self.path, self.password.as_str())
            .map_err(|e| anyhow!("save wallet: {e}"))
    }
}

/// The wallet slot: empty, locked (path remembered), or unlocked (state loaded).
///
/// The unlocked state carries the whole `WalletV2State` (the output store), so
/// it is boxed to keep the enum small (clippy `large_enum_variant`).
enum Slot {
    Empty,
    Locked { path: PathBuf, network: V2Network },
    Unlocked(Box<OpenWallet>),
}

pub struct WalletManager {
    inner: Mutex<Slot>,
}

impl WalletManager {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Slot::Empty),
        }
    }

    pub async fn is_open(&self) -> bool {
        !matches!(&*self.inner.lock().await, Slot::Empty)
    }

    pub async fn is_unlocked(&self) -> bool {
        matches!(&*self.inner.lock().await, Slot::Unlocked(_))
    }

    /// Non-sensitive metadata about the open wallet, for the Wallet Registry.
    /// Returns `None` when no wallet is open.
    pub async fn open_wallet_meta(&self) -> Option<OpenWalletMeta> {
        match &*self.inner.lock().await {
            Slot::Empty => None,
            Slot::Locked { path, network } => Some(OpenWalletMeta {
                vault_path: path.to_string_lossy().to_string(),
                network: network_str(*network),
            }),
            Slot::Unlocked(ow) => Some(OpenWalletMeta {
                vault_path: ow.path.to_string_lossy().to_string(),
                network: network_str(ow.network),
            }),
        }
    }

    /// The network of the currently-open wallet, if any (M2). Used to refuse
    /// starting the node on a network that doesn't match the open wallet. Mapped
    /// to the v1 `Network` enum the rest of the desktop (settings) speaks.
    pub async fn wallet_network(&self) -> Option<V1Network> {
        match &*self.inner.lock().await {
            Slot::Empty => None,
            Slot::Locked { network, .. } => Some(v2_to_v1_network(*network)),
            Slot::Unlocked(ow) => Some(v2_to_v1_network(ow.network)),
        }
    }

    /// Create a brand-new deterministic wallet from a freshly generated BIP-39
    /// seed. Returns the mnemonic phrase ONCE so the UI can force the user to
    /// write it down and confirm. After confirmation the UI must not keep it.
    pub async fn create_new(
        &self,
        path: &Path,
        password: &str,
        settings: &NodeSettings,
    ) -> Result<Zeroizing<String>> {
        let v1net = settings.wallet_network();
        let network = v1_to_v2_network(v1net);
        let chain_id = genesis_chain_id(v1net)?;

        let seed = Bip39Seed::generate_new().map_err(|e| anyhow!("seed gen: {e}"))?;
        let phrase = Zeroizing::new(seed.phrase().to_string());

        let state = new_state_from_seed(network, chain_id, &seed);
        let ow = OpenWallet {
            state,
            path: path.to_path_buf(),
            password: Zeroizing::new(password.to_string()),
            network,
        };
        ow.save()?;
        *self.inner.lock().await = Slot::Unlocked(Box::new(ow));
        Ok(phrase)
    }

    /// Restore a wallet from an existing BIP-39 phrase. This persists the seed
    /// and an empty output set; the funds are recovered later by
    /// `recover_from_seed` (coinbase) and `RpcChainSource`-driven reconciliation
    /// once the node is available.
    pub async fn restore_from_phrase(
        &self,
        path: &Path,
        password: &str,
        phrase: &str,
        settings: &NodeSettings,
    ) -> Result<()> {
        let v1net = settings.wallet_network();
        let network = v1_to_v2_network(v1net);
        let chain_id = genesis_chain_id(v1net)?;

        let seed = Bip39Seed::from_phrase(phrase, SeedAcceptance::LegacyRestore)
            .map_err(|e| anyhow!("invalid seed phrase: {e}"))?;

        let state = new_state_from_seed(network, chain_id, &seed);
        let ow = OpenWallet {
            state,
            path: path.to_path_buf(),
            password: Zeroizing::new(password.to_string()),
            network,
        };
        ow.save()?;
        *self.inner.lock().await = Slot::Unlocked(Box::new(ow));
        Ok(())
    }

    /// Open an existing wallet file (decrypted by password).
    pub async fn open(&self, path: &Path, password: &str) -> Result<()> {
        let state = load_wallet_state(path, password).map_err(|e| anyhow!("open wallet: {e}"))?;
        let network = state.network;
        *self.inner.lock().await = Slot::Unlocked(Box::new(OpenWallet {
            state,
            path: path.to_path_buf(),
            password: Zeroizing::new(password.to_string()),
            network,
        }));
        Ok(())
    }

    /// Lock: drop (and zeroize) the decrypted state + password, remembering the
    /// path so `unlock` can reload. State is already persisted after every
    /// mutation, so there is nothing to flush here.
    pub async fn lock(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        if let Slot::Unlocked(ow) = &*guard {
            *guard = Slot::Locked {
                path: ow.path.clone(),
                network: ow.network,
            };
        }
        Ok(())
    }

    /// Unlock: reload the remembered file with `password`. Works from `Locked`
    /// (the normal case) and is also tolerant of being called while already
    /// unlocked (re-verifies the password by reloading).
    pub async fn unlock(&self, password: &str) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let path = match &*guard {
            Slot::Locked { path, .. } => path.clone(),
            Slot::Unlocked(ow) => ow.path.clone(),
            Slot::Empty => return Err(anyhow!("no wallet open")),
        };
        let state =
            load_wallet_state(&path, password).map_err(|e| anyhow!("unlock failed: {e}"))?;
        let network = state.network;
        *guard = Slot::Unlocked(Box::new(OpenWallet {
            state,
            path,
            password: Zeroizing::new(password.to_string()),
            network,
        }));
        Ok(())
    }

    /// Verify a password against the open wallet WITHOUT changing session state.
    ///
    /// v2 has no standalone verify, so we attempt a decrypt of the on-disk file:
    /// a successful `load_wallet_state` proves the password; a decryption error
    /// is a wrong password (`Ok(false)`). Returns an error only when no wallet is
    /// open. As in v1, the BIP-39 *words* cannot be re-derived from an opened
    /// wallet — this only confirms ownership (gate for the "show seed" UI).
    pub async fn verify_password(&self, password: &str) -> Result<bool> {
        let guard = self.inner.lock().await;
        let path = match &*guard {
            Slot::Locked { path, .. } => path.clone(),
            Slot::Unlocked(ow) => ow.path.clone(),
            Slot::Empty => return Err(anyhow!("no wallet open")),
        };
        drop(guard);
        match load_wallet_state(&path, password) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Maturity-aware balance breakdown computed from the store against the
    /// last reconciled tip (the same tip the v2 coin selection uses, so the
    /// "spendable" shown matches what a send can actually select).
    pub async fn balance(&self) -> Result<BalanceInfo> {
        let guard = self.inner.lock().await;
        let ow = self.unlocked(&guard)?;
        Ok(compute_balance(&ow.state))
    }

    /// Create a receive request for an exact amount (noms): derive the next
    /// receive blinding, commit to it, and INSERT the resulting output into the
    /// store at C0 (Unconfirmed) so the swept funds are tracked and later
    /// confirmed by reconciliation. Returns commitment + blinding for the node's
    /// `/wallet/spend` (auto-sweep).
    pub async fn create_receive(&self, amount: u64, now: u64) -> Result<ReceiveInfo> {
        let mut guard = self.inner.lock().await;
        let ow = self.unlocked_mut(&mut guard)?;

        let req = ow
            .state
            .keychain
            .create_receive_request(amount)
            .map_err(|e| anyhow!("create receive request: {e}"))?;
        let deriver =
            KeychainDeriver::new(&ow.state.keychain).map_err(|e| anyhow!("keychain: {e}"))?;
        let blinding = deriver
            .receive_blinding(req.index)
            .map_err(|e| anyhow!("receive blinding: {e}"))?;
        let blinding_bytes = *blinding.as_bytes();

        // C0: register the owned output now (derivable, so recoverable), so the
        // incoming sweep payment is reconciled to Confirmed once mined.
        ow.state
            .outputs
            .insert(StoredOutput::new_unconfirmed(
                req.commitment,
                amount,
                blinding_bytes,
                OutputOrigin::ReceiveSlate,
                false,
                Some(DerivIndex::ReceiveRequest(req.index)),
                now,
            ))
            .map_err(|e| anyhow!("track receive output: {e}"))?;
        ow.save()?;

        Ok(ReceiveInfo {
            index: req.index,
            amount,
            commitment_hex: hex::encode(req.commitment),
            blinding_hex: hex::encode(blinding_bytes),
        })
    }

    // ── Slate protocol (interactive person-to-person send) ────────────────────
    // Three steps, Mimblewimble-style. The Slate carries only PUBLIC data, so it
    // is safe to export as hex and hand to the other party. Secrets stay in the
    // wallet's encrypted state. We only call the v2 payment functions; no crypto
    // is reimplemented here. `now` is a unix timestamp (for output bookkeeping);
    // coin-selection maturity uses the store's last reconciled tip, not `now`.

    /// Step 1 (sender): create a send slate for `amount`/`fee` (noms).
    /// Returns the slate serialized as hex for the UI to display/share.
    ///
    /// R-31(b): before coin selection we run a freshness short-circuit against the
    /// node — a cheap `tip()` check, and a full reconcile ONLY if the store is
    /// behind ([`STALE_TIP_THRESHOLD`]). This stops coin selection from picking
    /// stale (spent/immature) inputs that the node would later reject at submit
    /// ("input commitment not found"), without paying a full-chain scan on every
    /// send. If the node is unreachable the send fails here with a clear message
    /// rather than building against a possibly-stale store. `dom-wallet2`
    /// `create_send` stays pure (no node I/O of its own).
    pub async fn slate_create_send(
        &self,
        rpc_base_url: &str,
        amount: u64,
        fee: u64,
        now: u64,
    ) -> Result<String> {
        let src = rpc_source(rpc_base_url)?;
        let mut guard = self.inner.lock().await;
        let ow = self.unlocked_mut(&mut guard)?;

        if ow
            .state
            .sync_if_behind(&src, STALE_TIP_THRESHOLD, now)
            .map_err(|e| anyhow!("could not reach node to sync before send: {e}"))?
            .is_some()
        {
            // Persist the reconciled store before coin selection reads it.
            ow.save()?;
        }

        let sent = v2_create_send(&mut ow.state, amount, fee, now)
            .map_err(|e| anyhow!("create send slate: {e}"))?;
        ow.save()?;
        slate_to_hex(&sent.slate)
    }

    /// Step 2 (recipient): import the sender's slate, respond, return the
    /// responded slate as hex to hand back to the sender.
    pub async fn slate_receive(&self, slate_hex: &str, now: u64) -> Result<String> {
        let slate = slate_from_hex(slate_hex)?;
        let mut guard = self.inner.lock().await;
        let ow = self.unlocked_mut(&mut guard)?;
        let responded =
            v2_receive(&mut ow.state, slate, now).map_err(|e| anyhow!("receive slate: {e}"))?;
        ow.save()?;
        slate_to_hex(&responded)
    }

    /// Step 3 (sender): import the responded slate, finalize into a Transaction,
    /// and submit it to the node over `rpc_base_url`. Returns the tx hash hex.
    ///
    /// Atomicity mirrors v1's L10: `finalize_tracked` is pure and leaves the
    /// slate retryable on a crypto error; `submit_finalized` leaves the slate
    /// `Finalized` (no rollback) on a transport error, so an ambiguous failure
    /// never frees the inputs for a conflicting respend — the next reconcile /
    /// the background resubmit establishes the truth.
    pub async fn slate_finalize(
        &self,
        rpc_base_url: &str,
        slate_hex: &str,
        now: u64,
    ) -> Result<String> {
        let slate = slate_from_hex(slate_hex)?;
        let mut guard = self.inner.lock().await;
        let ow = self.unlocked_mut(&mut guard)?;

        let (_tx, slate_hash) = v2_finalize_tracked(&mut ow.state, slate, now)
            .map_err(|e| anyhow!("finalize slate: {e}"))?;
        // Persist the Finalized slate (with its tx bytes) BEFORE submitting, so a
        // crash between finalize and submit still leaves a resubmittable tx.
        ow.save()?;

        let sink = rpc_source(rpc_base_url)?;
        match v2_submit_finalized(&mut ow.state, &sink, slate_hash, now) {
            Ok(outcome) => {
                if let Some(warning) = &outcome.warning {
                    tracing::warn!(
                        "slate tx {} accepted with relay warning: {warning}",
                        hex::encode(outcome.tx_hash)
                    );
                }
                ow.save()?;
                Ok(hex::encode(outcome.tx_hash))
            }
            Err(e) => {
                // The slate stays Finalized (persisted above) for resubmit; do
                // NOT roll back — an ambiguous submit may have reached the node.
                tracing::warn!("slate submit failed, keeping tx resubmittable: {e}");
                Err(anyhow!("submit failed: {e}"))
            }
        }
    }

    /// Cancel a still-Unconfirmed send slate by its hash (releases reserved
    /// inputs, D1-deletes the Unconfirmed change). Hex is the sender slate's
    /// 32-byte hash. Kept for completeness / future UI use.
    #[allow(dead_code)]
    pub async fn slate_cancel(&self, slate_hash_hex: &str, now: u64) -> Result<()> {
        let hash = decode_hash32(slate_hash_hex)?;
        let mut guard = self.inner.lock().await;
        let ow = self.unlocked_mut(&mut guard)?;
        v2_cancel(&mut ow.state, hash, now).map_err(|e| anyhow!("cancel slate: {e}"))?;
        ow.save()
    }

    // ── Encrypted full-backup export / import (`wallet.dombak`, schema 4) ──────

    /// Export a complete, encrypted snapshot of the open wallet to `path`
    /// (`wallet.dombak`, schema 4). Captures the seed/keychain, the whole output
    /// store, pending slates, finalized-tx bytes and reconciliation metadata —
    /// the change/receive blindings the seed alone cannot rebuild (design §2.7).
    ///
    /// `passphrase` is the BACKUP's own secret, independent of the wallet
    /// password, so the backup can be restored on another machine. The wallet
    /// must be unlocked. The passphrase is NEVER interpolated into an error or a
    /// log line: only the backup-module error `Display` (which carries no secret
    /// material) is surfaced.
    pub async fn export_full_backup(&self, path: &Path, passphrase: &str) -> Result<()> {
        let exported_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let guard = self.inner.lock().await;
        let ow = self.unlocked(&guard)?;
        v2_export_full_backup(&ow.state, path, passphrase, exported_at)
            .map_err(|e| anyhow!("export backup: {e}"))
    }

    /// Restore a full backup into a BRAND-NEW vault file — the CONFIRMED
    /// non-destructive policy. Works WITHOUT a wallet open: this is the disaster
    /// case (fresh machine, no wallet) where the backup matters most. The caller
    /// supplies the target network EXPLICITLY; nothing reads or mutates an
    /// already-open wallet.
    ///
    /// `target_network` is the network the restored vault belongs to; its genesis
    /// gives the `expected_chain_id` the backup is validated against — the
    /// network check is NOT weakened by dropping the open-wallet dependency, the
    /// user simply asserts the network up front. `passphrase` is the backup's
    /// secret; `new_password` encrypts the new vault. Neither secret is
    /// interpolated into an error or a log line.
    ///
    /// Errors (all surfaced via `Display`, never `{:?}` of a secret):
    /// * the backup belongs to another chain/network (`ChainMismatch`);
    /// * wrong passphrase / tampering (`Decryption`); wrong file kind/schema;
    /// * the chosen new-vault path already exists (refused, never overwritten).
    pub async fn import_full_backup_to_new_vault(
        &self,
        backup_path: &Path,
        passphrase: &str,
        new_vault_path: &Path,
        new_password: &str,
        target_network: V2Network,
    ) -> Result<ImportedSummary> {
        // The backup's chain_id is validated against the EXPLICITLY-chosen target
        // network's genesis. No open wallet is read or required, so a disaster
        // restore on a virgin machine works directly.
        let expected_chain_id = genesis_chain_id(v2_to_v1_network(target_network))?;

        // Decrypt + validate (schema 4, kind == WalletState, chain_id). This call
        // returns the full state and NEVER writes to disk; the passphrase is not
        // interpolated into the surfaced error.
        let state = v2_import_full_backup(backup_path, passphrase, expected_chain_id)
            .map_err(|e| anyhow!("import backup: {e}"))?;

        // Write to a BRAND-NEW vault file. Refuse to overwrite an existing file:
        // defense-in-depth on top of the native save dialog so an import can never
        // clobber the open wallet (or any other wallet) already on disk.
        if new_vault_path.exists() {
            return Err(anyhow!(
                "refusing to overwrite an existing file at the chosen vault path"
            ));
        }
        save_wallet_state(&state, new_vault_path, new_password)
            .map_err(|e| anyhow!("save restored vault: {e}"))?;

        Ok(ImportedSummary {
            vault_path: new_vault_path.to_string_lossy().to_string(),
            network: network_str(state.network),
            outputs: state.outputs.len(),
            pending_slates: state.pending_slates.len(),
            last_reconciled_tip: state.meta.last_reconciled_tip,
        })
    }

    /// Recover derivable coinbase from the seed and reconcile against the node.
    ///
    /// This is the v2 replacement for v1's `rescan_against_node`: it pages the
    /// node's `/chain/scan` (with per-block fees) to rebuild ONLY the derivable
    /// coinbase outputs the seed owns, inserts any that are missing, then runs a
    /// full reconciliation (`WalletV2State::sync`) to bring every output's status
    /// — and the `last_reconciled_tip` cursor — up to the tip. Change and
    /// receive-slate outputs are already tracked at C0, so reconciliation alone
    /// keeps them correct; this method adds back coinbase a restored wallet owns.
    ///
    /// Idempotent: already-present outputs are skipped, and reconciliation is
    /// status-only (never drops an output).
    pub async fn recover_from_seed(&self, rpc_base_url: &str, now: u64) -> Result<RescanSummary> {
        let src = rpc_source(rpc_base_url)?;
        let mut guard = self.inner.lock().await;
        let ow = self.unlocked_mut(&mut guard)?;

        let tip = src.tip().map_err(|e| anyhow!("node tip: {e}"))?;

        let mut recovered = 0usize;
        let blocks = src
            .scan_for_restore(0, tip.height)
            .map_err(|e| anyhow!("chain scan for restore: {e}"))?;
        let coinbase = restore_coinbase_from_seed(&ow.state.keychain, &blocks, now)
            .map_err(|e| anyhow!("restore coinbase: {e}"))?;
        for out in coinbase {
            if ow.state.outputs.get(&out.commitment).is_none() {
                ow.state
                    .outputs
                    .insert(out)
                    .map_err(|e| anyhow!("insert recovered coinbase: {e}"))?;
                recovered += 1;
            }
        }

        let report = ow
            .state
            .sync(&src, 0, now)
            .map_err(|e| anyhow!("reconcile: {e}"))?;
        ow.save()?;

        Ok(summarize(report, recovered))
    }

    /// Resubmit every finalized-but-not-confirmed sender slate to the node.
    ///
    /// v2 keeps the public finalized tx bytes on each `PendingSlate{Sender}`, so
    /// (unlike v1's journal replay) this just re-runs `submit_finalized` for any
    /// slate still `Finalized`/`Submitted`. Used on unlock/open and on a timer.
    pub async fn resubmit_pending(
        &self,
        rpc_base_url: &str,
        now: u64,
    ) -> Result<PendingResubmitReport> {
        let sink = rpc_source(rpc_base_url)?;
        let mut guard = self.inner.lock().await;
        let ow = self.unlocked_mut(&mut guard)?;

        // Snapshot the hashes to retry so we don't borrow the vec across submits.
        let hashes: Vec<[u8; 32]> = ow
            .state
            .pending_slates
            .iter()
            .filter(|p| p.finalized_tx.is_some() && p.role == dom_wallet2::SlateRole::Sender)
            .filter(|p| {
                matches!(
                    p.status,
                    dom_wallet2::SlateLifecycle::Finalized | dom_wallet2::SlateLifecycle::Submitted
                )
            })
            .map(|p| p.slate_hash)
            .collect();

        let mut report = PendingResubmitReport::default();
        let mut changed = false;
        for hash in hashes {
            report.attempted += 1;
            match v2_submit_finalized(&mut ow.state, &sink, hash, now) {
                Ok(_) => {
                    report.submitted += 1;
                    changed = true;
                }
                // The node already has it (double-spend of an in-mempool tx, or
                // already mined): treated as success — reconcile will confirm it.
                Err(SubmitError::Sink(RpcSourceError::Rejected(reason))) => {
                    tracing::info!(
                        "pending slate {} already known to node: {reason}",
                        hex::encode(hash)
                    );
                    report.already_in_mempool += 1;
                }
                // Transient transport / busy chain → try again later.
                Err(SubmitError::Sink(
                    RpcSourceError::Request(_) | RpcSourceError::Busy | RpcSourceError::Status(_),
                )) => {
                    report.retry_later += 1;
                }
                Err(e) => {
                    tracing::warn!("pending slate {} resubmit failed: {e}", hex::encode(hash));
                    report.failed += 1;
                }
            }
        }
        if changed {
            ow.save()?;
        }
        Ok(report)
    }

    // ── internal helpers ──────────────────────────────────────────────────────

    fn unlocked<'a>(&self, guard: &'a Slot) -> Result<&'a OpenWallet> {
        match guard {
            Slot::Unlocked(ow) => Ok(ow.as_ref()),
            Slot::Empty => Err(anyhow!("no wallet open")),
            Slot::Locked { .. } => Err(anyhow!("wallet is locked")),
        }
    }

    fn unlocked_mut<'a>(&self, guard: &'a mut Slot) -> Result<&'a mut OpenWallet> {
        match guard {
            Slot::Unlocked(ow) => Ok(ow.as_mut()),
            Slot::Empty => Err(anyhow!("no wallet open")),
            Slot::Locked { .. } => Err(anyhow!("wallet is locked")),
        }
    }
}

/// Build a fresh `WalletV2State` carrying the seed bytes (state only — the
/// mnemonic words are never persisted; only the 64-byte derived seed is).
fn new_state_from_seed(network: V2Network, chain_id: [u8; 32], seed: &Bip39Seed) -> WalletV2State {
    let mut state = WalletV2State::new(network, chain_id);
    state.keychain.seed_bytes = Some(Zeroizing::new(*seed.seed_bytes()));
    state.keychain.seed_word_count = Some(seed.word_count() as u8);
    state
}

/// The chain id (= genesis hash bytes) for a wallet on `network`.
fn genesis_chain_id(network: V1Network) -> Result<[u8; 32]> {
    let genesis = dom_core::startup_genesis_hash_for_network_magic(network.magic())
        .map_err(|e| anyhow!("genesis hash: {e}"))?;
    Ok(*genesis.as_bytes())
}

/// Maturity-aware balance over the store at `last_reconciled_tip`.
fn compute_balance(state: &WalletV2State) -> BalanceInfo {
    let tip = state.meta.last_reconciled_tip;
    let maturity = state.network.coinbase_maturity();
    let mut spendable = 0u64;
    let mut reserved = 0u64;
    let mut immature = 0u64;
    for o in state.outputs.iter() {
        if o.status != OutputStatus::Confirmed {
            continue; // Unconfirmed/Spent/Reorged are not part of the balance
        }
        let mature = if o.is_coinbase {
            match o.origin_block {
                Some(b) => tip.saturating_sub(b.height) >= maturity,
                None => false,
            }
        } else {
            true
        };
        if !mature {
            immature = immature.saturating_add(o.value);
        } else if o.is_reserved() {
            reserved = reserved.saturating_add(o.value);
        } else {
            spendable = spendable.saturating_add(o.value);
        }
    }
    let confirmed = spendable.saturating_add(reserved);
    BalanceInfo {
        total: confirmed.saturating_add(immature),
        spendable,
        confirmed,
        immature,
    }
}

fn summarize(report: ReconcileReport, recovered: usize) -> RescanSummary {
    RescanSummary {
        scanned_tip: report.tip.map(|t| t.height).unwrap_or(0),
        recovered,
        confirmed: report.confirmed,
        spent: report.spent,
        reorged: report.reorged,
    }
}

/// Build an `RpcChainSource` (ChainSource + TxSink) for the node at `base_url`.
fn rpc_source(base_url: &str) -> Result<RpcChainSource> {
    RpcChainSource::new(base_url, RPC_REQUEST_TIMEOUT).map_err(|e| anyhow!("rpc source: {e}"))
}

fn v1_to_v2_network(n: V1Network) -> V2Network {
    match n {
        V1Network::Mainnet => V2Network::Mainnet,
        V1Network::Testnet => V2Network::Testnet,
        V1Network::Regtest => V2Network::Regtest,
    }
}

fn v2_to_v1_network(n: V2Network) -> V1Network {
    match n {
        V2Network::Mainnet => V1Network::Mainnet,
        V2Network::Testnet => V1Network::Testnet,
        V2Network::Regtest => V1Network::Regtest,
    }
}

/// Stable lowercase string for a wallet `Network`, used in registry metadata
/// (mirrors the desktop `NodeSettings` lowercase serde values).
fn network_str(network: V2Network) -> String {
    match network {
        V2Network::Mainnet => "mainnet",
        V2Network::Testnet => "testnet",
        V2Network::Regtest => "regtest",
    }
    .to_string()
}

// ── Slate (de)serialization for the UI bridge ────────────────────────────────
// The Slate is exchanged as hex text (copy/paste or QR). It contains only
// public data. `to_bytes`/`from_bytes` come from the DomSerialize/DomDeserialize
// traits (dom-serialization).

fn slate_to_hex(slate: &Slate) -> Result<String> {
    let bytes = slate
        .to_bytes()
        .map_err(|e| anyhow!("slate serialize: {e}"))?;
    Ok(hex::encode(bytes))
}

fn slate_from_hex(value: &str) -> Result<Slate> {
    // Tolerate whitespace/newlines from copy-paste.
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(&cleaned)
        .map_err(|_| anyhow!("invalid slate: not valid hex (corrupted or truncated)"))?;
    Slate::from_bytes(&bytes).map_err(|e| anyhow!("invalid slate: {e}"))
}

fn decode_hash32(value: &str) -> Result<[u8; 32]> {
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(&cleaned).map_err(|_| anyhow!("invalid hash: not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("invalid hash: must be 32 bytes"))
}

#[cfg(test)]
mod backup_wire_tests {
    //! Wire tests for the full-backup export/import path through `WalletManager`.
    //! These cover what the manager layer ADDS on top of `dom-wallet2::backup`
    //! (which already proves format fidelity at the crate level): correct
    //! passphrase passing, write-to-NEW-vault, the non-destructive guarantee, the
    //! cross-chain guard, and that no secret leaks through the wire (error string,
    //! `ImportedSummary`, or `Debug` of the restored state).
    //!
    //! The wallet is injected directly into the manager's `Slot` (same-module
    //! access to the private `inner`/`OpenWallet`/`Slot`) so the tests need no
    //! node for send/receive — the backup wire is independent of chain I/O.

    use super::*;
    use dom_wallet2::{PendingSlate, SlateLifecycle, SlateRole, SlateSecrets};
    use tempfile::TempDir;

    // Canary seed: a distinctive decimal byte (0xAB = 171) so a `Debug` LEAK of
    // the seed would print a long "171, 171, ..." run the anti-leak test detects.
    const SEED_CANARY: [u8; 64] = [0xAB; 64];
    // The non-derivable receiver blinding the backup exists to protect (0xE3=227).
    const SLATE_BLINDING: [u8; 32] = [0xE3; 32];
    // Secret passphrases — must NEVER surface in an error or a `Debug` string.
    const BAK_PASS: &str = "backup-pass-LEAKCANARY-Zx9";
    const NEW_VAULT_PASS: &str = "new-vault-pass-LEAKCANARY-Qw7";

    fn commit(tag: u8) -> [u8; 33] {
        let mut c = [0u8; 33];
        c[0] = tag;
        c
    }

    fn out(tag: u8, value: u64, origin: OutputOrigin) -> StoredOutput {
        StoredOutput::new_unconfirmed(commit(tag), value, [tag; 32], origin, false, None, 1000)
    }

    /// A real regtest state: seed + 2 outputs + 1 pending receiver slate. The
    /// `chain_id` is the REAL regtest genesis so the manager's import (which
    /// derives `expected_chain_id` from the target network) accepts it.
    fn populated_regtest_state() -> WalletV2State {
        let chain_id = genesis_chain_id(V1Network::Regtest).unwrap();
        let mut state = WalletV2State::new(V2Network::Regtest, chain_id);
        state.keychain.seed_bytes = Some(Zeroizing::new(SEED_CANARY));
        state.keychain.seed_word_count = Some(24);
        state.keychain.next_change_index = 3;
        state.keychain.next_receive_index = 5;
        state.meta.last_reconciled_tip = 42;
        state
            .outputs
            .insert(out(1, 1000, OutputOrigin::Coinbase))
            .unwrap();
        state
            .outputs
            .insert(out(2, 500, OutputOrigin::Change))
            .unwrap();
        state.pending_slates.push(PendingSlate {
            slate_hash: [0xB2; 32],
            role: SlateRole::Receiver,
            slate_bytes: vec![5, 6, 7],
            secrets: Some(SlateSecrets::Receiver {
                output_blinding: Zeroizing::new(SLATE_BLINDING),
            }),
            reserved_inputs: vec![],
            produced_output: Some([0xC7; 33]),
            finalized_tx: None,
            status: SlateLifecycle::Submitted,
        });
        state
    }

    /// Build a manager with an UNLOCKED wallet holding `state`, injected directly
    /// (no node needed). `path` is a placeholder; export/import never re-save the
    /// open wallet, so it need not exist on disk.
    async fn manager_with_open(state: WalletV2State, dir: &TempDir) -> WalletManager {
        let manager = WalletManager::new();
        *manager.inner.lock().await = Slot::Unlocked(Box::new(OpenWallet {
            state,
            path: dir.path().join("open-wallet.dat"),
            password: Zeroizing::new("wallet-login-pass".to_string()),
            network: V2Network::Regtest,
        }));
        manager
    }

    // ── T1: round-trip export → import → new vault preserves the state ─────────
    #[tokio::test]
    async fn t1_round_trip_to_new_vault_preserves_state() {
        let dir = TempDir::new().unwrap();
        let original = populated_regtest_state();
        let manager = manager_with_open(original.clone(), &dir).await;

        let dombak = dir.path().join("wallet.dombak");
        manager.export_full_backup(&dombak, BAK_PASS).await.unwrap();
        assert!(dombak.exists(), "backup file written");

        let new_vault = dir.path().join("restored.dat");
        let summary = manager
            .import_full_backup_to_new_vault(
                &dombak,
                BAK_PASS,
                &new_vault,
                NEW_VAULT_PASS,
                V2Network::Regtest,
            )
            .await
            .unwrap();

        // Summary reflects the recovered state (non-sensitive counts only).
        assert_eq!(summary.outputs, 2);
        assert_eq!(summary.pending_slates, 1);
        assert_eq!(summary.network, "regtest");
        assert_eq!(summary.last_reconciled_tip, 42);
        assert_eq!(summary.vault_path, new_vault.to_string_lossy());

        // The new vault decrypts with its OWN password to the same state.
        let restored = load_wallet_state(&new_vault, NEW_VAULT_PASS).unwrap();
        assert_eq!(restored.chain_id, original.chain_id);
        assert_eq!(restored.outputs.len(), 2);
        assert_eq!(restored.outputs.get(&commit(1)).unwrap().value, 1000);
        assert_eq!(restored.outputs.get(&commit(2)).unwrap().value, 500);
        assert_eq!(restored.keychain.seed_bytes.as_deref(), Some(&SEED_CANARY));
        assert_eq!(restored.keychain.next_change_index, 3);
        assert_eq!(restored.pending_slates.len(), 1);
        match restored.pending_slates[0].secrets.as_ref() {
            Some(SlateSecrets::Receiver { output_blinding }) => {
                assert_eq!(**output_blinding, SLATE_BLINDING);
            }
            other => panic!("expected receiver secret, got {other:?}"),
        }
    }

    // ── T2: wrong passphrase → Decryption, no file created, no leak ────────────
    #[tokio::test]
    async fn t2_wrong_passphrase_rejected_no_file_no_leak() {
        let dir = TempDir::new().unwrap();
        let manager = manager_with_open(populated_regtest_state(), &dir).await;
        let dombak = dir.path().join("wallet.dombak");
        manager.export_full_backup(&dombak, BAK_PASS).await.unwrap();

        let new_vault = dir.path().join("restored.dat");
        let err = manager
            .import_full_backup_to_new_vault(
                &dombak,
                "WRONG-ATTEMPT-PASS",
                &new_vault,
                NEW_VAULT_PASS,
                V2Network::Regtest,
            )
            .await
            .unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("decryption failed"), "got: {msg}");
        assert!(
            !new_vault.exists(),
            "no vault file created on wrong passphrase"
        );
        // Neither the (wrong) attempt nor any real secret leaks into the message.
        assert!(!msg.contains("WRONG-ATTEMPT-PASS"), "attempt passphrase leaked");
        assert!(!msg.contains(BAK_PASS), "backup passphrase leaked");
        assert!(!msg.contains(NEW_VAULT_PASS), "vault passphrase leaked");
    }

    // ── T3: import is non-destructive — the open wallet is untouched ───────────
    #[tokio::test]
    async fn t3_import_non_destructive_open_wallet_intact() {
        let dir = TempDir::new().unwrap();
        // The open wallet deliberately DIFFERS from the backup so any clobber shows.
        let chain_id = genesis_chain_id(V1Network::Regtest).unwrap();
        let mut open_state = WalletV2State::new(V2Network::Regtest, chain_id);
        open_state.keychain.seed_bytes = Some(Zeroizing::new([0x11; 64]));
        open_state
            .outputs
            .insert(out(9, 4242, OutputOrigin::Change))
            .unwrap();
        let manager = manager_with_open(open_state, &dir).await;

        // A DIFFERENT backup (the rich 2-output state) written via the crate fn.
        let dombak = dir.path().join("other.dombak");
        v2_export_full_backup(&populated_regtest_state(), &dombak, BAK_PASS, 0).unwrap();

        let new_vault = dir.path().join("restored.dat");
        let summary = manager
            .import_full_backup_to_new_vault(
                &dombak,
                BAK_PASS,
                &new_vault,
                NEW_VAULT_PASS,
                V2Network::Regtest,
            )
            .await
            .unwrap();
        assert_eq!(summary.outputs, 2, "new vault got the backup's outputs");
        assert!(new_vault.exists(), "new vault written separately");

        // The OPEN wallet inside the manager is byte-for-byte unchanged.
        let guard = manager.inner.lock().await;
        match &*guard {
            Slot::Unlocked(ow) => {
                assert_eq!(ow.state.outputs.len(), 1, "open wallet outputs untouched");
                assert!(
                    ow.state.outputs.get(&commit(9)).is_some(),
                    "open wallet's own output preserved"
                );
                assert_eq!(
                    ow.state.keychain.seed_bytes.as_deref(),
                    Some(&[0x11; 64]),
                    "open wallet seed untouched"
                );
                assert!(
                    ow.state.pending_slates.is_empty(),
                    "open wallet slates untouched"
                );
            }
            _ => panic!("wallet should still be unlocked after import"),
        }
    }

    // ── T4: no secret leaks via the summary or the restored state's Debug ──────
    #[tokio::test]
    async fn t4_no_secret_leaks_summary_or_debug() {
        let dir = TempDir::new().unwrap();
        let manager = manager_with_open(populated_regtest_state(), &dir).await;
        let dombak = dir.path().join("wallet.dombak");
        manager.export_full_backup(&dombak, BAK_PASS).await.unwrap();

        let new_vault = dir.path().join("restored.dat");
        let summary = manager
            .import_full_backup_to_new_vault(
                &dombak,
                BAK_PASS,
                &new_vault,
                NEW_VAULT_PASS,
                V2Network::Regtest,
            )
            .await
            .unwrap();

        // (a) The summary returned over IPC carries no secret material.
        let summary_dbg = format!("{summary:?}");
        assert!(
            !summary_dbg.contains("171, 171"),
            "seed bytes leaked into the summary"
        );
        assert!(!summary_dbg.contains(BAK_PASS), "backup passphrase in summary");
        assert!(
            !summary_dbg.contains(NEW_VAULT_PASS),
            "vault passphrase in summary"
        );

        // (b) `Debug` of the restored state redacts seed + slate secrets.
        let restored = load_wallet_state(&new_vault, NEW_VAULT_PASS).unwrap();
        let dump = format!("{restored:?}");
        assert!(dump.contains("<redacted>"), "redaction marker missing");
        assert!(
            !dump.contains("171, 171, 171, 171"),
            "seed leaked via Debug"
        );
        assert!(
            !dump.contains("227, 227, 227, 227"),
            "slate output blinding leaked via Debug"
        );
    }

    // ── T5: cross-chain target rejected BEFORE any write ───────────────────────
    #[tokio::test]
    async fn t5_cross_chain_target_rejected_before_write() {
        let dir = TempDir::new().unwrap();
        let manager = manager_with_open(populated_regtest_state(), &dir).await;
        let dombak = dir.path().join("wallet.dombak");
        manager.export_full_backup(&dombak, BAK_PASS).await.unwrap();

        let new_vault = dir.path().join("restored.dat");
        // Assert the WRONG target network (testnet) for a regtest backup. Testnet
        // has a finalized, distinct genesis, so this exercises the real
        // `ChainMismatch` guard (mainnet's genesis is intentionally not finalized
        // in this build, which would error earlier — also before any write).
        let err = manager
            .import_full_backup_to_new_vault(
                &dombak,
                BAK_PASS,
                &new_vault,
                NEW_VAULT_PASS,
                V2Network::Testnet,
            )
            .await
            .unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("chain id does not match"), "got: {msg}");
        assert!(
            !new_vault.exists(),
            "no vault written on chain mismatch (refused before write)"
        );
        assert!(!msg.contains(BAK_PASS), "passphrase leaked on chain mismatch");
    }
}
