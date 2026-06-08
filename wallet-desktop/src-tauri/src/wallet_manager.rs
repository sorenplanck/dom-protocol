//! Wallet state manager.
//!
//! Wraps `dom_wallet::WalletDir` — the portable wallet directory that bundles
//! the encrypted wallet file, the transaction journal (WAL), backups and logs.
//! We REUSE all of it; this module just exposes the operations the UI needs and
//! keeps the unlocked handle inside the Rust backend (never the frontend).
//!
//! SECURITY:
//!   * The unlocked `WalletDir` lives only here, behind a `Mutex`. The seed
//!     *bytes* and derived private keys never cross the Tauri IPC boundary.
//!   * The BIP-39 *mnemonic phrase* is the one exception: it crosses the IPC
//!     boundary EXACTLY ONCE, at wallet creation, so the onboarding UI can force
//!     the user to write it down (see `wallet_create`). It is never persisted by
//!     the frontend and the renderer scrubs it after confirmation (L7). After
//!     creation the words are not re-derivable from the opened wallet.
//!   * Passwords arrive as `String` from a single command, are used, and the
//!     binding is dropped. We wrap the live copy in `Zeroizing` where we hold
//!     it transiently.

use std::path::Path;

use anyhow::{anyhow, Result};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_tx::slate::Slate;
use dom_wallet::{
    Bip39Seed, NodeRpc, NodeRpcClient, ReceiveRequestDescriptor, RpcClientError, SeedAcceptance,
    Wallet, WalletDir,
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::settings::NodeSettings;

/// A receive descriptor flattened for the UI (the crate type isn't Serialize).
#[derive(Clone, serde::Serialize)]
pub struct ReceiveInfo {
    pub index: u32,
    pub amount: u64,
    pub address: String,
    pub commitment_hex: String,
    // TODO(protocol-team): `blinding_hex` carries the output's blinding factor.
    // Sharing it with a counterparty is part of `dom-wallet`'s receive protocol
    // (`ReceiveRequestDescriptor`), but whether exposing it is acceptable under
    // the project's confidentiality/theft model is a PROTOCOL-level question,
    // out of scope for the wallet-desktop. Not changed here — flagged for review
    // by the protocol team. Within this app it only travels over the local,
    // bearer-authenticated node RPC during the miner-reward auto-sweep.
    pub blinding_hex: String,
    pub status: String,
}

impl From<ReceiveRequestDescriptor> for ReceiveInfo {
    fn from(d: ReceiveRequestDescriptor) -> Self {
        ReceiveInfo {
            index: d.index,
            amount: d.amount,
            address: d.address,
            commitment_hex: d.commitment_hex,
            blinding_hex: d.blinding_hex,
            status: format!("{:?}", d.status),
        }
    }
}

/// Non-sensitive metadata about the currently-open wallet, used to populate a
/// Wallet Registry entry. Contains NO secret material (no password/seed/key) —
/// just the vault location and the plaintext `config.json` fields.
#[derive(Clone)]
pub struct OpenWalletMeta {
    pub vault_path: String,
    pub network: String,
    pub created_at: u64,
}

/// Balance breakdown for the dashboard, all in noms.
#[derive(Clone, Copy, serde::Serialize)]
pub struct BalanceInfo {
    pub total: u64,
    pub spendable: u64,
    pub confirmed: u64,
    pub immature: u64,
}

pub struct WalletManager {
    inner: Mutex<Option<WalletDir>>,
}

impl WalletManager {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
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

    /// Non-sensitive metadata about the open wallet, for the Wallet Registry.
    /// Returns `None` when no wallet is open. Reads only the vault path and the
    /// plaintext `config.json` (network, created_at) — never a secret.
    pub async fn open_wallet_meta(&self) -> Option<OpenWalletMeta> {
        let guard = self.inner.lock().await;
        guard.as_ref().map(|dir| {
            let cfg = dir.config();
            OpenWalletMeta {
                vault_path: dir.path().to_string_lossy().to_string(),
                network: network_str(cfg.network),
                created_at: cfg.created_at,
            }
        })
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
        let network = settings.wallet_network();
        let genesis = dom_core::startup_genesis_hash_for_network_magic(network.magic())
            .map_err(|e| anyhow!("genesis hash: {e}"))?;

        let seed = Bip39Seed::generate_new().map_err(|e| anyhow!("seed gen: {e}"))?;
        let phrase = Zeroizing::new(seed.phrase().to_string());

        let dir = WalletDir::create_from_seed(path, password, network, &genesis, &seed)
            .map_err(|e| anyhow!("create wallet: {e}"))?;
        *self.inner.lock().await = Some(dir);
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
        *self.inner.lock().await = Some(dir);
        Ok(())
    }

    /// Open an existing wallet directory (unlocked by password).
    pub async fn open(&self, path: &Path, password: &str) -> Result<()> {
        let dir = WalletDir::open(path, password).map_err(|e| anyhow!("open wallet: {e}"))?;
        *self.inner.lock().await = Some(dir);
        Ok(())
    }

    pub async fn lock(&self) -> Result<()> {
        if let Some(dir) = &mut *self.inner.lock().await {
            dir.wallet_mut().lock();
        }
        Ok(())
    }

    pub async fn unlock(&self, password: &str) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;
        dir.wallet_mut()
            .unlock(password)
            .map_err(|e| anyhow!("unlock failed: {e}"))?;
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

    /// Create a receive request for an exact amount (noms) and return its
    /// descriptor (address + commitment + blinding, for QR/copy).
    pub async fn create_receive(&self, amount: u64) -> Result<ReceiveInfo> {
        let mut guard = self.inner.lock().await;
        let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;
        let desc = dir
            .wallet_mut()
            .create_receive_request(amount)
            .map_err(|e| anyhow!("create receive request: {e}"))?;
        Ok(desc.into())
    }

    // ── Slate protocol (interactive person-to-person send) ────────────────────
    // Three steps, Mimblewimble-style. The Slate carries only PUBLIC data, so it
    // is safe to export as hex and hand to the other party. Secrets stay in the
    // wallet's encrypted state. We only call the three dom-wallet functions; no
    // crypto is reimplemented here.

    /// Step 1 (sender): create a send slate for `amount`/`fee` (noms).
    /// Returns the slate serialized as hex for the UI to display/share.
    pub async fn slate_create_send(
        &self,
        rpc: &NodeRpcClient,
        amount: u64,
        fee: u64,
    ) -> Result<String> {
        let height = rpc
            .status()
            .map_err(|e| anyhow!("node status: {e}"))?
            .chain_height;
        let mut guard = self.inner.lock().await;
        let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;
        let slate = dir
            .wallet_mut()
            .create_send_slate(amount, fee, height)
            .map_err(|e| anyhow!("create send slate: {e}"))?;
        slate_to_hex(&slate)
    }

    /// Step 2 (recipient): import the sender's slate, respond, return the
    /// responded slate as hex to hand back to the sender.
    pub async fn slate_receive(&self, rpc: &NodeRpcClient, slate_hex: &str) -> Result<String> {
        let height = rpc
            .status()
            .map_err(|e| anyhow!("node status: {e}"))?
            .chain_height;
        let slate = slate_from_hex(slate_hex)?;
        let mut guard = self.inner.lock().await;
        let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;
        let responded = dir
            .wallet_mut()
            .receive_slate(slate, height)
            .map_err(|e| anyhow!("receive slate: {e}"))?;
        slate_to_hex(&responded)
    }

    /// Step 3 (sender): import the responded slate, finalize into a Transaction,
    /// and submit it to the node. Returns the tx hash hex.
    pub async fn slate_finalize(&self, rpc: &NodeRpcClient, slate_hex: &str) -> Result<String> {
        let height = rpc
            .status()
            .map_err(|e| anyhow!("node status: {e}"))?
            .chain_height;
        let slate = slate_from_hex(slate_hex)?;
        let (tx, tx_hash) = {
            let mut guard = self.inner.lock().await;
            let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;
            let tx = dir
                .wallet_mut()
                .finalize_slate(slate, height)
                .map_err(|e| anyhow!("finalize slate: {e}"))?;
            let tx_hash = Wallet::tracking_tx_hash(&tx).map_err(|e| anyhow!("tx hash: {e}"))?;
            (tx, tx_hash)
        };
        match rpc.submit_tx(&tx) {
            Ok(_) => {
                let mut guard = self.inner.lock().await;
                let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;
                if let Err(e) = dir.wallet_mut().mark_submitted(tx_hash) {
                    tracing::warn!(
                        "mark_submitted failed after submit (tx {}): {e}",
                        hex::encode(tx_hash)
                    );
                }
                Ok(hex::encode(tx_hash))
            }
            Err(e) => {
                // L10: only roll back the reservation when the tx definitely did
                // NOT reach the node. On an ambiguous failure (read timeout, or a
                // mid-flight transport error) the node may have accepted it into
                // its mempool — cancelling locally would free the inputs and let
                // the wallet respend them, creating a conflicting transaction.
                if submit_failure_is_safe_to_rollback(&e) {
                    let mut guard = self.inner.lock().await;
                    if let Some(dir) = guard.as_mut() {
                        let _ = dir.wallet_mut().cancel_tx(tx_hash);
                    }
                } else {
                    tracing::warn!(
                        "submit ambiguous, keeping tx {} pending (no rollback): {e}",
                        hex::encode(tx_hash)
                    );
                }
                Err(anyhow!("submit failed: {e}"))
            }
        }
    }

    /// Verify a password against the ALREADY-OPEN wallet (M3).
    ///
    /// We must NOT re-open the `WalletDir` here: `WalletDir::open` takes an
    /// exclusive `wallet.lock`, which always fails while this wallet is open,
    /// so the old implementation could never succeed. Instead we decrypt the
    /// on-disk header in place via `Wallet::verify_password`, which touches no
    /// locks. Returns `Ok(true)` for the correct password, `Ok(false)` for a
    /// wrong one, and an error only when no wallet is open.
    ///
    /// NOTE (verified against the crate): `dom-wallet` intentionally does NOT
    /// expose a way to re-derive the BIP-39 *mnemonic words* from an opened
    /// wallet — the encrypted store keeps the seed *bytes*. Showing the words is
    /// only possible during onboarding (where we still hold them). This method
    /// merely confirms ownership.
    pub async fn verify_password(&self, password: &str) -> Result<bool> {
        let guard = self.inner.lock().await;
        let dir = guard.as_ref().ok_or_else(|| anyhow!("no wallet open"))?;
        Ok(dir.wallet().verify_password(password))
    }

    /// The network of the currently-open wallet, if any (M2). Used to refuse
    /// starting the node on a network that doesn't match the open wallet.
    pub async fn wallet_network(&self) -> Option<dom_wallet::Network> {
        self.inner
            .lock()
            .await
            .as_ref()
            .map(|d| d.wallet().network())
    }
}

/// Stable lowercase string for a wallet `Network`, used in registry metadata
/// (mirrors the desktop `NodeSettings` lowercase serde values).
fn network_str(network: dom_wallet::Network) -> String {
    match network {
        dom_wallet::Network::Mainnet => "mainnet",
        dom_wallet::Network::Testnet => "testnet",
        dom_wallet::Network::Regtest => "regtest",
    }
    .to_string()
}

/// Whether a failed `submit_tx` is safe to roll back locally (L10).
///
/// Returns `false` for the ambiguous cases where the node MAY already have the
/// transaction (a read timeout after the request was sent, or a transport error
/// that could have landed mid-flight). In those cases we keep the local
/// reservation pending instead of cancelling, so the wallet never respends the
/// same inputs. Every other failure (connect timeout, explicit rejection,
/// unauthorized, decode, config, serialization) means the tx did not take
/// effect and the reservation can be released.
fn submit_failure_is_safe_to_rollback(err: &RpcClientError) -> bool {
    !matches!(
        err,
        RpcClientError::ReadTimeout { .. } | RpcClientError::Transport { .. }
    )
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
