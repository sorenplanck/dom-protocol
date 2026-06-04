//! Wallet state manager.
//!
//! Wraps `dom_wallet::WalletDir` — the portable wallet directory that bundles
//! the encrypted wallet file, the transaction journal (WAL), backups and logs.
//! We REUSE all of it; this module just exposes the operations the UI needs and
//! keeps the unlocked handle inside the Rust backend (never the frontend).
//!
//! SECURITY:
//!   * The unlocked `WalletDir` lives only here, behind a `Mutex`. The seed and
//!     keys never cross the Tauri IPC boundary.
//!   * Passwords arrive as `String` from a single command, are used, and the
//!     binding is dropped. We wrap the live copy in `Zeroizing` where we hold
//!     it transiently.
//!   * Seed phrases are only ever returned to the UI on an explicit,
//!     password-gated request (onboarding confirmation / "show seed").

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use dom_crypto::pedersen::Commitment;
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_tx::slate::Slate;
use dom_wallet::{
    Bip39Seed, NodeRpc, NodeRpcClient, ReceiveRequestDescriptor, SeedAcceptance, Wallet, WalletDir,
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

        let seed = Bip39Seed::from_phrase(phrase, SeedAcceptance::AcceptKnown)
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

    /// Build a spend against a recipient receive descriptor (its commitment +
    /// blinding hex) and submit it through the local node RPC. Returns the
    /// tx hash hex on success.
    pub async fn send(
        &self,
        rpc: &NodeRpcClient,
        recipient_commitment_hex: &str,
        recipient_blinding_hex: &str,
        amount: u64,
        fee: u64,
    ) -> Result<String> {
        // Fetch current height from the node first — required by build_spend
        // for coinbase-maturity-aware coin selection.
        let status = rpc.status().map_err(|e| anyhow!("node status: {e}"))?;
        let height = status.chain_height;

        let commitment_bytes = parse_commitment_hex(recipient_commitment_hex)?;
        let blinding = parse_blinding_hex(recipient_blinding_hex)?;

        let mut guard = self.inner.lock().await;
        let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;

        let tx = dir
            .wallet_mut()
            .build_spend(
                Commitment::from_compressed_bytes(&commitment_bytes)
                    .map_err(|e| anyhow!("recipient commitment decode: {e}"))?,
                blinding,
                amount,
                fee,
                height,
            )
            .map_err(|e| anyhow!("build spend: {e}"))?;

        let tx_hash = Wallet::tracking_tx_hash(&tx).map_err(|e| anyhow!("tx hash: {e}"))?;

        match rpc.submit_tx(&tx) {
            Ok(_) => {
                if let Err(e) = dir.wallet_mut().mark_submitted(tx_hash) {
                    tracing::warn!("mark_submitted failed after submit (tx {}): {e}", hex::encode(tx_hash));
                }
                Ok(hex::encode(tx_hash))
            }
            Err(e) => {
                // Roll back the reservation so funds aren't stuck pending.
                let _ = dir.wallet_mut().cancel_tx(tx_hash);
                Err(anyhow!("submit failed: {e}"))
            }
        }
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
        let height = rpc.status().map_err(|e| anyhow!("node status: {e}"))?.chain_height;
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
        let height = rpc.status().map_err(|e| anyhow!("node status: {e}"))?.chain_height;
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
        let height = rpc.status().map_err(|e| anyhow!("node status: {e}"))?.chain_height;
        let slate = slate_from_hex(slate_hex)?;
        let mut guard = self.inner.lock().await;
        let dir = guard.as_mut().ok_or_else(|| anyhow!("no wallet open"))?;

        let tx = dir
            .wallet_mut()
            .finalize_slate(slate, height)
            .map_err(|e| anyhow!("finalize slate: {e}"))?;

        let tx_hash = Wallet::tracking_tx_hash(&tx).map_err(|e| anyhow!("tx hash: {e}"))?;
        match rpc.submit_tx(&tx) {
            Ok(_) => {
                if let Err(e) = dir.wallet_mut().mark_submitted(tx_hash) {
                    tracing::warn!("mark_submitted failed after submit (tx {}): {e}", hex::encode(tx_hash));
                }
                Ok(hex::encode(tx_hash))
            }
            Err(e) => {
                let _ = dir.wallet_mut().cancel_tx(tx_hash);
                Err(anyhow!("submit failed: {e}"))
            }
        }
    }

    /// Verify the password by re-opening the directory. Used to gate the
    /// "show seed" UI.
    ///
    /// IMPORTANT (verified against the crate): `dom-wallet` intentionally does
    /// NOT expose a way to re-derive the BIP-39 *mnemonic words* from an opened
    /// wallet — the encrypted store keeps the seed *bytes*, and `Bip39Seed`'s
    /// `phrase()` is only available at generation/restore time. This is a
    /// deliberate security property. Therefore the only place we can show the
    /// words is onboarding (where we still hold them). This method confirms the
    /// password so the UI can, at most, confirm wallet ownership and guide the
    /// user to their original written-down backup.
    pub async fn verify_password(&self, path: &Path, password: &str) -> Result<()> {
        let _ = WalletDir::open(path, password).map_err(|e| anyhow!("password check: {e}"))?;
        Ok(())
    }

    pub async fn wallet_path(&self) -> Option<PathBuf> {
        self.inner
            .lock()
            .await
            .as_ref()
            .map(|d| d.path().to_path_buf())
    }
}

fn parse_commitment_hex(value: &str) -> Result<[u8; 33]> {
    let bytes = hex::decode(value.trim())?;
    let arr: [u8; 33] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("commitment must be 33 bytes, got {}", v.len()))?;
    Ok(arr)
}

fn parse_blinding_hex(value: &str) -> Result<dom_crypto::BlindingFactor> {
    let bytes = hex::decode(value.trim())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("blinding must be 32 bytes, got {}", v.len()))?;
    dom_crypto::BlindingFactor::from_bytes(arr).map_err(|e| anyhow!("blinding decode: {e}"))
}

// ── Slate (de)serialization for the UI bridge ────────────────────────────────
// The Slate is exchanged as hex text (copy/paste or QR). It contains only
// public data. `to_bytes`/`from_bytes` come from the DomSerialize/DomDeserialize
// traits (dom-serialization).

fn slate_to_hex(slate: &Slate) -> Result<String> {
    let bytes = slate.to_bytes().map_err(|e| anyhow!("slate serialize: {e}"))?;
    Ok(hex::encode(bytes))
}

fn slate_from_hex(value: &str) -> Result<Slate> {
    // Tolerate whitespace/newlines from copy-paste.
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(&cleaned)
        .map_err(|_| anyhow!("invalid slate: not valid hex (corrupted or truncated)"))?;
    Slate::from_bytes(&bytes).map_err(|e| anyhow!("invalid slate: {e}"))
}
