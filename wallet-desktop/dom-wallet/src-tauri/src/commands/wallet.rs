//! V1 wallet commands: status, create, recover, open, unlock, lock, balance,
//! show-seed gate, change password.
//!
//! Send/receive/Slate commands are intentionally absent — they are V2 and live
//! (as `Err("not_in_v1")` stubs) in `transactions.rs`.

use std::sync::Arc;

use serde::Serialize;
use tauri::{Emitter, State};
use zeroize::Zeroizing;

use super::AppState;
use crate::error::{AppError, AppResult};
use crate::wallet_manager::LockReason;

/// Snapshot of wallet open/unlock state for the UI router.
#[derive(Serialize)]
pub struct WalletStatus {
    pub exists: bool,
    pub open: bool,
    pub unlocked: bool,
    pub network: Option<String>,
}

/// Result of creating a wallet: the mnemonic shown ONCE for write-down.
#[derive(Serialize)]
pub struct CreatedWallet {
    /// 24-word BIP-39 phrase. The frontend must scrub this after confirmation
    /// and never persist it.
    pub mnemonic: String,
}

fn net_str(n: dom_wallet::Network) -> String {
    match n {
        dom_wallet::Network::Mainnet => "mainnet",
        dom_wallet::Network::Testnet => "testnet",
        dom_wallet::Network::Regtest => "regtest",
    }
    .to_string()
}

/// Does a wallet directory already exist on disk at the configured path?
fn wallet_exists(dir: &std::path::Path) -> bool {
    dir.join(dom_wallet::WALLET_DAT_NAME).exists()
}

#[tauri::command]
pub async fn wallet_status(state: State<'_, Arc<AppState>>) -> AppResult<WalletStatus> {
    let settings = state.settings.read().await;
    let dir = settings.wallet_path();
    let exists = wallet_exists(&dir);
    drop(settings);

    let open = state.wallet.is_open().await;
    let unlocked = state.wallet.is_unlocked().await;
    let network = state.wallet.wallet_network().await.map(net_str);
    Ok(WalletStatus {
        exists,
        open,
        unlocked,
        network,
    })
}

/// Minimal client-side-mirrored password policy (the real KDF lives in the
/// crate; this is a UX gate so weak passwords never reach disk).
fn check_password_strength(pw: &str) -> AppResult<()> {
    if pw.chars().count() < 12 {
        return Err(AppError::WeakPassword(
            "use at least 12 characters".into(),
        ));
    }
    let classes = [
        pw.chars().any(|c| c.is_ascii_lowercase()),
        pw.chars().any(|c| c.is_ascii_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    if classes < 3 {
        return Err(AppError::WeakPassword(
            "mix upper, lower, digits and symbols".into(),
        ));
    }
    Ok(())
}

#[tauri::command]
pub async fn wallet_create(
    state: State<'_, Arc<AppState>>,
    password: String,
) -> AppResult<CreatedWallet> {
    let password = Zeroizing::new(password);
    check_password_strength(&password)?;

    let settings = state.settings.read().await.clone();
    let dir = settings.wallet_path();
    if wallet_exists(&dir) {
        return Err(AppError::Config(
            "a wallet already exists at this location".into(),
        ));
    }

    let mnemonic = state
        .wallet
        .create_new(&dir, &password, &settings)
        .await
        .map_err(AppError::from)?;

    Ok(CreatedWallet {
        mnemonic: mnemonic.to_string(),
    })
}

#[tauri::command]
pub async fn wallet_recover(
    state: State<'_, Arc<AppState>>,
    password: String,
    mnemonic: String,
) -> AppResult<()> {
    let password = Zeroizing::new(password);
    let mnemonic = Zeroizing::new(mnemonic);
    check_password_strength(&password)?;

    let settings = state.settings.read().await.clone();
    let dir = settings.wallet_path();
    if wallet_exists(&dir) {
        return Err(AppError::Config(
            "a wallet already exists at this location".into(),
        ));
    }
    state
        .wallet
        .restore_from_phrase(&dir, &password, &mnemonic, &settings)
        .await
        .map_err(AppError::from)
}

#[tauri::command]
pub async fn wallet_open(state: State<'_, Arc<AppState>>, password: String) -> AppResult<()> {
    let password = Zeroizing::new(password);
    let settings = state.settings.read().await.clone();
    let dir = settings.wallet_path();
    if !wallet_exists(&dir) {
        return Err(AppError::NoWalletOpen);
    }
    state
        .wallet
        .open(&dir, &password)
        .await
        // dom-wallet returns an error on bad password; map to the friendly one.
        .map_err(|_| AppError::BadPassword)
}

#[tauri::command]
pub async fn wallet_unlock(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    password: String,
) -> AppResult<()> {
    let password = Zeroizing::new(password);
    if !state.wallet.is_open().await {
        // Open lazily if a wallet exists on disk but isn't loaded yet.
        let settings = state.settings.read().await.clone();
        let dir = settings.wallet_path();
        if !wallet_exists(&dir) {
            return Err(AppError::NoWalletOpen);
        }
        state
            .wallet
            .open(&dir, &password)
            .await
            .map_err(|_| AppError::BadPassword)?;
    } else {
        state
            .wallet
            .unlock(&password)
            .await
            .map_err(|_| AppError::BadPassword)?;
    }
    let _ = app.emit("wallet://unlocked", ());
    Ok(())
}

#[tauri::command]
pub async fn wallet_lock(state: State<'_, Arc<AppState>>, app: tauri::AppHandle) -> AppResult<()> {
    state.wallet.lock().await.map_err(AppError::from)?;
    let _ = app.emit("wallet://locked", serde_json::json!({ "reason": LockReason::Manual.as_str() }));
    Ok(())
}

#[tauri::command]
pub async fn wallet_balance(state: State<'_, Arc<AppState>>) -> AppResult<crate::wallet_manager::BalanceInfo> {
    state.wallet.touch().await;
    if !state.wallet.is_unlocked().await {
        return Err(AppError::WalletLocked);
    }
    // Use the node's chain height for maturity math; fall back to 0 if the node
    // isn't up yet (balance still computes, immature/mature split may lag).
    let height = match state.node.endpoints().await {
        Some(ep) => crate::rpc_client::status_view(&ep)
            .await
            .map(|s| s.chain_height)
            .unwrap_or(0),
        None => 0,
    };
    state.wallet.balance(height).await.map_err(AppError::from)
}

/// Verify the password (gate for show-seed / change-password). Returns true on
/// match, false on mismatch.
#[tauri::command]
pub async fn wallet_verify_password(
    state: State<'_, Arc<AppState>>,
    password: String,
) -> AppResult<bool> {
    let password = Zeroizing::new(password);
    state
        .wallet
        .verify_password(&password)
        .await
        .map_err(AppError::from)
}
