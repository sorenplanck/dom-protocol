//! V1 node commands: start, stop, restart, status, mining toggle.
//!
//! These orchestrate the embedded node via `NodeHost`. The node is the source
//! of truth for consensus; the wallet only reads from it.

use std::sync::Arc;

use serde::Serialize;
use tauri::{Emitter, State};
use zeroize::Zeroizing;

use super::AppState;
use crate::error::{AppError, AppResult};
use crate::rpc_client::NodeStatusView;

#[derive(Serialize)]
pub struct NodeRunning {
    pub running: bool,
    pub rpc_port: Option<u16>,
    pub p2p_addr: Option<String>,
}

fn port_of(addr: &str) -> Option<u16> {
    addr.rsplit(':').next().and_then(|p| p.parse().ok())
}

#[tauri::command]
pub async fn node_is_running(state: State<'_, Arc<AppState>>) -> AppResult<NodeRunning> {
    let running = state.node.is_running().await;
    let ep = state.node.endpoints().await;
    Ok(NodeRunning {
        running,
        rpc_port: ep.as_ref().and_then(|e| port_of(&e.rpc_base_url)),
        p2p_addr: ep.map(|e| e.p2p_listen_addr),
    })
}

/// Start the embedded node using current settings and the open wallet's path.
/// The wallet must be unlocked so its password can be handed to the node for
/// coinbase crediting, and its network must match the settings network.
#[tauri::command]
pub async fn node_start(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    wallet_password: String,
) -> AppResult<()> {
    let wallet_password = Zeroizing::new(wallet_password);

    if state.node.is_running().await {
        return Err(AppError::NodeAlreadyRunning);
    }
    let settings = state.settings.read().await.clone();
    settings.validate()?;

    // Refuse to start the node on a network that disagrees with the open wallet
    // (prevents crediting coinbase to a wallet from another network).
    if let Some(wnet) = state.wallet.wallet_network().await {
        let want = settings.wallet_network();
        if std::mem::discriminant(&wnet) != std::mem::discriminant(&want) {
            return Err(AppError::Config(format!(
                "open wallet is on a different network than settings ({})",
                settings.network
            )));
        }
    }

    let wallet_path = state
        .wallet
        .wallet_path()
        .await
        .map(|p| p.to_string_lossy().into_owned());

    let endpoints = state
        .node
        .start(&settings, wallet_path, Some(wallet_password))
        .await
        .map_err(AppError::from)?;

    let _ = app.emit(
        "node://started",
        serde_json::json!({
            "rpc_port": port_of(&endpoints.rpc_base_url),
            "p2p_port": port_of(&endpoints.p2p_listen_addr),
        }),
    );
    Ok(())
}

#[tauri::command]
pub async fn node_stop(state: State<'_, Arc<AppState>>, app: tauri::AppHandle) -> AppResult<()> {
    state.node.stop().await.map_err(AppError::from)?;
    let _ = app.emit("node://stopped", serde_json::json!({ "reason": "user" }));
    Ok(())
}

#[tauri::command]
pub async fn node_restart(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    wallet_password: String,
) -> AppResult<()> {
    let wallet_password = Zeroizing::new(wallet_password);
    do_restart(state.inner(), &app, wallet_password).await
}

/// Shared restart implementation used by `node_restart` and `node_set_mining`.
async fn do_restart(
    state: &Arc<AppState>,
    app: &tauri::AppHandle,
    wallet_password: Zeroizing<String>,
) -> AppResult<()> {
    let settings = state.settings.read().await.clone();
    settings.validate()?;
    let wallet_path = state
        .wallet
        .wallet_path()
        .await
        .map(|p| p.to_string_lossy().into_owned());
    let endpoints = state
        .node
        .restart(&settings, wallet_path, Some(wallet_password))
        .await
        .map_err(AppError::from)?;
    let _ = app.emit(
        "node://started",
        serde_json::json!({
            "rpc_port": port_of(&endpoints.rpc_base_url),
            "p2p_port": port_of(&endpoints.p2p_listen_addr),
        }),
    );
    Ok(())
}

/// Current node status (chain height, peers, mining, hashrate, mempool).
#[tauri::command]
pub async fn node_status(state: State<'_, Arc<AppState>>) -> AppResult<NodeStatusView> {
    let ep = state
        .node
        .endpoints()
        .await
        .ok_or(AppError::NodeNotRunning)?;
    crate::rpc_client::status_view(&ep)
        .await
        .map_err(|e| AppError::Rpc(e.to_string()))
}

/// Toggle mining. This persists the preference and restarts the node so the new
/// `DOM_MINE` value takes effect (the node reads it at init). Requires the
/// wallet password to re-credit coinbase on restart.
#[tauri::command]
pub async fn node_set_mining(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    enabled: bool,
    wallet_password: String,
) -> AppResult<()> {
    {
        let mut s = state.settings.write().await;
        s.mining_enabled = enabled;
    }
    state.persist_settings().await?;

    // If the node is running, restart to apply. Otherwise the new value applies
    // at next start.
    if state.node.is_running().await {
        let pw = Zeroizing::new(wallet_password);
        do_restart(state.inner(), &app, pw).await?;
    }
    Ok(())
}
