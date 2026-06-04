//! DOM Wallet desktop — Tauri backend.
//!
//! Bridges the UI to the reused DOM crates (`dom-wallet`, `dom-node`,
//! `dom-rpc`, …) and hosts the embedded full node. No crypto, consensus, P2P
//! or wallet logic is reimplemented here.

mod log_capture;
mod metrics;
mod node_host;
mod settings;
mod wallet_manager;

use std::sync::Arc;

use dom_wallet::{NodeRpc, NodeRpcClient};
use tauri::{Emitter, Manager, State};
use tracing_subscriber::prelude::*;

use log_capture::{BroadcastLayer, LogBus};
use metrics::NodeMetrics;
use node_host::{NodeHost, NodeState};
use settings::NodeSettings;
use wallet_manager::{BalanceInfo, ReceiveInfo, WalletManager};

/// Shared application state, available to every command via `State<AppState>`.
pub struct AppState {
    wallet: WalletManager,
    node: Arc<NodeHost>,
    /// Retained so future commands can subscribe to the log bus directly.
    #[allow(dead_code)]
    logs: Arc<LogBus>,
}

/// Build a `NodeRpcClient` pointed at the embedded node, authenticated with the
/// process bearer token. Returns an error if the node was never started.
async fn rpc_client(state: &AppState) -> Result<NodeRpcClient, String> {
    let base = state
        .node
        .rpc_base_url()
        .await
        .ok_or_else(|| "node not started yet".to_string())?;
    let url = url::Url::parse(&base).map_err(|e| format!("bad rpc url: {e}"))?;
    NodeRpcClient::builder(url)
        .bearer_token(state.node.rpc_token().to_string())
        .build()
        .map_err(|e| format!("rpc client: {e}"))
}

// ── Wallet commands ───────────────────────────────────────────────────────────

#[tauri::command]
async fn wallet_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "open": state.wallet.is_open().await,
        "unlocked": state.wallet.is_unlocked().await,
    }))
}

/// Create a new wallet. Returns the BIP-39 phrase ONCE for the user to record.
/// The frontend must force write-down + confirmation and must not persist it.
#[tauri::command]
async fn wallet_create(
    state: State<'_, AppState>,
    path: String,
    password: String,
    settings: NodeSettings,
) -> Result<String, String> {
    let phrase = state
        .wallet
        .create_new(std::path::Path::new(&path), &password, &settings)
        .await
        .map_err(|e| e.to_string())?;
    // `phrase` is Zeroizing<String>; clone the inner words out for the one-time
    // return, then both copies drop/zeroize at end of scope.
    Ok(phrase.to_string())
}

#[tauri::command]
async fn wallet_restore(
    state: State<'_, AppState>,
    path: String,
    password: String,
    phrase: String,
    settings: NodeSettings,
) -> Result<(), String> {
    state
        .wallet
        .restore_from_phrase(std::path::Path::new(&path), &password, &phrase, &settings)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_open(
    state: State<'_, AppState>,
    path: String,
    password: String,
) -> Result<(), String> {
    state
        .wallet
        .open(std::path::Path::new(&path), &password)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_lock(state: State<'_, AppState>) -> Result<(), String> {
    state.wallet.lock().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_unlock(state: State<'_, AppState>, password: String) -> Result<(), String> {
    state
        .wallet
        .unlock(&password)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_balance(state: State<'_, AppState>) -> Result<BalanceInfo, String> {
    // Height from the node so maturity is computed correctly.
    let client = rpc_client(&state).await?;
    let height = client.status().map(|s| s.chain_height).unwrap_or(0);
    state.wallet.balance(height).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_create_receive(
    state: State<'_, AppState>,
    amount: u64,
) -> Result<ReceiveInfo, String> {
    state
        .wallet
        .create_receive(amount)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_send(
    state: State<'_, AppState>,
    recipient_commitment_hex: String,
    recipient_blinding_hex: String,
    amount: u64,
    fee: u64,
) -> Result<String, String> {
    let client = rpc_client(&state).await?;
    state
        .wallet
        .send(
            &client,
            &recipient_commitment_hex,
            &recipient_blinding_hex,
            amount,
            fee,
        )
        .await
        .map_err(|e| e.to_string())
}

// ── Slate protocol commands (interactive person-to-person) ───────────────────

/// Step 1 (sender): create a send slate. `amount`/`fee` in noms. Returns hex.
#[tauri::command]
async fn slate_create_send(
    state: State<'_, AppState>,
    amount: u64,
    fee: u64,
) -> Result<String, String> {
    let client = rpc_client(&state).await?;
    state
        .wallet
        .slate_create_send(&client, amount, fee)
        .await
        .map_err(|e| e.to_string())
}

/// Step 2 (recipient): import sender's slate (hex), respond, return responded hex.
#[tauri::command]
async fn slate_receive(state: State<'_, AppState>, slate_hex: String) -> Result<String, String> {
    let client = rpc_client(&state).await?;
    state
        .wallet
        .slate_receive(&client, &slate_hex)
        .await
        .map_err(|e| e.to_string())
}

/// Step 3 (sender): import responded slate (hex), finalize + submit. Returns tx hash hex.
#[tauri::command]
async fn slate_finalize(state: State<'_, AppState>, slate_hex: String) -> Result<String, String> {
    let client = rpc_client(&state).await?;
    state
        .wallet
        .slate_finalize(&client, &slate_hex)
        .await
        .map_err(|e| e.to_string())
}

/// Verify the password (gate for the "show seed" UI). See WalletManager docs:
/// the mnemonic words themselves cannot be re-derived after creation.
#[tauri::command]
async fn wallet_verify_password(
    state: State<'_, AppState>,
    password: String,
) -> Result<bool, String> {
    let path = state
        .wallet
        .wallet_path()
        .await
        .ok_or_else(|| "no wallet open".to_string())?;
    match state.wallet.verify_password(&path, &password).await {
        Ok(()) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

/// Generate an SVG QR code for an arbitrary string (the receive address).
#[tauri::command]
fn make_qr_svg(data: String) -> Result<String, String> {
    use qrcode::render::svg;
    use qrcode::QrCode;
    let code = QrCode::new(data.as_bytes()).map_err(|e| e.to_string())?;
    let svg = code
        .render::<svg::Color<'_>>()
        .min_dimensions(220, 220)
        .dark_color(svg::Color("#1c130c"))
        .light_color(svg::Color("#d8b483"))
        .build();
    Ok(svg)
}

/// Write plain text to a file chosen by the user. Used by "Save logs".
/// This touches only the path the user explicitly picked via the dialog.
#[tauri::command]
fn save_text_file(path: String, contents: String) -> Result<(), String> {
    std::fs::write(&path, contents).map_err(|e| format!("io error: {e}"))
}

/// Read a UTF-8 text file the user explicitly picked (for importing a slate).
/// Bounded to avoid loading a huge file by mistake.
#[tauri::command]
fn read_text_file(path: String) -> Result<String, String> {
    let meta = std::fs::metadata(&path).map_err(|e| format!("io error: {e}"))?;
    if meta.len() > 4 * 1024 * 1024 {
        return Err("file too large".into());
    }
    std::fs::read_to_string(&path).map_err(|e| format!("io error: {e}"))
}

// ── Node commands ───────────────────────────────────────────────────────────

#[tauri::command]
async fn node_start(state: State<'_, AppState>, settings: NodeSettings) -> Result<(), String> {
    state.node.start(settings).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn node_stop(state: State<'_, AppState>) -> Result<(), String> {
    state.node.stop().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn node_restart(
    state: State<'_, AppState>,
    settings: Option<NodeSettings>,
) -> Result<(), String> {
    state
        .node
        .restart(settings)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn node_state(state: State<'_, AppState>) -> Result<NodeState, String> {
    Ok(state.node.state().await)
}

/// Combined node status: chain height / network / mempool from RPC, plus
/// peer count and mining flag from Prometheus metrics.
#[tauri::command]
async fn node_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let mut out = serde_json::json!({ "state": state.node.state().await });

    if let Ok(client) = rpc_client(&state).await {
        if let Ok(s) = client.status() {
            out["chain_height"] = serde_json::json!(s.chain_height);
            out["mempool_size"] = serde_json::json!(s.mempool_size);
            out["network"] = serde_json::json!(s.network);
            out["version"] = serde_json::json!(s.version);
        }
    }
    Ok(out)
}

#[tauri::command]
async fn node_metrics(state: State<'_, AppState>, addr: String) -> Result<NodeMetrics, String> {
    let _ = state; // metrics are read directly from the local endpoint
    // Run the blocking scrape off the async runtime worker.
    tauri::async_runtime::spawn_blocking(move || metrics::fetch_metrics(&addr))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn default_settings() -> NodeSettings {
    NodeSettings::default()
}

/// Entry point used by both desktop `main.rs` and any test harness.
pub fn run() {
    // ── Tracing: install our broadcast layer alongside a console layer so the
    // node's logs reach both the terminal (dev) and the UI's Node/Logs tab.
    let bus = Arc::new(LogBus::new(2048));
    let filter = tracing_subscriber::EnvFilter::try_from_env("DOM_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(BroadcastLayer::new(bus.clone()))
        .init();

    let node = match NodeHost::new() {
        Ok(n) => Arc::new(n),
        Err(e) => {
            // RNG do SO indisponível — sem token RPC não há como operar com
            // segurança. Logamos de forma legível e encerramos sem panic.
            tracing::error!("falha ao iniciar o host do nó: {e}");
            eprintln!("DOM Wallet não pôde iniciar: {e}");
            std::process::exit(1);
        }
    };

    let state = AppState {
        wallet: WalletManager::new(),
        node: node.clone(),
        logs: bus.clone(),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(state)
        .setup(move |app| {
            // Pump log lines from the broadcast bus to the frontend as
            // "node-log" events. One background task for the app's lifetime.
            let handle = app.handle().clone();
            let mut rx = bus.subscribe();
            tauri::async_runtime::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(line) => {
                            let _ = handle.emit("node-log", line);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            // UI fell behind; keep going with newer lines.
                            continue;
                        }
                        Err(_) => break,
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            wallet_status,
            wallet_create,
            wallet_restore,
            wallet_open,
            wallet_lock,
            wallet_unlock,
            wallet_balance,
            wallet_create_receive,
            wallet_send,
            slate_create_send,
            slate_receive,
            slate_finalize,
            wallet_verify_password,
            make_qr_svg,
            save_text_file,
            read_text_file,
            node_start,
            node_stop,
            node_restart,
            node_state,
            node_status,
            node_metrics,
            default_settings,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            tracing::error!("erro fatal ao executar a DOM Wallet: {e}");
            eprintln!("Erro fatal ao executar a DOM Wallet: {e}");
            std::process::exit(1);
        });
}
