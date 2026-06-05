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
use tauri::{Emitter, State};
use tauri_plugin_dialog::DialogExt;
use tracing_subscriber::prelude::*;

use log_capture::{BroadcastLayer, LogBus};
use metrics::NodeMetrics;
use node_host::{NodeHost, NodeState};
use settings::NodeSettings;
use wallet_manager::{BalanceInfo, WalletManager};

/// Shared application state, available to every command via `State<AppState>`.
pub struct AppState {
    wallet: Arc<WalletManager>,
    node: Arc<NodeHost>,
    /// Retained so future commands can subscribe to the log bus directly.
    #[allow(dead_code)]
    logs: Arc<LogBus>,
    /// Serializes miner-reward sweeps (L5) so the periodic auto-sweep and the
    /// manual "sweep now" button can never run concurrently and double-spend the
    /// same matured outputs.
    sweep_lock: Arc<tokio::sync::Mutex<()>>,
}

/// Build a `NodeRpcClient` pointed at the embedded node, authenticated with the
/// process bearer token. Returns an error if the node was never started.
async fn rpc_client(state: &AppState) -> Result<NodeRpcClient, String> {
    rpc_client_from_node(&state.node).await
}

async fn rpc_client_from_node(node: &Arc<NodeHost>) -> Result<NodeRpcClient, String> {
    let base = node
        .rpc_base_url()
        .await
        .ok_or_else(|| "node not started yet".to_string())?;
    let url = url::Url::parse(&base).map_err(|e| format!("bad rpc url: {e}"))?;
    NodeRpcClient::builder(url)
        .bearer_token(node.rpc_token().to_string())
        .build()
        .map_err(|e| format!("rpc client: {e}"))
}

/// Parse a noms amount that arrives over the IPC boundary as a STRING (M1).
///
/// Amounts are `u64` noms. JSON numbers lose precision above 2^53, so the UI
/// sends them as decimal strings and we parse them losslessly here.
fn parse_noms(value: &str) -> Result<u64, String> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("invalid amount: {value:?}"))
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
    // L2: do NOT fall back to height 0 on RPC failure — balance(0) marks all
    // coinbase as immature and under-reports the spendable balance. Surface the
    // error instead so the UI shows "balance unavailable" rather than a wrong
    // number.
    let client = rpc_client(&state).await?;
    let height = client.status().map_err(|e| e.to_string())?.chain_height;
    state
        .wallet
        .balance(height)
        .await
        .map_err(|e| e.to_string())
}

// NOTE (L8): the non-interactive `wallet_send` / `wallet_create_receive`
// commands were removed. The wallet's only send/receive path is the interactive
// Slate protocol below (`slate_create_send` / `slate_receive` / `slate_finalize`).
// The internal `WalletManager::create_receive` is still used by the miner-reward
// auto-sweep (see `do_sweep`), but it is not exposed as a UI command.

// ── Slate protocol commands (interactive person-to-person) ───────────────────

/// Step 1 (sender): create a send slate. `amount`/`fee` are decimal-string noms
/// (M1: strings avoid the JSON 2^53 precision loss). Returns hex.
#[tauri::command]
async fn slate_create_send(
    state: State<'_, AppState>,
    amount: String,
    fee: String,
) -> Result<String, String> {
    let amount = parse_noms(&amount)?;
    let fee = parse_noms(&fee)?;
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
    state
        .wallet
        .verify_password(&password)
        .await
        .map_err(|e| e.to_string())
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

/// Max bytes we will write to a user-chosen text file (logs / slate export).
const MAX_SAVE_BYTES: usize = 16 * 1024 * 1024;
/// Max bytes we will read from a user-chosen text file (slate import).
const MAX_READ_BYTES: u64 = 4 * 1024 * 1024;

/// Save plain text to a file (M4). The native save dialog is opened HERE, in
/// the backend, so the renderer never supplies a path — closing the
/// arbitrary-file-write hole. Returns `true` if saved, `false` if the user
/// cancelled the dialog.
#[tauri::command]
async fn save_text_file(
    app: tauri::AppHandle,
    title: String,
    default_name: String,
    contents: String,
) -> Result<bool, String> {
    if contents.len() > MAX_SAVE_BYTES {
        return Err("content too large to save".into());
    }
    let picked = app
        .dialog()
        .file()
        .set_title(&title)
        .set_file_name(&default_name)
        .add_filter("Text", &["txt"])
        .blocking_save_file();
    let path = match picked {
        Some(fp) => fp.into_path().map_err(|e| format!("invalid path: {e}"))?,
        None => return Ok(false),
    };
    std::fs::write(&path, contents).map_err(|e| format!("io error: {e}"))?;
    Ok(true)
}

/// Read a UTF-8 text file (M4). The native open dialog is opened HERE, in the
/// backend; the renderer never supplies a path. Returns `None` if the user
/// cancelled. Bounded to avoid loading a huge file by mistake.
#[tauri::command]
async fn read_text_file(app: tauri::AppHandle, title: String) -> Result<Option<String>, String> {
    let picked = app.dialog().file().set_title(&title).blocking_pick_file();
    let path = match picked {
        Some(fp) => fp.into_path().map_err(|e| format!("invalid path: {e}"))?,
        None => return Ok(None),
    };
    let meta = std::fs::metadata(&path).map_err(|e| format!("io error: {e}"))?;
    if meta.len() > MAX_READ_BYTES {
        return Err("file too large".into());
    }
    std::fs::read_to_string(&path)
        .map(Some)
        .map_err(|e| format!("io error: {e}"))
}

// ── Node commands ───────────────────────────────────────────────────────────

/// M2: refuse to (re)start the embedded node on a network that doesn't match
/// the currently-open wallet. A testnet wallet driven by a mainnet node (or
/// vice-versa) would silently show an inconsistent balance/genesis view.
async fn ensure_wallet_network_matches(
    state: &AppState,
    settings: &NodeSettings,
) -> Result<(), String> {
    if let Some(wallet_net) = state.wallet.wallet_network().await {
        if !settings.matches_wallet_network(wallet_net) {
            return Err(format!(
                "network mismatch: the open wallet is {:?} but the selected network is {:?}",
                wallet_net, settings.network
            ));
        }
    }
    Ok(())
}

#[tauri::command]
async fn node_start(state: State<'_, AppState>, settings: NodeSettings) -> Result<(), String> {
    ensure_wallet_network_matches(&state, &settings).await?;
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
    if let Some(s) = &settings {
        ensure_wallet_network_matches(&state, s).await?;
    }
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

/// L6: only allow scraping a loopback metrics endpoint. The address comes from
/// the frontend, so without this guard a compromised renderer could turn this
/// command into an SSRF primitive against arbitrary hosts. The node's metrics
/// endpoint is always local (default 127.0.0.1:33371).
fn require_loopback_addr(addr: &str) -> Result<(), String> {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    let host = host.trim().trim_matches(|c| c == '[' || c == ']');
    if matches!(host, "127.0.0.1" | "localhost" | "::1") {
        Ok(())
    } else {
        Err(format!("refusing non-loopback metrics address: {addr}"))
    }
}

#[tauri::command]
async fn node_metrics(state: State<'_, AppState>, addr: String) -> Result<NodeMetrics, String> {
    let _ = state; // metrics are read directly from the local endpoint
    require_loopback_addr(&addr)?;
    // Run the blocking scrape off the async runtime worker.
    tauri::async_runtime::spawn_blocking(move || metrics::fetch_metrics(&addr))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

const AUTO_SWEEP_INTERVAL_SECS: u64 = 60;
const MINER_SWEEP_FEE_NOMS: u64 = 100_000; // 0.00100000 DOM

/// Move mature rewards from the embedded node miner wallet into the currently
/// open user wallet. Returns Some(tx_hash_hex) when a sweep was submitted,
/// or None when there is no mature balance above the sweep fee.
async fn do_sweep(
    node: Arc<NodeHost>,
    wallet: Arc<WalletManager>,
    sweep_lock: Arc<tokio::sync::Mutex<()>>,
) -> Result<Option<String>, String> {
    // L5: if a sweep is already in progress, skip rather than queue — two
    // concurrent sweeps would read the same matured balance and try to spend
    // the same outputs twice.
    let _guard = match sweep_lock.try_lock() {
        Ok(g) => g,
        Err(_) => return Ok(None),
    };
    if !wallet.is_open().await || !wallet.is_unlocked().await {
        return Ok(None);
    }

    let rpc_addr = match node.rpc_listen_addr().await {
        Some(addr) => addr,
        None => return Ok(None),
    };

    let balance = {
        let token = node.rpc_token().to_string();
        tauri::async_runtime::spawn_blocking(move || {
            metrics::fetch_node_wallet_balance(&rpc_addr, &token)
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?
    };

    if balance.confirmed_noms <= MINER_SWEEP_FEE_NOMS {
        return Ok(None);
    }

    let amount = balance.confirmed_noms - MINER_SWEEP_FEE_NOMS;
    let receive = wallet
        .create_receive(amount)
        .await
        .map_err(|e| e.to_string())?;

    let client = rpc_client_from_node(&node).await?;
    let outcome = client
        .wallet_spend(
            receive.commitment_hex,
            receive.blinding_hex,
            amount,
            MINER_SWEEP_FEE_NOMS,
        )
        .map_err(|e| format!("node wallet spend: {e}"))?;

    Ok(Some(hex::encode(outcome.tx_hash)))
}

#[tauri::command]
async fn sweep_miner_rewards(state: State<'_, AppState>) -> Result<Option<String>, String> {
    do_sweep(
        state.node.clone(),
        state.wallet.clone(),
        state.sweep_lock.clone(),
    )
    .await
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
            // OS RNG unavailable — without an RPC token there is no safe way to
            // operate. Log it readably and exit without panicking.
            tracing::error!("failed to start the node host: {e}");
            eprintln!("DOM Wallet could not start: {e}");
            std::process::exit(1);
        }
    };

    let wallet = Arc::new(WalletManager::new());
    let sweep_lock = Arc::new(tokio::sync::Mutex::new(()));

    let state = AppState {
        wallet: wallet.clone(),
        node: node.clone(),
        logs: bus.clone(),
        sweep_lock: sweep_lock.clone(),
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

            // Best-effort miner reward auto-sweep. It only runs when mining is
            // enabled, a user wallet is open/unlocked, and the node miner wallet
            // reports mature balance above the fixed sweep fee. Errors are logged
            // but never block the UI.
            let sweep_node = node.clone();
            let sweep_wallet = wallet.clone();
            let sweep_lock = sweep_lock.clone();
            tauri::async_runtime::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(AUTO_SWEEP_INTERVAL_SECS));
                loop {
                    interval.tick().await;
                    if !sweep_node.is_mining_enabled().await {
                        continue;
                    }
                    match do_sweep(sweep_node.clone(), sweep_wallet.clone(), sweep_lock.clone())
                        .await
                    {
                        Ok(Some(tx)) => tracing::info!("auto-swept miner rewards to wallet: {tx}"),
                        Ok(None) => {}
                        Err(e) => tracing::debug!("auto-sweep skipped/failed: {e}"),
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
            sweep_miner_rewards,
            default_settings,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            tracing::error!("fatal error running DOM Wallet: {e}");
            eprintln!("Fatal error running DOM Wallet: {e}");
            std::process::exit(1);
        });
}
