//! DOM Wallet (V1) — Tauri application entry point.
//!
//! Wires together:
//!   * tracing → live-log capture layer (Node tab stream)
//!   * shared `AppState` (wallet manager, node host, log bus, settings)
//!   * all V1 Tauri commands (+ V2 placeholders)
//!   * background tasks: node status poller, auto-lock watcher, log forwarder,
//!     startup update check
//!
//! Single process, separate async tasks (Principle 1). The wallet observes the
//! node, never drives it (Principle 2).

mod commands;
mod descriptor;
mod error;
mod log_capture;
mod node_host;
mod pending;
mod rpc_client;
mod settings;
mod slatepack;
mod updater;
mod wallet_manager;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tauri::{Emitter, Manager};
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

use commands::AppState;
use log_capture::LogBus;
use settings::NodeSettings;
use wallet_manager::LockReason;

/// Resolve the settings.json path under the OS app-config dir, with a HOME
/// fallback so the backend works even before Tauri's path API is available.
fn settings_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        PathBuf::from(dir).join(".dom-wallet").join("settings.json")
    } else {
        PathBuf::from(".dom-wallet").join("settings.json")
    }
}

/// Initialise tracing with our capture layer plus a console fmt layer. Returns
/// the `LogBus` the rest of the app subscribes to.
fn init_tracing() -> LogBus {
    let (bus, layer) = LogBus::new();
    let filter = EnvFilter::try_from_env("DOM_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    // The capture layer feeds the UI; the fmt layer is for the dev console.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .try_init();
    bus
}

/// Background: poll node status every ~1.5s and emit `node://status`.
fn spawn_status_poller(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(1500));
        loop {
            tick.tick().await;
            if !state.node.is_running().await {
                continue;
            }
            if let Some(ep) = state.node.endpoints().await {
                match rpc_client::status_view(&ep).await {
                    Ok(view) => {
                        let _ = app.emit("node://status", &view);
                    }
                    Err(e) => tracing::debug!("status poll failed: {e}"),
                }
            }
        }
    });
}

/// Background: auto-lock watcher. If a timeout is set and idle time exceeds it,
/// lock the wallet and emit `wallet://locked` with reason "timeout".
fn spawn_autolock(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(20));
        loop {
            tick.tick().await;
            let minutes = { state.settings.read().await.auto_lock_minutes };
            let Some(minutes) = minutes else { continue };
            if !state.wallet.is_unlocked().await {
                continue;
            }
            if state.wallet.idle_exceeds(minutes).await {
                if state.wallet.lock().await.is_ok() {
                    tracing::info!("wallet auto-locked after {minutes} min idle");
                    let _ = app.emit(
                        "wallet://locked",
                        serde_json::json!({ "reason": LockReason::Timeout.as_str() }),
                    );
                }
            }
        }
    });
}

/// Background: one-shot startup update check; emits `update://available` if a
/// newer non-draft release exists.
fn spawn_update_check(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        match updater::check(env!("CARGO_PKG_VERSION")).await {
            Ok(info) if info.newer => {
                let _ = app.emit("update://available", &info);
            }
            Ok(_) => {}
            Err(e) => tracing::debug!("startup update check failed: {e}"),
        }
    });
}

/// Run the Tauri application.
pub fn run() {
    let bus = init_tracing();
    let spath = settings_path();
    let settings = NodeSettings::load(&spath);
    let state = AppState::new(bus, settings, spath);

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(state.clone())
        .setup(move |app| {
            let handle = app.handle().clone();
            // Forward live logs to the UI.
            commands::logs::spawn_forwarder(handle.clone(), state.clone());
            // Periodic node status.
            spawn_status_poller(handle.clone(), state.clone());
            // Auto-lock watcher.
            spawn_autolock(handle.clone(), state.clone());
            // V2: background expiry sweep for slates/descriptors.
            crate::pending::expiry::spawn(handle.clone(), state.clone());
            // Update check.
            spawn_update_check(handle.clone());
            tracing::info!("DOM Wallet v{} started", env!("CARGO_PKG_VERSION"));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // wallet
            commands::wallet::wallet_status,
            commands::wallet::wallet_create,
            commands::wallet::wallet_recover,
            commands::wallet::wallet_open,
            commands::wallet::wallet_unlock,
            commands::wallet::wallet_lock,
            commands::wallet::wallet_balance,
            commands::wallet::wallet_verify_password,
            // node
            commands::node::node_is_running,
            commands::node::node_start,
            commands::node::node_stop,
            commands::node::node_restart,
            commands::node::node_status,
            commands::node::node_set_mining,
            // logs
            commands::logs::logs_snapshot,
            commands::logs::logs_export,
            // settings
            commands::settings::settings_get,
            commands::settings::settings_update,
            commands::settings::settings_available_cores,
            commands::settings::settings_export_backup,
            commands::settings::settings_change_password,
            // updates
            commands::updater_cmd::updates_check,
            // V2 — Slatepack (Mode A)
            commands::transactions::slatepack_get_address,
            commands::transactions::slatepack_generate_new_address,
            commands::transactions::slatepack_create_send,
            commands::transactions::slatepack_receive,
            commands::transactions::slatepack_respond,
            commands::transactions::slatepack_finalize,
            // V2 — Simple (Mode B)
            commands::transactions::simple_create_receive_request,
            commands::transactions::simple_parse_descriptor,
            commands::transactions::simple_send_to_descriptor,
            commands::transactions::simple_cancel_descriptor,
            // V2 — shared
            commands::transactions::cancel_pending_tx,
            commands::transactions::list_pending_txs,
            commands::transactions::get_full_transaction_history,
        ])
        .run(tauri::generate_context!())
        .expect("error while running DOM Wallet");
}
