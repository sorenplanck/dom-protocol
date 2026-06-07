//! Tauri command surface.
//!
//! `AppState` is the single shared state injected into every command. It holds
//! the wallet manager, the node host, the log bus, and the live settings. All
//! background tasks (status poller, log re-emitter, auto-lock watcher) read from
//! the same handles.

pub mod logs;
pub mod node;
pub mod settings;
pub mod transactions;
pub mod updater_cmd;
pub mod wallet;

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::log_capture::LogBus;
use crate::node_host::NodeHost;
use crate::settings::NodeSettings;
use crate::wallet_manager::WalletManager;

/// Process-wide shared state, injected via Tauri's managed state.
pub struct AppState {
    pub wallet: WalletManager,
    pub node: NodeHost,
    pub logs: LogBus,
    pub settings: RwLock<NodeSettings>,
    /// Where settings.json lives.
    pub settings_path: PathBuf,
}

impl AppState {
    pub fn new(logs: LogBus, settings: NodeSettings, settings_path: PathBuf) -> Arc<Self> {
        Arc::new(AppState {
            wallet: WalletManager::new(),
            node: NodeHost::new(),
            logs,
            settings: RwLock::new(settings),
            settings_path,
        })
    }

    /// Persist the current settings to disk.
    pub async fn persist_settings(&self) -> crate::error::AppResult<()> {
        let s = self.settings.read().await;
        s.save(&self.settings_path)
    }
}
