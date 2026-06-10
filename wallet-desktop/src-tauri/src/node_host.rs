//! Hosts the embedded DOM full node *inside* the wallet process.
//!
//! Lifecycle model (mirrors `dom-node`'s own `main.rs`):
//!   1. Build a `dom_config::NodeConfig` for the chosen network.
//!   2. Apply the settings the user controls in the UI (seed peers, ports,
//!      data dir, mining toggle, miner wallet) — exactly the same fields the
//!      stock node reads from its `DOM_*` environment variables. We pass them
//!      ONLY through the strongly-typed `NodeConfig`; we do NOT export any
//!      `DOM_*` process-global env var (H1/M5): `std::env::set_var` is not
//!      thread-safe against the running Tokio threads, and exporting
//!      `DOM_WALLET_PASSWORD` would leak the miner-wallet secret into the
//!      process environment. See `settings::to_node_config`.
//!   3. `DomNode::init(config)` then `Arc::new(node).run().await` on a Tokio
//!      task. `request_shutdown()` stops it; dropping + re-initing restarts it.
//!
//! RPC token: we generate a process-local bearer token and pass it through the
//! embedded node config, then hand the same value to the wallet's `NodeRpcClient`.
//! We do not export it through process-global environment variables.

use std::sync::Arc;

use anyhow::{anyhow, Context as _, Result};
use dom_node::node::DomNode;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::settings::NodeSettings;

/// Coarse-grained node state shown in the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeState {
    Stopped,
    Starting,
    Running,
    Stopping,
}

/// Everything we keep about a running (or stopped) node instance.
pub struct NodeHost {
    inner: Mutex<HostInner>,
    /// Bearer token for the local RPC. Generated once per process; reused on
    /// restart so the wallet's RPC client keeps working.
    rpc_token: String,
}

struct HostInner {
    state: NodeState,
    node: Option<Arc<DomNode>>,
    task: Option<JoinHandle<()>>,
    /// Last config used to start, so "restart" reuses it.
    last_settings: Option<NodeSettings>,
}

impl NodeHost {
    pub fn new() -> Result<Self> {
        // Generate a strong random token once. dom-rpc's own generator yields a
        // 64-char hex token; we match that shape.
        let token = generate_token()?;
        Ok(Self {
            inner: Mutex::new(HostInner {
                state: NodeState::Stopped,
                node: None,
                task: None,
                last_settings: None,
            }),
            rpc_token: token,
        })
    }

    pub fn rpc_token(&self) -> &str {
        &self.rpc_token
    }

    pub async fn state(&self) -> NodeState {
        self.inner.lock().await.state
    }

    /// The RPC base URL derived from the last-applied settings, e.g.
    /// `http://127.0.0.1:33372`. Returns None if never started.
    pub async fn rpc_base_url(&self) -> Option<String> {
        let inner = self.inner.lock().await;
        inner
            .last_settings
            .as_ref()
            .map(|s| format!("http://{}", s.rpc_listen_addr))
    }

    /// The raw RPC listen address (host:port, no scheme), e.g. "127.0.0.1:33372".
    /// Used by the auto-sweep to read the node wallet balance endpoint.
    pub async fn rpc_listen_addr(&self) -> Option<String> {
        let inner = self.inner.lock().await;
        inner
            .last_settings
            .as_ref()
            .map(|s| s.rpc_listen_addr.clone())
    }

    /// Whether the last-applied settings have mining enabled.
    pub async fn is_mining_enabled(&self) -> bool {
        let inner = self.inner.lock().await;
        inner
            .last_settings
            .as_ref()
            .map(|s| s.mine)
            .unwrap_or(false)
    }

    /// Start the node with the given settings. No-op (Ok) if already running.
    pub async fn start(&self, settings: NodeSettings) -> Result<()> {
        let mut inner = self.inner.lock().await;
        if matches!(inner.state, NodeState::Running | NodeState::Starting) {
            return Ok(());
        }
        inner.state = NodeState::Starting;

        // All configuration is passed via the strongly-typed NodeConfig below,
        // including the RPC bearer token. No DOM_* secret is exported through
        // process-global environment variables.
        let config = settings.to_node_config(Some(self.rpc_token.clone()))?;
        inner.last_settings = Some(settings);

        // Initialize the node (opens LMDB, verifies the H generator, etc.).
        // This is synchronous and can fail fast — surface the error to the UI.
        let node = Arc::new(DomNode::init(config).map_err(|e| anyhow!("node init failed: {e}"))?);

        let run_node = node.clone();
        let task = tokio::spawn(async move {
            if let Err(e) = run_node.run().await {
                tracing::error!("embedded node exited with error: {e}");
            } else {
                tracing::info!("embedded node stopped cleanly");
            }
        });

        inner.node = Some(node);
        inner.task = Some(task);
        inner.state = NodeState::Running;
        tracing::info!("embedded DOM node started");
        Ok(())
    }

    /// Request a graceful shutdown and wait for the run task to finish.
    pub async fn stop(&self) -> Result<()> {
        let (node, task) = {
            let mut inner = self.inner.lock().await;
            if matches!(inner.state, NodeState::Stopped | NodeState::Stopping) {
                return Ok(());
            }
            inner.state = NodeState::Stopping;
            (inner.node.take(), inner.task.take())
        };

        if let Some(node) = node {
            node.request_shutdown().await;
        }
        if let Some(task) = task {
            // Bounded wait so a hung node can't freeze the UI thread forever.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(20), task).await;
        }

        let mut inner = self.inner.lock().await;
        inner.state = NodeState::Stopped;
        tracing::info!("embedded DOM node shut down");
        Ok(())
    }

    /// Make sure the node is running with EXACTLY these settings.
    ///
    /// * stopped → start;
    /// * running with the same settings → no-op;
    /// * running with different settings (e.g. another wallet's node dir or
    ///   ports) → restart on the new settings.
    ///
    /// This is what wallet open/switch uses: a plain `start` is a no-op while
    /// running, which would silently leave the PREVIOUS wallet's node (and its
    /// chain data dir) serving the newly opened wallet.
    pub async fn ensure(&self, settings: NodeSettings) -> Result<()> {
        let needs_restart = {
            let inner = self.inner.lock().await;
            match inner.state {
                NodeState::Stopped | NodeState::Stopping => false,
                NodeState::Running | NodeState::Starting => {
                    inner.last_settings.as_ref() != Some(&settings)
                }
            }
        };
        if needs_restart {
            self.restart(Some(settings)).await
        } else {
            self.start(settings).await
        }
    }

    /// Stop then start again with the last-used (or new) settings.
    pub async fn restart(&self, settings: Option<NodeSettings>) -> Result<()> {
        let settings = match settings {
            Some(s) => s,
            None => self
                .inner
                .lock()
                .await
                .last_settings
                .clone()
                .context("no previous settings to restart with")?,
        };
        self.stop().await?;
        self.start(settings).await
    }
}

/// 64-char lowercase hex token, matching dom-rpc's own token shape.
/// Uses the OS CSPRNG via `getrandom`. Returns an error instead of panicking
/// if the OS RNG is unavailable, so the UI can surface it gracefully.
fn generate_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| anyhow!("OS RNG unavailable, cannot generate RPC token: {e}"))?;
    Ok(hex::encode(bytes))
}
