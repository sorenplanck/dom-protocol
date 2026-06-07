//! Embedded node lifecycle.
//!
//! The DOM node runs **in this same process** as a supervised tokio task — not
//! as an external binary over HTTP loopback (Principle 1). We import
//! `dom_node::node::DomNode` and `dom_config::NodeConfig` and orchestrate them;
//! no P2P / consensus / mining logic is reimplemented here.
//!
//! Lifecycle (Principle 2 — the wallet observes, never drives consensus):
//!   * `start` builds a `NodeConfig` from the user's [`NodeSettings`], generates
//!     a fresh RPC bearer token (kept in memory only — never written to disk),
//!     spawns `DomNode::run()` on a task, and records a [`RunningNode`] handle.
//!   * `stop` calls `request_shutdown()` for a graceful, coordinated stop and
//!     awaits the run task.
//!   * `restart` = stop then start.
//!
//! If the wallet half of the app hangs or panics, the node task is independent
//! and keeps running; if the node stops, the wallet simply stops receiving
//! updates — it never corrupts wallet state.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use dom_config::NodeConfig;
use dom_node::node::DomNode;
use rand::RngCore;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::settings::NodeSettings;

/// Connection facts the wallet needs to talk to (and display) the running node.
#[derive(Clone)]
pub struct NodeEndpoints {
    /// e.g. "http://127.0.0.1:33372"
    pub rpc_base_url: String,
    /// Bearer token for the local RPC. In memory only.
    pub rpc_token: Zeroizing<String>,
    /// e.g. "http://127.0.0.1:33371/metrics"
    pub metrics_url: String,
    /// The P2P listen address actually used.
    pub p2p_listen_addr: String,
}

struct RunningNode {
    node: Arc<DomNode>,
    run_task: JoinHandle<()>,
    endpoints: NodeEndpoints,
}

/// Owns the embedded node and its run task. Cloneable via `Arc` at the app
/// state level; the inner `Mutex` serialises start/stop.
pub struct NodeHost {
    inner: Mutex<Option<RunningNode>>,
}

impl NodeHost {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    pub async fn is_running(&self) -> bool {
        self.inner.lock().await.is_some()
    }

    /// The current RPC/metrics endpoints, if the node is running.
    pub async fn endpoints(&self) -> Option<NodeEndpoints> {
        self.inner.lock().await.as_ref().map(|r| r.endpoints.clone())
    }

    /// Build a `NodeConfig` from settings and the wallet path/password, generate
    /// a fresh bearer token, spawn the node, and record the handle.
    ///
    /// `wallet_password` is passed straight into `NodeConfig` (in memory) so the
    /// node can credit coinbase to the open wallet; it is never logged.
    pub async fn start(
        &self,
        settings: &NodeSettings,
        wallet_path: Option<String>,
        wallet_password: Option<Zeroizing<String>>,
    ) -> Result<NodeEndpoints> {
        let mut guard = self.inner.lock().await;
        if guard.is_some() {
            return Err(anyhow!("node is already running"));
        }

        // Base config for the selected network, then apply user overrides.
        let mut config = match settings.network.as_str() {
            "mainnet" => NodeConfig::mainnet(),
            "regtest" => NodeConfig::regtest(),
            _ => NodeConfig::testnet(),
        };

        if !settings.seed_peers.is_empty() {
            config.seed_peers = settings.seed_peers.clone();
        }
        config.p2p_listen_addr = settings.p2p_listen_addr.clone();
        config.data_dir = settings.data_dir.clone();
        config.mine = settings.mining_enabled;
        config.log_level = settings.log_level.clone();

        // Local-only RPC with a fresh per-launch bearer token (Principle: never
        // written to disk in plain; regenerated each start).
        let rpc_addr = settings.rpc_listen_addr.clone();
        let token = generate_bearer_token();
        config.rpc_listen_addr = Some(rpc_addr.clone());
        config.rpc_bearer_token = Some(token.to_string());

        // Prometheus metrics on loopback (peers, hashrate, mining flag…).
        let metrics_addr = settings.metrics_listen_addr.clone();
        config.metrics_listen_addr = Some(metrics_addr.clone());

        config.wallet_path = wallet_path;
        config.wallet_password = wallet_password.map(|p| p.to_string());

        let endpoints = NodeEndpoints {
            rpc_base_url: to_loopback_url(&rpc_addr),
            rpc_token: token,
            metrics_url: format!("{}/metrics", to_loopback_url(&metrics_addr)),
            p2p_listen_addr: config.p2p_listen_addr.clone(),
        };

        // Build the node. `init` is synchronous and may fail fast (e.g. an
        // unfinalised H generator) — surface that as a clean error.
        let node = Arc::new(DomNode::init(config).map_err(|e| anyhow!("node init failed: {e}"))?);

        // Drive the node on its own task. If `run` returns an error we log it;
        // the supervisor inside dom-node coordinates task shutdown.
        let run_node = node.clone();
        let run_task = tokio::spawn(async move {
            if let Err(e) = run_node.run().await {
                tracing::error!("embedded node stopped with error: {e}");
            } else {
                tracing::info!("embedded node stopped cleanly");
            }
        });

        tracing::info!(
            "embedded node started (rpc={}, metrics={}, p2p={})",
            endpoints.rpc_base_url,
            endpoints.metrics_url,
            endpoints.p2p_listen_addr
        );

        *guard = Some(RunningNode {
            node,
            run_task,
            endpoints: endpoints.clone(),
        });
        Ok(endpoints)
    }

    /// Request a graceful shutdown and await the run task.
    pub async fn stop(&self) -> Result<()> {
        let running = { self.inner.lock().await.take() };
        let Some(running) = running else {
            return Err(anyhow!("node is not running"));
        };
        tracing::info!("stopping embedded node…");
        running.node.request_shutdown().await;
        // Bound the wait so a wedged task can't hang the UI forever.
        match tokio::time::timeout(std::time::Duration::from_secs(20), running.run_task).await {
            Ok(Ok(())) => {}
            Ok(Err(join_err)) => tracing::warn!("node task join error: {join_err}"),
            Err(_) => tracing::warn!("node shutdown timed out; abandoning task"),
        }
        tracing::info!("embedded node stopped");
        Ok(())
    }

    /// Stop (if running) then start again with the latest settings.
    pub async fn restart(
        &self,
        settings: &NodeSettings,
        wallet_path: Option<String>,
        wallet_password: Option<Zeroizing<String>>,
    ) -> Result<NodeEndpoints> {
        if self.is_running().await {
            self.stop().await?;
        }
        self.start(settings, wallet_path, wallet_password).await
    }
}

/// 32 random bytes, hex-encoded → 64-char token. Kept in `Zeroizing`.
fn generate_bearer_token() -> Zeroizing<String> {
    use zeroize::Zeroize;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = Zeroizing::new(hex::encode(bytes));
    bytes.zeroize();
    token
}

/// Turn a listen addr like "127.0.0.1:33372" or "0.0.0.0:33372" into a URL the
/// loopback client can use ("http://127.0.0.1:33372").
fn to_loopback_url(listen_addr: &str) -> String {
    let port = listen_addr.rsplit(':').next().unwrap_or("33372");
    format!("http://127.0.0.1:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_url_extracts_port() {
        assert_eq!(to_loopback_url("0.0.0.0:33372"), "http://127.0.0.1:33372");
        assert_eq!(to_loopback_url("127.0.0.1:1234"), "http://127.0.0.1:1234");
    }

    #[test]
    fn bearer_token_is_64_hex_chars() {
        let t = generate_bearer_token();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
        // Two tokens differ (overwhelmingly).
        let t2 = generate_bearer_token();
        assert_ne!(*t, *t2);
    }
}
