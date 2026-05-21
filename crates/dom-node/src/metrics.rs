//! Node metrics for monitoring and observability.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct Metrics {
    pub chain_height: Arc<AtomicU64>,
    pub total_difficulty: Arc<AtomicU64>,
    pub peer_count: Arc<AtomicU64>,
    pub inbound_peers: Arc<AtomicU64>,
    pub outbound_peers: Arc<AtomicU64>,
    pub blocks_mined: Arc<AtomicU64>,
    pub mining_active: Arc<AtomicU64>,
    pub mempool_size: Arc<AtomicU64>,
    pub txs_received: Arc<AtomicU64>,
    pub txs_relayed: Arc<AtomicU64>,
    pub block_validation_time_ms: Arc<AtomicU64>,
    pub ibd_progress_percent: Arc<AtomicU64>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            chain_height: Arc::new(AtomicU64::new(0)),
            total_difficulty: Arc::new(AtomicU64::new(0)),
            peer_count: Arc::new(AtomicU64::new(0)),
            inbound_peers: Arc::new(AtomicU64::new(0)),
            outbound_peers: Arc::new(AtomicU64::new(0)),
            blocks_mined: Arc::new(AtomicU64::new(0)),
            mining_active: Arc::new(AtomicU64::new(0)),
            mempool_size: Arc::new(AtomicU64::new(0)),
            txs_received: Arc::new(AtomicU64::new(0)),
            txs_relayed: Arc::new(AtomicU64::new(0)),
            block_validation_time_ms: Arc::new(AtomicU64::new(0)),
            ibd_progress_percent: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn export_prometheus(&self) -> String {
        let mut out = String::new();
        let metrics_list = [
            ("dom_chain_height", "Current blockchain height", "gauge", &self.chain_height),
            ("dom_total_difficulty", "Total accumulated difficulty", "gauge", &self.total_difficulty),
            ("dom_peer_count", "Number of connected peers", "gauge", &self.peer_count),
            ("dom_inbound_peers", "Inbound peer connections", "gauge", &self.inbound_peers),
            ("dom_outbound_peers", "Outbound peer connections", "gauge", &self.outbound_peers),
            ("dom_blocks_mined", "Total blocks mined", "counter", &self.blocks_mined),
            ("dom_mining_active", "Mining status", "gauge", &self.mining_active),
            ("dom_mempool_size", "Mempool size", "gauge", &self.mempool_size),
            ("dom_txs_received", "Total txs received", "counter", &self.txs_received),
            ("dom_txs_relayed", "Total txs relayed", "counter", &self.txs_relayed),
            ("dom_block_validation_time_ms", "Block validation time", "gauge", &self.block_validation_time_ms),
            ("dom_ibd_progress_percent", "IBD progress", "gauge", &self.ibd_progress_percent),
        ];

        for (name, help, kind, counter) in metrics_list.iter() {
            out.push_str(&format!("# HELP {} {}\n", name, help));
            out.push_str(&format!("# TYPE {} {}\n", name, kind));
            out.push_str(&format!("{} {}\n\n", name, counter.load(Ordering::Relaxed)));
        }
        out
    }

    pub fn health_check(&self) -> HealthStatus {
        let height = self.chain_height.load(Ordering::Relaxed);
        let peers = self.peer_count.load(Ordering::Relaxed);
        let ibd_progress = self.ibd_progress_percent.load(Ordering::Relaxed);
        let healthy = height > 0 && peers > 0 && ibd_progress >= 99;
        HealthStatus {
            status: if healthy { "healthy" } else { "syncing" }.to_string(),
            height,
            peers,
            syncing: ibd_progress < 100,
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub status: String,
    pub height: u64,
    pub peers: u64,
    pub syncing: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_metrics_zero() {
        let m = Metrics::new();
        assert_eq!(m.chain_height.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn prometheus_export_works() {
        let m = Metrics::new();
        m.chain_height.store(100, Ordering::Relaxed);
        m.peer_count.store(5, Ordering::Relaxed);
        let output = m.export_prometheus();
        assert!(output.contains("dom_chain_height 100"));
        assert!(output.contains("dom_peer_count 5"));
    }

    #[test]
    fn health_check_healthy() {
        let m = Metrics::new();
        m.chain_height.store(100, Ordering::Relaxed);
        m.peer_count.store(3, Ordering::Relaxed);
        m.ibd_progress_percent.store(100, Ordering::Relaxed);
        assert_eq!(m.health_check().status, "healthy");
    }

    #[test]
    fn health_check_syncing() {
        let m = Metrics::new();
        m.chain_height.store(50, Ordering::Relaxed);
        m.ibd_progress_percent.store(50, Ordering::Relaxed);
        assert!(m.health_check().syncing);
    }
}
