//! NodeHandle implementation — bridges DomNode to the RPC layer.
//!
//! Uses a newtype wrapper (NodeHandleImpl) to satisfy Rust orphan rules:
//! both Arc<DomNode> and NodeHandle are defined outside dom-node.

use crate::node::DomNode;
use dom_rpc::{MempoolTxInfo, NodeHandle, PeerInfo, RpcError, UtxoInfo};
use dom_serialization::DomDeserialize;
use std::sync::Arc;

/// Newtype so we can impl the foreign NodeHandle trait for Arc<DomNode>.
pub struct NodeHandleImpl(pub Arc<DomNode>);

impl NodeHandle for NodeHandleImpl {
    fn chain_height(&self) -> u64 {
        match self.0.chain.try_lock() {
            Ok(c) => c.tip_height.0,
            Err(_) => 0,
        }
    }

    fn mempool_size(&self) -> usize {
        match self.0.mempool.try_lock() {
            Ok(m) => m.len(),
            Err(_) => 0,
        }
    }

    fn mempool_tx_hashes(&self) -> Vec<[u8; 32]> {
        match self.0.mempool.try_lock() {
            Ok(m) => m.all_hashes(),
            Err(_) => Vec::new(),
        }
    }

    fn get_mempool_tx(&self, hash: &[u8; 32]) -> Option<MempoolTxInfo> {
        let m = self.0.mempool.try_lock().ok()?;
        let entry = m.get_tx(hash)?;
        Some(MempoolTxInfo {
            tx_hash: entry.tx_hash,
            fee: entry.fee,
            fee_rate: entry.fee_rate,
            weight: entry.weight,
        })
    }

    fn submit_tx(&self, tx_bytes: Vec<u8>) -> Result<[u8; 32], RpcError> {
        use dom_consensus::Transaction;

        let tx = Transaction::from_bytes(&tx_bytes)
            .map_err(|e| RpcError::Rejected(format!("invalid tx encoding: {e}")))?;

        // Hash = Blake2b-256 of raw bytes (consistent with mempool internals)
        let tx_hash = *dom_crypto::blake2b_256(&tx_bytes).as_bytes();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut m = self
            .0
            .mempool
            .try_lock()
            .map_err(|_| RpcError::Overloaded("mempool busy".into()))?;

        m.accept_tx(tx, tx_hash, now)
            .map_err(|e| RpcError::Rejected(format!("{e}")))?;

        // Route via Dandelion++ stem
        if let (Ok(mut d), Ok(p)) = (
            self.0.dandelion.try_lock(),
            self.0.peers.try_lock(),
        ) {
            let peers = p.connected_peers();
            d.route_new_tx(tx_hash, &peers);
        }

        Ok(tx_hash)
    }

    fn get_block_header(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        let c = self.0.chain.try_lock().ok()?;
        c.store.get_block_header(hash).ok().flatten()
    }

    fn get_block_hash_at_height(&self, height: u64) -> Option<[u8; 32]> {
        let c = self.0.chain.try_lock().ok()?;
        c.store.get_hash_at_height(height).ok().flatten()
    }

    fn get_utxo(&self, commitment: &[u8; 33]) -> Option<UtxoInfo> {
        let c = self.0.chain.try_lock().ok()?;
        let current_height = c.tip_height.0;
        let entry = c.store.get_utxo(commitment).ok().flatten()?;
        Some(UtxoInfo {
            commitment: hex::encode(commitment),
            block_height: entry.block_height,
            is_coinbase: entry.is_coinbase,
            is_mature: entry.is_mature(current_height),
        })
    }

    fn get_peers(&self) -> Vec<PeerInfo> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        match self.0.peers.try_lock() {
            Ok(p) => p
                .connected_peers()
                .into_iter()
                .map(|addr| PeerInfo {
                    addr,
                    direction: "outbound".into(),
                    connected_since: now,
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}
