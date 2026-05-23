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

        // Route via Dandelion++: decide Stem vs Fluff and dispatch over
        // the corresponding broadcast channel. Peer tasks pick up envelopes
        // in their message_loop select! and emit Command::Tx to the wire.
        let (phase, stem_target) =
            if let (Ok(mut d), Ok(p)) = (self.0.dandelion.try_lock(), self.0.peers.try_lock()) {
                let peers: Vec<std::net::SocketAddr> = p
                    .connected_peers()
                    .into_iter()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                let ph = d.route_new_tx(tx_hash, &peers);
                let target = d.get_stem_peer(&tx_hash);
                (ph, target)
            } else {
                // Locks unavailable: fall back to Fluff so the tx still propagates.
                (dom_wire::dandelion::DandelionPhase::Fluff, None)
            };
        use dom_wire::dandelion::{DandelionPhase, StemEnvelope};
        match phase {
            DandelionPhase::Fluff => {
                let _ = self.0.tx_fluff_tx.send(tx_bytes.clone());
            }
            DandelionPhase::Stem => {
                if let Some(target) = stem_target {
                    let _ = self.0.tx_stem_tx.send(StemEnvelope {
                        target_peer: target,
                        tx_bytes: tx_bytes.clone(),
                    });
                } else {
                    // Route said Stem but no peer was stored — fall back to Fluff.
                    let _ = self.0.tx_fluff_tx.send(tx_bytes.clone());
                }
            }
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

    fn get_wallet_balance(&self) -> Option<dom_rpc::WalletBalanceResponse> {
        let wallet = self.0.wallet.as_ref()?.try_lock().ok()?;
        let height = self.0.chain.try_lock().ok()?.tip_height.0;
        let bal = wallet.balance(height);
        const NOMS: f64 = 100_000_000.0;
        Some(dom_rpc::WalletBalanceResponse {
            confirmed_noms: bal.confirmed,
            immature_noms: bal.immature,
            reserved_noms: bal.reserved,
            confirmed_dom: bal.confirmed as f64 / NOMS,
            immature_dom: bal.immature as f64 / NOMS,
        })
    }

    fn wallet_spend(&self, req: dom_rpc::SpendRequest) -> Result<[u8; 32], dom_rpc::RpcError> {
        use dom_crypto::{pedersen::Commitment, BlindingFactor};
        use dom_serialization::DomSerialize;

        // Decode recipient commitment (33 bytes hex)
        let commitment_bytes = hex::decode(&req.recipient_commitment)
            .map_err(|e| dom_rpc::RpcError::Rejected(format!("commitment hex: {e}")))?;
        if commitment_bytes.len() != 33 {
            return Err(dom_rpc::RpcError::Rejected(
                "commitment must be 33 bytes".into(),
            ));
        }
        let mut cb = [0u8; 33];
        cb.copy_from_slice(&commitment_bytes);
        let recipient_commitment = Commitment::from_compressed_bytes(&cb)
            .map_err(|e| dom_rpc::RpcError::Rejected(format!("commitment: {e}")))?;

        // Decode recipient blinding (32 bytes hex)
        let blinding_bytes = hex::decode(&req.recipient_blinding)
            .map_err(|e| dom_rpc::RpcError::Rejected(format!("blinding hex: {e}")))?;
        if blinding_bytes.len() != 32 {
            return Err(dom_rpc::RpcError::Rejected(
                "blinding must be 32 bytes".into(),
            ));
        }
        let mut bb = [0u8; 32];
        bb.copy_from_slice(&blinding_bytes);
        let recipient_blinding = BlindingFactor::from_bytes(bb)
            .map_err(|e| dom_rpc::RpcError::Rejected(format!("blinding: {e}")))?;

        // Get current height
        let height = self
            .0
            .chain
            .try_lock()
            .map_err(|_| dom_rpc::RpcError::Overloaded("chain busy".into()))?
            .tip_height
            .0;

        // Build spend transaction via wallet
        let wallet_arc = self
            .0
            .wallet
            .as_ref()
            .ok_or_else(|| dom_rpc::RpcError::Internal("wallet not configured".into()))?;

        let tx = {
            let mut wallet = wallet_arc
                .try_lock()
                .map_err(|_| dom_rpc::RpcError::Overloaded("wallet busy".into()))?;
            wallet
                .build_spend(
                    recipient_commitment,
                    recipient_blinding,
                    req.amount_noms,
                    req.fee_noms,
                    height,
                )
                .map_err(|e| dom_rpc::RpcError::Rejected(format!("build_spend: {e}")))?
        };

        // Serialize and submit to mempool
        let tx_bytes = tx
            .to_bytes()
            .map_err(|e| dom_rpc::RpcError::Internal(format!("serialize: {e}")))?;
        let tx_hash = *dom_crypto::blake2b_256(&tx_bytes).as_bytes();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut mempool = self
            .0
            .mempool
            .try_lock()
            .map_err(|_| dom_rpc::RpcError::Overloaded("mempool busy".into()))?;

        mempool
            .accept_tx(tx, tx_hash, now)
            .map_err(|e| dom_rpc::RpcError::Rejected(format!("mempool: {e}")))?;

        // Route via Dandelion++: decide Stem vs Fluff and dispatch over
        // the corresponding broadcast channel. Same logic as submit_tx above.
        let (phase, stem_target) =
            if let (Ok(mut d), Ok(p)) = (self.0.dandelion.try_lock(), self.0.peers.try_lock()) {
                let peers: Vec<std::net::SocketAddr> = p
                    .connected_peers()
                    .into_iter()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                let ph = d.route_new_tx(tx_hash, &peers);
                let target = d.get_stem_peer(&tx_hash);
                (ph, target)
            } else {
                (dom_wire::dandelion::DandelionPhase::Fluff, None)
            };
        use dom_wire::dandelion::{DandelionPhase, StemEnvelope};
        match phase {
            DandelionPhase::Fluff => {
                let _ = self.0.tx_fluff_tx.send(tx_bytes.clone());
            }
            DandelionPhase::Stem => {
                if let Some(target) = stem_target {
                    let _ = self.0.tx_stem_tx.send(StemEnvelope {
                        target_peer: target,
                        tx_bytes: tx_bytes.clone(),
                    });
                } else {
                    let _ = self.0.tx_fluff_tx.send(tx_bytes.clone());
                }
            }
        }

        Ok(tx_hash)
    }
}
