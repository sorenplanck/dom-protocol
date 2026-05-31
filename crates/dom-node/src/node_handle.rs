//! NodeHandle implementation — bridges DomNode to the RPC layer.
//!
//! Uses a newtype wrapper (NodeHandleImpl) to satisfy Rust orphan rules:
//! both Arc<DomNode> and NodeHandle are defined outside dom-node.

use crate::node::{clear_persisted_mempool_snapshot, snapshot_tx_chain_view, DomNode};
use dom_rpc::{MempoolTxInfo, NodeHandle, PeerInfo, RpcError, UtxoInfo};
use dom_serialization::DomDeserialize;
use std::sync::Arc;

/// Newtype so we can impl the foreign NodeHandle trait for Arc<DomNode>.
pub struct NodeHandleImpl(pub Arc<DomNode>);

fn rollback_failed_wallet_spend(
    wallet_arc: &tokio::sync::Mutex<dom_wallet::Wallet>,
    tx_hash: [u8; 32],
    original: RpcError,
) -> RpcError {
    match wallet_arc.try_lock() {
        Ok(mut wallet) => match wallet.cancel_tx(tx_hash) {
            Ok(()) => original,
            Err(e) => RpcError::Internal(format!(
                "{original}; wallet rollback for {} failed: {e}",
                hex::encode(tx_hash)
            )),
        },
        Err(_) => RpcError::Internal(format!(
            "{original}; wallet rollback for {} failed: wallet busy",
            hex::encode(tx_hash)
        )),
    }
}

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
        let chain_view = {
            let chain = self
                .0
                .chain
                .try_lock()
                .map_err(|_| RpcError::Overloaded("chain busy".into()))?;
            snapshot_tx_chain_view(&chain, &tx).map_err(|e| RpcError::Rejected(format!("{e}")))?
        };

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

        m.accept_tx_with_chain_view(
            tx,
            tx_hash,
            now,
            chain_view.current_height,
            chain_view.chain_id,
            chain_view.coinbase_maturity,
            |commitment| Ok(chain_view.utxos.get(commitment).cloned().flatten()),
        )
        .map_err(|e| RpcError::Rejected(format!("{e}")))?;
        drop(m);
        let chain = self
            .0
            .chain
            .try_lock()
            .map_err(|_| RpcError::Overloaded("chain busy".into()))?;
        clear_persisted_mempool_snapshot(&chain.store)
            .map_err(|e| RpcError::Internal(format!("persist mempool: {e}")))?;

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

        let wallet_tx_hash = dom_wallet::Wallet::tracking_tx_hash(&tx)
            .map_err(|e| dom_rpc::RpcError::Internal(format!("wallet tx hash: {e}")))?;

        // Serialize and submit to mempool
        let tx_bytes = tx
            .to_bytes()
            .map_err(|e| dom_rpc::RpcError::Internal(format!("serialize: {e}")))?;
        let tx_hash = *dom_crypto::blake2b_256(&tx_bytes).as_bytes();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut mempool = self.0.mempool.try_lock().map_err(|_| {
            rollback_failed_wallet_spend(
                wallet_arc,
                wallet_tx_hash,
                dom_rpc::RpcError::Overloaded("mempool busy".into()),
            )
        })?;

        let chain_view = {
            let chain = self.0.chain.try_lock().map_err(|_| {
                rollback_failed_wallet_spend(
                    wallet_arc,
                    wallet_tx_hash,
                    dom_rpc::RpcError::Overloaded("chain busy".into()),
                )
            })?;
            snapshot_tx_chain_view(&chain, &tx).map_err(|e| {
                rollback_failed_wallet_spend(
                    wallet_arc,
                    wallet_tx_hash,
                    dom_rpc::RpcError::Rejected(format!("mempool precheck: {e}")),
                )
            })?
        };

        mempool
            .accept_tx_with_chain_view(
                tx,
                tx_hash,
                now,
                chain_view.current_height,
                chain_view.chain_id,
                chain_view.coinbase_maturity,
                |commitment| Ok(chain_view.utxos.get(commitment).cloned().flatten()),
            )
            .map_err(|e| {
                rollback_failed_wallet_spend(
                    wallet_arc,
                    wallet_tx_hash,
                    dom_rpc::RpcError::Rejected(format!("mempool: {e}")),
                )
            })?;

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

#[cfg(test)]
mod tests {
    use super::{NodeHandle, NodeHandleImpl};
    use crate::node::DomNode;
    use dom_config::NodeConfig;
    use dom_consensus::transaction::{
        Transaction, TransactionInput, TransactionKernel, TransactionOutput,
    };
    use dom_core::{Amount, KERNEL_FEAT_PLAIN, MIN_RELAY_FEE_RATE, TAG_KERNEL_MSG};
    use dom_crypto::hash::blake2b_256_tagged;
    use dom_crypto::{bp_prove, pedersen::Commitment, schnorr_sign, BlindingFactor, SecretKey};
    use dom_rpc::SpendRequest;
    use dom_serialization::DomSerialize;
    use dom_wallet::{Network, OwnedOutput, Wallet};

    const TEST_LMDB_MAP_SIZE: usize = 64 << 20; // 64 MiB

    fn make_output(value: u64, height: u64, is_coinbase: bool) -> OwnedOutput {
        let bf = BlindingFactor::random();
        let commitment = Commitment::commit(value, &bf);
        OwnedOutput::new(
            *commitment.as_bytes(),
            value,
            *bf.as_bytes(),
            height,
            is_coinbase,
        )
    }

    fn test_config(data_dir: &str, wallet_path: &str) -> NodeConfig {
        NodeConfig {
            network: dom_config::Network::Regtest,
            data_dir: data_dir.to_string(),
            p2p_listen_addr: "127.0.0.1:0".into(),
            max_inbound: 4,
            min_outbound: 0,
            dns_seeds: vec![],
            seed_peers: vec![],
            mine: false,
            miner_throttle: Default::default(),
            miner_address: None,
            wallet_path: Some(wallet_path.to_string()),
            wallet_password: Some("password123".into()),
            log_level: "debug".into(),
            rpc_listen_addr: None,
        }
    }

    fn raw_spend_tx(
        input_value: u64,
        input_blinding: &BlindingFactor,
        chain_id: &[u8; 32],
    ) -> Vec<u8> {
        let fee = MIN_RELAY_FEE_RATE * 25;
        let output_value = input_value.checked_sub(fee).expect("fee below input");
        let kernel_blinding = BlindingFactor::random();
        let output_blinding = input_blinding
            .add(&kernel_blinding)
            .expect("output blinding");
        let input_commitment = Commitment::commit(input_value, input_blinding);
        let output_commitment = Commitment::commit(output_value, &output_blinding);
        let (proof, _) = bp_prove(output_value, &output_blinding).expect("range proof");
        let excess = Commitment::commit(0, &kernel_blinding);
        let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).expect("kernel secret");
        let msg = {
            let mut data = Vec::with_capacity(1 + 8 + 8);
            data.push(KERNEL_FEAT_PLAIN);
            data.extend_from_slice(&fee.to_le_bytes());
            data.extend_from_slice(&0u64.to_le_bytes());
            blake2b_256_tagged(TAG_KERNEL_MSG, &data)
        };
        let sig = schnorr_sign(&secret, msg.as_bytes(), chain_id).expect("kernel sig");

        Transaction {
            inputs: vec![TransactionInput {
                commitment: input_commitment,
            }],
            outputs: vec![TransactionOutput {
                commitment: output_commitment,
                proof: proof.bytes,
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(fee).unwrap(),
                lock_height: 0,
                excess,
                excess_signature: sig.to_bytes(),
            }],
            offset: [0u8; 32],
        }
        .to_bytes()
        .expect("serialize tx")
    }

    #[test]
    fn wallet_spend_rolls_back_reservation_when_mempool_is_busy() {
        let unique = format!(
            "dom-node-handle-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("unix time")
                .as_nanos()
        );
        let data_dir = std::env::temp_dir().join(format!("{unique}-data"));
        let wallet_path = std::env::temp_dir().join(format!("{unique}.dom"));
        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_file(&wallet_path);

        let node = std::sync::Arc::new(
            DomNode::init_with_map_size(
                test_config(
                    data_dir.to_str().expect("utf8 data dir"),
                    wallet_path.to_str().expect("utf8 wallet path"),
                ),
                // Windows CI reserves LMDB map size more strictly than Linux/macOS.
                // These wallet/node-handle fixtures are tiny, so tests use a small
                // explicit map size while production `DomNode::init` stays at 16 GiB.
                TEST_LMDB_MAP_SIZE,
            )
            .expect("init node"),
        );
        let handle = NodeHandleImpl(node.clone());

        {
            let wallet_arc = node.wallet.as_ref().expect("wallet configured");
            let mut wallet = wallet_arc.try_lock().expect("wallet lock");
            wallet.add_output(make_output(900, 100, false));
            wallet.save().expect("persist wallet");
        }

        let recipient_blinding = BlindingFactor::random();
        let recipient_commitment = Commitment::commit(800, &recipient_blinding);
        let req = SpendRequest {
            recipient_commitment: hex::encode(recipient_commitment.as_bytes()),
            recipient_blinding: hex::encode(recipient_blinding.as_bytes()),
            amount_noms: 800,
            fee_noms: 100,
        };

        let _mempool_guard = node.mempool.try_lock().expect("hold mempool lock");
        let err = handle
            .wallet_spend(req)
            .expect_err("mempool lock should fail");
        assert!(
            matches!(err, dom_rpc::RpcError::Overloaded(ref msg) if msg.contains("mempool busy")),
            "expected mempool busy error, got {err}"
        );

        {
            let wallet_arc = node.wallet.as_ref().expect("wallet configured");
            let wallet = wallet_arc.try_lock().expect("wallet lock");
            let balance = wallet.balance(1000);
            assert_eq!(balance.confirmed, 900);
            assert_eq!(
                balance.reserved, 0,
                "failed mempool admission must not leave funds reserved"
            );
        }

        let reopened =
            Wallet::open(&wallet_path, "password123").expect("reopen wallet after rollback");
        let reopened_balance = reopened.balance(1000);
        assert_eq!(reopened_balance.confirmed, 900);
        assert_eq!(
            reopened_balance.reserved, 0,
            "rollback must persist across restart"
        );
        assert_eq!(reopened.network(), Network::Regtest);

        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_file(&wallet_path);
    }

    #[test]
    fn submit_tx_rejects_inputs_missing_from_canonical_utxo_set() {
        let unique = format!(
            "dom-node-handle-missing-utxo-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("unix time")
                .as_nanos()
        );
        let data_dir = std::env::temp_dir().join(format!("{unique}-data"));
        let wallet_path = std::env::temp_dir().join(format!("{unique}.dom"));
        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_file(&wallet_path);

        let node = std::sync::Arc::new(
            DomNode::init_with_map_size(
                test_config(
                    data_dir.to_str().expect("utf8 data dir"),
                    wallet_path.to_str().expect("utf8 wallet path"),
                ),
                TEST_LMDB_MAP_SIZE,
            )
            .expect("init node"),
        );
        let chain_id = {
            let chain = node.chain.try_lock().expect("chain lock");
            *dom_consensus::derive_chain_id(chain.network_magic, &chain.genesis_hash).as_bytes()
        };
        let handle = NodeHandleImpl(node);

        let input_blinding = BlindingFactor::random();
        let tx_bytes = raw_spend_tx(500_000, &input_blinding, &chain_id);
        let err = handle
            .submit_tx(tx_bytes)
            .expect_err("missing utxo must reject");
        assert!(
            matches!(err, dom_rpc::RpcError::Rejected(ref msg) if msg.contains("input commitment not found in canonical UTXO set")),
            "expected canonical-utxo rejection, got {err}"
        );

        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_file(&wallet_path);
    }
}
