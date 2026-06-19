//! NodeHandle implementation — bridges DomNode to the RPC layer.
//!
//! Uses a newtype wrapper (NodeHandleImpl) to satisfy Rust orphan rules:
//! both Arc<DomNode> and NodeHandle are defined outside dom-node.

use crate::node::{clear_persisted_mempool_snapshot, snapshot_tx_chain_view, DomNode};
use dom_rpc::{MempoolTxInfo, NodeHandle, PeerInfo, RpcError, TxAdmission, UtxoInfo};
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

    fn submit_tx(&self, tx_bytes: Vec<u8>) -> Result<TxAdmission, RpcError> {
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
        self.0
            .metrics
            .txs_received
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.0
            .metrics
            .mempool_size
            .store(m.len() as u64, std::sync::atomic::Ordering::Relaxed);
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
        // `relayed` is true only when a broadcast channel actually had a live
        // subscriber (a connected peer task). With zero peers, send() returns
        // Err and the relay is a silent no-op — exactly how the first testnet
        // Slatepack tx was lost. We report this up so the RPC can warn and the
        // wallet can retransmit.
        let relayed = match phase {
            DandelionPhase::Fluff => self.0.tx_fluff_tx.send(tx_bytes.clone()).is_ok(),
            DandelionPhase::Stem => {
                if let Some(target) = stem_target {
                    self.0
                        .tx_stem_tx
                        .send(StemEnvelope {
                            target_peer: target,
                            tx_bytes: tx_bytes.clone(),
                        })
                        .is_ok()
                } else {
                    // Route said Stem but no peer was stored — fall back to Fluff.
                    self.0.tx_fluff_tx.send(tx_bytes.clone()).is_ok()
                }
            }
        };
        if relayed {
            self.0
                .metrics
                .txs_relayed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            tracing::info!(
                "tx accepted but not relayed: no peer subscribers (tx {})",
                hex::encode(tx_hash)
            );
        }

        Ok(TxAdmission { tx_hash, relayed })
    }

    fn network(&self) -> &'static str {
        self.0.config.network.as_str()
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
        let wallet_dir = self.0.wallet.as_ref()?.try_lock().ok()?;
        let height = self.0.chain.try_lock().ok()?.tip_height.0;
        let bal = wallet_dir.wallet().balance(height);
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

        let wallet_arc = self
            .0
            .wallet
            .as_ref()
            .ok_or_else(|| dom_rpc::RpcError::Internal("wallet not configured".into()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // DOM-AUDIT-005: reserve funds only under the same wallet lock that
        // performs mempool admission, so any rollback runs with the lock
        // already in hand — never a try_lock that could give up and leave
        // funds reserved.
        //
        // Acquire all three subsystem locks in canonical order
        // (Chain -> Mempool -> Wallet; see `lock_order`) and hold them across
        // the whole synchronous critical section. The wallet lock is held
        // continuously from coin selection through admission so no concurrent
        // spend can select the same inputs, and `accept_tx_with_chain_view`
        // (sync, operating on the chain *snapshot* + the held mempool guard)
        // never re-acquires chain or mempool. There is no `.await` inside the
        // critical section, so this does not reintroduce the DOM-AUDIT-001
        // lock-across-await pattern.
        let (tx_hash, tx_bytes, mempool_len) = {
            let chain = self
                .0
                .chain
                .try_lock()
                .map_err(|_| dom_rpc::RpcError::Overloaded("chain busy".into()))?;
            let mut mempool = self
                .0
                .mempool
                .try_lock()
                .map_err(|_| dom_rpc::RpcError::Overloaded("mempool busy".into()))?;
            let mut wallet_dir = wallet_arc
                .try_lock()
                .map_err(|_| dom_rpc::RpcError::Overloaded("wallet busy".into()))?;
            let wallet = wallet_dir.wallet_mut();

            let height = chain.tip_height.0;
            let built = wallet
                .build_spend_unreserved(
                    recipient_commitment,
                    recipient_blinding,
                    req.amount_noms,
                    req.fee_noms,
                    height,
                )
                .map_err(|e| dom_rpc::RpcError::Rejected(format!("build_spend: {e}")))?;

            let chain_view = snapshot_tx_chain_view(&chain, &built.tx)
                .map_err(|e| dom_rpc::RpcError::Rejected(format!("mempool precheck: {e}")))?;

            let tx_hash = built.tx_hash;
            let tx_bytes = built.tx_bytes.clone();

            // Phase 2: reserve, then attempt admission. Both run under the
            // wallet lock held here, so the rollback below cannot fail to
            // take the lock.
            wallet
                .reserve_built_spend(&built)
                .map_err(|e| dom_rpc::RpcError::Internal(format!("reserve: {e}")))?;

            let dom_wallet::BuiltSpend { tx, .. } = built;
            if let Err(e) = mempool.accept_tx_with_chain_view(
                tx,
                tx_hash,
                now,
                chain_view.current_height,
                chain_view.chain_id,
                chain_view.coinbase_maturity,
                |commitment| Ok(chain_view.utxos.get(commitment).cloned().flatten()),
            ) {
                // Rollback with the wallet lock ALREADY held — infallible
                // w.r.t. locking, so the reservation is never left stuck.
                if let Err(ce) = wallet.cancel_tx(tx_hash) {
                    return Err(dom_rpc::RpcError::Internal(format!(
                        "mempool: {e}; wallet rollback for {} failed: {ce}",
                        hex::encode(tx_hash)
                    )));
                }
                return Err(dom_rpc::RpcError::Rejected(format!("mempool: {e}")));
            }

            (tx_hash, tx_bytes, mempool.len())
        };

        self.0
            .metrics
            .txs_received
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.0
            .metrics
            .mempool_size
            .store(mempool_len as u64, std::sync::atomic::Ordering::Relaxed);

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
        let relayed = match phase {
            DandelionPhase::Fluff => self.0.tx_fluff_tx.send(tx_bytes.clone()).is_ok(),
            DandelionPhase::Stem => {
                if let Some(target) = stem_target {
                    self.0
                        .tx_stem_tx
                        .send(StemEnvelope {
                            target_peer: target,
                            tx_bytes: tx_bytes.clone(),
                        })
                        .is_ok()
                } else {
                    self.0.tx_fluff_tx.send(tx_bytes.clone()).is_ok()
                }
            }
        };
        if relayed {
            self.0
                .metrics
                .txs_relayed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            tracing::info!(
                "tx accepted but not relayed: no peer subscribers (tx {})",
                hex::encode(tx_hash)
            );
        }

        Ok(tx_hash)
    }

    fn scan_chain(&self, from: u64, to: u64) -> Result<dom_rpc::ChainScan, RpcError> {
        // GOLDEN RULE: never block on the chain lock. If it is busy (mining /
        // connecting a block), yield immediately with a retriable 503 — mining
        // always has priority over this read-only RPC.
        let c = self
            .0
            .chain
            .try_lock()
            .map_err(|_| RpcError::Overloaded("chain busy; retry".into()))?;

        let tip_height = c.tip_height.0;
        let tip_hash = *c.tip_hash.as_bytes();
        // Bound the work (and the lock hold): at most MAX_SCAN_RANGE heights,
        // never past the tip. Clients page across larger ranges.
        let effective_to = scan_to_clamped(from, to, tip_height);

        let mut blocks = Vec::new();
        if from <= effective_to {
            for height in from..=effective_to {
                if let Some(sb) = crate::wallet_scan::scan_block_at(&c.store, height)
                    .map_err(|e| RpcError::Internal(e.to_string()))?
                {
                    blocks.push(dom_rpc::ScanBlockData {
                        height: sb.height,
                        hash: sb.block_hash.unwrap_or([0u8; 32]),
                        output_commitments: sb.output_commitments,
                        input_commitments: sb.input_commitments,
                        fees: sb.total_fees_noms,
                    });
                }
            }
        }

        Ok(dom_rpc::ChainScan {
            tip: dom_rpc::ChainTip {
                height: tip_height,
                hash: tip_hash,
            },
            from,
            to: effective_to,
            blocks,
        })
    }
}

/// Highest height a single scan serves: `min(to, tip, from + MAX_SCAN_RANGE - 1)`.
/// When `from > to` (or `from > tip`) the result is `< from`, i.e. an empty scan
/// that still carries the tip.
pub(crate) fn scan_to_clamped(from: u64, to: u64, tip: u64) -> u64 {
    let cap = from.saturating_add(dom_rpc::MAX_SCAN_RANGE - 1);
    to.min(tip).min(cap)
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
    use dom_crypto::{bp2_prove, pedersen::Commitment, schnorr_sign, BlindingFactor, SecretKey};
    use dom_rpc::SpendRequest;
    use dom_serialization::DomSerialize;
    use dom_store::utxo::UtxoEntry;
    use dom_wallet::{Network, OwnedOutput, Wallet, WalletDir, WALLET_DAT_NAME};
    use std::sync::atomic::Ordering;

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
            disable_dns_seeds: false,
            seed_peers: vec![],
            mine: false,
            miner_throttle: Default::default(),
            miner_threads: 1,
            miner_address: None,
            wallet_path: Some(wallet_path.to_string()),
            wallet_password: Some("password123".into()),
            log_level: "debug".into(),
            rpc_listen_addr: None,
            rpc_bearer_token: None,
            metrics_listen_addr: None,
        }
    }

    /// The node no longer CREATES wallets (DOM-SEC-004: the old auto-create
    /// produced a legacy keychain with no recoverable seed). Tests pre-create
    /// the canonical WalletDir directory, exactly like the CLI/desktop wallet,
    /// and drop the handle so the node can take the exclusive lock.
    fn create_test_wallet_dir(path: &std::path::Path) {
        let _ = std::fs::remove_dir_all(path);
        WalletDir::create(
            path,
            "password123",
            Network::Regtest,
            &dom_core::Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        )
        .expect("create test wallet dir");
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
        let (proof, _) = bp2_prove(output_value, &output_blinding).expect("range proof");
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
                proof: proof,
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
        create_test_wallet_dir(&wallet_path);

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
            let mut wallet_dir = wallet_arc.try_lock().expect("wallet lock");
            let wallet = wallet_dir.wallet_mut();
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
            let wallet_dir = wallet_arc.try_lock().expect("wallet lock");
            let balance = wallet_dir.wallet().balance(1000);
            assert_eq!(balance.confirmed, 900);
            assert_eq!(
                balance.reserved, 0,
                "failed mempool admission must not leave funds reserved"
            );
        }

        let reopened = Wallet::open(&wallet_path.join(WALLET_DAT_NAME), "password123")
            .expect("reopen wallet after rollback");
        let reopened_balance = reopened.balance(1000);
        assert_eq!(reopened_balance.confirmed, 900);
        assert_eq!(
            reopened_balance.reserved, 0,
            "rollback must persist across restart"
        );
        assert_eq!(reopened.network(), Network::Regtest);

        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&wallet_path);
    }

    #[test]
    fn wallet_spend_rolls_back_reservation_when_admission_rejected() {
        // DOM-AUDIT-005: this is the case the old try_lock rollback could
        // leave stuck. The wallet output is fabricated and never enters the
        // chain's canonical UTXO set, so mempool admission rejects the tx
        // ("input commitment not found") AFTER the inputs were reserved. The
        // fix reserves and admits under the SAME wallet lock, so the rollback
        // (cancel_tx) runs with the lock already held — it can never fail to
        // acquire it, and the reservation must be fully released.
        let unique = format!(
            "dom-node-handle-rollback-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("unix time")
                .as_nanos()
        );
        let data_dir = std::env::temp_dir().join(format!("{unique}-data"));
        let wallet_path = std::env::temp_dir().join(format!("{unique}.dom"));
        let _ = std::fs::remove_dir_all(&data_dir);
        create_test_wallet_dir(&wallet_path);

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
        let handle = NodeHandleImpl(node.clone());

        {
            let wallet_arc = node.wallet.as_ref().expect("wallet configured");
            let mut wallet_dir = wallet_arc.try_lock().expect("wallet lock");
            let wallet = wallet_dir.wallet_mut();
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

        // No locks held by the test: the spend proceeds far enough to RESERVE,
        // then the mempool rejects admission, exercising the rollback path.
        let err = handle
            .wallet_spend(req)
            .expect_err("admission of an unknown-input tx must be rejected");
        assert!(
            matches!(err, dom_rpc::RpcError::Rejected(ref msg) if msg.contains("mempool:")),
            "expected mempool rejection, got {err}"
        );

        {
            let wallet_arc = node.wallet.as_ref().expect("wallet configured");
            let wallet_dir = wallet_arc.try_lock().expect("wallet lock");
            let balance = wallet_dir.wallet().balance(1000);
            assert_eq!(balance.confirmed, 900);
            assert_eq!(
                balance.reserved, 0,
                "rejected admission must roll back the reservation (no funds left stuck)"
            );
        }

        let reopened = Wallet::open(&wallet_path.join(WALLET_DAT_NAME), "password123")
            .expect("reopen wallet after rollback");
        let reopened_balance = reopened.balance(1000);
        assert_eq!(reopened_balance.confirmed, 900);
        assert_eq!(
            reopened_balance.reserved, 0,
            "rollback must persist across restart"
        );

        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&wallet_path);
    }

    #[test]
    fn network_reports_configured_value_not_hardcoded_mainnet() {
        // DOM-AUDIT-006: NodeHandle::network() must reflect the node's actual
        // configured network. test_config uses Regtest, so the handle must
        // report "regtest" — never the old hardcoded "mainnet".
        let unique = format!(
            "dom-node-handle-network-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("unix time")
                .as_nanos()
        );
        let data_dir = std::env::temp_dir().join(format!("{unique}-data"));
        let wallet_path = std::env::temp_dir().join(format!("{unique}.dom"));
        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&wallet_path);

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
        let handle = NodeHandleImpl(node);

        assert_eq!(handle.network(), "regtest");
        assert_ne!(handle.network(), "mainnet");

        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&wallet_path);
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
        let _ = std::fs::remove_dir_all(&wallet_path);

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
        let _ = std::fs::remove_dir_all(&wallet_path);
    }

    #[test]
    fn submit_tx_updates_received_relayed_and_mempool_metrics() {
        let unique = format!(
            "dom-node-handle-submit-metrics-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("unix time")
                .as_nanos()
        );
        let data_dir = std::env::temp_dir().join(format!("{unique}-data"));
        let wallet_path = std::env::temp_dir().join(format!("{unique}.dom"));
        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&wallet_path);

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
        let _relay_rx = node.tx_fluff_tx.subscribe();
        let chain_id = {
            let chain = node.chain.try_lock().expect("chain lock");
            *dom_consensus::derive_chain_id(chain.network_magic, &chain.genesis_hash).as_bytes()
        };

        let input_value = 500_000;
        let input_blinding = BlindingFactor::random();
        let input_commitment = Commitment::commit(input_value, &input_blinding);
        {
            let chain = node.chain.try_lock().expect("chain lock");
            chain
                .store
                .commit_block(
                    &[0xA7; 32],
                    0,
                    b"metrics-test-header",
                    b"metrics-test-body",
                    &[(
                        *input_commitment.as_bytes(),
                        UtxoEntry {
                            block_height: 0,
                            is_coinbase: false,
                            proof: Vec::new(),
                        }
                        .to_bytes(),
                    )],
                    &[],
                    &[],
                )
                .expect("plant canonical input utxo");
        }
        let tx_bytes = raw_spend_tx(input_value, &input_blinding, &chain_id);
        let handle = NodeHandleImpl(node.clone());

        let admission = handle.submit_tx(tx_bytes).expect("submit tx");

        assert_ne!(admission.tx_hash, [0u8; 32]);
        assert!(admission.relayed);
        assert_eq!(node.metrics.txs_received.load(Ordering::Relaxed), 1);
        assert_eq!(node.metrics.mempool_size.load(Ordering::Relaxed), 1);
        assert_eq!(node.metrics.txs_relayed.load(Ordering::Relaxed), 1);

        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&wallet_path);
    }

    #[test]
    fn submit_tx_with_zero_peer_subscribers_reports_not_relayed() {
        let unique = format!(
            "dom-node-handle-submit-no-subscribers-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("unix time")
                .as_nanos()
        );
        let data_dir = std::env::temp_dir().join(format!("{unique}-data"));
        let wallet_path = std::env::temp_dir().join(format!("{unique}.dom"));
        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&wallet_path);

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

        let input_value = 500_000;
        let input_blinding = BlindingFactor::random();
        let input_commitment = Commitment::commit(input_value, &input_blinding);
        {
            let chain = node.chain.try_lock().expect("chain lock");
            chain
                .store
                .commit_block(
                    &[0xB7; 32],
                    0,
                    b"no-subscriber-test-header",
                    b"no-subscriber-test-body",
                    &[(
                        *input_commitment.as_bytes(),
                        UtxoEntry {
                            block_height: 0,
                            is_coinbase: false,
                            proof: Vec::new(),
                        }
                        .to_bytes(),
                    )],
                    &[],
                    &[],
                )
                .expect("plant canonical input utxo");
        }
        let tx_bytes = raw_spend_tx(input_value, &input_blinding, &chain_id);
        let handle = NodeHandleImpl(node.clone());

        let admission = handle.submit_tx(tx_bytes).expect("submit tx");

        assert_ne!(admission.tx_hash, [0u8; 32]);
        assert!(!admission.relayed);
        assert_eq!(node.metrics.txs_received.load(Ordering::Relaxed), 1);
        assert_eq!(node.metrics.mempool_size.load(Ordering::Relaxed), 1);
        assert_eq!(node.metrics.txs_relayed.load(Ordering::Relaxed), 0);

        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&wallet_path);
    }

    // ── /chain/scan (RB-WALLET2-RPC-SOURCE, node side) ──────────────────────

    #[test]
    fn scan_to_clamped_caps_range_and_tip() {
        // Capped to MAX_SCAN_RANGE blocks (0..=999).
        assert_eq!(super::scan_to_clamped(0, 5000, 10_000), 999);
        // Smaller than the cap → honoured as requested.
        assert_eq!(super::scan_to_clamped(0, 5, 10_000), 5);
        // Never past the tip.
        assert_eq!(super::scan_to_clamped(0, 5000, 3), 3);
        // Empty request (from > to) → result < from (empty scan, tip still served).
        assert!(super::scan_to_clamped(5, 0, 100) < 5);
    }

    fn fresh_node(tag: &str) -> std::sync::Arc<DomNode> {
        let data_dir = std::env::temp_dir().join(format!("{tag}-data"));
        let wallet_path = std::env::temp_dir().join(format!("{tag}.dom"));
        let _ = std::fs::remove_dir_all(&data_dir);
        create_test_wallet_dir(&wallet_path);
        std::sync::Arc::new(
            DomNode::init_with_map_size(
                test_config(
                    data_dir.to_str().expect("utf8 data dir"),
                    wallet_path.to_str().expect("utf8 wallet path"),
                ),
                TEST_LMDB_MAP_SIZE,
            )
            .expect("init node"),
        )
    }

    #[test]
    fn scan_chain_clamps_to_tip_on_idle_node() {
        let node = fresh_node("scanchain-idle");
        let handle = NodeHandleImpl(node.clone());

        let scan = handle.scan_chain(0, 100).expect("scan ok on idle node");
        let tip = node.chain.try_lock().expect("idle chain lock").tip_height.0;
        assert_eq!(scan.tip.height, tip, "scan reports the real tip");
        assert_eq!(scan.from, 0);
        assert_eq!(scan.to, 100u64.min(tip), "to is clamped to the tip");
        // Every returned block is within the served range.
        assert!(scan.blocks.iter().all(|b| b.height <= scan.to));
    }

    #[test]
    fn scan_chain_yields_to_busy_chain_lock() {
        // GOLDEN RULE: a busy chain (mining / connecting) must get a retriable
        // 503 immediately — the scan never waits on the lock.
        let node = fresh_node("scanchain-busy");
        let handle = NodeHandleImpl(node.clone());

        let _chain_guard = node.chain.try_lock().expect("hold chain lock");
        let err = handle
            .scan_chain(0, 10)
            .expect_err("scan must not block on a held chain lock");
        assert!(
            matches!(err, dom_rpc::RpcError::Overloaded(ref m) if m.contains("chain busy")),
            "expected retriable Overloaded, got {err}"
        );
    }
}
