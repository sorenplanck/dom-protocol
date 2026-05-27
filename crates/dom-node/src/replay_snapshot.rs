//! Deterministic replay-equivalence snapshot tooling.

use crate::node::load_peer_rotation_snapshot;
use dom_chain::{ChainState, PersistedIbdState};
use dom_core::DomError;
use dom_mempool::Mempool;
use dom_wire::manager::{PeerManager, PersistedPeerRotationState};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Canonical replay-equivalence snapshot for focused convergence checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaySnapshot {
    /// Canonical chain tip height.
    pub chain_tip_height: u64,
    /// Canonical chain tip hash.
    pub chain_tip_hash: [u8; 32],
    /// Persisted IBD session snapshot, if present.
    pub persisted_ibd: Option<PersistedIbdState>,
    /// Persisted peer-rotation state, if present.
    pub persisted_peer_rotation: Option<PersistedPeerRotationState>,
    /// Runtime peer-rotation state captured canonically.
    pub runtime_peer_rotation: PersistedPeerRotationState,
    /// Canonical mempool transaction hashes.
    pub mempool_hashes: Vec<[u8; 32]>,
}

/// Field-level replay mismatch report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaySnapshotDiff {
    /// Canonical field names whose values diverged.
    pub fields: Vec<&'static str>,
}

impl ReplaySnapshotDiff {
    /// Returns true when no divergence was detected.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl ReplaySnapshot {
    /// Capture a deterministic snapshot from concrete runtime references.
    pub fn capture(
        chain: &ChainState,
        mempool: &Mempool,
        peers: &PeerManager,
    ) -> Result<Self, DomError> {
        Ok(Self {
            chain_tip_height: chain.tip_height.0,
            chain_tip_hash: *chain.tip_hash.as_bytes(),
            persisted_ibd: PersistedIbdState::load(&chain.store)?,
            persisted_peer_rotation: load_peer_rotation_snapshot(&chain.store)?,
            runtime_peer_rotation: peers.outbound_failure_state(),
            mempool_hashes: mempool.all_hashes(),
        })
    }

    /// Capture a deterministic snapshot from the live node mutex graph.
    pub async fn capture_runtime(
        chain: &Arc<Mutex<ChainState>>,
        mempool: &Arc<Mutex<Mempool>>,
        peers: &Arc<Mutex<PeerManager>>,
    ) -> Result<Self, DomError> {
        let chain = chain.lock().await;
        let mempool = mempool.lock().await;
        let peers = peers.lock().await;
        Self::capture(&chain, &mempool, &peers)
    }

    /// Compare two snapshots and report deterministic field-level divergence.
    pub fn diff(&self, other: &Self) -> ReplaySnapshotDiff {
        let mut fields = Vec::new();
        if self.chain_tip_height != other.chain_tip_height {
            fields.push("chain_tip_height");
        }
        if self.chain_tip_hash != other.chain_tip_hash {
            fields.push("chain_tip_hash");
        }
        if self.persisted_ibd != other.persisted_ibd {
            fields.push("persisted_ibd");
        }
        if self.persisted_peer_rotation != other.persisted_peer_rotation {
            fields.push("persisted_peer_rotation");
        }
        if self.runtime_peer_rotation != other.runtime_peer_rotation {
            fields.push("runtime_peer_rotation");
        }
        if self.mempool_hashes != other.mempool_hashes {
            fields.push("mempool_hashes");
        }
        ReplaySnapshotDiff { fields }
    }

    /// Enforce snapshot equivalence and report explicit divergence.
    pub fn assert_equivalent(&self, other: &Self) -> Result<(), DomError> {
        let diff = self.diff(other);
        if diff.is_empty() {
            return Ok(());
        }
        Err(DomError::Invalid(format!(
            "replay snapshot mismatch: {}",
            diff.fields.join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{persist_peer_rotation_snapshot, restore_peer_rotation_state};
    use dom_chain::{ChainState, IbdInterruption, IbdPhase, PersistedIbdState};
    use dom_consensus::transaction::{TransactionKernel, TransactionOutput};
    use dom_consensus::Transaction;
    use dom_core::{Amount, BlockHeight, Hash256, KERNEL_FEAT_PLAIN, NETWORK_MAGIC_REGTEST};
    use dom_crypto::pedersen::{BlindingFactor, Commitment};
    use dom_store::DomStore;
    use std::fs;
    use std::path::PathBuf;

    fn open_chain(dir: &std::path::Path) -> ChainState {
        let store = DomStore::open(dir).expect("open store");
        ChainState::open(
            store,
            Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
            NETWORK_MAGIC_REGTEST,
        )
        .expect("open chain")
    }

    fn fresh_test_dir(label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dom-replay-snapshot-{label}-{unique}"));
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    fn sample_ibd_state() -> PersistedIbdState {
        PersistedIbdState {
            phase: IbdPhase::BlockSync,
            peer_addr: "127.0.0.1:33369".into(),
            start_height: 7,
            best_peer_height: 11,
            headers_height: 9,
            blocks_height: 8,
            last_progress_height: 8,
            checkpoint_tip_hash: [0xAB; 32],
            retry_attempts: 2,
            last_interruption: Some(IbdInterruption::Timeout),
            pending_blocks: vec![[0x11; 32], [0x22; 32]],
            pending_headers: vec![vec![0x33; 64]],
            block_cursor: 1,
            header_cursor: 0,
            header_cursor_height: 9,
        }
    }

    fn commitment(seed: u8, value: u64) -> Commitment {
        let mut bytes = [0u8; 32];
        bytes[31] = seed.max(1);
        let blind = BlindingFactor::from_bytes(bytes).expect("blinding");
        Commitment::commit(value, &blind)
    }

    fn make_tx(fee_multiplier: u64, seed: u8) -> (Transaction, [u8; 32]) {
        use dom_serialization::DomSerialize;

        let tx = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: commitment(seed, 10 + u64::from(seed)),
                proof: vec![seed; 8],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(dom_core::MIN_RELAY_FEE_RATE * fee_multiplier).expect("fee"),
                lock_height: 0,
                excess: commitment(seed.wrapping_add(100), 0),
                excess_signature: [seed; 65],
            }],
            offset: [0u8; 32],
        };
        let hash = *dom_crypto::hash::blake2b_256(&tx.to_bytes().expect("tx bytes")).as_bytes();
        (tx, hash)
    }

    #[test]
    fn replay_snapshot_equivalence_is_canonical_across_insertion_order() {
        let dir_a = fresh_test_dir("equivalence-a");
        let dir_b = fresh_test_dir("equivalence-b");
        let mut chain_a = open_chain(&dir_a);
        let mut chain_b = open_chain(&dir_b);
        chain_a.tip_height = BlockHeight(8);
        chain_b.tip_height = BlockHeight(8);
        chain_a.tip_hash = Hash256::from_bytes([0x44; 32]);
        chain_b.tip_hash = Hash256::from_bytes([0x44; 32]);
        let ibd = sample_ibd_state();
        ibd.save(&chain_a.store).expect("save ibd a");
        ibd.save(&chain_b.store).expect("save ibd b");

        let mut peers_a = PeerManager::new(125, 2);
        let mut peers_b = PeerManager::new(125, 2);
        peers_a.record_outbound_failure("198.51.100.20:33369");
        peers_a.record_outbound_failure("198.51.100.30:33369");
        peers_b.record_outbound_failure("198.51.100.20:33369");
        peers_b.record_outbound_failure("198.51.100.30:33369");
        persist_peer_rotation_snapshot(&chain_a.store, &peers_a.outbound_failure_state())
            .expect("persist peers a");
        persist_peer_rotation_snapshot(&chain_b.store, &peers_b.outbound_failure_state())
            .expect("persist peers b");

        let (tx_a, hash_a) = make_tx(100, 1);
        let (tx_b, hash_b) = make_tx(200, 2);
        let mut mempool_a = Mempool::new();
        let mut mempool_b = Mempool::new();
        mempool_a
            .accept_tx(tx_a.clone(), hash_a, 1)
            .expect("mempool a1");
        mempool_a
            .accept_tx(tx_b.clone(), hash_b, 2)
            .expect("mempool a2");
        mempool_b.accept_tx(tx_b, hash_b, 2).expect("mempool b1");
        mempool_b.accept_tx(tx_a, hash_a, 1).expect("mempool b2");

        let snapshot_a =
            ReplaySnapshot::capture(&chain_a, &mempool_a, &peers_a).expect("capture a");
        let snapshot_b =
            ReplaySnapshot::capture(&chain_b, &mempool_b, &peers_b).expect("capture b");
        assert!(snapshot_a.diff(&snapshot_b).is_empty());
        snapshot_a
            .assert_equivalent(&snapshot_b)
            .expect("canonical snapshot equivalence");
        fs::remove_dir_all(&dir_a).expect("cleanup a");
        fs::remove_dir_all(&dir_b).expect("cleanup b");
    }

    #[test]
    fn replay_snapshot_peer_rotation_survives_reopen_and_restore() {
        let dir = fresh_test_dir("peer-rotation-reopen");
        let snapshot_before = {
            let mut chain = open_chain(&dir);
            chain.tip_height = BlockHeight(5);
            chain.tip_hash = Hash256::from_bytes([0x55; 32]);
            sample_ibd_state().save(&chain.store).expect("save ibd");

            let mut peers = PeerManager::new(125, 2);
            peers.record_outbound_failure("198.51.100.30:33369");
            peers.record_outbound_failure("198.51.100.30:33369");
            peers.record_outbound_failure("198.51.100.30:33369");
            persist_peer_rotation_snapshot(&chain.store, &peers.outbound_failure_state())
                .expect("persist peer rotation");
            ReplaySnapshot::capture(&chain, &Mempool::new(), &peers).expect("capture before")
        };

        let mut reopened_chain = open_chain(&dir);
        reopened_chain.tip_height = BlockHeight(5);
        reopened_chain.tip_hash = Hash256::from_bytes([0x55; 32]);
        let mut reopened_peers = PeerManager::new(125, 2);
        restore_peer_rotation_state(&reopened_chain.store, &mut reopened_peers)
            .expect("restore peer rotation");

        let snapshot_after =
            ReplaySnapshot::capture(&reopened_chain, &Mempool::new(), &reopened_peers)
                .expect("capture after");

        snapshot_before
            .assert_equivalent(&snapshot_after)
            .expect("reopen replay equivalence");
        fs::remove_dir_all(&dir).expect("cleanup reopen");
    }

    #[test]
    fn replay_snapshot_detects_peer_cooldown_divergence() {
        let base = ReplaySnapshot {
            chain_tip_height: 1,
            chain_tip_hash: [0x11; 32],
            persisted_ibd: None,
            persisted_peer_rotation: Some(PersistedPeerRotationState {
                next_failure_seq: 3,
                outbound_failures: vec![dom_wire::manager::PersistedOutboundFailure {
                    addr: "198.51.100.30:33369".into(),
                    failures: 3,
                    last_failure_seq: 3,
                    cooldown_rounds: 0,
                }],
            }),
            runtime_peer_rotation: PersistedPeerRotationState {
                next_failure_seq: 3,
                outbound_failures: vec![dom_wire::manager::PersistedOutboundFailure {
                    addr: "198.51.100.30:33369".into(),
                    failures: 3,
                    last_failure_seq: 3,
                    cooldown_rounds: 0,
                }],
            },
            mempool_hashes: vec![[0xAA; 32]],
        };
        let mut changed = base.clone();
        changed
            .persisted_peer_rotation
            .as_mut()
            .expect("persisted state")
            .outbound_failures[0]
            .cooldown_rounds = 2;
        changed.runtime_peer_rotation.outbound_failures[0].cooldown_rounds = 2;

        let diff = base.diff(&changed);
        assert_eq!(diff.fields, vec!["persisted_peer_rotation", "runtime_peer_rotation"]);
    }

    #[test]
    fn replay_snapshot_diff_reports_divergent_fields() {
        let base = ReplaySnapshot {
            chain_tip_height: 1,
            chain_tip_hash: [0x11; 32],
            persisted_ibd: None,
            persisted_peer_rotation: None,
            runtime_peer_rotation: PersistedPeerRotationState::default(),
            mempool_hashes: vec![[0xAA; 32]],
        };
        let mut changed = base.clone();
        changed.chain_tip_hash = [0x22; 32];
        changed.mempool_hashes = vec![[0xBB; 32]];

        let diff = base.diff(&changed);
        assert_eq!(diff.fields, vec!["chain_tip_hash", "mempool_hashes"]);
    }
}
