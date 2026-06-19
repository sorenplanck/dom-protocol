use dom_chain::ChainState;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    compute_block_pmmr_roots, derive_chain_id, Block, CoinbaseKernel, CoinbaseTransaction,
    Transaction, TransactionKernel, TransactionOutput,
};
use dom_core::{
    Amount, BlockHeight, DomError, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN,
    NETWORK_MAGIC_REGTEST, PROTOCOL_VERSION, TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::{
    hash::blake2b_256_tagged,
    keys::SecretKey,
    pedersen::{BlindingFactor, Commitment},
    schnorr_sign,
};
use dom_node::missing_block_tracker::MissingBlockTracker;
use dom_node::orphan_pool::{OrphanBlock, OrphanInsertOutcome, RuntimeOrphanPool};
use dom_pow::{
    compute_expected_target, fast_pow_hash, genesis_anchor, hash_meets_target, target_to_compact,
    target_to_difficulty, CompactTarget,
};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_store::DomStore;
use primitive_types::U256;
use std::collections::BTreeSet;

// Windows CI reserves the LMDB map size on disk, so multi-node fixtures must
// not open production-sized (16 GiB) maps. These fixtures are tiny.
const TEST_LMDB_MAP_SIZE: usize = 64 << 20; // 64 MiB
use tempfile::TempDir;

fn scalar(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic scalar")
}

fn build_coinbase(
    height: BlockHeight,
    claimed_fees: u64,
    seed: u8,
    chain_id: &[u8; 32],
) -> CoinbaseTransaction {
    let reward = dom_core::block_reward(height).noms();
    let explicit_value = reward + claimed_fees;
    let blinding = scalar(seed);
    let commitment = Commitment::commit(explicit_value, &blinding);
    let (proof, _) = dom_crypto::bp2_prove(explicit_value, &blinding).expect("coinbase proof");
    let excess = Commitment::commit(0, &blinding);
    let secret = SecretKey::from_bytes(blinding.as_bytes()).expect("coinbase secret");
    let msg = {
        let mut data = Vec::with_capacity(1 + 8);
        data.push(KERNEL_FEAT_COINBASE);
        data.extend_from_slice(&explicit_value.to_le_bytes());
        blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data)
    };
    let sig = schnorr_sign(&secret, msg.as_bytes(), chain_id).expect("coinbase sig");
    CoinbaseTransaction {
        output: TransactionOutput { commitment, proof },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value,
            excess,
            excess_signature: sig.to_bytes(),
        },
        offset: [0u8; 32],
    }
}

#[allow(clippy::too_many_arguments)]
fn mine_fast_header(
    seed_hash: [u8; 32],
    prev_hash: Hash256,
    height: BlockHeight,
    timestamp: Timestamp,
    output_root: Hash256,
    kernel_root: Hash256,
    rangeproof_root: Hash256,
    total_kernel_offset: [u8; 32],
    total_difficulty: U256,
) -> BlockHeader {
    let target = compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, height).expect("target");
    let mut nonce = 0u64;
    loop {
        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            height,
            prev_hash,
            timestamp,
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset,
            target: CompactTarget(target_to_compact(&target)),
            total_difficulty,
            pow: ProofOfWork {
                nonce,
                randomx_hash: Hash256::ZERO,
            },
        };
        let hash = fast_pow_hash(&seed_hash, &header.pow_preimage());
        if hash_meets_target(&hash, &target) {
            header.pow.randomx_hash = Hash256::from_bytes(hash);
            return header;
        }
        nonce = nonce.wrapping_add(1);
    }
}

fn block_hash(block: &Block) -> Hash256 {
    Hash256::from_bytes(
        *dom_crypto::hash::blake2b_256(&block.header.to_bytes().unwrap()).as_bytes(),
    )
}

fn build_coinbase_only_block(
    seed_hash: [u8; 32],
    prev_hash: Hash256,
    height: BlockHeight,
    parent_total_difficulty: U256,
    coinbase_seed: u8,
    chain_id: &[u8; 32],
) -> Block {
    let coinbase = build_coinbase(height, 0, coinbase_seed, chain_id);
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, &[]).expect("roots");
    let timestamp = genesis_anchor(NETWORK_MAGIC_REGTEST)
        .expect("anchor")
        .timestamp
        .checked_add_secs(height.0 * dom_core::TARGET_SPACING)
        .expect("timestamp");
    let target = compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, height).expect("target");
    let canonical_target = CompactTarget(target_to_compact(&target))
        .to_target()
        .expect("compact target round-trip");
    let total_difficulty =
        parent_total_difficulty + U256::from(target_to_difficulty(&canonical_target));
    let header = mine_fast_header(
        seed_hash,
        prev_hash,
        height,
        timestamp,
        output_root,
        kernel_root,
        rangeproof_root,
        [0u8; 32],
        total_difficulty,
    );
    Block {
        header,
        coinbase,
        transactions: vec![],
    }
}

#[derive(Clone)]
struct BlockFixture {
    block: Block,
    hash: Hash256,
}

fn fixture(
    seed_hash: [u8; 32],
    parent_hash: Hash256,
    parent_total_difficulty: U256,
    height: u64,
    coinbase_seed: u8,
    chain_id: &[u8; 32],
) -> BlockFixture {
    let block = build_coinbase_only_block(
        seed_hash,
        parent_hash,
        BlockHeight(height),
        parent_total_difficulty,
        coinbase_seed,
        chain_id,
    );
    let hash = block_hash(&block);
    BlockFixture { block, hash }
}

fn utxo_digest(store: &DomStore) -> [u8; 32] {
    digest_raw_kv(
        b"NODE_REORDERED_DELIVERY_UTXO_V1",
        store.read_all_utxos_raw().expect("utxo dump"),
    )
}

fn digest_raw_kv(tag: &[u8], entries: std::collections::BTreeMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(tag);
    for (key, value) in entries {
        bytes.extend_from_slice(&(key.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&key);
        bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&value);
    }
    *dom_crypto::hash::blake2b_256(&bytes).as_bytes()
}

fn kernel_index_digest(store: &DomStore) -> [u8; 32] {
    digest_raw_kv(
        b"NODE_REORDERED_DELIVERY_KERNEL_INDEX_V1",
        store.read_all_kernel_index_raw().expect("kernel dump"),
    )
}

fn pmmr_digest(chain: &ChainState) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"NODE_REORDERED_DELIVERY_PMMR_ROOTS_V1");
    for height in 0..=chain.tip_height.0 {
        let hash = chain
            .store
            .get_hash_at_height(height)
            .expect("height lookup")
            .expect("canonical hash");
        let header_bytes = chain
            .store
            .get_block_header(&hash)
            .expect("header lookup")
            .expect("canonical header");
        let header = BlockHeader::from_bytes(&header_bytes).expect("header decode");
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&hash);
        bytes.extend_from_slice(header.output_root.as_bytes());
        bytes.extend_from_slice(header.kernel_root.as_bytes());
        bytes.extend_from_slice(header.rangeproof_root.as_bytes());
    }
    *dom_crypto::hash::blake2b_256(&bytes).as_bytes()
}

fn mempool_tx(seed: u8, fee_multiplier: u64) -> (Transaction, [u8; 32]) {
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![TransactionOutput {
            commitment: Commitment::commit(10 + u64::from(seed), &scalar(seed)),
            proof: vec![seed; 100],
        }],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(dom_core::MIN_RELAY_FEE_RATE * fee_multiplier).expect("fee"),
            lock_height: 0,
            excess: Commitment::commit(0, &scalar(seed.wrapping_add(100))),
            excess_signature: [seed; 65],
        }],
        offset: [0u8; 32],
    };
    let hash = *dom_crypto::hash::blake2b_256(&tx.to_bytes().expect("tx bytes")).as_bytes();
    (tx, hash)
}

fn retained_side_hashes(chain: &ChainState) -> BTreeSet<[u8; 32]> {
    let canonical: BTreeSet<[u8; 32]> = (0..=chain.tip_height.0)
        .filter_map(|height| chain.store.get_hash_at_height(height).unwrap())
        .collect();
    chain
        .store
        .read_all_block_headers_raw()
        .expect("headers")
        .into_keys()
        .filter(|hash| !canonical.contains(hash))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    tip_hash: [u8; 32],
    height: u64,
    total_difficulty: U256,
    utxo_digest: [u8; 32],
    pmmr_digest: [u8; 32],
    kernel_index_digest: [u8; 32],
    mempool_digest: [u8; 32],
    orphan_len: usize,
    missing_len: usize,
    retained_side_hashes: BTreeSet<[u8; 32]>,
}

struct HarnessNode {
    dir: TempDir,
    chain: ChainState,
    mempool: dom_mempool::Mempool,
    tracker: MissingBlockTracker,
    orphans: RuntimeOrphanPool,
    now: Timestamp,
}

impl HarnessNode {
    fn new(orphan_total: usize, per_parent: usize) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let store =
            DomStore::open_with_map_size(dir.path(), TEST_LMDB_MAP_SIZE).expect("store open");
        let chain = ChainState::open(
            store,
            Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
            NETWORK_MAGIC_REGTEST,
        )
        .expect("chain open");
        Self {
            dir,
            chain,
            mempool: dom_mempool::Mempool::new(),
            tracker: MissingBlockTracker::new(8, 2, 8),
            orphans: RuntimeOrphanPool::new(orphan_total, per_parent),
            now: Timestamp(2_000_000_000),
        }
    }

    fn reconnect_runtime(&mut self, orphan_total: usize, per_parent: usize) {
        let store = DomStore::open_with_map_size(self.dir.path(), TEST_LMDB_MAP_SIZE)
            .expect("store reopen");
        self.chain = ChainState::open(
            store,
            Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
            NETWORK_MAGIC_REGTEST,
        )
        .expect("chain reopen");
        self.tracker = MissingBlockTracker::new(8, 2, 8);
        self.orphans = RuntimeOrphanPool::new(orphan_total, per_parent);
    }

    fn deliver(&mut self, block: &Block) -> Result<(), DomError> {
        self.deliver_bytes(block.to_bytes()?)
    }

    fn deliver_tx(&mut self, tx: Transaction, tx_hash: [u8; 32], now: u64) -> Result<(), DomError> {
        match self.mempool.accept_tx(tx, tx_hash, now) {
            Ok(()) | Err(DomError::PolicyRejected(_)) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn deliver_bytes(&mut self, block_bytes: Vec<u8>) -> Result<(), DomError> {
        let block = Block::from_bytes(&block_bytes)?;
        let hash = block_hash(&block);
        match self.chain.connect_block(&block, self.now) {
            Ok(_) => {
                self.tracker.resolve(hash.as_bytes());
                let children = self.orphans.take_children(hash.as_bytes());
                for child in children {
                    self.deliver_bytes(child.block_bytes)?;
                }
                Ok(())
            }
            Err(DomError::Orphan(_)) => {
                let orphan = OrphanBlock {
                    block_hash: *hash.as_bytes(),
                    parent_hash: *block.header.prev_hash.as_bytes(),
                    height: block.header.height.0,
                    block_bytes,
                };
                let outcome = self.orphans.insert(orphan.clone());
                if matches!(
                    outcome,
                    OrphanInsertOutcome::Inserted
                        | OrphanInsertOutcome::Duplicate
                        | OrphanInsertOutcome::EvictedOldest
                ) {
                    self.tracker.note_orphan(
                        orphan.block_hash,
                        orphan.parent_hash,
                        orphan.height.checked_sub(1),
                    );
                }
                Ok(())
            }
            Err(other) => Err(other),
        }
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            tip_hash: *self.chain.tip_hash.as_bytes(),
            height: self.chain.tip_height.0,
            total_difficulty: self.chain.tip_difficulty,
            utxo_digest: utxo_digest(&self.chain.store),
            pmmr_digest: pmmr_digest(&self.chain),
            kernel_index_digest: kernel_index_digest(&self.chain.store),
            mempool_digest: self.mempool.digest(),
            orphan_len: self.orphans.len(),
            missing_len: self.tracker.missing_len(),
            retained_side_hashes: retained_side_hashes(&self.chain),
        }
    }
}

fn assert_snapshots_equal(label: &str, left: &Snapshot, right: &Snapshot) {
    assert_eq!(
        left, right,
        "{label} diverged\nleft={left:#?}\nright={right:#?}"
    );
}

fn test_chain_id() -> [u8; 32] {
    *derive_chain_id(
        NETWORK_MAGIC_REGTEST,
        &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
    )
    .as_bytes()
}

#[test]
fn out_of_order_child_then_parent_converges_to_normal_tip() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let chain_id = test_chain_id();
    let genesis = fixture([0u8; 32], Hash256::ZERO, U256::zero(), 0, 10, &chain_id);
    let seed = *genesis.hash.as_bytes();
    let parent = fixture(
        seed,
        genesis.hash,
        genesis.block.header.total_difficulty,
        1,
        11,
        &chain_id,
    );
    let child = fixture(
        seed,
        parent.hash,
        parent.block.header.total_difficulty,
        2,
        12,
        &chain_id,
    );

    let mut ordered = HarnessNode::new(16, 8);
    ordered.deliver(&genesis.block).unwrap();
    ordered.deliver(&parent.block).unwrap();
    ordered.deliver(&child.block).unwrap();

    let mut reordered = HarnessNode::new(16, 8);
    reordered.deliver(&genesis.block).unwrap();
    reordered.deliver(&child.block).unwrap();
    assert_eq!(reordered.orphans.len(), 1);
    reordered.deliver(&parent.block).unwrap();

    assert_eq!(reordered.snapshot(), ordered.snapshot());
}

#[test]
fn multi_level_orphan_delivery_converges() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let chain_id = test_chain_id();
    let genesis = fixture([0u8; 32], Hash256::ZERO, U256::zero(), 0, 20, &chain_id);
    let seed = *genesis.hash.as_bytes();
    let parent = fixture(
        seed,
        genesis.hash,
        genesis.block.header.total_difficulty,
        1,
        21,
        &chain_id,
    );
    let child = fixture(
        seed,
        parent.hash,
        parent.block.header.total_difficulty,
        2,
        22,
        &chain_id,
    );
    let grandchild = fixture(
        seed,
        child.hash,
        child.block.header.total_difficulty,
        3,
        23,
        &chain_id,
    );

    let mut ordered = HarnessNode::new(16, 8);
    for block in [
        &genesis.block,
        &parent.block,
        &child.block,
        &grandchild.block,
    ] {
        ordered.deliver(block).unwrap();
    }

    let mut reordered = HarnessNode::new(16, 8);
    reordered.deliver(&genesis.block).unwrap();
    reordered.deliver(&grandchild.block).unwrap();
    reordered.deliver(&child.block).unwrap();
    assert_eq!(reordered.orphans.len(), 2);
    reordered.deliver(&parent.block).unwrap();

    assert_eq!(reordered.snapshot(), ordered.snapshot());
}

#[test]
fn duplicate_orphan_delivery_is_idempotent() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let chain_id = test_chain_id();
    let genesis = fixture([0u8; 32], Hash256::ZERO, U256::zero(), 0, 30, &chain_id);
    let seed = *genesis.hash.as_bytes();
    let parent = fixture(
        seed,
        genesis.hash,
        genesis.block.header.total_difficulty,
        1,
        31,
        &chain_id,
    );
    let child = fixture(
        seed,
        parent.hash,
        parent.block.header.total_difficulty,
        2,
        32,
        &chain_id,
    );

    let mut once = HarnessNode::new(16, 8);
    once.deliver(&genesis.block).unwrap();
    once.deliver(&child.block).unwrap();
    once.deliver(&parent.block).unwrap();

    let mut duplicate = HarnessNode::new(16, 8);
    duplicate.deliver(&genesis.block).unwrap();
    duplicate.deliver(&child.block).unwrap();
    duplicate.deliver(&child.block).unwrap();
    assert_eq!(
        duplicate.orphans.len(),
        1,
        "duplicate child must not duplicate pool state"
    );
    duplicate.deliver(&parent.block).unwrap();

    assert_eq!(duplicate.snapshot(), once.snapshot());
}

#[test]
fn bounded_orphan_spam_is_pruned_deterministically() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let chain_id = test_chain_id();
    let genesis = fixture([0u8; 32], Hash256::ZERO, U256::zero(), 0, 40, &chain_id);
    let seed = *genesis.hash.as_bytes();
    let parent = fixture(
        seed,
        genesis.hash,
        genesis.block.header.total_difficulty,
        1,
        41,
        &chain_id,
    );
    let keep_a = fixture(
        seed,
        parent.hash,
        parent.block.header.total_difficulty,
        2,
        42,
        &chain_id,
    );
    let keep_b = fixture(
        seed,
        parent.hash,
        parent.block.header.total_difficulty,
        2,
        43,
        &chain_id,
    );
    let drop_c = fixture(
        seed,
        parent.hash,
        parent.block.header.total_difficulty,
        2,
        44,
        &chain_id,
    );

    let mut node = HarnessNode::new(4, 2);
    node.deliver(&genesis.block).unwrap();
    node.deliver(&keep_a.block).unwrap();
    node.deliver(&keep_b.block).unwrap();
    node.deliver(&drop_c.block).unwrap();

    assert_eq!(
        node.orphans.len(),
        2,
        "per-parent bound must cap retained orphans"
    );

    node.deliver(&parent.block).unwrap();
    let snapshot = node.snapshot();
    assert_eq!(snapshot.orphan_len, 0);
    assert_eq!(snapshot.missing_len, 0);
    assert_eq!(snapshot.height, 2);
    let expected_tip = if keep_a.hash.as_bytes() <= keep_b.hash.as_bytes() {
        *keep_a.hash.as_bytes()
    } else {
        *keep_b.hash.as_bytes()
    };
    assert_eq!(snapshot.tip_hash, expected_tip);
}

#[test]
fn reordered_delivery_matches_normal_delivery_deep_state() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let chain_id = test_chain_id();
    let genesis = fixture([0u8; 32], Hash256::ZERO, U256::zero(), 0, 50, &chain_id);
    let seed = *genesis.hash.as_bytes();
    let a1 = fixture(
        seed,
        genesis.hash,
        genesis.block.header.total_difficulty,
        1,
        51,
        &chain_id,
    );
    let a2 = fixture(
        seed,
        a1.hash,
        a1.block.header.total_difficulty,
        2,
        52,
        &chain_id,
    );
    let b2 = fixture(
        seed,
        a1.hash,
        a1.block.header.total_difficulty,
        2,
        53,
        &chain_id,
    );
    let b3 = fixture(
        seed,
        b2.hash,
        b2.block.header.total_difficulty,
        3,
        54,
        &chain_id,
    );

    let mut normal = HarnessNode::new(16, 8);
    for block in [&genesis.block, &a1.block, &a2.block, &b2.block, &b3.block] {
        normal.deliver(block).unwrap();
    }

    let mut reordered = HarnessNode::new(16, 8);
    for block in [&genesis.block, &b3.block, &a2.block, &a1.block, &b2.block] {
        reordered.deliver(block).unwrap();
    }

    assert_eq!(reordered.snapshot(), normal.snapshot());
}

#[test]
fn equivalent_live_timelines_converge_to_identical_deep_snapshots() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let chain_id = test_chain_id();
    let genesis = fixture([0u8; 32], Hash256::ZERO, U256::zero(), 0, 60, &chain_id);
    let seed = *genesis.hash.as_bytes();
    let a1 = fixture(
        seed,
        genesis.hash,
        genesis.block.header.total_difficulty,
        1,
        61,
        &chain_id,
    );
    let a2 = fixture(
        seed,
        a1.hash,
        a1.block.header.total_difficulty,
        2,
        62,
        &chain_id,
    );
    let b2 = fixture(
        seed,
        a1.hash,
        a1.block.header.total_difficulty,
        2,
        63,
        &chain_id,
    );
    let b3 = fixture(
        seed,
        b2.hash,
        b2.block.header.total_difficulty,
        3,
        64,
        &chain_id,
    );
    let (tx_a, tx_a_hash) = mempool_tx(0xA0, 100);
    let (tx_b, tx_b_hash) = mempool_tx(0xB0, 200);

    let mut ordered = HarnessNode::new(16, 8);
    for block in [&genesis.block, &a1.block, &a2.block, &b2.block, &b3.block] {
        ordered.deliver(block).unwrap();
    }
    ordered.deliver_tx(tx_a.clone(), tx_a_hash, 10).unwrap();
    ordered.deliver_tx(tx_b.clone(), tx_b_hash, 20).unwrap();
    let ordered_snapshot = ordered.snapshot();

    let mut reversed_valid = HarnessNode::new(16, 8);
    for block in [&genesis.block, &a1.block, &b2.block, &a2.block, &b3.block] {
        reversed_valid.deliver(block).unwrap();
    }
    reversed_valid
        .deliver_tx(tx_b.clone(), tx_b_hash, 20)
        .unwrap();
    reversed_valid
        .deliver_tx(tx_a.clone(), tx_a_hash, 10)
        .unwrap();
    reversed_valid
        .deliver_tx(tx_a.clone(), tx_a_hash, 10)
        .unwrap();
    let reversed_snapshot = reversed_valid.snapshot();

    let mut delayed_parent = HarnessNode::new(16, 8);
    for block in [&genesis.block, &b3.block, &a2.block, &a1.block, &b2.block] {
        delayed_parent.deliver(block).unwrap();
    }
    delayed_parent
        .deliver_tx(tx_a.clone(), tx_a_hash, 10)
        .unwrap();
    delayed_parent
        .deliver_tx(tx_b.clone(), tx_b_hash, 20)
        .unwrap();
    let delayed_snapshot = delayed_parent.snapshot();

    let mut reconnect_mid_delivery = HarnessNode::new(16, 8);
    reconnect_mid_delivery.deliver(&genesis.block).unwrap();
    reconnect_mid_delivery.deliver(&b3.block).unwrap();
    assert_eq!(reconnect_mid_delivery.orphans.len(), 1);
    reconnect_mid_delivery
        .deliver_tx(tx_b.clone(), tx_b_hash, 20)
        .unwrap();
    reconnect_mid_delivery.reconnect_runtime(16, 8);
    assert_eq!(
        reconnect_mid_delivery.orphans.len(),
        0,
        "runtime orphan pool is not persisted across reconnect"
    );
    for block in [&a1.block, &b2.block, &b3.block, &a2.block, &b3.block] {
        reconnect_mid_delivery.deliver(block).unwrap();
    }
    reconnect_mid_delivery
        .deliver_tx(tx_a.clone(), tx_a_hash, 10)
        .unwrap();
    reconnect_mid_delivery
        .deliver_tx(tx_b.clone(), tx_b_hash, 20)
        .unwrap();
    let reconnect_snapshot = reconnect_mid_delivery.snapshot();

    for (label, snapshot) in [
        ("reversed-valid", &reversed_snapshot),
        ("delayed-parent", &delayed_snapshot),
        ("reconnect-mid-delivery", &reconnect_snapshot),
    ] {
        assert_snapshots_equal(label, &ordered_snapshot, snapshot);
        assert_eq!(snapshot.orphan_len, 0, "{label} retained no orphans");
        assert_eq!(
            snapshot.missing_len, 0,
            "{label} retained no missing parents"
        );
        assert_eq!(
            snapshot.height, 3,
            "{label} converged to the promoted branch"
        );
        assert_eq!(
            snapshot.tip_hash,
            *b3.hash.as_bytes(),
            "{label} converged to the same canonical tip"
        );
    }
}
