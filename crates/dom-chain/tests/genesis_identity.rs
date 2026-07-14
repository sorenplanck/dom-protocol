mod common;

use common::open_test_chain;
use dom_chain::{ChainState, ConnectResult};
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    compute_block_pmmr_roots, derive_chain_id, Block, CoinbaseKernel, CoinbaseTransaction,
    TransactionOutput,
};
use dom_core::{
    BlockHeight, DomError, Hash256, Timestamp, KERNEL_FEAT_COINBASE, NETWORK_MAGIC_REGTEST,
    PROTOCOL_VERSION, TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::{
    hash::{blake2b_256, blake2b_256_tagged},
    keys::SecretKey,
    pedersen::{BlindingFactor, Commitment},
    schnorr_sign,
};
use dom_pow::{
    compute_expected_target, fast_pow_hash, genesis_anchor, hash_meets_target, target_to_compact,
    target_to_difficulty, CompactTarget,
};
use dom_serialization::DomSerialize;
use primitive_types::U256;
use tempfile::TempDir;

fn scalar(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic scalar")
}

fn block_hash(block: &Block) -> Hash256 {
    Hash256::from_bytes(*blake2b_256(&block.header.to_bytes().expect("header bytes")).as_bytes())
}

fn open_chain(path: &std::path::Path, configured_genesis_hash: Hash256) -> ChainState {
    open_test_chain(path, configured_genesis_hash, NETWORK_MAGIC_REGTEST).expect("chain open")
}

fn build_coinbase(height: BlockHeight, seed: u8, chain_id: &[u8; 32]) -> CoinbaseTransaction {
    let explicit_value = dom_core::block_reward(height).noms();
    let blinding = scalar(seed);
    let commitment = Commitment::commit(explicit_value, &blinding);
    let (proof, _) = dom_crypto::bp2_prove(explicit_value, &blinding).expect("coinbase proof");
    let excess = Commitment::commit(0, &blinding);
    let secret = SecretKey::from_bytes(blinding.as_bytes()).expect("coinbase secret");
    let mut data = Vec::with_capacity(1 + 8);
    data.push(KERNEL_FEAT_COINBASE);
    data.extend_from_slice(&explicit_value.to_le_bytes());
    let msg = blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data);
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

fn mine_fast_header(
    seed_hash: [u8; 32],
    timestamp: Timestamp,
    output_root: Hash256,
    kernel_root: Hash256,
    rangeproof_root: Hash256,
    total_difficulty: U256,
) -> BlockHeader {
    let target = compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, BlockHeight::GENESIS)
        .expect("target");
    let mut nonce = 0u64;
    loop {
        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            height: BlockHeight::GENESIS,
            prev_hash: Hash256::ZERO,
            timestamp,
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0u8; 32],
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

fn genesis_block(coinbase_seed: u8, chain_id: &[u8; 32]) -> Block {
    let coinbase = build_coinbase(BlockHeight::GENESIS, coinbase_seed, chain_id);
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, &[]).expect("roots");
    let anchor = genesis_anchor(NETWORK_MAGIC_REGTEST).expect("anchor");
    let target = compute_expected_target(
        NETWORK_MAGIC_REGTEST,
        anchor.timestamp,
        BlockHeight::GENESIS,
    )
    .expect("target");
    let canonical_target = CompactTarget(target_to_compact(&target))
        .to_target()
        .expect("compact target round-trip");
    let total_difficulty = U256::from(target_to_difficulty(&canonical_target));
    let header = mine_fast_header(
        [0u8; 32],
        anchor.timestamp,
        output_root,
        kernel_root,
        rangeproof_root,
        total_difficulty,
    );
    Block {
        header,
        coinbase,
        transactions: vec![],
    }
}

fn assert_genesis_rejected(err: &DomError) {
    assert!(
        matches!(err, DomError::Invalid(_)),
        "invalid genesis identity must be rejected as Invalid, got {err:?}"
    );
    assert!(
        err.to_string().contains("genesis"),
        "error must identify genesis identity, got {err}"
    );
}

#[test]
fn configured_genesis_hash_rejects_alternate_height_zero_before_persistence() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let configured_genesis_hash = Hash256::from_bytes([0x42; 32]);
    let chain_id = *derive_chain_id(NETWORK_MAGIC_REGTEST, &configured_genesis_hash).as_bytes();
    let candidate = genesis_block(10, &chain_id);
    assert_ne!(block_hash(&candidate), configured_genesis_hash);

    let dir = TempDir::new().expect("tempdir");
    let mut chain = open_chain(dir.path(), configured_genesis_hash);
    let candidate_hash = block_hash(&candidate);
    let err = chain
        .connect_block(&candidate, Timestamp(2_000_000_000))
        .expect_err("alternate configured genesis must fail before persistence");
    assert_genesis_rejected(&err);
    assert_eq!(chain.tip_hash, Hash256::ZERO);
    assert!(
        chain
            .store
            .get_block_body(candidate_hash.as_bytes())
            .expect("read rejected body")
            .is_none(),
        "rejected alternate genesis must not persist a block body"
    );
}

#[test]
fn header_only_and_ibd_reject_alternate_configured_genesis() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let configured_genesis_hash = Hash256::from_bytes([0x43; 32]);
    let chain_id = *derive_chain_id(NETWORK_MAGIC_REGTEST, &configured_genesis_hash).as_bytes();
    let candidate = genesis_block(11, &chain_id);
    assert_ne!(block_hash(&candidate), configured_genesis_hash);

    let dir = TempDir::new().expect("tempdir");
    let chain = open_chain(dir.path(), configured_genesis_hash);
    let header_err = chain
        .validate_header_only(&candidate.header, Timestamp(2_000_000_000))
        .expect_err("header-only path must reject alternate configured genesis");
    assert_genesis_rejected(&header_err);

    let header_bytes = candidate.header.to_bytes().expect("header bytes");
    let ibd_err = chain
        .validate_ibd_headers_batch(&[header_bytes], Timestamp(2_000_000_000))
        .expect_err("IBD header batch must reject alternate configured genesis");
    assert_genesis_rejected(&ibd_err);
    assert_eq!(chain.tip_hash, Hash256::ZERO);
}

#[test]
fn height_zero_nonzero_prev_hash_rejected_before_persistence() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let configured_genesis_hash = Hash256::ZERO;
    let chain_id = *derive_chain_id(NETWORK_MAGIC_REGTEST, &configured_genesis_hash).as_bytes();
    let mut candidate = genesis_block(12, &chain_id);
    candidate.header.prev_hash = Hash256::from_bytes([0x01; 32]);
    let candidate_hash = block_hash(&candidate);

    let dir = TempDir::new().expect("tempdir");
    let mut chain = open_chain(dir.path(), configured_genesis_hash);
    let err = chain
        .connect_block(&candidate, Timestamp(2_000_000_000))
        .expect_err("height-zero nonzero prev_hash must reject");
    assert_genesis_rejected(&err);
    assert!(
        chain
            .store
            .get_block_body(candidate_hash.as_bytes())
            .expect("read rejected body")
            .is_none(),
        "rejected height-zero block must not persist a body"
    );
}

#[test]
fn height_zero_after_genesis_exists_rejects_alternate_and_preserves_original() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let configured_genesis_hash = Hash256::ZERO;
    let chain_id = *derive_chain_id(NETWORK_MAGIC_REGTEST, &configured_genesis_hash).as_bytes();
    let first = genesis_block(20, &chain_id);
    let first_hash = block_hash(&first);
    let alternate = (21u8..=250)
        .map(|seed| genesis_block(seed, &chain_id))
        .find(|block| block_hash(block).as_bytes() < first_hash.as_bytes())
        .expect("alternate lower hash genesis fixture");
    let alternate_hash = block_hash(&alternate);

    let dir = TempDir::new().expect("tempdir");
    let mut chain = open_chain(dir.path(), configured_genesis_hash);
    assert_eq!(
        chain
            .connect_block(&first, Timestamp(2_000_000_000))
            .expect("first genesis"),
        ConnectResult::BestChain
    );
    assert_eq!(chain.tip_hash, first_hash);

    let err = chain
        .connect_block(&alternate, Timestamp(2_000_000_000))
        .expect_err("second height-zero block must not replace canonical genesis");
    assert_genesis_rejected(&err);
    assert_eq!(chain.tip_hash, first_hash);
    assert_eq!(
        chain
            .store
            .get_hash_at_height(0)
            .expect("read height zero")
            .expect("height zero hash"),
        *first_hash.as_bytes()
    );
    assert!(
        chain
            .store
            .get_block_body(alternate_hash.as_bytes())
            .expect("read alternate body")
            .is_none(),
        "rejected alternate height-zero block must not persist a body"
    );
}

#[test]
fn reopen_rejects_stored_genesis_inconsistent_with_configured_network_identity() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let original_configured_hash = Hash256::ZERO;
    let chain_id = *derive_chain_id(NETWORK_MAGIC_REGTEST, &original_configured_hash).as_bytes();
    let genesis = genesis_block(30, &chain_id);
    let genesis_hash = block_hash(&genesis);

    let dir = TempDir::new().expect("tempdir");
    {
        let mut chain = open_chain(dir.path(), original_configured_hash);
        assert_eq!(
            chain
                .connect_block(&genesis, Timestamp(2_000_000_000))
                .expect("first genesis"),
            ConnectResult::BestChain
        );
        assert_eq!(chain.tip_hash, genesis_hash);
    }

    let mismatched_configured_hash = Hash256::from_bytes([0x44; 32]);
    let err = match open_test_chain(
        dir.path(),
        mismatched_configured_hash,
        NETWORK_MAGIC_REGTEST,
    ) {
        Ok(_) => panic!("reopen must reject stored genesis that mismatches configured identity"),
        Err(err) => err,
    };
    assert_genesis_rejected(&err);
}
