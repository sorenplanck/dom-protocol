//! dom-shield PROBE — FIX-018: reorg promotion skips the future-timestamp gate.
//!
//! `ChainState::promote_heavier_known_tip` used to validate each candidate block
//! on the promoted branch with `validate_block(block, &ctx)` while pinning
//! `ctx.now = Timestamp(u64::MAX)`. The shared `dom_consensus::validate_block`
//! does NOT enforce the future-timestamp limit at all — that limit
//! (`validate_future_timestamp_with_limit`) is applied by `ChainState` on the
//! live direct-connect and header-first paths. FIX-018 pins the equivalent gate
//! on reorg promotion.
//!
//! Consequence: a heavier side branch whose tip carries a timestamp arbitrarily
//! far in the future is rejected if offered as a DIRECT extension (future-time
//! gate fires), but is ACCEPTED when promoted via reorg (the gate is absent from
//! the validator the promotion path calls, and `now` is pinned to u64::MAX so it
//! could not fire even if present). This lets a miner with a heavier branch
//! inject a far-future block timestamp through the reorg door.
//!
//! ROOT-CAUSE PROBE (this test, runnable, GREEN): prove that the shared
//! validator `validate_block` accepts a fully-valid coinbase-only block whose
//! header timestamp is ~100 years in the future, under a realistic `now`. Since
//! reorg promotion relies on exactly this validator (with `now=u64::MAX`), this
//! demonstrates the missing gate. The GREEN assertion here IS the finding: a
//! hardened validator would either carry the future-time limit or the promotion
//! path would re-apply it.
//!
//! The end-to-end tests below store heavier side branches and then trigger
//! promotion. A far-future promoted branch must now be rejected, while a
//! timestamp-valid branch must still promote normally.

use dom_chain::ChainState;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::transaction::{CoinbaseKernel, CoinbaseTransaction, TransactionOutput};
use dom_consensus::{
    compute_block_pmmr_roots, derive_chain_id, validate_block, Block, ValidationContext,
};
use dom_core::{
    BlockHeight, DomError, Hash256, Timestamp, KERNEL_FEAT_COINBASE, NETWORK_MAGIC_REGTEST,
    PROTOCOL_VERSION, TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::keys::SecretKey;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::schnorr_sign;
use dom_pow::CompactTarget;
use dom_serialization::DomSerialize;
use dom_store::utxo::UtxoEntry;
use dom_store::DomStore;
use primitive_types::U256;

const FAR_FUTURE_TS: u64 = 1_700_000_000 + 100 * 365 * 24 * 3600; // ~100y ahead
const REALISTIC_NOW: u64 = 1_700_000_500; // a sane wall clock near genesis era
const TEST_LMDB_MAP_SIZE: usize = 64 << 20;

fn blinding(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic blinding")
}

fn regtest_chain_id() -> Hash256 {
    derive_chain_id(NETWORK_MAGIC_REGTEST, &Hash256::ZERO)
}

fn signed_coinbase(height: BlockHeight, seed: u8) -> CoinbaseTransaction {
    let reward = dom_core::block_reward(height).noms();
    let blinding = blinding(seed);
    let commitment = Commitment::commit(reward, &blinding);
    let (proof, _) = dom_crypto::bp2_prove(reward, &blinding).expect("coinbase proof");
    let excess = Commitment::commit(0, &blinding);
    let secret = SecretKey::from_bytes(blinding.as_bytes()).expect("coinbase secret");
    let msg = {
        let mut data = Vec::with_capacity(1 + 8);
        data.push(KERNEL_FEAT_COINBASE);
        data.extend_from_slice(&reward.to_le_bytes());
        blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data)
    };
    let sig =
        schnorr_sign(&secret, msg.as_bytes(), regtest_chain_id().as_bytes()).expect("coinbase sig");
    CoinbaseTransaction {
        output: TransactionOutput { commitment, proof },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value: reward,
            excess,
            excess_signature: sig.to_bytes(),
        },
        offset: [0u8; 32],
    }
}

fn coinbase_only_block_with(
    prev_hash: Hash256,
    height: u64,
    timestamp: u64,
    total_difficulty: u64,
    coinbase_seed: u8,
    nonce: u64,
) -> Block {
    let coinbase = signed_coinbase(BlockHeight(height), coinbase_seed);
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(BlockHeight(height), &coinbase, &[]).expect("pmmr roots");
    Block {
        header: BlockHeader {
            version: PROTOCOL_VERSION,
            height: BlockHeight(height),
            prev_hash,
            timestamp: Timestamp(timestamp),
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(0),
            total_difficulty: U256::from(total_difficulty),
            pow: ProofOfWork {
                nonce,
                randomx_hash: Hash256::ZERO,
            },
        },
        coinbase,
        transactions: vec![],
    }
}

fn coinbase_only_block(height: u64, timestamp: u64) -> Block {
    // Non-genesis blocks must carry a non-zero prev_hash (header syntax rule
    // enforced inside validate_block). The exact value is irrelevant to
    // validate_block because it does no parent lookup.
    coinbase_only_block_with(
        Hash256::from_bytes([0x42; 32]),
        height,
        timestamp,
        height + 1,
        0xC0,
        0,
    )
}

fn ctx_at(height: u64, now: u64) -> ValidationContext {
    ValidationContext {
        current_height: BlockHeight(height),
        chain_id: *regtest_chain_id().as_bytes(),
        now: Timestamp(now),
    }
}

fn block_hash(block: &Block) -> Hash256 {
    Hash256::from_bytes(
        *dom_crypto::hash::blake2b_256(&block.header.to_bytes().expect("header bytes")).as_bytes(),
    )
}

fn commit_canonical_block(store: &DomStore, block: &Block) -> Hash256 {
    let hash = block_hash(block);
    let header_bytes = block.header.to_bytes().expect("header bytes");
    let body_bytes = block.to_bytes().expect("block bytes");
    let coinbase_entry = UtxoEntry {
        block_height: block.header.height.0,
        is_coinbase: true,
        proof: block.coinbase.output.proof.clone(),
    };
    store
        .commit_block(
            hash.as_bytes(),
            block.header.height.0,
            &header_bytes,
            &body_bytes,
            &[(
                *block.coinbase.output.commitment.as_bytes(),
                coinbase_entry.to_bytes(),
            )],
            &[],
            &[(*block.coinbase.kernel.excess.as_bytes(), *hash.as_bytes())],
        )
        .expect("commit canonical block");
    hash
}

fn store_side_block(store: &DomStore, block: &Block) -> Hash256 {
    let hash = block_hash(block);
    store
        .store_known_block(
            hash.as_bytes(),
            &block.header.to_bytes().expect("header bytes"),
            &block.to_bytes().expect("block bytes"),
        )
        .expect("store side block");
    hash
}

fn open_chain_with_reorg_fixture(
    future_tip_timestamp: u64,
) -> (tempfile::TempDir, ChainState, Hash256) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = DomStore::open_with_map_size(dir.path(), TEST_LMDB_MAP_SIZE).expect("store");

    let genesis = coinbase_only_block_with(Hash256::ZERO, 0, REALISTIC_NOW - 300, 0, 0x10, 0);
    let genesis_hash = commit_canonical_block(&store, &genesis);

    let shared = coinbase_only_block_with(genesis_hash, 1, REALISTIC_NOW - 200, 1, 0x11, 1);
    let shared_hash = commit_canonical_block(&store, &shared);

    let old_tip = coinbase_only_block_with(shared_hash, 2, REALISTIC_NOW - 100, 2, 0x12, 2);
    let old_tip_hash = commit_canonical_block(&store, &old_tip);

    let side_2 = coinbase_only_block_with(shared_hash, 2, REALISTIC_NOW - 90, 3, 0x20, 20);
    let side_2_hash = store_side_block(&store, &side_2);

    let side_3 = coinbase_only_block_with(side_2_hash, 3, future_tip_timestamp, 4, 0x21, 21);
    let side_3_hash = store_side_block(&store, &side_3);

    let chain = ChainState::open(store, Hash256::ZERO, NETWORK_MAGIC_REGTEST).expect("chain open");
    assert_eq!(chain.tip_hash, old_tip_hash, "fixture canonical tip");
    (dir, chain, side_3_hash)
}

#[test]
fn validate_block_accepts_far_future_timestamp_under_realistic_now() {
    // A fully-valid coinbase-only block whose timestamp is ~100 years ahead of
    // `now`. The shared validator used by the reorg promotion path accepts it,
    // proving the future-timestamp gate is absent from `validate_block`. This is
    // the FIX-018 defect at its source: reorg promotion calls only this
    // validator (with now=u64::MAX), so a far-future heavier branch is
    // promotable while the same block is rejected on direct connect.
    let block = coinbase_only_block(1, FAR_FUTURE_TS);
    let result = validate_block(&block, &ctx_at(1, REALISTIC_NOW));
    assert!(
        result.is_ok(),
        "FIX-018: validate_block (the reorg-promotion validator) unexpectedly \
         rejected a far-future block — if this now fails, the future-time gate \
         was added to the shared validator and FIX-018 may be closed: re-verify \
         promote_heavier_known_tip. Got: {result:?}"
    );

    // Sanity: the same block is valid with now ALSO far in the future, matching
    // the u64::MAX the promotion path actually passes — i.e. `now` is irrelevant
    // to validate_block's verdict, which is the crux of the gap.
    let result_maxnow = validate_block(&block, &ctx_at(1, u64::MAX));
    assert!(
        result_maxnow.is_ok(),
        "validate_block verdict must be independent of now (it ignores future ts): {result_maxnow:?}"
    );
}

#[test]
fn fix018_reorg_rejects_far_future_branch_endtoend() {
    let (_dir, mut chain, side_tip_hash) = open_chain_with_reorg_fixture(FAR_FUTURE_TS);

    let err = chain
        .promote_heavier_known_tip(side_tip_hash, Timestamp(REALISTIC_NOW))
        .expect_err("reorg promotion must reject far-future timestamp");
    assert!(
        matches!(err, DomError::TemporarilyInvalid(_)),
        "expected future timestamp rejection, got: {err}"
    );
}

#[test]
fn fix018_reorg_promotes_valid_timestamp_branch_endtoend() {
    let valid_tip_timestamp = REALISTIC_NOW - 80;
    let (_dir, mut chain, side_tip_hash) = open_chain_with_reorg_fixture(valid_tip_timestamp);

    let reorg = chain
        .promote_heavier_known_tip(side_tip_hash, Timestamp(REALISTIC_NOW))
        .expect("timestamp-valid reorg should promote");
    assert_eq!(chain.tip_hash, side_tip_hash);
    assert_eq!(chain.tip_height, BlockHeight(3));
    assert_eq!(reorg.connected_blocks.len(), 2);
}
