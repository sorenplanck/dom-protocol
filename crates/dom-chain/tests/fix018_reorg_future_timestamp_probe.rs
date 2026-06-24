//! dom-shield PROBE — FIX-018: reorg promotion skips the future-timestamp gate.
//!
//! `ChainState::promote_heavier_known_tip` validates each candidate block on the
//! promoted branch with `validate_block(block, &ctx)` where
//! `ctx.now = Timestamp(u64::MAX)` (chain_state.rs ~line 1085). The shared
//! `dom_consensus::validate_block` does NOT enforce the future-timestamp limit
//! at all — that limit (`validate_future_timestamp_with_limit`) is applied only
//! on the LIVE direct-connect path inside `ChainState::connect_block`
//! (chain_state.rs:272) and in `validate_header_only` /
//! `validate_ibd_headers_batch`. It is never re-applied during reorg promotion.
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
//! The full end-to-end variant (store the heavier far-future branch as a side
//! chain, then trigger promotion and observe the reorg succeed) is recorded as
//! an #[ignore] companion below — assembling and committing a heavier multi-block
//! branch duplicates the reorg fixtures in reorg_equivalence.rs /
//! block_validation_ingress_adversarial.rs; the root-cause probe already pins the
//! defect at its source. Fixing it is a consensus/validation change
//! (PRECISA DECISÃO HUMANA), out of test-construction scope.

use dom_consensus::transaction::{CoinbaseKernel, CoinbaseTransaction, TransactionOutput};
use dom_consensus::{
    compute_block_pmmr_roots, derive_chain_id, validate_block, Block, ValidationContext,
};
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_core::{
    BlockHeight, Hash256, Timestamp, GENESIS_HASH_REGTEST, KERNEL_FEAT_COINBASE,
    NETWORK_MAGIC_REGTEST, PROTOCOL_VERSION, TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::keys::SecretKey;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::schnorr_sign;
use dom_pow::CompactTarget;
use primitive_types::U256;

const FAR_FUTURE_TS: u64 = 1_700_000_000 + 100 * 365 * 24 * 3600; // ~100y ahead
const REALISTIC_NOW: u64 = 1_700_000_500; // a sane wall clock near genesis era

fn blinding(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic blinding")
}

fn regtest_chain_id() -> Hash256 {
    derive_chain_id(NETWORK_MAGIC_REGTEST, &Hash256::from_bytes(GENESIS_HASH_REGTEST))
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
    let sig = schnorr_sign(&secret, msg.as_bytes(), regtest_chain_id().as_bytes())
        .expect("coinbase sig");
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

fn coinbase_only_block(height: u64, timestamp: u64) -> Block {
    let coinbase = signed_coinbase(BlockHeight(height), 0xC0);
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, &[]).expect("pmmr roots");
    Block {
        header: BlockHeader {
            version: PROTOCOL_VERSION,
            height: BlockHeight(height),
            // Non-genesis blocks must carry a non-zero prev_hash (header syntax
            // rule enforced inside validate_block). The exact value is
            // irrelevant to validate_block (it does no parent lookup).
            prev_hash: Hash256::from_bytes([0x42; 32]),
            timestamp: Timestamp(timestamp),
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(0),
            total_difficulty: U256::from(height + 1),
            pow: ProofOfWork {
                nonce: 0,
                randomx_hash: Hash256::ZERO,
            },
        },
        coinbase,
        transactions: vec![],
    }
}

fn ctx_at(height: u64, now: u64) -> ValidationContext {
    ValidationContext {
        current_height: BlockHeight(height),
        chain_id: *regtest_chain_id().as_bytes(),
        now: Timestamp(now),
    }
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
#[ignore = "FIX-018 end-to-end: store a heavier far-future side branch and \
observe promote_heavier_known_tip accept it while direct-connect rejects it. \
Assembling/committing a heavier multi-block branch duplicates reorg_equivalence.rs \
fixtures; the root-cause probe above already pins the defect. Fix is a \
consensus/validation change (PRECISA DECISÃO HUMANA)."]
fn fix018_reorg_promotes_far_future_branch_endtoend() {
    // Placeholder pinned by the #[ignore] note; the runnable root-cause probe
    // validate_block_accepts_far_future_timestamp_under_realistic_now carries
    // the executable evidence.
}
