//! Kani proofs for deterministic `dom-core` operations and validation predicates.
//!
//! Production `DomError` constructors retain their formatted diagnostics, while
//! the same validation conditions are exposed as allocation-free predicates for
//! complete symbolic coverage of those conditions.

use crate::{
    block_reward, is_placeholder_genesis_hash, is_valid_mainnet_genesis_hash, Amount, BlockHeight,
    FeeRate, Hash256, Timestamp, TransactionShape, BLOCK_REWARD_TABLE, COINBASE_MATURITY,
    GENESIS_HASH_MAINNET, GENESIS_HASH_REGTEST, GENESIS_HASH_TESTNET, GENESIS_TIMESTAMP_MAINNET,
    HALVING_EPOCHS, HALVING_INTERVAL, INITIAL_BLOCK_REWARD, MAINNET_GENESIS_FINALIZED,
    MAX_SUPPLY_NOMS, MIN_RELAY_FEE_RATE, REGTEST_COINBASE_MATURITY,
};

#[kani::proof]
fn amount_supply_predicate_matches_the_consensus_ceiling_for_every_value() {
    let noms: u64 = kani::any();
    kani::assert(
        Amount::is_valid_noms(noms) == (noms <= MAX_SUPPLY_NOMS),
        "amount predicate must exactly encode the supply ceiling",
    );
}

#[kani::proof]
fn transaction_count_predicate_matches_all_policy_limits() {
    let inputs: usize = kani::any();
    let outputs: usize = kani::any();
    let kernels: usize = kani::any();
    kani::assert(
        TransactionShape::counts_within_limits(inputs, outputs, kernels)
            == (inputs <= crate::MAX_INPUTS_PER_TX
                && outputs <= crate::MAX_OUTPUTS_PER_TX
                && kernels <= crate::MAX_KERNELS_PER_TX),
        "count predicate must exactly encode every policy limit",
    );
}

#[kani::proof]
fn mainnet_genesis_predicate_matches_all_identity_rejections() {
    let hash: [u8; 32] = kani::any();
    kani::assert(
        is_valid_mainnet_genesis_hash(&hash)
            == (hash != GENESIS_HASH_TESTNET
                && hash != GENESIS_HASH_REGTEST
                && !is_placeholder_genesis_hash(&hash)),
        "mainnet predicate must reject aliases and placeholders",
    );
}

#[kani::proof]
fn block_height_and_timestamp_checked_arithmetic_never_wrap() {
    let height: u64 = kani::any();
    let timestamp: u64 = kani::any();
    let delta: u64 = kani::any();

    kani::assert(
        BlockHeight(height).checked_next().is_some() == (height != u64::MAX),
        "height successor must be checked",
    );
    kani::assert(
        Timestamp(timestamp).checked_add_secs(delta).is_some()
            == timestamp.checked_add(delta).is_some(),
        "timestamp addition must be checked",
    );
    kani::assert(
        Timestamp(timestamp).checked_sub(Timestamp(delta)).is_some() == (timestamp >= delta),
        "timestamp subtraction must be checked",
    );
}

#[kani::proof]
fn block_reward_matches_the_frozen_epoch_table_for_every_height() {
    let height: u64 = kani::any();
    let epoch = height / HALVING_INTERVAL;
    let reward = block_reward(BlockHeight(height)).noms();

    if epoch >= u64::from(HALVING_EPOCHS) {
        kani::assert(reward == 0, "post-schedule reward must be zero");
    } else {
        kani::assert(
            reward == BLOCK_REWARD_TABLE[epoch as usize],
            "reward must equal the frozen epoch entry",
        );
    }
}

#[kani::proof]
fn hash_bytes_roundtrip_without_transformation() {
    let bytes: [u8; 32] = kani::any();
    let hash = Hash256::from_bytes(bytes);
    kani::assert(
        *hash.as_bytes() == bytes,
        "hash construction must preserve bytes",
    );
}

#[kani::proof]
fn frozen_consensus_constants_and_genesis_identity_hold() {
    kani::assert(
        INITIAL_BLOCK_REWARD == 3_300_000_000,
        "initial reward is frozen",
    );
    kani::assert(
        MAX_SUPPLY_NOMS == 3_299_996_676_900_000,
        "maximum issuance is frozen",
    );
    kani::assert(
        GENESIS_TIMESTAMP_MAINNET == 1_784_071_429,
        "mainnet timestamp is frozen",
    );
    kani::assert(MAINNET_GENESIS_FINALIZED, "mainnet identity is finalized");
    kani::assert(
        GENESIS_HASH_MAINNET != GENESIS_HASH_TESTNET,
        "mainnet and testnet identities must differ",
    );
    kani::assert(
        GENESIS_HASH_MAINNET != GENESIS_HASH_REGTEST,
        "mainnet and regtest identities must differ",
    );
    kani::assert(
        GENESIS_HASH_TESTNET != GENESIS_HASH_REGTEST,
        "testnet and regtest identities must differ",
    );
    kani::assert(
        !is_placeholder_genesis_hash(&GENESIS_HASH_MAINNET),
        "mainnet hash must not be a placeholder",
    );
    kani::assert(
        COINBASE_MATURITY > REGTEST_COINBASE_MATURITY,
        "regtest maturity must remain lower",
    );
    kani::assert(
        FeeRate::minimum_relay().noms_per_weight_unit == MIN_RELAY_FEE_RATE,
        "minimum relay fee must equal the frozen constant",
    );
}
