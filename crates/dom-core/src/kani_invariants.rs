//! Kani proofs for deterministic `dom-core` operations that do not allocate.
//!
//! `DomError` paths allocate formatted diagnostics and are outside the supported
//! Kani 0.67 model on this toolchain. Their acceptance and rejection behavior
//! remains covered by deterministic unit, property, Miri, and integration tests.

use crate::{
    block_reward, is_placeholder_genesis_hash, BlockHeight, FeeRate, Hash256, Timestamp,
    BLOCK_REWARD_TABLE, COINBASE_MATURITY, GENESIS_HASH_MAINNET, GENESIS_HASH_REGTEST,
    GENESIS_HASH_TESTNET, GENESIS_TIMESTAMP_MAINNET, HALVING_EPOCHS, HALVING_INTERVAL,
    INITIAL_BLOCK_REWARD, MAINNET_GENESIS_FINALIZED, MAX_SUPPLY_NOMS, MIN_RELAY_FEE_RATE,
    REGTEST_COINBASE_MATURITY,
};

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
