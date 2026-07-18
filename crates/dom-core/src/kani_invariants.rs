//! Kani proofs for deterministic `dom-core` operations and validation predicates.
//!
//! Production `DomError` constructors retain their formatted diagnostics, while
//! the same validation conditions are exposed as allocation-free predicates for
//! complete symbolic coverage of those conditions.

use crate::{
    block_reward, is_placeholder_genesis_hash, is_valid_mainnet_genesis_hash,
    maximum_supply_from_schedule, Amount, BlockHeight, FeeRate, Hash256, Timestamp,
    TransactionShape, BLOCK_REWARD_TABLE, COINBASE_MATURITY, FEE_POLICY_VERSION,
    GENESIS_HASH_MAINNET, GENESIS_HASH_REGTEST, GENESIS_HASH_TESTNET, GENESIS_NONCE_MAINNET,
    GENESIS_POW_DIGEST_MAINNET, GENESIS_TIMESTAMP_MAINNET, HALVING_EPOCHS, HALVING_INTERVAL,
    INITIAL_BLOCK_REWARD, MAINNET_GENESIS_FINALIZED, MAX_BLOCK_SERIALIZED_SIZE,
    MAX_GETBLOCKDATA_HASHES, MAX_HEADERS_PER_MSG, MAX_INPUTS_PER_TX, MAX_KERNELS_PER_TX,
    MAX_LOCATOR_HASHES, MAX_OUTPUTS_PER_TX, MAX_SUPPLY_NOMS, MIN_RELAY_FEE_RATE,
    NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET, PROTOCOL_VERSION,
    RECOVERY_CAPSULE_SIZE, REGTEST_COINBASE_MATURITY,
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
fn amount_checked_arithmetic_matches_u64_and_supply_bounds() {
    let lhs_noms: u64 = kani::any();
    let rhs_noms: u64 = kani::any();
    kani::assume(Amount::is_valid_noms(lhs_noms));
    kani::assume(Amount::is_valid_noms(rhs_noms));

    let lhs = Amount::from_valid_noms_for_proof(lhs_noms);
    let rhs = Amount::from_valid_noms_for_proof(rhs_noms);
    let mathematical_sum = u128::from(lhs_noms) + u128::from(rhs_noms);
    let expected_sum = if mathematical_sum <= u128::from(MAX_SUPPLY_NOMS) {
        Some(mathematical_sum as u64)
    } else {
        None
    };

    kani::assert(
        lhs.checked_add_noms(rhs) == expected_sum,
        "amount addition must reject both integer overflow and supply-cap excess",
    );
    kani::assert(
        lhs.checked_sub_noms(rhs)
            == if lhs_noms >= rhs_noms {
                Some(lhs_noms - rhs_noms)
            } else {
                None
            },
        "amount subtraction must reject exactly the underflowing region",
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
fn reward_table_recurrence_is_frozen_for_every_epoch() {
    let epoch: u8 = kani::any();
    kani::assume(usize::from(epoch) < BLOCK_REWARD_TABLE.len());
    let index = usize::from(epoch);

    if index == 0 {
        kani::assert(
            BLOCK_REWARD_TABLE[index] == INITIAL_BLOCK_REWARD,
            "epoch zero must equal the initial reward",
        );
    } else {
        kani::assert(
            BLOCK_REWARD_TABLE[index] == (BLOCK_REWARD_TABLE[index - 1] * 67) / 100,
            "each reward epoch must be the frozen integer 67-percent recurrence",
        );
    }
}

#[kani::proof]
fn maximum_supply_is_the_exact_checked_schedule_sum() {
    kani::assert(
        maximum_supply_from_schedule() == MAX_SUPPLY_NOMS,
        "production supply constant must be derived from the schedule specification",
    );
    kani::assert(
        MAX_SUPPLY_NOMS == 3_299_996_676_900_000,
        "derived maximum issuance must equal the frozen value",
    );
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
    kani::assert(GENESIS_NONCE_MAINNET == 7_150, "mainnet nonce is frozen");
    kani::assert(
        GENESIS_POW_DIGEST_MAINNET
            == [
                0x00, 0x00, 0x03, 0xbd, 0xa0, 0xb1, 0x41, 0x65, 0x6e, 0x3a, 0x08, 0x6f, 0xbb, 0x2e,
                0x01, 0x83, 0x21, 0xed, 0x26, 0x11, 0xc9, 0xd5, 0xa7, 0x23, 0xbf, 0x9b, 0x85, 0xcc,
                0xe9, 0xba, 0xf3, 0xab,
            ],
        "mainnet PoW digest is frozen",
    );
    kani::assert(
        NETWORK_MAGIC_MAINNET != NETWORK_MAGIC_TESTNET
            && NETWORK_MAGIC_MAINNET != NETWORK_MAGIC_REGTEST
            && NETWORK_MAGIC_TESTNET != NETWORK_MAGIC_REGTEST,
        "network magic values must be pairwise distinct",
    );
    kani::assert(PROTOCOL_VERSION == 2, "wire protocol version is frozen");
    kani::assert(FEE_POLICY_VERSION == 1, "fee policy version is frozen");
    kani::assert(
        RECOVERY_CAPSULE_SIZE == 96,
        "Recovery Capsule v1 size is frozen",
    );
    kani::assert(
        MAX_BLOCK_SERIALIZED_SIZE == 16 * 1_024 * 1_024,
        "serialized block cap is frozen",
    );
    kani::assert(
        MAX_INPUTS_PER_TX == 255 && MAX_OUTPUTS_PER_TX == 255 && MAX_KERNELS_PER_TX == 16,
        "transaction count limits are frozen",
    );
    kani::assert(
        MAX_HEADERS_PER_MSG == 2_000 && MAX_GETBLOCKDATA_HASHES == 128 && MAX_LOCATOR_HASHES == 32,
        "wire collection limits are frozen",
    );
}
