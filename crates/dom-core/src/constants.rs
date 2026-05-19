#![allow(missing_docs)]
//! Consensus constants — single source of truth for all DOM consensus parameters.
//!
//! Every constant is typed, documented, and classified as either:
//!   - CONSENSUS: affects block/tx validity; changes require hard fork
//!   - POLICY:    local relay behavior; MUST NOT affect consensus validity
//!
//! Source of truth: DOM whitepaper (May 2026).

// ── Timing & Difficulty ──────────────────────────────────────────────────────

/// [CONSENSUS] Target block spacing in seconds (2 minutes).
pub const TARGET_SPACING: u64 = 120;

/// [CONSENSUS] ASERT half-life in seconds (2 days).
pub const ASERT_HALF_LIFE: u64 = 172_800;

/// [CONSENSUS] Fixed-point radix bits for ASERT exponent arithmetic.
pub const ASERT_RADIX_BITS: u32 = 16;

/// [CONSENSUS] ASERT fixed-point radix (2^16 = 65536).
pub const ASERT_RADIX: u64 = 1u64 << ASERT_RADIX_BITS;

// ── Genesis ──────────────────────────────────────────────────────────────────

/// [CONSENSUS] Genesis PoW target compact = 0x1e00ffff.
/// Calibrated for CPU solo RandomX, ~2 min per block.
/// ASERT adjusts automatically from block 1 onward.
pub const GENESIS_TARGET_COMPACT: u32 = 0x1e00_ffff;

/// [CONSENSUS] Initial difficulty (computed from GENESIS_TARGET_COMPACT).
pub const INITIAL_DIFFICULTY: u64 = 1;

/// [CONSENSUS] Genesis block timestamp placeholder.
/// REPLACE on launch day with: date +%s
pub const GENESIS_TIMESTAMP_PLACEHOLDER: u64 = 1778642633;

/// [CONSENSUS] Immutable message inscribed in the genesis coinbase.
pub const GENESIS_MESSAGE: &str = "Not a store of value. A means of exchange.";

// ── Monetary Policy ──────────────────────────────────────────────────────────

/// [CONSENSUS] Base unit. 1 DOM = 100_000_000 noms.
pub const COIN_UNIT: u64 = 100_000_000;

/// [CONSENSUS] Initial block subsidy: 33 DOM in noms.
pub const INITIAL_BLOCK_REWARD: u64 = 33 * COIN_UNIT; // 3_300_000_000 noms

/// [CONSENSUS] Blocks between each halving of the block reward.
/// 330_000 blocks ≈ 1.25 years at 2-minute block time.
pub const HALVING_INTERVAL: u64 = 330_000;

/// [CONSENSUS] Number of active halving epochs.
/// After epoch 54, reward becomes 0 (integer arithmetic floor).
pub const HALVING_EPOCHS: u32 = 55;

/// [CONSENSUS] Block reward schedule, in noms, per halving epoch.
///
/// Derived deterministically via integer arithmetic:
///   reward(0) = 33 * COIN_UNIT
///   reward(n) = (reward(n-1) * 67) / 100
///
/// Integer arithmetic ensures bit-exact reproducibility across all
/// architectures and compilers. Floating-point math is forbidden in
/// consensus paths.
pub const BLOCK_REWARD_TABLE: [u64; 55] = [
    3_300_000_000,
    2_211_000_000,
    1_481_370_000,
    992_517_900,
    664_986_993,
    445_541_285,
    298_512_660,
    200_003_482,
    134_002_332,
    89_781_562,
    60_153_646,
    40_302_942,
    27_002_971,
    18_091_990,
    12_121_633,
    8_121_494,
    5_441_400,
    3_645_738,
    2_442_644,
    1_636_571,
    1_096_502,
    734_656,
    492_219,
    329_786,
    220_956,
    148_040,
    99_186,
    66_454,
    44_524,
    29_831,
    19_986,
    13_390,
    8_971,
    6_010,
    4_026,
    2_697,
    1_806,
    1_210,
    810,
    542,
    363,
    243,
    162,
    108,
    72,
    48,
    32,
    21,
    14,
    9,
    6,
    4,
    2,
    1,
    0,
];

/// [CONSENSUS] Maximum possible supply in noms.
/// Computed deterministically: sum over all epochs of reward * HALVING_INTERVAL.
/// Slightly less than 33,000,000 DOM due to integer truncation in late epochs.
pub const MAX_SUPPLY_NOMS: u64 = {
    let mut total: u64 = 0;
    let mut epoch: usize = 0;
    while epoch < 55 {
        total += BLOCK_REWARD_TABLE[epoch] * HALVING_INTERVAL;
        epoch += 1;
    }
    total
};

/// [CONSENSUS] Coinbase outputs must mature before spending.
/// 1000 blocks ≈ 1.4 days at 2-minute block time.
pub const COINBASE_MATURITY: u64 = 1_000;

// ── Block & Transaction Limits ───────────────────────────────────────────────

/// [CONSENSUS] Maximum block weight units.
pub const MAX_BLOCK_WEIGHT: u32 = 40_000;

/// [CONSENSUS] Maximum transaction weight units.
pub const MAX_TX_WEIGHT: u32 = 4_000;

/// [CONSENSUS] Maximum inputs per transaction.
pub const MAX_INPUTS_PER_TX: usize = 255;

/// [CONSENSUS] Maximum outputs per transaction.
pub const MAX_OUTPUTS_PER_TX: usize = 255;

/// [CONSENSUS] Maximum kernels per transaction.
pub const MAX_KERNELS_PER_TX: usize = 16;

/// [CONSENSUS] Maximum transactions per block.
pub const MAX_BLOCK_TXS: usize = 5_000;

/// [CONSENSUS] Maximum Bulletproof size in bytes.
pub const MAX_PROOF_SIZE: usize = 6_144;

/// [CONSENSUS] Maximum serialized block size in bytes (16 MiB).
pub const MAX_BLOCK_SERIALIZED_SIZE: usize = 16 * 1_024 * 1_024;

/// [POLICY] Maximum headers per Headers message (IBD batch size).
pub const MAX_HEADERS_PER_MSG: usize = 2_000;

/// [POLICY] Maximum block hashes a GetBlockData request can list.
pub const MAX_GETBLOCKDATA_HASHES: usize = 128;

/// [POLICY] Maximum block locator hashes in GetHeaders.
pub const MAX_LOCATOR_HASHES: usize = 32;

// ── Network & Timing Validation ──────────────────────────────────────────────

/// [CONSENSUS] Maximum seconds a block timestamp may be ahead of the local
/// clock before being rejected as TemporarilyInvalid. Per whitepaper §9 step 3.
pub const MAX_FUTURE_BLOCK_TIME: u64 = 120;

/// [CONSENSUS] Median-time-past window size.
pub const MEDIAN_TIME_WINDOW: usize = 11;

// ── Protocol & Network Identity ──────────────────────────────────────────────

/// [NETWORK] Protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// [NETWORK] Mainnet magic bytes: ASCII "DOM1" = 0x44_4F_4D_31
pub const NETWORK_MAGIC_MAINNET: u32 = 0x444F_4D31;

/// [NETWORK] Testnet magic bytes: ASCII "DOMT" = 0x44_4F_4D_54
pub const NETWORK_MAGIC_TESTNET: u32 = 0x444F_4D54;

/// [NETWORK] Default P2P port.
pub const P2P_PORT_MAINNET: u16 = 33_369;

/// [NETWORK] Default P2P port for testnet.
pub const P2P_PORT_TESTNET: u16 = 33_370;

/// [NETWORK] Maximum user agent string length in bytes.
pub const MAX_USER_AGENT_BYTES: usize = 256;

// ── Policy Constants (MUST NOT affect consensus validity) ────────────────────

/// [POLICY] Minimum relay fee rate in noms per weight unit.
pub const MIN_RELAY_FEE_RATE: u64 = 1_000;

/// [POLICY] Maximum depth of chain reorganization to accept.
pub const MAX_REORG_DEPTH_POLICY: u64 = 1_000;

// ── ASERT Target Bounds ──────────────────────────────────────────────────────

/// [CONSENSUS] Minimum PoW target (hardest difficulty).
pub const MIN_TARGET_BYTES: [u8; 32] = {
    let mut b = [0u8; 32];
    b[26] = 0xff;
    b[27] = 0xff;
    b
};

/// [CONSENSUS] Maximum PoW target (easiest difficulty / genesis).
pub const MAX_TARGET_BYTES: [u8; 32] = {
    let mut b = [0xff_u8; 32];
    b[0] = 0x00;
    b[1] = 0x00;
    b
};

/// Easy target for testnet — any RandomX hash passes. NOT for mainnet.
pub const TESTNET_EASY_TARGET: [u8; 32] = [0xff_u8; 32];

// ── Kernel Features ───────────────────────────────────────────────────────────

/// [CONSENSUS] Standard transaction kernel.
pub const KERNEL_FEAT_PLAIN: u8 = 0x00;

/// [CONSENSUS] Coinbase kernel — block reward.
pub const KERNEL_FEAT_COINBASE: u8 = 0x01;

/// [CONSENSUS] Height-locked kernel — absolute timelock.
pub const KERNEL_FEAT_HEIGHT_LOCKED: u8 = 0x02;

// ── Weight Units ──────────────────────────────────────────────────────────────

/// [CONSENSUS] Weight of a single transaction input.
pub const WEIGHT_INPUT: u32 = 1;

/// [CONSENSUS] Weight of a single transaction output.
pub const WEIGHT_OUTPUT: u32 = 21;

/// [CONSENSUS] Weight of a standard transaction kernel.
pub const WEIGHT_KERNEL: u32 = 3;

/// [CONSENSUS] Weight of a coinbase kernel.
pub const WEIGHT_COINBASE_KERNEL: u32 = 2;

// ── Cryptographic Domain Tags ────────────────────────────────────────────────

pub const TAG_KERNEL_SIG: &str = "DOM:kernel-sig:v1";
pub const TAG_KERNEL_MSG: &str = "DOM:kernel-msg:v1";
pub const TAG_KERNEL_MSG_COINBASE: &str = "DOM:kernel-msg:coinbase:v1";
pub const TAG_H2C: &str = "DOM:h2c:secp256k1:v6.1";
pub const TAG_BULLETPROOF: &str = "DOM:bulletproof:v1";
pub const TAG_BP_G: &str = "DOM:bp-G:v1";
pub const TAG_BP_H: &str = "DOM:bp-H:v1";
pub const TAG_CHAIN_ID: &str = "DOM:chain-id:v1";
pub const TAG_MUSIG2_TRANSCRIPT: &str = "DOM:musig2-transcript:v1";
pub const TAG_MUSIG2_NONCE: &str = "DOM:musig2-nonce:v1";

/// Tag for deriving the canonical genesis coinbase blinding factor.
/// Used to make the genesis block fully deterministic across all nodes.
pub const TAG_GENESIS_BLINDING: &str = "DOM:genesis-blinding:v1";
pub const TAG_PMMR_EMPTY: &str = "DOM:pmmr-empty:v1";
pub const TAG_PMMR_BAG: &str = "DOM:pmmr-bag:v1";
pub const TAG_PMMR_LEAF: &str = "DOM:pmmr-leaf:v1";
pub const TAG_PMMR_NODE: &str = "DOM:pmmr-node:v1";

// ── Compile-time Sanity Checks ───────────────────────────────────────────────

const _: () = {
    assert!(TARGET_SPACING == 120, "TARGET_SPACING must be 120s");
    assert!(
        ASERT_HALF_LIFE == 172_800,
        "ASERT_HALF_LIFE must be 172800s"
    );
    assert!(
        HALVING_INTERVAL == 330_000,
        "HALVING_INTERVAL must be 330000"
    );
    assert!(COIN_UNIT == 100_000_000, "COIN_UNIT must be 1e8");
    assert!(
        INITIAL_BLOCK_REWARD == 3_300_000_000,
        "Reward must be 33 DOM"
    );
    assert!(
        MAX_FUTURE_BLOCK_TIME == 120,
        "MAX_FUTURE_BLOCK_TIME must be 120s"
    );
    assert!(
        NETWORK_MAGIC_MAINNET == 0x444F_4D31,
        "Mainnet magic must be ASCII DOM1"
    );
    assert!(
        BLOCK_REWARD_TABLE[0] == INITIAL_BLOCK_REWARD,
        "Table[0] must equal INITIAL_BLOCK_REWARD"
    );
    assert!(
        BLOCK_REWARD_TABLE[54] == 0,
        "Table[54] must be 0 (integer floor)"
    );
};

// ── Runtime verification tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reward_table_is_deterministic() {
        // Recompute the table from scratch with integer arithmetic and compare.
        let mut r: u64 = INITIAL_BLOCK_REWARD;
        for epoch in 0..55 {
            assert_eq!(
                BLOCK_REWARD_TABLE[epoch], r,
                "BLOCK_REWARD_TABLE[{epoch}] mismatch"
            );
            r = (r * 67) / 100;
        }
    }

    #[test]
    fn reward_eventually_reaches_zero() {
        assert_eq!(BLOCK_REWARD_TABLE[54], 0);
    }

    #[test]
    fn supply_approximately_33m() {
        let dom = MAX_SUPPLY_NOMS / COIN_UNIT;
        assert!(dom >= 32_000_000, "supply should be >= 32M DOM, got {dom}");
        assert!(dom < 33_000_000, "supply should be < 33M DOM, got {dom}");
    }

    #[test]
    fn supply_matches_expected_value() {
        // Pre-computed and verified externally: 3_299_999_976_900_000 noms
        assert_eq!(MAX_SUPPLY_NOMS, 3_299_999_976_900_000);
    }

    #[test]
    fn max_target_bytes_layout() {
        assert_eq!(MAX_TARGET_BYTES[0], 0x00);
        assert_eq!(MAX_TARGET_BYTES[1], 0x00);
        for i in 2..32 {
            assert_eq!(MAX_TARGET_BYTES[i], 0xff);
        }
    }

    #[test]
    fn min_target_bytes_layout() {
        for i in 0..26 {
            assert_eq!(MIN_TARGET_BYTES[i], 0x00);
        }
        assert_eq!(MIN_TARGET_BYTES[26], 0xff);
        assert_eq!(MIN_TARGET_BYTES[27], 0xff);
        for i in 28..32 {
            assert_eq!(MIN_TARGET_BYTES[i], 0x00);
        }
    }
}
