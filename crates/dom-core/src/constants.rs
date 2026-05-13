//! Consensus constants — DOM_RFC_0000_Consensus_Constants.md
//!
//! This file is the SINGLE SOURCE OF TRUTH for all DOM consensus parameters.
//! Every constant is typed, documented, and classified as either:
//!   - CONSENSUS: affects block/tx validity; changes require hard fork
//!   - POLICY:    local relay behavior; MUST NOT affect consensus validity

// ── Timing & Difficulty ──────────────────────────────────────────────────────

/// [CONSENSUS] Target block spacing in seconds (2 minutes).
pub const TARGET_SPACING: u64 = 120;

/// [CONSENSUS] ASERT half-life in seconds (2 days).
/// Controls how fast difficulty adjusts after hash rate changes.
pub const ASERT_HALF_LIFE: u64 = 172_800;

/// [CONSENSUS] Fixed-point radix bits for ASERT exponent arithmetic.
/// All ASERT calculations use 16-bit fractional precision.
pub const ASERT_RADIX_BITS: u32 = 16;

/// [CONSENSUS] ASERT fixed-point radix (2^16 = 65536).
pub const ASERT_RADIX: u64 = 1u64 << ASERT_RADIX_BITS;

// ── Genesis Placeholders (Release Blockers) ──────────────────────────────────

/// [CONSENSUS — RELEASE BLOCKER] Genesis block target in compact form.
/// MUST be replaced with the deterministically generated value before
/// public testnet launch. See DOM_RFC_0006_Genesis_Finalization.md
/// [CONSENSUS] Genesis PoW target compact.
/// 0x1e00ffff: calibrado para CPU solo RandomX, ~2 min por bloco.
/// ASERT ajusta automaticamente conforme mais mineradores entram.
/// Genesis PoW target compact = 0x1e00ffff.
/// Expande para 0x0000ffff...ffff = MAX_TARGET.
pub const GENESIS_TARGET_COMPACT: u32 = 0x1e00_ffff;

/// [CONSENSUS — RELEASE BLOCKER] Initial difficulty.
/// Placeholder only. Will be computed from GENESIS_TARGET_COMPACT.
pub const INITIAL_DIFFICULTY: u64 = 1;

/// [CONSENSUS] Genesis block timestamp placeholder.
/// 2024-01-01T00:00:00Z in Unix time.
/// MUST be frozen before testnet launch.
/// [CONSENSUS] Genesis block timestamp (Unix seconds).
/// SUBSTITUIR no dia do lancamento com o comando: date +%s
/// Placeholder atual: 2026-01-01 00:00:00 UTC
pub const GENESIS_TIMESTAMP_PLACEHOLDER: u64 = 1778642633;

/// [CONSENSUS] Mensagem gravada permanentemente no bloco genesis.
/// Imutavel apos o lancamento. Define a filosofia da DOM.
pub const GENESIS_MESSAGE: &str =
    "Not a store of value. A means of exchange.";

// ── Monetary Policy ──────────────────────────────────────────────────────────

/// [CONSENSUS] Base unit. 1 DOM = 100_000_000 noms.
pub const COIN_UNIT: u64 = 100_000_000;

/// [CONSENSUS] Initial block subsidy: 24 DOM in noms.
pub const INITIAL_BLOCK_REWARD: u64 = 24 * COIN_UNIT; // 2_400_000_000 noms

/// [CONSENSUS] Blocks between each halving of the block reward.
/// 44_715 * 15 = 670_725 (same real-time duration as original, with 2-min blocks).
pub const HALVING_INTERVAL: u64 = 670_725;

/// [CONSENSUS] Maximum possible supply in noms.
/// Computed deterministically from the halving schedule:
/// sum over all epochs of: reward(epoch) * HALVING_INTERVAL
/// where reward(epoch) = INITIAL_BLOCK_REWARD >> epoch
///
/// This is the true ceiling — actual supply is slightly less due to
/// integer truncation in final halvings when reward < 1 nom.
pub const MAX_SUPPLY_NOMS: u64 = {
    let mut total: u64 = 0u64;
    let mut epoch: u32 = 0;
    while epoch < 64 {
        let reward = INITIAL_BLOCK_REWARD >> epoch;
        if reward == 0 { break; }
        // addition is safe: cumulative sum < 2*INITIAL_BLOCK_REWARD*HALVING_INTERVAL < 2^63
        total = total + reward * HALVING_INTERVAL;
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
/// Tamanho máximo de um range proof Bulletproof (64 bits via secp256k1-zkp).
/// Medido empiricamente: ~5126 bytes para 64 bits. 6144 dá margem segura.
pub const MAX_PROOF_SIZE: usize = 6_144;

/// [CONSENSUS] Maximum serialized block size in bytes (16 MiB).
pub const MAX_BLOCK_SERIALIZED_SIZE: usize = 16 * 1_024 * 1_024;

// ── Network & Timing Validation ──────────────────────────────────────────────

/// [CONSENSUS] Maximum seconds a block timestamp may be ahead of
/// the local clock before being rejected as TemporarilyInvalid.
pub const MAX_FUTURE_BLOCK_TIME: u64 = 7_200;

/// [CONSENSUS] Median-time-past window size.
pub const MEDIAN_TIME_WINDOW: usize = 11;

// ── Protocol & Network Identity ──────────────────────────────────────────────

/// [NETWORK] Protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// [NETWORK] Mainnet magic bytes: ASCII "DOM1" = 0x44_4F_4D_31
pub const NETWORK_MAGIC_MAINNET: u32 = 0x444F_4D31;

/// [NETWORK] Testnet magic bytes: ASCII "DOMT" = 0x44_4F_4D_54
pub const NETWORK_MAGIC_TESTNET: u32 = 0x444F_4D54;

/// [NETWORK] Default P2P port. Encodes 33M supply (33) and block reward (369).
pub const P2P_PORT_MAINNET: u16 = 33_369;

/// [NETWORK] Default P2P port for testnet.
pub const P2P_PORT_TESTNET: u16 = 33_370;

/// [NETWORK] Maximum user agent string length in bytes.
pub const MAX_USER_AGENT_BYTES: usize = 256;

// ── Policy Constants (MUST NOT affect consensus validity) ────────────────────

/// [POLICY] Minimum relay fee rate in noms per weight unit.
pub const MIN_RELAY_FEE_RATE: u64 = 1_000;

/// [POLICY] Maximum depth of chain reorganization to accept.
/// Deeper reorgs are rejected at the policy layer only.
pub const MAX_REORG_DEPTH_POLICY: u64 = 1_000;

// ── ASERT Target Bounds ──────────────────────────────────────────────────────

/// [CONSENSUS] Minimum PoW target (hardest difficulty).
/// 0x0000000000000000000000000000000000000000000000000000ffff00000000
pub const MIN_TARGET_BYTES: [u8; 32] = {
    // 0x0000000000000000000000000000000000000000000000000000ffff00000000
    // Big-endian: 0xffff at bytes 26-27 from start
    let mut b = [0u8; 32];
    b[26] = 0xff;
    b[27] = 0xff;
    b
};

/// [CONSENSUS] Maximum PoW target (easiest difficulty / genesis).
/// 0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
pub const MAX_TARGET_BYTES: [u8; 32] = {
    // 0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    // Big-endian: two zero bytes at the START (most significant)
    let mut b = [0xff_u8; 32];
    b[0] = 0x00;  // most significant byte
    b[1] = 0x00;  // second most significant byte
    b
};

/// Target fácil para testnet — qualquer hash RandomX passa.
/// NÃO usar em mainnet.
pub const TESTNET_EASY_TARGET: [u8; 32] = [0xff_u8; 32];

// ── Kernel Features (RFC-0008) ────────────────────────────────────────────────

/// [CONSENSUS] Standard transaction kernel (RFC-0008 Section 5).
pub const KERNEL_FEAT_PLAIN: u8 = 0x00;

/// [CONSENSUS] Coinbase kernel — block reward (RFC-0008 Section 3.1).
pub const KERNEL_FEAT_COINBASE: u8 = 0x01;

/// [CONSENSUS] Height-locked kernel — absolute timelock (RFC-0008 Section 5).
pub const KERNEL_FEAT_HEIGHT_LOCKED: u8 = 0x02;

// ── Weight Units (RFC-0010) ───────────────────────────────────────────────────

/// [CONSENSUS] Weight of a single transaction input (RFC-0010 Section 1.1).
pub const WEIGHT_INPUT: u32 = 1;

/// [CONSENSUS] Weight of a single transaction output (RFC-0010 Section 1.1).
pub const WEIGHT_OUTPUT: u32 = 21;

/// [CONSENSUS] Weight of a standard transaction kernel (RFC-0010 Section 1.1).
pub const WEIGHT_KERNEL: u32 = 3;

/// [CONSENSUS] Weight of a coinbase kernel (RFC-0010 Section 1.1).
pub const WEIGHT_COINBASE_KERNEL: u32 = 2;

// ── Cryptographic Domain Tags ────────────────────────────────────────────────

/// [CONSENSUS] Domain separation tag for kernel Schnorr signatures.
/// RFC-0009: challenge uses R_compressed (33 bytes SEC1), not R_x.
pub const TAG_KERNEL_SIG: &str = "DOM:kernel-sig:v1";

/// [CONSENSUS] Domain separation tag for kernel message hash (RFC-0009 Section 2.2).
pub const TAG_KERNEL_MSG: &str = "DOM:kernel-msg:v1";

/// [CONSENSUS] Domain separation tag for coinbase kernel message (RFC-0009 Section 2.2).
pub const TAG_KERNEL_MSG_COINBASE: &str = "DOM:kernel-msg:coinbase:v1";

/// [CONSENSUS] Domain separation tag for hash-to-curve H generator.
/// RFC-0009: uses SHA-256 (not Blake2b) in expand_message_xmd.
pub const TAG_H2C: &str = "DOM:h2c:secp256k1:v6.1";

/// [CONSENSUS] Domain separation tag for Bulletproof transcript (RFC-0009 Section 5.2).
pub const TAG_BULLETPROOF: &str = "DOM:bulletproof:v1";

/// [CONSENSUS] Domain separation tag for Bulletproof G generators.
pub const TAG_BP_G: &str = "DOM:bp-G:v1";

/// [CONSENSUS] Domain separation tag for Bulletproof H generators.
pub const TAG_BP_H: &str = "DOM:bp-H:v1";

/// [CONSENSUS] Domain separation tag for chain_id derivation (RFC-0009 Section 4.1).
pub const TAG_CHAIN_ID: &str = "DOM:chain-id:v1";

/// [CONSENSUS] Domain separation tag for MuSig2 transcript (RFC-0009 Section 3.4).
pub const TAG_MUSIG2_TRANSCRIPT: &str = "DOM:musig2-transcript:v1";

/// [CONSENSUS] Domain separation tag for MuSig2 nonce derivation (RFC-0009 Section 3.2).
pub const TAG_MUSIG2_NONCE: &str = "DOM:musig2-nonce:v1";

/// [CONSENSUS] Domain separation tag for PMMR empty root.
pub const TAG_PMMR_EMPTY: &str = "DOM:pmmr-empty:v1";

/// [CONSENSUS] Domain separation tag for PMMR bag operation.
pub const TAG_PMMR_BAG: &str = "DOM:pmmr-bag:v1";

/// [CONSENSUS] Domain separation tag for PMMR leaf hashing.
pub const TAG_PMMR_LEAF: &str = "DOM:pmmr-leaf:v1";

/// [CONSENSUS] Domain separation tag for PMMR node hashing.
pub const TAG_PMMR_NODE: &str = "DOM:pmmr-node:v1";

// ── Compile-time Sanity Checks ───────────────────────────────────────────────

const _: () = {
    assert!(TARGET_SPACING == 120,      "TARGET_SPACING must be 120s");
    assert!(ASERT_HALF_LIFE == 172_800, "ASERT_HALF_LIFE must be 172800s");
    assert!(HALVING_INTERVAL == 670_725, "HALVING_INTERVAL must be 670725");
    assert!(COIN_UNIT == 100_000_000,   "COIN_UNIT must be 1e8");
    assert!(INITIAL_BLOCK_REWARD == 2_400_000_000, "Reward must be 24 DOM");
    assert!(
        NETWORK_MAGIC_MAINNET == 0x444F_4D31,
        "Mainnet magic must be ASCII DOM1"
    );
};

// ── Compile-time and runtime verification tests ───────────────────────────────

#[cfg(test)]
mod target_tests {
    use super::*;

    #[test]
    fn max_target_bytes_layout() {
        // Big-endian: 0x0000ffffff...ffff
        assert_eq!(MAX_TARGET_BYTES[0], 0x00, "byte[0] must be 0x00");
        assert_eq!(MAX_TARGET_BYTES[1], 0x00, "byte[1] must be 0x00");
        for i in 2..32 {
            assert_eq!(MAX_TARGET_BYTES[i], 0xff, "byte[{i}] must be 0xff");
        }
        // Top 128 bits match MAX_TARGET_HI in dom-pow
        let hi = u128::from_be_bytes(MAX_TARGET_BYTES[0..16].try_into().unwrap());
        assert_eq!(hi, 0x0000_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
            "MAX_TARGET top 128 bits must match dom-pow::MAX_TARGET_HI");
    }

    #[test]
    fn min_target_bytes_layout() {
        // Most bytes are zero, 0xffff at bytes 26-27
        for i in 0..26 { assert_eq!(MIN_TARGET_BYTES[i], 0x00); }
        assert_eq!(MIN_TARGET_BYTES[26], 0xff);
        assert_eq!(MIN_TARGET_BYTES[27], 0xff);
        for i in 28..32 { assert_eq!(MIN_TARGET_BYTES[i], 0x00); }
    }

    #[test]
    fn max_target_gt_min_target() {
        // MAX_TARGET > MIN_TARGET (big-endian comparison)
        for i in 0..32 {
            if MAX_TARGET_BYTES[i] > MIN_TARGET_BYTES[i] { return; } // MAX > MIN ✓
            if MAX_TARGET_BYTES[i] < MIN_TARGET_BYTES[i] {
                panic!("MAX_TARGET must be greater than MIN_TARGET");
            }
        }
        panic!("MAX_TARGET and MIN_TARGET are equal");
    }

    #[test]
    fn max_supply_noms_deterministic() {
        // Recompute and verify matches constant
        let mut total: u64 = 0;
        for epoch in 0u32..64 {
            let reward = INITIAL_BLOCK_REWARD >> epoch;
            if reward == 0 { break; }
            total += reward * HALVING_INTERVAL;
        }
        assert_eq!(MAX_SUPPLY_NOMS, total,
            "MAX_SUPPLY_NOMS must equal computed halving sum");
    }

    #[test]
    fn max_supply_approximately_33m() {
        let dom = MAX_SUPPLY_NOMS / COIN_UNIT;
        assert!(dom >= 30_000_000, "supply should be >= 30M DOM, got {dom}");
        assert!(dom <= 35_000_000, "supply should be <= 35M DOM, got {dom}");
    }
}
