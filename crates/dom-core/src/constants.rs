#![allow(missing_docs)]
//! Consensus constants — single source of truth for all DOM consensus parameters.
//!
//! Every constant is typed, documented, and classified as either:
//!   - CONSENSUS: affects block/tx validity; changes require hard fork
//!   - POLICY:    local relay behavior; MUST NOT affect consensus validity
//!
//! Source of truth: DOM whitepaper (May 2026).

use crate::{DomError, Hash256};

// ── Timing & Difficulty ──────────────────────────────────────────────────────

/// [CONSENSUS] Target block spacing in seconds (2 minutes).
pub const TARGET_SPACING: u64 = 120;

/// [CONSENSUS] Canonical target block interval in seconds.
///
/// Alias of `TARGET_SPACING` kept for explicit retargeting codepaths and logs.
pub const TARGET_BLOCK_TIME_SECS: u64 = TARGET_SPACING;

/// [CONSENSUS] Number of blocks in the deterministic difficulty adjustment window.
pub const DIFFICULTY_ADJUSTMENT_WINDOW: u64 = 60;

/// [CONSENSUS] Hardest allowed per-window adjustment factor.
///
/// Fast blocks can make the next target at most this many times harder
/// (numerically smaller) in one adjustment step.
pub const MAX_DIFFICULTY_ADJUSTMENT_FACTOR_UP: u64 = 4;

/// [CONSENSUS] Easiest allowed per-window adjustment factor.
///
/// Slow blocks can make the next target at most this many times easier
/// (numerically larger) in one adjustment step.
pub const MAX_DIFFICULTY_ADJUSTMENT_FACTOR_DOWN: u64 = 4;

/// [CONSENSUS] ASERT half-life in target-spacing blocks.
pub const ASERT_HALF_LIFE_BLOCKS: u64 = 288;

/// [CONSENSUS] ASERT half-life in seconds.
pub const ASERT_HALF_LIFE: u64 = TARGET_SPACING * ASERT_HALF_LIFE_BLOCKS;

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

/// [CONSENSUS] Frozen testnet genesis timestamp (Unix seconds).
///
/// This value is already live on the controlled testnet and must remain stable
/// for every testnet node forever.
pub const GENESIS_TIMESTAMP_TESTNET: u64 = 1_778_642_633;

/// [CONSENSUS] Pre-launch mainnet genesis timestamp placeholder (Unix seconds).
///
/// This is only the ceremony input placeholder. It is not sufficient to enable
/// mainnet by itself: `GENESIS_HASH_MAINNET` must be pinned from the canonical
/// derivation path and `MAINNET_GENESIS_FINALIZED` must be flipped in the same
/// review set. Until then, any mainnet startup path MUST fail closed.
pub const GENESIS_TIMESTAMP_MAINNET_PLACEHOLDER: u64 = GENESIS_TIMESTAMP_TESTNET;

/// [CONSENSUS] Backwards-compatible alias used by pre-existing genesis code.
///
/// Do not treat this alias as proof that mainnet is finalized; use
/// `genesis_timestamp_for_network_magic()` plus
/// `ensure_network_genesis_ready()` instead.
pub const GENESIS_TIMESTAMP_PLACEHOLDER: u64 = GENESIS_TIMESTAMP_MAINNET_PLACEHOLDER;

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

/// [CONSENSUS] Testnet future timestamp bound.
///
/// Tighter than mainnet to prevent fast timestamp-warped testnet mining once
/// ASERT enforcement is active.
pub const TESTNET_MAX_FUTURE_BLOCK_TIME: u64 = 30;

/// [POLICY] Soft buffer for blocks slightly beyond MAX_FUTURE_BLOCK_TIME.
/// Blocks with timestamp in (now+MAX_FUTURE_BLOCK_TIME, now+MAX_FUTURE_BLOCK_TIME+SOFT_BUFFER]
/// are deferred for re-evaluation rather than immediately rejected.
/// This reduces orphan rate from transient clock drift without changing
/// the consensus rule (MAX_FUTURE_BLOCK_TIME remains the hard limit).
pub const FUTURE_BLOCK_SOFT_BUFFER_SECS: u64 = 60;

/// [POLICY] Testnet soft future timestamp buffer.
pub const TESTNET_FUTURE_BLOCK_SOFT_BUFFER_SECS: u64 = 15;

/// [CONSENSUS] Median-time-past window size.
pub const MEDIAN_TIME_WINDOW: usize = 11;

// ── Protocol & Network Identity ──────────────────────────────────────────────

/// [NETWORK] Protocol version.
pub const PROTOCOL_VERSION: u32 = 2;

/// [NETWORK] Mainnet magic bytes: ASCII "DOM1" = 0x44_4F_4D_31
pub const NETWORK_MAGIC_MAINNET: u32 = 0x444F_4D31;

/// [NETWORK] Testnet magic bytes: ASCII "DOMT" = 0x44_4F_4D_54
pub const NETWORK_MAGIC_TESTNET: u32 = 0x444F_4D54;

/// [NETWORK — DEV-ONLY] Regtest magic bytes: ASCII "DOMR" = 0x44_4F_4D_52
///
/// SECURITY: The magic byte differs from `NETWORK_MAGIC_MAINNET` /
/// `_TESTNET`, so any Regtest peer attempting to handshake with a
/// real-network node fails at the frame header. This is the primary
/// isolation mechanism — DO NOT change it without re-auditing the
/// peer dispatch path.
pub const NETWORK_MAGIC_REGTEST: u32 = 0x444F_4D52;

/// [NETWORK] Default P2P port.
pub const P2P_PORT_MAINNET: u16 = 33_369;

/// [NETWORK] Default P2P port for testnet.
pub const P2P_PORT_TESTNET: u16 = 33_370;

/// [NETWORK — DEV-ONLY] Default P2P port for Regtest.
/// Distinct from mainnet/testnet so accidental local conflicts also fail loudly.
pub const P2P_PORT_REGTEST: u16 = 33_371;

/// [DEV-ONLY] Coinbase maturity on Regtest: one confirmation.
///
/// Used exclusively by `Network::Regtest` codepaths so fast integration tests
/// can exercise the full spend pipeline. `COINBASE_MATURITY` (1000) is still
/// the canonical constant for Mainnet/Testnet and is unchanged.
pub const REGTEST_COINBASE_MATURITY: u64 = 1;

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

/// [CONSENSUS] Alias used by deterministic retargeting codepaths.
pub const MIN_ALLOWED_TARGET: [u8; 32] = MIN_TARGET_BYTES;

/// [CONSENSUS] Maximum PoW target (easiest difficulty / genesis).
pub const MAX_TARGET_BYTES: [u8; 32] = {
    let mut b = [0xff_u8; 32];
    b[0] = 0x00;
    b[1] = 0x00;
    b
};

/// [CONSENSUS] Alias used by deterministic retargeting codepaths.
pub const MAX_ALLOWED_TARGET: [u8; 32] = MAX_TARGET_BYTES;

/// Trivial PoW target for future regtest mode — ANY RandomX hash passes.
///
/// CRITICAL: This constant produces zero proof-of-work effort. Any block
/// with this target is mineable instantly. It exists ONLY to be wired into
/// a future `Network::Regtest` variant (similar to Bitcoin Core's regtest)
/// for fast integration tests and CI pipelines.
///
/// SECURITY INVARIANTS:
/// - MUST NEVER be used in Mainnet codepaths
/// - MUST NEVER be used in Testnet codepaths (testnet is real PoW)
/// - MUST only be reachable behind an explicit `Network::Regtest` check
/// - Any codepath that uses this without checking Network enum is a
///   security-critical bug
///
/// Originally defined as `TESTNET_EASY_TARGET` but renamed on 2026-05-23
/// after audit classified the old name as a trap (DOM-SEC audit findings).
/// Old name suggested testnet usage; new name screams "do not use".
///
/// To activate: add Network::Regtest variant + gate this constant behind
/// a `match network { Regtest => REGTEST_TRIVIAL_TARGET, _ => ... }` in
/// the miner and PoW validator. Do NOT skip the match.
///
/// NOTE (2026-05-24): set to `MAX_TARGET_BYTES` so this target is accepted
/// by `validate_target_bounds`. RandomX produces hashes whose first 2 bytes
/// are zero with probability 2^-16, giving ~milliseconds-per-block on the
/// cache-only VM used in regtest. The "trivial" label refers to effort
/// relative to mainnet, not to bypassing consensus validation — any
/// consensus-frozen invariant (target <= MAX_TARGET) still holds.
pub const REGTEST_TRIVIAL_TARGET_DO_NOT_USE_IN_PRODUCTION: [u8; 32] = MAX_TARGET_BYTES;

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

/// [CONSENSUS-CRITICAL] Domain separator for deterministic coinbase blinding derivation.
///
/// The wallet derives a deterministic blinding factor from the miner's secret key
/// plus block height. This allows wallet recovery from secret_key alone (no need
/// to backup outputs.bin separately).
///
/// Formula:
/// ```text
/// blinding = Blake2b-256-tagged(TAG_COINBASE_BLINDING, secret_key || height_le8)
/// ```
///
/// Resolves DOM-SEC-004 / TC-002 (HIGH): coinbase blinding factor previously
/// discarded after signing, making mining rewards unspendable.
pub const TAG_COINBASE_BLINDING: &str = "DOM:coinbase-blinding:v1";

/// Canonical genesis block hash for Testnet.
///
/// Derived deterministically from the canonical genesis construction path:
/// `dom-node::miner::build_genesis_coinbase` ->
/// `dom-consensus::compute_block_pmmr_roots` ->
/// `BlockHeader` serialization ->
/// `dom_crypto::hash::blake2b_256(header_bytes)`.
///
/// Any change in the genesis inputs (tag, timestamp, target, PMMR
/// construction, coinbase structure, or header serialization) changes this
/// hash and is therefore consensus-breaking.
///
/// Last computed: 2026-06-02 after lowering testnet target to MAX_COMPACT_TARGET.
pub const GENESIS_HASH_TESTNET: [u8; 32] = [
    0x56, 0x2c, 0x7a, 0xc5, 0xe4, 0x9d, 0x04, 0x99, 0xd0, 0x83, 0xf9, 0x8f, 0x15, 0xf4, 0x48, 0x45,
    0xb1, 0x49, 0x7e, 0xff, 0x88, 0xfb, 0x34, 0xde, 0x48, 0x9a, 0x61, 0xf8, 0x40, 0xaf, 0x72, 0xb2,
];

/// Explicit mainnet-launch gate.
///
/// Keeping this `false` is the only correct state while the repository still
/// carries placeholder mainnet genesis data. Flipping it to `true` requires the
/// same change set to:
/// 1. pin `GENESIS_HASH_MAINNET` from the canonical derivation path above,
/// 2. keep `NETWORK_MAGIC_MAINNET` unchanged, and
/// 3. record the ceremony artefacts described in `docs/GENESIS_CEREMONY.md`.
pub const MAINNET_GENESIS_FINALIZED: bool = false;

/// Canonical genesis block hash for Mainnet — UNFINALIZED until mainnet launch.
pub const GENESIS_HASH_MAINNET: [u8; 32] = [0u8; 32];

/// [DEV-ONLY] Canonical genesis block hash for Regtest.
///
/// Deterministic placeholder — a Regtest node bootstraps its own genesis
/// locally on first start (same path mainnet/testnet take through
/// `create_genesis_block`). Because Regtest peers are isolated by magic
/// byte (`NETWORK_MAGIC_REGTEST`), this value never reaches a non-Regtest
/// validator and a zero-array placeholder is acceptable.
pub const GENESIS_HASH_REGTEST: [u8; 32] = [0u8; 32];

/// Returns `true` if a genesis hash is still the all-zero placeholder.
pub const fn is_placeholder_genesis_hash(hash: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if hash[i] != 0 {
            return false;
        }
        i = i.saturating_add(1);
    }
    true
}

/// Validate a would-be mainnet genesis hash before allowing mainnet startup.
///
/// This rejects the placeholder hash and the currently pinned non-mainnet
/// constants so a misconfigured build cannot silently boot a "mainnet" node
/// bound to testnet or regtest identity.
pub fn validate_mainnet_genesis_hash(hash: [u8; 32]) -> Result<(), DomError> {
    if hash == GENESIS_HASH_TESTNET {
        return Err(DomError::Invalid(
            "mainnet genesis is not finalized: GENESIS_HASH_MAINNET must not alias GENESIS_HASH_TESTNET".into(),
        ));
    }
    if hash == GENESIS_HASH_REGTEST {
        return Err(DomError::Invalid(
            "mainnet genesis is not finalized: GENESIS_HASH_MAINNET must not alias GENESIS_HASH_REGTEST".into(),
        ));
    }
    if is_placeholder_genesis_hash(&hash) {
        return Err(DomError::Invalid(
            "mainnet genesis is not finalized: GENESIS_HASH_MAINNET is still the zero placeholder"
                .into(),
        ));
    }
    Ok(())
}

/// Return the configured genesis timestamp for a network magic value.
pub fn genesis_timestamp_for_network_magic(network_magic: u32) -> Result<u64, DomError> {
    match network_magic {
        NETWORK_MAGIC_MAINNET => Ok(GENESIS_TIMESTAMP_MAINNET_PLACEHOLDER),
        NETWORK_MAGIC_TESTNET | NETWORK_MAGIC_REGTEST => Ok(GENESIS_TIMESTAMP_TESTNET),
        other => Err(DomError::Invalid(format!(
            "unknown network magic 0x{other:08x} for genesis timestamp"
        ))),
    }
}

/// Return the configured genesis hash for a network magic value.
///
/// This returns the literal configured constant, even if the network is not yet
/// allowed to start. Startup paths should call
/// `startup_genesis_hash_for_network_magic()` instead.
pub fn configured_genesis_hash_for_network_magic(network_magic: u32) -> Result<Hash256, DomError> {
    let hash = match network_magic {
        NETWORK_MAGIC_MAINNET => GENESIS_HASH_MAINNET,
        NETWORK_MAGIC_TESTNET => GENESIS_HASH_TESTNET,
        NETWORK_MAGIC_REGTEST => GENESIS_HASH_REGTEST,
        other => {
            return Err(DomError::Invalid(format!(
                "unknown network magic 0x{other:08x} for genesis hash"
            )))
        }
    };
    Ok(Hash256::from_bytes(hash))
}

/// Fail closed if the requested network is not safe to start from its current
/// hardcoded genesis constants.
pub fn ensure_network_genesis_ready(network_magic: u32) -> Result<(), DomError> {
    if network_magic == 0 {
        return Err(DomError::Invalid(
            "mainnet genesis is not finalized: NETWORK_MAGIC_MAINNET is still the placeholder value".into(),
        ));
    }
    if network_magic != NETWORK_MAGIC_MAINNET {
        return Ok(());
    }
    if !MAINNET_GENESIS_FINALIZED {
        return Err(DomError::Invalid(
            "mainnet genesis is not finalized: genesis ceremony not finalized; see docs/GENESIS_CEREMONY.md".into(),
        ));
    }
    validate_mainnet_genesis_hash(GENESIS_HASH_MAINNET)?;
    let mainnet_timestamp = genesis_timestamp_for_network_magic(network_magic)?;
    if mainnet_timestamp == GENESIS_TIMESTAMP_MAINNET_PLACEHOLDER {
        return Err(DomError::Invalid(
            "mainnet genesis is not finalized: GENESIS_TIMESTAMP_MAINNET is still the placeholder value".into(),
        ));
    }
    Ok(())
}

/// Return the startup-safe genesis hash for a network magic value.
///
/// Mainnet callers must pass the explicit readiness gate first; testnet and
/// regtest use their configured constants directly.
pub fn startup_genesis_hash_for_network_magic(network_magic: u32) -> Result<Hash256, DomError> {
    ensure_network_genesis_ready(network_magic)?;
    configured_genesis_hash_for_network_magic(network_magic)
}
pub const TAG_PMMR_EMPTY: &str = "DOM:pmmr-empty:v1";
pub const TAG_PMMR_BAG: &str = "DOM:pmmr-bag:v1";
pub const TAG_PMMR_LEAF: &str = "DOM:pmmr-leaf:v1";
pub const TAG_PMMR_NODE: &str = "DOM:pmmr-node:v1";

// ── Compile-time Sanity Checks ───────────────────────────────────────────────

const _: () = {
    assert!(TARGET_SPACING == 120, "TARGET_SPACING must be 120s");
    assert!(
        ASERT_HALF_LIFE_BLOCKS == 288,
        "ASERT_HALF_LIFE_BLOCKS must be 288"
    );
    assert!(ASERT_HALF_LIFE == 34_560, "ASERT_HALF_LIFE must be 34560s");
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
        NETWORK_MAGIC_TESTNET == 0x444F_4D54,
        "Testnet magic must be ASCII DOMT"
    );
    assert!(
        NETWORK_MAGIC_REGTEST == 0x444F_4D52,
        "Regtest magic must be ASCII DOMR"
    );
    assert!(
        NETWORK_MAGIC_REGTEST != NETWORK_MAGIC_MAINNET,
        "Regtest magic must differ from mainnet"
    );
    assert!(
        NETWORK_MAGIC_REGTEST != NETWORK_MAGIC_TESTNET,
        "Regtest magic must differ from testnet"
    );
    assert!(
        !is_placeholder_genesis_hash(&GENESIS_HASH_TESTNET),
        "Testnet genesis hash must be pinned"
    );
    assert!(
        !MAINNET_GENESIS_FINALIZED || !is_placeholder_genesis_hash(&GENESIS_HASH_MAINNET),
        "Finalized mainnet must not keep a placeholder genesis hash"
    );
    assert!(
        P2P_PORT_REGTEST != P2P_PORT_MAINNET && P2P_PORT_REGTEST != P2P_PORT_TESTNET,
        "Regtest port must not collide with mainnet/testnet"
    );
    assert!(
        REGTEST_COINBASE_MATURITY < COINBASE_MATURITY,
        "REGTEST_COINBASE_MATURITY must be strictly less than the mainnet value"
    );
    assert!(
        COINBASE_MATURITY == 1_000,
        "Mainnet COINBASE_MATURITY must remain 1000 — Regtest uses a separate constant"
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

#[cfg(test)]
mod genesis_tests {
    use super::*;

    #[test]
    fn testnet_genesis_hash_is_pinned() {
        assert!(!is_placeholder_genesis_hash(&GENESIS_HASH_TESTNET));
    }

    #[test]
    fn genesis_timestamps_are_fixed() {
        assert_eq!(GENESIS_TIMESTAMP_TESTNET, 1_778_642_633);
        assert_eq!(
            GENESIS_TIMESTAMP_MAINNET_PLACEHOLDER, 1_778_642_633,
            "mainnet must not drift silently before the ceremony pins the final timestamp"
        );
    }

    #[test]
    fn network_magic_ids_are_fixed() {
        assert_eq!(NETWORK_MAGIC_MAINNET, 0x444F_4D31);
        assert_eq!(NETWORK_MAGIC_TESTNET, 0x444F_4D54);
        assert_eq!(NETWORK_MAGIC_REGTEST, 0x444F_4D52);
    }

    #[test]
    fn mainnet_guard_rejects_placeholder_hash() {
        let err = validate_mainnet_genesis_hash(GENESIS_HASH_MAINNET).unwrap_err();
        assert!(matches!(err, DomError::Invalid(_)));
        assert!(err.to_string().contains("mainnet genesis is not finalized"));
    }

    #[test]
    fn mainnet_guard_rejects_testnet_and_regtest_hashes() {
        let testnet_err = validate_mainnet_genesis_hash(GENESIS_HASH_TESTNET).unwrap_err();
        assert!(testnet_err.to_string().contains("TESTNET"));

        let regtest_err = validate_mainnet_genesis_hash(GENESIS_HASH_REGTEST).unwrap_err();
        assert!(regtest_err.to_string().contains("REGTEST"));
    }

    #[test]
    fn startup_guard_rejects_placeholder_network_magic() {
        let err = ensure_network_genesis_ready(0).unwrap_err();
        assert!(err
            .to_string()
            .contains("NETWORK_MAGIC_MAINNET is still the placeholder value"));
    }

    #[test]
    fn startup_hash_lookup_rejects_disabled_mainnet() {
        let err = startup_genesis_hash_for_network_magic(NETWORK_MAGIC_MAINNET).unwrap_err();
        assert!(err.to_string().contains("mainnet genesis is not finalized"));
    }

    #[test]
    fn startup_hash_lookup_preserves_testnet_and_regtest() {
        assert_eq!(
            startup_genesis_hash_for_network_magic(NETWORK_MAGIC_TESTNET)
                .unwrap()
                .as_bytes(),
            &GENESIS_HASH_TESTNET
        );
        assert_eq!(
            startup_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST)
                .unwrap()
                .as_bytes(),
            &GENESIS_HASH_REGTEST
        );
    }
}

// ── Time Discipline Thresholds ───────────────────────────────────────────────

/// [POLICY] Clock drift threshold for warnings.
/// Nodes with drift above this should be alerted but continue operating.
pub const CLOCK_DRIFT_WARN_SECS: i64 = 30;

/// [POLICY] Clock drift threshold for critical alerts.
/// Mining should be disabled if drift exceeds this value.
pub const CLOCK_DRIFT_ERROR_SECS: i64 = 60;

/// [POLICY] Peer drift threshold for scoring penalty.
/// Peers with timestamp drift above this trigger moderate scoring.
pub const PEER_DRIFT_WARN_SECS: i64 = 30;

/// [POLICY] Peer drift threshold for immediate disconnection.
/// Peers with timestamp drift above this are disconnected.
pub const PEER_DRIFT_DISCONNECT_SECS: i64 = 90;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reward_table_is_deterministic() {
        // Recompute the table from scratch with integer arithmetic and compare.
        let mut r: u64 = INITIAL_BLOCK_REWARD;
        for (epoch, _) in BLOCK_REWARD_TABLE.iter().enumerate().take(55) {
            assert_eq!(
                BLOCK_REWARD_TABLE[epoch], r,
                "BLOCK_REWARD_TABLE[{epoch}] mismatch"
            );
            r = {
                #[allow(clippy::integer_division)]
                let next = (r * 67) / 100;
                next
            };
        }
    }

    #[test]
    fn reward_eventually_reaches_zero() {
        assert_eq!(BLOCK_REWARD_TABLE[54], 0);
    }

    #[test]
    fn supply_approximately_33m() {
        #[allow(clippy::integer_division)]
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
        for item in MAX_TARGET_BYTES.iter().skip(2) {
            assert_eq!(*item, 0xff);
        }
    }

    #[test]
    fn min_target_bytes_layout() {
        for item in MIN_TARGET_BYTES.iter().take(26) {
            assert_eq!(*item, 0x00);
        }
        assert_eq!(MIN_TARGET_BYTES[26], 0xff);
        assert_eq!(MIN_TARGET_BYTES[27], 0xff);
        for item in MIN_TARGET_BYTES.iter().skip(28) {
            assert_eq!(*item, 0x00);
        }
    }

    #[test]
    fn regtest_trivial_target_is_accepted_by_consensus() {
        // REGTEST_TRIVIAL_TARGET must be <= MAX_TARGET_BYTES, otherwise any
        // regtest block carrying it is rejected by validate_target_bounds.
        // Cheapest invariant: identical to MAX_TARGET_BYTES (equality is the
        // weakest target consensus accepts).
        assert_eq!(
            REGTEST_TRIVIAL_TARGET_DO_NOT_USE_IN_PRODUCTION, MAX_TARGET_BYTES,
            "REGTEST_TRIVIAL_TARGET must equal MAX_TARGET_BYTES — consensus accepts it"
        );
    }
}
