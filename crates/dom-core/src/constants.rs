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

/// Consensus. Target block spacing in seconds (2 minutes).
pub const TARGET_SPACING: u64 = 120;

/// Consensus. Canonical target block interval in seconds.
///
/// Alias of `TARGET_SPACING` kept for explicit retargeting codepaths and logs.
pub const TARGET_BLOCK_TIME_SECS: u64 = TARGET_SPACING;

/// Consensus. Number of blocks in the deterministic difficulty adjustment window.
pub const DIFFICULTY_ADJUSTMENT_WINDOW: u64 = 60;

/// Consensus. Hardest allowed per-window adjustment factor.
///
/// Fast blocks can make the next target at most this many times harder
/// (numerically smaller) in one adjustment step.
pub const MAX_DIFFICULTY_ADJUSTMENT_FACTOR_UP: u64 = 4;

/// Consensus. Easiest allowed per-window adjustment factor.
///
/// Slow blocks can make the next target at most this many times easier
/// (numerically larger) in one adjustment step.
pub const MAX_DIFFICULTY_ADJUSTMENT_FACTOR_DOWN: u64 = 4;

/// Consensus. ASERT half-life in target-spacing blocks.
pub const ASERT_HALF_LIFE_BLOCKS: u64 = 288;

/// Consensus. ASERT half-life in seconds.
pub const ASERT_HALF_LIFE: u64 = TARGET_SPACING * ASERT_HALF_LIFE_BLOCKS;

/// Consensus. Fixed-point radix bits for ASERT exponent arithmetic.
pub const ASERT_RADIX_BITS: u32 = 16;

/// Consensus. ASERT fixed-point radix (2^16 = 65536).
pub const ASERT_RADIX: u64 = 1u64 << ASERT_RADIX_BITS;

// ── Genesis ──────────────────────────────────────────────────────────────────

/// Consensus. Genesis PoW target compact = 0x1e00ffff.
/// Calibrated for CPU solo RandomX, ~2 min per block.
/// ASERT adjusts automatically from block 1 onward.
pub const GENESIS_TARGET_COMPACT: u32 = 0x1e00_ffff;

/// Consensus. Frozen testnet genesis timestamp (Unix seconds).
///
/// This value is already live on the controlled testnet and must remain stable
/// for every testnet node forever.
pub const GENESIS_TIMESTAMP_TESTNET: u64 = 1_778_642_633;

/// Consensus. Historical pre-ceremony Mainnet timestamp sentinel.
///
/// Retained only so the readiness guard can reject an accidental rollback to
/// the old Testnet-aliasing placeholder. It is not used for construction.
pub const GENESIS_TIMESTAMP_MAINNET_PLACEHOLDER: u64 = GENESIS_TIMESTAMP_TESTNET;

/// Consensus. Final offline-ceremony Mainnet genesis timestamp (Unix seconds).
pub const GENESIS_TIMESTAMP_MAINNET: u64 = 1_784_071_429;

/// Consensus. Final offline-ceremony Regtest genesis timestamp (Unix seconds).
pub const GENESIS_TIMESTAMP_REGTEST: u64 = GENESIS_TIMESTAMP_MAINNET;

/// Consensus. Lowest valid Mainnet genesis nonce from the offline ceremony.
pub const GENESIS_NONCE_MAINNET: u64 = 7_150;

/// Consensus. Lowest valid Regtest genesis nonce from the offline ceremony.
pub const GENESIS_NONCE_REGTEST: u64 = 0;

/// Consensus. RandomX digest for the finalized Mainnet genesis header.
pub const GENESIS_POW_DIGEST_MAINNET: [u8; 32] = [
    0x00, 0x00, 0x03, 0xbd, 0xa0, 0xb1, 0x41, 0x65, 0x6e, 0x3a, 0x08, 0x6f, 0xbb, 0x2e, 0x01, 0x83,
    0x21, 0xed, 0x26, 0x11, 0xc9, 0xd5, 0xa7, 0x23, 0xbf, 0x9b, 0x85, 0xcc, 0xe9, 0xba, 0xf3, 0xab,
];

/// Consensus. Fast-development PoW digest for finalized Regtest genesis.
pub const GENESIS_POW_DIGEST_REGTEST: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x96, 0x5d, 0xe1, 0xca, 0x3c, 0xdb, 0x82, 0x26, 0xdd, 0x38, 0x7e, 0xa2, 0xa8, 0x75, 0xb6, 0x4d,
];

/// Consensus. Historical placeholder alias retained for rollback detection.
pub const GENESIS_TIMESTAMP_PLACEHOLDER: u64 = GENESIS_TIMESTAMP_MAINNET_PLACEHOLDER;

/// Consensus. Exact UTF-8 bytes carried by the Mainnet genesis inscription.
///
/// This constant is the sole source of the consensus payload. Testnet and
/// Regtest do not serialize it. The Mainnet identity format is defined by
/// `dom-chain`; presentation strings and documentation are not authorities.
pub const GENESIS_MESSAGE: &str = "Not a store of value. A means of exchange.";

// ── Monetary Policy ──────────────────────────────────────────────────────────

/// Consensus. Base unit. 1 DOM = 100_000_000 noms.
pub const COIN_UNIT: u64 = 100_000_000;

/// Consensus. Initial block subsidy: 33 DOM in noms.
pub const INITIAL_BLOCK_REWARD: u64 = 33 * COIN_UNIT; // 3_300_000_000 noms

/// Consensus. Blocks between each halving of the block reward.
/// 330_000 blocks ≈ 1.25 years at 2-minute block time.
pub const HALVING_INTERVAL: u64 = 330_000;

/// Consensus. Number of active halving epochs.
/// After epoch 54, reward becomes 0 (integer arithmetic floor).
pub const HALVING_EPOCHS: u32 = 55;

/// Consensus. Block reward schedule, in noms, per halving epoch.
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

/// Consensus. Maximum theoretical Mainnet issuance in noms.
///
/// Mainnet genesis is economically empty, so epoch zero contains
/// `HALVING_INTERVAL - 1` reward-bearing blocks (heights 1..329,999). Every
/// later nonzero epoch contains the full interval. Checked arithmetic makes a
/// future schedule change fail at compile time rather than wrap silently.
pub const MAX_SUPPLY_NOMS: u64 = maximum_supply_from_schedule();

/// Recompute the maximum Mainnet issuance from the frozen reward schedule.
///
/// Mainnet height zero has an economically empty body, so the first epoch has
/// one fewer reward-bearing block than later epochs. This function is the
/// allocation-free specification used both by the production constant and by
/// formal verification.
pub const fn maximum_supply_from_schedule() -> u64 {
    let mut total: u64 = 0;
    let mut epoch: usize = 0;
    while epoch < BLOCK_REWARD_TABLE.len() {
        let blocks = if epoch == 0 {
            match HALVING_INTERVAL.checked_sub(1) {
                Some(value) => value,
                None => panic!("HALVING_INTERVAL underflow"),
            }
        } else {
            HALVING_INTERVAL
        };
        let issued = match BLOCK_REWARD_TABLE[epoch].checked_mul(blocks) {
            Some(value) => value,
            None => panic!("maximum issuance multiplication overflow"),
        };
        total = match total.checked_add(issued) {
            Some(value) => value,
            None => panic!("maximum issuance addition overflow"),
        };
        epoch = match epoch.checked_add(1) {
            Some(value) => value,
            None => panic!("reward schedule index overflow"),
        };
    }
    total
}

/// Consensus. Coinbase outputs must mature before spending.
/// 1000 blocks ≈ 1.4 days at 2-minute block time.
pub const COINBASE_MATURITY: u64 = 1_000;

// ── Block & Transaction Limits ───────────────────────────────────────────────

/// Consensus. Maximum block weight units.
pub const MAX_BLOCK_WEIGHT: u32 = 40_000;

/// Consensus. Maximum transaction weight units.
pub const MAX_TX_WEIGHT: u32 = 4_000;

/// Consensus. Maximum inputs per transaction.
pub const MAX_INPUTS_PER_TX: usize = 255;

/// Consensus. Maximum outputs per transaction.
pub const MAX_OUTPUTS_PER_TX: usize = 255;

/// Consensus. Maximum kernels per transaction.
pub const MAX_KERNELS_PER_TX: usize = 16;

/// Consensus. Maximum transactions per block.
pub const MAX_BLOCK_TXS: usize = 5_000;

/// Consensus. Maximum range-proof size in bytes — the standard Bulletproof
/// envelope. DOM's bounded aggregate Bulletproof is a FIXED 739 bytes; DOM
/// emits exactly one proof per output, so 739 is the true maximum. 768
/// (3*256) gives ~93 bytes (~13.8%) of defensive headroom — enough to absorb a
/// minor format/version change without a consensus change, while still bounding
/// the per-proof deserialization allocation tightly. The verifier itself
/// accepts only the exact final 739-byte proof format.
pub const MAX_PROOF_SIZE: usize = 768;

/// Consensus. Exact Wallet V3 recovery capsule size.
pub const RECOVERY_CAPSULE_SIZE: usize = 96;

/// Consensus. Maximum length-prefixed output proof envelope. Recoverable
/// outputs carry the 739-byte range proof followed by a 96-byte capsule.
pub const MAX_OUTPUT_PROOF_ENVELOPE_SIZE: usize = 739 + RECOVERY_CAPSULE_SIZE;

/// Consensus. Maximum serialized block size in bytes (16 MiB).
pub const MAX_BLOCK_SERIALIZED_SIZE: usize = 16 * 1_024 * 1_024;

/// Transport. Maximum reassembled logical wire message, across Noise transport
/// fragments. A single logical message (e.g. a full `Block`, or an IBD `Headers`
/// batch) may exceed one Noise frame and is fragmented by the codec; this bounds
/// the reassembly buffer. Sized to the largest legitimate message — a full Block
/// — plus headroom for the `WireMessage` envelope. The codec rejects any frame
/// stream whose declared total exceeds this BEFORE allocating, as DoS defense.
pub const MAX_LOGICAL_MSG_BYTES: usize = MAX_BLOCK_SERIALIZED_SIZE + 64 * 1_024;

/// Policy. Maximum headers per Headers message (IBD batch size).
pub const MAX_HEADERS_PER_MSG: usize = 2_000;

/// Policy. Maximum block hashes a GetBlockData request can list.
pub const MAX_GETBLOCKDATA_HASHES: usize = 128;

/// Policy. Maximum block locator hashes in GetHeaders.
pub const MAX_LOCATOR_HASHES: usize = 32;

// ── Network & Timing Validation ──────────────────────────────────────────────

/// Consensus. Maximum seconds a block timestamp may be ahead of the local
/// clock before being rejected as TemporarilyInvalid. Per whitepaper §9 step 3.
pub const MAX_FUTURE_BLOCK_TIME: u64 = 120;

/// Consensus. Testnet future timestamp bound.
///
/// Tighter than mainnet to prevent fast timestamp-warped testnet mining once
/// ASERT enforcement is active.
pub const TESTNET_MAX_FUTURE_BLOCK_TIME: u64 = 30;

/// Policy. Soft buffer for blocks slightly beyond MAX_FUTURE_BLOCK_TIME.
/// Blocks with timestamp in (now+MAX_FUTURE_BLOCK_TIME, now+MAX_FUTURE_BLOCK_TIME+SOFT_BUFFER]
/// are deferred for re-evaluation rather than immediately rejected.
/// This reduces orphan rate from transient clock drift without changing
/// the consensus rule (MAX_FUTURE_BLOCK_TIME remains the hard limit).
pub const FUTURE_BLOCK_SOFT_BUFFER_SECS: u64 = 60;

/// Policy. Testnet soft future timestamp buffer.
pub const TESTNET_FUTURE_BLOCK_SOFT_BUFFER_SECS: u64 = 15;

/// Consensus. Median-time-past window size.
pub const MEDIAN_TIME_WINDOW: usize = 11;

// ── Protocol & Network Identity ──────────────────────────────────────────────

/// Network. Protocol version.
pub const PROTOCOL_VERSION: u32 = 2;

/// Network. Mainnet magic bytes: ASCII "DOM1" = 0x44_4F_4D_31
pub const NETWORK_MAGIC_MAINNET: u32 = 0x444F_4D31;

/// Network. Testnet magic bytes: ASCII "DOMT" = 0x44_4F_4D_54
pub const NETWORK_MAGIC_TESTNET: u32 = 0x444F_4D54;

/// [NETWORK — DEV-ONLY] Regtest magic bytes: ASCII "DOMR" = 0x44_4F_4D_52
///
/// SECURITY: The magic byte differs from `NETWORK_MAGIC_MAINNET` /
/// `_TESTNET`, so any Regtest peer attempting to handshake with a
/// real-network node fails at the frame header. This is the primary
/// isolation mechanism — DO NOT change it without re-auditing the
/// peer dispatch path.
pub const NETWORK_MAGIC_REGTEST: u32 = 0x444F_4D52;

/// Network. Default P2P port.
pub const P2P_PORT_MAINNET: u16 = 33_369;

/// Network. Default P2P port for testnet.
pub const P2P_PORT_TESTNET: u16 = 33_370;

/// [NETWORK — DEV-ONLY] Default P2P port for Regtest.
/// Distinct from mainnet/testnet so accidental local conflicts also fail loudly.
pub const P2P_PORT_REGTEST: u16 = 33_371;

/// Network. Default loopback RPC port for Mainnet.
///
/// RPC is disabled unless explicitly enabled. RPC ports are intentionally
/// distinct from every P2P port so an operator cannot accidentally direct an
/// RPC client at the peer protocol listener.
pub const RPC_PORT_MAINNET: u16 = 33_372;

/// Network. Default loopback RPC port for Testnet.
pub const RPC_PORT_TESTNET: u16 = 33_373;

/// [NETWORK — DEV-ONLY] Default loopback RPC port for Regtest.
pub const RPC_PORT_REGTEST: u16 = 33_374;

/// Service. Default loopback metrics port when metrics are explicitly enabled.
pub const METRICS_PORT: u16 = 3_371;

/// Service. Default loopback explorer HTTP port.
pub const EXPLORER_PORT: u16 = 8_081;

/// [DEV-ONLY] Coinbase maturity on Regtest: one confirmation.
///
/// Used exclusively by `Network::Regtest` codepaths so fast integration tests
/// can exercise the full spend pipeline. `COINBASE_MATURITY` (1000) is still
/// the canonical constant for Mainnet/Testnet and is unchanged.
pub const REGTEST_COINBASE_MATURITY: u64 = 1;

/// Network. Maximum user agent string length in bytes.
pub const MAX_USER_AGENT_BYTES: usize = 256;

// ── Policy Constants (MUST NOT affect consensus validity) ────────────────────

/// Policy. Minimum relay fee rate in noms per weight unit.
pub const MIN_RELAY_FEE_RATE: u64 = 1_000;

/// Policy. Maximum depth of chain reorganization to accept.
pub const MAX_REORG_DEPTH_POLICY: u64 = 1_000;

// ── ASERT Target Bounds ──────────────────────────────────────────────────────

/// Consensus. Minimum PoW target (hardest difficulty).
pub const MIN_TARGET_BYTES: [u8; 32] = {
    let mut b = [0u8; 32];
    b[26] = 0xff;
    b[27] = 0xff;
    b
};

/// Consensus. Alias used by deterministic retargeting codepaths.
pub const MIN_ALLOWED_TARGET: [u8; 32] = MIN_TARGET_BYTES;

/// Consensus. Maximum PoW target (easiest difficulty / genesis).
pub const MAX_TARGET_BYTES: [u8; 32] = {
    let mut b = [0xff_u8; 32];
    b[0] = 0x00;
    b[1] = 0x00;
    b
};

/// Consensus. Alias used by deterministic retargeting codepaths.
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

/// Consensus. Standard transaction kernel.
pub const KERNEL_FEAT_PLAIN: u8 = 0x00;

/// Consensus. Coinbase kernel — block reward.
pub const KERNEL_FEAT_COINBASE: u8 = 0x01;

/// Consensus. Height-locked kernel — absolute timelock.
pub const KERNEL_FEAT_HEIGHT_LOCKED: u8 = 0x02;

// ── Weight Units ──────────────────────────────────────────────────────────────

/// Consensus. Weight of a single transaction input.
pub const WEIGHT_INPUT: u32 = 1;

/// Consensus. Weight of a single transaction output.
pub const WEIGHT_OUTPUT: u32 = 21;

/// Consensus. Weight of a standard transaction kernel.
pub const WEIGHT_KERNEL: u32 = 3;

/// Consensus. Weight of a coinbase kernel.
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
/// Domain separator for the canonical Mainnet genesis inscription commitment.
pub const TAG_GENESIS_INSCRIPTION: &str = "DOM:genesis-inscription:v1";
/// Domain separator for the canonical Mainnet genesis identity envelope.
pub const TAG_MAINNET_GENESIS_IDENTITY: &str = "DOM:mainnet-genesis-identity:v1";
/// Domain separator for the complete canonical non-genesis block body.
pub const TAG_BLOCK_BODY_COMMITMENT: &str = "DOM:block-body-commitment:v1";
/// Domain separator binding the historical range-proof PMMR to the complete body.
pub const TAG_BOUND_RANGEPROOF_ROOT: &str = "DOM:bound-rangeproof-root:v1";
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
/// `dom-chain::build_canonical_genesis` ->
/// `dom-consensus::compute_block_pmmr_roots` ->
/// `BlockHeader` serialization ->
/// `dom_crypto::hash::blake2b_256(header_bytes)`.
///
/// Any change in the genesis inputs (tag, timestamp, target, PMMR
/// construction, coinbase structure, or header serialization) changes this
/// hash and is therefore consensus-breaking.
///
/// Regenerated after the bounded aggregate bp2 migration using
/// `TAG_GENESIS_BLINDING:v1`. The genesis coinbase now carries a 739-byte
/// bounded aggregate Bulletproof, so `rangeproof_root` and this hash are pinned
/// to that final format; `output_root`/`kernel_root` are unchanged. Regression
/// tested by `dom-node` `miner::tests::genesis_testnet_frozen_vectors`.
pub const GENESIS_HASH_TESTNET: [u8; 32] = [
    0x2a, 0xb5, 0xe6, 0xc7, 0x36, 0x07, 0xe8, 0xbf, 0xbb, 0xec, 0x2d, 0x4c, 0xe3, 0xea, 0x14, 0x19,
    0xcd, 0xa2, 0x9a, 0xe6, 0x89, 0x2e, 0x7f, 0x1c, 0x24, 0xfa, 0xcc, 0x46, 0x5c, 0xd6, 0x58, 0x21,
];

/// Explicit Mainnet genesis-finalization gate.
///
/// This records that the offline identity ceremony is complete. It does not
/// activate a service, listener, peer connection, seed, or deployment.
pub const MAINNET_GENESIS_FINALIZED: bool = true;

/// Canonical inscription-aware genesis block identifier for Mainnet.
pub const GENESIS_HASH_MAINNET: [u8; 32] = [
    0x18, 0x2e, 0x10, 0xaf, 0x28, 0xe7, 0xec, 0x07, 0x2f, 0x46, 0x2e, 0x60, 0x44, 0xf5, 0x80, 0xdc,
    0x9d, 0xd8, 0xc8, 0x66, 0xcb, 0x78, 0xdf, 0xc2, 0x93, 0xbb, 0xfa, 0xee, 0x4e, 0x93, 0x25, 0xce,
];

/// [DEV-ONLY] Canonical genesis block hash for Regtest.
///
/// Final deterministic Regtest genesis block identifier.
pub const GENESIS_HASH_REGTEST: [u8; 32] = [
    0xfd, 0xda, 0x02, 0x7e, 0x4a, 0x46, 0xdd, 0x36, 0x67, 0x17, 0xc6, 0xe0, 0xa9, 0x76, 0xbf, 0x3e,
    0x0a, 0x75, 0x12, 0xc5, 0xed, 0xf0, 0x84, 0x70, 0xb0, 0xdc, 0xa9, 0x9d, 0xde, 0xe3, 0xfe, 0x1f,
];

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

/// Return whether a candidate is valid for the finalized Mainnet identity.
#[must_use]
pub fn is_valid_mainnet_genesis_hash(hash: &[u8; 32]) -> bool {
    *hash != GENESIS_HASH_TESTNET
        && *hash != GENESIS_HASH_REGTEST
        && !is_placeholder_genesis_hash(hash)
}

/// Validate a would-be mainnet genesis hash before allowing mainnet startup.
///
/// This rejects the placeholder hash and the currently pinned non-mainnet
/// constants so a misconfigured build cannot silently boot a "mainnet" node
/// bound to testnet or regtest identity.
pub fn validate_mainnet_genesis_hash(hash: [u8; 32]) -> Result<(), DomError> {
    if is_valid_mainnet_genesis_hash(&hash) {
        return Ok(());
    }
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
    Err(DomError::Invalid(
        "mainnet genesis is not finalized: GENESIS_HASH_MAINNET is still the zero placeholder"
            .into(),
    ))
}

/// Return the configured genesis timestamp for a network magic value.
pub fn genesis_timestamp_for_network_magic(network_magic: u32) -> Result<u64, DomError> {
    match network_magic {
        NETWORK_MAGIC_MAINNET => Ok(GENESIS_TIMESTAMP_MAINNET),
        NETWORK_MAGIC_TESTNET => Ok(GENESIS_TIMESTAMP_TESTNET),
        NETWORK_MAGIC_REGTEST => Ok(GENESIS_TIMESTAMP_REGTEST),
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
        RPC_PORT_MAINNET != P2P_PORT_MAINNET
            && RPC_PORT_MAINNET != P2P_PORT_TESTNET
            && RPC_PORT_MAINNET != P2P_PORT_REGTEST
            && RPC_PORT_TESTNET != P2P_PORT_MAINNET
            && RPC_PORT_TESTNET != P2P_PORT_TESTNET
            && RPC_PORT_TESTNET != P2P_PORT_REGTEST
            && RPC_PORT_REGTEST != P2P_PORT_MAINNET
            && RPC_PORT_REGTEST != P2P_PORT_TESTNET
            && RPC_PORT_REGTEST != P2P_PORT_REGTEST,
        "RPC ports must not collide with P2P ports"
    );
    assert!(
        RPC_PORT_MAINNET != RPC_PORT_TESTNET
            && RPC_PORT_MAINNET != RPC_PORT_REGTEST
            && RPC_PORT_TESTNET != RPC_PORT_REGTEST,
        "RPC ports must be unique"
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
        assert_eq!(GENESIS_TIMESTAMP_MAINNET, 1_784_071_429);
        assert_eq!(GENESIS_TIMESTAMP_REGTEST, GENESIS_TIMESTAMP_MAINNET);
        assert_eq!(GENESIS_TIMESTAMP_MAINNET_PLACEHOLDER, 1_778_642_633);
    }

    #[test]
    fn network_magic_ids_are_fixed() {
        assert_eq!(NETWORK_MAGIC_MAINNET, 0x444F_4D31);
        assert_eq!(NETWORK_MAGIC_TESTNET, 0x444F_4D54);
        assert_eq!(NETWORK_MAGIC_REGTEST, 0x444F_4D52);
    }

    #[test]
    fn mainnet_guard_accepts_finalized_hash() {
        validate_mainnet_genesis_hash(GENESIS_HASH_MAINNET).unwrap();
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
    fn startup_hash_lookup_accepts_finalized_mainnet() {
        assert_eq!(
            startup_genesis_hash_for_network_magic(NETWORK_MAGIC_MAINNET)
                .unwrap()
                .as_bytes(),
            &GENESIS_HASH_MAINNET
        );
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

/// Policy. Clock drift threshold for warnings.
/// Nodes with drift above this should be alerted but continue operating.
pub const CLOCK_DRIFT_WARN_SECS: i64 = 30;

/// Policy. Clock drift threshold for critical alerts.
/// Mining should be disabled if drift exceeds this value.
pub const CLOCK_DRIFT_ERROR_SECS: i64 = 60;

/// Policy. Peer drift threshold for scoring penalty.
/// Peers with timestamp drift above this trigger moderate scoring.
pub const PEER_DRIFT_WARN_SECS: i64 = 30;

/// Policy. Peer drift threshold for immediate disconnection.
/// Peers with timestamp drift above this are disconnected.
pub const PEER_DRIFT_DISCONNECT_SECS: i64 = 90;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{block_reward, BlockHeight};

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
        assert_eq!(MAX_SUPPLY_NOMS, 3_299_996_676_900_000);
        assert_eq!(block_reward(BlockHeight::GENESIS).noms(), 3_300_000_000);
        assert_eq!(block_reward(BlockHeight(1)).noms(), 3_300_000_000);
        assert_eq!(block_reward(BlockHeight(17_819_999)).noms(), 1);
        assert_eq!(block_reward(BlockHeight(17_820_000)).noms(), 0);
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
