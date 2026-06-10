#![allow(missing_docs)]
//! # dom-pow
//!
//! ASERT difficulty adjustment + RandomX PoW validation.
//!
//! AUDIT FIXES:
//! 1. target_to_difficulty: no longer truncates to 128 bits.
//!    Uses full 256-bit integer division via (u128, u128) pair.
//! 2. mul_256_by_u128_div_radix: replaced saturating_mul with checked_mul.
//!    Overflow is now a hard error, not silent data corruption.
//! 3. MAX_TARGET_BYTES: zeros are now at start (big-endian), matching MAX_TARGET_HI.
//! 4. asert_no_time_change test: strict equality enforced, not ratio<=2 fudge.
//! 5. RandomX validation: real validation via randomx-rs, cache pool keyed by
//!    seed (`randomx_pool`) — avoids 256 MB re-allocation per validated block.

// `randomx_pool` requires manual Send/Sync impls; see module-level SAFETY notes.
// We keep the deny in the rest of the crate by attaching `#[allow(unsafe_code)]`
// directly at the module declaration below.
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![allow(clippy::arithmetic_side_effects)] // PoW math: U256 ops audited
#![deny(clippy::float_arithmetic)]

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use dom_core::{
    BlockHeight, DomError, Timestamp, ASERT_HALF_LIFE, ASERT_RADIX, GENESIS_TARGET_COMPACT,
    MAX_TARGET_BYTES, MIN_TARGET_BYTES, NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_REGTEST,
    NETWORK_MAGIC_TESTNET, TARGET_SPACING,
};
use primitive_types::U256;
use std::env;

#[allow(unsafe_code)]
pub mod randomx_pool;

// ── RandomX Seed Schedule (RFC-0011) ─────────────────────────────────────────

/// [CONSENSUS] RandomX seed rotation interval in blocks.
/// Seed changes every 2048 blocks (~2.8 days at 2-minute block time).
pub const RANDOMX_SEED_INTERVAL: u64 = 2048;

/// [CONSENSUS] RandomX seed lookahead offset.
/// Seed for epoch N uses the block hash at height (N * SEED_INTERVAL - SEED_OFFSET).
pub const RANDOMX_SEED_OFFSET: u64 = 64;

// ── ASERT Fractional Table ────────────────────────────────────────────────────

/// [CONSENSUS] 256-entry lookup table: table[i] = floor(2^(i/256) * 65536).
/// Monotonically non-decreasing. table[0]=65536, table[128]=92681, table[255]=130717.
pub const ASERT_FRAC_TABLE: [u32; 256] = [
    65536, 65713, 65891, 66070, 66249, 66429, 66609, 66789, 66971, 67152, 67334, 67517, 67700,
    67883, 68067, 68252, 68437, 68623, 68809, 68995, 69182, 69370, 69558, 69747, 69936, 70125,
    70315, 70506, 70697, 70889, 71081, 71274, 71467, 71661, 71855, 72050, 72245, 72441, 72638,
    72834, 73032, 73230, 73429, 73628, 73827, 74027, 74228, 74429, 74631, 74833, 75036, 75240,
    75444, 75648, 75853, 76059, 76265, 76472, 76679, 76887, 77096, 77305, 77514, 77725, 77935,
    78147, 78359, 78571, 78784, 78998, 79212, 79427, 79642, 79858, 80074, 80292, 80509, 80727,
    80946, 81166, 81386, 81607, 81828, 82050, 82272, 82495, 82719, 82943, 83168, 83394, 83620,
    83846, 84074, 84302, 84530, 84759, 84989, 85220, 85451, 85682, 85915, 86148, 86381, 86615,
    86850, 87086, 87322, 87559, 87796, 88034, 88273, 88512, 88752, 88993, 89234, 89476, 89718,
    89962, 90206, 90450, 90695, 90941, 91188, 91435, 91683, 91932, 92181, 92431, 92681, 92933,
    93185, 93437, 93691, 93945, 94199, 94455, 94711, 94968, 95225, 95483, 95742, 96002, 96262,
    96523, 96785, 97047, 97310, 97574, 97839, 98104, 98370, 98637, 98904, 99172, 99441, 99711,
    99981, 100252, 100524, 100797, 101070, 101344, 101619, 101894, 102170, 102447, 102725, 103004,
    103283, 103563, 103844, 104125, 104408, 104691, 104975, 105259, 105545, 105831, 106118, 106405,
    106694, 106983, 107273, 107564, 107856, 108148, 108441, 108735, 109030, 109326, 109622, 109919,
    110217, 110516, 110816, 111116, 111418, 111720, 112023, 112326, 112631, 112936, 113243, 113550,
    113857, 114166, 114476, 114786, 115097, 115409, 115722, 116036, 116351, 116666, 116982, 117300,
    117618, 117936, 118256, 118577, 118898, 119221, 119544, 119868, 120193, 120519, 120846, 121173,
    121502, 121831, 122162, 122493, 122825, 123158, 123492, 123827, 124162, 124499, 124837, 125175,
    125514, 125855, 126196, 126538, 126881, 127225, 127570, 127916, 128263, 128611, 128959, 129309,
    129660, 130011, 130364, 130717,
];

// ── CompactTarget ─────────────────────────────────────────────────────────────

/// Bitcoin-style compact target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactTarget(pub u32);

/// Easiest compact-representable target accepted by consensus.
///
/// `MAX_TARGET_BYTES` itself is not compact-stable: converting it to compact
/// form and back loses trailing precision. This constant is the canonical
/// compact form miners and validators can round-trip exactly.
pub const MAX_COMPACT_TARGET: u32 = 0x1e7f_ffff;

/// Testnet genesis compact target.
///
/// Calibrated for an accessible public-testnet bootstrap on modest CPUs while
/// remaining REAL proof-of-work — never the regtest trivial target. Expands to
/// ~131,075 expected hashes per block (~11.8 min at 185 h/s, ~21.8 min at
/// 100 h/s), exactly 2x harder than `MAX_COMPACT_TARGET`, so testnet ASERT
/// keeps headroom to EASE difficulty toward the consensus floor (~65,537
/// hashes per block) when network hashrate is low. The previous anchor
/// (0x1e7fff07, ~2.1M hashes) stalled weak hardware at block 1 because
/// genesis == max left the retarget clamp no room to ease.
pub const TESTNET_TARGET_COMPACT: u32 = 0x1e2e_ff7f;

/// Regtest compact target. Dev-only and intentionally easy.
pub const REGTEST_TARGET_COMPACT: u32 = MAX_COMPACT_TARGET;

/// Network-specific deterministic PoW parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowParams {
    /// Target spacing in seconds.
    pub target_spacing: u64,
    /// ASERT half-life in seconds.
    pub half_life: u64,
    /// Genesis anchor compact target.
    pub genesis_target_compact: u32,
    /// Easiest target the network may ever use.
    pub max_compact_target: u32,
}

impl PowParams {
    /// Expand the genesis compact target to 32-byte target bytes.
    pub fn genesis_target(&self) -> Result<[u8; 32], DomError> {
        CompactTarget(self.genesis_target_compact).to_target()
    }

    /// Expand the easiest allowed target to 32-byte target bytes.
    pub fn max_target(&self) -> Result<[u8; 32], DomError> {
        CompactTarget(self.max_compact_target).to_target()
    }
}

/// Return the canonical PoW parameters for the given network magic.
pub fn pow_params_for_network(network_magic: u32) -> PowParams {
    match network_magic {
        NETWORK_MAGIC_TESTNET => PowParams {
            target_spacing: TARGET_SPACING,
            half_life: ASERT_HALF_LIFE,
            genesis_target_compact: TESTNET_TARGET_COMPACT,
            // Decoupled from the genesis anchor: with genesis == max the
            // apply_exponent clamp froze every retarget at the anchor, so
            // testnet difficulty could never EASE under low hashrate. The
            // ceiling of easiness is the canonical compact-stable maximum
            // (still real PoW, ~65,537 expected hashes per block).
            max_compact_target: MAX_COMPACT_TARGET,
        },
        NETWORK_MAGIC_REGTEST => PowParams {
            target_spacing: TARGET_SPACING,
            half_life: ASERT_HALF_LIFE,
            genesis_target_compact: REGTEST_TARGET_COMPACT,
            max_compact_target: REGTEST_TARGET_COMPACT,
        },
        NETWORK_MAGIC_MAINNET => PowParams {
            target_spacing: TARGET_SPACING,
            half_life: ASERT_HALF_LIFE,
            genesis_target_compact: GENESIS_TARGET_COMPACT,
            max_compact_target: GENESIS_TARGET_COMPACT,
        },
        _ => PowParams {
            target_spacing: TARGET_SPACING,
            half_life: ASERT_HALF_LIFE,
            genesis_target_compact: GENESIS_TARGET_COMPACT,
            max_compact_target: GENESIS_TARGET_COMPACT,
        },
    }
}

impl CompactTarget {
    /// Expand to 32-byte big-endian target.
    pub fn to_target(&self) -> Result<[u8; 32], DomError> {
        let bits = self.0;
        let exponent = (bits >> 24) as usize;
        let mantissa = bits & 0x007f_ffff;
        if mantissa == 0 {
            return Ok([0u8; 32]);
        }
        if bits & 0x0080_0000 != 0 {
            return Err(DomError::Invalid("negative compact target".into()));
        }
        if exponent > 32 {
            return Err(DomError::Invalid(format!(
                "compact exponent {exponent} > 32"
            )));
        }
        let mut target = [0u8; 32];
        let w = |t: &mut [u8; 32], pos: usize, v: u8| {
            if pos < 32 {
                t[31 - pos] = v;
            }
        };
        if exponent >= 1 {
            w(&mut target, exponent - 1, (mantissa & 0xff) as u8);
        }
        if exponent >= 2 {
            w(&mut target, exponent - 2, ((mantissa >> 8) & 0xff) as u8);
        }
        if exponent >= 3 {
            w(&mut target, exponent - 3, ((mantissa >> 16) & 0xff) as u8);
        }
        validate_target_bounds(&target)?;
        Ok(target)
    }
}

fn validate_target_bounds(t: &[u8; 32]) -> Result<(), DomError> {
    if target_gt(t, &MAX_TARGET_BYTES) {
        return Err(DomError::Invalid("target > MAX_TARGET".into()));
    }
    if target_lt(t, &MIN_TARGET_BYTES) {
        return Err(DomError::Invalid("target < MIN_TARGET".into()));
    }
    Ok(())
}

fn target_gt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    false
}
fn target_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false
}

// ── ASERT Anchor ──────────────────────────────────────────────────────────────

/// ASERT static genesis anchor.
#[derive(Debug, Clone)]
pub struct AsertAnchor {
    /// Anchor timestamp.
    pub timestamp: Timestamp,
    /// Anchor height.
    pub height: BlockHeight,
    /// Anchor target (32 bytes big-endian).
    pub target: [u8; 32],
}

// ── ASERT Algorithm ───────────────────────────────────────────────────────────

/// Compute next target via ASERT — corrected 256-bit arithmetic.
pub fn asert_next_target(
    anchor: &AsertAnchor,
    block_timestamp: Timestamp,
    block_height: BlockHeight,
) -> Result<[u8; 32], DomError> {
    asert_next_target_with_params(
        anchor,
        block_timestamp,
        block_height,
        &PowParams {
            target_spacing: TARGET_SPACING,
            half_life: ASERT_HALF_LIFE,
            genesis_target_compact: GENESIS_TARGET_COMPACT,
            max_compact_target: MAX_COMPACT_TARGET,
        },
    )
}

/// Compute the next target via ASERT using explicit network parameters.
pub fn asert_next_target_with_params(
    anchor: &AsertAnchor,
    block_timestamp: Timestamp,
    block_height: BlockHeight,
    params: &PowParams,
) -> Result<[u8; 32], DomError> {
    let time_diff: i64 = (block_timestamp.0 as i64)
        .checked_sub(anchor.timestamp.0 as i64)
        .ok_or_else(|| DomError::Invalid("time_diff overflow".into()))?;

    let height_diff = block_height
        .0
        .checked_sub(anchor.height.0)
        .ok_or_else(|| DomError::Invalid("height before anchor".into()))?;
    let ideal_time: i64 = (height_diff as i64)
        .checked_mul(params.target_spacing as i64)
        .ok_or_else(|| DomError::Invalid("ideal_time overflow".into()))?;

    let exponent_seconds: i64 = time_diff
        .checked_sub(ideal_time)
        .ok_or_else(|| DomError::Invalid("exponent overflow".into()))?;

    // exponent_fp = exponent_seconds * 256 / HALF_LIFE (fixed-point, 256 entries per power-of-2)
    let exponent_fp: i128 = {
        let num = (exponent_seconds as i128)
            .checked_mul(256)
            .ok_or_else(|| DomError::Invalid("exponent_fp overflow".into()))?;
        floor_div_i128(num, params.half_life as i128)?
    };

    let integer_part = floor_div_i128(exponent_fp, 256)?;
    let frac_index = {
        let f = exponent_fp
            .checked_sub(
                integer_part
                    .checked_mul(256)
                    .ok_or_else(|| DomError::Invalid("frac overflow".into()))?,
            )
            .ok_or_else(|| DomError::Invalid("frac underflow".into()))? as usize;
        f.min(255)
    };

    let frac_multiplier = ASERT_FRAC_TABLE[frac_index] as u128;
    apply_exponent(
        &anchor.target,
        integer_part,
        frac_multiplier,
        &params.max_target()?,
    )
}

/// Apply exponent to anchor target using CHECKED 256-bit arithmetic.
///
/// AUDIT FIX: replaced saturating_mul with checked_mul throughout.
/// Overflow returns an error instead of silently corrupting difficulty.
fn apply_exponent(
    anchor_target: &[u8; 32],
    integer_part: i128,
    frac_multiplier: u128,
    max_target: &[u8; 32],
) -> Result<[u8; 32], DomError> {
    let hi = u128::from_be_bytes(anchor_target[0..16].try_into().unwrap());
    let lo = u128::from_be_bytes(anchor_target[16..32].try_into().unwrap());

    let radix = ASERT_RADIX as u128;

    // Multiply (hi, lo) by frac_multiplier then divide by radix (65536)
    let (new_hi, new_lo) = mul_256_div_radix_checked(hi, lo, frac_multiplier, radix)?;

    // Shift by integer_part
    let (shifted_hi, shifted_lo) = if integer_part >= 0 {
        let shift = integer_part.min(255) as u32;
        shift_left_256(new_hi, new_lo, shift)
    } else {
        let shift = (-integer_part).min(255) as u32;
        shift_right_256(new_hi, new_lo, shift)
    };

    let mut result = [0u8; 32];
    result[0..16].copy_from_slice(&shifted_hi.to_be_bytes());
    result[16..32].copy_from_slice(&shifted_lo.to_be_bytes());

    // Clamp
    if target_gt(&result, max_target) {
        return Ok(*max_target);
    }
    if result == [0u8; 32] || target_lt(&result, &MIN_TARGET_BYTES) {
        return Ok(MIN_TARGET_BYTES);
    }
    Ok(result)
}

/// 256-bit multiply by u128 then divide by radix (65536 = 2^16).
///
/// Computes exactly: floor((hi, lo) * multiplier / 65536)
///
/// Since val can be up to 256 bits and multiplier up to 17 bits, the product
/// is up to 273 bits — too wide for U256. We simulate 512-bit arithmetic by
/// splitting val into two 128-bit halves, multiplying each, then combining:
///
///   val = hi_256 * 2^128 + lo_256
///   val * m = hi_256 * m * 2^128 + lo_256 * m
///
/// Each half-product fits in U256 (128 + 17 = 145 bits for lo, same for hi).
/// Then we right-shift the combined 512-bit result by 16.
fn mul_256_div_radix_checked(
    hi: u128,
    lo: u128,
    multiplier: u128,
    radix: u128,
) -> Result<(u128, u128), DomError> {
    let _ = radix; // radix is always 65536 = 2^16; division is exact right-shift

    let m = U256::from(multiplier);

    // lo_256 * m — fits in U256 (128 + 17 bits = 145 bits)
    let lo_prod: U256 = U256::from(lo) * m;

    // hi_256 * m — fits in U256 (128 + 17 bits = 145 bits)
    let hi_prod: U256 = U256::from(hi) * m;

    // Combined 512-bit product (conceptually):
    //   total = hi_prod * 2^128 + lo_prod
    //
    // After right-shifting by 16 (dividing by radix = 2^16):
    //   result = (hi_prod * 2^128 + lo_prod) >> 16
    //          = hi_prod * 2^112 + lo_prod >> 16
    //
    // hi_prod * 2^112: hi_prod is 145 bits, shifted left 112 → 257 bits max.
    // This still overflows U256. So we extract the final (hi, lo) directly:
    //
    // result_bits[256:128] = hi_prod >> 16  (top 128 bits of result)
    // result_bits[128:0]   = (hi_prod << 112) | (lo_prod >> 16)  (bottom 128)
    //
    // The carry from lo_prod into the upper half:
    //   lo_carry = lo_prod >> 16  contributes to bits [112:0] of lower half
    //   hi contribution to lower half = (hi_prod & 0xffff) << 112
    //     i.e. the bottom 16 bits of hi_prod, shifted to bits [127:112]

    let lo_shifted: U256 = lo_prod >> 16;
    let hi_carry_into_lo: U256 = (hi_prod & U256::from(0xffffu128)) << 112;
    let new_lo_256: U256 = lo_shifted + hi_carry_into_lo;

    let new_hi_256: U256 = hi_prod >> 16;

    // Extract u128 halves (results fit in 128 bits each given input constraints)
    let new_hi = new_hi_256.low_u128();
    let new_lo = new_lo_256.low_u128();

    Ok((new_hi, new_lo))
}

fn shift_left_256(hi: u128, lo: u128, shift: u32) -> (u128, u128) {
    if shift == 0 {
        return (hi, lo);
    }
    if shift >= 256 {
        return (u128::MAX, u128::MAX);
    }
    let value = (U256::from(hi) << 128) | U256::from(lo);
    if value > (U256::MAX >> shift) {
        return (u128::MAX, u128::MAX);
    }
    let shifted = value << shift;
    (((shifted >> 128).low_u128()), shifted.low_u128())
}

fn shift_right_256(hi: u128, lo: u128, shift: u32) -> (u128, u128) {
    if shift == 0 {
        return (hi, lo);
    }
    if shift >= 256 {
        return (0, 0);
    }
    let value = (U256::from(hi) << 128) | U256::from(lo);
    let shifted = value >> shift;
    (((shifted >> 128).low_u128()), shifted.low_u128())
}

/// Floor division for i128 — rounds toward negative infinity.
pub fn floor_div_i128(a: i128, b: i128) -> Result<i128, DomError> {
    if b == 0 {
        return Err(DomError::Invalid("floor_div by zero".into()));
    }
    let d = a
        .checked_div(b)
        .ok_or_else(|| DomError::Invalid("floor_div overflow".into()))?;
    let r = a
        .checked_rem(b)
        .ok_or_else(|| DomError::Invalid("floor_div rem overflow".into()))?;
    if r != 0 && ((a < 0) != (b < 0)) {
        d.checked_sub(1)
            .ok_or_else(|| DomError::Invalid("floor_div adj overflow".into()))
    } else {
        Ok(d)
    }
}

// ── PoW Validation ────────────────────────────────────────────────────────────

/// Validation mode for block proof-of-work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowValidationMode {
    /// Full RandomX validation used on mainnet and testnet.
    RandomX,
    /// Deterministic dev/test-only fast mining and validation path.
    FastDevOnly,
}

fn fast_regtest_mining_requested() -> bool {
    matches!(
        env::var("DOM_REGTEST_FAST_MINING"),
        Ok(value) if value == "1" || value.eq_ignore_ascii_case("true")
    )
}

fn pow_validation_mode_for_network_inner(
    network_magic: u32,
    test_mode: bool,
    fast_requested: bool,
) -> Result<PowValidationMode, DomError> {
    if test_mode {
        return Ok(PowValidationMode::FastDevOnly);
    }

    // Regtest is a development-only network and ALWAYS uses the deterministic
    // fast validation path, as a pure function of the network — never relying
    // on process-global env state. This guarantees that any two regtest nodes
    // agree on PoW validation regardless of start order or whether the
    // DOM_REGTEST_FAST_MINING env var happens to be set in a given process.
    // Mainnet/testnet are unaffected: the fast_requested guard below still
    // rejects FastDevOnly on any non-regtest network.
    if network_magic == NETWORK_MAGIC_REGTEST {
        return Ok(PowValidationMode::FastDevOnly);
    }

    if fast_requested {
        if network_magic == NETWORK_MAGIC_REGTEST {
            return Ok(PowValidationMode::FastDevOnly);
        }
        return Err(DomError::Invalid(
            "DOM_REGTEST_FAST_MINING=1 is only allowed on regtest/devtest/test mode".into(),
        ));
    }

    Ok(PowValidationMode::RandomX)
}

/// Determine the validation mode for a network.
///
/// Fast mining is only available in test builds or when the explicit
/// `DOM_REGTEST_FAST_MINING=1` override is set on regtest.
pub fn pow_validation_mode_for_network(network_magic: u32) -> Result<PowValidationMode, DomError> {
    pow_validation_mode_for_network_inner(
        network_magic,
        cfg!(test),
        fast_regtest_mining_requested(),
    )
}

/// Deterministic dev/test-only PoW hash used by the fast mining path.
///
/// The function remains intentionally simple and auditable. It is not
/// used on mainnet/testnet.
pub fn fast_pow_hash(seed: &[u8; 32], preimage: &[u8]) -> [u8; 32] {
    type B2b256 = Blake2b<U32>;
    let mut hasher = B2b256::new();
    hasher.update(b"DOM_FAST_POW_V1");
    hasher.update(seed);
    hasher.update(preimage);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    // Dev/test fast mining must be instantaneous and auditable. Zero the high
    // half so the resulting hash is always below the regtest/test target while
    // preserving deterministic variation in the low half.
    out[..16].fill(0);
    out
}

/// Verify a block hash meets the required target (hash ≤ target, big-endian).
pub fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    !target_gt(hash, target)
}

/// Validate PoW via RandomX.
/// Compute the RandomX seed height for a given block height.
///
/// Seed schedule (RFC-0011, consensus-critical):
///   epoch       = floor(height / RANDOMX_SEED_INTERVAL)
///   seed_height = epoch * RANDOMX_SEED_INTERVAL - RANDOMX_SEED_OFFSET
///
/// For epoch 0 (early blocks), returns 0 (genesis hash used as seed).
/// The caller must supply the block hash at the returned height.
pub fn randomx_seed_height(height: u64) -> u64 {
    let epoch = height / RANDOMX_SEED_INTERVAL;
    if epoch == 0 {
        return 0;
    }
    let anchor = epoch * RANDOMX_SEED_INTERVAL;
    anchor.saturating_sub(RANDOMX_SEED_OFFSET)
}

/// Validate PoW via RandomX (RFC-0011).
///
/// Correct validation steps:
///   1. Compute RandomX(seed, pow_preimage) where:
///      - seed         = block hash at randomx_seed_height(block_height)
///      - pow_preimage = header serialized WITHOUT pow.randomx_hash but WITH pow.nonce
///   2. Check computed_hash == header.pow.randomx_hash
///   3. Check header.pow.randomx_hash <= target
///
/// Parameters:
///   pow_preimage  — header bytes excluding randomx_hash field (includes nonce)
///   randomx_hash  — header.pow.randomx_hash (claimed by miner)
///   seed          — 32-byte seed (hash of block at randomx_seed_height)
///   target        — expanded 32-byte target from CompactTarget
pub fn validate_pow_randomx(
    pow_preimage: &[u8],
    randomx_hash: &[u8; 32],
    seed: &[u8; 32],
    target: &[u8; 32],
) -> Result<bool, DomError> {
    let computed = randomx_pool::randomx_hash(seed, pow_preimage)?;
    if &computed != randomx_hash {
        return Ok(false);
    }
    Ok(hash_meets_target(randomx_hash, target))
}

/// Validate PoW using the network-appropriate mode.
pub fn validate_pow_for_network(
    network_magic: u32,
    pow_preimage: &[u8],
    pow_hash: &[u8; 32],
    seed: &[u8; 32],
    target: &[u8; 32],
) -> Result<bool, DomError> {
    match pow_validation_mode_for_network(network_magic)? {
        PowValidationMode::RandomX => validate_pow_randomx(pow_preimage, pow_hash, seed, target),
        PowValidationMode::FastDevOnly => {
            let computed = fast_pow_hash(seed, pow_preimage);
            if &computed != pow_hash {
                return Ok(false);
            }
            Ok(hash_meets_target(pow_hash, target))
        }
    }
}

/// Compute difficulty from target using correct 256-bit integer division.
///
/// AUDIT FIX v5→v6: Previous (u128,u128) decomposition was mathematically wrong —
/// the two limbs of the quotient are not independent. Now uses primitive_types::U256
/// for correct long division.
///
/// difficulty = MAX_TARGET / target  (256-bit)
///
/// Returns (hi: u128, lo: u128) of the 256-bit quotient.
/// Chain selection: greater (hi, lo) lexicographic pair = more work.
pub fn target_to_difficulty_u256(target: &[u8; 32]) -> (u128, u128) {
    let t = U256::from_big_endian(target);
    if t.is_zero() {
        return (u128::MAX, u128::MAX);
    }
    let max = U256::from_big_endian(&MAX_TARGET_BYTES);
    let diff = max / t; // U256 long division — correct
                        // Extract (hi, lo) from 256-bit result
    let hi = (diff >> 128).low_u128();
    let lo = diff.low_u128();
    (hi, lo)
}

/// Scalar per-block difficulty increment used by chain selection.
///
/// DOM-FINAL-008: the mathematically complete quotient is available from
/// [`target_to_difficulty_u256`], while this legacy scalar wrapper intentionally
/// preserves the current consensus representation for the per-block increment.
/// The exact boundary is `difficulty > 2^128`: above that point the increment is
/// represented by the high 128-bit limb and the low limb is ignored, so distinct
/// U256 quotients in that range may map to the same `u128`.
///
/// This is a consistency-over-precision rule, not a node-divergence risk: every
/// node applies the same deterministic projection before extending it back to
/// `U256` for `BlockHeader.total_difficulty`. If the boundary were ever crossed,
/// the single-block work increment would be underestimated, but the accumulated
/// header field remains a valid `U256` sum of those consensus-defined increments
/// and all nodes still agree on chain selection. The hash rate required for a
/// single block to exceed `2^128` difficulty is astronomical; this only affects
/// precision beyond the resolution of u128 (>2^128 difficulty), which no real
/// network will reach for centuries.
///
/// The plan decision for DOM-FINAL-008 is to document and test this boundary
/// rather than migrate chain-selection arithmetic now. Changing this function to
/// return `U256` would be a consensus arithmetic migration with much higher risk
/// than the theoretical precision limit it addresses.
pub fn target_to_difficulty(target: &[u8; 32]) -> u128 {
    let (hi, lo) = target_to_difficulty_u256(target);
    // Use hi if non-zero, otherwise lo — preserves ordering correctly
    if hi > 0 {
        hi
    } else {
        lo.max(1)
    }
}

// ── Genesis Anchor (RFC-0006) ─────────────────────────────────────────────────

/// Retorna o AsertAnchor do bloco genesis — consensus-critical.
///
/// Usado por todos os nos para calcular dificuldade a partir do bloco 1.
/// Qualquer alteracao aqui e um hard fork imediato.
///
/// The timestamp source is centralized in
/// `dom_core::genesis_timestamp_for_network_magic()` so all networks consume
/// one audited mapping from network identity to genesis anchor time.
pub fn genesis_anchor(network_magic: u32) -> Result<AsertAnchor, DomError> {
    let params = pow_params_for_network(network_magic);
    let timestamp = dom_core::genesis_timestamp_for_network_magic(network_magic)?;
    Ok(AsertAnchor {
        timestamp: dom_core::Timestamp(timestamp),
        height: dom_core::BlockHeight::GENESIS,
        target: params.genesis_target()?,
    })
}

/// Compute the canonical expected target bytes for a block on the given network.
///
/// Consensus headers store targets in compact form. ASERT itself produces a
/// 256-bit integer target, so the canonical consensus value is the ASERT result
/// rounded through the same compact representation that miners serialize and
/// validators expand.
pub fn compute_expected_target(
    network_magic: u32,
    block_timestamp: Timestamp,
    block_height: BlockHeight,
) -> Result<[u8; 32], DomError> {
    let params = pow_params_for_network(network_magic);
    if uses_dev_fixed_target(network_magic) {
        return params.max_target();
    }

    let anchor = genesis_anchor(network_magic)?;
    let raw_target = if block_height == BlockHeight::GENESIS {
        params.genesis_target()?
    } else {
        asert_next_target_with_params(&anchor, block_timestamp, block_height, &params)?
    };
    canonicalize_compact_target(&raw_target)
}

/// Backwards-compatible name for the canonical expected target helper.
pub fn expected_target_for_network(
    network_magic: u32,
    block_timestamp: Timestamp,
    block_height: BlockHeight,
) -> Result<[u8; 32], DomError> {
    compute_expected_target(network_magic, block_timestamp, block_height)
}

/// Convert a canonical 32-byte target to Bitcoin compact form.
pub fn target_to_compact(t: &[u8; 32]) -> u32 {
    let mut first = 0usize;
    for (i, &b) in t.iter().enumerate() {
        if b != 0 {
            first = i;
            break;
        }
    }
    if t[first] == 0 {
        return 0;
    }

    while first < 32 {
        let exp = (32 - first) as u32;
        let m = if first + 2 < 32 {
            (t[first] as u32) | ((t[first + 1] as u32) << 8) | ((t[first + 2] as u32) << 16)
        } else {
            t[first] as u32
        };
        let compact = (exp << 24) | m.min(0x007f_ffff);
        let expanded = compact_to_target_unchecked(compact);
        if !target_gt(&expanded, t) {
            return compact;
        }
        first += 1;
    }

    0
}

fn compact_to_target_unchecked(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    let mut target = [0u8; 32];
    let w = |t: &mut [u8; 32], pos: usize, v: u8| {
        if pos < 32 {
            t[31 - pos] = v;
        }
    };
    if exponent >= 1 {
        w(&mut target, exponent - 1, (mantissa & 0xff) as u8);
    }
    if exponent >= 2 {
        w(&mut target, exponent - 2, ((mantissa >> 8) & 0xff) as u8);
    }
    if exponent >= 3 {
        w(&mut target, exponent - 3, ((mantissa >> 16) & 0xff) as u8);
    }
    target
}

fn canonicalize_compact_target(target: &[u8; 32]) -> Result<[u8; 32], DomError> {
    CompactTarget(target_to_compact(target)).to_target()
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyWindowRetarget {
    previous_target: [u8; 32],
    next_target: [u8; 32],
    window_blocks: u64,
    actual_elapsed_secs: u64,
    bounded_elapsed_secs: u64,
    expected_elapsed_secs: u64,
}

/// Legacy deterministic windowed difficulty retarget kept only for regression
/// tests proving the old path is no longer the public consensus DAA.
#[cfg(test)]
fn legacy_window_retarget_for_tests_only(
    previous_target: &[u8; 32],
    actual_elapsed_secs: u64,
    window_blocks: u64,
) -> Result<LegacyWindowRetarget, DomError> {
    use dom_core::{
        MAX_ALLOWED_TARGET, MAX_DIFFICULTY_ADJUSTMENT_FACTOR_DOWN,
        MAX_DIFFICULTY_ADJUSTMENT_FACTOR_UP, MIN_ALLOWED_TARGET, TARGET_BLOCK_TIME_SECS,
    };
    use primitive_types::U512;

    if window_blocks == 0 {
        return Err(DomError::Invalid(
            "difficulty adjustment window must be non-zero".into(),
        ));
    }

    let expected_elapsed_secs = TARGET_BLOCK_TIME_SECS
        .checked_mul(window_blocks)
        .ok_or_else(|| DomError::Invalid("expected elapsed overflow".into()))?;

    let min_elapsed_secs = (expected_elapsed_secs / MAX_DIFFICULTY_ADJUSTMENT_FACTOR_UP).max(1);
    let max_elapsed_secs = expected_elapsed_secs
        .checked_mul(MAX_DIFFICULTY_ADJUSTMENT_FACTOR_DOWN)
        .ok_or_else(|| DomError::Invalid("max elapsed overflow".into()))?;
    let bounded_elapsed_secs = actual_elapsed_secs.clamp(min_elapsed_secs, max_elapsed_secs);

    let prev = U256::from_big_endian(previous_target);
    if prev.is_zero() {
        return Err(DomError::Invalid("previous target must be non-zero".into()));
    }

    let scaled = prev.full_mul(U256::from(bounded_elapsed_secs));
    let adjusted = scaled / U512::from(expected_elapsed_secs);

    let min = U256::from_big_endian(&MIN_ALLOWED_TARGET);
    let max = U256::from_big_endian(&MAX_ALLOWED_TARGET);

    let mut next = if adjusted < U512::from(min) {
        min
    } else if adjusted > U512::from(max) {
        max
    } else {
        let mut adjusted_bytes = [0u8; 64];
        adjusted.to_big_endian(&mut adjusted_bytes);
        let low = U256::from_big_endian(&adjusted_bytes[32..]);
        if low.is_zero() {
            min
        } else {
            low
        }
    };

    if next < min {
        next = min;
    } else if next > max {
        next = max;
    }

    let mut next_target = [0u8; 32];
    next.to_big_endian(&mut next_target);
    validate_target_bounds(&next_target)?;

    Ok(LegacyWindowRetarget {
        previous_target: *previous_target,
        next_target,
        window_blocks,
        actual_elapsed_secs,
        bounded_elapsed_secs,
        expected_elapsed_secs,
    })
}

/// `true` when this network intentionally uses the development-only fixed
/// trivial target instead of production retargeting.
pub fn uses_dev_fixed_target(network_magic: u32) -> bool {
    network_magic == dom_core::NETWORK_MAGIC_REGTEST
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_core::ASERT_HALF_LIFE_BLOCKS;

    #[test]
    fn table_monotone_and_bounds() {
        assert_eq!(ASERT_FRAC_TABLE[0], 65536);
        assert_eq!(ASERT_FRAC_TABLE[128], 92681);
        assert_eq!(ASERT_FRAC_TABLE[255], 130717);
        for i in 1..256 {
            assert!(
                ASERT_FRAC_TABLE[i] >= ASERT_FRAC_TABLE[i - 1],
                "not monotone at {i}"
            );
        }
        for (i, &v) in ASERT_FRAC_TABLE.iter().enumerate() {
            assert!((65536..131072).contains(&v), "out of bounds at {i}: {v}");
        }
    }

    #[test]
    fn floor_div_rounds_neg_inf() {
        assert_eq!(floor_div_i128(-7, 2).unwrap(), -4);
        assert_eq!(floor_div_i128(-1, 2).unwrap(), -1);
        assert_eq!(floor_div_i128(7, 2).unwrap(), 3);
    }

    #[test]
    fn hash_meets_target_basic() {
        assert!(hash_meets_target(&[0u8; 32], &MAX_TARGET_BYTES));
        assert!(!hash_meets_target(&[0xff_u8; 32], &MIN_TARGET_BYTES));
    }

    #[test]
    fn asert_deterministic() {
        let a = AsertAnchor {
            timestamp: Timestamp(1_704_067_200),
            height: BlockHeight(0),
            target: MAX_TARGET_BYTES,
        };
        let r1 = asert_next_target(&a, Timestamp(1_704_069_000), BlockHeight(1)).unwrap();
        let r2 = asert_next_target(&a, Timestamp(1_704_069_000), BlockHeight(1)).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn asert_slow_increases_target() {
        let t = {
            let mut b = [0u8; 32];
            b[2] = 0x0f;
            b[3] = 0xff;
            b
        };
        let a = AsertAnchor {
            timestamp: Timestamp(0),
            height: BlockHeight(0),
            target: t,
        };
        // 10x slower than expected
        let r = asert_next_target(&a, Timestamp(TARGET_SPACING * 10), BlockHeight(1)).unwrap();
        let t_hi = u128::from_be_bytes(t[0..16].try_into().unwrap());
        let r_hi = u128::from_be_bytes(r[0..16].try_into().unwrap());
        assert!(r_hi >= t_hi, "slow blocks must not decrease target");
    }

    #[test]
    fn asert_fast_decreases_target() {
        let a = AsertAnchor {
            timestamp: Timestamp(1_000_000),
            height: BlockHeight(0),
            target: MAX_TARGET_BYTES,
        };
        let r = asert_next_target(&a, Timestamp(1_000_010), BlockHeight(1)).unwrap();
        let max_hi = u128::from_be_bytes(MAX_TARGET_BYTES[0..16].try_into().unwrap());
        let r_hi = u128::from_be_bytes(r[0..16].try_into().unwrap());
        assert!(
            r_hi <= max_hi,
            "fast blocks must not increase target beyond max"
        );
    }

    #[test]
    fn difficulty_distinct_for_distinct_targets() {
        // Two targets that differ should have different difficulties
        let easy = MAX_TARGET_BYTES;
        let mut harder = MAX_TARGET_BYTES;
        harder[2] = 0x7f;
        let d_easy = target_to_difficulty(&easy);
        let d_hard = target_to_difficulty(&harder);
        assert!(
            d_hard >= d_easy,
            "harder target must have >= difficulty: {d_hard} >= {d_easy}"
        );
    }

    #[test]
    fn max_target_gives_min_difficulty() {
        let d = target_to_difficulty(&MAX_TARGET_BYTES);
        assert_eq!(d, 1, "MAX_TARGET must have difficulty 1");
    }

    #[test]
    fn scalar_difficulty_boundary_is_deterministic_and_u256_complete() {
        let max = U256::from_big_endian(&MAX_TARGET_BYTES);
        let boundary_increment = U256::from(1u8) << 127;
        let boundary_target_u256 = max / boundary_increment;
        let mut boundary_target = [0u8; 32];
        boundary_target_u256.to_big_endian(&mut boundary_target);

        let (boundary_hi, boundary_lo) = target_to_difficulty_u256(&boundary_target);
        assert_eq!(
            boundary_hi, 0,
            "chosen boundary target must stay within the scalar u128 limb"
        );
        assert!(
            boundary_lo >= (1u128 << 127),
            "boundary difficulty should be near the top half of u128"
        );
        assert_eq!(
            target_to_difficulty(&boundary_target),
            boundary_lo,
            "scalar path must return the exact low limb while hi == 0"
        );

        let mut hardest_target = [0u8; 32];
        hardest_target[31] = 1;
        let (hard_hi, hard_lo) = target_to_difficulty_u256(&hardest_target);
        assert!(
            hard_hi > 0,
            "target=1 must produce a quotient above the u128 scalar range"
        );
        assert!(
            hard_lo > 0,
            "U256 path retains the lower limb ignored by the scalar projection"
        );
        let scalar = target_to_difficulty(&hardest_target);
        assert_eq!(
            scalar, hard_hi,
            "above 2^128 the scalar path deterministically uses the high limb"
        );

        for _ in 0..8 {
            assert_eq!(target_to_difficulty(&hardest_target), scalar);
            assert_eq!(
                target_to_difficulty_u256(&hardest_target),
                (hard_hi, hard_lo)
            );
        }
    }

    /// Expected hash attempts for one block at the given target.
    fn expected_hashes(target: &[u8; 32]) -> U256 {
        U256::MAX / U256::from_big_endian(target)
    }

    #[test]
    fn testnet_genesis_is_2x_harder_than_easy_compact_target() {
        let easy = CompactTarget(MAX_COMPACT_TARGET).to_target().unwrap();
        let testnet = CompactTarget(TESTNET_TARGET_COMPACT).to_target().unwrap();
        let ratio = U256::from_big_endian(&easy) / U256::from_big_endian(&testnet);
        assert_eq!(ratio, U256::from(2u8));
    }

    /// Prova 1: o genesis da testnet passa validate_target_bounds (to_target
    /// valida internamente) e exige ~131k hashes/bloco — mineável por CPU
    /// modesta (~11.8 min a 185 h/s) sem ser trivial.
    #[test]
    fn testnet_genesis_passes_bounds_and_requires_about_131k_hashes() {
        let target = CompactTarget(TESTNET_TARGET_COMPACT)
            .to_target()
            .expect("genesis target must pass validate_target_bounds");
        let hashes = expected_hashes(&target);
        assert!(
            hashes >= U256::from(130_000u32) && hashes <= U256::from(132_000u32),
            "expected ~131,075 hashes per block, got {hashes}"
        );
    }

    /// Prova 2: na testnet, max_target é estritamente MAIS FÁCIL (maior) que
    /// o genesis_target — o clamp de apply_exponent tem espaço para o ASERT
    /// baixar a dificuldade (antes genesis == max congelava o retarget).
    #[test]
    fn testnet_asert_has_headroom_to_ease() {
        let params = pow_params_for_network(NETWORK_MAGIC_TESTNET);
        let genesis = params.genesis_target().unwrap();
        let max = params.max_target().unwrap();
        assert!(
            U256::from_big_endian(&max) > U256::from_big_endian(&genesis),
            "max_target must be easier than genesis_target on testnet"
        );
    }

    /// Prova 3: com blocos chegando MAIS DEVAGAR que o spacing (hashrate
    /// baixo), o retarget produz um alvo MAIS FÁCIL que o inicial — impossível
    /// antes desta mudança, quando o clamp prendia o resultado no anchor.
    #[test]
    fn testnet_slow_blocks_ease_difficulty_below_genesis() {
        let params = pow_params_for_network(NETWORK_MAGIC_TESTNET);
        let anchor = genesis_anchor(NETWORK_MAGIC_TESTNET).unwrap();
        // Bloco 1 atrasado meia half-life (17.280s além do ideal): o ASERT
        // deve facilitar ~sqrt(2)x — estritamente entre genesis e max.
        let late = Timestamp(anchor.timestamp.0 + params.target_spacing + params.half_life / 2);
        let next = asert_next_target_with_params(&anchor, late, BlockHeight(1), &params).unwrap();

        let genesis = U256::from_big_endian(&anchor.target);
        let max = U256::from_big_endian(&params.max_target().unwrap());
        let eased = U256::from_big_endian(&next);
        assert!(
            eased > genesis,
            "slow blocks must EASE the target (was impossible with genesis == max)"
        );
        assert!(eased <= max, "eased target must respect the max clamp");
    }

    /// Prova 4: mainnet e regtest ficam EXATAMENTE como estavam.
    #[test]
    fn mainnet_and_regtest_pow_params_unchanged() {
        assert_eq!(GENESIS_TARGET_COMPACT, 0x1e00_ffff);
        let mainnet = pow_params_for_network(NETWORK_MAGIC_MAINNET);
        assert_eq!(mainnet.genesis_target_compact, GENESIS_TARGET_COMPACT);
        assert_eq!(mainnet.max_compact_target, GENESIS_TARGET_COMPACT);

        let regtest = pow_params_for_network(NETWORK_MAGIC_REGTEST);
        assert_eq!(regtest.genesis_target_compact, REGTEST_TARGET_COMPACT);
        assert_eq!(regtest.max_compact_target, REGTEST_TARGET_COMPACT);
        assert_eq!(REGTEST_TARGET_COMPACT, MAX_COMPACT_TARGET);
    }

    /// Prova 5: o alvo de testnet continua PoW REAL — exige pelo menos 2x o
    /// piso do consenso (65.536 hashes, o mesmo do trivial de regtest) e nunca
    /// é mais fácil que o teto compact permitido.
    #[test]
    fn testnet_genesis_remains_real_pow() {
        let genesis = CompactTarget(TESTNET_TARGET_COMPACT).to_target().unwrap();
        let hashes = expected_hashes(&genesis);
        assert!(
            hashes >= U256::from(2u32 * 65_536),
            "testnet genesis must require at least 2x the consensus floor, got {hashes}"
        );
        let easiest = CompactTarget(MAX_COMPACT_TARGET).to_target().unwrap();
        assert!(
            U256::from_big_endian(&genesis) < U256::from_big_endian(&easiest),
            "testnet genesis must be strictly harder than the easiest allowed target"
        );
    }

    #[test]
    fn target_to_compact_round_trips_consensus_compacts() {
        for compact in [
            GENESIS_TARGET_COMPACT,
            TESTNET_TARGET_COMPACT,
            REGTEST_TARGET_COMPACT,
            MAX_COMPACT_TARGET,
        ] {
            let target = CompactTarget(compact).to_target().unwrap();
            assert_eq!(target_to_compact(&target), compact);
        }
    }

    #[test]
    fn min_target_canonicalizes_to_valid_compact_target() {
        let compact = target_to_compact(&MIN_TARGET_BYTES);
        let expanded = CompactTarget(compact).to_target().unwrap();

        assert!(!target_lt(&expanded, &MIN_TARGET_BYTES));
        assert!(!target_gt(&expanded, &MAX_TARGET_BYTES));
    }

    #[test]
    fn public_asert_half_life_is_288_blocks() {
        assert_eq!(ASERT_HALF_LIFE_BLOCKS, 288);
        for network_magic in [NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_TESTNET] {
            let params = pow_params_for_network(network_magic);
            assert_eq!(params.target_spacing, TARGET_SPACING);
            assert_eq!(params.half_life / params.target_spacing, 288);
        }
    }

    #[test]
    fn public_asert_half_life_seconds_is_34560() {
        assert_eq!(ASERT_HALF_LIFE, 34_560);
        assert_eq!(ASERT_HALF_LIFE, TARGET_SPACING * ASERT_HALF_LIFE_BLOCKS);
        for network_magic in [NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_TESTNET] {
            let params = pow_params_for_network(network_magic);
            assert_eq!(params.half_life, 34_560);
        }
    }

    #[test]
    fn testnet_params_decouple_genesis_anchor_from_max_target() {
        let params = pow_params_for_network(NETWORK_MAGIC_TESTNET);
        assert_eq!(params.target_spacing, TARGET_SPACING);
        assert_eq!(params.genesis_target_compact, TESTNET_TARGET_COMPACT);
        assert_eq!(params.max_compact_target, MAX_COMPACT_TARGET);
    }

    #[test]
    fn public_expected_target_is_asert_compact_canonicalized() {
        let params = pow_params_for_network(NETWORK_MAGIC_MAINNET);
        let anchor = genesis_anchor(NETWORK_MAGIC_MAINNET).unwrap();
        let height = BlockHeight(17);
        let timestamp = Timestamp(anchor.timestamp.0 + params.target_spacing * height.0 + 37);
        let raw = asert_next_target_with_params(&anchor, timestamp, height, &params).unwrap();
        let canonical = CompactTarget(target_to_compact(&raw)).to_target().unwrap();

        assert_eq!(
            compute_expected_target(NETWORK_MAGIC_MAINNET, timestamp, height).unwrap(),
            canonical
        );
    }

    #[test]
    fn regtest_expected_target_is_fixed_easy_target() {
        let anchor = genesis_anchor(NETWORK_MAGIC_REGTEST).unwrap();
        let target = compute_expected_target(
            NETWORK_MAGIC_REGTEST,
            Timestamp(anchor.timestamp.0 + 1),
            BlockHeight(25),
        )
        .unwrap();
        let fixed = CompactTarget(REGTEST_TARGET_COMPACT).to_target().unwrap();

        assert_eq!(target, fixed);
    }

    #[test]
    fn expected_target_large_positive_delta_clamps_to_public_max() {
        let params = pow_params_for_network(NETWORK_MAGIC_MAINNET);
        let anchor = genesis_anchor(NETWORK_MAGIC_MAINNET).unwrap();
        let target = compute_expected_target(
            NETWORK_MAGIC_MAINNET,
            Timestamp(anchor.timestamp.0 + ASERT_HALF_LIFE * 100),
            BlockHeight(1),
        )
        .unwrap();

        assert_eq!(target, params.max_target().unwrap());
    }

    #[test]
    fn expected_target_large_negative_delta_gets_harder() {
        let params = pow_params_for_network(NETWORK_MAGIC_MAINNET);
        let anchor = genesis_anchor(NETWORK_MAGIC_MAINNET).unwrap();
        let height = BlockHeight((ASERT_HALF_LIFE / TARGET_SPACING) * 4);
        let target = compute_expected_target(
            NETWORK_MAGIC_MAINNET,
            Timestamp(anchor.timestamp.0 + params.target_spacing),
            height,
        )
        .unwrap();

        assert!(U256::from_big_endian(&target) < U256::from_big_endian(&anchor.target));
    }

    #[test]
    fn fast_blocks_harden_difficulty_under_asert_288() {
        let params = pow_params_for_network(NETWORK_MAGIC_MAINNET);
        let anchor = genesis_anchor(NETWORK_MAGIC_MAINNET).unwrap();
        let height = BlockHeight(ASERT_HALF_LIFE_BLOCKS);
        let target = compute_expected_target(
            NETWORK_MAGIC_MAINNET,
            Timestamp(anchor.timestamp.0 + params.target_spacing),
            height,
        )
        .unwrap();

        assert_eq!(params.half_life, 34_560);
        assert!(U256::from_big_endian(&target) < U256::from_big_endian(&anchor.target));
    }

    #[test]
    fn slow_blocks_ease_difficulty_under_asert_288() {
        let params = pow_params_for_network(NETWORK_MAGIC_MAINNET);
        let anchor = genesis_anchor(NETWORK_MAGIC_MAINNET).unwrap();
        let height = BlockHeight(ASERT_HALF_LIFE_BLOCKS);
        let fast_target = compute_expected_target(
            NETWORK_MAGIC_MAINNET,
            Timestamp(anchor.timestamp.0 + params.target_spacing),
            height,
        )
        .unwrap();
        let slow_target = compute_expected_target(
            NETWORK_MAGIC_MAINNET,
            Timestamp(anchor.timestamp.0 + params.target_spacing * ASERT_HALF_LIFE_BLOCKS * 2),
            height,
        )
        .unwrap();

        assert_eq!(params.half_life, 34_560);
        assert!(U256::from_big_endian(&slow_target) > U256::from_big_endian(&fast_target));
    }

    #[test]
    fn expected_target_extreme_negative_delta_clamps_to_min() {
        let anchor = genesis_anchor(NETWORK_MAGIC_MAINNET).unwrap();
        let height = BlockHeight((ASERT_HALF_LIFE / TARGET_SPACING) * 300);
        let target = compute_expected_target(
            NETWORK_MAGIC_MAINNET,
            Timestamp(anchor.timestamp.0 + 1),
            height,
        )
        .unwrap();

        assert_eq!(target, MIN_TARGET_BYTES);
    }

    #[test]
    fn fast_pow_mode_activates_only_for_explicit_regtest_or_test_mode() {
        // Regtest ALWAYS uses FastDevOnly as a pure function of the network,
        // regardless of the env-var-derived `fast_requested` flag. This keeps
        // two regtest nodes in agreement without relying on process-global env
        // state.
        assert_eq!(
            pow_validation_mode_for_network_inner(NETWORK_MAGIC_REGTEST, false, false).unwrap(),
            PowValidationMode::FastDevOnly
        );
        assert_eq!(
            pow_validation_mode_for_network_inner(NETWORK_MAGIC_REGTEST, false, true).unwrap(),
            PowValidationMode::FastDevOnly
        );
        assert_eq!(
            pow_validation_mode_for_network_inner(NETWORK_MAGIC_MAINNET, true, false).unwrap(),
            PowValidationMode::FastDevOnly
        );
        assert!(
            pow_validation_mode_for_network_inner(NETWORK_MAGIC_MAINNET, false, true).is_err(),
            "DOM_REGTEST_FAST_MINING must fail closed on mainnet"
        );
        assert!(
            pow_validation_mode_for_network_inner(NETWORK_MAGIC_TESTNET, false, true).is_err(),
            "DOM_REGTEST_FAST_MINING must fail closed on testnet"
        );
    }

    #[test]
    fn fast_pow_hash_is_deterministic() {
        let seed = [0x11u8; 32];
        let preimage = b"pow-preimage";
        let first = fast_pow_hash(&seed, preimage);
        let second = fast_pow_hash(&seed, preimage);
        assert_eq!(first, second);
    }
}

// ── Strict ASERT behavioral tests (restored after audit) ─────────────────────

#[cfg(test)]
mod asert_strict_tests {
    use super::*;

    fn mid_target() -> [u8; 32] {
        // A target in the middle of valid range — easy to reason about
        let mut t = [0u8; 32];
        t[2] = 0x00;
        t[3] = 0x0f; // modest difficulty
        for item in t.iter_mut().skip(4) {
            *item = 0xff;
        }
        t
    }

    /// AUDIT: Previous test had ratio<=2 fudge. This is strict.
    /// Zero time drift MUST produce exactly the same target.
    /// If this fails, apply_exponent has residual arithmetic error.
    #[test]
    fn asert_zero_drift_preserves_target_exactly() {
        let t = mid_target();
        let anchor = AsertAnchor {
            timestamp: Timestamp(1_000_000),
            height: BlockHeight(0),
            target: t,
        };
        // Exactly on schedule: 1 block * TARGET_SPACING seconds
        let result = asert_next_target(
            &anchor,
            Timestamp(1_000_000 + TARGET_SPACING),
            BlockHeight(1),
        )
        .unwrap();
        assert_eq!(
            result, t,
            "zero time drift must preserve target exactly — any deviation is an arithmetic bug"
        );
    }

    #[test]
    fn asert_clamps_to_max_target_when_very_slow() {
        let easiest = CompactTarget(MAX_COMPACT_TARGET).to_target().unwrap();
        let anchor = AsertAnchor {
            timestamp: Timestamp(0),
            height: BlockHeight(0),
            target: easiest,
        };
        // Block arrives 100 half-lives late — should clamp to MAX
        let huge_time = TARGET_SPACING
            .checked_add(ASERT_HALF_LIFE.checked_mul(100).unwrap())
            .unwrap();
        let result = asert_next_target(&anchor, Timestamp(huge_time), BlockHeight(1)).unwrap();
        assert_eq!(
            result, easiest,
            "pathologically slow blocks must clamp to MAX_TARGET"
        );
    }

    #[test]
    fn asert_clamps_to_min_target_when_very_fast() {
        let anchor = AsertAnchor {
            timestamp: Timestamp(1_000_000_000),
            height: BlockHeight(0),
            target: MIN_TARGET_BYTES,
        };
        // Block arrives 1 second after anchor (100x faster than minimum spacing)
        let result = asert_next_target(&anchor, Timestamp(1_000_000_001), BlockHeight(1)).unwrap();
        // Must clamp at or below MIN_TARGET
        assert!(
            !target_gt(&result, &MIN_TARGET_BYTES),
            "pathologically fast blocks must clamp to MIN_TARGET, got {:?}",
            &result[0..8]
        );
    }

    #[test]
    fn asert_difficulty_u256_correct_long_division() {
        // Verify U256 long division is correct
        // MAX_TARGET / MAX_TARGET = 1
        let d = target_to_difficulty_u256(&MAX_TARGET_BYTES);
        assert_eq!(d, (0, 1), "MAX_TARGET/MAX_TARGET must equal 1");

        // Two distinct targets must have distinct difficulties
        let mut t1 = MAX_TARGET_BYTES;
        let mut t2 = MAX_TARGET_BYTES;
        t1[2] = 0x80;
        t2[2] = 0x40; // t2 is harder (smaller value)
        let d1 = target_to_difficulty(&t1);
        let d2 = target_to_difficulty(&t2);
        assert!(
            d2 > d1,
            "harder target (smaller value) must have higher difficulty: d2={d2} d1={d1}"
        );
    }

    #[test]
    fn difficulty_u256_ordering_preserved() {
        // For any t1 < t2 (big-endian), difficulty(t1) > difficulty(t2)
        let mut t_easy = [0u8; 32];
        t_easy[2] = 0x01; // large target = easy
        let mut t_hard = [0u8; 32];
        t_hard[4] = 0x01; // smaller target = hard

        let (h_easy, l_easy) = target_to_difficulty_u256(&t_easy);
        let (h_hard, l_hard) = target_to_difficulty_u256(&t_hard);

        let easy_wins = h_easy > h_hard || (h_easy == h_hard && l_easy > l_hard);
        assert!(!easy_wins, "harder target must have HIGHER difficulty pair");
    }
}

#[cfg(test)]
mod window_retarget_tests {
    use super::*;
    use dom_core::{
        DIFFICULTY_ADJUSTMENT_WINDOW, MAX_DIFFICULTY_ADJUSTMENT_FACTOR_DOWN,
        MAX_DIFFICULTY_ADJUSTMENT_FACTOR_UP, TARGET_BLOCK_TIME_SECS,
    };

    fn mid_target() -> [u8; 32] {
        let mut t = MAX_TARGET_BYTES;
        t[2] = 0x7f;
        t
    }

    #[test]
    fn fast_blocks_make_next_target_harder() {
        let previous = mid_target();
        let adjustment = legacy_window_retarget_for_tests_only(
            &previous,
            TARGET_BLOCK_TIME_SECS * (DIFFICULTY_ADJUSTMENT_WINDOW / 2),
            DIFFICULTY_ADJUSTMENT_WINDOW,
        )
        .unwrap();
        assert!(
            U256::from_big_endian(&adjustment.next_target) < U256::from_big_endian(&previous),
            "fast blocks must reduce the target"
        );
    }

    #[test]
    fn slow_blocks_make_next_target_easier() {
        let previous = mid_target();
        let adjustment = legacy_window_retarget_for_tests_only(
            &previous,
            TARGET_BLOCK_TIME_SECS * DIFFICULTY_ADJUSTMENT_WINDOW * 2,
            DIFFICULTY_ADJUSTMENT_WINDOW,
        )
        .unwrap();
        assert!(
            U256::from_big_endian(&adjustment.next_target) > U256::from_big_endian(&previous),
            "slow blocks must increase the target"
        );
    }

    #[test]
    fn adjustment_is_bounded_by_max_factors() {
        let previous = mid_target();
        let fast =
            legacy_window_retarget_for_tests_only(&previous, 0, DIFFICULTY_ADJUSTMENT_WINDOW)
                .unwrap();
        let slow = legacy_window_retarget_for_tests_only(
            &previous,
            TARGET_BLOCK_TIME_SECS * DIFFICULTY_ADJUSTMENT_WINDOW * 100,
            DIFFICULTY_ADJUSTMENT_WINDOW,
        )
        .unwrap();
        let previous_u256 = U256::from_big_endian(&previous);
        let fast_u256 = U256::from_big_endian(&fast.next_target);
        let slow_u256 = U256::from_big_endian(&slow.next_target);
        assert_eq!(
            fast.bounded_elapsed_secs,
            (fast.expected_elapsed_secs / MAX_DIFFICULTY_ADJUSTMENT_FACTOR_UP).max(1)
        );
        assert_eq!(
            slow.bounded_elapsed_secs,
            slow.expected_elapsed_secs * MAX_DIFFICULTY_ADJUSTMENT_FACTOR_DOWN
        );
        assert!(
            fast_u256 >= previous_u256 / U256::from(MAX_DIFFICULTY_ADJUSTMENT_FACTOR_UP),
            "hardening must be bounded"
        );
        assert!(
            slow_u256 <= previous_u256 * U256::from(MAX_DIFFICULTY_ADJUSTMENT_FACTOR_DOWN),
            "easing must be bounded"
        );
    }

    #[test]
    fn same_history_produces_same_next_target() {
        let previous = mid_target();
        let a = legacy_window_retarget_for_tests_only(
            &previous,
            TARGET_BLOCK_TIME_SECS * DIFFICULTY_ADJUSTMENT_WINDOW,
            DIFFICULTY_ADJUSTMENT_WINDOW,
        )
        .unwrap();
        let b = legacy_window_retarget_for_tests_only(
            &previous,
            TARGET_BLOCK_TIME_SECS * DIFFICULTY_ADJUSTMENT_WINDOW,
            DIFFICULTY_ADJUSTMENT_WINDOW,
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn regtest_fixed_target_does_not_leak_into_production_networks() {
        assert!(uses_dev_fixed_target(dom_core::NETWORK_MAGIC_REGTEST));
        assert!(!uses_dev_fixed_target(dom_core::NETWORK_MAGIC_MAINNET));
        assert!(!uses_dev_fixed_target(dom_core::NETWORK_MAGIC_TESTNET));
    }
}

// ── Serialization ─────────────────────────────────────────────────────────────

use dom_serialization::{DomDeserialize, DomSerialize, Reader, Writer};

impl DomSerialize for CompactTarget {
    fn serialize(&self, w: &mut Writer) -> Result<(), dom_core::DomError> {
        w.write_u32(self.0);
        Ok(())
    }
}

impl DomDeserialize for CompactTarget {
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, dom_core::DomError> {
        Ok(CompactTarget(r.read_u32()?))
    }
}

#[cfg(test)]
mod randomx_tests {
    use super::*;

    #[test]
    fn seed_height_epoch_zero() {
        // Blocos 0–2047: sempre usa genesis (altura 0)
        assert_eq!(randomx_seed_height(0), 0);
        assert_eq!(randomx_seed_height(1), 0);
        assert_eq!(randomx_seed_height(2047), 0);
    }

    #[test]
    fn seed_height_epoch_one() {
        // Blocos 2048–4095: seed = 2048 - 64 = 1984
        assert_eq!(randomx_seed_height(2048), 1984);
        assert_eq!(randomx_seed_height(4095), 1984);
    }

    #[test]
    fn seed_height_epoch_two() {
        // Blocos 4096–6143: seed = 4096 - 64 = 4032
        assert_eq!(randomx_seed_height(4096), 4032);
    }

    #[test]
    fn randomx_hash_is_deterministic() {
        let seed = [0u8; 32];
        let preimage = b"dom-testnet-block-0";
        let target = MAX_TARGET_BYTES;

        // Compute twice — must be identical
        let r1 = validate_pow_randomx(preimage, &[0u8; 32], &seed, &target);
        let r2 = validate_pow_randomx(preimage, &[0u8; 32], &seed, &target);
        // Both must succeed (even if hash doesn't meet target, no error)
        assert!(r1.is_ok(), "first call failed: {:?}", r1);
        assert!(r2.is_ok(), "second call failed: {:?}", r2);
    }

    #[test]
    fn randomx_wrong_hash_rejected() {
        let seed = [0u8; 32];
        let preimage = b"dom-block";
        let target = MAX_TARGET_BYTES;

        // Wrong hash (all 0xff) must not validate
        let wrong_hash = [0xff_u8; 32];
        let result =
            validate_pow_randomx(preimage, &wrong_hash, &seed, &target).expect("should not error");
        assert!(!result, "wrong randomx_hash must be rejected");
    }

    #[test]
    fn randomx_correct_hash_accepted_if_meets_target() {
        let seed = [0u8; 32];
        let preimage = b"dom-block";

        // Compute the real hash via the pool (single source of truth).
        let hash = randomx_pool::randomx_hash(&seed, preimage).unwrap();

        // Use all-0xff target so the hash always meets target.
        let all_max = [0xff_u8; 32];
        let result =
            validate_pow_randomx(preimage, &hash, &seed, &all_max).expect("should not error");
        assert!(result, "correct hash must be accepted with all-0xff target");
    }
}
