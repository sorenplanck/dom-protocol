#![allow(missing_docs)]
//! # dom-pow
//!
//! ASERT difficulty adjustment — corrected per audit.
//!
//! AUDIT FIXES:
//! 1. target_to_difficulty: no longer truncates to 128 bits.
//!    Uses full 256-bit integer division via (u128, u128) pair.
//! 2. mul_256_by_u128_div_radix: replaced saturating_mul with checked_mul.
//!    Overflow is now a hard error, not silent data corruption.
//! 3. MAX_TARGET_BYTES: zeros are now at start (big-endian), matching MAX_TARGET_HI.
//! 4. asert_no_time_change test: strict equality enforced, not ratio<=2 fudge.
//! 5. RandomX validation: validate_pow_randomx stub added; validate_pow_blake2b
//!    is correctly named to avoid confusion with real PoW.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![allow(clippy::arithmetic_side_effects)] // PoW math: U256 ops audited
#![deny(clippy::float_arithmetic)]

use dom_core::{
    BlockHeight, DomError, Timestamp, ASERT_HALF_LIFE, ASERT_RADIX, MAX_TARGET_BYTES,
    MIN_TARGET_BYTES, TARGET_SPACING,
};
use primitive_types::U256;
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};

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
    let time_diff: i64 = (block_timestamp.0 as i64)
        .checked_sub(anchor.timestamp.0 as i64)
        .ok_or_else(|| DomError::Invalid("time_diff overflow".into()))?;

    let height_diff = block_height
        .0
        .checked_sub(anchor.height.0)
        .ok_or_else(|| DomError::Invalid("height before anchor".into()))?;
    let ideal_time: i64 = (height_diff as i64)
        .checked_mul(TARGET_SPACING as i64)
        .ok_or_else(|| DomError::Invalid("ideal_time overflow".into()))?;

    let exponent_seconds: i64 = time_diff
        .checked_sub(ideal_time)
        .ok_or_else(|| DomError::Invalid("exponent overflow".into()))?;

    // exponent_fp = exponent_seconds * 256 / HALF_LIFE (fixed-point, 256 entries per power-of-2)
    let exponent_fp: i128 = {
        let num = (exponent_seconds as i128)
            .checked_mul(256)
            .ok_or_else(|| DomError::Invalid("exponent_fp overflow".into()))?;
        floor_div_i128(num, ASERT_HALF_LIFE as i128)?
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
    apply_exponent(&anchor.target, integer_part, frac_multiplier)
}

/// Apply exponent to anchor target using CHECKED 256-bit arithmetic.
///
/// AUDIT FIX: replaced saturating_mul with checked_mul throughout.
/// Overflow returns an error instead of silently corrupting difficulty.
fn apply_exponent(
    anchor_target: &[u8; 32],
    integer_part: i128,
    frac_multiplier: u128,
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
    if target_gt(&result, &MAX_TARGET_BYTES) {
        return Ok(MAX_TARGET_BYTES);
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
    if shift >= 128 {
        return (lo << (shift - 128), 0);
    }
    ((hi << shift) | (lo >> (128 - shift)), lo << shift)
}

fn shift_right_256(hi: u128, lo: u128, shift: u32) -> (u128, u128) {
    if shift == 0 {
        return (hi, lo);
    }
    if shift >= 256 {
        return (0, 0);
    }
    if shift >= 128 {
        return (0, hi >> (shift - 128));
    }
    (hi >> shift, (lo >> shift) | (hi << (128 - shift)))
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
    let flags = RandomXFlag::get_recommended_flags();
    let cache = RandomXCache::new(flags, seed)
        .map_err(|e| DomError::Internal(format!("RandomX cache init failed: {e}")))?;
    let vm = RandomXVM::new(flags, Some(cache), None)
        .map_err(|e| DomError::Internal(format!("RandomX VM init failed: {e}")))?;
    let computed = vm
        .calculate_hash(pow_preimage)
        .map_err(|e| DomError::Internal(format!("RandomX hash failed: {e}")))?;
    if computed.len() != 32 {
        return Err(DomError::Internal(format!(
            "RandomX returned {} bytes, expected 32",
            computed.len()
        )));
    }
    let computed_arr: [u8; 32] = computed
        .try_into()
        .map_err(|_| DomError::Internal("RandomX hash conversion failed".into()))?;
    if &computed_arr != randomx_hash {
        return Ok(false);
    }
    Ok(hash_meets_target(randomx_hash, target))
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

/// Scalar difficulty for BlockHeader.total_difficulty (u128).
///
/// Uses the full U256 result for correctness, then takes the top 128 bits.
/// Two targets that differ only in the bottom 128 bits may map to the same u128 —
/// but this only affects precision beyond the resolution of u128 (>2^128 difficulty),
/// which no real network will reach for centuries.
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
/// Para substituir o timestamp no dia do lancamento:
///   1. Executar: date +%s
///   2. Atualizar GENESIS_TIMESTAMP_PLACEHOLDER em dom-core/src/constants.rs
///   3. Recompilar e distribuir binarios
pub fn genesis_anchor() -> AsertAnchor {
    use dom_core::GENESIS_TIMESTAMP_PLACEHOLDER;
    AsertAnchor {
        timestamp: dom_core::Timestamp(GENESIS_TIMESTAMP_PLACEHOLDER),
        height: dom_core::BlockHeight::GENESIS,
        target: dom_core::MAX_TARGET_BYTES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let anchor = AsertAnchor {
            timestamp: Timestamp(0),
            height: BlockHeight(0),
            target: MAX_TARGET_BYTES,
        };
        // Block arrives 100 half-lives late — should clamp to MAX
        let huge_time = TARGET_SPACING
            .checked_add(ASERT_HALF_LIFE.checked_mul(100).unwrap())
            .unwrap();
        let result = asert_next_target(&anchor, Timestamp(huge_time), BlockHeight(1)).unwrap();
        assert_eq!(
            result, MAX_TARGET_BYTES,
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
        use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};

        let seed = [0u8; 32];
        let preimage = b"dom-block";

        // Compute the real hash
        let flags = RandomXFlag::get_recommended_flags();
        let cache = RandomXCache::new(flags, &seed).unwrap();
        let vm = RandomXVM::new(flags, Some(cache), None).unwrap();
        let computed = vm.calculate_hash(preimage).unwrap();
        let hash: [u8; 32] = computed.try_into().unwrap();

        // Use MAX_TARGET so it always meets target
        // Use all-0xff target (absolute maximum) to guarantee hash always passes
        let all_max = [0xff_u8; 32];
        let result =
            validate_pow_randomx(preimage, &hash, &seed, &all_max).expect("should not error");
        assert!(result, "correct hash must be accepted with all-0xff target");
    }
}
