//! dom-shield — dom-pow XDIFF: ASERT 256-bit multiply vs full-width U512 ref.
//!
//! TARGET VECTOR: `apply_exponent` / `mul_256_div_radix_checked`.
//!
//! The internal multiply computes, for an anchor target split into 128-bit
//! halves (hi, lo) and a frac multiplier `m`:
//!
//!     floor((hi * 2^128 + lo) * m / 65536)
//!
//! It reconstructs the low limb as
//!     new_lo = (lo*m >> 16) + ((hi*m & 0xffff) << 112)
//! and the high limb as
//!     new_hi = (hi*m) >> 16
//! then TRUNCATES each with `low_u128()`. When `new_lo` overflows 128 bits the
//! carry into `new_hi` is dropped — `new_hi` is NOT incremented. The result is
//! an off-by-one in the HIGH limb of the next target.
//!
//! This XDIFF drives `asert_next_target` (the public consensus entry point) with
//! inputs chosen so that `integer_part == 0` (pure frac multiply, no shift) and
//! the carry-loss is triggered, then compares against an independent U512
//! reference of the SAME ASERT computation. If they differ, the production
//! arithmetic is wrong.
//!
//! STATUS: GREEN regression — the production arithmetic must match the
//! independent U512 reference on the historical carry-loss vector family.
//! If this fails, a low→high carry regression re-entered consensus arithmetic.

use dom_core::{BlockHeight, Timestamp, ASERT_HALF_LIFE, TARGET_SPACING};
use dom_pow::{asert_next_target, AsertAnchor, ASERT_FRAC_TABLE};
use primitive_types::{U256, U512};

/// Floor division toward negative infinity (matches the production helper).
fn floor_div(a: i128, b: i128) -> i128 {
    let d = a / b;
    let r = a % b;
    if r != 0 && ((a < 0) != (b < 0)) {
        d - 1
    } else {
        d
    }
}

/// Independent full-width reference for ASERT next-target, using U512 for the
/// multiply so no carry is ever dropped. Mirrors the production control flow
/// (frac index selection, integer shift, MIN/MAX clamp) but performs the core
/// multiply in 512 bits.
fn asert_reference(
    anchor: &AsertAnchor,
    block_ts: u64,
    height: u64,
    max_target: &[u8; 32],
) -> [u8; 32] {
    let time_diff = block_ts as i64 - anchor.timestamp.0 as i64;
    let height_diff = height - anchor.height.0;
    let ideal = height_diff as i64 * TARGET_SPACING as i64;
    let exp_sec = time_diff - ideal;
    let exp_fp = floor_div(exp_sec as i128 * 256, ASERT_HALF_LIFE as i128);
    let integer_part = floor_div(exp_fp, 256);
    let frac_index = ((exp_fp - integer_part * 256) as usize).min(255);
    let m = ASERT_FRAC_TABLE[frac_index] as u128;

    let anchor_u = U256::from_big_endian(&anchor.target);
    // full-width multiply / 65536
    let prod = U512::from(anchor_u) * U512::from(m);
    let divided = prod >> 16;

    // integer shift
    let shifted: U512 = if integer_part >= 0 {
        let s = integer_part.min(255) as u32;
        divided << s
    } else {
        let s = (-integer_part).min(255) as u32;
        divided >> s
    };

    // take low 256 bits (production reassembles two u128 limbs => low 256 bits)
    let mask256 = (U512::from(1u8) << 256) - U512::from(1u8);
    let low256 = shifted & mask256;
    let result_u = U256::try_from(low256).unwrap_or(U256::MAX);

    let mut result = [0u8; 32];
    result_u.to_big_endian(&mut result);

    // clamp identical to production
    let max_u = U256::from_big_endian(max_target);
    let min_u = U256::from_big_endian(&dom_core::MIN_TARGET_BYTES);
    let rv = U256::from_big_endian(&result);
    if rv > max_u {
        return *max_target;
    }
    if result == [0u8; 32] || rv < min_u {
        return dom_core::MIN_TARGET_BYTES;
    }
    result
}

/// Concrete carry-loss vector reachable from the public API.
///
/// anchor target: top two bytes zero (so it is `<= MAX_TARGET`), index 2 nonzero
/// (so it is `>= MIN_TARGET`). frac index 22 (m = 69558). exponent_seconds = 2970
/// lands exactly on frac index 22 with integer_part == 0 (pure multiply, no shift).
/// time_diff = ideal_time(=120 for height 1) + 2970 = 3090. The production
/// The historical bug dropped the low→high carry in
/// `mul_256_div_radix_checked`, shifting the target by one unit in the high
/// limb. This test locks the repaired behavior to the U512 reference.
#[test]
fn asert_next_target_matches_u512_reference_on_carry_vector() {
    let target: [u8; 32] = [
        0, 0, 25, 78, 136, 179, 78, 254, 73, 203, 96, 240, 45, 211, 164, 117, 103, 231, 178, 85,
        229, 36, 38, 74, 2, 176, 107, 161, 230, 143, 74, 122,
    ];
    let anchor = AsertAnchor {
        timestamp: Timestamp(1_700_000_000),
        height: BlockHeight(0),
        target,
    };
    let block_ts = 1_700_000_000u64 + 3_090;
    let height = 1u64;

    let produced = asert_next_target(&anchor, Timestamp(block_ts), BlockHeight(height))
        .expect("asert must not error on a valid in-bounds vector");

    // Reference uses the public default params (mainnet MAX_COMPACT_TARGET).
    let max_target = dom_pow::CompactTarget(dom_pow::MAX_COMPACT_TARGET)
        .to_target()
        .unwrap();
    let reference = asert_reference(&anchor, block_ts, height, &max_target);

    assert_eq!(
        produced,
        reference,
        "ASERT next-target diverges from full-width U512 reference \
         (carry dropped from low into high limb) — DS-POW-MUL-CARRY / FIX-PoW-001.\n\
         produced[0..16] = {:02x?}\nreference[0..16] = {:02x?}",
        &produced[0..16],
        &reference[0..16]
    );
}

/// Randomized sweep over many in-bounds anchors + pure-frac drifts. Any
/// divergence from the U512 reference is an arithmetic carry bug. This widens
/// the single concrete vector above into a family.
#[test]
fn asert_next_target_matches_u512_reference_sweep() {
    let max_target = dom_pow::CompactTarget(dom_pow::MAX_COMPACT_TARGET)
        .to_target()
        .unwrap();

    let mut seed = 0xC0FF_EE12_3456_789Au64;
    let mut rnd = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    let mut divergences = 0usize;
    let mut first: Option<([u8; 32], u64)> = None;

    for _ in 0..20_000 {
        // in-bounds target: top two bytes zero, byte[2] nonzero.
        let mut t = [0u8; 32];
        t[2] = 1 + (rnd() % 255) as u8;
        for byte in t.iter_mut().skip(3) {
            *byte = (rnd() % 256) as u8;
        }
        // pure-frac drift: pick a frac index 1..=255, derive exp_sec, time_diff.
        let frac = 1 + (rnd() % 255) as i64;
        // exp_sec so that floor(exp_sec*256/HALF) == frac (and < 256 ⇒ integer_part 0)
        let exp_sec = frac * (ASERT_HALF_LIFE as i64) / 256;
        let block_ts = 1_700_000_000i64 + TARGET_SPACING as i64 + exp_sec;

        let anchor = AsertAnchor {
            timestamp: Timestamp(1_700_000_000),
            height: BlockHeight(0),
            target: t,
        };
        let produced = match asert_next_target(&anchor, Timestamp(block_ts as u64), BlockHeight(1))
        {
            Ok(p) => p,
            Err(_) => continue,
        };
        let reference = asert_reference(&anchor, block_ts as u64, 1, &max_target);
        if produced != reference {
            divergences += 1;
            if first.is_none() {
                first = Some((t, block_ts as u64));
            }
        }
    }

    assert_eq!(
        divergences, 0,
        "ASERT diverged from U512 reference in {divergences} cases \
         (carry-loss in 256-bit multiply) — DS-POW-MUL-CARRY / FIX-PoW-001. \
         first: {first:?}"
    );
}
