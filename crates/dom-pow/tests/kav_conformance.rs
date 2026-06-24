//! dom-shield — dom-pow KAV-conformância (known-answer / spec-conformance).
//!
//! One test per attack vector (Lens A: incorrect-result / non-conformance):
//!
//!   * ASERT_FRAC_TABLE recomputed independently from the SPEC formula
//!     `table[i] = floor(2^(i/256) * 65536)` — NOT read from the code under test.
//!     If the shipped table drifts from the formula the difficulty curve is wrong.
//!   * compact->target conformance against canonical Bitcoin-style nBits vectors.
//!   * hash_meets_target boundary: hash == target passes, target+1 fails.
//!   * ASERT zero-drift external reference: a block exactly on schedule must
//!     return the anchor target byte-for-byte (independent reference: identity).
//!
//! No production code is changed. These tests only observe behaviour.

use dom_core::{BlockHeight, Timestamp, MAX_TARGET_BYTES, TARGET_SPACING};
use dom_pow::{asert_next_target, hash_meets_target, AsertAnchor, CompactTarget, ASERT_FRAC_TABLE};

// ── KAV: ASERT_FRAC_TABLE vs spec formula floor(2^(i/256) * 65536) ────────────

/// Recompute every one of the 256 entries from the SPEC formula and compare to
/// the constant shipped in the crate. The reference is the formula, not the
/// code. `f64::powf` here is fine: this is a test crate (the crate-level
/// `deny(clippy::float_arithmetic)` does not apply to integration tests) and the
/// floored result is exact for all 256 indices (verified independently).
#[test]
#[allow(clippy::float_arithmetic)]
fn asert_frac_table_matches_floor_2_pow_i_over_256_times_65536() {
    for (i, &shipped) in ASERT_FRAC_TABLE.iter().enumerate() {
        let expected = ((2.0f64).powf(i as f64 / 256.0) * 65536.0).floor() as u32;
        assert_eq!(
            shipped, expected,
            "ASERT_FRAC_TABLE[{i}] drifted from floor(2^(i/256)*65536): \
             shipped={shipped}, formula={expected}"
        );
    }
    // Spec anchors documented in the source.
    assert_eq!(ASERT_FRAC_TABLE[0], 65536);
    assert_eq!(ASERT_FRAC_TABLE[128], 92681);
    assert_eq!(ASERT_FRAC_TABLE[255], 130717);
}

/// Independent cross-check of the same table using EXACT integer arithmetic
/// (no float at all): the i-th entry is the largest integer m with
/// m^256 <= 2^(4096 + i) = (65536^256) * 2^i. This rules out any float-rounding
/// coincidence in the float reference above.
///
/// Big integers are base-2^32 limbs stored little-endian in `Vec<u32>`. Each
/// partial product u32*u32 fits in u64; the accumulator carry chain stays in
/// u64 (sum of ~136 such products + carry < 2^64), so nothing overflows.
#[test]
fn asert_frac_table_matches_exact_integer_256th_root() {
    fn big_from_pow2(exp: usize) -> Vec<u32> {
        let words = exp / 32 + 1;
        let mut v = vec![0u32; words];
        v[exp / 32] = 1u32 << (exp % 32);
        v
    }
    fn trim(mut v: Vec<u32>) -> Vec<u32> {
        while v.len() > 1 && *v.last().unwrap() == 0 {
            v.pop();
        }
        v
    }
    fn big_mul(a: &[u32], b: &[u32]) -> Vec<u32> {
        let mut acc = vec![0u64; a.len() + b.len()];
        for (i, &ai) in a.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &bj) in b.iter().enumerate() {
                let cur = acc[i + j] + (ai as u64) * (bj as u64) + carry;
                acc[i + j] = cur & 0xffff_ffff;
                carry = cur >> 32;
            }
            // propagate the leftover carry
            let mut k = i + b.len();
            while carry > 0 {
                let cur = acc[k] + carry;
                acc[k] = cur & 0xffff_ffff;
                carry = cur >> 32;
                k += 1;
            }
        }
        trim(acc.into_iter().map(|x| x as u32).collect())
    }
    fn big_cmp(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
        let la = a.iter().rposition(|&x| x != 0).map(|p| p + 1).unwrap_or(1);
        let lb = b.iter().rposition(|&x| x != 0).map(|p| p + 1).unwrap_or(1);
        if la != lb {
            return la.cmp(&lb);
        }
        for k in (0..la).rev() {
            if a[k] != b[k] {
                return a[k].cmp(&b[k]);
            }
        }
        std::cmp::Ordering::Equal
    }
    fn big_pow256(m: u64) -> Vec<u32> {
        // m fits in 18 bits; store as two 32-bit limbs then square 8 times (^256).
        let mut acc = vec![(m & 0xffff_ffff) as u32, (m >> 32) as u32];
        acc = trim(acc);
        for _ in 0..8 {
            acc = big_mul(&acc, &acc);
        }
        acc
    }
    for (i, &entry) in ASERT_FRAC_TABLE.iter().enumerate() {
        let bound = big_from_pow2(4096 + i); // 2^(4096+i)
        let m = entry as u64;
        let m_pow = big_pow256(m);
        let m1_pow = big_pow256(m + 1);
        assert!(
            big_cmp(&m_pow, &bound) != std::cmp::Ordering::Greater,
            "entry {i}: m^256 must be <= 2^(4096+i)"
        );
        assert!(
            big_cmp(&m1_pow, &bound) == std::cmp::Ordering::Greater,
            "entry {i}: (m+1)^256 must be > 2^(4096+i) (m is not the floor)"
        );
    }
}

// ── KAV: compact -> target conformance (Bitcoin nBits style) ─────────────────

/// Canonical nBits-style expansion vectors. Each vector is
/// (compact bits, expected 32-byte big-endian target) computed from the
/// documented rule: target = mantissa(low 23 bits) << 8*(exponent-3).
#[test]
fn compact_to_target_known_vectors() {
    // Helper: build the expected big-endian target placing the 3 mantissa bytes
    // at byte positions [exponent-1, exponent-2, exponent-3] from the LSB end.
    fn expect(exp: usize, b0: u8, b1: u8, b2: u8) -> [u8; 32] {
        // b0 = mantissa & 0xff (least), b1 = next, b2 = most-significant.
        let mut t = [0u8; 32];
        let w = |t: &mut [u8; 32], pos: usize, v: u8| {
            if pos < 32 {
                t[31 - pos] = v;
            }
        };
        if exp >= 1 {
            w(&mut t, exp - 1, b0);
        }
        if exp >= 2 {
            w(&mut t, exp - 2, b1);
        }
        if exp >= 3 {
            w(&mut t, exp - 3, b2);
        }
        t
    }

    // 0x1d00ffff (classic Bitcoin genesis difficulty-1 style; mantissa 0x00ffff)
    // mantissa low byte 0xff, mid 0xff, high 0x00; exponent 0x1d = 29.
    let v1 = CompactTarget(0x1d00_ffff).to_target().unwrap();
    assert_eq!(v1, expect(29, 0xff, 0xff, 0x00));

    // 0x1e00ffff = DOM mainnet genesis compact (exponent 30).
    let v2 = CompactTarget(0x1e00_ffff).to_target().unwrap();
    assert_eq!(v2, expect(30, 0xff, 0xff, 0x00));

    // 0x1e7fffff = MAX_COMPACT_TARGET (exponent 30, mantissa 0x7fffff).
    let v3 = CompactTarget(0x1e7f_ffff).to_target().unwrap();
    assert_eq!(v3, expect(30, 0xff, 0xff, 0x7f));

    // Mid exponent inside bounds: 0x1c123456 (exponent 28, mantissa 0x123456).
    // mantissa low byte 0x56, mid 0x34, high 0x12.
    let v4 = CompactTarget(0x1c12_3456).to_target().unwrap();
    assert_eq!(v4, expect(28, 0x56, 0x34, 0x12));

    // Smallest in-bounds exponent for a full 3-byte mantissa, 0x0d7fffff
    // (exponent 13). Above MIN_TARGET (~2^80), so it passes validate bounds.
    let v5 = CompactTarget(0x0d7f_ffff).to_target().unwrap();
    assert_eq!(v5, expect(13, 0xff, 0xff, 0x7f));
}

// ── KAV: hash_meets_target boundary ──────────────────────────────────────────

/// hash == target must PASS; target + 1 (one unit harder than the hash) must
/// FAIL. This pins the inclusive `<=` semantics of the boundary.
#[test]
fn hash_meets_target_is_inclusive_at_equality_and_strict_above() {
    // Choose a target safely inside [MIN, MAX] with room to +/- 1.
    let mut target = [0u8; 32];
    target[2] = 0x12;
    target[31] = 0x10;

    // hash == target → passes.
    assert!(
        hash_meets_target(&target, &target),
        "hash == target must satisfy the inclusive boundary"
    );

    // hash = target + 1 (one larger ⇒ does NOT meet target).
    let mut hash_plus_one = target;
    // increment big-endian by 1
    for byte in hash_plus_one.iter_mut().rev() {
        if *byte == 0xff {
            *byte = 0;
        } else {
            *byte += 1;
            break;
        }
    }
    assert!(
        !hash_meets_target(&hash_plus_one, &target),
        "hash == target + 1 must FAIL the target"
    );

    // hash = target - 1 (one smaller ⇒ meets target).
    let mut hash_minus_one = target;
    for byte in hash_minus_one.iter_mut().rev() {
        if *byte == 0 {
            *byte = 0xff;
        } else {
            *byte -= 1;
            break;
        }
    }
    assert!(
        hash_meets_target(&hash_minus_one, &target),
        "hash == target - 1 must meet the target"
    );
}

// ── KAV: ASERT zero-drift identity reference ─────────────────────────────────

/// A block exactly on schedule (time_diff == ideal_time) must produce the anchor
/// target unchanged. Independent reference: the ASERT multiplier is 2^0 = 1, so
/// the output is the identity of the anchor target.
#[test]
fn asert_on_schedule_returns_anchor_target_identity() {
    let anchor = AsertAnchor {
        timestamp: Timestamp(1_700_000_000),
        height: BlockHeight(0),
        target: {
            let mut t = MAX_TARGET_BYTES;
            t[2] = 0x33; // keep strictly inside [MIN, MAX]
            t
        },
    };
    let on_schedule = Timestamp(anchor.timestamp.0 + TARGET_SPACING);
    let out = asert_next_target(&anchor, on_schedule, BlockHeight(1)).unwrap();
    assert_eq!(
        out, anchor.target,
        "exactly-on-schedule block must reproduce the anchor target (multiplier 2^0 = 1)"
    );
}
