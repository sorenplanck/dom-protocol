//! dom-shield — dom-pow KAV-negativo + KAV-drift-congelado.
//!
//! KAV-negativo: malformed compact targets and out-of-bounds targets MUST be
//! rejected with an error, not silently accepted or panicked on.
//!   * compact with the sign bit set (0x00800000) → "negative compact target".
//!   * compact exponent > 32 → rejected.
//!   * target > MAX_TARGET (via a too-large compact) → rejected by bounds.
//!   * target < MIN_TARGET (via a too-small-but-nonzero compact) → rejected.
//!
//! KAV-drift-congelado: byte-freeze a few canonical compact→target expansions
//! and a few canonical difficulties. A change in expansion arithmetic or in the
//! difficulty formula is a consensus drift and trips these frozen vectors.

use dom_core::MAX_TARGET_BYTES;
use dom_pow::{target_to_difficulty, CompactTarget, MAX_COMPACT_TARGET};

// ── KAV-negativo ──────────────────────────────────────────────────────────────

#[test]
fn negative_compact_sign_bit_rejected() {
    // exponent 0x1e, mantissa with sign bit set (0x800000 | 0x00ffff).
    let bits = 0x1e80_ffffu32;
    let err = CompactTarget(bits).to_target().unwrap_err();
    assert!(
        format!("{err:?}").to_lowercase().contains("negative"),
        "sign-bit compact must be rejected as negative, got {err:?}"
    );
}

#[test]
fn compact_exponent_above_32_rejected() {
    // exponent 33 (0x21), small nonzero mantissa.
    let bits = 0x2100_0001u32;
    let err = CompactTarget(bits).to_target().unwrap_err();
    assert!(
        format!("{err:?}").contains("33") || format!("{err:?}").to_lowercase().contains("exponent"),
        "exponent > 32 must be rejected, got {err:?}"
    );
}

#[test]
fn target_above_max_rejected_by_bounds() {
    // exponent 32 with full mantissa → expands to a value > MAX_TARGET (2^240).
    // 0x207fffff: exponent 32, mantissa 0x7fffff → bytes near the top of 32-byte
    // space, strictly greater than MAX_TARGET_BYTES (which is 0x0000ff..ff).
    let bits = 0x207f_ffffu32;
    let err = CompactTarget(bits).to_target().unwrap_err();
    assert!(
        format!("{err:?}").contains("MAX"),
        "target above MAX must be rejected by validate_target_bounds, got {err:?}"
    );
}

#[test]
fn target_below_min_rejected_by_bounds() {
    // A tiny nonzero target far below MIN_TARGET (MIN = 0x..ffff at bytes 26,27).
    // exponent 3, mantissa 1 → value = 1 << 0 ... actually places one byte; this
    // is well below MIN_TARGET and must be rejected.
    let bits = 0x0300_0001u32; // exponent 3, mantissa 0x000001
    let err = CompactTarget(bits).to_target().unwrap_err();
    assert!(
        format!("{err:?}").contains("MIN"),
        "target below MIN must be rejected by validate_target_bounds, got {err:?}"
    );
}

#[test]
fn zero_mantissa_returns_all_zero_target_unvalidated() {
    // DOCUMENTED PROBE (FIX-017): mantissa == 0 short-circuits to all-zero target
    // BEFORE validate_target_bounds runs. A zero target is unmineable
    // (hash <= 0 only for the zero hash) and never produced by ASERT
    // (apply_exponent maps zero to MIN_TARGET). Here we pin the observed
    // behaviour: to_target returns Ok([0;32]) and does not error.
    let bits = 0x1e00_0000u32; // exponent 30, mantissa 0
    let out = CompactTarget(bits).to_target().unwrap();
    assert_eq!(
        out, [0u8; 32],
        "zero-mantissa compact returns all-zero target (documented unmineable edge)"
    );
}

// ── KAV-drift-congelado ───────────────────────────────────────────────────────

/// Byte-freeze canonical compact→target expansions. These are consensus values;
/// any change is a hard fork and must trip here.
#[test]
fn frozen_canonical_target_bytes() {
    // MAX_COMPACT_TARGET = 0x1e7fffff (exponent 30, mantissa 0x7fffff).
    // Expansion places: byte at pos 29 = 0xff, pos 28 = 0xff, pos 27 = 0x7f.
    let max_compact = CompactTarget(MAX_COMPACT_TARGET).to_target().unwrap();
    let mut expect_max = [0u8; 32];
    expect_max[31 - 29] = 0xff; // index 2
    expect_max[31 - 28] = 0xff; // index 3
    expect_max[31 - 27] = 0x7f; // index 4
    assert_eq!(
        max_compact, expect_max,
        "MAX_COMPACT_TARGET expansion drifted"
    );

    // DOM mainnet genesis 0x1e00ffff (exponent 30, mantissa 0x00ffff).
    let genesis = CompactTarget(0x1e00_ffff).to_target().unwrap();
    let mut expect_genesis = [0u8; 32];
    expect_genesis[31 - 29] = 0xff; // index 2
    expect_genesis[31 - 28] = 0xff; // index 3
                                    // pos 27 high byte = 0x00, stays zero.
    assert_eq!(genesis, expect_genesis, "genesis compact expansion drifted");

    // Testnet genesis 0x1e2eff7f (exponent 30, mantissa 0x2eff7f).
    let testnet = CompactTarget(0x1e2e_ff7f).to_target().unwrap();
    let mut expect_testnet = [0u8; 32];
    expect_testnet[31 - 29] = 0x7f; // index 2  (mantissa low byte)
    expect_testnet[31 - 28] = 0xff; // index 3
    expect_testnet[31 - 27] = 0x2e; // index 4  (mantissa high byte)
    assert_eq!(testnet, expect_testnet, "testnet compact expansion drifted");
}

/// Byte-freeze canonical difficulties. MAX_TARGET → difficulty 1 (easiest).
#[test]
fn frozen_canonical_difficulties() {
    assert_eq!(
        target_to_difficulty(&MAX_TARGET_BYTES),
        1,
        "MAX_TARGET difficulty must be exactly 1"
    );

    // MAX_TARGET / 2  → difficulty 2.
    let mut half = MAX_TARGET_BYTES;
    // halving a big-endian value: shift right by 1.
    let mut carry = 0u8;
    for byte in half.iter_mut() {
        let new_carry = *byte & 1;
        *byte = (*byte >> 1) | (carry << 7);
        carry = new_carry;
    }
    assert_eq!(
        target_to_difficulty(&half),
        2,
        "MAX_TARGET/2 difficulty must be exactly 2"
    );
}
