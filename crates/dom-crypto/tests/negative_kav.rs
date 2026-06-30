//! F6 — negative known-answer vectors (rejection contract).
//!
//! Proves DISHONEST inputs are REJECTED (Err / false), complementing F4
//! (honest inputs work). Scope here = the 3 gaps the recon found NOT already
//! covered by tests/infinity_rejection.rs + tests/bulletproof*_adversarial.rs:
//!   (A) bp2 verify-time value ceiling  [probe in bulletproof_bp.rs, now GREEN]
//!   (B) Scalar (keys.rs) range + LE/BE non-confusion
//!   (C) PartialSig::from_bytes range/length
//! Everything else (PublicKey/SecretKey/BlindingFactor/Commitment/SchnorrSignature
//! negatives, borromean R-07 F-01/F-02 verify-time, prove-time caps, mutation/
//! cross/garbage) is ALREADY covered — not duplicated here.

use dom_crypto::keys::{Scalar, SecretKey};
use dom_crypto::schnorr::PartialSig;
use secp256k1::constants::CURVE_ORDER; // authoritative n (big-endian), from the library

/// Big-endian increment by 1 (for n+1).
fn be_increment(mut b: [u8; 32]) -> [u8; 32] {
    for i in (0..32).rev() {
        let (v, carry) = b[i].overflowing_add(1);
        b[i] = v;
        if !carry {
            break;
        }
    }
    b
}

// ── (A) bp2 verify-time ceiling — lives as an INTERNAL unit test ─────────────
// The (A) probe is NOT an integration test: it needs the private `prove_raw` to
// mint a >2^52 Bulletproof (the public prove API caps at MAX_PROVABLE_VALUE). It
// lives as a #[cfg(test)] unit test inside bulletproof_bp.rs:
//   bulletproof_bp::tests::probe_bp2_verify_rejects_value_above_max_provable
// It EXECUTED and CONFIRMED inflation: bp_verify returns Ok(true) for value=2^52
// (FIX-014, dom-shield reports/FIX-QUEUE.md). That test asserts the correct
// defense and is now GREEN. FIX-014 was RESOLVED in e5f2075 (bounded aggregate
// bp2 proof closes the inflation path; native-revalidated 2026-06-29).

// ── (B) Scalar range rejection (keys.rs:26/37) ──────────────────────────────
#[test]
fn scalar_rejects_zero_and_out_of_range() {
    let n = CURVE_ORDER; // big-endian
    let n_plus_1 = be_increment(n);

    // big-endian parser
    assert!(
        Scalar::from_be_bytes([0u8; 32]).is_err(),
        "BE zero must reject"
    );
    assert!(Scalar::from_be_bytes(n).is_err(), "BE == n must reject");
    assert!(
        Scalar::from_be_bytes(n_plus_1).is_err(),
        "BE n+1 must reject"
    );
    assert!(
        Scalar::from_be_bytes([0xFFu8; 32]).is_err(),
        "BE all-FF must reject"
    );

    // little-endian parser: zero and all-FF reject; n reversed to LE is also >= n
    assert!(
        Scalar::from_le_bytes([0u8; 32]).is_err(),
        "LE zero must reject"
    );
    assert!(
        Scalar::from_le_bytes([0xFFu8; 32]).is_err(),
        "LE all-FF must reject"
    );
    let mut n_le = n;
    n_le.reverse();
    assert!(Scalar::from_le_bytes(n_le).is_err(), "LE == n must reject");

    // sanity: n-1 (BE) is the largest valid scalar -> accepted.
    let mut n_minus_1 = n;
    for i in (0..32).rev() {
        let (v, borrow) = n_minus_1[i].overflowing_sub(1);
        n_minus_1[i] = v;
        if !borrow {
            break;
        }
    }
    assert!(
        Scalar::from_be_bytes(n_minus_1).is_ok(),
        "BE n-1 must be accepted"
    );
}

#[test]
fn scalar_le_be_not_conflated() {
    // Non-palindromic bytes: as LE this is 1; as BE this is 2^248. Different
    // scalars => the parser must not conflate endianness (malleability guard).
    let mut b = [0u8; 32];
    b[0] = 1;
    let le = Scalar::from_le_bytes(b).expect("valid LE scalar");
    let be = Scalar::from_be_bytes(b).expect("valid BE scalar");
    assert_ne!(
        le.as_le_bytes(),
        be.as_le_bytes(),
        "LE and BE interpretations of the same bytes must yield different scalars"
    );
}

#[test]
fn secretkey_rejects_wrong_length_and_zero() {
    assert!(
        SecretKey::from_bytes(&[1u8; 31]).is_err(),
        "31 bytes must reject"
    );
    assert!(
        SecretKey::from_bytes(&[1u8; 33]).is_err(),
        "33 bytes must reject"
    );
    assert!(
        SecretKey::from_bytes(&[0u8; 32]).is_err(),
        "zero must reject"
    );
}

// ── (C) PartialSig range/length rejection (schnorr.rs:33) ────────────────────
#[test]
fn partialsig_rejects_zero_oversize_and_wrong_length() {
    // s bytes are big-endian; PartialSig requires 0 < s < n and exactly 32 bytes.
    assert!(
        PartialSig::from_bytes(&[0u8; 32]).is_err(),
        "s = 0 must reject"
    );
    assert!(
        PartialSig::from_bytes(&CURVE_ORDER).is_err(),
        "s = n must reject"
    );
    assert!(
        PartialSig::from_bytes(&be_increment(CURVE_ORDER)).is_err(),
        "s = n+1 must reject"
    );
    assert!(
        PartialSig::from_bytes(&[0xFFu8; 32]).is_err(),
        "s all-FF (>= n) must reject"
    );
    assert!(
        PartialSig::from_bytes(&[1u8; 31]).is_err(),
        "31 bytes must reject"
    );
    assert!(
        PartialSig::from_bytes(&[1u8; 33]).is_err(),
        "33 bytes must reject"
    );
}
