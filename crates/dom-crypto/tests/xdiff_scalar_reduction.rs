//! XDIFF — k256 vs secp256k1 scalar handling at the curve-order boundary.
//!
//! dom-crypto links TWO independent secp256k1 stacks (k256 pure-Rust; secp256k1
//! C bindings). differential_crypto.rs already pins that they agree on pubkey
//! derivation and Pedersen point math. The gap this file fills: agreement on
//! SCALAR ADMISSIBILITY at the exact order boundary {0, n-1, n, n+1}. If the two
//! libraries disagreed on whether `n` is a valid scalar (one reducing mod n, the
//! other rejecting), a value sitting on the boundary could be accepted by the
//! signing path and rejected by a verifier — a consensus split. Both stacks MUST
//! treat (0, n) as the valid open interval, with identical verdicts.
//!
//! n is taken from the secp256k1 library constant CURVE_ORDER (authoritative,
//! big-endian) — not memorized.

use k256::elliptic_curve::PrimeField;
use secp256k1::constants::CURVE_ORDER; // authoritative n, big-endian

/// Does k256 accept these big-endian bytes as a canonical Scalar in [0, n)?
/// (k256's Scalar::from_repr reduces nothing — it returns None for >= n.)
fn k256_accepts(be: &[u8; 32]) -> bool {
    let fb = k256::FieldBytes::from(*be);
    bool::from(k256::Scalar::from_repr(fb).is_some())
}

/// Does the secp256k1 C library accept these bytes as a SecretKey (0 < k < n)?
fn secp_accepts_secretkey(be: &[u8; 32]) -> bool {
    secp256k1::SecretKey::from_slice(be).is_ok()
}

fn be_increment(mut b: [u8; 32]) -> [u8; 32] {
    for i in (0..32).rev() {
        let (v, carry) = b[i].overflowing_add(1);
        b[i] = v;
        if !carry {
            return b;
        }
    }
    b
}

fn be_decrement(mut b: [u8; 32]) -> [u8; 32] {
    for i in (0..32).rev() {
        let (v, borrow) = b[i].overflowing_sub(1);
        b[i] = v;
        if !borrow {
            return b;
        }
    }
    b
}

/// k256 admits exactly [0, n): 0 and n-1 in; n and n+1 out. (k256 includes 0
/// because a field-repr scalar may legitimately be zero; the rejection of 0 for
/// secret material is a higher-layer policy, tested separately in
/// infinity_rejection.rs / negative_kav.rs.)
#[test]
fn k256_scalar_boundary_is_exactly_zero_to_n() {
    let n = CURVE_ORDER;
    let n_minus_1 = be_decrement(n);
    let n_plus_1 = be_increment(n);

    assert!(
        k256_accepts(&[0u8; 32]),
        "k256 must accept 0 as a canonical scalar repr"
    );
    assert!(k256_accepts(&n_minus_1), "k256 must accept n-1");
    assert!(!k256_accepts(&n), "k256 must REJECT n (not reduce it to 0)");
    assert!(
        !k256_accepts(&n_plus_1),
        "k256 must REJECT n+1 (no silent reduction)"
    );
}

/// secp256k1 C admits exactly (0, n): rejects 0 and n; accepts n-1 and 1.
#[test]
fn secp256k1_secretkey_boundary_is_exactly_open_interval() {
    let n = CURVE_ORDER;
    let n_minus_1 = be_decrement(n);
    let n_plus_1 = be_increment(n);
    let mut one = [0u8; 32];
    one[31] = 1;

    assert!(!secp_accepts_secretkey(&[0u8; 32]), "secp must reject 0");
    assert!(secp_accepts_secretkey(&one), "secp must accept 1");
    assert!(secp_accepts_secretkey(&n_minus_1), "secp must accept n-1");
    assert!(!secp_accepts_secretkey(&n), "secp must reject n");
    assert!(!secp_accepts_secretkey(&n_plus_1), "secp must reject n+1");
}

/// The cross-impl agreement that actually matters for consensus: for every
/// boundary point, k256 and secp256k1 agree on admissibility over the COMMON
/// valid domain (0, n). The only intentional difference is the value 0, which
/// k256 admits as a field repr but secp256k1 rejects as secret material — so 0
/// is excluded from the agreement set and asserted separately above. Neither
/// library may SILENTLY REDUCE a boundary value: n and n+1 must be rejected by
/// BOTH, never wrapped to a small in-range scalar.
#[test]
fn k256_and_secp256k1_agree_on_open_interval_boundary() {
    let n = CURVE_ORDER;
    let cases: &[([u8; 32], &str)] = &[
        (
            {
                let mut b = [0u8; 32];
                b[31] = 1;
                b
            },
            "1",
        ),
        (be_decrement(n), "n-1"),
        (n, "n"),
        (be_increment(n), "n+1"),
    ];
    for (bytes, label) in cases {
        let k = k256_accepts(bytes);
        let s = secp_accepts_secretkey(bytes);
        assert_eq!(
            k, s,
            "k256 vs secp256k1 DISAGREE on scalar admissibility at {label}: \
             k256={k} secp256k1={s} — a boundary value accepted by one stack and \
             rejected by the other is a consensus-split precursor"
        );
    }
}
