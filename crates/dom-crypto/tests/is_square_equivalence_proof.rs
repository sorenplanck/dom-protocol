//! Machine-checkable companion to
//! `docs/DOM_RFC_0009_is_square_equivalence_proof.md` (AUDIT-002).
//!
//! TEST-ONLY. No production code. This computationally verifies the DERIVED
//! facts the proof rests on, so the proof is reproducible, not just readable:
//!
//!   (a) the k256 / libsecp square-root addition chain builds the exponent
//!       (p+1)/4 EXACTLY — computed by replaying the chain in the exponent
//!       domain, not by restating the prose;
//!   (b) (p+1) % 4 == 0  (p ≡ 3 mod 4);
//!   (c) (−1)^((p−1)/2) ≡ p−1  (−1 is a quadratic NON-residue);
//!   (d) the real DOM oracle isq_DOM (k256 FieldElement::sqrt(a).is_some())
//!       agrees with Euler's criterion [a^((p−1)/2) == 1] on a structured set
//!       including the edge values 0, 1, p−1, (p−1)/2, known QRs and QNRs.
//!
//! Exact integers use `U512` (every intermediate here is < 2^512, so the
//! arithmetic is exact — no modular wrap). The oracle uses the actual
//! `k256::FieldElement`, the same type the production bridge uses.

use k256::FieldElement;
use primitive_types::U512;

/// secp256k1 field prime p = 2^256 − 2^32 − 977, as an exact U512.
fn prime() -> U512 {
    (U512::one() << 256) - (U512::one() << 32) - U512::from(977u64)
}

/// `e << k` in the exponent domain (k squarings multiply the exponent by 2^k).
fn pow2k(e: U512, k: u32) -> U512 {
    e << k
}

/// Replay the secp256k1 square-root addition chain in the EXPONENT domain and
/// return (final exponent, per-block exponents) — mirrors k256 field.rs:222-235
/// and libsecp field_impl.h:56-128 operation-for-operation.
fn chain_exponent() -> (U512, Vec<(u32, U512)>) {
    let one = U512::one();
    let x2 = pow2k(one, 1) + one; // 2^2 − 1
    let x3 = pow2k(x2, 1) + one; // 2^3 − 1
    let x6 = pow2k(x3, 3) + x3; // 2^6 − 1
    let x9 = pow2k(x6, 3) + x3; // 2^9 − 1
    let x11 = pow2k(x9, 2) + x2; // 2^11 − 1
    let x22 = pow2k(x11, 11) + x11; // 2^22 − 1
    let x44 = pow2k(x22, 22) + x22;
    let x88 = pow2k(x44, 44) + x44;
    let x176 = pow2k(x88, 88) + x88;
    let x220 = pow2k(x176, 44) + x44;
    let x223 = pow2k(x220, 3) + x3; // 2^223 − 1
                                    // final assembly: x223.pow2k(23).mul(x22).pow2k(6).mul(x2).pow2k(2)
    let res = pow2k(pow2k(pow2k(x223, 23) + x22, 6) + x2, 2);
    let blocks = vec![
        (2u32, x2),
        (3, x3),
        (6, x6),
        (9, x9),
        (11, x11),
        (22, x22),
        (44, x44),
        (88, x88),
        (176, x176),
        (220, x220),
        (223, x223),
    ];
    (res, blocks)
}

/// (a) The addition chain builds exactly (p+1)/4, and each block xN == 2^N − 1.
#[test]
fn addition_chain_builds_p_plus_1_over_4() {
    let p = prime();
    let (res, blocks) = chain_exponent();

    for (n, val) in &blocks {
        let expected = (U512::one() << *n) - U512::one(); // 2^N − 1
        assert_eq!(*val, expected, "block x{n} must equal 2^{n} − 1");
    }

    assert_eq!(
        (p + U512::one()) % U512::from(4u64),
        U512::zero(),
        "(p+1) must be divisible by 4"
    );
    let target = (p + U512::one()) >> 2; // (p+1)/4
    assert_eq!(
        res, target,
        "addition-chain exponent must equal (p+1)/4 EXACTLY"
    );
}

/// (b) p ≡ 3 (mod 4).
#[test]
fn prime_is_three_mod_four() {
    let p = prime();
    assert_eq!(
        p % U512::from(4u64),
        U512::from(3u64),
        "p must be ≡ 3 (mod 4)"
    );
}

// ---- exact modular arithmetic over U512 (all operands < p < 2^256, so a*b <
// 2^512 fits U512 without wrapping) ----

fn modmul(a: U512, b: U512, p: U512) -> U512 {
    (a % p) * (b % p) % p
}

fn modpow(mut base: U512, mut exp: U512, p: U512) -> U512 {
    let mut acc = U512::one();
    base %= p;
    while !exp.is_zero() {
        if exp.bit(0) {
            acc = modmul(acc, base, p);
        }
        base = modmul(base, base, p);
        exp >>= 1;
    }
    acc
}

/// (c) (−1)^((p−1)/2) ≡ p−1 (mod p): −1 is a quadratic NON-residue (needs p≡3 mod4).
#[test]
fn minus_one_is_a_non_residue() {
    let p = prime();
    let exp = (p - U512::one()) >> 1; // (p−1)/2
    let minus_one = p - U512::one(); // ≡ −1 (mod p)
    let legendre = modpow(minus_one, exp, p);
    assert_eq!(
        legendre, minus_one,
        "(−1)^((p−1)/2) must be ≡ p−1 (i.e. −1), proving −1 is a QNR"
    );
}

/// Convert an exact field value a ∈ [0, p) into the real k256 FieldElement and
/// return isq_DOM(a) = (k256 sqrt is Some), i.e. exactly what
/// `zkp_prefix_from_y` computes in production.
fn isq_dom(a: U512) -> bool {
    let mut buf = [0u8; 64];
    a.to_big_endian(&mut buf);
    let be32: [u8; 32] = buf[32..].try_into().unwrap(); // low 256 bits, big-endian
    let fe = Option::<FieldElement>::from(FieldElement::from_bytes(&be32.into()))
        .expect("a < p is a valid field element");
    bool::from(fe.sqrt().is_some())
}

/// Euler's criterion QR test: a is a (nonzero) square iff a^((p−1)/2) == 1; a==0
/// is a square by convention. Returns whether a is a square in GF(p).
fn euler_is_square(a: U512, p: U512) -> bool {
    if a.is_zero() {
        return true;
    }
    modpow(a, (p - U512::one()) >> 1, p) == U512::one()
}

/// (d) isq_DOM (real k256 oracle) agrees with Euler's criterion on a structured
/// set: edge values, known QRs (b²), and the QNRs that arise. Also asserts the
/// set actually exercises BOTH branches (≥1 square and ≥1 non-square).
#[test]
fn isq_dom_agrees_with_euler_on_structured_set() {
    let p = prime();
    let half = (p - U512::one()) >> 1; // (p−1)/2

    let mut cases: Vec<U512> = vec![
        U512::zero(),
        U512::one(),
        U512::from(2u64),
        U512::from(3u64),
        U512::from(4u64),
        U512::from(7u64),
        p - U512::one(), // ≡ −1 (a QNR by test (c))
        half,            // (p−1)/2
        U512::from(123_456_789u64),
    ];
    // Known quadratic residues: b² mod p for small b are squares by construction.
    for b in 2u64..40 {
        let bb = U512::from(b);
        cases.push(modmul(bb, bb, p));
    }

    let mut squares = 0usize;
    let mut nonsquares = 0usize;
    for &a in &cases {
        let dom = isq_dom(a);
        let euler = euler_is_square(a, p);
        assert_eq!(
            dom, euler,
            "isq_DOM must equal Euler's QR predicate for a = {a:#x}"
        );
        if euler {
            squares += 1;
        } else {
            nonsquares += 1;
        }
    }
    // −1 (= p−1) is a QNR, so the non-square branch is necessarily exercised;
    // assert both branches were hit so the test can never vacuously pass.
    assert!(
        squares > 0,
        "structured set must contain quadratic residues"
    );
    assert!(
        nonsquares > 0,
        "structured set must contain non-residues (e.g. −1) — both branches tested"
    );

    // Pin the −1 case explicitly: −1 is a non-square for BOTH oracles.
    assert!(!isq_dom(p - U512::one()), "isq_DOM(−1) must be false (QNR)");
    assert!(
        !euler_is_square(p - U512::one(), p),
        "Euler(−1) must be false (QNR)"
    );
}
