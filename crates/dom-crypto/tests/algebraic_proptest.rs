//! F4 — algebraic-invariant property tests (proptest).
//!
//! Strengthens invariants previously covered only by single hand-picked
//! examples into randomized property tests, plus new coverage for the
//! BlindingFactor group law. Scope is ALGEBRAIC SOUNDNESS over VALID inputs —
//! panic/parse surfaces are fuzz territory (F2/F3), not here.
//!
//! A counterexample in #1 (homomorphism) or #2 (balance soundness) is a real
//! INFLATION finding, not a flaky test.

use dom_crypto::hash::{blake2b_256_tagged, DomHasher};
use dom_crypto::keys::SecretKey;
use dom_crypto::pedersen::{
    verify_balance_equation, BlindingFactor, BlindingFactorOrZero, Commitment,
};
use dom_crypto::schnorr::{schnorr_add_public_keys, schnorr_aggregate_sigs, PartialSig};
use proptest::prelude::*;

/// Build a valid BlindingFactor from raw bytes, or None if out of range / zero
/// (negligibly rare for random 32-byte input).
fn bf(bytes: [u8; 32]) -> Option<BlindingFactor> {
    BlindingFactor::from_bytes(bytes).ok()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // ── Property 1a — Pedersen homomorphism (addition) ──────────────────────
    // commit(v1,r1) + commit(v2,r2) == commit(v1+v2, r1+r2). Anti-inflation base.
    #[test]
    fn pedersen_homomorphic_add(
        v1 in 0u64..(1u64 << 40),
        v2 in 0u64..(1u64 << 40),
        b1 in any::<[u8; 32]>(),
        b2 in any::<[u8; 32]>(),
    ) {
        prop_assume!(bf(b1).is_some() && bf(b2).is_some());
        let r1 = bf(b1).unwrap();
        let r2 = bf(b2).unwrap();
        prop_assume!(r1.add(&r2).is_ok()); // r1+r2 == 0 is negligibly rare; skip
        let r_sum = r1.add(&r2).unwrap();

        let lhs = Commitment::commit(v1, &r1)
            .add(&Commitment::commit(v2, &r2))
            .expect("commitment add on valid points");
        let rhs = Commitment::commit(v1 + v2, &r_sum);
        prop_assert_eq!(lhs.as_bytes(), rhs.as_bytes());
    }

    // ── Property 1b — Pedersen homomorphism (subtraction) ───────────────────
    // commit(v1,r1) - commit(v2,r2) == commit(v1-v2, r1-r2), v1>=v2, r1!=r2.
    #[test]
    fn pedersen_homomorphic_sub(
        v2 in 0u64..(1u64 << 40),
        dv in 0u64..(1u64 << 40),
        b1 in any::<[u8; 32]>(),
        b2 in any::<[u8; 32]>(),
    ) {
        prop_assume!(bf(b1).is_some() && bf(b2).is_some());
        prop_assume!(b1 != b2); // distinct valid scalars => r1-r2 != 0
        let r1 = bf(b1).unwrap();
        let r2 = bf(b2).unwrap();
        let v1 = v2 + dv;

        let r_diff = match r1.sub(&r2).expect("bf sub") {
            BlindingFactorOrZero::NonZero(r) => r,
            BlindingFactorOrZero::Zero => return Ok(()), // unreachable for b1!=b2
        };
        let lhs = Commitment::commit(v1, &r1)
            .sub(&Commitment::commit(v2, &r2))
            .expect("commitment sub on valid points");
        let rhs = Commitment::commit(v1 - v2, &r_diff);
        prop_assert_eq!(lhs.as_bytes(), rhs.as_bytes());
    }

    // ── Property 2a — verify_balance_equation COMPLETENESS ──────────────────
    // A correctly-built balanced tx must verify (true).
    #[test]
    fn balance_equation_completeness(
        vo1 in 0u64..(1u64 << 30),
        vo2 in 0u64..(1u64 << 30),
        fee in 0u64..(1u64 << 20),
        b_in in any::<[u8; 32]>(),
        b_o1 in any::<[u8; 32]>(),
        b_o2 in any::<[u8; 32]>(),
    ) {
        prop_assume!(bf(b_in).is_some() && bf(b_o1).is_some() && bf(b_o2).is_some());
        let r_in = bf(b_in).unwrap();
        let r_o1 = bf(b_o1).unwrap();
        let r_o2 = bf(b_o2).unwrap();
        prop_assume!(r_o1.add(&r_o2).is_ok());
        let r_out_sum = r_o1.add(&r_o2).unwrap();
        // excess = (r_o1 + r_o2) - r_in ; skip degenerate zero
        let r_excess = match r_out_sum.sub(&r_in).expect("bf sub") {
            BlindingFactorOrZero::NonZero(r) => r,
            BlindingFactorOrZero::Zero => return Ok(()),
        };

        let v_in = vo1 + vo2 + fee;
        let input = Commitment::commit(v_in, &r_in);
        let o1 = Commitment::commit(vo1, &r_o1);
        let o2 = Commitment::commit(vo2, &r_o2);
        let excess = Commitment::commit(0, &r_excess);

        let ok = verify_balance_equation(&[o1, o2], &[input], &[excess], &[0u8; 32], fee)
            .expect("balance equation");
        prop_assert!(ok, "balanced tx must verify");
    }

    // ── Property 2b — verify_balance_equation SOUNDNESS (anti-inflation) ─────
    // Inflating an output VALUE by delta != 0 (same blinding) MUST be rejected.
    #[test]
    fn balance_equation_rejects_value_inflation(
        vo1 in 0u64..(1u64 << 30),
        vo2 in 0u64..(1u64 << 30),
        fee in 0u64..(1u64 << 20),
        delta in 1u64..100_000u64,
        b_in in any::<[u8; 32]>(),
        b_o1 in any::<[u8; 32]>(),
        b_o2 in any::<[u8; 32]>(),
    ) {
        prop_assume!(bf(b_in).is_some() && bf(b_o1).is_some() && bf(b_o2).is_some());
        let r_in = bf(b_in).unwrap();
        let r_o1 = bf(b_o1).unwrap();
        let r_o2 = bf(b_o2).unwrap();
        prop_assume!(r_o1.add(&r_o2).is_ok());
        let r_out_sum = r_o1.add(&r_o2).unwrap();
        let r_excess = match r_out_sum.sub(&r_in).expect("bf sub") {
            BlindingFactorOrZero::NonZero(r) => r,
            BlindingFactorOrZero::Zero => return Ok(()),
        };

        // The HONEST balance is over (vo1, vo2, fee). We then commit an output
        // whose VALUE is inflated by delta but reuse the honest excess => a real
        // value imbalance of delta*H that must be detected.
        prop_assert!(delta != 0, "generator must produce a real imbalance");
        let v_in = vo1 + vo2 + fee;
        let input = Commitment::commit(v_in, &r_in);
        let o1_bad = Commitment::commit(vo1 + delta, &r_o1); // inflated value, same blinding
        let o2 = Commitment::commit(vo2, &r_o2);
        let excess = Commitment::commit(0, &r_excess);

        let ok = verify_balance_equation(&[o1_bad, o2], &[input], &[excess], &[0u8; 32], fee)
            .expect("balance equation");
        prop_assert!(!ok, "output inflated by delta={} must be rejected", delta);
    }

    // ── Property 3a — schnorr_add_public_keys commutativity ─────────────────
    // add(A,B) == add(B,A) (point addition is commutative).
    #[test]
    fn schnorr_add_pubkeys_commutes(
        s1 in any::<[u8; 32]>(),
        s2 in any::<[u8; 32]>(),
    ) {
        prop_assume!(SecretKey::from_bytes(&s1).is_ok() && SecretKey::from_bytes(&s2).is_ok());
        let a = SecretKey::from_bytes(&s1).unwrap().public_key();
        let b = SecretKey::from_bytes(&s2).unwrap().public_key();
        let ab = schnorr_add_public_keys(&[a.clone(), b.clone()]);
        let ba = schnorr_add_public_keys(&[b, a]);
        prop_assume!(ab.is_ok() && ba.is_ok()); // skip A == -B (sum = infinity)
        prop_assert_eq!(ab.unwrap().to_compressed_bytes(), ba.unwrap().to_compressed_bytes());
    }

    // ── Property 3b — schnorr_aggregate_sigs s-sum commutativity ────────────
    // aggregate([p1,p2], R) == aggregate([p2,p1], R) (scalar sum commutes).
    #[test]
    fn schnorr_aggregate_s_sum_commutes(
        s1 in any::<[u8; 32]>(),
        s2 in any::<[u8; 32]>(),
        rk in any::<[u8; 32]>(),
    ) {
        prop_assume!(PartialSig::from_bytes(&s1).is_ok() && PartialSig::from_bytes(&s2).is_ok());
        prop_assume!(SecretKey::from_bytes(&rk).is_ok());
        let p1 = PartialSig::from_bytes(&s1).unwrap();
        let p2 = PartialSig::from_bytes(&s2).unwrap();
        let agg_r = SecretKey::from_bytes(&rk).unwrap().public_key();
        let s12 = schnorr_aggregate_sigs(&[p1.clone(), p2.clone()], &agg_r);
        let s21 = schnorr_aggregate_sigs(&[p2, p1], &agg_r);
        prop_assume!(s12.is_ok() && s21.is_ok()); // skip if s-sum == 0 / >= n
        prop_assert_eq!(s12.unwrap().to_bytes(), s21.unwrap().to_bytes());
    }

    // ── Property 4a — BlindingFactor group law: (r1+r2)-r2 == r1 ─────────────
    #[test]
    fn blinding_add_then_sub_recovers(
        b1 in any::<[u8; 32]>(),
        b2 in any::<[u8; 32]>(),
    ) {
        prop_assume!(bf(b1).is_some() && bf(b2).is_some());
        let r1 = bf(b1).unwrap();
        let r2 = bf(b2).unwrap();
        prop_assume!(r1.add(&r2).is_ok()); // r1+r2 == 0 skip
        let sum = r1.add(&r2).unwrap();
        let back = match sum.sub(&r2).expect("bf sub") {
            BlindingFactorOrZero::NonZero(r) => r,
            BlindingFactorOrZero::Zero => return Ok(()), // (r1+r2)-r2==r1!=0, unreachable
        };
        prop_assert_eq!(back.as_bytes(), r1.as_bytes());
    }

    // ── Property 4b — sub_nonzero rejects a zero difference (r - r) ──────────
    #[test]
    fn sub_nonzero_rejects_zero_difference(b in any::<[u8; 32]>()) {
        prop_assume!(bf(b).is_some());
        let r = bf(b).unwrap();
        prop_assert!(r.sub_nonzero(&r).is_err(), "r - r == 0 must be rejected");
    }

    // ── Property 5 — DomHasher incremental == one-shot, any split ───────────
    #[test]
    fn domhasher_incremental_matches_oneshot(
        tag in "[ -~]{0,40}",
        data in proptest::collection::vec(any::<u8>(), 0..512),
        split in 0usize..512,
    ) {
        let split = split.min(data.len());
        let oneshot = blake2b_256_tagged(&tag, &data);
        let mut h = DomHasher::new(&tag);
        h.update(&data[..split]);
        h.update(&data[split..]);
        let incremental = h.finalize();
        prop_assert_eq!(oneshot, incremental);
    }

    // ── Property 6 — blake2b_256_tagged injectivity / domain separation ─────
    // Distinct (tag,data) MUST give distinct digests (length-prefixed tag means
    // no boundary ambiguity, e.g. ("ab","") vs ("a","b")). A collision here is a
    // domain-separation regression.
    #[test]
    fn tagged_hash_domain_separation(
        tag1 in "[ -~]{0,32}",
        data1 in proptest::collection::vec(any::<u8>(), 0..128),
        tag2 in "[ -~]{0,32}",
        data2 in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        prop_assume!(tag1.as_bytes() != tag2.as_bytes() || data1 != data2);
        let h1 = blake2b_256_tagged(&tag1, &data1);
        let h2 = blake2b_256_tagged(&tag2, &data2);
        prop_assert_ne!(h1, h2);
    }
}
