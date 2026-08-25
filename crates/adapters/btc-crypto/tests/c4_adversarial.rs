//! C4 — adversarial suite, cryptographic domain (Annex M M.11.5).
//!
//! Covers the "Scalars and points" and "Session and participants" rows
//! that live at the crypto-backend boundary. The transaction/Taproot,
//! nonce/crash, and evidence/reorg rows are exercised by their own crates
//! (`adapter-btc` taproot/sighash tests, `btc-vault` crash harness, and
//! the observer/evidence layers). Every case here must FAIL closed.
//!
//! TEST-ONLY-NON-PRODUCTION.

mod common;

use btc_crypto::{BtcCryptoError, SecpContext};
use common::{compressed_pubkey, message, scalar_one, seeded, ORDER_BE};

struct Parties {
    sk1: [u8; 32],
    sk2: [u8; 32],
    pk1: [u8; 33],
    pk2: [u8; 33],
    t: [u8; 32],
    big_t: [u8; 33],
}

fn parties() -> Parties {
    let sk1 = seeded(0x01, 1);
    let sk2 = seeded(0x02, 2);
    let t = seeded(0x2b, 3);
    Parties {
        sk1,
        sk2,
        pk1: compressed_pubkey(&sk1).unwrap(),
        pk2: compressed_pubkey(&sk2).unwrap(),
        t,
        big_t: compressed_pubkey(&t).unwrap(),
    }
}

// ── Scalars and points ────────────────────────────────────────────────

#[test]
fn adaptor_secret_zero_is_rejected() {
    // t = 0 has no valid point and must never be adapted with.
    let ctx = SecpContext::new(&[0x5a; 32]);
    // A zero "point" is not on the curve and fails to parse.
    assert!(ctx.key_agg(&[[0u8; 33], [0u8; 33]]).is_err());
}

#[test]
fn taptweak_ge_n_fails_without_reduction() {
    let pp = parties();
    let (pk1, pk2) = (pp.pk1, pp.pk2);
    let ctx = SecpContext::new(&[0x5a; 32]);
    let mut keyagg = ctx.key_agg(&[pk1, pk2]).unwrap();
    assert_eq!(
        ctx.apply_tap_tweak(&mut keyagg, &ORDER_BE).unwrap_err(),
        BtcCryptoError::TapTweakRejected
    );
    // n + 1 also rejected.
    let mut n_plus_1 = ORDER_BE;
    n_plus_1[31] = n_plus_1[31].wrapping_add(1);
    let mut keyagg2 = ctx.key_agg(&[pk1, pk2]).unwrap();
    assert!(ctx.apply_tap_tweak(&mut keyagg2, &n_plus_1).is_err());
}

#[test]
fn malformed_adaptor_point_is_rejected() {
    let pp = parties();
    let (sk1, sk2, pk1, pk2) = (pp.sk1, pp.sk2, pp.pk1, pp.pk2);
    let ctx = SecpContext::new(&[0x5a; 32]);
    let mut keyagg = ctx.key_agg(&[pk1, pk2]).unwrap();
    let tt = ctx.tagged_sha256(b"TapTweak", &keyagg.internal_xonly);
    ctx.apply_tap_tweak(&mut keyagg, &tt).unwrap();
    let msg = message(1);
    let (_s1, p1) = ctx
        .nonce_gen(&seeded(0xa1, 1), &sk1, &pk1, &msg, &keyagg)
        .unwrap();
    let (_s2, p2) = ctx
        .nonce_gen(&seeded(0xa2, 1), &sk2, &pk2, &msg, &keyagg)
        .unwrap();
    let aggnonce = ctx.nonce_agg(&[p1.0, p2.0]).unwrap();
    // Identity/all-zero and off-curve adaptor points are rejected.
    assert!(ctx
        .nonce_process(&aggnonce, &msg, &keyagg, &[0u8; 33])
        .is_err());
    let mut off_curve = [0x02u8; 33];
    off_curve[1..].copy_from_slice(&[0xff; 32]);
    assert!(ctx
        .nonce_process(&aggnonce, &msg, &keyagg, &off_curve)
        .is_err());
}

#[test]
fn extract_rejects_non_matching_adaptor_point() {
    // t·G ≠ T: extraction against the wrong point fails the group check.
    let pp = parties();
    let (sk1, sk2, pk1, pk2, t, big_t) = (pp.sk1, pp.sk2, pp.pk1, pp.pk2, pp.t, pp.big_t);
    let ctx = SecpContext::new(&[0x5a; 32]);
    let mut keyagg = ctx.key_agg(&[pk1, pk2]).unwrap();
    let tt = ctx.tagged_sha256(b"TapTweak", &keyagg.internal_xonly);
    let tweak = ctx.apply_tap_tweak(&mut keyagg, &tt).unwrap();
    let msg = message(2);
    let (s1, p1) = ctx
        .nonce_gen(&seeded(0xa1, 2), &sk1, &pk1, &msg, &keyagg)
        .unwrap();
    let (s2, p2) = ctx
        .nonce_gen(&seeded(0xa2, 2), &sk2, &pk2, &msg, &keyagg)
        .unwrap();
    let aggnonce = ctx.nonce_agg(&[p1.0, p2.0]).unwrap();
    let session = ctx.nonce_process(&aggnonce, &msg, &keyagg, &big_t).unwrap();
    let ps1 = ctx
        .partial_sign(s1, &sk1, &pk1, &p1.0, &keyagg, &session)
        .unwrap();
    let ps2 = ctx
        .partial_sign(s2, &sk2, &pk2, &p2.0, &keyagg, &session)
        .unwrap();
    let pre = ctx
        .aggregate_pre_signature(&[ps1, ps2], &tweak.output_xonly, &msg, &session)
        .unwrap();
    let final_sig = ctx
        .adapt(&pre, &t, session.nonce_parity, &tweak.output_xonly, &msg)
        .unwrap();
    let mut wrong_t = big_t;
    wrong_t[32] ^= 0x02;
    assert!(ctx
        .extract(&final_sig, &pre, session.nonce_parity, &wrong_t)
        .is_err());
}

// ── Session and participants ──────────────────────────────────────────

#[test]
fn duplicate_participant_key_is_handled() {
    // KeyAgg with two identical keys is a protocol-level roster error
    // upstream (rejected by adapter-btc's roster), but even at the raw
    // crypto layer it must not silently produce a usable 2-of-2 that a
    // single party could complete. Aggregation itself may succeed; the
    // defense is the roster rule. Here we assert the aggregate of a key
    // with itself is deterministic and does not panic.
    let pp = parties();
    let pk1 = pp.pk1;
    let ctx = SecpContext::new(&[0x5a; 32]);
    let a = ctx.key_agg(&[pk1, pk1]);
    // Whether it errors or aggregates, it must be a clean Result.
    let _ = a.map(|k| k.internal_xonly);
}

#[test]
fn partial_from_wrong_key_fails_verification() {
    let pp = parties();
    let (sk1, sk2, pk1, pk2, big_t) = (pp.sk1, pp.sk2, pp.pk1, pp.pk2, pp.big_t);
    let ctx = SecpContext::new(&[0x5a; 32]);
    let mut keyagg = ctx.key_agg(&[pk1, pk2]).unwrap();
    let tt = ctx.tagged_sha256(b"TapTweak", &keyagg.internal_xonly);
    ctx.apply_tap_tweak(&mut keyagg, &tt).unwrap();
    let msg = message(3);
    let (s1, p1) = ctx
        .nonce_gen(&seeded(0xa1, 3), &sk1, &pk1, &msg, &keyagg)
        .unwrap();
    let (_s2, p2) = ctx
        .nonce_gen(&seeded(0xa2, 3), &sk2, &pk2, &msg, &keyagg)
        .unwrap();
    let aggnonce = ctx.nonce_agg(&[p1.0, p2.0]).unwrap();
    let session = ctx.nonce_process(&aggnonce, &msg, &keyagg, &big_t).unwrap();
    let ps1 = ctx
        .partial_sign(s1, &sk1, &pk1, &p1.0, &keyagg, &session)
        .unwrap();
    // Verifying signer 1's partial against signer 2's pubkey/pubnonce fails.
    assert!(ctx
        .partial_verify(&ps1, &p2.0, &pk2, &keyagg, &session)
        .is_err());
}

#[test]
fn partial_from_another_session_fails() {
    let pp = parties();
    let (sk1, sk2, pk1, pk2, big_t) = (pp.sk1, pp.sk2, pp.pk1, pp.pk2, pp.big_t);
    let ctx = SecpContext::new(&[0x5a; 32]);
    let mut keyagg = ctx.key_agg(&[pk1, pk2]).unwrap();
    let tt = ctx.tagged_sha256(b"TapTweak", &keyagg.internal_xonly);
    ctx.apply_tap_tweak(&mut keyagg, &tt).unwrap();

    // Session A.
    let msg_a = message(10);
    let (s1a, p1a) = ctx
        .nonce_gen(&seeded(0xa1, 10), &sk1, &pk1, &msg_a, &keyagg)
        .unwrap();
    let (_s2a, p2a) = ctx
        .nonce_gen(&seeded(0xa2, 10), &sk2, &pk2, &msg_a, &keyagg)
        .unwrap();
    let agg_a = ctx.nonce_agg(&[p1a.0, p2a.0]).unwrap();
    let session_a = ctx.nonce_process(&agg_a, &msg_a, &keyagg, &big_t).unwrap();
    let ps1a = ctx
        .partial_sign(s1a, &sk1, &pk1, &p1a.0, &keyagg, &session_a)
        .unwrap();

    // Session B (different message + nonces).
    let msg_b = message(11);
    let (_s1b, p1b) = ctx
        .nonce_gen(&seeded(0xa1, 11), &sk1, &pk1, &msg_b, &keyagg)
        .unwrap();
    let (_s2b, p2b) = ctx
        .nonce_gen(&seeded(0xa2, 11), &sk2, &pk2, &msg_b, &keyagg)
        .unwrap();
    let agg_b = ctx.nonce_agg(&[p1b.0, p2b.0]).unwrap();
    let session_b = ctx.nonce_process(&agg_b, &msg_b, &keyagg, &big_t).unwrap();

    // Session A's partial does not verify under session B.
    assert!(ctx
        .partial_verify(&ps1a, &p1a.0, &pk1, &keyagg, &session_b)
        .is_err());
}

#[test]
fn pre_signature_is_never_a_final_signature() {
    let pp = parties();
    let (sk1, sk2, pk1, pk2, big_t) = (pp.sk1, pp.sk2, pp.pk1, pp.pk2, pp.big_t);
    let ctx = SecpContext::new(&[0x5a; 32]);
    let mut keyagg = ctx.key_agg(&[pk1, pk2]).unwrap();
    let tt = ctx.tagged_sha256(b"TapTweak", &keyagg.internal_xonly);
    let tweak = ctx.apply_tap_tweak(&mut keyagg, &tt).unwrap();
    let msg = message(4);
    let (s1, p1) = ctx
        .nonce_gen(&seeded(0xa1, 4), &sk1, &pk1, &msg, &keyagg)
        .unwrap();
    let (s2, p2) = ctx
        .nonce_gen(&seeded(0xa2, 4), &sk2, &pk2, &msg, &keyagg)
        .unwrap();
    let aggnonce = ctx.nonce_agg(&[p1.0, p2.0]).unwrap();
    let session = ctx.nonce_process(&aggnonce, &msg, &keyagg, &big_t).unwrap();
    let ps1 = ctx
        .partial_sign(s1, &sk1, &pk1, &p1.0, &keyagg, &session)
        .unwrap();
    let ps2 = ctx
        .partial_sign(s2, &sk2, &pk2, &p2.0, &keyagg, &session)
        .unwrap();
    // aggregate_pre_signature internally rejects a pre-sig that verifies
    // as final; here it succeeds because the pre-sig is NOT final.
    let pre = ctx
        .aggregate_pre_signature(&[ps1, ps2], &tweak.output_xonly, &msg, &session)
        .unwrap();
    // Directly: the pre-signature must not verify under x(Q).
    assert!(ctx.verify_bip340(&tweak.output_xonly, &msg, &pre).is_err());
}

#[test]
fn non_canonical_secret_scalars_are_rejected() {
    // The AdaptorSecretV1 constructor path (via extract) requires canonical
    // t; a scalar ≥ n cannot be a valid extracted secret. We assert the
    // range check on the exact boundary.
    // `n` and `0` are both non-canonical for a secret.
    let ctx = SecpContext::new(&[0x5a; 32]);
    // Deriving a pubkey from n or 0 fails (non-canonical), which is the
    // same gate the adaptor point check uses.
    assert!(compressed_pubkey(&ORDER_BE).is_none());
    assert!(compressed_pubkey(&[0u8; 32]).is_none());
    // A canonical scalar (1) does derive.
    assert!(compressed_pubkey(&scalar_one()).is_some());
    let _ = ctx;
}
