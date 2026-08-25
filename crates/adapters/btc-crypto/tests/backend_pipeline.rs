//! Safe-backend equivalent of the FFI smoke (M.1.2, M.4.2): the full
//! 2-of-2 adaptor pipeline through the SAFE API, plus the self-checks the
//! wrapper is required to enforce.
//!
//! TEST-ONLY-NON-PRODUCTION: every secret here is a synthetic constant.
//! Valid compressed keys are derived from the pinned backend in
//! `keys_from_backend`, so the test hard-codes no guessed points.

use btc_crypto::{BtcCryptoError, SecpContext};

/// Synthetic 2-of-2 material plus the adaptor secret and its point.
struct Material {
    sk1: [u8; 32],
    sk2: [u8; 32],
    pk1: [u8; 33],
    pk2: [u8; 33],
    t: [u8; 32],
    big_t: [u8; 33],
}

#[test]
fn full_adaptor_pipeline_through_safe_api() {
    let Material {
        sk1,
        sk2,
        pk1,
        pk2,
        t,
        big_t,
    } = keys_from_backend();

    let ctx = SecpContext::new(&[0x5a; 32]);
    let msg = [0x6d; 32];

    // 1. Key aggregation in roster order + a Taproot-style tweak.
    let mut keyagg = ctx.key_agg(&[pk1, pk2]).expect("key agg");
    let taptweak = ctx.tagged_sha256(b"TapTweak", &keyagg.internal_xonly);
    let tweak = ctx.apply_tap_tweak(&mut keyagg, &taptweak).expect("tweak");
    let output_xonly = tweak.output_xonly;

    // 2-4. Nonces.
    let (sec1, pub1) = ctx
        .nonce_gen(&[0xa1; 32], &sk1, &pk1, &msg, &keyagg)
        .expect("nonce1");
    let (sec2, pub2) = ctx
        .nonce_gen(&[0xa2; 32], &sk2, &pk2, &msg, &keyagg)
        .expect("nonce2");
    let aggnonce = ctx.nonce_agg(&[pub1.0, pub2.0]).expect("nonce agg");

    // 5-6. Session with adaptor T (+ its public parity).
    let session = ctx
        .nonce_process(&aggnonce, &msg, &keyagg, &big_t)
        .expect("session");

    // 7. Partials, each self-verified inside partial_sign.
    let partial1 = ctx
        .partial_sign(sec1, &sk1, &pk1, &pub1.0, &keyagg, &session)
        .expect("partial1");
    let partial2 = ctx
        .partial_sign(sec2, &sk2, &pk2, &pub2.0, &keyagg, &session)
        .expect("partial2");
    ctx.partial_verify(&partial1, &pub1.0, &pk1, &keyagg, &session)
        .expect("verify1");
    ctx.partial_verify(&partial2, &pub2.0, &pk2, &keyagg, &session)
        .expect("verify2");

    // 8. Pre-signature — the wrapper proves it is NOT final.
    let pre_sig = ctx
        .aggregate_pre_signature(&[partial1, partial2], &output_xonly, &msg, &session)
        .expect("pre-signature");

    // 9. Adapt with t and verify.
    let final_sig = ctx
        .adapt(&pre_sig, &t, session.nonce_parity, &output_xonly, &msg)
        .expect("adapt");
    ctx.verify_bip340(&output_xonly, &msg, &final_sig)
        .expect("final verifies");

    // 10. Extract t' and check t'·G == T.
    let extracted = ctx
        .extract(&final_sig, &pre_sig, session.nonce_parity, &big_t)
        .expect("extract");
    assert_eq!(extracted, t, "extracted secret differs");
}

#[test]
fn taptweak_ge_n_fails_closed() {
    let m = keys_from_backend();
    let (pk1, pk2) = (m.pk1, m.pk2);
    let ctx = SecpContext::new(&[0x5a; 32]);
    let mut keyagg = ctx.key_agg(&[pk1, pk2]).expect("key agg");
    // n itself as a tweak must be rejected, never reduced (M.2.2 step 7).
    let n = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    assert_eq!(
        ctx.apply_tap_tweak(&mut keyagg, &n).unwrap_err(),
        BtcCryptoError::TapTweakRejected
    );
}

#[test]
fn wrong_adaptor_point_is_rejected_on_extract() {
    let Material {
        sk1,
        sk2,
        pk1,
        pk2,
        t,
        big_t,
    } = keys_from_backend();
    let ctx = SecpContext::new(&[0x5a; 32]);
    let msg = [0x6d; 32];
    let mut keyagg = ctx.key_agg(&[pk1, pk2]).expect("key agg");
    let taptweak = ctx.tagged_sha256(b"TapTweak", &keyagg.internal_xonly);
    let tweak = ctx.apply_tap_tweak(&mut keyagg, &taptweak).expect("tweak");
    let (sec1, pub1) = ctx
        .nonce_gen(&[0xa1; 32], &sk1, &pk1, &msg, &keyagg)
        .unwrap();
    let (sec2, pub2) = ctx
        .nonce_gen(&[0xa2; 32], &sk2, &pk2, &msg, &keyagg)
        .unwrap();
    let aggnonce = ctx.nonce_agg(&[pub1.0, pub2.0]).unwrap();
    let session = ctx.nonce_process(&aggnonce, &msg, &keyagg, &big_t).unwrap();
    let p1 = ctx
        .partial_sign(sec1, &sk1, &pk1, &pub1.0, &keyagg, &session)
        .unwrap();
    let p2 = ctx
        .partial_sign(sec2, &sk2, &pk2, &pub2.0, &keyagg, &session)
        .unwrap();
    let pre = ctx
        .aggregate_pre_signature(&[p1, p2], &tweak.output_xonly, &msg, &session)
        .unwrap();
    let final_sig = ctx
        .adapt(&pre, &t, session.nonce_parity, &tweak.output_xonly, &msg)
        .unwrap();
    // Extract against a DIFFERENT adaptor point must fail t·G == T (or
    // reject the mutated point outright).
    let mut wrong_t = big_t;
    wrong_t[32] ^= 0x01;
    let err = ctx
        .extract(&final_sig, &pre, session.nonce_parity, &wrong_t)
        .unwrap_err();
    assert!(matches!(
        err,
        BtcCryptoError::AdaptorPointMismatch | BtcCryptoError::InvalidPoint
    ));
}

/// Derive valid compressed keys straight from the pinned sys crate, so
/// these tests never hard-code guessed points.
fn keys_from_backend() -> Material {
    use btc_secp_sys::*;
    let size = unsafe { secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE) };
    let layout = std::alloc::Layout::from_size_align(size, 16).unwrap();
    let mem = unsafe { std::alloc::alloc(layout) };
    let c = unsafe { secp256k1_context_preallocated_create(mem.cast(), SECP256K1_CONTEXT_NONE) };
    let compressed = |sk: &[u8; 32]| -> [u8; 33] {
        let mut pk = secp256k1_pubkey { data: [0; 64] };
        assert_eq!(
            unsafe { secp256k1_ec_pubkey_create(c, &mut pk, sk.as_ptr()) },
            1
        );
        let mut out = [0u8; 33];
        let mut len = 33usize;
        assert_eq!(
            unsafe {
                secp256k1_ec_pubkey_serialize(
                    c,
                    out.as_mut_ptr(),
                    &mut len,
                    &pk,
                    SECP256K1_EC_COMPRESSED,
                )
            },
            1
        );
        out
    };
    let sk1 = [0x11u8; 32];
    let sk2 = [0x22u8; 32];
    let t = [0x2bu8; 32];
    let pk1 = compressed(&sk1);
    let pk2 = compressed(&sk2);
    let big_t = compressed(&t);
    unsafe {
        secp256k1_context_preallocated_destroy(c);
        std::alloc::dealloc(mem, layout);
    }
    Material {
        sk1,
        sk2,
        pk1,
        pk2,
        t,
        big_t,
    }
}
