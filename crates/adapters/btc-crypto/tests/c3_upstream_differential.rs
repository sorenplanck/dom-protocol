//! C3 — decisive differential against the pinned upstream (Annex M
//! M.11.4).
//!
//! The safe backend (`btc-crypto`) must be byte-for-byte identical to the
//! raw pinned secp256k1-zkp FFI it wraps. For a set of the naturally
//! computable C2 cells, this test drives BOTH paths — the safe API and a
//! second, hand-written raw-FFI transcript — and requires byte equality
//! of: the aggregate x-only key, the TapTweak output key, the serialized
//! pubnonces, the partial signatures, the 64-byte pre-signature, the
//! nonce parity, the 64-byte final signature, and the extracted secret.
//!
//! C1b is formally excluded from C3 (it depends on injection, M.11.4);
//! this file makes no C1b claim.
//!
//! TEST-ONLY-NON-PRODUCTION.

mod common;

use btc_crypto::{NonceParity, SecpContext};
use btc_secp_sys::*;
use common::{compressed_pubkey, message, seeded};

/// A raw-FFI RAII context mirroring the safe wrapper, used as the
/// independent differential path.
struct RawCtx {
    ctx: *mut secp256k1_context,
    mem: *mut u8,
    layout: std::alloc::Layout,
}
impl RawCtx {
    fn new() -> Self {
        let size = unsafe { secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE) };
        let layout = std::alloc::Layout::from_size_align(size, 16).unwrap();
        let mem = unsafe { std::alloc::alloc(layout) };
        let ctx =
            unsafe { secp256k1_context_preallocated_create(mem.cast(), SECP256K1_CONTEXT_NONE) };
        let seed = [0x5au8; 32];
        assert_eq!(
            unsafe { secp256k1_context_randomize(ctx, seed.as_ptr()) },
            1
        );
        Self { ctx, mem, layout }
    }
    fn p(&self) -> *const secp256k1_context {
        self.ctx
    }
}
impl Drop for RawCtx {
    fn drop(&mut self) {
        unsafe {
            secp256k1_context_preallocated_destroy(self.ctx);
            std::alloc::dealloc(self.mem, self.layout);
        }
    }
}

fn raw_pubkey(ctx: &RawCtx, compressed: &[u8; 33]) -> secp256k1_pubkey {
    let mut pk = secp256k1_pubkey { data: [0; 64] };
    assert_eq!(
        unsafe { secp256k1_ec_pubkey_parse(ctx.p(), &mut pk, compressed.as_ptr(), 33) },
        1
    );
    pk
}

/// The raw-FFI transcript of one adaptor pipeline, returning every byte
/// the safe path must match.
struct RawOutputs {
    agg_xonly: [u8; 32],
    output_xonly: [u8; 32],
    pubnonce1: [u8; 66],
    pubnonce2: [u8; 66],
    partial1: [u8; 32],
    partial2: [u8; 32],
    pre_sig: [u8; 64],
    nonce_parity: i32,
    final_sig: [u8; 64],
    extracted: [u8; 32],
}

/// Inputs of one differential pipeline run.
struct PipelineInputs {
    sk1: [u8; 32],
    sk2: [u8; 32],
    pk1: [u8; 33],
    pk2: [u8; 33],
    t: [u8; 32],
    big_t: [u8; 33],
    secrand1: [u8; 32],
    secrand2: [u8; 32],
    msg: [u8; 32],
}

#[allow(clippy::too_many_lines)]
fn raw_pipeline(inp: &PipelineInputs) -> RawOutputs {
    let PipelineInputs {
        sk1,
        sk2,
        pk1,
        pk2,
        t,
        big_t,
        secrand1,
        secrand2,
        msg,
    } = inp;
    let ctx = RawCtx::new();
    let rpk1 = raw_pubkey(&ctx, pk1);
    let rpk2 = raw_pubkey(&ctx, pk2);
    let rbig_t = raw_pubkey(&ctx, big_t);

    let mut cache = secp256k1_musig_keyagg_cache { data: [0; 197] };
    let mut agg = secp256k1_xonly_pubkey { data: [0; 64] };
    let pubkeys = [&rpk1 as *const _, &rpk2 as *const _];
    assert_eq!(
        unsafe {
            secp256k1_musig_pubkey_agg(
                ctx.p(),
                core::ptr::null_mut(),
                &mut agg,
                &mut cache,
                pubkeys.as_ptr(),
                2,
            )
        },
        1
    );
    let mut agg_xonly = [0u8; 32];
    assert_eq!(
        unsafe { secp256k1_xonly_pubkey_serialize(ctx.p(), agg_xonly.as_mut_ptr(), &agg) },
        1
    );

    // TapTweak = tagged_hash("TapTweak", x(P)); same as the safe path's
    // synthetic tweak in the differential (no merkle root needed here).
    let mut taptweak = [0u8; 32];
    let tag = b"TapTweak";
    assert_eq!(
        unsafe {
            secp256k1_tagged_sha256(
                ctx.p(),
                taptweak.as_mut_ptr(),
                tag.as_ptr(),
                tag.len(),
                agg_xonly.as_ptr(),
                32,
            )
        },
        1
    );
    let mut tweaked_full = secp256k1_pubkey { data: [0; 64] };
    assert_eq!(
        unsafe {
            secp256k1_musig_pubkey_xonly_tweak_add(
                ctx.p(),
                &mut tweaked_full,
                &mut cache,
                taptweak.as_ptr(),
            )
        },
        1
    );
    let mut output_key = secp256k1_xonly_pubkey { data: [0; 64] };
    let mut output_parity: core::ffi::c_int = 0;
    assert_eq!(
        unsafe {
            secp256k1_xonly_pubkey_from_pubkey(
                ctx.p(),
                &mut output_key,
                &mut output_parity,
                &tweaked_full,
            )
        },
        1
    );
    let mut output_xonly = [0u8; 32];
    assert_eq!(
        unsafe {
            secp256k1_xonly_pubkey_serialize(ctx.p(), output_xonly.as_mut_ptr(), &output_key)
        },
        1
    );

    let mut secnonce1 = secp256k1_musig_secnonce { data: [0; 132] };
    let mut secnonce2 = secp256k1_musig_secnonce { data: [0; 132] };
    let mut pn1 = secp256k1_musig_pubnonce { data: [0; 132] };
    let mut pn2 = secp256k1_musig_pubnonce { data: [0; 132] };
    for (sn, pn, sr, sk, pk) in [
        (&mut secnonce1, &mut pn1, secrand1, sk1, &rpk1),
        (&mut secnonce2, &mut pn2, secrand2, sk2, &rpk2),
    ] {
        assert_eq!(
            unsafe {
                secp256k1_musig_nonce_gen(
                    ctx.p(),
                    sn,
                    pn,
                    sr.as_ptr(),
                    sk.as_ptr(),
                    pk,
                    msg.as_ptr(),
                    &cache,
                    core::ptr::null(),
                )
            },
            1
        );
    }
    let mut pubnonce1 = [0u8; 66];
    let mut pubnonce2 = [0u8; 66];
    assert_eq!(
        unsafe { secp256k1_musig_pubnonce_serialize(ctx.p(), pubnonce1.as_mut_ptr(), &pn1) },
        1
    );
    assert_eq!(
        unsafe { secp256k1_musig_pubnonce_serialize(ctx.p(), pubnonce2.as_mut_ptr(), &pn2) },
        1
    );

    let mut aggnonce = secp256k1_musig_aggnonce { data: [0; 132] };
    let nonces = [&pn1 as *const _, &pn2 as *const _];
    assert_eq!(
        unsafe { secp256k1_musig_nonce_agg(ctx.p(), &mut aggnonce, nonces.as_ptr(), 2) },
        1
    );
    let mut session = secp256k1_musig_session { data: [0; 133] };
    assert_eq!(
        unsafe {
            secp256k1_musig_nonce_process(
                ctx.p(),
                &mut session,
                &aggnonce,
                msg.as_ptr(),
                &cache,
                &rbig_t,
            )
        },
        1
    );
    let mut nonce_parity: core::ffi::c_int = -1;
    assert_eq!(
        unsafe { secp256k1_musig_nonce_parity(ctx.p(), &mut nonce_parity, &session) },
        1
    );

    let mut ps1 = secp256k1_musig_partial_sig { data: [0; 36] };
    let mut ps2 = secp256k1_musig_partial_sig { data: [0; 36] };
    for (ps, sn, sk) in [
        (&mut ps1, &mut secnonce1, sk1),
        (&mut ps2, &mut secnonce2, sk2),
    ] {
        let mut keypair = secp256k1_keypair { data: [0; 96] };
        assert_eq!(
            unsafe { secp256k1_keypair_create(ctx.p(), &mut keypair, sk.as_ptr()) },
            1
        );
        assert_eq!(
            unsafe { secp256k1_musig_partial_sign(ctx.p(), ps, sn, &keypair, &cache, &session) },
            1
        );
    }
    let mut partial1 = [0u8; 32];
    let mut partial2 = [0u8; 32];
    assert_eq!(
        unsafe { secp256k1_musig_partial_sig_serialize(ctx.p(), partial1.as_mut_ptr(), &ps1) },
        1
    );
    assert_eq!(
        unsafe { secp256k1_musig_partial_sig_serialize(ctx.p(), partial2.as_mut_ptr(), &ps2) },
        1
    );

    let mut pre_sig = [0u8; 64];
    let partials = [&ps1 as *const _, &ps2 as *const _];
    assert_eq!(
        unsafe {
            secp256k1_musig_partial_sig_agg(
                ctx.p(),
                pre_sig.as_mut_ptr(),
                &session,
                partials.as_ptr(),
                2,
            )
        },
        1
    );

    let mut final_sig = [0u8; 64];
    assert_eq!(
        unsafe {
            secp256k1_musig_adapt(
                ctx.p(),
                final_sig.as_mut_ptr(),
                pre_sig.as_ptr(),
                t.as_ptr(),
                nonce_parity,
            )
        },
        1
    );
    let mut extracted = [0u8; 32];
    assert_eq!(
        unsafe {
            secp256k1_musig_extract_adaptor(
                ctx.p(),
                extracted.as_mut_ptr(),
                final_sig.as_ptr(),
                pre_sig.as_ptr(),
                nonce_parity,
            )
        },
        1
    );

    RawOutputs {
        agg_xonly,
        output_xonly,
        pubnonce1,
        pubnonce2,
        partial1,
        partial2,
        pre_sig,
        nonce_parity,
        final_sig,
        extracted,
    }
}

#[test]
fn c3_safe_api_is_byte_equal_to_raw_ffi() {
    // A handful of naturally computable cells across different key seeds.
    for index in 0u32..6 {
        let sk1 = seeded(0x01, index);
        let sk2 = seeded(0x02, index.wrapping_add(1));
        let t = seeded(0x2b, index);
        let (pk1, pk2, big_t) = match (
            compressed_pubkey(&sk1),
            compressed_pubkey(&sk2),
            compressed_pubkey(&t),
        ) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => continue,
        };
        let secrand1 = seeded(0xa1, index);
        let secrand2 = seeded(0xa2, index);
        let msg = message(index);

        // Raw path.
        let raw = raw_pipeline(&PipelineInputs {
            sk1,
            sk2,
            pk1,
            pk2,
            t,
            big_t,
            secrand1,
            secrand2,
            msg,
        });

        // Safe path — same inputs, same synthetic TapTweak (x(P) only).
        let ctx = SecpContext::new(&[0x5a; 32]);
        let mut keyagg = ctx.key_agg(&[pk1, pk2]).unwrap();
        assert_eq!(keyagg.internal_xonly, raw.agg_xonly, "agg key differs");
        let taptweak = ctx.tagged_sha256(b"TapTweak", &keyagg.internal_xonly);
        let tweak = ctx.apply_tap_tweak(&mut keyagg, &taptweak).unwrap();
        assert_eq!(tweak.output_xonly, raw.output_xonly, "output key differs");

        let (sec1, pub1) = ctx.nonce_gen(&secrand1, &sk1, &pk1, &msg, &keyagg).unwrap();
        let (sec2, pub2) = ctx.nonce_gen(&secrand2, &sk2, &pk2, &msg, &keyagg).unwrap();
        assert_eq!(pub1.0, raw.pubnonce1, "pubnonce1 differs");
        assert_eq!(pub2.0, raw.pubnonce2, "pubnonce2 differs");

        let aggnonce = ctx.nonce_agg(&[pub1.0, pub2.0]).unwrap();
        let session = ctx.nonce_process(&aggnonce, &msg, &keyagg, &big_t).unwrap();
        let expected_parity = match raw.nonce_parity {
            0 => NonceParity::Even,
            1 => NonceParity::Odd,
            other => panic!("raw parity out of domain: {other}"),
        };
        assert_eq!(
            session.nonce_parity, expected_parity,
            "nonce parity differs"
        );

        let partial1 = ctx
            .partial_sign(sec1, &sk1, &pk1, &pub1.0, &keyagg, &session)
            .unwrap();
        let partial2 = ctx
            .partial_sign(sec2, &sk2, &pk2, &pub2.0, &keyagg, &session)
            .unwrap();
        assert_eq!(partial1, raw.partial1, "partial1 differs");
        assert_eq!(partial2, raw.partial2, "partial2 differs");

        let pre_sig = ctx
            .aggregate_pre_signature(&[partial1, partial2], &tweak.output_xonly, &msg, &session)
            .unwrap();
        assert_eq!(pre_sig, raw.pre_sig, "pre-signature differs");

        let final_sig = ctx
            .adapt(
                &pre_sig,
                &t,
                session.nonce_parity,
                &tweak.output_xonly,
                &msg,
            )
            .unwrap();
        assert_eq!(final_sig, raw.final_sig, "final signature differs");

        let extracted = ctx
            .extract(&final_sig, &pre_sig, session.nonce_parity, &big_t)
            .unwrap();
        assert_eq!(extracted, raw.extracted, "extracted secret differs");
        assert_eq!(extracted, t, "extracted secret is not t");
    }
}
