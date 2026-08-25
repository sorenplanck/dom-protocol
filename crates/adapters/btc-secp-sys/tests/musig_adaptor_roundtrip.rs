//! Build-and-link smoke of the pinned backend (Annex M M.17 step 1).
//!
//! Proves that the vendored library compiles with MuSig2 enabled and that
//! the full 2-of-2 adaptor pipeline of M.4.2 holds end to end at the FFI
//! layer: keyagg → x-only (Taproot) tweak → nonce gen/agg → session with
//! adaptor T → partials (verified) → pre-signature → adapt(t) → BIP340
//! verify → extract(t' == t) → t'·G == T. Plus the two cheapest negative
//! proofs: a pre-signature is NOT a valid final signature, and the wrong
//! nonce parity does NOT extract the right secret.
//!
//! TEST-ONLY-NON-PRODUCTION: every secret in this file is a synthetic
//! test constant. Production secrets are born in the vault (M.6) and
//! never appear in fixtures.
//!
//! This is a smoke, not conformance: C1a (official BIP327 vectors), C1b,
//! C2, C3 and C4 are their own layers (M.11) and none of them is claimed
//! here.

use btc_secp_sys::*;

/// RAII preallocated context: the memory is caller-owned (16-byte
/// aligned) and outlives the context, exactly as the API requires.
struct Ctx {
    ctx: *mut secp256k1_context,
    memory: *mut u8,
    layout: std::alloc::Layout,
}

impl Ctx {
    fn new() -> Self {
        // SAFETY: valid flags; size query has no preconditions.
        let size = unsafe { secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE) };
        assert!(size > 0);
        let layout = std::alloc::Layout::from_size_align(size, 16).expect("test layout");
        // SAFETY: non-zero layout.
        let memory = unsafe { std::alloc::alloc(layout) };
        assert!(!memory.is_null(), "test allocation failed");
        // SAFETY: memory is `size` bytes, 16-byte aligned, exclusively ours.
        let ctx =
            unsafe { secp256k1_context_preallocated_create(memory.cast(), SECP256K1_CONTEXT_NONE) };
        assert!(!ctx.is_null(), "context creation failed");
        let seed = [0x5au8; 32];
        // SAFETY: ctx valid, seed is 32 bytes.
        assert_eq!(
            unsafe { secp256k1_context_randomize(ctx, seed.as_ptr()) },
            1
        );
        Self {
            ctx,
            memory,
            layout,
        }
    }
    fn get(&self) -> *const secp256k1_context {
        self.ctx
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: ctx came from preallocated_create in `memory`, which is
        // freed only after the context is destroyed, with its layout.
        unsafe {
            secp256k1_context_preallocated_destroy(self.ctx);
            std::alloc::dealloc(self.memory, self.layout);
        }
    }
}

fn pubkey_of(ctx: &Ctx, seckey: &[u8; 32]) -> secp256k1_pubkey {
    let mut pk = secp256k1_pubkey { data: [0; 64] };
    // SAFETY: all pointers valid; seckey is 32 bytes.
    assert_eq!(
        unsafe { secp256k1_ec_seckey_verify(ctx.get(), seckey.as_ptr()) },
        1
    );
    assert_eq!(
        unsafe { secp256k1_ec_pubkey_create(ctx.get(), &mut pk, seckey.as_ptr()) },
        1
    );
    pk
}

#[test]
fn full_two_of_two_adaptor_pipeline_holds_at_the_ffi_layer() {
    let ctx = Ctx::new();

    // Two deterministic TEST-ONLY participants, roster order fixed.
    let sk1 = [0x11u8; 32];
    let sk2 = [0x22u8; 32];
    let pk1 = pubkey_of(&ctx, &sk1);
    let pk2 = pubkey_of(&ctx, &sk2);

    // TEST-ONLY adaptor secret t and its point T = t·G.
    let t = [0x2bu8; 32];
    let big_t = pubkey_of(&ctx, &t);

    // 1. BIP327 key aggregation in roster order.
    let mut cache = secp256k1_musig_keyagg_cache { data: [0; 197] };
    let mut agg_xonly = secp256k1_xonly_pubkey { data: [0; 64] };
    let pubkeys = [&pk1 as *const _, &pk2 as *const _];
    // SAFETY: array of 2 valid pubkey pointers.
    assert_eq!(
        unsafe {
            secp256k1_musig_pubkey_agg(
                ctx.get(),
                core::ptr::null_mut(),
                &mut agg_xonly,
                &mut cache,
                pubkeys.as_ptr(),
                2,
            )
        },
        1,
        "key aggregation failed"
    );

    // 2. Taproot-style x-only tweak of the aggregate inside the cache
    //    (the real TapTweak hash arrives with M.17 step 5; any valid
    //    scalar exercises the same code path here).
    let tweak = [0x77u8; 32];
    let mut tweaked_full = secp256k1_pubkey { data: [0; 64] };
    // SAFETY: valid cache from pubkey_agg; tweak is 32 bytes.
    assert_eq!(
        unsafe {
            secp256k1_musig_pubkey_xonly_tweak_add(
                ctx.get(),
                &mut tweaked_full,
                &mut cache,
                tweak.as_ptr(),
            )
        },
        1,
        "x-only tweak failed"
    );
    let mut output_key = secp256k1_xonly_pubkey { data: [0; 64] };
    let mut output_parity: core::ffi::c_int = 0;
    // SAFETY: valid tweaked pubkey.
    assert_eq!(
        unsafe {
            secp256k1_xonly_pubkey_from_pubkey(
                ctx.get(),
                &mut output_key,
                &mut output_parity,
                &tweaked_full,
            )
        },
        1
    );

    // 3. The frozen message (a synthetic 32-byte sighash stand-in).
    let msg = [0x6du8; 32];

    // 4. Nonce generation for both signers (TEST-ONLY secrands — the
    //    durable one-shot property belongs to the vault, M.6).
    let mut secnonce1 = secp256k1_musig_secnonce { data: [0; 132] };
    let mut secnonce2 = secp256k1_musig_secnonce { data: [0; 132] };
    let mut pubnonce1 = secp256k1_musig_pubnonce { data: [0; 132] };
    let mut pubnonce2 = secp256k1_musig_pubnonce { data: [0; 132] };
    let secrand1 = [0xa1u8; 32];
    let secrand2 = [0xa2u8; 32];
    for (secnonce, pubnonce, secrand, sk, pk) in [
        (&mut secnonce1, &mut pubnonce1, &secrand1, &sk1, &pk1),
        (&mut secnonce2, &mut pubnonce2, &secrand2, &sk2, &pk2),
    ] {
        // SAFETY: all pointers valid; optional args passed explicitly.
        assert_eq!(
            unsafe {
                secp256k1_musig_nonce_gen(
                    ctx.get(),
                    secnonce,
                    pubnonce,
                    secrand.as_ptr(),
                    sk.as_ptr(),
                    pk,
                    msg.as_ptr(),
                    &cache,
                    core::ptr::null(),
                )
            },
            1,
            "nonce generation failed"
        );
    }

    // The 66-byte serialization is the canonical wire (M.5.2).
    let mut nonce_bytes = [0u8; MUSIG_PUBNONCE_SERIALIZED_LEN];
    // SAFETY: valid pubnonce, 66-byte output.
    assert_eq!(
        unsafe {
            secp256k1_musig_pubnonce_serialize(ctx.get(), nonce_bytes.as_mut_ptr(), &pubnonce1)
        },
        1
    );
    let mut reparsed = secp256k1_musig_pubnonce { data: [0; 132] };
    // SAFETY: 66 valid bytes in.
    assert_eq!(
        unsafe { secp256k1_musig_pubnonce_parse(ctx.get(), &mut reparsed, nonce_bytes.as_ptr()) },
        1,
        "canonical pubnonce roundtrip failed"
    );

    // 5. Aggregate nonces and process the session WITH the adaptor T.
    let mut aggnonce = secp256k1_musig_aggnonce { data: [0; 132] };
    let nonces = [&pubnonce1 as *const _, &pubnonce2 as *const _];
    // SAFETY: two valid pubnonce pointers.
    assert_eq!(
        unsafe { secp256k1_musig_nonce_agg(ctx.get(), &mut aggnonce, nonces.as_ptr(), 2) },
        1
    );
    let mut session = secp256k1_musig_session { data: [0; 133] };
    // SAFETY: all valid; adaptor = T makes the aggregate a pre-signature.
    assert_eq!(
        unsafe {
            secp256k1_musig_nonce_process(
                ctx.get(),
                &mut session,
                &aggnonce,
                msg.as_ptr(),
                &cache,
                &big_t,
            )
        },
        1,
        "nonce processing with adaptor failed"
    );

    // 6. The parity is a session fact, persisted publicly (M.4.2 step 3).
    let mut parity: core::ffi::c_int = -1;
    // SAFETY: valid session.
    assert_eq!(
        unsafe { secp256k1_musig_nonce_parity(ctx.get(), &mut parity, &session) },
        1
    );
    assert!(parity == 0 || parity == 1, "parity out of domain");

    // 7. Both partials, each VERIFIED (M.6.7: including our own).
    let mut partial1 = secp256k1_musig_partial_sig { data: [0; 36] };
    let mut partial2 = secp256k1_musig_partial_sig { data: [0; 36] };
    for (partial, secnonce, sk, pubnonce, pk) in [
        (&mut partial1, &mut secnonce1, &sk1, &pubnonce1, &pk1),
        (&mut partial2, &mut secnonce2, &sk2, &pubnonce2, &pk2),
    ] {
        let mut keypair = secp256k1_keypair { data: [0; 96] };
        // SAFETY: valid seckey.
        assert_eq!(
            unsafe { secp256k1_keypair_create(ctx.get(), &mut keypair, sk.as_ptr()) },
            1
        );
        // SAFETY: all valid; secnonce is consumed (zeroized) here.
        assert_eq!(
            unsafe {
                secp256k1_musig_partial_sign(
                    ctx.get(),
                    partial,
                    secnonce,
                    &keypair,
                    &cache,
                    &session,
                )
            },
            1,
            "partial signing failed"
        );
        // SAFETY: all valid.
        assert_eq!(
            unsafe {
                secp256k1_musig_partial_sig_verify(
                    ctx.get(),
                    partial,
                    pubnonce,
                    pk,
                    &cache,
                    &session,
                )
            },
            1,
            "partial signature failed verification"
        );
    }

    // 8. Aggregate into the 64-byte PRE-signature.
    let mut pre_sig = [0u8; 64];
    let partials = [&partial1 as *const _, &partial2 as *const _];
    // SAFETY: two valid partial pointers.
    assert_eq!(
        unsafe {
            secp256k1_musig_partial_sig_agg(
                ctx.get(),
                pre_sig.as_mut_ptr(),
                &session,
                partials.as_ptr(),
                2,
            )
        },
        1
    );

    // NEGATIVE: the pre-signature must NOT verify as a final signature
    // (M.11.3 case 7) — otherwise the adaptor gate is theater.
    // SAFETY: all valid.
    assert_eq!(
        unsafe {
            secp256k1_schnorrsig_verify(ctx.get(), pre_sig.as_ptr(), msg.as_ptr(), 32, &output_key)
        },
        0,
        "a pre-signature verified as final: adaptor breach"
    );

    // 9. Adapt with t and verify under the tweaked output key.
    let mut final_sig = [0u8; 64];
    // SAFETY: all valid 32/64-byte buffers.
    assert_eq!(
        unsafe {
            secp256k1_musig_adapt(
                ctx.get(),
                final_sig.as_mut_ptr(),
                pre_sig.as_ptr(),
                t.as_ptr(),
                parity,
            )
        },
        1
    );
    // SAFETY: all valid.
    assert_eq!(
        unsafe {
            secp256k1_schnorrsig_verify(
                ctx.get(),
                final_sig.as_ptr(),
                msg.as_ptr(),
                32,
                &output_key,
            )
        },
        1,
        "adapted signature failed BIP340 verification"
    );

    // 10. Extract t' and require exact equality AND t'·G == T (M.4.2
    //     step 10 — the group check, not just byte equality).
    let mut extracted = [0u8; 32];
    // SAFETY: all valid.
    assert_eq!(
        unsafe {
            secp256k1_musig_extract_adaptor(
                ctx.get(),
                extracted.as_mut_ptr(),
                final_sig.as_ptr(),
                pre_sig.as_ptr(),
                parity,
            )
        },
        1
    );
    assert_eq!(extracted, t, "extracted secret differs from the original");
    let extracted_point = pubkey_of(&ctx, &extracted);
    let mut lhs = [0u8; 33];
    let mut rhs = [0u8; 33];
    let mut len = 33usize;
    // SAFETY: valid pubkeys, 33-byte buffers, compressed flag.
    assert_eq!(
        unsafe {
            secp256k1_ec_pubkey_serialize(
                ctx.get(),
                lhs.as_mut_ptr(),
                &mut len,
                &extracted_point,
                SECP256K1_EC_COMPRESSED,
            )
        },
        1
    );
    len = 33;
    assert_eq!(
        unsafe {
            secp256k1_ec_pubkey_serialize(
                ctx.get(),
                rhs.as_mut_ptr(),
                &mut len,
                &big_t,
                SECP256K1_EC_COMPRESSED,
            )
        },
        1
    );
    assert_eq!(lhs, rhs, "extracted t' does not satisfy t'*G == T");

    // NEGATIVE: the WRONG parity must not extract the right secret.
    let mut wrong = [0u8; 32];
    // SAFETY: all valid.
    assert_eq!(
        unsafe {
            secp256k1_musig_extract_adaptor(
                ctx.get(),
                wrong.as_mut_ptr(),
                final_sig.as_ptr(),
                pre_sig.as_ptr(),
                1 - parity,
            )
        },
        1
    );
    assert_ne!(wrong, t, "parity inversion still extracted the secret");
}

#[test]
fn tagged_sha256_is_linked_and_deterministic() {
    let ctx = Ctx::new();
    let tag = b"TapTweak";
    let msg = [0x01u8; 32];
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    for out in [&mut out1, &mut out2] {
        // SAFETY: valid buffers and lengths.
        assert_eq!(
            unsafe {
                secp256k1_tagged_sha256(
                    ctx.get(),
                    out.as_mut_ptr(),
                    tag.as_ptr(),
                    tag.len(),
                    msg.as_ptr(),
                    32,
                )
            },
            1
        );
    }
    assert_eq!(out1, out2);
    assert_ne!(out1, [0u8; 32]);
}
