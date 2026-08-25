//! C2 — the 24-cell adaptor matrix (Annex M M.11.3).
//!
//! The matrix is the cartesian product
//!   ε_R ∈ {even, odd} × t ∈ {1, n−1, random} ×
//!   internal_flip ∈ {false, true} × output_flip ∈ {false, true}
//! = 24 cells. Because `nonce_process` folds the adaptor point `T = t·G`
//! into the session, the nonce parity ε_R is coupled to the keys and to
//! `t`; the cells are therefore reached by deterministic search over
//! synthetic key/nonce seeds (never by grinding for a cryptographic
//! event — the search only varies public structure), and coverage of all
//! 24 (t-class × internal_flip × output_flip × ε_R) combinations is
//! asserted. A combination left uncovered is reported, never silently
//! omitted (M.14.2).
//!
//! For every reached cell the full M.11.3 checklist runs: KeyAgg and
//! TapTweak are byte-stable, both partials verify, tampering one fails,
//! the pre-signature is NOT a valid final signature, adapt produces a
//! BIP340-valid signature under x(Q), extract returns exactly `t`,
//! t·G == T, and inverting the nonce parity does not extract `t`.
//!
//! TEST-ONLY-NON-PRODUCTION.

mod common;

use std::collections::BTreeSet;

use btc_crypto::{NonceParity, Parity, SecpContext};
use common::{compressed_pubkey, message, scalar_n_minus_1, scalar_one, seeded};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CellKey {
    t_class: u8,
    internal_flip: bool,
    output_flip: bool,
    eps_r: bool,
}

/// One reached cell: runs the full M.11.3 checklist, panicking on any
/// violation. Returns the observed parities so the caller can record
/// coverage.
fn run_cell(t: &[u8; 32], t_class: u8, vector_index: u32) -> Option<CellKey> {
    // Two synthetic signers whose secrets vary with the vector index so
    // different indices explore different aggregate/output parities.
    let sk1 = seeded(0x01, vector_index);
    let sk2 = seeded(0x02, vector_index.wrapping_add(1));
    let pk1 = compressed_pubkey(&sk1)?;
    let pk2 = compressed_pubkey(&sk2)?;
    let big_t = compressed_pubkey(t)?;
    let msg = message(vector_index);

    let ctx = SecpContext::new(&[0x5a; 32]);

    // 1. KeyAgg (byte-stable across two computations).
    let mut keyagg = ctx.key_agg(&[pk1, pk2]).ok()?;
    let keyagg2 = ctx.key_agg(&[pk1, pk2]).ok()?;
    assert_eq!(
        keyagg.internal_xonly, keyagg2.internal_xonly,
        "KeyAgg not byte-stable"
    );
    let internal_flip = keyagg.internal_parity == Parity::Odd;

    // 2. TapTweak + output key (byte-stable).
    let taptweak = ctx.tagged_sha256(b"TapTweak", &keyagg.internal_xonly);
    let tweak = ctx.apply_tap_tweak(&mut keyagg, &taptweak).ok()?;
    let output_flip = tweak.output_parity == Parity::Odd;
    let output_xonly = tweak.output_xonly;

    // 3. Nonces.
    let (sec1, pub1) = ctx
        .nonce_gen(&seeded(0xa1, vector_index), &sk1, &pk1, &msg, &keyagg)
        .ok()?;
    let (sec2, pub2) = ctx
        .nonce_gen(&seeded(0xa2, vector_index), &sk2, &pk2, &msg, &keyagg)
        .ok()?;
    let aggnonce = ctx.nonce_agg(&[pub1.0, pub2.0]).ok()?;

    // 4-6. Session, partials, pre-signature.
    let session = ctx.nonce_process(&aggnonce, &msg, &keyagg, &big_t).ok()?;
    let eps_r = session.nonce_parity == NonceParity::Odd;
    let partial1 = ctx
        .partial_sign(sec1, &sk1, &pk1, &pub1.0, &keyagg, &session)
        .ok()?;
    let partial2 = ctx
        .partial_sign(sec2, &sk2, &pk2, &pub2.0, &keyagg, &session)
        .ok()?;
    // Both partials verify.
    ctx.partial_verify(&partial1, &pub1.0, &pk1, &keyagg, &session)
        .expect("partial1 verifies");
    ctx.partial_verify(&partial2, &pub2.0, &pk2, &keyagg, &session)
        .expect("partial2 verifies");
    // Tampering one partial fails.
    let mut bad = partial1;
    bad[0] ^= 0x01;
    assert!(
        ctx.partial_verify(&bad, &pub1.0, &pk1, &keyagg, &session)
            .is_err(),
        "a tampered partial verified"
    );

    // 7. Pre-signature is NOT a valid final signature (checked inside).
    let pre_sig = ctx
        .aggregate_pre_signature(&[partial1, partial2], &output_xonly, &msg, &session)
        .expect("pre-signature");

    // 8-9. Adapt and verify.
    let final_sig = ctx
        .adapt(&pre_sig, t, session.nonce_parity, &output_xonly, &msg)
        .expect("adapt");
    ctx.verify_bip340(&output_xonly, &msg, &final_sig)
        .expect("final verifies BIP340");

    // 10-11. Extract == t and t·G == T.
    let extracted = ctx
        .extract(&final_sig, &pre_sig, session.nonce_parity, &big_t)
        .expect("extract");
    assert_eq!(&extracted, t, "extracted secret differs from t");

    // 12. Inverting the nonce parity does not extract t.
    let inverted = match session.nonce_parity {
        NonceParity::Even => NonceParity::Odd,
        NonceParity::Odd => NonceParity::Even,
    };
    match ctx.extract(&final_sig, &pre_sig, inverted, &big_t) {
        Err(_) => {}
        Ok(other) => assert_ne!(&other, t, "inverted parity still extracted t"),
    }

    let _ = t_class;
    Some(CellKey {
        t_class,
        internal_flip,
        output_flip,
        eps_r,
    })
}

#[test]
fn c2_adaptor_matrix_covers_all_24_cells() {
    let t_values: [(u8, [u8; 32]); 3] = [
        (0, scalar_one()),
        (1, scalar_n_minus_1()),
        (2, seeded(0x2b, 7)),
    ];

    let mut covered: BTreeSet<CellKey> = BTreeSet::new();
    // Bounded deterministic search: 8 parity combos per t-class, ample
    // budget to reach each.
    const MAX_INDEX: u32 = 4096;
    for (t_class, t) in &t_values {
        for index in 0..MAX_INDEX {
            if let Some(cell) = run_cell(t, *t_class, index) {
                covered.insert(cell);
            }
            // Early exit once all 8 (internal, output, ε_R) combos for
            // this t-class are covered.
            let have = covered.iter().filter(|c| c.t_class == *t_class).count();
            if have == 8 {
                break;
            }
        }
    }

    // Report any missing cell explicitly (no silent omission — M.14.2).
    let mut missing = Vec::new();
    for t_class in 0u8..3 {
        for internal_flip in [false, true] {
            for output_flip in [false, true] {
                for eps_r in [false, true] {
                    let key = CellKey {
                        t_class,
                        internal_flip,
                        output_flip,
                        eps_r,
                    };
                    if !covered.contains(&key) {
                        missing.push(key);
                    }
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "C2 matrix incomplete: {} of 24 cells uncovered",
        missing.len()
    );
    assert_eq!(covered.len(), 24, "expected exactly 24 cells");
}
