//! Lens B (Lazarus / crypto-APT) — funds-safety surface of dom-slate.
//!
//! dom-slate is PURE crypto: it transfers secret material to the caller in
//! zeroizing owners for persistence inside encrypted wallet state. These tests
//! pin that ownership surface and the nonce uniqueness properties.

mod common;

use dom_slate::{random_secret_key, respond_receive};
use std::collections::HashSet;
use zeroize::Zeroizing;

// ── Vector B-1: every exported transient secret has a zeroizing owner ────────
#[test]
fn secret_material_is_owned_by_zeroizing_wrappers() {
    fn assert_zeroizing(_: &Zeroizing<[u8; 32]>) {}

    let sender = common::build_balanced_send(1_000, 10, 500);
    assert_zeroizing(&sender.excess_blinding);
    assert_zeroizing(&sender.nonce);
    assert_zeroizing(&sender.change.as_ref().expect("change material").blinding);
    let resp = respond_receive(sender.slate, &common::TEST_CHAIN_ID).expect("respond");
    assert_zeroizing(&resp.recipient_output_blinding);
}

// ── Vector B-2: nonce + aggregate signature => sender key recovery (algebra) ──
//
// This is the *consequence* of B-1, and it IS behaviourally demonstrable: we
// don't need the crate to leak anything beyond what it already returns. Given
// the returned sender nonce `k_S` and the finalized aggregate signature, the
// sender's partial `s_S = k_S + c*x_S` is recoverable, hence `x_S`. We do NOT
// reimplement the recovery (that would be attack tooling); instead we assert the
// PRECONDITION that makes it possible: finalize hands back nothing that hides
// k_S, and k_S is a usable scalar. The defensive takeaway (nonce must be
// single-use and discarded) is documented in the source; this test pins that
// the nonce is exposed in the clear, which is the risk surface.
#[test]
fn sender_nonce_is_exposed_in_clear_enabling_key_recovery_if_reused() {
    let sender = common::build_balanced_send(1_000, 10, 500);
    // The nonce is returned in the clear (not opaque). If a caller ever reuses
    // it across two sessions with the same excess key, the excess key leaks.
    assert_ne!(
        *sender.nonce, [0u8; 32],
        "sender nonce must be a non-trivial scalar (exposed in clear to caller)"
    );
    // Pin the documented hazard as a behavioural fact: nonce and excess are
    // distinct independently-returned secrets, both required for finalize.
    assert_ne!(
        *sender.nonce, *sender.excess_blinding,
        "nonce and excess are independent secrets; reuse of nonce leaks excess"
    );
}

// ── Vector B-3: random_secret_key entropy / non-determinism (CSPRNG) ─────────
//
// Nonces and blindings come from `random_secret_key` (thread_rng, a CSPRNG).
// A predictable nonce in aggregate signing leaks the signing key, so the
// minimum observable guarantee is: successive draws are distinct and never the
// all-zero / trivially-structured scalar. Statistical entropy quality of
// thread_rng is out of scope (it is the std CSPRNG); this asserts the
// non-determinism property a deterministic-nonce regression would violate.
#[test]
fn random_secret_key_is_non_deterministic_across_draws() {
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for _ in 0..256 {
        let k = random_secret_key().to_be_bytes_raw();
        assert_ne!(k, [0u8; 32], "secret key must never be zero");
        assert!(
            seen.insert(k),
            "random_secret_key produced a duplicate in 256 draws (broken entropy)"
        );
    }
}

// ── Vector B-4: two builds never collide on excess/nonce (no fixed seed) ──────
#[test]
fn independent_sender_builds_do_not_reuse_nonce_or_excess() {
    let a = common::build_balanced_send(1_000, 10, 500);
    let b = common::build_balanced_send(1_000, 10, 500);
    assert_ne!(
        *a.nonce, *b.nonce,
        "sender nonce reused across builds (fatal)"
    );
    assert_ne!(
        *a.excess_blinding, *b.excess_blinding,
        "sender excess reused across builds"
    );
}
