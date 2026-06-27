//! dom-shield — Noise static-key persistence KAV + Lens B notes (node_handle/key sub-area).
//!
//! The node persists its Noise_XX static private key to the store metadata DB
//! (`load_or_create_noise_static_key` -> `parse_persisted_noise_static_key`).
//! The parser enforces TWO invariants the node relies on:
//!   1. length == 32 bytes (else Invalid), and
//!   2. the key is in CANONICAL CLAMPED form — `clamp_static_privkey(k) == k` —
//!      else Invalid ("not in canonical clamped form").
//!
//! Both `parse_persisted_noise_static_key` and `load_or_create_noise_static_key`
//! are private/`pub(crate)` (covered by in-src #[cfg(test)] tests). This file
//! pins the underlying PUBLIC clamp/keygen contract those checks depend on, so a
//! change to the clamp rule (which would silently change which persisted keys
//! the node accepts) is caught.
//!
//! ── Lens B (recorded, NOT fixed here — both touch behaviour/format) ──────────
//! * The persisted static private key is stored PLAINTEXT in the metadata DB
//!   (`store.put_metadata(NOISE_STATIC_KEY_METADATA_KEY, &privkey)`) and is NOT
//!   zeroized after use — the `[u8;32]` is returned by value and copied around.
//!   An attacker with disk read access recovers the node's long-term Noise
//!   identity. STATIC-REVIEW NOTE → key-at-rest hardening is a human decision.
//! * `NodeConfig.wallet_password: Option<String>` is held in the config struct
//!   and not wrapped in a zeroizing type — the password lingers in process
//!   memory for the node's lifetime. STATIC-REVIEW NOTE.
//!
//! Neither is exercised as a failing test: zeroization/at-rest-encryption are
//! fixes (format/behaviour changes), and the test-construction mandate stops at
//! discovery.

use dom_wire::handshake::{clamp_static_privkey, derive_static_pubkey, generate_static_keypair};

/// KAV: a freshly generated static key is ALREADY in canonical clamped form, so
/// the node's "must round-trip clamp unchanged" persistence check accepts it.
#[test]
fn generated_static_key_is_canonical_clamped() {
    for _ in 0..256 {
        let (priv_k, pub_k) = generate_static_keypair();
        let mut reclamped = priv_k;
        clamp_static_privkey(&mut reclamped);
        assert_eq!(
            reclamped, priv_k,
            "generate_static_keypair must already be clamped (node persistence check requires it)"
        );
        // Public key derivation is deterministic from the clamped private key.
        assert_eq!(derive_static_pubkey(&priv_k), pub_k);
    }
}

/// KAV: the clamp is idempotent and fixes the X25519 bit pattern (low 3 bits of
/// byte 0 cleared, top bit of byte 31 cleared, bit 6 of byte 31 set). This is
/// the exact predicate `parse_persisted_noise_static_key` uses to reject a
/// tampered/non-canonical on-disk key.
#[test]
fn clamp_is_idempotent_and_canonical() {
    // Worst-case input: all bits set.
    let mut k = [0xFFu8; 32];
    clamp_static_privkey(&mut k);
    // Canonical-form bit checks.
    assert_eq!(
        k[0] & 0b0000_0111,
        0,
        "low 3 bits of byte 0 must be cleared"
    );
    assert_eq!(k[31] & 0b1000_0000, 0, "top bit of byte 31 must be cleared");
    assert_eq!(
        k[31] & 0b0100_0000,
        0b0100_0000,
        "bit 6 of byte 31 must be set"
    );
    // Idempotent: a second clamp is a no-op (round-trip stability the node needs).
    let mut twice = k;
    clamp_static_privkey(&mut twice);
    assert_eq!(twice, k, "clamp must be idempotent");
}

/// A NON-canonical key (e.g. all zeros, which clamp would change) is exactly the
/// shape the node's persistence parser must reject. Prove clamp would alter it,
/// so `clamp(k) != k` — the rejection predicate fires.
#[test]
fn noncanonical_persisted_key_is_distinguishable() {
    let raw = [0u8; 32]; // not clamped: bit 6 of byte 31 is 0, clamp would set it
    let mut clamped = raw;
    clamp_static_privkey(&mut clamped);
    assert_ne!(
        clamped, raw,
        "an all-zero persisted key is non-canonical -> node parser must reject it"
    );
}
