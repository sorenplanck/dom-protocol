//! KAV frozen-drift — byte freeze of consensus-critical deterministic
//! outputs. Unlike conformance KAVs, a freeze test pins the CURRENT behavior so
//! ANY future drift (dependency bump, refactor, accidental format change) trips
//! a RED that demands explicit human re-confirmation. These are NOT conformance
//! claims — they are change-detectors on consensus surfaces.
//!
//! Surfaces frozen here (gaps not already byte-frozen elsewhere):
//!   (1) Schnorr (r_compressed, s) for a fixed (sk, msg, chain_id). The existing
//!       schnorr.rs::frozen_signature_vector_sk1_genesis_message only checks
//!       VERIFY + R prefix; it does NOT pin the 65 output bytes. A nonce-
//!       derivation or challenge-serialization drift that still self-verifies
//!       would slip past it. We pin the exact bytes here.
//!   (2) kernel_sig_tag digest: blake2b_256_tagged(TAG_KERNEL_SIG, msg) for a
//!       fixed message. hash.rs::kernel_sig_tag_vector only asserts non-zero /
//!       length; the actual 32-byte digest was never frozen.
//!
//! The pinned bytes were produced ONCE by this crate's own code (legitimate for
//! a drift detector) and locked. If you intend to change them, that is a
//! consensus decision — do not "update to green" without sign-off.
//!
//! bp2 675-byte frozen vector already exists
//! (bulletproof_bp.rs::bp2_prove_with_nonce_frozen_vector) — not duplicated.

use dom_crypto::{blake2b_256_tagged, schnorr_sign, SecretKey};

const MAINNET_CHAIN_ID: [u8; 32] = [0x01u8; 32];

// ── (1) Schnorr (r,s) byte-freeze ───────────────────────────────────────────

/// Frozen 65-byte signature for sk=[1;32], msg="DOM/schnorr/v1/vector/genesis",
/// chain_id=MAINNET. Pins R(33)||s(32). Filled by the construction run.
const FROZEN_SCHNORR_SIG_HEX: &str =
    "022b18f13359ba1cc33f9afd4c65bfb0e6a5c98ad1e07b59e91a1f828fd04fe0f2\
1d47f8c39fef52c89c211ddb850c65c41c3caac82179ab36e6573c817d3147a9";

#[test]
fn schnorr_signature_bytes_are_frozen() {
    let sk = SecretKey::from_bytes(&[1u8; 32]).unwrap();
    let msg = b"DOM/schnorr/v1/vector/genesis";
    let sig = schnorr_sign(&sk, msg, &MAINNET_CHAIN_ID).unwrap();
    let got = hex::encode(sig.to_bytes());
    assert_eq!(
        got, FROZEN_SCHNORR_SIG_HEX,
        "Schnorr (r,s) drift for the genesis vector — RFC6979 nonce, \
         schnorr_challenge serialization, or k256 arithmetic changed"
    );
}

// ── (2) kernel_sig_tag digest byte-freeze ───────────────────────────────────

/// Frozen blake2b_256_tagged(TAG_KERNEL_SIG, b"DOM/kernel/v1/vector"). Filled by
/// the construction run.
const FROZEN_KERNEL_SIG_TAG_HEX: &str =
    "47374aede098f383c2acd04106dad1d11c784f5ea5766d7a7076ae68ad5d754d";

#[test]
fn kernel_sig_tag_digest_is_frozen() {
    let digest = blake2b_256_tagged(dom_core::TAG_KERNEL_SIG, b"DOM/kernel/v1/vector");
    let got = hex::encode(digest.as_bytes());
    assert_eq!(
        got, FROZEN_KERNEL_SIG_TAG_HEX,
        "kernel_sig_tag digest drift — TAG_KERNEL_SIG value, tag-length-prefix \
         framing, or Blake2b config changed"
    );
}
