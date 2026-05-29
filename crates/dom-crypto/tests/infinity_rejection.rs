//! Roadmap v2 Phase 2.2 — Explicit infinity / identity rejection.
//!
//! The secp256k1 group identity (point at infinity) is encoded in
//! SEC1 as a single 0x00 byte; in 33-byte compressed form it
//! corresponds to the all-zero buffer `[0x00; 33]`. Identity is a
//! valid group element, so a straight `from_encoded_point` round-trip
//! parses it successfully — but it MUST NOT appear in any DOM wire
//! field. Each consensus surface has a specific reason:
//!
//!   * `PublicKey` — identity has no discrete log; signatures over
//!     such a key are forgeable.
//!   * `Commitment` — identity corresponds to a "trivially balanced"
//!     commitment (v=0, r=0). It would let a tx claim arbitrary
//!     hidden value while passing the balance equation.
//!   * `SchnorrSignature::R` — identity R sets the challenge input
//!     to a deterministic constant; the signer can solve for s
//!     without knowledge of the secret key.
//!   * Secret scalars — zero secret keys map to identity public keys
//!     and break every cryptographic security argument.
//!
//! Each test below pins one entry point. Several of them ALREADY
//! reject identity inputs at the boundary; the tests are regression
//! gates that catch any future refactor that loosens the parsing
//! layer.

use dom_crypto::keys::{PublicKey, SecretKey};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::schnorr::SchnorrSignature;

// ── (1) PublicKey parsing rejects identity + invalid prefixes ────────────────

/// A 33-byte all-zero buffer is the canonical SEC1 encoding of the
/// point at infinity. `PublicKey::from_compressed_bytes` MUST reject
/// it — both because the prefix byte (0x00) is not 0x02/0x03 and
/// because the underlying secp256k1 parser refuses identity.
#[test]
fn public_key_rejects_identity_all_zero() {
    let buf = [0u8; 33];
    let err = PublicKey::from_compressed_bytes(&buf).expect_err(
        "PublicKey::from_compressed_bytes MUST reject the all-zero SEC1 buffer (identity)",
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("0x02 or 0x03") || msg.contains("invalid"),
        "rejection must point at the prefix or curve validity, got: {msg}"
    );
}

/// SEC1 uncompressed prefix (0x04) MUST be rejected — DOM is
/// strict-compressed-only on the wire.
#[test]
fn public_key_rejects_uncompressed_prefix() {
    let mut buf = [0u8; 33];
    buf[0] = 0x04;
    assert!(PublicKey::from_compressed_bytes(&buf).is_err());
}

/// Hybrid SEC1 prefixes (0x06, 0x07) MUST be rejected.
#[test]
fn public_key_rejects_hybrid_prefixes() {
    for prefix in [0x06u8, 0x07] {
        let mut buf = [0u8; 33];
        buf[0] = prefix;
        assert!(
            PublicKey::from_compressed_bytes(&buf).is_err(),
            "prefix 0x{prefix:02x} must be rejected"
        );
    }
}

/// A 33-byte buffer with a valid 0x02 prefix but an x-coordinate
/// that is not on the curve MUST be rejected. Pinning here so a
/// future loosening of the parser cannot accept off-curve x-coords.
#[test]
fn public_key_rejects_off_curve_x_coordinate() {
    // x = 0 is not the x-coordinate of any curve point on secp256k1.
    let mut buf = [0u8; 33];
    buf[0] = 0x02;
    // bytes 1..33 stay zero — x = 0.
    assert!(PublicKey::from_compressed_bytes(&buf).is_err());
}

// ── (2) SecretKey rejects zero + out-of-range ────────────────────────────────

/// `SecretKey::from_bytes([0; 32])` MUST be rejected — a zero secret
/// key produces the identity public key (no discrete log).
#[test]
fn secret_key_rejects_zero() {
    let buf = [0u8; 32];
    assert!(
        SecretKey::from_bytes(&buf).is_err(),
        "secret key of zero must be rejected"
    );
}

/// Secret keys greater than or equal to the curve order n MUST be
/// rejected. `n = FFFFFFFF...FFFE BAAEDCE6 AF48A03B BFD25E8C D0364141`.
#[test]
fn secret_key_rejects_n_and_above() {
    // Curve order n exactly.
    let n: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    assert!(SecretKey::from_bytes(&n).is_err(), "n must be rejected");

    // n + 1.
    let mut n_plus_one = n;
    n_plus_one[31] = n_plus_one[31].wrapping_add(1);
    assert!(
        SecretKey::from_bytes(&n_plus_one).is_err(),
        "n+1 must be rejected"
    );

    // 2^256 - 1 (all ones, biggest possible 32-byte BE integer).
    let all_ones = [0xFFu8; 32];
    assert!(
        SecretKey::from_bytes(&all_ones).is_err(),
        "2^256 - 1 must be rejected"
    );
}

/// Conversely, `n - 1` MUST be ACCEPTED — it's the largest valid
/// scalar. Sanity baseline to catch an over-strict rejection that
/// drops legitimate keys.
#[test]
fn secret_key_accepts_n_minus_one() {
    let n_minus_one: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x40,
    ];
    SecretKey::from_bytes(&n_minus_one).expect("n-1 must be accepted");
}

// ── (3) BlindingFactor rejects zero + out-of-range ───────────────────────────

/// Zero blinding factor MUST be rejected. r=0 reduces a Pedersen
/// commitment to v*H — anyone who knows v can recompute it, which
/// breaks the hiding property.
#[test]
fn blinding_factor_rejects_zero() {
    assert!(BlindingFactor::from_bytes([0u8; 32]).is_err());
}

/// Blinding factor ≥ n MUST be rejected.
#[test]
fn blinding_factor_rejects_out_of_range() {
    let n: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    assert!(BlindingFactor::from_bytes(n).is_err());
    assert!(BlindingFactor::from_bytes([0xFFu8; 32]).is_err());
}

// ── (4) Commitment rejects identity (all-zero SEC1) ──────────────────────────

/// The all-zero SEC1 encoding `[0x00; 33]` decodes to the secp256k1
/// identity. `Commitment::from_compressed_bytes` MUST refuse it — a
/// commitment-at-identity carries no value or blinding information
/// and would trivially balance any cut-through equation.
#[test]
fn commitment_rejects_identity_all_zero() {
    let buf = [0u8; 33];
    assert!(
        Commitment::from_compressed_bytes(&buf).is_err(),
        "Commitment::from_compressed_bytes MUST reject the all-zero SEC1 buffer (identity)"
    );
}

/// SEC1 uncompressed (0x04) prefix MUST be rejected by the
/// commitment parser too.
#[test]
fn commitment_rejects_uncompressed_prefix() {
    let mut buf = [0u8; 33];
    buf[0] = 0x04;
    assert!(Commitment::from_compressed_bytes(&buf).is_err());
}

/// An x-coordinate ≥ the secp256k1 field modulus is not a valid
/// field element and MUST be rejected. Uses x = p exactly
/// (`FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F`)
/// so the SEC1 parser refuses before any curve-equation check runs.
#[test]
fn commitment_rejects_x_at_field_modulus() {
    let mut buf = [0u8; 33];
    buf[0] = 0x02;
    let p: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
        0xFC, 0x2F,
    ];
    buf[1..33].copy_from_slice(&p);
    assert!(
        Commitment::from_compressed_bytes(&buf).is_err(),
        "x = field modulus must be rejected — not a valid field element"
    );
}

// ── (5) SchnorrSignature rejects identity R + invalid s ──────────────────────

/// Schnorr `R` is parsed through `PublicKey::from_compressed_bytes`,
/// so the all-zero R buffer is rejected as part of signature parsing.
/// Pin this contract here so a future refactor cannot loosen R
/// parsing independent of the public-key one.
#[test]
fn schnorr_rejects_identity_r() {
    let mut sig_bytes = [0u8; 65];
    // R = identity (all zero), s = 1 (well-formed scalar).
    sig_bytes[33] = 0u8; // s bytes 0..31 stay zero
    sig_bytes[64] = 1u8; // s last byte = 1 → scalar value 1, valid
    let err = SchnorrSignature::from_bytes(&sig_bytes).expect_err("identity R must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("0x02 or 0x03") || msg.contains("invalid"),
        "rejection should mention the prefix or validity, got: {msg}"
    );
}

/// s = 0 (zero scalar) MUST be rejected. A zero s lets the verifier
/// equation degenerate to checking R == c*P, which is solvable
/// without knowledge of the secret key.
#[test]
fn schnorr_rejects_zero_s() {
    let mut sig_bytes = [0u8; 65];
    // R = valid (use generator G = 02||x_of_G).
    // x of G:
    let g_x: [u8; 32] = [
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8,
        0x17, 0x98,
    ];
    sig_bytes[0] = 0x02;
    sig_bytes[1..33].copy_from_slice(&g_x);
    // s stays all zero → scalar value 0, must be rejected.
    let err = SchnorrSignature::from_bytes(&sig_bytes).expect_err("s = 0 must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("zero") || msg.contains("range") || msg.contains("scalar"),
        "rejection should mention zero/range/scalar, got: {msg}"
    );
}

/// s ≥ n MUST be rejected.
#[test]
fn schnorr_rejects_s_out_of_range() {
    let mut sig_bytes = [0u8; 65];
    let g_x: [u8; 32] = [
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8,
        0x17, 0x98,
    ];
    sig_bytes[0] = 0x02;
    sig_bytes[1..33].copy_from_slice(&g_x);
    // s = all-ones (well above n).
    for b in &mut sig_bytes[33..65] {
        *b = 0xFF;
    }
    assert!(SchnorrSignature::from_bytes(&sig_bytes).is_err());
}

// ── (6) Wrong signature length ────────────────────────────────────────────────

/// SchnorrSignature MUST be exactly 65 bytes — 33 (R compressed) + 32 (s).
#[test]
fn schnorr_rejects_wrong_length() {
    for len in [0usize, 1, 32, 64, 66, 130] {
        let buf = vec![0u8; len];
        assert!(
            SchnorrSignature::from_bytes(&buf).is_err(),
            "len={len} must be rejected (only 65 is valid)"
        );
    }
}
