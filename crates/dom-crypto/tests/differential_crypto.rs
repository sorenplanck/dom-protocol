//! Roadmap v2 Phase 2.1 — Differential cryptographic testing.
//!
//! `dom-crypto` uses two independent secp256k1 implementations:
//!
//!   * `secp256k1` (libsecp256k1 C bindings) — drives `SecretKey`,
//!     `PublicKey`, Schnorr signing.
//!   * `k256` (pure Rust elliptic-curve) — drives Pedersen commitment
//!     point math and the H generator.
//!
//! Both are linked into the same binary. If they ever disagree on a
//! basic curve operation — scalar multiplication, SEC1 compression,
//! the H generator's coordinates — the protocol immediately forks
//! itself: a commitment built through the Pedersen path would
//! contain a point an external implementation cannot verify, and a
//! Schnorr signature over a header whose root was computed via k256
//! could be accepted by one impl and rejected by another.
//!
//! This file is the differential gate. It pins three orthogonal
//! contracts:
//!
//!   1. **Public-key derivation contract** — for a battery of secret
//!      scalars (including the BIP-340 published vectors and several
//!      large/edge-case scalars), `SecretKey::public_key()` and a
//!      direct `Scalar(k) * ProjectivePoint::GENERATOR` via k256
//!      produce *byte-identical* SEC1-compressed encodings.
//!
//!   2. **BIP-340 x-only consistency** — for each BIP-340 test
//!      vector secret key, the x-coordinate of the derived public
//!      key matches the published x-only pubkey. (The full
//!      SEC1-encoded compressed pubkey is recovered with the correct
//!      0x02/0x03 parity prefix determined by the y-coordinate.)
//!
//!   3. **Pedersen commitment construction** — `Commitment::commit(v, r)`
//!      MUST equal an independently-derived `v*H + r*G` computed
//!      through raw k256 against the H generator surfaced by
//!      `h_compressed()`. Verifies that the production helper has
//!      not drifted from the textbook recipe.
//!
//! Failure here is a CONSENSUS-CRITICAL finding: two healthy nodes
//! running the same binary could otherwise produce signatures /
//! commitments that fail to verify against each other once one of
//! them upgrades a single linker dependency.
//!
//! The vectors below are deliberately self-contained — they are
//! recomputed inside the test rather than pulled from external
//! files — so the test binary is hermetic and the cross-platform CI
//! matrix (Phase 1.4) can exercise it on every host without
//! download access.

use dom_crypto::h_generator::h_compressed;
use dom_crypto::keys::SecretKey;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};

/// BIP-340 published test vectors (Schnorr secret key + x-only public
/// key, hex). Sourced from
/// `https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv`.
/// Stored inline so the test is hermetic; the secret-key bytes are
/// what we drive through `SecretKey::public_key()` and compare against
/// the expected x-coordinate.
const BIP340_VECTORS: &[(&str, &str)] = &[
    (
        "0000000000000000000000000000000000000000000000000000000000000003",
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    ),
    (
        "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    ),
    (
        "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
        "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
    ),
    (
        "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
        "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
    ),
];

/// Parse a 32-byte big-endian hex secret key into a k256 `Scalar`.
/// Returns None for scalars that are zero or ≥ n (out of range).
fn scalar_from_be_hex(hex_str: &str) -> Option<Scalar> {
    let raw = hex::decode(hex_str).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    let fb = k256::FieldBytes::from(arr);
    let ct = Scalar::from_repr(fb);
    bool::from(ct.is_some()).then(|| ct.unwrap())
}

/// Compute the SEC1-compressed public key bytes via raw k256 — the
/// differential oracle that drives every test below. Independent of
/// the `secp256k1` C-bindings path used inside `dom-crypto`.
fn k256_pubkey_compressed(secret_be_hex: &str) -> [u8; 33] {
    let scalar = scalar_from_be_hex(secret_be_hex).expect("secret in range");
    let point = ProjectivePoint::GENERATOR * scalar;
    let affine: AffinePoint = point.into();
    let encoded = affine.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

// ── (1) Cross-impl public-key derivation ─────────────────────────────────────

/// `SecretKey::public_key()` (secp256k1 C) MUST agree byte-for-byte
/// with `Scalar * G` via k256 for every published BIP-340 secret
/// key. Catches a hidden divergence between the two curve impls
/// linked into the same binary.
#[test]
fn secp256k1_and_k256_agree_on_bip340_pubkeys() {
    for (sk_hex, _x_only_hex) in BIP340_VECTORS {
        let sk_bytes = hex::decode(sk_hex).expect("hex");
        let dom_pk = SecretKey::from_bytes(&sk_bytes)
            .expect("BIP-340 secret in range")
            .public_key()
            .to_compressed_bytes();
        let k256_pk = k256_pubkey_compressed(sk_hex);
        assert_eq!(
            dom_pk,
            k256_pk,
            "secp256k1/k256 disagree on pubkey for sk={sk_hex}: \
             dom={} k256={}",
            hex::encode(dom_pk),
            hex::encode(k256_pk),
        );
    }
}

/// For each BIP-340 vector, the x-coordinate of the derived public
/// key MUST match the published x-only pubkey (BIP-340 §2.2.2). The
/// parity-prefix byte is whichever 0x02/0x03 matches the y-coordinate
/// of `sk*G`; what's pinned here is the 32-byte x-only payload.
#[test]
fn bip340_vectors_match_published_x_only_pubkeys() {
    for (sk_hex, x_only_hex) in BIP340_VECTORS {
        let sk_bytes = hex::decode(sk_hex).expect("hex");
        let pk = SecretKey::from_bytes(&sk_bytes)
            .expect("BIP-340 secret")
            .public_key()
            .to_compressed_bytes();
        // Strip the parity prefix and compare 32-byte x-only.
        let derived_x = hex::encode(&pk[1..]).to_uppercase();
        assert_eq!(
            derived_x, *x_only_hex,
            "x-coordinate drift for sk={sk_hex}: derived={derived_x} expected={x_only_hex}"
        );
        assert!(
            pk[0] == 0x02 || pk[0] == 0x03,
            "SEC1 parity byte must be 0x02 or 0x03, got 0x{:02x}",
            pk[0]
        );
    }
}

/// Sweep an additional set of edge-case scalars (small, large near n,
/// non-trivial bit patterns) — the differential agreement MUST hold
/// across the entire scalar space, not just the published vectors.
#[test]
fn secp256k1_and_k256_agree_across_extra_scalars() {
    let extra: &[&str] = &[
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "00000000000000000000000000000000000000000000000000000000DEADBEEF",
        "8000000000000000000000000000000000000000000000000000000000000000",
        // n - 1 for secp256k1 (curve order minus one).
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
        // Half of the curve order (mid-range).
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
    ];
    for sk_hex in extra {
        let sk_bytes = hex::decode(sk_hex).expect("hex");
        let dom_pk = SecretKey::from_bytes(&sk_bytes)
            .expect("scalar in range")
            .public_key()
            .to_compressed_bytes();
        let k256_pk = k256_pubkey_compressed(sk_hex);
        assert_eq!(
            dom_pk, k256_pk,
            "differential pubkey mismatch at sk={sk_hex}"
        );
    }
}

// ── (2) Pedersen commitment differential ─────────────────────────────────────

/// Decompose `Commitment::commit(v, r)` by recomputing `v*H + r*G`
/// directly through raw k256 — independent of the production path
/// inside `pedersen.rs`. The SEC1-compressed outputs MUST be
/// byte-identical.
///
/// Coverage:
///   * v=0 (zero-value commitment)
///   * v=1 (smallest non-zero)
///   * v=MAX_SUPPLY_NOMS (largest legitimate value)
///   * mixed blinding patterns (zeros, all-ones, deterministic seeds)
#[test]
fn pedersen_commit_matches_independent_k256_recompute() {
    let h_compressed_bytes = h_compressed().expect("H generator must be valid");
    let h_encoded = EncodedPoint::from_bytes(h_compressed_bytes).expect("H SEC1 decode");
    let h_affine = AffinePoint::from_encoded_point(&h_encoded);
    let h_affine = Option::<AffinePoint>::from(h_affine).expect("H must lie on the curve");
    let h_point = ProjectivePoint::from(h_affine);
    let g_point = ProjectivePoint::GENERATOR;

    // (value, blinding_bytes) fixture set. The blinding bytes must be
    // < curve order; the high-bit-cleared seeds below are all safely
    // within range.
    let fixtures: &[(u64, [u8; 32])] = &[
        (0, [0x11u8; 32]),
        (1, [0x22u8; 32]),
        (1_000_000_000, [0x33u8; 32]),
        (dom_core::MAX_SUPPLY_NOMS, [0x44u8; 32]),
        (33, [0x55u8; 32]),
        // Deterministic ramp blinding.
        (42, {
            let mut b = [0u8; 32];
            for (i, v) in b.iter_mut().enumerate() {
                *v = (i as u8) ^ 0x5A;
            }
            b
        }),
    ];

    for (value, blinding_raw) in fixtures {
        // High bit cleared keeps the scalar safely below the curve
        // order for every fixture (curve order's top byte is 0xFF
        // followed by bytes <= 0xFE, so clearing 0x80 is sufficient
        // for this test's purposes; the production BlindingFactor
        // parsing rejects out-of-range bytes regardless).
        let mut b = *blinding_raw;
        b[0] &= 0x7F;
        let bf = BlindingFactor::from_bytes(b).expect("blinding in range");
        let dom_commit = Commitment::commit(*value, &bf);

        // Recompute v*H + r*G via raw k256.
        let v_scalar = Scalar::from(*value);
        let r_fb = k256::FieldBytes::from(b);
        let r_scalar_ct = Scalar::from_repr(r_fb);
        let r_scalar = Option::<Scalar>::from(r_scalar_ct).expect("r in range");
        let oracle = h_point * v_scalar + g_point * r_scalar;
        let oracle_affine: AffinePoint = oracle.into();
        let oracle_encoded = oracle_affine.to_encoded_point(true);

        assert_eq!(
            dom_commit.as_bytes() as &[u8],
            oracle_encoded.as_bytes(),
            "Commitment::commit drifted from textbook v*H + r*G at \
             (value={value}, blinding=0x{}): production={} oracle={}",
            hex::encode(b),
            hex::encode(dom_commit.as_bytes()),
            hex::encode(oracle_encoded.as_bytes()),
        );
    }
}

/// Pedersen commitment encoding contract: the production output
/// MUST be a SEC1-compressed 33-byte point with a 0x02/0x03 prefix
/// (never uncompressed, never identity). Pinned across the fixture
/// set to catch any latent reintroduction of a different encoding.
#[test]
fn pedersen_commit_encoding_is_sec1_compressed() {
    let bf = BlindingFactor::from_bytes([0x33u8; 32]).expect("valid blinding");
    for value in [0u64, 1, 33, 1_000_000_000, dom_core::MAX_SUPPLY_NOMS] {
        let c = Commitment::commit(value, &bf);
        let bytes = c.as_bytes();
        assert_eq!(bytes.len(), 33);
        assert!(
            bytes[0] == 0x02 || bytes[0] == 0x03,
            "commitment at v={value} not SEC1-compressed: prefix=0x{:02x}",
            bytes[0]
        );
    }
}

// ── (3) Round-trip determinism (within a single impl) ────────────────────────

/// Within a single binary, the production path MUST be deterministic
/// across rebuilds: the same `(value, blinding)` always yields the
/// same commitment bytes. Catches a latent reintroduction of random
/// nonce / hidden state inside the commitment helper.
#[test]
fn pedersen_commit_is_deterministic_across_repeats() {
    let bf = BlindingFactor::from_bytes([0x77u8; 32]).expect("valid blinding");
    let c0 = Commitment::commit(33_000_000, &bf);
    for _ in 0..32 {
        let cn = Commitment::commit(33_000_000, &bf);
        assert_eq!(c0, cn);
    }
}

// ── (4) Cross-impl scalar arithmetic sanity ──────────────────────────────────

/// Adding two SEC1 points via dom-crypto's `Commitment::add` MUST
/// agree with adding the two underlying projective points through
/// raw k256 — the same differential split as for `commit`, applied
/// to the homomorphic property the protocol relies on for cut-through
/// and balance-equation verification.
#[test]
fn commitment_add_matches_k256_projective_add() {
    let bf_a = BlindingFactor::from_bytes([0x12u8; 32]).expect("a");
    let bf_b = BlindingFactor::from_bytes([0x34u8; 32]).expect("b");
    let c_a = Commitment::commit(100, &bf_a);
    let c_b = Commitment::commit(200, &bf_b);
    let dom_sum = c_a.add(&c_b).expect("sum");

    // Independent recompute.
    let enc_a = EncodedPoint::from_bytes(c_a.as_bytes() as &[u8]).expect("enc a");
    let enc_b = EncodedPoint::from_bytes(c_b.as_bytes() as &[u8]).expect("enc b");
    let aff_a =
        Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&enc_a)).expect("a on curve");
    let aff_b =
        Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&enc_b)).expect("b on curve");
    let p_a = ProjectivePoint::from(aff_a);
    let p_b = ProjectivePoint::from(aff_b);
    let oracle: AffinePoint = (p_a + p_b).into();
    let oracle_enc = oracle.to_encoded_point(true);

    assert_eq!(dom_sum.as_bytes() as &[u8], oracle_enc.as_bytes());
}

// ── (5) k256 SEC1 round-trip ────────────────────────────────────────────────

/// Sanity baseline: a SEC1-compressed commitment round-trips through
/// `from_compressed_bytes` → `as_bytes` without modification. Catches
/// a regression where the parser would silently re-encode (e.g. via
/// a non-canonical y-coordinate path).
#[test]
fn commitment_sec1_roundtrip_is_byte_identical() {
    let bf = BlindingFactor::from_bytes([0xABu8; 32]).expect("valid");
    let c = Commitment::commit(99, &bf);
    let parsed = Commitment::from_compressed_bytes(c.as_bytes() as &[u8]).expect("parse");
    assert_eq!(c, parsed);
    assert_eq!(c.as_bytes() as &[u8], parsed.as_bytes() as &[u8]);
}
