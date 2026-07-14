//! Adversarial SOUNDNESS suite for the standard-Bulletproof production verifier
//! (`bp2_verify`, grin backend), mirroring the final range-proof API vectors
//! against the compatibility bp2 API (`bp2_prove` / `bp2_prove_with_nonce` /
//! `bp2_verify`).
//!
//! Scope is deliberately the GAPS not already covered elsewhere, to avoid
//! duplication:
//!   - happy-path / consensus-shape, single-byte tamper, cross-commitment
//!     commit-A-vs-B, and the size-serialization envelope are covered by
//!     `dom-consensus/tests/bulletproof_bp_consensus.rs`;
//!   - the exact-size gate (empty / != 739 / 739-malformed) is covered by
//!     `bulletproof_bp::tests::ds001_proof_size_must_be_exact`;
//!   - the wrong-H generator binding is covered in-crate by `binding_matrix`.
//!
//! What this file adds:
//!   1. Boundary value sweep (0, 1, 2^k, 2^k-1 for k=1..=51, MAX_PROVABLE_VALUE,
//!      MAX_SUPPLY_NOMS) — each MUST prove + verify clean.
//!   2. Single-bit mutation across the proof — MUST never verify true.
//!   3. Garbage proofs of EXACTLY 739 bytes — MUST never verify true.
//!   4. Cross-commitment, same blinding / different value (2nd variant).
//!   5. Out-of-range values rejected at prove-time, before any FFI.
//!   6. `bp2_prove_with_nonce` determinism (byte-identical proofs).

use dom_crypto::pedersen::BlindingFactor;
use dom_crypto::{bp2_prove, bp2_prove_with_nonce, bp2_verify, MAX_PROVABLE_VALUE};

/// Exact serialized length of DOM's bounded aggregate bp2 proof.
const BP2_PROOF_LEN: usize = 739;

/// Deterministic, always-valid blinding from a seed byte (non-zero, well below
/// the curve order.
fn blinding(seed: u8) -> BlindingFactor {
    let mut b = [0u8; 32];
    b[31] = seed;
    b[0] = 0x01; // ensure non-zero and well below curve order
    BlindingFactor::from_bytes(b).expect("valid blinding")
}

/// A deterministic valid (proof, commitment) pair via the fixed-nonce prover, so
/// individual failures reproduce across runs.
fn deterministic_proof(value: u64, seed: u8) -> (Vec<u8>, [u8; 33]) {
    let bf = blinding(seed);
    let mut nonce = [0u8; 32];
    nonce[0] = 0x42;
    nonce[31] = seed;
    bp2_prove_with_nonce(value, &bf, &nonce).expect("bp2 prove must succeed for in-range value")
}

// ── (1) Boundary value sweep ─────────────────────────────────────────────────

/// Every consensus-relevant value boundary MUST prove + verify round-trip clean
/// through the production bp2 path. Catches the boundary-bug class where the
/// verifier accepts only a strict subset of the declared 52-bit range.
#[test]
fn bp2_boundary_values_prove_and_verify() {
    let bf = blinding(0xAB);

    // 0, 1, then 2^k and 2^k - 1 for k = 1..=51, plus MAX_PROVABLE_VALUE (2^52-1)
    // and the protocol supply cap MAX_SUPPLY_NOMS.
    let mut values: Vec<u64> = vec![0, 1];
    for k in 1u64..=51 {
        values.push(1u64 << k);
        values.push((1u64 << k) - 1);
    }
    values.push(MAX_PROVABLE_VALUE);
    values.push(dom_core::MAX_SUPPLY_NOMS);

    for v in values {
        let (proof, commit) = bp2_prove(v, &bf).expect("bp2 prove in-range");
        assert_eq!(
            proof.len(),
            BP2_PROOF_LEN,
            "proof for v={v} must be 739 bytes"
        );
        let ok = bp2_verify(&commit, &proof).expect("bp2 verify must run");
        assert!(
            ok,
            "valid proof at boundary v={v} unexpectedly failed verify"
        );
    }
}

// ── (2) Single-bit mutation ──────────────────────────────────────────────────

/// Flipping any single bit in a valid proof MUST cause `bp2_verify` to either
/// reject (`Ok(false)`) or error (`Err`) — never `Ok(true)`. Exhaustive bit
/// coverage would be ~5400 verifications; sample one bit per 4th byte (a wide
/// spread across the proof) plus the last byte explicitly.
#[test]
fn bp2_single_bit_mutation_invalidates() {
    let (proof, commit) = deterministic_proof(33_000_000, 0x55);
    assert_eq!(proof.len(), BP2_PROOF_LEN);

    let mut tried = 0usize;
    let mut caught = 0usize;
    let mut check = |mutated: &[u8], where_: String| {
        tried += 1;
        match bp2_verify(&commit, mutated) {
            Ok(false) | Err(_) => caught += 1,
            Ok(true) => panic!("single-bit mutation {where_} unexpectedly verified TRUE"),
        }
    };

    // One bit (bit 0) per 4th byte.
    for byte_idx in (0..proof.len()).step_by(4) {
        let mut mutated = proof.clone();
        mutated[byte_idx] ^= 0x01;
        check(&mutated, format!("byte {byte_idx} bit 0"));
    }

    // The last byte explicitly (common truncation/rebuild target), all 8 bits.
    let last = proof.len() - 1;
    for bit in 0..8u8 {
        let mut mutated = proof.clone();
        mutated[last] ^= 1 << bit;
        check(&mutated, format!("last byte {last} bit {bit}"));
    }

    assert_eq!(
        caught, tried,
        "every sampled single-bit mutation must invalidate the proof; caught {caught}/{tried}"
    );
}

// ── (3) Garbage proofs of exactly 739 bytes ──────────────────────────────────

/// Garbage buffers of EXACTLY 739 bytes (so they clear the size gate and reach
/// the grin verifier) MUST NOT verify against a valid commitment. Off-size
/// garbage is already rejected by the size gate (`ds001_proof_size_must_be_exact`),
/// so this targets the verifier's own soundness on right-sized junk.
#[test]
fn bp2_garbage_exact_739_never_verifies() {
    let bf = blinding(0x77);
    let (_real, commit) = bp2_prove(1, &bf).expect("bp2 prove control");

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("all zeros", vec![0u8; BP2_PROOF_LEN]),
        ("all 0xFF", vec![0xFFu8; BP2_PROOF_LEN]),
        (
            "ramp 0..255",
            (0u8..=255).cycle().take(BP2_PROOF_LEN).collect(),
        ),
        (
            "alternating 0xAA/0x55",
            [0xAAu8, 0x55]
                .iter()
                .copied()
                .cycle()
                .take(BP2_PROOF_LEN)
                .collect(),
        ),
    ];

    for (label, garbage) in &cases {
        assert_eq!(
            garbage.len(),
            BP2_PROOF_LEN,
            "garbage '{label}' must be 739 bytes"
        );
        let verified = matches!(bp2_verify(&commit, garbage), Ok(true));
        assert!(
            !verified,
            "garbage proof '{label}' (739B) unexpectedly verified TRUE"
        );
    }
}

// ── (4) Cross-commitment: same blinding, different value (2nd variant) ────────

/// A proof bound to (v1, blind) MUST NOT verify against the commitment of
/// (v2, blind) with v1 != v2 and the SAME blinding. Catches a verifier that
/// ignores the value-side contribution of the commitment. (The commit-A-vs-B
/// variant with different blindings is covered in the consensus suite.)
#[test]
fn bp2_cross_commitment_same_blinding_diff_value() {
    let bf = blinding(0x33);
    let mut nonce = [0u8; 32];
    nonce[0] = 0x42;
    nonce[31] = 0x33;

    let (proof_v1, commit_v1) = bp2_prove_with_nonce(100, &bf, &nonce).expect("prove v1");
    let (_proof_v2, commit_v2) = bp2_prove_with_nonce(101, &bf, &nonce).expect("prove v2");

    assert_ne!(
        commit_v1, commit_v2,
        "different value with same blinding MUST give a different commitment"
    );
    let ok = matches!(bp2_verify(&commit_v2, &proof_v1), Ok(true));
    assert!(
        !ok,
        "proof for v=100 verified against commitment of v=101 (same blinding) — soundness break"
    );
}

// ── (5) Out-of-range value rejected at prove-time ────────────────────────────

/// Values strictly above MAX_PROVABLE_VALUE MUST be rejected by `bp2_prove`
/// before any range-proof generation (no FFI, no proof produced).
#[test]
fn bp2_out_of_range_rejected_at_prove_time() {
    let bf = blinding(0x88);
    let above_band: &[u64] = &[MAX_PROVABLE_VALUE + 1, 1u64 << 53, 1u64 << 62, u64::MAX];
    for &v in above_band {
        assert!(
            bp2_prove(v, &bf).is_err(),
            "value {v} > MAX_PROVABLE_VALUE must be rejected at prove-time"
        );
    }
}

// ── (6) Deterministic-nonce reproducibility ──────────────────────────────────

/// `bp2_prove_with_nonce` MUST be byte-deterministic across repeated invocations
/// with the same (value, blinding, nonce) — the property genesis reproducibility
/// relies on.
#[test]
fn bp2_prove_with_nonce_is_deterministic() {
    let bf = blinding(0xAA);
    let nonce = [0x77u8; 32];
    let v = 33_000_000u64;

    let (proof_a, commit_a) = bp2_prove_with_nonce(v, &bf, &nonce).expect("prove a");
    assert_eq!(proof_a.len(), BP2_PROOF_LEN);
    for _ in 0..8 {
        let (proof_b, commit_b) = bp2_prove_with_nonce(v, &bf, &nonce).expect("prove b");
        assert_eq!(
            proof_a, proof_b,
            "bp2 proof bytes drifted across identical inputs"
        );
        assert_eq!(commit_a, commit_b, "bp2 commitment bytes drifted");
    }
    // Sanity: the deterministic proof actually verifies.
    assert!(
        bp2_verify(&commit_a, &proof_a).expect("verify runs"),
        "deterministic proof must verify true"
    );
}
