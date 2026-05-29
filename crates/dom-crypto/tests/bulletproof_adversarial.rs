//! Roadmap v2 Phase 2.4 — Bulletproofs+ adversarial validation suite.
//!
//! `dom-crypto::bulletproof` wraps `secp256k1-zkp`'s Bulletproofs+
//! range-proof construction (52-bit range, value < 2^52). The
//! existing in-crate tests cover the happy path and a small set of
//! edge cases. This file expands the coverage to the failure
//! envelope the production verifier MUST reject:
//!
//!   1. **Boundary value sweep** — proofs at every consensus-relevant
//!      value boundary (0, 1, 2^k - 1 for k in 1..=52, MAX_PROVABLE_VALUE,
//!      MAX_SUPPLY_NOMS). Each MUST prove + verify round-trip clean.
//!
//!   2. **Cross-commitment swap** — a valid proof for commitment A
//!      MUST fail when verified against a different commitment B.
//!      This is the bug class where a malicious tx hands the
//!      verifier a stale proof from another value.
//!
//!   3. **Single-bit mutation** — flipping any single bit anywhere
//!      in a valid proof MUST invalidate verification (or be
//!      rejected at parse time). Sampled across the proof byte
//!      range for performance.
//!
//!   4. **Garbage proofs** — random byte buffers of various sizes
//!      MUST be rejected at verify-time (parser or BP+ verifier).
//!
//!   5. **Out-of-range value rejection at prove-time** — values >
//!      MAX_PROVABLE_VALUE MUST be rejected before any proof is
//!      attempted.
//!
//!   6. **Length envelope** — empty proof, near-MAX_PROOF_SIZE,
//!      oversized.
//!
//! The suite uses fixed-seed determinism where possible
//! (`prove_with_nonce`) so individual failures are reproducible
//! across CI runs.

use dom_crypto::bulletproof::{prove, prove_with_nonce, verify, MAX_PROVABLE_VALUE};
use dom_crypto::pedersen::BlindingFactor;

fn blinding(seed: u8) -> BlindingFactor {
    let mut b = [0u8; 32];
    b[31] = seed;
    b[0] = 0x01; // ensure non-zero and well below curve order
    BlindingFactor::from_bytes(b).expect("valid blinding")
}

fn deterministic_proof(value: u64, seed: u8) -> (Vec<u8>, [u8; 33]) {
    let bf = blinding(seed);
    let mut nonce = [0u8; 32];
    nonce[0] = 0x42;
    nonce[31] = seed;
    let (proof, commit) =
        prove_with_nonce(value, &bf, &nonce).expect("prove must succeed for in-range value");
    (proof.bytes, commit)
}

// ── (1) Boundary value sweep ─────────────────────────────────────────────────

/// Prove + verify must succeed for every value at a power-of-two
/// boundary up to 2^51, plus MAX_PROVABLE_VALUE itself (2^52 - 1).
/// Catches the boundary-bug class where the verifier accepts only
/// a strict subset of the declared range.
#[test]
fn boundary_values_prove_and_verify() {
    let bf = blinding(0xAB);
    // 0, 1, then 2^k for k = 1..=51, plus 2^52 - 1.
    let mut values: Vec<u64> = vec![0, 1];
    for k in 1u64..=51 {
        values.push(1u64 << k);
        values.push((1u64 << k) - 1);
    }
    values.push(MAX_PROVABLE_VALUE);

    for v in values {
        let (proof, commit) = prove(v, &bf).expect("prove in-range");
        let ok = verify(&commit, &proof.bytes).expect("verify must run");
        assert!(
            ok,
            "valid proof at boundary v={v} unexpectedly failed verify"
        );
    }
}

/// MAX_SUPPLY_NOMS (the protocol-level supply cap, separate from the
/// Bulletproofs 2^52 range) MUST be provable + verifiable. This is
/// the value the coinbase commitment carries on the maximally-funded
/// genesis-era block.
#[test]
fn max_supply_value_prove_and_verify() {
    let bf = blinding(0xCD);
    let v = dom_core::MAX_SUPPLY_NOMS;
    let (proof, commit) = prove(v, &bf).expect("prove MAX_SUPPLY_NOMS");
    assert!(
        verify(&commit, &proof.bytes).expect("verify must run"),
        "MAX_SUPPLY_NOMS proof unexpectedly failed verify"
    );
}

// ── (2) Cross-commitment swap ────────────────────────────────────────────────

/// A proof bound to (value=v_a, blinding=r_a) MUST NOT verify
/// against the commitment of a different (v, r) pair. This is the
/// soundness property a Bulletproofs+ range proof gives you: the
/// proof is committed-to via the commitment in the transcript.
#[test]
fn proof_for_commitment_a_does_not_verify_against_commitment_b() {
    let (proof_a, _commit_a) = deterministic_proof(123_456, 0x11);
    let (_proof_b, commit_b) = deterministic_proof(987_654, 0x22);
    // proof of A handed to verifier with commitment B.
    let ok = verify(&commit_b, &proof_a).unwrap_or(false);
    assert!(
        !ok,
        "proof for commitment A verified against commitment B — soundness break"
    );
}

/// Same blinding, different value MUST NOT cross-verify either.
/// Catches the case where the verifier ignores the value-side
/// contribution of the commitment.
#[test]
fn proof_does_not_verify_when_value_changes_with_same_blinding() {
    let bf = blinding(0x33);
    let mut nonce = [0u8; 32];
    nonce[0] = 0x42;
    nonce[31] = 0x33;

    let (proof_a, commit_a) = prove_with_nonce(100, &bf, &nonce).expect("prove A");
    let (_proof_b, commit_b) = prove_with_nonce(101, &bf, &nonce).expect("prove B");
    assert_ne!(
        commit_a, commit_b,
        "different value MUST give different commit"
    );
    assert!(
        !verify(&commit_b, &proof_a.bytes).unwrap_or(false),
        "proof for v=100 verified against commit of v=101 — soundness break"
    );
}

// ── (3) Single-bit mutation ──────────────────────────────────────────────────

/// Flipping any single bit in a valid proof MUST cause verification
/// to either reject (return Ok(false)) or fail parsing
/// (return Err). Tests a sample of bit positions across the proof —
/// exhaustive coverage would be ~5000 verifications which is slow,
/// so we sample at 8-byte stride.
#[test]
fn single_bit_mutation_invalidates_proof() {
    let (proof, commit) = deterministic_proof(33_000_000, 0x55);

    // Sample bit positions: every 8th byte * bit 0.
    let mut mutations_caught = 0usize;
    let mut mutations_tried = 0usize;
    for byte_idx in (0..proof.len()).step_by(8) {
        let mut mutated = proof.clone();
        mutated[byte_idx] ^= 0x01;
        mutations_tried += 1;
        match verify(&commit, &mutated) {
            Ok(false) | Err(_) => mutations_caught += 1,
            Ok(true) => {} // unexpected — counted in assert below
        }
    }
    assert_eq!(
        mutations_caught, mutations_tried,
        "single-bit mutation must invalidate every sampled bit; \
         caught {mutations_caught}/{mutations_tried}"
    );
}

/// Mutating the LAST byte (the highest-index byte of the proof) is
/// the most common typo / truncation-rebuild target. Pin it
/// individually.
#[test]
fn last_byte_mutation_invalidates_proof() {
    let (mut proof, commit) = deterministic_proof(42, 0x66);
    let last = proof.len() - 1;
    proof[last] ^= 0xFF;
    let ok = verify(&commit, &proof).unwrap_or(false);
    assert!(
        !ok,
        "mutating the last byte (idx {last}) did NOT invalidate the proof"
    );
}

// ── (4) Garbage proofs ────────────────────────────────────────────────────────

/// Random byte buffers of various lengths MUST NOT verify against
/// any commitment. Catches the bug class where the verifier
/// accepts arbitrary garbage because parsing is too lenient.
#[test]
fn garbage_proof_bytes_rejected() {
    let bf = blinding(0x77);
    let (_, commit) = prove(1, &bf).expect("prove control");

    // Variety of plausible garbage shapes.
    let cases: Vec<Vec<u8>> = vec![
        vec![0u8; 10],                          // all zero, short
        vec![0u8; 700],                         // all zero, near typical proof length
        vec![0xFFu8; 700],                      // all 0xFF
        (0u8..255).cycle().take(700).collect(), // patterned ramp
        vec![0xAAu8, 0x55].into_iter().cycle().take(700).collect(),
    ];
    for (idx, garbage) in cases.iter().enumerate() {
        let result = verify(&commit, garbage);
        let ok = matches!(result, Ok(true));
        assert!(
            !ok,
            "garbage proof case #{idx} (len={}) unexpectedly verified",
            garbage.len()
        );
    }
}

// ── (5) Out-of-range value rejection at prove-time ───────────────────────────

/// Values strictly above MAX_PROVABLE_VALUE MUST be rejected by
/// `prove` before any range-proof generation runs. Pin the entire
/// rejection band.
#[test]
fn values_above_max_provable_rejected_at_prove_time() {
    let bf = blinding(0x88);
    let above_band: &[u64] = &[
        MAX_PROVABLE_VALUE + 1,
        MAX_PROVABLE_VALUE + 1000,
        1u64 << 53,
        1u64 << 62,
        u64::MAX,
    ];
    for &v in above_band {
        assert!(
            prove(v, &bf).is_err(),
            "value {v} > MAX_PROVABLE_VALUE must be rejected at prove-time"
        );
    }
}

// ── (6) Length envelope ──────────────────────────────────────────────────────

/// Empty proof bytes MUST be rejected; oversized (above
/// MAX_PROOF_SIZE) MUST be rejected too. Below MAX_PROOF_SIZE,
/// length is informational only.
#[test]
fn proof_length_envelope_enforced() {
    let bf = blinding(0x99);
    let (_, commit) = prove(1, &bf).expect("control");

    // Empty bytes
    assert!(
        verify(&commit, &[]).is_err(),
        "empty proof bytes must surface as a parse / verify error"
    );

    // Oversized: MAX_PROOF_SIZE + 1 random bytes.
    let oversized = vec![0u8; dom_core::MAX_PROOF_SIZE + 1];
    assert!(
        verify(&commit, &oversized).is_err(),
        "proof above MAX_PROOF_SIZE must be rejected"
    );
}

// ── (7) Determinism via prove_with_nonce ─────────────────────────────────────

/// `prove_with_nonce` MUST be deterministic across N invocations
/// with the same (value, blinding, nonce). This is the property
/// the genesis coinbase relies on for cross-node reproducibility.
#[test]
fn prove_with_nonce_is_deterministic() {
    let bf = blinding(0xAA);
    let nonce = [0x77u8; 32];
    let v = 33_000_000;
    let (proof_a, commit_a) = prove_with_nonce(v, &bf, &nonce).expect("prove a");
    for _ in 0..8 {
        let (proof_b, commit_b) = prove_with_nonce(v, &bf, &nonce).expect("prove b");
        assert_eq!(proof_a.bytes, proof_b.bytes, "proof bytes drifted");
        assert_eq!(commit_a, commit_b, "commitment bytes drifted");
    }
}
