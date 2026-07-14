//! Final DOM range-proof test vectors for cross-implementation validation.

use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::range_proof::{prove, verify};

#[test]
fn vector_1_dom_exact() {
    let value = 1_000_000_000u64;
    let blinding = BlindingFactor::from_bytes([1u8; 32]).expect("blinding");

    let commitment = Commitment::commit(value, &blinding);
    let (proof, _nonce) = prove(value, &blinding).expect("prove");

    let valid = verify(commitment.as_bytes(), &proof.bytes).expect("verify");
    assert!(valid, "proof should verify");
}

#[test]
fn vector_369_dom_initial_reward() {
    let value = 369_000_000_000u64;
    let blinding = BlindingFactor::from_bytes([2u8; 32]).expect("blinding");

    let commitment = Commitment::commit(value, &blinding);
    let (proof, _nonce) = prove(value, &blinding).expect("prove");

    let valid = verify(commitment.as_bytes(), &proof.bytes).expect("verify");
    assert!(valid, "proof should verify");
}

#[test]
fn vector_1million_dom_large_tx() {
    // Large but valid transaction: 1,000,000 DOM
    // (Still well under MAX_PROVABLE = 2^52-1 = ~4.5M DOM)
    let value = 1_000_000_000_000_000u64;
    let blinding = BlindingFactor::from_bytes([3u8; 32]).expect("blinding");

    let commitment = Commitment::commit(value, &blinding);
    let (proof, _nonce) = prove(value, &blinding).expect("prove");

    let valid = verify(commitment.as_bytes(), &proof.bytes).expect("verify");
    assert!(valid, "proof should verify");
}

#[test]
fn vector_total_supply_exceeds_max() {
    // This should FAIL - total supply exceeds MAX_PROVABLE
    // 33M DOM = 33,000,000,000,000,000 > 2^52-1
    let value = 33_000_000_000_000_000u64;
    let blinding = BlindingFactor::from_bytes([4u8; 32]).expect("blinding");

    let result = prove(value, &blinding);
    assert!(result.is_err(), "Should reject value > MAX_PROVABLE");
}
