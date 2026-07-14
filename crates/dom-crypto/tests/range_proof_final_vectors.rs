//! Final DOM range-proof deterministic vectors.
//!
//! These vectors pin the production confidential-output format without relying
//! on random prover state. Each vector uses deterministic nonce input and checks
//! the hash of `commitment || proof`, where the proof is the final 739-byte
//! bounded aggregate Bulletproof.

use dom_crypto::pedersen::BlindingFactor;
use dom_crypto::range_proof::{
    prove_with_nonce, verify, RangeProof, MAX_PROVABLE_VALUE, RANGE_PROOF_SIZE,
};
use dom_crypto::{blake2b_256_tagged, RANGE_PROOF_SERIALIZATION_VERSION};

#[derive(Clone, Copy)]
struct Vector {
    name: &'static str,
    value: u64,
    blinding: [u8; 32],
    nonce: [u8; 32],
    expected_commitment_hex: &'static str,
    expected_payload_hash_hex: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        name: "minimum_value",
        value: 0,
        blinding: [0x01; 32],
        nonce: [0xA0; 32],
        expected_commitment_hex:
            "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        expected_payload_hash_hex:
            "7bb4b5b55109f391c115448b8cc0f08f3c75e68de02a7f24ec625c51f37290f1",
    },
    Vector {
        name: "maximum_value",
        value: MAX_PROVABLE_VALUE,
        blinding: [0x02; 32],
        nonce: [0xA1; 32],
        expected_commitment_hex:
            "02a63106aec46cbaa604242c2549bbafd5f4193a92416f8773d1d10842518ecdcb",
        expected_payload_hash_hex:
            "5089a67485ea8ec171cff2dbe8fe6cce375882790efdf784a3a0cefc811514f3",
    },
    Vector {
        name: "random_value_one",
        value: 42_424_242,
        blinding: [0x03; 32],
        nonce: [0xA2; 32],
        expected_commitment_hex:
            "03211d373a2e347bceeaa16c7e064cf0db009f80994565e31f0942b1015b00f21d",
        expected_payload_hash_hex:
            "31885d7e9e0c6f021060b5b8415ae5ff87c4c17cb9127ea3567f820264feedcd",
    },
    Vector {
        name: "random_value_two",
        value: 3_700_000_001,
        blinding: [0x04; 32],
        nonce: [0xA3; 32],
        expected_commitment_hex:
            "0259e2d51e9ec57e92c2c69cb1f630aa910c95e1163f9fd7af8ebe64c999fba3ee",
        expected_payload_hash_hex:
            "f32fb21129dd7a889c3c3253111114111190c85920f36d364f9e18feccb2bc39",
    },
    Vector {
        name: "coinbase_initial_reward",
        value: dom_core::INITIAL_BLOCK_REWARD,
        blinding: [0x05; 32],
        nonce: [0xA4; 32],
        expected_commitment_hex:
            "03a7bd6d7b7e47fd59b8e2f58f94243bcd94398ba2afae0910071a9d3c3c0960dc",
        expected_payload_hash_hex:
            "d3b7f859ebc6a28470881fe77d5f238946cf1195881e2aceabee4933d9455c0e",
    },
    Vector {
        name: "mixed_transaction_output",
        value: 1_234_567_890,
        blinding: [0x06; 32],
        nonce: [0xA5; 32],
        expected_commitment_hex:
            "03ce92dcec74c32fd186e456d375db1e2e8a138dd3d30716bb101f8f083be9be6d",
        expected_payload_hash_hex:
            "17225fec39ad133d89e573ff625907c4afb43a8e9a4b0edd76e928292caedb2b",
    },
];

fn payload_hash(commitment: &[u8; 33], proof: &[u8]) -> String {
    let mut payload = Vec::with_capacity(commitment.len() + proof.len());
    payload.extend_from_slice(commitment);
    payload.extend_from_slice(proof);
    hex::encode(blake2b_256_tagged("DOM:range-proof-vector:v1", &payload))
}

fn build(vector: Vector) -> (RangeProof, [u8; 33], String) {
    let blinding = BlindingFactor::from_bytes(vector.blinding).expect("valid blinding");
    let (proof, commitment) =
        prove_with_nonce(vector.value, &blinding, &vector.nonce).expect("prove vector");
    assert_eq!(proof.as_bytes().len(), RANGE_PROOF_SIZE);
    assert!(
        verify(&commitment, proof.as_bytes()).expect("verify vector"),
        "vector {} must verify",
        vector.name
    );
    let hash = payload_hash(&commitment, proof.as_bytes());
    (proof, commitment, hash)
}

#[test]
fn final_range_proof_vectors_are_frozen() {
    assert_eq!(RANGE_PROOF_SERIALIZATION_VERSION, 1);
    for &vector in VECTORS {
        let (proof, commitment, hash) = build(vector);
        assert_eq!(
            hex::encode(commitment),
            vector.expected_commitment_hex,
            "commitment drift for {}",
            vector.name
        );
        assert_eq!(
            hash, vector.expected_payload_hash_hex,
            "commitment||proof hash drift for {}",
            vector.name
        );

        let reparsed = RangeProof::from_bytes(proof.clone().into_bytes()).expect("reparse");
        assert_eq!(reparsed.as_bytes(), proof.as_bytes());
    }
}

#[test]
fn final_range_proof_multiple_outputs_are_independently_bound() {
    let built: Vec<_> = VECTORS.iter().copied().map(build).collect();
    for window in built.windows(2) {
        let (_, left_commitment, left_hash) = &window[0];
        let (right_proof, right_commitment, right_hash) = &window[1];
        assert_ne!(left_commitment, right_commitment);
        assert_ne!(left_hash, right_hash);
        assert!(
            !verify(left_commitment, right_proof.as_bytes()).unwrap_or(false),
            "proof for one output must not verify against another output"
        );
    }
}

#[test]
fn final_range_proof_restart_and_repeat_100_are_stable() {
    for _ in 0..100 {
        for &vector in VECTORS {
            let (proof_a, commitment_a, hash_a) = build(vector);
            let (proof_b, commitment_b, hash_b) = build(vector);
            assert_eq!(commitment_a, commitment_b);
            assert_eq!(proof_a.as_bytes(), proof_b.as_bytes());
            assert_eq!(hash_a, hash_b);
            assert_eq!(hash_a, vector.expected_payload_hash_hex);
        }
    }
}

#[test]
#[ignore]
fn print_final_range_proof_vectors() {
    for &vector in VECTORS {
        let (_, commitment, hash) = build(vector);
        eprintln!(
            "{} commitment={} payload_hash={}",
            vector.name,
            hex::encode(commitment),
            hash
        );
    }
}
