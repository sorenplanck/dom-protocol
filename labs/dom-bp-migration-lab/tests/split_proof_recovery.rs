use dom_bp_migration_lab::split_proof_candidate::{
    prove_single_with_distinct_nonces_for_test, prove_split_output, recover_split_output,
    rewind_single_for_test, CanonicalMetadata,
};
use dom_crypto::{pedersen::Commitment, BlindingFactor};

fn blind(byte: u8) -> BlindingFactor {
    BlindingFactor::from_bytes([byte; 32]).expect("nonzero blind")
}

#[test]
fn correct_nonce_recovers_the_exact_primary_tuple() {
    let bf = blind(0x31);
    let nonce = [0x42; 32];
    let metadata = CanonicalMetadata::new(7, 1, 99).expect("metadata");
    let (commitment, envelope) =
        prove_split_output(42, &bf, &nonce, metadata.clone()).expect("prove");
    let recovered = recover_split_output(&commitment, &envelope, &nonce)
        .expect("result")
        .expect("some");
    assert_eq!(recovered.value, 42);
    assert_eq!(recovered.blinding.as_bytes(), bf.as_bytes());
    assert_eq!(recovered.metadata.as_bytes(), metadata.as_bytes());
}

#[test]
fn wrong_nonce_returns_no_output() {
    let bf = blind(0x31);
    let (commitment, envelope) = prove_split_output(
        42,
        &bf,
        &[0x42; 32],
        CanonicalMetadata::new(7, 1, 99).expect("metadata"),
    )
    .expect("prove");
    assert!(recover_split_output(&commitment, &envelope, &[0x43; 32])
        .expect("result")
        .is_none());
}

#[test]
fn distinct_backend_private_nonce_cannot_recover_a_valid_original_blinding() {
    let bf = blind(0x31);
    let metadata = CanonicalMetadata::new(7, 1, 99).expect("metadata");
    let (commitment, proof) =
        prove_single_with_distinct_nonces_for_test(42, &bf, &[0x42; 32], &[0x43; 32], &metadata)
            .expect("prove");
    let recovered = rewind_single_for_test(&commitment, &proof, &[0x42; 32])
        .expect("rewind")
        .expect("header extraction");
    let recovered_blind =
        BlindingFactor::from_bytes(recovered.1).expect("nonzero recovered scalar");
    assert_ne!(
        Commitment::commit(recovered.0, &recovered_blind).as_bytes(),
        &commitment
    );
}
