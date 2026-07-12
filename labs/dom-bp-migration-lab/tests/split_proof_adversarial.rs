use dom_bp_migration_lab::split_proof_candidate::{
    prove_split_output, recover_split_output, verify_split_output, CanonicalMetadata,
    SINGLE_PROOF_LEN, SPLIT_PROOF_ENVELOPE_LEN,
};
use dom_crypto::BlindingFactor;

fn fixture() -> ([u8; 33], [u8; SPLIT_PROOF_ENVELOPE_LEN], [u8; 32]) {
    let bf = BlindingFactor::from_bytes([0x31; 32]).expect("blind");
    let nonce = [0x42; 32];
    let (commitment, envelope) = prove_split_output(
        42,
        &bf,
        &nonce,
        CanonicalMetadata::new(7, 1, 99).expect("metadata"),
    )
    .expect("prove");
    (commitment, envelope, nonce)
}

#[test]
fn proof_mutations_swaps_duplicates_and_wrong_commitment_fail_closed() {
    let (commitment, envelope, nonce) = fixture();
    for offset in [1, 1 + 192, 1 + SINGLE_PROOF_LEN, 1 + SINGLE_PROOF_LEN + 192] {
        let mut mutated = envelope;
        mutated[offset] ^= 1;
        assert!(!verify_split_output(&commitment, &mutated).expect("parsed"));
        assert!(recover_split_output(&commitment, &mutated, &nonce)
            .expect("parsed")
            .is_none());
    }
    let mut swapped = envelope;
    let (left, right) = swapped[1..].split_at_mut(SINGLE_PROOF_LEN);
    let primary = left.to_vec();
    left.copy_from_slice(right);
    right.copy_from_slice(&primary);
    assert!(!verify_split_output(&commitment, &swapped).expect("parsed"));
    let mut duplicate = envelope;
    let primary = duplicate[1..1 + SINGLE_PROOF_LEN].to_vec();
    duplicate[1 + SINGLE_PROOF_LEN..].copy_from_slice(&primary);
    assert!(!verify_split_output(&commitment, &duplicate).expect("parsed"));
    let mut wrong_commitment = commitment;
    wrong_commitment[0] ^= 1;
    assert!(
        verify_split_output(&wrong_commitment, &envelope).is_err()
            || !verify_split_output(&wrong_commitment, &envelope).expect("valid encoding false")
    );
}

#[test]
fn malformed_envelopes_and_all_zero_proofs_do_not_recover() {
    let (commitment, envelope, nonce) = fixture();
    for bytes in [
        Vec::new(),
        envelope[..SPLIT_PROOF_ENVELOPE_LEN - 1].to_vec(),
        [envelope.to_vec(), vec![0]].concat(),
        vec![0; SPLIT_PROOF_ENVELOPE_LEN],
    ] {
        assert!(
            verify_split_output(&commitment, &bytes).is_err()
                || !verify_split_output(&commitment, &bytes).expect("parsed")
        );
        assert!(
            recover_split_output(&commitment, &bytes, &nonce).is_err()
                || recover_split_output(&commitment, &bytes, &nonce)
                    .expect("parsed")
                    .is_none()
        );
    }
}
