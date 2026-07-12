use dom_bp_migration_lab::{CurrentOracle, VerifyResult};
use dom_crypto::{bp2_prove, pedersen::Commitment, BlindingFactor};

fn blind(byte: u8) -> BlindingFactor {
    BlindingFactor::from_bytes([byte; 32]).expect("test blind")
}

#[test]
fn single_commit_proof_above_ceiling_is_not_a_dom_proof() {
    let value = 1_u64 << 52;
    let raw = CurrentOracle::adversarial_single_64(value, [0x11; 32]).expect("raw single proof");
    assert_eq!(raw.len(), 675);
    let commitment = Commitment::commit(value, &blind(0x11));
    assert_eq!(
        CurrentOracle::verify(commitment.as_bytes(), &raw),
        VerifyResult::Malformed
    );
}

#[test]
fn wrong_complement_aggregate_is_rejected() {
    let value = 42;
    let proof = CurrentOracle::adversarial_wrong_complement(value, [0x11; 32])
        .expect("forged aggregate proof");
    assert_eq!(proof.len(), 739);
    let commitment = Commitment::commit(value, &blind(0x11));
    assert_eq!(
        CurrentOracle::verify(commitment.as_bytes(), &proof),
        VerifyResult::False
    );
}

#[test]
fn commitment_of_another_output_and_mutations_fail() {
    let (proof, commitment) = bp2_prove(42, &blind(0x11)).expect("valid proof");
    let (_other_proof, other_commitment) = bp2_prove(43, &blind(0x22)).expect("other proof");
    assert_eq!(
        CurrentOracle::verify(&other_commitment, &proof),
        VerifyResult::False
    );

    for index in [0, 192, proof.len() - 1] {
        let mut mutated = proof.clone();
        mutated[index] ^= 1;
        assert_ne!(
            CurrentOracle::verify(&commitment, &mutated),
            VerifyResult::True
        );
    }
}

#[test]
fn non_739_lengths_are_malformed_without_panic() {
    let (_proof, commitment) = bp2_prove(7, &blind(0x33)).expect("valid proof");
    for len in [0, 674, 675, 738, 740] {
        assert_eq!(
            CurrentOracle::verify(&commitment, &vec![0_u8; len]),
            VerifyResult::Malformed,
            "len={len}"
        );
    }
    assert_ne!(
        CurrentOracle::verify(&commitment, &[0_u8; 739]),
        VerifyResult::True
    );
}
