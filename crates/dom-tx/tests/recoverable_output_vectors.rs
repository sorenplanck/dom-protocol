use dom_consensus::{validate_range_proofs, Transaction, TransactionOutput};
use dom_crypto::recovery::{derive_recovery_root, OutputRecoveryDomain, RecoveryChainContext};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_tx::build_recoverable_output;

fn chain() -> RecoveryChainContext {
    RecoveryChainContext {
        network_magic: 0x4452_4547,
        chain_id: [0x22; 32],
    }
}

#[test]
fn recoverable_output_envelope_roundtrips_canonically() {
    let root = derive_recovery_root(&[0x21; 64], chain()).unwrap();
    let material =
        build_recoverable_output(&root, chain(), 42, 1, 9, OutputRecoveryDomain::Received).unwrap();
    assert_eq!(material.output.range_proof_bytes().unwrap().len(), 739);
    assert_eq!(material.output.proof.len(), 835);
    assert_eq!(
        material
            .output
            .recovery_capsule()
            .unwrap()
            .unwrap()
            .as_bytes()
            .len(),
        96
    );
    let bytes = material.output.to_bytes().unwrap();
    let decoded = TransactionOutput::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, material.output);
}

#[test]
fn recovery_capsule_mutation_breaks_consensus_proof_validation() {
    let root = derive_recovery_root(&[0x21; 64], chain()).unwrap();
    let mut output =
        build_recoverable_output(&root, chain(), 42, 1, 9, OutputRecoveryDomain::Received)
            .unwrap()
            .output;
    output.proof[739 + 40] ^= 1;
    let tx = Transaction {
        inputs: Vec::new(),
        outputs: vec![output],
        kernels: Vec::new(),
        offset: [0u8; 32],
    };
    assert!(validate_range_proofs(&tx).is_err());
}
