use dom_bp_migration_lab::{
    protocol::MAX_PROVABLE_VALUE,
    split_proof_candidate::{
        prove_split_output, recover_split_output, verify_split_output, CanonicalMetadata,
    },
    CurrentOracle, Operation, OracleCase, ProveResult,
};
use dom_crypto::BlindingFactor;
use rand::{rngs::StdRng, Rng, SeedableRng};

const PROPERTY_SEED: u64 = 0xD052_D5F1_17C0_0001;
const PROPERTY_CASES: usize = 10_000;

fn deterministic_blind(index: usize) -> BlindingFactor {
    if index.is_multiple_of(997) {
        // secp256k1 scalar order minus one, a valid boundary blinding.
        return BlindingFactor::from_bytes([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x40,
        ])
        .expect("n - 1 is a valid blinding");
    }
    BlindingFactor::from_bytes([((index % 250) + 1) as u8; 32]).expect("valid blinding")
}

fn nonce(index: usize) -> [u8; 32] {
    let mut nonce = [0_u8; 32];
    nonce[..8].copy_from_slice(&(index as u64).to_be_bytes());
    nonce[8..16].copy_from_slice(&(!(index as u64)).to_be_bytes());
    nonce[16..24].copy_from_slice(&((index as u64).rotate_left(17)).to_be_bytes());
    nonce[24..32].copy_from_slice(&((index as u64).rotate_right(9)).to_be_bytes());
    nonce
}

#[test]
fn seeded_split_candidate_matches_current_oracle_for_10k_cases() {
    let mut rng = StdRng::seed_from_u64(PROPERTY_SEED);
    let current = CurrentOracle;
    for index in 0..PROPERTY_CASES {
        let value = match index % 1_000 {
            0 => 0,
            1 => 1,
            2 => MAX_PROVABLE_VALUE.saturating_sub(rng.gen_range(0..=4096)),
            3 => MAX_PROVABLE_VALUE,
            4 => MAX_PROVABLE_VALUE.saturating_add(rng.gen_range(1..=4096)),
            5 => 1_u64 << rng.gen_range(52..=63),
            6 => u64::MAX,
            7 => MAX_PROVABLE_VALUE.wrapping_sub(rng.gen::<u64>()),
            _ => rng.gen::<u64>(),
        };
        let blind = deterministic_blind(index);
        let current_result = current.prove_verify(&OracleCase {
            schema_version: 1,
            case_id: format!("l2d-property-{PROPERTY_SEED:016x}-{index}"),
            operation: Operation::ProveVerify,
            value,
            blind_hex: hex::encode(blind.as_bytes()),
        });
        let expected = value <= MAX_PROVABLE_VALUE;
        assert_eq!(
            current_result.prove_result == ProveResult::Accepted,
            expected,
            "seed={PROPERTY_SEED:#x} index={index} value={value}"
        );
        let metadata = CanonicalMetadata::new(index as u32, (index % 2) as u8, index as u32 + 10)
            .expect("metadata");
        let recovery_nonce = nonce(index);
        match prove_split_output(value, &blind, &recovery_nonce, metadata.clone()) {
            Ok((commitment, envelope)) => {
                assert!(
                    expected,
                    "seed={PROPERTY_SEED:#x} index={index} accepted value={value}"
                );
                assert!(verify_split_output(&commitment, &envelope).expect("canonical envelope"));
                let recovered = recover_split_output(&commitment, &envelope, &recovery_nonce)
                    .expect("canonical envelope")
                    .expect("correct nonce");
                assert_eq!(recovered.value, value);
                assert_eq!(recovered.blinding.as_bytes(), blind.as_bytes());
                assert_eq!(recovered.metadata.as_bytes(), metadata.as_bytes());
                let mut wrong_nonce = recovery_nonce;
                wrong_nonce[31] ^= 1;
                assert!(recover_split_output(&commitment, &envelope, &wrong_nonce)
                    .expect("canonical envelope")
                    .is_none());
            }
            Err(error) => {
                assert!(
                    !expected,
                    "seed={PROPERTY_SEED:#x} index={index} value={value} error={error:?}"
                );
            }
        }
    }
}
