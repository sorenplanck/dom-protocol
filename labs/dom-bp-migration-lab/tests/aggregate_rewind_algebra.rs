use dom_bp_migration_lab::{
    aggregate_rewind_model::{
        current_aggregate_header, dom_blind_coefficient, packed_aggregate_header,
        recover_first_blind, recover_packed_aggregate, scalar_from_u64, zeroize_nonces,
        AggregationChallenges, CanonicalMetadata, CommitmentPair, NonceScalars, L1B_CASES,
        L1B_SEED,
    },
    protocol::MAX_PROVABLE_VALUE,
};
use k256::Scalar;
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn scalar_from_rng(rng: &mut StdRng) -> Scalar {
    Scalar::generate_vartime(rng)
}

fn nonces(index: u64) -> NonceScalars {
    NonceScalars {
        alpha: scalar_from_u64(10 + index),
        rho: scalar_from_u64(20 + index),
        tau1: scalar_from_u64(30 + index),
        tau2: scalar_from_u64(40 + index),
    }
}

#[test]
fn two_commitment_backend_coefficient_is_exact() {
    let z = scalar_from_u64(7);
    let r = scalar_from_u64(11);
    let pair = CommitmentPair::dom(42, MAX_PROVABLE_VALUE, r).expect("in range");
    let challenges = AggregationChallenges {
        z,
        x: scalar_from_u64(13),
    };
    let nonces = nonces(0);
    let header = current_aggregate_header(&pair, &nonces, &challenges);
    let masks = nonces.tau1 * challenges.x + nonces.tau2 * challenges.x.square();
    assert_eq!(
        -(header.serialized_taux + masks),
        dom_blind_coefficient(challenges.z) * r
    );
    assert_eq!(recover_first_blind(&header, &nonces, &challenges), Ok(r));
}

#[test]
fn current_aggregate_has_no_value_or_metadata_encoding() {
    let pair = CommitmentPair::dom(42, MAX_PROVABLE_VALUE, scalar_from_u64(9)).expect("in range");
    let challenges = AggregationChallenges {
        z: scalar_from_u64(7),
        x: scalar_from_u64(13),
    };
    let nonces = nonces(0);
    let header = current_aggregate_header(&pair, &nonces, &challenges);
    let metadata = CanonicalMetadata::test_vector();
    assert!(
        recover_packed_aggregate(
            &header,
            &nonces,
            &challenges,
            &pair,
            MAX_PROVABLE_VALUE,
            &metadata,
        )
        .is_err(),
        "the unmodified n_commits=2 alpha has no witness/message packing"
    );
}

#[test]
fn experimental_alpha_packing_recovers_exact_witness_when_coefficient_is_nonzero() {
    let metadata = CanonicalMetadata::test_vector();
    let r = scalar_from_u64(0x1234);
    let pair = CommitmentPair::dom(MAX_PROVABLE_VALUE, MAX_PROVABLE_VALUE, r).expect("in range");
    let challenges = AggregationChallenges {
        z: scalar_from_u64(7),
        x: scalar_from_u64(13),
    };
    let nonces = nonces(0);
    let header = packed_aggregate_header(&pair, &nonces, &challenges, &metadata);
    let recovered = recover_packed_aggregate(
        &header,
        &nonces,
        &challenges,
        &pair,
        MAX_PROVABLE_VALUE,
        &metadata,
    )
    .expect("recoverable under nonzero coefficient");
    assert_eq!(recovered.value, MAX_PROVABLE_VALUE);
    assert_eq!(recovered.blind, r);
    assert_eq!(recovered.metadata, metadata);
}

#[test]
fn seeded_10k_scalar_cases_recover_when_and_only_when_coefficient_is_invertible() {
    let mut rng = StdRng::seed_from_u64(L1B_SEED);
    let metadata = CanonicalMetadata::test_vector();
    for index in 0..L1B_CASES {
        let value = match index % 8 {
            0 => 0,
            1 => 1,
            2 => MAX_PROVABLE_VALUE - 1,
            3 => MAX_PROVABLE_VALUE,
            _ => rng.next_u64() & MAX_PROVABLE_VALUE,
        };
        let blind = scalar_from_rng(&mut rng);
        let z = loop {
            let candidate = scalar_from_rng(&mut rng);
            if candidate != Scalar::ONE {
                break candidate;
            }
        };
        let challenges = AggregationChallenges {
            z,
            x: scalar_from_rng(&mut rng),
        };
        let pair = CommitmentPair::dom(value, MAX_PROVABLE_VALUE, blind).expect("bounded value");
        let mut witness_nonces = NonceScalars {
            alpha: scalar_from_rng(&mut rng),
            rho: scalar_from_rng(&mut rng),
            tau1: scalar_from_rng(&mut rng),
            tau2: scalar_from_rng(&mut rng),
        };
        let header = packed_aggregate_header(&pair, &witness_nonces, &challenges, &metadata);
        let recovered = recover_packed_aggregate(
            &header,
            &witness_nonces,
            &challenges,
            &pair,
            MAX_PROVABLE_VALUE,
            &metadata,
        )
        .unwrap_or_else(|error| panic!("seed={L1B_SEED:#x} index={index} error={error:?}"));
        assert_eq!(recovered.value, value);
        assert_eq!(recovered.blind, blind);
        zeroize_nonces(&mut witness_nonces);
        assert_eq!(witness_nonces.alpha, Scalar::ZERO);
    }
}
