use dom_bp_migration_lab::{
    aggregate_rewind_model::{
        current_aggregate_header, packed_aggregate_header, recover_first_blind,
        recover_packed_aggregate, scalar_from_canonical_bytes, scalar_from_u64,
        AggregationChallenges, CanonicalMetadata, CommitmentPair, NonceScalars, RecoveryError,
    },
    protocol::MAX_PROVABLE_VALUE,
};
use k256::Scalar;

fn nonces() -> NonceScalars {
    NonceScalars {
        alpha: scalar_from_u64(2),
        rho: scalar_from_u64(3),
        tau1: scalar_from_u64(5),
        tau2: scalar_from_u64(7),
    }
}

#[test]
fn z_equal_one_cancels_r_and_is_fail_closed() {
    let pair = CommitmentPair::dom(42, MAX_PROVABLE_VALUE, scalar_from_u64(11)).expect("in range");
    let challenges = AggregationChallenges {
        z: Scalar::ONE,
        x: scalar_from_u64(13),
    };
    let header = current_aggregate_header(&pair, &nonces(), &challenges);
    assert_eq!(
        recover_first_blind(&header, &nonces(), &challenges),
        Err(RecoveryError::NonInvertibleBlindCoefficient)
    );
}

#[test]
fn zero_challenges_are_rejected_even_before_recovery() {
    let pair = CommitmentPair::dom(42, MAX_PROVABLE_VALUE, scalar_from_u64(11)).expect("in range");
    let header = current_aggregate_header(
        &pair,
        &nonces(),
        &AggregationChallenges {
            z: Scalar::ZERO,
            x: scalar_from_u64(1),
        },
    );
    assert_eq!(
        recover_first_blind(
            &header,
            &nonces(),
            &AggregationChallenges {
                z: Scalar::ZERO,
                x: scalar_from_u64(1)
            },
        ),
        Err(RecoveryError::InvalidChallenge)
    );
}

#[test]
fn wrong_nonce_or_metadata_or_commitment_is_rejected() {
    let metadata = CanonicalMetadata::test_vector();
    let pair = CommitmentPair::dom(42, MAX_PROVABLE_VALUE, scalar_from_u64(11)).expect("in range");
    let challenges = AggregationChallenges {
        z: scalar_from_u64(7),
        x: scalar_from_u64(13),
    };
    let header = packed_aggregate_header(&pair, &nonces(), &challenges, &metadata);
    let wrong = NonceScalars {
        alpha: scalar_from_u64(99),
        ..nonces()
    };
    assert!(
        recover_packed_aggregate(
            &header,
            &wrong,
            &challenges,
            &pair,
            MAX_PROVABLE_VALUE,
            &metadata
        )
        .is_err(),
        "wrong nonce material must never recover a witness"
    );
    let mut altered = metadata.clone();
    altered.0[19] ^= 1;
    assert_eq!(
        recover_packed_aggregate(
            &header,
            &nonces(),
            &challenges,
            &pair,
            MAX_PROVABLE_VALUE,
            &altered
        ),
        Err(RecoveryError::MetadataMismatch)
    );
    let other = CommitmentPair::dom(43, MAX_PROVABLE_VALUE, scalar_from_u64(11)).expect("in range");
    assert_eq!(
        recover_packed_aggregate(
            &header,
            &nonces(),
            &challenges,
            &other,
            MAX_PROVABLE_VALUE,
            &metadata
        ),
        Err(RecoveryError::CommitmentMismatch)
    );
}

#[test]
fn complement_order_and_bounds_are_checked_by_recomputation() {
    assert!(CommitmentPair::dom(
        MAX_PROVABLE_VALUE + 1,
        MAX_PROVABLE_VALUE,
        scalar_from_u64(1)
    )
    .is_none());
    let valid = CommitmentPair::dom(0, MAX_PROVABLE_VALUE, scalar_from_u64(1)).expect("zero valid");
    assert!(valid.is_dom_complement(MAX_PROVABLE_VALUE));
    let reversed = CommitmentPair {
        first_value: valid.second_value,
        first_blind: valid.second_blind,
        second_value: valid.first_value,
        second_blind: valid.first_blind,
    };
    // The reversed pair is internally a valid *different* DOM output.  It
    // must nevertheless fail when used as the commitment pair for a proof
    // created for `valid`.
    assert!(reversed.is_dom_complement(MAX_PROVABLE_VALUE));
    let metadata = CanonicalMetadata::test_vector();
    let challenges = AggregationChallenges {
        z: scalar_from_u64(7),
        x: scalar_from_u64(13),
    };
    let header = packed_aggregate_header(&valid, &nonces(), &challenges, &metadata);
    assert_eq!(
        recover_packed_aggregate(
            &header,
            &nonces(),
            &challenges,
            &reversed,
            MAX_PROVABLE_VALUE,
            &metadata,
        ),
        Err(RecoveryError::CommitmentMismatch)
    );
}

#[test]
fn blind_one_below_the_real_secp256k1_order_recovers() {
    // n - 1 for secp256k1's scalar field; this is a boundary witness, never
    // persisted outside this test process.
    let near_order = scalar_from_canonical_bytes([
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x40,
    ]);
    let pair = CommitmentPair::dom(1, MAX_PROVABLE_VALUE, near_order).expect("in range");
    let challenges = AggregationChallenges {
        z: scalar_from_u64(7),
        x: scalar_from_u64(13),
    };
    let header = current_aggregate_header(&pair, &nonces(), &challenges);
    assert_eq!(
        recover_first_blind(&header, &nonces(), &challenges),
        Ok(near_order)
    );
}
