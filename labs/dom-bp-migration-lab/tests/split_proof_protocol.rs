use dom_bp_migration_lab::split_proof_candidate::{
    CanonicalMetadata, LabError, SplitProofEnvelope, RECOVERY_METADATA_LEN, SINGLE_PROOF_LEN,
    SPLIT_PROOF_ENVELOPE_LEN, SPLIT_PROOF_VERSION,
};

#[test]
fn envelope_is_fixed_versioned_and_unambiguous() {
    let envelope = SplitProofEnvelope {
        primary_proof: [0x11; SINGLE_PROOF_LEN],
        complement_proof: [0x22; SINGLE_PROOF_LEN],
    };
    let encoded = envelope.encode();
    assert_eq!(encoded.len(), SPLIT_PROOF_ENVELOPE_LEN);
    assert_eq!(encoded[0], SPLIT_PROOF_VERSION);
    assert_eq!(
        SplitProofEnvelope::parse(&encoded)
            .expect("canonical envelope")
            .primary_proof,
        [0x11; SINGLE_PROOF_LEN]
    );
    for malformed in [
        Vec::new(),
        encoded[..SPLIT_PROOF_ENVELOPE_LEN - 1].to_vec(),
        [encoded.to_vec(), vec![0]].concat(),
    ] {
        assert_eq!(
            SplitProofEnvelope::parse(&malformed),
            Err(LabError::MalformedEnvelope)
        );
    }
    let mut unknown = encoded;
    unknown[0] = SPLIT_PROOF_VERSION + 1;
    assert_eq!(
        SplitProofEnvelope::parse(&unknown),
        Err(LabError::UnknownVersion)
    );
}

#[test]
fn metadata_encoding_is_strict_and_laboratory_only() {
    let metadata = CanonicalMetadata::new(7, 1, 9).expect("canonical metadata");
    assert_eq!(metadata.as_bytes().len(), RECOVERY_METADATA_LEN);
    assert_eq!(
        CanonicalMetadata::from_bytes(*metadata.as_bytes())
            .expect("decode")
            .as_bytes(),
        metadata.as_bytes()
    );
    let mut digest_mutation = *metadata.as_bytes();
    digest_mutation[19] ^= 1;
    assert_eq!(
        CanonicalMetadata::from_bytes(digest_mutation),
        Err(LabError::InvalidMetadata)
    );
    let mut network_mutation = *metadata.as_bytes();
    network_mutation[1] = 0;
    assert_eq!(
        CanonicalMetadata::from_bytes(network_mutation),
        Err(LabError::InvalidMetadata)
    );
    assert_eq!(
        CanonicalMetadata::new(1, 2, 3),
        Err(LabError::InvalidMetadata)
    );
}
