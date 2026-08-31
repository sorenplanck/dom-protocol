//! Golden and fail-closed codec tests for the distinct V2 evidence container.

use btc_evidence::{
    BitcoinEvidenceNetworkV2, BitcoinEvidenceRouteBindingV2, BitcoinHeaderPolicyBindingV2,
    BitcoinOutPointV2, BitcoinOutcomeV2, BitcoinTransactionClaimV2, EvidenceCodecErrorV2,
    KeystoneBitcoinEvidenceV2,
};

fn fixture() -> KeystoneBitcoinEvidenceV2 {
    KeystoneBitcoinEvidenceV2::new(
        BitcoinEvidenceRouteBindingV2::new([2; 32], [3; 32]).expect("route binding"),
        BitcoinHeaderPolicyBindingV2::new(
            BitcoinEvidenceNetworkV2::Regtest,
            [1; 32],
            8,
            [10; 32],
            [11; 32],
            2,
        )
        .expect("header policy binding"),
        BitcoinTransactionClaimV2::new(
            [6; 32],
            [7; 32],
            BitcoinOutPointV2::new([4; 32], 5).expect("V2 outpoint"),
            10,
            9,
            BitcoinOutcomeV2::KeyPathClaim,
        )
        .expect("transaction claim"),
        vec![1, 2, 3],
        vec![[12; 80]],
    )
    .expect("bounded fixture")
}

#[test]
fn v2_codec_golden_is_distinct_and_byte_frozen() {
    let evidence = fixture();
    let encoded = evidence.encode().expect("canonical V2 encoding");
    let expected = concat!(
        "4442544345565632", // DBTCEVV2
        "0002",             // codec version
        "00",               // regtest
        "0101010101010101010101010101010101010101010101010101010101010101",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "0303030303030303030303030303030303030303030303030303030303030303",
        "0404040404040404040404040404040404040404040404040404040404040404",
        "00000005",
        "0606060606060606060606060606060606060606060606060606060606060606",
        "0707070707070707070707070707070707070707070707070707070707070707",
        "0000000000000008",
        "0000000a",
        "00000009",
        "00", // key-path claim
        "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "00000002",
        "00000003",
        "010203",
        "00000001",
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
    );
    assert_eq!(hex::encode(&encoded), expected);
    assert_eq!(encoded.len(), 383);
    assert!(KeystoneBitcoinEvidenceV2::decode(&encoded).expect("golden decodes") == evidence);
}

#[test]
fn v2_decoder_rejects_magic_version_discriminants_trailing_and_truncation() {
    let encoded = fixture().encode().expect("fixture encodes");

    let mut wrong_magic = encoded.clone();
    wrong_magic[0] ^= 1;
    assert_eq!(
        KeystoneBitcoinEvidenceV2::decode(&wrong_magic)
            .err()
            .expect("wrong magic must fail"),
        EvidenceCodecErrorV2::InvalidMagic
    );

    let mut wrong_version = encoded.clone();
    wrong_version[8..10].copy_from_slice(&3u16.to_be_bytes());
    assert_eq!(
        KeystoneBitcoinEvidenceV2::decode(&wrong_version)
            .err()
            .expect("wrong version must fail"),
        EvidenceCodecErrorV2::UnsupportedCodecVersion
    );

    let mut unknown_network = encoded.clone();
    unknown_network[10] = u8::MAX;
    assert_eq!(
        KeystoneBitcoinEvidenceV2::decode(&unknown_network)
            .err()
            .expect("unknown network must fail"),
        EvidenceCodecErrorV2::UnknownDiscriminant
    );

    let mut unknown_outcome = encoded.clone();
    unknown_outcome[223] = u8::MAX;
    assert_eq!(
        KeystoneBitcoinEvidenceV2::decode(&unknown_outcome)
            .err()
            .expect("unknown outcome must fail"),
        EvidenceCodecErrorV2::UnknownDiscriminant
    );

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        KeystoneBitcoinEvidenceV2::decode(&trailing)
            .err()
            .expect("trailing byte must fail"),
        EvidenceCodecErrorV2::TrailingBytes
    );
    assert_eq!(
        KeystoneBitcoinEvidenceV2::decode(&encoded[..encoded.len() - 1])
            .err()
            .expect("truncation must fail"),
        EvidenceCodecErrorV2::Truncated
    );
}

#[test]
fn v2_decoder_checks_all_announced_bounds_before_allocating() {
    let oversized_container = vec![0; KeystoneBitcoinEvidenceV2::MAX_ENCODED_BYTES + 1];
    assert_eq!(
        KeystoneBitcoinEvidenceV2::decode(&oversized_container)
            .err()
            .expect("oversized container must fail"),
        EvidenceCodecErrorV2::BoundsExceeded
    );

    let mut oversized_block = fixture().encode().expect("fixture encodes");
    oversized_block[292..296].copy_from_slice(
        &KeystoneBitcoinEvidenceV2::MAX_FULL_BLOCK_BYTES
            .saturating_add(1)
            .to_be_bytes(),
    );
    assert_eq!(
        KeystoneBitcoinEvidenceV2::decode(&oversized_block)
            .err()
            .expect("oversized block field must fail"),
        EvidenceCodecErrorV2::BoundsExceeded
    );

    let mut excessive_headers = fixture().encode().expect("fixture encodes");
    excessive_headers[299..303].copy_from_slice(
        &KeystoneBitcoinEvidenceV2::MAX_CONFIRMATION_HEADERS
            .saturating_add(1)
            .to_be_bytes(),
    );
    assert_eq!(
        KeystoneBitcoinEvidenceV2::decode(&excessive_headers)
            .err()
            .expect("excessive header count must fail"),
        EvidenceCodecErrorV2::BoundsExceeded
    );
}

#[test]
fn v2_decoder_requires_an_explicit_valid_tree_shape() {
    let encoded = fixture().encode().expect("fixture encodes");

    let mut zero_transactions = encoded.clone();
    zero_transactions[215..219].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        KeystoneBitcoinEvidenceV2::decode(&zero_transactions)
            .err()
            .expect("empty shape must fail"),
        EvidenceCodecErrorV2::InvalidField
    );

    let mut excessive_transactions = encoded.clone();
    excessive_transactions[215..219].copy_from_slice(
        &KeystoneBitcoinEvidenceV2::MAX_TRANSACTIONS
            .saturating_add(1)
            .to_be_bytes(),
    );
    assert_eq!(
        KeystoneBitcoinEvidenceV2::decode(&excessive_transactions)
            .err()
            .expect("excessive tree shape must fail"),
        EvidenceCodecErrorV2::InvalidField
    );

    let mut out_of_range_position = encoded;
    out_of_range_position[219..223].copy_from_slice(&10u32.to_be_bytes());
    assert_eq!(
        KeystoneBitcoinEvidenceV2::decode(&out_of_range_position)
            .err()
            .expect("out-of-range position must fail"),
        EvidenceCodecErrorV2::InvalidField
    );
}
