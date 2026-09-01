//! Frozen transcript, purpose-separation, and parser mutation tests.

use dom_adaptor::{
    binding_factor_v1, nonce_commitment_hash_v1, BindingContextV1, NonceCommitmentV1,
    NonceRevealV1, PartialSignatureV1, ParticipantPublicNoncesV1, PurposeV1,
};
use dom_crypto::{schnorr_partial_sign, PartialSig, SecretKey};

fn public_key(byte: u8) -> dom_crypto::PublicKey {
    let mut scalar = [0u8; 32];
    scalar[31] = byte;
    SecretKey::from_bytes(&scalar)
        .expect("small canonical scalar")
        .public_key()
}

#[test]
fn purpose_registry_is_closed_and_versioned() {
    assert_eq!(PurposeV1::Refund.to_byte(), 1);
    assert_eq!(PurposeV1::ClaimAdaptor.to_byte(), 2);
    assert_eq!(PurposeV1::Funding.to_byte(), 3);
    assert_eq!(PurposeV1::Sponsor.to_byte(), 4);
    assert_eq!(PurposeV1::RefundAdaptor.to_byte(), 5);
    for value in 0u8..=u8::MAX {
        assert_eq!(
            PurposeV1::try_from(value).is_ok(),
            (1..=5).contains(&value),
            "purpose 0x{value:02x}"
        );
    }
    assert_eq!(
        PurposeV1::try_from(4).expect("Sponsor is a codec value"),
        PurposeV1::Sponsor
    );
    assert!(PurposeV1::Sponsor.require_strict_phase1().is_err());
    for purpose in [
        PurposeV1::Refund,
        PurposeV1::ClaimAdaptor,
        PurposeV1::Funding,
        PurposeV1::RefundAdaptor,
    ] {
        assert_eq!(
            purpose.require_strict_phase1().expect("authorized purpose"),
            purpose
        );
    }
}

#[test]
fn sponsor_roundtrips_in_codecs_but_cannot_enter_strict_crypto() {
    let key = public_key(1);
    let commitment = NonceCommitmentV1::new(PurposeV1::Sponsor, 7, [8; 32]);
    assert_eq!(
        NonceCommitmentV1::from_bytes(&commitment.to_bytes())
            .expect("Sponsor commitment codec")
            .purpose(),
        PurposeV1::Sponsor
    );
    let reveal = NonceRevealV1::new(PurposeV1::Sponsor, 7, key.clone(), key.clone());
    assert_eq!(
        NonceRevealV1::from_bytes(&reveal.to_bytes())
            .expect("Sponsor reveal codec")
            .purpose(),
        PurposeV1::Sponsor
    );
    assert!(nonce_commitment_hash_v1(
        &[1; 32],
        &[2; 32],
        &[3; 32],
        PurposeV1::Sponsor,
        &[4; 32],
        &key,
        &key,
        None,
    )
    .is_err());

    let mut scalar = [0u8; 32];
    scalar[31] = 1;
    let partial = PartialSignatureV1::new(
        PurposeV1::Sponsor,
        7,
        [8; 32],
        PartialSig::from_bytes(&scalar).expect("one is canonical"),
    );
    assert_eq!(
        PartialSignatureV1::from_bytes(&partial.to_bytes())
            .expect("Sponsor partial codec")
            .purpose(),
        PurposeV1::Sponsor
    );
    assert!(partial
        .verify_bound(
            PurposeV1::Sponsor,
            &[8; 32],
            &key,
            &key,
            &key,
            &key,
            &[9; 32],
            &[10; 32],
        )
        .is_err());
}

#[test]
fn collective_binding_matches_independently_frozen_hash_vector() {
    let generator = public_key(1);
    let context = BindingContextV1 {
        chain_id: [0xAD; 32],
        session_id: [0x01; 32],
        purpose: PurposeV1::ClaimAdaptor,
        template_hash: [0x22; 32],
    };
    let participant = ParticipantPublicNoncesV1 {
        participant_index: 0,
        signing_key: generator.clone(),
        first_nonce: generator.clone(),
        second_nonce: generator.clone(),
    };
    let factor = binding_factor_v1(&context, &[participant], Some(&generator))
        .expect("frozen binding transcript is valid");
    let expected: [u8; 32] =
        hex::decode("bf9353815692ec8c521504bf0fa8d34c75ffc2fb609ee961e19414d92025c054")
            .expect("hex")
            .try_into()
            .expect("32 bytes");
    assert_eq!(factor.to_be_bytes(), expected);
    assert!(factor.bind_public_nonces(&generator, &generator).is_ok());
}

#[test]
fn binding_rejects_wrong_grammar_order_and_empty_sets() {
    let context = BindingContextV1 {
        chain_id: [1; 32],
        session_id: [2; 32],
        purpose: PurposeV1::ClaimAdaptor,
        template_hash: [3; 32],
    };
    let adaptor = public_key(4);
    assert!(binding_factor_v1(&context, &[], Some(&adaptor)).is_err());
    assert!(binding_factor_v1(&context, &[], None).is_err());

    let participant = |index, scalar| ParticipantPublicNoncesV1 {
        participant_index: index,
        signing_key: public_key(scalar),
        first_nonce: public_key(scalar + 1),
        second_nonce: public_key(scalar + 2),
    };
    assert!(binding_factor_v1(
        &context,
        &[participant(2, 5), participant(1, 8)],
        Some(&adaptor),
    )
    .is_err());
    let duplicate_key = ParticipantPublicNoncesV1 {
        participant_index: 2,
        signing_key: public_key(5),
        first_nonce: public_key(12),
        second_nonce: public_key(13),
    };
    assert!(binding_factor_v1(
        &context,
        &[participant(1, 5), duplicate_key],
        Some(&adaptor),
    )
    .is_err());
    let duplicate_nonce = ParticipantPublicNoncesV1 {
        participant_index: 2,
        signing_key: public_key(12),
        first_nonce: public_key(6),
        second_nonce: public_key(13),
    };
    assert!(binding_factor_v1(
        &context,
        &[participant(1, 5), duplicate_nonce],
        Some(&adaptor),
    )
    .is_err());

    let funding = BindingContextV1 {
        purpose: PurposeV1::Funding,
        ..context
    };
    assert!(binding_factor_v1(&funding, &[participant(1, 5)], Some(&adaptor)).is_err());
    assert!(binding_factor_v1(&funding, &[participant(1, 5)], None).is_ok());
}

#[test]
fn critical_commitment_fields_are_domain_separated() {
    let r1 = public_key(1);
    let r2 = public_key(2);
    let adaptor = public_key(3);
    let base = nonce_commitment_hash_v1(
        &[4; 32],
        &[5; 32],
        &[6; 32],
        PurposeV1::ClaimAdaptor,
        &[7; 32],
        &r1,
        &r2,
        Some(&adaptor),
    )
    .expect("base commitment");
    let variants = [
        nonce_commitment_hash_v1(
            &[8; 32],
            &[5; 32],
            &[6; 32],
            PurposeV1::ClaimAdaptor,
            &[7; 32],
            &r1,
            &r2,
            Some(&adaptor),
        ),
        nonce_commitment_hash_v1(
            &[4; 32],
            &[8; 32],
            &[6; 32],
            PurposeV1::ClaimAdaptor,
            &[7; 32],
            &r1,
            &r2,
            Some(&adaptor),
        ),
        nonce_commitment_hash_v1(
            &[4; 32],
            &[5; 32],
            &[8; 32],
            PurposeV1::ClaimAdaptor,
            &[7; 32],
            &r1,
            &r2,
            Some(&adaptor),
        ),
        nonce_commitment_hash_v1(
            &[4; 32],
            &[5; 32],
            &[6; 32],
            PurposeV1::ClaimAdaptor,
            &[8; 32],
            &r1,
            &r2,
            Some(&adaptor),
        ),
        nonce_commitment_hash_v1(
            &[4; 32],
            &[5; 32],
            &[6; 32],
            PurposeV1::ClaimAdaptor,
            &[7; 32],
            &public_key(9),
            &r2,
            Some(&adaptor),
        ),
        nonce_commitment_hash_v1(
            &[4; 32],
            &[5; 32],
            &[6; 32],
            PurposeV1::ClaimAdaptor,
            &[7; 32],
            &r1,
            &public_key(9),
            Some(&adaptor),
        ),
        nonce_commitment_hash_v1(
            &[4; 32],
            &[5; 32],
            &[6; 32],
            PurposeV1::ClaimAdaptor,
            &[7; 32],
            &r1,
            &r2,
            Some(&public_key(9)),
        ),
    ];
    for variant in variants {
        assert_ne!(variant.expect("valid variant"), base);
    }
    assert!(nonce_commitment_hash_v1(
        &[4; 32],
        &[5; 32],
        &[6; 32],
        PurposeV1::Funding,
        &[7; 32],
        &r1,
        &r2,
        None,
    )
    .is_ok());
}

#[test]
fn all_fixed_width_parsers_are_panic_free_over_bounded_mutations() {
    let key = public_key(1);
    let commitment = NonceCommitmentV1::new(PurposeV1::Refund, 7, [8; 32]);
    let reveal = NonceRevealV1::new(PurposeV1::Funding, 9, key.clone(), key);
    let mut one = [0u8; 32];
    one[31] = 1;
    let partial = PartialSignatureV1::new(
        PurposeV1::ClaimAdaptor,
        11,
        [12; 32],
        PartialSig::from_bytes(&one).expect("one is canonical"),
    );
    assert_eq!(
        NonceCommitmentV1::from_bytes(&commitment.to_bytes())
            .expect("commitment roundtrip")
            .to_bytes(),
        commitment.to_bytes()
    );
    assert_eq!(
        NonceRevealV1::from_bytes(&reveal.to_bytes())
            .expect("reveal roundtrip")
            .to_bytes(),
        reveal.to_bytes()
    );
    assert_eq!(
        PartialSignatureV1::from_bytes(&partial.to_bytes())
            .expect("partial roundtrip")
            .to_bytes(),
        partial.to_bytes()
    );

    let corpus = [
        commitment.to_bytes().to_vec(),
        reveal.to_bytes().to_vec(),
        partial.to_bytes().to_vec(),
    ];
    for source in corpus {
        for length in 0..=source.len() + 2 {
            let mut candidate = source.clone();
            candidate.resize(length, 0xFF);
            let result = std::panic::catch_unwind(|| {
                let _ = NonceCommitmentV1::from_bytes(&candidate);
                let _ = NonceRevealV1::from_bytes(&candidate);
                let _ = PartialSignatureV1::from_bytes(&candidate);
            });
            assert!(result.is_ok(), "parsers must not panic at length {length}");
        }
    }
}

#[test]
fn bound_partial_uses_the_authoritative_aggregate_challenge() {
    let signing_secret = SecretKey::from_bytes(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 7,
    ])
    .expect("canonical signing key");
    let nonce_secret = SecretKey::from_bytes(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 11,
    ])
    .expect("canonical test nonce");
    let signing_key = signing_secret.public_key();
    let nonce = nonce_secret.public_key();
    let chain_id = [0xA5; 32];
    let message = [0x5A; 32];
    let template_hash = [0x33; 32];
    let partial = schnorr_partial_sign(
        &signing_secret,
        &nonce_secret,
        &nonce,
        &signing_key,
        &chain_id,
        &message,
    )
    .expect("authoritative DOM partial");
    let payload = PartialSignatureV1::new(PurposeV1::Funding, 0, template_hash, partial);
    assert!(payload
        .verify_bound(
            PurposeV1::Funding,
            &template_hash,
            &nonce,
            &signing_key,
            &nonce,
            &signing_key,
            &chain_id,
            &message,
        )
        .expect("bound partial verification"));
    assert!(payload
        .verify_bound(
            PurposeV1::Refund,
            &template_hash,
            &nonce,
            &signing_key,
            &nonce,
            &signing_key,
            &chain_id,
            &message,
        )
        .is_err());
    assert!(payload
        .verify_bound(
            PurposeV1::Funding,
            &[0x44; 32],
            &nonce,
            &signing_key,
            &nonce,
            &signing_key,
            &chain_id,
            &message,
        )
        .is_err());
}
