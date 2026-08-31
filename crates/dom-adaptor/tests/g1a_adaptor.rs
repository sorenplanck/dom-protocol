//! Production-boundary tests using the frozen SCAD0 corpus and real DOM verifier.

use dom_adaptor::{
    AdaptorPreSignatureV1, AdaptorSecret, ClaimObservationError, CoreAdaptorPreSignatureV1,
    DomClaimObservationTagV1, FinalSignatureOpeningContextV1, ObservedClaimBindingV1,
    ObservedClaimFactsV1, ObservedClaimLocationV1, VerifiedDomClaimObservationV1,
};
use dom_consensus::{validate_kernel_signatures, Transaction, TransactionKernel};
use dom_crypto::{PartialSig, PublicKey, SchnorrSignature};
use dom_serialization::DomDeserialize;

const CHAIN_ID: [u8; 32] = [0xAD; 32];
const MESSAGE: [u8; 32] = [
    0x10, 0xd4, 0x3a, 0x5a, 0xc3, 0x16, 0x0f, 0xdb, 0xc6, 0x7a, 0x1f, 0x8a, 0x29, 0x3f, 0x97, 0x50,
    0x55, 0x8e, 0x53, 0xc1, 0x8f, 0xa3, 0x7f, 0x58, 0xd3, 0x40, 0xdf, 0x3f, 0xdd, 0x41, 0xaa, 0x34,
];

fn decode_array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .expect("fixture field is hexadecimal")
        .try_into()
        .unwrap_or_else(|_| panic!("fixture field must contain {N} bytes"))
}

#[test]
fn all_eight_scad0_vectors_verify_adapt_extract_and_pass_consensus() {
    let mut count = 0;
    for line in include_str!("../../dom-consensus/tests/fixtures/scad0_adaptor_vectors_v1.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields = line.split('|').collect::<Vec<_>>();
        assert_eq!(fields.len(), 5, "SCAD0 record shape");
        let id = fields[0];
        let secret_bytes: [u8; 32] = decode_array(fields[1]);
        let secret = AdaptorSecret::from_be_bytes(secret_bytes)
            .unwrap_or_else(|error| panic!("{id} secret: {error}"));
        let adaptor_point = PublicKey::from_compressed_bytes(&decode_array::<33>(fields[2]))
            .unwrap_or_else(|error| panic!("{id} adaptor point: {error}"));
        assert_eq!(
            secret.public_point().expect("adaptor point"),
            adaptor_point,
            "{id} t*G == T"
        );
        let scalar_hat = PartialSig::from_bytes(&decode_array::<32>(fields[3]))
            .unwrap_or_else(|error| panic!("{id} scalar_hat: {error}"));
        let kernel = TransactionKernel::from_bytes(&hex::decode(fields[4]).expect("kernel hex"))
            .unwrap_or_else(|error| panic!("{id} kernel: {error}"));
        let expected_signature = SchnorrSignature::from_bytes(&kernel.excess_signature)
            .unwrap_or_else(|error| panic!("{id} signature: {error}"));
        let signing_key = PublicKey::from_compressed_bytes(kernel.excess.as_bytes())
            .unwrap_or_else(|error| panic!("{id} excess: {error}"));
        let aggregate_nonce_hat =
            PublicKey::from_compressed_bytes(expected_signature.r_compressed())
                .unwrap_or_else(|error| panic!("{id} nonce: {error}"));
        let pre_signature = AdaptorPreSignatureV1::new(
            [0x22; 32],
            adaptor_point,
            aggregate_nonce_hat,
            scalar_hat,
            [0x33; 32],
        );

        assert!(
            pre_signature
                .verify(&[0x22; 32], &[0x33; 32], &signing_key, &CHAIN_ID, &MESSAGE,)
                .unwrap_or_else(|error| panic!("{id} pre-signature verify: {error}")),
            "{id} pre-signature equation"
        );
        let adapted = pre_signature
            .adapt(
                &secret,
                &[0x22; 32],
                &[0x33; 32],
                &signing_key,
                &CHAIN_ID,
                &MESSAGE,
            )
            .unwrap_or_else(|error| panic!("{id} adaptation: {error}"));
        assert_eq!(
            adapted.to_bytes(),
            expected_signature.to_bytes(),
            "{id} exact adapted signature"
        );
        let extracted = pre_signature
            .extract(
                &adapted,
                &[0x22; 32],
                &[0x33; 32],
                &signing_key,
                &CHAIN_ID,
                &MESSAGE,
            )
            .unwrap_or_else(|error| panic!("{id} extraction: {error}"));
        assert_eq!(
            extracted.public_point().expect("extracted point"),
            secret.public_point().expect("adaptor point"),
            "{id} extracted point"
        );
        let revealed = pre_signature
            .extract_revealed_secret_be_bytes(
                &adapted,
                &[0x22; 32],
                &[0x33; 32],
                &signing_key,
                &CHAIN_ID,
                &MESSAGE,
            )
            .unwrap_or_else(|error| panic!("{id} revealed extraction: {error}"));
        assert_eq!(
            *revealed, secret_bytes,
            "{id} revealed bytes satisfy t*G == T"
        );

        let transaction = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            kernels: vec![kernel],
            offset: [0; 32],
        };
        validate_kernel_signatures(&transaction, &CHAIN_ID)
            .unwrap_or_else(|error| panic!("{id} real consensus verifier: {error}"));
        count += 1;
    }
    assert_eq!(
        count, 8,
        "the frozen SCAD0 corpus remains exactly eight vectors"
    );
}

#[test]
fn pre_signature_parser_is_exact_and_fail_closed() {
    let line = include_str!("../../dom-consensus/tests/fixtures/scad0_adaptor_vectors_v1.txt")
        .lines()
        .find(|line| line.starts_with("V01|"))
        .expect("V01 exists");
    let fields = line.split('|').collect::<Vec<_>>();
    let kernel = TransactionKernel::from_bytes(&hex::decode(fields[4]).expect("kernel hex"))
        .expect("kernel is canonical");
    let signature = SchnorrSignature::from_bytes(&kernel.excess_signature).expect("signature");
    let signing_key =
        PublicKey::from_compressed_bytes(kernel.excess.as_bytes()).expect("excess point");
    let pre_signature = AdaptorPreSignatureV1::new(
        [0x22; 32],
        PublicKey::from_compressed_bytes(&decode_array::<33>(fields[2])).expect("T"),
        PublicKey::from_compressed_bytes(signature.r_compressed()).expect("R_hat"),
        PartialSig::from_bytes(&decode_array::<32>(fields[3])).expect("s_hat"),
        [0x33; 32],
    );
    let bytes = pre_signature.to_bytes();
    assert_eq!(
        AdaptorPreSignatureV1::from_bytes(&bytes)
            .expect("canonical payload")
            .to_bytes(),
        bytes
    );
    assert!(AdaptorPreSignatureV1::from_bytes(&bytes[..161]).is_err());
    let mut with_trailing = bytes.to_vec();
    with_trailing.push(0);
    assert!(AdaptorPreSignatureV1::from_bytes(&with_trailing).is_err());

    for index in 32..65 {
        let mut mutated = bytes;
        mutated[index] ^= 0x80;
        if let Ok(parsed) = AdaptorPreSignatureV1::from_bytes(&mutated) {
            assert_ne!(parsed.adaptor_point(), pre_signature.adaptor_point());
        }
    }
    let mut zero_scalar = bytes;
    zero_scalar[98..130].fill(0);
    assert!(AdaptorPreSignatureV1::from_bytes(&zero_scalar).is_err());

    let order = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
        .expect("secp256k1 group order");
    let mut order_scalar = bytes;
    order_scalar[98..130].copy_from_slice(&order);
    assert!(AdaptorPreSignatureV1::from_bytes(&order_scalar).is_err());

    let mut order_plus_one = order;
    order_plus_one[31] = order_plus_one[31]
        .checked_add(1)
        .expect("group-order low byte can be incremented");
    let mut order_plus_one_scalar = bytes;
    order_plus_one_scalar[98..130].copy_from_slice(&order_plus_one);
    assert!(AdaptorPreSignatureV1::from_bytes(&order_plus_one_scalar).is_err());

    let mut mutated_template = bytes;
    mutated_template[0] ^= 1;
    let mutated_template =
        AdaptorPreSignatureV1::from_bytes(&mutated_template).expect("hash remains canonical bytes");
    assert!(mutated_template
        .verify(&[0x22; 32], &[0x33; 32], &signing_key, &CHAIN_ID, &MESSAGE,)
        .is_err());
    let mut mutated_transcript = bytes;
    mutated_transcript[161] ^= 1;
    let mutated_transcript = AdaptorPreSignatureV1::from_bytes(&mutated_transcript)
        .expect("hash remains canonical bytes");
    assert!(mutated_transcript
        .verify(&[0x22; 32], &[0x33; 32], &signing_key, &CHAIN_ID, &MESSAGE,)
        .is_err());
}

#[test]
fn core_and_session_bound_pre_signatures_have_distinct_exact_lengths() {
    let line = include_str!("../../dom-consensus/tests/fixtures/scad0_adaptor_vectors_v1.txt")
        .lines()
        .find(|line| line.starts_with("V01|"))
        .expect("V01 exists");
    let fields = line.split('|').collect::<Vec<_>>();
    let kernel = TransactionKernel::from_bytes(&hex::decode(fields[4]).expect("kernel hex"))
        .expect("kernel");
    let signature = SchnorrSignature::from_bytes(&kernel.excess_signature).expect("signature");
    let pre = AdaptorPreSignatureV1::new(
        [0x22; 32],
        PublicKey::from_compressed_bytes(&decode_array::<33>(fields[2])).expect("T"),
        PublicKey::from_compressed_bytes(signature.r_compressed()).expect("R_hat"),
        PartialSig::from_bytes(&decode_array::<32>(fields[3])).expect("s_hat"),
        [0x33; 32],
    );
    let core = pre.core_bytes();
    assert_eq!(core.len(), 65);
    assert_eq!(pre.to_bytes().len(), 162);
    assert_eq!(
        CoreAdaptorPreSignatureV1::from_bytes(&core)
            .expect("canonical core")
            .to_bytes(),
        core
    );
    assert!(CoreAdaptorPreSignatureV1::from_bytes(&pre.to_bytes()).is_err());
}

#[test]
fn wrong_adaptor_secret_and_mutated_signature_are_rejected() {
    let line = include_str!("../../dom-consensus/tests/fixtures/scad0_adaptor_vectors_v1.txt")
        .lines()
        .find(|line| line.starts_with("V01|"))
        .expect("V01 exists");
    let fields = line.split('|').collect::<Vec<_>>();
    let kernel = TransactionKernel::from_bytes(&hex::decode(fields[4]).expect("kernel hex"))
        .expect("kernel is canonical");
    let signature = SchnorrSignature::from_bytes(&kernel.excess_signature).expect("signature");
    let signing_key =
        PublicKey::from_compressed_bytes(kernel.excess.as_bytes()).expect("excess point");
    let pre_signature = AdaptorPreSignatureV1::new(
        [0x22; 32],
        PublicKey::from_compressed_bytes(&decode_array::<33>(fields[2])).expect("T"),
        PublicKey::from_compressed_bytes(signature.r_compressed()).expect("R_hat"),
        PartialSig::from_bytes(&decode_array::<32>(fields[3])).expect("s_hat"),
        [0x33; 32],
    );
    let mut wrong = [0u8; 32];
    wrong[31] = 1;
    let wrong = AdaptorSecret::from_be_bytes(wrong).expect("one is canonical");
    assert!(pre_signature
        .adapt(
            &wrong,
            &[0x22; 32],
            &[0x33; 32],
            &signing_key,
            &CHAIN_ID,
            &MESSAGE,
        )
        .is_err());

    let mut mutated = signature.to_bytes();
    mutated[64] ^= 1;
    if let Ok(mutated) = SchnorrSignature::from_bytes(&mutated) {
        assert!(pre_signature
            .extract(
                &mutated,
                &[0x22; 32],
                &[0x33; 32],
                &signing_key,
                &CHAIN_ID,
                &MESSAGE,
            )
            .is_err());
        assert!(pre_signature
            .extract_revealed_secret_be_bytes(
                &mutated,
                &[0x22; 32],
                &[0x33; 32],
                &signing_key,
                &CHAIN_ID,
                &MESSAGE,
            )
            .is_err());
    }
    assert!(pre_signature
        .extract_revealed_secret_be_bytes(
            &signature,
            &[0x23; 32],
            &[0x33; 32],
            &signing_key,
            &CHAIN_ID,
            &MESSAGE,
        )
        .is_err());
}

#[test]
fn unit_opening_verifier_accepts_only_the_exact_public_session_bindings() {
    let mut lines = include_str!("../../dom-consensus/tests/fixtures/scad0_adaptor_vectors_v1.txt")
        .lines()
        .filter(|line| line.starts_with('V'));
    let fields = lines
        .next()
        .expect("first SCAD0 vector exists")
        .split('|')
        .collect::<Vec<_>>();
    let other_fields = lines
        .next()
        .expect("second SCAD0 vector exists")
        .split('|')
        .collect::<Vec<_>>();
    let kernel = TransactionKernel::from_bytes(&hex::decode(fields[4]).expect("kernel hex"))
        .expect("kernel is canonical");
    let final_signature =
        SchnorrSignature::from_bytes(&kernel.excess_signature).expect("final signature");
    let signing_key =
        PublicKey::from_compressed_bytes(kernel.excess.as_bytes()).expect("signing key");
    let pre_signature = AdaptorPreSignatureV1::new(
        [0x22; 32],
        PublicKey::from_compressed_bytes(&decode_array::<33>(fields[2])).expect("T"),
        PublicKey::from_compressed_bytes(final_signature.r_compressed()).expect("R hat"),
        PartialSig::from_bytes(&decode_array::<32>(fields[3])).expect("s hat"),
        [0x33; 32],
    );
    let exact = FinalSignatureOpeningContextV1 {
        expected_claim_template_hash: &[0x22; 32],
        expected_transcript_hash: &[0x33; 32],
        signing_key: &signing_key,
        chain_id: &CHAIN_ID,
        kernel_message: &MESSAGE,
    };

    let _: () = pre_signature
        .verify_final_signature_opens_adaptor_point_v1(&final_signature, &exact)
        .expect("the exact final signature opens the committed adaptor point");

    let wrong_template = [0x23; 32];
    let wrong_transcript = [0x34; 32];
    let wrong_chain = [0xAE; 32];
    let mut wrong_message = MESSAGE;
    wrong_message[0] ^= 1;
    let other_kernel =
        TransactionKernel::from_bytes(&hex::decode(other_fields[4]).expect("other kernel hex"))
            .expect("other kernel is canonical");
    let wrong_signing_key = PublicKey::from_compressed_bytes(other_kernel.excess.as_bytes())
        .expect("other signing key");

    for (case, context) in [
        (
            "claim template",
            FinalSignatureOpeningContextV1 {
                expected_claim_template_hash: &wrong_template,
                expected_transcript_hash: &[0x33; 32],
                signing_key: &signing_key,
                chain_id: &CHAIN_ID,
                kernel_message: &MESSAGE,
            },
        ),
        (
            "transcript",
            FinalSignatureOpeningContextV1 {
                expected_claim_template_hash: &[0x22; 32],
                expected_transcript_hash: &wrong_transcript,
                signing_key: &signing_key,
                chain_id: &CHAIN_ID,
                kernel_message: &MESSAGE,
            },
        ),
        (
            "aggregate signing key",
            FinalSignatureOpeningContextV1 {
                expected_claim_template_hash: &[0x22; 32],
                expected_transcript_hash: &[0x33; 32],
                signing_key: &wrong_signing_key,
                chain_id: &CHAIN_ID,
                kernel_message: &MESSAGE,
            },
        ),
        (
            "chain",
            FinalSignatureOpeningContextV1 {
                expected_claim_template_hash: &[0x22; 32],
                expected_transcript_hash: &[0x33; 32],
                signing_key: &signing_key,
                chain_id: &wrong_chain,
                kernel_message: &MESSAGE,
            },
        ),
        (
            "kernel message",
            FinalSignatureOpeningContextV1 {
                expected_claim_template_hash: &[0x22; 32],
                expected_transcript_hash: &[0x33; 32],
                signing_key: &signing_key,
                chain_id: &CHAIN_ID,
                kernel_message: &wrong_message,
            },
        ),
    ] {
        assert!(
            pre_signature
                .verify_final_signature_opens_adaptor_point_v1(&final_signature, &context)
                .is_err(),
            "divergent {case} must fail closed"
        );
    }

    // The final signature remains valid for the original public session, but
    // pairing its scalar difference with another committed adaptor point must
    // still fail closed.
    let incompatible_pre_signature = AdaptorPreSignatureV1::new(
        [0x22; 32],
        PublicKey::from_compressed_bytes(&decode_array::<33>(other_fields[2]))
            .expect("different adaptor point"),
        PublicKey::from_compressed_bytes(final_signature.r_compressed()).expect("R hat"),
        PartialSig::from_bytes(&decode_array::<32>(fields[3])).expect("s hat"),
        [0x33; 32],
    );
    let transaction = Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
        kernels: vec![kernel],
        offset: [0; 32],
    };
    validate_kernel_signatures(&transaction, &CHAIN_ID)
        .expect("the observed final signature itself remains consensus-valid");
    assert!(incompatible_pre_signature
        .verify_final_signature_opens_adaptor_point_v1(&final_signature, &exact)
        .is_err());
}

/// The secp256k1 field prime `p = 2^256 - 2^32 - 977`. An x coordinate must be
/// strictly below it.
const FIELD_PRIME: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

fn compressed(prefix: u8, x: [u8; 32]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = prefix;
    out[1..].copy_from_slice(&x);
    out
}

/// Every classic SEC1 parsing escape must be rejected by class.
///
/// The existing negative coverage flips the high bit across the point bytes,
/// which produces mostly-invalid points but never pins *why* each class is
/// refused. ADR-0010 requires identity, non-canonical encodings and malformed
/// points to be rejected explicitly, so each class is named here.
#[test]
fn non_canonical_sec1_points_are_rejected_by_class() {
    let mut valid_x = [0u8; 32];
    valid_x[31] = 1; // x = 1 is on the curve.
    let mut not_on_curve_x = [0u8; 32];
    not_on_curve_x[31] = 5; // x = 5 has no square root of x^3 + 7.

    let cases: [(&str, [u8; 33]); 10] = [
        (
            "prefix 0x00 is not a compressed-point prefix",
            compressed(0x00, valid_x),
        ),
        (
            "prefix 0x01 is not a compressed-point prefix",
            compressed(0x01, valid_x),
        ),
        (
            "prefix 0x04 is the uncompressed prefix",
            compressed(0x04, valid_x),
        ),
        ("prefix 0x05 is reserved", compressed(0x05, valid_x)),
        ("prefix 0x06 is a hybrid prefix", compressed(0x06, valid_x)),
        ("prefix 0x07 is a hybrid prefix", compressed(0x07, valid_x)),
        ("all-zero encoding is the identity, not a point", [0u8; 33]),
        (
            "x equal to the field prime is out of range",
            compressed(0x02, FIELD_PRIME),
        ),
        (
            "x above the field prime is out of range",
            compressed(0x03, [0xff; 32]),
        ),
        (
            "x with no curve point must not decode",
            compressed(0x02, not_on_curve_x),
        ),
    ];

    // 1. The authoritative DOM point parser rejects every class directly.
    for (why, encoded) in &cases {
        assert!(
            PublicKey::from_compressed_bytes(encoded).is_err(),
            "DOM point parser accepted a bad encoding: {why}"
        );
    }

    // 2. And none of them can enter the canonical pre-signature payload, whose
    //    adaptor point occupies bytes 32..65 of the 162-byte layout.
    let line = include_str!("../../dom-consensus/tests/fixtures/scad0_adaptor_vectors_v1.txt")
        .lines()
        .find(|line| line.starts_with("V01|"))
        .expect("V01 exists");
    let fields = line.split('|').collect::<Vec<_>>();
    let kernel = TransactionKernel::from_bytes(&hex::decode(fields[4]).expect("kernel hex"))
        .expect("kernel is canonical");
    let signature = SchnorrSignature::from_bytes(&kernel.excess_signature).expect("signature");
    let canonical = AdaptorPreSignatureV1::new(
        [0x22; 32],
        PublicKey::from_compressed_bytes(&decode_array::<33>(fields[2])).expect("T"),
        PublicKey::from_compressed_bytes(signature.r_compressed()).expect("R_hat"),
        PartialSig::from_bytes(&decode_array::<32>(fields[3])).expect("s_hat"),
        [0x33; 32],
    )
    .to_bytes();

    for (why, encoded) in &cases {
        let mut payload = canonical;
        payload[32..65].copy_from_slice(encoded);
        assert!(
            AdaptorPreSignatureV1::from_bytes(&payload).is_err(),
            "pre-signature decoder accepted a bad adaptor point: {why}"
        );
    }

    // 3. A sanity anchor: the untouched payload still parses, so the loop above
    //    is rejecting the point and not the surrounding bytes.
    assert!(AdaptorPreSignatureV1::from_bytes(&canonical).is_ok());
}

/// Real SCAD0 corpus: the observation proof accepts exactly what the
/// unit-returning verifier accepts, and it seals the observed binding so a
/// genuine opening cannot later be paired with a different transaction.
#[test]
fn observation_opening_proof_seals_the_exact_observed_claim() {
    let fields = include_str!("../../dom-consensus/tests/fixtures/scad0_adaptor_vectors_v1.txt")
        .lines()
        .find(|line| line.starts_with('V'))
        .expect("first SCAD0 vector exists")
        .split('|')
        .collect::<Vec<_>>();
    let kernel = TransactionKernel::from_bytes(&hex::decode(fields[4]).expect("kernel hex"))
        .expect("kernel is canonical");
    let final_signature =
        SchnorrSignature::from_bytes(&kernel.excess_signature).expect("final signature");
    let signing_key =
        PublicKey::from_compressed_bytes(kernel.excess.as_bytes()).expect("signing key");
    let adaptor_point =
        PublicKey::from_compressed_bytes(&decode_array::<33>(fields[2])).expect("T");
    let pre_signature = AdaptorPreSignatureV1::new(
        [0x22; 32],
        adaptor_point.clone(),
        PublicKey::from_compressed_bytes(final_signature.r_compressed()).expect("R hat"),
        PartialSig::from_bytes(&decode_array::<32>(fields[3])).expect("s hat"),
        [0x33; 32],
    );
    let exact = FinalSignatureOpeningContextV1 {
        expected_claim_template_hash: &[0x22; 32],
        expected_transcript_hash: &[0x33; 32],
        signing_key: &signing_key,
        chain_id: &CHAIN_ID,
        kernel_message: &MESSAGE,
    };
    let binding = ObservedClaimBindingV1 {
        tx_hash: [0x41; 32],
        shared_output_commitment: [0x02; 33],
        kernel_index: 0,
    };
    let facts = ObservedClaimFactsV1 {
        chain_id: CHAIN_ID,
        session_id: [0x42; 32],
        tx_hash: binding.tx_hash,
        template_hash: [0x22; 32],
        shared_output_commitment: binding.shared_output_commitment,
        location: ObservedClaimLocationV1 {
            block_height: 9,
            block_hash: [0x43; 32],
            transaction_index: 1,
        },
        observed_tip_height: 13,
        observed_tip_id: [0x45; 32],
    };

    let proof = pre_signature
        .prove_observed_claim_opens_adaptor_point_v1(&final_signature, &exact, binding)
        .expect("the exact final signature opens the committed adaptor point");
    let observed = VerifiedDomClaimObservationV1::from_verified_opening_v1(
        proof,
        DomClaimObservationTagV1::CounterpartyClaimObserved,
        facts,
    )
    .expect("consistent observation");
    assert_eq!(observed.chain_id(), &CHAIN_ID);
    assert_eq!(observed.tx_hash(), &binding.tx_hash);
    assert_eq!(
        observed.shared_output_commitment(),
        &binding.shared_output_commitment
    );
    assert_eq!(observed.template_hash(), &[0x22; 32]);
    assert_eq!(observed.adaptor_point(), &adaptor_point);
    assert_eq!(observed.kernel_index(), 0);
    assert_eq!(observed.location(), facts.location);

    // A genuine opening paired with different observed facts fails closed.
    for divergent in [
        ObservedClaimFactsV1 {
            tx_hash: [0x44; 32],
            ..facts
        },
        ObservedClaimFactsV1 {
            shared_output_commitment: [0x03; 33],
            ..facts
        },
        ObservedClaimFactsV1 {
            template_hash: [0x23; 32],
            ..facts
        },
        ObservedClaimFactsV1 {
            chain_id: [0xAE; 32],
            ..facts
        },
        // A tip that predates the observed block cannot have that block as an
        // ancestor, so the pair is incoherent whatever the opening proves.
        ObservedClaimFactsV1 {
            observed_tip_height: facts.location.block_height - 1,
            ..facts
        },
        ObservedClaimFactsV1 {
            observed_tip_id: [0; 32],
            ..facts
        },
    ] {
        let proof = pre_signature
            .prove_observed_claim_opens_adaptor_point_v1(&final_signature, &exact, binding)
            .expect("the opening itself still succeeds");
        // `expect_err` is unavailable on purpose: it would require the
        // capability to implement `Debug`, and it deliberately does not.
        let Err(error) = VerifiedDomClaimObservationV1::from_verified_opening_v1(
            proof,
            DomClaimObservationTagV1::CounterpartyClaimObserved,
            divergent,
        ) else {
            panic!("facts that contradict the sealed opening must fail closed: {divergent:?}");
        };
        assert_eq!(error, ClaimObservationError::InconsistentObservation);
    }

    // The proof cannot be minted at all when the public session diverges.
    assert!(pre_signature
        .prove_observed_claim_opens_adaptor_point_v1(
            &final_signature,
            &FinalSignatureOpeningContextV1 {
                expected_claim_template_hash: &[0x23; 32],
                expected_transcript_hash: &[0x33; 32],
                signing_key: &signing_key,
                chain_id: &CHAIN_ID,
                kernel_message: &MESSAGE,
            },
            binding,
        )
        .is_err());
}
