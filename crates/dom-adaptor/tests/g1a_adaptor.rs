//! Production-boundary tests using the frozen SCAD0 corpus and real DOM verifier.

use dom_adaptor::{AdaptorPreSignatureV1, AdaptorSecret, CoreAdaptorPreSignatureV1};
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
        let secret = AdaptorSecret::from_be_bytes(decode_array(fields[1]))
            .unwrap_or_else(|error| panic!("{id} secret: {error}"));
        let adaptor_point = PublicKey::from_compressed_bytes(&decode_array::<33>(fields[2]))
            .unwrap_or_else(|error| panic!("{id} adaptor point: {error}"));
        assert_eq!(secret.public_point(), adaptor_point, "{id} t*G == T");
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
            extracted.public_point(),
            secret.public_point(),
            "{id} extracted point"
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
    }
}
