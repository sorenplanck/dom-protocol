use dom_consensus::{validate_kernel_signatures, Transaction, TransactionKernel};
use dom_crypto::{
    schnorr_aggregate_sigs, schnorr_challenge, schnorr_verify, PartialSig, PublicKey,
    SchnorrSignature,
};
use dom_serialization::DomDeserialize;
use k256::elliptic_curve::{sec1::FromEncodedPoint, PrimeField};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};

const CHAIN_ID: [u8; 32] = [0xAD; 32];
const MESSAGE: [u8; 32] = [
    0x10, 0xd4, 0x3a, 0x5a, 0xc3, 0x16, 0x0f, 0xdb, 0xc6, 0x7a, 0x1f, 0x8a, 0x29, 0x3f, 0x97, 0x50,
    0x55, 0x8e, 0x53, 0xc1, 0x8f, 0xa3, 0x7f, 0x58, 0xd3, 0x40, 0xdf, 0x3f, 0xdd, 0x41, 0xaa, 0x34,
];

struct Vector {
    id: String,
    t: [u8; 32],
    t_point: [u8; 33],
    s_hat: [u8; 32],
    kernel: TransactionKernel,
}

fn decode_array<const N: usize>(hex_value: &str) -> [u8; N] {
    decode_hex(hex_value)
        .try_into()
        .unwrap_or_else(|_| panic!("fixture field must contain exactly {N} bytes"))
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "fixture hex length must be even");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("fixture hex is ASCII");
            u8::from_str_radix(text, 16).expect("fixture field is hex")
        })
        .collect()
}

fn vectors() -> Vec<Vector> {
    include_str!("fixtures/scad0_adaptor_vectors_v1.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let fields = line.split('|').collect::<Vec<_>>();
            assert_eq!(fields.len(), 5, "fixture line has five fields");
            let kernel_bytes = decode_hex(fields[4]);
            assert_eq!(kernel_bytes.len(), 115, "kernel wire size is frozen");
            Vector {
                id: fields[0].to_owned(),
                t: decode_array(fields[1]),
                t_point: decode_array(fields[2]),
                s_hat: decode_array(fields[3]),
                kernel: TransactionKernel::from_bytes(&kernel_bytes)
                    .expect("fixture kernel is canonical"),
            }
        })
        .collect()
}

fn scalar(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_repr(bytes.into())).expect("fixture scalar is canonical")
}

fn point(bytes: [u8; 33]) -> ProjectivePoint {
    let encoded = EncodedPoint::from_bytes(bytes).expect("fixture point is SEC1");
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .expect("fixture point lies on secp256k1");
    ProjectivePoint::from(affine)
}

#[test]
fn canonical_scad0_vectors_verify_adapt_verify_extract() {
    let vectors = vectors();
    assert_eq!(
        vectors.len(),
        8,
        "the permanent SCAD0 corpus is frozen at 8"
    );

    for vector in vectors {
        let signature = SchnorrSignature::from_bytes(&vector.kernel.excess_signature)
            .unwrap_or_else(|error| panic!("{} signature parse: {error}", vector.id));
        let excess = PublicKey::from_compressed_bytes(vector.kernel.excess.as_bytes())
            .unwrap_or_else(|error| panic!("{} excess parse: {error}", vector.id));
        let r_hat = PublicKey::from_compressed_bytes(signature.r_compressed())
            .unwrap_or_else(|error| panic!("{} R_hat parse: {error}", vector.id));

        // verify(pre-signature): s_hat·G == R_hat + e·X - T.
        let challenge = scalar(
            *schnorr_challenge(signature.r_compressed(), &excess, &CHAIN_ID, &MESSAGE).as_bytes(),
        );
        let lhs = ProjectivePoint::GENERATOR * scalar(vector.s_hat);
        let rhs = point(*signature.r_compressed())
            + point(excess.to_compressed_bytes()) * challenge
            - point(vector.t_point);
        assert_eq!(lhs, rhs, "{} pre-signature verification", vector.id);

        // adapt through the production aggregation helper.
        let adapted = schnorr_aggregate_sigs(
            &[
                PartialSig::from_bytes(&vector.s_hat).unwrap(),
                PartialSig::from_bytes(&vector.t).unwrap(),
            ],
            &r_hat,
        )
        .unwrap_or_else(|error| panic!("{} adapt: {error}", vector.id));
        assert_eq!(
            adapted.to_bytes(),
            vector.kernel.excess_signature,
            "{} adapted signature bytes",
            vector.id
        );

        // verify through both the real primitive and the consensus wrapper.
        assert!(
            schnorr_verify(&adapted, &excess, &CHAIN_ID, &MESSAGE)
                .unwrap_or_else(|error| panic!("{} primitive verify: {error}", vector.id)),
            "{} primitive verification",
            vector.id
        );
        let tx = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            kernels: vec![vector.kernel.clone()],
            offset: [0; 32],
        };
        validate_kernel_signatures(&tx, &CHAIN_ID)
            .unwrap_or_else(|error| panic!("{} consensus verify: {error}", vector.id));

        // extract: t' = s - s_hat, then bind the scalar back to T.
        let signature_bytes = adapted.to_bytes();
        let s: [u8; 32] = signature_bytes[33..].try_into().unwrap();
        let extracted = scalar(s) - scalar(vector.s_hat);
        assert_eq!(
            extracted,
            scalar(vector.t),
            "{} extracted scalar",
            vector.id
        );
        assert_eq!(
            ProjectivePoint::GENERATOR * extracted,
            point(vector.t_point),
            "{} extracted t·G == T",
            vector.id
        );
    }
}
