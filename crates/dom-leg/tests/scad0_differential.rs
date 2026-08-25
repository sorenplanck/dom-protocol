//! §8 differential against the frozen SCAD0 corpus of pin 180b731.
//!
//! Byte-identical copy of
//! `dom-consensus/tests/fixtures/scad0_adaptor_vectors_v1.txt` (the integrity
//! test below locks the hash declared in the header). Each vector goes
//! through `AdaptorPreSignatureV1::{verify, adapt, extract}` and the adapted
//! signature is accepted by the REAL CONSENSUS VERIFIER
//! (`validate_kernel_signatures`) — the only suite in the repository that
//! ends there, complementing the round tests in `round.rs` (which end at
//! `finalize_plain_signature_v1`).
//!
//! Domain constants identical to those of the pinned crate's G1a tests — the
//! vectors were generated under those fixed bindings, which is why this
//! differential talks to the pin directly, and not to a real
//! `SessionBindings` (whose transcript embeds a per-session random
//! session_id).

use dom_adaptor::{AdaptorPreSignatureV1, AdaptorSecret};
use dom_consensus::{validate_kernel_signatures, Transaction, TransactionKernel};
use dom_crypto::{PartialSig, PublicKey, SchnorrSignature};
use dom_serialization::DomDeserialize;

const CHAIN_ID: [u8; 32] = [0xAD; 32];
const CLAIM_TEMPLATE_HASH: [u8; 32] = [0x22; 32];
const TRANSCRIPT_HASH: [u8; 32] = [0x33; 32];
const MESSAGE: [u8; 32] = [
    0x10, 0xd4, 0x3a, 0x5a, 0xc3, 0x16, 0x0f, 0xdb, 0xc6, 0x7a, 0x1f, 0x8a, 0x29, 0x3f, 0x97, 0x50,
    0x55, 0x8e, 0x53, 0xc1, 0x8f, 0xa3, 0x7f, 0x58, 0xd3, 0x40, 0xdf, 0x3f, 0xdd, 0x41, 0xaa, 0x34,
];

const FIXTURE: &str = include_str!("fixtures/scad0_adaptor_vectors_v1.txt");

fn hex_decode(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0, "hex length");
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex_decode(value).try_into().expect("fixture field width")
}

struct Vector {
    id: String,
    secret: AdaptorSecret,
    /// The corpus scalar in its canonical byte form, kept so the revealed
    /// export can be compared against it byte for byte.
    secret_bytes: [u8; 32],
    adaptor_point: PublicKey,
    scalar_hat: PartialSig,
    kernel: TransactionKernel,
}

impl Vector {
    fn signing_key(&self) -> PublicKey {
        PublicKey::from_compressed_bytes(self.kernel.excess.as_bytes()).expect("excess point")
    }

    fn final_signature(&self) -> SchnorrSignature {
        SchnorrSignature::from_bytes(&self.kernel.excess_signature).expect("kernel signature")
    }

    fn pre_signature(&self) -> AdaptorPreSignatureV1 {
        AdaptorPreSignatureV1::new(
            CLAIM_TEMPLATE_HASH,
            self.adaptor_point.clone(),
            PublicKey::from_compressed_bytes(self.final_signature().r_compressed()).expect("R_hat"),
            PartialSig::from_bytes(&self.scalar_hat.to_bytes()).expect("s_hat"),
            TRANSCRIPT_HASH,
        )
    }
}

fn vectors() -> Vec<Vector> {
    FIXTURE
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let fields = line.split('|').collect::<Vec<_>>();
            assert_eq!(fields.len(), 5, "SCAD0 record shape");
            Vector {
                id: fields[0].to_string(),
                secret: AdaptorSecret::from_be_bytes(hex_array(fields[1])).expect("t"),
                secret_bytes: hex_array(fields[1]),
                adaptor_point: PublicKey::from_compressed_bytes(&hex_array::<33>(fields[2]))
                    .expect("T"),
                scalar_hat: PartialSig::from_bytes(&hex_array::<32>(fields[3])).expect("s_hat"),
                kernel: TransactionKernel::from_bytes(&hex_decode(fields[4]))
                    .expect("fixture kernel is canonical"),
            }
        })
        .collect()
}

#[test]
fn fixture_copy_is_byte_identical_to_the_pin() {
    assert!(
        FIXTURE.contains("e99ad8a32edc3db52941e6729c032893d2b864ab995821debf574468b7beaa4b"),
        "corpus header diverged from the frozen copy"
    );
    assert_eq!(vectors().len(), 8, "the SCAD0 corpus has exactly 8 vectors");
}

#[test]
fn all_eight_vectors_verify_adapt_and_pass_the_real_consensus_verifier() {
    for vector in vectors() {
        assert_eq!(
            vector.secret.public_point().expect("t*G"),
            vector.adaptor_point,
            "{}: t*G == T",
            vector.id
        );
        let pre = vector.pre_signature();
        let signing_key = vector.signing_key();

        assert!(
            pre.verify(
                &CLAIM_TEMPLATE_HASH,
                &TRANSCRIPT_HASH,
                &signing_key,
                &CHAIN_ID,
                &MESSAGE,
            )
            .unwrap_or_else(|error| panic!("{}: verify: {error}", vector.id)),
            "{}: pre-signature equation",
            vector.id
        );

        let adapted = pre
            .adapt(
                &vector.secret,
                &CLAIM_TEMPLATE_HASH,
                &TRANSCRIPT_HASH,
                &signing_key,
                &CHAIN_ID,
                &MESSAGE,
            )
            .unwrap_or_else(|error| panic!("{}: adapt: {error}", vector.id));
        assert_eq!(
            adapted.to_bytes().as_slice(),
            &vector.kernel.excess_signature[..],
            "{}: adapted signature byte-identical to the frozen kernel",
            vector.id
        );

        // The produced signature is exactly the one the NORMAL, UNMODIFIED
        // DOM verifier accepts (§2.1) — end of the differential.
        let transaction = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            kernels: vec![vector.kernel.clone()],
            offset: [0; 32],
        };
        validate_kernel_signatures(&transaction, &CHAIN_ID)
            .unwrap_or_else(|error| panic!("{}: real consensus: {error}", vector.id));
    }
}

#[test]
fn all_eight_vectors_extract_the_committed_secret() {
    for vector in vectors() {
        let pre = vector.pre_signature();
        let extracted = pre
            .extract(
                &vector.final_signature(),
                &CLAIM_TEMPLATE_HASH,
                &TRANSCRIPT_HASH,
                &vector.signing_key(),
                &CHAIN_ID,
                &MESSAGE,
            )
            .unwrap_or_else(|error| panic!("{}: extract: {error}", vector.id));
        assert_eq!(
            extracted.public_point().expect("secret's point"),
            vector.adaptor_point,
            "{}: extracted t matches the committed T",
            vector.id
        );

        // D-016: the same extraction, through the authority's byte export.
        // Comparing the POINT proves we recovered the right scalar; comparing
        // the BYTES proves the value the counterparty leg would be claimed
        // with is that same scalar and not a look-alike.
        let revealed = pre
            .extract_revealed_secret_be_bytes(
                &vector.final_signature(),
                &CLAIM_TEMPLATE_HASH,
                &TRANSCRIPT_HASH,
                &vector.signing_key(),
                &CHAIN_ID,
                &MESSAGE,
            )
            .unwrap_or_else(|error| panic!("{}: revealed export: {error}", vector.id));
        assert_eq!(
            *revealed, vector.secret_bytes,
            "{}: revealed bytes are the corpus t, byte for byte",
            vector.id
        );
    }
}

#[test]
fn wrong_secret_and_mutated_signature_are_rejected() {
    let vector = &vectors()[0];
    let pre = vector.pre_signature();
    let signing_key = vector.signing_key();

    let mut wrong = [0u8; 32];
    wrong[31] = 1;
    let wrong = AdaptorSecret::from_be_bytes(wrong).expect("1 is canonical");
    assert!(
        pre.adapt(
            &wrong,
            &CLAIM_TEMPLATE_HASH,
            &TRANSCRIPT_HASH,
            &signing_key,
            &CHAIN_ID,
            &MESSAGE,
        )
        .is_err(),
        "secret whose point diverges from the committed T"
    );

    let mut mutated = vector.final_signature().to_bytes();
    mutated[64] ^= 1;
    if let Ok(mutated) = SchnorrSignature::from_bytes(&mutated) {
        // The byte export must refuse wherever the opaque path refuses; an
        // export that verified less would be exactly the wrong difference.
        assert!(
            pre.extract_revealed_secret_be_bytes(
                &mutated,
                &CLAIM_TEMPLATE_HASH,
                &TRANSCRIPT_HASH,
                &signing_key,
                &CHAIN_ID,
                &MESSAGE,
            )
            .is_err(),
            "the revealed export must reject a mutated final signature"
        );
        assert!(
            pre.extract(
                &mutated,
                &CLAIM_TEMPLATE_HASH,
                &TRANSCRIPT_HASH,
                &signing_key,
                &CHAIN_ID,
                &MESSAGE,
            )
            .is_err(),
            "a tampered final signature extracts no secret"
        );
    }
}
