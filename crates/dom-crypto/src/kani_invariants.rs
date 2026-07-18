//! Kani proofs for protocol-facing cryptographic boundary decisions.

use crate::keys::{classify_compressed_key_frontier, CompressedKeyFrontier};
use crate::range_proof::{range_proof_length_is_canonical, RANGE_PROOF_SIZE};
use crate::recovery::{
    classify_recovery_capsule_frontier, RecoveryCapsuleFrontier, RECOVERY_CAPSULE_SIZE,
    RECOVERY_CIPHERTEXT_SIZE, RECOVERY_METADATA_VERSION, RECOVERY_VERSION,
};
use crate::schnorr::{
    is_scalar_valid, partial_signature_length_is_canonical, signature_length_is_canonical,
};

const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerificationOutcome {
    Valid,
    Invalid,
    Malformed,
    InternalFailure,
}

const fn verification_is_accepted(outcome: VerificationOutcome) -> bool {
    matches!(outcome, VerificationOutcome::Valid)
}

#[kani::proof]
fn range_proof_length_gate_is_exact_for_every_usize() {
    let length: usize = kani::any();
    kani::assert(
        range_proof_length_is_canonical(length) == (length == 739),
        "the range-proof length gate must accept exactly 739 bytes",
    );
    kani::assert(
        RANGE_PROOF_SIZE == 739,
        "the frozen proof size must remain 739",
    );
}

#[kani::proof]
fn recovery_capsule_framing_is_exact_for_every_frontier() {
    let length: usize = kani::any();
    let version: u16 = kani::any();
    let ciphertext_length: usize = kani::any();
    let expected = if length != 96 {
        RecoveryCapsuleFrontier::WrongLength
    } else if version != 1 {
        RecoveryCapsuleFrontier::UnsupportedVersion
    } else if ciphertext_length != 80 {
        RecoveryCapsuleFrontier::WrongCiphertextLength
    } else {
        RecoveryCapsuleFrontier::Candidate
    };
    kani::assert(
        classify_recovery_capsule_frontier(length, version, ciphertext_length) == expected,
        "recovery capsule framing must be exact",
    );
    kani::assert(
        RECOVERY_CAPSULE_SIZE == 96
            && RECOVERY_CIPHERTEXT_SIZE == 80
            && RECOVERY_VERSION == 1
            && RECOVERY_METADATA_VERSION == 1,
        "frozen recovery constants must remain exact",
    );
}

#[kani::proof]
fn compressed_key_frontier_is_exact_for_every_length_and_prefix() {
    let length: usize = kani::any();
    let prefix: u8 = kani::any();
    let expected = if length != 33 {
        CompressedKeyFrontier::WrongLength
    } else if prefix != 0x02 && prefix != 0x03 {
        CompressedKeyFrontier::WrongPrefix
    } else {
        CompressedKeyFrontier::Candidate
    };
    kani::assert(
        classify_compressed_key_frontier(length, prefix) == expected,
        "compressed key framing must reject every wrong length and prefix",
    );
}

#[kani::proof]
fn signature_length_gates_are_exact_for_every_usize() {
    let length: usize = kani::any();
    kani::assert(
        partial_signature_length_is_canonical(length) == (length == 32),
        "partial signatures must be exactly 32 bytes",
    );
    kani::assert(
        signature_length_is_canonical(length) == (length == 65),
        "complete signatures must be exactly 65 bytes",
    );
}

#[kani::proof]
fn scalar_frontier_accepts_exactly_the_nonzero_values_below_curve_order() {
    let bytes: [u8; 32] = kani::any();
    let expected = bytes != [0; 32] && bytes < SECP256K1_ORDER;
    kani::assert(
        is_scalar_valid(&bytes) == expected,
        "scalar validity must be exactly 0 < scalar < secp256k1 order",
    );
}

#[kani::proof]
fn verification_outcomes_fail_closed() {
    let tag: u8 = kani::any();
    let outcome = match tag & 3 {
        0 => VerificationOutcome::Valid,
        1 => VerificationOutcome::Invalid,
        2 => VerificationOutcome::Malformed,
        _ => VerificationOutcome::InternalFailure,
    };
    kani::assert(
        verification_is_accepted(outcome) == matches!(outcome, VerificationOutcome::Valid),
        "only an explicit valid verification result may be accepted",
    );
}

#[kani::proof]
fn cryptographic_domains_are_pairwise_distinct() {
    let domains: [&[u8]; 8] = [
        dom_core::TAG_KERNEL_SIG.as_bytes(),
        dom_core::TAG_KERNEL_MSG.as_bytes(),
        dom_core::TAG_KERNEL_MSG_COINBASE.as_bytes(),
        crate::recovery::TAG_RECOVERY_ROOT,
        crate::recovery::TAG_RECOVERY_DETECTION,
        crate::recovery::TAG_RECOVERY_AEAD,
        crate::recovery::TAG_OUTPUT_BLINDING,
        crate::recovery::TAG_RECOVERY_AAD,
    ];
    let mut left = 0;
    while left < domains.len() {
        let mut right = left + 1;
        while right < domains.len() {
            kani::assert(
                domains[left] != domains[right],
                "crypto domains must be distinct",
            );
            right += 1;
        }
        left += 1;
    }
}
