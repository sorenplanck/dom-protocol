//! dom-shield XDIFF/KAV checks for the Slate `version` field.
//!
//! These are regression tests for the version gate: a receiver must reject
//! unsupported slate versions before parsing the rest of the body with the v1
//! layout.

use dom_serialization::{DomDeserialize, DomSerialize};
use dom_tx::slate::{OutputCommitmentAndProof, Slate, CURRENT_SLATE_VERSION};

use dom_crypto::pedersen::Commitment;
use dom_crypto::{bp2_prove, BlindingFactor, PublicKey, RangeProof, SecretKey};

fn commitment(value: u64, blinding_byte: u8) -> Commitment {
    let blinding = BlindingFactor::from_bytes([blinding_byte; 32]).unwrap();
    Commitment::commit(value, &blinding)
}

fn output(value: u64, blinding_byte: u8) -> OutputCommitmentAndProof {
    let blinding = BlindingFactor::from_bytes([blinding_byte; 32]).unwrap();
    let (proof_bytes, commitment_bytes) = bp2_prove(value, &blinding).unwrap();
    OutputCommitmentAndProof {
        commitment: Commitment::from_compressed_bytes(&commitment_bytes).unwrap(),
        proof: RangeProof::from_bytes(proof_bytes).unwrap(),
    }
}

fn public_key(secret_byte: u8) -> PublicKey {
    SecretKey::from_bytes(&[secret_byte; 32])
        .unwrap()
        .public_key()
}

fn base_slate(version: u16) -> Slate {
    Slate {
        version,
        chain_id: [2u8; 32],
        amount: 1_000,
        fee: 10,
        lock_height: 0,
        sender_inputs: vec![commitment(1_500, 3)],
        sender_change_output: Some(output(1_290, 5)),
        sender_public_excess: public_key(6),
        sender_public_nonce: public_key(7),
        sender_offset_contribution: [8u8; 32],
        recipient_output: None,
        recipient_public_excess: None,
        recipient_public_nonce: None,
        sender_partial_sig: None,
        recipient_partial_sig: None,
    }
}

/// XDIFF core: changing only the version prefix must make the slate invalid.
#[test]
fn xdiff_version_field_is_validated_before_body_parse() {
    let b1 = base_slate(CURRENT_SLATE_VERSION).to_bytes().unwrap();

    // v2 buffer = identical body, version prefix overwritten to 2 (LE u16).
    let mut b2 = b1.clone();
    let unsupported = CURRENT_SLATE_VERSION + 1;
    b2[0..2].copy_from_slice(&unsupported.to_le_bytes());

    // The encodings differ ONLY in the first two (version) bytes.
    assert_eq!(b1.len(), b2.len(), "version must not change body length");
    assert_ne!(&b1[0..2], &b2[0..2], "version bytes should differ");
    assert_eq!(
        &b1[2..],
        &b2[2..],
        "body after the version prefix is identical by construction"
    );

    let d1 = Slate::from_bytes(&b1).unwrap();
    let err = Slate::from_bytes(&b2).unwrap_err();

    assert_eq!(d1.version, CURRENT_SLATE_VERSION);
    assert!(
        err.to_string().contains(&format!(
            "unsupported slate version {unsupported} (expected {CURRENT_SLATE_VERSION})"
        )),
        "unsupported version should be rejected: {err:?}"
    );
}

/// Unsupported u16 versions are rejected by the allow-list.
#[test]
fn xdiff_arbitrary_version_rejected() {
    for v in [0u16, 2, 7, 255, 256, 0x7FFF, 0xFFFF] {
        let s = base_slate(v);
        let bytes = s.to_bytes().unwrap();
        let err = Slate::from_bytes(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("unsupported slate version"),
            "version {v} should be rejected by version gate: {err:?}"
        );
    }

    let current = base_slate(CURRENT_SLATE_VERSION).to_bytes().unwrap();
    let decoded = Slate::from_bytes(&current).unwrap();
    assert_eq!(decoded.version, CURRENT_SLATE_VERSION);
}

/// Cross-version "mis-parse" guard: a body that is otherwise valid v1 must
/// still be rejected when its declared version is unsupported.
#[test]
fn xdiff_forged_version_prefix_is_rejected_before_body_parse() {
    let v1 = base_slate(CURRENT_SLATE_VERSION);
    let mut bytes = v1.to_bytes().unwrap();
    // Overwrite the leading u16 LE version with 0xFFFF.
    bytes[0] = 0xFF;
    bytes[1] = 0xFF;

    let err = Slate::from_bytes(&bytes).unwrap_err();
    assert!(
        err.to_string().contains("unsupported slate version"),
        "forged-version body should be rejected: {err:?}"
    );
}
