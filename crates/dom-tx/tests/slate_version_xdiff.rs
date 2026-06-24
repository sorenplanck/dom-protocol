//! dom-shield — XDIFF / KAV on the Slate `version` field.
//!
//! FINDING UNDER TEST (likely RED-as-design): `Slate::deserialize` reads
//! `version: r.read_u16()?` (slate.rs) but NEVER validates or branches on it.
//! There is no `if version != EXPECTED { return Err(...) }` and no
//! version-conditional parsing. Consequences:
//!
//!   * A v2 sender and a v1 receiver do NOT detect the mismatch at the framing
//!     layer — the receiver happily decodes whatever follows using the single
//!     hardcoded layout, regardless of the declared version.
//!   * Any u16 (0, 1, 2, 0xFFFF, ...) is accepted as long as the remaining
//!     bytes match the one supported layout.
//!
//! These tests DOCUMENT that behavior. They are written to PASS against the
//! current (version-ignoring) implementation; the comments record that this is
//! a finding (missing version gate), not a fix. If a version gate is later
//! added, these tests turn RED and must be revisited — that is the intended
//! tripwire.

use dom_serialization::{DomDeserialize, DomSerialize};
use dom_tx::slate::{OutputCommitmentAndProof, Slate};

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

/// XDIFF core: the SAME byte body decodes identically regardless of the
/// declared version. We take ONE encoded v1 slate, then produce a v2 buffer by
/// flipping ONLY the 2-byte version prefix in place (the body — including the
/// randomized range proof — is byte-for-byte identical). Both decode
/// successfully and agree on every field except `version`. This proves the
/// version field is inert (no version-conditional parsing exists).
///
/// (Note: encoding two slates independently would differ in the range-proof
/// region because bp2_prove is randomized; we deliberately reuse one body so
/// the only varying bytes are the version prefix.)
#[test]
fn xdiff_version_field_is_ignored_during_parse() {
    let b1 = base_slate(1).to_bytes().unwrap();

    // v2 buffer = identical body, version prefix overwritten to 2 (LE u16).
    let mut b2 = b1.clone();
    b2[0] = 2;
    b2[1] = 0;

    // The encodings differ ONLY in the first two (version) bytes.
    assert_eq!(b1.len(), b2.len(), "version must not change body length");
    assert_ne!(&b1[0..2], &b2[0..2], "version bytes should differ");
    assert_eq!(
        &b1[2..],
        &b2[2..],
        "body after the version prefix is identical by construction"
    );

    let d1 = Slate::from_bytes(&b1).unwrap();
    let d2 = Slate::from_bytes(&b2).unwrap();

    // Both decode; they differ only in version. NO version validation occurs.
    assert_eq!(d1.version, 1);
    assert_eq!(d2.version, 2);
    let mut d2_as_v1 = d2.clone();
    d2_as_v1.version = 1;
    assert_eq!(
        d1, d2_as_v1,
        "FINDING: parser does not branch on version; bodies decode identically"
    );
}

/// Any arbitrary u16 version is accepted (no allow-list, no reject path).
/// Documents the absence of a version gate at the extreme values.
#[test]
fn xdiff_arbitrary_version_accepted() {
    for v in [0u16, 1, 2, 7, 255, 256, 0x7FFF, 0xFFFF] {
        let s = base_slate(v);
        let bytes = s.to_bytes().unwrap();
        let decoded = Slate::from_bytes(&bytes)
            .unwrap_or_else(|e| panic!("version {v} should decode: {e:?}"));
        assert_eq!(
            decoded.version, v,
            "FINDING: version {v} accepted verbatim, never validated"
        );
    }
}

/// Cross-version "mis-parse" demonstration: hand-craft bytes whose version
/// prefix says 0xFFFF but whose body is a valid v1 slate. The receiver decodes
/// it as if version were irrelevant — confirming a v2 sender / v1 receiver
/// scenario silently round-trips instead of being rejected at the version gate.
#[test]
fn xdiff_forged_version_prefix_still_parses_v1_body() {
    let v1 = base_slate(1);
    let mut bytes = v1.to_bytes().unwrap();
    // Overwrite the leading u16 LE version with 0xFFFF.
    bytes[0] = 0xFF;
    bytes[1] = 0xFF;

    let decoded = Slate::from_bytes(&bytes).expect("forged-version body still decodes");
    assert_eq!(decoded.version, 0xFFFF);
    assert_eq!(decoded.amount, v1.amount);
    assert_eq!(decoded.fee, v1.fee);
    assert_eq!(decoded.sender_inputs, v1.sender_inputs);
    // The body was interpreted with the single hardcoded layout; the declared
    // version (0xFFFF) had no effect on parsing. FINDING: missing version gate.
}
