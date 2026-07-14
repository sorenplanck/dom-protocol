//! dom-shield — directed-corruption + roundtrip-canonicality for `Slate`.
//!
//! The Slate is the counterparty-controlled Slatepack payload. The fuzz
//! targets (fuzz_slate_deserialize / fuzz_slate_roundtrip) already assert
//! "arbitrary bytes never panic" and "valid slate round-trips". These tests
//! cover the COMPLEMENTARY directed properties that fuzzing does not assert:
//!
//!   * truncation at every byte offset is a clean Err, never a panic;
//!   * trailing garbage after a valid slate is rejected (canonical length);
//!   * invalid Option presence flags (>1) are rejected;
//!   * encode(decode(x)) == x for a valid slate AND decode is canonical
//!     (re-encoding the decoded slate reproduces the exact bytes — no
//!     two-encodings-one-slate ambiguity).

use dom_serialization::{DomDeserialize, DomSerialize};
use dom_tx::slate::{OutputCommitmentAndProof, Slate, CURRENT_SLATE_VERSION};

use dom_crypto::pedersen::Commitment;
use dom_crypto::{bp2_prove, BlindingFactor, PartialSig, PublicKey, RangeProof, SecretKey};

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

fn partial_sig(scalar_byte: u8) -> PartialSig {
    PartialSig::from_bytes(&[scalar_byte; 32]).unwrap()
}

/// A maximally-populated slate (every Option = Some) for the widest layout.
fn full_slate() -> Slate {
    Slate {
        version: CURRENT_SLATE_VERSION,
        chain_id: [9u8; 32],
        amount: 2_000,
        fee: 20,
        lock_height: 144,
        sender_inputs: vec![commitment(3_000, 10), commitment(1_000, 11)],
        sender_change_output: Some(output(1_980, 12)),
        sender_public_excess: public_key(13),
        sender_public_nonce: public_key(14),
        sender_offset_contribution: [15u8; 32],
        recipient_output: Some(output(2_000, 16)),
        recipient_public_excess: Some(public_key(17)),
        recipient_public_nonce: Some(public_key(18)),
        sender_partial_sig: Some(partial_sig(19)),
        recipient_partial_sig: Some(partial_sig(20)),
        sender_change_recovery_capsule: Vec::new(),
        recipient_recovery_capsule: Vec::new(),
    }
}

/// Truncation at EVERY prefix length must yield Err, never a panic. (libfuzzer
/// explores this stochastically; here it is deterministic and exhaustive over
/// the canonical encoding length.)
#[test]
fn corruption_truncation_at_every_offset_is_clean_err() {
    let bytes = full_slate().to_bytes().unwrap();
    for n in 0..bytes.len() {
        let truncated = &bytes[..n];
        // Must not panic; a prefix of a valid slate is always incomplete.
        assert!(
            Slate::from_bytes(truncated).is_err(),
            "truncation to {n} of {} bytes should be rejected",
            bytes.len()
        );
    }
    // The full length decodes successfully (control).
    assert!(Slate::from_bytes(&bytes).is_ok());
}

/// Trailing garbage after a valid slate is rejected: the decode is
/// length-canonical (no silent acceptance of extra bytes).
#[test]
fn corruption_trailing_bytes_rejected() {
    let mut bytes = full_slate().to_bytes().unwrap();
    bytes.push(0x00);
    assert!(
        Slate::from_bytes(&bytes).is_err(),
        "trailing byte after canonical slate must be rejected"
    );
}

/// Single-bit/byte flips across the whole buffer never panic (only Ok/Err).
#[test]
fn corruption_byte_flips_never_panic() {
    let bytes = full_slate().to_bytes().unwrap();
    for i in 0..bytes.len() {
        let mut m = bytes.clone();
        m[i] ^= 0xFF;
        // Outcome is irrelevant; the contract is "no panic".
        let _ = Slate::from_bytes(&m);
    }
}

/// An invalid Option presence flag (anything other than 0/1) is rejected.
/// The first Option in the layout is `sender_change_output`, located right
/// after version(2)+chain_id(32)+amount(8)+fee(8)+lock_height(8)+
/// sender_inputs(u32 count + entries). We locate it by re-encoding a slate
/// whose sender_change_output = None, then corrupting that flag byte.
#[test]
fn corruption_invalid_option_flag_rejected() {
    let mut slate = full_slate();
    slate.sender_change_output = None; // make the flag byte a known 0
    let bytes = slate.to_bytes().unwrap();

    // offset of the sender_change_output presence flag:
    // 2 (version) + 32 (chain_id) + 8 (amount) + 8 (fee) + 8 (lock_height)
    // + 4 (sender_inputs u32 count) + 2*33 (two commitments).
    let flag_off = 2 + 32 + 8 + 8 + 8 + 4 + slate.sender_inputs.len() * 33;
    assert_eq!(
        bytes[flag_off], 0,
        "sanity: sender_change_output flag should be 0 (None)"
    );

    let mut m = bytes.clone();
    m[flag_off] = 2; // invalid presence flag
    let err = Slate::from_bytes(&m)
        .expect_err("invalid option flag must be rejected")
        .to_string();
    assert!(
        err.contains("option presence flag") || err.to_lowercase().contains("flag"),
        "expected option-flag rejection, got: {err}"
    );
}

/// Roundtrip canonicality: decode(encode(x)) == x AND encode(decode(bytes))
/// reproduces the exact bytes. No two distinct encodings map to one slate.
#[test]
fn canonicality_encode_decode_is_bijective() {
    for slate in [full_slate(), {
        // sender-only variant (all recipient Options = None)
        let mut s = full_slate();
        s.recipient_output = None;
        s.recipient_public_excess = None;
        s.recipient_public_nonce = None;
        s.sender_partial_sig = None;
        s.recipient_partial_sig = None;
        s
    }] {
        let bytes = slate.to_bytes().unwrap();
        let decoded = Slate::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, slate, "decode(encode(x)) must equal x");
        let reencoded = decoded.to_bytes().unwrap();
        assert_eq!(
            reencoded, bytes,
            "encode(decode(bytes)) must reproduce the exact bytes (canonical)"
        );
    }
}
