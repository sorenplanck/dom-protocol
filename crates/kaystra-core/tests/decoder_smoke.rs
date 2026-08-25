//! Decoder robustness smoke (F2 spec §17 properties).
//!
//! This is the property-based equivalent of the named fuzz targets, run
//! in every CI job: arbitrary bytes and single-byte mutations of valid
//! encodings are pushed through every strict decoder, and the required
//! properties are asserted:
//!
//! - no panic on arbitrary input (proptest fails the run on any panic);
//! - length validation BEFORE allocation;
//! - no trailing byte is ever ignored;
//! - unknown tag / unknown version fail closed;
//! - `decode(encode(x)) == x` for valid values;
//! - `encode(decode(bytes)) == bytes` for canonical bytes — a decoder
//!   that silently normalizes would make two different encodings share a
//!   hash, which is exactly the ambiguity A3 exists to forbid.
//!
//! SCOPE (declared, not implied): these are deterministic property runs,
//! not coverage-guided fuzzing. The `cargo-fuzz` targets named in §17
//! require a nightly toolchain with libFuzzer and are tracked as residual
//! hardening in the F2 closure report — they are NOT claimed here.

use kaystra_core::state::{EvidenceRefV1, SettlementEvent};
use kaystra_core::store_port::{
    decode_context, derive_event_id, encode_context, EventEnvelopeV1, PROTOCOL_VERSION,
};
use kaystra_core::terms::{SettlementTermsV1, TermsError, MAX_METADATA_BYTES};
use kaystra_core::types::*;
use proptest::prelude::*;

fn b32(x: u8) -> [u8; 32] {
    [x; 32]
}

fn valid_terms() -> SettlementTermsV1 {
    SettlementTermsV1 {
        settlement_id: SettlementId(b32(0xa1)),
        session_id: SessionId(b32(0xa2)),
        intent_hash: IntentHash(b32(0xa3)),
        solver_id: SolverId(b32(0xa4)),
        roster: [ParticipantId(b32(0xb1)), ParticipantId(b32(0xb2))],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: ChainId(b32(0xc1)),
            asset_id: AssetId(b32(0xc2)),
            amount: 5,
            beneficiary: ParticipantId(b32(0xb2)),
            refund_to: ParticipantId(b32(0xb1)),
            mechanism: LockMechanism::DomAdaptor2of2,
            deadline: TimelockSpec::BlockHeight { value: 100 },
            finality: FinalityPolicyV1 {
                min_confirmations: 2,
                max_reorg_depth: 6,
            },
            adapter_profile_hash: b32(0xc3),
        },
        counterparty_leg: LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: ChainId(b32(0xd1)),
            asset_id: AssetId(b32(0xd2)),
            amount: 7,
            beneficiary: ParticipantId(b32(0xb1)),
            refund_to: ParticipantId(b32(0xb2)),
            mechanism: LockMechanism::ConditionLock,
            deadline: TimelockSpec::TimestampSeconds { value: 1_700_000 },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 3,
            },
            adapter_profile_hash: b32(0xd3),
        },
        adaptor_point_sec1: {
            let mut p = [0xe1u8; 33];
            p[0] = 0x03;
            p
        },
        fee_limit: FeeLimitV1 {
            dom_max: 1,
            counterparty_max: 2,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 9,
        },
        assurance_policy_hash: Some(b32(0xf1)),
        policy_version: 3,
        metadata: b"smoke".to_vec(),
    }
}

fn valid_envelope() -> EventEnvelopeV1 {
    let event = SettlementEvent::ClaimEvidenceVerified {
        evidence: EvidenceRefV1 {
            chain_id: ChainId(b32(0xc1)),
            tx_id: b32(0x71),
            event_index: 3,
            block_height: 42,
            block_anchor: b32(0xa0),
        },
    };
    EventEnvelopeV1 {
        protocol_version: PROTOCOL_VERSION,
        settlement_id: SettlementId(b32(0xa1)),
        session_id: SessionId(b32(0xa2)),
        terms_hash: b32(0x33),
        source_chain: ChainId(b32(0xc1)),
        event_id: derive_event_id(SettlementId(b32(0xa1)), &event),
        source_sequence: 42,
        event,
    }
}

proptest! {
    /// Arbitrary bytes into the terms decoder: never a panic, and every
    /// accepted value re-encodes to exactly the input bytes.
    #[test]
    fn terms_decoder_survives_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..900)) {
        if let Ok(terms) = SettlementTermsV1::decode(&bytes) {
            prop_assert_eq!(terms.canonical_bytes().unwrap(), bytes);
        }
    }

    /// Arbitrary bytes into the envelope decoder, same contract.
    #[test]
    fn envelope_decoder_survives_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..400)
    ) {
        if let Ok(envelope) = EventEnvelopeV1::decode(&bytes) {
            prop_assert_eq!(envelope.canonical_bytes(), bytes);
        }
    }

    /// Arbitrary bytes into the context decoder, same contract.
    #[test]
    fn context_decoder_survives_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..64)
    ) {
        if let Ok(context) = decode_context(&bytes) {
            prop_assert_eq!(encode_context(&context), bytes);
        }
    }

    /// Single-byte mutations of a valid terms encoding either fail closed
    /// or describe exactly the mutated bytes. A mutation that decodes to
    /// something re-encoding differently would mean two byte strings map
    /// to one value — and therefore to one terms_hash.
    #[test]
    fn mutating_one_byte_of_valid_terms_never_normalizes(
        position in any::<prop::sample::Index>(),
        value in any::<u8>(),
    ) {
        let mut bytes = valid_terms().canonical_bytes().unwrap();
        let index = position.index(bytes.len());
        bytes[index] = value;
        if let Ok(terms) = SettlementTermsV1::decode(&bytes) {
            prop_assert_eq!(terms.canonical_bytes().unwrap(), bytes);
        }
    }

    /// Same, for the envelope.
    #[test]
    fn mutating_one_byte_of_a_valid_envelope_never_normalizes(
        position in any::<prop::sample::Index>(),
        value in any::<u8>(),
    ) {
        let mut bytes = valid_envelope().canonical_bytes();
        let index = position.index(bytes.len());
        bytes[index] = value;
        if let Ok(envelope) = EventEnvelopeV1::decode(&bytes) {
            prop_assert_eq!(envelope.canonical_bytes(), bytes);
        }
    }

    /// Truncating a valid encoding at any point always fails closed.
    #[test]
    fn any_truncation_fails_closed(position in any::<prop::sample::Index>()) {
        let terms_bytes = valid_terms().canonical_bytes().unwrap();
        let cut = position.index(terms_bytes.len());
        prop_assert!(SettlementTermsV1::decode(&terms_bytes[..cut]).is_err());

        let envelope_bytes = valid_envelope().canonical_bytes();
        let cut = position.index(envelope_bytes.len());
        prop_assert!(EventEnvelopeV1::decode(&envelope_bytes[..cut]).is_err());
    }

    /// Appending anything is always rejected: no trailing byte is ignored.
    #[test]
    fn trailing_bytes_are_never_ignored(tail in prop::collection::vec(any::<u8>(), 1..8)) {
        let mut terms_bytes = valid_terms().canonical_bytes().unwrap();
        terms_bytes.extend_from_slice(&tail);
        prop_assert_eq!(
            SettlementTermsV1::decode(&terms_bytes),
            Err(TermsError::TrailingBytes)
        );

        let mut envelope_bytes = valid_envelope().canonical_bytes();
        envelope_bytes.extend_from_slice(&tail);
        prop_assert!(EventEnvelopeV1::decode(&envelope_bytes).is_err());
    }
}

/// A declared metadata length beyond the bound is rejected BEFORE any
/// allocation: the input stays a few hundred bytes while claiming
/// gigabytes, and the decoder must refuse without reserving anything.
#[test]
fn oversized_length_is_rejected_before_allocating() {
    let mut bytes = valid_terms().canonical_bytes().unwrap();
    let len = bytes.len();
    let metadata_len = valid_terms().metadata.len();
    // Overwrite the metadata length field (the 4 bytes before the body).
    let field = len - metadata_len - 4;
    bytes[field..field + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    bytes.truncate(field + 4);
    assert_eq!(
        SettlementTermsV1::decode(&bytes),
        Err(TermsError::BoundsExceeded),
        "a huge declared length must be refused by the bound, not by allocation"
    );

    // Exactly at the bound with a truncated body is a truncation error,
    // never a silent short read.
    bytes[field..field + 4].copy_from_slice(&(MAX_METADATA_BYTES as u32).to_be_bytes());
    assert_eq!(
        SettlementTermsV1::decode(&bytes),
        Err(TermsError::TruncatedEncoding)
    );
}

/// Every unknown enum tag in the terms wire fails closed.
#[test]
fn unknown_tags_fail_closed() {
    let base = valid_terms().canonical_bytes().unwrap();
    // The DOM leg starts at 202 and is 195 bytes: role(1) chain(32)
    // asset(32) amount(16) beneficiary(32) refund_to(32) mechanism(1)
    // timelock tag(1)+value(8) min_conf(4) max_reorg(4) profile(32).
    // So the three tag bytes are role=202, mechanism=347, timelock=348.
    for offset in [202usize, 347, 348] {
        let mut bytes = base.clone();
        bytes[offset] = 0x7f;
        assert!(
            SettlementTermsV1::decode(&bytes).is_err(),
            "tag at offset {offset} was accepted"
        );
    }
    // Unknown version.
    let mut bytes = base.clone();
    bytes[8..10].copy_from_slice(&0xffffu16.to_be_bytes());
    assert_eq!(
        SettlementTermsV1::decode(&bytes),
        Err(TermsError::InvalidVersion)
    );
    // Unknown envelope event tag.
    let mut envelope = valid_envelope().canonical_bytes();
    let tag_at = 2 + 32 * 5 + 8;
    envelope[tag_at..tag_at + 2].copy_from_slice(&0x7fffu16.to_be_bytes());
    assert!(EventEnvelopeV1::decode(&envelope).is_err());
}
