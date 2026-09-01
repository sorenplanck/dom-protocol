//! SettlementTermsV1 frozen vectors + roundtrip properties (spec §15, §14).
//!
//! The committed fixtures under `fixtures/terms-v1/` are the A3 conformance
//! corpus: two valid vectors (canonical bytes + terms_hash) and eight
//! invalid mutations that MUST fail closed with a specific error. An
//! independent script (`scripts/verify_terms_vectors.py`, no kaystra-core
//! import) recomputes BLAKE2b-256 over `TERMS_DOMAIN || bytes` and compares
//! the hashes — same bytes, same hash, in Rust and outside it.
//!
//! `regenerate_vectors` (ignored) rewrites the corpus from the encoder; it
//! refuses to write any invalid vector whose decode error differs from the
//! frozen expectation, so a drifted offset fails loudly instead of
//! committing a lying fixture.

use std::fs;
use std::path::PathBuf;

use kaystra_core::terms::{SettlementTermsV1, TermsError, MAX_METADATA_BYTES};
use kaystra_core::types::*;
use proptest::prelude::*;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/terms-v1")
}

fn read_hex(name: &str) -> Vec<u8> {
    let path = fixtures_dir().join(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing fixture {}: {e}", path.display()));
    hex::decode(text.trim()).expect("fixture is not valid hex")
}

fn b32(x: u8) -> [u8; 32] {
    [x; 32]
}

/// Deterministic minimal valid terms: empty metadata, no assurance policy.
fn valid_minimal() -> SettlementTermsV1 {
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
            amount: 1,
            beneficiary: ParticipantId(b32(0xb2)),
            refund_to: ParticipantId(b32(0xb1)),
            mechanism: LockMechanism::DomAdaptor2of2,
            deadline: TimelockSpec::BlockHeight { value: 100 },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 1,
            },
            adapter_profile_hash: b32(0xc3),
        },
        counterparty_leg: LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: ChainId(b32(0xd1)),
            asset_id: AssetId(b32(0xd2)),
            amount: 1,
            beneficiary: ParticipantId(b32(0xb1)),
            refund_to: ParticipantId(b32(0xb2)),
            mechanism: LockMechanism::ConditionLock,
            deadline: TimelockSpec::TimestampSeconds {
                value: 1_700_000_000,
            },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 2,
            },
            adapter_profile_hash: b32(0xd3),
        },
        adaptor_point_sec1: {
            let mut p = [0xe1u8; 33];
            p[0] = 0x02;
            p
        },
        fee_limit: FeeLimitV1 {
            dom_max: 0,
            counterparty_max: 0,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 0,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata: Vec::new(),
    }
}

/// Deterministic full valid terms: every optional/extreme field exercised
/// (assurance policy present, non-empty metadata, u128/u64/u32 extremes,
/// odd point prefix, the remaining mechanism and timelock tags).
fn valid_full() -> SettlementTermsV1 {
    let mut t = valid_minimal();
    t.settlement_id = SettlementId(b32(0xa5));
    t.dom_leg.amount = u128::MAX;
    t.dom_leg.mechanism = LockMechanism::SchnorrAdaptor;
    t.dom_leg.deadline = TimelockSpec::BtcTime512s { value: 144 };
    t.dom_leg.finality = FinalityPolicyV1 {
        min_confirmations: 6,
        max_reorg_depth: 100,
    };
    t.counterparty_leg.mechanism = LockMechanism::HashlockFallback;
    t.adaptor_point_sec1[0] = 0x03;
    t.fee_limit = FeeLimitV1 {
        dom_max: u128::MAX,
        counterparty_max: 1,
    };
    t.recovery = RecoveryPolicyV1 {
        refund_before_funding: false,
        evidence_retention_blocks: u64::MAX,
    };
    t.assurance_policy_hash = Some(b32(0xf1));
    t.policy_version = u32::MAX;
    t.metadata = b"DOM-INTEROP F2 terms vector: full profile".to_vec();
    t
}

// Fixed offsets inside the valid-minimal encoding (header 8+2, then six
// 32-byte identifiers, then the two 195-byte legs, point at 592). The
// generator proves each mutation still hits its intended field by checking
// the decode error before writing the fixture.
const OFF_VERSION: usize = 8;
const OFF_ROSTER0: usize = 138;
const OFF_ROSTER1: usize = 170;
const OFF_DOM_ROLE: usize = 202;
const OFF_DOM_AMOUNT: usize = 267;
const OFF_POINT: usize = 592;

/// The eight invalid mutations of spec §15, with their frozen errors.
fn invalid_mutations() -> Vec<(&'static str, Vec<u8>, TermsError)> {
    let base = valid_minimal().canonical_bytes().expect("valid encodes");
    let mut out = Vec::new();

    let mut m = base.clone();
    m.copy_within(OFF_ROSTER0..OFF_ROSTER0 + 32, OFF_ROSTER1);
    out.push(("invalid-roster-equal.hex", m, TermsError::InvalidRoster));

    let mut m = base.clone();
    let r0: Vec<u8> = m[OFF_ROSTER0..OFF_ROSTER0 + 32].to_vec();
    m.copy_within(OFF_ROSTER1..OFF_ROSTER1 + 32, OFF_ROSTER0);
    m[OFF_ROSTER1..OFF_ROSTER1 + 32].copy_from_slice(&r0);
    out.push(("invalid-roster-unsorted.hex", m, TermsError::InvalidRoster));

    let mut m = base.clone();
    m[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&2u16.to_be_bytes());
    out.push(("invalid-version.hex", m, TermsError::InvalidVersion));

    let mut m = base.clone();
    m[OFF_DOM_ROLE] = 0x7f;
    out.push(("invalid-enum-tag.hex", m, TermsError::UnknownTag));

    let mut m = base.clone();
    m.push(0x00);
    out.push(("invalid-trailing-byte.hex", m, TermsError::TrailingBytes));

    let mut m = base.clone();
    m[OFF_DOM_AMOUNT..OFF_DOM_AMOUNT + 16].fill(0);
    out.push(("invalid-zero-amount.hex", m, TermsError::ZeroAmount));

    let mut m = base.clone();
    m[OFF_POINT] = 0x04;
    out.push(("invalid-point-prefix.hex", m, TermsError::NonCanonicalPoint));

    let mut m = base.clone();
    let len = m.len();
    m[len - 4..].copy_from_slice(&4097u32.to_be_bytes());
    m.extend(std::iter::repeat(0u8).take(4097));
    out.push((
        "invalid-oversize-metadata.hex",
        m,
        TermsError::BoundsExceeded,
    ));

    out
}

/// The DOM leg's mechanism byte, derived from the DOM role byte and the fixed
/// field order `role || chain_id(32) || asset_id(32) || amount(16) ||
/// beneficiary(32) || refund_to(32)`.
const OFF_DOM_MECHANISM: usize = OFF_DOM_ROLE + 1 + 32 + 32 + 16 + 32 + 32;

#[test]
fn the_cross_curve_mechanism_round_trips_and_an_unknown_tag_still_fails_closed() {
    let mut terms = valid_minimal();
    terms.counterparty_leg.mechanism = LockMechanism::CrossCurveSharedSpend;
    let bytes = terms.canonical_bytes().expect("valid encodes");
    assert_eq!(
        SettlementTermsV1::decode(&bytes).expect("decodes"),
        terms,
        "0x05 must survive the canonical round trip"
    );

    // The byte after the last ratified tag is still refused. Adding a
    // mechanism widens the frozen set by exactly one value, never opens it.
    let base = valid_minimal().canonical_bytes().expect("valid encodes");
    assert_eq!(base[OFF_DOM_MECHANISM], LockMechanism::DomAdaptor2of2 as u8);
    let mut unknown = base.clone();
    unknown[OFF_DOM_MECHANISM] = 0x07;
    assert_eq!(
        SettlementTermsV1::decode(&unknown).unwrap_err(),
        TermsError::UnknownTag
    );

    // And the new tags decode where the old ones do, at the same offset.
    for mechanism in [
        LockMechanism::CrossCurveSharedSpend,
        LockMechanism::CrossCurveConditionLock,
    ] {
        let mut cross_curve = base.clone();
        cross_curve[OFF_DOM_MECHANISM] = mechanism as u8;
        assert_eq!(
            SettlementTermsV1::decode(&cross_curve)
                .expect("decodes")
                .dom_leg
                .mechanism,
            mechanism
        );
    }
}

#[test]
fn adding_a_mechanism_does_not_move_any_frozen_terms_hash() {
    // The whole argument for leaving TERMS_VERSION at 1 is that terms which do
    // not use the new mechanism encode and hash exactly as before. The frozen
    // vectors are the evidence, so this asserts it directly rather than
    // relying on the vector test noticing.
    for (hex_name, hash_name, terms) in [
        ("valid-minimal.hex", "valid-minimal.hash", valid_minimal()),
        ("valid-full.hex", "valid-full.hash", valid_full()),
    ] {
        assert_eq!(
            terms.canonical_bytes().expect("encodes"),
            read_hex(hex_name)
        );
        assert_eq!(
            terms.terms_hash().expect("hashes").to_vec(),
            read_hex(hash_name)
        );
    }
}

#[test]
fn valid_vectors_are_frozen_and_roundtrip() {
    for (hex_name, hash_name, terms) in [
        ("valid-minimal.hex", "valid-minimal.hash", valid_minimal()),
        ("valid-full.hex", "valid-full.hash", valid_full()),
    ] {
        let bytes = read_hex(hex_name);
        let encoded = terms.canonical_bytes().expect("valid terms encode");
        assert_eq!(encoded, bytes, "{hex_name}: encoder drifted from fixture");

        let decoded = SettlementTermsV1::decode(&bytes).expect("fixture decodes");
        assert_eq!(decoded, terms, "{hex_name}: decode is not the inverse");

        let hash_file = fs::read_to_string(fixtures_dir().join(hash_name)).unwrap();
        let expected: [u8; 32] = hex::decode(hash_file.trim())
            .unwrap()
            .try_into()
            .expect("hash fixture is 32 bytes");
        assert_eq!(
            terms.terms_hash().unwrap(),
            expected,
            "{hash_name}: terms_hash drifted from fixture"
        );
    }
}

#[test]
fn invalid_vectors_fail_closed_with_the_frozen_error() {
    for (name, expected_bytes, expected_err) in invalid_mutations() {
        let bytes = read_hex(name);
        assert_eq!(bytes, expected_bytes, "{name}: fixture bytes drifted");
        match SettlementTermsV1::decode(&bytes) {
            Err(e) => assert_eq!(e, expected_err, "{name}: wrong error"),
            Ok(_) => panic!("{name}: decoded successfully — must fail closed"),
        }
    }
}

#[test]
fn metadata_bound_is_exact() {
    let mut t = valid_minimal();
    t.metadata = vec![0x5a; MAX_METADATA_BYTES];
    let bytes = t.canonical_bytes().expect("exactly at the bound encodes");
    assert_eq!(SettlementTermsV1::decode(&bytes).unwrap(), t);

    t.metadata.push(0x5a);
    assert_eq!(t.canonical_bytes(), Err(TermsError::BoundsExceeded));
}

#[test]
fn distinct_settlements_never_share_a_hash() {
    // Same terms_hash with a different settlement_id is another settlement
    // (spec §6.3): the id is inside the preimage, so the hashes differ.
    let a = valid_minimal();
    let mut b = valid_minimal();
    b.settlement_id = SettlementId(b32(0xee));
    assert_ne!(a.terms_hash().unwrap(), b.terms_hash().unwrap());
}

// ---- proptest roundtrips (spec §17: encode/decode inverse, hash stable) --

fn arb_id() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn arb_timelock() -> impl Strategy<Value = TimelockSpec> {
    prop_oneof![
        any::<u64>().prop_map(|value| TimelockSpec::BlockHeight { value }),
        any::<u64>().prop_map(|value| TimelockSpec::TimestampSeconds { value }),
        any::<u64>().prop_map(|value| TimelockSpec::BtcTime512s { value }),
    ]
}

fn arb_mechanism() -> impl Strategy<Value = LockMechanism> {
    prop_oneof![
        Just(LockMechanism::DomAdaptor2of2),
        Just(LockMechanism::ConditionLock),
        Just(LockMechanism::SchnorrAdaptor),
        Just(LockMechanism::HashlockFallback),
        Just(LockMechanism::CrossCurveSharedSpend),
    ]
}

fn arb_leg(role: LegRole) -> impl Strategy<Value = LegTermsV1> {
    (
        arb_id(),
        arb_id(),
        1u128..,
        arb_id(),
        arb_id(),
        arb_mechanism(),
        arb_timelock(),
        1u32..1000,
        0u32..1000,
        arb_id(),
    )
        .prop_map(
            move |(chain, asset, amount, bene, refund, mech, deadline, min_conf, extra, prof)| {
                LegTermsV1 {
                    role,
                    chain_id: ChainId(chain),
                    asset_id: AssetId(asset),
                    amount,
                    beneficiary: ParticipantId(bene),
                    refund_to: ParticipantId(refund),
                    mechanism: mech,
                    deadline,
                    finality: FinalityPolicyV1 {
                        min_confirmations: min_conf,
                        max_reorg_depth: min_conf + extra,
                    },
                    adapter_profile_hash: prof,
                }
            },
        )
}

fn arb_terms() -> impl Strategy<Value = SettlementTermsV1> {
    (
        (arb_id(), arb_id(), arb_id(), arb_id()),
        (arb_id(), arb_id()).prop_filter_map("roster must be distinct", |(a, b)| {
            if a == b {
                None
            } else if a < b {
                Some([ParticipantId(a), ParticipantId(b)])
            } else {
                Some([ParticipantId(b), ParticipantId(a)])
            }
        }),
        arb_leg(LegRole::Dom),
        arb_leg(LegRole::Counterparty),
        (prop::bool::ANY, prop::array::uniform32(any::<u8>())),
        (any::<u128>(), any::<u128>()),
        (prop::bool::ANY, any::<u64>()),
        prop::option::of(arb_id()),
        any::<u32>(),
        prop::collection::vec(any::<u8>(), 0..=64),
    )
        .prop_map(
            |(
                (settlement, session, intent, solver),
                roster,
                dom_leg,
                counterparty_leg,
                (odd, point_body),
                (dom_max, counterparty_max),
                (refund_first, retention),
                assurance,
                policy_version,
                metadata,
            )| {
                let mut adaptor_point_sec1 = [0u8; 33];
                adaptor_point_sec1[0] = if odd { 0x03 } else { 0x02 };
                adaptor_point_sec1[1..].copy_from_slice(&point_body);
                SettlementTermsV1 {
                    settlement_id: SettlementId(settlement),
                    session_id: SessionId(session),
                    intent_hash: IntentHash(intent),
                    solver_id: SolverId(solver),
                    roster,
                    dom_leg,
                    counterparty_leg,
                    adaptor_point_sec1,
                    fee_limit: FeeLimitV1 {
                        dom_max,
                        counterparty_max,
                    },
                    recovery: RecoveryPolicyV1 {
                        refund_before_funding: refund_first,
                        evidence_retention_blocks: retention,
                    },
                    assurance_policy_hash: assurance,
                    policy_version,
                    metadata,
                }
            },
        )
}

proptest! {
    /// decode(canonical_bytes(t)) == t for every valid t.
    #[test]
    fn roundtrip_is_the_identity(terms in arb_terms()) {
        let bytes = terms.canonical_bytes().unwrap();
        prop_assert_eq!(SettlementTermsV1::decode(&bytes).unwrap(), terms);
    }

    /// terms_hash is a pure function of the terms.
    #[test]
    fn hash_is_deterministic(terms in arb_terms()) {
        prop_assert_eq!(terms.terms_hash().unwrap(), terms.terms_hash().unwrap());
    }

    /// Any strict prefix of an encoding fails closed (never a panic, never
    /// a success), and one extra byte is always TrailingBytes.
    #[test]
    fn truncation_and_extension_fail_closed(terms in arb_terms(), cut in any::<prop::sample::Index>()) {
        let bytes = terms.canonical_bytes().unwrap();
        let cut = cut.index(bytes.len());
        prop_assert!(SettlementTermsV1::decode(&bytes[..cut]).is_err());
        let mut extended = bytes;
        extended.push(0x00);
        prop_assert_eq!(
            SettlementTermsV1::decode(&extended),
            Err(TermsError::TrailingBytes)
        );
    }
}

/// One-shot corpus generator. Run explicitly with
/// `cargo test -p kaystra-core regenerate_vectors -- --ignored` after an
/// INTENTIONAL wire change; the diff of the committed fixtures then shows
/// exactly what the change did to the canonical bytes and hashes.
#[test]
#[ignore = "writes the committed fixture corpus; run only on intentional wire changes"]
fn regenerate_vectors() {
    let dir = fixtures_dir();
    fs::create_dir_all(&dir).unwrap();

    for (hex_name, hash_name, terms) in [
        ("valid-minimal.hex", "valid-minimal.hash", valid_minimal()),
        ("valid-full.hex", "valid-full.hash", valid_full()),
    ] {
        let bytes = terms.canonical_bytes().expect("valid vector encodes");
        assert_eq!(
            SettlementTermsV1::decode(&bytes).expect("valid vector decodes"),
            terms
        );
        fs::write(dir.join(hex_name), hex::encode(&bytes) + "\n").unwrap();
        fs::write(
            dir.join(hash_name),
            hex::encode(terms.terms_hash().unwrap()) + "\n",
        )
        .unwrap();
    }

    for (name, bytes, expected_err) in invalid_mutations() {
        // Refuse to write a fixture that does not fail exactly as frozen.
        match SettlementTermsV1::decode(&bytes) {
            Err(e) if e == expected_err => {}
            other => panic!("{name}: expected {expected_err:?}, got {other:?}"),
        }
        fs::write(dir.join(name), hex::encode(&bytes) + "\n").unwrap();
    }
}
