//! The D-023 mandatory suite: the canonical F6→F2 carry of the
//! `accepted_terms_hash` (operator decision, 2026-08-10).
//!
//! Ratified encoding under test, verbatim:
//!
//! ```text
//! DOM-INTEROP/F6-TERMS-CARRY/V1\0 || accepted_terms_hash
//! ```
//!
//! literal byte-identical domain; exactly 32 hash bytes; no length
//! prefix; no padding; no trailing bytes; exactly one record; for the
//! F6→F2 V1 profile, `metadata` contains exactly this record.
//!
//! The two hashes are named apart throughout (D-023 §2):
//! `accepted_terms_hash` is the F6 negotiation's, and
//! `settlement_terms_hash` is the A3 hash of `SettlementTermsV1`'s
//! canonical bytes.
//!
//! Checks 4, 5 and 9 of the decision's list are already proven in
//! `g_f6_e2e.rs` (`the_settlement_terms_commit_the_negotiated_terms_hash`
//! and `the_assurance_refuses_any_other_terms_hash_by_name`) and are
//! preserved there unchanged. Check 11 — the previously frozen A3
//! vectors stay byte-identical — is adjudicated by the independent
//! verifier `scripts/verify_terms_vectors.py`, which runs in every CI
//! pass and imports nothing from the workspace.

use f6_engine::composition::{
    accepted_negotiation, parse_carry, verify_restored, CompositionRefusal, CARRY_DOMAIN,
    CARRY_RECORD_LEN,
};
use f6_engine::{BindingEventV1, DurableBinding, MemoryLog};
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::{
    AssetId as CoreAssetId, ChainId as CoreChainId, FeeLimitV1 as CoreFeeLimitV1, FinalityPolicyV1,
    IntentHash, LegRole, LegTermsV1, LockMechanism, ParticipantId as CoreParticipantId,
    RecoveryPolicyV1, SessionId, SettlementId, SolverId, TimelockSpec as CoreTimelock,
};
use rfq::ParticipantId;

const RFQ_ID: [u8; 32] = [0x0a; 32];
const QUOTE_ID: [u8; 32] = [0x0b; 32];
const RESERVATION: [u8; 32] = [0x71; 32];
const SOLVER: ParticipantId = ParticipantId([0x61; 32]);
const INITIATOR: ParticipantId = ParticipantId([0x31; 32]);
const ACCEPTED: [u8; 32] = [0x5d; 32];

/// A journal holding one accepted negotiation — the D-023 §3 source.
fn journal_with_binding() -> DurableBinding<MemoryLog> {
    let mut engine = DurableBinding::open(MemoryLog::new()).unwrap();
    engine
        .apply(&BindingEventV1::Reserved {
            reservation_id: RESERVATION,
            rfq_id: RFQ_ID,
            quote_id: QUOTE_ID,
            solver: SOLVER,
        })
        .unwrap();
    engine
        .apply(&BindingEventV1::Selected {
            rfq_id: RFQ_ID,
            winning_quote: QUOTE_ID,
            inputs_digest: [0x88; 32],
        })
        .unwrap();
    engine
        .apply(&BindingEventV1::Bound {
            rfq_id: RFQ_ID,
            quote_id: QUOTE_ID,
            solver: SOLVER,
            accepted_by: INITIATOR,
            reservation_id: RESERVATION,
            terms_hash: ACCEPTED,
        })
        .unwrap();
    engine
}

/// Minimal settlement terms with the given metadata, for the checks
/// that need the A3 hash and the engine-facing structure.
fn terms_with_metadata(metadata: Vec<u8>) -> SettlementTermsV1 {
    let leg = |role: LegRole| LegTermsV1 {
        role,
        chain_id: CoreChainId([0xc1; 32]),
        asset_id: CoreAssetId([0xc2; 32]),
        amount: 5,
        beneficiary: CoreParticipantId([0xb2; 32]),
        refund_to: CoreParticipantId([0xb1; 32]),
        mechanism: match role {
            LegRole::Dom => LockMechanism::DomAdaptor2of2,
            _ => LockMechanism::ConditionLock,
        },
        deadline: CoreTimelock::BlockHeight { value: 1_000 },
        finality: FinalityPolicyV1 {
            min_confirmations: 2,
            max_reorg_depth: 10,
        },
        adapter_profile_hash: [0xc3; 32],
    };
    SettlementTermsV1 {
        settlement_id: SettlementId([0xa1; 32]),
        session_id: SessionId([0x22; 32]),
        intent_hash: IntentHash(RFQ_ID),
        solver_id: SolverId(SOLVER.0),
        roster: [CoreParticipantId([0xb1; 32]), CoreParticipantId([0xb2; 32])],
        dom_leg: leg(LegRole::Dom),
        counterparty_leg: leg(LegRole::Counterparty),
        adaptor_point_sec1: {
            let mut p = [0xe1u8; 33];
            p[0] = 0x02;
            p
        },
        fee_limit: CoreFeeLimitV1 {
            dom_max: 50,
            counterparty_max: 40,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 10,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata,
    }
}

/// **D-023 check 1** — the canonical record is the literal domain
/// followed by exactly 32 bytes, and parses back to the same hash.
#[test]
fn t01_the_canonical_record_is_domain_then_exactly_32_bytes() {
    let engine = journal_with_binding();
    let accepted = accepted_negotiation(&engine, &RFQ_ID).unwrap();
    let record = accepted.carry_metadata();

    assert_eq!(record.len(), CARRY_RECORD_LEN);
    assert_eq!(&record[..CARRY_DOMAIN.len()], CARRY_DOMAIN);
    assert_eq!(&record[CARRY_DOMAIN.len()..], &ACCEPTED);
    assert_eq!(parse_carry(&record).unwrap(), ACCEPTED);

    // The three sinks derive from the ONE journal-sourced value.
    assert_eq!(accepted.accepted_terms_hash(), ACCEPTED);
    assert_eq!(accepted.assurance_terms_hash(), ACCEPTED);
}

/// **D-023 check 2** — an altered domain is refused. Every single-byte
/// corruption of the domain refuses, not just a sample.
#[test]
fn t02_an_altered_domain_is_refused() {
    let engine = journal_with_binding();
    let good = accepted_negotiation(&engine, &RFQ_ID)
        .unwrap()
        .carry_metadata();
    for index in 0..CARRY_DOMAIN.len() {
        let mut bad = good.clone();
        bad[index] ^= 0x01;
        assert_eq!(
            parse_carry(&bad).unwrap_err(),
            CompositionRefusal::TermsCarryMismatch,
            "domain byte {index} altered and still accepted"
        );
    }
}

/// **D-023 check 3** — absent, truncated, duplicated or trailing-byte
/// records are refused in the F6→F2 profile, where metadata is exactly
/// the one record.
#[test]
fn t03_absent_truncated_duplicated_and_trailing_are_refused() {
    let engine = journal_with_binding();
    let good = accepted_negotiation(&engine, &RFQ_ID)
        .unwrap()
        .carry_metadata();

    // Absent.
    assert_eq!(
        parse_carry(&[]).unwrap_err(),
        CompositionRefusal::TermsCarryMismatch
    );
    // Domain alone (hash absent).
    assert_eq!(
        parse_carry(CARRY_DOMAIN).unwrap_err(),
        CompositionRefusal::TermsCarryMismatch
    );
    // Truncated hash — every truncation length.
    for len in 0..good.len() {
        assert_eq!(
            parse_carry(&good[..len]).unwrap_err(),
            CompositionRefusal::TermsCarryMismatch,
            "truncation to {len} bytes accepted"
        );
    }
    // Duplicated record.
    let mut doubled = good.clone();
    doubled.extend_from_slice(&good);
    assert_eq!(
        parse_carry(&doubled).unwrap_err(),
        CompositionRefusal::TermsCarryMismatch
    );
    // One trailing byte; and padding.
    let mut trailing = good.clone();
    trailing.push(0x00);
    assert_eq!(
        parse_carry(&trailing).unwrap_err(),
        CompositionRefusal::TermsCarryMismatch
    );
}

/// **D-023 check 6** — `intent_hash` keeps its ratified meaning: it is
/// the RFQ id (the user intent), it is not the accepted_terms_hash, and
/// the carry never touches it.
#[test]
fn t06_intent_hash_keeps_its_ratified_meaning() {
    let engine = journal_with_binding();
    let accepted = accepted_negotiation(&engine, &RFQ_ID).unwrap();
    let terms = terms_with_metadata(accepted.carry_metadata());

    assert_eq!(terms.intent_hash.0, RFQ_ID, "intent_hash is the RFQ id");
    assert_ne!(
        terms.intent_hash.0,
        accepted.accepted_terms_hash(),
        "intent_hash must not be overwritten by the accepted_terms_hash"
    );

    // Changing the carry changes ONLY metadata; intent_hash is inert.
    let other = terms_with_metadata({
        let mut m = accepted.carry_metadata();
        let at = m.len() - 1;
        m[at] ^= 0x01;
        m
    });
    assert_eq!(other.intent_hash, terms.intent_hash);
}

/// **D-023 check 7** — the composition root does not accept independent
/// carry and F4 binding. The typed result has no public constructor;
/// the only source is the journal, and both sinks come from that one
/// value. What this test can and does show at runtime: values derived
/// through the API agree with the journaled binding, and a
/// caller-fabricated pair that disagrees is refused by the restore
/// check rather than absorbed.
#[test]
fn t07_the_composition_root_admits_no_independent_pair() {
    let engine = journal_with_binding();
    let accepted = accepted_negotiation(&engine, &RFQ_ID).unwrap();

    // The API's two sinks agree with the journal by construction.
    let journaled = engine.ledger().binding(&RFQ_ID).unwrap().terms_hash;
    assert_eq!(accepted.accepted_terms_hash(), journaled);
    assert_eq!(accepted.assurance_terms_hash(), journaled);
    assert_eq!(parse_carry(&accepted.carry_metadata()).unwrap(), journaled);

    // A fabricated independent pair — a carry for one hash next to an
    // F4 binding for another — cannot pass the restore check in either
    // direction.
    let foreign: [u8; 32] = [0xEE; 32];
    let mut fabricated = Vec::from(CARRY_DOMAIN);
    fabricated.extend_from_slice(&foreign);
    assert_eq!(
        verify_restored(&engine, &RFQ_ID, &fabricated, &journaled).unwrap_err(),
        CompositionRefusal::TermsCarryMismatch
    );
    assert_eq!(
        verify_restored(&engine, &RFQ_ID, &accepted.carry_metadata(), &foreign).unwrap_err(),
        CompositionRefusal::AssuranceBindingMismatch
    );
}

/// **D-023 check 8** — restore with divergence between the F6 journal,
/// the persisted carry and the F4 binding fails CLOSED with the named
/// refusal, in the ratified order, and never silently picks one of the
/// divergent values.
#[test]
fn t08_a_divergent_restore_fails_closed_by_name() {
    let engine = journal_with_binding();
    let accepted = accepted_negotiation(&engine, &RFQ_ID).unwrap();
    let good_carry = accepted.carry_metadata();
    let good_f4 = accepted.assurance_terms_hash();

    // The aligned restore succeeds and returns the journal's value.
    let restored = verify_restored(&engine, &RFQ_ID, &good_carry, &good_f4).unwrap();
    assert_eq!(restored.accepted_terms_hash(), ACCEPTED);

    // Carry diverges (any single byte): TermsCarryMismatch.
    for index in 0..good_carry.len() {
        let mut bad = good_carry.clone();
        bad[index] ^= 0x01;
        assert_eq!(
            verify_restored(&engine, &RFQ_ID, &bad, &good_f4).unwrap_err(),
            CompositionRefusal::TermsCarryMismatch,
            "carry byte {index} diverged and the restore did not fail"
        );
    }

    // F4 binding diverges: AssuranceBindingMismatch.
    assert_eq!(
        verify_restored(&engine, &RFQ_ID, &good_carry, &[0xEE; 32]).unwrap_err(),
        CompositionRefusal::AssuranceBindingMismatch
    );

    // No journaled negotiation at all: nothing to restore against.
    let empty = DurableBinding::open(MemoryLog::new()).unwrap();
    assert_eq!(
        verify_restored(&empty, &RFQ_ID, &good_carry, &good_f4).unwrap_err(),
        CompositionRefusal::NegotiationNotBound
    );
}

/// **D-023 check 10** — no economic parameter derives from metadata.
/// Two settlements identical in every economic field but carrying
/// DIFFERENT metadata records have different A3 `settlement_terms_hash`
/// values (the commitment) while every economic field compares equal —
/// and the A3 canonical bytes differ ONLY in the metadata region, so
/// nothing economic was derived from it.
#[test]
fn t10_no_economic_parameter_derives_from_metadata() {
    let engine = journal_with_binding();
    let accepted = accepted_negotiation(&engine, &RFQ_ID).unwrap();
    let a = terms_with_metadata(accepted.carry_metadata());
    let b = terms_with_metadata({
        let mut m = accepted.carry_metadata();
        let at = m.len() - 1;
        m[at] ^= 0x01;
        m
    });

    // The commitment differs (settlement_terms_hash, D-023 §2 naming)…
    assert_ne!(a.terms_hash().unwrap(), b.terms_hash().unwrap());

    // …while every economic field is identical.
    assert_eq!(a.settlement_id, b.settlement_id);
    assert_eq!(a.session_id, b.session_id);
    assert_eq!(a.intent_hash, b.intent_hash);
    assert_eq!(a.solver_id, b.solver_id);
    assert_eq!(a.roster, b.roster);
    assert_eq!(a.dom_leg, b.dom_leg);
    assert_eq!(a.counterparty_leg, b.counterparty_leg);
    assert_eq!(a.adaptor_point_sec1, b.adaptor_point_sec1);
    assert_eq!(a.fee_limit, b.fee_limit);
    assert_eq!(a.recovery, b.recovery);
    assert_eq!(a.assurance_policy_hash, b.assurance_policy_hash);
    assert_eq!(a.policy_version, b.policy_version);

    // And the canonical A3 bytes differ ONLY where the metadata lives:
    // strip the metadata region from both encodings and the remainder
    // is byte-identical.
    let bytes_a = a.canonical_bytes().unwrap();
    let bytes_b = b.canonical_bytes().unwrap();
    let head = bytes_a.len() - a.metadata.len();
    assert_eq!(bytes_a[..head], bytes_b[..head]);
}
