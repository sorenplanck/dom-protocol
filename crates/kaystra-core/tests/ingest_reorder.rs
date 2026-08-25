//! Ingest algorithm + deterministic reorder (F2 spec §10, step 8).
//!
//! Shapes proven here against the REAL machine and the REAL SQLite store:
//! claim evidence arriving before the funding is confirmed parks and is
//! applied later (E2E-007); permutations of the same event set converge
//! to the same economic projection (E2E-008 in miniature); evidence after
//! terminal is `LateNoEconomicEffect` (E2E-012); a diverging binding
//! fails before the machine runs (E2E-017); a gap is never filled by
//! assumption.

use std::path::PathBuf;

use kaystra_core::ingest::{ingest_event, EngineError, IngestResult, ReorderBuffer};
use kaystra_core::state::{EvidenceRefV1, SettlementEvent, SettlementState, TransitionError};
use kaystra_core::store_port::{
    EventEnvelopeV1, EvidenceStatus, SettlementStore, SqliteSettlementStore, PROTOCOL_VERSION,
};
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::*;

fn b32(x: u8) -> [u8; 32] {
    [x; 32]
}

fn db_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kaystra-f2-ingest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.sqlite"));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(dir.join(format!("{name}.sqlite{suffix}")));
    }
    path
}

fn terms() -> SettlementTermsV1 {
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
                min_confirmations: 1,
                max_reorg_depth: 2,
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
                max_reorg_depth: 1,
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
            evidence_retention_blocks: 10,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata: Vec::new(),
    }
}

fn evidence(height: u64, tx: u8) -> EvidenceRefV1 {
    EvidenceRefV1 {
        chain_id: ChainId(b32(0xc1)),
        tx_id: b32(tx),
        event_index: 0,
        block_height: height,
        block_anchor: b32(0xa0),
    }
}

fn env(t: &SettlementTermsV1, event_id: u8, seq: u64, event: SettlementEvent) -> EventEnvelopeV1 {
    EventEnvelopeV1 {
        protocol_version: PROTOCOL_VERSION,
        settlement_id: t.settlement_id,
        session_id: t.session_id,
        terms_hash: t.terms_hash().unwrap(),
        source_chain: t.dom_leg.chain_id,
        event_id: EvidenceId(b32(event_id)),
        source_sequence: seq,
        event,
    }
}

/// The four post-arm events of the claim path, in protocol order.
fn claim_script(t: &SettlementTermsV1) -> Vec<EventEnvelopeV1> {
    vec![
        env(
            t,
            0xe2,
            2,
            SettlementEvent::FundingObserved {
                evidence: evidence(10, 0x71),
            },
        ),
        env(
            t,
            0xe3,
            3,
            SettlementEvent::FundingConfirmed {
                evidence: evidence(10, 0x71),
            },
        ),
        env(
            t,
            0xe4,
            4,
            SettlementEvent::ClaimEvidenceVerified {
                evidence: evidence(11, 0x72),
            },
        ),
        env(
            t,
            0xe5,
            5,
            SettlementEvent::ClaimConfirmed {
                evidence: evidence(11, 0x72),
            },
        ),
    ]
}

fn setup(name: &str) -> (SqliteSettlementStore, SettlementTermsV1) {
    let store = SqliteSettlementStore::open(&db_path(name)).unwrap();
    let t = terms();
    store.create(&t, 1).unwrap();
    let armed = env(&t, 0xe1, 1, SettlementEvent::RefundArmed);
    assert!(matches!(
        ingest_event(&store, &armed, None, 5).unwrap(),
        IngestResult::Committed { .. }
    ));
    (store, t)
}

fn final_state(store: &SqliteSettlementStore, t: &SettlementTermsV1) -> SettlementState {
    store.load(t.settlement_id).unwrap().unwrap().context.state
}

#[test]
fn claim_before_funding_confirmation_parks_then_applies() {
    // E2E-007: the claim evidence arrives while the machine is still in
    // Confirming — parked, never guessed — and applies after the funding
    // confirmation commits.
    let (store, t) = setup("park-claim");
    let script = claim_script(&t);
    let mut buffer = ReorderBuffer::new();

    // FundingObserved accepted.
    assert!(matches!(
        buffer.ingest(&store, script[0].clone(), None, 10).unwrap(),
        IngestResult::Committed { .. }
    ));
    // ClaimEvidenceVerified while Confirming: illegal now => parked.
    assert_eq!(
        buffer.ingest(&store, script[2].clone(), None, 11).unwrap(),
        IngestResult::ParkedForReorder
    );
    assert_eq!(buffer.parked_len(), 1);
    assert_eq!(final_state(&store, &t), SettlementState::Confirming);

    // FundingConfirmed commits; the drain applies the parked claim proof.
    assert!(matches!(
        buffer.ingest(&store, script[1].clone(), None, 12).unwrap(),
        IngestResult::Committed { .. }
    ));
    assert_eq!(buffer.parked_len(), 0);
    let snapshot = store.load(t.settlement_id).unwrap().unwrap();
    assert_eq!(snapshot.context.state, SettlementState::Settling);
    assert!(snapshot.context.claim_evidence_verified);

    // ClaimConfirmed settles.
    assert!(matches!(
        buffer.ingest(&store, script[3].clone(), None, 13).unwrap(),
        IngestResult::Committed { .. }
    ));
    assert_eq!(final_state(&store, &t), SettlementState::Settled);
    assert_eq!(
        store.terminal(t.settlement_id).unwrap().unwrap().0,
        SettlementState::Settled
    );
}

#[test]
fn every_permutation_of_the_claim_script_converges() {
    // E2E-008 in miniature: all 24 permutations of the four post-arm
    // events end Settled with the same terminal, or leave a consistent
    // non-terminal state when order can never recover — here every
    // permutation converges because parking preserves the events.
    fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
        if items.len() <= 1 {
            return vec![items.to_vec()];
        }
        let mut out = Vec::new();
        for (i, head) in items.iter().enumerate() {
            let mut rest = items.to_vec();
            rest.remove(i);
            for mut tail in permutations(&rest) {
                let mut p = vec![head.clone()];
                p.append(&mut tail);
                out.push(p);
            }
        }
        out
    }

    for (n, perm) in permutations(&claim_script(&terms()))
        .into_iter()
        .enumerate()
    {
        let (store, t) = setup(&format!("perm-{n}"));
        let mut buffer = ReorderBuffer::new();
        for e in perm {
            // Every delivery either commits, parks, ACKs or is late —
            // never an error: the set is self-consistent.
            buffer.ingest(&store, e, None, 100 + n as i64).unwrap();
        }
        assert_eq!(
            final_state(&store, &t),
            SettlementState::Settled,
            "permutation {n} did not converge"
        );
        assert_eq!(buffer.parked_len(), 0, "permutation {n} left parked events");
        assert_eq!(
            store.terminal(t.settlement_id).unwrap().unwrap().0,
            SettlementState::Settled
        );
    }
}

#[test]
fn evidence_after_terminal_is_late_no_economic_effect() {
    // E2E-012: after Refunded, any evidence event is classified neutral,
    // recorded by identifier, and the terminal never changes.
    let (store, t) = setup("late");
    for e in [
        env(
            &t,
            0xe2,
            2,
            SettlementEvent::FundingObserved {
                evidence: evidence(10, 0x71),
            },
        ),
        env(
            &t,
            0xe3,
            3,
            SettlementEvent::RefundConfirmed {
                evidence: evidence(12, 0x73),
            },
        ),
    ] {
        assert!(matches!(
            ingest_event(&store, &e, None, 20).unwrap(),
            IngestResult::Committed { .. }
        ));
    }
    assert_eq!(final_state(&store, &t), SettlementState::Refunded);

    let late = env(
        &t,
        0xe9,
        9,
        SettlementEvent::ClaimConfirmed {
            evidence: evidence(13, 0x74),
        },
    );
    assert_eq!(
        ingest_event(&store, &late, None, 30).unwrap(),
        IngestResult::LateNoEconomicEffect
    );
    assert_eq!(
        ingest_event(&store, &late, None, 31).unwrap(),
        IngestResult::LateNoEconomicEffect,
        "late classification is idempotent"
    );
    assert_eq!(final_state(&store, &t), SettlementState::Refunded);
    assert_eq!(
        store.terminal(t.settlement_id).unwrap().unwrap().0,
        SettlementState::Refunded,
        "terminal never flips (claim XOR refund)"
    );
}

#[test]
fn diverging_binding_fails_before_the_machine() {
    // E2E-017: wrong terms_hash or session on the envelope is rejected
    // before transition() runs and nothing is written.
    let (store, t) = setup("binding");
    let mut wrong_terms = env(
        &t,
        0xe2,
        2,
        SettlementEvent::FundingObserved {
            evidence: evidence(10, 0x71),
        },
    );
    wrong_terms.terms_hash = b32(0xff);
    match ingest_event(&store, &wrong_terms, None, 10) {
        Err(EngineError::BindingMismatch) => {}
        other => panic!("expected BindingMismatch, got {other:?}"),
    }
    let mut wrong_session = env(
        &t,
        0xe2,
        2,
        SettlementEvent::FundingObserved {
            evidence: evidence(10, 0x71),
        },
    );
    wrong_session.session_id = SessionId(b32(0xff));
    match ingest_event(&store, &wrong_session, None, 10) {
        Err(EngineError::BindingMismatch) => {}
        other => panic!("expected BindingMismatch, got {other:?}"),
    }
    let snapshot = store.load(t.settlement_id).unwrap().unwrap();
    assert_eq!(snapshot.last_event_seq, 1, "nothing was journaled");
}

#[test]
fn duplicates_ack_and_gaps_are_never_filled_by_assumption() {
    let (store, t) = setup("gaps");
    let observed = env(
        &t,
        0xe2,
        2,
        SettlementEvent::FundingObserved {
            evidence: evidence(10, 0x71),
        },
    );
    assert!(matches!(
        ingest_event(&store, &observed, None, 10).unwrap(),
        IngestResult::Committed { .. }
    ));
    assert_eq!(
        ingest_event(&store, &observed, None, 11).unwrap(),
        IngestResult::Duplicate
    );

    // FundingConfirmed with evidence at a DIFFERENT height than observed:
    // EvidenceMismatch is a hard rejection — the gap is not parked away
    // and is never bridged by assumption.
    let mismatched = env(
        &t,
        0xe3,
        3,
        SettlementEvent::FundingConfirmed {
            evidence: evidence(12, 0x71),
        },
    );
    match ingest_event(&store, &mismatched, None, 12) {
        Err(EngineError::Machine(TransitionError::EvidenceMismatch)) => {}
        other => panic!("expected EvidenceMismatch, got {other:?}"),
    }
    assert_eq!(final_state(&store, &t), SettlementState::Confirming);
}

#[test]
fn non_evidence_events_never_park() {
    // TimelockExpired in Preparing is illegal AND carries no chain
    // position: hard rejection, not a park.
    let store = SqliteSettlementStore::open(&db_path("nonpark")).unwrap();
    let t = terms();
    store.create(&t, 1).unwrap();
    let premature = env(&t, 0xe7, 7, SettlementEvent::TimelockExpired);
    match ingest_event(&store, &premature, None, 10) {
        Err(EngineError::Machine(TransitionError::IllegalEvent)) => {}
        other => panic!("expected IllegalEvent, got {other:?}"),
    }
    assert!(store
        .evidence(t.settlement_id, EvidenceStatus::Parked)
        .unwrap()
        .is_empty());
}

#[test]
fn parked_evidence_is_durable_and_the_cursor_did_not_advance() {
    // The crash-recovery half of parking: the parked row survives in
    // observed_evidence, and no cursor advanced for the parked event, so
    // a restarted scanner redelivers it.
    let (store, t) = setup("durable-park");
    let claim = env(
        &t,
        0xe4,
        4,
        SettlementEvent::ClaimEvidenceVerified {
            evidence: evidence(11, 0x72),
        },
    );
    assert_eq!(
        ingest_event(&store, &claim, None, 10).unwrap(),
        IngestResult::ParkedForReorder
    );
    let parked = store
        .evidence(t.settlement_id, EvidenceStatus::Parked)
        .unwrap();
    assert_eq!(parked.len(), 1);
    assert_eq!(parked[0].evidence_id, EvidenceId(b32(0xe4)));
    assert!(
        store
            .cursor(t.settlement_id, t.dom_leg.chain_id)
            .unwrap()
            .is_none(),
        "cursor must not advance past a parked event"
    );
    // Redelivery after a crash: parks idempotently, no duplicate row.
    assert_eq!(
        ingest_event(&store, &claim, None, 11).unwrap(),
        IngestResult::ParkedForReorder
    );
    assert_eq!(
        store
            .evidence(t.settlement_id, EvidenceStatus::Parked)
            .unwrap()
            .len(),
        1
    );
}
