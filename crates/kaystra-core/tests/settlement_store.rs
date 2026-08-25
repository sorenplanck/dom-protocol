//! Durable SettlementStore contract (F2 spec §8.2, §9) driven end to end:
//! the REAL machine (`state::transition`) committed through the REAL
//! SQLite/WAL store, including idempotent ACK, equivocation, CAS, atomic
//! cursor advancement, deterministic outbox and the unique terminal row.

use std::path::PathBuf;

use kaystra_core::ingest::{ingest_event, IngestResult};
use kaystra_core::state::{transition, EvidenceRefV1, SettlementEvent, SettlementState};
use kaystra_core::store_port::{
    context_hash, decode_context, effects_to_outbox, encode_context, CommitResult, CursorUpdateV1,
    EventEnvelopeV1, EvidenceStatus, ParkResult, SettlementStore, SqliteSettlementStore,
    StorePortError, PROTOCOL_VERSION,
};
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::*;

fn b32(x: u8) -> [u8; 32] {
    [x; 32]
}

/// Fresh database path per test, isolated and cleaned up on entry.
fn db_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kaystra-f2-store-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.sqlite"));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(dir.join(format!("{name}.sqlite-wal")));
    let _ = std::fs::remove_file(dir.join(format!("{name}.sqlite-shm")));
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

fn evidence(height: u64) -> EvidenceRefV1 {
    EvidenceRefV1 {
        chain_id: ChainId(b32(0xc1)),
        tx_id: b32(0x71),
        event_index: 0,
        block_height: height,
        block_anchor: b32(0xa0),
    }
}

fn envelope(
    t: &SettlementTermsV1,
    event_id: u8,
    seq: u64,
    event: SettlementEvent,
) -> EventEnvelopeV1 {
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

/// Applies one envelope through the real machine and commits it.
fn drive(
    store: &SqliteSettlementStore,
    t: &SettlementTermsV1,
    env: &EventEnvelopeV1,
    cursor: Option<&CursorUpdateV1>,
    now: i64,
) -> CommitResult {
    let snapshot = store.load(t.settlement_id).unwrap().unwrap();
    let tr = transition(snapshot.context, &env.event).expect("machine accepts");
    let outbox = effects_to_outbox(env, &tr.effects);
    store
        .commit_transition(snapshot.context.revision, env, &tr, &outbox, cursor, now)
        .expect("commit succeeds")
}

#[test]
fn create_is_idempotent_and_diverging_binding_fails_closed() {
    let store = SqliteSettlementStore::open(&db_path("create")).unwrap();
    let t = terms();
    let first = store.create(&t, 1).unwrap();
    assert_eq!(first.context.state, SettlementState::Preparing);
    assert_eq!(first.context.revision, 0);
    let again = store.create(&t, 2).unwrap();
    assert_eq!(again, first, "byte-identical re-creation is an ACK");

    let mut diverging = t.clone();
    diverging.policy_version = 2; // same settlement_id, different terms
    match store.create(&diverging, 3) {
        Err(StorePortError::Equivocation) => {}
        other => panic!("diverging binding must fail closed, got {other:?}"),
    }
}

#[test]
fn commit_persists_context_effects_and_acks_duplicates() {
    let store = SqliteSettlementStore::open(&db_path("commit")).unwrap();
    let t = terms();
    store.create(&t, 1).unwrap();

    let env = envelope(&t, 0xe1, 1, SettlementEvent::RefundArmed);
    let result = drive(&store, &t, &env, None, 10);
    assert_eq!(result, CommitResult::Committed { revision: 1 });

    let snapshot = store.load(t.settlement_id).unwrap().unwrap();
    assert_eq!(snapshot.context.state, SettlementState::ReadyToFund);
    assert!(snapshot.context.refund_path_armed);
    assert_eq!(snapshot.last_event_seq, 1);

    // The AuthorizeFunding effect is in the outbox, exactly once,
    // invisible until commit and byte-stable across claims.
    let claimed = store.ready_outbox(100, 1_000, 10).unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(
        claimed[0].kind,
        kaystra_core::state::Effect::AuthorizeFunding
    );
    assert_eq!(claimed[0].attempts, 1);

    // Redelivery of the same envelope: idempotent ACK, nothing new.
    let snapshot = store.load(t.settlement_id).unwrap().unwrap();
    let tr = transition(snapshot.context, &env.event);
    // The machine would reject (ReadyToFund, RefundArmed) — the dedupe
    // fires FIRST, so the commit path never reaches the machine. Emulate
    // the §10 flow: dedupe wins even with a synthetic transition.
    assert!(
        tr.is_err(),
        "redelivered RefundArmed is illegal for the machine"
    );
    let refund_tr = transition(kaystra_core::state::SettlementContext::new(), &env.event).unwrap();
    let outbox = effects_to_outbox(&env, &refund_tr.effects);
    let dup = store
        .commit_transition(0, &env, &refund_tr, &outbox, None, 11)
        .unwrap();
    assert_eq!(dup, CommitResult::DuplicateSameBytes);
    assert!(
        store.ready_outbox(5_000, 1_000, 10).unwrap().len() <= 1,
        "duplicate commit must not enqueue new effects"
    );
}

#[test]
fn equivocation_same_event_id_different_bytes_fails_closed() {
    let store = SqliteSettlementStore::open(&db_path("equivocation")).unwrap();
    let t = terms();
    store.create(&t, 1).unwrap();
    let env = envelope(&t, 0xe1, 1, SettlementEvent::RefundArmed);
    drive(&store, &t, &env, None, 10);

    // Same event_id, different source_sequence => different bytes.
    let mut forged = envelope(&t, 0xe1, 2, SettlementEvent::RefundArmed);
    forged.source_sequence = 99;
    let snapshot = store.load(t.settlement_id).unwrap().unwrap();
    let tr = transition(kaystra_core::state::SettlementContext::new(), &forged.event).unwrap();
    let outbox = effects_to_outbox(&forged, &tr.effects);
    match store.commit_transition(snapshot.context.revision, &forged, &tr, &outbox, None, 11) {
        Err(StorePortError::Equivocation) => {}
        other => panic!("equivocation must fail closed, got {other:?}"),
    }
}

#[test]
fn stale_revision_loses_the_cas_and_leaves_no_trace() {
    let store = SqliteSettlementStore::open(&db_path("cas")).unwrap();
    let t = terms();
    store.create(&t, 1).unwrap();
    let env = envelope(&t, 0xe1, 1, SettlementEvent::RefundArmed);
    drive(&store, &t, &env, None, 10);

    // A racer that loaded revision 0 tries to commit a different event.
    let racer_env = envelope(
        &t,
        0xe2,
        2,
        SettlementEvent::FundingObserved {
            evidence: evidence(10),
        },
    );
    let stale = kaystra_core::state::SettlementContext::new();
    // Machine-legal from the stale context? (Preparing, FundingObserved)
    // is illegal, so build from the CURRENT context but present a stale
    // expected_revision — exactly the losing-CAS shape of E2E-016.
    let snapshot = store.load(t.settlement_id).unwrap().unwrap();
    let tr = transition(snapshot.context, &racer_env.event).unwrap();
    let outbox = effects_to_outbox(&racer_env, &tr.effects);
    let cursor = CursorUpdateV1 {
        chain_id: t.dom_leg.chain_id,
        cursor_bytes: vec![0x10],
        anchor_height: Some(10),
        anchor_hash: Some(b32(0xa0)),
    };
    match store.commit_transition(stale.revision, &racer_env, &tr, &outbox, Some(&cursor), 11) {
        Err(StorePortError::RevisionConflict) => {}
        other => panic!("stale CAS must fail, got {other:?}"),
    }
    // Nothing leaked: no journal row, no cursor, snapshot unchanged.
    let snapshot = store.load(t.settlement_id).unwrap().unwrap();
    assert_eq!(snapshot.context.revision, 1);
    assert_eq!(snapshot.last_event_seq, 1);
    assert!(store
        .cursor(t.settlement_id, t.dom_leg.chain_id)
        .unwrap()
        .is_none());
}

#[test]
fn cursor_advances_only_with_the_committed_event() {
    let store = SqliteSettlementStore::open(&db_path("cursor")).unwrap();
    let t = terms();
    store.create(&t, 1).unwrap();
    drive(
        &store,
        &t,
        &envelope(&t, 0xe1, 1, SettlementEvent::RefundArmed),
        None,
        10,
    );
    let cursor = CursorUpdateV1 {
        chain_id: t.dom_leg.chain_id,
        cursor_bytes: vec![0x10, 0x11],
        anchor_height: Some(10),
        anchor_hash: Some(b32(0xa0)),
    };
    drive(
        &store,
        &t,
        &envelope(
            &t,
            0xe2,
            2,
            SettlementEvent::FundingObserved {
                evidence: evidence(10),
            },
        ),
        Some(&cursor),
        11,
    );
    let stored = store
        .cursor(t.settlement_id, t.dom_leg.chain_id)
        .unwrap()
        .expect("cursor advanced with the commit");
    assert_eq!(stored.cursor_bytes, vec![0x10, 0x11]);
    assert_eq!(stored.anchor_height, Some(10));
    assert_eq!(stored.revision, 2);
}

#[test]
fn refund_path_reaches_the_unique_terminal_row() {
    let store = SqliteSettlementStore::open(&db_path("terminal")).unwrap();
    let t = terms();
    store.create(&t, 1).unwrap();
    drive(
        &store,
        &t,
        &envelope(&t, 0xe1, 1, SettlementEvent::RefundArmed),
        None,
        10,
    );
    drive(
        &store,
        &t,
        &envelope(
            &t,
            0xe2,
            2,
            SettlementEvent::FundingObserved {
                evidence: evidence(10),
            },
        ),
        None,
        11,
    );
    drive(
        &store,
        &t,
        &envelope(
            &t,
            0xe3,
            3,
            SettlementEvent::FundingConfirmed {
                evidence: evidence(10),
            },
        ),
        None,
        12,
    );
    let result = drive(
        &store,
        &t,
        &envelope(
            &t,
            0xe4,
            4,
            SettlementEvent::RefundConfirmed {
                evidence: evidence(13),
            },
        ),
        None,
        13,
    );
    assert_eq!(result, CommitResult::Committed { revision: 4 });

    let snapshot = store.load(t.settlement_id).unwrap().unwrap();
    assert_eq!(snapshot.context.state, SettlementState::Refunded);
    let (state, source, revision) = store.terminal(t.settlement_id).unwrap().unwrap();
    assert_eq!(state, SettlementState::Refunded);
    assert_eq!(source, EvidenceId(b32(0xe4)));
    assert_eq!(revision, 4);

    // Late evidence: identifier-only record, idempotent, terminal intact.
    store
        .record_late_evidence(t.settlement_id, EvidenceId(b32(0xe9)), state, 14)
        .unwrap();
    store
        .record_late_evidence(t.settlement_id, EvidenceId(b32(0xe9)), state, 15)
        .unwrap();
    assert_eq!(
        store.terminal(t.settlement_id).unwrap().unwrap().0,
        SettlementState::Refunded
    );
}

#[test]
fn outbox_lease_completion_and_byte_identical_resend() {
    let store = SqliteSettlementStore::open(&db_path("outbox")).unwrap();
    let t = terms();
    store.create(&t, 1).unwrap();
    drive(
        &store,
        &t,
        &envelope(&t, 0xe1, 1, SettlementEvent::RefundArmed),
        None,
        10,
    );

    let first = store.ready_outbox(1_000, 500, 10).unwrap();
    assert_eq!(first.len(), 1);
    let effect = first[0].clone();

    // Within the lease no one else claims it.
    assert!(store.ready_outbox(1_200, 500, 10).unwrap().is_empty());

    // After the lease expires it is re-claimed with the SAME bytes (C9:
    // crash after external effect, before completion => resend identical).
    let second = store.ready_outbox(1_600, 500, 10).unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].payload, effect.payload);
    assert_eq!(second[0].effect_id, effect.effect_id);
    assert_eq!(second[0].attempts, 2);

    // Completion with the WRONG hash fails closed and marks nothing.
    match store.complete_effect(effect.effect_id, b32(0xff), 1_700) {
        Err(StorePortError::Equivocation) => {}
        other => panic!("wrong payload hash must fail closed, got {other:?}"),
    }
    // Correct completion; idempotent; never dispatched again (C10).
    store
        .complete_effect(effect.effect_id, effect.payload_hash, 1_800)
        .unwrap();
    store
        .complete_effect(effect.effect_id, effect.payload_hash, 1_900)
        .unwrap();
    assert!(store.ready_outbox(10_000, 500, 10).unwrap().is_empty());
}

#[test]
fn unknown_envelope_version_fails_closed() {
    let store = SqliteSettlementStore::open(&db_path("version")).unwrap();
    let t = terms();
    store.create(&t, 1).unwrap();
    let mut env = envelope(&t, 0xe1, 1, SettlementEvent::RefundArmed);
    env.protocol_version = 2;
    let tr = transition(kaystra_core::state::SettlementContext::new(), &env.event).unwrap();
    let outbox = effects_to_outbox(&env, &tr.effects);
    match store.commit_transition(0, &env, &tr, &outbox, None, 10) {
        Err(StorePortError::UnknownVersion) => {}
        other => panic!("unknown version must fail closed, got {other:?}"),
    }
}

#[test]
fn parked_evidence_is_idempotent_ordered_and_conflict_checked() {
    let store = SqliteSettlementStore::open(&db_path("park")).unwrap();
    let t = terms();
    store.create(&t, 1).unwrap();

    let late = evidence(20);
    let early = EvidenceRefV1 {
        tx_id: b32(0x42),
        ..evidence(5)
    };
    assert_eq!(
        store
            .park_evidence(t.settlement_id, EvidenceId(b32(0x91)), &late)
            .unwrap(),
        ParkResult::Parked
    );
    assert_eq!(
        store
            .park_evidence(t.settlement_id, EvidenceId(b32(0x92)), &early)
            .unwrap(),
        ParkResult::Parked
    );
    assert_eq!(
        store
            .park_evidence(t.settlement_id, EvidenceId(b32(0x91)), &late)
            .unwrap(),
        ParkResult::AlreadyParked
    );
    // Same id, different content: equivocation.
    match store.park_evidence(t.settlement_id, EvidenceId(b32(0x91)), &evidence(21)) {
        Err(StorePortError::Equivocation) => {}
        other => panic!("conflicting park must fail closed, got {other:?}"),
    }
    // Canonical order (block_height, event_index, tx_id).
    let parked = store
        .evidence(t.settlement_id, EvidenceStatus::Parked)
        .unwrap();
    assert_eq!(parked.len(), 2);
    assert_eq!(parked[0].reference.block_height, 5);
    assert_eq!(parked[1].reference.block_height, 20);
}

#[test]
fn a_reorged_observation_that_comes_back_identically_is_reaffirmed() {
    // Spec §11: a reorg invalidates evidence at or above its height. If
    // the very same block is re-mined, the redelivery is byte-identical —
    // and the bytes carry the block anchor, so it PROVES the observation
    // is canonical again. The row must return to applied, otherwise its
    // confirmation could never be derived and the settlement would hang.
    let store = SqliteSettlementStore::open(&db_path("reaffirm")).unwrap();
    let t = terms();
    store.create(&t, 1).unwrap();
    let armed = envelope(&t, 0xe1, 1, SettlementEvent::RefundArmed);
    drive(&store, &t, &armed, None, 10);
    let observed = envelope(
        &t,
        0xe2,
        2,
        SettlementEvent::FundingObserved {
            evidence: evidence(10),
        },
    );
    drive(&store, &t, &observed, None, 11);
    assert_eq!(
        store
            .evidence(t.settlement_id, EvidenceStatus::Applied)
            .unwrap()
            .len(),
        1
    );

    // A reorg at that height invalidates it.
    store.invalidate_evidence_from(t.settlement_id, 10).unwrap();
    assert!(store
        .evidence(t.settlement_id, EvidenceStatus::Applied)
        .unwrap()
        .is_empty());

    // The identical observation comes back: re-affirmed AND re-applied.
    // Spec §11 rule 8 — the refresh COMMITS (the machine context
    // recovers what the canonical chain again proves); a redelivery
    // whose evidence was never invalidated still answers Duplicate
    // (proved right below by the second redelivery).
    assert!(matches!(
        ingest_event(&store, &observed, None, 12).unwrap(),
        IngestResult::Committed { .. }
    ));
    assert_eq!(
        ingest_event(&store, &observed, None, 13).unwrap(),
        IngestResult::Duplicate
    );
    let applied = store
        .evidence(t.settlement_id, EvidenceStatus::Applied)
        .unwrap();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].evidence_id, EvidenceId(b32(0xe2)));

    // A PARKED row is never promoted by this path: parking means the
    // event was never committed, so nothing can acknowledge it.
    let unrelated = EvidenceRefV1 {
        tx_id: b32(0x99),
        ..evidence(40)
    };
    store
        .park_evidence(t.settlement_id, EvidenceId(b32(0x93)), &unrelated)
        .unwrap();
    store
        .reaffirm_evidence(t.settlement_id, EvidenceId(b32(0x93)))
        .unwrap();
    assert_eq!(
        store
            .evidence(t.settlement_id, EvidenceStatus::Parked)
            .unwrap()
            .len(),
        1,
        "a parked row must stay parked"
    );
}

#[test]
fn context_encoding_roundtrips_and_rejects_corruption() {
    let store = SqliteSettlementStore::open(&db_path("context")).unwrap();
    let t = terms();
    store.create(&t, 1).unwrap();
    for env in [
        envelope(&t, 0xe1, 1, SettlementEvent::RefundArmed),
        envelope(
            &t,
            0xe2,
            2,
            SettlementEvent::FundingObserved {
                evidence: evidence(10),
            },
        ),
    ] {
        drive(&store, &t, &env, None, 10);
        let ctx = store.load(t.settlement_id).unwrap().unwrap().context;
        let bytes = encode_context(&ctx);
        assert_eq!(decode_context(&bytes).unwrap(), ctx);
        assert_eq!(context_hash(&ctx), context_hash(&ctx));
        // Truncation and trailing bytes fail closed.
        assert!(decode_context(&bytes[..bytes.len() - 1]).is_err());
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(decode_context(&extended).is_err());
    }
}

#[test]
fn journal_is_contiguous_and_replays_to_the_snapshot() {
    // Recovery shape (spec §13): the journal replays to the same context
    // the snapshot holds; a divergence would be corruption.
    let store = SqliteSettlementStore::open(&db_path("replay")).unwrap();
    let t = terms();
    store.create(&t, 1).unwrap();
    let script = [
        envelope(&t, 0xe1, 1, SettlementEvent::RefundArmed),
        envelope(
            &t,
            0xe2,
            2,
            SettlementEvent::FundingObserved {
                evidence: evidence(10),
            },
        ),
        envelope(
            &t,
            0xe3,
            3,
            SettlementEvent::FundingConfirmed {
                evidence: evidence(10),
            },
        ),
    ];
    for env in &script {
        drive(&store, &t, env, None, 10);
    }
    let rows = store.journal(t.settlement_id).unwrap();
    assert_eq!(rows.len(), 3);
    let mut ctx = kaystra_core::state::SettlementContext::new();
    for (row, env) in rows.iter().zip(script.iter()) {
        assert_eq!(row.envelope, *env);
        assert_eq!(row.expected_revision, ctx.revision);
        ctx = transition(ctx, &env.event).unwrap().next;
        assert_eq!(row.resulting_revision, ctx.revision);
        assert_eq!(row.context_hash, context_hash(&ctx));
    }
    let snapshot = store.load(t.settlement_id).unwrap().unwrap();
    assert_eq!(snapshot.context, ctx, "journal replay equals snapshot");
}
