//! End-to-end observation, finality, reorg and evidence behaviour of
//! `adapter-evm`, driven entirely by the deterministic in-crate mock.

mod common;

use adapter_evm::evidence::{EvidenceKind, EvidencePayload, EvmEvidence};
use adapter_evm::mock::Faults;
use adapter_evm::{EvmCursor, UnsignedEvmCall, ADAPTER_VERSION};
use common::{block_on, scenario, AMOUNT};
use counterparty_api::{
    AdapterError, ChainCursor, CounterpartyAdapter, ObservedEvent, RevealedSecretBytes,
    VerifiedOutcome,
};

fn heights(events: &[ObservedEvent]) -> Vec<u64> {
    events
        .iter()
        .map(|e| match e {
            ObservedEvent::LockOpened { height, .. }
            | ObservedEvent::LockClaimed { height, .. }
            | ObservedEvent::LockRefunded { height, .. } => *height,
            ObservedEvent::Reorged { from_height } => *from_height,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// happy path
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_is_observed_in_order() {
    let s = scenario(7);
    let open_h = s.mine_open();
    let claim_h = s.mine_claim();
    s.finalize_tip();

    let a = s.adapter();
    let (events, cursor) = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");

    assert_eq!(
        events,
        vec![
            ObservedEvent::LockOpened {
                lock_id: s.lock_id,
                height: open_h
            },
            ObservedEvent::LockClaimed {
                lock_id: s.lock_id,
                revealed: RevealedSecretBytes::new(s.secret),
                height: claim_h
            },
        ]
    );

    // The cursor is persistable and decodes back to exactly what it encoded.
    let decoded = EvmCursor::decode(&cursor, s.cfg.chain_id, &s.cfg.contract, s.cfg.start_block)
        .expect("cursor decodes");
    assert_eq!(decoded.next_from_block, s.height() + 1);
    assert_eq!(decoded.emitted_high_water, claim_h);

    // Re-observing from the advanced cursor yields nothing new.
    let (again, _) = a.observe_blocking(&cursor, 64).expect("observe");
    assert!(again.is_empty(), "cursor did not advance: {again:?}");
}

#[test]
fn refund_path_is_observed() {
    let s = scenario(11);
    s.mine_open();
    let refund_h = s.mine_refund();
    s.finalize_tip();

    let a = s.adapter();
    let (events, _) = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    assert_eq!(
        events.last(),
        Some(&ObservedEvent::LockRefunded {
            lock_id: s.lock_id,
            height: refund_h
        })
    );
}

#[test]
fn the_async_trait_surface_agrees_with_the_blocking_core() {
    let s = scenario(13);
    s.mine_open();
    s.mine_claim();
    s.finalize_tip();
    let a = s.adapter();

    let sync = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    let asynchronous = block_on(a.observe(&ChainCursor::default(), 64)).expect("observe");
    assert_eq!(sync, asynchronous);

    assert_eq!(a.adapter_version(), ADAPTER_VERSION);
    assert_eq!(a.chain_id(), adapter_evm::evm_counterparty_chain_id(31337));
    assert!(a.capabilities().supports_condition_lock);

    let artifact = block_on(a.prepare_lock(
        &adapter_evm::adapter::test_support::sample_neutral(a.config(), AMOUNT, s.deadline),
        &s.adaptor_point,
    ))
    .expect("prepare_lock");
    let call = UnsignedEvmCall::decode(&artifact.bytes).expect("decodes");
    assert_eq!(
        call.lock_id, s.lock_id,
        "prepare_lock must agree with the chain"
    );
    assert_eq!(call.binding, s.binding);
}

// ---------------------------------------------------------------------------
// finality
// ---------------------------------------------------------------------------

#[test]
fn nothing_above_the_finalized_height_is_ever_surfaced() {
    let s = scenario(17);
    let open_h = s.mine_open();
    s.mine_claim();
    // Finalize only up to the opening block.
    s.finalize(open_h);

    let a = s.adapter();
    let (events, cursor) = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    assert_eq!(heights(&events), vec![open_h]);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, ObservedEvent::LockClaimed { .. })),
        "a claim above the finalized height leaked out"
    );

    // Once the checkpoint advances, the claim appears — and only then.
    s.finalize_tip();
    let (events, _) = a.observe_blocking(&cursor, 64).expect("observe");
    assert!(events
        .iter()
        .any(|e| matches!(e, ObservedEvent::LockClaimed { .. })));
}

#[test]
fn an_endpoint_without_the_finalized_tag_fails_closed() {
    let s = scenario(19);
    s.mine_open();
    s.mine_claim();
    // No `finalize` call at all: the tag answers null.
    let a = s.adapter();
    assert_eq!(
        a.observe_blocking(&ChainCursor::default(), 64),
        Err(AdapterError::AdapterUnavailable),
        "A4-EVM: no fallback to a confirmation count"
    );

    s.finalize_tip();
    s.chain.set_faults(Faults {
        finalized_null: true,
        ..Faults::default()
    });
    assert_eq!(
        a.observe_blocking(&ChainCursor::default(), 64),
        Err(AdapterError::AdapterUnavailable)
    );
}

// ---------------------------------------------------------------------------
// reorg
// ---------------------------------------------------------------------------

#[test]
fn a_reorg_is_reported_and_the_cursor_rewinds() {
    let s = scenario(23);
    s.mine_open();
    let claim_h = s.mine_claim();
    s.finalize_tip();

    let a = s.adapter();
    let (events, cursor) = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    assert_eq!(events.len(), 2);

    // The block carrying the claim is orphaned.
    s.reorg(1);
    s.finalize_tip();

    let (events, rewound) = a.observe_blocking(&cursor, 64).expect("observe");
    assert_eq!(
        events,
        vec![ObservedEvent::Reorged {
            from_height: claim_h
        }],
        "a reorg must be an observable event, never a panic (I11)"
    );
    let decoded = EvmCursor::decode(&rewound, s.cfg.chain_id, &s.cfg.contract, s.cfg.start_block)
        .expect("cursor decodes");
    assert_eq!(decoded.next_from_block, claim_h);
    assert!(decoded.emitted_high_water < claim_h);
}

#[test]
fn a_reorg_does_not_un_reveal_the_secret() {
    let s = scenario(29);
    s.mine_open();
    s.mine_claim();
    s.finalize_tip();

    let a = s.adapter();
    let (_, cursor) = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    assert!(a.is_revealed(&s.lock_id).expect("state"));
    assert_eq!(
        a.revealed_secret(&s.lock_id).expect("state"),
        Some(RevealedSecretBytes::new(s.secret))
    );

    // Orphan the claim. The settlement effect is gone...
    s.reorg(1);
    s.finalize_tip();
    let (events, cursor) = a.observe_blocking(&cursor, 64).expect("observe");
    assert!(matches!(events.as_slice(), [ObservedEvent::Reorged { .. }]));

    // ... but `t` was broadcast, and no rewind can unsend a packet.
    assert!(
        a.is_revealed(&s.lock_id).expect("state"),
        "a reorg must not make an already-revealed scalar secret again"
    );
    assert_eq!(
        a.revealed_secret(&s.lock_id).expect("state"),
        Some(RevealedSecretBytes::new(s.secret)),
        "the scalar itself must survive the rewind unchanged"
    );

    // Replaying the rewound range does not resurrect the settlement effect
    // (the claim is simply not on this chain any more) and does not disturb the
    // secret either.
    let (replayed, _) = a.observe_blocking(&cursor, 64).expect("observe");
    assert!(
        !replayed
            .iter()
            .any(|e| matches!(e, ObservedEvent::LockClaimed { .. })),
        "the orphaned claim must not be re-surfaced as a settlement"
    );
    assert!(a.is_revealed(&s.lock_id).expect("state"));
}

#[test]
fn rewind_then_replay_is_idempotent() {
    let s = scenario(31);
    s.mine_open();
    s.mine_claim();
    s.mine(2);
    s.finalize_tip();

    let a = s.adapter();
    let (first, cursor) = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");

    // Re-observing from a rewound cursor must reproduce the same events.
    let start = EvmCursor::fresh(s.cfg.chain_id, s.cfg.contract, s.cfg.start_block);
    let (second, cursor_b) = a.observe_blocking(&start.encode(), 64).expect("observe");
    assert_eq!(first, second, "replay must be idempotent");
    assert_eq!(cursor, cursor_b);

    // And a third pass changes nothing.
    let (third, cursor_c) = a.observe_blocking(&start.encode(), 64).expect("observe");
    assert_eq!(second, third);
    assert_eq!(cursor_b, cursor_c);
}

#[test]
fn a_reorg_deeper_than_the_policy_fails_closed() {
    let s = scenario(37);
    s.mine(10);
    s.mine_open();
    s.mine(10);
    s.finalize_tip();

    let mut cfg = s.cfg;
    cfg.max_reorg_depth = 2;
    let a = adapter_evm::EvmAdapter::new(cfg, s.chain.clone()).expect("valid config");
    let (_, cursor) = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");

    s.reorg(9);
    s.finalize_tip();
    assert_eq!(
        a.observe_blocking(&cursor, 64),
        Err(AdapterError::ReorgDetected),
        "a reorg past max_reorg_depth must not be silently absorbed"
    );
}

#[test]
fn a_restart_from_a_persisted_cursor_resumes_correctly() {
    let s = scenario(41);
    let open_h = s.mine_open();
    s.finalize_tip();

    let first = s.adapter();
    let (events, cursor) = first
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    assert_eq!(heights(&events), vec![open_h]);

    // Simulate a process restart: brand new adapter, only the cursor bytes and
    // the lock terms survive.
    let restarted = s.adapter();
    restarted
        .track_lock(&s.terms)
        .expect("re-register the lock");
    let claim_h = s.mine_claim();
    s.finalize_tip();

    let (events, _) = restarted.observe_blocking(&cursor, 64).expect("observe");
    assert_eq!(
        events,
        vec![ObservedEvent::LockClaimed {
            lock_id: s.lock_id,
            revealed: RevealedSecretBytes::new(s.secret),
            height: claim_h
        }],
        "a restart must resume from the persisted cursor without replaying"
    );
}

#[test]
fn a_cursor_from_another_deployment_is_refused() {
    let s = scenario(43);
    s.mine_open();
    s.finalize_tip();
    let a = s.adapter();

    let foreign = EvmCursor::fresh(999, s.cfg.contract, 0).encode();
    assert_eq!(
        a.observe_blocking(&foreign, 64),
        Err(AdapterError::StaleCursor)
    );
    let foreign = EvmCursor::fresh(s.cfg.chain_id, [0xAB; 20], 0).encode();
    assert_eq!(
        a.observe_blocking(&foreign, 64),
        Err(AdapterError::StaleCursor)
    );
    let mut truncated = EvmCursor::fresh(s.cfg.chain_id, s.cfg.contract, 0).encode();
    truncated.0.pop();
    assert_eq!(
        a.observe_blocking(&truncated, 64),
        Err(AdapterError::VersionMismatch)
    );
}

// ---------------------------------------------------------------------------
// hostile endpoints
// ---------------------------------------------------------------------------

fn hostile_observe(faults: Faults) -> Result<Vec<ObservedEvent>, AdapterError> {
    let s = scenario(47);
    s.mine_open();
    s.mine_claim();
    s.finalize_tip();
    s.chain.set_faults(faults);
    let a = s.adapter();
    a.observe_blocking(&ChainCursor::default(), 64)
        .map(|(e, _)| e)
}

#[test]
fn every_hostile_endpoint_shape_fails_closed() {
    let cases: Vec<(&str, Faults, AdapterError)> = vec![
        (
            "transport down",
            Faults {
                break_transport: true,
                ..Faults::default()
            },
            AdapterError::AdapterUnavailable,
        ),
        (
            "wrong chain id",
            Faults {
                wrong_chain_id: true,
                ..Faults::default()
            },
            AdapterError::EvidenceInvalid,
        ),
        (
            "wrong bytecode",
            Faults {
                wrong_code: true,
                ..Faults::default()
            },
            AdapterError::EvidenceInvalid,
        ),
        (
            "foreign emitter",
            Faults {
                wrong_emitter: true,
                ..Faults::default()
            },
            AdapterError::EvidenceInvalid,
        ),
        (
            "unknown topic0",
            Faults {
                wrong_topic0: true,
                ..Faults::default()
            },
            AdapterError::EvidenceInvalid,
        ),
        (
            "wrong topic arity",
            Faults {
                wrong_topic_arity: true,
                ..Faults::default()
            },
            AdapterError::EvidenceInvalid,
        ),
        (
            "truncated log data",
            Faults {
                truncate_log_data: true,
                ..Faults::default()
            },
            AdapterError::EvidenceInvalid,
        ),
        (
            "extra log data",
            Faults {
                extra_log_data: true,
                ..Faults::default()
            },
            AdapterError::EvidenceInvalid,
        ),
        (
            "log marked removed",
            Faults {
                mark_logs_removed: true,
                ..Faults::default()
            },
            AdapterError::EvidenceInvalid,
        ),
        (
            "absent removed flag",
            Faults {
                drop_removed_field: true,
                ..Faults::default()
            },
            AdapterError::EvidenceInvalid,
        ),
        (
            "reverted receipt",
            Faults {
                receipt_reverted: true,
                ..Faults::default()
            },
            AdapterError::EvidenceInvalid,
        ),
        (
            "missing receipt",
            Faults {
                receipt_missing: true,
                ..Faults::default()
            },
            AdapterError::EvidenceInvalid,
        ),
        (
            "receipt in another block",
            Faults {
                receipt_block_mismatch: true,
                ..Faults::default()
            },
            AdapterError::EvidenceInvalid,
        ),
        (
            "no finalized tag",
            Faults {
                finalized_null: true,
                ..Faults::default()
            },
            AdapterError::AdapterUnavailable,
        ),
    ];
    for (name, faults, expected) in cases {
        assert_eq!(
            hostile_observe(faults),
            Err(expected),
            "hostile endpoint '{name}' was not rejected as expected"
        );
    }
}

#[test]
fn structurally_garbage_answers_fail_closed() {
    let got = hostile_observe(Faults {
        garbage_results: true,
        ..Faults::default()
    });
    assert!(got.is_err(), "garbage RPC results must not be interpreted");
}

#[test]
fn out_of_order_and_duplicated_pages_are_normalised() {
    let s = scenario(53);
    let open_h = s.mine_open();
    let claim_h = s.mine_claim();
    s.finalize_tip();
    s.chain.set_faults(Faults {
        logs_out_of_order: true,
        duplicate_logs: true,
        ..Faults::default()
    });

    let a = s.adapter();
    let (events, _) = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    assert_eq!(
        heights(&events),
        vec![open_h, claim_h],
        "results must be sorted by (blockNumber, logIndex) and deduplicated"
    );
    assert_eq!(events.len(), 2, "duplicates leaked through");
}

#[test]
fn logs_from_another_session_on_the_same_contract_are_ignored() {
    let s = scenario(59);
    s.mine_foreign_open();
    let open_h = s.mine_open();
    let claim_h = s.mine_claim();
    s.finalize_tip();

    let a = s.adapter();
    let (events, _) = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    assert_eq!(
        heights(&events),
        vec![open_h, claim_h],
        "a lock belonging to a different session must not be surfaced"
    );
}

#[test]
fn a_scalar_that_does_not_open_the_adaptor_point_is_fatal() {
    let s = scenario(61);
    s.mine_open();
    // A claim carrying a canonical but *wrong* scalar.
    let mut wrong = s.secret;
    wrong[31] ^= 0x0F;
    s.chain.with_mut(|c| {
        c.push_block();
        c.push_claimed(
            s.lock_id,
            s.binding,
            adapter_evm::adapter::test_support::FIXTURE_BENEFICIARY,
            wrong,
        )
        .expect("log appended");
    });
    s.finalize_tip();

    let a = s.adapter();
    assert_eq!(
        a.observe_blocking(&ChainCursor::default(), 64),
        Err(AdapterError::EvidenceInvalid),
        "a scalar that does not recover address(T) must be rejected"
    );
}

#[test]
fn a_non_canonical_scalar_is_rejected() {
    let s = scenario(67);
    s.mine_open();
    s.chain.with_mut(|c| {
        c.push_block();
        c.push_claimed(
            s.lock_id,
            s.binding,
            adapter_evm::adapter::test_support::FIXTURE_BENEFICIARY,
            [0u8; 32], // t == 0
        )
        .expect("log appended");
    });
    s.finalize_tip();
    let a = s.adapter();
    assert_eq!(
        a.observe_blocking(&ChainCursor::default(), 64),
        Err(AdapterError::EvidenceInvalid)
    );
}

// ---------------------------------------------------------------------------
// evidence
// ---------------------------------------------------------------------------

#[test]
fn evidence_round_trips_through_the_neutral_boundary() {
    let s = scenario(71);
    s.mine_open();
    let claim_h = s.mine_claim();
    s.finalize_tip();

    let a = s.adapter();
    let _ = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");

    let evidence = a
        .collect_evidence(&s.lock_id, EvidenceKind::Claimed)
        .expect("evidence collected");
    assert_eq!(evidence.block_number, claim_h);
    assert_eq!(evidence.lock_id, s.lock_id);
    assert_eq!(evidence.binding, s.binding);

    let bytes = evidence.encode();
    assert_eq!(
        block_on(a.verify_evidence(&bytes)),
        Ok(VerifiedOutcome::Claimed {
            revealed: RevealedSecretBytes::new(s.secret),
            height: claim_h
        })
    );

    // Funding evidence too.
    let funded = a
        .collect_evidence(&s.lock_id, EvidenceKind::Funded)
        .expect("evidence collected");
    assert_eq!(
        block_on(a.verify_evidence(&funded.encode())),
        Ok(VerifiedOutcome::Funded { height: 1 })
    );
}

#[test]
fn tampered_evidence_is_refused_field_by_field() {
    let s = scenario(73);
    s.mine_open();
    s.mine_claim();
    s.finalize_tip();
    let a = s.adapter();
    let _ = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    let good = a
        .collect_evidence(&s.lock_id, EvidenceKind::Claimed)
        .expect("evidence");

    let mut mutations: Vec<(&str, EvmEvidence)> = Vec::new();
    let mut e = good;
    e.chain_id += 1;
    mutations.push(("chain id", e));
    let mut e = good;
    e.contract[0] ^= 1;
    mutations.push(("contract", e));
    let mut e = good;
    e.code_hash[0] ^= 1;
    mutations.push(("codehash", e));
    let mut e = good;
    e.terms.session_id[0] ^= 1;
    mutations.push(("session id", e));
    let mut e = good;
    e.terms.terms_hash[0] ^= 1;
    mutations.push(("terms hash", e));
    let mut e = good;
    e.terms.amount[31] ^= 1;
    mutations.push(("amount", e));
    let mut e = good;
    e.binding[0] ^= 1;
    mutations.push(("binding", e));
    let mut e = good;
    e.lock_id[0] ^= 1;
    mutations.push(("lock id", e));
    let mut e = good;
    let mut slot = e.payload.wire_bytes();
    slot[0] ^= 1;
    e.payload = EvidencePayload::from_wire(e.kind, slot);
    mutations.push(("payload", e));
    let mut e = good;
    e.block_hash[0] ^= 1;
    mutations.push(("block hash", e));
    let mut e = good;
    e.tx_hash[0] ^= 1;
    mutations.push(("tx hash", e));
    let mut e = good;
    e.log_index += 1;
    mutations.push(("log index", e));
    let mut e = good;
    e.finalized_block_hash[0] ^= 1;
    mutations.push(("finalized block hash", e));
    let mut e = good;
    e.finalized_height += 1_000;
    mutations.push(("finalized height", e));

    for (name, e) in mutations {
        assert!(
            block_on(a.verify_evidence(&e.encode())).is_err(),
            "tampering with the {name} was accepted"
        );
    }

    // Sanity: the untouched record still verifies.
    assert!(block_on(a.verify_evidence(&good.encode())).is_ok());
}

#[test]
fn evidence_for_an_orphaned_block_is_refused() {
    let s = scenario(79);
    s.mine_open();
    s.mine_claim();
    s.finalize_tip();
    let a = s.adapter();
    let _ = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    let evidence = a
        .collect_evidence(&s.lock_id, EvidenceKind::Claimed)
        .expect("evidence");
    let bytes = evidence.encode();
    assert!(block_on(a.verify_evidence(&bytes)).is_ok());

    s.reorg(1);
    s.finalize_tip();
    assert!(
        block_on(a.verify_evidence(&bytes)).is_err(),
        "evidence pinned to an orphaned block must stop verifying"
    );
}

#[test]
fn malformed_evidence_frames_are_refused() {
    let s = scenario(83);
    s.mine_open();
    s.mine_claim();
    s.finalize_tip();
    let a = s.adapter();
    let _ = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");
    let good = a
        .collect_evidence(&s.lock_id, EvidenceKind::Claimed)
        .expect("evidence")
        .encode();

    assert!(block_on(a.verify_evidence(&[])).is_err());
    let mut short = good.clone();
    short.pop();
    assert!(block_on(a.verify_evidence(&short)).is_err());
    let mut long = good.clone();
    long.push(0);
    assert!(
        block_on(a.verify_evidence(&long)).is_err(),
        "trailing bytes must never be ignored"
    );
    let mut huge = good;
    huge.resize(1 << 16, 0);
    assert!(block_on(a.verify_evidence(&huge)).is_err());
}

// ---------------------------------------------------------------------------
// I6
// ---------------------------------------------------------------------------

#[test]
fn no_error_and_no_debug_rendering_ever_carries_the_scalar() {
    let s = scenario(89);
    s.mine_open();
    s.mine_claim();
    s.finalize_tip();
    let a = s.adapter();
    let (events, _) = a
        .observe_blocking(&ChainCursor::default(), 64)
        .expect("observe");

    let hex_secret: String = s.secret.iter().map(|b| format!("{b:02x}")).collect();
    let rendered = format!("{events:?}");
    assert!(
        !rendered.contains(&hex_secret),
        "the scalar leaked into a Debug rendering"
    );
    assert!(rendered.contains("redacted"));

    let evidence = a
        .collect_evidence(&s.lock_id, EvidenceKind::Claimed)
        .expect("evidence");
    let rendered = format!("{evidence:?}");
    assert!(!rendered.contains(&hex_secret));
    assert!(rendered.contains("<redacted>"));

    // Every error path is a unit variant, so it cannot carry material.
    let mut broken = evidence;
    let mut slot = broken.payload.wire_bytes();
    slot[0] ^= 1;
    broken.payload = EvidencePayload::from_wire(broken.kind, slot);
    let err = block_on(a.verify_evidence(&broken.encode())).expect_err("must fail");
    assert_eq!(format!("{err:?}"), "EvidenceInvalid");
    assert!(!format!("{err:?}{err}").contains(&hex_secret));
}

// ---------------------------------------------------------------------------
// caps
// ---------------------------------------------------------------------------

#[test]
fn the_event_budget_is_respected_and_capped() {
    let s = scenario(97);
    s.mine_open();
    for _ in 0..4 {
        s.mine_claim();
    }
    s.finalize_tip();
    let a = s.adapter();

    // A budget of one delivers exactly the first block's events, and the cursor
    // stops right after that block.
    let (events, cursor) = a
        .observe_blocking(&ChainCursor::default(), 1)
        .expect("observe");
    assert_eq!(events.len(), 1);
    let decoded = EvmCursor::decode(&cursor, s.cfg.chain_id, &s.cfg.contract, 0).expect("cursor");
    assert!(decoded.next_from_block <= s.height());

    // A zero budget consumes nothing at all.
    let (events, unchanged) = a
        .observe_blocking(&ChainCursor::default(), 0)
        .expect("observe");
    assert!(events.is_empty());
    assert_eq!(
        EvmCursor::decode(&unchanged, s.cfg.chain_id, &s.cfg.contract, 0)
            .expect("cursor")
            .next_from_block,
        0
    );

    // A budget above the hard ceiling is clamped, not honoured.
    let (all, _) = a
        .observe_blocking(&ChainCursor::default(), usize::MAX)
        .expect("observe");
    assert!(all.len() <= counterparty_api::MAX_EVENTS_PER_OBSERVE);
}
