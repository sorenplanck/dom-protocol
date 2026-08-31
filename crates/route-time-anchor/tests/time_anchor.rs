//! Adversarial and deterministic vectors for the durable V2 time authority.

#![allow(clippy::unwrap_used)]

mod common;

use std::fs;

use kaystra_core::types::TimelockSpec;
use route_time_anchor::{
    DurableRouteTimeAnchorStoreV2, EvidenceInstallOutcomeV2, FrozenRouteTimeCheckpointV2,
    FrozenRouteTimeProofCheckpointV2, PolicyInstallOutcomeV2, RouteTimeAnchorErrorV2,
    RouteTimeAnchorStoreConfigV2, RouteTimeEvidenceV2, RouteTimePolicyV2, SignedRouteTimePolicyV2,
};
use tempfile::TempDir;

use common::{checkpoints, evidence, fixture, signed_evidence, signed_policy, EVIDENCE_TIME};

fn store_path() -> (TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = directory.path().join("route-time-v2.sqlite");
    (directory, path)
}

#[test]
fn kat_canonical_policy_evidence_and_worst_case_intervals() {
    let fixture = fixture();
    let evidence = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    let policy_bytes = fixture.policy.canonical_bytes().unwrap();
    let evidence_bytes = evidence.canonical_bytes().unwrap();
    assert_eq!(policy_bytes.len(), 644);
    assert_eq!(evidence_bytes.len(), 880);
    assert_eq!(
        hex::encode(fixture.policy.policy_digest().unwrap()),
        "9bc976021efc2fb4918d63757a7972276bbbf4b309bd96c2ef1f88158b2471b4"
    );
    assert_eq!(
        hex::encode(evidence.evidence_digest().unwrap()),
        "acf69471e8157365f2cefa1b2f5a960b33c48759e63437e120c55895e5c46a91"
    );

    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let (_directory, path) = store_path();
    let mut store = DurableRouteTimeAnchorStoreV2::create(&path, config).unwrap();
    assert_eq!(
        store
            .install_policy(
                &signed_policy(&fixture),
                fixture.policy_context(),
                EVIDENCE_TIME,
            )
            .unwrap(),
        PolicyInstallOutcomeV2::Installed
    );
    assert_eq!(
        store
            .install_evidence(
                &signed_evidence(&fixture, &evidence),
                fixture.evidence_context(),
                EVIDENCE_TIME,
            )
            .unwrap(),
        EvidenceInstallOutcomeV2::Installed
    );
    let proof = store
        .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();
    let hub = proof.hub_proof();
    assert_eq!(hub.downstream.earliest_seconds, 1_000_100);
    assert_eq!(hub.downstream.latest_seconds, 1_000_210);
    assert_eq!(hub.upstream.earliest_seconds, 1_000_300);
    assert_eq!(hub.upstream.latest_seconds, 1_000_610);
    assert!(hub.upstream.earliest_seconds >= hub.downstream.latest_seconds + hub.margin_seconds);
    let counterparty = proof.counterparty_proof();
    assert_eq!(counterparty.downstream.earliest_seconds, 1_003_240);
    assert_eq!(counterparty.downstream.latest_seconds, 1_021_361);
    assert_eq!(counterparty.upstream.earliest_seconds, 3_200_000);
    assert!(
        counterparty.upstream.earliest_seconds
            >= counterparty.downstream.latest_seconds + counterparty.margin_seconds
    );
    assert_eq!(proof.issued_at_seconds(), EVIDENCE_TIME);
    assert_eq!(proof.valid_until_seconds(), EVIDENCE_TIME + 90);
    assert_eq!(
        hex::encode(proof.binding_digest()),
        "1920f7f7231eac109b2d937ed224b54984bc7532995f53e5bdca0bb6f6aa01b0"
    );
    store.revalidate_capability(&proof).unwrap();
    store
        .revalidate_capability_at(&proof, EVIDENCE_TIME)
        .unwrap();
    assert_eq!(
        store
            .consume_capability_at(proof, EVIDENCE_TIME + 90)
            .unwrap_err(),
        RouteTimeAnchorErrorV2::EvidenceStale
    );
}

#[test]
fn restart_revalidation_monotonic_refresh_and_reorg_are_fail_closed() {
    let fixture = fixture();
    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let (_directory, path) = store_path();
    let mut store = DurableRouteTimeAnchorStoreV2::create(&path, config).unwrap();
    let policy = signed_policy(&fixture);
    let evidence_v1 = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    let signed_v1 = signed_evidence(&fixture, &evidence_v1);
    store
        .install_policy(&policy, fixture.policy_context(), EVIDENCE_TIME)
        .unwrap();
    store
        .install_evidence(&signed_v1, fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();
    assert_eq!(
        store
            .install_evidence(&signed_v1, fixture.evidence_context(), EVIDENCE_TIME,)
            .unwrap(),
        EvidenceInstallOutcomeV2::AlreadyCurrent
    );
    let old_capability = store
        .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();
    drop(store);

    let mut reopened = DurableRouteTimeAnchorStoreV2::open_existing(&path, config).unwrap();
    assert_eq!(
        reopened.revalidate_capability(&old_capability),
        Err(RouteTimeAnchorErrorV2::StaleCapability)
    );
    let after_restart = reopened
        .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();
    reopened.revalidate_capability(&after_restart).unwrap();

    let evidence_v2 = evidence(&fixture.policy, 2, EVIDENCE_TIME + 20, 1);
    reopened
        .install_evidence(
            &signed_evidence(&fixture, &evidence_v2),
            fixture.evidence_context(),
            EVIDENCE_TIME + 20,
        )
        .unwrap();
    assert_eq!(
        reopened.revalidate_capability(&after_restart),
        Err(RouteTimeAnchorErrorV2::StaleCapability)
    );

    let mut reorg_checkpoints = checkpoints(&fixture.policy, 0, 2);
    reorg_checkpoints[2].anchor_hash[0] ^= 1;
    let reorg = RouteTimeEvidenceV2::new(
        &fixture.policy,
        3,
        EVIDENCE_TIME + 40,
        EVIDENCE_TIME + 340,
        reorg_checkpoints,
    )
    .unwrap();
    assert_eq!(
        reopened.install_evidence(
            &signed_evidence(&fixture, &reorg),
            fixture.evidence_context(),
            EVIDENCE_TIME + 40,
        ),
        Err(RouteTimeAnchorErrorV2::AnchorReorged)
    );
    assert_eq!(
        reopened
            .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME + 40,)
            .unwrap_err(),
        RouteTimeAnchorErrorV2::AnchorReorged
    );
    drop(reopened);
    let mut after_reorg = DurableRouteTimeAnchorStoreV2::open_existing(&path, config).unwrap();
    assert_eq!(
        after_reorg
            .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME + 40,)
            .unwrap_err(),
        RouteTimeAnchorErrorV2::AnchorReorged
    );
    drop(after_reorg);

    // A local row flip must not revive a route whose retained history proves
    // a threshold-signed frozen-anchor conflict.
    let tamper = rusqlite::Connection::open(&path).unwrap();
    tamper
        .execute(
            "UPDATE route_time_evidence_current SET status_tag = 0 WHERE singleton = 1",
            [],
        )
        .unwrap();
    drop(tamper);
    assert_eq!(
        DurableRouteTimeAnchorStoreV2::open_existing(&path, config).unwrap_err(),
        RouteTimeAnchorErrorV2::CorruptState
    );
}

#[test]
fn same_sequence_equivocation_invalidates_and_survives_restart() {
    let fixture = fixture();
    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let (_directory, path) = store_path();
    let mut store = DurableRouteTimeAnchorStoreV2::create(&path, config).unwrap();
    store
        .install_policy(
            &signed_policy(&fixture),
            fixture.policy_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let first = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    store
        .install_evidence(
            &signed_evidence(&fixture, &first),
            fixture.evidence_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let before_conflict = store
        .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();

    // The logical key is the same sequence. Different, independently signed
    // bytes must be retained as conflict evidence even when observation time
    // is unchanged; treating this as a harmless stale replay would leave the
    // route usable after authority equivocation.
    let equivocation = evidence(&fixture.policy, 1, EVIDENCE_TIME, 1);
    assert_eq!(
        store.install_evidence(
            &signed_evidence(&fixture, &equivocation),
            fixture.evidence_context(),
            EVIDENCE_TIME,
        ),
        Err(RouteTimeAnchorErrorV2::EvidenceRollback)
    );
    assert_eq!(
        store.revalidate_capability(&before_conflict),
        Err(RouteTimeAnchorErrorV2::StaleCapability)
    );
    assert_eq!(
        store
            .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME,)
            .unwrap_err(),
        RouteTimeAnchorErrorV2::AnchorReorged
    );
    drop(store);

    let mut reopened = DurableRouteTimeAnchorStoreV2::open_existing(&path, config).unwrap();
    assert_eq!(
        reopened
            .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME,)
            .unwrap_err(),
        RouteTimeAnchorErrorV2::AnchorReorged
    );
}

#[test]
fn historical_ladder_survives_expiry_and_later_equivocation_without_authorizing_current_work() {
    let fixture = fixture();
    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let (_directory, path) = store_path();
    let mut store = DurableRouteTimeAnchorStoreV2::create(&path, config).unwrap();
    let policy = signed_policy(&fixture);
    let original_evidence = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    let signed_original_evidence = signed_evidence(&fixture, &original_evidence);
    store
        .install_policy(&policy, fixture.policy_context(), EVIDENCE_TIME)
        .unwrap();
    store
        .install_evidence(
            &signed_original_evidence,
            fixture.evidence_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let original_proof = store
        .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();
    let ancestry = FrozenRouteTimeCheckpointV2::new(
        original_proof.route_scope_digest(),
        original_proof.policy_digest(),
        original_proof.evidence_digest(),
        original_proof.evidence_sequence(),
    )
    .unwrap();
    let checkpoint = FrozenRouteTimeProofCheckpointV2::new(
        ancestry,
        original_proof.binding_digest(),
        original_proof.issued_at_seconds(),
        original_proof.valid_until_seconds(),
        EVIDENCE_TIME,
    )
    .unwrap();
    let original_hub = original_proof.hub_proof();
    let original_counterparty = original_proof.counterparty_proof();

    let equivocation = evidence(&fixture.policy, 1, EVIDENCE_TIME, 1);
    assert_eq!(
        store.install_evidence(
            &signed_evidence(&fixture, &equivocation),
            fixture.evidence_context(),
            EVIDENCE_TIME,
        ),
        Err(RouteTimeAnchorErrorV2::EvidenceRollback)
    );
    assert_eq!(
        store
            .prove_current_route_ladder_from_checkpoint(
                ancestry,
                fixture.evidence_context(),
                EVIDENCE_TIME + 100,
            )
            .unwrap_err(),
        RouteTimeAnchorErrorV2::AnchorReorged
    );

    let recovered = store
        .verify_frozen_route_ladder(
            checkpoint,
            &policy,
            &signed_original_evidence,
            fixture.evidence_context(),
        )
        .unwrap();
    assert_eq!(recovered.binding_digest(), checkpoint.proof_digest());
    assert_eq!(recovered.hub_proof(), original_hub);
    assert_eq!(recovered.counterparty_proof(), original_counterparty);
    assert_eq!(recovered.validated_at_seconds(), EVIDENCE_TIME);
}

#[test]
fn historical_ladder_rejects_checkpoint_substitution_and_new_proof_masquerading_as_old() {
    let fixture = fixture();
    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let (_directory, path) = store_path();
    let mut store = DurableRouteTimeAnchorStoreV2::create(&path, config).unwrap();
    let policy = signed_policy(&fixture);
    let original_evidence = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    let signed_original_evidence = signed_evidence(&fixture, &original_evidence);
    store
        .install_policy(&policy, fixture.policy_context(), EVIDENCE_TIME)
        .unwrap();
    store
        .install_evidence(
            &signed_original_evidence,
            fixture.evidence_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let proof = store
        .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();
    let ancestry = FrozenRouteTimeCheckpointV2::new(
        proof.route_scope_digest(),
        proof.policy_digest(),
        proof.evidence_digest(),
        proof.evidence_sequence(),
    )
    .unwrap();
    let checkpoint = FrozenRouteTimeProofCheckpointV2::new(
        ancestry,
        proof.binding_digest(),
        proof.issued_at_seconds(),
        proof.valid_until_seconds(),
        EVIDENCE_TIME,
    )
    .unwrap();

    let mut wrong_proof_digest = checkpoint.proof_digest();
    wrong_proof_digest[0] ^= 1;
    let wrong_checkpoint = FrozenRouteTimeProofCheckpointV2::new(
        ancestry,
        wrong_proof_digest,
        checkpoint.issued_at_seconds(),
        checkpoint.valid_until_seconds(),
        checkpoint.validated_at_seconds(),
    )
    .unwrap();
    assert_eq!(
        store
            .verify_frozen_route_ladder(
                wrong_checkpoint,
                &policy,
                &signed_original_evidence,
                fixture.evidence_context(),
            )
            .unwrap_err(),
        RouteTimeAnchorErrorV2::FrozenCheckpointMismatch
    );

    let masquerading_evidence = evidence(&fixture.policy, 1, EVIDENCE_TIME, 1);
    assert_eq!(
        store
            .verify_frozen_route_ladder(
                checkpoint,
                &policy,
                &signed_evidence(&fixture, &masquerading_evidence),
                fixture.evidence_context(),
            )
            .unwrap_err(),
        RouteTimeAnchorErrorV2::FrozenCheckpointMismatch
    );
    assert_eq!(
        FrozenRouteTimeProofCheckpointV2::new(
            ancestry,
            checkpoint.proof_digest(),
            checkpoint.issued_at_seconds(),
            checkpoint.valid_until_seconds(),
            checkpoint.valid_until_seconds(),
        ),
        Err(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch)
    );

    let (_replacement_directory, replacement_path) = store_path();
    let mut replacement = DurableRouteTimeAnchorStoreV2::create(&replacement_path, config).unwrap();
    replacement
        .install_policy(&policy, fixture.policy_context(), EVIDENCE_TIME + 20)
        .unwrap();
    let replacement_evidence = evidence(&fixture.policy, 2, EVIDENCE_TIME + 20, 1);
    replacement
        .install_evidence(
            &signed_evidence(&fixture, &replacement_evidence),
            fixture.evidence_context(),
            EVIDENCE_TIME + 20,
        )
        .unwrap();
    assert_eq!(
        replacement
            .verify_frozen_route_ladder(
                checkpoint,
                &policy,
                &signed_original_evidence,
                fixture.evidence_context(),
            )
            .unwrap_err(),
        RouteTimeAnchorErrorV2::FrozenCheckpointMismatch
    );
}

#[test]
fn a_second_process_opening_is_refused_while_the_route_authority_is_live() {
    let fixture = fixture();
    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let (_directory, path) = store_path();
    let mut first = DurableRouteTimeAnchorStoreV2::create(&path, config).unwrap();
    first
        .install_policy(
            &signed_policy(&fixture),
            fixture.policy_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let current = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    first
        .install_evidence(
            &signed_evidence(&fixture, &current),
            fixture.evidence_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let old_proof = first
        .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();

    assert_eq!(
        DurableRouteTimeAnchorStoreV2::open_existing(&path, config).unwrap_err(),
        RouteTimeAnchorErrorV2::StorageUnavailable
    );
    first.revalidate_capability(&old_proof).unwrap();
    first
        .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();
}

#[test]
fn restart_rejects_tampered_retained_evidence_encoding() {
    let fixture = fixture();
    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let (_directory, path) = store_path();
    let mut store = DurableRouteTimeAnchorStoreV2::create(&path, config).unwrap();
    store
        .install_policy(
            &signed_policy(&fixture),
            fixture.policy_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let current = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    store
        .install_evidence(
            &signed_evidence(&fixture, &current),
            fixture.evidence_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    drop(store);

    let tamper = rusqlite::Connection::open(&path).unwrap();
    tamper
        .execute(
            "UPDATE route_time_evidence_current
             SET signed_bytes = zeroblob(length(signed_bytes)) WHERE singleton = 1",
            [],
        )
        .unwrap();
    drop(tamper);

    assert_eq!(
        DurableRouteTimeAnchorStoreV2::open_existing(&path, config).unwrap_err(),
        RouteTimeAnchorErrorV2::CorruptState
    );
}

#[test]
fn stale_future_profile_tamper_and_clock_rollback_refuse_by_name() {
    let fixture = fixture();
    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let (_directory, path) = store_path();
    let mut store = DurableRouteTimeAnchorStoreV2::create(&path, config).unwrap();
    store
        .install_policy(
            &signed_policy(&fixture),
            fixture.policy_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let current = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    store
        .install_evidence(
            &signed_evidence(&fixture, &current),
            fixture.evidence_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let proof = store
        .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();
    assert_eq!(
        store
            .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME - 1,)
            .unwrap_err(),
        RouteTimeAnchorErrorV2::ClockRollback
    );

    let future = RouteTimeEvidenceV2::new(
        &fixture.policy,
        2,
        EVIDENCE_TIME + 100,
        EVIDENCE_TIME + 400,
        checkpoints(&fixture.policy, 0, 1),
    )
    .unwrap();
    assert_eq!(
        store.install_evidence(
            &signed_evidence(&fixture, &future),
            fixture.evidence_context(),
            EVIDENCE_TIME + 50,
        ),
        Err(RouteTimeAnchorErrorV2::EvidenceFromFuture)
    );
    assert_eq!(
        store
            .consume_capability_at(proof, EVIDENCE_TIME + 300)
            .unwrap_err(),
        RouteTimeAnchorErrorV2::EvidenceStale
    );
    assert_eq!(
        store
            .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME,)
            .unwrap_err(),
        RouteTimeAnchorErrorV2::ClockRollback
    );

    let mut wrong_profile = checkpoints(&fixture.policy, 0, 1);
    wrong_profile[1].profile_digest[0] ^= 1;
    assert_eq!(
        RouteTimeEvidenceV2::new(
            &fixture.policy,
            2,
            EVIDENCE_TIME + 20,
            EVIDENCE_TIME + 320,
            wrong_profile,
        ),
        Err(RouteTimeAnchorErrorV2::RegistryMismatch)
    );
    let mut reversed_interval = checkpoints(&fixture.policy, 0, 1);
    reversed_interval[0].time_lower_seconds = reversed_interval[0].time_upper_seconds + 1;
    assert_eq!(
        RouteTimeEvidenceV2::new(
            &fixture.policy,
            2,
            EVIDENCE_TIME + 20,
            EVIDENCE_TIME + 320,
            reversed_interval,
        ),
        Err(RouteTimeAnchorErrorV2::InvalidEvidence)
    );
}

#[test]
fn unsafe_window_deadline_passed_and_overflow_never_bind() {
    let mut unsafe_fixture = fixture();
    unsafe_fixture.upstream.counterparty_leg.deadline =
        TimelockSpec::TimestampSeconds { value: 3_000_000 };
    unsafe_fixture.policy = RouteTimePolicyV2::from_registry(
        &unsafe_fixture.registry,
        &unsafe_fixture.upstream,
        &unsafe_fixture.downstream,
        common::limits(),
    )
    .unwrap();
    assert_proof_refusal(unsafe_fixture, RouteTimeAnchorErrorV2::UnsafeWindow);

    let mut passed_fixture = fixture();
    passed_fixture.downstream.counterparty_leg.deadline = TimelockSpec::BtcTime512s { value: 1 };
    passed_fixture.policy = RouteTimePolicyV2::from_registry(
        &passed_fixture.registry,
        &passed_fixture.upstream,
        &passed_fixture.downstream,
        common::limits(),
    )
    .unwrap();
    assert_proof_refusal(passed_fixture, RouteTimeAnchorErrorV2::DeadlinePassed);

    let mut overflow_fixture = fixture();
    overflow_fixture.upstream.dom_leg.deadline = TimelockSpec::BlockHeight { value: u64::MAX };
    overflow_fixture.policy = RouteTimePolicyV2::from_registry(
        &overflow_fixture.registry,
        &overflow_fixture.upstream,
        &overflow_fixture.downstream,
        common::limits(),
    )
    .unwrap();
    assert_proof_refusal(overflow_fixture, RouteTimeAnchorErrorV2::Overflow);
}

#[test]
fn funding_anchor_horizon_is_threshold_signed_and_cannot_be_optimistic() {
    let fixture = fixture();
    let mut optimistic_limits = common::limits();
    optimistic_limits.max_downstream_funding_anchor_delay_seconds = 1;
    assert_eq!(
        RouteTimePolicyV2::from_registry(
            &fixture.registry,
            &fixture.upstream,
            &fixture.downstream,
            optimistic_limits,
        ),
        Err(RouteTimeAnchorErrorV2::InvalidPolicy)
    );

    let mut altered_limits = common::limits();
    altered_limits.max_downstream_funding_anchor_delay_seconds += 1;
    let altered_policy = RouteTimePolicyV2::from_registry(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        altered_limits,
    )
    .unwrap();
    assert_ne!(
        altered_policy.policy_digest().unwrap(),
        fixture.policy.policy_digest().unwrap()
    );
    let old_signatures = signed_policy(&fixture).signatures().to_vec();
    let tampered_envelope = SignedRouteTimePolicyV2::new(&altered_policy, old_signatures).unwrap();

    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let (_directory, path) = store_path();
    let mut store = DurableRouteTimeAnchorStoreV2::create(&path, config).unwrap();
    assert_eq!(
        store.install_policy(&tampered_envelope, fixture.policy_context(), EVIDENCE_TIME,),
        Err(RouteTimeAnchorErrorV2::InvalidSignature)
    );
}

#[test]
fn public_dom_mainnet_is_explicitly_disabled() {
    let (registry, upstream, downstream) = common::mainnet_registry_and_terms();
    assert_eq!(
        RouteTimePolicyV2::from_registry(&registry, &upstream, &downstream, common::limits()),
        Err(RouteTimeAnchorErrorV2::MainnetDisabled)
    );
}

fn assert_proof_refusal(fixture: common::Fixture, expected: RouteTimeAnchorErrorV2) {
    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let (_directory, path) = store_path();
    let mut store = DurableRouteTimeAnchorStoreV2::create(&path, config).unwrap();
    store
        .install_policy(
            &signed_policy(&fixture),
            fixture.policy_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let current = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    store
        .install_evidence(
            &signed_evidence(&fixture, &current),
            fixture.evidence_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    assert_eq!(
        store
            .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME,)
            .unwrap_err(),
        expected
    );
}
