//! V2 composition across EVM, DOM and Bitcoin authenticated time domains.

#[path = "../../route-time-anchor/tests/common/mod.rs"]
mod time_common;

use std::fs;

use route_composer::{
    ComposedBindingV1, ComposedBindingV2, ComposedSettlementLegV1, ComposedWindowPolicyV1,
    ComposerRefusal, FinalClaimRevealModeV1, FinalClaimRoleSelectionV1,
    FinalClaimSecretSourceScopeInputV1, FinalClaimSecretSourceScopeV1, FinalClaimSecretSourceV1,
};
use route_time_anchor::{
    DurableRouteTimeAnchorStoreV2, FrozenRouteTimeCheckpointV2, FrozenRouteTimeProofCheckpointV2,
    RouteTimeAnchorStoreConfigV2, RouteTimeEvidenceVerificationContextV2,
    RouteTimePolicyVerificationContextV2,
};

use time_common::{evidence, fixture, signed_evidence, signed_policy, EVIDENCE_TIME};

fn store_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = directory.path().join("route-composer-time-v2.sqlite");
    (directory, path)
}

#[test]
fn v1_refuses_mixed_clocks_but_v2_binds_exact_authenticated_intervals() {
    let fixture = fixture();
    assert_eq!(
        ComposedBindingV1::bind(
            fixture.upstream.clone(),
            fixture.downstream.clone(),
            ComposedWindowPolicyV1 {
                hub_margin: 1,
                counterparty_margin: 1,
            },
        )
        .unwrap_err(),
        ComposerRefusal::MixedTimelockDomains
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
    let policy_context = RouteTimePolicyVerificationContextV2::new(
        &fixture.policy_authorities,
        &fixture.secp,
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
    );
    let evidence_context =
        RouteTimeEvidenceVerificationContextV2::new(policy_context, &fixture.evidence_authorities);
    let signed_policy_v1 = signed_policy(&fixture);
    store
        .install_policy(&signed_policy_v1, policy_context, EVIDENCE_TIME)
        .unwrap();
    let evidence_v1 = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    let signed_evidence_v1 = signed_evidence(&fixture, &evidence_v1);
    store
        .install_evidence(&signed_evidence_v1, evidence_context, EVIDENCE_TIME)
        .unwrap();
    let proof = store
        .prove_route_ladder(evidence_context, EVIDENCE_TIME)
        .unwrap();
    store.revalidate_capability(&proof).unwrap();
    let current_proof = store.consume_capability_at(proof, EVIDENCE_TIME).unwrap();
    let binding = ComposedBindingV2::bind(
        fixture.upstream.clone(),
        fixture.downstream.clone(),
        current_proof,
    )
    .unwrap();

    assert_eq!(binding.evidence_sequence(), 1);
    assert_eq!(binding.time_proof_issued_at_seconds(), EVIDENCE_TIME);
    assert_eq!(binding.time_proof_valid_until_seconds(), EVIDENCE_TIME + 90);
    assert_eq!(binding.time_proof_validated_at_seconds(), EVIDENCE_TIME);
    assert_eq!(
        binding.time_policy_digest(),
        fixture.policy.policy_digest().unwrap()
    );
    assert_eq!(
        binding.time_evidence_digest(),
        evidence_v1.evidence_digest().unwrap()
    );
    for rung in [binding.hub_time_proof(), binding.counterparty_time_proof()] {
        assert!(
            rung.upstream.earliest_seconds >= rung.downstream.latest_seconds + rung.margin_seconds
        );
    }
    assert_eq!(
        hex::encode(binding.binding_digest()),
        "d764c30462a6ee54364e1e0297fdd48c5e463ec81c16d098d6257da1593e1813"
    );

    // FinalClaim roles are explicit and source scopes carry their exact claim
    // templates. Neither roster order nor route position selects a role.
    let route_id = [0x91; 32];
    let source_scope = |terms: &kaystra_core::terms::SettlementTermsV1, template| {
        FinalClaimSecretSourceScopeV1::new(FinalClaimSecretSourceScopeInputV1 {
            secret_source: FinalClaimSecretSourceV1::LocalOrigin,
            reveal_mode: FinalClaimRevealModeV1::DomRevealsFirst,
            route_id,
            composition_binding_digest: binding.binding_digest(),
            source_chain_id: terms.dom_leg.chain_id,
            source_settlement_id: terms.settlement_id,
            source_session_id: terms.session_id,
            source_claim_template_hash: template,
            adaptor_point_sec1: terms.adaptor_point_sec1,
            adaptor_secret_origin_id: terms.dom_leg.beneficiary,
            dom_claim_sender_id: terms.dom_leg.beneficiary,
        })
        .unwrap()
    };
    let selection = |terms: &kaystra_core::terms::SettlementTermsV1, scope| {
        FinalClaimRoleSelectionV1::new(
            terms.dom_leg.beneficiary,
            terms.dom_leg.beneficiary,
            terms.dom_leg.refund_to,
            FinalClaimRevealModeV1::DomRevealsFirst,
            FinalClaimSecretSourceV1::LocalOrigin,
            scope,
        )
        .unwrap()
    };
    let upstream_scope = source_scope(binding.upstream(), [0x92; 32]);
    let downstream_scope = source_scope(binding.downstream(), [0x93; 32]);
    let role_plan = binding
        .bind_final_claim_role_plan(
            route_id,
            selection(binding.upstream(), upstream_scope),
            selection(binding.downstream(), downstream_scope),
        )
        .unwrap();
    assert_eq!(role_plan.route_scope_digest(), binding.route_scope_digest());
    assert_eq!(
        role_plan.composition_binding_digest(),
        binding.binding_digest()
    );
    assert_eq!(
        role_plan
            .entry(ComposedSettlementLegV1::Upstream)
            .dom_claim_sender_id(),
        binding.upstream().dom_leg.beneficiary
    );

    let mismatched_scope = FinalClaimSecretSourceScopeV1::new(FinalClaimSecretSourceScopeInputV1 {
        secret_source: FinalClaimSecretSourceV1::LocalOrigin,
        reveal_mode: FinalClaimRevealModeV1::DomRevealsFirst,
        route_id,
        composition_binding_digest: [0xff; 32],
        source_chain_id: binding.upstream().dom_leg.chain_id,
        source_settlement_id: binding.upstream().settlement_id,
        source_session_id: binding.upstream().session_id,
        source_claim_template_hash: [0x92; 32],
        adaptor_point_sec1: binding.upstream().adaptor_point_sec1,
        adaptor_secret_origin_id: binding.upstream().dom_leg.beneficiary,
        dom_claim_sender_id: binding.upstream().dom_leg.beneficiary,
    })
    .unwrap();
    assert_eq!(
        binding
            .bind_final_claim_role_plan(
                route_id,
                selection(binding.upstream(), mismatched_scope),
                selection(
                    binding.downstream(),
                    source_scope(binding.downstream(), [0x93; 32]),
                ),
            )
            .unwrap_err(),
        ComposerRefusal::InvalidFinalClaimRolePlan
    );

    let mut scalar = [0u8; 32];
    scalar[31] = 1;
    assert_eq!(
        binding.verify_revealed_scalar(&scalar).unwrap().expose(),
        &scalar
    );
    assert!(binding.composed_treasury_share().unwrap() > 0);

    let frozen_ancestry = FrozenRouteTimeCheckpointV2::new(
        binding.route_scope_digest(),
        binding.time_policy_digest(),
        binding.time_evidence_digest(),
        binding.evidence_sequence(),
    )
    .unwrap();
    let frozen_checkpoint = FrozenRouteTimeProofCheckpointV2::new(
        frozen_ancestry,
        binding.time_proof_digest(),
        binding.time_proof_issued_at_seconds(),
        binding.time_proof_valid_until_seconds(),
        binding.time_proof_validated_at_seconds(),
    )
    .unwrap();
    let historical_proof = store
        .verify_frozen_route_ladder(
            frozen_checkpoint,
            &signed_policy_v1,
            &signed_evidence_v1,
            evidence_context,
        )
        .unwrap();
    let recovered = ComposedBindingV2::bind_recovered(
        fixture.upstream.clone(),
        fixture.downstream.clone(),
        historical_proof,
    )
    .unwrap();
    assert_eq!(recovered.binding_digest(), binding.binding_digest());
    assert_eq!(recovered.hub_time_proof(), binding.hub_time_proof());
    assert_eq!(
        recovered.counterparty_time_proof(),
        binding.counterparty_time_proof()
    );

    // Fresh signed evidence changes the final V2 commitment even though the
    // settlement terms and their adaptor point remain byte-identical.
    let evidence_v2 = evidence(&fixture.policy, 2, EVIDENCE_TIME + 20, 1);
    store
        .install_evidence(
            &signed_evidence(&fixture, &evidence_v2),
            evidence_context,
            EVIDENCE_TIME + 20,
        )
        .unwrap();
    let refreshed_proof = store
        .prove_route_ladder(evidence_context, EVIDENCE_TIME + 20)
        .unwrap();
    let refreshed_proof = store
        .consume_capability_at(refreshed_proof, EVIDENCE_TIME + 20)
        .unwrap();
    let refreshed = ComposedBindingV2::bind(
        fixture.upstream.clone(),
        fixture.downstream.clone(),
        refreshed_proof,
    )
    .unwrap();
    assert_eq!(refreshed.evidence_sequence(), 2);
    assert_ne!(refreshed.binding_digest(), binding.binding_digest());

    // A capability for the original exact bytes cannot authorize even a
    // structurally valid metadata change in one settlement.
    let exact_proof = store
        .prove_route_ladder(evidence_context, EVIDENCE_TIME + 20)
        .unwrap();
    let exact_proof = store
        .consume_capability_at(exact_proof, EVIDENCE_TIME + 20)
        .unwrap();
    let mut different_upstream = fixture.upstream.clone();
    different_upstream.metadata.push(1);
    assert_eq!(
        ComposedBindingV2::bind(different_upstream, fixture.downstream.clone(), exact_proof,)
            .unwrap_err(),
        ComposerRefusal::TimeAnchorMismatch
    );
}
