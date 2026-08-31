//! Production admission of a mixed-clock composition through the V2 authority.

#[path = "../../route-time-anchor/tests/common/mod.rs"]
mod time_common;

use std::fs;

use btc_crypto::SecpContext;
use deployment_registry::{
    AuthoritySetV1, RegistrySignatureV1, RegistryStoreV1, RegistryValidationPolicyV1,
    SignedRegistryV1,
};
use dom_interopd::{
    RegistryRouteAdmissionAuthorityV1, RouteAdmissionRefusalV1, RouteRosterSnapshotsV1,
};
use route_composer::ComposedBindingV2;
use route_executor::{FrozenRouteAdmissionCheckpointV2, FrozenRouteTimeFactsV2};
use route_time_anchor::{DurableRouteTimeAnchorStoreV2, RouteTimeAnchorStoreConfigV2};

use time_common::{evidence, fixture, signed_evidence, signed_policy, EVIDENCE_TIME};

const REGISTRY_SECRETS: [[u8; 32]; 3] = [[0x03; 32], [0x04; 32], [0x05; 32]];

fn registry_authority(fixture: &time_common::Fixture) -> (AuthoritySetV1, SignedRegistryV1) {
    let digest = fixture.registry.manifest().manifest_digest().unwrap();
    let keys = REGISTRY_SECRETS
        .iter()
        .enumerate()
        .map(|(index, secret)| {
            fixture
                .secp
                .sign_bip340(secret, &[0x41; 32], &[0x42 + index as u8; 32])
                .unwrap()
                .1
        })
        .collect();
    let signatures = REGISTRY_SECRETS
        .iter()
        .enumerate()
        .map(|(index, secret)| {
            let (signature, _) = fixture
                .secp
                .sign_bip340(secret, &digest, &[0x50 + index as u8; 32])
                .unwrap();
            RegistrySignatureV1 {
                signer_index: index as u16,
                signature,
            }
        })
        .collect();
    (
        AuthoritySetV1::new(2, keys).unwrap(),
        SignedRegistryV1::new(fixture.registry.manifest(), signatures).unwrap(),
    )
}

#[test]
fn v2_admission_freezes_current_time_proof_and_refuses_expiry() {
    let fixture = fixture();
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }

    let (registry_authorities, signed_registry) = registry_authority(&fixture);
    let registry_authority_set_digest = registry_authorities.authority_set_digest().unwrap();
    let registry_path = directory.path().join("registry.sqlite3");
    let mut registry_store = RegistryStoreV1::create(&registry_path).unwrap();
    registry_store
        .install(
            &signed_registry,
            &registry_authorities,
            &fixture.secp,
            RegistryValidationPolicyV1 {
                now_seconds: EVIDENCE_TIME,
                expected_network_id: time_common::REGISTRY_NETWORK,
                minimum_epoch: 7,
            },
        )
        .unwrap();
    let admission_authority = RegistryRouteAdmissionAuthorityV1::new(
        registry_store,
        registry_authorities,
        SecpContext::new(&[0x7a; 32]),
        time_common::REGISTRY_NETWORK,
        7,
    )
    .unwrap();

    let time_config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let time_path = directory.path().join("route-time.sqlite3");
    let mut time_store = DurableRouteTimeAnchorStoreV2::create(&time_path, time_config).unwrap();
    time_store
        .install_policy(
            &signed_policy(&fixture),
            fixture.policy_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let time_evidence = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    time_store
        .install_evidence(
            &signed_evidence(&fixture, &time_evidence),
            fixture.evidence_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let proof = time_store
        .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();
    let current = time_store
        .consume_capability_at(proof, EVIDENCE_TIME)
        .unwrap();
    let composition = ComposedBindingV2::bind(
        fixture.upstream.clone(),
        fixture.downstream.clone(),
        current,
    )
    .unwrap();
    let route_id = [0xa7; 32];
    let rosters = RouteRosterSnapshotsV1 {
        upstream: [0xa8; 32],
        downstream: [0xa9; 32],
    };
    let admission = admission_authority
        .admit_validated_composed_route_v2(EVIDENCE_TIME, route_id, &composition, rosters)
        .unwrap();
    let time_binding = admission.route_time_binding_v2().unwrap();
    assert_eq!(
        time_binding.route_scope_digest(),
        composition.route_scope_digest()
    );
    assert_eq!(
        time_binding.policy_digest(),
        composition.time_policy_digest()
    );
    assert_eq!(
        time_binding.evidence_digest(),
        composition.time_evidence_digest()
    );
    assert_eq!(time_binding.proof_digest(), composition.time_proof_digest());
    assert_eq!(time_binding.evidence_sequence(), 1);
    assert_eq!(time_binding.issued_at_seconds(), EVIDENCE_TIME);
    assert_eq!(
        time_binding.valid_until_seconds(),
        composition.time_proof_valid_until_seconds()
    );
    assert_eq!(time_binding.validated_at_seconds(), EVIDENCE_TIME);

    let checkpoint = FrozenRouteAdmissionCheckpointV2 {
        network_id: time_common::REGISTRY_NETWORK,
        route_id,
        bindings: admission.frozen_bindings().clone(),
        composition_v2_digest: composition.binding_digest(),
        registry_epoch: admission.registry_epoch(),
        registry_manifest_digest: admission.registry_digest(),
        upstream_terms_digest: composition.upstream().terms_hash().unwrap(),
        downstream_terms_digest: composition.downstream().terms_hash().unwrap(),
        upstream_roster_snapshot: rosters.upstream,
        downstream_roster_snapshot: rosters.downstream,
        participant_bindings_digest: [0xaa; 32],
        relay_binding_digest: [0xab; 32],
        registry_authority_set_digest,
        time_policy_authority_set_digest: fixture
            .policy_authorities
            .authority_set_digest()
            .unwrap(),
        time_evidence_authority_set_digest: fixture
            .evidence_authorities
            .authority_set_digest()
            .unwrap(),
        time: FrozenRouteTimeFactsV2 {
            route_scope_digest: time_binding.route_scope_digest(),
            policy_digest: time_binding.policy_digest(),
            evidence_digest: time_binding.evidence_digest(),
            proof_digest: time_binding.proof_digest(),
            evidence_sequence: time_binding.evidence_sequence(),
            issued_at_seconds: time_binding.issued_at_seconds(),
            valid_until_seconds: time_binding.valid_until_seconds(),
            validated_at_seconds: time_binding.validated_at_seconds(),
        },
    };

    let recovered = admission_authority
        .recover_validated_composed_route_v2(route_id, &composition, &checkpoint)
        .unwrap();
    assert_eq!(recovered.frozen_bindings(), admission.frozen_bindings());
    assert_eq!(recovered.route_time_binding_v2(), Some(time_binding));

    let expiry = composition.time_proof_valid_until_seconds();
    assert!(matches!(
        admission_authority.admit_validated_composed_route_v2(
            expiry,
            route_id,
            &composition,
            rosters,
        ),
        Err(RouteAdmissionRefusalV1::TimeCapabilityNotCurrent)
    ));
    let recovered_after_expiry = admission_authority
        .recover_validated_composed_route_v2(route_id, &composition, &checkpoint)
        .unwrap();
    assert_eq!(
        recovered_after_expiry.route_time_binding_v2(),
        Some(time_binding)
    );

    let mut tampered = checkpoint.clone();
    tampered.time.proof_digest = [0xbc; 32];
    assert!(matches!(
        admission_authority.recover_validated_composed_route_v2(route_id, &composition, &tampered,),
        Err(RouteAdmissionRefusalV1::PinnedBindingMismatch)
    ));
}
