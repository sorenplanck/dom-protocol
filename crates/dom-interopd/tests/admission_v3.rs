//! Production admission of a Level-1 BLINDED composition (per-leg lock
//! points) through the V3 path: same registry authentication and frozen
//! public time checkpoint as V2 admission, over a composition whose legs
//! commit different points joined by the offset-relation proof.

#[path = "../../route-time-anchor/tests/common/mod.rs"]
mod time_common;

use std::fs;

use adapter_evm::binding::adaptor_point_of_scalar;
use btc_crypto::SecpContext;
use deployment_registry::{
    AuthoritySetV1, RegistrySignatureV1, RegistryStoreV1, RegistryValidationPolicyV1,
    SignedRegistryV1,
};
use dom_interopd::{
    RegistryRouteAdmissionAuthorityV1, RouteAdmissionRefusalV1, RouteRosterSnapshotsV1,
};
use route_composer::leg_blinding::{
    derive_leg_offset_v1, derive_leg_witness_v1, prove_offset_relation_v1, translate_witness_v1,
};
use route_composer::ComposedBindingV3;
use route_time_anchor::{
    DurableRouteTimeAnchorStoreV2, RouteTimeAnchorStoreConfigV2, RouteTimePolicyV2,
};

use time_common::{evidence, fixture, limits, signed_evidence, signed_policy, EVIDENCE_TIME};

const REGISTRY_SECRETS: [[u8; 32]; 3] = [[0x03; 32], [0x04; 32], [0x05; 32]];
const ROUTE_SEED: [u8; 32] = [0x4d; 32];
const ROUTE_ID_DERIVE: [u8; 32] = [0x5a; 32];

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
fn v3_admission_freezes_current_time_proof_and_refuses_expiry() {
    // The blinded terms: each leg commits its OWN lock point.
    let w_dn = derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID_DERIVE, 0).unwrap();
    let delta = derive_leg_offset_v1(&ROUTE_SEED, &ROUTE_ID_DERIVE, 0, 1).unwrap();
    let w_up = translate_witness_v1(&w_dn, &delta).unwrap();
    let mut fixture = fixture();
    fixture.upstream.adaptor_point_sec1 =
        adaptor_point_of_scalar(w_up.expose_big_endian()).unwrap();
    fixture.downstream.adaptor_point_sec1 =
        adaptor_point_of_scalar(w_dn.expose_big_endian()).unwrap();
    fixture.policy = RouteTimePolicyV2::from_registry(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        limits(),
    )
    .unwrap();

    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }

    let (registry_authorities, signed_registry) = registry_authority(&fixture);
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
    let preimage = ComposedBindingV3::binding_digest_preimage_for(
        &fixture.upstream,
        &fixture.downstream,
        &current,
    )
    .unwrap();
    let (_d, relation_proof) = prove_offset_relation_v1(&delta, &preimage).unwrap();
    let composition = ComposedBindingV3::bind(
        fixture.upstream.clone(),
        fixture.downstream.clone(),
        current,
        relation_proof,
    )
    .unwrap();

    let route_id = [0xb7; 32];
    let rosters = RouteRosterSnapshotsV1 {
        upstream: [0xb8; 32],
        downstream: [0xb9; 32],
    };
    let admission = admission_authority
        .admit_validated_composed_route_v3(EVIDENCE_TIME, route_id, &composition, rosters)
        .unwrap();

    // The frozen public time checkpoint is the composition's own.
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
    assert_eq!(time_binding.validated_at_seconds(), EVIDENCE_TIME);

    // An expired capability refuses new admission exactly as in V2.
    let expiry = composition.time_proof_valid_until_seconds();
    assert!(matches!(
        admission_authority.admit_validated_composed_route_v3(
            expiry,
            route_id,
            &composition,
            rosters,
        ),
        Err(RouteAdmissionRefusalV1::TimeCapabilityNotCurrent)
    ));

    // Degenerate roster snapshots refuse.
    assert!(matches!(
        admission_authority.admit_validated_composed_route_v3(
            EVIDENCE_TIME,
            route_id,
            &composition,
            RouteRosterSnapshotsV1 {
                upstream: [0; 32],
                downstream: [0xb9; 32],
            },
        ),
        Err(RouteAdmissionRefusalV1::InvalidRequest)
    ));
}
