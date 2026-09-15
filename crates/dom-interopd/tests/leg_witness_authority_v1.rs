//! The daemon's Level-1 leg-witness authority (§7.4 seam) against a REAL
//! admitted V3 composition: the downstream reveal is verified against the
//! downstream lock point, δ is derived locally from the provisioned seed,
//! and the translation opens the upstream lock point — while every wrong
//! input (foreign scalar, foreign seed, degenerate scope) refuses by name.

#[path = "../../route-time-anchor/tests/common/mod.rs"]
mod time_common;

use std::fs;
use std::rc::Rc;

use adapter_evm::binding::adaptor_point_of_scalar;
use dom_interopd::{
    LegWitnessAuthorityRefusalV1, RouteLegWitnessAuthorityV1, LEG_BLINDING_DOWNSTREAM_LEG_BYTE_V1,
    LEG_BLINDING_UPSTREAM_LEG_BYTE_V1,
};
use route_composer::leg_blinding::{
    derive_leg_offset_v1, derive_leg_witness_v1, prove_offset_relation_v1, translate_witness_v1,
};
use route_composer::{ComposedBindingV3, ComposedLeg};
use route_time_anchor::{
    DurableRouteTimeAnchorStoreV2, RouteTimeAnchorStoreConfigV2, RouteTimePolicyV2,
};
use zeroize::Zeroizing;

use time_common::{evidence, fixture, limits, signed_evidence, signed_policy, EVIDENCE_TIME};

const ROUTE_SEED: [u8; 32] = [0x7c; 32];
const ROUTE_ID: [u8; 32] = [0x3f; 32];

/// Admits one blinded V3 composition for the derivation scope above.
fn admitted_binding() -> Rc<ComposedBindingV3> {
    let w_dn =
        derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID, LEG_BLINDING_DOWNSTREAM_LEG_BYTE_V1).unwrap();
    let delta = derive_leg_offset_v1(
        &ROUTE_SEED,
        &ROUTE_ID,
        LEG_BLINDING_DOWNSTREAM_LEG_BYTE_V1,
        LEG_BLINDING_UPSTREAM_LEG_BYTE_V1,
    )
    .unwrap();
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
    let path = directory.path().join("leg-witness-authority-time.sqlite");
    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let mut store = DurableRouteTimeAnchorStoreV2::create(&path, config).unwrap();
    store
        .install_policy(
            &signed_policy(&fixture),
            fixture.policy_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let evidence_v1 = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    store
        .install_evidence(
            &signed_evidence(&fixture, &evidence_v1),
            fixture.evidence_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let proof = store
        .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();
    store.revalidate_capability(&proof).unwrap();
    let time_proof = store.consume_capability_at(proof, EVIDENCE_TIME).unwrap();
    let preimage = ComposedBindingV3::binding_digest_preimage_for(
        &fixture.upstream,
        &fixture.downstream,
        &time_proof,
    )
    .unwrap();
    let (_d, relation_proof) = prove_offset_relation_v1(&delta, &preimage).unwrap();
    Rc::new(
        ComposedBindingV3::bind(
            fixture.upstream.clone(),
            fixture.downstream.clone(),
            time_proof,
            relation_proof,
        )
        .unwrap(),
    )
}

#[test]
fn the_authority_translates_a_downstream_reveal_into_the_upstream_witness() {
    let binding = admitted_binding();
    let authority =
        RouteLegWitnessAuthorityV1::new(ROUTE_ID, Rc::clone(&binding), Zeroizing::new(ROUTE_SEED))
            .unwrap();

    let w_dn =
        derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID, LEG_BLINDING_DOWNSTREAM_LEG_BYTE_V1).unwrap();
    let w_up = authority
        .translate_downstream_exposure(w_dn.expose_big_endian())
        .unwrap();

    // The result is exactly the upstream leg's witness: it verifies as an
    // upstream reveal and differs from the downstream one.
    binding
        .verify_revealed_leg_scalar(ComposedLeg::Upstream, w_up.expose_big_endian())
        .unwrap();
    assert_ne!(w_up.expose_big_endian(), w_dn.expose_big_endian());

    // The authority never echoes secret material.
    assert_eq!(
        format!("{authority:?}"),
        "RouteLegWitnessAuthorityV1([redacted])"
    );
}

#[test]
fn foreign_scalars_seeds_and_degenerate_scope_refuse_by_name() {
    let binding = admitted_binding();

    // Degenerate scope refuses at construction.
    assert_eq!(
        RouteLegWitnessAuthorityV1::new([0u8; 32], Rc::clone(&binding), Zeroizing::new(ROUTE_SEED))
            .unwrap_err(),
        LegWitnessAuthorityRefusalV1::InvalidScope
    );
    assert_eq!(
        RouteLegWitnessAuthorityV1::new(ROUTE_ID, Rc::clone(&binding), Zeroizing::new([0u8; 32]))
            .unwrap_err(),
        LegWitnessAuthorityRefusalV1::InvalidScope
    );

    let authority =
        RouteLegWitnessAuthorityV1::new(ROUTE_ID, Rc::clone(&binding), Zeroizing::new(ROUTE_SEED))
            .unwrap();
    let w_dn =
        derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID, LEG_BLINDING_DOWNSTREAM_LEG_BYTE_V1).unwrap();

    // A scalar that does not open the downstream leg refuses first.
    let mut wrong = *w_dn.expose_big_endian();
    wrong[31] ^= 1;
    assert_eq!(
        authority.translate_downstream_exposure(&wrong).unwrap_err(),
        LegWitnessAuthorityRefusalV1::WrongLegScalar
    );

    // A foreign seed derives an offset the binding never committed to:
    // the translation refuses before any claim path sees the sum.
    let foreign = RouteLegWitnessAuthorityV1::new(
        ROUTE_ID,
        Rc::clone(&binding),
        Zeroizing::new([0x55u8; 32]),
    )
    .unwrap();
    assert_eq!(
        foreign
            .translate_downstream_exposure(w_dn.expose_big_endian())
            .unwrap_err(),
        LegWitnessAuthorityRefusalV1::TranslationRefused
    );
}
