//! Level 1 (per-leg witness blinding) end to end through the V3 binding:
//! per-leg lock points admitted under the authenticated V2 time
//! capability, the relation proof verified against the recomputed `D`
//! and the digest preimage, per-leg reveals, witness translation, the
//! observer harness (L1-T8) and the cross-curve range/DLEQ authorities
//! (L1-T9) — plus the L1-T6 bind refusals by name.

#[path = "../../route-time-anchor/tests/common/mod.rs"]
mod time_common;

use std::fs;

use adapter_evm::binding::adaptor_point_of_scalar;
use route_composer::leg_blinding::{
    derive_leg_offset_v1, derive_leg_witness_v1, leg_witness_to_cross_curve_252,
    prove_offset_relation_v1, translate_witness_v1, LegOffsetV1, ROLE_LEG_OFFSET_RELATION,
};
use route_composer::{ComposedBindingV3, ComposedLeg, ComposerRefusal};
use route_time_anchor::{
    DurableRouteTimeAnchorStoreV2, FrozenRouteTimeCheckpointV2, FrozenRouteTimeProofCheckpointV2,
    RouteTimeAnchorStoreConfigV2, RouteTimePolicyV2,
};

use time_common::{evidence, fixture, limits, signed_evidence, signed_policy, EVIDENCE_TIME};

const ROUTE_SEED: [u8; 32] = [0x5e; 32];
const ROUTE_ID: [u8; 32] = [0x1d; 32];
/// Leg bytes in the derivation context: the DOWNSTREAM leg reveals first.
const LEG_DOWNSTREAM: u8 = 0;
const LEG_UPSTREAM: u8 = 1;

fn store_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = directory
        .path()
        .join("route-composer-v3-leg-blinding.sqlite");
    (directory, path)
}

/// The route's derived secret material and the fixture whose terms
/// commit the two per-leg lock points `A_up = (w_dn + δ)·G` and
/// `A_dn = w_dn·G`, with the time policy rebuilt over the mutated terms
/// (the policy binds the exact terms hashes).
fn blinded_fixture() -> (time_common::Fixture, LegOffsetV1) {
    let w_dn = derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM).unwrap();
    let delta = derive_leg_offset_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
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
    (fixture, delta)
}

/// Opens a durable time-anchor store for the fixture and installs one
/// signed policy and one signed evidence row, ready to mint capabilities.
fn armed_store(
    fixture: &time_common::Fixture,
    path: &std::path::Path,
) -> DurableRouteTimeAnchorStoreV2 {
    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let mut store = DurableRouteTimeAnchorStoreV2::create(path, config).unwrap();
    store
        .install_policy(
            &signed_policy(fixture),
            fixture.policy_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let evidence_v1 = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    store
        .install_evidence(
            &signed_evidence(fixture, &evidence_v1),
            fixture.evidence_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    store
}

/// Mints one consumable time capability from an armed store. The
/// capability mutably borrows the store (exclusive authority) until a
/// bind consumes it.
fn capability<'authority>(
    store: &'authority mut DurableRouteTimeAnchorStoreV2,
    fixture: &time_common::Fixture,
) -> route_time_anchor::CurrentRouteTimeLadderV2<'authority> {
    let proof = store
        .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();
    store.revalidate_capability(&proof).unwrap();
    store.consume_capability_at(proof, EVIDENCE_TIME).unwrap()
}

#[test]
fn full_level1_round_trip_binds_reveals_translates_and_unlinks() {
    let (fixture, delta) = blinded_fixture();
    let (_directory, path) = store_path();
    let mut store = armed_store(&fixture, &path);

    // The endpoint that knows δ binds it into the digest PREIMAGE, then
    // the composition admits the proof and commits it into the final
    // digest (§7.1/§7.2).
    let time_proof = capability(&mut store, &fixture);
    let preimage = ComposedBindingV3::binding_digest_preimage_for(
        &fixture.upstream,
        &fixture.downstream,
        &time_proof,
    )
    .unwrap();
    let (_d, proof) = prove_offset_relation_v1(&delta, &preimage).unwrap();
    let binding = ComposedBindingV3::bind(
        fixture.upstream.clone(),
        fixture.downstream.clone(),
        time_proof,
        proof.clone(),
    )
    .unwrap();
    assert_eq!(binding.binding_digest_preimage(), preimage);
    assert_ne!(
        binding.binding_digest(),
        binding.binding_digest_preimage(),
        "the final digest additionally commits the 97-byte proof"
    );
    assert_eq!(binding.evidence_sequence(), 1);

    // Recovery rebuilds the exact same binding through the frozen-proof
    // path — one shared invariant and digest implementation (V2 regime).
    let frozen = FrozenRouteTimeProofCheckpointV2::new(
        FrozenRouteTimeCheckpointV2::new(
            binding.route_scope_digest(),
            binding.time_policy_digest(),
            binding.time_evidence_digest(),
            binding.evidence_sequence(),
        )
        .unwrap(),
        binding.time_proof_digest(),
        binding.time_proof_issued_at_seconds(),
        binding.time_proof_valid_until_seconds(),
        binding.time_proof_validated_at_seconds(),
    )
    .unwrap();
    let evidence_v1 = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    let historical = store
        .verify_frozen_route_ladder(
            frozen,
            &signed_policy(&fixture),
            &signed_evidence(&fixture, &evidence_v1),
            fixture.evidence_context(),
        )
        .unwrap();
    let recovered = ComposedBindingV3::bind_recovered(
        fixture.upstream.clone(),
        fixture.downstream.clone(),
        historical,
        proof,
    )
    .unwrap();
    assert_eq!(recovered.binding_digest(), binding.binding_digest());

    // Downstream claim reveals ITS OWN witness; verified against the
    // downstream lock point only.
    let w_dn = derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM).unwrap();
    let revealed = binding
        .verify_revealed_leg_scalar(ComposedLeg::Downstream, w_dn.expose_big_endian())
        .unwrap();

    // Translation with the route's δ produces the upstream witness, which
    // opens the upstream lock point and verifies as an upstream reveal.
    let w_up = binding
        .translate_revealed_downstream_witness(&revealed, &delta)
        .unwrap();
    binding
        .verify_revealed_leg_scalar(ComposedLeg::Upstream, w_up.expose_big_endian())
        .unwrap();

    // The two on-chain artifacts of one route share no recognizable
    // value: scalars differ, lock points differ (T0 linkage gone).
    assert_ne!(w_up.expose_big_endian(), revealed.expose_big_endian());
    assert_ne!(
        binding.upstream_lock_point_sec1(),
        binding.downstream_lock_point_sec1()
    );

    // Wrong-leg, out-of-range and perturbed reveals refuse by name.
    assert_eq!(
        binding
            .verify_revealed_leg_scalar(ComposedLeg::Upstream, w_dn.expose_big_endian())
            .unwrap_err(),
        ComposerRefusal::WrongSecret
    );
    let mut high = *w_dn.expose_big_endian();
    high[0] = 0x20; // outside the 252-bit cross-curve domain
    assert_eq!(
        binding
            .verify_revealed_leg_scalar(ComposedLeg::Downstream, &high)
            .unwrap_err(),
        ComposerRefusal::WrongSecret
    );
    let mut wrong = *w_dn.expose_big_endian();
    wrong[31] ^= 1;
    assert_eq!(
        binding
            .verify_revealed_leg_scalar(ComposedLeg::Downstream, &wrong)
            .unwrap_err(),
        ComposerRefusal::WrongSecret
    );

    // A different route's honestly derived offset is not the committed
    // relation: the translated sum opens nothing here.
    let foreign =
        derive_leg_offset_v1(&ROUTE_SEED, &[0x77; 32], LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
    assert_eq!(
        binding
            .translate_revealed_downstream_witness(&revealed, &foreign)
            .unwrap_err(),
        ComposerRefusal::WitnessTranslationRefused
    );
    assert!(binding.composed_treasury_share().unwrap() > 0);
}

/// L1-T6: every bind refusal by name, in the §7.2 order — the per-leg
/// point gate fires before anything else, a proof for another offset or
/// digest refuses, and a terms byte not covered by the time capability
/// refuses AFTER the proof (with a proof honestly minted for the
/// tampered preimage, isolating the V2 precondition).
#[test]
fn v3_bind_refusals_by_name() {
    let (fixture, delta) = blinded_fixture();
    let (_directory, path) = store_path();
    let mut store = armed_store(&fixture, &path);

    // Equal leg points refuse FIRST (I8), before the time machinery.
    let time_proof = capability(&mut store, &fixture);
    let mut equal_downstream = fixture.downstream.clone();
    equal_downstream.adaptor_point_sec1 = fixture.upstream.adaptor_point_sec1;
    let (_d, any_proof) = prove_offset_relation_v1(&delta, &[0u8; 32]).unwrap();
    assert_eq!(
        ComposedBindingV3::bind(
            fixture.upstream.clone(),
            equal_downstream,
            time_proof,
            any_proof,
        )
        .unwrap_err(),
        ComposerRefusal::EqualLegPoints
    );

    // A proof for a foreign offset refuses: D recomputed from the
    // committed points does not match the proven point.
    let time_proof = capability(&mut store, &fixture);
    let preimage = ComposedBindingV3::binding_digest_preimage_for(
        &fixture.upstream,
        &fixture.downstream,
        &time_proof,
    )
    .unwrap();
    let foreign =
        derive_leg_offset_v1(&ROUTE_SEED, &[0x77; 32], LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
    let (_d, foreign_proof) = prove_offset_relation_v1(&foreign, &preimage).unwrap();
    assert_eq!(
        ComposedBindingV3::bind(
            fixture.upstream.clone(),
            fixture.downstream.clone(),
            time_proof,
            foreign_proof,
        )
        .unwrap_err(),
        ComposerRefusal::RelationProofRefused
    );

    // A tampered response byte refuses.
    let time_proof = capability(&mut store, &fixture);
    let (_d, mut tampered) = prove_offset_relation_v1(&delta, &preimage).unwrap();
    tampered.response[31] ^= 1;
    assert_eq!(
        ComposedBindingV3::bind(
            fixture.upstream.clone(),
            fixture.downstream.clone(),
            time_proof,
            tampered,
        )
        .unwrap_err(),
        ComposerRefusal::RelationProofRefused
    );

    // A proof bound to some other digest refuses.
    let time_proof = capability(&mut store, &fixture);
    let (_d, wrong_digest_proof) = prove_offset_relation_v1(&delta, &[0x99; 32]).unwrap();
    assert_eq!(
        ComposedBindingV3::bind(
            fixture.upstream.clone(),
            fixture.downstream.clone(),
            time_proof,
            wrong_digest_proof,
        )
        .unwrap_err(),
        ComposerRefusal::RelationProofRefused
    );

    // A terms byte the capability never covered refuses at the V2
    // precondition — the relation proof is minted honestly for the
    // tampered preimage so the refusal isolates TimeAnchorMismatch.
    let time_proof = capability(&mut store, &fixture);
    let mut different_upstream = fixture.upstream.clone();
    different_upstream.metadata.push(1);
    let tampered_preimage = ComposedBindingV3::binding_digest_preimage_for(
        &different_upstream,
        &fixture.downstream,
        &time_proof,
    )
    .unwrap();
    let (_d, tampered_terms_proof) = prove_offset_relation_v1(&delta, &tampered_preimage).unwrap();
    assert_eq!(
        ComposedBindingV3::bind(
            different_upstream,
            fixture.downstream.clone(),
            time_proof,
            tampered_terms_proof,
        )
        .unwrap_err(),
        ComposerRefusal::TimeAnchorMismatch
    );
}

/// L1-T8: the observer harness. Given both legs' public artifacts of a
/// shuffled batch of ≥16 routes, minus every `δ`, the linkers available
/// to a T0 observer do not recover the pairing: byte equality finds
/// nothing, and the strongest generic arithmetic linker (the range test
/// on candidate differences — the recorded I9 skew) never narrows any
/// upstream reveal to a unique downstream candidate.
#[test]
fn observer_cannot_match_legs_across_a_shuffled_batch() {
    const BATCH: usize = 16;
    let mut upstream_reveals = Vec::new();
    let mut downstream_reveals = Vec::new();
    for index in 0..BATCH {
        let mut route_id = [0u8; 32];
        route_id[0] = index as u8;
        route_id[31] = 0xa7;
        let w_dn = derive_leg_witness_v1(&ROUTE_SEED, &route_id, LEG_DOWNSTREAM).unwrap();
        let delta =
            derive_leg_offset_v1(&ROUTE_SEED, &route_id, LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
        let w_up = translate_witness_v1(&w_dn, &delta).unwrap();
        upstream_reveals.push(*w_up.expose_big_endian());
        downstream_reveals.push(*w_dn.expose_big_endian());
    }

    // Linker 1 — byte equality (the pre-V3 attack): zero matches.
    for up in &upstream_reveals {
        assert!(!downstream_reveals.contains(up), "byte-equality relinks");
    }
    // Linker 2 — point equality: zero matches.
    for up in &upstream_reveals {
        let up_point = adaptor_point_of_scalar(up).unwrap();
        for dn in &downstream_reveals {
            assert_ne!(up_point, adaptor_point_of_scalar(dn).unwrap());
        }
    }
    // Linker 3 — the range test: candidate (up, dn) is "plausible" when
    // 0 < up − dn < 2^251 over the integers. The true pair always
    // qualifies; unlinkability holds because it never qualifies alone.
    let plausible = |up: &[u8; 32], dn: &[u8; 32]| -> bool {
        let mut borrow = 0i16;
        let mut difference = [0u8; 32];
        for i in (0..32).rev() {
            let value = i16::from(up[i]) - i16::from(dn[i]) - borrow;
            difference[i] = (value & 0xff) as u8;
            borrow = i16::from(value < 0);
        }
        borrow == 0 && difference != [0u8; 32] && difference[0] < 0x08
    };
    for (index, up) in upstream_reveals.iter().enumerate() {
        let candidates = downstream_reveals
            .iter()
            .filter(|dn| plausible(up, dn))
            .count();
        assert!(
            plausible(up, &downstream_reveals[index]),
            "the true pair must always be range-plausible"
        );
        assert!(
            candidates > 1,
            "upstream reveal {index} narrowed to a unique candidate"
        );
    }
}

/// L1-T9 (composer half): blinded witnesses feed the EXISTING
/// cross-curve machinery unchanged — `from_little_endian` is the range
/// authority, and the role-bound DLEQ proves each leg's own witness for
/// roles 1 and 3 exactly as today. Role byte 4 comes from the closed
/// registry, never minted locally.
#[test]
fn translated_witnesses_pass_the_cross_curve_range_authority_and_dleq_roles() {
    let w_dn = derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM).unwrap();
    let delta = derive_leg_offset_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
    let w_up = translate_witness_v1(&w_dn, &delta).unwrap();
    let mut rng = rand::thread_rng();
    for (witness, role) in [
        (&w_dn, xmr_dleq_sigma::ROLE_XMR_SHARED_SPEND),
        (&w_up, xmr_dleq_sigma::ROLE_SOLANA_CONDITION_LOCK),
    ] {
        let little_endian = leg_witness_to_cross_curve_252(witness);
        let secret = xmr_dleq_sigma::CrossCurveSecret252::from_little_endian(*little_endian)
            .expect("leg witness is a canonical 252-bit cross-curve secret");
        assert_eq!(
            &secret.dom_secret_big_endian(),
            witness.expose_big_endian(),
            "big-endian spelling matches the tree convention"
        );
        let bound = xmr_dleq_sigma::prove_bound(&secret, [1; 32], [2; 32], role, &mut rng).unwrap();
        let claim = xmr_dleq_sigma::verify_bound(&bound, &[1; 32], &[2; 32], role).unwrap();
        assert_eq!(
            xmr_dleq_sigma::revealed_dom_secret_to_xmr_scalar(
                secret.dom_secret_big_endian(),
                &claim
            )
            .unwrap(),
            secret.xmr_share_little_endian(),
        );
    }
    assert_eq!(
        ROLE_LEG_OFFSET_RELATION, 4,
        "role byte 4 is the registry's reserved value"
    );
}
