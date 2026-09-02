//! DR-PRIV-001 Level 1, end to end through the V3 binding: per-leg
//! witnesses joined by the secret offset, the relation proof verified
//! against the recomputed `D`, per-leg reveals, witness translation, and
//! the cross-curve range authority — plus the adversarial refusals of
//! §3.2 (forged proof, equal leg points, wrong-leg reveal, wrong offset).

use adapter_evm::binding::adaptor_point_of_scalar;
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::*;
use route_composer::leg_blinding::{
    derive_leg_offset_v1, derive_leg_witness_v1, leg_witness_to_cross_curve_252,
    prove_offset_relation_v1, translate_witness_v1, ROLE_LEG_OFFSET_RELATION,
};
use route_composer::{ComposedBindingV3, ComposedLeg, ComposedWindowPolicyV1, ComposerRefusal};

fn b32(x: u8) -> [u8; 32] {
    [x; 32]
}

const ROUTE_SEED: [u8; 32] = [0x5e; 32];
const ROUTE_ID: [u8; 32] = [0x1d; 32];
/// Leg bytes in the derivation context: the DOWNSTREAM leg reveals first.
const LEG_DOWNSTREAM: u8 = 0;
const LEG_UPSTREAM: u8 = 1;

/// Valid V3 terms committed to this leg's OWN lock point. Same fixture
/// shape as the V1 adversarial suite: one hub chain with height
/// deadlines, per-settlement counterparty chains with seconds deadlines.
fn terms(
    settlement: u8,
    dom_deadline: u64,
    cp_deadline_seconds: u64,
    leg_point: [u8; 33],
) -> SettlementTermsV1 {
    SettlementTermsV1 {
        settlement_id: SettlementId(b32(settlement)),
        session_id: SessionId(b32(settlement.wrapping_add(1))),
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
            deadline: TimelockSpec::BlockHeight {
                value: dom_deadline,
            },
            finality: FinalityPolicyV1 {
                min_confirmations: 2,
                max_reorg_depth: 10,
            },
            adapter_profile_hash: b32(0xc3),
        },
        counterparty_leg: LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: ChainId(b32(0xd1 ^ settlement)),
            asset_id: AssetId(b32(0xd2)),
            amount: 7,
            beneficiary: ParticipantId(b32(0xb1)),
            refund_to: ParticipantId(b32(0xb2)),
            mechanism: LockMechanism::ConditionLock,
            deadline: TimelockSpec::TimestampSeconds {
                value: cp_deadline_seconds,
            },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 9,
            },
            adapter_profile_hash: b32(0xd3),
        },
        adaptor_point_sec1: leg_point,
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

fn margin() -> ComposedWindowPolicyV1 {
    ComposedWindowPolicyV1 {
        hub_margin: 100,
        counterparty_margin: 100,
    }
}

/// Derives the route's two witnesses and offset, and returns the good
/// V3 pair: upstream committed to `A_up = (w_dn + δ)·G`, downstream to
/// `A_dn = w_dn·G`.
fn good_pair() -> (SettlementTermsV1, SettlementTermsV1) {
    let w_dn = derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM).unwrap();
    let delta = derive_leg_offset_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
    let w_up = translate_witness_v1(&w_dn, &delta).unwrap();
    let a_dn = adaptor_point_of_scalar(w_dn.expose_big_endian()).unwrap();
    let a_up = adaptor_point_of_scalar(w_up.expose_big_endian()).unwrap();
    (terms(0xa0, 2000, 2100, a_up), terms(0xd0, 900, 1000, a_dn))
}

#[test]
fn full_level1_round_trip_binds_reveals_translates_and_unlinks() {
    let (up, dn) = good_pair();
    let delta = derive_leg_offset_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();

    // The proving endpoint binds δ into the exact digest the composition
    // will carry, then the composition admits the proof.
    let digest = ComposedBindingV3::binding_digest_for(&up, &dn, margin()).unwrap();
    let (_d, proof) = prove_offset_relation_v1(&delta, &digest).unwrap();
    let binding = ComposedBindingV3::bind(up.clone(), dn.clone(), margin(), proof.clone()).unwrap();
    assert_eq!(binding.binding_digest(), digest);
    let again = ComposedBindingV3::bind(up, dn, margin(), proof).unwrap();
    assert_eq!(
        binding.binding_digest(),
        again.binding_digest(),
        "digest is a function of the inputs"
    );

    // Downstream claim reveals ITS OWN witness; the composition verifies
    // it against the downstream lock point only.
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

    // The two on-chain artifacts of one route share no recognizable value:
    // scalars differ, lock points differ (T0 byte-equality linkage gone).
    assert_ne!(w_up.expose_big_endian(), revealed.expose_big_endian());
    assert_ne!(
        binding.upstream_lock_point_sec1(),
        binding.downstream_lock_point_sec1()
    );
}

#[test]
fn wrong_leg_out_of_range_and_wrong_scalar_reveals_refuse() {
    let (up, dn) = good_pair();
    let delta = derive_leg_offset_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
    let digest = ComposedBindingV3::binding_digest_for(&up, &dn, margin()).unwrap();
    let (_d, proof) = prove_offset_relation_v1(&delta, &digest).unwrap();
    let binding = ComposedBindingV3::bind(up, dn, margin(), proof).unwrap();

    let w_dn = derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM).unwrap();
    // The downstream witness does not open the UPSTREAM leg.
    assert_eq!(
        binding
            .verify_revealed_leg_scalar(ComposedLeg::Upstream, w_dn.expose_big_endian())
            .unwrap_err(),
        ComposerRefusal::WrongSecret
    );
    // A reveal outside the 252-bit cross-curve domain refuses even if it
    // is a fine secp scalar.
    let mut high = *w_dn.expose_big_endian();
    high[0] = 0x20;
    assert_eq!(
        binding
            .verify_revealed_leg_scalar(ComposedLeg::Downstream, &high)
            .unwrap_err(),
        ComposerRefusal::WrongSecret
    );
    // A perturbed scalar refuses.
    let mut wrong = *w_dn.expose_big_endian();
    wrong[31] ^= 1;
    assert_eq!(
        binding
            .verify_revealed_leg_scalar(ComposedLeg::Downstream, &wrong)
            .unwrap_err(),
        ComposerRefusal::WrongSecret
    );
}

#[test]
fn translation_with_the_wrong_offset_refuses_before_any_claim() {
    let (up, dn) = good_pair();
    let delta = derive_leg_offset_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
    let digest = ComposedBindingV3::binding_digest_for(&up, &dn, margin()).unwrap();
    let (_d, proof) = prove_offset_relation_v1(&delta, &digest).unwrap();
    let binding = ComposedBindingV3::bind(up, dn, margin(), proof).unwrap();

    let w_dn = derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM).unwrap();
    let revealed = binding
        .verify_revealed_leg_scalar(ComposedLeg::Downstream, w_dn.expose_big_endian())
        .unwrap();
    // An offset for a DIFFERENT route derives honestly but is not the
    // committed relation: the translated sum opens nothing here.
    let foreign =
        derive_leg_offset_v1(&ROUTE_SEED, &[0x77; 32], LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
    assert_eq!(
        binding
            .translate_revealed_downstream_witness(&revealed, &foreign)
            .unwrap_err(),
        ComposerRefusal::WitnessTranslationRefused
    );
}

#[test]
fn equal_leg_points_refuse_by_name() {
    let (up, _dn) = good_pair();
    let a_up = up.adaptor_point_sec1;
    let dn = terms(0xd0, 900, 1000, a_up);
    let delta = derive_leg_offset_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
    let (_d, proof) = prove_offset_relation_v1(&delta, &[0u8; 32]).unwrap();
    assert_eq!(
        ComposedBindingV3::bind(up.clone(), dn.clone(), margin(), proof).unwrap_err(),
        ComposerRefusal::EqualLegPoints
    );
    assert_eq!(
        ComposedBindingV3::binding_digest_for(&up, &dn, margin()).unwrap_err(),
        ComposerRefusal::EqualLegPoints
    );
}

#[test]
fn a_proof_for_another_offset_or_digest_refuses_the_bind() {
    let (up, dn) = good_pair();
    let digest = ComposedBindingV3::binding_digest_for(&up, &dn, margin()).unwrap();

    // Right δ, wrong digest: the challenge does not bind this route.
    let delta = derive_leg_offset_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
    let (_d, wrong_digest_proof) = prove_offset_relation_v1(&delta, &[0x99; 32]).unwrap();
    assert_eq!(
        ComposedBindingV3::bind(up.clone(), dn.clone(), margin(), wrong_digest_proof).unwrap_err(),
        ComposerRefusal::RelationProofRefused
    );

    // Wrong δ, right digest: D recomputed from the committed points does
    // not match the proven point.
    let foreign =
        derive_leg_offset_v1(&ROUTE_SEED, &[0x77; 32], LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
    let (_d, foreign_proof) = prove_offset_relation_v1(&foreign, &digest).unwrap();
    assert_eq!(
        ComposedBindingV3::bind(up.clone(), dn.clone(), margin(), foreign_proof).unwrap_err(),
        ComposerRefusal::RelationProofRefused
    );

    // Right δ, right digest, tampered response byte.
    let (_d, mut proof) = prove_offset_relation_v1(&delta, &digest).unwrap();
    proof.response[31] ^= 1;
    assert_eq!(
        ComposedBindingV3::bind(up, dn, margin(), proof).unwrap_err(),
        ComposerRefusal::RelationProofRefused
    );
}

#[test]
fn translated_witnesses_pass_the_cross_curve_range_authority() {
    // Both per-leg witnesses feed the EXISTING cross-curve machinery
    // unchanged: `from_little_endian` is the range authority, and roles
    // 1–3 keep proving each leg's own witness. Role byte 4 is drawn from
    // the closed registry, not minted locally.
    let w_dn = derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM).unwrap();
    let delta = derive_leg_offset_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
    let w_up = translate_witness_v1(&w_dn, &delta).unwrap();
    for witness in [&w_dn, &w_up] {
        let le = leg_witness_to_cross_curve_252(witness);
        let secret = xmr_dleq_sigma::CrossCurveSecret252::from_little_endian(*le)
            .expect("leg witness is a canonical 252-bit cross-curve secret");
        assert_eq!(
            &secret.dom_secret_big_endian(),
            witness.expose_big_endian(),
            "big-endian spelling matches the tree convention"
        );
    }
    assert_eq!(
        ROLE_LEG_OFFSET_RELATION,
        xmr_dleq_sigma::ROLE_LEG_OFFSET_RELATION,
        "role byte 4 is the registry's, not a local mint"
    );
}
