//! Adversarial suite of the composed binding: every named refusal is
//! provoked and asserted BY NAME, and the happy path is checked for
//! digest determinism and scalar hand-off correctness.
//!
//! Clock discipline under test (audit findings F1/F2/F3): the hub rung
//! compares DOM-leg deadlines on ONE hub chain; the counterparty rung
//! compares seconds, or heights only on one shared chain; the digest
//! length-prefixes both encodings; T must decode to a curve point.

use adapter_evm::binding::adaptor_point_of_scalar;
use kaystra_core::state::SettlementState;
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::*;
use route_composer::{
    authorize_funding, ComposedBindingV1, ComposedLeg, ComposedWindowPolicyV1, ComposerRefusal,
};

fn b32(x: u8) -> [u8; 32] {
    [x; 32]
}

/// A canonical route scalar in `1..n-1` (same shape as the level-2 proof).
fn route_scalar() -> [u8; 32] {
    let mut t = [0u8; 32];
    for (i, byte) in t.iter_mut().enumerate() {
        *byte = (0x11 + i as u8) | 0x01;
    }
    t[0] = 0x2b;
    t
}

fn t_point() -> [u8; 33] {
    adaptor_point_of_scalar(&route_scalar()).expect("canonical scalar")
}

/// Valid terms committed to `t33`. The DOM leg sits on the single hub
/// chain with a height deadline (the engine's clock); the counterparty
/// leg sits on a per-settlement chain with a SECONDS deadline (the clock
/// every chain shares).
fn terms(
    settlement: u8,
    dom_deadline: u64,
    cp_deadline_seconds: u64,
    t33: [u8; 33],
) -> SettlementTermsV1 {
    SettlementTermsV1 {
        settlement_id: SettlementId(b32(settlement)),
        session_id: SessionId(b32(settlement.wrapping_add(1))),
        intent_hash: IntentHash(b32(0xa3)),
        solver_id: SolverId(b32(0xa4)),
        roster: [ParticipantId(b32(0xb1)), ParticipantId(b32(0xb2))],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: ChainId(b32(0xc1)), // ONE hub chain for both settlements
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
        adaptor_point_sec1: t33,
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

/// Hub rung: dn 900 -> up 2000 (blocks). Counterparty rung: dn 1000 ->
/// up 2100 (seconds). Both rungs clear their margins.
fn good_pair() -> (SettlementTermsV1, SettlementTermsV1) {
    let t33 = t_point();
    (terms(0xa0, 2000, 2100, t33), terms(0xd0, 900, 1000, t33))
}

#[test]
fn a_valid_composition_binds_and_its_digest_is_deterministic() {
    let (up, dn) = good_pair();
    let a = ComposedBindingV1::bind(up.clone(), dn.clone(), margin()).expect("valid composition");
    let b = ComposedBindingV1::bind(up, dn, margin()).expect("same composition");
    assert_eq!(
        a.binding_digest(),
        b.binding_digest(),
        "digest is a function of the inputs"
    );
    assert_eq!(
        a.adaptor_point_sec1(),
        t_point(),
        "T is the committed point"
    );
}

#[test]
fn each_margin_is_committed_into_the_digest() {
    let (up, dn) = good_pair();
    let a = ComposedBindingV1::bind(up.clone(), dn.clone(), margin()).unwrap();
    let b = ComposedBindingV1::bind(
        up.clone(),
        dn.clone(),
        ComposedWindowPolicyV1 {
            hub_margin: 101,
            counterparty_margin: 100,
        },
    )
    .unwrap();
    let c = ComposedBindingV1::bind(
        up,
        dn,
        ComposedWindowPolicyV1 {
            hub_margin: 100,
            counterparty_margin: 101,
        },
    )
    .unwrap();
    assert_ne!(a.binding_digest(), b.binding_digest());
    assert_ne!(a.binding_digest(), c.binding_digest());
    assert_ne!(b.binding_digest(), c.binding_digest());
}

#[test]
fn mismatched_adaptor_points_refuse() {
    let (up, mut dn) = good_pair();
    let mut other = route_scalar();
    other[31] ^= 0x01;
    dn.adaptor_point_sec1 = adaptor_point_of_scalar(&other).unwrap();
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::AdaptorPointMismatch
    );
}

#[test]
fn an_off_curve_adaptor_point_refuses_at_binding() {
    let (mut up, mut dn) = good_pair();
    // Valid SEC1 prefix, x-coordinate above the field prime: passes the
    // terms' own prefix check, decodes to no curve point.
    let mut garbage = [0xFFu8; 33];
    garbage[0] = 0x02;
    up.adaptor_point_sec1 = garbage;
    dn.adaptor_point_sec1 = garbage;
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::InvalidAdaptorPoint,
        "a T no scalar can open must refuse at binding, not at claim time"
    );
}

#[test]
fn two_hub_chains_refuse() {
    let (up, mut dn) = good_pair();
    dn.dom_leg.chain_id = ChainId(b32(0xc9));
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::HubChainMismatch,
        "the hub is ONE chain; two DOM clocks cannot anchor one ladder"
    );
}

#[test]
fn equal_numbers_in_different_dom_assets_are_not_conservation() {
    let (up, mut dn) = good_pair();
    dn.dom_leg.asset_id = AssetId(b32(0xca));
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::HubAssetMismatch
    );
}

#[test]
fn mixed_dom_profiles_and_non_adaptor_hub_legs_refuse() {
    let (up, mut dn) = good_pair();
    dn.dom_leg.adapter_profile_hash = b32(0xcb);
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::HubProfileMismatch
    );

    let (up, mut dn) = good_pair();
    dn.dom_leg.mechanism = LockMechanism::HashlockFallback;
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::InvalidHubMechanism
    );
}

#[test]
fn unrelated_intents_mixed_policies_and_optional_refunds_refuse() {
    let (up, mut dn) = good_pair();
    dn.intent_hash = IntentHash(b32(0xcc));
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::RouteIntentMismatch
    );

    let (up, mut dn) = good_pair();
    dn.policy_version = 2;
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::RoutePolicyMismatch
    );

    let (up, mut dn) = good_pair();
    dn.recovery.refund_before_funding = false;
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::UnsafeRecoveryPolicy
    );
}

#[test]
fn an_inverted_hub_ladder_refuses() {
    let t33 = t_point();
    // Upstream DOM deadline matures BEFORE downstream: the catastrophic window.
    let up = terms(0xa0, 900, 2100, t33);
    let dn = terms(0xd0, 2000, 1000, t33);
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::UnsafeComposedWindow
    );
}

#[test]
fn a_counterparty_margin_shortfall_of_one_unit_refuses() {
    let t33 = t_point();
    // Hub rung fine (900 -> 2000, margin 100); counterparty rung one
    // second short: 1000 + 100 > 1099.
    let up = terms(0xa0, 2000, 1099, t33);
    let dn = terms(0xd0, 900, 1000, t33);
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::UnsafeComposedWindow
    );
}

#[test]
fn the_exact_margin_boundary_binds() {
    let t33 = t_point();
    // Both rungs exactly at margin: 900+100=1000<=... hub 1000, cp 1100.
    let up = terms(0xa0, 1000, 1100, t33);
    let dn = terms(0xd0, 900, 1000, t33);
    assert!(ComposedBindingV1::bind(up, dn, margin()).is_ok());
}

#[test]
fn overflowing_deadline_addition_never_fakes_a_safety_margin() {
    let (mut up, mut dn) = good_pair();

    // The actual distance is only 50 blocks, below the required margin of
    // 100. Adding the margin to `dn` overflows u64, so the comparison must
    // fail closed instead of saturating to a deadline that `up` can equal.
    up.dom_leg.deadline = TimelockSpec::BlockHeight { value: u64::MAX };
    dn.dom_leg.deadline = TimelockSpec::BlockHeight {
        value: u64::MAX - 50,
    };

    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::UnsafeComposedWindow
    );

    let (mut up, mut dn) = good_pair();
    up.counterparty_leg.deadline = TimelockSpec::TimestampSeconds { value: u64::MAX };
    dn.counterparty_leg.deadline = TimelockSpec::TimestampSeconds {
        value: u64::MAX - 50,
    };
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::UnsafeComposedWindow
    );
}

#[test]
fn mixed_timelock_domains_refuse_rather_than_convert() {
    let t33 = t_point();
    let up = terms(0xa0, 2000, 2100, t33);
    let mut dn = terms(0xd0, 900, 1000, t33);
    // Downstream counterparty deadline as a HEIGHT against the upstream
    // SECONDS: refused, never converted (A4).
    dn.counterparty_leg.deadline = TimelockSpec::BlockHeight { value: 1000 };
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::MixedTimelockDomains
    );
}

#[test]
fn counterparty_heights_on_two_different_chains_refuse() {
    let t33 = t_point();
    let mut up = terms(0xa0, 2000, 0, t33);
    let mut dn = terms(0xd0, 900, 0, t33);
    // Heights on TWO chains: the same number is a different time.
    up.counterparty_leg.deadline = TimelockSpec::BlockHeight { value: 2100 };
    dn.counterparty_leg.deadline = TimelockSpec::BlockHeight { value: 1000 };
    assert_ne!(up.counterparty_leg.chain_id, dn.counterparty_leg.chain_id);
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::CrossChainClockMismatch
    );
}

#[test]
fn counterparty_heights_on_one_shared_chain_bind() {
    let t33 = t_point();
    let mut up = terms(0xa0, 2000, 0, t33);
    let mut dn = terms(0xd0, 900, 0, t33);
    // X -> DOM -> X: one counterparty chain, one clock; heights compare.
    let shared = ChainId(b32(0xe5));
    up.counterparty_leg.chain_id = shared;
    dn.counterparty_leg.chain_id = shared;
    up.counterparty_leg.deadline = TimelockSpec::BlockHeight { value: 2100 };
    dn.counterparty_leg.deadline = TimelockSpec::BlockHeight { value: 1000 };
    assert!(ComposedBindingV1::bind(up, dn, margin()).is_ok());
}

#[test]
fn a_zero_margin_refuses_on_either_rung() {
    let (up, dn) = good_pair();
    for policy in [
        ComposedWindowPolicyV1 {
            hub_margin: 0,
            counterparty_margin: 100,
        },
        ComposedWindowPolicyV1 {
            hub_margin: 100,
            counterparty_margin: 0,
        },
    ] {
        assert_eq!(
            ComposedBindingV1::bind(up.clone(), dn.clone(), policy).unwrap_err(),
            ComposerRefusal::ZeroSafetyMargin
        );
    }
}

#[test]
fn a_dom_transit_mismatch_refuses() {
    let (up, mut dn) = good_pair();
    dn.dom_leg.amount += 1;
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::DomTransitMismatch
    );
}

#[test]
fn the_same_settlement_twice_refuses() {
    let (up, mut dn) = good_pair();
    dn.settlement_id = up.settlement_id;
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::SettlementsNotDistinct
    );
}

#[test]
fn invalid_terms_refuse_before_anything_else() {
    let (mut up, dn) = good_pair();
    up.dom_leg.amount = 0; // TermsError::ZeroAmount inside validate()
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::InvalidTerms
    );
}

#[test]
fn the_right_scalar_is_released_and_the_wrong_one_refused_by_one_bit() {
    let (up, dn) = good_pair();
    let binding = ComposedBindingV1::bind(up, dn, margin()).unwrap();

    let t = route_scalar();
    let released = binding
        .verify_revealed_scalar(&t)
        .expect("the route scalar opens T");
    assert_eq!(released.expose(), &t);
    assert_eq!(
        format!("{released:?}"),
        "RouteScalar(REDACTED)",
        "no echo (I6)"
    );

    let mut flipped = t;
    flipped[7] ^= 0x40;
    assert_eq!(
        binding.verify_revealed_scalar(&flipped).unwrap_err(),
        ComposerRefusal::WrongSecret
    );

    let zero = [0u8; 32];
    assert_eq!(
        binding.verify_revealed_scalar(&zero).unwrap_err(),
        ComposerRefusal::WrongSecret,
        "zero is not a scalar"
    );
}

#[test]
fn the_composed_fee_is_the_composed_rate_once() {
    let (mut up, mut dn) = good_pair();
    // A transit large enough for the 0.10% rate to be visible.
    up.dom_leg.amount = 1_000_000;
    dn.dom_leg.amount = 1_000_000;
    let binding = ComposedBindingV1::bind(up, dn, margin()).unwrap();
    // COMPOSED_ROUTE_RATE / RATE_DENOMINATOR = 10 / 10_000 = 0.10%, once.
    assert_eq!(binding.composed_treasury_share().unwrap(), 1_000);
}

#[test]
fn funding_order_is_the_only_permitted_order() {
    use SettlementState::*;

    // Upstream may fund only when BOTH refunds are armed.
    assert!(authorize_funding(ComposedLeg::Upstream, ReadyToFund, ReadyToFund).is_ok());
    for dn in [Preparing, Confirming, Settling, Settled, Refunded] {
        assert_eq!(
            authorize_funding(ComposedLeg::Upstream, ReadyToFund, dn).unwrap_err(),
            ComposerRefusal::FundingOutOfOrder,
            "upstream must not fund while downstream is {dn:?}"
        );
    }
    assert_eq!(
        authorize_funding(ComposedLeg::Upstream, Preparing, ReadyToFund).unwrap_err(),
        ComposerRefusal::FundingOutOfOrder,
        "upstream must not fund before its own refund is armed"
    );

    // Downstream may fund only when the upstream funding is CONFIRMED.
    assert!(authorize_funding(ComposedLeg::Downstream, Settling, ReadyToFund).is_ok());
    for up in [Preparing, ReadyToFund, Confirming, Settled, Refunded] {
        assert_eq!(
            authorize_funding(ComposedLeg::Downstream, up, ReadyToFund).unwrap_err(),
            ComposerRefusal::FundingOutOfOrder,
            "downstream must not fund while upstream is {up:?}"
        );
    }
}

/// The four composed shapes (Foundation §1.2, the level-1 quartet:
/// BTC→DOM→BTC, EVM→DOM→EVM, BTC→DOM→EVM, EVM→DOM→BTC) all bind: the
/// composer constrains T, the hub, the ladder clocks, the transit and
/// the order — never WHICH counterparty chain sits on each side. Same
/// chain on both sides (X→DOM→X) is a valid composition, and the fee is
/// the composed rate in every one of the four.
#[test]
fn all_four_composed_shapes_bind() {
    let t33 = t_point();
    let chain_x = b32(0xe1);
    let chain_y = b32(0xe2);
    for (up_chain, dn_chain) in [
        (chain_x, chain_x), // X → DOM → X
        (chain_x, chain_y), // X → DOM → Y
        (chain_y, chain_x), // Y → DOM → X
        (chain_y, chain_y), // Y → DOM → Y
    ] {
        let mut up = terms(0xa0, 2000, 2100, t33);
        let mut dn = terms(0xd0, 900, 1000, t33);
        up.counterparty_leg.chain_id = ChainId(up_chain);
        dn.counterparty_leg.chain_id = ChainId(dn_chain);
        let binding =
            ComposedBindingV1::bind(up, dn, margin()).expect("every composed shape binds");
        assert!(binding.composed_treasury_share().unwrap() > 0);
    }
}

/// Swapping the two settlements' roles never yields a second valid
/// composition: for a pair with a real ladder, exactly ONE ordering
/// binds and the swap refuses (a route has one direction).
#[test]
fn swapped_roles_never_bind() {
    let (up, dn) = good_pair();
    assert!(ComposedBindingV1::bind(up.clone(), dn.clone(), margin()).is_ok());
    assert_eq!(
        ComposedBindingV1::bind(dn, up, margin()).unwrap_err(),
        ComposerRefusal::UnsafeComposedWindow,
        "the reversed ordering is the catastrophic window and must refuse"
    );
}

/// The digest commits WHICH settlement is upstream: X→DOM→Y and
/// Y→DOM→X over the same two settlements are different routes.
#[test]
fn the_digest_commits_the_direction_of_the_route() {
    let t33 = t_point();
    // Symmetric ladders so BOTH orderings bind.
    let a = terms(0xa0, 2000, 2100, t33);
    let mut b = terms(0xd0, 900, 1000, t33);
    let mut a2 = a.clone();
    let b2 = b.clone();
    // Make a second, reversed-ladder pair with the same identities.
    a2.dom_leg.deadline = TimelockSpec::BlockHeight { value: 900 };
    a2.counterparty_leg.deadline = TimelockSpec::TimestampSeconds { value: 1000 };
    b.dom_leg.deadline = TimelockSpec::BlockHeight { value: 2000 };
    b.counterparty_leg.deadline = TimelockSpec::TimestampSeconds { value: 2100 };
    let forward = ComposedBindingV1::bind(a, b2, margin()).unwrap();
    let reversed = ComposedBindingV1::bind(b, a2, margin()).unwrap();
    assert_ne!(
        forward.binding_digest(),
        reversed.binding_digest(),
        "who is upstream is committed, not inferred"
    );
}

/// Non-canonical scalars at the group-order boundary never verify:
/// zero, all-ones, and the secp256k1 order n itself.
#[test]
fn non_canonical_scalars_never_verify() {
    let (up, dn) = good_pair();
    let binding = ComposedBindingV1::bind(up, dn, margin()).unwrap();
    // n (the group order), big-endian — a scalar exactly out of range.
    let order: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    for bad in [[0u8; 32], [0xFF; 32], order] {
        assert_eq!(
            binding.verify_revealed_scalar(&bad).unwrap_err(),
            ComposerRefusal::WrongSecret
        );
    }
}

/// The COMPLETE funding-order matrix: of all 2×6×6 combinations of
/// (leg, upstream state, downstream state), exactly two authorize.
#[test]
fn the_full_funding_matrix_has_exactly_two_open_doors() {
    use SettlementState::*;
    let states = [
        Preparing,
        ReadyToFund,
        Confirming,
        Settling,
        Settled,
        Refunded,
    ];
    let mut authorized = Vec::new();
    for leg in [ComposedLeg::Upstream, ComposedLeg::Downstream] {
        for up in states {
            for dn in states {
                if authorize_funding(leg, up, dn).is_ok() {
                    authorized.push((leg, up, dn));
                }
            }
        }
    }
    assert_eq!(
        authorized,
        vec![
            (ComposedLeg::Upstream, ReadyToFund, ReadyToFund),
            (ComposedLeg::Downstream, Settling, ReadyToFund),
        ],
        "every other combination is a closed door"
    );
}

/// The two settlements sharing a SESSION id refuse just like a shared
/// settlement id: two escape hatches need two sessions.
#[test]
fn the_same_session_twice_refuses() {
    let (up, mut dn) = good_pair();
    dn.session_id = up.session_id;
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::SettlementsNotDistinct
    );
}

/// Terms validity is judged BEFORE composition rules: a zero-amount
/// settlement refuses as InvalidTerms even when it also breaks the
/// transit rule — the first gate is each settlement's own law.
#[test]
fn terms_validity_is_judged_before_composition_rules() {
    let (up, mut dn) = good_pair();
    dn.dom_leg.amount = 0; // breaks BOTH terms validity and the transit rule
    assert_eq!(
        ComposedBindingV1::bind(up, dn, margin()).unwrap_err(),
        ComposerRefusal::InvalidTerms,
        "the per-settlement law fires first"
    );
}
