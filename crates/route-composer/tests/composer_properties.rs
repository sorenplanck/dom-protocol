//! Property-based invariants of the composed binding.
//!
//! 1. **Ladder soundness.** Over arbitrary deadlines and margins, `bind`
//!    accepts EXACTLY when both same-clock rungs hold: never an unsafe
//!    window accepted, never a safe one refused.
//! 2. **Hand-off soundness.** No scalar other than `t` is ever released
//!    against `T = t*G` — including near-misses one bit away.
//! 3. **Digest injectivity over the committed surface.** Changing any
//!    sampled committed field (ids, amounts, deadlines, margins) changes
//!    the binding digest.

use adapter_evm::binding::adaptor_point_of_scalar;
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::*;
use proptest::prelude::*;
use route_composer::{ComposedBindingV1, ComposedWindowPolicyV1, ComposerRefusal};

fn b32(x: u8) -> [u8; 32] {
    [x; 32]
}

fn route_scalar() -> [u8; 32] {
    let mut t = [0u8; 32];
    for (i, byte) in t.iter_mut().enumerate() {
        *byte = (0x11 + i as u8) | 0x01;
    }
    t[0] = 0x2b;
    t
}

fn terms(settlement: u8, dom_deadline: u64, cp_seconds: u64, t33: [u8; 33]) -> SettlementTermsV1 {
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
            deadline: TimelockSpec::TimestampSeconds { value: cp_seconds },
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

proptest! {
    /// Ladder soundness: acceptance is EXACTLY both rungs holding.
    #[test]
    fn bind_accepts_exactly_when_both_rungs_hold(
        up_dom in 0u64..2_000_000,
        dn_dom in 0u64..2_000_000,
        up_cp in 0u64..2_000_000_000,
        dn_cp in 0u64..2_000_000_000,
        hub_margin in 1u64..10_000,
        cp_margin in 1u64..1_000_000,
    ) {
        let t33 = adaptor_point_of_scalar(&route_scalar()).unwrap();
        let up = terms(0xa0, up_dom, up_cp, t33);
        let dn = terms(0xd0, dn_dom, dn_cp, t33);
        let policy = ComposedWindowPolicyV1 { hub_margin, counterparty_margin: cp_margin };
        let hub_ok = dn_dom
            .checked_add(hub_margin)
            .is_some_and(|minimum_upstream| up_dom >= minimum_upstream);
        let cp_ok = dn_cp
            .checked_add(cp_margin)
            .is_some_and(|minimum_upstream| up_cp >= minimum_upstream);
        match ComposedBindingV1::bind(up, dn, policy) {
            Ok(_) => prop_assert!(hub_ok && cp_ok, "accepted an unsafe window"),
            Err(ComposerRefusal::UnsafeComposedWindow) =>
                prop_assert!(!(hub_ok && cp_ok), "refused a safe window"),
            Err(other) => prop_assert!(false, "unexpected refusal {other:?}"),
        }
    }

    /// Hand-off soundness: a scalar differing from `t` in one random bit
    /// never verifies against `T = t*G`.
    #[test]
    fn no_near_miss_scalar_ever_verifies(bit in 0usize..256) {
        let t = route_scalar();
        let t33 = adaptor_point_of_scalar(&t).unwrap();
        let up = terms(0xa0, 2000, 2100, t33);
        let dn = terms(0xd0, 900, 1000, t33);
        let policy = ComposedWindowPolicyV1 { hub_margin: 100, counterparty_margin: 100 };
        let binding = ComposedBindingV1::bind(up, dn, policy).unwrap();

        let mut wrong = t;
        wrong[bit / 8] ^= 1u8 << (bit % 8);
        prop_assert_eq!(
            binding.verify_revealed_scalar(&wrong).unwrap_err(),
            ComposerRefusal::WrongSecret
        );
        // And the genuine scalar still verifies afterwards.
        prop_assert!(binding.verify_revealed_scalar(&t).is_ok());
    }

    /// Digest injectivity over sampled committed fields.
    #[test]
    fn the_digest_commits_the_sampled_surface(
        which in 0usize..5,
        delta in 1u64..1_000,
    ) {
        let t33 = adaptor_point_of_scalar(&route_scalar()).unwrap();
        let base_up = terms(0xa0, 200_000, 300_000, t33);
        let base_dn = terms(0xd0, 900, 1000, t33);
        let policy = ComposedWindowPolicyV1 { hub_margin: 100, counterparty_margin: 100 };
        let a = ComposedBindingV1::bind(base_up.clone(), base_dn.clone(), policy).unwrap();

        let mut up = base_up;
        let mut dn = base_dn;
        let mut p = policy;
        match which {
            0 => { up.dom_leg.deadline = TimelockSpec::BlockHeight { value: 200_000 + delta }; }
            1 => { dn.counterparty_leg.deadline = TimelockSpec::TimestampSeconds { value: 1000 - (delta % 1000) }; }
            2 => { up.dom_leg.amount += u128::from(delta); dn.dom_leg.amount += u128::from(delta); }
            3 => { p.hub_margin += delta % 100; }
            _ => { p.counterparty_margin += delta % 100; }
        }
        // Skip the identity mutation when the delta collapses to zero.
        prop_assume!(!(which == 3 && delta % 100 == 0));
        prop_assume!(!(which == 4 && delta % 100 == 0));
        prop_assume!(!(which == 1 && delta % 1000 == 0));
        let b = ComposedBindingV1::bind(up, dn, p).unwrap();
        prop_assert_ne!(a.binding_digest(), b.binding_digest());
    }
}
