//! Protocol fee policy — NOT RATIFIED.
//!
//! Implements the fee model minuted in
//! `docs/adr/ADR-DOM-PROTOCOL-FEE-MODEL-DRAFT.md`, whose parameters the
//! operator approved in chat but which has not been ratified as a numbered
//! decision. Until that ratification this module is an interim
//! implementation in the sense of standing order 1: it is marked NOT
//! RATIFIED here, in the code, and nothing outside this crate is required to
//! consult it yet.
//!
//! ## Why the fee has two components
//!
//! RFC-0008 makes the DOM kernel fee **explicit and public** — the balance
//! equation is `Σv_out + fee = Σv_in`, and the coinbase enforces
//! `explicit_value == block_reward + sum(tx_fees_in_block)`. It has to be
//! public: that is how a miner knows what it is being paid.
//!
//! A percentage of the DOM leg amount, published as `kernel.fee`, therefore
//! reveals that amount by division:
//!
//! ```text
//! public_fee = rate × confidential_amount   ⇒   amount = public_fee / rate
//! ```
//!
//! which destroys DOM indistinguishability (I8). A percentage fee and a
//! percentage miner share cannot coexist. The two components are therefore
//! separated by what each can safely be:
//!
//! - the **treasury** share is the percentage, paid as a **confidential DOM
//!   output**, so nothing leaks;
//! - the **miner** share is a **fixed** minimum `kernel.fee` — public, but a
//!   constant carries no information about the amount.
//!
//! The miner component MUST stay constant. Making it depend on the amount in
//! any way — a percentage, or size buckets — reintroduces the leak, exactly
//! or as an order of magnitude.
//!
//! ## No consensus change
//!
//! Neither component changes DOM consensus. The miner share is an ordinary
//! `kernel.fee` that the existing coinbase rule already credits; the treasury
//! share is an ordinary confidential output. This is enforcement above
//! consensus, as P.3 items 2 and 6 require.

use crate::{RouteV1, F6_PROTOCOL_VERSION};
use kaystra_core::types::ChainId;

/// Subunits in one DOM (`dom_core::COIN_UNIT`), restated here so this crate
/// does not import the pin — the §4.2 boundary keeps `rfq` neutral.
pub const NOMS_PER_DOM: u128 = 100_000_000;

/// Treasury share of a simple route (DOM ↔ X): 0.05%, as a rate over
/// [`RATE_DENOMINATOR`].
pub const SIMPLE_ROUTE_RATE: u128 = 5;

/// Treasury share of a composed route (X → DOM → Y): 0.10%.
pub const COMPOSED_ROUTE_RATE: u128 = 10;

/// Denominator of the rates above: 5/10_000 = 0.05%.
pub const RATE_DENOMINATOR: u128 = 10_000;

/// The fixed miner component, in noms: 0.01 DOM.
///
/// **Constant on purpose.** It is published in the kernel, so any dependence
/// on the transacted amount would leak it (see the module docs). At the
/// current 33 DOM block reward this is about 0.03% of a block — clearly above
/// the ordinary cost of a transaction, so it is a real incentive, and far
/// below the reward, so it does not distort block economics.
pub const MINER_FIXED_NOMS: u128 = NOMS_PER_DOM / 100;

/// Shape of a route for fee purposes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouteShapeV1 {
    /// One settlement: the DOM and one counterparty chain.
    Simple,
    /// Two chained settlements: counterparty → DOM → counterparty.
    Composed,
}

/// Refusals this policy can produce.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum FeePolicyRefusal {
    /// The treasury share is below the rate this route owes.
    #[error("protocol fee below the ratified floor")]
    FeeBelowFloor,
    /// The miner component is below the fixed minimum.
    #[error("miner fee below the fixed minimum")]
    MinerFeeBelowFloor,
    /// The miner component is not the constant, so it would leak the amount.
    #[error("miner fee is not the fixed constant")]
    MinerFeeNotConstant,
    /// Checked arithmetic overflowed.
    #[error("fee arithmetic overflow")]
    Overflow,
}

/// Classifies a route by how many distinct counterparty chains it touches.
///
/// A route whose two legs sit on the same counterparty chain, or which
/// crosses the DOM between two different counterparty chains, is composed;
/// anything else is simple.
pub fn route_shape(route: &RouteV1, dom_chain_id: ChainId) -> RouteShapeV1 {
    let counterparty_chains: usize = route
        .legs
        .iter()
        .filter(|leg| leg.chain_id != dom_chain_id)
        .map(|leg| leg.chain_id)
        .fold(Vec::new(), |mut seen: Vec<ChainId>, chain| {
            if !seen.contains(&chain) {
                seen.push(chain);
            }
            seen
        })
        .len();
    if counterparty_chains >= 2 {
        RouteShapeV1::Composed
    } else {
        RouteShapeV1::Simple
    }
}

/// The treasury share this route owes on `dom_leg_amount`, in the DOM leg's
/// smallest unit. Charged ONCE PER ROUTE: a composed route pays the composed
/// rate once, not the simple rate twice.
///
/// Rounds up, so a settlement can never owe less than the rate by truncation.
pub fn treasury_share(dom_leg_amount: u128, shape: RouteShapeV1) -> Result<u128, FeePolicyRefusal> {
    let rate = match shape {
        RouteShapeV1::Simple => SIMPLE_ROUTE_RATE,
        RouteShapeV1::Composed => COMPOSED_ROUTE_RATE,
    };
    let numerator = dom_leg_amount
        .checked_mul(rate)
        .ok_or(FeePolicyRefusal::Overflow)?;
    // Ceiling division: never round the protocol's share down.
    let ceiling = numerator
        .checked_add(RATE_DENOMINATOR - 1)
        .ok_or(FeePolicyRefusal::Overflow)?;
    Ok(ceiling / RATE_DENOMINATOR)
}

/// Refuses a settlement whose fee components do not satisfy the policy.
///
/// `declared_treasury` is the confidential output paying the treasury;
/// `declared_miner` is the settlement's `kernel.fee`.
///
/// The treasury share is a FLOOR — paying more is allowed, since a solver may
/// round up. The miner component is an EQUALITY: paying more would make the
/// public kernel fee vary between settlements, which is precisely the leak
/// this split exists to prevent.
pub fn check_fee_components(
    dom_leg_amount: u128,
    shape: RouteShapeV1,
    declared_treasury: u128,
    declared_miner: u128,
) -> Result<(), FeePolicyRefusal> {
    let owed = treasury_share(dom_leg_amount, shape)?;
    if declared_treasury < owed {
        return Err(FeePolicyRefusal::FeeBelowFloor);
    }
    if declared_miner < MINER_FIXED_NOMS {
        return Err(FeePolicyRefusal::MinerFeeBelowFloor);
    }
    if declared_miner != MINER_FIXED_NOMS {
        return Err(FeePolicyRefusal::MinerFeeNotConstant);
    }
    Ok(())
}

/// The protocol version this schedule belongs to. A change of rates travels
/// as a new policy version rather than as a silent runtime change, which is
/// what keeps the schedule out of I2's prohibition on administrative levers.
pub const FEE_POLICY_VERSION: u16 = F6_PROTOCOL_VERSION;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LegDirectionV1, RouteLegV1};

    const DOM: ChainId = ChainId([0xd0; 32]);
    const BTC: ChainId = ChainId([0xb7; 32]);
    const EVM: ChainId = ChainId([0xe0; 32]);

    fn route(a: ChainId, b: ChainId) -> RouteV1 {
        RouteV1 {
            legs: [
                RouteLegV1 {
                    chain_id: a,
                    asset: kaystra_core::types::AssetId([0x01; 32]),
                    direction: LegDirectionV1::UserGives,
                },
                RouteLegV1 {
                    chain_id: b,
                    asset: kaystra_core::types::AssetId([0x02; 32]),
                    direction: LegDirectionV1::UserReceives,
                },
            ],
        }
    }

    #[test]
    fn a_dom_to_counterparty_route_is_simple() {
        assert_eq!(route_shape(&route(DOM, BTC), DOM), RouteShapeV1::Simple);
        assert_eq!(route_shape(&route(EVM, DOM), DOM), RouteShapeV1::Simple);
    }

    #[test]
    fn a_route_between_two_counterparty_chains_is_composed() {
        // BTC -> (DOM) -> EVM: the DOM is the hub, so the user's two legs sit
        // on two different counterparty chains.
        assert_eq!(route_shape(&route(BTC, EVM), DOM), RouteShapeV1::Composed);
    }

    #[test]
    fn the_simple_rate_is_five_basis_points() {
        // 1 DOM at 0.05% = 0.0005 DOM = 50_000 noms.
        assert_eq!(
            treasury_share(NOMS_PER_DOM, RouteShapeV1::Simple).unwrap(),
            50_000
        );
    }

    #[test]
    fn the_composed_rate_is_double_the_simple_one() {
        let simple = treasury_share(NOMS_PER_DOM, RouteShapeV1::Simple).unwrap();
        let composed = treasury_share(NOMS_PER_DOM, RouteShapeV1::Composed).unwrap();
        assert_eq!(composed, simple * 2);
        assert_eq!(composed, 100_000);
    }

    #[test]
    fn the_share_rounds_up_so_the_protocol_is_never_short_changed() {
        // 1 nom at 0.05% is 0.0005 noms, which must round to 1, not 0.
        assert_eq!(treasury_share(1, RouteShapeV1::Simple).unwrap(), 1);
    }

    #[test]
    fn a_correct_pair_of_components_is_accepted() {
        let amount = 1_000 * NOMS_PER_DOM;
        let owed = treasury_share(amount, RouteShapeV1::Simple).unwrap();
        assert!(check_fee_components(amount, RouteShapeV1::Simple, owed, MINER_FIXED_NOMS).is_ok());
    }

    #[test]
    fn a_treasury_share_below_the_floor_is_refused() {
        let amount = 1_000 * NOMS_PER_DOM;
        let owed = treasury_share(amount, RouteShapeV1::Simple).unwrap();
        assert_eq!(
            check_fee_components(amount, RouteShapeV1::Simple, owed - 1, MINER_FIXED_NOMS),
            Err(FeePolicyRefusal::FeeBelowFloor)
        );
    }

    #[test]
    fn paying_more_than_the_floor_is_allowed() {
        let amount = 1_000 * NOMS_PER_DOM;
        let owed = treasury_share(amount, RouteShapeV1::Simple).unwrap();
        assert!(
            check_fee_components(amount, RouteShapeV1::Simple, owed + 1, MINER_FIXED_NOMS).is_ok()
        );
    }

    #[test]
    fn a_miner_component_below_the_constant_is_refused() {
        let amount = NOMS_PER_DOM;
        let owed = treasury_share(amount, RouteShapeV1::Simple).unwrap();
        assert_eq!(
            check_fee_components(amount, RouteShapeV1::Simple, owed, MINER_FIXED_NOMS - 1),
            Err(FeePolicyRefusal::MinerFeeBelowFloor)
        );
    }

    /// The whole point of the split: an ABOVE-constant miner fee is refused
    /// too, because a kernel fee that varies between settlements is the leak.
    #[test]
    fn a_miner_component_above_the_constant_is_also_refused() {
        let amount = NOMS_PER_DOM;
        let owed = treasury_share(amount, RouteShapeV1::Simple).unwrap();
        assert_eq!(
            check_fee_components(amount, RouteShapeV1::Simple, owed, MINER_FIXED_NOMS + 1),
            Err(FeePolicyRefusal::MinerFeeNotConstant)
        );
    }

    /// The confidentiality property, stated as a test: two settlements of
    /// very different sizes publish the SAME miner fee, so the public value
    /// distinguishes nothing.
    #[test]
    fn the_public_miner_fee_does_not_distinguish_a_small_swap_from_a_large_one() {
        let small = NOMS_PER_DOM;
        let large = 10_000 * NOMS_PER_DOM;
        let small_owed = treasury_share(small, RouteShapeV1::Simple).unwrap();
        let large_owed = treasury_share(large, RouteShapeV1::Simple).unwrap();
        assert!(
            check_fee_components(small, RouteShapeV1::Simple, small_owed, MINER_FIXED_NOMS).is_ok()
        );
        assert!(
            check_fee_components(large, RouteShapeV1::Simple, large_owed, MINER_FIXED_NOMS).is_ok()
        );
        // The treasury shares differ — but they are confidential outputs.
        assert_ne!(small_owed, large_owed);
        // The published component is identical, which is the property.
    }

    #[test]
    fn the_arithmetic_refuses_rather_than_wrapping() {
        assert_eq!(
            treasury_share(u128::MAX, RouteShapeV1::Composed),
            Err(FeePolicyRefusal::Overflow)
        );
    }

    #[test]
    fn the_miner_constant_is_one_hundredth_of_a_dom() {
        assert_eq!(MINER_FIXED_NOMS, 1_000_000);
    }
}
