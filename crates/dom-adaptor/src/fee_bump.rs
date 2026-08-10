//! CPFP fee-bump calculator for contract transactions (spec §7.6).
//!
//! Master spec §7.6: "Uma assinatura preexistente não pode ser silenciosamente
//! atualizada com fee nova." Mimblewimble has no RBF ("RBF não é assumido sem
//! regra explícita da DOM") and the fee is frozen inside the signed kernel
//! message, so the V1 strategy is CPFP: reserve a controllable common output
//! and build an ordinary child that aggregates enough fee. **The parent stays
//! byte-identical** — nothing in this module touches, rebuilds, or re-signs a
//! parent; it only computes the child's required fee.
//!
//! The builder computes, verbatim from §7.6:
//!
//! ```text
//! required_child_fee = target_package_fee(parent_weight + child_weight)
//!                      - parent_fee
//! ```
//!
//! "com checked_*, teto de política e saldo suficiente" — those three guards,
//! exactly: every arithmetic step is checked, the result is capped by an
//! explicit policy ceiling, and the reserved child balance must cover it.
//! When the ceiling or the balance refuses, §7.6's consequence applies at the
//! caller: "a UI avisa que a confirmação depende da fee original."
//!
//! `target_package_fee` is the DOM authority, not a local invention: the
//! target rate times the package weight through
//! `dom_core::fee_policy::minimum_fee_for_weight`. Where the target rate
//! comes from (relay floor, estimator, operator) is the caller's input; under
//! a live relay that choice is the node-side fee-ladder work (Cronograma
//! 4.3), and so is the child's own relayability, which depends on mempool
//! policy this pure calculator does not model.

use crate::{AdaptorError, Result};
use dom_core::fee_policy::{minimum_fee_for_weight, FeeRate};

/// Policy ceiling for one child's fee (§7.6 "teto de política").
///
/// The ceiling is an explicit operator/policy input, validated nonzero — a
/// zero ceiling would silently forbid every bump, which must be an explicit
/// caller decision (not building a child at all), never a policy value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeBumpPolicyV1 {
    max_child_fee_noms: u64,
}

impl FeeBumpPolicyV1 {
    /// Construct the policy from the maximum child fee in noms.
    pub fn new(max_child_fee_noms: u64) -> Result<Self> {
        if max_child_fee_noms == 0 {
            return Err(AdaptorError::InvalidContext(
                "fee-bump policy ceiling must be nonzero",
            ));
        }
        Ok(Self { max_child_fee_noms })
    }

    /// The ceiling in noms.
    pub const fn max_child_fee_noms(&self) -> u64 {
        self.max_child_fee_noms
    }
}

/// The calculator's decision for one parent/child pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildFeeV1 {
    /// The parent's frozen fee already meets the package target at the given
    /// rate; no child is required and the parent is left exactly as signed.
    NotNeeded,
    /// Build the child with exactly this fee: it lifts the package —
    /// `parent_fee + fee_noms` — precisely to the target.
    Required {
        /// The child's fee in noms.
        fee_noms: u64,
    },
}

/// Compute the §7.6 required child fee, fail-closed on all three guards.
///
/// `target_fee_rate` is the rate the package must reach (the caller's
/// relay/estimator input); `available_child_balance_noms` is the value of the
/// reserved common output the child spends. Zero parent or child weight is a
/// degenerate shape and fails closed — a real parent and a real child both
/// weigh at least one unit under the DOM weight model.
pub fn required_child_fee_v1(
    target_fee_rate: FeeRate,
    parent_weight: u64,
    child_weight: u64,
    parent_fee_noms: u64,
    policy: &FeeBumpPolicyV1,
    available_child_balance_noms: u64,
) -> Result<ChildFeeV1> {
    if parent_weight == 0 || child_weight == 0 {
        return Err(AdaptorError::InvalidContext(
            "fee bump weights must be nonzero",
        ));
    }
    // §7.6: target_package_fee(parent_weight + child_weight), checked.
    let package_weight = parent_weight
        .checked_add(child_weight)
        .ok_or(AdaptorError::InvalidContext(
            "fee bump package weight overflows",
        ))?;
    let target_package_fee = minimum_fee_for_weight(package_weight, target_fee_rate)
        .map_err(|_| AdaptorError::InvalidContext("fee bump target fee overflows"))?;

    // The parent's frozen fee already reaches the target: no child, and the
    // parent remains byte-identical (§7.6).
    let Some(required) = target_package_fee.checked_sub(parent_fee_noms) else {
        return Ok(ChildFeeV1::NotNeeded);
    };
    if required == 0 {
        return Ok(ChildFeeV1::NotNeeded);
    }

    // §7.6 "teto de política": above the ceiling, the bump is refused and the
    // caller surfaces that confirmation depends on the original fee.
    if required > policy.max_child_fee_noms() {
        return Err(AdaptorError::InvalidContext(
            "required child fee exceeds the fee-bump policy ceiling",
        ));
    }
    // §7.6 "saldo suficiente": the reserved output must cover the child fee.
    if required > available_child_balance_noms {
        return Err(AdaptorError::InvalidContext(
            "required child fee exceeds the reserved child balance",
        ));
    }
    Ok(ChildFeeV1::Required { fee_noms: required })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate(noms_per_weight_unit: u64) -> FeeRate {
        FeeRate {
            noms_per_weight_unit,
        }
    }

    fn policy(ceiling: u64) -> FeeBumpPolicyV1 {
        FeeBumpPolicyV1::new(ceiling).expect("policy")
    }

    #[test]
    fn policy_rejects_a_zero_ceiling() {
        assert!(FeeBumpPolicyV1::new(0).is_err());
        assert_eq!(policy(500).max_child_fee_noms(), 500);
    }

    #[test]
    fn the_formula_is_exact_and_lifts_the_package_precisely_to_target() {
        // target_package_fee = 2 * (100 + 50) = 300; parent paid 120.
        let result = required_child_fee_v1(rate(2), 100, 50, 120, &policy(1_000), 1_000)
            .expect("child fee");
        assert_eq!(result, ChildFeeV1::Required { fee_noms: 180 });
        // §7.6 invariant: parent_fee + child_fee == target, exactly — the
        // package reaches the target with no over- or under-shoot.
        assert_eq!(120 + 180, 2 * (100 + 50));
    }

    #[test]
    fn a_parent_already_at_or_above_target_needs_no_child() {
        // Exactly at target.
        assert_eq!(
            required_child_fee_v1(rate(2), 100, 50, 300, &policy(1_000), 1_000).expect("ok"),
            ChildFeeV1::NotNeeded
        );
        // Above target.
        assert_eq!(
            required_child_fee_v1(rate(2), 100, 50, 400, &policy(1_000), 1_000).expect("ok"),
            ChildFeeV1::NotNeeded
        );
    }

    #[test]
    fn the_policy_ceiling_fails_closed_at_the_exact_boundary() {
        // required = 180: a ceiling of exactly 180 admits it…
        assert!(required_child_fee_v1(rate(2), 100, 50, 120, &policy(180), 1_000).is_ok());
        // …and one nom below refuses (§7.6: confirmation then depends on the
        // original fee).
        assert!(required_child_fee_v1(rate(2), 100, 50, 120, &policy(179), 1_000).is_err());
    }

    #[test]
    fn the_reserved_balance_fails_closed_at_the_exact_boundary() {
        assert!(required_child_fee_v1(rate(2), 100, 50, 120, &policy(1_000), 180).is_ok());
        assert!(required_child_fee_v1(rate(2), 100, 50, 120, &policy(1_000), 179).is_err());
    }

    #[test]
    fn every_checked_step_fails_closed_on_overflow_and_degenerate_shapes() {
        // Package weight overflow.
        assert!(required_child_fee_v1(rate(1), u64::MAX, 1, 0, &policy(10), 10).is_err());
        // Target fee overflow (weight * rate).
        assert!(required_child_fee_v1(rate(u64::MAX), 2, 2, 0, &policy(10), 10).is_err());
        // Degenerate zero weights.
        assert!(required_child_fee_v1(rate(2), 0, 50, 0, &policy(10), 10).is_err());
        assert!(required_child_fee_v1(rate(2), 100, 0, 0, &policy(10), 10).is_err());
    }

    #[test]
    fn a_zero_target_rate_never_requires_a_child() {
        // With a zero rate the target is zero and any frozen parent fee
        // satisfies it; the calculator must not manufacture a bump.
        assert_eq!(
            required_child_fee_v1(rate(0), 100, 50, 0, &policy(1_000), 1_000).expect("ok"),
            ChildFeeV1::NotNeeded
        );
    }
}
