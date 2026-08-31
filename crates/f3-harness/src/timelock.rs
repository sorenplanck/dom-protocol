//! Timelock margins and timelock-domain safety.
//!
//! # Two legs, two clocks, and no silent conversion
//!
//! The EVM leg's deadline is a UNIX timestamp: `ConditionLockV2.refund`
//! compares against `block.timestamp`, and the adapter declares
//! [`TimelockDomain::Timestamp`]. The dom-sim leg's timelock is a block height:
//! `SimTx::Refund { not_before_height }`, and the DOM-side capability is
//! [`TimelockDomain::BlockHeight`].
//!
//! Those two numbers are **not** interchangeable, and the failure mode of
//! treating them as if they were is silent and expensive: a "deadline" of
//! `1_800_000_000` read as a block height is a timelock that never expires, and
//! a height of `120` read as a timestamp is a deadline that expired in 1970.
//! So this module makes every crossing explicit:
//!
//! - a value is always a [`TimelockPoint`], which carries its domain;
//! - [`TimelockPolicy`] refuses to compare two points from different domains;
//! - the only way to move a value between domains is [`bridge`], and it fails
//!   unless the caller hands it a [`DeclaredDomainBridge`] that names both
//!   domains explicitly. There is no default, no fallback and no inference.
//!
//! # The four margins
//!
//! A deadline is not actionable until the last moment; it is actionable until
//! the last moment *minus everything that can go wrong on the way there*. The
//! harness refuses to act when the remaining window is smaller than the sum of
//! four named margins. Each is a separate constant because each has a separate
//! cause and would be retuned for a separate reason:
//!
//! | margin | what it pays for |
//! |---|---|
//! | [`FINALITY_MARGIN_SECS`] | the observation the action depends on must be *finalized*, and Ethereum finality lags the head by two epochs (64 slots, 12.8 min) plus the slack of a missed epoch |
//! | [`RPC_LAG_MARGIN_SECS`] | the endpoint we read is not the chain; a load-balanced provider can serve a view a few blocks stale, and `finalized` can lag further than `latest` |
//! | [`NETWORK_PROPAGATION_MARGIN_SECS`] | once authorised, the transaction still has to reach a builder and be included; at a congested base fee that is several blocks, not one |
//! | [`REACTION_MARGIN_SECS`] | the operator/process has to notice, authorise and submit; a crash-restart cycle happens inside this budget |
//!
//! The DOM-sim leg counts in blocks, so it has its own constants with the same
//! four causes. Their absolute values are deliberately conservative: being
//! early costs a retry, being late costs the funds.

use counterparty_api::TimelockDomain;

// ---------------------------------------------------------------------------
// EVM leg (Timestamp domain), in seconds
// ---------------------------------------------------------------------------

/// Finality margin, seconds. Two epochs is 12.8 min; a single missed epoch
/// pushes finality to ~19 min. 30 min covers both with room to spare.
pub const FINALITY_MARGIN_SECS: u64 = 30 * 60;

/// RPC lag margin, seconds. A provider that load-balances across nodes can
/// serve a view several blocks behind; five minutes is far beyond what a
/// healthy endpoint shows and still cheap to reserve.
pub const RPC_LAG_MARGIN_SECS: u64 = 5 * 60;

/// Network propagation and inclusion margin, seconds. Ten minutes is ~50
/// slots: enough for inclusion at a fee that was reasonable when the
/// transaction was authorised, even through a fee spike.
pub const NETWORK_PROPAGATION_MARGIN_SECS: u64 = 10 * 60;

/// Reaction margin, seconds. The budget for noticing, authorising and
/// submitting — including one crash-and-recover cycle.
pub const REACTION_MARGIN_SECS: u64 = 15 * 60;

/// Total EVM-leg safety margin, seconds (one hour).
pub const TOTAL_MARGIN_SECS: u64 = FINALITY_MARGIN_SECS
    + RPC_LAG_MARGIN_SECS
    + NETWORK_PROPAGATION_MARGIN_SECS
    + REACTION_MARGIN_SECS;

// ---------------------------------------------------------------------------
// DOM-sim leg (BlockHeight domain), in blocks
// ---------------------------------------------------------------------------

/// Finality margin, blocks.
pub const FINALITY_MARGIN_BLOCKS: u64 = 12;
/// RPC/observer lag margin, blocks.
pub const RPC_LAG_MARGIN_BLOCKS: u64 = 2;
/// Propagation and inclusion margin, blocks.
pub const NETWORK_PROPAGATION_MARGIN_BLOCKS: u64 = 3;
/// Reaction margin, blocks.
pub const REACTION_MARGIN_BLOCKS: u64 = 3;
/// Total DOM-sim-leg safety margin, blocks.
pub const TOTAL_MARGIN_BLOCKS: u64 = FINALITY_MARGIN_BLOCKS
    + RPC_LAG_MARGIN_BLOCKS
    + NETWORK_PROPAGATION_MARGIN_BLOCKS
    + REACTION_MARGIN_BLOCKS;

/// Errors this module can raise. None of them carries secret material.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum TimelockError {
    /// A point from one domain was used where another domain was required.
    #[error("timelock domain mismatch: expected {expected:?}, got {got:?}")]
    DomainMismatch {
        /// Domain the policy operates in.
        expected: TimelockDomain,
        /// Domain the caller supplied.
        got: TimelockDomain,
    },
    /// A crossing was attempted without an explicit declaration that the two
    /// domains correspond. Never converted silently.
    #[error("timelock domains {from:?} and {to:?} are not declared compatible")]
    DomainsNotDeclaredCompatible {
        /// Source domain.
        from: TimelockDomain,
        /// Target domain.
        to: TimelockDomain,
    },
    /// The declared bridge does not describe a usable correspondence.
    #[error("declared domain bridge is degenerate")]
    DegenerateBridge,
    /// The deadline is already in the past.
    #[error("deadline has already passed")]
    DeadlinePassed,
    /// The window left before the deadline is smaller than the safety margin.
    #[error("remaining window {remaining} is below the required margin {required}")]
    WindowTooNarrow {
        /// Units left before the deadline.
        remaining: u64,
        /// Units the policy requires.
        required: u64,
    },
    /// Arithmetic would wrap.
    #[error("timelock arithmetic overflow")]
    Overflow,
}

/// A point in time, in a named domain. The domain travels with the number so
/// that it cannot be dropped by accident.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TimelockPoint {
    /// Which clock this number belongs to.
    pub domain: TimelockDomain,
    /// The number itself: a UNIX timestamp, or a block height.
    pub value: u64,
}

impl TimelockPoint {
    /// A UNIX timestamp (the EVM leg).
    pub const fn timestamp(value: u64) -> Self {
        Self {
            domain: TimelockDomain::Timestamp,
            value,
        }
    }

    /// A block height (the dom-sim leg).
    pub const fn height(value: u64) -> Self {
        Self {
            domain: TimelockDomain::BlockHeight,
            value,
        }
    }
}

/// The margin set and the domain it is expressed in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TimelockPolicy {
    /// Domain every point handed to this policy must be in.
    pub domain: TimelockDomain,
    /// See [`FINALITY_MARGIN_SECS`].
    pub finality_margin: u64,
    /// See [`RPC_LAG_MARGIN_SECS`].
    pub rpc_lag_margin: u64,
    /// See [`NETWORK_PROPAGATION_MARGIN_SECS`].
    pub propagation_margin: u64,
    /// See [`REACTION_MARGIN_SECS`].
    pub reaction_margin: u64,
}

impl TimelockPolicy {
    /// The EVM leg's policy: timestamps, seconds.
    pub const fn evm() -> Self {
        Self {
            domain: TimelockDomain::Timestamp,
            finality_margin: FINALITY_MARGIN_SECS,
            rpc_lag_margin: RPC_LAG_MARGIN_SECS,
            propagation_margin: NETWORK_PROPAGATION_MARGIN_SECS,
            reaction_margin: REACTION_MARGIN_SECS,
        }
    }

    /// The dom-sim leg's policy: block heights, blocks.
    pub const fn dom_sim() -> Self {
        Self {
            domain: TimelockDomain::BlockHeight,
            finality_margin: FINALITY_MARGIN_BLOCKS,
            rpc_lag_margin: RPC_LAG_MARGIN_BLOCKS,
            propagation_margin: NETWORK_PROPAGATION_MARGIN_BLOCKS,
            reaction_margin: REACTION_MARGIN_BLOCKS,
        }
    }

    /// Checked sum of the four margins. A policy whose budget cannot be
    /// represented is invalid; saturating it could turn an impossible safety
    /// promise into an actionable `u64::MAX` window.
    pub fn total_margin(&self) -> core::result::Result<u64, TimelockError> {
        self.finality_margin
            .checked_add(self.rpc_lag_margin)
            .and_then(|sum| sum.checked_add(self.propagation_margin))
            .and_then(|sum| sum.checked_add(self.reaction_margin))
            .ok_or(TimelockError::Overflow)
    }

    /// Rejects a point that is not in this policy's domain.
    pub fn require_domain(&self, point: TimelockPoint) -> core::result::Result<u64, TimelockError> {
        if point.domain != self.domain {
            return Err(TimelockError::DomainMismatch {
                expected: self.domain,
                got: point.domain,
            });
        }
        Ok(point.value)
    }

    /// Units left between `now` and `deadline`, both of which must be in this
    /// policy's domain.
    pub fn remaining(
        &self,
        now: TimelockPoint,
        deadline: TimelockPoint,
    ) -> core::result::Result<u64, TimelockError> {
        let now = self.require_domain(now)?;
        let deadline = self.require_domain(deadline)?;
        deadline
            .checked_sub(now)
            .ok_or(TimelockError::DeadlinePassed)
    }

    /// The gate: `Ok(remaining)` only when the window still covers every
    /// margin. This is the call that must precede any irreversible action
    /// whose safety depends on beating a deadline.
    pub fn require_actionable(
        &self,
        now: TimelockPoint,
        deadline: TimelockPoint,
    ) -> core::result::Result<u64, TimelockError> {
        let remaining = self.remaining(now, deadline)?;
        let required = self.total_margin()?;
        if remaining < required {
            return Err(TimelockError::WindowTooNarrow {
                remaining,
                required,
            });
        }
        Ok(remaining)
    }

    /// The mirror image: `Ok(())` only when a *refund* deadline has genuinely
    /// passed, with the observation margins applied in the other direction so
    /// that a lagging endpoint cannot make us refund early.
    pub fn require_expired(
        &self,
        now: TimelockPoint,
        deadline: TimelockPoint,
    ) -> core::result::Result<(), TimelockError> {
        let now = self.require_domain(now)?;
        let deadline = self.require_domain(deadline)?;
        // Only the observation-side margins apply here: we are asserting that
        // the deadline is behind us even accounting for a stale view.
        let lag = self
            .finality_margin
            .checked_add(self.rpc_lag_margin)
            .ok_or(TimelockError::Overflow)?;
        let threshold = deadline.checked_add(lag).ok_or(TimelockError::Overflow)?;
        if now < threshold {
            return Err(TimelockError::WindowTooNarrow {
                remaining: threshold.saturating_sub(now),
                required: lag,
            });
        }
        Ok(())
    }
}

/// An operator-declared correspondence between two timelock domains.
///
/// Constructing one is the *only* way to move a value between domains, and
/// constructing one is an explicit statement: "on this deployment,
/// `from_units_per_step` units of `from` correspond to `to_units_per_step`
/// units of `to`, and `from_anchor` is the same instant as `to_anchor`". The
/// harness never manufactures such a statement on its own, because it is not
/// derivable from anything it can observe: a chain's block interval is an
/// empirical property, not a constant.
///
/// The rate is a ratio rather than a single number so that both directions are
/// expressible in integers: 12 seconds per block is `(12, 1)` going
/// timestamp→height and `(1, 12)` going height→timestamp.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeclaredDomainBridge {
    from: TimelockDomain,
    to: TimelockDomain,
    from_anchor: u64,
    to_anchor: u64,
    from_units_per_step: u64,
    to_units_per_step: u64,
}

impl DeclaredDomainBridge {
    /// Declares the correspondence. Fails closed on a degenerate declaration:
    /// the two domains must differ, and neither side of the ratio may be zero.
    pub fn declare(
        from: TimelockDomain,
        to: TimelockDomain,
        from_anchor: u64,
        to_anchor: u64,
        from_units_per_step: u64,
        to_units_per_step: u64,
    ) -> core::result::Result<Self, TimelockError> {
        if from == to || from_units_per_step == 0 || to_units_per_step == 0 {
            return Err(TimelockError::DegenerateBridge);
        }
        Ok(Self {
            from,
            to,
            from_anchor,
            to_anchor,
            from_units_per_step,
            to_units_per_step,
        })
    }

    /// Source domain.
    pub const fn from_domain(&self) -> TimelockDomain {
        self.from
    }

    /// Target domain.
    pub const fn to_domain(&self) -> TimelockDomain {
        self.to
    }

    /// Converts a point, rounding **away from optimism**: a point after the
    /// anchor is rounded down (it arrives sooner than the ratio suggests), a
    /// point before the anchor is rounded further back. Either way the
    /// converted value never claims more time than the declaration supports.
    pub fn convert(
        &self,
        point: TimelockPoint,
    ) -> core::result::Result<TimelockPoint, TimelockError> {
        if point.domain != self.from {
            return Err(TimelockError::DomainsNotDeclaredCompatible {
                from: point.domain,
                to: self.to,
            });
        }
        let value = if point.value >= self.from_anchor {
            let delta = point.value - self.from_anchor;
            let scaled = delta
                .checked_mul(self.to_units_per_step)
                .ok_or(TimelockError::Overflow)?
                / self.from_units_per_step;
            self.to_anchor
                .checked_add(scaled)
                .ok_or(TimelockError::Overflow)?
        } else {
            let delta = self.from_anchor - point.value;
            let scaled = delta
                .checked_mul(self.to_units_per_step)
                .ok_or(TimelockError::Overflow)?
                .div_ceil(self.from_units_per_step);
            self.to_anchor.saturating_sub(scaled)
        };
        Ok(TimelockPoint {
            domain: self.to,
            value,
        })
    }
}

/// The single crossing point between timelock domains.
///
/// - Same domain in and out: returned unchanged. No conversion happened.
/// - Different domains and `declared` is `None`, or names other domains:
///   [`TimelockError::DomainsNotDeclaredCompatible`]. **Never** a guess.
pub fn bridge(
    point: TimelockPoint,
    to: TimelockDomain,
    declared: Option<&DeclaredDomainBridge>,
) -> core::result::Result<TimelockPoint, TimelockError> {
    if point.domain == to {
        return Ok(point);
    }
    let Some(b) = declared else {
        return Err(TimelockError::DomainsNotDeclaredCompatible {
            from: point.domain,
            to,
        });
    };
    if b.from != point.domain || b.to != to {
        return Err(TimelockError::DomainsNotDeclaredCompatible {
            from: point.domain,
            to,
        });
    }
    b.convert(point)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn margins_are_named_summed_and_non_zero() {
        let p = TimelockPolicy::evm();
        assert_eq!(p.total_margin(), Ok(TOTAL_MARGIN_SECS));
        assert_eq!(TOTAL_MARGIN_SECS, 3_600, "one hour of EVM-side margin");
        let d = TimelockPolicy::dom_sim();
        assert_eq!(d.total_margin(), Ok(TOTAL_MARGIN_BLOCKS));
        assert_eq!(TOTAL_MARGIN_BLOCKS, 20);
        for m in [
            p.finality_margin,
            p.rpc_lag_margin,
            p.propagation_margin,
            p.reaction_margin,
        ] {
            assert!(m > 0, "every margin must pay for something");
        }
    }

    #[test]
    fn a_point_from_the_wrong_domain_is_refused() {
        let p = TimelockPolicy::evm();
        assert_eq!(
            p.require_domain(TimelockPoint::height(10)),
            Err(TimelockError::DomainMismatch {
                expected: TimelockDomain::Timestamp,
                got: TimelockDomain::BlockHeight,
            })
        );
        assert_eq!(p.require_domain(TimelockPoint::timestamp(10)), Ok(10));
    }

    #[test]
    fn a_narrow_window_is_refused_and_a_wide_one_is_not() {
        let p = TimelockPolicy::evm();
        let now = TimelockPoint::timestamp(1_000_000);
        let tight = TimelockPoint::timestamp(1_000_000 + TOTAL_MARGIN_SECS - 1);
        assert_eq!(
            p.require_actionable(now, tight),
            Err(TimelockError::WindowTooNarrow {
                remaining: TOTAL_MARGIN_SECS - 1,
                required: TOTAL_MARGIN_SECS,
            })
        );
        let exact = TimelockPoint::timestamp(1_000_000 + TOTAL_MARGIN_SECS);
        assert_eq!(p.require_actionable(now, exact), Ok(TOTAL_MARGIN_SECS));
    }

    #[test]
    fn a_passed_deadline_is_not_actionable() {
        let p = TimelockPolicy::evm();
        assert_eq!(
            p.require_actionable(TimelockPoint::timestamp(10), TimelockPoint::timestamp(9)),
            Err(TimelockError::DeadlinePassed)
        );
    }

    #[test]
    fn expiry_requires_the_observation_margins_too() {
        let p = TimelockPolicy::evm();
        let deadline = TimelockPoint::timestamp(2_000);
        let lag = FINALITY_MARGIN_SECS + RPC_LAG_MARGIN_SECS;
        // Just past the deadline is not enough: our view could be stale.
        assert!(p
            .require_expired(TimelockPoint::timestamp(2_001), deadline)
            .is_err());
        assert_eq!(
            p.require_expired(TimelockPoint::timestamp(2_000 + lag), deadline),
            Ok(())
        );
    }

    #[test]
    fn overflowing_margin_sets_fail_closed_in_both_directions() {
        let p = TimelockPolicy {
            domain: TimelockDomain::Timestamp,
            finality_margin: u64::MAX,
            rpc_lag_margin: 1,
            propagation_margin: 0,
            reaction_margin: 0,
        };

        assert_eq!(
            p.require_actionable(
                TimelockPoint::timestamp(0),
                TimelockPoint::timestamp(u64::MAX),
            ),
            Err(TimelockError::Overflow)
        );
        assert_eq!(
            p.require_expired(
                TimelockPoint::timestamp(u64::MAX),
                TimelockPoint::timestamp(0),
            ),
            Err(TimelockError::Overflow)
        );
    }

    #[test]
    fn crossing_domains_without_a_declaration_always_fails() {
        let ts = TimelockPoint::timestamp(1_800_000_000);
        assert_eq!(
            bridge(ts, TimelockDomain::BlockHeight, None),
            Err(TimelockError::DomainsNotDeclaredCompatible {
                from: TimelockDomain::Timestamp,
                to: TimelockDomain::BlockHeight,
            })
        );
        // Identity is not a conversion, so it is allowed and changes nothing.
        assert_eq!(bridge(ts, TimelockDomain::Timestamp, None), Ok(ts));
    }

    #[test]
    fn a_declared_bridge_converts_and_only_between_the_declared_domains() {
        // 12 seconds per block, anchored at (timestamp 1_000_000, height 500).
        let b = DeclaredDomainBridge::declare(
            TimelockDomain::Timestamp,
            TimelockDomain::BlockHeight,
            1_000_000,
            500,
            12,
            1,
        )
        .expect("well-formed declaration");
        assert_eq!(
            bridge(
                TimelockPoint::timestamp(1_000_120),
                TimelockDomain::BlockHeight,
                Some(&b)
            ),
            Ok(TimelockPoint::height(510))
        );
        // Rounds down in the future: 1_000_119 is not yet block 510.
        assert_eq!(
            b.convert(TimelockPoint::timestamp(1_000_119)),
            Ok(TimelockPoint::height(509))
        );
        // The reverse direction was not declared.
        assert_eq!(
            bridge(
                TimelockPoint::height(510),
                TimelockDomain::Timestamp,
                Some(&b)
            ),
            Err(TimelockError::DomainsNotDeclaredCompatible {
                from: TimelockDomain::BlockHeight,
                to: TimelockDomain::Timestamp,
            })
        );
    }

    #[test]
    fn degenerate_declarations_are_refused() {
        assert_eq!(
            DeclaredDomainBridge::declare(
                TimelockDomain::Timestamp,
                TimelockDomain::Timestamp,
                0,
                0,
                12,
                1
            ),
            Err(TimelockError::DegenerateBridge)
        );
        for (a, b) in [(0u64, 1u64), (1, 0)] {
            assert_eq!(
                DeclaredDomainBridge::declare(
                    TimelockDomain::Timestamp,
                    TimelockDomain::BlockHeight,
                    0,
                    0,
                    a,
                    b
                ),
                Err(TimelockError::DegenerateBridge)
            );
        }
    }

    #[test]
    fn the_ratio_expresses_both_directions_in_integers() {
        // Height -> timestamp on a 12 s chain: one block is twelve seconds.
        let up = DeclaredDomainBridge::declare(
            TimelockDomain::BlockHeight,
            TimelockDomain::Timestamp,
            0,
            0,
            1,
            12,
        )
        .expect("declaration");
        assert_eq!(
            up.convert(TimelockPoint::height(10)),
            Ok(TimelockPoint::timestamp(120))
        );
    }

    #[test]
    fn conversion_of_a_past_point_rounds_away_from_optimism() {
        let b = DeclaredDomainBridge::declare(
            TimelockDomain::Timestamp,
            TimelockDomain::BlockHeight,
            1_000_000,
            500,
            12,
            1,
        )
        .expect("declaration");
        // One second before the anchor is a whole block earlier, never the
        // same block.
        assert_eq!(
            b.convert(TimelockPoint::timestamp(999_999)),
            Ok(TimelockPoint::height(499))
        );
        assert_eq!(
            b.convert(TimelockPoint::timestamp(999_988)),
            Ok(TimelockPoint::height(499))
        );
    }
}
