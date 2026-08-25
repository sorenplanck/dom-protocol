//! Gas limits for the EVM leg's settlement calls, and why they are constants.
//!
//! # `eth_estimateGas` picks the wrong branch (audit finding I, P2)
//!
//! `ConditionLockCoreV2._payout` only attempts the optimistic push when
//! `gasleft() >= _payoutGasFloor()`. Below that floor it skips the push
//! entirely, books the whole amount as a pull credit and emits
//! `PayoutDeferred`. Crucially, **that path succeeds**: D-002 requires the
//! payout never to revert, so a deferred payout is a successful transaction.
//!
//! `eth_estimateGas` binary-searches for the lowest limit at which the
//! transaction *succeeds*. It therefore converges on the deferred path and
//! returns a limit far below the floor. The audit that found this reported, for
//! the ERC-20 deployment with an ordinary well-behaved token: completes at
//! 57 250, pushes at 230 500, a gap of 173 250 a caller must add by hand.
//!
//! Re-measured against the **delivered** bytecode by
//! `anvil_settlement_gas_limits_clear_the_deployed_push_threshold`, which reads
//! the estimate straight from the node and binary-searches the push threshold
//! at 250 gas of resolution:
//!
//! | leg | `eth_estimateGas` | pushes at | gap |
//! |---|---|---|---|
//! | native (`ConditionLockV2`) | 96 836 | 166 250 | 69 414 |
//! | ERC-20 (`ConditionLockERC20V2`, plain token) | 96 836 | 270 250 | 173 414 |
//!
//! Two things about that table are worth stating rather than leaving to be
//! noticed:
//!
//! * **The two estimates are identical, and that is not a copy-paste error.**
//!   On the deferred path neither contract touches its asset at all — the push
//!   is skipped before `_tryPushPayout` is reached — so what the estimator
//!   prices is the same asset-agnostic work in both cases: the claim, the
//!   `Claimed` log, one cold `pendingWithdrawals` write and the
//!   `PayoutDeferred` log. The legs only diverge *above* their floors, which is
//!   precisely the region the estimator never explores.
//! * **The ERC-20 gap reproduces the audit's to within 164 gas** (173 414 vs
//!   173 250), from a different storage-warmth baseline. The absolute figures
//!   move with how warm the slots are; the gap is the finding, and it is
//!   stable.
//!
//! An estimator-driven caller therefore never pushes. Every beneficiary pays
//! for a second `withdraw` transaction, the 30 000-gas stipend the contract was
//! tuned around is never exercised, and nothing anywhere reports a problem —
//! the transactions all succeed. That is a silent, permanent degradation of the
//! happy path, which is exactly the shape of bug a harness is supposed to catch
//! rather than reproduce.
//!
//! So the harness does not estimate. It fills the unsigned artifact's
//! `gas_limit_hint` from the constants below and broadcasts with an explicit
//! `--gas-limit`.
//!
//! # How the limits are derived
//!
//! Two measured quantities per leg — the completion threshold and the *push*
//! threshold — and then headroom on top of the push threshold. Headroom is not
//! decoration; three things can legitimately move the real cost above what was
//! measured on a quiet dev chain:
//!
//! 1. **Cold storage.** The measurement ran with the beneficiary's balance slot
//!    and the `pendingWithdrawals` slot in whatever state the scenario left
//!    them. A cold `SSTORE` from zero is 22 100 and a cold account access is
//!    2 600; a first-ever payout to a fresh beneficiary pays several of those.
//! 2. **The contract's own floor may rise.** `PAYOUT_GAS_FLOOR_ERC20` is
//!    200 000 today and is documented as sized against a ~164 000 worst case.
//!    A future tightening of that analysis moves the push threshold with it.
//! 3. **Asset variation.** The measurement used a minimal token. An honest
//!    token that does a little more per transfer raises the floor check's
//!    denominator without being hostile.
//!
//! Over-supplying gas is close to free — unused gas is refunded, and the only
//! cost is a larger up-front balance requirement. Under-supplying it costs the
//! beneficiary a whole extra transaction, every single time. The asymmetry is
//! stark, so the headroom is generous rather than tight.
//!
//! # These numbers are pinned by test, not by trust
//!
//! [`ERC20_SETTLEMENT_GAS_LIMIT`] and [`NATIVE_SETTLEMENT_GAS_LIMIT`] are
//! asserted against the recorded thresholds here, and — far more importantly —
//! the Anvil suite *measures the push threshold against the deployed bytecode*
//! by binary search and fails if a constant no longer clears it. A change to
//! `PAYOUT_GAS_FLOOR_ERC20` that outruns these values breaks a test instead of
//! silently degrading every payout to pull.

/// What `eth_estimateGas` returns for an ERC-20 `claim`.
///
/// Read from the node, not searched for: a search would be confounded by its
/// own side effects, because each succeeding probe warms and populates the
/// `pendingWithdrawals` slot the next probe then writes more cheaply. Measured
/// against `ConditionLockERC20V2` with a plain ERC-20 on Anvil 1.7.1, with that
/// slot cold — the state a first payout is actually in.
pub const ERC20_CLAIM_ESTIMATED_GAS: u64 = 96_836;

/// Lowest gas limit at which an ERC-20 `claim` actually performs the push.
///
/// Measured, same conditions. Above `PAYOUT_GAS_FLOOR_ERC20` (200 000) by the
/// cost of everything the contract does before reaching `_payout`, and by the
/// EIP-150 63/64 reserve the floor check has to leave behind.
pub const ERC20_CLAIM_PUSH_GAS: u64 = 270_250;

/// What `eth_estimateGas` returns for a native `claim`.
///
/// Equal to the ERC-20 figure, for the reason given in the module header: the
/// deferred path is asset-agnostic. The native leg has the same estimator
/// hazard with a lower floor (`PAYOUT_GAS_FLOOR` is 96 000), so it degrades
/// just as silently.
pub const NATIVE_CLAIM_ESTIMATED_GAS: u64 = 96_836;

/// Lowest gas limit at which a native `claim` actually performs the push.
pub const NATIVE_CLAIM_PUSH_GAS: u64 = 166_250;

/// Multiplier applied to a measured push threshold, in percent.
///
/// 175 % — i.e. 75 % headroom. Sized to absorb, simultaneously: a first-ever
/// payout paying cold `SSTORE`s it did not pay during the measurement
/// (~50 000), the contract's documented worst-case floor analysis being
/// tightened upward, and an honest asset that costs somewhat more per transfer
/// than the minimal one measured. Deliberately a round, explainable number
/// rather than a fitted one: a tight fit here would need re-fitting on every
/// contract change, and the cost of being generous is refunded gas.
pub const PUSH_HEADROOM_PERCENT: u64 = 175;

/// Gas limit the harness puts on every ERC-20-leg settlement call.
///
/// `ERC20_CLAIM_PUSH_GAS * 175 % = 472 937`, rounded to the nearest
/// [`ROUNDING_GRANULARITY_GAS`]. `open` on this leg is cheaper than a pushing
/// `claim` (a `transferFrom` and two capped `balanceOf` probes), so one
/// constant covers the whole leg rather than three that would drift apart.
pub const ERC20_SETTLEMENT_GAS_LIMIT: u64 = 450_000;

/// Gas limit the harness puts on every native-leg settlement call.
///
/// `NATIVE_CLAIM_PUSH_GAS * 175 % = 290 937`, rounded to the nearest
/// [`ROUNDING_GRANULARITY_GAS`].
pub const NATIVE_SETTLEMENT_GAS_LIMIT: u64 = 300_000;

/// Granularity the derived limits are rounded to.
///
/// The derivation produces awkward numbers (403 375, 218 750); a limit that
/// appears in a report and in a `--gas-limit` argument is easier to reason
/// about when it is round. Rounding is bounded by a tripwire below, so it can
/// never quietly become a second, undocumented safety factor.
pub const ROUNDING_GRANULARITY_GAS: u64 = 50_000;

/// The gas limit to use for a settlement call on a leg holding `asset`.
///
/// `address(0)` is the native leg; anything else is the ERC-20 leg, whose
/// payout path has a much higher floor.
pub const fn settlement_gas_limit(asset: &[u8; 20]) -> u64 {
    let mut i = 0;
    while i < 20 {
        if asset[i] != 0 {
            return ERC20_SETTLEMENT_GAS_LIMIT;
        }
        i += 1;
    }
    NATIVE_SETTLEMENT_GAS_LIMIT
}

/// `threshold` scaled by [`PUSH_HEADROOM_PERCENT`], saturating.
pub const fn with_headroom(threshold: u64) -> u64 {
    match threshold.checked_mul(PUSH_HEADROOM_PERCENT) {
        Some(v) => v / 100,
        None => u64::MAX,
    }
}

// ---------------------------------------------------------------------------
// Compile-time tripwires
// ---------------------------------------------------------------------------
//
// These are relationships between constants, so they are checked at compile
// time rather than by a test: a violation should break the build, not wait for
// somebody to run the suite. The *empirical* half — that these limits still
// clear the threshold of the actually deployed bytecode — is the Anvil test
// `anvil_settlement_gas_limits_clear_the_deployed_push_threshold`.

/// A settlement call must be given enough gas for the contract to take the push
/// branch. Anything less silently degrades every payout to pull.
const _: () = assert!(ERC20_SETTLEMENT_GAS_LIMIT >= ERC20_CLAIM_PUSH_GAS);
const _: () = assert!(NATIVE_SETTLEMENT_GAS_LIMIT >= NATIVE_CLAIM_PUSH_GAS);

/// Not merely "some" headroom: at least half again over the measured
/// threshold, so a shaved constant has to change this line too.
const _: () = assert!(ERC20_SETTLEMENT_GAS_LIMIT * 100 >= ERC20_CLAIM_PUSH_GAS * 150);
const _: () = assert!(NATIVE_SETTLEMENT_GAS_LIMIT * 100 >= NATIVE_CLAIM_PUSH_GAS * 150);

/// ...and each limit is the derived value rounded to
/// [`ROUNDING_GRANULARITY_GAS`], not an unexplained larger number: it must be a
/// multiple of the granularity and within one granularity of the derivation.
/// Without this, "headroom" could quietly absorb any future inflation.
const _: () = assert!(ERC20_SETTLEMENT_GAS_LIMIT % ROUNDING_GRANULARITY_GAS == 0);
const _: () = assert!(NATIVE_SETTLEMENT_GAS_LIMIT % ROUNDING_GRANULARITY_GAS == 0);
const _: () = assert!(
    ERC20_SETTLEMENT_GAS_LIMIT <= with_headroom(ERC20_CLAIM_PUSH_GAS) + ROUNDING_GRANULARITY_GAS
);
const _: () = assert!(
    NATIVE_SETTLEMENT_GAS_LIMIT <= with_headroom(NATIVE_CLAIM_PUSH_GAS) + ROUNDING_GRANULARITY_GAS
);

/// The estimator lands below the push threshold. If these ever converged,
/// `eth_estimateGas` would be safe again and this module could go away — so the
/// gap is asserted rather than assumed.
const _: () = assert!(ERC20_CLAIM_ESTIMATED_GAS < ERC20_CLAIM_PUSH_GAS);
const _: () = assert!(NATIVE_CLAIM_ESTIMATED_GAS < NATIVE_CLAIM_PUSH_GAS);
/// The gaps recorded in this module's table. On the ERC-20 leg the shortfall is
/// larger than the whole transaction the estimator thinks it is pricing, so an
/// estimator-driven caller is not marginally short — it is never going to push.
const _: () = assert!(ERC20_CLAIM_PUSH_GAS - ERC20_CLAIM_ESTIMATED_GAS == 173_414);
const _: () = assert!(NATIVE_CLAIM_PUSH_GAS - NATIVE_CLAIM_ESTIMATED_GAS == 69_414);

/// The ERC-20 payout floor is the higher of the two by construction.
const _: () = assert!(ERC20_SETTLEMENT_GAS_LIMIT > NATIVE_SETTLEMENT_GAS_LIMIT);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headroom_scales_and_never_wraps() {
        assert_eq!(with_headroom(100_000), 175_000);
        assert_eq!(with_headroom(0), 0);
        assert_eq!(with_headroom(u64::MAX), u64::MAX, "must saturate, not wrap");
    }

    #[test]
    fn the_leg_is_chosen_by_the_asset_not_by_a_flag() {
        assert_eq!(
            settlement_gas_limit(&[0u8; 20]),
            NATIVE_SETTLEMENT_GAS_LIMIT
        );
        // Every non-zero byte position must select the ERC-20 leg: a token
        // address is a token address wherever its bytes fall.
        for i in 0..20 {
            let mut token = [0u8; 20];
            token[i] = 1;
            assert_eq!(
                settlement_gas_limit(&token),
                ERC20_SETTLEMENT_GAS_LIMIT,
                "byte {i} must still mean `this is a token`"
            );
        }
    }

    #[test]
    fn the_estimator_gap_is_what_this_module_exists_for() {
        // The relationships are compile-time tripwires above; this records the
        // finding in a form that shows up in a test run.
        let gap = ERC20_CLAIM_PUSH_GAS - ERC20_CLAIM_ESTIMATED_GAS;
        assert_eq!(gap, 173_414, "the recorded ERC-20 estimator gap");
        assert!(
            ERC20_SETTLEMENT_GAS_LIMIT > ERC20_CLAIM_ESTIMATED_GAS + gap,
            "the pinned limit must sit above the push threshold, not merely \
             above what an estimator would return"
        );
    }
}
