// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ConditionLockCoreV2} from "./ConditionLockCoreV2.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title ConditionLockERC20V2
/// @notice ERC-20 EVM leg of a DOM<->EVM settlement.
/// @dev Same settlement semantics as `ConditionLockV2`; only the asset
///      movement differs. Foundation Document v0.2.1 section 2.3 and decision
///      D-002.
///
///      No privileged path of any kind: no stored operator, no halt switch, no
///      upgrade hook, no rescue or sweep (invariant I2). In particular there is
///      deliberately no way to move tokens that were sent here by mistake -
///      such a way would be exactly the privileged path the invariant forbids.
///
///      Token policy is fail-closed rather than accommodating:
///      * `open` measures the real balance delta and rejects anything that is
///        not exactly `terms.amount`, so fee-on-transfer, deflationary and
///        rebasing tokens are refused at the door instead of silently
///        under-funding a lock that promises `amount` to the beneficiary;
///      * an asset whose `balanceOf` will not answer a gas-capped probe is
///        rejected at `open`, because a payout that cannot be measured is a
///        payout this contract would have to take the asset's word for;
///      * on the payout path nothing the asset SAYS is believed. What it
///        returns from `transfer` is ignored entirely; only the measured
///        balance delta and the EVM-level call status decide what was
///        delivered. See `_deliver`;
///      * the payout push is gas-capped and returndata-bounded, so an asset
///        that blacklists the beneficiary, reverts, burns gas or returns a huge
///        buffer degrades to a pull credit instead of blocking settlement.
///
///      Note on the stipend: a minimal ERC-20 `transfer` to a destination whose
///      balance slot is still zero measures 23,736 gas, so it fits inside
///      `PAYOUT_GAS_STIPEND` (30,000) with about 6.3k to spare. Tokens that do
///      more per transfer - hooks, snapshots, per-transfer bookkeeping - exceed
///      it and land in the pull path. That is the intended degradation: the
///      beneficiary always ends up entitled to exactly `amount`, and only the
///      number of transactions changes. The suite pins both sides of that line.
contract ConditionLockERC20V2 is ConditionLockCoreV2 {
    /// @notice `terms.asset` has no code; it cannot be an ERC-20.
    error NotAContract();
    /// @notice The measured balance delta did not equal `terms.amount`.
    /// @dev Fee-on-transfer, deflationary and rebasing tokens land here.
    error InexactTransfer(uint256 expected, uint256 received);

    /// @dev Gas cap for every `balanceOf` probe, at `open` and on the payout
    ///      path alike. The two must use the SAME cap, and that is the whole
    ///      point of the constant existing: if `open` measured with the full
    ///      remaining budget while the payout measured under a cap, a token
    ///      could answer at the door and refuse afterwards purely by reading
    ///      `gasleft()`, and thereby choose which branch of `_deliver` judges
    ///      it. Making the two calls indistinguishable removes that oracle.
    ///
    ///      Sized generously rather than tightly, because being unmeasurable
    ///      under the cap is now grounds for rejection at `open`, and rejecting
    ///      an honest asset is a real cost:
    ///        * a plain mapping lookup is ~2_400 (dispatch, one cold SLOAD);
    ///        * a rebasing balance (shares times an index) adds a few SLOADs
    ///          and a mulDiv: under 12_000;
    ///        * a proxy adds a cold DELEGATECALL: ~3_300;
    ///      50_000 is roughly twenty cold SLOADs of headroom over the most
    ///      expensive shape in circulation, while still being far too little
    ///      for a hostile `balanceOf` to consume a settlement's gas budget.
    uint256 internal constant BALANCE_QUERY_GAS_CAP = 50_000;

    /// @dev Minimum `gasleft()` before a push is attempted here. Larger than the
    ///      base floor because an ERC-20 push is three calls, not one. Worst
    ///      case, in order:
    ///        * `balanceOf` probe: 2_600 cold account access, then 50_000
    ///          forwarded, which needs 50_794 available for the 63/64 reserve;
    ///        * `transfer`: 100 warm access, then 30_000 forwarded, needing
    ///          30_476 available;
    ///        * `balanceOf` probe: 100 warm access, then 50_000 forwarded;
    ///        * shortfall bookkeeping: cold SSTORE from zero 22_100 plus the
    ///          `PayoutDeferred` log ~1_500;
    ///        * payload encoding and general overhead: ~7_500.
    ///      That totals about 164_000, and the figure is confirmed rather than
    ///      assumed: `test_floorIsSufficientForTheGreediestMeasuredPush` drives
    ///      an asset whose every probe consumes its entire cap and still
    ///      answers, and finds that such a push completes with roughly 170_000
    ///      available. 200_000 keeps about 36_000 of slack on top.
    ///
    ///      The slack matters in one direction only: if a push is attempted and
    ///      the bookkeeping afterwards cannot fit, the whole claim runs out of
    ///      gas and reverts. Nothing is lost - the revert is atomic and
    ///      `Claimed(t)` goes with it - but the claimer's gas is wasted, so the
    ///      floor errs high. Erring much higher is not free either: below the
    ///      floor the push is skipped and the amount is credited for pull,
    ///      which is safe but costs the payee a second transaction, so an
    ///      inflated floor would push ordinary payouts onto the pull path for
    ///      no benefit.
    ///
    ///      Operational consequence of having a floor at all, on either leg:
    ///      the deferred path succeeds at a much lower gas limit than the push
    ///      path needs, and `eth_estimateGas` binary-searches for the lowest
    ///      SUCCEEDING limit. A caller who takes the estimate at face value
    ///      therefore lands on the deferral every time and never sees the
    ///      optimistic push. Integrators who want the one-transaction happy
    ///      path must add headroom above the estimate deliberately - roughly
    ///      this floor plus the cost of reaching it. Nothing is at risk either
    ///      way; it is a UX cliff, and it is the reason the floor is kept as
    ///      low as the derivation allows.
    uint256 internal constant PAYOUT_GAS_FLOOR_ERC20 = 200_000;

    /// @notice `terms.asset` did not answer a capped `balanceOf` probe.
    /// @dev An asset whose balance cannot be read cannot have its payouts
    ///      measured, and an unmeasurable payout is exactly the condition under
    ///      which this contract has to guess. Refusing at the door is the only
    ///      point where refusing is free.
    error UnmeasurableAsset();

    /// @dev The ERC-20 variant never handles the native asset, and never
    ///      handles a codeless address. `address(0)` is the ecrecover
    ///      precompile and every other codeless address is just as accepting: a
    ///      CALL to one succeeds, returns nothing and moves nothing. `address(0)`
    ///      is only the most obvious member of that set, so the check is on the
    ///      property, not on the one address.
    function _requireSupportedAsset(address asset) internal view override {
        if (asset == address(0)) revert AssetMismatch();
        if (asset.code.length == 0) revert NotAContract();
    }

    function _payoutGasFloor() internal pure override returns (uint256) {
        return PAYOUT_GAS_FLOOR_ERC20;
    }

    /// @dev Pulls exactly `amount` from the funder, or reverts.
    ///
    ///      Custody is measured through the SAME capped probe the payout path
    ///      uses, and an asset that cannot answer it is rejected outright. Two
    ///      reasons, both load-bearing:
    ///        * an asset whose balance cannot be read cannot have its payouts
    ///          measured, and this is the last moment at which refusing costs
    ///          nothing - after `open` the funds are committed and the payout
    ///          path is not allowed to revert;
    ///        * using the ordinary interface here, with the whole remaining gas
    ///          budget, while the payout path probes under a cap would hand the
    ///          asset a free oracle: `require(gasleft() >= X)` inside
    ///          `balanceOf` would pass at the door and fail at every payout,
    ///          letting the asset pick the branch that judges it. Identical
    ///          calls, identical cap, no oracle.
    ///
    ///      A funder who supplies too little gas for the probe to run at its
    ///      full cap sees this revert rather than a lock on an asset that will
    ///      later be unmeasurable. Fail-closed, and retryable with more gas.
    function _takeCustody(address asset, uint256 amount) internal override {
        _requireSupportedAsset(asset);
        // This contract never custodies ETH; accepting it would create a
        // balance no lock accounts for and no path could ever move it out.
        if (msg.value != 0) revert ValueMismatch();

        (bool measuredBefore, uint256 balanceBefore) = _probeBalance(asset);
        if (!measuredBefore) revert UnmeasurableAsset();

        SafeERC20.safeTransferFrom(IERC20(asset), msg.sender, address(this), amount);

        (bool measuredAfter, uint256 balanceAfter) = _probeBalance(asset);
        if (!measuredAfter) revert UnmeasurableAsset();

        // Reverts on underflow if the balance somehow went down, which is the
        // correct fail-closed outcome for an asset that misbehaves this badly.
        uint256 received = balanceAfter - balanceBefore;
        if (received != amount) revert InexactTransfer(amount, received);
    }

    /// @dev Gas-capped, returndata-bounded `transfer`. Never bubbles a revert,
    ///      so `Claimed(t)` can never be undone by the token or the recipient.
    ///
    ///      `assumeDeliveredWhenUnmeasured` is TRUE here. On this path an
    ///      unproven delivery must never become a credit: custody is pooled per
    ///      asset, so a credit booked against value that may already have left
    ///      is a liability every other lock's funds have to honour. Assuming
    ///      delivery confines the whole cost to the lock that chose the asset.
    ///
    ///      What that costs, stated rather than glossed: an asset that is
    ///      unmeasurable AND completes `transfer` without moving anything
    ///      leaves its payee with no tokens and no credit, and the custody
    ///      behind that lock then has no claimant at all. There is no sweep and
    ///      no recovery path, by design - one would be the privileged path
    ///      invariant I2 forbids, and it would be reachable by exactly the
    ///      party a sweep is supposed to protect against. The alternative
    ///      default would trade this for an unbacked liability against other
    ///      locks' funds, which is strictly worse: it moves the loss onto
    ///      parties who never chose the asset. Confining it here is the correct
    ///      half of the trade, not a costless one.
    function _tryPushPayout(address to, address asset, uint256 amount) internal override returns (uint256) {
        return _deliver(asset, to, amount, PAYOUT_GAS_STIPEND, true);
    }

    /// @dev Full-gas `transfer` used by the pull path.
    ///
    ///      `assumeDeliveredWhenUnmeasured` is FALSE here, which is the same
    ///      conservatism pointing the other way. This path is allowed to
    ///      revert, so an unproven delivery costs nothing to refuse: the
    ///      withdrawal reverts, the credit stays exactly where it was, and the
    ///      creditor can retry. Assuming delivery here would destroy a standing
    ///      credit on an asset's say-so, which is the mirror image of minting
    ///      one and is never necessary.
    function _pullTransfer(address to, address asset, uint256 amount) internal override returns (uint256) {
        return _deliver(asset, to, amount, gasleft(), false);
    }

    /// @dev Moves up to `amount` of `asset` to `to` and reports how much
    ///      PROVABLY left this contract's custody.
    ///
    ///      Nothing the asset SAYS is used. The return payload of `transfer` is
    ///      chosen by the asset and is therefore not evidence: an asset can move
    ///      the balance and then report failure, or report success and move
    ///      nothing, and either claim taken at face value corrupts the credit.
    ///      Only two things here are facts rather than claims:
    ///
    ///      1. THE CALL STATUS. A CALL that returns 0 means the callee frame
    ///         reverted or ran out of gas, and the EVM has already undone every
    ///         state change it made. So a failed call provably delivered
    ///         nothing. This is an EVM guarantee, not the asset's word, which is
    ///         why it is safe to act on while `returndata` is not.
    ///      2. THE MEASURED BALANCE DELTA. Two `balanceOf(address(this))` probes
    ///         bracketing the transfer. When both answer, the decrease is what
    ///         actually left, whatever the asset claims.
    ///
    ///      The delta is authoritative in BOTH directions, and the direction
    ///      that is easy to overlook deserves saying plainly: a `transfer` that
    ///      explicitly returns `false` while the probes report a drop counts as
    ///      delivered. An asset that lies downwards about its own balance can
    ///      therefore zero a payee's entitlement on that lock without paying
    ///      them. That is the SAFE half of the trade - no credit is minted, so
    ///      no other lock's custody is touched, and the damage stops at the lock
    ///      that chose the asset - and it is not a regression, because before
    ///      any of this an asset returning `true` without moving anything
    ///      produced the identical outcome. It is still a real loss for that
    ///      payee, and choosing an asset is choosing to trust it.
    ///
    ///      When the probes cannot be read there is nothing left to reason from,
    ///      and the two callers want opposite defaults - see
    ///      `assumeDeliveredWhenUnmeasured` at each call site. Neither default
    ///      consults the payload, so an asset cannot improve its outcome by
    ///      lying; the worst it can do by being unmeasurable is strand its own
    ///      payee. It cannot do that for long either: `_takeCustody` probes with
    ///      the same cap and refuses to open a lock on an asset that will not
    ///      answer, so reaching this branch at all requires an asset that
    ///      answered at the door and stopped answering later.
    ///
    ///      The probes are `staticcall`s with their own gas cap and a 32-byte
    ///      return area, because this runs after `Claimed(t)` was emitted: a
    ///      `balanceOf` that reverts, loops or returns megabytes must degrade,
    ///      never propagate.
    ///
    ///      KNOWN RESIDUE. Measurement defeats an asset that lies about its
    ///      return payload, because the balance is a second and independent
    ///      source. It does not defeat an asset that lies about the balance
    ///      itself: one that moves the value and then reports an unchanged
    ///      balance reads as a zero delta, and a credit is booked for value
    ///      that has gone. Nothing on chain can close that - if the asset's own
    ///      ledger is fiction there is no source of truth left, and the same
    ///      lie defeats `_takeCustody`'s exact-accounting check too. What
    ///      changed is the bar: a phantom credit used to need only a truthful
    ///      asset with an unusual return payload, a shape real tokens have; it
    ///      now needs one that actively misreports `balanceOf`.
    ///
    ///      The full shape is worth knowing, because minting the credit is only
    ///      half of it: while the asset keeps lying, THE SAME LIE BLOCKS THE
    ///      PULL. `_withdraw` requires the measured delta to equal the
    ///      instalment, and an asset frozen at a constant balance measures zero,
    ///      so the withdrawal reverts `PayoutFailed`. Realising the phantom
    ///      credit therefore requires the asset to lie at push time and tell the
    ///      truth at pull time. That is a deliberate two-phase act, not a static
    ///      misconfiguration - which is what makes this an exploitable residue
    ///      rather than a merely on-paper insolvency, and why it is recorded
    ///      here instead of being dismissed. Pinned end to end by
    ///      `test_assetLyingUpwardAboutItsBalanceCanStillMintAPhantomCredit`.
    function _deliver(address asset, address to, uint256 amount, uint256 gasCap, bool assumeDeliveredWhenUnmeasured)
        private
        returns (uint256)
    {
        (bool measuredBefore, uint256 balanceBefore) = _probeBalance(asset);

        bool callSucceeded = _callTransfer(asset, to, amount, gasCap);

        (bool measuredAfter, uint256 balanceAfter) = _probeBalance(asset);

        // Fact 1: the frame reverted, so the EVM rolled back anything it did.
        if (!callSucceeded) return 0;

        // Fact 2: the measured decrease.
        if (measuredBefore && measuredAfter) {
            // A balance that went UP (the asset minted to us, or a reentrant
            // hook deposited) means nothing left our account: report zero
            // rather than underflow.
            uint256 moved = balanceBefore > balanceAfter ? balanceBefore - balanceAfter : 0;

            // Clamp. An asset that drains more than it was asked for is
            // stealing from pooled custody; it must never be credited for the
            // excess, because that would silently retire other locks'
            // liabilities. Nothing here can stop such an asset from stealing -
            // only from being paid twice for it.
            return moved > amount ? amount : moved;
        }

        return assumeDeliveredWhenUnmeasured ? amount : 0;
    }

    /// @dev `IERC20.transfer` with an explicit gas cap, discarding returndata.
    ///      Written in assembly rather than delegated to `SafeERC20` because
    ///      `SafeERC20` neither caps the forwarded gas nor bounds the copied
    ///      returndata, and both are required on a path that runs after
    ///      `Claimed(t)` and must not bubble a revert.
    /// @return True if the call frame completed, false if it reverted or ran
    ///         out of gas. Deliberately NOT a judgement about whether the
    ///         transfer "worked": the return payload is never read, so a
    ///         zero-length return area is used and the asset cannot influence
    ///         this answer beyond succeeding or failing.
    function _callTransfer(address asset, address to, uint256 amount, uint256 gasCap) private returns (bool) {
        bytes memory payload = abi.encodeWithSelector(IERC20.transfer.selector, to, amount);
        bool success;
        assembly ("memory-safe") {
            success := call(gasCap, asset, 0, add(payload, 0x20), mload(payload), 0, 0)
        }
        return success;
    }

    /// @dev Bounded, non-reverting `balanceOf(address(this))`.
    /// @return measured True only if the probe returned exactly one word.
    /// @return value The reported balance, meaningless unless `measured`.
    function _probeBalance(address asset) private view returns (bool measured, uint256 value) {
        bytes memory payload = abi.encodeWithSelector(IERC20.balanceOf.selector, address(this));
        uint256 cap = BALANCE_QUERY_GAS_CAP;
        bool success;
        uint256 returnSize;
        uint256 returnWord;
        assembly ("memory-safe") {
            success := staticcall(cap, asset, add(payload, 0x20), mload(payload), 0x00, 0x20)
            returnSize := returndatasize()
            returnWord := mload(0x00)
        }
        // A short or oversized answer is not a balance. Treat it as unmeasured
        // rather than guessing.
        measured = success && returnSize == 32;
        value = measured ? returnWord : 0;
    }
}
