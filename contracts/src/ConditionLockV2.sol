// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ConditionLockCoreV2} from "./ConditionLockCoreV2.sol";

/// @title ConditionLockV2
/// @notice Native-ETH EVM leg of a DOM<->EVM settlement.
/// @notice Funds are locked against the secret `t` whose point `T = t*G` was
///         fixed during setup. A successful `claim` reveals `t` on chain; that
///         event is what the DOM leg consumes through
///         `AdaptorPreSignatureV1::extract`.
/// @dev Foundation Document v0.2.1 section 2.3 and decision D-002. All the
///      settlement logic, the derivation and the payout policy live in
///      `ConditionLockCoreV2`; this contract only knows how to move ETH.
///
///      No privileged path of any kind: no stored operator, no halt switch, no
///      upgrade hook, no rescue or sweep (invariant I2). The contract has no
///      constructor, so nothing about a deployment can be parameterised.
contract ConditionLockV2 is ConditionLockCoreV2 {
    /// @dev The native variant only ever handles `asset == address(0)`.
    ///      Any other asset belongs to `ConditionLockERC20V2`, and mixing the
    ///      two would let a token-denominated lock be settled with ETH.
    ///      Note for off-chain consumers: this is also reached from
    ///      `withdraw` / `withdrawTo` / `withdrawAmount`, so naming any asset
    ///      other than `address(0)` there reverts `AssetMismatch` rather than
    ///      `NothingToWithdraw`. Both mean "no value moved"; `AssetMismatch`
    ///      additionally means the request named an asset this deployment
    ///      cannot move at all, and is never a transient condition.
    function _requireSupportedAsset(address asset) internal pure override {
        if (asset != address(0)) revert AssetMismatch();
    }

    function _takeCustody(address asset, uint256 amount) internal view override {
        _requireSupportedAsset(asset);
        // Exact accounting: the value carried must be exactly the committed
        // amount. Overpaying would silently donate ETH that no lock accounts
        // for, which the solvency invariant would then have to tolerate.
        if (msg.value != amount) revert ValueMismatch();
    }

    /// @dev Gas-capped, returndata-bounded push. Written in assembly on purpose:
    ///      * `call(..., 0, 0)` for the return area means returndata is never
    ///        copied into memory, so a target that returns megabytes cannot
    ///        charge the settlement for memory expansion (return bomb);
    ///      * the explicit gas cap stops a target from burning the whole block
    ///        gas limit and stops it from having enough gas to reenter;
    ///      * a revert in the target surfaces as `ok == false`, never as a
    ///        bubbled revert, so `Claimed(t)` can never be undone.
    ///
    ///      Unlike a token transfer, a value-bearing CALL is unambiguous: the
    ///      EVM itself moves the balance, and it does so if and only if the
    ///      call succeeds. There is nothing to measure and nothing to
    ///      misreport, so `ok` maps directly onto the delivered amount.
    function _tryPushPayout(address to, address, uint256 amount) internal override returns (uint256) {
        uint256 stipend = PAYOUT_GAS_STIPEND;
        bool ok;
        assembly ("memory-safe") {
            ok := call(stipend, to, amount, 0, 0, 0, 0)
        }
        return ok ? amount : 0;
    }

    /// @dev Full-gas pull transfer. Returndata is still discarded so that a
    ///      hostile destination cannot grief the creditor who chose it.
    function _pullTransfer(address to, address, uint256 amount) internal override returns (uint256) {
        bool ok;
        assembly ("memory-safe") {
            ok := call(gas(), to, amount, 0, 0, 0, 0)
        }
        return ok ? amount : 0;
    }
}
