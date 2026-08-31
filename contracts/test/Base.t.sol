// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ConditionLockCoreV2} from "../src/ConditionLockCoreV2.sol";
import {LockBinding, LockTerms} from "../src/LockBinding.sol";
import {Test} from "forge-std/Test.sol";

/// @notice Shared fixtures and an INDEPENDENT reference implementation of the
///         section 1 derivation.
/// @dev The reference below is written from the spec table, word by word, and
///      never calls `LockBinding`. If the library and the reference ever
///      disagree, the cross-language vector file would be wrong too.
abstract contract F3TestBase is Test {
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @dev A canonical, arbitrary secret used across the suite.
    uint256 internal constant SECRET = 0xC0FFEE0000000000000000000000000000000000000000000000000000BADA55;

    /// @dev A second, different canonical secret.
    uint256 internal constant OTHER_SECRET = 0xDECAFBAD00000000000000000000000000000000000000000000000000001234;

    uint64 internal constant START_TIME = 1_000_000;
    uint64 internal constant LOCK_WINDOW = 7 days;
    uint256 internal constant AMOUNT = 3 ether;

    address internal funder = makeAddr("funder");
    address internal beneficiary = makeAddr("beneficiary");
    address internal stranger = makeAddr("stranger");

    function _setUpTime() internal {
        vm.warp(START_TIME);
    }

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    function _terms(address asset, uint256 amount, address beneficiary_, uint256 secret)
        internal
        view
        returns (LockTerms memory)
    {
        return LockTerms({
            domChainId: keccak256("dom-sim/regtest"),
            direction: 0,
            sessionId: keccak256("session-1"),
            termsHash: keccak256("terms-1"),
            participantsHash: keccak256("roster-1"),
            asset: asset,
            amount: amount,
            beneficiary: beneficiary_,
            adaptorAddress: vm.addr(secret),
            deadline: uint64(block.timestamp) + LOCK_WINDOW
        });
    }

    function _defaultNativeTerms() internal view returns (LockTerms memory) {
        return _terms(address(0), AMOUNT, beneficiary, SECRET);
    }

    // ------------------------------------------------------------------
    // Independent reference derivation (spec section 1)
    // ------------------------------------------------------------------

    function _refBinding(LockTerms memory t, uint256 chainId, address lockContract) internal pure returns (bytes32) {
        bytes memory head = bytes.concat(
            keccak256("DOM-Interop/ConditionLockV2/binding"),
            bytes32(uint256(2)), // BINDING_VERSION, ABI-padded
            bytes32(chainId),
            bytes32(uint256(uint160(lockContract)))
        );
        bytes memory body =
            bytes.concat(t.domChainId, bytes32(uint256(t.direction)), t.sessionId, t.termsHash, t.participantsHash);
        bytes memory tail = bytes.concat(
            bytes32(uint256(uint160(t.asset))),
            bytes32(t.amount),
            bytes32(uint256(uint160(t.beneficiary))),
            bytes32(uint256(uint160(t.adaptorAddress))),
            bytes32(uint256(t.deadline))
        );
        bytes memory encoded = bytes.concat(head, body, tail);
        // 14 fields, one 32-byte word each: this is what `abi.encode` must produce.
        require(encoded.length == 14 * 32, "reference layout drifted");
        return keccak256(encoded);
    }

    function _refLockId(bytes32 binding, address funder_) internal pure returns (bytes32) {
        bytes memory encoded = bytes.concat(
            keccak256("DOM-Interop/ConditionLockV2/lockId"),
            bytes32(uint256(2)),
            binding,
            bytes32(uint256(uint160(funder_)))
        );
        require(encoded.length == 4 * 32, "reference layout drifted");
        return keccak256(encoded);
    }

    // ------------------------------------------------------------------
    // Assertions shared by both variants
    // ------------------------------------------------------------------

    function _assertLockStored(
        ConditionLockCoreV2 lock,
        bytes32 lockId,
        LockTerms memory t,
        address expectedFunder,
        bool expectedSettled
    ) internal view {
        ConditionLockCoreV2.Lock memory stored = lock.lockOf(lockId);
        assertEq(stored.funder, expectedFunder, "funder");
        assertEq(stored.beneficiary, t.beneficiary, "beneficiary");
        assertEq(stored.adaptorAddress, t.adaptorAddress, "adaptorAddress");
        assertEq(stored.asset, t.asset, "asset");
        assertEq(stored.amount, t.amount, "amount");
        assertEq(stored.deadline, t.deadline, "deadline");
        assertEq(stored.settled, expectedSettled, "settled");
    }
}
