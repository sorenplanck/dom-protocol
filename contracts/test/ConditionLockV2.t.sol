// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ConditionLockCoreV2} from "../src/ConditionLockCoreV2.sol";
import {ConditionLockV2} from "../src/ConditionLockV2.sol";
import {LockBinding, LockTerms} from "../src/LockBinding.sol";
import {F3TestBase} from "./Base.t.sol";
import {ContractFunder, GoodReceiver} from "./mocks/HostileReceivers.sol";

/// @notice Adversarial suite for the native-ETH variant: open, claim, refund,
///         terminality and the claim-XOR-refund rule.
contract ConditionLockV2Test is F3TestBase {
    ConditionLockV2 internal lock;

    event LockOpened(
        bytes32 indexed lockId,
        bytes32 indexed binding,
        address indexed funder,
        address beneficiary,
        address asset,
        uint256 amount,
        address adaptorAddress,
        uint64 deadline
    );
    event Claimed(bytes32 indexed lockId, bytes32 indexed binding, address indexed beneficiary, uint256 t);
    event Refunded(bytes32 indexed lockId, bytes32 indexed binding, address indexed funder, uint256 amount);

    function setUp() public {
        _setUpTime();
        lock = new ConditionLockV2();
        vm.deal(funder, 1000 ether);
        vm.deal(stranger, 1000 ether);
    }

    function _open() internal returns (bytes32 lockId, LockTerms memory t) {
        t = _defaultNativeTerms();
        vm.prank(funder);
        lockId = lock.open{value: t.amount}(t);
    }

    // ------------------------------------------------------------------
    // open
    // ------------------------------------------------------------------

    function test_openStoresTheLockAndEmits() public {
        LockTerms memory t = _defaultNativeTerms();
        bytes32 expectedBinding = _refBinding(t, block.chainid, address(lock));
        bytes32 expectedLockId = _refLockId(expectedBinding, funder);

        vm.expectEmit(true, true, true, true, address(lock));
        emit LockOpened(
            expectedLockId, expectedBinding, funder, t.beneficiary, t.asset, t.amount, t.adaptorAddress, t.deadline
        );

        vm.prank(funder);
        bytes32 lockId = lock.open{value: t.amount}(t);

        assertEq(lockId, expectedLockId, "returned lock id must be the derived one");
        assertEq(address(lock).balance, t.amount);
        _assertLockStored(lock, lockId, t, funder, false);
        assertEq(lock.lockOf(lockId).binding, expectedBinding);
    }

    function test_openRejectsZeroBeneficiary() public {
        LockTerms memory t = _defaultNativeTerms();
        t.beneficiary = address(0);
        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.ZeroAddress.selector);
        lock.open{value: t.amount}(t);
    }

    function test_openRejectsZeroAdaptorAddress() public {
        LockTerms memory t = _defaultNativeTerms();
        t.adaptorAddress = address(0);
        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.ZeroAddress.selector);
        lock.open{value: t.amount}(t);
    }

    function test_openRejectsZeroAmount() public {
        LockTerms memory t = _defaultNativeTerms();
        t.amount = 0;
        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.BadAmount.selector);
        lock.open(t);
    }

    function test_openRejectsDeadlineInThePast() public {
        LockTerms memory t = _defaultNativeTerms();
        t.deadline = uint64(block.timestamp) - 1;
        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.BadDeadline.selector);
        lock.open{value: t.amount}(t);
    }

    function test_openRejectsDeadlineEqualToNow() public {
        LockTerms memory t = _defaultNativeTerms();
        t.deadline = uint64(block.timestamp);
        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.BadDeadline.selector);
        lock.open{value: t.amount}(t);
    }

    function test_openRejectsNonZeroAsset() public {
        LockTerms memory t = _defaultNativeTerms();
        t.asset = address(0xBEEF);
        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.AssetMismatch.selector);
        lock.open{value: t.amount}(t);
    }

    function test_openRejectsUnderpayment() public {
        LockTerms memory t = _defaultNativeTerms();
        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.ValueMismatch.selector);
        lock.open{value: t.amount - 1}(t);
    }

    function test_openRejectsOverpayment() public {
        LockTerms memory t = _defaultNativeTerms();
        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.ValueMismatch.selector);
        lock.open{value: t.amount + 1}(t);
    }

    function test_openRejectsNonCanonicalDirection() public {
        LockTerms memory t = _defaultNativeTerms();
        t.direction = 2;
        vm.prank(funder);
        vm.expectRevert(LockBinding.BadDirection.selector);
        lock.open{value: t.amount}(t);
    }

    function test_openAcceptsBothCanonicalDirections() public {
        LockTerms memory a = _defaultNativeTerms();
        a.direction = 0;
        LockTerms memory b = _defaultNativeTerms();
        b.direction = 1;

        vm.startPrank(funder);
        bytes32 idA = lock.open{value: a.amount}(a);
        bytes32 idB = lock.open{value: b.amount}(b);
        vm.stopPrank();

        assertTrue(idA != idB, "direction must separate the two legs");
    }

    function test_duplicateOpenSameTermsSameFunderReverts() public {
        (, LockTerms memory t) = _open();
        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.LockExists.selector);
        lock.open{value: t.amount}(t);
    }

    function test_sameTermsDifferentFunderYieldsDifferentLockId() public {
        (bytes32 idA, LockTerms memory t) = _open();
        vm.prank(stranger);
        bytes32 idB = lock.open{value: t.amount}(t);

        assertTrue(idA != idB, "funder must separate the lock ids");
        assertEq(lock.lockOf(idA).binding, lock.lockOf(idB).binding, "binding is funder-independent");
        assertEq(lock.lockOf(idA).funder, funder);
        assertEq(lock.lockOf(idB).funder, stranger);
        assertEq(address(lock).balance, 2 * t.amount);
    }

    /// @dev Anti-squatting: a stranger who front-runs with the victim's exact
    ///      terms only ever creates their OWN lock, and the victim's `open`
    ///      still succeeds afterwards.
    function test_thirdPartyCannotSquatSomeoneElsesLockId() public {
        LockTerms memory t = _defaultNativeTerms();
        bytes32 victimId = lock.deriveLockId(t, funder);

        vm.prank(stranger);
        bytes32 squatterId = lock.open{value: t.amount}(t);
        assertTrue(squatterId != victimId);
        assertEq(lock.lockOf(victimId).funder, address(0), "victim slot must still be free");

        vm.prank(funder);
        assertEq(lock.open{value: t.amount}(t), victimId);
    }

    /// @dev A settled lock keeps its funder set, so the same terms can never be
    ///      re-opened by the same account: on-chain replay protection.
    function test_reopenAfterSettlementReverts() public {
        (bytes32 lockId, LockTerms memory t) = _open();
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.LockExists.selector);
        lock.open{value: t.amount}(t);
    }

    function test_unknownLockReadsBackEmpty() public view {
        ConditionLockCoreV2.Lock memory stored = lock.lockOf(keccak256("nope"));
        assertEq(stored.funder, address(0));
        assertEq(stored.amount, 0);
        assertEq(stored.settled, false);
    }

    function testFuzz_openIsIdempotentInDerivation(uint256 amount, uint64 window, uint256 secret) public {
        amount = bound(amount, 1, 100 ether);
        window = uint64(bound(window, 1, 3650 days));
        secret = bound(secret, 1, SECP256K1_N - 1);

        LockTerms memory t = _defaultNativeTerms();
        t.amount = amount;
        t.deadline = uint64(block.timestamp) + window;
        t.adaptorAddress = vm.addr(secret);

        vm.deal(funder, amount);
        vm.prank(funder);
        bytes32 lockId = lock.open{value: amount}(t);

        assertEq(lockId, lock.deriveLockId(t, funder));
        assertEq(lockId, _refLockId(_refBinding(t, block.chainid, address(lock)), funder));
        _assertLockStored(lock, lockId, t, funder, false);
    }

    // ------------------------------------------------------------------
    // claim
    // ------------------------------------------------------------------

    function test_claimHappyPath() public {
        (bytes32 lockId, LockTerms memory t) = _open();
        uint256 balanceBefore = beneficiary.balance;

        vm.expectEmit(true, true, true, true, address(lock));
        emit Claimed(lockId, lock.lockOf(lockId).binding, beneficiary, SECRET);

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertEq(beneficiary.balance, balanceBefore + t.amount);
        assertEq(address(lock).balance, 0);
        assertTrue(lock.lockOf(lockId).settled);
        assertEq(lock.pendingWithdrawals(beneficiary, address(0)), 0, "happy path must not defer");
    }

    function test_claimRejectsScalarZero() public {
        (bytes32 lockId,) = _open();
        vm.prank(beneficiary);
        vm.expectRevert(LockBinding.NonCanonicalScalar.selector);
        lock.claim(lockId, 0);
        assertFalse(lock.lockOf(lockId).settled);
    }

    function test_claimRejectsScalarAtOrder() public {
        (bytes32 lockId,) = _open();
        vm.prank(beneficiary);
        vm.expectRevert(LockBinding.NonCanonicalScalar.selector);
        lock.claim(lockId, SECP256K1_N);
    }

    function test_claimRejectsScalarAboveOrder() public {
        (bytes32 lockId,) = _open();
        vm.prank(beneficiary);
        vm.expectRevert(LockBinding.NonCanonicalScalar.selector);
        lock.claim(lockId, type(uint256).max);
    }

    function test_claimRejectsScalarRecoveringADifferentAddress() public {
        (bytes32 lockId,) = _open();
        assertTrue(vm.addr(OTHER_SECRET) != vm.addr(SECRET));
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.WrongSecret.selector);
        lock.claim(lockId, OTHER_SECRET);
        assertFalse(lock.lockOf(lockId).settled);
        assertEq(address(lock).balance, AMOUNT, "a failed claim must not move value");
    }

    function testFuzz_claimRejectsEveryWrongScalar(uint256 wrong) public {
        wrong = bound(wrong, 1, SECP256K1_N - 1);
        vm.assume(wrong != SECRET);
        (bytes32 lockId,) = _open();
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.WrongSecret.selector);
        lock.claim(lockId, wrong);
    }

    /// @dev A lock whose adaptor address is zero cannot be created, so the
    ///      degenerate "recovered == address(0) matches the commitment" case is
    ///      unreachable rather than merely unlikely.
    function test_zeroAdaptorAddressLockCannotExist() public {
        LockTerms memory t = _defaultNativeTerms();
        t.adaptorAddress = address(0);
        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.ZeroAddress.selector);
        lock.open{value: t.amount}(t);
        assertEq(lock.lockOf(lock.deriveLockId(t, funder)).funder, address(0));
    }

    function test_claimByNonBeneficiaryReverts() public {
        (bytes32 lockId,) = _open();
        vm.prank(stranger);
        vm.expectRevert(ConditionLockCoreV2.NotBeneficiary.selector);
        lock.claim(lockId, SECRET);
    }

    function test_claimByFunderReverts() public {
        (bytes32 lockId,) = _open();
        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.NotBeneficiary.selector);
        lock.claim(lockId, SECRET);
    }

    function testFuzz_claimByAnyoneElseReverts(address caller) public {
        vm.assume(caller != beneficiary);
        (bytes32 lockId,) = _open();
        vm.prank(caller);
        vm.expectRevert(ConditionLockCoreV2.NotBeneficiary.selector);
        lock.claim(lockId, SECRET);
    }

    function test_claimOneSecondBeforeDeadlineSucceeds() public {
        (bytes32 lockId, LockTerms memory t) = _open();
        vm.warp(t.deadline - 1);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);
        assertTrue(lock.lockOf(lockId).settled);
    }

    function test_claimExactlyAtDeadlineReverts() public {
        (bytes32 lockId, LockTerms memory t) = _open();
        vm.warp(t.deadline);
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.Expired.selector);
        lock.claim(lockId, SECRET);
    }

    function test_claimAfterDeadlineReverts() public {
        (bytes32 lockId, LockTerms memory t) = _open();
        vm.warp(uint256(t.deadline) + 1 days);
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.Expired.selector);
        lock.claim(lockId, SECRET);
    }

    function test_claimOnUnknownLockReverts() public {
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.LockUnknown.selector);
        lock.claim(keccak256("nope"), SECRET);
    }

    function test_doubleClaimReverts() public {
        (bytes32 lockId,) = _open();
        vm.startPrank(beneficiary);
        lock.claim(lockId, SECRET);
        vm.expectRevert(ConditionLockCoreV2.AlreadySettled.selector);
        lock.claim(lockId, SECRET);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------
    // refund
    // ------------------------------------------------------------------

    function test_refundAtExactlyDeadlineSucceeds() public {
        (bytes32 lockId, LockTerms memory t) = _open();
        vm.warp(t.deadline);
        uint256 balanceBefore = funder.balance;

        vm.expectEmit(true, true, true, true, address(lock));
        emit Refunded(lockId, lock.lockOf(lockId).binding, funder, t.amount);

        vm.prank(stranger);
        lock.refund(lockId);

        assertEq(funder.balance, balanceBefore + t.amount, "refund always pays the funder");
        assertEq(address(lock).balance, 0);
        assertTrue(lock.lockOf(lockId).settled);
    }

    function test_refundOneSecondBeforeDeadlineReverts() public {
        (bytes32 lockId, LockTerms memory t) = _open();
        vm.warp(t.deadline - 1);
        vm.expectRevert(ConditionLockCoreV2.NotExpired.selector);
        lock.refund(lockId);
    }

    function test_refundImmediatelyAfterOpenReverts() public {
        (bytes32 lockId,) = _open();
        vm.expectRevert(ConditionLockCoreV2.NotExpired.selector);
        lock.refund(lockId);
    }

    /// @dev Anyone may pay the gas, but the destination is never the caller.
    function testFuzz_refundIsPermissionlessButNeverPaysTheCaller(address caller) public {
        vm.assume(caller != funder && caller != address(lock));
        vm.assume(caller.code.length == 0);
        assumeNotPrecompile(caller);
        assumeNotForgeAddress(caller);
        assumePayable(caller);

        (bytes32 lockId, LockTerms memory t) = _open();
        vm.warp(t.deadline);

        uint256 callerBefore = caller.balance;
        uint256 funderBefore = funder.balance;
        vm.prank(caller);
        lock.refund(lockId);

        assertEq(caller.balance, callerBefore, "caller must gain nothing");
        assertEq(funder.balance, funderBefore + t.amount);
    }

    function test_doubleRefundReverts() public {
        (bytes32 lockId, LockTerms memory t) = _open();
        vm.warp(t.deadline);
        lock.refund(lockId);
        vm.expectRevert(ConditionLockCoreV2.AlreadySettled.selector);
        lock.refund(lockId);
    }

    function test_refundOnUnknownLockReverts() public {
        vm.expectRevert(ConditionLockCoreV2.LockUnknown.selector);
        lock.refund(keccak256("nope"));
    }

    // ------------------------------------------------------------------
    // claim XOR refund
    // ------------------------------------------------------------------

    function test_claimThenRefundReverts() public {
        (bytes32 lockId, LockTerms memory t) = _open();
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);
        vm.warp(t.deadline);
        vm.expectRevert(ConditionLockCoreV2.AlreadySettled.selector);
        lock.refund(lockId);
    }

    function test_refundThenClaimReverts() public {
        (bytes32 lockId, LockTerms memory t) = _open();
        vm.warp(t.deadline);
        lock.refund(lockId);
        vm.prank(beneficiary);
        // Past the deadline the expiry check fires first; either way the lock
        // is terminal and no second payout is possible.
        vm.expectRevert(ConditionLockCoreV2.AlreadySettled.selector);
        lock.claim(lockId, SECRET);
    }

    /// @dev The claim window and the refund window are disjoint at every
    ///      instant, so the two outcomes can never both be reachable.
    function testFuzz_claimAndRefundWindowsAreDisjoint(uint64 when) public {
        (bytes32 lockId, LockTerms memory t) = _open();
        when = uint64(bound(when, START_TIME, uint256(t.deadline) + 365 days));
        vm.warp(when);

        bool claimAllowed = when < t.deadline;

        vm.prank(beneficiary);
        (bool claimOk,) = address(lock).call(abi.encodeCall(lock.claim, (lockId, SECRET)));
        assertEq(claimOk, claimAllowed, "claim window");

        (bool refundOk,) = address(lock).call(abi.encodeCall(lock.refund, (lockId)));
        assertEq(refundOk, !claimAllowed, "refund window");

        assertTrue(lock.lockOf(lockId).settled, "exactly one outcome must have happened");
        assertEq(address(lock).balance, 0);
    }

    // ------------------------------------------------------------------
    // ETH accounting
    // ------------------------------------------------------------------

    function test_contractHoldsExactlyTheOutstandingLiabilities() public {
        LockTerms memory a = _defaultNativeTerms();
        LockTerms memory b = _defaultNativeTerms();
        b.sessionId = keccak256("session-2");
        b.amount = 1 ether;

        vm.startPrank(funder);
        bytes32 idA = lock.open{value: a.amount}(a);
        bytes32 idB = lock.open{value: b.amount}(b);
        vm.stopPrank();
        assertEq(address(lock).balance, a.amount + b.amount);

        vm.prank(beneficiary);
        lock.claim(idA, SECRET);
        assertEq(address(lock).balance, b.amount);

        vm.warp(b.deadline);
        lock.refund(idB);
        assertEq(address(lock).balance, 0);
    }

    function test_contractRejectsBarePayments() public {
        // No `receive` and no `fallback`: value cannot enter except through `open`.
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(lock).call{value: 1 ether}("");
        assertFalse(ok, "the contract must not accept unaccounted ETH");
        assertEq(address(lock).balance, 0);
    }

    // ------------------------------------------------------------------
    // Contract funder / beneficiary happy paths
    // ------------------------------------------------------------------

    function test_contractBeneficiaryThatAcceptsEthIsPaidByPush() public {
        GoodReceiver receiver = new GoodReceiver();
        LockTerms memory t = _terms(address(0), AMOUNT, address(receiver), SECRET);

        vm.prank(funder);
        bytes32 lockId = lock.open{value: t.amount}(t);

        vm.prank(address(receiver));
        lock.claim(lockId, SECRET);

        assertEq(receiver.received(), t.amount);
        assertEq(lock.pendingWithdrawals(address(receiver), address(0)), 0);
    }

    function test_contractFunderThatAcceptsEthIsRefundedByPush() public {
        ContractFunder cf = new ContractFunder(address(lock));
        vm.deal(address(cf), 10 ether);

        LockTerms memory t = _defaultNativeTerms();
        bytes memory ret = cf.forward(abi.encodeCall(lock.open, (t)), t.amount);
        bytes32 lockId = abi.decode(ret, (bytes32));

        vm.warp(t.deadline);
        uint256 before = address(cf).balance;
        lock.refund(lockId);
        assertEq(address(cf).balance, before + t.amount);
    }
}
