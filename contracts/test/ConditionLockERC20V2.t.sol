// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ConditionLockCoreV2} from "../src/ConditionLockCoreV2.sol";
import {ConditionLockERC20V2} from "../src/ConditionLockERC20V2.sol";
import {ConditionLockV2} from "../src/ConditionLockV2.sol";
import {LockBinding, LockTerms} from "../src/LockBinding.sol";
import {F3TestBase} from "./Base.t.sol";
import {
    AmbiguousReturnToken,
    BouncingToken,
    CappedTransferToken,
    FalseReturnToken,
    FeeOnTransferToken,
    GasBurnerToken,
    GasSensitiveBalanceToken,
    GreedyProbeToken,
    HeavyToken,
    LyingBalanceToken,
    MockERC20,
    NoReturnToken,
    PartialTransferToken,
    ReentrantToken,
    ReturnBombToken,
    RevertingToken,
    ShrinkingLieToken,
    UnreadableBalanceToken,
    UpwardLieToken
} from "./mocks/HostileTokens.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @notice Adversarial suite for the ERC-20 variant: exact accounting at the
///         door, and a payout path that no token can use to block settlement.
contract ConditionLockERC20V2Test is F3TestBase {
    ConditionLockERC20V2 internal lock;
    MockERC20 internal token;

    event Claimed(bytes32 indexed lockId, bytes32 indexed binding, address indexed beneficiary, uint256 t);
    event Refunded(bytes32 indexed lockId, bytes32 indexed binding, address indexed funder, uint256 amount);
    event PayoutDeferred(address indexed to, address indexed asset, uint256 amount);
    event Withdrawal(address indexed account, address indexed asset, address indexed to, uint256 amount);

    function setUp() public {
        _setUpTime();
        lock = new ConditionLockERC20V2();
        token = new MockERC20();
        _fund(token, funder);
    }

    function _fund(MockERC20 tkn, address who) internal {
        tkn.mint(who, 1_000_000 ether);
        vm.prank(who);
        tkn.approve(address(lock), type(uint256).max);
    }

    function _tokenTerms(MockERC20 tkn, address beneficiary_) internal view returns (LockTerms memory) {
        return _terms(address(tkn), AMOUNT, beneficiary_, SECRET);
    }

    function _open(MockERC20 tkn, address beneficiary_) internal returns (bytes32 lockId, LockTerms memory t) {
        t = _tokenTerms(tkn, beneficiary_);
        vm.prank(funder);
        lockId = lock.open(t);
    }

    // ------------------------------------------------------------------
    // open: asset kind and exact accounting
    // ------------------------------------------------------------------

    function test_openStoresTheLockAndTakesExactCustody() public {
        LockTerms memory t = _tokenTerms(token, beneficiary);
        uint256 funderBefore = token.balanceOf(funder);

        vm.prank(funder);
        bytes32 lockId = lock.open(t);

        assertEq(lockId, _refLockId(_refBinding(t, block.chainid, address(lock)), funder));
        assertEq(token.balanceOf(address(lock)), t.amount);
        assertEq(token.balanceOf(funder), funderBefore - t.amount);
        _assertLockStored(lock, lockId, t, funder, false);
    }

    function test_openRejectsTheNativeAsset() public {
        LockTerms memory t = _tokenTerms(token, beneficiary);
        t.asset = address(0);
        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.AssetMismatch.selector);
        lock.open(t);
    }

    function test_openRejectsAnyAttachedValue() public {
        LockTerms memory t = _tokenTerms(token, beneficiary);
        vm.deal(funder, 1 ether);
        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.ValueMismatch.selector);
        lock.open{value: 1 wei}(t);
    }

    function test_openRejectsAnAssetWithoutCode() public {
        LockTerms memory t = _tokenTerms(token, beneficiary);
        t.asset = address(0xDEAD);
        vm.prank(funder);
        vm.expectRevert(ConditionLockERC20V2.NotAContract.selector);
        lock.open(t);
    }

    function test_openRejectsFeeOnTransferTokens() public {
        FeeOnTransferToken fot = new FeeOnTransferToken(100); // 1%
        _fund(fot, funder);
        LockTerms memory t = _tokenTerms(fot, beneficiary);

        vm.prank(funder);
        vm.expectRevert(
            abi.encodeWithSelector(ConditionLockERC20V2.InexactTransfer.selector, t.amount, t.amount - t.amount / 100)
        );
        lock.open(t);
        assertEq(fot.balanceOf(address(lock)), 0, "nothing may be absorbed");
    }

    function testFuzz_openRejectsAnyNonZeroFee(uint256 feeBps, uint256 amount) public {
        feeBps = bound(feeBps, 1, 10_000);
        amount = bound(amount, 10_000, 1000 ether);
        FeeOnTransferToken fot = new FeeOnTransferToken(feeBps);
        _fund(fot, funder);

        LockTerms memory t = _tokenTerms(fot, beneficiary);
        t.amount = amount;

        vm.prank(funder);
        vm.expectRevert();
        lock.open(t);
        assertEq(fot.balanceOf(address(lock)), 0);
    }

    function test_openRejectsAFalseReturningTransferFrom() public {
        FalseReturnToken bad = new FalseReturnToken();
        bad.setFailures(false, true);
        _fund(bad, funder);

        LockTerms memory t = _tokenTerms(bad, beneficiary);
        vm.prank(funder);
        vm.expectRevert(abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(bad)));
        lock.open(t);
    }

    function test_openRejectsARevertingTransferFrom() public {
        RevertingToken bad = new RevertingToken();
        bad.setReverts(false, true);
        _fund(bad, funder);

        LockTerms memory t = _tokenTerms(bad, beneficiary);
        vm.prank(funder);
        vm.expectRevert(RevertingToken.TokenRefused.selector);
        lock.open(t);
    }

    function test_openAcceptsAUsdtStyleTokenThatReturnsNothing() public {
        NoReturnToken usdt = new NoReturnToken();
        _fund(usdt, funder);

        (bytes32 lockId, LockTerms memory t) = _open(usdt, beneficiary);
        assertEq(usdt.balanceOf(address(lock)), t.amount);
        _assertLockStored(lock, lockId, t, funder, false);
    }

    function test_openRejectsInsufficientAllowance() public {
        vm.prank(funder);
        token.approve(address(lock), AMOUNT - 1);
        LockTerms memory t = _tokenTerms(token, beneficiary);
        vm.prank(funder);
        vm.expectRevert(abi.encodeWithSignature("Error(string)", "allowance"));
        lock.open(t);
    }

    function test_duplicateOpenSameTermsSameFunderReverts() public {
        (, LockTerms memory t) = _open(token, beneficiary);
        vm.prank(funder);
        vm.expectRevert(ConditionLockCoreV2.LockExists.selector);
        lock.open(t);
    }

    function test_sameTermsDifferentFunderYieldsDifferentLockId() public {
        (bytes32 idA, LockTerms memory t) = _open(token, beneficiary);
        _fund(token, stranger);
        vm.prank(stranger);
        bytes32 idB = lock.open(t);

        assertTrue(idA != idB);
        assertEq(token.balanceOf(address(lock)), 2 * t.amount);
    }

    function test_openRejectsNonCanonicalDirection() public {
        LockTerms memory t = _tokenTerms(token, beneficiary);
        t.direction = 3;
        vm.prank(funder);
        vm.expectRevert(LockBinding.BadDirection.selector);
        lock.open(t);
    }

    // ------------------------------------------------------------------
    // claim / refund
    // ------------------------------------------------------------------

    /// @dev The beneficiary already holds this token, so the ERC-20 `transfer`
    ///      fits inside the 30k payout stipend and the push goes through.
    function test_claimPushesWhenTheTransferFitsInTheStipend() public {
        token.mint(beneficiary, 1 ether); // warms the destination balance slot
        (bytes32 lockId, LockTerms memory t) = _open(token, beneficiary);
        uint256 before = token.balanceOf(beneficiary);

        vm.expectEmit(true, true, true, true, address(lock));
        emit Claimed(lockId, lock.lockOf(lockId).binding, beneficiary, SECRET);

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertEq(token.balanceOf(beneficiary), before + t.amount);
        assertEq(lock.pendingWithdrawals(beneficiary, address(token)), 0);
        assertEq(token.balanceOf(address(lock)), 0);
    }

    /// @dev A minimal ERC-20 `transfer` to a cold destination (a full
    ///      zero-to-non-zero SSTORE, 22.1k) still fits inside the 30k stipend:
    ///      measured at 23,736 gas by the test below, roughly 6.3k to spare.
    ///      Pinned here because that margin is small enough that a change on
    ///      either side flips the payout into the pull path.
    function test_claimPushesEvenToAColdDestinationBalance() public {
        assertEq(token.balanceOf(beneficiary), 0, "cold destination slot");
        (bytes32 lockId, LockTerms memory t) = _open(token, beneficiary);

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertEq(token.balanceOf(beneficiary), t.amount);
        assertEq(lock.pendingWithdrawals(beneficiary, address(token)), 0);
    }

    /// @dev Measures how much of the 30k stipend a minimal ERC-20 `transfer` to
    ///      a cold destination actually consumes, so the size of the margin is
    ///      a recorded number rather than an assumption. Run with `-vv` to see
    ///      the headroom.
    function test_minimalErc20TransferFitsInsideTheStipend() public {
        token.mint(address(this), 10 ether);
        assertEq(token.balanceOf(beneficiary), 0, "cold destination slot");

        uint256 gasBefore = gasleft();
        bool reportedSuccess = token.transfer(beneficiary, 1 ether);
        uint256 used = gasBefore - gasleft();

        assertTrue(reportedSuccess, "baseline transfer must report success");

        emit log_named_uint("minimal ERC-20 transfer gas (cold destination)", used);
        emit log_named_uint("PAYOUT_GAS_STIPEND headroom", 30_000 - used);
        assertLt(used, 30_000, "a minimal ERC-20 transfer must still fit in the stipend");
    }

    /// @dev The other side of that thin margin: an honest token that does a
    ///      little extra bookkeeping per transfer exceeds the stipend, and the
    ///      payout lands in the pull path. `Claimed(t)` is published either
    ///      way and the beneficiary is always made whole; only the number of
    ///      transactions changes.
    function test_claimDefersWhenTheTokenTransferExceedsTheStipend() public {
        HeavyToken heavy = new HeavyToken();
        _fund(heavy, funder);
        (bytes32 lockId, LockTerms memory t) = _open(heavy, beneficiary);

        vm.expectEmit(true, true, true, true, address(lock));
        emit Claimed(lockId, lock.lockOf(lockId).binding, beneficiary, SECRET);
        vm.expectEmit(true, true, true, true, address(lock));
        emit PayoutDeferred(beneficiary, address(heavy), t.amount);

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertTrue(lock.lockOf(lockId).settled);
        assertEq(lock.pendingWithdrawals(beneficiary, address(heavy)), t.amount);
        assertEq(heavy.balanceOf(beneficiary), 0, "nothing moved on the failed push");

        vm.expectEmit(true, true, true, true, address(lock));
        emit Withdrawal(beneficiary, address(heavy), beneficiary, t.amount);
        vm.prank(beneficiary);
        lock.withdraw(address(heavy));

        assertEq(heavy.balanceOf(beneficiary), t.amount);
        assertEq(heavy.balanceOf(address(lock)), 0);
        assertEq(lock.pendingWithdrawals(beneficiary, address(heavy)), 0);

        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.NothingToWithdraw.selector);
        lock.withdraw(address(heavy));
    }

    function test_refundAtDeadlinePaysTheFunder() public {
        (bytes32 lockId, LockTerms memory t) = _open(token, beneficiary);
        vm.warp(t.deadline);
        uint256 before = token.balanceOf(funder);

        vm.prank(stranger);
        lock.refund(lockId);

        // The funder already holds the token, so the push fits in the stipend.
        assertEq(token.balanceOf(funder), before + t.amount);
        assertEq(lock.pendingWithdrawals(funder, address(token)), 0);
    }

    function test_claimXorRefund() public {
        (bytes32 lockId, LockTerms memory t) = _open(token, beneficiary);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);
        vm.warp(t.deadline);
        vm.expectRevert(ConditionLockCoreV2.AlreadySettled.selector);
        lock.refund(lockId);
    }

    function test_refundThenClaimReverts() public {
        (bytes32 lockId, LockTerms memory t) = _open(token, beneficiary);
        vm.warp(t.deadline);
        lock.refund(lockId);
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.AlreadySettled.selector);
        lock.claim(lockId, SECRET);
    }

    function test_claimRejectsWrongSecretAndNonCanonicalScalars() public {
        (bytes32 lockId,) = _open(token, beneficiary);
        vm.startPrank(beneficiary);
        vm.expectRevert(LockBinding.NonCanonicalScalar.selector);
        lock.claim(lockId, 0);
        vm.expectRevert(LockBinding.NonCanonicalScalar.selector);
        lock.claim(lockId, SECP256K1_N);
        vm.expectRevert(ConditionLockCoreV2.WrongSecret.selector);
        lock.claim(lockId, OTHER_SECRET);
        vm.stopPrank();
        assertEq(token.balanceOf(address(lock)), AMOUNT, "a failed claim must not move tokens");
    }

    function test_claimAtDeadlineRevertsAndRefundBeforeDeadlineReverts() public {
        (bytes32 lockId, LockTerms memory t) = _open(token, beneficiary);
        vm.expectRevert(ConditionLockCoreV2.NotExpired.selector);
        lock.refund(lockId);
        vm.warp(t.deadline);
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.Expired.selector);
        lock.claim(lockId, SECRET);
    }

    // ------------------------------------------------------------------
    // Hostile tokens on the payout path
    // ------------------------------------------------------------------

    function test_revertingTokenDefersInsteadOfBlockingSettlement() public {
        RevertingToken bad = new RevertingToken();
        _fund(bad, funder);
        (bytes32 lockId, LockTerms memory t) = _open(bad, beneficiary);

        bad.setReverts(true, false);

        vm.expectEmit(true, true, true, true, address(lock));
        emit PayoutDeferred(beneficiary, address(bad), t.amount);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertTrue(lock.lockOf(lockId).settled, "settlement completed anyway");
        assertEq(lock.pendingWithdrawals(beneficiary, address(bad)), t.amount);

        // The pull is allowed to fail loudly while the token is still hostile.
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.PayoutFailed.selector);
        lock.withdraw(address(bad));
        assertEq(lock.pendingWithdrawals(beneficiary, address(bad)), t.amount, "credit preserved");

        // Once the token behaves, the credit is paid out exactly once.
        bad.setReverts(false, false);
        vm.prank(beneficiary);
        lock.withdraw(address(bad));
        assertEq(bad.balanceOf(beneficiary), t.amount);
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.NothingToWithdraw.selector);
        lock.withdraw(address(bad));
    }

    /// @dev A token that blacklists the beneficiary: settlement still happens,
    ///      and the beneficiary can route the credit to an address the token
    ///      tolerates.
    function test_blacklistingTokenCannotBlockSettlement() public {
        RevertingToken bad = new RevertingToken();
        _fund(bad, funder);
        (bytes32 lockId, LockTerms memory t) = _open(bad, beneficiary);
        bad.block_(beneficiary);

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);
        assertEq(lock.pendingWithdrawals(beneficiary, address(bad)), t.amount);

        vm.prank(beneficiary);
        lock.withdrawTo(address(bad), stranger);
        assertEq(bad.balanceOf(stranger), t.amount);
        assertEq(lock.pendingWithdrawals(beneficiary, address(bad)), 0);
    }

    function test_falseReturningTokenDefersInsteadOfSilentlySucceeding() public {
        FalseReturnToken bad = new FalseReturnToken();
        bad.setFailures(false, false);
        _fund(bad, funder);
        (bytes32 lockId, LockTerms memory t) = _open(bad, beneficiary);

        bad.setFailures(true, false);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertEq(bad.balanceOf(beneficiary), 0, "no tokens moved");
        assertEq(lock.pendingWithdrawals(beneficiary, address(bad)), t.amount, "and the credit is intact");

        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.PayoutFailed.selector);
        lock.withdraw(address(bad));
    }

    function test_gasBurningTokenDefersAndCannotDrainTheClaimer() public {
        GasBurnerToken bad = new GasBurnerToken();
        _fund(bad, funder);
        (bytes32 lockId, LockTerms memory t) = _open(bad, beneficiary);

        vm.prank(beneficiary);
        uint256 gasBefore = gasleft();
        lock.claim(lockId, SECRET);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(lock.lockOf(lockId).settled);
        assertEq(lock.pendingWithdrawals(beneficiary, address(bad)), t.amount);
        assertLt(gasUsed, 200_000, "the stipend caps what the token can burn");
    }

    /// @dev Anything that is neither empty nor exactly one `true` word is
    ///      treated as failure. Fail-closed: a token whose return value cannot
    ///      be interpreted never counts as a successful payout.
    /// @dev A malformed return payload from a token that moved NOTHING is a
    ///      genuine failure: nothing left custody, so the whole amount is
    ///      credited and the pull refuses too while the token stays malformed.
    function test_malformedReturnWithNoMovementIsTreatedAsFailure() public {
        ReturnBombToken bad = new ReturnBombToken(64);
        bad.setMoveOnTransfer(false);
        _fund(bad, funder);
        bad.mint(beneficiary, 1 ether);
        (bytes32 lockId, LockTerms memory t) = _open(bad, beneficiary);

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertEq(bad.balanceOf(beneficiary), 1 ether, "nothing moved");
        assertEq(lock.pendingWithdrawals(beneficiary, address(bad)), t.amount);
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.PayoutFailed.selector);
        lock.withdraw(address(bad));
    }

    /// @dev The dangerous half of the same shape, and the audit's P1: the token
    ///      DID move the balance and then reported it with a buffer the lock
    ///      cannot interpret. The measured delta overrides the payload, so no
    ///      credit is minted for value that already left. Booking one here is
    ///      what let a beneficiary collect twice out of pooled custody.
    function test_malformedReturnAfterARealMoveIsCreditedAsDelivered() public {
        ReturnBombToken bad = new ReturnBombToken(64);
        _fund(bad, funder);
        bad.mint(beneficiary, 1 ether);
        (bytes32 lockId, LockTerms memory t) = _open(bad, beneficiary);

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertEq(bad.balanceOf(beneficiary), 1 ether + t.amount, "the token really moved it");
        assertEq(lock.pendingWithdrawals(beneficiary, address(bad)), 0, "no phantom credit");
        assertEq(bad.balanceOf(address(lock)), 0, "custody exactly discharged");
    }

    function test_returnBombTokenCannotGriefThePullPath() public {
        ReturnBombToken bad = new ReturnBombToken(128 * 1024);
        bad.setMoveOnTransfer(false);
        _fund(bad, funder);
        bad.mint(beneficiary, 1 ether);
        (bytes32 lockId, LockTerms memory t) = _open(bad, beneficiary);

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);
        assertEq(lock.pendingWithdrawals(beneficiary, address(bad)), t.amount);

        uint256 gasBefore = gasleft();
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.PayoutFailed.selector);
        lock.withdraw(address(bad));
        uint256 gasUsed = gasBefore - gasleft();

        // The token pays for its own 128 KiB; the lock copies one word.
        assertLt(gasUsed, 400_000, "returndata must not be copied");
        assertEq(lock.pendingWithdrawals(beneficiary, address(bad)), t.amount, "credit preserved");
    }

    // ------------------------------------------------------------------
    // P1 regression: a payout is settled on the measured balance delta
    // ------------------------------------------------------------------

    /// @dev The audit's end-to-end proof, inverted into a regression test.
    ///      Two locks on the same token share one pool of custody. Lock A's
    ///      beneficiary claims through a token that moves the funds and then
    ///      misreports. If that produced a pull credit, A could withdraw a
    ///      second `amount` out of lock B's custody, A's lock would have paid
    ///      out `2 * amount`, and B would hold an unbacked credit. None of that
    ///      may happen.
    function test_ambiguousReturnCannotDrainAnUnrelatedLock() public {
        address secondFunder = makeAddr("secondFunder");
        address secondBeneficiary = makeAddr("secondBeneficiary");

        AmbiguousReturnToken tok = new AmbiguousReturnToken();
        _fund(tok, funder);
        _fund(tok, secondFunder);
        tok.mint(beneficiary, 1 wei);
        tok.mint(secondBeneficiary, 1 wei);

        LockTerms memory a = _tokenTerms(tok, beneficiary);
        a.sessionId = keccak256("drain-a");
        LockTerms memory b = _tokenTerms(tok, secondBeneficiary);
        b.sessionId = keccak256("drain-b");

        vm.prank(funder);
        bytes32 idA = lock.open(a);
        vm.prank(secondFunder);
        bytes32 idB = lock.open(b);
        assertEq(tok.balanceOf(address(lock)), 2 * AMOUNT, "two liabilities custodied");

        vm.prank(beneficiary);
        lock.claim(idA, SECRET);

        assertEq(tok.balanceOf(beneficiary), 1 wei + AMOUNT, "A was paid by the push");
        assertEq(lock.pendingWithdrawals(beneficiary, address(tok)), 0, "and must NOT be credited again");
        assertEq(tok.balanceOf(address(lock)), AMOUNT, "exactly lock B's custody remains");

        // There is nothing to pull, so lock B's money cannot be reached.
        tok.setReturnSize(32);
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.NothingToWithdraw.selector);
        lock.withdraw(address(tok));

        // Lock B settles normally and is fully backed.
        vm.prank(secondBeneficiary);
        lock.claim(idB, SECRET);
        assertEq(tok.balanceOf(secondBeneficiary), 1 wei + AMOUNT, "B was paid in full");
        assertEq(lock.pendingWithdrawals(secondBeneficiary, address(tok)), 0);
        assertEq(tok.balanceOf(address(lock)), 0, "custody exactly discharged, never overdrawn");
    }

    /// @dev Partial delivery credits exactly the shortfall, never the whole
    ///      amount: liability tracks what did not leave.
    function test_partialDeliveryCreditsOnlyTheShortfall() public {
        PartialTransferToken slow = new PartialTransferToken();
        slow.setFraction(1, 4);
        _fund(slow, funder);
        slow.mint(beneficiary, 1 ether);
        (bytes32 lockId, LockTerms memory t) = _open(slow, beneficiary);

        uint256 expectedDelivered = t.amount / 4;
        vm.expectEmit(true, true, true, true, address(lock));
        emit PayoutDeferred(beneficiary, address(slow), t.amount - expectedDelivered);

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertEq(slow.balanceOf(beneficiary), 1 ether + expectedDelivered);
        assertEq(lock.pendingWithdrawals(beneficiary, address(slow)), t.amount - expectedDelivered);
        assertEq(
            slow.balanceOf(address(lock)),
            lock.pendingWithdrawals(beneficiary, address(slow)),
            "custody still covers the liability exactly"
        );
    }

    /// @dev A pull that only delivers part of the credit is a failure: the
    ///      credit is all-or-nothing, and the revert also rolls back whatever
    ///      the token did move.
    function test_partialPullRevertsAndRestoresTheCredit() public {
        PartialTransferToken slow = new PartialTransferToken();
        slow.setFraction(0, 1); // deliver nothing at first, to create a credit
        _fund(slow, funder);
        (bytes32 lockId, LockTerms memory t) = _open(slow, beneficiary);

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);
        assertEq(lock.pendingWithdrawals(beneficiary, address(slow)), t.amount);

        slow.setFraction(1, 2); // now it delivers half and claims success
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.PayoutFailed.selector);
        lock.withdraw(address(slow));

        assertEq(lock.pendingWithdrawals(beneficiary, address(slow)), t.amount, "credit intact");
        assertEq(slow.balanceOf(beneficiary), 0, "the partial move was rolled back too");
        assertEq(slow.balanceOf(address(lock)), t.amount);

        slow.setFraction(1, 1);
        vm.prank(beneficiary);
        lock.withdraw(address(slow));
        assertEq(slow.balanceOf(beneficiary), t.amount);
        assertEq(slow.balanceOf(address(lock)), 0);
    }

    /// @dev A token that drains MORE than it was asked for cannot be stopped,
    ///      but it must never be credited for the excess: booking it would
    ///      silently retire other locks' liabilities. `delivered` is clamped.
    function test_overDeliveryIsClampedToTheAmountOwed() public {
        PartialTransferToken greedy = new PartialTransferToken();
        greedy.setFraction(2, 1); // moves twice what it was asked to
        _fund(greedy, funder);

        LockTerms memory a = _tokenTerms(greedy, beneficiary);
        a.sessionId = keccak256("greedy-a");
        LockTerms memory b = _tokenTerms(greedy, stranger);
        b.sessionId = keccak256("greedy-b");
        vm.startPrank(funder);
        bytes32 idA = lock.open(a);
        lock.open(b);
        vm.stopPrank();

        vm.prank(beneficiary);
        lock.claim(idA, SECRET);

        assertEq(greedy.balanceOf(beneficiary), 2 * AMOUNT, "the token took what it liked");
        assertEq(lock.pendingWithdrawals(beneficiary, address(greedy)), 0, "but is credited for at most the amount");
    }

    // ------------------------------------------------------------------
    // Fallback when the balance cannot be measured
    // ------------------------------------------------------------------

    function _openUnreadable(UnreadableBalanceToken tkn) internal returns (bytes32 lockId, LockTerms memory t) {
        tkn.mint(funder, 1_000_000 ether);
        vm.prank(funder);
        tkn.approve(address(lock), type(uint256).max);
        t = _terms(address(tkn), AMOUNT, beneficiary, SECRET);
        vm.prank(funder);
        lockId = lock.open(t);
    }

    /// @dev THE MATRIX. Three independent axes:
    ///        * measurable   - do both probes answer, only the first, only the
    ///                         second, or neither, and in which flavour of
    ///                         refusal (revert / gas burn / malformed answer);
    ///        * moved        - did `transfer` actually move the value;
    ///        * reported     - did `transfer` return `true`, an unreadable
    ///                         payload, or revert.
    ///
    ///      The old version of this test coupled `moved` to `reported`, which
    ///      made the one dangerous cell - unmeasurable AND moved AND reported
    ///      failure - unreachable, and a live finding invisible. All three axes
    ///      are now free.
    ///
    ///      The property asserted in EVERY cell is the one that actually
    ///      matters: the contract's custody must always cover every credit it
    ///      has booked. A credit for value that already left is exactly the
    ///      violation, because pooled custody means an unrelated lock pays for
    ///      it.
    function testFuzz_payoutDecisionMatrixNeverMintsAnUnbackedCredit(
        uint8 probeSeed,
        uint8 modeSeed,
        bool moves,
        uint8 reportSeed
    ) public {
        UnreadableBalanceToken tkn = new UnreadableBalanceToken();
        (bytes32 lockId, LockTerms memory t) = _openUnreadable(tkn);

        // A second, unrelated lock in the same token: its custody is what a
        // phantom credit would ultimately be paid out of.
        LockTerms memory other = _terms(address(tkn), AMOUNT, stranger, SECRET);
        other.sessionId = keccak256("matrix-bystander");
        vm.prank(funder);
        bytes32 otherId = lock.open(other);

        // Axis 1: which probes answer. 0 = both, 1 = first only fails,
        // 2 = second only fails, 3 = both fail.
        uint256 probes = bound(probeSeed, 0, 3);
        tkn.setMode(UnreadableBalanceToken.Mode(uint8(bound(modeSeed, 0, 2))));
        if (probes == 0) tkn.setProbes(false, false);
        if (probes == 1) tkn.setProbes(true, true);
        if (probes == 2) tkn.setProbes(false, true);
        if (probes == 3) tkn.setProbes(true, false);

        // Axes 2 and 3: what the transfer does and what it says about it.
        uint256 report = bound(reportSeed, 0, 2);
        tkn.setTransfer(moves, report == 0, report == 2);

        uint256 custodyBefore = tkn.ledger(address(lock));
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertTrue(lock.lockOf(lockId).settled, "settlement always completes");

        uint256 credit = lock.pendingWithdrawals(beneficiary, address(tkn));
        uint256 custodyAfter = tkn.ledger(address(lock));

        // THE invariant. Custody must cover this lock's credit plus the
        // bystander lock it has not settled yet.
        assertGe(custodyAfter, credit + other.amount, "custody must cover every liability");

        // Equivalently, and more directly: value that left is never credited.
        uint256 left = custodyBefore - custodyAfter;
        assertLe(left + credit, t.amount, "delivered plus credited never exceeds the entitlement");

        // A reverted transfer is an EVM-level guarantee that nothing moved, so
        // the credit must be the full amount - the contract does not need to
        // measure to know that.
        if (report == 2) {
            assertEq(left, 0, "a reverted transfer cannot have moved anything");
            assertEq(credit, t.amount, "and must therefore be credited in full");
        }

        // Settling the bystander can never pay out MORE than it was funded
        // with, and can never leave the contract owing more than it holds. It
        // CAN pay out less: an asset that lies about its own balance, or that
        // refuses to be measured, can strand its own payees - see
        // `test_shrinkingBalanceLieOverridesAnExplicitTransferFailure`. What
        // must never happen is one lock being settled out of another's money.
        _assertBystanderIsNeverRaided(tkn, otherId, other.deadline, other.amount);
    }

    function _assertBystanderIsNeverRaided(UnreadableBalanceToken tkn, bytes32 otherId, uint64 deadline, uint256 funded)
        private
    {
        vm.warp(deadline);
        uint256 heldBefore = tkn.ledger(funder);
        uint256 creditBefore = lock.pendingWithdrawals(funder, address(tkn));
        lock.refund(otherId);
        uint256 paid =
            (tkn.ledger(funder) - heldBefore) + (lock.pendingWithdrawals(funder, address(tkn)) - creditBefore);
        assertLe(paid, funded, "a lock must never pay out more than it was funded with");
        assertGe(
            tkn.ledger(address(lock)),
            lock.pendingWithdrawals(funder, address(tkn)) + lock.pendingWithdrawals(beneficiary, address(tkn)),
            "custody must still cover every standing credit"
        );
    }

    /// @dev The same matrix, walked EXHAUSTIVELY rather than sampled: every one
    ///      of the 4 probe masks x 3 refusal flavours x 2 movement choices x 3
    ///      report choices, 72 cells, each asserted and each counted. The fuzz
    ///      above explores; this one proves the space is covered, so no cell can
    ///      quietly stop being reachable the way the dangerous one did.
    function test_payoutDecisionMatrixIsExhaustivelyCovered() public {
        // Tally of OUTCOME CLASSES, not of loop iterations. A count of
        // iterations inside literal-bound loops is a compile-time tautology and
        // proves nothing about reachability; what has to be shown is that each
        // distinct behaviour of `_deliver` is actually produced by some cell.
        uint256 pushedInFull; // measured, moved -> nothing credited
        uint256 creditedInFull; // measured, nothing moved -> whole amount credited
        uint256 strandedUnmeasured; // unmeasured, nothing moved -> nothing credited
        uint256 assumedDelivered; // unmeasured, moved -> nothing credited
        uint256 revertedAndCredited; // frame reverted -> whole amount credited

        for (uint256 probes = 0; probes < 4; probes++) {
            for (uint256 flavour = 0; flavour < 3; flavour++) {
                for (uint256 moves = 0; moves < 2; moves++) {
                    for (uint256 report = 0; report < 3; report++) {
                        uint256 snap = vm.snapshotState();
                        uint256 class_ = _assertOneMatrixCell(probes, flavour, moves == 1, report);
                        vm.revertToState(snap);
                        if (class_ == 0) pushedInFull++;
                        else if (class_ == 1) creditedInFull++;
                        else if (class_ == 2) strandedUnmeasured++;
                        else if (class_ == 3) assumedDelivered++;
                        else revertedAndCredited++;
                    }
                }
            }
        }

        // Each class must be produced by at least one cell. If a change made
        // one unreachable - the way the dangerous cell was unreachable before
        // the mock's axes were separated - this fails.
        assertGt(pushedInFull, 0, "no cell delivered a measured push");
        assertGt(creditedInFull, 0, "no cell credited a measured non-delivery");
        assertGt(strandedUnmeasured, 0, "no cell reached the unmeasured no-op stranding");
        assertGt(assumedDelivered, 0, "no cell reached the unmeasured assumed-delivery branch");
        assertGt(revertedAndCredited, 0, "no cell reached the reverted-frame branch");

        // The classes partition the matrix: every cell landed in exactly one.
        assertEq(
            pushedInFull + creditedInFull + strandedUnmeasured + assumedDelivered + revertedAndCredited,
            72,
            "every cell must resolve to exactly one modelled outcome"
        );
    }

    /// @dev Runs one cell and asserts its EXACT expected outcome, derived from
    ///      the specification of `_deliver` rather than from observation:
    ///
    ///        * a reverted frame moved nothing (EVM guarantee) -> credit == amount;
    ///        * otherwise, if both probes answered -> credit == amount - moved;
    ///        * otherwise (unmeasured) -> the push assumes delivery -> credit == 0,
    ///          and the payee keeps only whatever the asset chose to move.
    ///
    ///      Note that several cells are behaviourally identical, and
    ///      deliberately so: when the report axis selects "revert", the frame
    ///      rolls back both the movement and the probe-mask flip, so the `moves`
    ///      axis and part of the `probes` axis cannot influence that third of
    ///      the matrix; and the refusal flavour is invisible whenever the mask
    ///      never refuses. Those collapses are properties of the EVM and of the
    ///      mock, not gaps - which is exactly why the assertion is on modelled
    ///      outcomes and the tally is on classes.
    /// @return class_ 0 pushed in full, 1 credited in full, 2 unmeasured
    ///         stranding, 3 unmeasured assumed delivery, 4 reverted frame.
    function _assertOneMatrixCell(uint256 probes, uint256 flavour, bool moves, uint256 report)
        private
        returns (uint256 class_)
    {
        UnreadableBalanceToken tkn = new UnreadableBalanceToken();
        (bytes32 lockId, LockTerms memory t) = _openUnreadable(tkn);

        // Keep the exhaustive matrix explicit: a numeric-to-enum cast would
        // make a future fourth mode silently enter this test without a model.
        if (flavour == 0) tkn.setMode(UnreadableBalanceToken.Mode.Revert);
        else if (flavour == 1) tkn.setMode(UnreadableBalanceToken.Mode.BurnGas);
        else tkn.setMode(UnreadableBalanceToken.Mode.ShortAnswer);
        if (probes == 0) tkn.setProbes(false, false);
        if (probes == 1) tkn.setProbes(true, true);
        if (probes == 2) tkn.setProbes(false, true);
        if (probes == 3) tkn.setProbes(true, false);
        tkn.setTransfer(moves, report == 0, report == 2);

        uint256 custodyBefore = tkn.ledger(address(lock));
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        uint256 credit = lock.pendingWithdrawals(beneficiary, address(tkn));
        uint256 left = custodyBefore - tkn.ledger(address(lock));

        // Model the two probe answers. `probes == 1` refuses first and answers
        // second; `probes == 2` answers first and refuses second - unless the
        // frame reverted, which rolls the flip back with it.
        bool reverted = report == 2;
        bool firstAnswered = probes == 0 || probes == 2;
        bool secondAnswered = probes == 0 || (probes == 1 && !reverted) || (probes == 2 && reverted);
        bool measured = firstAnswered && secondAnswered;

        assertTrue(lock.lockOf(lockId).settled, "settlement always completes");

        if (reverted) {
            assertEq(left, 0, "a reverted frame cannot have moved anything");
            assertEq(credit, t.amount, "a reverted transfer is credited in full");
            return 4;
        }
        if (measured) {
            assertEq(left, moves ? t.amount : 0, "the measured delta is what moved");
            assertEq(credit, t.amount - left, "and the shortfall is exactly what did not");
            return moves ? 0 : 1;
        }
        // Unmeasured: the push assumes delivery, so nothing is credited either
        // way, and the payee keeps only what the asset chose to move.
        assertEq(credit, 0, "an unmeasured push must never mint a credit");
        assertEq(left, moves ? t.amount : 0, "the payee keeps only what the asset moved");
        assertGe(tkn.ledger(address(lock)), credit, "custody must cover the credit");
        return moves ? 3 : 2;
    }

    /// @dev The specific cell the audit exploited, isolated: unmeasurable, value
    ///      moved, failure reported. Either probe failing on its own is enough
    ///      to reach it, so both orders are exercised - and neither may mint a
    ///      credit for money that is already gone.
    function test_eitherProbeFailingAloneCannotMintAPhantomCredit() public {
        _assertNoPhantomCreditWithProbeMask(true, true, "first probe only");
        _assertNoPhantomCreditWithProbeMask(false, true, "second probe only");
        _assertNoPhantomCreditWithProbeMask(true, false, "both probes");
    }

    function _assertNoPhantomCreditWithProbeMask(bool refusing, bool flip, string memory label) private {
        uint256 snap = vm.snapshotState();

        UnreadableBalanceToken tkn = new UnreadableBalanceToken();
        (bytes32 lockId, LockTerms memory t) = _openUnreadable(tkn);
        tkn.setTransfer(true, false, false); // moves the funds, reports them unreadably
        tkn.setProbes(refusing, flip);

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertEq(tkn.ledger(beneficiary), t.amount, string.concat(label, ": value left custody"));
        assertEq(
            lock.pendingWithdrawals(beneficiary, address(tkn)), 0, string.concat(label, ": and must NOT be credited")
        );
        assertEq(tkn.ledger(address(lock)), 0, string.concat(label, ": custody exactly discharged"));

        vm.revertToState(snap);
    }

    /// @dev Control for the three cases above: the same token with both probes
    ///      answering reaches the same conclusion. The outcome must not depend
    ///      on whether the token allowed itself to be measured, which is the
    ///      whole point of the fix.
    function test_controlBothProbesAnsweringReachesTheSameConclusion() public {
        UnreadableBalanceToken tkn = new UnreadableBalanceToken();
        (bytes32 lockId, LockTerms memory t) = _openUnreadable(tkn);
        tkn.setTransfer(true, false, false);
        tkn.setProbes(false, false);

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertEq(tkn.ledger(beneficiary), t.amount, "delivered");
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), 0, "measured, so nothing booked");
    }

    /// @dev The EVM-fact branch. A CALL that returns 0 means the callee frame
    ///      was reverted and every state change it made was undone, so nothing
    ///      moved - that is a property of the EVM, not a claim by the token.
    ///      Acting on it is therefore safe even when the balance is unreadable,
    ///      and it is what keeps an honest-but-broken token's payee credited.
    function test_revertedTransferIsCreditedInFullEvenWhenUnmeasurable() public {
        UnreadableBalanceToken tkn = new UnreadableBalanceToken();
        (bytes32 lockId, LockTerms memory t) = _openUnreadable(tkn);
        tkn.setTransfer(true, true, true); // would move, but reverts
        tkn.setProbes(true, false); // and both probes refuse

        vm.expectEmit(true, true, true, true, address(lock));
        emit PayoutDeferred(beneficiary, address(tkn), t.amount);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertEq(tkn.ledger(beneficiary), 0, "the revert undid the move");
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), t.amount, "so the full amount is credited");
        assertEq(tkn.ledger(address(lock)), t.amount, "and custody still backs it");
    }

    /// @dev A `balanceOf` that burns every unit of gas it is given must not be
    ///      able to take the settlement down with it.
    function test_gasBurningBalanceOfCannotStopSettlement() public {
        UnreadableBalanceToken tkn = new UnreadableBalanceToken();
        (bytes32 lockId, LockTerms memory t) = _openUnreadable(tkn);
        tkn.setMode(UnreadableBalanceToken.Mode.BurnGas);
        tkn.setProbes(true, false);

        vm.prank(beneficiary);
        uint256 gasBefore = gasleft();
        lock.claim(lockId, SECRET);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(lock.lockOf(lockId).settled);
        assertEq(tkn.ledger(beneficiary), t.amount, "the transfer itself still went through");
        assertLt(gasUsed, 400_000, "two capped probes bound the damage");
    }

    /// @dev A creditor's standing credit is never destroyed on an unmeasurable
    ///      pull. The push and the pull default in OPPOSITE directions when
    ///      nothing can be measured, and both directions are the conservative
    ///      one for the path they are on: the push must not mint a liability it
    ///      cannot back, the pull must not retire one it cannot prove it paid.
    function test_unmeasurablePullRevertsAndKeepsTheCredit() public {
        UnreadableBalanceToken tkn = new UnreadableBalanceToken();
        (bytes32 lockId, LockTerms memory t) = _openUnreadable(tkn);

        // Create a credit honestly: measurable, transfer reverts.
        tkn.setTransfer(false, false, true);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), t.amount);

        // Now the token stops answering and claims the pull worked.
        tkn.setTransfer(false, true, false);
        tkn.setProbes(true, false);
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.PayoutFailed.selector);
        lock.withdraw(address(tkn));
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), t.amount, "credit survives");

        // Measurable and honest again: the credit is paid, exactly once.
        tkn.setProbes(false, false);
        tkn.setTransfer(true, true, false);
        vm.prank(beneficiary);
        lock.withdraw(address(tkn));
        assertEq(tkn.ledger(beneficiary), t.amount);
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), 0);
    }

    /// @dev WHY the two unmeasured defaults may differ without creating a hole,
    ///      and the reason it is correct rather than merely defensible: the
    ///      pull returns 0, which makes `_withdraw` revert, and THAT REVERT
    ///      ROLLS BACK THE VERY DELIVERY IT REFUSED TO COUNT. The default
    ///      matches whether the caller can undo. On the push, which may not
    ///      revert, an unproven delivery is irreversible and so must not be
    ///      credited; on the pull it is reversible and so must not be retired.
    function test_pullRefusalRollsBackTheDeliveryItRefusedToCount() public {
        UnreadableBalanceToken tkn = new UnreadableBalanceToken();
        (bytes32 lockId, LockTerms memory t) = _openUnreadable(tkn);

        // Create a credit honestly: measurable, transfer reverts.
        tkn.setTransfer(false, false, true);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), t.amount);

        // Now the asset moves the value but refuses to be measured.
        tkn.setTransfer(true, true, false);
        tkn.setProbes(true, false);

        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.PayoutFailed.selector);
        lock.withdraw(address(tkn));

        // The refusal cost nothing: the transfer it declined to count was
        // undone with the frame, so custody and credit are both exactly as
        // they were. Nothing was double-counted and nothing was lost.
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), t.amount, "credit intact");
        assertEq(tkn.ledger(beneficiary), 0, "and the delivery was rolled back with the revert");
        assertEq(tkn.ledger(address(lock)), t.amount, "custody still backs the credit exactly");
    }

    /// @dev The cost of `assumeDeliveredWhenUnmeasured` on the push, stated as a
    ///      test rather than only as a comment: an asset that is unmeasurable
    ///      AND completes `transfer` without moving anything leaves its payee
    ///      with nothing and no credit, and the custody behind that lock has no
    ///      claimant. There is deliberately no sweep. The damage is confined to
    ///      the lock that chose the asset - every other lock's custody is
    ///      untouched - which is the correct half of the trade, not a free one.
    function test_unmeasurableNoOpTransferStrandsThePayeeAndTheCustody() public {
        UnreadableBalanceToken tkn = new UnreadableBalanceToken();
        (bytes32 lockId, LockTerms memory t) = _openUnreadable(tkn);

        // A bystander lock in the same asset, to show the damage is confined.
        LockTerms memory other = _terms(address(tkn), AMOUNT, stranger, SECRET);
        other.sessionId = keccak256("stranding-bystander");
        vm.prank(funder);
        bytes32 otherId = lock.open(other);

        tkn.setProbes(true, false); // unmeasurable
        tkn.setTransfer(false, true, false); // completes, moves nothing

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertTrue(lock.lockOf(lockId).settled, "settled, and `Claimed(t)` stands");
        assertEq(tkn.ledger(beneficiary), 0, "the payee got nothing");
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), 0, "and holds no credit");

        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.NothingToWithdraw.selector);
        lock.withdraw(address(tkn));

        // Custody for BOTH locks is still here: the stranded amount, plus the
        // bystander's. Nothing was raided to cover the stranding.
        assertEq(tkn.ledger(address(lock)), t.amount + other.amount, "both locks' custody intact");

        // And once the asset behaves again the bystander settles in full,
        // proving the stranding never touched it.
        tkn.setProbes(false, false);
        tkn.setTransfer(true, true, false);
        vm.prank(stranger);
        lock.claim(otherId, SECRET);
        assertEq(tkn.ledger(stranger), other.amount, "the uninvolved lock paid out in full");
        assertEq(tkn.ledger(address(lock)), t.amount, "leaving exactly the stranded amount with no claimant");
    }

    /// @dev FINDING H, pinned as an accepted trade-off. `refund` is
    ///      permissionless and the push only runs above the floor, so with an
    ///      unmeasurable asset a third party's gas limit decides between two
    ///      different outcomes for the funder: a standing credit, or nothing.
    ///      The griefer gains nothing either way and no other lock is touched,
    ///      but the choice is theirs and the funder cannot take it back.
    function test_grieferGasLimitChoosesBetweenACreditAndNothingForTheFunder() public {
        uint256 creditWhenPushSkipped;
        uint256 creditWhenPushRuns;

        uint256 snap = vm.snapshotState();
        creditWhenPushSkipped = _refundUnmeasurableAndReadCredit(150_000);
        vm.revertToState(snap);
        creditWhenPushRuns = _refundUnmeasurableAndReadCredit(gasleft());

        assertEq(creditWhenPushSkipped, AMOUNT, "below the floor the funder keeps a claim");
        assertEq(creditWhenPushRuns, 0, "at or above it the unmeasured push books nothing");
    }

    function _refundUnmeasurableAndReadCredit(uint256 gasLimit) private returns (uint256) {
        UnreadableBalanceToken tkn = new UnreadableBalanceToken();
        (bytes32 lockId, LockTerms memory t) = _openUnreadable(tkn);
        tkn.setProbes(true, false);
        tkn.setTransfer(false, true, false); // completes, moves nothing
        vm.warp(t.deadline);

        vm.prank(stranger);
        (bool ok,) = address(lock).call{gas: gasLimit}(abi.encodeCall(lock.refund, (lockId)));
        assertTrue(ok, "the refund itself always completes");
        assertTrue(lock.lockOf(lockId).settled);
        assertEq(tkn.ledger(stranger), 0, "the griefer never gains anything");
        return lock.pendingWithdrawals(funder, address(tkn));
    }

    /// @dev The control for the above: with a measurable asset both branches
    ///      agree, so the lever exists only while the asset is already hostile.
    function test_grieferHasNoLeverOnAMeasurableAsset() public {
        uint256 snap = vm.snapshotState();
        uint256 low = _refundMeasurableAndReadCredit(150_000);
        vm.revertToState(snap);
        uint256 high = _refundMeasurableAndReadCredit(gasleft());
        assertEq(low, AMOUNT);
        assertEq(high, AMOUNT, "measured: both branches credit the funder identically");
    }

    function _refundMeasurableAndReadCredit(uint256 gasLimit) private returns (uint256) {
        UnreadableBalanceToken tkn = new UnreadableBalanceToken();
        (bytes32 lockId, LockTerms memory t) = _openUnreadable(tkn);
        tkn.setTransfer(false, true, false); // measurable, moves nothing
        vm.warp(t.deadline);
        vm.prank(stranger);
        (bool ok,) = address(lock).call{gas: gasLimit}(abi.encodeCall(lock.refund, (lockId)));
        assertTrue(ok);
        return lock.pendingWithdrawals(funder, address(tkn));
    }

    // ------------------------------------------------------------------
    // Unmeasurable assets are refused at the door
    // ------------------------------------------------------------------

    /// @dev The gas oracle. `balanceOf` answers a full-budget call and refuses a
    ///      capped one, with no flag and no cooperation - just `gasleft()`. When
    ///      `open` measured through the ordinary interface and the payout probed
    ///      under a cap, this token was measurable exactly where it did not
    ///      matter and unmeasurable exactly where it did, which handed it the
    ///      choice of which branch judged it. Both sites now probe under the
    ///      same cap, so it never gets a lock at all.
    function test_gasOracleTokenIsRefusedAtOpen() public {
        GasSensitiveBalanceToken tkn = new GasSensitiveBalanceToken();
        tkn.mint(funder, 1_000_000 ether);
        vm.prank(funder);
        tkn.approve(address(lock), type(uint256).max);

        LockTerms memory t = _terms(address(tkn), AMOUNT, beneficiary, SECRET);
        vm.prank(funder);
        vm.expectRevert(ConditionLockERC20V2.UnmeasurableAsset.selector);
        lock.open(t);
        assertEq(tkn.ledger(address(lock)), 0, "no custody was taken");

        // The very same token, willing to be measured, is perfectly acceptable.
        tkn.setAlwaysReadable(true);
        vm.prank(funder);
        bytes32 lockId = lock.open(t);
        assertEq(tkn.ledger(address(lock)), t.amount);

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);
        assertEq(tkn.ledger(beneficiary), t.amount, "delivered");
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), 0, "measured, so no phantom credit");
    }

    /// @dev Every flavour of "will not answer a capped probe" is refused, not
    ///      just the gas-sensitive one.
    function testFuzz_unmeasurableAssetsAreRefusedAtOpen(uint8 modeSeed) public {
        UnreadableBalanceToken tkn = new UnreadableBalanceToken();
        tkn.mint(funder, 1_000_000 ether);
        vm.prank(funder);
        tkn.approve(address(lock), type(uint256).max);
        tkn.setMode(UnreadableBalanceToken.Mode(uint8(bound(modeSeed, 0, 2))));
        tkn.setProbes(true, false);

        LockTerms memory t = _terms(address(tkn), AMOUNT, beneficiary, SECRET);
        vm.prank(funder);
        vm.expectRevert(ConditionLockERC20V2.UnmeasurableAsset.selector);
        lock.open(t);
        assertEq(tkn.ledger(address(lock)), 0, "no custody was taken");
    }

    /// @dev The SECOND probe in `_takeCustody` matters just as much: an asset
    ///      that answers before the pull and refuses after it is unmeasurable
    ///      too, and must not get a lock either. Checking only the first probe
    ///      would leave the oracle half-open.
    function test_assetThatStopsAnsweringDuringOpenIsRefused() public {
        UnreadableBalanceToken tkn = new UnreadableBalanceToken();
        tkn.mint(funder, 1_000_000 ether);
        vm.prank(funder);
        tkn.approve(address(lock), type(uint256).max);

        tkn.setProbes(false, false); // answers the first probe
        tkn.setFlipInTransferFrom(true); // and stops answering before the second

        LockTerms memory t = _terms(address(tkn), AMOUNT, beneficiary, SECRET);
        vm.prank(funder);
        vm.expectRevert(ConditionLockERC20V2.UnmeasurableAsset.selector);
        lock.open(t);
        assertEq(tkn.ledger(address(lock)), 0, "the pull was rolled back");
    }

    /// @dev The ERC-20 push is three calls (probe, transfer, probe), so it has
    ///      its own, higher gas floor. Sweep the limit across the range that
    ///      straddles it: at every point the claim either reverts wholesale or
    ///      settles with the entitlement conserved exactly. No limit exists at
    ///      which a probe or the transfer is half-funded and value goes
    ///      missing.
    function test_gasSweepOnErc20ClaimNeverStrandsTheEntitlement() public {
        for (uint256 g = 60_000; g <= 320_000; g += 311) {
            uint256 snap = vm.snapshotState();

            (bytes32 lockId, LockTerms memory t) = _open(token, beneficiary);
            vm.prank(beneficiary);
            (bool ok,) = address(lock).call{gas: g}(abi.encodeCall(lock.claim, (lockId, SECRET)));

            if (ok) {
                assertTrue(lock.lockOf(lockId).settled, "settled");
                assertEq(
                    token.balanceOf(beneficiary) + lock.pendingWithdrawals(beneficiary, address(token)),
                    t.amount,
                    "entitlement conserved at every gas limit"
                );
                assertEq(token.balanceOf(address(lock)), lock.pendingWithdrawals(beneficiary, address(token)));
            } else {
                assertFalse(lock.lockOf(lockId).settled, "a failed claim leaves no trace");
            }
            vm.revertToState(snap);
        }
    }

    // ------------------------------------------------------------------
    // Sizing PAYOUT_GAS_FLOOR_ERC20
    // ------------------------------------------------------------------

    function _openGreedy(GreedyProbeToken tkn) internal returns (bytes32 lockId, LockTerms memory t) {
        tkn.mint(funder, 1_000_000 ether);
        vm.prank(funder);
        tkn.approve(address(lock), type(uint256).max);
        t = _terms(address(tkn), AMOUNT, beneficiary, SECRET);
        vm.prank(funder);
        lockId = lock.open(t);
    }

    /// @dev The floor exists so that a push, once attempted, can always finish
    ///      its bookkeeping. The worst case it has to cover is two probes that
    ///      each consume their entire cap and still answer, plus a transfer that
    ///      consumes the entire stipend. Sweep the gas limit finely across the
    ///      floor and require that the greediest measured push does complete
    ///      somewhere in range, and that at every single limit the entitlement
    ///      is conserved.
    function test_floorIsSufficientForTheGreediestMeasuredPush() public {
        uint256 minDelivered = type(uint256).max;
        bool sawRevertAfterDelivering;

        for (uint256 g = 100_000; g <= 420_000; g += 331) {
            uint256 snap = vm.snapshotState();

            GreedyProbeToken tkn = new GreedyProbeToken();
            (bytes32 lockId, LockTerms memory t) = _openGreedy(tkn);
            tkn.setGreedy(true);

            vm.prank(beneficiary);
            (bool ok,) = address(lock).call{gas: g}(abi.encodeCall(lock.claim, (lockId, SECRET)));

            if (ok) {
                uint256 credit = lock.pendingWithdrawals(beneficiary, address(tkn));
                assertTrue(lock.lockOf(lockId).settled, "settled");
                assertEq(tkn.ledger(beneficiary) + credit, t.amount, "entitlement conserved at every gas limit");
                assertEq(tkn.ledger(address(lock)), credit, "custody equals the liability");
                if (credit == 0 && g < minDelivered) minDelivered = g;
            } else {
                assertFalse(lock.lockOf(lockId).settled, "a failed claim leaves no trace");
                // Once the floor lets a push through, more gas must never make
                // things worse: a revert above that point would be exactly the
                // "push attempted, bookkeeping ran dry" band the floor exists
                // to eliminate.
                if (minDelivered != type(uint256).max) sawRevertAfterDelivering = true;
            }
            vm.revertToState(snap);
        }

        emit log_named_uint("lowest gas limit at which the greediest push delivers", minDelivered);
        // The bound has to be able to bind. The sweep tops out at 419,746, so
        // `< 420_000` was satisfied by the loop's own range and could not fail.
        // Measured today: 230,414, i.e. the floor plus ~30k of call overhead.
        // 260_000 leaves room for compiler drift while still failing if the
        // floor or the probe cost regressed materially.
        assertLt(minDelivered, 260_000, "the greediest measured push must deliver close to the floor");
        assertFalse(sawRevertAfterDelivering, "no gas limit may attempt a push it cannot finish");
    }

    /// @dev The branch the floor comment actually sizes: the transfer fails
    ///      after both probes have eaten their caps, so the cold SSTORE and the
    ///      `PayoutDeferred` log still have to fit afterwards.
    function test_floorCoversTheCreditWriteAfterAFullyBurnedPush() public {
        uint256 minComplete = type(uint256).max;

        for (uint256 g = 100_000; g <= 420_000; g += 331) {
            uint256 snap = vm.snapshotState();

            GreedyProbeToken tkn = new GreedyProbeToken();
            (bytes32 lockId, LockTerms memory t) = _openGreedy(tkn);
            tkn.setGreedy(true);
            tkn.setTransfer(false, false); // moves nothing, reports garbage

            vm.prank(beneficiary);
            (bool ok,) = address(lock).call{gas: g}(abi.encodeCall(lock.claim, (lockId, SECRET)));

            if (ok) {
                if (g < minComplete) minComplete = g;
                assertTrue(lock.lockOf(lockId).settled);
                assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), t.amount, "full credit booked");
                assertEq(tkn.ledger(address(lock)), t.amount, "custody untouched");
            } else {
                assertFalse(lock.lockOf(lockId).settled);
            }
            vm.revertToState(snap);
        }

        emit log_named_uint("lowest gas limit at which the deferred claim completes", minComplete);
        assertLt(minComplete, 300_000, "the credit write must fit after the greediest failed push");
    }

    // ------------------------------------------------------------------
    // Partial withdrawal: a credit is never permanently stranded
    // ------------------------------------------------------------------

    /// @dev Credits accumulate across locks, so an entirely honest asset with a
    ///      per-transfer cap can respect that cap at every `open` and still be
    ///      unable to move the accumulated credit in one go. `withdraw` is
    ///      all-or-nothing by design - under-delivery must not silently retire
    ///      a credit - which left such a creditor with no way out at all.
    ///      `withdrawAmount` is that way out, and it needs no privileged path.
    function test_creditAboveTheAssetsTransferCapIsRescuedByWithdrawAmount() public {
        CappedTransferToken tkn = new CappedTransferToken();
        _fund(tkn, funder);

        LockTerms memory a = _tokenTerms(tkn, beneficiary);
        a.sessionId = keccak256("cap-a");
        LockTerms memory b = _tokenTerms(tkn, beneficiary);
        b.sessionId = keccak256("cap-b");

        vm.startPrank(funder);
        bytes32 idA = lock.open(a);
        bytes32 idB = lock.open(b);
        vm.stopPrank();

        // Force both payouts into the pull path with a temporary cap of zero.
        tkn.setCap(0);
        vm.startPrank(beneficiary);
        lock.claim(idA, SECRET);
        lock.claim(idB, SECRET);
        vm.stopPrank();
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), 2 * AMOUNT, "credits accumulated");

        // The asset now behaves normally, within a 4 ether per-transfer cap.
        // 6 ether is owed, so the whole-credit paths still cannot settle it.
        tkn.setCap(4 ether);
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.PayoutFailed.selector);
        lock.withdraw(address(tkn));
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.PayoutFailed.selector);
        lock.withdrawTo(address(tkn), stranger);
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), 2 * AMOUNT, "credit intact");

        // In instalments the creditor gets every unit of it.
        vm.expectEmit(true, true, true, true, address(lock));
        emit Withdrawal(beneficiary, address(tkn), beneficiary, 4 ether);
        vm.prank(beneficiary);
        lock.withdrawAmount(address(tkn), beneficiary, 4 ether);
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), 2 ether);

        vm.prank(beneficiary);
        lock.withdrawAmount(address(tkn), beneficiary, 2 ether);
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), 0);
        assertEq(tkn.balanceOf(beneficiary), 2 * AMOUNT, "paid in full, exactly once");
        assertEq(tkn.balanceOf(address(lock)), 0);
    }

    /// @dev The qualifier in "drainable in whatever instalments the asset can
    ///      deliver" is load-bearing. An instalment LARGER than the asset's own
    ///      per-transfer limit under-delivers and reverts exactly as `withdraw`
    ///      would, so a creditor has to pick instalments the asset will honour
    ///      - which may mean discovering the limit by bisection. Nothing is
    ///      lost while they do: a failed instalment rolls back completely.
    function test_instalmentAboveTheAssetsCapStillFails() public {
        CappedTransferToken tkn = new CappedTransferToken();
        _fund(tkn, funder);
        (bytes32 lockId, LockTerms memory t) = _open(tkn, beneficiary);

        tkn.setCap(0);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), t.amount);

        tkn.setCap(1 ether);
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.PayoutFailed.selector);
        lock.withdrawAmount(address(tkn), beneficiary, 2 ether);
        assertEq(
            lock.pendingWithdrawals(beneficiary, address(tkn)), t.amount, "credit intact after a failed instalment"
        );
        assertEq(tkn.balanceOf(beneficiary), 0, "and the partial move was rolled back");

        // Within the cap it works, and repeated instalments drain it entirely.
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(beneficiary);
            lock.withdrawAmount(address(tkn), beneficiary, 1 ether);
        }
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), 0, "fully drained");
        assertEq(tkn.balanceOf(beneficiary), t.amount, "and fully delivered");
    }

    /// @dev Operational consequence of having a gas floor at all, pinned so the
    ///      natspec claim is measured rather than asserted: the deferred path
    ///      succeeds at a far lower gas limit than the push path needs, and
    ///      `eth_estimateGas` binary-searches for the lowest SUCCEEDING limit.
    ///      An estimator-driven caller therefore always lands on the deferral
    ///      and never sees the optimistic push unless it adds headroom by hand.
    ///      Nothing is at risk; it is a UX cliff integrators must know about.
    function test_estimateGasWouldAlwaysChooseTheDeferredPath() public {
        uint256 minComplete = type(uint256).max;
        uint256 minPush = type(uint256).max;

        for (uint256 g = 40_000; g <= 400_000; g += 311) {
            uint256 snap = vm.snapshotState();
            (bytes32 lockId,) = _open(token, beneficiary);
            vm.prank(beneficiary);
            (bool ok,) = address(lock).call{gas: g}(abi.encodeCall(lock.claim, (lockId, SECRET)));
            if (ok) {
                if (g < minComplete) minComplete = g;
                if (lock.pendingWithdrawals(beneficiary, address(token)) == 0 && g < minPush) minPush = g;
            }
            vm.revertToState(snap);
        }

        emit log_named_uint("lowest limit that succeeds (what estimateGas returns)", minComplete);
        emit log_named_uint("lowest limit that pushes", minPush);
        assertGt(minPush, minComplete, "the push needs strictly more gas than mere success");
        assertGt(minPush - minComplete, 100_000, "and no default estimator buffer covers the gap");
    }

    /// @dev A saturated credit is not fully withdrawable and cannot be: the
    ///      excess was never backed by custody. What must hold is that the
    ///      BACKED part is always reachable.
    function test_saturatedCreditStillYieldsItsBackedPart() public {
        CappedTransferToken tkn = new CappedTransferToken();
        _fund(tkn, funder);
        (bytes32 lockId, LockTerms memory t) = _open(tkn, beneficiary);

        tkn.setCap(0);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        // Plant a saturated credit the way `_addSaturating` would leave one.
        bytes32 outer = keccak256(abi.encode(beneficiary, uint256(2)));
        bytes32 slot = keccak256(abi.encode(address(tkn), outer));
        vm.store(address(lock), slot, bytes32(type(uint256).max));
        tkn.setCap(type(uint256).max);

        // The fictitious total can never move.
        vm.prank(beneficiary);
        vm.expectRevert();
        lock.withdraw(address(tkn));

        // The real, backed part always can.
        vm.prank(beneficiary);
        lock.withdrawAmount(address(tkn), beneficiary, t.amount);
        assertEq(tkn.balanceOf(beneficiary), t.amount, "the backed part is reachable");
        assertEq(tkn.balanceOf(address(lock)), 0, "custody fully discharged");
    }

    function test_withdrawAmountRejectsMoreThanTheCredit() public {
        HeavyToken heavy = new HeavyToken();
        _fund(heavy, funder);
        (bytes32 lockId, LockTerms memory t) = _open(heavy, beneficiary);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);
        assertEq(lock.pendingWithdrawals(beneficiary, address(heavy)), t.amount);

        vm.prank(beneficiary);
        vm.expectRevert(
            abi.encodeWithSelector(ConditionLockCoreV2.AmountExceedsCredit.selector, t.amount, t.amount + 1)
        );
        lock.withdrawAmount(address(heavy), beneficiary, t.amount + 1);

        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.BadAmount.selector);
        lock.withdrawAmount(address(heavy), beneficiary, 0);

        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.ZeroAddress.selector);
        lock.withdrawAmount(address(heavy), address(0), 1);

        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.AssetMismatch.selector);
        lock.withdrawAmount(address(0), beneficiary, 1);

        vm.prank(stranger);
        vm.expectRevert(ConditionLockCoreV2.NothingToWithdraw.selector);
        lock.withdrawAmount(address(heavy), stranger, 1);

        assertEq(lock.pendingWithdrawals(beneficiary, address(heavy)), t.amount, "nothing moved");
    }

    // ------------------------------------------------------------------
    // Documented residue: the measurement is authoritative downwards too
    // ------------------------------------------------------------------

    /// @dev An asset that lies DOWNWARDS about its own balance - a colossal
    ///      figure before the transfer, the real one after - is believed, even
    ///      though `transfer` explicitly returned `false` and moved nothing.
    ///      The payee is stranded on this lock with no credit.
    ///
    ///      This is the safe half of making the measurement authoritative: no
    ///      credit is minted, so no other lock's custody is touched and the
    ///      damage stops at the lock that chose the asset. It is also not a
    ///      regression - an asset returning `true` while moving nothing has
    ///      always produced exactly this outcome. Pinned so the trade-off stays
    ///      a decision rather than a discovery.
    function test_shrinkingBalanceLieOverridesAnExplicitTransferFailure() public {
        ShrinkingLieToken tkn = new ShrinkingLieToken();
        tkn.mint(funder, 1_000_000 ether);
        vm.prank(funder);
        tkn.approve(address(lock), type(uint256).max);

        LockTerms memory t = _terms(address(tkn), AMOUNT, beneficiary, SECRET);
        vm.prank(funder);
        bytes32 lockId = lock.open(t);
        assertEq(tkn.ledger(address(lock)), AMOUNT, "custody real");

        tkn.setLying(true);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertEq(tkn.ledger(beneficiary), 0, "nothing was ever delivered");
        assertEq(lock.pendingWithdrawals(beneficiary, address(tkn)), 0, "and nothing was credited");
        assertEq(tkn.ledger(address(lock)), AMOUNT, "custody intact for every other lock");
    }

    /// @dev THE RESIDUE, pinned deliberately. Measurement defeats an asset that
    ///      lies about its RETURN PAYLOAD, because the balance is a second,
    ///      independent source. It cannot defeat an asset that lies about the
    ///      balance itself: one that moves the value and then reports an
    ///      unchanged balance makes the delta read zero, and a credit is booked
    ///      for value that has already gone.
    ///
    ///      This is not a hole the contract can close - if the asset's own
    ///      ledger is fiction there is no source of truth left on chain, and
    ///      the same lie also defeats `open`'s exact-accounting check and every
    ///      other integration the asset has. What matters is that the bar moved:
    ///      before, a phantom credit needed only a truthful asset with an
    ///      unusual return payload, which is a shape honest tokens really have.
    ///      Now it needs an asset that actively misreports `balanceOf`.
    ///
    ///      Recorded here so it is a known, bounded residue with a name, and so
    ///      that anything which makes it EASIER to reach fails this test.
    function test_assetLyingUpwardAboutItsBalanceCanStillMintAPhantomCredit() public {
        UpwardLieToken tkn = new UpwardLieToken();
        tkn.mint(funder, 1_000_000 ether);
        vm.prank(funder);
        tkn.approve(address(lock), type(uint256).max);

        LockTerms memory t = _terms(address(tkn), AMOUNT, beneficiary, SECRET);
        vm.prank(funder);
        bytes32 lockId = lock.open(t);
        assertEq(tkn.ledger(address(lock)), AMOUNT, "custody real at the door");

        // From here the asset reports a frozen balance to its caller.
        tkn.setFreeze(true, AMOUNT);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertEq(tkn.ledger(beneficiary), AMOUNT, "the value really did leave");
        assertEq(
            lock.pendingWithdrawals(beneficiary, address(tkn)),
            AMOUNT,
            "and a credit was booked anyway: an asset lying about balanceOf is beyond reach"
        );
        assertEq(tkn.ledger(address(lock)), 0, "custody is empty behind that credit");
    }

    /// @dev An asset that sends tokens back INTO the lock while the payout runs
    ///      drives the "after" balance above the "before" one. `moved` floors at
    ///      zero, so the whole amount is credited - and the returned tokens back
    ///      that credit. Conservation holds and the depositor only harms itself.
    function test_depositDuringPayoutCannotMintAnUnbackedCredit() public {
        BouncingToken tkn = new BouncingToken();
        _fund(tkn, funder);
        tkn.mint(address(tkn), 100 ether);

        (bytes32 lockId, LockTerms memory t) = _open(tkn, beneficiary);
        tkn.setBounce(AMOUNT + 1 ether); // send back MORE than it moved out

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        uint256 credit = lock.pendingWithdrawals(beneficiary, address(tkn));
        assertEq(credit, t.amount, "balance went up, so nothing counts as delivered");
        assertGe(tkn.balanceOf(address(lock)), credit, "custody still covers the liability");
    }

    // ------------------------------------------------------------------
    // Credit arithmetic on the path that must never revert
    // ------------------------------------------------------------------

    /// @dev D-002 says `_payout` must not revert. Checked `+=` on the credit
    ///      made it revertible: two credits for the same creditor and asset
    ///      summing past `2**256 - 1` reverted with Panic(0x11) AFTER
    ///      `Claimed(t)` had been emitted, permanently stranding the lock.
    ///      The add saturates instead. Reaching this at all needs a token that
    ///      misreports its own balances by ~2**256 units.
    function test_creditOverflowSaturatesInsteadOfRevertingAfterClaimed() public {
        LyingBalanceToken tok = new LyingBalanceToken();
        tok.setTransferSucceeds(false);
        uint256 half = 1 << 255;

        LockTerms memory a = _terms(address(tok), half, beneficiary, SECRET);
        a.sessionId = keccak256("overflow-a");
        LockTerms memory b = _terms(address(tok), half, beneficiary, SECRET);
        b.sessionId = keccak256("overflow-b");

        vm.prank(funder);
        bytes32 idA = lock.open(a);
        tok.setFakeBalance(0); // so the second open also measures an exact delta
        vm.prank(funder);
        bytes32 idB = lock.open(b);

        vm.prank(beneficiary);
        lock.claim(idA, SECRET);
        assertEq(lock.pendingWithdrawals(beneficiary, address(tok)), half, "first credit");

        vm.expectEmit(true, true, true, true, address(lock));
        emit Claimed(idB, lock.lockOf(idB).binding, beneficiary, SECRET);
        vm.prank(beneficiary);
        lock.claim(idB, SECRET);

        assertTrue(lock.lockOf(idB).settled, "the lock must reach a terminal outcome");
        assertEq(
            lock.pendingWithdrawals(beneficiary, address(tok)),
            type(uint256).max,
            "the credit saturates rather than reverting the settlement"
        );
    }

    // ------------------------------------------------------------------
    // Reentrant tokens
    // ------------------------------------------------------------------

    function test_reentrantTokenCannotReenterOpen() public {
        ReentrantToken bad = new ReentrantToken();
        _fund(bad, funder);
        bad.arm(address(lock), ReentrantToken.Mode.Open, bytes32(0), 0, true);

        (bytes32 lockId, LockTerms memory t) = _open(bad, beneficiary);

        assertEq(bad.attackLog(), bad.LOG_BLOCKED(), "the token tried and the guard rejected it");
        assertEq(bad.nestedSelector(), ReentrancyGuard.ReentrancyGuardReentrantCall.selector, "by the guard");
        assertEq(bad.balanceOf(address(lock)), t.amount, "accounting is exact");
        _assertLockStored(lock, lockId, t, funder, false);
    }

    /// @dev The push path only forwards 30k, which is barely enough for the
    ///      token's own bookkeeping, so this test asserts the property that
    ///      must hold regardless of how far the attacker gets: settlement is
    ///      terminal and the beneficiary's entitlement is paid exactly once,
    ///      whether by push or by credit.
    function test_reentrantTokenCannotClaimTwiceFromThePushPath() public {
        ReentrantToken bad = new ReentrantToken();
        _fund(bad, funder);
        bad.mint(beneficiary, 1 ether);
        LockTerms memory t = _tokenTerms(bad, beneficiary);
        vm.prank(funder);
        bytes32 lockId = lock.open(t);

        bad.arm(address(lock), ReentrantToken.Mode.Claim, lockId, SECRET, false);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertTrue(lock.lockOf(lockId).settled);
        // `!= LOG_SUCCEEDED` alone is satisfied by LOG_IDLE, i.e. by the attack
        // never having run. Pin that it ran AND that the reentrancy guard is
        // what rejected it, not a shortage of gas inside the stipend.
        assertEq(bad.attackLog(), bad.LOG_BLOCKED(), "the nested claim ran and was rejected");
        assertEq(
            bad.nestedSelector(),
            ReentrancyGuard.ReentrancyGuardReentrantCall.selector,
            "the guard, not out-of-gas, is what rejected it"
        );
        assertEq(
            bad.balanceOf(beneficiary) + lock.pendingWithdrawals(beneficiary, address(bad)),
            1 ether + t.amount,
            "paid exactly once"
        );
        assertEq(bad.balanceOf(address(lock)), lock.pendingWithdrawals(beneficiary, address(bad)));
    }

    function test_reentrantTokenCannotDrainThePullPath() public {
        ReentrantToken bad = new ReentrantToken();
        _fund(bad, funder);
        LockTerms memory t = _tokenTerms(bad, beneficiary);
        vm.prank(funder);
        bytes32 lockId = lock.open(t);

        // Force the push into the pull path so the full-gas path can be attacked.
        bad.setFailTransfer(true);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);
        assertEq(lock.pendingWithdrawals(beneficiary, address(bad)), t.amount);
        bad.setFailTransfer(false);

        // Now attack the full-gas pull path.
        bad.arm(address(lock), ReentrantToken.Mode.Withdraw, lockId, SECRET, false);
        vm.prank(beneficiary);
        lock.withdraw(address(bad));

        assertEq(bad.attackLog(), bad.LOG_BLOCKED(), "the nested withdraw ran and was rejected");
        assertEq(bad.nestedSelector(), ReentrancyGuard.ReentrancyGuardReentrantCall.selector, "by the guard");
        assertEq(bad.balanceOf(beneficiary), t.amount, "paid exactly once");
        assertEq(bad.balanceOf(address(lock)), 0);
        assertEq(lock.pendingWithdrawals(beneficiary, address(bad)), 0);
    }

    function test_reentrantTokenCannotRefundDuringClaim() public {
        ReentrantToken bad = new ReentrantToken();
        _fund(bad, funder);
        bad.mint(beneficiary, 1 ether);
        LockTerms memory t = _tokenTerms(bad, beneficiary);
        vm.prank(funder);
        bytes32 lockId = lock.open(t);

        bad.arm(address(lock), ReentrantToken.Mode.Refund, lockId, SECRET, false);
        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertEq(bad.attackLog(), bad.LOG_BLOCKED(), "the nested refund ran and was rejected");
        assertEq(
            bad.nestedSelector(),
            ReentrancyGuard.ReentrancyGuardReentrantCall.selector,
            "the guard, not out-of-gas, is what rejected it"
        );
        assertEq(lock.pendingWithdrawals(funder, address(bad)), 0, "no refund happened");
    }

    // ------------------------------------------------------------------
    // Accounting
    // ------------------------------------------------------------------

    /// @dev The custodied balance always equals the unsettled locks plus the
    ///      outstanding credits, whichever way each payout went.
    function test_tokenBalanceCoversOutstandingLiabilities() public {
        HeavyToken heavy = new HeavyToken();
        _fund(heavy, funder);

        LockTerms memory a = _tokenTerms(heavy, beneficiary);
        LockTerms memory b = _tokenTerms(heavy, beneficiary);
        b.sessionId = keccak256("session-2");
        b.amount = 1 ether;

        vm.startPrank(funder);
        bytes32 idA = lock.open(a);
        bytes32 idB = lock.open(b);
        vm.stopPrank();
        assertEq(heavy.balanceOf(address(lock)), a.amount + b.amount);

        vm.prank(beneficiary);
        lock.claim(idA, SECRET);
        // The heavy token cannot be pushed inside the stipend, so the tokens
        // stay custodied against the credit.
        assertEq(lock.pendingWithdrawals(beneficiary, address(heavy)), a.amount);
        assertEq(
            heavy.balanceOf(address(lock)),
            b.amount + lock.pendingWithdrawals(beneficiary, address(heavy)),
            "balance covers unsettled locks plus credits"
        );

        vm.warp(b.deadline);
        lock.refund(idB);
        assertEq(
            heavy.balanceOf(address(lock)),
            lock.pendingWithdrawals(beneficiary, address(heavy)) + lock.pendingWithdrawals(funder, address(heavy))
        );

        vm.prank(beneficiary);
        lock.withdraw(address(heavy));
        assertEq(heavy.balanceOf(address(lock)), lock.pendingWithdrawals(funder, address(heavy)));
    }

    /// @dev Whatever an honest-but-awkward token does, the beneficiary ends up
    ///      entitled to exactly `amount`, either in hand or as a credit.
    ///      Deliberately excluded: a token that moves the balance and then
    ///      reports a malformed result. That token has lied, conservation is
    ///      not recoverable, and the fail-closed behaviour is pinned separately
    ///      in `test_malformedReturnWithNoMovementIsTreatedAsFailure`.
    function testFuzz_beneficiaryEntitlementIsConserved(uint8 kind, uint256 amount) public {
        amount = bound(amount, 1, 1000 ether);
        MockERC20 tkn;
        if (kind % 5 == 0) {
            tkn = new MockERC20();
        } else if (kind % 5 == 1) {
            tkn = new NoReturnToken();
        } else if (kind % 5 == 2) {
            RevertingToken r = new RevertingToken();
            r.setReverts(true, false);
            tkn = MockERC20(address(r));
        } else if (kind % 5 == 3) {
            FalseReturnToken f = new FalseReturnToken();
            f.setFailures(true, false);
            tkn = MockERC20(address(f));
        } else {
            tkn = new HeavyToken();
        }
        _fund(tkn, funder);

        LockTerms memory t = _tokenTerms(tkn, beneficiary);
        t.amount = amount;
        vm.prank(funder);
        bytes32 lockId = lock.open(t);

        vm.prank(beneficiary);
        lock.claim(lockId, SECRET);

        assertEq(
            tkn.balanceOf(beneficiary) + lock.pendingWithdrawals(beneficiary, address(tkn)),
            amount,
            "entitlement must be conserved"
        );
        assertEq(tkn.balanceOf(address(lock)), lock.pendingWithdrawals(beneficiary, address(tkn)));
    }

    function test_withdrawOfAnAssetWithNoCreditReverts() public {
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.NothingToWithdraw.selector);
        lock.withdraw(address(token));
    }

    /// @dev `address(0)` is the ecrecover precompile: it accepts any calldata,
    ///      returns nothing and never reverts, which the transfer path would
    ///      read as a successful USDT-style payout. A credit withdrawn to it
    ///      would be zeroed in exchange for nothing. `_takeCustody` makes such
    ///      a credit unreachable today, so this is a latent hazard rather than
    ///      a live bug - but the withdraw path must refuse the asset kind on
    ///      its own, not rely on that.
    function test_zeroAssetIsRejectedByWithdrawEvenWithACreditPlanted() public {
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.AssetMismatch.selector);
        lock.withdraw(address(0));

        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.AssetMismatch.selector);
        lock.withdrawTo(address(0), beneficiary);

        // Plant a credit directly in storage, bypassing every contract path,
        // and prove the withdraw still refuses instead of silently burning it.
        // pendingWithdrawals is slot 2: slot 0 is ReentrancyGuard._status,
        // slot 1 is _locks.
        bytes32 outer = keccak256(abi.encode(beneficiary, uint256(2)));
        bytes32 slot = keccak256(abi.encode(address(0), outer));
        vm.store(address(lock), slot, bytes32(uint256(1 ether)));
        assertEq(lock.pendingWithdrawals(beneficiary, address(0)), 1 ether, "credit planted");

        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.AssetMismatch.selector);
        lock.withdraw(address(0));
        assertEq(lock.pendingWithdrawals(beneficiary, address(0)), 1 ether, "credit not destroyed");
    }

    // ------------------------------------------------------------------
    // Cross-function reentrancy from inside `open`
    // ------------------------------------------------------------------

    /// @dev The dangerous shape: `open` writes the lock, emits, and only THEN
    ///      calls out to the token. A hostile token gets control with the WHOLE
    ///      gas budget - no payout stipend caps it here - while a second, fully
    ///      claimable lock already sits in storage. Only `nonReentrant` stands
    ///      between that and a claim executed against a half-finished `open`.
    function test_hostileTokenCannotClaimAnOlderLockFromInsideOpen() public {
        ReentrantToken bad = new ReentrantToken();
        _fund(bad, funder);

        LockTerms memory first = _tokenTerms(bad, beneficiary);
        first.sessionId = keccak256("reentrancy-first");
        vm.prank(funder);
        bytes32 idFirst = lock.open(first);

        bad.arm(address(lock), ReentrantToken.Mode.Claim, idFirst, SECRET, true);

        LockTerms memory second = _tokenTerms(bad, beneficiary);
        second.sessionId = keccak256("reentrancy-second");
        vm.prank(funder);
        bytes32 idSecond = lock.open(second);

        assertEq(bad.attackLog(), bad.LOG_BLOCKED(), "the nested claim ran with full gas and was rejected");
        assertEq(bad.nestedSelector(), ReentrancyGuard.ReentrancyGuardReentrantCall.selector, "by the guard");
        assertFalse(lock.lockOf(idFirst).settled, "lock 1 must be untouched");
        assertFalse(lock.lockOf(idSecond).settled);
        assertEq(bad.balanceOf(address(lock)), 2 * AMOUNT, "custody is exact for both locks");
    }

    /// @dev Same, aimed at `withdraw`: a live credit exists and the token tries
    ///      to drain it from inside an unrelated `open`.
    function test_hostileTokenCannotWithdrawFromInsideOpen() public {
        ReentrantToken bad = new ReentrantToken();
        _fund(bad, funder);

        LockTerms memory first = _tokenTerms(bad, beneficiary);
        first.sessionId = keccak256("withdraw-first");
        vm.prank(funder);
        bytes32 idFirst = lock.open(first);

        bad.setFailTransfer(true);
        vm.prank(beneficiary);
        lock.claim(idFirst, SECRET);
        bad.setFailTransfer(false);
        assertEq(lock.pendingWithdrawals(beneficiary, address(bad)), AMOUNT, "credit exists");

        bad.arm(address(lock), ReentrantToken.Mode.Withdraw, idFirst, SECRET, true);

        LockTerms memory second = _tokenTerms(bad, beneficiary);
        second.sessionId = keccak256("withdraw-second");
        vm.prank(funder);
        lock.open(second);

        assertEq(bad.attackLog(), bad.LOG_BLOCKED(), "the nested withdraw ran with full gas and was rejected");
        assertEq(bad.nestedSelector(), ReentrancyGuard.ReentrancyGuardReentrantCall.selector, "by the guard");
        assertEq(lock.pendingWithdrawals(beneficiary, address(bad)), AMOUNT, "credit untouched");
    }

    /// @dev The two deployments share no guard state, so this records that no
    ///      value crosses over regardless: neither contract can ever hold the
    ///      other's asset, and a lock id from one is unknown to the other.
    function test_crossContractReentrancyMovesNothing() public {
        ConditionLockV2 nativeLock = new ConditionLockV2();
        vm.deal(funder, 100 ether);

        LockTerms memory n = _terms(address(0), AMOUNT, beneficiary, SECRET);
        vm.prank(funder);
        bytes32 nativeId = nativeLock.open{value: n.amount}(n);

        (bytes32 erc20Id,) = _open(token, beneficiary);

        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.LockUnknown.selector);
        lock.claim(nativeId, SECRET);
        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.LockUnknown.selector);
        nativeLock.claim(erc20Id, SECRET);

        assertEq(address(nativeLock).balance, n.amount);
        assertEq(token.balanceOf(address(lock)), AMOUNT);
        assertEq(address(lock).balance, 0, "the ERC-20 contract never holds ETH");
    }

    function test_creditsAreSegregatedPerAsset() public {
        HeavyToken first = new HeavyToken();
        HeavyToken second = new HeavyToken();
        _fund(first, funder);
        _fund(second, funder);

        (bytes32 idA,) = _open(first, beneficiary);
        (bytes32 idB,) = _open(second, beneficiary);

        vm.startPrank(beneficiary);
        lock.claim(idA, SECRET);
        lock.claim(idB, SECRET);
        vm.stopPrank();

        assertEq(lock.pendingWithdrawals(beneficiary, address(first)), AMOUNT);
        assertEq(lock.pendingWithdrawals(beneficiary, address(second)), AMOUNT);

        vm.prank(beneficiary);
        lock.withdraw(address(first));
        assertEq(lock.pendingWithdrawals(beneficiary, address(first)), 0);
        assertEq(lock.pendingWithdrawals(beneficiary, address(second)), AMOUNT, "other asset untouched");
        assertEq(first.balanceOf(beneficiary), AMOUNT);
        assertEq(second.balanceOf(beneficiary), 0);
    }
}
