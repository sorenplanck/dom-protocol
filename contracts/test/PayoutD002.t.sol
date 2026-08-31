// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ConditionLockCoreV2} from "../src/ConditionLockCoreV2.sol";
import {ConditionLockV2} from "../src/ConditionLockV2.sol";
import {LockTerms} from "../src/LockBinding.sol";
import {F3TestBase} from "./Base.t.sol";
import {
    GasBurnerReceiver,
    GoodReceiver,
    ReasonCapturingReceiver,
    ReentrantReceiver,
    ReturnBombReceiver,
    RevertingReceiver
} from "./mocks/HostileReceivers.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @notice Decision D-002: the settlement outcome and, above all, the
///         publication of `t`, must never be revertible by the payout target.
///         Everything hostile a receiver can do must degrade to a pull credit.
contract PayoutD002Test is F3TestBase {
    ConditionLockV2 internal lock;

    event Claimed(bytes32 indexed lockId, bytes32 indexed binding, address indexed beneficiary, uint256 t);
    event Refunded(bytes32 indexed lockId, bytes32 indexed binding, address indexed funder, uint256 amount);
    event PayoutDeferred(address indexed to, address indexed asset, uint256 amount);
    event Withdrawal(address indexed account, address indexed asset, address indexed to, uint256 amount);

    function setUp() public {
        _setUpTime();
        lock = new ConditionLockV2();
        vm.deal(funder, 1000 ether);
        vm.deal(stranger, 1000 ether);
    }

    function _openFor(address beneficiary_, uint256 secret) internal returns (bytes32 lockId, LockTerms memory t) {
        t = _terms(address(0), AMOUNT, beneficiary_, secret);
        vm.prank(funder);
        lockId = lock.open{value: t.amount}(t);
    }

    function _openFrom(address funder_, address beneficiary_) internal returns (bytes32 lockId, LockTerms memory t) {
        t = _terms(address(0), AMOUNT, beneficiary_, SECRET);
        vm.deal(funder_, funder_.balance + t.amount);
        vm.prank(funder_);
        lockId = lock.open{value: t.amount}(t);
    }

    // ------------------------------------------------------------------
    // Claim payout: hostile beneficiary
    // ------------------------------------------------------------------

    function test_claimRevealsTEvenWhenTheBeneficiaryRejectsEth() public {
        RevertingReceiver receiver = new RevertingReceiver();
        (bytes32 lockId, LockTerms memory t) = _openFor(address(receiver), SECRET);
        bytes32 binding = lock.lockOf(lockId).binding;

        vm.expectEmit(true, true, true, true, address(lock));
        emit Claimed(lockId, binding, address(receiver), SECRET);
        vm.expectEmit(true, true, true, true, address(lock));
        emit PayoutDeferred(address(receiver), address(0), t.amount);

        vm.prank(address(receiver));
        lock.claim(lockId, SECRET);

        assertTrue(lock.lockOf(lockId).settled, "settlement must be terminal");
        assertEq(lock.pendingWithdrawals(address(receiver), address(0)), t.amount);
        assertEq(address(lock).balance, t.amount, "value stays custodied until pulled");
    }

    function test_claimSurvivesABeneficiaryThatBurnsAllGas() public {
        GasBurnerReceiver receiver = new GasBurnerReceiver();
        (bytes32 lockId, LockTerms memory t) = _openFor(address(receiver), SECRET);

        vm.prank(address(receiver));
        uint256 gasBefore = gasleft();
        lock.claim(lockId, SECRET);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(lock.lockOf(lockId).settled);
        assertEq(lock.pendingWithdrawals(address(receiver), address(0)), t.amount);
        // The stipend caps the damage: the burner can never take more than what
        // was forwarded to it (plus the 2300 value stipend the EVM adds).
        assertLt(gasUsed, 200_000, "gas burner must not be able to drain the claimer");
    }

    function test_claimSurvivesAReturnBombBeneficiary() public {
        // Sized to fit inside the payout stipend: memory expansion to 64 KiB
        // costs ~14.3k gas, well under the 30k forwarded.
        ReturnBombReceiver bomb = new ReturnBombReceiver(64 * 1024);
        (bytes32 lockId, LockTerms memory t) = _openFor(address(bomb), SECRET);

        vm.prank(address(bomb));
        uint256 gasBefore = gasleft();
        lock.claim(lockId, SECRET);
        uint256 gasUsed = gasBefore - gasleft();

        // The bomb "succeeds", so the push goes through and nothing is deferred.
        assertEq(address(bomb).balance, t.amount);
        assertEq(lock.pendingWithdrawals(address(bomb), address(0)), 0);
        // Returndata was never copied, so the caller paid nothing for 64 KiB.
        assertLt(gasUsed, 120_000, "returndata must not be copied into memory");
    }

    /// @dev A return bomb far larger than the stipend can afford: the target
    ///      runs out of gas, the push fails, and the value is deferred. The
    ///      caller still pays nothing for the buffer.
    function test_claimSurvivesAnOversizedReturnBomb() public {
        ReturnBombReceiver bomb = new ReturnBombReceiver(8 * 1024 * 1024);
        (bytes32 lockId, LockTerms memory t) = _openFor(address(bomb), SECRET);

        vm.prank(address(bomb));
        uint256 gasBefore = gasleft();
        lock.claim(lockId, SECRET);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(lock.lockOf(lockId).settled);
        assertEq(lock.pendingWithdrawals(address(bomb), address(0)), t.amount);
        assertLt(gasUsed, 200_000, "an oversized bomb must stay inside the stipend");
    }

    // ------------------------------------------------------------------
    // Refund payout: hostile funder (the original D-002 finding)
    // ------------------------------------------------------------------

    function test_refundIsNeverBlockedByAFunderThatRejectsEth() public {
        RevertingReceiver rejectingFunder = new RevertingReceiver();

        // Open from a contract that cannot receive ETH back.
        LockTerms memory t = _terms(address(0), AMOUNT, beneficiary, SECRET);
        vm.deal(address(rejectingFunder), t.amount);
        vm.prank(address(rejectingFunder));
        bytes32 lockId = lock.open{value: t.amount}(t);
        assertEq(lock.lockOf(lockId).funder, address(rejectingFunder));

        vm.warp(t.deadline);
        vm.expectEmit(true, true, true, true, address(lock));
        emit PayoutDeferred(address(rejectingFunder), address(0), t.amount);
        lock.refund(lockId);

        // Before D-002 this refund reverted and the funds were stuck forever,
        // because the claim window had already closed.
        assertTrue(lock.lockOf(lockId).settled);
        assertEq(lock.pendingWithdrawals(address(rejectingFunder), address(0)), t.amount);
    }

    function test_refundSurvivesAGasBurningFunder() public {
        GasBurnerReceiver burner = new GasBurnerReceiver();
        (bytes32 lockId, LockTerms memory t) = _openFrom(address(burner), beneficiary);

        vm.warp(t.deadline);
        lock.refund(lockId);

        assertEq(lock.pendingWithdrawals(address(burner), address(0)), t.amount);
    }

    // ------------------------------------------------------------------
    // Gas floor
    // ------------------------------------------------------------------

    /// @dev A caller cannot use a tight gas limit to make the push receive less
    ///      than the promised stipend: below the floor the push is skipped and
    ///      the value is credited for pull instead.
    function test_tightGasLimitFallsBackToPullInsteadOfShortChangingThePush() public {
        GoodReceiver receiver = new GoodReceiver();
        (bytes32 lockId, LockTerms memory t) = _openFor(address(receiver), SECRET);

        vm.prank(address(receiver));
        (bool ok,) = address(lock).call{gas: 120_000}(abi.encodeCall(lock.claim, (lockId, SECRET)));
        assertTrue(ok, "claim must still complete");

        assertTrue(lock.lockOf(lockId).settled);
        assertEq(
            receiver.received() + lock.pendingWithdrawals(address(receiver), address(0)),
            t.amount,
            "the beneficiary is made whole either way"
        );
    }

    /// @dev Sweeps the gas limit across the whole interesting range for a claim
    ///      whose beneficiary is a brand-new contract account (the most
    ///      expensive push: cold access, value transfer, account creation). At
    ///      every single limit the outcome is one of exactly two things: the
    ///      whole transaction reverted and left no trace, or the lock settled
    ///      and the beneficiary is entitled to exactly `amount`. There is no
    ///      window in which `Claimed(t)` survives without a payout or a credit.
    function test_gasSweepOnClaimNeverStrandsTheEntitlement() public {
        for (uint256 g = 40_000; g <= 200_000; g += 137) {
            uint256 snap = vm.snapshotState();

            address fresh = address(new GoodReceiver());
            LockTerms memory t = _terms(address(0), AMOUNT, fresh, SECRET);
            vm.prank(funder);
            bytes32 lockId = lock.open{value: t.amount}(t);

            vm.prank(fresh);
            (bool ok,) = address(lock).call{gas: g}(abi.encodeCall(lock.claim, (lockId, SECRET)));

            if (ok) {
                assertTrue(lock.lockOf(lockId).settled, "settled");
                assertEq(
                    fresh.balance + lock.pendingWithdrawals(fresh, address(0)),
                    t.amount,
                    "entitlement conserved at every gas limit"
                );
                assertEq(address(lock).balance, lock.pendingWithdrawals(fresh, address(0)));
            } else {
                assertFalse(lock.lockOf(lockId).settled, "a failed claim leaves no trace");
            }
            vm.revertToState(snap);
        }
    }

    /// @dev ACCEPTED TRADE-OFF, pinned so it stays a decision rather than a
    ///      surprise. `refund` is permissionless and the push is only attempted
    ///      above the gas floor, so a third party can pick a gas limit that
    ///      settles the refund into a pull credit instead of a direct transfer.
    ///      The funder loses a transaction, never the money, and the credit is
    ///      only ever theirs. The alternative - gating who may call `refund` -
    ///      would be the privileged path invariant I2 forbids.
    function test_strangerCanForceTheFunderOntoThePullPathButNeverTakesTheMoney() public {
        LockTerms memory t = _defaultNativeTerms();
        vm.prank(funder);
        bytes32 lockId = lock.open{value: t.amount}(t);
        vm.warp(t.deadline);

        uint256 funderBefore = funder.balance;
        uint256 strangerBefore = stranger.balance;

        bool forced;
        for (uint256 g = 60_000; g <= 130_000; g += 250) {
            uint256 snap = vm.snapshotState();
            vm.prank(stranger);
            (bool ok,) = address(lock).call{gas: g}(abi.encodeCall(lock.refund, (lockId)));
            if (ok && lock.pendingWithdrawals(funder, address(0)) == t.amount) {
                forced = true;
                break;
            }
            vm.revertToState(snap);
        }

        assertTrue(forced, "the grief is real and this test would be vacuous otherwise");
        assertEq(funder.balance, funderBefore, "the funder was not paid directly");
        assertEq(stranger.balance, strangerBefore, "and the griefer gained nothing");
        assertEq(lock.pendingWithdrawals(funder, address(0)), t.amount, "the credit is the funder's");

        // The funder is still made whole, unilaterally, with no cooperation.
        vm.prank(funder);
        lock.withdraw(address(0));
        assertEq(funder.balance, funderBefore + t.amount);
        assertEq(address(lock).balance, 0);
    }

    /// @dev The hooks now report an amount rather than a boolean, and `_payout`
    ///      books the shortfall. For a value-bearing CALL that is exactly the
    ///      old boolean - the EVM moves the balance if and only if the call
    ///      succeeds - so every native outcome must be unchanged: full push or
    ///      full credit, never a partial split, on both claim and refund.
    function testFuzz_nativePayoutIsStillAllOrNothing(bool accepts, uint256 amount, bool viaRefund) public {
        amount = bound(amount, 1, 100 ether);
        address party = accepts ? address(new GoodReceiver()) : address(new RevertingReceiver());

        LockTerms memory t = _terms(address(0), amount, viaRefund ? beneficiary : party, SECRET);
        if (viaRefund) {
            vm.deal(party, party.balance + amount);
            vm.prank(party);
        } else {
            vm.deal(funder, amount);
            vm.prank(funder);
        }
        bytes32 lockId = lock.open{value: amount}(t);

        uint256 before = party.balance;
        if (viaRefund) {
            vm.warp(t.deadline);
            lock.refund(lockId);
        } else {
            vm.prank(party);
            lock.claim(lockId, SECRET);
        }

        uint256 delivered = party.balance - before;
        uint256 credit = lock.pendingWithdrawals(party, address(0));
        assertEq(delivered + credit, amount, "conserved");
        assertTrue(delivered == 0 || delivered == amount, "native payouts are never partial");
        assertTrue(credit == 0 || credit == amount, "native credits are never partial");
        assertEq(address(lock).balance, credit);
    }

    /// @dev Partial withdrawal exists for assets that cannot move a whole credit
    ///      in one transfer. ETH always can, so on this leg it is simply a
    ///      smaller withdrawal - but it must still be creditor-only, bounded by
    ///      the standing credit, and leave the remainder intact.
    function test_partialWithdrawalOnTheNativeLeg() public {
        RevertingReceiver receiver = new RevertingReceiver();
        uint256 amount = _deferredCreditFor(address(receiver));

        vm.prank(address(receiver));
        vm.expectRevert(abi.encodeWithSelector(ConditionLockCoreV2.AmountExceedsCredit.selector, amount, amount + 1));
        lock.withdrawAmount(address(0), stranger, amount + 1);

        vm.prank(stranger);
        vm.expectRevert(ConditionLockCoreV2.NothingToWithdraw.selector);
        lock.withdrawAmount(address(0), stranger, 1);

        uint256 before = stranger.balance;
        vm.prank(address(receiver));
        lock.withdrawAmount(address(0), stranger, amount / 3);
        assertEq(stranger.balance, before + amount / 3);
        assertEq(lock.pendingWithdrawals(address(receiver), address(0)), amount - amount / 3);

        vm.prank(address(receiver));
        lock.withdrawTo(address(0), stranger);
        assertEq(stranger.balance, before + amount);
        assertEq(lock.pendingWithdrawals(address(receiver), address(0)), 0);
        assertEq(address(lock).balance, 0);
    }

    /// @dev Two deployments and two locks: nothing a settlement does on one
    ///      lock can reach another lock's custody or another deployment.
    function test_noCrossContractOrCrossLockLeakage() public {
        ConditionLockV2 second = new ConditionLockV2();

        LockTerms memory t = _defaultNativeTerms();
        vm.startPrank(funder);
        bytes32 idA = lock.open{value: t.amount}(t);
        bytes32 idB = second.open{value: t.amount}(t);
        vm.stopPrank();

        assertTrue(idA != idB, "the contract address separates the two lock ids");

        vm.prank(beneficiary);
        vm.expectRevert(ConditionLockCoreV2.LockUnknown.selector);
        lock.claim(idB, SECRET);

        vm.prank(beneficiary);
        lock.claim(idA, SECRET);
        assertEq(address(lock).balance, 0);
        assertEq(address(second).balance, t.amount, "the other deployment is untouched");
    }

    // ------------------------------------------------------------------
    // Reentrancy
    // ------------------------------------------------------------------

    /// @dev `attackLog == LOG_BLOCKED` on its own only says the nested call
    ///      failed - it cannot tell a reentrancy rejection apart from running
    ///      out of gas inside the 30k stipend. This keeps the revert selector
    ///      and pins that `ReentrancyGuardReentrantCall` is what fires, so the
    ///      other reentrancy tests in this file are testing the guard and not
    ///      an accident of the gas budget.
    function test_nestedClaimInsideTheStipendIsRejectedByTheGuardNotByGas() public {
        ReasonCapturingReceiver r = new ReasonCapturingReceiver(address(lock));
        (bytes32 lockId, LockTerms memory t) = _openFor(address(r), SECRET);

        r.arm(lockId, SECRET);
        r.callClaim(lockId, SECRET);

        assertTrue(r.ran(), "the nested frame ran");
        assertEq(r.nestedReturnSize(), 4, "a four-byte custom error, not an empty out-of-gas");
        assertEq(
            r.nestedSelector(),
            ReentrancyGuard.ReentrancyGuardReentrantCall.selector,
            "the guard, not out-of-gas, is what rejects the nested claim"
        );
        assertTrue(lock.lockOf(lockId).settled);
        assertEq(address(r).balance, t.amount, "paid exactly once");
    }

    /// @dev The nested `claim` really is executed and really is rejected: the
    ///      attack log survives because the receiver does not abort its frame,
    ///      so the push succeeds and the beneficiary is paid exactly once.
    function test_reentrantBeneficiaryCannotClaimTwice() public {
        ReentrantReceiver attacker = new ReentrantReceiver(address(lock));
        (bytes32 lockId, LockTerms memory t) = _openFor(address(attacker), SECRET);
        attacker.arm(ReentrantReceiver.Mode.Claim, lockId, SECRET);

        attacker.callClaim(lockId, SECRET);

        assertTrue(lock.lockOf(lockId).settled);
        assertEq(attacker.attackLog(), attacker.LOG_BLOCKED(), "the nested claim ran and was rejected");
        assertEq(address(attacker).balance, t.amount, "paid exactly once");
        assertEq(lock.pendingWithdrawals(address(attacker), address(0)), 0);
        assertEq(address(lock).balance, 0, "no double payout");
    }

    function test_reentrantBeneficiaryCannotRefundDuringClaim() public {
        ReentrantReceiver attacker = new ReentrantReceiver(address(lock));
        (bytes32 lockId, LockTerms memory t) = _openFor(address(attacker), SECRET);
        attacker.arm(ReentrantReceiver.Mode.Refund, lockId, SECRET);

        attacker.callClaim(lockId, SECRET);

        assertEq(attacker.attackLog(), attacker.LOG_BLOCKED());
        assertEq(address(attacker).balance, t.amount);
        assertEq(lock.pendingWithdrawals(funder, address(0)), 0, "no refund happened");
        assertEq(address(lock).balance, 0);
    }

    function test_reentrantBeneficiaryCannotOpenDuringClaim() public {
        ReentrantReceiver attacker = new ReentrantReceiver(address(lock));
        (bytes32 lockId, LockTerms memory t) = _openFor(address(attacker), SECRET);
        attacker.arm(ReentrantReceiver.Mode.Open, lockId, SECRET);

        attacker.callClaim(lockId, SECRET);

        assertEq(attacker.attackLog(), attacker.LOG_BLOCKED());
        assertEq(address(attacker).balance, t.amount);
    }

    /// @dev Same attack, but the receiver aborts its own frame after being
    ///      rejected. The push fails, the value is deferred, and `Claimed(t)`
    ///      still stands.
    function test_reentrantBeneficiaryThatAbortsOnlyDefersItsOwnPayout() public {
        ReentrantReceiver attacker = new ReentrantReceiver(address(lock));
        (bytes32 lockId, LockTerms memory t) = _openFor(address(attacker), SECRET);
        attacker.arm(ReentrantReceiver.Mode.Claim, lockId, SECRET);
        attacker.setRevertAfterAttack(true);

        vm.expectEmit(true, true, true, true, address(lock));
        emit PayoutDeferred(address(attacker), address(0), t.amount);
        attacker.callClaim(lockId, SECRET);

        assertTrue(lock.lockOf(lockId).settled);
        assertEq(address(attacker).balance, 0);
        assertEq(lock.pendingWithdrawals(address(attacker), address(0)), t.amount);
        assertEq(address(lock).balance, t.amount);
    }

    /// @dev Sets up a deferred credit for `attacker` on a lock keyed by `salt`.
    function _deferCreditForAttacker(ReentrantReceiver attacker, bytes32 salt)
        internal
        returns (bytes32 lockId, uint256 amount)
    {
        LockTerms memory t = _terms(address(0), AMOUNT, address(attacker), SECRET);
        t.sessionId = salt;
        vm.prank(funder);
        lockId = lock.open{value: t.amount}(t);
        amount = t.amount;

        attacker.arm(ReentrantReceiver.Mode.Claim, lockId, SECRET);
        attacker.setRevertAfterAttack(true);
        attacker.callClaim(lockId, SECRET);
        attacker.setRevertAfterAttack(false);
        assertEq(lock.pendingWithdrawals(address(attacker), address(0)), amount);
    }

    /// @dev The pull path forwards all remaining gas, so this is where the
    ///      reentrancy guard, rather than the stipend, is doing the work. The
    ///      nested call is rejected; the outer withdrawal still pays exactly
    ///      once and the credit cannot be drained twice.
    function test_reentrantWithdrawIsRejectedAndPaysExactlyOnce() public {
        ReentrantReceiver attacker = new ReentrantReceiver(address(lock));
        (bytes32 lockId, uint256 amount) = _deferCreditForAttacker(attacker, keccak256("reenter-withdraw"));

        attacker.arm(ReentrantReceiver.Mode.Withdraw, lockId, SECRET);
        attacker.callWithdraw(address(0));

        assertEq(attacker.attackLog(), attacker.LOG_BLOCKED(), "the nested withdraw ran and was rejected");
        assertEq(address(attacker).balance, amount, "paid exactly once");
        assertEq(lock.pendingWithdrawals(address(attacker), address(0)), 0);
        assertEq(address(lock).balance, 0);
    }

    function test_reentrantWithdrawToIsRejectedAndPaysExactlyOnce() public {
        ReentrantReceiver attacker = new ReentrantReceiver(address(lock));
        (bytes32 lockId, uint256 amount) = _deferCreditForAttacker(attacker, keccak256("reenter-withdrawTo"));

        attacker.arm(ReentrantReceiver.Mode.WithdrawTo, lockId, SECRET);
        attacker.callWithdrawTo(address(0), address(attacker));

        assertEq(attacker.attackLog(), attacker.LOG_BLOCKED());
        assertEq(address(attacker).balance, amount);
        assertEq(lock.pendingWithdrawals(address(attacker), address(0)), 0);
    }

    function test_reentrantClaimFromTheFullGasPullPathIsRejected() public {
        ReentrantReceiver attacker = new ReentrantReceiver(address(lock));
        (bytes32 lockId, uint256 amount) = _deferCreditForAttacker(attacker, keccak256("reenter-claim-from-pull"));

        attacker.arm(ReentrantReceiver.Mode.Claim, lockId, SECRET);
        attacker.callWithdraw(address(0));

        assertEq(attacker.attackLog(), attacker.LOG_BLOCKED());
        assertEq(address(attacker).balance, amount);
        assertEq(address(lock).balance, 0);
    }

    /// @dev If the destination aborts the pull, the whole withdrawal reverts and
    ///      the credit is left exactly where it was.
    function test_abortedPullLeavesTheCreditIntact() public {
        ReentrantReceiver attacker = new ReentrantReceiver(address(lock));
        (bytes32 lockId, uint256 amount) = _deferCreditForAttacker(attacker, keccak256("aborted-pull"));

        attacker.arm(ReentrantReceiver.Mode.Withdraw, lockId, SECRET);
        attacker.setRevertAfterAttack(true);
        vm.expectRevert(ConditionLockCoreV2.PayoutFailed.selector);
        attacker.callWithdraw(address(0));
        assertEq(lock.pendingWithdrawals(address(attacker), address(0)), amount, "credit preserved");
        assertEq(address(lock).balance, amount);

        // Standing down, the creditor is paid in full, exactly once.
        attacker.arm(ReentrantReceiver.Mode.Passive, lockId, SECRET);
        attacker.setRevertAfterAttack(false);
        attacker.callWithdraw(address(0));
        assertEq(address(attacker).balance, amount);
        assertEq(lock.pendingWithdrawals(address(attacker), address(0)), 0);
        assertEq(address(lock).balance, 0);
    }

    // ------------------------------------------------------------------
    // withdraw / withdrawTo
    // ------------------------------------------------------------------

    function _deferredCreditFor(address who) internal returns (uint256 amount) {
        (bytes32 lockId, LockTerms memory t) = _openFor(who, SECRET);
        vm.prank(who);
        lock.claim(lockId, SECRET);
        amount = t.amount;
        assertEq(lock.pendingWithdrawals(who, address(0)), amount);
    }

    function test_singleWithdrawAfterDeferral() public {
        RevertingReceiver receiver = new RevertingReceiver();
        // A reverting receiver cannot pull to itself; it pulls to an EOA.
        uint256 amount = _deferredCreditFor(address(receiver));

        vm.expectEmit(true, true, true, true, address(lock));
        emit Withdrawal(address(receiver), address(0), stranger, amount);
        vm.prank(address(receiver));
        lock.withdrawTo(address(0), stranger);

        assertEq(lock.pendingWithdrawals(address(receiver), address(0)), 0);
        assertEq(address(lock).balance, 0);
    }

    function test_withdrawToSelfPathAndDoubleWithdrawYieldsNothing() public {
        GasBurnerReceiver burner = new GasBurnerReceiver();
        (bytes32 lockId, LockTerms memory t) = _openFrom(address(burner), beneficiary);
        vm.warp(t.deadline);
        lock.refund(lockId);
        assertEq(lock.pendingWithdrawals(address(burner), address(0)), t.amount);

        // The burner only burns gas inside `receive`, and the pull path
        // forwards everything it has, so this succeeds.
        vm.prank(address(burner));
        vm.expectRevert(ConditionLockCoreV2.PayoutFailed.selector);
        lock.withdraw(address(0));

        // It can still route the money somewhere sane.
        vm.prank(address(burner));
        lock.withdrawTo(address(0), stranger);
        assertEq(lock.pendingWithdrawals(address(burner), address(0)), 0);

        vm.prank(address(burner));
        vm.expectRevert(ConditionLockCoreV2.NothingToWithdraw.selector);
        lock.withdraw(address(0));
    }

    function test_withdrawWithNoCreditReverts() public {
        vm.prank(stranger);
        vm.expectRevert(ConditionLockCoreV2.NothingToWithdraw.selector);
        lock.withdraw(address(0));
    }

    /// @dev The native contract can only ever move ETH, so a withdrawal named
    ///      against any other asset is refused on the asset kind rather than
    ///      falling through to "you happen to have no credit". Relying on the
    ///      zero credit would be relying on an accident of the storage layout.
    function test_withdrawOfAForeignAssetIsRejectedInTheNativeContract() public {
        RevertingReceiver receiver = new RevertingReceiver();
        uint256 amount = _deferredCreditFor(address(receiver));

        vm.prank(address(receiver));
        vm.expectRevert(ConditionLockCoreV2.AssetMismatch.selector);
        lock.withdraw(address(0xBEEF));

        vm.prank(address(receiver));
        vm.expectRevert(ConditionLockCoreV2.AssetMismatch.selector);
        lock.withdrawTo(address(0xBEEF), stranger);

        // The real credit is untouched and still collectable.
        vm.prank(address(receiver));
        lock.withdrawTo(address(0), stranger);
        assertEq(lock.pendingWithdrawals(address(receiver), address(0)), 0);
        assertEq(address(lock).balance, 0);
        assertGt(amount, 0);
    }

    function test_withdrawToZeroAddressReverts() public {
        RevertingReceiver receiver = new RevertingReceiver();
        _deferredCreditFor(address(receiver));
        vm.prank(address(receiver));
        vm.expectRevert(ConditionLockCoreV2.ZeroAddress.selector);
        lock.withdrawTo(address(0), address(0));
    }

    function test_onlyTheCreditorCanMoveTheCredit() public {
        RevertingReceiver receiver = new RevertingReceiver();
        uint256 amount = _deferredCreditFor(address(receiver));

        vm.prank(stranger);
        vm.expectRevert(ConditionLockCoreV2.NothingToWithdraw.selector);
        lock.withdrawTo(address(0), stranger);
        assertEq(lock.pendingWithdrawals(address(receiver), address(0)), amount);
    }

    function test_creditsAccumulateAcrossDeferralsAndPayOutOnce() public {
        RevertingReceiver receiver = new RevertingReceiver();

        LockTerms memory a = _terms(address(0), 1 ether, address(receiver), SECRET);
        LockTerms memory b = _terms(address(0), 2 ether, address(receiver), SECRET);
        b.sessionId = keccak256("session-2");

        vm.startPrank(funder);
        bytes32 idA = lock.open{value: a.amount}(a);
        bytes32 idB = lock.open{value: b.amount}(b);
        vm.stopPrank();

        vm.startPrank(address(receiver));
        lock.claim(idA, SECRET);
        lock.claim(idB, SECRET);
        vm.stopPrank();

        assertEq(lock.pendingWithdrawals(address(receiver), address(0)), 3 ether);

        uint256 before = stranger.balance;
        vm.prank(address(receiver));
        lock.withdrawTo(address(0), stranger);
        assertEq(stranger.balance, before + 3 ether);
        assertEq(address(lock).balance, 0);

        vm.prank(address(receiver));
        vm.expectRevert(ConditionLockCoreV2.NothingToWithdraw.selector);
        lock.withdrawTo(address(0), stranger);
    }

    /// @dev Whatever the receiver does, the beneficiary's total entitlement is
    ///      exactly `amount`: paid directly, credited, or a clean split of the
    ///      two is impossible because the payout is atomic.
    function testFuzz_beneficiaryIsMadeWholeExactlyOnce(uint8 kind, uint256 amount) public {
        amount = bound(amount, 1, 100 ether);
        address receiver;
        if (kind % 4 == 0) {
            receiver = address(new GoodReceiver());
        } else if (kind % 4 == 1) {
            receiver = address(new RevertingReceiver());
        } else if (kind % 4 == 2) {
            receiver = address(new GasBurnerReceiver());
        } else {
            receiver = address(new ReturnBombReceiver(4 * 1024));
        }

        LockTerms memory t = _terms(address(0), amount, receiver, SECRET);
        vm.deal(funder, amount);
        vm.prank(funder);
        bytes32 lockId = lock.open{value: amount}(t);

        vm.prank(receiver);
        lock.claim(lockId, SECRET);

        assertEq(
            receiver.balance + lock.pendingWithdrawals(receiver, address(0)), amount, "entitlement must be conserved"
        );
        assertEq(address(lock).balance, lock.pendingWithdrawals(receiver, address(0)));
    }
}
