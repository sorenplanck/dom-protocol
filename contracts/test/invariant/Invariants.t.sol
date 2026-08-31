// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ConditionLockERC20V2} from "../../src/ConditionLockERC20V2.sol";
import {ConditionLockV2} from "../../src/ConditionLockV2.sol";
import {MockERC20, UnreadableBalanceToken} from "../mocks/HostileTokens.sol";
import {Erc20Handler, NativeHandler} from "./Handlers.sol";
import {Test} from "forge-std/Test.sol";

/// @notice Invariants for the native-ETH lock, driven by a handler that mixes
///         honest actors with receivers that revert, burn gas and reenter.
contract ConditionLockV2InvariantTest is Test {
    ConditionLockV2 internal lock;
    NativeHandler internal handler;

    function setUp() public {
        vm.warp(1_000_000);
        lock = new ConditionLockV2();
        handler = new NativeHandler(lock);
        targetContract(address(handler));
    }

    /// @dev Invariant I4: claim and refund are mutually exclusive outcomes.
    function invariant_claimXorRefund() public view {
        uint256 n = handler.lockCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 id = handler.lockIds(i);
            assertFalse(handler.wasClaimed(id) && handler.wasRefunded(id), "claim and refund both happened");
            bool terminal = handler.wasClaimed(id) || handler.wasRefunded(id);
            assertEq(lock.lockOf(id).settled, terminal, "on-chain flag disagrees with the observed outcome");
        }
    }

    /// @dev No lock ever pays out more than the amount it was funded with.
    function invariant_noLockPaysMoreThanItsAmount() public view {
        uint256 n = handler.lockCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 id = handler.lockIds(i);
            assertLe(handler.paidOutOfLock(id), handler.lockAmount(id), "overpaid");
        }
    }

    /// @dev The custodied balance is exactly the outstanding liabilities: every
    ///      wei is either still locked or already credited to someone.
    function invariant_solvency() public view {
        uint256 liabilities = handler.outstandingLockValue() + handler.totalCredits();
        assertEq(address(lock).balance, liabilities, "balance must equal outstanding liabilities");
    }

    /// @dev Credits only ever shrink through `withdraw` / `withdrawTo`.
    function invariant_creditsAreMonotoneOutsideWithdraw() public view {
        assertFalse(handler.sawIllegalCreditDecrease(), "a credit vanished outside a withdrawal");
    }

    /// @dev A terminal lock stays terminal, and only its beneficiary can claim.
    function invariant_terminalOutcomesAreFinal() public view {
        assertFalse(handler.sawTerminalityRegression(), "a settled lock settled again");
    }

    /// @dev The invariants above are only worth anything if the handler can
    ///      actually reach the interesting states. This drives it by hand and
    ///      checks that opens, claims, refunds and deferred credits all occur,
    ///      so a handler that silently swallowed every call could not pass.
    function test_handlerReachesEveryInterestingState() public {
        for (uint256 i = 0; i < handler.actorCount(); i++) {
            handler.open(i, i, 1 ether, 10 days, 1234 + i);
        }
        assertEq(handler.lockCount(), handler.actorCount(), "no lock was opened");

        for (uint256 i = 0; i < handler.lockCount(); i++) {
            handler.claim(i, 0, false);
        }
        uint256 claimedCount;
        for (uint256 i = 0; i < handler.lockCount(); i++) {
            if (handler.wasClaimed(handler.lockIds(i))) claimedCount++;
        }
        assertGt(claimedCount, 0, "no lock was claimed");
        assertGt(handler.totalCredits(), 0, "no payout was ever deferred");

        // Open a fresh batch and let them all expire into refunds.
        uint256 before = handler.lockCount();
        handler.open(0, 1, 2 ether, 1 days, 999);
        handler.warp(2 days);
        handler.refund(before, 0);
        assertTrue(handler.wasRefunded(handler.lockIds(before)), "no lock was refunded");

        handler.withdraw(0);
        handler.withdrawTo(4, 0);
    }
}

/// @notice The same invariants for the ERC-20 lock, per token.
contract ConditionLockERC20V2InvariantTest is Test {
    ConditionLockERC20V2 internal lock;
    Erc20Handler internal handler;

    function setUp() public {
        vm.warp(1_000_000);
        lock = new ConditionLockERC20V2();
        handler = new Erc20Handler(lock);
        // Every run starts with a real credit and real custody in the
        // unmeasurable asset, so the invariant for it is never 0 >= 0.
        handler.seedUnmeasurableDeferral();
        targetContract(address(handler));
    }

    function invariant_claimXorRefund() public view {
        uint256 n = handler.lockCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 id = handler.lockIds(i);
            assertFalse(handler.wasClaimed(id) && handler.wasRefunded(id), "claim and refund both happened");
            assertEq(
                lock.lockOf(id).settled,
                handler.wasClaimed(id) || handler.wasRefunded(id),
                "on-chain flag disagrees with the observed outcome"
            );
        }
    }

    function invariant_noLockPaysMoreThanItsAmount() public view {
        uint256 n = handler.lockCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 id = handler.lockIds(i);
            assertLe(handler.paidOutOfLock(id), handler.lockAmount(id), "overpaid");
        }
    }

    /// @dev Per token, the custodied balance covers every unsettled lock plus
    ///      every credit.
    function invariant_solvencyPerToken() public view {
        uint256 n = handler.tokenCount();
        for (uint256 i = 0; i < n; i++) {
            MockERC20 tkn = MockERC20(handler.tokens(i));
            assertGe(
                tkn.balanceOf(address(lock)), handler.liabilitiesIn(address(tkn)), "token balance below liabilities"
            );
        }
    }

    /// @dev The same solvency check for the asset that can stop answering
    ///      probes mid-campaign. Every other token in the set consents to being
    ///      measured, so without this one the campaign would never exercise the
    ///      branch where the contract has to decide what happened without
    ///      evidence - which is precisely where the drain lived.
    function invariant_solvencyForTheUnmeasurableAsset() public view {
        // Non-vacuity first: the comparison below is only worth making because
        // the campaign starts from a settled deferral in this asset.
        assertTrue(handler.unmeasurableSeeded(), "the unmeasurable asset was never put in play");
        assertGt(handler.unmeasurableDeferrals(), 0, "no payout in the unmeasurable asset ever deferred");

        address asset = handler.unmeasurableAsset();
        assertGe(
            UnreadableBalanceToken(asset).ledger(address(lock)),
            handler.liabilitiesIn(asset),
            "unmeasurable asset: balance below liabilities"
        );
    }

    function invariant_terminalOutcomesAreFinal() public view {
        assertFalse(handler.sawTerminalityRegression(), "a settled lock settled again");
    }

    /// @dev The ERC-20 contract must never hold ETH: it has no way to move it out.
    function invariant_neverHoldsEther() public view {
        assertEq(address(lock).balance, 0);
    }

    /// @dev Reachability guard. Without this, all five invariants above could
    ///      hold vacuously if the handler silently swallowed every call. Drives
    ///      the handler by hand over every actor and every token and requires
    ///      that opens, claims, refunds, direct pushes and deferred credits all
    ///      actually occur.
    function test_handlerReachesEveryInterestingState() public {
        uint256 actors = handler.actorCount();
        uint256 kinds = handler.tokenCount();
        assertGt(kinds, 1, "the campaign must span more than one token behaviour");

        for (uint256 i = 0; i < actors; i++) {
            for (uint256 j = 0; j < kinds; j++) {
                handler.open(i, i, j, 1 ether, 10 days, 1234 + i * 10 + j);
            }
        }
        // The seeded deferral in the unmeasurable asset already occupies one
        // slot before this test opens anything.
        uint256 seeded = 1;
        uint256 opened = handler.lockCount();
        assertEq(opened, seeded + actors * kinds, "no ERC-20 lock was opened");
        assertTrue(handler.unmeasurableSeeded(), "the unmeasurable asset must start in play");
        assertGt(handler.unmeasurableDeferrals(), 0, "the seed must have produced a real deferral");
        assertGt(
            UnreadableBalanceToken(handler.unmeasurableAsset()).ledger(address(lock)),
            0,
            "the seed must have left real custody behind the credit"
        );
        assertGt(
            handler.liabilitiesIn(handler.unmeasurableAsset()),
            0,
            "so the solvency invariant for that asset is never 0 >= 0"
        );

        uint256 holdingsBeforeClaims = _actorHoldings();
        for (uint256 i = 0; i < opened; i++) {
            handler.claim(i);
        }

        uint256 claimed;
        for (uint256 i = 0; i < opened; i++) {
            if (handler.wasClaimed(handler.lockIds(i))) claimed++;
        }
        assertEq(claimed, opened, "every claim should have gone through");

        uint256 credited;
        for (uint256 j = 0; j < kinds; j++) {
            MockERC20 tkn = MockERC20(handler.tokens(j));
            for (uint256 i = 0; i < actors; i++) {
                credited += lock.pendingWithdrawals(handler.actors(i), address(tkn));
            }
        }
        assertGt(credited, 0, "no ERC-20 payout was ever deferred");
        // `pushed` must be a DELTA. The handler's constructor mints a million
        // of every token to every actor, so the absolute sum is ~16,000,000
        // ether before a single lock is opened and `assertGt(pushed, 0)` on it
        // could never fail.
        assertGt(_actorHoldings() - holdingsBeforeClaims, 0, "no ERC-20 payout was ever pushed directly");

        // Refund path.
        handler.open(0, 1, 0, 2 ether, 1 days, 4242);
        uint256 fresh = handler.lockCount() - 1;
        handler.warp(2 days);
        handler.refund(fresh, 0);
        assertTrue(handler.wasRefunded(handler.lockIds(fresh)), "no ERC-20 lock was ever refunded");

        // Withdrawal path, and the hostility toggles the campaign relies on.
        handler.withdraw(0, 1);
        handler.withdrawTo(0, 1, 1);
        handler.toggleTokenHostility(2, true, 0);
        handler.toggleTokenHostility(3, true, 2);

        // The unmeasurable asset. Break it so the transfer REVERTS: a reverted
        // frame provably moved nothing, so a credit is guaranteed and the
        // partial-withdrawal path below has something real to act on.
        handler.openUnmeasurable(0, 1, 1 ether, 5 days);
        uint256 unmeasurableLock = handler.lockCount() - 1;
        handler.breakUnmeasurable(0, true, false, true, false, true);
        handler.claim(unmeasurableLock);
        assertTrue(handler.wasClaimed(handler.lockIds(unmeasurableLock)), "the unmeasurable asset was never claimed");

        // `withdrawAmount` must actually be ENTERED, not skipped by a guard.
        // The credit belongs to the lock's beneficiary - actor 1, because
        // `openUnmeasurable` was called with `beneficiarySeed = 1` - so the
        // withdrawal has to be attempted as actor 1, and the asset has to be
        // measurable and willing to move again. Attempting it as actor 0, whose
        // credit in that asset is zero, is a provable no-op.
        address unmeasurableAsset = handler.unmeasurableAsset();
        address creditor = handler.actors(1);
        handler.breakUnmeasurable(0, false, false, true, true, false);
        uint256 creditBefore = lock.pendingWithdrawals(creditor, unmeasurableAsset);
        assertGt(creditBefore, 0, "the configured cell must actually produce a credit");

        handler.withdrawUnmeasurable(1, 1, 1, true);
        uint256 creditAfter = lock.pendingWithdrawals(creditor, unmeasurableAsset);
        assertLt(creditAfter, creditBefore, "withdrawAmount must have been entered and moved value");
        assertGt(creditAfter, 0, "and it must be a PARTIAL withdrawal, not the whole credit");

        // Same for the measurable-token partial path: token 4 is the capped
        // asset, whose payouts always defer, and actor 0 is the beneficiary of
        // the lock opened for it above.
        uint256 cappedIndex = 4;
        address capped = address(handler.tokens(cappedIndex));
        uint256 cappedCredit = lock.pendingWithdrawals(handler.actors(0), capped);
        assertGt(cappedCredit, 0, "the capped asset must have left a credit to draw down");
        handler.withdrawPartial(0, cappedIndex, 0, 1);
        assertLt(
            lock.pendingWithdrawals(handler.actors(0), capped), cappedCredit, "withdrawPartial must move value too"
        );

        // The observed-payout ghost reads reality, not the lock's face amount:
        // a payout that moved nothing and credited nothing records zero, where
        // the old accumulator would have recorded the whole amount.
        _assertObservedGhostIsNotTheFaceAmount();
    }

    /// @dev Opens a lock in the unmeasurable asset, makes it complete `transfer`
    ///      without moving anything while refusing every probe, and checks the
    ///      ghost records what actually happened - zero - rather than the lock's
    ///      amount. This is the difference between the accumulator meaning
    ///      something and being a restatement of the constant it is compared to.
    function _assertObservedGhostIsNotTheFaceAmount() private {
        handler.breakUnmeasurable(0, false, false, true, true, false);
        handler.openUnmeasurable(2, 2, 3 ether, 5 days);
        uint256 id = handler.lockCount() - 1;
        bytes32 lockId = handler.lockIds(id);

        // Unmeasurable, and the transfer completes while moving nothing.
        handler.breakUnmeasurable(0, true, false, false, true, false);
        handler.claim(id);

        assertTrue(handler.wasClaimed(lockId), "the lock settled");
        assertGt(handler.lockAmount(lockId), 0, "and it had a non-zero face amount");
        assertEq(handler.paidOutOfLock(lockId), 0, "but nothing was observed leaving, so the ghost records zero");
    }

    /// @dev Sum of every actor's holdings across the whole token set, used as a
    ///      baseline so "was anything pushed" is measured as a change and not
    ///      as an absolute that starts enormous.
    function _actorHoldings() private view returns (uint256 total) {
        for (uint256 j = 0; j < handler.tokenCount(); j++) {
            MockERC20 tkn = MockERC20(handler.tokens(j));
            for (uint256 i = 0; i < handler.actorCount(); i++) {
                total += tkn.balanceOf(handler.actors(i));
            }
        }
    }

    /// @dev Pins the vacuity the audit found, so the delta form above cannot
    ///      quietly regress to an absolute one: the naive metric is already
    ///      enormous before any claim runs.
    function test_absoluteHoldingsMetricWouldBeVacuous() public {
        Erc20Handler fresh = new Erc20Handler(new ConditionLockERC20V2());
        uint256 absolute;
        for (uint256 j = 0; j < fresh.tokenCount(); j++) {
            MockERC20 tkn = MockERC20(fresh.tokens(j));
            for (uint256 i = 0; i < fresh.actorCount(); i++) {
                absolute += tkn.balanceOf(fresh.actors(i));
            }
        }
        assertEq(fresh.lockCount(), 0, "no lock opened yet");
        assertGt(absolute, 0, "so asserting this is non-zero proves nothing about pushes");
    }
}
