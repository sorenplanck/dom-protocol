// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ConditionLockERC20V2} from "../../src/ConditionLockERC20V2.sol";
import {ConditionLockV2} from "../../src/ConditionLockV2.sol";
import {LockTerms} from "../../src/LockBinding.sol";
import {GasBurnerReceiver, GoodReceiver, ReentrantReceiver, RevertingReceiver} from "../mocks/HostileReceivers.sol";
import {
    AmbiguousReturnToken,
    CappedTransferToken,
    HeavyToken,
    MockERC20,
    RevertingToken,
    UnreadableBalanceToken
} from "../mocks/HostileTokens.sol";
import {Test} from "forge-std/Test.sol";

/// @notice Shared ghost bookkeeping for both invariant handlers.
/// @dev The handler is the only thing allowed to touch the lock during an
///      invariant campaign, so every state change is mirrored here and the
///      invariants can be stated as equalities rather than inequalities.
abstract contract BaseHandler is Test {
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    address[] public actors;
    bytes32[] public lockIds;

    mapping(bytes32 => bool) internal known;
    mapping(bytes32 => uint256) public lockAmount;
    mapping(bytes32 => address) public lockFunder;
    mapping(bytes32 => address) public lockBeneficiary;
    mapping(bytes32 => uint256) public lockSecret;
    mapping(bytes32 => bool) public wasClaimed;
    mapping(bytes32 => bool) public wasRefunded;
    /// @dev How much value a lock's settlement actually caused to leave this
    ///      contract, OBSERVED rather than assumed: the payee's asset balance
    ///      delta plus their credit delta, measured across the settlement call.
    ///      An earlier version accumulated `lockAmount[id]` here, which is the
    ///      very constant `invariant_noLockPaysMoreThanItsAmount` compares it
    ///      against - the comparison could then only fire on a second terminal
    ///      transition, which a different invariant already covers, and it was
    ///      blind to a lock genuinely paying out twice its amount.
    mapping(bytes32 => uint256) public paidOutOfLock;

    /// @dev Set if `pendingWithdrawals` ever decreased outside a withdrawal, or
    ///      if a terminal lock ever became non-terminal again.
    bool public sawIllegalCreditDecrease;
    bool public sawTerminalityRegression;

    uint256 public sessionCounter;

    /// @dev Call counters, printed by `forge test -vvv` invariant summaries.
    uint256 public callsOpen;
    uint256 public callsClaim;
    uint256 public callsRefund;
    uint256 public callsWithdraw;

    function lockCount() external view returns (uint256) {
        return lockIds.length;
    }

    function actorCount() external view returns (uint256) {
        return actors.length;
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }

    function _pickLock(uint256 seed) internal view returns (bytes32) {
        if (lockIds.length == 0) return bytes32(0);
        return lockIds[seed % lockIds.length];
    }

    function _recordOpen(bytes32 lockId, LockTerms memory t, address funder_, uint256 secret) internal {
        if (known[lockId]) return;
        known[lockId] = true;
        lockIds.push(lockId);
        lockAmount[lockId] = t.amount;
        lockFunder[lockId] = funder_;
        lockBeneficiary[lockId] = t.beneficiary;
        lockSecret[lockId] = secret;
    }

    function _termsFor(address asset, address beneficiary_, uint256 amount, uint64 window, uint256 secret)
        internal
        returns (LockTerms memory)
    {
        sessionCounter += 1;
        return LockTerms({
            domChainId: keccak256("dom-sim/invariant"),
            // The protocol has exactly two canonical directions.  Keep the
            // conversion out of the counter arithmetic so an unexpectedly
            // large counter cannot silently truncate into a new direction.
            direction: sessionCounter % 2 == 0 ? 0 : 1,
            sessionId: keccak256(abi.encode("session", sessionCounter)),
            termsHash: keccak256(abi.encode("terms", sessionCounter)),
            participantsHash: keccak256("roster"),
            asset: asset,
            amount: amount,
            beneficiary: beneficiary_,
            adaptorAddress: vm.addr(secret),
            deadline: uint64(block.timestamp) + window
        });
    }

    function warp(uint64 delta) external {
        vm.warp(block.timestamp + bound(delta, 1, 3 days));
    }

    /// @dev Sum of the amounts of every lock that has not reached a terminal
    ///      outcome, computed from the ghost state.
    function outstandingLockValue() external view returns (uint256 total) {
        for (uint256 i = 0; i < lockIds.length; i++) {
            bytes32 id = lockIds[i];
            if (!wasClaimed[id] && !wasRefunded[id]) total += lockAmount[id];
        }
    }
}

/// @notice Drives the native-ETH lock with a mix of well-behaved and hostile
///         counterparties.
contract NativeHandler is BaseHandler {
    ConditionLockV2 public immutable lock;
    ReentrantReceiver public immutable attacker;

    constructor(ConditionLockV2 lock_) {
        lock = lock_;
        attacker = new ReentrantReceiver(address(lock_));

        actors.push(makeAddr("alice"));
        actors.push(makeAddr("bob"));
        actors.push(makeAddr("carol"));
        actors.push(address(new GoodReceiver()));
        actors.push(address(new RevertingReceiver()));
        actors.push(address(new GasBurnerReceiver()));
        actors.push(address(attacker));
    }

    /// @dev Re-points the reentrant actor at a different entry point, so the
    ///      campaign keeps trying to reenter from inside live payouts.
    function armAttacker(uint256 lockSeed, uint8 modeSeed, bool abortFrame) external {
        bytes32 lockId = _pickLock(lockSeed);
        attacker.arm(ReentrantReceiver.Mode(uint8(bound(modeSeed, 0, 5))), lockId, lockSecret[lockId]);
        attacker.setRevertAfterAttack(abortFrame);
    }

    function open(uint256 funderSeed, uint256 beneficiarySeed, uint256 amountSeed, uint64 window, uint256 secretSeed)
        external
    {
        callsOpen += 1;
        address funder_ = _actor(funderSeed);
        address beneficiary_ = _actor(beneficiarySeed);
        uint256 amount = bound(amountSeed, 1, 100 ether);
        uint256 secret = bound(secretSeed, 1, SECP256K1_N - 1);
        window = uint64(bound(window, 1, 30 days));

        LockTerms memory t = _termsFor(address(0), beneficiary_, amount, window, secret);

        vm.deal(funder_, funder_.balance + amount);
        vm.prank(funder_);
        try lock.open{value: amount}(t) returns (bytes32 lockId) {
            _recordOpen(lockId, t, funder_, secret);
        } catch {}
    }

    function claim(uint256 lockSeed, uint256 wrongSecretSeed, bool useWrongSecret) external {
        callsClaim += 1;
        bytes32 lockId = _pickLock(lockSeed);
        if (lockId == bytes32(0)) return;

        uint256 secret = useWrongSecret ? bound(wrongSecretSeed, 1, SECP256K1_N - 1) : lockSecret[lockId];
        address caller = lockBeneficiary[lockId];
        uint256 creditsBefore = _totalCredits();
        uint256 payeeBefore = _entitlementHeldBy(caller);

        vm.prank(caller);
        try lock.claim(lockId, secret) {
            _afterSettlement(lockId, true, creditsBefore, caller, payeeBefore);
        } catch {
            _assertNoSilentCreditLoss(creditsBefore);
        }
    }

    function claimAsStranger(uint256 lockSeed, uint256 callerSeed) external {
        callsClaim += 1;
        bytes32 lockId = _pickLock(lockSeed);
        if (lockId == bytes32(0)) return;
        address caller = _actor(callerSeed);
        uint256 creditsBefore = _totalCredits();
        uint256 payeeBefore = _entitlementHeldBy(lockBeneficiary[lockId]);

        vm.prank(caller);
        try lock.claim(lockId, lockSecret[lockId]) {
            // Only legitimate if the caller really is the beneficiary.
            if (caller != lockBeneficiary[lockId]) sawTerminalityRegression = true;
            _afterSettlement(lockId, true, creditsBefore, lockBeneficiary[lockId], payeeBefore);
        } catch {
            _assertNoSilentCreditLoss(creditsBefore);
        }
    }

    function refund(uint256 lockSeed, uint256 callerSeed) external {
        callsRefund += 1;
        bytes32 lockId = _pickLock(lockSeed);
        if (lockId == bytes32(0)) return;
        uint256 creditsBefore = _totalCredits();
        uint256 payeeBefore = _entitlementHeldBy(lockFunder[lockId]);

        vm.prank(_actor(callerSeed));
        try lock.refund(lockId) {
            _afterSettlement(lockId, false, creditsBefore, lockFunder[lockId], payeeBefore);
        } catch {
            _assertNoSilentCreditLoss(creditsBefore);
        }
    }

    function withdraw(uint256 actorSeed) external {
        callsWithdraw += 1;
        address actor = _actor(actorSeed);
        vm.prank(actor);
        try lock.withdraw(address(0)) {} catch {}
    }

    function withdrawTo(uint256 actorSeed, uint256 toSeed) external {
        callsWithdraw += 1;
        address actor = _actor(actorSeed);
        address to = _actor(toSeed);
        vm.prank(actor);
        try lock.withdrawTo(address(0), to) {} catch {}
    }

    /// @dev Everything the payee is entitled to in this asset: what they hold
    ///      plus what they are owed. A settlement moves this by exactly what the
    ///      lock paid out, whichever branch the payout took.
    function _entitlementHeldBy(address who) private view returns (uint256) {
        return who.balance + lock.pendingWithdrawals(who, address(0));
    }

    function _afterSettlement(bytes32 lockId, bool viaClaim, uint256 creditsBefore, address payee, uint256 payeeBefore)
        private
    {
        if (wasClaimed[lockId] || wasRefunded[lockId]) {
            // A second terminal transition on the same lock must be impossible.
            sawTerminalityRegression = true;
        }
        if (viaClaim) {
            wasClaimed[lockId] = true;
        } else {
            wasRefunded[lockId] = true;
        }
        uint256 payeeAfter = _entitlementHeldBy(payee);
        paidOutOfLock[lockId] += payeeAfter > payeeBefore ? payeeAfter - payeeBefore : 0;
        _assertNoSilentCreditLoss(creditsBefore);
    }

    function _assertNoSilentCreditLoss(uint256 creditsBefore) private {
        // Credits may only shrink inside `withdraw`/`withdrawTo`, which are
        // accounted for by their own handler entry points.
        if (_totalCredits() < creditsBefore) sawIllegalCreditDecrease = true;
    }

    function _totalCredits() internal view returns (uint256 total) {
        for (uint256 i = 0; i < actors.length; i++) {
            total += lock.pendingWithdrawals(actors[i], address(0));
        }
    }

    function totalCredits() external view returns (uint256) {
        return _totalCredits();
    }
}

/// @notice Drives the ERC-20 lock over a mix of tokens, including one that
///         cannot be pushed inside the payout stipend and one that reverts.
contract Erc20Handler is BaseHandler {
    ConditionLockERC20V2 public immutable lock;
    MockERC20[] public tokens;
    UnreadableBalanceToken public unmeasurable;
    mapping(bytes32 => address) public lockAsset;

    /// @dev Set once by `seedUnmeasurableDeferral`, which every campaign run
    ///      starts from. Without it `invariant_solvencyForTheUnmeasurableAsset`
    ///      would compare 0 against 0 in any run where the random sequence
    ///      never happened to open, break and settle a lock in that asset -
    ///      passing while proving nothing.
    bool public unmeasurableSeeded;
    /// @dev Count of payouts in the unmeasurable asset that produced a credit.
    uint256 public unmeasurableDeferrals;

    constructor(ConditionLockERC20V2 lock_) {
        lock = lock_;

        actors.push(makeAddr("alice"));
        actors.push(makeAddr("bob"));
        actors.push(makeAddr("carol"));
        actors.push(address(new GoodReceiver()));

        // Pushes cleanly inside the payout stipend.
        tokens.push(new MockERC20());
        // Too heavy for the stipend: always lands in the pull path.
        tokens.push(MockERC20(address(new HeavyToken())));
        // Can be switched hostile mid-campaign.
        tokens.push(MockERC20(address(new RevertingToken())));
        // Moves the funds and then misreports them: the campaign must never
        // mint a credit for value that has already left custody.
        tokens.push(MockERC20(address(new AmbiguousReturnToken())));
        // Per-transfer cap, so payouts under-deliver, credits accumulate past
        // what one transfer can settle, and `withdrawAmount` is the only way to
        // drain them. The cap is set low from the start so the campaign always
        // has a partially-delivering asset in play, not merely the option of
        // one.
        tokens.push(MockERC20(address(new CappedTransferToken())));
        CappedTransferToken(address(tokens[4])).setCap(0.5 ether);

        // Answers probes while locks are opened and can be switched
        // unmeasurable mid-campaign. Held outside `tokens` because it is not a
        // `MockERC20`; `liabilitiesIn` covers it explicitly.
        unmeasurable = new UnreadableBalanceToken();

        for (uint256 i = 0; i < tokens.length; i++) {
            for (uint256 j = 0; j < actors.length; j++) {
                tokens[i].mint(actors[j], 1_000_000 ether);
                vm.prank(actors[j]);
                tokens[i].approve(address(lock_), type(uint256).max);
            }
        }
        for (uint256 j = 0; j < actors.length; j++) {
            unmeasurable.mint(actors[j], 1_000_000 ether);
            vm.prank(actors[j]);
            unmeasurable.approve(address(lock_), type(uint256).max);
        }
    }

    /// @notice Puts a real, settled deferral in the unmeasurable asset so the
    ///         solvency invariant for it has content from the first call of
    ///         every run. Idempotent, so the fuzzer re-calling it is harmless.
    function seedUnmeasurableDeferral() public {
        if (unmeasurableSeeded) return;
        unmeasurableSeeded = true;

        address funder_ = actors[0];
        address payee = actors[1];
        uint256 secret = 4242;

        unmeasurable.setProbes(false, false);
        unmeasurable.setTransfer(true, true, false);
        LockTerms memory t = _termsFor(address(unmeasurable), payee, 5 ether, 30 days, secret);
        vm.prank(funder_);
        bytes32 lockId = lock.open(t);
        _recordOpen(lockId, t, funder_, secret);
        lockAsset[lockId] = address(unmeasurable);

        // Make the transfer revert so the payout provably defers: a reverted
        // frame moved nothing, so the whole amount must be credited.
        unmeasurable.setTransfer(false, false, true);
        uint256 payeeBefore = _entitlementHeldBy(payee, address(unmeasurable));
        vm.prank(payee);
        lock.claim(lockId, secret);
        wasClaimed[lockId] = true;
        _recordObservedPayout(lockId, payee, payeeBefore);
        if (lock.pendingWithdrawals(payee, address(unmeasurable)) != 0) unmeasurableDeferrals += 1;

        unmeasurable.setTransfer(true, true, false);
    }

    /// @dev Opens a lock in the asset that can stop answering probes, then lets
    ///      the campaign flip its measurability and its transfer behaviour
    ///      independently. Without this the solvency invariant would only ever
    ///      see assets that consent to being measured.
    function openUnmeasurable(uint256 funderSeed, uint256 beneficiarySeed, uint256 amountSeed, uint64 window) external {
        callsOpen += 1;
        address funder_ = _actor(funderSeed);
        uint256 secret = bound(amountSeed, 1, SECP256K1_N - 1);
        LockTerms memory t = _termsFor(
            address(unmeasurable),
            _actor(beneficiarySeed),
            bound(amountSeed, 1, 100 ether),
            uint64(bound(window, 1, 30 days)),
            secret
        );
        // `open` refuses an asset that will not answer, so it must be readable
        // here; the campaign can break it again immediately afterwards.
        unmeasurable.setProbes(false, false);
        vm.prank(funder_);
        try lock.open(t) returns (bytes32 lockId) {
            _recordOpen(lockId, t, funder_, secret);
            lockAsset[lockId] = address(unmeasurable);
        } catch {}
    }

    /// @dev Lets the campaign move the capped asset's per-transfer limit, so
    ///      shortfalls of every size - including zero and the full amount - are
    ///      reachable.
    function setCappedAssetLimit(uint256 capSeed) external {
        CappedTransferToken(address(tokens[4])).setCap(bound(capSeed, 0, 2 ether));
    }

    function breakUnmeasurable(uint8 modeSeed, bool refusing, bool flip, bool moves, bool reportsOk, bool reverts_)
        external
    {
        unmeasurable.setMode(UnreadableBalanceToken.Mode(uint8(bound(modeSeed, 0, 2))));
        unmeasurable.setProbes(refusing, flip);
        unmeasurable.setTransfer(moves, reportsOk, reverts_);
    }

    function withdrawUnmeasurable(uint256 actorSeed, uint256 toSeed, uint256 amountSeed, bool takePart) external {
        callsWithdraw += 1;
        address actor = _actor(actorSeed);
        vm.startPrank(actor);
        if (takePart) {
            uint256 credit = lock.pendingWithdrawals(actor, address(unmeasurable));
            if (credit != 0) {
                try lock.withdrawAmount(address(unmeasurable), _actor(toSeed), bound(amountSeed, 1, credit)) {} catch {}
            }
        } else {
            try lock.withdraw(address(unmeasurable)) {} catch {}
        }
        vm.stopPrank();
    }

    function tokenCount() external view returns (uint256) {
        return tokens.length;
    }

    function _token(uint256 seed) internal view returns (MockERC20) {
        return tokens[seed % tokens.length];
    }

    function open(
        uint256 funderSeed,
        uint256 beneficiarySeed,
        uint256 tokenSeed,
        uint256 amountSeed,
        uint64 window,
        uint256 secretSeed
    ) external {
        callsOpen += 1;
        address funder_ = _actor(funderSeed);
        address beneficiary_ = _actor(beneficiarySeed);
        MockERC20 tkn = _token(tokenSeed);
        uint256 amount = bound(amountSeed, 1, 100 ether);
        uint256 secret = bound(secretSeed, 1, SECP256K1_N - 1);
        window = uint64(bound(window, 1, 30 days));

        LockTerms memory t = _termsFor(address(tkn), beneficiary_, amount, window, secret);

        vm.prank(funder_);
        try lock.open(t) returns (bytes32 lockId) {
            _recordOpen(lockId, t, funder_, secret);
            lockAsset[lockId] = address(tkn);
        } catch {}
    }

    function claim(uint256 lockSeed) external {
        callsClaim += 1;
        bytes32 lockId = _pickLock(lockSeed);
        if (lockId == bytes32(0)) return;

        address payee = lockBeneficiary[lockId];
        uint256 payeeBefore = _entitlementHeldBy(payee, lockAsset[lockId]);

        vm.prank(payee);
        try lock.claim(lockId, lockSecret[lockId]) {
            if (wasClaimed[lockId] || wasRefunded[lockId]) sawTerminalityRegression = true;
            wasClaimed[lockId] = true;
            _recordObservedPayout(lockId, payee, payeeBefore);
        } catch {}
    }

    function refund(uint256 lockSeed, uint256 callerSeed) external {
        callsRefund += 1;
        bytes32 lockId = _pickLock(lockSeed);
        if (lockId == bytes32(0)) return;

        address payee = lockFunder[lockId];
        uint256 payeeBefore = _entitlementHeldBy(payee, lockAsset[lockId]);

        vm.prank(_actor(callerSeed));
        try lock.refund(lockId) {
            if (wasClaimed[lockId] || wasRefunded[lockId]) sawTerminalityRegression = true;
            wasRefunded[lockId] = true;
            _recordObservedPayout(lockId, payee, payeeBefore);
        } catch {}
    }

    function withdraw(uint256 actorSeed, uint256 tokenSeed) external {
        callsWithdraw += 1;
        vm.prank(_actor(actorSeed));
        try lock.withdraw(address(_token(tokenSeed))) {} catch {}
    }

    function withdrawTo(uint256 actorSeed, uint256 tokenSeed, uint256 toSeed) external {
        callsWithdraw += 1;
        vm.prank(_actor(actorSeed));
        try lock.withdrawTo(address(_token(tokenSeed)), _actor(toSeed)) {} catch {}
    }

    function withdrawPartial(uint256 actorSeed, uint256 tokenSeed, uint256 toSeed, uint256 amountSeed) external {
        callsWithdraw += 1;
        address actor = _actor(actorSeed);
        MockERC20 tkn = _token(tokenSeed);
        uint256 credit = lock.pendingWithdrawals(actor, address(tkn));
        if (credit == 0) return;
        vm.prank(actor);
        try lock.withdrawAmount(address(tkn), _actor(toSeed), bound(amountSeed, 1, credit)) {} catch {}
    }

    /// @dev Observed entitlement of `who` in `asset`: held plus owed.
    ///
    ///      Reads GROUND TRUTH, never the asset's public `balanceOf`. The
    ///      unmeasurable asset exists precisely to lie to that function, and a
    ///      ghost built on it inherits the lie - measuring "before" while the
    ///      asset refuses and "after" once it has flipped produces a delta of
    ///      the payee's entire holdings out of nothing. The mocks expose an
    ///      honest ledger for exactly this reason, and a test oracle is allowed
    ///      to use it where the contract under test is not.
    function _entitlementHeldBy(address who, address asset) private view returns (uint256 held) {
        if (asset == address(unmeasurable)) {
            held = unmeasurable.ledger(who);
        } else if (asset != address(0)) {
            held = MockERC20(asset).balanceOf(who);
        }
        held += lock.pendingWithdrawals(who, asset);
    }

    function _recordObservedPayout(bytes32 lockId, address payee, uint256 payeeBefore) private {
        address asset = lockAsset[lockId];
        uint256 payeeAfter = _entitlementHeldBy(payee, asset);
        paidOutOfLock[lockId] += payeeAfter > payeeBefore ? payeeAfter - payeeBefore : 0;
        if (asset == address(unmeasurable) && lock.pendingWithdrawals(payee, asset) != 0) {
            unmeasurableDeferrals += 1;
        }
    }

    function toggleTokenHostility(uint256 tokenSeed, bool hostile, uint256 returnSizeSeed) external {
        MockERC20 tkn = _token(tokenSeed);
        if (address(tkn) == address(tokens[2])) {
            RevertingToken(address(tkn)).setReverts(hostile, false);
        } else if (address(tkn) == address(tokens[3])) {
            // 32 is the well-formed answer; anything else is a payload the
            // lock cannot interpret and must therefore not trust.
            uint256[4] memory sizes = [uint256(0), 32, 64, 96];
            AmbiguousReturnToken(address(tkn)).setReturnSize(sizes[returnSizeSeed % 4]);
        }
    }

    function unmeasurableAsset() external view returns (address) {
        return address(unmeasurable);
    }

    /// @dev Outstanding liabilities in one token: unsettled locks denominated
    ///      in it, plus every credit held in it.
    function liabilitiesIn(address asset) external view returns (uint256 total) {
        for (uint256 i = 0; i < lockIds.length; i++) {
            bytes32 id = lockIds[i];
            if (lockAsset[id] != asset) continue;
            if (!wasClaimed[id] && !wasRefunded[id]) total += lockAmount[id];
        }
        for (uint256 j = 0; j < actors.length; j++) {
            total += lock.pendingWithdrawals(actors[j], asset);
        }
    }
}
