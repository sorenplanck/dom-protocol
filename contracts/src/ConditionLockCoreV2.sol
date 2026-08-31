// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {LockBinding, LockTerms} from "./LockBinding.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title ConditionLockCoreV2
/// @notice Asset-agnostic core of the EVM leg of a DOM<->EVM settlement.
/// @dev Funds are locked against the secret `t` whose point `T = t*G` was fixed
///      during setup. A successful `claim` REVEALS `t` on chain; that event is
///      what the DOM leg consumes through `AdaptorPreSignatureV1::extract`.
///      Normative source: DOM-Interop Foundation Document v0.2.1 section 2.3
///      plus decision D-002, and the F3 interface spec sections 1 and 2.
///
///      Deliberate absences (invariant I2, "antipoder"): there is no privileged
///      path of any kind. No stored operator, no privileged constructor
///      argument, no global halt switch, no proxy or code replacement, no
///      rescue or sweep entry point. Every state transition is decided purely
///      by the terms committed at `open`, by `block.timestamp`, and by
///      knowledge of `t`.
///
///      Concrete asset handling (native ETH vs. ERC-20) is supplied by the two
///      subclasses through `_takeCustody`, `_tryPushPayout` and `_pullTransfer`.
///      The settlement logic itself lives here exactly once, so the two
///      variants cannot drift apart.
abstract contract ConditionLockCoreV2 is ReentrancyGuard {
    /// @notice Stored state of one lock.
    /// @dev `amount` is `uint256`, matching `LockTerms.amount` exactly: the
    ///      binding commits to a `uint256`, so narrowing the stored copy would
    ///      let two different committed amounts share one stored amount.
    struct Lock {
        address funder;
        address beneficiary;
        address adaptorAddress;
        address asset;
        uint256 amount;
        uint64 deadline;
        bytes32 binding;
        /// @dev The single terminal flag. `claim` and `refund` are mutually
        ///      exclusive outcomes (invariant I4) precisely because both read
        ///      and write this one bit.
        bool settled;
    }

    /// @dev Gas forwarded to a payout target on the optimistic push attempt.
    ///      Enough for a plain EOA transfer and for a small `receive()`, far
    ///      too little to run a reentrancy attack or a storage-heavy hook.
    uint256 internal constant PAYOUT_GAS_STIPEND = 30_000;

    /// @dev Minimum `gasleft()` required before a push is even attempted, for a
    ///      payout that is a single value-bearing CALL. Derived, not guessed:
    ///        * EIP-150 keeps 1/64 of the available gas, so forwarding
    ///          `PAYOUT_GAS_STIPEND` needs `STIPEND * 64 / 63` = 30_476 available
    ///          AFTER the call's own cost is charged;
    ///        * a value-bearing CALL costs 9_000, plus 25_000 more when the
    ///          target account does not yet exist, plus up to 2_600 for a cold
    ///          account access: 36_600;
    ///        * the pull fallback that runs when the push fails needs a cold
    ///          SSTORE from zero (22_100) plus the `PayoutDeferred` log (~1_500).
    ///      96_000 covers all of it with headroom. Below this threshold the
    ///      push is skipped entirely and the payout is credited for pull, so a
    ///      caller cannot use a tight gas limit to make the push silently
    ///      receive less than the promised stipend.
    ///
    ///      Subclasses whose push costs more than one CALL raise this through
    ///      `_payoutGasFloor`.
    uint256 internal constant PAYOUT_GAS_FLOOR = 96_000;

    /// @notice Locks by canonical lock id.
    mapping(bytes32 => Lock) private _locks;

    /// @notice Payouts whose push attempt failed, held for pull.
    /// @dev D-002: settlement is never blocked by the payout target. See
    ///      `_payout`. Indexed by account and then by asset so the two
    ///      contract variants share one accounting shape.
    mapping(address => mapping(address => uint256)) public pendingWithdrawals;

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
    /// @notice Part of a payout could not be delivered by the optimistic push
    ///         and is now held as a pull credit for `to`.
    /// @param amount The SHORTFALL, i.e. the part of the payout that provably
    ///        did not leave custody - not necessarily the whole lock amount. A
    ///        push that delivered everything emits nothing; a push that
    ///        delivered part of it emits only the remainder.
    event PayoutDeferred(address indexed to, address indexed asset, uint256 amount);
    event Withdrawal(address indexed account, address indexed asset, address indexed to, uint256 amount);

    /// @notice A lock with this id already exists (or already existed and settled).
    error LockExists();
    /// @notice No lock with this id was ever opened here.
    error LockUnknown();
    /// @notice The lock already reached a terminal outcome.
    error AlreadySettled();
    /// @notice `terms.amount` is zero.
    error BadAmount();
    /// @notice `terms.deadline` is not strictly in the future.
    error BadDeadline();
    /// @notice A required address argument was the zero address.
    error ZeroAddress();
    /// @notice `msg.sender` is not the committed beneficiary.
    error NotBeneficiary();
    /// @notice The deadline has been reached; claim is no longer possible.
    error Expired();
    /// @notice The deadline has not been reached yet; refund is not possible.
    error NotExpired();
    /// @notice `address(t*G)` does not match the committed adaptor address.
    error WrongSecret();
    /// @notice Nothing is credited for this account and asset.
    error NothingToWithdraw();
    /// @notice The pull transfer itself failed; the credit is left untouched.
    error PayoutFailed();
    /// @notice `terms.asset` does not match this contract's asset kind.
    error AssetMismatch();
    /// @notice `msg.value` does not match what this call is allowed to carry.
    error ValueMismatch();
    /// @notice A partial withdrawal asked for more than the standing credit.
    error AmountExceedsCredit(uint256 credit, uint256 requested);

    // ------------------------------------------------------------------
    // Derivation (identical in both variants, byte-identical in Rust)
    // ------------------------------------------------------------------

    /// @notice Canonical binding hash of `terms` for this chain and this contract.
    function deriveBinding(LockTerms calldata terms) public view returns (bytes32) {
        return LockBinding.deriveBinding(terms, block.chainid, address(this));
    }

    /// @notice Canonical lock id of `terms` when funded by `funder`.
    function deriveLockId(LockTerms calldata terms, address funder) public view returns (bytes32) {
        return LockBinding.deriveLockId(LockBinding.deriveBinding(terms, block.chainid, address(this)), funder);
    }

    /// @notice Returns `address(t*G)`; reverts for non-canonical `t`.
    function addressOfScalarTimesG(uint256 t) public pure returns (address) {
        return LockBinding.addressOfScalarTimesG(t);
    }

    /// @notice Reads a lock. An unknown lock reads back as an all-zero struct.
    function lockOf(bytes32 lockId) external view returns (Lock memory) {
        return _locks[lockId];
    }

    // ------------------------------------------------------------------
    // Settlement
    // ------------------------------------------------------------------

    /// @notice Opens a lock for `terms`, funded by `msg.sender`.
    /// @dev The lock id is derived, never supplied: a third party cannot
    ///      pre-empt someone else's lock id because `funder` is bound into it.
    ///      A settled lock keeps its `funder` set forever, so the same terms
    ///      funded by the same account can never be opened twice - that is the
    ///      on-chain replay guard for a given DOM session.
    function open(LockTerms calldata terms) external payable nonReentrant returns (bytes32 lockId) {
        LockBinding.requireCanonicalDirection(terms.direction);
        if (terms.beneficiary == address(0) || terms.adaptorAddress == address(0)) revert ZeroAddress();
        if (terms.amount == 0) revert BadAmount();
        if (terms.deadline <= block.timestamp) revert BadDeadline();

        bytes32 binding = LockBinding.deriveBinding(terms, block.chainid, address(this));
        lockId = LockBinding.deriveLockId(binding, msg.sender);
        if (_locks[lockId].funder != address(0)) revert LockExists();

        _locks[lockId] = Lock({
            funder: msg.sender,
            beneficiary: terms.beneficiary,
            adaptorAddress: terms.adaptorAddress,
            asset: terms.asset,
            amount: terms.amount,
            deadline: terms.deadline,
            binding: binding,
            settled: false
        });

        emit LockOpened(
            lockId,
            binding,
            msg.sender,
            terms.beneficiary,
            terms.asset,
            terms.amount,
            terms.adaptorAddress,
            terms.deadline
        );

        // Interaction last: the subclass validates the asset kind and pulls the
        // funds. State is already final, and `nonReentrant` covers the ERC-20
        // variant where `_takeCustody` calls out to the token.
        _takeCustody(terms.asset, terms.amount);
    }

    /// @notice Claims the lock by revealing the secret `t`.
    /// @dev `Claimed(t)` is emitted before any value moves and the payout that
    ///      follows can never revert (D-002). The DOM leg therefore always gets
    ///      its secret, whatever the beneficiary's contract code does.
    function claim(bytes32 lockId, uint256 t) external nonReentrant {
        Lock storage l = _locks[lockId];
        address beneficiary = l.beneficiary;
        if (l.funder == address(0)) revert LockUnknown();
        if (l.settled) revert AlreadySettled();
        if (msg.sender != beneficiary) revert NotBeneficiary();
        if (block.timestamp >= l.deadline) revert Expired();

        // Reverts on non-canonical `t`. For every canonical `t` the precompile
        // succeeds, so the zero check below is defence in depth only; a lock
        // whose adaptor address is zero cannot exist (rejected at `open`).
        address recovered = LockBinding.addressOfScalarTimesG(t);
        if (recovered == address(0) || recovered != l.adaptorAddress) revert WrongSecret();

        l.settled = true;

        uint256 amount = l.amount;
        address asset = l.asset;
        emit Claimed(lockId, l.binding, beneficiary, t);
        _payout(beneficiary, asset, amount);
    }

    /// @notice Refunds the funder once the deadline has passed.
    /// @dev Callable by anyone - there is no privileged path - but the
    ///      destination is always the original funder and is never derived from
    ///      `msg.sender`, so a third party can only pay gas on the funder's
    ///      behalf.
    ///
    ///      Accepted trade-off: because the caller chooses the gas limit and the
    ///      push is only attempted above `_payoutGasFloor`, a third party can
    ///      deliberately supply just enough gas to settle the refund into a pull
    ///      credit instead of a direct transfer. With a well-behaved asset that
    ///      costs the funder a second transaction and nothing else, and the
    ///      credit is only ever theirs.
    ///
    ///      With an asset that has gone unmeasurable, the same lever chooses
    ///      between two DIFFERENT outcomes for the funder, and this is worth
    ///      stating plainly because it is not obvious from either piece alone:
    ///        * refunded below the floor, the push is skipped and the whole
    ///          amount becomes a credit - a standing claim on custody that is
    ///          still sitting here, collectable once the asset behaves;
    ///        * refunded at or above the floor, the unmeasured push assumes
    ///          delivery (see `_tryPushPayout`) and books nothing, so the funder
    ///          ends with no credit at all.
    ///      A griefer can force the second for free; the funder cannot force the
    ///      first, because anyone may call `refund` at any time after the
    ///      deadline. The reachable damage is bounded by the asset the funder
    ///      chose - no other lock's custody is touched either way - but the
    ///      CHOICE belongs to an arbitrary third party.
    ///
    ///      The alternative - restricting who may call `refund` - would be a
    ///      privileged path, which invariant I2 forbids, and would make refunds
    ///      depend on a liveness assumption. Griefing the gas limit is the
    ///      cheaper of the two failures, so it stays.
    function refund(bytes32 lockId) external nonReentrant {
        Lock storage l = _locks[lockId];
        address funder = l.funder;
        if (funder == address(0)) revert LockUnknown();
        if (l.settled) revert AlreadySettled();
        if (block.timestamp < l.deadline) revert NotExpired();

        l.settled = true;

        uint256 amount = l.amount;
        address asset = l.asset;
        emit Refunded(lockId, l.binding, funder, amount);
        _payout(funder, asset, amount);
    }

    // ------------------------------------------------------------------
    // D-002 payout: bounded push, guaranteed pull fallback
    // ------------------------------------------------------------------

    /// @notice Withdraws the whole deferred credit to `msg.sender`.
    /// @dev On the native contract `asset` must be `address(0)`; on the ERC-20
    ///      contract it must be the token. A mismatched asset reverts
    ///      `AssetMismatch` rather than `NothingToWithdraw`, so an off-chain
    ///      consumer matching on the selector should treat both as "no value
    ///      moved" - `AssetMismatch` means the request named an asset this
    ///      deployment cannot move at all.
    function withdraw(address asset) external nonReentrant {
        _withdraw(asset, msg.sender, 0, true);
    }

    /// @notice Withdraws the whole deferred credit to an address chosen by the creditor.
    /// @dev Only the creditor can move their own credit; `to` is not privileged
    ///      and does not need to cooperate beyond accepting the asset.
    function withdrawTo(address asset, address to) external nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        _withdraw(asset, to, 0, true);
    }

    /// @notice Withdraws part of a deferred credit.
    /// @dev Escape hatch for a credit that can never move in one transfer:
    ///      credits accumulate across locks, so an entirely honest asset with a
    ///      per-transfer cap can respect that cap at every `open` and still be
    ///      unable to deliver the accumulated total, leaving `withdraw` to
    ///      revert forever. Draining it in instalments is the only way out that
    ///      does not require a privileged path.
    ///
    ///      A credit that reached `type(uint256).max` through the saturating
    ///      add in `_payout` is not fully withdrawable, and cannot be: the
    ///      excess was never backed by custody. What this entry point does
    ///      guarantee is that the BACKED part is always reachable, in whatever
    ///      instalments the asset can actually deliver. That residue is the
    ///      accepted price of never reverting after `Claimed(t)`.
    ///
    ///      "In whatever instalments the asset can deliver" is the precise
    ///      claim, and the qualifier is load-bearing: an instalment LARGER than
    ///      the asset's own per-transfer limit under-delivers and reverts
    ///      `PayoutFailed`, exactly as `withdraw` would. A creditor facing a
    ///      capped asset has to pick instalments the asset will honour, which
    ///      may mean discovering that cap by bisection. The credit is never
    ///      lost while they do - a failed instalment rolls back completely.
    ///
    ///      No privileged path: only the creditor can move their own credit,
    ///      and `to` gains nothing it was not sent.
    function withdrawAmount(address asset, address to, uint256 amount) external nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert BadAmount();
        _withdraw(asset, to, amount, false);
    }

    function _withdraw(address asset, address to, uint256 requested, bool wholeCredit) private {
        // A credit under an asset this contract cannot actually move is not
        // withdrawable, it is a hazard: without this check a "payout" could be
        // a call to an address that accepts anything and moves nothing, and the
        // credit would be destroyed in exchange for nothing.
        _requireSupportedAsset(asset);

        uint256 credit = pendingWithdrawals[msg.sender][asset];
        if (credit == 0) revert NothingToWithdraw();

        uint256 amount = wholeCredit ? credit : requested;
        if (amount > credit) revert AmountExceedsCredit(credit, amount);

        // Effect before interaction: the credit is reduced before anything is
        // called, so a second withdrawal of the same value is impossible even
        // if `to` reenters - and the reentrancy guard makes the attempt revert
        // outright anyway.
        pendingWithdrawals[msg.sender][asset] = credit - amount;

        // Unlike the push in `_payout`, this transfer is allowed to revert: the
        // creditor asked for it, and reverting restores the credit untouched.
        // Under-delivery is a failure too - rolling back also undoes whatever
        // the asset did move, so nothing is lost by refusing it.
        if (_pullTransfer(to, asset, amount) != amount) revert PayoutFailed();

        emit Withdrawal(msg.sender, asset, to, amount);
    }

    /// @dev Optimistic push with a hard gas cap and a pull fallback. This
    ///      function MUST NOT revert: the settlement outcome and, above all,
    ///      the publication of `t` must not depend on the payout target.
    ///
    ///      Only the SHORTFALL is credited. The hooks report how much value
    ///      provably left custody, so this can never book a liability for value
    ///      that already reached `to`. Booking the full amount whenever the
    ///      push "looked" unsuccessful was a real solvency hole: custody is
    ///      pooled per asset, so a phantom credit is later honoured out of an
    ///      unrelated lock's funds.
    function _payout(address to, address asset, uint256 amount) private {
        uint256 delivered;
        // Only attempt the push when the full stipend is genuinely forwardable
        // after the EIP-150 63/64 deduction; otherwise go straight to pull.
        if (gasleft() >= _payoutGasFloor()) {
            delivered = _tryPushPayout(to, asset, amount);
        }

        // The hooks guarantee `delivered <= amount`, so this cannot underflow.
        uint256 shortfall = amount - delivered;
        if (shortfall != 0) {
            // Saturating on purpose. Checked arithmetic here would be a revert
            // on the one path D-002 says must never revert, and the overflow it
            // would be protecting against is only reachable through an asset
            // that misreports its own balances by around 2**256 units. When
            // those two collide, keeping `Claimed(t)` published outranks the
            // last wei owed by an asset that is already lying.
            pendingWithdrawals[to][asset] = _addSaturating(pendingWithdrawals[to][asset], shortfall);
            emit PayoutDeferred(to, asset, shortfall);
        }
    }

    function _addSaturating(uint256 a, uint256 b) private pure returns (uint256) {
        unchecked {
            uint256 c = a + b;
            return c < a ? type(uint256).max : c;
        }
    }

    // ------------------------------------------------------------------
    // Asset hooks
    // ------------------------------------------------------------------

    /// @dev Reverts unless `asset` is the one asset kind this contract can move.
    function _requireSupportedAsset(address asset) internal view virtual;

    /// @dev Validates the asset kind and `msg.value`, then takes custody of
    ///      exactly `amount`. Reverts if it cannot do so exactly.
    function _takeCustody(address asset, uint256 amount) internal virtual;

    /// @dev Minimum `gasleft()` at which a push is worth attempting.
    function _payoutGasFloor() internal pure virtual returns (uint256) {
        return PAYOUT_GAS_FLOOR;
    }

    /// @dev Best-effort payout capped at `PAYOUT_GAS_STIPEND`.
    ///      MUST NOT bubble a revert, MUST NOT copy unbounded returndata, and
    ///      MUST return the amount that provably left this contract's custody,
    ///      never more than `amount`. Reporting more than actually moved
    ///      strands the recipient; reporting less mints a phantom liability
    ///      against pooled custody. Implementations therefore measure rather
    ///      than trust what the asset says about itself.
    function _tryPushPayout(address to, address asset, uint256 amount) internal virtual returns (uint256 delivered);

    /// @dev Full-gas payout used by the pull path. Same reporting contract as
    ///      `_tryPushPayout`: returns the amount that provably left custody.
    function _pullTransfer(address to, address asset, uint256 amount) internal virtual returns (uint256 delivered);
}
