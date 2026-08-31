// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Accepts every payment and counts what it received.
contract GoodReceiver {
    uint256 public received;

    receive() external payable {
        received += msg.value;
    }
}

/// @notice Rejects every incoming payment.
/// @dev The archetype behind D-002: before the fix, a funder like this could
///      never be refunded and the funds were locked forever.
contract RevertingReceiver {
    error Rejected();

    receive() external payable {
        revert Rejected();
    }
}

/// @notice Consumes every unit of gas it is handed, then fails.
/// @dev `invalid()` burns all remaining gas of the frame. With the payout
///      stipend in place, the settlement only loses the stipend.
contract GasBurnerReceiver {
    receive() external payable {
        assembly {
            invalid()
        }
    }
}

/// @notice Succeeds, but returns a large buffer to punish a caller that copies
///         returndata into memory.
/// @dev `returnSize` is expressed in bytes and must stay affordable inside the
///      payout stipend when the bomb is aimed at the push path.
contract ReturnBombReceiver {
    uint256 public immutable returnSize;

    constructor(uint256 returnSize_) {
        returnSize = returnSize_;
    }

    fallback() external payable {
        uint256 size = returnSize;
        assembly {
            return(0, size)
        }
    }

    receive() external payable {
        uint256 size = returnSize;
        assembly {
            return(0, size)
        }
    }
}

/// @notice Reenters the lock contract from inside the payout.
/// @dev `mode` selects which entry point is attacked. Every attempt must fail:
///      on the push path because the stipend is too small and because the lock
///      is already terminal, and on the pull path because of the reentrancy
///      guard.
///
///      Every storage slot this contract touches while running inside a payout
///      is pre-warmed to a non-zero value in `arm`, so that the whole attack
///      fits inside the 30k stipend. Otherwise a single cold zero-to-non-zero
///      SSTORE (22.1k) would exhaust the budget and the test would prove
///      nothing beyond "the stipend is small".
contract ReentrantReceiver {
    enum Mode {
        Passive,
        Claim,
        Refund,
        Withdraw,
        WithdrawTo,
        Open
    }

    /// @dev 1 = never ran, 2 = ran and the nested call failed, 3 = ran and the
    ///      nested call succeeded. Never zero, so writes stay cheap.
    uint256 public constant LOG_IDLE = 1;
    uint256 public constant LOG_BLOCKED = 2;
    uint256 public constant LOG_SUCCEEDED = 3;

    address public immutable lock;
    Mode public mode;
    bytes32 public lockId;
    uint256 public secret;
    uint256 public attackLog = LOG_IDLE;
    bool public revertAfterAttack;

    constructor(address lock_) {
        lock = lock_;
    }

    function arm(Mode mode_, bytes32 lockId_, uint256 secret_) external {
        mode = mode_;
        lockId = lockId_;
        secret = secret_;
        attackLog = LOG_IDLE;
    }

    function setRevertAfterAttack(bool value) external {
        revertAfterAttack = value;
    }

    function callClaim(bytes32 lockId_, uint256 t) external {
        (bool ok, bytes memory err) = lock.call(abi.encodeWithSignature("claim(bytes32,uint256)", lockId_, t));
        if (!ok) _bubble(err);
    }

    function callWithdraw(address asset) external {
        (bool ok, bytes memory err) = lock.call(abi.encodeWithSignature("withdraw(address)", asset));
        if (!ok) _bubble(err);
    }

    function callWithdrawTo(address asset, address to) external {
        (bool ok, bytes memory err) = lock.call(abi.encodeWithSignature("withdrawTo(address,address)", asset, to));
        if (!ok) _bubble(err);
    }

    receive() external payable {
        _attack();
    }

    function _attack() private {
        Mode m = mode;
        if (m == Mode.Passive) return;

        bytes memory payload;
        if (m == Mode.Claim) {
            payload = abi.encodeWithSignature("claim(bytes32,uint256)", lockId, secret);
        } else if (m == Mode.Refund) {
            payload = abi.encodeWithSignature("refund(bytes32)", lockId);
        } else if (m == Mode.Withdraw) {
            payload = abi.encodeWithSignature("withdraw(address)", address(0));
        } else if (m == Mode.WithdrawTo) {
            payload = abi.encodeWithSignature("withdrawTo(address,address)", address(0), address(this));
        } else {
            // `open` with empty terms; it must not be reachable from inside a payout.
            payload = abi.encodeWithSignature(
                "open((bytes32,uint8,bytes32,bytes32,bytes32,address,uint256,address,address,uint64))",
                bytes32(0),
                uint8(0),
                bytes32(0),
                bytes32(0),
                bytes32(0),
                address(0),
                uint256(0),
                address(0),
                address(0),
                uint64(0)
            );
        }

        (bool ok,) = lock.call(payload);
        attackLog = ok ? LOG_SUCCEEDED : LOG_BLOCKED;
        if (revertAfterAttack) revert("attack frame aborted");
    }

    function _bubble(bytes memory err) private pure {
        assembly {
            revert(add(err, 0x20), mload(err))
        }
    }
}

/// @notice Reenters `claim` from inside the payout and KEEPS THE REVERT REASON.
/// @dev `ReentrantReceiver` only records that the nested call failed, which
///      cannot distinguish a reentrancy rejection from a plain out-of-gas
///      inside the 30k stipend. This one preserves the first four bytes, so a
///      test can assert that `ReentrancyGuardReentrantCall` is what fired.
///      Every slot it writes during the payout is pre-warmed in the
///      constructor, otherwise a cold SSTORE alone would exhaust the stipend.
contract ReasonCapturingReceiver {
    address public immutable lock;
    bytes4 public nestedSelector;
    uint256 public nestedReturnSize;
    bool public ran;
    bytes32 public target;
    uint256 public secret;

    constructor(address lock_) {
        lock = lock_;
        nestedSelector = bytes4(uint32(1));
        nestedReturnSize = 1;
        ran = true;
    }

    function arm(bytes32 target_, uint256 secret_) external {
        target = target_;
        secret = secret_;
        ran = false;
    }

    function callClaim(bytes32 id, uint256 t) external {
        (bool ok, bytes memory err) = lock.call(abi.encodeWithSignature("claim(bytes32,uint256)", id, t));
        if (!ok) {
            assembly {
                revert(add(err, 0x20), mload(err))
            }
        }
    }

    receive() external payable {
        (bool ok, bytes memory err) = lock.call(abi.encodeWithSignature("claim(bytes32,uint256)", target, secret));
        ran = true;
        nestedReturnSize = err.length;
        if (!ok && err.length >= 4) {
            nestedSelector = bytes4(err[0]) | (bytes4(err[1]) >> 8) | (bytes4(err[2]) >> 16) | (bytes4(err[3]) >> 24);
        } else {
            nestedSelector = 0;
        }
    }
}

/// @notice Funder that is a contract and simply accepts ETH; used to show the
///         happy path is unaffected by the pull fallback machinery.
contract ContractFunder {
    address public immutable lock;

    constructor(address lock_) {
        lock = lock_;
    }

    receive() external payable {}

    function forward(bytes calldata data, uint256 value) external payable returns (bytes memory) {
        (bool ok, bytes memory ret) = lock.call{value: value}(data);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        return ret;
    }
}
