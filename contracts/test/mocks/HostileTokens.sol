// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Minimal, well-behaved ERC-20 used as the baseline in the ERC-20 suite.
/// @dev Deliberately hand-written rather than inherited from OpenZeppelin so
///      that the hostile variants below can subclass it and break exactly one
///      rule each.
contract MockERC20 {
    string public name = "Mock";
    string public symbol = "MCK";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external virtual {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external virtual returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external virtual returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external virtual returns (bool) {
        _spendAllowance(from, amount);
        _move(from, to, amount);
        return true;
    }

    function _spendAllowance(address from, uint256 amount) internal {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "allowance");
            allowance[from][msg.sender] = allowed - amount;
        }
    }

    function _move(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "balance");
        unchecked {
            balanceOf[from] -= amount;
        }
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}

/// @notice Takes a cut on every transfer, so the recipient never gets `amount`.
/// @dev Must be rejected outright by `open`'s exact-accounting check.
contract FeeOnTransferToken is MockERC20 {
    uint256 public immutable feeBps;

    constructor(uint256 feeBps_) {
        feeBps = feeBps_;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        _moveWithFee(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        _spendAllowance(from, amount);
        _moveWithFee(from, to, amount);
        return true;
    }

    function _moveWithFee(address from, address to, uint256 amount) private {
        uint256 fee = (amount * feeBps) / 10_000;
        _move(from, to, amount - fee);
        if (fee != 0) _move(from, address(0xFEE), fee);
    }
}

/// @notice Silently reports failure instead of reverting.
contract FalseReturnToken is MockERC20 {
    bool public failTransfer = true;
    bool public failTransferFrom;

    function setFailures(bool transfer_, bool transferFrom_) external {
        failTransfer = transfer_;
        failTransferFrom = transferFrom_;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        if (failTransfer) return false;
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        if (failTransferFrom) return false;
        _spendAllowance(from, amount);
        _move(from, to, amount);
        return true;
    }
}

/// @notice USDT-style token: moves the balance but returns no data at all.
/// @dev Must be fully supported, on both the push and the pull path.
contract NoReturnToken is MockERC20 {
    function transfer(address to, uint256 amount) external override returns (bool) {
        _move(msg.sender, to, amount);
        assembly {
            return(0, 0)
        }
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        _spendAllowance(from, amount);
        _move(from, to, amount);
        assembly {
            return(0, 0)
        }
    }
}

/// @notice Reverts on the operations selected by the test.
contract RevertingToken is MockERC20 {
    bool public revertOnTransfer;
    bool public revertOnTransferFrom;
    address public blocked;

    error TokenRefused();

    function setReverts(bool onTransfer, bool onTransferFrom) external {
        revertOnTransfer = onTransfer;
        revertOnTransferFrom = onTransferFrom;
    }

    /// @dev Blacklist behaviour: only transfers to `who` revert.
    function block_(address who) external {
        blocked = who;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        if (revertOnTransfer || (blocked != address(0) && to == blocked)) revert TokenRefused();
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        if (revertOnTransferFrom) revert TokenRefused();
        _spendAllowance(from, amount);
        _move(from, to, amount);
        return true;
    }
}

/// @notice A perfectly honest token that simply does more work per transfer.
/// @dev A minimal ERC-20 `transfer` to a cold destination costs roughly 29k
///      gas, which only just fits inside the 30k payout stipend. Real tokens
///      with transfer hooks, snapshots, reflection accounting or per-transfer
///      bookkeeping cost more and land in the pull path instead. This mock
///      pins that behaviour so the fallback is exercised by a token that is
///      not hostile at all.
contract HeavyToken is MockERC20 {
    mapping(uint256 => uint256) public transferJournal;
    uint256 public transferCount;

    function transfer(address to, uint256 amount) external override returns (bool) {
        _move(msg.sender, to, amount);
        uint256 n = transferCount + 1;
        transferCount = n;
        transferJournal[n] = amount;
        return true;
    }
}

/// @notice Burns every unit of gas it is given, on `transfer` only.
contract GasBurnerToken is MockERC20 {
    function transfer(address, uint256) external pure override returns (bool) {
        assembly {
            invalid()
        }
    }
}

/// @notice Succeeds but returns an enormous buffer.
/// @dev Also covers the "malformed return size" branch: anything that is
///      neither empty nor exactly one word is treated as failure.
contract ReturnBombToken is MockERC20 {
    uint256 public immutable returnSize;

    /// @dev When false the token returns its bomb WITHOUT moving anything, so
    ///      the payout genuinely failed and a credit must be booked. When true
    ///      it moves the balance first, which is the far more dangerous shape:
    ///      the value is gone and the return payload says otherwise.
    bool public moveOnTransfer = true;

    constructor(uint256 returnSize_) {
        returnSize = returnSize_;
    }

    function setMoveOnTransfer(bool value) external {
        moveOnTransfer = value;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        if (moveOnTransfer) _move(msg.sender, to, amount);
        uint256 size = returnSize;
        assembly {
            return(0, size)
        }
    }
}

/// @notice Moves the balance on `transfer` and then chooses, per call, whether
///         to report the move honestly or with a return buffer the lock cannot
///         interpret.
/// @dev The audit's proof that classifying "call succeeded but the return
///      payload is unreadable" as FAILURE is not fail-closed. The token has
///      already moved the funds; booking a pull credit on top of that mints a
///      liability against pooled custody, and the creditor later collects it
///      out of an unrelated lock's money.
contract AmbiguousReturnToken is MockERC20 {
    uint256 public returnSize = 64;

    function setReturnSize(uint256 v) external {
        returnSize = v;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        _move(msg.sender, to, amount);
        uint256 size = returnSize;
        if (size == 32) return true;
        assembly {
            return(0, size)
        }
    }
}

/// @notice Delivers only part of what it was asked to move, and says `true`.
contract PartialTransferToken is MockERC20 {
    uint256 public numerator = 1;
    uint256 public denominator = 2;

    function setFraction(uint256 numerator_, uint256 denominator_) external {
        numerator = numerator_;
        denominator = denominator_;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        _move(msg.sender, to, (amount * numerator) / denominator);
        return true;
    }
}

/// @notice Full driver for the payout decision matrix: it controls, orthogonally,
///         whether each `balanceOf` probe answers, whether `transfer` moves
///         value, and what `transfer` reports.
/// @dev The three axes must be independent, because the dangerous combination is
///      precisely the one a token with coupled axes can never produce:
///      UNMEASURABLE and VALUE MOVED and FAILURE REPORTED. An earlier version of
///      this mock only moved value when it also reported success, which made
///      that quadrant unreachable and hid a live finding.
///
///      Written standalone rather than as a `MockERC20` subclass because a
///      Solidity function cannot override an inherited public mapping getter.
///      `ledger` is the honest accessor the fixtures read; `balanceOf` is the
///      one the contract under test sees.
contract UnreadableBalanceToken {
    /// @dev How `balanceOf` refuses, when it refuses.
    enum Mode {
        Revert,
        BurnGas,
        ShortAnswer
    }

    mapping(address => uint256) public ledger;
    mapping(address => mapping(address => uint256)) public allowance;

    Mode public mode;
    /// @dev Whether `balanceOf` refuses right now.
    bool public refusing;
    /// @dev `transfer` toggles `refusing`. Because the two probes bracket the
    ///      transfer, this is what makes it possible to fail EXACTLY the first
    ///      probe (start refusing, flip off) or EXACTLY the second (start
    ///      answering, flip on).
    bool public flipInTransfer;

    /// @dev Same trick as `flipInTransfer`, but during `transferFrom`, so a
    ///      test can make an asset answer the first probe of `_takeCustody` and
    ///      refuse the second one.
    bool public flipInTransferFrom;

    bool public transferMoves = true;
    bool public transferReportsOk = true;
    bool public transferReverts;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function setMode(Mode mode_) external {
        mode = mode_;
    }

    function setProbes(bool refusing_, bool flipInTransfer_) external {
        refusing = refusing_;
        flipInTransfer = flipInTransfer_;
    }

    function setFlipInTransferFrom(bool value) external {
        flipInTransferFrom = value;
    }

    function setTransfer(bool moves, bool reportsOk, bool reverts_) external {
        transferMoves = moves;
        transferReportsOk = reportsOk;
        transferReverts = reverts_;
    }

    function mint(address to, uint256 amount) external {
        ledger[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function balanceOf(address who) external view returns (uint256) {
        if (!refusing) return ledger[who];
        Mode m = mode;
        if (m == Mode.Revert) revert("no balance for you");
        if (m == Mode.BurnGas) {
            assembly {
                invalid()
            }
        }
        // A well-formed call that answers with something that is not one word.
        assembly {
            return(0, 8)
        }
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (transferMoves) _move(msg.sender, to, amount);
        if (flipInTransfer) refusing = !refusing;
        if (transferReverts) revert("transfer refused");
        if (!transferReportsOk) {
            // Succeeds, but with a payload the caller cannot interpret.
            assembly {
                return(0, 64)
            }
        }
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "allowance");
            allowance[from][msg.sender] = allowed - amount;
        }
        _move(from, to, amount);
        if (flipInTransferFrom) refusing = !refusing;
        return true;
    }

    function _move(address from, address to, uint256 amount) private {
        require(ledger[from] >= amount, "balance");
        unchecked {
            ledger[from] -= amount;
        }
        ledger[to] += amount;
        emit Transfer(from, to, amount);
    }
}

/// @notice The gas oracle: `balanceOf` answers honestly when called with a
///         normal budget and refuses when called with a small one.
/// @dev The attack this shape enabled needed no flag and no cooperation. When
///      `open` measured custody through the ordinary interface with the whole
///      remaining budget while the payout path probed under a cap, a token
///      could read `gasleft()` to tell the two apart, pass at the door, and be
///      permanently unmeasurable afterwards - choosing for itself which branch
///      of the payout logic judged it. Both sites now probe under the same cap,
///      so this token is refused at `open`.
contract GasSensitiveBalanceToken {
    /// @dev Above what a capped probe can ever see, below what an ordinary
    ///      full-budget call has left.
    uint256 public probeThreshold = 60_000;

    mapping(address => uint256) public ledger;
    mapping(address => mapping(address => uint256)) public allowance;

    /// @dev 64 = "moved it, but the payload is unreadable"; 32 = clean `true`.
    uint256 public returnSize = 64;
    bool public alwaysReadable;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function setProbeThreshold(uint256 v) external {
        probeThreshold = v;
    }

    function setReturnSize(uint256 v) external {
        returnSize = v;
    }

    function setAlwaysReadable(bool v) external {
        alwaysReadable = v;
    }

    function mint(address to, uint256 amount) external {
        ledger[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function balanceOf(address who) external view returns (uint256) {
        if (!alwaysReadable) require(gasleft() >= probeThreshold, "balanceOf: not enough gas");
        return ledger[who];
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "allowance");
            allowance[from][msg.sender] = allowed - amount;
        }
        _move(from, to, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        uint256 size = returnSize;
        if (size == 32) return true;
        assembly {
            return(0, size)
        }
    }

    function _move(address from, address to, uint256 amount) private {
        require(ledger[from] >= amount, "balance");
        unchecked {
            ledger[from] -= amount;
        }
        ledger[to] += amount;
        emit Transfer(from, to, amount);
    }
}

/// @notice Every `balanceOf` eats almost the whole gas it is handed and still
///         answers, so a measured push really is three expensive calls.
/// @dev Used to size `PAYOUT_GAS_FLOOR_ERC20`: the floor must be high enough
///      that a push, once attempted, always finishes its bookkeeping. `greedy`
///      is off while the lock is opened and on afterwards, so the fixture can
///      set up normally and then make every payout probe as expensive as the
///      cap allows.
contract GreedyProbeToken {
    mapping(address => uint256) public ledger;
    mapping(address => mapping(address => uint256)) public allowance;

    bool public greedy;
    bool public transferMoves = true;
    bool public transferReportsOk = true;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function setGreedy(bool v) external {
        greedy = v;
    }

    function setTransfer(bool moves, bool reportsOk) external {
        transferMoves = moves;
        transferReportsOk = reportsOk;
    }

    function mint(address to, uint256 amount) external {
        ledger[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function balanceOf(address who) external view returns (uint256) {
        if (greedy) {
            // Burn down to just enough to return, so the probe consumes its
            // entire cap and still answers.
            while (gasleft() > 1200) {}
        }
        return ledger[who];
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "allowance");
            allowance[from][msg.sender] = allowed - amount;
        }
        _move(from, to, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (transferMoves) _move(msg.sender, to, amount);
        if (!transferReportsOk) {
            assembly {
                return(0, 64)
            }
        }
        return true;
    }

    function _move(address from, address to, uint256 amount) private {
        require(ledger[from] >= amount, "balance");
        unchecked {
            ledger[from] -= amount;
        }
        ledger[to] += amount;
        emit Transfer(from, to, amount);
    }
}

/// @notice Honest token that can never move more than `cap` in one `transfer`,
///         and silently delivers only what it can.
/// @dev Max-transaction-limit tokens exist in the wild. This one neither
///      reverts nor takes a fee, so `open` has no grounds to reject it, yet
///      credits accumulate across locks until no single transfer can settle
///      them. That is what `withdrawAmount` exists for.
contract CappedTransferToken is MockERC20 {
    uint256 public cap = type(uint256).max;

    function setCap(uint256 v) external {
        cap = v;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        uint256 moving = amount > cap ? cap : amount;
        _move(msg.sender, to, moving);
        return true;
    }
}

/// @notice Sends tokens back to the caller while its own `transfer` is running.
contract BouncingToken is MockERC20 {
    uint256 public bounce;

    function setBounce(uint256 v) external {
        bounce = v;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        _move(msg.sender, to, amount);
        uint256 b = bounce;
        if (b != 0 && balanceOf[address(this)] >= b) _move(address(this), msg.sender, b);
        return true;
    }
}

/// @notice `balanceOf` under-reports the drop: it moves the value but reports
///         the SAME balance afterwards, so the measured delta is zero.
/// @dev The one shape the measurement cannot defend against, kept as a pinned
///      residue rather than an unknown. See
///      `test_assetLyingUpwardAboutItsBalanceCanStillMintAPhantomCredit`.
contract UpwardLieToken {
    mapping(address => uint256) public ledger;
    mapping(address => mapping(address => uint256)) public allowance;

    bool public freezeReportedBalance;
    uint256 private frozenValue;

    function setFreeze(bool v, uint256 value) external {
        freezeReportedBalance = v;
        frozenValue = value;
    }

    function mint(address to, uint256 amount) external {
        ledger[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function balanceOf(address who) external view returns (uint256) {
        if (freezeReportedBalance && who == msg.sender) return frozenValue;
        return ledger[who];
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "allowance");
            allowance[from][msg.sender] = allowed - amount;
        }
        _move(from, to, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) private {
        require(ledger[from] >= amount, "balance");
        unchecked {
            ledger[from] -= amount;
        }
        ledger[to] += amount;
    }
}

/// @notice `balanceOf` answers with a well-formed word that is a lie: enormous
///         before the transfer, real afterwards. Nothing actually moves.
/// @dev Finding G. Both probes "succeed", so the measured drop is believed even
///      though `transfer` returned `false` and moved nothing.
contract ShrinkingLieToken {
    mapping(address => uint256) public ledger;
    mapping(address => mapping(address => uint256)) public allowance;

    bool public lying;

    function setLying(bool v) external {
        lying = v;
    }

    function mint(address to, uint256 amount) external {
        ledger[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function balanceOf(address who) external view returns (uint256) {
        if (lying) return type(uint256).max;
        return ledger[who];
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "allowance");
            allowance[from][msg.sender] = allowed - amount;
        }
        require(ledger[from] >= amount, "balance");
        unchecked {
            ledger[from] -= amount;
        }
        ledger[to] += amount;
        return true;
    }

    /// @dev Moves nothing, and does not even pretend to have succeeded.
    function transfer(address, uint256) external returns (bool) {
        lying = false; // so the second probe reports the (unchanged) real balance
        return false;
    }
}

/// @notice Reports a balance the test controls directly, so a credit can be
///         driven to the edge of `uint256` without any account ever holding
///         that many units.
contract LyingBalanceToken {
    uint256 public fakeBalance;
    bool public transferSucceeds;

    function setFakeBalance(uint256 v) external {
        fakeBalance = v;
    }

    function setTransferSucceeds(bool v) external {
        transferSucceeds = v;
    }

    function balanceOf(address) external view returns (uint256) {
        return fakeBalance;
    }

    function transferFrom(address, address, uint256 amount) external returns (bool) {
        fakeBalance += amount;
        return true;
    }

    function transfer(address, uint256) external view returns (bool) {
        return transferSucceeds;
    }
}

/// @notice Calls back into the lock contract from inside `transfer` /
///         `transferFrom`.
/// @dev Like `ReentrantReceiver`, the bookkeeping slot is pre-warmed to a
///      non-zero value so that the attack can actually execute inside the 30k
///      payout stipend instead of dying on a cold SSTORE. The hot fields are
///      packed into a single slot for the same reason.
contract ReentrantToken is MockERC20 {
    enum Mode {
        Passive,
        Claim,
        Refund,
        Withdraw,
        Open
    }

    uint256 public constant LOG_IDLE = 1;
    uint256 public constant LOG_BLOCKED = 2;
    uint256 public constant LOG_SUCCEEDED = 3;

    /// @dev Status in the low byte, the nested call's revert selector in bits
    ///      8..39. Packed into ONE slot on purpose: recording the selector in a
    ///      second slot would add a warm SSTORE that does not fit in the 30k
    ///      payout stipend, and the attack would then die on gas rather than on
    ///      the reentrancy guard - which is precisely the confusion the
    ///      selector is being recorded to rule out.
    uint256 public attackRecord = LOG_IDLE;

    // Packed into one slot: 20 + 1 + 1 bytes.
    address public lock;
    Mode public mode;
    bool public reenterOnTransferFrom;

    bytes32 public lockId;
    uint256 public secret;

    /// @dev Lets a test force the push payout into the pull path so that the
    ///      full-gas pull can then be attacked.
    bool public failTransfer;

    function setFailTransfer(bool value) external {
        failTransfer = value;
    }

    function arm(address lock_, Mode mode_, bytes32 lockId_, uint256 secret_, bool onTransferFrom) external {
        lock = lock_;
        mode = mode_;
        lockId = lockId_;
        secret = secret_;
        reenterOnTransferFrom = onTransferFrom;
        attackRecord = LOG_IDLE;
    }

    /// @notice Status of the last nested attempt: idle, blocked or succeeded.
    function attackLog() external view returns (uint256) {
        return attackRecord & 0xff;
    }

    /// @notice The selector the nested call reverted with, so a test can prove
    ///         the reentrancy guard fired rather than the frame running out of
    ///         gas. Zero if the call did not revert with a selector.
    function nestedSelector() external view returns (bytes4) {
        // `bytes4(bytes32(..))` takes the high four bytes.  Move the packed
        // low-word selector there instead of narrowing a uint256 through an
        // unchecked numeric cast.
        return bytes4(bytes32((attackRecord >> 8) << 224));
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        if (failTransfer) return false;
        _move(msg.sender, to, amount);
        _attack();
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        _spendAllowance(from, amount);
        _move(from, to, amount);
        if (reenterOnTransferFrom) _attack();
        return true;
    }

    function _attack() private {
        address target = lock;
        Mode m = mode;
        if (m == Mode.Passive || target == address(0)) return;

        bytes memory payload;
        if (m == Mode.Claim) {
            payload = abi.encodeWithSignature("claim(bytes32,uint256)", lockId, secret);
        } else if (m == Mode.Refund) {
            payload = abi.encodeWithSignature("refund(bytes32)", lockId);
        } else if (m == Mode.Withdraw) {
            payload = abi.encodeWithSignature("withdraw(address)", address(this));
        } else {
            payload = abi.encodeWithSignature(
                "open((bytes32,uint8,bytes32,bytes32,bytes32,address,uint256,address,address,uint64))",
                bytes32(0),
                uint8(0),
                bytes32(0),
                bytes32(0),
                bytes32(0),
                address(this),
                uint256(1),
                address(this),
                address(this),
                uint64(0)
            );
        }

        (bool ok, bytes memory err) = target.call(payload);
        uint256 selector;
        if (!ok && err.length >= 4) {
            selector = uint256(
                uint32(bytes4(err[0]) | (bytes4(err[1]) >> 8) | (bytes4(err[2]) >> 16) | (bytes4(err[3]) >> 24))
            );
        }
        attackRecord = (selector << 8) | (ok ? LOG_SUCCEEDED : LOG_BLOCKED);
    }
}
