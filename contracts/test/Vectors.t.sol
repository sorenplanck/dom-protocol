// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ConditionLockV2} from "../src/ConditionLockV2.sol";
import {LockBinding, LockTerms} from "../src/LockBinding.sol";
import {F3TestBase} from "./Base.t.sol";

/// @notice Produces `test/vectors/f3_vectors.json`, the cross-language fixture
///         consumed by the Rust EVM adapter, and asserts that the deployed
///         contract agrees with every vector it writes.
///
/// @dev JSON encoding rules, fixed here so the Rust side can decode without
///      guessing:
///      * every `bytes32` is a lowercase `0x` + 64 hex digit string;
///      * every `address` is an EIP-55 checksummed `0x` + 40 hex digit string
///        (compare case-insensitively);
///      * `amount` and `deadline` are base-10 STRINGS. `amount` is a `uint256`
///        and never fits a JSON number; `deadline` is a `uint64` and
///        `type(uint64).max` (2^64-1) already exceeds the IEEE-754 exact
///        integer range (2^53-1), so a bare JSON number is silently rounded to
///        2^64 by every double-based parser (JavaScript, jq). Emitting it as a
///        string is what makes this file safely consumable by ANY language,
///        which is the whole point of a cross-language vector artifact;
///      * `chainId` and `direction` are JSON numbers; both are small and exact.
///
///      The scalar vectors cover the canonical range boundaries (`1`, `n-1`)
///      plus low, high and pseudo-random interior points. The binding vectors
///      cover a base case, one variation per `LockTerms` field, plus a varied
///      funder, chain id and contract address, so a Rust implementation that
///      gets any single field's position or width wrong cannot pass.
contract VectorsTest is F3TestBase {
    string internal constant VECTOR_DIR = "test/vectors";
    string internal constant VECTOR_PATH = "test/vectors/f3_vectors.json";

    ConditionLockV2 internal lock;
    ConditionLockV2 internal otherLock;

    /// @dev Accumulators kept in storage so the JSON assembly never has to hold
    ///      a long chain of intermediates on the stack.
    string internal scalarBuffer;
    string internal bindingBuffer;
    uint256 internal scalarCount;
    uint256 internal bindingCount;

    function setUp() public {
        _setUpTime();
        lock = new ConditionLockV2();
        otherLock = new ConditionLockV2();
    }

    // ------------------------------------------------------------------
    // Vector emission
    // ------------------------------------------------------------------

    function test_writeCrossLanguageVectors() public {
        _emitScalarVectors();
        _emitBindingVectors();

        assertGe(scalarCount, 16, "spec section 5 requires at least 16 scalar vectors");
        assertGe(bindingCount, 8, "spec section 5 requires at least 8 binding vectors");

        string memory json =
            string.concat('{"scalarVectors":[', scalarBuffer, '],"bindingVectors":[', bindingBuffer, "]}");

        vm.createDir(VECTOR_DIR, true);
        vm.writeJson(json, VECTOR_PATH);

        _verifyFileRoundTrip();
    }

    /// @dev Reads the file back through the JSON parser and re-derives every
    ///      entry from the parsed values, so a malformed or mis-encoded file
    ///      fails here rather than silently in the Rust suite.
    function _verifyFileRoundTrip() private view {
        string memory json = vm.readFile(VECTOR_PATH);

        for (uint256 i = 0; i < scalarCount; i++) {
            string memory at = string.concat(".scalarVectors[", vm.toString(i), "]");
            uint256 t = uint256(vm.parseJsonBytes32(json, string.concat(at, ".t")));
            address adaptorAddress = vm.parseJsonAddress(json, string.concat(at, ".adaptorAddress"));
            assertEq(lock.addressOfScalarTimesG(t), adaptorAddress, "scalar vector round-trip");
        }

        for (uint256 i = 0; i < bindingCount; i++) {
            string memory at = string.concat(".bindingVectors[", vm.toString(i), "]");
            LockTerms memory t = LockTerms({
                domChainId: vm.parseJsonBytes32(json, string.concat(at, ".terms.domChainId")),
                direction: uint8(vm.parseJsonUint(json, string.concat(at, ".terms.direction"))),
                sessionId: vm.parseJsonBytes32(json, string.concat(at, ".terms.sessionId")),
                termsHash: vm.parseJsonBytes32(json, string.concat(at, ".terms.termsHash")),
                participantsHash: vm.parseJsonBytes32(json, string.concat(at, ".terms.participantsHash")),
                asset: vm.parseJsonAddress(json, string.concat(at, ".terms.asset")),
                amount: vm.parseUint(vm.parseJsonString(json, string.concat(at, ".terms.amount"))),
                beneficiary: vm.parseJsonAddress(json, string.concat(at, ".terms.beneficiary")),
                adaptorAddress: vm.parseJsonAddress(json, string.concat(at, ".terms.adaptorAddress")),
                deadline: uint64(vm.parseJsonUint(json, string.concat(at, ".terms.deadline")))
            });
            uint256 chainId = vm.parseJsonUint(json, string.concat(at, ".chainId"));
            address lockContract = vm.parseJsonAddress(json, string.concat(at, ".contract"));
            address funder_ = vm.parseJsonAddress(json, string.concat(at, ".funder"));

            assertEq(
                vm.parseJsonBytes32(json, string.concat(at, ".binding")),
                _refBinding(t, chainId, lockContract),
                "binding vector round-trip"
            );
            assertEq(
                vm.parseJsonBytes32(json, string.concat(at, ".lockId")),
                _refLockId(_refBinding(t, chainId, lockContract), funder_),
                "lockId vector round-trip"
            );
        }
    }

    function _emitScalarVectors() private {
        uint256 n = LockBinding.SECP256K1_N;

        // Boundaries and small values.
        _addScalar(1);
        _addScalar(2);
        _addScalar(3);
        _addScalar(7);
        _addScalar(n - 1);
        _addScalar(n - 2);
        _addScalar(n - 3);

        // Structured interior points.
        _addScalar(n / 2);
        _addScalar(n / 2 + 1);
        _addScalar(1 << 128);
        _addScalar((1 << 128) - 1);
        _addScalar(uint256(type(uint128).max) + 1);

        // Deterministic pseudo-random points, reproducible from the label alone.
        for (uint256 i = 0; i < 8; i++) {
            uint256 t = uint256(keccak256(abi.encodePacked("DOM-Interop/f3-vector/scalar", i)));
            _addScalar((t % (n - 1)) + 1);
        }
    }

    function _addScalar(uint256 t) private {
        address expected = lock.addressOfScalarTimesG(t);
        // Independent oracle: a real secp256k1 scalar multiplication.
        assertEq(expected, vm.addr(t), "contract disagrees with a real scalar multiplication");

        string memory entry =
            string.concat('{"t":"', vm.toString(bytes32(t)), '","adaptorAddress":"', vm.toString(expected), '"}');
        scalarBuffer = scalarCount == 0 ? entry : string.concat(scalarBuffer, ",", entry);
        scalarCount += 1;
    }

    function _emitBindingVectors() private {
        LockTerms memory base = LockTerms({
            domChainId: keccak256("DOM-Interop/f3-vector/domChainId"),
            direction: 0,
            sessionId: keccak256("DOM-Interop/f3-vector/sessionId"),
            termsHash: keccak256("DOM-Interop/f3-vector/termsHash"),
            participantsHash: keccak256("DOM-Interop/f3-vector/participantsHash"),
            asset: address(0),
            amount: 3 ether,
            beneficiary: address(uint160(0xB1)),
            adaptorAddress: vm.addr(SECRET),
            deadline: 1_900_000_000
        });
        address vectorFunder = address(uint160(0xF1));

        _addBinding(lock, base, vectorFunder);

        // One variation per LockTerms field, in wire order.
        LockTerms memory v;
        v = base;
        v.domChainId = keccak256("varied/domChainId");
        _addBinding(lock, v, vectorFunder);
        v = base;
        v.direction = 1;
        _addBinding(lock, v, vectorFunder);
        v = base;
        v.sessionId = keccak256("varied/sessionId");
        _addBinding(lock, v, vectorFunder);
        v = base;
        v.termsHash = keccak256("varied/termsHash");
        _addBinding(lock, v, vectorFunder);
        v = base;
        v.participantsHash = keccak256("varied/participantsHash");
        _addBinding(lock, v, vectorFunder);
        v = base;
        v.asset = address(uint160(0xA5));
        _addBinding(lock, v, vectorFunder);
        v = base;
        v.amount = type(uint256).max;
        _addBinding(lock, v, vectorFunder);
        v = base;
        v.beneficiary = address(uint160(0xB2));
        _addBinding(lock, v, vectorFunder);
        v = base;
        v.adaptorAddress = vm.addr(OTHER_SECRET);
        _addBinding(lock, v, vectorFunder);
        v = base;
        v.deadline = type(uint64).max;
        _addBinding(lock, v, vectorFunder);

        // Varied funder: same binding, different lock id.
        _addBinding(lock, base, address(uint160(0xF2)));

        // Varied contract address: different binding for identical terms.
        _addBinding(otherLock, base, vectorFunder);

        // Varied chain id.
        uint256 originalChainId = block.chainid;
        vm.chainId(11_155_111);
        _addBinding(lock, base, vectorFunder);
        vm.chainId(originalChainId);
    }

    function _addBinding(ConditionLockV2 target, LockTerms memory t, address funder_) private {
        bytes32 binding = target.deriveBinding(t);
        bytes32 lockId = target.deriveLockId(t, funder_);

        // The contract must agree with the independent reference derivation.
        assertEq(binding, _refBinding(t, block.chainid, address(target)), "binding disagrees with the reference");
        assertEq(lockId, _refLockId(binding, funder_), "lockId disagrees with the reference");

        string memory entry = string.concat(
            '{"chainId":',
            vm.toString(block.chainid),
            ',"contract":"',
            vm.toString(address(target)),
            '","terms":',
            _termsJson(t),
            ',"funder":"',
            vm.toString(funder_),
            '","binding":"',
            vm.toString(binding),
            '","lockId":"',
            vm.toString(lockId),
            '"}'
        );
        bindingBuffer = bindingCount == 0 ? entry : string.concat(bindingBuffer, ",", entry);
        bindingCount += 1;
    }

    function _termsJson(LockTerms memory t) private pure returns (string memory) {
        string memory head = string.concat(
            '{"domChainId":"',
            vm.toString(t.domChainId),
            '","direction":',
            vm.toString(uint256(t.direction)),
            ',"sessionId":"',
            vm.toString(t.sessionId),
            '","termsHash":"',
            vm.toString(t.termsHash),
            '","participantsHash":"',
            vm.toString(t.participantsHash),
            '"'
        );
        string memory tail = string.concat(
            ',"asset":"',
            vm.toString(t.asset),
            '","amount":"',
            vm.toString(t.amount),
            '","beneficiary":"',
            vm.toString(t.beneficiary),
            '","adaptorAddress":"',
            vm.toString(t.adaptorAddress),
            '","deadline":"',
            vm.toString(uint256(t.deadline)),
            '"}'
        );
        return string.concat(head, tail);
    }

    // ------------------------------------------------------------------
    // The vectors must describe the contract that is actually deployed
    // ------------------------------------------------------------------

    /// @dev A lock opened with the base terms really does land on the lock id
    ///      the vector file publishes, so the fixture is not merely a
    ///      self-consistent hash exercise.
    function test_vectorLockIdIsTheOneOpenUsesOnChain() public {
        LockTerms memory t = _defaultNativeTerms();
        bytes32 predicted = lock.deriveLockId(t, funder);

        vm.deal(funder, t.amount);
        vm.prank(funder);
        bytes32 actual = lock.open{value: t.amount}(t);

        assertEq(actual, predicted, "open must land on the derived lock id");
        assertEq(lock.lockOf(actual).binding, lock.deriveBinding(t));
    }
}
