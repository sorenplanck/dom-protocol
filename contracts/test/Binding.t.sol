// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ConditionLockV2} from "../src/ConditionLockV2.sol";
import {LockBinding, LockTerms} from "../src/LockBinding.sol";
import {F3TestBase} from "./Base.t.sol";

/// @notice Section 1 derivation: domains, layout, field sensitivity,
///         anti-squatting, anti-replay, anti-collision, and `address(t*G)`.
contract BindingTest is F3TestBase {
    ConditionLockV2 internal lock;
    ConditionLockV2 internal otherLock;

    /// @dev Names of the ten `LockTerms` fields, in wire order.
    string[10] internal FIELD_NAMES = [
        "domChainId",
        "direction",
        "sessionId",
        "termsHash",
        "participantsHash",
        "asset",
        "amount",
        "beneficiary",
        "adaptorAddress",
        "deadline"
    ];

    function setUp() public {
        _setUpTime();
        lock = new ConditionLockV2();
        otherLock = new ConditionLockV2();
    }

    // ------------------------------------------------------------------
    // Domain separators and version
    // ------------------------------------------------------------------

    function test_domainSeparatorsAreTheFrozenStrings() public pure {
        assertEq(
            LockBinding.BINDING_DOMAIN,
            keccak256("DOM-Interop/ConditionLockV2/binding"),
            "binding domain drifted from the spec"
        );
        assertEq(
            LockBinding.LOCKID_DOMAIN,
            keccak256("DOM-Interop/ConditionLockV2/lockId"),
            "lockId domain drifted from the spec"
        );
        assertEq(LockBinding.BINDING_VERSION, 2, "binding version drifted from the spec");
    }

    function test_domainSeparatorsAreDistinct() public pure {
        assertTrue(LockBinding.BINDING_DOMAIN != LockBinding.LOCKID_DOMAIN);
    }

    function test_curveConstantsAreSecp256k1() public pure {
        assertEq(LockBinding.SECP256K1_N, SECP256K1_N);
        assertEq(LockBinding.SECP256K1_GX, 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798);
        assertEq(LockBinding.V_FOR_G, 27);
    }

    // ------------------------------------------------------------------
    // Layout equivalence against the independent reference
    // ------------------------------------------------------------------

    function test_bindingMatchesReferenceLayout() public view {
        LockTerms memory t = _defaultNativeTerms();
        assertEq(lock.deriveBinding(t), _refBinding(t, block.chainid, address(lock)));
    }

    function test_lockIdMatchesReferenceLayout() public view {
        LockTerms memory t = _defaultNativeTerms();
        bytes32 binding = _refBinding(t, block.chainid, address(lock));
        assertEq(lock.deriveLockId(t, funder), _refLockId(binding, funder));
    }

    /// @dev The library splits `abi.encode` into three groups purely to dodge a
    ///      stack-too-deep in the legacy code generator. This pins that the
    ///      split is byte-identical to encoding the whole struct at once, which
    ///      is what the Rust side will reproduce.
    function testFuzz_splitEncodingEqualsSingleStructEncoding(LockTerms memory t) public view {
        bytes memory single =
            abi.encode(LockBinding.BINDING_DOMAIN, LockBinding.BINDING_VERSION, block.chainid, address(lock), t);
        assertEq(single.length, 14 * 32, "static tuple must inline into 14 words");
        assertEq(keccak256(single), lock.deriveBinding(t));
    }

    function testFuzz_derivationIsDeterministic(LockTerms memory t, address funder_) public view {
        assertEq(lock.deriveBinding(t), lock.deriveBinding(t));
        assertEq(lock.deriveLockId(t, funder_), lock.deriveLockId(t, funder_));
        assertEq(lock.deriveLockId(t, funder_), _refLockId(_refBinding(t, block.chainid, address(lock)), funder_));
    }

    // ------------------------------------------------------------------
    // Anti-replay: chain id and contract address
    // ------------------------------------------------------------------

    function test_bindingDependsOnChainId() public {
        LockTerms memory t = _defaultNativeTerms();
        bytes32 onA = lock.deriveBinding(t);
        vm.chainId(block.chainid + 1);
        bytes32 onB = lock.deriveBinding(t);
        assertTrue(onA != onB, "binding must not survive a chain change");
        assertTrue(lock.deriveLockId(t, funder) != _refLockId(onA, funder));
    }

    function test_bindingDependsOnContractAddress() public view {
        LockTerms memory t = _defaultNativeTerms();
        assertTrue(address(lock) != address(otherLock));
        assertTrue(lock.deriveBinding(t) != otherLock.deriveBinding(t), "binding must not survive a redeployment");
        assertTrue(lock.deriveLockId(t, funder) != otherLock.deriveLockId(t, funder));
    }

    // ------------------------------------------------------------------
    // Anti-squatting: the funder is bound in
    // ------------------------------------------------------------------

    function testFuzz_lockIdDependsOnFunder(address a, address b) public view {
        vm.assume(a != b);
        LockTerms memory t = _defaultNativeTerms();
        assertTrue(lock.deriveLockId(t, a) != lock.deriveLockId(t, b));

        // The binding itself is funder-independent by design: it is the terms
        // commitment shared by both legs. Checked against the hand-written
        // reference encoding, which has no funder in it at all - comparing
        // `deriveBinding` with itself would assert nothing.
        assertEq(lock.deriveBinding(t), _refBinding(t, block.chainid, address(lock)));
        assertEq(lock.deriveLockId(t, a), _refLockId(_refBinding(t, block.chainid, address(lock)), a));
        assertEq(lock.deriveLockId(t, b), _refLockId(_refBinding(t, block.chainid, address(lock)), b));
    }

    // ------------------------------------------------------------------
    // Field sensitivity: every field individually changes binding and lockId
    // ------------------------------------------------------------------

    /// @dev Changes exactly one field. Wrapping is deliberate: the numeric
    ///      fields are fuzzed over their whole range, and a checked `+ 1` would
    ///      turn "the maximum value" into a test failure instead of a mutation.
    ///      Wrapping never produces the original value, so the change is real
    ///      for every input.
    /// @dev A DEEP copy. `LockTerms memory m = t` would alias the same memory,
    ///      so mutating `m` would silently mutate `t` as well and every
    ///      "changed one field from the base" test would really be testing an
    ///      accumulating mutation against a moving base.
    function _copy(LockTerms memory t) internal pure returns (LockTerms memory) {
        return LockTerms({
            domChainId: t.domChainId,
            direction: t.direction,
            sessionId: t.sessionId,
            termsHash: t.termsHash,
            participantsHash: t.participantsHash,
            asset: t.asset,
            amount: t.amount,
            beneficiary: t.beneficiary,
            adaptorAddress: t.adaptorAddress,
            deadline: t.deadline
        });
    }

    function _mutate(LockTerms memory t, uint256 field) internal pure returns (LockTerms memory m) {
        m = _copy(t);
        // Wrapping is lexically scoped, so it has to live here rather than in a
        // helper: `x + 1` on the maximum value must wrap, not revert.
        unchecked {
            if (field == 0) {
                m.domChainId = keccak256(abi.encode(t.domChainId, "x"));
            } else if (field == 1) {
                m.direction = t.direction == 0 ? 1 : 0;
            } else if (field == 2) {
                m.sessionId = keccak256(abi.encode(t.sessionId, "x"));
            } else if (field == 3) {
                m.termsHash = keccak256(abi.encode(t.termsHash, "x"));
            } else if (field == 4) {
                m.participantsHash = keccak256(abi.encode(t.participantsHash, "x"));
            } else if (field == 5) {
                m.asset = address(uint160(t.asset) + 1);
            } else if (field == 6) {
                m.amount = t.amount + 1;
            } else if (field == 7) {
                m.beneficiary = address(uint160(t.beneficiary) + 1);
            } else if (field == 8) {
                m.adaptorAddress = address(uint160(t.adaptorAddress) + 1);
            } else {
                m.deadline = t.deadline + 1;
            }
        }
    }

    function test_everyFieldChangesBindingAndLockId() public view {
        LockTerms memory base = _defaultNativeTerms();
        bytes32 baseBinding = lock.deriveBinding(base);
        bytes32 baseLockId = lock.deriveLockId(base, funder);

        for (uint256 i = 0; i < 10; i++) {
            // `_mutate` deep-copies, so each iteration varies exactly one field
            // of the SAME base rather than accumulating onto the previous one.
            LockTerms memory m = _mutate(base, i);
            assertTrue(lock.deriveBinding(m) != baseBinding, FIELD_NAMES[i]);
            assertTrue(lock.deriveLockId(m, funder) != baseLockId, FIELD_NAMES[i]);
            // and the library still agrees with the independent reference
            assertEq(lock.deriveBinding(m), _refBinding(m, block.chainid, address(lock)));
            // the base really was left alone
            assertEq(lock.deriveBinding(base), baseBinding, "base was mutated by the helper");
        }
    }

    /// @dev Field participation over arbitrary terms, not keccak
    ///      collision-freeness. Asserting that two different term sets hash
    ///      differently would be a statement about keccak256 that no test can
    ///      fail; what CAN fail - and is what actually matters - is a field
    ///      being dropped from the preimage. So: take fuzzed terms, change one
    ///      fuzzed field, and require the binding and the lock id to move.
    function testFuzz_everyFieldParticipatesInTheHash(LockTerms memory t, uint256 field, address funder_) public view {
        field = bound(field, 0, 9);
        LockTerms memory m = _mutate(t, field);
        // `_mutate` wraps on overflow for the numeric fields; skip the rare
        // fuzz input where the mutation is a no-op.
        vm.assume(keccak256(abi.encode(m)) != keccak256(abi.encode(t)));

        assertTrue(lock.deriveBinding(m) != lock.deriveBinding(t), FIELD_NAMES[field]);
        assertTrue(lock.deriveLockId(m, funder_) != lock.deriveLockId(t, funder_), FIELD_NAMES[field]);
        assertEq(lock.deriveBinding(m), _refBinding(m, block.chainid, address(lock)));
    }

    /// @dev Hand-crafted calldata with garbage in the padding of the sub-word
    ///      fields. If the decoder merely masked instead of validating, two
    ///      different calldata payloads describing the same logical terms could
    ///      produce two different bindings, or a stored `deadline` that differs
    ///      from the hashed one. Every dirty word must be rejected.
    function test_dirtyCalldataWordsAreRejected() public view {
        LockTerms memory t = _defaultNativeTerms();
        bytes memory clean = abi.encodeWithSignature(
            "deriveBinding((bytes32,uint8,bytes32,bytes32,bytes32,address,uint256,address,address,uint64))",
            t.domChainId,
            uint256(t.direction),
            t.sessionId,
            t.termsHash,
            t.participantsHash,
            uint256(uint160(t.asset)),
            t.amount,
            uint256(uint160(t.beneficiary)),
            uint256(uint160(t.adaptorAddress)),
            uint256(t.deadline)
        );

        (bool ok, bytes memory ret) = address(lock).staticcall(clean);
        assertTrue(ok, "clean encoding must work");
        assertEq(abi.decode(ret, (bytes32)), lock.deriveBinding(t), "control");

        // Word index inside the tuple (0-based, after the 4-byte selector) and
        // the dirt to OR into it.
        uint256[5] memory dirtyWords = [uint256(1), 5, 7, 8, 9];
        uint256[5] memory dirt = [
            uint256(0x100), // direction: bit above uint8
            uint256(1) << 160, // asset: bit above address
            uint256(1) << 160, // beneficiary
            uint256(1) << 160, // adaptorAddress
            uint256(1) << 64 // deadline: bit above uint64
        ];

        for (uint256 i = 0; i < 5; i++) {
            bytes memory dirty = clean;
            uint256 off = 4 + 32 * dirtyWords[i];
            assembly {
                let p := add(add(dirty, 0x20), off)
                mstore(p, or(mload(p), mload(add(dirt, mul(0x20, i)))))
            }
            (bool dirtyOk,) = address(lock).staticcall(dirty);
            assertFalse(dirtyOk, "a dirty calldata word must be rejected, not silently masked");
        }
    }

    /// @dev Anti-collision: `abi.encode` gives every field its own word, so
    ///      moving bytes between two adjacent fields cannot produce the same
    ///      preimage the way `abi.encodePacked` would.
    function test_adjacentFieldsCannotBeConfused() public view {
        LockTerms memory a = _defaultNativeTerms();
        LockTerms memory b = _defaultNativeTerms();
        // Swap two same-width neighbours: with packed encoding of variable-width
        // fields this class of confusion is what breaks; here it must not.
        a.termsHash = bytes32(uint256(0x1122));
        a.participantsHash = bytes32(uint256(0x3344));
        b.termsHash = bytes32(uint256(0x3344));
        b.participantsHash = bytes32(uint256(0x1122));
        assertTrue(lock.deriveBinding(a) != lock.deriveBinding(b));
    }

    // ------------------------------------------------------------------
    // address(t*G)
    // ------------------------------------------------------------------

    function test_scalarZeroReverts() public {
        vm.expectRevert(LockBinding.NonCanonicalScalar.selector);
        lock.addressOfScalarTimesG(0);
    }

    function test_scalarAtOrAboveOrderReverts() public {
        vm.expectRevert(LockBinding.NonCanonicalScalar.selector);
        lock.addressOfScalarTimesG(SECP256K1_N);
        vm.expectRevert(LockBinding.NonCanonicalScalar.selector);
        lock.addressOfScalarTimesG(SECP256K1_N + 1);
        vm.expectRevert(LockBinding.NonCanonicalScalar.selector);
        lock.addressOfScalarTimesG(type(uint256).max);
    }

    function test_scalarOneIsTheGeneratorAddress() public view {
        // Independent oracle: `vm.addr` performs a real scalar multiplication.
        assertEq(lock.addressOfScalarTimesG(1), vm.addr(1));
    }

    function test_scalarOrderMinusOne() public view {
        assertEq(lock.addressOfScalarTimesG(SECP256K1_N - 1), vm.addr(SECP256K1_N - 1));
    }

    /// @dev The whole canonical range agrees with a real scalar multiplication.
    function testFuzz_scalarMatchesRealScalarMultiplication(uint256 t) public view {
        t = bound(t, 1, SECP256K1_N - 1);
        assertEq(lock.addressOfScalarTimesG(t), vm.addr(t));
    }

    /// @dev No canonical scalar can make the precompile return the zero address,
    ///      so the defensive zero check inside `claim` can never be the thing
    ///      that lets a wrong secret through.
    function testFuzz_canonicalScalarNeverYieldsZeroAddress(uint256 t) public view {
        t = bound(t, 1, SECP256K1_N - 1);
        assertTrue(lock.addressOfScalarTimesG(t) != address(0));
    }

    /// @dev The two degenerate `s` values do make the precompile return zero.
    ///      This is the "these inputs are bad" half of the argument; the
    ///      "no canonical `t` can produce them" half is the fuzz test below.
    function test_rawEcrecoverReturnsZeroForTheDegenerateSValues() public pure {
        uint256 gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
        // s == 0 corresponds to t == 0 (mod n), which is rejected up front.
        assertEq(ecrecover(bytes32(0), 27, bytes32(gx), bytes32(uint256(0))), address(0));
        // s >= n is unreachable because `mulmod(t, Gx, n)` is always < n.
        assertEq(ecrecover(bytes32(0), 27, bytes32(gx), bytes32(SECP256K1_N)), address(0));
    }

    /// @dev The other half: for every canonical `t`, the `s` fed to the
    ///      precompile is strictly inside `(0, n)`, so neither degenerate input
    ///      above is reachable. Together with the test above this is what
    ///      justifies calling the zero-address branch in `claim` unreachable.
    function testFuzz_sIsNeverDegenerateForACanonicalScalar(uint256 t) public pure {
        t = bound(t, 1, SECP256K1_N - 1);
        uint256 s = mulmod(t, 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, SECP256K1_N);
        assertTrue(s != 0, "s == 0 would make ecrecover return address(0)");
        assertTrue(s < SECP256K1_N, "s >= n would make ecrecover return address(0)");
    }

    function testFuzz_distinctScalarsGiveDistinctAddresses(uint256 a, uint256 b) public view {
        a = bound(a, 1, SECP256K1_N - 1);
        b = bound(b, 1, SECP256K1_N - 1);
        vm.assume(a != b);
        assertTrue(lock.addressOfScalarTimesG(a) != lock.addressOfScalarTimesG(b));
    }
}
