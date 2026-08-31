// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Canonical settlement terms of one EVM leg.
/// @dev The field order below is a FROZEN wire format: it is hashed with
///      `abi.encode` (one fixed 32-byte word per field) and reproduced
///      byte-for-byte by the Rust adapter workstream. Reordering, inserting or
///      retyping a field is a breaking change that requires a new
///      `BINDING_VERSION`.
struct LockTerms {
    /// @dev DOM `TrustedChainIdV1` (32 bytes).
    bytes32 domChainId;
    /// @dev 0 = DOM -> EVM, 1 = EVM -> DOM.
    uint8 direction;
    /// @dev DOM `session_id`.
    bytes32 sessionId;
    /// @dev DOM `terms_hash`.
    bytes32 termsHash;
    /// @dev keccak256 over the ordered participant roster encoding.
    bytes32 participantsHash;
    /// @dev `address(0)` in the native contract, token address in the ERC-20 contract.
    address asset;
    /// @dev Exact amount locked, in the asset's smallest unit.
    uint256 amount;
    /// @dev The only address allowed to `claim`.
    address beneficiary;
    /// @dev `address(T)` where `T = t*G`.
    address adaptorAddress;
    /// @dev UNIX timestamp; DOM `TimelockDomain::Timestamp`.
    uint64 deadline;
}

/// @title LockBinding
/// @notice Canonical binding / lock-id derivation and the secp256k1
///         `address(t*G)` helper shared by both ConditionLock variants.
/// @dev Normative source: F3 interface spec section 1, and the DOM-Interop
///      Foundation Document v0.2.1 section 2.3.
///
///      Three properties are load-bearing and are proven by the test suite:
///      * anti-squatting  - `lockId` binds `funder`, so it can never be a
///        caller-chosen argument and cannot be pre-empted by a third party.
///      * anti-replay     - `block.chainid` and `address(this)` are bound in,
///        so a lock opened on one chain/deployment is meaningless on another;
///        `sessionId` binds it to one DOM settlement session.
///      * anti-collision  - `abi.encode` (never `abi.encodePacked`) is used, so
///        every field occupies its own 32-byte word and no field-boundary
///        ambiguity between two different term sets is possible.
library LockBinding {
    /// @dev Domain separator for the binding hash.
    bytes32 internal constant BINDING_DOMAIN = keccak256("DOM-Interop/ConditionLockV2/binding");

    /// @dev Domain separator for the lock-id hash.
    bytes32 internal constant LOCKID_DOMAIN = keccak256("DOM-Interop/ConditionLockV2/lockId");

    /// @dev Version of the encoding above. Bumped only on a breaking layout change.
    uint16 internal constant BINDING_VERSION = 2;

    /// @dev Order of the secp256k1 group.
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @dev X coordinate of the secp256k1 generator G.
    uint256 internal constant SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;

    /// @dev G has an EVEN y coordinate, therefore recovery id 0 (v = 27)
    ///      reconstructs R = G from r = Gx.
    uint8 internal constant V_FOR_G = 27;

    /// @notice `t` is outside the canonical scalar range `0 < t < n`.
    error NonCanonicalScalar();

    /// @notice The direction byte is neither 0 (DOM -> EVM) nor 1 (EVM -> DOM).
    error BadDirection();

    /// @notice Canonical binding hash of `terms` for a given chain and lock contract.
    /// @dev Byte-identical to the Rust `binding()` in the EVM adapter crate.
    function deriveBinding(LockTerms memory terms, uint256 chainId, address lockContract)
        internal
        pure
        returns (bytes32)
    {
        // Every field is a static value type, so `abi.encode` emits exactly one
        // 32-byte word per field and concatenating three groups is byte-identical
        // to encoding all fourteen fields in a single call. The split exists
        // only because a single fourteen-argument `abi.encode` exhausts the
        // legacy code generator's stack; `Binding.t.sol` pins the equivalence.
        return keccak256(
            bytes.concat(
                abi.encode(BINDING_DOMAIN, BINDING_VERSION, chainId, lockContract),
                abi.encode(terms.domChainId, terms.direction, terms.sessionId, terms.termsHash),
                abi.encode(
                    terms.participantsHash,
                    terms.asset,
                    terms.amount,
                    terms.beneficiary,
                    terms.adaptorAddress,
                    terms.deadline
                )
            )
        );
    }

    /// @notice Canonical lock id for a binding funded by `funder`.
    /// @dev `funder` is always `msg.sender` at `open`; it is never caller-chosen.
    function deriveLockId(bytes32 binding, address funder) internal pure returns (bytes32) {
        return keccak256(abi.encode(LOCKID_DOMAIN, BINDING_VERSION, binding, funder));
    }

    /// @notice Returns `address(t*G)` for a canonical secp256k1 scalar `t`.
    /// @dev `ecrecover(h, v, r, s)` returns `address(r^-1 * (s*R - h*G))`.
    ///      With `h = 0`, `r = Gx` and `v = 27` (Gy is even) we get `R = G`, so
    ///      the result is `address(Gx^-1 * s * G)`. Feeding `s = t*Gx mod n`
    ///      yields `address(t*G)` for roughly 3k gas instead of a full
    ///      scalar multiplication.
    ///
    ///      This is EVM-side secp256k1 usage for address derivation only. It is
    ///      not a re-implementation of any DOM primitive, challenge or verifier
    ///      (invariant I15): no DOM signature is produced or checked here.
    ///
    ///      Reverts on `t == 0` and `t >= n`, so the caller never has to reason
    ///      about the degenerate `ecrecover` inputs. For every remaining `t` the
    ///      precompile succeeds, therefore a zero return value is unreachable
    ///      here; callers still reject it defensively.
    function addressOfScalarTimesG(uint256 t) internal pure returns (address) {
        if (t == 0 || t >= SECP256K1_N) revert NonCanonicalScalar();
        return ecrecover(bytes32(0), V_FOR_G, bytes32(SECP256K1_GX), bytes32(mulmod(t, SECP256K1_GX, SECP256K1_N)));
    }

    /// @notice Fail-closed validation of the direction byte.
    function requireCanonicalDirection(uint8 direction) internal pure {
        if (direction > 1) revert BadDirection();
    }
}
