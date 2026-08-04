# ADR-0018 — Canonical hash backend, purpose registry, and KDF stop

Status: **ACCEPTED** for the hash backend and `PurposeV1` registry. **BLOCKED**
for `SessionContextV1`, secret two-nonce derivation, and dependent signing
operations.

## Context

The Phase 1 completion mission requires one canonical DOM tagged-hash backend,
the exact Master Specification purpose registry, and an exact secret two-nonce
KDF. The KDF context includes `DirectionV1` and `PhaseV1`; their exact byte
assignments must exist before context bytes or KDF outputs can be implemented.

## Evidence

- **MISSION DECISION:** native BLAKE2b-256 through the authoritative DOM
  backend; `Refund=0x01`, `ClaimAdaptor=0x02`, `Funding=0x03`, and
  `Sponsor=0x04`; unknown bytes fail closed.
- **NORMATIVE DOCUMENT:** Master Specification Appendix E.6 assigns those four
  purpose bytes.
- **AUTHORITATIVE DOM CODE:**
  `crates/dom-crypto/src/hash.rs::blake2b_256_tagged` at DOM baseline
  `769822562565f18ef55423dc992e7aa661206b4a`.
- **FROZEN FIXTURE OR TEST:**
  `test-vectors/scriptless/hash-domains/DOM_G1A_BACKEND_FREEZE_V1.txt` and
  `crates/dom-adaptor/tests/preimplementation_freeze_probe.rs` exercise the
  real backend against independently computed Python `hashlib.blake2b`
  digests.
- **STAGE 0 FINDING:** no authoritative V2 normative block assigning exact
  bytes to both `DirectionV1` and `PhaseV1` is present in the three verified
  normative documents or the accepted repository ADRs.

## Decision

### Tagged hash

Every Scriptless `H_tag(tag, data)` delegates to
`dom_crypto::blake2b_256_tagged(tag, data)`. The backend is
`blake2::Blake2b<U32>`, which produces a native 32-byte BLAKE2b digest. It is
unkeyed and uses no configured salt or personalization. Its exact input is:

```text
u16_le(byte_length(tag)) || UTF-8 bytes(tag) || data
```

Scriptless tags are closed ASCII strings, so their UTF-8 bytes are identical
to their ASCII bytes. The function rejects no data length. It panics if the
tag length cannot fit in `u16`; closed Scriptless tags are statically far below
that bound. The result is `Hash256` containing the 32 digest bytes without
truncating a 64-byte digest. BLAKE2s, BLAKE2b-512 truncation, SHA-256, BIP340
duplicated-tag framing, keyed mode, salt, and personalization are not this
backend.

`dom-adaptor` must not instantiate BLAKE2 directly.

### Purpose registry

`PurposeV1` is a closed `repr(u8)` enum:

| Byte | Variant | Codec status | Strict Phase 1 signing policy |
|---:|---|---|---|
| `0x01` | `Refund` | accepted | accepted |
| `0x02` | `ClaimAdaptor` | accepted | accepted |
| `0x03` | `Funding` | accepted | accepted |
| `0x04` | `Sponsor` | accepted | rejected until an authorized Sponsor flow exists |

Every other byte is rejected. The exact name is `ClaimAdaptor`, not `Claim`.
The enum has no fallback and no `#[non_exhaustive]`. A future incompatible
registry requires a new explicitly versioned type.

Earlier Phase 1 material assigning `Funding=0x01`, or treating `0x04` as
unknown, is erroneous and is superseded by the Master Specification table and
this ADR.

### KDF stop

The three mission-provided secret nonce tags are reserved exactly as follows,
but they are **not registered for production use and are not implemented**
until the complete canonical context is byte-frozen:

```text
DOM:scriptless-secret-nonce-aux:v1
DOM:scriptless-secret-nonce-seed:v1
DOM:scriptless-secret-nonce-wide:v1
```

No competing V1 tag was found in the repository. Nevertheless, the absence of
explicit `DirectionV1` and `PhaseV1` byte assignments prevents construction of
`canonical_context_v1`, so it also prevents the complete KDF, nonce pair,
partial-signing workflow, and dependent vectors. Enum declaration order or
Rust defaults must not fill this gap.

The narrow `dom-crypto::scalar_from_wide_be(&[u8; 64])` arithmetic boundary may
be implemented independently because its input and big-endian reduction rule
are fully specified and it does not define context bytes or derive a nonce.

## Alternatives considered

- Inferring direction and phase bytes from names, declaration order, or an
  implementation plan: rejected because none is normative.
- Implementing the KDF over a partial context: rejected because it would freeze
  incompatible output bytes.
- Treating Sponsor as unknown: rejected because it violates Appendix E.6.
- Allowing Sponsor in strict Phase 1 signing because the codec recognizes it:
  rejected because codec recognition is not flow authorization.
- Instantiating BLAKE2 in `dom-adaptor`: rejected as a parallel backend.

## Consequences

Hash framing and purpose parsing can be corrected and tested now. Sponsor is
round-trippable without becoming executable. Wide scalar reduction can be
added to the authoritative arithmetic owner. G1a remains not approved and the
secret two-nonce workflow remains unavailable.

## Compatibility

This decision does not alter consensus, existing wire formats, kernel
serialization, persisted blocks, genesis, network magic, PoW, or the real DOM
signature verifier. The corrected purpose registry is an off-chain Scriptless
V1 codec that has not been activated in production.

## Risks

Downstream code could confuse codec acceptance with Sponsor authorization.
Every strict cryptographic entry point must therefore reject Sponsor before
hashing or scalar arithmetic. The unresolved direction/phase registry remains
a normative blocker and must stay visible.

