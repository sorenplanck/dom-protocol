# ADR-0018 — Ratified DOM Core secret-operation boundary

Status: **ACCEPTED** for the narrow DOM Core implementation boundary. This
decision does not approve G1a, G1b, Phase 1, publication, or production
activation.

## Context

NAR-DC-P1-001 §4.2 requires every Scriptless-specific secret nonce operation
to be private to `dom-adaptor`. At the same time, `dom-adaptor` must not depend
directly on `k256` or duplicate DOM's canonical scalar and point arithmetic.
The prior candidate exposed protocol-named nonce derivation, record conversion,
and raw bound-partial helpers from `dom-crypto`; a safe downstream crate could
therefore bypass the vault lifecycle.

## Evidence

- **RATIFIED NORMATIVE RECORD:** `NAR-DC-P1-001-omnibus-gap-closure.en.md`
  §4 fixes the safe-Rust ownership and test boundary.
- **AUTHORITATIVE DOM CODE:** `crates/dom-crypto/src/scriptless.rs` owns the
  constant-time arithmetic boundary; `crates/dom-crypto/src/hash.rs` owns
  `blake2b_256_tagged`; `crates/dom-crypto/src/schnorr.rs` owns canonical
  scalar parsing.
- **ENGINEERING ADR:** ADR-0017 prohibits generic arithmetic escape hatches and
  ADR-0014 requires final verification by the unchanged DOM verifier.
- **FROZEN EVIDENCE:** SCAD0 and the independent two-nonce vectors fix the
  existing adaptor convention and nonce KDF outputs.

## Decision

`dom-adaptor` privately owns all Scriptless-specific secret workflow:

- the three ratified KDF tags, framing, masking, seed, wide expansion, retry,
  and pair construction;
- raw public-nonce derivation from a live pair;
- the bound-partial equation `k1 + b*k2 + e*x`;
- conversion of a live pair into the exact zeroizing record transfer; and
- deterministic auxiliary-randomness injection under `cfg(test)` only.

None of those operations or owning types is exported by `dom-adaptor` or
`dom-crypto`. The production route is the statically typed
`VaultBackedSignerV1<V: NonceVaultV1>` state machine. The default build has no
Cargo feature that enables deterministic secret helpers or a raw nonce route.

`dom-crypto` exposes only generic authoritative operations needed to keep
curve arithmetic out of `dom-adaptor`:

- `scalar_from_wide_be(&[u8; 64]) -> Option<Zeroizing<[u8; 32]>>` performs the
  constant-time big-endian reduction and rejects zero;
- `secret_scalar_public_key` validates one canonical nonzero scalar and
  derives its canonical compressed public point;
- `secret_scalar_mul_add_assign` validates its fixed inputs and replaces a
  caller-owned zeroizing accumulator with `a + b*c`;
- `verify_scalar_response` verifies the generic public Schnorr relation
  `zG = A + cX`; and
- `SecretScalar` remains the opaque, non-cloneable generic adaptor-secret type.

These functions contain no Scriptless KDF tag, context framing, nonce-pair
type, record codec, partial artifact, permit, exposure operation, storage
policy, or deterministic randomness. They neither return a signing-share byte
view nor provide a Scriptless raw-signing function.

`SigningShareV1` is owned by `dom-adaptor`, validates canonical input, stores no
publicly readable secret bytes, implements no clone/debug/display/serde
surface, and zeroizes on drop. Every fallible constructor or importer places
incoming secret arrays under an RAII `Zeroizing` guard before validation.

## Alternatives considered

- Public protocol-named helpers in `dom-crypto`: rejected because they form a
  vault bypass even when documented as low level.
- A Cargo feature for deterministic nonce input: rejected because dependency
  features unify and are not an access-control boundary.
- Direct `k256` use in `dom-adaptor`: rejected because it duplicates the
  authoritative DOM boundary.
- A public generic scalar export or arbitrary linear-combination API: rejected
  because it would create a reusable secret extraction or signing oracle.
- Moving generic arithmetic into Wallet or storage code: rejected because it
  reverses ownership and dependency direction.

## Consequences

The public safe API cannot import a Scriptless secret pair, derive or reveal a
raw pair, convert live nonce scalars to record bytes, or invoke raw partial
signing. Production secret ownership advances only through the vault-backed
type state. New secret equations require a separately reviewed ADR rather than
widening the generic arithmetic boundary.

## Compatibility

This decision affects only new private Scriptless development APIs. It does
not change consensus, L1 wire encoding, existing transaction or kernel
serialization, persisted blocks, genesis, chain identifiers, network magic,
PoW, or the real DOM signature verifier.

## Risks

Safe-Rust API closure does not prove filesystem durability, witness behavior,
compiler-level zeroization, platform conformance, fuzz completeness, or
independent cryptographic agreement. Those remain separate gate evidence and
must not be inferred from this ADR.
