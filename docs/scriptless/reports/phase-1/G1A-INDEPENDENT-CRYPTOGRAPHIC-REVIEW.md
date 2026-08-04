# G1a independent cryptographic review

Date: 2026-08-04

Status: **REVIEW COMPLETE — G1a NOT APPROVED**

Independent evidence commit:
`3486a863ba922e2b7a4fc52e5ded988c6d32de87`

First reviewed production commit:
`0fbd5ada658dc608703c6c9592839eefb7722cf7`

Final reviewed production commit:
`f821937a8ff1712d5f9bafd58f152b82073538f2`

## Review boundary

The independent vectors were committed before this reviewer inspected any G1a
production source, report, commit, or output. Production inspection began only
after the coordinator accepted the independence barrier and authorized the
exact commit above. This review does not edit G1a production code.

The review covers:

- exact normative and independent-vector byte comparison;
- execution through the real DOM verifier;
- constant-time secret arithmetic and secret-dependent control flow;
- compiler-visible zeroization and drop behavior;
- secret type traits and public API exposure;
- nonce lifetime and double-use prevention;
- bounded parsing and panic behavior;
- dependency ownership, including direct and transitive `k256` use;
- unsafe code and log/error redaction.

## Historical first byte divergence

The external comparison harness stopped at the first mismatch, as required.
The signed NAR-002 §8.2 transcript update uses the exact tag
`DOM:scriptless-transcript:v1`. Production commit `0fbd5ada...` used
`DOM:scriptless-transcript-update:v1` in
`crates/dom-adaptor/src/session.rs`.

For the fixed comparison body
`11*32 || 22*32 || 01 || 0001`, the exact results were:

```text
expected=5930fbb3ee378c7db46c863d72adb5c57518dda3f6841d0cc9995a7ddbdb9b8d
production=182758d3006f363eb05f5bb0f8e67d12aa211de0e61ad2e5dd5141bbc5cf57be
exit_code=2
```

No later vector was compared against that commit after this mismatch. The
coordinator requested an explicit correction commit. The independent vectors
were not changed or reinterpreted.

Production corrected the tag in commit `1bb46ce`. The unchanged final harness
run against `f821937a...` then matched all 311 named intermediate values and all
three final signatures passed the real DOM verifier. See
`G1A-PRODUCTION-COMPARISON-EVIDENCE.md`.

## Final adjudication of findings

| ID | Final status | Evidence and residual boundary |
|---|---|---|
| IR-01 | Resolved | The exact `DOM:scriptless-transcript:v1` tag matches the independent digest and all final vectors. |
| IR-02 | Resolved in evidence path; production pending integration | The nonce pair is opaque and partial signing consumes it. The complete path is absent from default production resolution, so no default safe double-sign API remains. G1b integration must preserve consuming ownership. |
| IR-03 | Resolved | Default production cannot supply deterministic auxiliary bytes. OS randomness is owned internally; deterministic input exists only under the explicit non-default test helper. |
| IR-04 | Fail-closed quarantine; integration blocker open | Permit parsing and nonce capabilities are crate-sealed, and the raw `dom-crypto` nonce path is absent from default production resolution. Durable G1b issuance has not yet replaced the quarantine, so this is not a completed production lifecycle. |
| IR-05 | Fail-closed quarantine; integration blocker open | The evidence path enforces separate commitment, reveal, and partial permit stages, one-shot reveal, and consuming partial signing. These capabilities are unavailable in default production pending integrated G1b authority. |
| IR-06 | Source-level resolution complete; runtime tooling remains separate evidence | Nonce, share, KDF, adaptation, extraction, partial, and aggregate accumulator scalar temporaries use `Zeroizing` or explicit zeroization. The constant-time wide reduction remains inside authoritative `dom-crypto`. Sanitizer/compiler-output claims are not made by this source review. |
| IR-07 | Closed as non-secret public-artifact access, with hardening recommendation | `PartialSignatureV1` itself is non-Clone/non-Debug, while `partial()` exposes the already public irreversible scalar after a message exists. This does not expose a nonce or enable recomputation/reuse. Restricting the accessor to crate scope and aggregating internally would better preserve the wrapper invariant. |
| IR-08 | Resolved | Participant construction is fallible and rejects an all-zero derived participant ID before returning the value. |
| IR-09 | Resolved at contract boundary | Session generation loops with fresh OS randomness on zero/collision and returns only after `SessionIdRegistryV1` durably accepts the ID. The registry contract permanently owns uniqueness; its persistent implementation belongs to G1b. |

## Positive observations against `0fbd5ada...`

- `dom-adaptor` had no direct `k256` dependency. Its transitive `k256` use was
  owned by authoritative `dom-crypto`.
- `dom-adaptor` forbade unsafe code and no unsafe block appeared in the reviewed
  Scriptless arithmetic module.
- Secret nonce-pair, authorized nonce-pair, adaptor-secret, adaptor
  pre-signature, and exposure-permit wrappers did not derive generic
  serialization.
- Context and fixed-width parsers bounded lengths before allocation or fixed
  slicing; participant count was bounded to 2 through 16.
- Closed Purpose, Direction, Phase, ContractKind, and ExposureKind codecs
  rejected unknown discriminants.
- No production logging call was present in the reviewed `dom-adaptor` or
  `dom-crypto::scriptless` modules.
- The committed fuzz targets reached the canonical context, closed registries,
  SEC1/scalar parsers, commitment/reveal/partial payloads, both pre-signature
  forms, and exposure permit.

These positive observations do not close the durable integration gate.

## Constant-time and zeroization review

The final source review found no secret-dependent branch in the nonce scalar
arithmetic. Zero tests are constant-time choices converted only to decide
whether a complete unexported pair must be discarded. Wide reduction delegates
to `k256`'s constant-time `Reduce<U512>` inside `dom-crypto`; `dom-adaptor` has
no direct `k256` dependency.

RAII guards cover auxiliary randomness, masks, masked shares, seed inputs,
expansion digests, wide values, secret scalar conversions, nonce scalars,
signing shares, produced partial scalars, adaptor scalars, extracted scalars,
and the aggregate partial accumulator. Opaque secret scalar and nonce types do
not implement cloning, copying, debug/display, equality/ordering, or generic
serialization. No Scriptless production logging call was found.

This is a source-level audit. It does not claim Miri, Valgrind, Windows, macOS,
or compiler-assembly execution. The repository's separately recorded sanitizer
and fuzz evidence remains independently required by the gate.

## Dependency and API review

- `dom-adaptor` has no direct `k256` dependency. Transitive `k256` belongs to
  authoritative `dom-crypto`.
- `dom-adaptor` forbids unsafe code. No unsafe code exists in the reviewed
  Scriptless arithmetic module.
- Default production feature resolution does not enable `test-helpers`.
- A negative external compile probe proved that the raw derivation and nonce
  pair types cannot be imported from default `dom-crypto`, and that the
  `dom-adaptor` secret pair is not publicly exported.
- The helper path is explicitly non-default evidence only. It must never be a
  release feature or a substitute for integrated durable authorization.

## Final verdict

The cryptographic construction at the frozen inputs matches the independent
implementation byte for byte, and every generated final signature passed the
real DOM verifier. No cryptographic-byte divergence remains at the reviewed
HEAD.

G1a is nevertheless **NOT APPROVED**. The default production build deliberately
quarantines the nonce generation/exposure/signing lifecycle to remove a safe
G1b bypass. Production completion requires a deliberate integrated authority
that provides the durable permits without restoring any raw safe API. G1b and
platform evidence remain separate mandatory gates.
