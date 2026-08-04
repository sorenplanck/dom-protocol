# G1a production comparison evidence

Date: 2026-08-04

Status: **BYTE COMPARISON COMPLETE — G1a NOT APPROVED**

Independent evidence commit before comparison:
`3486a863ba922e2b7a4fc52e5ded988c6d32de87`

Independence-barrier report commit:
`f0a8be6efce885281fc2a4c4619698d2aa494f9f`

Final reviewed production code commit:
`f821937a8ff1712d5f9bafd58f152b82073538f2`

Final reviewed production tree:
`49c1d430e59c8caa5cdcc06b1726972dd1a95850`

## Frozen evidence

The independent output was not changed after production inspection began:

```text
full_adaptor_reference_outputs_v1.json
SHA-256 68f7d9e9b202b2c4380fe913f69ab15ed5205871cc82c84e3ee78eaaf5762206
```

The comparison harness is:

```text
compare_production.rs
SHA-256 4d4df3e5d47f53c4acf1ce1b2c9e16ddb0a57c6bb43c7612ff5440433a6d63f0
```

The updated local vector manifest SHA-256 is
`b408c4826bcda2d25a0d431ced0cf48619974071c9667c5b6ec3bef05c3c47f2`.

The harness was placed in an external throwaway Cargo binary. Its dependencies
pointed to an immutable local snapshot of the exact reviewed tree. It enabled
only the explicit non-default `dom-adaptor/fuzzing`,
`dom-adaptor/test-helpers`, and `dom-crypto/test-helpers` features required to
feed signed deterministic inputs into the quarantined evidence API. No local
path dependency was added to either production repository.

## Comparison command and result

With `PRODUCTION_SNAPSHOT` bound to the immutable tree above and
`EVIDENCE_ROOT` bound to this repository, the external harness was built and
run as follows:

```text
cargo fmt --all --check
cargo check --locked
cargo run --locked -- "$EVIDENCE_ROOT/test-vectors/scriptless/two-nonce/independent/ratified-v1/full_adaptor_reference_outputs_v1.json"
```

All commands exited zero. The final line was:

```text
COMPARISON_COMPLETE matched_fields=311
```

The 311 named comparisons covered:

- the corrected transcript-update domain;
- both participant identity hashes in every purpose case;
- canonical context parse and byte-exact re-encoding;
- every tagged-hash length, tag, input, and digest used by the KDF;
- masks, masked signing shares, seeds, expansion halves, wide inputs, and
  authoritative scalar reductions;
- both public nonces, commitments, and commitment/reveal payloads;
- binding preimages, digests, scalars, and effective participant nonces;
- aggregate nonces, aggregate signing keys, and adaptor aggregate nonces;
- DOM kernel challenge preimages, digests, and scalars;
- both participant partials, payloads, and verification equations;
- aggregate pre-signature scalars and canonical pre-signature bytes;
- ClaimAdaptor adaptation and extraction;
- every final 65-byte signature.

There was no divergence against the final reviewed code. The earlier
`0fbd5ada658dc608703c6c9592839eefb7722cf7` transcript-tag divergence remains
recorded in the independent review as historical corrective evidence; the
independent vectors were never modified to accommodate it.

## Real DOM verifier

The harness called `dom_crypto::scriptless_verify_final_signature`, which
delegates to the unchanged authoritative DOM Schnorr verifier. Results:

| Case | Purpose | Result |
|---|---|---|
| `V1-Refund` | `0x01` | pass |
| `V1-ClaimAdaptor` | `0x02` | pass |
| `V1-Funding` | `0x03` | pass |

The ClaimAdaptor pre-signature equation also passed, adaptation produced the
frozen final signature, and extraction produced the frozen adaptor point.

## Default production API quarantine

An external negative compile probe depended on `dom-adaptor` and `dom-crypto`
with default features only and attempted to import:

```text
dom_adaptor::SecretNoncePairV1
dom_crypto::ScriptlessNonceDerivationV1
dom_crypto::ScriptlessSecretNoncePairV1
```

`cargo check --offline` exited 101 with unresolved imports. Rust reported that
the two `dom-crypto` items were configured out behind `test-helpers`; the
`dom-adaptor` secret pair was not exported. This is the expected pass condition
for the negative compile probe. Default production resolution therefore has no
safe raw nonce derivation, public nonce export, or partial-signing bypass.

The quarantined helper path does not constitute a production G1a lifecycle.
The integrated G1b durable authorization authority must deliberately supply a
non-bypassable production boundary before the gate can close.

## Gate effect

- Independent implementation committed before comparison: **complete**.
- Every compared intermediate byte: **match**.
- Real DOM verifier for all three signing purposes: **pass**.
- Default raw nonce API bypass: **fail-closed quarantine verified**.
- Production durable nonce/permit lifecycle integration: **not implemented**.
- G1a approved: **no**.

The open lifecycle item is a code/integration blocker, not a cryptographic-byte
divergence. G1a remains correctly open until the integrated G1b authority
replaces the evidence-only quarantine without reopening a safe bypass.
