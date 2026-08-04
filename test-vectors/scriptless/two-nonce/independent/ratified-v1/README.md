# Independent ratified Phase 1 V1 evidence

This directory contains the pre-comparison independent reference implementations
and frozen outputs for the ratified DOM Scriptless Contracts nonce KDF and
complete two-party signing construction.

## Independence boundary

The generator was written on branch
`test/phase-1-independent-vectors-ratified` from coordinator commit
`6062f9adb6ddd1812c41b2fb66b9ec69a249f324`. Before this evidence commit,
the author did not inspect the G1a worktree, branch, source code, commits,
reports, or outputs. The only construction inputs were:

- the ratified NAR-001 exact bytes;
- the signed input-only KAT V2 exact bytes;
- `crates/dom-crypto/src/hash.rs::blake2b_256_tagged` for the authoritative
  public hash framing;
- the secp256k1 public curve parameters.

The complete two-party generator additionally consumes only:

- the ratified NAR-002 exact bytes;
- the separately signed input-only two-party fixture exact bytes;
- the already independent KDF implementation in this directory.

NAR-002 supplies the Refund and Funding cases and the participant identity
assignments. The signed input-only fixture supplies the ClaimAdaptor inputs.
Neither source contains expected cryptographic outputs.

The implementation uses CPython's standard-library `hashlib.blake2b` and a
small, bounded pure-Python secp256k1 arithmetic implementation. It imports no
DOM Rust crate, no production Scriptless module, and no third-party elliptic
curve package.

## Generate and verify

From the repository root:

```text
python3 test-vectors/scriptless/two-nonce/independent/ratified-v1/generate_reference.py
python3 test-vectors/scriptless/two-nonce/independent/ratified-v1/generate_reference.py --check
python3 test-vectors/scriptless/two-nonce/independent/ratified-v1/generate_full_adaptor_reference.py
python3 test-vectors/scriptless/two-nonce/independent/ratified-v1/generate_full_adaptor_reference.py --check
sha256sum --check test-vectors/scriptless/two-nonce/independent/ratified-v1/MANIFEST.sha256
```

The generator validates every signed fixture input before hashing. It emits all
required intermediate bytes for the 3 base cases and 13 accepted mutations,
then proves fail-closed rejection of all 20 negative mutations using explicit
error classifications.

## Complete output scope

`reference_outputs_v1.json` independently freezes the ratified context, KDF,
wide reduction, and public nonce-pair outputs from KAT V2.

`full_adaptor_reference_outputs_v1.json` independently freezes complete
two-party Refund, ClaimAdaptor, and Funding cases. It records every canonical
context, tagged-hash input, KDF intermediate, public nonce, commitment, binding
coefficient, effective and aggregate nonce, DOM challenge, participant partial,
aggregate pre-signature, adaptation, extraction, and final 65-byte signature.
It also records 50 fail-closed negative cases. The embedded pure-Python verifier
checks the unchanged DOM Schnorr equation using the exact ratified challenge
framing.

Execution through the real DOM Rust verifier is deliberately deferred until
after the pre-comparison evidence commit, as required by NAR-002 §11.7. This
directory does not claim that deferred evidence before it is actually run.

No comparison with production G1a was performed before the evidence commit.
