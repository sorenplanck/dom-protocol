# Independent ratified KDF V1 evidence

This directory contains the pre-comparison independent reference implementation
and outputs for the ratified DOM Scriptless Contracts nonce KDF V1.

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

The implementation uses CPython's standard-library `hashlib.blake2b` and a
small, bounded pure-Python secp256k1 arithmetic implementation. It imports no
DOM Rust crate, no production Scriptless module, and no third-party elliptic
curve package.

## Generate and verify

From the repository root:

```text
python3 test-vectors/scriptless/two-nonce/independent/ratified-v1/generate_reference.py
python3 test-vectors/scriptless/two-nonce/independent/ratified-v1/generate_reference.py --check
sha256sum --check test-vectors/scriptless/two-nonce/independent/ratified-v1/MANIFEST.sha256
```

The generator validates every signed fixture input before hashing. It emits all
required intermediate bytes for the 3 base cases and 13 accepted mutations,
then proves fail-closed rejection of all 20 negative mutations using explicit
error classifications.

## Scope boundary

`reference_outputs_v1.json` independently freezes the ratified context, KDF,
wide reduction, and public nonce-pair outputs. It deliberately does not invent
a second participant's secret inputs. Therefore it does not claim a complete
two-party binding, partial-signature, aggregation, adaptation, or extraction
vector. Such a supplemental vector requires separately identified input bytes
and must remain distinct from outputs derived exclusively from the signed KAT.

No comparison with production G1a was performed before the evidence commit.
