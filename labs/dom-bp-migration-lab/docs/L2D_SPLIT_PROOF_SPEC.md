# L2-D Split Proof Recovery Candidate

Author: Soren Planck
Email: sorenplanck@tutamail.com
Status: Laboratory / Not Production

## Scope

This document specifies a laboratory-only versioned envelope containing two
independent classic Grin single-commit Bulletproofs. It does not authorize a
production migration, consensus change, backend change, wire format, wallet
change, or node change.

## Equations and anti-inflation argument

Let `M = 2^52 - 1`, with DOM generator `H` and secp256k1 base `G`:

```
C0 = vH + rG
C1 = M H - C0 = (M-v)H + (-r)G
P0 = BP64(C0, v, r)
P1 = BP64(C1, M-v, -r)
```

The candidate accepts only if the unchanged classic single-commit verifier
accepts both `P0` under `C0` and `P1` under a complement reconstructed from
`C0`. A prover cannot provide a separate complement commitment. Both proofs
assert non-negative 64-bit values, so `v >= 0` and `M-v >= 0`; therefore
`0 <= v <= M`. This is the same acceptance relation frozen by L0.

## Fixed laboratory envelope

```
byte 0: version = 1
bytes 1..675: P0, a 675-byte classic single-commit 64-bit proof
bytes 676..1350: P1, a 675-byte classic single-commit 64-bit proof
```

The exact envelope length is 1351 bytes. Parsing rejects every other length,
unknown version, missing proof, truncation, extension, and trailing byte. This
is not a production wire format.

## Backend contract

The live backend declares `secp256k1_bulletproof_rangeproof_prove` in
`include/secp256k1_bulletproofs.h:161-182`, verification in `:58-88`, and the
single-commit rewind API in `:106-135`. The message has exactly 20 bytes
(`:120`, `:159`). For a single 64-bit commitment the backend yields 675 bytes;
the formula is in `include/secp256k1_bulletproofs.h:19` and L0 confirms it by
execution.

The C prover derives `(alpha,rho)` from `nonce` and `(tau1,tau2)` from
`private_nonce` at `rangeproof_impl.h:512-513`. It stores value/message in
`alpha` only for `n_commits==1` at `:526-540`. Rewind derives all four scalars
from its one supplied nonce at `:749-750` and derives the blind from `taux` at
`:835-846`. Therefore P0 supplies the exact same nonce to both prove arguments.
The nonce/private-nonce mismatch regression confirms that a header extraction
then produces a blinding that fails recomputation against C0.

The C rewind routine reads the header but does not perform full inner-product
verification (`rangeproof_impl.h:724-848`). Recovery must always verify P0 and
P1 before rewind. A wrong nonce returns the backend failure result and the
laboratory API returns no output.

## Prover and nonce domains

The laboratory prover rejects `v > M`, computes the complement witness, uses
the recovery nonce for both P0 backend nonce inputs, and embeds the exact
20-byte metadata in P0. P1 uses `SHA-256("DOM:L2D:split-proof:p1-nonce:v1" ||
recovery_nonce)` for both of its backend nonce inputs. No nonce, blinding,
proof plaintext, or recovered tuple is logged.

## Metadata

The experimental 20-byte layout is:

```
0: output version = 1
1: network identifier = 42
2..5: account, u32 big-endian
6: branch, restricted to 0 or 1
7..10: index, u32 big-endian
11..19: first nine bytes of SHA-256("DOM:L2D:metadata:v1" || bytes[0..11])
```

Decode rejects an unsupported version, network, branch, or digest mismatch.
This encoding is laboratory-only and is not approved production metadata.

## Verification and recovery

Verification parses the fixed envelope, validates SEC1 C0, derives C1 as
`M*H-C0`, and runs the unchanged backend verifier on P0/C0 and P1/C1. It never
rewinds and never consumes metadata.

Recovery parses, derives C1, fully verifies both proofs, then rewinds P0. It
rejects on wrong nonce, malformed proof, invalid metadata, `v > M`, or any
failed recomputation. It recomputes C0 from `(v,r)`, recomputes C1 from
`(M-v,-r)`, and returns only after both equalities hold.

## Malformed inputs and zeroization

Envelope parsing and SEC1 conversion fail closed. Mutation tests cover P0/P1
headers and inner-product regions, proof swaps, duplicates, wrong commitments,
truncation, extension, all-zero proofs, and random-length-equivalent proof
bytes. Temporary raw proof and recovered blinding buffers are zeroized in the
laboratory adapter. A production design must retain this property for all
nonce, scalar, and recovery buffers.

## Comparison and risks

L0 uses one 739-byte aggregated proof and has the same ceiling relation. L1-B
confirmed that the aggregated blind term `z^2(1-z)r` can erase r when `z=1`.
This split construction avoids aggregation for P0 and uses the existing
single-commit rewind contract. The cost is a 1351-byte envelope, two proofs,
and versioned migration work. Production migration remains unauthorized.
