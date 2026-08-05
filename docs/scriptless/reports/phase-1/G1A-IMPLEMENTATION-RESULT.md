# G1a implementation result

Status: **PARTIAL — G1a NOT APPROVED**

## Scope and baseline

- Branch: `feat/phase-1-g1a-implementation`
- Starting commit: `a37f0bbeeb7c0ee5579154ae64476e8374d1dabb`
- DOM cryptographic baseline: `769822562565f18ef55423dc992e7aa661206b4a`
- Worktree: `/home/leonardov/dom-scriptless-dev/worktrees/g1a`

This branch implements only evidence-backed G1a components. It does not alter
consensus, wire formats, persisted blocks, genesis, network magic, PoW, or
existing DOM serialization. It does not implement G1b, a nonce vault, session
state machine, or remote witness.

## Implemented production components

### Authoritative DOM arithmetic extension

`crates/dom-crypto/src/scriptless.rs` adds the narrow boundary accepted by
ADR-0017:

- `ScriptlessSecretScalar`: canonical big-endian `[1,n-1]`, zeroized on drop,
  no `Clone`, `Debug`, or generic serialization;
- `scriptless_verify_pre_signature`: verifies
  `s_hat*G == R_hat + e*X - T` with `schnorr_challenge`;
- `scriptless_adapt_signature`: computes the standard DOM scalar `s=s_hat+t`;
- `scriptless_extract_adaptor_secret`: computes `t=s-s_hat`, enforces identical
  nonce points, and checks `t*G==T` before returning a secret;
- `scriptless_bind_public_nonces`: computes `R1+b*R2` and rejects infinity;
- `scriptless_verify_bound_partial`: verifies `s_i*G==R_i+e*X_i`; and
- `scriptless_verify_final_signature`: delegates to the unchanged DOM verifier.

`k256` remains private to `dom-crypto`. `dom-adaptor` has no direct production
dependency on it and does not duplicate DOM hashing, challenges, point parsing,
or signature verification.

### Canonical `dom-adaptor` boundary

- `PurposeV1` accepts only Refund `0x01`, Claim Adaptor `0x02`, and Funding
  `0x03`; Sponsor and all other bytes are rejected.
- `NonceCommitmentV1` is exactly 35 bytes.
- `NonceRevealV1` is exactly 69 bytes and parses points through `PublicKey`.
- `PartialSignatureV1` is exactly 67 bytes, has no `Clone`/`Debug`, binds purpose
  and template before partial verification, and parses its scalar through
  `PartialSig`.
- `AdaptorPreSignatureV1` is exactly 162 bytes, has no `Clone`/`Debug`, verifies
  before adaptation, verifies the adapted final signature, and validates
  extraction against `T`.
- Commitment and binding transcripts use only `blake2b_256_tagged` with the
  frozen tags and conditional adaptor-point grammar.
- Collective binding requires a nonempty, strictly increasing participant
  index order and uses direct nonzero big-endian digest mapping without
  reduction or retry.

## Executed evidence

- All eight frozen SCAD0 records verify their pre-signature equation.
- Adaptation reproduces every frozen 65-byte final signature exactly.
- Extraction reproduces a secret whose public point equals frozen `T`.
- Every adapted kernel passes `dom_consensus::validate_kernel_signatures`.
- The independently frozen binding hash
  `bf9353815692ec8c521504bf0fa8d34c75ffc2fb609ee961e19414d92025c054`
  is reproduced exactly.
- Exact-length parser failures, malformed point/scalar paths, wrong secrets,
  mutated signatures, purpose closure, participant ordering, purpose grammar,
  and critical commitment fields have negative coverage.
- Bounded parser mutation probes use `catch_unwind` and complete without panic.

The SCAD0 corpus and implementation-generated tests are not labeled as an
independent implementation of the two-nonce scheme.

## Deliberately unimplemented or blocked

1. **Secret two-nonce KDF:** no byte-exact ratified derivation exists. No nonce
   generation or caller-provided production signing API was added.
2. **Independent two-nonce and aggregation vectors:** no independent reviewed
   implementation has supplied them.
3. **Complete cumulative session transcript:** initial hash and Phase 3-SM
   direction/phase discriminants remain blocked.
4. **Two-nonce partial creation and aggregation workflow:** public binding and
   verification exist, but secret signing cannot proceed without the KDF and
   G1b lifecycle.
5. **Persistent fuzz campaign:** bounded no-panic tests are not a substitute for
   completed fuzzing.
6. **Independent audit:** constant-time behavior, zeroization on every compiler
   path, and absence of parallel implementations still require dedicated
   review.
7. **Independent adaptor vectors:** SCAD0 is strong executable evidence but has
   correlated laboratory provenance.

## Gate result

G1a remains **NOT APPROVED**. The implementation is useful for continued
review and independent vector production, but it is not authorized for real
funds or production. G1b remains independently required.

## Validation commands

The following commands were executed successfully in this worktree:

```text
cargo metadata --no-deps --format-version 1 --locked          PASS
cargo fmt --all --check                                      PASS
cargo check -p dom-adaptor --locked                          PASS
cargo test -p dom-adaptor --locked                           PASS (12 tests)
cargo test -p dom-crypto --lib scriptless --locked           PASS (3 tests)
cargo test -p dom-consensus --test scad0_adaptor_fixtures \
  --locked                                                   PASS (1 test)
cargo clippy -p dom-adaptor --all-targets --locked -- \
  -D warnings                                                PASS
cargo clippy -p dom-crypto --lib --locked -- -D warnings     PASS
sha256sum --check test-vectors/scriptless/MANIFEST.sha256    PASS (2 files)
git diff --check                                             PASS
```

The repository-wide preflight and gate scripts intentionally reject this
independent worktree path because they are pinned to the coordinator working
tree. They were not weakened or modified here. The coordinator must run them
after reviewing the branch without treating that as integration authorization.

## Prohibited operations confirmation

No official repository was modified. No DL2P material was imported. No push,
merge, release, publication, or remote mutation was performed.
