# SCAD0 Adaptor Fixture Provenance

`scad0_adaptor_vectors_v1.txt` is imported byte for byte from the pinned DOM
Protocol revision. It is **not** generated, regenerated, or derived here, and
no test in this repository may produce it. Regeneration would make the corpus
self-referential: a wrong verifier would then be checked against vectors that a
wrong verifier produced.

## Source

```text
repository: https://github.com/sorenplanck/dom-protocol
revision:   6f2b230ebbec390040dbf0bff110efaf4bb0f101
path:       crates/dom-consensus/tests/fixtures/scad0_adaptor_vectors_v1.txt
blob:       a7f409ae5e27f0f74b9622a104034a32288628e0
```

The revision is the immutable pin this workspace already builds against, so the
vectors and the verifier that consumes them come from the same reviewed tree.

## Imported artifact

| Artifact | SHA-256 |
|---|---|
| `crates/dom-scriptless-crypto/tests/fixtures/scad0_adaptor_vectors_v1.txt` | `4be1657e8101a036ae2b0ea8d409e284b3c8c7215ccb9d92dc7b29b9dc7dbe10` |

The imported file was compared byte for byte with
`git show 6f2b230ebbec390040dbf0bff110efaf4bb0f101:crates/dom-consensus/tests/fixtures/scad0_adaptor_vectors_v1.txt`
before this record was written. The comparison returned exit code `0`.

Reproduce with:

```sh
git -C <dom-protocol> show \
  6f2b230ebbec390040dbf0bff110efaf4bb0f101:crates/dom-consensus/tests/fixtures/scad0_adaptor_vectors_v1.txt \
  | cmp - crates/dom-scriptless-crypto/tests/fixtures/scad0_adaptor_vectors_v1.txt
```

## Content

Eight frozen vectors, `V01` through `V08`, one per line, five `|`-separated
fields:

```text
id | t | T | s_hat | kernel
```

- `t` — the adaptor secret scalar, 32 bytes. Public test material.
- `T` — the adaptor point, 33 bytes SEC1 compressed.
- `s_hat` — the pre-signature scalar, 32 bytes.
- `kernel` — the canonical 115-byte transaction kernel, whose excess is the
  aggregate signing key `X` and whose excess signature carries `R̂`.

The file's own header records the upstream origin report and extract digests:

```text
Origin report SHA-256: 037e21269c9929ab01ff50ea773fe3685de735fc0fe874b40fdcc12c1a2a1b17
Extract SHA-256:       e99ad8a32edc3db52941e6729c032893d2b864ab995821debf574468b7beaa4b
```

## Parity coverage, as measured

The SEC1 prefixes were decoded from the eight records rather than taken from any
description of them. `X` is the kernel excess and `R̂` is the `R` of the kernel
excess signature, both read with the canonical consensus codec.

| Vector | `T` | `X` | `R̂` |
|---|---|---|---|
| V01 | 02 | 02 | 02 |
| V02 | 02 | 03 | 03 |
| V03 | 03 | 02 | 02 |
| V04 | 03 | 03 | 03 |
| V05 | 02 | 02 | 02 |
| V06 | 02 | 03 | 03 |
| V07 | 03 | 02 | 02 |
| V08 | 03 | 03 | 03 |

Four distinct `(T, X, R̂)` triples appear, each twice. `X` and `R̂` carry the
same parity in every record, so the corpus contains **no** vector in which the
signing key and the aggregate nonce have differing parity. `T` does vary
independently of both.

This is what the corpus covers, recorded because it is less than a reader might
assume: eight records cannot realise sixteen combinations, and these eight
realise four. Anyone extending the negative tests should not treat this corpus
as exhaustive over parity.

The vectors are also frozen for the full `verify → adapt → verify → extract`
cycle upstream. This repository exercises only the `verify` step: adaptation and
extraction are outside the current scope, and no code here performs them.

## Session bindings

The vectors carry no Claim template hash and no transcript hash, because those
are DOM Contracts session bindings rather than adaptor-core values. The tests
derive them deterministically from each vector's identifier, injectively, so
that every vector belongs to a distinct session. They are test bindings and
carry no authority.

They are **not** part of the adaptor challenge. The pinned
`scriptless_verify_pre_signature` computes the challenge over `R̂`, `X`, the
chain identifier and the kernel message only; `AdaptorPreSignatureV1::verify`
compares the two hashes for equality and nothing more. A cryptographically
valid core `(T, R̂, ŝ)` can therefore be re-bound to any template and transcript
pair by rewriting bytes `0..32` and `130..162` and presenting the matching
request. `claim_adaptor_v1.rs` records that property in
`the_session_bindings_are_byte_equality_not_challenge_input`, so the limit is
stated by a test rather than left for a reader to discover.

The chain identifier and kernel message digest are the frozen constants the
upstream fixture consumer uses, so the challenge this repository verifies
against is the same one the corpus was frozen for.

## Guard

`scripts/check-claim-adaptor-provenance.sh` fails closed unless this record,
the fixture, its digest, the pinned revision, and the pinned verifier call path
all still agree. It never regenerates the fixture.
