# G1a finalization result

Status: **G1a NOT APPROVED**

## Executive result

This branch completed every safe G1a task that is independent of the missing
canonical context discriminants. It corrected the V1 purpose registry, froze
the authoritative DOM tagged-hash backend, added the authorized constant-time
wide-scalar reduction boundary, added a 10,000-case deterministic
adapt/extract property test, and added persistent parser fuzz targets.

G1a is not approved. Stage 0 found no authoritative V2 normative block with
explicit byte assignments for both `DirectionV1` and `PhaseV1`. That is a
mandatory stop condition for `SessionContextV1`, the secret two-nonce KDF,
secret nonce-pair creation, participant partial signing, and all dependent
vectors. No bytes were inferred or invented.

## Baseline and scope

- Worktree: `/home/leonardov/dom-scriptless-dev/worktrees/g1a`
- Branch: `feat/phase-1-g1a-implementation`
- Starting HEAD: `79e29eae0312add012773e17fbc49ab031ee7d1a`
- Starting tree: `3f74920a6006bedf447cb8ced36907c2b90110fa`
- Rust: `rustc 1.96.1 (31fca3adb 2026-06-26)`
- Cargo: `cargo 1.96.1 (356927216 2026-06-26)`
- Starting `Cargo.lock` SHA-256:
  `9a904a1540c6cdb92c154ecdb178ca222fa8ea031a91a29e87bc920ad4ccce35`

This work did not modify consensus, existing wire formats, kernel
serialization, persisted blocks, genesis, network magic, PoW, the real DOM
signature verifier, official repositories, the Wallet, or another worktree.

## Commits created

1. `cf28c30` — `docs(scriptless): freeze hash backend and purpose registry`
2. `456fe66` — `fix(scriptless): align PurposeV1 with canonical registry`
3. `66da6be` — `feat(scriptless): add authoritative wide scalar reduction`
4. `4546ff4` — `test(scriptless): add 10000-cycle adaptor property coverage`
5. `4789d13` — `test(scriptless): add persistent adaptor fuzz targets`

The report and gate-evidence update are committed separately after the
validation recorded below.

## Accepted inputs

### Authoritative tagged hash

ADR-0018 freezes the backend as
`crates/dom-crypto/src/hash.rs::blake2b_256_tagged`:

- `blake2::Blake2b<U32>` native 32-byte BLAKE2b output;
- unkeyed;
- no configured salt;
- no configured personalization;
- exact input `u16_le(byte_length(tag)) || tag_bytes || data`;
- closed Scriptless tags are ASCII, hence ASCII and UTF-8 bytes coincide;
- output is not BLAKE2s and is not a truncated BLAKE2b-512 digest; and
- `dom-adaptor` contains no direct BLAKE2 instantiation.

The existing independent Python/hashlib freeze vectors continued to pass
against the real DOM backend.

### PurposeV1

The exact closed `repr(u8)` registry is:

| Byte | Variant | Codec | Strict Phase 1 execution |
|---:|---|---|---|
| `0x01` | `Refund` | accepted | accepted |
| `0x02` | `ClaimAdaptor` | accepted | accepted |
| `0x03` | `Funding` | accepted | accepted |
| `0x04` | `Sponsor` | accepted | rejected |

Every other byte fails closed. Sponsor is recognized by canonical codecs but
`PurposeV1::require_strict_phase1` and strict cryptographic entry points reject
it. ADR-0012 now records the erratum for earlier material that assigned
`Funding=0x01`, used the name `Claim`, or treated `Sponsor=0x04` as unknown.

### DirectionV1 and PhaseV1

Both registries remain **BLOCKED**. No exact byte assignment was present in an
authoritative normative source. No Rust enums or context encoding were created.

### Wide scalar reduction

`dom_crypto::scalar_from_wide_be(input: &[u8; 64]) ->
Option<ScriptlessSecretScalar>`:

- accepts exactly 64 bytes;
- interprets them as a 512-bit big-endian integer;
- delegates to `k256::Scalar`'s constant-time `Reduce<U512>` implementation
  inside `dom-crypto`;
- rejects a zero residue;
- returns the existing opaque, zeroizing, non-Clone, non-Debug secret type;
- zeroizes the internal wide copy and reduced scalar on every local return
  path; and
- leaves the borrowed input under caller ownership for subsequent zeroization.

Tests cover zero, one, the group order, group order plus one, and a 512-bit
high-bit input. `dom-adaptor` has no direct `k256` dependency; its direct
normal dependencies are only `dom-core`, `dom-crypto`, and `thiserror`.

## Deliberately blocked construction

The mission-provided tags are recorded exactly in ADR-0018 but are not
registered for production use and are not called by production code:

```text
DOM:scriptless-secret-nonce-aux:v1
DOM:scriptless-secret-nonce-seed:v1
DOM:scriptless-secret-nonce-wide:v1
```

The repository contains no competing V1 strings. Nevertheless,
`canonical_context_v1` cannot be encoded without exact Direction and Phase
bytes. Consequently this branch does not implement:

- `SessionContextV1`;
- operating-system CSPRNG ownership for the nonce KDF;
- mask, seed, retry, or `W_1`/`W_2` expansion;
- `SecretNoncePair`;
- public nonce-pair derivation from secret nonces;
- secret participant partial signing;
- a one-shot vault permit;
- complete partial aggregation; or
- dependent KDF/two-nonce vectors.

## Executed tests

All commands below ran in this worktree after the changes.

| Command | Result | Evidence summary |
|---|---|---|
| `cargo metadata --no-deps --format-version 1 --locked` | PASS, exit 0 | workspace metadata resolved |
| `cargo fmt --all --check` | PASS, exit 0 | no formatting drift |
| `cargo check -p dom-adaptor --locked` | PASS, exit 0 | production crate compiled |
| `cargo test -p dom-adaptor --locked` | PASS, exit 0 | 13 integration tests; all eight SCAD0 cases included |
| `cargo test -p dom-crypto --lib scriptless --locked` | PASS, exit 0 | 5 tests; 10,000-case property included; 164.22 seconds test time |
| `cargo test -p dom-consensus --test scad0_adaptor_fixtures --locked` | PASS, exit 0 | permanent SCAD0 corpus passed unchanged |
| `cargo clippy -p dom-adaptor --all-targets --locked -- -D warnings` | PASS, exit 0 | no warnings |
| `cargo clippy -p dom-crypto --lib --locked -- -D warnings` | PASS, exit 0 | no warnings |
| `sha256sum --check test-vectors/scriptless/MANIFEST.sha256` | PASS, exit 0 | both vector files intact |
| `sha256sum --check docs/scriptless/source-guides/normative/MANIFEST.sha256` | PASS, exit 0 | all three normative copies intact |
| `git diff --check` | PASS, exit 0 | no whitespace errors |

The 10,000-case deterministic test executed
`extract(adapt(presign)) == t` through the authoritative arithmetic boundary.
Every generated final 65-byte signature passed the unchanged real DOM verifier,
and every extracted scalar satisfied `t*G == T`. This is
implementation-generated property evidence, not an independent vector set.

## Fuzz and sanitizer evidence

Persistent targets are committed in `crates/dom-adaptor/fuzz`.

| Target / command | Platform | Result |
|---|---|---|
| `cargo +nightly fuzz check` | Linux x86_64, nightly toolchain, ASan instrumentation | PASS, exit 0 |
| `cargo +nightly fuzz run canonical_messages -- -max_total_time=10 -print_final_stats=1` | Linux x86_64, ASan/libFuzzer | 1,258,812 executions in 11 seconds; 0 crashes; peak RSS 458 MiB |
| `cargo +nightly fuzz run adaptor_pre_signature -- -max_total_time=10 -print_final_stats=1` | Linux x86_64, ASan/libFuzzer | 1,027,102 executions in 11 seconds; 0 crashes; peak RSS 397 MiB |

The generated corpora are preserved locally under
`crates/dom-adaptor/fuzz/corpus`: 18 canonical-message files and 5
adaptor-pre-signature files. The root `.gitignore` intentionally ignores fuzz
corpora, so they are preserved locally but are not committed. No crash artifact
exists under `crates/dom-adaptor/fuzz/artifacts`.

The initial `cargo fuzz check` under the stable toolchain failed before target
execution because stable Rust rejects `-Zsanitizer=address`. The explicit
nightly invocation then compiled and executed both targets successfully. This
is real Linux ASan/libFuzzer evidence for the recorded short campaigns; it is
not a claim that another repository-approved sanitizer workflow, Miri,
Valgrind, Windows, or macOS ran.

## Gate state

### Implemented and executed, but not independently sufficient

- authoritative DOM hash delegation and differential hash vectors;
- corrected closed four-value PurposeV1 codec;
- strict Sponsor policy rejection;
- constant-time wide scalar reduction boundary;
- adaptor verification, adaptation, extraction, and final DOM verification;
- all eight SCAD0 records;
- 10,000 deterministic closed-cycle cases;
- fixed-width parser mutation tests; and
- two persistent parser fuzz targets with short Linux ASan campaigns.

### Mandatory blockers

1. **Normative blocker:** exact `DirectionV1` bytes are absent.
2. **Normative blocker:** exact `PhaseV1` bytes are absent.
3. **Code blocker caused by 1/2:** canonical context, KDF, secret nonce pair,
   one-shot partial signing, and full aggregation cannot be implemented.
4. **Independent-review blocker:** the independent implementation and
   intermediate byte comparison belong to Agent 2 and are not evidence in this
   branch.
5. **Review blocker:** a dedicated constant-time/zeroization/compiler-output
   review of the complete KDF and one-shot nonce lifetime is impossible before
   that code exists.
6. **Fuzz blocker:** the canonical context decoder and blocked signing workflow
   do not exist, so their required persistent fuzz targets cannot exist.
7. **Coverage blocker:** no independent evidence was available here to define
   and adjudicate the mission's requested 16 parity-combination matrix beyond
   the unchanged SCAD0 parity coverage.

No G1a checklist box was marked complete solely from documentation, focused
tests, self-generated property cases, or a short fuzz campaign.

## Prohibited operations confirmation

- No push, merge, rebase, tag, release, publication, or remote mutation was
  performed.
- No official repository or other worktree was modified.
- No DL2P material was imported.
- No real-funds flow or production activation was authorized.
- No consensus, existing wire, persisted-block, genesis, network-magic, or PoW
  change was made.
- No direct `dom-adaptor -> k256` dependency was added.

