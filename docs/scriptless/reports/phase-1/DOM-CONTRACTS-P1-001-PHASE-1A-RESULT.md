# DOM Contracts P1-001 Phase 1A Result

Status: **BLOCKED — LOCAL DOM CORE CANDIDATE COMPLETE; G1A IS NOT APPROVED**
Branch: `feat/phase-1-integrated`
Starting commit: `b059f5c4279b86671efc078b5988c580a2a4e4d8`
Implementation commit: `547a8aba6a280de8ab8371d1c1dc7b9c5050a512`
Fuzz-target commit: `bbcdbdc34e149cfb20732b13fe76c507228a70ab`
Platform: Linux x86_64

## Scope and verdict

This report covers only the isolated DOM Core Phase 1A assignment. It does not
modify Wallet code, implement the Phase 2 contract lifecycle, authorize real
funds, activate production, alter consensus or existing L1 wire bytes, import
DL2P, publish a crate, or create a remote revision.

The signed omnibus record closed the former normative gaps for the safe-Rust
ownership boundary, share proof of knowledge, and collaborative Bulletproof
profile. The corresponding local DOM implementation now compiles and its
focused evidence passes. G1a remains **NOT APPROVED** because the mandatory
independent post-diff review, complete fuzz/sanitizer campaigns, platform
matrix, publication pin, and operational two-wallet evidence are not complete.

## Normative input

The operator-supplied record used for this work is:

- file: `NAR-DC-P1-001-omnibus-gap-closure.en.md`;
- SHA-256: `88586449d577038ac98e9463250821ed9b3d1e6c94f5b11abfaf036a93eec655`;
- signature SHA-256:
  `2f19ec266f05e440cb5de2b91bc4295b93b2629170adbf6d020505ebb2311ffc`;
- public key:
  `RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3`; and
- `minisign -Vm` result: exit 0, signature and trusted-comment signature
  verified.

The signed bytes were not modified or copied into production code. ADR-0018
records the narrow engineering decision implemented from NAR-DC-P1-001 §4.

## Local commits preserved

| Commit | Change |
|---|---|
| `b3a2306b6e5447745671e297df4dec3d5f357670` | Permanent exact one-input/one-output/one-kernel transaction validation through consensus. |
| `81998ab9d565bd997dcc6dd9502bb0048a5f9638` | Explicit canonical scalar boundary evidence. |
| `b059f5c4279b86671efc078b5988c580a2a4e4d8` | Exact 739-byte Bulletproof assertion in the spend baseline. |
| `547a8aba6a280de8ab8371d1c1dc7b9c5050a512` | Ratified secret boundary, share PoK, collaborative Bulletproof phases, vault computation ordering, and current-tree comparison adapter. |
| `bbcdbdc34e149cfb20732b13fe76c507228a70ab` | Persistent canonical-context, share-PoK, and Bulletproof parser fuzz targets; obsolete raw nonce target removed. |

No prior commit was amended, rebased, squashed, or rewritten.

## Implemented DOM Core boundary

### Non-bypassable secret ownership

- Scriptless-specific nonce KDF tags, context binding, retry, nonce-pair
  ownership, public-nonce derivation, record transfer, and bound partial
  computation are private to `dom-adaptor`.
- Deterministic auxiliary randomness is available only under `cfg(test)`; no
  production Cargo feature enables it.
- `SigningShareV1` and the private nonce owners are non-cloneable,
  non-debuggable, non-serializable, and zeroizing.
- Fallible secret import places incoming arrays under RAII zeroization before
  validation.
- `dom-adaptor` has no direct `k256` dependency.
- `dom-crypto` retains only generic authoritative constant-time scalar/point
  operations and the unchanged DOM verifier boundary.
- Compile-fail probes demonstrate that downstream callers cannot import the
  secret nonce owner, raw derivation/reveal/partial functions, sealer/import
  capabilities, or reusable authorization capabilities.

### Vault-backed ordering

`NonceVaultV1` now requires a durable reservation claim and a consumed opaque
computation permit before nonce derivation, reveal opening, or a partial
attempt. The high-level signer follows:

1. claim the reservation and budget;
2. durably begin the exact computation stage;
3. compute using private one-shot material;
4. store the sealed secret transfer before commitment exposure; and
5. obtain and consume durable exposure authorization for exact persisted
   bytes.

Concrete Wallet/store implementations must conform to this revised trait.
This report does not claim Wallet durability or witness conformance.

Generic vault errors are retained internally but their `Debug` and `Display`
representations are fixed redacted strings. A secret-marker test proves that a
concrete error's formatting is not propagated.

### Share proof of knowledge

The ratified Share PoK V1 statement, challenge framing, proof codec, prover,
and verifier are implemented through the authoritative DOM hash, scalar, and
point boundaries. Tests cover exact encoding, role/index/recovery binding,
wrong shares, roster and scalar mutations, and strict parsing.

### Collaborative Bulletproof phases

The pinned DOM Bulletproof backend now exposes one-shot round-one and final
states, public `T1/T2`, checked round-two `tau_x`, aggregate `tau_x`, exact
739-byte finalization, and verification by the unchanged DOM verifier.
Backend context, generator, and scratch allocation failures return typed
fail-closed errors; production initialization contains no panic assertion.

The `dom-adaptor` orchestration keeps the common nonce share, local blinding,
private nonce, and raw round-two share crate-sealed and one-shot. Tests execute
the production wrapper for 2, 3, and 16 participants.

## Frozen independent evidence integrity

The immutable independent generator, expected outputs, comparator, and both
manifests were not changed. In particular:

| Artifact | SHA-256 |
|---|---|
| Frozen comparator | `4d4df3e5d47f53c4acf1ce1b2c9e16ddb0a57c6bb43c7612ff5440433a6d63f0` |
| Frozen full outputs | `68f7d9e9b202b2c4380fe913f69ab15ed5205871cc82c84e3ee78eaaf5762206` |
| Current-tree private adapter | `5ffb5521f9218a3fff59fef796acb16874fcb20814a43595daac4836c4f5bd8c` |

The current-tree adapter lives under `crates/dom-adaptor/src/`, not in the
frozen evidence directory. It contains a prominent public/insecure test-vector
warning, is compiled only under `cfg(test)`, does not print intermediate secret
fixture bytes, and compares the unchanged expected JSON against the private
production implementation. The fresh result was:

```text
COMPARISON_COMPLETE matched_fields=311
```

All 311 intermediate comparisons matched. Refund, ClaimAdaptor, and Funding
final signatures passed the real DOM verifier within that comparison.

## Fresh executed validation

All commands below ran in this worktree after the production fixes. Exit codes
were zero unless explicitly stated otherwise.

| Command | Objective result |
|---|---|
| `cargo test -p dom-adaptor --locked` | 33 unit tests, 4 G1a tests, 7 transcript tests, 3 freeze probes, and 7 compile-fail doctests passed. |
| `cargo test -p dom-crypto --lib scriptless --features test-helpers --locked` | 6 passed in 138.34 s, including a new deterministic 10,000-cycle adapt/extract run through the real verifier and all 16 SEC1 parity combinations. |
| `cargo test -p dom-consensus --test scad0_adaptor_fixtures --locked` | 1 passed; all eight frozen SCAD0 cases exercised. |
| `cargo clippy -p dom-adaptor --all-targets --locked -- -D warnings` | Passed with warnings denied. |
| `cargo clippy -p dom-crypto --lib --locked -- -D warnings` | Passed with warnings denied. |
| `cargo check -p dom-adaptor --all-features --release --locked` | Release feature resolution compiled; no raw deterministic helper feature exists. |
| `cargo metadata --no-deps --format-version 1 --locked` | Passed. |
| `cargo check --manifest-path crates/dom-adaptor/fuzz/Cargo.toml --bins --locked` | All persistent fuzz binaries compiled. |
| `sha256sum --check test-vectors/scriptless/two-nonce/independent/ratified-v1/MANIFEST.sha256` | Every frozen independent artifact reported `OK`. |
| `sha256sum --check test-vectors/scriptless/MANIFEST.sha256` | Every Scriptless vector artifact reported `OK`. |
| `cargo fmt --all --check` | Passed. |
| `git diff --check` | Passed. |

The persistent fuzz targets compile, but compilation is not a fuzz campaign.
No ASan/libFuzzer duration, crash-free execution count, sanitizer result,
Windows result, or macOS result is claimed here.

## Resolved earlier findings

- The former raw safe-Rust Scriptless nonce/partial bypass is closed by moving
  protocol ownership into private `dom-adaptor` modules and removing the
  production feature that exported those owners.
- The former share-PoK normative gap is superseded by the signed omnibus
  record and implemented with exact codecs and tests.
- The former collaborative Bulletproof normative/backend gap is superseded by
  the signed omnibus record and implemented through the pinned backend with
  one-shot typed states.
- The frozen independent evidence path is byte-identical; the mechanically
  adapted current-tree comparator is separate test code and does not rewrite
  independent history.

These closures are implementation inputs and focused evidence. They do not,
by themselves, approve G1a.

## Remaining blockers

- Independent post-diff security review of commits `547a8aba...` and
  `bbcdbdc...` is pending; any open CRITICAL or HIGH finding blocks G1a.
- Real fuzz and sanitizer campaigns on every required parser are pending.
- Windows and macOS execution are pending; prepared workflows are not
  execution evidence.
- The operational two-wallet regtest scenario remains pending.
- DOM adaptor publication and a consumable immutable Wallet dependency pin are
  pending separate authorization.
- Full G1b durable store, witness, crash/fault, rollback, restore-quarantine,
  budget, and ordinary-Wallet-isolation adjudication belongs to the other
  integration workstream.
- Production numeric policies remain absent unless supported by a separately
  ratified measurement ADR.

## Official-source integrity

Final read-only inspection reproduced the expected official state:

| Source | Branch | HEAD | Tree | Status |
|---|---|---|---|---|
| DOM | `release/mainnet` | `769822562565f18ef55423dc992e7aa661206b4a` | `9cee98e2d393d52b7a330e398a04216f98f4f339` | only the known untracked parity probe |
| Wallet | `redesign/restore-remote-scan` | `1868e61bc39eca223d794348d70e48668ad06708` | `5c572e4b5d083dbb7caa0ca608c0d2864add9f6c` | only the three known untracked reports |

Preserved untracked SHA-256 values are:

- DOM probe:
  `e036be3b8ae8f081a214958ed47e0d311c14e91277cbc57797f7276ef8c66064`;
- Wallet reports:
  `88efe0f79ee4a795d3918e8c431b1477e1d5909a96445a8048309de01195e7f1`,
  `41741803d8f95c64ca40d8ffc6584f07cb833736f9c88264debd1f9e30d76d68`,
  and `71936f8fca1bacb5901a7add3c791bb8832b0afb5d81fa487119de2a0cd84059`.

None was executed, imported, copied, edited, removed, or renamed.

## Adjudication

- `IMPLEMENTATION_RESULT = COMPLETE` for this narrow DOM Core assignment;
- `G1A = NOT APPROVED`;
- `G1B = NOT APPROVED`;
- `PHASE1 = NOT APPROVED`; and
- `PRODUCTION = NOT AUTHORIZED`.

No push, merge, release, publication, remote mutation, official-repository
modification, DL2P import, consensus/wire change, real-funds authorization, or
production activation occurred.
