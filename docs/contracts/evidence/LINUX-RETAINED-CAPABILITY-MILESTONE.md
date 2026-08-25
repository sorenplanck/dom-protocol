# Linux Retained-Capability Milestone Evidence

Status: **IMPLEMENTED AND LOCALLY VALIDATED; NOT A GATE APPROVAL**

This report records the bounded Linux filesystem milestone implemented after
ratification of NAR-DC-P1-005. It is execution evidence, not approval of G1B,
Phase 1, production, publication, or mainnet use.

## Scope

The milestone covers only the retained Linux filesystem and locking boundary
required before a concrete DOM Contracts Store can perform an authoritative
transaction. It does not implement or claim:

- the revised `NonceVaultV1` lifecycle;
- reservation, budget, journal, restore, or exposure orchestration;
- witness or watchtower behavior;
- Windows or macOS support;
- production configuration or mainnet activation.

The implementation is internal to `dom-scriptless-store`. It cannot authorize
or export adaptor material.

## Baseline and commits

The work started from ratified commit
`fdb29297dd22547b1f86fe33967f72ef46e3ca12` on branch
`feat/contracts-live-vault-runtime`.

The following local commits were created:

| Commit | Subject | Files |
|---|---|---|
| `5db4bc5038e9e8beb387ad755454196c2b279920` | `build(store): pin retained Linux capability dependencies` | `Cargo.lock`, `crates/dom-scriptless-store/Cargo.toml` |
| `0b63ed59ca91f844d8ae2846b364d52e56e265cf` | `fix(store): use ratified bounded artifact paths` | `crates/dom-scriptless-store/src/canonical.rs`, `crates/dom-scriptless-store/src/canonical/path.rs`, `crates/dom-scriptless-store/src/lib.rs` |
| `353fd8d78cf369dfa1800005fef8c2ec2771a053` | `feat(store): add retained Linux capability boundary` | `crates/dom-scriptless-store/src/lib.rs`, `crates/dom-scriptless-store/src/runtime.rs`, `crates/dom-scriptless-store/src/runtime/linux.rs` |
| `3bcca4a90eaddf1bf181b1b96c4010c49aa1d6ad` | `test(store): harden retained filesystem invariants` | `crates/dom-scriptless-store/src/runtime/linux.rs` |

The validated code HEAD before creation of this report was
`3bcca4a90eaddf1bf181b1b96c4010c49aa1d6ad`, with tree
`64aa43cfb4a74a029c6811654d3d1439d6311672` and a clean tracked worktree.

## Dependency closure

The direct Linux dependencies are pinned exactly as ratified:

| Crate | Version | Direct feature selection | Downloaded archive SHA-256 |
|---|---:|---|---|
| `cap-std` | `4.0.2` | default features disabled | `7281235d6e96d3544ca18bba9049be92f4190f8d923e3caef1b5f66cfa752608` |
| `cap-fs-ext` | `4.0.2` | `std`; default features disabled | `d78e5a3368ae89b7cb68186411452b4b9fac8b41be9c19bf3f47c2d2c8e36e6b` |
| `rustix` | `1.1.4` | `std`, `fs`, `process`; default features disabled | `b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190` |
| `nix` | `0.31.3` | `fs`, `feature`; default features disabled | `cf20d2fde8ff38632c426f1165ed7436270b44f199fc55284c38276f9db47c3d` |

`Cargo.lock` contains these exact versions and registry checksums. Cargo
feature unification also enables transitive `rustix` features required by
`cap-std` and `cap-primitives`; the direct Store declaration remains the exact
ratified profile, and the complete resolved graph is lockfile-bound.

## Implemented security boundary

`crates/dom-scriptless-store/src/runtime/linux.rs` implements the following
safe-Rust boundary:

- retained `cap_std::fs::Dir` capabilities;
- strict single-component validation against the frozen component registry;
- fail-closed `fpathconf(NAME_MAX)` validation requiring at least 229 bytes;
- `openat2` with `BENEATH`, `NO_SYMLINKS`, and `NO_MAGICLINKS` resolution;
- `NOFOLLOW` and `CLOEXEC` on authoritative opens;
- exact owner, mode, type, and regular-file link-count validation after open;
- owner-only `0700` directories and `0600` authoritative files;
- create-no-clobber with `CREATE | EXCL`;
- descriptor `fsync` for files and directories;
- pre-mutation rejection of an unsynchronizable destination directory;
- `renameat2(RENAME_NOREPLACE)` for no-replace publication;
- replacing rename only for the exact active-generation pointer names;
- retained-source identity validation before rename;
- retained-parent, retained-target, no-follow identity validation before
  `unlinkat`, followed by parent sync and exact absence verification;
- one nonblocking exclusive `flock` retained for the authority lifetime;
- independent directory scans opened through `openat2`, never through `.` or
  a duplicated directory cursor;
- redacted error variants that contain no path, record bytes, nonce, or secret;
- no application `unsafe`, ambient production path, `canonicalize`, `openat`
  fallback, raw syscall, shell helper, or weaker syscall fallback.

The former 294-byte tombstone staging name and 317-byte flat restore-record
name were corrected to the signed 229-byte staging component and nested
210-byte/107-byte restore-record components.

## Executed validation

Environment:

- OS/kernel: Linux `7.0.0-28-generic`, `x86_64`;
- filesystem used by the worktree: `ext4`;
- Rust: `rustc 1.96.1 (31fca3adb 2026-06-26)`;
- Cargo: `cargo 1.96.1 (356927216 2026-06-26)`.

All commands below ran against code HEAD
`3bcca4a90eaddf1bf181b1b96c4010c49aa1d6ad`:

| Command | Result | Exit code | Recorded elapsed time |
|---|---|---:|---:|
| `cargo metadata --locked --no-deps --format-version 1` | PASS | 0 | 0 s |
| `cargo fmt --all -- --check` | PASS | 0 | 1 s |
| `cargo check -p dom-scriptless-store --locked` | PASS | 0 | 2 s |
| `cargo test -p dom-scriptless-store --locked` | PASS | 0 | 4 s |
| `cargo clippy -p dom-scriptless-store --all-targets --locked -- -D warnings` | PASS | 0 | 1 s |
| `git diff --check` | PASS | 0 | 0 s |

The Store test command reported:

- 102 parent-process unit tests passed;
- one subprocess-helper test was intentionally ignored by the parent harness;
- that exact helper was invoked by the lock test in a real second process and
  reported 1 passed, 0 failed;
- 2 compile-fail documentation tests passed;
- no failed tests.

The retained-boundary subset supplied 13 passing parent-process tests plus the
successful child-process helper. It exercised:

- canonical component acceptance and rejection, including the exact 229-byte
  maximum;
- create-no-clobber and exact-byte reopen verification;
- wrong mode and hard-link rejection;
- final-component symlink rejection;
- no-replace rename without overwriting existing bytes;
- the active-pointer-only replacing rename restriction;
- lock exclusion in a second open instance and in a real second process;
- verified unlink and rejection after pathname replacement;
- rejection of unknown and symlink directory entries;
- independent repeated directory scans;
- rejection of an unsynchronizable path-only parent before mutation.

## Blocking dependency/API mismatch

The workspace is pinned to public DOM revision
`67fe11c441c2b7801b6f70809ab58caa4804c22a`. At that revision,
`crates/dom-adaptor/src/nonce_vault.rs` still exposes the superseded public
contract:

- `PreparedExposureV1` is defined at line 475 as a raw `ExposureBytes` wrapper;
- `NonceVaultV1` begins at line 566;
- `claim_reservation` begins at line 580;
- one shared `begin_computation` permit begins at line 588;
- `authorize_exposure` begins at line 607;
- permit-ID-only `resend_exported` begins at line 632;
- caller-selected `abort(..., AbortReasonV1)` begins at line 638.

The public revision does not contain the revised NAR-DC-P1-005 fresh/resume
request split, request-lookup custody, `VaultReservationHandleV1` binding,
distinct stage and persistence permits, validated accepted signing-round
state, prepared-artifact validation boundary, request-authorized resend, or
caller-free cancellation.

Implementing the concrete Store against the superseded trait would preserve a
known bypass and contradict the signed record. Creating a local substitute,
unpublished revision pin, path override, or compatibility facade would create
false conformance. Therefore no concrete `NonceVaultV1` implementation was
attempted in this branch.

## Remaining work and adjudication

The retained Linux boundary is a completed prerequisite, not the complete
Store runtime. The following remain open until the revised DOM API is
implemented, reviewed, published, and pinned:

- exact Store trait conformance and high-level reservation handles;
- durable reservation, budget, journal, secret, exposure, and tombstone
  transactions;
- exact resend and caller-free cancellation;
- crash-prefix recovery and restore quarantine;
- complete process-death, concurrency, fault-injection, fuzz, and sanitizer
  matrices;
- Windows and macOS backend decisions and real-runner evidence.

No consensus, existing DOM wire, DOM Wallet, remote repository, release,
publication, mainnet, or real-funds operation was changed or authorized.

```text
LINUX_RETAINED_CAPABILITY_BOUNDARY = IMPLEMENTED_AND_LOCALLY_VALIDATED
CONCRETE_NONCE_VAULT_CONFORMANCE = BLOCKED_BY_UNPUBLISHED_DOM_API
G1B = NOT APPROVED
PHASE1 = NOT APPROVED
PRODUCTION = NOT AUTHORIZED
PUSH = NOT PERFORMED
MERGE = NOT PERFORMED
RELEASE = NOT PERFORMED
```
