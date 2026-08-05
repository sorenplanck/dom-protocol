# Independent Phase 1 Integration Expectations

Date: 2026-08-04

Status: **FROZEN BEFORE INTEGRATED CANDIDATE INSPECTION**

Review worktree baseline: `76915842465f89867b045c9016d532dc3538ac2d`

This document freezes the independent review checklist, adversarial probes,
negative expectations, and conformance plan for the integrated G1a/G1b
candidate. It was written without inspecting either integration worktree. It
does not approve implementation, evidence, a gate, publication, production, or
real-funds use.

## 1. Authority and immutable evidence

The review applies the following sources in order:

1. ratified `ADR-P1-001`, exact content SHA-256
   `e35c39e74f9af61e19ecda8e1ca503f37a7fc04c6e2a0f40f5d96bf6a20d1596`;
2. ratified sources referenced by that ADR and the normative manifest;
3. current registries and gate checklists;
4. the pre-comparison independent evidence commit
   `3486a863ba922e2b7a4fc52e5ded988c6d32de87`;
5. the independence-barrier commit
   `f0a8be6efce885281fc2a4c4619698d2aa494f9f`;
6. the prior independent comparison and review commit
   `6b90e7a021541a63a728354910b323603da635b2`.

The frozen independent full-vector artifact has SHA-256
`68f7d9e9b202b2c4380fe913f69ab15ed5205871cc82c84e3ee78eaaf5762206`.
The independent generator has SHA-256
`fa4e8347685e69489e5a85c11725896104a26fcfc3b4194f253e2ddcca808cf2`.
The post-barrier comparison harness has SHA-256
`4d4df3e5d47f53c4acf1ce1b2c9e16ddb0a57c6bb43c7612ff5440433a6d63f0`.

The frozen reference contains three positive purpose cases and fifty negative
cases. The prior comparison matched 311 named intermediate values. Those bytes
must remain unchanged. Historical success is provenance, not fresh integrated
execution evidence.

## 2. Review independence barrier

Before this document and its machine-readable attack catalog are committed,
the reviewer must not inspect:

- `/home/leonardov/dom-scriptless-dev/worktrees/phase1-integrated-dom`;
- `/home/leonardov/dom-scriptless-dev/worktrees/phase1-integrated-wallet`;
- an integrated diff, patch, source archive, report, test output, or API list.

After the barrier commit, implementation-specific probe source may be written
only to realize an attack already frozen here. Its expected outcome must not be
changed to accommodate production behavior. A discrepancy is reported at the
first observable divergence.

## 3. Mandatory review questions

### 3.1 Single authority and dependency closure

- Exactly one `dom-adaptor` definition owns `PurposeV1`, `DirectionV1`,
  `SigningPhaseV1`, `ExposureKindV1`, context codecs, exposure bindings, and
  lifecycle errors.
- Every registry is closed. Unknown bytes fail closed. `Sponsor` parses but is
  rejected by strict Phase 1 execution policy.
- `dom-adaptor` has no direct `k256` dependency and no Wallet, database,
  witness, transport, application, DL2P, or absolute-path dependency.
- The Wallet production composition root statically selects one reviewed vault
  implementation. Application input cannot replace it through a trait object,
  plugin, FFI, RPC, UI, or configuration-selected implementation.
- Test helpers, deterministic randomness, test vaults, and deterministic
  witnesses are absent from release feature resolution.

### 3.2 Capability non-forgeability

- The persisted 252-byte permit record is syntax and audit state, never
  authorization by itself.
- The in-process capability has no public constructor and no conversion from
  bytes, permit records, digests, receipts, or Booleans.
- It is not `Clone`, `Copy`, `Debug`, `Display`, `Serialize`, or `Deserialize`.
- Its type is tied to the concrete vault instance and it is consumed by value.
- A safe caller cannot authorize two exports, change bound bytes, or reuse it
  after process restart.
- No application-facing method accepts caller-supplied witness acceptance,
  receipt validity, storage success, synchronization success, permit bytes,
  witness key, secret nonce, `k1`, `k2`, or raw partial signature authority.

### 3.3 Secret ownership and codecs

- `NonceSecretRecordV1` is exactly `142 + context_length` bytes and accepts
  only the context-derived range 387 through 882 bytes.
- The record codec is manual and canonical. No Serde, bincode, JSON, CBOR,
  native layout, pointer-sized length, trailing bytes, or unchecked allocation
  defines secret-record bytes.
- The record persists canonical nonzero `k1` and `k2`, never the signing share
  or auxiliary KDF state.
- All record, context, AAD, reservation, participant, public-nonce,
  commitment, reveal, and lifecycle bindings are revalidated after open.
- Plaintext transfer, opened plaintext, nonce pairs, scalar temporaries, and
  partial-signing temporaries are guarded by compiler-visible zeroization on
  success, error, and unwind paths.
- Secret-bearing values cannot be cloned, copied, formatted, generically
  serialized, ordered, logged, or exposed as reusable bytes.

### 3.4 Durable authorization order

- Reservation persists the sealed secret, charges budgets, journals the
  reservation, verifies the witness receipt, and durably records the complete
  projection before returning an opaque handle.
- Commitment and reveal bytes are persisted before authorization. Their permit
  is durably spent before bytes cross the boundary.
- Partial signing records the attempt boundary before opening the secret,
  computes and locally verifies exactly once, persists the exact partial,
  witnesses consumption, destroys the secret, writes the tombstone and
  terminal state, synchronizes required data and directories, spends the
  permit, and only then returns the persisted bytes.
- No drop implementation is treated as a durable transaction.
- Every retry reads immutable persisted bytes. It performs no KDF, nonce
  decryption, point derivation, partial computation, witness advance, budget
  charge, or new permit creation.
- Abort, timeout, crash, corruption, restore, epoch rotation, compaction, and
  backward clock never refund budget or revive an identifier or secret.

### 3.5 Witness, restore, and ordinary Wallet isolation

- Witness messages and receipts are canonical, bounded, authenticated, signed,
  monotonic, replay-safe, and fail closed on divergence or equivocation.
- There is no silent local-file or unauthenticated production fallback.
- Restore begins quarantined and computes conservative unions of irreversible
  state. Ambiguous nonterminal reservations burn or remain quarantined.
- Ordinary Wallet operations do not import, construct, initialize, contact, or
  mutate the vault, witness, budget store, anchor, or Scriptless journal.
- Ordinary operations succeed while the witness is unavailable, with test
  counters proving zero initialization and zero connections.
- Witness-visible payloads exclude Wallet identity, contract, value, address,
  purpose, transaction hash, preimage, signing key, session contents, and
  plaintext journal or artifact bytes. Timing and sequence leakage is reported.

## 4. Frozen adversarial attack families

The complete machine-readable catalog is
`test-vectors/scriptless/integration-review/v1/attack-expectations.tsv`.
The following families are mandatory and cannot be removed after candidate
inspection:

1. raw secret, raw reveal, raw partial, deterministic RNG, and bypass imports;
2. capability construction, deserialization, copying, formatting, and reuse;
3. caller-forged receipt, Boolean, witness key, storage result, and permit;
4. registry duplication, unknown discriminants, and Sponsor execution;
5. secret-record truncation, extension, length abuse, context mismatch,
   scalar malleability, AAD mutation, and reservation mismatch;
6. permit length, binding, stage, digest, receipt-chain, and spent-state abuse;
7. exact retry versus recomputation and conflicting idempotency;
8. crash cuts around every durable boundary and partial-attempt ambiguity;
9. restore rollback, remote-ahead, local-ahead, divergence, epoch rotation,
   backward clock, and identifier resurrection;
10. budget refund/reset attacks;
11. witness downgrade, fallback, replay, equivocation, oversized parser input,
    and privacy leakage;
12. ordinary Wallet reachability and release-feature leakage;
13. secret log, error, panic, temporary-file, and crash-artifact leakage;
14. direct/transitive dependency ownership, unsafe code, consensus/wire changes,
    DL2P reachability, and absolute path dependencies.

## 5. Conformance execution plan

### 5.1 Candidate identity

Record path, branch, HEAD, tree ID, status, lockfile SHA-256, Rust toolchain,
feature graph, and dependency graph for the integrated DOM and Wallet heads.
Refuse review if either tree has unexpected tracked changes.

### 5.2 Public API and source review

1. Enumerate all public items in `dom-adaptor` and the Wallet vault package.
2. Trace every constructor and conversion for secret, permit, capability,
   receipt, reservation, prepared exposure, and authorized exposure types.
3. Search default and all-feature resolution for lower-level escape hatches.
4. Review `unsafe`, trait implementations, formatting, logging, error, panic,
   and zeroization paths.
5. Review feature unification, reverse dependencies, build scripts, dev
   dependencies, and transitive cryptographic ownership.
6. Review durable ordering as an explicit state-transition table, including
   every error edge and unwind edge.
7. Review ordinary Wallet composition and call graph from frontend through
   production backend.

### 5.3 Executable negative probes

After the barrier commit, create temporary downstream crates outside both
production repositories. The probes must attempt every API attack in the TSV.
Expected compile-fail probes pass only when compilation fails for the intended
privacy, trait, move, or feature-resolution reason. A syntax error or unrelated
dependency error is not a pass. Runtime fail-closed probes pass only when no
public bytes cross the boundary and irreversible state matches the expected
terminal or quarantined state.

### 5.4 Frozen cryptographic comparison

Run the unchanged comparison algorithm against the exact integrated
`dom-adaptor` tree and the frozen vector SHA-256. Compare all 311 named fields,
not only final scalars. Stop at and report the first divergence. Run Refund,
ClaimAdaptor, and Funding through the unchanged real DOM verifier. Do not
modify the reference generator, outputs, or expected fields.

### 5.5 Fault and process-death probes

Use real subprocess termination at the mission-defined cut points. For every
cut, record local state, remote head, budget, permit, secret inventory,
tombstone, outbound digest, resend capability, and reopen/restore result. The
only permitted external behavior is no export or byte-identical authorized
resend. Recalculation, nonce reuse, budget refund, resurrection, or premature
quarantine exit is a blocker.

### 5.6 Fuzz, sanitizer, and platform evidence

Use committed fuzz targets for every integrated parser. Record actual command,
tool version, corpus, executions, elapsed time, crash artifacts, exit code, and
platform. Prepared workflows are not execution. Linux evidence cannot be
reported as Windows or macOS evidence. An OOM, panic, unbounded allocation,
complexity timeout, accepted noncanonical encoding, sanitizer finding, or
secret-containing crash artifact fails the applicable gate.

## 6. Finding severity

- **CRITICAL:** exploitable nonce reuse, pre-durability export, forged
  authorization, secret disclosure, consensus/wire change, or fail-open
  witness/restore behavior.
- **HIGH:** safe bypass path, recomputation retry, restore resurrection,
  budget refund/reset, unreviewed production vault selection, test-feature
  leakage, duplicate semantic authority, or unresolved durability ambiguity.
- **MEDIUM:** bounded hardening issue without a demonstrated authority bypass,
  privacy metadata overexposure, incomplete negative coverage, or evidence
  quality defect.
- **LOW:** maintainability, documentation precision, or defense-in-depth issue
  with no gate-invalidating behavior.

Any open CRITICAL or HIGH finding keeps the affected gate not approved.

## 7. Frozen verdict rules

The reviewer will issue an independent report only after recording candidate
heads and executing the applicable probes. No checklist item is complete merely
because code or documentation exists. Every completion needs an objective
criterion, a command and exit code, an artifact SHA-256, the real platform, and
no contradictory finding.

Phase 1 cannot be approved while any mandatory platform execution,
publication/pin, operational-policy ratification, independent review, fault
matrix, fuzz/sanitizer, or gate item is open. Production remains unauthorized
under every outcome of this review.
