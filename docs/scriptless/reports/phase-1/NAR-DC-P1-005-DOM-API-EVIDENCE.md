# NAR-DC-P1-005 DOM API Evidence

## Status and authority

This report records DOM-side implementation and independent-review correction
evidence for the signed NAR-DC-P1-005 reservation-runtime boundary. The branch
started from ratification commit
`e8e08ae0f3048992855a35af315dba22b8f009b7` and preserves every subsequent
local evidence commit.

The controlling source is
`docs/scriptless/source-guides/normative/amendments/NAR-DC-P1-005-reservation-runtime-and-linux-capability-closure.en.md`:

- document SHA-256:
  `4f5582a17426ed5b03d6aa37d6c2fc9cfe564985ec3614d0d4a30fed8ae2d635`;
- signature-file SHA-256:
  `c12a8d65040b03ef507c4309c9c4bf655437bcd9c5c982e9f9a36a04dce90b83`.

This evidence does not adjudicate G1A, G1B, consolidated G1, publication,
production, mainnet, Phase 2, or real-funds use. No consensus, existing wire,
kernel verifier, persisted block, DOM Wallet, or DL2P behavior changed.

## Implementation commits

| Commit | Subject | Evidence |
|---|---|---|
| `5606ab7aefd2f8d60f4ca917bcffd7b9b146ef74` | `feat(scriptless): bind live vault reservation runtime API` | Introduced the live handle GAT boundary, distinct request/permit identifiers, request custody, canonical operation inputs, bound prepared exposure, consumed resend request, authenticated DSC1 owner, and vault-backed signer integration. |
| `3279a6065488e730b352164e5e18cf1cb3f76fea` | `fix(scriptless): harden signing round authority` | Made bootstrap opaque, authenticated before equivocation handling, rejected sequence regression, verified accepted partial equations, and made resend authority one-shot. |
| `0cccb84e42727354d5cffe73a03c467a8fe06f9b` | `fix(scriptless): validate live post-export projections` | Verified live stage and spent permit/kind/outbound-digest projections after commitment and reveal export. |
| `85757b6ec6906200eb3bcf2ec66c10f5fdf35a5c` | `fix(scriptless): close trusted signing round gaps` | Added bounded DSC1 buffering and parser/state regressions, corrected private KDF/final-attempt ordering, and reduced repeated live-stage reads. Its provisional source-shaped session route was subsequently quarantined after independent review. |
| `36a5fbc1a5e4193f023c5ffd6c02f8413b9cf57c` | `test(scriptless): fuzz authenticated DSC1 acceptance` | Added the persistent ASan/libFuzzer target under `cfg(fuzzing)` only. |
| `3aeb4cc6f9712bc26bb70d375b85eaa9296a6c8f` | `fix(scriptless): close reviewed runtime state defects` | Quarantined the unratified session constructor, closed semantic-failure slots, propagated and checked final retry, enforced spent kinds, shortened KDF auxiliary lifetime, corrected stale ordering comments, and changed fuzzing to structured authenticated multi-action transitions. |

## Closed implementation findings

### Ratified nonce-attempt ordering

`NAR-DC-P1-004-live-store-layout-and-runtime-closure.en.md` section 8.3 is the
ordering authority incorporated by signed NAR-DC-P1-005 section 1. It requires:

1. private OS-randomized KDF and full-pair retry selection;
2. construction and durable recording of the exact final-retry attempt;
3. secret sealing; and
4. only then public computation and exposure processing.

`VaultBackedSignerV1::derive_and_export_commitment` follows that order through
`prepare_private_nonce_derivation_attempt` at
`crates/dom-adaptor/src/vault_signer.rs:846`. The helper completes the private
KDF loop, explicitly drops the zeroizing auxiliary derivation owner, and only
then constructs `NonceDerivationRequestV1`. The Store call follows at lines
416–419; no public nonce is computed beforehand. The stale comment that placed the
durable attempt before secret generation was corrected at
`crates/dom-adaptor/src/nonce_vault.rs:1110`.

The regression test
`private_kdf_finishes_before_the_final_retry_request_is_constructed` verifies
that the generated request carries the exact signer-selected retry and binding.
This ordering is closed by existing signed authority; it is not a new normative
gap.

### Authenticated round state

The round owner now:

- enforces commitment/sequence 0, reveal/sequence 1, and partial/sequence 2;
- caps pending authenticated messages at the six-message two-party profile;
- treats byte-identical duplicates as idempotent;
- permanently closes on authenticated equivocation, regression, invalid future
  sequence, invalid ancestry, reveal mismatch, or partial-equation failure;
- cannot discard a semantically invalid logical slot and later accept a
  corrected replacement;
- never leaves an invalid selected successor as a head-of-line blocker; and
- verifies participant partial equations before completion.

Primary symbols are `accept_message` at
`crates/dom-adaptor/src/signing_round.rs:531` and `drain_ready` at line 594.
Tests cover authenticated header, flags, kind, length, payload and trailing-byte
mutations; exact duplicate; equivocation; future sequence; bad ancestry; valid
partial acceptance; and invalid reveal/partial followed by a corrected message.

### Resume projection checks

The signer copies `live_stage()` once before local validation and dispatch,
propagates the exact persisted final retry into resumed commitment/reveal
contexts, compares that retry after fresh exports, and enforces that commitment
and reveal accessors contain their assigned closed kinds. Unit tests cover
presence mismatch, wrong retry, wrong kind, and a handle whose repeated stage
accessor would return different values.

This closes the concrete double-read, retry, and descriptor-kind defects. It
does not prove that all seven separately frozen accessors are one atomic Store
snapshot; that distinct interface gap remains below.

### Structured persistent fuzz target

The `dsc1_signing_round` target submits arbitrary parser input and then drives
fuzz-selected authenticated canonical commitments, reveals, partials,
out-of-order delivery, duplicates, equivocation, ancestry, and semantic
failures. Its entry point exists only under `cfg(fuzzing)` and no Cargo feature
can expose it in a normal or release resolution. A compile-fail documentation
test proves that the symbol is unavailable in ordinary builds.

## Required NAR-006 interface inputs

The following three gaps are deliberately not implemented or inferred. They
require one signed follow-up assignment, referred to here as NAR-006.

### 1. Accepted-session authority

NAR-002 section 6 lines 196–211 permits an explicit nonzero session ID only in
signed fixtures. Production must prove the canonical CSPRNG construction and
lifetime uniqueness. NAR-DC-P1-005 section 4.4 lines 454–462 additionally
requires complete validated roster mapping, accepted contract terms, local
share equality, and initial transcript ancestry.

The provisional `SigningRoundSessionRequestV1` accepted caller-shaped source
values and therefore did not prove that authority. It and its bootstrap
constructor are now compiled only under `cfg(test)` or `cfg(fuzzing)` at
`crates/dom-adaptor/src/signing_round.rs:284`; there is no production
`VaultBackedSignerV1::begin_signing_round` method and no public re-export.

NAR-006 must freeze an opaque, non-caller-fabricable accepted-session authority,
including initiator/responder session-ID provenance, durable lifetime
uniqueness, accepted terms, validated role/roster mapping, starting transcript,
and exact next-sender sequences. Until then, production construction fails
closed.

### 2. Atomic retained-handle snapshot

NAR-DC-P1-005 section 3.1 lines 99–127 freezes seven separate read-only handle
accessors and lines 129–131 prohibit exposing another field. Lines 190–197 also
require one coherent retained-lock snapshot. A DOM helper cannot prove that
separate trait calls came from one atomic Store projection.

NAR-006 must either replace those accessors with one opaque atomic snapshot or
add an exact snapshot method and freeze its type, creation authority, lifetime,
and revalidation rules. The current local snapshot helper is only a double-read
mitigation and is not claimed as normative closure.

### 3. Trusted restart resend identity

NAR-DC-P1-005 section 4.5 lines 514–526 requires `ResendRequestV1` to bind the
complete `NonceIdentityV1`, including the Store-generated `nonce_epoch`.
Section 3.1 exposes only `reservation_nonce_id()` and prohibits another
identifier. All other identity fields can be recomputed from trusted signer
state; the epoch cannot.

The resumed commitment and reveal states intentionally retain
`nonce_identity: None` at `crates/dom-adaptor/src/vault_signer.rs:365` and line
387. Restart resend therefore returns `CorruptState` instead of inventing an
epoch. NAR-006 must assign a non-authorizing trusted route for the complete
current-generation identity, preferably in the atomic snapshot above.

## Independent-review disposition

| Finding | Disposition |
|---|---|
| KDF happened after durable attempt. | **CLOSED** by signed NAR-DC-P1-004 ordering and corrected implementation/test. |
| Pending storage was unbounded and could head-of-line block. | **CLOSED** by exact sequence mapping, bound, and fail-closed successor handling. |
| Semantic reveal/partial failure lost the logical slot. | **CLOSED** by permanent state closure and corrected-message regressions. |
| Resume lost final retry or accepted wrong spent kinds. | **CLOSED** by exact propagation/comparison and kind checks. |
| KDF auxiliary owner lived through persistence/export. | **CLOSED** by immediate zeroizing drop before request construction. |
| Fuzzing could not reach authenticated transitions. | **CLOSED AS TARGET DESIGN** by structured signed multi-action inputs; the executed campaign remains limited evidence. |
| Caller-shaped production session request lacked accepted-session authority. | **QUARANTINED; NAR-006 REQUIRED**. |
| Separate live accessors do not prove atomic coherence. | **NAR-006 REQUIRED**. |
| Restart resend lacks Store-owned nonce epoch. | **NAR-006 REQUIRED**. |

## Executed validation

All commands below executed in the isolated DOM worktree on Linux. The final
full-suite row is updated after the documentation commit and clean-HEAD rerun.

| Command | Exit | Result |
|---|---:|---|
| `cargo fmt --all -- --check` | 0 | Passed. |
| `cargo check -p dom-adaptor --all-targets --locked` | 0 | Passed. |
| Focused semantic-failure test | 0 | 1 passed, 0 failed. |
| Focused vault-signer tests | 0 | 4 passed, 0 failed. |
| `cargo clippy -p dom-adaptor --all-targets --locked -- -D warnings` | 0 | Passed with warnings denied. |
| `cargo +nightly fuzz build dsc1_signing_round` | 0 | Persistent structured target compiled with ASan. |
| `cargo +nightly fuzz run dsc1_signing_round -- -max_total_time=15 -timeout=5 -seed=20260805 -print_final_stats=1` | 0 | 404 executions in 16 seconds; 21 corpus units/35 bytes, 24 new units, peak RSS 53 MiB, zero crashes. This is limited smoke evidence, not a complete campaign. |
| Local persisted corpus inventory | 0 | 20 ignored corpus files; aggregate inventory SHA-256 `2d51e71f9eb3db520f1e4ed8490d183b18b760aca1224a0fccab3817da5db5bc`; zero crash artifacts. |
| Normal feature graph search for `fuzz`/`dangerous` | 0 | No fuzz or dangerous test feature in ordinary resolution. |
| `git diff --check` | 0 | Passed before every implementation commit. |

The suite retains the frozen eight-vector SCAD0 path, all 311 frozen independent
intermediate comparisons, closed registries and parsers, participant-bound
partial validation, one-shot authorization compile failures, and real DOM
verifier coverage already owned by `dom-adaptor`.

## Remaining gates

- The three NAR-006 interface inputs above remain open.
- Concrete DOM Contracts Store conformance must be rerun after the revised
  signed interfaces are ratified and implemented.
- Linux Store crash-matrix and durable restart-resend evidence remain downstream
  Store responsibilities and are not proven by this DOM-only branch.
- Windows and macOS runtime evidence was not executed here.
- Publication and an immutable DOM Contracts dependency pin remain
  coordinator-controlled gates.
- No external security audit was performed.

This branch is improved DOM API evidence for NAR-006 drafting and
cross-repository review. It is not evidence that G1A, G1B, consolidated Phase 1,
or production is approved.

## Prohibited-operation confirmation

No push, merge, rebase, release, publication, production activation, real-funds
authorization, official-repository modification, DOM Wallet integration, or
DL2P import was performed by this correction tranche.
