# DOM Contracts Phase 1 Candidate Closure

Status: **G1B/G1C CANDIDATE CLOSED; CROSS-REPOSITORY PHASE 1 PENDING**

Date: 2026-08-09  
Repository: `sorenplanck/dom-contracts`

## Decision

The DOM Contracts-owned Phase 1 Store/Nonce Vault boundary (G1B) and its
commit-bound composition with the pinned DOM Protocol adaptor (G1C) are closed
as an engineering candidate. This decision applies to the repository revision
that contains this record and only while its required checks are green.

The combined DOM Scriptless Phase 1 is not declared closed by this repository.
Final DOM Protocol G1A evidence and its formal integration remain an external
dependency. Repository tests also cannot authorize production, a release,
mainnet, real funds, or Phase 2.

## Bound inputs

| Input | Binding |
| --- | --- |
| DOM Protocol revision | `6f2b230ebbec390040dbf0bff110efaf4bb0f101` |
| DOM Protocol tree | `7b22395a3d1a1c3d8eac84c376643cffd7ce7bb5` |
| Dependency repository | `https://github.com/sorenplanck/dom-protocol` |
| Rust toolchain | `1.96.1` |
| Normative signatures | Minisign key ID `74197A95CA309CF0` |

Every tracked DOM Protocol dependency uses the same immutable public revision.
No path override, branch dependency, tag dependency, or unpublished revision is
accepted by the mechanical gate.

## Candidate evidence

| Area | Evidence | Adjudication |
| --- | --- | --- |
| Linux workspace | Locked metadata, formatting, all-target/all-feature check, Clippy with warnings denied, workspace tests, and architecture-boundary validation are mandatory in `.github/workflows/ci.yml`. | Required green check |
| Portable boundary | `.github/workflows/phase1-platform-evidence.yml` executes the six required read-only commands on Windows x86-64, macOS ARM64, and macOS x86-64. | Required green check on the final candidate |
| Current Store fuzz/ASan | `.github/workflows/phase1-linux-fuzz-evidence.yml` executes 100,000 fixed-seed ASan/libFuzzer cases for each of the four current parser targets. | Required green check on the final candidate |
| Release bypass | `scripts/check-release-surface.sh` requires a supported release Store build to pass and the `evidence-only` release build to fail with the exact policy diagnostic. | Enforced in CI |
| Dependency and architecture boundary | `scripts/phase1-gate.sh` and `scripts/check-boundaries.sh` reject mutable dependency pins, forbidden repository coupling, and an unsupported runtime surface. | Pass mechanically |
| Public UX boundary | `G-UX1-PHASE1-BOUNDARY.md` records the absence of application-facing nonce and partial-signing control and keeps the complete stop-ship gate pending. | Phase 1 assignment satisfied |
| Authorship | `scripts/check-authorship.sh` rejects any post-baseline author or committer other than Soren Planck and rejects co-author trailers. | Enforced in CI |

The portable run is evidence for compilation and tests on unsupported runtime
platforms. It does not add a Windows or macOS durable runtime. The native
binary remains a fail-closed validation shell.

## Where run identities are recorded

NAR-DC-P1-006 §5.2 binds platform evidence to one exact commit, and §9 stops
adjudication on a required job that is not bound to the final commit. A run
identity therefore cannot live in the tree it attests: naming a run here would
require a further commit, and that commit would invalidate the run it just
named. The table above consequently names required workflows and their
adjudication condition, never a run identity.

§7.2 already assigns run capture to the coordinator, outside this tree. For
every required job the coordinator records the repository, branch, workflow
path, workflow-file SHA-256, run identity, URL, triggering commit, runner
label, operating system, architecture, toolchain, exact command, exit code,
duration, state, and sanitized logs or hashes, and verifies the remote commit
and every job result independently. A GitHub summary or an agent report alone
is insufficient.

The adjudication rule is therefore: the final candidate is the commit at the
tip of the publication branch, and every row marked as a required green check
must have a coordinator-captured run whose triggering commit equals that tip. A
run on an ancestor commit is history, never a substitute.

Runs captured before this record adopted that rule, retained as history only:

| Run | Triggering commit | Result |
| --- | --- | --- |
| `31349273622` | `0b55aa9d2ba62ac023de94efa126451b82eec311` | all three platform jobs passed |
| `31349843494` | `839bd34d603e23c8a21a68b6141841b8f2619212` | all three platform jobs passed |

## Residual gates

The following conditions remain outside this candidate closure:

- final, integrated DOM Protocol G1A evidence at the revision consumed by this
  repository;
- the Master Specification Gate G0 full public-path baseline, including the
  permanent two-wallet restart/rescan and recipient-spend scenario on the
  exact production commit; the existing DOM Protocol branch is explicitly
  marked WIP and is not treated as a passing gate;
- final adjudication of the separate G1A property-test and UBSan evidence
  packages without pretending that their evidence-only branches are the
  pinned production branch;
- the complete G-UX1 acceptance matrix assigned to Phases 3 through 7;
- independent external security review;
- explicit release and production authorization;
- any mainnet or real-funds path.

### Outstanding evidence obligations

The mechanical checks above do not discharge the following commit-bound
obligations. They are listed so that no reader mistakes a green check surface
for a complete evidence set:

- adjudication of the completed NAR-DC-P1-004 §20 fuzz enumeration. All eleven
  required surfaces now have persistent targets. Ten are covered by the four
  targets in this repository and are mapped surface by surface in
  `STORE-FUZZ-SANITIZER-EVIDENCE.md`. The eleventh, the four closed request
  types, is covered by a `cfg(fuzzing)` harness inside `dom-adaptor`, because
  §20 also requires those types to stay non-constructible by an application
  caller and no downstream target can reach them. That harness lives in the
  DOM Protocol repository and its campaign is adjudicated with G1A, not here;
- the 10,000-case adaptor closed-cycle property run on the final revision,
  which NAR-DC-P1-006 §8 forbids satisfying with a historical count;
- a fresh independent 311-field comparison against the consumed revision;
- the zeroization, secret-copy, panic/unwind, logging, and constant-time review
  required by NAR-DC-P1-002 §14.4;
- the selected-history secret, local-path, dump, and database scan required
  before any publication step;
- static and runtime proof that ordinary `dom-wallet-v3` shares no dependency,
  import, initialization, connection, or state with this Store; and
- a clean cache-independent reproducibility execution on the current pin.
  `DOM-ADAPTOR-PIN-VALIDATION.md` records that execution only for the
  superseded revision `180b731a6aeba37f03a74fb49e985bf8741d0885`.

## Machine-readable status

```text
DOM_CONTRACTS_G1B = CLOSED_AS_PHASE1_CANDIDATE
DOM_CONTRACTS_G1C = CLOSED_AS_PHASE1_CANDIDATE
DOM_SCRIPTLESS_CROSS_REPOSITORY_PHASE1 = ADJUDICATED_SEE_G1_ADJUDICATION
G_UX1_PHASE1_CONTRIBUTION = SATISFIED
G_UX1_FULL_GATE = PENDING
PLATFORM_EVIDENCE_COMMIT_BINDING = COORDINATOR_CAPTURED_AT_PUBLICATION_TIP
REQUIRED_CHECK_RUNS_RECORDED_IN_TREE = NO_BY_DESIGN
OUTSTANDING_EVIDENCE_OBLIGATIONS = OPEN
CURRENT_PIN_CLEAN_REPRODUCIBILITY = PENDING
PRODUCTION = NOT_AUTHORIZED
MAINNET = DISABLED
PHASE2 = NOT_AUTHORIZED
REAL_FUNDS = PROHIBITED
```
