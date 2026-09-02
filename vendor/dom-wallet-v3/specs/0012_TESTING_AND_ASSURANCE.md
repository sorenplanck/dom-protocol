# DOM Wallet V3 Testing and Assurance

**Status:** REVIEW
**Owner:** Soren Planck

## Purpose and scope

This specification defines the evidence program required to implement and promote DOM Wallet V3 safely. It covers deterministic tests, adversarial tests, quality gates, evidence retention, and independent review. It does not claim that compilation, a test count, or a successful happy path proves wallet correctness.

## Authoritative sources and terminology

Authoritative sources are Specifications 0001 through 0011, DOM implementation and test authority, and comparative-study reports for test categories only. An **evidence item** binds a requirement, exact commit, environment, command, result, artifact digest, severity, and reviewer status. A **state-model runner** executes the canonical model and implementation against the same generated commands. A **failure artifact** is redacted deterministic input, trace, seed, cursor, and recovery state sufficient to reproduce a failure.

## Protected properties, boundaries, and assumptions

Tests, fixtures, node harnesses, ChainSource scripts, clocks, randomness, storage, transports, dependencies, build pipelines, and reports are all evidence boundaries. A test double may simplify transport or storage only when it preserves the domain contract being tested. Tests MUST NOT make unverified source data canonical or expose production secrets.

## Test infrastructure and data model

The test infrastructure MUST provide a deterministic clock; test-only randomness with recorded seed; transactional in-memory storage with acknowledgement and fault hooks; scripted ChainSource with StableView, hash divergence, lower-height, paging, and corruption controls; node harness; transport harness for duplication, reordering, delay, loss, and corruption; state-model runner; artifact factories for canonical records, envelopes, backups, V2 sources, slates, and malformed values.

Each test case records requirement identifiers, input seed, model and implementation Generation, ChainId, CanonicalCursor, result, failure classification, and redacted artifacts. Fixtures use synthetic values, are minimal and versioned, contain no credentials or real wallet material, and identify their intended schema and chain.

## Invariants and mandatory evidence

The evidence program MUST prove or expose failure for: reservation uniqueness; no partial logical commit; synchronization idempotency; same-height hash reconciliation; rollback-plus-replay equivalence to FreshReconciliation; valid restart or typed RecoveryRequired; monotonic non-reuse floors; cross-chain rejection; exact-byte retry; derived-balance equality; no secret leakage; bounded untrusted work; and every threat and invariant in 0001 and 0002.

DOM-W2-SYNC-001 requires directed evidence for same-height hash divergence, lower canonical height, missing hash, changed hash, unverifiable hash, restart between cursor and state publication, selection after every case, and repeated reconciliation.

## Approved ScanTarget assurance evidence

The following are required future implementation and verification evidence for the owner-approved ScanTarget WALLET POLICY in 0005 and its reorganization consequences in 0006. This list does not claim that any test exists, executes, or passes. Deterministic evidence MUST cover target creation from height and block hash; rejection of height-only targets; same-height hash divergence; lower canonical tip; missing target hash; changed target hash; unverifiable hash-at-height; source identity change; source disagreement; inconsistent page contents; repeated pages with conflicting data; missing pages; reordered pages; changed scan bounds; unexpected PMMR range expansion; a higher tip with bounded proof that the target remains canonical; a higher tip without ancestry proof; bounded ancestry exhaustion; timeout and retry-budget exhaustion; interrupted provisional scan; restart with a still-valid ScanTarget; restart with an invalidated ScanTarget; crash before activation; crash during atomic generation publication; rejection of partial-page activation; proof that the canonical cursor and every scan-derived mutation commit together; no cursor advancement after failed final validation; quarantine or deletion of invalid provisional state; full-rescan fallback; source switching with independent target revalidation; reorganization during a scan; reorganization during durable reorg replay; rollback-plus-replay equivalence with deterministic fresh reconciliation; and resource-bound enforcement under adversarial source behavior.

The harness MUST represent each target as height, block hash, source identity, bounded range, and evidence version. It MUST distinguish provisional staged state from canonical state and assert that no test double supplies a DOM Protocol StableView guarantee, snapshot witness, finality guarantee, or new node endpoint. DOM-W2-SYNC-001 remains mandatory and unchanged: height alone never establishes freshness or scan coherence.

## Required verification portfolio

| Evidence class | Required scope |
|---|---|
| Unit tests | Parsing, transition guards, capabilities, record invariants, arithmetic, redaction, and typed errors |
| Property tests | Generative invariants, serialization, allocation floors, balances, reservation uniqueness, idempotency, and bounded work |
| Executable reference model | Domain transitions compared with implementation under identical generated commands |
| Generated state-machine tests | Lifecycle, storage, sync, reorg, restore, migration, and API command interleavings |
| Integration tests | Storage, DOM validation, ChainSource, transport, backup, restore, and capability boundaries |
| Restart tests | Every durable acknowledgement and recovery phase |
| Reorganization tests | Same-height, lower-height, longer fork, removed and re-mined output or spend, and rollback convergence |
| Concurrency tests | Expected-Generation conflicts, reservations, allocation, restore, migration, and request replay |
| Corruption and adversarial tests | Truncation, wrong password, malformed fields, rollback, stale source, replay, exhaustion, and secret leakage |
| Compatibility and migration tests | Version negotiation, rejected downgrade, read-only V2 staging, source preservation, and post-migration lifecycle |
| Multi-wallet and multi-node end-to-end tests | Duplicate, reordered, delayed, unavailable, and conflicting evidence across wallet and node harnesses |
| Fuzz targets | Envelope, storage, backup, V2 source, canonical records, source replies, transaction context, API, and transport parsing |

## Valid behavior

The implementation is eligible for promotion only when each normative property maps to one or more evidence items and failures retain usable redacted artifacts. Miri and sanitizers SHOULD run where compatible with dependencies and platform. Dependency audit and deny checks, secret scanning, reproducible-build verification, release provenance, and independent review MUST be part of the later release gate.

Coverage measurement MAY identify blind spots but MUST NOT be a substitute for property evidence. A flaky test is quarantined only with a tracked severity, owner, deterministic reproduction investigation, and expiry policy; it MUST NOT be silently retried until green. Critical or high-severity invariant violations block promotion. Lower-severity findings require disposition, mitigation, and retest evidence.

## Invalid behavior

It is invalid to accept an unseeded nondeterministic failure without retaining a reproduction path, use a real credential in a fixture, treat a green happy path as proof of a threat treatment, remove a failing test without equivalent evidence, mark a requirement covered by unrelated compilation, or publish unredacted secret-bearing failure artifacts. A test harness MUST NOT permit unbounded generated work or resource exhaustion outside declared limits.

## Persistence and atomicity

Test storage MUST model old-or-complete-new durable acknowledgement, corruption, truncation, and restart. State-machine traces record durable boundaries and RecoveryEvents. Test reports are immutable evidence artifacts keyed by exact source commit and command; updating a report requires fresh execution evidence rather than copying a prior result.

## Crash and restart behavior

Every operation with a durable unit, external exposure, temporary file, source cursor, activation, or migration marker has tests before acknowledgement, after acknowledgement, and on reopen. Restart acceptance is either valid canonical state or a typed recovery state with bounded next action. Silent repair or replacement secret generation is invalid.

## Reorganization, concurrency, replay, and idempotency

The state-model runner MUST generate ReorgPlans and compare rollback plus replay with FreshReconciliation. Concurrent command generation MUST include losing expected-Generation writers and duplicated delivery. Replayed requests, restores, migrations, and sync steps must converge or return their recorded typed outcome. DOM-W2-SYNC-001 cases are mandatory regression tests.

## Security, compatibility, and migration impact

Secret scanning covers source, documentation, fixtures, reports, configuration, and generated artifacts. Fuzz corpora and failure traces are redacted. Compatibility evidence does not authorize foreign protocol behavior. Migration evidence includes read-only source handling, deterministic reports, full backup, activation rollback, and local or regtest post-migration spend tests.

## Reporting, gates, and independent review

Each CI report MUST include exact commit, branch, environment, commands, requirement-to-evidence matrix, threat-to-test matrix, invariant-to-test matrix, result, skipped tests with reason, coverage interpretation, severity summary, blockers, failure-artifact locations, and reviewer status. Reproducible builds and release provenance require independently repeatable inputs and outputs. Independent review occurs after implementation and evidence completion and MUST include cryptographic, storage, chain-source, lifecycle, recovery, API, migration, and adversarial test scope.

## Required verification

| Test class | Required coverage |
|---|---|
| Unit tests | Every invariant guard and invalid non-mutation path |
| Property tests | All global state, non-reuse, balance, and bounded-work properties |
| Executable-model tests | Every state-machine transition and convergence rule |
| Integration tests | All port boundaries and DOM validator interactions |
| Restart tests | All durable, exposure, and activation boundaries |
| Reorganization tests | Every DOM-W2-SYNC-001 case and 0006 convergence property |
| Concurrency tests | Every expected-Generation and idempotency boundary |
| Fault-injection tests | Storage, source, transport, crypto, backup, and migration failures |
| Fuzz targets | All untrusted parsers and recovery plans |

## Acceptance criteria for promotion from DRAFT to REVIEW

Promotion requires a complete requirement-to-evidence matrix for 0000 through 0011, approved deterministic harness design, severity and flake policies, CI gate design, failure-artifact retention rules, and independent-review scope. Implementation promotion requires executed evidence at the exact implementation commit; design-only evidence is not implementation evidence.

## Dependencies and unresolved decisions

This specification depends on Specifications 0001 through 0011.

CI platform matrix, coverage thresholds, supported sanitizer and Miri matrix, dependency-policy toolchain, reproducible-build environment, release-provenance format, failure-artifact retention duration, and independent-review provider remain unresolved pending approved engineering and release policy.

## Review Blockers

* DEC-ASSURANCE-RELEASE
* DEC-ECON-BLOCK-WEIGHT
