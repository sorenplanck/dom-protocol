# Foundational Specifications Pass 2

**Owner:** Soren Planck
**Base commit:** 69fe8f1889ca6ef1e78aa89074514deaeda725c0
**Branch:** main
**Result:** FOUNDATIONAL_SPECIFICATIONS_PASS2_COMPLETE

## Inputs and integrity

The initial authorized uncommitted files were specs/0003_TRANSACTION_LIFECYCLE.md, specs/0007_KEY_DERIVATION_AND_SECRETS.md, and specs/0008_BACKUP_AND_RECOVERY.md. Their substantive DRAFT content was reviewed, corrected, expanded, and retained where consistent with DOM evidence.

Epic reference commit: cd3c9677cf67a68122a496cf601c47978cf99285.
DOM comparative baseline: aa7f389a157af1b1a486dcb7e27cb80e7b543de3.

The governing decision remained DOM semantics > Epic strategy. Comparative evidence establishes observed protected properties and engineering lessons only. It does not establish live interoperability, a comprehensive security assessment, operational readiness, or any authorization beyond specification work.

## Existing-draft review results

The lifecycle draft correctly established durable preparation, exact-byte retry, and reorganization retention; it was expanded with identifier ownership, transition authority, evidence classes, result taxonomy, cancellation boundaries, and distinct test classes. The secrets draft correctly separated foreign cryptography; it was corrected to avoid treating V2 associated-data behavior as established and expanded with provenance, floors, session, parser, and review requirements. The backup draft correctly separated recovery products; it was expanded with manifest coverage, staging, activation, merge rejection, publication, and failure contracts.

## Files read

Repository inputs read: README.md; CONTRIBUTING.md; docs/ARCHITECTURE.md; docs/ENGINEERING_SOURCES.md; docs/REFERENCE_BASELINE.md; docs/EPIC_DOM_ADOPTION_MATRIX.md; docs/CONFIRMED_DESIGN_INPUTS.md; docs/SPECIFICATION_GATE.md; specs/0000_DESIGN_PRINCIPLES.md; specs/0001_THREAT_MODEL.md; specs/0002_WALLET_STATE_MODEL.md; specs/0004_STORAGE_ATOMICITY.md; specs/0005_CHAIN_SOURCE_AND_SYNC.md; specs/0006_REORG_AND_ROLLBACK.md; specs/README.md; reports/FOUNDATIONAL_SPECIFICATIONS_PASS1.md; and the initial complete diffs for 0003, 0007, and 0008.

Read-only reference evidence included DOM wallet-crypto, wallet-keys, wallet2 state, pending, persistence, backup, transport, consensus, transaction, slate, node, and relevant tests and fuzz targets. Comparative-study reports read were 00, 01, 03 through 05, 07 through 19, plus confirmed-findings, evidence-limitations, and equivalence-matrix artifacts under /home/leonardov/wallet-reference-study.

## Files written

- specs/0003_TRANSACTION_LIFECYCLE.md
- specs/0007_KEY_DERIVATION_AND_SECRETS.md
- specs/0008_BACKUP_AND_RECOVERY.md
- specs/0009_ECONOMIC_RULES.md
- specs/0010_API_AND_TRANSPORT_SECURITY.md
- specs/0011_MIGRATION_FROM_V2.md
- specs/0012_TESTING_AND_ASSURANCE.md
- specs/README.md
- reports/FOUNDATIONAL_SPECIFICATIONS_PASS2.md

## Specification summaries

| Specification | First-pass outcome |
|---|---|
| 0003 | Defines stable lifecycle identifiers, local and external evidence separation, transition authority, atomic reservation, exact-byte submission, uncertainty recovery, reclassification, and test obligations. |
| 0007 | Defines secret boundaries, provenance, floors, wrapper restrictions, DOM-backed envelope evidence, and cryptographic decisions requiring direct authority. |
| 0008 | Separates seed-only, full, migration, and repair recovery; defines staging, manifest coverage, activation, rollback risk, and restore tests. |
| 0009 | Separates DOM consensus from wallet policy; binds selection to canonical spendability, bounded work, reservation, revalidation, and economic evidence. |
| 0010 | Defines capabilities, local-safe binding, scoped unlock, bounded canonical parsing, transport uncertainty, redaction, and adapter limits. |
| 0011 | Defines read-only V2 source capture, staging, deterministic dispositions, conservative floors, reconciliation, backup, activation, and preservation. |
| 0012 | Defines deterministic model, harnesses, adversarial portfolio, evidence mapping, CI report content, severity, and review gates. |

## DOM properties preserved

The pass preserves DOM chain identity, DOM-native transaction and slate authority, consensus-controlled fees, weights, coinbase, maturity, kernels, commitments, cut-through, privacy, BIP-39 and BIP-32 evidence, distinct DOM derivation behavior, encrypted envelopes, atomic publication strategy, V2 full-backup and chain-check evidence, retained output records, and canonical reconciliation.

DOM-W2-SYNC-001 is mandatory across lifecycle, backup, economics, API gating, migration, and assurance: freshness compares BlockHeight and BlockHash, and missing, changed, unverifiable, same-height divergent, or lower-height evidence forces reconciliation.

## Epic strategies adopted conceptually

Conceptually adopted strategies are small domain and infrastructure boundaries, one atomic logical unit, private context before external exposure, reservation before delivery, explicit state machines, canonical checkpoint and scan, chain-bound versioned backup, least-privilege separation, delivery uncertainty handling, and property-oriented test categories.

## Epic-specific behavior rejected

Rejected behavior includes Epic source, tests, comments, identifiers, layouts, fee and weight rules, coinbase and maturity rules, kernels, commitments, proof rewind, derivation paths, KDF parameters, slate formats, transaction formats, compatibility behavior, API routes, and named transports.

## Cross-spec consistency

WalletIdentity and WalletId alias one immutable chain-bound identity. AccountId, TransactionId, TransactionIntentId, ReservationId, Generation, ChainId, BlockHeight, BlockHash, CanonicalCursor, StableView, OutputRecord, Reservation, TransactionRecord, PrivateTransactionContext, DurableIntent, RecoveryEvent, AuditEvent, LocalIntent, NonReuseEvidence, ExposureRecord, UncertaintyState, AtomicActivation, DeterministicReconciliation, FreshReconciliation, and ReorgPlan are aligned with the 0002 through 0006 model and explicitly extended by the new specifications.

Lifecycle uses 0004 durable units. Full backup contains the canonical state needed by 0002. Restore and migration preserve non-reuse floors. Economics uses the exact 0002 spendability predicate. APIs enforce 0001 least privilege. Assurance maps each normative property to planned evidence.

## Confirmed conflicts and unresolved blocking decisions

The confirmed conflict is that design-input language describes chain-bound associated data while inspected current DOM V2 envelope code authenticates and validates ChainId in payload after decryption rather than using AEAD associated data. V3 associated-data and chain-binding construction is therefore blocked pending direct DOM cryptographic authority and vectors.

Other blocking decisions are: anti-rollback mechanism; stable-view evidence form; canonical serialization; backend durability profile; lifecycle participant-wire, expiry, cancellation, and retention policy; V3 domain-label registry; point and scalar representation policy; KDF upgrade and bounds; V3 backup format and divergent-record policy; DOM economic rule matrix; credentials, revocation, remote transport, and limit policy; supported V2 source matrix; and CI, release, and independent-review policy. Each has an explicit owner specification and promotion gate.

## Threat-to-test summary

Remote and narrow-capability callers map to capability, expiry, parser-limit, replay, and redaction tests. Storage corruption and rollback map to envelope, crash, restart, and activation tests. Malicious or stale sources map to StableView, same-height, lower-height, rollback, and reconciliation tests. Backup theft maps to password, authenticated-envelope, bounded-work, and secret-leakage tests. Concurrent callers map to expected-Generation, reservation, allocation, and idempotency tests. Migration risk maps to source-preservation, dry-run equivalence, and post-migration lifecycle tests.

## Invariant-to-test summary

Reservation uniqueness maps to unit, property, concurrency, and model tests. No partial logical commit maps to durable-unit fault and restart tests. Non-reuse floors map to property, restore, migration, and reorganization tests. Exact-byte retry maps to lifecycle integration and restart tests. Derived-balance equality maps to economics property and integration tests. Cross-chain rejection maps to all parser, backup, API, and migration suites. Bounded untrusted work maps to parser and fuzz suites.

## DOM-W2-SYNC-001 coverage

Coverage is specified in 0003, 0008, 0009, 0010, 0011, and 0012. Required cases are same-height hash divergence, lower canonical height, missing hash, changed hash, unverifiable hash, interruption around cursor publication, selection after reconciliation, reorganization classification, restore, migration, and repeated synchronization idempotency.

## Validation commands and results

The completed change set was checked with: cargo metadata --no-deps --format-version 1; git diff --check; git diff --name-only; git diff --check --cached after staging; grep-based prohibited-phrase and language checks; non-empty and DRAFT status checks; specification-index checks; relative Markdown-link checks; complete diff inspection; git status --short; and git rev-list --left-right --count main...origin/main after push.

Results: only the nine authorized files changed; all required files are non-empty; all seven new specifications state DRAFT; the index lists 0000 through 0012 and records first-pass completion for 0001 through 0012; no prohibited attribution or unsupported readiness statement was found; Markdown links are relative and target existing files; diff checks passed; and the complete diff was inspected.

## Repository-integrity checks

The repository root, main branch, origin remote, base commit, author configuration, committer identity, initial unstaged authorized draft set, and absence of staged changes were verified before editing. Reference repositories, reports, artifacts, branches, indexes, and working trees were treated as read-only. Only the nine listed files were written.

## Verdict

FOUNDATIONAL_SPECIFICATIONS_PASS2_COMPLETE
