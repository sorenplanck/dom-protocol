# DOM Wallet V3 Migration from V2

**Status:** DRAFT
**Owner:** Soren Planck

## Purpose and scope

This specification defines a conservative migration from supported DOM Wallet V2 sources into V3 staging. It preserves source material, validates provenance and semantics, and activates only a reconciled canonical V3 generation. It does not mutate a V2 source, import a foreign wallet, or promise conversion of unsupported data.

## Authoritative sources and terminology

Authoritative sources are Specifications 0001, 0002, 0004 through 0008, DOM Wallet V2 persistence, backup, state, key, and transaction code and tests, and DOM consensus. A **MigrationSource** is a read-only source snapshot. A **SourceManifest** records source application, commit when available, schema, envelope or backup kind, ChainId, capture time, and digest. A **RecordDisposition** is Converted, RetainedAsEvidence, RequiresRecovery, OmittedWithConsequence, or Rejected. A **MigrationMarker** binds a completed staging result to a source digest and mapping report.

## Trust boundaries, assumptions, and data model

The source filesystem, backup media, password input, metadata, and ChainSource are untrusted. Migration reads a protected snapshot or offline copy; it MUST NOT open a source with write capability, change its index, rotate credentials, or delete any source file. The V2 source is preserved before and after V3 activation.

Staging contains SourceManifest, validated normalized WalletIdentity and Account mapping, OutputRecords, derivation positions and floors, NonReuseEvidence, ExposureRecords, Reservations, TransactionRecords, LocalIntents, DurableIntents, PrivateTransactionContexts and disposal evidence, history, cursor metadata, RecoveryEvents, AuditEvents, ReorgPlans where represented, source-to-V3 identifiers, RecordDispositions, difference report, and MigrationMarker. Unknown source data is retained as redacted source evidence only when safe and necessary for recovery; it is never treated as a valid V3 record merely because it parsed.

## Invariants

1. Source access is read-only and non-mutating; source preservation is verified before activation.
2. Supported source recognition requires an approved application, schema, envelope or backup kind, ChainId, and validation path. An unrecognized source is rejected.
3. Chain mismatch is rejected before state merge, display, selection, signing, or activation.
4. Derivation and non-reuse floors are the conservative maximum of valid source evidence, staging evidence, and post-scan evidence; they never decrease.
5. Every parsed source record has exactly one deterministic RecordDisposition and a redacted reason.
6. Migration uses a 0004 durable unit for complete converted state, marker, recovery event, audit event, and activation; partial active migration is forbidden.
7. Repeating the same dry run against the same source snapshot produces equivalent mapping, disposition, and difference reports apart from permitted timestamps.

## Valid behavior

The migration sequence is: preserve source; capture SourceManifest; validate envelope and records with bounded parsing; reject foreign chain; normalize into staging; classify outputs, indices, pending slates, private contexts, transaction history, backups, and metadata; advance floors; run global-invariant and balance validation; reconcile through ChainSource; write a V3 full backup; emit deterministic report; and atomically activate or abort.

Pending slates and contexts are not assumed final. They are normalized as valid V3 lifecycle evidence only after their DOM format, participant binding, context integrity, and uncertainty state validate. Otherwise they become RequiresRecovery or Rejected with source evidence. Finalized bytes are preserved only when authoritative DOM parsing and ChainId binding succeed. Source output balances are advisory; the post-migration derived balance is calculated from canonical V3 records after reconciliation.

The difference report MUST list source digest, source identity, ChainId, counts per disposition, identifier mapping, omitted classes and consequences, uncertainty, floor changes, reconciliation result, and activation decision without exposing secrets or transaction link detail. The V3 full backup is created from validated staging before activation and is not a substitute for preserving V2.

## Invalid behavior

The wallet MUST abort without activation on a mutable or unproven source, wrong ChainId, unsupported schema, failed envelope authentication, malformed fixed-size field, duplicate identity, unbounded input, ambiguous derivation mapping, conflicting non-reuse evidence, invalid global invariant, unexplained balance discrepancy, or reconciliation failure. It MUST NOT silently fabricate derivation positions, substitute a foreign slate or KDF, merge an unsupported record, delete V2, or make staged outputs spendable before reconciliation.

## Persistence and atomicity

The source manifest and staging records are encrypted and recoverable but non-active. AtomicActivation publishes all converted canonical state, MigrationMarker, mapping report digest, recovery completion, and audit evidence in one expected-Generation durable unit. Before acknowledgement the old V3 generation remains authoritative. After acknowledgement the prior V3 generation and V2 source remain preserved according to recovery policy.

## Crash and restart behavior

Crash before activation leaves V2 untouched and V3 active state unchanged; restart resumes or discards only validated staging based on RecoveryEvent. Crash after activation reopens the new generation, validates MigrationMarker and source digest, and resumes required reconciliation. It MUST NOT rerun conversion as a second logical import when the same marker exists.

## Reorganization, concurrency, replay, and idempotency

Migration reconciliation follows 0005 and 0006, including DOM-W2-SYNC-001: missing, changed, unverifiable, same-height divergent, or lower-height cursor evidence requires reconciliation. Concurrent migration, restore, or lifecycle mutation uses expected Generation; one operation wins and others leave source and active V3 state untouched. Replaying a request with the same source digest and identity returns the recorded result; changed bytes or manifest under the same request identity are rejected.

## Security, compatibility, and migration impact

Source paths, account labels, outputs, slate data, passwords, and private contexts are confidential and MUST be redacted from reports, logs, and support bundles. Compatibility is limited to explicitly approved DOM V2 source kinds. Epic formats, compatibility behavior, derivation paths, encryption, transactions, slates, APIs, and transports are rejected.

## Required verification

| Test class | Required coverage |
|---|---|
| Unit tests | Source recognition, read-only enforcement, envelope and record validation, dispositions, chain rejection, floor advancement, and balance validation |
| Property tests | Dry-run equivalence, deterministic report, no floor decrease, no duplicate mapping, and source preservation |
| Executable-model tests | Generated parse, normalize, stage, reconcile, backup, activate, abort, crash, and replay sequences |
| Integration tests | Supported V2 snapshots, pending contexts, history, full backup, and migrated local or regtest lifecycle |
| Restart tests | Every stage and activation acknowledgement boundary |
| Reorganization tests | Same-height, lower-height, removed output, and re-mined output reconciliation after migration |
| Concurrency tests | Migration versus restore, sync, selection, and repeated dry run |
| Fault-injection tests | Source read, password, parser, staging, backup, reconciliation, and activation failure |
| Fuzz targets | V2 envelope, backup, state, output, slate, context, index, and metadata parsers without mutation or panic |

## Acceptance criteria for promotion from DRAFT to REVIEW

Promotion requires an approved supported-source matrix, direct format vectors, read-only source proof, deterministic conversion and difference-report oracles, source-preservation evidence, full backup before activation, and migrated lifecycle tests. A parsed backup or a one-time conversion result is insufficient.

## Dependencies and unresolved decisions

Dependencies are 0001, 0002, 0004, 0005, 0006, 0007, 0008, and 0012.

The supported V2 source-version matrix, source-byte retention policy, exact normalization mappings for every V2 pending state, account-label policy, and post-activation rollback retention period require direct V2 evidence and review before implementation.

## Review Blockers

* DEC-MIGRATION-MATRIX
* DEC-CRYPTO-ENVELOPE-BINDING
