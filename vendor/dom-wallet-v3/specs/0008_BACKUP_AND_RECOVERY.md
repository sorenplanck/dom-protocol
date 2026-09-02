# DOM Wallet V3 Backup and Recovery

**Status:** DRAFT
**Owner:** Soren Planck

## Purpose and scope

This specification defines seed-only recovery, V3 full-backup recovery, V2 migration recovery, and repair or full-rescan as distinct products. It specifies safety properties, staging, activation, and limits; it does not promise reconstruction of data that DOM derivation and canonical evidence cannot recover.

## Authoritative sources and terminology

Authoritative sources are Specifications 0000 through 0007, DOM Wallet V1/V2 backup and persistence code and tests, DOM wallet-crypto, DOM wallet-keys, and DOM consensus. A **FullBackup** is an encrypted snapshot of one validated canonical Generation. **AtomicActivation** is a 0004 durable unit that makes fully validated staging state active. **DeterministicReconciliation** is the idempotent reconciliation of the same local intent against the same StableView. **FreshReconciliation** is the comparison oracle for that result. A **RestoreReport** is a deterministic redacted report of validation, disposition, and reconciliation.

## Products and explicit guarantees

| Product | May recover | Must report or omit |
|---|---|---|
| Seed-only recovery | Deterministic DOM coinbase material only where canonical scan inputs satisfy the authoritative recovery contract | Receive-request recovery without its required authoritative inputs, non-derivable random change and interactive receive material, private contexts, finalized bytes, history, reservations, and metadata absent from seed and chain evidence |
| V3 full backup | All included canonical records from one authenticated Generation | The selected schema's declared omissions; it does not prove a newer local generation was not lost |
| V2 migration recovery | Validated V2 data normalized by 0011 | Unsupported, corrupt, ambiguous, or foreign-chain source material |
| Repair or full-rescan | Chain-derived observations and rebuildable indexes | It MUST retain local intent, allocations, non-reuse evidence, contexts, and records; it MUST NOT invent non-derivable data |

Seed-only recovery MUST NOT claim recovery of random blindings or an interactive context without full-backup evidence. Where DOM recognizes a deterministic coinbase or receive-request domain, its recovery remains subject to authoritative inputs required by that domain and canonical reconciliation.

## Trust boundaries, assumptions, and data model

Backup media, passwords, source files, temporary paths, and supplied parameters are untrusted. Export reads one validated Generation and MUST NOT mutate active state. Import parses bounded authenticated input only into staging. Active state changes only after domain validation, reconciliation, and AtomicActivation.

A V3 full backup format contains a format magic, format and schema versions, WalletIdentity, ChainId, active Generation, bounded KDF-profile identifier, AEAD metadata, manifest, and encrypted canonical payload. The manifest authenticates record classes, counts, lengths, and integrity coverage. The V3 magic, wire encoding, KDF profile representation, and associated-data construction are unresolved and MUST be approved before implementation; V2 magic and schema are migration-recognition evidence only.

The canonical payload MUST include WalletIdentity, Account records, ChainId, Generation, CanonicalCursor and StableView evidence, OutputRecords, Reservations, TransactionRecords, LocalIntents, DurableIntents, PrivateTransactionContexts and disposal evidence, derivation positions, NonReuseEvidence, ExposureRecords, RecoveryEvents, AuditEvents, ReorgPlans, finalized bytes where retained, and migration metadata. It MUST omit plaintext credentials, active unlock sessions, transport handles, transient caches, and rebuildable derived indexes; the RestoreReport MUST identify these omissions and their consequences.

## Invariants

1. A full backup represents exactly one internally validated Generation and binds all included chain-bound records to one ChainId.
2. Parsing validates bounds, magic, version, lengths, duplicates, schema rules, and authenticated ciphertext before constructing records.
3. Restore preserves the old active Generation until AtomicActivation; an invalid import leaves it unchanged.
4. Derivation and non-reuse floors advance to the maximum valid evidence and never decrease.
5. A restored output is not spendable until ChainSource reconciliation, maturity evaluation, and 0002/0009 predicates succeed.
6. A stale but authenticated backup is a rollback risk. It MUST be surfaced in the report; it MUST NOT silently replace newer evidence.
7. The merge policy for divergent V3 canonical records is reject-and-preserve until an approved conflict policy exists. V2 non-destructive merge ordering is not inherited.

## Valid behavior

Export validates the selected Generation, creates a uniquely named temporary output in the destination durability domain, writes the encrypted envelope, performs the selected file and directory synchronization, atomically publishes it, and records export completion only after its declared durability point. A temporary-file collision, sync failure, or publish failure returns a typed failure and preserves active state.

Import first derives keys under bounded work limits, authenticates the envelope, validates the manifest and canonical records, rejects wrong password without a distinguishing secret-bearing message, stages normalized state, advances floors conservatively, performs DeterministicReconciliation using the height-and-hash cursor rule, records completion in staging, and then atomically activates or aborts. The previous active Generation remains available until activation is durably acknowledged.

Repeated import with the same authenticated backup identity and request identity MUST return the recorded outcome or perform an equivalent no-op. A different byte sequence using the same request identity is rejected.

## Invalid behavior

The wallet MUST reject without activation a wrong ChainId, wrong password, corruption, truncation, unsupported critical version, duplicate canonical identity, malformed fixed-size field, oversized KDF or record parameter, unbounded nesting or collection, stale generation accepted as current, or unsupported conflicting record. It MUST NOT merge foreign-chain state, silently downgrade a record, overwrite active state during staging, expose an imported output as spendable before reconciliation, or declare a seed-only result equivalent to a full backup.

## Persistence and atomicity

Export and restore use 0004 durability semantics. Staging is non-active, encrypted where it contains secrets, bounded, and associated with a RecoveryEvent. AtomicActivation commits active records, generation, recovery completion, and redacted audit evidence together. Backup retention MAY retain prior published generations according to an explicit policy; deletion MUST be best-effort, evidenced, and never required to declare recovery complete.

## Crash and restart behavior

A crash before publication leaves only a recoverable temporary artifact or no artifact and never changes active wallet state. Restart validates or safely removes a known temporary artifact without treating it as a completed backup. A crash during import preserves staging or the old active Generation. A crash after activation acknowledgement reopens the new Generation and validates the completed staged reconciliation; it MAY run non-authorizing verification but MUST block selection if validation fails.

## Reorganization, concurrency, replay, and idempotency

Missing, changed, unverifiable, same-height divergent, or lower-height cursor evidence requires reconciliation under 0005 and 0006. Restore does not bypass DOM-W2-SYNC-001. Concurrent exports snapshot one acknowledged Generation. Restore and activation require expected Generation; a conflict preserves staging and returns a retryable conflict. Repeated restore and rollback-plus-replay MUST converge with FreshReconciliation.

## Security, compatibility, and migration impact

Reports, filenames, logs, and support bundles MUST be redacted. Passwords, seeds, and plaintext contexts MUST NOT be included. DOM V2 full backup and output backup formats are accepted only by 0011 read-only staging after direct source validation. Foreign backup formats, KDFs, derivation paths, and merge rules are rejected. Current DOM V2 envelope evidence protects chain binding in authenticated payload and validates it after decryption; whether V3 must use authenticated associated data for ChainId is an explicit blocking cryptographic decision, not a claimed existing property.

## Required verification

| Test class | Required coverage |
|---|---|
| Unit tests | Manifest, version, chain, duplicate, bounds, password, corruption, truncation, unknown-version, and stale-generation rejection |
| Property tests | Single-generation consistency, floor monotonicity, deterministic report, repeated restore convergence, and no downgrade |
| Executable-model tests | Export, stage, validate, reconcile, activate, abort, crash, and rollback commands |
| Integration tests | Full round trip, seed-only limitation matrix, migration staging, and restore followed by a local or regtest spend |
| Restart tests | Every temporary-write, synchronization, publish, stage, reconcile, and activation point |
| Reorganization tests | Same-height and lower-height divergence, removed or re-mined output, and cursor reconciliation after restore |
| Concurrency tests | Export snapshot conflict, simultaneous restore, and activation generation conflict |
| Fault-injection tests | Temporary path, write, sync, rename, directory durability, KDF, authentication, staging, and activation failures |
| Fuzz targets | Envelope, manifest, record framing, duplicate identities, nested collections, and corrupted ciphertext without panic or excess work |

## Acceptance criteria for promotion from DRAFT to REVIEW

Promotion requires an approved V3 format and bounded KDF policy, a reviewed seed-only guarantee matrix, complete inclusion or omission traceability for every 0002 record, staged-activation evidence, and restore-spend test oracles. A successful import alone is insufficient.

## Dependencies and unresolved decisions

Dependencies are 0001, 0002, 0004, 0005, 0006, 0007, 0011, and 0012.

The V3 magic and encoding, authenticated associated-data contract, bounded KDF profile policy, anti-rollback mechanism, divergent-record conflict policy, temporary-file retention policy, and repair boundary require cryptographic, storage, source, and migration review before implementation.

## Review Blockers

* DEC-CRYPTO-ENVELOPE-BINDING
* DEC-BACKUP-FORMAT
* DEC-ROLLBACK-PROTECTION
