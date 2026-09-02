# Foundational Specifications Cross Review

**Owner:** Soren Planck
**Input commit:** f059767484139141c0ff05ebd95411c7c5b2c072
**Pass 2 commit:** 32b152bd81394d4236f6a43630b54aaa37354245
**Branch:** main
**Review date:** 2026-07-11
**Epic reference commit:** cd3c9677cf67a68122a496cf601c47978cf99285
**DOM comparative baseline:** aa7f389a157af1b1a486dcb7e27cb80e7b543de3

## Method and inventory

The review read the required repository documents, all foundational specifications, Pass 1 and Pass 2 reports, and authoritative DOM wallet-crypto, wallet-keys, wallet2, consensus, transaction, slate, RPC, node, RFC, test, and fuzz evidence as applicable. Comparative material was used only for protected properties and test categories. Three independent read-only reviews covered terminology/state, persistence/sync/recovery, and economics/API/assurance.

The repository-derived decision inventory contains 30 decisions: 7 RESOLVED and 23 BLOCKING. The prior advisory count was 14. The counts differ because the repository groups distinct contracts in prose and the review records each independently selectable contract.

## CONFIRMED findings

| ID | Severity | Contract, evidence, resolution, and validation |
|---|---|---|
| F-CRYPTO-001 | HIGH | 0004 required AEAD associated data while 0007/0008 left V3 construction unselected. DOM wallet-crypto encrypts and decrypts without AAD and V2 validates ChainId after decrypt. 0004 now requires authenticated identity fields without selecting construction; DEC-CRYPTO-ENVELOPE-BINDING blocks implementation. Cross-chain/tamper vectors are required. |
| F-LIFECYCLE-001 | HIGH | 0003 prohibited later mempool observation after timeout or rejection, contrary to ChainSource-owned observation. The lifecycle now permits matching source evidence regardless of adapter result; confirmation still requires sync DUW. Restart/node-result tests are required. |
| F-LIFECYCLE-002 | MEDIUM | Finalization omitted the 0002 local-control transition. 0003 and 0004 now atomically set selected inputs to locally_finalized_spend(TransactionId) and retain reservations. Model, concurrency, and reorg tests are required. |
| F-RESTORE-001 | HIGH | 0008 activated after reconciliation yet described unfinished post-activation reconciliation. It now records reconciliation in staging before activation and blocks selection if later verification fails. Crash tests are required. |
| F-ECON-001 | HIGH | 0003/0009 rejected zero change while allowing no-change. DOM slate and wallet2 payment support exact spend with absent change. The contract now distinguishes no-change cardinality zero from positive change cardinality. |
| F-ECON-002 | HIGH | DOM RFC0010/source and RFC0011 conflict on coinbase block weight. DEC-ECON-BLOCK-WEIGHT is BLOCKING pending corrected or superseding DOM authority. |
| F-API-001 | MEDIUM | 0010 allowed uncertainty recording without state mutation. It now permits only bounded audit/recovery evidence through a DUW and forbids ownership/lifecycle mutation. |
| F-ASSURANCE-001 | LOW | 0012 omitted 0000 from evidence scope. It now requires 0000 through 0011 traceability. |
| F-TERMINOLOGY-001 | MEDIUM | The register and matrix designate compatible authorities without inventing wire encodings: 0002 core state, 0003 lifecycle identifiers, 0005 StableView, 0006 ReorgPlan, and 0008 activation/reconciliation terms. |

## REFUTED findings

| ID | Concern and evidence |
|---|---|
| R-SYNC-001 | Height-only freshness survives. Refuted: 0003,0005,0006,0008,0011,0012 explicitly require height-and-hash reconciliation. |
| R-DURABILITY-001 | External effect may precede durable recovery state. Refuted: 0003 and 0004 require preparation or DurableIntent before delivery/submission. |
| R-RECOVERY-001 | Restore or migration can reduce floors. Refuted: 0007,0008,0011 require maximum valid evidence and no decrease. |
| R-API-001 | Epic API behavior is inherited. Refuted: 0010 explicitly rejects Epic routes and transports. |
| R-ASSURANCE-001 | A happy path is accepted as evidence. Refuted: 0012 expressly rejects compilation, count, and happy-path sufficiency. |

## Promotion and consistency result

All specifications remain DRAFT. Each has exact Review Blockers where applicable. No document is promoted because HIGH blockers affect its safety contract, including envelope binding, StableView evidence, rollback protection, or the conflicting economic authority. The consistency matrix is complete and every row has a CONFIRMED_CONSISTENT or CONFIRMED_CONFLICT_RESOLVED verdict.

Blocking severity summary: 0 CRITICAL, 4 HIGH, and 19 MEDIUM or LOW blockers.

| Specifications | Promotion result |
|---|---|
| 0000 through 0002 | DRAFT; foundational security, serialization, rollback, account, and deployment blockers remain. |
| 0003 through 0006 | DRAFT; participant, reservation, StableView, and bounded-reorg blockers remain. |
| 0007 through 0008 | DRAFT; V3 secret-domain, envelope-binding, backup-format, and rollback blockers remain. |
| 0009 through 0010 | DRAFT; conflicting block-weight authority and deployment-policy blockers remain. |
| 0011 through 0012 | DRAFT; migration-matrix and assurance-release blockers remain. |

DOM-W2-SYNC-001 was verified in state, storage, source, reorg, lifecycle, backup, migration, assurance, matrix, and this report. README identity was preserved: banner reference, badges, wallet sections, palette language, and closing statement remain. Gate 0 remains COMPLETE and Gate 1 remains IN PROGRESS.

## Validation and integrity

Validation checks only the authorized files; Markdown language and relative links; decision and finding statuses; index/README counts; DOM-W2-SYNC-001 consistency; prohibited attribution and unsupported readiness claims; banner and visual-identity report hashes; diff checks; complete diff inspection; author, committer, trailer, push, and branch synchronization checks.

Validation result: all reviewed findings are classified CONFIRMED or REFUTED, every decision-register row is RESOLVED or BLOCKING, all thirty inventory decisions are represented, every confirmed finding has an applied resolution or associated blocker, and the review is complete despite the remaining blockers.

## Verdict

FOUNDATIONAL_CROSS_REVIEW_COMPLETE_BLOCKED
