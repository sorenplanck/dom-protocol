# Foundational StableView Approval

**Status:** COMPLETE
**Owner:** Soren Planck
**Input commit:** `2d3a9edccc8f71ed7f9d344d9e44b2fb0c1ece69`
**Branch:** `main`
**Approval date:** 2026-07-11
**Final verdict:** FOUNDATIONAL_STABLE_VIEW_APPROVAL_APPLIED

## Decision and authority

DEC-STABLE-VIEW originally had status BLOCKING, ownership DOM_PROTOCOL, and severity HIGH. Soren Planck, as project owner, approved Option C:

> APPROVED OPTION C — Adopt the Epic-style limited ChainSource and bounded PMMR scan strategy, strengthened for DOM with mandatory target-tip height-and-hash binding, post-scan tip revalidation, atomic cursor activation, provisional results until validation, and fail-closed reconciliation or full-rescan fallback whenever coherent-view evidence cannot be established.

The final status is RESOLVED. The final ownership is `OWNER_APPROVED_WALLET_POLICY_WITH_DOM_PROTOCOL_BOUNDARY`. The approval is a wallet policy over limited adapter evidence; it does not create a DOM Protocol StableView capability, snapshot guarantee, finality guarantee, protocol witness, or endpoint.

Epic-inspired strategy is limited to bounded ChainSource access, bounded PMMR traversal, refresh, scan, repair, and reconciliation. DOM-specific strengthening requires height-and-hash target binding, provisional state, final target validation, atomic activation, bounded ancestry, and fail-closed recovery.

## Approved ScanTarget contract

Specification 0005 is authoritative for the wallet-domain `ScanTarget` record with `target_height`, `target_block_hash`, `source_identity`, `scan_bounds`, and `evidence_version`. The adapter obtains and validates target height and target block hash before scanning; height alone is insufficient. It traverses only the bounded PMMR or output range corresponding to the target.

Every page, staged record, and discovered mutation is provisional and bound to the same ScanTarget. Provisional data cannot update the canonical cursor, confirmed balances, canonical output state, maturity, transaction confirmation, or completed reorganization state. Before activation, target hash-at-height and scan-bound correspondence are revalidated. A higher tip is accepted only with bounded ancestry or hash-at-height evidence proving the original target remains canonical.

Lower tip, changed, missing, or unverifiable target hash, source-identity change, source disagreement, inconsistent pages, repeated conflicting pages, missing or reordered pages, changed bounds, unexpected range expansion, unavailable ancestry, exhausted limits, timeout, or retry exhaustion invalidates or quarantines provisional state. The wallet then enters typed reconciliation, a fresh bounded scan, or full-rescan fallback. Source switching independently revalidates the same target or invalidates staged work.

Canonical activation atomically commits cursor `(height, block_hash)` with every scan-derived state mutation. A crash before activation preserves the prior generation; atomic publication reopens either the complete prior or complete new generation, never a mixture. Resumed work revalidates ScanTarget before reuse. Reorganization preserves target and ancestor evidence in ReorgPlan, performs bounded freeze, rewind, replay, validation, and activation, and uses full rescan when safe ancestry cannot be established. Rollback plus replay for the accepted canonical chain and retained local intent equals deterministic fresh reconciliation.

## Files and specification effects

Files read were `README.md`, `specs/README.md`, Specifications 0005, 0006, and 0012, `docs/FOUNDATIONAL_DECISION_REGISTER.md`, `docs/FOUNDATIONAL_PROTOCOL_DECISION_REQUEST.md`, and `docs/SPECIFICATION_CONSISTENCY_MATRIX.md`. Files read and written remained under `/home/leonardov/dom-wallet-v3`; no external repository was accessed and no background process was created.

Phase A files written were `specs/0005_CHAIN_SOURCE_AND_SYNC.md`, `specs/0006_REORG_AND_ROLLBACK.md`, `docs/FOUNDATIONAL_PROTOCOL_DECISION_REQUEST.md`, `docs/FOUNDATIONAL_DECISION_REGISTER.md`, and `specs/README.md`. Phase B files written were `specs/0012_TESTING_AND_ASSURANCE.md`, `docs/SPECIFICATION_CONSISTENCY_MATRIX.md`, this report, and `README.md`.

Specification 0005 owns ScanTarget acquisition, bounded page traversal, provisional evidence, final target validation, source switching, and canonical activation preconditions. Specification 0006 owns target invalidation consequences, bounded common-ancestor discovery, ReorgPlan, rewind, replay, restart, and fallback. Specification 0012 now defines required future deterministic ScanTarget evidence. The protocol request is closed by owner-approved wallet policy, and the decision register records the final ownership and status. The matrix assigns 0005, 0006, and 0012 their respective authorities.

Specifications 0005 and 0006 are promoted to REVIEW. The current total is eight REVIEW specifications and five DRAFT specifications. There are 29 effective RESOLVED decisions and 1 effective BLOCKING decision. DEC-V3-SECRET-DOMAINS is the sole remaining effective blocker, owned by CRYPTOGRAPHIC_REVIEW with HIGH severity; it is unchanged.

## Required future tests

Future deterministic evidence is required for target creation, rejection of height-only targets, all target-hash and tip divergence cases, source identity and disagreement, inconsistent, repeated-conflicting, missing, and reordered pages, bound and PMMR-range mutation, higher-tip validation with and without bounded proof, ancestry and retry exhaustion, interrupted and resumed scans, crashes before and during activation, no partial activation or cursor advance after failed validation, provisional-state quarantine, full rescan, source switching, reorganization during scan and replay, rollback-plus-replay equivalence, and adversarial resource bounds. These requirements are recorded in Specification 0012; no implementation or test execution is claimed.

## Verification and integrity

DOM-W2-SYNC-001 remains authoritative and unchanged: height alone does not prove freshness or coherence, and cursor plus justified state activate atomically. README identity, the official banner, Gate 0 COMPLETE, and Gate 1 IN PROGRESS are preserved. No protocol or cryptographic construction was invented. The cryptographic request, historical reports, banner, and visual-identity report remain unchanged.

Validation used repository-local checks for root and branch, Phase A preconditions, allowed changed-file names, effective decision statuses, specification counts, Markdown links, immutable-file diffs, `git diff --check`, full unstaged-diff inspection, cached-diff inspection before commit, author and committer identity, push synchronization, and final clean status.
