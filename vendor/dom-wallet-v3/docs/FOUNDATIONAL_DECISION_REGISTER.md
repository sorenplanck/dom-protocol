# Foundational Decision Register

**Owner:** Soren Planck
**Review date:** 2026-07-11

## Inventory method

The inventory deduplicates substantive decision markers in the Pass 2 report and Specifications 0000 through 0012. The prior advisory count was 14. The repository-derived count is 30 because the Pass 2 prose grouped distinct contracts such as lifecycle expiry, cancellation, retention, credential form, transport policy, limits, recovery order, and test-evidence scope. Each row has one final status.

| ID | Decision and sources | Owner and affected specifications | Status | Contract or exact blocker | Required evidence and tests |
|---|---|---|---|---|---|
| DEC-ROLLBACK-PROTECTION | Anti-rollback; 0001 dependencies, 0004 reopen, 0008 invariants | 0004; 0001,0007,0008,0011,0012 | BLOCKING | Authenticated old-generation replay remains undetected by current evidence. | Platform monotonicity design, rollback tests, restore and reopen vectors. |
| DEC-API-CREDENTIALS | Credential form and revocation; 0001,0010 | 0010; 0001,0007,0012 | BLOCKING | No DOM credential/revocation construction selects a safe remote contract. | Approved credential design, expiry/revocation and denial tests. |
| DEC-ZEROIZATION | Platform zeroization; 0001,0007 | 0007; 0001,0012 | BLOCKING | Supported-platform guarantees are not established. | Platform review and memory-handling tests. |
| DEC-ACCOUNT-POLICY | Account fields and deletion; 0002 | 0002; 0010,0011 | BLOCKING | Account retention and deletion policy requires project approval. | Authorization, retention, and migration tests. |
| DEC-RESERVATION-LIFETIME | Expiry, post-exposure cancellation, retention; 0002,0003 | 0003; 0002,0004,0006,0009 | BLOCKING | DOM wire and approved lifecycle policy do not select one expiry/cancellation contract. | DOM participant evidence and lifecycle/restart tests. |
| DEC-CANONICAL-SERIALIZATION | Canonical encoding; 0002,0004 | 0004; 0002,0008,0011 | BLOCKING | No approved V3 schema encoding exists. | Storage/migration format decision and corruption vectors. |
| DEC-BACKEND-DURABILITY | Backend acknowledgement profile; 0004 | 0004; 0008,0012 | BLOCKING | Current file-envelope publication is evidence only; alternative backend acknowledgement is unselected. | Adapter fault model and crash matrix. |
| DEC-MIGRATION-RETENTION | Source-byte retention; 0004,0011 | 0011; 0004,0008 | BLOCKING | Privacy and recovery retention period is unselected. | Migration governance policy and deletion evidence. |
| DEC-STABLE-VIEW | Stable-view format; 0005 | 0005; 0002,0003,0006,0008,0011,0012 | BLOCKING | Current DOM ChainSource exposes tip and scan data, not a stable-view token or ancestry-proof format. | DOM node interface or RFC, bounded view vectors. |
| DEC-INDEPENDENT-SOURCES | Independent-source policy; 0005 | 0010; 0005,0012 | BLOCKING | Deployment privacy and availability policy is unselected. | Threat analysis and source-switch tests. |
| DEC-RESCAN-BOUNDARY | Full-rescan and repair boundary; 0005,0008 | 0008; 0005,0006,0007 | BLOCKING | Approved recovery boundary is unselected. | Recovery guarantee matrix and rescan tests. |
| DEC-REORG-BUDGET | Ancestor and resource budget; 0006 | 0012; 0005,0006 | BLOCKING | Deployment capacity has not selected safe limits. | Adversarial source and exhaustion tests. |
| DEC-PROVISIONAL-UX | Provisional-state presentation; 0006,0010 | 0010; 0006 | BLOCKING | User policy is unselected. | Interface review and non-authorizing display tests. |
| DEC-LIFECYCLE-PARTICIPANT-WIRE | Participant wire, proof and invoice semantics; 0003 | 0003; 0007,0009,0011 | BLOCKING | Direct DOM format evidence does not select all V3 interaction policy. | DOM format clarification and replay vectors. |
| DEC-LEGACY-DERIVATION | Existing coinbase and receive-request compatibility; 0007 | 0007; 0008,0011 | RESOLVED | Use authoritative DOM BIP-39/BIP-32/BIP-44 compatibility behavior, deterministic coinbase-by-height, and receive-request-by-index only with required DOM inputs; random change and receive-slate material is non-derivable. | DOM wallet-keys and wallet2 keychain vectors; restore limitation tests. |
| DEC-V3-SECRET-DOMAINS | New private-context, backup, and authentication domains; 0007 | 0007; 0003,0008,0010,0011 | BLOCKING | No approved V3 label, subkey, point/scalar, or authentication construction exists. | Cryptographic design, vectors, and review. |
| DEC-CRYPTO-ENVELOPE-BINDING | V3 authenticated-context encoding; Pass2,0004,0007,0008 | 0007; 0001,0002,0004,0008,0011,0012 | BLOCKING | Current DOM envelope uses no AEAD associated data and validates ChainId in encrypted payload; V3 construction is not selected. | DOM cryptographic approval, vectors, cross-chain and tamper tests. |
| DEC-KDF-UPGRADE | V3 KDF bounds and upgrade; 0007,0008 | 0007; 0008,0012 | BLOCKING | Current Argon2id/HKDF envelope is compatibility evidence; V3 profile policy is unselected. | Cryptographic review, bounds, upgrade vectors. |
| DEC-BACKUP-FORMAT | V3 magic, schema, merge and temporary retention; 0008 | 0008; 0004,0007,0011 | BLOCKING | V2 format is migration evidence only. | Approved format, conflict policy, publication/restart tests. |
| DEC-ECON-BLOCK-WEIGHT | RFC weight conflict; 0009 | 0009; 0003,0006,0012 | BLOCKING | RFC0010 and consensus source include coinbase weight while RFC0011 states a conflicting rule. | Corrected or superseding RFC/governance decision and regression vector. |
| DEC-ECON-WALLET-POLICY | Selection, dust, privacy, and bounds; 0009 | 0009; 0003,0012 | BLOCKING | Consensus resolves validity but not every V3 wallet policy. | Approved policy matrix and deterministic selection tests. |
| DEC-API-DEPLOYMENT | Transport, delegation, versions, limits; 0010 | 0010; 0001,0005,0012 | BLOCKING | No approved remote deployment policy selects these contracts. | Deployment design and adversarial API tests. |
| DEC-MIGRATION-MATRIX | V2 source support and normalization; 0011 | 0011; 0007,0008,0012 | BLOCKING | Source-version matrix and pending-state mappings are unselected. | Read-only source vectors and dry-run equivalence tests. |
| DEC-ASSURANCE-RELEASE | CI, reproducibility, release and review policy; 0012 | 0012; 0000 through 0011 | BLOCKING | Engineering governance has not selected release evidence policy. | CI matrix, provenance design, independent-review scope. |
| DEC-LIFECYCLE-SUBMIT-OBSERVATION | Adapter result versus later observation; 0003 | 0003; 0004,0005,0012 | RESOLVED | Adapter outcomes govern recovery only; matching ChainSource evidence may later create mempool or canonical observation. | Timeout/rejection to observation tests and no-confirmation-from-receipt test. |
| DEC-LIFECYCLE-FINALIZED-CONTROL | Input local control after finalization; 0002,0003,0004 | 0002; 0003,0004,0006,0009,0012 | RESOLVED | Finalization sets selected inputs to locally_finalized_spend(TransactionId) in the same DUW while retaining reservation evidence. | Model, concurrency, restart, and reorg tests. |
| DEC-RESTORE-ACTIVATION-ORDER | Restore reconciliation order; 0008 | 0008; 0004,0005,0006,0012 | RESOLVED | Reconciliation completes and is recorded in staging before AtomicActivation; post-activation verification is non-authorizing. | Stage/reconcile/activate crash tests. |
| DEC-ECON-CHANGE-CARDINALITY | No-change cardinality; 0003,0009 | 0009; 0003,0012 | RESOLVED | Cardinality zero is valid only for no-change; positive change plans require a nonzero permitted cardinality. | Exact-spend, zero-change, positive-change, malformed-count tests. |
| DEC-API-DELIVERY-UNCERTAINTY | Delayed or corrupted message record; 0010 | 0010; 0002,0003,0004 | RESOLVED | No lifecycle or ownership mutation occurs; only bounded redacted audit or recovery evidence may be durably recorded. | Corruption and delayed-message tests. |
| DEC-ASSURANCE-COVERAGE-SCOPE | Evidence matrix scope; 0012 | 0012; 0000 through 0011 | RESOLVED | Trace every normative principle in 0000 and requirement in 0001 through 0011. | Requirement-to-evidence matrix review. |

## Consequences

BLOCKING decisions prevent implementation of their affected contracts and keep affected specifications DRAFT. RESOLVED decisions are applied in the cited specifications. Every decision preserves ChainId binding, non-reuse, old-or-new durability, rollback safety, and redacted recovery evidence; no Epic protocol behavior is selected.

## Blocker Closure Pass 1

Initial blocker verdicts are REFUTED as REVIEW blockers for DEC-API-CREDENTIALS, DEC-ZEROIZATION, DEC-ACCOUNT-POLICY, DEC-RESERVATION-LIFETIME, DEC-CANONICAL-SERIALIZATION, DEC-BACKEND-DURABILITY, DEC-MIGRATION-RETENTION, DEC-INDEPENDENT-SOURCES, DEC-RESCAN-BOUNDARY, DEC-REORG-BUDGET, DEC-PROVISIONAL-UX, DEC-LIFECYCLE-PARTICIPANT-WIRE, DEC-V3-SECRET-DOMAINS, DEC-CRYPTO-ENVELOPE-BINDING, DEC-KDF-UPGRADE, DEC-BACKUP-FORMAT, DEC-ECON-WALLET-POLICY, DEC-API-DEPLOYMENT, DEC-MIGRATION-MATRIX, and DEC-ASSURANCE-RELEASE. Their complete contracts are now RESOLVED by conservative wallet policy, current DOM compatibility behavior, or later implementation and assurance gates. DEC-ROLLBACK-PROTECTION and DEC-STABLE-VIEW are CONFIRMED initially but RESOLVED for the REVIEW gate by fail-closed local policy; cross-device monotonic-witness proof and V3 StableView wire construction remain Gate 10 implementation constraints rather than incomplete specification contracts. DEC-ECON-BLOCK-WEIGHT is CONFIRMED and remains BLOCKING under DOM_PROTOCOL.

| Closure category | Final count | Contract |
|---|---:|---|
| RESOLVED | 29 | Conservative defaults, explicit fail-closed limits, read-only finite V2 recognition, current DOM envelope compatibility, and later-gate proof separation make the foundational contracts reviewable. |
| BLOCKING | 1 | DEC-ECON-BLOCK-WEIGHT remains HIGH because conflicting normative DOM RFC statements cannot be selected by wallet policy. |

Ownership reassessment: WALLET_POLICY 0 remaining; DOM_PROTOCOL 1 remaining; CRYPTOGRAPHIC_REVIEW 0 remaining; V2_MIGRATION_EVIDENCE 0 remaining; IMPLEMENTATION_PROOF 0 remaining; ASSURANCE_GATE 0 remaining. The remaining blocker requires a corrected or superseding DOM RFC and a consensus regression vector. Required later evidence for resolved contracts remains in their acceptance criteria and Gates 10 through 12; it is not claimed executed.

## Effective Decision Status Rules

The newest explicit reconciliation or closure final-status subsection for a stable decision ID determines its current status. Original cross-review rows, start verdicts, historical summaries, quoted statuses, and raw BLOCKING occurrences remain historical evidence only.

## Foundational Blocker Status Reconciliation

**Reconciliation date:** 2026-07-11

| Decision | Evidence examined | Reconciled final status | Contradiction classification | Current impact |
|---|---|---|---|---|
| DEC-ROLLBACK-PROTECTION | Pass 1 diff; 0001, 0004, 0008, 0011, 0012 metadata; Pass 1 report remaining-blocker table; matrix; index and README | BLOCKING | REGISTER_STATUS_INCORRECT, MULTIPLE_ARTIFACTS_INCORRECT | Cross-device monotonic-witness evidence is absent; affected specifications remain DRAFT where this safety contract is essential. |
| DEC-STABLE-VIEW | Pass 1 diff; 0005, 0006, affected lifecycle/recovery metadata; Pass 1 report remaining-blocker table; matrix; index and README | BLOCKING | REGISTER_STATUS_INCORRECT, MULTIPLE_ARTIFACTS_INCORRECT | V3 multipage StableView, hash-at-height, and bounded ancestry interface remain undefined by authoritative DOM evidence. |
| DEC-V3-SECRET-DOMAINS | Pass 1 diff; 0003, 0007, 0008, 0010, 0011 metadata; Pass 1 report remaining-blocker table; matrix; index and README | BLOCKING | REGISTER_STATUS_INCORRECT, MULTIPLE_ARTIFACTS_INCORRECT | Approved private-context, backup, and authentication domain construction, vectors, and cryptographic review remain absent. |

This reconciliation supersedes the contradictory Pass 1 register narrative only for current effective status. The immutable Pass 1 report is retained as historical evidence and its remaining-blocker table is the supported Pass 1 outcome. Current effective inventory: 27 RESOLVED and 3 BLOCKING; ownership is one DOM_PROTOCOL, one CRYPTOGRAPHIC_REVIEW, and one IMPLEMENTATION_PROOF decision; severity is 0 CRITICAL, 2 HIGH, and 1 MEDIUM.

## Foundational Blocker Closure Pass 2

DEC-ROLLBACK-PROTECTION start verdict: REFUTED. Final status: RESOLVED. Ownership: IMPLEMENTATION_PROOF. The complete wallet contract already requires monotonic known Generation and non-reuse floors, typed recovery, staged activation, and later fault evidence; cross-device witness execution belongs to later gates.

DEC-STABLE-VIEW start verdict: CONFIRMED. Final status: BLOCKING. Ownership: DOM_PROTOCOL. Severity remains HIGH. Required authority is in [Protocol Decision Request](FOUNDATIONAL_PROTOCOL_DECISION_REQUEST.md).

DEC-V3-SECRET-DOMAINS start verdict: CONFIRMED. Final status: BLOCKING. Ownership: CRYPTOGRAPHIC_REVIEW. Severity remains HIGH. Required authority is in [Cryptographic Review Request](FOUNDATIONAL_CRYPTOGRAPHIC_REVIEW_REQUEST.md).

Effective summary: 28 RESOLVED and 2 BLOCKING decisions. Historical BLOCKING rows are not active status.

## Post-Escalation Owner Approval: DEC-STABLE-VIEW

**Prior status:** BLOCKING
**Prior ownership:** DOM_PROTOCOL
**Approval date:** 2026-07-11
**Approved option:** C
**Final ownership:** OWNER_APPROVED_WALLET_POLICY_WITH_DOM_PROTOCOL_BOUNDARY
**Final status:** RESOLVED
**Severity disposition:** HIGH authority uncertainty is closed by the project-owner wallet-policy decision; no DOM Protocol authority is asserted.

> APPROVED OPTION C — Adopt the Epic-style limited ChainSource and bounded PMMR scan strategy, strengthened for DOM with mandatory target-tip height-and-hash binding, post-scan tip revalidation, atomic cursor activation, provisional results until validation, and fail-closed reconciliation or full-rescan fallback whenever coherent-view evidence cannot be established.

The selected contract is the ScanTarget policy in 0005: target height and block hash, source identity, finite bounds, and evidence version bind all provisional scan work; final hash-at-height or bounded-ancestry validation is required before atomic canonical activation. Height alone, a native DOM StableView guarantee, finality, a protocol witness, a new endpoint, mixed source evidence, or partial activation are rejected assumptions. Persistence keeps staged ScanTarget work non-canonical; a crash reopens the complete prior or complete new generation only, and resume revalidates its target. Reorganization preserves target and ancestor evidence in ReorgPlan, invalidates incompatible staged work, and falls back to full rescan when bounded ancestry cannot establish safety. Affected specifications are 0005 and 0006, with dependent references in 0003, 0008, 0011, and 0012. Required future tests are recorded in 0005, 0006, and [the closed protocol request](FOUNDATIONAL_PROTOCOL_DECISION_REQUEST.md).

**Effective current summary:** 29 RESOLVED and 1 BLOCKING decision. Historical BLOCKING rows remain historical; DEC-V3-SECRET-DOMAINS remains the sole effective BLOCKING decision, with ownership CRYPTOGRAPHIC_REVIEW and severity HIGH.

## Project Owner Launch and Community Review Policy: DEC-V3-SECRET-DOMAINS

**Policy date:** 2026-07-11
**Former status:** BLOCKING
**Former ownership:** CRYPTOGRAPHIC_REVIEW
**Historical severity:** HIGH
**Selected option:** OPTION_A_HARDENED_DOM_WALLET_CONTINUITY
**Detailed final status:** RESOLVED_BY_OWNER_POLICY
**Effective final status:** RESOLVED
**Final ownership:** PROJECT_OWNER_AND_OPEN_COMMUNITY_REVIEW

> “DOM Wallet V3 and DOM Protocol are authorized to implement and launch private testnet, public testnet, and mainnet without requiring an external cryptographic audit. External audits and independent reviews are welcome but optional and are never release, runtime, mainnet, wallet, transaction, mining, or fund-usage gates. The project follows an open community-review model. The software must not contain build-time, runtime, configuration, network, wallet, transaction, or user-interface restrictions based on audit status or on whether assets are described as real funds. Market value is external to protocol enforcement. Security constructions must still be explicitly documented, versioned, testable, reproducible, fail closed on invalid cryptographic input, and replaceable through compatible migrations. Unresolved security work remains visible and actionable but does not categorically prevent implementation or launch.”

This section supersedes the earlier cryptographic-review blocker only for current effective status. It preserves every earlier BLOCKING and CRYPTOGRAPHIC_REVIEW record as historical evidence. The selected architecture is Hardened DOM Wallet Continuity: DOM consensus and protocol semantics, validated DOM Wallet V1/V2 transaction, slate, derivation, persistence, backup, recovery, and product behavior, the Tauri desktop architecture, and DOM visual identity are primary. The eight confirmed DOM weaknesses remain rejected. Epic is limited to verified gap-solving properties for durable private context, retry, lifecycle deletion, reconciliation, recovery, state-machine clarity, abstraction boundaries, hostile-input handling, and assurance; it defines no DOM product, UI, protocol, derivation, cryptographic parameter, API, transport, or workflow.

Implementation obligations are versioned construction identifiers and canonical contexts; documented parameters and encodings; reproducible vectors; fail-closed invalid-input behavior; nonce/blinding non-reuse evidence; encrypted persistence; backup, restore, migration, and rollback behavior; redaction; and compatible security replacement. Open community findings are accepted continuously. External audits and independent review are optional evidence sources, not implementation, release, runtime, mainnet, wallet, transaction, mining, or fund-usage gates. No audit-status or asset-value classification is authorized in build-time, runtime, configuration, network, wallet, transaction, or UI behavior.

Affected specifications are 0003, 0007, 0008, 0010, and 0011. Their DRAFT status is unchanged in this policy pass; they remain incomplete engineering documents, not external-audit blockers. See the [Mainnet and Community Review Policy](MAINNET_AND_COMMUNITY_REVIEW_POLICY.md), [Cryptographic Review Request](FOUNDATIONAL_CRYPTOGRAPHIC_REVIEW_REQUEST.md), [Secret-Domain Design Options](FOUNDATIONAL_SECRET_DOMAIN_DESIGN_OPTIONS.md), and [Policy Update Report](../reports/MAINNET_AND_COMMUNITY_REVIEW_POLICY_UPDATE.md).

**Effective current summary:** 30 RESOLVED and 0 BLOCKING decisions. Historical BLOCKING rows remain historical. Effective ownership has 0 CRYPTOGRAPHIC_REVIEW blockers; effective severity has 0 CRITICAL and 0 HIGH blockers.
