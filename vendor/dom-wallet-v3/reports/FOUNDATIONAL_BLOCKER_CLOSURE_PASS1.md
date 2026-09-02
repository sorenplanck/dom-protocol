# Foundational Blocker Closure Pass 1

**Owner:** Soren Planck
**Input commit:** 7a2a47b38e9daa5b5065a734c4f785c9aa67e708
**Branch:** main
**Review date:** 2026-07-11
**Previous verdict:** FOUNDATIONAL_CROSS_REVIEW_COMPLETE_BLOCKED

## Initial inventory and independent verification

The initial register contained 30 decisions: 7 RESOLVED, 23 BLOCKING, 4 HIGH, and 0 CRITICAL. The previous advisory count was 23 blocking decisions and matches the repository-derived initial blocker count. Read-only reviewers independently covered protocol/economics and cryptography, lifecycle/persistence, and synchronization/recovery/migration.

Every initial blocker received an initial verdict. CONFIRMED at pass start: DEC-ROLLBACK-PROTECTION, DEC-STABLE-VIEW, DEC-V3-SECRET-DOMAINS, DEC-ECON-BLOCK-WEIGHT, and the policy or evidence gaps listed in the decision register. REFUTED as REVIEW blockers: requirements whose complete conservative contract is already specified or can be selected as wallet policy, and requirements whose proof belongs to later implementation or assurance gates.

## Resolutions applied

Current DOM consensus code and validation tests resolve DEC-ECON-BLOCK-WEIGHT: coinbase contributes one output plus one kernel, totaling 23 weight units. DOM RFC0011 exclusion language is documentation drift; wallet policy does not choose the consensus rule. DEC-ECON-WALLET-POLICY resolves to bounded deterministic selection, exact-spend zero change, one positive change, checked arithmetic, and authoritative revalidation.

DEC-CRYPTO-ENVELOPE-BINDING resolves by reusing the current DOM encrypted-envelope contract without inventing AEAD associated data: authenticated encrypted plaintext carries WalletIdentity, ChainId, purpose, and version and validates them before activation. DEC-KDF-UPGRADE resolves by pinning the current DOM versioned Argon2id, HKDF-SHA256, and ChaCha20Poly1305 profile and rejecting unknown profiles. Zeroization, durability, retention, API, migration, and assurance proof requirements are correctly carried to later gates when their normative contract is already complete.

## Remaining blockers

| ID | Ownership | Severity | Exact missing evidence |
|---|---|---|---|
| DEC-ROLLBACK-PROTECTION | IMPLEMENTATION_PROOF | MEDIUM | A cross-device monotonic witness or equivalent platform evidence for detecting replay of an older valid full-wallet generation. |
| DEC-STABLE-VIEW | DOM_PROTOCOL | HIGH | DOM node interface or RFC defining a V3 multipage StableView binding, hash-at-height and bounded ancestry evidence. |
| DEC-V3-SECRET-DOMAINS | CRYPTOGRAPHIC_REVIEW | HIGH | Approved V3 private-context, backup, and authentication domain construction, vectors, and independent cryptographic review. |

No WALLET_POLICY, V2_MIGRATION_EVIDENCE, or ASSURANCE_GATE blocker remains. The remaining contracts cannot be closed safely by wallet policy.

## Promotion result

Specifications 0000, 0001, 0002, 0004, 0009, and 0012 are REVIEW. Specifications 0003, 0005, 0006, 0007, 0008, 0010, and 0011 remain DRAFT because the remaining high blockers directly affect their safety contract. Gate 0 remains COMPLETE and Gate 1 remains IN PROGRESS.

DOM-W2-SYNC-001 remains mandatory: height alone never proves freshness; nonmatching or unverifiable height-and-hash evidence reconciles or fails closed. The matrix and register were updated to retain canonical ownership and evidence mapping. README identity, banner reference, badges, sections, palette language, and closing statement were preserved.

## Validation and verdict

Validation checks authorized-file scope, status/index consistency, decision status, relative links, immutable artifact diffs, English prose, prohibited attribution, diff checks, and complete diff inspection. Implementation test execution remains a later-gate requirement and is not claimed by this report.

FOUNDATIONAL_BLOCKER_CLOSURE_PASS1_COMPLETE_PARTIAL
