# Mainnet and Community Review Policy Update

**Input commit:** `fb16b5fedcb2bc7243e439c4d1f6b9bfbe563893`
**Branch:** `main`
**Date:** 2026-07-11
**Final verdict:** MAINNET_AND_COMMUNITY_REVIEW_POLICY_APPLIED

## Owner correction

The prior current-status artifacts treated DEC-V3-SECRET-DOMAINS as an effective HIGH blocker and described independent cryptographic review as a prerequisite for implementation progress. The project owner corrected that governance model. The exact approved policy is recorded in [Mainnet and Community Review Policy](../docs/MAINNET_AND_COMMUNITY_REVIEW_POLICY.md).

The owner selected `OPTION_A_HARDENED_DOM_WALLET_CONTINUITY`. The former detailed status `BLOCKING`, former ownership `CRYPTOGRAPHIC_REVIEW`, and historical HIGH severity are retained in the decision register. The new detailed status is `RESOLVED_BY_OWNER_POLICY`; the effective status is `RESOLVED`; final ownership is `PROJECT_OWNER_AND_OPEN_COMMUNITY_REVIEW`.

## Updated governance

The implementation baseline is DOM consensus and protocol semantics, validated DOM Wallet V1/V2 properties, DOM-native workflows, the existing Tauri desktop architecture, and the established DOM visual identity. Epic is limited to verified gap-solving properties for private-context durability, retry, explicit lifecycle deletion, reconciliation, recovery, state-machine clarity, abstraction boundaries, hostile-input handling, and assurance. Epic UI, APIs, transports, protocol semantics, derivation paths, parameters, and workflows are not adopted.

External audits and independent reviews are optional evidence sources. Community review is `OPEN_AND_CONTINUOUS`. Implementation, private testnet, public testnet, and mainnet are authorized without an external-audit condition. Audit status and whether assets are described as real funds are prohibited runtime or policy classifications. The project remains experimental and unaudited until evidence changes; authorization is not a safety, audit, or risk-free claim.

## Current effective result

| Measure | Result |
| --- | --- |
| Option selected | OPTION_A_HARDENED_DOM_WALLET_CONTINUITY |
| DEC-V3 detailed status | RESOLVED_BY_OWNER_POLICY |
| DEC-V3 effective status | RESOLVED |
| DEC-V3 ownership | PROJECT_OWNER_AND_OPEN_COMMUNITY_REVIEW |
| Effective decisions | 30 RESOLVED; 0 BLOCKING |
| Effective HIGH blockers | 0 |
| Specification status | 8 REVIEW; 5 DRAFT unchanged |
| Implementation authorization | YES |
| Mainnet launch conditioned on external audit | NO |
| Audit status runtime enforcement | PROHIBITED |
| Real-funds runtime classification | NOT_A_PROTOCOL_CONCEPT |

The five DRAFT specifications remain incomplete engineering documents. Gate 1 remains IN PROGRESS as a specification-completion tracker and is not a runtime, implementation, release, testnet, mainnet, wallet, transaction, mining, or fund-usage prohibition.

## Files read and written

Read: README.md; specs/README.md; docs/FOUNDATIONAL_DECISION_REGISTER.md; docs/FOUNDATIONAL_CRYPTOGRAPHIC_REVIEW_REQUEST.md; docs/FOUNDATIONAL_SECRET_DOMAIN_DESIGN_OPTIONS.md; and docs/DOM_TAURI_PRODUCT_CONTINUITY.md.

Written: README.md; specs/README.md; docs/FOUNDATIONAL_DECISION_REGISTER.md; docs/FOUNDATIONAL_CRYPTOGRAPHIC_REVIEW_REQUEST.md; docs/FOUNDATIONAL_SECRET_DOMAIN_DESIGN_OPTIONS.md; docs/MAINNET_AND_COMMUNITY_REVIEW_POLICY.md; and this report.

## Validation and integrity

Validation verifies the repository boundary, absence of external repository and network access other than the required Git synchronization, no background process, exactly seven modified files, unchanged specifications and implementation/Tauri/frontend source, Option A selection, DOM/Tauri primacy, Epic limitation, DEC-V3 effective resolution, counts, optional-audit policy, absence of audit/value runtime enforcement proposals, links, English prose, prohibited attribution, `git diff --check`, complete diff inspection, cached-diff inspection, commit identity, push synchronization, and clean final tree. Historical reports, assets, Cargo files, workflows, source, tests, fixtures, APIs, and migrations remain unchanged.
