# Foundational Secret-Domain Options — Pass 1

**Input commit:** `d1b53d552397c6da8f9b0e03f0bfefd4d8855d6a`
**Branch:** `main`
**Pinned DOM evidence commit:** `aa7f389a157af1b1a486dcb7e27cb80e7b543de3`
**Date:** 2026-07-11
**Final verdict:** FOUNDATIONAL_SECRET_DOMAIN_OPTIONS_PASS1_COMPLETE

## Scope and boundaries

This pass documented DOM-native secret-domain evidence, the selected DOM Tauri product direction, and three non-selecting candidate families for independent cryptographic review. It did not access the Epic repository, did not read DOM source from its dirty working tree, did not change any specification or current-status artifact, did not select an option, and did not resolve DEC-V3-SECRET-DOMAINS.

DOM was inspected only through immutable Git objects at the pinned commit. The dirty DOM repository's HEAD, branch, index, tracked-change list, untracked-file list, and complete-status hash were captured before and rechecked after the study. Epic was used only through committed wallet-repository documents.

## Tauri continuity result

[DOM Tauri Product Continuity](../docs/DOM_TAURI_PRODUCT_CONTINUITY.md) records Tauri as the selected V3 desktop baseline. The DOM Wallet product identity, DOM symbol, dark-bronze-paper visual language, onboarding, balance/account presentation, send/receive/slate workflow, history, backup/recovery, settings, node configuration, diagnostics, and platform integration remain continuity requirements. V3 replaces unsafe backend coupling behind typed capability and domain boundaries; it does not copy Epic UI, API, transport, or product architecture.

## DOM evidence result

[The DOM reference study](DOM_WALLET_SECRET_DOMAIN_REFERENCE_STUDY.md) recorded validated DOM properties: V2 explicit pending-context persistence, retry retention and terminal wipe; DOM transaction/slate and fund-derivation compatibility; typed envelope rejection; versioned password-protected envelopes; atomic publication; complete V2 backup; chain mismatch rejection; and honest seed-only recovery boundaries.

It also confirmed V1 weaknesses that V3 must replace: public `blinding_hex`, password-only legacy backup handling, legacy password-derived coinbase compatibility, missing V3 domain construction, missing V3 AAD/binding decision, missing authenticated non-reuse/rollback witness, and missing unified authentication/secret-domain framework. Every historical concern examined is recorded as CONFIRMED or REFUTED in the reference study.

## Epic secondary role

The completed [Epic study](EPIC_SECRET_DOMAIN_REFERENCE_STUDY.md) is used only for verified gap-solving properties: durable private context before external effects, retry persistence, terminal deletion, repair/recovery categories, privilege separation, hostile-input handling, and assurance categories. It does not supply V3 cryptography, Tauri, UI, APIs, transport, chain semantics, or a unified secret-domain construction.

## Options, threat review, and reviewer gate

[Design options](../docs/FOUNDATIONAL_SECRET_DOMAIN_DESIGN_OPTIONS.md) defines exactly three DOM-native families: Hardened DOM Wallet Continuity (Option A), DOM-Native Labeled Subkey Hierarchy (Option B), and Hybrid DOM Fund Derivation with Independent Domain Roots (Option C). Option A is expressly DOM-first. None is selected, approved, secure, recommended, or implementation-authorized.

The options package evaluates cross-chain/network/wallet/account/purpose reuse, role confusion, nonce and blinding reuse, legacy exposure, backup and database rollback, old allocation state, credential substitution, KDF abuse, envelope attacks, migration provenance, frontend and Tauri IPC leakage, logging leakage, seed/authentication compromise, and partial writes. It defines only vector schema; every output remains `TO_BE_PROVIDED_BY_APPROVED_REVIEWED_CONSTRUCTION`.

The required gate is:

`DESIGN_OPTIONS_DOCUMENTED -> INDEPENDENT_CRYPTOGRAPHIC_REVIEW -> OPTION_SELECTED_OR_REJECTED -> CONSTRUCTION_SPECIFIED -> TEST_VECTORS_APPROVED -> SPECIFICATIONS_UPDATED -> IMPLEMENTATION_AUTHORIZED`

## Request update and status immutability

The cryptographic review request is appended with DOM/Tauri primary evidence, Epic secondary evidence, links to both reports and the options document, and explicit fields: selected option `UNSELECTED`, construction `NOT_SPECIFIED`, vectors `NOT_PROVIDED`, independent review `NOT_COMPLETED`. DEC-V3-SECRET-DOMAINS remains BLOCKING, owned by CRYPTOGRAPHIC_REVIEW, severity HIGH. Specifications, README, the decision register, the consistency matrix, protocol request, and all prior reports remain unchanged.

## Files written

- `docs/DOM_TAURI_PRODUCT_CONTINUITY.md`
- `docs/FOUNDATIONAL_SECRET_DOMAIN_DESIGN_OPTIONS.md`
- `docs/FOUNDATIONAL_CRYPTOGRAPHIC_REVIEW_REQUEST.md`
- `reports/DOM_WALLET_SECRET_DOMAIN_REFERENCE_STUDY.md`
- `reports/FOUNDATIONAL_SECRET_DOMAIN_OPTIONS_PASS1.md`

## Validation

Validation checks repository and identity preconditions; allowed-file scope; immutable DOM object-only access; DOM repository state before/after; absence of Epic access and background processes; unchanged specifications and current-status artifacts; Tauri continuity; no Epic product adoption; DEC-V3 status; option non-selection; no unapproved construction or parameter; all risk verdicts; pinned source references; English prose; relative links; prohibited attribution; readiness and real-fund claims; `git diff --check`; complete diff inspection; cached-diff inspection; commit identity; push synchronization; and final clean working tree.
