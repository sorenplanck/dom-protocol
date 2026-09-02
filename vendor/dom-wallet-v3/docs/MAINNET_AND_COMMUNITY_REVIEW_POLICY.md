# Mainnet and Community Review Policy

**Status:** OWNER_APPROVED
**Owner:** Soren Planck
**Policy date:** 2026-07-11
**Selected secret-domain architecture:** OPTION_A_HARDENED_DOM_WALLET_CONTINUITY

## Authoritative owner policy

> “DOM Wallet V3 and DOM Protocol are authorized to implement and launch private testnet, public testnet, and mainnet without requiring an external cryptographic audit. External audits and independent reviews are welcome but optional and are never release, runtime, mainnet, wallet, transaction, mining, or fund-usage gates. The project follows an open community-review model. The software must not contain build-time, runtime, configuration, network, wallet, transaction, or user-interface restrictions based on audit status or on whether assets are described as real funds. Market value is external to protocol enforcement. Security constructions must still be explicitly documented, versioned, testable, reproducible, fail closed on invalid cryptographic input, and replaceable through compatible migrations. Unresolved security work remains visible and actionable but does not categorically prevent implementation or launch.”

## Scope and launch philosophy

This policy governs the launch and review model for DOM Wallet V3 and DOM Protocol. It authorizes private-testnet implementation and launch, public-testnet implementation and launch, and mainnet implementation and launch without an external-audit condition. It adopts an open-launch and continuous-community-review philosophy sometimes associated with open protocol projects; it does not claim equivalence to Bitcoin's security, adoption, history, review depth, or risk profile.

Authorization is not a security assurance. The software remains experimental and unaudited until evidence changes. This policy does not claim audit completion, formal verification, bug freedom, production safety, economic value, or absence of cryptographic risk.

## Community review and optional audits

Community review is `OPEN_AND_CONTINUOUS`. Public issues, patches, test vectors, reproducible reports, compatibility cases, and security findings are welcome at every stage. External audits and independent reviews are welcome evidence but are optional. No reviewer outcome, audit result, or asset-value characterization may become a build-time, runtime, configuration, network, wallet, transaction, mining, release, mainnet, or user-interface condition.

`EXTERNAL_AUDIT_REQUIRED=NO`
`INDEPENDENT_REVIEW_REQUIRED_FOR_LAUNCH=NO`
`AUDIT_STATUS_RUNTIME_ENFORCEMENT=PROHIBITED`
`REAL_FUNDS_RUNTIME_CLASSIFICATION=NOT_A_PROTOCOL_CONCEPT`

## DOM-first and Tauri-first continuity

DOM consensus, approved protocol semantics, transaction and slate formats, chain identity, and cryptographic primitives remain authoritative. Validated DOM Wallet V1/V2 properties and the established DOM Tauri desktop product direction are the primary continuity baseline. The official DOM symbol, dark-bronze-paper visual identity, onboarding, account/balance, send/receive, history, backup/recovery, settings, node configuration, diagnostics, and platform integration remain DOM product requirements.

Epic serves only verified gaps: durable private-context persistence before dependent effects, retry durability, explicit lifecycle deletion, reconciliation, recovery, state-machine clarity, abstraction boundaries, hostile-input handling, and assurance strategies. Epic UI, APIs, transport, protocol rules, derivation paths, parameters, formats, and workflows are excluded.

## Option A and cryptographic implementation obligations

Option A — Hardened DOM Wallet Continuity is selected. It preserves validated DOM-native transaction, slate, derivation, persistence, backup, recovery, and product behavior while rejecting the eight confirmed DOM weaknesses documented in the secret-domain reference study.

Implementation must provide explicit, versioned, testable, reproducible constructions and canonical contexts; fail closed on invalid cryptographic input; preserve nonce/blinding non-reuse; protect secrets from UI, IPC, logs, errors, telemetry, support bundles, filenames, and public identifiers; and support compatible security migrations. Construction identifiers, encodings, parameters, vectors, negative tests, property tests, interoperability evidence, backup/restore behavior, rollback behavior, rotation, and migration rules are engineering deliverables subject to continuous community review.

## Versioning, migration, and fail-closed behavior

Unknown versions, malformed or ambiguous encodings, chain/network mismatch, unavailable required evidence, and invalid cryptographic input must produce typed fail-closed behavior. Security improvements must be versioned and replaceable through compatible migration. Restore and migration must preserve non-reuse obligations and must never infer missing provenance. Rotation must not alter authoritative DOM fund derivation.

## Disclosure, intake, patches, and emergency response

The project will publicly track known security work and limitations without treating their existence as a categorical implementation or launch prohibition. Vulnerability reports and community findings should include a minimal reproducer, affected version, impact, and safe disclosure details. Patches receive normal community review, reproducible validation, compatibility analysis, and clear release notes. Emergency response prioritizes user safety, accurate disclosure, reversible mitigation where possible, compatible migrations, and prompt publication of the technical rationale.

## Authorization versus assurance

`PRIVATE_TESTNET_IMPLEMENTATION_AUTHORIZED=YES`
`PUBLIC_TESTNET_IMPLEMENTATION_AUTHORIZED=YES`
`MAINNET_IMPLEMENTATION_AUTHORIZED=YES`
`MAINNET_LAUNCH_NOT_CONDITIONED_ON_EXTERNAL_AUDIT=YES`
`IMPLEMENTATION_AUTHORIZED=YES`
`EFFECTIVE_DECISION_COUNTS=30_RESOLVED_0_BLOCKING_0_HIGH_BLOCKERS`

These authorizations do not represent an audit, a guarantee of safety, a claim of completed implementation, or an assertion about market value. They prohibit audit-status and asset-value enforcement from protocol and wallet behavior while keeping security work transparent and actionable.
