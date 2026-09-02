# Foundational Specifications Pass 1

**Owner:** Soren Planck
**Result:** SPECIFICATION_PASS1_COMPLETE

## Inputs

Repository input commit: `581f0c7f8ba259d0255403d163203caae053e2a4`.

Epic reference commit: `cd3c9677cf67a68122a496cf601c47978cf99285`.

DOM study baseline: `aa7f389a157af1b1a486dcb7e27cb80e7b543de3`.

The governing decision was `DOM semantics > Epic strategy`. DOM Wallet V1 and V2 remain the evidence for DOM-specific experience and validated properties. The comparative reference was used only for protected properties, architectural strategies, failure handling, recovery methods, and test categories.

## Files read

Repository evidence read:

* `docs/REFERENCE_BASELINE.md`
* `docs/ENGINEERING_SOURCES.md`
* `docs/EPIC_DOM_ADOPTION_MATRIX.md`
* `docs/CONFIRMED_DESIGN_INPUTS.md`
* `docs/SPECIFICATION_GATE.md`
* `specs/0000_DESIGN_PRINCIPLES.md`
* relevant DOM Wallet V1/V2 storage, state, transport, restore, and backup terminology in `/home/leonardov/dom-protocol`

Study reports read:

* `00_EXECUTIVE_SUMMARY.md`
* `14_EPIC_DOM_EQUIVALENCE_MATRIX.md`
* `15_DOM_GAPS_CONFIRMED.md`
* `16_DOM_WALLET_VNEXT_DESIGN_INPUTS.md`
* `17_TEST_PORTFOLIO_FOR_DOM.md`
* `18_FINAL_VERDICT.md`
* `19_EPIC_FILE_BY_FILE_V3_FOUNDATION.md`

## Files written

* `specs/0001_THREAT_MODEL.md`
* `specs/0002_WALLET_STATE_MODEL.md`
* `specs/0004_STORAGE_ATOMICITY.md`
* `specs/0005_CHAIN_SOURCE_AND_SYNC.md`
* `specs/0006_REORG_AND_ROLLBACK.md`
* `specs/README.md`
* `reports/FOUNDATIONAL_SPECIFICATIONS_PASS1.md`

## Key decisions

1. The canonical wallet model is a chain-bound, versioned encrypted generation with distinct records for identity, accounts, derivation positions, outputs, reservations, transaction records, private contexts, cursor, recovery events, and redacted audit events.
2. Output chain observation, maturity, and local control are separate orthogonal dimensions. Spendability and balance are derived predicates, not mutable loose flags.
3. Every logical wallet operation has one backend-independent durable unit of work with expected-generation conflict detection, deterministic serialization, authenticated encryption boundary, durable acknowledgement, recovery event, and idempotency key where an external effect is possible.
4. Transaction bytes, private contexts, reservations, and related records cannot be split into plaintext or non-atomic sidecars.
5. A chain source provides bounded evidence only. Authentication of a source does not establish validity of its chain data.
6. Reorganization recovery is durable, bounded, evidence-based, provisional, and converges with deterministic fresh reconciliation for the same canonical chain and local intent.

## Confirmed requirement: DOM-W2-SYNC-001

`DOM-W2-SYNC-001` is incorporated as a mandatory design requirement in the synchronization and rollback specifications. Freshness compares both height and block hash. Same-height reorganization, lower-height canonical view, missing hash, changed hash, and unverifiable hash force reconciliation. Cursor advancement and all corresponding wallet changes commit atomically.

## Cross-spec consistency checks

| Concept | Consistent contract |
|---|---|
| Identifiers | Stable typed record identities; references are retained through reclassification and tombstones. |
| Cursor | Verified `(height, block_hash)` plus view evidence; never height alone; committed with matching observations. |
| Generations | Strictly increasing durable state generations, distinct from chain height, with expected-generation conflict detection. |
| Reservations | One active reservation per output; retained local-control evidence across reorganization until lifecycle resolution. |
| Transaction references | One stable transaction record links intent, private context, observations, recovery, and later lifecycle states. |
| Private contexts | Encrypted canonical-state records, never plaintext or non-atomic sidecars. |
| Recovery events | Durable, idempotent, phase-bearing records used for crash/restart across storage, sync, and rollback. |
| Crash terminology | Acknowledged DUW is authoritative; otherwise reopen validates old-or-new state and resumes durable intent or plan. |

## Unresolved decisions

* Anti-rollback protection against replay of an old but authenticated storage generation affects recovery integrity; it requires platform and storage evidence and is gated by assurance acceptance.
* Stable-view evidence format affects detection of moving or inconsistent sources; it requires DOM node capability analysis and is gated by chain-source design review.
* Exact canonical serialization encoding affects persistence compatibility and corruption handling; it requires storage and cryptographic review and is gated by storage review.
* Reservation expiry and final transaction reclassification affect lifecycle liveness; they require Specification 0003 and are gated by its review.
* Account policy, secret zeroization, backup recovery boundary, migration retention, source diversity, ancestor limits, and provisional-state interface policy are explicitly assigned to their later specifications and gates.

## Validation commands

The final validation commands are:

```text
git diff --check
git diff -- specs/0001_THREAT_MODEL.md specs/0002_WALLET_STATE_MODEL.md specs/0004_STORAGE_ATOMICITY.md specs/0005_CHAIN_SOURCE_AND_SYNC.md specs/0006_REORG_AND_ROLLBACK.md specs/README.md reports/FOUNDATIONAL_SPECIFICATIONS_PASS1.md
git status --short
```

The pass is specification work only. It creates no production implementation, migration, test implementation, fixture, continuous-integration change, commit, or push.

## Verdict

SPECIFICATION_PASS1_COMPLETE
