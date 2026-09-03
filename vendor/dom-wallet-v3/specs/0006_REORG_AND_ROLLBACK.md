# DOM Wallet V3 Reorganization and Rollback

**Status:** REVIEW
**Owner:** Soren Planck

## Purpose and scope

This specification defines deterministic recovery when canonical DOM chain observations change. It applies to same-height reorganizations, lower observed tips, removed receives, removed spends, remine events, and interrupted rollback. It does not define consensus validity, final transaction lifecycle labels, or a source transport. DOM coinbase and maturity rules remain exclusively DOM consensus rules.

## Authoritative sources and terminology

Sources are 0000 through 0005, the confirmed DOM-W2-SYNC-001 finding, and DOM Wallet V1/V2 retained-output and canonical-reconciliation experience. A **reorg plan** is the encrypted durable recovery event that records a bounded rollback/replay operation. A **common ancestor** is the highest verified height/hash shared by the committed cursor and the ScanTarget being reconciled. A **provisional state** is a user-visible state in which chain-derived balances and selection are restricted until reconciliation completes.

## Entry conditions and protected properties

Rollback MUST begin when the mandatory freshness comparison in 0005 finds a same-height hash divergence, a lower-height canonical tip, a changed or missing cursor hash, a verified non-ancestor cursor, ScanTarget invalidation, source change, source disagreement, incompatible ancestry, or inconsistent staged scan evidence. It MAY begin after a later higher tip reveals prior divergence. It MUST NOT begin solely because an unauthenticated or malformed source makes an unsupported claim.

The protected properties are: no use of stale chain observation for spending; no loss of local intent, allocation evidence, private contexts, or retained historical records; DOM-native recalculation of coinbase maturity; bounded and evidence-based ancestry discovery; resumable atomic recovery; and convergence with fresh reconciliation.

## Bounded common-ancestor discovery

The wallet MUST compare the current cursor and new ScanTarget using hash-at-height and ancestry evidence under the one ScanTarget defined by 0005. It MUST search backward only within configured depth, response, time, and retry limits. It MAY use a bounded efficient search strategy, but every selected ancestor MUST be verified by height and hash; it MUST NOT guess an ancestor from height, timestamp, or a source assertion alone.

If no common ancestor can be proven within limits, if the source cannot produce required evidence, or if ScanTarget evidence changes during discovery, the wallet MUST enter a recovery-required provisional state and use the safe full-rescan fallback. The fallback retains local intent, derivation allocation evidence, reservations, private contexts, transaction records, audit history, and tombstones; it rebuilds only chain-derived observations and indexes from an approved boundary.

## Durable reorg plan and atomic phase order

A reorg plan has a stable `plan_id`, expected generation, old cursor, target ScanTarget evidence, verified ancestor evidence or full-rescan reason, affected range, durable phase, idempotency key, and recovery status. It is created in a DUW before rollback effects become externally visible. Its phases are:

1. **Planned:** persist entry evidence and set provisional state; selection from affected chain observations is blocked.
2. **Ancestor verified:** persist the bounded common ancestor or full-rescan decision.
3. **Rollback applied:** in one or more resumable DUWs, reclassify observations above the ancestor, recalculate maturity inputs, retain removed evidence, and atomically checkpoint the rewound cursor with each completed range.
4. **Replay applied:** scan and reconcile the target ScanTarget in ordered bounded ranges, keeping effects provisional until validation.
5. **Validated:** revalidate target hash, bounds, and required ancestry; verify invariants and convergence checks; atomically activate or clear provisional restrictions only in this DUW.
6. **Completed:** retain a redacted completion event and plan tombstone.

Each phase transition MUST validate expected generation. A crash leaves the last acknowledged phase authoritative. Restart during freeze, rewind, replay, validation, or activation MUST resume deterministically from that phase or fail closed. Repeating an acknowledged or incomplete phase MUST be idempotent. A reorganization during staged scan work MUST invalidate the ScanTarget and create a successor plan referencing the prior plan, or restart from the last committed safe checkpoint; it MUST NOT merge incompatible targets or clear provisional restrictions prematurely.

## Reclassification rules

Chain observation, maturity, and local control remain separate as defined in 0002.

* A receive whose origin leaves the canonical chain becomes `removed_from_canonical`; its value, ownership evidence, derivation reference, and tombstone are retained. It is not counted as confirmed, mature, or spendable.
* A locally controlled output whose canonical spend is removed becomes `canonical_unspent` only after replay verifies its origin remains canonical; its maturity is recalculated, and local control remains reserved or finalized if local intent requires it.
* An output whose origin and spend both leave the chain becomes `removed_from_canonical` with retained evidence. It MUST NOT be silently restored to available.
* A transaction record is reclassified only through the lifecycle contract of 0003, using explicit chain-observation evidence. It MUST retain prior observation and recovery linkage.
* Active reservations remain unique and durable. A rollback MUST NOT automatically release a reservation merely because a submitted spend leaves the chain; 0003 decides release, replacement, cancellation, or continued recovery subject to 0002 invariants.
* Pending spends remain local intent. Their external acceptance or chain observation is reconciled after replay using their durable idempotency keys and canonical DOM transaction reference.
* Coinbase maturity MUST be recalculated from the output's replayed canonical origin and current DOM consensus maturity rule. A removed or moved origin MUST not retain a maturity conclusion from the old branch.

## Cursor, persistence, crash, and restart behavior

The cursor may move backward only through a reorg-plan DUW that contains the corresponding record reclassification and replay checkpoint. It may move forward only through the synchronization DUW of 0004 and 0005. It MUST always include both height and hash. A plan cannot be declared complete based on matching height alone.

On restart, open validation MUST locate the active plan, validate its old cursor, plan range, phase, references, and current canonical state, then resume deterministically. If plan bytes, ancestry evidence, or a required private-context reference are corrupt, normal operation MUST remain blocked while a safe full rescan or authenticated recovery procedure is selected. No restart path may discard a removed receive or allocation evidence to make progress.

## Valid and invalid behavior

Valid rollback is bounded, evidence-based, atomic by phase, idempotent, and visibly provisional. Valid replay uses one ScanTarget and fresh cursor checkpoints. Invalid behavior includes height-only freshness, guessed ancestry, cursor rewind without record changes, deletion of removed observations, automatic release of unrelated reservations, use of an immature coinbase, use of mixed target evidence, unbounded ancestor search, or treating a partial plan as final.

## Convergence requirement

For the same canonical chain and the same local intent, **rollback plus replay MUST equal deterministic fresh reconciliation**. Equality means the same wallet identity, retained record identities, chain observations, maturity results, cursor, active reservations, transaction references, private-context linkage, recovery completion state, and derived spendability/balance projections, except for allowed redacted audit timestamps and plan identifiers. Implementations MUST test this semantic equality directly.

## Security considerations

Reorganizations are normal protocol behavior, not evidence of corruption by themselves. A malicious source can force work; limits and provisional fail-closed behavior prevent it from forcing speculative spending or unbounded resource use. User-visible status MUST state that observations are provisional without exposing ownership, private context, or detailed source data. Full rescan is a safety fallback, not permission to abandon chain binding or non-reuse evidence.

## Required verification

| Test class | Required coverage |
|---|---|
| Unit tests | Entry-condition classification, ancestor evidence validation, every output reclassification, coinbase maturity recalculation, cursor phase rules, and invalid non-mutation. |
| Property tests | Rollback plus replay equals fresh reconciliation for generated forks and local intent; retained identity and reservation uniqueness survive arbitrary repeated plans. |
| Integration tests | same-height hash divergence, lower canonical tip, target invalidation, incompatible ancestry, source change, source disagreement, longer reorg, removed receive, removed spend, remine, active reservation, pending spend, source switching, and full-rescan fallback. |
| Fault-injection tests | Crash before and after every plan phase DUW, corrupt plan, source change during discovery/replay, reorg during staged scan or reorg, exhausted depth/response limits, and restart during freeze, rewind, replay, validation, and activation. |
| Fuzz targets | Ancestor evidence, plan records, cursor records, scan-range boundaries, and malformed chain observations; no panic, guessed ancestry, or unbounded work. |

## Acceptance criteria for ACCEPTED

The required future evidence includes a complete convergence oracle, same-height and lower-tip cases, ScanTarget invalidation, phase atomicity from 0004, target validation from 0005, and compatible lifecycle reclassification and reservation outcomes from 0003. REVIEW records the complete policy contract; it does not claim execution of that evidence.

## Dependencies and unresolved decisions

Dependencies are 0001, 0002, 0003, 0004, and 0005. Specifications 0007 through 0009 contribute secret recovery, backup boundary, and DOM economic/maturity validation.

* **Maximum automatic ancestor depth and rescan resource budget:** a conservative bounded policy is required by 0005; deployment calibration is later assurance evidence at 0012.
* **User policy for prolonged provisional state:** affects user experience without changing safety. Evidence required: approved interface policy. Gate: 0010 review.
* **Final lifecycle reclassification vocabulary:** affects transaction display and cancellation. Evidence required: 0003 lifecycle state machine. Gate: 0003 review.

## Review Blockers

None. DEC-STABLE-VIEW is resolved by the Owner-approved ScanTarget WALLET POLICY. DEC-REORG-BUDGET is later-gate assurance evidence, not a REVIEW blocker.
