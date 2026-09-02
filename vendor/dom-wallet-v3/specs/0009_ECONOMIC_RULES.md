# DOM Wallet V3 Economic Rules

**Status:** REVIEW
**Owner:** Soren Planck

## Purpose and scope

This specification governs wallet policy around DOM-native selection and pre-submission validation. Transaction balance, fees, weights, limits, dust, coinbase, maturity, kernels, commitments, cut-through, and consensus validity derive exclusively from authoritative DOM consensus and policy. This document does not select a foreign formula, constant, or transaction representation.

## Authoritative sources and terminology

Authoritative sources are DOM consensus, transaction validation, economic RFCs, node and wallet tests, and Specifications 0001 through 0006. Specification 0002 defines OutputRecord and spendability; 0003 owns lifecycle; 0004 owns reservation atomicity; 0005 and 0006 own canonical evidence and reorganization.

**Consensus invalidity** means a DOM validation failure. **Wallet policy** is a privacy, availability, or resource preference that may reject an otherwise valid candidate. **EconomicPlan** is a deterministic recorded candidate set, output cardinality, fee result, change disposition, and policy version. It is not a new transaction format.

## Protected properties, boundaries, and assumptions

The economics component calculates only through approved DOM authority and receives canonical OutputRecords from the domain. It may not change ChainSource observations, maturity, local control, or reservations. A caller-supplied amount, fee preference, change request, or selection strategy is untrusted input. It MUST be bounded and validated before allocation or reservation.

## State and data model

An EconomicPlan references TransactionIntentId, ChainId, expected Generation, selected OutputRecord identifiers, intended amount, authoritative DOM fee and weight result, effective input and output cardinality, permitted change cardinality, policy version, and rejection or insufficiency reason. It records no secret and becomes part of 0003 preparation only after complete validation.

An output is eligible only when the exact 0002 spendable predicate holds: active ChainId, canonical unspent observation, mature status, available local control, no active reservation, and all DOM economic predicates. Coinbase maturity is calculated solely from authoritative DOM consensus and canonical origin.

## Invariants

1. The authoritative DOM validator is the final authority for balance, fee, weight, limits, kernels, commitments, cut-through, coinbase, and maturity.
2. Wallet policy MUST NOT present its preference as consensus invalidity.
3. A selection is bounded by approved search, input, output, work, and time limits; exhaustion returns a typed policy result without mutation.
4. Input sum, output sum, fee, and all checked arithmetic are revalidated at finalization and immediately before submission.
5. A candidate reserves outputs only in the 0003 preparation unit after a complete EconomicPlan validates.
6. No-change has effective change cardinality zero and is permitted only when authoritative DOM balance and fee validation succeeds. A caller-requested positive change plan MUST use a nonzero permitted cardinality before any division, modulus, allocation, or reservation.
7. A reorganization or maturity change invalidates prior eligibility and requires revalidation before finalization, repost, or submission.

## Valid behavior

For deterministic tests, selection MUST order candidates by descending value and then DOM commitment reference, use checked accumulation, and stop at declared consensus and wallet work bounds. Wallet policy permits exact spend with no change; otherwise it creates exactly one positive change output. Production policy MAY use a recorded privacy ordering only when it remains bounded and produces an equivalent valid economic plan. It MUST use authoritative DOM economics for every candidate.

Insufficient funds means no bounded eligible candidate satisfies amount plus the authoritative fee. It is distinct from a malformed request, immature funds, policy rejection, source uncertainty, or consensus invalidity. Dust treatment, maximum inputs, maximum outputs, fee preference range, and allowed change cardinality derive from approved DOM evidence; where authority conflicts or is absent, the wallet returns a blocking-policy result rather than selecting a rule.

Finalization and pre-submission revalidation MUST check that inputs remain canonical, mature, unreserved by another transaction, and compliant with the current DOM authority. A stale plan MUST be discarded or recomputed under the new Generation.

## Invalid behavior

The wallet MUST reject without reservation a negative or overflowing amount representation, invalid positive change cardinality, foreign-chain or provisional output, non-spendable input, unchecked arithmetic, unbounded search request, stale plan, insufficient candidate, or fee/weight rule derived from another protocol. It MUST NOT divide by a caller-supplied count before validating it, reserve before validation, treat a policy preference as a consensus rule, or use an old canonical cursor to authorize spending.

## Persistence and atomicity

EconomicPlan creation is pure until 0003 preparation. The accepted plan, selected outputs, reservations, any change allocation, TransactionRecord, PrivateTransactionContext, recovery record, and audit record are committed in one 0004 durable unit. A rejected plan does not advance Generation. Finalization records the authoritative validation result and exact bytes atomically with context disposition.

## Crash and restart behavior

Before preparation acknowledgement, no selection exists. After acknowledgement, restart validates the recorded plan, reservations, canonical evidence, and economic policy version before resuming. It MUST not reserve a substitute set or create replacement change material merely because a search was interrupted. Any uncertainty enters the lifecycle recovery flow.

## Reorganization, concurrency, replay, and idempotency

Reorganization recalculates chain observation and maturity through 0006. A plan using a removed, spent, immature, or provisional output becomes invalid and its lifecycle state is reclassified without erasing evidence. Concurrent preparation uses expected Generation and reservation uniqueness; only one candidate can reserve an output. Replayed selection with the same intent returns its recorded plan or outcome; a changed request is rejected.

## Security, compatibility, and migration impact

Selection details, amounts, account links, and candidate ordering are privacy-sensitive and MUST be redacted from diagnostics. Migration imports output evidence through 0011 and cannot make it eligible until reconciliation. Epic fee and weight formulas, constants, coinbase and maturity rules, kernels, commitments, cut-through behavior, dust policy, and selection windows are rejected.

## Required verification

| Test class | Required coverage |
|---|---|
| Unit tests | Eligibility, exact spend, no-change, invalid change count, insufficient funds, overflow, maturity, and policy-versus-consensus classification |
| Property tests | Derived-balance equality, fee sufficiency, reservation uniqueness, bounded termination, and no selection of an ineligible output |
| Executable-model tests | Generated selections, reservations, finalization, cursor changes, and reorganization invalidation |
| Integration tests | DOM validator-backed fee and weight checks, coinbase maturity, and lifecycle pre-submission revalidation |
| Restart tests | Interrupted plan, reservation, and finalization recovery |
| Reorganization tests | Same-height and lower-height reconciliation, removed input, maturity regression, and re-mined output |
| Concurrency tests | Competing selection, change allocation, and expected-Generation conflict |
| Fault-injection tests | Arithmetic, policy lookup, validator, storage, and source failures |
| Fuzz targets | Amounts, counts, selection preferences, output sets, and adversarial boundary values without panic or unbounded work |

## Acceptance criteria for promotion from DRAFT to REVIEW

Promotion requires a traceable DOM authority matrix for every implemented fee, weight, limit, dust, coinbase, maturity, and cardinality rule; deterministic test vectors; privacy-policy review; and economics-to-lifecycle test oracles. A source conflict or missing authority blocks implementation of the affected rule.

## Dependencies and unresolved decisions

Dependencies are 0001, 0002, 0003, 0004, 0005, 0006, and 0012.

Current DOM consensus code and validation tests control fee, weight, maturity, input/output limits, and coinbase treatment. The wallet policy above controls selection ordering and change strategy only; it MUST NOT invent a dust threshold. A future conflicting authority is rejected until the governing DOM source is corrected or superseded.
