# ADR Errata — Treasury Fee Collection Superseded by ACTF v1.1

**Status:** Draft for ratification  
**Date:** 2026-08-24  
**Applies to:** `ADR-DOM-PROTOCOL-FEE-MODEL-DRAFT.md` and any derived text that describes a separate Treasury settlement transaction.

---

## SUPERSESSION

The following earlier mechanism is superseded in full:

> Treasury percentage fees are collected pay-as-you-go in a separate DOM transaction and never in the atomic path of the swap.

After ACTF v1.1 ratification, the controlling rule is:

> For an ACTF-enabled interoperability route with a positive Treasury fee, the Treasury fee is a confidential output of the unique successful fee-bearing DOM claim. The route settlement and Treasury fee become effective in the same DOM transaction. A refund, abort, expiry, or failed route contains no Treasury percentage output.

Consequences:

1. no Treasury reserve is prepaid;
2. no Treasury debt accrues;
3. no epoch or batch settlement exists;
4. no post-route Treasury payment exists;
5. no percentage is placed in `kernel.fee`;
6. the fixed miner kernel fee remains unchanged;
7. a composed route has exactly one fee-bearing claim;
8. after `ACTF_PREPARED`, Treasury service availability is not required for funding, claim, or refund;
9. legacy F7 two-party routes remain unchanged;
10. `tau == 0` uses the legacy F7 path and creates no zero-valued output.

---

## PRECEDENCE

After ratification:

```text
ratified economic fee decision
    >
ACTF_V1_1_SPEC.md
    >
this errata
    >
non-conflicting legacy ADR text
```

Conflicting legacy paragraphs must be visibly marked `SUPERSEDED`. They must not remain as co-equal alternatives.

---

## IMPLEMENTATION HOLD

This errata and `ACTF_V1_1_SPEC.md` do not grant implementation or mainnet authority before G-F8 and the cryptographic acceptance gates specified by ACTF v1.1.
