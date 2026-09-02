# Foundational Protocol Decision Request

**Owner:** Soren Planck
**Decision:** DEC-STABLE-VIEW
**Severity:** HIGH

DOM Wallet V3 requires one coherent multipage scan guarantee: target-tip binding, hash-at-height evidence, and bounded ancestry evidence. Current wallet2 ChainSource behavior exposes tip and scan range, not this V3 guarantee. The wallet can fail closed but cannot create a protocol witness.

Options: A, approve a DOM StableView node/RFC capability; B, approve an equivalent proof-capable interface; C, approve a documented limited source interface with fail-closed fallback. Required tests cover same-height divergence, lower tip, view change, missing hash, bounded ancestry failure, restart, and rollback-plus-replay equivalence.

**Approval:** APPROVED OPTION A / APPROVED OPTION B / APPROVED OPTION C / REJECTED FOR REVISION

## Owner Approval

**Approval date:** 2026-07-11
**Decision authority:** Soren Planck, project owner
**Result:** APPROVED OPTION C
**Final ownership:** OWNER_APPROVED_WALLET_POLICY_WITH_DOM_PROTOCOL_BOUNDARY
**Final status:** RESOLVED

> APPROVED OPTION C — Adopt the Epic-style limited ChainSource and bounded PMMR scan strategy, strengthened for DOM with mandatory target-tip height-and-hash binding, post-scan tip revalidation, atomic cursor activation, provisional results until validation, and fail-closed reconciliation or full-rescan fallback whenever coherent-view evidence cannot be established.

The approval selects a wallet policy over limited adapter evidence. It creates no DOM Protocol StableView guarantee, finality rule, protocol witness, or node endpoint. Specifications 0005 and 0006 own the contract; 0003, 0008, 0011, and 0012 consume it where applicable. Required future tests cover same-height divergence, lower target tip, changed, missing, or unverifiable target hash, source change or disagreement, page inconsistency, mutated bounds, bounded-ancestry exhaustion, interrupted work, restart, atomic publication, full rescan, source switching, reorg during scan, and rollback-plus-replay equivalence.
