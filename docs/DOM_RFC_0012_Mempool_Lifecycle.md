# DOM RFC-0012 — Mempool Lifecycle, Reorg Reinjection, and Same-Block Spends

Status: **Normative**
Extends: RFC-0007, RFC-0010
Depends on: RFC-0000, RFC-0007, RFC-0008, RFC-0010

---

## Motivation

The consensus/distributed-systems audit identified four under-specified areas in
the transaction-relay subsystem. Each was an *implicit* assumption rather than a
stated rule, which is exactly the class of ambiguity that lets independent
implementations (or the same implementation across restarts) diverge:

1. **Mempool restart policy** was implicit ("intentionally restart-empty") and
   coexisted with persistence scaffolding that *implied* the mempool was part of
   persisted/replayable state. Mixed semantics.
2. **Reopen revalidation** had no stated rule because the restart policy itself
   was unstated.
3. **Reorg reinjection** existed in code but its exclusion rules, ordering, and
   convergence guarantees were not documented.
4. **Same-block spends / cut-through** — direct-extension input validation
   consults only the *pre-block* UTXO set, which interacts with cut-through
   semantics in a way the spec never pinned down.

This RFC makes each rule explicit and normative. The governing principle, per the
DOM hardening rules, is: **choose the safer, simpler, more deterministic rule, and
document the rationale.**

The single invariant that ties all four decisions together:

> **The mempool is a local relay/liveness cache. It is never consensus state.
> Consensus validity is a pure function of the block and the canonical chain
> state, and never of local mempool contents.**

---

## 1. Mempool Restart Policy (Task 26) — VOLATILE

### 1.1 Decision

DOM adopts a **volatile mempool**:

- On node start/reopen the mempool is **empty by construction**.
- The mempool is **never persisted** as part of canonical or replayable state.
- Any on-disk mempool bytes left by an older build are **legacy state**; they are
  **cleared, never loaded**, on init (and defensively on every block connect and
  tx admission).

### 1.2 Rationale

- **Simplicity & determinism.** An empty-on-restart mempool has exactly one
  possible post-restart state. There is no decode path, no migration matrix, and
  no ordering question at startup.
- **Consensus-neutrality is trivial to prove.** Because no validation path takes
  the mempool as an input, mempool state — present, absent, or restarted — cannot
  change which blocks are valid or which chain is canonical.
- **Fail-closed.** Corrupt or adversarial on-disk mempool bytes cannot inject
  unvalidated transactions into a running node, because they are never read into
  runtime state.

### 1.3 Consensus-neutrality (normative)

- `dom_consensus::validate_block` and the `dom-chain` connect/IBD/reorg/replay
  paths take only the block and canonical chain state. They take **no mempool
  argument**. This is a structural guarantee, not a convention.
- Mempool admission (`accept_tx_with_chain_view`) validates a candidate against a
  **snapshot of canonical chain state**, never against another node's mempool.

### 1.4 Network reconvergence (liveness, not safety)

Restart-equivalent *mempool* convergence is a **liveness/availability** property,
delivered by the relay layer, not by persistence:

- Transactions propagate via Dandelion++ relay (stem → fluff) on first receipt.
- A node advertises its mempool contents by canonical `tx_hash` (the INV listing,
  `Mempool::all_hashes`, sorted ascending), and peers re-request what they lack.

A freshly restarted node therefore re-acquires the live transaction set passively
from peers. Crucially, **a node that never re-acquires a pending transaction is
still fully consensus-correct** — it simply may not template that transaction into
a block it mines. No node can be forced into an invalid state by another node's
mempool, by construction (§1.3).

### 1.5 Replay snapshots

Because the mempool is not persisted, it is **not part of the canonical
replay-equivalence snapshot**. The replay snapshot captures persisted, restart-
surviving state (chain tip, IBD session, peer rotation). The live mempool hash
listing may be captured as a **runtime convergence diagnostic**, but it is
explicitly labelled as non-persisted, non-consensus state and is not expected to
survive a restart.

---

## 2. Reopen Revalidation (Task 27) — NOT APPLICABLE (by design)

Task 27 ("revalidate every persisted mempool transaction on reopen") is **not
applicable** under the volatile policy, because no mempool transaction is ever
persisted or loaded. There is therefore no persisted transaction to revalidate.

The volatile policy is enforced and proven rather than left implicit:

- **No blind load.** `DomNode::init` never reads on-disk mempool bytes into runtime
  state; it calls `clear_persisted_mempool_snapshot` and constructs `Mempool::new()`.
- **Fail-closed on legacy/corrupt bytes.** If an older build (or an adversary with
  disk access) left mempool metadata, init clears it and starts empty regardless of
  whether the bytes decode.
- **Deterministic.** Restart state is independent of pre-restart mempool contents.
- **Consensus unchanged.** Chain validity after restart is identical with or without
  any pre-restart mempool state (§1.3).

These properties are covered by dedicated tests (see the test list in the task
report). Should DOM ever adopt a persistent mempool, this section must be replaced
with a full revalidate-on-reopen specification (validate each persisted tx against
the current canonical UTXO, drop spent/conflicting/immature/corrupt entries
deterministically, apply canonical ordering, and include a mempool digest in the
replay snapshot).

---

## 3. Reorg Reinjection (Task 28) — DETERMINISTIC

### 3.1 Decision

When a reorg disconnects blocks, transactions from those blocks that are still
valid under the **new** canonical chain are reinjected into the live mempool, in
canonical order. Reinjection affects **transaction availability only**, never block
validity (§1.3).

### 3.2 Candidate set and exclusions

The candidate set is exactly the regular transactions of the disconnected blocks
(`ReorgDelta::disconnected_txs`). The following are excluded:

- **Coinbase transactions** — *structurally* excluded: `disconnected_txs` is built
  from `block.transactions`, which never contains `block.coinbase`.
- **Transactions invalid under the new canonical UTXO** — any candidate with an
  input that is not a live UTXO (or an immature coinbase) under the new tip is
  dropped.
- **Transactions whose outputs or kernels already exist** under the new canonical
  chain (already mined on the surviving branch) are dropped, preventing duplicate
  injection.

### 3.3 Conflict resolution and ordering (normative)

- Candidates are processed in **`tx_hash` ascending** order.
- Each candidate is revalidated against a snapshot of the **new** canonical UTXO.
- Double-spends are resolved deterministically by hash: when two candidates (or a
  candidate and an already-admitted transaction) reserve the same input, the
  first in `tx_hash` order wins; the later one is rejected by the mempool's
  input-reservation check.
- Confirmed-input cleanup for the connected branch runs **before** reinjection, so
  transactions invalidated by the new branch are removed first.

### 3.4 Convergence guarantee

Two nodes that experience the same reorg converge to the **same mempool digest**
(canonical hash-ordered snapshot), independent of the order in which they
originally received the disconnected transactions. This is the same
permutation-invariance the mempool guarantees for normal admission, applied to the
reinjection batch.

---

## 4. Same-Block Spends and Cut-Through (Task 29) — FORBIDDEN (Policy B)

### 4.1 Decision

A published block **must not** spend an output created earlier in the same block.
The canonical (post-cut-through) form of a block contains **no commitment that
appears as both a block input and a block output**. Any block violating this is
rejected unconditionally, before cryptographic checks.

This is RFC-0010 §3.3 ("block must be in canonical cut-through form"), here stated
as the formal same-block-spend rule.

### 4.2 Rationale

- It matches the existing DOM architecture: input validation against the
  *pre-block* UTXO set is **correct and complete** under this rule, because after
  cut-through every surviving block input necessarily spends a pre-existing
  (pre-block) UTXO. No path needs an intra-block output overlay.
- It is the simplest deterministic rule: there is no intra-block dependency graph
  to order, and no ambiguity about which internal spends survive.
- Cut-through (`apply_cut_through`) remains available as an *aggregation* utility
  (e.g. for relay/transaction merging), but it is **not** part of the consensus
  block-validation path. Consensus does not silently rewrite a submitted block;
  it requires the block to already be in canonical cut-through form and rejects it
  otherwise.

### 4.3 Path alignment (normative)

All of the following agree, because they share `dom_consensus::validate_block`
(which performs the §4.1 check) and validate inputs against the pre-block UTXO set:

| Path | Mechanism |
|------|-----------|
| Mempool admission | a tx spending an unconfirmed (same-block) output is rejected: its input is not in the canonical UTXO set |
| Miner assembly | selects only admitted mempool txs, so a dependent (same-block-spending) tx is never available to template |
| Direct-extension (live) validation | `validate_block` cut-through check + pre-block UTXO input check |
| IBD validation | same `validate_block` |
| Replay validation | same `validate_block` |
| Reorg candidate validation | same `validate_block` |

Because every path funnels through the same check, **live and IBD validation
cannot disagree**, and a reorg cannot reintroduce a same-block-spend inconsistency.

---

## 5. Summary of Invariants

- **I-1.** Consensus validity never depends on local mempool contents.
- **I-2.** The mempool is empty after restart; on-disk mempool bytes are cleared,
  never loaded.
- **I-3.** Reorg reinjection is deterministic (hash-ordered, conflict-resolved
  by hash) and convergent across delivery orders.
- **I-4.** A published block never spends a same-block output; all validation
  paths enforce this identically.
