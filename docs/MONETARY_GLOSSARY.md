# DOM Monetary Glossary

## Purpose

This glossary stabilizes terminology used in DOM's monetary doctrine and
hardening-oriented governance documents. It is descriptive, documentation-only,
and non-consensus-changing.

Normative consensus behavior remains defined by the implementation, normative
RFCs, and consensus-critical specifications. The definitions below clarify
doctrinal and operational language only. They do not redefine consensus,
implementation behavior, or monetary policy.

## Definitions

### Adversarial Resilience

The ability of the protocol and its supporting operational model to preserve
deterministic correctness under malformed inputs, hostile peers, crash events,
reorg conditions, and other non-cooperative environments.

### Bounded Runtime Safety

The property that validation, replay, recovery, and related operational paths
remain within explicit or controlled resource bounds. It matters because
deterministic correctness is weakened if valid processing depends on unbounded
runtime behavior.

### Canonical Accumulator Integrity

The condition that canonical accumulators, including state-committing data
structures, remain consistent with the accepted canonical history. It matters
because accumulator drift can corrupt state reconstruction without changing the
nominal rule set.

### Canonical Convergence

The property that honest nodes given the same valid history and consensus rules
converge on the same canonical state. It is a prerequisite for deterministic
monetary continuity across independent nodes.

### Canonical Monetary History

The accepted sequence of monetary state transitions that defines the valid
historical basis for replay, reconstruction, and balance interpretation.

### Canonical Persistence

The condition that persisted canonical pointers and durable state correspond to
the canonical chain rather than merely recent or locally observed state.

### Canonical State

The protocol state that corresponds to the accepted canonical history under the
active consensus rules and deterministic reconstruction path.

### Cleanup Convergence

The property that cleanup, compaction, rebuild, or reconciliation paths arrive
at the same valid end state as fresh deterministic replay. It matters because
maintenance paths must not create alternate monetary interpretations.

### Conservative Protocol Evolution

An evolution discipline that prefers small, reviewable, hardening-aligned
changes over rapid feature expansion. It treats replay safety, persistence
correctness, and operational predictability as gating concerns.

### Deterministic Monetary Integrity

Monetary integrity evaluated not only as rule-bound issuance, but as the
ability of independent nodes to reconstruct, verify, and preserve the same
monetary state under replay, restart, recovery, and adversarial conditions.

### Deterministic Monetary State

A monetary state that can be reproduced from the same canonical inputs without
implementation-dependent ambiguity. It matters because balances and supply
constraints are only reliable when state reconstruction is deterministic.

### Deterministic Recovery

Recovery behavior that detects, refuses, or rebuilds unsafe partial state in a
way that preserves deterministic protocol interpretation. It does not imply that
all failures are automatically recoverable.

### Deterministic Replay

Replay of canonical history that yields the same resulting state when executed
from the same inputs under the same rules. It is the operational basis for
verifiable monetary continuity.

### Deterministic State Transition

A state transition whose accepted inputs and resulting outputs are not left to
implementation discretion. Deterministic state transitions reduce ambiguity in
monetary validation and reconstruction.

### Durable State Reconstruction

Reconstruction of usable protocol state from durable records in a way that is
consistent with canonical history and deterministic validation rules.

### Monetary Entropy

Growth in monetary ambiguity caused by non-deterministic processing, unsafe
state continuation, inconsistent reconstruction, or unclear canonical history.
It is undesirable because it weakens monetary predictability without formally
changing policy.

### Monetary Integrity

The condition that issuance, validation, historical reconstruction, and durable
state continuity remain coherent under the protocol's rule set.

### Operational Predictability

The expectation that protocol-relevant behavior remains stable enough to be
reasoned about, validated, and recovered without hidden state-dependent
surprises. It matters because operational volatility can become monetary
ambiguity in distributed systems.

### Persistence Integrity

The condition that persisted state remains internally consistent and aligned
with valid protocol interpretation. It matters because corrupted or semantically
incorrect persistence can distort replay and restart outcomes.

### Persistence Safety

The property that persistence behavior does not silently weaken deterministic
correctness during commit, reopen, crash, rollback, or rebuild paths.

### Persistence-Safe Evolution

Protocol evolution disciplined so that changes do not introduce ambiguous
persistence behavior, unsafe reopen semantics, or divergent reconstruction
paths.

### PMMR Integrity

The condition that PMMR contents, roots, and reconstruction behavior remain
consistent with canonical history and deterministic update rules. It matters
because PMMR corruption can invalidate state continuity without an obvious rule
change.

### Recovery Safety

The property that recovery paths preserve deterministic correctness or fail
closed when safe continuation cannot be established.

### Replay Divergence

A condition in which replay of what should be equivalent canonical inputs
produces materially different resulting states, histories, or acceptance
outcomes across executions or nodes.

### Replay Equivalence

The property that equivalent canonical inputs replay to equivalent resulting
state and history. It matters because deterministic monetary validation depends
on replay being stable, not merely locally plausible.

### Replay Integrity

The condition that replay remains faithful to canonical history, accepted state
transitions, and deterministic validation rules.

### Replay-Safe Evolution

Protocol evolution disciplined so that changes do not create ambiguous replay
paths, history reinterpretation, or divergence between fresh replay and
accepted canonical state.

### Restart Equivalence

The property that a restart from valid persisted state yields the same
canonical interpretation that existed before shutdown, subject to the same
protocol rules and durable inputs.

### State Continuity

Continuity of valid protocol state across operation, replay, restart, and
recovery without introducing monetary ambiguity or alternate canonical
interpretations.
