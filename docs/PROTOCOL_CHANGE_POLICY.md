# DOM Protocol Change Policy

## Purpose

This document defines DOM's operational protocol-change discipline. It is
engineering governance guidance for evaluating proposed changes to a
deterministic monetary protocol.

It is documentation-only and non-consensus-changing. It does not alter
consensus rules, monetary policy, issuance semantics, PMMR semantics, replay
semantics, persistence rules, wallet recovery behavior, or network behavior.
It does not create governance authority, voting rights, or institutional
control. It formalizes engineering discipline only.

## Document Authority

Consensus-authoritative behavior is defined by:

1. The implementation (`crates/dom-*/`)
2. The normative RFC set (`docs/DOM_RFC_000*.md`)
3. Consensus-critical specifications and static assertions in `dom-core`

This document is doctrinal and non-authoritative with respect to consensus
behavior. Related doctrinal documents — `docs/MONETARY_CONSTITUTION.md`,
`docs/MONETARY_GLOSSARY.md`, and `docs/MONETARY_ALIGNMENT_REVIEW.md` — are
likewise non-authoritative. Where any doctrinal document conflicts with the
implementation or normative RFCs, the implementation and RFCs govern.

## Core Engineering Principles

DOM evaluates protocol evolution under a conservative systems model. Proposed
changes are expected to preserve:

- deterministic execution
- replay equivalence
- restart equivalence
- persistence correctness
- canonical convergence
- bounded runtime behavior
- adversarial resilience
- crash-safe recovery
- deterministic recovery
- conservative protocol evolution
- operational predictability

These principles are not independent preferences. They are coupled
requirements for maintaining deterministic monetary integrity under replay,
restart, recovery, and hostile operating conditions.

## Change Safety Requirements

Changes affecting protocol behavior require elevated scrutiny when they can
influence any of the following:

- replay safety
- restart equivalence
- persistence correctness
- deterministic execution
- bounded runtime behavior
- cleanup convergence
- crash recovery
- canonical convergence
- deterministic state transitions
- persistence-safe recovery

A change is not low risk merely because it appears localized in code. If it
can alter accepted history reconstruction, canonical pointer behavior, stored
state interpretation, validation ordering, or recovery outcomes, it must be
treated as a higher-risk protocol change.

Where uncertainty exists, the safer assumption is that replay paths,
persistence paths, and reconstruction paths are protocol-sensitive until shown
otherwise.

## Mandatory Validation Standards

Proposed protocol-relevant changes are expected to be evaluated against the
validation categories appropriate to their risk profile, including:

- replay equivalence testing
- restart validation
- crash recovery testing
- persistence consistency validation
- adversarial testing
- deterministic integration testing
- cleanup convergence testing
- hostile-network testing
- bounded-behavior validation

The required depth depends on the change category, but changes affecting
canonical state, recovery, acceptance behavior, or persistence safety should
not rely on local reasoning alone. They should be supported by evidence that
the modified behavior remains deterministic under adversarial and recovery
conditions.

## High-Risk Change Categories

The following areas require stricter review because they can affect consensus
interpretation, canonical reconstruction, or durable state continuity:

- consensus logic
- persistence and storage layers
- replay-path logic
- PMMR behavior
- serialization
- wallet recovery semantics
- networking state machines
- deterministic state transitions
- chain-state reconstruction
- recovery pipelines

Changes in these areas should be treated as high risk even when they do not
intend to alter consensus. The relevant question is not only what the change
declares, but what it can influence under replay, restart, partial
persistence, reorg, or adversarial input.

## Upgrade Philosophy

DOM follows a minimal and conservative upgrade philosophy.

Protocol evolution should preserve compatibility discipline, operational
predictability, deterministic evolution, and hardening-before-expansion.
Correctness takes priority over velocity. Stability takes priority over
experimentation.

Speculative feature expansion remains subordinate to hardening maturity. A
change that increases surface area without clear improvement to correctness,
recoverability, or bounded behavior carries a higher burden of justification.

## Forbidden Engineering Philosophy

DOM rejects engineering approaches that subordinate protocol correctness to
novelty, velocity, or scope expansion. This includes:

- speculative rewrites
- hype-driven architecture
- unnecessary abstraction
- complexity-first design
- protocol sprawl
- uncontrolled extensibility
- architecture inflation
- premature optimization
- feature velocity over correctness
- ecosystem-first prioritization

The preferred discipline is incremental, reviewable hardening with explicit
attention to deterministic behavior and recovery safety.

## Relationship to Active Hardening

The active hardening roadmap remains the primary operational priority.

This includes ongoing focus on:

- reorg hardening
- IBD hardening
- replay and restart convergence
- persistence stabilization
- deterministic cleanup convergence
- adversarial networking
- wallet RPC hardening
- public testnet stabilization

This policy does not compete with that work. Governance doctrine remains
subordinate to protocol correctness, recovery safety, and deterministic
convergence.

## Operational Scope Boundaries

This document does not:

- create protocol governance authority
- establish voting systems
- establish treasury control
- establish monetary authority
- create institutional control structures
- alter consensus rules
- alter issuance rules
- mandate future features
- formalize future runtime systems

Future concepts, if considered at all, remain conceptual, conditional,
architecture-dependent, and maturity-dependent. This document does not convert
future possibilities into present commitments.
