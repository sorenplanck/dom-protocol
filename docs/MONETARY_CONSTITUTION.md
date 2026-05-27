# DOM Monetary Constitution

## Purpose

This document states the monetary doctrine of DOM as it is already implied by
the repository architecture, normative RFC set, and active hardening roadmap.
It is documentation-only, non-consensus-changing, and non-executable.

It does not alter monetary policy, issuance, consensus rules, validation
semantics, PMMR behavior, replay semantics, persistence rules, or wallet
recovery assumptions. It formalizes existing architectural commitments so that
monetary doctrine remains aligned with deterministic protocol behavior.
Operational term definitions used throughout this document are stabilized in
`docs/MONETARY_GLOSSARY.md`. Consensus-authoritative behavior is defined by
the implementation and normative RFCs, not by this document.

## Monetary Philosophy

DOM is a monetary protocol oriented around deterministic monetary integrity.
This means monetary correctness is not treated as issuance arithmetic alone. It
is treated as the ability of independent nodes to arrive at the same monetary
state from the same canonical history, under replay, restart, recovery, and
adversarial operating conditions.

Deterministic monetary integrity requires replay-verifiable monetary history,
proof-of-work anchoring, canonical convergence, bounded runtime behavior, and
persistence-safe recovery. It rejects monetary entropy arising from ambiguous
state transitions, discretionary issuance, non-deterministic validation, or
unsafe continuation after partial state failure.

DOM therefore favors monetary predictability over discretionary flexibility,
correctness over velocity, stability over experimentation, and conservative
protocol evolution over feature-driven expansion. Operational integrity is part
of monetary integrity because a monetary system that cannot be replayed,
restarted, or recovered deterministically cannot provide stable monetary
continuity.

## Monetary Guarantees

DOM is governed by a fixed-supply monetary philosophy anchored in proof of work
and enforced by deterministic consensus rules.

Under this doctrine:

- monetary issuance is rule-bound, not discretionary
- there is no governance minting
- there is no treasury printing
- there is no staking inflation
- there are no privileged monetary actors
- there are no hidden issuance vectors by design objective
- operational policy must remain neutral with respect to lawful consensus
  participation

This document does not restate or reinterpret the existing monetary schedule.
It affirms that the schedule is a protocol rule, not an administrative tool.

## Deterministic Monetary State

DOM treats deterministic state continuity as a monetary requirement.

Monetary correctness depends on:

- replay integrity, so canonical history can be re-executed without divergence
- canonical convergence, so honest nodes reach the same best monetary state
- deterministic replay, so identical accepted histories yield identical results
- restart equivalence, so restart does not alter canonical monetary state
- persistence integrity, so stored state does not silently drift from validated
  state
- state continuity, so recovery does not introduce monetary ambiguity
- deterministic recovery, so unsafe partial state is detected, refused, or
  rebuilt without altering monetary rules

Issuance limits, balance rules, maturity rules, and consensus checks are
necessary but not sufficient on their own. A monetary protocol must also be able
to reconstruct, verify, and recover its monetary history deterministically. In
DOM, replay safety and persistence-safe recovery are part of monetary
correctness, not external operational conveniences.

## Protocol Neutrality

DOM is designed to minimize privileged monetary position inside the protocol.

Proof-of-work participation is intended to remain rule-governed rather than
permissioned. Consensus validity does not depend on privileged validators,
special monetary governors, or discretionary issuance authorities. Protocol
behavior is expected to remain deterministic across honest implementations and
conservative in its authority boundaries.

Protocol neutrality in this context means the system should not create special
monetary classes with administrative access to issuance, validation outcome, or
canonical monetary history. Operational roles may exist for deployment,
maintenance, or bootstrap coordination, but those roles do not constitute
discretionary monetary authority.

## Evolution Philosophy

DOM adopts a slow evolution model subordinate to hardening maturity.

Protocol evolution should proceed only when changes can be justified under
deterministic upgrade discipline, adversarial validation discipline, replay-safe
evolution, persistence-safe evolution, and operational predictability.

Hardening precedes expansion. Changes that widen protocol surface area without
clear improvement to correctness, recoverability, or security are contrary to
this doctrine. Future conceptual systems, if ever considered, must remain
subordinate to demonstrated hardening maturity and must not weaken deterministic
monetary state continuity.

## Explicit Non-Goals

DOM is not pursuing:

- inflationary staking
- governance inflation
- treasury issuance
- speculative tokenomics
- hyper-financialization
- complexity-first architecture
- uncontrolled ecosystem expansion
- DeFi-centric evolution
- smart-contract-first protocol identity
- privileged monetary governance

DOM is a monetary protocol. Its doctrine does not treat monetary infrastructure
as a substrate for discretionary financial layering.

## Relationship to Engineering Hardening

This doctrine does not compete with the active engineering roadmap and does not
change repository priorities.

The primary operational priority remains protocol correctness, including reorg
hardening, IBD hardening, replay and restart convergence, persistence
stabilization, wallet RPC hardening, adversarial network testing, deterministic
cleanup convergence, and public testnet readiness.

Doctrine remains subordinate to engineering validation. Where doctrine and
implementation discipline interact, correctness, replay safety, persistence
integrity, and canonical convergence remain the controlling standards.
