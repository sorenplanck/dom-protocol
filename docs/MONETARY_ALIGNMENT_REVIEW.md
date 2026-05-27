# Monetary Alignment Review

**Status:** Analytical — Non-Normative  
**Scope:** Repository-wide doctrine and terminology review  
**Date:** 2026-05-27

---

## 1. Purpose

This document is a doctrine-alignment review and repository consistency analysis. It evaluates terminology consistency, monetary language, governance wording, architectural identity, and source hierarchy across the DOM Protocol documentation corpus.

This document:
- does not alter protocol behavior
- does not alter consensus semantics
- does not alter issuance semantics
- does not alter replay semantics
- does not alter persistence semantics
- does not define governance authority
- does not redefine monetary policy
- does not create implementation obligations

It records observations and identifies alignment gaps that may benefit from targeted, conservative remediation in future documentation maintenance work. All findings are evidence-based, drawn from inspection of the existing repository. Recommendations are narrowly scoped and do not prescribe rewrites.

---

## 2. Repository Alignment Scope

This review evaluates the following document categories across the repository:

- **Normative RFCs:** `docs/DOM_RFC_0004_*`, `DOM_RFC_0008_*`, `DOM_RFC_0009_*`, `DOM_RFC_0010_*`, `DOM_RFC_0011_*`
- **Design documents:** `WHITEPAPER.md`, `README.md`
- **Doctrinal documents:** `docs/MONETARY_CONSTITUTION.md`, `docs/MONETARY_GLOSSARY.md`, `docs/MONETARY_INTEGRITY_PROOFS.md`, `docs/PROTOCOL_CHANGE_POLICY.md`
- **Operational documents:** `docs/CONSENSUS.md`, `docs/RELEASE_BLOCKERS.md`, `docs/GENESIS_CEREMONY.md`, `docs/ECONOMIC_SECURITY.md`, `docs/ROADMAP_v2.md`, `docs/REPLAY_AUDIT_ARCHITECTURE.md`
- **Implementation:** `crates/dom-core/src/constants.rs` (canonical constant definitions)

The review is architecture-oriented and operationally conservative. It does not evaluate test infrastructure, binary tooling, or per-crate internal documentation.

---

## 3. Terminology Drift Findings

### TD-01 — Stale Monetary Parameters in CONSENSUS.md

**Observed Drift:**  
`docs/CONSENSUS.md` validator V13 states:

```
Initial: 369 DOM, halving every 44,715 blocks
```

All other authoritative sources state `33 DOM` initial reward and `330,000` block halving interval. Implementation (`crates/dom-core/src/constants.rs`) has static assertions pinning these values:

```rust
INITIAL_BLOCK_REWARD == 3_300_000_000,   // 33 DOM
HALVING_INTERVAL == 330_000,
```

**Affected Documents:** `docs/CONSENSUS.md` exclusively.

**Operational Significance:** High. A reader consulting `CONSENSUS.md` for protocol parameters receives values that are approximately an order of magnitude incorrect on both dimensions. A new implementer following this file would produce a consensus-incompatible node.

**Severity:** Critical — factual contradiction of all authoritative sources.

**Conservative Recommendation:** `docs/CONSENSUS.md` should be annotated at the top as superseded by the implementation and normative RFCs, pending rewrite. It must not be cited as a normative source until updated to reflect current parameters.

---

### TD-02 — Balance Equation Formulation in CONSENSUS.md

**Observed Drift:**  
`docs/CONSENSUS.md` validator V9 states:

```
sum(outputs) - sum(inputs) - sum(kernels) == 0
```

The normative formulation, per `WHITEPAPER.md` §4.3, `docs/DOM_RFC_0008_Balance_Coinbase_Fee_Offset.md`, and `docs/RELEASE_BLOCKERS.md` (RB-FEE-SIGN), is:

```
sum(outputs) - sum(inputs) + fee*H = sum(kernel_excesses) + offset*G
```

The `CONSENSUS.md` form omits the fee commitment term, uses `sum(kernels)` rather than `sum(kernel_excesses)`, and elides the offset. `RELEASE_BLOCKERS.md` documents that the original RFC-0008 contained an incorrect sign for the fee term and that the implementation was subsequently corrected. `CONSENSUS.md` reflects neither the original RFC-0008 form nor the corrected form.

**Affected Documents:** `docs/CONSENSUS.md` V9.

**Operational Significance:** High. The fee-term omission and incorrect kernel reference would lead any reader to conclude the balance equation is simpler than it is, potentially masking consensus-critical validations.

**Severity:** Critical — `CONSENSUS.md` V9 is mathematically incomplete and reflects a superseded state.

**Conservative Recommendation:** As with TD-01, `CONSENSUS.md` should be marked superseded. The authoritative balance equation is in `docs/DOM_RFC_0008_Balance_Coinbase_Fee_Offset.md` and `WHITEPAPER.md` §4.3.

---

### TD-03 — Incomplete Validator Enumeration in CONSENSUS.md

**Observed Drift:**  
`docs/CONSENSUS.md` lists four validators (V9, V13, V14, V18). `WHITEPAPER.md` §8 and `docs/RELEASE_BLOCKERS.md` describe an 18-step block validation pipeline including: ASERT difficulty, RandomX PoW verification, Schnorr signature validation, chain_id binding, kernel malleability rejection, offset canonicalization, cut-through correctness, H-generator startup verification, and Bulletproofs+ range-proof validation. None of these appear in `CONSENSUS.md`.

**Affected Documents:** `docs/CONSENSUS.md`.

**Operational Significance:** Moderate as a standalone document; critical if a reader uses it as a complete validation checklist.

**Severity:** High — the enumeration covers less than 25% of the implemented pipeline.

**Conservative Recommendation:** Same remediation as TD-01 and TD-02; the document should be marked as a placeholder stub, not a normative validator list.

---

### TD-04 — Supply Terminology Variation

**Observed Drift:**  
Different documents use slightly different phrasings to refer to the same concept:

| Document | Phrasing |
|---|---|
| `WHITEPAPER.md` | "fixed total supply of 33,000,000 DOM" |
| `README.md` | "Supply Cap: 33,000,000 DOM" |
| `MONETARY_CONSTITUTION.md` | "fixed-supply monetary philosophy" |
| `RELEASE_BLOCKERS.md` | "MAX_SUPPLY_NOMS... computed deterministically" |
| `docs/MONETARY_GLOSSARY.md` | "Maximum Supply" |

The underlying numerical values and concepts are consistent across all sources. The variation is presentational, not substantive.

**Affected Documents:** All major documentation.

**Operational Significance:** Low. The variation does not introduce mathematical ambiguity — all documents yield the same supply ceiling.

**Severity:** Low — terminology variance without definitional conflict.

**Conservative Recommendation:** When updating documentation, prefer "fixed total supply" or the MONETARY_GLOSSARY term "Maximum Supply" for consistency. No immediate rewrite warranted.

---

### TD-05 — Deterministic-Language Density Variation

**Observed Drift:**  
`docs/MONETARY_CONSTITUTION.md` and `docs/MONETARY_GLOSSARY.md` use a specific compound term, *deterministic monetary integrity*, with a formal definition. `README.md`, `WHITEPAPER.md`, and `docs/ECONOMIC_SECURITY.md` use "deterministic" extensively but do not reference or cross-link the formal definition. Readers consulting those documents do not encounter the doctrinal definition unless they independently locate `MONETARY_GLOSSARY.md`.

**Affected Documents:** `README.md`, `WHITEPAPER.md`, `docs/ECONOMIC_SECURITY.md`.

**Operational Significance:** Low for protocol correctness. Moderate for doctrinal coherence.

**Severity:** Low — definitional gap in discoverability, not substantive inconsistency.

**Conservative Recommendation:** Design documents that invoke "deterministic" in monetary or replay contexts could note that `docs/MONETARY_GLOSSARY.md` provides operational definitions. A single cross-reference addition per document is sufficient.

---

## 4. Monetary Ambiguity Findings

### MA-01 — Regtest Coinbase Maturity Differentiation

**Evidence:**  
`crates/dom-core/src/constants.rs` defines:
- `COINBASE_MATURITY: u64 = 1_000` (mainnet/testnet)
- `REGTEST_COINBASE_MATURITY: u64 = 1` (regtest only)

`docs/CONSENSUS.md` validator V14 states "Coinbase spendable after 1000 blocks" without indicating this differs in regtest. The distinction is enforced by static assertion in the implementation.

**Architectural Implications:** None for mainnet. Regtest nodes using `REGTEST_COINBASE_MATURITY = 1` are not consensus-compatible with mainnet by design. The differentiation is correct and intentional.

**Operational Implications:** Documentation that presents coinbase maturity as a single universal value may mislead testers who observe different behavior in regtest, potentially causing diagnostic confusion.

**Severity:** Low — architectural intent is sound; documentation clarity is incomplete.

**Conservative Remediation Direction:** Any documentation citing the 1,000-block maturity figure should note the regtest variant. `docs/REGTEST.md` is the appropriate location for this clarification.

---

### MA-02 — Issuance Wording Scope

**Evidence:**  
`docs/MONETARY_CONSTITUTION.md` explicitly enumerates what issuance mechanisms are absent: "there is no governance minting," "there is no treasury printing," "there is no staking inflation," "there are no privileged monetary actors." `WHITEPAPER.md` uses parallel but differently structured language: "no premine, no ICO, no reserved supply," "no staking," "no governance tokens."

The two enumerations are substantively aligned but structurally disjoint. A reader consulting only `WHITEPAPER.md` does not encounter the explicit staking-inflation and governance-minting exclusions; a reader consulting only `MONETARY_CONSTITUTION.md` does not encounter the "no premine, no ICO" language.

**Architectural Implications:** None. Both documents describe the same system. No issuance path exists outside mining rewards per the implementation.

**Operational Implications:** Incomplete cross-referencing may leave an auditor relying on one source uncertain whether the complementary exclusions exist elsewhere.

**Severity:** Low — complementary, not contradictory.

**Conservative Remediation Direction:** Either document could include a single cross-reference to the other for completeness. No content rewrite is warranted.

---

### MA-03 — Fee-Policy Relay vs. Consensus Distinction

**Evidence:**  
`WHITEPAPER.md` states: "Zero-fee transactions are consensus-valid but relay-policy rejected." This distinction — consensus-valid versus relay-rejected — appears in the whitepaper but is not consistently surfaced in `docs/CONSENSUS.md` or `docs/MONETARY_GLOSSARY.md`.

**Architectural Implications:** The distinction matters for operator tooling and wallet UX. A zero-fee transaction that passes consensus validation will be rejected by nodes enforcing relay policy, leading to liveness failure for the sender.

**Operational Implications:** Moderate. The relay-vs-consensus distinction is architecturally significant for transaction propagation behavior and must be understood by wallet implementers and operators.

**Severity:** Low in terms of protocol ambiguity; moderate in terms of operational clarity.

**Conservative Remediation Direction:** `docs/MONETARY_GLOSSARY.md` could add "Relay Policy" as a distinct term with its relationship to consensus validity made explicit. This is a targeted addition, not a rewrite.

---

## 5. Governance Ambiguity Findings

### GA-01 — Engineering Governance Authority vs. Monetary Authority Partition

**Evidence:**  
Repository documentation establishes two distinct authority domains that are structurally separate but not explicitly described as such in a single location:

- **Monetary parameters are immutable post-genesis.** `docs/GENESIS_CEREMONY.md` specifies that after `GENESIS_HASH_MAINNET` is pinned, the following constants must never be modified: `INITIAL_BLOCK_REWARD`, `HALVING_INTERVAL`, `HALVING_EPOCHS`, `MAX_SUPPLY_NOMS`, `NETWORK_MAGIC_MAINNET`, `P2P_PORT_MAINNET`. Enforcement is via branch protection on `crates/dom-core/src/constants.rs` requiring CODEOWNERS review.

- **Engineering evolution authority is held by the maintainer.** `docs/ROADMAP_v2.md` states that "HIGH items must be either complete or have documented residual risk accepted by maintainer." `docs/PROTOCOL_CHANGE_POLICY.md` establishes engineering coupling principles but explicitly states it "does not create protocol governance authority."

The partition is correct and coherent. No single document consolidates it.

**Operational Implications:** An external auditor reviewing any single document in isolation may not find the complete authority model. The governance model is distributed across at least three documents: `MONETARY_CONSTITUTION.md`, `GENESIS_CEREMONY.md`, and `PROTOCOL_CHANGE_POLICY.md`.

**Future Drift Risk:** As the codebase grows and contributors change, the maintainer-authority model may drift without a single authoritative governance statement. The current structure relies on document-level enforcement, which is weaker than cryptographic enforcement.

**Severity:** Low. The model is internally consistent; the risk is fragmentation of discovery.

**Conservative Remediation Direction:** A short "Governance and Authority Summary" section in `docs/PROTOCOL_CHANGE_POLICY.md` — pointing to `GENESIS_CEREMONY.md` for monetary immutability and `ROADMAP_v2.md` for engineering authority — would consolidate the model without introducing a new governance document.

---

### GA-02 — Bootstrap Infrastructure Control Language

**Evidence:**  
`docs/RELEASE_BLOCKERS.md` (RB-DNS-SEEDS) notes: "No domain names specified — RFC-0011 defers to bootstrap discovery." `docs/DOM_RFC_0011_Bootstrap_PMMR_FeePolicy.md` addresses protocol-level bootstrap semantics. However, the operational question of who controls the DNS seed infrastructure, and under what obligations, is not documented anywhere in the repository.

`WHITEPAPER.md` §12 states "Anyone with a CPU can mine block 0" and "The protocol launches with no privileged access." These statements apply to mining genesis, not to DNS seed control.

**Operational Implications:** During the bootstrap period, DNS seed operators have practical influence over which nodes new participants reach first. This is an operational reality of DNS-based peer discovery. The repository does not document obligations or limits on DNS seed operators, nor what constitutes acceptable divergence between different seed providers.

**Future Drift Risk:** Without documented expectations for DNS seed operation, operational centralization could accumulate without triggering a doctrinal conflict, because no document constrains it.

**Severity:** Low as a protocol matter (DNS seeds are advisory, not consensus-authoritative); moderate as an operational-neutrality matter.

**Conservative Remediation Direction:** `docs/DEPLOYMENT.md` or a dedicated section in `docs/DOM_RFC_0011_Bootstrap_PMMR_FeePolicy.md` could document the expected operational model for DNS seeds: their advisory role, operator obligations (if any), and the protocol-level mechanisms by which nodes can operate without them.

---

### GA-03 — Witness Role in Genesis Ceremony

**Evidence:**  
`docs/GENESIS_CEREMONY.md` specifies: "Witnesses: ≥3 independent technically-competent observers" for the genesis ceremony. It does not define "independent," the selection process for witnesses, what constitutes a valid witness observation, or whether witness disagreement can block or delay ceremony completion.

**Operational Implications:** The ceremony procedure is specified in terms of outcomes (timestamp anchoring, hash commitment) but not in terms of witness process. A ceremony conducted with witnesses who lack the technical means to verify the parameters independently would satisfy the letter of the requirement without its intent.

**Future Drift Risk:** Low, given this is a one-time event. However, if the ceremony is delayed or contested, the absence of a defined process for witness disagreement could create operational uncertainty.

**Severity:** Low — applies only to the pre-mainnet genesis event.

**Conservative Remediation Direction:** `docs/GENESIS_CEREMONY.md` could add a brief subsection specifying what witnesses are expected to independently verify (at minimum: `GENESIS_HASH_MAINNET`, `INITIAL_BLOCK_REWARD`, `HALVING_INTERVAL`, `MAX_SUPPLY_NOMS`, the RFC9380 H generator derivation) and that witness attestation is advisory rather than blocking.

---

## 6. Architectural Identity Findings

### AI-01 — Identity Consistency Across Documents

The core architectural identity claims are strongly aligned across all major documents:

| Claim | Sources | Status |
|---|---|---|
| Peer-to-peer electronic cash | `WHITEPAPER.md` Abstract, `README.md` §Executive Summary | Consistent |
| Medium of exchange, not store of value | `WHITEPAPER.md` §1, genesis message | Consistent |
| No premine, no ICO, no reserved supply | `WHITEPAPER.md` §4.2, `README.md` | Consistent |
| CPU-accessible mining at genesis | `WHITEPAPER.md` §12 | Consistent |
| No smart contracts, no scripting | `WHITEPAPER.md` §2, §10 | Consistent |
| No staking inflation, no governance tokens | `WHITEPAPER.md` §10, `MONETARY_CONSTITUTION.md` | Consistent |
| Deterministic monetary integrity | `MONETARY_CONSTITUTION.md`, `MONETARY_GLOSSARY.md` | Consistent |
| Conservative protocol evolution | `PROTOCOL_CHANGE_POLICY.md`, `MONETARY_CONSTITUTION.md` | Consistent |

No conflicting architectural identity claims were found across authoritative documents.

---

### AI-02 — Hardening-First Identity in Roadmap vs. Design Documents

**Evidence:**  
`docs/ROADMAP_v2.md` and `docs/PROTOCOL_CHANGE_POLICY.md` present a hardening-first, milestone-gated operational identity. `WHITEPAPER.md` presents the protocol design but does not characterize the development methodology in equivalent terms.

The hardening-first framing in `ROADMAP_v2.md` ("Hardening precedes expansion") and `README.md` §Design Philosophy is consistent with `PROTOCOL_CHANGE_POLICY.md`'s explicit prohibition on "speculative rewrites" and "hype-driven architecture." However, these characterizations are spread across operational documents rather than integrated into the primary design document.

**Operational Implications:** Reviewers reading `WHITEPAPER.md` alone receive a complete protocol description but not the development discipline that governs how the protocol evolves. This creates a gap between design intent and operational commitment that is filled only by reading operational documents.

**Severity:** Low — not a contradiction, but an incompleteness in the primary design document.

**Conservative Remediation Direction:** A brief "Development Discipline" section or cross-reference in `WHITEPAPER.md` pointing to `PROTOCOL_CHANGE_POLICY.md` would surface the operational commitment to hardening-first evolution without altering the design document's technical content.

---

### AI-03 — Mimblewimble Attribution Language

**Evidence:**  
`WHITEPAPER.md` references Grin, Monero, Bitcoin Cash as sources of the underlying technology, stating "What is new is the synthesis, the launch model, and the commitment to remain a currency." This framing is accurate and does not overclaim novelty.

However, `README.md` describes DOM as "Mimblewimble-based decentralized monetary protocol" without the same attributional context. Neither document is incorrect, but the level of attribution differs between primary documents.

**Severity:** Low — no inconsistency in technical claims, only in attribution depth.

**Conservative Remediation Direction:** No action required. The `WHITEPAPER.md` attribution is sufficient for the authoritative design document.

---

## 7. Source Hierarchy Findings

### SH-01 — Absence of Explicit Source Hierarchy Statement

**Evidence:**  
No single document in the repository explicitly states the normative authority hierarchy. The hierarchy that emerges from reading across documents is:

1. **Consensus-authoritative:** Implementation code, normative RFCs
2. **Design-authoritative:** `WHITEPAPER.md` (v4), `docs/RELEASE_BLOCKERS.md` (tracks implementation fidelity)
3. **Doctrinal (non-consensus):** `docs/MONETARY_CONSTITUTION.md`, `docs/MONETARY_GLOSSARY.md`, `docs/PROTOCOL_CHANGE_POLICY.md`
4. **Conceptual (non-binding):** `docs/MONETARY_INTEGRITY_PROOFS.md`, `docs/REPLAY_AUDIT_ARCHITECTURE.md`
5. **Operational (pre-mainnet, event-specific):** `docs/GENESIS_CEREMONY.md`
6. **Outdated (should not be cited):** `docs/CONSENSUS.md` in its current form

`docs/MONETARY_GLOSSARY.md` includes the disclaimer: "Normative consensus behavior remains defined by the implementation, normative RFCs, and consensus-critical specifications." This is correct but local to that document.

**Operational Implications:** An external auditor has no single reference document to determine which sources govern disputed questions. The hierarchy must currently be inferred.

**Severity:** Low. The hierarchy is recoverable by careful reading; there are no active contradictions between normative sources.

**Conservative Remediation Direction:** `docs/PROTOCOL_CHANGE_POLICY.md` or `README.md` could include a brief "Document Authority" section establishing the hierarchy explicitly. This is an additive annotation, not a rewrite.

---

### SH-02 — CONSENSUS.md Normative Status Ambiguity

**Evidence:**  
`docs/CONSENSUS.md` is named and positioned as a normative consensus document. Its current content contradicts authoritative sources on three dimensions (reward, halving interval, balance equation) and covers fewer than 25% of the implemented validation pipeline. Despite this, it carries no deprecation notice, no version indicator, and no cross-reference to the normative RFCs or implementation.

**Operational Implications:** Any reader or external auditor treating `CONSENSUS.md` as current documentation receives materially incorrect protocol parameters. The document's position in the `docs/` directory, under a normative filename, amplifies the risk.

**Severity:** High. This is the most operationally significant documentation inconsistency in the repository.

**Conservative Remediation Direction:** At minimum, prepend `docs/CONSENSUS.md` with a notice identifying it as an outdated placeholder, specifying which sources supersede it, and directing readers to the implementation and normative RFCs. A full rewrite to match the current 18-step validation pipeline is warranted before mainnet, but the deprecation notice is a non-invasive immediate step.

---

### SH-03 — Normative RFC Coverage vs. Implementation

**Evidence:**  
The release blockers list tracks implementation fidelity against design through `RELEASE_BLOCKERS.md`. Several validators that are implemented (ASERT, RandomX, Schnorr with RFC9380 H, chain_id binding, offset canonicalization) have corresponding RFCs (RFC-0004, RFC-0008, RFC-0009, RFC-0010). The validation pipeline itself does not have a standalone RFC; it is described in `WHITEPAPER.md` §8 and tracked in `RELEASE_BLOCKERS.md`.

A dedicated RFC for the block validation pipeline (the 18-step sequence) would close this gap.

**Severity:** Low. The pipeline is documented across `WHITEPAPER.md` and `RELEASE_BLOCKERS.md`; the absence of a standalone RFC does not create ambiguity today.

**Conservative Remediation Direction:** A future RFC (e.g., RFC-0012 or similar) documenting the complete block validation pipeline would consolidate pipeline normative references. This is a deferred documentation task, not an immediate operational gap.

---

## 8. Philosophical Drift Risks

### PD-01 — Ecosystem Expansion Language Risk

**Observed:**  
Current documentation does not exhibit ecosystem-expansion drift. `WHITEPAPER.md` §2 explicitly excludes smart contracts, scripting, staking, governance tokens, DAOs, and foundations. `MONETARY_CONSTITUTION.md` formally excludes governance minting, treasury printing, and staking inflation. `PROTOCOL_CHANGE_POLICY.md` prohibits "protocol sprawl" and "speculative rewrites."

**Likelihood:** Low under current governance. The explicit renunciations are formally documented.

**Risk:** These exclusions are documented in prose, not enforced by protocol rules. As the contributor base grows, proposals introducing extensions (layer-2 constructs, token primitives, bridge functionality) could be framed as not technically altering the base layer, creating pressure on the prohibition scope.

**Severity:** Low currently; moderate as a long-term governance risk if the contributor base expands without doctrinal onboarding.

**Conservative Remediation Direction:** The `PROTOCOL_CHANGE_POLICY.md` prohibition on "protocol sprawl" is the primary mitigation. No additional mechanism is warranted at this stage.

---

### PD-02 — Replay-Language Consistency Risk

**Observed:**  
The terms *replay*, *restart equivalence*, and *persistence integrity* are used across `docs/REPLAY_AUDIT_ARCHITECTURE.md`, `docs/MONETARY_GLOSSARY.md`, and `docs/PROTOCOL_CHANGE_POLICY.md` with consistent intent. However, `WHITEPAPER.md` and `README.md` use "deterministic" broadly without the specific sub-categorization defined in `MONETARY_GLOSSARY.md`.

**Likelihood:** Low that this creates immediate operational divergence; moderate that as replay tooling is developed, the looser usage in design documents leads to miscommunication about scope.

**Severity:** Low. Definitions are canonical in `MONETARY_GLOSSARY.md`; adoption across other documents is gradual.

**Conservative Remediation Direction:** As replay audit infrastructure matures, primary documentation should adopt the `MONETARY_GLOSSARY.md` sub-terms where precision is needed. No immediate action required.

---

### PD-03 — Operational-Authority Accumulation Risk

**Observed:**  
The current governance model places engineering authority with a named maintainer (Soren Planck) with no succession mechanism documented. This is an intentional minimalist choice consistent with "no DAO, no foundation, no central legal entity."

**Risk:** The absence of a succession mechanism is operationally sound for a pre-mainnet protocol with a small contributor base. If the protocol achieves significant adoption, the named-maintainer model becomes a single point of operational failure for the documentation and branch-protection infrastructure, separate from the protocol itself (which remains permissionlessly operable).

**Severity:** Low as a current risk; moderate as a long-term operational-continuity consideration.

**Conservative Remediation Direction:** Documentation of maintainer obligations (rather than a succession plan) would be consistent with the current model's minimalism. What obligations attach to holding the release-signing key, and what constitutes abandonment of that role, could be addressed in `docs/PROTOCOL_CHANGE_POLICY.md` without creating a governance system.

---

### PD-04 — Stale Documentation Propagation Risk

**Observed:**  
`docs/CONSENSUS.md` is demonstrably stale and carries no deprecation notice. If the repository is cited by external researchers, auditors, or implementers, this document will be encountered as part of the canonical documentation set.

**Likelihood:** High that external auditors will inspect `docs/CONSENSUS.md`. Certain that its current content will produce incorrect conclusions.

**Severity:** High. This is the primary drift risk in the current documentation state.

**Conservative Remediation Direction:** A deprecation notice prepended to `docs/CONSENSUS.md` is a minimal, non-invasive mitigation. See SH-02.

---

## 9. Conservative Alignment Recommendations

The following recommendations are narrowly scoped, non-invasive, and prioritized by operational risk. None of them require consensus changes, implementation changes, or broad document rewrites.

### Priority 1 — Immediate (Pre-External Audit)

**R-01:** Prepend `docs/CONSENSUS.md` with a supersession notice identifying the document as an outdated placeholder, listing the contradictions with current authoritative sources (reward, halving interval, balance equation), and directing readers to the implementation, `WHITEPAPER.md` §8, `docs/DOM_RFC_0008_Balance_Coinbase_Fee_Offset.md`, and `docs/RELEASE_BLOCKERS.md` as normative sources.

This is a six-to-ten line prepended notice. It does not require rewriting the body of the document.

**R-02:** Add a "Document Authority" statement to `docs/PROTOCOL_CHANGE_POLICY.md` or `README.md` that explicitly establishes the source hierarchy (implementation → normative RFCs → design documents → doctrinal documents → conceptual documents). One paragraph is sufficient.

---

### Priority 2 — Pre-Mainnet Documentation Pass

**R-03:** Add a cross-reference from `WHITEPAPER.md` and `README.md` to `docs/MONETARY_GLOSSARY.md` in sections that invoke "deterministic" in the monetary or replay context. A parenthetical or footnote is sufficient.

**R-04:** Document the relay-vs-consensus distinction for zero-fee transactions in `docs/MONETARY_GLOSSARY.md` under a "Relay Policy" entry, cross-referencing `WHITEPAPER.md`.

**R-05:** Add a brief "Governance and Authority Summary" to `docs/PROTOCOL_CHANGE_POLICY.md` that maps monetary immutability (per `docs/GENESIS_CEREMONY.md`) and engineering authority (per `docs/ROADMAP_v2.md`) into a single summary, without creating a new governance document.

**R-06:** `docs/GENESIS_CEREMONY.md` should specify what independent witnesses are expected to verify during the ceremony. This is an additive clarification, not a procedural change.

---

### Priority 3 — Deferred (Post-Mainnet or As Needed)

**R-07:** A future normative RFC for the complete 18-step block validation pipeline would close the gap between `WHITEPAPER.md` §8 (descriptive) and the implementation (normative). This is not blocking but improves long-term maintainability.

**R-08:** The DNS seed operational model (advisory role, absence of protocol-level obligations, permissionless alternatives) could be documented in `docs/DEPLOYMENT.md` as operational guidance for bootstrap-period operators.

---

## 10. Relationship to Active Hardening

Engineering hardening remains the primary operational priority. The following prerequisite work takes precedence over any documentation cleanup:

- Replay and restart convergence hardening (active, blocking testnet stability)
- Persistence stabilization and LMDB durability (active)
- Adversarial network hardening — peer scoring, ban policy wiring, sybil resistance (active)
- Public testnet deployment and 90-day continuous operation gate (Phase 8.1)
- ≥10,000 CPU-hour fuzz campaign (Phase 8.2)
- External security audit (Phase 8.3–8.4)

Doctrine alignment remains subordinate to protocol correctness and operational stability. Recommendations R-01 and R-02 above are the only items appropriate to address during active hardening phases, as they are low-effort and reduce external-audit confusion risk without interfering with implementation work.

Recommendations R-03 through R-08 are appropriate for the pre-mainnet documentation pass, after engineering milestones are satisfied.

No doctrine alignment recommendation takes precedence over an open entry in `docs/RELEASE_BLOCKERS.md`.

---

## 11. Explicit Scope Boundaries

This document does NOT:

- alter consensus semantics
- alter issuance semantics
- alter replay semantics
- alter persistence semantics
- create governance authority of any kind
- create mandatory repository rewrites
- create implementation obligations
- create feature-roadmap commitments
- create institutional governance systems
- establish voting systems, staking mechanisms, or treasury structures
- reinterpret the monetary schedule
- modify normative RFC content
- modify the WHITEPAPER
- modify the README
- modify `crates/dom-core/src/constants.rs` or any other implementation file
- constitute a binding protocol change proposal

All findings are descriptive. All recommendations are advisory. The implementation, normative RFCs, and `docs/RELEASE_BLOCKERS.md` remain the authoritative sources for protocol behavior.
