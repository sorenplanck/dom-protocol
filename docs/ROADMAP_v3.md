# DOM Protocol — Roadmap v3 (post Bulletproof migration)

Status: ADOPTED 2026-06-19
Replaces: Roadmap v2 (2026-05-24, pre-migration, "Bulletproofs+").
Trigger: Completion and merge of the Borromean→Bulletproof migration
(Phases 0–5) into main, plus the decision to build a dedicated security-audit
framework ("dom-shield"). Decision made under principle
"Security > Stability > Usability".

## Current state (snapshot — 2026-06-19)

Range-proof system: **Bulletproof** (bp2 via grin secp256k1zkp, custom H_DOM
generator). The earlier Borromean system is fully retired from consensus.
- Migration Phases 0–2: proof generation and consensus verification switched
  to bp2; ~30 test fixtures migrated; MAX_PROOF_SIZE = 768 (real proof 675);
  genesis coinbase regenerated as a 675-byte Bulletproof.
- Phase 3 (validation): `transfer_slate_e2e` (real wallet→wallet interactive
  slate transfer, bp2 verified through consensus) and `deterministic_replay`
  (pinned canonical-state digest, permanent CI gate) — both green.
- Phase 4 (documentation): all normative docs aligned to Bulletproof/768/675.
- Phase 5 (is_square proof): the SEC1↔zkp bridge equivalence proven over the
  domain E of valid curve points, conditional on standard number-theory facts
  (Euler / Jacobi=Legendre / Legendre multiplicativity), with a machine-checked
  companion (addition chain == (p+1)/4; −1 is a QNR). Documented in
  docs/DOM_RFC_0009_is_square_equivalence_proof.md.
- Consolidated to main at merge 53fdb30; recovery tag pre-bp-migration-main at
  1c143ad. Post-merge fixes: cosmetic lint sweep (fmt/clippy) and the final
  three stale Borromean test fixtures (slate + wallet helpers) migrated to bp2.

CI: builds + clippy + tests across Linux (x86_64, ARM), macOS (x86_64, ARM),
and Windows (x86_64); fmt and clippy -D warnings gates; release-blocker jobs
(crate tests, integration, ibd) green.

Website: dom-protocol.org live; whitepaper published.

Tooling: nightly + cargo-fuzz installed; Docker installed (host-side).
DOM already ships a 13-target cargo-fuzz suite across 4 crates.

Known orthogonal issues: ibd_two_node t1/t7 RandomX-throughput timeouts in
constrained environments (documented in KNOWN_ISSUES.md, not migration-caused).

## What changed vs v2

- "Bulletproofs+" is retired language. DOM uses standard Bulletproof; the
  is_square equivalence is now proven, not merely sampled.
- Much of v2's Phases 1–3 is already implemented (deterministic replay,
  cross-platform CI, differential crypto, infinity rejection, crash
  consistency, partial persistence). Those items are marked done below.
- New: the **dom-shield** security-audit framework (a separate private repo)
  is the mechanism that executes the remaining adversarial work (v2 Phases
  2.4, 4, 5, and the mainnet fuzzing campaign). It is not extra scope — it is
  how the adversarial phases get done.
- Phase 8 (mainnet gate) is rewritten to match the project's launch model:
  mainnet from block zero, no premine, no private round, no public testnet
  (avoids creating insiders); validation by the project's own audit software
  plus a private burn-in.

## Phases

### Phase 1 — Consensus Immutability Lock (CRITICAL)
- 1.1 Replay determinism — `deterministic_replay` with pinned digest: DONE
      (CI gate). Cross-node replay comparison: remaining.
- 1.2 Reorg equivalence — reorg_equivalence + adversarial reorg suites: DONE.
      Randomized reorg fuzzing: remaining (folded into dom-shield).
- 1.3 PMMR hardening — DOM-PMMR-001 RESOLVED (RFC-0004). Adversarial suite +
      proptest oracle: DONE. Rewind equivalence: DEFERRED (no rewind API yet).
- 1.4 Cross-platform equivalence CI — Linux/macOS/Windows × x86_64/ARM with
      snapshot byte-equivalence: DONE (live in CI).

### Phase 2 — Cryptographic Hardening (HIGH)
- 2.1 Differential testing vs k256 / BIP-340 / secp256k1: DONE
      (differential_crypto, 1000+ bridge samples).
- 2.2 Explicit infinity / subgroup / off-curve rejection: DONE
      (infinity_rejection, 16 tests).
- 2.3 Constant-time review (side-channel): remaining.
- 2.4 Bulletproof adversarial suite — partially DONE (bulletproof_adversarial,
      bp2 consensus tests). Deep fuzzing of bp2_verify: dom-shield, first target.
- 2.5 Secret memory hygiene (zeroize): partially in place; review remaining.

### Phase 3 — Storage Durability (CRITICAL)
- 3.1 Crash consistency (SIGKILL during commit/rollback/flush): DONE
      (crash_consistency, crash_consistency_sigkill).
- 3.2 Partial persistence detection: DONE (partial_persistence,
      corruption_detection, recovery_equivalence).
- 3.3 LMDB hardening (overwrite policy, map_size growth, ENOSPC): partial;
      formalization remaining.
- 3.4 Filesystem adversarial testing (ext4/xfs/btrfs/zfs durability): remaining.

### Phase 4 — Adversarial Network Hardening (HIGH) — executed via dom-shield
- 4.1 IBD adversarial replay — ibd_adversarial suite: DONE; extend in shield.
- 4.2 Eclipse resistance: remaining.
- 4.3 Resource exhaustion defense — resource_exhaustion: DONE; extend.
- 4.4 Sybil resistance: remaining.

### Phase 5 — Economic Security (HIGH) — executed via dom-shield
- 5.1 ASERT adversarial modeling — asert_adversarial: DONE; extend.
- 5.2 Miner game theory: remaining.
- 5.3 Mempool hardening — mempool_adversarial: DONE; extend.

### Phase 6 — Recoverability Proofs (CRITICAL)
- 6.1 Recovery equivalence (bit-for-bit) — recovery_equivalence: DONE.
- 6.2 Corruption detection + safe rebuild — corruption_detection: DONE.
- 6.3 Bootstrap recoverability: remaining.

### Phase 7 — Spec ↔ Code Locking (HIGH, ongoing)
- 7.1 RFC authoritative model — RFC-0000..0010 + RFC-0009 is_square proof.
- 7.2 Drift elimination — drift_audit, rfc_constants_audit: DONE (active).
- 7.3 Tests as spec — frozen vectors / pinned digests: in place.

### Phase 8 — dom-shield: Security Audit Framework (the mechanism)
The dedicated framework that performs the heavy adversarial work. Two layers:
Layer 1 deterministic tooling (no AI at runtime), Layer 2 reasoning (design of
attacks, reviewed by the maintainer). Build order:
- 8.1 bp2_verify fuzzing (untrusted proof bytes → grin C FFI → consensus).
- 8.2 Consensus invariants (proptest): no inflation, no double-spend, balance
      equation holds.
- 8.3 Mimblewimble attack catalog (private): inflation, double-spend,
      cut-through abuse, kernel/offset forgery, range-proof attacks, privacy,
      P2P (eclipse/sybil/exhaustion).
- 8.4 Static checks: cargo-audit (dependency CVEs), security clippy lints.
- 8.5 Orchestrator + finding reports (severity, trigger, file:line, minimal
      reproducer, fix + regression test).

### Phase 9 — Mainnet Readiness Gate (FINAL)
Launch model: mainnet from block zero — no premine, no private round, no
public testnet (avoids creating insiders).
- 9.1 dom-shield audit complete across consensus + crypto + storage + P2P,
      with all findings resolved or carrying maintainer-accepted residual risk.
- 9.2 Sustained fuzzing campaign (target on the order of 10,000+ CPU-hours)
      with zero unresolved crashes on consensus-critical parsers/verifiers.
- 9.3 Audit performed by the project's own audit software (dom-shield); its
      reports reviewed and signed off by the maintainer (Soren Planck).
- 9.4 Private burn-in: the maintainer runs a real continuous chain (single
      operator, not public) long enough to surface time-dependent issues
      (memory growth, stability under load, slow leaks) that static analysis
      and fuzzing cannot. No public participants — preserves the no-insiders
      principle while still validating live behavior.
- 9.5 Genesis ceremony: deterministic genesis, message
      "Not a store of value. A means of exchange."

## Non-negotiables

- Mainnet does not launch until ALL Phase 9 items complete.
- Mainnet does not launch until all CRITICAL items across Phases 1–6 complete.
- HIGH items must be either complete or carry documented residual risk
  accepted by the maintainer.
- No public testnet (philosophical choice, not a shortcut): all validation
  happens before block zero, via the audit software and the private burn-in.
- No exceptions for marketing, deadline, or competitive pressure.

## Principle

The cost of thorough hardening is trivial compared to the cost of a consensus
failure in production. This roadmap is milestone-based, not calendar-based:
each gate opens only when its work is actually done.
