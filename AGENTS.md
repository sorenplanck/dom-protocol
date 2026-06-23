# DOM Protocol — Codex Operational Instructions

## Mission

You are operating inside the real DOM Protocol repository. Treat this repository as a pre-mainnet blockchain protocol codebase. Your role is to assist with security review, protocol hardening, validation, test creation, and controlled remediation.

## Mandatory Reading Before Any Audit or Patch

Before auditing, modifying, refactoring, deleting, renaming, or generating files, read these documents:

1. `audit/00_MASTER_INDEX.md`
2. `audit/01_PROTOCOL_OVERVIEW.md`
3. `audit/02_CONSENSUS_INVARIANTS.md`
4. `audit/03_CRYPTOGRAPHIC_ASSUMPTIONS.md`
5. `audit/04_THREAT_MODEL.md`
6. `audit/05_ATTACK_SURFACES.md`
7. `audit/06_AUDIT_CHECKLIST.md`
8. `audit/07_FORBIDDEN_FILES.md`
9. `audit/08_VALIDATION_COMMANDS.md`
10. `audit/09_KNOWN_RISKS.md`
11. `audit/10_REPORT_TEMPLATE.md`

## Operating Rules

- Do not treat these files as documentation to summarize only. Use them as mandatory operational constraints.
- Do not modify forbidden files unless the user explicitly authorizes the exact file and exact purpose.
- Never weaken consensus, cryptographic, validation, difficulty, wallet, mempool, chain, or P2P invariants to make tests pass.
- Never replace real validation with stubs, mocks, fake values, placeholder checks, or permissive bypasses.
- Prefer adding tests before changing protocol logic.
- Preserve backward-compatible behavior unless the task explicitly requires a breaking protocol change.
- Classify findings by severity: Critical, High, Medium, Low, Informational.
- Every security finding must include: impact, exploitability, affected files, proof or reasoning, recommended fix, and validation commands.
- Every patch must include validation evidence.
- After every successful commit, push commits to GitHub unless explicitly told not to.

## Required Workflow

1. Recon: map affected crates, modules, invariants, and tests.
2. Risk analysis: identify protocol-critical paths and possible exploit classes.
3. Plan: produce a concise implementation/audit plan before edits.
4. Test-first when feasible: add regression or negative tests before patching.
5. Patch: minimal, scoped, auditable changes.
6. Validate: run the commands defined in `audit/08_VALIDATION_COMMANDS.md`.
7. Report: produce final audit or patch report using `audit/10_REPORT_TEMPLATE.md`.

## Hard Stop Conditions

Stop and report instead of patching if:

- A change would alter consensus rules without explicit authorization.
- A change would modify genesis, emission, difficulty, cryptographic verification, kernel validation, or block acceptance rules.
- A validation failure appears unrelated to the requested scope and could indicate baseline corruption.
- You cannot distinguish between expected protocol behavior and a security flaw.

## dom-shield: test-construction method (locked 2026-06-22)

The goal of dom-shield is to BUILD THE TESTS that discover bugs by running — not to audit-and-fix by hand. The shield is the auditor; we build the auditor.

For EACH part of the code (attackable crate/module/function), the flow is:

1. **EXHAUSTIVELY ENUMERATE the attack vectors** — NOT "find the bug". List EVERY way to break/attack the part, through two lenses:
   - Lens A (bug-per-function): panic/crash, incorrect result / non-conformance with spec, non-determinism, malleability, DoS/amplification, overflow.
   - Lens B (Lazarus Group / crypto APT): key extraction (zeroization of ALL intermediates, not just fields), prediction (entropy/CSPRNG), side-channel (every op over secret bytes non constant-time), supply-chain (provenance of each dep), cross-impl differential (do versions derive identically?).

2. **ONE TEST PER VECTOR.** If the part has N distinct vectors, it has N tests. No fewer (no uncovered door), no more (no theater). The number of tests = the number of attack vectors.

3. **RIGHT TECHNIQUE PER VECTOR** — choose the one fit for that door, not a default:
   - correctness/conformance → known-answer vectors (KAV) against spec/external reference
   - panic/crash/OOB → fuzz (cargo-fuzz)
   - invariant/property → proptest
   - corrupted persisted state → directed-corruption test
   - side-channel → timing test (dudect) / static review
   - divergence between implementations → differential harness (XDIFF)
   - supply-chain → cargo-deny/cargo-audit
   - DoS-amplification → fuzz + resource-limit assert, or analysis if there is no multiplier

4. **ANTI-THEATER:** a test is justified only if the vector is genuinely attackable. Proving by analysis that a vector is NOT exploitable (bounded by construction, source outside the threat model) is worth as much as writing the test — record it with justification, no theater test.

5. **SCOPE:** every attackable surface is in (incl. funds-safety/crypto labeled as wallet). Only genuinely non-attackable tooling (cli, test-runners) stays out. Privacy/de-anon (I4) is deprioritized for being outside the critical threat model, not for being non-attackable.

6. **PER-TEST RITUAL:** create in dom-protocol (Part A) → register in dom-shield COVERAGE.md + run-audit.sh if fuzz (Part B) → atomic commit (Soren Planck, no trailers). Push is a human decision after OPSEC verification.

7. **BUILDING A TEST ≠ FIXING A BUG.** Building the test is safe (read-only over behavior). Fixing what the test exposes is a separate task and REQUIRES HUMAN DECISION when it touches consensus/key-derivation/format. The shield discovers; the fix is a separate queue.

**Reference example — dom-wallet-keys:** 41 distinct attack vectors enumerated (Lens A: BIP-32 conformance, modular reduction, panic on seed/path, blinding/masks; Lens B: zeroization, entropy, side-channel, supply-chain, cross-impl v1↔v2). 41 vectors = ~41 tests. That is the real scale of covering a part properly.

