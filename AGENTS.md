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

