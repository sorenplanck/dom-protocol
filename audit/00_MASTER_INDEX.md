# DOM Protocol Audit Knowledge Base - Master Index

Compatibility path for tools and instructions that expect
`audit/00_MASTER_INDEX.md`.

The original repository path `audit/00_MASTER_INDEX` remains present for
backward compatibility. This `.md` file is intentionally equivalent in meaning
and should be kept aligned with that file if the audit index is updated.

## Purpose

This directory is the operational knowledge base for Codex or any auditor
working on DOM Protocol. It defines the audit scope, mandatory invariants,
threat model, forbidden files, validation commands, and reporting format.

## Reading Order for Full Audit

1. `01_PROTOCOL_OVERVIEW.md` - architecture and subsystem map.
2. `02_CONSENSUS_INVARIANTS.md` - rules that must never be weakened.
3. `03_CRYPTOGRAPHIC_ASSUMPTIONS.md` - cryptographic primitives and assumptions.
4. `04_THREAT_MODEL.md` - known attacker models and exploit classes.
5. `05_ATTACK_SURFACES.md` - subsystem-by-subsystem attack surface.
6. `06_AUDIT_CHECKLIST.md` - complete audit checklist.
7. `07_FORBIDDEN_FILES.md` - files that cannot be changed without explicit authorization.
8. `08_VALIDATION_COMMANDS.md` - required validation commands.
9. `09_KNOWN_RISKS.md` - known risks, fragile areas, and unresolved concerns.
10. `10_REPORT_TEMPLATE.md` - final report format.

## Mandatory Rule

No audit, patch, refactor, or automated change may proceed without first reading
this index and the relevant documents listed above.

## Expected Audit Output

Every audit pass must produce:

- Executive summary.
- Scope reviewed.
- Files inspected.
- Findings by severity.
- Consensus impact assessment.
- Cryptography impact assessment.
- Mempool/reorg/double-spend assessment.
- Wallet safety assessment.
- P2P/DoS assessment.
- Validation evidence.
- Remaining risks.
