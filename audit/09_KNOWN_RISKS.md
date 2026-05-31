# DOM Protocol Known Risks and Fragile Areas

## Purpose

This file tracks known risks, unresolved concerns, and fragile areas. Update after every major audit pass.

## Current Known Risk Categories

### Consensus-Critical Unknowns

- Exact genesis immutability guarantees must be confirmed.
- Exact difficulty adjustment algorithm must be reviewed.
- Exact emission schedule enforcement must be reviewed.
- Exact reorg and rollback behavior must be reviewed.

### Cryptographic Unknowns

- Commitment and range proof implementation must be traced end-to-end.
- Kernel signature domain separation must be verified.
- Serialization used for signing and hashing must be verified as canonical.

### Mempool Unknowns

- Conflict resolution under reorg must be verified.
- Orphan handling must be verified.
- Resource limits must be confirmed.

### P2P Unknowns

- Message size and rate limits must be confirmed.
- Peer scoring and ban policy must be confirmed.
- Eclipse resistance must be reviewed.

### Wallet Unknowns

- Seed/key generation and storage must be reviewed.
- Transaction construction must be tested for edge cases.
- Wallet behavior across reorgs must be verified.

## Finding Format

Add known risks using this format:

```markdown
## RISK-YYYY-MM-DD-001 — Title

Severity: Critical | High | Medium | Low | Informational
Status: Open | Mitigated | Accepted | Needs Review
Area: Consensus | Crypto | Mempool | P2P | Wallet | Storage | CI
Affected files:
- path/to/file.rs

Description:

Impact:

Recommended next step:

Validation required:
```

