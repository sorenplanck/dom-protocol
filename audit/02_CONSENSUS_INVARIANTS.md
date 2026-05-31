# DOM Protocol Consensus Invariants

## Absolute Rule

Consensus rules must never be weakened to pass tests or simplify implementation. Any change to consensus must be explicitly authorized and documented.

## Core Invariants

### Monetary Safety

- No transaction may create value outside authorized coinbase/emission rules.
- Sum of inputs, outputs, fees, and kernel excess must validate according to protocol rules.
- Coinbase outputs must obey maturity rules.
- Emission schedule must be deterministic and enforced.
- Supply accounting must be auditable and deterministic across nodes.

### Transaction Validity

- Every input must reference an existing, unspent output.
- Every spent output must be removed exactly once.
- Every new output must be inserted exactly once.
- Duplicate inputs are invalid.
- Duplicate outputs or commitment collisions must be rejected or safely handled.
- Range proofs must be verified where applicable.
- Kernel signatures and excess commitments must be verified.
- Lock heights, timelocks, maturity, and replay constraints must be enforced.

### Block Validity

- Block headers must validate against the configured consensus rules.
- Parent references must be valid except for genesis.
- Timestamp rules must be deterministic and resistant to manipulation.
- Difficulty target must be enforced exactly.
- Block weight/size limits must be enforced.
- Transaction aggregation and cut-through must not hide invalid spends.
- Coinbase count and placement must obey protocol rules.

### Chain Selection and Reorgs

- Chain selection must be deterministic.
- Heavier/valid chain rules must not allow invalid state transitions.
- Reorgs must correctly disconnect old blocks and connect new blocks.
- UTXO state after reorg must match deterministic replay.
- Mempool must be reconciled safely after reorg.
- No double-spend may survive reorg reconciliation.

### Mempool Consistency

- Mempool admission must use equivalent validity rules to block inclusion, except for explicitly documented policy differences.
- Conflicting spends must be rejected or deterministically resolved.
- Orphans must not bypass full validation when parents arrive.
- Reorgs must not reintroduce invalid or already-spent transactions.

### Persistence and Recovery

- Restarting a node must not change consensus state.
- Persisted chain state must match replayed state.
- Corrupt or partial database writes must be detected or recovered safely.
- Genesis state must be deterministic and immutable unless explicitly authorized.

## Red Flags

Treat these as high-risk changes:

- Removing validation checks.
- Changing default difficulty, genesis, emission, maturity, or chain selection.
- Replacing validation errors with warnings.
- Accepting malformed data for compatibility.
- Adding bypass flags or permissive fallback paths.
- Making tests pass by weakening invariants.

