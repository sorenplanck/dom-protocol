# DOM Protocol Threat Model

## Attacker Model

Assume attackers can:

- Submit arbitrary transactions.
- Connect as peers and send malformed P2P messages.
- Mine or simulate blocks under adversarial conditions.
- Attempt reorgs, double spends, and mempool conflicts.
- Restart, desync, or resource-exhaust nodes.
- Exploit serialization, database, wallet, and networking edge cases.
- Observe public network traffic.
- Run modified clients.

Do not assume peers, wallets, miners, or RPC clients are honest.

## Critical Attack Classes

### Inflation Attacks

Goal: create coins outside allowed emission.

Audit targets:

- Transaction balance equation.
- Kernel validation.
- Range proof enforcement.
- Coinbase validation.
- Cut-through and aggregation.
- Block connection logic.

Severity: Critical.

### Double-Spend Attacks

Goal: spend the same output more than once.

Audit targets:

- UTXO spend marking.
- Duplicate input detection.
- Mempool conflict detection.
- Reorg disconnect/connect logic.
- Orphan transaction handling.
- Concurrent block/tx processing.

Severity: Critical or High.

### Invalid Block Acceptance

Goal: make nodes accept blocks that violate consensus.

Audit targets:

- Header validation.
- Parent validation.
- Difficulty enforcement.
- Timestamp rules.
- Coinbase rules.
- Transaction validation inside block.
- State transition atomicity.

Severity: Critical.

### Consensus Split

Goal: make honest nodes disagree on canonical chain or state.

Audit targets:

- Serialization and hashing.
- Non-deterministic iteration.
- Platform-dependent behavior.
- Time-dependent validation.
- Database recovery.
- Reorg tie-breaking.

Severity: Critical.

### Mempool Poisoning

Goal: fill or corrupt mempool with invalid, conflicting, or resource-heavy transactions.

Audit targets:

- Admission policy.
- Size and fee limits.
- Orphan handling.
- Conflict resolution.
- Revalidation after reorg.
- Rate limiting.

Severity: High.

### P2P Denial of Service

Goal: exhaust CPU, memory, disk, file descriptors, or bandwidth.

Audit targets:

- Message size limits.
- Parsing limits.
- Peer scoring.
- Ban policy.
- Backpressure.
- Request/response amplification.
- Unbounded queues.

Severity: High.

### Eclipse and Isolation Attacks

Goal: isolate a node from honest peers.

Audit targets:

- Peer diversity.
- Peer selection.
- Address manager.
- Inbound/outbound connection policy.
- Ban and scoring manipulation.

Severity: High or Medium.

### Wallet Loss or Mis-Spend

Goal: cause fund loss, incorrect balance, replay, or failed recovery.

Audit targets:

- Key storage.
- Seed recovery.
- Change output handling.
- Transaction construction.
- Fee calculation.
- Broadcast retry behavior.
- Sync correctness.

Severity: High.

