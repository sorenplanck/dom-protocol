# DOM Protocol Overview

## Objective

DOM Protocol is treated as a pre-mainnet blockchain protocol requiring security-first review. The auditor must understand and preserve all protocol-critical behavior.

## Core Subsystems to Map

Update this file with exact paths after inspecting the repository.

### Consensus / Chain

Expected responsibilities:

- Block validation.
- Header validation.
- Chain state transition.
- Reorg handling.
- Difficulty adjustment.
- Coinbase rules.
- Supply/emission constraints.
- UTXO set integrity.

Potential paths to inspect:

- `crates/dom-chain/`
- `crates/dom-consensus/`
- `crates/dom-node/`
- `src/chain/`
- `src/consensus/`

### Cryptography / Mimblewimble

Expected responsibilities:

- Pedersen commitments.
- Range proofs.
- Kernel signatures.
- Excess validation.
- Cut-through safety.
- Transaction aggregation.
- Balance equation validation.

Potential paths to inspect:

- `crates/dom-crypto/`
- `crates/dom-chain/src/tx/`
- `src/crypto/`
- `src/mimblewimble/`

### Mempool

Expected responsibilities:

- Transaction admission.
- Double-spend prevention.
- Orphan handling.
- Reorg reconciliation.
- Fee and priority rules.
- DoS resistance.

Potential paths to inspect:

- `crates/dom-mempool/`
- `crates/dom-node/src/mempool/`

### P2P / Networking

Expected responsibilities:

- Peer discovery.
- Message validation.
- Peer scoring.
- Rate limiting.
- Ban policy.
- Block and transaction propagation.
- Eclipse and spam resistance.

Potential paths to inspect:

- `crates/dom-p2p/`
- `crates/dom-node/src/net/`

### Wallet

Expected responsibilities:

- Key management.
- Address/account handling.
- Transaction construction.
- Change output safety.
- Replay protection.
- Sync correctness.
- Error handling around failed broadcasts.

Potential paths to inspect:

- `crates/dom-wallet/`
- `crates/dom-wallet-app/`

### Mining

Expected responsibilities:

- Candidate block construction.
- Coinbase creation.
- Difficulty target enforcement.
- Header nonce search.
- Block submission validation.

Potential paths to inspect:

- `crates/dom-miner/`
- `crates/dom-node/src/mining/`

## Audit Principle

The auditor must not assume correctness from naming, comments, or previous tests. Each protocol-critical path must be traced from external input to validation, state mutation, and persistence.

