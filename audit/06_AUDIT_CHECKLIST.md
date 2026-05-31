# DOM Protocol Audit Checklist

## 1. Repository Recon

- [ ] Identify all crates and binaries.
- [ ] Identify consensus-critical modules.
- [ ] Identify wallet-critical modules.
- [ ] Identify P2P and RPC entrypoints.
- [ ] Identify database/state storage modules.
- [ ] Identify tests, fuzz targets, fixtures, and CI workflows.

## 2. Consensus Audit

- [ ] Trace block validation from network/RPC/miner input to state mutation.
- [ ] Verify transaction validation rules.
- [ ] Verify UTXO spend and insert logic.
- [ ] Verify duplicate input/output handling.
- [ ] Verify coinbase and emission rules.
- [ ] Verify difficulty target enforcement.
- [ ] Verify chain selection and reorg logic.
- [ ] Verify deterministic serialization and hashing.
- [ ] Verify restart/replay consistency.

## 3. Cryptography Audit

- [ ] Verify commitment validation.
- [ ] Verify range proof enforcement.
- [ ] Verify kernel signature validation.
- [ ] Verify excess and fee accounting.
- [ ] Verify secure randomness in wallet paths.
- [ ] Verify no secrets are logged.
- [ ] Verify no cryptographic validation is bypassed in production.

## 4. Mempool Audit

- [ ] Verify admission validation.
- [ ] Verify conflict detection.
- [ ] Verify orphan handling.
- [ ] Verify reorg reconciliation.
- [ ] Verify size, fee, and eviction policy.
- [ ] Verify DoS resistance.

## 5. P2P Audit

- [ ] Verify message size limits.
- [ ] Verify parser error handling.
- [ ] Verify peer scoring and bans.
- [ ] Verify rate limiting.
- [ ] Verify block/transaction propagation validation.
- [ ] Verify resistance to malformed peer behavior.

## 6. Wallet Audit

- [ ] Verify key generation and storage.
- [ ] Verify transaction construction.
- [ ] Verify fee calculation.
- [ ] Verify change output handling.
- [ ] Verify sync and reorg handling.
- [ ] Verify recovery behavior.
- [ ] Verify user-facing error handling.

## 7. Tests Required

- [ ] Negative tests for invalid blocks.
- [ ] Negative tests for invalid transactions.
- [ ] Double-spend tests.
- [ ] Reorg tests.
- [ ] Mempool conflict tests.
- [ ] Serialization determinism tests.
- [ ] Database restart/replay tests.
- [ ] P2P malformed message tests.
- [ ] Wallet transaction construction tests.

## 8. Final Review

- [ ] No forbidden files changed without authorization.
- [ ] No consensus weakening.
- [ ] No fake metrics, fake validations, or placeholder security.
- [ ] All required validation commands run or explicitly justified if unavailable.
- [ ] Findings classified by severity.
- [ ] Remediation plan produced.

