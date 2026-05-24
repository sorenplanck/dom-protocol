# DOM Protocol — Roadmap v2 (post Track A consolidated audit)

Status: ADOPTED 2026-05-24
Replaces: ad-hoc roadmap implied by Docs 8-11 + initial testnet schedule.
Trigger: Track A consolidated audit + hardening checklist from external
blockchain-specialist AI auditor. Decision made under principle
"Security > Stability > Usability".

## Current state (snapshot)

Docs 1-7: complete.
Docs 8-10: complete (8 partial — spend_e2e blocked by env until VPS).
Network::Regtest: complete (commits in B7 series).
Audit findings A-01..A-06: addressed (commits 74aa11f..1b26b13).
Tests: 282+ unit, 11 fuzz targets (~55M inputs zero crashes).

## Phases

Phase 1 — Consensus Immutability Lock (CRITICAL, ~3-6 months)
- 1.1 Replay determinism proofs
 - deterministic replay suite
 - snapshot/replay equivalence tests
 - cross-node replay comparison
- 1.2 Reorg equivalence closure
 - automated reorg simulation framework
 - randomized reorg fuzzing
 - rollback/replay equivalence assertions
- 1.3 PMMR formal hardening
 - PMMR corruption tests
 - rewind equivalence tests
 - randomized insertion/removal tests
- 1.4 Cross-platform equivalence CI
 - Linux + Windows + macOS
 - x86_64 + ARM
 - root equivalence snapshots
 - serialization equivalence suite

Phase 2 — Cryptographic Hardening (HIGH, ~1-2 months, parallel)
- 2.1 Differential testing (1000+ vectors vs rust-secp256k1-zkp, BIP-340,
      Monero, Grin)
- 2.2 Explicit infinity rejection (R, P, subgroup correctness)
- 2.3 Constant-time review (ctgrind, dudect, side-channel analysis)
- 2.4 Full Bulletproofs+ adversarial suite
- 2.5 Secret memory hygiene (zeroize, compiler-resistant wipes)

Phase 3 — Storage Durability (CRITICAL, ~2-3 months, parallel with Phase 1)
- 3.1 Crash consistency testing
 - SIGKILL during commit
 - SIGKILL during rollback
 - SIGKILL during PMMR flush
 - interrupted sync
- 3.2 Partial persistence detection
 - body without header
 - header without index
 - partial PMMR
 - orphan partial persistence
- 3.3 LMDB hardening
 - overwrite policy classes (formalized beyond current NO_OVERWRITE)
 - corruption detection
 - map_size growth strategy
 - ENOSPC handling
- 3.4 Filesystem adversarial testing (ext4, xfs, btrfs, zfs flush durability)

Phase 4 — Adversarial Network Hardening (HIGH, ~2-3 months)
- 4.1 IBD adversarial replay framework
- 4.2 Eclipse resistance
- 4.3 Resource exhaustion defense
- 4.4 Sybil resistance

Phase 5 — Economic Security (HIGH, ~2-3 months)
- 5.1 ASERT adversarial modeling
- 5.2 Miner game theory
- 5.3 Mempool hardening

Phase 6 — Recoverability Proofs (CRITICAL, depends on Phase 1+3)
- 6.1 Recovery equivalence (bit-for-bit post crash/rollback/replay/partial sync)
- 6.2 Corruption detection (detect + refuse unsafe continuation + safe rebuild)
- 6.3 Bootstrap recoverability

Phase 7 — Spec ↔ Code Locking (HIGH, parallel ongoing)
- 7.1 RFC authoritative model
- 7.2 Drift elimination
- 7.3 Tests as spec

Phase 8 — Mainnet Readiness Gate (FINAL)
- 8.1 Public adversarial testnet 90+ days
- 8.2 Fuzzing campaign — minimum 10,000+ CPU-hours
- 8.3 External independent audit
- 8.4 Bug bounty 30-90 days minimum
- 8.5 Genesis ceremony

## Timeline

Realistic: 12-18 months from 2026-05-24 to mainnet.
Optimistic (parallel execution): 12 months.
Pessimistic: 18-24 months.

## Non-negotiables

- Mainnet does not launch until ALL Phase 8 items complete.
- Mainnet does not launch until all CRITICAL items across Phases 1-6 complete.
- HIGH items must be either complete or have documented residual risk
 accepted by maintainer.
- Public testnet must run 90+ days continuous without consensus break.
- No exceptions for marketing pressure, deadline pressure, or competitive
 pressure.

## Principle reaffirmed

> "Blockchain não é hobby. Erros matam projetos e pessoas perdem fundos."

This roadmap exists because every blockchain that died young died of
exactly the items listed above. The cost of 12-18 months of hardening
is trivial compared to the cost of mainnet failure.
