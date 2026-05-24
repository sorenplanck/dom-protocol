# DOM Protocol Roadmap v2: Mainnet Launch Phases

**Version:** 2.0  
**Effective Date:** 2026-05-24  
**Target Mainnet Launch:** Q4 2027 (12-18 months)  
**Current Status:** Post-B7 (Regtest complete), beginning Phase 1

---

## Executive Summary

This roadmap outlines 8 sequential hardening phases to achieve mainnet launch. Each phase is atomic (start→completion) with defined scope, deliverables, and go/no-go criteria. The roadmap prioritizes **Security > Stability > Usability** per the DOM whitepaper (May 2026).

**Key Constraints:**
- Consensus constants are FROZEN (COINBASE_MATURITY, GENESIS_HASH_MAINNET, target bounds)
- No breaking changes to core consensus logic
- All security findings from audits must be resolved before mainnet
- Testnet must be stable 3+ months before launch

---

## Timeline Overview

```
2026-05-24 (Today) ──→ 2026-12-24 (Phases 1-4) ──→ 2027-03-24 (Phases 5-6) ──→ 2027-06-24 (Phases 7-8) ──→ Q4 2027 (Mainnet)
  ↓ Phase 1                  ↓ Phase 5                 ↓ Phase 7
  Consensus Immutability     Economic Security        Mainnet Gate
```

| Phase | Name | Duration | Start | End |
|-------|------|----------|-------|-----|
| 1 | Consensus Immutability | 8 weeks | 2026-05-24 | 2026-07-18 |
| 2 | Cryptographic Hardening | 8 weeks | 2026-07-18 | 2026-09-12 |
| 3 | Storage Durability | 8 weeks | 2026-09-12 | 2026-11-07 |
| 4 | Network Hardening | 8 weeks | 2026-11-07 | 2026-12-26 |
| 5 | Economic Security | 8 weeks | 2026-12-26 | 2027-02-20 |
| 6 | Recoverability | 8 weeks | 2027-02-20 | 2027-04-17 |
| 7 | Specification Locking | 4 weeks | 2027-04-17 | 2027-05-15 |
| 8 | Mainnet Gate | 8 weeks | 2027-05-15 | 2027-07-10 |

**Total: ~72 weeks (~18 months)** with 2-week phase transitions for testing/integration.

---

## Phase 1: Consensus Immutability (Weeks 1-8)

**Goal:** Lock consensus rules and prove they cannot change without a hard fork.

### Deliverables

1. **Consensus Specification Finalization**
   - Audit all 10 RFCs (RFC-0007 through RFC-0011) against code
   - Document any discrepancies as explicit RFC amendments
   - Version as RFC v1.0 (immutable, timestamped)
   - Create spec PDF/HTML for offline reference

2. **Consensus Test Vectors**
   - 50+ deterministic test vectors covering:
     - Valid transactions (all kernel types, outputs, inputs)
     - Valid blocks (empty, max-size, reorg scenarios)
     - Invalid transactions (all rejection reasons)
     - Invalid blocks (all rejection reasons)
     - Edge cases (balance equation edge cases, weight overflows, etc.)
   - Test vectors in JSON format with expected outcomes
   - Cross-validate with independent implementation (if possible)

3. **Consensus Immutability Audit**
   - Formal review of consensus paths (dom-consensus, dom-chain)
   - Verify no runtime switches can alter validation logic
   - Confirm all thresholds are constants (not config)
   - Ensure hard fork detection is clear (version number, timestamp gate)

4. **Frozen Constants Registry**
   - Document all consensus constants in CONSENSUS.md:
     - TARGET_SPACING, ASERT_HALF_LIFE, ASERT_RADIX_BITS
     - COINBASE_MATURITY, BLOCK_REWARD_TABLE, HALVING_INTERVAL
     - MAX_BLOCK_WEIGHT, MAX_TX_WEIGHT, MAX_INPUTS_PER_TX
     - All PoW bounds (MIN_TARGET_BYTES, MAX_TARGET_BYTES)
   - Add compile-time assertion for each constant's immutability
   - Timestamp the lock: "Frozen on <date> for mainnet launch"

### Go/No-Go Criteria

- [ ] All RFC amendments merged and versioned
- [ ] 50+ test vectors created and pass on current code
- [ ] No consensus logic changes allowed after this phase (hard rule)
- [ ] Immutability audit passes (independent reviewer)
- [ ] Frozen constants registry complete + testnet node rejects blocks with mismatched constants

### Success Metric

"Consensus rules are provably fixed and cannot change without hard fork."

---

## Phase 2: Cryptographic Hardening (Weeks 9-16)

**Goal:** Audit and harden all cryptographic primitives (Schnorr, Pedersen, Bulletproofs, Blake2b, RandomX).

### Deliverables

1. **Cryptographic Audit**
   - Independent third-party audit of dom-crypto crate:
     - Schnorr signatures (RFC 8032 + BIP 340 compliance)
     - Pedersen commitments (curve math, point validation)
     - Bulletproofs+ range proofs (proof correctness, soundness)
     - Blake2b-256 hashing (domain separation, collision resistance)
   - Deliver audit report with remediation plan
   - Fix all HIGH/CRITICAL findings; document MEDIUM findings

2. **RandomX Hardening**
   - Validate RandomX integration (no unsafe blocks, correct flags)
   - Test RandomX behavior under CPU/memory constraints
   - Verify seed rotation timing (seed_height, reorg safety)
   - Add fuzzing targets for hash preimage validation

3. **Cryptographic Test Suite**
   - 100+ test cases for each primitive:
     - Schnorr: signature generation, verification, rejection cases
     - Pedersen: commitment, opening, range proof binding
     - Bulletproofs: proofs of different value ranges, edge cases
     - Blake2b: known-answer tests (KAT), domain separation
   - Performance benchmarks (signature/sec, proof verify/sec)

4. **Key Material Handling**
   - Audit all secret key usage in codebase (wallet, miner, Node)
   - Ensure no key leakage in logs/errors
   - Validate key derivation (BIP-32, constant time)
   - Add secure wipe tests (memory zeroing after use)

### Go/No-Go Criteria

- [ ] External audit completed with remediations merged
- [ ] 100+ crypto tests pass; fuzzing harness created
- [ ] No HIGH/CRITICAL findings remain
- [ ] RandomX integration reviewed and hardened
- [ ] Key material handling audit cleared

### Success Metric

"All cryptographic primitives have passed external audit and fuzzing."

---

## Phase 3: Storage Durability (Weeks 17-24)

**Goal:** Harden LMDB storage layer for data integrity and corruption recovery.

### Deliverables

1. **Storage Durability Audit**
   - Independent audit of dom-store (LMDB integration):
     - Transaction atomicity (all-or-nothing block commits)
     - Concurrency safety (lock-free, mutex correctness)
     - Data durability (fsync timing, map growth)
     - Corruption detection (checksums, invariant checks)
   - Fix all issues; document recovery procedures

2. **Corruption Detection & Recovery**
   - Implement checksums (BLAKE2B-256) for all stored values
   - Add invariant validation on startup:
     - Height index matches chain tip
     - UTXO commitments match stored values
     - Kernel index consistency
   - Create `--rebuild-db` recovery mode
   - Document recovery procedures in ops runbook

3. **Storage Persistence Tests**
   - Crash simulation: kill process mid-block, verify recovery
   - Disk full simulation: verify graceful degradation
   - Map size growth: test 10MB → 1GB scenarios
   - Reorg stress: 1000 blocks reorg + persistence verification

4. **Database Monitoring**
   - Add telemetry (block count, UTXO count, DB size)
   - Export metrics for Prometheus/Grafana
   - Alert on inconsistencies (index mismatch, orphan UTXOs)

### Go/No-Go Criteria

- [ ] Storage durability audit passed
- [ ] Checksums implemented for all values
- [ ] Corruption detection tests pass
- [ ] Recovery procedures documented and tested
- [ ] Monitoring + alerting deployed

### Success Metric

"Storage layer can survive process crashes and recover without data loss."

---

## Phase 4: Network Hardening (Weeks 25-32)

**Goal:** Harden P2P network for DoS resistance, peer management, and relay security.

### Deliverables

1. **Network Security Audit**
   - Independent audit of dom-wire and dom-node network code:
     - Noise protocol (handshake, encryption, authentication)
     - Message framing (deserialization bounds, size limits)
     - IBD logic (block request ordering, timeout handling)
     - Block relay (propagation safety, rebroadcast prevention)
   - Fix all HIGH/CRITICAL findings

2. **DoS Mitigation**
   - Rate limiting (per-peer message limits)
   - Bandwidth accounting (input/output bytes per peer)
   - Ban scoring (automated peer disconnect for abuse)
   - Conn limits (max inbound, max outbound per IP)
   - Test with adversarial node (send junk, slow hashes, etc.)

3. **Peer Discovery & Stability**
   - DNS seed validation (retry, timeout, fallback)
   - Peer database persistence (UPnP addresses, hardened peers)
   - Connection diversification (subnet isolation, min outbound)
   - Peer scoring (uptime, block delivery, validation passes)
   - Test: simulate 30% peer churn, verify network stays connected

4. **Relay Loop Prevention**
   - Audit transaction + block relay for duplicate transmissions
   - Verify Dandelion++ stem/fluff state machine
   - Test relay with 100+ nodes, verify no explosion
   - Document relay policy (min fee rate, priority)

### Go/No-Go Criteria

- [ ] Network security audit passed
- [ ] DoS mitigation deployed + tested against adversarial peer
- [ ] Peer discovery stable over 1 week of continuous running
- [ ] Relay loop detection + prevention verified
- [ ] Bandwidth limits per peer enforced

### Success Metric

"Network can survive DoS attacks and maintains stable peer connectivity."

---

## Phase 5: Economic Security (Weeks 33-40)

**Goal:** Verify economic incentives and attack cost/benefit.

### Deliverables

1. **Monetary Policy Audit**
   - Verify block rewards match spec (33M total, 67% halving)
   - Verify fee calculation (weight × rate_per_unit)
   - Verify coinbase maturity (1000 blocks = ~1.4 days)
   - Test halving logic at epochs 0, 1, 54 (edge cases)
   - Document economic assumptions (mining cost, market price)

2. **Attack Cost Analysis**
   - 51% attack: compute cost (RandomX GH/s) vs mining reward/day
   - Double spend cost: transaction fee vs coinbase value
   - Sybil attack cost: node count vs peer limits
   - Long-range attack: storage cost of full chain (1 year = ~100GB)
   - Create attack matrix documenting relative costs

3. **Incentive Compatibility Tests**
   - Test: honest mining > selfish mining (on Testnet)
   - Test: transaction fee > coin age attack
   - Test: ASERT difficulty adjustment (no difficulty collapse)
   - Verify miner has no incentive to withhold blocks
   - Document game-theoretic security model

4. **Fee Market Simulation**
   - Run 30-day Testnet burn-in with synthetic load (100 tx/sec)
   - Monitor fee evolution (min → max over time)
   - Verify no congestion collapse or fee spiral
   - Document recommended fee rate guidance

### Go/No-Go Criteria

- [ ] Monetary policy audit passed
- [ ] Attack cost matrix published
- [ ] All incentive compatibility tests pass
- [ ] 30-day Testnet burn-in completed without incidents
- [ ] Fee market guidance documented

### Success Metric

"Economic incentives align with honest mining; attacks are economically infeasible."

---

## Phase 6: Recoverability (Weeks 41-48)

**Goal:** Enable users to recover funds from wallet backups and emergency scenarios.

### Deliverables

1. **Wallet Recovery Testing**
   - Test HD wallet derivation (BIP-32):
     - Seed → master key → child keys → addresses
     - Verify deterministic across 1000 iterations
     - Test with Testnet transactions (spend + recovery)
   - Test mnemonic backup (12-word, 24-word):
     - Generate → backup → import → recover balance
     - Cross-validate with hardware wallet (if available)

2. **Cold Storage Procedures**
   - Document air-gapped key generation (no internet)
   - Test seed splitting (Shamir secret sharing with 3-of-5)
   - Verify paper wallet printout + QR codes
   - Create recovery runbook for lost keys (prove ownership)

3. **Disaster Recovery Modes**
   - `--rebuild-db` mode to reconstruct chain from peers
   - `--scan-blockchain` mode to recover all owned outputs
   - `--export-keys` mode to backup in plaintext (encrypted storage)
   - Test each mode with Testnet (10GB chain)

4. **Security Review**
   - Audit wallet crate for key material leaks
   - Verify password stretching (Argon2 or PBKDF2)
   - Test against known wallet attack vectors
   - Document threat model (local machine compromise, etc.)

### Go/No-Go Criteria

- [ ] HD wallet recovery tested + documented
- [ ] Mnemonic backup/restore working on Testnet
- [ ] Cold storage procedures documented
- [ ] Disaster recovery modes working
- [ ] Wallet security audit passed

### Success Metric

"Users can recover funds from wallet backup with high confidence."

---

## Phase 7: Specification Locking (Weeks 49-52)

**Goal:** Freeze all specifications and create immutable documentation for mainnet.

### Deliverables

1. **Specification Snapshot**
   - Create MAINNET_SPEC_v1.0 PDF with:
     - All RFCs (consolidated into single document)
     - Consensus rules (finalized in Phase 1)
     - Network protocol (P2P message format, serialization)
     - Wallet specification (derivation, encryption, backup)
     - Timestamp + cryptographic hash for verification
   - Host immutable copy (IPFS or equivalent)

2. **Compatibility Commitment**
   - Define major.minor.patch versioning
   - Document upgrade path (how nodes will handle hard forks)
   - Commit to not changing consensus rules for 2+ years
   - Create protocol version byte for future extensibility

3. **Implementation Validation**
   - Verify Rust implementation against spec
   - List any deliberate deviations (with rationale)
   - Create independent test vectors (JavaScript, Python, Go)
   - Document how future implementers can validate compliance

4. **Release Candidate Freeze**
   - Tag code as v1.0.0-rc1
   - Branch mainnet/v1.0 (no further changes)
   - Create release notes documenting all phases
   - Announce mainnet launch timeline

### Go/No-Go Criteria

- [ ] Specification PDF complete and immutable
- [ ] Compatibility commitment published
- [ ] Independent test vector implementations pass
- [ ] v1.0.0-rc1 tagged and frozen
- [ ] Mainnet launch date announced (Q4 2027)

### Success Metric

"Specification is immutable; future protocol changes are impossible without hard fork."

---

## Phase 8: Mainnet Gate (Weeks 53-60)

**Goal:** Final security review and mainnet genesis creation.

### Deliverables

1. **Final Security Review**
   - Run all audit findings through remediations
   - Conduct internal security review (Soren + team)
   - Red team penetration test (hire external firm, if resources allow)
   - Fuzzing campaigns (100M+ iterations on critical paths)
   - Fix any findings; document wontfixes with justification

2. **Mainnet Genesis Block**
   - Choose genesis timestamp (launch day + 0:00 UTC)
   - Compute GENESIS_HASH_MAINNET (deterministic from coinbase)
   - Verify consensus node produces identical hash
   - Create immutable genesis snapshot (no replay from Testnet)

3. **Mainnet Readiness Checklist**
   - [ ] All 8 phases complete + passed
   - [ ] 3+ months Testnet stability (>99% uptime)
   - [ ] Independent security audits passed
   - [ ] Community review period (2 weeks for final feedback)
   - [ ] Seed node infrastructure deployed (TBD operator)
   - [ ] DNS seeds configured and tested
   - [ ] RPC/indexer infrastructure ready

4. **Launch Execution**
   - Announce mainnet launch (T-7 days, T-1 day, T-0 countdowns)
   - Coordinate seed node operators to start at T-0
   - Monitor network health (peer count, block time, fee market)
   - Publish launch report (uptime, transactions, security)

### Go/No-Go Criteria

- [ ] All audit findings fixed or documented as acceptable
- [ ] Red team test passed
- [ ] Mainnet genesis hash published and frozen
- [ ] Seed nodes operational and synced
- [ ] Community has 2 weeks for final feedback
- [ ] Security team gives go/no-go approval

### Success Metric

"DOM Protocol mainnet launches with full security review + community consensus."

---

## Cross-Phase Activities

### Continuous (All Phases)

- **Testnet Stability:** Maintain public Testnet with 99.5%+ uptime
- **Documentation:** Update docs/ with every phase completion
- **Community Engagement:** Monthly progress reports + AMA sessions
- **Incident Response:** Fix HIGH/CRITICAL issues within 48 hours

### Testing Infrastructure

- **Unit Tests:** Maintain 95%+ code coverage (cargo tarpaulin)
- **Integration Tests:** E2E tests for all phases (dom-integration-tests)
- **Testnet Load Testing:** 100+ concurrent nodes, 1000+ tx/sec load
- **Fuzzing:** Continuous fuzzing on critical paths (dom-pow, dom-crypto, dom-consensus)

### Performance Targets

- **Block Validation:** <100ms per block (on modern CPU)
- **Transaction Relay:** <1s end-to-end propagation (on 50-node network)
- **IBD Speed:** >1 MB/sec block download (on local network)
- **Memory:** Node process <1 GB RAM (excluding RandomX cache)

### Security Standards

- **Code Review:** 2+ approvals per PR before merge
- **Dependency Audits:** `cargo audit` passing in CI
- **Compiler Warnings:** `cargo clippy` with no warnings
- **Unsafe Code:** Banned (deny unsafe_code in all crates)

---

## Risk Mitigation

### High Risks

| Risk | Mitigation |
|------|-----------|
| **Consensus bug discovered late** | Phase 1 immutability lock prevents changes; hard fork required |
| **RandomX vulnerability found** | Replace with ASERT-only PoW if needed; mainnet migration prepared |
| **Network DoS attack on Testnet** | Documented incident response; peer banning + rate limits ready |
| **Fee market collapse** | Adjust MIN_RELAY_FEE_RATE; economic simulation in Phase 5 |
| **Audit findings too severe** | Extend timeline; cannot launch without clearance |

### Medium Risks

| Risk | Mitigation |
|------|-----------|
| **Wallet key derivation bug** | Testnet recovery testing in Phase 6 catches issues |
| **LMDB data corruption** | Phase 3 checksums + recovery mode; 30-day stress test |
| **Peer discovery failure** | Phase 4 tests DNS fallback + hardcoded seeds |

### Low Risks

| Risk | Mitigation |
|------|-----------|
| **Minor API usability issues** | v1.1 (post-mainnet) can address; v1.0 frozen |
| **Documentation incomplete** | Community contributions accepted post-launch |

---

## Success Criteria

### Per-Phase

- Each phase must reach 100% deliverables before proceeding
- Any HIGH/CRITICAL security finding blocks advancement
- Community consensus required for timeline changes

### Overall

- **Security:** 3+ independent audits passed, zero HIGH findings
- **Stability:** Testnet 99.5%+ uptime for 3+ months
- **Community:** Positive sentiment in Discord/forums during launch window
- **Economic:** Launch with realistic fee market guidance + mining analysis

---

## Post-Mainnet (v1.1+)

After mainnet launch, a v1.1 roadmap will address:

- **Dandelion++ Privacy:** Full deployment on all nodes
- **MuSig2 Multisig:** Multi-owner transactions
- **Wallet Slates:** Transaction negotiation protocol
- **Light Client:** SPV proofs for mobile wallets
- **Sharded UTXO:** Scaling to 1000s of tx/sec

---

## Governance

**Decision Authority:**  
Soren Planck (project lead) in consultation with:
- Security team (2+ members)
- Testnet operators (3+ seed node operators)
- Community (Discord consensus in high-impact decisions)

**Conflict Resolution:**  
- Timeline conflicts: Security > Stability > Usability (hard rule)
- Feature disputes: Frozen constants (consensus) cannot change; go to v1.1 if needed
- Incident response: Lead reviewer decides; documented post-incident report

**Change Procedure:**  
- Minor timeline adjustments: Lead decision (≤2 week slippage)
- Major scope changes: Phase reset required (cannot be combined)
- Security findings: Block advancement immediately; no exceptions

---

## Questions & Contact

For roadmap questions or timeline concerns:
- Create issue on GitHub: sorenplanck/dom-protocol
- Discord: #mainnet-launch channel
- Email: soren@dom-protocol.org (TBD)

---

**Last Updated:** 2026-05-24  
**Next Review:** After Phase 1 completion (2026-07-18)
