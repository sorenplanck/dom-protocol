# DOM Protocol Mainnet Launch Checklist

**Last Updated:** 2026-05-19  
**Target Launch:** Q3 2026  
**Current Phase:** Testnet Burn-In + Phase 1 Audit

---

## Pre-Launch Phases

### PHASE 0: Security Audit ✅ IN PROGRESS

#### Phase 1: Consensus + Crypto (Week 1-2)

- [ ] **Consensus Validators (V1-V18)**
  - [ ] Validate transaction structure (10 steps per RFC-0007)
  - [ ] Validate block structure (14 steps per RFC-0007)
  - [ ] Balance equation proof (RFC-0008 §1.1)
  - [ ] Coinbase maturity enforcement
  - [ ] Lock height validation
  - [ ] PMMR root verification
  - [ ] Kernel signature verification (Schnorr + chain_id)
  - [ ] Range proof validation (Bulletproofs+)
  - [ ] Duplicate detection (inputs, outputs, kernels)
  - [ ] Weight calculation (per RFC-0010)

- [ ] **Cryptographic Primitives**
  - [ ] Schnorr signatures (secp256k1, BIP-340 compliant)
    - [ ] Deterministic nonce (RFC6979)
    - [ ] Chain_id binding (replay protection)
    - [ ] Signature validity checks
  - [ ] Pedersen commitments (secp256k1)
    - [ ] H_DOM derivation (RFC9380, DST="DOM:h2c:secp256k1:v6.1")
    - [ ] Determinism across architectures
    - [ ] Point validation (on-curve, not infinity)
  - [ ] Bulletproofs+ range proofs
    - [ ] Prove/verify roundtrip
    - [ ] Format conversion (SEC1 ↔ zkp)
    - [ ] Max value enforcement (2^52)
  - [ ] Blake2b-256 tagged hashing
    - [ ] Domain separation (tag length prefix)
    - [ ] Cross-context collision resistance
  - [ ] Random number generation (threat model: no weak RNG)

#### Phase 2: Storage + P2P + PoW (Week 3-4)

- [ ] **Storage Layer (LMDB)**
  - [ ] Atomic block commits (all-or-nothing)
  - [ ] UTXO tracking (commitment → entry)
  - [ ] Height index (height → hash)
  - [ ] Chain tip persistence
  - [ ] Kernel index (excess → block)
  - [ ] Data corruption detection
  - [ ] Map size limits (16 GiB expandable)

- [ ] **P2P Network**
  - [ ] Noise protocol (encrypted + authenticated handshake)
  - [ ] Message framing + deserialization
  - [ ] IBD (Initial Block Download) phases 1-3
  - [ ] Block relay (new blocks broadcast)
  - [ ] Transaction relay (mempool propagation)
  - [ ] Peer discovery (DNS seeds, bootstrap)
  - [ ] Ban scoring (DoS defense)

- [ ] **Proof of Work**
  - [ ] RandomX validation
  - [ ] ASERT difficulty adjustment
  - [ ] Target encoding/decoding
  - [ ] Total difficulty accumulation (U256)
  - [ ] Seed height calculation
  - [ ] Genesis target (0x1e00ffff for mainnet)

---

### PHASE 1: Testnet Public (3+ months)

#### Testnet Infrastructure

- [ ] **Public Testnet Nodes**
  - [ ] Seed node 1 (operator: TBD)
  - [ ] Seed node 2 (operator: TBD)
  - [ ] Seed node 3 (operator: TBD)
  - [ ] Block explorer (optional)
  - [ ] Faucet for test DOM (optional)

#### Testnet Validation

- [ ] **No Consensus Failures**
  - [ ] 0 reorgs > MAX_REORG_DEPTH_POLICY
  - [ ] 0 consensus validator failures
  - [ ] 0 balance equation mismatches
  - [ ] 0 double-spends
  - [ ] 0 signature validation failures

- [ ] **Network Stability**
  - [ ] 99.9% uptime (allow 1 restart per week max)
  - [ ] < 1 second peer discovery latency
  - [ ] < 30 second block propagation
  - [ ] 0 mempool deadlocks

- [ ] **Performance Benchmarks**
  - [ ] Block validation time < 1 second
  - [ ] Transaction validation time < 100ms
  - [ ] Signature verification < 50ms per kernel
  - [ ] Range proof verification < 100ms per output

#### Testnet Duration

- **Minimum:** 3 consecutive months
- **Target:** 6+ months (catch seasonal edge cases)
- **Criteria:** 0 unplanned restarts, 0 consensus failures, stable block time

#### Testnet Data Collection

- [ ] Block time distribution (std dev < 50% of target)
- [ ] Transaction throughput (TX/hour)
- [ ] Network propagation latency (peer-to-peer)
- [ ] Memory usage patterns
- [ ] Disk I/O characteristics
- [ ] CPU utilization under load

---

### PHASE 2: Mainnet Genesis Preparation (2-4 weeks)

#### Immutable Parameters Freeze

- [ ] **Consensus Constants** (dom-core/src/constants.rs)
  - [x] INITIAL_BLOCK_REWARD = 33 DOM
  - [x] HALVING_INTERVAL = 330,000 blocks
  - [x] TARGET_SPACING = 120 seconds
  - [x] MAX_SUPPLY_NOMS = 3,299,999,976,900,000
  - [x] COINBASE_MATURITY = 1,000
  - [x] MAX_FUTURE_BLOCK_TIME = 120s
  - [ ] GENESIS_TIMESTAMP_PLACEHOLDER → actual launch time

- [ ] **Network Parameters**
  - [x] NETWORK_MAGIC_MAINNET = 0x444F4D31
  - [x] P2P_PORT_MAINNET = 33,369
  - [x] PROTOCOL_VERSION = 1
  - [ ] GENESIS_HASH_MAINNET = [computed deterministically]

- [ ] **Cryptographic Parameters**
  - [x] H_DOM_COMPRESSED (RFC9380 derived)
  - [x] ASERT_HALF_LIFE = 172,800 seconds
  - [x] ASERT_RADIX_BITS = 16
  - [ ] All domain tags frozen and documented

#### Genesis Block Construction

- [ ] **Deterministic Coinbase**
  - [ ] Blinding factor derived from TAG_GENESIS_BLINDING
  - [ ] Range proof nonce derived deterministically
  - [ ] Signature reproducible on all nodes
  - [ ] Excess = blinding * G (commitment commitment)

- [ ] **Deterministic Header**
  - [ ] Timestamp = actual launch time (unix seconds)
  - [ ] Prev_hash = [0; 32] (genesis)
  - [ ] Height = 0
  - [ ] PMMR roots computed from coinbase
  - [ ] Target = genesis_anchor().target
  - [ ] Total difficulty = U256::one()

- [ ] **Deterministic Hash**
  - [ ] `genesis_hash = Blake2b("DOM:block-hash:v1", header_bytes)`
  - [ ] Same hash on every node (bitwise identical)
  - [ ] Hardcoded as GENESIS_HASH_MAINNET constant

#### Mainnet Node Deployment

- [ ] **Seed Nodes**
  - [ ] Node 1: IP/DNS, operator contact
  - [ ] Node 2: IP/DNS, operator contact
  - [ ] Node 3: IP/DNS, operator contact

- [ ] **Bootstrap Configuration**
  - [ ] DNS seeds programmed
  - [ ] Hardcoded peers (fallback)
  - [ ] Initial peer list generation

#### Documentation Freeze

- [ ] **Immutable Specs**
  - [ ] Whitepaper v3 final (no further updates)
  - [ ] RFC-0000 through RFC-0011 frozen
  - [ ] Genesis block documented (hash, timestamp, reward)
  - [ ] Network parameters published

- [ ] **Operational Guides**
  - [ ] Node deployment guide
  - [ ] Wallet setup guide
  - [ ] Mining guide (solo + pool)
  - [ ] Troubleshooting guide

---

### PHASE 3: Mainnet Launch (T=0)

#### Pre-Launch Window (T-24 hours)

- [ ] **Final Sanity Checks**
  - [ ] All 238 unit tests passing
  - [ ] All clippy warnings resolved
  - [ ] All fuzzing runs successful (no crashes)
  - [ ] All benchmark targets met
  - [ ] All documentation finalized

- [ ] **Seed Node Startup** (T-12 hours)
  - [ ] Node 1 genesis block loaded
  - [ ] Node 2 genesis block loaded
  - [ ] Node 3 genesis block loaded
  - [ ] P2P connections established
  - [ ] Block propagation verified

- [ ] **Public Announcement**
  - [ ] Genesis hash published
  - [ ] Launch time confirmed
  - [ ] Mainnet endpoints listed
  - [ ] Social media notification

#### Launch Window (T=0)

- [ ] **Mainnet Goes Live**
  - [ ] Seed nodes accepting connections
  - [ ] First blocks mined
  - [ ] Block propagation working
  - [ ] No consensus failures observed

- [ ] **Community Activation**
  - [ ] Wallets can sync
  - [ ] Explorers can index
  - [ ] Exchanges can validate

---

## Risk Mitigation

### Critical Issues (Halt Mainnet If Detected)

**During Testnet:**
- [ ] Consensus validator missing step → no launch
- [ ] Balance equation breakdown → no launch
- [ ] Cryptographic failure (sig/proof invalid) → no launch
- [ ] ASERT difficulty exploit discovered → no launch
- [ ] 2+ reorgs > MAX_REORG_DEPTH → pause & investigate

**During Genesis:**
- [ ] Genesis hash mismatch across nodes → rollback
- [ ] First block fails validation → rollback
- [ ] P2P handshake broken → debug & retry

### Medium Issues (Defer to v1.1)

- [ ] Dandelion++ not implemented (P2P privacy)
- [ ] MuSig2 not implemented (multisig)
- [ ] Wallet slate protocol missing (interactive payments)
- [ ] Ban policy not enforced (peer scoring exists but unenforced)

### Low Issues (Monitor, Document)

- [ ] Block time variance > 50% target (ASERT will adjust)
- [ ] Peer discovery slow on new nodes
- [ ] Memory usage spike during sync
- [ ] Clippy warnings in dependencies

---

## Sign-Off Matrix

### Required Approvals

| Role | Sign-Off Required | Date |
|------|-------------------|------|
| **Lead Dev** (Soren Planck) | Phase 1 Audit Pass | ⏳ |
| **Security Auditor** | Phase 1 + 2 Complete | ⏳ |
| **Community Lead** | Testnet Stable 3+ months | ⏳ |
| **Exchange (Optional)** | Mainnet Ready | ⏳ |

### Launch Criteria (ALL required)

- [x] Whitepaper v3 complete
- [ ] Phase 1 audit complete (consensus + crypto)
- [ ] Phase 2 audit complete (storage + P2P + PoW)
- [ ] 238 unit tests passing, 0 failures
- [ ] Public testnet stable 3+ months
- [ ] Genesis block deterministic + reproducible
- [ ] Mainnet seed nodes ready
- [ ] Documentation complete + frozen

---

## Post-Launch Monitoring

### First 30 Days (Critical Watch)

- [ ] Block time variance tracking
- [ ] Peer count trending
- [ ] Consensus validator failures (0 allowed)
- [ ] Memory/CPU usage patterns
- [ ] Network throughput

### Months 2-3 (Ongoing)

- [ ] Halving countdown (if block 330k approaching)
- [ ] Difficulty adjustment smoothness
- [ ] Wallet bug reports
- [ ] Exchange integration issues

### Year 1 (Maintenance)

- [ ] v1.1 development (Dandelion++, MuSig2, wallet slate)
- [ ] Hardware wallet support
- [ ] Exchange listings
- [ ] Mining pool integration

---

## Appendix: Critical File Versions

| File | Current Version | Locked For Mainnet |
|------|-----------------|-------------------|
| `crates/dom-core/src/constants.rs` | ✅ Final | ✅ Yes |
| `WHITEPAPER.md` | v3 (May 2026) | ⏳ Pending Launch |
| `RFC-0000.md` through `RFC-0011.md` | Final | ⏳ Pending Launch |
| `Cargo.toml` (workspace) | Production deps | ✅ Final |
| `Cargo.lock` | Pinned | ✅ Yes |

---

**Checklist Owner:** Soren Planck  
**Last Review:** 2026-05-19  
**Next Review:** Post-Phase 1 Audit  
**Emergency Contact:** sorenplanck@tutamail.com
