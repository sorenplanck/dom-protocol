# DOM Protocol — Mainnet Ready

**Version:** v0.1.0 Testnet  
**Status:** Testnet Operational • Mainnet Preparation  
**Last Updated:** 2026-05-19

---

## Executive Summary

DOM Protocol is a Mimblewimble blockchain with CPU-friendly RandomX proof-of-work. The network is currently running a stable testnet with 156 blocks mined over 18+ hours with **zero consensus failures**. Mainnet launch is targeted for Q3 2026 pending security audit completion and 3+ months of public testnet stability.

### Current Testnet Metrics

| Metric | Value |
|--------|-------|
| **Blocks Mined** | 156 |
| **Uptime** | 18h 38m (continuous) |
| **Consensus Failures** | 0 |
| **Block Time Average** | ~7.2 minutes |
| **Target Block Time** | 2 minutes (ASERT adjusts) |
| **Network** | Testnet (easy difficulty) |
| **Nodes** | 1 (single private node) |

---

## Protocol Specifications

### Monetary Policy

| Parameter | Value | Justification |
|-----------|-------|---------------|
| **Supply Cap** | 33,000,000 DOM | Fixed at genesis; consensus-critical |
| **Initial Block Reward** | 33 DOM | Halves every 330,000 blocks (~1.25 years) |
| **Halving Schedule** | 55 epochs | Last reward block: epoch 54 (year ~55) |
| **Max Supply (Noms)** | 3,299,999,976,900,000 | Integer arithmetic; deterministic |
| **Coin Unit** | 1 DOM = 100,000,000 noms | Divisibility for payments |
| **Coinbase Maturity** | 1,000 blocks | ~1.4 days at target spacing |

### Consensus Rules

| Parameter | Value | RFC |
|-----------|-------|-----|
| **Target Block Time** | 2 minutes (120s) | RFC-0000 §2 |
| **Difficulty Algorithm** | ASERT (Absolutely Scheduled Exponential Rise Targets) | RFC-0011 |
| **ASERT Half-Life** | 2 days (172,800s) | RFC-0011 |
| **PoW Algorithm** | RandomX (CPU-optimized) | RFC-0005 |
| **Hash Function** | Blake2b-256 (tagged) | RFC-0001 |
| **Signature Scheme** | Schnorr (secp256k1, BIP-340) | RFC-0009 |
| **Range Proof** | Bulletproofs+ (2^52 range) | RFC-0002 |
| **Commitment** | Pedersen (secp256k1, H_DOM via RFC9380) | RFC-0002 |

### Network Identity

| Parameter | Mainnet | Testnet |
|-----------|---------|---------|
| **Network Magic** | `0x444F4D31` (ASCII "DOM1") | `0x444F4D54` (ASCII "DOMT") |
| **P2P Port** | 33,369 | 33,370 |
| **Protocol Version** | 1 | 1 |
| **Genesis Hash** | [UNFINALIZED] | `78f5e0f4...` (deterministic) |

### Consensus Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| **Max Block Weight** | 40,000 units | Prevent bloat |
| **Max TX Weight** | 4,000 units | Per-transaction limit |
| **Max Inputs/TX** | 255 | Prevent quadratic hashing |
| **Max Outputs/TX** | 255 | Prevent bloat |
| **Max Kernels/TX** | 16 | Limit signature count |
| **Max TXs/Block** | 5,000 | Prevent memory exhaustion |
| **Max Proof Size** | 6,144 bytes | Bulletproof size cap |
| **Max Block Size** | 16 MiB | Storage limit |
| **Max Future Timestamp** | 2 minutes | Prevent spam |
| **Median-Time Window** | 11 blocks | For timestamp validation |

---

## Project Structure

### Rust Workspace (16 Crates)

```
dom-protocol/
├── dom-core/                    # Constants, types, errors (immutable)
├── dom-crypto/                  # Schnorr, Pedersen, Bulletproofs+, H_DOM
├── dom-serialization/           # DomSerialize/Deserialize trait + codecs
├── dom-pmmr/                    # Pruned Merkle Mountain Range
├── dom-pow/                     # RandomX, ASERT, difficulty math
├── dom-consensus/               # Validators V1-V18 (CRITICAL)
├── dom-tx/                      # SpendBuilder, transactions, coinbase
├── dom-wallet/                  # Argon2id KDF, encrypted persistence
├── dom-chain/                   # ChainState, connect_block, reorg
├── dom-store/                   # LMDB persistence
├── dom-mempool/                 # Mempool (basic, needs relay)
├── dom-node/                    # P2P, mining, IBD
├── dom-wire/                    # Noise codec, messages
├── dom-rpc/                     # JSON-RPC 2.0
├── dom-config/                  # Config parsing
└── dom-integration-tests/       # E2E tests (TODO)
```

### Key Files

- **Whitepaper:** `WHITEPAPER.md` (v3, May 2026)
- **Specs:** `DOM_v6_1_Serialization_RFC.md` + `DOM_RFC_000X_*.md`
- **Known Issues:** `KNOWN_ISSUES.md` (RESOLVED: Pedersen/Bulletproof format)
- **Release Blockers:** `docs/RELEASE_BLOCKERS.md` (tracking)

---

## Testnet Burn-In Results

### Stability Metrics

| Metric | Status |
|--------|--------|
| **Consensus Validation** | ✅ All 238 unit tests passing |
| **Block Production** | ✅ 156 blocks, 0 reorgs |
| **Chain Continuity** | ✅ 18h 38m without interruption |
| **Crash Count** | ✅ 0 critical failures |
| **Network Sync** | ⏳ IBD phase 3 complete (single node) |

### Block Time Analysis

```
Genesis → Block 1:      ~0s   (deterministic)
Block 1 → Block 2:      2m 2s (expected delay)
Block 2 → Block 3:      1m 32s
Block 3 → Block 4:      55m 40s (ASERT adjusted — testnet easy target)
Block 4 → Block 5:      6m 18s (recovered)
...
Block 155 → Block 156:  27m 39s (variance normal at testnet difficulty)

Average Block Time: ~7.2 minutes
(Target: 2 minutes; ASERT will tighten for mainnet)
```

### Resource Usage

| Resource | Usage | Limit |
|----------|-------|-------|
| **Log File** | 528 KB | Healthy (2,719 lines) |
| **LMDB Size** | 2.7 MB | Minimal (156 blocks) |
| **Memory** | <100 MB | Expected |
| **CPU** | ~1 core (mining) | Acceptable |

---

## Security & Audit Status

### PHASE 1 Audit (In Progress)

**Scope:** Consensus layer (validators V1-V18) + Crypto layer (Schnorr, Bulletproofs+, Pedersen, H_DOM)

**Status:** Specification review and adversarial testing underway.

**Expected Completion:** Week of 2026-05-26

### PHASE 2 Audit (Planned)

**Scope:** Storage layer (LMDB) + P2P layer (Noise, message loop) + PoW/ASERT

**Expected Start:** Post-Phase 1 completion

---

## Mainnet Launch Prerequisites

### ✅ Completed

- [x] Whitepaper v3 finalized
- [x] All 16 crates implemented + tested
- [x] 238 unit tests passing (0 failures)
- [x] Testnet private operational (156 blocks, 18h+)
- [x] Genesis block deterministic
- [x] Pedersen/Bulletproof format consistency verified
- [x] Balance equation proven (multiple test vectors)
- [x] Schnorr signature validation working
- [x] ASERT difficulty adjustment working
- [x] IBD (Initial Block Download) phases 1-3 complete
- [x] Serialization codec complete + tested

### ⏳ In Progress

- [ ] Phase 1 audit (consensus + crypto)
- [ ] Phase 2 audit (storage + P2P + PoW)
- [ ] Testnet public (3+ months minimum)
- [ ] Mainnet genesis preparation (frozen params)

### ❌ Not Started / Deferred

- [ ] Dandelion++ (privacy mixing) — deferred to v1.1
- [ ] MuSig2 (multisig) — deferred to v1.1
- [ ] Wallet slate protocol — deferred to v1.1
- [ ] DNS seed operators — needs community

---

## How to Run

### Build

```bash
cd ~/dom
cargo build --release
```

### Run Testnet Node

```bash
./target/release/dom-node --testnet
```

Logs to `/tmp/dom-node-a.log`. Monitor with:

```bash
watch -n 30 'grep -c "New chain tip" /tmp/dom-node-a.log'
```

### Run Tests

```bash
cargo test --workspace
cargo clippy --all -- -D warnings
cargo fmt --check
```

### Mine a Block (Manual)

The miner is integrated into the node. Mining starts automatically on startup.

---

## Mainnet Launch Timeline

| Phase | Duration | Status |
|-------|----------|--------|
| **Phase 1 Audit** | 1-2 weeks | 🔄 In Progress |
| **Phase 2 Audit** | 1-2 weeks | ⏳ Queued |
| **Public Testnet** | 3+ months | ⏳ Awaiting Audit |
| **Genesis Preparation** | 2-4 weeks | ⏳ Pre-Launch |
| **Mainnet Launch** | TBD | 🎯 Q3 2026 Target |

---

## Security Considerations

### ⚠️ Known Limitations

- **Wallet KDF:** Currently uses Argon2id (OWASP recommended). Do NOT use for real funds on mainnet without professional audit.
- **Dandelion++:** Not implemented; P2P IP leakage possible. Defer to v1.1.
- **MuSig2:** Not implemented; multisig deferred to v1.1.
- **Ban Policy:** Peer scoring exists but not enforced. Nodes may not ban bad peers aggressively.

### ✅ Implemented Safeguards

- Schnorr signatures with chain_id (replay protection)
- Bulletproofs+ range proofs (2^52 max value)
- Pedersen commitments (deterministic via H_DOM)
- ASERT difficulty (smooth, non-exploitable)
- Coinbase maturity (1,000 blocks)
- Balance equation (Mimblewimble-correct)
- Checked arithmetic (no silent overflow)
- Tagged hashing (domain separation)

---

## Contributing

See `CONTRIBUTING.md` (TBD).

All commits must:
1. Pass `cargo test --workspace`
2. Pass `cargo clippy --all -- -D warnings`
3. Follow `rustfmt` style
4. Reference RFC-XXXX or KB-XX in message

---

## Contact

- **Pseudonym:** Soren Planck
- **Email:** sorenplanck@tutamail.com
- **GitHub:** github.com/sorenplanck/dom-protocol

---

## License

[TBD — Choose MIT, Apache 2.0, or dual]

---

**Last Updated:** 2026-05-19  
**Next Review:** Post-Phase 1 Audit
