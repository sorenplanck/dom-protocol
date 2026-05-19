# DOM: A Peer-to-Peer Electronic Cash System

**Soren Planck**
**Version 4 — May 2026**

---

## Abstract

DOM is a peer-to-peer electronic cash system that returns to the original vision of digital money: a medium of exchange, not a store of value. By combining Mimblewimble's transaction model with RandomX proof-of-work, ASERT difficulty adjustment, and Bulletproofs+ range proofs, DOM achieves transactional privacy, ASIC-resistant mining, smooth difficulty retargeting, and constant chain growth through cut-through. There is no premine, no ICO, no reserved supply. The protocol launches with no privileged access. Anyone with a CPU can mine block 0.

---

## 1. Introduction

Bitcoin proposed a solution to the double-spending problem without a trusted intermediary [1]. The system worked as designed. But over time, Bitcoin transformed: from a means of exchange into a store of value. The market spoke. People hold Bitcoin; they do not spend it.

This is not a flaw. A reserve asset is a legitimate role. But it leaves a gap — there is still no widely-used cryptocurrency for everyday transactions. Existing privacy coins have one or more shortcomings: complex addressing models, perpetual chain growth, ASIC capture, contentious governance, or unverifiable supply.

DOM fills this gap. The design is conservative: every component is taken from peer-reviewed cryptographic research or from production cryptocurrencies that have run for years without compromise. DOM is not a research project. It is a synthesis.

The DOM thesis: a currency designed to be spent must be private, must be fast to verify, must be cheap to transact, and must remain accessible to ordinary hardware. DOM optimizes for all four.

---

## 2. Privacy: Mimblewimble

Mimblewimble [2] removes addresses and explicit amounts from the blockchain. Every output is a Pedersen commitment:

```
C = v * H + r * G
```

where `v` is the value, `r` is a random blinding factor, `G` is the secp256k1 generator, and `H` is a second generator with no known discrete logarithm relation to `G` (derived in DOM via RFC9380 hash-to-curve [8]). The blinding factor hides the value; the commitment proves the value is some specific number without revealing which.

A transaction is valid when the conservation equation holds:

```
sum(outputs) - sum(inputs) = sum(kernel_excesses) + offset * G + fee * H
```

This equation can be verified by anyone, in any order, without knowing the values involved. No addresses, no amounts, no balances appear on the chain.

Mimblewimble has two additional properties critical for DOM:

**Cut-through.** When an output created in block 5 is spent in block 100, both can be removed from the chain without invalidating any subsequent state. The remaining commitment math still balances. This means DOM's chain grows at a rate proportional to the *current* UTXO set size, not the historical transaction count. Over time, the chain becomes more efficient, not less.

**No script.** There is no scripting language. No smart contracts. This is a deliberate design choice: scripts are the source of most consensus bugs and most surveillance surface in other cryptocurrencies. DOM does one thing — move money — and does it without ambiguity.

DOM uses range proofs (Bulletproofs+ [3]) to prove that each committed value lies in `[0, 2^52)`. This prevents creation of outputs with negative values, which would otherwise allow silent inflation. The range `2^52 ≈ 4.5 × 10^15` is chosen because it exceeds the total supply of DOM in noms (`~3.3 × 10^15`), while avoiding an overflow bug in the `secp256k1-zkp` library at `2^64`.

---

## 3. Mining: RandomX

Bitcoin's SHA-256 proof-of-work has been dominated by ASICs since 2013. This centralizes mining geographically and economically, and excludes ordinary participants.

DOM uses RandomX [4], the proof-of-work algorithm from Monero. RandomX is designed to perform optimally on general-purpose CPUs and resist ASIC implementation. The algorithm generates a random program for each input and executes it on a virtual machine. This requires:

- Large amounts of cache memory (2 GiB in fast mode, 256 MiB in light mode)
- General-purpose floating-point and integer arithmetic
- Frequent branching and unpredictable memory access patterns

These requirements match what modern CPUs already provide cheaply, and what ASIC vendors cannot replicate without effectively building a general-purpose CPU — at which point they have no economic advantage over commodity hardware.

Mining DOM on a laptop is competitive with mining DOM on a server. There is no "mining industry" by design.

### 3.1 Difficulty: ASERT

DOM uses ASERT (Absolutely Scheduled Exponential Rising Targets) for difficulty adjustment [6]. Unlike Bitcoin's epoch-based retargeting (every 2016 blocks), ASERT adjusts difficulty *every block* based on the deviation between the actual block timestamp and an absolute schedule anchored at the genesis block.

The target for block at height `h` and timestamp `t` is:

```
T(h, t) = T_anchor * 2^((t - t_anchor - TARGET_SPACING * (h - h_anchor)) / HALF_LIFE)
```

where:
- `TARGET_SPACING = 120 seconds` (2 minutes)
- `HALF_LIFE = 172,800 seconds` (2 days)

`HALF_LIFE` is the time it takes difficulty to halve or double in response to sustained hashrate change.

ASERT has three advantages over Bitcoin's algorithm:

- **No retargeting boundaries** to exploit (no two-week manipulation windows)
- **Smooth response** to hashrate changes — no overshoot oscillations
- **Anchor-based math** — difficulty calculation is stateless and does not depend on historical blocks

The ASERT anchor is hardcoded at genesis. Every node computes the same target from the same anchor. No consensus question can arise about difficulty.

---

## 4. Supply

DOM has a fixed total supply of **33,000,000 DOM**, distributed entirely via mining. The schedule:

| Parameter | Value |
|-----------|-------|
| **Initial block reward** | 33 DOM (3,300,000,000 noms) |
| **Halving interval** | 330,000 blocks (~1.25 years at 2-minute blocks) |
| **Halving epochs** | 55 (after epoch 54, reward reaches 0) |
| **Block time** | 2 minutes (120 seconds) |
| **Smallest unit** | 1 nom = 10⁻⁸ DOM |
| **Max supply (noms)** | 3,299,999,976,900,000 |

### 4.1 Reward Schedule

The reward at epoch `n` is derived by integer arithmetic:

```
reward(0) = 33 * COIN_UNIT = 3,300,000,000 noms
reward(n) = (reward(n-1) * 67) / 100
```

This is **not** a strict halving but a 67% retention factor per epoch. The choice produces a smooth supply curve that approaches the cap asymptotically. By epoch 54, the reward reaches 0 noms (integer arithmetic floor).

The total supply is computed deterministically:

```
total = Σ (BLOCK_REWARD_TABLE[epoch] * HALVING_INTERVAL)  for epoch in 0..55
      = 3,299,999,976,900,000 noms
      ≈ 33,000,000 DOM
```

Integer arithmetic ensures bit-exact reproducibility across all architectures. Floating-point math is forbidden in consensus paths.

### 4.2 No Premine

There is no premine. The first DOM ever mined is the block 0 coinbase, and it is mined by whoever runs the protocol first. The smallest unit is 1 nom = 10⁻⁸ DOM, identical in granularity to Bitcoin's satoshi.

### 4.3 Fee Model

Every transaction declares a fee, the fee is added to the coinbase reward of the block that includes it, and the fee appears in the balance equation as `fee * H` on the LHS:

```
sum(outputs) - sum(inputs) + fee * H = sum(kernel_excesses) + offset * G
```

Zero-fee transactions are consensus-valid but relay-policy rejected.

### 4.4 Coinbase Maturity

Coinbase outputs are locked for **1,000 blocks** (~1.4 days at target spacing) before they can be spent. This prevents miners from spending newly-minted coins in transactions that might be invalidated by a reorganization.

---

## 5. Privacy at the Network Layer

Mimblewimble hides values and addresses *on the chain*. But the act of broadcasting a transaction to peers reveals timing information. An adversary running a well-connected node can correlate which IP first announced a transaction, defeating the privacy guarantees of the commitment scheme.

DOM addresses this with Dandelion++ [5]: transactions propagate in two phases.

**Stem phase.** The originating node forwards the transaction to a single randomly chosen peer. That peer forwards it to another single peer. With probability 1-p, the transaction continues stemming; with probability p, it transitions to fluff.

**Fluff phase.** The transaction is gossiped normally to all peers.

After several stem hops, the IP that announces the transaction in fluff phase has no correlation with the IP that originated it. An adversary monitoring the network sees only that some node, somewhere on the stem path, eventually fluffed the transaction.

Dandelion++ does not require user configuration. It is part of the protocol.

> **Implementation status:** Dandelion++ is specified for v1.0 but the message-loop integration is deferred to v1.1. v1.0 uses simple flood relay with random offset for graph privacy.

---

## 6. P2P Transport

All DOM peer connections use the Noise Protocol Framework, specifically the Noise_XX pattern with ChaChaPoly + Blake2b. The handshake:

1. Initiator sends ephemeral key
2. Responder sends ephemeral key, encrypted static key, encrypted handshake confirmation
3. Initiator sends encrypted static key, encrypted handshake confirmation

The result is mutual authentication and a session-keyed encrypted channel. Network observers see only encrypted ciphertext after the first message exchange. The handshake completes in three messages and is subject to a 10-second timeout to prevent Slowloris attacks.

Each node has a persistent Noise static keypair. The public key serves as the node identity for the lifetime of that data directory. There is no association between node identity and any transaction.

### 6.1 Peer Scoring

Peer scoring enforces protocol compliance:

| Behavior | Score |
|----------|-------|
| Malformed message | +20 |
| Wrong chain magic | +100 (immediate ban) |
| Invalid PoW | +50 |
| Address flooding | +30 |
| **Ban threshold** | 100 |

Banned peers are persisted in the local store with an expiration timestamp.

### 6.2 Network Identity

| Network | Magic | P2P Port |
|---------|-------|----------|
| **Mainnet** | `0x444F4D31` ("DOM1") | 33,369 |
| **Testnet** | `0x444F4D54` ("DOMT") | 33,370 |

The chain_id is derived deterministically from `Blake2b(magic || genesis_hash)` and is included in every Schnorr signature challenge, preventing cross-network replay attacks.

---

## 7. Block Structure

A DOM block consists of:

### 7.1 Header (fixed size)

| Field | Type | Size |
|-------|------|------|
| Version | u32 | 4 bytes |
| Height | u64 | 8 bytes |
| Previous block hash | Hash256 | 32 bytes |
| Timestamp | u64 | 8 bytes |
| Output PMMR root | Hash256 | 32 bytes |
| Kernel PMMR root | Hash256 | 32 bytes |
| Range proof PMMR root | Hash256 | 32 bytes |
| Total kernel offset | bytes | 32 bytes |
| Compact target | u32 | 4 bytes |
| Total difficulty | U256 (big-endian) | 32 bytes |
| Nonce | u64 | 8 bytes |
| RandomX hash | Hash256 | 32 bytes |

### 7.2 Body

- **Inputs:** list of 33-byte commitments being spent
- **Outputs:** list of (commitment, range proof) pairs
- **Kernels:** list of (features, fee/explicit_value, lock_height, excess, signature)
- **Coinbase:** exactly one CoinbaseTransaction (output + coinbase kernel)

### 7.3 Consensus Limits

| Limit | Value |
|-------|-------|
| **Max block weight** | 40,000 units |
| **Max TX weight** | 4,000 units |
| **Max inputs/TX** | 255 |
| **Max outputs/TX** | 255 |
| **Max kernels/TX** | 16 |
| **Max TXs/block** | 5,000 |
| **Max proof size** | 6,144 bytes |
| **Max block size** | 16 MiB |
| **Max future timestamp** | 120 seconds |
| **Median-time window** | 11 blocks |

Weight is calculated as: `1 * inputs + 21 * outputs + 3 * kernels`, plus `2` for coinbase kernels.

The body is verified against:

1. The conservation equation (Mimblewimble balance)
2. The range proofs (each output value in [0, 2⁵²))
3. The Schnorr signatures on the kernels (proof of knowledge of the excess private key)
4. The cut-through invariants (no duplicate commitments, no orphaned inputs)
5. The coinbase rules (one and only one coinbase kernel per block; coinbase outputs locked for 1,000 blocks)

---

## 8. Validation Pipeline

A block is accepted when it passes a strict 18-step pipeline (specified in RFC-0007 and RFC-0010):

### 8.1 Header Validation

1. Header syntax (version, structure)
2. PoW (block hash meets compact target via RandomX)
3. Future timestamp bound (`t < now + 120s`)
4. Median time past (strict monotonic over 11-block window)
5. Previous block exists and is in the main chain
6. Height = prev.height + 1
7. Target matches ASERT calculation
8. Total difficulty matches prev + target_to_difficulty(target)

### 8.2 Body Validation

9a. No duplicate commitments within block
9b. All inputs reference existing unspent outputs
9c. No output created and spent in same block (cut-through done before broadcast)
10. All output range proofs verify
11. All kernel signatures verify (Schnorr with chain_id)
12. Block-level balance equation holds (including coinbase)
13. Aggregate offset is canonical (in [0, n-1])
14. Coinbase has exactly one kernel with features=COINBASE
15. Coinbase explicit_value ≤ subsidy(height) + sum(tx_fees)
16. Coinbase output locked for 1,000 blocks
17. PMMR roots match recomputed roots after applying the block
18. Block weight ≤ MAX_BLOCK_WEIGHT (40,000)

### 8.3 Error Classification

| Error | Behavior |
|-------|----------|
| `Invalid` | Consensus-fatal; block rejected, peer scored |
| `Malformed` | Message rejected; peer scored only for ban threshold |
| `TemporarilyInvalid` | Retry allowed (e.g., orphan blocks waiting for parent) |
| `PolicyRejected` | Local relay rejection; no peer penalty |

---

## 9. Cryptographic Choices

DOM's cryptographic primitives are conservative and standard:

| Component | Algorithm | RFC |
|-----------|-----------|-----|
| **Curve** | secp256k1 | Bitcoin reference |
| **Schnorr signatures** | BIP-340 with chain_id binding | RFC-0009 |
| **Hash function (structural)** | Blake2b-256 (tagged) | RFC-0001 |
| **Hash function (PoW seed)** | RandomX preimage | RFC-0005 |
| **MAC** | HMAC-SHA256 (RFC 6979 nonces) | RFC 6979 |
| **AEAD** | ChaCha20-Poly1305 (Noise) | RFC 7539 |
| **Key derivation (wallet)** | Argon2id + HKDF-SHA256 | OWASP |
| **Hash-to-curve** | RFC9380 | RFC 9380 |
| **Range proofs** | Bulletproofs+ (via secp256k1-zkp) | RFC-0002 |

### 9.1 H Generator

The H generator is derived deterministically via RFC9380 [8] hash-to-curve with the domain separation tag `"DOM:h2c:secp256k1:v6.1"`:

```
H_DOM = hash_to_curve(b"", DST="DOM:h2c:secp256k1:v6.1")
H_DOM_COMPRESSED = 020e2cfc9aba78455ffd390cf5f1d17b9982d0ee29b266bb3ea6217b078f09d550
```

The H generator is verified at node startup. A node refuses to start with a placeholder H. This prevents an attack class where a backdoored H with a known discrete log relation to G would enable silent inflation.

### 9.2 Domain Separation

All consensus hashes use tagged hashing with format:

```
Blake2b-256( u16_le(len(tag)) || tag || data )
```

Tags are namespaced (e.g., `DOM:kernel-sig:v1`, `DOM:chain-id:v1`, `DOM:pmmr-leaf:v1`) to prevent cross-context hash collisions.

### 9.3 Multi-Signature (Deferred)

MuSig2 multi-signature aggregation is specified in RFC-0009 but **deferred to v1.1**. v1.0 supports only single-key Schnorr kernels.

---

## 10. What DOM Does Not Have

DOM deliberately omits features common to other cryptocurrencies:

- **No scripting.** No smart contracts. No virtual machine.
- **No tokens.** No NFTs. No issued assets.
- **No staking.** No governance tokens. No on-chain voting.
- **No premine.** No founder reward. No development tax.
- **No DAO.** No foundation. No central legal entity.

This minimalism is not a missing feature list. It is the feature list. Every line of code that does not move money is a line of code that can be exploited.

---

## 11. Implementation Status

DOM is implemented in Rust as a workspace of 16 crates. As of May 2026:

| Component | Status |
|-----------|--------|
| **Consensus validators (V1-V18)** | ✅ Implemented |
| **Cryptographic primitives** | ✅ Implemented (Schnorr, Pedersen, Bulletproofs+, H_DOM) |
| **Serialization (canonical)** | ✅ Implemented |
| **PMMR (Pruned Merkle Mountain Range)** | ✅ Implemented |
| **PoW (RandomX + ASERT)** | ✅ Implemented |
| **Storage (LMDB)** | ✅ Implemented |
| **P2P (Noise XX)** | ✅ Implemented |
| **IBD (Initial Block Download)** | ✅ Phases 1-3 complete |
| **JSON-RPC** | ✅ Implemented |
| **Wallet (encrypted, Argon2id)** | ✅ Implemented |
| **Mining loop** | ✅ Implemented |
| **Dandelion++** | ⏳ Deferred to v1.1 |
| **MuSig2** | ⏳ Deferred to v1.1 |
| **Wallet slate protocol** | ⏳ Deferred to v1.1 |

### 11.1 Test Coverage

```
Total unit tests:       238 passing, 0 failures
Crates with tests:      13 / 16
Clippy warnings:        0
Format compliance:      100%
```

### 11.2 Testnet Burn-In

A private testnet has been running continuously since 2026-05-19:

| Metric | Value |
|--------|-------|
| **Blocks mined** | 156+ |
| **Continuous uptime** | 18h+ |
| **Consensus failures** | 0 |
| **Average block time** | ~7.2 min (testnet easy difficulty) |
| **Critical errors** | 0 |

A public testnet announcement is pending completion of Phase 1 and Phase 2 security audits.

---

## 12. Launch

DOM launches when:

1. Phase 1 audit (consensus + crypto) is complete
2. Phase 2 audit (storage + P2P + PoW) is complete
3. Public testnet has run stable for 3+ months
4. Genesis parameters are finalized
5. Code is published

The genesis coinbase contains the message:

> "Not a store of value. A means of exchange."

No participant — including the protocol author — has any advantage at launch. The first block is mineable by anyone who runs the binary at the moment of launch. The difficulty is set to a value mineable on a single CPU. ASERT adjusts upward as additional hashrate joins.

There is no announcement, no ICO, no airdrop, no premine, no founder allocation. DOM either succeeds as a means of exchange because people choose to use it, or it does not. The protocol does not depend on its author after launch.

**Target launch:** Q3 2026, pending audit completion.

---

## 13. Conclusion

DOM is what Bitcoin was supposed to be — a peer-to-peer electronic cash system used for actual transactions. Every design choice serves this end: privacy by default, mining accessible to ordinary hardware, smooth difficulty adjustment, constant chain size, minimal attack surface, transparent launch.

The technology is proven. Mimblewimble has been live in Grin since 2019. RandomX has been live in Monero since 2019. ASERT has been live in Bitcoin Cash since 2020. Bulletproofs are live in Monero. Noise transport secures WhatsApp and WireGuard. DOM is the careful integration of components that already work.

What is new is the synthesis, the launch model, and the commitment to remain a currency rather than become a security.

---

## References

[1] Nakamoto, S. (2008). *Bitcoin: A Peer-to-Peer Electronic Cash System.*

[2] Jedusor, T. E. (2016). *Mimblewimble.*

[3] Bünz, B., Bootle, J., Boneh, D., Poelstra, A., Wuille, P., Maxwell, G. (2018). *Bulletproofs: Short Proofs for Confidential Transactions and More.* IEEE S&P 2018. With Bulletproofs+ extension by Chung, H., Han, K., Ju, C., Kim, M., Seo, J. H. (2020).

[4] tevador et al. (2019). *RandomX Specification.* Available at github.com/tevador/RandomX.

[5] Fanti, G., Venkatakrishnan, S. B., Bakshi, S., Denby, B., Bhargava, S., Miller, A., Viswanath, P. (2018). *Dandelion++: Lightweight Cryptocurrency Networking with Formal Anonymity Guarantees.* SIGMETRICS 2018.

[6] Faust, S., Sigl, G., et al. (2020). *ASERT Difficulty Adjustment Algorithm.* Bitcoin Cash specification.

[7] Yu, G. (2020). *Mimblewimble Non-Interactive Transaction Scheme.* IACR ePrint 2020/1064.

[8] Faz-Hernandez, A., Scott, S., Sullivan, N., Wahby, R. S., Wood, C. A. (2023). *RFC 9380: Hashing to Elliptic Curves.* IETF.

---

## Appendix A: Whitepaper Changelog

| Version | Date | Changes |
|---------|------|---------|
| v1 | 2026-05 (early) | Initial draft |
| v2 | 2026-05 | Minor revisions |
| v3 | 2026-05 (mid) | Reward = 24 DOM, Halving = 670,725, 30 epochs (placeholder values) |
| **v4** | **2026-05-19** | **Reward = 33 DOM, Halving = 330,000, 55 epochs, Supply = 33M (production values)** |

---

**Document Owner:** Soren Planck
**Contact:** sorenplanck@tutamail.com
**Repository:** github.com/sorenplanck/dom-protocol
**License:** [TBD — Choose MIT, Apache 2.0, or dual]
