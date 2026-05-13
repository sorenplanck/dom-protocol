# DOM: A Peer-to-Peer Electronic Cash System

**Soren Planck**
**May 2026**

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

where `v` is the value, `r` is a random blinding factor, `G` is the secp256k1 generator, and `H` is a second generator with no known discrete logarithm relation to `G` (derived in DOM via RFC9380 hash-to-curve). The blinding factor hides the value; the commitment proves the value is some specific number without revealing which.

A transaction is valid when the sum of input commitments equals the sum of output commitments plus the fee:

```
sum(outputs) - sum(inputs) + fee * H = sum(kernel_excesses) + offset * G
```

This conservation equation can be verified by anyone, in any order, without knowing the values involved. No addresses, no amounts, no balances appear on the chain.

Mimblewimble has two additional properties critical for DOM:

**Cut-through.** When an output created in block 5 is spent in block 100, both can be removed from the chain without invalidating any subsequent state. The remaining commitment math still balances. This means DOM's chain grows at a rate proportional to the *current* UTXO set size, not the historical transaction count. Over time, the chain becomes more efficient, not less.

**No script.** There is no scripting language. No smart contracts. This is a deliberate design choice: scripts are the source of most consensus bugs and most surveillance surface in other cryptocurrencies. DOM does one thing — move money — and does it without ambiguity.

DOM uses range proofs (Bulletproofs+ [3]) to prove that each committed value lies in `[0, 2^52)`. This prevents creation of outputs with negative values, which would otherwise allow silent inflation. The range `2^52` is chosen because it exceeds the total supply of DOM in noms, while avoiding an overflow bug in the `secp256k1-zkp` library at `2^64`.

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

DOM uses ASERT (Absolutely Scheduled Exponential Rising Targets) for difficulty adjustment. Unlike Bitcoin's epoch-based retargeting (every 2016 blocks), ASERT adjusts difficulty *every block* based on the deviation between the actual block timestamp and an absolute schedule anchored at the genesis block.

The target for block at height `h` and timestamp `t` is:

```
T(h, t) = T_anchor * 2^((t - t_anchor - TARGET_SPACING * (h - h_anchor)) / HALF_LIFE)
```

where `HALF_LIFE = 172,800 seconds` (2 days) is the time it takes difficulty to halve or double in response to sustained hashrate change.

ASERT has three advantages over Bitcoin's algorithm:
- **No retargeting boundaries** to exploit (no two-week manipulation windows)
- **Smooth response** to hashrate changes — no overshoot oscillations
- **Anchor-based math** — difficulty calculation is stateless and does not depend on historical blocks

The ASERT anchor is hardcoded at genesis. Every node computes the same target from the same anchor. No consensus question can arise about difficulty.

---

## 4. Supply

DOM has a fixed total supply approaching 32,194,800 DOM, distributed via mining. The schedule:

- **Initial block reward:** 24 DOM (2.4 billion noms)
- **Halving interval:** 670,725 blocks (approximately 2.55 years at 2-minute blocks)
- **Halvings:** 30 epochs, after which the reward is effectively zero
- **Block time:** 2 minutes target

The reward function is `reward(epoch) = 24 DOM >> epoch`. Summed over all epochs, the total supply is:

```
total = 670725 * 24 * (1 + 1/2 + 1/4 + ...) ≈ 32,194,800 DOM
```

There is no premine. The first DOM ever mined is the block 0 coinbase, and it is mined by whoever runs the protocol first. The smallest unit is 1 nom = 10^-8 DOM, identical in granularity to Bitcoin's satoshi.

The fee model is direct: every transaction declares a fee, the fee is added to the coinbase reward of the block that includes it, and the fee appears in the balance equation as `fee * H` on the input side. Zero-fee transactions are consensus-valid but relay-policy rejected.

---

## 5. Privacy at the Network Layer

Mimblewimble hides values and addresses *on the chain*. But the act of broadcasting a transaction to peers reveals timing information. An adversary running a well-connected node can correlate which IP first announced a transaction, defeating the privacy guarantees of the commitment scheme.

DOM addresses this with Dandelion++ [5]: transactions propagate in two phases.

**Stem phase.** The originating node forwards the transaction to a single randomly chosen peer. That peer forwards it to another single peer. With probability 1-p, the transaction continues stemming; with probability p, it transitions to fluff.

**Fluff phase.** The transaction is gossiped normally to all peers.

After several stem hops, the IP that announces the transaction in fluff phase has no correlation with the IP that originated it. An adversary monitoring the network sees only that some node, somewhere on the stem path, eventually fluffed the transaction.

Dandelion++ does not require user configuration. It is part of the protocol.

---

## 6. P2P Transport

All DOM peer connections use the Noise Protocol Framework, specifically the Noise_XX pattern with ChaChaPoly + Blake2b. The handshake:

1. Initiator sends ephemeral key
2. Responder sends ephemeral key, encrypted static key, encrypted handshake confirmation
3. Initiator sends encrypted static key, encrypted handshake confirmation

The result is mutual authentication and a session-keyed encrypted channel. Network observers see only encrypted ciphertext after the first message exchange. The handshake completes in three messages and is subject to a 10-second timeout to prevent Slowloris attacks.

Each node has a persistent Noise static keypair. The public key serves as the node identity for the lifetime of that data directory. There is no association between node identity and any transaction.

Peer scoring enforces protocol compliance:
- Malformed message: +20 score
- Wrong chain magic: +100 score (immediate ban)
- Invalid PoW: +50 score
- Address flooding: +30 score
- Ban threshold: 100

Banned peers are persisted in the local store with an expiration timestamp.

---

## 7. Block Structure

A DOM block consists of:

**Header (fixed size):**
- Version (u32)
- Height (u64)
- Previous block hash (32 bytes)
- Timestamp (u64)
- Output PMMR root (32 bytes)
- Kernel PMMR root (32 bytes)
- Range proof PMMR root (32 bytes)
- Total kernel offset (32 bytes — canonical secp256k1 scalar)
- Compact target (u32)
- Total difficulty (U256, 32 bytes big-endian)
- Proof of work: nonce (u64) + RandomX hash (32 bytes)

**Body:**
- Inputs: list of 33-byte commitments being spent
- Outputs: list of (commitment, range proof) pairs
- Kernels: list of (features, fee/explicit_value, lock_height, excess, signature)

The body is verified against:
1. The conservation equation (Mimblewimble balance)
2. The range proofs (each output value in [0, 2^52))
3. The Schnorr signatures on the kernels (proof of knowledge of the excess private key)
4. The cut-through invariants (no duplicate commitments, no orphaned inputs)
5. The coinbase rules (one and only one coinbase kernel per block; coinbase outputs locked for COINBASE_MATURITY blocks)

---

## 8. Validation Pipeline

A block is accepted when it passes a strict 18-step pipeline (specified in RFC-0010):

1. Header syntax
2. PoW (block hash meets compact target)
3. Future timestamp bound (`t < now + 120s`)
4. Median time past (strict monotonic)
5. Previous block exists and is in the main chain
6. Height = prev.height + 1
7. Target matches ASERT calculation
8. Total difficulty matches prev + target_to_difficulty(target)
9a. No duplicate commitments within block
9b. All inputs reference existing unspent outputs
9c. No output created and spent in same block (cut-through done before broadcast)
10. All output range proofs verify
11. All kernel signatures verify
12. Block-level balance equation holds (including coinbase)
13. Aggregate offset is canonical
14. Coinbase has exactly one kernel with features=COINBASE
15. Coinbase explicit_value ≤ subsidy(height) + sum(tx_fees)
16. Coinbase output locked for COINBASE_MATURITY blocks
17. PMMR roots match recomputed roots after applying the block
18. Block weight ≤ MAX_BLOCK_WEIGHT

Any failure rejects the block as `Invalid` (consensus-fatal). A `Malformed` error rejects the message but does not penalize the peer beyond the ban score. `TemporarilyInvalid` errors allow retry (e.g., orphan blocks waiting for parent).

---

## 9. Cryptographic Choices

DOM's cryptographic primitives are conservative and standard:

- **Curve:** secp256k1 (the Bitcoin curve)
- **Schnorr signatures:** as in BIP-340, with chain_id included in the challenge to prevent cross-network replay
- **MuSig2:** for multi-signature kernels (specified, implementation deferred to v1.1)
- **Hash function:** Blake2b-256 for structural hashing; SHA-256 for genesis hash and Bitcoin compatibility
- **MAC:** HMAC-SHA256 for RFC 6979 deterministic nonces
- **AEAD:** ChaCha20-Poly1305 for Noise transport
- **Key derivation:** HKDF-SHA256
- **Hash-to-curve:** RFC9380 for the H generator (`H = 020e2cfc9aba78455ffd390cf5f1d17b9982d0ee29b266bb3ea6217b078f09d550`)
- **Range proofs:** Bulletproofs+ via `secp256k1-zkp`

The H generator is derived deterministically and verified at node startup. A node refuses to start with a placeholder H. This prevents an attack class where a backdoored H with a known discrete log relation to G would enable silent inflation.

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

## 11. Launch

DOM launches when the protocol implementation is feature-complete, the genesis timestamp is finalized, and the code is published.

The genesis coinbase contains the message:

> "Not a store of value. A means of exchange."

No participant — including the protocol author — has any advantage at launch. The first block is mineable by anyone who runs the binary at the moment of launch. The difficulty is set to a value mineable on a single CPU. ASERT adjusts upward as additional hashrate joins.

There is no announcement, no ICO, no airdrop, no premine, no founder allocation. DOM either succeeds as a means of exchange because people choose to use it, or it does not. The protocol does not depend on its author after launch.

---

## 12. Conclusion

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
