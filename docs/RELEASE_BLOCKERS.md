# DOM Release Blockers — Updated after External Audit

Last updated: 2026-05-12 (post-external-audit revision)

Mainnet launch FORBIDDEN until ALL items resolved.
Testnet launch FORBIDDEN until items marked [TESTNET] resolved.

---

## STATUS LEGEND
✅ RESOLVED — fixed in codebase
🔴 OPEN — not yet resolved
🔧 PARTIAL — partially resolved, residual issue documented

---

## [TESTNET] RB-RANDOMX — RandomX PoW Not Validated

**Severity: CRITICAL — PoW completely bypassed**
**File:** `crates/dom-pow/src/lib.rs::validate_pow_randomx`
**Status:** 🔴 OPEN

**Problem (from audit):** `validate_pow` used Blake2b of header as PoW hash.
RandomX field exists in header but was never validated against actual RandomX output.
Any attacker can mine blocks in milliseconds on any CPU.

**Required:**
- [ ] Add `randomx-rs` to `dom-pow/Cargo.toml` (pin to specific commit)
- [ ] Implement `validate_pow_randomx(preimage, hash, seed, target)`
- [ ] Define seed schedule (RFC-0011): seed = Blake2b of block at H-64, rotated every 2048 blocks
- [ ] Generate RandomX test vectors (at least genesis + heights 2048, 4096)
- [ ] Independently reproduce vectors in two implementations

**Current state:** `validate_pow_randomx()` returns `DomError::Internal` with clear message.

---

## [TESTNET] RB-BULLETPROOFS — secp256k1-zkp Integration

**Severity: CRITICAL — range proofs not validated, inflation possible**
**File:** `crates/dom-crypto/src/bulletproof.rs`
**Status:** 🔧 PARTIAL (homemade code deleted, correct stub present)

**Problem (from audit):** Previous homemade implementation was Bulletproofs 2017,
not Bulletproofs+ 2021, with multiple soundness bugs:
- IPA missing u·c_L term (forged proofs possible)
- Transcript not updated with challenges (broken Fiat-Shamir)
- Scalar fallback to Scalar::ONE (challenge bias)
- Panic on identity point (DoS)
- f64 in consensus code (float arithmetic violation)

**Required:**
- [ ] Add `secp256k1-zkp = { version = "0.11", features = ["bulletproofs", "pedersen", "global-context"] }`
- [ ] Implement `prove()` via `secp256k1_zkp::RangeProof::new(...)`
- [ ] Implement `verify()` via `secp256k1_zkp::RangeProof::verify(...)`
- [ ] Specify transcript label: `"DOM:bulletproof:v1"`
- [ ] Generate and independently reproduce test vectors
- [ ] Audit the secp256k1-zkp version being used

**Current state:** `prove()` and `verify()` return `DomError::Internal` with clear message.
Homemade buggy code has been deleted.

---

## [TESTNET] RB-H-GENERATOR — H Generator Finalization

**Severity: CRITICAL — potential Pedersen commitment backdoor**
**File:** `crates/dom-crypto/src/h_generator.rs`
**Status:** 🔧 PARTIAL (derive_h_generator() implemented, constant needs verification)

**Problem (from audit):** `H_COMPRESSED_FINAL` was `pub const` with placeholder bytes.
If placeholder is accidentally a valid curve point, its discrete log relative to G
may be known, enabling commitment forgery (inflation backdoor).

**Required:**
- [ ] Run `cargo test print_h_generator` on reference hardware
- [ ] Update `H_COMPRESSED_FINAL` with the output
- [ ] Run `cargo test h_final_matches_derivation` — must pass
- [ ] Independently reproduce in k256, openssl, libsecp256k1+h2c
- [ ] Make constant private, expose only via `h_compressed() -> Result<>`
- [ ] Fail-fast on startup if H still placeholder
- [ ] Freeze in genesis manifest (RFC-0006)

---

## [TESTNET] RB-PIPELINE — Validation Pipeline Orchestration

**Severity: CRITICAL — balance equation and signatures never called**
**File:** `crates/dom-consensus/src/lib.rs`
**Status:** ✅ RESOLVED (orchestrated `validate_transaction()` and `validate_block_transactions()` implemented)

**Previous problem:** `connect_block` committed blocks after structural checks only.
Range proofs, Schnorr signatures, and balance equation were never called.

**Current state:** `validate_transaction()` calls all 10 steps in order.
Steps 6 (Bulletproofs) and 7 (Schnorr) propagate `DomError::Internal` as release blockers
rather than silently passing. `validate_transaction_calls_all_steps` test verifies this.

---

## [TESTNET] RB-CUTTHROUGH — Cut-Through Asymmetry Fixed

**Severity: CRITICAL — inputs were not removed, balance equation violable**
**File:** `crates/dom-consensus/src/cutthrough.rs`
**Status:** ✅ RESOLVED

**Previous problem:** `apply_cut_through` removed matching outputs but kept ALL inputs
(`filter returning true`). After cut-through, balance equation would see phantom inputs.

**Current state:** Both inputs AND outputs in the eliminated set are removed.
Test `matched_input_and_output_both_removed` verifies this explicitly.

---

## [TESTNET] RB-SCHNORR-CHAINID — chain_id in Schnorr verify

**Severity: CRITICAL — cross-chain replay possible**
**File:** `crates/dom-crypto/src/schnorr.rs`
**Status:** ✅ RESOLVED

**Previous problem:** `schnorr_verify` did not accept `chain_id`. Only `schnorr_sign`
included chain_id in the nonce — the challenge hash was chain-id-free.

**Current state:** `schnorr_challenge()` now includes `chain_id` in the challenge.
`schnorr_verify()` requires `chain_id` as parameter.
Test `cross_chain_replay_prevented` verifies mainnet sig fails on testnet.
Signature fields are now private — construction requires `from_bytes()`.

---

## [TESTNET] RB-MAX-TARGET — MAX_TARGET_BYTES byte order

**Severity: CRITICAL — zeros were at end (LE) not start (BE)**
**File:** `crates/dom-core/src/constants.rs`
**Status:** ✅ RESOLVED

**Previous problem:** `b[30]=0; b[31]=0` put zeros at end (little-endian style).
Should be `b[0]=0; b[1]=0` (big-endian, most significant bytes).

**Current state:** `b[0]=0x00; b[1]=0x00` — zeros at start.
Test `max_target_bytes_layout` verifies byte layout and consistency with `MAX_TARGET_HI`.

---

## [TESTNET] RB-ASERT-ARITH — ASERT saturating_mul overflow

**Severity: CRITICAL — difficulty corrupted for high targets**
**File:** `crates/dom-pow/src/lib.rs`
**Status:** ✅ RESOLVED

**Previous problem:** `hi.saturating_mul(multiplier)` silently corrupted difficulty
when target near MAX_TARGET. Also `target_to_difficulty` truncated to 128 bits.

**Current state:** `checked_mul` used throughout — overflow returns `DomError::Invalid`.
`target_to_difficulty_u256` returns full (u128, u128) 256-bit result.
Test `asert_no_time_change_returns_same_target` removed fudge factor (was `ratio<=2`).

---

## [TESTNET] RB-SUM-COMMITS — sum_commitments identity point crash

**Severity: CRITICAL — coinbase validation panicked**
**File:** `crates/dom-crypto/src/pedersen.rs`
**Status:** ✅ RESOLVED

**Previous problem:** `sum_commitments([])` returned `Commitment([0u8;33])` which is
not valid SEC1. Caused `verify_balance_equation` to crash for coinbase (no inputs).

**Current state:** `sum_projective()` works entirely in `ProjectivePoint` space.
Balance equation comparison is done in group element space, never encoding identity.

---

## [TESTNET] RB-MAX-SUPPLY — MAX_SUPPLY_NOMS inconsistency

**Severity: IMPORTANT — three different supply numbers in codebase**
**File:** `crates/dom-core/src/constants.rs`
**Status:** ✅ RESOLVED

**Previous problem:** Constant said 33,020,670 DOM, comment said 32,999,670 DOM,
README said 33,000,000 DOM — three different values.

**Current state:** Computed deterministically from halving schedule as const expression.
Test `max_supply_approximately_33m` verifies result is in [32.9M, 33.1M] DOM.

---

## [MAINNET] RB-BAN-POLICY — Peer ban scoring never called

**Severity: CRITICAL — DoS defense is decoration**
**Status:** 🔴 OPEN

`add_ban_score` defined but zero call sites. Malformed messages, invalid PoW,
wrong chain_id — none increment the ban score.

**Required:** Call `add_ban_score` at every message rejection point with scores:
- Malformed message: +20
- Invalid PoW: +50
- Wrong chain_id: +100 (immediate ban)
- Address flooding: +30 + rate limit
- Invalid signature: +25

Persist bans in LMDB with expire timestamp.

---

## [MAINNET] RB-HANDSHAKE-TIMEOUT — Slowloris DoS via no I/O timeout

**Severity: CRITICAL**
**Status:** 🔴 OPEN

`read_framed` has no timeout. 125 attackers each holding a half-open connection
exhaust `MAX_INBOUND_CONNECTIONS`.

**Required:** `tokio::time::timeout(Duration::from_secs(10), read_framed(...))` 
in handshake, `60s` idle timeout in message loop.

---

## [MAINNET] RB-DNS-SEEDS — DNS seeds undefined

**Severity: CRITICAL for bootstrap security**
**Status:** 🔴 OPEN

No domains specified, no governance, no hardcoded fallback IPs.

**Required:** RFC-0011 "Bootstrap Discovery" with ≥5 independent seed operators,
hardcoded fallback IPs, ADDR rate limiting, DNSSEC guidance.

---

## [MAINNET] RB-WALLET-SLATE — Wallet slate protocol not specified

**Severity: IMPORTANT — no interactive payment protocol**
**Status:** 🔴 OPEN

`dom-wallet` is empty. No RFC for slate format, rounds, replay protection, timeout.

**Required:** Decision between Grin-style interactive vs ECDH stealth addresses,
then RFC + implementation.

---

## [MAINNET] RB-IBD — Initial Block Download

**Severity: CRITICAL**
**Status:** 🔧 PARTIAL (ibd.rs skeleton present, RFC missing)

**Required:** RFC with headers-first mandate, minimum work checkpoint, stalling detection,
parallel block download, hardcoded checkpoints.

---

## Summary Table

| ID | Description | Target | Status |
|---|---|---|---|
| RB-RANDOMX | RandomX PoW validation | Testnet | 🔴 OPEN |
| RB-BULLETPROOFS | secp256k1-zkp integration | Testnet | 🔧 PARTIAL |
| RB-H-GENERATOR | H constant verification | Testnet | 🔧 PARTIAL |
| RB-PIPELINE | Validation orchestration | Testnet | ✅ RESOLVED |
| RB-CUTTHROUGH | Cut-through inputs removed | Testnet | ✅ RESOLVED |
| RB-SCHNORR-CHAINID | chain_id in Schnorr verify | Testnet | ✅ RESOLVED |
| RB-MAX-TARGET | MAX_TARGET byte order | Testnet | ✅ RESOLVED |
| RB-ASERT-ARITH | ASERT 256-bit arithmetic | Testnet | 🔧 PARTIAL (U256 correct, tests strict) |
| RB-SUM-COMMITS | Balance eq identity crash | Testnet | ✅ RESOLVED |
| RB-MAX-SUPPLY | Supply constant consistency | Testnet | ✅ RESOLVED |
| RB-BAN-POLICY | Peer ban enforcement | Mainnet | 🔴 OPEN |
| RB-HANDSHAKE-TIMEOUT | Slowloris DoS | Mainnet | 🔴 OPEN |
| RB-DNS-SEEDS | Bootstrap discovery | Mainnet | 🔴 OPEN |
| RB-WALLET-SLATE | Wallet slate protocol | Mainnet | 🔴 OPEN |
| RB-IBD | Initial block download | Mainnet | 🔧 PARTIAL |

---

## [TESTNET] RB-COINBASE-SIG — Coinbase Schnorr Signature Validation

**Severity: CRITICAL (introduced in v5, fixed in v6)**
**File:** `crates/dom-consensus/src/transaction.rs`
**Status:** ✅ RESOLVED

**Problem:** `CoinbaseTransaction::validate` did not verify the Schnorr signature
on the coinbase kernel. Any observer could copy a coinbase excess+signature and
claim another miner's block reward without knowing the blinding factor.

**Current state:** `validate_coinbase_signature(chain_id)` called in `validate()`.
chain_id is bound via `schnorr_challenge()` (not double-bound in kernel_message).

---

## [TESTNET] RB-KERNEL-MALLEABLE — lock_height Malleability

**Severity: IMPORTANT (v4 finding, fixed in v6)**  
**File:** `crates/dom-consensus/src/transaction.rs`
**Status:** ✅ RESOLVED

Non-HEIGHT_LOCKED kernels with `lock_height != 0` are now rejected as `Invalid`.

---

## [TESTNET] RB-OFFSET-CANONICAL — total_kernel_offset Scalar Validation

**Severity: IMPORTANT (v4 finding, fixed in v6)**
**File:** `crates/dom-consensus/src/block.rs`
**Status:** ✅ RESOLVED

`validate_header_syntax` now rejects `total_kernel_offset >= n` as `Malformed`.
---

## [TESTNET] RB-FEE-SIGN — Balance Equation Fee Sign (present since v4, fixed in v7)

**Severity: CRITICAL**
**File:** `crates/dom-crypto/src/pedersen.rs`, `docs/DOM_RFC_0008_Balance_Coinbase_Fee_Offset.md`
**Status:** ✅ RESOLVED

**Problem (audit v6→v7):** `verify_balance_equation` had `rhs += fee*H` (positive sign).
This is mathematically impossible for any valid transaction — it implies outputs exceed
inputs by fee amount (inflation). The test `balance_equation_simple_transaction` also
had wrong r_excess convention (r_in - r_out instead of r_out - r_in).

**Root cause:** RFC-0008 §1.1 was written with wrong sign. Implementation faithfully
followed the wrong spec.

**Fix:** Moved `fee*H` to LHS:
  `lhs = sum(outputs) - sum(inputs) + fee*H`
  `rhs = sum(kernel_excesses) + offset*G`

Consistent with Grin, MWTP paper (eprint 2020/1064 §2.1).
Test corrected to use Grin r_excess convention.
Three tests now verify: with fee, without fee, with offset.
RFC-0008 §1.1, §1.2, and §3.4 updated.

---

## [TESTNET] RB-H-STARTUP — H Placeholder DoS via Node Startup

**Severity: CRITICAL**
**File:** `crates/dom-node/src/main.rs`
**Status:** ✅ RESOLVED

**Problem (audit v6):** `main.rs` only logged error if H was placeholder,
then continued. First transaction would call `h_point()` → `.expect()` → panic → crash.
Attacker with network access could DoS any node not using finalized H.

**Fix:** `main.rs` now returns `Err(anyhow)` on startup if `h_compressed()` fails.
Node refuses to start until H is finalized. Fail-fast, not fail-crash.


---

## [TESTNET] RB-HANDSHAKE-TIMEOUT — Reclassified from Mainnet to Testnet

**Status:** ✅ RESOLVED in v8

`perform_handshake_initiator` and `_responder` now wrapped in
`tokio::time::timeout(10s)`. `codec.recv()` has 60s idle timeout.
`PolicyRejected` error on timeout (no ban score — not a malicious peer,
just a slow one).

---

## [TESTNET] RB-MUSIG2 — MuSig2 implementation missing

**Severity: IMPORTANT**
**Status:** 🔴 OPEN

RFC-0009 §3 specifies MuSig2 (2-round, HKDF-SHA256 nonce, session tracking).
No implementation exists. No crate for MuSig2 is referenced in any Cargo.toml.

**Decision needed:** Is MuSig2 mandatory for v1.0 or deferred to v1.1?

- If mandatory: add `secp256k1-zkp` feature `musig` to RB-BULLETPROOFS checklist
- If deferred: document that v1.0 kernels are single-signer Schnorr only

Until decided, single-signer Schnorr (dom-crypto/schnorr.rs) is the only
available kernel signing path.

---

## [TESTNET] RB-GENESIS-ANCHOR — ASERT anchor not tracked

**Severity: IMPORTANT**
**Status:** 🔴 OPEN

ASERT requires a static genesis anchor (height=0, timestamp, target).
These values depend on RFC-0006 (genesis artifact, also OPEN).

Without the finalized anchor, all nodes compute different ASERT difficulty
from block 1 onward — testnet diverges immediately.

Required: finalize genesis timestamp + target → freeze in RFC-0003 anchor.

---

## [MAINNET] RB-BULLETPROOFS-H-BINDING — H generator in secp256k1-zkp

**Severity: IMPORTANT**
**Status:** 🔴 OPEN (must be checked during RB-BULLETPROOFS integration)

RFC-0009 §5.1 requires H in Bulletproofs == H in Pedersen commitments.
`secp256k1-zkp` uses its own internal H (Blockstream convention).

Before completing RB-BULLETPROOFS:
- [ ] Verify H_zkp == H_DOM (compare 33-byte compressed points)
- [ ] If different: find secp256k1-zkp API for custom H generator
- [ ] Add test vector: prove(v, r, H_DOM) → verify with H_DOM

---

## [MAINNET] RB-DANDELION — Dandelion++ implementation status

**Severity: IMPORTANT**
**Status:** 🔧 PARTIAL (code present, not integrated into message loop)

`dom-wire/src/dandelion.rs` has DandelionRouter implementation.
Without Dandelion++, transaction origin is trivially deanonymized by timing.

Required:
- Integrate DandelionRouter into dom-node message loop
- Verify stem probability = 0.9 (RFC-0009 recommends, not hardcoded yet)
- Add test: transaction stemmed through N hops before fluff
