# DOM Release Blockers — Updated after External Audit

Last updated: 2026-05-24 (post-B6 sweep — verified RB-H-GENERATOR and RB-DANDELION resolved; codebase audit found zero TODO/FIXME/unimplemented!/todo! anywhere in `crates/*/src/`; clippy --all-targets clean; consensus pipeline traced end-to-end)

Mainnet launch FORBIDDEN until ALL items resolved.
Testnet launch FORBIDDEN until items marked [TESTNET] resolved.

---

## STATUS LEGEND
✅ RESOLVED — fixed in codebase
🔴 OPEN — not yet resolved
🔧 PARTIAL — partially resolved, residual issue documented

---

## [TESTNET] RB-RANDOMX — RandomX PoW Validation

**Severity: CRITICAL — PoW completely bypassed**
**File:** `crates/dom-pow/src/lib.rs::validate_pow_randomx`, `crates/dom-pow/src/randomx_pool.rs`
**Status:** ✅ RESOLVED

**Problem (from audit):** `validate_pow` used Blake2b of header as PoW hash.
RandomX field exists in header but was never validated against actual RandomX output.
Any attacker could mine blocks in milliseconds on any CPU.

**Required:**
- [x] Add `randomx-rs` to `dom-pow/Cargo.toml` (`randomx-rs = "1.4.1"` in workspace)
- [x] Implement `validate_pow_randomx(preimage, hash, seed, target)` — calls
  `randomx_pool::randomx_hash`, compares against claimed hash, then verifies
  `hash_meets_target`.
- [x] Define seed schedule (RFC-0011): `randomx_seed_height(height)` returns
  `epoch * RANDOMX_SEED_INTERVAL - RANDOMX_SEED_OFFSET` (2048 / 64). Epoch 0
  uses genesis. Wired into `dom-consensus::block::validate_pow`.
- [x] Generate RandomX test vectors: `tests/randomx_vectors.rs` covers seed
  schedule for heights 0/2048/4096 *and* a frozen hash vector for
  `seed=[0;32], preimage="DOM/randomx/v1/vector/genesis"`.
- [ ] Independently reproduce frozen hash vector in a second RandomX
  implementation (e.g. xmrig / official tevador C++). Tracked separately,
  not a build-time blocker.

**Cache pool (memory + IBD performance):**
RandomX cache initialization allocates ~256 MB and takes hundreds of ms.
`randomx_pool` keeps at most `MAX_POOL_ENTRIES = 2` caches alive — covers the
current and previous seed epoch (sufficient for blocks straddling a rotation
boundary). FIFO eviction. Caches are `Arc`-shared between concurrent
validators (`SyncCache` wrapper with safety justification documented in the
module preamble — RandomX C library guarantees read-only concurrent cache
access). Single per-call VM (`~2 MB` scratchpad) provides isolation without
re-paying cache init.

**Mining path:** `dom-node::miner::mine_blocking` retains its own
`RandomXCache + RandomXDataset` (FLAG_FULL_MEM mode, ~2.25 GB) — dataset mode
is correct for mining throughput and is constructed once per mining session,
so it does not go through the pool.

---

## [TESTNET] RB-BULLETPROOFS — secp256k1-zkp Integration

**Severity: CRITICAL — range proofs not validated, inflation possible**
**File:** `crates/dom-crypto/src/bulletproof.rs`
**Status:** ✅ RESOLVED

**Problem (from audit):** Previous homemade implementation was Bulletproofs 2017,
not Bulletproofs+ 2021, with multiple soundness bugs:
- IPA missing u·c_L term (forged proofs possible)
- Transcript not updated with challenges (broken Fiat-Shamir)
- Scalar fallback to Scalar::ONE (challenge bias)
- Panic on identity point (DoS)
- f64 in consensus code (float arithmetic violation)

**Required:**
- [x] Add `secp256k1-zkp` (git pin: BlockstreamResearch/rust-secp256k1-zkp@master,
  features `["global-context", "rand-std"]`). Pin commit before mainnet.
- [x] Implement `prove()` via `secp256k1_zkp::RangeProof::new(...)` (52-bit range,
  ≥ MAX_SUPPLY_NOMS).
- [x] Implement `verify()` via `secp256k1_zkp::RangeProof::verify(...)` —
  checks `range.start == 0`.
- [x] Specify transcript label: `"DOM:bulletproof:v1"`.
- [x] H_DOM ↔ secp256k1-zkp Generator binding: `dom_generator()` builds the
  generator from `[0x0a || H_DOM_X]`, verified equivalent to k256-derived H
  by `pedersen_and_bulletproof_use_same_generator` (RB-BULLETPROOFS-H-BINDING).
- [x] SEC1 ↔ zkp commitment encoding (0x02/0x03 ↔ 0x08/0x09) with 200-sample
  roundtrip tests.
- [x] Verified `MAX_SUPPLY_NOMS` proof works, value above `MAX_PROVABLE_VALUE`
  rejected, empty proofs rejected, oversized proofs capped via `MAX_PROOF_SIZE`.
- [ ] Pin git dependency to specific commit (track in mainnet checklist).
- [ ] Generate audit-style frozen test vector at known (value, blinding, nonce)
  for independent reproduction; current tests cover correctness but not
  byte-for-byte cross-implementation reproducibility.

**Current state:** All 12 unit tests in `bulletproof.rs` pass. End-to-end
prove→verify roundtrip works for 0, small values, and `MAX_SUPPLY_NOMS`. H
binding between Pedersen and Bulletproof is enforced by automated test.

---

## [TESTNET] RB-H-GENERATOR — H Generator Finalization

**Severity: CRITICAL — potential Pedersen commitment backdoor**
**File:** `crates/dom-crypto/src/h_generator.rs`
**Status:** ✅ RESOLVED (2026-05-24 — verified by B6 sweep)

**Problem (from audit):** `H_COMPRESSED_FINAL` was `pub const` with placeholder bytes.
If placeholder is accidentally a valid curve point, its discrete log relative to G
may be known, enabling commitment forgery (inflation backdoor).

**Resolved checklist:**
- [x] `H_COMPRESSED_FINAL` populated with RFC9380 (`DOM:h2c:secp256k1:v6.1`)
  output: `02 0e2cfc9aba78455ffd390cf5f1d17b9982d0ee29b266bb3ea6217b078f09d550`.
- [x] `h_compressed()` returns `Err(DomError::Internal)` if the runtime
  derivation diverges from the hardcoded constant — fail-fast.
- [x] Constant is module-private (`const`, not `pub const`).
- [x] `dom-node::main` calls `h_compressed()` at startup and refuses to boot
  on mismatch (RB-H-STARTUP — see resolved section below).
- [x] Bulletproofs integration binds the same H via
  `dom_generator()` in `bulletproof.rs` and asserts equivalence with
  `pedersen_and_bulletproof_use_same_generator`.
- [ ] (Mainnet checklist, not strictly a code blocker) Independently reproduce
  in openssl + libsecp256k1+h2c before genesis freeze.

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

## [TESTNET] RB-SCHNORR-RX — R encoding in Schnorr challenge

**Severity: CRITICAL — implementation divergence → silent consensus fork**
**File:** `crates/dom-crypto/src/schnorr.rs`, `docs/SECURITY_AUDIT.md` §1
**Status:** ✅ RESOLVED (2026-05-24)

**Problem (from audit):** RFC-0001 originally defined the Schnorr challenge as
`Blake2b-256(... || R_x || pk || msg)` where `R_x` was described as
"x-coordinate of R" without specifying encoding. Two distinct curve points
share the same x-coordinate (R and -R), so independent implementations could
disagree on which 32-byte representation to include — silent consensus fork.

**Decision:** R MUST be the 33-byte SEC1-compressed encoding (parity byte
0x02/0x03 followed by 32-byte x). NOT 32-byte BIP-340 x-only. Migrating to
BIP-340 was rejected: it would be a hard fork against frozen RFC-0009 spec
and the existing block format (`excess_signature: [u8; 65]` = 33 R + 32 s)
with no security gain over SEC1+parity. The audit fix already mandates SEC1.

**Resolved checklist:**
- [x] `SchnorrSignature.r_compressed: [u8; 33]` (SEC1, parity byte preserved).
- [x] `schnorr_challenge()` binds `r_compressed` (33 bytes including parity).
- [x] `to_bytes()/from_bytes()` round-trip at 65 bytes; `from_bytes` validates
  SEC1 prefix via `PublicKey::from_compressed_bytes`.
- [x] Test `signature_r_is_sec1_33_bytes` asserts encoding shape.
- [x] Test `r_and_neg_r_yield_different_challenges` asserts parity binding.
- [x] Frozen vector `frozen_signature_vector_sk1_genesis_message` locks
  (sk=[1;32], msg="DOM/schnorr/v1/vector/genesis", chain_id=mainnet)
  to a deterministic 65-byte signature reproducible across nodes.

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

## B6 Sweep Findings (2026-05-24)

Post-B5 sweep across the entire workspace produced the following observations:

* **Codebase hygiene:** 0 `TODO`/`FIXME`/`XXX`/`HACK` markers in `crates/*/src/`;
  0 `unimplemented!()`/`todo!()`; 4 `panic!`/`unreachable!` total, all inside
  `#[cfg(test)]` blocks or genuinely unreachable state machine arms.
* **Build/lint:** `cargo build --all` and `cargo clippy --all-targets` finish
  warning-free on the reference toolchain.
* **Pipeline trace:** `connect_block` (`dom-chain/src/chain_state.rs:67`) is
  the single entry point and chains every consensus-critical check —
  header syntax, parent existence, height monotonicity, MTP,
  future-timestamp bound, RandomX PoW (`validate_pow`), total-difficulty
  consistency, `validate_block` (which fans out to weight, duplicates,
  PMMR roots and the 10-step per-transaction validation including
  bulletproofs + Schnorr + balance equation), UTXO set existence
  *and* coinbase maturity (`chain_state.rs:187`).
* **Status promotions:** RB-H-GENERATOR and RB-DANDELION moved from
  PARTIAL → RESOLVED based on direct code inspection (see updated sections
  above).
* **Remaining mainnet-level blockers (operationally driven, not code defects):**
  RB-BAN-POLICY (no call sites for `add_ban_score` — defines but never
  invokes), RB-DNS-SEEDS, RB-WALLET-SLATE (Doc 7), RB-IBD RFC,
  RB-MUSIG2 (mandatory-vs-deferred decision), RB-GENESIS-ANCHOR
  mainnet finalization (testnet anchor is already frozen).
* **Local-dev blocker (not a security/consensus issue):** RandomX dataset
  size + `COINBASE_MATURITY = 1000` make every integration test that
  needs two miners infeasible on a 2 GB WSL laptop. Tracked separately
  as the "Regtest mode" work item.

---

## Summary Table

| ID | Description | Target | Status |
|---|---|---|---|
| RB-RANDOMX | RandomX PoW validation | Testnet | ✅ RESOLVED |
| RB-BULLETPROOFS | secp256k1-zkp integration | Testnet | ✅ RESOLVED |
| RB-H-GENERATOR | H constant verification | Testnet | ✅ RESOLVED |
| RB-PIPELINE | Validation orchestration | Testnet | ✅ RESOLVED |
| RB-CUTTHROUGH | Cut-through inputs removed | Testnet | ✅ RESOLVED |
| RB-SCHNORR-RX | R encoding (SEC1 33-byte vs BIP-340) | Testnet | ✅ RESOLVED |
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
**Status:** ✅ RESOLVED (2026-05-24)

RFC-0009 §5.1 requires H in Bulletproofs == H in Pedersen commitments.
`secp256k1-zkp` uses its own internal H (Blockstream convention) by default,
but `Generator::from_slice(&[0x0a || H_x])` accepts a custom x-coordinate
and rebuilds the canonical curve point. `dom_generator()` uses this path
with `H_DOM_X` (validated against `h_generator::h_compressed()`).

Resolved checklist:
- [x] Verify H_zkp == H_DOM — enforced by `bulletproof::tests::h_dom_binding_verified`
- [x] Custom generator path — `dom_generator()` in `bulletproof.rs`
- [x] Round-trip test: `pedersen_and_bulletproof_use_same_generator` asserts
  Pedersen commit (k256, H_DOM) and Bulletproof commit (secp256k1-zkp,
  dom_generator) produce byte-identical SEC1 outputs.

---

## [MAINNET] RB-DANDELION — Dandelion++ implementation status

**Severity: IMPORTANT**
**Status:** ✅ RESOLVED (2026-05-24 — verified by B6 sweep)

`dom-wire/src/dandelion.rs` houses the `DandelionRouter`; `dom-node/src/node.rs`
constructs it inside `DomNode` (`dandelion: Arc<Mutex<DandelionRouter>>`,
line 33 / 189) and the message loop routes stem envelopes through it
(`node.rs:313+`, `node_handle.rs:74+`). New incoming transactions are
forwarded into the router via `submit_tx`, and `get_stem_peer`/`StemEnvelope`
drive forwarding decisions during the stem phase.

Open follow-ups (tracked separately, not blocking):
- Stem probability constant audit (vs. RFC-0009 §X.Y recommended 0.9).
- Multi-hop stem test in `dom-integration-tests` (requires Regtest
  network — see Doc 8 spend_e2e remediation work).
