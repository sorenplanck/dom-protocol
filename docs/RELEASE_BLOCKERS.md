# DOM Release Blockers — Updated after External Audit

Last reconciled against code: 2026-07-01 (previous reconciliation 2026-06-10 — see
`docs/RECONCILIATION_REPORT.md`). The 2026-07-01 pass re-verified every OPEN/PARTIAL
entry against the real source with `file:line` evidence; the items updated below:
RB-BAN-POLICY (residual shrunk — Addr handler + per-class scores landed),
RB-GENESIS-ANCHOR (testnet anchor frozen — resolved for testnet),
RB-BULLETPROOFS (git pin checkbox — the pin exists and is deny.toml-enforced),
RB-TESTNET-DEPLOY / RB-FUZZ-CAMPAIGN (superseded by ROADMAP_v3 Phase 9 — the
launch model no longer includes a public testnet).

> **Authoritative gate note (2026-07-01):** the mainnet gating criteria live in
> `docs/ROADMAP_v3.md` Phase 9 (adopted 2026-06-19). Entries in this file that
> predate v3 are kept as the historical record; where they conflict with
> ROADMAP_v3, ROADMAP_v3 wins.

Last updated: 2026-05-24 (post-B7 — `Network::Regtest` added; unblocks local two-miner integration tests including Doc 8 spend_e2e. Magic byte / port / maturity / RandomX-flags isolated; consensus logic unchanged. See `docs/REGTEST.md`.)

**B7 follow-up (2026-05-24):** two consensus bugs surfaced by spend_e2e re-enablement and were fixed:
* `65c6a2d` — `REGTEST_TRIVIAL_TARGET_DO_NOT_USE_IN_PRODUCTION` was `[0xff; 32]`, strictly greater than `MAX_TARGET_BYTES`, so every Regtest block was rejected by `validate_target_bounds`. Set equal to `MAX_TARGET_BYTES` (the weakest accepted target). Zero changes to validators.
* `a0dfbd2` — `create_genesis_block` was overwriting `chain.genesis_hash` with the computed hash, while `chain_id_for()` (miner) and `Wallet::create` keep using the constant `GENESIS_HASH_REGTEST = [0; 32]`. Result: `ValidationContext.chain_id` diverged from what the wallet/miner signed coinbase kernels with, so every block past genesis failed with "coinbase kernel signature invalid". Dropped the overwrite; all sites now consistently bind chain_id to the constant until pre-launch genesis-hash finalisation.

**Local-dev tests env-blocked on WSL2 (B7 follow-up):** multi-node and mining-heavy integration tests (`spend_e2e`, `two_node`, `three_node`, `ibd`, `reorg`, `late_join`, `wallet_flow`, `mempool_relay`) are marked `#[ignore = "env-blocked-wsl"]` and carry the `ENV-BLOCKED-WSL-2026-05-24` header. Reason: Regtest target `0000ffff…ff` requires ~2^16 RandomX hashes per block; on WSL2's cache-only single-thread VM the rate is too low to finish two-block prologues inside test deadlines (observed range: 10–40+ min per run, non-deterministic). The tests are *not* protocol bugs — bugs surfaced were fixed above. Tracking: re-run on a VPS or dedicated machine with ≥8 GB RAM dedicated before mainnet; any non-env failure there is a real bug. Single-node mining-free tests (`replay_determinism`, `chain_persistence`) remain enabled.

Mainnet launch FORBIDDEN until ALL items resolved.
Testnet launch FORBIDDEN until items marked [TESTNET] resolved.

---

## CI Release-Blocker Gates

The CI workflow on pull requests and pushes to `main` has an explicit
`release-blocker-gate` job. The gate does not run tests itself; it fails unless
all release-blocker jobs finish successfully:

- `fmt`
- `build-test`
- `release-blocker-crate-tests`
- `release-blocker-integration-tests`

The release-blocker jobs are mandatory. They do not use `continue-on-error`.
Any failure in these jobs fails the release gate.

Critical groups covered by the gate:

| Critical group | CI job / command coverage | Why it blocks release |
| --- | --- | --- |
| Consensus validation | `release-blocker-crate-tests`: `cargo test -p dom-consensus`, `cargo test -p dom-chain`, `cargo test -p dom-node`; `build-test`: `cargo test --workspace --exclude dom-integration-tests --all-targets` | Consensus validation failures can admit invalid blocks, reject valid blocks, or fork nodes. |
| UTXO reopen integrity | `release-blocker-crate-tests`: `cargo test -p dom-chain`, including `crates/dom-chain/tests/corruption_detection.rs` reopen/corruption tests | Reopen must rebuild the exact canonical UTXO/kernel-index state after restart or repair; divergence is a consensus and funds-safety blocker. |
| Orphan/reordered delivery | `release-blocker-crate-tests`: `cargo test -p dom-node`, including `crates/dom-node/tests/multinode_reordered_delivery.rs` | Nodes must converge under out-of-order, duplicate, delayed-parent, and reconnect delivery timelines. |
| Future-block restart equivalence | `release-blocker-crate-tests`: `cargo test -p dom-node`, including `future_block_queue` restart/drop-policy tests | Runtime-only future-block state must converge after restart through deterministic redelivery rather than persisted local timing. |
| IBD/reorg multi-node | `release-blocker-integration-tests`: `cargo test -p dom-integration-tests -- --test-threads=1` and `cargo test -p dom-integration-tests -- --ignored --test-threads=1` with `DOM_REGTEST_FAST_MINING=1` | Multi-node IBD and reorg convergence protect network catch-up and canonical-chain agreement. |
| Runtime shutdown | `release-blocker-crate-tests`: `cargo test -p dom-node`, including shutdown and task-supervisor tests | Shutdown must cancel runtime work, drain persistence safely, and allow clean restart without detached tasks or partial state. |

Integration tests that are marked `#[ignore]` for local environment limits are
not skipped by the release gate. The integration release-blocker job runs them
explicitly with `--ignored` and sets `DOM_REGTEST_FAST_MINING=1` plus
`DOM_NETWORK=regtest`. This uses the project test configuration for viable
Regtest mining in CI instead of omitting mining-heavy IBD/reorg tests or
weakening their assertions.

---

## STATUS LEGEND
✅ RESOLVED — fixed in codebase
🔴 OPEN — not yet resolved
🔧 PARTIAL — partially resolved, residual issue documented
🟠 OPEN (OPERATIONAL) — code mechanism present; what remains is operational data /
governance, not engineering

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

> **STATUS UPDATE (bp-migration, commit e07af6f):** The integration described
> below (Blockstream `secp256k1-zkp` / `RangeProof`) was the borromean-era path.
> It has since been superseded: the consensus range-proof system is now standard
> Bulletproofs via grin `secp256k1zkp` (audited FFI shim, custom H_DOM generator),
> 675-byte proofs, consensus `MAX_PROOF_SIZE = 768`. The H_DOM binding and SEC1↔zkp
> encoding requirements below still hold and are preserved as the historical record.

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
- [x] Pin git dependency to specific commit — DONE (re-verified 2026-07-01):
  `Cargo.toml:51` pins `secp256k1-zkp` to rev `264e84adf7b06fb4d028eb2fd992f33c4d8999b7`;
  `grin_secp256k1zkp = "=0.7.15"` is an exact crates.io pin (`Cargo.toml:54`);
  enforced structurally by `deny.toml` (`required-git-spec = "rev"`, line 62;
  `unknown-git = "deny"`, line 59) and gated in CI (`ci.yml:138` supply-chain job).
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

## [TESTNET] RB-ASERT-ARITH — ASERT 256-bit arithmetic

**Severity: CRITICAL — difficulty corrupted for high targets**
**File:** `crates/dom-pow/src/lib.rs`
**Status:** ✅ RESOLVED

**Previous problem:** `hi.saturating_mul(multiplier)` silently corrupted difficulty
when target near MAX_TARGET. Also `target_to_difficulty` truncated to 128 bits.

**Current state:** the internal multiply reconstructs
`floor((hi * 2^128 + lo) * m / 65536)` without dropping the carry from the
low limb into the high limb. `checked_mul`/full-width arithmetic is used
throughout, `target_to_difficulty_u256` returns the full `(u128, u128)` 256-bit
result, and strict regression coverage includes the historical carry vector plus
an independent U512 reference sweep.

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

## [MAINNET] RB-BAN-POLICY — Peer ban scoring

**Severity: CRITICAL — DoS defense**
**Status:** 🔧 PARTIAL (reconciled 2026-06-10)

**Correction:** the original "`add_ban_score` defined but zero call sites" is FALSE.
Scoring IS wired and enforced:
- `record_peer_violation` / `record_pending_peer_violation` are called at ~14
  rejection points in `crates/dom-node/src/node.rs` (handshake/hello timeout,
  malformed frame, second Hello, GetHeaders/GetBlockData parse errors, block/tx
  validation errors, etc.); mapping in `peer_violation_score`
  (`node.rs:1712-1731`).
- Enforcement: `PeerInfo::add_ban_score` (`crates/dom-wire/src/peer.rs:84-92`) sets
  `PeerState::Banned` at `BAN_THRESHOLD=100` and the node drops the connection.
- Persistence: `persist_peer_reputation_state` + `PEER_REPUTATION_METADATA_KEY`
  store reputation in LMDB and reload on restart.
- Applied as specced: `Malformed → +20`, `WRONG_CHAIN_ID → +100`.

**Residual (re-verified 2026-07-01 — two of the three prior residuals are CLOSED):**
- ~~Score granularity~~ **mostly closed:** `INVALID_POW(50)` and
  `INVALID_SIGNATURE(25)` are now mapped (`node.rs:1914-1921` via
  `PeerMisbehavior::InvalidPow`/`InvalidSignature`). Remaining sliver:
  `INVALID_TX_STRUCTURE(15)` is a dead constant (`peer.rs:19`, zero references) —
  invalid tx structure still falls into the catch-all `Invalid(_) →
  PROTOCOL_VIOLATION(10)` (`node.rs:1922`, pinned by test `node.rs:5895-5898`).
- ~~Address flooding~~ **CLOSED:** `Command::Addr` has a real handler in the live
  message loop (`node.rs:4444-4482`) with flood rate limiting
  (`MAX_ADDR_MESSAGES_PER_WINDOW=4`, `pex.rs:234-239`) and `ADDRESS_FLOODING(+30)`
  scoring on overflow (`node.rs:4457-4467`). GetAddr responses are also
  serve-side rate-limited (`node.rs:4416-4442`).
- **No decay/expiry for a registered peer — still OPEN.** Pre-registration
  penalties expire (`PENDING_PENALTY_TTL_SECS=15min`,
  `crates/dom-wire/src/manager.rs:19`), but a registered peer's `ban_score` is a
  monotonic `saturating_add` with no timestamp (`peer.rs:84-92`). Note: a
  `PeerScorer` with time-based ban expiry exists (`dom-node/src/peer_scoring.rs:45-97`)
  but is dead code — zero call sites outside its own unit tests.

**Required to close:** map (or delete) `INVALID_TX_STRUCTURE`; add ban
decay/expire for registered peers (or wire the existing `peer_scoring` module).

---

## RB-HANDSHAKE-TIMEOUT — Slowloris DoS via no I/O timeout

**Severity: CRITICAL**
**Status:** ✅ RESOLVED (reconciled 2026-06-10)

This previously-duplicated `[MAINNET] 🔴 OPEN` entry was obsolete and contradicted
the resolved entry below. The code confirms the fix: `HANDSHAKE_TIMEOUT_SECS=10`
(`crates/dom-wire/src/handshake.rs:20`) wraps both `perform_handshake_initiator`
and `_responder` in `tokio::time::timeout` (`:116-121`, `:163-168`), and
`NoiseCodec::recv` enforces `IDLE_TIMEOUT_SECS=60` per frame
(`crates/dom-wire/src/codec.rs:125-135`). Timeout returns `PolicyRejected`
(non-bannable — a slow peer is not a malicious one). See the canonical resolved
section "[TESTNET] RB-HANDSHAKE-TIMEOUT — Reclassified from Mainnet to Testnet"
below.

---

## [MAINNET] RB-DNS-SEEDS — Bootstrap discovery

**Severity: CRITICAL for bootstrap security**
**Status:** 🟠 OPEN (OPERATIONAL) (reconciled 2026-06-10)

**Correction:** the resolution *mechanism* exists and is wired into bootstrap:
- `crates/dom-wire/src/dns_seed.rs` — `resolve_seeds(mainnet, port, custom_seeds)`
  resolves via the system resolver, accepts custom seeds, and falls back to
  hardcoded IPs. `MAINNET_DNS_SEEDS` lists 5 domains, `TESTNET_DNS_SEEDS` 2.
- `NodeConfig` has the fields (`crates/dom-config/src/lib.rs:88,98,100`):
  `dns_seeds`, `disable_dns_seeds`, `seed_peers`; mainnet default lists 2 domains
  (`:159-162`).
- Wired at startup: `resolve_configured_dns_seeds` (`node.rs:2302`) is called on
  boot (`:1048`) and extended with `seed_peers` (`:1051`).

**Residual (genuinely open — operational/governance, not code):**
- The `seed*.dom-protocol.org` domains are placeholders — not yet operated /
  published in DNS by independent operators.
- `MAINNET_SEED_IPS` is empty (`dns_seed.rs` literal comment "To be filled after
  genesis") — no hardcoded fallback IPs.
- Governance (≥5 independent operators) and DNSSEC guidance are not decided.
- ADDR rate limiting is absent (shares the gap with RB-BAN-POLICY residual).

This is the only one of the five `[MAINNET]` blockers that genuinely blocks a
public network today — but as a **launch/operational** task, not engineering.

**Required:** stand up real seeds (DNS or IPs) and populate the lists; formal
RFC-0011 "Bootstrap Discovery" (≥5 operators, fallback IPs, ADDR rate limiting,
DNSSEC guidance).

---

## [MAINNET] RB-WALLET-SLATE — Wallet slate protocol

**Severity: IMPORTANT — interactive payment protocol**
**Status:** 🔧 PARTIAL (reconciled 2026-06-10)

**Correction:** "`dom-wallet` is empty" is FALSE, and the design decision was
already made and implemented:
- The model is **interactive Mimblewimble (Grin-style)** — decided in code (round
  partial-signature flow; no ECDH/stealth addresses).
- Slate type: `crates/dom-tx/src/slate.rs:41` (`version, chain_id, amount, fee,
  lock_height`, sender/recipient inputs/outputs, `*_public_excess`,
  `*_public_nonce`, `*_partial_sig`).
- 3-step flow implemented: `create_send_slate` (`crates/dom-wallet/src/wallet.rs:1163`)
  → `receive_slate` (`:1292`) → `finalize_slate` (`:1395`), aggregating via
  `schnorr_partial_sign` / `schnorr_aggregate_sigs` / `schnorr_add_public_keys`.
- Replay protection: `chain_id` bound in the Schnorr challenge.
- Tested e2e + adversarial:
  `finalize_slate_end_to_end_builds_valid_aggregate_transaction` (`wallet.rs:2695`),
  cross-chain / non-owned / amount-fee / output / partial-sig tamper rejection
  (`:2756`, `:2820`, …).

**Residual:**
- Formal RFC for the slate (document) is missing — only code doc-comments exist.
- No slate timeout/expiry — reserved inputs are released only via manual
  `cancel_tx`.
- Transport / async exchange UX (file/QR/endpoint between sender and recipient) is
  out of the slate's own scope; the finished tx relays through the normal tx path.

**Required to close:** write the slate RFC; add slate timeout/expiry; (optionally)
a transport/UX layer.

---

## [MAINNET] RB-IBD — Initial Block Download

**Severity: CRITICAL**
**Status:** 🔧 PARTIAL (reconciled 2026-06-10)

**Correction:** "skeleton present" understates it — `crates/dom-chain/src/ibd.rs`
is a real implementation (~867 lines): `IbdPhase`/`IbdInterruption`/`IbdControl`,
a resumable, LMDB-persisted `PersistedIbdState` (`save/load/clear`,
`from_persisted`), headers-first `process_headers` (`:433`), stalling/timeout
handling (`note_round_progress`/`note_empty_response`, `MAX_IBD_RETRY_ATTEMPTS=3`),
and batched block download via `MAX_GETBLOCKDATA_HASHES` in `dom-node`. Tested by
`ibd_adversarial.rs` (invalid/out-of-order/flood/memory-growth),
`ibd_persistence.rs` (resume), and `ibd_two_node.rs` (2-node, env-gated by RandomX).

**Residual:**
- Formal IBD RFC (document) is missing — this is the doc's actual gap.
- No hardcoded checkpoints / minimum-work checkpoint (grep for `CHECKPOINT` in
  `dom-core`/`dom-config`/`ibd.rs` is empty; `checkpoint_tip_hash`, `ibd.rs:93`, is
  a per-session resume anchor, not a global trust checkpoint).
- Parallel multi-peer block download not verified (current path is sequential
  batches).

**Required to close:** write the IBD RFC; add hardcoded checkpoints / minimum-work
checkpoint; (optionally) parallel multi-peer download.

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
  *[Superseded 2026-06-10: the "no call sites for `add_ban_score`" observation is
  no longer accurate — scoring is wired, enforced and persisted. RB-BAN-POLICY,
  RB-WALLET-SLATE and RB-IBD were re-classified after code reconciliation; see
  their sections above and `docs/RECONCILIATION_REPORT.md`.]*
* **Local-dev blocker (not a security/consensus issue):** B7 added
  `Network::Regtest` with `REGTEST_COINBASE_MATURITY = 1` and the
  cache-only RandomX VM (~256 MB instead of ~2 GB), which removed the
  dataset and maturity barriers. The remaining gap is hash-rate: WSL2's
  shared CPU produces too few hashes/second against the `2^-16` Regtest
  target to finish multi-block integration scenarios inside test
  deadlines. Multi-node tests carry an `ENV-BLOCKED-WSL-2026-05-24`
  marker plus `#[ignore]` and will be re-enabled on the first VPS or
  dedicated-CPU run (see header note above).

---

## [MAINNET] RB-WALLET2-RPC-SOURCE — Wallet v2 chain scan transport

**Severity: IMPORTANT — wallet v2 cannot sync against a live node without it**
**Status:** ✅ RESOLVED (status re-verified against the code 2026-07-01; the
entry below was stale — every "required to close" item is implemented and
tested)

Wallet v2 (`dom-wallet2`) reconciles its store from `ScanBlock`s via the
`ChainSource` trait + `sync` driver (`crates/dom-wallet2/src/transport.rs`).
All three closure items shipped:

- **Node endpoint** — `GET /chain/scan?from&to` routed in
  `crates/dom-rpc/src/lib.rs` (`chain_scan_handler`), served by
  `NodeHandleImpl::scan_chain` (`crates/dom-node/src/node_handle.rs`), which
  wraps the shared per-block extractor `scan_block_at`
  (`crates/dom-node/src/wallet_scan.rs`) so the RPC and the embedded rescan
  can never diverge. Range clamped to `MAX_SCAN_RANGE` and the tip; response
  carries `{tip:{height,hash}, from, to, blocks:[{height, hash,
  output_commitments, input_commitments, fees}]}`. A busy chain answers a
  retriable `503` via `try_lock` — the scan never waits on the chain lock
  (pinned by `scan_chain_yields_to_busy_chain_lock`).
- **`RpcChainSource: ChainSource + TxSink`** —
  `crates/dom-wallet2/src/rpc_source.rs`: paging across the node's range cap,
  `503` retry with backoff, `Unsupported` detection, `scan_for_restore`
  carrying per-block fees, `POST /tx/submit`. Tested against a mock HTTP
  server (paging, busy retry, restore fees, submit outcomes).
- **Incremental sync (the optional item)** — `StoreMeta.last_reconciled_tip` /
  `last_reconciled_hash` exist (`crates/dom-wallet2/src/types.rs`,
  `wallet_state.rs`) and the `sync` driver's `from` parameter consumes them.

The desktop wallet already runs on this path in production:
`wallet-desktop/src-tauri/src/wallet_manager.rs` drives reconciliation and
submission through `RpcChainSource` against the embedded node's public RPC.

Verified 2026-07-01: `cargo test -p dom-wallet2 -p dom-rpc` (187 tests) and
`cargo test -p dom-node scan_chain` all green.

---

## [MAINNET] RB-WALLET2-RECEIVE-RESTORE — Wallet v2 receive-request restore-from-seed

**Severity: IMPORTANT — affects seed-only recovery completeness**
**Status:** 🔴 OPEN

Wallet v2 restore-from-seed (`crates/dom-wallet2/src/keychain.rs`,
`restore_coinbase_from_seed`) recovers the **coinbase** outputs (seed-derivable
by height, value public = `reward + fees`). **Receive-requests are not restored**
yet.

The blocker is the **amount**: matching a receive-request output requires
`Commitment::commit(amount, derived_blinding)`, but the amount is neither
on-chain (hidden in the Pedersen commitment) nor derivable from the seed. The
blinding is seed-derivable (by index); the amount is not. So receive-request
restore needs an **amount source** — in practice the store backup (`wallet.dombak`,
§2.7), the same 2nd recovery layer that already covers the fully non-derivable
change / receive-slate outputs.

This is the inherent derivable/non-derivable boundary of the v2 design, exposed
rather than hidden: the seed alone is a partial recovery; the encrypted store
backup is the complete one.

**Required to close:**
- Decide the amount source for receive-requests (store backup is the natural
  one) and implement matching against it, OR
- Persist created receive-requests (amount + index) so a from-store restore can
  reconstruct them; document that seed-only restore cannot.

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
| RB-ASERT-ARITH | ASERT 256-bit arithmetic | Testnet | ✅ RESOLVED |
| RB-SUM-COMMITS | Balance eq identity crash | Testnet | ✅ RESOLVED |
| RB-MAX-SUPPLY | Supply constant consistency | Testnet | ✅ RESOLVED |
| RB-BAN-POLICY | Peer ban enforcement | Mainnet | 🔧 PARTIAL (wired+persisted; ADDR handler + PoW/sig scores landed 2026-07-01; residual: INVALID_TX_STRUCTURE dead constant, ban decay) |
| RB-HANDSHAKE-TIMEOUT | Slowloris DoS | Mainnet | ✅ RESOLVED (10s handshake + 60s idle) |
| RB-DNS-SEEDS | Bootstrap discovery | Mainnet | 🟠 OPEN (OPERATIONAL) (mechanism done; real seeds + governance pending) |
| RB-WALLET-SLATE | Wallet slate protocol | Mainnet | 🔧 PARTIAL (interactive slate implemented+tested; residual: RFC, timeout) |
| RB-IBD | Initial block download | Mainnet | 🔧 PARTIAL (implemented+tested; residual: RFC, hardcoded checkpoints) |
| RB-WALLET2-RPC-SOURCE | Wallet v2 chain scan transport (node RPC endpoint + RpcChainSource) | Mainnet | ✅ RESOLVED (endpoint + RpcChainSource + incremental sync shipped and tested; desktop runs on it) |
| RB-WALLET2-RECEIVE-RESTORE | Wallet v2 restore-from-seed of receive-requests (needs an amount source) | Mainnet | 🔴 OPEN (coinbase restore done; receive-request restore deferred) |
| RB-GENESIS-ANCHOR | ASERT genesis anchor | Testnet | ✅ RESOLVED for testnet (frozen + pinned by `genesis_testnet_frozen_vectors`); mainnet anchor deferred by design to the ceremony |
| RB-TESTNET-DEPLOY | Public adversarial testnet | Mainnet | ⚪ SUPERSEDED by ROADMAP_v3 (no public testnet; private burn-in + shield audit instead) |
| RB-FUZZ-CAMPAIGN | Sustained fuzz campaign | Mainnet | 🔴 OPEN as ROADMAP_v3 Phase 9.2 (~44-58 targets exist; sustained execution + log pending) |

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
**Status:** ✅ RESOLVED (deferred to v1.1)

MuSig2 is **not** a v1.0 release requirement. The shipping v1.0 kernel signing
path is single-signer Schnorr only, and the product docs already reflect that:

- `WHITEPAPER.md`: "MuSig2 multi-signature aggregation is deferred to v1.1"
- `docs/MAINNET_LAUNCH.md`: MuSig2 tracked under v1.1 development

Resolution: keep v1.0 single-signer only, do **not** treat MuSig2 absence as a
release blocker, and keep any future MuSig2 work gated to the v1.1 roadmap.

---

## [TESTNET] RB-GENESIS-ANCHOR — ASERT anchor not tracked

**Severity: IMPORTANT**
**Status:** ✅ RESOLVED for testnet (re-verified against code 2026-07-01);
mainnet anchor deferred by design to the genesis ceremony (fail-closed).

ASERT requires a static genesis anchor (height=0, timestamp, target).

**Current state (2026-07-01):**
- `GENESIS_TIMESTAMP_TESTNET = 1_778_642_633` frozen (`constants.rs:63`, asserted
  at `constants.rs:651`); `GENESIS_HASH_TESTNET` is a real non-zero frozen value
  (`constants.rs:435-438`).
- `genesis_anchor()` derives the `AsertAnchor` deterministically from the frozen
  genesis timestamp + the network's `genesis_target()`
  (`crates/dom-pow/src/lib.rs:673-681`).
- The whole testnet genesis (hash, PMMR roots, 739-byte bp2 coinbase proof, and
  the anchor) is pinned by the regression test `genesis_testnet_frozen_vectors`
  (`crates/dom-node/src/miner.rs:1450`).
- Mainnet: intentionally NOT frozen — `MAINNET_GENESIS_FINALIZED = false`
  (`constants.rs:448`) fail-closes the node until the launch ceremony freezes the
  real values. That is the ceremony's deliverable, not a code gap.

---

## [MAINNET] RB-BULLETPROOFS-H-BINDING — H generator in secp256k1-zkp

**Severity: IMPORTANT**
**Status:** ✅ RESOLVED (2026-05-24)

> **STATUS UPDATE (bp-migration, commit e07af6f):** The H_DOM binding requirement
> below carried forward unchanged into the migration. The range-proof backend is
> now grin `secp256k1zkp` (via the audited FFI shim) rather than the Blockstream
> `secp256k1-zkp` referenced here, but `dom_generator()` still rebuilds the custom
> H_DOM generator and `pedersen_and_bulletproof_use_same_generator` still asserts
> byte-identical SEC1 commitments. Preserved as the historical record.

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

---

## [MAINNET] RB-PMMR-001 — PMMR silent leaf mutation (Phases A–E)

**Severity:** CRITICAL — chainstate forgery primitive.
**Status:** ✅ RESOLVED in algorithm; deferred validation items tracked below.

Two collaborating defects in `Pmmr::push` collapsed `root()` for any
multi-leaf MMR to a single peak hash that ignored the inner leaves
(`node_height` used `trailing_ones` instead of Grin's postorder height;
`leaf_pos` was the *post*-insert node count, placing fresh leaves into
parent slots). Combined: any block producer could rewrite historical
UTXO / kernel sets without disturbing the committed PMMR roots.

Fix: Grin-derived postorder height with `jump_left` until `is_all_ones`;
`leaf_pos = nodes_before(n) + 1`; `set_node` overwrite guard; shared
`compute_block_pmmr_roots` helper between miner and validator. Pinned
RFC-0004 hex vectors enforced via `vectors_match_pinned_hex`.

Resolved commits:
- `bcd59ad` fix(pmmr): Phase B — Grin-postorder index arithmetic.
- `91f78ed` test(pmmr): Phase D — adversarial validation suite.
- `151acbe` fix(node): Phase C — miner packs mempool + shared PMMR helper.
- `2994048` test(test-vectors): Phase E — recapture RFC-0004 PMMR roots.
- RFC-0004 normative spec authored (Phase G).

### Deferred Phase F validation gaps (tracking, not closed)

| Gap | Reason for deferral | Tracked under |
|---|---|---|
| Cross-platform deterministic roots (Linux / Windows / macOS / ARM64) | No CI matrix yet — single-VPS environment. | Phase 1.4 |
| Interrupted-flush PMMR-specific harness (kill mid `commit_block`, reopen, equivalence) | Phase 3.2 covers store-level partial persistence; a PMMR-level equivalent over `output_root` / `kernel_root` / `rangeproof_root` is not yet wired. | Phase 3.2 extension |
| `replay_determinism` re-execution on the corrected algorithm | RandomX FULL_MEM dataset init ≈ 150 s per block on the current VPS — 3-block test budget exceeds practical session timeouts. **Empirical measurements:** `chain_persistence` (1-block mine + restart) passed in 158.75 s with tip hash `a987f084bbd3f31a07a2831fa04e146a82030a9423abd26d9470745dc5201bbb`. `replay_determinism::replay_same_chain_reopens_to_identical_tip` (2-block mine) **timed out at 900 s** on this VPS — sustained mining beyond one block is not feasible in-session. 3-block `replay_to_two_chains_yields_identical_tip` is correspondingly deferred. Re-execution requires a dedicated mining host with FULL_MEM RandomX throughput ≥ 1 block / 60 s. | Phase 6.1 |

Until those gaps are closed, the Phase F status is "partially validated
empirically — full closure requires the listed infrastructure".

---

## [MAINNET] RB-LMDB-MAPSIZE — dynamic map_size growth

**Severity:** IMPORTANT — operational fail-stop, not a consensus bug.
**Status:** 🔴 OPEN — intentionally deferred from Phase 3.3.

`DomStore::open` pre-allocates a 16 GiB LMDB map. At the current block
budget (~1 MB per block, ~120 s spacing) this provides ≥5 years of
headroom; running out is a "next decade" issue. When a commit
nevertheless hits `MDB_MAP_FULL`, `commit_block` returns a
`DomError::Internal` carrying the `LMDB_MAP_FULL_SENTINEL` substring so
the chain-init layer can recognise the condition distinctly.

What is NOT yet implemented:

* Automatic map_size extension while the node is running. Doing this
  safely requires a quiescent point with no in-flight read txns and
  proper lock coordination across the async multi-reader pool.
* Operator runbook for offline extension. The procedure (stop node,
  call `mdb_env_set_mapsize` from a small helper, restart) is mechanically
  sound but undocumented; will be added alongside Phase 6
  rebuild-from-genesis runbooks.

These gaps are not blocking for mainnet candidate status: the sentinel
fail-stop guarantees we cannot silently lose blocks past the map limit.
Tracking exists so the deferral does not get forgotten.

---

## [MAINNET] RB-PMMR-001-RFC — RFC-0004 normative PMMR spec

**Severity:** CRITICAL — was the absence of a written spec for the
exact PMMR layout the protocol runs.
**Status:** ✅ RESOLVED (commit `ed0492d`).

Full normative specification authored at
`docs/DOM_RFC_0004_PMMR_Hardening.md`. Pins position arithmetic, the
four hashing tags, the right-to-left bagging fold, the append
algorithm plus overwrite invariant, the block-level iteration order,
the nine canonical hex test vectors, the DOM-PMMR-001 bug history, and
the explicit list of deferred validation gaps (cross-platform,
interrupted-flush, full replay_determinism re-execution on the
corrected algorithm).

---

## [MAINNET] RB-FS-MATRIX — filesystem adversarial coverage

**Severity:** IMPORTANT — durability under non-default mount options.
**Status:** 🟡 PARTIAL — tmpfs + ext4 covered in CI; btrfs / xfs / zfs deferred.

`dom-store/tests/crash_consistency_sigkill.rs` and `lmdb_durability.rs`
exercise the post-Phase-3.3 fsync-by-default LMDB commit path. On the
Phase 1.4 CI matrix:

* **tmpfs** — GitHub-hosted runners back `/tmp` (and therefore
  `tempfile::TempDir`) on tmpfs. tmpfs ignores fsync (data lives in
  memory until eviction), so these legs validate the consistency
  contract on the LMDB side without proving the kernel-to-disk path.
* **ext4** — the default `/` filesystem on `ubuntu-latest` and
  `ubuntu-22.04-arm` is ext4 with the standard `data=ordered`
  journal. Tests that explicitly mount or write to `/var` go through
  ext4 with full journaling.
* **APFS** (macos-*) and **NTFS** (windows-*) — provided by the
  hosted runners; not enumerated explicitly but exercised
  transitively by `cargo test`.

What is NOT yet exercised in CI:

* **btrfs / xfs / zfs**, each with at least one non-default mount
  option (`commit=N`, `nobarrier`, `sync=disabled`, etc.). The
  failure shape we care about is: an LMDB commit returns Ok, the
  power goes out, the filesystem replays its journal and the LMDB
  meta page comes back at an earlier state than the data pages.
  Reproducing this on a GitHub-hosted runner requires
  loop-mounting an image with the target FS, killing power via
  `qemu` or `dmsetup` snapshots, and remounting — substantially
  more infrastructure than `tempfile::TempDir`.

Mitigation tracking: this gap does not block mainnet candidate
status; the Phase 3.3 fsync change already eliminates the most
likely loss mode (kernel never persisted the dirty page). Filesystem
journal replay anomalies are tail risk that the bug-bounty / public
testnet phases (8.1, 8.4) are positioned to surface in the wild
before mainnet launch.

---

## [MAINNET] RB-EVICTION-POLICY — slot monopolisation defence

**Severity:** IMPORTANT — eclipse-attack residual risk.
**Status:** 🔴 OPEN — Phase 4.2 follow-up, not in scope this session.

`PeerManager` enforces inbound `MAX_PEERS_SAME_SLASH_16 = 2` plus
the `max_inbound` cap. Once those slots are full there is no
eviction; the first peers to connect hold the slots indefinitely.
An attacker who is fast enough to connect before legitimate peers
can monopolise the inbound surface despite passing the subnet
check.

The 7 tests in `dom-wire/tests/eclipse_resistance.rs` pin the
defensive surface that does exist (subnet flood cap, inbound cap,
disconnect-frees-slot bookkeeping, IPv4+IPv6 coverage). They are
the floor; an eviction policy is the next ceiling.

Documented mitigation paths for the follow-up:

* Bitcoin Core "feeler + eviction" model: when full, evict the
  oldest non-active peer if a new outbound discovery has higher
  score.
* Random eviction (Sybil-resistant): on each new inbound that
  passes subnet check, evict a random existing inbound (probability
  inversely proportional to score).
* Per-peer score weighted by service-time and behaviour signal
  (good block relay, valid headers).

A full implementation requires per-peer scoring and a controlled
disconnect path through the async event loop. Not blocking for
mainnet candidate (the existing defences eliminate the most
obvious attack shape — single-subnet flood), tracked here so the
limitation does not get forgotten.

---

## [MAINNET] RB-PEX-SUBNET — subnet diversity in PEX known set

**Severity:** LOW — PEX is discovery only; connection-level subnet
cap (`MAX_PEERS_SAME_SLASH_16 = 2`) already gates the actual peers
that get connected.
**Status:** 🔴 OPEN — Phase 4.4 follow-up.

`PexManager` enforces a `max_peers` cap on the known-address set
but does NOT enforce subnet diversity inside that set. An attacker
controlling 10_000 IPs across a single /16 could fill the known
set with their addresses (subject to the `max_peers` cap). The
attack does NOT translate into actual connections — the
`PeerManager`'s inbound /16 cap rejects them at handshake time —
but it wastes outbound-dialer attempts against attacker-controlled
endpoints.

Mitigation path (low priority):

* When `add_peer` would push the known set over a per-/16
  threshold, evict the lowest-scoring same-/16 entry instead of
  rejecting the new one.
* Track /16 distribution as a metric so operators can detect a
  Sybil PEX flood in progress.

Tracked under `dom-node/tests/sybil_resistance.rs` documentation.
The 10 sybil_resistance tests pin everything else: flood bound,
malformed filtering, dedupe, cooldown, failure tracking, addr
payload caps.

---

## [MAINNET] RB-TESTNET-DEPLOY — Phase 8.1 public adversarial testnet

**Severity:** CRITICAL gate — mainnet launch is blocked on this.
**Status:** ⚪ SUPERSEDED by ROADMAP_v3 (adopted 2026-06-19; recorded here
2026-07-01). The v3 launch model has **no public testnet** (philosophical
choice — no insiders): validation happens before block zero via the
dom-shield audit (Phase 9.1/9.3), the sustained fuzz campaign (9.2), and a
**private burn-in** run by the maintainer (9.4). See `docs/ROADMAP_v3.md`
Phase 9. The section below is preserved as the v2-era historical record.

Phase 8.1 calls for a public adversarial testnet running ≥ 90 days
continuous without consensus break. The protocol source is
testnet-ready (Phase 1.3-7.3 + the Bloco 5 adversarial-resilience
suites all green), but no actual testnet is currently deployed.

Required to close:

* Deploy ≥ 5 seed nodes in geographically diverse datacentres.
* Publish testnet seed addresses in
  `dom-wire/src/dns_seed.rs::TESTNET_SEEDS` (already templated).
* Operate continuously for 90 d. Any consensus break, unrecoverable
  state, or peer eclipse during the window resets the clock.
* Coordinate the bug-bounty rewards (Phase 8.4 policy already
  authored) in testnet-equivalent fiat units.
* Run the ceremony rehearsal (per Phase 8.5 final paragraph) at
  testnet launch.

Tracking note: testnet failure modes that surface protocol bugs
are the most valuable feedback the project can get pre-launch.
The 90-day window is a hard minimum; longer is better.

---

## [MAINNET] RB-FUZZ-CAMPAIGN — Phase 8.2 ≥ 10 000 CPU-hour fuzz

**Severity:** CRITICAL gate — mainnet launch is blocked on this.
**Status:** 🔴 OPEN — carried forward into ROADMAP_v3 as Phase 9.2 (the
sustained fuzz campaign remains a mainnet gate under v3; this entry stays
open, tracked there). Progress since this entry was written (re-verified
2026-07-01): the harness inventory grew from 13 to **~44-58 cargo-fuzz
targets across 16+ crates** (`crates/*/fuzz/fuzz_targets/`), including
`fuzz_bp2_verify.rs` (ROADMAP_v3 Phase 8.1's first target). What is still
missing is the sustained execution itself: only a ~25 s/target smoke run is
recorded (`docs/FUZZING.md`, 2026-05-23) — no hour-scale campaign log yet.

Phase 8.2 calls for ≥ 10 000 CPU-hours of fuzz coverage across:

* `cargo fuzz` harnesses for: serialization round-trip, PMMR push,
  range-proof verification, Schnorr verify, Pedersen commit/verify,
  block decode + validate, wire-message decode, ASERT next_target,
  IBD header processing, mempool accept_tx, chain corruption
  detection.
* Property-based proptest sweeps run with `--ignore-tests=false`
  for 10 000+ iterations per property (replay determinism,
  adversarial suite, eclipse-resistance, sybil-resistance,
  mempool-adversarial, ASERT-adversarial, IBD-adversarial,
  bulletproof-adversarial, infinity-rejection, differential-crypto).
* Long-running differential fuzz: DOM ↔ Grin on the secp256k1-zkp
  surface, DOM ↔ libsecp256k1 on the point-arithmetic surface.

The 10 000-CPU-hour figure is a calibration anchor — the goal is
not the wall-clock hours but the empirical demonstration that the
existing test surfaces have been exercised at scale without
finding new failures.

Required to close:

* Provision a fuzz-cluster (cloud / dedicated farm).
* Author / dust off `cargo fuzz` harnesses for each surface above.
  Some already exist in pre-session work; the inventory is in
  `docs/FUZZING.md` (which will be updated as harnesses are
  added / refreshed).
* Archive the per-corpus crash inputs (if any) into
  `tests/fuzz/corpus/` under git LFS so the regressions are
  reproducible.
* Publish the campaign log: total CPU-hours, harnesses run,
  inputs processed, crashes / non-crash bugs found and fixed,
  remaining open. The log becomes `docs/FUZZ_CAMPAIGN.md` at
  mainnet handover.

Tracking note: per the Phase 8.5 ceremony checklist, the fuzz
campaign MUST be complete and archived before the ceremony
runs.
