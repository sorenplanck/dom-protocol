# DOM Protocol — FABLE5 Security Audit (pre-testnet)

**Date:** 2026-06-30
**Auditor:** Fable 5 (defensive robustness/hardening review, pre-testnet)
**Branch:** `audit/fix-9-open-items` — `git HEAD = 0776c56`, working tree clean at start.
**Mode:** read-only across all production code (`crates/**/src/**`, `Cargo.toml`,
deploy/scripts). Writes authorized only in `crates/**/tests/` (NEW files) and in this
report. No `src/` file was touched. No `git add/commit/push`.

> **Relation to the prior pass (2026-06-10, `main` HEAD `edc4b54`):** this is a
> re-audit against the CURRENT branch code, which already incorporates the dom-shield
> program (FIX-005…FIX-044) and the "9 open items". The still-valid conclusions from
> that pass (FABLE5-001 mempool admission ordering — **resolved**; FABLE5-002
> side-chain quarantine — **bounded/intentional**) were re-verified in the code and
> remain valid (§6). The NEW findings in this pass are **FABLE5-003 through -006**.

> **STATUS UPDATE (2026-07-01, verified by execution):** all four findings below were
> fixed on this branch AFTER this report was written, by the auditoria2 fix wave:
>
> | Finding | Fix commit | Verification (2026-07-01) |
> |---|---|---|
> | FABLE5-003 (Critical) | `65f4cb9` (A2-006) — `Commitment::add`/`sub` fail closed on the identity point (`pedersen.rs:99-122`) | PoC test `robustness_complement_identity_panic` now **GREEN** (run this date) |
> | FABLE5-004 (High) | `8cbbed2` (A2-004) — RandomX seed resolved from the candidate block's own branch | detector test `a690397`; `cargo test -p dom-chain` green (157 tests) |
> | FABLE5-005 (Medium) | `513cf2e` (A2-005) — MTP window taken from the block's own branch | `cargo test -p dom-chain` green |
> | FABLE5-006 (Low) | `2472fff` (A2-009) — HD derivation intermediates zeroized on every path (`hd_wallet.rs`) | code re-read at source; wallet-keys suite green |
>
> **Readiness reclassification:** the FABLE5-003/-004 blockers in §1 are closed.
> Regtest remains ready; networked deployments are no longer blocked by this report's
> findings. Mainnet remains gated by ROADMAP_v3 Phase 9 (the authoritative launch
> gate — note the v3 launch model has **no public testnet**: dom-shield audit +
> sustained fuzz campaign + private burn-in + genesis ceremony). The readiness table
> in §1 and the Status column in §2 are preserved below as the historical record of
> what this pass found; where they say "Blocked", read them together with this block.

---

## 1. Executive summary and readiness classification

DOM is **substantially hardened**: the inherited fixes (Noise, genesis,
Pedersen/Bulletproof) remain valid with executable proof (§5); monetary integrity
holds on every consensus path (§4 PHASE 1); the network/parsing surface is well
covered (§4 PHASE 3, **no new** high/critical finding). The prior fix program closes
the DOM-AUDIT-001…009 and FIX-005…044 families, verified by sampling against the real
code.

This pass found **1 CRITICAL finding confirmed by an executing test** (remote node
crash via `bp2_verify` — FABLE5-003) and **2 consensus-divergence findings** sharing
the **same root cause** (the live `connect_block` path resolves the RandomX seed and
MTP ancestors from the canonical height index, not from the candidate block's own
ancestry — FABLE5-004/-005), plus **1 LOW** memory-hygiene finding (FABLE5-006).
FABLE5-003 is a **testnet blocker**: a single peer can abort the process of every
validating node.

### Baseline validation (run this session)

| Command | Result |
|---|---|
| `cargo build --workspace` | **OK** (exit 0) |
| `cargo test -p dom-crypto` | **OK** — `0 failed` (incl. `bulletproof_bp::differential::random_1000_match`) |
| `cargo test -p dom-core -p dom-serialization` | **OK** — green |
| `cargo test -p dom-crypto --test robustness_complement_identity_panic` (NEW) | **FAILS by panic** — *this is the finding* FABLE5-003 (RED by design; see §7.1) |
| `cargo audit` (590 deps) | **OK** — no advisories |

> **Method note on the full suite:** `cargo test --workspace` does not finish within
> this session's budget because the heavy targets (native RandomX in
> `dom-node`/`dom-integration-tests`) compile/run for tens of minutes on this machine
> (consistent with `KNOWN_ISSUES.md` — IBD timeouts are RandomX throughput, not a
> bug). I validated the crates relevant to each finding individually.

### Readiness classification

| Target | Verdict | Justification |
|---|---|---|
| **Regtest** | ✅ **Ready** | Single/local actor; FABLE5-003 is not triggered by honest actors; consensus/crypto crate suites green. |
| **Private testnet** | ⛔ **Blocked by FABLE5-003** | The panic→abort in `bp2_verify` is reachable by **any** participant who submits a tx/block with `commitment = MAX_PROVABLE_VALUE·H`. It drops every node. Fix before any networked deploy. |
| **Public testnet** | ⛔ **Blocked** | FABLE5-003 (trivial kill-switch) **and** assessment of FABLE5-004 (consensus partition on a deep cross-epoch reorg). |
| **Mainnet** | ⛔ **Not yet** | Operational prerequisites: `GENESIS_HASH_MAINNET`/`NETWORK_MAGIC_MAINNET`/`GENESIS_TIMESTAMP_MAINNET` are still fail-closed placeholders (`constants.rs:451,460`, guarded by `is_placeholder_genesis_hash`/`assert_*`) → **NEEDS HUMAN DECISION** (genesis ceremony). Plus the findings above + soak. |

---

## 2. Findings table (new in this pass)

| ID | Sev. | Title | File:line | Status |
|---|---|---|---|---|
| **FABLE5-003** | 🔴 **Critical** | `bp2_verify` panics→abort when `commitment == MAX_PROVABLE_VALUE·H` (the complement becomes the point at infinity; `Commitment::sub` copies a 1-byte encoding into `[0u8;33]`). Remote crash / consensus halt. | `dom-crypto/src/pedersen.rs:110` (panic); `:235-240` + `bulletproof_bp.rs:550-553` (trigger); `dom-consensus/src/transaction.rs:405,740`, `dom-slate/src/lib.rs:389` (reach) | **CONFIRMED BY TEST** (panic reproduced) |
| **FABLE5-004** | 🟠 **High** | `connect_block` validates PoW for **every** block (incl. side-chain) with a RandomX seed taken from the **canonical height index**, not from the block's own ancestry. A deep reorg (>64) crossing a RandomX epoch boundary → consensus partition vs. nodes that sync via IBD (branch-aware). | `dom-chain/src/chain_state.rs:273` → `compute_randomx_seed` `:821-831` (`get_hash_at_height`) | **Confirmed by reading**; end-to-end exploit **NEEDS PATCH/TEST** |
| **FABLE5-005** | 🟡 **Medium** | Same pattern: a competing block's Median-Time-Past is computed over **canonical** ancestors (`get_recent_timestamps` → `get_hash_at_height`), not the branch's own ancestors. Accept/reject divergence between branches under adversarial timestamps. | `dom-chain/src/chain_state.rs:265` → `get_recent_timestamps` `:1008-1025` | **Confirmed by reading** |
| **FABLE5-006** | 🔵 **Low** | Secret HD-derivation intermediates are not zeroized (the HMAC `result` and the `il` tweak). Memory hygiene (cold-boot / disclosure). | `dom-wallet-keys/src/hd_wallet.rs:77,119,121` | **Confirmed by reading** |
| — | Info | `HeadersPayload::from_bytes` is the only parser sizing `with_capacity(n)` without a remaining-bytes check (n≤2000 ⇒ ~48 KB transient; immaterial). | `dom-wire/src/message.rs:327` | Informational |
| — | Info | Scoring asymmetry: malformed sig (`Invalid`, ban 10) vs. well-formed-but-wrong sig (`InvalidSignature`, ban 25); both pay the preceding bp_verify, ban triggers within ≤10 tx/IP. | `dom-consensus/src/lib.rs:145,156` | Informational (by design) |
| — | Info | `IbdState::process_headers` docstring claims it validates PoW/continuity, but it only checks height continuity (real validation is `validate_ibd_headers_batch`). | `dom-chain/src/ibd.rs` | Informational (doc drift) |

**Merit decisions:** the **fix** for FABLE5-004/-005 touches consensus validation (how
a candidate's seed/MTP is resolved) → **NEEDS HUMAN DECISION**. The FABLE5-003 fix is
fail-closed and does not change a consensus rule, but it lives in the crypto
serialization layer → confirm with the crypto suite before applying.

---

## 3. FABLE5-003 — CRITICAL (detailed, confirmed by test)

**Title:** remote node crash (panic → `abort`) in `Commitment::sub` via `bp2_verify`
on a forged `commitment` equal to `MAX_PROVABLE_VALUE·H`.
**Severity:** Critical (consensus liveness DoS, network-reachable).

### Description (root cause)
`bp2_verify` (the live consensus range-proof check) derives the bounded-pair
complement `C' = MAX_PROVABLE_VALUE·H − C` from the issuer-supplied `commitment` `C`
(`derive_complement_commitment`, `pedersen.rs:235-240`, called at
`bulletproof_bp.rs:550-553`). `Commitment::sub`/`add` serialize the result with:

```rust
let encoded = EncodedPoint::from(diff).compress();
let mut bytes = [0u8; 33];
bytes.copy_from_slice(encoded.as_bytes());   // pedersen.rs:110
```

When the result is the **point at infinity** (identity), its SEC1 compressed encoding
is **1 byte**, and `copy_from_slice` into `[0u8;33]` **panics** on the length
mismatch. The result is the identity exactly when `C == MAX_PROVABLE_VALUE·H` — a
single, publicly computable curve point. `Cargo.toml:119` sets
`[profile.release] panic = "abort"`, so the panic **aborts the whole process** in
release.

Broken defense observed: the repo **already recognizes** that the identity is
dangerous and rejects it at the **input** boundary
(`crates/dom-crypto/tests/infinity_rejection.rs`, `Commitment::from_compressed_bytes`
rejects `[0;33]`). But here the identity arises **internally** in the complement
arithmetic, where there is no such guard.

### Scenario
An attacker builds an output with `commitment = MAX_PROVABLE_VALUE·H` (the unblinded
commitment to `2^52−1`; a valid SEC1 point accepted by `from_compressed_bytes`) and
any 739-byte proof (passes the size gate; the panic happens **before** the FFI
verify). On validating the tx/block — mempool admission, block validation, or
`Slate::finalize` — any node calls `bp2_verify` and aborts. Reach in the code:
`transaction.rs:405` (**coinbase** output), `transaction.rs:740` (normal tx output),
`dom-slate/src/lib.rs:389` (finalize). **A single broadcast tx/block drops every
validating node.**

### Evidence (executing test)
**New** file: `crates/dom-crypto/tests/robustness_complement_identity_panic.rs`. It
builds `MAX·H` using only the public API (`commit(MAX,r).sub(commit(0,r))`) and calls
`bp2_verify(MAX_H, &[0u8;739])`, asserting the correct contract (`Ok(false)|Err`).

```
$ cargo test -p dom-crypto --test robustness_complement_identity_panic -- --nocapture
running 1 test
thread 'bp2_verify_does_not_panic_on_max_times_h_commitment' panicked at
crates/dom-crypto/src/pedersen.rs:110:15:
copy_from_slice: source slice length (1) does not match destination slice length (33)
test bp2_verify_does_not_panic_on_max_times_h_commitment ... FAILED
test result: FAILED. 0 passed; 1 failed; ...
```

The test is **RED by design** (it encodes the correct contract and fails on the
current bug); it converts to GREEN once the fix lands — the "RED test as finding"
pattern already used in this repo. It was **NOT** marked `#[ignore]` (forbidden; that
would mask the failure).

### Impact
A de-facto unauthenticated network kill-switch: the attacker's cost is ~zero (a fixed
point + proof bytes), and the node aborts. No inflation/double-spend, but a total
consensus halt. **Blocks any networked deploy.**

### Fix (with trade-offs) — outside my write scope (src is read-only)
1. **Fail-closed in the arithmetic:** `Commitment::add`/`sub` return `Err`
   (`DomError::Invalid`) when the resulting point is the identity, instead of
   serializing 1 byte. Covers all callers at once. **Recommended.**
2. **Reject the identity complement in `derive_complement_commitment`/`bp_verify`:**
   treat identity as `Ok(false)` (invalid proof). More local, same effect on the
   consensus path.
This is fail-closed robustness (the degenerate commitment is invalid anyway), **not**
a consensus-rule change — but it lives in the crypto layer; confirm with
`cargo test -p dom-crypto` before applying.

### Missing tests (after patch)
- The new test turns GREEN (`Ok(false)|Err`).
- End-to-end: a block whose **coinbase** has `commitment = MAX·H` is **rejected** (not
  crashed) by `validate_block`; a tx with output `MAX·H` is rejected at mempool
  admission.
- Property/fuzz: `bp2_verify(any valid point, 739B proof)` never panics.

---

## 4. FABLE5-004 / -005 — consensus divergence from non-branch-aware resolution (one root)

**Common root:** `ChainState::connect_block` (`chain_state.rs:200`) is the entry point
for the live relay path (`node.rs:3973` calls `c.connect_block`), the direct
extension, and the side branch (`store_known_block` + `promote_heavier_known_tip`,
`:391-399`). For **every** non-genesis block it validates:
- **PoW** with `seed = compute_randomx_seed(header.height.0)` (`:273`), which reads
  `store.get_hash_at_height(seed_height)` (`:823`) — the **canonical** block at that
  height;
- **MTP** with `get_recent_timestamps(header.height.0, 11)` (`:265`), which also reads
  `get_hash_at_height(h)` (`:1016`) — the **canonical** blocks at the prior heights.

Side-branch blocks are persisted by `store_known_block`, which does **not** update the
height index. So when validating a competing block, the seed/ancestors come from the
**canonical** branch, not the candidate's branch. The IBD path was explicitly
hardened to be branch-aware (`compute_randomx_seed_with_batch`, `:492`;
`collect_ibd_ancestor_timestamps`), which is evidence the resolution **should** be
branch-aware — the asymmetry is the proof this is a gap, not a design.

`apply_connect` (promotion, `:1142-1151`) re-validates inputs/maturity but **not** PoW
or MTP — so a block must clear `connect_block`'s canonical gate **before** it can be
stored/promoted. Nothing rescues it.

### FABLE5-004 (High) — RandomX seed
`RANDOMX_SEED_INTERVAL = 2048`, `RANDOMX_SEED_OFFSET = 64` ⇒
`seed_height(H) = floor(H/2048)·2048 − 64`. A competing branch that (a) forks at
height `< e·2048−64` and (b) extends to `≥ e·2048` uses, for the epoch-`e` blocks,
**its own** block at `e·2048−64` as the seed. Minimum reorg depth ≈ 64 blocks
(≤ `MAX_REORG_DEPTH_POLICY = 1000`). A steady-state node validates that block with the
**canonical** seed → RandomX mismatch → `InvalidPow` → the block is **never stored** →
the node **cannot** adopt the heavier chain. A node that obtains the same branch via
IBD (branch-aware, sequential commit) **accepts** it. → **permanent partition**
between IBD-synced and relay-synced nodes.

### FABLE5-005 (Medium) — MTP ancestors
For a competing block whose fork falls within the 11-block window (the common
short-reorg case), the MTP floor is computed over **canonical** timestamps, not the
branch's. Usually timestamps across branches are close (no flip), but a miner can
forge timestamps that **pass** against its own branch ancestors and **fail**
(`DomError::Invalid`, hard reject) against the canonical ones — or vice versa →
accept divergence between nodes with different tips. `validate_parent_timestamp_progression`
(`:264`) guarantees monotonicity against the immediate parent, but the median floor
uses the wrong set.

### Evidence
**Confirmed by reading** the real code (every cited line verified at source):
`connect_block:265,273`; `compute_randomx_seed:821-831` (canonical) vs
`compute_randomx_seed_with_batch:845-871` (branch-aware); `get_recent_timestamps:1008-1025`;
`promote_heavier_known_tip`/`apply_connect:1142-1151` (no PoW/MTP re-check); relay →
`node.rs:3973`. I did **not** build the end-to-end test (see §8): it requires mining a
real >64-block reorg crossing an epoch boundary with RandomX — infeasible in this
session's budget.

### Impact
Consensus partition (network split) between node populations, no inflation. A >64-block
reorg is rare/expensive in a healthy PoW chain, but it is **within the protocol's
allowed limits** and adversarially inducible by a miner with enough hashpower.
FABLE5-005 is more reachable (short reorgs) but needs adversarial timestamps for the
flip.

### Fix (with trade-offs) — **NEEDS HUMAN DECISION** (touches consensus)
Resolve the seed and MTP ancestors by walking the **candidate block's own ancestry**
(via `prev_hash` / the known-block store), exactly as the IBD path already does with
`compute_randomx_seed_with_batch` — i.e., a variant of
`compute_randomx_seed`/`get_recent_timestamps` that traverses the candidate's branch
instead of the canonical height index. Trade-off: extra I/O per competing-block
validation (by-hash lookups instead of by-height) and care not to introduce per-peer
cost (side-chain storms) — combine with the existing bounds
(`prune_retained_side_chains`, `MAX_REORG_DEPTH_POLICY`). This is a change to a
consensus validation path → not mine to decide alone.

### Missing tests (after decision)
- `connect_block_sidechain_seed_uses_branch_not_canonical`: a competing branch that
  crosses an epoch boundary with its own seed block ≠ canonical is **accepted** and
  promoted (today it fails `InvalidPow`). Use a FastDevOnly target to isolate seed
  selection.
- `connect_block_sidechain_mtp_uses_branch_ancestors`: acceptance decided by the
  branch's own median, not the canonical one.
- IBD-vs-relay differential: the same cross-epoch branch drives both paths to the
  **same** verdict.

---

## 5. Inherited fixes — still valid, with proof (re-verified against the real code)

### 5.1 Noise frame overflow → capped fragmentation (`dom-wire/src/codec.rs`)
**Valid.** On receive, as soon as the 4-byte prefix arrives the declared total is
validated against `MAX_LOGICAL_MSG_BYTES` **before** any pre-allocation
(`codec.rs:166-176`); the buffer grows by ≤ `CHUNK (65519)` per frame and overrun is
rejected (`:178-186`). Per-frame timeout via `IDLE_TIMEOUT_SECS` (`:142`).
**Proof:** `recv_rejects_oversized_declared_length`, `roundtrip_max_block_size`, etc.
(`dom-wire` suite).

### 5.2 Genesis state drift → create == reopen (`dom-chain`)
**Valid.** `create_genesis_block` (`miner.rs:564-565`) persists the changeset via
`dom_chain::genesis_canonical_changeset`, which is exactly
`build_utxo_changeset` + `extract_kernel_excesses` (`chain_state.rs:1406-1408`) — the
**same** helpers the reopen path uses in `ensure_canonical_utxo_set` /
`reconstruct_canonical_utxo_set` (`:174`, `:1208-1233`). Thus `create == reopen` by
construction.

### 5.3 Unified Pedersen/Bulletproof H + sec1↔zkp bridge (`dom-crypto`)
**Valid.** The zkp generator (`bulletproof_bp.rs:83-91`) reconstructs `0x0a/0x0b || X`
by copying the X of Pedersen's `H_COMPRESSED_FINAL` — X is byte-for-byte equal. The
`sec1↔zkp` bridge uses `is_square` via `FieldElement::sqrt`; the loop in `zkp_to_sec1`
iterates over exactly the 2 prefixes (finite) and, since `−1` is a QNR mod p, exactly
one matches. **Proof:** `dom-crypto` suite green (`0 failed`), incl. `random_1000_match`.

### 5.4 FIX-014 — inflation closure via bounded aggregate proof
**Valid.** `bp_verify` (`bulletproof_bp.rs:538-558`) requires exact size (739B),
derives `C' = MAX_PROVABLE_VALUE·H − C`, and verifies the aggregate over `[C, C']`. A
value `v` must satisfy `v ∈ [0,2^64)` **and** `MAX−v ∈ [0,2^64)`, forcing
`v ≤ MAX_PROVABLE_VALUE = 2^52−1`. **Coinbase included** (`transaction.rs:405`).
> Note: this is exactly the path where FABLE5-003 lives — the inflation fix is
> correct, but the complement arithmetic needs fail-closed handling of the identity.

### 5.5 Others (re-verified by sampling)
- DOM-AUDIT-004 RPC `page*limit` `checked_mul` + clamp (`dom-rpc/src/lib.rs:449-462`).
- DOM-AUDIT-006 `/status` reads the real network.
- DOM-AUDIT-009 `commit_block` errors on `NotFound` when removing a canonical spent
  UTXO (`dom-store/src/db.rs:516-521`) — not silent.
- DOM-AUDIT-008 difficulty: `total_difficulty` is `U256` end-to-end; only the scalar
  per-block increment is `u128`, with the boundary documented at 2^128/block
  (astronomical) and a deterministic projection identical on all nodes.
- FIX-028 `read_list` bounds by remaining bytes before alloc; FIX-035 empty token
  rejected; FIX-041 ban reputation is IP-only.

---

## 6. Re-verification of the prior FABLE5 findings (2026-06-10)

| Finding | Current state (code) | Evidence |
|---|---|---|
| FABLE5-001 (crypto before the cheap gates; unscored replay) | **Resolved** | `precheck_cheap_admission_gates` before `validate_transaction` (`dom-mempool/src/lib.rs:254`); short-circuit of known replay before the chain lock (`node.rs:4244`, `mempool.contains`). |
| FABLE5-002 (side-chain persisted before contextual validation) | **Bounded/intentional** | `connect_block:381-405`: `store_known_block` only after `validate_block` (PoW+crypto+balance); retention via `prune_retained_side_chains`; promotion fails closed. Unchanged and correct. |

---

## 7. Files created in this pass
- `crates/dom-crypto/tests/robustness_complement_identity_panic.rs` — FABLE5-003 PoC
  (**RED by design**; it is the finding). See §7.1.
- `audit/FABLE5_SECURITY_AUDIT.md` — this report (supersedes the 2026-06-10 pass).

### 7.1 Note on the RED test
The new test **fails by panic** today — that is the point: it asserts the correct
contract (`bp2_verify` never panics) and exposes the bug. Keeping it in the tree leaves
`cargo test -p dom-crypto` red until FABLE5-003 is fixed. Per the integrity principles,
I did **not** mark it `#[ignore]` nor loosen the assertion. If the maintainer prefers a
green tree before deciding the fix, removing the file is the maintainer's decision (I
did not take it).

---

## 8. What I could NOT test (and why)
- **Full `cargo test --workspace`:** native RandomX targets (`dom-node`,
  `dom-integration-tests`) exceed this session's time budget (consistent with
  `KNOWN_ISSUES.md`). Validated per crate.
- **FABLE5-004/-005 end-to-end:** require mining a real >64-block reorg crossing a
  RandomX epoch boundary, with adversarial timestamps — infeasible here. I proved the
  **code behavior** (canonical vs. branch-aware selection) by reading the source; the
  exploit is marked **NEEDS PATCH/TEST** and, for the fix, **HUMAN DECISION**.
- **FABLE5-003 end-to-end (real block/coinbase):** I proved the panic at the
  `bp2_verify` boundary (the function consensus calls); assembling a full block with a
  `MAX·H` coinbase was not done — the crash point is the same function.
- **Multi-peer network DoS with real sockets:** out of unit-test reach.

## 9. Method limitations
- Read-only on production: where the fix would touch `src/`, I described it and left
  the decision (FABLE5-003 fail-closed; FABLE5-004/-005 consensus → **HUMAN DECISION**).
- Broad mapping of the 3 phases via exploration agents, **re-verified in the code** at
  the critical points (`connect_block` seed/MTP, `Commitment::sub`, bp2 complement,
  Noise codec, genesis changeset, `bp2_verify` call sites). Where I cite a line, I
  confirmed it at source.
- No `git add/commit/push`; no branch/config change.
