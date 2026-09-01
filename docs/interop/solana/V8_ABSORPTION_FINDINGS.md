# DOM↔SOL V8 — what the package is, and what stands between it and production

Date: 2026-09-01
Reviewed: `dom-solana-v8-overlay` (74 files), the `v7-full → v8-full` patch, and
`dom-protocol-feat-domv2-xmr-solana-v8-full`.
Absorbed into: `mainnetswap` @ `7ea7f968`.

Every statement below was verified against the code, or against a gate that was
actually run. Nothing is taken from the documents shipped with the package.

---

## 0. The construction is right

Before the defects, the thing that matters: this is **not** a hashlock leg.
`programs/dom-solana-escrow/src/secret.rs` verifies `s · G_ed25519 == P` through
Solana's curve25519 syscall, against the *same* 252-bit witness the Monero leg
uses. `solana-route-secret` mints it with the same audited `CrossCurveDLEQ`, and
`SolanaRouteSecret::dom_adaptor_point()` is the secp256k1 half of the identical
claim. One witness, two curves, one proof binding them.

The 252-bit domain is re-enforced **on chain**, before the syscall:

```rust
if little_endian[31] & 0xf0 != 0 {
    return Err(EscrowProgramError::InvalidSecret);
}
```

That is the correct place for it. A syscall that reduces modulo the group order
would otherwise accept a witness the DLEQ never proved.

And one architectural judgement is correct in a way that deserves saying plainly:
**the Solana leg does not need a refund adaptor.** A program can enforce its own
timelock refund; a Monero shared spend key cannot. The asymmetry that forced
`NAR-DC-P1-009` on the XMR side is genuinely absent here, and the package is
right not to invent one.

Also right: `attest_immutable_program` refuses a program that still has an
upgrade authority, pins the program-data hash, and reads both accounts at
`Finalized` through an RPC quorum. Token-2022 is refused by strict program-id
check. The eight client account orders match the program's `next_account_info`
order exactly, with `ensure_no_extra` closing every tail. `solana-escrow-wire`
is `no_std` and dependency-free because the on-chain program links it.

---

## A. Blocking (7 — A7 restated)

### A1. The DLEQ role byte collides with the XMR refund role

```rust
// crates/adapters/solana-route-secret/src/lib.rs
pub const ROLE_SOLANA_CONDITION_LOCK: u8 = 2;

// crates/adapters/xmr-dleq-sigma/src/lib.rs
pub const ROLE_XMR_SHARED_SPEND: u8 = 1;
pub const ROLE_XMR_REFUND_SHARE:  u8 = 2;   // ← same byte
```

The role tag exists for exactly one purpose, stated in the auditor handoff:
*a proof for one path must not be replayable as the other*. With one byte
serving two paths, it does not.

This is not an argument. It is measured, in
`crates/f8-solana-e2e/tests/role_collision_probe.rs`:

```
test the_two_role_constants_are_the_same_byte ... ok
test an_xmr_refund_proof_verifies_as_a_solana_condition_lock_proof ... ok
```

A proof minted by `XmrRefundSecret::generate` — for the Monero refund path and
nothing else — is handed unmodified to `solana_route_secret::verify_counterparty_bundle`
and is **accepted**. Settlement id and context hash still separate two unrelated
settlements; they do not separate two legs of one composed route, which is the
case DOM v2 exists for.

The package is not at fault: it was authored on v7-full, where role 2 was free.
The collision is created by the merge, and it must be resolved before the merge
lands.

**Fix:** `ROLE_SOLANA_CONDITION_LOCK = 3`, and the role space moved into
`xmr-dleq-sigma` as a single closed registry, so a fourth leg cannot repeat this
by construction rather than by care. Left undone here: assigning a consensus
byte is your signature, not mine.

### A2. `SolanaNetwork::MainnetBeta` is admissible

Every other chain in this branch refuses mainnet **by omission**:

| Chain | Mainnet |
|---|---|
| Bitcoin | absent from `BitcoinNetworkV1` (D-027) |
| Monero | absent from `MoneroNetworkV1` |
| EVM | chain id 1 refuses |
| **Solana** | **`MainnetBeta = 1`, and nothing refuses it** |

`SolanaAdapterProfileV1::new` accepts any network; the only thing `network`
changes is `require_immutable_program`. So a profile can be built for Solana
mainnet-beta today, in a branch where no other chain can reach mainnet at all.

**Fix:** remove the variant, exactly as `MoneroNetworkV1` did. The comment there
is the precedent: refused "by omission, not by a special case".

### A3. `LockMechanism::ConditionLock` is a false label for this leg

`kaystra-core` ratifies it as:

```rust
/// EVM ConditionLock contract (ecrecover trick on t·G).
ConditionLock = 0x02,
```

An EVM ConditionLock verifies on **secp256k1** — the DOM curve — via `ecrecover`.
No cross-curve proof is involved. The Solana leg verifies on **ed25519** and
depends on the cross-curve DLEQ for its soundness. A verifier reading frozen
terms tagged `0x02` would conclude no DLEQ is required.

This is the same defect class as `SchnorrAdaptor` on the XMR leg, which we
already refused, with one aggravation: `ConditionLock` is an existing ratified
tag, so using it here silently widens a meaning already signed rather than
proposing a new one.

**Fix:** a dedicated mechanism (`CrossCurveConditionLock = 0x06`) — or an
explicit, signed widening of `ConditionLock`. Either way it is a ratification,
not a code change I can make alone.

### A4. The leg is invisible to `chain-profile` and to `route-time-anchor`

There is no `ChainKindV1::Solana` and no `ClockKindV2::Solana`.

State the good half first, because it changes what this item is.
`route-time-anchor` enforces `upstream.earliest >= downstream.latest + margin`,
and the checkpoint binding that feeds it is a **closed match** over
`(chain kind, deployment, timelock spec)` gated on the leg's mechanism:

```rust
(ChainKindV1::Monero { .. }, ChainDeploymentV1::Monero(d), TimelockSpec::BlockHeight { .. })
    if leg.mechanism == LockMechanism::CrossCurveSharedSpend => (ClockKindV2::Monero, d.genesis_hash),
...
_ => return Err(RouteTimeAnchorErrorV2::UnsupportedTopology),
```

So the Monero leg already has cross-leg timelock ordering, and **a route with a
Solana leg cannot be armed at all today** — it falls to `UnsupportedTopology`.
The system fails closed. This is an addition to a closed registry, not a hole.

Two things follow. First, it is a hard blocker: no composed DOM↔SOL route runs
until `ChainKindV1::Solana`, `ChainDeploymentV1::Solana` and `ClockKindV2::Solana`
exist and a match arm admits them. Second, A3 is load-bearing here — the arm
gates on `leg.mechanism`, so the mechanism tag is not a label, it is a condition.
Tagging the Solana leg `ConditionLock` would demand `ChainKindV1::Evm`, which it
is not, and the route would be refused for the right reason by accident rather
than the right reason on purpose.

Within the Solana crates themselves, `solana-profile` checks that the binding's
`refund_after_unix` matches the frozen terms, which is binding consistency, not
timelock ordering.

Aggravating: the escrow refunds on `Clock::unix_timestamp`, a stake-weighted
validator estimate with real historical drift from wall clock. Its `ClockKindV2`
projection has to be conservative about that drift, the way `Monero` was
restricted to absolute height because it is "the only clock the XMR leg offers
that an observer can evaluate deterministically".

### A5. The base is v7-full again — A1 of the XMR review, verbatim

`ACTIVE_COMPONENTS.json` says `"cumulative_from": "dom-protocol-feat-domv2-xmr-v7-full"`.
All **13** interop crates are still missing from the full zip: `dom-interopd`,
`deployment-registry`, `route-time-anchor`, `route-executor`,
`settlement-coordinator`, `participant-binding`, `btc-actuator`, `evm-actuator`,
`dom-actuator`, `dom-final-claim-binding`, `route-secret-vault`,
`solver-inventory`, `solver-status`.

Adopting the v8 zip as the base would delete the daemon, the deployment
registry, the time anchor and the chain actuators — including the very crate
A4 needs.

**Done:** the 24 crates and the program were absorbed into `mainnetswap`
instead. The direction is one-way and stays one-way.

### A6. The package did not compile, and the same codec defect recurred a third time

`cargo check` on absorption, five errors:

| Defect | Where |
|---|---|
| `[u8; 64]: Serialize`/`Deserialize` not satisfied (×3) | `solana-types::SolanaSignature` |
| `PartialEq` not const-stable in a `const fn` | `solana-types::SolanaPubkey::is_zero` |
| `RevealedSecretBytes(..)` — private field | `solana-route-secret`, `solana-counterparty` |
| `WireError` lacks `Error` for `?` | `f8-solana-e2e` |

The 64-byte serde failure is the **third** appearance of this class: `[u8; 33]`
in v6, `[u8; 33]` again in v7, `[u8; 64]` now. It was fixed the same way — a
fixed-width codec that refuses any other length, because a consensus-sensitive
identity must not depend on a serializer's array representation.

The `RevealedSecretBytes` failures are worth reading as a signal rather than a
chore: the field was closed in `mainnetswap` after v7 branched, so the older
base constructs a redacting wrapper by bypassing its only constructor. The
compiler caught it. It would not have caught it on the v7 base.

**Done.** All fixed; the full workspace now passes `clippy --workspace
--all-targets -D warnings` at zero, and `cargo fmt --all -- --check` is clean.

### A7. ~~No nullifier~~ — withdrawn. The route secret has nowhere to live.

The nullifier claim was wrong and is withdrawn. There is no crate named for it,
but `solana-setup-store` carries the property in its schema:

```sql
secp_claim BLOB UNIQUE NOT NULL CHECK(length(secp_claim)=33),
ed_claim   BLOB UNIQUE NOT NULL CHECK(length(ed_claim)=32),
```

Both halves of the public claim are unique across the table, exact replay of an
identical binding is idempotent, and a divergent setup on the same settlement
returns `Conflict`. That is the one-shot registry, folded into the setup store
instead of a separate crate. Nothing to add.

What is genuinely missing at this line is the **other** store. `SolanaRouteSecret`
lives only inside `InitializedSolanaSession`, in memory, and is never persisted.
The XMR leg has `xmr-secret-store`, which keeps the route secret encrypted at
rest. Here, a process that dies between funding and claim loses the witness: the
funds are then recoverable only by waiting out the timelock refund. That is not
a loss of funds — the program's refund path is real — but every interrupted
session degrades to its slowest outcome, and a node that restarts cannot resume
any settlement it had open.

---

## B. Required before production (6)

### B1. 15 tests in 5,760 lines; the program that holds the funds has one

17 of 25 crates have zero tests. The distribution:

| Crate | Tests | Lines | Role |
|---|---|---|---|
| `dom-solana-escrow` (program) | **1** | 902 | holds and releases every lamport |
| `solana-observer` | 0 | 235 | terminal-state evidence |
| `solana-program-attestation` | 0 | 91 | immutability + code hash |
| `solana-profile` | 0 | 368 | setup validation, the whole gate |
| `solana-session-init` | 0 | 135 | pre-funding binding |
| `solana-observation-store` | 0 | 411 | durable observation |
| `solana-delivery` / `-sqlite` | 0 | 408 | exact-bytes delivery journal |
| `solana-rpc` / `-pool` | 0 | 364 | quorum |

The program's single test is `zero_secret_is_rejected`. Nothing exercises claim,
refund, close, PDA substitution, account substitution, or double-terminal.

One test was worse than absent: `solana-setup-store` shipped

```rust
assert_eq!("solana_setup_v1".ends_with("_v1"), true);
```

a tautology over a string literal, counted in the total. That crate is at zero.

### B2. The program has never been compiled for the target it runs on

`cargo clippy` on the program reports `unexpected cfg condition value: solana`,
which proves `target_os = "solana"` has never been active. On the host,
`multiply_edwards` resolves to the `curve25519-dalek` fallback. On chain it
resolves to the syscall. **The only path that matters has never been built**,
and the CI `program` job (`cargo test --manifest-path …`) builds the host path
too.

The program is also `exclude`d from the DOM workspace, so
`clippy --workspace -D warnings` never sees it. It currently carries 6 warnings.

### B3. Whether the curve25519 syscall is enabled on the target cluster

The entire design rests on `sol_curve_group_op` being active where you intend to
settle. This is a live-cluster fact, not a code fact, and this container cannot
reach a Solana RPC to check it. It is the **first** thing to verify on the VPS,
because if the answer is no on your target cluster, no amount of the rest
matters:

```bash
solana feature status --url <cluster> | grep -i curve25519
```

Deploy the program to that cluster and call `Claim` with a known-good witness
before anything else is built on top.

### B4. `program-id.txt` is a placeholder

`3KN5WMzZsmwDCfKYheaVgx8Xo4veke815LJo3iYrdeNw` corresponds to no deployment.
Until the program is deployed, its program-data hash recorded, and its upgrade
authority revoked, `attest_immutable_program` has nothing true to attest — and
`SolanaAdapterProfileV1.program_id` has nothing real to pin.

### B5. The static validator checks textual presence, not wiring

`scripts/solana-v8-static-validate.py` is 64 lines whose substantive check is:

```python
required=['multiply_edwards','TimelockNotReached','attest_immutable_program',
          'SolanaKaystraSource','SqliteSolanaDeliveryStore','Token-2022']
```

— six strings, greped across the tree. This is the same defect as
`xmr-v7-static-validate.py:193`, which "verified" guarded initialization by
grepping for its name. A gate that cannot fail on a disconnected implementation
is not a gate.

### B6. Nothing connects the leg to the DOM engine

`finalize_session` and `prepare_route_secret` have callers **only** in
`f8-solana-e2e`. There is no `solana-runtime-wiring`, no actuator, and no bridge
carrying a revealed DOM secret into the escrow's `Claim` instruction — the role
`xmr-kaystra-bridge` plays for Monero. Internally the Solana crates are wired
honestly (the observer really does call `attest_immutable_program`;
`finalize_session` really does call `validate_setup`); it is the outer boundary
that is open.

---

## C. State of the tree after absorption

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | **0** |
| Solana crate tests (24 crates) | 14 passed, 0 failed |
| `dom-solana-escrow` (own workspace) | 2 passed, 0 failed, 6 warnings |
| Role collision probe | 2 passed — the collision is real |

Changes made: 8 files, all of them compile or lint repairs plus the probe. No
invariant was widened, no check softened, and no consensus byte assigned.

---

## D. Order of work

1. **Resolve the role byte** (A1) — one line of code, but a ratification. Nothing
   downstream is safe to build first.
2. **Remove `MainnetBeta`** (A2). Trivial, and it closes an open door.
3. **Decide the mechanism tag** (A3) — new variant, or a signed widening.
4. **Verify the syscall on the target cluster** (B3), then deploy and pin (B4).
   If B3 fails, stop; the design does not run there.
5. **`ChainKindV1::Solana` + `ClockKindV2::Solana`, then the time ladder** (A4).
   This is the item that makes the route atomic rather than merely paired.
6. **Build the program for `target_os = "solana"`** and run it under
   `solana-program-test` (B2), then adversarial account/PDA substitution (B1).
7. **The nullifier** (A7), the wiring and bridge (B6), a real static gate (B5).
8. **Independent audit** of the program and of the third DLEQ role.

Steps 1–3 are yours to sign. Steps 4–8 are measured engineering.

No document in the package, and not this one, authorizes mainnet.

---

## E. Closure record — 2026-09-01, same day, after construction

Everything in section D that was engineering (steps 5–7 and the code half of
1–3) has been built. The measured state:

| Item | Was | Is |
|---|---|---|
| A1 role byte | collision, proven | registry closed in `xmr-dleq-sigma`, `ROLE_SOLANA_CONDITION_LOCK = 3`, probe inverted to a regression test |
| A2 MainnetBeta | admissible | variant deleted; refused by omission in both enums |
| A3 mechanism | `ConditionLock` (false label) | `CrossCurveConditionLock = 0x06`, wired through terms, profile, admission |
| A4 time anchor | leg unrepresentable | `ChainKindV1::Solana`, `ChainDeploymentV1::Solana`, `ClockKindV2::Solana = 5`, ±3600s drift band; **and the Monero projection arm, found missing, repaired** |
| A7 witness at rest | in memory only | `solana-secret-store` (XChaCha20-Poly1305) + `persist_route_witness`/`resume_session` |
| B1 tests | 15, one a tautology | ~50 across the leg; the program's native paths run as deployed code under a syscall-stubbed harness (9 adversarial tests) |
| B2 target build | never | `sbf-solana-solana` via platform-tools v1.48; `dom_solana_escrow.so` SHA-256 `2a3c12b23bf84b453a06b688bc733868bb3bfd09efc95226322e245ea3459d93`; lockfile pinned |
| B5 static gate | grep of six strings | caller-graph + role-registry + mainnet-absence gate that demonstrably fails on dead wiring |
| B6 engine wiring | none | `solana-kaystra-bridge` (RevealedSecretSinkV1) + `solana-runtime-wiring` gated on `attest_immutable_program` |

Ratification record: `docs/specifications/normative/NAR-DC-P1-010-solana-counterparty-leg-and-role-registry.en.md`
(PROPOSED / UNSIGNED). What remains is its §5: the syscall check on the target
cluster, real deployment + authority revocation, a local-validator run, the
audit, and daemon composition — the same distance the Monero leg stands at.
