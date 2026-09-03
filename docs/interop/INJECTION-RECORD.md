# The interoperability layer inside the DOM

**Status: NOT RATIFIED.** This document records what was done and how each
claim can be checked. It asserts no gate verdict.

The DOM is mainnet. The whole injection is built on one rule, given by the
operator and stated by the Foundation Document before him:

> §P.3.2 — "No component alters `dom-protocol`, DOM Wallet, `dom-contracts`
> or consensus."
> §P.3.6 — "A component that 'requires' a consensus change is defective."

So the layer was not merged into the node. It was placed beside it.

---

## 1. The invariant, and how to check it in one command

The twenty-nine crates of the node are byte for byte the release line, with
**one named exception**, recorded in full below:
`crates/dom-integration-tests/tests/replay_determinism.rs`.

```bash
git diff release/mainnetv2 -- crates/dom-cli crates/dom-core \
  crates/dom-consensus crates/dom-crypto crates/dom-serialization \
  crates/dom-pmmr crates/dom-pow crates/dom-chain crates/dom-wire \
  crates/dom-tx crates/dom-slate crates/dom-mempool crates/dom-store \
  crates/dom-config crates/dom-node crates/dom-wallet \
  crates/dom-wallet-crypto crates/dom-wallet-keys \
  crates/dom-wallet-core-api crates/dom-wallet-recovery \
  crates/dom-wallet2 crates/dom-rpc crates/dom-test-vectors \
  crates/dom-integration-tests crates/dom-explorer crates/dom-faucet \
  crates/dom-wallet-app crates/dom-test-runner crates/dom-agent-runner
```

It prints exactly one hunk, in `replay_determinism.rs`, and nothing else.
Outside `crates/`, the only pre-existing files that changed at all are
`Cargo.toml` and `deny.toml`, and both changed by addition only —
`git diff release/mainnetv2 -- Cargo.toml deny.toml | grep '^-[^-]'` is empty.

### The exception, its reason, and its death condition

`crates/dom-integration-tests/tests/replay_determinism.rs` carries one hunk
that the release line does not. It repairs a defect of the release line, not
of the injection.

The test `side_chain_block_does_not_rewrite_canonical_tip_after_restart`
mines a canonical height-1 block and an independent height-1 competitor, then
asserts `ConnectResult::SideChain`. Both blocks sit at height 1 on regtest
with the same fixed target, so their total difficulty is **equal by
construction**, and the node's own fork choice breaks an equal-work tie by the
lexicographically smaller hash — `is_better_fork_choice_tip`,
`crates/dom-chain/src/chain_state.rs:130`. The assertion therefore holds only
when the competitor's hash happens to sort above the canonical tip's. It is a
coin flip on the mined nonce, and the test's ten subsequent assertions all
depend on the competitor losing.

Measured, not inferred. On the release line itself — the same test rebuilt
with `3008587`'s own `Cargo.toml` and `Cargo.lock`, both verified identical by
sha256 — **8 failures in 16 runs**. On this branch before the fix, 42 runs
correlate perfectly with the tie-break: competitor hash below the canonical
tip ⇒ failure, above ⇒ pass, 42 of 42 without exception. The CI history of
`release/mainnetv2` shows the workflow ran three times in total, all on 10
August, the last of them green: with a 50% coin, three runs reveal nothing.
The defect is live on the release line and has simply never been exercised
enough to surface.

The fix makes the **scenario** deterministic rather than the result
conditional: it re-mines the competitor until it loses the tie-break. That is
the scenario the test's name already describes. Accepting either result would
make the test incapable of failing; writing the reorg branch would be dozens
of new lines in a node file. Selecting the fixture keeps the test's subject,
leaves its body untouched, and holds the diff to one hunk.

Two preconditions of the loop were verified before it was written, not
assumed. `produce_single_block` yields distinct hashes on repeated in-process
calls — 16 of 16 distinct, measured — because `test_config` derives a fresh
data directory per call from pid, port and nanoseconds, and the node identity
follows the directory. And port 43403 cannot collide across attempts because
`spawn_node` only calls `DomNode::init`; the P2P bind lives in `run()`
(`crates/dom-node/src/node.rs:678`), which this path never invokes. The loop
is bounded at 16 attempts, so a spurious failure has probability 2⁻¹⁶.

**This exception dies when the node line adopts the same text.**
`scripts/check-node-test-exception.sh` enforces both halves: it pins the
release-line blob and the fixed text by sha256, asserts the difference is
exactly one hunk, and **fails** the moment the release line contains the fix —
telling whoever sees it to restore byte identity with `git checkout`, delete
the guard and its CI wiring, and remove this section. It fails closed if it
cannot reach the release commit; it does not skip. All four failure modes were
exercised against a simulated adoption before the guard was wired in.

---

## 2. What entered

Sixty-eight workspace members, up from thirty.

| Group | Crates |
| --- | --- |
| Settlement path | `dom-adaptor`, `dom-leg`, `dom-vault`, `kaystra-core`, `store`, `uspe` |
| Contracts | the seven `dom-scriptless-*` |
| Counterparty adapters | `adapters/{btc,btc-crypto,btc-secp-sys,btc-vault,dom-real,evm}` |
| Quote, board and routing | `rfq`, `solver`, `intent-book`, `relay`, `relay-scriptless-wire`, `route-composer`, `route-transport`, `chain-profile`, `counterparty-api`, `f6-engine`, `f7-anchor-authority` |
| F2–F7 acceptance harness | `f2-harness`, `f2-model`, `f3-harness`, `f4-harness`, `f4-model`, `f5-e2e`, `f6-model`, `f7-e2e`, and `adapters/{btc-evidence,btc-live,btc-observer,btc-secp-c1a,dom-sim}` |
| Bridges (new) | `dom-scriptless-primitives`, `dom-scriptless-consensus`, `dom-scriptless-bulletproof` |

---

## 3. The three bridges, and why they exist

In the laboratory lineage the layer reached into the node: it needed eleven
symbols that lived **inside** `dom-crypto` and `dom-consensus`. Those
symbols do not exist on the release line, and the node cannot grow them.
No crate of the node consumes any of them — measured — so all eleven were
placed beside the node instead.

Each bridge is pinned to the node by a test rather than by this document.

### `dom-scriptless-primitives` — the adaptor arithmetic

Consumes only the node's public surface: `schnorr_challenge`,
`schnorr_verify`, `PublicKey`, `PartialSig`, `SchnorrSignature`. The DOM's
challenge and verifier are never reimplemented (I15).

Five SEC1 and scalar encodings the node keeps private had no public route
out and are transcribed into `curve`. `curve::conformance` re-derives each
one through `dom_crypto`'s own public parsers and fails if they diverge.

### `dom-scriptless-consensus` — the transaction projections

`scriptless_transaction_template_bytes_v1` and
`scriptless_kernel_message_digest_v1`. Both are off-chain adapters; neither
alters DOM serialization or participates in validation. They read only
public fields, public limits and the node's kernel tag. Guarded by a frozen
template digest and by an assertion that the kernel digest *is* the node's
own tagged hash.

### `dom-scriptless-bulletproof` — the collaborative MPC

The one bridge that could not be written against a public surface. The
shared-output MPC drives grin's raw rangeproof FFI with H_DOM as
`value_gen`, and every wrapper it needs is crate-private inside
`dom-crypto`. That backend is therefore transcribed here.

Three conformance tests pin the copy to the node, in both roles:

| Test | What it refuses |
| --- | --- |
| `h_generator_is_the_nodes` | a second H generator |
| `proofs_this_backend_builds_pass_the_nodes_verifier` | proofs the DOM would reject |
| `proofs_the_node_builds_pass_this_backend` | a verifier stricter or looser than the DOM's |

One helper, `commit_unblinded`, reaches a private generator handle and has
no faithful transcription. It is expressed through the node's own public
constructor instead, as `commit(v, b) - commit(0, b)`, which cancels the
blinding term for any `b` and leaves exactly `v·H_DOM`.

**This duplication is an audit item, not a design.** It exists only because
the node is immutable. If `dom-crypto` ever exposes its backend, the
transcription should be deleted, not maintained.

---

## 4. What did not travel, and why

Three things stayed behind. None of them is blocked work waiting to resume —
each is laboratory apparatus that only appeared to belong here because it
lived under `crates/`.

**`laboratory/`** — the minutes, adjudications and signatures of the F7/F8
process. Governance record, not product.

**`f7-runner`** — the laboratory runtime, removed from this branch's HISTORY,
not merely excluded from the build. Excluding it left its source published,
and that source is the only place in any of the four lineages that BUILDS
paths into two of the three protected runtime directories from a
machine-local root the code validates against, naming four credential files.
`crates/f2-harness/tests/workspace_exclusions.rs` now refuses the path itself
rather than listing it, so re-adding it under exclusion cannot pass.

**`dom-leg/f7-wallet-compositor-evidence-only`** (named `f7-wallet-compositor`
until the Stage 13 guard pass required the name to carry the surface it
forwards) — the Wallet V3 compositor, and the six
`dom-wallet-*` git dependencies it switched on. Three written bases, none of
them anyone's judgement: `check-boundaries.sh:13` makes an ordinary DOM Wallet
dependency an architectural violation; `dom-leg`'s own comment declared the
feature evidence apparatus, "never enabled by the production F7 runner"; and
`f7-runner` was its only consumer anywhere, so the runner's removal left it
with no caller at all.

It went out as a normal commit rather than a rewrite: those six declarations
carry no machine-local path, so what they violated was the CURRENT boundary
state, which `git grep` reads from HEAD.

The removal reached further than the feature's name suggests — `lib.rs` gated
three modules on it, plus a test module included by `#[path]` — and every
dependency it switched on was checked one at a time for another consumer
before being dropped. Nine had none.

**This is what finally closed the second node.** The Wallet V3 pin resolved
the DOM through a git revision of this same repository, putting an older node
in the graph whose `TransactionInput` is a different type from ours. An
earlier revision of this record claimed that was already resolved; it was
true only of the resolved graph, while Cargo's optional closure still carried
`dom-protocol @ 6f8a947d` in the lockfile. With the compositor gone the
lockfile lost 950 lines, and both the graph and the closure now hold exactly
two git packages, both `secp256k1-zkp`. There is one DOM and it is mainnet.

---

## 5. Two pins moved, both upward, both dev-only

`tempfile` in `f3-harness` was `=3.23.0` while the absorbed
crates carry `=3.24.0`. Aligned upward, the same direction the absorption
took. Both are dev-dependencies; the exact pin is kept rather than widened
to a range.

---

## 6. Five defects the injection surfaced, and how each was closed

Bringing the layer under the DOM's workspace and the DOM's audits put it
under checks it had never faced. Each finding below reproduces identically
in the laboratory monorepo, so none was caused by the injection — and none
was left standing.

### The Bulletproof statement was frozen over the wrong shares

Twelve tests in `dom-scriptless-crypto::shared_output_v1` failed with "the
pinned Bulletproof statement was refused". `freeze_shared_output_statement_v1`
injected `v*H` into share 0 before freezing, while
`BpStatementV1::aggregate_commitment_from_shares` adds `v*H` once on top of
the ordered sum — so the statement asserted `2v*H + R` against an aggregate
of `v*H + R`, and every real formation was refused.

The injection had a written reason: that the aggregate check "only asserts
`sum(shares) == aggregate`" and so could not refuse a statement claiming `v`
over an aggregate that opens to `0`. True of an earlier check; the pinned one
now rebuilds `v*H + Σ shares`, so it refuses exactly that on its own. The
defence became the authority's, and layering on top of it broke the
composition. `dom-adaptor` is the cryptographic authority (§P.2), so the
consumer moved. Every refusal test still passes.

### Two fault-injection hooks I wrongly called unreachable

**This entry corrects an earlier claim in this document.** It first said the
resend interposition and the evidence test clock were installed by no test and
could not be, and recorded them as removed. That was wrong.

`mod signer_e2e` is gated `#[cfg(all(test, feature = "evidence-only"))]` and
uses both — `resend_revalidates_full_store_across_lookup_interposition`
installs the interposition, `budget_scopes_windows_clock_and_abort_states_fail_closed`
drives the clock. My reasoning about the pin sealing `ResendRequestV1` was
about the wrong entry point.

What made the error survive is the part worth keeping: **no gate compiled that
intersection.** `cargo test --workspace` builds default features;
`clippy --all-targets` builds targets, not feature combinations. So the
consumer and the hooks disappeared from every check at once, and deleting them
looked clean in a green tree.

Both are restored under `all(test, feature = "evidence-only")` — the exact
condition of their only consumer, tighter than the `#[cfg(test)]` they carried
— so they exist where they are used and are dead in no configuration. The gate
now compiles the surface: `interop-real-backend` lints and tests
`dom-scriptless-store --features evidence-only` and lints
`store --features failpoints`.

### A test that assumed seven directories where six exist

`restored_generation_inventory_allows_only_the_seven_optional_namespaces`
removed seven namespace directories, but `collaborative-secrets` is created
lazily and is absent in a fresh generation. The removal now accepts an
already-absent namespace — and only that; every other error still propagates —
while the assertion that follows is unchanged.

### Bare commit hashes under the DOM's drift audit

`dom-leg` documented the real-adaptor round as running "over the crate pinned
at" a revision, which stopped being true the moment `dom-adaptor` became a
workspace member. The two frozen commits that carried the same shape left
with `f7-runner` itself.

### A crate outside the workspace is a crate no gate covers

`wallet-desktop` is the node's own exclusion and the only one left.
`the_workspace_excludes_exactly_the_crates_it_is_allowed_to` pins the list and
fails on any change, and `the_forbidden_paths_are_absent_from_the_tree` goes
further for `crates/f7-runner`: it refuses the path itself, because listing a
removed crate as an exclusion would restore exactly the state that was
removed. Both verified by injecting the violation and watching them fire.

---

## 7. The toolchain is not pinned, and source identity does not cover it

Section 1's invariant is a **source** invariant. It says the node's twenty-nine
crates are byte-identical to `release/mainnetv2`. It does not say the binary is.

`rust-toolchain.toml` is byte-identical to the release line — the injection did
not touch it — and it reads:

```toml
[toolchain]
channel = "stable"
```

`stable` floats. Nothing in this repository pins a compiler version, so the
binary the mainnet runs is a function of the day it was built, with or without
this injection. This gate ran on:

```
cargo 1.98.0 (797e8a9bc 2026-08-05)
rustc 1.98.0 (88d9e12ae 2026-08-18)
```

The layer did **not** raise the floor. The highest MSRV in the resolved graph
is 1.92, declared by `eframe`/`egui`, which the node's own `dom-wallet-app`
pulls in — the node already required it. `rusqlite =0.40.1` and
`libsqlite3-sys`, which only layer crates use, declare no `rust-version` at
all. The workspace's `rust-version = "1.75"` is unchanged and was already
below what the node's own dependencies demand.

Whether to pin a compiler version for reproducible mainnet builds is an open
question this record raises and does not decide.

### The layer's exact pins moved the node's dependency versions — several down

This is the sharper form of the same point, and it is an **open item, not a
closed one.**

The node declares its dependencies as ranges (`sha2 = "0.10"`,
`proptest = "1"`, `tempfile = "3.10"`). The layer declares many of the same
crates as exact pins (`=0.10.8`, `=1.7.0`, `=3.24.0`, `=0.2.16`). Cargo
resolves one version per major, and an exact pin is the binding constraint —
so the layer's pins decide what the node compiles against. Fourteen packages
that already existed on the release line resolve differently now:

| Package | Release line | After injection | Node crates reached |
| --- | --- | --- | --- |
| `sha2` | 0.10.9 | **0.10.8** | dom-crypto, dom-wallet, dom-wallet-crypto, dom-wallet-keys |
| `proptest` | 1.11.0 | **1.7.0** | 21 node crates' property tests |
| `tempfile` | 3.27.0 | **3.24.0** | 10 node crates |
| `getrandom` | 0.2.17 | **0.2.16** | transitive |
| `serde`, `serde_json` | 1.0.228 / 1.0.149 | 1.0.229 / 1.0.151 | 9 node crates |

No package was dropped, and 85 are new. `sha2` is the node's hashing
dependency and it moved **backwards**, so that one was answered from the
crate's own changelog and source rather than left as a worry.

**sha2 0.10.9 -> 0.10.8 is inert here.** The 0.10.9 release (2025-04-30) has a
single entry, and it is an addition: the opt-in `force-soft-compact` feature
selecting a compact software backend (backport of RustCrypto/hashes#686 via
#687). No fix, no advisory. The source diff between the two versions agrees
with the changelog exactly — doc examples in `lib.rs`, and in `sha256.rs` and
`sha512.rs` one new `cfg_if` branch gated on that new feature plus the
`soft_compact.rs` modules it selects. No existing compression function is
touched. Nothing in this workspace enables `force-soft-compact` or
`force-soft`, and `cargo deny check advisories` reports nothing against `sha2`
at either version.

The other four downgrades are dev/test or transitive and carry no advisory
either. `proptest` is the one with a behavioural surface — it generates the
node's property-test cases — and its effect was measured directly: see the
flake section below.

Section 1's `git diff` is still true and still empty. That is exactly the
limit worth naming: **byte-identical source does not mean the node builds the
same artifact as the release line does.** It does not, today.

What remains open is fidelity, not a known defect: the node compiles against
a dependency set its own CI never exercised. Two ways out, and the choice is
not mine to make:

1. **Align the layer's pins up** to the versions the release line resolves.
   This restores the node's dependency set exactly, and follows the direction
   the absorption already took with `tempfile`. Its cost: the layer would no
   longer run against the versions its F7 evidence was produced on.
2. **Accept the drag** and record it. Its cost: mainnet compiles against a
   dependency set that the release line's own CI never tested, including a
   downgraded `sha2`.

Neither is free, and both are supply-chain decisions over an audited pin set
(D-ORQ-10). They are put here for the coordinator rather than taken.

### One node test is flaky, and the flake pre-dates the injection

`dom-chain`'s `convergence_same_canonical_tip_independent_of_arrival_order`
fails intermittently with `direct connect duplicate output commitment`. It
surfaced during a full workspace run, where it also aborts the remaining test
targets.

`crates/dom-chain` is byte-identical to the release line, but that alone did
not settle it: the section above shows the injection changed what the node
links against, and `proptest` moved four minor versions backwards across the
node's test suites. So the drag was a live candidate cause.

It was measured rather than argued. A `release/mainnetv2` worktree was built
with **its own lockfile** — the pre-injection dependency set — and the same
test run repeatedly on both sides:

| Tree | Passed | Failed | Rate |
| --- | --- | --- | --- |
| `release/mainnetv2`, its own lockfile | 50 | 1 of 51 | ~2.0% |
| This tree, after the injection | 53 | 1 of 54 | ~1.9% |

The release line fails at the same rate. **The flake pre-dates the injection
and the dependency drag did not worsen it.** It remains a real defect in a
node test — the node is immutable here, so it is reported, not fixed — and the
reproduction is: run that test enough times on either tree.

Note what this does *not* retire: the dependency drag above is still open on
its own terms. This measurement clears it of causing this one flake, nothing
more.

---

## 8. The supply-chain gate, and a defect of mine it exposed

`cargo deny check` runs in the node's own `supply-chain` job — all four
checks, advisories included — and `cargo audit` beside it. The layer's licence
policy was merged into the same `deny.toml`, so that job now governs both.

**My merge broke it.** The block I appended carried the tail of the
laboratory's `deny.toml`, which was itself the node's file plus that block —
so `[bans]` and `[sources]` were declared twice. TOML forbids redefining a
table, so `cargo deny check` aborted at the parse and the advisories check did
not run at all. Every local gate stayed green, because cargo-deny is not part
of them. The duplicates were byte-identical to the node's own sections and are
removed; what was genuinely new — `[licenses.private]` and the three named
crate exceptions of A-015/A-016 — remains.

`the_supply_chain_policy_declares_no_table_twice` now fails on any repeated
table header, and a companion test asserts the four denials the node's policy
header names (`yanked`, `unknown-registry`, `unknown-git`,
`required-git-spec = "rev"`) survive the merge. Verified by reintroducing the
duplicate and watching the guard name it, then reverting.

With the file repaired, `cargo-deny 0.20.2` reports:

```
advisories FAILED, bans ok, licenses ok, sources ok
```

`licenses ok` is the layer's policy working — the three exceptions resolve and
the allow-list holds. `bans ok` and `sources ok` mean every git dependency the
layer brought is pinned by exact rev.

### The one advisory, and closing it at the source

The advisory was `webbrowser 1.2.1` (`BROWSER` argument injection), reached
through `egui-winit -> eframe -> dom-wallet-app` — a node crate, a node
dependency. `release/mainnetv2` resolves the same version and, run with its
own lockfile, produced the identical verdict. The supply-chain job was red on
the release line too.

Pre-existing is an origin, not a licence to leave it standing. It was closed
by **upgrading**, which is the only direction permitted here:

`egui-winit` declares `webbrowser = "1.2"`, a range admitting `>=1.2.0,
<2.0.0`, so the fixed 1.2.4 is inside it. `cargo update -p webbrowser
--precise 1.2.4` was enough — no manifest was touched, and in particular
`dom-wallet-app`'s was not edited to force a newer `eframe`. Forcing a version
into the node would have been the dependency drag running the other way.

Four things were proven rather than assumed:

| Claim | Result |
| --- | --- |
| `cargo deny check` | `advisories ok, bans ok, licenses ok, sources ok` (exit 0) |
| The node's 29 crates | `git diff` against `release/mainnetv2` still empty |
| The extended gate, `--no-fail-fast` | 445 suites, 3817 tests, 0 failures; both feature surfaces green |
| `Cargo.lock` delta | `webbrowser 1.2.1 -> 1.2.4`; `core-foundation 0.10.1` leaves the graph (0.9.4, the release line's own, remains). No version moved down. |

`ignore` in `[advisories]` stays empty, and
`the_advisory_ignore_list_holds_only_what_was_proven` now pins it. An entry may
be added only with the ID `cargo deny` reported, a reference to a written
unreachability proof, and an expiry date — never to make a build green, and
never before upgrading has been ruled out. Verified by injecting a clandestine
ID and watching the guard name it, then reverting.

**What the node's own line still needs.** This closed the red in the merged
tree by moving the lockfile, not by changing any node source. The release line
resolves `webbrowser 1.2.1` on its own and remains red until it takes the same
update. That is one command in that repository —
`cargo update -p webbrowser --precise 1.2.4` — and it is the operator's to run
there. Nothing in this layer can reach it.

---

## 9. One barrier added on the operator's decision, and what it does not do

**This is new policy, not the application of an existing rule.** The
`dom-scriptless-store` crate already bars its `evidence-only` surface from
release builds; the operator decided to extend the same rule to `relay`'s
`relay-fault-injection`, and `crates/relay/src/lib.rs` now carries:

```rust
#[cfg(all(feature = "relay-fault-injection", not(debug_assertions)))]
compile_error!("the relay fault-injection surface is forbidden in release builds");
```

The reason is narrow and worth stating exactly: it is a safeguard against a
**build-configuration mistake** in a component third parties compile. It is
not a security fix, and it is not a defect report against the feature — that
feature is correctly gated, off by default, and enabled by nothing in the
tree.

Two layers enforce it, mirroring what the Contracts lineage already did for
the Store. `the_release_barriers_are_present_in_source` proves the barrier is
still WRITTEN, catching a deletion without needing a release build to notice.
`scripts/check-relay-fault-surface.sh` — a sibling of
`check-release-surface.sh`, not an extension of it, since that script pins one
exact diagnostic and the two subjects are independent — proves it FIRES. Both
were verified by deleting the barrier and watching each react.

Three things were proven rather than assumed: release with the feature fails
with the exact diagnostic; release without it compiles clean; and **debug with
the feature still compiles and its thirteen tests still pass**, the four
fault-injection ones among them. The point is to stop an accident, not to
amputate the crate, and a guard that quietly removed the laboratory capability
would be a worse defect than the one it prevents.

**The hole, stated rather than hidden.** `not(debug_assertions)` is an
imperfect approximation of "release": a release profile with debug-assertions
enabled slips past it. The Store lives with the same hole, and consistency
with the existing pattern was chosen over a better discriminator only this
crate would use. So the barrier stops a mistake; it does not stop intent. A
guard whose limitation is written down is a guard. One that presents itself as
airtight is a trap for the next reader.

---

## 10. What this record does not claim

- No gate verdict. `G-F7` and `G-F8` exist only when the operator says so
  in writing.
- The layer's own phase evidence (F0–F6 closures, the F7 laboratory record)
  is carried in `docs/interop/` as history. It was produced elsewhere and is
  not re-established by this injection.
- Refunds (RTE7/RTE8) remain `NOT_EXECUTED`, exactly as the F7 record left
  them.
