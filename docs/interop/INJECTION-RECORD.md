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

The twenty-nine crates of the node are byte for byte the release line:

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

It prints nothing. Outside `crates/`, the only pre-existing files that
changed at all are `Cargo.toml` and `deny.toml`, and both changed by
addition only — `git diff release/mainnetv2 -- Cargo.toml deny.toml | grep
'^-[^-]'` is empty.

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

## 4. What is blocked, and why nothing was weakened to hide it

`f7-runner` — the laboratory runtime — is in the tree but out of the
workspace build, with the reason written in `Cargo.toml`.

It is the only crate that enables `dom-leg/f7-wallet-compositor`, and
nothing depends on it. That feature pulls Wallet V3 at
`dom-wallet-v3 @ 512def5`, which was built against the F7 node lineage and
expects scanner surfaces the release line does not publish:
`ScanTransaction`, `TransactionLocation`, and a `CoinbaseScanMetadata`
carrying `kernel_features`, `kernel_excess_signature`, `offset` and
`output_proof_envelope`.

Two ways existed to make it compile, and both were refused: growing those
types on the node breaks the rule, and stubbing them in the wallet would
fake a scanner. It builds the day `dom-wallet-v3` publishes a revision
against the release line.

Related: the Wallet V3 pin resolves the DOM through a git revision of this
same repository, which placed a **second, older node** in the graph — its
`TransactionInput` is a different type from ours. All twenty-one node
packages it reaches are patched onto the local tree, so there is one DOM
and it is mainnet.

---

## 5. Two pins moved, both upward, both dev-only

`tempfile` in `f3-harness` and `f7-runner` was `=3.23.0` while the absorbed
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
workspace member. `f7-runner`'s two frozen commits are evidence of what the
twenty settled routes ran against; they are labelled as evidence and
deliberately not repointed, because repointing them would restate what the
evidence was made on.

### A crate outside the workspace is a crate no gate covers

`f7-runner` is excluded for a reason written in `Cargo.toml`, and the reason
holds. The risk is not that entry but the next one, added quietly to make a
build pass. `the_workspace_excludes_exactly_the_crates_it_is_allowed_to` pins
the list — both entries, each with its reason — and fails on any change, so
growing it takes a diff a reviewer sees. Verified by adding a clandestine
exclusion and watching the guard fail.

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

No package was dropped, and 85 are new. But `sha2` is the node's hashing
dependency and it moved **backwards**.

Section 1's `git diff` is still true and still empty. That is exactly the
limit worth naming: **byte-identical source does not mean the node builds the
same artifact as the release line does.** It does not, today.

Two ways out, and the choice is not mine to make:

1. **Align the layer's pins up** to the versions the release line resolves.
   This restores the node's dependency set exactly, and follows the direction
   the absorption already took with `tempfile`. Its cost: the layer would no
   longer run against the versions its F7 evidence was produced on.
2. **Accept the drag** and record it. Its cost: mainnet compiles against a
   dependency set that the release line's own CI never tested, including a
   downgraded `sha2`.

Neither is free, and both are supply-chain decisions over an audited pin set
(D-ORQ-10). They are put here for the coordinator rather than taken.

### One node test is flaky, and its cause is not yet established

`dom-chain`'s `convergence_same_canonical_tip_independent_of_arrival_order`
fails roughly one run in four, with `direct connect duplicate output
commitment`. Measured: three passes and one failure in four consecutive runs.

`crates/dom-chain` is byte-identical to the release line, so the injection did
not change its source. What the injection **did** change is what it links
against, per the section above — `proptest` alone moved four minor versions
backwards across the node's test suites. That makes the drag a candidate
cause that has not been excluded, and the honest statement is that this flake
has not been shown to pre-date the injection. Establishing it requires running
the same test on `release/mainnetv2` with its own lockfile, which this record
does not yet contain.

---

## 8. What this record does not claim

- No gate verdict. `G-F7` and `G-F8` exist only when the operator says so
  in writing.
- The layer's own phase evidence (F0–F6 closures, the F7 laboratory record)
  is carried in `docs/interop/` as history. It was produced elsewhere and is
  not re-established by this injection.
- Refunds (RTE7/RTE8) remain `NOT_EXECUTED`, exactly as the F7 record left
  them.
