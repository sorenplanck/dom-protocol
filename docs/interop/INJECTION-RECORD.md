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

## 6. What this record does not claim

- No gate verdict. `G-F7` and `G-F8` exist only when the operator says so
  in writing.
- The layer's own phase evidence (F0–F6 closures, the F7 laboratory record)
  is carried in `docs/interop/` as history. It was produced elsewhere and is
  not re-established by this injection.
- Refunds (RTE7/RTE8) remain `NOT_EXECUTED`, exactly as the F7 record left
  them.
