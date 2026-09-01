# DOM↔XMR — handoff for the auditor and the operator's VPS

Two things this project cannot do for itself are an *independent* cryptographic
audit and a live Monero run. This document is what each of them needs, so
neither has to reconstruct the context.

Base: `sorenplanck/dom-protocol`, branch `mainnetswap`.

---

## Part 1 — For the independent cryptographic auditor

### 1.1 What to audit, and why it matters

The atomicity of a DOM↔XMR swap rests on one claim: that a single 252-bit
witness has a secp256k1 point (used as the DOM adaptor point) and an ed25519
scalar (used as a Monero spend share), and that a proof ties them together
without leaking the witness. If that claim is wrong, the two legs are not
bound, and one party can take both.

The construction is the cross-curve DLEQ from `sigma_fun`. This project did not
invent it. What has *not* been reviewed by a third party is this project's
**use** of it.

### 1.2 The exact surface

| Item | Location |
|---|---|
| DLEQ wrapper, proof/verify, role binding | `crates/adapters/xmr-dleq-sigma/src/lib.rs` |
| Claim-side secret | `crates/adapters/xmr-route-secret/src/lib.rs` |
| Refund-side secret and executor | `crates/adapters/xmr-refund-adaptor/src/lib.rs` |
| Public claim wire codec (65 bytes, fixed width) | `xmr-dleq-sigma`, `CrossCurvePublicClaim` |
| One-shot claim registry | `crates/adapters/xmr-dleq-nullifier-store/src/lib.rs` |

### 1.3 The specific questions

1. **The 252-bit domain.** secp256k1's order is ≈2²⁵⁶ and ed25519's is ≈2²⁵².
   The code confines the witness to a shared 252-bit domain rather than
   reducing an arbitrary secp scalar modulo the ed order, which would be
   unsound. Is the domain construction correct, and is the rejection of
   out-of-domain witnesses complete? A guard already refuses
   `from_bytes_mod_order` appearing in this crate.
2. **Two roles, one construction.** `ROLE_XMR_SHARED_SPEND = 1` and
   `ROLE_XMR_REFUND_SHARE = 2` bind otherwise-identical proofs to the claim and
   refund paths. Does the role tag enter the challenge in a way that genuinely
   separates the two, so a proof for one path cannot be replayed as the other?
3. **Settlement and context binding.** Proofs are bound to a settlement id and
   a context hash. Is that binding sound against a counterparty who has seen
   proofs from other settlements?
4. **Nullifier scope.** The registry refuses reuse of a public claim across
   settlements. Is the identity it keys on the right one?
5. **The wire codec.** `CrossCurvePublicClaim` serializes as exactly
   `secp_compressed || ed_compressed`, 65 bytes, refusing any other length,
   because a consensus-sensitive identity must not depend on a serializer's
   array representation. Is anything else in the envelope malleable?

### 1.4 What is deliberately out of scope

The refund construction is **specified but not active**: `NAR-DC-P1-009` §4
records that the DOM refund path is timelock-only and reveals nothing, so the
refund executor cannot yet perform a recovery. An auditor should read that
section before assuming the refund path is live.

---

## Part 2 — For the operator's VPS (live stagenet run)

### 2.1 Why this cannot be done here

The container that built this has no reachable Monero node: the outbound proxy
blocks the Monero RPC ports (38081/38089 return 403 or reset). Every XMR test
in this tree runs against mocks. **No sweep has ever been broadcast.**

### 2.2 What to stand up

1. **A Monero stagenet daemon.** `monerod --stagenet`, fully synced. The
   registry pins the genesis, so a wrong network fails closed rather than
   settling on the wrong chain:

   | Network | Ratified genesis |
   |---|---|
   | Stagenet | `76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb` |
   | Testnet | `48ca7cd3c8de5b6a4d53d2861fbdaedca141553559f9be9520068053cda8430b` |

   These are derived, not transcribed — `deployment-registry` recomputes them
   from the upstream genesis transaction in a test. Confirm your node agrees:

   ```bash
   curl -s http://127.0.0.1:38081/json_rpc -d \
     '{"jsonrpc":"2.0","id":"0","method":"get_block_header_by_height","params":{"height":0}}' \
     | jq -r .result.block_header.hash
   ```

2. **The GPL sidecar**, built from `external-gpl/dom-xmr-sidecar` into the
   pinned Eigenwallet workspace (`scripts/install-sidecar-into-eigenwallet.py`).
   It runs as its own process, under its own licence, reachable only over an
   authenticated Unix socket.

3. **The runtime**, wired through `xmr-runtime-wiring::attach_xmr_consumer`.

### 2.3 What to run, in order

```bash
bash scripts/xmr-v6/run-v6-gates.sh      # or the xmr-v7 workflow
cargo test -p f8-xmr-kaystra-e2e         # end-to-end against mocks
```

Then, on stagenet, the first real exercise:

1. fund a shared output through the sidecar;
2. observe funding reach the confirmation target through the RPC quorum;
3. drive a DOM claim so the witness is revealed;
4. confirm the bridge builds **one** sweep, persists the exact bytes, and
   broadcasts them;
5. kill the process between persistence and broadcast, restart, and confirm the
   retry re-submits **the same bytes** and does not re-sign.

Step 5 is the one that matters most: it is the property the delivery journal
exists for, and it has only ever been tested in memory.

### 2.4 What will refuse, and correctly

- **Any production route**, until an operator supplies a
  `NonCooperativeRefundCapability` — and, beyond that, until the DOM refund path
  actually reveals (`NAR-DC-P1-009` §4). `attach_xmr_consumer` returns
  `RefundNotProductionCapable` for a laboratory-only policy.
- **Monero mainnet**, which is absent from `MoneroNetworkV1` by construction.

### 2.5 Two signatures outstanding

| Record | SHA-256 |
|---|---|
| `NAR-DC-P1-008` — mechanism and chain kind | `01d45f67f2955f3da3c8fa9181b1aff9f4e159fd18be0426c9386bf84952dd56` |
| `NAR-DC-P1-009` — refund adaptor symmetry | `9d30c7cbe39dbd78cc1474596c3387e6c9de4d5f692a77e13440b9834fa62615` |

Unsigned bytes grant no authority. Neither record authorizes mainnet.
