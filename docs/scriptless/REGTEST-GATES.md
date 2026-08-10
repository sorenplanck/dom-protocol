# Regtest Exit Gates (G2–G5) — Runbook

Date: 2026-08-10

Each exit gate in `DOM-Scriptless-Cronograma-Implementacao-v1.md` has two halves:

- **Node-independent invariants** — pure logic. These run today in
  `crates/dom-adaptor/tests/scriptless_gate_readiness.rs`:

  ```sh
  cargo test -p dom-adaptor --test scriptless_gate_readiness
  ```

  Four tests, one per gate, all passing. They assert the foundation each gate's
  demonstration stands on: the 872-byte wire arithmetic and the no-isolated-spend
  gate (G2), abort-always-available and resume (G3), the funding order and
  bilateral backup (G4), and the byte-verified adaptor extraction and claim floor
  (G5).

- **Regtest demonstration** — needs a running node and two wallets. This
  document is the step list for that half. A gate is closed only when both halves
  pass on the final commit.

The existing two-node harness in `crates/dom-integration-tests` (see
`tests/ibd_two_node.rs` and `src/helpers.rs`) is the starting point: it already
builds `DomNode` instances on local ports, performs the Noise handshake, mines,
and converges. The scriptless demonstrations extend that harness.

## Prerequisite: the public scriptless driver

The regtest demonstrations need one piece that is not yet built: a public
two-wallet driver that runs the collaborative Bulletproof and the contract
choreography end to end. Today the collaborative BP runs internally
(`bulletproof_mpc.rs`, `pub(crate)`, verified by the real DOM verifier), and the
contract session, funding authority, and deadline policy are public. The driver
that threads them — round-1 admission gated by the partial-commitment proof,
then the funding-order and backup gates, then transaction assembly — is the
pending 2.2 orchestration work. Build it first; the gate tests below call it.

## G2 — shared output accepted by consensus, 872 bytes on the wire

1. Two wallets run the collaborative Bulletproof to a 739-byte proof. Gate
   round-1 admission with `verify_all_partial_commitments_v1`, so a commitment
   share without a valid opening proof is rejected before the output is built.
2. Assemble the `TransactionOutput` with the shared commitment, the 739-byte
   proof, and the 96-byte decoy capsule (`combine_decoy_capsule_v1`).
3. Submit it to a regtest node. Assert consensus accepts it, and its serialized
   size is exactly **872 bytes** (33 commitment + 4 length prefix + 739 proof +
   96 capsule).
4. Assert neither wallet alone can produce a spending signature for the output.
5. Confirm `HugePages`/perf shows no regression against a baseline output.

## G3 — interruption at every protocol step

1. Drive the full choreography on a node, persisting the contract state
   (`ContractStateV1`) at each transition through the Contracts store's atomic
   write (the pending 3.3 persistence).
2. Using the store's process-death harness (the same pattern as the store's
   existing crash matrix), kill the process immediately before and after each
   durable write.
3. On restart, call `ContractStateV1::resume` from the last durable checkpoint.
   Assert the contract either continues correctly or aborts releasing reserves.
   No cut may leave a lost-funds or wedged-input state.

## G4 — simulated abandonment; nobody loses funds or refund unlocks first try

1. Enforce the inviolable order with `FundingAuthorizationV1`: build the funding
   unsigned; co-sign the refund spending the shared output with
   `KERNEL_FEAT_HEIGHT_LOCKED` and `lock_height = H_refund` (from
   `RefundDeadlinePolicyV1::refund_lock_height`); only then sign and publish the
   funding. Gate funding on the bilateral backup
   (`verify_bilateral_backup_v1`).
2. Abandon the session at every step. Assert no funds are lost at any cut.
3. Mine to `H_refund`. Assert the refund is accepted first try — reproducing the
   O-03 result over the shared output.
4. Exercise the escalating-fee refund ladder (pending 4.3) under the node's real
   relay policy: confirm a higher-fee refund relays when a lower-fee one has aged
   below the relay minimum.

## G5 — full two-terminal cycle plus a near-deadline claim

1. **Happy path**: pre-sign the claim shifted by `T`; publish it on the node;
   extract `t` from the kernel and assert `t*G == T` byte for byte (the
   readiness test proves the closed cycle; here it runs against a published
   kernel).
2. **Refund path**: in a second run, take the timeout refund without revealing
   `t`; assert no `t` is extractable.
3. **Adversarial near-deadline claim**: attempt to publish a claim inside the
   unsafe window and assert `RefundDeadlinePolicyV1::claim_is_safe` rejects it,
   and that the counterparty's refund wins the race when the claim floor is
   violated.
4. Record the Dandelion++ stem-phase timing analysis for the `t` reveal (this
   is analysis, not a pass/fail assertion; the claim-floor margin is the code
   part and is already enforced).

## Where the gate tests live

- Node-independent halves: `crates/dom-adaptor/tests/scriptless_gate_readiness.rs`.
- Regtest halves: add to `crates/dom-integration-tests/tests/` (e.g.
  `scriptless_g2.rs` … `scriptless_g5.rs`), reusing `helpers::*` and the
  two-node pattern, once the public driver exists. Mark them `#[ignore]` until
  the node fixture is present so the workspace suite stays green without a node.

```text
G2_NODE_DEMO = PENDING_DRIVER_AND_NODE
G3_NODE_DEMO = PENDING_STORE_AND_NODE
G4_NODE_DEMO = PENDING_DRIVER_AND_NODE
G5_NODE_DEMO = PENDING_DRIVER_AND_NODE
READINESS_TESTS = PASSING
```
