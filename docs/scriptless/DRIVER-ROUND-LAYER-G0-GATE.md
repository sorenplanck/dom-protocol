# Driver Round Layer — Spec-Gated Until G0

Date: 2026-08-10
Status: **BLOCKED by the master specification §5 until Gate G0**

## Decision from the source

The collaborative-output driver has two halves. The session layer (§4.2/§4.3,
`collaborative_output.rs`) is done. The **round layer** — the collaborative
Bulletproof rounds (§5.4) wired into the real output path so a consensus-valid
shared output can be built and published — is explicitly gated by the master
specification `DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0`, §5:

> **"BLOQUEADO ATÉ G0.** O resultado temporário confirma viabilidade
> criptográfica, mas sua **integração permanente só começa depois** que o mesmo
> commit-base provar o **envio comum 1→1 completo de §15.7**. A Bulletproof
> colaborativa não pode mascarar um builder/slate/scanner basal que nunca foi
> exercitado ponta a ponta."

So:

- The **temporary result** (the tested 739-byte collaborative proof already in
  `bulletproof_mpc.rs`) is permitted as cryptographic-viability confirmation, and
  it exists.
- The **permanent integration** — exposing the round driver as the real
  output-building path — **only begins after G0**: the full common 1→1 DOM send
  proven end to end on the same base commit (§15.7). G0 has never executed; it
  needs a running node.

Building the round-layer integration now would violate this explicit gate.
Therefore the driver is finished as far as the specification permits before G0.

## Why this also surfaced a concrete integration defect

Tracing the round layer against consensus surfaced the exact reason §5's gate
matters: the collaborative proof, as the MPC currently builds it, would **not**
verify under consensus for a real shared output. This is the concrete work the
post-G0 integration must resolve.

- **Consensus** verifies an output's range proof with the recovery capsule as
  `extra_commit`, passing the **raw capsule bytes** (96 bytes):
  `crates/dom-consensus/src/transaction.rs:620`,
  `range_proof_verify_with_extra_commit(commitment, proof, capsule.as_bytes())`.
- **Single-party** (consensus-accepted) builds the proof the same way:
  `bp_prove_with_extra_commit(value, blinding, extra_commit: &[u8])` with the raw
  capsule bytes (`crates/dom-tx/src/lib.rs`).
- **Collaborative MPC** binds a **fixed 32-byte** `extra_commit`:
  `bulletproof_mpc_round1(..., extra_commit: [u8; 32])`
  (`crates/dom-crypto/src/bulletproof_bp.rs:808`), threaded through round 2 and
  finalize via `BulletproofMpcRound1State.extra_commit` (32 bytes) and its FFI
  calls (`extra_commit.as_ptr(), extra_commit.len()`, always 32).

A 32-byte `extra_commit` cannot equal the raw 96-byte capsule, so a
collaborative proof built this way fails the consensus range-proof check for a
shared output that carries a capsule. §5.2 confirms the intent: *"recovery_binding_hash
é o hash dos bytes exatos passados como extra_commit"* — the value passed to the
proof is the exact (raw) extra_commit bytes, and `recovery_binding_hash` is their
hash for transcript binding. §1.3's structural indistinguishability requirement
also forces the collaborative proof to use the same `extra_commit` as
single-party (the raw capsule), or the two proofs are bound to different
transcripts.

## The bounded fix, for the post-G0 integration

1. `bulletproof_mpc_round1`'s `extra_commit` becomes `&[u8]`, and
   `BulletproofMpcRound1State.extra_commit` becomes owned variable-length bytes,
   threaded unchanged through round 2 and finalize. The FFI already takes
   `ptr + len`, so no FFI-signature change is needed.
2. The round driver passes the **raw decoy-capsule bytes** (96) as
   `extra_commit`; the statement's `recovery_binding_hash` stays
   `hash(extra_commit)` (§5.2).
3. Verification is testable **without a node**: `range_proof_verify_with_extra_commit`
   is the exact call consensus makes, so a test building the collaborative proof
   with the 96-byte capsule and verifying it with the same 96 bytes proves the
   range-proof half of consensus acceptance. The signature/balance half is
   node-side.

This is bounded and node-independent to verify, but it is precisely the
"integração permanente" §5 blocks until G0, and it touches the sealed
Bulletproof FFI wrapper and the frozen 739-byte evidence. It is therefore left
for the post-G0 integration, not done here.

## Status

```text
DRIVER_SESSION_LAYER = DONE_SPEC_4_2_4_3
DRIVER_ROUND_LAYER_INTEGRATION = BLOCKED_BY_SPEC_5_UNTIL_G0
G0 = NEVER_EXECUTED_NEEDS_NODE (DC-P1-G017 / §15.7)
MPC_EXTRA_COMMIT_WIDTH = 32_BYTES_MUST_BECOME_RAW_CAPSULE_FOR_CONSENSUS
FIX_VERIFIABLE_WITHOUT_NODE = YES_VIA_RANGE_PROOF_VERIFY_WITH_EXTRA_COMMIT
PRODUCTION = NOT_AUTHORIZED
MAINNET = DISABLED
REAL_FUNDS = PROHIBITED
```
