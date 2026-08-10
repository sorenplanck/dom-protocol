# Driver Blocker — Partial-Commitment PoK vs Pedersen Commitment Shares

Date: 2026-08-10
Status: **RESOLVED by the master specification — see "Resolution from the source"**

## Resolution from the source

The master specification `DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0.docx`
settles this. The blinding proof of knowledge lives at the **session layer over
the pure point `R_i = r_i*G`**, not over the Bulletproof statement's commitment
shares, so the mismatch below never arises in the flow the spec defines.

- **§4.2 "Share de blinding"**: *"Cada participante escolhe r_i e publica
  R_i = r_i·G. Para impedir contribuição sem conhecimento e ataques de ponto
  malformado, envia PoK Schnorr"*, with context
  `chain_id || session_id || participant_id || role || participant_index || R_i
  || terms_hash || capsule_hash` under the tag `DOM:scriptless-share-pop:v1`.
  This is exactly what `share_pop.rs` implements (same tag, same fields, with
  `recovery_binding_hash` carrying `capsule_hash`). Line 375 of the spec names it
  literally: *"Proof of knowledge do share de blinding/chave."*
- **§4.3 "Commitment agregado"**: *"Depois de validar todas as PoKs:
  R_total = Σ R_i; C = vH + R_total"*, rejecting `R_total` or `C` at infinity.
- **§1.2**: *"Cada participante conhece r_i, mas ninguém precisa conhecer r ...
  O blinding agregado nunca é reconstruído."* So `C` is computed by point
  addition, never by summing the scalars.
- **§5.1 / §5.2**: the Bulletproof statement is a **separate backend layer**
  (`values = [v, MAX-v]`, `blinds_i = [r_i, -r_i]`). Its commitment-share
  representation is internal to the range-proof backend and is not the object
  the §4.2 PoK proves.

Consequently the driver's admission gate is `share_pop` over `R_i` (§4.2),
followed by `C = vH + Σ R_i` (§4.3). The `partial_commitment_pop` module remains
a correct standalone discrete-log PoK but is **not** the §4.2 primitive and is
not required by the driver. The original finding below rested on the wrong
assumption that the PoK must bind the Bulletproof statement's Pedersen share; the
spec places it one layer up, over `R_i`.

## Original finding (superseded, kept for the audit trail)

Building the public two-wallet collaborative-output driver surfaced a
correctness mismatch between two components that were built separately.

- The collaborative Bulletproof statement (`BpStatementV1`) records each
  participant's commitment share as a **Pedersen commitment**:

  ```text
  C_j = v_j * H + r_j * G
  ```

  where the value distribution is a convention — the index-0 participant carries
  the whole value `v`, the others carry `0` — and `value_noms` is stored once,
  not per participant. See `BpLocalBlindingV1::commitment_share`, which computes
  `Commitment::commit(value_share, blind)`.

- The Phase 2.4 partial-commitment proof (`PartialCommitmentProofV1`,
  `partial_commitment_pop.rs`) proves knowledge of `r_j` behind a **plain
  discrete-log point**:

  ```text
  P_j = r_j * G
  ```

  via `PartialBlindingV1::commitment_share`, which is `secret_scalar_public_key`.

For a value-zero participant `C_j = r_j * G`, so the proof matches. For the
value-carrying participant `C_j = v * H + r_j * G != r_j * G`, so the proof is
over the wrong point. Wiring the 2.4 gate into round-1 admission as-is would
therefore assert a proof of knowledge of a point that is not the statement's
commitment share — a cryptographically wrong check in a security-critical path.

## Why the driver stopped here

The public collaborative-output driver's whole purpose is to enforce, at round-1
admission, that every party knows the opening of its commitment share before the
shared output is built (the joint-blinding + rogue-key defense). If the
enforced proof is over the wrong point, the driver would ship a subtly broken
gate. It was not built on that foundation.

## Correct resolution (bounded, testable)

Prove knowledge of `r_j` behind the **Pedersen residual**, not behind
`r_j * G`:

```text
residual_j = C_j - v_j * H
           = r_j * G
```

The verifier is given the public value share `v_j`, computes `v_j * H`,
subtracts it from the statement's commitment share, and runs the existing
Schnorr PoK over `residual_j`. The prover already holds `r_j` and produces the
same proof over `residual_j`.

The point arithmetic is available with **existing public helpers** — no
`dom_crypto` surface change is needed:

- `Commitment::sub` (public) computes `C_j - X`.
- `v_j * H` is `Commitment::commit(v_j, b).sub(Commitment::commit(0, b))` for any
  blinding `b`, i.e. `(v_j*H + b*G) - (b*G) = v_j*H`, avoiding any question about
  a zero blinding.

So the code change to `partial_commitment_pop.rs` is bounded:

1. `prove_partial_commitment_v1` / `verify_partial_commitment_v1` take the public
   `value_share: u64` for the participant.
2. Both bind `residual = C_j - v_j*H` and run the Schnorr relation over it.
3. Extend the tests: a value-carrying participant (`v != 0`) must verify against
   its Pedersen commitment share — the case that is currently broken — and a
   wrong `r_j` or wrong `v_j` must fail closed.

## The open question that must be settled first

The fix hinges on **where each participant's value share `v_j` comes from**, and
that is a protocol convention, not settled code:

- `BpStatementV1` stores one `value_noms`, not a per-participant value vector.
- The only evidence of the distribution is a **test helper** in
  `bulletproof_mpc.rs` (`collaborative_proof`), which assigns the whole value to
  index 0 and `0` to the rest. That is an inference from a test, not a rule read
  from the normative specification.

Encoding the wrong value-distribution convention would introduce a different
security bug. Before making this security-critical change, the convention must
be confirmed from the normative source (the omnibus closure / NAR records) or
the coordinator: does index 0 always carry the full value, is it role-derived,
or is a per-participant value vector required in the statement? Only then is the
residual correction unambiguous, and only then can the public driver be built on
top of it.

This blocker is why the driver was not built in one pass: the wiring looked
mechanical but rests on a protocol convention that is not yet confirmed, and a
guess in this path is a guess in a security-critical gate.

## What is NOT affected

- The standalone Phase 2.4 tests remain correct **as a discrete-log PoK** — they
  never claimed to bind a Pedersen commitment; they proved knowledge of `r`
  behind `r*G`, which is exactly what they test.
- The joint-blinding enforcement gate `verify_all_partial_commitments_v1` is
  correct **for discrete-log shares**; it inherits this residual correction
  automatically once the underlying prove/verify bind the residual.
- Every other component (decoy, contract session, funding authority, deadline
  and claim-floor policy, the G1 property and fuzz work) is independent of this
  and unaffected.

## Machine-readable status

```text
COLLABORATIVE_OUTPUT_DRIVER = BLOCKED_ON_POK_RESIDUAL_CORRECTION
POK_2_4_AS_DISCRETE_LOG = CORRECT
POK_2_4_FOR_PEDERSEN_SHARES = REQUIRES_RESIDUAL_BINDING
RESOLUTION_ARITHMETIC = COMMITMENT_SUB_EXISTS_NO_CRYPTO_SURFACE_CHANGE
RESOLUTION_BLOCKER = VALUE_DISTRIBUTION_CONVENTION_UNCONFIRMED
DECISION_NEEDED = CONFIRM_PER_PARTICIPANT_VALUE_SHARE_RULE
```
