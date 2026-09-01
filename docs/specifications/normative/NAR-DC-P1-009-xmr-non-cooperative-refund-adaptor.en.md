# NAR-DC-P1-009 — Non-Cooperative XMR Refund: Adaptor Symmetry

Status: **PROPOSED / UNSIGNED / NOT NORMATIVE**

Date: 2026-09-01

Project: DOM Interop / Kaystra counterparty legs

Scope: the refund-side cross-curve secret and its role tag; the concrete
non-cooperative refund executor; and the refund adaptor round in the DOM
scriptless core that makes a DOM refund reveal its witness.

This record does not approve production, mainnet, real funds, a release, or an
external security audit. It assigns normative meaning only.

## 1. Authority and ratification effect

This record supplements `NAR-DC-P1-008-monero-counterparty-leg-mechanism-and-chain-kind.en.md`
(SHA-256 `01d45f67f2955f3da3c8fa9181b1aff9f4e159fd18be0426c9386bf84952dd56`)
and the seven signed records it in turn supplements.

The detached signature must verify with the established project operator
Minisign public key:

```text
RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
key ID 74197A95CA309CF0
```

Unsigned bytes grant no authority. The implementation described here is present
in the tree and reaches nothing on its own: no route is admitted for production
until an operator supplies this executor to `admit_refund_policy`, and §4
records what remains missing regardless.

## 2. Problem closed

The claim path alone is not an atomic swap.

In a DOM→XMR route the Monero funder places funds in an output whose spend key
is the sum of two shares: the one they hold, and the one the counterparty proves
— through the cross-curve DLEQ — to be the same witness as the DOM adaptor
point. When the counterparty claims the DOM leg they expose that witness on the
DOM chain; the funder combines it with their own share and sweeps.
`xmr-kaystra-bridge` implements exactly that.

If the counterparty never claims, the funder is stuck. The Monero sits in a
shared output they cannot open alone, and no Monero-side timelock helps: Monero
has no script that could enforce one. The funds are recoverable only if the
other share also becomes learnable.

Frozen Kaystra V1 had no mechanism for that, and V7 shipped the refund policy as
an interface with no executor, so every production route failed closed. That is
correct behaviour and not a solution.

## 3. Decision

### 3.1 A second role tag

`ROLE_XMR_REFUND_SHARE = 2` is ratified in `xmr-dleq-sigma`, beside the existing
`ROLE_XMR_SHARED_SPEND = 1`.

The claim path and the refund path each carry their own 252-bit cross-curve
secret, and each proof is bound to its own role. A proof minted for one path
does not verify for the other, so a counterparty cannot present the refund
witness where the claim witness is expected, or the reverse.

Evidence: `a_refund_proof_verifies_only_under_the_refund_role`.

### 3.2 The symmetry

```text
  claim  path :  DOM claim  reveals  t   (ROLE_XMR_SHARED_SPEND)
  refund path :  DOM refund reveals  u   (ROLE_XMR_REFUND_SHARE)
```

With both paths adaptor-bound, exactly one completes, and either completion
teaches the waiting party the share they lacked:

- the counterparty claims DOM → the funder learns `t` → the funder sweeps;
- the funder refunds DOM after the deadline → the counterparty learns `u` → the
  counterparty sweeps the Monero back.

Neither party can take both legs, and neither can strand the other.

### 3.3 The concrete executor

`crates/adapters/xmr-refund-adaptor` supplies `XmrRefundSecret`, the refund-side
verification entry point, and `DomRefundAdaptorExecutor`, which implements
`NonCooperativeRefundCapability`.

The executor is bound to one settlement's refund proof. Its
`executor_profile_hash` commits to the crate's domain separator and to the exact
refund point, so two settlements never share an executor identity, and an
artifact cannot be satisfied by an executor bound to a different route.
`validate_artifact` admits an artifact only when its refund point is exactly the
point this executor holds the witness relationship for.

Evidence: `the_executor_admits_only_its_own_refund_point`,
`two_settlements_never_share_an_executor_identity`,
`a_scalar_that_is_not_the_refund_witness_is_refused`.

## 4. The DOM refund now reveals

When this record was first drafted, §4 recorded that the construction in §3 was
complete on the Monero side and inert on the DOM side: `dom-scriptless-crypto`
had `claim_adaptor_round` and no refund equivalent, so the DOM refund was
timelock-only and exposed nothing.

That gap is closed. The refund adaptor round is implemented.

### 4.1 The purpose tag

`PurposeV1::RefundAdaptor = 0x05` is ratified in `dom-adaptor`, beside
`Refund = 0x01`, `ClaimAdaptor = 0x02`, `Funding = 0x03` and `Sponsor = 0x04`.

It is deliberately **not** `Refund`. A plain refund is the timelock path and
reveals nothing; sharing a purpose byte would let one binding transcript stand
for both, and a caller could then present a plain refund where an adaptor-bound
one was required. `begin_refund_adaptor_round_v1` refuses `PurposeV1::Refund`
by name.

The purpose is inside the pinned binding transcript, so a refund round and a
claim round over otherwise identical inputs derive different binding factors,
and a partial signature produced for one does not satisfy the other.

The decoder registry stays closed: `PurposeV1::try_from` refuses every byte
outside `0x01..=0x05`, and `closed_registries_reject_unknown_values` enumerates
all 256 values to hold that.

### 4.2 The round

`crates/dom-scriptless-crypto/src/refund_adaptor_round.rs` composes the same
pinned primitives as the claim round, under the refund purpose and over the
refund adaptor point `U`:

```text
R_i = R1_i + R2_i · b     dom_scriptless_primitives::scriptless_bind_public_nonces
R   = Σ R_i               dom_adaptor::aggregate_public_nonces_v1
R̂   = R + U               dom_adaptor::aggregate_public_nonces_v1([R, U])
```

`complete_cycle_v1` pre-signs, verifies through the pinned verifier, adapts,
verifies the finalized signature natively, extracts, and requires `u·G == U`.
It returns the revealed witness, because that value is public the moment the
refund is published — withholding it would not make it secret, only harder for
the honest counterparty to act on.

Evidence: `a_completed_refund_reveals_the_refund_witness` and
`the_complete_cycle_closes_on_the_adaptor_point`.

### 4.3 Distinct nonces across the two rounds

This is the sharpest requirement, and it is a property of Schnorr rather than a
policy choice: two signatures over the same nonce with different challenges
expose the signing key by subtraction. The claim round and the refund round are
exactly that pair, so a participant that reuses a nonce pair across them leaks
its share.

`RefundAdaptorRoundV1::require_nonces_distinct_from_claim` refuses a roster that
reuses any published nonce from the claim round, and refuses a refund point
equal to the claim point — which would collapse the two legs into one.

The module cannot see the claim round on its own, so the caller must present it
whenever both rounds exist for one settlement. That duty is stated in the
module documentation rather than left implicit.

Evidence: `nonces_reused_from_the_claim_round_are_refused`,
`distinct_nonces_across_the_two_rounds_are_accepted`,
`a_refund_point_equal_to_the_claim_point_is_refused`.

### 4.4 Under the same guard as the claim round

`scripts/check-refund-adaptor-two-nonce.sh` holds the refund round to the
discipline `check-adaptor-two-nonce.sh` holds the claim round to: every frozen
step reached through its pinned function by name, the measured relation
`R̂ = R + U` frozen by a known-answer test, one construction site for the cycle
evidence, no public function accepting nonce or share material, no funding or
broadcast, no unsafe code, and a recorded deterministic sweep of 10,000
sessions. Both guards pass.

### 4.5 The actuator capability

`dom-actuator` maps `PurposeV1::RefundAdaptor` to `DomActionV1::PresignRefund`,
the same capability a plain refund carries.

This is a derivation, not a new grant. `PresignRefund` authorizes "produce this
participant's refund signing artifacts", and a refund adaptor round produces
exactly those: the same refund transaction, the same beneficiary, the same
artifacts. What differs is that the signature is adaptor-bound and therefore
reveals a witness — one the participant itself chose to commit, which grants no
additional authority over funds and so needs no additional capability.

The session store reaches the same conclusion independently: the refund adaptor
signs under `SessionPhaseV1::RefundSigning`, from the `TemplatesCommitted`
predecessor, against the refund template — the plain refund's phases, because
it is the plain refund's transaction. Only the finalization differs, and there
it groups with `ClaimAdaptor`, because both complete by adaptation rather than
plain finalization.

Evidence: `the_refund_adaptor_purpose_maps_to_the_refund_signing_capability`,
which also holds that the claim capability stays separate and that `Sponsor`
stays unauthorized.

## 5. What this record does not decide

- **The independent cryptographic audit.** Two constructions now need it: the
  cross-curve DLEQ used across two roles, and the refund adaptor round itself.
  The refund round composes only pinned primitives and is held by the same
  guard as the claim round, but composition is not proof, and no third party
  has reviewed either.
- **Proof of possession.** The refund round inherits the claim round's stated
  boundary: participant signing keys are accepted as published points and
  aggregated by plain sum, which is safe only once each participant has proved
  possession of its share. The pinned revision owns that proof and neither
  round verifies it. It remains a required composition step that is still owed.
- **A live run.** No refund adaptor round has been exercised against a live
  chain, and no Monero sweep has been broadcast.
- **Monero mainnet**, which remains unrepresentable in `MoneroNetworkV1`.
