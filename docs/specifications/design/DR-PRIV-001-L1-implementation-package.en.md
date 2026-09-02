# Level 1 — Per-Leg Witness Blinding: Definitive Implementation Package

## Route unlinkability against external observers, 2024-baseline edition

Status: **IMPLEMENTATION SPECIFICATION / HANDOFF DOCUMENT / NOT NORMATIVE UNTIL RATIFIED**

Date: 2026-09-02

Audience: the implementing agent. This document is **self-contained**: it
carries the complete construction, the complete reference code, the exact
integration map into the `dom-protocol` tree, the full test plan, and the
ratification checklist. Nothing else is required reading; the pinned
records below are the authority trail, not prerequisites.

Authority trail (pins):

```text
NAR-DC-P1-011  — the ratification vehicle for this work (per-leg witness
                 blinding). This package implements exactly its §3.
DR-PRIV-001    — the design record (Part I = Level 1).
DR-PRIV-001-S2 — the 2024-revision transcription. Level-1-relevant part:
                 the strengthened adaptor-signature baseline of
                 [GSST24], transcribed from [Jost24]:
                 SHA-256 ae79710e9ad733612e732148addd3fd6aaea218aec7665040e5b55e4f735410a
[GMM+22]       — Foundations of Coin Mixing Services (ePrint 2022/942):
                 SHA-256 5bb25d7e47dd31d37f15f9a1b72bad67c0e63e715407f7a44a4b3caa78892e45
```

Base tree: `mainnetswap = f114b0b1` lineage. All type and path names
below are the real ones in that tree.

---

## 1. Problem, claim, and non-claims

### 1.1 The problem

One composed route today carries **one** secret witness across both legs.
Settlement therefore writes the same secret value — or artifacts
deterministically derived from it — onto two public ledgers:

- the EVM `ConditionLock` (0x02) publishes the scalar in claim calldata
  and its point in contract state;
- the Solana `CrossCurveConditionLock` (0x06) publishes the scalar in the
  claim instruction;
- the XMR `CrossCurveSharedSpend` (0x05) and the BTC/DOM adaptor legs
  bind to the same 252-bit value.

Any observer of both chains links the two halves of a route **by byte
equality**. No statistics needed.

### 1.2 The claim Level 1 makes

Under the V3 binding, an adversary holding the complete public artifacts
of both legs — lock points, revealed witnesses, transactions — but not
the secret offset `δ`, gains no advantage in matching the legs of one
route over guessing among the candidate set.

### 1.3 Non-claims (print these wherever the feature is described)

- Amounts and timing still correlate. Only denomination/batching policy
  addresses that; none is part of Level 1.
- The solver links the legs by construction (it composed them). Blinding
  the solver is Level 2 (A2L+/BCS), a separate gated track. **Do not
  import any Level-2 machinery into Level 1** — no encryption, no
  randomizable NIZK, no puzzle store. §3.3 makes this binding.
- A party that learns `δ` links trivially; `δ` is exactly as sensitive
  as the other route secrets.

---

## 2. The construction

### 2.1 Why the naive spelling is forbidden

"Reveal `t + r` on one leg and `t` on the other" **breaks the
cross-curve legs**. XMR and Solana require the *same integer witness*
`w < 2^252` to be simultaneously a valid secp256k1 scalar and a valid
ed25519 scalar (`xmr_dleq_sigma::CrossCurveSecret252` enforces this; the
role-bound DLEQ proves it). Modular addition on either curve's order
does not commute with the 252-bit same-integer requirement. Any
implementation that blinds by modular arithmetic on a shared scalar is
wrong and must be refused in review.

### 2.2 The correct construction

**Each leg gets its own independent witness. The linkage is a secret
integer relation held off-chain, authenticated inside the composed
binding.**

For one composed route:

- `w_up`, `w_dn` — upstream and downstream leg witnesses, independent,
  each derived in `[1, 2^251)`.
- `δ` — the leg offset, a route secret in `[1, 2^251)`, known only to
  the two endpoint daemons. Never transported; derived (§5).
- Binding relation, **over the integers** (no modular wrap; the ranges
  guarantee it): `w_dn = w_up + δ  <  2^252` — still a valid
  cross-curve witness for every leg kind.
- Per-leg lock points `A_up = w_up·G`, `A_dn = w_dn·G` (secp256k1;
  cross-curve legs additionally carry their ed25519 companions through
  the existing machinery, unchanged).
- Public relation point `D = δ·G = A_dn − A_up`, committed inside the
  composed binding together with a Schnorr proof of knowledge of `δ`
  (§4.2). `D` lives only in the binding — never on chain.

Settlement flow: the exposing leg reveals **its own** `w_up`; the
materializer computes `w_dn = w_up + δ` (bound-checked integer add) and
drives the consuming leg. Every child, contract, program, and refund
construction sees an ordinary witness for its own leg. **Nothing
on-chain changes shape** — only witness *values* decouple.

Unlinkability argument (for the record): with `w_up` uniform in its
range and `δ` secret, `(w_up, w_up + δ)` is distributed as an
independent pair up to a negligible range skew at the top of the
interval (accepted and recorded, not mitigated). An observer of both
chains sees two unrelated-looking points and two unrelated-looking
scalars; recognizing the pair requires `δ` or `D`, which never leave
the authenticated binding.

### 2.3 What does NOT change

- `LockMechanism` bytes 0x01–0x06: untouched.
- The Solana escrow program, the EVM contract, the XMR shared-spend and
  BTC constructions: untouched.
- DLEQ roles 1–3 and their proofs: untouched — each leg proves **its
  own** witness exactly as today.
- Refund machinery (including NAR-DC-P1-009's non-cooperative refund
  adaptor): untouched in mechanism; under V3 each leg's refund binds to
  that leg's blinded witness, which it already does structurally.

---

## 3. The 2024 baseline (what the update means for Level 1)

The 2024 work ([Jost24] building on [GSST24]) targets Level 2, but two
of its conclusions become the **baseline** Level 1 is implemented
against, and one anti-conclusion must be stated to keep scope tight:

### 3.1 Strengthened adaptor-signature requirements ([GSST24])

[GSST24] showed the older adaptor-signature definitions admit
**malleable pre-signatures**: a scheme can be "secure" under the old
definitions while one verifying pre-signature adapts into two distinct
full signatures. The strengthened property set is:

1. pre-signature correctness;
2. extractability;
3. **unique extractability** — one verifying pre-signature commits to
   one full-signature/witness outcome (game: adversary with pSign/Sign
   oracles must produce `(m, Y, ⟨σ, σ, σ′)`, `σ ≠ σ′`, both verifying,
   `⟨σ` pre-verifying, both extractions yielding valid witnesses; must
   succeed only with negligible probability);
4. unlinkability (adapted vs. ordinary signatures indistinguishable);
5. pre-verify soundness;
6. pre-signature adaptability.

**Level-1 obligation**: the leg claim and refund adaptor rounds in
`dom-scriptless-crypto` (claim_adaptor, claim_adaptor_round,
refund_adaptor_round) are audited and test-vectored against all six
properties, with unique extractability exercised explicitly (test
L1-T12, §8). Honest note for the auditor: on the discrete-log relation
a statement has a unique witness, so extraction ambiguity collapses for
honest statements — the audit still matters because (a) the *encodings*
must not admit pair-shaped or otherwise malleable pre-signatures, and
(b) Level 2 will reuse these rounds and requires the full property set;
establishing the baseline now is one audit instead of two.

### 3.2 Failure-shape discipline (selective-failure lineage)

Any *new* verification surface added by V3 that is visible to a remote
peer must fail with the fixed-shape, cause-free refusal idiom (uniform
abort; detailed cause only in the local journal). V3 adds exactly one
peer-visible verification — binding admission (`bind`) — and it already
follows the tree's fail-closed refusal idiom; keep it cause-free on the
wire.

### 3.3 What the 2024 update does NOT bring into Level 1 (binding)

Level 1 uses **no encryption, no randomizable NIZK, no puzzles**. The
only proof in Level 1 is the Schnorr PoK of `δ` (§4.2), which is always
generated **fresh by a party that knows `δ`** — there is no
re-randomization requirement and no proof transport between mutually
distrusting parties. Do not add HSM-CL, LOE wrappers, Groth–Sahai
proofs, blind credentials, or hub/solver stores to this work; any PR
mixing Level-2 machinery into Level 1 is refused as scope violation.

---

## 4. Reference implementation

Target location: new module `leg_blinding` inside `route-composer`
(it owns `RouteScalar` and the binding digests), or sibling crate
`dom-leg-blinding` if the crate graph prefers it. Dependencies are
already in the workspace, pinned: `blake2 =0.10.6`, `zeroize =1.8.2`,
`subtle =2.6.1`, and — only for the relation proof — `secp256kfun` as
re-exported through `sigma_fun =0.7.0` (the pin `xmr-dleq-sigma`
already carries; **do not introduce a second secp implementation**).

### 4.1 The blinding module (complete)

```rust
//! Per-leg witness blinding for composed routes (Level 1).
//!
//! One route, two legs, two independent witnesses `w_up`, `w_dn`, joined
//! by the secret integer relation `w_dn = w_up + δ` with every operand
//! below 2^251, so the sum stays below 2^252 and remains a valid
//! cross-curve witness for the XMR/Solana leg kinds. The relation is
//! authenticated inside the composed binding through the public point
//! `D = δ·G` and a Schnorr proof of knowledge of `δ`; the scalar `δ`
//! itself is a route secret and never leaves the two endpoint daemons.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Domain for deriving the leg offset from the route's private seed.
const LEG_OFFSET_DERIVE_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/ROUTE-COMPOSER/LEG-OFFSET-DERIVE/V1\0";
/// Domain for deriving a leg witness from the route's private seed.
const LEG_WITNESS_DERIVE_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/ROUTE-COMPOSER/LEG-WITNESS-DERIVE/V1\0";
/// Domain for the offset-relation Schnorr proof challenge (DLEQ role 4;
/// the byte is written into the transcript exactly like roles 1..3).
const LEG_OFFSET_RELATION_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/ROUTE-COMPOSER/LEG-OFFSET-RELATION/V1\0";
/// Domain for the deterministic proof nonce (RFC-6979 posture).
const LEG_OFFSET_NONCE_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/ROUTE-COMPOSER/LEG-OFFSET-NONCE/V1\0";
/// The reserved role byte in the closed DLEQ role registry (§6).
pub const ROLE_LEG_OFFSET_RELATION: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LegBlindingErrorV1 {
    /// A candidate scalar fell outside [1, 2^251) after derivation.
    #[error("derived value outside the admissible range")]
    Range,
    /// The integer sum left the 252-bit cross-curve range. With both
    /// operands honestly below 2^251 this is unreachable; reaching it
    /// proves a corrupted operand and must refuse the route.
    #[error("witness translation left the cross-curve range")]
    TranslationOverflow,
    /// The relation proof failed verification.
    #[error("leg-offset relation proof refused")]
    RelationProof,
}

/// One leg's private witness, bounded to [1, 2^251).
///
/// Exists only through [`derive_leg_witness_v1`] or
/// [`translate_witness_v1`]; bytes are big-endian (the revealed-secp
/// spelling the rest of the tree uses), zeroized on drop, `Debug`
/// redacted (I6 discipline).
pub struct LegWitnessV1(Zeroizing<[u8; 32]>);

impl LegWitnessV1 {
    /// Big-endian bytes, for the leg's own claim path only.
    pub fn expose_big_endian(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for LegWitnessV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LegWitnessV1(REDACTED)")
    }
}

/// The secret leg offset δ, bounded to [1, 2^251), zeroizing, redacted.
pub struct LegOffsetV1(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for LegOffsetV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LegOffsetV1(REDACTED)")
    }
}

/// Big-endian 256-bit check: value < 2^251 and value != 0.
fn in_admissible_range(bytes: &[u8; 32]) -> bool {
    // 2^251 has bit 251 set: the most significant byte must be below
    // 0b0000_1000 = 0x08 for the value to be < 2^251.
    let below = bytes[0] < 0x08;
    let nonzero: bool = !bool::from(bytes.ct_eq(&[0u8; 32]));
    below && nonzero
}

/// Deterministic domain-separated derivation into [1, 2^251).
///
/// Counter-mode rejection sampling: candidate = Blake2b-256(domain ‖
/// route_seed ‖ len(context) ‖ context ‖ counter) with the top five
/// bits cleared; a zero candidate advances the counter. Clearing the
/// bits makes every candidate < 2^251 by construction, so the loop
/// terminates on the first nonzero draw (one retry has probability
/// 2^-251).
fn derive_bounded_scalar(
    domain: &[u8],
    route_seed: &[u8; 32],
    context: &[u8],
) -> Result<Zeroizing<[u8; 32]>, LegBlindingErrorV1> {
    for counter in 0u8..=7 {
        let mut hasher =
            Blake2bVar::new(32).map_err(|_| LegBlindingErrorV1::Range)?;
        hasher.update(domain);
        hasher.update(route_seed);
        hasher.update(&[u8::try_from(context.len() & 0xff).unwrap_or(0)]);
        hasher.update(context);
        hasher.update(&[counter]);
        let mut candidate = Zeroizing::new([0u8; 32]);
        hasher
            .finalize_variable(candidate.as_mut())
            .map_err(|_| LegBlindingErrorV1::Range)?;
        candidate[0] &= 0x07; // clear bits 255..251: candidate < 2^251
        if in_admissible_range(&candidate) {
            return Ok(candidate);
        }
    }
    Err(LegBlindingErrorV1::Range)
}

/// Derives the secret leg offset δ for one ordered leg pair of a route.
///
/// `route_seed` is the route's private derivation seed (§5); `route_id`
/// and the ordered pair pin the value to exactly one consuming edge, so
/// no offset is ever reused across routes, directions, or epochs.
pub fn derive_leg_offset_v1(
    route_seed: &[u8; 32],
    route_id: &[u8; 32],
    from_leg: u8,
    to_leg: u8,
) -> Result<LegOffsetV1, LegBlindingErrorV1> {
    let mut context = [0u8; 34];
    context[..32].copy_from_slice(route_id);
    context[32] = from_leg;
    context[33] = to_leg;
    derive_bounded_scalar(LEG_OFFSET_DERIVE_DOMAIN_V1, route_seed, &context)
        .map(LegOffsetV1)
}

/// Derives one leg's witness for one route.
pub fn derive_leg_witness_v1(
    route_seed: &[u8; 32],
    route_id: &[u8; 32],
    leg: u8,
) -> Result<LegWitnessV1, LegBlindingErrorV1> {
    let mut context = [0u8; 33];
    context[..32].copy_from_slice(route_id);
    context[32] = leg;
    derive_bounded_scalar(LEG_WITNESS_DERIVE_DOMAIN_V1, route_seed, &context)
        .map(LegWitnessV1)
}

/// 256-bit big-endian addition with carry, returning overflow.
fn add_be_256(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], bool) {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    (out, carry != 0)
}

/// Translates the revealed witness of one leg into the other leg's
/// witness: `w_to = w_from + δ`, over the integers.
///
/// The result must stay below 2^252 (top four bits clear) to remain a
/// valid cross-curve witness; with honest inputs the bound holds by
/// construction, so a violation is proof of a corrupted operand and
/// refuses the route rather than proceeding.
pub fn translate_witness_v1(
    from: &LegWitnessV1,
    offset: &LegOffsetV1,
) -> Result<LegWitnessV1, LegBlindingErrorV1> {
    let (sum, carry) = add_be_256(&from.0, &offset.0);
    // < 2^252: the most significant byte must stay below 0b0001_0000.
    if carry || sum[0] >= 0x10 {
        let mut sum = sum;
        sum.zeroize();
        return Err(LegBlindingErrorV1::TranslationOverflow);
    }
    Ok(LegWitnessV1(Zeroizing::new(sum)))
}

/// A leg witness re-expressed as the existing canonical cross-curve
/// secret spelling (little-endian), exactly what
/// `xmr_dleq_sigma::CrossCurveSecret252::from_little_endian` expects.
/// That call remains the range authority of last resort.
pub fn leg_witness_to_cross_curve_252(
    witness: &LegWitnessV1,
) -> Zeroizing<[u8; 32]> {
    let mut little_endian = Zeroizing::new(*witness.expose_big_endian());
    little_endian.reverse();
    little_endian
}
```

### 4.2 The relation proof (complete)

Statement: knowledge of `δ` with `D = δ·G`, where the verifier ALWAYS
recomputes `D = A_dn − A_up` from the binding's committed leg points —
a prover-supplied `D` binds nothing and is refused. Written against
`secp256kfun` exactly as the tree links it (spellings of markers and
methods follow the pinned re-export at compile time; the transcript
layout and the equation are the specification and must not move):

```rust
use secp256kfun::marker::{NonZero, Public, Secret, Zero};
use secp256kfun::{g, s, Point, Scalar, G};

/// Serialized Schnorr PoK of δ for `D = δ·G`, 97 bytes:
/// 33 (compressed R) ‖ 32 (s) ‖ 32 (binding digest echoed for audit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffsetRelationProofV1 {
    pub nonce_point: [u8; 33],
    pub response: [u8; 32],
    pub binding_digest: [u8; 32],
}

fn relation_challenge(
    nonce_point: &Point,
    relation_point: &Point,
    binding_digest: &[u8; 32],
) -> Result<Scalar<Public, Zero>, LegBlindingErrorV1> {
    let mut hasher =
        Blake2bVar::new(32).map_err(|_| LegBlindingErrorV1::RelationProof)?;
    hasher.update(LEG_OFFSET_RELATION_DOMAIN_V1);
    hasher.update(&[ROLE_LEG_OFFSET_RELATION]);
    hasher.update(&nonce_point.to_bytes());
    hasher.update(&relation_point.to_bytes());
    hasher.update(binding_digest);
    let mut challenge = [0u8; 32];
    hasher
        .finalize_variable(&mut challenge)
        .map_err(|_| LegBlindingErrorV1::RelationProof)?;
    Ok(Scalar::from_bytes_mod_order(challenge).public())
}

/// Proves knowledge of δ, binding `D = δ·G` into `binding_digest`.
///
/// The nonce is deterministic (Blake2b-512 in its own domain over
/// (δ, D, digest), reduced) — RFC-6979 posture: a broken RNG can never
/// leak δ through nonce reuse.
pub fn prove_offset_relation_v1(
    delta: &LegOffsetV1,
    binding_digest: &[u8; 32],
) -> Result<(Point, OffsetRelationProofV1), LegBlindingErrorV1> {
    let delta_scalar: Scalar<Secret, NonZero> =
        Scalar::from_bytes(*delta.0)
            .and_then(|s: Scalar<Secret, Zero>| s.non_zero())
            .ok_or(LegBlindingErrorV1::Range)?;
    let relation_point = g!(delta_scalar * G).normalize();

    let mut hasher =
        Blake2bVar::new(64).map_err(|_| LegBlindingErrorV1::RelationProof)?;
    hasher.update(LEG_OFFSET_NONCE_DOMAIN_V1);
    hasher.update(&*delta.0);
    hasher.update(&relation_point.to_bytes());
    hasher.update(binding_digest);
    let mut wide = Zeroizing::new([0u8; 64]);
    hasher
        .finalize_variable(wide.as_mut())
        .map_err(|_| LegBlindingErrorV1::RelationProof)?;
    let mut narrow = Zeroizing::new([0u8; 32]);
    narrow.copy_from_slice(&wide[..32]);
    let nonce: Scalar<Secret, NonZero> = Scalar::from_bytes_mod_order(*narrow)
        .non_zero()
        .ok_or(LegBlindingErrorV1::RelationProof)?;

    let nonce_point = g!(nonce * G).normalize();
    let challenge =
        relation_challenge(&nonce_point, &relation_point, binding_digest)?;
    let response = s!(nonce + challenge * delta_scalar);

    Ok((
        relation_point,
        OffsetRelationProofV1 {
            nonce_point: nonce_point.to_bytes(),
            response: response.to_bytes(),
            binding_digest: *binding_digest,
        },
    ))
}

/// Verifies the relation proof against the recomputed relation point.
pub fn verify_offset_relation_v1(
    relation_point: &Point,          // ALWAYS recomputed: A_dn − A_up
    proof: &OffsetRelationProofV1,
    expected_binding_digest: &[u8; 32],
) -> Result<(), LegBlindingErrorV1> {
    if &proof.binding_digest != expected_binding_digest {
        return Err(LegBlindingErrorV1::RelationProof);
    }
    let nonce_point = Point::from_bytes(proof.nonce_point)
        .ok_or(LegBlindingErrorV1::RelationProof)?;
    let response: Scalar<Public, Zero> =
        Scalar::from_bytes(proof.response)
            .ok_or(LegBlindingErrorV1::RelationProof)?
            .public();
    let challenge =
        relation_challenge(&nonce_point, relation_point, expected_binding_digest)?;
    // s·G == R + e·D
    let lhs = g!(response * G).normalize();
    let rhs = g!(nonce_point + challenge * relation_point).normalize();
    if lhs == rhs {
        Ok(())
    } else {
        Err(LegBlindingErrorV1::RelationProof)
    }
}
```

### 4.3 Unit tests to ship inside the module (complete bodies)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_domain_separated_and_in_range() {
        let seed = [7u8; 32];
        let route = [9u8; 32];
        let a = derive_leg_offset_v1(&seed, &route, 0, 1).unwrap();
        let b = derive_leg_offset_v1(&seed, &route, 0, 1).unwrap();
        assert_eq!(&*a.0, &*b.0, "deterministic");
        let c = derive_leg_offset_v1(&seed, &route, 1, 0).unwrap();
        assert_ne!(&*a.0, &*c.0, "direction-separated");
        let w = derive_leg_witness_v1(&seed, &route, 0).unwrap();
        assert_ne!(&*a.0, w.expose_big_endian(), "domain-separated");
        assert!(a.0[0] < 0x08 && w.expose_big_endian()[0] < 0x08);
    }

    #[test]
    fn translation_stays_in_the_cross_curve_range_and_is_reproducible() {
        let seed = [3u8; 32];
        let route = [4u8; 32];
        let w_up = derive_leg_witness_v1(&seed, &route, 0).unwrap();
        let delta = derive_leg_offset_v1(&seed, &route, 0, 1).unwrap();
        let w_dn = translate_witness_v1(&w_up, &delta).unwrap();
        assert!(w_dn.expose_big_endian()[0] < 0x10, "< 2^252");
        let again = translate_witness_v1(&w_up, &delta).unwrap();
        assert_eq!(w_dn.expose_big_endian(), again.expose_big_endian());
    }

    #[test]
    fn corrupted_operand_refuses_instead_of_wrapping() {
        let mut high = [0u8; 32];
        high[0] = 0xff; // far above 2^251: forged operand
        let w = LegWitnessV1(Zeroizing::new(high));
        let delta = LegOffsetV1(Zeroizing::new(high));
        assert!(matches!(
            translate_witness_v1(&w, &delta),
            Err(LegBlindingErrorV1::TranslationOverflow)
        ));
    }

    #[test]
    fn relation_proof_round_trips_and_binds() {
        let seed = [5u8; 32];
        let route = [6u8; 32];
        let digest = [8u8; 32];
        let delta = derive_leg_offset_v1(&seed, &route, 0, 1).unwrap();
        let (point, proof) = prove_offset_relation_v1(&delta, &digest).unwrap();
        verify_offset_relation_v1(&point, &proof, &digest).unwrap();
        assert!(verify_offset_relation_v1(&point, &proof, &[9u8; 32]).is_err());
        let mut bad = proof.clone();
        bad.response[31] ^= 1;
        assert!(verify_offset_relation_v1(&point, &bad, &digest).is_err());
        let mut bad_nonce = proof.clone();
        bad_nonce.nonce_point[10] ^= 1;
        assert!(verify_offset_relation_v1(&point, &bad_nonce, &digest).is_err());
    }

    #[test]
    fn cross_curve_spelling_is_the_tree_convention() {
        let seed = [1u8; 32];
        let route = [2u8; 32];
        let w = derive_leg_witness_v1(&seed, &route, 0).unwrap();
        let le = leg_witness_to_cross_curve_252(&w);
        let mut back = *le;
        back.reverse();
        assert_eq!(&back, w.expose_big_endian());
        // Integration test (separate crate boundary) MUST additionally
        // drive xmr_dleq_sigma::CrossCurveSecret252::from_little_endian
        // and prove_bound/verify_bound roles 1..3 with these bytes.
    }
}
```

---

## 5. Provisioning and lifecycle of `δ` and the witnesses

- Everything derives from one **route derivation seed**, provisioned to
  both endpoint daemons exactly like the existing route secrets (the
  stdin secrets bundle gains one 32-byte field in its next family
  version; follow the same promote-vN pattern the secrets reader
  already uses). Both daemons derive identical values locally.
- **`δ` never crosses any wire** — not even the authenticated relay.
  There is no synchronization message for it; determinism IS the
  synchronization.
- Derivation inputs pin `(route_id, direction, leg)`, so nothing is
  reusable across routes. There is no rotation surface because there is
  no reuse.
- Zeroization: both secret types wrap `Zeroizing`; every intermediate
  (including refused sums) zeroizes; `Debug` is redacted everywhere.

---

## 6. Registry: role byte 4

In `xmr-dleq-sigma`, extend the closed table exactly in the
NAR-DC-P1-010 regime:

```rust
/// Schnorr PoK transcript domain for the composed-binding leg-offset
/// relation (Level 1). Consumed by route-composer; minted ONLY here.
pub const ROLE_LEG_OFFSET_RELATION: u8 = 4;

pub const ROLES_V1: &[(u8, &str)] = &[
    (ROLE_XMR_SHARED_SPEND, "xmr-shared-spend"),
    (ROLE_XMR_REFUND_SHARE, "xmr-refund-share"),
    (ROLE_SOLANA_CONDITION_LOCK, "solana-condition-lock"),
    (ROLE_LEG_OFFSET_RELATION, "leg-offset-relation"),
];
```

`route-composer` re-exports the byte from the registry — **never defines
it** (delete the local constant from §4.1 at integration time and import
instead). Extend the uniqueness test and the static gate
(`scripts/solana-v8-static-validate.py` family) to the new entry.

---

## 7. `ComposedBindingV3` and the consumption seam

### 7.1 Binding additions (all inside `binding_digest`)

1. `upstream_lock_point: [u8; 33]` — `A_up`, compressed.
2. `downstream_lock_point: [u8; 33]` — `A_dn`, compressed.
3. `offset_relation_proof: OffsetRelationProofV1` (97 bytes).

### 7.2 `bind` admission order (fail-closed, all-or-nothing)

1. decode both leg points; refuse `A_up == A_dn` (a zero offset is
   dishonest by range and silently reintroduces the disclosure);
2. recompute `D = A_dn − A_up` — never accept a prover-supplied `D`;
3. `verify_offset_relation_v1(D, proof, binding_digest_preimage)`;
4. all existing V2 preconditions, unchanged.

### 7.3 API surface

- `verify_revealed_scalar` **does not exist in V3**. No compatibility
  shim: a function handing out "the route scalar" is a standing
  invitation to relink the legs.
- New: `verify_revealed_leg_scalar(leg, bytes) -> LegWitnessV1` —
  checks the revelation against **that leg's** committed point (and for
  cross-curve legs defers to the leg's own claim/DLEQ verification as
  today).
- New: `translate_witness(from: &LegWitnessV1, offset: &LegOffsetV1)`
  — the only path to the other leg's witness (§4.1's
  `translate_witness_v1`).
- V1/V2 bindings stay decodable for recovery tooling and tests; a live
  production route composes on V3 only (one-way, like the V10-only
  production entrypoint).

### 7.4 Materializer flow (dom-interopd)

```text
exposing child reveals bytes
  → verify_revealed_leg_scalar(exposing_leg, bytes)      // w_from
  → translate_witness(w_from, δ_route)                   // w_to
  → consuming child receives an ordinary witness for its leg
```

Cross-curve legs re-express through
`leg_witness_to_cross_curve_252` → `CrossCurveSecret252::from_little_endian`.
No child, actuator, contract or program learns that blinding exists.

---

## 8. Integration map and test plan

### 8.1 File-by-file

| Surface | Work |
|---|---|
| `crates/route-composer` | module §4; `ComposedBindingV3` §7; retire the single-scalar surface |
| `crates/kaystra-core` | terms carry per-leg lock points; audits asserting cross-leg point equality flip to asserting the committed relation |
| `crates/adapters/xmr-dleq-sigma` | §6 registry entry + tests + static gate |
| `crates/dom-interopd` | plan source/materializer call the §7.4 flow; secrets bundle vN+1 with the route derivation seed; input/admission loaders accept the V3 family (promote-vN, mechanical) |
| `dom-scriptless-crypto` | no functional change; receives the §3.1 audit + L1-T12 vectors |
| refund paths | no change; covered by L1-T10 |
| wallet | no code; recognizes the V3 lineage as ordinary maintenance |

### 8.2 Mandatory tests

- **L1-T1..T5** — the §4.3 unit bodies, verbatim.
- **L1-T6** — bind refusals: prover-supplied `D`; `δ = 0`
  (`A_up == A_dn`); tampered proof; wrong digest; transcript domain
  swap; role-byte swap. Each refuses.
- **L1-T7** — composition dry-run: full two-leg route; assert the two
  revealed scalars differ; claim settles; refund settles.
- **L1-T8** — observer harness: given both leg transcripts minus `δ`,
  matching legs across a shuffled batch of ≥16 routes performs no
  better than chance.
- **L1-T9** — cross-curve integration: blinded witnesses through
  `CrossCurveSecret252::from_little_endian` and roles 1–3
  `prove_bound`/`verify_bound`; existing XMR and Solana e2e harnesses
  green end to end with blinded witnesses.
- **L1-T10** — refund reveal on one leg exposes only that leg's
  witness; the other leg's claim remains impossible without `δ`.
- **L1-T11** — secret hygiene: debug/log scan shows no witness, offset,
  or seed bytes; all intermediates zeroize (fault-injection style where
  the tree already has it).
- **L1-T12** *(2024 baseline)* — unique-extractability vectors for the
  leg claim/refund adaptor rounds: a verifying pre-signature admits
  exactly one completing signature; any mutated completion fails
  verification or extraction; no pair-shaped pre-signature encoding
  decodes.
- **Gates** — `cargo fmt` clean; clippy **zero** across touched crates
  (the project's zero-`#[allow]` policy; `#[expect(reason)]` only per
  house rules); full production suites green.

---

## 9. Invariants (carry verbatim into the implementing PR and the NAR)

- **I1** — Witnesses and offsets are derived in `[1, 2^251)`;
  translation checks `< 2^252` and refuses instead of wrapping.
- **I2** — `δ` never leaves the endpoint daemons; it is derived, not
  transported.
- **I3** — The relation point `D` is always recomputed from committed
  leg points by verifiers; never prover-supplied.
- **I4** — Every derived value is bound to `route_id`, direction, and
  leg; nothing is reusable across routes.
- **I5** — The relation-proof transcript includes role byte 4 and the
  binding digest; the nonce is deterministic in its own domain.
- **I6** — All secret material zeroizes on drop; `Debug` never exposes
  it.
- **I7** — Refund paths bind to per-leg witnesses only; no path exists
  in which revealing one leg's refund witness completes another leg
  without `δ`.
- **I8** — `δ = 0` (equal leg points) is refused at bind time.
- **I9** — The range-skew distinguishing advantage is accepted and
  recorded, not mitigated.
- **I10** — Level 1 claims exactly T0-unlinkability of the
  cryptographic artifacts; the §1.3 non-claims accompany every
  operator-facing description.
- **I11** *(2024)* — The leg adaptor rounds are audited against the
  [GSST24] six-property set, unique extractability included, with
  L1-T12 vectors in-tree.
- **I12** *(2024, scope)* — No Level-2 machinery (encryption,
  randomizable NIZK, puzzles, hub stores, blind credentials) enters
  Level-1 code paths. The only proof is the fresh Schnorr PoK of `δ`.

---

## 10. Ratification checklist (maps to NAR-DC-P1-011 §§5–6)

- [ ] Implementation matches §§2, 4–7 exactly; deviations return to the
      record first.
- [ ] L1-T1..T12 present and green; gates clean.
- [ ] Registry entry + static gate extended (§6).
- [ ] Secrets family promoted with its own record or NAR supplement.
- [ ] DR-PRIV-001 (Part I) archived beside the NAR with SHA-256 pinned
      at signing.
- [ ] The §1.3 non-claims wired into the operator-facing known-limits
      output.
- [ ] Unsigned bytes grant no authority; signature only after all of
      the above (operator Minisign key
      `RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3`,
      key ID `74197A95CA309CF0`).

## 11. Out of scope (pointers only)

Solver-blind puzzles (A2L+/BCS, the [GMM+22]+[GSST24]+[Jost24] stack)
are Level 2: separate record set (DR-PRIV-001 Part II, S1, S2), separate
gates, secp-only legs in v1, not started by this package. Level 1 ships
first, alone, and immediately removes cross-chain byte-equality linkage
for **all** leg kinds including XMR and Solana.

---

*End of the Level-1 implementation package. Nothing here is normative
until implemented, gated, and ratified under NAR-DC-P1-011.*
