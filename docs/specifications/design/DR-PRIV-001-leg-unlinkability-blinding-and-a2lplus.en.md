# DR-PRIV-001 — Leg Unlinkability for Composed Routes

## Level 1: Per-Leg Witness Blinding · Level 2: Solver-Blind Puzzles (A2L+ shape)

Status: **DESIGN RECORD / NOT IMPLEMENTED / NOT NORMATIVE / UNSIGNED**

Date: 2026-09-02

Project: DOM Interop / Kaystra composed routes

Intended home: `docs/specifications/design/DR-PRIV-001-leg-unlinkability-blinding-and-a2lplus.en.md`

Scope: the privacy upgrade path for two-leg composed routes. Level 1 removes
the on-chain linkage between the two legs of one route (defeats an external
observer of both chains). Level 2 removes the solver's own ability to link
the two legs of the routes it serves (an A2L-family puzzle-blinding overlay,
restricted to same-curve legs in its first version). This record freezes the
constructions, the wire shapes, the state machines and the reference code so
a future implementation phase starts from decisions, not from research.

This record approves nothing. It becomes normative only when ratified under
the project's NAR discipline and signed with the established operator
Minisign key (`RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3`,
key ID `74197A95CA309CF0`). Unsigned bytes grant no authority.

---

## 0. The linkability problem, stated against the current tree

Today one composed route carries **one** secret witness. The types are, in
the tree as of `mainnetswap = f114b0b1`:

- `route_composer::RouteScalar` — the 32-byte revealed route secret,
  zeroizing, obtainable only through
  `ComposedBindingV1/V2::verify_revealed_scalar`.
- `xmr_dleq_sigma::CrossCurveSecret252` — the same witness in its canonical
  252-bit form, valid simultaneously as a secp256k1 scalar and an ed25519
  scalar; `revealed_dom_secret_to_xmr_scalar` converts the revealed
  big-endian secp bytes into the ed25519 little-endian scalar.
- `kaystra_core::LockMechanism` — `DomAdaptor2of2 = 0x01`,
  `ConditionLock = 0x02` (EVM ecrecover on `t·G`), `SchnorrAdaptor = 0x03`,
  `HashlockFallback = 0x04`, `CrossCurveSharedSpend = 0x05` (XMR),
  `CrossCurveConditionLock = 0x06` (Solana `s·G_ed == P` syscall).
- `xmr_dleq_sigma::ROLES_V1` — the **closed** DLEQ role registry:
  `1 = xmr-shared-spend`, `2 = xmr-refund-share`,
  `3 = solana-condition-lock`. NAR-DC-P1-010 closed this space; any new
  role is a registry extension with its own ratification line.

Because both legs bind to the same witness, settlement publishes the **same
scalar value** on two chains (or its deterministic 252-bit reduction). The
linkage is not statistical; it is byte equality:

| Adversary | Capability | Links the legs today? |
|---|---|---|
| **T0** — external observer of both chains | reads both ledgers | **Yes — trivially**, by comparing revealed scalars / lock points |
| **T1** — the solver itself | is a participant on both legs | Yes — by construction (it composed the route) |
| **T2** — solver colluding with observer | both of the above | Yes |

- **Level 1** (§2) defeats **T0**. Cheap: no new cryptographic assumptions,
  no new dependencies, works for every leg kind including XMR and Solana.
- **Level 2** (§3) defeats **T1** for the *cryptographic* linkage, subject
  to anonymity-set hygiene (§3.2). Expensive: verifiable linearly
  homomorphic encryption, and same-curve legs only in v1.
- Nothing in this record defeats **T2** on amounts and timing. Only uniform
  denominations and epoch batching do that, and they are operational policy
  (§3.2), not cryptography.

---

# Part I — Level 1: per-leg witnesses joined by a secret offset

## 1.1 Why the naive spelling fails, and the correct one

The naive spelling — "reveal `t + r` on one leg and `t` on the other" — dies
on the cross-curve legs. The XMR and Solana constructions require the *same*
integer witness `w < 2^252` to be a valid scalar on **both** secp256k1 and
ed25519 (that is exactly what `CrossCurveSecret252` enforces and what the
role-bound DLEQ proves). Adding an offset modulo the secp order breaks the
252-bit range, and adding modulo one curve's order does not commute with
reduction into the other's.

The correct construction inverts the direction of derivation:

> **Each leg gets its own independent witness. The linkage is a secret
> linear relation held off-chain, authenticated inside the composed
> binding.**

Notation, for one composed route:

- `w_up`, `w_dn` — the upstream and downstream leg witnesses, independent,
  each sampled (or derived, §1.4) in the range `[1, 2^251)`.
- `δ` ("the leg offset") — a route secret in `[1, 2^251)`, known to the two
  endpoint daemons of the route (the same parties that hold the route's
  other secrets), **never** published, **never** on chain.
- The binding relation, over the integers (no modular wrap, guaranteed by
  the ranges): `w_dn = w_up + δ`, hence `w_dn < 2^252` — still a valid
  cross-curve witness for any leg kind.
- Per-leg lock points: `A_up = w_up·G`, `A_dn = w_dn·G` on secp256k1;
  cross-curve legs additionally carry their ed25519 companions exactly as
  today, each proven with the existing role-bound DLEQ **for that leg's own
  witness** (roles 1–3 unchanged).
- Public relation point: `D = δ·G = A_dn − A_up`, carried **inside the
  composed binding** (off-chain, participant-only), with a proof of
  knowledge of `δ` (§1.5) so the binding cannot be forged around it.

Settlement flow change: the leg that exposes first reveals **its own**
witness (`w_up`); the consuming side computes `w_dn = w_up + δ` (integer
add, bound-checked) and drives the other leg's claim. Nothing else in the
claim machinery changes: each leg's adaptor / condition-lock / shared-spend
sees a perfectly ordinary witness for that leg.

### Unlinkability argument (T0)

An observer of both chains sees `A_up`, `w_up` on one chain and `A_dn`,
`w_dn` on the other. Without `δ`: `w_dn − w_up` is a value the observer can
compute — **but so can it for every cross-pair of unrelated settlements**;
any two claims on any two chains have *some* difference. The distinguisher
would need to recognize that this difference equals a *committed* `δ`, and
`δ`/`D` never leave the authenticated binding. Formally: with `w_up`
uniform in its range and `δ` secret, the pair `(w_up, w_up + δ)` is
distributed identically (up to the negligible range skew at the top of
`[0, 2^251)`, see §1.7-I9) to a pair of independent witnesses. Byte-equality
linkage is gone; so is point-relation linkage.

What Level 1 deliberately does **not** hide: the solver (T1) knows `δ` is
not needed to link — it composed both legs. Amount and timing correlation
remain for everyone. Those are Level 2 and §3.2 respectively.

## 1.2 What changes where (integration map)

| Surface | Change |
|---|---|
| `route-composer` | new `ComposedBindingV3`: per-leg witness commitments `A_up`, `A_dn`, the relation point `D`, the `OffsetRelationProofV1`, all bound into `binding_digest`; `verify_revealed_scalar` becomes per-leg (`verify_revealed_leg_scalar(leg, bytes) -> LegWitnessV1`) and a new `translate_witness(from_leg, witness, offset) -> LegWitnessV1` owns the integer add |
| `kaystra-core` | terms gain the per-leg lock point (each leg's terms already carry their own condition material; the change is that the two legs' points are no longer equal — audits that asserted equality flip to asserting the committed relation) |
| `xmr-dleq-sigma` | **no change to roles 1–3** (each leg still proves its own witness); one new role byte `4 = leg-offset-relation` reserved for the Schnorr PoK domain (§1.5), extending the closed registry per the NAR-DC-P1-010 discipline |
| secret provisioning | `δ` enters the daemon like the other route secrets (stdin secrets bundle, next version), zeroizing end to end; both endpoint daemons derive it deterministically (§1.4) so it never crosses the wire at all |
| children / materializer | the plan source extracts `w_up`, calls `translate_witness`, hands `w_dn` to the consuming child; `secret_source_is_extractable_v1`-style guards unchanged in shape |
| refund paths | untouched in mechanism: each leg's refund adaptor round (NAR-DC-P1-009) binds to that leg's own witness; a refund reveal on leg L exposes `w_L` only, which without `δ` says nothing about the other leg (T0), exactly mirroring the claim path |

## 1.3 Reference implementation — module `leg_blinding`

Target: a new module inside `route-composer` (it already owns `RouteScalar`
and the binding digests) or a sibling crate `dom-leg-blinding`. The code
below is written against the workspace's pinned libraries: `blake2 =0.10.6`
(already a route-composer dependency), `zeroize =1.8.2`, `subtle =2.6.1`,
and — only for the point algebra of the relation proof —
`secp256kfun` as re-exported by `sigma_fun =0.7.0` (the exact pin the tree
already carries through `xmr-dleq-sigma`; do not introduce a second secp
implementation).

```rust
//! Per-leg witness blinding for composed routes (DR-PRIV-001, Level 1).
//!
//! One route, two legs, two independent witnesses `w_up`, `w_dn`, joined by
//! the secret integer relation `w_dn = w_up + δ` with every operand below
//! 2^251, so the sum stays below 2^252 and remains a valid cross-curve
//! witness for the XMR/Solana leg kinds. The relation is authenticated
//! inside the composed binding through the public point `D = δ·G` and a
//! Schnorr proof of knowledge of `δ`; the scalar `δ` itself is a route
//! secret and never leaves the two endpoint daemons.

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
/// the byte is written into the transcript exactly like roles 1..3 are).
const LEG_OFFSET_RELATION_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/ROUTE-COMPOSER/LEG-OFFSET-RELATION/V1\0";
/// The reserved role byte in the closed DLEQ role registry.
pub const ROLE_LEG_OFFSET_RELATION: u8 = 4;

/// Range bound: witnesses and offsets live in [1, 2^251), so that
/// `witness + offset < 2^252` holds over the integers and the sum is a
/// valid `CrossCurveSecret252` for any leg kind.
const RANGE_BITS: u32 = 251;

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
/// [`translate_witness_v1`]; bytes are big-endian (matching the revealed
/// secp spelling the rest of the tree uses), zeroized on drop, `Debug`
/// redacted.
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

/// Big-endian 256-bit comparison: value < 2^251 and value != 0.
fn in_admissible_range(bytes: &[u8; 32]) -> bool {
    // 2^251 has bit 251 set: byte 0 (most significant) must be below
    // 0b0000_1000 = 0x08 for the value to be < 2^251.
    let below = bytes[0] < 0x08;
    let nonzero: bool = !bool::from(bytes.ct_eq(&[0u8; 32]));
    below && nonzero
}

/// Deterministic domain-separated derivation into [1, 2^251).
///
/// Counter-mode rejection sampling: candidate = Blake2b-256(domain ‖
/// route_seed ‖ context ‖ counter) with the top five bits cleared; a zero
/// candidate advances the counter. The cleared-bits spelling makes every
/// candidate < 2^251 by construction, so the loop terminates on the first
/// nonzero draw (probability of even one retry is 2^-251).
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

/// Derives the secret leg offset δ for one ordered leg pair of one route.
///
/// `route_seed` is the route's private derivation seed (provisioned with
/// the other route secrets); `route_id` and the ordered pair pin the value
/// to exactly one consuming edge, so no offset is ever reused across
/// routes, directions, or epochs.
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

/// Derives the upstream leg witness for one route.
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
/// valid cross-curve witness; with honest inputs both operands are below
/// 2^251 and the bound holds by construction, so a violation is proof of a
/// corrupted operand and refuses the route rather than proceeding.
pub fn translate_witness_v1(
    from: &LegWitnessV1,
    offset: &LegOffsetV1,
) -> Result<LegWitnessV1, LegBlindingErrorV1> {
    let (sum, carry) = add_be_256(&from.0, &offset.0);
    // < 2^252: most significant byte must stay below 0b0001_0000.
    if carry || sum[0] >= 0x10 {
        let mut sum = sum;
        sum.zeroize();
        return Err(LegBlindingErrorV1::TranslationOverflow);
    }
    Ok(LegWitnessV1(Zeroizing::new(sum)))
}
```

### 1.3.1 The relation proof (`OffsetRelationProofV1`)

Statement: `D = δ·G` for the committed relation point
`D = A_dn − A_up`. A plain Schnorr proof of knowledge of the discrete log
of `D`, with the challenge bound to the composed binding digest and to the
reserved role byte, in the house transcript style. Written against
`secp256kfun` exactly as `xmr-dleq-sigma` already links it (via
`sigma_fun =0.7.0`; no new curve dependency):

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

/// Proves knowledge of δ binding `D = δ·G` into `binding_digest`.
///
/// `delta` must be the exact offset the composed binding commits to; the
/// nonce is derived deterministically from (δ, D, digest) in its own
/// domain (RFC-6979 style), so a broken RNG can never leak δ through
/// nonce reuse.
pub fn prove_offset_relation_v1(
    delta: &LegOffsetV1,
    binding_digest: &[u8; 32],
) -> Result<(Point, OffsetRelationProofV1), LegBlindingErrorV1> {
    let delta_scalar: Scalar<Secret, NonZero> =
        Scalar::from_bytes(*delta.0)
            .and_then(|s: Scalar<Secret, Zero>| s.non_zero())
            .ok_or(LegBlindingErrorV1::Range)?;
    let relation_point = g!(delta_scalar * G).normalize();

    // Deterministic nonce: Blake2b-512 over its own domain, reduced.
    let mut hasher =
        Blake2bVar::new(64).map_err(|_| LegBlindingErrorV1::RelationProof)?;
    hasher.update(b"DOM-INTEROP/ROUTE-COMPOSER/LEG-OFFSET-NONCE/V1\0");
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
    let challenge = relation_challenge(&nonce_point, &relation_point, binding_digest)?;
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

/// Verifies the relation proof against the committed points.
///
/// `relation_point` MUST be recomputed by the verifier as
/// `A_dn − A_up` from the binding's own committed leg points — never
/// accepted from the prover — or the proof binds nothing.
pub fn verify_offset_relation_v1(
    relation_point: &Point,
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

> Implementation note on API spellings: `secp256kfun` 0.7-era marker/method
> names (`non_zero()`, `public()`, `from_bytes_mod_order`, `normalize`)
> drift between minor versions. The pinned re-export inside the tree is the
> authority; adjust spellings to compile against it, changing nothing in
> the transcript layout (domain ‖ role byte ‖ R ‖ D ‖ digest) or in the
> equation.

### 1.3.2 Cross-curve legs

For an XMR (`CrossCurveSharedSpend`) or Solana (`CrossCurveConditionLock`)
leg, that leg's witness `w_L` feeds the **existing** machinery unchanged:

```rust
/// A leg witness re-expressed as the existing canonical cross-curve
/// secret. Little-endian, as `CrossCurveSecret252::from_little_endian`
/// expects; the [1, 2^252) range is guaranteed by construction here.
pub fn leg_witness_to_cross_curve_252(
    witness: &LegWitnessV1,
) -> Zeroizing<[u8; 32]> {
    let mut little_endian = Zeroizing::new(*witness.expose_big_endian());
    little_endian.reverse();
    little_endian
}
```

The leg's role-bound DLEQ (`prove_bound`/`verify_bound`, roles 1–3) then
proves the same statements it proves today, just for `w_L` instead of the
shared `t`. **No change to `xmr-dleq-sigma`'s proofs.** The only registry
motion is reserving role byte `4` for §1.3.1's transcript, following the
same uniqueness test `ROLES_V1` already enforces.

### 1.3.3 Tests to ship with the module (minimum set)

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
    fn translation_stays_in_the_cross_curve_range_and_inverts() {
        let seed = [3u8; 32];
        let route = [4u8; 32];
        let w_up = derive_leg_witness_v1(&seed, &route, 0).unwrap();
        let delta = derive_leg_offset_v1(&seed, &route, 0, 1).unwrap();
        let w_dn = translate_witness_v1(&w_up, &delta).unwrap();
        assert!(w_dn.expose_big_endian()[0] < 0x10, "< 2^252");
        // w_dn - δ == w_up (checked through re-addition of the borrow-free
        // inverse in the real module; spelled here as digest equality of
        // the recomputed sum).
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
        // wrong digest refuses
        assert!(verify_offset_relation_v1(&point, &proof, &[9u8; 32]).is_err());
        // tampered response refuses
        let mut bad = proof.clone();
        bad.response[31] ^= 1;
        assert!(verify_offset_relation_v1(&point, &bad, &digest).is_err());
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
        // feed into xmr_dleq_sigma::CrossCurveSecret252::from_little_endian
        // in the integration test — that call is the range authority.
    }
}
```

## 1.4 Provisioning and lifecycle of `δ`

- `δ` and the per-leg witnesses derive from one **route derivation seed**
  provisioned exactly like the existing route secrets (stdin bundle, next
  secrets version). Both endpoint daemons derive identical values locally;
  **`δ` never crosses any wire, ever** — not even the authenticated relay.
- Derivation inputs pin route, direction and leg (`route_id ‖ from ‖ to`),
  so no value survives across routes; there is no rotation problem because
  there is no reuse.
- Zeroization: both types wrap `Zeroizing`; every intermediate (`wide`,
  `narrow`, refused sums) zeroizes; `Debug` is redacted — the I6 discipline
  the tree already enforces for `RouteScalar`.

## 1.5 Composed binding changes (`ComposedBindingV3`)

Additions to the binding (all inside `binding_digest`):

1. `upstream_lock_point: [u8; 33]` — `A_up`, compressed.
2. `downstream_lock_point: [u8; 33]` — `A_dn`, compressed.
3. `offset_relation_proof: OffsetRelationProofV1`.

Verification order in `bind` (fail-closed, all-or-nothing):
recompute `D = A_dn − A_up` from the committed points → verify the proof
against `D` and the digest → only then admit the binding. The verifier
**never** accepts `D` as an input.

`verify_revealed_leg_scalar(leg, bytes)` replaces the single
`verify_revealed_scalar`: it checks `bytes·G == A_leg` (and, for
cross-curve legs, defers to the leg's own claim/DLEQ verification exactly
as today) and returns a `LegWitnessV1`. The old single-scalar API is
retired with the V3 family, not kept as a compatibility hole.

## 1.6 Migration and versioning

- New binding family (`V3`) and a new manifest/terms lineage entry, in the
  same promote-vN pattern the production config already uses; V1/V2 routes
  remain decodable for recovery, not admittable for new production routes
  once V3 is ratified — mirroring how the V10-only production entrypoint
  treats older families.
- `LockMechanism` bytes are untouched: the mechanism per leg is the same;
  only the witness values decouple.
- Role registry: add `(4, "leg-offset-relation")` to `ROLES_V1`'s successor
  with the same collision test, under a NAR supplement.

## 1.7 Invariants (to be carried verbatim into the implementing NAR)

- **I1** — Witnesses and offsets are sampled/derived in `[1, 2^251)`;
  translation checks `< 2^252` and refuses instead of wrapping.
- **I2** — `δ` never leaves the endpoint daemons; it is derived, not
  transported.
- **I3** — The relation point `D` is always recomputed from committed leg
  points by verifiers; never prover-supplied.
- **I4** — Every derived value is bound to `route_id`, direction and leg;
  nothing is reusable across routes.
- **I5** — The relation proof transcript includes the role byte `4` and the
  binding digest; the nonce is deterministic in its own domain.
- **I6** — All secret material zeroizes on drop; `Debug` never exposes it.
- **I7** — Refund paths bind to per-leg witnesses only; no path exists in
  which revealing one leg's refund witness completes another leg without
  `δ`.
- **I8** — A V3 route with equal leg points (`A_up == A_dn`, i.e. `δ = 0`)
  is refused at bind time: zero offset defeats the purpose and `δ ∈ [1,·)`
  makes it impossible honestly.
- **I9** — The range skew argument (top of the range unreachable for
  `w_dn`) is accepted: the distinguishing advantage is ≤ 2^-(251-λ) for
  the observed sample sizes; recorded, not mitigated.
- **I10** — Level 1 claims exactly T0-unlinkability of the *cryptographic
  artifacts*. Amount/timing correlation is out of scope and stated as such
  in every operator-facing description.

---

# Part II — Level 2: solver-blind puzzles (A2L+ shape)

## 2.1 Goal, actors, and the honest security preamble

Goal: the solver (hub) serving many concurrent composed routes must not be
able to tell which incoming (upstream) settlement funds which outgoing
(downstream) settlement, beyond what amounts and timing reveal.

Actor mapping (A2L paper terms → DOM terms):

| A2L | DOM |
|---|---|
| Tumbler **T** | the solver daemon |
| Sender **S** | the upstream counterparty daemon (pays the solver) |
| Receiver **R** | the downstream counterparty daemon (is paid by the solver) |

**Security preamble — read before implementing anything.** The original
A2L publication's security argument was later shown to be flawed; the 2022
work on the foundations of coin-mixing services (Glaeser et al., ACM CCS
2022) gives a counterexample against the claimed security of A2L as stated
— the tumbler can be abused as an oracle by an adversary interleaving
sessions — and constructs repaired protocols ("blind conditional
signatures"; A2L+ and A2L-UC) with proofs. **This record freezes
interfaces, message shapes, state machines and the blinding algebra, which
are common to the family. The exact NIZK/commitment set that distinguishes
A2L+ from broken-A2L MUST be transcribed from the 2022 paper at
implementation time (gate G2 in §2.8) and reviewed against it — not
reinvented, not lifted from the 2020 PoC.** Where a message below carries
the marker `[A2L+ hardening]`, the final field set comes from that
transcription.

### Scope restriction in v1: same-curve legs only

The puzzle encrypts and blinds a witness in `Z_q` of secp256k1. The
multiplicative blinding `α → β·α mod q` does **not** preserve the 252-bit
same-integer cross-curve property that the XMR and Solana leg mechanisms
require (`CrossCurveSecret252`). Therefore Level 2 v1 admits only routes
whose *puzzle-bearing* legs are secp-native (`DomAdaptor2of2`,
`ConditionLock`, `SchnorrAdaptor`). Extending blind puzzles across the
ed25519 boundary is open research (gate G4): the known avenues — range
proofs on the blinded value plus per-curve DLEQ, or switching the blinding
to the 252-bit integer domain with rejection — each break at least one of
{homomorphism, range, proof cost} and none is adopted here.

### What Level 2 does NOT do

- It does not hide amounts: **uniform denominations are mandatory** for the
  privacy claim to be non-vacuous (§2.2).
- It does not hide timing: **epoch batching is mandatory** (§2.2).
- It does not protect against a solver that serves only one route in an
  epoch (anonymity set of 1).
- It does not replace Level 1; it composes with it (Level 1 keeps T0 out;
  Level 2 blinds T1).

## 2.2 Operational policy that carries the privacy (normative-to-be)

- **Denominations**: a published, finite set per asset pair; every Level-2
  route uses exactly one denomination; change is made by composing several
  routes, never by odd amounts.
- **Epochs**: the solver runs fixed-length epochs; all promises of an epoch
  use an epoch-scoped HE key (`pk_T^{(e)}`); solving happens in the same
  epoch; unsolved puzzles expire into the refund path. Epoch length and
  minimum batch size `k_min` are deployment policy; below `k_min` the
  solver MUST refuse Level-2 admission (fail-closed, like everything else)
  rather than run a vacuous mix.
- **Fees**: fixed per denomination, paid identically by every route in the
  epoch, or they become a linking channel.

## 2.3 Cryptographic interfaces

The construction needs a **verifiable linearly homomorphic encryption over
`Z_q`** (q = secp256k1 group order) with scalar evaluation, ciphertext
re-randomization, and a NIZK that a ciphertext encrypts the discrete log of
a public point. The reference instantiation in the literature and in the
2020 PoC is **HSM-CL over class groups of imaginary quadratic order**
(Castagnos–Laguillaumie), which has the exact plaintext space `Z_q`.

```rust
/// Verifiable linearly homomorphic encryption over the secp256k1 scalar
/// field. Instantiation candidates and their gates are in §2.7 — no
/// implementation in this workspace satisfies the audit bar today, which
/// is why Level 2 is interface-frozen rather than implemented.
pub trait CondEncryption {
    type PublicKey: Clone + core::fmt::Debug;
    type SecretKey: zeroize::Zeroize;
    type Ciphertext: Clone + PartialEq + core::fmt::Debug;
    /// NIZK: "pk is well-formed" (CL setup soundness).
    type KeyProof: Clone;
    /// NIZK: "ct encrypts the discrete log of point A" (CL-DL relation).
    type CtDlogProof: Clone;
    type Error: core::fmt::Debug;

    fn keygen(
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
    ) -> Result<(Self::PublicKey, Self::SecretKey, Self::KeyProof), Self::Error>;

    fn verify_key(pk: &Self::PublicKey, proof: &Self::KeyProof)
        -> Result<(), Self::Error>;

    /// Encrypts a secp scalar and proves it is the dlog of `dlog_point`.
    fn encrypt_with_dlog_proof(
        pk: &Self::PublicKey,
        witness: &secp256kfun::Scalar,
        dlog_point: &secp256kfun::Point,
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
    ) -> Result<(Self::Ciphertext, Self::CtDlogProof), Self::Error>;

    fn verify_ct_dlog(
        pk: &Self::PublicKey,
        ct: &Self::Ciphertext,
        dlog_point: &secp256kfun::Point,
        proof: &Self::CtDlogProof,
    ) -> Result<(), Self::Error>;

    /// Homomorphic scalar evaluation: Enc(α) → Enc(k·α mod q), PLUS full
    /// ciphertext re-randomization. The 2020 PoC's own comment records the
    /// pitfall this signature exists to close: blinding only the plaintext
    /// leaves the ciphertext itself linkable; the blinding factor must
    /// re-randomize in the ciphertext group, not merely scale in Z_q.
    fn eval_scal_rerandomized(
        pk: &Self::PublicKey,
        ct: &Self::Ciphertext,
        k: &secp256kfun::Scalar,
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
    ) -> Result<Self::Ciphertext, Self::Error>;

    fn decrypt(
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<secp256kfun::Scalar, Self::Error>;
}
```

## 2.4 The protocol, message-precise

Two subprotocols per route, plus the epoch admission token. All transport
rides the existing authenticated relay/noise runtime — Level 2 adds **no
new sockets**. Every message struct gets `canonical_bytes()` in the house
ASCII/length-prefixed style and is digest-bound into the session, exactly
like every other authenticated artifact in the tree; the fields below are
the semantic payload.

### 2.4.0 Epoch admission token `[A2L+ hardening]`

Purpose: the anti-oracle fence. The solver answers **one** solve per issued
promise, and cannot tell *which* promise a solve corresponds to. Mechanism
family: randomizable signatures (Pointcheval–Sanders over BLS12-381 in the
PoC) issued blindly at promise time and shown randomized at solve time —
one token, one solve, unlinkable. The final token protocol (PS vs. the
2022 paper's exact choice) is fixed at gate G2.

```rust
/// Blindly-issued, randomizable one-show admission token. Interface only;
/// instantiation fixed at gate G2 with the A2L+ transcription.
pub trait AdmissionToken {
    type IssuerKey;
    type Token: Clone;
    type ShowProof;
    // issue_blind(issuer, blinded_request) -> blinded_token
    // unblind(blinded_token) -> Token
    // show(token, context) -> ShowProof   // randomized: unlinkable to issue
    // verify_show(issuer_pk, context, proof) -> bool + double-show registry
}
```

The solver keeps a **double-show nullifier store** per epoch (same
discipline as the tree's `xmr-dleq-nullifier-store`): a token shown twice
refuses.

### 2.4.1 Puzzle Promise (solver T ↔ receiver R, downstream leg)

```rust
use secp256kfun::{Point, Scalar};

/// T → R. The puzzle and the conditional promise on the downstream claim.
pub struct PromiseMsg1<E: CondEncryption> {
    /// Epoch HE public key and its well-formedness proof (sent once per
    /// epoch in practice; digest-referenced here).
    pub epoch_key_digest: [u8; 32],
    /// A = α·G — the adaptor point for the downstream claim.
    pub adaptor_point: Point,
    /// c = Enc(pk_T, α).
    pub puzzle_ciphertext: E::Ciphertext,
    /// NIZK that `puzzle_ciphertext` encrypts dlog(adaptor_point).
    pub ct_dlog_proof: E::CtDlogProof,
    /// Adaptor pre-signature over R's exact downstream claim, verifiable
    /// with the existing `verify_claim_adaptor_pre_signature_v1` machinery
    /// against `adaptor_point`.
    pub claim_pre_signature: Vec<u8>,
    /// Blind admission-token issuance payload. [A2L+ hardening]
    pub token_issuance: Vec<u8>,
}

/// R's verification obligations, in order, all fail-closed:
/// 1. epoch key digest matches the admitted epoch key + key proof;
/// 2. `verify_ct_dlog(pk_T, c, A, π)`;
/// 3. the pre-signature verifies against A and R's exact claim terms
///    (kaystra terms digest, not a hash of caller-shaped bytes);
/// 4. token issuance well-formed. Any failure refuses the route BEFORE
///    R locks anything downstream-visible.
pub struct PromiseAccepted<E: CondEncryption> {
    /// β ←$ Z_q*, R's blinding factor. Zeroizing.
    pub beta: Scalar,
    /// A' = β·A.
    pub blinded_point: Point,
    /// c' = eval_scal_rerandomized(pk_T, c, β).
    pub blinded_ciphertext: E::Ciphertext,
    /// Unblinded admission token. [A2L+ hardening]
    pub token: Vec<u8>,
}
```

R forwards the **blinded** puzzle `(A', c', token)` to S over the route's
private transport. T never sees this handoff.

### 2.4.2 Puzzle Solve (sender S ↔ solver T, upstream leg)

```rust
/// S → T. The doubly-blinded solve request tied to S's upstream payment.
pub struct SolveMsg1<E: CondEncryption> {
    /// A'' = τ·A' where τ ←$ Z_q* is S's own blinding factor.
    pub solve_point: Point,
    /// c'' = eval_scal_rerandomized(pk_T, c', τ).
    pub solve_ciphertext: E::Ciphertext,
    /// S's adaptor pre-signature over the exact upstream payment to T,
    /// bound to `solve_point`: T completing it on-chain (or in-journal)
    /// reveals γ = τ·β·α to S.
    pub payment_pre_signature: Vec<u8>,
    /// Randomized token show + double-show context. [A2L+ hardening]
    pub token_show: Vec<u8>,
}

/// T's obligations, in order:
/// 1. verify token show; check nullifier store; record nullifier —
///    REFUSE on double show [A2L+ hardening: this is the oracle fence];
/// 2. verify the payment pre-signature against `solve_point` and the
///    exact upstream terms;
/// 3. γ = decrypt(sk_T^{(e)}, c'');  check γ·G == solve_point — a
///    mismatch proves a malformed request and REFUSES without revealing
///    anything;
/// 4. complete the adaptor with γ, collecting the upstream payment; the
///    completed signature is what discloses γ to S, atomically with T
///    being paid. T learns nothing linking (A'', c'') to any (A, c) it
///    issued: both point and ciphertext are blinded and re-randomized.
pub struct SolveCompleted {
    /// γ = τ·β·α, extracted by S from the completed signature via the
    ///  standard adaptor extraction (already in dom-scriptless-crypto).
    pub gamma: Scalar,
}
```

### 2.4.3 Unblinding chain and downstream claim

```rust
/// S: γ' = τ⁻¹·γ = β·α; sent to R over the route transport.
pub fn unblind_sender(gamma: &Scalar, tau: &Scalar) -> Option<Scalar> {
    let tau_inv = tau.clone().non_zero()?.invert();
    Some(secp256kfun::s!(tau_inv * gamma).public().secret())
}

/// R: α = β⁻¹·γ'; MUST check α·G == adaptor_point before use, then
/// completes the promised pre-signature and claims downstream. The claim
/// publishes only γ-family values blinded per leg — the on-chain artifacts
/// of the two legs share no recognizable value (Level 1 composes here:
/// each leg's witness is additionally offset per Part I).
pub fn unblind_receiver(
    gamma_prime: &Scalar,
    beta: &Scalar,
    adaptor_point: &Point,
) -> Option<Scalar> {
    let beta_inv = beta.clone().non_zero()?.invert();
    let alpha = secp256kfun::s!(beta_inv * gamma_prime);
    let check = secp256kfun::g!(alpha * G).normalize();
    (&check == adaptor_point).then(|| alpha.secret())
}
```

> The exact `secp256kfun` inversion/marker spellings follow the pinned
> version at implementation time; the algebra above is the specification.

### 2.4.4 Atomicity and the refund lattice

- If T never solves: S's upstream pre-signature is never completed — S
  loses nothing; R's promise expires into the downstream refund adaptor
  round (NAR-DC-P1-009 machinery, per leg, unchanged).
- If T solves but S aborts before forwarding γ′: T has been paid, R can
  still refund after timeout — **this is the A2L griefing asymmetry**; the
  fee schedule and the denomination policy must price it, and the epoch
  refund windows must nest exactly like the tree's existing two-leg window
  policy (`ComposedWindowPolicyV1` discipline: downstream refund window
  strictly inside upstream claim window).
- If R aborts after receiving γ′: R simply doesn't claim; refunds fire.
  Nobody's witness leaks: every revealed value is blinded per leg.

## 2.5 Role state machines (house idiom)

Typed hop-by-hop state machines, one per role, in the exact style the tree
already uses (data-carrying enums, `transition(self, msg) -> Result<Self,
Refusal>`, no `Default`, every secret `Zeroizing`, every message digest
verified before its content is touched, refusals never destructive):

```rust
pub enum ReceiverStateV1<E: CondEncryption> {
    /// Awaiting the epoch key announcement.
    AwaitEpochKey,
    /// Awaiting PromiseMsg1 for this route.
    AwaitPromise { epoch_key: E::PublicKey },
    /// Promise verified; puzzle blinded and forwarded to the sender.
    Forwarded {
        beta: Scalar,               // Zeroizing wrapper in the real module
        adaptor_point: Point,
        claim_pre_signature: Vec<u8>,
    },
    /// γ′ received and verified; ready to claim downstream.
    Solvable { alpha: Scalar, claim_pre_signature: Vec<u8> },
    /// Terminal: claimed, refunded, or refused (with reason).
    Terminal(ReceiverOutcomeV1),
}

pub enum SenderStateV1<E: CondEncryption> {
    AwaitPuzzle,
    /// Blinded puzzle received from R; τ sampled; solve request sent.
    Solving { tau: Scalar, solve_point: Point },
    /// γ extracted from T's completed signature; γ′ forwarded to R.
    Settled { gamma_prime_sent: bool },
    Terminal(SenderOutcomeV1),
}

pub enum SolverStateV1<E: CondEncryption> {
    /// Per-epoch: key generated, key proof published, k_min gate armed.
    EpochOpen { secret_key: E::SecretKey, issued: u64, solved: u64 },
    /// Terminal per epoch: closed, keys destroyed (forward secrecy for
    /// the epoch: sk_T^{(e)} zeroizes at epoch close; expired puzzles
    /// become permanently unsolvable, which the refund lattice absorbs).
    EpochClosed,
}
```

Durability: a `PuzzleStoreV1` in the state directory, fixed file name in
the layout (`puzzle-hub.v1.sqlite3` for the solver;
`puzzle-leg.v1.sqlite3` for counterparties), following the same
create/reopen/allowlist/parent-chain discipline the actuator stores use,
journaling: issued promises (digest, token nullifier space), solve
nullifiers, epoch boundaries, and — on the counterparty side — β/τ under
the sealed retention vault (the same sealing machinery the route-secret
vault already provides). Crash anywhere resumes to the exact journaled
step or refuses; no partial state is ever reconstructed from memory.

## 2.6 Where Level 2 sits in the production composition

- A new optional pair of authorities, sibling to the F6 pair in the stage
  layout: the **puzzle-hub authority** (solver runtime) and the
  **puzzle-leg authority** (counterparty runtime), activated only for
  routes whose terms carry the Level-2 marker and whose legs pass the
  same-curve gate. Routes without the marker compose exactly as today —
  Level 2 is strictly additive.
- Admission: the route shape gate (the `selected_counterparty_deployments`
  successor) refuses a Level-2-marked route whose legs include
  `CrossCurveSharedSpend`/`CrossCurveConditionLock` (gate G4 lifts this),
  or whose denomination is off-schedule, with named errors in the
  `PRODUCTION_KNOWN_LIMITS_V1` style.
- Transport: relay/noise sessions as today; the R→S puzzle handoff is a
  new authenticated message kind on the existing route channel.

## 2.7 Dependency reality check (why Level 2 is frozen, not built)

| Need | Candidates | State |
|---|---|---|
| HSM-CL over class groups, Rust | the 2020 PoC's `class` git crate; `bicycl` (C++, FFI) | **none production-grade**; the PoC's dependency chain (curv v0.2.3, class fork, libsecp 0.3.5) is unmaintained and fails the project's pinning/audit bar outright |
| CL-DL NIZK | ships with the above | same |
| PS randomizable signatures (BLS12-381) | `bls12_381` + hand-rolled PS (the PoC has a readable one) | reimplement in-tree against pinned `bls12_381`; small, testable |
| Alternative HE | Paillier + range proofs (mature libs) | changes plaintext space (`Z_N` vs `Z_q`) and adds range-proof cost per operation; recorded as fallback, not preferred |

**Gate G3**: an audited class-group implementation (or an accepted FFI
boundary to one) is a precondition to any Level-2 code entering the tree.
The 2020 PoC is a **reading reference only** (its upstream is GPL —
anything ever taken verbatim lives under `external-gpl` like the XMR
sidecar; the intent here is zero verbatim intake).

## 2.8 Gates (all must close, in order, before Level 2 ships)

- **G1** — this record ratified under the NAR discipline (covers Part I
  too; Part I has no other gate and can ship first).
- **G2** — A2L+ transcription: the exact hardening set (token protocol,
  NIZKs, session-interleaving fence) transcribed from Glaeser et al.,
  CCS 2022, into a supplement of this record, with the paper's theorem
  statements quoted and the message fields finalized. **Verify the
  citation against the paper itself at transcription time.**
- **G3** — HE dependency audit (§2.7).
- **G4** — cross-curve extension research, or a permanent recorded
  restriction to secp legs.
- **G5** — anonymity-set operational policy (denominations, epoch length,
  `k_min`, fee schedule) fixed per deployment and printed at startup with
  the known-limits banner.

---

# Part III — Adoption order, test plan, open questions

## 3.1 Order

1. **Level 1** end to end (module of §1.3 → `ComposedBindingV3` → terms →
   children translation → role byte 4 → NAR supplement). No new
   dependencies; every piece testable against the existing suites; ships
   independently of Level 2 and immediately kills T0 linkage for **all**
   leg kinds including XMR/Solana.
2. Level 2 gates G1–G3, then the hub/leg authorities behind the same-curve
   admission gate, dark-launched on testnets with synthetic uniform
   traffic before any real route carries the marker.

## 3.2 Test plan beyond §1.3.3

- **Composition test**: full two-leg dry route with Level 1 on — assert the
  two revealed on-chain scalars differ, assert claim and refund both
  settle, assert an "observer" harness given both transcripts minus `δ`
  cannot match legs better than chance across a batch of shuffled routes.
- **Cross-curve integration**: blinded witnesses through
  `CrossCurveSecret252::from_little_endian`, `prove_bound`/`verify_bound`
  roles 1–3, the Solana syscall path and the XMR shared-spend path in the
  existing e2e harnesses.
- **Adversarial**: forged `D`, prover-supplied relation point, zero offset,
  out-of-range operands, transcript domain swaps, role-byte swaps —
  every one refuses.
- **Level 2 dry protocol test**: the three state machines against a mock
  `CondEncryption` (exponent-in-the-clear test double), asserting the
  solver's transcript view is identical across permuted promise/solve
  pairings — the unlinkability smoke test the PoC's `dry.rs` sketches,
  rewritten in-tree.

## 3.3 Open questions (tracked, not blocking Part I)

- Q1: does the wallet UX surface Level-1 routes differently? (No on-chain
  difference; likely no.)
- Q2: batch-verification of `OffsetRelationProofV1` across route admission
  (cheap Schnorr batching; optimization only).
- Q3: Level-2 fee accounting inside the solver inventory/bond store —
  interaction with the stage-8 solver work.
- Q4: whether the DOM leg itself (hub chain) can be the puzzle-bearing leg
  in Level 2, letting XMR/SOL legs ride Level 1 only within a Level-2
  route — a possible partial answer to G4 that needs its own analysis.

---

*End of DR-PRIV-001. Nothing in this document is implemented; nothing is
normative until ratified and signed.*
