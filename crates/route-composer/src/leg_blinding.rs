//! Per-leg witness blinding for composed routes (DR-PRIV-001, Level 1) —
//! NOT RATIFIED.
//!
//! One route, two legs, two independent witnesses joined by the secret
//! integer relation `w_to = w_from + δ` with every operand below 2^251, so
//! the sum stays below 2^252 and remains a valid cross-curve witness for
//! the XMR/Solana leg kinds. The relation is authenticated inside the
//! composed binding through the public point `D = δ·G` and a Schnorr proof
//! of knowledge of `δ`; the scalar `δ` itself is a route secret and never
//! leaves the two endpoint daemons (DR-PRIV-001 I2).
//!
//! Naming: `from` is the leg whose claim reveals first (the composed
//! route's DOWNSTREAM settlement — the one whose claim publishes its
//! witness on chain), `to` is the leg whose claim the revealed witness
//! drives after translation (the UPSTREAM settlement). DR-PRIV-001 §1.1
//! spells the same relation as `w_dn = w_up + δ` with "up" meaning the
//! first-revealed witness; the frozen algebra is identical:
//! `consumed = revealed + δ`, `D = A_consumed − A_revealed`.
//!
//! Unlinkability claim (T0, DR-PRIV-001 §1.1): an observer of both chains
//! sees two independent-looking witnesses; without `δ` their difference is
//! indistinguishable from the difference of any unrelated cross-pair of
//! settlements. The solver (T1) still links by construction — that is
//! Level 2's business, not this module's (I10).

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use sigma_fun::secp256k1::fun::{
    g,
    marker::{Public, Secret, Zero},
    s, Point, Scalar, G,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Domain for deriving the leg offset from the route's private seed.
pub const LEG_OFFSET_DERIVE_DOMAIN_V1: &[u8] = b"DOM-INTEROP/ROUTE-COMPOSER/LEG-OFFSET-DERIVE/V1\0";
/// Domain for deriving a leg witness from the route's private seed.
pub const LEG_WITNESS_DERIVE_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/ROUTE-COMPOSER/LEG-WITNESS-DERIVE/V1\0";
/// Domain for the offset-relation Schnorr proof challenge (DLEQ role 4;
/// the byte is written into the transcript exactly like roles 1..3 are).
pub const LEG_OFFSET_RELATION_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/ROUTE-COMPOSER/LEG-OFFSET-RELATION/V1\0";
/// Domain for the deterministic relation-proof nonce (RFC-6979 style: a
/// broken RNG can never leak `δ` through nonce reuse — DR-PRIV-001 I5).
const LEG_OFFSET_NONCE_DOMAIN_V1: &[u8] = b"DOM-INTEROP/ROUTE-COMPOSER/LEG-OFFSET-NONCE/V1\0";
/// The reserved role byte, re-exported from the closed DLEQ role
/// registry (`xmr_dleq_sigma::ROLES_V1`). Minted ONLY there — this crate
/// never defines a role byte of its own (L1 package §6; the static role
/// gate refuses any out-of-registry mint).
pub use xmr_dleq_sigma::ROLE_LEG_OFFSET_RELATION;

/// Wire length of a serialized [`OffsetRelationProofV1`]:
/// 33 (compressed R) ‖ 32 (s) ‖ 32 (binding digest echoed for audit).
pub const OFFSET_RELATION_PROOF_LEN: usize = 97;

/// Everything this module can refuse, by name. Every refusal is terminal
/// for the attempted step (I13 discipline of the composer).
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

/// One leg's private witness, below 2^252 (derived values are below
/// 2^251; a translated value may use the extra bit).
///
/// Exists only through [`derive_leg_witness_v1`], [`translate_witness_v1`]
/// or a verified per-leg reveal (`ComposedBindingV3`); bytes are
/// big-endian (matching the revealed secp spelling the rest of the tree
/// uses), zeroized on drop, `Debug` redacted (I6).
pub struct LegWitnessV1(Zeroizing<[u8; 32]>);

impl LegWitnessV1 {
    /// Big-endian bytes, for the leg's own claim path only.
    pub fn expose_big_endian(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constructor reserved for the composed binding's own verified
    /// reveal path: the caller has already checked `bytes·G == A_leg`.
    pub(crate) fn from_verified_big_endian(bytes: &[u8; 32]) -> Self {
        Self(Zeroizing::new(*bytes))
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
/// Counter-mode rejection sampling: candidate = BLAKE2b-256(domain ‖
/// route_seed ‖ len(context) ‖ context ‖ counter) with the top five bits
/// cleared; a zero candidate advances the counter. The cleared-bits
/// spelling makes every candidate < 2^251 by construction, so the loop
/// terminates on the first nonzero draw (probability of even one retry
/// is 2^-251).
fn derive_bounded_scalar(
    domain: &[u8],
    route_seed: &[u8; 32],
    context: &[u8],
) -> Result<Zeroizing<[u8; 32]>, LegBlindingErrorV1> {
    debug_assert!(context.len() <= u8::MAX as usize);
    for counter in 0u8..=7 {
        let mut hasher = Blake2bVar::new(32).map_err(|_| LegBlindingErrorV1::Range)?;
        hasher.update(domain);
        hasher.update(route_seed);
        hasher.update(&[context.len() as u8]);
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
/// routes, directions, or epochs (I4). Both endpoint daemons derive the
/// identical value locally; δ never crosses any wire (I2).
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
    derive_bounded_scalar(LEG_OFFSET_DERIVE_DOMAIN_V1, route_seed, &context).map(LegOffsetV1)
}

/// Derives one leg's own witness for one route.
pub fn derive_leg_witness_v1(
    route_seed: &[u8; 32],
    route_id: &[u8; 32],
    leg: u8,
) -> Result<LegWitnessV1, LegBlindingErrorV1> {
    let mut context = [0u8; 33];
    context[..32].copy_from_slice(route_id);
    context[32] = leg;
    derive_bounded_scalar(LEG_WITNESS_DERIVE_DOMAIN_V1, route_seed, &context).map(LegWitnessV1)
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
/// witness: `w_to = w_from + δ`, over the integers (no modular wrap).
///
/// The result must stay below 2^252 (top four bits clear) to remain a
/// valid cross-curve witness; with honest inputs both operands are below
/// 2^251 and the bound holds by construction, so a violation is proof of
/// a corrupted operand and refuses the route rather than proceeding (I1).
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

/// A leg witness re-expressed as the existing canonical cross-curve
/// secret. Little-endian, as `CrossCurveSecret252::from_little_endian`
/// expects; the [1, 2^252) range is guaranteed by construction here, and
/// that call remains the range authority on the consuming side.
pub fn leg_witness_to_cross_curve_252(witness: &LegWitnessV1) -> Zeroizing<[u8; 32]> {
    let mut little_endian = Zeroizing::new(*witness.expose_big_endian());
    little_endian.reverse();
    little_endian
}

/// Serialized Schnorr PoK of δ for `D = δ·G`, 97 bytes on the wire:
/// 33 (compressed R) ‖ 32 (s) ‖ 32 (binding digest echoed for audit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffsetRelationProofV1 {
    /// Compressed nonce point `R = r·G`.
    pub nonce_point: [u8; 33],
    /// Response scalar `s = r + e·δ (mod q)`, big-endian.
    pub response: [u8; 32],
    /// The composed binding digest the challenge was bound to, echoed so
    /// audits can match a stored proof to its binding without recompute.
    pub binding_digest: [u8; 32],
}

impl OffsetRelationProofV1 {
    /// Exact 97-byte wire form: `nonce_point ‖ response ‖ binding_digest`.
    pub fn to_canonical_bytes(&self) -> [u8; OFFSET_RELATION_PROOF_LEN] {
        let mut out = [0u8; OFFSET_RELATION_PROOF_LEN];
        out[..33].copy_from_slice(&self.nonce_point);
        out[33..65].copy_from_slice(&self.response);
        out[65..].copy_from_slice(&self.binding_digest);
        out
    }

    /// Decode exactly [`OFFSET_RELATION_PROOF_LEN`] bytes; any other
    /// length is refused.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != OFFSET_RELATION_PROOF_LEN {
            return None;
        }
        let mut nonce_point = [0u8; 33];
        let mut response = [0u8; 32];
        let mut binding_digest = [0u8; 32];
        nonce_point.copy_from_slice(&bytes[..33]);
        response.copy_from_slice(&bytes[33..65]);
        binding_digest.copy_from_slice(&bytes[65..]);
        Some(Self {
            nonce_point,
            response,
            binding_digest,
        })
    }
}

/// Fiat–Shamir challenge of the relation proof: BLAKE2b-256(domain ‖
/// role byte ‖ R ‖ D ‖ digest), reduced modulo the group order. The role
/// byte rides in the transcript exactly like DLEQ roles 1..3 do (I5).
fn relation_challenge(
    nonce_point: &Point,
    relation_point: &Point,
    binding_digest: &[u8; 32],
) -> Result<Scalar<Public, Zero>, LegBlindingErrorV1> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| LegBlindingErrorV1::RelationProof)?;
    hasher.update(LEG_OFFSET_RELATION_DOMAIN_V1);
    hasher.update(&[ROLE_LEG_OFFSET_RELATION]);
    hasher.update(&nonce_point.to_bytes());
    hasher.update(&relation_point.to_bytes());
    hasher.update(binding_digest);
    let mut challenge = [0u8; 32];
    hasher
        .finalize_variable(&mut challenge)
        .map_err(|_| LegBlindingErrorV1::RelationProof)?;
    Ok(Scalar::<Public, Zero>::from_bytes_mod_order(challenge))
}

/// Proves knowledge of δ binding `D = δ·G` into `binding_digest`, and
/// returns `D` alongside the proof.
///
/// `delta` must be the exact offset the composed binding commits to; the
/// nonce is derived deterministically from (δ, D, digest) in its own
/// domain (RFC-6979 style), so a broken RNG can never leak δ through
/// nonce reuse (I5).
pub fn prove_offset_relation_v1(
    delta: &LegOffsetV1,
    binding_digest: &[u8; 32],
) -> Result<(Point, OffsetRelationProofV1), LegBlindingErrorV1> {
    let delta_scalar = Scalar::<Secret, Zero>::from_bytes(*delta.0)
        .and_then(|scalar| scalar.non_zero())
        .ok_or(LegBlindingErrorV1::Range)?;
    let relation_point = g!(delta_scalar * G).normalize().public();

    // Deterministic nonce: BLAKE2b-512 over its own domain, truncated to
    // 32 bytes and reduced. Every intermediate zeroizes (I6).
    let mut hasher = Blake2bVar::new(64).map_err(|_| LegBlindingErrorV1::RelationProof)?;
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
    let nonce = Scalar::<Secret, Zero>::from_bytes_mod_order(*narrow)
        .non_zero()
        .ok_or(LegBlindingErrorV1::RelationProof)?;

    let nonce_point = g!(nonce * G).normalize().public();
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
/// `A_to − A_from` from the binding's own committed leg points — never
/// accepted from the prover — or the proof binds nothing (I3;
/// [`relation_point_from_committed_legs`] is that recomputation).
pub fn verify_offset_relation_v1(
    relation_point: &Point,
    proof: &OffsetRelationProofV1,
    expected_binding_digest: &[u8; 32],
) -> Result<(), LegBlindingErrorV1> {
    if &proof.binding_digest != expected_binding_digest {
        return Err(LegBlindingErrorV1::RelationProof);
    }
    let nonce_point: Point =
        Point::from_bytes(proof.nonce_point).ok_or(LegBlindingErrorV1::RelationProof)?;
    let response = Scalar::<Public, Zero>::from_bytes(proof.response)
        .ok_or(LegBlindingErrorV1::RelationProof)?;
    let challenge = relation_challenge(&nonce_point, relation_point, expected_binding_digest)?;
    // s·G == R + e·D
    let lhs = g!(response * G).normalize();
    let rhs = g!(nonce_point + challenge * relation_point).normalize();
    if lhs == rhs {
        Ok(())
    } else {
        Err(LegBlindingErrorV1::RelationProof)
    }
}

/// Recomputes the relation point `D = A_to − A_from` from the two
/// committed per-leg lock points.
///
/// This is the ONLY admissible source of `D` for verification (I3): a
/// prover-supplied `D` binds nothing. Equal leg points yield the identity
/// and refuse — a zero offset defeats the purpose and `δ ∈ [1, 2^251)`
/// makes it impossible honestly (I8).
pub fn relation_point_from_committed_legs(
    to_point_sec1: &[u8; 33],
    from_point_sec1: &[u8; 33],
) -> Result<Point, LegBlindingErrorV1> {
    let to_point: Point =
        Point::from_bytes(*to_point_sec1).ok_or(LegBlindingErrorV1::RelationProof)?;
    let from_point: Point =
        Point::from_bytes(*from_point_sec1).ok_or(LegBlindingErrorV1::RelationProof)?;
    g!(to_point - from_point)
        .normalize()
        .non_zero()
        .ok_or(LegBlindingErrorV1::RelationProof)
}

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
    fn different_routes_and_seeds_derive_different_values() {
        let a = derive_leg_witness_v1(&[7u8; 32], &[9u8; 32], 0).unwrap();
        let b = derive_leg_witness_v1(&[7u8; 32], &[10u8; 32], 0).unwrap();
        let c = derive_leg_witness_v1(&[8u8; 32], &[9u8; 32], 0).unwrap();
        assert_ne!(a.expose_big_endian(), b.expose_big_endian());
        assert_ne!(a.expose_big_endian(), c.expose_big_endian());
    }

    #[test]
    fn translation_stays_in_the_cross_curve_range_and_is_deterministic() {
        let seed = [3u8; 32];
        let route = [4u8; 32];
        let w_from = derive_leg_witness_v1(&seed, &route, 0).unwrap();
        let delta = derive_leg_offset_v1(&seed, &route, 0, 1).unwrap();
        let w_to = translate_witness_v1(&w_from, &delta).unwrap();
        assert!(w_to.expose_big_endian()[0] < 0x10, "< 2^252");
        let again = translate_witness_v1(&w_from, &delta).unwrap();
        assert_eq!(w_to.expose_big_endian(), again.expose_big_endian());
        // The sum really is w_from + δ over the integers: subtracting the
        // offset byte-wise with borrow recovers the exact operand.
        let mut borrow = 0i16;
        let mut recovered = [0u8; 32];
        for i in (0..32).rev() {
            let diff = i16::from(w_to.expose_big_endian()[i]) - i16::from(delta.0[i]) - borrow;
            recovered[i] = (diff & 0xff) as u8;
            borrow = i16::from(diff < 0);
        }
        assert_eq!(borrow, 0, "no borrow out of the top");
        assert_eq!(&recovered, w_from.expose_big_endian());
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
        // tampered nonce point refuses
        let mut bad = proof.clone();
        bad.nonce_point[1] ^= 1;
        assert!(verify_offset_relation_v1(&point, &bad, &digest).is_err());
        // echoed digest is part of the statement
        let mut bad = proof.clone();
        bad.binding_digest[0] ^= 1;
        assert!(verify_offset_relation_v1(&point, &bad, &digest).is_err());
    }

    #[test]
    fn proof_for_one_offset_refuses_against_another_relation_point() {
        let digest = [8u8; 32];
        let delta_a = derive_leg_offset_v1(&[5u8; 32], &[6u8; 32], 0, 1).unwrap();
        let delta_b = derive_leg_offset_v1(&[5u8; 32], &[7u8; 32], 0, 1).unwrap();
        let (_point_a, proof_a) = prove_offset_relation_v1(&delta_a, &digest).unwrap();
        let (point_b, _proof_b) = prove_offset_relation_v1(&delta_b, &digest).unwrap();
        // a forged / prover-supplied D never verifies someone else's proof
        assert!(verify_offset_relation_v1(&point_b, &proof_a, &digest).is_err());
    }

    #[test]
    fn relation_point_is_recomputed_and_equal_legs_refuse() {
        let seed = [11u8; 32];
        let route = [12u8; 32];
        let digest = [13u8; 32];
        let w_from = derive_leg_witness_v1(&seed, &route, 0).unwrap();
        let delta = derive_leg_offset_v1(&seed, &route, 0, 1).unwrap();
        let w_to = translate_witness_v1(&w_from, &delta).unwrap();

        let from_scalar = Scalar::<Secret, Zero>::from_bytes(*w_from.expose_big_endian())
            .and_then(|scalar| scalar.non_zero())
            .unwrap();
        let to_scalar = Scalar::<Secret, Zero>::from_bytes(*w_to.expose_big_endian())
            .and_then(|scalar| scalar.non_zero())
            .unwrap();
        let a_from = g!(from_scalar * G).normalize().public().to_bytes();
        let a_to = g!(to_scalar * G).normalize().public().to_bytes();

        // D recomputed from the committed leg points verifies the proof.
        let recomputed = relation_point_from_committed_legs(&a_to, &a_from).unwrap();
        let (proved, proof) = prove_offset_relation_v1(&delta, &digest).unwrap();
        assert_eq!(recomputed, proved, "A_to − A_from == δ·G");
        verify_offset_relation_v1(&recomputed, &proof, &digest).unwrap();

        // Equal leg points (δ = 0) refuse at recomputation (I8).
        assert!(matches!(
            relation_point_from_committed_legs(&a_from, &a_from),
            Err(LegBlindingErrorV1::RelationProof)
        ));
    }

    /// L1-T6 (transcript half): a proof whose challenge was computed
    /// under a swapped domain or role byte never verifies, even with the
    /// right δ. The forge helper mirrors the prover exactly, so the
    /// canonical spelling passing proves the helper honest.
    #[test]
    fn transcript_domain_or_role_swap_refuses() {
        fn forge(
            delta: &LegOffsetV1,
            digest: &[u8; 32],
            domain: &[u8],
            role: u8,
        ) -> (Point, OffsetRelationProofV1) {
            let delta_scalar = Scalar::<Secret, Zero>::from_bytes(*delta.0)
                .and_then(|scalar| scalar.non_zero())
                .unwrap();
            let relation_point = g!(delta_scalar * G).normalize().public();
            let nonce = Scalar::<Secret, Zero>::from_bytes_mod_order([0x42u8; 32])
                .non_zero()
                .unwrap();
            let nonce_point = g!(nonce * G).normalize().public();
            let mut hasher = Blake2bVar::new(32).unwrap();
            hasher.update(domain);
            hasher.update(&[role]);
            hasher.update(&nonce_point.to_bytes());
            hasher.update(&relation_point.to_bytes());
            hasher.update(digest);
            let mut challenge = [0u8; 32];
            hasher.finalize_variable(&mut challenge).unwrap();
            let challenge = Scalar::<Public, Zero>::from_bytes_mod_order(challenge);
            let response = s!(nonce + challenge * delta_scalar);
            (
                relation_point,
                OffsetRelationProofV1 {
                    nonce_point: nonce_point.to_bytes(),
                    response: response.to_bytes(),
                    binding_digest: *digest,
                },
            )
        }

        let delta = derive_leg_offset_v1(&[5u8; 32], &[6u8; 32], 0, 1).unwrap();
        let digest = [8u8; 32];
        let (point, honest) = forge(
            &delta,
            &digest,
            LEG_OFFSET_RELATION_DOMAIN_V1,
            ROLE_LEG_OFFSET_RELATION,
        );
        verify_offset_relation_v1(&point, &honest, &digest).unwrap();
        let (point, swapped_domain) = forge(
            &delta,
            &digest,
            LEG_WITNESS_DERIVE_DOMAIN_V1,
            ROLE_LEG_OFFSET_RELATION,
        );
        assert!(verify_offset_relation_v1(&point, &swapped_domain, &digest).is_err());
        let (point, swapped_role) = forge(&delta, &digest, LEG_OFFSET_RELATION_DOMAIN_V1, 1);
        assert!(verify_offset_relation_v1(&point, &swapped_role, &digest).is_err());
    }

    /// L1-T11 (module half): `Debug` never exposes secret bytes.
    #[test]
    fn secret_types_debug_is_redacted() {
        let w = derive_leg_witness_v1(&[1u8; 32], &[2u8; 32], 0).unwrap();
        let d = derive_leg_offset_v1(&[1u8; 32], &[2u8; 32], 0, 1).unwrap();
        assert_eq!(format!("{w:?}"), "LegWitnessV1(REDACTED)");
        assert_eq!(format!("{d:?}"), "LegOffsetV1(REDACTED)");
    }

    #[test]
    fn proof_wire_form_round_trips_and_bounds_length() {
        let delta = derive_leg_offset_v1(&[5u8; 32], &[6u8; 32], 0, 1).unwrap();
        let (_, proof) = prove_offset_relation_v1(&delta, &[8u8; 32]).unwrap();
        let bytes = proof.to_canonical_bytes();
        assert_eq!(
            OffsetRelationProofV1::from_canonical_bytes(&bytes).unwrap(),
            proof
        );
        assert!(OffsetRelationProofV1::from_canonical_bytes(&bytes[..96]).is_none());
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
        // feeding into xmr_dleq_sigma::CrossCurveSecret252::from_little_endian
        // is the integration test's business — that call is the range
        // authority on the consuming side.
    }
}
