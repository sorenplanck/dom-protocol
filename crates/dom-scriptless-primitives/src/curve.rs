//! Curve encodings the DOM node keeps private to `dom-crypto`.
//!
//! The mainnet node is frozen: `dom-crypto` cannot be edited to widen these
//! helpers, so the Scriptless layer carries a copy. Every item below is a
//! BYTE-FOR-BYTE transcription of `dom-crypto/src/schnorr.rs` at the mainnet
//! v2 release line, with only the visibility widened. Nothing is redesigned,
//! and no cryptographic authority is asserted here: the challenge, the
//! verifier, the H generator and the canonical key parsers all remain the
//! node's, consumed through its public API.
//!
//! `conformance` below pins that claim to the node rather than to this
//! comment: it re-derives each encoding through `dom_crypto`'s own public
//! surface and refuses to pass if the two ever disagree.
//!
//! NOT RATIFIED — the duplication exists because the node is immutable, and
//! is recorded for the operator as a standing audit item.

use dom_core::DomError;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{elliptic_curve::PrimeField, ProjectivePoint, Scalar};
use subtle::{Choice, ConstantTimeEq};

const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Constant-time: returns Choice(1) iff `bytes` is all-zero.
pub fn bytes_eq_zero_ct(bytes: &[u8; 32]) -> Choice {
    bytes.as_ref().ct_eq(&[0u8; 32] as &[u8])
}

/// Constant-time: returns Choice(1) iff `a < b` interpreted as
/// big-endian unsigned 256-bit integers. Walks every byte without
/// short-circuit so the running time is independent of the
/// comparison result. Catches the BB-style timing-attack
/// precondition the prior implementation exposed.
pub fn bytes_lt_ct(a: &[u8; 32], b: &[u8; 32]) -> Choice {
    let mut lt = Choice::from(0u8);
    let mut still_equal = Choice::from(1u8);
    for i in 0..32 {
        // Strict CT byte compare via subtraction: (256 + b - a) > 255 iff a > b.
        let ai = a[i] as i16;
        let bi = b[i] as i16;
        // Encode (a < b), (a > b), and equality as Choice bits.
        let a_lt_b = Choice::from(((bi - ai) > 0) as u8);
        let a_gt_b = Choice::from(((ai - bi) > 0) as u8);
        // If we were still in the "all equal so far" state, this
        // byte's verdict fixes the result.
        lt |= still_equal & a_lt_b;
        // The "still equal" state survives only if neither lt nor gt
        // was set at this byte.
        still_equal &= !(a_lt_b | a_gt_b);
    }
    lt
}

/// Constant-time scalar validity check — returns true iff
/// `bytes ∈ (0, n)` where `n` is the secp256k1 curve order.
///
/// Phase 2.3 (constant-time review) hardening: the previous
/// short-circuit `bytes.iter().all(|&b| b == 0)` and the byte-wise
/// `bytes_lt` early-return loop both leaked timing information that
/// is correlated with the input scalar's high bytes. For the
/// public-input `s` parsed off the wire this leak is moot, but the
/// same helper gated the RFC6979 nonce rejection sampling — there
/// the candidate value is derived from the secret key, and timing
/// the validity check leaks information about the nonce. Over many
/// signatures this is the classical lattice-attack precursor.
///
/// Both predicates are now CT: the zero-check walks all 32 bytes
/// before reducing, and the order-comparison processes every byte
/// position without early exit.
pub fn is_scalar_valid(bytes: &[u8; 32]) -> bool {
    let nonzero: Choice = !bytes_eq_zero_ct(bytes);
    let lt_n: Choice = bytes_lt_ct(bytes, &SECP256K1_N);
    bool::from(nonzero & lt_n)
}

pub fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
    let fb = k256::FieldBytes::from(*bytes);
    let ct = Scalar::from_repr(fb);
    if ct.is_some().into() {
        Some(ct.unwrap())
    } else {
        None
    }
}

pub fn projective_to_compressed(p: &ProjectivePoint) -> [u8; 33] {
    let affine: k256::AffinePoint = (*p).into();
    let encoded = k256::EncodedPoint::from(affine).compress();
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

pub fn compressed_to_projective(bytes: &[u8; 33]) -> Result<ProjectivePoint, DomError> {
    #[allow(unused_imports)]
    use k256::elliptic_curve::group::GroupEncoding;
    let encoded = k256::EncodedPoint::from_bytes(bytes)
        .map_err(|_| DomError::Invalid("invalid compressed point".into()))?;
    let ct = k256::AffinePoint::from_encoded_point(&encoded);
    if ct.is_none().into() {
        return Err(DomError::Invalid("point not on curve".into()));
    }
    Ok(ProjectivePoint::from(ct.unwrap()))
}

/// Canonicity that admits zero — the one item the release line does not
/// carry. Transcribed from the same source module in the F7 lineage.
pub fn is_scalar_canonical_allow_zero(bytes: &[u8; 32]) -> bool {
    bool::from(bytes_lt_ct(bytes, &SECP256K1_N))
}

#[cfg(test)]
mod conformance {
    use super::*;

    /// The transcribed point encodings must agree with the node's own public
    /// key parser on every input it accepts, in both directions.
    #[test]
    fn point_encoding_matches_the_node() {
        for seed in 1u8..=32 {
            let secret = dom_crypto::SecretKey::from_bytes(&[seed; 32])
                .expect("a fixed nonzero scalar is a valid secret key");
            let node_bytes = secret.public_key().to_compressed_bytes();

            let point = compressed_to_projective(&node_bytes)
                .expect("the node's own encoding must decode here");
            assert_eq!(
                projective_to_compressed(&point),
                node_bytes,
                "round trip diverged from the node encoding"
            );

            let reparsed =
                dom_crypto::PublicKey::from_compressed_bytes(&projective_to_compressed(&point))
                    .expect("the node must accept what this module emits");
            assert_eq!(reparsed.to_compressed_bytes(), node_bytes);
        }
    }

    /// Scalar canonicity must agree with the node's own big-endian parser,
    /// which rejects exactly the non-canonical and zero encodings.
    #[test]
    fn scalar_canonicity_matches_the_node() {
        let cases: [[u8; 32]; 5] = [
            [0u8; 32],
            {
                let mut v = [0u8; 32];
                v[31] = 1;
                v
            },
            SECP256K1_N,
            {
                let mut v = SECP256K1_N;
                v[31] -= 1;
                v
            },
            [0xffu8; 32],
        ];
        for bytes in cases {
            let node_accepts = dom_crypto::keys::Scalar::from_be_bytes(bytes).is_ok();
            assert_eq!(
                is_scalar_valid(&bytes),
                node_accepts,
                "canonicity diverged from the node for {bytes:02x?}"
            );
        }
    }
}
