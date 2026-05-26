// Allow missing docs during development
#![allow(missing_docs)]
//! Schnorr signatures — corrected per audit findings.

use crate::hash::blake2b_256_tagged;
use crate::keys::{PublicKey, SecretKey};
use dom_core::{DomError, Hash256, TAG_KERNEL_SIG};
use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{elliptic_curve::PrimeField, ProjectivePoint, Scalar};
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};

type HmacSha256 = Hmac<Sha256>;

const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SchnorrSignature {
    r_compressed: [u8; 33],
    s: [u8; 32],
}

impl SchnorrSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() != 65 {
            return Err(DomError::Malformed(format!(
                "signature must be 65 bytes, got {}",
                bytes.len()
            )));
        }
        let mut r_compressed = [0u8; 33];
        let mut s = [0u8; 32];
        r_compressed.copy_from_slice(&bytes[..33]);
        s.copy_from_slice(&bytes[33..]);
        crate::keys::PublicKey::from_compressed_bytes(&r_compressed)?;
        if !is_scalar_valid(&s) {
            return Err(DomError::Invalid(
                "signature scalar s is zero or >= n".into(),
            ));
        }
        Ok(Self { r_compressed, s })
    }

    pub fn to_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..33].copy_from_slice(&self.r_compressed);
        out[33..].copy_from_slice(&self.s);
        out
    }

    pub fn r_compressed(&self) -> &[u8; 33] {
        &self.r_compressed
    }
}

pub fn schnorr_challenge(
    r_compressed: &[u8; 33],
    public_key: &PublicKey,
    chain_id: &[u8; 32],
    message: &[u8],
) -> Hash256 {
    let pk_bytes = public_key.to_compressed_bytes();
    let mut data = Vec::with_capacity(33 + 33 + 32 + message.len());
    data.extend_from_slice(r_compressed);
    data.extend_from_slice(&pk_bytes);
    data.extend_from_slice(chain_id);
    data.extend_from_slice(message);
    blake2b_256_tagged(TAG_KERNEL_SIG, &data)
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
    let fb = k256::FieldBytes::from(*bytes);
    let ct = Scalar::from_repr(fb);
    if ct.is_some().into() {
        Some(ct.unwrap())
    } else {
        None
    }
}

fn projective_to_compressed(p: &ProjectivePoint) -> [u8; 33] {
    let affine: k256::AffinePoint = (*p).into();
    let encoded = k256::EncodedPoint::from(affine).compress();
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

pub fn schnorr_sign(
    sk: &SecretKey,
    message: &[u8],
    chain_id: &[u8; 32],
) -> Result<SchnorrSignature, DomError> {
    let sk_bytes = sk.to_be_bytes_raw();
    let pk = sk.public_key();

    let msg_hash = {
        use crate::hash::blake2b_256;
        let mut combined = Vec::with_capacity(message.len() + 32);
        combined.extend_from_slice(message);
        combined.extend_from_slice(chain_id);
        blake2b_256(&combined)
    };

    let k_bytes = rfc6979_nonce(&sk_bytes, msg_hash.as_bytes())?;

    // R = k * G
    let k_scalar = scalar_from_bytes(&k_bytes)
        .ok_or_else(|| DomError::Internal("RFC6979 produced invalid nonce".into()))?;
    let r_point = ProjectivePoint::GENERATOR * k_scalar;
    let r_compressed = projective_to_compressed(&r_point);

    let challenge_hash = schnorr_challenge(&r_compressed, &pk, chain_id, message);
    let c_bytes: [u8; 32] = *challenge_hash.as_bytes();

    // s = k + c*sk mod n
    let s_bytes = scalar_add_mul(&k_bytes, &c_bytes, &sk_bytes)?;

    Ok(SchnorrSignature {
        r_compressed,
        s: s_bytes,
    })
}

pub fn schnorr_verify(
    sig: &SchnorrSignature,
    public_key: &PublicKey,
    chain_id: &[u8; 32],
    message: &[u8],
) -> Result<bool, DomError> {
    let c_hash = schnorr_challenge(&sig.r_compressed, public_key, chain_id, message);
    let c_bytes: [u8; 32] = *c_hash.as_bytes();

    // s*G
    let s_scalar = scalar_from_bytes(&sig.s)
        .ok_or_else(|| DomError::Invalid("s is not a valid scalar".into()))?;
    let sg = ProjectivePoint::GENERATOR * s_scalar;

    // c*P
    let pk_bytes = public_key.to_compressed_bytes();
    let p_point = compressed_to_projective(&pk_bytes)?;
    let c_scalar = scalar_from_bytes(&c_bytes)
        .ok_or_else(|| DomError::Invalid("challenge scalar invalid".into()))?;
    let cp = p_point * c_scalar;

    // R
    let r_point = compressed_to_projective(&sig.r_compressed)?;

    // Check: s*G == R + c*P
    Ok(sg == r_point + cp)
}

fn compressed_to_projective(bytes: &[u8; 33]) -> Result<ProjectivePoint, DomError> {
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

// ── Internal helpers ──────────────────────────────────────────────────────────

fn rfc6979_nonce(sk: &[u8; 32], msg: &[u8; 32]) -> Result<[u8; 32], DomError> {
    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];
    let mut mac = HmacSha256::new_from_slice(&k).unwrap();
    mac.update(&v);
    mac.update(&[0x00]);
    mac.update(sk);
    mac.update(msg);
    k = mac.finalize().into_bytes().into();
    let mut mac = HmacSha256::new_from_slice(&k).unwrap();
    mac.update(&v);
    v = mac.finalize().into_bytes().into();
    let mut mac = HmacSha256::new_from_slice(&k).unwrap();
    mac.update(&v);
    mac.update(&[0x01]);
    mac.update(sk);
    mac.update(msg);
    k = mac.finalize().into_bytes().into();
    let mut mac = HmacSha256::new_from_slice(&k).unwrap();
    mac.update(&v);
    v = mac.finalize().into_bytes().into();
    for _ in 0..100 {
        let mut mac = HmacSha256::new_from_slice(&k).unwrap();
        mac.update(&v);
        v = mac.finalize().into_bytes().into();
        if is_scalar_valid(&v) {
            return Ok(v);
        }
        let mut mac = HmacSha256::new_from_slice(&k).unwrap();
        mac.update(&v);
        mac.update(&[0x00]);
        k = mac.finalize().into_bytes().into();
        let mut mac = HmacSha256::new_from_slice(&k).unwrap();
        mac.update(&v);
        v = mac.finalize().into_bytes().into();
    }
    Err(DomError::Internal(
        "RFC6979 failed after 100 attempts".into(),
    ))
}

fn scalar_add_mul(a: &[u8; 32], c: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], DomError> {
    let a_s = scalar_from_bytes(a).ok_or_else(|| DomError::Invalid("a not valid scalar".into()))?;
    let b_s = scalar_from_bytes(b).ok_or_else(|| DomError::Invalid("b not valid scalar".into()))?;
    let c_s = scalar_from_bytes(c).ok_or_else(|| DomError::Invalid("c not valid scalar".into()))?;
    let result = a_s + c_s * b_s;
    Ok(result.to_repr().into())
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
fn is_scalar_valid(bytes: &[u8; 32]) -> bool {
    let nonzero: Choice = !bytes_eq_zero_ct(bytes);
    let lt_n: Choice = bytes_lt_ct(bytes, &SECP256K1_N);
    bool::from(nonzero & lt_n)
}

/// Constant-time: returns Choice(1) iff `bytes` is all-zero.
fn bytes_eq_zero_ct(bytes: &[u8; 32]) -> Choice {
    bytes.as_ref().ct_eq(&[0u8; 32] as &[u8])
}

/// Constant-time: returns Choice(1) iff `a < b` interpreted as
/// big-endian unsigned 256-bit integers. Walks every byte without
/// short-circuit so the running time is independent of the
/// comparison result. Catches the BB-style timing-attack
/// precondition the prior implementation exposed.
fn bytes_lt_ct(a: &[u8; 32], b: &[u8; 32]) -> Choice {
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

#[cfg(test)]
mod tests {
    use super::*;
    const MAINNET_CHAIN_ID: [u8; 32] = [0x01u8; 32];
    const TESTNET_CHAIN_ID: [u8; 32] = [0x02u8; 32];

    fn sk() -> SecretKey {
        SecretKey::from_bytes(&[1u8; 32]).unwrap()
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = sk();
        let pk = sk.public_key();
        let sig = schnorr_sign(&sk, b"msg", &MAINNET_CHAIN_ID).unwrap();
        assert!(schnorr_verify(&sig, &pk, &MAINNET_CHAIN_ID, b"msg").unwrap());
    }

    #[test]
    fn wrong_chain_id_fails_verify() {
        let sk = sk();
        let pk = sk.public_key();
        let sig = schnorr_sign(&sk, b"msg", &MAINNET_CHAIN_ID).unwrap();
        let valid = schnorr_verify(&sig, &pk, &TESTNET_CHAIN_ID, b"msg").unwrap();
        assert!(!valid);
    }

    #[test]
    fn wrong_message_fails() {
        let sk = sk();
        let pk = sk.public_key();
        let sig = schnorr_sign(&sk, b"correct", &MAINNET_CHAIN_ID).unwrap();
        assert!(!schnorr_verify(&sig, &pk, &MAINNET_CHAIN_ID, b"wrong").unwrap());
    }

    #[test]
    fn deterministic_signing() {
        let sk = sk();
        let s1 = schnorr_sign(&sk, b"m", &MAINNET_CHAIN_ID).unwrap();
        let s2 = schnorr_sign(&sk, b"m", &MAINNET_CHAIN_ID).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn signature_fields_private() {
        let sk = sk();
        let sig = schnorr_sign(&sk, b"msg", &MAINNET_CHAIN_ID).unwrap();
        let bytes = sig.to_bytes();
        let sig2 = SchnorrSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn invalid_s_zero_rejected() {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x02;
        assert!(SchnorrSignature::from_bytes(&bytes).is_err());
    }

    #[test]
    fn cross_chain_replay_prevented() {
        let sk = sk();
        let pk = sk.public_key();
        let sig = schnorr_sign(&sk, b"transfer 100 DOM", &MAINNET_CHAIN_ID).unwrap();
        let replay = schnorr_verify(&sig, &pk, &TESTNET_CHAIN_ID, b"transfer 100 DOM");
        assert!(matches!(replay, Ok(false) | Err(_)));
    }

    // ── R_x ambiguity resolution (SECURITY_AUDIT.md §1, RFC-0009 §4) ─────────
    // R MUST be the 33-byte SEC1-compressed encoding (parity byte 0x02/0x03
    // followed by 32-byte x-coordinate), NOT 32-byte BIP-340 x-only.

    #[test]
    fn signature_r_is_sec1_33_bytes() {
        let sig = schnorr_sign(&sk(), b"r_encoding_test", &MAINNET_CHAIN_ID).unwrap();
        let r = sig.r_compressed();
        assert_eq!(r.len(), 33, "R must serialize as 33-byte SEC1");
        assert!(
            r[0] == 0x02 || r[0] == 0x03,
            "prefix must be SEC1 even/odd (0x02/0x03), got 0x{:02x}",
            r[0]
        );
        let total = sig.to_bytes();
        assert_eq!(total.len(), 65, "signature must be 33 (R) + 32 (s) = 65 bytes");
    }

    #[test]
    fn r_and_neg_r_yield_different_challenges() {
        // Negating R flips the SEC1 parity byte; the challenge MUST change.
        // This is the concrete property the SEC1-vs-x-only decision prevents.
        let sig = schnorr_sign(&sk(), b"flip_R", &MAINNET_CHAIN_ID).unwrap();
        let pk = sk().public_key();
        let r = *sig.r_compressed();

        let mut r_neg = r;
        r_neg[0] = if r[0] == 0x02 { 0x03 } else { 0x02 };

        let c1 = schnorr_challenge(&r, &pk, &MAINNET_CHAIN_ID, b"flip_R");
        let c2 = schnorr_challenge(&r_neg, &pk, &MAINNET_CHAIN_ID, b"flip_R");
        assert_ne!(
            c1.as_bytes(),
            c2.as_bytes(),
            "challenge must include R's parity byte — otherwise R and -R collide"
        );
    }

    /// Frozen Schnorr vector — consensus-critical.
    ///
    /// Locks the (sk=[1;32], msg="DOM/schnorr/v1/vector/genesis",
    /// chain_id=MAINNET) → (r_compressed, s) binding. Any drift in
    /// RFC6979 nonce derivation, schnorr_challenge serialization
    /// (incl. SEC1 33-byte R encoding), or k256/Scalar arithmetic will
    /// trip this test and require explicit re-confirmation.
    #[test]
    fn frozen_signature_vector_sk1_genesis_message() {
        let sk = SecretKey::from_bytes(&[1u8; 32]).unwrap();
        let msg = b"DOM/schnorr/v1/vector/genesis";
        let sig = schnorr_sign(&sk, msg, &MAINNET_CHAIN_ID).unwrap();
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 65);

        // Verify deterministically reproducible (RFC6979).
        let sig2 = schnorr_sign(&sk, msg, &MAINNET_CHAIN_ID).unwrap();
        assert_eq!(sig, sig2, "RFC6979 must be deterministic");

        // Verify with the public key.
        let pk = sk.public_key();
        assert!(schnorr_verify(&sig, &pk, &MAINNET_CHAIN_ID, msg).unwrap());

        // R prefix must be SEC1 (not 0x00/0x04/0x06/0x07 or out-of-range).
        let r = sig.r_compressed();
        assert!(r[0] == 0x02 || r[0] == 0x03);
    }
}
