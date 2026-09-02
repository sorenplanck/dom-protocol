//! Same-252-bit secp256k1↔ed25519 DLEQ proof used for DOM↔XMR setup.

#![forbid(unsafe_code)]

use std::sync::OnceLock;

use curve25519_dalek_ng::{
    constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, scalar::Scalar,
};
use rand::{CryptoRng, RngCore};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigma_fun::{
    ext::dl_secp256k1_ed25519_eq::{CrossCurveDLEQ, CrossCurveDLEQProof},
    secp256k1::fun::{
        g,
        marker::{EvenY, NonZero, Normal, Public, Secret},
        Point as SecpPoint, Scalar as SecpScalar, G,
    },
    HashTranscript,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum accepted serialized proof bytes before decoding.
pub const MAX_PROOF_BYTES: usize = 256 * 1024;
/// Bound envelope version.
pub const PROOF_VERSION: u16 = 1;
/// Role tag for an XMR shared spend share.
pub const ROLE_XMR_SHARED_SPEND: u8 = 1;
/// Role tag for the refund-side share.
///
/// The claim path and the refund path each carry their own cross-curve secret,
/// and each proof is bound to its own role. A proof minted for one path
/// therefore does not verify for the other, so a counterparty cannot present
/// the refund witness where the claim witness is expected, or the reverse.
pub const ROLE_XMR_REFUND_SHARE: u8 = 2;
/// Role tag for the Solana condition-lock witness.
///
/// Lives here, next to the other roles, because the role space is a single
/// consensus registry: every leg that binds a cross-curve proof draws its
/// byte from this table and nowhere else. The Solana leg originally minted
/// its own byte in its own crate and landed on `2`, colliding with
/// [`ROLE_XMR_REFUND_SHARE`]; the probe in `f8-solana-e2e` showed an XMR
/// refund proof verifying unchanged as a Solana condition-lock proof.
pub const ROLE_SOLANA_CONDITION_LOCK: u8 = 3;

/// The closed role registry. A new leg extends this table in this file, in
/// the same change that introduces its role constant; `roles_are_unique`
/// below refuses a duplicate or zero byte at test time.
pub const ROLES_V1: &[(u8, &str)] = &[
    (ROLE_XMR_SHARED_SPEND, "xmr-shared-spend"),
    (ROLE_XMR_REFUND_SHARE, "xmr-refund-share"),
    (ROLE_SOLANA_CONDITION_LOCK, "solana-condition-lock"),
];
/// Canonical compressed Monero Pedersen H.
pub const MONERO_PEDERSEN_H: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

/// DLEQ failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DleqError {
    /// Witness is zero.
    #[error("cross-curve witness is zero")]
    ZeroSecret,
    /// Witness is not canonical in the common 252-bit domain.
    #[error("cross-curve witness is outside the 252-bit domain")]
    Outside252BitDomain,
    /// Proof system generators could not be initialized.
    #[error("cross-curve proof system initialization failed")]
    Initialization,
    /// Serialized proof exceeds the pre-allocation bound.
    #[error("cross-curve proof exceeds bound")]
    ProofTooLarge,
    /// Proof serialization or decoding failed.
    #[error("cross-curve proof serialization failed")]
    Serialization,
    /// Public secp256k1 point is invalid.
    #[error("invalid secp256k1 claim")]
    InvalidSecpPoint,
    /// Public ed25519 point is invalid or not prime-order.
    #[error("invalid ed25519 claim")]
    InvalidEdPoint,
    /// Proof statement failed.
    #[error("cross-curve proof verification failed")]
    VerificationFailed,
    /// Settlement/profile binding differs.
    #[error("cross-curve proof context mismatch")]
    ContextMismatch,
}

/// One-shot canonical witness. The same integer is used on both curves.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CrossCurveSecret252 {
    little_endian: [u8; 32],
}

impl core::fmt::Debug for CrossCurveSecret252 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CrossCurveSecret252(<redacted>)")
    }
}

impl CrossCurveSecret252 {
    /// Generates a non-zero witness accepted by the 252-bit proof.
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        loop {
            let scalar = Scalar::random(rng);
            let bytes = scalar.to_bytes();
            if scalar != Scalar::zero() && (bytes[31] & 0b0001_0000) == 0 {
                return Self {
                    little_endian: bytes,
                };
            }
        }
    }

    /// Imports a canonical common-domain witness.
    pub fn from_little_endian(bytes: [u8; 32]) -> Result<Self, DleqError> {
        let scalar = Scalar::from_canonical_bytes(bytes).ok_or(DleqError::Outside252BitDomain)?;
        if scalar == Scalar::zero() {
            return Err(DleqError::ZeroSecret);
        }
        if (bytes[31] & 0b0001_0000) != 0 {
            return Err(DleqError::Outside252BitDomain);
        }
        Ok(Self {
            little_endian: bytes,
        })
    }

    fn scalar(&self) -> Result<Scalar, DleqError> {
        Scalar::from_canonical_bytes(self.little_endian).ok_or(DleqError::Outside252BitDomain)
    }

    /// DOM/secp256k1 big-endian bytes.
    pub fn dom_secret_big_endian(&self) -> [u8; 32] {
        let mut bytes = self.little_endian;
        bytes.reverse();
        bytes
    }

    /// XMR/ed25519 canonical little-endian bytes.
    pub fn xmr_share_little_endian(&self) -> [u8; 32] {
        self.little_endian
    }

    /// Public two-curve image of the witness, computed exactly as the
    /// verification side recomputes it in [`revealed_dom_secret_to_xmr_scalar`].
    /// This is a deterministic derivation, not a proof: callers that need a
    /// third party to trust the claim must still carry the DLEQ bundle.
    pub fn public_claim(&self) -> Result<CrossCurvePublicClaim, DleqError> {
        let ed_scalar = self.scalar()?;
        let secp_scalar = SecpScalar::<Secret, NonZero>::from_bytes(self.dom_secret_big_endian())
            .ok_or(DleqError::Outside252BitDomain)?;
        Ok(CrossCurvePublicClaim {
            secp_compressed: g!(secp_scalar * G).normalize().to_bytes(),
            ed_compressed: (&ed_scalar * &ED25519_BASEPOINT_TABLE)
                .compress()
                .to_bytes(),
        })
    }
}

/// Public claim proved by DLEQ.
///
/// Serialization is a manual fixed-width encoding rather than a derive: the
/// SEC1 point is 33 bytes, which `serde` does not implement for arrays, and a
/// consensus-sensitive identity must not depend on a serializer's array
/// representation. The wire form is exactly `secp_compressed || ed_compressed`,
/// 65 bytes, and any other length is refused on decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossCurvePublicClaim {
    /// SEC1 compressed `t*G_secp`; this is DOM's adaptor point.
    pub secp_compressed: [u8; 33],
    /// Compressed `t*G_ed`; this is the remote XMR spend share.
    pub ed_compressed: [u8; 32],
}

/// Fixed wire length of a serialized [`CrossCurvePublicClaim`].
pub const CROSS_CURVE_PUBLIC_CLAIM_LEN: usize = 65;

impl CrossCurvePublicClaim {
    /// Exact 65-byte wire form: `secp_compressed || ed_compressed`.
    pub fn to_canonical_bytes(&self) -> [u8; CROSS_CURVE_PUBLIC_CLAIM_LEN] {
        let mut out = [0u8; CROSS_CURVE_PUBLIC_CLAIM_LEN];
        out[..33].copy_from_slice(&self.secp_compressed);
        out[33..].copy_from_slice(&self.ed_compressed);
        out
    }

    /// Decode exactly [`CROSS_CURVE_PUBLIC_CLAIM_LEN`] bytes; any other length
    /// is refused.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CROSS_CURVE_PUBLIC_CLAIM_LEN {
            return None;
        }
        let mut secp = [0u8; 33];
        let mut ed = [0u8; 32];
        secp.copy_from_slice(&bytes[..33]);
        ed.copy_from_slice(&bytes[33..]);
        Some(Self {
            secp_compressed: secp,
            ed_compressed: ed,
        })
    }
}

impl Serialize for CrossCurvePublicClaim {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_canonical_bytes())
    }
}

impl<'de> Deserialize<'de> for CrossCurvePublicClaim {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ClaimVisitor;
        impl<'de> serde::de::Visitor<'de> for ClaimVisitor {
            type Value = CrossCurvePublicClaim;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "exactly {CROSS_CURVE_PUBLIC_CLAIM_LEN} bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                CrossCurvePublicClaim::from_canonical_bytes(v)
                    .ok_or_else(|| E::invalid_length(v.len(), &self))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut buf = [0u8; CROSS_CURVE_PUBLIC_CLAIM_LEN];
                for (i, slot) in buf.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                // The buffer is already the fixed width; failing closed here
                // costs nothing and leaves no panic path inside a decoder.
                CrossCurvePublicClaim::from_canonical_bytes(&buf)
                    .ok_or_else(|| serde::de::Error::invalid_length(buf.len(), &self))
            }
        }
        deserializer.deserialize_bytes(ClaimVisitor)
    }
}

/// Bounded serialized Sigma proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossCurveProofBytes {
    /// Wire version.
    pub version: u16,
    /// Bincode-encoded `CrossCurveDLEQProof`.
    pub proof: Vec<u8>,
    /// Public statement.
    pub claim: CrossCurvePublicClaim,
}

/// Settlement-bound proof envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundCrossCurveProofV1 {
    /// Envelope version.
    pub version: u16,
    /// One-shot settlement identifier.
    pub settlement_id: [u8; 32],
    /// Domain-separated setup context hash.
    pub context_hash: [u8; 32],
    /// Semantic role.
    pub role: u8,
    /// Underlying proof and claim.
    pub bundle: CrossCurveProofBytes,
}

impl CrossCurveProofBytes {
    /// Stable hash used in setup bindings.
    pub fn proof_hash(&self) -> Result<[u8; 32], DleqError> {
        if self.proof.len() > MAX_PROOF_BYTES {
            return Err(DleqError::ProofTooLarge);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"DOM-INTEROP/XMR-DLEQ-PROOF/V1\0");
        hasher.update(self.version.to_be_bytes());
        hasher.update(self.claim.secp_compressed);
        hasher.update(self.claim.ed_compressed);
        hasher.update((self.proof.len() as u64).to_be_bytes());
        hasher.update(&self.proof);
        Ok(hasher.finalize().into())
    }
}

impl BoundCrossCurveProofV1 {
    /// Stable hash of all public binding fields.
    pub fn binding_hash(&self) -> Result<[u8; 32], DleqError> {
        let mut hasher = Sha256::new();
        hasher.update(b"DOM-INTEROP/XMR-DLEQ-BOUND/V1\0");
        hasher.update(self.version.to_be_bytes());
        hasher.update(self.settlement_id);
        hasher.update(self.context_hash);
        hasher.update([self.role]);
        hasher.update(self.bundle.proof_hash()?);
        Ok(hasher.finalize().into())
    }
}

type Transcript = HashTranscript<Sha256, ChaCha20Rng>;
type ProofSystem = CrossCurveDLEQ<Transcript>;
type SecpPublicPoint = SecpPoint<Normal, Public, NonZero>;

static PROOF_SYSTEM: OnceLock<Result<ProofSystem, DleqError>> = OnceLock::new();

fn build_system() -> Result<ProofSystem, DleqError> {
    let generator = (*G).normalize().to_bytes_uncompressed();
    let x_coordinate: [u8; 32] = Sha256::digest(generator).into();
    let secp_h = SecpPoint::<EvenY>::from_xonly_bytes(x_coordinate)
        .ok_or(DleqError::Initialization)?
        .normalize();
    let ed_h = CompressedEdwardsY(MONERO_PEDERSEN_H)
        .decompress()
        .filter(|point| point.is_torsion_free())
        .ok_or(DleqError::Initialization)?;
    Ok(ProofSystem::new(secp_h, ed_h))
}

fn system() -> Result<&'static ProofSystem, DleqError> {
    match PROOF_SYSTEM.get_or_init(build_system) {
        Ok(value) => Ok(value),
        Err(error) => Err(error.clone()),
    }
}

/// Creates the underlying proof.
pub fn prove(
    secret: &CrossCurveSecret252,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<CrossCurveProofBytes, DleqError> {
    let scalar = secret.scalar()?;
    let (proof, (secp, ed)) = system()?.prove(&scalar, rng);
    let encoded = bincode::serialize(&proof).map_err(|_| DleqError::Serialization)?;
    if encoded.len() > MAX_PROOF_BYTES {
        return Err(DleqError::ProofTooLarge);
    }
    Ok(CrossCurveProofBytes {
        version: PROOF_VERSION,
        proof: encoded,
        claim: CrossCurvePublicClaim {
            secp_compressed: secp.normalize().to_bytes(),
            ed_compressed: ed.compress().to_bytes(),
        },
    })
}

/// Verifies proof and public points.
pub fn verify(bundle: &CrossCurveProofBytes) -> Result<(), DleqError> {
    if bundle.version != PROOF_VERSION {
        return Err(DleqError::VerificationFailed);
    }
    if bundle.proof.len() > MAX_PROOF_BYTES {
        return Err(DleqError::ProofTooLarge);
    }
    let proof: CrossCurveDLEQProof =
        bincode::deserialize(&bundle.proof).map_err(|_| DleqError::Serialization)?;
    let secp = SecpPublicPoint::from_bytes(bundle.claim.secp_compressed)
        .ok_or(DleqError::InvalidSecpPoint)?;
    let ed = CompressedEdwardsY(bundle.claim.ed_compressed)
        .decompress()
        .filter(|point| point.is_torsion_free())
        .ok_or(DleqError::InvalidEdPoint)?;
    if !system()?.verify(&proof, (secp, ed)) {
        return Err(DleqError::VerificationFailed);
    }
    Ok(())
}

/// Creates a settlement/context-bound proof envelope.
pub fn prove_bound(
    secret: &CrossCurveSecret252,
    settlement_id: [u8; 32],
    context_hash: [u8; 32],
    role: u8,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<BoundCrossCurveProofV1, DleqError> {
    if settlement_id == [0; 32] || context_hash == [0; 32] || role == 0 {
        return Err(DleqError::ContextMismatch);
    }
    Ok(BoundCrossCurveProofV1 {
        version: PROOF_VERSION,
        settlement_id,
        context_hash,
        role,
        bundle: prove(secret, rng)?,
    })
}

/// Verifies the bound envelope and returns the public claim.
pub fn verify_bound(
    bound: &BoundCrossCurveProofV1,
    settlement_id: &[u8; 32],
    context_hash: &[u8; 32],
    role: u8,
) -> Result<CrossCurvePublicClaim, DleqError> {
    if bound.version != PROOF_VERSION
        || &bound.settlement_id != settlement_id
        || &bound.context_hash != context_hash
        || bound.role != role
    {
        return Err(DleqError::ContextMismatch);
    }
    verify(&bound.bundle)?;
    Ok(bound.bundle.claim)
}

/// Verifies the revealed DOM scalar against both DLEQ public claims and returns
/// the exact canonical XMR scalar bytes. No modulo reduction is performed.
pub fn revealed_dom_secret_to_xmr_scalar(
    dom_secret_big_endian: [u8; 32],
    claim: &CrossCurvePublicClaim,
) -> Result<[u8; 32], DleqError> {
    let mut little_endian = dom_secret_big_endian;
    little_endian.reverse();
    let secret = CrossCurveSecret252::from_little_endian(little_endian)?;
    let ed_scalar = secret.scalar()?;
    let secp_scalar = SecpScalar::<Secret, NonZero>::from_bytes(dom_secret_big_endian)
        .ok_or(DleqError::Outside252BitDomain)?;
    let expected_secp = g!(secp_scalar * G).normalize().to_bytes();
    let expected_ed = (&ed_scalar * &ED25519_BASEPOINT_TABLE)
        .compress()
        .to_bytes();
    if expected_secp != claim.secp_compressed || expected_ed != claim.ed_compressed {
        return Err(DleqError::VerificationFailed);
    }
    Ok(little_endian)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_unique_and_nonzero() {
        for (index, (byte, name)) in ROLES_V1.iter().enumerate() {
            assert_ne!(*byte, 0, "role {name} uses the reserved zero byte");
            for (other_byte, other_name) in &ROLES_V1[index + 1..] {
                assert_ne!(
                    byte, other_byte,
                    "roles {name} and {other_name} share byte {byte}"
                );
            }
        }
    }

    #[test]
    fn round_trip_and_revelation_match() -> Result<(), DleqError> {
        let mut rng = rand::thread_rng();
        let secret = CrossCurveSecret252::generate(&mut rng);
        let bound = prove_bound(&secret, [1; 32], [2; 32], ROLE_XMR_SHARED_SPEND, &mut rng)?;
        let claim = verify_bound(&bound, &[1; 32], &[2; 32], ROLE_XMR_SHARED_SPEND)?;
        assert_eq!(
            revealed_dom_secret_to_xmr_scalar(secret.dom_secret_big_endian(), &claim)?,
            secret.xmr_share_little_endian(),
        );
        Ok(())
    }

    #[test]
    fn oversized_proof_fails_before_decode() {
        let bundle = CrossCurveProofBytes {
            version: PROOF_VERSION,
            proof: vec![0_u8; MAX_PROOF_BYTES + 1],
            claim: CrossCurvePublicClaim {
                secp_compressed: [2_u8; 33],
                ed_compressed: [0_u8; 32],
            },
        };
        assert_eq!(bundle.proof_hash().unwrap_err(), DleqError::ProofTooLarge);
    }
}
