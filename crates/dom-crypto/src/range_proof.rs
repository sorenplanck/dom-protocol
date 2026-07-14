//! Final DOM confidential-output range proof API.
//!
//! DOM consensus uses one production range-proof architecture: a bounded
//! two-commitment aggregate classic Bulletproof over `(v, MAX_PROVABLE_VALUE-v)`.
//! The backend lives in `bulletproof_bp`; this module is the stable public API
//! used by consensus, node, wallet, slate, and tests.

use crate::bulletproof_bp;
use crate::pedersen::BlindingFactor;
use dom_core::DomError;

/// Consensus serialization version for final DOM range proofs.
pub const RANGE_PROOF_SERIALIZATION_VERSION: u8 = 1;

/// Largest value accepted by the production range-proof prover.
///
/// DOM proves both `v` and `MAX_PROVABLE_VALUE - v` in one aggregate proof, so
/// verification enforces `0 <= v <= MAX_PROVABLE_VALUE`.
pub const MAX_PROVABLE_VALUE: u64 = (1u64 << 52) - 1;

/// Exact byte length of the final DOM range proof.
pub const RANGE_PROOF_SIZE: usize = bulletproof_bp::SINGLE_BULLETPROOF_SIZE;

/// Owned serialized final DOM range proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeProof {
    /// Canonical 739-byte proof bytes.
    pub bytes: Vec<u8>,
}

impl RangeProof {
    /// Construct a final range proof from serialized bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, DomError> {
        if bytes.len() != RANGE_PROOF_SIZE {
            return Err(DomError::Invalid(format!(
                "range proof length {} != {}",
                bytes.len(),
                RANGE_PROOF_SIZE
            )));
        }
        Ok(Self { bytes })
    }

    /// Borrow serialized proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the proof and return serialized bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Prove `value` with a fresh private nonce.
pub fn prove(value: u64, blinding: &BlindingFactor) -> Result<(RangeProof, [u8; 33]), DomError> {
    let (proof, commitment) = bulletproof_bp::bp_prove(value, blinding)?;
    Ok((RangeProof::from_bytes(proof)?, commitment))
}

/// Prove `value` with deterministic nonce input.
///
/// This is required only where consensus byte reproducibility matters, such as
/// deterministic genesis construction and frozen test vectors.
pub fn prove_with_nonce(
    value: u64,
    blinding: &BlindingFactor,
    nonce: &[u8; 32],
) -> Result<(RangeProof, [u8; 33]), DomError> {
    let (proof, commitment) = bulletproof_bp::bp_prove_with_nonce(value, blinding, nonce)?;
    Ok((RangeProof::from_bytes(proof)?, commitment))
}

/// Prove `value` and return serialized proof bytes.
pub fn prove_bytes(value: u64, blinding: &BlindingFactor) -> Result<(Vec<u8>, [u8; 33]), DomError> {
    bulletproof_bp::bp_prove(value, blinding)
}

/// Prove a value while binding immutable application bytes into the proof
/// transcript. The caller must supply identical bytes during verification.
pub fn prove_bytes_with_extra_commit(
    value: u64,
    blinding: &BlindingFactor,
    extra_commit: &[u8],
) -> Result<(Vec<u8>, [u8; 33]), DomError> {
    bulletproof_bp::bp_prove_with_extra_commit(value, blinding, extra_commit)
}

/// Prove `value` with deterministic nonce input and return serialized bytes.
pub fn prove_bytes_with_nonce(
    value: u64,
    blinding: &BlindingFactor,
    nonce: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 33]), DomError> {
    bulletproof_bp::bp_prove_with_nonce(value, blinding, nonce)
}

/// Verify a serialized proof against a SEC1-compressed Pedersen commitment.
pub fn verify(commitment_sec1: &[u8; 33], proof_bytes: &[u8]) -> Result<bool, DomError> {
    bulletproof_bp::bp_verify(commitment_sec1, proof_bytes)
}

/// Verify a proof and immutable application bytes bound into its transcript.
pub fn verify_with_extra_commit(
    commitment_sec1: &[u8; 33],
    proof_bytes: &[u8],
    extra_commit: &[u8],
) -> Result<bool, DomError> {
    bulletproof_bp::bp_verify_with_extra_commit(commitment_sec1, proof_bytes, extra_commit)
}
