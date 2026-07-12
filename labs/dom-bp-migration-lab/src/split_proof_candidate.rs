//! Laboratory-only versioned split-proof candidate. Not production code.

#![allow(unsafe_code)]

use dom_crypto::{derive_h_generator, pedersen::Commitment, BlindingFactor};
use k256::{
    elliptic_curve::{
        group::prime::PrimeCurveAffine,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        PrimeField,
    },
    AffinePoint, EncodedPoint, FieldElement, ProjectivePoint, Scalar,
};
use secp256k1zkp::{constants, ffi};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::os::raw::{c_int, c_uchar};
use std::ptr;
use thiserror::Error;
use zeroize::Zeroize;

use crate::protocol::MAX_PROVABLE_VALUE;

pub const SPLIT_PROOF_VERSION: u8 = 1;
/// Classic Grin Bulletproof, `nbits=64`, `n_commits=1`.
pub const SINGLE_PROOF_LEN: usize = 675;
pub const SPLIT_PROOF_ENVELOPE_LEN: usize = 1 + (2 * SINGLE_PROOF_LEN);
pub const RECOVERY_METADATA_LEN: usize = 20;
pub const METADATA_OUTPUT_VERSION: u8 = 1;
pub const METADATA_NETWORK_ID: u8 = 42;
const SCRATCH_SIZE: usize = 1 << 20;
const P1_NONCE_DOMAIN: &[u8] = b"DOM:L2D:split-proof:p1-nonce:v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LabError {
    #[error("split proof envelope is malformed")]
    MalformedEnvelope,
    #[error("split proof envelope has an unknown version")]
    UnknownVersion,
    #[error("value exceeds the DOM maximum provable value")]
    ValueAboveMaximum,
    #[error("blinding factor is invalid")]
    InvalidBlinding,
    #[error("commitment is malformed")]
    MalformedCommitment,
    #[error("metadata is non-canonical")]
    InvalidMetadata,
    #[error("classic Bulletproof backend rejected proof generation")]
    BackendProve,
    #[error("classic Bulletproof backend setup failed")]
    BackendSetup,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalMetadata([u8; RECOVERY_METADATA_LEN]);

impl CanonicalMetadata {
    pub fn new(account: u32, branch: u8, index: u32) -> Result<Self, LabError> {
        if branch > 1 {
            return Err(LabError::InvalidMetadata);
        }
        let mut bytes = [0_u8; RECOVERY_METADATA_LEN];
        bytes[0] = METADATA_OUTPUT_VERSION;
        bytes[1] = METADATA_NETWORK_ID;
        bytes[2..6].copy_from_slice(&account.to_be_bytes());
        bytes[6] = branch;
        bytes[7..11].copy_from_slice(&index.to_be_bytes());
        let digest = metadata_digest(&bytes[..11]);
        bytes[11..20].copy_from_slice(&digest);
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; RECOVERY_METADATA_LEN]) -> Result<Self, LabError> {
        if bytes[0] != METADATA_OUTPUT_VERSION || bytes[1] != METADATA_NETWORK_ID || bytes[6] > 1 {
            return Err(LabError::InvalidMetadata);
        }
        if bytes[11..20] != metadata_digest(&bytes[..11]) {
            return Err(LabError::InvalidMetadata);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; RECOVERY_METADATA_LEN] {
        &self.0
    }
}

fn metadata_digest(prefix: &[u8]) -> [u8; 9] {
    let mut hasher = Sha256::new();
    hasher.update(b"DOM:L2D:metadata:v1");
    hasher.update(prefix);
    let digest = hasher.finalize();
    let mut result = [0_u8; 9];
    result.copy_from_slice(&digest[..9]);
    result
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitProofEnvelope {
    pub primary_proof: [u8; SINGLE_PROOF_LEN],
    pub complement_proof: [u8; SINGLE_PROOF_LEN],
}

impl SplitProofEnvelope {
    pub fn encode(&self) -> [u8; SPLIT_PROOF_ENVELOPE_LEN] {
        let mut bytes = [0_u8; SPLIT_PROOF_ENVELOPE_LEN];
        bytes[0] = SPLIT_PROOF_VERSION;
        bytes[1..1 + SINGLE_PROOF_LEN].copy_from_slice(&self.primary_proof);
        bytes[1 + SINGLE_PROOF_LEN..].copy_from_slice(&self.complement_proof);
        bytes
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, LabError> {
        if bytes.len() != SPLIT_PROOF_ENVELOPE_LEN {
            return Err(LabError::MalformedEnvelope);
        }
        if bytes[0] != SPLIT_PROOF_VERSION {
            return Err(LabError::UnknownVersion);
        }
        let mut primary_proof = [0_u8; SINGLE_PROOF_LEN];
        let mut complement_proof = [0_u8; SINGLE_PROOF_LEN];
        primary_proof.copy_from_slice(&bytes[1..1 + SINGLE_PROOF_LEN]);
        complement_proof.copy_from_slice(&bytes[1 + SINGLE_PROOF_LEN..]);
        Ok(Self {
            primary_proof,
            complement_proof,
        })
    }
}

#[derive(Clone, Debug)]
pub struct RecoveredOutput {
    pub value: u64,
    pub blinding: BlindingFactor,
    pub metadata: CanonicalMetadata,
}

type RawRewind = (u64, [u8; 32], [u8; RECOVERY_METADATA_LEN]);

mod ffi_extra {
    use super::*;

    unsafe extern "C" {
        pub fn secp256k1_generator_parse(
            ctx: *const ffi::Context,
            gen64_out: *mut c_uchar,
            input33: *const c_uchar,
        ) -> c_int;
    }
}

pub fn prove_split_output(
    value: u64,
    blinding: &BlindingFactor,
    recovery_nonce: &[u8; 32],
    metadata: CanonicalMetadata,
) -> Result<([u8; 33], [u8; SPLIT_PROOF_ENVELOPE_LEN]), LabError> {
    if value > MAX_PROVABLE_VALUE {
        return Err(LabError::ValueAboveMaximum);
    }
    let complement_value = MAX_PROVABLE_VALUE - value;
    let complement_blind = negate_blinding(blinding)?;
    let c0 = Commitment::commit(value, blinding);
    let c1 = Commitment::commit(complement_value, &complement_blind);
    if complement_from_c0(c0.as_bytes())? != *c1.as_bytes() {
        return Err(LabError::MalformedCommitment);
    }

    let p1_nonce = derive_p1_nonce(recovery_nonce);
    let primary_proof = with_backend(|backend| {
        backend.prove(
            value,
            blinding,
            recovery_nonce,
            recovery_nonce,
            Some(metadata.as_bytes()),
        )
    })?;
    let complement_proof = with_backend(|backend| {
        backend.prove(
            complement_value,
            &complement_blind,
            &p1_nonce,
            &p1_nonce,
            None,
        )
    })?;
    let envelope = SplitProofEnvelope {
        primary_proof,
        complement_proof,
    }
    .encode();
    Ok((*c0.as_bytes(), envelope))
}

pub fn verify_split_output(
    commitment_c0: &[u8; 33],
    envelope_bytes: &[u8],
) -> Result<bool, LabError> {
    let envelope = SplitProofEnvelope::parse(envelope_bytes)?;
    let c1 = complement_from_c0(commitment_c0)?;
    with_backend(|backend| {
        Ok(backend.verify(commitment_c0, &envelope.primary_proof)
            && backend.verify(&c1, &envelope.complement_proof))
    })
}

/// Laboratory diagnostic for tests; it exposes only boolean verification
/// outcomes and no witness material.
pub fn verify_split_components_for_test(
    commitment_c0: &[u8; 33],
    envelope_bytes: &[u8],
) -> Result<(bool, bool), LabError> {
    let envelope = SplitProofEnvelope::parse(envelope_bytes)?;
    let c1 = complement_from_c0(commitment_c0)?;
    with_backend(|backend| {
        Ok((
            backend.verify(commitment_c0, &envelope.primary_proof),
            backend.verify(&c1, &envelope.complement_proof),
        ))
    })
}

pub fn recover_split_output(
    commitment_c0: &[u8; 33],
    envelope_bytes: &[u8],
    recovery_nonce: &[u8; 32],
) -> Result<Option<RecoveredOutput>, LabError> {
    let envelope = SplitProofEnvelope::parse(envelope_bytes)?;
    let c1 = complement_from_c0(commitment_c0)?;
    // Full verification precedes every extraction. The upstream rewind routine
    // itself reads only the proof header and is not a complete verifier.
    let verified = with_backend(|backend| {
        Ok(backend.verify(commitment_c0, &envelope.primary_proof)
            && backend.verify(&c1, &envelope.complement_proof))
    })?;
    if !verified {
        return Ok(None);
    }
    let Some((value, blind_bytes, metadata_bytes)) = with_backend(|backend| {
        backend.rewind(commitment_c0, &envelope.primary_proof, recovery_nonce)
    })?
    else {
        return Ok(None);
    };
    let mut blind_bytes = blind_bytes;
    let result = (|| {
        if value > MAX_PROVABLE_VALUE {
            return Ok(None);
        }
        let blinding =
            BlindingFactor::from_bytes(blind_bytes).map_err(|_| LabError::InvalidBlinding)?;
        let metadata = match CanonicalMetadata::from_bytes(metadata_bytes) {
            Ok(metadata) => metadata,
            Err(_) => return Ok(None),
        };
        let recomputed_c0 = Commitment::commit(value, &blinding);
        if recomputed_c0.as_bytes() != commitment_c0 {
            return Ok(None);
        }
        let complement_value = MAX_PROVABLE_VALUE - value;
        let complement_blind = negate_blinding(&blinding)?;
        let recomputed_c1 = Commitment::commit(complement_value, &complement_blind);
        if recomputed_c1.as_bytes() != &c1 {
            return Ok(None);
        }
        Ok(Some(RecoveredOutput {
            value,
            blinding,
            metadata,
        }))
    })();
    blind_bytes.zeroize();
    result
}

/// Laboratory regression hook for the nonce/private-nonce mismatch contract.
pub fn prove_single_with_distinct_nonces_for_test(
    value: u64,
    blinding: &BlindingFactor,
    nonce: &[u8; 32],
    private_nonce: &[u8; 32],
    metadata: &CanonicalMetadata,
) -> Result<([u8; 33], [u8; SINGLE_PROOF_LEN]), LabError> {
    let proof = with_backend(|backend| {
        backend.prove(
            value,
            blinding,
            nonce,
            private_nonce,
            Some(metadata.as_bytes()),
        )
    })?;
    Ok((*Commitment::commit(value, blinding).as_bytes(), proof))
}

pub fn rewind_single_for_test(
    commitment: &[u8; 33],
    proof: &[u8; SINGLE_PROOF_LEN],
    nonce: &[u8; 32],
) -> Result<Option<RawRewind>, LabError> {
    with_backend(|backend| backend.rewind(commitment, proof, nonce))
}

fn derive_p1_nonce(recovery_nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(P1_NONCE_DOMAIN);
    hasher.update(recovery_nonce);
    hasher.finalize().into()
}

fn negate_blinding(blinding: &BlindingFactor) -> Result<BlindingFactor, LabError> {
    let scalar = Option::<Scalar>::from(Scalar::from_repr((*blinding.as_bytes()).into()))
        .ok_or(LabError::InvalidBlinding)?;
    BlindingFactor::from_bytes((-scalar).to_bytes().into()).map_err(|_| LabError::InvalidBlinding)
}

fn complement_from_c0(c0: &[u8; 33]) -> Result<[u8; 33], LabError> {
    let c0 = Commitment::from_compressed_bytes(c0).map_err(|_| LabError::MalformedCommitment)?;
    let encoded =
        EncodedPoint::from_bytes(c0.as_bytes()).map_err(|_| LabError::MalformedCommitment)?;
    let c0_affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or(LabError::MalformedCommitment)?;
    let h_bytes = derive_h_generator().map_err(|_| LabError::BackendSetup)?;
    let h_encoded = EncodedPoint::from_bytes(h_bytes).map_err(|_| LabError::BackendSetup)?;
    let h_affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&h_encoded))
        .ok_or(LabError::BackendSetup)?;
    let result: AffinePoint = (ProjectivePoint::from(h_affine) * Scalar::from(MAX_PROVABLE_VALUE)
        - ProjectivePoint::from(c0_affine))
    .into();
    if bool::from(result.is_identity()) {
        return Err(LabError::MalformedCommitment);
    }
    let compressed = EncodedPoint::from(result).compress();
    let mut bytes = [0_u8; 33];
    bytes.copy_from_slice(compressed.as_bytes());
    Ok(bytes)
}

/// Converts DOM external SEC1 encoding to the zkp Pedersen encoding expected
/// by the Grin FFI. Only the prefix changes; it encodes the quadratic class of
/// the affine Y coordinate.
fn sec1_to_zkp_commitment(sec1: &[u8; 33]) -> Result<[u8; 33], LabError> {
    let encoded = EncodedPoint::from_bytes(sec1).map_err(|_| LabError::MalformedCommitment)?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or(LabError::MalformedCommitment)?;
    let uncompressed = affine.to_encoded_point(false);
    let y: [u8; 32] = uncompressed.as_bytes()[33..65]
        .try_into()
        .map_err(|_| LabError::MalformedCommitment)?;
    let y_field = Option::<FieldElement>::from(FieldElement::from_bytes(&y.into()))
        .ok_or(LabError::MalformedCommitment)?;
    let mut zkp = *sec1;
    zkp[0] = if bool::from(y_field.sqrt().is_some()) {
        0x08
    } else {
        0x09
    };
    Ok(zkp)
}

struct RawSingleBackend {
    ctx: *mut ffi::Context,
    gens: *mut ffi::BulletproofGenerators,
}

thread_local! {
    static RAW_SINGLE_BACKEND: RefCell<Option<RawSingleBackend>> = const { RefCell::new(None) };
}

fn with_backend<T>(
    operation: impl FnOnce(&RawSingleBackend) -> Result<T, LabError>,
) -> Result<T, LabError> {
    RAW_SINGLE_BACKEND.with(|slot| {
        if slot.borrow().is_none() {
            *slot.borrow_mut() = Some(RawSingleBackend::new()?);
        }
        let backend = slot.borrow();
        operation(backend.as_ref().expect("backend initialized"))
    })
}

impl RawSingleBackend {
    fn new() -> Result<Self, LabError> {
        let ctx = unsafe {
            ffi::secp256k1_context_create(ffi::SECP256K1_START_SIGN | ffi::SECP256K1_START_VERIFY)
        };
        if ctx.is_null() {
            return Err(LabError::BackendSetup);
        }
        let gens = unsafe {
            ffi::secp256k1_bulletproof_generators_create(ctx, constants::GENERATOR_G.as_ptr(), 256)
        };
        if gens.is_null() {
            unsafe { ffi::secp256k1_context_destroy(ctx) };
            return Err(LabError::BackendSetup);
        }
        Ok(Self { ctx, gens })
    }

    fn h_dom_internal(&self) -> Result<[u8; 64], LabError> {
        let mut compressed = derive_h_generator().map_err(|_| LabError::BackendSetup)?;
        compressed[0] = match compressed[0] {
            0x02 => 0x0a,
            0x03 => 0x0b,
            _ => return Err(LabError::BackendSetup),
        };
        let mut internal = [0_u8; 64];
        let ok = unsafe {
            ffi_extra::secp256k1_generator_parse(
                self.ctx,
                internal.as_mut_ptr(),
                compressed.as_ptr(),
            )
        };
        if ok == 1 {
            Ok(internal)
        } else {
            Err(LabError::BackendSetup)
        }
    }

    fn prove(
        &self,
        value: u64,
        blinding: &BlindingFactor,
        nonce: &[u8; 32],
        private_nonce: &[u8; 32],
        metadata: Option<&[u8; RECOVERY_METADATA_LEN]>,
    ) -> Result<[u8; SINGLE_PROOF_LEN], LabError> {
        let h_dom = self.h_dom_internal()?;
        let mut proof = [0_u8; constants::MAX_PROOF_SIZE];
        let mut plen = proof.len();
        let blind_ptr = blinding.as_bytes().as_ptr();
        let scratch = unsafe { ffi::secp256k1_scratch_space_create(self.ctx, SCRATCH_SIZE) };
        if scratch.is_null() {
            return Err(LabError::BackendSetup);
        }
        let message_ptr = metadata.map_or(ptr::null(), |message| message.as_ptr());
        let ok = unsafe {
            ffi::secp256k1_bulletproof_rangeproof_prove(
                self.ctx,
                scratch,
                self.gens,
                proof.as_mut_ptr(),
                &mut plen,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &value,
                ptr::null(),
                &blind_ptr,
                ptr::null(),
                1,
                h_dom.as_ptr(),
                64,
                nonce.as_ptr(),
                private_nonce.as_ptr(),
                ptr::null(),
                0,
                message_ptr,
            )
        };
        unsafe { ffi::secp256k1_scratch_space_destroy(scratch) };
        if ok != 1 || plen != SINGLE_PROOF_LEN {
            return Err(LabError::BackendProve);
        }
        let mut output = [0_u8; SINGLE_PROOF_LEN];
        output.copy_from_slice(&proof[..SINGLE_PROOF_LEN]);
        proof.zeroize();
        Ok(output)
    }

    fn verify(&self, commitment: &[u8; 33], proof: &[u8; SINGLE_PROOF_LEN]) -> bool {
        let Ok(h_dom) = self.h_dom_internal() else {
            return false;
        };
        let mut commit = [0_u8; 64];
        let Ok(zkp_commitment) = sec1_to_zkp_commitment(commitment) else {
            return false;
        };
        if unsafe {
            ffi::secp256k1_pedersen_commitment_parse(
                self.ctx,
                commit.as_mut_ptr(),
                zkp_commitment.as_ptr(),
            )
        } != 1
        {
            return false;
        }
        let scratch = unsafe { ffi::secp256k1_scratch_space_create(self.ctx, SCRATCH_SIZE) };
        if scratch.is_null() {
            return false;
        }
        let ok = unsafe {
            ffi::secp256k1_bulletproof_rangeproof_verify(
                self.ctx,
                scratch,
                self.gens,
                proof.as_ptr(),
                SINGLE_PROOF_LEN,
                ptr::null(),
                commit.as_ptr(),
                1,
                64,
                h_dom.as_ptr(),
                ptr::null(),
                0,
            )
        };
        unsafe { ffi::secp256k1_scratch_space_destroy(scratch) };
        ok == 1
    }

    fn rewind(
        &self,
        commitment: &[u8; 33],
        proof: &[u8; SINGLE_PROOF_LEN],
        nonce: &[u8; 32],
    ) -> Result<Option<RawRewind>, LabError> {
        let h_dom = self.h_dom_internal()?;
        let mut commit = [0_u8; 64];
        let zkp_commitment = sec1_to_zkp_commitment(commitment)?;
        if unsafe {
            ffi::secp256k1_pedersen_commitment_parse(
                self.ctx,
                commit.as_mut_ptr(),
                zkp_commitment.as_ptr(),
            )
        } != 1
        {
            return Ok(None);
        }
        let mut value = 0_u64;
        let mut blind = [0_u8; 32];
        let mut metadata = [0_u8; RECOVERY_METADATA_LEN];
        let ok = unsafe {
            ffi::secp256k1_bulletproof_rangeproof_rewind(
                self.ctx,
                &mut value,
                blind.as_mut_ptr(),
                proof.as_ptr(),
                SINGLE_PROOF_LEN,
                0,
                commit.as_ptr(),
                h_dom.as_ptr(),
                nonce.as_ptr(),
                ptr::null(),
                0,
                metadata.as_mut_ptr(),
            )
        };
        if ok == 1 {
            Ok(Some((value, blind, metadata)))
        } else {
            blind.zeroize();
            Ok(None)
        }
    }
}

impl Drop for RawSingleBackend {
    fn drop(&mut self) {
        unsafe {
            ffi::secp256k1_bulletproof_generators_destroy(self.ctx, self.gens);
            ffi::secp256k1_context_destroy(self.ctx);
        }
    }
}
