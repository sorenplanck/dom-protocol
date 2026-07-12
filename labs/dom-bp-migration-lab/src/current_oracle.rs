//! Reproduction of the live DOM classic/standard Bulletproof consensus path.
//!
//! The raw FFI below is laboratory-only. It exists solely to mint adversarial
//! proofs which the safe production API correctly refuses to construct.

#![allow(unsafe_code)]

use crate::protocol::{
    OracleCase, OracleResponse, ProveResult, VerifyResult, CURRENT_PROOF_LEN, MAX_PROVABLE_VALUE,
    PROOF_NBITS, PROOF_NCOMMITS,
};
use dom_crypto::{bp2_prove, bp2_verify, derive_h_generator, BlindingFactor};
use secp256k1zkp::{constants, ffi};
use std::os::raw::{c_int, c_uchar};
use std::ptr;

const RAW_PROOF_NBITS: usize = 64;
const RAW_SCRATCH_SIZE: usize = 1 << 20;
const DOM_BP_SOURCE: &str = include_str!("../../../crates/dom-crypto/src/bulletproof_bp.rs");

mod raw_ffi {
    use super::*;

    unsafe extern "C" {
        pub fn secp256k1_generator_parse(
            ctx: *const ffi::Context,
            gen64_out: *mut c_uchar,
            input33: *const c_uchar,
        ) -> c_int;
        pub fn secp256k1_bulletproof_rangeproof_prove(
            ctx: *const ffi::Context,
            scratch: *mut ffi::ScratchSpace,
            gens: *const ffi::BulletproofGenerators,
            proof: *mut c_uchar,
            plen: *mut usize,
            tau_x: *mut c_uchar,
            t_one: *mut ffi::PublicKey,
            t_two: *mut ffi::PublicKey,
            value: *const u64,
            min_value: *const u64,
            blind: *const *const c_uchar,
            commits: *const *const c_uchar,
            n_commits: usize,
            value_gen: *const c_uchar,
            nbits: usize,
            nonce: *const c_uchar,
            private_nonce: *const c_uchar,
            extra_commit: *const c_uchar,
            extra_commit_len: usize,
            message: *const c_uchar,
        ) -> c_int;
    }
}

struct RawBackend {
    ctx: *mut ffi::Context,
    gens: *mut ffi::BulletproofGenerators,
}

impl RawBackend {
    fn new() -> Result<Self, &'static str> {
        // SAFETY: standard Grin constructors; every null return is checked.
        let ctx = unsafe {
            ffi::secp256k1_context_create(ffi::SECP256K1_START_SIGN | ffi::SECP256K1_START_VERIFY)
        };
        if ctx.is_null() {
            return Err("backend_context_create_failed");
        }
        // SAFETY: ctx is live; generator and count match DOM's live backend.
        let gens = unsafe {
            ffi::secp256k1_bulletproof_generators_create(ctx, constants::GENERATOR_G.as_ptr(), 256)
        };
        if gens.is_null() {
            // SAFETY: ctx was created above and has not yet been destroyed.
            unsafe { ffi::secp256k1_context_destroy(ctx) };
            return Err("backend_generators_create_failed");
        }
        Ok(Self { ctx, gens })
    }

    fn h_dom_internal(&self) -> Result<[u8; 64], &'static str> {
        let compressed = derive_h_generator().map_err(|_| "h_dom_derivation_failed")?;
        let mut serialized = compressed;
        serialized[0] = match serialized[0] {
            0x02 => 0x0a,
            0x03 => 0x0b,
            _ => return Err("h_dom_invalid_sec1"),
        };
        let mut internal = [0_u8; 64];
        // SAFETY: all pointers have fixed valid lengths and ctx is live.
        let result = unsafe {
            raw_ffi::secp256k1_generator_parse(self.ctx, internal.as_mut_ptr(), serialized.as_ptr())
        };
        if result == 1 {
            Ok(internal)
        } else {
            Err("h_dom_generator_parse_failed")
        }
    }

    fn prove(&self, values: &[u64], blinds: &[[u8; 32]]) -> Result<Vec<u8>, &'static str> {
        if values.len() != blinds.len() || values.is_empty() {
            return Err("raw_witness_shape_invalid");
        }
        let value_gen = self.h_dom_internal()?;
        let blind_ptrs: Vec<*const u8> = blinds.iter().map(|blind| blind.as_ptr()).collect();
        let mut proof = [0_u8; constants::MAX_PROOF_SIZE];
        let mut plen = proof.len();
        let rewind = [0x42_u8; 32];
        let private = [0x42_u8; 32];
        // SAFETY: all input arrays are live and sizes match values.len(); scratch
        // is fresh for this call and is destroyed before returning.
        let scratch = unsafe { ffi::secp256k1_scratch_space_create(self.ctx, RAW_SCRATCH_SIZE) };
        if scratch.is_null() {
            return Err("scratch_create_failed");
        }
        let result = unsafe {
            raw_ffi::secp256k1_bulletproof_rangeproof_prove(
                self.ctx,
                scratch,
                self.gens,
                proof.as_mut_ptr(),
                &mut plen,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                values.as_ptr(),
                ptr::null(),
                blind_ptrs.as_ptr(),
                ptr::null(),
                values.len(),
                value_gen.as_ptr(),
                RAW_PROOF_NBITS,
                rewind.as_ptr(),
                private.as_ptr(),
                ptr::null(),
                0,
                ptr::null(),
            )
        };
        // SAFETY: scratch was created above and is no longer used.
        unsafe { ffi::secp256k1_scratch_space_destroy(scratch) };
        if result != 1 {
            return Err("raw_prove_rejected");
        }
        Ok(proof[..plen].to_vec())
    }
}

impl Drop for RawBackend {
    fn drop(&mut self) {
        // SAFETY: both handles were created together and are destroyed once.
        unsafe {
            ffi::secp256k1_bulletproof_generators_destroy(self.ctx, self.gens);
            ffi::secp256k1_context_destroy(self.ctx);
        }
    }
}

#[derive(Debug, Default)]
pub struct CurrentOracle;

impl CurrentOracle {
    pub fn assert_consensus_constants() {
        assert_eq!(
            dom_crypto::bulletproof::MAX_PROVABLE_VALUE,
            MAX_PROVABLE_VALUE
        );
        assert_eq!(PROOF_NBITS, 64);
        assert_eq!(PROOF_NCOMMITS, 2);
        assert_eq!(CURRENT_PROOF_LEN, 739);
        assert!(DOM_BP_SOURCE.contains("pub(crate) const SINGLE_BULLETPROOF_SIZE: usize = 739;"));
        assert!(DOM_BP_SOURCE.contains("pub(crate) const PROOF_NBITS: usize = 64;"));
        assert!(DOM_BP_SOURCE.contains("const PROOF_NCOMMITS: usize = 2;"));
        assert!(DOM_BP_SOURCE.contains("let values = [value, complement_value];"));
    }

    pub fn prove_verify(&self, case: &OracleCase) -> OracleResponse {
        Self::assert_consensus_constants();
        let mut response = OracleResponse::new(case.case_id.clone());
        if case.schema_version != crate::protocol::SCHEMA_VERSION {
            response.error_class = Some("unsupported_schema_version");
            return response;
        }
        let blind = match parse_blind(&case.blind_hex) {
            Ok(blind) => blind,
            Err(error_class) => {
                response.error_class = Some(error_class);
                return response;
            }
        };
        match bp2_prove(case.value, &blind) {
            Ok((proof, commitment)) => {
                response.proof_len = Some(proof.len());
                if proof.len() != CURRENT_PROOF_LEN {
                    response.error_class = Some("unexpected_proof_length");
                    return response;
                }
                response.prove_result = ProveResult::Accepted;
                response.verify_attempted = true;
                match bp2_verify(&commitment, &proof) {
                    Ok(true) => response.verify_result = VerifyResult::True,
                    Ok(false) => response.verify_result = VerifyResult::False,
                    Err(_) => {
                        response.verify_result = VerifyResult::Malformed;
                        response.error_class = Some("verification_error");
                    }
                }
            }
            Err(_) if case.value > MAX_PROVABLE_VALUE => {
                response.prove_result = ProveResult::Rejected;
                response.error_class = Some("value_above_max");
            }
            Err(_) => {
                response.error_class = Some("prove_error");
            }
        }
        response
    }

    pub fn verify(commitment: &[u8; 33], proof: &[u8]) -> VerifyResult {
        match bp2_verify(commitment, proof) {
            Ok(true) => VerifyResult::True,
            Ok(false) => VerifyResult::False,
            Err(_) => VerifyResult::Malformed,
        }
    }

    pub fn adversarial_single_64(value: u64, blind: [u8; 32]) -> Result<Vec<u8>, &'static str> {
        RawBackend::new()?.prove(&[value], &[blind])
    }

    pub fn adversarial_wrong_complement(
        value: u64,
        blind: [u8; 32],
    ) -> Result<Vec<u8>, &'static str> {
        RawBackend::new()?.prove(&[value, 1_337], &[blind, [0x22_u8; 32]])
    }
}

fn parse_blind(blind_hex: &str) -> Result<BlindingFactor, &'static str> {
    let decoded = hex::decode(blind_hex).map_err(|_| "invalid_blind_hex")?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| "invalid_blind_length")?;
    BlindingFactor::from_bytes(bytes).map_err(|_| "invalid_blind")
}
