//! Standard Bulletproof range proofs (grin `secp256k1zkp` backend) — Phase 1.
//!
//! This module is the **standard-Bulletproof** path for DOM, distinct from the
//! borromean-based [`crate::bulletproof`] module. It is built on grin's
//! `secp256k1zkp` (libsecp256k1-zkp) classic bulletproof rangeproof, which
//! produces a single 64-bit proof of [`SINGLE_BULLETPROOF_SIZE`] = 675 bytes,
//! versus the ~4166-byte borromean proof.
//!
//! Like the borromean path, proofs here are bound to DOM's **H_DOM** value
//! generator (RFC9380, DST="DOM:h2c:secp256k1:v6.1"). grin's *safe* API
//! hardcodes its own `GENERATOR_H`, so H_DOM is supplied through the raw FFI
//! `value_gen` parameter (the path proven in Phase 1 Gate 1).
//!
//! Commitments are exchanged in the same **SEC1** (`0x02/0x03`) form the
//! borromean path uses; internally they round-trip through the libsecp pedersen
//! **zkp** form (`0x08/0x09`, is_square encoding). grin's pedersen serialization
//! (`output[0] = 9 ^ is_quad_var(y)`) is byte-identical to Blockstream's, so the
//! SEC1<->zkp conversion here mirrors [`crate::bulletproof`] exactly and must
//! stay consistent with it.
//!
//! Status: implemented but **NOT wired into consensus** and **NOT exported**
//! from the crate's public API. The borromean [`crate::bulletproof`] module
//! remains the live path and is untouched. `bp_prove`/`bp_verify` are
//! crate-private; this module exists to validate the standard-Bulletproof
//! prove/verify pair under H_DOM inside the real `dom-crypto` crate, parallel
//! to borromean, ahead of the migration.

// Justification for overriding the crate-wide `#![deny(unsafe_code)]`:
// the grin bulletproof rangeproof is only reachable through C FFI. The unsafe
// surface is confined to this module's `raw_ffi` block and the thin helpers
// that call it; every unsafe site documents its SAFETY invariants. The
// borromean path stays 100% safe-Rust.
#![allow(unsafe_code)]
// Scaffold: `bp_prove`/`bp_verify` (and the helpers they reach) are not called
// from non-test crate code yet because this path is not wired into consensus.
// Silence dead_code until it is wired up so a non-test `cargo build` stays clean.
#![allow(dead_code)]

use crate::bulletproof::MAX_PROVABLE_VALUE; // reuse the borromean bound — do not redefine
use crate::pedersen::BlindingFactor;
use dom_core::DomError;
use k256::FieldElement;
use rand::RngCore;
use secp256k1::PublicKey as Secp256k1PublicKey;
use secp256k1zkp::{constants, ffi};
use std::ptr;

/// Serialized byte length of a single 64-bit grin Bulletproof range proof.
/// (grin `constants::SINGLE_BULLET_PROOF_SIZE`; borromean proofs are ~4166 bytes.)
pub(crate) const SINGLE_BULLETPROOF_SIZE: usize = 675;

/// Number of bits proven by a grin single-value Bulletproof. The 675-byte proof
/// is the 64-bit variant; DOM additionally enforces [`MAX_PROVABLE_VALUE`].
pub(crate) const PROOF_NBITS: usize = 64;

/// Scratch arena size for grin's bulletproof FFI (mirrors grin's own
/// `SCRATCH_SPACE_SIZE`); generous virtual reservation, freed after each call.
const SCRATCH_SIZE: usize = 256 * (1 << 20);

/// Number of bulletproof generators to create (mirrors grin's `MAX_GENERATORS`).
const N_GENERATORS: usize = 256;

/// H_DOM value generator in grin's 33-byte *zkp-serialized* form (`0x0a || H_DOM_X`).
///
/// The x-coordinate is sourced from the crate's single canonical derivation
/// ([`crate::h_generator::derive_h_generator`]) so this path can never diverge
/// from the borromean [`crate::bulletproof`] generator. The 0x0a/0x0b prefix
/// encodes Y parity (mapped from the SEC1 0x02/0x03 prefix), matching the
/// generator-serialization convention libsecp256k1-zkp's `generator_parse`
/// expects.
pub(crate) fn h_dom_zkp_serialized() -> Result<[u8; 33], DomError> {
    let compressed = crate::h_generator::derive_h_generator()?; // 0x02||X or 0x03||X
    let mut out = [0u8; 33];
    out[0] = match compressed[0] {
        0x02 => 0x0a, // even Y
        0x03 => 0x0b, // odd Y
        other => {
            return Err(DomError::Internal(format!(
                "unexpected SEC1 compressed prefix for H_DOM: 0x{other:02x}"
            )))
        }
    };
    out[1..].copy_from_slice(&compressed[1..]);
    Ok(out)
}

// ---------------------------------------------------------------------------
// SEC1 <-> zkp commitment encoding.
//
// Mirrors `crate::bulletproof::{sec1_to_zkp, zkp_to_sec1}` verbatim (those are
// private to that module). MUST stay consistent — both libs use the identical
// pedersen serialization `output[0] = 9 ^ is_quad_var(y)` (0x08 square / 0x09).
// ---------------------------------------------------------------------------

/// Convert a SEC1 commitment (0x02/0x03 prefix) to libsecp zkp form (0x08/0x09).
fn sec1_to_zkp(sec1_bytes: &[u8; 33]) -> Result<[u8; 33], DomError> {
    let pk = Secp256k1PublicKey::from_slice(sec1_bytes)
        .map_err(|e| DomError::Invalid(format!("invalid SEC1: {e}")))?;
    let uncompressed = pk.serialize_uncompressed();
    let y_bytes: [u8; 32] = uncompressed[33..65].try_into().unwrap();
    let y_field = FieldElement::from_bytes(&y_bytes.into())
        .expect("Y from valid point is valid field element");
    let is_square: bool = y_field.sqrt().is_some().into();
    let zkp_prefix = if is_square { 0x08 } else { 0x09 };
    let mut zkp_bytes = *sec1_bytes;
    zkp_bytes[0] = zkp_prefix;
    Ok(zkp_bytes)
}

/// Convert a libsecp zkp commitment (0x08/0x09 prefix) to SEC1 form (0x02/0x03).
fn zkp_to_sec1(zkp_bytes: &[u8; 33]) -> Result<[u8; 33], DomError> {
    let x_bytes: [u8; 32] = zkp_bytes[1..].try_into().unwrap();
    // Validate the zkp bytes describe a real point (consistent with borromean path).
    let _ = secp256k1_zkp::PedersenCommitment::from_slice(zkp_bytes)
        .map_err(|e| DomError::Invalid(format!("invalid zkp: {e}")))?;
    for &prefix in &[0x02_u8, 0x03_u8] {
        let mut sec1_bytes = [0u8; 33];
        sec1_bytes[0] = prefix;
        sec1_bytes[1..].copy_from_slice(&x_bytes);
        if let Ok(pk) = Secp256k1PublicKey::from_slice(&sec1_bytes) {
            let uncompressed = pk.serialize_uncompressed();
            let y: [u8; 32] = uncompressed[33..65].try_into().unwrap();
            let y_field = FieldElement::from_bytes(&y.into()).expect("valid Y");
            let is_square: bool = y_field.sqrt().is_some().into();
            let expected_zkp = if is_square { 0x08 } else { 0x09 };
            if expected_zkp == zkp_bytes[0] {
                return Ok(sec1_bytes);
            }
        }
    }
    Err(DomError::Internal("zkp→SEC1: no valid prefix found".into()))
}

/// Raw FFI bindings to grin's bundled libsecp256k1-zkp.
///
/// These resolve to grin's native `secp256k1_*` symbols (grin does not prefix
/// its C symbols, so they are disjoint from Blockstream's
/// `rustsecp256k1zkp_v0_10_0_*` symbols and coexist in the same binary —
/// validated in Phase 1 Gate 0). Declarations reuse grin's opaque
/// context/generator types from `secp256k1zkp::ffi`, so they are ABI-identical
/// to grin's own. grin's `ffi` exposes the pedersen/scratch/generators/context
/// helpers we also use, but it does NOT expose `secp256k1_generator_parse`
/// (needed to turn the 33-byte serialized H_DOM into the 64-byte internal
/// `value_gen`) nor the bulletproof rangeproof entry points with a clear
/// home here — we declare the full surface this module drives in one place;
/// re-declaring an `extern` reference to an already-declared C symbol is sound.
///
/// SAFETY (applies to every function below): all pointer arguments must be
/// valid for the documented direction and length, the context/scratch/
/// generators handles must come from the matching grin constructors, and
/// `value_gen` must point to a 64-byte internal generator produced by
/// `secp256k1_generator_parse`. Calls must happen on a live context.
mod raw_ffi {
    use secp256k1zkp::ffi::{BulletproofGenerators, Context, PublicKey, ScratchSpace};
    use std::os::raw::{c_int, c_uchar};

    // `size_t` is pointer-width unsigned (== usize on supported targets),
    // matching grin's `libc::size_t` typedef in its own FFI declarations.
    #[allow(non_camel_case_types)]
    pub(crate) type size_t = usize;

    extern "C" {
        /// Parse a 33-byte serialized generator (`0x0a/0x0b || X`) into the
        /// 64-byte internal generator form written to `gen64_out`.
        ///
        /// SAFETY: `ctx` live; `gen64_out` writable for 64 bytes; `input33`
        /// readable for 33 bytes. Returns 1 on success, 0 if not a valid
        /// generator (e.g. off-curve).
        pub(crate) fn secp256k1_generator_parse(
            ctx: *const Context,
            gen64_out: *mut c_uchar,
            input33: *const c_uchar,
        ) -> c_int;

        /// grin classic Bulletproof rangeproof prover (single 64-bit value path).
        ///
        /// SAFETY: see module note. `proof` writable for `*plen` bytes; on
        /// return `*plen` is the real length. `value_gen` selects the value
        /// generator (DOM passes H_DOM). Returns 1 on success.
        pub(crate) fn secp256k1_bulletproof_rangeproof_prove(
            ctx: *const Context,
            scratch: *mut ScratchSpace,
            gens: *const BulletproofGenerators,
            proof: *mut c_uchar,
            plen: *mut size_t,
            tau_x: *mut c_uchar,
            t_one: *mut PublicKey,
            t_two: *mut PublicKey,
            value: *const u64,
            min_value: *const u64,
            blind: *const *const c_uchar,
            commits: *const *const c_uchar,
            n_commits: size_t,
            value_gen: *const c_uchar,
            nbits: size_t,
            nonce: *const c_uchar,
            private_nonce: *const c_uchar,
            extra_commit: *const c_uchar,
            extra_commit_len: size_t,
            message: *const c_uchar,
        ) -> c_int;

        /// grin classic Bulletproof rangeproof verifier (single value path).
        ///
        /// SAFETY: see module note. `proof` readable for `plen` bytes; `commit`
        /// points to a 64-byte internal commitment; `value_gen` must match the
        /// generator the proof/commit were built under. Returns 1 if verified.
        pub(crate) fn secp256k1_bulletproof_rangeproof_verify(
            ctx: *const Context,
            scratch: *mut ScratchSpace,
            gens: *const BulletproofGenerators,
            proof: *const c_uchar,
            plen: size_t,
            min_value: *const u64,
            commit: *const c_uchar,
            n_commits: size_t,
            nbits: size_t,
            value_gen: *const c_uchar,
            extra_commit: *const c_uchar,
            extra_commit_len: size_t,
        ) -> c_int;
    }
}

/// Owns a grin context + bulletproof generator set, freed on drop.
struct Backend {
    ctx: *mut ffi::Context,
    gens: *mut ffi::BulletproofGenerators,
}

impl Backend {
    fn new() -> Result<Self, DomError> {
        // SAFETY: context_create/generators_create are the grin constructors;
        // we null-check both and free the ctx if generator creation fails.
        unsafe {
            let ctx = ffi::secp256k1_context_create(
                ffi::SECP256K1_START_SIGN | ffi::SECP256K1_START_VERIFY,
            );
            if ctx.is_null() {
                return Err(DomError::Internal("grin context_create returned null".into()));
            }
            let gens =
                ffi::secp256k1_bulletproof_generators_create(ctx, constants::GENERATOR_G.as_ptr(), N_GENERATORS);
            if gens.is_null() {
                ffi::secp256k1_context_destroy(ctx);
                return Err(DomError::Internal("grin generators_create returned null".into()));
            }
            Ok(Self { ctx, gens })
        }
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        // SAFETY: ctx/gens were produced by the matching grin constructors and
        // are not used after this point.
        unsafe {
            ffi::secp256k1_bulletproof_generators_destroy(self.ctx, self.gens);
            ffi::secp256k1_context_destroy(self.ctx);
        }
    }
}

/// Parse the canonical H_DOM into grin's 64-byte internal generator form.
fn h_dom_internal(backend: &Backend) -> Result<[u8; 64], DomError> {
    let ser = h_dom_zkp_serialized()?;
    let mut g = [0u8; 64];
    // SAFETY: ctx live; g writable for 64 bytes; ser readable for 33 bytes.
    let ok = unsafe { raw_ffi::secp256k1_generator_parse(backend.ctx, g.as_mut_ptr(), ser.as_ptr()) };
    if ok != 1 {
        return Err(DomError::Internal("H_DOM generator_parse failed".into()));
    }
    Ok(g)
}

/// Pedersen commit C = value*value_gen + blind*G, returned in 33-byte zkp form.
fn commit_zkp(
    backend: &Backend,
    value: u64,
    blind: &[u8; 32],
    value_gen: &[u8; 64],
) -> Result<[u8; 33], DomError> {
    let mut ci = [0u8; 64];
    // SAFETY: ctx live; ci writable for 64 bytes; blind/value_gen/G readable for
    // their fixed lengths.
    let r = unsafe {
        ffi::secp256k1_pedersen_commit(
            backend.ctx,
            ci.as_mut_ptr(),
            blind.as_ptr(),
            value,
            value_gen.as_ptr(),
            constants::GENERATOR_G.as_ptr(),
        )
    };
    if r != 1 {
        return Err(DomError::Invalid("pedersen_commit failed".into()));
    }
    let mut out = [0u8; 33];
    // SAFETY: ctx live; out writable for 33 bytes; ci is a valid internal commitment.
    unsafe { ffi::secp256k1_pedersen_commitment_serialize(backend.ctx, out.as_mut_ptr(), ci.as_ptr()) };
    Ok(out)
}

/// Bulletproof prove for `value` under `value_gen` (random nonces). Returns proof bytes.
fn prove_raw(
    backend: &Backend,
    value: u64,
    blind: &[u8; 32],
    value_gen: &[u8; 64],
) -> Result<Vec<u8>, DomError> {
    let mut proof = [0u8; constants::MAX_PROOF_SIZE];
    let mut plen: usize = constants::MAX_PROOF_SIZE;
    let mut rewind = [0u8; 32];
    let mut private = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut rewind);
    rand::thread_rng().fill_bytes(&mut private);
    let blinds: [*const u8; 1] = [blind.as_ptr()];
    let v = value;

    // SAFETY: scratch from grin constructor (null-checked); all pointers valid
    // for the call; scratch destroyed before return.
    let r = unsafe {
        let scratch = ffi::secp256k1_scratch_space_create(backend.ctx, SCRATCH_SIZE);
        if scratch.is_null() {
            return Err(DomError::Internal("scratch_space_create returned null".into()));
        }
        let r = raw_ffi::secp256k1_bulletproof_rangeproof_prove(
            backend.ctx,
            scratch,
            backend.gens,
            proof.as_mut_ptr(),
            &mut plen,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &v as *const u64,
            ptr::null(),
            blinds.as_ptr(),
            ptr::null(),
            1,
            value_gen.as_ptr(),
            PROOF_NBITS,
            rewind.as_ptr(),
            private.as_ptr(),
            ptr::null(),
            0,
            ptr::null(),
        );
        ffi::secp256k1_scratch_space_destroy(scratch);
        r
    };
    if r != 1 {
        return Err(DomError::Internal("bulletproof prove failed".into()));
    }
    Ok(proof[..plen].to_vec())
}

/// Bulletproof verify of `proof` against a 33-byte zkp `commit` under `value_gen`.
fn verify_raw(
    backend: &Backend,
    commit_zkp33: &[u8; 33],
    proof: &[u8],
    value_gen: &[u8; 64],
) -> Result<bool, DomError> {
    let mut ci = [0u8; 64];
    // SAFETY: ctx live; ci writable for 64 bytes; commit readable for 33 bytes.
    if unsafe { ffi::secp256k1_pedersen_commitment_parse(backend.ctx, ci.as_mut_ptr(), commit_zkp33.as_ptr()) }
        != 1
    {
        return Ok(false);
    }
    // SAFETY: scratch from grin constructor (null-checked); proof readable for
    // proof.len(); ci is a valid internal commitment; scratch destroyed before return.
    let r = unsafe {
        let scratch = ffi::secp256k1_scratch_space_create(backend.ctx, SCRATCH_SIZE);
        if scratch.is_null() {
            return Err(DomError::Internal("scratch_space_create returned null".into()));
        }
        let r = raw_ffi::secp256k1_bulletproof_rangeproof_verify(
            backend.ctx,
            scratch,
            backend.gens,
            proof.as_ptr(),
            proof.len(),
            ptr::null(),
            ci.as_ptr(),
            1,
            PROOF_NBITS,
            value_gen.as_ptr(),
            ptr::null(),
            0,
        );
        ffi::secp256k1_scratch_space_destroy(scratch);
        r
    };
    Ok(r == 1)
}

/// Generate a standard Bulletproof for `(value, blinding)` under H_DOM.
///
/// Returns `(proof_bytes, commitment_sec1)`. Rejects `value > MAX_PROVABLE_VALUE`
/// before any FFI call (same defensive bound as the borromean path).
///
/// Exported from the crate as `bp2_prove` (the second, standard-Bulletproof
/// backend). NOT yet wired into consensus — it runs parallel to the borromean
/// `bp_prove`.
pub fn bp_prove(
    value: u64,
    blinding: &BlindingFactor,
) -> Result<(Vec<u8>, [u8; 33]), DomError> {
    if value > MAX_PROVABLE_VALUE {
        return Err(DomError::Invalid(format!(
            "value {value} > MAX_PROVABLE_VALUE {MAX_PROVABLE_VALUE}"
        )));
    }
    let backend = Backend::new()?;
    let h_dom = h_dom_internal(&backend)?;
    let blind = blinding.as_bytes();
    let zkp = commit_zkp(&backend, value, blind, &h_dom)?;
    let sec1 = zkp_to_sec1(&zkp)?;
    let proof = prove_raw(&backend, value, blind, &h_dom)?;
    Ok((proof, sec1))
}

/// Verify a standard Bulletproof against a SEC1 commitment under H_DOM.
///
/// Exported from the crate as `bp2_verify` (the second, standard-Bulletproof
/// backend). NOT yet wired into consensus — it runs parallel to the borromean
/// `bp_verify`.
pub fn bp_verify(commitment_sec1: &[u8; 33], proof_bytes: &[u8]) -> Result<bool, DomError> {
    if proof_bytes.is_empty() {
        return Err(DomError::Malformed("range proof vazio".into()));
    }
    if proof_bytes.len() > dom_core::MAX_PROOF_SIZE {
        return Err(DomError::Malformed(format!(
            "range proof muito grande: {} bytes",
            proof_bytes.len()
        )));
    }
    let backend = Backend::new()?;
    let h_dom = h_dom_internal(&backend)?;
    let zkp = sec1_to_zkp(commitment_sec1)?;
    verify_raw(&backend, &zkp, proof_bytes, &h_dom)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MATRIX_VALUES: [u64; 4] = [1, 42, 1_000_000, 4_503_599_627_370_495]; // last = 2^52 - 1
    const TEST_BLIND: [u8; 32] = [0x11u8; 32];

    /// Link/coexistence smoke test (kept from scaffold): the grin dependency
    /// links inside the real dom-crypto crate and H_DOM parses via grin's FFI.
    #[test]
    fn grin_links_and_h_dom_parses() {
        let ser = h_dom_zkp_serialized().expect("H_DOM serialize");
        assert_eq!(ser.len(), 33);
        assert!(ser[0] == 0x0a || ser[0] == 0x0b);
        let backend = Backend::new().expect("backend");
        let g = h_dom_internal(&backend).expect("H_DOM parse");
        assert!(g.iter().any(|&b| b != 0));
        assert_eq!(SINGLE_BULLETPROOF_SIZE, 675);
        assert_eq!(PROOF_NBITS, 64);
    }

    /// Gate-1 generator-binding matrix, now in-crate, for all four values.
    #[test]
    fn binding_matrix_in_crate() {
        let blind = BlindingFactor::from_bytes(TEST_BLIND).expect("blind");
        let backend = Backend::new().expect("backend");
        let h_dom = h_dom_internal(&backend).expect("H_DOM");
        let h_def: [u8; 64] = constants::GENERATOR_H;
        assert_ne!(h_dom, h_def, "H_DOM must differ from grin's default H");

        for &v in MATRIX_VALUES.iter() {
            let c_dom = commit_zkp(&backend, v, blind.as_bytes(), &h_dom).unwrap();
            let c_def = commit_zkp(&backend, v, blind.as_bytes(), &h_def).unwrap();
            let pr_dom = prove_raw(&backend, v, blind.as_bytes(), &h_dom).unwrap();
            let pr_def = prove_raw(&backend, v, blind.as_bytes(), &h_def).unwrap();

            // A: commit=H_DOM prove=H_DOM verify=H_DOM -> PASS
            assert!(verify_raw(&backend, &c_dom, &pr_dom, &h_dom).unwrap(), "A v={v}");
            // B: commit=H_DOM prove=H_default verify=H_DOM -> FAIL
            assert!(!verify_raw(&backend, &c_dom, &pr_def, &h_dom).unwrap(), "B v={v}");
            // C: commit=H_DOM prove=H_DOM verify=H_default -> FAIL
            assert!(!verify_raw(&backend, &c_dom, &pr_dom, &h_def).unwrap(), "C v={v}");
            // D: control, all H_default -> PASS
            assert!(verify_raw(&backend, &c_def, &pr_def, &h_def).unwrap(), "D v={v}");

            // proof is a real 675-byte Bulletproof
            assert_eq!(pr_dom.len(), 675, "proof len v={v}");
        }
    }

    /// End-to-end SEC1 round-trip through the production wrappers, all values.
    #[test]
    fn bp_prove_verify_sec1_roundtrip() {
        for &v in MATRIX_VALUES.iter() {
            let blind = BlindingFactor::random();
            let (proof, sec1) = bp_prove(v, &blind).expect("prove");
            assert_eq!(proof.len(), 675, "v={v}");
            assert!(bp_verify(&sec1, &proof).unwrap(), "verify v={v}");
        }
    }

    /// Value 0 proves and verifies.
    #[test]
    fn value_zero_roundtrips() {
        let blind = BlindingFactor::random();
        let (proof, sec1) = bp_prove(0, &blind).expect("prove 0");
        assert_eq!(proof.len(), 675);
        assert!(bp_verify(&sec1, &proof).unwrap());
    }

    /// MAX_PROVABLE_VALUE proves and verifies.
    #[test]
    fn max_provable_roundtrips() {
        let blind = BlindingFactor::random();
        let (proof, sec1) = bp_prove(MAX_PROVABLE_VALUE, &blind).expect("prove max");
        assert_eq!(proof.len(), 675);
        assert!(bp_verify(&sec1, &proof).unwrap());
    }

    /// MAX_PROVABLE_VALUE + 1 is rejected by bp_prove before any FFI, no panic.
    #[test]
    fn above_max_rejected_without_panic() {
        let blind = BlindingFactor::random();
        let r = bp_prove(MAX_PROVABLE_VALUE + 1, &blind);
        assert!(r.is_err(), "value above MAX_PROVABLE_VALUE must be rejected");
    }

    /// A proof must not verify against a different commitment.
    #[test]
    fn wrong_commitment_fails() {
        let (proof, _sec1) = bp_prove(42, &BlindingFactor::random()).unwrap();
        let (_p2, sec1_other) = bp_prove(43, &BlindingFactor::random()).unwrap();
        assert!(
            !bp_verify(&sec1_other, &proof).unwrap(),
            "proof for 42 must not verify against commitment of 43"
        );
    }

    /// Negative-generator tests: a flipped or all-zero generator must reject.
    #[test]
    fn negative_generator_rejected() {
        let blind = BlindingFactor::from_bytes(TEST_BLIND).unwrap();
        let backend = Backend::new().unwrap();
        let h_dom = h_dom_internal(&backend).unwrap();
        let c_dom = commit_zkp(&backend, 42, blind.as_bytes(), &h_dom).unwrap();
        let pr_dom = prove_raw(&backend, 42, blind.as_bytes(), &h_dom).unwrap();

        // N1: flip one byte of the serialized H_DOM.
        let mut flipped = h_dom_zkp_serialized().unwrap();
        flipped[20] ^= 0x01;
        let mut g1 = [0u8; 64];
        // SAFETY: ctx live; buffers correctly sized.
        let parsed1 = unsafe {
            raw_ffi::secp256k1_generator_parse(backend.ctx, g1.as_mut_ptr(), flipped.as_ptr())
        };
        let n1 = if parsed1 != 1 {
            true // off-curve => rejected at parse
        } else {
            !verify_raw(&backend, &c_dom, &pr_dom, &g1).unwrap()
        };
        assert!(n1, "flipped generator must be rejected");

        // N2: all-zero serialized generator (0x0a || 0..0).
        let mut zero = [0u8; 33];
        zero[0] = 0x0a;
        let mut g2 = [0u8; 64];
        // SAFETY: ctx live; buffers correctly sized.
        let parsed2 =
            unsafe { raw_ffi::secp256k1_generator_parse(backend.ctx, g2.as_mut_ptr(), zero.as_ptr()) };
        let n2 = if parsed2 != 1 {
            true
        } else {
            !verify_raw(&backend, &c_dom, &pr_dom, &g2).unwrap()
        };
        assert!(n2, "all-zero generator must be rejected");
    }
}
