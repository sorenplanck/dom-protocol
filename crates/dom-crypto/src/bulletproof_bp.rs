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

/// Scratch arena size for grin's bulletproof FFI, per thread (reused, not
/// per-call). Empirically the minimum for a single 64-bit proof is ~15.8 KiB to
/// prove / ~9.2 KiB to verify (measured against grin 0.7.15); 1 MiB gives ~65x
/// headroom while being 256x smaller than grin's batch-sized 256 MiB default.
const SCRATCH_SIZE: usize = 1 << 20; // 1 MiB

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

/// Shared grin context + bulletproof generator set, initialized once and reused
/// for the lifetime of the process. Building the context (ecmult tables) and the
/// 256 generators is expensive; per-call recreation (alongside a 256 MiB scratch)
/// was the consensus-viability blocker flagged in review. Now all three heavy
/// resources are reused: context+generators here, scratch per-thread below.
struct Backend {
    ctx: *mut ffi::Context,
    gens: *mut ffi::BulletproofGenerators,
}

// SAFETY (threading): per libsecp256k1's own header — "A constructed context can
// safely be used from multiple threads simultaneously" for const API calls. We
// only ever invoke const operations (prove/verify/commit/parse/serialize) and
// NEVER call the non-const secp256k1_context_randomize after creation, so no
// locking is required. The BulletproofGenerators set is immutable after
// creation. Hence sharing context+generators across threads is sound. The
// mutable scratch is deliberately NOT shared (see SCRATCH). The singleton is
// intentionally never destroyed (process-lifetime), so there is no Drop /
// double-free hazard from sharing the raw pointers.
unsafe impl Send for Backend {}
unsafe impl Sync for Backend {}

static SHARED: std::sync::OnceLock<Backend> = std::sync::OnceLock::new();

/// Lazily initialize and return the process-wide shared backend.
fn backend() -> &'static Backend {
    SHARED.get_or_init(|| {
        // SAFETY: standard grin constructors; both results checked non-null. The
        // shim cannot operate without a context/generators, so failure panics.
        unsafe {
            let ctx = ffi::secp256k1_context_create(
                ffi::SECP256K1_START_SIGN | ffi::SECP256K1_START_VERIFY,
            );
            assert!(!ctx.is_null(), "grin context_create returned null");
            let gens = ffi::secp256k1_bulletproof_generators_create(
                ctx,
                constants::GENERATOR_G.as_ptr(),
                N_GENERATORS,
            );
            assert!(!gens.is_null(), "grin generators_create returned null");
            Backend { ctx, gens }
        }
    })
}

/// Per-thread reusable scratch space. grin's header states scratch "cannot
/// safely be shared between threads without additional synchronization", so each
/// thread owns its own, created once and reused across calls (each bulletproof
/// call does allocate_frame/deallocate_frame internally, leaving it clean).
/// Freed at thread exit.
struct ScratchHandle(*mut ffi::ScratchSpace);

impl Drop for ScratchHandle {
    fn drop(&mut self) {
        // SAFETY: created via scratch_space_create on the shared ctx; destroyed
        // exactly once, at thread exit, and never used afterwards.
        unsafe { ffi::secp256k1_scratch_space_destroy(self.0) };
    }
}

thread_local! {
    static SCRATCH: ScratchHandle = {
        let b = backend();
        // SAFETY: shared ctx is live for the process lifetime; SCRATCH_SIZE > 0.
        let s = unsafe { ffi::secp256k1_scratch_space_create(b.ctx, SCRATCH_SIZE) };
        assert!(!s.is_null(), "grin scratch_space_create returned null");
        ScratchHandle(s)
    };
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

    let r = SCRATCH.with(|scratch| {
        // SAFETY: shared ctx/gens are live for the process lifetime; the reused
        // per-thread scratch is exclusive to this thread; all pointers are valid
        // for the call (proof writable for plen; blind/value_gen fixed lengths).
        unsafe {
            raw_ffi::secp256k1_bulletproof_rangeproof_prove(
                backend.ctx,
                scratch.0,
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
            )
        }
    });
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
    let r = SCRATCH.with(|scratch| {
        // SAFETY: shared ctx/gens are live for the process lifetime; the reused
        // per-thread scratch is exclusive to this thread; proof readable for
        // proof.len(); ci is a valid internal commitment.
        unsafe {
            raw_ffi::secp256k1_bulletproof_rangeproof_verify(
                backend.ctx,
                scratch.0,
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
            )
        }
    });
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
    let backend = backend();
    let h_dom = h_dom_internal(backend)?;
    let blind = blinding.as_bytes();
    let zkp = commit_zkp(backend, value, blind, &h_dom)?;
    let sec1 = zkp_to_sec1(&zkp)?;
    let proof = prove_raw(backend, value, blind, &h_dom)?;
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
    let backend = backend();
    let h_dom = h_dom_internal(backend)?;
    let zkp = sec1_to_zkp(commitment_sec1)?;
    verify_raw(backend, &zkp, proof_bytes, &h_dom)
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
        let backend = backend();
        let g = h_dom_internal(backend).expect("H_DOM parse");
        assert!(g.iter().any(|&b| b != 0));
        assert_eq!(SINGLE_BULLETPROOF_SIZE, 675);
        assert_eq!(PROOF_NBITS, 64);
    }

    /// Gate-1 generator-binding matrix, now in-crate, for all four values.
    #[test]
    fn binding_matrix_in_crate() {
        let blind = BlindingFactor::from_bytes(TEST_BLIND).expect("blind");
        let backend = backend();
        let h_dom = h_dom_internal(backend).expect("H_DOM");
        let h_def: [u8; 64] = constants::GENERATOR_H;
        assert_ne!(h_dom, h_def, "H_DOM must differ from grin's default H");

        for &v in MATRIX_VALUES.iter() {
            let c_dom = commit_zkp(backend, v, blind.as_bytes(), &h_dom).unwrap();
            let c_def = commit_zkp(backend, v, blind.as_bytes(), &h_def).unwrap();
            let pr_dom = prove_raw(backend, v, blind.as_bytes(), &h_dom).unwrap();
            let pr_def = prove_raw(backend, v, blind.as_bytes(), &h_def).unwrap();

            // A: commit=H_DOM prove=H_DOM verify=H_DOM -> PASS
            assert!(verify_raw(backend, &c_dom, &pr_dom, &h_dom).unwrap(), "A v={v}");
            // B: commit=H_DOM prove=H_default verify=H_DOM -> FAIL
            assert!(!verify_raw(backend, &c_dom, &pr_def, &h_dom).unwrap(), "B v={v}");
            // C: commit=H_DOM prove=H_DOM verify=H_default -> FAIL
            assert!(!verify_raw(backend, &c_dom, &pr_dom, &h_def).unwrap(), "C v={v}");
            // D: control, all H_default -> PASS
            assert!(verify_raw(backend, &c_def, &pr_def, &h_def).unwrap(), "D v={v}");

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
        let backend = backend();
        let h_dom = h_dom_internal(backend).unwrap();
        let c_dom = commit_zkp(backend, 42, blind.as_bytes(), &h_dom).unwrap();
        let pr_dom = prove_raw(backend, 42, blind.as_bytes(), &h_dom).unwrap();

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
            !verify_raw(backend, &c_dom, &pr_dom, &g1).unwrap()
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
            !verify_raw(backend, &c_dom, &pr_dom, &g2).unwrap()
        };
        assert!(n2, "all-zero generator must be rejected");
    }
}

/// Differential cross-check: the standard-Bulletproof shim must produce the
/// EXACT SAME commitment bytes as DOM's canonical Pedersen layer
/// ([`crate::pedersen::Commitment::commit`], the same SEC1 the borromean path
/// emits). If they diverged, the range proof and the balance equation would be
/// proving about different commitments. Also checks both proof systems
/// (borromean + bulletproof) verify against that one shared commitment.
#[cfg(test)]
mod differential {
    use super::*;
    use crate::pedersen::Commitment;
    use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

    const SEED: u64 = 0xD0_4D_B_u64; // deterministic, reproducible
    const N_RANDOM: usize = 1000;

    /// Largest valid scalar = secp256k1 group order n - 1.
    const N_MINUS_1: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x40,
    ];

    /// DOM canonical Pedersen commitment (SEC1), via the same path borromean uses.
    fn canonical_sec1(value: u64, blinding: &BlindingFactor) -> [u8; 33] {
        *Commitment::commit(value, blinding).as_bytes()
    }

    /// Shim commitment (SEC1), exactly as `bp_prove` computes it, but reusing a
    /// shared backend so a 1000-iteration loop stays fast. Equivalence to the
    /// public `bp_prove` wrapper is asserted separately in `fixed_and_edges`.
    fn shim_sec1(backend: &Backend, h_dom: &[u8; 64], value: u64, blinding: &BlindingFactor) -> [u8; 33] {
        let zkp = commit_zkp(backend, value, blinding.as_bytes(), h_dom).expect("commit_zkp");
        zkp_to_sec1(&zkp).expect("zkp->sec1")
    }

    /// Assert byte-identical commitments + both proof systems bind to the shared
    /// commitment. `report` labels the pair for a CRITICAL mismatch.
    fn check_pair(
        backend: &Backend,
        h_dom: &[u8; 64],
        value: u64,
        blinding: &BlindingFactor,
        report: &str,
    ) {
        let canon = canonical_sec1(value, blinding);
        let shim = shim_sec1(backend, h_dom, value, blinding);
        assert_eq!(
            canon,
            shim,
            "CRITICAL commitment mismatch [{report}] value={value} blinding={}\n  canonical(pedersen)={}\n  shim(bulletproof_bp)={}",
            hex::encode(blinding.as_bytes()),
            hex::encode(canon),
            hex::encode(shim),
        );

        // Soundness: both proof systems must verify against this shared commitment.
        // bulletproof (grin) — reuse the shared backend.
        let bp_proof = prove_raw(backend, value, blinding.as_bytes(), h_dom).expect("bp prove");
        let zkp = commit_zkp(backend, value, blinding.as_bytes(), h_dom).expect("commit_zkp");
        assert!(
            verify_raw(backend, &zkp, &bp_proof, h_dom).expect("bp verify"),
            "bulletproof must verify against shared commitment [{report}] value={value}"
        );

        // borromean (Blockstream) — its returned commitment must equal canonical too.
        let (rp, borr_sec1) = crate::bulletproof::prove(value, blinding).expect("borromean prove");
        assert_eq!(
            canon, borr_sec1,
            "CRITICAL borromean commitment != canonical [{report}] value={value}"
        );
        assert!(
            crate::bulletproof::verify(&canon, &rp.bytes).expect("borromean verify"),
            "borromean must verify against shared commitment [{report}] value={value}"
        );
    }

    #[test]
    fn fixed_and_edges() {
        let backend = backend();
        let h_dom = h_dom_internal(backend).expect("H_DOM");

        // The shared-backend shim path must match the public bp_prove wrapper byte-for-byte.
        {
            let b = BlindingFactor::from_bytes([0x11u8; 32]).unwrap();
            let (_proof, wrapper_sec1) = bp_prove(42, &b).unwrap();
            assert_eq!(
                wrapper_sec1,
                shim_sec1(backend, &h_dom, 42, &b),
                "public bp_prove must match shared-backend shim commitment"
            );
            assert_eq!(
                wrapper_sec1,
                canonical_sec1(42, &b),
                "public bp_prove must match canonical Pedersen commitment"
            );
        }

        let fixed_values: [u64; 8] = [
            0,
            1,
            42,
            1_000,
            1_000_000,
            1u64 << 26,
            1u64 << 40,
            MAX_PROVABLE_VALUE, // 2^52 - 1
        ];
        let edge_blindings: [[u8; 32]; 3] = [
            {
                let mut b = [0u8; 32];
                b[31] = 1; // smallest valid scalar (=1)
                b
            },
            N_MINUS_1, // largest valid scalar
            {
                let mut b = [0u8; 32];
                b[1..].fill(0xff);
                b[0] = 0x00; // leading 0x00 keeps it < n; "high" pattern, last byte 0xff
                b[31] = 0x01; // last-byte-1
                b
            },
        ];

        // Fixed values with a fixed mid blinding.
        let mid = BlindingFactor::from_bytes([0x7Au8; 32]).unwrap();
        for &v in fixed_values.iter() {
            check_pair(backend, &h_dom, v, &mid, "fixed");
        }
        // Edge blindings across a few values.
        for (i, eb) in edge_blindings.iter().enumerate() {
            let b = BlindingFactor::from_bytes(*eb)
                .unwrap_or_else(|e| panic!("edge blinding {i} invalid: {e:?}"));
            for &v in &[0u64, 42, 1_000_000, MAX_PROVABLE_VALUE] {
                check_pair(backend, &h_dom, v, &b, "edge");
            }
        }
    }

    #[test]
    fn random_1000_match() {
        let backend = backend();
        let h_dom = h_dom_internal(backend).expect("H_DOM");
        let mut rng = StdRng::seed_from_u64(SEED);

        for i in 0..N_RANDOM {
            let value = rng.gen_range(0..=MAX_PROVABLE_VALUE);
            let blinding = loop {
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                if let Ok(b) = BlindingFactor::from_bytes(bytes) {
                    break b;
                }
            };
            check_pair(backend, &h_dom, value, &blinding, &format!("random#{i}"));
        }
    }
}
