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
use crate::sec1_zkp_bridge::{sec1_to_zkp, zkp_to_sec1}; // single source of truth for SEC1<->zkp
use dom_core::DomError;
use rand::RngCore;
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

// SEC1 <-> zkp commitment encoding is shared with the borromean path via
// `crate::sec1_zkp_bridge` (imported above) — single source of truth.

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

/// Owns one grin scratch space, created and destroyed PER FFI CALL.
///
/// DS-001: the scratch must NOT be reused across calls. grin's bulletproof FFI
/// can return early on a malformed proof WITHOUT releasing the scratch frame it
/// allocated; reusing the same scratch then accumulates leaked frames until the
/// arena pointer walks off its region and the next call SEGVs (reproduced: a
/// valid proof crashing on the 5th call after malformed ones). Creating a fresh
/// scratch per call and destroying it on scope exit (Drop) mirrors grin's own
/// usage (`pedersen.rs` wraps every prove/verify in create+destroy) and gives
/// each call a clean arena, so a leak in one call cannot poison the next.
struct ScratchHandle(*mut ffi::ScratchSpace);

impl ScratchHandle {
    /// Create a fresh scratch space for a single FFI operation. Paired with
    /// Drop (destroy), this gives create+destroy per call — grin's own usage
    /// pattern (pedersen.rs). A reused scratch can leak a frame when the FFI
    /// returns early on a malformed proof, accumulating until SEGV (DS-001).
    fn new(backend: &Backend) -> Self {
        // SAFETY: backend.ctx is live for the process lifetime; SCRATCH_SIZE > 0.
        let s = unsafe { ffi::secp256k1_scratch_space_create(backend.ctx, SCRATCH_SIZE) };
        assert!(!s.is_null(), "grin scratch_space_create returned null");
        ScratchHandle(s)
    }
}

impl Drop for ScratchHandle {
    fn drop(&mut self) {
        // SAFETY: created via scratch_space_create on the shared ctx; destroyed
        // exactly once, when this per-call handle leaves scope, never used after.
        unsafe { ffi::secp256k1_scratch_space_destroy(self.0) };
    }
}

/// Parse the canonical H_DOM into grin's 64-byte internal generator form.
fn h_dom_internal(backend: &Backend) -> Result<[u8; 64], DomError> {
    let ser = h_dom_zkp_serialized()?;
    let mut g = [0u8; 64];
    // SAFETY: ctx live; g writable for 64 bytes; ser readable for 33 bytes.
    let ok =
        unsafe { raw_ffi::secp256k1_generator_parse(backend.ctx, g.as_mut_ptr(), ser.as_ptr()) };
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
    unsafe {
        ffi::secp256k1_pedersen_commitment_serialize(backend.ctx, out.as_mut_ptr(), ci.as_ptr())
    };
    Ok(out)
}

/// Bulletproof prove for `value` under `value_gen` with EXPLICIT nonces.
/// The proof is a deterministic function of (value, blind, value_gen, rewind,
/// private) — fixed nonces => byte-identical proof (see determinism gate test).
fn prove_raw_with_nonces(
    backend: &Backend,
    value: u64,
    blind: &[u8; 32],
    value_gen: &[u8; 64],
    rewind: &[u8; 32],
    private: &[u8; 32],
) -> Result<Vec<u8>, DomError> {
    let mut proof = [0u8; constants::MAX_PROOF_SIZE];
    let mut plen: usize = constants::MAX_PROOF_SIZE;
    let blinds: [*const u8; 1] = [blind.as_ptr()];
    let v = value;

    // DS-001: fresh scratch per call, destroyed on scope exit (Drop) — same
    // create+destroy-per-call discipline the verify path uses, so the prove path
    // can never reuse (and thus poison) a scratch arena across calls.
    let scratch = ScratchHandle::new(backend);
    // SAFETY: shared ctx/gens are live for the process lifetime; `scratch` is a
    // freshly-created arena exclusive to this call; all pointers are valid for
    // the call (proof writable for plen; blind/value_gen/nonces fixed lengths).
    let r = unsafe {
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
    };
    if r != 1 {
        return Err(DomError::Internal("bulletproof prove failed".into()));
    }
    Ok(proof[..plen].to_vec())
}

/// Bulletproof prove for `value` under `value_gen` with fresh RANDOM nonces.
fn prove_raw(
    backend: &Backend,
    value: u64,
    blind: &[u8; 32],
    value_gen: &[u8; 64],
) -> Result<Vec<u8>, DomError> {
    let mut rewind = [0u8; 32];
    let mut private = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut rewind);
    rand::thread_rng().fill_bytes(&mut private);
    prove_raw_with_nonces(backend, value, blind, value_gen, &rewind, &private)
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
    if unsafe {
        ffi::secp256k1_pedersen_commitment_parse(
            backend.ctx,
            ci.as_mut_ptr(),
            commit_zkp33.as_ptr(),
        )
    } != 1
    {
        return Ok(false);
    }
    // DS-001: fresh scratch per call, destroyed on scope exit (Drop), so a frame
    // the FFI may leak on a malformed proof cannot accumulate into a later SEGV.
    let scratch = ScratchHandle::new(backend);
    // SAFETY: shared ctx/gens are live for the process lifetime; `scratch` is a
    // freshly-created arena exclusive to this call; proof readable for
    // proof.len(); ci is a valid internal commitment.
    let r = unsafe {
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
pub fn bp_prove(value: u64, blinding: &BlindingFactor) -> Result<(Vec<u8>, [u8; 33]), DomError> {
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

// Domain-separation tags for deriving grin's two bulletproof nonces from DOM's
// single deterministic seed. Distinct tags => independent rewind/private nonces
// from the same seed, mirroring borromean's single-nonce determinism while
// satisfying grin's two-nonce API. Stable: changing these changes every
// deterministic (e.g. genesis) proof, so they are frozen by the pinned vector test.
const TAG_BP2_REWIND_NONCE: &str = "DOM:bp2-rewind-nonce:v1";
const TAG_BP2_PRIVATE_NONCE: &str = "DOM:bp2-private-nonce:v1";

/// Generate a standard Bulletproof for `(value, blinding)` under H_DOM with a
/// DETERMINISTIC nonce derived from a single 32-byte DOM seed.
///
/// Mirrors borromean's `prove_with_nonce` (one seed in), but grin's prover needs
/// two nonces, so both are derived from the seed via domain-separated tagged
/// hashes ([`TAG_BP2_REWIND_NONCE`] / [`TAG_BP2_PRIVATE_NONCE`]). A fixed seed
/// therefore yields a byte-reproducible proof — required for the genesis block.
///
/// Returns `(proof_bytes, commitment_sec1)`. Rejects `value > MAX_PROVABLE_VALUE`
/// before any FFI call. Exported as `bp2_prove_with_nonce`.
pub fn bp_prove_with_nonce(
    value: u64,
    blinding: &BlindingFactor,
    nonce_bytes: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 33]), DomError> {
    if value > MAX_PROVABLE_VALUE {
        return Err(DomError::Invalid(format!(
            "value {value} > MAX_PROVABLE_VALUE {MAX_PROVABLE_VALUE}"
        )));
    }
    // Deterministically derive grin's two nonces from the single DOM seed.
    let rewind = *crate::blake2b_256_tagged(TAG_BP2_REWIND_NONCE, nonce_bytes).as_bytes();
    let private = *crate::blake2b_256_tagged(TAG_BP2_PRIVATE_NONCE, nonce_bytes).as_bytes();

    let backend = backend();
    let h_dom = h_dom_internal(backend)?;
    let blind = blinding.as_bytes();
    let zkp = commit_zkp(backend, value, blind, &h_dom)?;
    let sec1 = zkp_to_sec1(&zkp)?;
    let proof = prove_raw_with_nonces(backend, value, blind, &h_dom, &rewind, &private)?;
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
    if proof_bytes.len() != SINGLE_BULLETPROOF_SIZE {
        return Err(DomError::Malformed(format!(
            "range proof tamanho invalido: {} bytes (esperado {SINGLE_BULLETPROOF_SIZE})",
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

    /// DS-001 regression: `bp_verify` must reject any proof whose length is not
    /// EXACTLY `SINGLE_BULLETPROOF_SIZE` (675) BEFORE any FFI call on the proof —
    /// closing the SEGV path (the reproducer was a 651-byte proof that reached
    /// grin's scalar parse). Off-size proofs are stopped by the size gate; only
    /// the exact 675-byte length proceeds to (safe) verification.
    #[test]
    fn ds001_proof_size_must_be_exact() {
        let blind = BlindingFactor::from_bytes(TEST_BLIND).expect("blind");
        let (proof, commitment) = bp_prove(42, &blind).expect("bp2 prove");
        assert_eq!(
            proof.len(),
            SINGLE_BULLETPROOF_SIZE,
            "sanity: a real Bulletproof is exactly 675 bytes"
        );

        // Exact-size (675) real proof passes the size gate AND verifies.
        match bp_verify(&commitment, &proof) {
            Ok(true) => {}
            other => panic!("valid 675-byte proof must verify Ok(true), got {other:?}"),
        }

        // A 675-byte all-zeros proof passes the SIZE gate (675 == 675); it then
        // fails verification, but the error must NOT be a size error.
        match bp_verify(&commitment, &[0u8; SINGLE_BULLETPROOF_SIZE]) {
            Ok(false) => {}
            Ok(true) => panic!("all-zeros 675-byte proof must not verify true"),
            Err(e) => assert!(
                !e.to_string().contains("tamanho invalido"),
                "675-byte proof must not be rejected by the size gate, got: {e}"
            ),
        }

        // Off-size proofs (incl. 651 = the DS-001 reproducer, the 674/676
        // boundaries, and 768 = the old cap) are rejected by the size gate with
        // the specific message, BEFORE any FFI touches the proof bytes.
        for len in [651usize, 674, 676, 768] {
            let err = bp_verify(&commitment, &vec![0u8; len])
                .expect_err("off-size proof must be rejected");
            assert!(
                err.to_string().contains("tamanho invalido"),
                "len {len} must be rejected as size-invalid, got: {err}"
            );
        }

        // Empty proof keeps its specific message.
        let err_empty = bp_verify(&commitment, &[]).expect_err("empty must be rejected");
        assert!(
            err_empty.to_string().contains("range proof vazio"),
            "empty proof must report 'range proof vazio', got: {err_empty}"
        );
    }

    /// DS-001 REGRESSION GUARDIAN (runs always — it must NOT crash).
    ///
    /// Feeds the grin FFI 200 exact-675-byte but MALFORMED proofs (blake2b of a
    /// counter), all on the SAME thread, against a valid SEC1 commitment. Before
    /// the per-call scratch fix this reused-scratch hammering accumulated leaked
    /// frames and SEGV'd; now every call MUST return (`Ok(false)` or `Err`). A
    /// panic/SEGV here means the scratch is being reused again (DS-001 regressed).
    #[test]
    fn ds001_exact_size_malformed_does_not_crash() {
        // Deterministic pseudo-random 675-byte buffer derived from a counter.
        fn pseudo_random_675(counter: u32) -> Vec<u8> {
            let mut out = Vec::with_capacity(SINGLE_BULLETPROOF_SIZE);
            let mut block: u32 = 0;
            while out.len() < SINGLE_BULLETPROOF_SIZE {
                let mut seed = Vec::with_capacity(8);
                seed.extend_from_slice(&counter.to_le_bytes());
                seed.extend_from_slice(&block.to_le_bytes());
                let h = crate::blake2b_256_tagged("DOM:ds001-malformed-probe:v1", &seed);
                out.extend_from_slice(h.as_bytes());
                block += 1;
            }
            out.truncate(SINGLE_BULLETPROOF_SIZE);
            out
        }

        let blind = BlindingFactor::from_bytes([0x22u8; 32]).expect("blind");
        let (_real_proof, commitment) = bp_prove(7, &blind).expect("bp2 prove");

        for i in 0..200u32 {
            let proof = pseudo_random_675(i);
            assert_eq!(
                proof.len(),
                SINGLE_BULLETPROOF_SIZE,
                "probe proof must be exactly 675 bytes"
            );
            // Flushed marker so a SEGV inside the FFI leaves the crashing index
            // as the last line on stderr (identifies the deterministic reproducer).
            eprintln!("PROBE iter {i} -> calling bp_verify ...");
            // Must RETURN gracefully — never panic / SEGV. A valid commitment +
            // exact-size proof reaches the grin verify FFI by design here.
            match bp_verify(&commitment, &proof) {
                Ok(false) | Err(_) => {}
                Ok(true) => {
                    panic!("iteration {i}: malformed 675-byte proof verified TRUE (impossible)")
                }
            }
        }
        println!("DS-001 probe: 200 malformed 675-byte proofs all returned gracefully (no crash).");
    }

    /// DS-001 REGRESSION GUARDIAN (runs always — it must NOT crash).
    ///
    /// This is the permanent guardian distilled from the DS-001 state-vs-content
    /// investigation. That investigation proved the SEGV was NOT content-driven
    /// (a single malformed counter=4 in isolation survived) but ACCUMULATION-
    /// driven: reusing one per-thread grin scratch space leaked a frame on each
    /// malformed-proof FFI call until the arena pointer ran off its region and a
    /// later call SEGV'd — deterministically the 5th call, even when that 5th
    /// call was a VALID proof (the "Scenario D" interleave). The fix
    /// creates+destroys the scratch PER CALL, so frames cannot accumulate.
    ///
    /// The test hammers the SAME thread with 12 `bp_verify` calls, interleaving
    /// malformed 675-byte proofs (counters 0..=6) with valid proofs from
    /// `bp_prove`. The first five calls reproduce Scenario D EXACTLY
    /// (valid, malformed, valid, malformed, valid) — the trailing valid 5th call
    /// is the one that used to SEGV. Every call must return gracefully (Ok/Err)
    /// with no panic/SEGV. If the scratch is ever reused again, this test crashes
    /// the whole test process — the strongest possible regression signal.
    #[test]
    fn ds001_scratch_no_accumulation_regression() {
        // Deterministic 675-byte pseudo-random buffer — same derivation the other
        // DS-001 probes use, so reproducers line up across tests.
        fn malformed_proof(counter: u32) -> Vec<u8> {
            let mut out = Vec::with_capacity(SINGLE_BULLETPROOF_SIZE);
            let mut block: u32 = 0;
            while out.len() < SINGLE_BULLETPROOF_SIZE {
                let mut seed = Vec::with_capacity(8);
                seed.extend_from_slice(&counter.to_le_bytes());
                seed.extend_from_slice(&block.to_le_bytes());
                let h = crate::blake2b_256_tagged("DOM:ds001-malformed-probe:v1", &seed);
                out.extend_from_slice(h.as_bytes());
                block += 1;
            }
            out.truncate(SINGLE_BULLETPROOF_SIZE);
            out
        }

        let blind = BlindingFactor::from_bytes([0x22u8; 32]).expect("blind");
        let (valid_proof, commitment) = bp_prove(7, &blind).expect("bp2 prove");
        assert_eq!(
            valid_proof.len(),
            SINGLE_BULLETPROOF_SIZE,
            "sanity: a real Bulletproof is exactly 675 bytes"
        );

        // 12 calls on ONE thread. Calls 1..=5 are Scenario D verbatim — the old
        // SEGV fired on call 5 (the trailing VALID proof). The rest keep
        // interleaving and cover malformed counters 0..=6.
        let calls: Vec<(&str, Vec<u8>)> = vec![
            ("valid", valid_proof.clone()),      // 1
            ("malformed#1", malformed_proof(1)), // 2  (D)
            ("valid", valid_proof.clone()),      // 3  (D)
            ("malformed#3", malformed_proof(3)), // 4  (D)
            ("valid", valid_proof.clone()),      // 5  <- old crash point (VALID)
            ("malformed#0", malformed_proof(0)), // 6
            ("valid", valid_proof.clone()),      // 7
            ("malformed#2", malformed_proof(2)), // 8
            ("valid", valid_proof.clone()),      // 9
            ("malformed#4", malformed_proof(4)), // 10 (the documented reproducer counter)
            ("malformed#5", malformed_proof(5)), // 11
            ("malformed#6", malformed_proof(6)), // 12
        ];
        assert!(
            calls.len() >= 12,
            "regression must exercise at least 12 same-thread calls"
        );

        for (i, (label, proof)) in calls.iter().enumerate() {
            let n = i + 1;
            assert_eq!(
                proof.len(),
                SINGLE_BULLETPROOF_SIZE,
                "call {n} ({label}) must be exactly 675 bytes"
            );
            // Reaching here on every iteration is the assertion: no SEGV/panic.
            match bp_verify(&commitment, proof) {
                Ok(true) => assert!(
                    label.starts_with("valid"),
                    "call {n}: a MALFORMED proof verified TRUE (impossible)"
                ),
                Ok(false) => assert!(
                    !label.starts_with("valid"),
                    "call {n}: a VALID proof failed verification (unexpected)"
                ),
                Err(_) => assert!(
                    !label.starts_with("valid"),
                    "call {n}: a VALID proof returned Err (unexpected)"
                ),
            }
        }
    }

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
            assert!(
                verify_raw(backend, &c_dom, &pr_dom, &h_dom).unwrap(),
                "A v={v}"
            );
            // B: commit=H_DOM prove=H_default verify=H_DOM -> FAIL
            assert!(
                !verify_raw(backend, &c_dom, &pr_def, &h_dom).unwrap(),
                "B v={v}"
            );
            // C: commit=H_DOM prove=H_DOM verify=H_default -> FAIL
            assert!(
                !verify_raw(backend, &c_dom, &pr_dom, &h_def).unwrap(),
                "C v={v}"
            );
            // D: control, all H_default -> PASS
            assert!(
                verify_raw(backend, &c_def, &pr_def, &h_def).unwrap(),
                "D v={v}"
            );

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
        assert!(
            r.is_err(),
            "value above MAX_PROVABLE_VALUE must be rejected"
        );
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
        let parsed2 = unsafe {
            raw_ffi::secp256k1_generator_parse(backend.ctx, g2.as_mut_ptr(), zero.as_ptr())
        };
        let n2 = if parsed2 != 1 {
            true
        } else {
            !verify_raw(backend, &c_dom, &pr_dom, &g2).unwrap()
        };
        assert!(n2, "all-zero generator must be rejected");
    }

    /// DETERMINISM GATE (Phase 2): bp_prove_with_nonce is byte-reproducible.
    /// Two independent proves with the SAME DOM seed yield BYTE-IDENTICAL 675-byte
    /// proofs that verify under H_DOM, for values 0, 42, MAX_PROVABLE_VALUE. This
    /// is the precondition for a reproducible genesis coinbase. If it ever fails,
    /// genesis cannot be reproducible.
    #[test]
    fn bp2_prove_with_nonce_is_deterministic() {
        let blinding = BlindingFactor::from_bytes([0x11u8; 32]).unwrap();
        let nonce = [0x07u8; 32];
        for value in [0u64, 42, MAX_PROVABLE_VALUE] {
            let (p1, sec1_a) = bp_prove_with_nonce(value, &blinding, &nonce).unwrap();
            let (p2, sec1_b) = bp_prove_with_nonce(value, &blinding, &nonce).unwrap();
            assert_eq!(p1.len(), 675, "proof len value={value}");
            assert_eq!(
                p1,
                p2,
                "NON-DETERMINISTIC bp2 proof for value={value}\n p1={}\n p2={}",
                hex::encode(&p1),
                hex::encode(&p2)
            );
            assert_eq!(sec1_a, sec1_b, "commitment must be stable, value={value}");
            assert!(
                bp_verify(&sec1_a, &p1).unwrap(),
                "deterministic proof must verify under H_DOM, value={value}"
            );
        }
    }

    /// FROZEN VECTOR: pins the exact 675-byte deterministic proof + commitment for
    /// a fixed (value, blinding, nonce), so any drift in the nonce derivation or
    /// the prover output is caught. Genesis-style: a fixed seed must always yield
    /// these exact bytes.
    #[test]
    fn bp2_prove_with_nonce_frozen_vector() {
        let blinding = BlindingFactor::from_bytes([0x11u8; 32]).unwrap();
        let nonce = [0x07u8; 32];
        let (proof, sec1) = bp_prove_with_nonce(42, &blinding, &nonce).unwrap();
        assert_eq!(proof.len(), 675);

        // Frozen: value=42, blinding=[0x11;32], DOM seed nonce=[0x07;32], H_DOM.
        const EXPECTED_SEC1: &str =
            "03171d4a3e65fcaf5f0937308dd1fe1cf33c337c4d5f559a03166e051884e9a402";
        const EXPECTED_PROOF: &str = "29816c0be734c6cbd7cdab9d67c66cb8a52b8534bb169abb6d74931931969ff4b32054f674bc9b8ea3e8dfb2a1db3551362bb3308c982e1577108204c9f3378d0cdffd891622f8171d3ba09d1b657248ff5dfcb7aabe7b1d734588336a31a6c774462df4ff4cb42a70fb2ebcfbf747a38edfd76dd621e867b48529be73721fd985a9b86e61edc1b2178170c3d176b941ced3454961d2ddb311d87d9bfe59d90c77ef428aef25f1d5955e0586b6331402f9ee2d81e2e78783f0f67b2ee05b12122c1aec82e0ccc0a3e8b7de99e50c856488dacdc120afe2b50d1fea33ba561be32c685c31920d1746b6dd72367415ec3ce77e47edac38d637421d5a0d37512b7e58ba95ad058c83d051adad94e2b0c79c28fbb3aa330d3568ca0217ebe79a0a16a786fb00307a36b6d434c1e33b92f4bed98ed01deee51b86b290b1f999db52b5b1dff4a823eff374714be6bddb061aebea56f206e3e3423d2a41f16e201529aa0a8002be1f28ff996d2ef438dc34f3a66c3235338c9d4965ae46750f408f45a57f550513b96088d75f881e7ecb969d21752382a62a86c367197c7f7cd0ba7e6b4dd1be9314e228d2e4978e79d409312db971b66e112a24d32778a22af1ce0307a9145fd605b7b15d9b4b9da774b4906d64414967192a7b593f0139ca01687252b2e4db249806da2c7e40b21c33a04ec4321deddbe25192e215cfd54846de6a00d30cab00cfede9396bf33fcd641e47b2699e3955b2c24045ac6d858b7e8d0e9621589c1314df4f7aff3567f4aed04ea27bad63154fbabe6367db329054259dedc42c09992ad09314428b57bf2ec22a08ad1cf1bdae36f01efa11488819b900887e51e28085deeca2d14d675eb85beccb7f56707a072cdfbd55d4838d36e3ce869698419080852d19de2a66559ee23ee8f62e7c212ca6527ecc13df4645772eee4b4a4a";
        assert_eq!(hex::encode(sec1), EXPECTED_SEC1, "commitment drift");
        assert_eq!(hex::encode(&proof), EXPECTED_PROOF, "proof byte drift");
        assert!(bp_verify(&sec1, &proof).unwrap());
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

    const SEED: u64 = 0x000D_04DB_u64; // deterministic, reproducible
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
    fn shim_sec1(
        backend: &Backend,
        h_dom: &[u8; 64],
        value: u64,
        blinding: &BlindingFactor,
    ) -> [u8; 33] {
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
