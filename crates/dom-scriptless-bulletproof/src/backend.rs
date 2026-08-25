//! Final bounded aggregate Bulletproof backend (grin `secp256k1zkp`).
//!
//! This module is the only production backend for DOM confidential-output range
//! proofs. It is built on grin's `secp256k1zkp` classic Bulletproof rangeproof
//! and produces one bounded aggregate proof of [`SINGLE_BULLETPROOF_SIZE`] =
//! 739 bytes for two commitments.
//!
//! Proofs here are bound to DOM's **H_DOM** value generator (RFC9380,
//! DST="DOM:h2c:secp256k1:v6.1"). grin's *safe* API hardcodes its own
//! `GENERATOR_H`, so H_DOM is supplied through the raw FFI `value_gen`
//! parameter.
//!
//! Commitments are exchanged in **SEC1** compressed form (`0x02/0x03 || X`);
//! internally they round-trip through libsecp Pedersen zkp form (`0x08/0x09`,
//! is_square encoding).
//!
//! Status: live final range-proof backend under H_DOM. Each output proves
//! both `v` and `MAX_PROVABLE_VALUE - v` in one aggregate proof, so consensus
//! verification enforces DOM's 52-bit ceiling without relying on unsupported
//! upstream `max_value` semantics.

// Justification for overriding the crate-wide `#![deny(unsafe_code)]`:
// the grin bulletproof rangeproof is only reachable through C FFI. The unsafe
// surface is confined to this module's `raw_ffi` block and the thin helpers
// that call it; every unsafe site documents its SAFETY invariants. The rest of
// the crate remains safe Rust.
// ── TRANSCRIPTION, NOT A SECOND DESIGN ────────────────────────────────────
// This module is `dom-crypto/src/bulletproof_bp.rs` of the F7 lineage, moved
// here unchanged except for the paths above, because the mainnet node cannot
// be edited to expose its crate-private grin backend to the MPC that needs
// it. `conformance` at the end of this file pins the copy to the node.
// ──────────────────────────────────────────────────────────────────────────

#![allow(unsafe_code)]
// Keep dead_code allowed because this module still exposes some narrowly scoped
// helper paths only used by tests/regressions.
#![allow(dead_code)]

use crate::node_private::{derive_complement_commitment, negate_blinding};
use crate::sec1_zkp_bridge::{sec1_to_zkp, zkp_to_sec1}; // single source of truth for SEC1<->zkp
use dom_core::DomError;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::range_proof::MAX_PROVABLE_VALUE;
use rand::RngCore;
use secp256k1zkp::{constants, ffi};
use std::ptr;
use zeroize::{Zeroize, Zeroizing};

/// Serialized byte length of DOM's bounded aggregate Bulletproof:
/// one proof over `(v, MAX_PROVABLE_VALUE - v)`, both as 64-bit commitments.
/// grin upstream's classic aggregate format yields 739 bytes for `(nbits=64,
/// n_commits=2)`, which still fits DOM's 768-byte consensus envelope.
pub(crate) const SINGLE_BULLETPROOF_SIZE: usize = 739;

/// Number of bits proven per commitment by grin classic Bulletproof.
/// DOM keeps the upstream-valid 64-bit width and enforces the 52-bit ceiling by
/// aggregating proofs for `(v, MAX_PROVABLE_VALUE - v)`.
pub(crate) const PROOF_NBITS: usize = 64;

/// DOM proves two commitments per output:
///   1. `v`
///   2. `MAX_PROVABLE_VALUE - v`
const PROOF_NCOMMITS: usize = 2;

const MPC_FINALIZE_CONTINUATION_MAGIC_V1: &[u8; 4] = b"DBFC";
const MPC_FINALIZE_CONTINUATION_VERSION_V1: u16 = 1;
const MPC_FINALIZE_CONTINUATION_FIXED_LEN_V1: usize = 278;
const MPC_FINALIZE_CONTINUATION_MAX_EXTRA_COMMIT_LEN_V1: usize = u16::MAX as usize;

fn proof_has_valid_curve_points(proof: &[u8]) -> bool {
    // The first Bulletproof section is 64 bytes of scalars followed by one
    // parity byte and four x-only points (32 bytes each).
    if proof.len() < 64 + 1 + 4 * 32 {
        return false;
    }
    let parity = proof[64];
    (0..4).all(|i| {
        let mut sec1 = [0u8; 33];
        sec1[0] = if parity & (1 << i) == 0 { 0x02 } else { 0x03 };
        sec1[1..].copy_from_slice(&proof[65 + i * 32..97 + i * 32]);
        secp256k1::PublicKey::from_slice(&sec1).is_ok()
    })
}

/// Scratch arena size for grin's bulletproof FFI, per thread (reused, not
/// per-call). Empirically the minimum for a single 64-bit proof is ~15.8 KiB to
/// prove / ~9.2 KiB to verify (measured against grin 0.7.15); 1 MiB gives ~65x
/// headroom while being 256x smaller than grin's batch-sized 256 MiB default.
const SCRATCH_SIZE: usize = 1 << 20; // 1 MiB

/// Number of bulletproof generators to create.
/// For the bounded aggregate proof, verify/prove need `2 * nbits * n_commits`
/// generators = `2 * 64 * 2 = 256`, so the existing grin-sized set remains exact.
const N_GENERATORS: usize = 256;

/// H_DOM value generator in grin's 33-byte *zkp-serialized* form (`0x0a || H_DOM_X`).
///
/// The x-coordinate is sourced from the crate's single canonical derivation
/// ([`dom_crypto::h_generator::derive_h_generator`]) so this path can never diverge
/// from the canonical H_DOM generator. The 0x0a/0x0b prefix encodes Y parity
/// (mapped from the SEC1 0x02/0x03 prefix), matching the
/// generator-serialization convention libsecp256k1-zkp's `generator_parse`
/// expects.
pub(crate) fn h_dom_zkp_serialized() -> Result<[u8; 33], DomError> {
    let compressed = dom_crypto::h_generator::derive_h_generator()?; // 0x02||X or 0x03||X
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

// SEC1 <-> zkp commitment encoding is centralized in `crate::sec1_zkp_bridge`.

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

        /// Parse one canonical compressed SEC1 public key into the backend
        /// representation used by the multiparty prover phases.
        pub(crate) fn secp256k1_ec_pubkey_parse(
            ctx: *const Context,
            output: *mut PublicKey,
            input: *const c_uchar,
            input_len: size_t,
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

static SHARED: std::sync::OnceLock<Result<Backend, &'static str>> = std::sync::OnceLock::new();

/// Lazily initialize and return the process-wide shared backend.
fn backend() -> Result<&'static Backend, DomError> {
    let initialized = SHARED.get_or_init(|| {
        // SAFETY: standard grin constructors; both results are checked before
        // their pointers can enter `Backend`. Initialization failure remains a
        // typed fail-closed error instead of aborting the process.
        unsafe {
            let ctx = ffi::secp256k1_context_create(
                ffi::SECP256K1_START_SIGN | ffi::SECP256K1_START_VERIFY,
            );
            if ctx.is_null() {
                return Err("grin context_create returned null");
            }
            let gens = ffi::secp256k1_bulletproof_generators_create(
                ctx,
                constants::GENERATOR_G.as_ptr(),
                N_GENERATORS,
            );
            if gens.is_null() {
                ffi::secp256k1_context_destroy(ctx);
                return Err("grin generators_create returned null");
            }
            Ok(Backend { ctx, gens })
        }
    });
    initialized
        .as_ref()
        .map_err(|message| DomError::Internal((*message).into()))
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
    fn new(backend: &Backend) -> Result<Self, DomError> {
        // SAFETY: backend.ctx is live for the process lifetime; SCRATCH_SIZE > 0.
        let s = unsafe { ffi::secp256k1_scratch_space_create(backend.ctx, SCRATCH_SIZE) };
        if s.is_null() {
            return Err(DomError::Internal(
                "grin scratch_space_create returned null".into(),
            ));
        }
        Ok(ScratchHandle(s))
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

/// Bulletproof prove for `values` / `blinds` under `value_gen` with explicit
/// nonces. The proof is deterministic in the full witness tuple, so fixed
/// nonces yield byte-identical aggregate proofs.
fn prove_raw_values_with_nonces(
    backend: &Backend,
    values: &[u64],
    blinds: &[[u8; 32]],
    value_gen: &[u8; 64],
    rewind: &[u8; 32],
    private: &[u8; 32],
    extra_commit: &[u8],
) -> Result<Vec<u8>, DomError> {
    let extra_commit_ptr = if extra_commit.is_empty() {
        ptr::null()
    } else {
        extra_commit.as_ptr()
    };
    let mut proof = [0u8; constants::MAX_PROOF_SIZE];
    let mut plen: usize = constants::MAX_PROOF_SIZE;
    let blind_ptrs: Vec<*const u8> = blinds.iter().map(|b| b.as_ptr()).collect();

    // DS-001: fresh scratch per call, destroyed on scope exit (Drop) — same
    // create+destroy-per-call discipline the verify path uses, so the prove path
    // can never reuse (and thus poison) a scratch arena across calls.
    let scratch = ScratchHandle::new(backend)?;
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
            values.as_ptr(),
            ptr::null(),
            blind_ptrs.as_ptr(),
            ptr::null(),
            values.len(),
            value_gen.as_ptr(),
            PROOF_NBITS,
            rewind.as_ptr(),
            private.as_ptr(),
            extra_commit_ptr,
            extra_commit.len(),
            ptr::null(),
        )
    };
    if r != 1 {
        return Err(DomError::Internal("bulletproof prove failed".into()));
    }
    Ok(proof[..plen].to_vec())
}

/// Prove the bounded pair `(value, MAX_PROVABLE_VALUE - value)` under H_DOM.
fn prove_raw_with_nonces(
    backend: &Backend,
    value: u64,
    blind: &[u8; 32],
    value_gen: &[u8; 64],
    rewind: &[u8; 32],
    private: &[u8; 32],
    extra_commit: &[u8],
) -> Result<Vec<u8>, DomError> {
    let complement_value = MAX_PROVABLE_VALUE
        .checked_sub(value)
        .ok_or_else(|| DomError::Invalid("value exceeds MAX_PROVABLE_VALUE".into()))?;
    let complement_blind = negate_blinding(blind)?;
    let values = [value, complement_value];
    let blinds = [*blind, complement_blind];
    prove_raw_values_with_nonces(
        backend,
        &values,
        &blinds,
        value_gen,
        rewind,
        private,
        extra_commit,
    )
}

/// Bulletproof prove for `value` under `value_gen` with fresh RANDOM nonces.
fn prove_raw(
    backend: &Backend,
    value: u64,
    blind: &[u8; 32],
    value_gen: &[u8; 64],
    extra_commit: &[u8],
) -> Result<Vec<u8>, DomError> {
    let mut rewind = [0u8; 32];
    let mut private = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut rewind);
    rand::thread_rng().fill_bytes(&mut private);
    prove_raw_with_nonces(
        backend,
        value,
        blind,
        value_gen,
        &rewind,
        &private,
        extra_commit,
    )
}

/// Bulletproof verify of `proof` against a commitment pair under `value_gen`.
fn verify_raw(
    backend: &Backend,
    commit_zkp33: &[[u8; 33]; PROOF_NCOMMITS],
    proof: &[u8],
    value_gen: &[u8; 64],
    extra_commit: &[u8],
) -> Result<bool, DomError> {
    let extra_commit_ptr = if extra_commit.is_empty() {
        ptr::null()
    } else {
        extra_commit.as_ptr()
    };
    let mut cis = [[0u8; 64]; PROOF_NCOMMITS];
    for (i, commit) in commit_zkp33.iter().enumerate() {
        // SAFETY: ctx live; each slot writable for 64 bytes; commits readable for 33 bytes.
        if unsafe {
            ffi::secp256k1_pedersen_commitment_parse(
                backend.ctx,
                cis[i].as_mut_ptr(),
                commit.as_ptr(),
            )
        } != 1
        {
            return Ok(false);
        }
    }
    // DS-001: fresh scratch per call, destroyed on scope exit (Drop), so a frame
    // the FFI may leak on a malformed proof cannot accumulate into a later SEGV.
    let scratch = ScratchHandle::new(backend)?;
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
            cis.as_ptr() as *const u8,
            PROOF_NCOMMITS,
            PROOF_NBITS,
            value_gen.as_ptr(),
            extra_commit_ptr,
            extra_commit.len(),
        )
    };
    Ok(r == 1)
}

/// Generate a standard Bulletproof for `(value, blinding)` under H_DOM.
///
/// Returns `(proof_bytes, commitment_sec1)`. Rejects `value > MAX_PROVABLE_VALUE`
/// before any FFI call.
///
/// Exposed through the stable `range_proof` API.
/// The proof is one aggregate proof over `(v, MAX_PROVABLE_VALUE - v)`, binding
/// the output to the same 52-bit ceiling consensus expects.
pub fn bp_prove(value: u64, blinding: &BlindingFactor) -> Result<(Vec<u8>, [u8; 33]), DomError> {
    if value > MAX_PROVABLE_VALUE {
        return Err(DomError::Invalid(format!(
            "value {value} > MAX_PROVABLE_VALUE {MAX_PROVABLE_VALUE}"
        )));
    }
    let backend = backend()?;
    let h_dom = h_dom_internal(backend)?;
    let blind = blinding.as_bytes();
    let zkp = commit_zkp(backend, value, blind, &h_dom)?;
    let sec1 = zkp_to_sec1(&zkp)?;
    let proof = prove_raw(backend, value, blind, &h_dom, &[])?;
    Ok((proof, sec1))
}

/// Generate the final bounded proof while committing immutable application
/// bytes into its transcript. Wallet V3 binds its recovery capsule here.
pub fn bp_prove_with_extra_commit(
    value: u64,
    blinding: &BlindingFactor,
    extra_commit: &[u8],
) -> Result<(Vec<u8>, [u8; 33]), DomError> {
    if value > MAX_PROVABLE_VALUE {
        return Err(DomError::Invalid(format!(
            "value {value} > MAX_PROVABLE_VALUE {MAX_PROVABLE_VALUE}"
        )));
    }
    if extra_commit.is_empty() {
        return Err(DomError::Invalid(
            "range proof extra commitment must not be empty".into(),
        ));
    }
    let backend = backend()?;
    let h_dom = h_dom_internal(backend)?;
    let blind = blinding.as_bytes();
    let zkp = commit_zkp(backend, value, blind, &h_dom)?;
    let sec1 = zkp_to_sec1(&zkp)?;
    let proof = prove_raw(backend, value, blind, &h_dom, extra_commit)?;
    Ok((proof, sec1))
}

// Domain-separation tags for deriving grin's two bulletproof nonces from DOM's
// single deterministic seed. Distinct tags => independent rewind/private nonces
// from the same seed while satisfying grin's two-nonce API. Stable: changing these changes every
// deterministic (e.g. genesis) proof, so they are frozen by the pinned vector test.
const TAG_BP2_REWIND_NONCE: &str = "DOM:bp2-rewind-nonce:v1";
const TAG_BP2_PRIVATE_NONCE: &str = "DOM:bp2-private-nonce:v1";

/// Generate a standard Bulletproof for `(value, blinding)` under H_DOM with a
/// DETERMINISTIC nonce derived from a single 32-byte DOM seed.
///
/// grin's prover needs two nonces, so both are derived from the seed via
/// domain-separated tagged hashes ([`TAG_BP2_REWIND_NONCE`] /
/// [`TAG_BP2_PRIVATE_NONCE`]). A fixed seed
/// therefore yields a byte-reproducible proof — required for the genesis block.
///
/// Returns `(proof_bytes, commitment_sec1)`. Rejects `value > MAX_PROVABLE_VALUE`
/// before any FFI call. Exposed through the stable `range_proof` API.
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
    let rewind = *dom_crypto::blake2b_256_tagged(TAG_BP2_REWIND_NONCE, nonce_bytes).as_bytes();
    let private = *dom_crypto::blake2b_256_tagged(TAG_BP2_PRIVATE_NONCE, nonce_bytes).as_bytes();

    let backend = backend()?;
    let h_dom = h_dom_internal(backend)?;
    let blind = blinding.as_bytes();
    let zkp = commit_zkp(backend, value, blind, &h_dom)?;
    let sec1 = zkp_to_sec1(&zkp)?;
    let proof = prove_raw_with_nonces(backend, value, blind, &h_dom, &rewind, &private, &[])?;
    Ok((proof, sec1))
}

/// Test-only escape hatch for constructing a legacy single-commit bp2 proof.
///
/// This exists solely to regression-test that the bounded aggregate verifier
/// rejects the historical unsafe format, including over-cap values. Production
/// code must continue using [`bp_prove`], which enforces the 52-bit ceiling and
/// emits the bounded aggregate proof.
#[cfg(any(test, feature = "test-helpers"))]
#[doc(hidden)]
pub fn bp2_test_only_prove_legacy_single_with_nonce(
    value: u64,
    blinding: &BlindingFactor,
    nonce: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 33]), DomError> {
    let backend = backend()?;
    let h_dom = h_dom_internal(backend)?;
    let zkp = commit_zkp(backend, value, blinding.as_bytes(), &h_dom)?;
    let sec1 = zkp_to_sec1(&zkp)?;
    let proof = prove_raw_values_with_nonces(
        backend,
        &[value],
        &[*blinding.as_bytes()],
        &h_dom,
        nonce,
        nonce,
        &[],
    )?;
    Ok((proof, sec1))
}

/// Verify a final bounded aggregate Bulletproof against a SEC1 commitment under H_DOM.
///
/// Exposed through the stable `range_proof` API.
/// The verifier derives `C' = MAX_PROVABLE_VALUE*H - C` and verifies one
/// aggregate proof over `[C, C']`, closing the historical 64-bit inflation gap.
pub fn bp_verify(commitment_sec1: &[u8; 33], proof_bytes: &[u8]) -> Result<bool, DomError> {
    if proof_bytes.is_empty() {
        return Err(DomError::Malformed("range proof is empty".into()));
    }
    if !crate::node_private::range_proof_length_is_canonical(proof_bytes.len()) {
        return Err(DomError::Malformed(format!(
            "invalid range proof length: {} bytes (expected {SINGLE_BULLETPROOF_SIZE})",
            proof_bytes.len()
        )));
    }
    // The classic grin proof begins with a zkp-serialized curve point.  Reject
    // impossible prefixes before entering the C verifier: malformed proofs
    // otherwise reach a grin early-return path that leaks its scratch frame.
    if !proof_has_valid_curve_points(proof_bytes) {
        return Ok(false);
    }
    let backend = backend()?;
    let h_dom = h_dom_internal(backend)?;
    let complement_sec1 = derive_complement_commitment(
        &dom_crypto::pedersen::Commitment::from_compressed_bytes(commitment_sec1)?,
        MAX_PROVABLE_VALUE,
    )?;
    let commits = [
        sec1_to_zkp(commitment_sec1)?,
        sec1_to_zkp(complement_sec1.as_bytes())?,
    ];
    verify_raw(backend, &commits, proof_bytes, &h_dom, &[])
}

/// Verify the final bounded proof and immutable application transcript bytes.
pub fn bp_verify_with_extra_commit(
    commitment_sec1: &[u8; 33],
    proof_bytes: &[u8],
    extra_commit: &[u8],
) -> Result<bool, DomError> {
    if extra_commit.is_empty() {
        return Err(DomError::Malformed(
            "range proof extra commitment must not be empty".into(),
        ));
    }
    if !crate::node_private::range_proof_length_is_canonical(proof_bytes.len()) {
        return Err(DomError::Malformed(format!(
            "range proof length {} != {SINGLE_BULLETPROOF_SIZE}",
            proof_bytes.len()
        )));
    }
    let backend = backend()?;
    let h_dom = h_dom_internal(backend)?;
    let complement_sec1 = derive_complement_commitment(
        &dom_crypto::pedersen::Commitment::from_compressed_bytes(commitment_sec1)?,
        MAX_PROVABLE_VALUE,
    )?;
    let commits = [
        sec1_to_zkp(commitment_sec1)?,
        sec1_to_zkp(complement_sec1.as_bytes())?,
    ];
    verify_raw(backend, &commits, proof_bytes, &h_dom, extra_commit)
}

/// Public first-round points produced by the pinned collaborative backend.
#[derive(Clone, PartialEq, Eq)]
pub struct BulletproofMpcRound1Output {
    t_one: [u8; 33],
    t_two: [u8; 33],
}

impl BulletproofMpcRound1Output {
    /// Return canonical compressed `T1`.
    pub const fn t_one(&self) -> &[u8; 33] {
        &self.t_one
    }

    /// Return canonical compressed `T2`.
    pub const fn t_two(&self) -> &[u8; 33] {
        &self.t_two
    }
}

/// One-shot private state between collaborative Bulletproof rounds one and two.
///
/// This type deliberately implements no clone, copy, debug, display, equality,
/// ordering, or generic serialization.
pub struct BulletproofMpcRound1State {
    value: u64,
    blind_pair: Zeroizing<[[u8; 32]; PROOF_NCOMMITS]>,
    commitments: [[u8; 33]; PROOF_NCOMMITS],
    common_nonce: Zeroizing<[u8; 32]>,
    private_nonce: Zeroizing<[u8; 32]>,
    // Owned variable-length extra_commit: the raw recovery-capsule bytes the
    // proof is bound to, threaded unchanged through rounds 2 and finalize so
    // every phase binds the exact bytes consensus verifies against (§5.2/§1.3).
    extra_commit: Vec<u8>,
}

/// One-shot private state accepted only by the final backend phase.
///
/// This type deliberately implements no clone, copy, debug, display, equality,
/// ordering, or generic serialization.
pub struct BulletproofMpcFinalizeState {
    state: BulletproofMpcRound1State,
    t_one: ffi::PublicKey,
    t_two: ffi::PublicKey,
}

fn continuation_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<[u8; N], DomError> {
    let end = cursor
        .checked_add(N)
        .ok_or_else(|| DomError::Malformed("BP finalizer continuation length overflow".into()))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| DomError::Malformed(format!("BP finalizer continuation misses {field}")))?
        .try_into()
        .map_err(|_| DomError::Malformed(format!("BP finalizer continuation invalid {field}")))?;
    *cursor = end;
    Ok(value)
}

/// Serialize one consumed collaborative-BP finalizer into the canonical V1
/// crash-continuation plaintext used exclusively by an authenticated vault.
///
/// This is a low-level custody hook, not a wire codec. The returned buffer
/// contains secret blinding and nonce material and therefore is zeroizing. A
/// higher layer must pass it directly to authenticated encryption, bind it to
/// the statement/participant/aggregate-round-1 identity, and never log,
/// clone, back up, or transport it. The operational adaptor exposes this hook
/// only through one-shot Store capabilities.
#[doc(hidden)]
pub fn bulletproof_mpc_finalize_continuation_to_bytes_v1(
    state: BulletproofMpcFinalizeState,
) -> Result<Zeroizing<Vec<u8>>, DomError> {
    let backend = backend()?;
    let BulletproofMpcFinalizeState {
        state,
        t_one,
        t_two,
    } = state;
    let BulletproofMpcRound1State {
        value,
        blind_pair,
        commitments,
        common_nonce,
        private_nonce,
        extra_commit,
    } = state;
    if extra_commit.len() > MPC_FINALIZE_CONTINUATION_MAX_EXTRA_COMMIT_LEN_V1 {
        return Err(DomError::Invalid(
            "BP finalizer continuation extra_commit exceeds the V1 bound".into(),
        ));
    }
    let extra_len = u32::try_from(extra_commit.len()).map_err(|_| {
        DomError::Invalid("BP finalizer continuation extra_commit is too long".into())
    })?;
    let capacity = MPC_FINALIZE_CONTINUATION_FIXED_LEN_V1
        .checked_add(extra_commit.len())
        .ok_or_else(|| DomError::Malformed("BP finalizer continuation length overflow".into()))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    bytes.extend_from_slice(MPC_FINALIZE_CONTINUATION_MAGIC_V1);
    bytes.extend_from_slice(&MPC_FINALIZE_CONTINUATION_VERSION_V1.to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes.extend_from_slice(&blind_pair[0]);
    bytes.extend_from_slice(&blind_pair[1]);
    bytes.extend_from_slice(&commitments[0]);
    bytes.extend_from_slice(&commitments[1]);
    bytes.extend_from_slice(common_nonce.as_ref());
    bytes.extend_from_slice(private_nonce.as_ref());
    bytes.extend_from_slice(&extra_len.to_le_bytes());
    bytes.extend_from_slice(&extra_commit);
    bytes.extend_from_slice(&mpc_serialize_public_key(backend, &t_one)?);
    bytes.extend_from_slice(&mpc_serialize_public_key(backend, &t_two)?);
    debug_assert_eq!(bytes.len(), capacity);
    Ok(bytes)
}

/// Reconstruct one collaborative-BP finalizer from authenticated canonical V1
/// custody plaintext and bind it to all expected public protocol inputs.
///
/// The caller must supply bytes obtained from authenticated, rollback-safe
/// storage. Parsing revalidates every scalar, point, commitment relation,
/// aggregate round-1 point, statement value/commitment, and exact
/// `extra_commit` before rebuilding the opaque backend state. The input is
/// consumed and zeroized on every path.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn bulletproof_mpc_finalize_continuation_from_bytes_v1(
    bytes: Zeroizing<Vec<u8>>,
    expected_value: u64,
    expected_commitment: &[u8; 33],
    expected_blinding_point: &[u8; 33],
    expected_t_one: &[u8; 33],
    expected_t_two: &[u8; 33],
    expected_extra_commit: &[u8],
) -> Result<BulletproofMpcFinalizeState, DomError> {
    if bytes.len() < MPC_FINALIZE_CONTINUATION_FIXED_LEN_V1 {
        return Err(DomError::Malformed(
            "BP finalizer continuation is shorter than the V1 minimum".into(),
        ));
    }
    let mut cursor = 0usize;
    let magic = continuation_array::<4>(&bytes, &mut cursor, "magic")?;
    if &magic != MPC_FINALIZE_CONTINUATION_MAGIC_V1 {
        return Err(DomError::Invalid(
            "BP finalizer continuation magic mismatch".into(),
        ));
    }
    let version = u16::from_le_bytes(continuation_array::<2>(&bytes, &mut cursor, "version")?);
    if version != MPC_FINALIZE_CONTINUATION_VERSION_V1 {
        return Err(DomError::Invalid(
            "BP finalizer continuation version mismatch".into(),
        ));
    }
    let value = u64::from_le_bytes(continuation_array::<8>(&bytes, &mut cursor, "value")?);
    if value != expected_value || value > MAX_PROVABLE_VALUE {
        return Err(DomError::Invalid(
            "BP finalizer continuation value differs from the statement".into(),
        ));
    }
    let first_blind = Zeroizing::new(continuation_array::<32>(
        &bytes,
        &mut cursor,
        "primary blinding",
    )?);
    let complement_blind = Zeroizing::new(continuation_array::<32>(
        &bytes,
        &mut cursor,
        "complement blinding",
    )?);
    BlindingFactor::from_bytes(*first_blind)?;
    if dom_scriptless_primitives::secret_scalar_public_key(&first_blind)?.to_compressed_bytes()
        != *expected_blinding_point
    {
        return Err(DomError::Invalid(
            "BP finalizer continuation blinding differs from the participant share".into(),
        ));
    }
    if negate_blinding(&first_blind)? != *complement_blind {
        return Err(DomError::Invalid(
            "BP finalizer continuation complement blinding mismatch".into(),
        ));
    }
    BlindingFactor::from_bytes(*complement_blind)?;
    let commitments = [
        continuation_array::<33>(&bytes, &mut cursor, "primary commitment")?,
        continuation_array::<33>(&bytes, &mut cursor, "complement commitment")?,
    ];
    let expected_aggregate = Commitment::from_compressed_bytes(expected_commitment)?;
    let expected_complement =
        derive_complement_commitment(&expected_aggregate, MAX_PROVABLE_VALUE)?;
    if &commitments[0] != expected_commitment || expected_complement.as_bytes() != &commitments[1] {
        return Err(DomError::Invalid(
            "BP finalizer continuation commitment relation mismatch".into(),
        ));
    }
    let common_nonce = Zeroizing::new(continuation_array::<32>(
        &bytes,
        &mut cursor,
        "common nonce",
    )?);
    let private_nonce = Zeroizing::new(continuation_array::<32>(
        &bytes,
        &mut cursor,
        "private nonce",
    )?);
    if !dom_scriptless_primitives::scalar_bytes_are_canonical(&common_nonce, false)
        || !dom_scriptless_primitives::scalar_bytes_are_canonical(&private_nonce, false)
    {
        return Err(DomError::Invalid(
            "BP finalizer continuation nonce is zero or noncanonical".into(),
        ));
    }
    let extra_len = u32::from_le_bytes(continuation_array::<4>(
        &bytes,
        &mut cursor,
        "extra_commit length",
    )?) as usize;
    if extra_len > MPC_FINALIZE_CONTINUATION_MAX_EXTRA_COMMIT_LEN_V1 {
        return Err(DomError::Invalid(
            "BP finalizer continuation extra_commit exceeds the V1 bound".into(),
        ));
    }
    let expected_len = MPC_FINALIZE_CONTINUATION_FIXED_LEN_V1
        .checked_add(extra_len)
        .ok_or_else(|| DomError::Malformed("BP finalizer continuation length overflow".into()))?;
    if bytes.len() != expected_len {
        return Err(DomError::Malformed(format!(
            "BP finalizer continuation length {}, expected {expected_len}",
            bytes.len()
        )));
    }
    let extra_end = cursor
        .checked_add(extra_len)
        .ok_or_else(|| DomError::Malformed("BP finalizer continuation length overflow".into()))?;
    let extra_commit = bytes
        .get(cursor..extra_end)
        .ok_or_else(|| DomError::Malformed("BP finalizer continuation misses extra_commit".into()))?
        .to_vec();
    cursor = extra_end;
    if extra_commit != expected_extra_commit {
        return Err(DomError::Invalid(
            "BP finalizer continuation extra_commit differs from the statement".into(),
        ));
    }
    let t_one_bytes = continuation_array::<33>(&bytes, &mut cursor, "aggregate T1")?;
    let t_two_bytes = continuation_array::<33>(&bytes, &mut cursor, "aggregate T2")?;
    if &t_one_bytes != expected_t_one || &t_two_bytes != expected_t_two {
        return Err(DomError::Invalid(
            "BP finalizer continuation aggregate round-1 points mismatch".into(),
        ));
    }
    debug_assert_eq!(cursor, bytes.len());
    let backend = backend()?;
    Ok(BulletproofMpcFinalizeState {
        state: BulletproofMpcRound1State {
            value,
            blind_pair: Zeroizing::new([*first_blind, *complement_blind]),
            commitments,
            common_nonce,
            private_nonce,
            extra_commit,
        },
        t_one: mpc_parse_public_key(backend, &t_one_bytes)?,
        t_two: mpc_parse_public_key(backend, &t_two_bytes)?,
    })
}

fn mpc_internal_commitments(
    backend: &Backend,
    commitments: &[[u8; 33]; PROOF_NCOMMITS],
) -> Result<[[u8; 64]; PROOF_NCOMMITS], DomError> {
    let mut parsed = [[0u8; 64]; PROOF_NCOMMITS];
    for (index, commitment) in commitments.iter().enumerate() {
        let zkp = sec1_to_zkp(commitment)?;
        // SAFETY: the shared context is live, the output slot is writable for
        // 64 bytes, and `zkp` is an exact parsed commitment encoding.
        if unsafe {
            ffi::secp256k1_pedersen_commitment_parse(
                backend.ctx,
                parsed[index].as_mut_ptr(),
                zkp.as_ptr(),
            )
        } != 1
        {
            return Err(DomError::Invalid(
                "collaborative Bulletproof commitment parsing failed".into(),
            ));
        }
    }
    Ok(parsed)
}

fn mpc_parse_public_key(backend: &Backend, bytes: &[u8; 33]) -> Result<ffi::PublicKey, DomError> {
    // Validate through the authoritative Rust-facing parser before crossing
    // the FFI boundary, including canonical byte-exact re-encoding.
    let canonical = dom_crypto::PublicKey::from_compressed_bytes(bytes)?;
    if canonical.to_compressed_bytes() != *bytes {
        return Err(DomError::Invalid(
            "collaborative Bulletproof point is noncanonical".into(),
        ));
    }
    let mut point = ffi::PublicKey::new();
    // SAFETY: the backend context is live, output is writable for one public
    // key, and `bytes` is readable for its exact 33-byte length.
    if unsafe {
        raw_ffi::secp256k1_ec_pubkey_parse(backend.ctx, &mut point, bytes.as_ptr(), bytes.len())
    } != 1
    {
        return Err(DomError::Invalid(
            "collaborative Bulletproof point parsing failed".into(),
        ));
    }
    Ok(point)
}

fn mpc_serialize_public_key(
    backend: &Backend,
    point: &ffi::PublicKey,
) -> Result<[u8; 33], DomError> {
    let mut bytes = [0u8; 33];
    let mut length = bytes.len();
    // SAFETY: output is writable for 33 bytes and `point` is a live backend
    // public key returned by the pinned prover.
    let result = unsafe {
        ffi::secp256k1_ec_pubkey_serialize(
            backend.ctx,
            bytes.as_mut_ptr(),
            &mut length,
            point,
            ffi::SECP256K1_SER_COMPRESSED,
        )
    };
    if result != 1 || length != bytes.len() {
        return Err(DomError::Internal(
            "collaborative Bulletproof point serialization failed".into(),
        ));
    }
    dom_crypto::PublicKey::from_compressed_bytes(&bytes)?;
    Ok(bytes)
}

/// Execute the pinned backend's collaborative first phase.
///
/// `common_nonce` is the ratified joint nonce and `private_nonce` is a fresh,
/// independent nonzero scalar. Both are consumed into the returned one-shot
/// state. The caller is responsible for deriving them under the higher-level
/// protocol; this function defines no network or storage format.
pub fn bulletproof_mpc_round1(
    value: u64,
    blinding: BlindingFactor,
    aggregate_commitment: [u8; 33],
    common_nonce: Zeroizing<[u8; 32]>,
    private_nonce: Zeroizing<[u8; 32]>,
    // Variable-length so the collaborative proof can bind the exact bytes
    // consensus verifies against — the raw recovery capsule. Spec §5.2:
    // "recovery_binding_hash é o hash dos bytes exatos passados como
    // extra_commit"; §1.3 structural indistinguishability requires the same
    // extra_commit as the single-party path, which is the raw capsule.
    extra_commit: &[u8],
) -> Result<(BulletproofMpcRound1State, BulletproofMpcRound1Output), DomError> {
    let complement_value = MAX_PROVABLE_VALUE
        .checked_sub(value)
        .ok_or_else(|| DomError::Invalid("value exceeds MAX_PROVABLE_VALUE".into()))?;
    let aggregate = dom_crypto::pedersen::Commitment::from_compressed_bytes(&aggregate_commitment)?;
    let complement = derive_complement_commitment(&aggregate, MAX_PROVABLE_VALUE)?;
    let commitments = [aggregate_commitment, *complement.as_bytes()];
    let blind_pair = Zeroizing::new([*blinding.as_bytes(), negate_blinding(blinding.as_bytes())?]);
    if !dom_scriptless_primitives::scalar_bytes_are_canonical(&common_nonce, false)
        || !dom_scriptless_primitives::scalar_bytes_are_canonical(&private_nonce, false)
    {
        return Err(DomError::Invalid(
            "collaborative Bulletproof nonce is zero or noncanonical".into(),
        ));
    }

    let backend = backend()?;
    let value_gen = h_dom_internal(backend)?;
    let internal = mpc_internal_commitments(backend, &commitments)?;
    let commitment_ptrs = [internal[0].as_ptr(), internal[1].as_ptr()];
    let blind_ptrs = [blind_pair[0].as_ptr(), blind_pair[1].as_ptr()];
    let values = [value, complement_value];
    let mut t_one = ffi::PublicKey::new();
    let mut t_two = ffi::PublicKey::new();
    let scratch = ScratchHandle::new(backend)?;
    // SAFETY: fixed arrays outlive the call, scratch is exclusive, and the
    // output pointers reference initialized FFI public-key storage.
    let result = unsafe {
        raw_ffi::secp256k1_bulletproof_rangeproof_prove(
            backend.ctx,
            scratch.0,
            backend.gens,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut t_one,
            &mut t_two,
            values.as_ptr(),
            ptr::null(),
            blind_ptrs.as_ptr(),
            commitment_ptrs.as_ptr(),
            PROOF_NCOMMITS,
            value_gen.as_ptr(),
            PROOF_NBITS,
            common_nonce.as_ptr(),
            private_nonce.as_ptr(),
            if extra_commit.is_empty() {
                ptr::null()
            } else {
                extra_commit.as_ptr()
            },
            extra_commit.len(),
            ptr::null(),
        )
    };
    if result != 1 {
        return Err(DomError::Internal(
            "collaborative Bulletproof round 1 failed".into(),
        ));
    }
    let output = BulletproofMpcRound1Output {
        t_one: mpc_serialize_public_key(backend, &t_one)?,
        t_two: mpc_serialize_public_key(backend, &t_two)?,
    };
    Ok((
        BulletproofMpcRound1State {
            value,
            blind_pair,
            commitments,
            common_nonce,
            private_nonce,
            extra_commit: extra_commit.to_vec(),
        },
        output,
    ))
}

/// Consume round-one state and execute the pinned backend's second phase.
pub fn bulletproof_mpc_round2(
    state: BulletproofMpcRound1State,
    aggregate_t_one: &[u8; 33],
    aggregate_t_two: &[u8; 33],
) -> Result<(BulletproofMpcFinalizeState, Zeroizing<[u8; 32]>), DomError> {
    let backend = backend()?;
    let value_gen = h_dom_internal(backend)?;
    let internal = mpc_internal_commitments(backend, &state.commitments)?;
    let commitment_ptrs = [internal[0].as_ptr(), internal[1].as_ptr()];
    let blind_ptrs = [state.blind_pair[0].as_ptr(), state.blind_pair[1].as_ptr()];
    let values = [state.value, MAX_PROVABLE_VALUE - state.value];
    let mut t_one = mpc_parse_public_key(backend, aggregate_t_one)?;
    let mut t_two = mpc_parse_public_key(backend, aggregate_t_two)?;
    let mut tau_x = Zeroizing::new([0u8; 32]);
    let scratch = ScratchHandle::new(backend)?;
    // SAFETY: inputs satisfy the round-one invariants, aggregate T1/T2 were
    // parsed canonically, and `tau_x` is writable for exactly 32 bytes.
    let result = unsafe {
        raw_ffi::secp256k1_bulletproof_rangeproof_prove(
            backend.ctx,
            scratch.0,
            backend.gens,
            ptr::null_mut(),
            ptr::null_mut(),
            tau_x.as_mut_ptr(),
            &mut t_one,
            &mut t_two,
            values.as_ptr(),
            ptr::null(),
            blind_ptrs.as_ptr(),
            commitment_ptrs.as_ptr(),
            PROOF_NCOMMITS,
            value_gen.as_ptr(),
            PROOF_NBITS,
            state.common_nonce.as_ptr(),
            state.private_nonce.as_ptr(),
            if state.extra_commit.is_empty() {
                ptr::null()
            } else {
                state.extra_commit.as_ptr()
            },
            state.extra_commit.len(),
            ptr::null(),
        )
    };
    if result != 1 || !dom_scriptless_primitives::scalar_bytes_are_canonical(&tau_x, true) {
        return Err(DomError::Internal(
            "collaborative Bulletproof round 2 failed".into(),
        ));
    }
    Ok((
        BulletproofMpcFinalizeState {
            state,
            t_one,
            t_two,
        },
        tau_x,
    ))
}

/// Add ordered canonical round-two shares modulo the secp256k1 group order.
pub fn bulletproof_mpc_aggregate_tau_x(
    shares: Vec<Zeroizing<[u8; 32]>>,
) -> Result<Zeroizing<[u8; 32]>, DomError> {
    if shares.is_empty() {
        return Err(DomError::Malformed(
            "collaborative Bulletproof tau_x set is empty".into(),
        ));
    }
    let mut sum = Zeroizing::new(k256::Scalar::ZERO);
    for share in shares {
        let scalar = MpcTauXShareScalar::parse(&share)?;
        *sum += scalar.as_scalar();
    }
    Ok(Zeroizing::new(sum.to_bytes().into()))
}

/// Private, non-copying owner for a parsed participant `tau_x` share.
///
/// `k256::Scalar` is itself `Copy`; keeping it behind this private owner and
/// passing it to aggregation only by reference makes retirement explicit and
/// guarantees zeroization on success, error, and unwind paths.
struct MpcTauXShareScalar(k256::Scalar);

impl MpcTauXShareScalar {
    fn parse(bytes: &[u8; 32]) -> Result<Self, DomError> {
        dom_scriptless_primitives::curve::scalar_from_bytes(bytes)
            .map(Self)
            .ok_or_else(|| {
                DomError::Invalid("collaborative Bulletproof tau_x is noncanonical".into())
            })
    }

    const fn as_scalar(&self) -> &k256::Scalar {
        &self.0
    }
}

impl Drop for MpcTauXShareScalar {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Consume final-phase state, create exactly one 739-byte proof, and verify it
/// through the unchanged DOM backend before returning it.
pub fn bulletproof_mpc_finalize(
    mut state: BulletproofMpcFinalizeState,
    mut aggregate_tau_x: Zeroizing<[u8; 32]>,
) -> Result<Vec<u8>, DomError> {
    if !dom_scriptless_primitives::scalar_bytes_are_canonical(&aggregate_tau_x, true) {
        return Err(DomError::Invalid(
            "collaborative Bulletproof aggregate tau_x is noncanonical".into(),
        ));
    }
    let backend = backend()?;
    let value_gen = h_dom_internal(backend)?;
    let internal = mpc_internal_commitments(backend, &state.state.commitments)?;
    let commitment_ptrs = [internal[0].as_ptr(), internal[1].as_ptr()];
    let blind_ptrs = [
        state.state.blind_pair[0].as_ptr(),
        state.state.blind_pair[1].as_ptr(),
    ];
    let values = [state.state.value, MAX_PROVABLE_VALUE - state.state.value];
    let mut proof = [0u8; constants::MAX_PROOF_SIZE];
    let mut proof_length = proof.len();
    let scratch = ScratchHandle::new(backend)?;
    // SAFETY: every pointer references fixed live storage for the complete
    // call; tau_x and T1/T2 came from the checked preceding phases.
    let result = unsafe {
        raw_ffi::secp256k1_bulletproof_rangeproof_prove(
            backend.ctx,
            scratch.0,
            backend.gens,
            proof.as_mut_ptr(),
            &mut proof_length,
            aggregate_tau_x.as_mut_ptr(),
            &mut state.t_one,
            &mut state.t_two,
            values.as_ptr(),
            ptr::null(),
            blind_ptrs.as_ptr(),
            commitment_ptrs.as_ptr(),
            PROOF_NCOMMITS,
            value_gen.as_ptr(),
            PROOF_NBITS,
            state.state.common_nonce.as_ptr(),
            state.state.private_nonce.as_ptr(),
            if state.state.extra_commit.is_empty() {
                ptr::null()
            } else {
                state.state.extra_commit.as_ptr()
            },
            state.state.extra_commit.len(),
            ptr::null(),
        )
    };
    if result != 1 || proof_length != SINGLE_BULLETPROOF_SIZE {
        return Err(DomError::Internal(format!(
            "collaborative Bulletproof finalization returned {proof_length} bytes"
        )));
    }
    let proof = proof[..proof_length].to_vec();
    if !bp_verify_with_extra_commit(
        &state.state.commitments[0],
        &proof,
        &state.state.extra_commit,
    )? {
        return Err(DomError::Invalid(
            "collaborative Bulletproof failed the unchanged DOM verifier".into(),
        ));
    }
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_crypto::pedersen::Commitment;
    use k256::elliptic_curve::PrimeField;
    use zeroize::{Zeroize, Zeroizing};

    const MATRIX_VALUES: [u64; 4] = [1, 42, 1_000_000, 4_503_599_627_370_495]; // last = 2^52 - 1
    const TEST_BLIND: [u8; 32] = [0x11u8; 32];

    const BP_STATEMENT_TAG: &str = "DOM:scriptless-bp-statement:v1";
    const BP_NO_RECOVERY_TAG: &str = "DOM:scriptless-bp-no-recovery:v1";
    const BP_COMMON_COMMIT_TAG: &str = "DOM:scriptless-bp-common-commit:v1";
    const BP_COMMON_JOINT_TAG: &str = "DOM:scriptless-bp-common-joint:v1";
    const BP_COMMON_NONCE_TAG: &str = "DOM:scriptless-bp-common-nonce:v1";

    struct MpcRoundOne {
        t_one: ffi::PublicKey,
        t_two: ffi::PublicKey,
    }

    fn internal_commitments(
        backend: &Backend,
        commitments: &[[u8; 33]; PROOF_NCOMMITS],
    ) -> Result<[[u8; 64]; PROOF_NCOMMITS], DomError> {
        let mut parsed = [[0u8; 64]; PROOF_NCOMMITS];
        for (index, commitment) in commitments.iter().enumerate() {
            let zkp = sec1_to_zkp(commitment)?;
            // SAFETY: the shared context is live, the output slot is writable
            // for 64 bytes, and `zkp` is an exact 33-byte serialized commitment.
            if unsafe {
                ffi::secp256k1_pedersen_commitment_parse(
                    backend.ctx,
                    parsed[index].as_mut_ptr(),
                    zkp.as_ptr(),
                )
            } != 1
            {
                return Err(DomError::Invalid(
                    "MPC aggregate commitment parsing failed".into(),
                ));
            }
        }
        Ok(parsed)
    }

    // The parameter list mirrors the libsecp256k1-zkp MPC prover entry point
    // one-for-one. Grouping them into a struct would add a translation layer
    // between validated Rust values and the FFI call, which is exactly where
    // pointer/length mistakes hide.
    #[allow(clippy::too_many_arguments)]
    fn mpc_round_one(
        backend: &Backend,
        values: &[u64; PROOF_NCOMMITS],
        blinds: &[[u8; 32]; PROOF_NCOMMITS],
        commitments: &[[u8; 33]; PROOF_NCOMMITS],
        value_gen: &[u8; 64],
        common_nonce: &[u8; 32],
        private_nonce: &[u8; 32],
        extra_commit: &[u8],
    ) -> Result<MpcRoundOne, DomError> {
        let internal = internal_commitments(backend, commitments)?;
        let commitment_ptrs = [internal[0].as_ptr(), internal[1].as_ptr()];
        let blind_ptrs = [blinds[0].as_ptr(), blinds[1].as_ptr()];
        let mut t_one = ffi::PublicKey::new();
        let mut t_two = ffi::PublicKey::new();
        let scratch = ScratchHandle::new(backend)?;
        // SAFETY: all fixed arrays outlive the call, the scratch is exclusive,
        // and first-phase output pointers reference initialized FFI public keys.
        let result = unsafe {
            raw_ffi::secp256k1_bulletproof_rangeproof_prove(
                backend.ctx,
                scratch.0,
                backend.gens,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut t_one,
                &mut t_two,
                values.as_ptr(),
                ptr::null(),
                blind_ptrs.as_ptr(),
                commitment_ptrs.as_ptr(),
                PROOF_NCOMMITS,
                value_gen.as_ptr(),
                PROOF_NBITS,
                common_nonce.as_ptr(),
                private_nonce.as_ptr(),
                extra_commit.as_ptr(),
                extra_commit.len(),
                ptr::null(),
            )
        };
        if result != 1 {
            return Err(DomError::Internal("Bulletproof MPC round 1 failed".into()));
        }
        Ok(MpcRoundOne { t_one, t_two })
    }

    fn combine_public_keys(
        backend: &Backend,
        points: &[ffi::PublicKey],
    ) -> Result<ffi::PublicKey, DomError> {
        let pointers: Vec<*const ffi::PublicKey> = points.iter().map(core::ptr::from_ref).collect();
        let mut sum = ffi::PublicKey::new();
        // SAFETY: every pointer references a live parsed FFI public key and the
        // output is writable for exactly one FFI public key.
        if unsafe {
            ffi::secp256k1_ec_pubkey_combine(
                backend.ctx,
                &mut sum,
                pointers.as_ptr(),
                i32::try_from(pointers.len()).expect("participant count is at most 16"),
            )
        } != 1
        {
            return Err(DomError::Invalid(
                "Bulletproof MPC point aggregation failed".into(),
            ));
        }
        Ok(sum)
    }

    fn serialize_public_key(
        backend: &Backend,
        point: &ffi::PublicKey,
    ) -> Result<[u8; 33], DomError> {
        let mut bytes = [0u8; 33];
        let mut length = bytes.len();
        // SAFETY: the output buffer is writable for 33 bytes and `point` is a
        // live FFI public key returned by the pinned prover or combiner.
        let result = unsafe {
            ffi::secp256k1_ec_pubkey_serialize(
                backend.ctx,
                bytes.as_mut_ptr(),
                &mut length,
                point,
                ffi::SECP256K1_SER_COMPRESSED,
            )
        };
        if result != 1 || length != 33 {
            return Err(DomError::Internal(
                "Bulletproof MPC point serialization failed".into(),
            ));
        }
        Ok(bytes)
    }

    // Same reasoning as `mpc_round_one`: the shape is dictated by the FFI.
    #[allow(clippy::too_many_arguments)]
    fn mpc_round_two(
        backend: &Backend,
        values: &[u64; PROOF_NCOMMITS],
        blinds: &[[u8; 32]; PROOF_NCOMMITS],
        commitments: &[[u8; 33]; PROOF_NCOMMITS],
        value_gen: &[u8; 64],
        common_nonce: &[u8; 32],
        private_nonce: &[u8; 32],
        extra_commit: &[u8],
        t_one: &mut ffi::PublicKey,
        t_two: &mut ffi::PublicKey,
    ) -> Result<Zeroizing<[u8; 32]>, DomError> {
        let internal = internal_commitments(backend, commitments)?;
        let commitment_ptrs = [internal[0].as_ptr(), internal[1].as_ptr()];
        let blind_ptrs = [blinds[0].as_ptr(), blinds[1].as_ptr()];
        let mut tau_x = Zeroizing::new([0u8; 32]);
        let scratch = ScratchHandle::new(backend)?;
        // SAFETY: inputs satisfy the same invariants as round one; aggregate
        // T1/T2 are valid combined FFI public keys and tau_x is writable.
        let result = unsafe {
            raw_ffi::secp256k1_bulletproof_rangeproof_prove(
                backend.ctx,
                scratch.0,
                backend.gens,
                ptr::null_mut(),
                ptr::null_mut(),
                tau_x.as_mut_ptr(),
                t_one,
                t_two,
                values.as_ptr(),
                ptr::null(),
                blind_ptrs.as_ptr(),
                commitment_ptrs.as_ptr(),
                PROOF_NCOMMITS,
                value_gen.as_ptr(),
                PROOF_NBITS,
                common_nonce.as_ptr(),
                private_nonce.as_ptr(),
                extra_commit.as_ptr(),
                extra_commit.len(),
                ptr::null(),
            )
        };
        if result != 1 {
            return Err(DomError::Internal("Bulletproof MPC round 2 failed".into()));
        }
        Ok(tau_x)
    }

    #[allow(clippy::too_many_arguments)]
    fn mpc_finalize(
        backend: &Backend,
        values: &[u64; PROOF_NCOMMITS],
        blinds: &[[u8; 32]; PROOF_NCOMMITS],
        commitments: &[[u8; 33]; PROOF_NCOMMITS],
        value_gen: &[u8; 64],
        common_nonce: &[u8; 32],
        private_nonce: &[u8; 32],
        extra_commit: &[u8],
        tau_x: &mut [u8; 32],
        t_one: &mut ffi::PublicKey,
        t_two: &mut ffi::PublicKey,
    ) -> Result<Vec<u8>, DomError> {
        let internal = internal_commitments(backend, commitments)?;
        let commitment_ptrs = [internal[0].as_ptr(), internal[1].as_ptr()];
        let blind_ptrs = [blinds[0].as_ptr(), blinds[1].as_ptr()];
        let mut proof = [0u8; constants::MAX_PROOF_SIZE];
        let mut proof_length = proof.len();
        let scratch = ScratchHandle::new(backend)?;
        // SAFETY: every pointer references a fixed live buffer for the complete
        // call; aggregate tau_x/T1/T2 came from the preceding checked phases.
        let result = unsafe {
            raw_ffi::secp256k1_bulletproof_rangeproof_prove(
                backend.ctx,
                scratch.0,
                backend.gens,
                proof.as_mut_ptr(),
                &mut proof_length,
                tau_x.as_mut_ptr(),
                t_one,
                t_two,
                values.as_ptr(),
                ptr::null(),
                blind_ptrs.as_ptr(),
                commitment_ptrs.as_ptr(),
                PROOF_NCOMMITS,
                value_gen.as_ptr(),
                PROOF_NBITS,
                common_nonce.as_ptr(),
                private_nonce.as_ptr(),
                extra_commit.as_ptr(),
                extra_commit.len(),
                ptr::null(),
            )
        };
        if result != 1 || proof_length != SINGLE_BULLETPROOF_SIZE {
            return Err(DomError::Internal(format!(
                "Bulletproof MPC finalization failed or returned {proof_length} bytes"
            )));
        }
        Ok(proof[..proof_length].to_vec())
    }

    fn scalar_add_all(scalars: &[Zeroizing<[u8; 32]>]) -> Zeroizing<[u8; 32]> {
        let mut sum = Zeroizing::new(k256::Scalar::ZERO);
        for scalar in scalars {
            let bytes: [u8; 32] = scalar
                .as_ref()
                .try_into()
                .expect("tau_x has an exact scalar length");
            let parsed = k256::Scalar::from_repr(bytes.into());
            assert!(
                bool::from(parsed.is_some()),
                "backend returned canonical tau_x"
            );
            *sum += parsed.unwrap();
        }
        Zeroizing::new(sum.to_bytes().into())
    }

    fn wide_nonce(tag: &str, input: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut counter = 0u32;
        loop {
            let mut body = Zeroizing::new(Vec::with_capacity(1 + input.len() + 4));
            body.push(0);
            body.extend_from_slice(input);
            body.extend_from_slice(&counter.to_le_bytes());
            let mut first = dom_crypto::blake2b_256_tagged(tag, body.as_ref());
            body[0] = 1;
            let mut second = dom_crypto::blake2b_256_tagged(tag, body.as_ref());
            let mut wide = Zeroizing::new([0u8; 64]);
            wide[..32].copy_from_slice(first.as_bytes());
            wide[32..].copy_from_slice(second.as_bytes());
            first.zeroize();
            second.zeroize();
            if let Some(scalar) = dom_scriptless_primitives::scalar_from_wide_be(&wide) {
                return scalar;
            }
            counter = counter
                .checked_add(1)
                .expect("test counter does not overflow");
        }
    }

    fn collaborative_proof(participant_count: usize) -> (Vec<u8>, [u8; 33]) {
        assert!((2..=16).contains(&participant_count));
        let backend = backend().expect("backend");
        let h_dom = h_dom_internal(backend).expect("H_DOM");
        let value = 42u64;
        let values = [value, MAX_PROVABLE_VALUE - value];
        let mut aggregate_blind = BlindingFactor::from_bytes({
            let mut bytes = [0u8; 32];
            bytes[31] = 1;
            bytes
        })
        .expect("first blind");
        let mut blind_shares = Vec::with_capacity(participant_count);
        let mut commitment_shares = Vec::with_capacity(participant_count);
        for index in 0..participant_count {
            let mut bytes = [0u8; 32];
            bytes[31] = u8::try_from(index + 1).expect("at most sixteen participants");
            let blind = BlindingFactor::from_bytes(bytes).expect("small blind");
            if index > 0 {
                aggregate_blind = aggregate_blind.add(&blind).expect("nonzero blind sum");
            }
            commitment_shares.push(Commitment::commit(
                if index == 0 { value } else { 0 },
                &blind,
            ));
            blind_shares.push(blind);
        }
        let aggregate_commitment = commitment_shares[1..]
            .iter()
            .try_fold(commitment_shares[0].clone(), |sum, share| sum.add(share))
            .expect("commitment sum");
        assert!(aggregate_commitment.verify(value, &aggregate_blind));
        let complement = derive_complement_commitment(&aggregate_commitment, MAX_PROVABLE_VALUE)
            .expect("complement");
        let commitments = [*aggregate_commitment.as_bytes(), *complement.as_bytes()];

        let participant_ids: Vec<[u8; 32]> = (0..participant_count)
            .map(|index| [u8::try_from(index + 1).expect("bounded participant"); 32])
            .collect();
        let recovery = *dom_crypto::blake2b_256_tagged(BP_NO_RECOVERY_TAG, &[]).as_bytes();
        let mut statement = Vec::with_capacity(187 + 65 * participant_count);
        statement.extend_from_slice(b"DSBP");
        statement.extend_from_slice(&1u16.to_le_bytes());
        statement.extend_from_slice(&[0x11; 32]);
        statement.extend_from_slice(&[0x22; 32]);
        statement.push(u8::try_from(participant_count).expect("bounded participant count"));
        for participant in &participant_ids {
            statement.extend_from_slice(participant);
        }
        statement.extend_from_slice(&value.to_le_bytes());
        statement.extend_from_slice(&MAX_PROVABLE_VALUE.to_le_bytes());
        statement.extend_from_slice(&dom_crypto::h_compressed().expect("H_DOM"));
        statement.push(u8::try_from(participant_count).expect("bounded share count"));
        for commitment in &commitment_shares {
            statement.extend_from_slice(commitment.as_bytes());
        }
        statement.extend_from_slice(aggregate_commitment.as_bytes());
        statement.extend_from_slice(&recovery);
        statement.push(64);
        assert_eq!(statement.len(), 187 + 65 * participant_count);
        let statement_hash =
            *dom_crypto::blake2b_256_tagged(BP_STATEMENT_TAG, &statement).as_bytes();

        let q_values: Vec<[u8; 32]> = (0..participant_count)
            .map(|index| [0x40 + u8::try_from(index).expect("bounded participant"); 32])
            .collect();
        for ((participant, q), expected_index) in participant_ids
            .iter()
            .zip(&q_values)
            .zip(0..participant_count)
        {
            let mut input = Vec::with_capacity(96);
            input.extend_from_slice(&statement_hash);
            input.extend_from_slice(participant);
            input.extend_from_slice(q);
            let commitment = dom_crypto::blake2b_256_tagged(BP_COMMON_COMMIT_TAG, &input);
            assert_ne!(
                commitment.as_bytes(),
                &[0u8; 32],
                "commitment {expected_index}"
            );
        }
        let mut joint_input = Vec::with_capacity(33 + 64 * participant_count);
        joint_input.extend_from_slice(&statement_hash);
        joint_input.push(u8::try_from(participant_count).expect("bounded participant count"));
        for (participant, q) in participant_ids.iter().zip(&q_values) {
            joint_input.extend_from_slice(participant);
            joint_input.extend_from_slice(q);
        }
        let joint = dom_crypto::blake2b_256_tagged(BP_COMMON_JOINT_TAG, &joint_input);
        let mut nonce_input = Vec::with_capacity(64);
        nonce_input.extend_from_slice(&statement_hash);
        nonce_input.extend_from_slice(joint.as_bytes());
        let common_nonce = wide_nonce(BP_COMMON_NONCE_TAG, &nonce_input);

        let mut round_one = Vec::with_capacity(participant_count);
        let mut local_blind_pairs = Vec::with_capacity(participant_count);
        let mut private_nonces = Vec::with_capacity(participant_count);
        for (index, blind) in blind_shares.iter().enumerate() {
            let pair = [
                *blind.as_bytes(),
                negate_blinding(blind.as_bytes()).expect("negative"),
            ];
            let mut private_nonce = [0u8; 32];
            private_nonce[31] = 0x20 + u8::try_from(index).expect("bounded participant");
            round_one.push(
                mpc_round_one(
                    backend,
                    &values,
                    &pair,
                    &commitments,
                    &h_dom,
                    &common_nonce,
                    &private_nonce,
                    &recovery,
                )
                .expect("round one"),
            );
            local_blind_pairs.push(pair);
            private_nonces.push(Zeroizing::new(private_nonce));
        }
        let mut t_one = combine_public_keys(
            backend,
            &round_one
                .iter()
                .map(|round| round.t_one)
                .collect::<Vec<_>>(),
        )
        .expect("T1 sum");
        let mut t_two = combine_public_keys(
            backend,
            &round_one
                .iter()
                .map(|round| round.t_two)
                .collect::<Vec<_>>(),
        )
        .expect("T2 sum");
        let t_one_bytes = serialize_public_key(backend, &t_one).expect("T1 serialization");
        let t_two_bytes = serialize_public_key(backend, &t_two).expect("T2 serialization");
        assert!(secp256k1::PublicKey::from_slice(&t_one_bytes).is_ok());
        assert!(secp256k1::PublicKey::from_slice(&t_two_bytes).is_ok());

        let tau_shares: Vec<_> = local_blind_pairs
            .iter()
            .zip(&private_nonces)
            .map(|(pair, private_nonce)| {
                mpc_round_two(
                    backend,
                    &values,
                    pair,
                    &commitments,
                    &h_dom,
                    &common_nonce,
                    private_nonce,
                    &recovery,
                    &mut t_one,
                    &mut t_two,
                )
                .expect("round two")
            })
            .collect();
        let mut tau_x = scalar_add_all(&tau_shares);
        let proof = mpc_finalize(
            backend,
            &values,
            &local_blind_pairs[0],
            &commitments,
            &h_dom,
            &common_nonce,
            &private_nonces[0],
            &recovery,
            &mut tau_x,
            &mut t_one,
            &mut t_two,
        )
        .expect("finalization");
        assert_eq!(proof.len(), SINGLE_BULLETPROOF_SIZE);
        assert!(
            bp_verify_with_extra_commit(aggregate_commitment.as_bytes(), &proof, &recovery)
                .expect("real DOM verifier")
        );
        (proof, *aggregate_commitment.as_bytes())
    }

    #[test]
    fn ratified_collaborative_bulletproof_mpc_harness() {
        for participant_count in [2usize, 3, 16] {
            let (proof, commitment) = collaborative_proof(participant_count);
            assert_eq!(proof.len(), 739);
            assert!(!matches!(bp_verify(&commitment, &proof), Ok(true)));
        }
        let first = collaborative_proof(2);
        let second = collaborative_proof(2);
        assert_eq!(
            first, second,
            "fixed MPC harness inputs must be deterministic"
        );
    }

    fn legacy_single_proof(value: u64, blind: &[u8; 32], nonce: &[u8; 32]) -> (Vec<u8>, [u8; 33]) {
        let bf = BlindingFactor::from_bytes(*blind).expect("blind");
        bp2_test_only_prove_legacy_single_with_nonce(value, &bf, nonce).expect("legacy single bp2")
    }

    fn commit_pair_with_gen(
        backend: &Backend,
        value: u64,
        blind: &[u8; 32],
        value_gen: &[u8; 64],
    ) -> [[u8; 33]; PROOF_NCOMMITS] {
        let first = commit_zkp(backend, value, blind, value_gen).expect("first");
        let complement_blind = negate_blinding(blind).expect("neg blind");
        let second = commit_zkp(
            backend,
            MAX_PROVABLE_VALUE - value,
            &complement_blind,
            value_gen,
        )
        .expect("second");
        [first, second]
    }

    /// PROBE [F6-A] — does bp2 `bp_verify` enforce the MAX_PROVABLE_VALUE (2^52-1)
    /// ceiling at VERIFY time? Borromean `bulletproof::verify` does (R-07); this
    /// module's `bp_verify` only size-gates + FFI-verifies. We mint a LEGACY
    /// single-commit Bulletproof of value > MAX_PROVABLE_VALUE and assert the
    /// bounded aggregate verifier rejects it.
    ///
    /// CONFIRMED 2026-06-23 (by execution): bp_verify returned Ok(true) for
    /// value = 2^52 (MAX_PROVABLE_VALUE + 1) => FIX-014 (CRITICAL inflation, see
    /// dom-shield reports/FIX-QUEUE.md).
    ///
    #[test]
    fn probe_bp2_verify_rejects_value_above_max_provable() {
        let value = MAX_PROVABLE_VALUE + 1; // 2^52 — one above the ceiling
        let nonce = [0xA5; 32];
        let (proof, sec1) = legacy_single_proof(value, &TEST_BLIND, &nonce);
        assert_eq!(proof.len(), 675, "legacy unsafe proof must stay 675 bytes");

        let result = bp_verify(&sec1, &proof);
        assert!(
            matches!(result, Ok(false) | Err(_)),
            "INFLATION: bp_verify accepted a proof of value {} > MAX_PROVABLE_VALUE {} => {:?}",
            value,
            MAX_PROVABLE_VALUE,
            result
        );
    }

    #[test]
    fn malformed_zero_prefixed_proof_is_rejected_before_ffi() {
        let commitment =
            hex::decode("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f")
                .expect("commitment hex");
        let commitment: [u8; 33] = commitment.try_into().expect("commitment length");
        let proof = [0u8; SINGLE_BULLETPROOF_SIZE];
        assert_eq!(bp_verify(&commitment, &proof), Ok(false));
    }

    /// DS-001 regression: `bp_verify` must reject any proof whose length is not
    /// EXACTLY `SINGLE_BULLETPROOF_SIZE` (739) BEFORE any FFI call on the proof —
    /// closing the SEGV path (the reproducer was a 651-byte proof that reached
    /// grin's scalar parse). Off-size proofs are stopped by the size gate; only
    /// the exact 739-byte length proceeds to (safe) verification.
    #[test]
    fn ds001_proof_size_must_be_exact() {
        let blind = BlindingFactor::from_bytes(TEST_BLIND).expect("blind");
        let (proof, commitment) = bp_prove(42, &blind).expect("bp2 prove");
        assert_eq!(
            proof.len(),
            SINGLE_BULLETPROOF_SIZE,
            "sanity: a real bounded aggregate Bulletproof is exactly 739 bytes"
        );

        // Exact-size real proof passes the size gate AND verifies.
        match bp_verify(&commitment, &proof) {
            Ok(true) => {}
            other => panic!("valid 739-byte proof must verify Ok(true), got {other:?}"),
        }

        // An all-zeros proof of the exact pinned length passes the SIZE gate; it then
        // fails verification, but the error must NOT be a size error.
        match bp_verify(&commitment, &[0u8; SINGLE_BULLETPROOF_SIZE]) {
            Ok(false) => {}
            Ok(true) => panic!("all-zeros 739-byte proof must not verify true"),
            Err(e) => assert!(
                !e.to_string().contains("invalid range proof length"),
                "739-byte proof must not be rejected by the size gate, got: {e}"
            ),
        }

        // Off-size proofs (incl. 651 = the DS-001 reproducer, the 738/740
        // boundaries, and 768 = the old cap) are rejected by the size gate with
        // the specific message, BEFORE any FFI touches the proof bytes.
        for len in [651usize, 738, 740, 768] {
            let err = bp_verify(&commitment, &vec![0u8; len])
                .expect_err("off-size proof must be rejected");
            assert!(
                err.to_string().contains("invalid range proof length"),
                "len {len} must be rejected as size-invalid, got: {err}"
            );
        }

        // Empty proof keeps its specific message.
        let err_empty = bp_verify(&commitment, &[]).expect_err("empty must be rejected");
        assert!(
            err_empty.to_string().contains("range proof is empty"),
            "empty proof must report 'range proof is empty', got: {err_empty}"
        );
    }

    /// DS-001 REGRESSION GUARDIAN (runs always — it must NOT crash).
    ///
    /// Feeds the grin FFI 200 exact-size but MALFORMED proofs (blake2b of a
    /// counter), all on the SAME thread, against a valid SEC1 commitment. Before
    /// the per-call scratch fix this reused-scratch hammering accumulated leaked
    /// frames and SEGV'd; now every call MUST return (`Ok(false)` or `Err`). A
    /// panic/SEGV here means the scratch is being reused again (DS-001 regressed).
    #[test]
    fn ds001_exact_size_malformed_does_not_crash() {
        // Deterministic pseudo-random exact-size buffer derived from a counter.
        fn pseudo_random_exact(counter: u32) -> Vec<u8> {
            let mut out = Vec::with_capacity(SINGLE_BULLETPROOF_SIZE);
            let mut block: u32 = 0;
            while out.len() < SINGLE_BULLETPROOF_SIZE {
                let mut seed = Vec::with_capacity(8);
                seed.extend_from_slice(&counter.to_le_bytes());
                seed.extend_from_slice(&block.to_le_bytes());
                let h = dom_crypto::blake2b_256_tagged("DOM:ds001-malformed-probe:v1", &seed);
                out.extend_from_slice(h.as_bytes());
                block += 1;
            }
            out.truncate(SINGLE_BULLETPROOF_SIZE);
            out
        }

        let blind = BlindingFactor::from_bytes([0x22u8; 32]).expect("blind");
        let (_real_proof, commitment) = bp_prove(7, &blind).expect("bp2 prove");

        for i in 0..200u32 {
            let proof = pseudo_random_exact(i);
            assert_eq!(
                proof.len(),
                SINGLE_BULLETPROOF_SIZE,
                "probe proof must be exactly 739 bytes"
            );
            // Flushed marker so a SEGV inside the FFI leaves the crashing index
            // as the last line on stderr (identifies the deterministic reproducer).
            eprintln!("PROBE iter {i} -> calling bp_verify ...");
            // Must RETURN gracefully — never panic / SEGV. A valid commitment +
            // exact-size proof reaches the grin verify FFI by design here.
            match bp_verify(&commitment, &proof) {
                Ok(false) | Err(_) => {}
                Ok(true) => {
                    panic!("iteration {i}: malformed 739-byte proof verified TRUE (impossible)")
                }
            }
        }
        println!("DS-001 probe: 200 malformed 739-byte proofs all returned gracefully (no crash).");
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
    /// malformed 739-byte proofs (counters 0..=6) with valid proofs from
    /// `bp_prove`. The first five calls reproduce Scenario D EXACTLY
    /// (valid, malformed, valid, malformed, valid) — the trailing valid 5th call
    /// is the one that used to SEGV. Every call must return gracefully (Ok/Err)
    /// with no panic/SEGV. If the scratch is ever reused again, this test crashes
    /// the whole test process — the strongest possible regression signal.
    #[test]
    fn ds001_scratch_no_accumulation_regression() {
        // Deterministic exact-size pseudo-random buffer — same derivation the other
        // DS-001 probes use, so reproducers line up across tests.
        fn malformed_proof(counter: u32) -> Vec<u8> {
            let mut out = Vec::with_capacity(SINGLE_BULLETPROOF_SIZE);
            let mut block: u32 = 0;
            while out.len() < SINGLE_BULLETPROOF_SIZE {
                let mut seed = Vec::with_capacity(8);
                seed.extend_from_slice(&counter.to_le_bytes());
                seed.extend_from_slice(&block.to_le_bytes());
                let h = dom_crypto::blake2b_256_tagged("DOM:ds001-malformed-probe:v1", &seed);
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
            "sanity: a real bounded aggregate Bulletproof is exactly 739 bytes"
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
                "call {n} ({label}) must be exactly 739 bytes"
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
        let backend = backend().expect("backend");
        let g = h_dom_internal(backend).expect("H_DOM parse");
        assert!(g.iter().any(|&b| b != 0));
        assert_eq!(SINGLE_BULLETPROOF_SIZE, 739);
        assert_eq!(PROOF_NBITS, 64);
        assert_eq!(PROOF_NCOMMITS, 2);
    }

    /// Gate-1 generator-binding matrix, now in-crate, for all four values.
    #[test]
    fn binding_matrix_in_crate() {
        let blind = BlindingFactor::from_bytes(TEST_BLIND).expect("blind");
        let backend = backend().expect("backend");
        let h_dom = h_dom_internal(backend).expect("H_DOM");
        let h_def: [u8; 64] = constants::GENERATOR_H;
        assert_ne!(h_dom, h_def, "H_DOM must differ from grin's default H");

        for &v in MATRIX_VALUES.iter() {
            let pr_dom = prove_raw(backend, v, blind.as_bytes(), &h_dom, &[]).unwrap();
            let pr_def = prove_raw(backend, v, blind.as_bytes(), &h_def, &[]).unwrap();
            let c_dom_pair = commit_pair_with_gen(backend, v, blind.as_bytes(), &h_dom);
            let c_def_pair = commit_pair_with_gen(backend, v, blind.as_bytes(), &h_def);

            // A: commit=H_DOM prove=H_DOM verify=H_DOM -> PASS
            assert!(
                verify_raw(backend, &c_dom_pair, &pr_dom, &h_dom, &[]).unwrap(),
                "A v={v}"
            );
            // B: commit=H_DOM prove=H_default verify=H_DOM -> FAIL
            assert!(
                !verify_raw(backend, &c_dom_pair, &pr_def, &h_dom, &[]).unwrap(),
                "B v={v}"
            );
            // C: commit=H_DOM prove=H_DOM verify=H_default -> FAIL
            assert!(
                !verify_raw(backend, &c_dom_pair, &pr_dom, &h_def, &[]).unwrap(),
                "C v={v}"
            );
            // D: control, all H_default -> PASS
            assert!(
                verify_raw(backend, &c_def_pair, &pr_def, &h_def, &[]).unwrap(),
                "D v={v}"
            );

            assert_eq!(pr_dom.len(), 739, "proof len v={v}");
        }
    }

    /// End-to-end SEC1 round-trip through the production wrappers, all values.
    #[test]
    fn bp_prove_verify_sec1_roundtrip() {
        for &v in MATRIX_VALUES.iter() {
            let blind = BlindingFactor::random();
            let (proof, sec1) = bp_prove(v, &blind).expect("prove");
            assert_eq!(proof.len(), 739, "v={v}");
            assert!(bp_verify(&sec1, &proof).unwrap(), "verify v={v}");
        }
    }

    /// Value 0 proves and verifies.
    #[test]
    fn value_zero_roundtrips() {
        let blind = BlindingFactor::random();
        let (proof, sec1) = bp_prove(0, &blind).expect("prove 0");
        assert_eq!(proof.len(), 739);
        assert!(bp_verify(&sec1, &proof).unwrap());
    }

    /// MAX_PROVABLE_VALUE proves and verifies.
    #[test]
    fn max_provable_roundtrips() {
        let blind = BlindingFactor::random();
        let (proof, sec1) = bp_prove(MAX_PROVABLE_VALUE, &blind).expect("prove max");
        assert_eq!(proof.len(), 739);
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
        let backend = backend().expect("backend");
        let h_dom = h_dom_internal(backend).unwrap();
        let pr_dom = prove_raw(backend, 42, blind.as_bytes(), &h_dom, &[]).unwrap();
        let c_dom_pair = commit_pair_with_gen(backend, 42, blind.as_bytes(), &h_dom);

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
            !verify_raw(backend, &c_dom_pair, &pr_dom, &g1, &[]).unwrap()
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
            !verify_raw(backend, &c_dom_pair, &pr_dom, &g2, &[]).unwrap()
        };
        assert!(n2, "all-zero generator must be rejected");
    }

    /// DETERMINISM GATE (Phase 2): bp_prove_with_nonce is byte-reproducible.
    /// Two independent proves with the SAME DOM seed yield BYTE-IDENTICAL 739-byte
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
            assert_eq!(p1.len(), 739, "proof len value={value}");
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

    /// FROZEN VECTOR: pins the exact 739-byte deterministic proof + commitment for
    /// a fixed (value, blinding, nonce), so any drift in the nonce derivation or
    /// the prover output is caught. Genesis-style: a fixed seed must always yield
    /// these exact bytes.
    #[test]
    fn bp2_prove_with_nonce_frozen_vector() {
        let blinding = BlindingFactor::from_bytes([0x11u8; 32]).unwrap();
        let nonce = [0x07u8; 32];
        let (proof, sec1) = bp_prove_with_nonce(42, &blinding, &nonce).unwrap();
        assert_eq!(proof.len(), 739);

        // Frozen: value=42, blinding=[0x11;32], DOM seed nonce=[0x07;32], H_DOM.
        const EXPECTED_SEC1: &str =
            "03171d4a3e65fcaf5f0937308dd1fe1cf33c337c4d5f559a03166e051884e9a402";
        const EXPECTED_PROOF: &str = "b138ab8ce5eadcd500c45e5f22289780f02fa5a81f498380e48b3ec29fe42fb78dea2dadd5d5177b31ea0e0cb75b81b2480be4af81e5888d7eba7eab861d72f70362172ba077446543c5b607cb78311788d17b6b7662338b224b6b8d8a85f7c8851a6b3498c9fc09946a566545651bd78478ba9dffc9399b244588234309ed59733effd9091b9c875069f318f6b1ca49acb28799326815a36e8be3f9fa5be871bf43c91f800dbbe3851ea4b9378f54c1dbdab43ce1db7a914c8dc49ebb3c58ea1029479af6f3d235a662be92358299323aeadb59e39ba932937bb95b567fd1082ca54666201d8534ae51ec428782e229aa33908af4a1a590a4dd0b1ae8a789877ef9e7402d748f04ec86da01f62ff6266749c117d665de0cada811a0179c4c7d852afee47e996f75eec1b2b458fc30b1f6e3326c564aafa2e79e9f3c7a13ba4c872dcd388f011bc41ffbb0b2be666a2ff0dcfb19d6a5115c41dc4f4bf52fbd5c5cf90c0170be7e419cf053371eb94370b373ff8280956d95f9b20ec53257dfec3496c1d4eda480b5280c8748f0822e900610412448b41dd6ff1c6675bf63b60553c803ab266134cbfdd27349a85d751961ccb7986061b73e4800baeffbf8abf81e0e9424b70bea656cefd9aac1395d3388d888bcb60d07d45bb1fb06330761169a5739f5dfc014cd0a4598e7c77a19f96c150b6a20621f81fe0060790d910c82a8277c47573fbe731f8c8d68381804254526541636f7b797018a580f697d5b96e42eb7614b326fd5e53984bb257ecab9b9e87d1253ea4b00a1b40780e3ba01f72f4b6954f0efab12871dba5ac8660c4e8edc3752014922feae6957babe2310d60c0379eaad90cdd0fe6949d038fc38b103c09412dce7b581b3368bca81047bf2fc14cb9f767452167472db19482d561798bbb2710d820de574253d74304ba60f0775b4f0d22ba1b48b353709cc733ff354bc5f581f242f460892806f8353666108815f7b090d13edd877285e9734a41014204b6764446c7c2d5e03fe035cc29a264d2e";
        assert_eq!(hex::encode(sec1), EXPECTED_SEC1, "commitment drift");
        assert_eq!(hex::encode(&proof), EXPECTED_PROOF, "proof byte drift");
        assert!(bp_verify(&sec1, &proof).unwrap());
    }

    #[test]
    fn forged_second_commitment_is_rejected() {
        let backend = backend().expect("backend");
        let h_dom = h_dom_internal(backend).expect("h_dom");
        let value = 42u64;
        let nonce = [0x44; 32];
        let values = [value, 1_337u64];
        let blinds = [TEST_BLIND, [0x55; 32]];
        let proof =
            prove_raw_values_with_nonces(backend, &values, &blinds, &h_dom, &nonce, &nonce, &[])
                .expect("forged aggregate");
        let sec1 = zkp_to_sec1(&commit_zkp(backend, value, &TEST_BLIND, &h_dom).expect("commit"))
            .expect("sec1");
        let result = bp_verify(&sec1, &proof);
        assert!(
            matches!(result, Ok(false) | Err(_)),
            "forged second commitment must be rejected, got {result:?}"
        );
    }

    #[test]
    fn complement_commitment_matches_direct_construction() {
        let blind = BlindingFactor::from_bytes(TEST_BLIND).expect("blind");
        let value = 4242u64;
        let commit = Commitment::commit(value, &blind);
        let complement = derive_complement_commitment(&commit, MAX_PROVABLE_VALUE).expect("derive");
        let neg_blind = negate_blinding(blind.as_bytes()).expect("neg");
        let complement_blind = BlindingFactor::from_bytes(neg_blind).expect("neg blind");
        let direct = Commitment::commit(MAX_PROVABLE_VALUE - value, &complement_blind);
        assert_eq!(complement, direct);
    }
}

/// Differential cross-check: the final range-proof backend must produce the
/// EXACT SAME commitment bytes as DOM's canonical Pedersen layer
/// ([`dom_crypto::pedersen::Commitment::commit`]). If they diverged, the range proof
/// and the balance equation would be proving about different commitments.
#[cfg(test)]
mod differential {
    use super::*;
    use dom_crypto::pedersen::Commitment;
    use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

    const SEED: u64 = 0x000D_04DB_u64; // deterministic, reproducible
    const N_RANDOM: usize = 1000;

    /// Largest valid scalar = secp256k1 group order n - 1.
    const N_MINUS_1: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x40,
    ];

    /// DOM canonical Pedersen commitment (SEC1).
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

        // Soundness: the final backend must verify against this shared
        // commitment.
        let bp_proof =
            prove_raw(backend, value, blinding.as_bytes(), h_dom, &[]).expect("bp prove");
        let zkp = commit_zkp(backend, value, blinding.as_bytes(), h_dom).expect("commit_zkp");
        let commit_pair = {
            let sec1 = zkp_to_sec1(&zkp).expect("zkp->sec1");
            let complement = derive_complement_commitment(
                &Commitment::from_compressed_bytes(&sec1).expect("commitment parse"),
                MAX_PROVABLE_VALUE,
            )
            .expect("complement");
            [
                zkp,
                sec1_to_zkp(complement.as_bytes()).expect("complement sec1->zkp"),
            ]
        };
        assert!(
            verify_raw(backend, &commit_pair, &bp_proof, h_dom, &[]).expect("bp verify"),
            "bulletproof must verify against shared commitment [{report}] value={value}"
        );
    }

    #[test]
    fn fixed_and_edges() {
        let backend = backend().expect("backend");
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
        let backend = backend().expect("backend");
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

// ── Conformance to the node ───────────────────────────────────────────────
#[cfg(test)]
mod conformance {
    use super::*;

    /// The transcribed backend must derive the DOM's H generator, not one of
    /// its own. The node publishes its generator; this must equal it.
    #[test]
    fn h_generator_is_the_nodes() {
        let mine = h_dom_zkp_serialized().expect("derive H here");
        let theirs = dom_crypto::h_generator::h_compressed().expect("the node's own H");

        // The generator serialization libsecp expects carries 0x0a/0x0b for
        // the parity SEC1 writes as 0x02/0x03. The X coordinate is the same
        // material, and it is the material that identifies the generator.
        let expected_prefix = match theirs[0] {
            0x02 => 0x0a,
            0x03 => 0x0b,
            other => panic!("the node published a non-SEC1 H prefix 0x{other:02x}"),
        };
        assert_eq!(mine[0], expected_prefix, "H parity diverged from the node");
        assert_eq!(
            &mine[1..],
            &theirs[1..],
            "this copy derives a different H generator than the node"
        );
    }

    /// A proof this backend produces must satisfy the node's own public
    /// verifier. If the copy ever drifts, a DOM node rejects what it built.
    #[test]
    fn proofs_this_backend_builds_pass_the_nodes_verifier() {
        for value in [0u64, 1, 42, 1_000_000] {
            let blinding = fixed_blinding(value as u8 | 1);
            let (proof, commitment) = bp_prove(value, &blinding).expect("prove here");

            assert!(
                dom_crypto::range_proof::verify(&commitment, &proof)
                    .expect("the node must be able to verify this proof"),
                "the node rejected a proof this copy produced for value {value}"
            );
        }
    }

    /// And the converse: a proof the node produces must satisfy this copy.
    /// Together the two directions pin the copy to the node in both roles.
    #[test]
    fn proofs_the_node_builds_pass_this_backend() {
        for value in [0u64, 7, 99, 1_000_000] {
            let blinding = fixed_blinding(value as u8 | 1);
            let commitment = dom_crypto::pedersen::Commitment::commit(value, &blinding);
            let (proof, node_commitment) = dom_crypto::range_proof::prove_bytes(value, &blinding)
                .expect("the node must prove here");
            assert_eq!(
                &node_commitment,
                commitment.as_bytes(),
                "the node committed to something this copy does not recognise"
            );

            assert!(
                bp_verify(commitment.as_bytes(), &proof).expect("verify here"),
                "this copy rejected a proof the node produced for value {value}"
            );
        }
    }

    fn fixed_blinding(seed: u8) -> dom_crypto::pedersen::BlindingFactor {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        dom_crypto::pedersen::BlindingFactor::from_bytes(bytes)
            .expect("a fixed nonzero blinding is valid")
    }
}
