//! Minimal FFI surface over the vendored, pinned secp256k1-zkp
//! (Annex M v3.2, M.1.2 / M.17 step 1).
//!
//! This is the ONLY crate in the workspace that contains `unsafe`: raw
//! declarations of the exact C functions the Bitcoin leg needs, and
//! nothing else. Every semantic decision — canonical scalars, parity
//! handling, verify-after-every-FFI-success, fail-closed errors — lives
//! in the SAFE wrapper crate above this one (`adapter-btc`), never here.
//!
//! Surface (deliberately closed):
//! - context create/destroy/randomize;
//! - EC keys: seckey verify, pubkey create/parse/serialize, keypair,
//!   x-only parse/serialize/from-pubkey;
//! - MuSig2 (BIP327): key aggregation + x-only (Taproot) tweak, nonce
//!   gen/agg/process WITH adaptor, partial sign/verify/agg, nonce
//!   parity, adapt, extract_adaptor;
//! - BIP340 verification and tagged SHA-256.
//!
//! Pin provenance is recorded in `VENDOR.md` and enforced by vendoring:
//! upstream secp256k1-zkp `6152622613fdf1c5af6f31f74c427c4e9ee120ce`,
//! symbols re-prefixed `dominterop_secp_v0_10_0_` for link isolation.

#![deny(missing_docs)]
// FFI declarations are inherently unsafe; this crate is the single,
// bounded exception to the workspace-wide forbid(unsafe_code).
#![allow(non_camel_case_types)]

use core::ffi::{c_int, c_uchar, c_void};

/// Flags for a verification-capable context (`SECP256K1_CONTEXT_VERIFY`
/// is a no-op in modern upstream; NONE suffices for all operations, but
/// SIGN|VERIFY is kept for explicitness with this vendored revision).
pub const SECP256K1_CONTEXT_NONE: u32 = 1;
/// Historical SIGN flag (harmless with this revision).
pub const SECP256K1_CONTEXT_SIGN: u32 = 1 | (1 << 9);
/// Historical VERIFY flag (harmless with this revision).
pub const SECP256K1_CONTEXT_VERIFY: u32 = 1 | (1 << 8);
/// SEC1 compressed serialization flag.
pub const SECP256K1_EC_COMPRESSED: u32 = (1 << 1) | (1 << 8);

/// Opaque context object.
#[repr(C)]
pub struct secp256k1_context {
    _private: [u8; 0],
}

/// Parsed public key (opaque 64-byte representation).
#[repr(C)]
pub struct secp256k1_pubkey {
    /// Opaque backend representation — never a wire format.
    pub data: [c_uchar; 64],
}

/// Parsed x-only public key (opaque 64-byte representation).
#[repr(C)]
pub struct secp256k1_xonly_pubkey {
    /// Opaque backend representation — never a wire format.
    pub data: [c_uchar; 64],
}

/// Keypair (opaque 96-byte representation; contains secret material).
#[repr(C)]
pub struct secp256k1_keypair {
    /// Opaque backend representation; CONTAINS THE SECRET KEY.
    pub data: [c_uchar; 96],
}

/// MuSig2 key-aggregation cache (opaque, 197 bytes; public material).
#[repr(C)]
pub struct secp256k1_musig_keyagg_cache {
    /// Opaque backend representation — never a wire format (M.1.3.8).
    pub data: [c_uchar; 197],
}

/// MuSig2 secret nonce (opaque, 132 bytes; SECRET, memory-only, never
/// serialized — Annex M M.6.6).
#[repr(C)]
pub struct secp256k1_musig_secnonce {
    /// Opaque backend representation; SECRET MATERIAL.
    pub data: [c_uchar; 132],
}

/// MuSig2 public nonce (opaque, 132 bytes).
#[repr(C)]
pub struct secp256k1_musig_pubnonce {
    /// Opaque backend representation — serialize via the dedicated call.
    pub data: [c_uchar; 132],
}

/// MuSig2 aggregate nonce (opaque, 132 bytes).
#[repr(C)]
pub struct secp256k1_musig_aggnonce {
    /// Opaque backend representation — serialize via the dedicated call.
    pub data: [c_uchar; 132],
}

/// MuSig2 session (opaque, 133 bytes; public material).
#[repr(C)]
pub struct secp256k1_musig_session {
    /// Opaque backend representation — never a wire format.
    pub data: [c_uchar; 133],
}

/// MuSig2 partial signature (opaque, 36 bytes).
#[repr(C)]
pub struct secp256k1_musig_partial_sig {
    /// Opaque backend representation — serialize via the dedicated call.
    pub data: [c_uchar; 36],
}

/// Serialized public nonce length (two compressed points).
pub const MUSIG_PUBNONCE_SERIALIZED_LEN: usize = 66;
/// Serialized partial signature length (one scalar).
pub const MUSIG_PARTIAL_SIG_SERIALIZED_LEN: usize = 32;

// The vendored library is built with USE_EXTERNAL_DEFAULT_CALLBACKS: the
// two default callbacks must exist at link time. They abort, matching the
// upstream contract — an illegal-argument callback firing means a bug in
// the SAFE wrapper (a violated NONNULL or an unaligned type), and
// continuing would be undefined behavior. No secret is formatted here.
#[no_mangle]
extern "C" fn dominterop_secp_v0_10_0_default_illegal_callback_fn(
    _message: *const c_uchar,
    _data: *mut c_void,
) {
    std::process::abort();
}

#[no_mangle]
extern "C" fn dominterop_secp_v0_10_0_default_error_callback_fn(
    _message: *const c_uchar,
    _data: *mut c_void,
) {
    std::process::abort();
}

extern "C" {
    /// Size in bytes a preallocated context of `flags` requires. The
    /// vendored tree (like upstream -sys crates) compiles ONLY the
    /// preallocated context API: the caller owns the memory, 16-byte
    /// aligned, for the context's whole lifetime.
    #[link_name = "dominterop_secp_v0_10_0_context_preallocated_size"]
    pub fn secp256k1_context_preallocated_size(flags: u32) -> usize;

    /// Creates a context inside caller-owned memory of at least
    /// [`secp256k1_context_preallocated_size`] bytes, 16-byte aligned.
    #[link_name = "dominterop_secp_v0_10_0_context_preallocated_create"]
    pub fn secp256k1_context_preallocated_create(
        prealloc: *mut c_void,
        flags: u32,
    ) -> *mut secp256k1_context;

    /// Tears down a preallocated context. The caller frees the memory
    /// AFTERWARDS, with the same layout it allocated.
    #[link_name = "dominterop_secp_v0_10_0_context_preallocated_destroy"]
    pub fn secp256k1_context_preallocated_destroy(ctx: *mut secp256k1_context);

    /// Re-randomizes the context (side-channel hardening).
    #[link_name = "dominterop_secp_v0_10_0_context_randomize"]
    pub fn secp256k1_context_randomize(
        ctx: *mut secp256k1_context,
        seed32: *const c_uchar,
    ) -> c_int;

    /// Verifies a 32-byte secret key is canonical and non-zero.
    #[link_name = "dominterop_secp_v0_10_0_ec_seckey_verify"]
    pub fn secp256k1_ec_seckey_verify(
        ctx: *const secp256k1_context,
        seckey: *const c_uchar,
    ) -> c_int;

    /// Computes the public key of a secret key.
    #[link_name = "dominterop_secp_v0_10_0_ec_pubkey_create"]
    pub fn secp256k1_ec_pubkey_create(
        ctx: *const secp256k1_context,
        pubkey: *mut secp256k1_pubkey,
        seckey: *const c_uchar,
    ) -> c_int;

    /// Parses a serialized public key (33- or 65-byte forms).
    #[link_name = "dominterop_secp_v0_10_0_ec_pubkey_parse"]
    pub fn secp256k1_ec_pubkey_parse(
        ctx: *const secp256k1_context,
        pubkey: *mut secp256k1_pubkey,
        input: *const c_uchar,
        inputlen: usize,
    ) -> c_int;

    /// Serializes a public key (compressed with the flag above).
    #[link_name = "dominterop_secp_v0_10_0_ec_pubkey_serialize"]
    pub fn secp256k1_ec_pubkey_serialize(
        ctx: *const secp256k1_context,
        output: *mut c_uchar,
        outputlen: *mut usize,
        pubkey: *const secp256k1_pubkey,
        flags: u32,
    ) -> c_int;

    /// Builds a keypair from a secret key.
    #[link_name = "dominterop_secp_v0_10_0_keypair_create"]
    pub fn secp256k1_keypair_create(
        ctx: *const secp256k1_context,
        keypair: *mut secp256k1_keypair,
        seckey: *const c_uchar,
    ) -> c_int;

    /// Extracts the public key of a keypair.
    #[link_name = "dominterop_secp_v0_10_0_keypair_pub"]
    pub fn secp256k1_keypair_pub(
        ctx: *const secp256k1_context,
        pubkey: *mut secp256k1_pubkey,
        keypair: *const secp256k1_keypair,
    ) -> c_int;

    /// Parses a 32-byte x-only public key.
    #[link_name = "dominterop_secp_v0_10_0_xonly_pubkey_parse"]
    pub fn secp256k1_xonly_pubkey_parse(
        ctx: *const secp256k1_context,
        pubkey: *mut secp256k1_xonly_pubkey,
        input32: *const c_uchar,
    ) -> c_int;

    /// Serializes an x-only public key to 32 bytes.
    #[link_name = "dominterop_secp_v0_10_0_xonly_pubkey_serialize"]
    pub fn secp256k1_xonly_pubkey_serialize(
        ctx: *const secp256k1_context,
        output32: *mut c_uchar,
        pubkey: *const secp256k1_xonly_pubkey,
    ) -> c_int;

    /// Converts a pubkey to x-only, reporting the discarded parity.
    #[link_name = "dominterop_secp_v0_10_0_xonly_pubkey_from_pubkey"]
    pub fn secp256k1_xonly_pubkey_from_pubkey(
        ctx: *const secp256k1_context,
        xonly_pubkey: *mut secp256k1_xonly_pubkey,
        pk_parity: *mut c_int,
        pubkey: *const secp256k1_pubkey,
    ) -> c_int;

    /// BIP340 signing over a 32-byte message under a keypair. The
    /// binding exists because F6 senders sign Relay envelopes with
    /// their canonical roster key (A10, ratified): the same pinned
    /// library that verifies must produce, so there is exactly one
    /// BIP340 implementation in the tree (I15).
    #[link_name = "dominterop_secp_v0_10_0_schnorrsig_sign32"]
    pub fn secp256k1_schnorrsig_sign32(
        ctx: *const secp256k1_context,
        sig64: *mut c_uchar,
        msg32: *const c_uchar,
        keypair: *const secp256k1_keypair,
        aux_rand32: *const c_uchar,
    ) -> c_int;

    /// BIP340 verification over a 32-byte message.
    #[link_name = "dominterop_secp_v0_10_0_schnorrsig_verify"]
    pub fn secp256k1_schnorrsig_verify(
        ctx: *const secp256k1_context,
        sig64: *const c_uchar,
        msg: *const c_uchar,
        msglen: usize,
        pubkey: *const secp256k1_xonly_pubkey,
    ) -> c_int;

    /// BIP340-style tagged SHA-256.
    #[link_name = "dominterop_secp_v0_10_0_tagged_sha256"]
    pub fn secp256k1_tagged_sha256(
        ctx: *const secp256k1_context,
        hash32: *mut c_uchar,
        tag: *const c_uchar,
        taglen: usize,
        msg: *const c_uchar,
        msglen: usize,
    ) -> c_int;

    // ---- MuSig2 (BIP327) with adaptor support -------------------------

    /// Parses a 66-byte serialized public nonce.
    #[link_name = "dominterop_secp_v0_10_0_musig_pubnonce_parse"]
    pub fn secp256k1_musig_pubnonce_parse(
        ctx: *const secp256k1_context,
        nonce: *mut secp256k1_musig_pubnonce,
        input66: *const c_uchar,
    ) -> c_int;

    /// Serializes a public nonce to 66 bytes.
    #[link_name = "dominterop_secp_v0_10_0_musig_pubnonce_serialize"]
    pub fn secp256k1_musig_pubnonce_serialize(
        ctx: *const secp256k1_context,
        output66: *mut c_uchar,
        nonce: *const secp256k1_musig_pubnonce,
    ) -> c_int;

    /// Parses a 66-byte serialized aggregate nonce.
    #[link_name = "dominterop_secp_v0_10_0_musig_aggnonce_parse"]
    pub fn secp256k1_musig_aggnonce_parse(
        ctx: *const secp256k1_context,
        nonce: *mut secp256k1_musig_aggnonce,
        input66: *const c_uchar,
    ) -> c_int;

    /// Serializes an aggregate nonce to 66 bytes.
    #[link_name = "dominterop_secp_v0_10_0_musig_aggnonce_serialize"]
    pub fn secp256k1_musig_aggnonce_serialize(
        ctx: *const secp256k1_context,
        output66: *mut c_uchar,
        nonce: *const secp256k1_musig_aggnonce,
    ) -> c_int;

    /// Serializes a partial signature to 32 bytes.
    #[link_name = "dominterop_secp_v0_10_0_musig_partial_sig_serialize"]
    pub fn secp256k1_musig_partial_sig_serialize(
        ctx: *const secp256k1_context,
        output32: *mut c_uchar,
        partial_sig: *const secp256k1_musig_partial_sig,
    ) -> c_int;

    /// Parses a 32-byte serialized partial signature.
    #[link_name = "dominterop_secp_v0_10_0_musig_partial_sig_parse"]
    pub fn secp256k1_musig_partial_sig_parse(
        ctx: *const secp256k1_context,
        partial_sig: *mut secp256k1_musig_partial_sig,
        input32: *const c_uchar,
    ) -> c_int;

    /// BIP327 key aggregation over an ORDERED pubkey array.
    #[link_name = "dominterop_secp_v0_10_0_musig_pubkey_agg"]
    pub fn secp256k1_musig_pubkey_agg(
        ctx: *const secp256k1_context,
        scratch: *mut c_void,
        agg_pk: *mut secp256k1_xonly_pubkey,
        keyagg_cache: *mut secp256k1_musig_keyagg_cache,
        pubkeys: *const *const secp256k1_pubkey,
        n_pubkeys: usize,
    ) -> c_int;

    /// Full (non-x-only) aggregate public key from a keyagg cache.
    #[link_name = "dominterop_secp_v0_10_0_musig_pubkey_get"]
    pub fn secp256k1_musig_pubkey_get(
        ctx: *const secp256k1_context,
        agg_pk: *mut secp256k1_pubkey,
        keyagg_cache: *const secp256k1_musig_keyagg_cache,
    ) -> c_int;

    /// X-only (Taproot) tweak of the aggregate key inside the cache.
    /// Returns 0 on overflow/infinity — the caller MUST fail closed and
    /// never reduce (Annex M M.2.2 step 7).
    #[link_name = "dominterop_secp_v0_10_0_musig_pubkey_xonly_tweak_add"]
    pub fn secp256k1_musig_pubkey_xonly_tweak_add(
        ctx: *const secp256k1_context,
        output_pubkey: *mut secp256k1_pubkey,
        keyagg_cache: *mut secp256k1_musig_keyagg_cache,
        tweak32: *const c_uchar,
    ) -> c_int;

    /// Nonce generation. `session_secrand32` is the one-shot secret
    /// randomness of Annex M M.6 — the caller owns its vault discipline.
    #[link_name = "dominterop_secp_v0_10_0_musig_nonce_gen"]
    pub fn secp256k1_musig_nonce_gen(
        ctx: *const secp256k1_context,
        secnonce: *mut secp256k1_musig_secnonce,
        pubnonce: *mut secp256k1_musig_pubnonce,
        session_secrand32: *const c_uchar,
        seckey: *const c_uchar,
        pubkey: *const secp256k1_pubkey,
        msg32: *const c_uchar,
        keyagg_cache: *const secp256k1_musig_keyagg_cache,
        extra_input32: *const c_uchar,
    ) -> c_int;

    /// Aggregates public nonces (roster order is the caller's law).
    #[link_name = "dominterop_secp_v0_10_0_musig_nonce_agg"]
    pub fn secp256k1_musig_nonce_agg(
        ctx: *const secp256k1_context,
        aggnonce: *mut secp256k1_musig_aggnonce,
        pubnonces: *const *const secp256k1_musig_pubnonce,
        n_pubnonces: usize,
    ) -> c_int;

    /// Computes the session; a non-NULL `adaptor` makes the aggregate a
    /// PRE-signature (Annex M M.4.2 step 2).
    #[link_name = "dominterop_secp_v0_10_0_musig_nonce_process"]
    pub fn secp256k1_musig_nonce_process(
        ctx: *const secp256k1_context,
        session: *mut secp256k1_musig_session,
        aggnonce: *const secp256k1_musig_aggnonce,
        msg32: *const c_uchar,
        keyagg_cache: *const secp256k1_musig_keyagg_cache,
        adaptor: *const secp256k1_pubkey,
    ) -> c_int;

    /// Produces a partial signature, zeroizing the secnonce (one-shot at
    /// the backend layer; the DURABLE one-shot lives in the vault).
    #[link_name = "dominterop_secp_v0_10_0_musig_partial_sign"]
    pub fn secp256k1_musig_partial_sign(
        ctx: *const secp256k1_context,
        partial_sig: *mut secp256k1_musig_partial_sig,
        secnonce: *mut secp256k1_musig_secnonce,
        keypair: *const secp256k1_keypair,
        keyagg_cache: *const secp256k1_musig_keyagg_cache,
        session: *const secp256k1_musig_session,
    ) -> c_int;

    /// Verifies one partial signature (mandatory for every partial,
    /// including our own — Annex M M.6.7).
    #[link_name = "dominterop_secp_v0_10_0_musig_partial_sig_verify"]
    pub fn secp256k1_musig_partial_sig_verify(
        ctx: *const secp256k1_context,
        partial_sig: *const secp256k1_musig_partial_sig,
        pubnonce: *const secp256k1_musig_pubnonce,
        pubkey: *const secp256k1_pubkey,
        keyagg_cache: *const secp256k1_musig_keyagg_cache,
        session: *const secp256k1_musig_session,
    ) -> c_int;

    /// Aggregates partials into a 64-byte (pre-)signature.
    #[link_name = "dominterop_secp_v0_10_0_musig_partial_sig_agg"]
    pub fn secp256k1_musig_partial_sig_agg(
        ctx: *const secp256k1_context,
        sig64: *mut c_uchar,
        session: *const secp256k1_musig_session,
        partial_sigs: *const *const secp256k1_musig_partial_sig,
        n_sigs: usize,
    ) -> c_int;

    /// Nonce parity of the session (Annex M M.4.2 step 3).
    #[link_name = "dominterop_secp_v0_10_0_musig_nonce_parity"]
    pub fn secp256k1_musig_nonce_parity(
        ctx: *const secp256k1_context,
        nonce_parity: *mut c_int,
        session: *const secp256k1_musig_session,
    ) -> c_int;

    /// Adapts a pre-signature with the secret adaptor.
    #[link_name = "dominterop_secp_v0_10_0_musig_adapt"]
    pub fn secp256k1_musig_adapt(
        ctx: *const secp256k1_context,
        sig64: *mut c_uchar,
        pre_sig64: *const c_uchar,
        sec_adaptor32: *const c_uchar,
        nonce_parity: c_int,
    ) -> c_int;

    /// Extracts the secret adaptor from (signature, pre-signature).
    #[link_name = "dominterop_secp_v0_10_0_musig_extract_adaptor"]
    pub fn secp256k1_musig_extract_adaptor(
        ctx: *const secp256k1_context,
        sec_adaptor32: *mut c_uchar,
        sig64: *const c_uchar,
        pre_sig64: *const c_uchar,
        nonce_parity: c_int,
    ) -> c_int;
}
