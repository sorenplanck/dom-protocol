//! RAII wrapper over the preallocated secp256k1 context.
//!
//! The vendored tree compiles only the preallocated context API: the
//! caller owns the memory (16-byte aligned) for the context's whole
//! lifetime. This module is the single owner of that memory.

use core::ffi::c_void;
use std::alloc::{alloc, dealloc, Layout};

use btc_secp_sys::{
    secp256k1_context, secp256k1_context_preallocated_create,
    secp256k1_context_preallocated_destroy, secp256k1_context_preallocated_size,
    secp256k1_context_randomize, SECP256K1_CONTEXT_NONE,
};

/// A live secp256k1 context and the aligned memory backing it.
///
/// `Send`/`Sync`: the context is only ever used through `&self` and the
/// underlying library is thread-safe for verification/aggregation once
/// randomized; the wrapper never mutates the context after construction.
pub struct SecpContext {
    ctx: *mut secp256k1_context,
    memory: *mut u8,
    layout: Layout,
}

// SAFETY: after construction the context is immutable and the C library
// permits concurrent read-only use of a single context. The wrapper
// exposes only `&self` methods.
unsafe impl Send for SecpContext {}
unsafe impl Sync for SecpContext {}

impl SecpContext {
    /// Creates and randomizes a context. `seed32` hardens against
    /// side-channels; callers pass fresh entropy in production.
    pub fn new(seed32: &[u8; 32]) -> Self {
        // SAFETY: valid flags; the size query has no preconditions.
        let size = unsafe { secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE) };
        assert!(size > 0, "context size query returned zero");
        let layout = match Layout::from_size_align(size, 16) {
            Ok(layout) => layout,
            // The alignment is a compile-time power of two; a size outside
            // `Layout`'s range means the linked backend violated its own
            // preallocation ABI and continuing cannot be memory-safe.
            Err(_) => std::process::abort(),
        };
        // SAFETY: layout has non-zero size.
        let memory = unsafe { alloc(layout) };
        assert!(!memory.is_null(), "context allocation failed");
        // SAFETY: `memory` is `size` bytes, 16-byte aligned, exclusively
        // owned by this struct for the context's whole lifetime.
        let ctx = unsafe {
            secp256k1_context_preallocated_create(memory.cast::<c_void>(), SECP256K1_CONTEXT_NONE)
        };
        assert!(!ctx.is_null(), "context creation failed");
        // SAFETY: ctx is valid; seed is 32 bytes.
        let randomized = unsafe { secp256k1_context_randomize(ctx, seed32.as_ptr()) };
        assert_eq!(randomized, 1, "context randomization failed");
        Self {
            ctx,
            memory,
            layout,
        }
    }

    /// The raw const pointer for FFI calls that only read the context.
    pub(crate) fn as_ptr(&self) -> *const secp256k1_context {
        self.ctx
    }
}

impl Drop for SecpContext {
    fn drop(&mut self) {
        // SAFETY: `ctx` was created in `memory`; we destroy the context
        // first, then free the memory with the exact layout we allocated.
        unsafe {
            secp256k1_context_preallocated_destroy(self.ctx);
            dealloc(self.memory, self.layout);
        }
    }
}
