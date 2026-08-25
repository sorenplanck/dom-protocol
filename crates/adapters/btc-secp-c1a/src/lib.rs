//! C1a/C1b conformance harness (Annex M M.11.1, M.11.2).
//!
//! Safe wrappers over the C driver that (a) runs the pinned upstream
//! secp256k1-zkp test suite — with the official BIP327 vector families
//! embedded upstream — and (b) exposes the two C1b semantic probes for
//! tagged-hash integers ≥ n.
//!
//! DEV-ONLY: no production crate depends on this one; the guard script
//! enforces it.

#![deny(missing_docs)]

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_uchar};

extern "C" {
    fn dominterop_c1a_upstream_tests_main(argc: c_int, argv: *mut *mut c_char) -> c_int;
    fn dominterop_c1b_scalar_set_b32_semantics(in32: *const c_uchar, out32: *mut c_uchar) -> c_int;
    fn dominterop_c1b_xonly_tweak_add_accepts(tweak32: *const c_uchar) -> c_int;
    fn dominterop_c1b_init() -> c_int;
}

/// Runs the complete upstream test suite of the pinned revision with the
/// given iteration count and deterministic seed (64 hex chars).
///
/// The BIP327 vector families run inside `run_musig_tests` regardless of
/// `count`. A vector failure aborts the process (upstream `CHECK`
/// semantics), so a normal return with 0 IS the pass signal.
pub fn run_upstream_suite(count: u32, seed_hex: &str) -> i32 {
    assert_eq!(seed_hex.len(), 64, "seed must be 64 hex chars");
    assert!(
        seed_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "seed must be hex"
    );
    let arg0 = CString::new("c1a-upstream-tests").expect("static"); // I14-ALLOW: static string, no interior NUL
    let arg1 = CString::new(count.to_string()).expect("static"); // I14-ALLOW: decimal digits have no interior NUL
    let arg2 = CString::new(seed_hex).expect("validated hex"); // I14-ALLOW: validated hex has no interior NUL
    let mut argv = [
        arg0.as_ptr().cast_mut(),
        arg1.as_ptr().cast_mut(),
        arg2.as_ptr().cast_mut(),
        std::ptr::null_mut(),
    ];
    // SAFETY: argv holds three valid NUL-terminated strings that outlive
    // the call; the C main only reads them.
    unsafe { dominterop_c1a_upstream_tests_main(3, argv.as_mut_ptr()) }
}

/// C1b probe: the library's interpretation of a 32-byte big-endian
/// integer as a scalar (the KeyAgg-coefficient semantics). Returns
/// `(reduced_bytes, overflowed)`.
pub fn scalar_set_b32_semantics(input: [u8; 32]) -> ([u8; 32], bool) {
    let mut out = [0u8; 32];
    // SAFETY: both pointers reference valid 32-byte buffers.
    let overflow =
        unsafe { dominterop_c1b_scalar_set_b32_semantics(input.as_ptr(), out.as_mut_ptr()) };
    (out, overflow != 0)
}

/// C1b probe: whether the x-only tweak-add boundary ACCEPTS `tweak32`
/// (the TapTweak semantics: a tweak ≥ n must be rejected, not reduced).
pub fn xonly_tweak_add_accepts(tweak32: [u8; 32]) -> bool {
    // SAFETY: init creates the global context once; the probe reads the
    // 32-byte buffer only.
    unsafe {
        assert_eq!(dominterop_c1b_init(), 1, "context init");
        dominterop_c1b_xonly_tweak_add_accepts(tweak32.as_ptr()) == 1
    }
}
