#![no_main]
//! Fuzz target: dom_pow::CompactTarget::to_target on arbitrary u32.
//!
//! Invariant (Lens A: panic/crash/OOB): expanding ANY 32-bit compact value must
//! never panic. It returns Ok(target) or Err(DomError); both are fine. The
//! internal byte-writer indexing (exponent-derived positions) must stay in
//! bounds for every exponent 0..=255.

use libfuzzer_sys::fuzz_target;
use dom_pow::CompactTarget;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let bits = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    // Must be panic-free for every u32.
    let _ = CompactTarget(bits).to_target();
});
