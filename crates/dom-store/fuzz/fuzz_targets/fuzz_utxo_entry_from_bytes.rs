#![no_main]
//! Fuzz target: dom_store::UtxoEntry::from_bytes
//!
//! Invariant: deserialization of arbitrary persisted-state bytes must NEVER
//! panic. Either Ok(UtxoEntry) or Err(DomError) — both acceptable. The parser
//! is fixed-offset (9-byte header + tail proof) with a length guard, so this is
//! a totality / crash-freedom check over the on-disk recovery surface.

use libfuzzer_sys::fuzz_target;
use dom_store::UtxoEntry;

fuzz_target!(|data: &[u8]| {
    let _ = UtxoEntry::from_bytes(data);
});
