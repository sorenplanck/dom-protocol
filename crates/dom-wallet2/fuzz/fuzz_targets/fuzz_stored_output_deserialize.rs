#![no_main]
//! Fuzz target: serde_json deserialize of a single StoredOutput.
//!
//! `StoredOutput` carries custom serde codecs for the 33-byte commitment and the
//! 32-byte Zeroizing blinding (length-checked, copy_from_slice). A wrong-length
//! field, or any malformed JSON, must return a serde error — never panic
//! (copy_from_slice on a mismatched length WOULD panic if the length guard were
//! missing). This fuzzes that codec directly.
use dom_wallet2::StoredOutput;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<StoredOutput>(data);
});
