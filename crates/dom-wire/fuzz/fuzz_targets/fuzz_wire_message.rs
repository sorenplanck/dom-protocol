#![no_main]
//! Fuzz target: dom_wire::message::WireMessage::from_bytes
//!
//! Entry point for ALL incoming P2P bytes after Noise decryption.
//! A panic here is a remote DoS vector.
//!
//! Magic is randomized from input prefix to also explore wrong-magic path.
use libfuzzer_sys::fuzz_target;
use dom_wire::message::WireMessage;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let _ = WireMessage::from_bytes(&data[4..], magic);
    // Also test with a known-correct magic to cover the post-magic-check paths.
    let _ = WireMessage::from_bytes(&data[4..], 0xDEADBEEF);
});
