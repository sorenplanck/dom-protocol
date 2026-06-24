#![no_main]
//! Fuzz target: dom_store::PeerAddr::from_bytes
//!
//! Invariant: deserialization of arbitrary persisted-state bytes must NEVER
//! panic. The addr string is the LMDB key (passed in); the value blob carries
//! last_seen (u64 LE) + failures (u32 LE) with a 12-byte length guard. Trailing
//! bytes past 12 are ignored (malleable; pinned in directed_corruption_store.rs)
//! but must never cause a panic. We split the raw fuzz input into a key-ish
//! prefix and the value blob to exercise both arguments.

use libfuzzer_sys::fuzz_target;
use dom_store::PeerAddr;

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    let (addr_bytes, value) = data.split_at(split);
    let addr = String::from_utf8_lossy(addr_bytes).into_owned();
    let _ = PeerAddr::from_bytes(addr, value);
});
