#![no_main]
//! Fuzz target: dom_chain::PersistedIbdState::from_bytes
//!
//! Attack vector (Lens A: panic/crash on corrupted persisted state). The IBD
//! session snapshot is read back from LMDB metadata on every restart
//! (PersistedIbdState::load). A torn write, downgrade, or hostile data_dir can
//! present arbitrary bytes. The decoder must NEVER panic, over-read, or
//! over-allocate: it must return Ok(state) or Err(DomError) for ANY input.
//!
//! The deserializer contains length-prefixed Vec reads (pending_blocks,
//! pending_headers) capped at MAX_HEADERS_PER_MSG, cursor-vs-count checks, a
//! utf8 peer_addr decode, and monotonic-height / retry-cap semantic checks —
//! all reachable from raw bytes. This target drives all of them.

use libfuzzer_sys::fuzz_target;
use dom_serialization::DomDeserialize;
use dom_chain::PersistedIbdState;

fuzz_target!(|data: &[u8]| {
    let _ = PersistedIbdState::from_bytes(data);
});
