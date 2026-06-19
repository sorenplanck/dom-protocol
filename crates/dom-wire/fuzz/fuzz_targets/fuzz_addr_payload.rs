#![no_main]
//! Fuzz target: `dom_wire::message::AddrPayload::from_bytes`.
//!
//! The Addr response (`Command::Addr = 0x0B`) is a peer-supplied list of peer
//! addresses (`AddrEntry`): the address-book / peer-discovery attack surface.
//! A malicious peer fully controls these bytes — the classic eclipse / DoS
//! vector. The parser promises (per its doc) to reject oversized counts,
//! truncated payloads, and trailing bytes, and to allocate only after the
//! declared count is proven plausible. This target hammers exactly those
//! promises with unrestricted peer bytes:
//!
//!   - a lying `count` (huge declared length, short payload) — must NOT
//!     pre-allocate (libFuzzer's RSS limit catches an OOM if it does);
//!   - a plausible count but the entry list truncated mid-element;
//!   - trailing bytes after a complete list (must be rejected);
//!   - malformed `AddrEntry` (bad IP family / address / port);
//!   - the list at the exact limit and one past it.
//!
//! Invariant: decoding ARBITRARY bytes must NEVER panic, abort, or OOM — only
//! `Ok(AddrPayload)` or `Err(_)`. A crash here is a remotely-reachable node DoS.

use dom_wire::message::AddrPayload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = AddrPayload::from_bytes(data);
});
