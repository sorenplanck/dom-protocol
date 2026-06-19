#![no_main]
//! Fuzz target: `dom_wire::message::GetAddrPayload::from_bytes`.
//!
//! The GetAddr request (`Command::GetAddr = 0x0A`) MUST carry an empty payload.
//! A peer can send arbitrary bytes here; the parser must reject any non-empty /
//! garbage payload with `Err` and never panic. Minimal surface, included for
//! completeness of the Addr/PEX message family.
//!
//! Invariant: arbitrary bytes must never panic — only `Ok` (empty) or `Err`.

use dom_wire::message::GetAddrPayload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = GetAddrPayload::from_bytes(data);
});
