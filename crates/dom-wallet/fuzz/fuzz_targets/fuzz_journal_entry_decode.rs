#![no_main]
//! Fuzz target: serde_json decode of a single dom_wallet::JournalEntry.
//!
//! Subfamily: fuzz-panic (Lens A — panic/crash, malleability).
//!
//! This isolates the per-line JSON parse that `TxJournal::replay` performs
//! (`serde_json::from_str::<JournalEntry>`), including the custom hex32/hex33
//! deserializers for the byte-array fields. Invariant: parsing arbitrary
//! UTF-8-ish bytes must NEVER panic — only return Ok(JournalEntry) or
//! Err(serde_json::Error). The hex-length guards in journal.rs must reject
//! wrong-length hex without indexing out of bounds.

use libfuzzer_sys::fuzz_target;
use dom_wallet::JournalEntry;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<JournalEntry>(s);
    }
});
