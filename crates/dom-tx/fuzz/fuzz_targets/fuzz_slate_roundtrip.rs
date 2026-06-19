#![no_main]
//! Fuzz target: Slate parse/serialize idempotence (canonical-form invariant).
//!
//! If `Slate::from_bytes` accepts a byte string, then re-serializing the parsed
//! slate and parsing it again MUST yield the identical slate. Any mismatch is a
//! serialization/parse asymmetry — a non-canonical acceptance or a malleability
//! bug where two distinct encodings decode to the same logical slate (or a
//! decoded slate fails to re-encode). Trailing-byte tolerance is fine: it would
//! drop on re-serialize and the re-parsed slate still equals the original.
//!
//! Invariant: `from_bytes(data) = Ok(s)` ⇒ `from_bytes(to_bytes(s)) = Ok(s)`,
//! and neither re-serialize nor re-parse may panic.

use dom_serialization::{DomDeserialize, DomSerialize};
use dom_tx::slate::Slate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(slate) = Slate::from_bytes(data) {
        let reserialized = slate
            .to_bytes()
            .expect("a successfully-parsed slate must re-serialize");
        let reparsed = Slate::from_bytes(&reserialized)
            .expect("a slate's own serialization must re-parse");
        assert_eq!(slate, reparsed, "slate parse/serialize is not idempotent");
    }
});
