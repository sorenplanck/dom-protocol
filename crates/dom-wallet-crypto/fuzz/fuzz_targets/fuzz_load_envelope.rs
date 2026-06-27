#![no_main]
//! Fuzz target: dom_wallet_crypto::load_envelope on ARBITRARY file bytes.
//!
//! Invariant: parsing arbitrary bytes as an envelope must NEVER panic. The
//! header parse (length/magic/version checks), the salt/nonce slicing, the
//! Argon2id+HKDF key derivation, the ChaCha20Poly1305 decrypt and the final
//! serde_json parse must all reach a typed `Result`, never an unwrap/slice OOB.
//!
//! We write `data` to a temp file and load it under a fixed expected
//! magic/version/password. Any return value is acceptable (Ok or any
//! EnvelopeError) — only a panic/abort is a finding.
//!
//! Note: Argon2id at 64 MiB makes each non-rejected case heavy; the loader
//! short-circuits on bad magic/version/length BEFORE the KDF, so most inputs
//! are cheap. Run with a small max_len.

use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use std::io::Write;

const MAGIC: &[u8; 14] = b"DOM-TEST-ENV\0\0";

#[derive(Debug, Deserialize)]
struct Payload {
    #[allow(dead_code)]
    a: u32,
    #[allow(dead_code)]
    b: String,
}

fuzz_target!(|data: &[u8]| {
    let mut f = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(_) => return,
    };
    if f.write_all(data).is_err() {
        return;
    }
    if f.flush().is_err() {
        return;
    }
    let _ = dom_wallet_crypto::load_envelope::<Payload>(f.path(), MAGIC, 1, "pw");
});
