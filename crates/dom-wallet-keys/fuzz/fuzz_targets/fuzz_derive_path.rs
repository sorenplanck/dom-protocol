#![no_main]
//! Fuzz target: dom_wallet_keys::ExtendedPrivKey::derive_path
//!
//! Invariant: deriving an ARBITRARY path string must NEVER panic. Either
//! Ok(node) or Err(HdError) — both acceptable. Path parsing (split on '/',
//! strip "m/", strip trailing "'", u32::parse, checked_add for HARDENED_OFFSET)
//! is the attackable string surface; child() arithmetic is exercised too.
//!
//! Layout: first 32 bytes = seed (always a valid in-range master seed); the
//! UTF-8-lossy remainder = the path string under test.

use dom_wallet_keys::ExtendedPrivKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    let master = match ExtendedPrivKey::from_seed(&seed) {
        Ok(m) => m,
        Err(_) => return,
    };
    let path = String::from_utf8_lossy(&data[32..]);
    let _ = master.derive_path(&path);
});
