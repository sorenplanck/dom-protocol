#![no_main]
//! Fuzz target: dom_wallet_keys::Bip39Seed::from_phrase
//!
//! Invariant: parsing an ARBITRARY string as a BIP-39 phrase must NEVER panic.
//! Either Ok(Bip39Seed) or Err(SeedError) — both acceptable. We drive both
//! acceptance policies (NewWallet / LegacyRestore) since the word-count gate
//! and the BIP-39 parser are exercised on different paths.

use dom_wallet_keys::{Bip39Seed, SeedAcceptance};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Bip39Seed::from_phrase(s, SeedAcceptance::NewWallet);
        let _ = Bip39Seed::from_phrase(s, SeedAcceptance::LegacyRestore);
    }
});
