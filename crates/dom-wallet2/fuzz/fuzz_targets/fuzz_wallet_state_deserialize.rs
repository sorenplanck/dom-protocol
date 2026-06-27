#![no_main]
//! Fuzz target: serde_json deserialize of the decrypted WalletV2State payload.
//!
//! `dom-wallet-crypto` stores the payload as serde_json inside the AEAD
//! envelope; after decrypt, `load_wallet_state` does
//! `serde_json::from_slice::<WalletV2State>`. The AEAD tag guards integrity, but
//! a hostile payload (or a future format bug) reaching the deserializer must
//! NEVER panic — only Ok/Err. This fuzzes that exact parse over arbitrary bytes.
use dom_wallet2::WalletV2State;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<WalletV2State>(data);
});
