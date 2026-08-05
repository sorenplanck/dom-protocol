#![no_main]
//! Exercise the bounded canonical session-context parser.

use dom_adaptor::{SessionContextV1, SigningShareV1, TrustedChainIdV1};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 768 {
        return;
    }
    let trusted_chain = TrustedChainIdV1::from_signed_fixture([0x11; 32]);
    let mut share_bytes = [0u8; 32];
    share_bytes[31] = 1;
    let signing_share =
        SigningShareV1::from_be_bytes(share_bytes).expect("fixed scalar is canonical");
    let _ = SessionContextV1::from_bytes(data, &trusted_chain, &signing_share);
});
