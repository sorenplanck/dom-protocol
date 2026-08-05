#![no_main]
//! Exercise exact Share PoK statement and proof parsers.

use dom_adaptor::{SharePoPStatementV1, ShareProofV1, TrustedChainIdV1};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > SharePoPStatementV1::ENCODED_LEN + 1 {
        return;
    }
    let trusted_chain = TrustedChainIdV1::from_signed_fixture([0x11; 32]);
    let roster = [[0x21; 32], [0x42; 32]];
    if data.first().copied().unwrap_or_default() & 1 == 0 {
        let _ = SharePoPStatementV1::from_bytes(data, &trusted_chain, &roster);
    } else {
        let _ = ShareProofV1::from_bytes(data);
    }
});
