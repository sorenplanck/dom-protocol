#![no_main]
//! Exercise exact Share PoK statement and proof parsers.

use dom_adaptor::{SharePoPStatementV1, ShareProofV1, TrustedChainIdV1};
use dom_crypto::Hash256;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    if payload.len() > SharePoPStatementV1::ENCODED_LEN {
        return;
    }
    let trusted_chain =
        TrustedChainIdV1::from_authenticated_genesis(0x5343_465a, &Hash256::from_bytes([0x11; 32]));
    let roster = [[0x21; 32], [0x42; 32]];
    if selector & 1 == 0 {
        let _ = SharePoPStatementV1::from_bytes(payload, &trusted_chain, &roster);
    } else {
        let _ = ShareProofV1::from_bytes(payload);
    }
});
