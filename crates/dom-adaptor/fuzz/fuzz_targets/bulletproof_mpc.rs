#![no_main]
//! Exercise exact collaborative Bulletproof statement and round parsers.

use dom_adaptor::{BpRound1ShareV1, BpStatementV1, SigningShareV1, TrustedChainIdV1};
use dom_crypto::{scriptless_add_public_points, Hash256};
use libfuzzer_sys::fuzz_target;

fn point(value: u8) -> dom_crypto::PublicKey {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    SigningShareV1::from_be_bytes(bytes)
        .expect("fixed scalar is canonical")
        .public_key()
        .clone()
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    if payload.len() > 1_256 {
        return;
    }
    let trusted_chain =
        TrustedChainIdV1::from_authenticated_genesis(0x5343_465a, &Hash256::from_bytes([0x11; 32]));
    match selector % 2 {
        0 => {
            let _ = BpStatementV1::from_bytes(payload, &trusted_chain);
        }
        _ => {
            let shares = vec![point(3), point(5)];
            let aggregate = scriptless_add_public_points(&shares).expect("fixed aggregate");
            let statement = BpStatementV1::new(
                &trusted_chain,
                [0x22; 32],
                vec![[0x31; 32], [0x32; 32]],
                42,
                shares,
                aggregate,
                None,
            )
            .expect("fixed statement");
            let _ = BpRound1ShareV1::from_bytes(payload, &statement);
        }
    }
});
