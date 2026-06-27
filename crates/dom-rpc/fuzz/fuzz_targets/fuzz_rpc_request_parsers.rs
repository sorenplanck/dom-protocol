#![no_main]
//! dom-shield fuzz-panic — dom-rpc request parsers (panic/crash on hostile bytes)
//!
//! Drives the request-parse surface of dom-rpc on arbitrary attacker bytes,
//! asserting NO panic/abort regardless of input.
//!
//! Reachable from outside the crate (fuzzed directly):
//!   - `serde_json::from_slice::<SpendRequest>` — the POST /wallet/spend body
//!     parser (SpendRequest is `pub` + `#[derive(Deserialize)]`).
//!   - `hex::decode` on the SpendRequest hex fields — mirrors the production
//!     `decode_hex` / `parse_hash_hex` path that get_tx / get_utxo / submit_tx
//!     run on untrusted hex, including the fixed-size `try_into::<[u8; N]>`.
//!
//! NOT reachable from a separate crate (documented, not fuzzed here):
//!   - `decode_hex`, `parse_hash_hex`, `MempoolQuery`, `ScanQuery`, the `router`
//!     handlers — all private (`fn` / `struct` are crate-private; `router` takes
//!     the private `middleware::BearerToken`). They are exercised end-to-end by
//!     the in-crate `#[cfg(test)]` HTTP families (KAV-negativo parse/auth). A
//!     fuzz target cannot name them; re-home into the crate if a libfuzzer pass
//!     over them is wanted later.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1) /wallet/spend body parser on arbitrary bytes (serde_json::from_slice).
    //    Must never panic — only Ok/Err.
    if let Ok(req) = serde_json::from_slice::<dom_rpc::SpendRequest>(data) {
        // 2) The hex fields then flow into hex::decode + fixed-size try_into in
        //    production (decode_hex / parse_hash_hex). Replay that decode shape
        //    on the parsed strings to catch any panic in the hex→array step.
        if let Ok(bytes) = hex::decode(&req.recipient_commitment) {
            // recipient_commitment is a 33-byte commitment in production.
            let _: Result<[u8; 33], _> = bytes.try_into();
        }
        if let Ok(bytes) = hex::decode(&req.recipient_blinding) {
            // recipient_blinding is a 32-byte blinding factor in production.
            let _: Result<[u8; 32], _> = bytes.try_into();
        }
    }

    // 3) Also feed the raw bytes straight through the generic hex decode +
    //    32-byte coercion (the get_tx / parse_hash_hex shape) when they happen
    //    to be valid UTF-8 — the path a malicious /tx/<hex> segment takes.
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(bytes) = hex::decode(s) {
            let _: Result<[u8; 32], _> = bytes.clone().try_into();
            let _: Result<[u8; 33], _> = bytes.try_into();
        }
    }
});
