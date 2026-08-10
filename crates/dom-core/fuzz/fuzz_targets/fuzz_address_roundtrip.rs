#![no_main]
//! Fuzz target: `dom_core::Address` encode→decode roundtrip + encoder no-panic.
//!
//! Drives the ENCODER (`Address::encode` → `to_5bit`, `polymod`, charset index)
//! with arbitrary 33-byte payloads and either network, then feeds the result
//! back through `decode`. Two invariants:
//!   1. `encode` never panics for any payload (it indexes CHARSET by 5-bit
//!      values and shifts the checksum — both must stay in bounds).
//!   2. roundtrip is lossless: decode(encode(addr)) == addr. A mismatch is an
//!      address-misdirection bug (the user sees a string that decodes to a
//!      different key/network than they signed for).
//!
//! The first 33 bytes are the payload; the next byte (if present) selects the
//! network. This keeps the encoder fed with structured input rather than the
//! decoder, which the sibling `fuzz_address_decode` target already hammers.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return;
    }
    let mut payload = [0u8; 33];
    payload.copy_from_slice(&data[..33]);
    let is_mainnet = data.get(33).map(|b| b & 1 == 1).unwrap_or(true);

    let network_magic = if is_mainnet {
        dom_core::NETWORK_MAGIC_MAINNET
    } else {
        dom_core::NETWORK_MAGIC_TESTNET
    };
    let Ok(addr) = dom_core::Address::new_for_network(payload, network_magic) else {
        return;
    };
    let s = addr.encode(); // must not panic

    let decoded = dom_core::Address::decode(&s).expect("encoder output must decode");
    assert_eq!(decoded, addr, "encode→decode roundtrip diverged");
});
