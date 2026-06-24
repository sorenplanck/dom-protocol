#![no_main]
//! Fuzz target: dom_faucet payment-request parser.
//!
//! Surface: `parse_and_validate_payment_request` (reached via the default-off
//! `shield-probe` re-export). This is the sole attacker-controlled parse surface
//! of dom-faucet — the raw `payment_request` String from `POST /api/request`.
//!
//! Invariant: parsing ANY byte string must NEVER panic / OOB / abort. The parser
//! must always return Ok(_) or Err(_). The faucet amount is also driven from the
//! input so the amount-equality and commit() branches are exercised.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Drive the faucet amount from the first 8 bytes; rest is the request text.
    let (amount, text) = if data.len() >= 8 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&data[..8]);
        (u64::from_le_bytes(a), &data[8..])
    } else {
        (10_000u64, data)
    };
    // Lossy is fine: we only need arbitrary str content; invalid UTF-8 is mapped
    // but the parser's job is to never panic on whatever it receives.
    let s = String::from_utf8_lossy(text);
    let _ = dom_faucet::shield_probe::parse_and_validate(&s, amount);
});
