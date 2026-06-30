//! dom-shield — `Address` (bech32m) KAV-negativo + KAV-drift-congelado.
//!
//! These integration tests drive ONLY the public `Address` API (`encode` /
//! `decode`). They cover the attack vectors that live at the address-envelope
//! boundary (case-malleability, length, payload size, checksum, HRP) plus a
//! byte-freeze (drift) of canonical addresses. No production logic is changed.
//!
//! Bech32m PRIMITIVE-level KAV/XDIFF (BIP-350 raw vectors, from_5bit padding,
//! reference-crate differential) live in `src/address.rs` `#[cfg(test)]`
//! `shield_bech32m`, where the private codec is reachable.

use dom_core::Address;

// ── KAV-negativo ─────────────────────────────────────────────────────────────

/// KAV-negativo. BIP-350 §"Decode" forbids MIXED-case strings: a decoder MUST
/// reject any string that contains both upper- and lower-case characters.
/// `Address::decode` now rejects mixed-case explicitly (address.rs:78) BEFORE
/// the `to_lowercase()` normalization, instead of silently case-folding it.
///
/// This is an address-malleability vector: a single logical address has many
/// distinct on-the-wire spellings that all decode to the same payload, and a
/// BIP-350-conformant peer would reject what this node accepts (consensus /
/// interop divergence). The test asserts the CORRECT (BIP-350) behavior —
/// rejection — and pins the exact case.
///
/// STATUS: RESOLVED — DOM-CORE-ADDR-CASE: mixed-case Bech32m is now rejected
/// before lowercasing (address.rs:78). This test is active (no #[ignore]) and
/// GREEN; it originally exposed the finding and now guards against regression.
#[test]
fn mixed_case_address_is_rejected() {
    // A canonical all-lowercase address that decodes fine.
    let addr = Address::new([0x02u8; 33], true);
    let lower = addr.encode();
    assert!(
        Address::decode(&lower).is_ok(),
        "baseline lowercase must decode"
    );

    // Flip exactly one data character to uppercase -> MIXED case.
    // Find the first ASCII lowercase letter after the 'dom1' prefix and upcase it.
    let mut chars: Vec<char> = lower.chars().collect();
    let mut flipped = false;
    for c in chars.iter_mut().skip(4) {
        if c.is_ascii_lowercase() {
            *c = c.to_ascii_uppercase();
            flipped = true;
            break;
        }
    }
    assert!(
        flipped,
        "address must contain a lowercase data char to flip"
    );
    let mixed: String = chars.into_iter().collect();
    assert_ne!(mixed, lower, "must actually differ in case");

    // BIP-350: a mixed-case string MUST be rejected.
    assert!(
        Address::decode(&mixed).is_err(),
        "BIP-350 forbids mixed-case bech32m; mixed-case address {mixed} must be rejected"
    );
}

/// KAV-negativo. Wrong payload length: a string that bech32m-decodes cleanly but
/// whose decoded payload is not exactly 33 bytes MUST be rejected by
/// `Address::decode`. (32-byte payload encoded with a valid checksum.)
#[test]
fn wrong_length_payload_rejected() {
    use bech32::{Bech32m, Hrp};
    let dom = Hrp::parse("dom").unwrap();
    // VALID-checksum bech32m strings under the `dom` HRP but with payloads that
    // are NOT 33 bytes. The reference crate gives them a correct checksum, so the
    // ONLY thing that can reject them is DOM's 33-byte payload gate — isolating
    // that vector from any checksum failure.
    for wrong_len in [0usize, 1, 32, 34, 64] {
        let payload = vec![0xAB_u8; wrong_len];
        let s = bech32::encode::<Bech32m>(dom, &payload).unwrap();
        // Sanity: the string itself is checksum-valid per the reference crate.
        assert!(bech32::decode(&s).is_ok(), "reference must accept {s}");
        assert!(
            Address::decode(&s).is_err(),
            "valid-checksum `dom` address with {wrong_len}-byte payload must be rejected (only 33 is legal)"
        );
    }
}

/// KAV-negativo. Unknown HRP. A perfectly-checksummed bech32m string whose HRP
/// is neither `dom` nor `tdom` MUST be rejected (it is a different network /
/// asset; accepting it is cross-asset address confusion).
#[test]
fn unknown_hrp_rejected() {
    let addr = Address::new([0x02u8; 33], true);
    let s = addr.encode();
    // Re-checksum under a foreign HRP via the reference crate so the checksum is
    // VALID (isolating the HRP-policy check, not a checksum failure).
    use bech32::{Bech32m, Hrp};
    let hrp = Hrp::parse("btc").unwrap();
    let _ = s; // original kept for documentation
    let foreign = bech32::encode::<Bech32m>(hrp, &[0x02u8; 33]).unwrap();
    assert!(
        Address::decode(&foreign).is_err(),
        "address with unknown HRP `btc` must be rejected"
    );
}

/// KAV-negativo. Bad checksum: a single data-char mutation that keeps the string
/// in-charset but breaks the bech32m checksum MUST be rejected.
#[test]
fn bad_checksum_rejected() {
    let addr = Address::new([0x05u8; 33], true);
    let mut s = addr.encode();
    // Mutate a data char (skip the 'dom1' prefix) to a different in-charset char.
    let bytes = unsafe { s.as_bytes_mut() };
    let i = 5; // inside data
    bytes[i] = if bytes[i] == b'q' { b'p' } else { b'q' };
    assert!(
        Address::decode(&s).is_err(),
        "address with corrupted checksum must be rejected"
    );
}

/// KAV-negativo. Over-length string: anything longer than `MAX_ADDRESS_LEN`
/// (90) MUST be rejected before any decoding work.
#[test]
fn over_length_rejected() {
    let s = "dom1".to_string() + &"q".repeat(120);
    assert!(
        Address::decode(&s).is_err(),
        "address longer than MAX_ADDRESS_LEN must be rejected"
    );
}

/// KAV-negativo. Empty / no-separator / garbage strings must be rejected, never
/// panic.
#[test]
fn structurally_invalid_strings_rejected() {
    for s in ["", "1", "dom", "domqqqq", "\u{00e9}1qqqqqq"] {
        assert!(
            Address::decode(s).is_err(),
            "structurally invalid string {s:?} must be rejected"
        );
    }
}

// ── KAV-drift-congelado (byte-freeze) ────────────────────────────────────────

/// KAV-drift-congelado. Freeze the exact bech32m string for two canonical
/// payloads on each network. Any change to the encoder (charset, checksum
/// constant, HRP, 5-bit packing) silently changes the address a user sees for a
/// given key — a funds-misdirection / wallet-incompatibility regression. These
/// literals are computed once and pinned; a drift turns this RED.
#[test]
fn canonical_address_byte_freeze() {
    // payload = all-0x02, mainnet.
    let a_main = Address::new([0x02u8; 33], true).encode();
    // payload = all-0x03, testnet.
    let a_test = Address::new([0x03u8; 33], false).encode();
    // payload = incrementing 0,1,2,... , mainnet.
    let mut inc = [0u8; 33];
    for (i, b) in inc.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    let a_inc = Address::new(inc, true).encode();

    assert_eq!(
        a_main, ADDR_MAIN_02,
        "mainnet all-0x02 address drifted from frozen value"
    );
    assert_eq!(
        a_test, ADDR_TEST_03,
        "testnet all-0x03 address drifted from frozen value"
    );
    assert_eq!(
        a_inc, ADDR_MAIN_INC,
        "mainnet incrementing-payload address drifted from frozen value"
    );

    // Round-trip the frozen literals back to the original payloads.
    assert_eq!(Address::decode(ADDR_MAIN_02).unwrap().payload, [0x02u8; 33]);
    assert_eq!(Address::decode(ADDR_TEST_03).unwrap().payload, [0x03u8; 33]);
    assert_eq!(Address::decode(ADDR_MAIN_INC).unwrap().payload, inc);
}

// Frozen canonical address strings (computed from the current encoder and
// pinned; see canonical_address_byte_freeze).
const ADDR_MAIN_02: &str = "dom1qgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqy3rj4dj";
const ADDR_TEST_03: &str = "tdom1qvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxfvmd3z";
const ADDR_MAIN_INC: &str = "dom1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqde9c6k";
