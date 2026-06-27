//! DOM address encoding and decoding.
//!
//! DOM addresses use a Bech32m encoding (BIP-350) with human-readable parts:
//! - Mainnet: "dom"
//! - Testnet: "tdom"
//!
//! An address encodes a 33-byte compressed public key commitment.
//! Format: <hrp>1<bech32m-encoded-data><checksum>
//!
//! RFC-0010: Address System.

use crate::DomError;

/// Human-readable part for mainnet addresses.
pub const ADDRESS_HRP_MAINNET: &str = "dom";

/// Human-readable part for testnet addresses.
pub const ADDRESS_HRP_TESTNET: &str = "tdom";

/// Maximum address string length (hrp + separator + data + checksum).
pub const MAX_ADDRESS_LEN: usize = 90;

/// Bech32m constant (BIP-350).
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// Bech32 charset.
const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Reverse lookup: ASCII → 5-bit value (0xFF = invalid).
#[allow(clippy::cast_possible_truncation)]
const CHARSET_REV: [u8; 128] = {
    let mut rev = [0xFFu8; 128];
    let mut i = 0usize;
    while i < 32 {
        rev[CHARSET[i] as usize] = i as u8; // safe: i < 32, fits u8
        i += 1;
    }
    rev
};

/// A DOM address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// The 33-byte compressed public key (or commitment).
    pub payload: [u8; 33],
    /// Whether this is a mainnet or testnet address.
    pub is_mainnet: bool,
}

impl Address {
    /// Create an address from a 33-byte payload.
    pub fn new(payload: [u8; 33], is_mainnet: bool) -> Self {
        Self {
            payload,
            is_mainnet,
        }
    }

    /// Encode address to Bech32m string.
    pub fn encode(&self) -> String {
        let hrp = if self.is_mainnet {
            ADDRESS_HRP_MAINNET
        } else {
            ADDRESS_HRP_TESTNET
        };
        bech32m_encode(hrp, &self.payload)
    }

    /// Decode a Bech32m address string.
    pub fn decode(s: &str) -> Result<Self, DomError> {
        if s.len() > MAX_ADDRESS_LEN {
            return Err(DomError::Malformed("address too long".into()));
        }
        let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
        let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
        if has_lower && has_upper {
            return Err(DomError::Malformed(
                "mixed-case bech32m address is not allowed".into(),
            ));
        }
        let s_lower = s.to_lowercase();
        let (hrp, payload) = bech32m_decode(&s_lower)?;
        if payload.len() != 33 {
            return Err(DomError::Malformed(format!(
                "address payload must be 33 bytes, got {}",
                payload.len()
            )));
        }
        let is_mainnet = match hrp.as_str() {
            ADDRESS_HRP_MAINNET => true,
            ADDRESS_HRP_TESTNET => false,
            other => {
                return Err(DomError::Malformed(format!(
                    "unknown address HRP: {}",
                    other
                )))
            }
        };
        let mut arr = [0u8; 33];
        arr.copy_from_slice(&payload);
        Ok(Self {
            payload: arr,
            is_mainnet,
        })
    }

    /// Return the human-readable part for this address.
    pub fn hrp(&self) -> &str {
        if self.is_mainnet {
            ADDRESS_HRP_MAINNET
        } else {
            ADDRESS_HRP_TESTNET
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl std::str::FromStr for Address {
    type Err = DomError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode(s)
    }
}

// ── Bech32m internals ────────────────────────────────────────────────────────

/// Compute Bech32m checksum polymod.
fn polymod(values: &[u8]) -> u32 {
    let gen: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = ((chk >> 25) & 0xFF) as u8;
        chk = ((chk & 0x01ff_ffff).wrapping_shl(5)) ^ (v as u32);
        for (i, &g) in gen.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Build HRP expansion for checksum.
#[allow(clippy::arithmetic_side_effects)]
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(hrp.len() * 2 + 1);
    for c in hrp.bytes() {
        v.push(c >> 5);
    }
    v.push(0);
    for c in hrp.bytes() {
        v.push(c & 31);
    }
    v
}

/// Convert bytes to 5-bit groups.
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
fn to_5bit(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = acc.wrapping_shl(8) | b as u32;
        bits = bits.wrapping_add(8);
        while bits >= 5 {
            bits = bits.wrapping_sub(5);
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push((acc.wrapping_shl(5u32.wrapping_sub(bits)) & 31) as u8);
    }
    out
}

/// Convert 5-bit groups back to bytes.
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
fn from_5bit(data: &[u8]) -> Result<Vec<u8>, DomError> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        if b >= 32 {
            return Err(DomError::Malformed("invalid 5-bit value".into()));
        }
        acc = acc.wrapping_shl(5) | b as u32;
        bits = bits.wrapping_add(5);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            out.push((acc >> bits) as u8);
        }
    }
    // Remaining bits must be zero padding
    let mask = (1u32 << bits).wrapping_sub(1);
    if bits >= 5 || (acc & mask) != 0 {
        return Err(DomError::Malformed("invalid bech32 padding".into()));
    }
    Ok(out)
}

/// Encode data as Bech32m with given HRP.
#[allow(clippy::arithmetic_side_effects)]
fn bech32m_encode(hrp: &str, data: &[u8]) -> String {
    let mut values = hrp_expand(hrp);
    let data5 = to_5bit(data);
    values.extend_from_slice(&data5);
    values.extend_from_slice(&[0u8; 6]);
    let checksum = polymod(&values) ^ BECH32M_CONST;

    let mut out = String::with_capacity(hrp.len() + 1 + data5.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for &v in &data5 {
        out.push(CHARSET[v as usize] as char);
    }
    for i in 0u32..6 {
        let shift = 5u32.wrapping_mul(5u32.wrapping_sub(i));
        let idx = ((checksum >> shift) & 31) as usize;
        out.push(CHARSET[idx] as char);
    }
    out
}

/// Decode a Bech32m string into (hrp, data).
#[allow(clippy::arithmetic_side_effects)]
fn bech32m_decode(s: &str) -> Result<(String, Vec<u8>), DomError> {
    let sep = s
        .rfind('1')
        .ok_or_else(|| DomError::Malformed("no separator in address".into()))?;

    if sep == 0 {
        return Err(DomError::Malformed("empty HRP".into()));
    }
    if s.len() - sep - 1 < 6 {
        return Err(DomError::Malformed("address too short for checksum".into()));
    }

    let hrp = &s[..sep];
    let data_str = &s[sep + 1..];

    // Decode each character to 5-bit value
    let mut values = Vec::with_capacity(data_str.len());
    for c in data_str.bytes() {
        if c >= 128 {
            return Err(DomError::Malformed("non-ASCII in address".into()));
        }
        let v = CHARSET_REV[c as usize];
        if v == 0xFF {
            return Err(DomError::Malformed(format!(
                "invalid character {} in address",
                c as char
            )));
        }
        values.push(v);
    }

    // Verify checksum
    let mut check_input = hrp_expand(hrp);
    check_input.extend_from_slice(&values);
    if polymod(&check_input) != BECH32M_CONST {
        return Err(DomError::Malformed("invalid bech32m checksum".into()));
    }

    // Decode data (strip 6-char checksum)
    let payload5 = &values[..values.len() - 6];
    let payload = from_5bit(payload5)?;

    Ok((hrp.to_string(), payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip_mainnet() {
        let payload = [0x02u8; 33];
        let addr = Address::new(payload, true);
        let encoded = addr.encode();
        assert!(encoded.starts_with("dom1"));
        let decoded = Address::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, payload);
        assert!(decoded.is_mainnet);
    }

    #[test]
    fn encode_decode_roundtrip_testnet() {
        let payload = [0x03u8; 33];
        let addr = Address::new(payload, false);
        let encoded = addr.encode();
        assert!(encoded.starts_with("tdom1"));
        let decoded = Address::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, payload);
        assert!(!decoded.is_mainnet);
    }

    #[test]
    fn invalid_checksum_rejected() {
        let payload = [0x02u8; 33];
        let addr = Address::new(payload, true);
        let mut encoded = addr.encode();
        // Flip last char
        let last = encoded.pop().unwrap();
        encoded.push(if last == 'q' { 'p' } else { 'q' });
        assert!(Address::decode(&encoded).is_err());
    }

    #[test]
    fn wrong_hrp_rejected() {
        let payload = [0x02u8; 33];
        let addr = Address::new(payload, true);
        let encoded = addr.encode();
        // Swap hrp
        let wrong = encoded.replace("dom1", "btc1");
        assert!(Address::decode(&wrong).is_err());
    }

    #[test]
    fn display_and_fromstr() {
        let payload = [0x02u8; 33];
        let addr = Address::new(payload, true);
        let s = addr.to_string();
        let parsed: Address = s.parse().unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn address_is_33_bytes() {
        // 32-byte payload should fail
        let s = bech32m_encode("dom", &[0x02u8; 32]);
        let result = Address::decode(&s);
        assert!(result.is_err());
    }
}

// ── dom-shield: bech32m PRIMITIVE test families ───────────────────────────────
//
// These exercise the private bech32m codec (`bech32m_decode` / `from_5bit`)
// directly, independent of the 33-byte `Address` envelope, which the
// integration-test layer (tests/*.rs) cannot reach. Subfamilies:
//   - KAV-conformância : BIP-350 authoritative valid vectors (checksum const).
//   - KAV-negativo     : BIP-350 invalid vectors (bad checksum / charset / sep);
//                        from_5bit non-canonical-padding rejection.
//   - XDIFF            : DOM primitive vs the `bech32` reference crate.
// No production logic is touched. Compiled out of non-test builds.
#[cfg(test)]
mod shield_bech32m {
    use super::*;

    /// KAV-conformância. Authoritative BIP-350 VALID bech32m strings (sourced
    /// from the BIP-350 spec test-vector list, NOT from this code's output).
    /// DOM's `bech32m_decode` verifies the polymod equals `BECH32M_CONST`; every
    /// spec-valid string must therefore pass the checksum stage. (Some have
    /// non-byte-aligned data that `from_5bit` legitimately rejects as padding —
    /// so we assert at the checksum boundary, which is the BIP-350 invariant
    /// under test here.) Each vector is independently confirmed valid by the
    /// external `bech32` reference crate so the expectation is not self-defined.
    #[test]
    fn bip350_valid_vectors_pass_checksum() {
        // BIP-350 authoritative VALID bech32m strings. Each is independently
        // confirmed by the reference `bech32` crate below before DOM is asserted
        // against it, so the expectation is externally anchored, not self-defined.
        const VALID: &[&str] = &[
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "?1v759aa",
        ];
        for s in VALID {
            // Independent authority: the reference crate accepts it as bech32m.
            assert!(
                bech32::decode(s).is_ok(),
                "reference crate must accept BIP-350 valid vector {s}"
            );

            // DOM's checksum stage, over the single-case (lowered) form, must
            // satisfy the bech32m constant. BIP-350 checksum is case-folded.
            let lower = s.to_lowercase();
            let sep = lower.rfind('1').expect("vector has separator");
            let hrp = &lower[..sep];
            let data_str = &lower[sep + 1..];
            let mut values = Vec::with_capacity(data_str.len());
            for c in data_str.bytes() {
                let v = CHARSET_REV[c as usize];
                assert_ne!(v, 0xFF, "vector {s} has out-of-charset char");
                values.push(v);
            }
            let mut chk_in = hrp_expand(hrp);
            chk_in.extend_from_slice(&values);
            assert_eq!(
                polymod(&chk_in),
                BECH32M_CONST,
                "BIP-350 valid vector {s} must satisfy the bech32m checksum"
            );
        }
    }

    /// KAV-negativo. Authoritative BIP-350 INVALID bech32m strings. Each must be
    /// rejected by `bech32m_decode` (after the same lowercasing the production
    /// `Address::decode` applies). Reasons: HRP char out of range, bad checksum,
    /// invalid data character, or no/empty separator.
    #[test]
    fn bip350_invalid_vectors_rejected() {
        // Invalidity that manifests at the bech32m PRIMITIVE level (bad checksum,
        // out-of-charset data char, no separator, empty HRP) — i.e. independent
        // of the `Address` envelope's separate length / payload-size checks, and
        // surviving the lowercasing that production `Address::decode` applies.
        const INVALID: &[&str] = &[
            // valid charset but checksum does not satisfy bech32m constant
            "a1lqfn3b",
            // invalid data character 'b' (not in bech32 charset) after lowering
            "abcdef1b7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            // invalid data character 'i'
            "abcdef1i7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            // no separator '1' at all
            "abcdefghijklmnop",
            // empty HRP (separator at index 0)
            "1lqfn3a",
            // data part shorter than the 6-char checksum
            "dom1qqq",
        ];
        for s in INVALID {
            let lower = s.to_lowercase();
            assert!(
                bech32m_decode(&lower).is_err(),
                "invalid bech32m primitive vector {s} (lowered: {lower}) must be rejected"
            );
            // Cross-anchor: the reference crate must also reject it as bech32m.
            assert!(
                bech32::decode(&lower).is_err(),
                "reference crate must also reject {s}"
            );
        }
    }

    /// KAV-negativo (padding). `from_5bit` MUST reject non-canonical trailing
    /// padding: leftover high bits that are non-zero, or >= 5 leftover bits.
    /// Construct a 5-bit group sequence whose final partial group carries a
    /// non-zero pad bit and assert rejection; assert a clean-padded counterpart
    /// is accepted.
    #[test]
    fn from_5bit_rejects_noncanonical_padding() {
        // One 5-bit symbol => 5 bits, < 8, so no byte emitted; leftover 5 bits.
        // bits == 5 triggers the `bits >= 5` rejection branch regardless of value.
        assert!(
            from_5bit(&[0b00001]).is_err(),
            "5 leftover bits must be rejected as invalid padding"
        );
        // Two symbols => 10 bits => 1 byte + 2 leftover bits. If those 2 bits
        // are non-zero, it is non-canonical padding and must be rejected.
        // symbols: 0b00001, 0b00011 -> acc bits: 0000100011 -> byte 0x11, rem 0b11
        assert!(
            from_5bit(&[0b00001, 0b00011]).is_err(),
            "non-zero trailing pad bits must be rejected"
        );
        // Canonical counterpart: two symbols with zero leftover -> accepted.
        // 0b00001, 0b00000 -> byte 0x10, rem 0b00 -> ok
        assert!(
            from_5bit(&[0b00001, 0b00000]).is_ok(),
            "zero-padded byte-aligned-remainder must be accepted"
        );
        // Out-of-range 5-bit value (>=32) must be rejected.
        assert!(
            from_5bit(&[32]).is_err(),
            "5-bit value >= 32 must be rejected"
        );
    }

    /// XDIFF. DOM's hand-rolled bech32m vs the external `bech32` reference crate
    /// over many random payloads/HRPs. Any divergence in the produced string is
    /// an address-misdirection (funds) bug. We compare DOM `bech32m_encode`
    /// against `bech32::encode::<Bech32m>` for identical (hrp, data).
    #[test]
    fn xdiff_encode_matches_bech32_crate() {
        use bech32::{Bech32m, Hrp};

        // Deterministic LCG so the test is reproducible without a rng dev-dep.
        let mut state: u64 = 0x0123_4567_89ab_cdef;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };

        let hrps = ["dom", "tdom", "bc", "tb", "abcdef"];
        for hrp_s in hrps {
            let hrp = Hrp::parse(hrp_s).expect("valid hrp");
            for _ in 0..200 {
                let len = (next() % 40) as usize; // 0..=39 bytes
                let data: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();

                let dom_out = bech32m_encode(hrp_s, &data);
                let reference =
                    bech32::encode::<Bech32m>(hrp, &data).expect("reference encode must succeed");

                assert_eq!(
                    dom_out, reference,
                    "XDIFF encode divergence for hrp={hrp_s} data={data:02x?}"
                );
            }
        }
    }

    /// XDIFF (decode direction). For random byte payloads, DOM's full
    /// encode→decode of the raw primitive must agree with the reference crate's
    /// decode of DOM's output: same hrp, same recovered data bytes. Catches a
    /// decoder that disagrees with the reference on what a string means.
    #[test]
    fn xdiff_decode_matches_bech32_crate() {
        use bech32::Hrp;

        let mut state: u64 = 0xdead_beef_cafe_f00d;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };

        for hrp_s in ["dom", "tdom", "abcdef"] {
            let _ = Hrp::parse(hrp_s).expect("valid hrp");
            for _ in 0..200 {
                let len = (next() % 40) as usize;
                let data: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();

                let s = bech32m_encode(hrp_s, &data);

                // DOM decode of its own output.
                let (dom_hrp, dom_data) =
                    bech32m_decode(&s).expect("DOM must decode its own output");

                // Reference decode of the SAME string.
                let (ref_hrp, ref_data) =
                    bech32::decode(&s).expect("reference must decode DOM output");

                assert_eq!(dom_hrp, ref_hrp.as_str(), "XDIFF hrp divergence for {s}");
                assert_eq!(dom_data, ref_data, "XDIFF data divergence for {s}");
            }
        }
    }
}
