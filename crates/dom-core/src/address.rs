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
        Self { payload, is_mainnet }
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
        Ok(Self { payload: arr, is_mainnet })
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
    let gen: [u32; 5] = [
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3,
    ];
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
