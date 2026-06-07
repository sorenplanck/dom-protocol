//! Slatepack address: a bech32-encoded x25519 public key.
//!
//! A Slatepack address is **not** a blockchain address — no UTXOs are tied to
//! it. It is used only for slate exchange and encryption of the slate to the
//! recipient. The encoded payload is the 32-byte x25519 (Montgomery) public key
//! that also performs the Diffie-Hellman in `encryption.rs`, so the same key
//! both names the address and decrypts to it. (Earlier docs referred to
//! ed25519; the implementation uses x25519 throughout — corrected per audit
//! W-06. No ed25519↔x25519 conversion is performed.)
//!
//! Wallets generate a fresh address per transaction by default (privacy). Per
//! the brief, the HRP is network-scoped:
//!   * mainnet: `dom`
//!   * testnet: `domtest`
//!   * regtest: `domreg`
//!
//! We use the `bech32` crate directly here (rather than `dom_core::Address`,
//! whose HRPs `dom`/`tdom` are for on-chain addresses) because the Slatepack
//! address namespace is deliberately distinct.

use bech32::{Bech32m, Hrp};

use crate::error::{AppError, AppResult};

/// HRP for a given network string.
pub fn hrp_for_network(network: &str) -> &'static str {
    match network {
        "mainnet" => "dom",
        "regtest" => "domreg",
        _ => "domtest",
    }
}

/// Encode a 32-byte x25519 public key as a `dom1…` Slatepack address.
pub fn encode_address(pubkey: &[u8; 32], network: &str) -> AppResult<String> {
    let hrp = Hrp::parse(hrp_for_network(network))
        .map_err(|e| AppError::Other(format!("bad HRP: {e}")))?;
    bech32::encode::<Bech32m>(hrp, pubkey)
        .map_err(|e| AppError::Other(format!("address encode: {e}")))
}

/// Decode a `dom1…` Slatepack address into (hrp, 32-byte pubkey). Validates the
/// HRP belongs to the DOM Slatepack namespace and the payload is 32 bytes.
pub fn decode_address(addr: &str) -> AppResult<(String, [u8; 32])> {
    let (hrp, data) = bech32::decode(addr.trim())
        .map_err(|_| AppError::Other("not a valid DOM Slatepack address".into()))?;
    let hrp_str = hrp.as_str().to_string();
    if !matches!(hrp_str.as_str(), "dom" | "domtest" | "domreg") {
        return Err(AppError::Other(format!(
            "address HRP '{hrp_str}' is not a DOM Slatepack address"
        )));
    }
    if data.len() != 32 {
        return Err(AppError::Other(
            "Slatepack address payload must be 32 bytes".into(),
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data);
    Ok((hrp_str, key))
}

/// True if `addr` parses as a DOM Slatepack address.
pub fn is_valid_address(addr: &str) -> bool {
    decode_address(addr).is_ok()
}

/// Check that an address belongs to the expected network.
pub fn address_matches_network(addr: &str, network: &str) -> bool {
    match decode_address(addr) {
        Ok((hrp, _)) => hrp == hrp_for_network(network),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_address() {
        let key = [7u8; 32];
        for net in ["mainnet", "testnet", "regtest"] {
            let addr = encode_address(&key, net).unwrap();
            assert!(addr.starts_with(hrp_for_network(net)));
            let (hrp, decoded) = decode_address(&addr).unwrap();
            assert_eq!(hrp, hrp_for_network(net));
            assert_eq!(decoded, key);
            assert!(address_matches_network(&addr, net));
        }
    }

    #[test]
    fn deterministic_from_key() {
        let key = [42u8; 32];
        let a = encode_address(&key, "testnet").unwrap();
        let b = encode_address(&key, "testnet").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_garbage() {
        assert!(!is_valid_address("not an address"));
        assert!(decode_address("dom1qqqq").is_err());
    }

    #[test]
    fn rejects_wrong_network() {
        let addr = encode_address(&[1u8; 32], "mainnet").unwrap();
        assert!(!address_matches_network(&addr, "testnet"));
    }
}
