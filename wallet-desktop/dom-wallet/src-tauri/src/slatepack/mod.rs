//! Slatepack (Mode A) — transport layer over the DOM `Slate`.
//!
//! Responsibilities (all transport; no Mimblewimble logic here):
//!   * Generate a per-transaction keypair backing both the `dom1…` address
//!     (x25519/bech32) and the encryption (x25519) — the same key.
//!   * Seal serialized slate bytes to a recipient address → BEGINDOMPACK string.
//!   * Open a BEGINDOMPACK string with our secret → slate bytes.
//!
//! The `Slate` itself (build/sign/finalize) is owned by the dom-wallet crate;
//! this module only moves its bytes around confidentially.
//!
//! Key model: we sample a 32-byte secret scalar and use it as an x25519
//! `StaticSecret`; the matching x25519 public key (Montgomery point) is what we
//! bech32-encode as the address. Encryption and address are therefore the same
//! key, so a recipient who publishes an address can always decrypt to it. (We
//! use the 32-byte x25519 public key as the address payload; the same key
//! performs the DH in encryption.rs, so a published address can always decrypt.)

pub mod address;
pub mod decode;
pub mod encode;
pub mod encryption;

use rand::RngCore;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

/// A per-transaction Slatepack keypair. The secret is zeroized on drop.
pub struct SlateKeypair {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl SlateKeypair {
    /// Generate a fresh keypair.
    pub fn generate() -> Self {
        let mut sk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sk);
        let secret = StaticSecret::from(sk);
        let public = XPublicKey::from(&secret);
        let pub_bytes = *public.as_bytes();
        // Re-wrap the raw secret in Zeroizing; clear the stack copy.
        let wrapped = Zeroizing::new(sk);
        SlateKeypair {
            secret: wrapped,
            public: pub_bytes,
        }
    }

    /// Rebuild from a stored 32-byte secret (e.g. from `v2-meta.json`).
    pub fn from_secret(secret: [u8; 32]) -> Self {
        let s = StaticSecret::from(secret);
        let public = *XPublicKey::from(&s).as_bytes();
        SlateKeypair {
            secret: Zeroizing::new(secret),
            public,
        }
    }

    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    /// This keypair's `dom1…` address for the given network.
    pub fn address(&self, network: &str) -> AppResult<String> {
        address::encode_address(&self.public, network)
    }
}

/// Seal serialized `slate_bytes` for `recipient_address`, producing a
/// BEGINDOMPACK envelope. Validates the address and (optionally) its network.
pub fn seal_slate_for(
    recipient_address: &str,
    expected_network: Option<&str>,
    slate_bytes: &[u8],
) -> AppResult<String> {
    let (hrp, recipient_pub) = address::decode_address(recipient_address)?;
    if let Some(net) = expected_network {
        if hrp != address::hrp_for_network(net) {
            return Err(AppError::Other(format!(
                "recipient address is for a different network ({hrp})"
            )));
        }
    }
    let sealed = encryption::seal(&recipient_pub, slate_bytes)?;
    Ok(encode::encode_envelope(&sealed))
}

/// Open a BEGINDOMPACK envelope addressed to `keypair`, returning slate bytes.
pub fn open_slate(keypair: &SlateKeypair, envelope: &str) -> AppResult<Zeroizing<Vec<u8>>> {
    let sealed = decode::decode_envelope(envelope)?;
    encryption::open(keypair.secret_bytes(), &sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_seal_open_cycle() {
        let recipient = SlateKeypair::generate();
        let addr = recipient.address("testnet").unwrap();

        let slate_bytes = b"serialized slate payload";
        let envelope = seal_slate_for(&addr, Some("testnet"), slate_bytes).unwrap();
        assert!(envelope.starts_with("BEGINDOMPACK."));

        let opened = open_slate(&recipient, &envelope).unwrap();
        assert_eq!(&opened[..], slate_bytes);
    }

    #[test]
    fn keypair_from_secret_is_stable() {
        let kp = SlateKeypair::generate();
        let rebuilt = SlateKeypair::from_secret(*kp.secret_bytes());
        assert_eq!(kp.public(), rebuilt.public());
    }

    #[test]
    fn rejects_cross_network_address() {
        let recipient = SlateKeypair::generate();
        let main_addr = recipient.address("mainnet").unwrap();
        let res = seal_slate_for(&main_addr, Some("testnet"), b"x");
        assert!(res.is_err());
    }
}
