//! HD Wallet key derivation for DOM Protocol.
//!
//! Implements BIP-32 hierarchical deterministic key derivation adapted
//! for Mimblewimble/secp256k1. Derives blinding factors for outputs
//! from a master seed.
//!
//! Derivation path convention (BIP-44 style):
//!   m / purpose' / coin_type' / account' / change / index
//!
//! DOM coin type: 330 (matching DOM's 330,000 block halving interval)

use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, SecretKey};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

/// DOM BIP-44 coin type.
pub const DOM_COIN_TYPE: u32 = 330;

/// BIP-32 hardened key offset.
pub const HARDENED_OFFSET: u32 = 0x8000_0000;

/// Errors from HD derivation.
#[derive(Debug, thiserror::Error)]
pub enum HdError {
    /// Invalid seed length (must be 16-64 bytes).
    #[error("invalid seed length: {0}")]
    InvalidSeedLength(usize),

    /// Key derivation produced an invalid scalar.
    #[error("invalid derived key (retry with next index)")]
    InvalidKey,

    /// Derivation path is invalid.
    #[error("invalid derivation path: {0}")]
    InvalidPath(String),
}

/// An extended private key node in the HD tree.
#[derive(Clone)]
pub struct ExtendedPrivKey {
    /// 32-byte private key (secp256k1 scalar).
    key: Zeroizing<[u8; 32]>,
    /// 32-byte chain code.
    chain_code: [u8; 32],
    /// Depth in the tree (0 = master).
    pub depth: u8,
    /// Child index at this level.
    pub index: u32,
}

impl Zeroize for ExtendedPrivKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.chain_code.zeroize();
    }
}

impl Drop for ExtendedPrivKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ExtendedPrivKey {
    /// Derive master key from seed bytes (BIP-32).
    ///
    /// `seed` must be 16-64 bytes (typically 64 from BIP-39 PBKDF2).
    pub fn from_seed(seed: &[u8]) -> Result<Self, HdError> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(HdError::InvalidSeedLength(seed.len()));
        }
        type HmacSha512 = Hmac<Sha512>;
        let mut mac =
            HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC can take key of any size");
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        // BIP-32: the master key is invalid if IL == 0 or IL >= n. `from_slice`
        // rejects both; if invalid the seed must be discarded (we surface it).
        SecretKey::from_slice(&key).map_err(|_| HdError::InvalidKey)?;

        Ok(Self {
            key: Zeroizing::new(key),
            chain_code,
            depth: 0,
            index: 0,
        })
    }

    /// Derive a child key at given index.
    pub fn child(&self, index: u32) -> Result<Self, HdError> {
        // Parent private key as a validated secp256k1 scalar (BIP-32 requires
        // kpar < n; from_slice enforces it).
        let parent_sk =
            SecretKey::from_slice(self.key.as_ref()).map_err(|_| HdError::InvalidKey)?;

        type HmacSha512 = Hmac<Sha512>;
        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).expect("HMAC can take key of any size");

        if index >= HARDENED_OFFSET {
            // Hardened: data = 0x00 || ser256(kpar) || ser32(i)
            mac.update(&[0x00]);
            mac.update(self.key.as_ref());
        } else {
            // Non-hardened: data = serP(point(kpar)) || ser32(i)
            // serP = 33-byte compressed public key of the parent.
            let parent_pk = PublicKey::from_secret_key_global(&parent_sk);
            mac.update(&parent_pk.serialize());
        }
        mac.update(&index.to_be_bytes());

        let result = mac.finalize().into_bytes();

        let mut il = [0u8; 32];
        il.copy_from_slice(&result[..32]);

        // ki = (IL + kpar) mod n. `Scalar::from_be_bytes` rejects IL >= n; the
        // tweak-add rejects a zero result. Both are the BIP-32 "invalid index"
        // cases (caller should advance the index; here we surface InvalidKey).
        let tweak = Scalar::from_be_bytes(il).map_err(|_| HdError::InvalidKey)?;
        let child_key = parent_sk
            .add_tweak(&tweak)
            .map_err(|_| HdError::InvalidKey)?
            .secret_bytes();

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&result[32..]);

        Ok(Self {
            key: Zeroizing::new(child_key),
            chain_code,
            depth: self.depth.saturating_add(1),
            index,
        })
    }

    /// Derive key at a path string.
    ///
    /// Example: "m/44'/330'/0'/0/0"
    pub fn derive_path(&self, path: &str) -> Result<Self, HdError> {
        let path = path.trim_start_matches("m/");
        if path.is_empty() {
            return Ok(self.clone());
        }

        let mut current = self.clone();
        for component in path.split('/') {
            let (index_str, hardened) = if let Some(s) = component.strip_suffix('\'') {
                (s, true)
            } else {
                (component, false)
            };

            let index: u32 = index_str
                .parse()
                .map_err(|_| HdError::InvalidPath(format!("bad index: {}", component)))?;

            let child_index = if hardened {
                index
                    .checked_add(HARDENED_OFFSET)
                    .ok_or(HdError::InvalidKey)?
            } else {
                index
            };

            current = current.child(child_index)?;
        }
        Ok(current)
    }

    /// Derive a blinding factor for a specific output.
    ///
    /// Path: m/44'/330'/account'/change/index
    pub fn derive_blinding(
        &self,
        account: u32,
        change: u32,
        index: u32,
    ) -> Result<Zeroizing<[u8; 32]>, HdError> {
        // Build path: m/44'/330'/account'/change/index
        let path = format!(
            "m/44'/{}'/{}'/{}/{}",
            DOM_COIN_TYPE, account, change, index,
        );
        let child = self.derive_path(&path)?;
        Ok(child.key.clone())
    }

    /// Get the raw key bytes (for use as blinding factor).
    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Get the 32-byte chain code (BIP-32). Exposed for HD interop checks
    /// (e.g. validating derivation against external BIP-32 test vectors).
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> Vec<u8> {
        vec![0x5eu8; 64]
    }

    #[test]
    fn master_key_from_seed() {
        let master = ExtendedPrivKey::from_seed(&test_seed()).unwrap();
        assert_eq!(master.depth, 0);
        assert_ne!(*master.key_bytes(), [0u8; 32]);
    }

    #[test]
    fn deterministic_derivation() {
        let m1 = ExtendedPrivKey::from_seed(&test_seed()).unwrap();
        let m2 = ExtendedPrivKey::from_seed(&test_seed()).unwrap();
        assert_eq!(
            m1.child(0).unwrap().key_bytes(),
            m2.child(0).unwrap().key_bytes()
        );
    }

    #[test]
    fn different_indices_give_different_keys() {
        let master = ExtendedPrivKey::from_seed(&test_seed()).unwrap();
        let c0 = master.child(0).unwrap();
        let c1 = master.child(1).unwrap();
        assert_ne!(c0.key_bytes(), c1.key_bytes());
    }

    #[test]
    fn hardened_differs_from_normal() {
        let master = ExtendedPrivKey::from_seed(&test_seed()).unwrap();
        let normal = master.child(0).unwrap();
        let hardened = master.child(HARDENED_OFFSET).unwrap();
        assert_ne!(normal.key_bytes(), hardened.key_bytes());
    }

    #[test]
    fn path_derivation() {
        let master = ExtendedPrivKey::from_seed(&test_seed()).unwrap();
        let derived = master.derive_path("m/44'/330'/0'/0/0").unwrap();
        assert!(derived.depth > 0);
        assert_ne!(*derived.key_bytes(), [0u8; 32]);
    }

    #[test]
    fn invalid_seed_length() {
        assert!(ExtendedPrivKey::from_seed(&[0u8; 8]).is_err());
        assert!(ExtendedPrivKey::from_seed(&[0u8; 65]).is_err());
        assert!(ExtendedPrivKey::from_seed(&[0u8; 32]).is_ok());
    }

    #[test]
    fn depth_increments() {
        let master = ExtendedPrivKey::from_seed(&test_seed()).unwrap();
        let child = master.child(0).unwrap();
        assert_eq!(child.depth, 1);
        let grandchild = child.child(0).unwrap();
        assert_eq!(grandchild.depth, 2);
    }
}
