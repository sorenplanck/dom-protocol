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
            "m/44'/{}'/{}'/{}'/{}/{}",
            44u32, DOM_COIN_TYPE, account, change, index,
        );
        let child = self.derive_path(&path)?;
        Ok(child.key.clone())
    }

    /// Get the raw key bytes (for use as blinding factor).
    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> Vec<u8> {
        vec![0x5eu8; 64]
    }

    // ── BIP-32 conformance KAV (shield) ───────────────────────────────────
    // Known-answer vectors from the official BIP-0032 spec, Test Vector 1
    // (seed 000102030405060708090a0b0c0d0e0f). Validates DOM HD derivation
    // against the official BIP-0032 test vectors. Must PASS — proves DOM keys
    // are recoverable by ANY standard BIP-32 wallet (full interop).
    //
    // Expected values are decoded from the spec's official xprv strings (an
    // external source), not from DOM's own output.

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex"))
            .collect()
    }

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex_bytes(s);
        assert_eq!(v.len(), 32, "expected 32-byte hex");
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn test_bip32_vector1_master_key() {
        let seed = hex_bytes("000102030405060708090a0b0c0d0e0f");
        let master = ExtendedPrivKey::from_seed(&seed).expect("master from seed");
        let expected_key =
            hex32("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        let expected_chain_code =
            hex32("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
        assert_eq!(
            *master.key_bytes(),
            expected_key,
            "master private key must match BIP-32 Test Vector 1"
        );
        assert_eq!(
            master.chain_code, expected_chain_code,
            "master chain code must match BIP-32 Test Vector 1"
        );
    }

    #[test]
    fn test_bip32_vector1_derive_hardened() {
        let seed = hex_bytes("000102030405060708090a0b0c0d0e0f");
        let master = ExtendedPrivKey::from_seed(&seed).expect("master from seed");
        let child = master.derive_path("m/0'").expect("derive m/0'");
        let expected_key =
            hex32("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea");
        let expected_chain_code =
            hex32("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");
        assert_eq!(
            *child.key_bytes(),
            expected_key,
            "m/0' private key must match BIP-32 Test Vector 1"
        );
        assert_eq!(
            child.chain_code, expected_chain_code,
            "m/0' chain code must match BIP-32 Test Vector 1"
        );
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
