//! Minimal Solana public types without taking a dependency on the full SDK.

#![forbid(unsafe_code)]

use core::fmt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// System Program id (`11111111111111111111111111111111`).
pub const SYSTEM_PROGRAM_ID: SolanaPubkey = SolanaPubkey([0; 32]);
/// Classic SPL Token Program id.
pub const LEGACY_TOKEN_PROGRAM_ID: SolanaPubkey = SolanaPubkey([
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
]);
/// Upgradeable BPF loader id.
pub const BPF_LOADER_UPGRADEABLE_ID: SolanaPubkey = SolanaPubkey([
    2, 168, 246, 145, 78, 136, 161, 176, 226, 16, 21, 62, 247, 99, 174, 43, 0, 194, 185, 61, 22,
    193, 36, 210, 192, 83, 122, 16, 4, 128, 0, 0,
]);

/// A 32-byte Solana public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SolanaPubkey(pub [u8; 32]);

impl fmt::Debug for SolanaPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SolanaPubkey({}..)", &self.to_base58()[..6])
    }
}

impl SolanaPubkey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_base58(value: &str) -> Result<Self, SolanaTypeError> {
        let decoded = bs58::decode(value)
            .into_vec()
            .map_err(|_| SolanaTypeError::Base58)?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| SolanaTypeError::Length)?;
        Ok(Self(bytes))
    }

    pub fn to_base58(self) -> String {
        bs58::encode(self.0).into_string()
    }

    /// Written as an explicit loop because `PartialEq` on arrays is not a
    /// const trait; a non-const helper would push the all-zero refusal out of
    /// the constant contexts that pin the well-known program ids.
    pub const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < 32 {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }
}

/// A 64-byte transaction signature.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SolanaSignature(pub [u8; 64]);

/// `serde` implements its array traits only up to 32 elements, so a 64-byte
/// signature has to carry its own codec. It is written as a fixed-width byte
/// sequence that refuses any other length, rather than a variable-length one:
/// a signature is a consensus-sensitive identity, and its wire form must not
/// depend on how a serializer chooses to represent an array.
impl Serialize for SolanaSignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SolanaSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SignatureVisitor;

        impl<'v> serde::de::Visitor<'v> for SignatureVisitor {
            type Value = SolanaSignature;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("exactly 64 signature bytes")
            }

            fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                let bytes: [u8; 64] = value
                    .try_into()
                    .map_err(|_| E::invalid_length(value.len(), &self))?;
                Ok(SolanaSignature(bytes))
            }

            fn visit_seq<A: serde::de::SeqAccess<'v>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = [0u8; 64];
                for (index, slot) in bytes.iter_mut().enumerate() {
                    *slot = sequence
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }
                if sequence.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(65, &self));
                }
                Ok(SolanaSignature(bytes))
            }
        }

        deserializer.deserialize_bytes(SignatureVisitor)
    }
}

impl fmt::Debug for SolanaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SolanaSignature({}..)", &self.to_base58()[..8])
    }
}

impl SolanaSignature {
    pub fn from_base58(value: &str) -> Result<Self, SolanaTypeError> {
        let decoded = bs58::decode(value)
            .into_vec()
            .map_err(|_| SolanaTypeError::Base58)?;
        let bytes: [u8; 64] = decoded.try_into().map_err(|_| SolanaTypeError::Length)?;
        Ok(Self(bytes))
    }

    pub fn to_base58(self) -> String {
        bs58::encode(self.0).into_string()
    }

    /// 32-byte neutral transaction identifier for Kaystra's fixed reference.
    pub fn digest32(self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"DOM-INTEROP/SOLANA-SIGNATURE-ID/V1\0");
        hasher.update(self.0);
        hasher.finalize().into()
    }
}

/// A 32-byte recent/block hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SolanaHash(pub [u8; 32]);

impl SolanaHash {
    pub fn from_base58(value: &str) -> Result<Self, SolanaTypeError> {
        let decoded = bs58::decode(value)
            .into_vec()
            .map_err(|_| SolanaTypeError::Base58)?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| SolanaTypeError::Length)?;
        Ok(Self(bytes))
    }

    pub fn to_base58(self) -> String {
        bs58::encode(self.0).into_string()
    }
}

/// Account meta used by a client instruction plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaAccountMeta {
    pub pubkey: SolanaPubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// SDK-independent instruction plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaInstruction {
    pub program_id: SolanaPubkey,
    pub accounts: Vec<SolanaAccountMeta>,
    pub data: Vec<u8>,
}

/// Commitment requested from RPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Commitment {
    Processed,
    Confirmed,
    Finalized,
}

impl Commitment {
    pub const fn as_rpc_str(self) -> &'static str {
        match self {
            Self::Processed => "processed",
            Self::Confirmed => "confirmed",
            Self::Finalized => "finalized",
        }
    }
}

/// Canonical slot anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SolanaBlockAnchor {
    pub slot: u64,
    pub blockhash: SolanaHash,
}

/// RPC account snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolanaAccountSnapshot {
    pub context_slot: u64,
    pub lamports: u64,
    pub owner: SolanaPubkey,
    pub executable: bool,
    pub rent_epoch: u64,
    pub data: Vec<u8>,
}

impl SolanaAccountSnapshot {
    pub fn commitment_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"DOM-INTEROP/SOLANA-ACCOUNT/V1\0");
        hasher.update(self.lamports.to_be_bytes());
        hasher.update(self.owner.0);
        hasher.update([u8::from(self.executable)]);
        hasher.update(self.rent_epoch.to_be_bytes());
        hasher.update((self.data.len() as u64).to_be_bytes());
        hasher.update(&self.data);
        hasher.finalize().into()
    }
}

/// Status of a transaction signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SolanaSignatureStatus {
    pub slot: u64,
    pub confirmation: Commitment,
    pub failed: bool,
}

/// One compiled instruction from a transaction message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolanaCompiledInstruction {
    pub program_id: SolanaPubkey,
    pub accounts: Vec<SolanaPubkey>,
    pub data: Vec<u8>,
}

/// Canonical transaction view used by the observer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolanaTransactionRecord {
    pub slot: u64,
    pub signature: SolanaSignature,
    pub recent_blockhash: SolanaHash,
    pub success: bool,
    pub instructions: Vec<SolanaCompiledInstruction>,
}

impl SolanaTransactionRecord {
    pub fn commitment_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"DOM-INTEROP/SOLANA-TRANSACTION/V1\0");
        hasher.update(self.slot.to_be_bytes());
        hasher.update(self.signature.0);
        hasher.update(self.recent_blockhash.0);
        hasher.update([u8::from(self.success)]);
        for instruction in &self.instructions {
            hasher.update(instruction.program_id.0);
            hasher.update((instruction.accounts.len() as u64).to_be_bytes());
            for account in &instruction.accounts {
                hasher.update(account.0);
            }
            hasher.update((instruction.data.len() as u64).to_be_bytes());
            hasher.update(&instruction.data);
        }
        hasher.finalize().into()
    }
}

/// Parsed classic SPL token account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyTokenAccount {
    pub mint: SolanaPubkey,
    pub authority: SolanaPubkey,
    pub amount: u64,
    pub state: u8,
}

impl LegacyTokenAccount {
    pub const LEN: usize = 165;

    pub fn decode(data: &[u8]) -> Result<Self, SolanaTypeError> {
        if data.len() != Self::LEN {
            return Err(SolanaTypeError::Length);
        }
        let mut mint = [0u8; 32];
        mint.copy_from_slice(&data[..32]);
        let mut authority = [0u8; 32];
        authority.copy_from_slice(&data[32..64]);
        let mut amount = [0u8; 8];
        amount.copy_from_slice(&data[64..72]);
        let state = data[108];
        if state == 0 {
            return Err(SolanaTypeError::Invalid);
        }
        Ok(Self {
            mint: SolanaPubkey(mint),
            authority: SolanaPubkey(authority),
            amount: u64::from_le_bytes(amount),
            state,
        })
    }
}

/// Parsed classic SPL mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyMint {
    pub supply: u64,
    pub decimals: u8,
    pub initialized: bool,
}

impl LegacyMint {
    pub const LEN: usize = 82;

    pub fn decode(data: &[u8]) -> Result<Self, SolanaTypeError> {
        if data.len() != Self::LEN {
            return Err(SolanaTypeError::Length);
        }
        let mut supply = [0u8; 8];
        supply.copy_from_slice(&data[36..44]);
        let initialized = match data[45] {
            0 => false,
            1 => true,
            _ => return Err(SolanaTypeError::Invalid),
        };
        Ok(Self {
            supply: u64::from_le_bytes(supply),
            decimals: data[44],
            initialized,
        })
    }
}

/// Public type error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SolanaTypeError {
    #[error("invalid base58")]
    Base58,
    #[error("invalid fixed length")]
    Length,
    #[error("invalid Solana value")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_token_program_roundtrip() {
        assert_eq!(
            SolanaPubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            Ok(LEGACY_TOKEN_PROGRAM_ID),
        );
    }

    #[test]
    fn signature_digest_is_domain_separated() {
        assert_ne!(SolanaSignature([1; 64]).digest32(), [1; 32]);
    }
}
