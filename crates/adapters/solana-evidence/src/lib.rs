//! Canonical finalized evidence for the DOM Solana leg.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_types::{SolanaHash, SolanaPubkey, SolanaSignature};

pub const EVIDENCE_VERSION: u16 = 1;
pub const MAX_EVIDENCE_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaFundingEvidenceV1 {
    pub settlement_id: [u8; 32],
    pub terms_hash: [u8; 32],
    pub program_id: SolanaPubkey,
    pub state_pda: SolanaPubkey,
    pub vault_pda: SolanaPubkey,
    pub signature: SolanaSignature,
    pub instruction_index: u16,
    pub slot: u64,
    pub blockhash: SolanaHash,
    pub amount: u64,
    pub mint: SolanaPubkey,
    pub state_hash: [u8; 32],
    pub vault_hash: [u8; 32],
    pub program_data_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaClaimEvidenceV1 {
    pub settlement_id: [u8; 32],
    pub terms_hash: [u8; 32],
    pub program_id: SolanaPubkey,
    pub state_pda: SolanaPubkey,
    pub vault_pda: SolanaPubkey,
    pub signature: SolanaSignature,
    pub instruction_index: u16,
    pub slot: u64,
    pub blockhash: SolanaHash,
    pub amount: u64,
    pub mint: SolanaPubkey,
    pub revealed_secret_be: [u8; 32],
    pub terminal_state_hash: [u8; 32],
    pub vault_hash: [u8; 32],
    pub program_data_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaRefundEvidenceV1 {
    pub settlement_id: [u8; 32],
    pub terms_hash: [u8; 32],
    pub program_id: SolanaPubkey,
    pub state_pda: SolanaPubkey,
    pub vault_pda: SolanaPubkey,
    pub signature: SolanaSignature,
    pub instruction_index: u16,
    pub slot: u64,
    pub blockhash: SolanaHash,
    pub amount: u64,
    pub mint: SolanaPubkey,
    pub terminal_state_hash: [u8; 32],
    pub vault_hash: [u8; 32],
    pub program_data_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SolanaEvidenceBodyV1 {
    Funding(SolanaFundingEvidenceV1),
    Claim(SolanaClaimEvidenceV1),
    Refund(SolanaRefundEvidenceV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaEvidenceEnvelopeV1 {
    pub version: u16,
    pub body: SolanaEvidenceBodyV1,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    #[error("invalid evidence field")]
    Invalid,
    #[error("settlement/terms binding mismatch")]
    BindingMismatch,
    #[error("evidence wire version mismatch")]
    VersionMismatch,
    #[error("evidence exceeds bound")]
    BoundsExceeded,
    #[error("malformed or noncanonical evidence")]
    Malformed,
}

impl SolanaEvidenceEnvelopeV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EvidenceError> {
        if self.version != EVIDENCE_VERSION {
            return Err(EvidenceError::VersionMismatch);
        }
        self.validate()?;
        let bytes = bincode::serialize(self).map_err(|_| EvidenceError::Malformed)?;
        if bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(EvidenceError::BoundsExceeded);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EvidenceError> {
        if bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(EvidenceError::BoundsExceeded);
        }
        let value: Self = bincode::deserialize(bytes).map_err(|_| EvidenceError::Malformed)?;
        if value.encode()?.as_slice() != bytes {
            return Err(EvidenceError::Malformed);
        }
        Ok(value)
    }

    pub fn evidence_id(&self) -> Result<[u8; 32], EvidenceError> {
        let bytes = self.encode()?;
        let mut hasher = Sha256::new();
        hasher.update(b"DOM-INTEROP/SOLANA-EVIDENCE/V1\0");
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }

    pub fn validate(&self) -> Result<(), EvidenceError> {
        let common = match &self.body {
            SolanaEvidenceBodyV1::Funding(v) => (
                &v.settlement_id,
                &v.terms_hash,
                v.program_id,
                v.state_pda,
                v.vault_pda,
                v.signature,
                v.slot,
                v.blockhash,
                v.amount,
                v.state_hash,
                v.program_data_hash,
            ),
            SolanaEvidenceBodyV1::Claim(v) => {
                if v.revealed_secret_be == [0; 32] {
                    return Err(EvidenceError::Invalid);
                }
                (
                    &v.settlement_id,
                    &v.terms_hash,
                    v.program_id,
                    v.state_pda,
                    v.vault_pda,
                    v.signature,
                    v.slot,
                    v.blockhash,
                    v.amount,
                    v.terminal_state_hash,
                    v.program_data_hash,
                )
            }
            SolanaEvidenceBodyV1::Refund(v) => (
                &v.settlement_id,
                &v.terms_hash,
                v.program_id,
                v.state_pda,
                v.vault_pda,
                v.signature,
                v.slot,
                v.blockhash,
                v.amount,
                v.terminal_state_hash,
                v.program_data_hash,
            ),
        };
        if common.0 == &[0; 32]
            || common.1 == &[0; 32]
            || common.2.is_zero()
            || common.3.is_zero()
            || common.4.is_zero()
            || common.5 .0 == [0; 64]
            || common.6 == 0
            || common.7 .0 == [0; 32]
            || common.8 == 0
            || common.9 == [0; 32]
            || common.10 == [0; 32]
        {
            return Err(EvidenceError::Invalid);
        }
        Ok(())
    }

    pub fn require_binding(
        &self,
        settlement: &[u8; 32],
        terms: &[u8; 32],
    ) -> Result<(), EvidenceError> {
        let (actual_settlement, actual_terms) = match &self.body {
            SolanaEvidenceBodyV1::Funding(v) => (&v.settlement_id, &v.terms_hash),
            SolanaEvidenceBodyV1::Claim(v) => (&v.settlement_id, &v.terms_hash),
            SolanaEvidenceBodyV1::Refund(v) => (&v.settlement_id, &v.terms_hash),
        };
        if actual_settlement != settlement || actual_terms != terms {
            return Err(EvidenceError::BindingMismatch);
        }
        Ok(())
    }
}
