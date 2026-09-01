//! Conversion of finalized Solana evidence into Kaystra neutral records.

#![forbid(unsafe_code)]

use kaystra_core::{settlement_engine::ChainRecordV1, state::EvidenceRefV1, types::ChainId};
use solana_evidence::{
    SolanaClaimEvidenceV1, SolanaEvidenceBodyV1, SolanaEvidenceEnvelopeV1, SolanaFundingEvidenceV1,
    SolanaRefundEvidenceV1,
};

/// Record conversion error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// Chain id is zero.
    #[error("zero Solana chain id")]
    ZeroChainId,
    /// Evidence did not match the frozen setup.
    #[error("invalid Solana evidence")]
    InvalidEvidence,
}

/// Convert a funding envelope.
pub fn funding_record(
    chain_id: ChainId,
    evidence: &SolanaFundingEvidenceV1,
    expected_settlement: &[u8; 32],
    expected_terms: &[u8; 32],
) -> Result<ChainRecordV1, RecordError> {
    require_chain(chain_id)?;
    let envelope = SolanaEvidenceEnvelopeV1 {
        version: solana_evidence::EVIDENCE_VERSION,
        body: SolanaEvidenceBodyV1::Funding(evidence.clone()),
    };
    envelope
        .validate()
        .map_err(|_| RecordError::InvalidEvidence)?;
    envelope
        .require_binding(expected_settlement, expected_terms)
        .map_err(|_| RecordError::InvalidEvidence)?;
    Ok(ChainRecordV1::Funding {
        evidence: evidence_ref(
            chain_id,
            evidence.signature.digest32(),
            evidence.instruction_index,
            evidence.slot,
            evidence.blockhash.0,
        )?,
    })
}

/// Convert a claim envelope.
pub fn claim_record(
    chain_id: ChainId,
    evidence: &SolanaClaimEvidenceV1,
    expected_settlement: &[u8; 32],
    expected_terms: &[u8; 32],
) -> Result<ChainRecordV1, RecordError> {
    require_chain(chain_id)?;
    let envelope = SolanaEvidenceEnvelopeV1 {
        version: solana_evidence::EVIDENCE_VERSION,
        body: SolanaEvidenceBodyV1::Claim(evidence.clone()),
    };
    envelope
        .validate()
        .map_err(|_| RecordError::InvalidEvidence)?;
    envelope
        .require_binding(expected_settlement, expected_terms)
        .map_err(|_| RecordError::InvalidEvidence)?;
    Ok(ChainRecordV1::Claim {
        evidence: evidence_ref(
            chain_id,
            evidence.signature.digest32(),
            evidence.instruction_index,
            evidence.slot,
            evidence.blockhash.0,
        )?,
    })
}

/// Convert a refund envelope.
pub fn refund_record(
    chain_id: ChainId,
    evidence: &SolanaRefundEvidenceV1,
    expected_settlement: &[u8; 32],
    expected_terms: &[u8; 32],
) -> Result<ChainRecordV1, RecordError> {
    require_chain(chain_id)?;
    let envelope = SolanaEvidenceEnvelopeV1 {
        version: solana_evidence::EVIDENCE_VERSION,
        body: SolanaEvidenceBodyV1::Refund(evidence.clone()),
    };
    envelope
        .validate()
        .map_err(|_| RecordError::InvalidEvidence)?;
    envelope
        .require_binding(expected_settlement, expected_terms)
        .map_err(|_| RecordError::InvalidEvidence)?;
    Ok(ChainRecordV1::Refund {
        evidence: evidence_ref(
            chain_id,
            evidence.signature.digest32(),
            evidence.instruction_index,
            evidence.slot,
            evidence.blockhash.0,
        )?,
    })
}

/// Construct a neutral reorg record.
pub fn reorg_record(slot: u64, old_blockhash: [u8; 32]) -> Result<ChainRecordV1, RecordError> {
    if old_blockhash == [0; 32] {
        return Err(RecordError::InvalidEvidence);
    }
    Ok(ChainRecordV1::Reorg {
        from_height: slot,
        old_anchor: old_blockhash,
    })
}

fn require_chain(chain_id: ChainId) -> Result<(), RecordError> {
    if chain_id.0 == [0; 32] {
        Err(RecordError::ZeroChainId)
    } else {
        Ok(())
    }
}

fn evidence_ref(
    chain_id: ChainId,
    tx_id: [u8; 32],
    instruction_index: u16,
    slot: u64,
    blockhash: [u8; 32],
) -> Result<EvidenceRefV1, RecordError> {
    if tx_id == [0; 32] || blockhash == [0; 32] || slot == 0 {
        return Err(RecordError::InvalidEvidence);
    }
    Ok(EvidenceRefV1 {
        chain_id,
        tx_id,
        event_index: u32::from(instruction_index),
        block_height: slot,
        block_anchor: blockhash,
    })
}
