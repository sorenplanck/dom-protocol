//! Conversion of fully verified XMR evidence into Kaystra neutral records.

#![forbid(unsafe_code)]

use kaystra_core::{settlement_engine::ChainRecordV1, state::EvidenceRefV1, types::ChainId};
use xmr_evidence::{XmrFundingEvidenceV2, XmrRefundEvidenceV2, XmrSpendEvidenceV2};

/// Record conversion failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// Chain id is zero.
    #[error("zero XMR chain id")]
    ZeroChainId,
    /// Evidence or one of its frozen bindings is invalid.
    #[error("invalid XMR evidence")]
    InvalidEvidence,
}

/// Converts final funding evidence.
pub fn funding_record(
    chain_id: ChainId,
    evidence: &XmrFundingEvidenceV2,
    expected_settlement: &[u8; 32],
    expected_terms_hash: &[u8; 32],
    expected_amount: u64,
    expected_destination_commitment: &[u8; 32],
    min_confirmations: u32,
) -> Result<ChainRecordV1, RecordError> {
    require_chain(chain_id)?;
    evidence
        .validate(min_confirmations)
        .map_err(|_| RecordError::InvalidEvidence)?;
    evidence
        .require_binding(expected_settlement, expected_terms_hash)
        .map_err(|_| RecordError::InvalidEvidence)?;
    if evidence.amount_piconero != expected_amount
        || &evidence.destination_commitment != expected_destination_commitment
    {
        return Err(RecordError::InvalidEvidence);
    }
    Ok(ChainRecordV1::Funding {
        evidence: evidence_ref(
            chain_id,
            evidence.tx_hash,
            evidence.output_index,
            evidence.block_height,
            evidence.block_hash,
        )?,
    })
}

/// Converts final XMR sweep evidence into Kaystra's claim record.
pub fn spend_claim_record(
    chain_id: ChainId,
    evidence: &XmrSpendEvidenceV2,
    expected_settlement: &[u8; 32],
    expected_terms_hash: &[u8; 32],
    expected_funding_tx: &[u8; 32],
    min_confirmations: u32,
) -> Result<ChainRecordV1, RecordError> {
    require_chain(chain_id)?;
    evidence
        .validate(
            expected_settlement,
            expected_terms_hash,
            expected_funding_tx,
            min_confirmations,
        )
        .map_err(|_| RecordError::InvalidEvidence)?;
    Ok(ChainRecordV1::Claim {
        evidence: evidence_ref(
            chain_id,
            evidence.spending_tx_hash,
            0,
            evidence.block_height,
            evidence.block_hash,
        )?,
    })
}

/// Converts final refund evidence.
pub fn refund_record(
    chain_id: ChainId,
    evidence: &XmrRefundEvidenceV2,
    expected_settlement: &[u8; 32],
    expected_terms_hash: &[u8; 32],
    expected_funding_tx: &[u8; 32],
    min_confirmations: u32,
) -> Result<ChainRecordV1, RecordError> {
    require_chain(chain_id)?;
    evidence
        .validate(
            expected_settlement,
            expected_terms_hash,
            expected_funding_tx,
            min_confirmations,
        )
        .map_err(|_| RecordError::InvalidEvidence)?;
    Ok(ChainRecordV1::Refund {
        evidence: evidence_ref(
            chain_id,
            evidence.refund_tx_hash,
            0,
            evidence.block_height,
            evidence.block_hash,
        )?,
    })
}

/// Constructs a reorg record.
pub fn reorg_record(from_height: u64, old_anchor: [u8; 32]) -> Result<ChainRecordV1, RecordError> {
    if old_anchor == [0; 32] {
        return Err(RecordError::InvalidEvidence);
    }
    Ok(ChainRecordV1::Reorg {
        from_height,
        old_anchor,
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
    event_index: u32,
    block_height: u64,
    block_anchor: [u8; 32],
) -> Result<EvidenceRefV1, RecordError> {
    if tx_id == [0; 32] || block_anchor == [0; 32] {
        return Err(RecordError::InvalidEvidence);
    }
    Ok(EvidenceRefV1 {
        chain_id,
        tx_id,
        event_index,
        block_height,
        block_anchor,
    })
}
