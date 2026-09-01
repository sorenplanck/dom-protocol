//! Canonical DOM-bound Monero funding, spend, and refund evidence.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

const FUNDING_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-FUNDING-EVIDENCE/V2\0";
const SPEND_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-SPEND-EVIDENCE/V2\0";
const REFUND_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-REFUND-EVIDENCE/V2\0";

/// Evidence validation failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    /// A mandatory public identifier is zero.
    #[error("zero XMR evidence identifier")]
    ZeroIdentifier,
    /// Amount is zero.
    #[error("zero XMR amount")]
    ZeroAmount,
    /// Confirmation target is not met.
    #[error("insufficient XMR confirmations")]
    InsufficientConfirmations,
    /// Settlement differs from the frozen operation.
    #[error("XMR settlement binding mismatch")]
    SettlementMismatch,
    /// Terms differ from the frozen operation.
    #[error("XMR terms binding mismatch")]
    TermsMismatch,
    /// The spend/refund does not refer to the frozen funding transaction.
    #[error("XMR funding transaction binding mismatch")]
    FundingMismatch,
}

/// Verified inclusion of the expected funding output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmrFundingEvidenceV2 {
    /// Settlement identifier.
    pub settlement_id: [u8; 32],
    /// Frozen Kaystra terms hash.
    pub terms_hash: [u8; 32],
    /// Funding transaction hash.
    pub tx_hash: [u8; 32],
    /// Output index within the funding transaction.
    pub output_index: u32,
    /// Exact amount received in piconero.
    pub amount_piconero: u64,
    /// Inclusion height.
    pub block_height: u64,
    /// Inclusion block hash.
    pub block_hash: [u8; 32],
    /// Confirmations at verification time.
    pub confirmations: u32,
    /// Commitment to the expected combined XMR public spend key.
    pub destination_commitment: [u8; 32],
}

impl XmrFundingEvidenceV2 {
    /// Validates mandatory fields and finality.
    pub fn validate(&self, min_confirmations: u32) -> Result<(), EvidenceError> {
        if self.settlement_id == [0; 32]
            || self.terms_hash == [0; 32]
            || self.tx_hash == [0; 32]
            || self.block_hash == [0; 32]
            || self.destination_commitment == [0; 32]
        {
            return Err(EvidenceError::ZeroIdentifier);
        }
        if self.amount_piconero == 0 {
            return Err(EvidenceError::ZeroAmount);
        }
        if self.confirmations < min_confirmations {
            return Err(EvidenceError::InsufficientConfirmations);
        }
        Ok(())
    }

    /// Requires settlement and terms binding.
    pub fn require_binding(
        &self,
        settlement_id: &[u8; 32],
        terms_hash: &[u8; 32],
    ) -> Result<(), EvidenceError> {
        if &self.settlement_id != settlement_id {
            return Err(EvidenceError::SettlementMismatch);
        }
        if &self.terms_hash != terms_hash {
            return Err(EvidenceError::TermsMismatch);
        }
        Ok(())
    }

    /// Canonical encoding independent from Rust layout/serde.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(32 * 5 + 4 + 8 * 2 + 4);
        output.extend_from_slice(&self.settlement_id);
        output.extend_from_slice(&self.terms_hash);
        output.extend_from_slice(&self.tx_hash);
        output.extend_from_slice(&self.output_index.to_be_bytes());
        output.extend_from_slice(&self.amount_piconero.to_be_bytes());
        output.extend_from_slice(&self.block_height.to_be_bytes());
        output.extend_from_slice(&self.block_hash);
        output.extend_from_slice(&self.confirmations.to_be_bytes());
        output.extend_from_slice(&self.destination_commitment);
        output
    }

    /// Domain-separated evidence id.
    pub fn evidence_id(&self) -> [u8; 32] {
        hash_evidence(FUNDING_DOMAIN, &self.canonical_bytes())
    }
}

/// Verified inclusion of the XMR sweep/claim transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmrSpendEvidenceV2 {
    /// Settlement identifier.
    pub settlement_id: [u8; 32],
    /// Frozen terms hash.
    pub terms_hash: [u8; 32],
    /// Spending transaction hash.
    pub spending_tx_hash: [u8; 32],
    /// Funding transaction consumed by the spend.
    pub funding_tx_hash: [u8; 32],
    /// Inclusion height.
    pub block_height: u64,
    /// Inclusion block hash.
    pub block_hash: [u8; 32],
    /// Confirmations at verification time.
    pub confirmations: u32,
}

impl XmrSpendEvidenceV2 {
    /// Validates all public bindings.
    pub fn validate(
        &self,
        settlement_id: &[u8; 32],
        terms_hash: &[u8; 32],
        funding_tx_hash: &[u8; 32],
        min_confirmations: u32,
    ) -> Result<(), EvidenceError> {
        validate_terminal(
            &ObservedTerminal {
                settlement: self.settlement_id,
                terms: self.terms_hash,
                transaction: self.spending_tx_hash,
                funding: self.funding_tx_hash,
                block_hash: self.block_hash,
                confirmations: self.confirmations,
            },
            &ExpectedTerminal {
                settlement: settlement_id,
                terms: terms_hash,
                funding: funding_tx_hash,
                min_confirmations,
            },
        )
    }

    /// Canonical encoding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        terminal_bytes(
            self.settlement_id,
            self.terms_hash,
            self.spending_tx_hash,
            self.funding_tx_hash,
            self.block_height,
            self.block_hash,
            self.confirmations,
        )
    }

    /// Domain-separated evidence id.
    pub fn evidence_id(&self) -> [u8; 32] {
        hash_evidence(SPEND_DOMAIN, &self.canonical_bytes())
    }
}

/// Verified inclusion of a refund transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmrRefundEvidenceV2 {
    /// Settlement identifier.
    pub settlement_id: [u8; 32],
    /// Frozen terms hash.
    pub terms_hash: [u8; 32],
    /// Refund transaction hash.
    pub refund_tx_hash: [u8; 32],
    /// Funding transaction consumed by the refund.
    pub funding_tx_hash: [u8; 32],
    /// Inclusion height.
    pub block_height: u64,
    /// Inclusion block hash.
    pub block_hash: [u8; 32],
    /// Confirmations at verification time.
    pub confirmations: u32,
}

impl XmrRefundEvidenceV2 {
    /// Validates all public bindings.
    pub fn validate(
        &self,
        settlement_id: &[u8; 32],
        terms_hash: &[u8; 32],
        funding_tx_hash: &[u8; 32],
        min_confirmations: u32,
    ) -> Result<(), EvidenceError> {
        validate_terminal(
            &ObservedTerminal {
                settlement: self.settlement_id,
                terms: self.terms_hash,
                transaction: self.refund_tx_hash,
                funding: self.funding_tx_hash,
                block_hash: self.block_hash,
                confirmations: self.confirmations,
            },
            &ExpectedTerminal {
                settlement: settlement_id,
                terms: terms_hash,
                funding: funding_tx_hash,
                min_confirmations,
            },
        )
    }

    /// Canonical encoding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        terminal_bytes(
            self.settlement_id,
            self.terms_hash,
            self.refund_tx_hash,
            self.funding_tx_hash,
            self.block_height,
            self.block_hash,
            self.confirmations,
        )
    }

    /// Domain-separated evidence id.
    pub fn evidence_id(&self) -> [u8; 32] {
        hash_evidence(REFUND_DOMAIN, &self.canonical_bytes())
    }
}

/// The terminal facts an observer read off the chain.
struct ObservedTerminal {
    settlement: [u8; 32],
    terms: [u8; 32],
    transaction: [u8; 32],
    funding: [u8; 32],
    block_hash: [u8; 32],
    confirmations: u32,
}

/// The frozen facts the observation must match.
struct ExpectedTerminal<'a> {
    settlement: &'a [u8; 32],
    terms: &'a [u8; 32],
    funding: &'a [u8; 32],
    min_confirmations: u32,
}

fn validate_terminal(
    observed: &ObservedTerminal,
    expected: &ExpectedTerminal<'_>,
) -> Result<(), EvidenceError> {
    if observed.settlement == [0; 32]
        || observed.terms == [0; 32]
        || observed.transaction == [0; 32]
        || observed.funding == [0; 32]
        || observed.block_hash == [0; 32]
    {
        return Err(EvidenceError::ZeroIdentifier);
    }
    if &observed.settlement != expected.settlement {
        return Err(EvidenceError::SettlementMismatch);
    }
    if &observed.terms != expected.terms {
        return Err(EvidenceError::TermsMismatch);
    }
    if &observed.funding != expected.funding {
        return Err(EvidenceError::FundingMismatch);
    }
    if observed.confirmations < expected.min_confirmations {
        return Err(EvidenceError::InsufficientConfirmations);
    }
    Ok(())
}

fn terminal_bytes(
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
    transaction_hash: [u8; 32],
    funding_tx_hash: [u8; 32],
    block_height: u64,
    block_hash: [u8; 32],
    confirmations: u32,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(32 * 5 + 8 + 4);
    output.extend_from_slice(&settlement_id);
    output.extend_from_slice(&terms_hash);
    output.extend_from_slice(&transaction_hash);
    output.extend_from_slice(&funding_tx_hash);
    output.extend_from_slice(&block_height.to_be_bytes());
    output.extend_from_slice(&block_hash);
    output.extend_from_slice(&confirmations.to_be_bytes());
    output
}

fn hash_evidence(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn funding() -> XmrFundingEvidenceV2 {
        XmrFundingEvidenceV2 {
            settlement_id: [1; 32],
            terms_hash: [2; 32],
            tx_hash: [3; 32],
            output_index: 7,
            amount_piconero: 123,
            block_height: 99,
            block_hash: [4; 32],
            confirmations: 10,
            destination_commitment: [5; 32],
        }
    }

    #[test]
    fn encoding_and_id_are_deterministic() {
        assert_eq!(funding().canonical_bytes(), funding().canonical_bytes());
        assert_eq!(funding().evidence_id(), funding().evidence_id());
    }

    #[test]
    fn terms_binding_is_enforced() {
        assert_eq!(
            funding().require_binding(&[1; 32], &[9; 32]),
            Err(EvidenceError::TermsMismatch),
        );
    }
}
