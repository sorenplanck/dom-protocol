//! Persists finalized Solana anchors and verified events before Kaystra scans.

#![forbid(unsafe_code)]

use kaystra_core::{state::EvidenceRefV1, types::ChainId};
use solana_evidence::{SolanaEvidenceBodyV1, SolanaEvidenceEnvelopeV1};
use solana_kaystra_source::{SolanaSlotAnchor, VerifiedSolanaEvent, VerifiedSolanaEventKind};
use solana_observation_store::{ObservationStoreError, SqliteVerifiedSolanaFeed};
use solana_observer::{ObservationKind, ObserverError, SolanaSettlementObserver};
use solana_rpc::SolanaRpc;
use solana_types::SolanaSignature;

/// Pump failure.
#[derive(Debug, thiserror::Error)]
pub enum PumpError {
    /// Live verification failed.
    #[error("Solana observer failed: {0}")]
    Observer(#[from] ObserverError),
    /// Durable feed failed.
    #[error("Solana observation store failed: {0}")]
    Store(#[from] ObservationStoreError),
    /// Evidence had an unexpected variant.
    #[error("Solana evidence variant mismatch")]
    EvidenceMismatch,
}

/// Observe one known transaction and persist its canonical consequence.
pub fn observe_and_persist<R: SolanaRpc>(
    observer: &SolanaSettlementObserver<R>,
    store: &SqliteVerifiedSolanaFeed,
    chain_id: ChainId,
    signature: SolanaSignature,
    kind: ObservationKind,
) -> Result<SolanaEvidenceEnvelopeV1, PumpError> {
    let envelope = observer.observe(signature, kind)?;
    let (event_kind, settlement_id, terms_hash, tx_id, index, slot, blockhash) =
        match &envelope.body {
            SolanaEvidenceBodyV1::Funding(value) => (
                VerifiedSolanaEventKind::Funding,
                value.settlement_id,
                value.terms_hash,
                value.signature.digest32(),
                value.instruction_index,
                value.slot,
                value.blockhash.0,
            ),
            SolanaEvidenceBodyV1::Claim(value) => (
                VerifiedSolanaEventKind::Claim,
                value.settlement_id,
                value.terms_hash,
                value.signature.digest32(),
                value.instruction_index,
                value.slot,
                value.blockhash.0,
            ),
            SolanaEvidenceBodyV1::Refund(value) => (
                VerifiedSolanaEventKind::Refund,
                value.settlement_id,
                value.terms_hash,
                value.signature.digest32(),
                value.instruction_index,
                value.slot,
                value.blockhash.0,
            ),
        };
    store.replace_canonical_suffix(slot, slot, &[SolanaSlotAnchor { slot, blockhash }])?;
    store.insert_event(&VerifiedSolanaEvent {
        settlement_id,
        terms_hash,
        kind: event_kind,
        evidence: EvidenceRefV1 {
            chain_id,
            tx_id,
            event_index: u32::from(index),
            block_height: slot,
            block_anchor: blockhash,
        },
    })?;
    Ok(envelope)
}
