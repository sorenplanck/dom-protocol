//! Live Solana broadcast boundary with exact-signature reconciliation.

#![forbid(unsafe_code)]

use solana_delivery::{DeliveryError, DeliveryRecord, DeliveryState, DeliveryStore};
use solana_rpc::{RpcError, SolanaRpc};
use solana_types::{Commitment, SolanaSignature};

/// Live boundary error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LiveError {
    #[error("Solana RPC unavailable")]
    Retryable,
    #[error("Solana RPC returned a divergent signature")]
    SignatureMismatch,
    #[error("Solana delivery store rejected the operation")]
    Delivery,
}

/// Submit exact bytes and reconcile response with the precomputed signature.
pub fn submit_exact<R: SolanaRpc, D: DeliveryStore>(
    rpc: &R,
    delivery: &D,
    record: DeliveryRecord,
) -> Result<DeliveryRecord, LiveError> {
    if record.state == DeliveryState::Finalized {
        return Ok(record);
    }
    let returned = rpc
        .send_transaction(&record.raw_transaction)
        .map_err(map_rpc)?;
    if returned != record.signature {
        return Err(LiveError::SignatureMismatch);
    }
    delivery
        .mark_submitted(&record.settlement_id)
        .map_err(map_delivery)?;
    delivery
        .load(&record.settlement_id)
        .map_err(map_delivery)?
        .ok_or(LiveError::Delivery)
}

/// Reconcile an ambiguous submission by querying signature status.
pub fn reconcile_submission<R: SolanaRpc, D: DeliveryStore>(
    rpc: &R,
    delivery: &D,
    settlement_id: &[u8; 32],
) -> Result<Option<DeliveryRecord>, LiveError> {
    let Some(record) = delivery.load(settlement_id).map_err(map_delivery)? else {
        return Ok(None);
    };
    let status = rpc
        .get_signature_status(record.signature)
        .map_err(map_rpc)?;
    let Some(status) = status else {
        return Ok(Some(record));
    };
    if status.failed {
        return Err(LiveError::SignatureMismatch);
    }
    if status.confirmation == Commitment::Finalized {
        delivery
            .mark_finalized(settlement_id)
            .map_err(map_delivery)?;
    } else {
        delivery
            .mark_submitted(settlement_id)
            .map_err(map_delivery)?;
    }
    delivery.load(settlement_id).map_err(map_delivery)
}

/// Prepare exact signed bytes idempotently.
pub fn prepare_signed<D: DeliveryStore>(
    delivery: &D,
    settlement_id: [u8; 32],
    source_operation_id: [u8; 32],
    signature: SolanaSignature,
    raw_transaction: &[u8],
) -> Result<DeliveryRecord, LiveError> {
    delivery
        .prepare_exact(
            settlement_id,
            source_operation_id,
            signature,
            raw_transaction,
        )
        .map_err(map_delivery)
}

fn map_rpc(error: RpcError) -> LiveError {
    match error {
        RpcError::Unavailable | RpcError::Remote | RpcError::NotFound => LiveError::Retryable,
        RpcError::InvalidResponse | RpcError::BoundsExceeded => LiveError::SignatureMismatch,
    }
}

fn map_delivery(_: DeliveryError) -> LiveError {
    LiveError::Delivery
}
