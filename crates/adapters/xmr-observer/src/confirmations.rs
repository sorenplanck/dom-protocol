//! Quorum-backed transaction confirmations.

use crate::{
    relative_confirmations, XmrConfirmationStatus, XmrObserverError, XmrRpc, XmrRpcPool,
    XmrTransactionStatus,
};

/// Resolves transaction status against a separately agreed canonical tip.
pub async fn confirmation_status<R: XmrRpc>(
    pool: &XmrRpcPool<R>,
    tx_hash: [u8; 32],
) -> Result<XmrConfirmationStatus, XmrObserverError> {
    let canonical_tip = pool.canonical_tip().await?;
    let status = pool.transaction_status(tx_hash).await?;
    match status {
        XmrTransactionStatus::Unseen | XmrTransactionStatus::InPool => Ok(XmrConfirmationStatus {
            status,
            inclusion_block_hash: None,
            confirmations: 0,
            canonical_tip,
        }),
        XmrTransactionStatus::InBlock { block_height } => {
            let confirmations = relative_confirmations(block_height, canonical_tip.height)
                .ok_or(XmrObserverError::StaleTip)?;
            let inclusion_block_hash = pool.block_hash(block_height).await?;
            Ok(XmrConfirmationStatus {
                status,
                inclusion_block_hash: Some(inclusion_block_hash),
                confirmations,
                canonical_tip,
            })
        }
    }
}
