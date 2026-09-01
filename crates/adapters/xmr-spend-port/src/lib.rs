//! Synchronous ports matching Kaystra's synchronous outbox execution.

#![forbid(unsafe_code)]

use xmr_live_sidecar_api::{
    BuildSweepRequestV2, BuildSweepResponseV2, VerifyFundingRequestV2, VerifyFundingResponseV2,
};

/// External failure classification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpendPortError {
    /// Byte-identical retry may succeed.
    #[error("transient XMR port failure")]
    Retryable,
    /// Input/response is permanently invalid.
    #[error("permanent XMR port rejection")]
    Rejected,
}

/// Exact raw-transaction submission result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastAcceptance {
    /// Node accepted exact bytes.
    Accepted,
    /// Exact transaction is already present in pool/chain.
    AlreadyKnown,
}

/// Scans and verifies the expected funding output.
pub trait FundingVerifyPort: Send {
    /// Verifies exact amount/spendability with the private view key.
    fn verify_funding(
        &mut self,
        request: VerifyFundingRequestV2,
    ) -> Result<VerifyFundingResponseV2, SpendPortError>;
}

/// Constructs one exact signed sweep transaction.
pub trait SweepBuildPort: Send {
    /// `request_nonce` is the sidecar idempotency key.
    fn build_sweep(
        &mut self,
        request: BuildSweepRequestV2,
    ) -> Result<BuildSweepResponseV2, SpendPortError>;
}

/// Broadcasts already-persisted exact bytes without reconstruction.
pub trait ExactBroadcastPort: Send {
    /// Submits exact bytes or reconciles an ambiguous prior submission.
    fn submit_exact(
        &mut self,
        tx_hash: [u8; 32],
        raw_tx: &[u8],
    ) -> Result<BroadcastAcceptance, SpendPortError>;
}
