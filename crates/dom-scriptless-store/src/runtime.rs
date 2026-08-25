//! Retained-capability runtime foundations.
//!
//! The module remains private so callers can reach only the deliberately
//! re-exported concrete vault and error boundary, not filesystem internals or
//! constructors for sensitive process-local capabilities.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{
    verify_funding_artifacts_v1, verify_operational_funding_gate_evidence_v1,
    verify_operational_m8_funding_gate_evidence_v1, AcceptedContractsSigningSessionV1,
    AuthenticatedContractsRefundV1, AuthenticatedOperationalBpContinuationV1,
    AuthenticatedOperationalBpFinalProofV1, AuthenticatedPostAnchorClaimPreSignatureV1,
    ClaimSigningAuthorizationV1, ConsumedClaimSigningAuthorizationV1,
    ContractsReservationLookupCustodyV1, ContractsSessionStoreV1,
    ContractsSigningSessionAuthorityV1, DomTransactionValidationContextV1,
    DurableContractsReservationLookupV1, DurableTransportOutcomeV1, DurableTransportReceiptV1,
    ExactDomFundingBroadcasterV1, ExactDomRefundBroadcasterV1, FundingAuthorizationV1,
    FundingBroadcastV1, FundingRetransmissionV1, OperationalBpContinuationStageV1,
    OperationalFundingGateVerificationRequestV1, OperationalM8FundingGateVerificationRequestV1,
    PreparedOperationalM8FundingGateV1, PreparedOperationalM8ReadyToFundVoteV1, RefundBroadcastV1,
    SessionStoreError, SessionTransportIdentityReferenceV1, SessionTransportParticipantV1,
    TerminalCollaborativeSessionEvidenceV1, VerifiedFundingArtifactsV1,
    VerifiedOperationalFundingGateEvidenceV1, VerifiedOperationalM8FundingGateEvidenceV1,
};
#[cfg(all(target_os = "linux", feature = "evidence-only"))]
pub use linux::{BackupPolicyLimitsV1, CompletedBackupV1};
#[cfg(target_os = "linux")]
pub use linux::{ContractsNonceVaultV1, InventoryError, RetainedRestoreTargetV1};
