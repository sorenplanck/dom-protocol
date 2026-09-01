//! Participant-scoped production authority for the DOM leg of an interop route.
//!
//! This crate connects the encrypted DOM wallet and the retained-capability
//! Scriptless Contracts authorities.  It owns only one participant's wallet
//! material and persists only public commitments, digests and execution state.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod contracts;
mod model;
mod store;
mod wallet;

pub use contracts::{
    participant_contracts_signer_v1, ContractsDomSignerV1, DomClaimPersistenceRequestV1,
    DomContractsActuatorV1, DomFinalClaimAdmissionBundleV2, DomFinalClaimPersistenceRequestV2,
    PersistedRefundTakeoverRequestV1, SameOwnerFinalClaimRecoveryRequestV2,
};
pub use model::{
    DomActionV1, DomActuatorCapabilityV1, DomActuatorError, DomActuatorResult,
    DomFinalityObservationV1, DomFinalityRevalidationV1, DomParticipantSigningShareV1,
    DomParticipantV1, DomSessionBindingV1, DomSettlementChildBindingRequestV1,
    DomSettlementChildBindingV1, DomSettlementChildExposureV1, DomSettlementChildLocatorV1,
    DomSettlementChildPortCallJournalStatusV1, DomSettlementChildPortCallKeyV1,
    DomSettlementChildPortCallKindV1, DomSettlementChildPortCallOutcomeV1, ScopedDomActionV1,
    DOM_SETTLEMENT_CHILD_PORT_CALL_OUTCOME_V1_BYTES,
};
pub use store::{
    DomActuatorStoreV1, DomChainObservationV1, DomClaimAdmissionV1, DomClaimBroadcastV1,
    DomClaimCustodyAuditV1, DomClaimCustodyClassificationV1, DomFinalClaimAdmissionV2,
    DomFinalClaimCustodyAuditV2, DomLeaseV1, DomOperationDispositionV1,
    LatchedFinalClaimSubmissionV2,
};
pub use wallet::{
    AuthenticatedDomPayoutFaceV1, DomOutputReservationV1, DomParticipantWalletSessionV1,
    DomParticipantWalletV1, DomPayoutFaceRequestV1, DomPayoutFaceSelectionRequestV1,
    DomReservedOutputV1, DomWalletAuthorityBindingV1, DomWalletSessionLegV1,
    FundingSigningShareRequestV1, SharedOutputSpendSigningShareRequestV1,
    WalletReservationRequestV1,
};
