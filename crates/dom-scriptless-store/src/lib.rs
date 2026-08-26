// The laboratory surface of this crate — the evidence-only constructors and
// the restore, backup and funding-authorization paths that only they reach —
// is compiled OUT of the default profile by design. `scripts/check-release-
// surface.sh` makes that a gate: a release build must accept the crate without
// the feature and must REFUSE it with the feature.
//
// In exactly that build, the support those paths use becomes unreachable and
// `dead_code` reports it. That is the design working, not a defect, so the
// lint is quieted only there. Under `test` and under `evidence-only` — the two
// configurations where this code is actually built and exercised — the lint
// stays fully on and any genuinely unused item is still an error.
#![cfg_attr(not(any(test, feature = "evidence-only")), allow(dead_code))]

//! Fail-closed canonical storage codecs for DOM Contracts.
//!
//! Authenticated canonical-record creation and validation use the pinned DOM
//! purpose registry and authoritative Contracts storage hash boundary.
//! The Linux retained-capability filesystem boundary implements the canonical
//! `NonceVaultV1` composition surface published by `dom-adaptor`. Its
//! production type exposes opaque reservation and one-shot export
//! capabilities; creation remains composition-root controlled, while fixed
//! policy and passphrase constructors are restricted to the `evidence-only`
//! feature. Unpublished legacy vault formats are retained in repository
//! history only and are not part of this crate's module graph.
//!
//! Active-secret presence and deletion evidence is authenticated only by the
//! retained root, lock, generation, journal, tombstone, and sealed-record
//! authority in the canonical runtime. A downstream caller cannot inject such
//! evidence into the minimal journal verifier:
//!
//! ```compile_fail
//! use dom_scriptless_store::ActiveSecretEvidenceV1;
//! ```
//!
//! ```compile_fail
//! use dom_scriptless_store::MinimalJournalV1;
//!
//! let mut journal = MinimalJournalV1::new();
//! let caller_claimed_secret_absence: Option<()> = None;
//! let _ = journal.verify_next(&[], caller_claimed_secret_absence);
//! ```
//!
//! Composite restore authority and its anchor/input capabilities remain
//! crate-private implementation seams. External callers cannot import them or
//! manufacture an anchored continuation:
//!
//! ```compile_fail
//! use dom_scriptless_store::{
//!     CompositeJournalV1, RestoreJournalInputsV1, VerifiedRestoreAnchorV1,
//! };
//! ```
//!
//! ```compile_fail
//! use dom_scriptless_store::MinimalJournalV1;
//!
//! let _ = MinimalJournalV1::continue_after_verified_restore;
//! ```
//!
//! Store permits and retained restore authority are linear process-local
//! values. Downstream code cannot duplicate them:
//!
//! ```compile_fail
//! use dom_adaptor::NonceVaultV1;
//! use dom_scriptless_store::ContractsNonceVaultV1;
//!
//! type Permit = <ContractsNonceVaultV1 as NonceVaultV1>::DerivationAttemptPermit;
//! fn duplicate(value: Permit) { let _ = value.clone(); }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::NonceVaultV1;
//! use dom_scriptless_store::ContractsNonceVaultV1;
//!
//! type Permit = <ContractsNonceVaultV1 as NonceVaultV1>::InitialSecretOpenPermit;
//! fn duplicate(value: Permit) { let _ = value.clone(); }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::NonceVaultV1;
//! use dom_scriptless_store::ContractsNonceVaultV1;
//!
//! type Permit = <ContractsNonceVaultV1 as NonceVaultV1>::StageComputationPermit;
//! fn duplicate(value: Permit) { let _ = value.clone(); }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::NonceVaultV1;
//! use dom_scriptless_store::ContractsNonceVaultV1;
//!
//! type Permit = <ContractsNonceVaultV1 as NonceVaultV1>::ArtifactPersistencePermit;
//! fn duplicate(value: Permit) { let _ = value.clone(); }
//! ```
//!
//! The associated permit type cannot be constructed, converted to raw bytes,
//! or used twice after its first owned consumption:
//!
//! ```compile_fail
//! use dom_adaptor::NonceVaultV1;
//! use dom_scriptless_store::ContractsNonceVaultV1;
//!
//! type Permit = <ContractsNonceVaultV1 as NonceVaultV1>::DerivationAttemptPermit;
//! fn manufacture() -> Permit { Permit {} }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::NonceVaultV1;
//! use dom_scriptless_store::ContractsNonceVaultV1;
//!
//! type Permit = <ContractsNonceVaultV1 as NonceVaultV1>::StageComputationPermit;
//! fn extract(value: Permit) -> Vec<u8> { Vec::<u8>::from(value) }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::NonceVaultV1;
//! use dom_scriptless_store::ContractsNonceVaultV1;
//!
//! type Permit = <ContractsNonceVaultV1 as NonceVaultV1>::ArtifactPersistencePermit;
//! fn consume(_: Permit) {}
//! fn reuse(value: Permit) { consume(value); consume(value); }
//! ```
//!
//! ```compile_fail
//! use dom_scriptless_store::RetainedRestoreTargetV1;
//! fn duplicate(value: RetainedRestoreTargetV1) { let _ = value.clone(); }
//! ```
//!
//! ```compile_fail
//! use dom_scriptless_store::RetainedRestoreTargetV1;
//! fn manufacture() -> RetainedRestoreTargetV1 { RetainedRestoreTargetV1 {} }
//! ```
//!
//! Resumed signer payloads are likewise linear and cannot be cloned or
//! manufactured by downstream callers:
//!
//! ```compile_fail
//! use dom_adaptor::CommitmentExportedV1;
//! fn duplicate(value: CommitmentExportedV1<()>) { let _ = value.clone(); }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::RevealExportedV1;
//! fn duplicate(value: RevealExportedV1<()>) { let _ = value.clone(); }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::PartialExportedTerminalV1;
//! fn manufacture() -> PartialExportedTerminalV1 { PartialExportedTerminalV1 {} }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::CommitmentExportedV1;
//! fn extract(value: CommitmentExportedV1<()>) { let _ = value.into_handle(); }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(all(feature = "evidence-only", not(debug_assertions)))]
compile_error!("the evidence-only Store surface is forbidden in release builds");

mod canonical;
#[cfg(target_os = "linux")]
mod runtime;

#[cfg(target_os = "linux")]
pub use runtime::{
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
pub use runtime::{BackupPolicyLimitsV1, CompletedBackupV1};
#[cfg(target_os = "linux")]
pub use runtime::{ContractsNonceVaultV1, InventoryError, RetainedRestoreTargetV1};

pub use canonical::{
    adaptor_outbound_digest_v1, canonical_attempt_relative_path, canonical_backup_directory_name,
    canonical_backup_staging_directory_name, canonical_exposure_relative_path,
    canonical_generation_directory_name, canonical_journal_filename,
    canonical_restore_completed_directory_name, canonical_restore_initialized_marker_name,
    canonical_restore_record_directory_name, canonical_restore_record_filename,
    canonical_restore_staging_directory_name, canonical_tombstone_filename,
    canonical_tombstone_staging_filename, contracts_exposure_outbound_digest_v1,
    encode_nonce_identity, parse_nonce_identity, permit_lookup_id_v1, ActiveVaultGenerationV1,
    ArtifactKindV1, AttemptRecordV1, BudgetChargeV1, BudgetPolicyProfileV1, BudgetPolicyV1,
    CanonicalCodecError, DirectionV1, ExposureAuthorizationPayloadV1, ExposureRecordV1,
    ExposureStateV1, ExposureVersionIdV1, JournalEntryV1, JournalPayloadEvidenceV1,
    JournalPayloadV1, MinimalJournalV1, NonceDerivationAttemptV1, NonceIdentityV1,
    PartialConsumedPayloadV1, PermitIdV1, PermitRetirementV1, PurposeV1, ReservationAuthorityV1,
    ReservationContextBindingV1, SessionClaimV1, SigningPhaseV1, StoreLockIdentityV1,
    StoreRootIdentityV1, TombstoneV1, UnauthenticatedActiveVaultGenerationV1,
    UnauthenticatedAttemptRecordV1, UnauthenticatedBackupBundlePreimageV1,
    UnauthenticatedBackupManifestV1, UnauthenticatedComputationAttemptV1,
    UnauthenticatedEpochAdvancePayloadV1, UnauthenticatedExposureAuthorizationPayloadV1,
    UnauthenticatedExposureRecordV1, UnauthenticatedExposureVersionIdV1,
    UnauthenticatedJournalEntryV1, UnauthenticatedJournalEnvelopeV1,
    UnauthenticatedJournalPayloadV1, UnauthenticatedNonceDerivationAttemptV1,
    UnauthenticatedPartialConsumedPayloadV1, UnauthenticatedReservePayloadV1,
    UnauthenticatedRestoreCompletePayloadV1, UnauthenticatedRestoreCompleteV1,
    UnauthenticatedRestoreManifestV1, UnauthenticatedRestoreOnlyRootV1,
    UnauthenticatedRestorePendingIndexV1, UnauthenticatedRestoreRecordItemV1,
    UnauthenticatedRestoreRecordKeyV1, UnauthenticatedRestoreRecordPayloadV1,
    UnauthenticatedRestoreRecordSetV1, UnauthenticatedRestoreRecordV1,
    UnauthenticatedSessionClaimV1, UnauthenticatedStoreLockIdentityV1,
    UnauthenticatedStoreRootIdentityV1, UnauthenticatedTombstoneV1,
    UnauthenticatedVaultGenerationCoreV1, VaultGenerationCoreV1, ACTIVE_VAULT_GENERATION_LEN,
    ATTEMPT_RECORD_LEN, BACKUP_BUNDLE_PREIMAGE_LEN, BACKUP_MANIFEST_LEN, BUDGET_CHARGE_ADAPTOR_LEN,
    BUDGET_CHARGE_NO_ADAPTOR_LEN, BUDGET_POLICY_LEN, EPOCH_ADVANCE_PAYLOAD_LEN,
    EXPOSURE_RECORD_MAX_LEN, EXPOSURE_RECORD_MIN_LEN, EXPOSURE_VERSION_ID_LEN,
    JOURNAL_ENTRY_MAX_LEN, JOURNAL_ENTRY_MIN_LEN, JOURNAL_PAYLOAD_MAX_LEN,
    NONCE_DERIVATION_ATTEMPT_LEN, NONCE_IDENTITY_LEN, PERMIT_RETIREMENT_LEN,
    RESERVATION_AUTHORITY_ADAPTOR_LEN, RESERVATION_AUTHORITY_NO_ADAPTOR_LEN,
    RESERVATION_CONTEXT_ADAPTOR_LEN, RESERVATION_CONTEXT_NO_ADAPTOR_LEN, RESTORE_COMPLETE_LEN,
    RESTORE_MANIFEST_LEN, RESTORE_ONLY_ROOT_LEN, RESTORE_PENDING_INDEX_LEN,
    RESTORE_RECORD_ITEM_PREFIX_LEN, RESTORE_RECORD_KEY_LEN, RESTORE_RECORD_PAYLOAD_LEN,
    RESTORE_RECORD_SET_MIN_LEN, SESSION_CLAIM_LEN, STORE_IDENTITY_LEN, TOMBSTONE_LEN,
    VAULT_GENERATION_CORE_LEN,
};
pub use canonical::{JournalEntryKindV1, RestoreActionV1, RestoreRecordFamilyV1, TerminalReasonV1};
pub use canonical::{
    SessionChainProjectionV1, SessionIrreversibleV1, SessionPhaseV1, SessionRecordFieldsV1,
    SessionRecordV1, SessionTxObservationV1,
};
