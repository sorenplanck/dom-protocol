//! Integrated cryptographic and durable-authority boundary for DOM Scriptless Contracts.
//!
//! The crate reuses DOM's authoritative hash, canonical point/scalar parsers,
//! challenge, arithmetic, and verifier. NAR-001 ratifies the canonical context
//! and secret two-nonce derivation implemented here with opaque, one-shot
//! ownership. This crate also owns the storage-independent Nonce Vault
//! contract; durable implementations belong to the independent DOM Contracts
//! store (the specialized Scriptless wallet), never the ordinary DOM Wallet.
//! They must fail closed when witness or rollback evidence is incomplete.
//!
//! Default downstream code cannot import a reusable secret nonce owner:
//!
//! ```compile_fail
//! use dom_adaptor::SecretNoncePairV1;
//! ```
//!
//! It cannot call deterministic/raw nonce derivation or raw reveal/signing:
//!
//! ```compile_fail
//! use dom_adaptor::{derive_secret_nonce_pair_v1, raw_nonce_reveal_v1,
//!     raw_partial_sign_v1};
//! ```
//!
//! Collaborative-proof secrets and the scalar-share transport remain
//! crate-sealed until the later session/store orchestration is authorized:
//!
//! ```compile_fail
//! use dom_adaptor::{BpCommonNonceShareV1, BpLocalBlindingV1, BpRound2ShareV1};
//! ```
//!
//! A fresh reservation cannot be constructed from caller-selected identifiers:
//!
//! ```compile_fail
//! use dom_adaptor::FreshReservationRequestV1;
//! let _request = FreshReservationRequestV1(/* private */);
//! ```
//!
//! Prepared and authorized values have no public constructors. Parsing a
//! 252-byte durable record never yields either capability:
//!
//! ```compile_fail
//! use dom_adaptor::{AuthorizedExposureV1, PreparedExposureV1};
//! let prepared = PreparedExposureV1(/* private */);
//! let authorized = AuthorizedExposureV1::from_vault_export(&prepared);
//! ```
//!
//! Request lookup and permit lookup are distinct types with no conversion:
//!
//! ```compile_fail
//! use dom_adaptor::{PermitIdV1, ReservationRequestLookupV1};
//! fn confuse(lookup: ReservationRequestLookupV1) -> PermitIdV1 { lookup.into() }
//! ```
//!
//! The signer-owned signing-round bootstrap is not part of the public API:
//!
//! ```compile_fail
//! use dom_adaptor::ValidatedSigningRoundBootstrapV1;
//! ```
//!
//! The unratified source-shaped signing-session request is not part of the
//! production API:
//!
//! ```compile_fail
//! use dom_adaptor::SigningRoundSessionRequestV1;
//! ```
//!
//! A generic accepted-session implementation cannot invoke the associated-type
//! production entry:
//!
//! ```compile_fail
//! use dom_adaptor::{AcceptedSigningSessionV1, NonceVaultV1,
//!     ReservationLookupCustodyV1, SigningSessionAuthorityV1, VaultBackedSignerV1};
//! fn start<V, C, S, T>(signer: &mut VaultBackedSignerV1<V, C, S>, session: T)
//! where
//!     V: NonceVaultV1,
//!     C: ReservationLookupCustodyV1,
//!     S: SigningSessionAuthorityV1,
//!     T: AcceptedSigningSessionV1,
//! {
//!     let _round = signer.begin_accepted_signing_round(session);
//! }
//! ```
//!
//! An accepted-session handle is consumed by the production entry and cannot
//! start a second signing round:
//!
//! ```compile_fail
//! use dom_adaptor::{NonceVaultV1, ReservationLookupCustodyV1,
//!     SigningSessionAuthorityV1, VaultBackedSignerV1};
//! fn reuse<V, C, S>(signer: &mut VaultBackedSignerV1<V, C, S>,
//!                   session: S::AcceptedSession)
//! where
//!     V: NonceVaultV1,
//!     C: ReservationLookupCustodyV1,
//!     S: SigningSessionAuthorityV1,
//! {
//!     let _first = signer.begin_accepted_signing_round(session);
//!     let _second = signer.begin_accepted_signing_round(session);
//! }
//! ```
//!
//! The internal accepted-session replay helper remains unnameable downstream:
//!
//! ```compile_fail
//! use dom_adaptor::ValidatedSigningRoundStateV1;
//! let _ = ValidatedSigningRoundStateV1::from_accepted_session;
//! ```
//!
//! The persistent DSC1 fuzz harness is unavailable in ordinary builds:
//!
//! ```compile_fail
//! use dom_adaptor::fuzz_dsc1_signing_round_acceptance_v1;
//! ```
//!
//! Sealer/import capabilities cannot be constructed by downstream callers:
//!
//! ```compile_fail
//! use dom_adaptor::{VaultSecretImportCapabilityV1, VaultSecretSealCapabilityV1};
//! let _seal = VaultSecretSealCapabilityV1::new();
//! let _import = VaultSecretImportCapabilityV1::new();
//! ```
//!
//! A capability is consumed by its first use and cannot be reused:
//!
//! ```compile_fail
//! use dom_adaptor::{NonceSecretTransferV1, VaultSecretSealCapabilityV1};
//! fn reuse(cap: VaultSecretSealCapabilityV1,
//!          first: NonceSecretTransferV1,
//!          second: NonceSecretTransferV1) {
//!     let _ = cap.into_plaintext(first);
//!     let _ = cap.into_plaintext(second);
//! }
//! ```
//!
//! Store audit cannot be confused with a secret transfer or import authority:
//!
//! ```compile_fail
//! use dom_adaptor::{audit_nonce_secret_plaintext_v1, NonceSecretTransferV1};
//! use zeroize::Zeroizing;
//! let plaintext = Zeroizing::new(vec![0_u8; 387]);
//! let _: NonceSecretTransferV1 = audit_nonce_secret_plaintext_v1(plaintext);
//! ```
//!
//! The vault-backed signer cannot release or mutably expose its concrete vault:
//!
//! ```compile_fail
//! use dom_adaptor::{NonceVaultV1, ReservationLookupCustodyV1, VaultBackedSignerV1};
//! use dom_adaptor::SigningSessionAuthorityV1;
//! fn escape<V: NonceVaultV1, C: ReservationLookupCustodyV1,
//!           S: SigningSessionAuthorityV1>(
//!     signer: &mut VaultBackedSignerV1<V, C, S>) {
//!     let _vault = signer.vault_mut();
//! }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::{NonceVaultV1, ReservationLookupCustodyV1, VaultBackedSignerV1};
//! use dom_adaptor::SigningSessionAuthorityV1;
//! fn escape<V: NonceVaultV1, C: ReservationLookupCustodyV1,
//!           S: SigningSessionAuthorityV1>(
//!     signer: VaultBackedSignerV1<V, C, S>) {
//!     let _vault = signer.into_inner();
//! }
//! ```
//!
//! The vault composition boundary does not admit a trait-object plugin:
//!
//! ```compile_fail
//! use dom_adaptor::NonceVaultV1;
//! fn install(_vault: &dyn NonceVaultV1) {}
//! ```
//!
//! Reservation handles are fully opaque. The removed fragmented getter view
//! cannot be imported by a downstream caller:
//!
//! ```compile_fail
//! use dom_adaptor::VaultReservationHandleV1;
//! ```
//!
//! A recovered Store descriptor cannot be converted into resend authority by
//! downstream code; the private request constructor is signer-owned:
//!
//! ```compile_fail
//! use dom_adaptor::{ResendRequestV1, ValidatedResendAuthorizationV1,
//!     VaultSpentArtifactSnapshotV1};
//! fn forge<S: VaultSpentArtifactSnapshotV1>(
//!     authority: ValidatedResendAuthorizationV1, spent: &S) {
//!     let _request = ResendRequestV1::from_recovered(authority, spent);
//! }
//! ```
//!
//! The safe cancellation route accepts no caller-selected terminal reason:
//!
//! ```compile_fail
//! use dom_adaptor::AbortReasonV1;
//! ```
//!
//! Validated resend output is a closed typed artifact, not a raw-byte escape:
//!
//! ```compile_fail
//! use dom_adaptor::ResentArtifactV1;
//! fn raw(artifact: ResentArtifactV1) {
//!     let _bytes = artifact.as_bytes();
//! }
//! ```
//!
//! Partial-restart preparation remains crate-private:
//!
//! ```compile_fail
//! use dom_adaptor::PreparedPartialRestartResendV1;
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::signing_round::PreparedPartialRestartResendV1;
//! fn split(prepared: PreparedPartialRestartResendV1) {
//!     let _ = prepared.into_parts();
//! }
//! ```
//!
//! Downstream callers cannot invoke the crate-private round preparation:
//!
//! ```compile_fail
//! use dom_adaptor::{ReservationRequestLookupV1, SigningShareV1,
//!     ValidatedSigningRoundStateV1};
//! fn prepare(round: &mut ValidatedSigningRoundStateV1, share: &SigningShareV1,
//!            lookup: ReservationRequestLookupV1) {
//!     let _ = round.prepare_partial_resend_after_restart(share, lookup);
//! }
//! ```
//!
//! The opaque resend authority cannot be constructed or cloned downstream:
//!
//! ```compile_fail
//! use dom_adaptor::ValidatedResendAuthorizationV1;
//! fn clone_authority(authority: ValidatedResendAuthorizationV1) {
//!     let _ = authority.clone();
//! }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::ValidatedResendAuthorizationV1;
//! fn serialize_authority(authority: ValidatedResendAuthorizationV1) {
//!     let _ = authority.to_bytes();
//! }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::ValidatedResendAuthorizationV1;
//! fn serialize(authority: &ValidatedResendAuthorizationV1) {
//!     let _ = serde_json::to_vec(authority);
//! }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::ValidatedResendAuthorizationV1;
//! fn deserialize(bytes: &[u8]) {
//!     let _: ValidatedResendAuthorizationV1 = serde_json::from_slice(bytes).unwrap();
//! }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::ValidatedResendAuthorizationV1;
//! fn raw_conversion(authority: ValidatedResendAuthorizationV1) {
//!     let _: Vec<u8> = authority.into();
//! }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::ValidatedResendAuthorizationV1;
//! fn reuse_authority(authority: ValidatedResendAuthorizationV1) {
//!     drop(authority);
//!     drop(authority);
//! }
//! ```
//!
//! ```compile_fail
//! use dom_adaptor::{PurposeV1, ResendProtocolStageV1, ReservationRequestLookupV1,
//!     SessionId, ValidatedResendAuthorizationV1};
//! fn forge(lookup: ReservationRequestLookupV1, session: SessionId) {
//!     let _ = ValidatedResendAuthorizationV1::new(
//!         lookup, [1; 32], session, PurposeV1::Refund,
//!         ResendProtocolStageV1::PartialSignature, [2; 32]);
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod adaptor;
mod bulletproof_mpc;
mod context;
mod contract_session;
mod decoy_capsule;
mod error;
mod messages;
mod nonce;
mod nonce_secret_record;
mod nonce_vault;
mod partial_commitment_pop;
mod permit;
mod reservation_binding;
mod secret_nonce;
mod session;
mod share_pop;
mod signing_round;
mod signing_share;
mod transcript;
mod vault_operation;
mod vault_signer;

#[cfg(test)]
mod independent_vector_comparison;

pub use adaptor::{AdaptorPreSignatureV1, AdaptorSecret, CoreAdaptorPreSignatureV1};
pub use bulletproof_mpc::{BpRound1ShareV1, BpStatementV1};
pub use context::{DirectionV1, SessionContextInputsV1, SessionContextV1, SigningPhaseV1};
pub use contract_session::{
    ContractEnvelopeV1, ContractStageV1, ContractStateV1, RefundDeadlinePolicyV1,
};
pub use decoy_capsule::{
    combine_decoy_capsule_v1, DecoyCommitmentV1, DecoyContributionV1, DecoyRevealV1,
    DECOY_VARIABLE_LEN,
};
pub use error::{AdaptorError, Result};
pub use messages::{NonceCommitmentV1, NonceRevealV1, PartialSignatureV1, PurposeV1};
pub use nonce::{
    aggregate_partial_signatures_v1, aggregate_public_nonces_v1, finalize_plain_signature_v1,
    PublicNoncePairV1,
};
pub use nonce_secret_record::{
    audit_nonce_secret_plaintext_v1, NonceSecretTransferV1, VaultSecretImportCapabilityV1,
    VaultSecretSealCapabilityV1,
};
pub use nonce_vault::{
    validate_prepared_exposure_v1, AuthorizedExposureV1, BudgetScope, CounterpartyBucket,
    ExposureBytes, ExposurePermitBindingV1, NonceIdentityV1, NonceReservation, NonceVaultError,
    NonceVaultV1, ParticipantId, PermitIdV1, PreparedExposureV1, PreparedExposureValidationError,
    ProcessComputationBindingIdV1, Purpose, ResendProtocolStageV1, ResendRequestV1,
    ReservationLiveStageV1, ReservationNonceId, ReservationRequestLookupV1,
    ReservationResumeResultV1, ReservationState, RestoreState, SessionId,
    SpentArtifactDescriptorV1, TemplateHash, TerminalReservationV1,
    ValidatedPreparedExposureViewV1, VaultArtifactPersistencePermitV1, VaultComputationStageV1,
    VaultExportedArtifactV1, VaultKeyId, VaultReservationSnapshotV1, VaultSpentArtifactSnapshotV1,
};
pub use partial_commitment_pop::{
    prove_partial_commitment_v1, verify_all_partial_commitments_v1, verify_partial_commitment_v1,
    PartialBlindingV1, PartialCommitmentProofV1,
};
pub use permit::{exposure_outbound_digest_v1, validate_exposure_permit_record_v1, ExposureKindV1};
pub use reservation_binding::{
    DurableReservationLookupV1, FreshReservationRequestV1, PreparedFreshReservationV1,
    ReservationContextBindingV1, ReservationLookupCustodyV1, ReservationResumeRequestV1,
};
pub use session::{
    advance_transcript_hash_v1, canonical_template_v1, generate_session_id_v1,
    initial_transcript_hash_v1, session_message_digest_v1, ContractKindV1, ParticipantIdentityV1,
    ParticipantRosterV1, SessionIdRegistryV1, TrustedChainIdV1,
};
pub use share_pop::{
    prove_share_knowledge_v1, verify_share_knowledge_v1, SharePoPStatementV1, ShareProofV1,
};
pub use signing_round::{
    AcceptedMessageDispositionV1, AcceptedSigningSessionV1, SigningSessionAuthorityV1,
    ValidatedAcceptedSessionMessageV1, ValidatedCommitmentRoundV1, ValidatedDerivationBaseV1,
    ValidatedResendAuthorizationV1, ValidatedRevealRoundV1, ValidatedSigningRoundStateV1,
};

#[cfg(fuzzing)]
#[doc(hidden)]
pub use nonce_vault::fuzz_nar006_runtime_bindings_v1;
#[cfg(fuzzing)]
#[doc(hidden)]
pub use reservation_binding::fuzz_closed_request_types_v1;
#[cfg(fuzzing)]
#[doc(hidden)]
pub use signing_round::fuzz_dsc1_signing_round_acceptance_v1;
pub use signing_share::SigningShareV1;
pub use transcript::{
    binding_factor_v1, nonce_commitment_hash_v1, BindingContextV1, BindingFactorV1,
    ParticipantPublicNoncesV1,
};
pub use vault_operation::{
    NonceDerivationRequestV1, ProtocolCommitmentSetV1, ProtocolRevealSetV1,
    StageComputationRequestV1, ValidatedVaultComputationViewV1, PROTOCOL_COMMITMENT_SET_LEN,
    PROTOCOL_REVEAL_ENTRY_LEN, PROTOCOL_REVEAL_SET_MIN_LEN,
};
pub use vault_signer::{
    CommitmentExportedV1, PartialExportedTerminalV1, ResentArtifactV1, ReservedNonceV1,
    ResumedReservationV1, RevealExportedV1, VaultBackedSignerError, VaultBackedSignerV1,
};

#[cfg(test)]
mod independent_vector_tests {
    #[test]
    fn frozen_independent_outputs_match_all_311_intermediates() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../test-vectors/scriptless/two-nonce/independent/ratified-v1/full_adaptor_reference_outputs_v1.json",
        );
        assert_eq!(super::independent_vector_comparison::run(&path), 311);
    }
}
