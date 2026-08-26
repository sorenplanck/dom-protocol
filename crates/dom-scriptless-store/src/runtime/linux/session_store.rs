//! Operational retained-capability persistence for canonical contract sessions.
//!
//! This module is deliberately additive to the signed nonce-vault layout. It
//! reuses the Linux capability boundary and [`crate::SessionRecordV1`] while
//! leaving [`super::ContractsNonceVaultV1`] as the only nonce authority.

use super::{
    ExpectedNodeType, LinuxCapabilityError, RetainedDirectory, RetainedExclusiveLock,
    ValidatedComponent,
};
use crate::{
    BudgetPolicyProfileV1, BudgetPolicyV1, CanonicalCodecError, SessionChainProjectionV1,
    SessionPhaseV1, SessionRecordV1, BUDGET_POLICY_LEN,
};
use cap_std::fs::Dir;
use dom_adaptor::{
    advance_transcript_hash_v1, aggregate_partial_signatures_v1, aggregate_public_nonces_v1,
    binding_factor_v1, canonical_template_v1, initial_transcript_hash_v1, nonce_commitment_hash_v1,
    verify_bilateral_backup_v1, AcceptedOperationalSigningSessionV1, AcceptedSigningSessionV1,
    AdaptorPreSignatureV1, AggregateBpRound1, AggregateBpRound2, BindingContextV1, BpRound1ShareV1,
    BpRound2ShareV1, BpStatementV1, CollaborativeRangeProof, ContractKindV1, DirectionV1,
    DomCollaborativeRangeProofV1, DomainTag, DurableBpRound2TransportV1,
    DurableOperationalFundingIssuanceV1, DurableOperationalM8FundingIssuanceV1,
    DurableReservationLookupV1, LocalBpSecrets, NonceCommitmentV1, NonceRevealV1,
    OperationalFundingAuthorizationBindingV1, OperationalFundingAuthorizationError,
    OperationalFundingAuthorizationImportCapabilityV1, OperationalFundingAuthorizationStoreV1,
    OperationalFundingAuthorizationV1, OperationalFundingPersistenceCapabilityV1,
    OperationalFundingTransactionSinkV1, OperationalFundingUnsignedTemplateV1,
    OperationalM8FundingAuthorizationBindingV1,
    OperationalM8FundingAuthorizationImportCapabilityV1, OperationalM8FundingAuthorizationStoreV1,
    OperationalM8FundingAuthorizationV1, OperationalM8FundingPersistenceCapabilityV1,
    OperationalM8FundingTransactionSinkV1, OperationalSigningSessionAuthorityV1,
    PartialSignatureV1, ParticipantIdentityV1, ParticipantPublicNoncesV1, ParticipantRosterV1,
    PendingCommonNonce, PreparedFreshReservationV1, PurposeV1, RangeProof739,
    ReservationLookupCustodyV1, ReservationLookupRecoveryCustodyV1,
    ReservationLookupRecoveryRequestV1, ReservationRequestLookupV1,
    ScriptlessTransactionTemplateV1, SessionId, ShareBackupAckV1, SharedBlindingBindingV1,
    SigningPhaseV1, TrustedChainIdV1,
};
use dom_consensus::{validate_transaction, Transaction, ValidationContext};
use dom_core::{BlockHeight, Timestamp, KERNEL_FEAT_HEIGHT_LOCKED};
use dom_crypto::{
    blake2b_256, recovery::RecoveryCapsule, schnorr_verify, PublicKey, SchnorrSignature,
};
use dom_scriptless_consensus::scriptless_kernel_message_digest_v1;
use dom_scriptless_crypto::{
    verify_claim_adaptor_pre_signature_v1, ClaimAdaptorVerificationRequestV1,
};
use dom_serialization::{DomDeserialize, DomSerialize};
use f7_anchor_authority::VerifiedF7AnchorAuthorizationV1;
use rand_core::{OsRng, RngCore};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};
use zeroize::Zeroizing;

const ROOT_IDENTITY_NAME: &str = "session-store-root.bin";
const LOCK_IDENTITY_NAME: &str = "session-store-lock.bin";
const POLICY_NAME: &str = "session-store-policy.bin";
const RECORDS_NAME: &str = "session-records";
const ARTIFACTS_NAME: &str = "session-artifacts";
const CONSUMPTIONS_NAME: &str = "session-consumptions";
const ROSTERS_NAME: &str = "session-rosters";
const MESSAGES_NAME: &str = "session-messages";
const RESERVATION_LOOKUPS_NAME: &str = "session-reservation-lookups";

const ROOT_MAGIC: &[u8; 8] = b"DOMSSRT1";
const LOCK_MAGIC: &[u8; 8] = b"DOMSSLK1";
const ARTIFACT_MAGIC: &[u8; 8] = b"DOMSFAR1";
const CONSUMPTION_MAGIC: &[u8; 8] = b"DOMSFCT1";
const ROSTER_MAGIC: &[u8; 8] = b"DOMSTRR1";
const TRANSPORT_IDENTITY_MAGIC: &[u8; 8] = b"DOMSTI01";
const MESSAGE_RECORD_MAGIC: &[u8; 8] = b"DOMSTRM1";
const SIGNING_BINDING_MAGIC: &[u8; 8] = b"DOMSSBR1";
const FUNDING_GATE_MAGIC: &[u8; 8] = b"DOMSFGE1";
const M8_FUNDING_GATE_MAGIC: &[u8; 8] = b"DOMSM8G1";
const FUNDING_ISSUANCE_MAGIC: &[u8; 8] = b"DOMSFIU1";
const M8_FUNDING_ISSUANCE_MAGIC: &[u8; 8] = b"DOMSM8I1";
const FUNDING_COMMIT_MAGIC: &[u8; 8] = b"DOMSFPC1";
const M8_FUNDING_COMMIT_MAGIC: &[u8; 8] = b"DOMSM8C1";
const RESERVATION_LOOKUP_MAGIC: &[u8; 8] = b"DOMSRL01";
const POST_ANCHOR_CLAIM_AUTH_MAGIC: &[u8; 8] = b"DOMSPAC1";
const POST_ANCHOR_CLAIM_BINDING_MAGIC: &[u8; 8] = b"DOMSPCB1";
const POST_ANCHOR_CLAIM_PRE_SIGNATURE_MAGIC: &[u8; 8] = b"DOMSPPS1";
const FORMAT_VERSION: u16 = 1;
const ROOT_IDENTITY_LEN: usize = 112;
const LOCK_IDENTITY_LEN: usize = 80;
const ARTIFACT_PREFIX_LEN: usize = 168;
const CONSUMPTION_PREFIX_LEN: usize = 128;
const CONSUMPTION_MAX_LEN: usize = CONSUMPTION_PREFIX_LEN + SESSION_RECORD_MAX_LEN + DIGEST_LEN;
const TRANSPORT_ROSTER_LEN: usize = 244;
const TRANSPORT_IDENTITY_BINDING_LEN: usize = 370;
const TRANSPORT_MESSAGE_PREFIX_LEN: usize = 208;
const TRANSPORT_MESSAGE_MAX_LEN: usize =
    TRANSPORT_MESSAGE_PREFIX_LEN + (1024 * 1024 + 213) + SESSION_RECORD_MAX_LEN + DIGEST_LEN;
const SIGNING_BINDING_PREFIX_LEN: usize = 672;
const SIGNING_BINDING_MAX_LEN: usize =
    SIGNING_BINDING_PREFIX_LEN + DOM_TRANSACTION_MAX_LEN + DIGEST_LEN;
const FUNDING_GATE_PREFIX_LEN: usize = 416;
const FUNDING_GATE_MAX_LEN: usize =
    FUNDING_GATE_PREFIX_LEN + DOM_TRANSACTION_MAX_LEN * 3 + 162 + 2048 + DIGEST_LEN;
const M8_FUNDING_GATE_PREFIX_LEN: usize = 448;
const M8_FUNDING_GATE_MAX_LEN: usize =
    M8_FUNDING_GATE_PREFIX_LEN + DOM_TRANSACTION_MAX_LEN * 3 + 2048 + DIGEST_LEN;
const FUNDING_ISSUANCE_PREFIX_LEN: usize = 464;
const FUNDING_ISSUANCE_MAX_LEN: usize =
    FUNDING_ISSUANCE_PREFIX_LEN + DOM_TRANSACTION_MAX_LEN + DIGEST_LEN;
const M8_FUNDING_ISSUANCE_PREFIX_LEN: usize = 504;
const M8_FUNDING_ISSUANCE_MAX_LEN: usize =
    M8_FUNDING_ISSUANCE_PREFIX_LEN + DOM_TRANSACTION_MAX_LEN + SESSION_RECORD_MAX_LEN + DIGEST_LEN;
const FUNDING_COMMIT_PREFIX_LEN: usize = 128;
const FUNDING_COMMIT_MAX_LEN: usize =
    FUNDING_COMMIT_PREFIX_LEN + FUNDING_ARTIFACT_MAX_LEN + CONSUMPTION_MAX_LEN + DIGEST_LEN;
const M8_FUNDING_COMMIT_PREFIX_LEN: usize = 160;
const M8_FUNDING_COMMIT_MAX_LEN: usize =
    M8_FUNDING_COMMIT_PREFIX_LEN + FUNDING_ARTIFACT_MAX_LEN + CONSUMPTION_MAX_LEN + DIGEST_LEN;
const RESERVATION_LOOKUP_RECORD_LEN: usize = 216;
const POST_ANCHOR_CLAIM_AUTH_RECORD_LEN: usize = 648;
const POST_ANCHOR_CLAIM_BINDING_RECORD_LEN: usize = 240;
const POST_ANCHOR_CLAIM_PRE_SIGNATURE_RECORD_LEN: usize = 667;
const MAX_ACCEPTED_TRANSPORT_MESSAGES: usize = 256;
const DIGEST_LEN: usize = 32;
const SESSION_RECORD_MAX_LEN: usize = 70 * 1024;
const DOM_TRANSACTION_MAX_LEN: usize = 1024 * 1024;
const FUNDING_ARTIFACT_MAX_LEN: usize =
    ARTIFACT_PREFIX_LEN + DOM_TRANSACTION_MAX_LEN * 2 + DIGEST_LEN;

const ROOT_HASH_TAG: &str = "DOM:contracts-session-store-root:v1";
const LOCK_HASH_TAG: &str = "DOM:contracts-session-store-lock:v1";
const REFUND_HASH_TAG: &str = "DOM:contracts-session-refund-bytes:v1";
const FUNDING_HASH_TAG: &str = "DOM:contracts-session-funding-bytes:v1";
const ARTIFACT_HASH_TAG: &str = "DOM:contracts-session-funding-artifacts:v1";
const CONSUMPTION_HASH_TAG: &str = "DOM:contracts-session-funding-consumption:v1";
const ROSTER_HASH_TAG: &str = "DOM:contracts-session-transport-roster:v1";
const TRANSPORT_IDENTITY_HASH_TAG: &str = "DOM:contracts-session-transport-identity-binding:v1";
const MESSAGE_RECORD_HASH_TAG: &str = "DOM:contracts-session-transport-message-record:v1";
const SIGNING_BINDING_HASH_TAG: &str = "DOM:contracts-operational-signing-binding:v1";
const FUNDING_GATE_HASH_TAG: &str = "DOM:contracts-operational-funding-gate:v1";
const M8_FUNDING_GATE_HASH_TAG: &str = "DOM:contracts-operational-m8-funding-gate:v1";
const FUNDING_ISSUANCE_HASH_TAG: &str = "DOM:contracts-operational-funding-issuance:v1";
const M8_FUNDING_ISSUANCE_HASH_TAG: &str = "DOM:contracts-operational-m8-funding-issuance:v1";
const FUNDING_COMMIT_HASH_TAG: &str = "DOM:contracts-operational-funding-commit:v1";
const M8_FUNDING_COMMIT_HASH_TAG: &str = "DOM:contracts-operational-m8-funding-commit:v1";
const CANONICAL_DOM_TEMPLATE_MAGIC: &[u8; 8] = b"DOMSCTT1";
const CANONICAL_DOM_TEMPLATE_VERSION: u16 = 1;
const RESERVATION_LOOKUP_HASH_TAG: &str = "DOM:contracts-reservation-lookup-custody:v1";
const POST_ANCHOR_CLAIM_AUTH_HASH_TAG: &str =
    "DOM:contracts-post-anchor-claim-signing-authorization:v1";
const POST_ANCHOR_CLAIM_BINDING_HASH_TAG: &str =
    "DOM:contracts-post-anchor-claim-signing-session-binding:v1";
const POST_ANCHOR_CLAIM_ROSTER_HASH_TAG: &str = "DOM:contracts-post-anchor-claim-signing-roster:v1";
const POST_ANCHOR_CLAIM_PRE_SIGNATURE_HASH_TAG: &str =
    "DOM:contracts-post-anchor-claim-pre-signature:v1";
const BILATERAL_BACKUP_HASH_TAG: &str = "DOM:contracts-bilateral-backup-receipt:v1";
const TRANSPORT_MESSAGE_DIGEST_TAG: &str = "DOM:scriptless-message:v1";
const TRANSPORT_TRANSCRIPT_TAG: &str = "DOM:scriptless-transcript:v1";

/// Redacted failure from the operational contract-session store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStoreError {
    /// A retained filesystem operation failed.
    Filesystem,
    /// Another process retains the exclusive store authority.
    StoreBusy,
    /// An exact object already exists with conflicting authority bytes.
    Conflict,
    /// A canonical record or successor was malformed.
    Canonical,
    /// The explicit policy profile is not valid for this constructor.
    PolicyProfile,
    /// Durable state failed authentication or was internally inconsistent.
    Quarantined,
    /// DOM canonical decoding or consensus verification rejected an artifact.
    InvalidDomTransaction,
    /// The requested session does not exist.
    SessionNotFound,
    /// The requested state transition is not owned by this operation.
    InvalidTransition,
    /// Funding was already authorized, consumed, or made unreachable safely.
    FundingAuthorityUnavailable,
    /// Post-anchor DOM claim-signing authority is absent, stale, or consumed.
    ClaimSigningAuthorityUnavailable,
    /// The closed durable transport journal reached its bounded capacity.
    CapacityExceeded,
    /// The operating-system CSPRNG failed.
    RandomFailure,
}

impl fmt::Display for SessionStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Filesystem => "retained session-store filesystem operation failed",
            Self::StoreBusy => "retained session store is busy",
            Self::Conflict => "session-store compare-and-swap conflict",
            Self::Canonical => "canonical session record was rejected",
            Self::PolicyProfile => "session-store policy profile was rejected",
            Self::Quarantined => "session store is quarantined",
            Self::InvalidDomTransaction => "DOM transaction artifact was rejected",
            Self::SessionNotFound => "session was not found",
            Self::InvalidTransition => "session transition was rejected",
            Self::FundingAuthorityUnavailable => "funding authority is unavailable",
            Self::ClaimSigningAuthorityUnavailable => {
                "post-anchor DOM claim-signing authority is unavailable"
            }
            Self::CapacityExceeded => "durable transport journal capacity is exhausted",
            Self::RandomFailure => "operating-system randomness failed",
        })
    }
}

impl Error for SessionStoreError {}

impl From<LinuxCapabilityError> for SessionStoreError {
    fn from(error: LinuxCapabilityError) -> Self {
        match error {
            LinuxCapabilityError::StoreBusy => Self::StoreBusy,
            LinuxCapabilityError::AlreadyExists => Self::Conflict,
            LinuxCapabilityError::NotFound => Self::SessionNotFound,
            LinuxCapabilityError::ExactBytesMismatch
            | LinuxCapabilityError::IdentityMismatch
            | LinuxCapabilityError::InvalidObject
            | LinuxCapabilityError::InvalidDirectoryEntry => Self::Quarantined,
            LinuxCapabilityError::InvalidComponent
            | LinuxCapabilityError::UnsupportedFilesystem
            | LinuxCapabilityError::OperationFailed { .. } => Self::Filesystem,
        }
    }
}

impl From<CanonicalCodecError> for SessionStoreError {
    fn from(_: CanonicalCodecError) -> Self {
        Self::Canonical
    }
}

/// Explicit real-DOM validation context for one funding transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomTransactionValidationContextV1 {
    current_height: u64,
    chain_id: [u8; 32],
    now_unix_seconds: u64,
}

/// Exact public inputs whose authorities are checked before a durable
/// operational funding-gate record may be created.
pub struct OperationalFundingGateVerificationRequestV1<'a> {
    /// Contract session receiving the gate evidence.
    pub session_id: [u8; 32],
    /// Frozen contract-terms digest.
    pub terms_hash: [u8; 32],
    /// Fully signed height-locked refund bytes.
    pub refund_bytes: &'a [u8],
    /// Exact absolute refund unlock height.
    pub refund_unlock_height: u64,
    /// Claim transaction template whose adaptor pre-signature is verified.
    pub claim_template: &'a Transaction,
    /// Frozen refund template. Its canonical hash and shared-output input are
    /// compared with the fully signed refund transaction.
    pub refund_template: &'a Transaction,
    /// Kernel index signed by the claim adaptor pre-signature.
    pub claim_kernel_index: usize,
    /// Exact canonical claim adaptor pre-signature bytes.
    pub claim_pre_signature: &'a [u8],
    /// Transcript predecessor bound into the adaptor challenge.
    pub claim_transcript_hash: [u8; 32],
    /// Explicit real-DOM validation context.
    pub dom_context: DomTransactionValidationContextV1,
    /// Exact durable shared-blinding bindings, in participant order.
    pub shared_blinding_bindings: [&'a SharedBlindingBindingV1; 2],
    /// Frozen collaborative Bulletproof statement for the funding output.
    pub bp_statement: &'a BpStatementV1,
    /// Store-issued durable backup acknowledgements, in participant order.
    pub backup_acknowledgements: &'a [ShareBackupAckV1],
}

/// Opaque verifier result accepted by the retained Store's gate-preparation
/// method. It has no public constructor, codec, `Clone`, or `Debug` surface.
pub struct VerifiedOperationalFundingGateEvidenceV1 {
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    chain_id: [u8; 32],
    claim_transcript_hash: [u8; 32],
    claim_template_hash: [u8; 32],
    refund_template_hash: [u8; 32],
    bp_statement_hash: [u8; 32],
    recovery_binding_hash: [u8; 32],
    shared_output_commitment: [u8; 33],
    refund_unlock_height: u64,
    validation_height: u64,
    now_unix_seconds: u64,
    refund_bytes: Vec<u8>,
    claim_pre_signature: Vec<u8>,
    claim_template_bytes: Vec<u8>,
    refund_template_bytes: Vec<u8>,
    bp_statement_bytes: Vec<u8>,
    refund_tx_hash: [u8; 32],
    claim_pre_signature_hash: [u8; 32],
    backup_receipt_hash: [u8; 32],
}

/// Exact pre-funding inputs for the additive M.8 two-phase funding profile.
///
/// Unlike [`OperationalFundingGateVerificationRequestV1`], this profile
/// deliberately contains no claim adaptor pre-signature or claim nonce. It
/// freezes the claim template and public adaptor point while preserving the
/// already-signed refund and collaborative-output safety evidence.
pub struct OperationalM8FundingGateVerificationRequestV1<'a> {
    /// Contract session receiving the gate evidence.
    pub session_id: [u8; 32],
    /// Frozen contract-terms digest.
    pub terms_hash: [u8; 32],
    /// Canonical M.8 policy digest frozen before funding.
    pub m8_policy_digest: [u8; 32],
    /// Fully signed height-locked refund bytes.
    pub refund_bytes: &'a [u8],
    /// Exact absolute refund unlock height.
    pub refund_unlock_height: u64,
    /// Frozen claim transaction template; it is not signed in this phase.
    pub claim_template: &'a Transaction,
    /// Kernel that the post-anchor ClaimAdaptor round will sign.
    pub claim_kernel_index: usize,
    /// Public adaptor point frozen before funding.
    pub claim_adaptor_point: &'a PublicKey,
    /// Frozen refund template corresponding to `refund_bytes`.
    pub refund_template: &'a Transaction,
    /// Explicit real-DOM validation context.
    pub dom_context: DomTransactionValidationContextV1,
    /// Exact durable shared-blinding bindings, in participant order.
    pub shared_blinding_bindings: [&'a SharedBlindingBindingV1; 2],
    /// Frozen collaborative Bulletproof statement for the funding output.
    pub bp_statement: &'a BpStatementV1,
    /// Store-issued durable backup acknowledgements, in participant order.
    pub backup_acknowledgements: &'a [ShareBackupAckV1],
}

/// Opaque verifier result for the additive pre-funding M.8 profile.
///
/// It has no public constructor, codec, `Clone`, or `Debug` surface. In
/// particular, there is no field in which a claim nonce or pre-signature can
/// be smuggled into the pre-anchor gate.
pub struct VerifiedOperationalM8FundingGateEvidenceV1 {
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    m8_policy_digest: [u8; 32],
    chain_id: [u8; 32],
    claim_template_hash: [u8; 32],
    claim_adaptor_point: PublicKey,
    refund_template_hash: [u8; 32],
    bp_statement_hash: [u8; 32],
    recovery_binding_hash: [u8; 32],
    shared_output_commitment: [u8; 33],
    refund_unlock_height: u64,
    validation_height: u64,
    now_unix_seconds: u64,
    refund_bytes: Vec<u8>,
    claim_template_bytes: Vec<u8>,
    refund_template_bytes: Vec<u8>,
    bp_statement_bytes: Vec<u8>,
    refund_tx_hash: [u8; 32],
    backup_receipt_hash: [u8; 32],
}

/// Linear Store-owned reference to one exact prepared M.8 funding gate.
///
/// It deliberately exposes neither the bilateral backup receipt hash nor a
/// public constructor or codec.  Production composition consumes this handle
/// at the purpose-specific authorization boundary; after restart the retained
/// Store may reissue only a reference to the same authenticated gate record.
pub struct PreparedOperationalM8FundingGateV1 {
    session_id: [u8; 32],
    gate_digest: [u8; 32],
    refund_tx_hash: [u8; 32],
}

impl PreparedOperationalM8FundingGateV1 {
    /// Returns the exact public digest carried by both `ReadyToFund` votes.
    ///
    /// The Store authenticated the retained M.8 gate before issuing this
    /// linear handle.  This projection deliberately exposes only the public
    /// gate commitment and never the bilateral `backup_receipt_hash` retained
    /// inside the immutable gate record.  Funding issuance or restart still
    /// consumes this handle and reauthenticates that record independently.
    pub const fn ready_to_fund_vote_payload(&self) -> [u8; 32] {
        self.gate_digest
    }

    /// Returns the authenticated public hash of the exact retained refund.
    ///
    /// This is safe to carry across the compositor boundary: the refund bytes
    /// and bilateral backup acknowledgement remain Store-private, and every
    /// later use of this handle reauthenticates the immutable gate record.
    pub const fn refund_tx_hash(&self) -> [u8; 32] {
        self.refund_tx_hash
    }
}

/// Store-issued description of the next canonical M.8 `ReadyToFund` vote.
///
/// The value contains only public authenticated envelope fields. It has no
/// public constructor or codec and deliberately carries neither signed bytes,
/// private key material, nor the retained bilateral backup acknowledgement.
pub struct PreparedOperationalM8ReadyToFundVoteV1 {
    session_id: [u8; 32],
    participant_id: [u8; 32],
    sequence: u64,
    previous_transcript_hash: [u8; 32],
    payload: [u8; 32],
}

impl PreparedOperationalM8ReadyToFundVoteV1 {
    /// Session bound to this vote.
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Canonically selected participant that must sign this vote.
    pub const fn participant_id(&self) -> [u8; 32] {
        self.participant_id
    }

    /// Durable sender-local DSC1 sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Exact durable transcript predecessor for the DSC1 envelope.
    pub const fn previous_transcript_hash(&self) -> [u8; 32] {
        self.previous_transcript_hash
    }

    /// Exact public M.8 gate digest carried by message type `0x11`.
    pub const fn payload(&self) -> [u8; 32] {
        self.payload
    }
}

/// Next canonical stage reconstructed from the authenticated BP journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalBpContinuationStageV1 {
    /// Accept the ordered `0x05` common-nonce commitments.
    CommonCommit,
    /// Accept the ordered `0x06` common-nonce reveals.
    CommonReveal,
    /// Accept the ordered `0x07` round-one commitments.
    RoundCommit,
    /// Accept the ordered typed `0x08` round-one shares.
    Round1,
    /// Accept the ordered secret-bearing `0x09` round-two transports.
    Round2,
    /// Both round-two shares are durable and either participant may finalize.
    Finalize,
    /// The sole `0x0a` final proof is durable and verified.
    Complete,
}

/// Opaque authenticated continuation of one operational BP transcript.
///
/// Construction is Store-only after complete retained roster, identity,
/// session-chain, DSC1, statement, recovery-capsule, typed-share, and proof
/// verification.  It deliberately has no public constructor, codec, `Clone`,
/// `Copy`, `Debug`, or equality implementation.  The typed progress can be
/// extracted only by consuming this handle.
#[must_use]
pub struct AuthenticatedOperationalBpContinuationV1 {
    chain_id: [u8; 32],
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    statement_hash: [u8; 32],
    session_revision: u64,
    transcript_hash: [u8; 32],
    stage: OperationalBpContinuationStageV1,
    accepted_participants: [bool; 2],
    statement: BpStatementV1,
    common_commitments: [Option<[u8; 32]>; 2],
    common_reveals: [Option<Zeroizing<[u8; 32]>>; 2],
    round1_commitments: [Option<[u8; 32]>; 2],
    round1_shares: [Option<BpRound1ShareV1>; 2],
    round2_shares: [Option<Zeroizing<[u8; BpRound2ShareV1::ENCODED_LEN]>>; 2],
    finalizer_participant_index: Option<u16>,
    final_proof: Option<RangeProof739>,
}

impl AuthenticatedOperationalBpContinuationV1 {
    /// Exact authenticated DOM chain identity.
    pub const fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }

    /// Exact contract session authenticated by this continuation.
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Cross-chain terms hash authenticated by the retained session chain.
    pub const fn terms_hash(&self) -> [u8; 32] {
        self.terms_hash
    }

    /// Hash of the exact canonical collaborative-BP statement.
    pub const fn statement_hash(&self) -> [u8; 32] {
        self.statement_hash
    }

    /// Revision of the authenticated retained BP-prefix head.
    pub const fn session_revision(&self) -> u64 {
        self.session_revision
    }

    /// Transcript hash of the authenticated retained BP-prefix head.
    pub const fn transcript_hash(&self) -> [u8; 32] {
        self.transcript_hash
    }

    /// Next canonical collaborative-BP stage.
    pub const fn stage(&self) -> OperationalBpContinuationStageV1 {
        self.stage
    }

    /// Accepted participant mask for the current stage.
    ///
    /// A completed two-party stage advances with a fresh mask. `Complete`
    /// carries exactly the sole finalizer bit.
    pub const fn accepted_participants(&self) -> [bool; 2] {
        self.accepted_participants
    }

    /// Exact-compares a caller-owned common commitment at `CommonCommit`.
    pub fn require_common_commitment(
        &self,
        participant_index: u16,
        candidate: &[u8; 32],
    ) -> Result<(), SessionStoreError> {
        self.require_fixed_candidate(
            OperationalBpContinuationStageV1::CommonCommit,
            participant_index,
            candidate,
            &self.common_commitments,
        )
    }

    /// Exact-compares a caller-owned common reveal at `CommonReveal` without
    /// returning the retained reveal.
    pub fn require_common_reveal(
        &self,
        participant_index: u16,
        candidate: &[u8; 32],
    ) -> Result<(), SessionStoreError> {
        if self.stage != OperationalBpContinuationStageV1::CommonReveal {
            return Err(SessionStoreError::InvalidTransition);
        }
        let retained = self
            .common_reveals
            .get(usize::from(participant_index))
            .and_then(Option::as_ref)
            .ok_or(SessionStoreError::InvalidTransition)?;
        if retained[..] != candidate[..] {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }

    /// Exact-compares a caller-owned round-one commitment at `RoundCommit`.
    pub fn require_round1_commitment(
        &self,
        participant_index: u16,
        candidate: &[u8; 32],
    ) -> Result<(), SessionStoreError> {
        self.require_fixed_candidate(
            OperationalBpContinuationStageV1::RoundCommit,
            participant_index,
            candidate,
            &self.round1_commitments,
        )
    }

    /// Exact-compares a typed caller-owned round-one share at `Round1`.
    pub fn require_round1_share(
        &self,
        participant_index: u16,
        candidate: &BpRound1ShareV1,
    ) -> Result<(), SessionStoreError> {
        if self.stage != OperationalBpContinuationStageV1::Round1 {
            return Err(SessionStoreError::InvalidTransition);
        }
        let retained = self
            .round1_shares
            .get(usize::from(participant_index))
            .and_then(Option::as_ref)
            .ok_or(SessionStoreError::InvalidTransition)?;
        if retained.to_bytes() != candidate.to_bytes() {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }

    /// Finishes one independently reopened common nonce from `RoundCommit`
    /// onward using the Store's private authenticated ordered `0x05/0x06`
    /// transcript. No reveal getter exists.
    pub fn finish_common_nonce(
        &self,
        pending: PendingCommonNonce,
    ) -> Result<LocalBpSecrets, SessionStoreError> {
        if matches!(
            self.stage,
            OperationalBpContinuationStageV1::CommonCommit
                | OperationalBpContinuationStageV1::CommonReveal
        ) {
            return Err(SessionStoreError::InvalidTransition);
        }
        let commitments = [
            self.common_commitments[0].ok_or(SessionStoreError::Quarantined)?,
            self.common_commitments[1].ok_or(SessionStoreError::Quarantined)?,
        ];
        let mut reveal_zero = [0u8; 32];
        reveal_zero.copy_from_slice(
            &self.common_reveals[0]
                .as_ref()
                .ok_or(SessionStoreError::Quarantined)?[..],
        );
        let mut reveal_one = [0u8; 32];
        reveal_one.copy_from_slice(
            &self.common_reveals[1]
                .as_ref()
                .ok_or(SessionStoreError::Quarantined)?[..],
        );
        let reveals = vec![Zeroizing::new(reveal_zero), Zeroizing::new(reveal_one)];
        pending
            .finish(&self.statement, &commitments, reveals)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)
    }

    /// Reconstructs a fresh public round-one aggregate while in `Round2`.
    pub fn aggregate_round1(&self) -> Result<AggregateBpRound1, SessionStoreError> {
        if self.stage != OperationalBpContinuationStageV1::Round2 {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.build_aggregate_round1()
    }

    /// Authenticates and consumes a caller-owned durable round-two transport.
    ///
    /// An already accepted participant is exact-compared to the private
    /// retained 104 bytes. A missing participant is checked only through the
    /// DOM-owned statement/session/index binding. The returned zeroizing bytes
    /// are the caller's own bytes; retained bytes are never returned.
    pub fn require_round2_transport(
        &self,
        participant_index: u16,
        candidate: DurableBpRound2TransportV1,
    ) -> Result<Zeroizing<[u8; BpRound2ShareV1::ENCODED_LEN]>, SessionStoreError> {
        if self.stage != OperationalBpContinuationStageV1::Round2
            || usize::from(participant_index) >= 2
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let expected_binding = dom_adaptor::CollaborativeBpNonceBindingV1::from_statement(
            &self.statement,
            participant_index,
        )
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        if candidate.binding() != &expected_binding {
            return Err(SessionStoreError::InvalidTransition);
        }
        let candidate = candidate.into_zeroizing_bytes();
        if let Some(retained) = self.round2_shares[usize::from(participant_index)].as_ref() {
            if retained[..] != candidate[..] {
                return Err(SessionStoreError::InvalidTransition);
            }
        }
        Ok(candidate)
    }

    /// Consumes the `Finalize` handle into Store-built typed aggregates.
    pub fn into_finalize_aggregates(
        self,
    ) -> Result<(AggregateBpRound1, AggregateBpRound2), SessionStoreError> {
        if self.stage != OperationalBpContinuationStageV1::Finalize {
            return Err(SessionStoreError::InvalidTransition);
        }
        let aggregate_round1 = self.build_aggregate_round1()?;
        let Self {
            statement,
            round2_shares,
            ..
        } = self;
        let shares = round2_shares
            .into_iter()
            .map(|share| {
                let share = share.ok_or(SessionStoreError::Quarantined)?;
                BpRound2ShareV1::from_bytes(share.as_ref(), &statement)
                    .map_err(|_| SessionStoreError::Quarantined)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let aggregate_round2 = AggregateBpRound2::new(&statement, shares)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        Ok((aggregate_round1, aggregate_round2))
    }

    /// Consumes the completed continuation into the sole verified proof.
    pub fn into_final_proof(
        mut self,
    ) -> Result<AuthenticatedOperationalBpFinalProofV1, SessionStoreError> {
        if self.stage != OperationalBpContinuationStageV1::Complete {
            return Err(SessionStoreError::InvalidTransition);
        }
        let proof = self
            .final_proof
            .take()
            .ok_or(SessionStoreError::Quarantined)?;
        let finalizer_participant_index = self
            .finalizer_participant_index
            .ok_or(SessionStoreError::Quarantined)?;
        let proof_digest = *blake2b_256(proof.as_bytes()).as_bytes();
        Ok(AuthenticatedOperationalBpFinalProofV1 {
            finalizer_participant_index,
            proof_digest,
            proof,
        })
    }

    fn require_fixed_candidate(
        &self,
        expected_stage: OperationalBpContinuationStageV1,
        participant_index: u16,
        candidate: &[u8; 32],
        retained: &[Option<[u8; 32]>; 2],
    ) -> Result<(), SessionStoreError> {
        if self.stage != expected_stage
            || retained
                .get(usize::from(participant_index))
                .and_then(Option::as_ref)
                != Some(candidate)
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }

    fn build_aggregate_round1(&self) -> Result<AggregateBpRound1, SessionStoreError> {
        let commitments = [
            self.round1_commitments[0].ok_or(SessionStoreError::Quarantined)?,
            self.round1_commitments[1].ok_or(SessionStoreError::Quarantined)?,
        ];
        let shares = [
            self.round1_shares[0]
                .as_ref()
                .ok_or(SessionStoreError::Quarantined)?
                .clone(),
            self.round1_shares[1]
                .as_ref()
                .ok_or(SessionStoreError::Quarantined)?
                .clone(),
        ];
        AggregateBpRound1::new(&self.statement, &commitments, &shares)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)
    }
}

/// Opaque Store-authenticated handle for the sole durable BP final proof.
///
/// It has no public constructor, codec, `Clone`, `Copy`, `Debug`, or equality
/// implementation. The exact proof can be extracted only by consuming it.
pub struct AuthenticatedOperationalBpFinalProofV1 {
    finalizer_participant_index: u16,
    proof_digest: [u8; 32],
    proof: RangeProof739,
}

impl AuthenticatedOperationalBpFinalProofV1 {
    /// Authenticated roster position of the participant that sent `0x0a`.
    pub const fn finalizer_participant_index(&self) -> u16 {
        self.finalizer_participant_index
    }

    /// Plain BLAKE2b-256 digest of the exact verified 739-byte proof.
    pub const fn proof_digest(&self) -> [u8; 32] {
        self.proof_digest
    }

    /// Consumes this authentication handle into the exact DOM proof.
    pub fn into_proof(self) -> RangeProof739 {
        self.proof
    }
}

/// Verifies the complete no-claim-presignature M.8 funding safety profile.
pub fn verify_operational_m8_funding_gate_evidence_v1(
    request: OperationalM8FundingGateVerificationRequestV1<'_>,
) -> Result<VerifiedOperationalM8FundingGateEvidenceV1, SessionStoreError> {
    if request.session_id == [0; 32]
        || request.terms_hash == [0; 32]
        || request.m8_policy_digest == [0; 32]
        || request.refund_unlock_height == 0
        || request.claim_kernel_index != 0
        || request.claim_template.kernels.len() != 1
        || request.refund_template.kernels.is_empty()
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    PublicKey::from_compressed_bytes(&request.claim_adaptor_point.to_compressed_bytes())
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let refund_context = DomTransactionValidationContextV1::new(
        request.refund_unlock_height,
        *request.dom_context.chain_id(),
        request.dom_context.now_unix_seconds(),
    );
    let refund = validate_exact_dom_transaction(request.refund_bytes, refund_context)?;
    if refund.kernels.is_empty()
        || refund.kernels.iter().any(|kernel| {
            kernel.features != KERNEL_FEAT_HEIGHT_LOCKED
                || kernel.lock_height != request.refund_unlock_height
        })
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    let (claim_template_bytes, claim_template_hash) = canonical_template_v1(request.claim_template)
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let (refund_template_bytes, refund_template_hash) =
        canonical_template_v1(request.refund_template)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let (_, signed_refund_template_hash) =
        canonical_template_v1(&refund).map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    if refund_template_hash != signed_refund_template_hash
        || request.claim_template.inputs.len() != 1
        || request.refund_template.inputs.len() != 1
        || request.claim_template.inputs[0].commitment
            != request.refund_template.inputs[0].commitment
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    let shared_output_commitment = *request.claim_template.inputs[0].commitment.as_bytes();
    let first = request.shared_blinding_bindings[0];
    let second = request.shared_blinding_bindings[1];
    if first.chain_id() != request.dom_context.chain_id()
        || second.chain_id() != request.dom_context.chain_id()
        || first.session_id() != &request.session_id
        || second.session_id() != &request.session_id
        || first.terms_hash() != &request.terms_hash
        || second.terms_hash() != &request.terms_hash
        || first.roster() != second.roster()
        || first.capsule_hash() != second.capsule_hash()
        || first.capsule_hash() != request.bp_statement.recovery_binding_hash()
        || request.bp_statement.chain_id() != *request.dom_context.chain_id()
        || request.bp_statement.session_id() != request.session_id
        || request.bp_statement.participant_ids() != first.roster()
        || request.bp_statement.commitment_shares()
            != [first.share_point().clone(), second.share_point().clone()]
        || request
            .bp_statement
            .aggregate_commitment()
            .to_compressed_bytes()
            != shared_output_commitment
        || first.participant_index() != 0
        || second.participant_index() != 1
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    verify_bilateral_backup_v1(
        &[first.share_point().clone(), second.share_point().clone()],
        request.backup_acknowledgements,
    )
    .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let first_binding = first.to_aad_bytes();
    let second_binding = second.to_aad_bytes();
    let mut backup_receipt = Vec::with_capacity(8 + first_binding.len() + second_binding.len());
    backup_receipt.extend_from_slice(&(first_binding.len() as u32).to_le_bytes());
    backup_receipt.extend_from_slice(&first_binding);
    backup_receipt.extend_from_slice(&(second_binding.len() as u32).to_le_bytes());
    backup_receipt.extend_from_slice(&second_binding);
    Ok(VerifiedOperationalM8FundingGateEvidenceV1 {
        session_id: request.session_id,
        terms_hash: request.terms_hash,
        m8_policy_digest: request.m8_policy_digest,
        chain_id: *request.dom_context.chain_id(),
        claim_template_hash,
        claim_adaptor_point: request.claim_adaptor_point.clone(),
        refund_template_hash,
        bp_statement_hash: request.bp_statement.statement_hash(),
        recovery_binding_hash: *request.bp_statement.recovery_binding_hash(),
        shared_output_commitment,
        refund_unlock_height: request.refund_unlock_height,
        validation_height: request.dom_context.current_height(),
        now_unix_seconds: request.dom_context.now_unix_seconds(),
        refund_bytes: request.refund_bytes.to_vec(),
        claim_template_bytes,
        refund_template_bytes,
        bp_statement_bytes: request.bp_statement.to_bytes().to_vec(),
        refund_tx_hash: *dom_crypto::blake2b_256(request.refund_bytes).as_bytes(),
        backup_receipt_hash: tagged_hash(BILATERAL_BACKUP_HASH_TAG, &backup_receipt),
    })
}

/// Verifies the complete refund, claim-adaptor, and bilateral durable-backup
/// evidence used by the operational funding gate.
pub fn verify_operational_funding_gate_evidence_v1(
    request: OperationalFundingGateVerificationRequestV1<'_>,
) -> Result<VerifiedOperationalFundingGateEvidenceV1, SessionStoreError> {
    if request.session_id == [0; 32]
        || request.terms_hash == [0; 32]
        || request.claim_transcript_hash == [0; 32]
        || request.refund_unlock_height == 0
        || request.claim_pre_signature.is_empty()
        || request.claim_pre_signature.len() != 162
        || request.claim_kernel_index != 0
        || request.claim_template.kernels.len() != 1
        || request.refund_template.kernels.is_empty()
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    let refund_context = DomTransactionValidationContextV1::new(
        request.refund_unlock_height,
        *request.dom_context.chain_id(),
        request.dom_context.now_unix_seconds(),
    );
    let refund = validate_exact_dom_transaction(request.refund_bytes, refund_context)?;
    if refund.kernels.is_empty()
        || refund.kernels.iter().any(|kernel| {
            kernel.features != KERNEL_FEAT_HEIGHT_LOCKED
                || kernel.lock_height != request.refund_unlock_height
        })
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    let (claim_template_bytes, claim_template_hash) = canonical_template_v1(request.claim_template)
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let (refund_template_bytes, refund_template_hash) =
        canonical_template_v1(request.refund_template)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let (_, signed_refund_template_hash) =
        canonical_template_v1(&refund).map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    if refund_template_hash != signed_refund_template_hash
        || request.claim_template.inputs.len() != 1
        || request.refund_template.inputs.len() != 1
        || request.claim_template.inputs[0].commitment
            != request.refund_template.inputs[0].commitment
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    let shared_output_commitment = *request.claim_template.inputs[0].commitment.as_bytes();
    let claim_kernel = request
        .claim_template
        .kernels
        .get(request.claim_kernel_index)
        .ok_or(SessionStoreError::InvalidDomTransaction)?;
    let claim_request = ClaimAdaptorVerificationRequestV1 {
        pre_signature: request.claim_pre_signature,
        claim_template_hash,
        transcript_hash: request.claim_transcript_hash,
        aggregate_signing_key: *claim_kernel.excess.as_bytes(),
        chain_id: *request.dom_context.chain_id(),
        kernel_message_digest: *scriptless_kernel_message_digest_v1(claim_kernel).as_bytes(),
    };
    verify_claim_adaptor_pre_signature_v1(&claim_request)
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;

    let first = request.shared_blinding_bindings[0];
    let second = request.shared_blinding_bindings[1];
    if first.chain_id() != request.dom_context.chain_id()
        || second.chain_id() != request.dom_context.chain_id()
        || first.session_id() != &request.session_id
        || second.session_id() != &request.session_id
        || first.terms_hash() != &request.terms_hash
        || second.terms_hash() != &request.terms_hash
        || first.roster() != second.roster()
        || first.capsule_hash() != second.capsule_hash()
        || first.capsule_hash() != request.bp_statement.recovery_binding_hash()
        || request.bp_statement.chain_id() != *request.dom_context.chain_id()
        || request.bp_statement.session_id() != request.session_id
        || request.bp_statement.participant_ids() != first.roster()
        || request.bp_statement.commitment_shares()
            != [first.share_point().clone(), second.share_point().clone()]
        || request
            .bp_statement
            .aggregate_commitment()
            .to_compressed_bytes()
            != shared_output_commitment
        || first.participant_index() != 0
        || second.participant_index() != 1
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    verify_bilateral_backup_v1(
        &[first.share_point().clone(), second.share_point().clone()],
        request.backup_acknowledgements,
    )
    .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let first_binding = first.to_aad_bytes();
    let second_binding = second.to_aad_bytes();
    let mut backup_receipt = Vec::with_capacity(8 + first_binding.len() + second_binding.len());
    backup_receipt.extend_from_slice(&(first_binding.len() as u32).to_le_bytes());
    backup_receipt.extend_from_slice(&first_binding);
    backup_receipt.extend_from_slice(&(second_binding.len() as u32).to_le_bytes());
    backup_receipt.extend_from_slice(&second_binding);
    let refund_tx_hash = *dom_crypto::blake2b_256(request.refund_bytes).as_bytes();
    let claim_pre_signature_hash = *dom_crypto::blake2b_256(request.claim_pre_signature).as_bytes();
    Ok(VerifiedOperationalFundingGateEvidenceV1 {
        session_id: request.session_id,
        terms_hash: request.terms_hash,
        chain_id: *request.dom_context.chain_id(),
        claim_transcript_hash: request.claim_transcript_hash,
        claim_template_hash,
        refund_template_hash,
        bp_statement_hash: request.bp_statement.statement_hash(),
        recovery_binding_hash: *request.bp_statement.recovery_binding_hash(),
        shared_output_commitment,
        refund_unlock_height: request.refund_unlock_height,
        validation_height: request.dom_context.current_height(),
        now_unix_seconds: request.dom_context.now_unix_seconds(),
        refund_bytes: request.refund_bytes.to_vec(),
        claim_pre_signature: request.claim_pre_signature.to_vec(),
        claim_template_bytes,
        refund_template_bytes,
        bp_statement_bytes: request.bp_statement.to_bytes().to_vec(),
        refund_tx_hash,
        claim_pre_signature_hash,
        backup_receipt_hash: tagged_hash(BILATERAL_BACKUP_HASH_TAG, &backup_receipt),
    })
}

impl DomTransactionValidationContextV1 {
    /// Creates an explicit context. No network, height, time, or chain default
    /// is selected by the Store.
    pub const fn new(current_height: u64, chain_id: [u8; 32], now_unix_seconds: u64) -> Self {
        Self {
            current_height,
            chain_id,
            now_unix_seconds,
        }
    }

    /// Returns the caller-selected canonical height.
    pub const fn current_height(&self) -> u64 {
        self.current_height
    }

    /// Returns the caller-selected chain identifier.
    pub const fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }

    /// Returns the caller-selected Unix time.
    pub const fn now_unix_seconds(&self) -> u64 {
        self.now_unix_seconds
    }

    fn consensus(self) -> ValidationContext {
        ValidationContext {
            current_height: BlockHeight(self.current_height),
            chain_id: self.chain_id,
            now: Timestamp(self.now_unix_seconds),
        }
    }
}

/// What authenticating post-anchor claim evidence yields: the session record
/// the evidence was authenticated against, and the three digests bound to it.
type AuthenticatedPostAnchorClaimV1 = (SessionRecordV1, [u8; 32], [u8; 32], [u8; 32]);

/// Opaque verifier-issued authority for exact refund and funding bytes.
///
/// It intentionally has no public constructor, fields, codec, equality,
/// ordering, `Clone`, or `Debug` implementation.
pub struct VerifiedFundingArtifactsV1 {
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    refund_unlock_height: u64,
    refund_bytes: Vec<u8>,
    funding_bytes: Vec<u8>,
    refund_digest: [u8; 32],
    funding_digest: [u8; 32],
}

/// Verifies exact canonical transaction bytes with the pinned real DOM
/// decoder and complete consensus transaction verifier.
///
/// The refund is validated at its declared unlock height and every refund
/// kernel must be height-locked at that exact height. This validates a
/// pre-signed future refund without pretending it is currently spendable.
pub fn verify_funding_artifacts_v1(
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    refund_unlock_height: u64,
    refund_bytes: &[u8],
    funding_bytes: &[u8],
    funding_context: DomTransactionValidationContextV1,
) -> Result<VerifiedFundingArtifactsV1, SessionStoreError> {
    if session_id == [0; 32]
        || terms_hash == [0; 32]
        || refund_unlock_height == 0
        || refund_bytes.is_empty()
        || funding_bytes.is_empty()
        || refund_bytes.len() > DOM_TRANSACTION_MAX_LEN
        || funding_bytes.len() > DOM_TRANSACTION_MAX_LEN
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    let refund_context = DomTransactionValidationContextV1::new(
        refund_unlock_height,
        *funding_context.chain_id(),
        funding_context.now_unix_seconds(),
    );
    let refund = validate_exact_dom_transaction(refund_bytes, refund_context)?;
    if refund.kernels.is_empty()
        || refund.kernels.iter().any(|kernel| {
            kernel.features != KERNEL_FEAT_HEIGHT_LOCKED
                || kernel.lock_height != refund_unlock_height
        })
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    validate_exact_dom_transaction(funding_bytes, funding_context)?;
    let refund_digest = tagged_hash(REFUND_HASH_TAG, refund_bytes);
    let funding_digest = tagged_hash(FUNDING_HASH_TAG, funding_bytes);
    if refund_digest == funding_digest {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    Ok(VerifiedFundingArtifactsV1 {
        session_id,
        terms_hash,
        refund_unlock_height,
        refund_bytes: refund_bytes.to_vec(),
        funding_bytes: funding_bytes.to_vec(),
        refund_digest,
        funding_digest,
    })
}

fn validate_exact_dom_transaction(
    bytes: &[u8],
    context: DomTransactionValidationContextV1,
) -> Result<Transaction, SessionStoreError> {
    let transaction = <Transaction as DomDeserialize>::from_bytes(bytes)
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    if transaction
        .to_bytes()
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?
        != bytes
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    validate_transaction(&transaction, &context.consensus())
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    Ok(transaction)
}

fn canonical_dom_transaction_bytes_v1(
    transaction: &Transaction,
) -> Result<Vec<u8>, SessionStoreError> {
    let bytes = transaction
        .to_bytes()
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let decoded = <Transaction as DomDeserialize>::from_bytes(&bytes)
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    if decoded != *transaction
        || decoded
            .to_bytes()
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?
            != bytes
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    Ok(bytes)
}

fn parse_canonical_dom_template_v1(bytes: &[u8]) -> Result<Transaction, SessionStoreError> {
    let mut cursor = 0usize;
    if take_canonical_dom_template_field(bytes, &mut cursor, CANONICAL_DOM_TEMPLATE_MAGIC.len())?
        != CANONICAL_DOM_TEMPLATE_MAGIC
        || u16::from_le_bytes(copy_array(take_canonical_dom_template_field(
            bytes,
            &mut cursor,
            2,
        )?)?)
            != CANONICAL_DOM_TEMPLATE_VERSION
    {
        return Err(SessionStoreError::Quarantined);
    }

    let input_count = usize::try_from(u32::from_le_bytes(copy_array(
        take_canonical_dom_template_field(bytes, &mut cursor, 4)?,
    )?))
    .map_err(|_| SessionStoreError::Quarantined)?;
    if input_count > dom_core::MAX_INPUTS_PER_TX {
        return Err(SessionStoreError::Quarantined);
    }
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let encoded: [u8; 33] =
            copy_array(take_canonical_dom_template_field(bytes, &mut cursor, 33)?)?;
        let commitment = dom_crypto::pedersen::Commitment::from_compressed_bytes(&encoded)
            .map_err(|_| SessionStoreError::Quarantined)?;
        inputs.push(dom_consensus::TransactionInput { commitment });
    }

    let output_count = usize::try_from(u32::from_le_bytes(copy_array(
        take_canonical_dom_template_field(bytes, &mut cursor, 4)?,
    )?))
    .map_err(|_| SessionStoreError::Quarantined)?;
    if output_count > dom_core::MAX_OUTPUTS_PER_TX {
        return Err(SessionStoreError::Quarantined);
    }
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let encoded: [u8; 33] =
            copy_array(take_canonical_dom_template_field(bytes, &mut cursor, 33)?)?;
        let commitment = dom_crypto::pedersen::Commitment::from_compressed_bytes(&encoded)
            .map_err(|_| SessionStoreError::Quarantined)?;
        let proof_len = usize::try_from(u32::from_le_bytes(copy_array(
            take_canonical_dom_template_field(bytes, &mut cursor, 4)?,
        )?))
        .map_err(|_| SessionStoreError::Quarantined)?;
        if proof_len > dom_core::MAX_OUTPUT_PROOF_ENVELOPE_SIZE {
            return Err(SessionStoreError::Quarantined);
        }
        let proof = take_canonical_dom_template_field(bytes, &mut cursor, proof_len)?.to_vec();
        outputs.push(dom_consensus::TransactionOutput { commitment, proof });
    }

    let kernel_count = usize::try_from(u32::from_le_bytes(copy_array(
        take_canonical_dom_template_field(bytes, &mut cursor, 4)?,
    )?))
    .map_err(|_| SessionStoreError::Quarantined)?;
    if kernel_count > dom_core::MAX_KERNELS_PER_TX {
        return Err(SessionStoreError::Quarantined);
    }
    let mut kernels = Vec::with_capacity(kernel_count);
    for _ in 0..kernel_count {
        let features = take_canonical_dom_template_field(bytes, &mut cursor, 1)?[0];
        let fee = dom_core::Amount::from_noms(u64::from_le_bytes(copy_array(
            take_canonical_dom_template_field(bytes, &mut cursor, 8)?,
        )?))
        .map_err(|_| SessionStoreError::Quarantined)?;
        let lock_height = u64::from_le_bytes(copy_array(take_canonical_dom_template_field(
            bytes,
            &mut cursor,
            8,
        )?)?);
        let encoded: [u8; 33] =
            copy_array(take_canonical_dom_template_field(bytes, &mut cursor, 33)?)?;
        let excess = dom_crypto::pedersen::Commitment::from_compressed_bytes(&encoded)
            .map_err(|_| SessionStoreError::Quarantined)?;
        kernels.push(dom_consensus::TransactionKernel {
            features,
            fee,
            lock_height,
            excess,
            excess_signature: [0; 65],
        });
    }

    let offset = copy_array(take_canonical_dom_template_field(bytes, &mut cursor, 32)?)?;
    if cursor != bytes.len() {
        return Err(SessionStoreError::Quarantined);
    }
    let transaction = Transaction {
        inputs,
        outputs,
        kernels,
        offset,
    };
    dom_consensus::validate_transaction_structure(&transaction)
        .map_err(|_| SessionStoreError::Quarantined)?;
    Ok(transaction)
}

fn authenticate_canonical_dom_template_hash_v1(
    bytes: &[u8],
) -> Result<[u8; 32], SessionStoreError> {
    let transaction = parse_canonical_dom_template_v1(bytes)?;
    let (canonical, _) =
        canonical_template_v1(&transaction).map_err(|_| SessionStoreError::Quarantined)?;
    if canonical != bytes {
        return Err(SessionStoreError::Quarantined);
    }
    Ok(tagged_hash(DomainTag::Template.as_str(), bytes))
}

fn take_canonical_dom_template_field<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], SessionStoreError> {
    let end = cursor
        .checked_add(length)
        .ok_or(SessionStoreError::Quarantined)?;
    let field = bytes
        .get(*cursor..end)
        .ok_or(SessionStoreError::Quarantined)?;
    *cursor = end;
    Ok(field)
}

/// Opaque, process-bound, one-shot funding authorization.
///
/// Issuance occurs only after the artifact object and `FundingAuthorized`
/// session successor are durable. The value has no codec and cannot survive a
/// restart or be reconstructed from public fields.
pub struct FundingAuthorizationV1 {
    open_instance_id: [u8; 32],
    session_id: [u8; 32],
    authorized_revision: u64,
    session_digest: [u8; 32],
    artifact_digest: [u8; 32],
}

/// Linear exact funding bytes returned only after durable authorization
/// consumption and a durable `FundingBroadcast` successor.
pub struct FundingBroadcastV1 {
    exact_bytes: Vec<u8>,
}

impl FundingBroadcastV1 {
    /// Consumes this one broadcast attempt inside the selected exact-byte DOM
    /// broadcaster. The transaction bytes cannot be copied through this API.
    pub fn dispatch_with<B: ExactDomFundingBroadcasterV1>(
        self,
        broadcaster: &mut B,
    ) -> Result<B::Receipt, B::Error> {
        broadcaster.broadcast_exact_funding(&self.exact_bytes)
    }

    /// Returns exact bytes only in explicitly non-production evidence builds.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn as_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}

/// Exact-byte real-DOM funding broadcast boundary.
pub trait ExactDomFundingBroadcasterV1 {
    /// Adapter-specific redacted failure.
    type Error: Error;
    /// Node acknowledgement/evidence returned by the real adapter.
    type Receipt;
    /// Submit the exact persisted canonical funding bytes once.
    fn broadcast_exact_funding(&mut self, exact_bytes: &[u8])
        -> Result<Self::Receipt, Self::Error>;
}

/// Exact-byte real-DOM refund broadcast boundary.
pub trait ExactDomRefundBroadcasterV1 {
    /// Adapter-specific redacted failure.
    type Error: Error;
    /// Node acknowledgement/evidence returned by the real adapter.
    type Receipt;
    /// Submit the exact persisted canonical refund bytes once.
    fn broadcast_exact_refund(&mut self, exact_bytes: &[u8]) -> Result<Self::Receipt, Self::Error>;
}

/// Linear byte-identical retransmission loaded from durable consumed state.
/// This is not first-broadcast authority and is available only after the
/// original authorization has been durably retired.
pub struct FundingRetransmissionV1 {
    exact_bytes: Vec<u8>,
}

impl FundingRetransmissionV1 {
    /// Converts an authenticated retransmission into the same one-shot
    /// broadcast capability the original authorization produced.
    ///
    /// This grants no new authority. `resend_funding_broadcast` has already
    /// required the one-shot funding authorization to be durably consumed and
    /// the `FundingBroadcast` successor to be part of the authenticated session
    /// history, so these bytes are byte-identical to the ones authorized once
    /// and can never be a second authorization.
    #[must_use]
    pub fn into_broadcast(self) -> FundingBroadcastV1 {
        FundingBroadcastV1 {
            exact_bytes: self.exact_bytes,
        }
    }

    /// Consumes this fresh durable retransmission attempt through the real DOM
    /// broadcaster.
    pub fn dispatch_with<B: ExactDomFundingBroadcasterV1>(
        self,
        broadcaster: &mut B,
    ) -> Result<B::Receipt, B::Error> {
        broadcaster.broadcast_exact_funding(&self.exact_bytes)
    }

    /// Canonical BLAKE2b-256 identity of the exact funding transaction.
    ///
    /// This is deliberately a hash and not the bytes. The transaction identity
    /// is public — it is what appears on chain and in every receipt — while the
    /// exact bytes stay unavailable outside evidence builds. A route resumed
    /// after its funding was already broadcast needs the identity to rebuild
    /// its receipt without ever handling the transaction itself.
    #[must_use]
    pub fn funding_tx_hash(&self) -> [u8; 32] {
        *blake2b_256(&self.exact_bytes).as_bytes()
    }

    /// Returns exact bytes only in explicitly non-production evidence builds.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn as_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}

/// Linear exact persisted refund bytes released only after real DOM timelock
/// verification at the caller's explicit current chain context.
pub struct RefundBroadcastV1 {
    exact_bytes: Vec<u8>,
}

/// One participant's public transport authentication binding.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionTransportParticipantV1 {
    participant_id: [u8; 32],
    identity_key: PublicKey,
    direction: DirectionV1,
}

impl SessionTransportParticipantV1 {
    /// Constructs a nonzero public participant binding.
    pub fn new(
        participant_id: [u8; 32],
        identity_key: PublicKey,
        direction: DirectionV1,
    ) -> Result<Self, SessionStoreError> {
        if participant_id == [0; 32] {
            return Err(SessionStoreError::Canonical);
        }
        Ok(Self {
            participant_id,
            identity_key,
            direction,
        })
    }

    /// Returns the stable public participant identifier.
    pub const fn participant_id(&self) -> &[u8; 32] {
        &self.participant_id
    }
}

/// Public-only reference from one session participant to the independent DOM
/// Contracts application keystore.
///
/// This record deliberately carries neither the X25519 private key nor the
/// DOM Schnorr identity secret. It binds the opaque keystore reference and
/// Noise public key to the same participant and Schnorr public key already
/// frozen in the canonical transport roster.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionTransportIdentityReferenceV1 {
    participant_id: [u8; 32],
    key_reference: [u8; 32],
    noise_public_key: [u8; 32],
    schnorr_public_key: PublicKey,
}

impl SessionTransportIdentityReferenceV1 {
    /// Constructs one nonzero public identity reference.
    pub fn new(
        participant_id: [u8; 32],
        key_reference: [u8; 32],
        noise_public_key: [u8; 32],
        schnorr_public_key: PublicKey,
    ) -> Result<Self, SessionStoreError> {
        if participant_id == [0; 32] || key_reference == [0; 32] || noise_public_key == [0; 32] {
            return Err(SessionStoreError::Canonical);
        }
        Ok(Self {
            participant_id,
            key_reference,
            noise_public_key,
            schnorr_public_key,
        })
    }

    /// Stable public participant identifier.
    pub const fn participant_id(&self) -> &[u8; 32] {
        &self.participant_id
    }

    /// Opaque independent Contracts-keystore record reference.
    pub const fn key_reference(&self) -> &[u8; 32] {
        &self.key_reference
    }

    /// Frozen X25519 Noise static public key.
    pub const fn noise_public_key(&self) -> &[u8; 32] {
        &self.noise_public_key
    }

    /// Frozen dedicated DOM Schnorr DSC1 identity public key.
    pub const fn schnorr_public_key(&self) -> &PublicKey {
        &self.schnorr_public_key
    }
}

/// Durable receipt for one authenticated signed transport message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableTransportReceiptV1 {
    /// Digest of the exact canonical unsigned message bytes.
    pub message_digest: [u8; 32],
    /// Transcript committed by the durable session successor.
    pub transcript_hash: [u8; 32],
    /// Sender-local sequence.
    pub sequence: u64,
    /// Raw closed message-type discriminant.
    pub message_type: u8,
    /// Whether this call was an exact durable duplicate.
    pub duplicate: bool,
}

/// Result of durable transport acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableTransportOutcomeV1 {
    /// The exact message and session successor are durable; an ACK may now be
    /// emitted with this receipt.
    Accepted(DurableTransportReceiptV1),
    /// Different validly signed bytes reused one logical key. The supplied
    /// `FailedClosed` successor is durable; no ACK may be emitted.
    EquivocationPersisted,
}

impl RefundBroadcastV1 {
    /// Consumes this refund attempt through the selected exact-byte DOM
    /// broadcaster.
    pub fn dispatch_with<B: ExactDomRefundBroadcasterV1>(
        self,
        broadcaster: &mut B,
    ) -> Result<B::Receipt, B::Error> {
        broadcaster.broadcast_exact_refund(&self.exact_bytes)
    }

    /// Returns exact bytes only in explicitly non-production evidence builds.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn as_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}

/// Static operational DOM adaptor authority implemented by the retained
/// Contracts store.
///
/// The marker has no constructor and carries no caller-supplied state. Its
/// associated accepted-session type can be issued only by
/// [`ContractsSessionStoreV1::bind_operational_signing_session`] or recovered
/// by [`ContractsSessionStoreV1::resume_operational_signing_session`].
pub struct ContractsSigningSessionAuthorityV1 {
    _private: (),
}

impl OperationalSigningSessionAuthorityV1 for ContractsSigningSessionAuthorityV1 {
    type Error = SessionStoreError;
    type AcceptedSession = AcceptedContractsSigningSessionV1;
}

/// Store-owned reservation-lookup custody borrowed by the operational signer.
///
/// This value has no public constructor, filesystem handle, codec, `Clone`, or
/// `Debug`. It is issued only as a narrow borrow of an already-open retained
/// [`ContractsSessionStoreV1`].
pub struct ContractsReservationLookupCustodyV1<'store> {
    store: &'store ContractsSessionStoreV1,
}

/// Opaque process-only proof that one exact reservation lookup was persisted
/// and authenticated by the retained Contracts session store.
///
/// The value deliberately has no public constructor, codec, `Clone`, `Copy`,
/// `Debug`, or equality implementation. Consuming it can authorize only the
/// matching already-prepared request inside `dom-adaptor`.
pub struct DurableContractsReservationLookupV1 {
    request_lookup: ReservationRequestLookupV1,
    context_binding_digest: [u8; 32],
    session_id: SessionId,
    _open_instance_id: [u8; 32],
    _record_digest: [u8; 32],
}

impl DurableReservationLookupV1 for DurableContractsReservationLookupV1 {
    fn request_lookup(&self) -> &ReservationRequestLookupV1 {
        &self.request_lookup
    }

    fn context_binding_digest(&self) -> &[u8; 32] {
        &self.context_binding_digest
    }

    fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}

/// Opaque proof that candidate refund bytes are the exact persisted F7 refund
/// behind an authenticated, consumed funding authorization.
///
/// The capability contains public identifiers only and intentionally exposes
/// neither the persisted transaction bytes nor a constructor, codec, `Clone`,
/// `Copy`, `Debug`, or equality implementation.
pub struct AuthenticatedContractsRefundV1 {
    session_id: [u8; 32],
    transaction_hash: [u8; 32],
    exact_bytes_digest: [u8; 32],
    funding_artifact_digest: [u8; 32],
    funding_consumption_digest: [u8; 32],
    funding_broadcast_record_digest: [u8; 32],
    refund_phase_record_digest: [u8; 32],
}

/// Owned projection consumed from the Store-free real-chain F7 authority.
///
/// This type is deliberately private. Production callers cannot provide raw
/// digests or construct a lookalike request; the only public issuance method
/// consumes [`VerifiedF7AnchorAuthorizationV1`] by value.
struct PostAnchorDomClaimSigningEvidenceV1 {
    chain_id: [u8; 32],
    session_id: [u8; 32],
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
    m8_policy_digest: [u8; 32],
    m8_anchor_evidence_digest: [u8; 32],
    dom_funding_id: [u8; 32],
    bitcoin_funding_id: [u8; 32],
    dom_shared_output_commitment: [u8; 33],
    expected_claim_template_hash: [u8; 32],
    expected_round_start_transcript_hash: [u8; 32],
    expected_adaptor_point: PublicKey,
    dom_confirmation_depth: u32,
    bitcoin_confirmation_depth: u32,
}

impl PostAnchorDomClaimSigningEvidenceV1 {
    fn consume_verified(
        verified: VerifiedF7AnchorAuthorizationV1,
    ) -> Result<Self, SessionStoreError> {
        let expected_adaptor_point =
            PublicKey::from_compressed_bytes(verified.adaptor_point_bytes())
                .map_err(|_| SessionStoreError::ClaimSigningAuthorityUnavailable)?;
        Ok(Self {
            chain_id: *verified.dom_chain_id(),
            session_id: *verified.session_id(),
            settlement_id: *verified.settlement_id(),
            terms_hash: *verified.terms_hash(),
            m8_policy_digest: *verified.m8_policy_digest(),
            m8_anchor_evidence_digest: *verified.anchor_evidence_digest(),
            dom_funding_id: *verified.dom_funding_id(),
            bitcoin_funding_id: *verified.bitcoin_funding_id(),
            dom_shared_output_commitment: *verified.dom_shared_output_commitment(),
            expected_claim_template_hash: *verified.claim_template_hash(),
            expected_round_start_transcript_hash: *verified.claim_round_start_transcript_hash(),
            expected_adaptor_point,
            dom_confirmation_depth: verified.dom_confirmation_depth(),
            bitcoin_confirmation_depth: verified.bitcoin_confirmation_depth(),
        })
    }
}

/// Linear, process-bound proof that one post-anchor claim-signing issuance is
/// durably present but has not yet crossed the nonce/signing boundary.
///
/// This value has no public constructor, codec, `Clone`, `Copy`, `Debug`, or
/// equality implementation. It must be consumed by
/// [`ContractsSessionStoreV1::consume_post_anchor_dom_claim_signing`] before a
/// signer is allowed to reserve a nonce.
pub struct ClaimSigningAuthorizationV1 {
    session_id: [u8; 32],
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
    m8_policy_digest: [u8; 32],
    m8_anchor_evidence_digest: [u8; 32],
    dom_funding_id: [u8; 32],
    bitcoin_funding_id: [u8; 32],
    dom_shared_output_commitment: [u8; 33],
    claim_template_hash: [u8; 32],
    round_start_transcript_hash: [u8; 32],
    adaptor_point: PublicKey,
    issuance_id: [u8; 32],
    issuance_record_digest: [u8; 32],
    bound_session_revision: u64,
    bound_session_record_digest: [u8; 32],
    dom_confirmation_depth: u32,
    bitcoin_confirmation_depth: u32,
    open_instance_id: [u8; 32],
}

impl ClaimSigningAuthorizationV1 {
    /// Returns the bound Contracts session.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Returns the frozen Interop settlement identifier.
    pub const fn settlement_id(&self) -> &[u8; 32] {
        &self.settlement_id
    }

    /// Returns the frozen pre-funding terms digest.
    pub const fn terms_hash(&self) -> &[u8; 32] {
        &self.terms_hash
    }

    /// Returns the canonical pre-funding M.8 policy digest.
    pub const fn m8_policy_digest(&self) -> &[u8; 32] {
        &self.m8_policy_digest
    }

    /// Returns the exact opaque M.8 anchor-evidence digest.
    pub const fn m8_anchor_evidence_digest(&self) -> &[u8; 32] {
        &self.m8_anchor_evidence_digest
    }

    /// Returns the exact authenticated DOM funding transaction identifier.
    pub const fn dom_funding_id(&self) -> &[u8; 32] {
        &self.dom_funding_id
    }

    /// Returns the exact authenticated Bitcoin funding transaction identifier.
    pub const fn bitcoin_funding_id(&self) -> &[u8; 32] {
        &self.bitcoin_funding_id
    }

    /// Returns the exact confidential DOM shared-output commitment.
    pub const fn dom_shared_output_commitment(&self) -> &[u8; 33] {
        &self.dom_shared_output_commitment
    }

    /// Returns the canonical DOM claim-template digest.
    pub const fn claim_template_hash(&self) -> &[u8; 32] {
        &self.claim_template_hash
    }

    /// Returns the authenticated claim-round predecessor transcript.
    pub const fn round_start_transcript_hash(&self) -> &[u8; 32] {
        &self.round_start_transcript_hash
    }

    /// Returns the frozen public adaptor point.
    pub const fn adaptor_point(&self) -> &PublicKey {
        &self.adaptor_point
    }

    /// Returns the immutable issuance-record digest for audit correlation.
    pub const fn issuance_record_digest(&self) -> &[u8; 32] {
        &self.issuance_record_digest
    }

    /// Returns the exact `FundingConfirmed` revision bound by this issuance.
    pub const fn bound_session_revision(&self) -> u64 {
        self.bound_session_revision
    }

    /// Returns the digest of that exact `FundingConfirmed` revision.
    pub const fn bound_session_record_digest(&self) -> &[u8; 32] {
        &self.bound_session_record_digest
    }

    /// Returns the real DOM confirmation depth proven at issuance.
    pub const fn dom_confirmation_depth(&self) -> u32 {
        self.dom_confirmation_depth
    }

    /// Returns the real Bitcoin confirmation depth proven at issuance.
    pub const fn bitcoin_confirmation_depth(&self) -> u32 {
        self.bitcoin_confirmation_depth
    }
}

/// Linear proof that post-anchor claim authority was durably consumed before
/// nonce reservation or signing.
///
/// This is the only capability intended for a production DOM claim signer.
/// It contains public bindings only and deliberately has no constructor,
/// codec, `Clone`, `Copy`, `Debug`, or equality implementation.
pub struct ConsumedClaimSigningAuthorizationV1 {
    session_id: [u8; 32],
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
    m8_policy_digest: [u8; 32],
    m8_anchor_evidence_digest: [u8; 32],
    dom_funding_id: [u8; 32],
    bitcoin_funding_id: [u8; 32],
    dom_shared_output_commitment: [u8; 33],
    claim_template_hash: [u8; 32],
    round_start_transcript_hash: [u8; 32],
    adaptor_point: PublicKey,
    issuance_id: [u8; 32],
    issuance_record_digest: [u8; 32],
    consumption_record_digest: [u8; 32],
    bound_session_revision: u64,
    bound_session_record_digest: [u8; 32],
    dom_confirmation_depth: u32,
    bitcoin_confirmation_depth: u32,
    _open_instance_id: [u8; 32],
}

impl ConsumedClaimSigningAuthorizationV1 {
    /// Returns the bound Contracts session.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Returns the frozen Interop settlement identifier.
    pub const fn settlement_id(&self) -> &[u8; 32] {
        &self.settlement_id
    }

    /// Returns the frozen pre-funding terms digest.
    pub const fn terms_hash(&self) -> &[u8; 32] {
        &self.terms_hash
    }

    /// Returns the canonical pre-funding M.8 policy digest.
    pub const fn m8_policy_digest(&self) -> &[u8; 32] {
        &self.m8_policy_digest
    }

    /// Returns the exact opaque M.8 anchor-evidence digest.
    pub const fn m8_anchor_evidence_digest(&self) -> &[u8; 32] {
        &self.m8_anchor_evidence_digest
    }

    /// Returns the exact authenticated DOM funding transaction identifier.
    pub const fn dom_funding_id(&self) -> &[u8; 32] {
        &self.dom_funding_id
    }

    /// Returns the exact authenticated Bitcoin funding transaction identifier.
    pub const fn bitcoin_funding_id(&self) -> &[u8; 32] {
        &self.bitcoin_funding_id
    }

    /// Returns the exact confidential DOM shared-output commitment.
    pub const fn dom_shared_output_commitment(&self) -> &[u8; 33] {
        &self.dom_shared_output_commitment
    }

    /// Returns the canonical DOM claim-template digest.
    pub const fn claim_template_hash(&self) -> &[u8; 32] {
        &self.claim_template_hash
    }

    /// Returns the authenticated claim-round predecessor transcript.
    pub const fn round_start_transcript_hash(&self) -> &[u8; 32] {
        &self.round_start_transcript_hash
    }

    /// Returns the frozen public adaptor point.
    pub const fn adaptor_point(&self) -> &PublicKey {
        &self.adaptor_point
    }

    /// Returns the original immutable issuance-record digest.
    pub const fn issuance_record_digest(&self) -> &[u8; 32] {
        &self.issuance_record_digest
    }

    /// Returns the durable consumption-record digest.
    pub const fn consumption_record_digest(&self) -> &[u8; 32] {
        &self.consumption_record_digest
    }

    /// Returns the exact `FundingConfirmed` revision bound by this authority.
    pub const fn bound_session_revision(&self) -> u64 {
        self.bound_session_revision
    }

    /// Returns the digest of that exact `FundingConfirmed` revision.
    pub const fn bound_session_record_digest(&self) -> &[u8; 32] {
        &self.bound_session_record_digest
    }

    /// Returns the real DOM confirmation depth proven at issuance.
    pub const fn dom_confirmation_depth(&self) -> u32 {
        self.dom_confirmation_depth
    }

    /// Returns the real Bitcoin confirmation depth proven at issuance.
    pub const fn bitcoin_confirmation_depth(&self) -> u32 {
        self.bitcoin_confirmation_depth
    }
}

impl AuthenticatedContractsRefundV1 {
    /// Returns the lifetime-unique Contracts session identifier.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Returns the canonical DOM hash of the exact authenticated refund.
    pub const fn transaction_hash(&self) -> &[u8; 32] {
        &self.transaction_hash
    }

    /// Returns the domain-separated digest of the exact canonical bytes.
    pub const fn exact_bytes_digest(&self) -> &[u8; 32] {
        &self.exact_bytes_digest
    }

    /// Returns the digest of the immutable funding/refund artifact record.
    pub const fn funding_artifact_digest(&self) -> &[u8; 32] {
        &self.funding_artifact_digest
    }

    /// Returns the digest of the exact funding-consumption record.
    pub const fn funding_consumption_digest(&self) -> &[u8; 32] {
        &self.funding_consumption_digest
    }

    /// Returns the historical `FundingBroadcast` session-record digest.
    pub const fn funding_broadcast_record_digest(&self) -> &[u8; 32] {
        &self.funding_broadcast_record_digest
    }

    /// Returns the current `RefundBroadcast` or `Refunded` record digest.
    pub const fn refund_phase_record_digest(&self) -> &[u8; 32] {
        &self.refund_phase_record_digest
    }
}

/// Opaque, authenticated reconstruction of the durable post-anchor Claim
/// adaptor pre-signature.
///
/// The Store issues this value only after replaying the complete retained
/// `SigNonceCommit -> SigNonceReveal -> SigPartial` prefix, verifying both
/// partial equations, aggregating with the pinned DOM authority, and fsyncing
/// the exact canonical 162-byte result. The value deliberately implements no
/// `Clone`, `Copy`, `Debug`, equality, or codec trait. Its one consuming
/// extraction is intended exclusively for the DOM-leg finalizer.
pub struct AuthenticatedPostAnchorClaimPreSignatureV1 {
    session_id: [u8; 32],
    claim_template_hash: [u8; 32],
    reveal_transcript_hash: [u8; 32],
    artifact_record_digest: [u8; 32],
    pre_signature: AdaptorPreSignatureV1,
}

impl AuthenticatedPostAnchorClaimPreSignatureV1 {
    /// Lifetime-unique Contracts session owning the retained round.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Exact canonical DOM claim template authenticated by the Store.
    pub const fn claim_template_hash(&self) -> &[u8; 32] {
        &self.claim_template_hash
    }

    /// Transcript immediately after both nonce reveals and before partials.
    pub const fn reveal_transcript_hash(&self) -> &[u8; 32] {
        &self.reveal_transcript_hash
    }

    /// Domain-separated digest of the immutable retained artifact record.
    pub const fn artifact_record_digest(&self) -> &[u8; 32] {
        &self.artifact_record_digest
    }

    /// Consumes the Store authentication handle into the verified DOM object.
    pub fn into_pre_signature(self) -> AdaptorPreSignatureV1 {
        self.pre_signature
    }
}

/// Linear immutable view of one signing session authenticated by the Store.
///
/// Private authority bindings include the exact durable session revision and
/// digest that were current when the handle was issued. The type deliberately
/// has no public constructor, codec, `Clone`, `Copy`, or `Debug` implementation.
pub struct AcceptedContractsSigningSessionV1 {
    trusted_chain_id: TrustedChainIdV1,
    session_id: [u8; 32],
    contract_kind: ContractKindV1,
    purpose: PurposeV1,
    roster: ParticipantRosterV1,
    transaction_template: Transaction,
    kernel_index: usize,
    adaptor_point: Option<PublicKey>,
    initial_transcript_hash: [u8; 32],
    round_start_transcript_hash: [u8; 32],
    sender_sequence_bases: [u64; 2],
    accepted_messages: Vec<Vec<u8>>,
    _session_revision: u64,
    _session_record_digest: [u8; 32],
    _open_instance_id: [u8; 32],
    _post_anchor_consumption_digest: Option<[u8; 32]>,
}

impl AcceptedSigningSessionV1 for AcceptedContractsSigningSessionV1 {
    fn trusted_chain_id(&self) -> &TrustedChainIdV1 {
        &self.trusted_chain_id
    }

    fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    fn contract_kind(&self) -> ContractKindV1 {
        self.contract_kind
    }

    fn purpose(&self) -> PurposeV1 {
        self.purpose
    }

    fn roster(&self) -> &ParticipantRosterV1 {
        &self.roster
    }

    fn transaction_template(&self) -> &Transaction {
        &self.transaction_template
    }

    fn kernel_index(&self) -> usize {
        self.kernel_index
    }

    fn adaptor_point(&self) -> Option<&PublicKey> {
        self.adaptor_point.as_ref()
    }

    fn initial_transcript_hash(&self) -> &[u8; 32] {
        &self.initial_transcript_hash
    }

    fn accepted_signing_messages(&self) -> impl Iterator<Item = &[u8]> {
        self.accepted_messages.iter().map(Vec::as_slice)
    }
}

impl AcceptedOperationalSigningSessionV1 for AcceptedContractsSigningSessionV1 {
    fn round_start_transcript_hash(&self) -> &[u8; 32] {
        &self.round_start_transcript_hash
    }

    fn sender_sequence_bases(&self) -> &[u64; 2] {
        &self.sender_sequence_bases
    }
}

/// Retained-capability operational store for authenticated session records.
///
/// This is a sibling authority to the nonce vault. It never derives, stores,
/// exports, or recreates a nonce.
pub struct ContractsSessionStoreV1 {
    root: RetainedDirectory,
    records: RetainedDirectory,
    artifacts: RetainedDirectory,
    consumptions: RetainedDirectory,
    rosters: RetainedDirectory,
    messages: RetainedDirectory,
    reservation_lookups: RetainedDirectory,
    _retained_lock: RetainedExclusiveLock,
    policy: BudgetPolicyV1,
    _store_id: [u8; 32],
    open_instance_id: [u8; 32],
    operation: Mutex<()>,
    process_funding_authorities: Mutex<BTreeSet<[u8; 32]>>,
    process_claim_signing_authorities: Mutex<BTreeSet<[u8; 32]>>,
}

/// Opaque proof that the Contracts session store authenticated an immutable
/// terminal session successor for collaborative-secret retirement.
///
/// This value has no public constructor, codec, `Clone`, or `Debug`. It is
/// consumed by the sibling retained nonce vault, which persists its exact
/// session and record binding before deleting any encrypted collaborative
/// material.
pub struct TerminalCollaborativeSessionEvidenceV1 {
    session_id: [u8; 32],
    terminal_phase: SessionPhaseV1,
    terminal_record_digest: [u8; 32],
}

impl TerminalCollaborativeSessionEvidenceV1 {
    pub(super) const fn into_parts(self) -> ([u8; 32], SessionPhaseV1, [u8; 32]) {
        (
            self.session_id,
            self.terminal_phase,
            self.terminal_record_digest,
        )
    }
}

impl ContractsSessionStoreV1 {
    /// Creates a production-composition session store with an explicit,
    /// separately ratified production policy. No default policy exists.
    pub fn create_production(
        parent: Arc<Dir>,
        root_name: &str,
        policy: BudgetPolicyV1,
    ) -> Result<Self, SessionStoreError> {
        if policy.profile() != BudgetPolicyProfileV1::ProductionRatified {
            return Err(SessionStoreError::PolicyProfile);
        }
        Self::create(parent, root_name, policy)
    }

    /// Reopens a production-composition session store with the exact explicit
    /// policy expected by the trusted composition root.
    pub fn open_production(
        parent: Arc<Dir>,
        root_name: &str,
        policy: BudgetPolicyV1,
    ) -> Result<Self, SessionStoreError> {
        if policy.profile() != BudgetPolicyProfileV1::ProductionRatified {
            return Err(SessionStoreError::PolicyProfile);
        }
        Self::open(parent, root_name, policy)
    }

    /// Creates an evidence-only store. This constructor is absent unless the
    /// explicit evidence feature (or unit-test build) is active.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn create_evidence_only(
        parent: Arc<Dir>,
        root_name: &str,
        policy: BudgetPolicyV1,
    ) -> Result<Self, SessionStoreError> {
        if policy.profile() != BudgetPolicyProfileV1::EvidenceOnly {
            return Err(SessionStoreError::PolicyProfile);
        }
        Self::create(parent, root_name, policy)
    }

    /// Reopens an evidence-only store under its retained lock.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn open_evidence_only(
        parent: Arc<Dir>,
        root_name: &str,
        policy: BudgetPolicyV1,
    ) -> Result<Self, SessionStoreError> {
        if policy.profile() != BudgetPolicyProfileV1::EvidenceOnly {
            return Err(SessionStoreError::PolicyProfile);
        }
        Self::open(parent, root_name, policy)
    }

    /// Returns the exact authenticated policy supplied by the composition
    /// root and persisted at store creation.
    pub const fn policy(&self) -> &BudgetPolicyV1 {
        &self.policy
    }

    /// Borrows the retained session store as the production reservation-lookup
    /// custody selected by [`dom_adaptor::VaultBackedSignerV1`].
    ///
    /// The returned value cannot outlive this store and cannot reopen or clone
    /// its authority. All mutations remain serialized by the store's retained
    /// process lock and operation mutex.
    pub const fn reservation_lookup_custody(&self) -> ContractsReservationLookupCustodyV1<'_> {
        ContractsReservationLookupCustodyV1 { store: self }
    }

    /// Returns the zero-state marker selecting this Store's operational
    /// signing-session authority in `VaultBackedSignerV1`.
    pub const fn operational_signing_session_authority(
        &self,
    ) -> ContractsSigningSessionAuthorityV1 {
        ContractsSigningSessionAuthorityV1 { _private: () }
    }

    fn create(
        parent: Arc<Dir>,
        root_name: &str,
        policy: BudgetPolicyV1,
    ) -> Result<Self, SessionStoreError> {
        let root = RetainedDirectory::create_under(
            parent,
            ValidatedComponent::operator_selected_root(root_name)?,
        )?;
        let store_id = random_nonzero()?;
        let root_bytes = encode_root_identity(store_id, *policy.policy_digest());
        let lock_bytes =
            encode_lock_identity(store_id, tagged_hash(ROOT_HASH_TAG, &root_bytes[..80]));
        root.create_immutable_file(
            &ValidatedComponent::registered(ROOT_IDENTITY_NAME)?,
            &root_bytes,
        )?;
        root.create_immutable_file(
            &ValidatedComponent::registered(LOCK_IDENTITY_NAME)?,
            &lock_bytes,
        )?;
        root.create_immutable_file(
            &ValidatedComponent::registered(POLICY_NAME)?,
            policy.as_bytes(),
        )?;
        let records = root.create_child_directory(ValidatedComponent::registered(RECORDS_NAME)?)?;
        let artifacts =
            root.create_child_directory(ValidatedComponent::registered(ARTIFACTS_NAME)?)?;
        let consumptions =
            root.create_child_directory(ValidatedComponent::registered(CONSUMPTIONS_NAME)?)?;
        let rosters = root.create_child_directory(ValidatedComponent::registered(ROSTERS_NAME)?)?;
        let messages =
            root.create_child_directory(ValidatedComponent::registered(MESSAGES_NAME)?)?;
        let reservation_lookups =
            root.create_child_directory(ValidatedComponent::registered(RESERVATION_LOOKUPS_NAME)?)?;
        records.sync()?;
        artifacts.sync()?;
        consumptions.sync()?;
        rosters.sync()?;
        messages.sync()?;
        reservation_lookups.sync()?;
        root.sync()?;
        let retained_lock =
            root.acquire_lock(&ValidatedComponent::registered(LOCK_IDENTITY_NAME)?)?;
        let store = Self {
            root,
            records,
            artifacts,
            consumptions,
            rosters,
            messages,
            reservation_lookups,
            _retained_lock: retained_lock,
            policy,
            _store_id: store_id,
            open_instance_id: random_nonzero()?,
            operation: Mutex::new(()),
            process_funding_authorities: Mutex::new(BTreeSet::new()),
            process_claim_signing_authorities: Mutex::new(BTreeSet::new()),
        };
        store.recover_operational_funding_issuances()?;
        store.recover_consumed_funding()?;
        store.recover_transport_messages()?;
        store.audit_locked()?;
        Ok(store)
    }

    fn open(
        parent: Arc<Dir>,
        root_name: &str,
        policy: BudgetPolicyV1,
    ) -> Result<Self, SessionStoreError> {
        let root = RetainedDirectory::open_under(
            parent,
            ValidatedComponent::operator_selected_root(root_name)?,
        )?;
        let retained_lock =
            root.acquire_lock(&ValidatedComponent::registered(LOCK_IDENTITY_NAME)?)?;
        require_root_inventory(&root)?;
        let persisted_policy = BudgetPolicyV1::from_bytes(&root.read_bounded_file(
            &ValidatedComponent::registered(POLICY_NAME)?,
            BUDGET_POLICY_LEN,
        )?)?;
        if persisted_policy.as_bytes() != policy.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
        let root_bytes = root.read_bounded_file(
            &ValidatedComponent::registered(ROOT_IDENTITY_NAME)?,
            ROOT_IDENTITY_LEN,
        )?;
        let store_id = decode_root_identity(&root_bytes, policy.policy_digest())?;
        let lock_bytes = root.read_bounded_file(
            &ValidatedComponent::registered(LOCK_IDENTITY_NAME)?,
            LOCK_IDENTITY_LEN,
        )?;
        decode_lock_identity(
            &lock_bytes,
            store_id,
            tagged_hash(ROOT_HASH_TAG, &root_bytes[..80]),
        )?;
        let records = root.open_child_directory(ValidatedComponent::registered(RECORDS_NAME)?)?;
        let artifacts =
            root.open_child_directory(ValidatedComponent::registered(ARTIFACTS_NAME)?)?;
        let consumptions =
            root.open_child_directory(ValidatedComponent::registered(CONSUMPTIONS_NAME)?)?;
        let rosters = root.open_child_directory(ValidatedComponent::registered(ROSTERS_NAME)?)?;
        let messages = root.open_child_directory(ValidatedComponent::registered(MESSAGES_NAME)?)?;
        let reservation_lookups =
            root.open_child_directory(ValidatedComponent::registered(RESERVATION_LOOKUPS_NAME)?)?;
        recover_staging(&records)?;
        recover_staging(&artifacts)?;
        recover_staging(&consumptions)?;
        recover_staging(&rosters)?;
        recover_staging(&messages)?;
        recover_staging(&reservation_lookups)?;
        let store = Self {
            root,
            records,
            artifacts,
            consumptions,
            rosters,
            messages,
            reservation_lookups,
            _retained_lock: retained_lock,
            policy,
            _store_id: store_id,
            open_instance_id: random_nonzero()?,
            operation: Mutex::new(()),
            process_funding_authorities: Mutex::new(BTreeSet::new()),
            process_claim_signing_authorities: Mutex::new(BTreeSet::new()),
        };
        store.recover_operational_funding_issuances()?;
        store.recover_consumed_funding()?;
        store.recover_transport_messages()?;
        store.audit_locked()?;
        Ok(store)
    }

    /// Creates one revision-zero authenticated session record durably.
    /// Funding-authorized or already-broadcast records cannot enter through
    /// this import boundary.
    pub fn create_session(
        &self,
        initial: &SessionRecordV1,
    ) -> Result<SessionRecordV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        if initial.revision() != 0
            || initial.irreversible().funding_authorized
            || is_funding_or_later_economic_phase(initial.phase())
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        match self.load_session_locked(initial.session_id()) {
            Ok(_) => return Err(SessionStoreError::Conflict),
            Err(SessionStoreError::SessionNotFound) => {}
            Err(error) => return Err(error),
        }
        self.persist_session_record(initial)?;
        self.load_session_locked(initial.session_id())
    }

    /// Loads and authenticates the complete contiguous history, returning its
    /// current record.
    pub fn load_session(&self, session_id: [u8; 32]) -> Result<SessionRecordV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.load_session_locked(session_id)
    }

    /// Loads the unique still-custodied public retry lookup for an exact
    /// session and reservation-context binding after restart.
    ///
    /// An abandoned lookup is terminal and is never returned. A duplicate,
    /// malformed, mismatched, or missing record fails closed; no fresh lookup
    /// is generated by this read path.
    pub fn load_custodied_reservation_lookup(
        &self,
        session_id: [u8; 32],
        context_binding_digest: [u8; 32],
    ) -> Result<ReservationRequestLookupV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let record = self.unique_reservation_lookup_record(
            session_id,
            context_binding_digest,
            ReservationLookupStateV1::Custodied,
        )?;
        if self.reservation_lookup_abandonment_exists(&record.request_lookup)? {
            return Err(SessionStoreError::InvalidTransition);
        }
        ReservationRequestLookupV1::from_bytes(record.request_lookup)
            .map_err(|_| SessionStoreError::Quarantined)
    }

    /// Authenticates candidate DOM refund bytes against the exact immutable
    /// artifact, operational funding commit, funding consumption, historical
    /// `FundingBroadcast`, and current refund-path session record.
    ///
    /// `RefundEligible` is intentionally rejected: bytes have not yet crossed
    /// the linear Store-issued refund broadcast authority in that phase.
    pub fn authenticate_persisted_refund(
        &self,
        session_id: [u8; 32],
        candidate_exact_bytes: &[u8],
    ) -> Result<AuthenticatedContractsRefundV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(session_id)?;
        if !matches!(
            current.phase(),
            SessionPhaseV1::RefundBroadcast | SessionPhaseV1::Refunded
        ) {
            return Err(SessionStoreError::InvalidTransition);
        }
        let artifact = self.load_artifact(session_id)?;
        let consumption = self.load_consumption(session_id)?;
        if artifact.session_id != session_id
            || artifact.digest != consumption.artifact_digest
            || artifact.authorized_revision != consumption.authorized_revision
            || artifact.refund_bytes.as_slice() != candidate_exact_bytes
        {
            return Err(SessionStoreError::Quarantined);
        }
        match (
            self.issuance_exists(session_id)?,
            self.m8_issuance_exists(session_id)?,
        ) {
            (true, false) => {
                if self.m8_funding_commit_exists(session_id)? {
                    return Err(SessionStoreError::Quarantined);
                }
                let commit = self.load_funding_commit(session_id)?;
                if commit.artifact.bytes != artifact.bytes
                    || commit.consumption.bytes != consumption.bytes
                {
                    return Err(SessionStoreError::Quarantined);
                }
                self.verify_operational_commit_against_authority(&commit)?;
            }
            (false, true) => {
                if self.funding_commit_exists(session_id)? {
                    return Err(SessionStoreError::Quarantined);
                }
                let commit = self.load_m8_funding_commit(session_id)?;
                if commit.artifact.bytes != artifact.bytes
                    || commit.consumption.bytes != consumption.bytes
                {
                    return Err(SessionStoreError::Quarantined);
                }
                self.verify_m8_commit_against_authority(&commit)?;
            }
            _ => return Err(SessionStoreError::Quarantined),
        }
        let candidate = <Transaction as DomDeserialize>::from_bytes(candidate_exact_bytes)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        if candidate
            .to_bytes()
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?
            != candidate_exact_bytes
            || candidate.kernels.is_empty()
            || candidate.kernels.iter().any(|kernel| {
                kernel.features != KERNEL_FEAT_HEIGHT_LOCKED
                    || kernel.lock_height != artifact.refund_unlock_height
            })
        {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
        let funding_broadcast = consumption.broadcast_record()?;
        let durable_funding_broadcast =
            self.load_session_revision(session_id, funding_broadcast.revision())?;
        if funding_broadcast.phase() != SessionPhaseV1::FundingBroadcast
            || durable_funding_broadcast.as_bytes() != funding_broadcast.as_bytes()
            || funding_broadcast.digest() != &consumption.broadcast_record_digest
        {
            return Err(SessionStoreError::Quarantined);
        }
        let transaction_hash = *dom_crypto::blake2b_256(candidate_exact_bytes).as_bytes();
        if transaction_hash == [0; 32] {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
        Ok(AuthenticatedContractsRefundV1 {
            session_id,
            transaction_hash,
            exact_bytes_digest: tagged_hash(REFUND_HASH_TAG, candidate_exact_bytes),
            funding_artifact_digest: artifact.digest,
            funding_consumption_digest: copy_array(
                &consumption.bytes[consumption.bytes.len() - DIGEST_LEN..],
            )?,
            funding_broadcast_record_digest: consumption.broadcast_record_digest,
            refund_phase_record_digest: *current.digest(),
        })
    }

    /// Durably issues the only post-anchor DOM claim-signing authorization.
    ///
    /// The current head must be the exact `FundingConfirmed` revision named by
    /// the Store-free full real-chain authority. This method consumes its
    /// non-forgeable result, reauthenticates the complete M.8 funding commit and
    /// frozen ClaimAdaptor binding, then fsyncs an immutable issuance before
    /// returning. It does not reserve a nonce or expose signing authority yet.
    pub fn issue_post_anchor_dom_claim_signing(
        &self,
        verified_anchors: VerifiedF7AnchorAuthorizationV1,
    ) -> Result<ClaimSigningAuthorizationV1, SessionStoreError> {
        let evidence = PostAnchorDomClaimSigningEvidenceV1::consume_verified(verified_anchors)?;
        let _guard = self.operation_lock()?;
        if self
            .load_post_anchor_claim_authorization(
                evidence.session_id,
                PostAnchorClaimAuthorizationStateV1::Issued,
            )
            .is_ok()
            || self.post_anchor_claim_consumption_exists(evidence.session_id)?
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let (current, m8_funding_gate_digest, m8_funding_issuance_digest, funding_commit_digest) =
            self.authenticate_post_anchor_claim_evidence(&evidence)?;
        let record = PostAnchorClaimAuthorizationRecordV1::new_issued(
            &evidence,
            &current,
            m8_funding_gate_digest,
            m8_funding_issuance_digest,
            funding_commit_digest,
            random_nonzero()?,
        )?;
        self.persist_post_anchor_claim_authorization(&record)?;
        test_crash_hook("post-anchor-claim-after-issuance-persist");
        let durable = self.load_post_anchor_claim_authorization(
            evidence.session_id,
            PostAnchorClaimAuthorizationStateV1::Issued,
        )?;
        if durable.bytes != record.bytes
            || !self
                .process_claim_signing_authorities
                .lock()
                .map_err(|_| SessionStoreError::StoreBusy)?
                .insert(record.issuance_id)
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        record.issued_capability(self.open_instance_id)
    }

    /// Rehydrates the same immutable unconsumed issuance after a crash.
    ///
    /// No issuance identifier, revision, or digest is reminted. A second live
    /// process-local handle for the same retained Store is rejected.
    pub fn resume_post_anchor_dom_claim_signing(
        &self,
        session_id: [u8; 32],
    ) -> Result<ClaimSigningAuthorizationV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let issued = self.load_post_anchor_claim_authorization(
            session_id,
            PostAnchorClaimAuthorizationStateV1::Issued,
        )?;
        if self.post_anchor_claim_consumption_exists(session_id)? {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        self.authenticate_post_anchor_claim_record(&issued)?;
        if !self
            .process_claim_signing_authorities
            .lock()
            .map_err(|_| SessionStoreError::StoreBusy)?
            .insert(issued.issuance_id)
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        issued.issued_capability(self.open_instance_id)
    }

    /// Durably consumes an issuance before any claim nonce may be reserved or
    /// any DOM claim share may be signed.
    pub fn consume_post_anchor_dom_claim_signing(
        &self,
        authorization: ClaimSigningAuthorizationV1,
    ) -> Result<ConsumedClaimSigningAuthorizationV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        if authorization.open_instance_id != self.open_instance_id
            || !self
                .process_claim_signing_authorities
                .lock()
                .map_err(|_| SessionStoreError::StoreBusy)?
                .contains(&authorization.issuance_id)
            || self.post_anchor_claim_consumption_exists(authorization.session_id)?
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let issued = self.load_post_anchor_claim_authorization(
            authorization.session_id,
            PostAnchorClaimAuthorizationStateV1::Issued,
        )?;
        if issued.issuance_id != authorization.issuance_id
            || issued.digest != authorization.issuance_record_digest
            || issued.session_id != authorization.session_id
            || issued.settlement_id != authorization.settlement_id
            || issued.terms_hash != authorization.terms_hash
            || issued.m8_policy_digest != authorization.m8_policy_digest
            || issued.m8_anchor_evidence_digest != authorization.m8_anchor_evidence_digest
            || issued.dom_funding_id != authorization.dom_funding_id
            || issued.bitcoin_funding_id != authorization.bitcoin_funding_id
            || issued.dom_shared_output_commitment != authorization.dom_shared_output_commitment
            || issued.claim_template_hash != authorization.claim_template_hash
            || issued.round_start_transcript_hash != authorization.round_start_transcript_hash
            || issued.adaptor_point != authorization.adaptor_point
            || issued.bound_session_revision != authorization.bound_session_revision
            || issued.bound_session_record_digest != authorization.bound_session_record_digest
            || issued.dom_confirmation_depth != authorization.dom_confirmation_depth
            || issued.bitcoin_confirmation_depth != authorization.bitcoin_confirmation_depth
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        self.authenticate_post_anchor_claim_record(&issued)?;
        let consumed = PostAnchorClaimAuthorizationRecordV1::new_consumed(&issued)?;
        self.persist_post_anchor_claim_authorization(&consumed)?;
        test_crash_hook("post-anchor-claim-after-consumption-persist");
        let durable = self.load_post_anchor_claim_authorization(
            authorization.session_id,
            PostAnchorClaimAuthorizationStateV1::Consumed,
        )?;
        if durable.bytes != consumed.bytes {
            return Err(SessionStoreError::Quarantined);
        }
        consumed.consumed_capability(&issued, self.open_instance_id)
    }

    /// Rehydrates the same consumed authority after a crash between durable
    /// consumption and signer entry. It never recreates an unconsumed token.
    pub fn resume_consumed_post_anchor_dom_claim_signing(
        &self,
        session_id: [u8; 32],
    ) -> Result<ConsumedClaimSigningAuthorizationV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let issued = self.load_post_anchor_claim_authorization(
            session_id,
            PostAnchorClaimAuthorizationStateV1::Issued,
        )?;
        let consumed = self.load_post_anchor_claim_authorization(
            session_id,
            PostAnchorClaimAuthorizationStateV1::Consumed,
        )?;
        if consumed.predecessor_digest != issued.digest
            || consumed.issuance_id != issued.issuance_id
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        self.audit_post_anchor_claim_authorization(&issued, Some(&consumed))?;
        if !self
            .process_claim_signing_authorities
            .lock()
            .map_err(|_| SessionStoreError::StoreBusy)?
            .insert(issued.issuance_id)
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        consumed.consumed_capability(&issued, self.open_instance_id)
    }

    /// Authenticates the current complete session history and issues a
    /// one-shot bridge to the independent collaborative-secret vault only
    /// when the durable head is economically terminal.
    pub fn authorize_collaborative_secret_retirement(
        &self,
        session_id: [u8; 32],
    ) -> Result<TerminalCollaborativeSessionEvidenceV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(session_id)?;
        if !matches!(
            current.phase(),
            SessionPhaseV1::Settled
                | SessionPhaseV1::Refunded
                | SessionPhaseV1::Aborted
                | SessionPhaseV1::FailedClosed
        ) {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(TerminalCollaborativeSessionEvidenceV1 {
            session_id,
            terminal_phase: current.phase(),
            terminal_record_digest: *current.digest(),
        })
    }

    /// Freezes and issues one operational signing-session view over the single
    /// global DSC1 journal.
    ///
    /// Both participants' exact canonical 160-byte `TxTemplateCommit`
    /// messages, the complete transport roster, aggregate kernel key, current
    /// phase, round predecessor transcript, and global sender sequence bases
    /// are authenticated before an immutable binding record is fsynced. The
    /// returned handle has no public constructor or codec.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_operational_signing_session(
        &self,
        trusted_chain_id: TrustedChainIdV1,
        session_id: [u8; 32],
        contract_kind: ContractKindV1,
        purpose: PurposeV1,
        roster: ParticipantRosterV1,
        transaction_template: Transaction,
        kernel_index: usize,
        adaptor_point: Option<PublicKey>,
    ) -> Result<AcceptedContractsSigningSessionV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let current = self.load_session_locked(session_id)?;
        let transport_roster = self.load_transport_roster(session_id)?;
        let identity_binding = self.load_transport_identity_binding(session_id)?;
        require_transport_identity_binding(&transport_roster, &identity_binding)?;
        validate_operational_signing_inputs(
            &trusted_chain_id,
            &current,
            contract_kind,
            purpose,
            &roster,
            &transaction_template,
            kernel_index,
            adaptor_point.as_ref(),
            &transport_roster,
        )?;
        let canonical_transaction = canonical_dom_transaction_bytes_v1(&transaction_template)?;
        let (_, template_hash) = canonical_template_v1(&transaction_template)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let initial_transcript_hash =
            initial_transcript_hash_v1(&trusted_chain_id, &session_id, contract_kind, &roster);
        let round = self.audit_operational_signing_round(
            session_id,
            purpose,
            &roster,
            template_hash,
            signing_phase_for_purpose(purpose),
        )?;
        let binding = SigningSessionBindingRecordV1::new(
            &trusted_chain_id,
            &current,
            contract_kind,
            purpose,
            &roster,
            &canonical_transaction,
            template_hash,
            kernel_index,
            adaptor_point.as_ref(),
            initial_transcript_hash,
            &round,
        )?;
        self.persist_signing_binding(&binding)?;
        let durable = self.load_signing_binding(session_id, purpose)?;
        if durable.bytes != binding.bytes {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(AcceptedContractsSigningSessionV1 {
            trusted_chain_id,
            session_id,
            contract_kind,
            purpose,
            roster,
            transaction_template,
            kernel_index,
            adaptor_point,
            initial_transcript_hash,
            round_start_transcript_hash: round.round_start_transcript_hash,
            sender_sequence_bases: round.sender_sequence_bases,
            accepted_messages: round.accepted_messages,
            _session_revision: round.round_start_revision,
            _session_record_digest: round.round_start_record_digest,
            _open_instance_id: self.open_instance_id,
            _post_anchor_consumption_digest: None,
        })
    }

    /// Reissues a process-local operational handle after restart solely from
    /// the immutable binding and the reauthenticated global DSC1 journal.
    /// Caller-shaped roster, transaction, adaptor, transcript, or sequence
    /// values are deliberately absent from this recovery boundary.
    pub fn resume_operational_signing_session(
        &self,
        trusted_chain_id: TrustedChainIdV1,
        session_id: [u8; 32],
        purpose: PurposeV1,
    ) -> Result<AcceptedContractsSigningSessionV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let binding = self.load_signing_binding(session_id, purpose)?;
        let decoded = binding.decode(&trusted_chain_id)?;
        let current = self.load_session_locked(session_id)?;
        let transport_roster = self.load_transport_roster(session_id)?;
        let identity_binding = self.load_transport_identity_binding(session_id)?;
        require_transport_identity_binding(&transport_roster, &identity_binding)?;
        let recomputed_initial = initial_transcript_hash_v1(
            &trusted_chain_id,
            &session_id,
            decoded.contract_kind,
            &decoded.roster,
        );
        if binding.bytes[80..112] != current.terms_hash()
            || decoded.initial_transcript_hash != recomputed_initial
        {
            return Err(SessionStoreError::Quarantined);
        }
        validate_operational_signing_inputs(
            &trusted_chain_id,
            &current,
            decoded.contract_kind,
            purpose,
            &decoded.roster,
            &decoded.transaction_template,
            decoded.kernel_index,
            decoded.adaptor_point.as_ref(),
            &transport_roster,
        )?;
        let round = self.audit_operational_signing_round(
            session_id,
            purpose,
            &decoded.roster,
            decoded.template_hash,
            signing_phase_for_purpose(purpose),
        )?;
        if round.round_start_transcript_hash != decoded.round_start_transcript_hash
            || round.sender_sequence_bases != decoded.sender_sequence_bases
            || round.round_start_revision != decoded.round_start_revision
            || round.round_start_record_digest != decoded.round_start_record_digest
            || round.template_commit_payload != decoded.template_commit_payload
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(AcceptedContractsSigningSessionV1 {
            trusted_chain_id,
            session_id,
            contract_kind: decoded.contract_kind,
            purpose,
            roster: decoded.roster,
            transaction_template: decoded.transaction_template,
            kernel_index: decoded.kernel_index,
            adaptor_point: decoded.adaptor_point,
            initial_transcript_hash: decoded.initial_transcript_hash,
            round_start_transcript_hash: round.round_start_transcript_hash,
            sender_sequence_bases: round.sender_sequence_bases,
            accepted_messages: round.accepted_messages,
            _session_revision: round.round_start_revision,
            _session_record_digest: round.round_start_record_digest,
            _open_instance_id: self.open_instance_id,
            _post_anchor_consumption_digest: None,
        })
    }

    /// Reconstructs the exact authenticated collaborative-BP continuation.
    ///
    /// The caller supplies the frozen typed statement and the exact typed
    /// recovery capsule because the session Store deliberately does not own
    /// the sibling collaborative-secret vault. Raw capsule bytes or a caller-
    /// supplied digest are not accepted. The Store reauthenticates its full
    /// DSC1 journal and retained roster/identity references, then accepts only
    /// the canonical `0x05..=0x0a` prefix with exact revisions, predecessor
    /// transcripts, directions, sender-local sequences, payload lengths,
    /// typed shares, commitments, aggregates, and final proof.
    pub fn resume_operational_bp_continuation(
        &self,
        trusted_chain_id: TrustedChainIdV1,
        session_id: [u8; 32],
        expected_terms_hash: [u8; 32],
        statement: &BpStatementV1,
        recovery_capsule: &RecoveryCapsule,
    ) -> Result<AuthenticatedOperationalBpContinuationV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let current = self.load_session_locked(session_id)?;
        let roster = self.load_transport_roster(session_id)?;
        let identity_binding = self.load_transport_identity_binding(session_id)?;
        require_transport_identity_binding(&roster, &identity_binding)?;
        if trusted_chain_id.as_bytes() == &[0; 32]
            || expected_terms_hash == [0; 32]
            || current.terms_hash() != expected_terms_hash
            || roster.chain_id != *trusted_chain_id.as_bytes()
            || roster.session_id != session_id
            || statement.chain_id() != roster.chain_id
            || statement.session_id() != session_id
            || statement.participant_ids().len() != 2
            || statement.commitment_shares().len() != 2
            || statement.participant_ids().iter().any(|statement_id| {
                !roster
                    .participants
                    .iter()
                    .any(|participant| participant.participant_id == *statement_id)
            })
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let canonical_statement =
            BpStatementV1::from_bytes(statement.to_bytes(), &trusted_chain_id)
                .map_err(|_| SessionStoreError::Canonical)?;
        if canonical_statement.to_bytes() != statement.to_bytes()
            || canonical_statement.statement_hash() != statement.statement_hash()
            || blake2b_256(recovery_capsule.as_bytes()).as_bytes()
                != statement.recovery_binding_hash()
        {
            return Err(SessionStoreError::Quarantined);
        }
        let verifier =
            DomCollaborativeRangeProofV1::new(statement, recovery_capsule.as_bytes().to_vec())
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        self.audit_operational_bp_continuation(session_id, &current, &roster, statement, &verifier)
    }

    /// Binds the post-anchor ClaimAdaptor signing round after the dedicated
    /// authorization was durably consumed.
    ///
    /// Unlike the legacy pre-funding ClaimSigning path, this method keeps the
    /// economic phase at `FundingConfirmed`. The linear consumed capability,
    /// exact unchanged anchor projection, canonical template, adaptor point,
    /// global DSC1 ancestry, and two-party roster are all authenticated before
    /// the signing-session view is returned.
    pub fn bind_post_anchor_dom_claim_signing_session(
        &self,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        trusted_chain_id: TrustedChainIdV1,
        contract_kind: ContractKindV1,
        roster: ParticipantRosterV1,
        transaction_template: Transaction,
        kernel_index: usize,
    ) -> Result<AcceptedContractsSigningSessionV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let (issued, _consumed, current) =
            self.authenticate_live_consumed_claim_authority(authorization)?;
        if trusted_chain_id.as_bytes() != &issued.chain_id {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let transport_roster = self.load_transport_roster(issued.session_id)?;
        let identity_binding = self.load_transport_identity_binding(issued.session_id)?;
        require_transport_identity_binding(&transport_roster, &identity_binding)?;
        validate_post_anchor_signing_inputs(
            &trusted_chain_id,
            &current,
            contract_kind,
            &roster,
            &transaction_template,
            kernel_index,
            &issued.adaptor_point,
            &transport_roster,
        )?;
        let canonical_transaction = canonical_dom_transaction_bytes_v1(&transaction_template)?;
        let (_, template_hash) = canonical_template_v1(&transaction_template)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        if template_hash != issued.claim_template_hash {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let initial_transcript_hash = initial_transcript_hash_v1(
            &trusted_chain_id,
            &issued.session_id,
            contract_kind,
            &roster,
        );
        let round = self.audit_operational_signing_round(
            issued.session_id,
            PurposeV1::ClaimAdaptor,
            &roster,
            template_hash,
            SessionPhaseV1::FundingConfirmed,
        )?;
        if round.round_start_revision < issued.bound_session_revision
            || round.round_start_transcript_hash != issued.round_start_transcript_hash
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let binding = SigningSessionBindingRecordV1::new(
            &trusted_chain_id,
            &current,
            contract_kind,
            PurposeV1::ClaimAdaptor,
            &roster,
            &canonical_transaction,
            template_hash,
            kernel_index,
            Some(&issued.adaptor_point),
            initial_transcript_hash,
            &round,
        )?;
        self.persist_signing_binding(&binding)?;
        let durable = self.load_signing_binding(issued.session_id, PurposeV1::ClaimAdaptor)?;
        if durable.bytes != binding.bytes {
            return Err(SessionStoreError::Quarantined);
        }
        let binding_digest = copy_array(&durable.bytes[durable.bytes.len() - DIGEST_LEN..])?;
        let round_binding = PostAnchorClaimSigningBindingRecordV1::new(
            issued.session_id,
            authorization.issuance_record_digest,
            authorization.consumption_record_digest,
            binding_digest,
            participant_roster_digest(&roster),
            round.round_start_record_digest,
        )?;
        self.persist_post_anchor_claim_signing_binding(&round_binding)?;
        let durable_round_binding =
            self.load_post_anchor_claim_signing_binding(issued.session_id)?;
        if durable_round_binding.bytes != round_binding.bytes {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(AcceptedContractsSigningSessionV1 {
            trusted_chain_id,
            session_id: issued.session_id,
            contract_kind,
            purpose: PurposeV1::ClaimAdaptor,
            roster,
            transaction_template,
            kernel_index,
            adaptor_point: Some(issued.adaptor_point),
            initial_transcript_hash,
            round_start_transcript_hash: round.round_start_transcript_hash,
            sender_sequence_bases: round.sender_sequence_bases,
            accepted_messages: round.accepted_messages,
            _session_revision: round.round_start_revision,
            _session_record_digest: round.round_start_record_digest,
            _open_instance_id: self.open_instance_id,
            _post_anchor_consumption_digest: Some(authorization.consumption_record_digest),
        })
    }

    /// Rehydrates the exact post-anchor ClaimAdaptor signing round after a
    /// restart without accepting caller-shaped roster, template, or adaptor
    /// values.
    pub fn resume_post_anchor_dom_claim_signing_session(
        &self,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        trusted_chain_id: TrustedChainIdV1,
    ) -> Result<AcceptedContractsSigningSessionV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let (issued, _consumed, current) =
            self.authenticate_live_consumed_claim_authority(authorization)?;
        if trusted_chain_id.as_bytes() != &issued.chain_id {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let binding = self.load_signing_binding(issued.session_id, PurposeV1::ClaimAdaptor)?;
        let decoded = binding.decode(&trusted_chain_id)?;
        let round_binding = self.load_post_anchor_claim_signing_binding(issued.session_id)?;
        let transport_roster = self.load_transport_roster(issued.session_id)?;
        let identity_binding = self.load_transport_identity_binding(issued.session_id)?;
        require_transport_identity_binding(&transport_roster, &identity_binding)?;
        validate_post_anchor_signing_inputs(
            &trusted_chain_id,
            &current,
            decoded.contract_kind,
            &decoded.roster,
            &decoded.transaction_template,
            decoded.kernel_index,
            &issued.adaptor_point,
            &transport_roster,
        )?;
        let recomputed_initial = initial_transcript_hash_v1(
            &trusted_chain_id,
            &issued.session_id,
            decoded.contract_kind,
            &decoded.roster,
        );
        let round = self.audit_operational_signing_round(
            issued.session_id,
            PurposeV1::ClaimAdaptor,
            &decoded.roster,
            decoded.template_hash,
            SessionPhaseV1::FundingConfirmed,
        )?;
        if decoded.template_hash != issued.claim_template_hash
            || decoded.adaptor_point.as_ref() != Some(&issued.adaptor_point)
            || decoded.initial_transcript_hash != recomputed_initial
            || decoded.round_start_transcript_hash != round.round_start_transcript_hash
            || decoded.sender_sequence_bases != round.sender_sequence_bases
            || decoded.round_start_revision != round.round_start_revision
            || decoded.round_start_record_digest != round.round_start_record_digest
            || decoded.template_commit_payload != round.template_commit_payload
            || round_binding.issuance_record_digest != authorization.issuance_record_digest
            || round_binding.consumption_record_digest != authorization.consumption_record_digest
            || round_binding.signing_binding_record_digest
                != copy_array(&binding.bytes[binding.bytes.len() - DIGEST_LEN..])?
            || round_binding.roster_digest != participant_roster_digest(&decoded.roster)
            || round_binding.round_start_record_digest != round.round_start_record_digest
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        Ok(AcceptedContractsSigningSessionV1 {
            trusted_chain_id,
            session_id: issued.session_id,
            contract_kind: decoded.contract_kind,
            purpose: PurposeV1::ClaimAdaptor,
            roster: decoded.roster,
            transaction_template: decoded.transaction_template,
            kernel_index: decoded.kernel_index,
            adaptor_point: decoded.adaptor_point,
            initial_transcript_hash: decoded.initial_transcript_hash,
            round_start_transcript_hash: round.round_start_transcript_hash,
            sender_sequence_bases: round.sender_sequence_bases,
            accepted_messages: round.accepted_messages,
            _session_revision: round.round_start_revision,
            _session_record_digest: round.round_start_record_digest,
            _open_instance_id: self.open_instance_id,
            _post_anchor_consumption_digest: Some(authorization.consumption_record_digest),
        })
    }

    /// Reconstructs and durably retains the exact aggregate Claim adaptor
    /// pre-signature after a crash or lost process-local return value.
    ///
    /// No nonce is reopened and no partial is recomputed. The method accepts
    /// only the same live consumed post-anchor authorization, reauthenticates
    /// the immutable signing/session bindings and all six DSC1 round messages,
    /// verifies both retained partials against the canonical public inputs,
    /// and then persists the exact canonical pre-signature before returning an
    /// opaque handle. Repeated calls and process restarts load the identical
    /// retained record; a gap, equivocation, mutation, or binding mismatch
    /// fails closed.
    pub fn reconstruct_post_anchor_dom_claim_pre_signature(
        &self,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        trusted_chain_id: TrustedChainIdV1,
    ) -> Result<AuthenticatedPostAnchorClaimPreSignatureV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let (issued, consumed, _current) =
            self.authenticate_live_consumed_claim_authority(authorization)?;
        if trusted_chain_id.as_bytes() != &issued.chain_id {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let binding = self.load_signing_binding(issued.session_id, PurposeV1::ClaimAdaptor)?;
        let decoded = binding.decode(&trusted_chain_id)?;
        let round_binding = self.load_post_anchor_claim_signing_binding(issued.session_id)?;
        let round = self.audit_operational_signing_round(
            issued.session_id,
            PurposeV1::ClaimAdaptor,
            &decoded.roster,
            decoded.template_hash,
            SessionPhaseV1::FundingConfirmed,
        )?;
        let signing_binding_digest =
            copy_array(&binding.bytes[binding.bytes.len() - DIGEST_LEN..])?;
        if decoded.template_hash != issued.claim_template_hash
            || decoded.adaptor_point.as_ref() != Some(&issued.adaptor_point)
            || round.round_start_transcript_hash != issued.round_start_transcript_hash
            || decoded.round_start_transcript_hash != round.round_start_transcript_hash
            || decoded.sender_sequence_bases != round.sender_sequence_bases
            || decoded.round_start_revision != round.round_start_revision
            || decoded.round_start_record_digest != round.round_start_record_digest
            || decoded.template_commit_payload != round.template_commit_payload
            || round_binding.issuance_record_digest != issued.digest
            || round_binding.consumption_record_digest != consumed.digest
            || round_binding.signing_binding_record_digest != signing_binding_digest
            || round_binding.roster_digest != participant_roster_digest(&decoded.roster)
            || round_binding.round_start_record_digest != round.round_start_record_digest
            || round.accepted_messages.len() != 6
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let pre_signature = derive_post_anchor_claim_pre_signature(
            &issued.chain_id,
            issued.session_id,
            &issued.claim_template_hash,
            &issued.adaptor_point,
            &decoded,
            &round,
        )?;
        let expected = PostAnchorClaimPreSignatureRecordV1::new(
            &issued,
            &consumed,
            signing_binding_digest,
            round_binding.digest,
            participant_roster_digest(&decoded.roster),
            &round,
            &pre_signature,
        )?;
        let durable = match self.load_post_anchor_claim_pre_signature(issued.session_id) {
            Ok(existing) => {
                if existing.bytes != expected.bytes {
                    return Err(SessionStoreError::Quarantined);
                }
                existing
            }
            Err(SessionStoreError::SessionNotFound) => {
                self.persist_post_anchor_claim_pre_signature(&expected)?;
                test_crash_hook("post-anchor-claim-after-pre-signature-persist");
                let persisted = self.load_post_anchor_claim_pre_signature(issued.session_id)?;
                if persisted.bytes != expected.bytes {
                    return Err(SessionStoreError::Quarantined);
                }
                persisted
            }
            Err(error) => return Err(error),
        };
        durable.authenticated_handle()
    }

    /// Durably compare-and-swaps a non-funding protocol successor.
    ///
    /// The successor must be byte-for-byte reproducible by
    /// [`SessionRecordV1::advance`]. Funding authorization and broadcast edges
    /// are deliberately unavailable here and have dedicated gated methods.
    /// Same-phase projection updates are also unavailable here; scanners must
    /// use [`Self::update_chain_projection`].
    pub fn advance_session(
        &self,
        expected_revision: u64,
        successor: &SessionRecordV1,
    ) -> Result<SessionRecordV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(successor.session_id())?;
        if current.revision() != expected_revision {
            return Err(SessionStoreError::Conflict);
        }
        let terminal_disposition = matches!(
            successor.phase(),
            SessionPhaseV1::Aborted | SessionPhaseV1::FailedClosed
        );
        if current.phase() == successor.phase()
            || matches!(
                successor.phase(),
                SessionPhaseV1::FundingAuthorized | SessionPhaseV1::FundingBroadcast
            )
            || (!current.irreversible().funding_authorized
                && successor.irreversible().funding_authorized)
            || (matches!(
                current.phase(),
                SessionPhaseV1::ClaimPrepared | SessionPhaseV1::FundingAuthorized
            ) && !terminal_disposition)
            || (is_post_broadcast_economic_phase(successor.phase())
                && !is_funding_or_later_economic_phase(current.phase()))
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        if current.phase() == SessionPhaseV1::FundingAuthorized
            && self.consumption_exists(current.session_id())?
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        require_exact_successor(&current, expected_revision, successor)?;
        self.persist_session_record(successor)?;
        self.load_session_locked(successor.session_id())
    }

    /// Applies a scanner/reorg compare-and-swap that changes only the
    /// reversible chain projection (plus the mandatory revision and digest).
    pub fn update_chain_projection(
        &self,
        session_id: [u8; 32],
        expected_revision: u64,
        chain: SessionChainProjectionV1,
    ) -> Result<SessionRecordV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(session_id)?;
        if current.revision() != expected_revision {
            return Err(SessionStoreError::Conflict);
        }
        let successor = current.advance(
            expected_revision,
            current.phase(),
            current.transcript_hash(),
            current.irreversible(),
            chain,
            current.encrypted_payload(),
        )?;
        self.persist_session_record(&successor)?;
        self.load_session_locked(session_id)
    }

    /// Persists the exact verified pre-funding evidence before either
    /// participant may submit its `ReadyToFund` vote.
    ///
    /// Each subsequent `ReadyToFund` payload is exactly the returned digest.
    /// The record contains the fully signed refund and verified claim
    /// pre-signature, while the durable shared-blinding bindings determine the
    /// bilateral-backup receipt hash. This operation does not authorize or sign
    /// funding.
    pub fn prepare_operational_funding_gate(
        &self,
        evidence: VerifiedOperationalFundingGateEvidenceV1,
    ) -> Result<[u8; 32], SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(evidence.session_id)?;
        if current.phase() != SessionPhaseV1::ClaimPrepared
            || current.irreversible().funding_authorized
            || current.terms_hash() != evidence.terms_hash
            || self.any_operational_issuance_exists(evidence.session_id)?
            || self.consumption_exists(evidence.session_id)?
            || self.artifact_exists(evidence.session_id)?
            || self.any_operational_commit_exists(evidence.session_id)?
            || self.m8_funding_gate_exists(evidence.session_id)?
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        self.require_claim_presignature_journal_evidence(
            evidence.session_id,
            evidence.claim_transcript_hash,
            &evidence.claim_pre_signature,
        )?;
        let gate = OperationalFundingGateRecordV1::new(evidence)?;
        self.persist_funding_gate(&gate)?;
        let durable = self.load_funding_gate(gate.session_id)?;
        if durable.bytes != gate.bytes {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(gate.digest)
    }

    /// Persists the additive M.8 pre-funding safety gate without creating or
    /// accepting a claim adaptor nonce or pre-signature.
    ///
    /// The legacy pre-signature-first gate remains unchanged. This F7 profile
    /// starts from the exact durable `RefundSigned` head, freezes the M.8
    /// policy digest, claim template and adaptor point, and returns only the
    /// digest participants must use for their readiness votes.
    pub fn prepare_operational_m8_funding_gate(
        &self,
        evidence: VerifiedOperationalM8FundingGateEvidenceV1,
    ) -> Result<[u8; 32], SessionStoreError> {
        Ok(self
            .prepare_operational_m8_funding_gate_record(evidence)?
            .digest)
    }

    /// Persists and returns a linear reference to the exact prepared M.8 gate.
    ///
    /// Unlike the compatibility digest-returning entry point, this authority
    /// can be consumed by the purpose-specific funding authorization methods
    /// below without releasing the private bilateral backup receipt hash to
    /// the compositor.
    pub fn prepare_operational_m8_funding_gate_authority(
        &self,
        evidence: VerifiedOperationalM8FundingGateEvidenceV1,
    ) -> Result<PreparedOperationalM8FundingGateV1, SessionStoreError> {
        let gate = self.prepare_operational_m8_funding_gate_record(evidence)?;
        Ok(PreparedOperationalM8FundingGateV1 {
            session_id: gate.session_id,
            gate_digest: gate.digest,
            refund_tx_hash: gate.refund_tx_hash,
        })
    }

    /// Canonical refund transaction identity recorded by the durable M.8
    /// funding gate.
    ///
    /// The gate may already be consumed; this reads only the public
    /// transaction identity it recorded, which a route resumed after its
    /// funding was broadcast needs in order to rebuild its receipt. It grants
    /// no funding authority, performs no phase transition, and still requires
    /// the gate to belong to this exact session with a matching terms hash.
    pub fn durable_m8_refund_tx_hash(
        &self,
        session_id: [u8; 32],
    ) -> Result<[u8; 32], SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.load_m8_funding_gate(session_id)?;
        let current = self.load_session_locked(session_id)?;
        if gate.session_id != session_id || current.terms_hash() != gate.terms_hash {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        Ok(gate.refund_tx_hash)
    }

    /// Rehydrates a process-local reference to the same authenticated gate.
    ///
    /// This does not mint a funding issuance.  The subsequent issue/resume
    /// operation still executes every canonical template, session and profile
    /// check in [`OperationalM8FundingAuthorizationStoreV1`].
    ///
    /// The gate is accepted from the phase in which it is created through the
    /// phase in which it is consumed, and the record must belong to this exact
    /// session with a matching terms hash.
    pub fn resume_operational_m8_funding_gate_authority(
        &self,
        session_id: [u8; 32],
    ) -> Result<PreparedOperationalM8FundingGateV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.load_m8_funding_gate(session_id)?;
        let current = self.load_session_locked(session_id)?;
        // The gate is created when the refund is signed and is consumed when
        // funding is authorized. `ClaimSigning` and `ClaimPrepared` are the two
        // phases the session passes through in between, so a session resumed in
        // either of them holds a gate that exists and has not been used. Every
        // check that matters is unchanged: the gate must belong to this exact
        // session, its terms hash must still match, and all four accepted
        // phases are at or after `RefundSigned`, so refund-before-funding (I5)
        // still holds. Restricting this to only the two endpoint phases refused
        // a durable, unconsumed gate and made a restart before funding
        // unrecoverable.
        if gate.session_id != session_id
            || current.terms_hash() != gate.terms_hash
            || !matches!(
                current.phase(),
                SessionPhaseV1::RefundSigned
                    | SessionPhaseV1::ClaimSigning
                    | SessionPhaseV1::ClaimPrepared
                    | SessionPhaseV1::FundingAuthorized
            )
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        Ok(PreparedOperationalM8FundingGateV1 {
            session_id,
            gate_digest: gate.digest,
            refund_tx_hash: gate.refund_tx_hash,
        })
    }

    /// Reconstructs the next missing canonical M.8 `ReadyToFund` vote.
    ///
    /// The authenticated durable journal must be an exact zero-, one-, or
    /// two-vote participant-order prefix. `None` means both votes are already
    /// durable, including after a funding-issuance crash and restart.
    pub fn prepare_next_operational_m8_ready_to_fund_vote(
        &self,
        prepared: &PreparedOperationalM8FundingGateV1,
    ) -> Result<Option<PreparedOperationalM8ReadyToFundVoteV1>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.prepare_next_operational_m8_ready_to_fund_vote_locked(prepared)
    }

    /// Authenticates and durably appends one prepared M.8 `ReadyToFund` vote.
    ///
    /// The caller signs only the public fields exposed by the Store-issued
    /// token. Contracts revalidates the current gate and prefix, parses and
    /// verifies the exact `0x11` DSC1 envelope through the ordinary durable
    /// transport path, and constructs the same-phase successor internally.
    pub fn accept_prepared_operational_m8_ready_to_fund_vote(
        &self,
        prepared: &PreparedOperationalM8FundingGateV1,
        vote: PreparedOperationalM8ReadyToFundVoteV1,
        signed_bytes: &[u8],
    ) -> Result<(), SessionStoreError> {
        let (envelope, successor) = {
            let _guard = self.operation_lock()?;
            let expected = self
                .prepare_next_operational_m8_ready_to_fund_vote_locked(prepared)?
                .ok_or(SessionStoreError::FundingAuthorityUnavailable)?;
            if vote.session_id != expected.session_id
                || vote.participant_id != expected.participant_id
                || vote.sequence != expected.sequence
                || vote.previous_transcript_hash != expected.previous_transcript_hash
                || vote.payload != expected.payload
            {
                return Err(SessionStoreError::InvalidTransition);
            }
            let envelope = ParsedTransportEnvelopeV1::parse(signed_bytes)?;
            let roster = self.load_transport_roster(vote.session_id)?;
            let participant = roster
                .participants
                .iter()
                .find(|candidate| candidate.participant_id == vote.participant_id)
                .ok_or(SessionStoreError::Quarantined)?;
            if envelope.chain_id != roster.chain_id
                || envelope.session_id != vote.session_id
                || envelope.sender_id != vote.participant_id
                || envelope.sequence != vote.sequence
                || envelope.previous_transcript_hash != vote.previous_transcript_hash
                || envelope.message_type != 0x11
                || envelope.payload(signed_bytes)? != vote.payload
            {
                return Err(SessionStoreError::InvalidTransition);
            }
            let current = self.load_session_locked(vote.session_id)?;
            if current.phase() != SessionPhaseV1::RefundSigned
                || current.transcript_hash() != vote.previous_transcript_hash
            {
                return Err(SessionStoreError::FundingAuthorityUnavailable);
            }
            let transcript_hash = accepted_transport_transcript_hash(
                &current.transcript_hash(),
                &envelope.message_digest,
                participant.direction,
                0x11,
                SessionPhaseV1::RefundSigned,
            )?;
            let successor = current.advance(
                current.revision(),
                SessionPhaseV1::RefundSigned,
                transcript_hash,
                current.irreversible(),
                current.chain(),
                current.encrypted_payload(),
            )?;
            (envelope, successor)
        };
        match self.accept_transport_message(signed_bytes, &successor, None)? {
            DurableTransportOutcomeV1::Accepted(receipt)
                if receipt.message_digest == envelope.message_digest
                    && receipt.transcript_hash == successor.transcript_hash()
                    && receipt.sequence == vote.sequence
                    && receipt.message_type == 0x11 =>
            {
                Ok(())
            }
            DurableTransportOutcomeV1::Accepted(_)
            | DurableTransportOutcomeV1::EquivocationPersisted => {
                Err(SessionStoreError::Quarantined)
            }
        }
    }

    /// Issues the one-shot DOM funding-sign authority from a Store-owned gate.
    ///
    /// The caller provides only the authoritative template and BP statement;
    /// every other field, including the backup receipt hash, is loaded from the
    /// exact immutable gate record and rechecked by the existing DOM authority.
    pub fn issue_prepared_operational_m8_funding_authorization(
        &mut self,
        prepared: PreparedOperationalM8FundingGateV1,
        template: &ScriptlessTransactionTemplateV1,
        bp_statement: &BpStatementV1,
    ) -> Result<OperationalM8FundingAuthorizationV1, SessionStoreError> {
        self.authorize_from_prepared_operational_m8_gate(prepared, template, bp_statement, false)
    }

    /// Reimports the exact already-issued authority after restart.
    ///
    /// It can neither create a new issuance nor substitute a legacy profile.
    pub fn resume_prepared_operational_m8_funding_authorization(
        &mut self,
        prepared: PreparedOperationalM8FundingGateV1,
        template: &ScriptlessTransactionTemplateV1,
        bp_statement: &BpStatementV1,
    ) -> Result<OperationalM8FundingAuthorizationV1, SessionStoreError> {
        self.authorize_from_prepared_operational_m8_gate(prepared, template, bp_statement, true)
    }

    fn prepare_operational_m8_funding_gate_record(
        &self,
        evidence: VerifiedOperationalM8FundingGateEvidenceV1,
    ) -> Result<OperationalM8FundingGateRecordV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(evidence.session_id)?;
        if current.phase() != SessionPhaseV1::RefundSigned
            || current.irreversible().funding_authorized
            || current.terms_hash() != evidence.terms_hash
            || self.any_operational_issuance_exists(evidence.session_id)?
            || self.consumption_exists(evidence.session_id)?
            || self.artifact_exists(evidence.session_id)?
            || self.any_operational_commit_exists(evidence.session_id)?
            || self.m8_funding_gate_exists(evidence.session_id)?
            || self.funding_gate_exists(evidence.session_id)?
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        self.require_no_pre_anchor_claim_signing_evidence(evidence.session_id, current.revision())?;
        let gate = OperationalM8FundingGateRecordV1::new(evidence)?;
        self.persist_m8_funding_gate(&gate)?;
        let durable = self.load_m8_funding_gate(gate.session_id)?;
        if durable.bytes != gate.bytes {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(gate)
    }

    fn authorize_from_prepared_operational_m8_gate(
        &mut self,
        prepared: PreparedOperationalM8FundingGateV1,
        template: &ScriptlessTransactionTemplateV1,
        bp_statement: &BpStatementV1,
        resume: bool,
    ) -> Result<OperationalM8FundingAuthorizationV1, SessionStoreError> {
        let gate = self.load_m8_funding_gate(prepared.session_id)?;
        let current = self.load_session_locked(prepared.session_id)?;
        if gate.session_id != prepared.session_id
            || gate.digest != prepared.gate_digest
            || gate.refund_tx_hash != prepared.refund_tx_hash
            || current.terms_hash() != gate.terms_hash
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let result = if resume {
            // Resume must rebuild the binding the issuance froze, not the one
            // the live session would produce now. Authorization pins the
            // transcript hash of the RefundSigned revision, and the funding
            // signing rounds that follow keep advancing the transcript while
            // the phase stays FundingAuthorized, so `current.transcript_hash()`
            // is already stale by the time a cut route resumes. This function
            // is the only supplier of that field, and the store it calls states
            // the required source itself: `resume_operational_m8_funding_
            // authorization` compares the presented binding against
            // `issuance.funding_authorized_record.transcript_hash()`. Reading
            // it from there makes the two halves agree. Every check in the
            // store is left exactly as it was; a missing or quarantined
            // issuance still refuses the resume through `load_m8_funding_
            // issuance`.
            //
            // RATIFIED 2026-08-19 by operator signature over
            // `F7_M8_FUNDING_RESUME_FOR_RATIFICATION.md`; the signature is
            // retained with the document in the laboratory's `ratifications/`.
            let issuance = self.load_m8_funding_issuance(prepared.session_id)?;
            template.resume_funding_m8_authorization_v1(
                &gate.chain_id,
                gate.session_id,
                issuance.funding_authorized_record.transcript_hash(),
                gate.terms_hash,
                bp_statement,
                gate.claim_template_hash,
                gate.claim_adaptor_point.to_compressed_bytes(),
                gate.refund_tx_hash,
                gate.backup_receipt_hash,
                gate.m8_policy_digest,
                self,
            )
        } else {
            template.authorize_funding_m8_v1(
                &gate.chain_id,
                gate.session_id,
                current.transcript_hash(),
                gate.terms_hash,
                bp_statement,
                gate.claim_template_hash,
                gate.claim_adaptor_point.to_compressed_bytes(),
                gate.refund_tx_hash,
                gate.backup_receipt_hash,
                gate.m8_policy_digest,
                self,
            )
        };
        result.map_err(|error| match error {
            OperationalFundingAuthorizationError::Protocol(_) => {
                SessionStoreError::InvalidDomTransaction
            }
            OperationalFundingAuthorizationError::Store(error) => error,
        })
    }

    /// Evidence-only compatibility path retained for the pre-F7 model.
    ///
    /// Production composition must use the [`OperationalFundingAuthorizationStoreV1`]
    /// and [`OperationalFundingTransactionSinkV1`] implementations below.
    /// Persists exact verified refund/funding bytes, commits the exact
    /// `ClaimPrepared -> FundingAuthorized` successor with CAS+fsync, and only
    /// then issues one opaque process-bound authorization.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn issue_funding_authorization(
        &self,
        expected_revision: u64,
        ready_to_fund: &SessionRecordV1,
        verified: VerifiedFundingArtifactsV1,
    ) -> Result<FundingAuthorizationV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(ready_to_fund.session_id())?;
        if current.revision() != expected_revision {
            return Err(SessionStoreError::Conflict);
        }
        if current.phase() != SessionPhaseV1::ClaimPrepared
            || current.irreversible().funding_authorized
            || ready_to_fund.phase() != SessionPhaseV1::FundingAuthorized
            || !ready_to_fund.irreversible().funding_authorized
            || verified.session_id != current.session_id()
            || verified.terms_hash != current.terms_hash()
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        require_exact_successor(&current, expected_revision, ready_to_fund)?;
        if self.consumption_exists(current.session_id())? {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let artifact = FundingArtifactRecordV1::new(
            ready_to_fund.session_id(),
            ready_to_fund.terms_hash(),
            ready_to_fund.revision(),
            verified,
        )?;
        self.persist_artifact(&artifact)?;
        test_crash_hook("issue-after-artifact-persist");
        self.persist_session_record(ready_to_fund)?;
        test_crash_hook("issue-after-session-persist");
        let durable = self.load_session_locked(ready_to_fund.session_id())?;
        if durable.as_bytes() != ready_to_fund.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(FundingAuthorizationV1 {
            open_instance_id: self.open_instance_id,
            session_id: durable.session_id(),
            authorized_revision: durable.revision(),
            session_digest: *durable.digest(),
            artifact_digest: artifact.digest,
        })
    }

    /// Consumes one authorization durably before returning exact funding bytes
    /// for broadcast.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn consume_funding_authorization(
        &self,
        authorization: FundingAuthorizationV1,
        funding_broadcast: &SessionRecordV1,
    ) -> Result<FundingBroadcastV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        if authorization.open_instance_id != self.open_instance_id
            || authorization.session_id != funding_broadcast.session_id()
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let current = self.load_session_locked(authorization.session_id)?;
        if current.revision() != authorization.authorized_revision
            || current.digest() != &authorization.session_digest
            || current.phase() != SessionPhaseV1::FundingAuthorized
            || !current.irreversible().funding_authorized
            || funding_broadcast.phase() != SessionPhaseV1::FundingBroadcast
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        require_exact_successor(&current, current.revision(), funding_broadcast)?;
        if self.consumption_exists(current.session_id())? {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let artifact = self.load_artifact(current.session_id())?;
        if artifact.digest != authorization.artifact_digest
            || artifact.authorized_revision != current.revision()
            || artifact.terms_hash != current.terms_hash()
        {
            return Err(SessionStoreError::Quarantined);
        }
        let consumption = FundingConsumptionRecordV1::new(
            current.session_id(),
            current.revision(),
            artifact.digest,
            funding_broadcast,
        )?;
        self.persist_consumption(&consumption)?;
        test_crash_hook("consume-after-retirement-persist");
        self.persist_session_record(funding_broadcast)?;
        test_crash_hook("consume-after-session-persist");
        let durable = self.load_session_locked(current.session_id())?;
        if durable.as_bytes() != funding_broadcast.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(FundingBroadcastV1 {
            exact_bytes: artifact.funding_bytes,
        })
    }

    /// Reloads byte-identical funding bytes after a lost ACK, process crash,
    /// or restart. The original one-shot authorization must already be
    /// durably consumed and the recorded `FundingBroadcast` successor must be
    /// part of the authenticated session history.
    pub fn resend_funding_broadcast(
        &self,
        session_id: [u8; 32],
    ) -> Result<FundingRetransmissionV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(session_id)?;
        let artifact = self.load_artifact(session_id)?;
        let consumption = self.load_consumption(session_id)?;
        if artifact.digest != consumption.artifact_digest
            || artifact.authorized_revision != consumption.authorized_revision
        {
            return Err(SessionStoreError::Quarantined);
        }
        self.require_operational_commit_if_issued(session_id, &artifact, &consumption)?;
        let broadcast_revision = consumption
            .authorized_revision
            .checked_add(1)
            .ok_or(SessionStoreError::Quarantined)?;
        if current.revision() < broadcast_revision {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let broadcast = self.load_session_revision(session_id, broadcast_revision)?;
        if broadcast.phase() != SessionPhaseV1::FundingBroadcast
            || broadcast.digest() != &consumption.broadcast_record_digest
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(FundingRetransmissionV1 {
            exact_bytes: artifact.funding_bytes,
        })
    }

    /// Loads the exact persisted pre-signed refund only when its real DOM
    /// height lock is mature in the explicit current chain context and the
    /// durable session phase has entered the refund path.
    pub fn load_refund_broadcast(
        &self,
        session_id: [u8; 32],
        current_context: DomTransactionValidationContextV1,
    ) -> Result<RefundBroadcastV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(session_id)?;
        if !matches!(
            current.phase(),
            SessionPhaseV1::RefundEligible | SessionPhaseV1::RefundBroadcast
        ) {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let artifact = self.load_artifact(session_id)?;
        let consumption = self.load_consumption(session_id)?;
        if artifact.digest != consumption.artifact_digest
            || artifact.authorized_revision != consumption.authorized_revision
        {
            return Err(SessionStoreError::Quarantined);
        }
        self.require_operational_commit_if_issued(session_id, &artifact, &consumption)?;
        let broadcast_revision = consumption
            .authorized_revision
            .checked_add(1)
            .ok_or(SessionStoreError::Quarantined)?;
        if current.revision() < broadcast_revision {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let broadcast = self.load_session_revision(session_id, broadcast_revision)?;
        if broadcast.phase() != SessionPhaseV1::FundingBroadcast
            || broadcast.digest() != &consumption.broadcast_record_digest
        {
            return Err(SessionStoreError::Quarantined);
        }
        if current_context.current_height() < artifact.refund_unlock_height {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
        let refund = validate_exact_dom_transaction(&artifact.refund_bytes, current_context)?;
        if refund.kernels.is_empty()
            || refund.kernels.iter().any(|kernel| {
                kernel.features != KERNEL_FEAT_HEIGHT_LOCKED
                    || kernel.lock_height != artifact.refund_unlock_height
            })
        {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
        if current.phase() == SessionPhaseV1::RefundEligible {
            let refund_broadcast = current.advance(
                current.revision(),
                SessionPhaseV1::RefundBroadcast,
                current.transcript_hash(),
                current.irreversible(),
                current.chain(),
                current.encrypted_payload(),
            )?;
            self.persist_session_record(&refund_broadcast)?;
            test_crash_hook("refund-after-broadcast-successor-persist");
            if self.load_session_locked(session_id)?.as_bytes() != refund_broadcast.as_bytes() {
                return Err(SessionStoreError::Quarantined);
            }
        }
        Ok(RefundBroadcastV1 {
            exact_bytes: artifact.refund_bytes,
        })
    }

    /// Persists the exact two-participant public transport roster before any
    /// message can be accepted for a session.
    pub fn bind_transport_roster(
        &self,
        session_id: [u8; 32],
        chain_id: [u8; 32],
        participants: [SessionTransportParticipantV1; 2],
    ) -> Result<(), SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(session_id)?;
        if chain_id == [0; 32]
            || participants[0].participant_id == participants[1].participant_id
            || participants[0].identity_key == participants[1].identity_key
            || participants[0].direction == participants[1].direction
            || participants[0].direction != DirectionV1::Initiator
            || participants[1].direction != DirectionV1::Responder
            || current.phase() == SessionPhaseV1::FailedClosed
        {
            return Err(SessionStoreError::Canonical);
        }
        let roster = TransportRosterRecordV1::new(session_id, chain_id, participants);
        let final_name = roster_name(session_id);
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.rosters,
            &staging_name,
            &final_name,
            &roster.bytes,
            TRANSPORT_ROSTER_LEN,
        )
    }

    /// Persists the public-only independent Contracts-keystore references for
    /// the exact two participants already frozen in the transport roster.
    ///
    /// The participant order and DOM Schnorr public keys must exactly equal
    /// the roster. The two opaque references and Noise public keys must be
    /// distinct. This immutable record is the restart bridge from the session
    /// database to the separately encrypted Contracts identity keystore; no
    /// private key bytes cross this API.
    pub fn bind_transport_identity_references(
        &self,
        session_id: [u8; 32],
        references: [SessionTransportIdentityReferenceV1; 2],
    ) -> Result<(), SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(session_id)?;
        let roster = self.load_transport_roster(session_id)?;
        if current.phase() == SessionPhaseV1::FailedClosed
            || references[0].participant_id == references[1].participant_id
            || references[0].key_reference == references[1].key_reference
            || references[0].noise_public_key == references[1].noise_public_key
        {
            return Err(SessionStoreError::Canonical);
        }
        for (participant, reference) in roster.participants.iter().zip(references.iter()) {
            if participant.participant_id != reference.participant_id
                || participant.identity_key != reference.schnorr_public_key
            {
                return Err(SessionStoreError::Canonical);
            }
        }
        let binding =
            TransportIdentityBindingRecordV1::new(session_id, roster.chain_id, references);
        let final_name = transport_identity_binding_name(session_id);
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.rosters,
            &staging_name,
            &final_name,
            &binding.bytes,
            TRANSPORT_IDENTITY_BINDING_LEN,
        )
    }

    /// Reloads and authenticates the public Contracts-keystore references for
    /// one session. Missing or divergent references fail closed; callers then
    /// cannot establish an F7 Noise channel or sign a DSC1 envelope.
    pub fn transport_identity_references(
        &self,
        session_id: [u8; 32],
    ) -> Result<[SessionTransportIdentityReferenceV1; 2], SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.load_session_locked(session_id)?;
        let binding = self.load_transport_identity_binding(session_id)?;
        let roster = self.load_transport_roster(session_id)?;
        require_transport_identity_binding(&roster, &binding)?;
        Ok(binding.references)
    }

    /// Authenticates and durably accepts one canonical signed transport
    /// message together with its exact `SessionRecordV1::advance` successor.
    /// Success is returned only after both bytes and successor are synced, so
    /// an ACK emitted afterward survives restart. Exact duplicates return the
    /// same receipt; validly signed differing bytes persist `FailedClosed`.
    pub fn accept_transport_message(
        &self,
        signed_bytes: &[u8],
        successor: &SessionRecordV1,
        failed_closed_successor: Option<&SessionRecordV1>,
    ) -> Result<DurableTransportOutcomeV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let envelope = ParsedTransportEnvelopeV1::parse(signed_bytes)?;
        let roster = self.load_transport_roster(envelope.session_id)?;
        let identity_binding = self.load_transport_identity_binding(envelope.session_id)?;
        require_transport_identity_binding(&roster, &identity_binding)?;
        if roster.chain_id != envelope.chain_id {
            return Err(SessionStoreError::Canonical);
        }
        let participant = roster
            .participants
            .iter()
            .find(|candidate| candidate.participant_id == envelope.sender_id)
            .ok_or(SessionStoreError::Canonical)?;
        envelope.verify(&participant.identity_key)?;
        let name = transport_message_name(
            envelope.session_id,
            envelope.sender_id,
            envelope.sequence,
            false,
        );
        match self.messages.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            TRANSPORT_MESSAGE_MAX_LEN,
        ) {
            Ok(bytes) => {
                let accepted = TransportMessageRecordV1::from_bytes(&bytes)?;
                let (accepted_envelope, accepted_direction) =
                    self.authenticate_transport_record(&name, &accepted)?;
                if accepted.equivocation
                    || accepted_envelope.session_id != envelope.session_id
                    || accepted_envelope.sender_id != envelope.sender_id
                    || accepted_envelope.sequence != envelope.sequence
                    || accepted_direction != participant.direction
                {
                    return Err(SessionStoreError::Quarantined);
                }
                if accepted.signed_bytes == signed_bytes {
                    let durable = self.load_session_revision(
                        accepted.session_id,
                        accepted.successor.revision(),
                    )?;
                    if durable.as_bytes() != accepted.successor.as_bytes() {
                        return Err(SessionStoreError::Quarantined);
                    }
                    return Ok(DurableTransportOutcomeV1::Accepted(accepted.receipt(true)));
                }
                let failed = failed_closed_successor.ok_or(SessionStoreError::InvalidTransition)?;
                let current = self.load_session_locked(envelope.session_id)?;
                require_failed_closed_successor(&current, failed)?;
                let equivocation = TransportMessageRecordV1::new(
                    &envelope,
                    signed_bytes,
                    failed,
                    participant.direction,
                    true,
                )?;
                let final_name = transport_message_name(
                    envelope.session_id,
                    envelope.sender_id,
                    envelope.sequence,
                    true,
                );
                let staging_name = format!(".{final_name}.staging");
                publish_immutable(
                    &self.messages,
                    &staging_name,
                    &final_name,
                    &equivocation.bytes,
                    TRANSPORT_MESSAGE_MAX_LEN,
                )?;
                self.persist_session_record(failed)?;
                return Ok(DurableTransportOutcomeV1::EquivocationPersisted);
            }
            Err(LinuxCapabilityError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        let current = self.load_session_locked(envelope.session_id)?;
        if current.phase() == SessionPhaseV1::FailedClosed {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.require_authenticated_transport_successor(
            &current,
            &envelope,
            signed_bytes,
            participant.direction,
            successor,
        )?;
        let expected_sequence =
            self.next_transport_sequence(envelope.session_id, envelope.sender_id)?;
        if envelope.sequence != expected_sequence {
            return Err(SessionStoreError::InvalidTransition);
        }
        if self.transport_message_count(envelope.session_id)? >= MAX_ACCEPTED_TRANSPORT_MESSAGES {
            return Err(SessionStoreError::CapacityExceeded);
        }
        let record = TransportMessageRecordV1::new(
            &envelope,
            signed_bytes,
            successor,
            participant.direction,
            false,
        )?;
        let staging_name = format!(".{name}.staging");
        publish_immutable(
            &self.messages,
            &staging_name,
            &name,
            &record.bytes,
            TRANSPORT_MESSAGE_MAX_LEN,
        )?;
        test_crash_hook("transport-after-message-persist");
        self.persist_session_record(successor)?;
        test_crash_hook("transport-after-session-persist");
        Ok(DurableTransportOutcomeV1::Accepted(record.receipt(false)))
    }

    /// Claim-only post-anchor transport entrypoint for the F7 composition.
    ///
    /// The consumed linear capability is reauthenticated before delegating to
    /// the global DSC1 journal. The ordinary transport path also checks the
    /// same durable consumed record for `FundingConfirmed` signing messages,
    /// so this convenience boundary cannot be bypassed by calling it directly.
    pub fn accept_post_anchor_dom_claim_transport_message(
        &self,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        signed_bytes: &[u8],
        successor: &SessionRecordV1,
        failed_closed_successor: Option<&SessionRecordV1>,
    ) -> Result<DurableTransportOutcomeV1, SessionStoreError> {
        {
            let _guard = self.operation_lock()?;
            let (issued, _, _) = self.authenticate_live_consumed_claim_authority(authorization)?;
            let envelope = ParsedTransportEnvelopeV1::parse(signed_bytes)?;
            if envelope.session_id != issued.session_id
                || !(0x0c..=0x0f).contains(&envelope.message_type)
            {
                return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
            }
        }
        self.accept_transport_message(signed_bytes, successor, failed_closed_successor)
    }

    fn operation_lock(&self) -> Result<MutexGuard<'_, ()>, SessionStoreError> {
        self.operation
            .lock()
            .map_err(|_| SessionStoreError::Quarantined)
    }

    fn persist_session_record(&self, record: &SessionRecordV1) -> Result<(), SessionStoreError> {
        let final_name = session_record_name(record.session_id(), record.revision());
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.records,
            &staging_name,
            &final_name,
            record.as_bytes(),
            SESSION_RECORD_MAX_LEN,
        )
    }

    fn load_session_locked(
        &self,
        session_id: [u8; 32],
    ) -> Result<SessionRecordV1, SessionStoreError> {
        let session_hex = hex_lower(&session_id);
        let mut records = Vec::new();
        self.records.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let Some((name_session, revision)) = parse_session_record_name(name) else {
                return Err(LinuxCapabilityError::InvalidDirectoryEntry);
            };
            if name_session != session_hex {
                return Ok(());
            }
            let bytes = self.records.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                SESSION_RECORD_MAX_LEN,
            )?;
            let record = SessionRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if hex_lower(&record.session_id()) != name_session || record.revision() != revision {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            records.push(record);
            Ok(())
        })?;
        records.sort_by_key(SessionRecordV1::revision);
        let Some(first) = records.first() else {
            return Err(SessionStoreError::SessionNotFound);
        };
        if first.revision() != 0 {
            return Err(SessionStoreError::Quarantined);
        }
        for pair in records.windows(2) {
            let previous = &pair[0];
            let next = &pair[1];
            if next.revision()
                != previous
                    .revision()
                    .checked_add(1)
                    .ok_or(SessionStoreError::Quarantined)?
            {
                return Err(SessionStoreError::Quarantined);
            }
            require_exact_successor(previous, previous.revision(), next)
                .map_err(|_| SessionStoreError::Quarantined)?;
        }
        records.pop().ok_or(SessionStoreError::SessionNotFound)
    }

    fn persist_artifact(
        &self,
        artifact: &FundingArtifactRecordV1,
    ) -> Result<(), SessionStoreError> {
        let final_name = artifact_name(artifact.session_id);
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.artifacts,
            &staging_name,
            &final_name,
            &artifact.bytes,
            FUNDING_ARTIFACT_MAX_LEN,
        )
    }

    fn persist_funding_gate(
        &self,
        gate: &OperationalFundingGateRecordV1,
    ) -> Result<(), SessionStoreError> {
        let final_name = funding_gate_name(gate.session_id);
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.artifacts,
            &staging_name,
            &final_name,
            &gate.bytes,
            FUNDING_GATE_MAX_LEN,
        )
    }

    fn persist_m8_funding_gate(
        &self,
        gate: &OperationalM8FundingGateRecordV1,
    ) -> Result<(), SessionStoreError> {
        let final_name = m8_funding_gate_name(gate.session_id);
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.artifacts,
            &staging_name,
            &final_name,
            &gate.bytes,
            M8_FUNDING_GATE_MAX_LEN,
        )
    }

    fn load_m8_funding_gate(
        &self,
        session_id: [u8; 32],
    ) -> Result<OperationalM8FundingGateRecordV1, SessionStoreError> {
        let name = m8_funding_gate_name(session_id);
        match self.artifacts.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            M8_FUNDING_GATE_MAX_LEN,
        ) {
            Ok(bytes) => {
                let gate = OperationalM8FundingGateRecordV1::from_bytes(&bytes)?;
                if gate.session_id != session_id {
                    return Err(SessionStoreError::Quarantined);
                }
                Ok(gate)
            }
            Err(LinuxCapabilityError::NotFound) => Err(SessionStoreError::SessionNotFound),
            Err(error) => Err(error.into()),
        }
    }

    fn m8_funding_gate_exists(&self, session_id: [u8; 32]) -> Result<bool, SessionStoreError> {
        match self.load_m8_funding_gate(session_id) {
            Ok(_) => Ok(true),
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn load_funding_gate(
        &self,
        session_id: [u8; 32],
    ) -> Result<OperationalFundingGateRecordV1, SessionStoreError> {
        let name = funding_gate_name(session_id);
        match self.artifacts.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            FUNDING_GATE_MAX_LEN,
        ) {
            Ok(bytes) => {
                let gate = OperationalFundingGateRecordV1::from_bytes(&bytes)?;
                if gate.session_id != session_id {
                    return Err(SessionStoreError::Quarantined);
                }
                Ok(gate)
            }
            Err(LinuxCapabilityError::NotFound) => Err(SessionStoreError::SessionNotFound),
            Err(error) => Err(error.into()),
        }
    }

    fn funding_gate_exists(&self, session_id: [u8; 32]) -> Result<bool, SessionStoreError> {
        match self.load_funding_gate(session_id) {
            Ok(_) => Ok(true),
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn persist_funding_issuance(
        &self,
        issuance: &OperationalFundingIssuanceRecordV1,
    ) -> Result<(), SessionStoreError> {
        let final_name = funding_issuance_name(*issuance.binding.session_id());
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.artifacts,
            &staging_name,
            &final_name,
            &issuance.bytes,
            FUNDING_ISSUANCE_MAX_LEN,
        )
    }

    fn persist_m8_funding_issuance(
        &self,
        issuance: &OperationalM8FundingIssuanceRecordV1,
    ) -> Result<(), SessionStoreError> {
        let final_name = m8_funding_issuance_name(*issuance.binding.session_id());
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.artifacts,
            &staging_name,
            &final_name,
            &issuance.bytes,
            M8_FUNDING_ISSUANCE_MAX_LEN,
        )
    }

    fn persist_funding_commit(
        &self,
        commit: &OperationalFundingCommitRecordV1,
    ) -> Result<(), SessionStoreError> {
        let final_name = funding_commit_name(commit.session_id);
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.consumptions,
            &staging_name,
            &final_name,
            &commit.bytes,
            FUNDING_COMMIT_MAX_LEN,
        )
    }

    fn persist_m8_funding_commit(
        &self,
        commit: &OperationalM8FundingCommitRecordV1,
    ) -> Result<(), SessionStoreError> {
        let final_name = m8_funding_commit_name(commit.session_id);
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.consumptions,
            &staging_name,
            &final_name,
            &commit.bytes,
            M8_FUNDING_COMMIT_MAX_LEN,
        )
    }

    fn load_funding_commit(
        &self,
        session_id: [u8; 32],
    ) -> Result<OperationalFundingCommitRecordV1, SessionStoreError> {
        let name = funding_commit_name(session_id);
        match self.consumptions.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            FUNDING_COMMIT_MAX_LEN,
        ) {
            Ok(bytes) => {
                let commit = OperationalFundingCommitRecordV1::from_bytes(&bytes)?;
                if commit.session_id != session_id {
                    return Err(SessionStoreError::Quarantined);
                }
                Ok(commit)
            }
            Err(LinuxCapabilityError::NotFound) => Err(SessionStoreError::SessionNotFound),
            Err(error) => Err(error.into()),
        }
    }

    fn load_m8_funding_commit(
        &self,
        session_id: [u8; 32],
    ) -> Result<OperationalM8FundingCommitRecordV1, SessionStoreError> {
        let name = m8_funding_commit_name(session_id);
        match self.consumptions.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            M8_FUNDING_COMMIT_MAX_LEN,
        ) {
            Ok(bytes) => {
                let commit = OperationalM8FundingCommitRecordV1::from_bytes(&bytes)?;
                if commit.session_id != session_id {
                    return Err(SessionStoreError::Quarantined);
                }
                Ok(commit)
            }
            Err(LinuxCapabilityError::NotFound) => Err(SessionStoreError::SessionNotFound),
            Err(error) => Err(error.into()),
        }
    }

    fn load_funding_issuance(
        &self,
        session_id: [u8; 32],
    ) -> Result<OperationalFundingIssuanceRecordV1, SessionStoreError> {
        let name = funding_issuance_name(session_id);
        match self.artifacts.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            FUNDING_ISSUANCE_MAX_LEN,
        ) {
            Ok(bytes) => {
                let issuance = OperationalFundingIssuanceRecordV1::from_bytes(&bytes)?;
                if issuance.binding.session_id() != &session_id {
                    return Err(SessionStoreError::Quarantined);
                }
                Ok(issuance)
            }
            Err(LinuxCapabilityError::NotFound) => Err(SessionStoreError::SessionNotFound),
            Err(error) => Err(error.into()),
        }
    }

    fn load_m8_funding_issuance(
        &self,
        session_id: [u8; 32],
    ) -> Result<OperationalM8FundingIssuanceRecordV1, SessionStoreError> {
        let name = m8_funding_issuance_name(session_id);
        match self.artifacts.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            M8_FUNDING_ISSUANCE_MAX_LEN,
        ) {
            Ok(bytes) => {
                let issuance = OperationalM8FundingIssuanceRecordV1::from_bytes(&bytes)?;
                if issuance.binding.session_id() != &session_id {
                    return Err(SessionStoreError::Quarantined);
                }
                Ok(issuance)
            }
            Err(LinuxCapabilityError::NotFound) => Err(SessionStoreError::SessionNotFound),
            Err(error) => Err(error.into()),
        }
    }

    fn issuance_exists(&self, session_id: [u8; 32]) -> Result<bool, SessionStoreError> {
        match self.load_funding_issuance(session_id) {
            Ok(_) => Ok(true),
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn m8_issuance_exists(&self, session_id: [u8; 32]) -> Result<bool, SessionStoreError> {
        match self.load_m8_funding_issuance(session_id) {
            Ok(_) => Ok(true),
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn any_operational_issuance_exists(
        &self,
        session_id: [u8; 32],
    ) -> Result<bool, SessionStoreError> {
        Ok(self.issuance_exists(session_id)? || self.m8_issuance_exists(session_id)?)
    }

    fn funding_commit_exists(&self, session_id: [u8; 32]) -> Result<bool, SessionStoreError> {
        match self.load_funding_commit(session_id) {
            Ok(_) => Ok(true),
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn m8_funding_commit_exists(&self, session_id: [u8; 32]) -> Result<bool, SessionStoreError> {
        match self.load_m8_funding_commit(session_id) {
            Ok(_) => Ok(true),
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn any_operational_commit_exists(
        &self,
        session_id: [u8; 32],
    ) -> Result<bool, SessionStoreError> {
        Ok(self.funding_commit_exists(session_id)? || self.m8_funding_commit_exists(session_id)?)
    }

    fn require_operational_commit_if_issued(
        &self,
        session_id: [u8; 32],
        artifact: &FundingArtifactRecordV1,
        consumption: &FundingConsumptionRecordV1,
    ) -> Result<(), SessionStoreError> {
        if !self.any_operational_issuance_exists(session_id)? {
            return Ok(());
        }
        match (
            self.issuance_exists(session_id)?,
            self.m8_issuance_exists(session_id)?,
        ) {
            (true, false) => {
                if self.m8_funding_commit_exists(session_id)? {
                    return Err(SessionStoreError::Quarantined);
                }
                let commit = self.load_funding_commit(session_id)?;
                if commit.artifact.bytes != artifact.bytes
                    || commit.consumption.bytes != consumption.bytes
                {
                    return Err(SessionStoreError::Quarantined);
                }
                self.verify_operational_commit_against_authority(&commit)?;
            }
            (false, true) => {
                if self.funding_commit_exists(session_id)? {
                    return Err(SessionStoreError::Quarantined);
                }
                let commit = self.load_m8_funding_commit(session_id)?;
                if commit.artifact.bytes != artifact.bytes
                    || commit.consumption.bytes != consumption.bytes
                {
                    return Err(SessionStoreError::Quarantined);
                }
                self.verify_m8_commit_against_authority(&commit)?;
            }
            _ => return Err(SessionStoreError::Quarantined),
        }
        Ok(())
    }

    fn verify_operational_commit_against_authority(
        &self,
        commit: &OperationalFundingCommitRecordV1,
    ) -> Result<(), SessionStoreError> {
        if self.m8_issuance_exists(commit.session_id)?
            || self.m8_funding_gate_exists(commit.session_id)?
            || self.m8_funding_commit_exists(commit.session_id)?
        {
            return Err(SessionStoreError::Quarantined);
        }
        let issuance = self.load_funding_issuance(commit.session_id)?;
        let gate = self.load_funding_gate(commit.session_id)?;
        let artifact = &commit.artifact;
        let consumption = &commit.consumption;
        if issuance.gate_digest != gate.digest
            || issuance.binding.session_id() != &commit.session_id
            || issuance.binding.chain_id() != &gate.chain_id
            || issuance.binding.terms_hash() != &gate.terms_hash
            || issuance.binding.shared_output_commitment() != &gate.shared_output_commitment
            || issuance.binding.bp_statement_hash() != &gate.bp_statement_hash
            || issuance.binding.claim_template_hash() != &gate.claim_template_hash
            || issuance.binding.refund_tx_hash() != &gate.refund_tx_hash
            || issuance.binding.claim_presignature_hash() != &gate.claim_pre_signature_hash
            || issuance.binding.backup_receipt_hash() != &gate.backup_receipt_hash
            || artifact.session_id != gate.session_id
            || artifact.terms_hash != gate.terms_hash
            || artifact.refund_unlock_height != gate.refund_unlock_height
            || artifact.refund_bytes != gate.refund_bytes
            || artifact.digest != consumption.artifact_digest
            || artifact.authorized_revision != consumption.authorized_revision
        {
            return Err(SessionStoreError::Quarantined);
        }
        let terminal =
            self.load_session_revision(commit.session_id, artifact.authorized_revision)?;
        self.audit_funding_authorized_signing_prefix(
            commit.session_id,
            &gate.chain_id,
            &gate.terms_hash,
            &issuance.unsigned_template_bytes,
            issuance.binding.funding_template_hash(),
            &issuance.funding_authorized_record,
            &terminal,
            true,
        )
        .map_err(|_| SessionStoreError::Quarantined)?;
        let funding = validate_exact_dom_transaction(
            &artifact.funding_bytes,
            DomTransactionValidationContextV1::new(
                gate.validation_height,
                gate.chain_id,
                gate.now_unix_seconds,
            ),
        )
        .map_err(|_| SessionStoreError::Quarantined)?;
        let (template_bytes, template_hash) =
            canonical_template_v1(&funding).map_err(|_| SessionStoreError::Quarantined)?;
        let shared_output_count = funding
            .outputs
            .iter()
            .filter(|output| output.commitment.as_bytes() == &gate.shared_output_commitment)
            .count();
        if template_bytes != issuance.unsigned_template_bytes
            || template_hash != *issuance.binding.funding_template_hash()
            || shared_output_count != 1
        {
            return Err(SessionStoreError::Quarantined);
        }
        let successor = consumption
            .broadcast_record()
            .map_err(|_| SessionStoreError::Quarantined)?;
        require_exact_successor(&terminal, artifact.authorized_revision, &successor)
            .map_err(|_| SessionStoreError::Quarantined)?;
        if successor.phase() != SessionPhaseV1::FundingBroadcast
            || successor.digest() != &consumption.broadcast_record_digest
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }

    fn verify_m8_commit_against_authority(
        &self,
        commit: &OperationalM8FundingCommitRecordV1,
    ) -> Result<(), SessionStoreError> {
        if self.issuance_exists(commit.session_id)?
            || self.funding_gate_exists(commit.session_id)?
            || self.funding_commit_exists(commit.session_id)?
        {
            return Err(SessionStoreError::Quarantined);
        }
        let issuance = self.load_m8_funding_issuance(commit.session_id)?;
        let gate = self.load_m8_funding_gate(commit.session_id)?;
        let artifact = &commit.artifact;
        let consumption = &commit.consumption;
        if commit.issuance_record_digest != issuance.digest
            || issuance.gate_digest != gate.digest
            || issuance.binding.session_id() != &commit.session_id
            || issuance.binding.chain_id() != &gate.chain_id
            || issuance.binding.terms_hash() != &gate.terms_hash
            || issuance.binding.m8_policy_digest() != &gate.m8_policy_digest
            || issuance.binding.shared_output_commitment() != &gate.shared_output_commitment
            || issuance.binding.bp_statement_hash() != &gate.bp_statement_hash
            || issuance.binding.claim_template_hash() != &gate.claim_template_hash
            || issuance.binding.claim_adaptor_point()
                != &gate.claim_adaptor_point.to_compressed_bytes()
            || issuance.binding.refund_tx_hash() != &gate.refund_tx_hash
            || issuance.binding.backup_receipt_hash() != &gate.backup_receipt_hash
            || artifact.session_id != gate.session_id
            || artifact.terms_hash != gate.terms_hash
            || artifact.refund_unlock_height != gate.refund_unlock_height
            || artifact.refund_bytes != gate.refund_bytes
            || artifact.digest != consumption.artifact_digest
            || artifact.authorized_revision != consumption.authorized_revision
        {
            return Err(SessionStoreError::Quarantined);
        }
        self.require_no_pre_anchor_claim_signing_evidence(
            commit.session_id,
            artifact.authorized_revision,
        )?;
        let terminal =
            self.load_session_revision(commit.session_id, artifact.authorized_revision)?;
        self.audit_funding_authorized_signing_prefix(
            commit.session_id,
            &gate.chain_id,
            &gate.terms_hash,
            &issuance.unsigned_template_bytes,
            issuance.binding.funding_template_hash(),
            &issuance.funding_authorized_record,
            &terminal,
            true,
        )
        .map_err(|_| SessionStoreError::Quarantined)?;
        let funding = validate_exact_dom_transaction(
            &artifact.funding_bytes,
            DomTransactionValidationContextV1::new(
                gate.validation_height,
                gate.chain_id,
                gate.now_unix_seconds,
            ),
        )
        .map_err(|_| SessionStoreError::Quarantined)?;
        let (template_bytes, template_hash) =
            canonical_template_v1(&funding).map_err(|_| SessionStoreError::Quarantined)?;
        let shared_output_count = funding
            .outputs
            .iter()
            .filter(|output| output.commitment.as_bytes() == &gate.shared_output_commitment)
            .count();
        let successor = consumption
            .broadcast_record()
            .map_err(|_| SessionStoreError::Quarantined)?;
        require_exact_successor(&terminal, artifact.authorized_revision, &successor)
            .map_err(|_| SessionStoreError::Quarantined)?;
        if successor.phase() != SessionPhaseV1::FundingBroadcast
            || successor.digest() != &consumption.broadcast_record_digest
            || template_bytes != issuance.unsigned_template_bytes
            || template_hash != *issuance.binding.funding_template_hash()
            || shared_output_count != 1
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }

    fn load_artifact(
        &self,
        session_id: [u8; 32],
    ) -> Result<FundingArtifactRecordV1, SessionStoreError> {
        let name = artifact_name(session_id);
        let bytes = self.artifacts.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            FUNDING_ARTIFACT_MAX_LEN,
        )?;
        let artifact = FundingArtifactRecordV1::from_bytes(&bytes)?;
        if artifact.session_id != session_id {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(artifact)
    }

    fn artifact_exists(&self, session_id: [u8; 32]) -> Result<bool, SessionStoreError> {
        match self.load_artifact(session_id) {
            Ok(_) => Ok(true),
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn persist_consumption(
        &self,
        consumption: &FundingConsumptionRecordV1,
    ) -> Result<(), SessionStoreError> {
        let final_name = consumption_name(consumption.session_id);
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.consumptions,
            &staging_name,
            &final_name,
            &consumption.bytes,
            CONSUMPTION_MAX_LEN,
        )
    }

    fn consumption_exists(&self, session_id: [u8; 32]) -> Result<bool, SessionStoreError> {
        match self.load_consumption(session_id) {
            Ok(_) => Ok(true),
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn load_consumption(
        &self,
        session_id: [u8; 32],
    ) -> Result<FundingConsumptionRecordV1, SessionStoreError> {
        let name = consumption_name(session_id);
        match self
            .consumptions
            .read_bounded_file(&ValidatedComponent::registered(&name)?, CONSUMPTION_MAX_LEN)
        {
            Ok(bytes) => {
                let record = FundingConsumptionRecordV1::from_bytes(&bytes)?;
                if record.session_id != session_id {
                    return Err(SessionStoreError::Quarantined);
                }
                Ok(record)
            }
            Err(LinuxCapabilityError::NotFound) => Err(SessionStoreError::SessionNotFound),
            Err(error) => Err(error.into()),
        }
    }

    fn load_transport_roster(
        &self,
        session_id: [u8; 32],
    ) -> Result<TransportRosterRecordV1, SessionStoreError> {
        let name = roster_name(session_id);
        let bytes = self.rosters.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            TRANSPORT_ROSTER_LEN,
        )?;
        let roster = TransportRosterRecordV1::from_bytes(&bytes)?;
        if roster.session_id != session_id {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(roster)
    }

    fn load_transport_identity_binding(
        &self,
        session_id: [u8; 32],
    ) -> Result<TransportIdentityBindingRecordV1, SessionStoreError> {
        let name = transport_identity_binding_name(session_id);
        let bytes = self.rosters.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            TRANSPORT_IDENTITY_BINDING_LEN,
        )?;
        let binding = TransportIdentityBindingRecordV1::from_bytes(&bytes)?;
        if binding.session_id != session_id {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(binding)
    }

    fn persist_signing_binding(
        &self,
        binding: &SigningSessionBindingRecordV1,
    ) -> Result<(), SessionStoreError> {
        let final_name = signing_binding_name(binding.session_id, binding.purpose);
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.rosters,
            &staging_name,
            &final_name,
            &binding.bytes,
            SIGNING_BINDING_MAX_LEN,
        )
    }

    fn load_signing_binding(
        &self,
        session_id: [u8; 32],
        purpose: PurposeV1,
    ) -> Result<SigningSessionBindingRecordV1, SessionStoreError> {
        let name = signing_binding_name(session_id, purpose);
        let bytes = self.rosters.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            SIGNING_BINDING_MAX_LEN,
        )?;
        let binding = SigningSessionBindingRecordV1::from_bytes(&bytes)?;
        if binding.session_id != session_id || binding.purpose != purpose {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(binding)
    }

    fn persist_post_anchor_claim_authorization(
        &self,
        record: &PostAnchorClaimAuthorizationRecordV1,
    ) -> Result<(), SessionStoreError> {
        let final_name = post_anchor_claim_authorization_name(record.session_id, record.state);
        let staging_name = format!(".{final_name}.staging");
        let directory = match record.state {
            PostAnchorClaimAuthorizationStateV1::Issued => &self.artifacts,
            PostAnchorClaimAuthorizationStateV1::Consumed => &self.consumptions,
        };
        publish_immutable(
            directory,
            &staging_name,
            &final_name,
            &record.bytes,
            POST_ANCHOR_CLAIM_AUTH_RECORD_LEN,
        )
    }

    fn persist_post_anchor_claim_signing_binding(
        &self,
        record: &PostAnchorClaimSigningBindingRecordV1,
    ) -> Result<(), SessionStoreError> {
        let final_name = post_anchor_claim_signing_binding_name(record.session_id);
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.rosters,
            &staging_name,
            &final_name,
            &record.bytes,
            POST_ANCHOR_CLAIM_BINDING_RECORD_LEN,
        )
    }

    fn load_post_anchor_claim_signing_binding(
        &self,
        session_id: [u8; 32],
    ) -> Result<PostAnchorClaimSigningBindingRecordV1, SessionStoreError> {
        let name = post_anchor_claim_signing_binding_name(session_id);
        let bytes = self.rosters.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            POST_ANCHOR_CLAIM_BINDING_RECORD_LEN,
        )?;
        let record = PostAnchorClaimSigningBindingRecordV1::from_bytes(&bytes)?;
        if record.session_id != session_id {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(record)
    }

    fn persist_post_anchor_claim_pre_signature(
        &self,
        record: &PostAnchorClaimPreSignatureRecordV1,
    ) -> Result<(), SessionStoreError> {
        let final_name = post_anchor_claim_pre_signature_name(record.session_id);
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.artifacts,
            &staging_name,
            &final_name,
            &record.bytes,
            POST_ANCHOR_CLAIM_PRE_SIGNATURE_RECORD_LEN,
        )
    }

    fn load_post_anchor_claim_pre_signature(
        &self,
        session_id: [u8; 32],
    ) -> Result<PostAnchorClaimPreSignatureRecordV1, SessionStoreError> {
        let name = post_anchor_claim_pre_signature_name(session_id);
        match self.artifacts.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            POST_ANCHOR_CLAIM_PRE_SIGNATURE_RECORD_LEN,
        ) {
            Ok(bytes) => {
                let record = PostAnchorClaimPreSignatureRecordV1::from_bytes(&bytes)?;
                if record.session_id != session_id {
                    return Err(SessionStoreError::Quarantined);
                }
                Ok(record)
            }
            Err(LinuxCapabilityError::NotFound) => Err(SessionStoreError::SessionNotFound),
            Err(error) => Err(error.into()),
        }
    }

    fn load_post_anchor_claim_authorization(
        &self,
        session_id: [u8; 32],
        state: PostAnchorClaimAuthorizationStateV1,
    ) -> Result<PostAnchorClaimAuthorizationRecordV1, SessionStoreError> {
        let name = post_anchor_claim_authorization_name(session_id, state);
        let directory = match state {
            PostAnchorClaimAuthorizationStateV1::Issued => &self.artifacts,
            PostAnchorClaimAuthorizationStateV1::Consumed => &self.consumptions,
        };
        match directory.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            POST_ANCHOR_CLAIM_AUTH_RECORD_LEN,
        ) {
            Ok(bytes) => {
                let record = PostAnchorClaimAuthorizationRecordV1::from_bytes(&bytes)?;
                if record.session_id != session_id || record.state != state {
                    return Err(SessionStoreError::Quarantined);
                }
                Ok(record)
            }
            Err(LinuxCapabilityError::NotFound) => Err(SessionStoreError::SessionNotFound),
            Err(error) => Err(error.into()),
        }
    }

    fn post_anchor_claim_consumption_exists(
        &self,
        session_id: [u8; 32],
    ) -> Result<bool, SessionStoreError> {
        match self.load_post_anchor_claim_authorization(
            session_id,
            PostAnchorClaimAuthorizationStateV1::Consumed,
        ) {
            Ok(_) => Ok(true),
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn authenticate_post_anchor_claim_evidence(
        &self,
        evidence: &PostAnchorDomClaimSigningEvidenceV1,
    ) -> Result<AuthenticatedPostAnchorClaimV1, SessionStoreError> {
        if evidence.session_id == [0; 32]
            || evidence.settlement_id == [0; 32]
            || evidence.terms_hash == [0; 32]
            || evidence.m8_policy_digest == [0; 32]
            || evidence.m8_anchor_evidence_digest == [0; 32]
            || evidence.dom_funding_id == [0; 32]
            || evidence.bitcoin_funding_id == [0; 32]
            || evidence.dom_shared_output_commitment == [0; 33]
            || evidence.expected_claim_template_hash == [0; 32]
            || evidence.expected_round_start_transcript_hash == [0; 32]
            || evidence.chain_id == [0; 32]
            || evidence.dom_confirmation_depth == 0
            || evidence.bitcoin_confirmation_depth == 0
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let current = self.load_session_locked(evidence.session_id)?;
        if current.phase() != SessionPhaseV1::FundingConfirmed
            || !current.irreversible().funding_authorized
            || current.terms_hash() != evidence.terms_hash
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let gate = self.load_m8_funding_gate(evidence.session_id)?;
        let issuance = self.load_m8_funding_issuance(evidence.session_id)?;
        let commit = self.load_m8_funding_commit(evidence.session_id)?;
        self.verify_m8_commit_against_authority(&commit)?;
        let funding_commit_digest = copy_array(&commit.bytes[commit.bytes.len() - DIGEST_LEN..])?;
        let persisted_dom_funding_id =
            *dom_crypto::blake2b_256(&commit.artifact.funding_bytes).as_bytes();
        if self.funding_gate_exists(evidence.session_id)?
            || self.issuance_exists(evidence.session_id)?
            || issuance.gate_digest != gate.digest
            || issuance.binding.chain_id() != &gate.chain_id
            || issuance.binding.session_id() != &evidence.session_id
            || issuance.binding.terms_hash() != &evidence.terms_hash
            || issuance.binding.m8_policy_digest() != &evidence.m8_policy_digest
            || issuance.binding.claim_template_hash() != &evidence.expected_claim_template_hash
            || issuance.binding.claim_adaptor_point()
                != &evidence.expected_adaptor_point.to_compressed_bytes()
            || issuance.binding.shared_output_commitment() != &evidence.dom_shared_output_commitment
            || issuance.digest == [0; 32]
            || gate.chain_id != evidence.chain_id
            || gate.terms_hash != evidence.terms_hash
            || gate.m8_policy_digest != evidence.m8_policy_digest
            || gate.claim_template_hash != evidence.expected_claim_template_hash
            || gate.claim_adaptor_point != evidence.expected_adaptor_point
            || gate.shared_output_commitment != evidence.dom_shared_output_commitment
            || persisted_dom_funding_id != evidence.dom_funding_id
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        if current.transcript_hash() != evidence.expected_round_start_transcript_hash {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        Ok((current, gate.digest, issuance.digest, funding_commit_digest))
    }

    fn authenticate_post_anchor_claim_record(
        &self,
        issued: &PostAnchorClaimAuthorizationRecordV1,
    ) -> Result<(), SessionStoreError> {
        if issued.state != PostAnchorClaimAuthorizationStateV1::Issued {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let current = self.load_session_locked(issued.session_id)?;
        let bound = self.load_session_revision(issued.session_id, issued.bound_session_revision)?;
        let gate = self.load_m8_funding_gate(issued.session_id)?;
        let issuance = self.load_m8_funding_issuance(issued.session_id)?;
        let commit = self.load_m8_funding_commit(issued.session_id)?;
        self.verify_m8_commit_against_authority(&commit)?;
        let funding_commit_digest = copy_array(&commit.bytes[commit.bytes.len() - DIGEST_LEN..])?;
        let persisted_dom_funding_id =
            *dom_crypto::blake2b_256(&commit.artifact.funding_bytes).as_bytes();
        if self.funding_gate_exists(issued.session_id)?
            || self.issuance_exists(issued.session_id)?
            || issuance.gate_digest != gate.digest
            || issuance.binding.m8_policy_digest() != &issued.m8_policy_digest
            || issuance.binding.claim_template_hash() != &issued.claim_template_hash
            || issuance.binding.claim_adaptor_point() != &issued.adaptor_point.to_compressed_bytes()
            || issuance.binding.shared_output_commitment() != &issued.dom_shared_output_commitment
            || current.phase() != SessionPhaseV1::FundingConfirmed
            || !current.irreversible().funding_authorized
            || bound.phase() != SessionPhaseV1::FundingConfirmed
            || bound.digest() != &issued.bound_session_record_digest
            || bound.terms_hash() != current.terms_hash()
            || bound.irreversible() != current.irreversible()
            || bound.chain() != current.chain()
            || bound.encrypted_payload() != current.encrypted_payload()
            || issued.terms_hash != current.terms_hash()
            || issued.m8_policy_digest != gate.m8_policy_digest
            || issued.chain_id != gate.chain_id
            || issued.claim_template_hash != gate.claim_template_hash
            || issued.adaptor_point != gate.claim_adaptor_point
            || issued.dom_funding_id != persisted_dom_funding_id
            || issued.dom_shared_output_commitment != gate.shared_output_commitment
            || issued.bitcoin_funding_id == [0; 32]
            || issued.dom_confirmation_depth == 0
            || issued.bitcoin_confirmation_depth == 0
            || issued.m8_funding_gate_digest != gate.digest
            || issued.m8_funding_issuance_digest != issuance.digest
            || issued.operational_funding_commit_digest != funding_commit_digest
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        Ok(())
    }

    fn audit_post_anchor_claim_authorization(
        &self,
        issued: &PostAnchorClaimAuthorizationRecordV1,
        consumed: Option<&PostAnchorClaimAuthorizationRecordV1>,
    ) -> Result<(), SessionStoreError> {
        if issued.state != PostAnchorClaimAuthorizationStateV1::Issued {
            return Err(SessionStoreError::Quarantined);
        }
        let bound = self.load_session_revision(issued.session_id, issued.bound_session_revision)?;
        let gate = self.load_m8_funding_gate(issued.session_id)?;
        let issuance = self.load_m8_funding_issuance(issued.session_id)?;
        let commit = self.load_m8_funding_commit(issued.session_id)?;
        self.verify_m8_commit_against_authority(&commit)?;
        let funding_commit_digest = copy_array(&commit.bytes[commit.bytes.len() - DIGEST_LEN..])?;
        let persisted_dom_funding_id =
            *dom_crypto::blake2b_256(&commit.artifact.funding_bytes).as_bytes();
        if self.funding_gate_exists(issued.session_id)?
            || self.issuance_exists(issued.session_id)?
            || issuance.gate_digest != gate.digest
            || issuance.binding.m8_policy_digest() != &issued.m8_policy_digest
            || issuance.binding.claim_template_hash() != &issued.claim_template_hash
            || issuance.binding.claim_adaptor_point() != &issued.adaptor_point.to_compressed_bytes()
            || issuance.binding.shared_output_commitment() != &issued.dom_shared_output_commitment
            || issued.chain_id == [0; 32]
            || bound.phase() != SessionPhaseV1::FundingConfirmed
            || bound.digest() != &issued.bound_session_record_digest
            || bound.terms_hash() != issued.terms_hash
            || gate.chain_id != issued.chain_id
            || gate.terms_hash != issued.terms_hash
            || gate.m8_policy_digest != issued.m8_policy_digest
            || gate.claim_template_hash != issued.claim_template_hash
            || gate.claim_adaptor_point != issued.adaptor_point
            || issued.dom_funding_id != persisted_dom_funding_id
            || issued.dom_shared_output_commitment != gate.shared_output_commitment
            || issued.bitcoin_funding_id == [0; 32]
            || issued.dom_confirmation_depth == 0
            || issued.bitcoin_confirmation_depth == 0
            || bound.transcript_hash() != issued.round_start_transcript_hash
            || gate.digest != issued.m8_funding_gate_digest
            || issuance.digest != issued.m8_funding_issuance_digest
            || funding_commit_digest != issued.operational_funding_commit_digest
        {
            return Err(SessionStoreError::Quarantined);
        }
        if let Some(consumed) = consumed {
            if consumed.state != PostAnchorClaimAuthorizationStateV1::Consumed
                || consumed.predecessor_digest != issued.digest
                || consumed.session_id != issued.session_id
                || consumed.settlement_id != issued.settlement_id
                || consumed.terms_hash != issued.terms_hash
                || consumed.m8_policy_digest != issued.m8_policy_digest
                || consumed.m8_anchor_evidence_digest != issued.m8_anchor_evidence_digest
                || consumed.dom_funding_id != issued.dom_funding_id
                || consumed.bitcoin_funding_id != issued.bitcoin_funding_id
                || consumed.dom_shared_output_commitment != issued.dom_shared_output_commitment
                || consumed.chain_id != issued.chain_id
                || consumed.claim_template_hash != issued.claim_template_hash
                || consumed.round_start_transcript_hash != issued.round_start_transcript_hash
                || consumed.adaptor_point != issued.adaptor_point
                || consumed.bound_session_revision != issued.bound_session_revision
                || consumed.bound_session_record_digest != issued.bound_session_record_digest
                || consumed.m8_funding_gate_digest != issued.m8_funding_gate_digest
                || consumed.m8_funding_issuance_digest != issued.m8_funding_issuance_digest
                || consumed.issuance_id != issued.issuance_id
                || consumed.operational_funding_commit_digest
                    != issued.operational_funding_commit_digest
                || consumed.dom_confirmation_depth != issued.dom_confirmation_depth
                || consumed.bitcoin_confirmation_depth != issued.bitcoin_confirmation_depth
            {
                return Err(SessionStoreError::Quarantined);
            }
        }
        Ok(())
    }

    fn authenticate_live_consumed_claim_authority(
        &self,
        authorization: &ConsumedClaimSigningAuthorizationV1,
    ) -> Result<
        (
            PostAnchorClaimAuthorizationRecordV1,
            PostAnchorClaimAuthorizationRecordV1,
            SessionRecordV1,
        ),
        SessionStoreError,
    > {
        if authorization._open_instance_id != self.open_instance_id
            || !self
                .process_claim_signing_authorities
                .lock()
                .map_err(|_| SessionStoreError::StoreBusy)?
                .contains(&authorization.issuance_id)
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let issued = self.load_post_anchor_claim_authorization(
            authorization.session_id,
            PostAnchorClaimAuthorizationStateV1::Issued,
        )?;
        let consumed = self.load_post_anchor_claim_authorization(
            authorization.session_id,
            PostAnchorClaimAuthorizationStateV1::Consumed,
        )?;
        self.audit_post_anchor_claim_authorization(&issued, Some(&consumed))?;
        let current = self.load_session_locked(issued.session_id)?;
        let bound = self.load_session_revision(issued.session_id, issued.bound_session_revision)?;
        if authorization.session_id != issued.session_id
            || authorization.settlement_id != issued.settlement_id
            || authorization.terms_hash != issued.terms_hash
            || authorization.m8_policy_digest != issued.m8_policy_digest
            || authorization.m8_anchor_evidence_digest != issued.m8_anchor_evidence_digest
            || authorization.dom_funding_id != issued.dom_funding_id
            || authorization.bitcoin_funding_id != issued.bitcoin_funding_id
            || authorization.dom_shared_output_commitment != issued.dom_shared_output_commitment
            || authorization.claim_template_hash != issued.claim_template_hash
            || authorization.round_start_transcript_hash != issued.round_start_transcript_hash
            || authorization.adaptor_point != issued.adaptor_point
            || authorization.issuance_record_digest != issued.digest
            || authorization.consumption_record_digest != consumed.digest
            || authorization.bound_session_revision != issued.bound_session_revision
            || authorization.bound_session_record_digest != issued.bound_session_record_digest
            || authorization.dom_confirmation_depth != issued.dom_confirmation_depth
            || authorization.bitcoin_confirmation_depth != issued.bitcoin_confirmation_depth
            || current.phase() != SessionPhaseV1::FundingConfirmed
            || bound.phase() != SessionPhaseV1::FundingConfirmed
            || current.terms_hash() != bound.terms_hash()
            || current.irreversible() != bound.irreversible()
            || current.chain() != bound.chain()
            || current.encrypted_payload() != bound.encrypted_payload()
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        Ok((issued, consumed, current))
    }

    fn next_transport_sequence(
        &self,
        session_id: [u8; 32],
        sender_id: [u8; 32],
    ) -> Result<u64, SessionStoreError> {
        let prefix = format!("{}-{}-", hex_lower(&session_id), hex_lower(&sender_id));
        let mut sequences = Vec::new();
        self.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if name.starts_with(&prefix) && name.ends_with(".message") {
                let sequence = parse_transport_message_sequence(name)
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
                sequences.push(sequence);
            }
            Ok(())
        })?;
        sequences.sort_unstable();
        for (index, sequence) in sequences.iter().enumerate() {
            let expected = u64::try_from(index).map_err(|_| SessionStoreError::Quarantined)?;
            if *sequence != expected {
                return Err(SessionStoreError::Quarantined);
            }
        }
        u64::try_from(sequences.len()).map_err(|_| SessionStoreError::Quarantined)
    }

    fn transport_message_count(&self, session_id: [u8; 32]) -> Result<usize, SessionStoreError> {
        let prefix = format!("{}-", hex_lower(&session_id));
        let mut count = 0usize;
        self.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if name.starts_with(&prefix) && name.ends_with(".message") {
                parse_transport_message_sequence(name)
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
                count = count
                    .checked_add(1)
                    .ok_or(LinuxCapabilityError::InvalidObject)?;
            }
            Ok(())
        })?;
        Ok(count)
    }

    fn authenticate_transport_record(
        &self,
        name: &str,
        record: &TransportMessageRecordV1,
    ) -> Result<(ParsedTransportEnvelopeV1, DirectionV1), SessionStoreError> {
        let expected_name = transport_message_name(
            record.session_id,
            record.sender_id,
            record.sequence,
            record.equivocation,
        );
        if name != expected_name {
            return Err(SessionStoreError::Quarantined);
        }
        let roster = self.load_transport_roster(record.session_id)?;
        let participant = roster
            .participants
            .iter()
            .find(|candidate| candidate.participant_id == record.sender_id)
            .ok_or(SessionStoreError::Quarantined)?;
        let envelope = ParsedTransportEnvelopeV1::parse(&record.signed_bytes)
            .map_err(|_| SessionStoreError::Quarantined)?;
        envelope
            .verify(&participant.identity_key)
            .map_err(|_| SessionStoreError::Quarantined)?;
        if envelope.chain_id != roster.chain_id || record.direction != participant.direction {
            return Err(SessionStoreError::Quarantined);
        }
        if record.equivocation {
            if record.successor.phase() != SessionPhaseV1::FailedClosed {
                return Err(SessionStoreError::Quarantined);
            }
            let accepted_name =
                transport_message_name(record.session_id, record.sender_id, record.sequence, false);
            let accepted_bytes = self.messages.read_bounded_file(
                &ValidatedComponent::registered(&accepted_name)?,
                TRANSPORT_MESSAGE_MAX_LEN,
            )?;
            let accepted = TransportMessageRecordV1::from_bytes(&accepted_bytes)
                .map_err(|_| SessionStoreError::Quarantined)?;
            if accepted.equivocation
                || accepted.session_id != record.session_id
                || accepted.sender_id != record.sender_id
                || accepted.sequence != record.sequence
                || accepted.signed_bytes == record.signed_bytes
            {
                return Err(SessionStoreError::Quarantined);
            }
        }
        Ok((envelope, participant.direction))
    }

    fn require_authenticated_transport_successor(
        &self,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        signed_bytes: &[u8],
        direction: DirectionV1,
        successor: &SessionRecordV1,
    ) -> Result<(), SessionStoreError> {
        if current.phase() == SessionPhaseV1::RefundSigned && envelope.message_type == 0x11 {
            let gate = self.load_m8_funding_gate(current.session_id())?;
            if self.funding_gate_exists(current.session_id())?
                || self.issuance_exists(current.session_id())?
                || envelope.payload(signed_bytes)? != gate.digest
                || successor.phase() != SessionPhaseV1::RefundSigned
            {
                return Err(SessionStoreError::FundingAuthorityUnavailable);
            }
            require_exact_successor(current, current.revision(), successor)?;
            if envelope.previous_transcript_hash != current.transcript_hash()
                || successor.transcript_hash()
                    != accepted_transport_transcript_hash(
                        &current.transcript_hash(),
                        &envelope.message_digest,
                        direction,
                        envelope.message_type,
                        SessionPhaseV1::RefundSigned,
                    )?
            {
                return Err(SessionStoreError::InvalidTransition);
            }
            return Ok(());
        }
        if current.phase() != SessionPhaseV1::FundingConfirmed
            || !(0x0c..=0x0f).contains(&envelope.message_type)
        {
            return require_transport_successor(current, envelope, direction, successor);
        }
        let issued = self.load_post_anchor_claim_authorization(
            current.session_id(),
            PostAnchorClaimAuthorizationStateV1::Issued,
        )?;
        let consumed = self.load_post_anchor_claim_authorization(
            current.session_id(),
            PostAnchorClaimAuthorizationStateV1::Consumed,
        )?;
        self.audit_post_anchor_claim_authorization(&issued, Some(&consumed))?;
        let bound = self.load_session_revision(issued.session_id, issued.bound_session_revision)?;
        if bound.phase() != SessionPhaseV1::FundingConfirmed
            || bound.digest() != &issued.bound_session_record_digest
            || current.terms_hash() != bound.terms_hash()
            || current.irreversible() != bound.irreversible()
            || current.chain() != bound.chain()
            || current.encrypted_payload() != bound.encrypted_payload()
            || successor.phase() != SessionPhaseV1::FundingConfirmed
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let payload = envelope.payload(signed_bytes)?;
        match envelope.message_type {
            0x0c..=0x0e
                if signing_payload_purpose(envelope.message_type, payload)?
                    == PurposeV1::ClaimAdaptor => {}
            0x0f => {
                let pre_signature = AdaptorPreSignatureV1::from_bytes(payload)
                    .map_err(|_| SessionStoreError::Canonical)?;
                if pre_signature.claim_template_hash() != &issued.claim_template_hash
                    || pre_signature.adaptor_point() != &issued.adaptor_point
                {
                    return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
                }
            }
            _ => return Err(SessionStoreError::ClaimSigningAuthorityUnavailable),
        }
        require_exact_successor(current, current.revision(), successor)?;
        if envelope.previous_transcript_hash != current.transcript_hash()
            || successor.transcript_hash()
                != accepted_transport_transcript_hash(
                    &current.transcript_hash(),
                    &envelope.message_digest,
                    direction,
                    envelope.message_type,
                    SessionPhaseV1::FundingConfirmed,
                )?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }

    fn audit_operational_bp_continuation(
        &self,
        session_id: [u8; 32],
        current: &SessionRecordV1,
        roster: &TransportRosterRecordV1,
        statement: &BpStatementV1,
        verifier: &DomCollaborativeRangeProofV1,
    ) -> Result<AuthenticatedOperationalBpContinuationV1, SessionStoreError> {
        let bp_participant_indices = [
            roster
                .participants
                .iter()
                .position(|participant| {
                    participant.participant_id == statement.participant_ids()[0]
                })
                .ok_or(SessionStoreError::InvalidTransition)?,
            roster
                .participants
                .iter()
                .position(|participant| {
                    participant.participant_id == statement.participant_ids()[1]
                })
                .ok_or(SessionStoreError::InvalidTransition)?,
        ];
        if bp_participant_indices[0] == bp_participant_indices[1] {
            return Err(SessionStoreError::InvalidTransition);
        }
        let prefix = format!("{}-", hex_lower(&session_id));
        let mut retained = Vec::new();
        self.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if !name.starts_with(&prefix) {
                return Ok(());
            }
            let bytes = self.messages.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                TRANSPORT_MESSAGE_MAX_LEN,
            )?;
            let record = TransportMessageRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            retained.push((name.to_owned(), record));
            Ok(())
        })?;

        let mut messages = Vec::new();
        for (name, record) in retained {
            let (envelope, direction) = self.authenticate_transport_record(&name, &record)?;
            if record.equivocation {
                return Err(SessionStoreError::Quarantined);
            }
            let durable = self.load_session_revision(session_id, record.successor.revision())?;
            if durable.as_bytes() != record.successor.as_bytes() {
                return Err(SessionStoreError::Quarantined);
            }
            if (0x05..=0x0a).contains(&envelope.message_type) {
                messages.push((record.successor.revision(), record, envelope, direction));
            }
        }
        messages.sort_by_key(|(revision, _, _, _)| *revision);
        if messages.len() > 11 || messages.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(SessionStoreError::Quarantined);
        }

        let round_start_revision = match messages.first() {
            Some((revision, _, _, _)) => revision
                .checked_sub(1)
                .ok_or(SessionStoreError::Quarantined)?,
            None => current.revision(),
        };
        let round_start = self.load_session_revision(session_id, round_start_revision)?;
        if round_start.phase() != SessionPhaseV1::SharesRevealed {
            return Err(SessionStoreError::InvalidTransition);
        }
        let mut sender_sequence_bases = [0_u64; 2];
        for (index, roster_index) in bp_participant_indices.into_iter().enumerate() {
            let participant = &roster.participants[roster_index];
            sender_sequence_bases[index] = self.transport_sequence_at_revision(
                session_id,
                participant.participant_id,
                round_start_revision,
            )?;
            sender_sequence_bases[index]
                .checked_add(6)
                .ok_or(SessionStoreError::CapacityExceeded)?;
        }

        let mut common_commitments = [None, None];
        let mut common_reveals: [Option<Zeroizing<[u8; 32]>>; 2] = [None, None];
        let mut round1_commitments = [None, None];
        let mut round1_shares: [Option<BpRound1ShareV1>; 2] = [None, None];
        let mut round2_shares: [Option<Zeroizing<[u8; BpRound2ShareV1::ENCODED_LEN]>>; 2] =
            [None, None];
        let mut finalizer_participant_index = None;
        let mut final_proof = None;
        let mut transcript_hash = round_start.transcript_hash();
        let mut session_revision = round_start_revision;

        for (position, (revision, record, envelope, direction)) in messages.into_iter().enumerate()
        {
            let (expected_type, participant_index, expected_sequence) = if position < 10 {
                let participant_index = position % 2;
                let pair_index = position / 2;
                let expected_type = 0x05_u8
                    .checked_add(
                        u8::try_from(pair_index).map_err(|_| SessionStoreError::Canonical)?,
                    )
                    .ok_or(SessionStoreError::Canonical)?;
                let expected_sequence = sender_sequence_bases[participant_index]
                    .checked_add(
                        u64::try_from(pair_index)
                            .map_err(|_| SessionStoreError::CapacityExceeded)?,
                    )
                    .ok_or(SessionStoreError::CapacityExceeded)?;
                (expected_type, participant_index, expected_sequence)
            } else {
                let participant_index = bp_participant_indices
                    .iter()
                    .position(|roster_index| {
                        roster.participants[*roster_index].participant_id == envelope.sender_id
                    })
                    .ok_or(SessionStoreError::Quarantined)?;
                let expected_sequence = sender_sequence_bases[participant_index]
                    .checked_add(5)
                    .ok_or(SessionStoreError::CapacityExceeded)?;
                (0x0a, participant_index, expected_sequence)
            };
            let expected_revision = round_start_revision
                .checked_add(
                    u64::try_from(position)
                        .map_err(|_| SessionStoreError::CapacityExceeded)?
                        .checked_add(1)
                        .ok_or(SessionStoreError::CapacityExceeded)?,
                )
                .ok_or(SessionStoreError::CapacityExceeded)?;
            let expected_phase = match expected_type {
                0x05 => SessionPhaseV1::BpCommonCommitted,
                0x06 => SessionPhaseV1::BpCommonEstablished,
                0x07 => SessionPhaseV1::BpNonceCommitted,
                0x08 => SessionPhaseV1::BpRound1Complete,
                0x09 => SessionPhaseV1::BpRound2Complete,
                0x0a => SessionPhaseV1::OutputFinalized,
                _ => return Err(SessionStoreError::Canonical),
            };
            let participant = &roster.participants[bp_participant_indices[participant_index]];
            let predecessor_revision = expected_revision
                .checked_sub(1)
                .ok_or(SessionStoreError::Quarantined)?;
            let predecessor = self.load_session_revision(session_id, predecessor_revision)?;
            let durable = self.load_session_revision(session_id, revision)?;
            if revision != expected_revision
                || envelope.message_type != expected_type
                || envelope.sender_id != participant.participant_id
                || envelope.sequence != expected_sequence
                || envelope.previous_transcript_hash != transcript_hash
                || direction != participant.direction
                || predecessor.transcript_hash() != transcript_hash
                || durable.phase() != expected_phase
                || durable.as_bytes() != record.successor.as_bytes()
            {
                return Err(SessionStoreError::InvalidTransition);
            }
            require_exact_successor(&predecessor, predecessor_revision, &durable)
                .map_err(|_| SessionStoreError::Quarantined)?;
            let expected_transcript = accepted_transport_transcript_hash(
                &transcript_hash,
                &envelope.message_digest,
                direction,
                expected_type,
                expected_phase,
            )?;
            if durable.transcript_hash() != expected_transcript {
                return Err(SessionStoreError::Quarantined);
            }
            let payload = envelope.payload(&record.signed_bytes)?;
            match expected_type {
                0x05 => {
                    let commitment: [u8; 32] = payload
                        .try_into()
                        .map_err(|_| SessionStoreError::Quarantined)?;
                    if common_commitments[participant_index]
                        .replace(commitment)
                        .is_some()
                    {
                        return Err(SessionStoreError::Quarantined);
                    }
                }
                0x06 => {
                    let reveal: [u8; 32] = payload
                        .try_into()
                        .map_err(|_| SessionStoreError::Quarantined)?;
                    let accepted = common_commitments[participant_index]
                        .ok_or(SessionStoreError::Quarantined)?;
                    let mut input = [0u8; 96];
                    input[..32].copy_from_slice(&statement.statement_hash());
                    input[32..64].copy_from_slice(&participant.participant_id);
                    input[64..].copy_from_slice(&reveal);
                    if tagged_hash(DomainTag::BpCommonCommit.as_str(), &input) != accepted
                        || common_reveals[participant_index]
                            .replace(Zeroizing::new(reveal))
                            .is_some()
                    {
                        return Err(SessionStoreError::Quarantined);
                    }
                }
                0x07 => {
                    let commitment: [u8; 32] = payload
                        .try_into()
                        .map_err(|_| SessionStoreError::Quarantined)?;
                    if round1_commitments[participant_index]
                        .replace(commitment)
                        .is_some()
                    {
                        return Err(SessionStoreError::Quarantined);
                    }
                }
                0x08 => {
                    if payload.len() != BpRound1ShareV1::ENCODED_LEN
                        || payload[38..70] != participant.participant_id
                        || u16::from_le_bytes(
                            payload[70..72]
                                .try_into()
                                .map_err(|_| SessionStoreError::Quarantined)?,
                        ) != u16::try_from(participant_index)
                            .map_err(|_| SessionStoreError::Quarantined)?
                    {
                        return Err(SessionStoreError::Quarantined);
                    }
                    let share = BpRound1ShareV1::from_bytes(payload, statement)
                        .map_err(|_| SessionStoreError::Quarantined)?;
                    if round1_commitments[participant_index] != Some(share.reveal_commitment())
                        || round1_shares[participant_index].replace(share).is_some()
                    {
                        return Err(SessionStoreError::Quarantined);
                    }
                }
                0x09 => {
                    if payload.len() != BpRound2ShareV1::ENCODED_LEN
                        || payload[38..70] != participant.participant_id
                        || u16::from_le_bytes(
                            payload[70..72]
                                .try_into()
                                .map_err(|_| SessionStoreError::Quarantined)?,
                        ) != u16::try_from(participant_index)
                            .map_err(|_| SessionStoreError::Quarantined)?
                    {
                        return Err(SessionStoreError::Quarantined);
                    }
                    BpRound2ShareV1::from_bytes(payload, statement)
                        .map_err(|_| SessionStoreError::Quarantined)?;
                    let mut share = Zeroizing::new([0u8; BpRound2ShareV1::ENCODED_LEN]);
                    share.copy_from_slice(payload);
                    if round2_shares[participant_index].replace(share).is_some() {
                        return Err(SessionStoreError::Quarantined);
                    }
                }
                0x0a => {
                    let proof = RangeProof739::try_from(payload)
                        .map_err(|_| SessionStoreError::Quarantined)?;
                    verifier
                        .verify_final(statement, &proof)
                        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
                    if finalizer_participant_index
                        .replace(
                            u16::try_from(participant_index)
                                .map_err(|_| SessionStoreError::Quarantined)?,
                        )
                        .is_some()
                        || final_proof.replace(proof).is_some()
                    {
                        return Err(SessionStoreError::Quarantined);
                    }
                }
                _ => return Err(SessionStoreError::Canonical),
            }
            transcript_hash = expected_transcript;
            session_revision = revision;
        }

        let accepted_count = usize::try_from(
            session_revision
                .checked_sub(round_start_revision)
                .ok_or(SessionStoreError::Quarantined)?,
        )
        .map_err(|_| SessionStoreError::CapacityExceeded)?;
        if accepted_count > 11 {
            return Err(SessionStoreError::Quarantined);
        }
        if accepted_count < 11
            && (current.revision() != session_revision
                || current.transcript_hash() != transcript_hash)
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        if accepted_count >= 8 {
            let commitments = [
                round1_commitments[0].ok_or(SessionStoreError::Quarantined)?,
                round1_commitments[1].ok_or(SessionStoreError::Quarantined)?,
            ];
            let shares = [
                round1_shares[0]
                    .as_ref()
                    .ok_or(SessionStoreError::Quarantined)?
                    .clone(),
                round1_shares[1]
                    .as_ref()
                    .ok_or(SessionStoreError::Quarantined)?
                    .clone(),
            ];
            AggregateBpRound1::new(statement, &commitments, &shares)
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        }
        if accepted_count >= 10 {
            let shares = round2_shares
                .iter()
                .map(|share| {
                    BpRound2ShareV1::from_bytes(
                        share
                            .as_ref()
                            .ok_or(SessionStoreError::Quarantined)?
                            .as_ref(),
                        statement,
                    )
                    .map_err(|_| SessionStoreError::Quarantined)
                })
                .collect::<Result<Vec<_>, _>>()?;
            AggregateBpRound2::new(statement, shares)
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        }

        let (stage, accepted_participants) = match accepted_count {
            0 => (
                OperationalBpContinuationStageV1::CommonCommit,
                [false, false],
            ),
            1 => (
                OperationalBpContinuationStageV1::CommonCommit,
                [true, false],
            ),
            2 => (
                OperationalBpContinuationStageV1::CommonReveal,
                [false, false],
            ),
            3 => (
                OperationalBpContinuationStageV1::CommonReveal,
                [true, false],
            ),
            4 => (
                OperationalBpContinuationStageV1::RoundCommit,
                [false, false],
            ),
            5 => (OperationalBpContinuationStageV1::RoundCommit, [true, false]),
            6 => (OperationalBpContinuationStageV1::Round1, [false, false]),
            7 => (OperationalBpContinuationStageV1::Round1, [true, false]),
            8 => (OperationalBpContinuationStageV1::Round2, [false, false]),
            9 => (OperationalBpContinuationStageV1::Round2, [true, false]),
            10 => (OperationalBpContinuationStageV1::Finalize, [false, false]),
            11 => {
                let index =
                    usize::from(finalizer_participant_index.ok_or(SessionStoreError::Quarantined)?);
                let mut mask = [false, false];
                *mask.get_mut(index).ok_or(SessionStoreError::Quarantined)? = true;
                (OperationalBpContinuationStageV1::Complete, mask)
            }
            _ => return Err(SessionStoreError::Quarantined),
        };
        Ok(AuthenticatedOperationalBpContinuationV1 {
            chain_id: roster.chain_id,
            session_id,
            terms_hash: current.terms_hash(),
            statement_hash: statement.statement_hash(),
            session_revision,
            transcript_hash,
            stage,
            accepted_participants,
            statement: statement.clone(),
            common_commitments,
            common_reveals,
            round1_commitments,
            round1_shares,
            round2_shares,
            finalizer_participant_index,
            final_proof,
        })
    }

    fn audit_operational_signing_round(
        &self,
        session_id: [u8; 32],
        purpose: PurposeV1,
        roster: &ParticipantRosterV1,
        expected_template_hash: [u8; 32],
        expected_round_phase: SessionPhaseV1,
    ) -> Result<OperationalSigningRoundAuditV1, SessionStoreError> {
        let prefix = format!("{}-", hex_lower(&session_id));
        let mut records = Vec::new();
        self.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if !name.starts_with(&prefix) {
                return Ok(());
            }
            let bytes = self.messages.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                TRANSPORT_MESSAGE_MAX_LEN,
            )?;
            let record = TransportMessageRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            records.push((name.to_owned(), record));
            Ok(())
        })?;
        let mut authenticated = Vec::with_capacity(records.len());
        for (name, record) in records {
            let (envelope, direction) = self.authenticate_transport_record(&name, &record)?;
            if record.equivocation {
                return Err(SessionStoreError::Quarantined);
            }
            let durable = self.load_session_revision(session_id, record.successor.revision())?;
            if durable.as_bytes() != record.successor.as_bytes() {
                return Err(SessionStoreError::Quarantined);
            }
            authenticated.push((record.successor.revision(), record, envelope, direction));
        }
        authenticated.sort_by_key(|(revision, _, _, _)| *revision);
        if authenticated.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(SessionStoreError::Quarantined);
        }

        let mut template_commits = BTreeMap::new();
        let mut signing = Vec::new();
        for (revision, record, envelope, direction) in authenticated {
            let payload = envelope.payload(&record.signed_bytes)?;
            if envelope.message_type == 0x0b {
                let payload: [u8; 160] = payload
                    .try_into()
                    .map_err(|_| SessionStoreError::Quarantined)?;
                if let Some(existing) = template_commits.insert(envelope.sender_id, payload) {
                    if existing != payload {
                        return Err(SessionStoreError::Quarantined);
                    }
                }
            } else if (0x0c..=0x0e).contains(&envelope.message_type)
                && signing_payload_purpose(envelope.message_type, payload)? == purpose
            {
                signing.push((revision, record.signed_bytes, envelope, direction));
            } else if (0x0c..=0x0e).contains(&envelope.message_type)
                && !signing_payload_purpose(envelope.message_type, payload)?
                    .is_strict_v1_authorized()
            {
                return Err(SessionStoreError::Quarantined);
            }
        }
        if template_commits.len() != roster.entries().len()
            || roster
                .entries()
                .iter()
                .any(|participant| !template_commits.contains_key(participant.participant_id()))
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let template_commit_payload = *template_commits
            .values()
            .next()
            .ok_or(SessionStoreError::InvalidTransition)?;
        if template_commits
            .values()
            .any(|payload| payload != &template_commit_payload)
            || template_hash_for_purpose(&template_commit_payload, purpose)
                != expected_template_hash
        {
            return Err(SessionStoreError::Quarantined);
        }

        signing.sort_by_key(|(revision, _, _, _)| *revision);
        let round_start_revision = match signing.first() {
            Some((revision, _, _, _)) => revision
                .checked_sub(1)
                .ok_or(SessionStoreError::Quarantined)?,
            None => self.load_session_locked(session_id)?.revision(),
        };
        let round_start = self.load_session_revision(session_id, round_start_revision)?;
        if round_start.phase() != expected_round_phase {
            return Err(SessionStoreError::InvalidTransition);
        }
        let mut sender_sequence_bases = [0_u64; 2];
        for (protocol_index, participant) in roster.entries().iter().enumerate() {
            sender_sequence_bases[protocol_index] = self.transport_sequence_at_revision(
                session_id,
                *participant.participant_id(),
                round_start_revision,
            )?;
            sender_sequence_bases[protocol_index]
                .checked_add(2)
                .ok_or(SessionStoreError::CapacityExceeded)?;
        }
        let mut transcript = round_start.transcript_hash();
        let mut reveal_transcript_hash = None;
        let mut terminal_revision = round_start_revision;
        let mut terminal_record_digest = *round_start.digest();
        let mut accepted = Vec::with_capacity(signing.len());
        for (position, (revision, bytes, envelope, direction)) in signing.into_iter().enumerate() {
            if position >= 6 {
                return Err(SessionStoreError::CapacityExceeded);
            }
            let kind_index = position / 2;
            let protocol_index = position % 2;
            let expected_kind = 0x0c_u8
                .checked_add(u8::try_from(kind_index).map_err(|_| SessionStoreError::Canonical)?)
                .ok_or(SessionStoreError::Canonical)?;
            let expected_participant = &roster.entries()[protocol_index];
            let expected_sequence = sender_sequence_bases[protocol_index]
                .checked_add(
                    u64::try_from(kind_index).map_err(|_| SessionStoreError::CapacityExceeded)?,
                )
                .ok_or(SessionStoreError::CapacityExceeded)?;
            let expected_signing_index = roster
                .signing_index(expected_participant.participant_id())
                .map_err(|_| SessionStoreError::Canonical)?;
            let payload = envelope.payload(&bytes)?;
            let participant_index = signing_payload_participant_index(expected_kind, payload)?;
            if envelope.message_type != expected_kind
                || envelope.sender_id != *expected_participant.participant_id()
                || envelope.sequence != expected_sequence
                || envelope.previous_transcript_hash != transcript
                || direction != expected_participant.direction()
                || participant_index != expected_signing_index
            {
                return Err(SessionStoreError::InvalidTransition);
            }
            let phase =
                signing_phase_for_message(expected_kind).ok_or(SessionStoreError::Canonical)?;
            transcript =
                advance_transcript_hash_v1(&transcript, &envelope.message_digest, direction, phase);
            let durable = self.load_session_revision(session_id, revision)?;
            if durable.transcript_hash() != transcript {
                return Err(SessionStoreError::Quarantined);
            }
            terminal_revision = revision;
            terminal_record_digest = *durable.digest();
            if position == 3 {
                reveal_transcript_hash = Some(transcript);
            }
            accepted.push(bytes);
        }
        Ok(OperationalSigningRoundAuditV1 {
            round_start_revision,
            round_start_record_digest: *round_start.digest(),
            round_start_transcript_hash: round_start.transcript_hash(),
            reveal_transcript_hash,
            terminal_revision,
            terminal_record_digest,
            terminal_transcript_hash: transcript,
            sender_sequence_bases,
            template_commit_payload,
            accepted_messages: accepted,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn audit_funding_authorized_signing_prefix(
        &self,
        session_id: [u8; 32],
        chain_id: &[u8; 32],
        terms_hash: &[u8; 32],
        expected_template_bytes: &[u8],
        expected_template_hash: &[u8; 32],
        authorized: &SessionRecordV1,
        terminal: &SessionRecordV1,
        require_complete: bool,
    ) -> Result<(), SessionStoreError> {
        let authorized_revision = authorized.revision();
        let accepted_count = terminal
            .revision()
            .checked_sub(authorized_revision)
            .ok_or(SessionStoreError::Quarantined)?;
        if accepted_count > 6 || (require_complete && accepted_count != 6) {
            return Err(SessionStoreError::Quarantined);
        }
        let durable_authorized = self.load_session_revision(session_id, authorized_revision)?;
        let durable_terminal = self.load_session_revision(session_id, terminal.revision())?;
        if authorized.session_id() != session_id
            || terminal.session_id() != session_id
            || durable_authorized.as_bytes() != authorized.as_bytes()
            || durable_terminal.as_bytes() != terminal.as_bytes()
            || authorized.phase() != SessionPhaseV1::FundingAuthorized
            || terminal.phase() != SessionPhaseV1::FundingAuthorized
            || !authorized.irreversible().funding_authorized
            || terminal.terms_hash() != authorized.terms_hash()
            || terminal.irreversible() != authorized.irreversible()
            || terminal.chain() != authorized.chain()
            || terminal.encrypted_payload() != authorized.encrypted_payload()
            || authorized.terms_hash() != *terms_hash
        {
            return Err(SessionStoreError::Quarantined);
        }

        let binding = match self.load_signing_binding(session_id, PurposeV1::Funding) {
            Ok(binding) => binding,
            Err(SessionStoreError::SessionNotFound) if accepted_count == 0 && !require_complete => {
                return Ok(())
            }
            Err(error) => return Err(error),
        };
        let bytes = &binding.bytes;
        let transaction_bytes = &bytes[SIGNING_BINDING_PREFIX_LEN..bytes.len() - DIGEST_LEN];
        let transaction = <Transaction as DomDeserialize>::from_bytes(transaction_bytes)
            .map_err(|_| SessionStoreError::Quarantined)?;
        let canonical_transaction = transaction
            .to_bytes()
            .map_err(|_| SessionStoreError::Quarantined)?;
        let (template_bytes, template_hash) =
            canonical_template_v1(&transaction).map_err(|_| SessionStoreError::Quarantined)?;
        let contract_kind =
            ContractKindV1::try_from(u16::from_le_bytes(copy_array(&bytes[12..14])?))
                .map_err(|_| SessionStoreError::Quarantined)?;
        let kernel_index = u32::from_le_bytes(copy_array(&bytes[232..236])?) as usize;
        let template_commit_payload: [u8; 160] = copy_array(&bytes[312..472])?;
        if bytes[48..80] != *chain_id
            || bytes[80..112] != *terms_hash
            || u64::from_le_bytes(copy_array(&bytes[112..120])?) != authorized_revision
            || bytes[120..152] != *authorized.digest()
            || bytes[184..216] != authorized.transcript_hash()
            || bytes[240..272] != *expected_template_hash
            || bytes[11] != 0
            || bytes[272..305] != [0; 33]
            || contract_kind != ContractKindV1::WitnessOrTimeout
            || canonical_transaction != transaction_bytes
            || template_bytes != expected_template_bytes
            || template_hash != *expected_template_hash
            || template_hash_for_purpose(&template_commit_payload, PurposeV1::Funding)
                != *expected_template_hash
            || kernel_index >= transaction.kernels.len()
        {
            return Err(SessionStoreError::Quarantined);
        }

        let transport_roster = self.load_transport_roster(session_id)?;
        if transport_roster.chain_id != *chain_id {
            return Err(SessionStoreError::Quarantined);
        }
        let mut participant_ids = [[0_u8; 32]; 2];
        let mut identity_keys = Vec::with_capacity(2);
        let mut signing_keys = Vec::with_capacity(2);
        let mut directions = [DirectionV1::Initiator; 2];
        let mut sequence_bases = [0_u64; 2];
        for index in 0..2 {
            let offset = 472 + index * 99;
            participant_ids[index].copy_from_slice(&bytes[offset..offset + 32]);
            identity_keys.push(
                PublicKey::from_compressed_bytes(&bytes[offset + 32..offset + 65])
                    .map_err(|_| SessionStoreError::Quarantined)?,
            );
            signing_keys.push(
                PublicKey::from_compressed_bytes(&bytes[offset + 65..offset + 98])
                    .map_err(|_| SessionStoreError::Quarantined)?,
            );
            directions[index] = DirectionV1::try_from(bytes[offset + 98])
                .map_err(|_| SessionStoreError::Quarantined)?;
            let sequence_offset = 216 + index * 8;
            sequence_bases[index] =
                u64::from_le_bytes(copy_array(&bytes[sequence_offset..sequence_offset + 8])?);
            let transport = transport_roster
                .participants
                .iter()
                .find(|candidate| candidate.participant_id == participant_ids[index])
                .ok_or(SessionStoreError::Quarantined)?;
            if transport.identity_key != identity_keys[index]
                || transport.direction != directions[index]
            {
                return Err(SessionStoreError::Quarantined);
            }
        }
        if participant_ids[0] == [0; 32]
            || participant_ids[0] >= participant_ids[1]
            || identity_keys[0] == identity_keys[1]
            || signing_keys[0] == signing_keys[1]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut aggregate_keys = signing_keys.clone();
        aggregate_keys.sort_by_key(PublicKey::to_compressed_bytes);
        let aggregate = aggregate_public_nonces_v1(&aggregate_keys)
            .map_err(|_| SessionStoreError::Quarantined)?;
        if transaction.kernels[kernel_index].excess.as_bytes() != &aggregate.to_compressed_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
        let signing_indices =
            if signing_keys[0].to_compressed_bytes() < signing_keys[1].to_compressed_bytes() {
                [0_u16, 1_u16]
            } else {
                [1_u16, 0_u16]
            };

        let prefix = format!("{}-", hex_lower(&session_id));
        let mut records = Vec::new();
        self.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if !name.starts_with(&prefix) {
                return Ok(());
            }
            let record_bytes = self.messages.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                TRANSPORT_MESSAGE_MAX_LEN,
            )?;
            let record = TransportMessageRecordV1::from_bytes(&record_bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if record.successor.revision() > authorized_revision
                && record.successor.revision() <= terminal.revision()
            {
                records.push((name.to_owned(), record));
            }
            Ok(())
        })?;
        records.sort_by_key(|(_, record)| record.successor.revision());
        if records.len()
            != usize::try_from(accepted_count).map_err(|_| SessionStoreError::CapacityExceeded)?
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut predecessor = authorized.clone();
        for (position, (name, record)) in records.into_iter().enumerate() {
            let stage_index = position / 2;
            let protocol_index = position % 2;
            let expected_revision = authorized_revision
                .checked_add(
                    u64::try_from(position + 1).map_err(|_| SessionStoreError::CapacityExceeded)?,
                )
                .ok_or(SessionStoreError::CapacityExceeded)?;
            let expected_kind = 0x0c_u8
                .checked_add(u8::try_from(stage_index).map_err(|_| SessionStoreError::Canonical)?)
                .ok_or(SessionStoreError::Canonical)?;
            let expected_sequence = sequence_bases[protocol_index]
                .checked_add(
                    u64::try_from(stage_index).map_err(|_| SessionStoreError::CapacityExceeded)?,
                )
                .ok_or(SessionStoreError::CapacityExceeded)?;
            let (envelope, direction) = self.authenticate_transport_record(&name, &record)?;
            let payload = envelope.payload(&record.signed_bytes)?;
            let durable = self.load_session_revision(session_id, expected_revision)?;
            if record.equivocation
                || record.successor.revision() != expected_revision
                || durable.as_bytes() != record.successor.as_bytes()
                || envelope.message_type != expected_kind
                || envelope.sender_id != participant_ids[protocol_index]
                || envelope.sequence != expected_sequence
                || direction != directions[protocol_index]
                || signing_payload_purpose(expected_kind, payload)? != PurposeV1::Funding
                || signing_payload_participant_index(expected_kind, payload)?
                    != signing_indices[protocol_index]
                || record.successor.phase() != SessionPhaseV1::FundingAuthorized
            {
                return Err(SessionStoreError::Quarantined);
            }
            self.require_authenticated_transport_successor(
                &predecessor,
                &envelope,
                &record.signed_bytes,
                direction,
                &record.successor,
            )?;
            predecessor = record.successor;
        }
        if predecessor.as_bytes() != terminal.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }

    fn transport_sequence_at_revision(
        &self,
        session_id: [u8; 32],
        sender_id: [u8; 32],
        inclusive_revision: u64,
    ) -> Result<u64, SessionStoreError> {
        let prefix = format!("{}-{}-", hex_lower(&session_id), hex_lower(&sender_id));
        let mut sequences = Vec::new();
        self.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if !name.starts_with(&prefix) || !name.ends_with(".message") {
                return Ok(());
            }
            let bytes = self.messages.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                TRANSPORT_MESSAGE_MAX_LEN,
            )?;
            let record = TransportMessageRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if record.successor.revision() <= inclusive_revision {
                sequences.push(record.sequence);
            }
            Ok(())
        })?;
        sequences.sort_unstable();
        for (index, sequence) in sequences.iter().enumerate() {
            if *sequence != u64::try_from(index).map_err(|_| SessionStoreError::Quarantined)? {
                return Err(SessionStoreError::Quarantined);
            }
        }
        u64::try_from(sequences.len()).map_err(|_| SessionStoreError::CapacityExceeded)
    }

    fn require_claim_presignature_journal_evidence(
        &self,
        session_id: [u8; 32],
        claim_transcript_hash: [u8; 32],
        exact_pre_signature: &[u8],
    ) -> Result<(), SessionStoreError> {
        let prefix = format!("{}-", hex_lower(&session_id));
        let mut matches = 0usize;
        self.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if !name.starts_with(&prefix) || !name.ends_with(".message") {
                return Ok(());
            }
            let bytes = self.messages.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                TRANSPORT_MESSAGE_MAX_LEN,
            )?;
            let record = TransportMessageRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if record.equivocation || record.message_type != 0x0f {
                return Ok(());
            }
            let (envelope, _) = self
                .authenticate_transport_record(name, &record)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let payload = envelope
                .payload(&record.signed_bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if payload == exact_pre_signature
                && envelope.previous_transcript_hash == claim_transcript_hash
            {
                matches = matches
                    .checked_add(1)
                    .ok_or(LinuxCapabilityError::InvalidObject)?;
            }
            Ok(())
        })?;
        if matches == 0 {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }

    /// Proves that the M.8 pre-funding DSC1 ancestry has not emitted or
    /// accepted any ClaimAdaptor signing material through the exact funding
    /// issuance revision. Refund/Funding signing traffic is permitted; any
    /// claim commitment, reveal, partial, or adaptor pre-signature is a hard
    /// profile-confusion failure. Nonce allocation is prevented separately by
    /// the consumed post-anchor signer capability.
    fn require_no_pre_anchor_claim_signing_evidence(
        &self,
        session_id: [u8; 32],
        through_revision: u64,
    ) -> Result<(), SessionStoreError> {
        let prefix = format!("{}-", hex_lower(&session_id));
        self.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if !name.starts_with(&prefix) || !name.ends_with(".message") {
                return Ok(());
            }
            let bytes = self.messages.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                TRANSPORT_MESSAGE_MAX_LEN,
            )?;
            let record = TransportMessageRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if record.successor.revision() > through_revision
                || !(0x0c..=0x0f).contains(&record.message_type)
            {
                return Ok(());
            }
            let (envelope, _) = self
                .authenticate_transport_record(name, &record)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let payload = envelope
                .payload(&record.signed_bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let is_claim = match record.message_type {
                0x0c..=0x0e => {
                    signing_payload_purpose(record.message_type, payload)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                        == PurposeV1::ClaimAdaptor
                }
                0x0f => true,
                _ => false,
            };
            if is_claim {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            Ok(())
        })?;
        Ok(())
    }

    fn require_ready_to_fund_votes(
        &self,
        session_id: [u8; 32],
        gate_digest: [u8; 32],
        expected_phase: SessionPhaseV1,
    ) -> Result<(), SessionStoreError> {
        let roster = self.load_transport_roster(session_id)?;
        let senders =
            self.authenticated_ready_to_fund_vote_senders(session_id, gate_digest, expected_phase)?;
        if roster
            .participants
            .iter()
            .any(|participant| !senders.contains(&participant.participant_id))
            || senders.len() != 2
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        Ok(())
    }

    fn prepare_next_operational_m8_ready_to_fund_vote_locked(
        &self,
        prepared: &PreparedOperationalM8FundingGateV1,
    ) -> Result<Option<PreparedOperationalM8ReadyToFundVoteV1>, SessionStoreError> {
        let gate = self.load_m8_funding_gate(prepared.session_id)?;
        let current = self.load_session_locked(prepared.session_id)?;
        let roster = self.load_transport_roster(prepared.session_id)?;
        let identity_binding = self.load_transport_identity_binding(prepared.session_id)?;
        require_transport_identity_binding(&roster, &identity_binding)?;
        if gate.session_id != prepared.session_id
            || gate.digest != prepared.gate_digest
            || gate.refund_tx_hash != prepared.refund_tx_hash
            || roster.chain_id != gate.chain_id
            || current.terms_hash() != gate.terms_hash
            || !matches!(
                current.phase(),
                SessionPhaseV1::RefundSigned | SessionPhaseV1::FundingAuthorized
            )
            || self.funding_gate_exists(prepared.session_id)?
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let senders = self.authenticated_ready_to_fund_vote_senders(
            prepared.session_id,
            gate.digest,
            SessionPhaseV1::RefundSigned,
        )?;
        let accepted = senders.len();
        if accepted > roster.participants.len()
            || roster
                .participants
                .iter()
                .enumerate()
                .any(|(index, participant)| {
                    senders.contains(&participant.participant_id) != (index < accepted)
                })
        {
            return Err(SessionStoreError::Quarantined);
        }
        if accepted == roster.participants.len() {
            return Ok(None);
        }
        if current.phase() != SessionPhaseV1::RefundSigned
            || current.irreversible().funding_authorized
            || self.any_operational_issuance_exists(prepared.session_id)?
            || self.consumption_exists(prepared.session_id)?
            || self.any_operational_commit_exists(prepared.session_id)?
            || self.artifact_exists(prepared.session_id)?
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let participant = &roster.participants[accepted];
        Ok(Some(PreparedOperationalM8ReadyToFundVoteV1 {
            session_id: prepared.session_id,
            participant_id: participant.participant_id,
            sequence: self
                .next_transport_sequence(prepared.session_id, participant.participant_id)?,
            previous_transcript_hash: current.transcript_hash(),
            payload: gate.digest,
        }))
    }

    fn authenticated_ready_to_fund_vote_senders(
        &self,
        session_id: [u8; 32],
        gate_digest: [u8; 32],
        expected_phase: SessionPhaseV1,
    ) -> Result<BTreeSet<[u8; 32]>, SessionStoreError> {
        let prefix = format!("{}-", hex_lower(&session_id));
        let mut senders = BTreeSet::new();
        self.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if !name.starts_with(&prefix) || !name.ends_with(".message") {
                return Ok(());
            }
            let bytes = self.messages.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                TRANSPORT_MESSAGE_MAX_LEN,
            )?;
            let record = TransportMessageRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if record.equivocation || record.message_type != 0x11 {
                return Ok(());
            }
            let (envelope, _) = self
                .authenticate_transport_record(name, &record)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let payload = envelope
                .payload(&record.signed_bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if payload == gate_digest && record.successor.phase() == expected_phase {
                let durable = self
                    .load_session_revision(session_id, record.successor.revision())
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                if durable.as_bytes() != record.successor.as_bytes() {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                senders.insert(envelope.sender_id);
            }
            Ok(())
        })?;
        Ok(senders)
    }

    fn require_funding_template_commits(
        &self,
        session_id: [u8; 32],
        funding_template_hash: [u8; 32],
        claim_template_hash: [u8; 32],
        refund_template_hash: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        let roster = self.load_transport_roster(session_id)?;
        let prefix = format!("{}-", hex_lower(&session_id));
        let mut senders = BTreeSet::new();
        self.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if !name.starts_with(&prefix) || !name.ends_with(".message") {
                return Ok(());
            }
            let bytes = self.messages.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                TRANSPORT_MESSAGE_MAX_LEN,
            )?;
            let record = TransportMessageRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if record.equivocation || record.message_type != 0x0b {
                return Ok(());
            }
            let (envelope, _) = self
                .authenticate_transport_record(name, &record)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let payload: [u8; 160] = envelope
                .payload(&record.signed_bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                .try_into()
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if template_hash_for_purpose(&payload, PurposeV1::Funding) == funding_template_hash
                && template_hash_for_purpose(&payload, PurposeV1::ClaimAdaptor)
                    == claim_template_hash
                && template_hash_for_purpose(&payload, PurposeV1::Refund) == refund_template_hash
            {
                senders.insert(envelope.sender_id);
            }
            Ok(())
        })?;
        if roster
            .participants
            .iter()
            .any(|participant| !senders.contains(&participant.participant_id))
            || senders.len() != 2
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        Ok(())
    }

    fn audit_locked(&self) -> Result<(), SessionStoreError> {
        require_root_inventory(&self.root)?;
        let persisted_policy = BudgetPolicyV1::from_bytes(&self.root.read_bounded_file(
            &ValidatedComponent::registered(POLICY_NAME)?,
            BUDGET_POLICY_LEN,
        )?)?;
        if persisted_policy.as_bytes() != self.policy.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
        let mut sessions = BTreeSet::new();
        self.records.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let (session, _) = parse_session_record_name(name)
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            sessions.insert(session);
            Ok(())
        })?;
        for session in sessions {
            let session_id = decode_hex_32(&session).ok_or(SessionStoreError::Quarantined)?;
            let current = self.load_session_locked(session_id)?;
            if current.irreversible().funding_authorized {
                match self.load_artifact(session_id) {
                    Ok(artifact) => {
                        if artifact.terms_hash != current.terms_hash()
                            || artifact.authorized_revision > current.revision()
                        {
                            return Err(SessionStoreError::Quarantined);
                        }
                    }
                    Err(SessionStoreError::SessionNotFound)
                        if matches!(
                            current.phase(),
                            SessionPhaseV1::FundingAuthorized
                                | SessionPhaseV1::Aborted
                                | SessionPhaseV1::FailedClosed
                        ) =>
                    {
                        match (
                            self.issuance_exists(session_id)?,
                            self.m8_issuance_exists(session_id)?,
                        ) {
                            (true, false) => {
                                let issuance = self.load_funding_issuance(session_id)?;
                                let durable_authorized = self.load_session_revision(
                                    session_id,
                                    issuance.authorized_revision,
                                )?;
                                if issuance.funding_authorized_record.as_bytes()
                                    != durable_authorized.as_bytes()
                                    || current.revision() < issuance.authorized_revision
                                    || self.consumption_exists(session_id)?
                                {
                                    return Err(SessionStoreError::Quarantined);
                                }
                            }
                            (false, true) => {
                                let issuance = self.load_m8_funding_issuance(session_id)?;
                                let durable_authorized = self.load_session_revision(
                                    session_id,
                                    issuance.authorized_revision,
                                )?;
                                if issuance.funding_authorized_record.as_bytes()
                                    != durable_authorized.as_bytes()
                                    || current.revision() < issuance.authorized_revision
                                    || self.consumption_exists(session_id)?
                                {
                                    return Err(SessionStoreError::Quarantined);
                                }
                            }
                            _ => return Err(SessionStoreError::Quarantined),
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        self.audit_artifacts()?;
        self.audit_consumptions()?;
        self.audit_transport()?;
        self.audit_reservation_lookups()?;
        Ok(())
    }

    fn audit_transport(&self) -> Result<(), SessionStoreError> {
        self.rosters.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let session = if let Some(session) = name
                .strip_suffix(".transport-roster")
                .and_then(decode_hex_32)
            {
                self.load_transport_roster(session)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                session
            } else if let Some(session) = name
                .strip_suffix(".transport-identities")
                .and_then(decode_hex_32)
            {
                let binding = self
                    .load_transport_identity_binding(session)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let roster = self
                    .load_transport_roster(session)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                require_transport_identity_binding(&roster, &binding)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                session
            } else if let Some((session, purpose)) = parse_signing_binding_name(name) {
                let binding = self
                    .load_signing_binding(session, purpose)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                if binding.bytes[48..80] == [0; 32] {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                session
            } else if let Some(session) = name
                .strip_suffix(".post-anchor-claim-signing-binding")
                .and_then(decode_hex_32)
            {
                let round = self
                    .load_post_anchor_claim_signing_binding(session)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let issued = self
                    .load_post_anchor_claim_authorization(
                        session,
                        PostAnchorClaimAuthorizationStateV1::Issued,
                    )
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let consumed = self
                    .load_post_anchor_claim_authorization(
                        session,
                        PostAnchorClaimAuthorizationStateV1::Consumed,
                    )
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let signing = self
                    .load_signing_binding(session, PurposeV1::ClaimAdaptor)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let roster_digest = if signing.bytes[48..80] == issued.chain_id {
                    // `TrustedChainIdV1` intentionally has no raw-byte import;
                    // the roster bytes are authenticated directly here and
                    // decoded again through the real trusted chain on resume.
                    let mut roster_bytes = Vec::with_capacity(202);
                    roster_bytes.extend_from_slice(&2_u16.to_le_bytes());
                    for index in 0..2 {
                        let offset = 472 + index * 99;
                        roster_bytes.extend_from_slice(&signing.bytes[offset..offset + 99]);
                    }
                    tagged_hash(POST_ANCHOR_CLAIM_ROSTER_HASH_TAG, &roster_bytes)
                } else {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                };
                if round.digest == [0; 32]
                    || round.issuance_record_digest != issued.digest
                    || round.consumption_record_digest != consumed.digest
                    || round.signing_binding_record_digest
                        != copy_array(&signing.bytes[signing.bytes.len() - DIGEST_LEN..])
                            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    || round.roster_digest != roster_digest
                {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                session
            } else {
                return Err(LinuxCapabilityError::InvalidDirectoryEntry);
            };
            self.load_session_locked(session)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            Ok(())
        })?;
        let mut records = Vec::new();
        self.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let bytes = self.messages.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                TRANSPORT_MESSAGE_MAX_LEN,
            )?;
            let record = TransportMessageRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            records.push((name.to_owned(), record));
            Ok(())
        })?;
        let mut accepted_sequences: BTreeMap<([u8; 32], [u8; 32]), Vec<u64>> = BTreeMap::new();
        let mut accepted_counts: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        for (name, record) in records {
            let (envelope, direction) = self.authenticate_transport_record(&name, &record)?;
            let durable = self
                .load_session_revision(record.session_id, record.successor.revision())
                .map_err(|_| SessionStoreError::Quarantined)?;
            if durable.as_bytes() != record.successor.as_bytes() {
                return Err(SessionStoreError::Quarantined);
            }
            if record.equivocation {
                if record.successor.phase() != SessionPhaseV1::FailedClosed {
                    return Err(SessionStoreError::Quarantined);
                }
            } else {
                let predecessor_revision = record
                    .successor
                    .revision()
                    .checked_sub(1)
                    .ok_or(SessionStoreError::Quarantined)?;
                let predecessor = self
                    .load_session_revision(record.session_id, predecessor_revision)
                    .map_err(|_| SessionStoreError::Quarantined)?;
                self.require_authenticated_transport_successor(
                    &predecessor,
                    &envelope,
                    &record.signed_bytes,
                    direction,
                    &record.successor,
                )
                .map_err(|_| SessionStoreError::Quarantined)?;
                accepted_sequences
                    .entry((record.session_id, record.sender_id))
                    .or_default()
                    .push(record.sequence);
                let count = accepted_counts.entry(record.session_id).or_default();
                *count = count.checked_add(1).ok_or(SessionStoreError::Quarantined)?;
            }
        }
        if accepted_counts
            .values()
            .any(|count| *count > MAX_ACCEPTED_TRANSPORT_MESSAGES)
        {
            return Err(SessionStoreError::Quarantined);
        }
        for sequences in accepted_sequences.values_mut() {
            sequences.sort_unstable();
            for (index, sequence) in sequences.iter().enumerate() {
                if *sequence != u64::try_from(index).map_err(|_| SessionStoreError::Quarantined)? {
                    return Err(SessionStoreError::Quarantined);
                }
            }
        }
        Ok(())
    }

    /// Completes an issuance whose immutable burn record reached disk before
    /// its exact `FundingAuthorized` successor. This recovery never creates a
    /// second issuance or changes its digest/revision; it only publishes the
    /// successor already authenticated inside that issuance record.
    fn recover_operational_funding_issuances(&self) -> Result<(), SessionStoreError> {
        let mut session_ids = Vec::new();
        self.artifacts.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if let Some(session_hex) = name.strip_suffix(".operational-funding-issuance") {
                session_ids.push(
                    decode_hex_32(session_hex)
                        .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?,
                );
            } else if let Some(session_hex) = name.strip_suffix(".operational-m8-funding-issuance")
            {
                session_ids.push(
                    decode_hex_32(session_hex)
                        .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?,
                );
            }
            Ok(())
        })?;
        for session_id in session_ids {
            let legacy = self.issuance_exists(session_id)?;
            let m8 = self.m8_issuance_exists(session_id)?;
            if legacy == m8 {
                return Err(SessionStoreError::Quarantined);
            }
            if m8 {
                self.recover_one_m8_funding_issuance(session_id)?;
                continue;
            }
            let issuance = self.load_funding_issuance(session_id)?;
            let gate = self.load_funding_gate(session_id)?;
            if self.m8_funding_gate_exists(session_id)? {
                return Err(SessionStoreError::Quarantined);
            }
            let current = self.load_session_locked(session_id)?;
            let template_hash =
                authenticate_canonical_dom_template_hash_v1(&issuance.unsigned_template_bytes)?;
            if issuance.gate_digest != gate.digest
                || issuance.binding.chain_id() != &gate.chain_id
                || issuance.binding.session_id() != &session_id
                || issuance.binding.terms_hash() != &gate.terms_hash
                || issuance.binding.shared_output_commitment() != &gate.shared_output_commitment
                || issuance.binding.bp_statement_hash() != &gate.bp_statement_hash
                || issuance.binding.claim_template_hash() != &gate.claim_template_hash
                || issuance.binding.refund_tx_hash() != &gate.refund_tx_hash
                || issuance.binding.claim_presignature_hash() != &gate.claim_pre_signature_hash
                || issuance.binding.backup_receipt_hash() != &gate.backup_receipt_hash
                || issuance.binding.funding_template_hash() != &template_hash
                || issuance.binding.transcript_hash()
                    != &issuance.funding_authorized_record.transcript_hash()
                || issuance.binding.terms_hash() != &issuance.funding_authorized_record.terms_hash()
            {
                return Err(SessionStoreError::Quarantined);
            }
            let predecessor_revision = issuance
                .authorized_revision
                .checked_sub(1)
                .ok_or(SessionStoreError::Quarantined)?;
            if current.revision() == predecessor_revision {
                if current.phase() != SessionPhaseV1::ClaimPrepared
                    || current.irreversible().funding_authorized
                    || issuance.binding.transcript_hash() != &current.transcript_hash()
                    || self.consumption_exists(session_id)?
                {
                    return Err(SessionStoreError::Quarantined);
                }
                require_exact_successor(
                    &current,
                    predecessor_revision,
                    &issuance.funding_authorized_record,
                )
                .map_err(|_| SessionStoreError::Quarantined)?;
                self.persist_session_record(&issuance.funding_authorized_record)?;
            } else if current.revision() >= issuance.authorized_revision {
                let durable =
                    self.load_session_revision(session_id, issuance.authorized_revision)?;
                if durable.as_bytes() != issuance.funding_authorized_record.as_bytes() {
                    return Err(SessionStoreError::Quarantined);
                }
            } else {
                return Err(SessionStoreError::Quarantined);
            }
        }
        Ok(())
    }

    fn recover_one_m8_funding_issuance(
        &self,
        session_id: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        if self.funding_gate_exists(session_id)? || self.issuance_exists(session_id)? {
            return Err(SessionStoreError::Quarantined);
        }
        let issuance = self.load_m8_funding_issuance(session_id)?;
        let gate = self.load_m8_funding_gate(session_id)?;
        let current = self.load_session_locked(session_id)?;
        self.require_no_pre_anchor_claim_signing_evidence(
            session_id,
            issuance.authorized_revision,
        )?;
        let template_hash =
            authenticate_canonical_dom_template_hash_v1(&issuance.unsigned_template_bytes)?;
        if issuance.gate_digest != gate.digest
            || issuance.binding.chain_id() != &gate.chain_id
            || issuance.binding.session_id() != &session_id
            || issuance.binding.terms_hash() != &gate.terms_hash
            || issuance.binding.m8_policy_digest() != &gate.m8_policy_digest
            || issuance.binding.shared_output_commitment() != &gate.shared_output_commitment
            || issuance.binding.bp_statement_hash() != &gate.bp_statement_hash
            || issuance.binding.claim_template_hash() != &gate.claim_template_hash
            || issuance.binding.claim_adaptor_point()
                != &gate.claim_adaptor_point.to_compressed_bytes()
            || issuance.binding.refund_tx_hash() != &gate.refund_tx_hash
            || issuance.binding.backup_receipt_hash() != &gate.backup_receipt_hash
            || issuance.binding.funding_template_hash() != &template_hash
            || issuance.binding.transcript_hash()
                != &issuance.funding_authorized_record.transcript_hash()
        {
            return Err(SessionStoreError::Quarantined);
        }
        let predecessor_revision = issuance
            .authorized_revision
            .checked_sub(1)
            .ok_or(SessionStoreError::Quarantined)?;
        if current.revision() == predecessor_revision {
            if current.phase() != SessionPhaseV1::RefundSigned
                || current.irreversible().funding_authorized
                || issuance.binding.transcript_hash() != &current.transcript_hash()
                || self.consumption_exists(session_id)?
            {
                return Err(SessionStoreError::Quarantined);
            }
            require_exact_successor(
                &current,
                predecessor_revision,
                &issuance.funding_authorized_record,
            )
            .map_err(|_| SessionStoreError::Quarantined)?;
            self.persist_session_record(&issuance.funding_authorized_record)?;
        } else if current.revision() >= issuance.authorized_revision {
            let durable = self.load_session_revision(session_id, issuance.authorized_revision)?;
            if durable.as_bytes() != issuance.funding_authorized_record.as_bytes() {
                return Err(SessionStoreError::Quarantined);
            }
        } else {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }

    fn recover_consumed_funding(&self) -> Result<(), SessionStoreError> {
        let mut commits = Vec::new();
        let mut m8_commits = Vec::new();
        self.consumptions.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if let Some(session_hex) = name.strip_suffix(".operational-funding-commit") {
                let session_id = decode_hex_32(session_hex)
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
                let bytes = self.consumptions.read_bounded_file(
                    &ValidatedComponent::registered(name)?,
                    FUNDING_COMMIT_MAX_LEN,
                )?;
                let commit = OperationalFundingCommitRecordV1::from_bytes(&bytes)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                if commit.session_id != session_id {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                commits.push(commit);
            } else if let Some(session_hex) = name.strip_suffix(".operational-m8-funding-commit") {
                let session_id = decode_hex_32(session_hex)
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
                let bytes = self.consumptions.read_bounded_file(
                    &ValidatedComponent::registered(name)?,
                    M8_FUNDING_COMMIT_MAX_LEN,
                )?;
                let commit = OperationalM8FundingCommitRecordV1::from_bytes(&bytes)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                if commit.session_id != session_id {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                m8_commits.push(commit);
            } else if name.strip_suffix(".funding-consumed").is_none()
                && name
                    .strip_suffix(".post-anchor-claim-signing-consumed")
                    .is_none()
            {
                return Err(LinuxCapabilityError::InvalidDirectoryEntry);
            }
            Ok(())
        })?;
        for commit in commits {
            if self.m8_issuance_exists(commit.session_id)?
                || self.m8_funding_commit_exists(commit.session_id)?
            {
                return Err(SessionStoreError::Quarantined);
            }
            self.verify_operational_commit_against_authority(&commit)?;
            self.persist_artifact(&commit.artifact)?;
            self.persist_consumption(&commit.consumption)?;
        }
        for commit in m8_commits {
            if self.issuance_exists(commit.session_id)?
                || self.funding_commit_exists(commit.session_id)?
            {
                return Err(SessionStoreError::Quarantined);
            }
            self.verify_m8_commit_against_authority(&commit)?;
            self.persist_artifact(&commit.artifact)?;
            self.persist_consumption(&commit.consumption)?;
        }
        let mut session_ids = Vec::new();
        self.consumptions.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let Some(session_hex) = name.strip_suffix(".funding-consumed") else {
                return Ok(());
            };
            let session_id =
                decode_hex_32(session_hex).ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            session_ids.push(session_id);
            Ok(())
        })?;
        for session_id in session_ids {
            let consumption = self.load_consumption(session_id)?;
            let artifact = self.load_artifact(session_id)?;
            if artifact.digest != consumption.artifact_digest
                || artifact.authorized_revision != consumption.authorized_revision
            {
                return Err(SessionStoreError::Quarantined);
            }
            let successor = consumption.broadcast_record()?;
            let current = self.load_session_locked(session_id)?;
            if current.revision() == consumption.authorized_revision {
                require_exact_successor(&current, current.revision(), &successor)
                    .map_err(|_| SessionStoreError::Quarantined)?;
                self.persist_session_record(&successor)?;
            } else if current.revision() > consumption.authorized_revision {
                let durable = self.load_session_revision(session_id, successor.revision())?;
                if durable.as_bytes() != successor.as_bytes() {
                    return Err(SessionStoreError::Quarantined);
                }
            } else {
                return Err(SessionStoreError::Quarantined);
            }
        }
        Ok(())
    }

    fn recover_transport_messages(&self) -> Result<(), SessionStoreError> {
        let mut records = Vec::new();
        self.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let bytes = self.messages.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                TRANSPORT_MESSAGE_MAX_LEN,
            )?;
            let record = TransportMessageRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            records.push((name.to_owned(), record));
            Ok(())
        })?;
        // Authenticate the complete pending set before recovery mutates a
        // session revision. Internal record digests are corruption checks;
        // sender identity signatures and the immutable roster are authority.
        for (name, record) in &records {
            self.authenticate_transport_record(name, record)?;
        }
        records.sort_by_key(|(_, record)| record.successor.revision());
        for (_, record) in records {
            let current = self.load_session_locked(record.session_id)?;
            if current.revision() < record.successor.revision() {
                if current
                    .revision()
                    .checked_add(1)
                    .ok_or(SessionStoreError::Quarantined)?
                    != record.successor.revision()
                {
                    return Err(SessionStoreError::Quarantined);
                }
                require_exact_successor(&current, current.revision(), &record.successor)
                    .map_err(|_| SessionStoreError::Quarantined)?;
                if record.equivocation && record.successor.phase() != SessionPhaseV1::FailedClosed {
                    return Err(SessionStoreError::Quarantined);
                }
                if !record.equivocation {
                    let envelope = ParsedTransportEnvelopeV1::parse(&record.signed_bytes)
                        .map_err(|_| SessionStoreError::Quarantined)?;
                    self.require_authenticated_transport_successor(
                        &current,
                        &envelope,
                        &record.signed_bytes,
                        record.direction,
                        &record.successor,
                    )
                    .map_err(|_| SessionStoreError::Quarantined)?;
                }
                self.persist_session_record(&record.successor)?;
            } else {
                let durable =
                    self.load_session_revision(record.session_id, record.successor.revision())?;
                if durable.as_bytes() != record.successor.as_bytes() {
                    return Err(SessionStoreError::Quarantined);
                }
            }
        }
        Ok(())
    }

    fn audit_artifacts(&self) -> Result<(), SessionStoreError> {
        self.artifacts.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let (session_hex, kind) = if let Some(session) = name.strip_suffix(".funding-artifacts")
            {
                (session, 0_u8)
            } else if let Some(session) = name.strip_suffix(".operational-funding-gate") {
                (session, 1_u8)
            } else if let Some(session) = name.strip_suffix(".operational-m8-funding-gate") {
                (session, 4_u8)
            } else if let Some(session) = name.strip_suffix(".operational-m8-funding-issuance") {
                (session, 5_u8)
            } else if let Some(session) = name.strip_suffix(".operational-funding-issuance") {
                (session, 2_u8)
            } else if let Some(session) = name.strip_suffix(".post-anchor-claim-signing-issued") {
                (session, 3_u8)
            } else if let Some(session) = name.strip_suffix(".post-anchor-claim-pre-signature") {
                (session, 6_u8)
            } else {
                return Err(LinuxCapabilityError::InvalidDirectoryEntry);
            };
            let session_id =
                decode_hex_32(session_hex).ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            let current = self
                .load_session_locked(session_id)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            match kind {
                0 => {
                    let artifact = self
                        .load_artifact(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    let pending = current.phase() == SessionPhaseV1::ClaimPrepared
                        && current.revision().checked_add(1) == Some(artifact.authorized_revision);
                    let committed = current.irreversible().funding_authorized
                        && artifact.authorized_revision <= current.revision();
                    if artifact.terms_hash != current.terms_hash() || (!pending && !committed) {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                    if self
                        .any_operational_issuance_exists(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    {
                        match (
                            self.issuance_exists(session_id)
                                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
                            self.m8_issuance_exists(session_id)
                                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
                        ) {
                            (true, false) => {
                                let commit = self
                                    .load_funding_commit(session_id)
                                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                                self.verify_operational_commit_against_authority(&commit)
                                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                                if commit.artifact.bytes != artifact.bytes {
                                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                                }
                            }
                            (false, true) => {
                                let commit = self
                                    .load_m8_funding_commit(session_id)
                                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                                self.verify_m8_commit_against_authority(&commit)
                                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                                if commit.artifact.bytes != artifact.bytes {
                                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                                }
                            }
                            _ => return Err(LinuxCapabilityError::ExactBytesMismatch),
                        }
                    }
                }
                1 => {
                    if self
                        .m8_funding_gate_exists(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                    let gate = self
                        .load_funding_gate(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    if gate.terms_hash != current.terms_hash()
                        || gate.chain_id == [0; 32]
                        || gate.claim_transcript_hash == [0; 32]
                    {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                }
                2 => {
                    let issuance = self
                        .load_funding_issuance(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    let gate = self
                        .load_funding_gate(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    let burned_before_successor = current.phase() == SessionPhaseV1::ClaimPrepared
                        && current.revision().checked_add(1) == Some(issuance.authorized_revision)
                        && require_exact_successor(
                            &current,
                            current.revision(),
                            &issuance.funding_authorized_record,
                        )
                        .is_ok();
                    let successor_durable = issuance.authorized_revision <= current.revision();
                    if issuance.gate_digest != gate.digest
                        || (!burned_before_successor && !successor_durable)
                        || issuance.binding.chain_id() != &gate.chain_id
                        || issuance.binding.session_id() != &session_id
                        || issuance.binding.transcript_hash()
                            != &issuance.funding_authorized_record.transcript_hash()
                        || issuance.binding.terms_hash() != &gate.terms_hash
                        || issuance.binding.shared_output_commitment()
                            != &gate.shared_output_commitment
                        || issuance.binding.bp_statement_hash() != &gate.bp_statement_hash
                        || issuance.binding.claim_template_hash() != &gate.claim_template_hash
                        || issuance.binding.refund_tx_hash() != &gate.refund_tx_hash
                        || issuance.binding.claim_presignature_hash()
                            != &gate.claim_pre_signature_hash
                        || issuance.binding.backup_receipt_hash() != &gate.backup_receipt_hash
                        || authenticate_canonical_dom_template_hash_v1(
                            &issuance.unsigned_template_bytes,
                        )
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                            != *issuance.binding.funding_template_hash()
                    {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                }
                3 => {
                    let issued = self
                        .load_post_anchor_claim_authorization(
                            session_id,
                            PostAnchorClaimAuthorizationStateV1::Issued,
                        )
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    self.audit_post_anchor_claim_authorization(&issued, None)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                }
                4 => {
                    if self
                        .funding_gate_exists(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                    let gate = self
                        .load_m8_funding_gate(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    if gate.terms_hash != current.terms_hash()
                        || gate.chain_id == [0; 32]
                        || gate.m8_policy_digest == [0; 32]
                    {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                }
                5 => {
                    if self
                        .funding_gate_exists(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                        || self
                            .issuance_exists(session_id)
                            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                    let issuance = self
                        .load_m8_funding_issuance(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    let gate = self
                        .load_m8_funding_gate(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    self.require_no_pre_anchor_claim_signing_evidence(
                        session_id,
                        issuance.authorized_revision,
                    )
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    let predecessor_revision = issuance
                        .authorized_revision
                        .checked_sub(1)
                        .ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
                    let burned_before_successor = current.revision() == predecessor_revision
                        && current.phase() == SessionPhaseV1::RefundSigned
                        && require_exact_successor(
                            &current,
                            current.revision(),
                            &issuance.funding_authorized_record,
                        )
                        .is_ok();
                    let successor_durable = issuance.authorized_revision <= current.revision();
                    let template_hash = authenticate_canonical_dom_template_hash_v1(
                        &issuance.unsigned_template_bytes,
                    )
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    if issuance.gate_digest != gate.digest
                        || (!burned_before_successor && !successor_durable)
                        || issuance.binding.chain_id() != &gate.chain_id
                        || issuance.binding.session_id() != &session_id
                        || issuance.binding.transcript_hash()
                            != &issuance.funding_authorized_record.transcript_hash()
                        || issuance.binding.terms_hash() != &gate.terms_hash
                        || issuance.binding.m8_policy_digest() != &gate.m8_policy_digest
                        || issuance.binding.shared_output_commitment()
                            != &gate.shared_output_commitment
                        || issuance.binding.bp_statement_hash() != &gate.bp_statement_hash
                        || issuance.binding.claim_template_hash() != &gate.claim_template_hash
                        || issuance.binding.claim_adaptor_point()
                            != &gate.claim_adaptor_point.to_compressed_bytes()
                        || issuance.binding.refund_tx_hash() != &gate.refund_tx_hash
                        || issuance.binding.backup_receipt_hash() != &gate.backup_receipt_hash
                        || template_hash != *issuance.binding.funding_template_hash()
                    {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                }
                6 => {
                    let record = self
                        .load_post_anchor_claim_pre_signature(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    let issued = self
                        .load_post_anchor_claim_authorization(
                            session_id,
                            PostAnchorClaimAuthorizationStateV1::Issued,
                        )
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    let consumed = self
                        .load_post_anchor_claim_authorization(
                            session_id,
                            PostAnchorClaimAuthorizationStateV1::Consumed,
                        )
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    let signing = self
                        .load_signing_binding(session_id, PurposeV1::ClaimAdaptor)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    let round = self
                        .load_post_anchor_claim_signing_binding(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    let terminal = self
                        .load_session_revision(session_id, record.terminal_revision)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    if record.chain_id != issued.chain_id
                        || record.claim_template_hash != issued.claim_template_hash
                        || record.adaptor_point != issued.adaptor_point
                        || record.round_start_transcript_hash != issued.round_start_transcript_hash
                        || record.issuance_record_digest != issued.digest
                        || record.consumption_record_digest != consumed.digest
                        || record.signing_binding_record_digest
                            != copy_array(&signing.bytes[signing.bytes.len() - DIGEST_LEN..])
                                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                        || record.round_binding_record_digest != round.digest
                        || record.round_start_record_digest != round.round_start_record_digest
                        || record.roster_digest != round.roster_digest
                        || terminal.digest() != &record.terminal_record_digest
                        || terminal.transcript_hash() != record.terminal_transcript_hash
                        || record.pre_signature.claim_template_hash() != &record.claim_template_hash
                        || record.pre_signature.adaptor_point() != &record.adaptor_point
                        || record.pre_signature.transcript_hash() != &record.reveal_transcript_hash
                    {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                }
                _ => return Err(LinuxCapabilityError::InvalidObject),
            }
            Ok(())
        })?;
        Ok(())
    }

    fn audit_consumptions(&self) -> Result<(), SessionStoreError> {
        self.consumptions.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if let Some(session_hex) = name.strip_suffix(".operational-funding-commit") {
                let session_id = decode_hex_32(session_hex)
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
                let commit = self
                    .load_funding_commit(session_id)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                if !self
                    .issuance_exists(session_id)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    || self
                        .m8_issuance_exists(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    || self
                        .m8_funding_commit_exists(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                self.verify_operational_commit_against_authority(&commit)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let artifact = self
                    .load_artifact(session_id)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let consumption = self
                    .load_consumption(session_id)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                if commit.artifact.bytes != artifact.bytes
                    || commit.consumption.bytes != consumption.bytes
                {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                return Ok(());
            }
            if let Some(session_hex) = name.strip_suffix(".operational-m8-funding-commit") {
                let session_id = decode_hex_32(session_hex)
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
                if self
                    .issuance_exists(session_id)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    || self
                        .funding_commit_exists(session_id)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                let commit = self
                    .load_m8_funding_commit(session_id)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                self.verify_m8_commit_against_authority(&commit)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let artifact = self
                    .load_artifact(session_id)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let consumption = self
                    .load_consumption(session_id)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                if commit.artifact.bytes != artifact.bytes
                    || commit.consumption.bytes != consumption.bytes
                {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                return Ok(());
            }
            if let Some(session_hex) = name.strip_suffix(".post-anchor-claim-signing-consumed") {
                let session_id = decode_hex_32(session_hex)
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
                let issued = self
                    .load_post_anchor_claim_authorization(
                        session_id,
                        PostAnchorClaimAuthorizationStateV1::Issued,
                    )
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let consumed = self
                    .load_post_anchor_claim_authorization(
                        session_id,
                        PostAnchorClaimAuthorizationStateV1::Consumed,
                    )
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                self.audit_post_anchor_claim_authorization(&issued, Some(&consumed))
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                return Ok(());
            }
            let session_hex = name
                .strip_suffix(".funding-consumed")
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            let session_id =
                decode_hex_32(session_hex).ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            let bytes = self
                .consumptions
                .read_bounded_file(&ValidatedComponent::registered(name)?, CONSUMPTION_MAX_LEN)?;
            let consumption = FundingConsumptionRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let artifact = self
                .load_artifact(session_id)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let current = self
                .load_session_locked(session_id)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if consumption.session_id != session_id
                || consumption.artifact_digest != artifact.digest
                || consumption.authorized_revision != artifact.authorized_revision
                || current.revision() < consumption.authorized_revision
            {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            if current.revision() > consumption.authorized_revision {
                let broadcast_revision = consumption
                    .authorized_revision
                    .checked_add(1)
                    .ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
                let broadcast = self
                    .load_session_revision(session_id, broadcast_revision)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                if broadcast.phase() != SessionPhaseV1::FundingBroadcast
                    || broadcast.digest() != &consumption.broadcast_record_digest
                {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
            }
            Ok(())
        })?;
        Ok(())
    }

    fn load_session_revision(
        &self,
        session_id: [u8; 32],
        revision: u64,
    ) -> Result<SessionRecordV1, SessionStoreError> {
        let name = session_record_name(session_id, revision);
        let bytes = self.records.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            SESSION_RECORD_MAX_LEN,
        )?;
        let record = SessionRecordV1::from_bytes(&bytes)?;
        if record.session_id() != session_id || record.revision() != revision {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(record)
    }

    fn persist_reservation_lookup_record(
        &self,
        record: &ReservationLookupRecordV1,
    ) -> Result<(), SessionStoreError> {
        let final_name = reservation_lookup_record_name(record.request_lookup, record.state);
        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &self.reservation_lookups,
            &staging_name,
            &final_name,
            &record.bytes,
            RESERVATION_LOOKUP_RECORD_LEN,
        )
    }

    fn load_reservation_lookup_record(
        &self,
        request_lookup: [u8; 32],
        state: ReservationLookupStateV1,
    ) -> Result<ReservationLookupRecordV1, SessionStoreError> {
        let name = reservation_lookup_record_name(request_lookup, state);
        match self.reservation_lookups.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            RESERVATION_LOOKUP_RECORD_LEN,
        ) {
            Ok(bytes) => {
                let record = ReservationLookupRecordV1::from_bytes(&bytes)?;
                if record.request_lookup != request_lookup || record.state != state {
                    return Err(SessionStoreError::Quarantined);
                }
                Ok(record)
            }
            Err(LinuxCapabilityError::NotFound) => Err(SessionStoreError::SessionNotFound),
            Err(error) => Err(error.into()),
        }
    }

    fn reservation_lookup_abandonment_exists(
        &self,
        request_lookup: &[u8; 32],
    ) -> Result<bool, SessionStoreError> {
        match self.load_reservation_lookup_record(
            *request_lookup,
            ReservationLookupStateV1::AbandonedBeforeVaultClaim,
        ) {
            Ok(_) => Ok(true),
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn unique_reservation_lookup_record(
        &self,
        session_id: [u8; 32],
        context_binding_digest: [u8; 32],
        state: ReservationLookupStateV1,
    ) -> Result<ReservationLookupRecordV1, SessionStoreError> {
        if session_id == [0; 32] || context_binding_digest == [0; 32] {
            return Err(SessionStoreError::Canonical);
        }
        let mut found = None;
        self.reservation_lookups.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let Some((name_lookup, name_state)) = parse_reservation_lookup_record_name(name) else {
                return Err(LinuxCapabilityError::InvalidDirectoryEntry);
            };
            let bytes = self.reservation_lookups.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                RESERVATION_LOOKUP_RECORD_LEN,
            )?;
            let record = ReservationLookupRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if record.request_lookup != name_lookup || record.state != name_state {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            if record.state == state
                && record.session_id == session_id
                && record.context_binding_digest == context_binding_digest
            {
                if found.is_some() {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                found = Some(record);
            }
            Ok(())
        })?;
        found.ok_or(SessionStoreError::SessionNotFound)
    }

    fn audit_reservation_lookups(&self) -> Result<(), SessionStoreError> {
        let mut custodied = BTreeMap::new();
        let mut abandoned = Vec::new();
        let mut binding_owners = BTreeMap::new();
        self.reservation_lookups.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let Some((name_lookup, name_state)) = parse_reservation_lookup_record_name(name) else {
                return Err(LinuxCapabilityError::InvalidDirectoryEntry);
            };
            let bytes = self.reservation_lookups.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                RESERVATION_LOOKUP_RECORD_LEN,
            )?;
            let record = ReservationLookupRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if record.request_lookup != name_lookup || record.state != name_state {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            let durable_session = self
                .load_session_revision(record.session_id, record.session_revision)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if durable_session.digest() != &record.session_record_digest {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            match record.state {
                ReservationLookupStateV1::Custodied => {
                    let key = (record.session_id, record.context_binding_digest);
                    if binding_owners.insert(key, record.request_lookup).is_some()
                        || custodied.insert(record.request_lookup, record).is_some()
                    {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                }
                ReservationLookupStateV1::AbandonedBeforeVaultClaim => abandoned.push(record),
            }
            Ok(())
        })?;
        for terminal in abandoned {
            let custody = custodied
                .get(&terminal.request_lookup)
                .ok_or(SessionStoreError::Quarantined)?;
            if terminal.session_id != custody.session_id
                || terminal.context_binding_digest != custody.context_binding_digest
                || terminal.predecessor_digest != custody.digest
            {
                return Err(SessionStoreError::Quarantined);
            }
        }
        Ok(())
    }

    fn persist_reservation_lookup_custody_fields(
        &self,
        session_id: [u8; 32],
        request_lookup: [u8; 32],
        context_binding_digest: [u8; 32],
    ) -> Result<DurableContractsReservationLookupV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        if request_lookup == [0; 32] || context_binding_digest == [0; 32] {
            return Err(SessionStoreError::Canonical);
        }
        let current = self.load_session_locked(session_id)?;
        if is_terminal_phase(current.phase()) {
            return Err(SessionStoreError::InvalidTransition);
        }
        match self.unique_reservation_lookup_record(
            session_id,
            context_binding_digest,
            ReservationLookupStateV1::Custodied,
        ) {
            Ok(existing) if existing.request_lookup != request_lookup => {
                return Err(SessionStoreError::Conflict)
            }
            Ok(_) | Err(SessionStoreError::SessionNotFound) => {}
            Err(error) => return Err(error),
        }
        if self.reservation_lookup_abandonment_exists(&request_lookup)? {
            return Err(SessionStoreError::InvalidTransition);
        }
        let record = match self
            .load_reservation_lookup_record(request_lookup, ReservationLookupStateV1::Custodied)
        {
            Ok(existing) => {
                if existing.session_id != session_id
                    || existing.context_binding_digest != context_binding_digest
                {
                    return Err(SessionStoreError::Conflict);
                }
                existing
            }
            Err(SessionStoreError::SessionNotFound) => {
                let created = ReservationLookupRecordV1::new_custodied(
                    &current,
                    request_lookup,
                    context_binding_digest,
                )?;
                self.persist_reservation_lookup_record(&created)?;
                test_crash_hook("reservation-lookup-after-custody-persist");
                let durable = self.load_reservation_lookup_record(
                    request_lookup,
                    ReservationLookupStateV1::Custodied,
                )?;
                if durable.bytes != created.bytes {
                    return Err(SessionStoreError::Quarantined);
                }
                durable
            }
            Err(error) => return Err(error),
        };
        Ok(DurableContractsReservationLookupV1 {
            request_lookup: ReservationRequestLookupV1::from_bytes(record.request_lookup)
                .map_err(|_| SessionStoreError::Quarantined)?,
            context_binding_digest: record.context_binding_digest,
            session_id: SessionId::from_bytes(record.session_id)
                .map_err(|_| SessionStoreError::Quarantined)?,
            _open_instance_id: self.open_instance_id,
            _record_digest: record.digest,
        })
    }
}

impl ReservationLookupCustodyV1 for ContractsReservationLookupCustodyV1<'_> {
    type Error = SessionStoreError;
    type DurableLookup = DurableContractsReservationLookupV1;

    fn persist_prepared_lookup(
        &mut self,
        prepared: &PreparedFreshReservationV1,
    ) -> Result<Self::DurableLookup, Self::Error> {
        self.store.persist_reservation_lookup_custody_fields(
            *prepared.session_id().as_bytes(),
            *prepared.request_lookup().as_bytes(),
            *prepared.context_binding_digest(),
        )
    }

    fn abandon_before_vault_claim(
        &mut self,
        lookup: &ReservationRequestLookupV1,
        session_id: &SessionId,
        context_binding_digest: &[u8; 32],
    ) -> Result<(), Self::Error> {
        let _guard = self.store.operation_lock()?;
        let custody = self.store.load_reservation_lookup_record(
            *lookup.as_bytes(),
            ReservationLookupStateV1::Custodied,
        )?;
        if custody.session_id != *session_id.as_bytes()
            || custody.context_binding_digest != *context_binding_digest
        {
            return Err(SessionStoreError::Conflict);
        }
        match self.store.load_reservation_lookup_record(
            *lookup.as_bytes(),
            ReservationLookupStateV1::AbandonedBeforeVaultClaim,
        ) {
            Ok(existing) => {
                if existing.session_id != custody.session_id
                    || existing.context_binding_digest != custody.context_binding_digest
                    || existing.predecessor_digest != custody.digest
                {
                    return Err(SessionStoreError::Quarantined);
                }
                return Ok(());
            }
            Err(SessionStoreError::SessionNotFound) => {}
            Err(error) => return Err(error),
        }
        let current = self.store.load_session_locked(custody.session_id)?;
        let abandonment = ReservationLookupRecordV1::new_abandoned(&current, &custody)?;
        self.store.persist_reservation_lookup_record(&abandonment)?;
        test_crash_hook("reservation-lookup-after-abandonment-persist");
        let durable = self.store.load_reservation_lookup_record(
            custody.request_lookup,
            ReservationLookupStateV1::AbandonedBeforeVaultClaim,
        )?;
        if durable.bytes != abandonment.bytes {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }
}

impl ReservationLookupRecoveryCustodyV1 for ContractsReservationLookupCustodyV1<'_> {
    fn load_custodied_lookup(
        &mut self,
        request: &ReservationLookupRecoveryRequestV1,
    ) -> Result<ReservationRequestLookupV1, Self::Error> {
        self.store.load_custodied_reservation_lookup(
            *request.session_id().as_bytes(),
            *request.context_binding_digest(),
        )
    }
}

impl OperationalFundingAuthorizationStoreV1 for ContractsSessionStoreV1 {
    type Error = SessionStoreError;

    fn issue_operational_funding_authorization(
        &mut self,
        binding: &OperationalFundingAuthorizationBindingV1,
        unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
        capability: OperationalFundingAuthorizationImportCapabilityV1,
    ) -> Result<OperationalFundingAuthorizationV1, Self::Error> {
        let _guard = self.operation_lock()?;
        let session_id = *binding.session_id();
        if self.any_operational_issuance_exists(session_id)?
            || self.consumption_exists(session_id)?
            || self.m8_funding_gate_exists(session_id)?
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let current = self.load_session_locked(session_id)?;
        let gate = self.load_funding_gate(session_id)?;
        if current.phase() != SessionPhaseV1::ClaimPrepared
            || current.irreversible().funding_authorized
            || current.terms_hash() != gate.terms_hash
            || binding.chain_id() != &gate.chain_id
            || binding.transcript_hash() != &current.transcript_hash()
            || binding.terms_hash() != &gate.terms_hash
            || binding.shared_output_commitment() != &gate.shared_output_commitment
            || binding.bp_statement_hash() != &gate.bp_statement_hash
            || binding.claim_template_hash() != &gate.claim_template_hash
            || binding.refund_tx_hash() != &gate.refund_tx_hash
            || binding.claim_presignature_hash() != &gate.claim_pre_signature_hash
            || binding.backup_receipt_hash() != &gate.backup_receipt_hash
            || binding.funding_template_hash() != unsigned_template.template_hash()
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let (canonical_template_bytes, template_hash) =
            canonical_template_v1(unsigned_template.transaction())
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        canonical_dom_transaction_bytes_v1(unsigned_template.transaction())?;
        if canonical_template_bytes != unsigned_template.canonical_template_bytes()
            || template_hash != *unsigned_template.template_hash()
            || template_hash != *binding.funding_template_hash()
            || unsigned_template.bp_statement().to_bytes() != gate.bp_statement_bytes
            || unsigned_template.bp_statement().statement_hash() != gate.bp_statement_hash
            || unsigned_template.bp_statement().chain_id() != gate.chain_id
            || unsigned_template.bp_statement().session_id() != session_id
            || unsigned_template.bp_statement().recovery_binding_hash()
                != &gate.recovery_binding_hash
            || unsigned_template
                .bp_statement()
                .aggregate_commitment()
                .to_compressed_bytes()
                != gate.shared_output_commitment
        {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
        self.require_funding_template_commits(
            session_id,
            template_hash,
            gate.claim_template_hash,
            gate.refund_template_hash,
        )?;
        self.require_ready_to_fund_votes(session_id, gate.digest, SessionPhaseV1::ClaimPrepared)?;
        self.require_claim_presignature_journal_evidence(
            session_id,
            gate.claim_transcript_hash,
            &gate.claim_pre_signature,
        )?;
        validate_exact_dom_transaction(
            &gate.refund_bytes,
            DomTransactionValidationContextV1::new(
                gate.refund_unlock_height,
                gate.chain_id,
                gate.now_unix_seconds,
            ),
        )?;
        let shared_output_matches = unsigned_template
            .transaction()
            .outputs
            .iter()
            .filter(|output| output.commitment.as_bytes() == &gate.shared_output_commitment)
            .count();
        let claim_template = parse_canonical_dom_template_v1(&gate.claim_template_bytes)?;
        let refund_template = parse_canonical_dom_template_v1(&gate.refund_template_bytes)?;
        if shared_output_matches != 1
            || claim_template.inputs.len() != 1
            || refund_template.inputs.len() != 1
            || claim_template.inputs[0].commitment.as_bytes() != &gate.shared_output_commitment
            || refund_template.inputs[0].commitment.as_bytes() != &gate.shared_output_commitment
            || gate.bp_statement_hash == [0; 32]
            || gate.recovery_binding_hash == [0; 32]
            || gate.bp_statement_bytes.len() < 317
            || gate.bp_statement_bytes[38..70] != session_id
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let mut irreversible = current.irreversible();
        irreversible.funding_authorized = true;
        let funding_authorized = current.advance(
            current.revision(),
            SessionPhaseV1::FundingAuthorized,
            current.transcript_hash(),
            irreversible,
            current.chain(),
            current.encrypted_payload(),
        )?;
        let issuance = OperationalFundingIssuanceRecordV1::new(
            binding.clone(),
            funding_authorized.revision(),
            gate.digest,
            &canonical_template_bytes,
            &funding_authorized,
        )?;
        // The no-replace issuance row burns the only slot before a signing
        // token can exist. A crash after this point remains safely pre-funding
        // and cannot reissue.
        self.persist_funding_issuance(&issuance)?;
        test_crash_hook("operational-issue-after-burn-persist");
        self.persist_session_record(&funding_authorized)?;
        test_crash_hook("operational-issue-after-session-persist");
        let durable = self.load_funding_issuance(session_id)?;
        if durable.bytes != issuance.bytes
            || self.load_session_locked(session_id)?.as_bytes() != funding_authorized.as_bytes()
        {
            return Err(SessionStoreError::Quarantined);
        }
        let proof = DurableOperationalFundingIssuanceV1::new(
            binding.clone(),
            issuance.digest,
            funding_authorized.revision(),
        )
        .map_err(|_| SessionStoreError::Canonical)?;
        self.process_funding_authorities
            .lock()
            .map_err(|_| SessionStoreError::StoreBusy)?
            .insert(session_id);
        capability
            .import(binding, proof)
            .map_err(|_| SessionStoreError::FundingAuthorityUnavailable)
    }

    fn resume_operational_funding_authorization(
        &mut self,
        binding: &OperationalFundingAuthorizationBindingV1,
        unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
        capability: OperationalFundingAuthorizationImportCapabilityV1,
    ) -> Result<OperationalFundingAuthorizationV1, Self::Error> {
        let _guard = self.operation_lock()?;
        let session_id = *binding.session_id();
        if self.consumption_exists(session_id)?
            || self.m8_issuance_exists(session_id)?
            || self.m8_funding_gate_exists(session_id)?
            || self
                .process_funding_authorities
                .lock()
                .map_err(|_| SessionStoreError::StoreBusy)?
                .contains(&session_id)
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let issuance = self.load_funding_issuance(session_id)?;
        let gate = self.load_funding_gate(session_id)?;
        let current = self.load_session_locked(session_id)?;
        let (canonical_template_bytes, template_hash) =
            canonical_template_v1(unsigned_template.transaction())
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        self.audit_funding_authorized_signing_prefix(
            session_id,
            &gate.chain_id,
            &gate.terms_hash,
            &issuance.unsigned_template_bytes,
            binding.funding_template_hash(),
            &issuance.funding_authorized_record,
            &current,
            false,
        )
        .map_err(|_| SessionStoreError::FundingAuthorityUnavailable)?;
        if current.phase() != SessionPhaseV1::FundingAuthorized
            || !current.irreversible().funding_authorized
            || issuance.binding != *binding
            || issuance.gate_digest != gate.digest
            || issuance.unsigned_template_bytes != canonical_template_bytes
            || canonical_template_bytes != unsigned_template.canonical_template_bytes()
            || template_hash != *unsigned_template.template_hash()
            || template_hash != *binding.funding_template_hash()
            || binding.chain_id() != &gate.chain_id
            || binding.transcript_hash() != &issuance.funding_authorized_record.transcript_hash()
            || binding.terms_hash() != &gate.terms_hash
            || binding.shared_output_commitment() != &gate.shared_output_commitment
            || binding.bp_statement_hash() != &gate.bp_statement_hash
            || binding.claim_template_hash() != &gate.claim_template_hash
            || binding.refund_tx_hash() != &gate.refund_tx_hash
            || binding.claim_presignature_hash() != &gate.claim_pre_signature_hash
            || binding.backup_receipt_hash() != &gate.backup_receipt_hash
            || unsigned_template.bp_statement().to_bytes() != gate.bp_statement_bytes
            || unsigned_template.bp_statement().statement_hash() != gate.bp_statement_hash
            || unsigned_template.bp_statement().chain_id() != gate.chain_id
            || unsigned_template.bp_statement().session_id() != session_id
            || unsigned_template.bp_statement().recovery_binding_hash()
                != &gate.recovery_binding_hash
            || unsigned_template
                .bp_statement()
                .aggregate_commitment()
                .to_compressed_bytes()
                != gate.shared_output_commitment
            || self.any_operational_commit_exists(session_id)?
            || self.artifact_exists(session_id)?
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let proof = DurableOperationalFundingIssuanceV1::new(
            binding.clone(),
            issuance.digest,
            issuance.authorized_revision,
        )
        .map_err(|_| SessionStoreError::Canonical)?;
        let authorization = capability
            .import(binding, proof)
            .map_err(|_| SessionStoreError::FundingAuthorityUnavailable)?;
        if !self
            .process_funding_authorities
            .lock()
            .map_err(|_| SessionStoreError::StoreBusy)?
            .insert(session_id)
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        Ok(authorization)
    }
}

impl OperationalM8FundingAuthorizationStoreV1 for ContractsSessionStoreV1 {
    type Error = SessionStoreError;

    fn issue_operational_m8_funding_authorization(
        &mut self,
        binding: &OperationalM8FundingAuthorizationBindingV1,
        unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
        capability: OperationalM8FundingAuthorizationImportCapabilityV1,
    ) -> Result<OperationalM8FundingAuthorizationV1, Self::Error> {
        let _guard = self.operation_lock()?;
        let session_id = *binding.session_id();
        if self.any_operational_issuance_exists(session_id)?
            || self.consumption_exists(session_id)?
            || self.any_operational_commit_exists(session_id)?
            || self.artifact_exists(session_id)?
            || self.funding_gate_exists(session_id)?
            || self
                .process_funding_authorities
                .lock()
                .map_err(|_| SessionStoreError::StoreBusy)?
                .contains(&session_id)
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let current = self.load_session_locked(session_id)?;
        let gate = self.load_m8_funding_gate(session_id)?;
        if current.phase() != SessionPhaseV1::RefundSigned
            || current.irreversible().funding_authorized
            || current.terms_hash() != gate.terms_hash
            || binding.chain_id() != &gate.chain_id
            || binding.session_id() != &gate.session_id
            || binding.transcript_hash() != &current.transcript_hash()
            || binding.terms_hash() != &gate.terms_hash
            || binding.shared_output_commitment() != &gate.shared_output_commitment
            || binding.bp_statement_hash() != &gate.bp_statement_hash
            || binding.claim_template_hash() != &gate.claim_template_hash
            || binding.claim_adaptor_point() != &gate.claim_adaptor_point.to_compressed_bytes()
            || binding.m8_policy_digest() != &gate.m8_policy_digest
            || binding.refund_tx_hash() != &gate.refund_tx_hash
            || binding.backup_receipt_hash() != &gate.backup_receipt_hash
            || binding.funding_template_hash() != unsigned_template.template_hash()
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let (canonical_template_bytes, template_hash) =
            canonical_template_v1(unsigned_template.transaction())
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        canonical_dom_transaction_bytes_v1(unsigned_template.transaction())?;
        if canonical_template_bytes != unsigned_template.canonical_template_bytes()
            || template_hash != *unsigned_template.template_hash()
            || template_hash != *binding.funding_template_hash()
            || unsigned_template.bp_statement().to_bytes() != gate.bp_statement_bytes
            || unsigned_template.bp_statement().statement_hash() != gate.bp_statement_hash
            || unsigned_template.bp_statement().chain_id() != gate.chain_id
            || unsigned_template.bp_statement().session_id() != session_id
            || unsigned_template.bp_statement().recovery_binding_hash()
                != &gate.recovery_binding_hash
            || unsigned_template
                .bp_statement()
                .aggregate_commitment()
                .to_compressed_bytes()
                != gate.shared_output_commitment
        {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
        self.require_funding_template_commits(
            session_id,
            template_hash,
            gate.claim_template_hash,
            gate.refund_template_hash,
        )?;
        self.require_ready_to_fund_votes(session_id, gate.digest, SessionPhaseV1::RefundSigned)?;
        self.require_no_pre_anchor_claim_signing_evidence(session_id, current.revision())?;
        validate_exact_dom_transaction(
            &gate.refund_bytes,
            DomTransactionValidationContextV1::new(
                gate.refund_unlock_height,
                gate.chain_id,
                gate.now_unix_seconds,
            ),
        )?;
        let shared_output_matches = unsigned_template
            .transaction()
            .outputs
            .iter()
            .filter(|output| output.commitment.as_bytes() == &gate.shared_output_commitment)
            .count();
        let claim_template = parse_canonical_dom_template_v1(&gate.claim_template_bytes)?;
        let refund_template = parse_canonical_dom_template_v1(&gate.refund_template_bytes)?;
        if shared_output_matches != 1
            || claim_template.inputs.len() != 1
            || claim_template.kernels.len() != 1
            || refund_template.inputs.len() != 1
            || claim_template.inputs[0].commitment.as_bytes() != &gate.shared_output_commitment
            || refund_template.inputs[0].commitment.as_bytes() != &gate.shared_output_commitment
            || gate.bp_statement_hash == [0; 32]
            || gate.recovery_binding_hash == [0; 32]
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let mut irreversible = current.irreversible();
        irreversible.funding_authorized = true;
        let funding_authorized = current.advance(
            current.revision(),
            SessionPhaseV1::FundingAuthorized,
            current.transcript_hash(),
            irreversible,
            current.chain(),
            current.encrypted_payload(),
        )?;
        let issuance = OperationalM8FundingIssuanceRecordV1::new(
            binding.clone(),
            funding_authorized.revision(),
            gate.digest,
            &canonical_template_bytes,
            &funding_authorized,
        )?;
        self.persist_m8_funding_issuance(&issuance)?;
        test_crash_hook("operational-m8-issue-after-burn-persist");
        self.persist_session_record(&funding_authorized)?;
        test_crash_hook("operational-m8-issue-after-session-persist");
        let durable = self.load_m8_funding_issuance(session_id)?;
        if durable.bytes != issuance.bytes
            || self.load_session_locked(session_id)?.as_bytes() != funding_authorized.as_bytes()
        {
            return Err(SessionStoreError::Quarantined);
        }
        let proof = DurableOperationalM8FundingIssuanceV1::new(
            binding.clone(),
            issuance.digest,
            funding_authorized.revision(),
        )
        .map_err(|_| SessionStoreError::Canonical)?;
        if !self
            .process_funding_authorities
            .lock()
            .map_err(|_| SessionStoreError::StoreBusy)?
            .insert(session_id)
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        capability
            .import(binding, proof)
            .map_err(|_| SessionStoreError::FundingAuthorityUnavailable)
    }

    fn resume_operational_m8_funding_authorization(
        &mut self,
        binding: &OperationalM8FundingAuthorizationBindingV1,
        unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
        capability: OperationalM8FundingAuthorizationImportCapabilityV1,
    ) -> Result<OperationalM8FundingAuthorizationV1, Self::Error> {
        let _guard = self.operation_lock()?;
        let session_id = *binding.session_id();
        if self.consumption_exists(session_id)?
            || self.any_operational_commit_exists(session_id)?
            || self.artifact_exists(session_id)?
            || self.issuance_exists(session_id)?
            || self.funding_gate_exists(session_id)?
            || self
                .process_funding_authorities
                .lock()
                .map_err(|_| SessionStoreError::StoreBusy)?
                .contains(&session_id)
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let issuance = self.load_m8_funding_issuance(session_id)?;
        let gate = self.load_m8_funding_gate(session_id)?;
        let current = self.load_session_locked(session_id)?;
        let (canonical_template_bytes, template_hash) =
            canonical_template_v1(unsigned_template.transaction())
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        self.require_no_pre_anchor_claim_signing_evidence(session_id, current.revision())?;
        self.audit_funding_authorized_signing_prefix(
            session_id,
            &gate.chain_id,
            &gate.terms_hash,
            &issuance.unsigned_template_bytes,
            binding.funding_template_hash(),
            &issuance.funding_authorized_record,
            &current,
            false,
        )
        .map_err(|_| SessionStoreError::FundingAuthorityUnavailable)?;
        if current.phase() != SessionPhaseV1::FundingAuthorized
            || !current.irreversible().funding_authorized
            || issuance.binding != *binding
            || issuance.gate_digest != gate.digest
            || issuance.unsigned_template_bytes != canonical_template_bytes
            || canonical_template_bytes != unsigned_template.canonical_template_bytes()
            || template_hash != *unsigned_template.template_hash()
            || template_hash != *binding.funding_template_hash()
            || binding.chain_id() != &gate.chain_id
            || binding.transcript_hash() != &issuance.funding_authorized_record.transcript_hash()
            || binding.terms_hash() != &gate.terms_hash
            || binding.shared_output_commitment() != &gate.shared_output_commitment
            || binding.bp_statement_hash() != &gate.bp_statement_hash
            || binding.claim_template_hash() != &gate.claim_template_hash
            || binding.claim_adaptor_point() != &gate.claim_adaptor_point.to_compressed_bytes()
            || binding.m8_policy_digest() != &gate.m8_policy_digest
            || binding.refund_tx_hash() != &gate.refund_tx_hash
            || binding.backup_receipt_hash() != &gate.backup_receipt_hash
            || unsigned_template.bp_statement().to_bytes() != gate.bp_statement_bytes
            || unsigned_template.bp_statement().statement_hash() != gate.bp_statement_hash
            || unsigned_template.bp_statement().chain_id() != gate.chain_id
            || unsigned_template.bp_statement().session_id() != session_id
            || unsigned_template.bp_statement().recovery_binding_hash()
                != &gate.recovery_binding_hash
            || unsigned_template
                .bp_statement()
                .aggregate_commitment()
                .to_compressed_bytes()
                != gate.shared_output_commitment
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let proof = DurableOperationalM8FundingIssuanceV1::new(
            binding.clone(),
            issuance.digest,
            issuance.authorized_revision,
        )
        .map_err(|_| SessionStoreError::Canonical)?;
        let authorization = capability
            .import(binding, proof)
            .map_err(|_| SessionStoreError::FundingAuthorityUnavailable)?;
        if !self
            .process_funding_authorities
            .lock()
            .map_err(|_| SessionStoreError::StoreBusy)?
            .insert(session_id)
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        Ok(authorization)
    }
}

impl OperationalFundingTransactionSinkV1 for ContractsSessionStoreV1 {
    type Error = SessionStoreError;
    type PersistedFunding = FundingBroadcastV1;

    fn persist_verified_funding(
        &mut self,
        capability: OperationalFundingPersistenceCapabilityV1,
    ) -> Result<Self::PersistedFunding, Self::Error> {
        let _guard = self.operation_lock()?;
        let authorization = capability.authorization();
        let binding = authorization.binding();
        let session_id = *binding.session_id();
        if self.m8_issuance_exists(session_id)?
            || self.m8_funding_gate_exists(session_id)?
            || self.m8_funding_commit_exists(session_id)?
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let issuance = self.load_funding_issuance(session_id)?;
        let gate = self.load_funding_gate(session_id)?;
        let current = self.load_session_locked(session_id)?;
        let (signed_template_bytes, signed_template_hash) =
            canonical_template_v1(capability.transaction())
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let shared_output_matches = capability
            .transaction()
            .outputs
            .iter()
            .filter(|output| output.commitment.as_bytes() == &gate.shared_output_commitment)
            .count();
        self.audit_funding_authorized_signing_prefix(
            session_id,
            &gate.chain_id,
            &gate.terms_hash,
            &issuance.unsigned_template_bytes,
            binding.funding_template_hash(),
            &issuance.funding_authorized_record,
            &current,
            true,
        )
        .map_err(|_| SessionStoreError::FundingAuthorityUnavailable)?;
        if self.consumption_exists(session_id)?
            || self.funding_commit_exists(session_id)?
            || self.artifact_exists(session_id)?
            || issuance.binding != *binding
            || issuance.digest != *authorization.issuance_record_digest()
            || issuance.authorized_revision != authorization.authorized_revision()
            || issuance.gate_digest != gate.digest
            || binding.terms_hash() != &gate.terms_hash
            || binding.shared_output_commitment() != &gate.shared_output_commitment
            || binding.bp_statement_hash() != &gate.bp_statement_hash
            || binding.claim_template_hash() != &gate.claim_template_hash
            || current.phase() != SessionPhaseV1::FundingAuthorized
            || !current.irreversible().funding_authorized
            || capability.template_hash() != binding.funding_template_hash()
            || capability.template_hash() != &signed_template_hash
            || signed_template_bytes != issuance.unsigned_template_bytes
            || capability.shared_output_commitment() != &gate.shared_output_commitment
            || shared_output_matches != 1
            || capability.canonical_bytes()
                != capability
                    .transaction()
                    .to_bytes()
                    .map_err(|_| SessionStoreError::InvalidDomTransaction)?
            || *dom_crypto::blake2b_256(capability.canonical_bytes()).as_bytes()
                != *capability.tx_hash()
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        capability
            .verify(binding.chain_id(), gate.validation_height)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let artifact = FundingArtifactRecordV1::new_operational(
            &gate,
            current.revision(),
            capability.canonical_bytes(),
        )?;
        let funding_broadcast = current.advance(
            current.revision(),
            SessionPhaseV1::FundingBroadcast,
            current.transcript_hash(),
            current.irreversible(),
            current.chain(),
            current.encrypted_payload(),
        )?;
        let consumption = FundingConsumptionRecordV1::new(
            session_id,
            current.revision(),
            artifact.digest,
            &funding_broadcast,
        )?;
        let commit = OperationalFundingCommitRecordV1::new(artifact, consumption)?;
        self.verify_operational_commit_against_authority(&commit)?;
        self.persist_funding_commit(&commit)?;
        test_crash_hook("operational-sink-after-commit-intent-persist");
        self.persist_artifact(&commit.artifact)?;
        test_crash_hook("operational-sink-after-artifact-persist");
        self.persist_consumption(&commit.consumption)?;
        test_crash_hook("operational-sink-after-consumption-persist");
        self.persist_session_record(&funding_broadcast)?;
        test_crash_hook("operational-sink-after-session-persist");
        let durable = self.load_session_locked(session_id)?;
        let durable_artifact = self.load_artifact(session_id)?;
        let durable_consumption = self.load_consumption(session_id)?;
        if durable.as_bytes() != funding_broadcast.as_bytes()
            || durable_artifact.bytes != commit.artifact.bytes
            || durable_consumption.bytes != commit.consumption.bytes
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(FundingBroadcastV1 {
            exact_bytes: commit.artifact.funding_bytes,
        })
    }
}

impl OperationalM8FundingTransactionSinkV1 for ContractsSessionStoreV1 {
    type Error = SessionStoreError;
    type PersistedFunding = FundingBroadcastV1;

    fn persist_verified_m8_funding(
        &mut self,
        capability: OperationalM8FundingPersistenceCapabilityV1,
    ) -> Result<Self::PersistedFunding, Self::Error> {
        let _guard = self.operation_lock()?;
        let authorization = capability.authorization();
        let binding = authorization.binding();
        let session_id = *binding.session_id();
        if self.issuance_exists(session_id)? || self.funding_gate_exists(session_id)? {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let issuance = self.load_m8_funding_issuance(session_id)?;
        let gate = self.load_m8_funding_gate(session_id)?;
        let current = self.load_session_locked(session_id)?;
        let (signed_template_bytes, signed_template_hash) =
            canonical_template_v1(capability.transaction())
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let shared_output_matches = capability
            .transaction()
            .outputs
            .iter()
            .filter(|output| output.commitment.as_bytes() == &gate.shared_output_commitment)
            .count();
        self.audit_funding_authorized_signing_prefix(
            session_id,
            &gate.chain_id,
            &gate.terms_hash,
            &issuance.unsigned_template_bytes,
            binding.funding_template_hash(),
            &issuance.funding_authorized_record,
            &current,
            true,
        )
        .map_err(|_| SessionStoreError::FundingAuthorityUnavailable)?;
        if self.consumption_exists(session_id)?
            || self.any_operational_commit_exists(session_id)?
            || self.artifact_exists(session_id)?
            || issuance.binding != *binding
            || issuance.digest != *authorization.issuance_record_digest()
            || issuance.authorized_revision != authorization.authorized_revision()
            || issuance.gate_digest != gate.digest
            || binding.chain_id() != &gate.chain_id
            || binding.terms_hash() != &gate.terms_hash
            || binding.m8_policy_digest() != &gate.m8_policy_digest
            || binding.shared_output_commitment() != &gate.shared_output_commitment
            || binding.bp_statement_hash() != &gate.bp_statement_hash
            || binding.claim_template_hash() != &gate.claim_template_hash
            || binding.claim_adaptor_point() != &gate.claim_adaptor_point.to_compressed_bytes()
            || binding.refund_tx_hash() != &gate.refund_tx_hash
            || binding.backup_receipt_hash() != &gate.backup_receipt_hash
            || current.phase() != SessionPhaseV1::FundingAuthorized
            || !current.irreversible().funding_authorized
            || capability.template_hash() != binding.funding_template_hash()
            || capability.template_hash() != &signed_template_hash
            || signed_template_bytes != issuance.unsigned_template_bytes
            || capability.shared_output_commitment() != &gate.shared_output_commitment
            || shared_output_matches != 1
            || capability.canonical_bytes()
                != capability
                    .transaction()
                    .to_bytes()
                    .map_err(|_| SessionStoreError::InvalidDomTransaction)?
            || *dom_crypto::blake2b_256(capability.canonical_bytes()).as_bytes()
                != *capability.tx_hash()
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        capability
            .verify(binding.chain_id(), gate.validation_height)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let artifact = FundingArtifactRecordV1::new_operational_m8(
            &gate,
            current.revision(),
            capability.canonical_bytes(),
        )?;
        let funding_broadcast = current.advance(
            current.revision(),
            SessionPhaseV1::FundingBroadcast,
            current.transcript_hash(),
            current.irreversible(),
            current.chain(),
            current.encrypted_payload(),
        )?;
        let consumption = FundingConsumptionRecordV1::new(
            session_id,
            current.revision(),
            artifact.digest,
            &funding_broadcast,
        )?;
        let commit =
            OperationalM8FundingCommitRecordV1::new(issuance.digest, artifact, consumption)?;
        self.verify_m8_commit_against_authority(&commit)?;
        self.persist_m8_funding_commit(&commit)?;
        test_crash_hook("operational-m8-sink-after-commit-intent-persist");
        self.persist_artifact(&commit.artifact)?;
        test_crash_hook("operational-m8-sink-after-artifact-persist");
        self.persist_consumption(&commit.consumption)?;
        test_crash_hook("operational-m8-sink-after-consumption-persist");
        self.persist_session_record(&funding_broadcast)?;
        test_crash_hook("operational-m8-sink-after-session-persist");
        let durable = self.load_session_locked(session_id)?;
        let durable_artifact = self.load_artifact(session_id)?;
        let durable_consumption = self.load_consumption(session_id)?;
        if durable.as_bytes() != funding_broadcast.as_bytes()
            || durable_artifact.bytes != commit.artifact.bytes
            || durable_consumption.bytes != commit.consumption.bytes
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(FundingBroadcastV1 {
            exact_bytes: commit.artifact.funding_bytes,
        })
    }
}

struct FundingArtifactRecordV1 {
    bytes: Vec<u8>,
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    authorized_revision: u64,
    refund_unlock_height: u64,
    refund_bytes: Vec<u8>,
    funding_bytes: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReservationLookupStateV1 {
    Custodied,
    AbandonedBeforeVaultClaim,
}

impl ReservationLookupStateV1 {
    const fn byte(self) -> u8 {
        match self {
            Self::Custodied => 0x01,
            Self::AbandonedBeforeVaultClaim => 0x02,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, SessionStoreError> {
        match byte {
            0x01 => Ok(Self::Custodied),
            0x02 => Ok(Self::AbandonedBeforeVaultClaim),
            _ => Err(SessionStoreError::Quarantined),
        }
    }

    const fn suffix(self) -> &'static str {
        match self {
            Self::Custodied => ".reservation-lookup",
            Self::AbandonedBeforeVaultClaim => ".reservation-abandoned",
        }
    }
}

struct ReservationLookupRecordV1 {
    bytes: [u8; RESERVATION_LOOKUP_RECORD_LEN],
    state: ReservationLookupStateV1,
    request_lookup: [u8; 32],
    session_id: [u8; 32],
    context_binding_digest: [u8; 32],
    session_revision: u64,
    session_record_digest: [u8; 32],
    predecessor_digest: [u8; 32],
    digest: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PostAnchorClaimAuthorizationStateV1 {
    Issued,
    Consumed,
}

impl PostAnchorClaimAuthorizationStateV1 {
    const fn byte(self) -> u8 {
        match self {
            Self::Issued => 0x01,
            Self::Consumed => 0x02,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, SessionStoreError> {
        match byte {
            0x01 => Ok(Self::Issued),
            0x02 => Ok(Self::Consumed),
            _ => Err(SessionStoreError::Quarantined),
        }
    }

    const fn suffix(self) -> &'static str {
        match self {
            Self::Issued => ".post-anchor-claim-signing-issued",
            Self::Consumed => ".post-anchor-claim-signing-consumed",
        }
    }
}

struct PostAnchorClaimAuthorizationRecordV1 {
    bytes: [u8; POST_ANCHOR_CLAIM_AUTH_RECORD_LEN],
    state: PostAnchorClaimAuthorizationStateV1,
    session_id: [u8; 32],
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
    m8_policy_digest: [u8; 32],
    m8_anchor_evidence_digest: [u8; 32],
    chain_id: [u8; 32],
    dom_funding_id: [u8; 32],
    bitcoin_funding_id: [u8; 32],
    dom_shared_output_commitment: [u8; 33],
    claim_template_hash: [u8; 32],
    round_start_transcript_hash: [u8; 32],
    adaptor_point: PublicKey,
    bound_session_revision: u64,
    bound_session_record_digest: [u8; 32],
    m8_funding_gate_digest: [u8; 32],
    m8_funding_issuance_digest: [u8; 32],
    issuance_id: [u8; 32],
    operational_funding_commit_digest: [u8; 32],
    predecessor_digest: [u8; 32],
    dom_confirmation_depth: u32,
    bitcoin_confirmation_depth: u32,
    digest: [u8; 32],
}

struct PostAnchorClaimSigningBindingRecordV1 {
    bytes: [u8; POST_ANCHOR_CLAIM_BINDING_RECORD_LEN],
    session_id: [u8; 32],
    issuance_record_digest: [u8; 32],
    consumption_record_digest: [u8; 32],
    signing_binding_record_digest: [u8; 32],
    roster_digest: [u8; 32],
    round_start_record_digest: [u8; 32],
    digest: [u8; 32],
}

struct PostAnchorClaimPreSignatureRecordV1 {
    bytes: [u8; POST_ANCHOR_CLAIM_PRE_SIGNATURE_RECORD_LEN],
    session_id: [u8; 32],
    chain_id: [u8; 32],
    claim_template_hash: [u8; 32],
    adaptor_point: PublicKey,
    issuance_record_digest: [u8; 32],
    consumption_record_digest: [u8; 32],
    signing_binding_record_digest: [u8; 32],
    round_binding_record_digest: [u8; 32],
    round_start_record_digest: [u8; 32],
    terminal_record_digest: [u8; 32],
    terminal_revision: u64,
    round_start_transcript_hash: [u8; 32],
    reveal_transcript_hash: [u8; 32],
    terminal_transcript_hash: [u8; 32],
    roster_digest: [u8; 32],
    pre_signature: AdaptorPreSignatureV1,
    digest: [u8; 32],
}

impl PostAnchorClaimSigningBindingRecordV1 {
    fn new(
        session_id: [u8; 32],
        issuance_record_digest: [u8; 32],
        consumption_record_digest: [u8; 32],
        signing_binding_record_digest: [u8; 32],
        roster_digest: [u8; 32],
        round_start_record_digest: [u8; 32],
    ) -> Result<Self, SessionStoreError> {
        if [
            session_id,
            issuance_record_digest,
            consumption_record_digest,
            signing_binding_record_digest,
            roster_digest,
            round_start_record_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(SessionStoreError::Canonical);
        }
        let mut bytes = [0; POST_ANCHOR_CLAIM_BINDING_RECORD_LEN];
        bytes[..8].copy_from_slice(POST_ANCHOR_CLAIM_BINDING_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[16..48].copy_from_slice(&session_id);
        bytes[48..80].copy_from_slice(&issuance_record_digest);
        bytes[80..112].copy_from_slice(&consumption_record_digest);
        bytes[112..144].copy_from_slice(&signing_binding_record_digest);
        bytes[144..176].copy_from_slice(&roster_digest);
        bytes[176..208].copy_from_slice(&round_start_record_digest);
        let digest = tagged_hash(POST_ANCHOR_CLAIM_BINDING_HASH_TAG, &bytes[..208]);
        bytes[208..240].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            session_id,
            issuance_record_digest,
            consumption_record_digest,
            signing_binding_record_digest,
            roster_digest,
            round_start_record_digest,
            digest,
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() != POST_ANCHOR_CLAIM_BINDING_RECORD_LEN
            || &bytes[..8] != POST_ANCHOR_CLAIM_BINDING_MAGIC
            || u16::from_le_bytes(copy_array(&bytes[8..10])?) != FORMAT_VERSION
            || bytes[10..16] != [0; 6]
            || bytes[208..240] != tagged_hash(POST_ANCHOR_CLAIM_BINDING_HASH_TAG, &bytes[..208])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let record = Self {
            bytes: copy_array(bytes)?,
            session_id: copy_array(&bytes[16..48])?,
            issuance_record_digest: copy_array(&bytes[48..80])?,
            consumption_record_digest: copy_array(&bytes[80..112])?,
            signing_binding_record_digest: copy_array(&bytes[112..144])?,
            roster_digest: copy_array(&bytes[144..176])?,
            round_start_record_digest: copy_array(&bytes[176..208])?,
            digest: copy_array(&bytes[208..240])?,
        };
        if [
            record.session_id,
            record.issuance_record_digest,
            record.consumption_record_digest,
            record.signing_binding_record_digest,
            record.roster_digest,
            record.round_start_record_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(record)
    }
}

impl PostAnchorClaimPreSignatureRecordV1 {
    fn new(
        issued: &PostAnchorClaimAuthorizationRecordV1,
        consumed: &PostAnchorClaimAuthorizationRecordV1,
        signing_binding_record_digest: [u8; 32],
        round_binding_record_digest: [u8; 32],
        roster_digest: [u8; 32],
        round: &OperationalSigningRoundAuditV1,
        pre_signature: &AdaptorPreSignatureV1,
    ) -> Result<Self, SessionStoreError> {
        let reveal_transcript_hash = round
            .reveal_transcript_hash
            .ok_or(SessionStoreError::InvalidTransition)?;
        if issued.state != PostAnchorClaimAuthorizationStateV1::Issued
            || consumed.state != PostAnchorClaimAuthorizationStateV1::Consumed
            || consumed.predecessor_digest != issued.digest
            || consumed.digest == [0; 32]
            || signing_binding_record_digest == [0; 32]
            || round_binding_record_digest == [0; 32]
            || roster_digest == [0; 32]
            || round.round_start_record_digest == [0; 32]
            || round.terminal_record_digest == [0; 32]
            || round.round_start_transcript_hash != issued.round_start_transcript_hash
            || round.terminal_revision < round.round_start_revision
            || round.accepted_messages.len() != 6
            || pre_signature.claim_template_hash() != &issued.claim_template_hash
            || pre_signature.adaptor_point() != &issued.adaptor_point
            || pre_signature.transcript_hash() != &reveal_transcript_hash
        {
            return Err(SessionStoreError::Canonical);
        }
        let mut bytes = [0; POST_ANCHOR_CLAIM_PRE_SIGNATURE_RECORD_LEN];
        bytes[..8].copy_from_slice(POST_ANCHOR_CLAIM_PRE_SIGNATURE_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[16..48].copy_from_slice(&issued.session_id);
        bytes[48..80].copy_from_slice(&issued.chain_id);
        bytes[80..112].copy_from_slice(&issued.claim_template_hash);
        bytes[112..145].copy_from_slice(&issued.adaptor_point.to_compressed_bytes());
        bytes[145..177].copy_from_slice(&issued.digest);
        bytes[177..209].copy_from_slice(&consumed.digest);
        bytes[209..241].copy_from_slice(&signing_binding_record_digest);
        bytes[241..273].copy_from_slice(&round_binding_record_digest);
        bytes[273..305].copy_from_slice(&round.round_start_record_digest);
        bytes[305..337].copy_from_slice(&round.terminal_record_digest);
        bytes[337..345].copy_from_slice(&round.terminal_revision.to_le_bytes());
        bytes[345..377].copy_from_slice(&round.round_start_transcript_hash);
        bytes[377..409].copy_from_slice(&reveal_transcript_hash);
        bytes[409..441].copy_from_slice(&round.terminal_transcript_hash);
        bytes[441..473].copy_from_slice(&roster_digest);
        bytes[473..635].copy_from_slice(&pre_signature.to_bytes());
        let digest = tagged_hash(POST_ANCHOR_CLAIM_PRE_SIGNATURE_HASH_TAG, &bytes[..635]);
        bytes[635..667].copy_from_slice(&digest);
        Self::from_bytes(&bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() != POST_ANCHOR_CLAIM_PRE_SIGNATURE_RECORD_LEN
            || &bytes[..8] != POST_ANCHOR_CLAIM_PRE_SIGNATURE_MAGIC
            || u16::from_le_bytes(copy_array(&bytes[8..10])?) != FORMAT_VERSION
            || bytes[10..16] != [0; 6]
            || bytes[635..667]
                != tagged_hash(POST_ANCHOR_CLAIM_PRE_SIGNATURE_HASH_TAG, &bytes[..635])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let session_id = copy_array(&bytes[16..48])?;
        let chain_id = copy_array(&bytes[48..80])?;
        let claim_template_hash = copy_array(&bytes[80..112])?;
        let adaptor_point = PublicKey::from_compressed_bytes(&bytes[112..145])
            .map_err(|_| SessionStoreError::Quarantined)?;
        let issuance_record_digest = copy_array(&bytes[145..177])?;
        let consumption_record_digest = copy_array(&bytes[177..209])?;
        let signing_binding_record_digest = copy_array(&bytes[209..241])?;
        let round_binding_record_digest = copy_array(&bytes[241..273])?;
        let round_start_record_digest = copy_array(&bytes[273..305])?;
        let terminal_record_digest = copy_array(&bytes[305..337])?;
        let terminal_revision = u64::from_le_bytes(copy_array(&bytes[337..345])?);
        let round_start_transcript_hash = copy_array(&bytes[345..377])?;
        let reveal_transcript_hash = copy_array(&bytes[377..409])?;
        let terminal_transcript_hash = copy_array(&bytes[409..441])?;
        let roster_digest = copy_array(&bytes[441..473])?;
        let pre_signature = AdaptorPreSignatureV1::from_bytes(&bytes[473..635])
            .map_err(|_| SessionStoreError::Quarantined)?;
        let digest = copy_array(&bytes[635..667])?;
        if [
            session_id,
            chain_id,
            claim_template_hash,
            issuance_record_digest,
            consumption_record_digest,
            signing_binding_record_digest,
            round_binding_record_digest,
            round_start_record_digest,
            terminal_record_digest,
            round_start_transcript_hash,
            reveal_transcript_hash,
            terminal_transcript_hash,
            roster_digest,
            digest,
        ]
        .contains(&[0; 32])
            || pre_signature.claim_template_hash() != &claim_template_hash
            || pre_signature.adaptor_point() != &adaptor_point
            || pre_signature.transcript_hash() != &reveal_transcript_hash
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes
                .try_into()
                .map_err(|_| SessionStoreError::Quarantined)?,
            session_id,
            chain_id,
            claim_template_hash,
            adaptor_point,
            issuance_record_digest,
            consumption_record_digest,
            signing_binding_record_digest,
            round_binding_record_digest,
            round_start_record_digest,
            terminal_record_digest,
            terminal_revision,
            round_start_transcript_hash,
            reveal_transcript_hash,
            terminal_transcript_hash,
            roster_digest,
            pre_signature,
            digest,
        })
    }

    fn authenticated_handle(
        &self,
    ) -> Result<AuthenticatedPostAnchorClaimPreSignatureV1, SessionStoreError> {
        Ok(AuthenticatedPostAnchorClaimPreSignatureV1 {
            session_id: self.session_id,
            claim_template_hash: self.claim_template_hash,
            reveal_transcript_hash: self.reveal_transcript_hash,
            artifact_record_digest: self.digest,
            pre_signature: AdaptorPreSignatureV1::from_bytes(&self.pre_signature.to_bytes())
                .map_err(|_| SessionStoreError::Quarantined)?,
        })
    }
}

impl PostAnchorClaimAuthorizationRecordV1 {
    fn new_issued(
        evidence: &PostAnchorDomClaimSigningEvidenceV1,
        bound_session: &SessionRecordV1,
        m8_funding_gate_digest: [u8; 32],
        m8_funding_issuance_digest: [u8; 32],
        operational_funding_commit_digest: [u8; 32],
        issuance_id: [u8; 32],
    ) -> Result<Self, SessionStoreError> {
        Self::new(
            PostAnchorClaimAuthorizationStateV1::Issued,
            evidence.session_id,
            evidence.settlement_id,
            evidence.terms_hash,
            evidence.m8_policy_digest,
            evidence.m8_anchor_evidence_digest,
            evidence.chain_id,
            evidence.dom_funding_id,
            evidence.bitcoin_funding_id,
            evidence.dom_shared_output_commitment,
            evidence.expected_claim_template_hash,
            evidence.expected_round_start_transcript_hash,
            &evidence.expected_adaptor_point,
            bound_session.revision(),
            *bound_session.digest(),
            m8_funding_gate_digest,
            m8_funding_issuance_digest,
            issuance_id,
            operational_funding_commit_digest,
            [0; 32],
            evidence.dom_confirmation_depth,
            evidence.bitcoin_confirmation_depth,
        )
    }

    fn new_consumed(issued: &Self) -> Result<Self, SessionStoreError> {
        if issued.state != PostAnchorClaimAuthorizationStateV1::Issued {
            return Err(SessionStoreError::Canonical);
        }
        Self::new(
            PostAnchorClaimAuthorizationStateV1::Consumed,
            issued.session_id,
            issued.settlement_id,
            issued.terms_hash,
            issued.m8_policy_digest,
            issued.m8_anchor_evidence_digest,
            issued.chain_id,
            issued.dom_funding_id,
            issued.bitcoin_funding_id,
            issued.dom_shared_output_commitment,
            issued.claim_template_hash,
            issued.round_start_transcript_hash,
            &issued.adaptor_point,
            issued.bound_session_revision,
            issued.bound_session_record_digest,
            issued.m8_funding_gate_digest,
            issued.m8_funding_issuance_digest,
            issued.issuance_id,
            issued.operational_funding_commit_digest,
            issued.digest,
            issued.dom_confirmation_depth,
            issued.bitcoin_confirmation_depth,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        state: PostAnchorClaimAuthorizationStateV1,
        session_id: [u8; 32],
        settlement_id: [u8; 32],
        terms_hash: [u8; 32],
        m8_policy_digest: [u8; 32],
        m8_anchor_evidence_digest: [u8; 32],
        chain_id: [u8; 32],
        dom_funding_id: [u8; 32],
        bitcoin_funding_id: [u8; 32],
        dom_shared_output_commitment: [u8; 33],
        claim_template_hash: [u8; 32],
        round_start_transcript_hash: [u8; 32],
        adaptor_point: &PublicKey,
        bound_session_revision: u64,
        bound_session_record_digest: [u8; 32],
        m8_funding_gate_digest: [u8; 32],
        m8_funding_issuance_digest: [u8; 32],
        issuance_id: [u8; 32],
        operational_funding_commit_digest: [u8; 32],
        predecessor_digest: [u8; 32],
        dom_confirmation_depth: u32,
        bitcoin_confirmation_depth: u32,
    ) -> Result<Self, SessionStoreError> {
        if session_id == [0; 32]
            || settlement_id == [0; 32]
            || terms_hash == [0; 32]
            || m8_policy_digest == [0; 32]
            || m8_anchor_evidence_digest == [0; 32]
            || chain_id == [0; 32]
            || dom_funding_id == [0; 32]
            || bitcoin_funding_id == [0; 32]
            || dom_shared_output_commitment == [0; 33]
            || claim_template_hash == [0; 32]
            || round_start_transcript_hash == [0; 32]
            || bound_session_record_digest == [0; 32]
            || m8_funding_gate_digest == [0; 32]
            || m8_funding_issuance_digest == [0; 32]
            || issuance_id == [0; 32]
            || operational_funding_commit_digest == [0; 32]
            || dom_confirmation_depth == 0
            || bitcoin_confirmation_depth == 0
            || (state == PostAnchorClaimAuthorizationStateV1::Issued
                && predecessor_digest != [0; 32])
            || (state == PostAnchorClaimAuthorizationStateV1::Consumed
                && predecessor_digest == [0; 32])
        {
            return Err(SessionStoreError::Canonical);
        }
        let mut bytes = [0; POST_ANCHOR_CLAIM_AUTH_RECORD_LEN];
        bytes[..8].copy_from_slice(POST_ANCHOR_CLAIM_AUTH_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[10] = state.byte();
        bytes[11] = PurposeV1::ClaimAdaptor.to_byte();
        bytes[16..48].copy_from_slice(&session_id);
        bytes[48..80].copy_from_slice(&settlement_id);
        bytes[80..112].copy_from_slice(&terms_hash);
        bytes[112..144].copy_from_slice(&m8_policy_digest);
        bytes[144..176].copy_from_slice(&m8_anchor_evidence_digest);
        bytes[176..208].copy_from_slice(&chain_id);
        bytes[208..240].copy_from_slice(&dom_funding_id);
        bytes[240..272].copy_from_slice(&bitcoin_funding_id);
        bytes[272..305].copy_from_slice(&dom_shared_output_commitment);
        bytes[305..337].copy_from_slice(&claim_template_hash);
        bytes[337..369].copy_from_slice(&round_start_transcript_hash);
        bytes[369..402].copy_from_slice(&adaptor_point.to_compressed_bytes());
        bytes[402..406].copy_from_slice(&dom_confirmation_depth.to_le_bytes());
        bytes[406..410].copy_from_slice(&bitcoin_confirmation_depth.to_le_bytes());
        bytes[416..424].copy_from_slice(&bound_session_revision.to_le_bytes());
        bytes[424..456].copy_from_slice(&bound_session_record_digest);
        bytes[456..488].copy_from_slice(&m8_funding_gate_digest);
        bytes[488..520].copy_from_slice(&m8_funding_issuance_digest);
        bytes[520..552].copy_from_slice(&issuance_id);
        bytes[552..584].copy_from_slice(&operational_funding_commit_digest);
        bytes[584..616].copy_from_slice(&predecessor_digest);
        let digest = tagged_hash(POST_ANCHOR_CLAIM_AUTH_HASH_TAG, &bytes[..616]);
        bytes[616..648].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            state,
            session_id,
            settlement_id,
            terms_hash,
            m8_policy_digest,
            m8_anchor_evidence_digest,
            chain_id,
            dom_funding_id,
            bitcoin_funding_id,
            dom_shared_output_commitment,
            claim_template_hash,
            round_start_transcript_hash,
            adaptor_point: adaptor_point.clone(),
            bound_session_revision,
            bound_session_record_digest,
            m8_funding_gate_digest,
            m8_funding_issuance_digest,
            issuance_id,
            operational_funding_commit_digest,
            predecessor_digest,
            dom_confirmation_depth,
            bitcoin_confirmation_depth,
            digest,
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() != POST_ANCHOR_CLAIM_AUTH_RECORD_LEN
            || &bytes[..8] != POST_ANCHOR_CLAIM_AUTH_MAGIC
            || u16::from_le_bytes(copy_array(&bytes[8..10])?) != FORMAT_VERSION
            || bytes[11] != PurposeV1::ClaimAdaptor.to_byte()
            || bytes[12..16] != [0; 4]
            || bytes[410..416] != [0; 6]
            || bytes[616..648] != tagged_hash(POST_ANCHOR_CLAIM_AUTH_HASH_TAG, &bytes[..616])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let state = PostAnchorClaimAuthorizationStateV1::from_byte(bytes[10])?;
        let record = Self {
            bytes: copy_array(bytes)?,
            state,
            session_id: copy_array(&bytes[16..48])?,
            settlement_id: copy_array(&bytes[48..80])?,
            terms_hash: copy_array(&bytes[80..112])?,
            m8_policy_digest: copy_array(&bytes[112..144])?,
            m8_anchor_evidence_digest: copy_array(&bytes[144..176])?,
            chain_id: copy_array(&bytes[176..208])?,
            dom_funding_id: copy_array(&bytes[208..240])?,
            bitcoin_funding_id: copy_array(&bytes[240..272])?,
            dom_shared_output_commitment: copy_array(&bytes[272..305])?,
            claim_template_hash: copy_array(&bytes[305..337])?,
            round_start_transcript_hash: copy_array(&bytes[337..369])?,
            adaptor_point: PublicKey::from_compressed_bytes(&bytes[369..402])
                .map_err(|_| SessionStoreError::Quarantined)?,
            dom_confirmation_depth: u32::from_le_bytes(copy_array(&bytes[402..406])?),
            bitcoin_confirmation_depth: u32::from_le_bytes(copy_array(&bytes[406..410])?),
            bound_session_revision: u64::from_le_bytes(copy_array(&bytes[416..424])?),
            bound_session_record_digest: copy_array(&bytes[424..456])?,
            m8_funding_gate_digest: copy_array(&bytes[456..488])?,
            m8_funding_issuance_digest: copy_array(&bytes[488..520])?,
            issuance_id: copy_array(&bytes[520..552])?,
            operational_funding_commit_digest: copy_array(&bytes[552..584])?,
            predecessor_digest: copy_array(&bytes[584..616])?,
            digest: copy_array(&bytes[616..648])?,
        };
        if record.session_id == [0; 32]
            || record.settlement_id == [0; 32]
            || record.terms_hash == [0; 32]
            || record.m8_policy_digest == [0; 32]
            || record.m8_anchor_evidence_digest == [0; 32]
            || record.chain_id == [0; 32]
            || record.dom_funding_id == [0; 32]
            || record.bitcoin_funding_id == [0; 32]
            || record.dom_shared_output_commitment == [0; 33]
            || record.claim_template_hash == [0; 32]
            || record.round_start_transcript_hash == [0; 32]
            || record.bound_session_record_digest == [0; 32]
            || record.m8_funding_gate_digest == [0; 32]
            || record.m8_funding_issuance_digest == [0; 32]
            || record.issuance_id == [0; 32]
            || record.operational_funding_commit_digest == [0; 32]
            || record.dom_confirmation_depth == 0
            || record.bitcoin_confirmation_depth == 0
            || (state == PostAnchorClaimAuthorizationStateV1::Issued
                && record.predecessor_digest != [0; 32])
            || (state == PostAnchorClaimAuthorizationStateV1::Consumed
                && record.predecessor_digest == [0; 32])
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(record)
    }

    fn matches_evidence(&self, evidence: &PostAnchorDomClaimSigningEvidenceV1) -> bool {
        self.session_id == evidence.session_id
            && self.settlement_id == evidence.settlement_id
            && self.terms_hash == evidence.terms_hash
            && self.m8_policy_digest == evidence.m8_policy_digest
            && self.m8_anchor_evidence_digest == evidence.m8_anchor_evidence_digest
            && self.chain_id == evidence.chain_id
            && self.dom_funding_id == evidence.dom_funding_id
            && self.bitcoin_funding_id == evidence.bitcoin_funding_id
            && self.dom_shared_output_commitment == evidence.dom_shared_output_commitment
            && self.claim_template_hash == evidence.expected_claim_template_hash
            && self.round_start_transcript_hash == evidence.expected_round_start_transcript_hash
            && self.adaptor_point == evidence.expected_adaptor_point
            && self.dom_confirmation_depth == evidence.dom_confirmation_depth
            && self.bitcoin_confirmation_depth == evidence.bitcoin_confirmation_depth
    }

    fn issued_capability(
        &self,
        open_instance_id: [u8; 32],
    ) -> Result<ClaimSigningAuthorizationV1, SessionStoreError> {
        if self.state != PostAnchorClaimAuthorizationStateV1::Issued {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        Ok(ClaimSigningAuthorizationV1 {
            session_id: self.session_id,
            settlement_id: self.settlement_id,
            terms_hash: self.terms_hash,
            m8_policy_digest: self.m8_policy_digest,
            m8_anchor_evidence_digest: self.m8_anchor_evidence_digest,
            dom_funding_id: self.dom_funding_id,
            bitcoin_funding_id: self.bitcoin_funding_id,
            dom_shared_output_commitment: self.dom_shared_output_commitment,
            claim_template_hash: self.claim_template_hash,
            round_start_transcript_hash: self.round_start_transcript_hash,
            adaptor_point: self.adaptor_point.clone(),
            issuance_id: self.issuance_id,
            issuance_record_digest: self.digest,
            bound_session_revision: self.bound_session_revision,
            bound_session_record_digest: self.bound_session_record_digest,
            dom_confirmation_depth: self.dom_confirmation_depth,
            bitcoin_confirmation_depth: self.bitcoin_confirmation_depth,
            open_instance_id,
        })
    }

    fn consumed_capability(
        &self,
        issued: &Self,
        open_instance_id: [u8; 32],
    ) -> Result<ConsumedClaimSigningAuthorizationV1, SessionStoreError> {
        if self.state != PostAnchorClaimAuthorizationStateV1::Consumed
            || issued.state != PostAnchorClaimAuthorizationStateV1::Issued
            || self.predecessor_digest != issued.digest
            || self.issuance_id != issued.issuance_id
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        Ok(ConsumedClaimSigningAuthorizationV1 {
            session_id: self.session_id,
            settlement_id: self.settlement_id,
            terms_hash: self.terms_hash,
            m8_policy_digest: self.m8_policy_digest,
            m8_anchor_evidence_digest: self.m8_anchor_evidence_digest,
            dom_funding_id: self.dom_funding_id,
            bitcoin_funding_id: self.bitcoin_funding_id,
            dom_shared_output_commitment: self.dom_shared_output_commitment,
            claim_template_hash: self.claim_template_hash,
            round_start_transcript_hash: self.round_start_transcript_hash,
            adaptor_point: self.adaptor_point.clone(),
            issuance_id: self.issuance_id,
            issuance_record_digest: issued.digest,
            consumption_record_digest: self.digest,
            bound_session_revision: self.bound_session_revision,
            bound_session_record_digest: self.bound_session_record_digest,
            dom_confirmation_depth: self.dom_confirmation_depth,
            bitcoin_confirmation_depth: self.bitcoin_confirmation_depth,
            _open_instance_id: open_instance_id,
        })
    }
}

impl ReservationLookupRecordV1 {
    fn new_custodied(
        session: &SessionRecordV1,
        request_lookup: [u8; 32],
        context_binding_digest: [u8; 32],
    ) -> Result<Self, SessionStoreError> {
        Self::new(
            session,
            ReservationLookupStateV1::Custodied,
            request_lookup,
            context_binding_digest,
            [0; 32],
        )
    }

    fn new_abandoned(session: &SessionRecordV1, custody: &Self) -> Result<Self, SessionStoreError> {
        if custody.state != ReservationLookupStateV1::Custodied {
            return Err(SessionStoreError::Canonical);
        }
        Self::new(
            session,
            ReservationLookupStateV1::AbandonedBeforeVaultClaim,
            custody.request_lookup,
            custody.context_binding_digest,
            custody.digest,
        )
    }

    fn new(
        session: &SessionRecordV1,
        state: ReservationLookupStateV1,
        request_lookup: [u8; 32],
        context_binding_digest: [u8; 32],
        predecessor_digest: [u8; 32],
    ) -> Result<Self, SessionStoreError> {
        if session.session_id() == [0; 32]
            || request_lookup == [0; 32]
            || context_binding_digest == [0; 32]
            || (state == ReservationLookupStateV1::Custodied && predecessor_digest != [0; 32])
            || (state == ReservationLookupStateV1::AbandonedBeforeVaultClaim
                && predecessor_digest == [0; 32])
        {
            return Err(SessionStoreError::Canonical);
        }
        let mut bytes = [0; RESERVATION_LOOKUP_RECORD_LEN];
        bytes[..8].copy_from_slice(RESERVATION_LOOKUP_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[10] = state.byte();
        bytes[16..48].copy_from_slice(&request_lookup);
        bytes[48..80].copy_from_slice(&session.session_id());
        bytes[80..112].copy_from_slice(&context_binding_digest);
        bytes[112..120].copy_from_slice(&session.revision().to_le_bytes());
        bytes[120..152].copy_from_slice(session.digest());
        bytes[152..184].copy_from_slice(&predecessor_digest);
        let digest = tagged_hash(RESERVATION_LOOKUP_HASH_TAG, &bytes[..184]);
        bytes[184..216].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            state,
            request_lookup,
            session_id: session.session_id(),
            context_binding_digest,
            session_revision: session.revision(),
            session_record_digest: *session.digest(),
            predecessor_digest,
            digest,
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() != RESERVATION_LOOKUP_RECORD_LEN
            || &bytes[..8] != RESERVATION_LOOKUP_MAGIC
            || u16::from_le_bytes(copy_array(&bytes[8..10])?) != FORMAT_VERSION
            || bytes[11..16] != [0; 5]
            || bytes[184..216] != tagged_hash(RESERVATION_LOOKUP_HASH_TAG, &bytes[..184])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let state = ReservationLookupStateV1::from_byte(bytes[10])?;
        let request_lookup = copy_array(&bytes[16..48])?;
        let session_id = copy_array(&bytes[48..80])?;
        let context_binding_digest = copy_array(&bytes[80..112])?;
        let predecessor_digest = copy_array(&bytes[152..184])?;
        if request_lookup == [0; 32]
            || session_id == [0; 32]
            || context_binding_digest == [0; 32]
            || (state == ReservationLookupStateV1::Custodied && predecessor_digest != [0; 32])
            || (state == ReservationLookupStateV1::AbandonedBeforeVaultClaim
                && predecessor_digest == [0; 32])
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: copy_array(bytes)?,
            state,
            request_lookup,
            session_id,
            context_binding_digest,
            session_revision: u64::from_le_bytes(copy_array(&bytes[112..120])?),
            session_record_digest: copy_array(&bytes[120..152])?,
            predecessor_digest,
            digest: copy_array(&bytes[184..216])?,
        })
    }
}

struct OperationalFundingGateRecordV1 {
    bytes: Vec<u8>,
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    chain_id: [u8; 32],
    claim_transcript_hash: [u8; 32],
    claim_template_hash: [u8; 32],
    refund_template_hash: [u8; 32],
    bp_statement_hash: [u8; 32],
    recovery_binding_hash: [u8; 32],
    shared_output_commitment: [u8; 33],
    refund_tx_hash: [u8; 32],
    claim_pre_signature_hash: [u8; 32],
    backup_receipt_hash: [u8; 32],
    refund_unlock_height: u64,
    validation_height: u64,
    now_unix_seconds: u64,
    refund_bytes: Vec<u8>,
    claim_pre_signature: Vec<u8>,
    claim_template_bytes: Vec<u8>,
    refund_template_bytes: Vec<u8>,
    bp_statement_bytes: Vec<u8>,
    digest: [u8; 32],
}

struct OperationalM8FundingGateRecordV1 {
    bytes: Vec<u8>,
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    m8_policy_digest: [u8; 32],
    chain_id: [u8; 32],
    claim_template_hash: [u8; 32],
    claim_adaptor_point: PublicKey,
    refund_template_hash: [u8; 32],
    bp_statement_hash: [u8; 32],
    recovery_binding_hash: [u8; 32],
    shared_output_commitment: [u8; 33],
    refund_tx_hash: [u8; 32],
    backup_receipt_hash: [u8; 32],
    refund_unlock_height: u64,
    validation_height: u64,
    now_unix_seconds: u64,
    refund_bytes: Vec<u8>,
    claim_template_bytes: Vec<u8>,
    refund_template_bytes: Vec<u8>,
    bp_statement_bytes: Vec<u8>,
    digest: [u8; 32],
}

struct OperationalFundingIssuanceRecordV1 {
    bytes: Vec<u8>,
    binding: OperationalFundingAuthorizationBindingV1,
    authorized_revision: u64,
    gate_digest: [u8; 32],
    unsigned_template_bytes: Vec<u8>,
    funding_authorized_record: SessionRecordV1,
    digest: [u8; 32],
}

/// Immutable one-shot issuance for the profile-tagged M.8 two-phase path.
///
/// This is intentionally a distinct retained record from the legacy
/// claim-pre-signature-first issuance. Its embedded DOM binding contains the
/// canonical `M8T2` profile tag and has no field capable of carrying a claim
/// pre-signature.
struct OperationalM8FundingIssuanceRecordV1 {
    bytes: Vec<u8>,
    binding: OperationalM8FundingAuthorizationBindingV1,
    authorized_revision: u64,
    gate_digest: [u8; 32],
    unsigned_template_bytes: Vec<u8>,
    funding_authorized_record: SessionRecordV1,
    digest: [u8; 32],
}

struct OperationalFundingCommitRecordV1 {
    bytes: Vec<u8>,
    session_id: [u8; 32],
    artifact: FundingArtifactRecordV1,
    consumption: FundingConsumptionRecordV1,
}

struct OperationalM8FundingCommitRecordV1 {
    bytes: Vec<u8>,
    session_id: [u8; 32],
    issuance_record_digest: [u8; 32],
    artifact: FundingArtifactRecordV1,
    consumption: FundingConsumptionRecordV1,
}

struct OperationalSigningRoundAuditV1 {
    round_start_revision: u64,
    round_start_record_digest: [u8; 32],
    round_start_transcript_hash: [u8; 32],
    reveal_transcript_hash: Option<[u8; 32]>,
    terminal_revision: u64,
    terminal_record_digest: [u8; 32],
    terminal_transcript_hash: [u8; 32],
    sender_sequence_bases: [u64; 2],
    template_commit_payload: [u8; 160],
    accepted_messages: Vec<Vec<u8>>,
}

struct SigningSessionBindingRecordV1 {
    bytes: Vec<u8>,
    session_id: [u8; 32],
    purpose: PurposeV1,
}

struct DecodedSigningSessionBindingV1 {
    contract_kind: ContractKindV1,
    roster: ParticipantRosterV1,
    transaction_template: Transaction,
    template_hash: [u8; 32],
    kernel_index: usize,
    adaptor_point: Option<PublicKey>,
    initial_transcript_hash: [u8; 32],
    round_start_transcript_hash: [u8; 32],
    sender_sequence_bases: [u64; 2],
    round_start_revision: u64,
    round_start_record_digest: [u8; 32],
    template_commit_payload: [u8; 160],
}

struct TransportRosterRecordV1 {
    bytes: [u8; TRANSPORT_ROSTER_LEN],
    session_id: [u8; 32],
    chain_id: [u8; 32],
    participants: [SessionTransportParticipantV1; 2],
}

struct TransportIdentityBindingRecordV1 {
    bytes: [u8; TRANSPORT_IDENTITY_BINDING_LEN],
    session_id: [u8; 32],
    chain_id: [u8; 32],
    references: [SessionTransportIdentityReferenceV1; 2],
}

impl TransportRosterRecordV1 {
    fn new(
        session_id: [u8; 32],
        chain_id: [u8; 32],
        participants: [SessionTransportParticipantV1; 2],
    ) -> Self {
        let mut bytes = [0; TRANSPORT_ROSTER_LEN];
        bytes[..8].copy_from_slice(ROSTER_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[16..48].copy_from_slice(&session_id);
        bytes[48..80].copy_from_slice(&chain_id);
        for (index, participant) in participants.iter().enumerate() {
            let offset = 80 + index * 66;
            bytes[offset..offset + 32].copy_from_slice(&participant.participant_id);
            bytes[offset + 32..offset + 65]
                .copy_from_slice(&participant.identity_key.to_compressed_bytes());
            bytes[offset + 65] = participant.direction.to_byte();
        }
        let digest = tagged_hash(ROSTER_HASH_TAG, &bytes[..212]);
        bytes[212..].copy_from_slice(&digest);
        Self {
            bytes,
            session_id,
            chain_id,
            participants,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() != TRANSPORT_ROSTER_LEN
            || &bytes[..8] != ROSTER_MAGIC
            || u16::from_le_bytes([bytes[8], bytes[9]]) != FORMAT_VERSION
            || bytes[10..16] != [0; 6]
            || bytes[212..] != tagged_hash(ROSTER_HASH_TAG, &bytes[..212])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let session_id = copy_array(&bytes[16..48])?;
        let chain_id = copy_array(&bytes[48..80])?;
        let parse = |index: usize| -> Result<SessionTransportParticipantV1, SessionStoreError> {
            let offset = 80 + index * 66;
            SessionTransportParticipantV1::new(
                copy_array(&bytes[offset..offset + 32])?,
                PublicKey::from_compressed_bytes(&bytes[offset + 32..offset + 65])
                    .map_err(|_| SessionStoreError::Quarantined)?,
                DirectionV1::try_from(bytes[offset + 65])
                    .map_err(|_| SessionStoreError::Quarantined)?,
            )
        };
        let participants = [parse(0)?, parse(1)?];
        if session_id == [0; 32]
            || chain_id == [0; 32]
            || participants[0].participant_id == participants[1].participant_id
            || participants[0].identity_key == participants[1].identity_key
            || participants[0].direction == participants[1].direction
            || participants[0].direction != DirectionV1::Initiator
            || participants[1].direction != DirectionV1::Responder
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut exact = [0; TRANSPORT_ROSTER_LEN];
        exact.copy_from_slice(bytes);
        Ok(Self {
            bytes: exact,
            session_id,
            chain_id,
            participants,
        })
    }
}

impl TransportIdentityBindingRecordV1 {
    fn new(
        session_id: [u8; 32],
        chain_id: [u8; 32],
        references: [SessionTransportIdentityReferenceV1; 2],
    ) -> Self {
        let mut bytes = [0u8; TRANSPORT_IDENTITY_BINDING_LEN];
        bytes[..8].copy_from_slice(TRANSPORT_IDENTITY_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[16..48].copy_from_slice(&session_id);
        bytes[48..80].copy_from_slice(&chain_id);
        for (index, reference) in references.iter().enumerate() {
            let offset = 80 + index * 129;
            bytes[offset..offset + 32].copy_from_slice(&reference.participant_id);
            bytes[offset + 32..offset + 64].copy_from_slice(&reference.key_reference);
            bytes[offset + 64..offset + 96].copy_from_slice(&reference.noise_public_key);
            bytes[offset + 96..offset + 129]
                .copy_from_slice(&reference.schnorr_public_key.to_compressed_bytes());
        }
        let digest = tagged_hash(TRANSPORT_IDENTITY_HASH_TAG, &bytes[..338]);
        bytes[338..].copy_from_slice(&digest);
        Self {
            bytes,
            session_id,
            chain_id,
            references,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() != TRANSPORT_IDENTITY_BINDING_LEN
            || &bytes[..8] != TRANSPORT_IDENTITY_MAGIC
            || u16::from_le_bytes([bytes[8], bytes[9]]) != FORMAT_VERSION
            || bytes[10..16] != [0; 6]
            || bytes[338..] != tagged_hash(TRANSPORT_IDENTITY_HASH_TAG, &bytes[..338])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let session_id = copy_array(&bytes[16..48])?;
        let chain_id = copy_array(&bytes[48..80])?;
        let parse =
            |index: usize| -> Result<SessionTransportIdentityReferenceV1, SessionStoreError> {
                let offset = 80 + index * 129;
                SessionTransportIdentityReferenceV1::new(
                    copy_array(&bytes[offset..offset + 32])?,
                    copy_array(&bytes[offset + 32..offset + 64])?,
                    copy_array(&bytes[offset + 64..offset + 96])?,
                    PublicKey::from_compressed_bytes(&bytes[offset + 96..offset + 129])
                        .map_err(|_| SessionStoreError::Quarantined)?,
                )
                .map_err(|_| SessionStoreError::Quarantined)
            };
        let references = [parse(0)?, parse(1)?];
        if session_id == [0; 32]
            || chain_id == [0; 32]
            || references[0].participant_id == references[1].participant_id
            || references[0].key_reference == references[1].key_reference
            || references[0].noise_public_key == references[1].noise_public_key
            || references[0].schnorr_public_key == references[1].schnorr_public_key
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut exact = [0u8; TRANSPORT_IDENTITY_BINDING_LEN];
        exact.copy_from_slice(bytes);
        Ok(Self {
            bytes: exact,
            session_id,
            chain_id,
            references,
        })
    }
}

impl SigningSessionBindingRecordV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        trusted_chain_id: &TrustedChainIdV1,
        session: &SessionRecordV1,
        contract_kind: ContractKindV1,
        purpose: PurposeV1,
        roster: &ParticipantRosterV1,
        transaction_bytes: &[u8],
        template_hash: [u8; 32],
        kernel_index: usize,
        adaptor_point: Option<&PublicKey>,
        initial_transcript_hash: [u8; 32],
        round: &OperationalSigningRoundAuditV1,
    ) -> Result<Self, SessionStoreError> {
        let transaction_len =
            u32::try_from(transaction_bytes.len()).map_err(|_| SessionStoreError::Canonical)?;
        let kernel_index = u32::try_from(kernel_index).map_err(|_| SessionStoreError::Canonical)?;
        let total = SIGNING_BINDING_PREFIX_LEN
            .checked_add(transaction_bytes.len())
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Canonical)?;
        if total > SIGNING_BINDING_MAX_LEN || roster.entries().len() != 2 {
            return Err(SessionStoreError::Canonical);
        }
        let mut bytes = vec![0; total];
        bytes[..8].copy_from_slice(SIGNING_BINDING_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[10] = purpose.to_byte();
        bytes[11] = u8::from(adaptor_point.is_some());
        bytes[12..14].copy_from_slice(&contract_kind.to_le_bytes());
        bytes[16..48].copy_from_slice(&session.session_id());
        bytes[48..80].copy_from_slice(trusted_chain_id.as_bytes());
        bytes[80..112].copy_from_slice(&session.terms_hash());
        bytes[112..120].copy_from_slice(&round.round_start_revision.to_le_bytes());
        bytes[120..152].copy_from_slice(&round.round_start_record_digest);
        bytes[152..184].copy_from_slice(&initial_transcript_hash);
        bytes[184..216].copy_from_slice(&round.round_start_transcript_hash);
        bytes[216..224].copy_from_slice(&round.sender_sequence_bases[0].to_le_bytes());
        bytes[224..232].copy_from_slice(&round.sender_sequence_bases[1].to_le_bytes());
        bytes[232..236].copy_from_slice(&kernel_index.to_le_bytes());
        bytes[236..240].copy_from_slice(&transaction_len.to_le_bytes());
        bytes[240..272].copy_from_slice(&template_hash);
        match adaptor_point {
            Some(point) => bytes[272..305].copy_from_slice(&point.to_compressed_bytes()),
            None => bytes[272..305].fill(0),
        }
        bytes[312..472].copy_from_slice(&round.template_commit_payload);
        for (index, participant) in roster.entries().iter().enumerate() {
            let offset = 472 + index * 99;
            bytes[offset..offset + 32].copy_from_slice(participant.participant_id());
            bytes[offset + 32..offset + 65]
                .copy_from_slice(&participant.identity_public_key().to_compressed_bytes());
            bytes[offset + 65..offset + 98]
                .copy_from_slice(&participant.signing_public_key().to_compressed_bytes());
            bytes[offset + 98] = participant.direction().to_byte();
        }
        bytes[SIGNING_BINDING_PREFIX_LEN..total - DIGEST_LEN].copy_from_slice(transaction_bytes);
        let digest = tagged_hash(SIGNING_BINDING_HASH_TAG, &bytes[..total - DIGEST_LEN]);
        bytes[total - DIGEST_LEN..].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            session_id: session.session_id(),
            purpose,
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < SIGNING_BINDING_PREFIX_LEN + DIGEST_LEN
            || bytes.len() > SIGNING_BINDING_MAX_LEN
            || &bytes[..8] != SIGNING_BINDING_MAGIC
            || u16::from_le_bytes(copy_array(&bytes[8..10])?) != FORMAT_VERSION
            || bytes[14..16] != [0; 2]
            || bytes[305..312] != [0; 7]
            || bytes[670..672] != [0; 2]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let transaction_len = u32::from_le_bytes(copy_array(&bytes[236..240])?) as usize;
        let total = SIGNING_BINDING_PREFIX_LEN
            .checked_add(transaction_len)
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Quarantined)?;
        if total != bytes.len()
            || bytes[total - DIGEST_LEN..]
                != tagged_hash(SIGNING_BINDING_HASH_TAG, &bytes[..total - DIGEST_LEN])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let session_id = copy_array(&bytes[16..48])?;
        let purpose = PurposeV1::try_from(bytes[10]).map_err(|_| SessionStoreError::Quarantined)?;
        if session_id == [0; 32] || !purpose.is_strict_v1_authorized() || bytes[11] > 1 {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            session_id,
            purpose,
        })
    }

    fn decode(
        &self,
        trusted_chain_id: &TrustedChainIdV1,
    ) -> Result<DecodedSigningSessionBindingV1, SessionStoreError> {
        let bytes = &self.bytes;
        if bytes[48..80] != *trusted_chain_id.as_bytes() {
            return Err(SessionStoreError::Canonical);
        }
        let contract_kind =
            ContractKindV1::try_from(u16::from_le_bytes(copy_array(&bytes[12..14])?))
                .map_err(|_| SessionStoreError::Quarantined)?;
        let parse_participant = |index: usize| -> Result<ParticipantIdentityV1, SessionStoreError> {
            let offset = 472 + index * 99;
            let participant = ParticipantIdentityV1::new(
                trusted_chain_id,
                PublicKey::from_compressed_bytes(&bytes[offset + 32..offset + 65])
                    .map_err(|_| SessionStoreError::Quarantined)?,
                PublicKey::from_compressed_bytes(&bytes[offset + 65..offset + 98])
                    .map_err(|_| SessionStoreError::Quarantined)?,
                DirectionV1::try_from(bytes[offset + 98])
                    .map_err(|_| SessionStoreError::Quarantined)?,
            )
            .map_err(|_| SessionStoreError::Quarantined)?;
            if participant.participant_id() != &bytes[offset..offset + 32] {
                return Err(SessionStoreError::Quarantined);
            }
            Ok(participant)
        };
        let roster = ParticipantRosterV1::new(vec![parse_participant(0)?, parse_participant(1)?])
            .map_err(|_| SessionStoreError::Quarantined)?;
        let transaction_bytes = &bytes[SIGNING_BINDING_PREFIX_LEN..bytes.len() - DIGEST_LEN];
        let transaction_template = <Transaction as DomDeserialize>::from_bytes(transaction_bytes)
            .map_err(|_| SessionStoreError::Quarantined)?;
        let canonical_transaction = transaction_template
            .to_bytes()
            .map_err(|_| SessionStoreError::Quarantined)?;
        let (_, template_hash) = canonical_template_v1(&transaction_template)
            .map_err(|_| SessionStoreError::Quarantined)?;
        if canonical_transaction != transaction_bytes || template_hash != bytes[240..272] {
            return Err(SessionStoreError::Quarantined);
        }
        let adaptor_point = match bytes[11] {
            0 if bytes[272..305] == [0; 33] => None,
            1 => Some(
                PublicKey::from_compressed_bytes(&bytes[272..305])
                    .map_err(|_| SessionStoreError::Quarantined)?,
            ),
            _ => return Err(SessionStoreError::Quarantined),
        };
        Ok(DecodedSigningSessionBindingV1 {
            contract_kind,
            roster,
            transaction_template,
            template_hash,
            kernel_index: u32::from_le_bytes(copy_array(&bytes[232..236])?) as usize,
            adaptor_point,
            initial_transcript_hash: copy_array(&bytes[152..184])?,
            round_start_transcript_hash: copy_array(&bytes[184..216])?,
            sender_sequence_bases: [
                u64::from_le_bytes(copy_array(&bytes[216..224])?),
                u64::from_le_bytes(copy_array(&bytes[224..232])?),
            ],
            round_start_revision: u64::from_le_bytes(copy_array(&bytes[112..120])?),
            round_start_record_digest: copy_array(&bytes[120..152])?,
            template_commit_payload: copy_array(&bytes[312..472])?,
        })
    }
}

struct ParsedTransportEnvelopeV1 {
    chain_id: [u8; 32],
    session_id: [u8; 32],
    sender_id: [u8; 32],
    sequence: u64,
    previous_transcript_hash: [u8; 32],
    message_type: u8,
    signature: [u8; 65],
    message_digest: [u8; 32],
}

impl ParsedTransportEnvelopeV1 {
    fn parse(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        const FIXED: usize = 213;
        if bytes.len() < FIXED
            || bytes[..4] != *b"DSC1"
            || u16::from_le_bytes(copy_array(&bytes[4..6])?) != 1
            || !(1..=0x14).contains(&bytes[6])
            || bytes[7] != 0
        {
            return Err(SessionStoreError::Canonical);
        }
        let payload_len = u32::from_le_bytes(copy_array(&bytes[144..148])?) as usize;
        let unsigned_len = 148usize
            .checked_add(payload_len)
            .ok_or(SessionStoreError::Canonical)?;
        let total = unsigned_len
            .checked_add(65)
            .ok_or(SessionStoreError::Canonical)?;
        if total != bytes.len()
            || payload_len > 1024 * 1024
            || payload_len > transport_payload_cap(bytes[6]).ok_or(SessionStoreError::Canonical)?
        {
            return Err(SessionStoreError::Canonical);
        }
        let mut signature = [0; 65];
        signature.copy_from_slice(&bytes[unsigned_len..]);
        let chain_id = copy_array(&bytes[8..40])?;
        let session_id = copy_array(&bytes[40..72])?;
        let sender_id = copy_array(&bytes[72..104])?;
        if chain_id == [0; 32] || session_id == [0; 32] || sender_id == [0; 32] {
            return Err(SessionStoreError::Canonical);
        }
        Ok(Self {
            chain_id,
            session_id,
            sender_id,
            sequence: u64::from_le_bytes(copy_array(&bytes[104..112])?),
            previous_transcript_hash: copy_array(&bytes[112..144])?,
            message_type: bytes[6],
            signature,
            message_digest: tagged_hash(TRANSPORT_MESSAGE_DIGEST_TAG, &bytes[..unsigned_len]),
        })
    }

    fn verify(&self, key: &PublicKey) -> Result<(), SessionStoreError> {
        let signature = SchnorrSignature::from_bytes(&self.signature)
            .map_err(|_| SessionStoreError::Canonical)?;
        match schnorr_verify(&signature, key, &self.chain_id, &self.message_digest) {
            Ok(true) => Ok(()),
            _ => Err(SessionStoreError::Canonical),
        }
    }

    fn payload<'a>(&self, complete_bytes: &'a [u8]) -> Result<&'a [u8], SessionStoreError> {
        let payload_len = u32::from_le_bytes(copy_array(&complete_bytes[144..148])?) as usize;
        let end = 148usize
            .checked_add(payload_len)
            .ok_or(SessionStoreError::Canonical)?;
        complete_bytes
            .get(148..end)
            .ok_or(SessionStoreError::Canonical)
    }
}

struct TransportMessageRecordV1 {
    bytes: Vec<u8>,
    session_id: [u8; 32],
    sender_id: [u8; 32],
    sequence: u64,
    message_type: u8,
    message_digest: [u8; 32],
    direction: DirectionV1,
    signed_bytes: Vec<u8>,
    successor: SessionRecordV1,
    equivocation: bool,
}

impl TransportMessageRecordV1 {
    fn new(
        envelope: &ParsedTransportEnvelopeV1,
        signed_bytes: &[u8],
        successor: &SessionRecordV1,
        direction: DirectionV1,
        equivocation: bool,
    ) -> Result<Self, SessionStoreError> {
        let message_len =
            u32::try_from(signed_bytes.len()).map_err(|_| SessionStoreError::Canonical)?;
        let successor_len =
            u32::try_from(successor.as_bytes().len()).map_err(|_| SessionStoreError::Canonical)?;
        let total = TRANSPORT_MESSAGE_PREFIX_LEN
            .checked_add(signed_bytes.len())
            .and_then(|value| value.checked_add(successor.as_bytes().len()))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Canonical)?;
        if total > TRANSPORT_MESSAGE_MAX_LEN {
            return Err(SessionStoreError::Canonical);
        }
        let mut bytes = vec![0; total];
        bytes[..8].copy_from_slice(MESSAGE_RECORD_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[10] = u8::from(equivocation);
        bytes[11] = envelope.message_type;
        bytes[12] = direction.to_byte();
        bytes[16..48].copy_from_slice(&envelope.session_id);
        bytes[48..80].copy_from_slice(&envelope.sender_id);
        bytes[80..88].copy_from_slice(&envelope.sequence.to_le_bytes());
        bytes[88..120].copy_from_slice(&envelope.message_digest);
        bytes[120..152].copy_from_slice(successor.transcript_hash().as_slice());
        bytes[152..184].copy_from_slice(successor.digest());
        bytes[184..192].copy_from_slice(&successor.revision().to_le_bytes());
        bytes[192..196].copy_from_slice(&message_len.to_le_bytes());
        bytes[196..200].copy_from_slice(&successor_len.to_le_bytes());
        let message_end = TRANSPORT_MESSAGE_PREFIX_LEN + signed_bytes.len();
        bytes[TRANSPORT_MESSAGE_PREFIX_LEN..message_end].copy_from_slice(signed_bytes);
        bytes[message_end..total - DIGEST_LEN].copy_from_slice(successor.as_bytes());
        let digest = tagged_hash(MESSAGE_RECORD_HASH_TAG, &bytes[..total - DIGEST_LEN]);
        bytes[total - DIGEST_LEN..].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            session_id: envelope.session_id,
            sender_id: envelope.sender_id,
            sequence: envelope.sequence,
            message_type: envelope.message_type,
            message_digest: envelope.message_digest,
            direction,
            signed_bytes: signed_bytes.to_vec(),
            successor: successor.clone(),
            equivocation,
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < TRANSPORT_MESSAGE_PREFIX_LEN + DIGEST_LEN
            || bytes.len() > TRANSPORT_MESSAGE_MAX_LEN
            || &bytes[..8] != MESSAGE_RECORD_MAGIC
            || u16::from_le_bytes(copy_array(&bytes[8..10])?) != FORMAT_VERSION
            || bytes[10] > 1
            || !(1..=0x14).contains(&bytes[11])
            || bytes[13..16] != [0; 3]
            || bytes[200..208] != [0; 8]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let message_len = u32::from_le_bytes(copy_array(&bytes[192..196])?) as usize;
        let successor_len = u32::from_le_bytes(copy_array(&bytes[196..200])?) as usize;
        let total = TRANSPORT_MESSAGE_PREFIX_LEN
            .checked_add(message_len)
            .and_then(|value| value.checked_add(successor_len))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Quarantined)?;
        if total != bytes.len()
            || bytes[total - DIGEST_LEN..]
                != tagged_hash(MESSAGE_RECORD_HASH_TAG, &bytes[..total - DIGEST_LEN])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let message_end = TRANSPORT_MESSAGE_PREFIX_LEN + message_len;
        let signed_bytes = bytes[TRANSPORT_MESSAGE_PREFIX_LEN..message_end].to_vec();
        let envelope = ParsedTransportEnvelopeV1::parse(&signed_bytes)
            .map_err(|_| SessionStoreError::Quarantined)?;
        let successor = SessionRecordV1::from_bytes(&bytes[message_end..total - DIGEST_LEN])
            .map_err(|_| SessionStoreError::Quarantined)?;
        let session_id = copy_array(&bytes[16..48])?;
        let sender_id = copy_array(&bytes[48..80])?;
        let sequence = u64::from_le_bytes(copy_array(&bytes[80..88])?);
        let message_digest = copy_array(&bytes[88..120])?;
        let direction =
            DirectionV1::try_from(bytes[12]).map_err(|_| SessionStoreError::Quarantined)?;
        if envelope.session_id != session_id
            || envelope.sender_id != sender_id
            || envelope.sequence != sequence
            || envelope.message_type != bytes[11]
            || envelope.message_digest != message_digest
            || successor.session_id() != session_id
            || successor.transcript_hash() != bytes[120..152]
            || successor.digest() != &bytes[152..184]
            || successor.revision() != u64::from_le_bytes(copy_array(&bytes[184..192])?)
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            session_id,
            sender_id,
            sequence,
            message_type: bytes[11],
            message_digest,
            direction,
            signed_bytes,
            successor,
            equivocation: bytes[10] == 1,
        })
    }

    fn receipt(&self, duplicate: bool) -> DurableTransportReceiptV1 {
        DurableTransportReceiptV1 {
            message_digest: self.message_digest,
            transcript_hash: self.successor.transcript_hash(),
            sequence: self.sequence,
            message_type: self.message_type,
            duplicate,
        }
    }
}

impl OperationalFundingGateRecordV1 {
    fn new(evidence: VerifiedOperationalFundingGateEvidenceV1) -> Result<Self, SessionStoreError> {
        let refund_len = u32::try_from(evidence.refund_bytes.len())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let claim_len = u32::try_from(evidence.claim_pre_signature.len())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let claim_template_len = u32::try_from(evidence.claim_template_bytes.len())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let refund_template_len = u32::try_from(evidence.refund_template_bytes.len())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let statement_len = u32::try_from(evidence.bp_statement_bytes.len())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let total = FUNDING_GATE_PREFIX_LEN
            .checked_add(evidence.refund_bytes.len())
            .and_then(|value| value.checked_add(evidence.claim_pre_signature.len()))
            .and_then(|value| value.checked_add(evidence.claim_template_bytes.len()))
            .and_then(|value| value.checked_add(evidence.refund_template_bytes.len()))
            .and_then(|value| value.checked_add(evidence.bp_statement_bytes.len()))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::InvalidDomTransaction)?;
        if total > FUNDING_GATE_MAX_LEN {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
        let mut bytes = vec![0; total];
        bytes[..8].copy_from_slice(FUNDING_GATE_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[16..48].copy_from_slice(&evidence.session_id);
        bytes[48..80].copy_from_slice(&evidence.terms_hash);
        bytes[80..112].copy_from_slice(&evidence.chain_id);
        bytes[112..144].copy_from_slice(&evidence.claim_transcript_hash);
        bytes[144..176].copy_from_slice(&evidence.refund_tx_hash);
        bytes[176..208].copy_from_slice(&evidence.claim_pre_signature_hash);
        bytes[208..240].copy_from_slice(&evidence.backup_receipt_hash);
        bytes[240..248].copy_from_slice(&evidence.refund_unlock_height.to_le_bytes());
        bytes[248..256].copy_from_slice(&evidence.validation_height.to_le_bytes());
        bytes[256..264].copy_from_slice(&evidence.now_unix_seconds.to_le_bytes());
        bytes[264..268].copy_from_slice(&refund_len.to_le_bytes());
        bytes[268..272].copy_from_slice(&claim_len.to_le_bytes());
        bytes[272..304].copy_from_slice(&evidence.claim_template_hash);
        bytes[304..336].copy_from_slice(&evidence.refund_template_hash);
        bytes[336..368].copy_from_slice(&evidence.bp_statement_hash);
        bytes[368..401].copy_from_slice(&evidence.shared_output_commitment);
        bytes[401..405].copy_from_slice(&claim_template_len.to_le_bytes());
        bytes[405..409].copy_from_slice(&refund_template_len.to_le_bytes());
        bytes[409..413].copy_from_slice(&statement_len.to_le_bytes());
        let refund_end = FUNDING_GATE_PREFIX_LEN + evidence.refund_bytes.len();
        let claim_end = refund_end + evidence.claim_pre_signature.len();
        let claim_template_end = claim_end + evidence.claim_template_bytes.len();
        let refund_template_end = claim_template_end + evidence.refund_template_bytes.len();
        bytes[FUNDING_GATE_PREFIX_LEN..refund_end].copy_from_slice(&evidence.refund_bytes);
        bytes[refund_end..claim_end].copy_from_slice(&evidence.claim_pre_signature);
        bytes[claim_end..claim_template_end].copy_from_slice(&evidence.claim_template_bytes);
        bytes[claim_template_end..refund_template_end]
            .copy_from_slice(&evidence.refund_template_bytes);
        bytes[refund_template_end..total - DIGEST_LEN]
            .copy_from_slice(&evidence.bp_statement_bytes);
        let digest = tagged_hash(FUNDING_GATE_HASH_TAG, &bytes[..total - DIGEST_LEN]);
        bytes[total - DIGEST_LEN..].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            session_id: evidence.session_id,
            terms_hash: evidence.terms_hash,
            chain_id: evidence.chain_id,
            claim_transcript_hash: evidence.claim_transcript_hash,
            claim_template_hash: evidence.claim_template_hash,
            refund_template_hash: evidence.refund_template_hash,
            bp_statement_hash: evidence.bp_statement_hash,
            recovery_binding_hash: evidence.recovery_binding_hash,
            shared_output_commitment: evidence.shared_output_commitment,
            refund_tx_hash: evidence.refund_tx_hash,
            claim_pre_signature_hash: evidence.claim_pre_signature_hash,
            backup_receipt_hash: evidence.backup_receipt_hash,
            refund_unlock_height: evidence.refund_unlock_height,
            validation_height: evidence.validation_height,
            now_unix_seconds: evidence.now_unix_seconds,
            refund_bytes: evidence.refund_bytes,
            claim_pre_signature: evidence.claim_pre_signature,
            claim_template_bytes: evidence.claim_template_bytes,
            refund_template_bytes: evidence.refund_template_bytes,
            bp_statement_bytes: evidence.bp_statement_bytes,
            digest,
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < FUNDING_GATE_PREFIX_LEN + DIGEST_LEN
            || bytes.len() > FUNDING_GATE_MAX_LEN
            || &bytes[..8] != FUNDING_GATE_MAGIC
            || u16::from_le_bytes(copy_array(&bytes[8..10])?) != FORMAT_VERSION
            || bytes[10..16] != [0; 6]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let refund_len = u32::from_le_bytes(copy_array(&bytes[264..268])?) as usize;
        let claim_len = u32::from_le_bytes(copy_array(&bytes[268..272])?) as usize;
        let claim_template_len = u32::from_le_bytes(copy_array(&bytes[401..405])?) as usize;
        let refund_template_len = u32::from_le_bytes(copy_array(&bytes[405..409])?) as usize;
        let statement_len = u32::from_le_bytes(copy_array(&bytes[409..413])?) as usize;
        let total = FUNDING_GATE_PREFIX_LEN
            .checked_add(refund_len)
            .and_then(|value| value.checked_add(claim_len))
            .and_then(|value| value.checked_add(claim_template_len))
            .and_then(|value| value.checked_add(refund_template_len))
            .and_then(|value| value.checked_add(statement_len))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Quarantined)?;
        if total != bytes.len()
            || refund_len == 0
            || claim_len != 162
            || claim_template_len == 0
            || refund_template_len == 0
            || statement_len == 0
            || bytes[413..416] != [0; 3]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let digest = tagged_hash(FUNDING_GATE_HASH_TAG, &bytes[..total - DIGEST_LEN]);
        if bytes[total - DIGEST_LEN..] != digest {
            return Err(SessionStoreError::Quarantined);
        }
        let refund_end = FUNDING_GATE_PREFIX_LEN + refund_len;
        let claim_end = refund_end + claim_len;
        let claim_template_end = claim_end + claim_template_len;
        let refund_template_end = claim_template_end + refund_template_len;
        let refund_bytes = bytes[FUNDING_GATE_PREFIX_LEN..refund_end].to_vec();
        let claim_pre_signature = bytes[refund_end..claim_end].to_vec();
        let claim_template_bytes = bytes[claim_end..claim_template_end].to_vec();
        let refund_template_bytes = bytes[claim_template_end..refund_template_end].to_vec();
        let bp_statement_bytes = bytes[refund_template_end..total - DIGEST_LEN].to_vec();
        let session_id = copy_array(&bytes[16..48])?;
        let terms_hash = copy_array(&bytes[48..80])?;
        let chain_id = copy_array(&bytes[80..112])?;
        let claim_transcript_hash = copy_array(&bytes[112..144])?;
        let refund_tx_hash = copy_array(&bytes[144..176])?;
        let claim_pre_signature_hash = copy_array(&bytes[176..208])?;
        let backup_receipt_hash = copy_array(&bytes[208..240])?;
        let claim_template_hash = copy_array(&bytes[272..304])?;
        let refund_template_hash = copy_array(&bytes[304..336])?;
        let bp_statement_hash = copy_array(&bytes[336..368])?;
        let shared_output_commitment = copy_array(&bytes[368..401])?;
        let refund_unlock_height = u64::from_le_bytes(copy_array(&bytes[240..248])?);
        let validation_height = u64::from_le_bytes(copy_array(&bytes[248..256])?);
        let now_unix_seconds = u64::from_le_bytes(copy_array(&bytes[256..264])?);
        let statement_participants = bp_statement_bytes.get(70).copied().unwrap_or_default();
        let statement_aggregate_offset = 121usize
            .checked_add(65usize.saturating_mul(usize::from(statement_participants)))
            .ok_or(SessionStoreError::Quarantined)?;
        let statement_recovery_offset = statement_aggregate_offset
            .checked_add(33)
            .ok_or(SessionStoreError::Quarantined)?;
        let recovery_binding_hash = copy_array(
            bp_statement_bytes
                .get(statement_recovery_offset..statement_recovery_offset.saturating_add(32))
                .ok_or(SessionStoreError::Quarantined)?,
        )?;
        if [
            session_id,
            terms_hash,
            chain_id,
            claim_transcript_hash,
            refund_tx_hash,
            claim_pre_signature_hash,
            backup_receipt_hash,
        ]
        .contains(&[0; 32])
            || recovery_binding_hash == [0; 32]
            || *dom_crypto::blake2b_256(&refund_bytes).as_bytes() != refund_tx_hash
            || *dom_crypto::blake2b_256(&claim_pre_signature).as_bytes() != claim_pre_signature_hash
            || tagged_hash("DOM:scriptless-bp-statement:v1", &bp_statement_bytes)
                != bp_statement_hash
            || bp_statement_bytes.len() < 317
            || bp_statement_bytes[..4] != *b"DSBP"
            || bp_statement_bytes[6..38] != chain_id
            || bp_statement_bytes[38..70] != session_id
            || statement_participants != 2
            || bp_statement_bytes
                .get(statement_aggregate_offset..statement_aggregate_offset.saturating_add(33))
                != Some(shared_output_commitment.as_slice())
        {
            return Err(SessionStoreError::Quarantined);
        }
        let claim_template = parse_canonical_dom_template_v1(&claim_template_bytes)?;
        let refund_template = parse_canonical_dom_template_v1(&refund_template_bytes)?;
        if canonical_template_v1(&claim_template).map_err(|_| SessionStoreError::Quarantined)?
            != (claim_template_bytes.clone(), claim_template_hash)
            || canonical_template_v1(&refund_template)
                .map_err(|_| SessionStoreError::Quarantined)?
                != (refund_template_bytes.clone(), refund_template_hash)
        {
            return Err(SessionStoreError::Quarantined);
        }
        let refund = validate_exact_dom_transaction(
            &refund_bytes,
            DomTransactionValidationContextV1::new(
                refund_unlock_height,
                chain_id,
                now_unix_seconds,
            ),
        )
        .map_err(|_| SessionStoreError::Quarantined)?;
        let claim_kernel = claim_template
            .kernels
            .first()
            .ok_or(SessionStoreError::Quarantined)?;
        verify_claim_adaptor_pre_signature_v1(&ClaimAdaptorVerificationRequestV1 {
            pre_signature: &claim_pre_signature,
            claim_template_hash,
            transcript_hash: claim_transcript_hash,
            aggregate_signing_key: *claim_kernel.excess.as_bytes(),
            chain_id,
            kernel_message_digest: *scriptless_kernel_message_digest_v1(claim_kernel).as_bytes(),
        })
        .map_err(|_| SessionStoreError::Quarantined)?;
        if refund.kernels.is_empty()
            || refund.kernels.iter().any(|kernel| {
                kernel.features != KERNEL_FEAT_HEIGHT_LOCKED
                    || kernel.lock_height != refund_unlock_height
            })
            || claim_template.inputs.len() != 1
            || refund_template.inputs.len() != 1
            || claim_template.inputs[0].commitment.as_bytes() != &shared_output_commitment
            || refund_template.inputs[0].commitment.as_bytes() != &shared_output_commitment
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            session_id,
            terms_hash,
            chain_id,
            claim_transcript_hash,
            claim_template_hash,
            refund_template_hash,
            bp_statement_hash,
            recovery_binding_hash,
            shared_output_commitment,
            refund_tx_hash,
            claim_pre_signature_hash,
            backup_receipt_hash,
            refund_unlock_height,
            validation_height,
            now_unix_seconds,
            refund_bytes,
            claim_pre_signature,
            claim_template_bytes,
            refund_template_bytes,
            bp_statement_bytes,
            digest,
        })
    }
}

impl OperationalM8FundingGateRecordV1 {
    fn new(
        evidence: VerifiedOperationalM8FundingGateEvidenceV1,
    ) -> Result<Self, SessionStoreError> {
        let refund_len = u32::try_from(evidence.refund_bytes.len())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let claim_template_len = u32::try_from(evidence.claim_template_bytes.len())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let refund_template_len = u32::try_from(evidence.refund_template_bytes.len())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let statement_len = u32::try_from(evidence.bp_statement_bytes.len())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let total = M8_FUNDING_GATE_PREFIX_LEN
            .checked_add(evidence.refund_bytes.len())
            .and_then(|value| value.checked_add(evidence.claim_template_bytes.len()))
            .and_then(|value| value.checked_add(evidence.refund_template_bytes.len()))
            .and_then(|value| value.checked_add(evidence.bp_statement_bytes.len()))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::InvalidDomTransaction)?;
        if total > M8_FUNDING_GATE_MAX_LEN {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
        let mut bytes = vec![0; total];
        bytes[..8].copy_from_slice(M8_FUNDING_GATE_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[10] = 0x01; // M.8 two-phase funding profile.
        bytes[16..48].copy_from_slice(&evidence.session_id);
        bytes[48..80].copy_from_slice(&evidence.terms_hash);
        bytes[80..112].copy_from_slice(&evidence.m8_policy_digest);
        bytes[112..144].copy_from_slice(&evidence.chain_id);
        bytes[144..176].copy_from_slice(&evidence.claim_template_hash);
        bytes[176..209].copy_from_slice(&evidence.claim_adaptor_point.to_compressed_bytes());
        bytes[209..241].copy_from_slice(&evidence.refund_template_hash);
        bytes[241..273].copy_from_slice(&evidence.bp_statement_hash);
        bytes[273..305].copy_from_slice(&evidence.recovery_binding_hash);
        bytes[305..338].copy_from_slice(&evidence.shared_output_commitment);
        bytes[338..370].copy_from_slice(&evidence.refund_tx_hash);
        bytes[370..402].copy_from_slice(&evidence.backup_receipt_hash);
        bytes[402..410].copy_from_slice(&evidence.refund_unlock_height.to_le_bytes());
        bytes[410..418].copy_from_slice(&evidence.validation_height.to_le_bytes());
        bytes[418..426].copy_from_slice(&evidence.now_unix_seconds.to_le_bytes());
        bytes[426..430].copy_from_slice(&refund_len.to_le_bytes());
        bytes[430..434].copy_from_slice(&claim_template_len.to_le_bytes());
        bytes[434..438].copy_from_slice(&refund_template_len.to_le_bytes());
        bytes[438..442].copy_from_slice(&statement_len.to_le_bytes());
        let refund_end = M8_FUNDING_GATE_PREFIX_LEN + evidence.refund_bytes.len();
        let claim_template_end = refund_end + evidence.claim_template_bytes.len();
        let refund_template_end = claim_template_end + evidence.refund_template_bytes.len();
        bytes[M8_FUNDING_GATE_PREFIX_LEN..refund_end].copy_from_slice(&evidence.refund_bytes);
        bytes[refund_end..claim_template_end].copy_from_slice(&evidence.claim_template_bytes);
        bytes[claim_template_end..refund_template_end]
            .copy_from_slice(&evidence.refund_template_bytes);
        bytes[refund_template_end..total - DIGEST_LEN]
            .copy_from_slice(&evidence.bp_statement_bytes);
        let digest = tagged_hash(M8_FUNDING_GATE_HASH_TAG, &bytes[..total - DIGEST_LEN]);
        bytes[total - DIGEST_LEN..].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            session_id: evidence.session_id,
            terms_hash: evidence.terms_hash,
            m8_policy_digest: evidence.m8_policy_digest,
            chain_id: evidence.chain_id,
            claim_template_hash: evidence.claim_template_hash,
            claim_adaptor_point: evidence.claim_adaptor_point,
            refund_template_hash: evidence.refund_template_hash,
            bp_statement_hash: evidence.bp_statement_hash,
            recovery_binding_hash: evidence.recovery_binding_hash,
            shared_output_commitment: evidence.shared_output_commitment,
            refund_tx_hash: evidence.refund_tx_hash,
            backup_receipt_hash: evidence.backup_receipt_hash,
            refund_unlock_height: evidence.refund_unlock_height,
            validation_height: evidence.validation_height,
            now_unix_seconds: evidence.now_unix_seconds,
            refund_bytes: evidence.refund_bytes,
            claim_template_bytes: evidence.claim_template_bytes,
            refund_template_bytes: evidence.refund_template_bytes,
            bp_statement_bytes: evidence.bp_statement_bytes,
            digest,
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < M8_FUNDING_GATE_PREFIX_LEN + DIGEST_LEN
            || bytes.len() > M8_FUNDING_GATE_MAX_LEN
            || &bytes[..8] != M8_FUNDING_GATE_MAGIC
            || u16::from_le_bytes(copy_array(&bytes[8..10])?) != FORMAT_VERSION
            || bytes[10] != 0x01
            || bytes[11..16] != [0; 5]
            || bytes[442..448] != [0; 6]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let refund_len = u32::from_le_bytes(copy_array(&bytes[426..430])?) as usize;
        let claim_template_len = u32::from_le_bytes(copy_array(&bytes[430..434])?) as usize;
        let refund_template_len = u32::from_le_bytes(copy_array(&bytes[434..438])?) as usize;
        let statement_len = u32::from_le_bytes(copy_array(&bytes[438..442])?) as usize;
        let total = M8_FUNDING_GATE_PREFIX_LEN
            .checked_add(refund_len)
            .and_then(|value| value.checked_add(claim_template_len))
            .and_then(|value| value.checked_add(refund_template_len))
            .and_then(|value| value.checked_add(statement_len))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Quarantined)?;
        if total != bytes.len()
            || refund_len == 0
            || claim_template_len == 0
            || refund_template_len == 0
            || statement_len == 0
            || bytes[total - DIGEST_LEN..]
                != tagged_hash(M8_FUNDING_GATE_HASH_TAG, &bytes[..total - DIGEST_LEN])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let refund_end = M8_FUNDING_GATE_PREFIX_LEN + refund_len;
        let claim_template_end = refund_end + claim_template_len;
        let refund_template_end = claim_template_end + refund_template_len;
        let refund_bytes = bytes[M8_FUNDING_GATE_PREFIX_LEN..refund_end].to_vec();
        let claim_template_bytes = bytes[refund_end..claim_template_end].to_vec();
        let refund_template_bytes = bytes[claim_template_end..refund_template_end].to_vec();
        let bp_statement_bytes = bytes[refund_template_end..total - DIGEST_LEN].to_vec();
        let session_id = copy_array(&bytes[16..48])?;
        let terms_hash = copy_array(&bytes[48..80])?;
        let m8_policy_digest = copy_array(&bytes[80..112])?;
        let chain_id = copy_array(&bytes[112..144])?;
        let claim_template_hash = copy_array(&bytes[144..176])?;
        let claim_adaptor_point = PublicKey::from_compressed_bytes(&bytes[176..209])
            .map_err(|_| SessionStoreError::Quarantined)?;
        let refund_template_hash = copy_array(&bytes[209..241])?;
        let bp_statement_hash = copy_array(&bytes[241..273])?;
        let recovery_binding_hash = copy_array(&bytes[273..305])?;
        let shared_output_commitment = copy_array(&bytes[305..338])?;
        let refund_tx_hash = copy_array(&bytes[338..370])?;
        let backup_receipt_hash = copy_array(&bytes[370..402])?;
        let refund_unlock_height = u64::from_le_bytes(copy_array(&bytes[402..410])?);
        let validation_height = u64::from_le_bytes(copy_array(&bytes[410..418])?);
        let now_unix_seconds = u64::from_le_bytes(copy_array(&bytes[418..426])?);
        if [
            session_id,
            terms_hash,
            m8_policy_digest,
            chain_id,
            claim_template_hash,
            refund_template_hash,
            bp_statement_hash,
            recovery_binding_hash,
            refund_tx_hash,
            backup_receipt_hash,
        ]
        .contains(&[0; 32])
            || shared_output_commitment == [0; 33]
            || refund_unlock_height == 0
            || *dom_crypto::blake2b_256(&refund_bytes).as_bytes() != refund_tx_hash
            || tagged_hash("DOM:scriptless-bp-statement:v1", &bp_statement_bytes)
                != bp_statement_hash
        {
            return Err(SessionStoreError::Quarantined);
        }
        let statement_participants = bp_statement_bytes.get(70).copied().unwrap_or_default();
        let statement_aggregate_offset = 121usize
            .checked_add(65usize.saturating_mul(usize::from(statement_participants)))
            .ok_or(SessionStoreError::Quarantined)?;
        let statement_recovery_offset = statement_aggregate_offset
            .checked_add(33)
            .ok_or(SessionStoreError::Quarantined)?;
        if bp_statement_bytes.len() < 317
            || bp_statement_bytes[..4] != *b"DSBP"
            || bp_statement_bytes[6..38] != chain_id
            || bp_statement_bytes[38..70] != session_id
            || statement_participants != 2
            || bp_statement_bytes
                .get(statement_aggregate_offset..statement_aggregate_offset.saturating_add(33))
                != Some(shared_output_commitment.as_slice())
            || bp_statement_bytes
                .get(statement_recovery_offset..statement_recovery_offset.saturating_add(32))
                != Some(recovery_binding_hash.as_slice())
        {
            return Err(SessionStoreError::Quarantined);
        }
        let claim_template = parse_canonical_dom_template_v1(&claim_template_bytes)?;
        let refund_template = parse_canonical_dom_template_v1(&refund_template_bytes)?;
        if canonical_template_v1(&claim_template).map_err(|_| SessionStoreError::Quarantined)?
            != (claim_template_bytes.clone(), claim_template_hash)
            || canonical_template_v1(&refund_template)
                .map_err(|_| SessionStoreError::Quarantined)?
                != (refund_template_bytes.clone(), refund_template_hash)
            || claim_template.kernels.len() != 1
            || claim_template.inputs.len() != 1
            || refund_template.inputs.len() != 1
            || claim_template.inputs[0].commitment.as_bytes() != &shared_output_commitment
            || refund_template.inputs[0].commitment.as_bytes() != &shared_output_commitment
        {
            return Err(SessionStoreError::Quarantined);
        }
        let refund = validate_exact_dom_transaction(
            &refund_bytes,
            DomTransactionValidationContextV1::new(
                refund_unlock_height,
                chain_id,
                now_unix_seconds,
            ),
        )
        .map_err(|_| SessionStoreError::Quarantined)?;
        if refund.kernels.is_empty()
            || refund.kernels.iter().any(|kernel| {
                kernel.features != KERNEL_FEAT_HEIGHT_LOCKED
                    || kernel.lock_height != refund_unlock_height
            })
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            session_id,
            terms_hash,
            m8_policy_digest,
            chain_id,
            claim_template_hash,
            claim_adaptor_point,
            refund_template_hash,
            bp_statement_hash,
            recovery_binding_hash,
            shared_output_commitment,
            refund_tx_hash,
            backup_receipt_hash,
            refund_unlock_height,
            validation_height,
            now_unix_seconds,
            refund_bytes,
            claim_template_bytes,
            refund_template_bytes,
            bp_statement_bytes,
            digest: copy_array(&bytes[total - DIGEST_LEN..])?,
        })
    }
}

impl OperationalFundingIssuanceRecordV1 {
    fn new(
        binding: OperationalFundingAuthorizationBindingV1,
        authorized_revision: u64,
        gate_digest: [u8; 32],
        unsigned_template_bytes: &[u8],
        funding_authorized_record: &SessionRecordV1,
    ) -> Result<Self, SessionStoreError> {
        let template_len = u32::try_from(unsigned_template_bytes.len())
            .map_err(|_| SessionStoreError::Canonical)?;
        let successor_len = u32::try_from(funding_authorized_record.as_bytes().len())
            .map_err(|_| SessionStoreError::Canonical)?;
        let total = FUNDING_ISSUANCE_PREFIX_LEN
            .checked_add(unsigned_template_bytes.len())
            .and_then(|value| value.checked_add(funding_authorized_record.as_bytes().len()))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Canonical)?;
        if total > FUNDING_ISSUANCE_MAX_LEN
            || binding.session_id() != &funding_authorized_record.session_id()
            || authorized_revision != funding_authorized_record.revision()
            || gate_digest == [0; 32]
        {
            return Err(SessionStoreError::Canonical);
        }
        let mut bytes = vec![0; total];
        bytes[..8].copy_from_slice(FUNDING_ISSUANCE_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[16..379].copy_from_slice(&binding.to_bytes());
        bytes[379..387].copy_from_slice(&authorized_revision.to_le_bytes());
        bytes[387..419].copy_from_slice(&gate_digest);
        bytes[419..423].copy_from_slice(&template_len.to_le_bytes());
        bytes[423..427].copy_from_slice(&successor_len.to_le_bytes());
        bytes[432..464].copy_from_slice(funding_authorized_record.digest());
        let template_end = FUNDING_ISSUANCE_PREFIX_LEN + unsigned_template_bytes.len();
        bytes[FUNDING_ISSUANCE_PREFIX_LEN..template_end].copy_from_slice(unsigned_template_bytes);
        bytes[template_end..total - DIGEST_LEN]
            .copy_from_slice(funding_authorized_record.as_bytes());
        let digest = tagged_hash(FUNDING_ISSUANCE_HASH_TAG, &bytes[..total - DIGEST_LEN]);
        bytes[total - DIGEST_LEN..].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            binding,
            authorized_revision,
            gate_digest,
            unsigned_template_bytes: unsigned_template_bytes.to_vec(),
            funding_authorized_record: funding_authorized_record.clone(),
            digest,
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < FUNDING_ISSUANCE_PREFIX_LEN + DIGEST_LEN
            || bytes.len() > FUNDING_ISSUANCE_MAX_LEN
            || &bytes[..8] != FUNDING_ISSUANCE_MAGIC
            || u16::from_le_bytes(copy_array(&bytes[8..10])?) != FORMAT_VERSION
            || bytes[10..16] != [0; 6]
            || bytes[427..432] != [0; 5]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let template_len = u32::from_le_bytes(copy_array(&bytes[419..423])?) as usize;
        let successor_len = u32::from_le_bytes(copy_array(&bytes[423..427])?) as usize;
        let total = FUNDING_ISSUANCE_PREFIX_LEN
            .checked_add(template_len)
            .and_then(|value| value.checked_add(successor_len))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Quarantined)?;
        if total != bytes.len()
            || template_len == 0
            || successor_len == 0
            || bytes[total - DIGEST_LEN..]
                != tagged_hash(FUNDING_ISSUANCE_HASH_TAG, &bytes[..total - DIGEST_LEN])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let binding = OperationalFundingAuthorizationBindingV1::new(
            copy_array(&bytes[26..58])?,
            copy_array(&bytes[58..90])?,
            copy_array(&bytes[90..122])?,
            copy_array(&bytes[122..154])?,
            copy_array(&bytes[154..187])?,
            copy_array(&bytes[187..219])?,
            copy_array(&bytes[219..251])?,
            copy_array(&bytes[251..283])?,
            copy_array(&bytes[283..315])?,
            copy_array(&bytes[315..347])?,
            copy_array(&bytes[347..379])?,
        )
        .map_err(|_| SessionStoreError::Quarantined)?;
        if binding.to_bytes() != bytes[16..379] {
            return Err(SessionStoreError::Quarantined);
        }
        let template_end = FUNDING_ISSUANCE_PREFIX_LEN + template_len;
        let funding_authorized_record =
            SessionRecordV1::from_bytes(&bytes[template_end..total - DIGEST_LEN])
                .map_err(|_| SessionStoreError::Quarantined)?;
        let authorized_revision = u64::from_le_bytes(copy_array(&bytes[379..387])?);
        if funding_authorized_record.session_id() != *binding.session_id()
            || funding_authorized_record.revision() != authorized_revision
            || funding_authorized_record.digest() != &bytes[432..464]
            || funding_authorized_record.phase() != SessionPhaseV1::FundingAuthorized
            || !funding_authorized_record.irreversible().funding_authorized
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            binding,
            authorized_revision,
            gate_digest: copy_array(&bytes[387..419])?,
            unsigned_template_bytes: bytes[FUNDING_ISSUANCE_PREFIX_LEN..template_end].to_vec(),
            funding_authorized_record,
            digest: copy_array(&bytes[total - DIGEST_LEN..])?,
        })
    }
}

impl OperationalM8FundingIssuanceRecordV1 {
    fn new(
        binding: OperationalM8FundingAuthorizationBindingV1,
        authorized_revision: u64,
        gate_digest: [u8; 32],
        unsigned_template_bytes: &[u8],
        funding_authorized_record: &SessionRecordV1,
    ) -> Result<Self, SessionStoreError> {
        let template_len = u32::try_from(unsigned_template_bytes.len())
            .map_err(|_| SessionStoreError::Canonical)?;
        let successor_len = u32::try_from(funding_authorized_record.as_bytes().len())
            .map_err(|_| SessionStoreError::Canonical)?;
        let total = M8_FUNDING_ISSUANCE_PREFIX_LEN
            .checked_add(unsigned_template_bytes.len())
            .and_then(|value| value.checked_add(funding_authorized_record.as_bytes().len()))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Canonical)?;
        if total > M8_FUNDING_ISSUANCE_MAX_LEN
            || binding.session_id() != &funding_authorized_record.session_id()
            || authorized_revision != funding_authorized_record.revision()
            || gate_digest == [0; 32]
            || unsigned_template_bytes.is_empty()
        {
            return Err(SessionStoreError::Canonical);
        }
        let mut bytes = vec![0; total];
        bytes[..8].copy_from_slice(M8_FUNDING_ISSUANCE_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[10] = 0x02;
        bytes[16..416].copy_from_slice(&binding.to_bytes());
        bytes[416..424].copy_from_slice(&authorized_revision.to_le_bytes());
        bytes[424..456].copy_from_slice(&gate_digest);
        bytes[456..460].copy_from_slice(&template_len.to_le_bytes());
        bytes[460..464].copy_from_slice(&successor_len.to_le_bytes());
        bytes[472..504].copy_from_slice(funding_authorized_record.digest());
        let template_end = M8_FUNDING_ISSUANCE_PREFIX_LEN + unsigned_template_bytes.len();
        bytes[M8_FUNDING_ISSUANCE_PREFIX_LEN..template_end]
            .copy_from_slice(unsigned_template_bytes);
        bytes[template_end..total - DIGEST_LEN]
            .copy_from_slice(funding_authorized_record.as_bytes());
        let digest = tagged_hash(M8_FUNDING_ISSUANCE_HASH_TAG, &bytes[..total - DIGEST_LEN]);
        bytes[total - DIGEST_LEN..].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            binding,
            authorized_revision,
            gate_digest,
            unsigned_template_bytes: unsigned_template_bytes.to_vec(),
            funding_authorized_record: funding_authorized_record.clone(),
            digest,
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < M8_FUNDING_ISSUANCE_PREFIX_LEN + DIGEST_LEN
            || bytes.len() > M8_FUNDING_ISSUANCE_MAX_LEN
            || &bytes[..8] != M8_FUNDING_ISSUANCE_MAGIC
            || u16::from_le_bytes(copy_array(&bytes[8..10])?) != FORMAT_VERSION
            || bytes[10] != 0x02
            || bytes[11..16] != [0; 5]
            || bytes[464..472] != [0; 8]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let template_len = u32::from_le_bytes(copy_array(&bytes[456..460])?) as usize;
        let successor_len = u32::from_le_bytes(copy_array(&bytes[460..464])?) as usize;
        let total = M8_FUNDING_ISSUANCE_PREFIX_LEN
            .checked_add(template_len)
            .and_then(|value| value.checked_add(successor_len))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Quarantined)?;
        if total != bytes.len()
            || template_len == 0
            || successor_len == 0
            || bytes[total - DIGEST_LEN..]
                != tagged_hash(M8_FUNDING_ISSUANCE_HASH_TAG, &bytes[..total - DIGEST_LEN])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let binding = OperationalM8FundingAuthorizationBindingV1::new(
            copy_array(&bytes[30..62])?,
            copy_array(&bytes[62..94])?,
            copy_array(&bytes[94..126])?,
            copy_array(&bytes[126..158])?,
            copy_array(&bytes[158..191])?,
            copy_array(&bytes[191..223])?,
            copy_array(&bytes[223..255])?,
            copy_array(&bytes[255..287])?,
            copy_array(&bytes[287..320])?,
            copy_array(&bytes[320..352])?,
            copy_array(&bytes[352..384])?,
            copy_array(&bytes[384..416])?,
        )
        .map_err(|_| SessionStoreError::Quarantined)?;
        if binding.to_bytes() != bytes[16..416] {
            return Err(SessionStoreError::Quarantined);
        }
        let template_end = M8_FUNDING_ISSUANCE_PREFIX_LEN + template_len;
        let funding_authorized_record =
            SessionRecordV1::from_bytes(&bytes[template_end..total - DIGEST_LEN])
                .map_err(|_| SessionStoreError::Quarantined)?;
        let authorized_revision = u64::from_le_bytes(copy_array(&bytes[416..424])?);
        if funding_authorized_record.session_id() != *binding.session_id()
            || funding_authorized_record.revision() != authorized_revision
            || funding_authorized_record.digest() != &bytes[472..504]
            || funding_authorized_record.phase() != SessionPhaseV1::FundingAuthorized
            || !funding_authorized_record.irreversible().funding_authorized
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            binding,
            authorized_revision,
            gate_digest: copy_array(&bytes[424..456])?,
            unsigned_template_bytes: bytes[M8_FUNDING_ISSUANCE_PREFIX_LEN..template_end].to_vec(),
            funding_authorized_record,
            digest: copy_array(&bytes[total - DIGEST_LEN..])?,
        })
    }
}

impl OperationalFundingCommitRecordV1 {
    fn new(
        artifact: FundingArtifactRecordV1,
        consumption: FundingConsumptionRecordV1,
    ) -> Result<Self, SessionStoreError> {
        if artifact.session_id != consumption.session_id
            || artifact.authorized_revision != consumption.authorized_revision
            || artifact.digest != consumption.artifact_digest
        {
            return Err(SessionStoreError::Canonical);
        }
        let artifact_len =
            u32::try_from(artifact.bytes.len()).map_err(|_| SessionStoreError::Canonical)?;
        let consumption_len =
            u32::try_from(consumption.bytes.len()).map_err(|_| SessionStoreError::Canonical)?;
        let total = FUNDING_COMMIT_PREFIX_LEN
            .checked_add(artifact.bytes.len())
            .and_then(|value| value.checked_add(consumption.bytes.len()))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Canonical)?;
        if total > FUNDING_COMMIT_MAX_LEN {
            return Err(SessionStoreError::Canonical);
        }
        let mut bytes = vec![0; total];
        bytes[..8].copy_from_slice(FUNDING_COMMIT_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[16..48].copy_from_slice(&artifact.session_id);
        bytes[48..52].copy_from_slice(&artifact_len.to_le_bytes());
        bytes[52..56].copy_from_slice(&consumption_len.to_le_bytes());
        bytes[56..88].copy_from_slice(&artifact.digest);
        bytes[88..120].copy_from_slice(&consumption.bytes[consumption.bytes.len() - DIGEST_LEN..]);
        let artifact_end = FUNDING_COMMIT_PREFIX_LEN + artifact.bytes.len();
        bytes[FUNDING_COMMIT_PREFIX_LEN..artifact_end].copy_from_slice(&artifact.bytes);
        bytes[artifact_end..total - DIGEST_LEN].copy_from_slice(&consumption.bytes);
        let digest = tagged_hash(FUNDING_COMMIT_HASH_TAG, &bytes[..total - DIGEST_LEN]);
        bytes[total - DIGEST_LEN..].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            session_id: artifact.session_id,
            artifact,
            consumption,
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < FUNDING_COMMIT_PREFIX_LEN + DIGEST_LEN
            || bytes.len() > FUNDING_COMMIT_MAX_LEN
            || &bytes[..8] != FUNDING_COMMIT_MAGIC
            || u16::from_le_bytes(copy_array(&bytes[8..10])?) != FORMAT_VERSION
            || bytes[10..16] != [0; 6]
            || bytes[120..128] != [0; 8]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let artifact_len = u32::from_le_bytes(copy_array(&bytes[48..52])?) as usize;
        let consumption_len = u32::from_le_bytes(copy_array(&bytes[52..56])?) as usize;
        let total = FUNDING_COMMIT_PREFIX_LEN
            .checked_add(artifact_len)
            .and_then(|value| value.checked_add(consumption_len))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Quarantined)?;
        if total != bytes.len()
            || bytes[total - DIGEST_LEN..]
                != tagged_hash(FUNDING_COMMIT_HASH_TAG, &bytes[..total - DIGEST_LEN])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let artifact_end = FUNDING_COMMIT_PREFIX_LEN + artifact_len;
        let artifact =
            FundingArtifactRecordV1::from_bytes(&bytes[FUNDING_COMMIT_PREFIX_LEN..artifact_end])?;
        let consumption =
            FundingConsumptionRecordV1::from_bytes(&bytes[artifact_end..total - DIGEST_LEN])?;
        let session_id = copy_array(&bytes[16..48])?;
        if artifact.session_id != session_id
            || consumption.session_id != session_id
            || artifact.digest != bytes[56..88]
            || consumption.bytes[consumption.bytes.len() - DIGEST_LEN..] != bytes[88..120]
            || artifact.digest != consumption.artifact_digest
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            session_id,
            artifact,
            consumption,
        })
    }
}

impl OperationalM8FundingCommitRecordV1 {
    fn new(
        issuance_record_digest: [u8; 32],
        artifact: FundingArtifactRecordV1,
        consumption: FundingConsumptionRecordV1,
    ) -> Result<Self, SessionStoreError> {
        if issuance_record_digest == [0; 32]
            || artifact.session_id != consumption.session_id
            || artifact.authorized_revision != consumption.authorized_revision
            || artifact.digest != consumption.artifact_digest
        {
            return Err(SessionStoreError::Canonical);
        }
        let artifact_len =
            u32::try_from(artifact.bytes.len()).map_err(|_| SessionStoreError::Canonical)?;
        let consumption_len =
            u32::try_from(consumption.bytes.len()).map_err(|_| SessionStoreError::Canonical)?;
        let total = M8_FUNDING_COMMIT_PREFIX_LEN
            .checked_add(artifact.bytes.len())
            .and_then(|value| value.checked_add(consumption.bytes.len()))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Canonical)?;
        if total > M8_FUNDING_COMMIT_MAX_LEN {
            return Err(SessionStoreError::Canonical);
        }
        let mut bytes = vec![0; total];
        bytes[..8].copy_from_slice(M8_FUNDING_COMMIT_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[10] = 0x02;
        bytes[16..48].copy_from_slice(&artifact.session_id);
        bytes[48..80].copy_from_slice(&issuance_record_digest);
        bytes[80..84].copy_from_slice(&artifact_len.to_le_bytes());
        bytes[84..88].copy_from_slice(&consumption_len.to_le_bytes());
        bytes[88..120].copy_from_slice(&artifact.digest);
        bytes[120..152].copy_from_slice(&consumption.bytes[consumption.bytes.len() - DIGEST_LEN..]);
        let artifact_end = M8_FUNDING_COMMIT_PREFIX_LEN + artifact.bytes.len();
        bytes[M8_FUNDING_COMMIT_PREFIX_LEN..artifact_end].copy_from_slice(&artifact.bytes);
        bytes[artifact_end..total - DIGEST_LEN].copy_from_slice(&consumption.bytes);
        let digest = tagged_hash(M8_FUNDING_COMMIT_HASH_TAG, &bytes[..total - DIGEST_LEN]);
        bytes[total - DIGEST_LEN..].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            session_id: artifact.session_id,
            issuance_record_digest,
            artifact,
            consumption,
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < M8_FUNDING_COMMIT_PREFIX_LEN + DIGEST_LEN
            || bytes.len() > M8_FUNDING_COMMIT_MAX_LEN
            || &bytes[..8] != M8_FUNDING_COMMIT_MAGIC
            || u16::from_le_bytes(copy_array(&bytes[8..10])?) != FORMAT_VERSION
            || bytes[10] != 0x02
            || bytes[11..16] != [0; 5]
            || bytes[152..160] != [0; 8]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let artifact_len = u32::from_le_bytes(copy_array(&bytes[80..84])?) as usize;
        let consumption_len = u32::from_le_bytes(copy_array(&bytes[84..88])?) as usize;
        let total = M8_FUNDING_COMMIT_PREFIX_LEN
            .checked_add(artifact_len)
            .and_then(|value| value.checked_add(consumption_len))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Quarantined)?;
        if total != bytes.len()
            || artifact_len == 0
            || consumption_len == 0
            || bytes[total - DIGEST_LEN..]
                != tagged_hash(M8_FUNDING_COMMIT_HASH_TAG, &bytes[..total - DIGEST_LEN])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let artifact_end = M8_FUNDING_COMMIT_PREFIX_LEN + artifact_len;
        let artifact = FundingArtifactRecordV1::from_bytes(
            &bytes[M8_FUNDING_COMMIT_PREFIX_LEN..artifact_end],
        )?;
        let consumption =
            FundingConsumptionRecordV1::from_bytes(&bytes[artifact_end..total - DIGEST_LEN])?;
        let session_id = copy_array(&bytes[16..48])?;
        let issuance_record_digest = copy_array(&bytes[48..80])?;
        if issuance_record_digest == [0; 32]
            || artifact.session_id != session_id
            || consumption.session_id != session_id
            || artifact.digest != bytes[88..120]
            || consumption.bytes[consumption.bytes.len() - DIGEST_LEN..] != bytes[120..152]
            || artifact.digest != consumption.artifact_digest
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            session_id,
            issuance_record_digest,
            artifact,
            consumption,
        })
    }
}

impl FundingArtifactRecordV1 {
    fn new_operational_m8(
        gate: &OperationalM8FundingGateRecordV1,
        authorized_revision: u64,
        funding_bytes: &[u8],
    ) -> Result<Self, SessionStoreError> {
        Self::new_operational_fields(
            gate.session_id,
            gate.terms_hash,
            authorized_revision,
            gate.refund_unlock_height,
            &gate.refund_bytes,
            funding_bytes,
        )
    }

    fn new_operational(
        gate: &OperationalFundingGateRecordV1,
        authorized_revision: u64,
        funding_bytes: &[u8],
    ) -> Result<Self, SessionStoreError> {
        Self::new_operational_fields(
            gate.session_id,
            gate.terms_hash,
            authorized_revision,
            gate.refund_unlock_height,
            &gate.refund_bytes,
            funding_bytes,
        )
    }

    fn new_operational_fields(
        session_id: [u8; 32],
        terms_hash: [u8; 32],
        authorized_revision: u64,
        refund_unlock_height: u64,
        refund_bytes: &[u8],
        funding_bytes: &[u8],
    ) -> Result<Self, SessionStoreError> {
        if funding_bytes.is_empty() || funding_bytes.len() > DOM_TRANSACTION_MAX_LEN {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
        let refund_len = u32::try_from(refund_bytes.len())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let funding_len = u32::try_from(funding_bytes.len())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let total = ARTIFACT_PREFIX_LEN
            .checked_add(refund_bytes.len())
            .and_then(|value| value.checked_add(funding_bytes.len()))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::InvalidDomTransaction)?;
        if total > FUNDING_ARTIFACT_MAX_LEN {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
        let funding_digest = tagged_hash(FUNDING_HASH_TAG, funding_bytes);
        let refund_digest = tagged_hash(REFUND_HASH_TAG, refund_bytes);
        let mut bytes = vec![0; total];
        bytes[..8].copy_from_slice(ARTIFACT_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[16..48].copy_from_slice(&session_id);
        bytes[48..80].copy_from_slice(&terms_hash);
        bytes[80..88].copy_from_slice(&authorized_revision.to_le_bytes());
        bytes[88..96].copy_from_slice(&refund_unlock_height.to_le_bytes());
        bytes[96..100].copy_from_slice(&refund_len.to_le_bytes());
        bytes[100..104].copy_from_slice(&funding_len.to_le_bytes());
        bytes[104..136].copy_from_slice(&refund_digest);
        bytes[136..168].copy_from_slice(&funding_digest);
        let refund_end = ARTIFACT_PREFIX_LEN + refund_bytes.len();
        bytes[ARTIFACT_PREFIX_LEN..refund_end].copy_from_slice(refund_bytes);
        bytes[refund_end..total - DIGEST_LEN].copy_from_slice(funding_bytes);
        let digest = tagged_hash(ARTIFACT_HASH_TAG, &bytes[..total - DIGEST_LEN]);
        bytes[total - DIGEST_LEN..].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            session_id,
            terms_hash,
            authorized_revision,
            refund_unlock_height,
            refund_bytes: refund_bytes.to_vec(),
            funding_bytes: funding_bytes.to_vec(),
            digest,
        })
    }

    fn new(
        session_id: [u8; 32],
        terms_hash: [u8; 32],
        authorized_revision: u64,
        verified: VerifiedFundingArtifactsV1,
    ) -> Result<Self, SessionStoreError> {
        let refund_len = u32::try_from(verified.refund_bytes.len())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let funding_len = u32::try_from(verified.funding_bytes.len())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let payload_len = verified
            .refund_bytes
            .len()
            .checked_add(verified.funding_bytes.len())
            .ok_or(SessionStoreError::InvalidDomTransaction)?;
        let total = ARTIFACT_PREFIX_LEN
            .checked_add(payload_len)
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::InvalidDomTransaction)?;
        if total > FUNDING_ARTIFACT_MAX_LEN
            || verified.session_id != session_id
            || verified.terms_hash != terms_hash
        {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
        let mut bytes = vec![0; total];
        bytes[..8].copy_from_slice(ARTIFACT_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[16..48].copy_from_slice(&session_id);
        bytes[48..80].copy_from_slice(&terms_hash);
        bytes[80..88].copy_from_slice(&authorized_revision.to_le_bytes());
        bytes[88..96].copy_from_slice(&verified.refund_unlock_height.to_le_bytes());
        bytes[96..100].copy_from_slice(&refund_len.to_le_bytes());
        bytes[100..104].copy_from_slice(&funding_len.to_le_bytes());
        bytes[104..136].copy_from_slice(&verified.refund_digest);
        bytes[136..168].copy_from_slice(&verified.funding_digest);
        let refund_end = ARTIFACT_PREFIX_LEN + verified.refund_bytes.len();
        bytes[ARTIFACT_PREFIX_LEN..refund_end].copy_from_slice(&verified.refund_bytes);
        bytes[refund_end..total - DIGEST_LEN].copy_from_slice(&verified.funding_bytes);
        let digest = tagged_hash(ARTIFACT_HASH_TAG, &bytes[..total - DIGEST_LEN]);
        bytes[total - DIGEST_LEN..].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            session_id,
            terms_hash,
            authorized_revision,
            refund_unlock_height: verified.refund_unlock_height,
            refund_bytes: verified.refund_bytes,
            funding_bytes: verified.funding_bytes,
            digest,
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < ARTIFACT_PREFIX_LEN + DIGEST_LEN
            || bytes.len() > FUNDING_ARTIFACT_MAX_LEN
            || &bytes[..8] != ARTIFACT_MAGIC
            || u16::from_le_bytes([bytes[8], bytes[9]]) != FORMAT_VERSION
            || bytes[10..16] != [0; 6]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let refund_len = u32::from_le_bytes(copy_array(&bytes[96..100])?) as usize;
        let funding_len = u32::from_le_bytes(copy_array(&bytes[100..104])?) as usize;
        let refund_unlock_height = u64::from_le_bytes(copy_array(&bytes[88..96])?);
        let total = ARTIFACT_PREFIX_LEN
            .checked_add(refund_len)
            .and_then(|value| value.checked_add(funding_len))
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Quarantined)?;
        if total != bytes.len() || refund_len == 0 || funding_len == 0 || refund_unlock_height == 0
        {
            return Err(SessionStoreError::Quarantined);
        }
        let digest = tagged_hash(ARTIFACT_HASH_TAG, &bytes[..total - DIGEST_LEN]);
        if bytes[total - DIGEST_LEN..] != digest {
            return Err(SessionStoreError::Quarantined);
        }
        let refund_end = ARTIFACT_PREFIX_LEN + refund_len;
        if tagged_hash(REFUND_HASH_TAG, &bytes[ARTIFACT_PREFIX_LEN..refund_end]) != bytes[104..136]
            || tagged_hash(FUNDING_HASH_TAG, &bytes[refund_end..total - DIGEST_LEN])
                != bytes[136..168]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let session_id = copy_array(&bytes[16..48])?;
        let terms_hash = copy_array(&bytes[48..80])?;
        if session_id == [0; 32] || terms_hash == [0; 32] {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            session_id,
            terms_hash,
            authorized_revision: u64::from_le_bytes(copy_array(&bytes[80..88])?),
            refund_unlock_height,
            refund_bytes: bytes[ARTIFACT_PREFIX_LEN..refund_end].to_vec(),
            funding_bytes: bytes[refund_end..total - DIGEST_LEN].to_vec(),
            digest,
        })
    }
}

struct FundingConsumptionRecordV1 {
    bytes: Vec<u8>,
    session_id: [u8; 32],
    authorized_revision: u64,
    artifact_digest: [u8; 32],
    broadcast_record_digest: [u8; 32],
}

impl FundingConsumptionRecordV1 {
    fn new(
        session_id: [u8; 32],
        authorized_revision: u64,
        artifact_digest: [u8; 32],
        broadcast_record: &SessionRecordV1,
    ) -> Result<Self, SessionStoreError> {
        let successor_len = u32::try_from(broadcast_record.as_bytes().len())
            .map_err(|_| SessionStoreError::Canonical)?;
        let total = CONSUMPTION_PREFIX_LEN
            .checked_add(broadcast_record.as_bytes().len())
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Canonical)?;
        if total > CONSUMPTION_MAX_LEN {
            return Err(SessionStoreError::Canonical);
        }
        let mut bytes = vec![0; total];
        bytes[..8].copy_from_slice(CONSUMPTION_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[16..48].copy_from_slice(&session_id);
        bytes[48..56].copy_from_slice(&authorized_revision.to_le_bytes());
        bytes[56..88].copy_from_slice(&artifact_digest);
        bytes[88..120].copy_from_slice(broadcast_record.digest());
        bytes[120..124].copy_from_slice(&successor_len.to_le_bytes());
        bytes[CONSUMPTION_PREFIX_LEN..total - DIGEST_LEN]
            .copy_from_slice(broadcast_record.as_bytes());
        let digest = tagged_hash(CONSUMPTION_HASH_TAG, &bytes[..total - DIGEST_LEN]);
        bytes[total - DIGEST_LEN..].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            session_id,
            authorized_revision,
            artifact_digest,
            broadcast_record_digest: *broadcast_record.digest(),
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < CONSUMPTION_PREFIX_LEN + DIGEST_LEN
            || bytes.len() > CONSUMPTION_MAX_LEN
            || &bytes[..8] != CONSUMPTION_MAGIC
            || u16::from_le_bytes([bytes[8], bytes[9]]) != FORMAT_VERSION
            || bytes[10..16] != [0; 6]
            || bytes[124..128] != [0; 4]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let successor_len = u32::from_le_bytes(copy_array(&bytes[120..124])?) as usize;
        let total = CONSUMPTION_PREFIX_LEN
            .checked_add(successor_len)
            .and_then(|value| value.checked_add(DIGEST_LEN))
            .ok_or(SessionStoreError::Quarantined)?;
        if total != bytes.len()
            || successor_len == 0
            || bytes[total - DIGEST_LEN..]
                != tagged_hash(CONSUMPTION_HASH_TAG, &bytes[..total - DIGEST_LEN])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let successor =
            SessionRecordV1::from_bytes(&bytes[CONSUMPTION_PREFIX_LEN..total - DIGEST_LEN])?;
        let session_id = copy_array(&bytes[16..48])?;
        let authorized_revision = u64::from_le_bytes(copy_array(&bytes[48..56])?);
        let broadcast_record_digest = copy_array(&bytes[88..120])?;
        if successor.session_id() != session_id
            || successor.revision()
                != authorized_revision
                    .checked_add(1)
                    .ok_or(SessionStoreError::Quarantined)?
            || successor.phase() != SessionPhaseV1::FundingBroadcast
            || successor.digest() != &broadcast_record_digest
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            session_id,
            authorized_revision,
            artifact_digest: copy_array(&bytes[56..88])?,
            broadcast_record_digest,
        })
    }

    fn broadcast_record(&self) -> Result<SessionRecordV1, SessionStoreError> {
        let end = self
            .bytes
            .len()
            .checked_sub(DIGEST_LEN)
            .ok_or(SessionStoreError::Quarantined)?;
        SessionRecordV1::from_bytes(&self.bytes[CONSUMPTION_PREFIX_LEN..end])
            .map_err(SessionStoreError::from)
    }
}

fn require_exact_successor(
    current: &SessionRecordV1,
    expected_revision: u64,
    successor: &SessionRecordV1,
) -> Result<(), SessionStoreError> {
    let reconstructed = current.advance(
        expected_revision,
        successor.phase(),
        successor.transcript_hash(),
        successor.irreversible(),
        successor.chain(),
        successor.encrypted_payload(),
    )?;
    if reconstructed.as_bytes() != successor.as_bytes() {
        return Err(SessionStoreError::Canonical);
    }
    Ok(())
}

fn publish_immutable(
    directory: &RetainedDirectory,
    staging_name: &str,
    final_name: &str,
    exact_bytes: &[u8],
    maximum_length: usize,
) -> Result<(), SessionStoreError> {
    let final_component = ValidatedComponent::registered(final_name)?;
    match directory.read_bounded_file(&final_component, maximum_length) {
        Ok(existing) if existing == exact_bytes => return Ok(()),
        Ok(_) => return Err(SessionStoreError::Conflict),
        Err(LinuxCapabilityError::NotFound) => {}
        Err(error) => return Err(error.into()),
    }
    let staging_component = ValidatedComponent::registered(staging_name)?;
    if let Ok(stale) = directory.open_file(&staging_component, false) {
        directory.unlink_verified_file(&staging_component, &stale)?;
    }
    let staging = directory.create_immutable_file(&staging_component, exact_bytes)?;
    directory.rename_no_replace(&staging_component, &final_component, &staging)?;
    let persisted = directory.read_bounded_file(&final_component, maximum_length)?;
    if persisted != exact_bytes {
        return Err(SessionStoreError::Quarantined);
    }
    Ok(())
}

fn recover_staging(directory: &RetainedDirectory) -> Result<(), SessionStoreError> {
    let mut staging = Vec::new();
    directory.scan_lexicographic(|name, node| {
        if node.node_type != ExpectedNodeType::RegularFile {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        if name.starts_with('.') && name.ends_with(".staging") {
            staging.push(name.to_owned());
        }
        Ok(())
    })?;
    for name in staging {
        let component = ValidatedComponent::registered(&name)?;
        let retained = directory.open_file(&component, false)?;
        directory.unlink_verified_file(&component, &retained)?;
    }
    Ok(())
}

fn require_root_inventory(root: &RetainedDirectory) -> Result<(), SessionStoreError> {
    let expected = BTreeMap::from([
        (ROOT_IDENTITY_NAME, ExpectedNodeType::RegularFile),
        (LOCK_IDENTITY_NAME, ExpectedNodeType::RegularFile),
        (POLICY_NAME, ExpectedNodeType::RegularFile),
        (RECORDS_NAME, ExpectedNodeType::Directory),
        (ARTIFACTS_NAME, ExpectedNodeType::Directory),
        (CONSUMPTIONS_NAME, ExpectedNodeType::Directory),
        (ROSTERS_NAME, ExpectedNodeType::Directory),
        (MESSAGES_NAME, ExpectedNodeType::Directory),
        (RESERVATION_LOOKUPS_NAME, ExpectedNodeType::Directory),
    ]);
    let mut observed = BTreeMap::new();
    root.scan_lexicographic(|name, identity| {
        observed.insert(name.to_owned(), identity.node_type);
        Ok(())
    })?;
    if observed.len() != expected.len()
        || observed
            .iter()
            .any(|(name, node)| expected.get(name.as_str()) != Some(node))
    {
        return Err(SessionStoreError::Quarantined);
    }
    Ok(())
}

fn encode_root_identity(store_id: [u8; 32], policy_digest: [u8; 32]) -> [u8; ROOT_IDENTITY_LEN] {
    let mut bytes = [0; ROOT_IDENTITY_LEN];
    bytes[..8].copy_from_slice(ROOT_MAGIC);
    bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&store_id);
    bytes[48..80].copy_from_slice(&policy_digest);
    let digest = tagged_hash(ROOT_HASH_TAG, &bytes[..80]);
    bytes[80..].copy_from_slice(&digest);
    bytes
}

fn decode_root_identity(
    bytes: &[u8],
    expected_policy_digest: &[u8; 32],
) -> Result<[u8; 32], SessionStoreError> {
    if bytes.len() != ROOT_IDENTITY_LEN
        || &bytes[..8] != ROOT_MAGIC
        || u16::from_le_bytes([bytes[8], bytes[9]]) != FORMAT_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[48..80] != *expected_policy_digest
        || bytes[80..] != tagged_hash(ROOT_HASH_TAG, &bytes[..80])
    {
        return Err(SessionStoreError::Quarantined);
    }
    let store_id = copy_array(&bytes[16..48])?;
    if store_id == [0; 32] {
        return Err(SessionStoreError::Quarantined);
    }
    Ok(store_id)
}

fn encode_lock_identity(store_id: [u8; 32], root_digest: [u8; 32]) -> [u8; LOCK_IDENTITY_LEN] {
    let mut bytes = [0; LOCK_IDENTITY_LEN];
    bytes[..8].copy_from_slice(LOCK_MAGIC);
    bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&store_id);
    bytes[48..80].copy_from_slice(&tagged_hash(
        LOCK_HASH_TAG,
        &[&store_id[..], &root_digest[..]].concat(),
    ));
    bytes
}

fn decode_lock_identity(
    bytes: &[u8],
    store_id: [u8; 32],
    root_digest: [u8; 32],
) -> Result<(), SessionStoreError> {
    if bytes.len() != LOCK_IDENTITY_LEN
        || &bytes[..8] != LOCK_MAGIC
        || u16::from_le_bytes([bytes[8], bytes[9]]) != FORMAT_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != store_id
        || bytes[48..80] != tagged_hash(LOCK_HASH_TAG, &[&store_id[..], &root_digest[..]].concat())
    {
        return Err(SessionStoreError::Quarantined);
    }
    Ok(())
}

fn session_record_name(session_id: [u8; 32], revision: u64) -> String {
    format!("{}-{revision:020}.session", hex_lower(&session_id))
}

fn parse_session_record_name(name: &str) -> Option<(String, u64)> {
    let body = name.strip_suffix(".session")?;
    if body.len() != 85 || body.as_bytes().get(64) != Some(&b'-') {
        return None;
    }
    let session = &body[..64];
    let revision = &body[65..];
    if decode_hex_32(session).is_none() || !revision.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some((session.to_owned(), revision.parse().ok()?))
}

fn artifact_name(session_id: [u8; 32]) -> String {
    format!("{}.funding-artifacts", hex_lower(&session_id))
}

fn funding_gate_name(session_id: [u8; 32]) -> String {
    format!("{}.operational-funding-gate", hex_lower(&session_id))
}

fn m8_funding_gate_name(session_id: [u8; 32]) -> String {
    format!("{}.operational-m8-funding-gate", hex_lower(&session_id))
}

fn funding_issuance_name(session_id: [u8; 32]) -> String {
    format!("{}.operational-funding-issuance", hex_lower(&session_id))
}

fn m8_funding_issuance_name(session_id: [u8; 32]) -> String {
    format!("{}.operational-m8-funding-issuance", hex_lower(&session_id))
}

fn funding_commit_name(session_id: [u8; 32]) -> String {
    format!("{}.operational-funding-commit", hex_lower(&session_id))
}

fn m8_funding_commit_name(session_id: [u8; 32]) -> String {
    format!("{}.operational-m8-funding-commit", hex_lower(&session_id))
}

fn post_anchor_claim_authorization_name(
    session_id: [u8; 32],
    state: PostAnchorClaimAuthorizationStateV1,
) -> String {
    format!("{}{}", hex_lower(&session_id), state.suffix())
}

fn consumption_name(session_id: [u8; 32]) -> String {
    format!("{}.funding-consumed", hex_lower(&session_id))
}

fn reservation_lookup_record_name(
    request_lookup: [u8; 32],
    state: ReservationLookupStateV1,
) -> String {
    format!("{}{}", hex_lower(&request_lookup), state.suffix())
}

fn parse_reservation_lookup_record_name(
    name: &str,
) -> Option<([u8; 32], ReservationLookupStateV1)> {
    for state in [
        ReservationLookupStateV1::Custodied,
        ReservationLookupStateV1::AbandonedBeforeVaultClaim,
    ] {
        if let Some(value) = name.strip_suffix(state.suffix()) {
            return Some((decode_hex_32(value)?, state));
        }
    }
    None
}

fn roster_name(session_id: [u8; 32]) -> String {
    format!("{}.transport-roster", hex_lower(&session_id))
}

fn transport_identity_binding_name(session_id: [u8; 32]) -> String {
    format!("{}.transport-identities", hex_lower(&session_id))
}

fn signing_binding_name(session_id: [u8; 32], purpose: PurposeV1) -> String {
    format!(
        "{}-{:02x}.operational-signing-binding",
        hex_lower(&session_id),
        purpose.to_byte()
    )
}

fn post_anchor_claim_signing_binding_name(session_id: [u8; 32]) -> String {
    format!(
        "{}.post-anchor-claim-signing-binding",
        hex_lower(&session_id)
    )
}

fn post_anchor_claim_pre_signature_name(session_id: [u8; 32]) -> String {
    format!("{}.post-anchor-claim-pre-signature", hex_lower(&session_id))
}

fn parse_signing_binding_name(name: &str) -> Option<([u8; 32], PurposeV1)> {
    let body = name.strip_suffix(".operational-signing-binding")?;
    if body.len() != 67 || body.as_bytes().get(64) != Some(&b'-') {
        return None;
    }
    let session_id = decode_hex_32(&body[..64])?;
    let purpose_byte = u8::from_str_radix(&body[65..], 16).ok()?;
    let purpose = PurposeV1::try_from(purpose_byte).ok()?;
    purpose
        .is_strict_v1_authorized()
        .then_some((session_id, purpose))
}

fn transport_message_name(
    session_id: [u8; 32],
    sender_id: [u8; 32],
    sequence: u64,
    equivocation: bool,
) -> String {
    let suffix = if equivocation {
        "equivocation"
    } else {
        "message"
    };
    format!(
        "{}-{}-{sequence:020}.{suffix}",
        hex_lower(&session_id),
        hex_lower(&sender_id)
    )
}

fn parse_transport_message_sequence(name: &str) -> Option<u64> {
    let body = name.strip_suffix(".message")?;
    if body.len() != 150
        || body.as_bytes().get(64) != Some(&b'-')
        || body.as_bytes().get(129) != Some(&b'-')
    {
        return None;
    }
    body[130..].parse().ok()
}

fn template_hash_for_purpose(payload: &[u8; 160], purpose: PurposeV1) -> [u8; 32] {
    let source = match purpose {
        PurposeV1::Funding => &payload[..32],
        PurposeV1::ClaimAdaptor => &payload[32..64],
        PurposeV1::Refund => &payload[64..96],
        PurposeV1::Sponsor => return [0; 32],
    };
    let mut result = [0; 32];
    result.copy_from_slice(source);
    result
}

fn signing_phase_for_purpose(purpose: PurposeV1) -> SessionPhaseV1 {
    match purpose {
        PurposeV1::Refund => SessionPhaseV1::RefundSigning,
        PurposeV1::ClaimAdaptor => SessionPhaseV1::ClaimSigning,
        PurposeV1::Funding => SessionPhaseV1::FundingAuthorized,
        PurposeV1::Sponsor => SessionPhaseV1::FailedClosed,
    }
}

fn signing_phase_for_message(message_type: u8) -> Option<SigningPhaseV1> {
    match message_type {
        0x0c => Some(SigningPhaseV1::SigNonceCommit),
        0x0d => Some(SigningPhaseV1::SigNonceReveal),
        0x0e => Some(SigningPhaseV1::SigPartial),
        0x0f => Some(SigningPhaseV1::SigAdapt),
        _ => None,
    }
}

fn signing_payload_purpose(
    message_type: u8,
    payload: &[u8],
) -> Result<PurposeV1, SessionStoreError> {
    match message_type {
        0x0c => NonceCommitmentV1::from_bytes(payload)
            .map(|value| value.purpose())
            .map_err(|_| SessionStoreError::Canonical),
        0x0d => NonceRevealV1::from_bytes(payload)
            .map(|value| value.purpose())
            .map_err(|_| SessionStoreError::Canonical),
        0x0e => PartialSignatureV1::from_bytes(payload)
            .map(|value| value.purpose())
            .map_err(|_| SessionStoreError::Canonical),
        _ => Err(SessionStoreError::Canonical),
    }
}

fn signing_payload_participant_index(
    message_type: u8,
    payload: &[u8],
) -> Result<u16, SessionStoreError> {
    match message_type {
        0x0c => NonceCommitmentV1::from_bytes(payload)
            .map(|value| value.participant_index())
            .map_err(|_| SessionStoreError::Canonical),
        0x0d => NonceRevealV1::from_bytes(payload)
            .map(|value| value.participant_index())
            .map_err(|_| SessionStoreError::Canonical),
        0x0e => PartialSignatureV1::from_bytes(payload)
            .map(|value| value.participant_index())
            .map_err(|_| SessionStoreError::Canonical),
        _ => Err(SessionStoreError::Canonical),
    }
}

#[allow(clippy::too_many_arguments)]
fn derive_post_anchor_claim_pre_signature(
    chain_id: &[u8; 32],
    session_id: [u8; 32],
    claim_template_hash: &[u8; 32],
    adaptor_point: &PublicKey,
    binding: &DecodedSigningSessionBindingV1,
    round: &OperationalSigningRoundAuditV1,
) -> Result<AdaptorPreSignatureV1, SessionStoreError> {
    if chain_id == &[0; 32]
        || session_id == [0; 32]
        || claim_template_hash == &[0; 32]
        || binding.template_hash != *claim_template_hash
        || binding.adaptor_point.as_ref() != Some(adaptor_point)
        || binding.roster.entries().len() != 2
        || round.accepted_messages.len() != 6
        || round.reveal_transcript_hash.is_none()
    {
        return Err(SessionStoreError::InvalidTransition);
    }
    let mut transcript = round.round_start_transcript_hash;
    let mut commitments = Vec::with_capacity(2);
    let mut reveals = Vec::with_capacity(2);
    let mut partials = Vec::with_capacity(2);
    let mut derived_reveal_transcript = None;
    for (position, bytes) in round.accepted_messages.iter().enumerate() {
        let protocol_index = position % 2;
        let stage_index = position / 2;
        let expected_kind = 0x0c_u8
            .checked_add(u8::try_from(stage_index).map_err(|_| SessionStoreError::Canonical)?)
            .ok_or(SessionStoreError::Canonical)?;
        let participant = &binding.roster.entries()[protocol_index];
        let expected_sequence = round.sender_sequence_bases[protocol_index]
            .checked_add(u64::try_from(stage_index).map_err(|_| SessionStoreError::Canonical)?)
            .ok_or(SessionStoreError::CapacityExceeded)?;
        let expected_signing_index = binding
            .roster
            .signing_index(participant.participant_id())
            .map_err(|_| SessionStoreError::Canonical)?;
        let envelope = ParsedTransportEnvelopeV1::parse(bytes)?;
        let payload = envelope.payload(bytes)?;
        if envelope.chain_id != *chain_id
            || envelope.session_id != session_id
            || envelope.sender_id != *participant.participant_id()
            || envelope.sequence != expected_sequence
            || envelope.previous_transcript_hash != transcript
            || envelope.message_type != expected_kind
            || signing_payload_purpose(expected_kind, payload)? != PurposeV1::ClaimAdaptor
            || signing_payload_participant_index(expected_kind, payload)? != expected_signing_index
        {
            return Err(SessionStoreError::Quarantined);
        }
        match expected_kind {
            0x0c => commitments.push(
                NonceCommitmentV1::from_bytes(payload).map_err(|_| SessionStoreError::Canonical)?,
            ),
            0x0d => reveals.push(
                NonceRevealV1::from_bytes(payload).map_err(|_| SessionStoreError::Canonical)?,
            ),
            0x0e => partials.push(
                PartialSignatureV1::from_bytes(payload)
                    .map_err(|_| SessionStoreError::Canonical)?,
            ),
            _ => return Err(SessionStoreError::Canonical),
        }
        let phase = signing_phase_for_message(expected_kind).ok_or(SessionStoreError::Canonical)?;
        transcript = advance_transcript_hash_v1(
            &transcript,
            &envelope.message_digest,
            participant.direction(),
            phase,
        );
        if position == 3 {
            derived_reveal_transcript = Some(transcript);
        }
    }
    let reveal_transcript_hash = derived_reveal_transcript
        .filter(|digest| Some(*digest) == round.reveal_transcript_hash)
        .ok_or(SessionStoreError::Quarantined)?;
    if transcript != round.terminal_transcript_hash
        || commitments.len() != 2
        || reveals.len() != 2
        || partials.len() != 2
    {
        return Err(SessionStoreError::Quarantined);
    }
    for protocol_index in 0..2 {
        let participant = &binding.roster.entries()[protocol_index];
        let expected = nonce_commitment_hash_v1(
            chain_id,
            &session_id,
            participant.participant_id(),
            PurposeV1::ClaimAdaptor,
            claim_template_hash,
            reveals[protocol_index].first(),
            reveals[protocol_index].second(),
            Some(adaptor_point),
        )
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        if commitments[protocol_index].nonce_reveal_hash() != expected.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
    }

    let mut canonical_keys: Vec<PublicKey> = binding
        .roster
        .entries()
        .iter()
        .map(|participant| participant.signing_public_key().clone())
        .collect();
    canonical_keys.sort_by_key(PublicKey::to_compressed_bytes);
    let mut public_nonces = Vec::with_capacity(2);
    for reveal in &reveals {
        let signing_key = canonical_keys
            .get(usize::from(reveal.participant_index()))
            .ok_or(SessionStoreError::Quarantined)?;
        public_nonces.push(ParticipantPublicNoncesV1 {
            participant_index: reveal.participant_index(),
            signing_key: signing_key.clone(),
            first_nonce: reveal.first().clone(),
            second_nonce: reveal.second().clone(),
        });
    }
    public_nonces.sort_by_key(|entry| entry.participant_index);
    let binding_factor = binding_factor_v1(
        &BindingContextV1 {
            chain_id: *chain_id,
            session_id,
            purpose: PurposeV1::ClaimAdaptor,
            template_hash: *claim_template_hash,
        },
        &public_nonces,
        Some(adaptor_point),
    )
    .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let effective_nonces: Vec<PublicKey> = public_nonces
        .iter()
        .map(|entry| binding_factor.bind_public_nonces(&entry.first_nonce, &entry.second_nonce))
        .collect::<Result<_, _>>()
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let aggregate_nonce = aggregate_public_nonces_v1(&effective_nonces)
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let aggregate_nonce_hat = aggregate_public_nonces_v1(&[aggregate_nonce, adaptor_point.clone()])
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let aggregate_signing_key = aggregate_public_nonces_v1(&canonical_keys)
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let kernel = binding
        .transaction_template
        .kernels
        .get(binding.kernel_index)
        .ok_or(SessionStoreError::InvalidDomTransaction)?;
    let message = scriptless_kernel_message_digest_v1(kernel);
    for partial in &partials {
        let index = usize::from(partial.participant_index());
        if index >= 2
            || !partial
                .verify_bound(
                    PurposeV1::ClaimAdaptor,
                    claim_template_hash,
                    &effective_nonces[index],
                    &canonical_keys[index],
                    &aggregate_nonce_hat,
                    &aggregate_signing_key,
                    chain_id,
                    message.as_bytes(),
                )
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?
        {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
    }
    let scalar_hat =
        aggregate_partial_signatures_v1(&partials, PurposeV1::ClaimAdaptor, claim_template_hash)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let pre_signature = AdaptorPreSignatureV1::new(
        *claim_template_hash,
        adaptor_point.clone(),
        aggregate_nonce_hat,
        scalar_hat,
        reveal_transcript_hash,
    );
    if !pre_signature
        .verify(
            claim_template_hash,
            &reveal_transcript_hash,
            &aggregate_signing_key,
            chain_id,
            message.as_bytes(),
        )
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    Ok(pre_signature)
}

fn require_transport_identity_binding(
    roster: &TransportRosterRecordV1,
    binding: &TransportIdentityBindingRecordV1,
) -> Result<(), SessionStoreError> {
    if binding.session_id != roster.session_id
        || binding.chain_id != roster.chain_id
        || binding
            .references
            .iter()
            .zip(roster.participants.iter())
            .any(|(reference, participant)| {
                reference.participant_id != participant.participant_id
                    || reference.schnorr_public_key != participant.identity_key
            })
    {
        return Err(SessionStoreError::Quarantined);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_operational_signing_inputs(
    trusted_chain_id: &TrustedChainIdV1,
    session: &SessionRecordV1,
    contract_kind: ContractKindV1,
    purpose: PurposeV1,
    roster: &ParticipantRosterV1,
    transaction_template: &Transaction,
    kernel_index: usize,
    adaptor_point: Option<&PublicKey>,
    transport_roster: &TransportRosterRecordV1,
) -> Result<(), SessionStoreError> {
    if trusted_chain_id.as_bytes() == &[0; 32]
        || transport_roster.chain_id != *trusted_chain_id.as_bytes()
        || roster.entries().len() != 2
        || session.phase() != signing_phase_for_purpose(purpose)
        || kernel_index >= transaction_template.kernels.len()
        || contract_kind != ContractKindV1::WitnessOrTimeout
    {
        return Err(SessionStoreError::InvalidTransition);
    }
    purpose
        .require_strict_phase1()
        .map_err(|_| SessionStoreError::Canonical)?;
    match (purpose, adaptor_point) {
        (PurposeV1::ClaimAdaptor, Some(_)) | (PurposeV1::Funding | PurposeV1::Refund, None) => {}
        _ => return Err(SessionStoreError::Canonical),
    }
    for participant in roster.entries() {
        let recomputed = ParticipantIdentityV1::new(
            trusted_chain_id,
            participant.identity_public_key().clone(),
            participant.signing_public_key().clone(),
            participant.direction(),
        )
        .map_err(|_| SessionStoreError::Canonical)?;
        let transport = transport_roster
            .participants
            .iter()
            .find(|candidate| candidate.participant_id == *participant.participant_id())
            .ok_or(SessionStoreError::Canonical)?;
        if recomputed.participant_id() != participant.participant_id()
            || transport.identity_key != *participant.identity_public_key()
            || transport.direction != participant.direction()
        {
            return Err(SessionStoreError::Canonical);
        }
    }
    let mut signing_keys: Vec<PublicKey> = roster
        .entries()
        .iter()
        .map(|participant| participant.signing_public_key().clone())
        .collect();
    signing_keys.sort_by_key(PublicKey::to_compressed_bytes);
    let aggregate = aggregate_public_nonces_v1(&signing_keys)
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    if transaction_template.kernels[kernel_index].excess.as_bytes()
        != &aggregate.to_compressed_bytes()
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    canonical_dom_transaction_bytes_v1(transaction_template)?;
    Ok(())
}

// Eight arguments, each an independent authority this function cross-checks
// against the others. Bundling them into a struct would move the checks off
// the call sites without removing one of them.
#[allow(clippy::too_many_arguments)]
fn validate_post_anchor_signing_inputs(
    trusted_chain_id: &TrustedChainIdV1,
    session: &SessionRecordV1,
    contract_kind: ContractKindV1,
    roster: &ParticipantRosterV1,
    transaction_template: &Transaction,
    kernel_index: usize,
    adaptor_point: &PublicKey,
    transport_roster: &TransportRosterRecordV1,
) -> Result<(), SessionStoreError> {
    if trusted_chain_id.as_bytes() == &[0; 32]
        || transport_roster.chain_id != *trusted_chain_id.as_bytes()
        || roster.entries().len() != 2
        || session.phase() != SessionPhaseV1::FundingConfirmed
        || !session.irreversible().funding_authorized
        || kernel_index >= transaction_template.kernels.len()
        || contract_kind != ContractKindV1::WitnessOrTimeout
    {
        return Err(SessionStoreError::InvalidTransition);
    }
    PublicKey::from_compressed_bytes(&adaptor_point.to_compressed_bytes())
        .map_err(|_| SessionStoreError::Canonical)?;
    for participant in roster.entries() {
        let recomputed = ParticipantIdentityV1::new(
            trusted_chain_id,
            participant.identity_public_key().clone(),
            participant.signing_public_key().clone(),
            participant.direction(),
        )
        .map_err(|_| SessionStoreError::Canonical)?;
        let transport = transport_roster
            .participants
            .iter()
            .find(|candidate| candidate.participant_id == *participant.participant_id())
            .ok_or(SessionStoreError::Canonical)?;
        if recomputed.participant_id() != participant.participant_id()
            || transport.identity_key != *participant.identity_public_key()
            || transport.direction != participant.direction()
        {
            return Err(SessionStoreError::Canonical);
        }
    }
    Ok(())
}

fn transport_transcript_hash(
    previous: &[u8; 32],
    digest: &[u8; 32],
    direction: DirectionV1,
    phase: SessionPhaseV1,
) -> [u8; 32] {
    let mut body = [0; 67];
    body[..32].copy_from_slice(previous);
    body[32..64].copy_from_slice(digest);
    body[64] = direction.to_byte();
    body[65..].copy_from_slice(&(phase as u16).to_le_bytes());
    tagged_hash(TRANSPORT_TRANSCRIPT_TAG, &body)
}

fn transport_payload_cap(message_type: u8) -> Option<usize> {
    match message_type {
        0x01 | 0x02 => Some(8 * 1024),
        0x03 | 0x05 | 0x06 | 0x07 | 0x0c | 0x11 | 0x13 | 0x14 => Some(4 * 1024),
        0x04 | 0x08 | 0x09 | 0x0b | 0x0d | 0x0e | 0x0f => Some(8 * 1024),
        0x0a => Some(16 * 1024),
        0x10 | 0x12 => Some(512 * 1024),
        _ => None,
    }
}

fn require_failed_closed_successor(
    current: &SessionRecordV1,
    failed: &SessionRecordV1,
) -> Result<(), SessionStoreError> {
    if failed.phase() != SessionPhaseV1::FailedClosed
        || failed.transcript_hash() != current.transcript_hash()
        || failed.irreversible() != current.irreversible()
        || failed.chain() != current.chain()
        || failed.encrypted_payload() != current.encrypted_payload()
    {
        return Err(SessionStoreError::InvalidTransition);
    }
    require_exact_successor(current, current.revision(), failed)
}

fn require_transport_successor(
    current: &SessionRecordV1,
    envelope: &ParsedTransportEnvelopeV1,
    direction: DirectionV1,
    successor: &SessionRecordV1,
) -> Result<(), SessionStoreError> {
    require_exact_successor(current, current.revision(), successor)?;
    if !transport_message_accepts_phase(envelope.message_type, successor.phase())
        || !transport_phase_movement(current.phase(), successor.phase(), envelope.message_type)
        || envelope.previous_transcript_hash != current.transcript_hash()
        || successor.transcript_hash()
            != accepted_transport_transcript_hash(
                &current.transcript_hash(),
                &envelope.message_digest,
                direction,
                envelope.message_type,
                successor.phase(),
            )?
    {
        return Err(SessionStoreError::InvalidTransition);
    }
    Ok(())
}

fn accepted_transport_transcript_hash(
    previous: &[u8; 32],
    digest: &[u8; 32],
    direction: DirectionV1,
    message_type: u8,
    economic_phase: SessionPhaseV1,
) -> Result<[u8; 32], SessionStoreError> {
    if message_type == 0x14 {
        return Ok(*previous);
    }
    match signing_phase_for_message(message_type) {
        Some(signing_phase) => Ok(advance_transcript_hash_v1(
            previous,
            digest,
            direction,
            signing_phase,
        )),
        None => Ok(transport_transcript_hash(
            previous,
            digest,
            direction,
            economic_phase,
        )),
    }
}

fn transport_message_accepts_phase(message_type: u8, phase: SessionPhaseV1) -> bool {
    match message_type {
        0x01 => phase == SessionPhaseV1::Created,
        0x02 => phase == SessionPhaseV1::TermsCommitted,
        0x03 => phase == SessionPhaseV1::SharesCommitted,
        0x04 => phase == SessionPhaseV1::SharesRevealed,
        0x05 => phase == SessionPhaseV1::BpCommonCommitted,
        0x06 => phase == SessionPhaseV1::BpCommonEstablished,
        0x07 => phase == SessionPhaseV1::BpNonceCommitted,
        0x08 => phase == SessionPhaseV1::BpRound1Complete,
        0x09 => phase == SessionPhaseV1::BpRound2Complete,
        0x0a => phase == SessionPhaseV1::OutputFinalized,
        0x0b => phase == SessionPhaseV1::TemplatesCommitted,
        0x0c..=0x0e => matches!(
            phase,
            SessionPhaseV1::RefundSigning
                | SessionPhaseV1::ClaimSigning
                | SessionPhaseV1::FundingAuthorized
        ),
        0x0f => phase == SessionPhaseV1::ClaimPrepared,
        0x10 => phase == SessionPhaseV1::RefundSigned,
        // The candidate Store persists each participant's readiness vote as a
        // same-phase ClaimPrepared journal successor. Only the operational
        // one-shot issuance may enter FundingAuthorized. FundingAuthorized is
        // retained for replay compatibility with already accepted evidence.
        0x11 => matches!(
            phase,
            SessionPhaseV1::ClaimPrepared | SessionPhaseV1::FundingAuthorized
        ),
        0x12 => phase == SessionPhaseV1::ClaimBroadcast,
        0x13 => phase == SessionPhaseV1::Aborted,
        0x14 => true,
        _ => false,
    }
}

fn transport_phase_movement(
    current: SessionPhaseV1,
    next: SessionPhaseV1,
    message_type: u8,
) -> bool {
    if message_type == 0x14 {
        return current == next;
    }
    if message_type == 0x13 {
        return !matches!(
            current,
            SessionPhaseV1::Settled
                | SessionPhaseV1::Refunded
                | SessionPhaseV1::Aborted
                | SessionPhaseV1::FailedClosed
        ) && next == SessionPhaseV1::Aborted;
    }
    // The closed table is in the protocol crate, which already depends on this
    // Store crate. Preserve acyclicity by spelling only its exact adjacent V1
    // edges here; same-phase multi-message rounds remain permitted.
    current == next
        || matches!(
            (current, next),
            (SessionPhaseV1::Created, SessionPhaseV1::TermsCommitted)
                | (
                    SessionPhaseV1::TermsCommitted,
                    SessionPhaseV1::SharesCommitted
                )
                | (
                    SessionPhaseV1::SharesCommitted,
                    SessionPhaseV1::SharesRevealed
                )
                | (
                    SessionPhaseV1::SharesRevealed,
                    SessionPhaseV1::BpCommonCommitted
                )
                | (
                    SessionPhaseV1::BpCommonCommitted,
                    SessionPhaseV1::BpCommonEstablished
                )
                | (
                    SessionPhaseV1::BpCommonEstablished,
                    SessionPhaseV1::BpNonceCommitted
                )
                | (
                    SessionPhaseV1::BpNonceCommitted,
                    SessionPhaseV1::BpRound1Complete
                )
                | (
                    SessionPhaseV1::BpRound1Complete,
                    SessionPhaseV1::BpRound2Complete
                )
                | (
                    SessionPhaseV1::BpRound2Complete,
                    SessionPhaseV1::OutputFinalized
                )
                | (
                    SessionPhaseV1::OutputFinalized,
                    SessionPhaseV1::TemplatesCommitted
                )
                | (
                    SessionPhaseV1::TemplatesCommitted,
                    SessionPhaseV1::RefundSigning
                )
                | (SessionPhaseV1::RefundSigning, SessionPhaseV1::RefundSigned)
                | (SessionPhaseV1::RefundSigned, SessionPhaseV1::ClaimSigning)
                | (SessionPhaseV1::ClaimSigning, SessionPhaseV1::ClaimPrepared)
                | (
                    SessionPhaseV1::ClaimPrepared,
                    SessionPhaseV1::FundingAuthorized
                )
                | (
                    SessionPhaseV1::FundingAuthorized,
                    SessionPhaseV1::FundingBroadcast
                )
                | (
                    SessionPhaseV1::FundingBroadcast,
                    SessionPhaseV1::FundingConfirmed
                )
                | (
                    SessionPhaseV1::FundingConfirmed,
                    SessionPhaseV1::ClaimBroadcast
                )
                | (
                    SessionPhaseV1::FundingConfirmed,
                    SessionPhaseV1::RefundEligible
                )
                | (SessionPhaseV1::ClaimBroadcast, SessionPhaseV1::Settled)
                | (
                    SessionPhaseV1::RefundEligible,
                    SessionPhaseV1::RefundBroadcast
                )
                | (SessionPhaseV1::RefundBroadcast, SessionPhaseV1::Refunded)
        )
}

fn is_funding_or_later_economic_phase(phase: SessionPhaseV1) -> bool {
    matches!(
        phase,
        SessionPhaseV1::FundingAuthorized
            | SessionPhaseV1::FundingBroadcast
            | SessionPhaseV1::FundingConfirmed
            | SessionPhaseV1::ClaimBroadcast
            | SessionPhaseV1::RefundEligible
            | SessionPhaseV1::RefundBroadcast
            | SessionPhaseV1::Settled
            | SessionPhaseV1::Refunded
    )
}

fn is_terminal_phase(phase: SessionPhaseV1) -> bool {
    matches!(
        phase,
        SessionPhaseV1::Settled
            | SessionPhaseV1::Refunded
            | SessionPhaseV1::Aborted
            | SessionPhaseV1::FailedClosed
    )
}

fn is_post_broadcast_economic_phase(phase: SessionPhaseV1) -> bool {
    matches!(
        phase,
        SessionPhaseV1::FundingConfirmed
            | SessionPhaseV1::ClaimBroadcast
            | SessionPhaseV1::RefundEligible
            | SessionPhaseV1::RefundBroadcast
            | SessionPhaseV1::Settled
            | SessionPhaseV1::Refunded
    )
}

fn tagged_hash(tag: &str, bytes: &[u8]) -> [u8; 32] {
    *dom_crypto::blake2b_256_tagged(tag, bytes).as_bytes()
}

fn participant_roster_digest(roster: &ParticipantRosterV1) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(2 + roster.entries().len() * 100);
    bytes.extend_from_slice(&(roster.entries().len() as u16).to_le_bytes());
    for participant in roster.entries() {
        bytes.extend_from_slice(participant.participant_id());
        bytes.extend_from_slice(&participant.identity_public_key().to_compressed_bytes());
        bytes.extend_from_slice(&participant.signing_public_key().to_compressed_bytes());
        bytes.push(participant.direction().to_byte());
    }
    tagged_hash(POST_ANCHOR_CLAIM_ROSTER_HASH_TAG, &bytes)
}

fn random_nonzero() -> Result<[u8; 32], SessionStoreError> {
    for _ in 0..4 {
        let mut value = [0; 32];
        OsRng
            .try_fill_bytes(&mut value)
            .map_err(|_| SessionStoreError::RandomFailure)?;
        if value != [0; 32] {
            return Ok(value);
        }
    }
    Err(SessionStoreError::RandomFailure)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut output = [0; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        output[index] = high.checked_mul(16)?.checked_add(low)?;
    }
    Some(output)
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], SessionStoreError> {
    bytes.try_into().map_err(|_| SessionStoreError::Quarantined)
}

#[cfg(test)]
fn test_crash_hook(boundary: &str) {
    use std::io::Write as _;

    if std::env::var("DOM_F7_SESSION_STORE_CRASH_CUT")
        .ok()
        .as_deref()
        != Some(boundary)
    {
        return;
    }
    if let Some(marker) = std::env::var_os("DOM_F7_SESSION_STORE_CRASH_MARKER") {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(marker)
        {
            let _ = file.write_all(boundary.as_bytes());
            let _ = file.sync_all();
        }
    }
    std::process::abort();
}

#[cfg(not(test))]
fn test_crash_hook(_: &str) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ContractsNonceVaultV1, SessionIrreversibleV1, SessionRecordFieldsV1, SessionTxObservationV1,
    };
    use dom_adaptor::{SigningShareV1, VaultBackedSignerV1};
    use dom_consensus::{TransactionInput, TransactionKernel, TransactionOutput};
    use dom_core::{Amount, Hash256, KERNEL_FEAT_PLAIN, TAG_KERNEL_MSG};
    use dom_crypto::{
        hash::blake2b_256_tagged,
        pedersen::{BlindingFactor, Commitment},
        schnorr_sign, PartialSig, SecretKey,
    };
    use dom_scriptless_crypto::{
        authoritative_storage_hash_v1, generate_storage_ids, Passphrase, StorageHashDomainV1,
    };
    use static_assertions::assert_not_impl_any;
    use std::{
        fs::{self, File},
        os::unix::{fs::PermissionsExt, process::ExitStatusExt},
        path::{Path, PathBuf},
        process::{self, Command},
        sync::atomic::{AtomicU64, Ordering},
        thread,
    };

    assert_not_impl_any!(FundingAuthorizationV1: Clone, Copy, fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(FundingBroadcastV1: Clone, Copy, fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(FundingRetransmissionV1: Clone, Copy, fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(RefundBroadcastV1: Clone, Copy, fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(VerifiedFundingArtifactsV1: Clone, Copy, fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(DurableContractsReservationLookupV1: Clone, Copy, fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(AuthenticatedContractsRefundV1: Clone, Copy, fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(PreparedOperationalM8FundingGateV1: Clone, Copy, fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(PreparedOperationalM8ReadyToFundVoteV1: Clone, Copy, fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(AuthenticatedOperationalBpContinuationV1: Clone, Copy, fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(AuthenticatedOperationalBpFinalProofV1: Clone, Copy, fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(ClaimSigningAuthorizationV1: Clone, Copy, fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(ConsumedClaimSigningAuthorizationV1: Clone, Copy, fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(AuthenticatedPostAnchorClaimPreSignatureV1: Clone, Copy, fmt::Debug, Eq, PartialEq);

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Result<Self, Box<dyn Error>> {
            loop {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "dom-contracts-session-store-{}-{sequence}",
                    process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                        return Ok(Self(path));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(Box::new(error)),
                }
            }
        }

        fn capability(&self) -> Result<Arc<Dir>, Box<dyn Error>> {
            Ok(Arc::new(Dir::from_std_file(File::open(&self.0)?)))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn policy(profile: BudgetPolicyProfileV1) -> Result<BudgetPolicyV1, Box<dyn Error>> {
        let mut bytes = [0; BUDGET_POLICY_LEN];
        bytes[..8].copy_from_slice(b"DOMNVBP1");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10] = profile as u8;
        bytes[11] = 1;
        bytes[16..48].fill(0x41);
        bytes[48..56].copy_from_slice(&100_u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&50_u64.to_le_bytes());
        bytes[64..68].copy_from_slice(&10_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&25_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&3_600_u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&60_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&86_400_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&1_u64.to_le_bytes());
        let digest =
            authoritative_storage_hash_v1(StorageHashDomainV1::BudgetPolicy, &bytes[..112]);
        bytes[112..].copy_from_slice(&digest);
        Ok(BudgetPolicyV1::from_bytes(&bytes)?)
    }

    fn projection(height: u64) -> SessionChainProjectionV1 {
        SessionChainProjectionV1 {
            tip_id: [height as u8; 32],
            tip_height: height,
            funding: SessionTxObservationV1::Unknown,
            claim: SessionTxObservationV1::Unknown,
            refund: SessionTxObservationV1::Unknown,
        }
    }

    fn record(phase: SessionPhaseV1) -> Result<SessionRecordV1, CanonicalCodecError> {
        SessionRecordV1::new(
            SessionRecordFieldsV1 {
                session_id: [0x31; 32],
                revision: 0,
                phase,
                terms_hash: [0x32; 32],
                transcript_hash: [0x33; 32],
                irreversible: SessionIrreversibleV1 {
                    any_signing_share_sent: true,
                    funding_authorized: false,
                    adaptor_secret_exposed: false,
                    nonce_epoch: 7,
                },
                chain: projection(100),
            },
            b"sealed-test-payload",
        )
    }

    fn funding_successors(
        current: &SessionRecordV1,
    ) -> Result<(SessionRecordV1, SessionRecordV1), CanonicalCodecError> {
        let mut irreversible = current.irreversible();
        irreversible.funding_authorized = true;
        let ready = current.advance(
            current.revision(),
            SessionPhaseV1::FundingAuthorized,
            [0x41; 32],
            irreversible,
            current.chain(),
            current.encrypted_payload(),
        )?;
        let broadcast = ready.advance(
            ready.revision(),
            SessionPhaseV1::FundingBroadcast,
            [0x42; 32],
            ready.irreversible(),
            ready.chain(),
            ready.encrypted_payload(),
        )?;
        Ok((ready, broadcast))
    }

    fn verified_for_test(current: &SessionRecordV1) -> VerifiedFundingArtifactsV1 {
        let refund_bytes = b"exact-presigned-refund-test-bytes".to_vec();
        let funding_bytes = b"exact-funding-test-bytes".to_vec();
        VerifiedFundingArtifactsV1 {
            session_id: current.session_id(),
            terms_hash: current.terms_hash(),
            refund_unlock_height: 500,
            refund_digest: tagged_hash(REFUND_HASH_TAG, &refund_bytes),
            funding_digest: tagged_hash(FUNDING_HASH_TAG, &funding_bytes),
            refund_bytes,
            funding_bytes,
        }
    }

    // TEST VECTOR ONLY — PUBLIC AND INSECURE. These deterministic scalars are
    // restricted to temporary tests and have no economic value.
    fn scalar(seed: u8) -> Result<BlindingFactor, Box<dyn Error>> {
        let mut bytes = [0; 32];
        bytes[31] = seed.max(1);
        Ok(BlindingFactor::from_bytes(bytes)?)
    }

    struct PostAnchorClaimPreSignatureTestFixture {
        issued: PostAnchorClaimAuthorizationRecordV1,
        consumed: PostAnchorClaimAuthorizationRecordV1,
        round: OperationalSigningRoundAuditV1,
        pre_signature: AdaptorPreSignatureV1,
    }

    impl PostAnchorClaimPreSignatureTestFixture {
        fn new(accepted_message_count: usize) -> Result<Self, Box<dyn Error>> {
            let current = record(SessionPhaseV1::ClaimPrepared)?;
            let (_, broadcast) = funding_successors(&current)?;
            let confirmed = broadcast.advance(
                broadcast.revision(),
                SessionPhaseV1::FundingConfirmed,
                [0x43; 32],
                broadcast.irreversible(),
                broadcast.chain(),
                broadcast.encrypted_payload(),
            )?;
            let adaptor_point = SecretKey::from_bytes(&[0x17; 32])?.public_key();
            let shared_output = Commitment::commit(41, &scalar(0x18)?);
            let evidence = PostAnchorDomClaimSigningEvidenceV1 {
                chain_id: [0x71; 32],
                session_id: confirmed.session_id(),
                settlement_id: [0x81; 32],
                terms_hash: confirmed.terms_hash(),
                m8_policy_digest: [0x80; 32],
                m8_anchor_evidence_digest: [0x82; 32],
                dom_funding_id: [0x8a; 32],
                bitcoin_funding_id: [0x8b; 32],
                dom_shared_output_commitment: *shared_output.as_bytes(),
                expected_claim_template_hash: [0x83; 32],
                expected_round_start_transcript_hash: confirmed.transcript_hash(),
                expected_adaptor_point: adaptor_point.clone(),
                dom_confirmation_depth: 6,
                bitcoin_confirmation_depth: 7,
            };
            let issued = PostAnchorClaimAuthorizationRecordV1::new_issued(
                &evidence, &confirmed, [0x85; 32], [0x86; 32], [0x87; 32], [0x88; 32],
            )?;
            let consumed = PostAnchorClaimAuthorizationRecordV1::new_consumed(&issued)?;
            let reveal_transcript_hash = [0x91; 32];
            let mut scalar_bytes = [0; 32];
            scalar_bytes[31] = 0x1a;
            let pre_signature = AdaptorPreSignatureV1::new(
                evidence.expected_claim_template_hash,
                adaptor_point,
                SecretKey::from_bytes(&[0x19; 32])?.public_key(),
                PartialSig::from_bytes(&scalar_bytes)?,
                reveal_transcript_hash,
            );
            let terminal_revision = confirmed
                .revision()
                .checked_add(u64::try_from(accepted_message_count)?)
                .ok_or(SessionStoreError::CapacityExceeded)?;
            let accepted_messages: Vec<Vec<u8>> = (0..accepted_message_count)
                .map(|index| u8::try_from(index).map(|value| vec![value.wrapping_add(0xa0)]))
                .collect::<Result<_, _>>()?;
            let round = OperationalSigningRoundAuditV1 {
                round_start_revision: confirmed.revision(),
                round_start_record_digest: *confirmed.digest(),
                round_start_transcript_hash: confirmed.transcript_hash(),
                reveal_transcript_hash: Some(reveal_transcript_hash),
                terminal_revision,
                terminal_record_digest: [0x92; 32],
                terminal_transcript_hash: [0x93; 32],
                sender_sequence_bases: [4, 7],
                template_commit_payload: [0x94; 160],
                accepted_messages,
            };
            Ok(Self {
                issued,
                consumed,
                round,
                pre_signature,
            })
        }

        fn record(&self) -> Result<PostAnchorClaimPreSignatureRecordV1, SessionStoreError> {
            PostAnchorClaimPreSignatureRecordV1::new(
                &self.issued,
                &self.consumed,
                [0x95; 32],
                [0x96; 32],
                [0x97; 32],
                &self.round,
                &self.pre_signature,
            )
        }
    }

    fn kernel_message(features: u8, fee: u64, lock_height: u64) -> [u8; 32] {
        let mut body = Vec::new();
        body.push(features);
        body.extend_from_slice(&fee.to_le_bytes());
        body.extend_from_slice(&lock_height.to_le_bytes());
        *blake2b_256_tagged(TAG_KERNEL_MSG, &body).as_bytes()
    }

    fn real_dom_transaction_bytes(
        features: u8,
        lock_height: u64,
        input_value: u64,
        output_value: u64,
        input_seed: u8,
        kernel_seed: u8,
        chain_id: &[u8; 32],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let input_blinding = scalar(input_seed)?;
        let kernel_blinding = scalar(kernel_seed)?;
        let output_blinding = input_blinding.add(&kernel_blinding)?;
        let fee = input_value
            .checked_sub(output_value)
            .ok_or(SessionStoreError::InvalidDomTransaction)?;
        let input_commitment = Commitment::commit(input_value, &input_blinding);
        let output_commitment = Commitment::commit(output_value, &output_blinding);
        let (proof, _) = dom_crypto::bp2_prove(output_value, &output_blinding)?;
        let excess = Commitment::commit(0, &kernel_blinding);
        let secret = SecretKey::from_bytes(kernel_blinding.as_bytes())?;
        let signature = schnorr_sign(
            &secret,
            &kernel_message(features, fee, lock_height),
            chain_id,
        )?;
        let transaction = Transaction {
            inputs: vec![TransactionInput {
                commitment: input_commitment,
            }],
            outputs: vec![TransactionOutput {
                commitment: output_commitment,
                proof,
            }],
            kernels: vec![TransactionKernel {
                features,
                fee: Amount::from_noms(fee)?,
                lock_height,
                excess,
                excess_signature: signature.to_bytes(),
            }],
            offset: [0; 32],
        };
        Ok(transaction.to_bytes()?)
    }

    // Eight arguments because the signed transport envelope binds eight
    // independent values; a fixture that grouped them would hide which field a
    // failing vector actually moved.
    #[allow(clippy::too_many_arguments)]
    fn transport_signed_bytes(
        key: &SecretKey,
        chain_id: [u8; 32],
        session_id: [u8; 32],
        sender_id: [u8; 32],
        sequence: u64,
        previous_transcript_hash: [u8; 32],
        message_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let payload_len = u32::try_from(payload.len())?;
        let mut unsigned = vec![0; 148 + payload.len()];
        unsigned[..4].copy_from_slice(b"DSC1");
        unsigned[4..6].copy_from_slice(&1_u16.to_le_bytes());
        unsigned[6] = message_type;
        unsigned[8..40].copy_from_slice(&chain_id);
        unsigned[40..72].copy_from_slice(&session_id);
        unsigned[72..104].copy_from_slice(&sender_id);
        unsigned[104..112].copy_from_slice(&sequence.to_le_bytes());
        unsigned[112..144].copy_from_slice(&previous_transcript_hash);
        unsigned[144..148].copy_from_slice(&payload_len.to_le_bytes());
        unsigned[148..].copy_from_slice(payload);
        let digest = tagged_hash(TRANSPORT_MESSAGE_DIGEST_TAG, &unsigned);
        let signature = schnorr_sign(key, &digest, &chain_id)?;
        unsigned.extend_from_slice(&signature.to_bytes());
        Ok(unsigned)
    }

    struct OperationalBpTestFixture {
        trusted_chain_id: TrustedChainIdV1,
        capsule: RecoveryCapsule,
        statement: BpStatementV1,
        alice: SecretKey,
        bob: SecretKey,
        participant_ids: [[u8; 32]; 2],
        payloads: Vec<Vec<u8>>,
    }

    impl OperationalBpTestFixture {
        fn new() -> Result<Self, Box<dyn Error>> {
            let trusted_chain_id = TrustedChainIdV1::from_authenticated_genesis(
                0x0011_2233,
                &Hash256::from_bytes([0x51; 32]),
            );
            let mut capsule_bytes = [0u8; 96];
            capsule_bytes[..2].copy_from_slice(&1_u16.to_le_bytes());
            capsule_bytes[14..16].copy_from_slice(&80_u16.to_le_bytes());
            let capsule = RecoveryCapsule::from_bytes(&capsule_bytes)?;
            let participant_ids = [[0xa1; 32], [0xb2; 32]];
            let mut share_a_bytes = [0u8; 32];
            share_a_bytes[31] = 3;
            let mut share_b_bytes = [0u8; 32];
            share_b_bytes[31] = 5;
            let share_a = SigningShareV1::from_be_bytes(share_a_bytes)?;
            let share_b = SigningShareV1::from_be_bytes(share_b_bytes)?;
            let commitment_shares =
                vec![share_a.public_key().clone(), share_b.public_key().clone()];
            let aggregate_commitment =
                BpStatementV1::aggregate_commitment_from_shares(&commitment_shares, 42)?;
            let statement = BpStatementV1::new(
                &trusted_chain_id,
                [0x31; 32],
                participant_ids.to_vec(),
                42,
                commitment_shares,
                aggregate_commitment,
                Some(*blake2b_256(capsule.as_bytes()).as_bytes()),
            )?;
            let driver_a =
                DomCollaborativeRangeProofV1::new(&statement, capsule.as_bytes().to_vec())?;
            let driver_b =
                DomCollaborativeRangeProofV1::new(&statement, capsule.as_bytes().to_vec())?;
            let (pending_a, common_commit_a) = PendingCommonNonce::new(&statement, 0, &share_a)?;
            let (pending_b, common_commit_b) = PendingCommonNonce::new(&statement, 1, &share_b)?;
            let common_reveal_a = pending_a.reveal_bytes();
            let common_reveal_b = pending_b.reveal_bytes();
            let accepted_common = [common_commit_a, common_commit_b];
            let local_a = pending_a.finish(
                &statement,
                &accepted_common,
                vec![common_reveal_a.clone(), common_reveal_b.clone()],
            )?;
            let local_b = pending_b.finish(
                &statement,
                &accepted_common,
                vec![common_reveal_a.clone(), common_reveal_b.clone()],
            )?;
            let round1_a = driver_a.round1(&statement, &local_a)?;
            let round1_b = driver_b.round1(&statement, &local_b)?;
            let round1_commit_a = round1_a.reveal_commitment();
            let round1_commit_b = round1_b.reveal_commitment();
            let aggregate_round1 = AggregateBpRound1::new(
                &statement,
                &[round1_commit_a, round1_commit_b],
                &[round1_a.clone(), round1_b.clone()],
            )?;
            let round2_a = driver_a
                .round2(&statement, &local_a, &aggregate_round1)?
                .into_zeroizing_bytes();
            let round2_b = driver_b
                .round2(&statement, &local_b, &aggregate_round1)?
                .into_zeroizing_bytes();
            let aggregate_round2 = AggregateBpRound2::new(
                &statement,
                vec![
                    BpRound2ShareV1::from_bytes(round2_a.as_ref(), &statement)?,
                    BpRound2ShareV1::from_bytes(round2_b.as_ref(), &statement)?,
                ],
            )?;
            let proof = driver_b.finalize(&statement, &aggregate_round1, &aggregate_round2)?;
            let payloads = vec![
                common_commit_a.to_vec(),
                common_commit_b.to_vec(),
                common_reveal_a[..].to_vec(),
                common_reveal_b[..].to_vec(),
                round1_commit_a.to_vec(),
                round1_commit_b.to_vec(),
                round1_a.to_bytes().to_vec(),
                round1_b.to_bytes().to_vec(),
                round2_a[..].to_vec(),
                round2_b[..].to_vec(),
                proof.as_bytes().to_vec(),
            ];
            Ok(Self {
                trusted_chain_id,
                capsule,
                statement,
                alice: SecretKey::from_bytes(&[0x11; 32])?,
                bob: SecretKey::from_bytes(&[0x12; 32])?,
                participant_ids,
                payloads,
            })
        }

        fn signing_key(&self, participant_index: usize) -> &SecretKey {
            if participant_index == 0 {
                &self.alice
            } else {
                &self.bob
            }
        }
    }

    fn operational_bp_store(
        temporary: &TestDirectory,
        evidence_policy: &BudgetPolicyV1,
        fixture: &OperationalBpTestFixture,
    ) -> Result<(ContractsSessionStoreV1, SessionRecordV1), Box<dyn Error>> {
        let store = ContractsSessionStoreV1::create_evidence_only(
            temporary.capability()?,
            "sessions",
            evidence_policy.clone(),
        )?;
        let initial = record(SessionPhaseV1::SharesRevealed)?;
        store.create_session(&initial)?;
        store.bind_transport_roster(
            initial.session_id(),
            *fixture.trusted_chain_id.as_bytes(),
            [
                SessionTransportParticipantV1::new(
                    fixture.participant_ids[0],
                    fixture.alice.public_key(),
                    DirectionV1::Initiator,
                )?,
                SessionTransportParticipantV1::new(
                    fixture.participant_ids[1],
                    fixture.bob.public_key(),
                    DirectionV1::Responder,
                )?,
            ],
        )?;
        store.bind_transport_identity_references(
            initial.session_id(),
            [
                SessionTransportIdentityReferenceV1::new(
                    fixture.participant_ids[0],
                    [0x61; 32],
                    [0x71; 32],
                    fixture.alice.public_key(),
                )?,
                SessionTransportIdentityReferenceV1::new(
                    fixture.participant_ids[1],
                    [0x62; 32],
                    [0x72; 32],
                    fixture.bob.public_key(),
                )?,
            ],
        )?;
        Ok((store, initial))
    }

    fn bp_phase(message_type: u8) -> Result<SessionPhaseV1, SessionStoreError> {
        match message_type {
            0x05 => Ok(SessionPhaseV1::BpCommonCommitted),
            0x06 => Ok(SessionPhaseV1::BpCommonEstablished),
            0x07 => Ok(SessionPhaseV1::BpNonceCommitted),
            0x08 => Ok(SessionPhaseV1::BpRound1Complete),
            0x09 => Ok(SessionPhaseV1::BpRound2Complete),
            0x0a => Ok(SessionPhaseV1::OutputFinalized),
            _ => Err(SessionStoreError::Canonical),
        }
    }

    fn accept_bp_payload(
        store: &ContractsSessionStoreV1,
        fixture: &OperationalBpTestFixture,
        current: &SessionRecordV1,
        participant_index: usize,
        sequence: u64,
        message_type: u8,
        payload: &[u8],
    ) -> Result<SessionRecordV1, Box<dyn Error>> {
        let direction = if participant_index == 0 {
            DirectionV1::Initiator
        } else {
            DirectionV1::Responder
        };
        let signed = transport_signed_bytes(
            fixture.signing_key(participant_index),
            *fixture.trusted_chain_id.as_bytes(),
            current.session_id(),
            fixture.participant_ids[participant_index],
            sequence,
            current.transcript_hash(),
            message_type,
            payload,
        )?;
        let envelope = ParsedTransportEnvelopeV1::parse(&signed)?;
        let phase = bp_phase(message_type)?;
        let successor = current.advance(
            current.revision(),
            phase,
            accepted_transport_transcript_hash(
                &current.transcript_hash(),
                &envelope.message_digest,
                direction,
                message_type,
                phase,
            )?,
            current.irreversible(),
            current.chain(),
            current.encrypted_payload(),
        )?;
        match store.accept_transport_message(&signed, &successor, None)? {
            DurableTransportOutcomeV1::Accepted(receipt) if !receipt.duplicate => Ok(successor),
            _ => Err(Box::new(SessionStoreError::Quarantined)),
        }
    }

    fn accept_bp_prefix(
        store: &ContractsSessionStoreV1,
        fixture: &OperationalBpTestFixture,
        mut current: SessionRecordV1,
        count: usize,
    ) -> Result<SessionRecordV1, Box<dyn Error>> {
        for position in 0..count {
            let (participant_index, sequence, message_type) = if position < 10 {
                (
                    position % 2,
                    u64::try_from(position / 2)?,
                    0x05 + (position / 2) as u8,
                )
            } else {
                (1, 5, 0x0a)
            };
            current = accept_bp_payload(
                store,
                fixture,
                &current,
                participant_index,
                sequence,
                message_type,
                &fixture.payloads[position],
            )?;
        }
        Ok(current)
    }

    #[test]
    fn operational_bp_all_prefixes_restart_with_closed_stages_and_masks(
    ) -> Result<(), Box<dyn Error>> {
        let fixture = OperationalBpTestFixture::new()?;
        let expected = [
            (
                OperationalBpContinuationStageV1::CommonCommit,
                [false, false],
            ),
            (
                OperationalBpContinuationStageV1::CommonCommit,
                [true, false],
            ),
            (
                OperationalBpContinuationStageV1::CommonReveal,
                [false, false],
            ),
            (
                OperationalBpContinuationStageV1::CommonReveal,
                [true, false],
            ),
            (
                OperationalBpContinuationStageV1::RoundCommit,
                [false, false],
            ),
            (OperationalBpContinuationStageV1::RoundCommit, [true, false]),
            (OperationalBpContinuationStageV1::Round1, [false, false]),
            (OperationalBpContinuationStageV1::Round1, [true, false]),
            (OperationalBpContinuationStageV1::Round2, [false, false]),
            (OperationalBpContinuationStageV1::Round2, [true, false]),
            (OperationalBpContinuationStageV1::Finalize, [false, false]),
            (OperationalBpContinuationStageV1::Complete, [false, true]),
        ];
        for (prefix, (expected_stage, expected_mask)) in expected.into_iter().enumerate() {
            let temporary = TestDirectory::create()?;
            let evidence_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
            let (store, initial) = operational_bp_store(&temporary, &evidence_policy, &fixture)?;
            let terminal = accept_bp_prefix(&store, &fixture, initial.clone(), prefix)?;
            drop(store);
            let reopened = ContractsSessionStoreV1::open_evidence_only(
                temporary.capability()?,
                "sessions",
                evidence_policy,
            )?;
            let continuation = reopened.resume_operational_bp_continuation(
                fixture.trusted_chain_id,
                initial.session_id(),
                initial.terms_hash(),
                &fixture.statement,
                &fixture.capsule,
            )?;
            assert_eq!(
                continuation.chain_id(),
                *fixture.trusted_chain_id.as_bytes()
            );
            assert_eq!(continuation.session_id(), initial.session_id());
            assert_eq!(continuation.terms_hash(), initial.terms_hash());
            assert_eq!(
                continuation.statement_hash(),
                fixture.statement.statement_hash()
            );
            assert_eq!(continuation.session_revision(), terminal.revision());
            assert_eq!(continuation.transcript_hash(), terminal.transcript_hash());
            assert_eq!(continuation.stage(), expected_stage);
            assert_eq!(continuation.accepted_participants(), expected_mask);
            match prefix {
                1 => {
                    continuation.require_common_commitment(
                        0,
                        fixture.payloads[0]
                            .as_slice()
                            .try_into()
                            .map_err(|_| SessionStoreError::Canonical)?,
                    )?;
                    assert!(continuation
                        .require_common_commitment(1, &[0x99; 32])
                        .is_err());
                }
                3 => {
                    continuation.require_common_reveal(
                        0,
                        fixture.payloads[2]
                            .as_slice()
                            .try_into()
                            .map_err(|_| SessionStoreError::Canonical)?,
                    )?;
                }
                5 => {
                    continuation.require_round1_commitment(
                        0,
                        fixture.payloads[4]
                            .as_slice()
                            .try_into()
                            .map_err(|_| SessionStoreError::Canonical)?,
                    )?;
                }
                7 => {
                    let share =
                        BpRound1ShareV1::from_bytes(&fixture.payloads[6], &fixture.statement)?;
                    continuation.require_round1_share(0, &share)?;
                }
                8 | 9 => {
                    continuation.aggregate_round1()?;
                }
                10 => {
                    continuation.into_finalize_aggregates()?;
                }
                11 => {
                    let final_proof = continuation.into_final_proof()?;
                    assert_eq!(final_proof.finalizer_participant_index(), 1);
                    assert_eq!(
                        final_proof.proof_digest(),
                        *blake2b_256(&fixture.payloads[10]).as_bytes()
                    );
                    assert_eq!(
                        final_proof.into_proof().as_bytes(),
                        fixture.payloads[10].as_slice()
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[test]
    fn operational_bp_responder_finalizer_is_accepted_and_competing_finalizer_fails_closed(
    ) -> Result<(), Box<dyn Error>> {
        let fixture = OperationalBpTestFixture::new()?;
        let temporary = TestDirectory::create()?;
        let evidence_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let (store, initial) = operational_bp_store(&temporary, &evidence_policy, &fixture)?;
        let finalized = accept_bp_prefix(&store, &fixture, initial.clone(), 11)?;
        drop(store);
        let reopened = ContractsSessionStoreV1::open_evidence_only(
            temporary.capability()?,
            "sessions",
            evidence_policy,
        )?;
        let responder_final_record = TransportMessageRecordV1::from_bytes(&fs::read(
            temporary
                .path()
                .join("sessions")
                .join(MESSAGES_NAME)
                .join(transport_message_name(
                    initial.session_id(),
                    fixture.participant_ids[1],
                    5,
                    false,
                )),
        )?)?;
        match reopened.accept_transport_message(
            &responder_final_record.signed_bytes,
            &responder_final_record.successor,
            None,
        )? {
            DurableTransportOutcomeV1::Accepted(receipt) => assert!(receipt.duplicate),
            DurableTransportOutcomeV1::EquivocationPersisted => {
                return Err(Box::new(SessionStoreError::Quarantined));
            }
        }
        assert_eq!(
            reopened.load_session(initial.session_id())?.revision(),
            finalized.revision()
        );
        let accepted = reopened.resume_operational_bp_continuation(
            fixture.trusted_chain_id,
            initial.session_id(),
            initial.terms_hash(),
            &fixture.statement,
            &fixture.capsule,
        )?;
        assert_eq!(accepted.stage(), OperationalBpContinuationStageV1::Complete);
        assert_eq!(accepted.accepted_participants(), [false, true]);
        assert_eq!(
            accepted.into_final_proof()?.finalizer_participant_index(),
            1
        );

        let competing = accept_bp_payload(
            &reopened,
            &fixture,
            &finalized,
            0,
            5,
            0x0a,
            &fixture.payloads[10],
        )?;
        assert_eq!(competing.phase(), SessionPhaseV1::OutputFinalized);
        assert!(matches!(
            reopened.resume_operational_bp_continuation(
                fixture.trusted_chain_id,
                initial.session_id(),
                initial.terms_hash(),
                &fixture.statement,
                &fixture.capsule,
            ),
            Err(SessionStoreError::Quarantined)
        ));
        Ok(())
    }

    #[test]
    fn operational_bp_gap_reorder_tamper_equivocation_and_profile_confusion_fail_closed(
    ) -> Result<(), Box<dyn Error>> {
        let fixture = OperationalBpTestFixture::new()?;

        let gap_directory = TestDirectory::create()?;
        let gap_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let (gap_store, gap_initial) = operational_bp_store(&gap_directory, &gap_policy, &fixture)?;
        accept_bp_prefix(&gap_store, &fixture, gap_initial.clone(), 5)?;
        drop(gap_store);
        fs::remove_file(
            gap_directory
                .path()
                .join("sessions")
                .join(MESSAGES_NAME)
                .join(transport_message_name(
                    gap_initial.session_id(),
                    fixture.participant_ids[1],
                    0,
                    false,
                )),
        )?;
        assert!(ContractsSessionStoreV1::open_evidence_only(
            gap_directory.capability()?,
            "sessions",
            gap_policy,
        )
        .is_err());

        let tamper_directory = TestDirectory::create()?;
        let tamper_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let (tamper_store, tamper_initial) =
            operational_bp_store(&tamper_directory, &tamper_policy, &fixture)?;
        accept_bp_prefix(&tamper_store, &fixture, tamper_initial.clone(), 4)?;
        drop(tamper_store);
        let tamper_path = tamper_directory
            .path()
            .join("sessions")
            .join(MESSAGES_NAME)
            .join(transport_message_name(
                tamper_initial.session_id(),
                fixture.participant_ids[0],
                1,
                false,
            ));
        let mut tampered = fs::read(&tamper_path)?;
        tampered[TRANSPORT_MESSAGE_PREFIX_LEN + 20] ^= 0x80;
        fs::write(tamper_path, tampered)?;
        assert!(ContractsSessionStoreV1::open_evidence_only(
            tamper_directory.capability()?,
            "sessions",
            tamper_policy,
        )
        .is_err());

        let reorder_directory = TestDirectory::create()?;
        let reorder_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let (reorder_store, reorder_initial) =
            operational_bp_store(&reorder_directory, &reorder_policy, &fixture)?;
        accept_bp_payload(
            &reorder_store,
            &fixture,
            &reorder_initial,
            1,
            0,
            0x05,
            &fixture.payloads[1],
        )?;
        assert!(reorder_store
            .resume_operational_bp_continuation(
                fixture.trusted_chain_id,
                reorder_initial.session_id(),
                reorder_initial.terms_hash(),
                &fixture.statement,
                &fixture.capsule,
            )
            .is_err());

        let equivocation_directory = TestDirectory::create()?;
        let equivocation_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let (equivocation_store, equivocation_initial) =
            operational_bp_store(&equivocation_directory, &equivocation_policy, &fixture)?;
        let equivocation_current = accept_bp_prefix(
            &equivocation_store,
            &fixture,
            equivocation_initial.clone(),
            2,
        )?;
        let different = transport_signed_bytes(
            &fixture.alice,
            *fixture.trusted_chain_id.as_bytes(),
            equivocation_initial.session_id(),
            fixture.participant_ids[0],
            0,
            equivocation_initial.transcript_hash(),
            0x05,
            &[0x99; 32],
        )?;
        let failed = equivocation_current.advance(
            equivocation_current.revision(),
            SessionPhaseV1::FailedClosed,
            equivocation_current.transcript_hash(),
            equivocation_current.irreversible(),
            equivocation_current.chain(),
            equivocation_current.encrypted_payload(),
        )?;
        assert_eq!(
            equivocation_store.accept_transport_message(
                &different,
                &equivocation_current,
                Some(&failed),
            )?,
            DurableTransportOutcomeV1::EquivocationPersisted
        );
        assert!(equivocation_store
            .resume_operational_bp_continuation(
                fixture.trusted_chain_id,
                equivocation_initial.session_id(),
                equivocation_initial.terms_hash(),
                &fixture.statement,
                &fixture.capsule,
            )
            .is_err());

        let profile_directory = TestDirectory::create()?;
        let profile_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let (profile_store, profile_initial) =
            operational_bp_store(&profile_directory, &profile_policy, &fixture)?;
        let profile_current =
            accept_bp_prefix(&profile_store, &fixture, profile_initial.clone(), 6)?;
        let mut confused_share = fixture.payloads[6].clone();
        confused_share[6] ^= 0x01;
        accept_bp_payload(
            &profile_store,
            &fixture,
            &profile_current,
            0,
            3,
            0x08,
            &confused_share,
        )?;
        assert!(profile_store
            .resume_operational_bp_continuation(
                fixture.trusted_chain_id,
                profile_initial.session_id(),
                profile_initial.terms_hash(),
                &fixture.statement,
                &fixture.capsule,
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn operational_bp_terms_capsule_and_m8_vote_boundaries_are_fail_closed(
    ) -> Result<(), Box<dyn Error>> {
        let fixture = OperationalBpTestFixture::new()?;
        let temporary = TestDirectory::create()?;
        let evidence_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let (store, initial) = operational_bp_store(&temporary, &evidence_policy, &fixture)?;
        accept_bp_prefix(&store, &fixture, initial.clone(), 8)?;
        assert!(store
            .resume_operational_bp_continuation(
                fixture.trusted_chain_id,
                initial.session_id(),
                [0x98; 32],
                &fixture.statement,
                &fixture.capsule,
            )
            .is_err());
        let mut wrong_capsule_bytes = *fixture.capsule.as_bytes();
        wrong_capsule_bytes[16] ^= 0x01;
        let wrong_capsule = RecoveryCapsule::from_bytes(&wrong_capsule_bytes)?;
        assert!(store
            .resume_operational_bp_continuation(
                fixture.trusted_chain_id,
                initial.session_id(),
                initial.terms_hash(),
                &fixture.statement,
                &wrong_capsule,
            )
            .is_err());

        let m8_directory = TestDirectory::create()?;
        let m8_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let m8_store = ContractsSessionStoreV1::create_evidence_only(
            m8_directory.capability()?,
            "sessions",
            m8_policy.clone(),
        )
        .map_err(|error| format!("create M.8 Store: {error}"))?;
        let m8_current = record(SessionPhaseV1::RefundSigned)?;
        m8_store
            .create_session(&m8_current)
            .map_err(|error| format!("create M.8 session: {error}"))?;
        let backup_receipt_hash = [0xb8; 32];
        let input_blinding = scalar(3)?.add(&scalar(5)?)?;
        let kernel_blinding = scalar(13)?;
        let output_blinding = input_blinding.add(&kernel_blinding)?;
        let input_commitment = Commitment::commit(42, &input_blinding);
        assert_eq!(
            input_commitment.as_bytes(),
            &fixture
                .statement
                .aggregate_commitment()
                .to_compressed_bytes()
        );
        let output_commitment = Commitment::commit(40, &output_blinding);
        let (proof, _) = dom_crypto::bp2_prove(40, &output_blinding)?;
        let kernel_secret = SecretKey::from_bytes(kernel_blinding.as_bytes())?;
        let refund_unlock_height = 500;
        let refund_transaction = Transaction {
            inputs: vec![TransactionInput {
                commitment: input_commitment,
            }],
            outputs: vec![TransactionOutput {
                commitment: output_commitment,
                proof,
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_HEIGHT_LOCKED,
                fee: Amount::from_noms(2)?,
                lock_height: refund_unlock_height,
                excess: Commitment::commit(0, &kernel_blinding),
                excess_signature: schnorr_sign(
                    &kernel_secret,
                    &kernel_message(KERNEL_FEAT_HEIGHT_LOCKED, 2, refund_unlock_height),
                    fixture.trusted_chain_id.as_bytes(),
                )?
                .to_bytes(),
            }],
            offset: [0; 32],
        };
        let refund_bytes = refund_transaction.to_bytes()?;
        let (refund_template_bytes, refund_template_hash) =
            canonical_template_v1(&refund_transaction)?;
        let parsed_template = parse_canonical_dom_template_v1(&refund_template_bytes)?;
        assert_eq!(
            canonical_template_v1(&parsed_template)?,
            (refund_template_bytes.clone(), refund_template_hash)
        );
        let mut tampered_template = refund_template_bytes.clone();
        tampered_template[0] ^= 0x01;
        assert!(parse_canonical_dom_template_v1(&tampered_template).is_err());
        assert!(parse_canonical_dom_template_v1(
            &refund_template_bytes[..refund_template_bytes.len() - 1]
        )
        .is_err());
        let mut trailing_template = refund_template_bytes.clone();
        trailing_template.push(0);
        assert!(parse_canonical_dom_template_v1(&trailing_template).is_err());
        let vote_payload;
        {
            let prepared = m8_store
                .prepare_operational_m8_funding_gate_authority(
                    VerifiedOperationalM8FundingGateEvidenceV1 {
                        session_id: m8_current.session_id(),
                        terms_hash: m8_current.terms_hash(),
                        m8_policy_digest: [0x81; 32],
                        chain_id: *fixture.trusted_chain_id.as_bytes(),
                        claim_template_hash: refund_template_hash,
                        claim_adaptor_point: fixture.bob.public_key(),
                        refund_template_hash,
                        bp_statement_hash: fixture.statement.statement_hash(),
                        recovery_binding_hash: *fixture.statement.recovery_binding_hash(),
                        shared_output_commitment: fixture
                            .statement
                            .aggregate_commitment()
                            .to_compressed_bytes(),
                        refund_unlock_height,
                        validation_height: 100,
                        now_unix_seconds: 1_700_000_000,
                        refund_tx_hash: *blake2b_256(&refund_bytes).as_bytes(),
                        refund_bytes,
                        claim_template_bytes: refund_template_bytes.clone(),
                        refund_template_bytes,
                        bp_statement_bytes: fixture.statement.to_bytes().to_vec(),
                        backup_receipt_hash,
                    },
                )
                .map_err(|error| format!("prepare M.8 funding gate: {error}"))?;
            vote_payload = prepared.ready_to_fund_vote_payload();
            assert_ne!(vote_payload, [0; 32]);
            assert_ne!(vote_payload, backup_receipt_hash);
        }
        drop(m8_store);

        let reopened_m8_store = ContractsSessionStoreV1::open_evidence_only(
            m8_directory.capability()?,
            "sessions",
            m8_policy,
        )
        .map_err(|error| format!("reopen M.8 Store: {error}"))?;
        let reopened_prepared = reopened_m8_store
            .resume_operational_m8_funding_gate_authority(m8_current.session_id())
            .map_err(|error| format!("resume M.8 funding gate: {error}"))?;
        assert_eq!(reopened_prepared.ready_to_fund_vote_payload(), vote_payload);
        Ok(())
    }

    #[test]
    fn create_load_cas_reorg_and_restart_are_exact() -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let store = ContractsSessionStoreV1::create_evidence_only(
            temporary.capability()?,
            "sessions",
            policy.clone(),
        )?;
        let initial = record(SessionPhaseV1::Created)?;
        assert_eq!(
            store.create_session(&initial)?.as_bytes(),
            initial.as_bytes()
        );
        let terms = initial.advance(
            0,
            SessionPhaseV1::TermsCommitted,
            [0x44; 32],
            initial.irreversible(),
            initial.chain(),
            initial.encrypted_payload(),
        )?;
        let durable = store.advance_session(0, &terms)?;
        assert_eq!(durable.as_bytes(), terms.as_bytes());
        assert!(matches!(
            store.advance_session(0, &terms),
            Err(SessionStoreError::Conflict)
        ));
        let reorged = store.update_chain_projection(initial.session_id(), 1, projection(90))?;
        assert_eq!(reorged.phase(), terms.phase());
        assert_eq!(reorged.transcript_hash(), terms.transcript_hash());
        assert_eq!(reorged.irreversible(), terms.irreversible());
        assert_eq!(reorged.encrypted_payload(), terms.encrypted_payload());
        assert_eq!(reorged.chain(), projection(90));
        drop(store);
        let reopened = ContractsSessionStoreV1::open_evidence_only(
            temporary.capability()?,
            "sessions",
            policy,
        )?;
        assert_eq!(
            reopened.load_session(initial.session_id())?.as_bytes(),
            reorged.as_bytes()
        );
        Ok(())
    }

    #[test]
    fn funding_is_persisted_consumed_and_returned_byte_identically() -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let store = ContractsSessionStoreV1::create_evidence_only(
            temporary.capability()?,
            "sessions",
            policy.clone(),
        )?;
        let current = record(SessionPhaseV1::ClaimPrepared)?;
        store.create_session(&current)?;
        let (ready, broadcast) = funding_successors(&current)?;
        let authorization =
            store.issue_funding_authorization(0, &ready, verified_for_test(&current))?;
        assert_eq!(
            store.load_session(current.session_id())?.as_bytes(),
            ready.as_bytes()
        );
        let outbound = store.consume_funding_authorization(authorization, &broadcast)?;
        assert_eq!(outbound.as_bytes(), b"exact-funding-test-bytes");
        assert_eq!(
            store
                .resend_funding_broadcast(current.session_id())?
                .as_bytes(),
            outbound.as_bytes()
        );
        assert_eq!(
            store.load_session(current.session_id())?.as_bytes(),
            broadcast.as_bytes()
        );
        drop(store);
        let reopened = ContractsSessionStoreV1::open_evidence_only(
            temporary.capability()?,
            "sessions",
            policy,
        )?;
        assert_eq!(
            reopened
                .resend_funding_broadcast(current.session_id())?
                .as_bytes(),
            outbound.as_bytes()
        );
        assert!(matches!(
            reopened.issue_funding_authorization(0, &ready, verified_for_test(&current)),
            Err(SessionStoreError::Conflict)
        ));
        Ok(())
    }

    #[test]
    fn concurrent_funding_issuance_has_exactly_one_winner() -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let store = Arc::new(ContractsSessionStoreV1::create_evidence_only(
            temporary.capability()?,
            "sessions",
            policy(BudgetPolicyProfileV1::EvidenceOnly)?,
        )?);
        let current = record(SessionPhaseV1::ClaimPrepared)?;
        store.create_session(&current)?;
        let (ready, _) = funding_successors(&current)?;
        let successes = thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..8 {
                let store = Arc::clone(&store);
                let current = current.clone();
                let ready = ready.clone();
                handles.push(scope.spawn(move || {
                    store
                        .issue_funding_authorization(0, &ready, verified_for_test(&current))
                        .is_ok()
                }));
            }
            handles
                .into_iter()
                .filter_map(|handle| handle.join().ok())
                .filter(|success| *success)
                .count()
        });
        assert_eq!(successes, 1);
        assert_eq!(
            store.load_session(current.session_id())?.phase(),
            SessionPhaseV1::FundingAuthorized
        );
        Ok(())
    }

    #[test]
    fn production_constructors_reject_evidence_policy_and_bind_exact_bytes(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let evidence = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        assert!(matches!(
            ContractsSessionStoreV1::create_production(
                temporary.capability()?,
                "rejected",
                evidence
            ),
            Err(SessionStoreError::PolicyProfile)
        ));
        let production = policy(BudgetPolicyProfileV1::ProductionRatified)?;
        let store = ContractsSessionStoreV1::create_production(
            temporary.capability()?,
            "production",
            production.clone(),
        )?;
        assert_eq!(store.policy().as_bytes(), production.as_bytes());
        drop(store);
        let reopened = ContractsSessionStoreV1::open_production(
            temporary.capability()?,
            "production",
            production.clone(),
        )?;
        assert_eq!(reopened.policy().as_bytes(), production.as_bytes());
        Ok(())
    }

    #[test]
    fn nonce_vault_production_composition_requires_and_reopens_with_explicit_policy(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let production = policy(BudgetPolicyProfileV1::ProductionRatified)?;
        let passphrase = Passphrase::new(b"public-production-composition-test".to_vec())?;
        let vault = ContractsNonceVaultV1::create_production(
            temporary.capability()?,
            "nonce-vault",
            generate_storage_ids()?,
            &passphrase,
            production.clone(),
        )?;
        drop(vault);
        let reopened = ContractsNonceVaultV1::open_production(
            temporary.capability()?,
            "nonce-vault",
            passphrase,
            production,
        )?;
        drop(reopened);
        Ok(())
    }

    #[test]
    fn malformed_or_noncanonical_dom_artifacts_fail_closed() {
        let context = DomTransactionValidationContextV1::new(10, [0x51; 32], 1_700_000_000);
        assert!(matches!(
            verify_funding_artifacts_v1(
                [0x11; 32],
                [0x12; 32],
                100,
                b"not-a-dom-refund",
                b"not-a-dom-funding",
                context,
            ),
            Err(SessionStoreError::InvalidDomTransaction)
        ));
    }

    #[test]
    fn pinned_dom_verifier_issues_artifacts_for_real_canonical_transactions(
    ) -> Result<(), Box<dyn Error>> {
        let chain_id = [0x51; 32];
        let refund = real_dom_transaction_bytes(
            KERNEL_FEAT_HEIGHT_LOCKED,
            100,
            2_000,
            1_980,
            10,
            11,
            &chain_id,
        )?;
        let funding =
            real_dom_transaction_bytes(KERNEL_FEAT_PLAIN, 0, 1_000, 990, 12, 13, &chain_id)?;
        let current = record(SessionPhaseV1::ClaimPrepared)?;
        let verified = verify_funding_artifacts_v1(
            current.session_id(),
            current.terms_hash(),
            100,
            &refund,
            &funding,
            DomTransactionValidationContextV1::new(10, chain_id, 1_700_000_000),
        )?;
        assert_eq!(verified.refund_bytes, refund);
        assert_eq!(verified.funding_bytes, funding);
        Ok(())
    }

    #[test]
    fn mature_refund_loads_exact_persisted_dom_bytes_after_restart() -> Result<(), Box<dyn Error>> {
        let chain_id = [0x51; 32];
        let refund = real_dom_transaction_bytes(
            KERNEL_FEAT_HEIGHT_LOCKED,
            100,
            2_000,
            1_980,
            10,
            11,
            &chain_id,
        )?;
        let funding =
            real_dom_transaction_bytes(KERNEL_FEAT_PLAIN, 0, 1_000, 990, 12, 13, &chain_id)?;
        let temporary = TestDirectory::create()?;
        let evidence_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let store = ContractsSessionStoreV1::create_evidence_only(
            temporary.capability()?,
            "sessions",
            evidence_policy.clone(),
        )?;
        let current = record(SessionPhaseV1::ClaimPrepared)?;
        store.create_session(&current)?;
        let verified = verify_funding_artifacts_v1(
            current.session_id(),
            current.terms_hash(),
            100,
            &refund,
            &funding,
            DomTransactionValidationContextV1::new(10, chain_id, 1_700_000_000),
        )?;
        let (ready, broadcast) = funding_successors(&current)?;
        let authorization = store.issue_funding_authorization(0, &ready, verified)?;
        let _funding = store.consume_funding_authorization(authorization, &broadcast)?;
        let confirmed = broadcast.advance(
            broadcast.revision(),
            SessionPhaseV1::FundingConfirmed,
            [0x43; 32],
            broadcast.irreversible(),
            broadcast.chain(),
            broadcast.encrypted_payload(),
        )?;
        store.advance_session(broadcast.revision(), &confirmed)?;
        let eligible = confirmed.advance(
            confirmed.revision(),
            SessionPhaseV1::RefundEligible,
            [0x44; 32],
            confirmed.irreversible(),
            confirmed.chain(),
            confirmed.encrypted_payload(),
        )?;
        store.advance_session(confirmed.revision(), &eligible)?;
        assert!(matches!(
            store.load_refund_broadcast(
                current.session_id(),
                DomTransactionValidationContextV1::new(99, chain_id, 1_700_000_000)
            ),
            Err(SessionStoreError::InvalidDomTransaction)
        ));
        drop(store);
        let reopened = ContractsSessionStoreV1::open_evidence_only(
            temporary.capability()?,
            "sessions",
            evidence_policy,
        )?;
        let outbound = reopened.load_refund_broadcast(
            current.session_id(),
            DomTransactionValidationContextV1::new(100, chain_id, 1_700_000_000),
        )?;
        assert_eq!(outbound.as_bytes(), refund);
        Ok(())
    }

    #[test]
    fn durable_transport_survives_restart_duplicate_reorder_and_equivocation(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let evidence_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let store = ContractsSessionStoreV1::create_evidence_only(
            temporary.capability()?,
            "sessions",
            evidence_policy.clone(),
        )?;
        let initial = record(SessionPhaseV1::Created)?;
        store.create_session(&initial)?;
        let alice = SecretKey::from_bytes(&[0x11; 32])?;
        let bob = SecretKey::from_bytes(&[0x12; 32])?;
        let alice_id = [0xa1; 32];
        let bob_id = [0xb2; 32];
        let chain_id = [0xc3; 32];
        store.bind_transport_roster(
            initial.session_id(),
            chain_id,
            [
                SessionTransportParticipantV1::new(
                    alice_id,
                    alice.public_key(),
                    DirectionV1::Initiator,
                )?,
                SessionTransportParticipantV1::new(
                    bob_id,
                    bob.public_key(),
                    DirectionV1::Responder,
                )?,
            ],
        )?;
        store.bind_transport_identity_references(
            initial.session_id(),
            [
                SessionTransportIdentityReferenceV1::new(
                    alice_id,
                    [0x31; 32],
                    [0x41; 32],
                    alice.public_key(),
                )?,
                SessionTransportIdentityReferenceV1::new(
                    bob_id,
                    [0x32; 32],
                    [0x42; 32],
                    bob.public_key(),
                )?,
            ],
        )?;
        let offer = transport_signed_bytes(
            &alice,
            chain_id,
            initial.session_id(),
            alice_id,
            0,
            initial.transcript_hash(),
            0x01,
            b"offer",
        )?;
        let envelope = ParsedTransportEnvelopeV1::parse(&offer)?;
        let transcript = transport_transcript_hash(
            &initial.transcript_hash(),
            &envelope.message_digest,
            DirectionV1::Initiator,
            SessionPhaseV1::Created,
        );
        let successor = initial.advance(
            0,
            SessionPhaseV1::Created,
            transcript,
            initial.irreversible(),
            initial.chain(),
            initial.encrypted_payload(),
        )?;
        let first = store.accept_transport_message(&offer, &successor, None)?;
        let first_receipt = match first {
            DurableTransportOutcomeV1::Accepted(receipt) => receipt,
            DurableTransportOutcomeV1::EquivocationPersisted => {
                return Err(Box::new(SessionStoreError::Quarantined));
            }
        };
        assert!(!first_receipt.duplicate);
        drop(store);
        let reopened = ContractsSessionStoreV1::open_evidence_only(
            temporary.capability()?,
            "sessions",
            evidence_policy,
        )?;
        let duplicate = reopened.accept_transport_message(&offer, &successor, None)?;
        let duplicate_receipt = match duplicate {
            DurableTransportOutcomeV1::Accepted(receipt) => receipt,
            DurableTransportOutcomeV1::EquivocationPersisted => {
                return Err(Box::new(SessionStoreError::Quarantined));
            }
        };
        assert!(duplicate_receipt.duplicate);
        assert_eq!(
            duplicate_receipt.message_digest,
            first_receipt.message_digest
        );
        assert_eq!(
            duplicate_receipt.transcript_hash,
            first_receipt.transcript_hash
        );

        let gap = transport_signed_bytes(
            &alice,
            chain_id,
            initial.session_id(),
            alice_id,
            2,
            successor.transcript_hash(),
            0x01,
            b"gap",
        )?;
        let gap_envelope = ParsedTransportEnvelopeV1::parse(&gap)?;
        let gap_successor = successor.advance(
            1,
            SessionPhaseV1::Created,
            transport_transcript_hash(
                &successor.transcript_hash(),
                &gap_envelope.message_digest,
                DirectionV1::Initiator,
                SessionPhaseV1::Created,
            ),
            successor.irreversible(),
            successor.chain(),
            successor.encrypted_payload(),
        )?;
        assert!(matches!(
            reopened.accept_transport_message(&gap, &gap_successor, None),
            Err(SessionStoreError::InvalidTransition)
        ));

        let different = transport_signed_bytes(
            &alice,
            chain_id,
            initial.session_id(),
            alice_id,
            0,
            initial.transcript_hash(),
            0x01,
            b"different",
        )?;
        let failed = successor.advance(
            1,
            SessionPhaseV1::FailedClosed,
            successor.transcript_hash(),
            successor.irreversible(),
            successor.chain(),
            successor.encrypted_payload(),
        )?;
        assert_eq!(
            reopened.accept_transport_message(&different, &successor, Some(&failed))?,
            DurableTransportOutcomeV1::EquivocationPersisted
        );
        assert_eq!(
            reopened.load_session(initial.session_id())?.phase(),
            SessionPhaseV1::FailedClosed
        );
        Ok(())
    }

    #[test]
    fn contracts_identity_public_references_survive_restart_and_tamper_fails_closed(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let evidence_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let store = ContractsSessionStoreV1::create_evidence_only(
            temporary.capability()?,
            "sessions",
            evidence_policy.clone(),
        )?;
        let initial = record(SessionPhaseV1::Created)?;
        store.create_session(&initial)?;
        let alice = SecretKey::from_bytes(&[0x21; 32])?;
        let bob = SecretKey::from_bytes(&[0x22; 32])?;
        let alice_id = [0xa1; 32];
        let bob_id = [0xb2; 32];
        let chain_id = [0xc3; 32];
        store.bind_transport_roster(
            initial.session_id(),
            chain_id,
            [
                SessionTransportParticipantV1::new(
                    alice_id,
                    alice.public_key(),
                    DirectionV1::Initiator,
                )?,
                SessionTransportParticipantV1::new(
                    bob_id,
                    bob.public_key(),
                    DirectionV1::Responder,
                )?,
            ],
        )?;
        let wrong_identity = SecretKey::from_bytes(&[0x23; 32])?;
        assert!(matches!(
            store.bind_transport_identity_references(
                initial.session_id(),
                [
                    SessionTransportIdentityReferenceV1::new(
                        alice_id,
                        [0x31; 32],
                        [0x41; 32],
                        wrong_identity.public_key(),
                    )?,
                    SessionTransportIdentityReferenceV1::new(
                        bob_id,
                        [0x32; 32],
                        [0x42; 32],
                        bob.public_key(),
                    )?,
                ]
            ),
            Err(SessionStoreError::Canonical)
        ));
        store.bind_transport_identity_references(
            initial.session_id(),
            [
                SessionTransportIdentityReferenceV1::new(
                    alice_id,
                    [0x31; 32],
                    [0x41; 32],
                    alice.public_key(),
                )?,
                SessionTransportIdentityReferenceV1::new(
                    bob_id,
                    [0x32; 32],
                    [0x42; 32],
                    bob.public_key(),
                )?,
            ],
        )?;
        let loaded = store.transport_identity_references(initial.session_id())?;
        assert_eq!(loaded[0].key_reference(), &[0x31; 32]);
        assert_eq!(loaded[1].noise_public_key(), &[0x42; 32]);
        drop(store);

        let reopened = ContractsSessionStoreV1::open_evidence_only(
            temporary.capability()?,
            "sessions",
            evidence_policy.clone(),
        )?;
        let loaded = reopened.transport_identity_references(initial.session_id())?;
        assert_eq!(loaded[0].participant_id(), &alice_id);
        assert_eq!(loaded[1].schnorr_public_key(), &bob.public_key());
        drop(reopened);

        let path = temporary
            .path()
            .join("sessions")
            .join(ROSTERS_NAME)
            .join(transport_identity_binding_name(initial.session_id()));
        let mut bytes = fs::read(&path)?;
        bytes[96] ^= 0x80;
        fs::write(path, bytes)?;
        assert!(matches!(
            ContractsSessionStoreV1::open_evidence_only(
                temporary.capability()?,
                "sessions",
                evidence_policy
            ),
            Err(SessionStoreError::Quarantined)
        ));
        Ok(())
    }

    #[test]
    fn transport_crash_cuts_recover_before_duplicate_ack() -> Result<(), Box<dyn Error>> {
        for cut in [
            "transport-after-message-persist",
            "transport-after-session-persist",
        ] {
            let temporary = TestDirectory::create()?;
            let evidence_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
            let store = ContractsSessionStoreV1::create_evidence_only(
                temporary.capability()?,
                "sessions",
                evidence_policy.clone(),
            )?;
            let initial = record(SessionPhaseV1::Created)?;
            store.create_session(&initial)?;
            let alice = SecretKey::from_bytes(&[0x11; 32])?;
            let bob = SecretKey::from_bytes(&[0x12; 32])?;
            let alice_id = [0xa1; 32];
            let bob_id = [0xb2; 32];
            let chain_id = [0xc3; 32];
            store.bind_transport_roster(
                initial.session_id(),
                chain_id,
                [
                    SessionTransportParticipantV1::new(
                        alice_id,
                        alice.public_key(),
                        DirectionV1::Initiator,
                    )?,
                    SessionTransportParticipantV1::new(
                        bob_id,
                        bob.public_key(),
                        DirectionV1::Responder,
                    )?,
                ],
            )?;
            store.bind_transport_identity_references(
                initial.session_id(),
                [
                    SessionTransportIdentityReferenceV1::new(
                        alice_id,
                        [0x31; 32],
                        [0x41; 32],
                        alice.public_key(),
                    )?,
                    SessionTransportIdentityReferenceV1::new(
                        bob_id,
                        [0x32; 32],
                        [0x42; 32],
                        bob.public_key(),
                    )?,
                ],
            )?;
            drop(store);

            let marker = temporary.path().join(format!("{cut}.marker"));
            let status = Command::new(std::env::current_exe()?)
                .arg("--ignored")
                .arg("--exact")
                .arg("runtime::linux::session_store::tests::transport_crash_child")
                .env("DOM_F7_SESSION_STORE_PARENT", temporary.path())
                .env("DOM_F7_SESSION_STORE_CRASH_CUT", cut)
                .env("DOM_F7_SESSION_STORE_CRASH_MARKER", &marker)
                .status()?;
            assert!(!status.success());
            assert_eq!(fs::read(&marker)?, cut.as_bytes());

            let reopened = ContractsSessionStoreV1::open_evidence_only(
                temporary.capability()?,
                "sessions",
                evidence_policy,
            )?;
            let durable = reopened.load_session(initial.session_id())?;
            assert_eq!(durable.revision(), 1);
            assert_eq!(durable.phase(), SessionPhaseV1::Created);
            let offer = transport_signed_bytes(
                &alice,
                chain_id,
                initial.session_id(),
                alice_id,
                0,
                initial.transcript_hash(),
                0x01,
                b"crash-durable-offer",
            )?;
            let outcome = reopened.accept_transport_message(&offer, &durable, None)?;
            match outcome {
                DurableTransportOutcomeV1::Accepted(receipt) => assert!(receipt.duplicate),
                DurableTransportOutcomeV1::EquivocationPersisted => {
                    return Err(Box::new(SessionStoreError::Quarantined));
                }
            }
        }
        Ok(())
    }

    #[test]
    #[ignore = "subprocess helper invoked by transport_crash_cuts_recover_before_duplicate_ack"]
    fn transport_crash_child() -> Result<(), Box<dyn Error>> {
        let parent =
            std::env::var_os("DOM_F7_SESSION_STORE_PARENT").ok_or(SessionStoreError::Filesystem)?;
        let capability = Arc::new(Dir::from_std_file(File::open(parent)?));
        let store = ContractsSessionStoreV1::open_evidence_only(
            capability,
            "sessions",
            policy(BudgetPolicyProfileV1::EvidenceOnly)?,
        )?;
        let initial = store.load_session([0x31; 32])?;
        let alice = SecretKey::from_bytes(&[0x11; 32])?;
        let offer = transport_signed_bytes(
            &alice,
            [0xc3; 32],
            initial.session_id(),
            [0xa1; 32],
            0,
            initial.transcript_hash(),
            0x01,
            b"crash-durable-offer",
        )?;
        let envelope = ParsedTransportEnvelopeV1::parse(&offer)?;
        let successor = initial.advance(
            initial.revision(),
            SessionPhaseV1::Created,
            transport_transcript_hash(
                &initial.transcript_hash(),
                &envelope.message_digest,
                DirectionV1::Initiator,
                SessionPhaseV1::Created,
            ),
            initial.irreversible(),
            initial.chain(),
            initial.encrypted_payload(),
        )?;
        let _outcome = store.accept_transport_message(&offer, &successor, None)?;
        Err(Box::new(SessionStoreError::Quarantined))
    }

    #[test]
    fn authorization_from_an_old_open_instance_is_rejected_after_restart(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let store = ContractsSessionStoreV1::create_evidence_only(
            temporary.capability()?,
            "sessions",
            policy.clone(),
        )?;
        let current = record(SessionPhaseV1::ClaimPrepared)?;
        store.create_session(&current)?;
        let (ready, broadcast) = funding_successors(&current)?;
        let authorization =
            store.issue_funding_authorization(0, &ready, verified_for_test(&current))?;
        drop(store);
        let reopened = ContractsSessionStoreV1::open_evidence_only(
            temporary.capability()?,
            "sessions",
            policy,
        )?;
        assert!(matches!(
            reopened.consume_funding_authorization(authorization, &broadcast),
            Err(SessionStoreError::FundingAuthorityUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn tampered_artifact_quarantines_restart() -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let store = ContractsSessionStoreV1::create_evidence_only(
            temporary.capability()?,
            "sessions",
            policy.clone(),
        )?;
        let current = record(SessionPhaseV1::ClaimPrepared)?;
        store.create_session(&current)?;
        let (ready, _) = funding_successors(&current)?;
        let _authorization =
            store.issue_funding_authorization(0, &ready, verified_for_test(&current))?;
        drop(store);
        let path = temporary
            .path()
            .join("sessions/session-artifacts")
            .join(artifact_name(current.session_id()));
        let mut bytes = fs::read(&path)?;
        let last = bytes.last_mut().ok_or(SessionStoreError::Quarantined)?;
        *last ^= 0x01;
        fs::write(path, bytes)?;
        assert!(matches!(
            ContractsSessionStoreV1::open_evidence_only(
                temporary.capability()?,
                "sessions",
                policy
            ),
            Err(SessionStoreError::Quarantined)
        ));
        Ok(())
    }

    #[test]
    fn retained_lock_excludes_a_second_process() -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let _store = ContractsSessionStoreV1::create_evidence_only(
            temporary.capability()?,
            "sessions",
            policy,
        )?;
        let status = Command::new(std::env::current_exe()?)
            .arg("--ignored")
            .arg("--exact")
            .arg("runtime::linux::session_store::tests::busy_lock_child")
            .env("DOM_F7_SESSION_STORE_PARENT", temporary.path())
            .status()?;
        assert!(status.success());
        Ok(())
    }

    #[test]
    #[ignore = "subprocess helper invoked by retained_lock_excludes_a_second_process"]
    fn busy_lock_child() -> Result<(), Box<dyn Error>> {
        let parent =
            std::env::var_os("DOM_F7_SESSION_STORE_PARENT").ok_or(SessionStoreError::Filesystem)?;
        let capability = Arc::new(Dir::from_std_file(File::open(parent)?));
        assert!(matches!(
            ContractsSessionStoreV1::open_evidence_only(
                capability,
                "sessions",
                policy(BudgetPolicyProfileV1::EvidenceOnly)?
            ),
            Err(SessionStoreError::StoreBusy)
        ));
        Ok(())
    }

    #[test]
    fn crash_cuts_are_fail_safe_and_restart_authenticates_the_prefix() -> Result<(), Box<dyn Error>>
    {
        for cut in [
            "issue-after-artifact-persist",
            "issue-after-session-persist",
            "consume-after-retirement-persist",
            "consume-after-session-persist",
        ] {
            let temporary = TestDirectory::create()?;
            let evidence_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
            let store = ContractsSessionStoreV1::create_evidence_only(
                temporary.capability()?,
                "sessions",
                evidence_policy.clone(),
            )?;
            let current = record(SessionPhaseV1::ClaimPrepared)?;
            store.create_session(&current)?;
            drop(store);
            let marker = temporary.path().join(format!("{cut}.marker"));
            let status = Command::new(std::env::current_exe()?)
                .arg("--ignored")
                .arg("--exact")
                .arg("runtime::linux::session_store::tests::crash_cut_child")
                .env("DOM_F7_SESSION_STORE_PARENT", temporary.path())
                .env("DOM_F7_SESSION_STORE_CRASH_CUT", cut)
                .env("DOM_F7_SESSION_STORE_CRASH_MARKER", &marker)
                .status()?;
            assert!(!status.success());
            assert_eq!(fs::read(&marker)?, cut.as_bytes());
            let reopened = ContractsSessionStoreV1::open_evidence_only(
                temporary.capability()?,
                "sessions",
                evidence_policy,
            )?;
            let durable = reopened.load_session(current.session_id())?;
            let expected_phase = match cut {
                "issue-after-artifact-persist" => SessionPhaseV1::ClaimPrepared,
                "issue-after-session-persist" => SessionPhaseV1::FundingAuthorized,
                "consume-after-retirement-persist" => SessionPhaseV1::FundingBroadcast,
                "consume-after-session-persist" => SessionPhaseV1::FundingBroadcast,
                _ => return Err(Box::new(SessionStoreError::Quarantined)),
            };
            assert_eq!(durable.phase(), expected_phase);
            if cut == "issue-after-artifact-persist" {
                let (ready, _) = funding_successors(&current)?;
                assert!(reopened
                    .issue_funding_authorization(0, &ready, verified_for_test(&current))
                    .is_ok());
            }
            if cut.starts_with("consume-") {
                assert_eq!(
                    reopened
                        .resend_funding_broadcast(current.session_id())?
                        .as_bytes(),
                    b"exact-funding-test-bytes"
                );
            }
        }
        Ok(())
    }

    #[test]
    #[ignore = "subprocess helper invoked by crash_cuts_are_fail_safe_and_restart_authenticates_the_prefix"]
    fn crash_cut_child() -> Result<(), Box<dyn Error>> {
        let parent =
            std::env::var_os("DOM_F7_SESSION_STORE_PARENT").ok_or(SessionStoreError::Filesystem)?;
        let cut = std::env::var("DOM_F7_SESSION_STORE_CRASH_CUT")?;
        let capability = Arc::new(Dir::from_std_file(File::open(parent)?));
        let store = ContractsSessionStoreV1::open_evidence_only(
            capability,
            "sessions",
            policy(BudgetPolicyProfileV1::EvidenceOnly)?,
        )?;
        let current = store.load_session([0x31; 32])?;
        let (ready, broadcast) = funding_successors(&current)?;
        let authorization =
            store.issue_funding_authorization(0, &ready, verified_for_test(&current))?;
        if cut.starts_with("consume-") {
            let _outbound = store.consume_funding_authorization(authorization, &broadcast)?;
        }
        Err(Box::new(SessionStoreError::Quarantined))
    }

    #[test]
    fn stale_and_forged_successors_cannot_bypass_funding_gate() -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let store = ContractsSessionStoreV1::create_evidence_only(
            temporary.capability()?,
            "sessions",
            policy(BudgetPolicyProfileV1::EvidenceOnly)?,
        )?;
        let current = record(SessionPhaseV1::ClaimPrepared)?;
        store.create_session(&current)?;
        let (ready, _) = funding_successors(&current)?;
        assert!(matches!(
            store.advance_session(0, &ready),
            Err(SessionStoreError::InvalidTransition)
        ));
        let shortcut = current.advance(
            0,
            SessionPhaseV1::Refunded,
            [0x99; 32],
            current.irreversible(),
            current.chain(),
            b"different-payload",
        )?;
        assert!(matches!(
            store.advance_session(0, &shortcut),
            Err(SessionStoreError::InvalidTransition)
        ));
        let aborted = current.advance(
            0,
            SessionPhaseV1::Aborted,
            [0x98; 32],
            current.irreversible(),
            current.chain(),
            b"sealed-abort-payload",
        )?;
        assert!(store.advance_session(0, &aborted).is_ok());
        assert!(matches!(
            store.update_chain_projection(current.session_id(), 0, projection(1)),
            Err(SessionStoreError::Conflict)
        ));
        Ok(())
    }

    #[test]
    fn post_anchor_claim_authorization_codec_is_linear_exact_and_tamper_evident(
    ) -> Result<(), Box<dyn Error>> {
        let current = record(SessionPhaseV1::ClaimPrepared)?;
        let (_, broadcast) = funding_successors(&current)?;
        let confirmed = broadcast.advance(
            broadcast.revision(),
            SessionPhaseV1::FundingConfirmed,
            [0x43; 32],
            broadcast.irreversible(),
            broadcast.chain(),
            broadcast.encrypted_payload(),
        )?;
        let adaptor_secret = SecretKey::from_bytes(&[0x17; 32])?;
        let adaptor_point = adaptor_secret.public_key();
        let shared_output = Commitment::commit(41, &scalar(0x18)?);
        let evidence = PostAnchorDomClaimSigningEvidenceV1 {
            chain_id: [0x71; 32],
            session_id: confirmed.session_id(),
            settlement_id: [0x81; 32],
            terms_hash: confirmed.terms_hash(),
            m8_policy_digest: [0x80; 32],
            m8_anchor_evidence_digest: [0x82; 32],
            dom_funding_id: [0x8a; 32],
            bitcoin_funding_id: [0x8b; 32],
            dom_shared_output_commitment: *shared_output.as_bytes(),
            expected_claim_template_hash: [0x83; 32],
            expected_round_start_transcript_hash: [0x84; 32],
            expected_adaptor_point: adaptor_point.clone(),
            dom_confirmation_depth: 6,
            bitcoin_confirmation_depth: 7,
        };
        let issued = PostAnchorClaimAuthorizationRecordV1::new_issued(
            &evidence, &confirmed, [0x85; 32], [0x86; 32], [0x87; 32], [0x88; 32],
        )?;
        let reparsed = PostAnchorClaimAuthorizationRecordV1::from_bytes(&issued.bytes)?;
        assert_eq!(reparsed.bytes, issued.bytes);
        assert!(reparsed.matches_evidence(&evidence));
        let capability = reparsed.issued_capability([0x89; 32])?;
        assert_eq!(capability.session_id(), &confirmed.session_id());
        assert_eq!(capability.m8_anchor_evidence_digest(), &[0x82; 32]);
        assert_eq!(capability.dom_funding_id(), &[0x8a; 32]);
        assert_eq!(capability.bitcoin_funding_id(), &[0x8b; 32]);
        assert_eq!(
            capability.dom_shared_output_commitment(),
            shared_output.as_bytes()
        );
        assert_eq!(capability.dom_confirmation_depth(), 6);
        assert_eq!(capability.bitcoin_confirmation_depth(), 7);
        assert_eq!(capability.adaptor_point(), &adaptor_point);
        let consumed = PostAnchorClaimAuthorizationRecordV1::new_consumed(&issued)?;
        let consumed_reparsed = PostAnchorClaimAuthorizationRecordV1::from_bytes(&consumed.bytes)?;
        let consumed_capability = consumed_reparsed.consumed_capability(&issued, [0x89; 32])?;
        assert_eq!(consumed_capability.issuance_record_digest(), &issued.digest);
        assert_eq!(
            consumed_capability.consumption_record_digest(),
            &consumed.digest
        );
        let mut tampered = consumed.bytes;
        tampered[208] ^= 1;
        assert!(matches!(
            PostAnchorClaimAuthorizationRecordV1::from_bytes(&tampered),
            Err(SessionStoreError::Quarantined)
        ));
        let mut wrong_evidence = PostAnchorDomClaimSigningEvidenceV1 {
            chain_id: [0x71; 32],
            session_id: confirmed.session_id(),
            settlement_id: [0x81; 32],
            terms_hash: confirmed.terms_hash(),
            m8_policy_digest: [0x80; 32],
            m8_anchor_evidence_digest: [0x82; 32],
            dom_funding_id: [0x8a; 32],
            bitcoin_funding_id: [0x8b; 32],
            dom_shared_output_commitment: *shared_output.as_bytes(),
            expected_claim_template_hash: [0x83; 32],
            expected_round_start_transcript_hash: [0x84; 32],
            expected_adaptor_point: adaptor_point,
            dom_confirmation_depth: 6,
            bitcoin_confirmation_depth: 7,
        };
        wrong_evidence.m8_anchor_evidence_digest[0] ^= 1;
        assert!(!issued.matches_evidence(&wrong_evidence));
        Ok(())
    }

    #[test]
    fn post_anchor_claim_pre_signature_codec_is_exact_idempotent_and_opaque(
    ) -> Result<(), Box<dyn Error>> {
        let fixture = PostAnchorClaimPreSignatureTestFixture::new(6)?;
        let record = fixture.record()?;
        let reparsed = PostAnchorClaimPreSignatureRecordV1::from_bytes(&record.bytes)?;
        assert_eq!(reparsed.bytes, record.bytes);
        assert_eq!(reparsed.digest, record.digest);
        assert_eq!(reparsed.session_id, fixture.issued.session_id);
        assert_eq!(
            reparsed.claim_template_hash,
            fixture.issued.claim_template_hash
        );
        assert_eq!(
            reparsed.reveal_transcript_hash,
            fixture
                .round
                .reveal_transcript_hash
                .ok_or(SessionStoreError::Canonical)?
        );

        let identical = PostAnchorClaimPreSignatureTestFixture::new(6)?.record()?;
        assert_eq!(identical.bytes, record.bytes);
        assert_eq!(identical.digest, record.digest);

        let handle = reparsed.authenticated_handle()?;
        assert_eq!(handle.session_id(), &record.session_id);
        assert_eq!(handle.claim_template_hash(), &record.claim_template_hash);
        assert_eq!(
            handle.reveal_transcript_hash(),
            &record.reveal_transcript_hash
        );
        assert_eq!(handle.artifact_record_digest(), &record.digest);
        assert_eq!(
            handle.into_pre_signature().to_bytes(),
            fixture.pre_signature.to_bytes()
        );
        Ok(())
    }

    #[test]
    fn post_anchor_claim_pre_signature_rejects_tamper_gap_and_predecessor_drift(
    ) -> Result<(), Box<dyn Error>> {
        let fixture = PostAnchorClaimPreSignatureTestFixture::new(6)?;
        let mut tampered = fixture.record()?.bytes;
        tampered[473] ^= 1;
        assert!(matches!(
            PostAnchorClaimPreSignatureRecordV1::from_bytes(&tampered),
            Err(SessionStoreError::Quarantined)
        ));

        let five_message_gap = PostAnchorClaimPreSignatureTestFixture::new(5)?;
        assert!(matches!(
            five_message_gap.record(),
            Err(SessionStoreError::Canonical)
        ));

        let mut predecessor_drift = PostAnchorClaimPreSignatureTestFixture::new(6)?;
        predecessor_drift.round.round_start_transcript_hash[0] ^= 1;
        assert!(matches!(
            predecessor_drift.record(),
            Err(SessionStoreError::Canonical)
        ));
        Ok(())
    }

    #[test]
    fn post_anchor_claim_pre_signature_publish_survives_crash_and_reopens_idempotently(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let directory = RetainedDirectory::create_under(
            temporary.capability()?,
            ValidatedComponent::operator_selected_root("pre-signature-artifacts")?,
        )?;
        drop(directory);

        let marker = temporary.path().join("post-anchor-pre-signature.marker");
        let status = Command::new(std::env::current_exe()?)
            .arg("--ignored")
            .arg("--exact")
            .arg(
                "runtime::linux::session_store::tests::post_anchor_claim_pre_signature_publish_crash_child",
            )
            .env("DOM_F7_SESSION_STORE_PARENT", temporary.path())
            .env(
                "DOM_F7_SESSION_STORE_CRASH_CUT",
                "post-anchor-claim-after-pre-signature-persist",
            )
            .env("DOM_F7_SESSION_STORE_CRASH_MARKER", &marker)
            .status()?;
        assert_eq!(status.signal(), Some(nix::libc::SIGABRT));
        assert_eq!(
            fs::read(&marker)?,
            b"post-anchor-claim-after-pre-signature-persist"
        );

        let directory = RetainedDirectory::open_under(
            temporary.capability()?,
            ValidatedComponent::operator_selected_root("pre-signature-artifacts")?,
        )?;
        recover_staging(&directory)?;
        let expected = PostAnchorClaimPreSignatureTestFixture::new(6)?.record()?;
        let final_name = post_anchor_claim_pre_signature_name(expected.session_id);
        let exact_bytes = directory.read_bounded_file(
            &ValidatedComponent::registered(&final_name)?,
            POST_ANCHOR_CLAIM_PRE_SIGNATURE_RECORD_LEN,
        )?;
        let reopened = PostAnchorClaimPreSignatureRecordV1::from_bytes(&exact_bytes)?;
        assert_eq!(reopened.bytes, expected.bytes);

        let staging_name = format!(".{final_name}.staging");
        publish_immutable(
            &directory,
            &staging_name,
            &final_name,
            &expected.bytes,
            POST_ANCHOR_CLAIM_PRE_SIGNATURE_RECORD_LEN,
        )?;
        let mut conflicting = expected.bytes;
        conflicting[473] ^= 1;
        assert_eq!(
            publish_immutable(
                &directory,
                &staging_name,
                &final_name,
                &conflicting,
                POST_ANCHOR_CLAIM_PRE_SIGNATURE_RECORD_LEN,
            ),
            Err(SessionStoreError::Conflict)
        );
        Ok(())
    }

    #[test]
    #[ignore = "subprocess helper invoked by post_anchor_claim_pre_signature_publish_survives_crash_and_reopens_idempotently"]
    fn post_anchor_claim_pre_signature_publish_crash_child() -> Result<(), Box<dyn Error>> {
        let parent =
            std::env::var_os("DOM_F7_SESSION_STORE_PARENT").ok_or(SessionStoreError::Filesystem)?;
        let directory = RetainedDirectory::open_under(
            Arc::new(Dir::from_std_file(File::open(parent)?)),
            ValidatedComponent::operator_selected_root("pre-signature-artifacts")?,
        )?;
        let record = PostAnchorClaimPreSignatureTestFixture::new(6)?.record()?;
        let final_name = post_anchor_claim_pre_signature_name(record.session_id);
        publish_immutable(
            &directory,
            &format!(".{final_name}.staging"),
            &final_name,
            &record.bytes,
            POST_ANCHOR_CLAIM_PRE_SIGNATURE_RECORD_LEN,
        )?;
        test_crash_hook("post-anchor-claim-after-pre-signature-persist");
        Err(Box::new(SessionStoreError::Quarantined))
    }

    #[test]
    fn m8_funding_issuance_codec_is_profile_separated_and_tamper_evident(
    ) -> Result<(), Box<dyn Error>> {
        let current = record(SessionPhaseV1::RefundSigned)?;
        let mut irreversible = current.irreversible();
        irreversible.funding_authorized = true;
        let authorized = current.advance(
            current.revision(),
            SessionPhaseV1::FundingAuthorized,
            current.transcript_hash(),
            irreversible,
            current.chain(),
            current.encrypted_payload(),
        )?;
        let shared_output = Commitment::commit(41, &scalar(0x11)?);
        let adaptor_point = SecretKey::from_bytes(&[0x17; 32])?.public_key();
        let m8_binding = OperationalM8FundingAuthorizationBindingV1::new(
            [0x40; 32],
            authorized.session_id(),
            authorized.transcript_hash(),
            authorized.terms_hash(),
            *shared_output.as_bytes(),
            [0x42; 32],
            [0x43; 32],
            [0x44; 32],
            adaptor_point.to_compressed_bytes(),
            [0x45; 32],
            [0x46; 32],
            [0x47; 32],
        )?;
        let m8 = OperationalM8FundingIssuanceRecordV1::new(
            m8_binding,
            authorized.revision(),
            [0x48; 32],
            b"canonical-unsigned-m8-funding-template",
            &authorized,
        )?;
        let reparsed = OperationalM8FundingIssuanceRecordV1::from_bytes(&m8.bytes)?;
        assert_eq!(reparsed.bytes, m8.bytes);
        assert_eq!(reparsed.digest, m8.digest);

        let legacy_binding = OperationalFundingAuthorizationBindingV1::new(
            [0x40; 32],
            authorized.session_id(),
            authorized.transcript_hash(),
            authorized.terms_hash(),
            *shared_output.as_bytes(),
            [0x42; 32],
            [0x43; 32],
            [0x44; 32],
            [0x46; 32],
            [0x49; 32],
            [0x47; 32],
        )?;
        let legacy = OperationalFundingIssuanceRecordV1::new(
            legacy_binding,
            authorized.revision(),
            [0x48; 32],
            b"canonical-unsigned-legacy-funding-template",
            &authorized,
        )?;
        assert!(matches!(
            OperationalM8FundingIssuanceRecordV1::from_bytes(&legacy.bytes),
            Err(SessionStoreError::Quarantined)
        ));
        assert!(matches!(
            OperationalFundingIssuanceRecordV1::from_bytes(&m8.bytes),
            Err(SessionStoreError::Quarantined)
        ));

        let mut tampered = m8.bytes;
        tampered[320] ^= 1;
        assert!(matches!(
            OperationalM8FundingIssuanceRecordV1::from_bytes(&tampered),
            Err(SessionStoreError::Quarantined)
        ));
        Ok(())
    }

    #[test]
    fn production_reservation_lookup_custody_is_restart_durable_and_terminal(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let evidence_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let store = ContractsSessionStoreV1::create_evidence_only(
            temporary.capability()?,
            "sessions",
            evidence_policy.clone(),
        )?;
        let current = record(SessionPhaseV1::Created)?;
        store.create_session(&current)?;
        let request_lookup = [0x91; 32];
        let context_binding_digest = [0x92; 32];
        let durable = store.persist_reservation_lookup_custody_fields(
            current.session_id(),
            request_lookup,
            context_binding_digest,
        )?;
        assert_eq!(durable.request_lookup().as_bytes(), &request_lookup);
        assert_eq!(durable.context_binding_digest(), &context_binding_digest);
        assert_eq!(durable.session_id().as_bytes(), &current.session_id());
        assert_eq!(
            store
                .load_custodied_reservation_lookup(current.session_id(), context_binding_digest,)?
                .as_bytes(),
            &request_lookup
        );

        // Compile-time production composition proof. The function is not
        // executed; its body can compile only if the concrete Contracts vault,
        // retained lookup custody, and operational session authority satisfy
        // the frozen `VaultBackedSignerV1::new_operational` bounds together.
        fn compose<'store>(
            vault: ContractsNonceVaultV1,
            session_store: &'store ContractsSessionStoreV1,
            trusted_chain: TrustedChainIdV1,
            share: dom_adaptor::SigningShareV1,
        ) -> VaultBackedSignerV1<
            ContractsNonceVaultV1,
            ContractsReservationLookupCustodyV1<'store>,
            ContractsSigningSessionAuthorityV1,
        > {
            VaultBackedSignerV1::new_operational(
                vault,
                session_store.reservation_lookup_custody(),
                session_store.operational_signing_session_authority(),
                trusted_chain,
                share,
            )
        }
        let _compose = compose;
        // The outer type carries no Drop impl, which is all clippy sees. The
        // call is still load-bearing: it runs the destructors of what the type
        // CONTAINS — the retained directory and lock handles — and the reopen
        // below fails if those are still held. Removing it would leave the
        // store alive to the end of scope and break the test it belongs to.
        #[allow(clippy::drop_non_drop)]
        {
            drop(durable);
            drop(store);
        }

        let reopened = ContractsSessionStoreV1::open_evidence_only(
            temporary.capability()?,
            "sessions",
            evidence_policy.clone(),
        )?;
        assert_eq!(
            reopened
                .load_custodied_reservation_lookup(current.session_id(), context_binding_digest,)?
                .as_bytes(),
            &request_lookup
        );
        let lookup = ReservationRequestLookupV1::from_bytes(request_lookup)?;
        let session_id = SessionId::from_bytes(current.session_id())?;
        let mut custody = reopened.reservation_lookup_custody();
        assert_eq!(
            custody.abandon_before_vault_claim(&lookup, &session_id, &[0x95; 32],),
            Err(SessionStoreError::Conflict)
        );
        custody.abandon_before_vault_claim(&lookup, &session_id, &context_binding_digest)?;
        custody.abandon_before_vault_claim(&lookup, &session_id, &context_binding_digest)?;
        assert_eq!(
            reopened
                .load_custodied_reservation_lookup(current.session_id(), context_binding_digest,),
            Err(SessionStoreError::InvalidTransition)
        );
        assert!(matches!(
            reopened.persist_reservation_lookup_custody_fields(
                current.session_id(),
                request_lookup,
                context_binding_digest,
            ),
            Err(SessionStoreError::InvalidTransition)
        ));
        // Same as above: dropping releases the contained handles, which is
        // what the reopen requires.
        #[allow(clippy::drop_non_drop)]
        drop(custody);
        drop(reopened);

        let reopened_again = ContractsSessionStoreV1::open_evidence_only(
            temporary.capability()?,
            "sessions",
            evidence_policy,
        )?;
        assert!(reopened_again.reservation_lookup_abandonment_exists(&request_lookup)?);
        Ok(())
    }

    #[test]
    fn reservation_lookup_tamper_and_cross_binding_replay_fail_closed() -> Result<(), Box<dyn Error>>
    {
        let temporary = TestDirectory::create()?;
        let evidence_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
        let store = ContractsSessionStoreV1::create_evidence_only(
            temporary.capability()?,
            "sessions",
            evidence_policy.clone(),
        )?;
        let current = record(SessionPhaseV1::Created)?;
        store.create_session(&current)?;
        let lookup = [0xa1; 32];
        let binding = [0xa2; 32];
        let _durable = store.persist_reservation_lookup_custody_fields(
            current.session_id(),
            lookup,
            binding,
        )?;
        assert!(matches!(
            store.persist_reservation_lookup_custody_fields(
                current.session_id(),
                [0xa3; 32],
                binding,
            ),
            Err(SessionStoreError::Conflict)
        ));
        // Same as above: dropping releases the contained handles, which is
        // what the reopen requires.
        #[allow(clippy::drop_non_drop)]
        drop(_durable);
        drop(store);

        let path = temporary
            .path()
            .join("sessions")
            .join(RESERVATION_LOOKUPS_NAME)
            .join(reservation_lookup_record_name(
                lookup,
                ReservationLookupStateV1::Custodied,
            ));
        let mut bytes = fs::read(&path)?;
        bytes[80] ^= 1;
        fs::write(&path, bytes)?;
        assert!(matches!(
            ContractsSessionStoreV1::open_evidence_only(
                temporary.capability()?,
                "sessions",
                evidence_policy,
            ),
            Err(SessionStoreError::Quarantined)
        ));
        Ok(())
    }

    #[test]
    fn reservation_lookup_crash_cuts_converge_without_fresh_fallback() -> Result<(), Box<dyn Error>>
    {
        for (mode, cut) in [
            ("custody", "reservation-lookup-after-custody-persist"),
            ("abandon", "reservation-lookup-after-abandonment-persist"),
        ] {
            let temporary = TestDirectory::create()?;
            let evidence_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
            let store = ContractsSessionStoreV1::create_evidence_only(
                temporary.capability()?,
                "sessions",
                evidence_policy.clone(),
            )?;
            let current = record(SessionPhaseV1::Created)?;
            store.create_session(&current)?;
            if mode == "abandon" {
                let _durable = store.persist_reservation_lookup_custody_fields(
                    current.session_id(),
                    [0xb1; 32],
                    [0xb2; 32],
                )?;
            }
            drop(store);
            let marker = temporary.path().join(format!("{mode}.marker"));
            let status = Command::new(std::env::current_exe()?)
                .arg("--ignored")
                .arg("--exact")
                .arg("runtime::linux::session_store::tests::reservation_lookup_crash_child")
                .env("DOM_F7_SESSION_STORE_PARENT", temporary.path())
                .env("DOM_F7_RESERVATION_LOOKUP_CRASH_MODE", mode)
                .env("DOM_F7_SESSION_STORE_CRASH_CUT", cut)
                .env("DOM_F7_SESSION_STORE_CRASH_MARKER", &marker)
                .status()?;
            assert_eq!(status.signal(), Some(nix::libc::SIGABRT));
            assert_eq!(fs::read(&marker)?, cut.as_bytes());
            let reopened = ContractsSessionStoreV1::open_evidence_only(
                temporary.capability()?,
                "sessions",
                evidence_policy,
            )?;
            if mode == "custody" {
                assert_eq!(
                    reopened
                        .load_custodied_reservation_lookup([0x31; 32], [0xb2; 32])?
                        .as_bytes(),
                    &[0xb1; 32]
                );
            } else {
                assert_eq!(
                    reopened.load_custodied_reservation_lookup([0x31; 32], [0xb2; 32]),
                    Err(SessionStoreError::InvalidTransition)
                );
                assert!(matches!(
                    reopened.persist_reservation_lookup_custody_fields(
                        [0x31; 32], [0xb1; 32], [0xb2; 32],
                    ),
                    Err(SessionStoreError::InvalidTransition)
                ));
            }
        }
        Ok(())
    }

    #[test]
    #[ignore = "subprocess helper invoked by reservation_lookup_crash_cuts_converge_without_fresh_fallback"]
    fn reservation_lookup_crash_child() -> Result<(), Box<dyn Error>> {
        let parent =
            std::env::var_os("DOM_F7_SESSION_STORE_PARENT").ok_or(SessionStoreError::Filesystem)?;
        let mode = std::env::var("DOM_F7_RESERVATION_LOOKUP_CRASH_MODE")?;
        let store = ContractsSessionStoreV1::open_evidence_only(
            Arc::new(Dir::from_std_file(File::open(parent)?)),
            "sessions",
            policy(BudgetPolicyProfileV1::EvidenceOnly)?,
        )?;
        if mode == "custody" {
            let _capability = store
                .persist_reservation_lookup_custody_fields([0x31; 32], [0xb1; 32], [0xb2; 32])?;
        } else if mode == "abandon" {
            let lookup = ReservationRequestLookupV1::from_bytes([0xb1; 32])?;
            let session_id = SessionId::from_bytes([0x31; 32])?;
            store
                .reservation_lookup_custody()
                .abandon_before_vault_claim(&lookup, &session_id, &[0xb2; 32])?;
        } else {
            return Err(Box::new(SessionStoreError::Canonical));
        }
        Err(Box::new(SessionStoreError::Quarantined))
    }
}
