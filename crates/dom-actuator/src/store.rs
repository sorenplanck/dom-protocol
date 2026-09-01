//! Durable public control plane for one DOM participant authority.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use blake2::digest::{consts::U32, Digest};
use blake2::Blake2b;
use deployment_registry::{DomNetworkV1, DomRuntimeIdentityV1};
use dom_adaptor::{OperationalClaimPersistenceCapabilityV1, OperationalClaimTransactionSinkV1};
use dom_crypto::pedersen::Commitment;
use dom_scriptless_chain_adapter::{
    canonical_transaction_hash_v1, validate_submission_receipt_facts_v1, SubmissionReceiptV1,
    SubmissionStateV1, MAX_CANONICAL_TRANSACTION_BYTES_V1,
};
use rusqlite::config::DbConfig;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
#[cfg(target_os = "linux")]
use rustix::fs::{flock, FlockOperation};
#[cfg(target_os = "linux")]
use rustix::process::geteuid;
use zeroize::Zeroizing;

use crate::model::{
    CapabilityIssuanceV1, Digest32, DomActionV1, DomActuatorCapabilityV1, DomActuatorError,
    DomActuatorResult, DomSessionBindingV1, DomSettlementChildBindingRequestV1,
    DomSettlementChildBindingV1, DomSettlementChildExposureV1, DomSettlementChildLocatorV1,
    DomSettlementChildPortCallJournalStatusV1, DomSettlementChildPortCallKeyV1,
    DomSettlementChildPortCallKindV1, DomSettlementChildPortCallOutcomeV1, ScopedDomActionV1,
    StoredDomSessionBindingPartsV1,
};

const SCHEMA_VERSION: i64 = 10;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const MAX_LEASE_DURATION_MS: u64 = 86_400_000;
const PAYOUT_FACE_EFFECT_DOMAIN: &[u8] = b"DOM:actuator-payout-face-effect:v1";
const PAYOUT_FACE_EVENT_DOMAIN: &[u8] = b"DOM:actuator-payout-face-event:v1";
const PAYOUT_FACE_PREPARE_DOMAIN: &[u8] = b"DOM:actuator-payout-face-prepare:v1";
const PAYOUT_FACE_RECORD_DOMAIN: &[u8] = b"DOM:actuator-payout-face-record:v1";

const OP_PREPARED: i64 = 0;
const OP_COMPLETED: i64 = 1;

const RESERVATION_PREPARED: i64 = 0;
const RESERVATION_ACTIVE: i64 = 1;
const RESERVATION_RELEASED: i64 = 2;

const STAGE_BOUND: i64 = 0;
const STAGE_OUTPUTS_RESERVED: i64 = 1;
const STAGE_SHARED_OUTPUT: i64 = 2;
const STAGE_BULLETPROOF: i64 = 3;
const STAGE_REFUND_PRESIGNED: i64 = 4;
const STAGE_CLAIM_PREPARED: i64 = 5;
const STAGE_FUNDING_BROADCAST: i64 = 6;
const STAGE_FUNDING_CONFIRMED: i64 = 7;
const STAGE_CLAIM_BROADCAST: i64 = 8;
const STAGE_REFUND_BROADCAST: i64 = 9;
const STAGE_CLAIM_FINAL: i64 = 10;
const STAGE_REFUND_FINAL: i64 = 11;
const STAGE_REORG_RECOVERY: i64 = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CreationBoundaryV1 {
    ProcessLockPublished,
    DatabaseFileSynced,
    BeforeSchemaTransaction,
    BeforeSchemaCommit,
    SchemaCommitted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResumableCreationStateV1 {
    PristineSqlite,
    InitializedExact,
}

const SCHEMA_SQL: &str = "
CREATE TABLE dom_store_identity (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
    instance_id BLOB UNIQUE NOT NULL CHECK(length(instance_id) = 32)
) STRICT;

CREATE TABLE dom_leases (
    participant_id BLOB PRIMARY KEY NOT NULL CHECK(length(participant_id) = 32),
    owner_id BLOB NOT NULL CHECK(length(owner_id) = 32),
    fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch > 0),
    lease_until_unix_ms INTEGER NOT NULL CHECK(lease_until_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0)
) STRICT;

CREATE TABLE dom_sessions (
    session_id BLOB PRIMARY KEY NOT NULL CHECK(length(session_id) = 32),
    route_id BLOB NOT NULL CHECK(length(route_id) = 32),
    participant_id BLOB NOT NULL CHECK(length(participant_id) = 32),
    participant_index INTEGER NOT NULL CHECK(participant_index IN (0, 1)),
    chain_id BLOB NOT NULL CHECK(length(chain_id) = 32),
    genesis_hash BLOB NOT NULL CHECK(length(genesis_hash) = 32),
    network_tag INTEGER NOT NULL CHECK(network_tag BETWEEN 1 AND 3),
    network_magic INTEGER NOT NULL CHECK(network_magic > 0 AND network_magic <= 4294967295),
    protocol_version INTEGER NOT NULL CHECK(protocol_version > 0 AND protocol_version <= 4294967295),
    rangeproof_serialization_version INTEGER NOT NULL CHECK(rangeproof_serialization_version > 0 AND rangeproof_serialization_version <= 255),
    terms_digest BLOB NOT NULL CHECK(length(terms_digest) = 32),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    deployment_digest BLOB NOT NULL CHECK(length(deployment_digest) = 32),
    asset_binding_digest BLOB NOT NULL CHECK(length(asset_binding_digest) = 32),
    registry_epoch INTEGER NOT NULL CHECK(registry_epoch > 0),
    min_confirmations INTEGER NOT NULL CHECK(min_confirmations > 0),
    max_reorg_depth INTEGER NOT NULL CHECK(max_reorg_depth >= min_confirmations),
    stage_tag INTEGER NOT NULL CHECK(stage_tag BETWEEN 0 AND 12),
    revision INTEGER NOT NULL CHECK(revision >= 0),
    journal_head BLOB NOT NULL CHECK(length(journal_head) = 32),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0),
    UNIQUE(route_id, session_id)
) STRICT;

CREATE TABLE dom_operations (
    effect_id BLOB PRIMARY KEY NOT NULL CHECK(length(effect_id) = 32),
    route_id BLOB NOT NULL CHECK(length(route_id) = 32),
    session_id BLOB NOT NULL REFERENCES dom_sessions(session_id) ON DELETE RESTRICT,
    participant_id BLOB NOT NULL CHECK(length(participant_id) = 32),
    action_tag INTEGER NOT NULL CHECK(action_tag BETWEEN 1 AND 10),
    fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch > 0),
    scope_digest BLOB NOT NULL CHECK(length(scope_digest) = 32),
    evidence_digest BLOB NOT NULL CHECK(length(evidence_digest) = 32),
    secret_binding_digest BLOB CHECK(secret_binding_digest IS NULL OR length(secret_binding_digest) = 32),
    authorization_digest BLOB NOT NULL CHECK(length(authorization_digest) = 32),
    status_tag INTEGER NOT NULL CHECK(status_tag IN (0, 1)),
    receipt_digest BLOB CHECK(receipt_digest IS NULL OR length(receipt_digest) = 32),
    reconciliation_digest BLOB CHECK(reconciliation_digest IS NULL OR length(reconciliation_digest) = 32),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0),
    CHECK((status_tag = 0 AND receipt_digest IS NULL) OR
          (status_tag = 1 AND receipt_digest IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX dom_secret_binding_once
ON dom_operations(secret_binding_digest)
WHERE secret_binding_digest IS NOT NULL;

CREATE UNIQUE INDEX dom_shared_output_once_per_session
ON dom_operations(session_id, action_tag)
WHERE action_tag = 2;

CREATE TABLE dom_settlement_children (
    custody_digest BLOB PRIMARY KEY NOT NULL CHECK(length(custody_digest) = 32),
    effect_id BLOB UNIQUE NOT NULL REFERENCES dom_operations(effect_id) ON DELETE RESTRICT CHECK(length(effect_id) = 32),
    route_id BLOB NOT NULL CHECK(length(route_id) = 32),
    session_id BLOB NOT NULL REFERENCES dom_sessions(session_id) ON DELETE RESTRICT CHECK(length(session_id) = 32),
    participant_id BLOB NOT NULL CHECK(length(participant_id) = 32),
    action_tag INTEGER NOT NULL CHECK(action_tag IN (6, 7, 8)),
    exposure_tag INTEGER NOT NULL CHECK(exposure_tag BETWEEN 1 AND 3),
    semantic_digest BLOB NOT NULL CHECK(length(semantic_digest) = 32),
    registry_digest BLOB NOT NULL CHECK(length(registry_digest) = 32),
    terms_digest BLOB NOT NULL CHECK(length(terms_digest) = 32),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    deployment_digest BLOB NOT NULL CHECK(length(deployment_digest) = 32),
    chain_id BLOB NOT NULL CHECK(length(chain_id) = 32),
    transaction_id BLOB NOT NULL CHECK(length(transaction_id) = 32),
    intent_digest BLOB NOT NULL CHECK(length(intent_digest) = 32),
    binding_record_digest BLOB NOT NULL CHECK(length(binding_record_digest) = 32),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    CHECK((action_tag IN (6, 8) AND exposure_tag = 1) OR
          (action_tag = 7 AND exposure_tag IN (2, 3)))
) STRICT;

CREATE TABLE dom_settlement_child_port_calls (
    call_kind INTEGER NOT NULL CHECK(call_kind BETWEEN 1 AND 3),
    coordinator_attempt_id BLOB NOT NULL CHECK(length(coordinator_attempt_id) = 32),
    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
    custody_digest BLOB NOT NULL REFERENCES dom_settlement_children(custody_digest) ON DELETE RESTRICT CHECK(length(custody_digest) = 32),
    effect_id BLOB NOT NULL REFERENCES dom_operations(effect_id) ON DELETE RESTRICT CHECK(length(effect_id) = 32),
    binding_record_digest BLOB NOT NULL CHECK(length(binding_record_digest) = 32),
    actuator_fencing_epoch INTEGER NOT NULL CHECK(actuator_fencing_epoch > 0),
    outcome_bytes BLOB CHECK(outcome_bytes IS NULL OR length(outcome_bytes) = 66),
    outcome_digest BLOB CHECK(outcome_digest IS NULL OR length(outcome_digest) = 32),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    committed_at_unix_ms INTEGER CHECK(committed_at_unix_ms IS NULL OR committed_at_unix_ms >= created_at_unix_ms),
    PRIMARY KEY(call_kind, coordinator_attempt_id),
    CHECK((outcome_bytes IS NULL AND outcome_digest IS NULL AND committed_at_unix_ms IS NULL) OR
          (outcome_bytes IS NOT NULL AND outcome_digest IS NOT NULL AND committed_at_unix_ms IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX dom_settlement_child_attempt_once
ON dom_settlement_child_port_calls(coordinator_attempt_id);

CREATE TABLE dom_claim_custody (
    session_id BLOB PRIMARY KEY NOT NULL REFERENCES dom_sessions(session_id) ON DELETE RESTRICT CHECK(length(session_id) = 32),
    effect_id BLOB UNIQUE NOT NULL REFERENCES dom_operations(effect_id) ON DELETE RESTRICT CHECK(length(effect_id) = 32),
    route_id BLOB NOT NULL CHECK(length(route_id) = 32),
    participant_id BLOB NOT NULL CHECK(length(participant_id) = 32),
    fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch > 0),
    authorization_digest BLOB NOT NULL CHECK(length(authorization_digest) = 32),
    tx_hash BLOB NOT NULL CHECK(length(tx_hash) = 32),
    template_hash BLOB NOT NULL CHECK(length(template_hash) = 32),
    shared_output_commitment BLOB NOT NULL CHECK(length(shared_output_commitment) = 33),
    exact_bytes BLOB NOT NULL CHECK(length(exact_bytes) > 0 AND length(exact_bytes) <= 16777216),
    exact_bytes_digest BLOB NOT NULL CHECK(length(exact_bytes_digest) = 32),
    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
    send_attempted INTEGER NOT NULL CHECK(send_attempted IN (0, 1)),
    send_attempt_count INTEGER NOT NULL CHECK(send_attempt_count >= 0),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0),
    CHECK(tx_hash = exact_bytes_digest)
) STRICT;

CREATE TABLE dom_claim_admission (
    session_id BLOB PRIMARY KEY NOT NULL REFERENCES dom_claim_custody(session_id) ON DELETE RESTRICT CHECK(length(session_id) = 32),
    effect_id BLOB UNIQUE NOT NULL REFERENCES dom_operations(effect_id) ON DELETE RESTRICT CHECK(length(effect_id) = 32),
    route_id BLOB NOT NULL CHECK(length(route_id) = 32),
    participant_id BLOB NOT NULL CHECK(length(participant_id) = 32),
    fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch > 0),
    tx_hash BLOB NOT NULL CHECK(length(tx_hash) = 32),
    claim_record_digest BLOB NOT NULL CHECK(length(claim_record_digest) = 32),
    receipt_state_tag INTEGER NOT NULL CHECK(receipt_state_tag BETWEEN 1 AND 3),
    receipt_relayed INTEGER NOT NULL CHECK(receipt_relayed IN (0, 1)),
    receipt_digest BLOB NOT NULL CHECK(length(receipt_digest) = 32),
    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0),
    CHECK(receipt_state_tag = 3 OR receipt_relayed = 1)
) STRICT;

CREATE TABLE dom_final_claim_attempt_v2 (
    session_id BLOB PRIMARY KEY NOT NULL REFERENCES dom_sessions(session_id) ON DELETE RESTRICT CHECK(length(session_id) = 32),
    effect_id BLOB UNIQUE NOT NULL REFERENCES dom_operations(effect_id) ON DELETE RESTRICT CHECK(length(effect_id) = 32),
    route_id BLOB NOT NULL CHECK(length(route_id) = 32),
    participant_id BLOB NOT NULL CHECK(length(participant_id) = 32),
    owner_id BLOB NOT NULL CHECK(length(owner_id) = 32),
    fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch > 0),
    authorization_digest BLOB NOT NULL CHECK(length(authorization_digest) = 32),
    dom_claim_sender_id BLOB NOT NULL CHECK(length(dom_claim_sender_id) = 32),
    final_claim_receiver_id BLOB NOT NULL CHECK(length(final_claim_receiver_id) = 32),
    tx_hash BLOB NOT NULL CHECK(length(tx_hash) = 32),
    template_hash BLOB NOT NULL CHECK(length(template_hash) = 32),
    shared_output_commitment BLOB NOT NULL CHECK(length(shared_output_commitment) = 33),
    exposure_record_digest BLOB NOT NULL CHECK(length(exposure_record_digest) = 32),
    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
    send_attempt_count INTEGER NOT NULL CHECK(send_attempt_count > 0),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0),
    CHECK(dom_claim_sender_id = participant_id),
    CHECK(final_claim_receiver_id <> participant_id)
) STRICT;

CREATE TABLE dom_final_claim_admission_v2 (
    session_id BLOB PRIMARY KEY NOT NULL REFERENCES dom_final_claim_attempt_v2(session_id) ON DELETE RESTRICT CHECK(length(session_id) = 32),
    effect_id BLOB UNIQUE NOT NULL REFERENCES dom_operations(effect_id) ON DELETE RESTRICT CHECK(length(effect_id) = 32),
    route_id BLOB NOT NULL CHECK(length(route_id) = 32),
    participant_id BLOB NOT NULL CHECK(length(participant_id) = 32),
    fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch > 0),
    dom_claim_sender_id BLOB NOT NULL CHECK(length(dom_claim_sender_id) = 32),
    final_claim_receiver_id BLOB NOT NULL CHECK(length(final_claim_receiver_id) = 32),
    tx_hash BLOB NOT NULL CHECK(length(tx_hash) = 32),
    exposure_record_digest BLOB NOT NULL CHECK(length(exposure_record_digest) = 32),
    attempt_record_digest BLOB NOT NULL CHECK(length(attempt_record_digest) = 32),
    receipt_state_tag INTEGER NOT NULL CHECK(receipt_state_tag BETWEEN 1 AND 3),
    receipt_relayed INTEGER NOT NULL CHECK(receipt_relayed IN (0, 1)),
    receipt_digest BLOB NOT NULL CHECK(length(receipt_digest) = 32),
    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0),
    CHECK(receipt_state_tag = 3 OR receipt_relayed = 1),
    CHECK(dom_claim_sender_id = participant_id),
    CHECK(final_claim_receiver_id <> participant_id)
) STRICT;

CREATE TABLE dom_terminal_finality (
    session_id BLOB NOT NULL REFERENCES dom_sessions(session_id) ON DELETE RESTRICT CHECK(length(session_id) = 32),
    kind_tag INTEGER NOT NULL CHECK(kind_tag IN (1, 2, 3)),
    tx_hash BLOB NOT NULL CHECK(length(tx_hash) = 32),
    block_height INTEGER NOT NULL CHECK(block_height >= 0),
    block_hash BLOB NOT NULL CHECK(length(block_hash) = 32),
    tip_height INTEGER NOT NULL CHECK(tip_height >= block_height),
    tip_hash BLOB NOT NULL CHECK(length(tip_hash) = 32),
    confirmation_depth INTEGER NOT NULL CHECK(confirmation_depth > 0),
    minimum_confirmations INTEGER NOT NULL CHECK(minimum_confirmations > 0),
    max_reorg_depth INTEGER NOT NULL CHECK(max_reorg_depth >= minimum_confirmations),
    evidence_digest BLOB NOT NULL CHECK(length(evidence_digest) = 32),
    checkpoint_bytes BLOB NOT NULL CHECK(length(checkpoint_bytes) >= 246 AND length(checkpoint_bytes) <= 196608),
    checkpoint_digest BLOB NOT NULL CHECK(length(checkpoint_digest) = 32),
    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    reorg_evidence_digest BLOB CHECK(
        (active = 1 AND reorg_evidence_digest IS NULL) OR
        (active = 0 AND reorg_evidence_digest IS NOT NULL
         AND length(reorg_evidence_digest) = 32)
    ),
    fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch > 0),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0),
    PRIMARY KEY(session_id, kind_tag)
) STRICT;

CREATE UNIQUE INDEX dom_active_terminal_finality_once
ON dom_terminal_finality(session_id)
WHERE active = 1 AND kind_tag IN (1, 2);

CREATE TABLE dom_output_reservations (
    reservation_digest BLOB PRIMARY KEY NOT NULL CHECK(length(reservation_digest) = 32),
    effect_id BLOB UNIQUE NOT NULL REFERENCES dom_operations(effect_id) ON DELETE RESTRICT,
    route_id BLOB NOT NULL CHECK(length(route_id) = 32),
    session_id BLOB NOT NULL REFERENCES dom_sessions(session_id) ON DELETE RESTRICT,
    total_value INTEGER NOT NULL CHECK(total_value > 0),
    output_count INTEGER NOT NULL CHECK(output_count > 0 AND output_count <= 4096),
    status_tag INTEGER NOT NULL CHECK(status_tag IN (0, 1, 2)),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0)
) STRICT;

CREATE TABLE dom_output_reservation_items (
    reservation_digest BLOB NOT NULL REFERENCES dom_output_reservations(reservation_digest) ON DELETE RESTRICT,
    commitment BLOB NOT NULL CHECK(length(commitment) = 33),
    value INTEGER NOT NULL CHECK(value > 0),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    PRIMARY KEY(reservation_digest, commitment)
) STRICT;

CREATE UNIQUE INDEX dom_output_active_once
ON dom_output_reservation_items(commitment)
WHERE active = 1;

CREATE TABLE dom_payout_face_preparations (
    session_id BLOB PRIMARY KEY NOT NULL REFERENCES dom_sessions(session_id) ON DELETE RESTRICT,
    route_id BLOB NOT NULL CHECK(length(route_id) = 32),
    participant_id BLOB NOT NULL CHECK(length(participant_id) = 32),
    payout_commitment BLOB UNIQUE NOT NULL CHECK(length(payout_commitment) = 33),
    payout_value INTEGER NOT NULL CHECK(payout_value > 0),
    wallet_ownership_digest BLOB NOT NULL CHECK(length(wallet_ownership_digest) = 32),
    store_instance_id BLOB NOT NULL CHECK(length(store_instance_id) = 32),
    prepare_digest BLOB UNIQUE NOT NULL CHECK(length(prepare_digest) = 32),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0)
) STRICT;

CREATE TABLE dom_payout_face_evidence (
    session_id BLOB PRIMARY KEY NOT NULL REFERENCES dom_sessions(session_id) ON DELETE RESTRICT,
    prepare_digest BLOB UNIQUE NOT NULL REFERENCES dom_payout_face_preparations(prepare_digest) ON DELETE RESTRICT,
    route_id BLOB NOT NULL CHECK(length(route_id) = 32),
    participant_id BLOB NOT NULL CHECK(length(participant_id) = 32),
    payout_commitment BLOB UNIQUE NOT NULL CHECK(length(payout_commitment) = 33),
    payout_value INTEGER NOT NULL CHECK(payout_value > 0),
    wallet_ownership_digest BLOB NOT NULL CHECK(length(wallet_ownership_digest) = 32),
    store_instance_id BLOB NOT NULL CHECK(length(store_instance_id) = 32),
    wallet_ciphertext_digest BLOB NOT NULL CHECK(length(wallet_ciphertext_digest) = 32),
    evidence_revision INTEGER NOT NULL CHECK(evidence_revision > 0),
    event_effect_id BLOB UNIQUE NOT NULL CHECK(length(event_effect_id) = 32),
    event_digest BLOB UNIQUE NOT NULL CHECK(length(event_digest) = 32),
    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0)
) STRICT;

CREATE TABLE dom_session_events (
    session_id BLOB NOT NULL REFERENCES dom_sessions(session_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK(revision > 0),
    effect_id BLOB NOT NULL CHECK(length(effect_id) = 32),
    event_digest BLOB NOT NULL CHECK(length(event_digest) = 32),
    previous_head BLOB NOT NULL CHECK(length(previous_head) = 32),
    entry_hash BLOB NOT NULL CHECK(length(entry_hash) = 32),
    fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch > 0),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    PRIMARY KEY(session_id, revision),
    UNIQUE(session_id, effect_id, event_digest)
) STRICT;

PRAGMA user_version = 10;
";

/// Exact process lease and signer fencing generation for one participant.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DomLeaseV1 {
    participant_id: Digest32,
    owner_id: Digest32,
    fencing_epoch: u64,
    lease_until_unix_ms: u64,
}

impl DomLeaseV1 {
    /// Participant exclusively owned by this lease.
    pub const fn participant_id(self) -> Digest32 {
        self.participant_id
    }

    /// Monotonic generation that every action capability carries.
    pub const fn fencing_epoch(self) -> u64 {
        self.fencing_epoch
    }

    /// Exact absolute lease expiry.
    pub const fn lease_until_unix_ms(self) -> u64 {
        self.lease_until_unix_ms
    }
}

impl core::fmt::Debug for DomLeaseV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DomLeaseV1")
            .field("participant_id", &self.participant_id)
            .field("owner_id", &"<redacted owner>")
            .field("fencing_epoch", &self.fencing_epoch)
            .field("lease_until_unix_ms", &self.lease_until_unix_ms)
            .finish()
    }
}

/// Idempotent disposition of a persist-before-externalize operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomOperationDispositionV1 {
    /// A new durable intent was written.
    Prepared,
    /// The exact same durable intent already existed.
    Idempotent,
    /// The exact action and public receipt were already completed.
    AlreadyCompleted,
}

/// Linear opaque handle for one exact claim already placed in durable custody.
///
/// It deliberately has no `Clone`, `Copy`, `Debug`, codec or byte accessor.
/// Public inspection is limited to the transaction identity. Legacy V1 handles
/// cannot authorize a new send: dispatch only reissues an already-durable
/// admission proof, while unadmitted custody remains recovery-only.
pub struct DomClaimBroadcastV1 {
    session_id: Digest32,
    effect_id: Digest32,
    fencing_epoch: u64,
    tx_hash: Digest32,
    exact_bytes: Zeroizing<Vec<u8>>,
}

impl DomClaimBroadcastV1 {
    /// Canonical DOM transaction identity of this exact adapted claim.
    pub const fn tx_hash(&self) -> Digest32 {
        self.tx_hash
    }
}

/// Reauthenticated disposition of one exact legacy V1 claim custody row.
///
/// This classification is derived only from owner-only durable records: the
/// legacy V1 claim-custody row and its admission, or the V2 `FinalClaim`
/// attempt row and its admission mirror. Exactly one of the two generations may
/// exist for a session. `PotentiallyExposed` is deliberately conservative: a
/// durable pre-RPC attempt marker means the claim secret may already be public
/// even when no admission receipt survived. None of these values grants send,
/// replay, takeover, signing, or refund authority, and none of them — including
/// `Admitted` — ever re-authorizes a refund.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "the reauthenticated legacy custody classification must drive recovery"]
pub enum DomClaimCustodyClassificationV1 {
    /// A validated economic-admission record is durably bound to the custody.
    Admitted,
    /// A send was durably marked before RPC, but no admission record survives.
    PotentiallyExposed,
    /// No send attempt and no admission record are durably present.
    Unattempted,
}

impl DomClaimCustodyClassificationV1 {
    /// Whether durable economic admission has been reauthenticated.
    #[must_use]
    pub const fn is_admitted(self) -> bool {
        matches!(self, Self::Admitted)
    }

    /// Whether an ambiguous pre-RPC latch requires secret-public recovery.
    #[must_use]
    pub const fn is_potentially_exposed(self) -> bool {
        matches!(self, Self::PotentiallyExposed)
    }

    /// Whether custody has no durable send-attempt or admission marker.
    #[must_use]
    pub const fn is_unattempted(self) -> bool {
        matches!(self, Self::Unattempted)
    }

    /// Monotone conservative severity of one reauthenticated classification.
    const fn severity(self) -> u8 {
        match self {
            Self::Unattempted => 0,
            Self::PotentiallyExposed => 1,
            Self::Admitted => 2,
        }
    }

    /// Join two independently reauthenticated sources conservatively.
    ///
    /// The DOM Contracts store and this owner-only control plane commit in two
    /// separate durable transactions, so a crash can leave the actuator behind
    /// the Contracts records. The joined value is always the stronger of the
    /// two: a local `Unattempted` can never mask a Contracts exposure marker,
    /// and the result therefore never regresses across restarts. This is a pure
    /// predicate; it grants no send, replay, takeover, signing or refund
    /// authority.
    // No `#[must_use]` here: the return type carries one, and it carries a
    // *message* this bare attribute did not. Dropping the attribute keeps the
    // obligation and improves what the caller is told when they ignore it.
    pub const fn join_conservative(self, other: Self) -> Self {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
}

/// Public-fact audit view of one exact retained legacy V1 claim.
///
/// The view contains only route/session identities and commitments required to
/// reconcile the retained transaction. It deliberately contains no canonical
/// bytes, receipt facts, authorization digest, scalar, or conversion back into
/// broadcast authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "the reauthenticated legacy claim custody audit must be acted upon"]
pub struct DomClaimCustodyAuditV1 {
    classification: DomClaimCustodyClassificationV1,
    session_id: Digest32,
    effect_id: Digest32,
    route_id: Digest32,
    participant_id: Digest32,
    custody_fencing_epoch: u64,
    tx_hash: Digest32,
    template_hash: Digest32,
    shared_output_commitment: [u8; 33],
    custody_record_digest: Digest32,
    send_attempt_count: u64,
    admission_record_digest: Option<Digest32>,
}

impl DomClaimCustodyAuditV1 {
    /// Reauthenticated legacy custody disposition.
    pub const fn classification(&self) -> DomClaimCustodyClassificationV1 {
        self.classification
    }

    /// Scriptless Contracts session owning this custody.
    #[must_use]
    pub const fn session_id(&self) -> Digest32 {
        self.session_id
    }

    /// Exact route-executor effect that persisted this claim.
    #[must_use]
    pub const fn effect_id(&self) -> Digest32 {
        self.effect_id
    }

    /// Route identity bound to the retained session.
    #[must_use]
    pub const fn route_id(&self) -> Digest32 {
        self.route_id
    }

    /// Local participant identity bound to the custody row.
    #[must_use]
    pub const fn participant_id(&self) -> Digest32 {
        self.participant_id
    }

    /// Fencing generation currently committed by the custody row.
    #[must_use]
    pub const fn custody_fencing_epoch(&self) -> u64 {
        self.custody_fencing_epoch
    }

    /// Canonical transaction identity derived from the retained exact bytes.
    #[must_use]
    pub const fn tx_hash(&self) -> Digest32 {
        self.tx_hash
    }

    /// Claim template commitment reauthenticated from custody.
    #[must_use]
    pub const fn template_hash(&self) -> Digest32 {
        self.template_hash
    }

    /// Shared-output commitment spent by the exact retained claim.
    #[must_use]
    pub const fn shared_output_commitment(&self) -> [u8; 33] {
        self.shared_output_commitment
    }

    /// Commitment to every retained custody fact, including the attempt latch.
    #[must_use]
    pub const fn custody_record_digest(&self) -> Digest32 {
        self.custody_record_digest
    }

    /// Monotonic number of durably marked historical send attempts.
    #[must_use]
    pub const fn send_attempt_count(&self) -> u64 {
        self.send_attempt_count
    }

    /// Admission-row commitment, present only for reauthenticated admission.
    #[must_use]
    pub const fn admission_record_digest(&self) -> Option<Digest32> {
        self.admission_record_digest
    }
}

/// Opaque durable proof that the exact retained claim reached economic admission.
///
/// The value has no public constructor, `Clone`, `Copy`, `Debug`, codec or raw
/// transaction accessor.  It is minted only after the validated node receipt
/// has been committed to the owner-only actuator store, or reissued by
/// reauthenticating that exact record after restart.  A future Contracts 0x12
/// authority can consume this value without accepting caller-shaped receipt
/// facts.
#[must_use = "the durable claim admission must be consumed by the next protocol boundary"]
pub struct DomClaimAdmissionV1 {
    session_id: Digest32,
    effect_id: Digest32,
    original_fencing_epoch: u64,
    tx_hash: Digest32,
    state: SubmissionStateV1,
    relayed: bool,
    receipt_digest: Digest32,
    record_digest: Digest32,
}

impl DomClaimAdmissionV1 {
    /// Scriptless Contracts session whose exact claim was admitted.
    #[must_use]
    pub const fn session_id(&self) -> Digest32 {
        self.session_id
    }

    /// Route-executor effect whose exact claim was admitted.
    #[must_use]
    pub const fn effect_id(&self) -> Digest32 {
        self.effect_id
    }

    /// Fencing generation that performed the admitted externalization.
    #[must_use]
    pub const fn original_fencing_epoch(&self) -> u64 {
        self.original_fencing_epoch
    }

    /// Exact claim transaction admitted by the node.
    #[must_use]
    pub const fn tx_hash(&self) -> Digest32 {
        self.tx_hash
    }

    /// Exact validated node knowledge state retained in the admission record.
    #[must_use]
    pub const fn submission_state(&self) -> SubmissionStateV1 {
        self.state
    }

    /// Whether the exact claim reached at least one relay subscriber.
    #[must_use]
    pub const fn was_relayed(&self) -> bool {
        self.relayed
    }

    /// Canonical commitment emitted by the validated DOM submission boundary.
    #[must_use]
    pub const fn receipt_digest(&self) -> Digest32 {
        self.receipt_digest
    }

    /// Owner-only record commitment binding route, effect, receipt and custody.
    #[must_use]
    pub const fn admission_record_digest(&self) -> Digest32 {
        self.record_digest
    }
}

/// Opaque durable mirror of one admitted V2 `FinalClaim` submission.
///
/// The value has no public constructor, `Clone`, `Copy`, `Debug`, codec or
/// transaction accessor, and it deliberately carries no canonical claim bytes:
/// the exact adapted claim remains the sole custody of the DOM Contracts store
/// exposure record. This mirror is minted only after the Contracts admission
/// record is durable and the validated node receipt has been crossed against
/// the owner-only pre-RPC attempt latch, or reissued by reauthenticating that
/// exact record after restart. It is an operational mirror: it is never an
/// input to the Contracts store and never the source of the `FinalClaim` 0x12
/// transport authority.
#[must_use = "the durable V2 final-claim admission must be consumed by the next protocol boundary"]
pub struct DomFinalClaimAdmissionV2 {
    session_id: Digest32,
    effect_id: Digest32,
    original_fencing_epoch: u64,
    dom_claim_sender_id: Digest32,
    final_claim_receiver_id: Digest32,
    tx_hash: Digest32,
    exposure_record_digest: Digest32,
    state: SubmissionStateV1,
    relayed: bool,
    receipt_digest: Digest32,
    record_digest: Digest32,
}

impl DomFinalClaimAdmissionV2 {
    /// Scriptless Contracts session whose exact final claim was admitted.
    #[must_use]
    pub const fn session_id(&self) -> Digest32 {
        self.session_id
    }

    /// Route-executor effect whose exact final claim was admitted.
    #[must_use]
    pub const fn effect_id(&self) -> Digest32 {
        self.effect_id
    }

    /// Fencing generation that performed the admitted externalization.
    #[must_use]
    pub const fn original_fencing_epoch(&self) -> u64 {
        self.original_fencing_epoch
    }

    /// Frozen participant that is the only canonical 0x12 sender for this leg.
    #[must_use]
    pub const fn dom_claim_sender_id(&self) -> Digest32 {
        self.dom_claim_sender_id
    }

    /// Frozen participant that is the only accepted 0x12 receiver for this leg.
    #[must_use]
    pub const fn final_claim_receiver_id(&self) -> Digest32 {
        self.final_claim_receiver_id
    }

    /// Exact final-claim transaction admitted by the node.
    #[must_use]
    pub const fn tx_hash(&self) -> Digest32 {
        self.tx_hash
    }

    /// Contracts exposure-record commitment that preceded the first submission.
    #[must_use]
    pub const fn exposure_record_digest(&self) -> Digest32 {
        self.exposure_record_digest
    }

    /// Exact validated node knowledge state retained in the mirror record.
    #[must_use]
    pub const fn submission_state(&self) -> SubmissionStateV1 {
        self.state
    }

    /// Whether the exact final claim reached at least one relay subscriber.
    #[must_use]
    pub const fn was_relayed(&self) -> bool {
        self.relayed
    }

    /// Canonical commitment emitted by the validated DOM submission boundary.
    #[must_use]
    pub const fn receipt_digest(&self) -> Digest32 {
        self.receipt_digest
    }

    /// Owner-only mirror commitment binding route, effect, receipt and attempt.
    #[must_use]
    pub const fn admission_record_digest(&self) -> Digest32 {
        self.record_digest
    }
}

/// Public-fact audit view of one exact retained V2 `FinalClaim` custody mirror.
///
/// The view contains only route/session/role identities and public commitments.
/// It deliberately contains no canonical bytes, no receipt facts beyond the
/// commitment already committed by the record, no authorization digest and no
/// conversion back into submission or transport authority.
///
/// The classification reported here is the *local* disposition only. The DOM
/// Contracts store is the authority on exposure, so a caller must join this
/// value with the Contracts disposition through
/// [`DomClaimCustodyClassificationV1::join_conservative`] before acting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "the reauthenticated V2 final-claim custody audit must be acted upon"]
pub struct DomFinalClaimCustodyAuditV2 {
    classification: DomClaimCustodyClassificationV1,
    session_id: Digest32,
    effect_id: Digest32,
    route_id: Digest32,
    participant_id: Digest32,
    dom_claim_sender_id: Digest32,
    final_claim_receiver_id: Digest32,
    custody_fencing_epoch: u64,
    tx_hash: Digest32,
    template_hash: Digest32,
    shared_output_commitment: [u8; 33],
    exposure_record_digest: Digest32,
    attempt_record_digest: Digest32,
    send_attempt_count: u64,
    admission_record_digest: Option<Digest32>,
}

impl DomFinalClaimCustodyAuditV2 {
    /// Locally reauthenticated V2 custody disposition.
    // Same as `join_conservative`: `DomClaimCustodyClassificationV1` is itself
    // `#[must_use]` with a message, so the bare attribute here only made the
    // diagnostic worse.
    pub const fn classification(&self) -> DomClaimCustodyClassificationV1 {
        self.classification
    }

    /// Scriptless Contracts session owning this V2 custody mirror.
    #[must_use]
    pub const fn session_id(&self) -> Digest32 {
        self.session_id
    }

    /// Exact route-executor effect that latched this attempt.
    #[must_use]
    pub const fn effect_id(&self) -> Digest32 {
        self.effect_id
    }

    /// Route identity bound to the retained session.
    #[must_use]
    pub const fn route_id(&self) -> Digest32 {
        self.route_id
    }

    /// Local participant identity bound to the mirror row.
    #[must_use]
    pub const fn participant_id(&self) -> Digest32 {
        self.participant_id
    }

    /// Frozen canonical 0x12 sender; always the local participant.
    #[must_use]
    pub const fn dom_claim_sender_id(&self) -> Digest32 {
        self.dom_claim_sender_id
    }

    /// Frozen canonical 0x12 receiver; never the local participant.
    #[must_use]
    pub const fn final_claim_receiver_id(&self) -> Digest32 {
        self.final_claim_receiver_id
    }

    /// Fencing generation currently committed by the mirror row.
    #[must_use]
    pub const fn custody_fencing_epoch(&self) -> u64 {
        self.custody_fencing_epoch
    }

    /// Canonical transaction identity of the exact retained final claim.
    #[must_use]
    pub const fn tx_hash(&self) -> Digest32 {
        self.tx_hash
    }

    /// Claim template commitment reauthenticated from the Contracts authority.
    #[must_use]
    pub const fn template_hash(&self) -> Digest32 {
        self.template_hash
    }

    /// Shared-output commitment spent by the exact retained final claim.
    #[must_use]
    pub const fn shared_output_commitment(&self) -> [u8; 33] {
        self.shared_output_commitment
    }

    /// Contracts exposure-record commitment that authorized the first send.
    #[must_use]
    pub const fn exposure_record_digest(&self) -> Digest32 {
        self.exposure_record_digest
    }

    /// Commitment to every retained attempt fact, including the attempt count.
    #[must_use]
    pub const fn attempt_record_digest(&self) -> Digest32 {
        self.attempt_record_digest
    }

    /// Monotonic number of durably latched pre-RPC send attempts.
    #[must_use]
    pub const fn send_attempt_count(&self) -> u64 {
        self.send_attempt_count
    }

    /// Mirror commitment, present only for reauthenticated economic admission.
    #[must_use]
    pub const fn admission_record_digest(&self) -> Option<Digest32> {
        self.admission_record_digest
    }
}

/// Sealed proof that a pre-RPC V2 exposure attempt is durably latched.
///
/// This token is minted only by [`DomActuatorStoreV1::latch_final_claim_attempt_v2`],
/// after the owner-only attempt row is committed. It has no public constructor,
/// `Clone`, `Copy`, `Debug`, codec or byte accessor, and it carries only public
/// commitments.
///
/// Its purpose is to make the normative ordering a *type* obligation rather
/// than a discipline: the DOM Contracts store can reissue a byte-identical
/// submission handle from the exposure record alone, so a handle by itself does
/// not prove that this control plane latched the attempt. Requiring this token
/// at the dispatch boundary makes "no submission without a durable pre-RPC
/// attempt latch" unrepresentable rather than merely documented.
#[must_use = "the latched pre-RPC attempt must gate the submission"]
pub struct LatchedFinalClaimSubmissionV2 {
    session_id: Digest32,
    tx_hash: Digest32,
    attempt_record_digest: Digest32,
}

impl LatchedFinalClaimSubmissionV2 {
    /// Scriptless Contracts session whose exposure attempt is durable.
    #[must_use]
    pub const fn session_id(&self) -> Digest32 {
        self.session_id
    }

    /// Exact final-claim transaction this attempt was latched for.
    #[must_use]
    pub const fn tx_hash(&self) -> Digest32 {
        self.tx_hash
    }

    /// Commitment to the exact attempt row, including its attempt counter.
    #[must_use]
    pub const fn attempt_record_digest(&self) -> Digest32 {
        self.attempt_record_digest
    }
}

struct StoredFinalClaimAttemptV2 {
    session_id: Digest32,
    effect_id: Digest32,
    route_id: Digest32,
    participant_id: Digest32,
    owner_id: Digest32,
    fencing_epoch: u64,
    authorization_digest: Digest32,
    dom_claim_sender_id: Digest32,
    final_claim_receiver_id: Digest32,
    tx_hash: Digest32,
    template_hash: Digest32,
    shared_output_commitment: [u8; 33],
    exposure_record_digest: Digest32,
    record_digest: Digest32,
    send_attempt_count: u64,
}

struct StoredFinalClaimAdmissionV2 {
    session_id: Digest32,
    effect_id: Digest32,
    route_id: Digest32,
    participant_id: Digest32,
    fencing_epoch: u64,
    dom_claim_sender_id: Digest32,
    final_claim_receiver_id: Digest32,
    tx_hash: Digest32,
    exposure_record_digest: Digest32,
    attempt_record_digest: Digest32,
    state: SubmissionStateV1,
    relayed: bool,
    receipt_digest: Digest32,
    record_digest: Digest32,
}

/// Public commitments the Contracts pre-submit handle already authenticated.
///
/// These facts are copied out of the linear Contracts submission handle by the
/// crate-local façade; they are never accepted from an external caller, and the
/// struct is crate-private precisely so no caller-shaped path can exist.
pub(crate) struct FinalClaimAttemptFactsV2 {
    pub(crate) authority_evidence_digest: Digest32,
    pub(crate) dom_claim_sender_id: Digest32,
    pub(crate) final_claim_receiver_id: Digest32,
    pub(crate) tx_hash: Digest32,
    pub(crate) template_hash: Digest32,
    pub(crate) shared_output_commitment: [u8; 33],
    pub(crate) exposure_record_digest: Digest32,
}

/// Role facts read out of the move-only Contracts transport authority.
///
/// Crate-private for the same reason as [`FinalClaimAttemptFactsV2`]: the only
/// legal producer is the façade that has just consumed the linear Contracts
/// authority returned by `complete_operational_final_claim_admission_v2`.
pub(crate) struct FinalClaimTransportAuthorityFactsV2 {
    pub(crate) session_id: Digest32,
    pub(crate) dom_claim_sender_id: Digest32,
    pub(crate) final_claim_receiver_id: Digest32,
}

struct StoredClaimAdmissionV1 {
    session_id: Digest32,
    effect_id: Digest32,
    route_id: Digest32,
    participant_id: Digest32,
    fencing_epoch: u64,
    tx_hash: Digest32,
    claim_record_digest: Digest32,
    state: SubmissionStateV1,
    relayed: bool,
    receipt_digest: Digest32,
    record_digest: Digest32,
}

#[cfg(test)]
pub(crate) struct PendingClaimAdmissionV1 {
    session_id: Digest32,
    effect_id: Digest32,
    route_id: Digest32,
    participant_id: Digest32,
    fencing_epoch: u64,
    tx_hash: Digest32,
    claim_record_digest: Digest32,
}

struct StoredClaimCustodyV1 {
    session_id: Digest32,
    effect_id: Digest32,
    route_id: Digest32,
    participant_id: Digest32,
    fencing_epoch: u64,
    authorization_digest: Digest32,
    tx_hash: Digest32,
    template_hash: Digest32,
    shared_output_commitment: [u8; 33],
    exact_bytes: Zeroizing<Vec<u8>>,
    exact_bytes_digest: Digest32,
    record_digest: Digest32,
    send_attempted: bool,
    send_attempt_count: u64,
}

#[derive(Clone, Copy)]
struct ClaimSendStateV1 {
    attempted: bool,
    attempt_count: u64,
}

impl ClaimSendStateV1 {
    const UNSENT: Self = Self {
        attempted: false,
        attempt_count: 0,
    };
}

pub(crate) struct RetainedDomClaimIdentityV1 {
    pub(crate) tx_hash: Digest32,
    pub(crate) template_hash: Digest32,
    pub(crate) shared_output_commitment: [u8; 33],
}

pub(crate) struct DomClaimPersistenceSinkV1<'store> {
    store: &'store mut DomActuatorStoreV1,
    lease: DomLeaseV1,
    capability: Option<DomActuatorCapabilityV1>,
    expected_template_hash: Digest32,
    expected_shared_output_commitment: [u8; 33],
    expected_claim_authority_evidence_digest: Digest32,
    validation_height: u64,
    now_unix_ms: u64,
}

pub(crate) struct ClaimPersistenceSinkRequestV1 {
    pub(crate) lease: DomLeaseV1,
    pub(crate) capability: DomActuatorCapabilityV1,
    pub(crate) expected_template_hash: Digest32,
    pub(crate) expected_shared_output_commitment: [u8; 33],
    pub(crate) expected_claim_authority_evidence_digest: Digest32,
    pub(crate) validation_height: u64,
    pub(crate) now_unix_ms: u64,
}

/// Public chain observation accepted by the actuator control plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomChainObservationV1 {
    /// Funding became canonical/final enough for the session policy.
    FundingConfirmed,
    /// Funding left the canonical chain and recovery is required.
    FundingReorg,
}

impl DomChainObservationV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::FundingConfirmed => 1,
            Self::FundingReorg => 2,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum DomTerminalKindV1 {
    Claim = 1,
    Refund = 2,
    Funding = 3,
}

impl DomTerminalKindV1 {
    const fn finality_observation_tag(self) -> u8 {
        match self {
            Self::Claim => 3,
            Self::Refund => 4,
            Self::Funding => 1,
        }
    }

    const fn reorg_observation_tag(self) -> u8 {
        match self {
            Self::Claim => 5,
            Self::Refund => 6,
            Self::Funding => 2,
        }
    }

    fn decode(value: i64) -> DomActuatorResult<Self> {
        match value {
            1 => Ok(Self::Claim),
            2 => Ok(Self::Refund),
            3 => Ok(Self::Funding),
            _ => Err(DomActuatorError::UnsupportedFormat),
        }
    }
}

pub(crate) struct DomTerminalFinalityRecordV1<'checkpoint> {
    pub(crate) kind: DomTerminalKindV1,
    pub(crate) tx_hash: Digest32,
    pub(crate) block_height: u64,
    pub(crate) block_hash: Digest32,
    pub(crate) tip_height: u64,
    pub(crate) tip_hash: Digest32,
    pub(crate) confirmation_depth: u32,
    pub(crate) minimum_confirmations: u32,
    pub(crate) max_reorg_depth: u32,
    pub(crate) evidence_digest: Digest32,
    pub(crate) checkpoint_bytes: &'checkpoint [u8],
}

pub(crate) struct RetainedDomTerminalCheckpointV1 {
    pub(crate) kind: DomTerminalKindV1,
    pub(crate) tx_hash: Digest32,
    pub(crate) block_height: u64,
    pub(crate) block_hash: Digest32,
    pub(crate) minimum_confirmations: u32,
    pub(crate) max_reorg_depth: u32,
    pub(crate) evidence_digest: Digest32,
    pub(crate) checkpoint_bytes: Vec<u8>,
}

pub(crate) struct RetainedDomTerminalInvalidationV1 {
    pub(crate) kind: DomTerminalKindV1,
    pub(crate) tx_hash: Digest32,
    pub(crate) block_height: u64,
    pub(crate) block_hash: Digest32,
    pub(crate) prior_evidence_digest: Digest32,
    pub(crate) reorg_evidence_digest: Digest32,
}

pub(crate) struct DomTerminalReorgRecordV1 {
    pub(crate) kind: DomTerminalKindV1,
    pub(crate) tx_hash: Digest32,
    pub(crate) prior_evidence_digest: Digest32,
    pub(crate) current_tip_height: u64,
    pub(crate) current_tip_hash: Digest32,
    pub(crate) common_ancestor_height: u64,
    pub(crate) removed_depth: u32,
    pub(crate) minimum_confirmations: u32,
    pub(crate) max_reorg_depth: u32,
    pub(crate) evidence_digest: Digest32,
}

struct StoredDomTerminalFinalityV1 {
    kind: DomTerminalKindV1,
    tx_hash: Digest32,
    block_height: u64,
    block_hash: Digest32,
    tip_height: u64,
    tip_hash: Digest32,
    confirmation_depth: u32,
    minimum_confirmations: u32,
    max_reorg_depth: u32,
    evidence_digest: Digest32,
    checkpoint_bytes: Vec<u8>,
    checkpoint_digest: Digest32,
    record_digest: Digest32,
    active: bool,
    reorg_evidence_digest: Option<Digest32>,
    fencing_epoch: u64,
}

#[derive(Clone, Copy)]
struct StoredOperation {
    scope_digest: Digest32,
    evidence_digest: Digest32,
    secret_binding_digest: Option<Digest32>,
    authorization_digest: Digest32,
    fencing_epoch: u64,
    status: i64,
    receipt_digest: Option<Digest32>,
}

pub(crate) struct RetainedOutputReservationV1 {
    pub(crate) reservation_digest: Digest32,
    pub(crate) route_id: Digest32,
    pub(crate) session_id: Digest32,
    pub(crate) outputs: Vec<([u8; 33], u64)>,
    pub(crate) status: i64,
}

pub(crate) struct PreparedDomPayoutFaceV1 {
    pub(crate) binding: DomSessionBindingV1,
    pub(crate) payout_commitment: [u8; 33],
    pub(crate) payout_value: u64,
    pub(crate) wallet_ownership_digest: Digest32,
    pub(crate) store_instance_id: Digest32,
    pub(crate) prepare_digest: Digest32,
    pub(crate) created_at_unix_ms: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct RetainedDomPayoutFaceEvidenceV1 {
    pub(crate) binding: DomSessionBindingV1,
    pub(crate) payout_commitment: [u8; 33],
    pub(crate) payout_value: u64,
    pub(crate) wallet_ownership_digest: Digest32,
    pub(crate) store_instance_id: Digest32,
    pub(crate) prepare_digest: Digest32,
    pub(crate) wallet_ciphertext_digest: Digest32,
    pub(crate) evidence_revision: u64,
    pub(crate) record_digest: Digest32,
    pub(crate) created_at_unix_ms: u64,
}

#[derive(Clone, Copy)]
struct DomPayoutFaceRecordFactsV1 {
    binding: DomSessionBindingV1,
    payout_commitment: [u8; 33],
    payout_value: u64,
    wallet_ownership_digest: Digest32,
    store_instance_id: Digest32,
    prepare_digest: Digest32,
    wallet_ciphertext_digest: Digest32,
    evidence_revision: u64,
    event_effect_id: Digest32,
    event_digest: Digest32,
    created_at_unix_ms: u64,
}

struct RawOutputReservationByEffectRowV1 {
    reservation_digest: Vec<u8>,
    route_id: Vec<u8>,
    session_id: Vec<u8>,
    status: i64,
}

struct RawDomPayoutFaceEvidenceRowV1 {
    prepare_digest: Vec<u8>,
    route_id: Vec<u8>,
    participant_id: Vec<u8>,
    payout_commitment: Vec<u8>,
    payout_value: i64,
    wallet_ownership_digest: Vec<u8>,
    store_instance_id: Vec<u8>,
    wallet_ciphertext_digest: Vec<u8>,
    evidence_revision: i64,
    event_effect_id: Vec<u8>,
    event_digest: Vec<u8>,
    record_digest: Vec<u8>,
    created_at_unix_ms: i64,
}

impl RawDomPayoutFaceEvidenceRowV1 {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            prepare_digest: row.get(0)?,
            route_id: row.get(1)?,
            participant_id: row.get(2)?,
            payout_commitment: row.get(3)?,
            payout_value: row.get(4)?,
            wallet_ownership_digest: row.get(5)?,
            store_instance_id: row.get(6)?,
            wallet_ciphertext_digest: row.get(7)?,
            evidence_revision: row.get(8)?,
            event_effect_id: row.get(9)?,
            event_digest: row.get(10)?,
            record_digest: row.get(11)?,
            created_at_unix_ms: row.get(12)?,
        })
    }
}

struct RawDomPayoutFacePreparationRowV1 {
    route_id: Vec<u8>,
    participant_id: Vec<u8>,
    payout_commitment: Vec<u8>,
    payout_value: i64,
    wallet_ownership_digest: Vec<u8>,
    store_instance_id: Vec<u8>,
    prepare_digest: Vec<u8>,
    created_at_unix_ms: i64,
}

impl RawDomPayoutFacePreparationRowV1 {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            route_id: row.get(0)?,
            participant_id: row.get(1)?,
            payout_commitment: row.get(2)?,
            payout_value: row.get(3)?,
            wallet_ownership_digest: row.get(4)?,
            store_instance_id: row.get(5)?,
            prepare_digest: row.get(6)?,
            created_at_unix_ms: row.get(7)?,
        })
    }
}

impl RawOutputReservationByEffectRowV1 {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            reservation_digest: row.get(0)?,
            route_id: row.get(1)?,
            session_id: row.get(2)?,
            status: row.get(3)?,
        })
    }
}

#[derive(Clone, Copy)]
struct StoredSettlementChildBindingV1 {
    request: DomSettlementChildBindingRequestV1,
    transaction_id: Digest32,
    binding_record_digest: Digest32,
}

struct StoredSettlementChildPortCallV1 {
    key: DomSettlementChildPortCallKeyV1,
    actuator_fencing_epoch: u64,
    outcome: Option<DomSettlementChildPortCallOutcomeV1>,
    outcome_digest: Option<Digest32>,
}

struct RawClaimCustodyRowV1 {
    effect_id: Vec<u8>,
    route_id: Vec<u8>,
    participant_id: Vec<u8>,
    fencing_epoch: i64,
    authorization_digest: Vec<u8>,
    tx_hash: Vec<u8>,
    template_hash: Vec<u8>,
    shared_output_commitment: Vec<u8>,
    exact_bytes: Vec<u8>,
    exact_bytes_digest: Vec<u8>,
    record_digest: Vec<u8>,
    send_attempted: i64,
    send_attempt_count: i64,
}

impl RawClaimCustodyRowV1 {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            effect_id: row.get(0)?,
            route_id: row.get(1)?,
            participant_id: row.get(2)?,
            fencing_epoch: row.get(3)?,
            authorization_digest: row.get(4)?,
            tx_hash: row.get(5)?,
            template_hash: row.get(6)?,
            shared_output_commitment: row.get(7)?,
            exact_bytes: row.get(8)?,
            exact_bytes_digest: row.get(9)?,
            record_digest: row.get(10)?,
            send_attempted: row.get(11)?,
            send_attempt_count: row.get(12)?,
        })
    }
}

struct RawClaimAdmissionRowV1 {
    effect_id: Vec<u8>,
    route_id: Vec<u8>,
    participant_id: Vec<u8>,
    fencing_epoch: i64,
    tx_hash: Vec<u8>,
    claim_record_digest: Vec<u8>,
    receipt_state_tag: i64,
    receipt_relayed: i64,
    receipt_digest: Vec<u8>,
    record_digest: Vec<u8>,
}

impl RawClaimAdmissionRowV1 {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            effect_id: row.get(0)?,
            route_id: row.get(1)?,
            participant_id: row.get(2)?,
            fencing_epoch: row.get(3)?,
            tx_hash: row.get(4)?,
            claim_record_digest: row.get(5)?,
            receipt_state_tag: row.get(6)?,
            receipt_relayed: row.get(7)?,
            receipt_digest: row.get(8)?,
            record_digest: row.get(9)?,
        })
    }
}

struct RawTerminalFinalityRowV1 {
    kind_tag: i64,
    tx_hash: Vec<u8>,
    block_height: i64,
    block_hash: Vec<u8>,
    tip_height: i64,
    tip_hash: Vec<u8>,
    confirmation_depth: i64,
    minimum_confirmations: i64,
    max_reorg_depth: i64,
    evidence_digest: Vec<u8>,
    checkpoint_bytes: Vec<u8>,
    checkpoint_digest: Vec<u8>,
    record_digest: Vec<u8>,
    active: i64,
    reorg_evidence_digest: Option<Vec<u8>>,
    fencing_epoch: i64,
}

impl RawTerminalFinalityRowV1 {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            kind_tag: row.get(0)?,
            tx_hash: row.get(1)?,
            block_height: row.get(2)?,
            block_hash: row.get(3)?,
            tip_height: row.get(4)?,
            tip_hash: row.get(5)?,
            confirmation_depth: row.get(6)?,
            minimum_confirmations: row.get(7)?,
            max_reorg_depth: row.get(8)?,
            evidence_digest: row.get(9)?,
            checkpoint_bytes: row.get(10)?,
            checkpoint_digest: row.get(11)?,
            record_digest: row.get(12)?,
            active: row.get(13)?,
            reorg_evidence_digest: row.get(14)?,
            fencing_epoch: row.get(15)?,
        })
    }
}

struct RawSettlementChildBindingRowV1 {
    effect_id: Vec<u8>,
    route_id: Vec<u8>,
    session_id: Vec<u8>,
    participant_id: Vec<u8>,
    action_tag: i64,
    exposure_tag: i64,
    semantic_digest: Vec<u8>,
    registry_digest: Vec<u8>,
    terms_digest: Vec<u8>,
    profile_digest: Vec<u8>,
    deployment_digest: Vec<u8>,
    chain_id: Vec<u8>,
    transaction_id: Vec<u8>,
    intent_digest: Vec<u8>,
    binding_record_digest: Vec<u8>,
}

impl RawSettlementChildBindingRowV1 {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            effect_id: row.get(0)?,
            route_id: row.get(1)?,
            session_id: row.get(2)?,
            participant_id: row.get(3)?,
            action_tag: row.get(4)?,
            exposure_tag: row.get(5)?,
            semantic_digest: row.get(6)?,
            registry_digest: row.get(7)?,
            terms_digest: row.get(8)?,
            profile_digest: row.get(9)?,
            deployment_digest: row.get(10)?,
            chain_id: row.get(11)?,
            transaction_id: row.get(12)?,
            intent_digest: row.get(13)?,
            binding_record_digest: row.get(14)?,
        })
    }
}

struct RawSettlementChildPortCallRowV1 {
    call_kind: i64,
    request_digest: Vec<u8>,
    custody_digest: Vec<u8>,
    effect_id: Vec<u8>,
    binding_record_digest: Vec<u8>,
    actuator_fencing_epoch: i64,
    outcome_bytes: Option<Vec<u8>>,
    outcome_digest: Option<Vec<u8>>,
}

impl RawSettlementChildPortCallRowV1 {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            call_kind: row.get(0)?,
            request_digest: row.get(1)?,
            custody_digest: row.get(2)?,
            effect_id: row.get(3)?,
            binding_record_digest: row.get(4)?,
            actuator_fencing_epoch: row.get(5)?,
            outcome_bytes: row.get(6)?,
            outcome_digest: row.get(7)?,
        })
    }
}

struct RawSessionBindingRowV1 {
    route_id: Vec<u8>,
    participant_id: Vec<u8>,
    participant_index: i64,
    chain_id: Vec<u8>,
    genesis_hash: Vec<u8>,
    network_tag: i64,
    network_magic: i64,
    protocol_version: i64,
    rangeproof_serialization_version: i64,
    terms_digest: Vec<u8>,
    profile_digest: Vec<u8>,
    deployment_digest: Vec<u8>,
    asset_binding_digest: Vec<u8>,
    registry_epoch: i64,
    min_confirmations: i64,
    max_reorg_depth: i64,
}

impl RawSessionBindingRowV1 {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            route_id: row.get(0)?,
            participant_id: row.get(1)?,
            participant_index: row.get(2)?,
            chain_id: row.get(3)?,
            genesis_hash: row.get(4)?,
            network_tag: row.get(5)?,
            network_magic: row.get(6)?,
            protocol_version: row.get(7)?,
            rangeproof_serialization_version: row.get(8)?,
            terms_digest: row.get(9)?,
            profile_digest: row.get(10)?,
            deployment_digest: row.get(11)?,
            asset_binding_digest: row.get(12)?,
            registry_epoch: row.get(13)?,
            min_confirmations: row.get(14)?,
            max_reorg_depth: row.get(15)?,
        })
    }
}

struct RawOperationRowV1 {
    scope_digest: Vec<u8>,
    evidence_digest: Vec<u8>,
    secret_binding_digest: Option<Vec<u8>>,
    authorization_digest: Vec<u8>,
    fencing_epoch: i64,
    status_tag: i64,
    receipt_digest: Option<Vec<u8>>,
}

impl RawOperationRowV1 {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            scope_digest: row.get(0)?,
            evidence_digest: row.get(1)?,
            secret_binding_digest: row.get(2)?,
            authorization_digest: row.get(3)?,
            fencing_epoch: row.get(4)?,
            status_tag: row.get(5)?,
            receipt_digest: row.get(6)?,
        })
    }
}

#[derive(Clone, Copy)]
struct TerminalFinalityDigestMaterialV1 {
    kind: DomTerminalKindV1,
    tx_hash: Digest32,
    block_height: u64,
    block_hash: Digest32,
    tip_height: u64,
    tip_hash: Digest32,
    confirmation_depth: u32,
    minimum_confirmations: u32,
    max_reorg_depth: u32,
    evidence_digest: Digest32,
    checkpoint_digest: Digest32,
    reorg_evidence_digest: Option<Digest32>,
    active: bool,
    fencing_epoch: u64,
}

#[derive(Clone, Copy)]
struct ValidatedSubmissionReceiptFactsV1 {
    tx_hash: Digest32,
    state: SubmissionStateV1,
    relayed: bool,
    receipt_digest: Digest32,
}

impl ValidatedSubmissionReceiptFactsV1 {
    fn from_receipt(receipt: SubmissionReceiptV1) -> DomActuatorResult<Self> {
        let facts = Self {
            tx_hash: receipt.tx_hash(),
            state: receipt.state(),
            relayed: receipt.was_relayed(),
            receipt_digest: receipt.receipt_digest_v1(),
        };
        facts.validate()?;
        Ok(facts)
    }

    #[cfg(test)]
    fn for_test(
        tx_hash: Digest32,
        state: SubmissionStateV1,
        relayed: bool,
    ) -> DomActuatorResult<Self> {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(b"DOM:submission-receipt:v1");
        hasher.update(tx_hash);
        hasher.update([state.tag_v1(), u8::from(relayed)]);
        let facts = Self {
            tx_hash,
            state,
            relayed,
            receipt_digest: hasher.finalize().into(),
        };
        facts.validate()?;
        Ok(facts)
    }

    fn validate(self) -> DomActuatorResult<()> {
        validate_submission_receipt_facts_v1(
            self.tx_hash,
            self.state,
            self.relayed,
            self.receipt_digest,
        )
        .map_err(|_| DomActuatorError::CapabilityMismatch)
    }

    const fn tx_hash(self) -> Digest32 {
        self.tx_hash
    }

    const fn state(self) -> SubmissionStateV1 {
        self.state
    }

    const fn was_relayed(self) -> bool {
        self.relayed
    }

    const fn is_economically_admitted(self) -> bool {
        self.state.is_confirmed() || self.relayed
    }

    const fn receipt_digest_v1(self) -> Digest32 {
        self.receipt_digest
    }
}

/// Single-process, owner-only SQLite authority for participant control state.
///
/// The encrypted wallet and retained Contracts nonce vault remain separate
/// authorities. This database stores no seed, private key, blinding/share,
/// nonce or plaintext adaptor scalar. Its sole secret-bearing artifact is the
/// exact adapted claim transaction in dedicated owner-only custody; those bytes
/// never cross into the route store, formatting, codecs, or public accessors.
pub struct DomActuatorStoreV1 {
    connection: Connection,
    path: PathBuf,
    store_instance_id: Digest32,
    database_authority: File,
    _process_lock: File,
}

impl core::fmt::Debug for DomActuatorStoreV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DomActuatorStoreV1([redacted])")
    }
}

impl DomActuatorStoreV1 {
    /// Create a new owner-only production store without replacing any path.
    pub fn create(path: &Path) -> DomActuatorResult<Self> {
        Self::create_with_boundary_hook(path, |_| Ok(()))
    }

    fn create_with_boundary_hook<F>(path: &Path, mut boundary: F) -> DomActuatorResult<Self>
    where
        F: FnMut(CreationBoundaryV1) -> DomActuatorResult<()>,
    {
        require_linux()?;
        let parent = path
            .parent()
            .ok_or(DomActuatorError::InvalidStorageAuthority)?;
        validate_owner_directory(parent)?;
        require_create_path_absent(path)?;
        require_sidecars_absent(path)?;
        let process_lock = acquire_process_lock(path, true)?;
        boundary(CreationBoundaryV1::ProcessLockPublished)?;
        let database_authority = create_database_authority(path)?;
        boundary(CreationBoundaryV1::DatabaseFileSynced)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| DomActuatorError::StorageUnavailable)?;
        configure_connection(&connection)?;
        validate_database_path(&connection, path)?;
        validate_open_file_identity(&database_authority, path)?;
        boundary(CreationBoundaryV1::BeforeSchemaTransaction)?;
        create_schema_with_boundary_hook(&connection, || {
            boundary(CreationBoundaryV1::BeforeSchemaCommit)
        })?;
        boundary(CreationBoundaryV1::SchemaCommitted)?;
        let store_instance_id = load_store_instance_id(&connection)?;
        let store = Self {
            connection,
            path: path.to_path_buf(),
            store_instance_id,
            database_authority,
            _process_lock: process_lock,
        };
        store.audit_storage_authority()?;
        sync_directory(parent)?;
        Ok(store)
    }

    /// Resume only an authenticated empty crash prefix of an explicit
    /// production create whose exact intent is already durable externally.
    ///
    /// The owner-only lock published by [`Self::create`] must already exist
    /// and be exclusively acquirable. The database may be absent, pristine
    /// SQLite, or the exact V10 schema with every economic table empty. Foreign
    /// schema, metadata, sidecars, or retained economic state are refused.
    pub fn resume_create_production(path: &Path) -> DomActuatorResult<Self> {
        require_linux()?;
        let parent = path
            .parent()
            .ok_or(DomActuatorError::InvalidStorageAuthority)?;
        validate_owner_directory(parent)?;
        let process_lock = acquire_process_lock(path, false)?;
        let database_authority = match fs::symlink_metadata(path) {
            Ok(_) => {
                validate_owner_file(path)?;
                validate_resumable_sidecars(path)?;
                open_database_authority(path)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                require_sqlite_sidecars_absent(path)?;
                create_database_authority(path)?
            }
            Err(_) => return Err(DomActuatorError::StorageUnavailable),
        };
        let state = preflight_resumable_creation_state(path, &database_authority)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| DomActuatorError::StorageUnavailable)?;
        configure_connection(&connection)?;
        validate_database_path(&connection, path)?;
        validate_open_file_identity(&database_authority, path)?;
        match state {
            ResumableCreationStateV1::PristineSqlite => create_schema(&connection)?,
            ResumableCreationStateV1::InitializedExact => {}
        }
        validate_pristine_initialized_store(&connection)?;
        let store_instance_id = load_store_instance_id(&connection)?;
        let store = Self {
            connection,
            path: path.to_path_buf(),
            store_instance_id,
            database_authority,
            _process_lock: process_lock,
        };
        store.audit_storage_authority()?;
        sync_directory(parent)?;
        Ok(store)
    }

    /// Reopen an existing exact V10 production store; never create or migrate it.
    ///
    /// The schema version is part of the authenticated identity of this store.
    /// Prior databases — including V9, which has no wallet-authenticated payout
    /// evidence — are refused with `UnsupportedFormat` rather than upgraded in
    /// place, so no migration can run under a live route.
    pub fn open_existing(path: &Path) -> DomActuatorResult<Self> {
        require_linux()?;
        match fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(DomActuatorError::DatabaseMissing)
            }
            Err(_) => return Err(DomActuatorError::StorageUnavailable),
        }
        let parent = path
            .parent()
            .ok_or(DomActuatorError::InvalidStorageAuthority)?;
        validate_owner_directory(parent)?;
        validate_owner_file(path)?;
        validate_resumable_sidecars(path)?;
        let process_lock = acquire_process_lock(path, false)?;
        let database_authority = open_database_authority(path)?;
        if preflight_resumable_creation_state(path, &database_authority)?
            == ResumableCreationStateV1::PristineSqlite
        {
            return Err(DomActuatorError::CreationIncomplete);
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| DomActuatorError::StorageUnavailable)?;
        configure_connection(&connection)?;
        validate_database_path(&connection, path)?;
        validate_backend_and_schema(&connection)?;
        let store_instance_id = load_store_instance_id(&connection)?;
        let store = Self {
            connection,
            path: path.to_path_buf(),
            store_instance_id,
            database_authority,
            _process_lock: process_lock,
        };
        store.audit_storage_authority()?;
        Ok(store)
    }

    /// Acquire an absent/expired participant lease.  Every takeover increments
    /// the fencing epoch; an unexpired different owner fails closed.
    pub fn acquire_lease(
        &mut self,
        participant_id: Digest32,
        owner_id: Digest32,
        now_unix_ms: u64,
        duration_ms: u64,
    ) -> DomActuatorResult<DomLeaseV1> {
        validate_digest(participant_id)?;
        validate_digest(owner_id)?;
        let lease_until = deadline(now_unix_ms, duration_ms)?;
        let transaction = self.immediate()?;
        let existing = load_lease(&transaction, participant_id)?;
        let lease = match existing {
            None => {
                transaction
                    .execute(
                        "INSERT INTO dom_leases
                         (participant_id, owner_id, fencing_epoch,
                          lease_until_unix_ms, updated_at_unix_ms)
                         VALUES (?1, ?2, 1, ?3, ?4)",
                        params![
                            participant_id.as_slice(),
                            owner_id.as_slice(),
                            to_sql(lease_until)?,
                            to_sql(now_unix_ms)?
                        ],
                    )
                    .map_err(storage)?;
                DomLeaseV1 {
                    participant_id,
                    owner_id,
                    fencing_epoch: 1,
                    lease_until_unix_ms: lease_until,
                }
            }
            Some((current_owner, epoch, until)) if until >= now_unix_ms => {
                if current_owner != owner_id {
                    return Err(DomActuatorError::LeaseHeld);
                }
                DomLeaseV1 {
                    participant_id,
                    owner_id,
                    fencing_epoch: epoch,
                    lease_until_unix_ms: until,
                }
            }
            Some((_old_owner, epoch, _until)) => {
                let next = epoch
                    .checked_add(1)
                    .ok_or(DomActuatorError::InvalidBinding)?;
                transaction
                    .execute(
                        "UPDATE dom_leases SET owner_id=?2, fencing_epoch=?3,
                         lease_until_unix_ms=?4, updated_at_unix_ms=?5
                         WHERE participant_id=?1 AND fencing_epoch=?6",
                        params![
                            participant_id.as_slice(),
                            owner_id.as_slice(),
                            to_sql(next)?,
                            to_sql(lease_until)?,
                            to_sql(now_unix_ms)?,
                            to_sql(epoch)?
                        ],
                    )
                    .map_err(storage)?;
                DomLeaseV1 {
                    participant_id,
                    owner_id,
                    fencing_epoch: next,
                    lease_until_unix_ms: lease_until,
                }
            }
        };
        transaction.commit().map_err(storage)?;
        Ok(lease)
    }

    /// Renew the exact live lease without changing its fencing generation.
    pub fn renew_lease(
        &mut self,
        lease: DomLeaseV1,
        now_unix_ms: u64,
        duration_ms: u64,
    ) -> DomActuatorResult<DomLeaseV1> {
        let until = deadline(now_unix_ms, duration_ms)?;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let changed = transaction
            .execute(
                "UPDATE dom_leases SET lease_until_unix_ms=?4,
                 updated_at_unix_ms=?5 WHERE participant_id=?1 AND owner_id=?2
                 AND fencing_epoch=?3",
                params![
                    lease.participant_id.as_slice(),
                    lease.owner_id.as_slice(),
                    to_sql(lease.fencing_epoch)?,
                    to_sql(until)?,
                    to_sql(now_unix_ms)?
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(DomActuatorError::StaleFence);
        }
        transaction.commit().map_err(storage)?;
        Ok(DomLeaseV1 {
            lease_until_unix_ms: until,
            ..lease
        })
    }

    /// Bind one route/session to the sole participant and authenticated DOM deployment.
    pub fn bind_session(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        binding.validate()?;
        if binding.participant().participant_id() != lease.participant_id {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        if let Some(stored) = load_binding(&transaction, binding.session_id())? {
            if stored != binding {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            transaction.commit().map_err(storage)?;
            return Ok(DomOperationDispositionV1::Idempotent);
        }
        transaction
            .execute(
                "INSERT INTO dom_sessions
                 (session_id, route_id, participant_id, participant_index,
                  chain_id, genesis_hash, network_tag, network_magic, protocol_version,
                  rangeproof_serialization_version, terms_digest, profile_digest, deployment_digest,
                  asset_binding_digest, registry_epoch, min_confirmations, max_reorg_depth,
                  stage_tag, revision,
                  journal_head, created_at_unix_ms, updated_at_unix_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,0,0,?18,?19,?19)",
                params![
                    binding.session_id().as_slice(),
                    binding.route_id().as_slice(),
                    binding.participant().participant_id().as_slice(),
                    i64::from(binding.participant().protocol_index()),
                    binding.chain_id().as_slice(),
                    binding.genesis_hash().as_slice(),
                    i64::from(binding.runtime_identity().network as u8),
                    i64::from(binding.runtime_identity().network_magic),
                    i64::from(binding.runtime_identity().protocol_version),
                    i64::from(binding.runtime_identity().range_proof_serialization_version),
                    binding.terms_digest().as_slice(),
                    binding.profile_digest().as_slice(),
                    binding.deployment_digest().as_slice(),
                    binding.asset_binding_digest().as_slice(),
                    to_sql(binding.registry_epoch())?,
                    i64::from(binding.min_confirmations()),
                    i64::from(binding.max_reorg_depth()),
                    [0_u8; 32].as_slice(),
                    to_sql(now_unix_ms)?
                ],
            )
            .map_err(storage)?;
        transaction.commit().map_err(storage)?;
        Ok(DomOperationDispositionV1::Prepared)
    }

    /// Persists the exact owner-minted intent before the encrypted wallet is
    /// mutated. This phase never advances the session revision and cannot mint
    /// an F6 authority.
    pub(crate) fn prepare_payout_face(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        payout_commitment: [u8; 33],
        payout_value: u64,
        wallet_ownership_digest: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<PreparedDomPayoutFaceV1> {
        binding.validate()?;
        validate_digest(wallet_ownership_digest)?;
        if payout_value == 0 || Commitment::from_compressed_bytes(&payout_commitment).is_err() {
            return Err(DomActuatorError::InvalidBinding);
        }
        let store_instance_id = self.store_instance_id;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        if let Some(prepared) = load_payout_face_preparation(&transaction, binding)? {
            if prepared.payout_commitment != payout_commitment
                || prepared.payout_value != payout_value
                || prepared.wallet_ownership_digest != wallet_ownership_digest
                || prepared.store_instance_id != store_instance_id
            {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            if load_payout_face_evidence(&transaction, binding)?.is_some() {
                return Err(DomActuatorError::CapabilityMismatch);
            }
            transaction.commit().map_err(storage)?;
            return Ok(prepared);
        }
        if load_stage(&transaction, binding.session_id())? != STAGE_BOUND {
            return Err(DomActuatorError::InvalidStage);
        }
        let prepare_digest = payout_face_prepare_digest(
            binding,
            payout_commitment,
            payout_value,
            wallet_ownership_digest,
            store_instance_id,
            now_unix_ms,
        );
        transaction
            .execute(
                "INSERT INTO dom_payout_face_preparations
                 (session_id,route_id,participant_id,payout_commitment,payout_value,
                  wallet_ownership_digest,store_instance_id,prepare_digest,created_at_unix_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    binding.session_id().as_slice(),
                    binding.route_id().as_slice(),
                    binding.participant().participant_id().as_slice(),
                    payout_commitment.as_slice(),
                    to_sql(payout_value)?,
                    wallet_ownership_digest.as_slice(),
                    store_instance_id.as_slice(),
                    prepare_digest.as_slice(),
                    to_sql(now_unix_ms)?,
                ],
            )
            .map_err(|_| DomActuatorError::IdempotencyConflict)?;
        transaction.commit().map_err(storage)?;
        Ok(PreparedDomPayoutFaceV1 {
            binding,
            payout_commitment,
            payout_value,
            wallet_ownership_digest,
            store_instance_id,
            prepare_digest,
            created_at_unix_ms: now_unix_ms,
        })
    }

    /// Reissues an existing preparation for an already-pinned wallet. It never
    /// creates a row, so a wallet restored without its exact actuator Store is
    /// refused instead of being adopted by a fresh Store.
    pub(crate) fn recover_payout_face_preparation(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        prepare_digest: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<PreparedDomPayoutFaceV1> {
        validate_digest(prepare_digest)?;
        let store_instance_id = self.store_instance_id;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        let prepared = load_payout_face_preparation(&transaction, binding)?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if prepared.prepare_digest != prepare_digest
            || prepared.store_instance_id != store_instance_id
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        transaction.commit().map_err(storage)?;
        Ok(prepared)
    }

    /// Recovers the exact wallet selection already bound to this session.
    ///
    /// This read-only seam exists so the wallet can resume payout ownership
    /// without accepting a commitment from the composition root. It returns
    /// no blinding, capability or generic store handle.
    pub(crate) fn retained_payout_face_selection(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<Option<([u8; 33], u64)>> {
        binding.validate()?;
        let store_instance_id = self.store_instance_id;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        let Some(prepared) = load_payout_face_preparation(&transaction, binding)? else {
            transaction.commit().map_err(storage)?;
            return Ok(None);
        };
        if prepared.store_instance_id != store_instance_id {
            return Err(DomActuatorError::InvalidStorageAuthority);
        }
        if let Some(retained) = load_payout_face_evidence(&transaction, binding)? {
            if !active_payout_face_matches_preparation(&retained, &prepared) {
                return Err(DomActuatorError::IdempotencyConflict);
            }
        }
        transaction.commit().map_err(storage)?;
        Ok(Some((prepared.payout_commitment, prepared.payout_value)))
    }

    /// Activates one exact preparation only after the encrypted wallet pin was
    /// fsynced. The first activation appends exactly one session event; restart
    /// reissues the same active evidence without another revision.
    pub(crate) fn activate_payout_face(
        &mut self,
        lease: DomLeaseV1,
        prepared: &PreparedDomPayoutFaceV1,
        wallet_ciphertext_digest: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<RetainedDomPayoutFaceEvidenceV1> {
        validate_digest(wallet_ciphertext_digest)?;
        let binding = prepared.binding;
        let store_instance_id = self.store_instance_id;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        let stored = load_payout_face_preparation(&transaction, binding)?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if !prepared_payout_face_matches(&stored, prepared)
            || prepared.store_instance_id != store_instance_id
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        if let Some(retained) = load_payout_face_evidence(&transaction, binding)? {
            if !active_payout_face_matches_preparation(&retained, prepared) {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            transaction.commit().map_err(storage)?;
            return Ok(retained);
        }
        if load_stage(&transaction, binding.session_id())? != STAGE_BOUND {
            return Err(DomActuatorError::InvalidStage);
        }
        let event_effect_id = hash_parts(&[
            PAYOUT_FACE_EFFECT_DOMAIN,
            prepared.prepare_digest.as_slice(),
            prepared.store_instance_id.as_slice(),
        ]);
        let event_digest = hash_parts(&[
            PAYOUT_FACE_EVENT_DOMAIN,
            event_effect_id.as_slice(),
            prepared.wallet_ownership_digest.as_slice(),
            wallet_ciphertext_digest.as_slice(),
            binding.terms_digest().as_slice(),
            binding.deployment_digest().as_slice(),
            binding.asset_binding_digest().as_slice(),
        ]);
        let current_revision: i64 = transaction
            .query_row(
                "SELECT revision FROM dom_sessions WHERE session_id=?1",
                params![binding.session_id().as_slice()],
                |row| row.get(0),
            )
            .map_err(storage)?;
        let evidence_revision = from_sql(current_revision)?
            .checked_add(1)
            .ok_or(DomActuatorError::RevisionConflict)?;
        append_event(
            &transaction,
            binding.session_id(),
            event_effect_id,
            event_digest,
            STAGE_BOUND,
            lease.fencing_epoch,
            now_unix_ms,
        )?;
        let record_digest = payout_face_record_digest(&DomPayoutFaceRecordFactsV1 {
            binding,
            payout_commitment: prepared.payout_commitment,
            payout_value: prepared.payout_value,
            wallet_ownership_digest: prepared.wallet_ownership_digest,
            store_instance_id: prepared.store_instance_id,
            prepare_digest: prepared.prepare_digest,
            wallet_ciphertext_digest,
            evidence_revision,
            event_effect_id,
            event_digest,
            created_at_unix_ms: now_unix_ms,
        });
        transaction
            .execute(
                "INSERT INTO dom_payout_face_evidence
                 (session_id,prepare_digest,route_id,participant_id,payout_commitment,payout_value,
                  wallet_ownership_digest,store_instance_id,wallet_ciphertext_digest,
                  evidence_revision,event_effect_id,event_digest,record_digest,created_at_unix_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![
                    binding.session_id().as_slice(),
                    prepared.prepare_digest.as_slice(),
                    binding.route_id().as_slice(),
                    binding.participant().participant_id().as_slice(),
                    prepared.payout_commitment.as_slice(),
                    to_sql(prepared.payout_value)?,
                    prepared.wallet_ownership_digest.as_slice(),
                    prepared.store_instance_id.as_slice(),
                    wallet_ciphertext_digest.as_slice(),
                    to_sql(evidence_revision)?,
                    event_effect_id.as_slice(),
                    event_digest.as_slice(),
                    record_digest.as_slice(),
                    to_sql(now_unix_ms)?,
                ],
            )
            .map_err(|_| DomActuatorError::IdempotencyConflict)?;
        transaction.commit().map_err(storage)?;
        Ok(RetainedDomPayoutFaceEvidenceV1 {
            binding,
            payout_commitment: prepared.payout_commitment,
            payout_value: prepared.payout_value,
            wallet_ownership_digest: prepared.wallet_ownership_digest,
            store_instance_id: prepared.store_instance_id,
            prepare_digest: prepared.prepare_digest,
            wallet_ciphertext_digest,
            evidence_revision,
            record_digest,
            created_at_unix_ms: now_unix_ms,
        })
    }

    pub(crate) fn validate_payout_face(
        &mut self,
        lease: DomLeaseV1,
        expected: &RetainedDomPayoutFaceEvidenceV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<()> {
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, expected.binding)?;
        let retained = load_payout_face_evidence(&transaction, expected.binding)?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if retained.binding != expected.binding
            || retained.payout_commitment != expected.payout_commitment
            || retained.payout_value != expected.payout_value
            || retained.wallet_ownership_digest != expected.wallet_ownership_digest
            || retained.store_instance_id != expected.store_instance_id
            || retained.prepare_digest != expected.prepare_digest
            || retained.wallet_ciphertext_digest != expected.wallet_ciphertext_digest
            || retained.record_digest != expected.record_digest
            || retained.evidence_revision != expected.evidence_revision
            || retained.created_at_unix_ms != expected.created_at_unix_ms
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        transaction.commit().map_err(storage)
    }

    /// Persist an exact action intent before returning its move-only capability.
    ///
    /// `secret_binding_digest` is mandatory for shared-output, Bulletproof and
    /// signing actions and is globally one-shot. It is a public vault/session
    /// commitment, never the secret itself.
    pub fn authorize_action(
        &mut self,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        evidence_digest: Digest32,
        secret_binding_digest: Option<Digest32>,
        now_unix_ms: u64,
    ) -> DomActuatorResult<(DomActuatorCapabilityV1, DomOperationDispositionV1)> {
        validate_digest(evidence_digest)?;
        if scope.action().consumes_unique_secret_binding() != secret_binding_digest.is_some() {
            return Err(DomActuatorError::InvalidBinding);
        }
        if let Some(digest) = secret_binding_digest {
            validate_digest(digest)?;
        }
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_scope(&transaction, lease, scope)?;
        require_no_refund_after_claim_exposure(&transaction, scope)?;
        let scope_digest = scope_digest(scope);
        let authorization_digest = authorization_digest(
            scope_digest,
            evidence_digest,
            secret_binding_digest,
            lease.fencing_epoch,
        );
        if let Some(existing) = load_operation(&transaction, scope.effect_id())? {
            if existing.scope_digest != scope_digest
                || existing.evidence_digest != evidence_digest
                || existing.secret_binding_digest != secret_binding_digest
            {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            if existing.fencing_epoch != lease.fencing_epoch {
                return Err(DomActuatorError::ReconciliationRequired);
            }
            if existing.authorization_digest != authorization_digest {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            let disposition = if existing.status == OP_COMPLETED {
                DomOperationDispositionV1::AlreadyCompleted
            } else {
                DomOperationDispositionV1::Idempotent
            };
            transaction.commit().map_err(storage)?;
            return Ok((
                DomActuatorCapabilityV1::issue(
                    scope,
                    lease.fencing_epoch,
                    authorization_digest,
                    CapabilityIssuanceV1::Resumed,
                ),
                disposition,
            ));
        }
        let stage = load_stage(&transaction, scope.binding().session_id())?;
        require_action_stage(stage, scope.action())?;
        let result = transaction.execute(
            "INSERT INTO dom_operations
             (effect_id,route_id,session_id,participant_id,action_tag,
              fencing_epoch,scope_digest,evidence_digest,secret_binding_digest,
              authorization_digest,status_tag,receipt_digest,reconciliation_digest,
              created_at_unix_ms,updated_at_unix_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,NULL,NULL,?11,?11)",
            params![
                scope.effect_id().as_slice(),
                scope.binding().route_id().as_slice(),
                scope.binding().session_id().as_slice(),
                scope.binding().participant().participant_id().as_slice(),
                i64::from(scope.action().tag()),
                to_sql(lease.fencing_epoch)?,
                scope_digest.as_slice(),
                evidence_digest.as_slice(),
                secret_binding_digest.map(|value| value.to_vec()),
                authorization_digest.as_slice(),
                to_sql(now_unix_ms)?
            ],
        );
        if result.is_err() {
            if secret_binding_digest.is_some() {
                return Err(DomActuatorError::SecretReuseDetected);
            }
            return Err(DomActuatorError::StorageUnavailable);
        }
        transaction.commit().map_err(storage)?;
        Ok((
            DomActuatorCapabilityV1::issue(
                scope,
                lease.fencing_epoch,
                authorization_digest,
                CapabilityIssuanceV1::Fresh,
            ),
            DomOperationDispositionV1::Prepared,
        ))
    }

    /// Complete a non-reservation action with a public receipt commitment.
    pub(crate) fn complete_action(
        &mut self,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        receipt_digest: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        validate_digest(receipt_digest)?;
        if capability.scope().action() == DomActionV1::ReserveOutputs {
            return Err(DomActuatorError::InvalidStage);
        }
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        validate_capability(&transaction, lease, &capability)?;
        let existing = load_operation(&transaction, capability.scope().effect_id())?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if existing.status == OP_COMPLETED {
            if existing.receipt_digest == Some(receipt_digest) {
                transaction.commit().map_err(storage)?;
                return Ok(DomOperationDispositionV1::AlreadyCompleted);
            }
            return Err(DomActuatorError::IdempotencyConflict);
        }
        complete_operation_and_advance(
            &transaction,
            lease,
            capability.scope(),
            receipt_digest,
            now_unix_ms,
        )?;
        transaction.commit().map_err(storage)?;
        Ok(DomOperationDispositionV1::Prepared)
    }

    /// Persist one coordinator locator only after the Contracts façade has
    /// reauthenticated the exact retained transaction identity.
    ///
    /// This entry point is crate-private so a caller cannot install a
    /// request-shaped transaction id.  The row contains commitments only and is
    /// atomically crossed against the completed route action before commit.
    pub(crate) fn persist_authenticated_settlement_child_binding(
        &mut self,
        lease: DomLeaseV1,
        request: DomSettlementChildBindingRequestV1,
        transaction_id: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomSettlementChildBindingV1> {
        request.validate()?;
        validate_digest(transaction_id)?;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_scope(&transaction, lease, request.scope())?;
        let operation = load_operation(&transaction, request.scope().effect_id())?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if operation.status != OP_COMPLETED
            || operation.fencing_epoch > lease.fencing_epoch
            || operation.scope_digest != scope_digest(request.scope())
            || !settlement_child_transaction_matches_operation(
                &transaction,
                request,
                transaction_id,
                operation,
            )?
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let record_digest = settlement_child_binding_record_digest(request, transaction_id);
        if let Some(existing) =
            load_settlement_child_binding(&transaction, request.custody_digest())?
        {
            if existing.request != request
                || existing.transaction_id != transaction_id
                || existing.binding_record_digest != record_digest
            {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            let view = validate_settlement_child_binding(&transaction, existing)?;
            transaction.commit().map_err(storage)?;
            return Ok(view);
        }
        if load_settlement_child_binding_by_effect(&transaction, request.scope().effect_id())?
            .is_some()
        {
            return Err(DomActuatorError::IdempotencyConflict);
        }
        let scope = request.scope();
        let binding = scope.binding();
        transaction
            .execute(
                "INSERT INTO dom_settlement_children
                 (custody_digest,effect_id,route_id,session_id,participant_id,
                  action_tag,exposure_tag,semantic_digest,registry_digest,
                  terms_digest,profile_digest,deployment_digest,chain_id,
                  transaction_id,intent_digest,binding_record_digest,created_at_unix_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![
                    request.custody_digest().as_slice(),
                    scope.effect_id().as_slice(),
                    binding.route_id().as_slice(),
                    binding.session_id().as_slice(),
                    binding.participant().participant_id().as_slice(),
                    i64::from(scope.action().tag()),
                    i64::from(request.exposure().tag()),
                    request.semantic_digest().as_slice(),
                    request.registry_digest().as_slice(),
                    binding.terms_digest().as_slice(),
                    binding.profile_digest().as_slice(),
                    binding.deployment_digest().as_slice(),
                    binding.chain_id().as_slice(),
                    transaction_id.as_slice(),
                    request.intent_digest().as_slice(),
                    record_digest.as_slice(),
                    to_sql(now_unix_ms)?,
                ],
            )
            .map_err(storage)?;
        let stored = load_settlement_child_binding(&transaction, request.custody_digest())?
            .ok_or(DomActuatorError::StorageUnavailable)?;
        let view = validate_settlement_child_binding(&transaction, stored)?;
        transaction.commit().map_err(storage)?;
        Ok(view)
    }

    /// Atomically reload one raw-free settlement-child binding under the live
    /// participant lease.
    ///
    /// Kept crate-private so production callers must pass through
    /// `DomContractsActuatorV1`, which reauthenticates the same transaction in
    /// the one already-open Contracts store before releasing this view.
    pub(crate) fn settlement_child_binding(
        &mut self,
        lease: DomLeaseV1,
        custody_digest: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomSettlementChildBindingV1> {
        validate_digest(custody_digest)?;
        let transaction = self.deferred()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let stored = load_settlement_child_binding(&transaction, custody_digest)?
            .ok_or(DomActuatorError::ReconciliationRequired)?;
        let view = validate_settlement_child_binding(&transaction, stored)?;
        if view
            .request()
            .scope()
            .binding()
            .participant()
            .participant_id()
            != lease.participant_id
            || view.operation_fencing_epoch() > lease.fencing_epoch
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        transaction.commit().map_err(storage)?;
        Ok(view)
    }

    /// Durably reserve or replay one exact coordinator child-port call.
    ///
    /// The request digest must cover the complete canonical dispatch,
    /// reconciliation or observation request. Reusing an attempt id with any
    /// other family, request, effect or custody locator fails closed.
    pub fn begin_settlement_child_port_call(
        &mut self,
        lease: DomLeaseV1,
        key: DomSettlementChildPortCallKeyV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomSettlementChildPortCallJournalStatusV1> {
        validate_settlement_child_port_call_key(key)?;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let binding = require_settlement_child_port_call_binding(&transaction, lease, key)?;
        if let Some(existing) =
            load_settlement_child_port_call(&transaction, key.coordinator_attempt_id())?
        {
            require_settlement_child_port_call_key(&existing, key, lease)?;
            let status = settlement_child_port_call_status(&existing)?;
            if let DomSettlementChildPortCallJournalStatusV1::Committed(outcome) = status {
                validate_settlement_child_port_call_outcome(&binding, key.call_kind(), outcome)?;
            }
            transaction.commit().map_err(storage)?;
            return Ok(status);
        }
        transaction
            .execute(
                "INSERT INTO dom_settlement_child_port_calls
                 (call_kind,coordinator_attempt_id,request_digest,custody_digest,
                  effect_id,binding_record_digest,actuator_fencing_epoch,
                  outcome_bytes,outcome_digest,created_at_unix_ms,committed_at_unix_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,NULL,NULL,?8,NULL)",
                params![
                    i64::from(key.call_kind().tag()),
                    key.coordinator_attempt_id().as_slice(),
                    key.request_digest().as_slice(),
                    key.locator().custody_digest().as_slice(),
                    key.locator().effect_id().as_slice(),
                    key.locator().binding_record_digest().as_slice(),
                    to_sql(lease.fencing_epoch)?,
                    to_sql(now_unix_ms)?,
                ],
            )
            .map_err(storage)?;
        transaction.commit().map_err(storage)?;
        Ok(DomSettlementChildPortCallJournalStatusV1::Pending)
    }

    /// Commit a stable public child-port result before returning it upstream.
    ///
    /// Recommitting the exact result is an idempotent restart replay. A
    /// different result for the same attempt is rejected.
    pub fn commit_settlement_child_port_call_outcome(
        &mut self,
        lease: DomLeaseV1,
        key: DomSettlementChildPortCallKeyV1,
        outcome: DomSettlementChildPortCallOutcomeV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomSettlementChildPortCallOutcomeV1> {
        validate_settlement_child_port_call_key(key)?;
        outcome.validate_for(key.call_kind())?;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let binding = require_settlement_child_port_call_binding(&transaction, lease, key)?;
        validate_settlement_child_port_call_outcome(&binding, key.call_kind(), outcome)?;
        let existing = load_settlement_child_port_call(&transaction, key.coordinator_attempt_id())?
            .ok_or(DomActuatorError::InvalidStage)?;
        require_settlement_child_port_call_key(&existing, key, lease)?;
        if let DomSettlementChildPortCallJournalStatusV1::Committed(committed) =
            settlement_child_port_call_status(&existing)?
        {
            if committed != outcome {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            transaction.commit().map_err(storage)?;
            return Ok(committed);
        }
        let outcome_bytes = outcome.canonical_bytes();
        let outcome_digest = settlement_child_port_call_outcome_digest(&outcome_bytes);
        let changed = transaction
            .execute(
                "UPDATE dom_settlement_child_port_calls SET
                 outcome_bytes=?1,outcome_digest=?2,committed_at_unix_ms=?3
                 WHERE call_kind=?4 AND coordinator_attempt_id=?5
                 AND outcome_bytes IS NULL AND outcome_digest IS NULL
                 AND committed_at_unix_ms IS NULL",
                params![
                    outcome_bytes.as_slice(),
                    outcome_digest.as_slice(),
                    to_sql(now_unix_ms)?,
                    i64::from(key.call_kind().tag()),
                    key.coordinator_attempt_id().as_slice(),
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(DomActuatorError::IdempotencyConflict);
        }
        let committed =
            load_settlement_child_port_call(&transaction, key.coordinator_attempt_id())?
                .ok_or(DomActuatorError::UnsupportedFormat)?;
        require_settlement_child_port_call_key(&committed, key, lease)?;
        let result = match settlement_child_port_call_status(&committed)? {
            DomSettlementChildPortCallJournalStatusV1::Committed(value) => value,
            DomSettlementChildPortCallJournalStatusV1::Pending => {
                return Err(DomActuatorError::UnsupportedFormat)
            }
        };
        transaction.commit().map_err(storage)?;
        Ok(result)
    }

    /// Re-fence an old prepared action only after public proof that it was not externalized.
    pub fn reauthorize_not_externalized(
        &mut self,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        previous_authorization_digest: Digest32,
        non_externalization_evidence: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomActuatorCapabilityV1> {
        if scope.action() == DomActionV1::BroadcastClaim {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        validate_digest(non_externalization_evidence)?;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_scope(&transaction, lease, scope)?;
        require_no_refund_after_claim_exposure(&transaction, scope)?;
        let existing = load_operation(&transaction, scope.effect_id())?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if existing.scope_digest != scope_digest(scope)
            || existing.authorization_digest != previous_authorization_digest
            || existing.status != OP_PREPARED
            || existing.fencing_epoch >= lease.fencing_epoch
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let next = authorization_digest(
            existing.scope_digest,
            existing.evidence_digest,
            existing.secret_binding_digest,
            lease.fencing_epoch,
        );
        let changed = transaction
            .execute(
                "UPDATE dom_operations SET fencing_epoch=?2,
                 authorization_digest=?3,reconciliation_digest=?4,
                 updated_at_unix_ms=?5 WHERE effect_id=?1 AND status_tag=0
                 AND fencing_epoch=?6",
                params![
                    scope.effect_id().as_slice(),
                    to_sql(lease.fencing_epoch)?,
                    next.as_slice(),
                    non_externalization_evidence.as_slice(),
                    to_sql(now_unix_ms)?,
                    to_sql(existing.fencing_epoch)?
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(DomActuatorError::RevisionConflict);
        }
        transaction.commit().map_err(storage)?;
        Ok(DomActuatorCapabilityV1::issue(
            scope,
            lease.fencing_epoch,
            next,
            CapabilityIssuanceV1::Resumed,
        ))
    }

    /// Re-fence an exact retained funding/refund replay after takeover.
    ///
    /// This narrow path is crate-private because only the Contracts façade can
    /// supply `receipt_digest` from its authenticated exact-byte outbox. It
    /// never reopens a signing/share operation and never changes the completed
    /// receipt or session stage.
    pub(crate) fn reauthorize_retained_exact_replay(
        &mut self,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        previous_authorization_digest: Digest32,
        receipt_digest: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomActuatorCapabilityV1> {
        validate_digest(receipt_digest)?;
        if !matches!(
            scope.action(),
            DomActionV1::BroadcastFunding | DomActionV1::BroadcastRefund
        ) {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_scope(&transaction, lease, scope)?;
        require_no_refund_after_claim_exposure(&transaction, scope)?;
        let existing = load_operation(&transaction, scope.effect_id())?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if existing.scope_digest != scope_digest(scope)
            || existing.authorization_digest != previous_authorization_digest
            || existing.status != OP_COMPLETED
            || existing.receipt_digest != Some(receipt_digest)
            || existing.fencing_epoch >= lease.fencing_epoch
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let next = authorization_digest(
            existing.scope_digest,
            existing.evidence_digest,
            existing.secret_binding_digest,
            lease.fencing_epoch,
        );
        let reconciliation = hash_parts(&[
            b"DOM:actuator-retained-exact-replay:v1",
            &scope.binding().session_id(),
            &scope.effect_id(),
            &[scope.action().tag()],
            &receipt_digest,
            &lease.fencing_epoch.to_be_bytes(),
        ]);
        let changed = transaction
            .execute(
                "UPDATE dom_operations SET fencing_epoch=?2,
                 authorization_digest=?3,reconciliation_digest=?4,
                 updated_at_unix_ms=?5 WHERE effect_id=?1 AND status_tag=1
                 AND fencing_epoch=?6 AND receipt_digest=?7",
                params![
                    scope.effect_id().as_slice(),
                    to_sql(lease.fencing_epoch)?,
                    next.as_slice(),
                    reconciliation.as_slice(),
                    to_sql(now_unix_ms)?,
                    to_sql(existing.fencing_epoch)?,
                    receipt_digest.as_slice()
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(DomActuatorError::RevisionConflict);
        }
        transaction.commit().map_err(storage)?;
        Ok(DomActuatorCapabilityV1::issue(
            scope,
            lease.fencing_epoch,
            next,
            CapabilityIssuanceV1::Resumed,
        ))
    }

    /// Reconcile an old prepared action as already externalized, without retrying it.
    pub fn reconcile_externalized(
        &mut self,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        previous_authorization_digest: Digest32,
        receipt_digest: Digest32,
        reconciliation_evidence: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<()> {
        if scope.action() == DomActionV1::BroadcastClaim {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        validate_digest(receipt_digest)?;
        validate_digest(reconciliation_evidence)?;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_scope(&transaction, lease, scope)?;
        require_no_refund_after_claim_exposure(&transaction, scope)?;
        let existing = load_operation(&transaction, scope.effect_id())?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if existing.scope_digest != scope_digest(scope)
            || existing.authorization_digest != previous_authorization_digest
            || existing.status != OP_PREPARED
            || existing.fencing_epoch >= lease.fencing_epoch
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        transaction
            .execute(
                "UPDATE dom_operations SET reconciliation_digest=?2
                 WHERE effect_id=?1 AND status_tag=0",
                params![
                    scope.effect_id().as_slice(),
                    reconciliation_evidence.as_slice()
                ],
            )
            .map_err(storage)?;
        complete_operation_and_advance(&transaction, lease, scope, receipt_digest, now_unix_ms)?;
        transaction.commit().map_err(storage)?;
        Ok(())
    }

    /// Apply one public canonical/finality/reorg observation under the current fence.
    pub(crate) fn record_chain_observation(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        event_id: Digest32,
        observation: DomChainObservationV1,
        evidence_digest: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        validate_digest(event_id)?;
        validate_digest(evidence_digest)?;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        let stage = load_stage(&transaction, binding.session_id())?;
        let next = match observation {
            DomChainObservationV1::FundingConfirmed
                if matches!(stage, STAGE_FUNDING_BROADCAST | STAGE_REORG_RECOVERY) =>
            {
                STAGE_FUNDING_CONFIRMED
            }
            DomChainObservationV1::FundingReorg
                if matches!(
                    stage,
                    STAGE_FUNDING_CONFIRMED | STAGE_CLAIM_BROADCAST | STAGE_REFUND_BROADCAST
                ) =>
            {
                STAGE_REORG_RECOVERY
            }
            _ => return Err(DomActuatorError::InvalidStage),
        };
        let event_digest = hash_parts(&[
            b"DOM:actuator-observation:v1",
            &binding.route_id(),
            &binding.session_id(),
            &event_id,
            &[observation.tag()],
            &evidence_digest,
        ]);
        if event_already_applied(&transaction, binding.session_id(), event_id, event_digest)? {
            transaction.commit().map_err(storage)?;
            return Ok(DomOperationDispositionV1::Idempotent);
        }
        append_event(
            &transaction,
            binding.session_id(),
            event_id,
            event_digest,
            next,
            lease.fencing_epoch,
            now_unix_ms,
        )?;
        transaction.commit().map_err(storage)?;
        Ok(DomOperationDispositionV1::Prepared)
    }

    pub(crate) fn record_terminal_finality(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        record: DomTerminalFinalityRecordV1<'_>,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        validate_terminal_finality_record(binding, &record)?;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        if record.kind == DomTerminalKindV1::Claim {
            require_exposed_claim_identity(&transaction, binding, record.tx_hash)?;
        }
        let expected_stage = match record.kind {
            DomTerminalKindV1::Claim => STAGE_CLAIM_BROADCAST,
            DomTerminalKindV1::Refund => STAGE_REFUND_BROADCAST,
            DomTerminalKindV1::Funding => STAGE_FUNDING_BROADCAST,
        };
        let final_stage = match record.kind {
            DomTerminalKindV1::Claim => STAGE_CLAIM_FINAL,
            DomTerminalKindV1::Refund => STAGE_REFUND_FINAL,
            DomTerminalKindV1::Funding => STAGE_FUNDING_CONFIRMED,
        };
        let stage = load_stage(&transaction, binding.session_id())?;
        let checkpoint_digest = finality_checkpoint_digest(record.checkpoint_bytes);
        let row_digest = terminal_finality_record_digest(
            binding,
            TerminalFinalityDigestMaterialV1 {
                kind: record.kind,
                tx_hash: record.tx_hash,
                block_height: record.block_height,
                block_hash: record.block_hash,
                tip_height: record.tip_height,
                tip_hash: record.tip_hash,
                confirmation_depth: record.confirmation_depth,
                minimum_confirmations: record.minimum_confirmations,
                max_reorg_depth: record.max_reorg_depth,
                evidence_digest: record.evidence_digest,
                checkpoint_digest,
                reorg_evidence_digest: None,
                active: true,
                fencing_epoch: lease.fencing_epoch,
            },
        );
        if let Some(existing) = load_terminal_finality(&transaction, binding, record.kind)? {
            let exact = existing.tx_hash == record.tx_hash
                && existing.block_height == record.block_height
                && existing.block_hash == record.block_hash
                && existing.tip_height == record.tip_height
                && existing.tip_hash == record.tip_hash
                && existing.confirmation_depth == record.confirmation_depth
                && existing.minimum_confirmations == record.minimum_confirmations
                && existing.max_reorg_depth == record.max_reorg_depth
                && existing.evidence_digest == record.evidence_digest
                && existing.checkpoint_digest == checkpoint_digest
                && existing.checkpoint_bytes == record.checkpoint_bytes;
            if existing.active {
                let replay_stage_is_valid = stage == final_stage
                    || (record.kind == DomTerminalKindV1::Funding
                        && matches!(
                            stage,
                            STAGE_CLAIM_BROADCAST
                                | STAGE_REFUND_BROADCAST
                                | STAGE_CLAIM_FINAL
                                | STAGE_REFUND_FINAL
                        ));
                if exact && replay_stage_is_valid {
                    transaction.commit().map_err(storage)?;
                    return Ok(DomOperationDispositionV1::Idempotent);
                }
                return Err(DomActuatorError::IdempotencyConflict);
            }
            if existing.tx_hash != record.tx_hash {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            if !matches!(stage, STAGE_REORG_RECOVERY) && stage != expected_stage {
                return Err(DomActuatorError::InvalidStage);
            }
            let changed = transaction
                .execute(
                    "UPDATE dom_terminal_finality SET tx_hash=?3,block_height=?4,
                     block_hash=?5,tip_height=?6,tip_hash=?7,confirmation_depth=?8,
                     minimum_confirmations=?9,max_reorg_depth=?10,evidence_digest=?11,
                     checkpoint_bytes=?12,checkpoint_digest=?13,record_digest=?14,
                     active=1,reorg_evidence_digest=NULL,fencing_epoch=?15,
                     updated_at_unix_ms=?16
                     WHERE session_id=?1 AND kind_tag=?2 AND active=0",
                    params![
                        binding.session_id().as_slice(),
                        record.kind as u8,
                        record.tx_hash.as_slice(),
                        to_sql(record.block_height)?,
                        record.block_hash.as_slice(),
                        to_sql(record.tip_height)?,
                        record.tip_hash.as_slice(),
                        i64::from(record.confirmation_depth),
                        i64::from(record.minimum_confirmations),
                        i64::from(record.max_reorg_depth),
                        record.evidence_digest.as_slice(),
                        record.checkpoint_bytes,
                        checkpoint_digest.as_slice(),
                        row_digest.as_slice(),
                        to_sql(lease.fencing_epoch)?,
                        to_sql(now_unix_ms)?,
                    ],
                )
                .map_err(storage)?;
            if changed != 1 {
                return Err(DomActuatorError::RevisionConflict);
            }
        } else {
            if !matches!(stage, STAGE_REORG_RECOVERY) && stage != expected_stage {
                return Err(DomActuatorError::InvalidStage);
            }
            transaction
                .execute(
                    "INSERT INTO dom_terminal_finality
                     (session_id,kind_tag,tx_hash,block_height,block_hash,tip_height,
                      tip_hash,confirmation_depth,minimum_confirmations,max_reorg_depth,
                      evidence_digest,checkpoint_bytes,checkpoint_digest,record_digest,
                      active,reorg_evidence_digest,fencing_epoch,created_at_unix_ms,
                      updated_at_unix_ms)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,
                             1,NULL,?15,?16,?16)",
                    params![
                        binding.session_id().as_slice(),
                        record.kind as u8,
                        record.tx_hash.as_slice(),
                        to_sql(record.block_height)?,
                        record.block_hash.as_slice(),
                        to_sql(record.tip_height)?,
                        record.tip_hash.as_slice(),
                        i64::from(record.confirmation_depth),
                        i64::from(record.minimum_confirmations),
                        i64::from(record.max_reorg_depth),
                        record.evidence_digest.as_slice(),
                        record.checkpoint_bytes,
                        checkpoint_digest.as_slice(),
                        row_digest.as_slice(),
                        to_sql(lease.fencing_epoch)?,
                        to_sql(now_unix_ms)?,
                    ],
                )
                .map_err(storage)?;
        }
        let event_id = hash_parts(&[
            b"DOM:actuator-terminal-finality-event:v1",
            &binding.session_id(),
            &[record.kind as u8],
            &record.evidence_digest,
        ]);
        let event_digest = hash_parts(&[
            b"DOM:actuator-observation:v1",
            &binding.route_id(),
            &binding.session_id(),
            &event_id,
            &[record.kind.finality_observation_tag()],
            &record.evidence_digest,
        ]);
        append_event(
            &transaction,
            binding.session_id(),
            event_id,
            event_digest,
            final_stage,
            lease.fencing_epoch,
            now_unix_ms,
        )?;
        transaction.commit().map_err(storage)?;
        Ok(DomOperationDispositionV1::Prepared)
    }

    pub(crate) fn retained_terminal_checkpoint(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        kind: DomTerminalKindV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<RetainedDomTerminalCheckpointV1> {
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        let expected_stage = match kind {
            DomTerminalKindV1::Claim => STAGE_CLAIM_FINAL,
            DomTerminalKindV1::Refund => STAGE_REFUND_FINAL,
            DomTerminalKindV1::Funding => STAGE_FUNDING_CONFIRMED,
        };
        let stage = load_stage(&transaction, binding.session_id())?;
        let stage_is_valid = stage == expected_stage
            || (kind == DomTerminalKindV1::Funding
                && matches!(
                    stage,
                    STAGE_CLAIM_BROADCAST
                        | STAGE_REFUND_BROADCAST
                        | STAGE_CLAIM_FINAL
                        | STAGE_REFUND_FINAL
                ));
        if !stage_is_valid {
            return Err(DomActuatorError::InvalidStage);
        }
        let retained = load_terminal_finality(&transaction, binding, kind)?
            .filter(|record| record.active)
            .ok_or(DomActuatorError::ReorgEvidenceRequired)?;
        transaction.commit().map_err(storage)?;
        Ok(RetainedDomTerminalCheckpointV1 {
            kind,
            tx_hash: retained.tx_hash,
            block_height: retained.block_height,
            block_hash: retained.block_hash,
            minimum_confirmations: retained.minimum_confirmations,
            max_reorg_depth: retained.max_reorg_depth,
            evidence_digest: retained.evidence_digest,
            checkpoint_bytes: retained.checkpoint_bytes,
        })
    }

    /// Reload an already-committed terminal invalidation after a process crash.
    ///
    /// The inactive finality row retains both the original block facts and the
    /// exact reorg evidence digest. This is the recovery half of the child-port
    /// journal boundary: a crash after recording the fork but before committing
    /// the coordinator outcome cannot erase or synthesize either digest.
    pub(crate) fn retained_terminal_invalidation(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        kind: DomTerminalKindV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<Option<RetainedDomTerminalInvalidationV1>> {
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        let Some(retained) = load_terminal_finality(&transaction, binding, kind)? else {
            transaction.commit().map_err(storage)?;
            return Ok(None);
        };
        if retained.active {
            transaction.commit().map_err(storage)?;
            return Ok(None);
        }
        if load_stage(&transaction, binding.session_id())? != STAGE_REORG_RECOVERY {
            return Err(DomActuatorError::UnsupportedFormat);
        }
        let reorg_evidence_digest = retained
            .reorg_evidence_digest
            .ok_or(DomActuatorError::UnsupportedFormat)?;
        let invalidation = RetainedDomTerminalInvalidationV1 {
            kind: retained.kind,
            tx_hash: retained.tx_hash,
            block_height: retained.block_height,
            block_hash: retained.block_hash,
            prior_evidence_digest: retained.evidence_digest,
            reorg_evidence_digest,
        };
        transaction.commit().map_err(storage)?;
        Ok(Some(invalidation))
    }

    pub(crate) fn record_terminal_reorg(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        record: DomTerminalReorgRecordV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        validate_terminal_reorg_record(binding, &record)?;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        if record.kind == DomTerminalKindV1::Claim {
            require_exposed_claim_identity(&transaction, binding, record.tx_hash)?;
        }
        let expected_stage = match record.kind {
            DomTerminalKindV1::Claim => STAGE_CLAIM_FINAL,
            DomTerminalKindV1::Refund => STAGE_REFUND_FINAL,
            DomTerminalKindV1::Funding => STAGE_FUNDING_CONFIRMED,
        };
        let stage = load_stage(&transaction, binding.session_id())?;
        let event_id = hash_parts(&[
            b"DOM:actuator-terminal-reorg-event:v1",
            &binding.session_id(),
            &[record.kind as u8],
            &record.evidence_digest,
        ]);
        let event_digest = hash_parts(&[
            b"DOM:actuator-observation:v1",
            &binding.route_id(),
            &binding.session_id(),
            &event_id,
            &[record.kind.reorg_observation_tag()],
            &record.evidence_digest,
        ]);
        if event_already_applied(&transaction, binding.session_id(), event_id, event_digest)? {
            transaction.commit().map_err(storage)?;
            return Ok(DomOperationDispositionV1::Idempotent);
        }
        let stage_is_valid = stage == expected_stage
            || (record.kind == DomTerminalKindV1::Funding
                && matches!(
                    stage,
                    STAGE_CLAIM_BROADCAST
                        | STAGE_REFUND_BROADCAST
                        | STAGE_CLAIM_FINAL
                        | STAGE_REFUND_FINAL
                ));
        if !stage_is_valid {
            return Err(DomActuatorError::InvalidStage);
        }
        let retained = load_terminal_finality(&transaction, binding, record.kind)?
            .filter(|value| value.active)
            .ok_or(DomActuatorError::ReorgEvidenceRequired)?;
        if retained.tx_hash != record.tx_hash
            || retained.evidence_digest != record.prior_evidence_digest
            || retained.minimum_confirmations != record.minimum_confirmations
            || retained.max_reorg_depth != record.max_reorg_depth
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let inactive_digest = terminal_finality_record_digest(
            binding,
            TerminalFinalityDigestMaterialV1 {
                kind: retained.kind,
                tx_hash: retained.tx_hash,
                block_height: retained.block_height,
                block_hash: retained.block_hash,
                tip_height: retained.tip_height,
                tip_hash: retained.tip_hash,
                confirmation_depth: retained.confirmation_depth,
                minimum_confirmations: retained.minimum_confirmations,
                max_reorg_depth: retained.max_reorg_depth,
                evidence_digest: retained.evidence_digest,
                checkpoint_digest: retained.checkpoint_digest,
                reorg_evidence_digest: Some(record.evidence_digest),
                active: false,
                fencing_epoch: lease.fencing_epoch,
            },
        );
        let changed = transaction
            .execute(
                "UPDATE dom_terminal_finality SET active=0,reorg_evidence_digest=?3,
                 fencing_epoch=?4,record_digest=?5,updated_at_unix_ms=?6
                 WHERE session_id=?1 AND kind_tag=?2 AND active=1 AND record_digest=?7",
                params![
                    binding.session_id().as_slice(),
                    record.kind as u8,
                    record.evidence_digest.as_slice(),
                    to_sql(lease.fencing_epoch)?,
                    inactive_digest.as_slice(),
                    to_sql(now_unix_ms)?,
                    retained.record_digest.as_slice(),
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(DomActuatorError::RevisionConflict);
        }
        append_event(
            &transaction,
            binding.session_id(),
            event_id,
            event_digest,
            STAGE_REORG_RECOVERY,
            lease.fencing_epoch,
            now_unix_ms,
        )?;
        transaction.commit().map_err(storage)?;
        Ok(DomOperationDispositionV1::Prepared)
    }

    pub(crate) fn prepare_output_reservation(
        &mut self,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        reservation_digest: Digest32,
        outputs: &[(Vec<u8>, u64)],
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        validate_digest(reservation_digest)?;
        if outputs.is_empty() || outputs.len() > 4096 {
            return Err(DomActuatorError::InvalidBinding);
        }
        let total = outputs.iter().try_fold(0_u64, |sum, (commitment, value)| {
            if commitment.len() != 33 || *value == 0 {
                return Err(DomActuatorError::InvalidBinding);
            }
            sum.checked_add(*value)
                .ok_or(DomActuatorError::InvalidBinding)
        })?;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        validate_capability(&transaction, lease, capability)?;
        if capability.scope().action() != DomActionV1::ReserveOutputs {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        if let Some((stored_digest, stored_total, stored_count, status)) = transaction
            .query_row(
                "SELECT reservation_digest,total_value,output_count,status_tag
                 FROM dom_output_reservations WHERE effect_id=?1",
                params![capability.scope().effect_id().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?
        {
            if blob32(stored_digest)? != reservation_digest
                || from_sql(stored_total)? != total
                || usize::try_from(stored_count).ok() != Some(outputs.len())
            {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            let stored_items = load_reservation_items(&transaction, reservation_digest)?;
            if stored_items != outputs {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            transaction.commit().map_err(storage)?;
            return Ok(if status == RESERVATION_ACTIVE {
                DomOperationDispositionV1::AlreadyCompleted
            } else {
                DomOperationDispositionV1::Idempotent
            });
        }
        transaction
            .execute(
                "INSERT INTO dom_output_reservations
                 (reservation_digest,effect_id,route_id,session_id,total_value,
                  output_count,status_tag,created_at_unix_ms,updated_at_unix_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,0,?7,?7)",
                params![
                    reservation_digest.as_slice(),
                    capability.scope().effect_id().as_slice(),
                    capability.scope().binding().route_id().as_slice(),
                    capability.scope().binding().session_id().as_slice(),
                    to_sql(total)?,
                    i64::try_from(outputs.len()).map_err(|_| DomActuatorError::InvalidBinding)?,
                    to_sql(now_unix_ms)?
                ],
            )
            .map_err(storage)?;
        for (commitment, value) in outputs {
            let inserted = transaction.execute(
                "INSERT INTO dom_output_reservation_items
                 (reservation_digest,commitment,value,active) VALUES (?1,?2,?3,1)",
                params![reservation_digest.as_slice(), commitment, to_sql(*value)?],
            );
            if inserted.is_err() {
                return Err(DomActuatorError::OutputReservationConflict);
            }
        }
        transaction.commit().map_err(storage)?;
        Ok(DomOperationDispositionV1::Prepared)
    }

    pub(crate) fn activate_output_reservation(
        &mut self,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        reservation_digest: Digest32,
        wallet_receipt_digest: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        validate_digest(wallet_receipt_digest)?;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        validate_capability(&transaction, lease, &capability)?;
        let row: (Vec<u8>, i64) = transaction
            .query_row(
                "SELECT reservation_digest,status_tag FROM dom_output_reservations
                 WHERE effect_id=?1",
                params![capability.scope().effect_id().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage)?;
        if blob32(row.0)? != reservation_digest {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        if row.1 == RESERVATION_ACTIVE {
            transaction.commit().map_err(storage)?;
            return Ok(DomOperationDispositionV1::AlreadyCompleted);
        }
        if row.1 != RESERVATION_PREPARED {
            return Err(DomActuatorError::InvalidStage);
        }
        transaction
            .execute(
                "UPDATE dom_output_reservations SET status_tag=1,
                 updated_at_unix_ms=?2 WHERE reservation_digest=?1 AND status_tag=0",
                params![reservation_digest.as_slice(), to_sql(now_unix_ms)?],
            )
            .map_err(storage)?;
        complete_operation_and_advance(
            &transaction,
            lease,
            capability.scope(),
            wallet_receipt_digest,
            now_unix_ms,
        )?;
        transaction.commit().map_err(storage)?;
        Ok(DomOperationDispositionV1::Prepared)
    }

    pub(crate) fn reservation_for_effect(
        &self,
        effect_id: Digest32,
    ) -> DomActuatorResult<Option<RetainedOutputReservationV1>> {
        let transaction = self.deferred()?;
        let row = transaction
            .query_row(
                "SELECT reservation_digest,route_id,session_id,status_tag
                 FROM dom_output_reservations
                 WHERE effect_id=?1",
                params![effect_id.as_slice()],
                RawOutputReservationByEffectRowV1::from_row,
            )
            .optional()
            .map_err(storage)?;
        let Some(row) = row else {
            transaction.commit().map_err(storage)?;
            return Ok(None);
        };
        let reservation_digest = blob32(row.reservation_digest)?;
        let mut statement = transaction
            .prepare(
                "SELECT commitment,value FROM dom_output_reservation_items
                 WHERE reservation_digest=?1 ORDER BY commitment ASC",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map(params![reservation_digest.as_slice()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(storage)?;
        let mut outputs = Vec::new();
        for row in rows {
            let (commitment, value) = row.map_err(storage)?;
            outputs.push((blob33(commitment)?, from_sql(value)?));
        }
        drop(statement);
        transaction.commit().map_err(storage)?;
        Ok(Some(RetainedOutputReservationV1 {
            reservation_digest,
            route_id: blob32(row.route_id)?,
            session_id: blob32(row.session_id)?,
            outputs,
            status: row.status,
        }))
    }

    pub(crate) fn reservation_by_digest(
        &self,
        reservation_digest: Digest32,
    ) -> DomActuatorResult<Option<RetainedOutputReservationV1>> {
        let transaction = self.deferred()?;
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = transaction
            .query_row(
                "SELECT route_id,session_id,status_tag FROM dom_output_reservations
                 WHERE reservation_digest=?1",
                params![reservation_digest.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage)?;
        let Some((route, session, status)) = row else {
            transaction.commit().map_err(storage)?;
            return Ok(None);
        };
        let mut statement = transaction
            .prepare(
                "SELECT commitment,value FROM dom_output_reservation_items
                 WHERE reservation_digest=?1 ORDER BY commitment ASC",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map(params![reservation_digest.as_slice()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(storage)?;
        let mut outputs = Vec::new();
        for row in rows {
            let (commitment, value) = row.map_err(storage)?;
            outputs.push((blob33(commitment)?, from_sql(value)?));
        }
        drop(statement);
        transaction.commit().map_err(storage)?;
        Ok(Some(RetainedOutputReservationV1 {
            reservation_digest,
            route_id: blob32(route)?,
            session_id: blob32(session)?,
            outputs,
            status,
        }))
    }

    pub(crate) fn validate_live_capability(
        &mut self,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<()> {
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        validate_capability(&transaction, lease, capability)?;
        let operation = load_operation(&transaction, capability.scope().effect_id())?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if operation.status != OP_PREPARED {
            return Err(DomActuatorError::InvalidStage);
        }
        transaction.commit().map_err(storage)
    }

    pub(crate) fn validate_retained_capability(
        &mut self,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<()> {
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        validate_capability(&transaction, lease, capability)?;
        let operation = load_operation(&transaction, capability.scope().effect_id())?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if operation.status != OP_PREPARED && operation.status != OP_COMPLETED {
            return Err(DomActuatorError::InvalidStage);
        }
        transaction.commit().map_err(storage)
    }

    pub(crate) fn claim_persistence_sink(
        &mut self,
        request: ClaimPersistenceSinkRequestV1,
    ) -> DomActuatorResult<DomClaimPersistenceSinkV1<'_>> {
        let ClaimPersistenceSinkRequestV1 {
            lease,
            capability,
            expected_template_hash,
            expected_shared_output_commitment,
            expected_claim_authority_evidence_digest,
            validation_height,
            now_unix_ms,
        } = request;
        validate_digest(expected_template_hash)?;
        validate_digest(expected_claim_authority_evidence_digest)?;
        if expected_shared_output_commitment == [0; 33]
            || capability.scope().action() != DomActionV1::BroadcastClaim
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        self.validate_live_capability(lease, &capability, now_unix_ms)?;
        Ok(DomClaimPersistenceSinkV1 {
            store: self,
            lease,
            capability: Some(capability),
            expected_template_hash,
            expected_shared_output_commitment,
            expected_claim_authority_evidence_digest,
            validation_height,
            now_unix_ms,
        })
    }

    /// Reauthenticate and classify one exact retained legacy V1 claim.
    ///
    /// This is a read-only authority boundary. It verifies the live participant
    /// lease, the complete session binding, canonical custody bytes and every
    /// retained admission commitment before returning public audit facts.
    pub fn audit_retained_claim_custody_v1(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomClaimCustodyAuditV1> {
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        let audit = load_claim_custody_audit(&transaction, binding)?;
        transaction.commit().map_err(storage)?;
        Ok(audit)
    }

    pub(crate) fn resume_claim_broadcast(
        &mut self,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomClaimBroadcastV1> {
        if capability.scope().action() != DomActionV1::BroadcastClaim {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        validate_capability(&transaction, lease, capability)?;
        let operation = load_operation(&transaction, capability.scope().effect_id())?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        let claim = load_claim_custody(&transaction, capability.scope().binding().session_id())?
            .ok_or(DomActuatorError::ReconciliationRequired)?;
        validate_claim_scope(&claim, capability)?;
        if operation.status != OP_COMPLETED
            || operation.receipt_digest != Some(claim.tx_hash)
            || claim.fencing_epoch != lease.fencing_epoch
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let admission = load_claim_admission(&transaction, claim.session_id)?
            .ok_or(DomActuatorError::InvalidStage)?;
        validate_claim_admission_scope(&admission, &claim)?;
        let broadcast = claim.into_broadcast();
        transaction.commit().map_err(storage)?;
        Ok(broadcast)
    }

    pub(crate) fn prepare_claim_dispatch(
        &mut self,
        lease: DomLeaseV1,
        broadcast: &DomClaimBroadcastV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomClaimAdmissionV1> {
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let claim = load_claim_custody(&transaction, broadcast.session_id)?
            .ok_or(DomActuatorError::ReconciliationRequired)?;
        if claim.effect_id != broadcast.effect_id
            || claim.fencing_epoch != lease.fencing_epoch
            || broadcast.fencing_epoch != lease.fencing_epoch
            || claim.tx_hash != broadcast.tx_hash
            || claim.exact_bytes != broadcast.exact_bytes
        {
            return Err(DomActuatorError::StaleFence);
        }
        let admission = load_claim_admission(&transaction, broadcast.session_id)?
            .ok_or(DomActuatorError::InvalidStage)?;
        validate_claim_admission_scope(&admission, &claim)?;
        let admitted = admission.into_capability();
        transaction.commit().map_err(storage)?;
        Ok(admitted)
    }

    #[cfg(test)]
    fn prepare_historical_claim_admission_for_test(
        &mut self,
        lease: DomLeaseV1,
        broadcast: &DomClaimBroadcastV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<PendingClaimAdmissionV1> {
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let claim = load_claim_custody(&transaction, broadcast.session_id)?
            .ok_or(DomActuatorError::ReconciliationRequired)?;
        if claim.effect_id != broadcast.effect_id
            || claim.fencing_epoch != lease.fencing_epoch
            || broadcast.fencing_epoch != lease.fencing_epoch
            || claim.tx_hash != broadcast.tx_hash
            || claim.exact_bytes != broadcast.exact_bytes
        {
            return Err(DomActuatorError::StaleFence);
        }
        if load_claim_admission(&transaction, broadcast.session_id)?.is_some() {
            return Err(DomActuatorError::InvalidStage);
        }
        let next_count = claim
            .send_attempt_count
            .checked_add(1)
            .ok_or(DomActuatorError::UnsupportedFormat)?;
        let next_record_digest = claim_custody_record_digest(
            ScopedDomActionV1::new(
                load_binding(&transaction, claim.session_id)?
                    .ok_or(DomActuatorError::UnsupportedFormat)?,
                claim.effect_id,
                DomActionV1::BroadcastClaim,
            )?,
            claim.fencing_epoch,
            claim.authorization_digest,
            claim.tx_hash,
            claim.template_hash,
            claim.shared_output_commitment,
            ClaimSendStateV1 {
                attempted: true,
                attempt_count: next_count,
            },
        );
        let changed = transaction
            .execute(
                "UPDATE dom_claim_custody SET send_attempted=1,send_attempt_count=?2,
                 record_digest=?3,updated_at_unix_ms=?4 WHERE session_id=?1
                 AND fencing_epoch=?5 AND record_digest=?6",
                params![
                    broadcast.session_id.as_slice(),
                    to_sql(next_count)?,
                    next_record_digest.as_slice(),
                    to_sql(now_unix_ms)?,
                    to_sql(lease.fencing_epoch)?,
                    claim.record_digest.as_slice(),
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(DomActuatorError::RevisionConflict);
        }
        let pending = PendingClaimAdmissionV1 {
            session_id: claim.session_id,
            effect_id: claim.effect_id,
            route_id: claim.route_id,
            participant_id: claim.participant_id,
            fencing_epoch: claim.fencing_epoch,
            tx_hash: claim.tx_hash,
            claim_record_digest: next_record_digest,
        };
        transaction.commit().map_err(storage)?;
        Ok(pending)
    }

    #[cfg(test)]
    fn persist_claim_admission(
        &mut self,
        lease: DomLeaseV1,
        pending: PendingClaimAdmissionV1,
        receipt: ValidatedSubmissionReceiptFactsV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomClaimAdmissionV1> {
        let receipt_digest = receipt.receipt_digest_v1();
        if pending.fencing_epoch != lease.fencing_epoch
            || receipt.tx_hash() != pending.tx_hash
            || !receipt.is_economically_admitted()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        validate_submission_receipt_facts_v1(
            receipt.tx_hash(),
            receipt.state(),
            receipt.was_relayed(),
            receipt_digest,
        )
        .map_err(|_| DomActuatorError::CapabilityMismatch)?;

        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let claim = load_claim_custody(&transaction, pending.session_id)?
            .ok_or(DomActuatorError::ReconciliationRequired)?;
        if claim.session_id != pending.session_id
            || claim.effect_id != pending.effect_id
            || claim.route_id != pending.route_id
            || claim.participant_id != pending.participant_id
            || claim.fencing_epoch != pending.fencing_epoch
            || claim.tx_hash != pending.tx_hash
            || claim.record_digest != pending.claim_record_digest
            || !claim.send_attempted
            || claim.send_attempt_count == 0
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        if let Some(existing) = load_claim_admission(&transaction, pending.session_id)? {
            validate_claim_admission_scope(&existing, &claim)?;
            if existing.state != receipt.state()
                || existing.relayed != receipt.was_relayed()
                || existing.receipt_digest != receipt_digest
            {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            let admitted = existing.into_capability();
            transaction.commit().map_err(storage)?;
            return Ok(admitted);
        }
        let record_digest = claim_admission_record_digest(
            &claim,
            receipt.state(),
            receipt.was_relayed(),
            receipt_digest,
        );
        transaction
            .execute(
                "INSERT INTO dom_claim_admission
                 (session_id,effect_id,route_id,participant_id,fencing_epoch,
                  tx_hash,claim_record_digest,receipt_state_tag,receipt_relayed,
                  receipt_digest,record_digest,created_at_unix_ms,updated_at_unix_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?12)",
                params![
                    pending.session_id.as_slice(),
                    pending.effect_id.as_slice(),
                    pending.route_id.as_slice(),
                    pending.participant_id.as_slice(),
                    to_sql(pending.fencing_epoch)?,
                    pending.tx_hash.as_slice(),
                    pending.claim_record_digest.as_slice(),
                    i64::from(receipt.state().tag_v1()),
                    i64::from(u8::from(receipt.was_relayed())),
                    receipt_digest.as_slice(),
                    record_digest.as_slice(),
                    to_sql(now_unix_ms)?,
                ],
            )
            .map_err(storage)?;
        let admitted = DomClaimAdmissionV1 {
            session_id: pending.session_id,
            effect_id: pending.effect_id,
            original_fencing_epoch: pending.fencing_epoch,
            tx_hash: pending.tx_hash,
            state: receipt.state(),
            relayed: receipt.was_relayed(),
            receipt_digest,
            record_digest,
        };
        transaction.commit().map_err(storage)?;
        Ok(admitted)
    }

    pub(crate) fn resume_claim_admission(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomClaimAdmissionV1> {
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        let claim = load_claim_custody(&transaction, binding.session_id())?
            .ok_or(DomActuatorError::ReconciliationRequired)?;
        let admission = load_claim_admission(&transaction, binding.session_id())?
            .ok_or(DomActuatorError::ReconciliationRequired)?;
        validate_claim_admission_scope(&admission, &claim)?;
        if admission.route_id != binding.route_id()
            || admission.participant_id != binding.participant().participant_id()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let admitted = admission.into_capability();
        transaction.commit().map_err(storage)?;
        Ok(admitted)
    }

    pub(crate) fn retained_claim_identity(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<RetainedDomClaimIdentityV1> {
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        if !matches!(
            load_stage(&transaction, binding.session_id())?,
            STAGE_CLAIM_BROADCAST | STAGE_CLAIM_FINAL | STAGE_REORG_RECOVERY
        ) {
            return Err(DomActuatorError::InvalidStage);
        }
        let audit = load_claim_custody_audit(&transaction, binding)?;
        if audit.classification == DomClaimCustodyClassificationV1::Unattempted {
            return Err(DomActuatorError::InvalidStage);
        }
        transaction.commit().map_err(storage)?;
        Ok(RetainedDomClaimIdentityV1 {
            tx_hash: audit.tx_hash,
            template_hash: audit.template_hash,
            shared_output_commitment: audit.shared_output_commitment,
        })
    }

    /// Reauthenticate the durable V2 `FinalClaim` action binding without writes.
    ///
    /// This read-only pre-check runs before the DOM Contracts store is asked to
    /// persist the exposure record, so a capability that is not bound to this
    /// exact revalidated Contracts authority fails closed before any
    /// irreversible exposure marker can be written and long before any RPC.
    pub(crate) fn require_prepared_final_claim_authority_v2(
        &mut self,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        expected_evidence_digest: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<()> {
        validate_digest(expected_evidence_digest)?;
        if capability.scope().action() != DomActionV1::BroadcastClaim {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        validate_capability(&transaction, lease, capability)?;
        let operation = load_operation(&transaction, capability.scope().effect_id())?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if operation.evidence_digest != expected_evidence_digest {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        if operation.status != OP_PREPARED && operation.status != OP_COMPLETED {
            return Err(DomActuatorError::InvalidStage);
        }
        if load_final_claim_admission_v2(&transaction, capability.scope().binding().session_id())?
            .is_some()
        {
            return Err(DomActuatorError::InvalidStage);
        }
        transaction.commit().map_err(storage)
    }

    /// Re-fence one already-exposed V2 `FinalClaim` for the same retained
    /// process owner after its lease expired.
    ///
    /// The transaction bytes remain solely in the Contracts store. This
    /// boundary accepts only the public facts reauthenticated from that same
    /// retained submission authority and atomically advances both the
    /// completed operation and its owner mirror. A different owner can observe
    /// or reconcile the exposed transaction, but can never obtain replay
    /// authority.
    pub(crate) fn reauthorize_same_owner_final_claim_replay_v2(
        &mut self,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        previous_authorization_digest: Digest32,
        facts: &FinalClaimAttemptFactsV2,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomActuatorCapabilityV1> {
        if scope.action() != DomActionV1::BroadcastClaim {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        validate_digest(previous_authorization_digest)?;
        validate_digest(facts.authority_evidence_digest)?;
        validate_digest(facts.dom_claim_sender_id)?;
        validate_digest(facts.final_claim_receiver_id)?;
        validate_digest(facts.tx_hash)?;
        validate_digest(facts.template_hash)?;
        validate_digest(facts.exposure_record_digest)?;
        if facts.shared_output_commitment == [0; 33] {
            return Err(DomActuatorError::CapabilityMismatch);
        }

        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_scope(&transaction, lease, scope)?;
        let operation = load_operation(&transaction, scope.effect_id())?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        let attempt = load_final_claim_attempt_v2(&transaction, scope.binding().session_id())?
            .ok_or(DomActuatorError::ReconciliationRequired)?;
        validate_final_claim_attempt_operation_v2(&transaction, &attempt)?;
        if load_final_claim_admission_v2(&transaction, scope.binding().session_id())?.is_some() {
            return Err(DomActuatorError::InvalidStage);
        }
        if operation.status != OP_COMPLETED
            || operation.scope_digest != scope_digest(scope)
            || operation.evidence_digest != facts.authority_evidence_digest
            || operation.authorization_digest != previous_authorization_digest
            || operation.receipt_digest != Some(facts.exposure_record_digest)
            || attempt.effect_id != scope.effect_id()
            || attempt.route_id != scope.binding().route_id()
            || attempt.participant_id != scope.binding().participant().participant_id()
            || attempt.owner_id != lease.owner_id
            || attempt.fencing_epoch != operation.fencing_epoch
            || attempt.fencing_epoch >= lease.fencing_epoch
            || attempt.authorization_digest != previous_authorization_digest
            || attempt.dom_claim_sender_id != facts.dom_claim_sender_id
            || attempt.final_claim_receiver_id != facts.final_claim_receiver_id
            || attempt.tx_hash != facts.tx_hash
            || attempt.template_hash != facts.template_hash
            || attempt.shared_output_commitment != facts.shared_output_commitment
            || attempt.exposure_record_digest != facts.exposure_record_digest
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }

        let next_authorization_digest = authorization_digest(
            operation.scope_digest,
            operation.evidence_digest,
            operation.secret_binding_digest,
            lease.fencing_epoch,
        );
        let next_attempt_record_digest = final_claim_attempt_record_digest_v2(
            scope,
            attempt.owner_id,
            lease.fencing_epoch,
            next_authorization_digest,
            facts,
            attempt.send_attempt_count,
        );
        let reconciliation_digest = hash_parts(&[
            b"DOM:actuator-final-claim-same-owner-replay:v1",
            &scope.binding().route_id(),
            &scope.binding().session_id(),
            &scope.effect_id(),
            &attempt.owner_id,
            &attempt.fencing_epoch.to_be_bytes(),
            &lease.fencing_epoch.to_be_bytes(),
            &facts.tx_hash,
            &facts.exposure_record_digest,
        ]);
        let operation_changed = transaction
            .execute(
                "UPDATE dom_operations SET fencing_epoch=?2,authorization_digest=?3,
                 reconciliation_digest=?4,updated_at_unix_ms=?5
                 WHERE effect_id=?1 AND status_tag=1 AND fencing_epoch=?6
                 AND authorization_digest=?7 AND receipt_digest=?8",
                params![
                    scope.effect_id().as_slice(),
                    to_sql(lease.fencing_epoch)?,
                    next_authorization_digest.as_slice(),
                    reconciliation_digest.as_slice(),
                    to_sql(now_unix_ms)?,
                    to_sql(attempt.fencing_epoch)?,
                    previous_authorization_digest.as_slice(),
                    facts.exposure_record_digest.as_slice(),
                ],
            )
            .map_err(storage)?;
        if operation_changed != 1 {
            return Err(DomActuatorError::RevisionConflict);
        }
        let attempt_changed = transaction
            .execute(
                "UPDATE dom_final_claim_attempt_v2
                 SET fencing_epoch=?2,authorization_digest=?3,record_digest=?4,
                     updated_at_unix_ms=?5
                 WHERE session_id=?1 AND owner_id=?6 AND fencing_epoch=?7
                   AND authorization_digest=?8 AND record_digest=?9",
                params![
                    scope.binding().session_id().as_slice(),
                    to_sql(lease.fencing_epoch)?,
                    next_authorization_digest.as_slice(),
                    next_attempt_record_digest.as_slice(),
                    to_sql(now_unix_ms)?,
                    attempt.owner_id.as_slice(),
                    to_sql(attempt.fencing_epoch)?,
                    previous_authorization_digest.as_slice(),
                    attempt.record_digest.as_slice(),
                ],
            )
            .map_err(storage)?;
        if attempt_changed != 1 {
            return Err(DomActuatorError::RevisionConflict);
        }
        transaction.commit().map_err(storage)?;
        Ok(DomActuatorCapabilityV1::issue(
            scope,
            lease.fencing_epoch,
            next_authorization_digest,
            CapabilityIssuanceV1::Resumed,
        ))
    }

    /// Durably latch one pre-RPC V2 `FinalClaim` send attempt.
    ///
    /// This is the owner-only mirror of the Contracts exposure marker and it is
    /// committed strictly *before* the exact bytes may reach the node. The row
    /// carries no canonical bytes: the Contracts exposure record remains the
    /// sole custody. A first latch requires a live prepared `BroadcastClaim`
    /// operation and advances the session to `ClaimBroadcast`, which by itself
    /// removes every refund stage; a later latch is only the byte-identical
    /// retry of an ambiguous submission and must match every retained fact.
    /// Once economic admission is durable no further attempt can be latched.
    pub(crate) fn latch_final_claim_attempt_v2(
        &mut self,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        facts: &FinalClaimAttemptFactsV2,
        now_unix_ms: u64,
    ) -> DomActuatorResult<LatchedFinalClaimSubmissionV2> {
        let scope = capability.scope();
        if scope.action() != DomActionV1::BroadcastClaim {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        validate_digest(facts.authority_evidence_digest)?;
        validate_digest(facts.dom_claim_sender_id)?;
        validate_digest(facts.final_claim_receiver_id)?;
        validate_digest(facts.tx_hash)?;
        validate_digest(facts.template_hash)?;
        validate_digest(facts.exposure_record_digest)?;
        if facts.shared_output_commitment == [0; 33]
            || facts.dom_claim_sender_id != scope.binding().participant().participant_id()
            || facts.final_claim_receiver_id == facts.dom_claim_sender_id
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let session_id = scope.binding().session_id();
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        validate_capability(&transaction, lease, capability)?;
        if load_final_claim_admission_v2(&transaction, session_id)?.is_some() {
            return Err(DomActuatorError::InvalidStage);
        }
        let operation = load_operation(&transaction, scope.effect_id())?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if operation.evidence_digest != facts.authority_evidence_digest {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let latched_record_digest = match load_final_claim_attempt_v2(&transaction, session_id)? {
            None => {
                if operation.status != OP_PREPARED {
                    return Err(DomActuatorError::InvalidStage);
                }
                if load_claim_custody(&transaction, session_id)?.is_some() {
                    return Err(DomActuatorError::IdempotencyConflict);
                }
                require_action_stage(
                    load_stage(&transaction, session_id)?,
                    DomActionV1::BroadcastClaim,
                )?;
                let record_digest = final_claim_attempt_record_digest_v2(
                    scope,
                    lease.owner_id,
                    lease.fencing_epoch,
                    capability.authorization_digest(),
                    facts,
                    1,
                );
                transaction
                    .execute(
                        "INSERT INTO dom_final_claim_attempt_v2
                         (session_id,effect_id,route_id,participant_id,owner_id,fencing_epoch,
                          authorization_digest,dom_claim_sender_id,final_claim_receiver_id,
                          tx_hash,template_hash,shared_output_commitment,
                          exposure_record_digest,record_digest,send_attempt_count,
                          created_at_unix_ms,updated_at_unix_ms)
                         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,1,?15,?15)",
                        params![
                            session_id.as_slice(),
                            scope.effect_id().as_slice(),
                            scope.binding().route_id().as_slice(),
                            scope.binding().participant().participant_id().as_slice(),
                            lease.owner_id.as_slice(),
                            to_sql(lease.fencing_epoch)?,
                            capability.authorization_digest().as_slice(),
                            facts.dom_claim_sender_id.as_slice(),
                            facts.final_claim_receiver_id.as_slice(),
                            facts.tx_hash.as_slice(),
                            facts.template_hash.as_slice(),
                            facts.shared_output_commitment.as_slice(),
                            facts.exposure_record_digest.as_slice(),
                            record_digest.as_slice(),
                            to_sql(now_unix_ms)?,
                        ],
                    )
                    .map_err(storage)?;
                complete_operation_and_advance(
                    &transaction,
                    lease,
                    scope,
                    facts.exposure_record_digest,
                    now_unix_ms,
                )?;
                record_digest
            }
            Some(existing) => {
                if operation.status != OP_COMPLETED
                    || operation.receipt_digest != Some(existing.exposure_record_digest)
                    || existing.effect_id != scope.effect_id()
                    || existing.route_id != scope.binding().route_id()
                    || existing.participant_id != scope.binding().participant().participant_id()
                    || existing.owner_id != lease.owner_id
                    || existing.fencing_epoch != lease.fencing_epoch
                    || existing.authorization_digest != capability.authorization_digest()
                    || existing.dom_claim_sender_id != facts.dom_claim_sender_id
                    || existing.final_claim_receiver_id != facts.final_claim_receiver_id
                    || existing.tx_hash != facts.tx_hash
                    || existing.template_hash != facts.template_hash
                    || existing.shared_output_commitment != facts.shared_output_commitment
                    || existing.exposure_record_digest != facts.exposure_record_digest
                {
                    return Err(DomActuatorError::CapabilityMismatch);
                }
                let next_count = existing
                    .send_attempt_count
                    .checked_add(1)
                    .ok_or(DomActuatorError::UnsupportedFormat)?;
                let next_record_digest = final_claim_attempt_record_digest_v2(
                    scope,
                    existing.owner_id,
                    lease.fencing_epoch,
                    capability.authorization_digest(),
                    facts,
                    next_count,
                );
                let changed = transaction
                    .execute(
                        "UPDATE dom_final_claim_attempt_v2
                         SET send_attempt_count=?2,record_digest=?3,updated_at_unix_ms=?4
                         WHERE session_id=?1 AND fencing_epoch=?5 AND record_digest=?6",
                        params![
                            session_id.as_slice(),
                            to_sql(next_count)?,
                            next_record_digest.as_slice(),
                            to_sql(now_unix_ms)?,
                            to_sql(lease.fencing_epoch)?,
                            existing.record_digest.as_slice(),
                        ],
                    )
                    .map_err(storage)?;
                if changed != 1 {
                    return Err(DomActuatorError::RevisionConflict);
                }
                next_record_digest
            }
        };
        transaction.commit().map_err(storage)?;
        Ok(LatchedFinalClaimSubmissionV2 {
            session_id,
            tx_hash: facts.tx_hash,
            attempt_record_digest: latched_record_digest,
        })
    }

    /// Mirror one validated V2 `FinalClaim` economic admission.
    ///
    /// The Contracts admission record is always committed first; this call only
    /// completes the owner-only mirror. Both the role facts and the receipt are
    /// non-forgeable: the former are read out of the linear Contracts transport
    /// authority by the crate-local façade, the latter can only be produced by
    /// the validated DOM submission boundary. No admission is ever manufactured
    /// from reconstructed facts.
    pub(crate) fn persist_final_claim_admission_receipt_v2(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        authority: &FinalClaimTransportAuthorityFactsV2,
        receipt: SubmissionReceiptV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalClaimAdmissionV2> {
        let receipt = ValidatedSubmissionReceiptFactsV1::from_receipt(receipt)?;
        self.persist_final_claim_admission_v2(lease, binding, authority, receipt, now_unix_ms)
    }

    fn persist_final_claim_admission_v2(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        authority: &FinalClaimTransportAuthorityFactsV2,
        receipt: ValidatedSubmissionReceiptFactsV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalClaimAdmissionV2> {
        let receipt_digest = receipt.receipt_digest_v1();
        if !receipt.is_economically_admitted() || authority.session_id != binding.session_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        validate_submission_receipt_facts_v1(
            receipt.tx_hash(),
            receipt.state(),
            receipt.was_relayed(),
            receipt_digest,
        )
        .map_err(|_| DomActuatorError::CapabilityMismatch)?;

        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        let attempt = load_final_claim_attempt_v2(&transaction, binding.session_id())?
            .ok_or(DomActuatorError::ReconciliationRequired)?;
        validate_final_claim_attempt_operation_v2(&transaction, &attempt)?;
        if attempt.route_id != binding.route_id()
            || attempt.participant_id != binding.participant().participant_id()
            || attempt.fencing_epoch != lease.fencing_epoch
            || attempt.dom_claim_sender_id != authority.dom_claim_sender_id
            || attempt.final_claim_receiver_id != authority.final_claim_receiver_id
            || attempt.tx_hash != receipt.tx_hash()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        if let Some(existing) = load_final_claim_admission_v2(&transaction, binding.session_id())? {
            validate_final_claim_admission_scope_v2(&existing, &attempt)?;
            if existing.state != receipt.state()
                || existing.relayed != receipt.was_relayed()
                || existing.receipt_digest != receipt_digest
            {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            let admitted = existing.into_capability();
            transaction.commit().map_err(storage)?;
            return Ok(admitted);
        }
        let record_digest = final_claim_admission_record_digest_v2(
            &attempt,
            receipt.state(),
            receipt.was_relayed(),
            receipt_digest,
        );
        transaction
            .execute(
                "INSERT INTO dom_final_claim_admission_v2
                 (session_id,effect_id,route_id,participant_id,fencing_epoch,
                  dom_claim_sender_id,final_claim_receiver_id,tx_hash,
                  exposure_record_digest,attempt_record_digest,receipt_state_tag,
                  receipt_relayed,receipt_digest,record_digest,
                  created_at_unix_ms,updated_at_unix_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?15)",
                params![
                    attempt.session_id.as_slice(),
                    attempt.effect_id.as_slice(),
                    attempt.route_id.as_slice(),
                    attempt.participant_id.as_slice(),
                    to_sql(attempt.fencing_epoch)?,
                    attempt.dom_claim_sender_id.as_slice(),
                    attempt.final_claim_receiver_id.as_slice(),
                    attempt.tx_hash.as_slice(),
                    attempt.exposure_record_digest.as_slice(),
                    attempt.record_digest.as_slice(),
                    i64::from(receipt.state().tag_v1()),
                    i64::from(u8::from(receipt.was_relayed())),
                    receipt_digest.as_slice(),
                    record_digest.as_slice(),
                    to_sql(now_unix_ms)?,
                ],
            )
            .map_err(storage)?;
        let admitted = DomFinalClaimAdmissionV2 {
            session_id: attempt.session_id,
            effect_id: attempt.effect_id,
            original_fencing_epoch: attempt.fencing_epoch,
            dom_claim_sender_id: attempt.dom_claim_sender_id,
            final_claim_receiver_id: attempt.final_claim_receiver_id,
            tx_hash: attempt.tx_hash,
            exposure_record_digest: attempt.exposure_record_digest,
            state: receipt.state(),
            relayed: receipt.was_relayed(),
            receipt_digest,
            record_digest,
        };
        transaction.commit().map_err(storage)?;
        Ok(admitted)
    }

    /// Reissue the exact V2 admission mirror after restart, without any RPC.
    pub(crate) fn resume_final_claim_admission_v2(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalClaimAdmissionV2> {
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        let attempt = load_final_claim_attempt_v2(&transaction, binding.session_id())?
            .ok_or(DomActuatorError::ReconciliationRequired)?;
        validate_final_claim_attempt_operation_v2(&transaction, &attempt)?;
        let admission = load_final_claim_admission_v2(&transaction, binding.session_id())?
            .ok_or(DomActuatorError::ReconciliationRequired)?;
        validate_final_claim_admission_scope_v2(&admission, &attempt)?;
        if attempt.route_id != binding.route_id()
            || attempt.participant_id != binding.participant().participant_id()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let admitted = admission.into_capability();
        transaction.commit().map_err(storage)?;
        Ok(admitted)
    }

    /// Reauthenticate and classify the local V2 `FinalClaim` custody mirror.
    ///
    /// This is a read-only authority boundary and reports only the *local*
    /// disposition; the DOM Contracts store remains the exposure authority.
    pub fn audit_final_claim_custody_v2(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalClaimCustodyAuditV2> {
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        let audit = load_final_claim_custody_audit_v2(&transaction, binding)?;
        transaction.commit().map_err(storage)?;
        Ok(audit)
    }

    pub(crate) fn retained_final_claim_identity_v2(
        &mut self,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<RetainedDomClaimIdentityV1> {
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_binding(&transaction, lease, binding)?;
        if !matches!(
            load_stage(&transaction, binding.session_id())?,
            STAGE_CLAIM_BROADCAST | STAGE_CLAIM_FINAL | STAGE_REORG_RECOVERY
        ) {
            return Err(DomActuatorError::InvalidStage);
        }
        let audit = load_final_claim_custody_audit_v2(&transaction, binding)?;
        if audit.classification == DomClaimCustodyClassificationV1::Unattempted {
            return Err(DomActuatorError::InvalidStage);
        }
        transaction.commit().map_err(storage)?;
        Ok(RetainedDomClaimIdentityV1 {
            tx_hash: audit.tx_hash,
            template_hash: audit.template_hash,
            shared_output_commitment: audit.shared_output_commitment,
        })
    }

    pub(crate) fn release_output_reservation(
        &mut self,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        reservation_digest: Digest32,
        wallet_receipt_digest: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<()> {
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        validate_capability(&transaction, lease, &capability)?;
        if capability.scope().action() != DomActionV1::ReleaseOutputs {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let status: i64 = transaction
            .query_row(
                "SELECT status_tag FROM dom_output_reservations
                 WHERE reservation_digest=?1 AND session_id=?2",
                params![
                    reservation_digest.as_slice(),
                    capability.scope().binding().session_id().as_slice()
                ],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if status == RESERVATION_RELEASED {
            return Ok(());
        }
        transaction
            .execute(
                "UPDATE dom_output_reservation_items SET active=0
                 WHERE reservation_digest=?1",
                params![reservation_digest.as_slice()],
            )
            .map_err(storage)?;
        transaction
            .execute(
                "UPDATE dom_output_reservations SET status_tag=2,
                 updated_at_unix_ms=?2 WHERE reservation_digest=?1",
                params![reservation_digest.as_slice(), to_sql(now_unix_ms)?],
            )
            .map_err(storage)?;
        complete_operation_and_advance(
            &transaction,
            lease,
            capability.scope(),
            wallet_receipt_digest,
            now_unix_ms,
        )?;
        transaction.commit().map_err(storage)?;
        Ok(())
    }

    fn immediate(&mut self) -> DomActuatorResult<Transaction<'_>> {
        self.audit_file_authority()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        validate_database_path(&transaction, &self.path)?;
        validate_backend_and_schema(&transaction)?;
        if load_store_instance_id(&transaction)? != self.store_instance_id {
            return Err(DomActuatorError::InvalidStorageAuthority);
        }
        audit_retained_state_in_transaction(&transaction)?;
        Ok(transaction)
    }

    fn deferred(&self) -> DomActuatorResult<Transaction<'_>> {
        self.audit_file_authority()?;
        let transaction = self.connection.unchecked_transaction().map_err(storage)?;
        validate_database_path(&transaction, &self.path)?;
        validate_backend_and_schema(&transaction)?;
        if load_store_instance_id(&transaction)? != self.store_instance_id {
            return Err(DomActuatorError::InvalidStorageAuthority);
        }
        audit_retained_state_in_transaction(&transaction)?;
        Ok(transaction)
    }

    fn audit_storage_authority(&self) -> DomActuatorResult<()> {
        let transaction = self.deferred()?;
        transaction.commit().map_err(storage)
    }

    fn audit_file_authority(&self) -> DomActuatorResult<()> {
        let parent = self
            .path
            .parent()
            .ok_or(DomActuatorError::InvalidStorageAuthority)?;
        validate_owner_directory(parent)?;
        validate_open_file_identity(&self.database_authority, &self.path)?;
        let process_lock_path = lock_path(&self.path);
        validate_open_file_identity(&self._process_lock, &process_lock_path)?;
        if self
            ._process_lock
            .metadata()
            .map_err(|_| DomActuatorError::StorageUnavailable)?
            .len()
            != 0
        {
            return Err(DomActuatorError::InvalidStorageAuthority);
        }
        validate_resumable_sidecars(&self.path)
    }
}

impl OperationalClaimTransactionSinkV1 for DomClaimPersistenceSinkV1<'_> {
    type Error = DomActuatorError;
    type PersistedClaim = DomClaimBroadcastV1;

    fn persist_verified_claim(
        &mut self,
        claim: OperationalClaimPersistenceCapabilityV1,
    ) -> DomActuatorResult<Self::PersistedClaim> {
        let capability = self
            .capability
            .take()
            .ok_or(DomActuatorError::IdempotencyConflict)?;
        if capability.scope().action() != DomActionV1::BroadcastClaim
            || claim.template_hash() != &self.expected_template_hash
            || claim.shared_output_commitment() != &self.expected_shared_output_commitment
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        claim
            .verify(
                &capability.scope().binding().chain_id(),
                self.validation_height,
            )
            .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
        if claim.canonical_bytes().is_empty()
            || claim.canonical_bytes().len() > MAX_CANONICAL_TRANSACTION_BYTES_V1
        {
            return Err(DomActuatorError::InvalidBinding);
        }
        let exact_bytes = Zeroizing::new(claim.canonical_bytes().to_vec());
        let tx_hash = canonical_transaction_hash_v1(&exact_bytes)
            .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
        if &tx_hash != claim.tx_hash() {
            return Err(DomActuatorError::CryptoAuthorityUnavailable);
        }
        let scope = capability.scope();
        let authorization_digest = capability.authorization_digest();
        let record_digest = claim_custody_record_digest(
            scope,
            self.lease.fencing_epoch,
            authorization_digest,
            tx_hash,
            self.expected_template_hash,
            self.expected_shared_output_commitment,
            ClaimSendStateV1::UNSENT,
        );
        let transaction = self.store.immediate()?;
        validate_lease(&transaction, self.lease, self.now_unix_ms)?;
        validate_capability(&transaction, self.lease, &capability)?;
        let operation = load_operation(&transaction, scope.effect_id())?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if operation.status != OP_PREPARED
            || operation.evidence_digest != self.expected_claim_authority_evidence_digest
            || load_claim_custody(&transaction, scope.binding().session_id())?.is_some()
        {
            return Err(DomActuatorError::IdempotencyConflict);
        }
        require_action_stage(
            load_stage(&transaction, scope.binding().session_id())?,
            DomActionV1::BroadcastClaim,
        )?;
        transaction
            .execute(
                "INSERT INTO dom_claim_custody
                 (session_id,effect_id,route_id,participant_id,fencing_epoch,
                  authorization_digest,tx_hash,template_hash,shared_output_commitment,
                  exact_bytes,exact_bytes_digest,record_digest,send_attempted,
                  send_attempt_count,created_at_unix_ms,updated_at_unix_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?7,?11,0,0,?12,?12)",
                params![
                    scope.binding().session_id().as_slice(),
                    scope.effect_id().as_slice(),
                    scope.binding().route_id().as_slice(),
                    scope.binding().participant().participant_id().as_slice(),
                    to_sql(self.lease.fencing_epoch)?,
                    authorization_digest.as_slice(),
                    tx_hash.as_slice(),
                    self.expected_template_hash.as_slice(),
                    self.expected_shared_output_commitment.as_slice(),
                    exact_bytes.as_slice(),
                    record_digest.as_slice(),
                    to_sql(self.now_unix_ms)?,
                ],
            )
            .map_err(storage)?;
        complete_operation_and_advance(&transaction, self.lease, scope, tx_hash, self.now_unix_ms)?;
        transaction.commit().map_err(storage)?;
        Ok(DomClaimBroadcastV1 {
            session_id: scope.binding().session_id(),
            effect_id: scope.effect_id(),
            fencing_epoch: self.lease.fencing_epoch,
            tx_hash,
            exact_bytes,
        })
    }
}

fn storage(_: rusqlite::Error) -> DomActuatorError {
    DomActuatorError::StorageUnavailable
}

fn claim_custody_record_digest(
    scope: ScopedDomActionV1,
    fencing_epoch: u64,
    authorization_digest: Digest32,
    tx_hash: Digest32,
    template_hash: Digest32,
    shared_output_commitment: [u8; 33],
    send_state: ClaimSendStateV1,
) -> Digest32 {
    hash_parts(&[
        b"DOM:actuator-claim-custody:v1",
        &scope.binding().route_id(),
        &scope.binding().session_id(),
        &scope.binding().participant().participant_id(),
        &scope.effect_id(),
        &fencing_epoch.to_be_bytes(),
        &authorization_digest,
        &tx_hash,
        &template_hash,
        &shared_output_commitment,
        &[u8::from(send_state.attempted)],
        &send_state.attempt_count.to_be_bytes(),
    ])
}

fn load_claim_custody(
    transaction: &Transaction<'_>,
    session_id: Digest32,
) -> DomActuatorResult<Option<StoredClaimCustodyV1>> {
    let row = transaction
        .query_row(
            "SELECT effect_id,route_id,participant_id,fencing_epoch,
             authorization_digest,tx_hash,template_hash,shared_output_commitment,
             exact_bytes,exact_bytes_digest,record_digest,send_attempted,send_attempt_count
             FROM dom_claim_custody WHERE session_id=?1",
            params![session_id.as_slice()],
            RawClaimCustodyRowV1::from_row,
        )
        .optional()
        .map_err(storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let claim = StoredClaimCustodyV1 {
        session_id,
        effect_id: blob32(row.effect_id)?,
        route_id: blob32(row.route_id)?,
        participant_id: blob32(row.participant_id)?,
        fencing_epoch: from_sql(row.fencing_epoch)?,
        authorization_digest: blob32(row.authorization_digest)?,
        tx_hash: blob32(row.tx_hash)?,
        template_hash: blob32(row.template_hash)?,
        shared_output_commitment: blob33(row.shared_output_commitment)?,
        exact_bytes: Zeroizing::new(row.exact_bytes),
        exact_bytes_digest: blob32(row.exact_bytes_digest)?,
        record_digest: blob32(row.record_digest)?,
        send_attempted: match row.send_attempted {
            0 => false,
            1 => true,
            _ => return Err(DomActuatorError::UnsupportedFormat),
        },
        send_attempt_count: from_sql(row.send_attempt_count)?,
    };
    let canonical_hash = canonical_transaction_hash_v1(&claim.exact_bytes)
        .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    let scope = ScopedDomActionV1::new(
        load_binding(transaction, session_id)?.ok_or(DomActuatorError::UnsupportedFormat)?,
        claim.effect_id,
        DomActionV1::BroadcastClaim,
    )?;
    if canonical_hash != claim.tx_hash
        || claim.exact_bytes_digest != claim.tx_hash
        || claim.record_digest
            != claim_custody_record_digest(
                scope,
                claim.fencing_epoch,
                claim.authorization_digest,
                claim.tx_hash,
                claim.template_hash,
                claim.shared_output_commitment,
                ClaimSendStateV1 {
                    attempted: claim.send_attempted,
                    attempt_count: claim.send_attempt_count,
                },
            )
        || (claim.send_attempted && claim.send_attempt_count == 0)
        || (!claim.send_attempted && claim.send_attempt_count != 0)
    {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(Some(claim))
}

fn claim_admission_record_digest(
    claim: &StoredClaimCustodyV1,
    state: SubmissionStateV1,
    relayed: bool,
    receipt_digest: Digest32,
) -> Digest32 {
    hash_parts(&[
        b"DOM:actuator-claim-admission:v1",
        &claim.route_id,
        &claim.session_id,
        &claim.participant_id,
        &claim.effect_id,
        &claim.fencing_epoch.to_be_bytes(),
        &claim.tx_hash,
        &claim.record_digest,
        &[state.tag_v1()],
        &[u8::from(relayed)],
        &receipt_digest,
    ])
}

fn load_claim_admission(
    transaction: &Transaction<'_>,
    session_id: Digest32,
) -> DomActuatorResult<Option<StoredClaimAdmissionV1>> {
    let row = transaction
        .query_row(
            "SELECT effect_id,route_id,participant_id,fencing_epoch,tx_hash,
             claim_record_digest,receipt_state_tag,receipt_relayed,
             receipt_digest,record_digest
             FROM dom_claim_admission WHERE session_id=?1",
            params![session_id.as_slice()],
            RawClaimAdmissionRowV1::from_row,
        )
        .optional()
        .map_err(storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let state = match row.receipt_state_tag {
        1 => SubmissionStateV1::New,
        2 => SubmissionStateV1::Mempool,
        3 => SubmissionStateV1::Confirmed,
        _ => return Err(DomActuatorError::UnsupportedFormat),
    };
    let relayed = match row.receipt_relayed {
        0 => false,
        1 => true,
        _ => return Err(DomActuatorError::UnsupportedFormat),
    };
    let admission = StoredClaimAdmissionV1 {
        session_id,
        effect_id: blob32(row.effect_id)?,
        route_id: blob32(row.route_id)?,
        participant_id: blob32(row.participant_id)?,
        fencing_epoch: from_sql(row.fencing_epoch)?,
        tx_hash: blob32(row.tx_hash)?,
        claim_record_digest: blob32(row.claim_record_digest)?,
        state,
        relayed,
        receipt_digest: blob32(row.receipt_digest)?,
        record_digest: blob32(row.record_digest)?,
    };
    let claim =
        load_claim_custody(transaction, session_id)?.ok_or(DomActuatorError::UnsupportedFormat)?;
    validate_claim_custody_operation(transaction, &claim)?;
    if validate_submission_receipt_facts_v1(
        admission.tx_hash,
        admission.state,
        admission.relayed,
        admission.receipt_digest,
    )
    .is_err()
        || admission.effect_id != claim.effect_id
        || admission.route_id != claim.route_id
        || admission.participant_id != claim.participant_id
        || admission.fencing_epoch != claim.fencing_epoch
        || admission.tx_hash != claim.tx_hash
        || admission.claim_record_digest != claim.record_digest
        || !claim.send_attempted
        || claim.send_attempt_count == 0
        || admission.record_digest
            != claim_admission_record_digest(
                &claim,
                admission.state,
                admission.relayed,
                admission.receipt_digest,
            )
    {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(Some(admission))
}

fn validate_claim_custody_operation(
    transaction: &Transaction<'_>,
    claim: &StoredClaimCustodyV1,
) -> DomActuatorResult<()> {
    let binding =
        load_binding(transaction, claim.session_id)?.ok_or(DomActuatorError::UnsupportedFormat)?;
    let scope = ScopedDomActionV1::new(binding, claim.effect_id, DomActionV1::BroadcastClaim)?;
    let operation =
        load_operation(transaction, claim.effect_id)?.ok_or(DomActuatorError::UnsupportedFormat)?;
    if claim.route_id != binding.route_id()
        || claim.participant_id != binding.participant().participant_id()
        || operation.status != OP_COMPLETED
        || operation.fencing_epoch != claim.fencing_epoch
        || operation.scope_digest != scope_digest(scope)
        || operation.authorization_digest != claim.authorization_digest
        || operation.receipt_digest != Some(claim.tx_hash)
    {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(())
}

fn validate_claim_admission_scope(
    admission: &StoredClaimAdmissionV1,
    claim: &StoredClaimCustodyV1,
) -> DomActuatorResult<()> {
    if admission.session_id != claim.session_id
        || admission.effect_id != claim.effect_id
        || admission.route_id != claim.route_id
        || admission.participant_id != claim.participant_id
        || admission.fencing_epoch != claim.fencing_epoch
        || admission.tx_hash != claim.tx_hash
        || admission.claim_record_digest != claim.record_digest
    {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    Ok(())
}

/// Require an exposed exact claim, in either custody generation, for one txid.
///
/// Terminal finality and reorg reconciliation are legal for a merely exposed
/// claim, because a durable pre-RPC attempt means the transaction may already be
/// canonical; they are never legal for an unattempted one, and they never create
/// or upgrade an admission. Exactly one custody generation may exist for a
/// session: V2 never coexists with legacy V1 bytes.
fn require_exposed_claim_identity(
    transaction: &Transaction<'_>,
    binding: DomSessionBindingV1,
    tx_hash: Digest32,
) -> DomActuatorResult<()> {
    let has_v2 = load_final_claim_attempt_v2(transaction, binding.session_id())?.is_some();
    let has_v1 = load_claim_custody(transaction, binding.session_id())?.is_some();
    let (classification, retained_tx_hash) = match (has_v2, has_v1) {
        (true, true) => return Err(DomActuatorError::UnsupportedFormat),
        (true, false) => {
            let audit = load_final_claim_custody_audit_v2(transaction, binding)?;
            (audit.classification, audit.tx_hash)
        }
        (false, _) => {
            let audit = load_claim_custody_audit(transaction, binding)?;
            (audit.classification, audit.tx_hash)
        }
    };
    if classification == DomClaimCustodyClassificationV1::Unattempted {
        return Err(DomActuatorError::InvalidStage);
    }
    if retained_tx_hash != tx_hash {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    Ok(())
}

fn load_claim_custody_audit(
    transaction: &Transaction<'_>,
    binding: DomSessionBindingV1,
) -> DomActuatorResult<DomClaimCustodyAuditV1> {
    let claim = load_claim_custody(transaction, binding.session_id())?
        .ok_or(DomActuatorError::ReconciliationRequired)?;
    if claim.route_id != binding.route_id()
        || claim.participant_id != binding.participant().participant_id()
    {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    validate_claim_custody_operation(transaction, &claim)?;
    let admission = load_claim_admission(transaction, binding.session_id())?;
    if let Some(admission) = admission.as_ref() {
        validate_claim_admission_scope(admission, &claim)?;
        if !claim.send_attempted || claim.send_attempt_count == 0 {
            return Err(DomActuatorError::UnsupportedFormat);
        }
    }
    let classification = if admission.is_some() {
        DomClaimCustodyClassificationV1::Admitted
    } else if claim.send_attempted {
        DomClaimCustodyClassificationV1::PotentiallyExposed
    } else {
        DomClaimCustodyClassificationV1::Unattempted
    };
    Ok(DomClaimCustodyAuditV1 {
        classification,
        session_id: claim.session_id,
        effect_id: claim.effect_id,
        route_id: claim.route_id,
        participant_id: claim.participant_id,
        custody_fencing_epoch: claim.fencing_epoch,
        tx_hash: claim.tx_hash,
        template_hash: claim.template_hash,
        shared_output_commitment: claim.shared_output_commitment,
        custody_record_digest: claim.record_digest,
        send_attempt_count: claim.send_attempt_count,
        admission_record_digest: admission.map(|value| value.record_digest),
    })
}

impl StoredClaimAdmissionV1 {
    fn into_capability(self) -> DomClaimAdmissionV1 {
        DomClaimAdmissionV1 {
            session_id: self.session_id,
            effect_id: self.effect_id,
            original_fencing_epoch: self.fencing_epoch,
            tx_hash: self.tx_hash,
            state: self.state,
            relayed: self.relayed,
            receipt_digest: self.receipt_digest,
            record_digest: self.record_digest,
        }
    }
}

fn final_claim_attempt_record_digest_v2(
    scope: ScopedDomActionV1,
    owner_id: Digest32,
    fencing_epoch: u64,
    authorization_digest: Digest32,
    facts: &FinalClaimAttemptFactsV2,
    send_attempt_count: u64,
) -> Digest32 {
    hash_parts(&[
        b"DOM:actuator-final-claim-attempt:v2",
        &scope.binding().route_id(),
        &scope.binding().session_id(),
        &scope.binding().participant().participant_id(),
        &scope.effect_id(),
        &owner_id,
        &fencing_epoch.to_be_bytes(),
        &authorization_digest,
        &facts.authority_evidence_digest,
        &facts.dom_claim_sender_id,
        &facts.final_claim_receiver_id,
        &facts.tx_hash,
        &facts.template_hash,
        &facts.shared_output_commitment,
        &facts.exposure_record_digest,
        &send_attempt_count.to_be_bytes(),
    ])
}

fn final_claim_admission_record_digest_v2(
    attempt: &StoredFinalClaimAttemptV2,
    state: SubmissionStateV1,
    relayed: bool,
    receipt_digest: Digest32,
) -> Digest32 {
    hash_parts(&[
        b"DOM:actuator-final-claim-admission:v2",
        &attempt.route_id,
        &attempt.session_id,
        &attempt.participant_id,
        &attempt.effect_id,
        &attempt.fencing_epoch.to_be_bytes(),
        &attempt.dom_claim_sender_id,
        &attempt.final_claim_receiver_id,
        &attempt.tx_hash,
        &attempt.exposure_record_digest,
        &attempt.record_digest,
        &[state.tag_v1()],
        &[u8::from(relayed)],
        &receipt_digest,
    ])
}

struct FinalClaimAttemptRowV2 {
    effect_id: Vec<u8>,
    route_id: Vec<u8>,
    participant_id: Vec<u8>,
    owner_id: Vec<u8>,
    fencing_epoch: i64,
    authorization_digest: Vec<u8>,
    dom_claim_sender_id: Vec<u8>,
    final_claim_receiver_id: Vec<u8>,
    tx_hash: Vec<u8>,
    template_hash: Vec<u8>,
    shared_output_commitment: Vec<u8>,
    exposure_record_digest: Vec<u8>,
    record_digest: Vec<u8>,
    send_attempt_count: i64,
}

fn load_final_claim_attempt_v2(
    transaction: &Transaction<'_>,
    session_id: Digest32,
) -> DomActuatorResult<Option<StoredFinalClaimAttemptV2>> {
    let row: Option<FinalClaimAttemptRowV2> = transaction
        .query_row(
            "SELECT effect_id,route_id,participant_id,owner_id,fencing_epoch,authorization_digest,
             dom_claim_sender_id,final_claim_receiver_id,tx_hash,template_hash,
             shared_output_commitment,exposure_record_digest,record_digest,send_attempt_count
             FROM dom_final_claim_attempt_v2 WHERE session_id=?1",
            params![session_id.as_slice()],
            |row| {
                Ok(FinalClaimAttemptRowV2 {
                    effect_id: row.get(0)?,
                    route_id: row.get(1)?,
                    participant_id: row.get(2)?,
                    owner_id: row.get(3)?,
                    fencing_epoch: row.get(4)?,
                    authorization_digest: row.get(5)?,
                    dom_claim_sender_id: row.get(6)?,
                    final_claim_receiver_id: row.get(7)?,
                    tx_hash: row.get(8)?,
                    template_hash: row.get(9)?,
                    shared_output_commitment: row.get(10)?,
                    exposure_record_digest: row.get(11)?,
                    record_digest: row.get(12)?,
                    send_attempt_count: row.get(13)?,
                })
            },
        )
        .optional()
        .map_err(storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let attempt = StoredFinalClaimAttemptV2 {
        session_id,
        effect_id: blob32(row.effect_id)?,
        route_id: blob32(row.route_id)?,
        participant_id: blob32(row.participant_id)?,
        owner_id: blob32(row.owner_id)?,
        fencing_epoch: from_sql(row.fencing_epoch)?,
        authorization_digest: blob32(row.authorization_digest)?,
        dom_claim_sender_id: blob32(row.dom_claim_sender_id)?,
        final_claim_receiver_id: blob32(row.final_claim_receiver_id)?,
        tx_hash: blob32(row.tx_hash)?,
        template_hash: blob32(row.template_hash)?,
        shared_output_commitment: blob33(row.shared_output_commitment)?,
        exposure_record_digest: blob32(row.exposure_record_digest)?,
        record_digest: blob32(row.record_digest)?,
        send_attempt_count: from_sql(row.send_attempt_count)?,
    };
    if attempt.owner_id == [0; 32]
        || attempt.send_attempt_count == 0
        || attempt.dom_claim_sender_id != attempt.participant_id
        || attempt.final_claim_receiver_id == attempt.participant_id
    {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(Some(attempt))
}

struct FinalClaimAdmissionRowV2 {
    effect_id: Vec<u8>,
    route_id: Vec<u8>,
    participant_id: Vec<u8>,
    fencing_epoch: i64,
    dom_claim_sender_id: Vec<u8>,
    final_claim_receiver_id: Vec<u8>,
    tx_hash: Vec<u8>,
    exposure_record_digest: Vec<u8>,
    attempt_record_digest: Vec<u8>,
    receipt_state_tag: i64,
    receipt_relayed: i64,
    receipt_digest: Vec<u8>,
    record_digest: Vec<u8>,
}

fn load_final_claim_admission_v2(
    transaction: &Transaction<'_>,
    session_id: Digest32,
) -> DomActuatorResult<Option<StoredFinalClaimAdmissionV2>> {
    let row: Option<FinalClaimAdmissionRowV2> = transaction
        .query_row(
            "SELECT effect_id,route_id,participant_id,fencing_epoch,dom_claim_sender_id,
             final_claim_receiver_id,tx_hash,exposure_record_digest,attempt_record_digest,
             receipt_state_tag,receipt_relayed,receipt_digest,record_digest
             FROM dom_final_claim_admission_v2 WHERE session_id=?1",
            params![session_id.as_slice()],
            |row| {
                Ok(FinalClaimAdmissionRowV2 {
                    effect_id: row.get(0)?,
                    route_id: row.get(1)?,
                    participant_id: row.get(2)?,
                    fencing_epoch: row.get(3)?,
                    dom_claim_sender_id: row.get(4)?,
                    final_claim_receiver_id: row.get(5)?,
                    tx_hash: row.get(6)?,
                    exposure_record_digest: row.get(7)?,
                    attempt_record_digest: row.get(8)?,
                    receipt_state_tag: row.get(9)?,
                    receipt_relayed: row.get(10)?,
                    receipt_digest: row.get(11)?,
                    record_digest: row.get(12)?,
                })
            },
        )
        .optional()
        .map_err(storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let state = match row.receipt_state_tag {
        1 => SubmissionStateV1::New,
        2 => SubmissionStateV1::Mempool,
        3 => SubmissionStateV1::Confirmed,
        _ => return Err(DomActuatorError::UnsupportedFormat),
    };
    let relayed = match row.receipt_relayed {
        0 => false,
        1 => true,
        _ => return Err(DomActuatorError::UnsupportedFormat),
    };
    let admission = StoredFinalClaimAdmissionV2 {
        session_id,
        effect_id: blob32(row.effect_id)?,
        route_id: blob32(row.route_id)?,
        participant_id: blob32(row.participant_id)?,
        fencing_epoch: from_sql(row.fencing_epoch)?,
        dom_claim_sender_id: blob32(row.dom_claim_sender_id)?,
        final_claim_receiver_id: blob32(row.final_claim_receiver_id)?,
        tx_hash: blob32(row.tx_hash)?,
        exposure_record_digest: blob32(row.exposure_record_digest)?,
        attempt_record_digest: blob32(row.attempt_record_digest)?,
        state,
        relayed,
        receipt_digest: blob32(row.receipt_digest)?,
        record_digest: blob32(row.record_digest)?,
    };
    let attempt = load_final_claim_attempt_v2(transaction, session_id)?
        .ok_or(DomActuatorError::UnsupportedFormat)?;
    validate_final_claim_attempt_operation_v2(transaction, &attempt)?;
    if validate_submission_receipt_facts_v1(
        admission.tx_hash,
        admission.state,
        admission.relayed,
        admission.receipt_digest,
    )
    .is_err()
        || validate_final_claim_admission_scope_v2(&admission, &attempt).is_err()
        || admission.record_digest
            != final_claim_admission_record_digest_v2(
                &attempt,
                admission.state,
                admission.relayed,
                admission.receipt_digest,
            )
    {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(Some(admission))
}

fn validate_final_claim_attempt_operation_v2(
    transaction: &Transaction<'_>,
    attempt: &StoredFinalClaimAttemptV2,
) -> DomActuatorResult<()> {
    let binding = load_binding(transaction, attempt.session_id)?
        .ok_or(DomActuatorError::UnsupportedFormat)?;
    let scope = ScopedDomActionV1::new(binding, attempt.effect_id, DomActionV1::BroadcastClaim)?;
    let operation = load_operation(transaction, attempt.effect_id)?
        .ok_or(DomActuatorError::UnsupportedFormat)?;
    let facts = FinalClaimAttemptFactsV2 {
        authority_evidence_digest: operation.evidence_digest,
        dom_claim_sender_id: attempt.dom_claim_sender_id,
        final_claim_receiver_id: attempt.final_claim_receiver_id,
        tx_hash: attempt.tx_hash,
        template_hash: attempt.template_hash,
        shared_output_commitment: attempt.shared_output_commitment,
        exposure_record_digest: attempt.exposure_record_digest,
    };
    if attempt.route_id != binding.route_id()
        || attempt.participant_id != binding.participant().participant_id()
        || operation.status != OP_COMPLETED
        || operation.fencing_epoch != attempt.fencing_epoch
        || operation.scope_digest != scope_digest(scope)
        || operation.authorization_digest != attempt.authorization_digest
        || operation.receipt_digest != Some(attempt.exposure_record_digest)
        || attempt.record_digest
            != final_claim_attempt_record_digest_v2(
                scope,
                attempt.owner_id,
                attempt.fencing_epoch,
                attempt.authorization_digest,
                &facts,
                attempt.send_attempt_count,
            )
    {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(())
}

fn validate_final_claim_admission_scope_v2(
    admission: &StoredFinalClaimAdmissionV2,
    attempt: &StoredFinalClaimAttemptV2,
) -> DomActuatorResult<()> {
    if admission.session_id != attempt.session_id
        || admission.effect_id != attempt.effect_id
        || admission.route_id != attempt.route_id
        || admission.participant_id != attempt.participant_id
        || admission.fencing_epoch != attempt.fencing_epoch
        || admission.dom_claim_sender_id != attempt.dom_claim_sender_id
        || admission.final_claim_receiver_id != attempt.final_claim_receiver_id
        || admission.tx_hash != attempt.tx_hash
        || admission.exposure_record_digest != attempt.exposure_record_digest
        || admission.attempt_record_digest != attempt.record_digest
    {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    Ok(())
}

fn load_final_claim_custody_audit_v2(
    transaction: &Transaction<'_>,
    binding: DomSessionBindingV1,
) -> DomActuatorResult<DomFinalClaimCustodyAuditV2> {
    let attempt = load_final_claim_attempt_v2(transaction, binding.session_id())?
        .ok_or(DomActuatorError::ReconciliationRequired)?;
    if attempt.route_id != binding.route_id()
        || attempt.participant_id != binding.participant().participant_id()
    {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    validate_final_claim_attempt_operation_v2(transaction, &attempt)?;
    let admission = load_final_claim_admission_v2(transaction, binding.session_id())?;
    if let Some(admission) = admission.as_ref() {
        validate_final_claim_admission_scope_v2(admission, &attempt)?;
    }
    // A durable pre-RPC attempt latch means the adapted claim may already be
    // public, so the weakest disposition this mirror can ever report is
    // `PotentiallyExposed`; `Unattempted` is reserved for the absent row and is
    // signalled by the `ReconciliationRequired` above.
    let classification = if admission.is_some() {
        DomClaimCustodyClassificationV1::Admitted
    } else {
        DomClaimCustodyClassificationV1::PotentiallyExposed
    };
    Ok(DomFinalClaimCustodyAuditV2 {
        classification,
        session_id: attempt.session_id,
        effect_id: attempt.effect_id,
        route_id: attempt.route_id,
        participant_id: attempt.participant_id,
        dom_claim_sender_id: attempt.dom_claim_sender_id,
        final_claim_receiver_id: attempt.final_claim_receiver_id,
        custody_fencing_epoch: attempt.fencing_epoch,
        tx_hash: attempt.tx_hash,
        template_hash: attempt.template_hash,
        shared_output_commitment: attempt.shared_output_commitment,
        exposure_record_digest: attempt.exposure_record_digest,
        attempt_record_digest: attempt.record_digest,
        send_attempt_count: attempt.send_attempt_count,
        admission_record_digest: admission.map(|value| value.record_digest),
    })
}

impl StoredFinalClaimAdmissionV2 {
    fn into_capability(self) -> DomFinalClaimAdmissionV2 {
        DomFinalClaimAdmissionV2 {
            session_id: self.session_id,
            effect_id: self.effect_id,
            original_fencing_epoch: self.fencing_epoch,
            dom_claim_sender_id: self.dom_claim_sender_id,
            final_claim_receiver_id: self.final_claim_receiver_id,
            tx_hash: self.tx_hash,
            exposure_record_digest: self.exposure_record_digest,
            state: self.state,
            relayed: self.relayed,
            receipt_digest: self.receipt_digest,
            record_digest: self.record_digest,
        }
    }
}

fn validate_terminal_finality_record(
    binding: DomSessionBindingV1,
    record: &DomTerminalFinalityRecordV1<'_>,
) -> DomActuatorResult<()> {
    let expected_depth = record
        .tip_height
        .checked_sub(record.block_height)
        .and_then(|distance| distance.checked_add(1))
        .and_then(|depth| u32::try_from(depth).ok())
        .ok_or(DomActuatorError::InvalidBinding)?;
    if record.tx_hash == [0; 32]
        || record.block_hash == [0; 32]
        || record.tip_hash == [0; 32]
        || record.evidence_digest == [0; 32]
        || record.checkpoint_bytes.len() < 246
        || record.checkpoint_bytes.len() > 196_608
        || record.confirmation_depth != expected_depth
        || record.confirmation_depth < binding.min_confirmations()
        || record.minimum_confirmations != binding.min_confirmations()
        || record.max_reorg_depth != binding.max_reorg_depth()
    {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    Ok(())
}

fn validate_terminal_reorg_record(
    binding: DomSessionBindingV1,
    record: &DomTerminalReorgRecordV1,
) -> DomActuatorResult<()> {
    if record.tx_hash == [0; 32]
        || record.prior_evidence_digest == [0; 32]
        || record.current_tip_hash == [0; 32]
        || record.evidence_digest == [0; 32]
        || record.common_ancestor_height > record.current_tip_height
        || record.removed_depth == 0
        || record.removed_depth > binding.max_reorg_depth()
        || record.minimum_confirmations != binding.min_confirmations()
        || record.max_reorg_depth != binding.max_reorg_depth()
    {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    Ok(())
}

fn finality_checkpoint_digest(checkpoint_bytes: &[u8]) -> Digest32 {
    hash_parts(&[
        b"DOM:actuator-terminal-finality-checkpoint:v1",
        checkpoint_bytes,
    ])
}

fn terminal_finality_record_digest(
    binding: DomSessionBindingV1,
    material: TerminalFinalityDigestMaterialV1,
) -> Digest32 {
    let reorg_tag = [u8::from(material.reorg_evidence_digest.is_some())];
    let reorg_evidence_digest = material.reorg_evidence_digest.unwrap_or([0; 32]);
    hash_parts(&[
        b"DOM:actuator-terminal-finality-row:v2",
        &binding.route_id(),
        &binding.session_id(),
        &[material.kind as u8],
        &material.tx_hash,
        &material.block_height.to_be_bytes(),
        &material.block_hash,
        &material.tip_height.to_be_bytes(),
        &material.tip_hash,
        &material.confirmation_depth.to_be_bytes(),
        &material.minimum_confirmations.to_be_bytes(),
        &material.max_reorg_depth.to_be_bytes(),
        &material.evidence_digest,
        &material.checkpoint_digest,
        &reorg_tag,
        &reorg_evidence_digest,
        &[u8::from(material.active)],
        &material.fencing_epoch.to_be_bytes(),
    ])
}

fn load_terminal_finality(
    transaction: &Transaction<'_>,
    binding: DomSessionBindingV1,
    expected_kind: DomTerminalKindV1,
) -> DomActuatorResult<Option<StoredDomTerminalFinalityV1>> {
    let row = transaction
        .query_row(
            "SELECT kind_tag,tx_hash,block_height,block_hash,tip_height,tip_hash,
             confirmation_depth,minimum_confirmations,max_reorg_depth,evidence_digest,
             checkpoint_bytes,checkpoint_digest,record_digest,active,reorg_evidence_digest,
             fencing_epoch
             FROM dom_terminal_finality WHERE session_id=?1 AND kind_tag=?2",
            params![binding.session_id().as_slice(), expected_kind as u8],
            RawTerminalFinalityRowV1::from_row,
        )
        .optional()
        .map_err(storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let value = StoredDomTerminalFinalityV1 {
        kind: DomTerminalKindV1::decode(row.kind_tag)?,
        tx_hash: blob32(row.tx_hash)?,
        block_height: from_sql(row.block_height)?,
        block_hash: blob32(row.block_hash)?,
        tip_height: from_sql(row.tip_height)?,
        tip_hash: blob32(row.tip_hash)?,
        confirmation_depth: u32::try_from(row.confirmation_depth)
            .map_err(|_| DomActuatorError::UnsupportedFormat)?,
        minimum_confirmations: u32::try_from(row.minimum_confirmations)
            .map_err(|_| DomActuatorError::UnsupportedFormat)?,
        max_reorg_depth: u32::try_from(row.max_reorg_depth)
            .map_err(|_| DomActuatorError::UnsupportedFormat)?,
        evidence_digest: blob32(row.evidence_digest)?,
        checkpoint_bytes: row.checkpoint_bytes,
        checkpoint_digest: blob32(row.checkpoint_digest)?,
        record_digest: blob32(row.record_digest)?,
        active: match row.active {
            0 => false,
            1 => true,
            _ => return Err(DomActuatorError::UnsupportedFormat),
        },
        reorg_evidence_digest: row.reorg_evidence_digest.map(blob32).transpose()?,
        fencing_epoch: from_sql(row.fencing_epoch)?,
    };
    let expected_depth = value
        .tip_height
        .checked_sub(value.block_height)
        .and_then(|distance| distance.checked_add(1))
        .and_then(|depth| u32::try_from(depth).ok())
        .ok_or(DomActuatorError::UnsupportedFormat)?;
    if value.kind != expected_kind
        || value.tx_hash == [0; 32]
        || value.block_hash == [0; 32]
        || value.tip_hash == [0; 32]
        || value.evidence_digest == [0; 32]
        || value.reorg_evidence_digest.is_some() == value.active
        || value.confirmation_depth != expected_depth
        || value.confirmation_depth < value.minimum_confirmations
        || value.minimum_confirmations != binding.min_confirmations()
        || value.max_reorg_depth != binding.max_reorg_depth()
        || value.checkpoint_bytes.len() < 246
        || value.checkpoint_bytes.len() > 196_608
        || finality_checkpoint_digest(&value.checkpoint_bytes) != value.checkpoint_digest
        || terminal_finality_record_digest(
            binding,
            TerminalFinalityDigestMaterialV1 {
                kind: value.kind,
                tx_hash: value.tx_hash,
                block_height: value.block_height,
                block_hash: value.block_hash,
                tip_height: value.tip_height,
                tip_hash: value.tip_hash,
                confirmation_depth: value.confirmation_depth,
                minimum_confirmations: value.minimum_confirmations,
                max_reorg_depth: value.max_reorg_depth,
                evidence_digest: value.evidence_digest,
                checkpoint_digest: value.checkpoint_digest,
                reorg_evidence_digest: value.reorg_evidence_digest,
                active: value.active,
                fencing_epoch: value.fencing_epoch,
            },
        ) != value.record_digest
    {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(Some(value))
}

fn validate_claim_scope(
    claim: &StoredClaimCustodyV1,
    capability: &DomActuatorCapabilityV1,
) -> DomActuatorResult<()> {
    let scope = capability.scope();
    if claim.session_id != scope.binding().session_id()
        || claim.effect_id != scope.effect_id()
        || claim.route_id != scope.binding().route_id()
        || claim.participant_id != scope.binding().participant().participant_id()
        || claim.authorization_digest != capability.authorization_digest()
    {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    Ok(())
}

impl StoredClaimCustodyV1 {
    fn into_broadcast(self) -> DomClaimBroadcastV1 {
        DomClaimBroadcastV1 {
            session_id: self.session_id,
            effect_id: self.effect_id,
            fencing_epoch: self.fencing_epoch,
            tx_hash: self.tx_hash,
            exact_bytes: self.exact_bytes,
        }
    }
}

fn settlement_child_binding_record_digest(
    request: DomSettlementChildBindingRequestV1,
    transaction_id: Digest32,
) -> Digest32 {
    let scope = request.scope();
    let binding = scope.binding();
    hash_parts(&[
        b"DOM:actuator-settlement-child-binding:v1",
        &binding.route_id(),
        &binding.session_id(),
        &binding.participant().participant_id(),
        &scope.effect_id(),
        &[scope.action().tag()],
        &[request.exposure().tag()],
        &request.semantic_digest(),
        &request.registry_digest(),
        &binding.terms_digest(),
        &binding.profile_digest(),
        &binding.deployment_digest(),
        &binding.chain_id(),
        &transaction_id,
        &request.intent_digest(),
        &request.custody_digest(),
    ])
}

fn decode_settlement_child_action(value: i64) -> DomActuatorResult<DomActionV1> {
    match value {
        6 => Ok(DomActionV1::BroadcastFunding),
        7 => Ok(DomActionV1::BroadcastClaim),
        8 => Ok(DomActionV1::BroadcastRefund),
        _ => Err(DomActuatorError::UnsupportedFormat),
    }
}

fn load_settlement_child_binding(
    transaction: &Transaction<'_>,
    custody_digest: Digest32,
) -> DomActuatorResult<Option<StoredSettlementChildBindingV1>> {
    let row = transaction
        .query_row(
            "SELECT effect_id,route_id,session_id,participant_id,action_tag,
             exposure_tag,semantic_digest,registry_digest,terms_digest,
             profile_digest,deployment_digest,chain_id,transaction_id,
             intent_digest,binding_record_digest
             FROM dom_settlement_children WHERE custody_digest=?1",
            params![custody_digest.as_slice()],
            RawSettlementChildBindingRowV1::from_row,
        )
        .optional()
        .map_err(storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let session_id = blob32(row.session_id)?;
    let binding =
        load_binding(transaction, session_id)?.ok_or(DomActuatorError::UnsupportedFormat)?;
    if blob32(row.route_id)? != binding.route_id()
        || blob32(row.participant_id)? != binding.participant().participant_id()
        || blob32(row.terms_digest)? != binding.terms_digest()
        || blob32(row.profile_digest)? != binding.profile_digest()
        || blob32(row.deployment_digest)? != binding.deployment_digest()
        || blob32(row.chain_id)? != binding.chain_id()
    {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    let scope = ScopedDomActionV1::new(
        binding,
        blob32(row.effect_id)?,
        decode_settlement_child_action(row.action_tag)?,
    )
    .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    let request = DomSettlementChildBindingRequestV1::new(
        scope,
        blob32(row.semantic_digest)?,
        blob32(row.registry_digest)?,
        blob32(row.intent_digest)?,
        custody_digest,
        DomSettlementChildExposureV1::decode(row.exposure_tag)?,
    )
    .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    Ok(Some(StoredSettlementChildBindingV1 {
        request,
        transaction_id: blob32(row.transaction_id)?,
        binding_record_digest: blob32(row.binding_record_digest)?,
    }))
}

fn load_settlement_child_binding_by_effect(
    transaction: &Transaction<'_>,
    effect_id: Digest32,
) -> DomActuatorResult<Option<StoredSettlementChildBindingV1>> {
    let custody: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT custody_digest FROM dom_settlement_children WHERE effect_id=?1",
            params![effect_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    custody
        .map(blob32)
        .transpose()?
        .map(|value| {
            load_settlement_child_binding(transaction, value)?
                .ok_or(DomActuatorError::UnsupportedFormat)
        })
        .transpose()
}

fn validate_settlement_child_binding(
    transaction: &Transaction<'_>,
    stored: StoredSettlementChildBindingV1,
) -> DomActuatorResult<DomSettlementChildBindingV1> {
    stored
        .request
        .validate()
        .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    validate_digest(stored.transaction_id).map_err(|_| DomActuatorError::UnsupportedFormat)?;
    let operation = load_operation(transaction, stored.request.scope().effect_id())?
        .ok_or(DomActuatorError::UnsupportedFormat)?;
    let expected_record =
        settlement_child_binding_record_digest(stored.request, stored.transaction_id);
    let expected_authorization = authorization_digest(
        operation.scope_digest,
        operation.evidence_digest,
        operation.secret_binding_digest,
        operation.fencing_epoch,
    );
    if stored.binding_record_digest != expected_record
        || operation.scope_digest != scope_digest(stored.request.scope())
        || operation.evidence_digest == [0; 32]
        || operation.secret_binding_digest.is_some()
        || operation.authorization_digest != expected_authorization
        || operation.status != OP_COMPLETED
        || !settlement_child_transaction_matches_operation(
            transaction,
            stored.request,
            stored.transaction_id,
            operation,
        )?
    {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(DomSettlementChildBindingV1 {
        request: stored.request,
        transaction_id: stored.transaction_id,
        operation_fencing_epoch: operation.fencing_epoch,
        operation_evidence_digest: operation.evidence_digest,
        operation_authorization_digest: operation.authorization_digest,
        locator: DomSettlementChildLocatorV1 {
            effect_id: stored.request.scope().effect_id(),
            binding_record_digest: stored.binding_record_digest,
            custody_digest: stored.request.custody_digest(),
        },
    })
}

fn settlement_child_transaction_matches_operation(
    transaction: &Transaction<'_>,
    request: DomSettlementChildBindingRequestV1,
    transaction_id: Digest32,
    operation: StoredOperation,
) -> DomActuatorResult<bool> {
    match request.scope().action() {
        DomActionV1::BroadcastFunding | DomActionV1::BroadcastRefund => {
            Ok(operation.receipt_digest == Some(transaction_id))
        }
        DomActionV1::BroadcastClaim => {
            let Some(attempt) =
                load_final_claim_attempt_v2(transaction, request.scope().binding().session_id())?
            else {
                return Ok(false);
            };
            validate_final_claim_attempt_operation_v2(transaction, &attempt)?;
            Ok(attempt.effect_id == request.scope().effect_id()
                && attempt.tx_hash == transaction_id
                && operation.receipt_digest == Some(attempt.exposure_record_digest))
        }
        _ => Ok(false),
    }
}

fn validate_settlement_child_port_call_key(
    key: DomSettlementChildPortCallKeyV1,
) -> DomActuatorResult<()> {
    if key.coordinator_attempt_id() == [0; 32]
        || key.request_digest() == [0; 32]
        || key.locator().effect_id() == [0; 32]
        || key.locator().binding_record_digest() == [0; 32]
        || key.locator().custody_digest() == [0; 32]
    {
        return Err(DomActuatorError::InvalidBinding);
    }
    Ok(())
}

fn require_settlement_child_port_call_binding(
    transaction: &Transaction<'_>,
    lease: DomLeaseV1,
    key: DomSettlementChildPortCallKeyV1,
) -> DomActuatorResult<DomSettlementChildBindingV1> {
    let stored = load_settlement_child_binding(transaction, key.locator().custody_digest())?
        .ok_or(DomActuatorError::CapabilityMismatch)?;
    let view = validate_settlement_child_binding(transaction, stored)?;
    if view.locator() != key.locator()
        || view
            .request()
            .scope()
            .binding()
            .participant()
            .participant_id()
            != lease.participant_id
        || view.operation_fencing_epoch() > lease.fencing_epoch
    {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    Ok(view)
}

fn load_settlement_child_port_call(
    transaction: &Transaction<'_>,
    coordinator_attempt_id: Digest32,
) -> DomActuatorResult<Option<StoredSettlementChildPortCallV1>> {
    let row = transaction
        .query_row(
            "SELECT call_kind,request_digest,custody_digest,effect_id,
             binding_record_digest,actuator_fencing_epoch,outcome_bytes,outcome_digest
             FROM dom_settlement_child_port_calls WHERE coordinator_attempt_id=?1",
            params![coordinator_attempt_id.as_slice()],
            RawSettlementChildPortCallRowV1::from_row,
        )
        .optional()
        .map_err(storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let call_kind = DomSettlementChildPortCallKindV1::decode(row.call_kind)?;
    let outcome = row
        .outcome_bytes
        .as_deref()
        .map(DomSettlementChildPortCallOutcomeV1::from_canonical_bytes)
        .transpose()?;
    Ok(Some(StoredSettlementChildPortCallV1 {
        key: DomSettlementChildPortCallKeyV1 {
            call_kind,
            coordinator_attempt_id,
            request_digest: blob32(row.request_digest)?,
            locator: DomSettlementChildLocatorV1 {
                effect_id: blob32(row.effect_id)?,
                binding_record_digest: blob32(row.binding_record_digest)?,
                custody_digest: blob32(row.custody_digest)?,
            },
        },
        actuator_fencing_epoch: from_sql(row.actuator_fencing_epoch)?,
        outcome,
        outcome_digest: row.outcome_digest.map(blob32).transpose()?,
    }))
}

fn require_settlement_child_port_call_key(
    stored: &StoredSettlementChildPortCallV1,
    key: DomSettlementChildPortCallKeyV1,
    lease: DomLeaseV1,
) -> DomActuatorResult<()> {
    if stored.key != key || stored.actuator_fencing_epoch > lease.fencing_epoch {
        return Err(DomActuatorError::IdempotencyConflict);
    }
    Ok(())
}

fn settlement_child_port_call_outcome_digest(bytes: &[u8]) -> Digest32 {
    hash_parts(&[b"DOM:actuator-settlement-child-port-outcome:v1", bytes])
}

fn settlement_child_port_call_status(
    stored: &StoredSettlementChildPortCallV1,
) -> DomActuatorResult<DomSettlementChildPortCallJournalStatusV1> {
    match (stored.outcome, stored.outcome_digest) {
        (None, None) => Ok(DomSettlementChildPortCallJournalStatusV1::Pending),
        (Some(outcome), Some(digest)) => {
            outcome
                .validate_for(stored.key.call_kind())
                .map_err(|_| DomActuatorError::UnsupportedFormat)?;
            if settlement_child_port_call_outcome_digest(&outcome.canonical_bytes()) != digest {
                return Err(DomActuatorError::UnsupportedFormat);
            }
            Ok(DomSettlementChildPortCallJournalStatusV1::Committed(
                outcome,
            ))
        }
        _ => Err(DomActuatorError::UnsupportedFormat),
    }
}

fn validate_settlement_child_port_call_outcome(
    binding: &DomSettlementChildBindingV1,
    kind: DomSettlementChildPortCallKindV1,
    outcome: DomSettlementChildPortCallOutcomeV1,
) -> DomActuatorResult<()> {
    outcome.validate_for(kind)?;
    if let DomSettlementChildPortCallOutcomeV1::Externalized {
        first_exposure_evidence_digest,
        ..
    } = outcome
    {
        let expected =
            binding.request().exposure() == DomSettlementChildExposureV1::FirstSecretExposure;
        if first_exposure_evidence_digest.is_some() != expected {
            return Err(DomActuatorError::CapabilityMismatch);
        }
    }
    Ok(())
}

fn validate_digest(value: Digest32) -> DomActuatorResult<()> {
    if value == [0; 32] {
        Err(DomActuatorError::InvalidBinding)
    } else {
        Ok(())
    }
}

fn deadline(now: u64, duration: u64) -> DomActuatorResult<u64> {
    if duration == 0 || duration > MAX_LEASE_DURATION_MS {
        return Err(DomActuatorError::InvalidBinding);
    }
    now.checked_add(duration)
        .ok_or(DomActuatorError::InvalidBinding)
}

fn to_sql(value: u64) -> DomActuatorResult<i64> {
    i64::try_from(value).map_err(|_| DomActuatorError::InvalidBinding)
}

fn from_sql(value: i64) -> DomActuatorResult<u64> {
    u64::try_from(value).map_err(|_| DomActuatorError::UnsupportedFormat)
}

fn blob32(value: Vec<u8>) -> DomActuatorResult<Digest32> {
    value
        .try_into()
        .map_err(|_| DomActuatorError::UnsupportedFormat)
}

fn blob33(value: Vec<u8>) -> DomActuatorResult<[u8; 33]> {
    value
        .try_into()
        .map_err(|_| DomActuatorError::UnsupportedFormat)
}

fn hash_parts(parts: &[&[u8]]) -> Digest32 {
    let mut hasher = Blake2b::<U32>::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn scope_digest(scope: ScopedDomActionV1) -> Digest32 {
    let binding = scope.binding();
    hash_parts(&[
        b"DOM:actuator-scope:v1",
        &binding.route_id(),
        &binding.session_id(),
        &scope.effect_id(),
        &[scope.action().tag()],
        &binding.participant().participant_id(),
        &[binding.participant().protocol_index()],
        &binding.chain_id(),
        &binding.genesis_hash(),
        &[binding.runtime_identity().network as u8],
        &binding.runtime_identity().network_magic.to_be_bytes(),
        &binding.runtime_identity().protocol_version.to_be_bytes(),
        &[binding.runtime_identity().range_proof_serialization_version],
        &binding.terms_digest(),
        &binding.profile_digest(),
        &binding.deployment_digest(),
        &binding.asset_binding_digest(),
        &binding.registry_epoch().to_be_bytes(),
        &binding.min_confirmations().to_be_bytes(),
        &binding.max_reorg_depth().to_be_bytes(),
    ])
}

fn authorization_digest(
    scope: Digest32,
    evidence: Digest32,
    secret_binding: Option<Digest32>,
    fence: u64,
) -> Digest32 {
    hash_parts(&[
        b"DOM:actuator-authorization:v1",
        &scope,
        &evidence,
        &secret_binding.unwrap_or([0; 32]),
        &fence.to_be_bytes(),
    ])
}

fn load_lease(
    transaction: &Transaction<'_>,
    participant_id: Digest32,
) -> DomActuatorResult<Option<(Digest32, u64, u64)>> {
    let row: Option<(Vec<u8>, i64, i64)> = transaction
        .query_row(
            "SELECT owner_id,fencing_epoch,lease_until_unix_ms FROM dom_leases
             WHERE participant_id=?1",
            params![participant_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(storage)?;
    row.map(|(owner, epoch, until)| Ok((blob32(owner)?, from_sql(epoch)?, from_sql(until)?)))
        .transpose()
}

fn validate_lease(
    transaction: &Transaction<'_>,
    lease: DomLeaseV1,
    now_unix_ms: u64,
) -> DomActuatorResult<()> {
    let (owner, fence, until) =
        load_lease(transaction, lease.participant_id)?.ok_or(DomActuatorError::StaleFence)?;
    if owner != lease.owner_id || fence != lease.fencing_epoch {
        return Err(DomActuatorError::StaleFence);
    }
    if until != lease.lease_until_unix_ms || until < now_unix_ms {
        return Err(DomActuatorError::LeaseExpired);
    }
    Ok(())
}

fn load_binding(
    transaction: &Transaction<'_>,
    session_id: Digest32,
) -> DomActuatorResult<Option<DomSessionBindingV1>> {
    let row = transaction
        .query_row(
            "SELECT route_id,participant_id,participant_index,chain_id,genesis_hash,
             network_tag,network_magic,protocol_version,rangeproof_serialization_version,
             terms_digest,profile_digest,deployment_digest,asset_binding_digest,
             registry_epoch,min_confirmations,max_reorg_depth
             FROM dom_sessions WHERE session_id=?1",
            params![session_id.as_slice()],
            RawSessionBindingRowV1::from_row,
        )
        .optional()
        .map_err(storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let participant = crate::model::DomParticipantV1::new(
        blob32(row.participant_id)?,
        u8::try_from(row.participant_index).map_err(|_| DomActuatorError::UnsupportedFormat)?,
    )?;
    // Construction from persisted authenticated fields is kept inside this
    // module; validation below detects corruption before the value is used.
    let binding = DomSessionBindingV1::from_parts_for_store(StoredDomSessionBindingPartsV1 {
        route_id: blob32(row.route_id)?,
        session_id,
        participant,
        chain_id: blob32(row.chain_id)?,
        genesis_hash: blob32(row.genesis_hash)?,
        runtime_identity: DomRuntimeIdentityV1 {
            network: match u8::try_from(row.network_tag)
                .map_err(|_| DomActuatorError::UnsupportedFormat)?
            {
                1 => DomNetworkV1::Mainnet,
                2 => DomNetworkV1::Testnet,
                3 => DomNetworkV1::Regtest,
                _ => return Err(DomActuatorError::UnsupportedFormat),
            },
            network_magic: u32::try_from(row.network_magic)
                .map_err(|_| DomActuatorError::UnsupportedFormat)?,
            protocol_version: u32::try_from(row.protocol_version)
                .map_err(|_| DomActuatorError::UnsupportedFormat)?,
            range_proof_serialization_version: u8::try_from(row.rangeproof_serialization_version)
                .map_err(|_| DomActuatorError::UnsupportedFormat)?,
        },
        terms_digest: blob32(row.terms_digest)?,
        profile_digest: blob32(row.profile_digest)?,
        deployment_digest: blob32(row.deployment_digest)?,
        asset_binding_digest: blob32(row.asset_binding_digest)?,
        registry_epoch: from_sql(row.registry_epoch)?,
        min_confirmations: u32::try_from(row.min_confirmations)
            .map_err(|_| DomActuatorError::UnsupportedFormat)?,
        max_reorg_depth: u32::try_from(row.max_reorg_depth)
            .map_err(|_| DomActuatorError::UnsupportedFormat)?,
    })?;
    Ok(Some(binding))
}

fn require_binding(
    transaction: &Transaction<'_>,
    lease: DomLeaseV1,
    binding: DomSessionBindingV1,
) -> DomActuatorResult<()> {
    if binding.participant().participant_id() != lease.participant_id
        || load_binding(transaction, binding.session_id())? != Some(binding)
    {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    Ok(())
}

fn require_scope(
    transaction: &Transaction<'_>,
    lease: DomLeaseV1,
    scope: ScopedDomActionV1,
) -> DomActuatorResult<()> {
    require_binding(transaction, lease, scope.binding())
}

fn payout_face_prepare_digest(
    binding: DomSessionBindingV1,
    payout_commitment: [u8; 33],
    payout_value: u64,
    wallet_ownership_digest: Digest32,
    store_instance_id: Digest32,
    created_at_unix_ms: u64,
) -> Digest32 {
    let runtime = binding.runtime_identity();
    hash_parts(&[
        PAYOUT_FACE_PREPARE_DOMAIN,
        binding.route_id().as_slice(),
        binding.session_id().as_slice(),
        binding.participant().participant_id().as_slice(),
        &[binding.participant().protocol_index()],
        binding.chain_id().as_slice(),
        binding.genesis_hash().as_slice(),
        &[runtime.network as u8],
        &runtime.network_magic.to_be_bytes(),
        &runtime.protocol_version.to_be_bytes(),
        &[runtime.range_proof_serialization_version],
        binding.terms_digest().as_slice(),
        binding.profile_digest().as_slice(),
        binding.deployment_digest().as_slice(),
        binding.asset_binding_digest().as_slice(),
        &binding.registry_epoch().to_be_bytes(),
        &binding.min_confirmations().to_be_bytes(),
        &binding.max_reorg_depth().to_be_bytes(),
        payout_commitment.as_slice(),
        &payout_value.to_be_bytes(),
        wallet_ownership_digest.as_slice(),
        store_instance_id.as_slice(),
        &created_at_unix_ms.to_be_bytes(),
    ])
}

fn prepared_payout_face_matches(
    left: &PreparedDomPayoutFaceV1,
    right: &PreparedDomPayoutFaceV1,
) -> bool {
    left.binding == right.binding
        && left.payout_commitment == right.payout_commitment
        && left.payout_value == right.payout_value
        && left.wallet_ownership_digest == right.wallet_ownership_digest
        && left.store_instance_id == right.store_instance_id
        && left.prepare_digest == right.prepare_digest
        && left.created_at_unix_ms == right.created_at_unix_ms
}

fn active_payout_face_matches_preparation(
    active: &RetainedDomPayoutFaceEvidenceV1,
    prepared: &PreparedDomPayoutFaceV1,
) -> bool {
    active.binding == prepared.binding
        && active.payout_commitment == prepared.payout_commitment
        && active.payout_value == prepared.payout_value
        && active.wallet_ownership_digest == prepared.wallet_ownership_digest
        && active.store_instance_id == prepared.store_instance_id
        && active.prepare_digest == prepared.prepare_digest
}

fn load_payout_face_preparation(
    transaction: &Transaction<'_>,
    binding: DomSessionBindingV1,
) -> DomActuatorResult<Option<PreparedDomPayoutFaceV1>> {
    let row = transaction
        .query_row(
            "SELECT route_id,participant_id,payout_commitment,payout_value,
                    wallet_ownership_digest,store_instance_id,prepare_digest,created_at_unix_ms
             FROM dom_payout_face_preparations WHERE session_id=?1",
            params![binding.session_id().as_slice()],
            RawDomPayoutFacePreparationRowV1::from_row,
        )
        .optional()
        .map_err(storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let payout_commitment = blob33(row.payout_commitment)?;
    Commitment::from_compressed_bytes(&payout_commitment)
        .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    let payout_value = from_sql(row.payout_value)?;
    let wallet_ownership_digest = blob32(row.wallet_ownership_digest)?;
    let store_instance_id = blob32(row.store_instance_id)?;
    let prepare_digest = blob32(row.prepare_digest)?;
    let created_at_unix_ms = from_sql(row.created_at_unix_ms)?;
    if blob32(row.route_id)? != binding.route_id()
        || blob32(row.participant_id)? != binding.participant().participant_id()
        || payout_value == 0
        || wallet_ownership_digest == [0; 32]
        || store_instance_id == [0; 32]
        || prepare_digest == [0; 32]
        || payout_face_prepare_digest(
            binding,
            payout_commitment,
            payout_value,
            wallet_ownership_digest,
            store_instance_id,
            created_at_unix_ms,
        ) != prepare_digest
    {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(Some(PreparedDomPayoutFaceV1 {
        binding,
        payout_commitment,
        payout_value,
        wallet_ownership_digest,
        store_instance_id,
        prepare_digest,
        created_at_unix_ms,
    }))
}

fn payout_face_record_digest(facts: &DomPayoutFaceRecordFactsV1) -> Digest32 {
    let binding = facts.binding;
    let runtime = binding.runtime_identity();
    hash_parts(&[
        PAYOUT_FACE_RECORD_DOMAIN,
        binding.route_id().as_slice(),
        binding.session_id().as_slice(),
        binding.participant().participant_id().as_slice(),
        &[binding.participant().protocol_index()],
        binding.chain_id().as_slice(),
        binding.genesis_hash().as_slice(),
        &[runtime.network as u8],
        &runtime.network_magic.to_be_bytes(),
        &runtime.protocol_version.to_be_bytes(),
        &[runtime.range_proof_serialization_version],
        binding.terms_digest().as_slice(),
        binding.profile_digest().as_slice(),
        binding.deployment_digest().as_slice(),
        binding.asset_binding_digest().as_slice(),
        &binding.registry_epoch().to_be_bytes(),
        &binding.min_confirmations().to_be_bytes(),
        &binding.max_reorg_depth().to_be_bytes(),
        facts.payout_commitment.as_slice(),
        &facts.payout_value.to_be_bytes(),
        facts.wallet_ownership_digest.as_slice(),
        facts.store_instance_id.as_slice(),
        facts.prepare_digest.as_slice(),
        facts.wallet_ciphertext_digest.as_slice(),
        &facts.evidence_revision.to_be_bytes(),
        facts.event_effect_id.as_slice(),
        facts.event_digest.as_slice(),
        &facts.created_at_unix_ms.to_be_bytes(),
    ])
}

fn load_payout_face_evidence(
    transaction: &Transaction<'_>,
    binding: DomSessionBindingV1,
) -> DomActuatorResult<Option<RetainedDomPayoutFaceEvidenceV1>> {
    let row = transaction
        .query_row(
            "SELECT prepare_digest,route_id,participant_id,payout_commitment,payout_value,
                    wallet_ownership_digest,store_instance_id,wallet_ciphertext_digest,
                    evidence_revision,event_effect_id,event_digest,record_digest,created_at_unix_ms
             FROM dom_payout_face_evidence WHERE session_id=?1",
            params![binding.session_id().as_slice()],
            RawDomPayoutFaceEvidenceRowV1::from_row,
        )
        .optional()
        .map_err(storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let prepare_digest = blob32(row.prepare_digest)?;
    let payout_commitment = blob33(row.payout_commitment)?;
    Commitment::from_compressed_bytes(&payout_commitment)
        .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    let payout_value = from_sql(row.payout_value)?;
    let wallet_ownership_digest = blob32(row.wallet_ownership_digest)?;
    let store_instance_id = blob32(row.store_instance_id)?;
    let wallet_ciphertext_digest = blob32(row.wallet_ciphertext_digest)?;
    let evidence_revision = from_sql(row.evidence_revision)?;
    let event_effect_id = blob32(row.event_effect_id)?;
    let event_digest = blob32(row.event_digest)?;
    let record_digest = blob32(row.record_digest)?;
    let created_at_unix_ms = from_sql(row.created_at_unix_ms)?;
    let preparation = load_payout_face_preparation(transaction, binding)?;
    let preparation_matches = preparation.as_ref().is_some_and(|prepared| {
        prepared.payout_commitment == payout_commitment
            && prepared.payout_value == payout_value
            && prepared.wallet_ownership_digest == wallet_ownership_digest
            && prepared.store_instance_id == store_instance_id
            && prepared.prepare_digest == prepare_digest
    });
    let event: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT effect_id,event_digest FROM dom_session_events
             WHERE session_id=?1 AND revision=?2",
            params![binding.session_id().as_slice(), to_sql(evidence_revision)?],
            |event| Ok((event.get(0)?, event.get(1)?)),
        )
        .optional()
        .map_err(storage)?;
    let event_matches = match event {
        Some((effect, digest)) => {
            blob32(effect)? == event_effect_id && blob32(digest)? == event_digest
        }
        None => false,
    };
    if blob32(row.route_id)? != binding.route_id()
        || blob32(row.participant_id)? != binding.participant().participant_id()
        || payout_value == 0
        || wallet_ownership_digest == [0; 32]
        || store_instance_id == [0; 32]
        || prepare_digest == [0; 32]
        || wallet_ciphertext_digest == [0; 32]
        || evidence_revision == 0
        || event_effect_id == [0; 32]
        || event_digest == [0; 32]
        || !preparation_matches
        || !event_matches
        || payout_face_record_digest(&DomPayoutFaceRecordFactsV1 {
            binding,
            payout_commitment,
            payout_value,
            wallet_ownership_digest,
            store_instance_id,
            prepare_digest,
            wallet_ciphertext_digest,
            evidence_revision,
            event_effect_id,
            event_digest,
            created_at_unix_ms,
        }) != record_digest
    {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(Some(RetainedDomPayoutFaceEvidenceV1 {
        binding,
        payout_commitment,
        payout_value,
        wallet_ownership_digest,
        store_instance_id,
        prepare_digest,
        wallet_ciphertext_digest,
        evidence_revision,
        record_digest,
        created_at_unix_ms,
    }))
}

fn load_stage(transaction: &Transaction<'_>, session_id: Digest32) -> DomActuatorResult<i64> {
    transaction
        .query_row(
            "SELECT stage_tag FROM dom_sessions WHERE session_id=?1",
            params![session_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage)
}

fn require_action_stage(stage: i64, action: DomActionV1) -> DomActuatorResult<()> {
    let accepted = match action {
        DomActionV1::ReserveOutputs => stage == STAGE_BOUND,
        DomActionV1::ContributeSharedOutput => stage == STAGE_OUTPUTS_RESERVED,
        DomActionV1::CollaborativeBulletproof => stage == STAGE_SHARED_OUTPUT,
        DomActionV1::PresignRefund => stage == STAGE_BULLETPROOF,
        DomActionV1::PresignClaimAdaptor => matches!(
            stage,
            STAGE_REFUND_PRESIGNED | STAGE_FUNDING_CONFIRMED | STAGE_REORG_RECOVERY
        ),
        DomActionV1::BroadcastFunding => {
            if stage < STAGE_REFUND_PRESIGNED {
                return Err(DomActuatorError::RefundNotArmed);
            }
            matches!(stage, STAGE_REFUND_PRESIGNED | STAGE_CLAIM_PREPARED)
        }
        DomActionV1::BroadcastClaim => {
            matches!(stage, STAGE_FUNDING_CONFIRMED | STAGE_REORG_RECOVERY)
        }
        DomActionV1::BroadcastRefund => matches!(
            stage,
            STAGE_FUNDING_BROADCAST | STAGE_FUNDING_CONFIRMED | STAGE_REORG_RECOVERY
        ),
        DomActionV1::Reconcile => stage >= STAGE_FUNDING_BROADCAST,
        DomActionV1::ReleaseOutputs => {
            matches!(stage, STAGE_CLAIM_FINAL | STAGE_REFUND_FINAL)
        }
    };
    if accepted {
        Ok(())
    } else {
        Err(DomActuatorError::InvalidStage)
    }
}

fn next_stage(stage: i64, action: DomActionV1) -> DomActuatorResult<i64> {
    require_action_stage(stage, action)?;
    Ok(match action {
        DomActionV1::ReserveOutputs => STAGE_OUTPUTS_RESERVED,
        DomActionV1::ContributeSharedOutput => STAGE_SHARED_OUTPUT,
        DomActionV1::CollaborativeBulletproof => STAGE_BULLETPROOF,
        DomActionV1::PresignRefund => STAGE_REFUND_PRESIGNED,
        DomActionV1::PresignClaimAdaptor if stage == STAGE_REFUND_PRESIGNED => STAGE_CLAIM_PREPARED,
        DomActionV1::PresignClaimAdaptor => stage,
        DomActionV1::BroadcastFunding => STAGE_FUNDING_BROADCAST,
        DomActionV1::BroadcastClaim => STAGE_CLAIM_BROADCAST,
        DomActionV1::BroadcastRefund => STAGE_REFUND_BROADCAST,
        DomActionV1::Reconcile => stage,
        DomActionV1::ReleaseOutputs => stage,
    })
}

fn load_operation(
    transaction: &Transaction<'_>,
    effect_id: Digest32,
) -> DomActuatorResult<Option<StoredOperation>> {
    let row = transaction
        .query_row(
            "SELECT scope_digest,evidence_digest,secret_binding_digest,
                 authorization_digest,fencing_epoch,status_tag,receipt_digest
                 FROM dom_operations WHERE effect_id=?1",
            params![effect_id.as_slice()],
            RawOperationRowV1::from_row,
        )
        .optional()
        .map_err(storage)?;
    row.map(|row| {
        Ok(StoredOperation {
            scope_digest: blob32(row.scope_digest)?,
            evidence_digest: blob32(row.evidence_digest)?,
            secret_binding_digest: row.secret_binding_digest.map(blob32).transpose()?,
            authorization_digest: blob32(row.authorization_digest)?,
            fencing_epoch: from_sql(row.fencing_epoch)?,
            status: row.status_tag,
            receipt_digest: row.receipt_digest.map(blob32).transpose()?,
        })
    })
    .transpose()
}

fn validate_capability(
    transaction: &Transaction<'_>,
    lease: DomLeaseV1,
    capability: &DomActuatorCapabilityV1,
) -> DomActuatorResult<()> {
    require_scope(transaction, lease, capability.scope())?;
    require_no_refund_after_claim_exposure(transaction, capability.scope())?;
    if capability.fencing_epoch() != lease.fencing_epoch {
        return Err(DomActuatorError::StaleFence);
    }
    let stored = load_operation(transaction, capability.scope().effect_id())?
        .ok_or(DomActuatorError::CapabilityMismatch)?;
    if stored.scope_digest != scope_digest(capability.scope())
        || stored.authorization_digest != capability.authorization_digest()
        || stored.fencing_epoch != lease.fencing_epoch
    {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    Ok(())
}

fn require_no_refund_after_claim_exposure(
    transaction: &Transaction<'_>,
    scope: ScopedDomActionV1,
) -> DomActuatorResult<()> {
    if scope.action() != DomActionV1::BroadcastRefund {
        return Ok(());
    }
    // "No refund after the marker" is unconditional. A durable V2 attempt latch
    // — or a legacy V1 `send_attempted` latch — means the adapted claim may
    // already be public, and durable economic admission makes it certainly
    // public. Neither state may be spent as evidence that the send failed, so
    // economic admission grants no exemption here: refund after exposure is a
    // route/coordinator policy decision taken under `SecretPublic` knowledge,
    // never an inference made by this control plane.
    // Retained-but-unattempted legacy custody blocks refund for the separate
    // reason that the exact claim is already armed; only `Admitted` was ever
    // exempt and that exemption is exactly what is removed here, so any V2
    // attempt row and any V1 custody row now fail closed alike.
    if load_final_claim_attempt_v2(transaction, scope.binding().session_id())?.is_some()
        || load_claim_custody(transaction, scope.binding().session_id())?.is_some()
    {
        return Err(DomActuatorError::InvalidStage);
    }
    Ok(())
}

fn complete_operation_and_advance(
    transaction: &Transaction<'_>,
    lease: DomLeaseV1,
    scope: ScopedDomActionV1,
    receipt_digest: Digest32,
    now_unix_ms: u64,
) -> DomActuatorResult<()> {
    let stage = load_stage(transaction, scope.binding().session_id())?;
    let next = next_stage(stage, scope.action())?;
    let changed = transaction
        .execute(
            "UPDATE dom_operations SET status_tag=1,receipt_digest=?2,
             updated_at_unix_ms=?3 WHERE effect_id=?1 AND status_tag=0",
            params![
                scope.effect_id().as_slice(),
                receipt_digest.as_slice(),
                to_sql(now_unix_ms)?
            ],
        )
        .map_err(storage)?;
    if changed != 1 {
        return Err(DomActuatorError::RevisionConflict);
    }
    let event_digest = hash_parts(&[
        b"DOM:actuator-completion:v1",
        &scope_digest(scope),
        &receipt_digest,
    ]);
    append_event(
        transaction,
        scope.binding().session_id(),
        scope.effect_id(),
        event_digest,
        next,
        lease.fencing_epoch,
        now_unix_ms,
    )
}

fn event_already_applied(
    transaction: &Transaction<'_>,
    session_id: Digest32,
    effect_id: Digest32,
    event_digest: Digest32,
) -> DomActuatorResult<bool> {
    let existing: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT event_digest FROM dom_session_events
             WHERE session_id=?1 AND effect_id=?2",
            params![session_id.as_slice(), effect_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    match existing {
        None => Ok(false),
        Some(value) => {
            if blob32(value)? == event_digest {
                Ok(true)
            } else {
                Err(DomActuatorError::IdempotencyConflict)
            }
        }
    }
}

fn append_event(
    transaction: &Transaction<'_>,
    session_id: Digest32,
    effect_id: Digest32,
    event_digest: Digest32,
    next_stage: i64,
    fencing_epoch: u64,
    now_unix_ms: u64,
) -> DomActuatorResult<()> {
    let (revision, previous): (i64, Vec<u8>) = transaction
        .query_row(
            "SELECT revision,journal_head FROM dom_sessions WHERE session_id=?1",
            params![session_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(storage)?;
    let revision_u64 = from_sql(revision)?;
    let next_revision = revision_u64
        .checked_add(1)
        .ok_or(DomActuatorError::InvalidBinding)?;
    let previous = blob32(previous)?;
    let entry = hash_parts(&[
        b"DOM:actuator-journal:v1",
        &session_id,
        &next_revision.to_be_bytes(),
        &effect_id,
        &event_digest,
        &previous,
        &fencing_epoch.to_be_bytes(),
    ]);
    transaction
        .execute(
            "INSERT INTO dom_session_events
             (session_id,revision,effect_id,event_digest,previous_head,entry_hash,
              fencing_epoch,created_at_unix_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                session_id.as_slice(),
                to_sql(next_revision)?,
                effect_id.as_slice(),
                event_digest.as_slice(),
                previous.as_slice(),
                entry.as_slice(),
                to_sql(fencing_epoch)?,
                to_sql(now_unix_ms)?
            ],
        )
        .map_err(storage)?;
    let changed = transaction
        .execute(
            "UPDATE dom_sessions SET stage_tag=?2,revision=?3,journal_head=?4,
             updated_at_unix_ms=?5 WHERE session_id=?1 AND revision=?6",
            params![
                session_id.as_slice(),
                next_stage,
                to_sql(next_revision)?,
                entry.as_slice(),
                to_sql(now_unix_ms)?,
                revision
            ],
        )
        .map_err(storage)?;
    if changed != 1 {
        return Err(DomActuatorError::RevisionConflict);
    }
    Ok(())
}

fn load_reservation_items(
    transaction: &Transaction<'_>,
    reservation_digest: Digest32,
) -> DomActuatorResult<Vec<(Vec<u8>, u64)>> {
    let mut statement = transaction
        .prepare(
            "SELECT commitment,value FROM dom_output_reservation_items
             WHERE reservation_digest=?1 ORDER BY commitment ASC",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map(params![reservation_digest.as_slice()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(storage)?;
    let mut result = Vec::new();
    for row in rows {
        let (commitment, value) = row.map_err(storage)?;
        result.push((commitment, from_sql(value)?));
    }
    Ok(result)
}

fn create_schema(connection: &Connection) -> DomActuatorResult<()> {
    create_schema_with_boundary_hook(connection, || Ok(()))
}

fn create_schema_with_boundary_hook<F>(
    connection: &Connection,
    before_commit: F,
) -> DomActuatorResult<()>
where
    F: FnOnce() -> DomActuatorResult<()>,
{
    let mut instance_id = [0_u8; 32];
    getrandom::getrandom(&mut instance_id).map_err(|_| DomActuatorError::StorageUnavailable)?;
    validate_digest(instance_id)?;
    let transaction = connection.unchecked_transaction().map_err(storage)?;
    transaction.execute_batch(SCHEMA_SQL).map_err(storage)?;
    transaction
        .execute(
            "INSERT INTO dom_store_identity(singleton,instance_id) VALUES (1,?1)",
            params![instance_id.as_slice()],
        )
        .map_err(storage)?;
    before_commit()?;
    transaction.commit().map_err(storage)
}

fn load_store_instance_id(connection: &Connection) -> DomActuatorResult<Digest32> {
    let (count, raw): (i64, Vec<u8>) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM dom_store_identity),instance_id
             FROM dom_store_identity WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    let instance_id = blob32(raw)?;
    if count != 1 || instance_id == [0; 32] {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(instance_id)
}

fn preflight_resumable_creation_state(
    path: &Path,
    database_authority: &File,
) -> DomActuatorResult<ResumableCreationStateV1> {
    validate_open_file_identity(database_authority, path)?;
    if database_authority
        .metadata()
        .map_err(|_| DomActuatorError::StorageUnavailable)?
        .len()
        == 0
    {
        return Ok(ResumableCreationStateV1::PristineSqlite);
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    connection
        .pragma_update(None, "query_only", "ON")
        .and_then(|_| connection.pragma_update(None, "trusted_schema", "OFF"))
        .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    if !connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|_| DomActuatorError::UnsupportedFormat)?
        || !connection
            .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
            .map_err(|_| DomActuatorError::UnsupportedFormat)?
    {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    let quick: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    let foreign_key_violations: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    let objects = schema_objects(&connection)?;
    if quick != "ok" || foreign_key_violations != 0 || application_id != 0 {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    if version == 0 {
        return if objects.is_empty() {
            Ok(ResumableCreationStateV1::PristineSqlite)
        } else {
            Err(DomActuatorError::UnsupportedFormat)
        };
    }
    if version != SCHEMA_VERSION || objects != expected_schema_objects()? {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    validate_open_file_identity(database_authority, path)?;
    Ok(ResumableCreationStateV1::InitializedExact)
}

fn validate_pristine_initialized_store(connection: &Connection) -> DomActuatorResult<()> {
    validate_backend_and_schema(connection)?;
    load_store_instance_id(connection)?;
    let economic_rows: i64 = connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM dom_leases) +
                 (SELECT COUNT(*) FROM dom_sessions) +
                 (SELECT COUNT(*) FROM dom_operations) +
                 (SELECT COUNT(*) FROM dom_settlement_children) +
                 (SELECT COUNT(*) FROM dom_settlement_child_port_calls) +
                 (SELECT COUNT(*) FROM dom_claim_custody) +
                 (SELECT COUNT(*) FROM dom_claim_admission) +
                 (SELECT COUNT(*) FROM dom_final_claim_attempt_v2) +
                 (SELECT COUNT(*) FROM dom_final_claim_admission_v2) +
                 (SELECT COUNT(*) FROM dom_terminal_finality) +
                 (SELECT COUNT(*) FROM dom_output_reservations) +
                 (SELECT COUNT(*) FROM dom_output_reservation_items) +
                 (SELECT COUNT(*) FROM dom_payout_face_preparations) +
                 (SELECT COUNT(*) FROM dom_payout_face_evidence) +
                 (SELECT COUNT(*) FROM dom_session_events)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| DomActuatorError::UnsupportedFormat)?;
    if economic_rows != 0 {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(())
}

fn configure_connection(connection: &Connection) -> DomActuatorResult<()> {
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(storage)?;
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(storage)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             PRAGMA temp_store=MEMORY;",
        )
        .map_err(storage)?;
    Ok(())
}

fn validate_backend_and_schema(connection: &Connection) -> DomActuatorResult<()> {
    let journal: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(storage)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(storage)?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(storage)?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(storage)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(storage)?;
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(storage)?;
    let foreign_key_violations: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(storage)?;
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(storage)?;
    if !journal.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || trusted_schema != 0
        || version != SCHEMA_VERSION
        || application_id != 0
        || foreign_key_violations != 0
        || quick_check != "ok"
        || !connection
            .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
            .map_err(storage)?
    {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    let expected = expected_schema_objects()?;
    let actual = schema_objects(connection)?;
    if actual != expected {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(())
}

fn audit_retained_state_in_transaction(transaction: &Transaction<'_>) -> DomActuatorResult<()> {
    audit_core_records(transaction)?;
    audit_claim_admission_records(transaction)?;
    audit_terminal_finality_records(transaction)?;
    audit_output_reservation_records(transaction)?;
    audit_payout_face_preparation_records(transaction)?;
    audit_payout_face_evidence_records(transaction)?;
    audit_settlement_child_records(transaction)
}

struct RetainedSessionAuditRow {
    participant_id: Vec<u8>,
    stage: i64,
    revision: i64,
    journal_head: Vec<u8>,
    created_at: i64,
    updated_at: i64,
}

struct RetainedEventAuditRow {
    revision: i64,
    effect_id: Vec<u8>,
    event_digest: Vec<u8>,
    previous_head: Vec<u8>,
    entry_hash: Vec<u8>,
    fencing_epoch: i64,
    created_at: i64,
}

struct RetainedOperationAuditRow {
    route_id: Vec<u8>,
    session_id: Vec<u8>,
    participant_id: Vec<u8>,
    action_tag: i64,
    fencing_epoch: i64,
    scope_digest: Vec<u8>,
    evidence_digest: Vec<u8>,
    secret_binding_digest: Option<Vec<u8>>,
    authorization_digest: Vec<u8>,
    status: i64,
    receipt_digest: Option<Vec<u8>>,
    reconciliation_digest: Option<Vec<u8>>,
    created_at: i64,
    updated_at: i64,
}

struct RetainedReservationAuditRow {
    effect_id: Vec<u8>,
    route_id: Vec<u8>,
    session_id: Vec<u8>,
    total_value: i64,
    output_count: i64,
    status: i64,
    created_at: i64,
    updated_at: i64,
}

fn audit_core_records(transaction: &Transaction<'_>) -> DomActuatorResult<()> {
    {
        let mut statement = transaction
            .prepare(
                "SELECT participant_id,owner_id,fencing_epoch,lease_until_unix_ms,
                        updated_at_unix_ms FROM dom_leases ORDER BY participant_id",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(storage)?;
        for row in rows {
            let (participant, owner, fence, until, updated) = row.map_err(storage)?;
            validate_digest(blob32(participant)?)
                .and_then(|_| validate_digest(blob32(owner)?))
                .map_err(|_| DomActuatorError::UnsupportedFormat)?;
            let fence = from_sql(fence)?;
            let until = from_sql(until)?;
            let updated = from_sql(updated)?;
            if fence == 0 || updated > until {
                return Err(DomActuatorError::UnsupportedFormat);
            }
        }
    }

    let session_ids = {
        let mut statement = transaction
            .prepare("SELECT session_id FROM dom_sessions ORDER BY session_id")
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(storage)?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(blob32(row.map_err(storage)?)?);
        }
        ids
    };
    for session_id in session_ids {
        let binding =
            load_binding(transaction, session_id)?.ok_or(DomActuatorError::UnsupportedFormat)?;
        binding
            .validate()
            .map_err(|_| DomActuatorError::UnsupportedFormat)?;
        let retained = transaction
            .query_row(
                "SELECT participant_id,stage_tag,revision,journal_head,
                        created_at_unix_ms,updated_at_unix_ms
                 FROM dom_sessions WHERE session_id=?1",
                params![session_id.as_slice()],
                |row| {
                    Ok(RetainedSessionAuditRow {
                        participant_id: row.get(0)?,
                        stage: row.get(1)?,
                        revision: row.get(2)?,
                        journal_head: row.get(3)?,
                        created_at: row.get(4)?,
                        updated_at: row.get(5)?,
                    })
                },
            )
            .map_err(storage)?;
        let participant_id = blob32(retained.participant_id)?;
        let (_, current_fence, _) =
            load_lease(transaction, participant_id)?.ok_or(DomActuatorError::UnsupportedFormat)?;
        let expected_revision = from_sql(retained.revision)?;
        let retained_head = blob32(retained.journal_head)?;
        let created_at = from_sql(retained.created_at)?;
        let updated_at = from_sql(retained.updated_at)?;
        if participant_id != binding.participant().participant_id()
            || !(STAGE_BOUND..=STAGE_REORG_RECOVERY).contains(&retained.stage)
            || created_at > updated_at
        {
            return Err(DomActuatorError::UnsupportedFormat);
        }

        let mut statement = transaction
            .prepare(
                "SELECT revision,effect_id,event_digest,previous_head,entry_hash,
                        fencing_epoch,created_at_unix_ms
                 FROM dom_session_events WHERE session_id=?1 ORDER BY revision",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map(params![session_id.as_slice()], |row| {
                Ok(RetainedEventAuditRow {
                    revision: row.get(0)?,
                    effect_id: row.get(1)?,
                    event_digest: row.get(2)?,
                    previous_head: row.get(3)?,
                    entry_hash: row.get(4)?,
                    fencing_epoch: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })
            .map_err(storage)?;
        let mut sequence = 0_u64;
        let mut head = [0_u8; 32];
        for row in rows {
            let row = row.map_err(storage)?;
            sequence = sequence
                .checked_add(1)
                .ok_or(DomActuatorError::UnsupportedFormat)?;
            let revision = from_sql(row.revision)?;
            let effect_id = blob32(row.effect_id)?;
            let event_digest = blob32(row.event_digest)?;
            let previous_head = blob32(row.previous_head)?;
            let entry_hash = blob32(row.entry_hash)?;
            let event_fence = from_sql(row.fencing_epoch)?;
            let event_created_at = from_sql(row.created_at)?;
            let expected_entry = hash_parts(&[
                b"DOM:actuator-journal:v1",
                &session_id,
                &sequence.to_be_bytes(),
                &effect_id,
                &event_digest,
                &head,
                &event_fence.to_be_bytes(),
            ]);
            if revision != sequence
                || effect_id == [0; 32]
                || event_digest == [0; 32]
                || previous_head != head
                || entry_hash != expected_entry
                || event_fence == 0
                || event_fence > current_fence
                || event_created_at < created_at
                || event_created_at > updated_at
            {
                return Err(DomActuatorError::UnsupportedFormat);
            }
            head = entry_hash;
        }
        if sequence != expected_revision || head != retained_head {
            return Err(DomActuatorError::UnsupportedFormat);
        }
    }

    let effect_ids = {
        let mut statement = transaction
            .prepare("SELECT effect_id FROM dom_operations ORDER BY effect_id")
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(storage)?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(blob32(row.map_err(storage)?)?);
        }
        ids
    };
    for effect_id in effect_ids {
        let retained = transaction
            .query_row(
                "SELECT route_id,session_id,participant_id,action_tag,fencing_epoch,
                        scope_digest,evidence_digest,secret_binding_digest,
                        authorization_digest,status_tag,receipt_digest,reconciliation_digest,
                        created_at_unix_ms,updated_at_unix_ms
                 FROM dom_operations WHERE effect_id=?1",
                params![effect_id.as_slice()],
                |row| {
                    Ok(RetainedOperationAuditRow {
                        route_id: row.get(0)?,
                        session_id: row.get(1)?,
                        participant_id: row.get(2)?,
                        action_tag: row.get(3)?,
                        fencing_epoch: row.get(4)?,
                        scope_digest: row.get(5)?,
                        evidence_digest: row.get(6)?,
                        secret_binding_digest: row.get(7)?,
                        authorization_digest: row.get(8)?,
                        status: row.get(9)?,
                        receipt_digest: row.get(10)?,
                        reconciliation_digest: row.get(11)?,
                        created_at: row.get(12)?,
                        updated_at: row.get(13)?,
                    })
                },
            )
            .map_err(storage)?;
        let session_id = blob32(retained.session_id)?;
        let binding =
            load_binding(transaction, session_id)?.ok_or(DomActuatorError::UnsupportedFormat)?;
        let action = decode_action(retained.action_tag)?;
        let scope = ScopedDomActionV1::new(binding, effect_id, action)
            .map_err(|_| DomActuatorError::UnsupportedFormat)?;
        let fence = from_sql(retained.fencing_epoch)?;
        let (_, current_fence, _) =
            load_lease(transaction, binding.participant().participant_id())?
                .ok_or(DomActuatorError::UnsupportedFormat)?;
        let stored_scope_digest = blob32(retained.scope_digest)?;
        let evidence_digest = blob32(retained.evidence_digest)?;
        let secret_binding_digest = retained.secret_binding_digest.map(blob32).transpose()?;
        let stored_authorization_digest = blob32(retained.authorization_digest)?;
        let receipt_digest = retained.receipt_digest.map(blob32).transpose()?;
        let reconciliation_digest = retained.reconciliation_digest.map(blob32).transpose()?;
        let created_at = from_sql(retained.created_at)?;
        let updated_at = from_sql(retained.updated_at)?;
        let event_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM dom_session_events
                 WHERE session_id=?1 AND effect_id=?2",
                params![session_id.as_slice(), effect_id.as_slice()],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if blob32(retained.route_id)? != binding.route_id()
            || blob32(retained.participant_id)? != binding.participant().participant_id()
            || stored_scope_digest != scope_digest(scope)
            || evidence_digest == [0; 32]
            || action.consumes_unique_secret_binding() != secret_binding_digest.is_some()
            || secret_binding_digest == Some([0; 32])
            || stored_authorization_digest
                != authorization_digest(
                    stored_scope_digest,
                    evidence_digest,
                    secret_binding_digest,
                    fence,
                )
            || fence == 0
            || fence > current_fence
            || reconciliation_digest == Some([0; 32])
            || created_at > updated_at
            || !matches!(retained.status, OP_PREPARED | OP_COMPLETED)
            || (retained.status == OP_PREPARED && (receipt_digest.is_some() || event_count != 0))
            || (retained.status == OP_COMPLETED
                && (receipt_digest.is_none()
                    || receipt_digest == Some([0; 32])
                    || event_count != 1))
        {
            return Err(DomActuatorError::UnsupportedFormat);
        }
    }
    Ok(())
}

fn decode_action(value: i64) -> DomActuatorResult<DomActionV1> {
    match value {
        1 => Ok(DomActionV1::ReserveOutputs),
        2 => Ok(DomActionV1::ContributeSharedOutput),
        3 => Ok(DomActionV1::CollaborativeBulletproof),
        4 => Ok(DomActionV1::PresignRefund),
        5 => Ok(DomActionV1::PresignClaimAdaptor),
        6 => Ok(DomActionV1::BroadcastFunding),
        7 => Ok(DomActionV1::BroadcastClaim),
        8 => Ok(DomActionV1::BroadcastRefund),
        9 => Ok(DomActionV1::Reconcile),
        10 => Ok(DomActionV1::ReleaseOutputs),
        _ => Err(DomActuatorError::UnsupportedFormat),
    }
}

fn audit_terminal_finality_records(transaction: &Transaction<'_>) -> DomActuatorResult<()> {
    let keys = {
        let mut statement = transaction
            .prepare(
                "SELECT session_id,kind_tag FROM dom_terminal_finality
                 ORDER BY session_id,kind_tag",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(storage)?;
        let mut keys = Vec::new();
        for row in rows {
            let (session_id, kind) = row.map_err(storage)?;
            keys.push((blob32(session_id)?, DomTerminalKindV1::decode(kind)?));
        }
        keys
    };
    for (session_id, kind) in keys {
        let binding =
            load_binding(transaction, session_id)?.ok_or(DomActuatorError::UnsupportedFormat)?;
        let retained = load_terminal_finality(transaction, binding, kind)?
            .ok_or(DomActuatorError::UnsupportedFormat)?;
        let (_, current_fence, _) =
            load_lease(transaction, binding.participant().participant_id())?
                .ok_or(DomActuatorError::UnsupportedFormat)?;
        let (created_at, updated_at): (i64, i64) = transaction
            .query_row(
                "SELECT created_at_unix_ms,updated_at_unix_ms
                 FROM dom_terminal_finality WHERE session_id=?1 AND kind_tag=?2",
                params![session_id.as_slice(), kind as u8],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage)?;
        if from_sql(created_at)? > from_sql(updated_at)?
            || retained.fencing_epoch == 0
            || retained.fencing_epoch > current_fence
        {
            return Err(DomActuatorError::UnsupportedFormat);
        }
        match kind {
            DomTerminalKindV1::Claim => {
                require_exposed_claim_identity(transaction, binding, retained.tx_hash)
                    .map_err(|_| DomActuatorError::UnsupportedFormat)?;
            }
            DomTerminalKindV1::Funding | DomTerminalKindV1::Refund => {
                let action_tag = if kind == DomTerminalKindV1::Funding {
                    DomActionV1::BroadcastFunding as u8
                } else {
                    DomActionV1::BroadcastRefund as u8
                };
                let matching_operation: i64 = transaction
                    .query_row(
                        "SELECT COUNT(*) FROM dom_operations
                         WHERE session_id=?1 AND action_tag=?2 AND status_tag=?3
                           AND receipt_digest=?4",
                        params![
                            session_id.as_slice(),
                            action_tag,
                            OP_COMPLETED,
                            retained.tx_hash.as_slice()
                        ],
                        |row| row.get(0),
                    )
                    .map_err(storage)?;
                if matching_operation != 1 {
                    return Err(DomActuatorError::UnsupportedFormat);
                }
            }
        }
        let stage = load_stage(transaction, session_id)?;
        let invalidated_checkpoints: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM dom_terminal_finality
                 WHERE session_id=?1 AND active=0",
                params![session_id.as_slice()],
                |row| row.get(0),
            )
            .map_err(storage)?;
        let stage_is_valid = if stage == STAGE_REORG_RECOVERY {
            invalidated_checkpoints > 0
        } else if retained.active {
            match kind {
                DomTerminalKindV1::Claim => stage == STAGE_CLAIM_FINAL,
                DomTerminalKindV1::Refund => stage == STAGE_REFUND_FINAL,
                DomTerminalKindV1::Funding => matches!(
                    stage,
                    STAGE_FUNDING_CONFIRMED
                        | STAGE_CLAIM_BROADCAST
                        | STAGE_REFUND_BROADCAST
                        | STAGE_CLAIM_FINAL
                        | STAGE_REFUND_FINAL
                ),
            }
        } else {
            false
        };
        if !stage_is_valid {
            return Err(DomActuatorError::UnsupportedFormat);
        }
    }
    let orphaned_reorg_stage: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM dom_sessions AS session
             WHERE session.stage_tag=?1
               AND NOT EXISTS (
                   SELECT 1 FROM dom_terminal_finality AS finality
                   WHERE finality.session_id=session.session_id AND finality.active=0
               )",
            params![STAGE_REORG_RECOVERY],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if orphaned_reorg_stage != 0 {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(())
}

fn audit_output_reservation_records(transaction: &Transaction<'_>) -> DomActuatorResult<()> {
    let reservation_digests = {
        let mut statement = transaction
            .prepare(
                "SELECT reservation_digest FROM dom_output_reservations
                 ORDER BY reservation_digest",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(storage)?;
        let mut values = Vec::new();
        for row in rows {
            values.push(blob32(row.map_err(storage)?)?);
        }
        values
    };
    for reservation_digest in reservation_digests {
        validate_digest(reservation_digest).map_err(|_| DomActuatorError::UnsupportedFormat)?;
        let retained = transaction
            .query_row(
                "SELECT effect_id,route_id,session_id,total_value,output_count,status_tag,
                        created_at_unix_ms,updated_at_unix_ms
                 FROM dom_output_reservations WHERE reservation_digest=?1",
                params![reservation_digest.as_slice()],
                |row| {
                    Ok(RetainedReservationAuditRow {
                        effect_id: row.get(0)?,
                        route_id: row.get(1)?,
                        session_id: row.get(2)?,
                        total_value: row.get(3)?,
                        output_count: row.get(4)?,
                        status: row.get(5)?,
                        created_at: row.get(6)?,
                        updated_at: row.get(7)?,
                    })
                },
            )
            .map_err(storage)?;
        let effect_id = blob32(retained.effect_id)?;
        let session_id = blob32(retained.session_id)?;
        let binding =
            load_binding(transaction, session_id)?.ok_or(DomActuatorError::UnsupportedFormat)?;
        let operation =
            load_operation(transaction, effect_id)?.ok_or(DomActuatorError::UnsupportedFormat)?;
        let reserve_scope = ScopedDomActionV1::new(binding, effect_id, DomActionV1::ReserveOutputs)
            .map_err(|_| DomActuatorError::UnsupportedFormat)?;
        let items = load_reservation_items(transaction, reservation_digest)?;
        let total = items.iter().try_fold(0_u64, |sum, (_, value)| {
            sum.checked_add(*value)
                .ok_or(DomActuatorError::UnsupportedFormat)
        })?;
        let active_items: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM dom_output_reservation_items
                 WHERE reservation_digest=?1 AND active=1",
                params![reservation_digest.as_slice()],
                |row| row.get(0),
            )
            .map_err(storage)?;
        let expected_items =
            i64::try_from(items.len()).map_err(|_| DomActuatorError::UnsupportedFormat)?;
        let expected_operation_status = match retained.status {
            RESERVATION_PREPARED => OP_PREPARED,
            RESERVATION_ACTIVE | RESERVATION_RELEASED => OP_COMPLETED,
            _ => return Err(DomActuatorError::UnsupportedFormat),
        };
        let expected_active_items = if retained.status == RESERVATION_RELEASED {
            0
        } else {
            expected_items
        };
        if blob32(retained.route_id)? != binding.route_id()
            || operation.scope_digest != scope_digest(reserve_scope)
            || operation.status != expected_operation_status
            || from_sql(retained.total_value)? != total
            || retained.output_count != expected_items
            || active_items != expected_active_items
            || expected_items == 0
            || expected_items > 4_096
            || from_sql(retained.created_at)? > from_sql(retained.updated_at)?
        {
            return Err(DomActuatorError::UnsupportedFormat);
        }
    }
    Ok(())
}

fn audit_payout_face_evidence_records(transaction: &Transaction<'_>) -> DomActuatorResult<()> {
    let mut statement = transaction
        .prepare("SELECT session_id FROM dom_payout_face_evidence ORDER BY session_id")
        .map_err(storage)?;
    let rows = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(storage)?;
    let mut session_ids = Vec::new();
    for row in rows {
        session_ids.push(blob32(row.map_err(storage)?)?);
    }
    drop(statement);
    for session_id in session_ids {
        let binding =
            load_binding(transaction, session_id)?.ok_or(DomActuatorError::UnsupportedFormat)?;
        if load_payout_face_evidence(transaction, binding)?.is_none() {
            return Err(DomActuatorError::UnsupportedFormat);
        }
    }
    Ok(())
}

fn audit_payout_face_preparation_records(transaction: &Transaction<'_>) -> DomActuatorResult<()> {
    let store_instance_id = load_store_instance_id(transaction)?;
    let mut statement = transaction
        .prepare("SELECT session_id FROM dom_payout_face_preparations ORDER BY session_id")
        .map_err(storage)?;
    let rows = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(storage)?;
    let mut session_ids = Vec::new();
    for row in rows {
        session_ids.push(blob32(row.map_err(storage)?)?);
    }
    drop(statement);
    for session_id in session_ids {
        let binding =
            load_binding(transaction, session_id)?.ok_or(DomActuatorError::UnsupportedFormat)?;
        let prepared = load_payout_face_preparation(transaction, binding)?
            .ok_or(DomActuatorError::UnsupportedFormat)?;
        if prepared.store_instance_id != store_instance_id {
            return Err(DomActuatorError::UnsupportedFormat);
        }
    }
    Ok(())
}

fn audit_claim_admission_records(transaction: &Transaction<'_>) -> DomActuatorResult<()> {
    let session_ids = {
        let mut statement = transaction
            .prepare("SELECT session_id FROM dom_claim_custody ORDER BY session_id ASC")
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(storage)?;
        let mut session_ids = Vec::new();
        for row in rows {
            session_ids.push(blob32(row.map_err(storage)?)?);
        }
        session_ids
    };
    for session_id in session_ids {
        let claim = load_claim_custody(transaction, session_id)?
            .ok_or(DomActuatorError::UnsupportedFormat)?;
        validate_claim_custody_operation(transaction, &claim)?;
        if let Some(admission) = load_claim_admission(transaction, session_id)? {
            validate_claim_admission_scope(&admission, &claim)
                .map_err(|_| DomActuatorError::UnsupportedFormat)?;
        }
    }
    let v2_session_ids = {
        let mut statement = transaction
            .prepare("SELECT session_id FROM dom_final_claim_attempt_v2 ORDER BY session_id ASC")
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(storage)?;
        let mut session_ids = Vec::new();
        for row in rows {
            session_ids.push(blob32(row.map_err(storage)?)?);
        }
        session_ids
    };
    for session_id in v2_session_ids {
        let attempt = load_final_claim_attempt_v2(transaction, session_id)?
            .ok_or(DomActuatorError::UnsupportedFormat)?;
        validate_final_claim_attempt_operation_v2(transaction, &attempt)?;
        if let Some(admission) = load_final_claim_admission_v2(transaction, session_id)? {
            validate_final_claim_admission_scope_v2(&admission, &attempt)?;
        }
    }
    let mixed_generations: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM dom_claim_custody AS legacy
             JOIN dom_final_claim_attempt_v2 AS current
               ON current.session_id=legacy.session_id",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if mixed_generations != 0 {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(())
}

fn audit_settlement_child_records(transaction: &Transaction<'_>) -> DomActuatorResult<()> {
    let custody_digests = {
        let mut statement = transaction
            .prepare(
                "SELECT custody_digest FROM dom_settlement_children
                 ORDER BY custody_digest ASC",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(storage)?;
        let mut values = Vec::new();
        for row in rows {
            values.push(blob32(row.map_err(storage)?)?);
        }
        values
    };
    for custody_digest in custody_digests {
        let stored = load_settlement_child_binding(transaction, custody_digest)?
            .ok_or(DomActuatorError::UnsupportedFormat)?;
        let view = validate_settlement_child_binding(transaction, stored)?;
        let (_, current_fencing_epoch, _) = load_lease(
            transaction,
            view.request()
                .scope()
                .binding()
                .participant()
                .participant_id(),
        )?
        .ok_or(DomActuatorError::UnsupportedFormat)?;
        if view.operation_fencing_epoch() > current_fencing_epoch {
            return Err(DomActuatorError::UnsupportedFormat);
        }
    }
    let attempt_ids = {
        let mut statement = transaction
            .prepare(
                "SELECT coordinator_attempt_id FROM dom_settlement_child_port_calls
                 ORDER BY coordinator_attempt_id ASC",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(storage)?;
        let mut values = Vec::new();
        for row in rows {
            values.push(blob32(row.map_err(storage)?)?);
        }
        values
    };
    for attempt_id in attempt_ids {
        let stored = load_settlement_child_port_call(transaction, attempt_id)?
            .ok_or(DomActuatorError::UnsupportedFormat)?;
        validate_settlement_child_port_call_key(stored.key)
            .map_err(|_| DomActuatorError::UnsupportedFormat)?;
        let child =
            load_settlement_child_binding(transaction, stored.key.locator().custody_digest())?
                .ok_or(DomActuatorError::UnsupportedFormat)?;
        let binding = validate_settlement_child_binding(transaction, child)?;
        let (_, current_fencing_epoch, _) = load_lease(
            transaction,
            binding
                .request()
                .scope()
                .binding()
                .participant()
                .participant_id(),
        )?
        .ok_or(DomActuatorError::UnsupportedFormat)?;
        if binding.locator() != stored.key.locator()
            || stored.actuator_fencing_epoch == 0
            || stored.actuator_fencing_epoch > current_fencing_epoch
        {
            return Err(DomActuatorError::UnsupportedFormat);
        }
        let status = settlement_child_port_call_status(&stored)?;
        if let DomSettlementChildPortCallJournalStatusV1::Committed(outcome) = status {
            validate_settlement_child_port_call_outcome(&binding, stored.key.call_kind(), outcome)
                .map_err(|_| DomActuatorError::UnsupportedFormat)?;
        }
    }
    Ok(())
}

fn expected_schema_objects() -> DomActuatorResult<BTreeMap<(String, String), String>> {
    let connection = Connection::open_in_memory().map_err(storage)?;
    connection.execute_batch(SCHEMA_SQL).map_err(storage)?;
    schema_objects(&connection)
}

fn schema_objects(
    connection: &Connection,
) -> DomActuatorResult<BTreeMap<(String, String), String>> {
    const MAX_SCHEMA_OBJECTS: i64 = 32;
    const MAX_SCHEMA_SQL_BYTES: i64 = 262_144;
    let (count, maximum, total): (i64, Option<i64>, Option<i64>) = connection
        .query_row(
            "SELECT COUNT(*),MAX(length(sql)),SUM(length(sql)) FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(storage)?;
    if !(0..=MAX_SCHEMA_OBJECTS).contains(&count)
        || maximum.is_some_and(|value| !(0..=MAX_SCHEMA_SQL_BYTES).contains(&value))
        || total.is_some_and(|value| !(0..=MAX_SCHEMA_SQL_BYTES).contains(&value))
    {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    let mut statement = connection
        .prepare(
            "SELECT type,name,sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(storage)?;
    let mut objects = BTreeMap::new();
    for row in rows {
        let (kind, name, sql) = row.map_err(storage)?;
        let sql = sql.ok_or(DomActuatorError::UnsupportedFormat)?;
        if objects.insert((kind, name), sql).is_some() {
            return Err(DomActuatorError::UnsupportedFormat);
        }
    }
    if i64::try_from(objects.len()).map_err(|_| DomActuatorError::UnsupportedFormat)? != count {
        return Err(DomActuatorError::UnsupportedFormat);
    }
    Ok(objects)
}

fn validate_database_path(connection: &Connection, expected: &Path) -> DomActuatorResult<()> {
    let canonical =
        fs::canonicalize(expected).map_err(|_| DomActuatorError::InvalidStorageAuthority)?;
    if canonical != expected {
        return Err(DomActuatorError::InvalidStorageAuthority);
    }
    let mut statement = connection
        .prepare("PRAGMA database_list")
        .map_err(storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })
        .map_err(storage)?;
    let mut saw_main = false;
    for row in rows {
        let (name, path) = row.map_err(storage)?;
        match name.as_str() {
            "main" if Path::new(&path) == canonical => saw_main = true,
            "temp" if path.is_empty() => {}
            _ => return Err(DomActuatorError::InvalidStorageAuthority),
        }
    }
    if saw_main {
        Ok(())
    } else {
        Err(DomActuatorError::InvalidStorageAuthority)
    }
}

fn require_linux() -> DomActuatorResult<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(DomActuatorError::LinuxRequired)
    }
}

fn lock_path(database: &Path) -> PathBuf {
    let mut value = database.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn sidecar_path(database: &Path, suffix: &str) -> PathBuf {
    let mut value = database.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn require_create_path_absent(path: &Path) -> DomActuatorResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(DomActuatorError::DatabasePresent),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(DomActuatorError::StorageUnavailable),
    }
}

fn acquire_process_lock(database: &Path, create: bool) -> DomActuatorResult<File> {
    let path = lock_path(database);
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create {
        options.create_new(true);
    }
    #[cfg(target_os = "linux")]
    options.mode(FILE_MODE);
    let file = options
        .open(&path)
        .map_err(|_| DomActuatorError::InvalidStorageAuthority)?;
    validate_open_file_identity(&file, &path)?;
    if file
        .metadata()
        .map_err(|_| DomActuatorError::StorageUnavailable)?
        .len()
        != 0
    {
        return Err(DomActuatorError::InvalidStorageAuthority);
    }
    #[cfg(target_os = "linux")]
    {
        flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| DomActuatorError::ProcessLocked)?;
    }
    validate_open_file_identity(&file, &path)?;
    if create {
        file.sync_all()
            .map_err(|_| DomActuatorError::StorageUnavailable)?;
        sync_directory(
            database
                .parent()
                .ok_or(DomActuatorError::InvalidStorageAuthority)?,
        )?;
    }
    Ok(file)
}

fn create_database_authority(path: &Path) -> DomActuatorResult<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(target_os = "linux")]
    options.mode(FILE_MODE);
    let file = options
        .open(path)
        .map_err(|_| DomActuatorError::StorageUnavailable)?;
    validate_open_file_identity(&file, path)?;
    file.sync_all()
        .map_err(|_| DomActuatorError::StorageUnavailable)?;
    sync_directory(
        path.parent()
            .ok_or(DomActuatorError::InvalidStorageAuthority)?,
    )?;
    Ok(file)
}

fn open_database_authority(path: &Path) -> DomActuatorResult<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| DomActuatorError::StorageUnavailable)?;
    validate_open_file_identity(&file, path)?;
    Ok(file)
}

fn validate_owner_directory(path: &Path) -> DomActuatorResult<()> {
    #[cfg(target_os = "linux")]
    {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| DomActuatorError::InvalidStorageAuthority)?;
        let canonical =
            fs::canonicalize(path).map_err(|_| DomActuatorError::InvalidStorageAuthority)?;
        if canonical != path
            || !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o7777 != DIRECTORY_MODE
            || metadata.nlink() == 0
        {
            return Err(DomActuatorError::InvalidStorageAuthority);
        }
    }
    Ok(())
}

fn validate_owner_file(path: &Path) -> DomActuatorResult<()> {
    #[cfg(target_os = "linux")]
    {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| DomActuatorError::InvalidStorageAuthority)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o7777 != FILE_MODE
            || metadata.nlink() != 1
        {
            return Err(DomActuatorError::InvalidStorageAuthority);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_open_file_identity(file: &File, path: &Path) -> DomActuatorResult<()> {
    validate_owner_file(path)?;
    let retained = file
        .metadata()
        .map_err(|_| DomActuatorError::StorageUnavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| DomActuatorError::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(DomActuatorError::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_open_file_identity(_file: &File, _path: &Path) -> DomActuatorResult<()> {
    Err(DomActuatorError::LinuxRequired)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SqliteSidecarKindV1 {
    Wal,
    SharedMemory,
    RollbackJournal,
}

fn validate_resumable_sidecars(path: &Path) -> DomActuatorResult<()> {
    #[cfg(target_os = "linux")]
    for (suffix, kind) in [
        ("-wal", SqliteSidecarKindV1::Wal),
        ("-shm", SqliteSidecarKindV1::SharedMemory),
        ("-journal", SqliteSidecarKindV1::RollbackJournal),
    ] {
        let sidecar = sidecar_path(path, suffix);
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => validate_sqlite_sidecar_shape(&sidecar, kind)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(DomActuatorError::StorageUnavailable),
        }
    }
    #[cfg(not(target_os = "linux"))]
    return Err(DomActuatorError::LinuxRequired);
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_sqlite_sidecar_shape(path: &Path, kind: SqliteSidecarKindV1) -> DomActuatorResult<()> {
    validate_owner_file(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| DomActuatorError::StorageUnavailable)?;
    let retained = file
        .metadata()
        .map_err(|_| DomActuatorError::StorageUnavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| DomActuatorError::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(DomActuatorError::InvalidStorageAuthority);
    }
    if retained.len() == 0 {
        return Ok(());
    }
    let mut header = [0u8; 8];
    file.read_exact(&mut header)
        .map_err(|_| DomActuatorError::InvalidStorageAuthority)?;
    let valid = match kind {
        SqliteSidecarKindV1::Wal => {
            retained.len() >= 32
                && matches!(
                    u32::from_be_bytes(
                        header[..4]
                            .try_into()
                            .map_err(|_| DomActuatorError::InvalidStorageAuthority)?
                    ),
                    0x377f_0682 | 0x377f_0683
                )
        }
        SqliteSidecarKindV1::SharedMemory => {
            retained.len() >= 32_768
                && retained.len() % 32_768 == 0
                && u32::from_ne_bytes(
                    header[..4]
                        .try_into()
                        .map_err(|_| DomActuatorError::InvalidStorageAuthority)?,
                ) == 3_007_000
        }
        SqliteSidecarKindV1::RollbackJournal => {
            retained.len() >= 28 && header == [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]
        }
    };
    if !valid {
        return Err(DomActuatorError::InvalidStorageAuthority);
    }
    Ok(())
}

fn require_sidecars_absent(path: &Path) -> DomActuatorResult<()> {
    for suffix in ["-wal", "-shm", "-journal", ".lock"] {
        match fs::symlink_metadata(sidecar_path(path, suffix)) {
            Ok(_) => return Err(DomActuatorError::InvalidStorageAuthority),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(DomActuatorError::StorageUnavailable),
        }
    }
    Ok(())
}

fn require_sqlite_sidecars_absent(path: &Path) -> DomActuatorResult<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        match fs::symlink_metadata(sidecar_path(path, suffix)) {
            Ok(_) => return Err(DomActuatorError::InvalidStorageAuthority),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(DomActuatorError::StorageUnavailable),
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> DomActuatorResult<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| DomActuatorError::StorageUnavailable)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{DomParticipantV1, WalletReservationRequestV1};
    use dom_crypto::pedersen::BlindingFactor;
    use static_assertions::assert_not_impl_any;
    use std::error::Error;
    use std::process::{Command, Stdio};

    const CREATION_FAULT_PATH_ENV: &str = "DOM_ACTUATOR_TEST_CREATION_FAULT_PATH";
    const CREATION_FAULT_BOUNDARY_ENV: &str = "DOM_ACTUATOR_TEST_CREATION_FAULT_BOUNDARY";
    const LOCK_PROBE_PATH_ENV: &str = "DOM_ACTUATOR_TEST_LOCK_PROBE_PATH";
    const CREATION_CRASH_EXIT: i32 = 91;

    pub(crate) type TestResult<T = ()> = core::result::Result<T, Box<dyn Error>>;

    pub(crate) trait TestContext<T> {
        fn test_context(self, context: &'static str) -> TestResult<T>;
    }

    impl<T, E> TestContext<T> for core::result::Result<T, E>
    where
        E: core::fmt::Display,
    {
        fn test_context(self, context: &'static str) -> TestResult<T> {
            self.map_err(|error| std::io::Error::other(format!("{context}: {error}")).into())
        }
    }

    impl<T> TestContext<T> for Option<T> {
        fn test_context(self, context: &'static str) -> TestResult<T> {
            self.ok_or_else(|| std::io::Error::other(context).into())
        }
    }

    fn require_dom_error<T>(
        result: DomActuatorResult<T>,
        expected: DomActuatorError,
    ) -> TestResult {
        match result {
            Err(actual) if actual == expected => Ok(()),
            Err(actual) => Err(std::io::Error::other(format!(
                "expected DOM actuator error {expected}, got {actual}"
            ))
            .into()),
            Ok(_) => Err(std::io::Error::other(format!(
                "expected DOM actuator error {expected}, got success"
            ))
            .into()),
        }
    }

    assert_not_impl_any!(DomClaimBroadcastV1: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(DomClaimAdmissionV1: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(PendingClaimAdmissionV1: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(DomClaimCustodyAuditV1:
        core::ops::Deref,
        AsRef<[u8]>,
        AsRef<DomClaimAdmissionV1>,
        AsRef<DomClaimBroadcastV1>,
        Into<DomClaimAdmissionV1>,
        Into<DomClaimBroadcastV1>
    );
    assert_not_impl_any!(DomFinalClaimAdmissionV2: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(DomFinalClaimAdmissionV2:
        core::ops::Deref,
        AsRef<[u8]>,
        Into<Vec<u8>>,
        AsRef<DomClaimBroadcastV1>,
        Into<DomClaimBroadcastV1>
    );
    assert_not_impl_any!(DomFinalClaimCustodyAuditV2:
        core::ops::Deref,
        AsRef<[u8]>,
        Into<Vec<u8>>,
        AsRef<DomFinalClaimAdmissionV2>,
        Into<DomFinalClaimAdmissionV2>,
        AsRef<DomClaimBroadcastV1>,
        Into<DomClaimBroadcastV1>
    );
    assert_not_impl_any!(LatchedFinalClaimSubmissionV2: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(LatchedFinalClaimSubmissionV2:
        core::ops::Deref,
        AsRef<[u8]>,
        Into<Vec<u8>>,
        AsRef<DomFinalClaimAdmissionV2>,
        Into<DomFinalClaimAdmissionV2>
    );
    assert_not_impl_any!(FinalClaimAttemptFactsV2: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(FinalClaimTransportAuthorityFactsV2: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(PreparedDomPayoutFaceV1: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(DomSettlementChildBindingV1:
        Clone,
        Copy,
        AsRef<[u8]>,
        Into<Vec<u8>>
    );

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct ClaimStateSnapshot {
        session_stage: i64,
        session_revision: i64,
        journal_head: Vec<u8>,
        session_updated_at: i64,
        operation_fence: i64,
        operation_authorization: Vec<u8>,
        operation_reconciliation: Option<Vec<u8>>,
        operation_updated_at: i64,
        custody_fence: i64,
        custody_authorization: Vec<u8>,
        custody_record: Vec<u8>,
        send_attempted: i64,
        send_attempt_count: i64,
        custody_updated_at: i64,
        admission_count: i64,
        operation_count: i64,
        event_count: i64,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct PreparedClaimStateSnapshot {
        lease_owner: Vec<u8>,
        lease_fence: i64,
        lease_until: i64,
        lease_updated_at: i64,
        session_stage: i64,
        session_revision: i64,
        journal_head: Vec<u8>,
        session_updated_at: i64,
        operation_fence: i64,
        operation_authorization: Vec<u8>,
        operation_reconciliation: Option<Vec<u8>>,
        operation_status: i64,
        operation_receipt: Option<Vec<u8>>,
        operation_updated_at: i64,
    }

    pub(crate) fn digest(tag: u8) -> Digest32 {
        [tag; 32]
    }

    fn payout_commitment(tag: u8) -> TestResult<[u8; 33]> {
        let blinding = BlindingFactor::from_bytes([tag; 32]).test_context("payout blinding")?;
        Ok(*Commitment::commit(50, &blinding).as_bytes())
    }

    fn activate_payout_face_for_test(
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        commitment: [u8; 33],
        ownership_digest: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<RetainedDomPayoutFaceEvidenceV1> {
        let prepared = store.prepare_payout_face(
            lease,
            binding,
            commitment,
            50,
            ownership_digest,
            now_unix_ms,
        )?;
        store.activate_payout_face(lease, &prepared, digest(70), now_unix_ms + 1)
    }

    pub(crate) fn binding(route: u8, session: u8) -> TestResult<DomSessionBindingV1> {
        let runtime_identity = DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest);
        let genesis_hash =
            *dom_core::startup_genesis_hash_for_network_magic(runtime_identity.network_magic)
                .test_context("supported regtest startup identity")?
                .as_bytes();
        let chain_id = *dom_consensus::derive_chain_id(
            runtime_identity.network_magic,
            &dom_crypto::Hash256::from_bytes(genesis_hash),
        )
        .as_bytes();
        DomSessionBindingV1::from_parts_for_store(StoredDomSessionBindingPartsV1 {
            route_id: digest(route),
            session_id: digest(session),
            participant: DomParticipantV1::new(digest(9), 0).test_context("participant")?,
            chain_id,
            genesis_hash,
            runtime_identity,
            terms_digest: digest(12),
            profile_digest: digest(13),
            deployment_digest: digest(14),
            asset_binding_digest: digest(15),
            registry_epoch: 1,
            min_confirmations: 2,
            max_reorg_depth: 10,
        })
        .test_context("binding")
    }

    pub(crate) fn setup() -> TestResult<(tempfile::TempDir, PathBuf, DomActuatorStoreV1, DomLeaseV1)>
    {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().test_context("tempdir")?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(DIRECTORY_MODE))
            .test_context("owner-only tempdir")?;
        let path = directory.path().join("dom-actuator.sqlite");
        let mut store = DomActuatorStoreV1::create(&path).test_context("create")?;
        let lease = store
            .acquire_lease(digest(9), digest(20), 1_000, 10_000)
            .test_context("lease")?;
        Ok((directory, path, store, lease))
    }

    fn empty_store_path() -> TestResult<(tempfile::TempDir, PathBuf)> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(DIRECTORY_MODE))?;
        let canonical = fs::canonicalize(directory.path())?;
        Ok((directory, canonical.join("dom-actuator.sqlite")))
    }

    fn creation_boundary_name(boundary: CreationBoundaryV1) -> &'static str {
        match boundary {
            CreationBoundaryV1::ProcessLockPublished => "process-lock-published",
            CreationBoundaryV1::DatabaseFileSynced => "database-file-synced",
            CreationBoundaryV1::BeforeSchemaTransaction => "before-schema-transaction",
            CreationBoundaryV1::BeforeSchemaCommit => "before-schema-commit",
            CreationBoundaryV1::SchemaCommitted => "schema-committed",
        }
    }

    fn parse_creation_boundary(
        value: &str,
    ) -> core::result::Result<CreationBoundaryV1, std::io::Error> {
        match value {
            "process-lock-published" => Ok(CreationBoundaryV1::ProcessLockPublished),
            "database-file-synced" => Ok(CreationBoundaryV1::DatabaseFileSynced),
            "before-schema-transaction" => Ok(CreationBoundaryV1::BeforeSchemaTransaction),
            "before-schema-commit" => Ok(CreationBoundaryV1::BeforeSchemaCommit),
            "schema-committed" => Ok(CreationBoundaryV1::SchemaCommitted),
            _ => Err(std::io::Error::other(
                "unknown DOM actuator creation boundary",
            )),
        }
    }

    fn stage_process_creation_crash(path: &Path, boundary: CreationBoundaryV1) -> TestResult {
        let status = Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("store::tests::creation_fault_process_child")
            .arg("--nocapture")
            .env(CREATION_FAULT_PATH_ENV, path)
            .env(
                CREATION_FAULT_BOUNDARY_ENV,
                creation_boundary_name(boundary),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.code() != Some(CREATION_CRASH_EXIT) {
            return Err(std::io::Error::other(
                "DOM actuator creation child missed requested crash boundary",
            )
            .into());
        }
        Ok(())
    }

    fn stage_creation_fault(path: &Path, boundary: CreationBoundaryV1) -> DomActuatorResult<()> {
        DomActuatorStoreV1::create_with_boundary_hook(path, |reached| {
            if reached == boundary {
                Err(DomActuatorError::StorageUnavailable)
            } else {
                Ok(())
            }
        })
        .map(drop)
    }

    fn scope(
        binding: DomSessionBindingV1,
        effect: u8,
        action: DomActionV1,
    ) -> TestResult<ScopedDomActionV1> {
        ScopedDomActionV1::new(binding, digest(effect), action).test_context("scope")
    }

    fn reserve_stage(
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        effect: u8,
        commitment: u8,
    ) -> TestResult {
        let reserve = scope(binding, effect, DomActionV1::ReserveOutputs)?;
        let (capability, _) = store
            .authorize_action(lease, reserve, digest(effect + 40), None, 1_001)
            .test_context("authorize reserve")?;
        let request = WalletReservationRequestV1::new(10).test_context("request")?;
        let reservation = hash_parts(&[
            b"test-reservation",
            &binding.session_id(),
            &request.required_value().to_be_bytes(),
        ]);
        store
            .prepare_output_reservation(
                lease,
                &capability,
                reservation,
                &[(vec![commitment; 33], 10)],
                1_002,
            )
            .test_context("prepare reservation")?;
        store
            .activate_output_reservation(lease, capability, reservation, digest(90), 1_003)
            .test_context("activate reservation")?;
        Ok(())
    }

    fn complete_stage(
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        effect: u8,
        action: DomActionV1,
    ) -> TestResult {
        let unique = action
            .consumes_unique_secret_binding()
            .then(|| digest(effect + 100));
        let (capability, _) = store
            .authorize_action(
                lease,
                scope(binding, effect, action)?,
                digest(effect + 50),
                unique,
                1_100 + u64::from(effect),
            )
            .test_context("authorize stage")?;
        store
            .complete_action(
                lease,
                capability,
                digest(effect + 70),
                1_200 + u64::from(effect),
            )
            .test_context("complete stage")?;
        Ok(())
    }

    fn advance_to_funding_broadcast(
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
    ) -> TestResult {
        advance_to_funding_broadcast_from(store, lease, binding, 21, 1)
    }

    fn advance_to_funding_broadcast_from(
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        first_effect: u8,
        unique: u8,
    ) -> TestResult {
        reserve_stage(store, lease, binding, first_effect, unique)?;
        complete_stage(
            store,
            lease,
            binding,
            first_effect + 1,
            DomActionV1::ContributeSharedOutput,
        )?;
        complete_stage(
            store,
            lease,
            binding,
            first_effect + 2,
            DomActionV1::CollaborativeBulletproof,
        )?;
        complete_stage(
            store,
            lease,
            binding,
            first_effect + 3,
            DomActionV1::PresignRefund,
        )?;
        complete_stage(
            store,
            lease,
            binding,
            first_effect + 4,
            DomActionV1::PresignClaimAdaptor,
        )?;
        complete_stage(
            store,
            lease,
            binding,
            first_effect + 5,
            DomActionV1::BroadcastFunding,
        )?;
        Ok(())
    }

    pub(crate) fn advance_to_funding_confirmed(
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
    ) -> TestResult {
        advance_to_funding_broadcast(store, lease, binding)?;
        store
            .record_chain_observation(
                lease,
                binding,
                digest(120),
                DomChainObservationV1::FundingConfirmed,
                digest(121),
                1_500,
            )
            .test_context("funding finality")?;
        Ok(())
    }

    pub(crate) fn seed_exact_claim_custody(
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
    ) -> TestResult<(ScopedDomActionV1, Digest32, Digest32, DomClaimBroadcastV1)> {
        let claim_scope = scope(binding, 27, DomActionV1::BroadcastClaim)?;
        let evidence = digest(122);
        let (capability, _) = store
            .authorize_action(lease, claim_scope, evidence, None, 1_510)
            .test_context("authorize claim")?;
        let authorization = capability.authorization_digest();
        // Canonical encoding of an empty transaction (three zero-length lists
        // and a zero offset). This bypass exists only in this lower-layer store
        // test; production receives bytes solely through VerifiedClaimTransactionV1.
        let exact_bytes = Zeroizing::new(vec![0_u8; 44]);
        let tx_hash =
            canonical_transaction_hash_v1(&exact_bytes).test_context("canonical fixture")?;
        let template_hash = digest(123);
        let shared_output = [0x24; 33];
        let record_digest = claim_custody_record_digest(
            claim_scope,
            lease.fencing_epoch,
            authorization,
            tx_hash,
            template_hash,
            shared_output,
            ClaimSendStateV1::UNSENT,
        );
        let transaction = store.immediate().test_context("transaction")?;
        validate_capability(&transaction, lease, &capability).test_context("capability")?;
        transaction
            .execute(
                "INSERT INTO dom_claim_custody
                 (session_id,effect_id,route_id,participant_id,fencing_epoch,
                  authorization_digest,tx_hash,template_hash,shared_output_commitment,
                  exact_bytes,exact_bytes_digest,record_digest,send_attempted,
                  send_attempt_count,created_at_unix_ms,updated_at_unix_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?7,?11,0,0,1511,1511)",
                params![
                    binding.session_id().as_slice(),
                    claim_scope.effect_id().as_slice(),
                    binding.route_id().as_slice(),
                    binding.participant().participant_id().as_slice(),
                    to_sql(lease.fencing_epoch).test_context("fence")?,
                    authorization.as_slice(),
                    tx_hash.as_slice(),
                    template_hash.as_slice(),
                    shared_output.as_slice(),
                    exact_bytes.as_slice(),
                    record_digest.as_slice(),
                ],
            )
            .test_context("claim custody")?;
        complete_operation_and_advance(&transaction, lease, claim_scope, tx_hash, 1_511)
            .test_context("complete custody")?;
        transaction.commit().test_context("commit custody")?;
        let broadcast = DomClaimBroadcastV1 {
            session_id: binding.session_id(),
            effect_id: claim_scope.effect_id(),
            fencing_epoch: lease.fencing_epoch,
            tx_hash,
            exact_bytes,
        };
        Ok((claim_scope, evidence, authorization, broadcast))
    }

    pub(crate) fn claim_state_snapshot(
        store: &DomActuatorStoreV1,
        binding: DomSessionBindingV1,
    ) -> TestResult<ClaimStateSnapshot> {
        store
            .connection
            .query_row(
                "SELECT s.stage_tag,s.revision,s.journal_head,s.updated_at_unix_ms,
                        o.fencing_epoch,o.authorization_digest,o.reconciliation_digest,
                        o.updated_at_unix_ms,c.fencing_epoch,c.authorization_digest,
                        c.record_digest,c.send_attempted,c.send_attempt_count,
                        c.updated_at_unix_ms,
                        (SELECT COUNT(*) FROM dom_claim_admission a
                         WHERE a.session_id=s.session_id),
                        (SELECT COUNT(*) FROM dom_operations all_operations
                         WHERE all_operations.session_id=s.session_id),
                        (SELECT COUNT(*) FROM dom_session_events e
                         WHERE e.session_id=s.session_id)
                 FROM dom_sessions s
                 JOIN dom_operations o ON o.session_id=s.session_id AND o.action_tag=7
                 JOIN dom_claim_custody c ON c.session_id=s.session_id
                 WHERE s.session_id=?1",
                params![binding.session_id().as_slice()],
                |row| {
                    Ok(ClaimStateSnapshot {
                        session_stage: row.get(0)?,
                        session_revision: row.get(1)?,
                        journal_head: row.get(2)?,
                        session_updated_at: row.get(3)?,
                        operation_fence: row.get(4)?,
                        operation_authorization: row.get(5)?,
                        operation_reconciliation: row.get(6)?,
                        operation_updated_at: row.get(7)?,
                        custody_fence: row.get(8)?,
                        custody_authorization: row.get(9)?,
                        custody_record: row.get(10)?,
                        send_attempted: row.get(11)?,
                        send_attempt_count: row.get(12)?,
                        custody_updated_at: row.get(13)?,
                        admission_count: row.get(14)?,
                        operation_count: row.get(15)?,
                        event_count: row.get(16)?,
                    })
                },
            )
            .test_context("claim state snapshot")
    }

    fn prepared_claim_state_snapshot(
        store: &DomActuatorStoreV1,
        binding: DomSessionBindingV1,
        effect_id: Digest32,
    ) -> TestResult<PreparedClaimStateSnapshot> {
        store
            .connection
            .query_row(
                "SELECT l.owner_id,l.fencing_epoch,l.lease_until_unix_ms,l.updated_at_unix_ms,
                        s.stage_tag,s.revision,s.journal_head,s.updated_at_unix_ms,
                        o.fencing_epoch,o.authorization_digest,o.reconciliation_digest,
                        o.status_tag,o.receipt_digest,o.updated_at_unix_ms
                 FROM dom_sessions s
                 JOIN dom_leases l ON l.participant_id=s.participant_id
                 JOIN dom_operations o ON o.session_id=s.session_id
                 WHERE s.session_id=?1 AND o.effect_id=?2",
                params![binding.session_id().as_slice(), effect_id.as_slice()],
                |row| {
                    Ok(PreparedClaimStateSnapshot {
                        lease_owner: row.get(0)?,
                        lease_fence: row.get(1)?,
                        lease_until: row.get(2)?,
                        lease_updated_at: row.get(3)?,
                        session_stage: row.get(4)?,
                        session_revision: row.get(5)?,
                        journal_head: row.get(6)?,
                        session_updated_at: row.get(7)?,
                        operation_fence: row.get(8)?,
                        operation_authorization: row.get(9)?,
                        operation_reconciliation: row.get(10)?,
                        operation_status: row.get(11)?,
                        operation_receipt: row.get(12)?,
                        operation_updated_at: row.get(13)?,
                    })
                },
            )
            .test_context("prepared claim state snapshot")
    }

    fn actuator_row_counts(store: &DomActuatorStoreV1) -> TestResult<[i64; 13]> {
        Ok([
            store
                .connection
                .query_row("SELECT COUNT(*) FROM dom_leases", [], |row| row.get(0))
                .test_context("lease row count")?,
            store
                .connection
                .query_row("SELECT COUNT(*) FROM dom_sessions", [], |row| row.get(0))
                .test_context("session row count")?,
            store
                .connection
                .query_row("SELECT COUNT(*) FROM dom_operations", [], |row| row.get(0))
                .test_context("operation row count")?,
            store
                .connection
                .query_row("SELECT COUNT(*) FROM dom_claim_custody", [], |row| {
                    row.get(0)
                })
                .test_context("claim custody row count")?,
            store
                .connection
                .query_row("SELECT COUNT(*) FROM dom_claim_admission", [], |row| {
                    row.get(0)
                })
                .test_context("claim admission row count")?,
            store
                .connection
                .query_row("SELECT COUNT(*) FROM dom_terminal_finality", [], |row| {
                    row.get(0)
                })
                .test_context("terminal finality row count")?,
            store
                .connection
                .query_row("SELECT COUNT(*) FROM dom_output_reservations", [], |row| {
                    row.get(0)
                })
                .test_context("reservation row count")?,
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM dom_output_reservation_items",
                    [],
                    |row| row.get(0),
                )
                .test_context("reservation item row count")?,
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM dom_payout_face_preparations",
                    [],
                    |row| row.get(0),
                )
                .test_context("payout face preparation row count")?,
            store
                .connection
                .query_row("SELECT COUNT(*) FROM dom_payout_face_evidence", [], |row| {
                    row.get(0)
                })
                .test_context("payout face evidence row count")?,
            store
                .connection
                .query_row("SELECT COUNT(*) FROM dom_session_events", [], |row| {
                    row.get(0)
                })
                .test_context("session event row count")?,
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM dom_final_claim_attempt_v2",
                    [],
                    |row| row.get(0),
                )
                .test_context("V2 final-claim attempt row count")?,
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM dom_final_claim_admission_v2",
                    [],
                    |row| row.get(0),
                )
                .test_context("V2 final-claim admission row count")?,
        ])
    }

    pub(crate) fn payout_face_progress(
        store: &DomActuatorStoreV1,
        binding: DomSessionBindingV1,
    ) -> TestResult<(i64, i64, i64, i64)> {
        store
            .connection
            .query_row(
                "SELECT s.revision,
                        (SELECT COUNT(*) FROM dom_payout_face_preparations p
                         WHERE p.session_id=s.session_id),
                        (SELECT COUNT(*) FROM dom_payout_face_evidence p
                         WHERE p.session_id=s.session_id),
                        (SELECT COUNT(*) FROM dom_session_events e
                         WHERE e.session_id=s.session_id)
                 FROM dom_sessions s WHERE s.session_id=?1",
                params![binding.session_id().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .test_context("payout face progress")
    }

    pub(crate) fn mark_claim_potentially_exposed_for_test(
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        broadcast: &DomClaimBroadcastV1,
        now_unix_ms: u64,
    ) -> TestResult<PendingClaimAdmissionV1> {
        store
            .prepare_historical_claim_admission_for_test(lease, broadcast, now_unix_ms)
            .test_context("historical pre-RPC exposure latch")
    }

    fn seed_historical_claim_admission(
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        _binding: DomSessionBindingV1,
        broadcast: &DomClaimBroadcastV1,
        state: SubmissionStateV1,
        relayed: bool,
        now_unix_ms: u64,
    ) -> TestResult<DomClaimAdmissionV1> {
        let pending =
            mark_claim_potentially_exposed_for_test(store, lease, broadcast, now_unix_ms)?;
        let receipt = submission_receipt_facts(broadcast.tx_hash(), state, relayed)?;
        store
            .persist_claim_admission(lease, pending, receipt, now_unix_ms + 1)
            .test_context("persist historical admission fixture")
    }

    fn submission_receipt_facts(
        tx_hash: Digest32,
        state: SubmissionStateV1,
        relayed: bool,
    ) -> TestResult<ValidatedSubmissionReceiptFactsV1> {
        ValidatedSubmissionReceiptFactsV1::for_test(tx_hash, state, relayed)
            .test_context("validated submission receipt facts")
    }

    pub(crate) fn finality_record<'a>(
        kind: DomTerminalKindV1,
        tx_hash: Digest32,
        checkpoint: &'a [u8],
    ) -> DomTerminalFinalityRecordV1<'a> {
        DomTerminalFinalityRecordV1 {
            kind,
            tx_hash,
            block_height: 8,
            block_hash: digest(130),
            tip_height: 9,
            tip_hash: digest(131),
            confirmation_depth: 2,
            minimum_confirmations: 2,
            max_reorg_depth: 10,
            evidence_digest: digest(132),
            checkpoint_bytes: checkpoint,
        }
    }

    #[test]
    fn creation_fault_process_child() -> TestResult {
        let Some(path) = std::env::var_os(CREATION_FAULT_PATH_ENV) else {
            return Ok(());
        };
        let boundary = parse_creation_boundary(&std::env::var(CREATION_FAULT_BOUNDARY_ENV)?)?;
        let store = DomActuatorStoreV1::create_with_boundary_hook(Path::new(&path), |reached| {
            if reached == boundary {
                std::process::exit(CREATION_CRASH_EXIT);
            }
            Ok(())
        })?;
        drop(store);
        Err(std::io::Error::other("DOM actuator creation boundary was not reached").into())
    }

    #[test]
    fn provisioning_lock_probe_process_child() -> TestResult {
        let Some(path) = std::env::var_os(LOCK_PROBE_PATH_ENV) else {
            return Ok(());
        };
        match DomActuatorStoreV1::open_existing(Path::new(&path)) {
            Err(DomActuatorError::ProcessLocked) => Ok(()),
            Ok(store) => {
                drop(store);
                Err(std::io::Error::other("second process acquired DOM actuator lock").into())
            }
            Err(error) => Err(std::io::Error::other(format!(
                "unexpected second-process DOM actuator error: {error}"
            ))
            .into()),
        }
    }

    #[test]
    fn production_resume_recovers_every_durable_creation_prefix() -> TestResult {
        for boundary in [
            CreationBoundaryV1::ProcessLockPublished,
            CreationBoundaryV1::DatabaseFileSynced,
            CreationBoundaryV1::BeforeSchemaTransaction,
            CreationBoundaryV1::BeforeSchemaCommit,
            CreationBoundaryV1::SchemaCommitted,
        ] {
            let (_directory, path) = empty_store_path()?;
            stage_process_creation_crash(&path, boundary)?;
            match boundary {
                CreationBoundaryV1::ProcessLockPublished => require_dom_error(
                    DomActuatorStoreV1::open_existing(&path),
                    DomActuatorError::DatabaseMissing,
                )?,
                CreationBoundaryV1::DatabaseFileSynced
                | CreationBoundaryV1::BeforeSchemaTransaction
                | CreationBoundaryV1::BeforeSchemaCommit => require_dom_error(
                    DomActuatorStoreV1::open_existing(&path),
                    DomActuatorError::CreationIncomplete,
                )?,
                CreationBoundaryV1::SchemaCommitted => {
                    let reopened = DomActuatorStoreV1::open_existing(&path)?;
                    drop(reopened);
                }
            }
            let resumed = DomActuatorStoreV1::resume_create_production(&path)?;
            require_dom_error(
                DomActuatorStoreV1::resume_create_production(&path),
                DomActuatorError::ProcessLocked,
            )?;
            drop(resumed);
            drop(DomActuatorStoreV1::resume_create_production(&path)?);
            drop(DomActuatorStoreV1::open_existing(&path)?);
        }
        Ok(())
    }

    #[test]
    fn production_resume_refuses_missing_lock_foreign_sqlite_and_economic_state() -> TestResult {
        let (_directory, path) = empty_store_path()?;
        drop(create_database_authority(&path)?);
        require_dom_error(
            DomActuatorStoreV1::resume_create_production(&path),
            DomActuatorError::InvalidStorageAuthority,
        )?;

        let (_directory, path) = empty_store_path()?;
        require_dom_error(
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced),
            DomActuatorError::StorageUnavailable,
        )?;
        let foreign = Connection::open(&path)?;
        foreign.execute_batch("CREATE TABLE caller_shaped(value BLOB) STRICT;")?;
        drop(foreign);
        require_dom_error(
            DomActuatorStoreV1::resume_create_production(&path),
            DomActuatorError::UnsupportedFormat,
        )?;

        let (_directory, path) = empty_store_path()?;
        require_dom_error(
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced),
            DomActuatorError::StorageUnavailable,
        )?;
        let legacy = Connection::open(&path)?;
        legacy.pragma_update(None, "user_version", SCHEMA_VERSION - 1)?;
        drop(legacy);
        require_dom_error(
            DomActuatorStoreV1::resume_create_production(&path),
            DomActuatorError::UnsupportedFormat,
        )?;

        let (_directory, path) = empty_store_path()?;
        require_dom_error(
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced),
            DomActuatorError::StorageUnavailable,
        )?;
        let alternate = Connection::open(&path)?;
        alternate.pragma_update(None, "application_id", 41)?;
        drop(alternate);
        require_dom_error(
            DomActuatorStoreV1::resume_create_production(&path),
            DomActuatorError::UnsupportedFormat,
        )?;

        let (_directory, path, mut store, lease) = setup()?;
        store.bind_session(lease, binding(1, 2)?, 1_001)?;
        drop(store);
        require_dom_error(
            DomActuatorStoreV1::resume_create_production(&path),
            DomActuatorError::UnsupportedFormat,
        )?;
        drop(DomActuatorStoreV1::open_existing(&path)?);
        Ok(())
    }

    #[test]
    fn production_resume_refuses_malformed_sidecars_modes_and_links() -> TestResult {
        use std::os::unix::fs::PermissionsExt;

        let (_directory, path) = empty_store_path()?;
        require_dom_error(
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced),
            DomActuatorError::StorageUnavailable,
        )?;
        let wal = sidecar_path(&path, "-wal");
        fs::write(&wal, b"caller-shaped")?;
        fs::set_permissions(&wal, fs::Permissions::from_mode(FILE_MODE))?;
        require_dom_error(
            DomActuatorStoreV1::resume_create_production(&path),
            DomActuatorError::InvalidStorageAuthority,
        )?;

        let (_directory, path) = empty_store_path()?;
        require_dom_error(
            stage_creation_fault(&path, CreationBoundaryV1::ProcessLockPublished),
            DomActuatorError::StorageUnavailable,
        )?;
        fs::set_permissions(lock_path(&path), fs::Permissions::from_mode(0o644))?;
        require_dom_error(
            DomActuatorStoreV1::resume_create_production(&path),
            DomActuatorError::InvalidStorageAuthority,
        )?;

        let (_directory, path) = empty_store_path()?;
        require_dom_error(
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced),
            DomActuatorError::StorageUnavailable,
        )?;
        let hardlink = path.with_file_name("dom-actuator-hardlink.sqlite");
        fs::hard_link(&path, &hardlink)?;
        require_dom_error(
            DomActuatorStoreV1::resume_create_production(&path),
            DomActuatorError::InvalidStorageAuthority,
        )?;

        let (_directory, path) = empty_store_path()?;
        require_dom_error(
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced),
            DomActuatorError::StorageUnavailable,
        )?;
        let lock_hardlink = path.with_file_name("dom-actuator-hardlink.lock");
        fs::hard_link(lock_path(&path), &lock_hardlink)?;
        require_dom_error(
            DomActuatorStoreV1::resume_create_production(&path),
            DomActuatorError::InvalidStorageAuthority,
        )?;
        Ok(())
    }

    #[test]
    fn production_process_lock_and_retained_named_paths_fail_closed() -> TestResult {
        use std::os::unix::fs::OpenOptionsExt;

        let (_directory, path) = empty_store_path()?;
        let store = DomActuatorStoreV1::create(&path)?;
        let status = Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("store::tests::provisioning_lock_probe_process_child")
            .arg("--nocapture")
            .env(LOCK_PROBE_PATH_ENV, &path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        assert!(
            status.success(),
            "second process must not acquire DOM store"
        );

        let displaced = path.with_file_name("displaced-dom-actuator.sqlite");
        fs::rename(&path, &displaced)?;
        let replacement = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&path)?;
        replacement.sync_all()?;
        drop(replacement);
        require_dom_error(
            store.audit_storage_authority(),
            DomActuatorError::InvalidStorageAuthority,
        )?;
        drop(store);

        let (_directory, path) = empty_store_path()?;
        let store = DomActuatorStoreV1::create(&path)?;
        let lock = lock_path(&path);
        let displaced_lock = path.with_file_name("displaced-dom-actuator.lock");
        fs::rename(&lock, &displaced_lock)?;
        let replacement_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&lock)?;
        replacement_lock.sync_all()?;
        drop(replacement_lock);
        require_dom_error(
            store.audit_storage_authority(),
            DomActuatorError::InvalidStorageAuthority,
        )?;
        Ok(())
    }

    #[test]
    fn live_store_refuses_tampered_journal_before_read_or_write() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let retained_binding = binding(1, 2)?;
        store.bind_session(lease, retained_binding, 1_001)?;

        let attacker = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        attacker.execute(
            "UPDATE dom_sessions SET journal_head=?2 WHERE session_id=?1",
            params![
                retained_binding.session_id().as_slice(),
                digest(240).as_slice()
            ],
        )?;
        drop(attacker);

        require_dom_error(
            store.reservation_for_effect(digest(241)),
            DomActuatorError::UnsupportedFormat,
        )?;
        require_dom_error(
            store.acquire_lease(digest(242), digest(243), 1_002, 100),
            DomActuatorError::UnsupportedFormat,
        )?;

        let observer = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let unexpected_lease: i64 = observer.query_row(
            "SELECT COUNT(*) FROM dom_leases WHERE participant_id=?1",
            params![digest(242).as_slice()],
            |row| row.get(0),
        )?;
        assert_eq!(unexpected_lease, 0, "failed audit must precede mutation");
        Ok(())
    }

    #[test]
    fn production_store_rejects_weak_directory_and_database_modes() -> TestResult {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().test_context("tempdir")?;
        let path = directory.path().join("dom-actuator.sqlite");

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))
            .test_context("weak directory mode")?;
        assert!(matches!(
            DomActuatorStoreV1::create(&path),
            Err(DomActuatorError::InvalidStorageAuthority)
        ));

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(DIRECTORY_MODE))
            .test_context("owner-only directory mode")?;
        drop(DomActuatorStoreV1::create(&path).test_context("create owner-only store")?);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .test_context("weak database mode")?;
        assert!(matches!(
            DomActuatorStoreV1::open_existing(&path),
            Err(DomActuatorError::InvalidStorageAuthority)
        ));
        Ok(())
    }

    #[test]
    fn mainnet_adapter_identity_uses_startup_safe_genesis() -> TestResult {
        let genesis =
            dom_core::startup_genesis_hash_for_network_magic(dom_core::NETWORK_MAGIC_MAINNET)
                .test_context("finalized mainnet genesis")?;
        let chain_id =
            *dom_consensus::derive_chain_id(dom_core::NETWORK_MAGIC_MAINNET, &genesis).as_bytes();
        let mainnet = DomSessionBindingV1::from_parts_for_store(StoredDomSessionBindingPartsV1 {
            route_id: digest(1),
            session_id: digest(2),
            participant: DomParticipantV1::new(digest(9), 0).test_context("participant")?,
            chain_id,
            genesis_hash: *genesis.as_bytes(),
            runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Mainnet),
            terms_digest: digest(12),
            profile_digest: digest(13),
            deployment_digest: digest(14),
            asset_binding_digest: digest(15),
            registry_epoch: 1,
            min_confirmations: 2,
            max_reorg_depth: 10,
        })
        .test_context("public binding")?;
        let expected = mainnet
            .expected_dom_identity()
            .test_context("startup-safe mainnet identity")?;
        assert_eq!(expected.network, "mainnet");
        assert_eq!(expected.chain_id, chain_id);
        assert_eq!(expected.genesis_hash, *genesis.as_bytes());
        Ok(())
    }

    #[test]
    fn restart_duplicate_is_idempotent_and_equivocation_fails() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        reserve_stage(&mut store, lease, bound, 21, 1)?;
        let action = scope(bound, 22, DomActionV1::ContributeSharedOutput)?;
        let (first, disposition) = store
            .authorize_action(lease, action, digest(30), Some(digest(31)), 1_300)
            .test_context("first")?;
        assert_eq!(disposition, DomOperationDispositionV1::Prepared);
        assert!(first.is_fresh());
        let expected = first.authorization_digest();
        drop(store);

        let mut reopened = DomActuatorStoreV1::open_existing(&path).test_context("reopen")?;
        let resumed = reopened
            .acquire_lease(digest(9), digest(20), 1_301, 10_000)
            .test_context("same owner")?;
        let (duplicate, disposition) = reopened
            .authorize_action(resumed, action, digest(30), Some(digest(31)), 1_302)
            .test_context("duplicate")?;
        assert_eq!(disposition, DomOperationDispositionV1::Idempotent);
        assert!(duplicate.is_resumed());
        assert_eq!(duplicate.authorization_digest(), expected);
        assert!(matches!(
            reopened.authorize_action(resumed, action, digest(32), Some(digest(31)), 1_303),
            Err(DomActuatorError::IdempotencyConflict)
        ));
        Ok(())
    }

    #[test]
    fn cross_route_effect_and_output_reservation_are_exclusive() -> TestResult {
        let (_directory, _path, mut store, lease) = setup()?;
        let first = binding(1, 2)?;
        let second = binding(3, 4)?;
        store
            .bind_session(lease, first, 1_000)
            .test_context("bind first")?;
        store
            .bind_session(lease, second, 1_000)
            .test_context("bind second")?;
        reserve_stage(&mut store, lease, first, 21, 7)?;

        let reserve = scope(second, 22, DomActionV1::ReserveOutputs)?;
        let (capability, _) = store
            .authorize_action(lease, reserve, digest(40), None, 1_100)
            .test_context("authorize second")?;
        assert_eq!(
            store.prepare_output_reservation(
                lease,
                &capability,
                digest(41),
                &[(vec![7; 33], 10)],
                1_101
            ),
            Err(DomActuatorError::OutputReservationConflict)
        );

        let cross = ScopedDomActionV1::new(second, digest(21), DomActionV1::ReserveOutputs)
            .test_context("cross scope")?;
        assert!(matches!(
            store.authorize_action(lease, cross, digest(61), None, 1_102),
            Err(DomActuatorError::IdempotencyConflict)
        ));
        Ok(())
    }

    #[test]
    fn public_nonce_or_share_binding_is_globally_one_shot() -> TestResult {
        let (_directory, _path, mut store, lease) = setup()?;
        let first = binding(1, 2)?;
        let second = binding(3, 4)?;
        store
            .bind_session(lease, first, 1_000)
            .test_context("bind first")?;
        store
            .bind_session(lease, second, 1_000)
            .test_context("bind second")?;
        reserve_stage(&mut store, lease, first, 21, 1)?;
        reserve_stage(&mut store, lease, second, 22, 2)?;
        let shared_secret_binding = digest(77);
        store
            .authorize_action(
                lease,
                scope(first, 30, DomActionV1::ContributeSharedOutput)?,
                digest(31),
                Some(shared_secret_binding),
                1_100,
            )
            .test_context("first unique binding")?;
        assert!(matches!(
            store.authorize_action(
                lease,
                scope(second, 32, DomActionV1::ContributeSharedOutput)?,
                digest(33),
                Some(shared_secret_binding),
                1_101,
            ),
            Err(DomActuatorError::SecretReuseDetected)
        ));

        assert!(matches!(
            store.authorize_action(
                lease,
                scope(first, 34, DomActionV1::ContributeSharedOutput)?,
                digest(35),
                Some(digest(78)),
                1_102,
            ),
            Err(DomActuatorError::SecretReuseDetected)
        ));
        Ok(())
    }

    #[test]
    fn funding_is_impossible_until_refund_is_durable() -> TestResult {
        let (_directory, _path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        let funding = scope(bound, 60, DomActionV1::BroadcastFunding)?;
        assert!(matches!(
            store.authorize_action(lease, funding, digest(61), None, 1_001),
            Err(DomActuatorError::RefundNotArmed)
        ));
        reserve_stage(&mut store, lease, bound, 21, 1)?;
        complete_stage(
            &mut store,
            lease,
            bound,
            22,
            DomActionV1::ContributeSharedOutput,
        )?;
        complete_stage(
            &mut store,
            lease,
            bound,
            23,
            DomActionV1::CollaborativeBulletproof,
        )?;
        assert!(matches!(
            store.authorize_action(lease, funding, digest(61), None, 1_500),
            Err(DomActuatorError::RefundNotArmed)
        ));
        complete_stage(&mut store, lease, bound, 24, DomActionV1::PresignRefund)?;
        assert!(store
            .authorize_action(lease, funding, digest(61), None, 1_700)
            .is_ok());
        Ok(())
    }

    #[test]
    fn stale_fence_cannot_complete_and_takeover_requires_reconciliation() -> TestResult {
        let (_directory, path, mut store, lease_one) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease_one, bound, 1_000)
            .test_context("bind")?;
        reserve_stage(&mut store, lease_one, bound, 21, 1)?;
        let action = scope(bound, 22, DomActionV1::ContributeSharedOutput)?;
        let (old_capability, _) = store
            .authorize_action(lease_one, action, digest(30), Some(digest(31)), 1_100)
            .test_context("old authorization")?;
        let old_digest = old_capability.authorization_digest();
        drop(store);

        let mut reopened = DomActuatorStoreV1::open_existing(&path).test_context("reopen")?;
        let lease_two = reopened
            .acquire_lease(digest(9), digest(40), 11_001, 10_000)
            .test_context("takeover")?;
        assert_eq!(lease_two.fencing_epoch(), 2);
        assert_eq!(
            reopened.complete_action(lease_one, old_capability, digest(41), 11_002),
            Err(DomActuatorError::StaleFence)
        );
        assert!(matches!(
            reopened.authorize_action(lease_two, action, digest(30), Some(digest(31)), 11_003,),
            Err(DomActuatorError::ReconciliationRequired)
        ));
        let refenced = reopened
            .reauthorize_not_externalized(lease_two, action, old_digest, digest(42), 11_004)
            .test_context("re-fence")?;
        assert_eq!(refenced.fencing_epoch(), 2);
        assert!(refenced.is_resumed());
        Ok(())
    }

    #[test]
    fn takeover_replays_only_an_exact_completed_chain_outbox_receipt() -> TestResult {
        let (_directory, path, mut store, lease_one) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease_one, bound, 1_000)
            .test_context("bind")?;
        reserve_stage(&mut store, lease_one, bound, 21, 1)?;
        complete_stage(
            &mut store,
            lease_one,
            bound,
            22,
            DomActionV1::ContributeSharedOutput,
        )?;
        complete_stage(
            &mut store,
            lease_one,
            bound,
            23,
            DomActionV1::CollaborativeBulletproof,
        )?;
        complete_stage(&mut store, lease_one, bound, 24, DomActionV1::PresignRefund)?;
        let funding = scope(bound, 60, DomActionV1::BroadcastFunding)?;
        let (capability, _) = store
            .authorize_action(lease_one, funding, digest(61), None, 1_700)
            .test_context("authorize funding")?;
        let previous = capability.authorization_digest();
        store
            .complete_action(lease_one, capability, digest(62), 1_701)
            .test_context("persist exact funding outbox")?;
        drop(store);

        let mut reopened = DomActuatorStoreV1::open_existing(&path).test_context("reopen")?;
        let lease_two = reopened
            .acquire_lease(digest(9), digest(40), 11_001, 10_000)
            .test_context("takeover")?;
        assert!(matches!(
            reopened.authorize_action(lease_two, funding, digest(61), None, 11_002),
            Err(DomActuatorError::ReconciliationRequired)
        ));
        assert!(matches!(
            reopened.reauthorize_retained_exact_replay(
                lease_two,
                funding,
                previous,
                digest(63),
                11_003,
            ),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        let adopted = reopened
            .reauthorize_retained_exact_replay(lease_two, funding, previous, digest(62), 11_004)
            .test_context("adopt exact retained receipt")?;
        assert_eq!(adopted.fencing_epoch(), 2);
        assert!(adopted.is_resumed());
        assert_eq!(
            reopened
                .complete_action(lease_two, adopted, digest(62), 11_005)
                .test_context("idempotent retained replay")?,
            DomOperationDispositionV1::AlreadyCompleted
        );
        Ok(())
    }

    #[test]
    fn unattempted_claim_is_classified_and_all_send_authority_stays_closed() -> TestResult {
        let (_directory, _path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (claim_scope, evidence, previous, broadcast) =
            seed_exact_claim_custody(&mut store, lease, bound)?;
        let audit = store
            .audit_retained_claim_custody_v1(lease, bound, 1_512)
            .test_context("reauthenticate unattempted custody")?;
        assert_eq!(
            audit.classification(),
            DomClaimCustodyClassificationV1::Unattempted
        );
        assert!(audit.classification().is_unattempted());
        assert_eq!(audit.session_id(), bound.session_id());
        assert_eq!(audit.effect_id(), claim_scope.effect_id());
        assert_eq!(audit.route_id(), bound.route_id());
        assert_eq!(audit.participant_id(), bound.participant().participant_id());
        assert_eq!(audit.custody_fencing_epoch(), lease.fencing_epoch());
        assert_eq!(audit.tx_hash(), broadcast.tx_hash());
        assert_eq!(audit.template_hash(), digest(123));
        assert_eq!(audit.shared_output_commitment(), [0x24; 33]);
        assert_ne!(audit.custody_record_digest(), [0; 32]);
        assert_eq!(audit.send_attempt_count(), 0);
        assert_eq!(audit.admission_record_digest(), None);

        let (capability, disposition) = store
            .authorize_action(lease, claim_scope, evidence, None, 1_513)
            .test_context("reload completed claim intent")?;
        assert_eq!(disposition, DomOperationDispositionV1::AlreadyCompleted);
        let before = claim_state_snapshot(&store, bound)?;
        assert!(matches!(
            store.retained_claim_identity(lease, bound, 1_514),
            Err(DomActuatorError::InvalidStage)
        ));
        assert!(matches!(
            store.prepare_claim_dispatch(lease, &broadcast, 1_515),
            Err(DomActuatorError::InvalidStage)
        ));
        assert!(matches!(
            store.resume_claim_broadcast(lease, &capability, 1_516),
            Err(DomActuatorError::InvalidStage)
        ));
        assert!(matches!(
            store.reauthorize_retained_exact_replay(
                lease,
                claim_scope,
                previous,
                broadcast.tx_hash(),
                1_517,
            ),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert!(matches!(
            store.authorize_action(
                lease,
                scope(bound, 28, DomActionV1::BroadcastRefund)?,
                digest(124),
                None,
                1_518,
            ),
            Err(DomActuatorError::InvalidStage)
        ));
        let checkpoint = vec![0x50; 606];
        assert!(matches!(
            store.record_terminal_finality(
                lease,
                bound,
                finality_record(DomTerminalKindV1::Claim, broadcast.tx_hash(), &checkpoint),
                1_519,
            ),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(claim_state_snapshot(&store, bound)?, before);
        Ok(())
    }

    #[test]
    fn unadmitted_claim_revokes_prepared_refund_capability_without_mutation() -> TestResult {
        let (_directory, _path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let refund_scope = scope(bound, 28, DomActionV1::BroadcastRefund)?;
        let refund_evidence = digest(124);
        let (refund_capability, disposition) = store
            .authorize_action(lease, refund_scope, refund_evidence, None, 1_500)
            .test_context("prepare refund before claim custody")?;
        assert_eq!(disposition, DomOperationDispositionV1::Prepared);
        let (_claim_scope, _claim_evidence, _previous, _broadcast) =
            seed_exact_claim_custody(&mut store, lease, bound)?;
        let before = claim_state_snapshot(&store, bound)?;

        assert!(matches!(
            store.validate_live_capability(lease, &refund_capability, 1_512),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(claim_state_snapshot(&store, bound)?, before);
        assert!(matches!(
            store.authorize_action(lease, refund_scope, refund_evidence, None, 1_513),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(claim_state_snapshot(&store, bound)?, before);
        assert!(matches!(
            store.complete_action(lease, refund_capability, digest(125), 1_514),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(claim_state_snapshot(&store, bound)?, before);
        Ok(())
    }

    #[test]
    fn potentially_exposed_claim_survives_restart_without_replay_or_admission() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (claim_scope, evidence, _previous, broadcast) =
            seed_exact_claim_custody(&mut store, lease, bound)?;
        let _pending =
            mark_claim_potentially_exposed_for_test(&mut store, lease, &broadcast, 1_520)?;
        let audit = store
            .audit_retained_claim_custody_v1(lease, bound, 1_521)
            .test_context("reauthenticate ambiguous custody")?;
        assert_eq!(
            audit.classification(),
            DomClaimCustodyClassificationV1::PotentiallyExposed
        );
        assert!(audit.classification().is_potentially_exposed());
        assert_eq!(audit.send_attempt_count(), 1);
        assert_eq!(audit.admission_record_digest(), None);
        drop(store);

        let mut reopened =
            DomActuatorStoreV1::open_existing(&path).test_context("reopen ambiguous")?;
        let resumed_lease = reopened
            .acquire_lease(digest(9), digest(20), 1_522, 10_000)
            .test_context("same owner resumes")?;
        let (capability, disposition) = reopened
            .authorize_action(resumed_lease, claim_scope, evidence, None, 1_523)
            .test_context("reload completed claim intent")?;
        assert_eq!(disposition, DomOperationDispositionV1::AlreadyCompleted);
        let before = claim_state_snapshot(&reopened, bound)?;
        assert!(matches!(
            reopened.resume_claim_broadcast(resumed_lease, &capability, 1_524),
            Err(DomActuatorError::InvalidStage)
        ));
        assert!(matches!(
            reopened.prepare_claim_dispatch(resumed_lease, &broadcast, 1_525),
            Err(DomActuatorError::InvalidStage)
        ));
        assert!(matches!(
            reopened.authorize_action(
                resumed_lease,
                scope(bound, 28, DomActionV1::BroadcastRefund)?,
                digest(124),
                None,
                1_526,
            ),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(claim_state_snapshot(&reopened, bound)?, before);
        Ok(())
    }

    #[test]
    fn admitted_claim_reissues_only_its_durable_proof_without_new_attempt() -> TestResult {
        let (_directory, _path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (claim_scope, evidence, _previous, broadcast) =
            seed_exact_claim_custody(&mut store, lease, bound)?;
        let admission = seed_historical_claim_admission(
            &mut store,
            lease,
            bound,
            &broadcast,
            SubmissionStateV1::Confirmed,
            false,
            1_520,
        )?;
        let audit = store
            .audit_retained_claim_custody_v1(lease, bound, 1_522)
            .test_context("reauthenticate admitted custody")?;
        assert_eq!(
            audit.classification(),
            DomClaimCustodyClassificationV1::Admitted
        );
        assert!(audit.classification().is_admitted());
        assert_eq!(
            audit.admission_record_digest(),
            Some(admission.admission_record_digest())
        );
        let identity = store
            .retained_claim_identity(lease, bound, 1_522)
            .test_context("admitted observation identity")?;
        assert_eq!(identity.tx_hash, broadcast.tx_hash());
        let (capability, disposition) = store
            .authorize_action(lease, claim_scope, evidence, None, 1_523)
            .test_context("reload admitted claim intent")?;
        assert_eq!(disposition, DomOperationDispositionV1::AlreadyCompleted);
        let before = claim_state_snapshot(&store, bound)?;
        let reissued = store
            .prepare_claim_dispatch(lease, &broadcast, 1_524)
            .test_context("reissue admitted proof")?;
        assert_eq!(reissued.tx_hash(), broadcast.tx_hash());
        let replay = store
            .resume_claim_broadcast(lease, &capability, 1_525)
            .test_context("admission-gated opaque replay handle")?;
        let resumed = store
            .prepare_claim_dispatch(lease, &replay, 1_526)
            .test_context("reissue proof without dispatch")?;
        assert_eq!(
            resumed.admission_record_digest(),
            admission.admission_record_digest()
        );
        assert_eq!(claim_state_snapshot(&store, bound)?, before);
        Ok(())
    }

    #[test]
    fn unadmitted_custody_with_inconsistent_completed_operation_is_rejected_on_reopen() -> TestResult
    {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (claim_scope, _evidence, _authorization, _broadcast) =
            seed_exact_claim_custody(&mut store, lease, bound)?;
        drop(store);

        let connection =
            Connection::open(&path).test_context("open operation corruption fixture")?;
        assert_eq!(
            connection
                .execute(
                    "UPDATE dom_operations SET receipt_digest=?1 WHERE effect_id=?2",
                    params![digest(198).as_slice(), claim_scope.effect_id().as_slice()],
                )
                .test_context("corrupt completed claim receipt")?,
            1
        );
        drop(connection);

        assert!(matches!(
            DomActuatorStoreV1::open_existing(&path),
            Err(DomActuatorError::UnsupportedFormat)
        ));
        Ok(())
    }

    #[test]
    fn tampered_claim_admission_is_rejected_during_restart_audit() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (_claim_scope, _evidence, _authorization, broadcast) =
            seed_exact_claim_custody(&mut store, lease, bound)?;
        let _admission = seed_historical_claim_admission(
            &mut store,
            lease,
            bound,
            &broadcast,
            SubmissionStateV1::Confirmed,
            false,
            1_520,
        )?;
        drop(store);

        let connection = Connection::open(&path).test_context("open for corruption fixture")?;
        assert_eq!(
            connection
                .execute(
                    "UPDATE dom_claim_admission SET receipt_digest=?1 WHERE session_id=?2",
                    params![digest(199).as_slice(), bound.session_id().as_slice()],
                )
                .test_context("tamper receipt commitment")?,
            1
        );
        drop(connection);
        assert!(matches!(
            DomActuatorStoreV1::open_existing(&path),
            Err(DomActuatorError::UnsupportedFormat)
        ));
        Ok(())
    }

    #[test]
    fn takeover_reissues_durable_admission_without_rebroadcasting() -> TestResult {
        let (_directory, path, mut store, lease_one) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease_one, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease_one, bound)?;
        let (claim_scope, _evidence, previous, broadcast) =
            seed_exact_claim_custody(&mut store, lease_one, bound)?;
        let tx_hash = broadcast.tx_hash();
        let admission = seed_historical_claim_admission(
            &mut store,
            lease_one,
            bound,
            &broadcast,
            SubmissionStateV1::Confirmed,
            false,
            1_520,
        )?;
        let original_record = admission.admission_record_digest();
        let original_receipt = admission.receipt_digest();
        assert_eq!(admission.original_fencing_epoch(), 1);
        drop(store);

        let mut reopened = DomActuatorStoreV1::open_existing(&path).test_context("reopen")?;
        let lease_two = reopened
            .acquire_lease(digest(9), digest(40), 11_001, 10_000)
            .test_context("take over expired lease")?;
        assert_eq!(lease_two.fencing_epoch(), 2);

        // An admitted claim has no replayable broadcast authority under the
        // new generation. Recovery can only reissue the opaque owner-only
        // admission record, a path with no RPC or exact-byte parameter.
        assert!(matches!(
            reopened.reauthorize_retained_exact_replay(
                lease_two,
                claim_scope,
                previous,
                tx_hash,
                11_002,
            ),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        let reissued = reopened
            .resume_claim_admission(lease_two, bound, 11_003)
            .test_context("reissue retained admission without broadcast")?;
        assert_eq!(reissued.original_fencing_epoch(), 1);
        assert_eq!(reissued.tx_hash(), tx_hash);
        assert_eq!(reissued.receipt_digest(), original_receipt);
        assert_eq!(reissued.admission_record_digest(), original_record);
        Ok(())
    }

    #[test]
    fn prepared_claim_without_custody_cannot_advance_or_refence_after_takeover() -> TestResult {
        let (_directory, path, mut store, lease_one) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease_one, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease_one, bound)?;
        let claim_scope = scope(bound, 27, DomActionV1::BroadcastClaim)?;
        let (capability, disposition) = store
            .authorize_action(lease_one, claim_scope, digest(122), None, 1_510)
            .test_context("prepare claim operation without custody")?;
        assert_eq!(disposition, DomOperationDispositionV1::Prepared);
        let previous_authorization = capability.authorization_digest();
        drop(store);

        let mut reopened = DomActuatorStoreV1::open_existing(&path).test_context("reopen")?;
        let lease_two = reopened
            .acquire_lease(digest(9), digest(40), 11_001, 10_000)
            .test_context("take over expired lease")?;
        let before_state =
            prepared_claim_state_snapshot(&reopened, bound, claim_scope.effect_id())?;
        let before_counts = actuator_row_counts(&reopened)?;
        let before_database =
            fs::read(&path).test_context("read complete database before rejects")?;
        assert_eq!(before_state.lease_fence, 2);
        assert_eq!(before_state.operation_fence, 1);
        assert_eq!(before_state.operation_status, OP_PREPARED);
        assert_eq!(before_counts[3], 0, "no retained claim custody");
        assert_eq!(before_counts[4], 0, "no retained claim admission");

        assert!(matches!(
            reopened.reauthorize_not_externalized(
                lease_two,
                claim_scope,
                previous_authorization,
                [0; 32],
                11_002,
            ),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert_eq!(
            prepared_claim_state_snapshot(&reopened, bound, claim_scope.effect_id())?,
            before_state
        );
        assert_eq!(actuator_row_counts(&reopened)?, before_counts);
        assert_eq!(
            fs::read(&path).test_context("read database after rejected refence")?,
            before_database
        );

        assert!(matches!(
            reopened.reconcile_externalized(
                lease_two,
                claim_scope,
                previous_authorization,
                [0; 32],
                [0; 32],
                11_003,
            ),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert_eq!(
            prepared_claim_state_snapshot(&reopened, bound, claim_scope.effect_id())?,
            before_state
        );
        assert_eq!(actuator_row_counts(&reopened)?, before_counts);
        assert_eq!(
            fs::read(&path).test_context("read database after rejected reconciliation")?,
            before_database
        );
        Ok(())
    }

    #[test]
    fn pre_takeover_pending_receipt_cannot_cross_the_new_fence() -> TestResult {
        let (_directory, path, mut store, lease_one) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease_one, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease_one, bound)?;
        let (_claim_scope, _evidence, _previous, broadcast) =
            seed_exact_claim_custody(&mut store, lease_one, bound)?;
        let tx_hash = broadcast.tx_hash();
        let stale_pending =
            mark_claim_potentially_exposed_for_test(&mut store, lease_one, &broadcast, 1_520)?;
        let stale_receipt = submission_receipt_facts(tx_hash, SubmissionStateV1::Confirmed, false)?;

        // The RPC completed, but the old owner did not commit its receipt.
        drop(store);
        let mut reopened = DomActuatorStoreV1::open_existing(&path).test_context("reopen")?;
        let lease_two = reopened
            .acquire_lease(digest(9), digest(40), 11_001, 10_000)
            .test_context("take over expired lease")?;
        assert_eq!(lease_two.fencing_epoch(), 2);
        assert!(matches!(
            reopened.persist_claim_admission(lease_two, stale_pending, stale_receipt, 11_002),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert!(matches!(
            reopened.resume_claim_admission(lease_two, bound, 11_003),
            Err(DomActuatorError::ReconciliationRequired)
        ));
        Ok(())
    }

    #[test]
    fn stale_claim_fence_and_takeover_cannot_reauthorize_legacy_claim() -> TestResult {
        let (_directory, path, mut store, lease_one) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease_one, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease_one, bound)?;
        let (claim_scope, _evidence, previous, broadcast) =
            seed_exact_claim_custody(&mut store, lease_one, bound)?;
        let tx_hash = broadcast.tx_hash();
        let _pending =
            mark_claim_potentially_exposed_for_test(&mut store, lease_one, &broadcast, 1_520)?;
        drop(store);

        let mut reopened = DomActuatorStoreV1::open_existing(&path).test_context("reopen")?;
        let lease_two = reopened
            .acquire_lease(digest(9), digest(40), 11_001, 10_000)
            .test_context("takeover")?;
        let audit = reopened
            .audit_retained_claim_custody_v1(lease_two, bound, 11_002)
            .test_context("takeover audit remains potentially exposed")?;
        assert!(audit.classification().is_potentially_exposed());
        assert_eq!(audit.custody_fencing_epoch(), 1);
        assert!(matches!(
            reopened.prepare_claim_dispatch(lease_one, &broadcast, 11_003),
            Err(DomActuatorError::StaleFence)
        ));
        assert!(matches!(
            reopened.reauthorize_retained_exact_replay(
                lease_two,
                claim_scope,
                previous,
                digest(200),
                11_004,
            ),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        let before = claim_state_snapshot(&reopened, bound)?;
        assert!(matches!(
            reopened.reauthorize_retained_exact_replay(
                lease_two,
                claim_scope,
                previous,
                tx_hash,
                11_005,
            ),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert_eq!(claim_state_snapshot(&reopened, bound)?, before);
        Ok(())
    }

    #[test]
    fn funding_checkpoint_survives_restart_and_reorgs_after_terminal_progress() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_broadcast(&mut store, lease, bound)?;
        let funding_checkpoint = vec![0x46; 606];
        store
            .record_terminal_finality(
                lease,
                bound,
                finality_record(DomTerminalKindV1::Funding, digest(96), &funding_checkpoint),
                1_500,
            )
            .test_context("funding checkpoint")?;
        let retained = store
            .retained_terminal_checkpoint(lease, bound, DomTerminalKindV1::Funding, 1_501)
            .test_context("retained funding checkpoint")?;
        assert_eq!(retained.tx_hash, digest(96));
        assert_eq!(retained.block_height, 8);
        assert_eq!(retained.block_hash, digest(130));

        let (_claim_scope, _evidence, _authorization, broadcast) =
            seed_exact_claim_custody(&mut store, lease, bound)?;
        let _pending =
            mark_claim_potentially_exposed_for_test(&mut store, lease, &broadcast, 1_520)?;
        let claim_checkpoint = vec![0x47; 606];
        store
            .record_terminal_finality(
                lease,
                bound,
                finality_record(
                    DomTerminalKindV1::Claim,
                    broadcast.tx_hash(),
                    &claim_checkpoint,
                ),
                1_521,
            )
            .test_context("claim checkpoint alongside funding")?;
        let active: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM dom_terminal_finality WHERE active=1",
                [],
                |row| row.get(0),
            )
            .test_context("active checkpoint count")?;
        assert_eq!(active, 2);

        drop(store);
        let mut reopened = DomActuatorStoreV1::open_existing(&path).test_context("reopen")?;
        let resumed = reopened
            .acquire_lease(digest(9), digest(20), 1_600, 10_000)
            .test_context("resume lease")?;
        assert_eq!(
            reopened
                .record_terminal_reorg(
                    resumed,
                    bound,
                    DomTerminalReorgRecordV1 {
                        kind: DomTerminalKindV1::Funding,
                        tx_hash: digest(96),
                        prior_evidence_digest: digest(132),
                        current_tip_height: 12,
                        current_tip_hash: digest(140),
                        common_ancestor_height: 7,
                        removed_depth: 3,
                        minimum_confirmations: 2,
                        max_reorg_depth: 10,
                        evidence_digest: digest(141),
                    },
                    1_601,
                )
                .test_context("funding reorg after terminal progress")?,
            DomOperationDispositionV1::Prepared
        );
        assert!(matches!(
            reopened.retained_terminal_checkpoint(
                resumed,
                bound,
                DomTerminalKindV1::Funding,
                1_602,
            ),
            Err(DomActuatorError::InvalidStage)
        ));
        let invalidation = reopened
            .retained_terminal_invalidation(resumed, bound, DomTerminalKindV1::Funding, 1_603)
            .test_context("recover funding invalidation")?
            .test_context("durable invalidation")?;
        assert_eq!(invalidation.tx_hash, digest(96));
        assert_eq!(invalidation.block_height, 8);
        assert_eq!(invalidation.block_hash, digest(130));
        assert_eq!(invalidation.prior_evidence_digest, digest(132));
        assert_eq!(invalidation.reorg_evidence_digest, digest(141));

        drop(reopened);
        let mut recovered =
            DomActuatorStoreV1::open_existing(&path).test_context("reopen after reorg")?;
        let recovered_lease = recovered
            .acquire_lease(digest(9), digest(20), 1_604, 10_000)
            .test_context("recover same owner lease")?;
        let after_restart = recovered
            .retained_terminal_invalidation(
                recovered_lease,
                bound,
                DomTerminalKindV1::Funding,
                1_605,
            )
            .test_context("reload funding invalidation")?
            .test_context("retained invalidation after restart")?;
        assert_eq!(after_restart.reorg_evidence_digest, digest(141));

        recovered
            .connection
            .execute(
                "UPDATE dom_terminal_finality SET reorg_evidence_digest=?1 WHERE kind_tag=?2",
                params![digest(142).as_slice(), DomTerminalKindV1::Funding as u8],
            )
            .test_context("tamper retained reorg digest")?;
        drop(recovered);
        assert!(matches!(
            DomActuatorStoreV1::open_existing(&path),
            Err(DomActuatorError::UnsupportedFormat)
        ));
        Ok(())
    }

    #[test]
    fn funding_reorg_is_isolated_per_dom_leg_across_restart() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let upstream = binding(1, 2)?;
        let downstream = binding(1, 3)?;
        store.bind_session(lease, upstream, 1_000)?;
        store.bind_session(lease, downstream, 1_001)?;
        advance_to_funding_broadcast(&mut store, lease, upstream)?;
        advance_to_funding_broadcast_from(&mut store, lease, downstream, 31, 2)?;
        store.record_terminal_finality(
            lease,
            upstream,
            finality_record(DomTerminalKindV1::Funding, digest(96), &[0x46; 606]),
            1_500,
        )?;
        store.record_terminal_finality(
            lease,
            downstream,
            finality_record(DomTerminalKindV1::Funding, digest(106), &[0x56; 606]),
            1_501,
        )?;
        store.record_terminal_reorg(
            lease,
            upstream,
            DomTerminalReorgRecordV1 {
                kind: DomTerminalKindV1::Funding,
                tx_hash: digest(96),
                prior_evidence_digest: digest(132),
                current_tip_height: 12,
                current_tip_hash: digest(140),
                common_ancestor_height: 7,
                removed_depth: 3,
                minimum_confirmations: 2,
                max_reorg_depth: 10,
                evidence_digest: digest(141),
            },
            1_502,
        )?;
        assert!(store
            .retained_terminal_invalidation(lease, upstream, DomTerminalKindV1::Funding, 1_503,)?
            .is_some());
        assert_eq!(
            store
                .retained_terminal_checkpoint(
                    lease,
                    downstream,
                    DomTerminalKindV1::Funding,
                    1_504,
                )?
                .tx_hash,
            digest(106)
        );

        drop(store);
        let mut reopened = DomActuatorStoreV1::open_existing(&path)?;
        let resumed = reopened.acquire_lease(digest(9), digest(20), 2_000, 10_000)?;
        let upstream_reorg = reopened
            .retained_terminal_invalidation(resumed, upstream, DomTerminalKindV1::Funding, 2_001)?
            .test_context("upstream reorg survives restart")?;
        assert_eq!(upstream_reorg.reorg_evidence_digest, digest(141));
        assert_eq!(
            reopened
                .retained_terminal_checkpoint(
                    resumed,
                    downstream,
                    DomTerminalKindV1::Funding,
                    2_002,
                )?
                .tx_hash,
            digest(106)
        );
        assert!(
            reopened
                .retained_terminal_invalidation(
                    resumed,
                    downstream,
                    DomTerminalKindV1::Funding,
                    2_003,
                )?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn active_claim_checkpoint_cannot_authenticate_a_bare_reorg_stage() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_broadcast(&mut store, lease, bound)?;
        store
            .record_terminal_finality(
                lease,
                bound,
                finality_record(DomTerminalKindV1::Funding, digest(96), &[0x46; 606]),
                1_500,
            )
            .test_context("funding checkpoint")?;
        let (_claim_scope, _evidence, _authorization, broadcast) =
            seed_exact_claim_custody(&mut store, lease, bound)?;
        let _pending =
            mark_claim_potentially_exposed_for_test(&mut store, lease, &broadcast, 1_520)?;
        store
            .record_terminal_finality(
                lease,
                bound,
                finality_record(DomTerminalKindV1::Claim, broadcast.tx_hash(), &[0x47; 606]),
                1_521,
            )
            .test_context("claim checkpoint")?;
        drop(store);

        let connection = Connection::open(&path).test_context("open bare reorg fixture")?;
        assert_eq!(
            connection
                .execute(
                    "UPDATE dom_sessions SET stage_tag=?1 WHERE session_id=?2",
                    params![STAGE_REORG_RECOVERY, bound.session_id().as_slice()],
                )
                .test_context("tamper stage without invalidation")?,
            1
        );
        drop(connection);
        assert!(matches!(
            DomActuatorStoreV1::open_existing(&path),
            Err(DomActuatorError::UnsupportedFormat)
        ));
        Ok(())
    }

    #[test]
    fn potentially_exposed_claim_finality_is_exact_without_minting_admission() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (_scope, _evidence, _authorization, broadcast) =
            seed_exact_claim_custody(&mut store, lease, bound)?;
        let tx_hash = broadcast.tx_hash();
        let _pending =
            mark_claim_potentially_exposed_for_test(&mut store, lease, &broadcast, 1_520)?;
        let custody_before = store
            .audit_retained_claim_custody_v1(lease, bound, 1_521)
            .test_context("audit potentially exposed custody before observation")?;
        let identity = store
            .retained_claim_identity(lease, bound, 1_521)
            .test_context("potentially exposed observation identity")?;
        assert_eq!(identity.tx_hash, tx_hash);
        assert_eq!(claim_state_snapshot(&store, bound)?.admission_count, 0);
        let checkpoint = vec![0x51; 606];
        let record = finality_record(DomTerminalKindV1::Claim, tx_hash, &checkpoint);
        assert_eq!(
            store
                .record_terminal_finality(lease, bound, record, 1_530)
                .test_context("finality")?,
            DomOperationDispositionV1::Prepared
        );
        let duplicate = finality_record(DomTerminalKindV1::Claim, tx_hash, &checkpoint);
        assert_eq!(
            store
                .record_terminal_finality(lease, bound, duplicate, 1_531)
                .test_context("duplicate")?,
            DomOperationDispositionV1::Idempotent
        );
        drop(store);

        let mut reopened = DomActuatorStoreV1::open_existing(&path).test_context("reopen")?;
        let resumed = reopened
            .acquire_lease(digest(9), digest(20), 1_532, 10_000)
            .test_context("resume lease")?;
        let retained = reopened
            .retained_terminal_checkpoint(resumed, bound, DomTerminalKindV1::Claim, 1_533)
            .test_context("retained checkpoint")?;
        assert_eq!(retained.tx_hash, tx_hash);
        assert_eq!(retained.checkpoint_bytes, checkpoint);
        assert_eq!(retained.minimum_confirmations, bound.min_confirmations());
        let audit = reopened
            .audit_retained_claim_custody_v1(resumed, bound, 1_533)
            .test_context("potential exposure remains latched after finality")?;
        assert_eq!(
            audit.classification(),
            DomClaimCustodyClassificationV1::PotentiallyExposed
        );
        assert_eq!(audit.admission_record_digest(), None);
        assert_eq!(audit, custody_before);

        let wrong_policy_bytes = vec![0x52; 606];
        let mut wrong_policy =
            finality_record(DomTerminalKindV1::Claim, tx_hash, &wrong_policy_bytes);
        wrong_policy.minimum_confirmations = 3;
        assert_eq!(
            reopened.record_terminal_finality(resumed, bound, wrong_policy, 1_534),
            Err(DomActuatorError::CapabilityMismatch)
        );
        Ok(())
    }

    #[test]
    fn potentially_exposed_claim_reorg_requires_exact_prior_finality() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (_scope, _evidence, _authorization, broadcast) =
            seed_exact_claim_custody(&mut store, lease, bound)?;
        let tx_hash = broadcast.tx_hash();
        let _pending =
            mark_claim_potentially_exposed_for_test(&mut store, lease, &broadcast, 1_520)?;
        let custody_before = store
            .audit_retained_claim_custody_v1(lease, bound, 1_521)
            .test_context("audit potentially exposed custody before finality/reorg")?;
        let checkpoint = vec![0x51; 606];
        store
            .record_terminal_finality(
                lease,
                bound,
                finality_record(DomTerminalKindV1::Claim, tx_hash, &checkpoint),
                1_530,
            )
            .test_context("finality")?;
        let too_deep = DomTerminalReorgRecordV1 {
            kind: DomTerminalKindV1::Claim,
            tx_hash,
            prior_evidence_digest: digest(132),
            current_tip_height: 12,
            current_tip_hash: digest(140),
            common_ancestor_height: 1,
            removed_depth: 11,
            minimum_confirmations: 2,
            max_reorg_depth: 10,
            evidence_digest: digest(141),
        };
        assert_eq!(
            store.record_terminal_reorg(lease, bound, too_deep, 1_531),
            Err(DomActuatorError::CapabilityMismatch)
        );
        let wrong_prior = DomTerminalReorgRecordV1 {
            kind: DomTerminalKindV1::Claim,
            tx_hash,
            prior_evidence_digest: digest(200),
            current_tip_height: 12,
            current_tip_hash: digest(140),
            common_ancestor_height: 7,
            removed_depth: 3,
            minimum_confirmations: 2,
            max_reorg_depth: 10,
            evidence_digest: digest(142),
        };
        assert_eq!(
            store.record_terminal_reorg(lease, bound, wrong_prior, 1_532),
            Err(DomActuatorError::CapabilityMismatch)
        );
        let exact = DomTerminalReorgRecordV1 {
            kind: DomTerminalKindV1::Claim,
            tx_hash,
            prior_evidence_digest: digest(132),
            current_tip_height: 12,
            current_tip_hash: digest(140),
            common_ancestor_height: 7,
            removed_depth: 3,
            minimum_confirmations: 2,
            max_reorg_depth: 10,
            evidence_digest: digest(143),
        };
        assert_eq!(
            store
                .record_terminal_reorg(lease, bound, exact, 1_533)
                .test_context("bounded exact reorg")?,
            DomOperationDispositionV1::Prepared
        );
        assert!(matches!(
            store.retained_terminal_checkpoint(lease, bound, DomTerminalKindV1::Claim, 1_534),
            Err(DomActuatorError::InvalidStage)
        ));
        let recovery_identity = store
            .retained_claim_identity(lease, bound, 1_534)
            .test_context("exact potentially exposed identity remains observable after reorg")?;
        assert_eq!(recovery_identity.tx_hash, tx_hash);
        assert_eq!(claim_state_snapshot(&store, bound)?.admission_count, 0);
        let recovery_before = claim_state_snapshot(&store, bound)?;
        assert!(matches!(
            store.authorize_action(
                lease,
                scope(bound, 28, DomActionV1::BroadcastRefund)?,
                digest(147),
                None,
                1_534,
            ),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(claim_state_snapshot(&store, bound)?, recovery_before);

        drop(store);
        let mut reopened =
            DomActuatorStoreV1::open_existing(&path).test_context("reopen after reorg")?;
        let resumed = reopened
            .acquire_lease(digest(9), digest(20), 1_535, 10_000)
            .test_context("resume after reorg")?;
        let wrong_tx_checkpoint = vec![0x61; 606];
        assert_eq!(
            reopened.record_terminal_finality(
                resumed,
                bound,
                finality_record(DomTerminalKindV1::Claim, digest(201), &wrong_tx_checkpoint,),
                1_536,
            ),
            Err(DomActuatorError::CapabilityMismatch)
        );
        let exact_checkpoint = vec![0x62; 606];
        let mut refinality = finality_record(DomTerminalKindV1::Claim, tx_hash, &exact_checkpoint);
        refinality.block_hash = digest(144);
        refinality.tip_hash = digest(145);
        refinality.evidence_digest = digest(146);
        assert_eq!(
            reopened
                .record_terminal_finality(resumed, bound, refinality, 1_537)
                .test_context("exact refinality after restart")?,
            DomOperationDispositionV1::Prepared
        );
        let retained = reopened
            .retained_terminal_checkpoint(resumed, bound, DomTerminalKindV1::Claim, 1_538)
            .test_context("retained refinality")?;
        assert_eq!(retained.tx_hash, tx_hash);
        assert_eq!(retained.evidence_digest, digest(146));
        assert_eq!(retained.checkpoint_bytes, exact_checkpoint);
        let audit = reopened
            .audit_retained_claim_custody_v1(resumed, bound, 1_539)
            .test_context("potential exposure survives reorg and refinality")?;
        assert_eq!(
            audit.classification(),
            DomClaimCustodyClassificationV1::PotentiallyExposed
        );
        assert_eq!(audit.admission_record_digest(), None);
        assert_eq!(audit, custody_before);
        Ok(())
    }

    // -- V2 `FinalClaim` control plane ------------------------------------
    //
    // These fixtures exercise the owner-only mirror directly. The exact adapted
    // claim never enters this store in V2: the DOM Contracts exposure record is
    // its only custody, so every fixture below carries commitments only.

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct FinalClaimV2StateSnapshot {
        session_stage: i64,
        session_revision: i64,
        journal_head: Vec<u8>,
        session_updated_at: i64,
        operation_status: i64,
        operation_fence: i64,
        operation_authorization: Vec<u8>,
        operation_evidence: Vec<u8>,
        operation_receipt: Option<Vec<u8>>,
        operation_reconciliation: Option<Vec<u8>>,
        operation_updated_at: i64,
        attempt_fence: Option<i64>,
        attempt_record: Option<Vec<u8>>,
        attempt_count: Option<i64>,
        attempt_updated_at: Option<i64>,
        admission_record: Option<Vec<u8>>,
        admission_receipt: Option<Vec<u8>>,
        counts: [i64; 13],
    }

    pub(crate) fn final_claim_v2_state_snapshot(
        store: &DomActuatorStoreV1,
        binding: DomSessionBindingV1,
    ) -> TestResult<FinalClaimV2StateSnapshot> {
        let counts = actuator_row_counts(store)?;
        store
            .connection
            .query_row(
                "SELECT s.stage_tag,s.revision,s.journal_head,s.updated_at_unix_ms,
                        o.status_tag,o.fencing_epoch,o.authorization_digest,o.evidence_digest,
                        o.receipt_digest,o.reconciliation_digest,o.updated_at_unix_ms,
                        a.fencing_epoch,a.record_digest,a.send_attempt_count,a.updated_at_unix_ms,
                        d.record_digest,d.receipt_digest
                 FROM dom_sessions s
                 JOIN dom_operations o ON o.session_id=s.session_id AND o.action_tag=7
                 LEFT JOIN dom_final_claim_attempt_v2 a ON a.session_id=s.session_id
                 LEFT JOIN dom_final_claim_admission_v2 d ON d.session_id=s.session_id
                 WHERE s.session_id=?1",
                params![binding.session_id().as_slice()],
                |row| {
                    Ok(FinalClaimV2StateSnapshot {
                        session_stage: row.get(0)?,
                        session_revision: row.get(1)?,
                        journal_head: row.get(2)?,
                        session_updated_at: row.get(3)?,
                        operation_status: row.get(4)?,
                        operation_fence: row.get(5)?,
                        operation_authorization: row.get(6)?,
                        operation_evidence: row.get(7)?,
                        operation_receipt: row.get(8)?,
                        operation_reconciliation: row.get(9)?,
                        operation_updated_at: row.get(10)?,
                        attempt_fence: row.get(11)?,
                        attempt_record: row.get(12)?,
                        attempt_count: row.get(13)?,
                        attempt_updated_at: row.get(14)?,
                        admission_record: row.get(15)?,
                        admission_receipt: row.get(16)?,
                        counts,
                    })
                },
            )
            .test_context("V2 final-claim state snapshot")
    }

    pub(crate) const FINAL_CLAIM_V2_RECEIVER_ID: Digest32 = [0xC7; 32];

    pub(crate) fn final_claim_v2_facts(
        evidence_digest: Digest32,
        binding: DomSessionBindingV1,
    ) -> FinalClaimAttemptFactsV2 {
        final_claim_v2_facts_for(evidence_digest, binding, 160)
    }

    pub(crate) fn final_claim_v2_facts_for(
        evidence_digest: Digest32,
        binding: DomSessionBindingV1,
        tx_tag: u8,
    ) -> FinalClaimAttemptFactsV2 {
        FinalClaimAttemptFactsV2 {
            authority_evidence_digest: evidence_digest,
            dom_claim_sender_id: binding.participant().participant_id(),
            final_claim_receiver_id: FINAL_CLAIM_V2_RECEIVER_ID,
            tx_hash: digest(tx_tag),
            template_hash: digest(161),
            shared_output_commitment: [0x2A; 33],
            exposure_record_digest: digest(162),
        }
    }

    pub(crate) fn seed_prepared_final_claim_v2(
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
    ) -> TestResult<(
        ScopedDomActionV1,
        Digest32,
        DomActuatorCapabilityV1,
        FinalClaimAttemptFactsV2,
    )> {
        seed_prepared_final_claim_v2_at(store, lease, binding, 27, 163, 160)
    }

    pub(crate) fn seed_prepared_final_claim_v2_at(
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        binding: DomSessionBindingV1,
        effect_tag: u8,
        evidence_tag: u8,
        tx_tag: u8,
    ) -> TestResult<(
        ScopedDomActionV1,
        Digest32,
        DomActuatorCapabilityV1,
        FinalClaimAttemptFactsV2,
    )> {
        let claim_scope = scope(binding, effect_tag, DomActionV1::BroadcastClaim)?;
        let evidence = digest(evidence_tag);
        let (capability, disposition) = store
            .authorize_action(lease, claim_scope, evidence, None, 1_510)
            .test_context("authorize V2 final claim")?;
        assert_eq!(disposition, DomOperationDispositionV1::Prepared);
        let facts = final_claim_v2_facts_for(evidence, binding, tx_tag);
        Ok((claim_scope, evidence, capability, facts))
    }

    fn final_claim_v2_admission_receipt(
        _binding: DomSessionBindingV1,
        tx_hash: Digest32,
        state: SubmissionStateV1,
        relayed: bool,
    ) -> TestResult<ValidatedSubmissionReceiptFactsV1> {
        submission_receipt_facts(tx_hash, state, relayed)
    }

    #[test]
    fn production_final_claim_v2_attempt_latches_before_rpc_and_blocks_every_refund() -> TestResult
    {
        let (_directory, _path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (claim_scope, evidence, capability, facts) =
            seed_prepared_final_claim_v2(&mut store, lease, bound)?;

        // Before the latch the session is still refund-eligible.
        let refund_scope = scope(bound, 28, DomActionV1::BroadcastRefund)?;
        let (refund_capability, disposition) = store
            .authorize_action(lease, refund_scope, digest(124), None, 1_511)
            .test_context("refund is legal while the claim is unexposed")?;
        assert_eq!(disposition, DomOperationDispositionV1::Prepared);
        assert!(matches!(
            store.audit_final_claim_custody_v2(lease, bound, 1_512),
            Err(DomActuatorError::ReconciliationRequired)
        ));

        store
            .require_prepared_final_claim_authority_v2(lease, &capability, evidence, 1_513)
            .test_context("prepared V2 authority binding")?;
        let latched = store
            .latch_final_claim_attempt_v2(lease, &capability, &facts, 1_514)
            .test_context("latch the pre-RPC exposure attempt")?;
        assert_eq!(latched.session_id(), bound.session_id());
        assert_eq!(latched.tx_hash(), facts.tx_hash);

        let audit = store
            .audit_final_claim_custody_v2(lease, bound, 1_515)
            .test_context("reauthenticate exposed V2 custody")?;
        assert_eq!(
            audit.classification(),
            DomClaimCustodyClassificationV1::PotentiallyExposed
        );
        assert!(audit.classification().is_potentially_exposed());
        assert_eq!(audit.session_id(), bound.session_id());
        assert_eq!(audit.effect_id(), claim_scope.effect_id());
        assert_eq!(audit.route_id(), bound.route_id());
        assert_eq!(audit.participant_id(), bound.participant().participant_id());
        assert_eq!(
            audit.dom_claim_sender_id(),
            bound.participant().participant_id()
        );
        assert_eq!(audit.final_claim_receiver_id(), FINAL_CLAIM_V2_RECEIVER_ID);
        assert_eq!(audit.custody_fencing_epoch(), lease.fencing_epoch());
        assert_eq!(audit.tx_hash(), facts.tx_hash);
        assert_eq!(audit.template_hash(), facts.template_hash);
        assert_eq!(
            audit.shared_output_commitment(),
            facts.shared_output_commitment
        );
        assert_eq!(audit.exposure_record_digest(), facts.exposure_record_digest);
        assert_ne!(audit.attempt_record_digest(), [0; 32]);
        assert_eq!(audit.send_attempt_count(), 1);
        assert_eq!(audit.admission_record_digest(), None);

        // The pre-RPC latch has already removed every refund stage, and the
        // conservative classification refuses refund independently of stage.
        let before = final_claim_v2_state_snapshot(&store, bound)?;
        assert!(matches!(
            store.validate_live_capability(lease, &refund_capability, 1_516),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);
        assert!(matches!(
            store.authorize_action(lease, refund_scope, digest(124), None, 1_517),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);
        assert!(matches!(
            store.complete_action(lease, refund_capability, digest(125), 1_518),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);

        // Economic admission grants no refund exemption: once the marker is
        // durable the secret is public, and only an explicit route policy taken
        // under that knowledge may ever move value back. This control plane
        // never infers it.
        let authority = FinalClaimTransportAuthorityFactsV2 {
            session_id: bound.session_id(),
            dom_claim_sender_id: bound.participant().participant_id(),
            final_claim_receiver_id: FINAL_CLAIM_V2_RECEIVER_ID,
        };
        let receipt = final_claim_v2_admission_receipt(
            bound,
            facts.tx_hash,
            SubmissionStateV1::Confirmed,
            true,
        )?;
        // The capability is bound rather than dropped, and it is not what this
        // test is about: the subject is the durable mirror the call writes, which
        // the audit below reads back. Discarding the token silently would have
        // hidden that distinction; naming it states it.
        let _admission = store
            .persist_final_claim_admission_v2(lease, bound, &authority, receipt, 1_519)
            .test_context("mirror the validated economic admission")?;
        assert_eq!(
            store
                .audit_final_claim_custody_v2(lease, bound, 1_520)
                .test_context("admitted audit")?
                .classification(),
            DomClaimCustodyClassificationV1::Admitted
        );
        let admitted = final_claim_v2_state_snapshot(&store, bound)?;
        assert!(matches!(
            store.authorize_action(lease, refund_scope, digest(124), None, 1_521),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, admitted);
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_refuses_foreign_sender_and_self_receiver_without_writing(
    ) -> TestResult {
        let (_directory, _path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (_claim_scope, evidence, capability, facts) =
            seed_prepared_final_claim_v2(&mut store, lease, bound)?;
        let before = final_claim_v2_state_snapshot(&store, bound)?;

        let foreign_sender = FinalClaimAttemptFactsV2 {
            dom_claim_sender_id: digest(201),
            ..final_claim_v2_facts(evidence, bound)
        };
        assert!(matches!(
            store.latch_final_claim_attempt_v2(lease, &capability, &foreign_sender, 1_514),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);

        let self_receiver = FinalClaimAttemptFactsV2 {
            final_claim_receiver_id: bound.participant().participant_id(),
            ..final_claim_v2_facts(evidence, bound)
        };
        assert!(matches!(
            store.latch_final_claim_attempt_v2(lease, &capability, &self_receiver, 1_515),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);

        let zero_receiver = FinalClaimAttemptFactsV2 {
            final_claim_receiver_id: [0; 32],
            ..final_claim_v2_facts(evidence, bound)
        };
        assert!(matches!(
            store.latch_final_claim_attempt_v2(lease, &capability, &zero_receiver, 1_516),
            Err(DomActuatorError::InvalidBinding)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);

        // These owner-store validation calls have no adapter parameter, so an
        // RPC before their role checks is structurally impossible.
        let _latched = store
            .latch_final_claim_attempt_v2(lease, &capability, &facts, 1_517)
            .test_context("the exact frozen roles still latch")?;
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_latch_requires_the_exact_revalidated_authority() -> TestResult {
        let (_directory, _path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (_claim_scope, evidence, capability, _facts) =
            seed_prepared_final_claim_v2(&mut store, lease, bound)?;
        let before = final_claim_v2_state_snapshot(&store, bound)?;

        // A different revalidated V2 authority yields a different evidence
        // digest, so the durable action intent no longer matches.
        let rebound = FinalClaimAttemptFactsV2 {
            authority_evidence_digest: digest(164),
            ..final_claim_v2_facts(evidence, bound)
        };
        assert!(matches!(
            store.require_prepared_final_claim_authority_v2(lease, &capability, digest(164), 1_513),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);
        assert!(matches!(
            store.latch_final_claim_attempt_v2(lease, &capability, &rebound, 1_514),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);
        assert!(matches!(
            store.require_prepared_final_claim_authority_v2(lease, &capability, [0; 32], 1_515),
            Err(DomActuatorError::InvalidBinding)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);
        // This owner-store authority check has no adapter parameter; failure
        // therefore cannot have reached the node.
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_retry_is_byte_identical_and_never_mints_a_new_identity(
    ) -> TestResult {
        let (_directory, _path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (_claim_scope, evidence, capability, facts) =
            seed_prepared_final_claim_v2(&mut store, lease, bound)?;
        let _latched = store
            .latch_final_claim_attempt_v2(lease, &capability, &facts, 1_514)
            .test_context("first pre-RPC latch")?;
        let first = store
            .audit_final_claim_custody_v2(lease, bound, 1_515)
            .test_context("first exposed audit")?;

        let _latched = store
            .latch_final_claim_attempt_v2(lease, &capability, &facts, 1_516)
            .test_context("byte-identical retry after an ambiguous submission")?;
        let second = store
            .audit_final_claim_custody_v2(lease, bound, 1_517)
            .test_context("retried exposed audit")?;
        assert_eq!(second.send_attempt_count(), 2);
        assert_eq!(second.tx_hash(), first.tx_hash());
        assert_eq!(
            second.exposure_record_digest(),
            first.exposure_record_digest()
        );
        assert_eq!(second.template_hash(), first.template_hash());
        assert_ne!(
            second.attempt_record_digest(),
            first.attempt_record_digest()
        );
        assert_eq!(
            second.classification(),
            DomClaimCustodyClassificationV1::PotentiallyExposed
        );

        // A retry that is not byte-identical is refused with zero mutation.
        let before = final_claim_v2_state_snapshot(&store, bound)?;
        for divergent in [
            FinalClaimAttemptFactsV2 {
                tx_hash: digest(165),
                ..final_claim_v2_facts(evidence, bound)
            },
            FinalClaimAttemptFactsV2 {
                template_hash: digest(166),
                ..final_claim_v2_facts(evidence, bound)
            },
            FinalClaimAttemptFactsV2 {
                shared_output_commitment: [0x2B; 33],
                ..final_claim_v2_facts(evidence, bound)
            },
            FinalClaimAttemptFactsV2 {
                exposure_record_digest: digest(167),
                ..final_claim_v2_facts(evidence, bound)
            },
        ] {
            assert!(matches!(
                store.latch_final_claim_attempt_v2(lease, &capability, &divergent, 1_518),
                Err(DomActuatorError::CapabilityMismatch)
            ));
            assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);
        }
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_admission_requires_the_exact_admitted_receipt() -> TestResult {
        let (_directory, _path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (_claim_scope, _evidence, capability, facts) =
            seed_prepared_final_claim_v2(&mut store, lease, bound)?;
        let authority = FinalClaimTransportAuthorityFactsV2 {
            session_id: bound.session_id(),
            dom_claim_sender_id: bound.participant().participant_id(),
            final_claim_receiver_id: FINAL_CLAIM_V2_RECEIVER_ID,
        };

        // No attempt latch means no admission can ever be mirrored.
        let admitted_receipt = final_claim_v2_admission_receipt(
            bound,
            facts.tx_hash,
            SubmissionStateV1::Confirmed,
            false,
        )?;
        assert!(matches!(
            store.persist_final_claim_admission_v2(
                lease,
                bound,
                &authority,
                admitted_receipt,
                1_513
            ),
            Err(DomActuatorError::ReconciliationRequired)
        ));

        let _latched = store
            .latch_final_claim_attempt_v2(lease, &capability, &facts, 1_514)
            .test_context("pre-RPC latch")?;
        let before = final_claim_v2_state_snapshot(&store, bound)?;

        // A receipt for a different transaction never admits this claim.
        let foreign_receipt = final_claim_v2_admission_receipt(
            bound,
            digest(168),
            SubmissionStateV1::Confirmed,
            true,
        )?;
        assert!(matches!(
            store.persist_final_claim_admission_v2(
                lease,
                bound,
                &authority,
                foreign_receipt,
                1_515
            ),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);

        // Role facts that do not match the frozen attempt are refused.
        let foreign_authority = FinalClaimTransportAuthorityFactsV2 {
            session_id: bound.session_id(),
            dom_claim_sender_id: bound.participant().participant_id(),
            final_claim_receiver_id: digest(202),
        };
        assert!(matches!(
            store.persist_final_claim_admission_v2(
                lease,
                bound,
                &foreign_authority,
                admitted_receipt,
                1_516
            ),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);

        let admission = store
            .persist_final_claim_admission_v2(lease, bound, &authority, admitted_receipt, 1_517)
            .test_context("mirror the validated economic admission")?;
        assert_eq!(admission.session_id(), bound.session_id());
        assert_eq!(admission.tx_hash(), facts.tx_hash);
        assert_eq!(
            admission.exposure_record_digest(),
            facts.exposure_record_digest
        );
        assert_eq!(
            admission.dom_claim_sender_id(),
            bound.participant().participant_id()
        );
        assert_eq!(
            admission.final_claim_receiver_id(),
            FINAL_CLAIM_V2_RECEIVER_ID
        );
        assert_eq!(admission.submission_state(), SubmissionStateV1::Confirmed);
        assert!(!admission.was_relayed());
        assert_eq!(
            admission.receipt_digest(),
            admitted_receipt.receipt_digest_v1()
        );
        assert_ne!(admission.admission_record_digest(), [0; 32]);
        assert_eq!(
            store
                .audit_final_claim_custody_v2(lease, bound, 1_518)
                .test_context("admitted audit")?
                .classification(),
            DomClaimCustodyClassificationV1::Admitted
        );
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_admission_is_idempotent_and_conflict_fails_closed() -> TestResult {
        let (_directory, _path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (_claim_scope, _evidence, capability, facts) =
            seed_prepared_final_claim_v2(&mut store, lease, bound)?;
        let authority = FinalClaimTransportAuthorityFactsV2 {
            session_id: bound.session_id(),
            dom_claim_sender_id: bound.participant().participant_id(),
            final_claim_receiver_id: FINAL_CLAIM_V2_RECEIVER_ID,
        };
        let _latched = store
            .latch_final_claim_attempt_v2(lease, &capability, &facts, 1_514)
            .test_context("pre-RPC latch")?;
        let confirmed = final_claim_v2_admission_receipt(
            bound,
            facts.tx_hash,
            SubmissionStateV1::Confirmed,
            false,
        )?;
        let first = store
            .persist_final_claim_admission_v2(lease, bound, &authority, confirmed, 1_515)
            .test_context("first mirror")?;
        let after_first = final_claim_v2_state_snapshot(&store, bound)?;

        let repeated = store
            .persist_final_claim_admission_v2(lease, bound, &authority, confirmed, 1_516)
            .test_context("idempotent readback of the exact mirror")?;
        assert_eq!(
            repeated.admission_record_digest(),
            first.admission_record_digest()
        );
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, after_first);

        let relayed_mempool = final_claim_v2_admission_receipt(
            bound,
            facts.tx_hash,
            SubmissionStateV1::Mempool,
            true,
        )?;
        assert!(matches!(
            store.persist_final_claim_admission_v2(
                lease,
                bound,
                &authority,
                relayed_mempool,
                1_517
            ),
            Err(DomActuatorError::IdempotencyConflict)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, after_first);

        // Admitted custody refuses any further dispatch attempt.
        assert!(matches!(
            store.latch_final_claim_attempt_v2(lease, &capability, &facts, 1_518),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, after_first);
        assert!(matches!(
            store.require_prepared_final_claim_authority_v2(
                lease,
                &capability,
                facts.authority_evidence_digest,
                1_519
            ),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, after_first);

        let resumed = store
            .resume_final_claim_admission_v2(lease, bound, 1_520)
            .test_context("reissue the durable mirror without RPC")?;
        assert_eq!(
            resumed.admission_record_digest(),
            first.admission_record_digest()
        );
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, after_first);
        Ok(())
    }

    #[test]
    fn production_exposed_final_claim_v2_survives_takeover_without_replay_or_refence() -> TestResult
    {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (claim_scope, evidence, capability, facts) =
            seed_prepared_final_claim_v2(&mut store, lease, bound)?;
        let previous = capability.authorization_digest();
        let _latched = store
            .latch_final_claim_attempt_v2(lease, &capability, &facts, 1_514)
            .test_context("pre-RPC latch")?;
        drop(store);

        let mut reopened =
            DomActuatorStoreV1::open_existing(&path).test_context("reopen after crash")?;
        let resumed = reopened
            .acquire_lease(digest(9), digest(21), 12_000, 10_000)
            .test_context("takeover lease")?;
        assert!(resumed.fencing_epoch() > lease.fencing_epoch());
        let audit = reopened
            .audit_final_claim_custody_v2(resumed, bound, 12_001)
            .test_context("exposure survives restart and takeover")?;
        assert_eq!(
            audit.classification(),
            DomClaimCustodyClassificationV1::PotentiallyExposed
        );
        assert_eq!(audit.send_attempt_count(), 1);
        let before = final_claim_v2_state_snapshot(&reopened, bound)?;

        // The generic re-fencing entrypoints still refuse `BroadcastClaim`, and
        // a stale-fence attempt latch cannot cross the new generation.
        assert!(matches!(
            reopened.reauthorize_not_externalized(
                resumed,
                claim_scope,
                previous,
                digest(169),
                12_002,
            ),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&reopened, bound)?, before);
        assert!(matches!(
            reopened.reconcile_externalized(
                resumed,
                claim_scope,
                previous,
                digest(170),
                digest(171),
                12_003,
            ),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&reopened, bound)?, before);
        assert!(matches!(
            reopened.reauthorize_same_owner_final_claim_replay_v2(
                resumed,
                claim_scope,
                previous,
                &facts,
                12_004,
            ),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&reopened, bound)?, before);
        assert!(matches!(
            reopened.reauthorize_retained_exact_replay(
                resumed,
                claim_scope,
                previous,
                facts.exposure_record_digest,
                12_005,
            ),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&reopened, bound)?, before);
        assert!(matches!(
            reopened.latch_final_claim_attempt_v2(resumed, &capability, &facts, 12_006),
            Err(DomActuatorError::StaleFence)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&reopened, bound)?, before);
        assert!(matches!(
            reopened.resume_final_claim_admission_v2(resumed, bound, 12_007),
            Err(DomActuatorError::ReconciliationRequired)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&reopened, bound)?, before);

        // Refund stays closed under the conservative disposition.
        assert!(matches!(
            reopened.authorize_action(
                resumed,
                scope(bound, 28, DomActionV1::BroadcastRefund)?,
                digest(124),
                None,
                12_008,
            ),
            Err(DomActuatorError::InvalidStage)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&reopened, bound)?, before);
        // A fresh authorization on the new fence is idempotent readback only.
        assert!(matches!(
            reopened.authorize_action(resumed, claim_scope, evidence, None, 12_009),
            Err(DomActuatorError::ReconciliationRequired)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&reopened, bound)?, before);
        Ok(())
    }

    #[test]
    fn production_exposed_final_claim_v2_same_owner_replays_exactly_after_expiry() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (claim_scope, evidence, capability, facts) =
            seed_prepared_final_claim_v2(&mut store, lease, bound)?;
        let previous = capability.authorization_digest();
        let first = store
            .latch_final_claim_attempt_v2(lease, &capability, &facts, 1_514)
            .test_context("pre-RPC latch")?;
        drop(store);

        let mut reopened =
            DomActuatorStoreV1::open_existing(&path).test_context("reopen after crash")?;
        let resumed = reopened
            .acquire_lease(digest(9), lease.owner_id, 12_000, 10_000)
            .test_context("same owner recovers expired lease")?;
        assert!(resumed.fencing_epoch() > lease.fencing_epoch());
        let before = reopened
            .audit_final_claim_custody_v2(resumed, bound, 12_001)
            .test_context("exposed audit before re-fence")?;
        assert_eq!(
            before.classification(),
            DomClaimCustodyClassificationV1::PotentiallyExposed
        );
        assert_eq!(before.send_attempt_count(), 1);
        assert_eq!(before.tx_hash(), facts.tx_hash);

        let resumed_capability = reopened
            .reauthorize_same_owner_final_claim_replay_v2(
                resumed,
                claim_scope,
                previous,
                &facts,
                12_002,
            )
            .test_context("same owner exact replay authority")?;
        assert_ne!(
            resumed_capability.authorization_digest(),
            capability.authorization_digest()
        );
        assert!(matches!(
            reopened.authorize_action(resumed, claim_scope, evidence, None, 12_003),
            Ok((_, DomOperationDispositionV1::AlreadyCompleted))
        ));
        let retried = reopened
            .latch_final_claim_attempt_v2(resumed, &resumed_capability, &facts, 12_004)
            .test_context("byte-identical same-owner retry")?;
        assert_eq!(retried.session_id(), first.session_id());
        assert_eq!(retried.tx_hash(), first.tx_hash());
        assert_ne!(
            retried.attempt_record_digest(),
            first.attempt_record_digest()
        );
        let after = reopened
            .audit_final_claim_custody_v2(resumed, bound, 12_005)
            .test_context("exposed audit after exact retry")?;
        assert_eq!(
            after.classification(),
            DomClaimCustodyClassificationV1::PotentiallyExposed
        );
        assert_eq!(after.send_attempt_count(), 2);
        assert_eq!(after.tx_hash(), before.tx_hash());
        assert!(matches!(
            reopened.authorize_action(
                resumed,
                scope(bound, 28, DomActionV1::BroadcastRefund)?,
                digest(124),
                None,
                12_006,
            ),
            Err(DomActuatorError::InvalidStage)
        ));
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_owner_binding_tamper_fails_closed_on_restart() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (_claim_scope, _evidence, capability, facts) =
            seed_prepared_final_claim_v2(&mut store, lease, bound)?;
        let _latched = store
            .latch_final_claim_attempt_v2(lease, &capability, &facts, 1_514)
            .test_context("pre-RPC latch")?;
        store
            .connection
            .execute(
                "UPDATE dom_final_claim_attempt_v2 SET owner_id=?2 WHERE session_id=?1",
                params![bound.session_id().as_slice(), digest(99).as_slice()],
            )
            .test_context("tamper retained owner")?;
        drop(store);

        assert!(matches!(
            DomActuatorStoreV1::open_existing(&path),
            Err(DomActuatorError::UnsupportedFormat)
        ));
        Ok(())
    }

    #[test]
    fn production_tampered_final_claim_v2_records_fail_closed_on_restart() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (_claim_scope, _evidence, capability, facts) =
            seed_prepared_final_claim_v2(&mut store, lease, bound)?;
        let authority = FinalClaimTransportAuthorityFactsV2 {
            session_id: bound.session_id(),
            dom_claim_sender_id: bound.participant().participant_id(),
            final_claim_receiver_id: FINAL_CLAIM_V2_RECEIVER_ID,
        };
        let _latched = store
            .latch_final_claim_attempt_v2(lease, &capability, &facts, 1_514)
            .test_context("pre-RPC latch")?;
        let receipt = final_claim_v2_admission_receipt(
            bound,
            facts.tx_hash,
            SubmissionStateV1::Confirmed,
            true,
        )?;
        // Same as above: what is under test is the durable row, which the raw
        // statement below tampers with on purpose. The token is not the subject
        // and is not carried to a protocol boundary here.
        let _admission = store
            .persist_final_claim_admission_v2(lease, bound, &authority, receipt, 1_515)
            .test_context("mirror admission")?;
        store
            .connection
            .execute(
                "UPDATE dom_final_claim_admission_v2 SET receipt_relayed=0
                 WHERE session_id=?1",
                params![bound.session_id().as_slice()],
            )
            .test_context("tamper the retained receipt facts")?;
        drop(store);

        assert!(matches!(
            DomActuatorStoreV1::open_existing(&path),
            Err(DomActuatorError::UnsupportedFormat)
        ));
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_schema_is_versioned_and_carries_no_claim_bytes() -> TestResult {
        let (_directory, _path, store, _lease) = setup()?;
        let version: i64 = store
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .test_context("schema version")?;
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(SCHEMA_VERSION, 10);
        for table in ["dom_final_claim_attempt_v2", "dom_final_claim_admission_v2"] {
            let mut statement = store
                .connection
                .prepare(&format!("PRAGMA table_info({table})"))
                .test_context("V2 table info")?;
            let columns: Vec<String> = statement
                .query_map([], |row| row.get::<_, String>(1))
                .test_context("V2 columns")?
                .map(|column| column.test_context("V2 column name"))
                .collect::<TestResult<_>>()?;
            assert!(!columns.is_empty());
            for column in &columns {
                assert!(
                    !column.contains("bytes"),
                    "the V2 mirror must never retain claim bytes: {column}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn production_settlement_child_journal_replays_exact_outcome_after_restart() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;

        let request = DomSettlementChildBindingRequestV1::new(
            scope(bound, 26, DomActionV1::BroadcastFunding)?,
            digest(180),
            digest(181),
            digest(182),
            digest(183),
            DomSettlementChildExposureV1::NonSecret,
        )
        .test_context("settlement-child request")?;
        let binding = store
            .persist_authenticated_settlement_child_binding(lease, request, digest(96), 1_600)
            .test_context("persist binding")?;
        let locator = binding.locator();
        assert_eq!(
            format!("{binding:?}"),
            "DomSettlementChildBindingV1([redacted])"
        );

        let key = DomSettlementChildPortCallKeyV1::new(
            DomSettlementChildPortCallKindV1::Dispatch,
            digest(184),
            digest(185),
            &binding,
        )
        .test_context("port-call key")?;
        assert_eq!(
            store
                .begin_settlement_child_port_call(lease, key, 1_601)
                .test_context("begin call")?,
            DomSettlementChildPortCallJournalStatusV1::Pending
        );
        let stable = DomSettlementChildPortCallOutcomeV1::Externalized {
            evidence_digest: digest(186),
            first_exposure_evidence_digest: None,
        };
        assert_eq!(
            store
                .commit_settlement_child_port_call_outcome(lease, key, stable, 1_602)
                .test_context("commit outcome")?,
            stable
        );

        let transplanted = DomSettlementChildPortCallKeyV1::new(
            DomSettlementChildPortCallKindV1::Dispatch,
            digest(184),
            digest(187),
            &binding,
        )
        .test_context("transplanted key")?;
        assert_eq!(
            store.begin_settlement_child_port_call(lease, transplanted, 1_603),
            Err(DomActuatorError::IdempotencyConflict)
        );

        drop(store);
        let mut reopened = DomActuatorStoreV1::open_existing(&path).test_context("reopen")?;
        let resumed = reopened
            .acquire_lease(digest(9), digest(20), 2_000, 10_000)
            .test_context("resume lease")?;
        let rebound = reopened
            .settlement_child_binding(resumed, request.custody_digest(), 2_001)
            .test_context("reload binding")?;
        assert_eq!(rebound.locator(), locator);
        let replay_key = DomSettlementChildPortCallKeyV1::new(
            DomSettlementChildPortCallKindV1::Dispatch,
            digest(184),
            digest(185),
            &rebound,
        )
        .test_context("replay key")?;
        assert_eq!(
            reopened
                .begin_settlement_child_port_call(resumed, replay_key, 2_002)
                .test_context("replay outcome")?,
            DomSettlementChildPortCallJournalStatusV1::Committed(stable)
        );

        reopened
            .connection
            .execute(
                "UPDATE dom_settlement_child_port_calls SET outcome_digest=?1",
                params![digest(188).as_slice()],
            )
            .test_context("tamper outcome digest")?;
        drop(reopened);
        assert!(matches!(
            DomActuatorStoreV1::open_existing(&path),
            Err(DomActuatorError::UnsupportedFormat)
        ));
        Ok(())
    }

    #[test]
    fn production_settlement_child_attempt_cannot_cross_dom_sessions() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let upstream = binding(1, 2)?;
        let downstream = binding(1, 3)?;
        store
            .bind_session(lease, upstream, 1_000)
            .test_context("bind upstream")?;
        store
            .bind_session(lease, downstream, 1_001)
            .test_context("bind downstream")?;
        advance_to_funding_broadcast(&mut store, lease, upstream)?;
        advance_to_funding_broadcast_from(&mut store, lease, downstream, 31, 2)?;

        let upstream_request = DomSettlementChildBindingRequestV1::new(
            scope(upstream, 26, DomActionV1::BroadcastFunding)?,
            digest(180),
            digest(181),
            digest(182),
            digest(183),
            DomSettlementChildExposureV1::NonSecret,
        )?;
        let downstream_request = DomSettlementChildBindingRequestV1::new(
            scope(downstream, 36, DomActionV1::BroadcastFunding)?,
            digest(190),
            digest(191),
            digest(192),
            digest(193),
            DomSettlementChildExposureV1::NonSecret,
        )?;
        let upstream_binding = store.persist_authenticated_settlement_child_binding(
            lease,
            upstream_request,
            digest(96),
            1_600,
        )?;
        let downstream_binding = store.persist_authenticated_settlement_child_binding(
            lease,
            downstream_request,
            digest(106),
            1_601,
        )?;
        let attempt_id = digest(194);
        let upstream_key = DomSettlementChildPortCallKeyV1::new(
            DomSettlementChildPortCallKindV1::Dispatch,
            attempt_id,
            digest(195),
            &upstream_binding,
        )?;
        let downstream_transplant = DomSettlementChildPortCallKeyV1::new(
            DomSettlementChildPortCallKindV1::Dispatch,
            attempt_id,
            digest(196),
            &downstream_binding,
        )?;
        assert_eq!(
            store.begin_settlement_child_port_call(lease, upstream_key, 1_602)?,
            DomSettlementChildPortCallJournalStatusV1::Pending
        );
        assert_eq!(
            store.begin_settlement_child_port_call(lease, downstream_transplant, 1_603),
            Err(DomActuatorError::IdempotencyConflict)
        );

        drop(store);
        let mut reopened = DomActuatorStoreV1::open_existing(&path)?;
        let resumed = reopened.acquire_lease(digest(9), digest(20), 2_000, 10_000)?;
        assert_eq!(
            reopened.begin_settlement_child_port_call(resumed, upstream_key, 2_001)?,
            DomSettlementChildPortCallJournalStatusV1::Pending
        );
        assert_eq!(
            reopened.begin_settlement_child_port_call(resumed, downstream_transplant, 2_002),
            Err(DomActuatorError::IdempotencyConflict)
        );
        Ok(())
    }

    #[test]
    fn production_settlement_child_outcome_codec_is_strict_and_typed() -> TestResult {
        let canonical = DomSettlementChildPortCallOutcomeV1::Final {
            evidence_digest: digest(190),
        }
        .canonical_bytes();
        assert_eq!(
            DomSettlementChildPortCallOutcomeV1::from_canonical_bytes(&canonical)
                .test_context("canonical outcome")?
                .canonical_bytes(),
            canonical
        );
        let mut zero = canonical;
        zero[1..33].fill(0);
        assert!(DomSettlementChildPortCallOutcomeV1::from_canonical_bytes(&zero).is_err());
        let mut trailing = canonical.to_vec();
        trailing.push(0);
        assert!(DomSettlementChildPortCallOutcomeV1::from_canonical_bytes(&trailing).is_err());
        assert!(DomSettlementChildPortCallOutcomeV1::Pending {
            evidence_digest: digest(191),
        }
        .validate_for(DomSettlementChildPortCallKindV1::Observation)
        .is_ok());
        assert!(DomSettlementChildPortCallOutcomeV1::Pending {
            evidence_digest: digest(191),
        }
        .validate_for(DomSettlementChildPortCallKindV1::Dispatch)
        .is_err());
        Ok(())
    }

    #[test]
    fn production_final_claim_settlement_child_uses_v2_attempt_tx_not_exposure_receipt(
    ) -> TestResult {
        let (_directory, _path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (claim_scope, _evidence, capability, facts) =
            seed_prepared_final_claim_v2(&mut store, lease, bound)?;
        let _latched = store
            .latch_final_claim_attempt_v2(lease, &capability, &facts, 1_514)
            .test_context("latch V2 exposure")?;
        assert_ne!(facts.tx_hash, facts.exposure_record_digest);

        let request = DomSettlementChildBindingRequestV1::new(
            claim_scope,
            digest(192),
            digest(193),
            digest(194),
            digest(195),
            DomSettlementChildExposureV1::FirstSecretExposure,
        )
        .test_context("claim binding request")?;
        assert_eq!(
            store.persist_authenticated_settlement_child_binding(
                lease,
                request,
                digest(196),
                1_515,
            ),
            Err(DomActuatorError::CapabilityMismatch)
        );
        let binding = store
            .persist_authenticated_settlement_child_binding(lease, request, facts.tx_hash, 1_516)
            .test_context("bind V2 claim tx")?;
        assert_eq!(binding.transaction_id(), facts.tx_hash);
        assert_eq!(
            binding.request().scope().action(),
            DomActionV1::BroadcastClaim
        );
        Ok(())
    }

    #[test]
    fn production_v7_store_is_refused_without_migration() -> TestResult {
        let (_directory, path, store, _lease) = setup()?;
        store
            .connection
            .execute_batch("PRAGMA user_version=7;")
            .test_context("mark prior schema")?;
        drop(store);
        assert!(matches!(
            DomActuatorStoreV1::open_existing(&path),
            Err(DomActuatorError::UnsupportedFormat)
        ));
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_conservative_join_never_downgrades_exposure() -> TestResult {
        use DomClaimCustodyClassificationV1::{Admitted, PotentiallyExposed, Unattempted};

        for (local, contracts, expected) in [
            (Unattempted, Unattempted, Unattempted),
            (Unattempted, PotentiallyExposed, PotentiallyExposed),
            (Unattempted, Admitted, Admitted),
            (PotentiallyExposed, PotentiallyExposed, PotentiallyExposed),
            (PotentiallyExposed, Admitted, Admitted),
            (Admitted, Admitted, Admitted),
            // A strictly stronger local disposition is local corruption; the
            // join still reports the stronger value so the façade can detect it.
            (PotentiallyExposed, Unattempted, PotentiallyExposed),
            (Admitted, Unattempted, Admitted),
            (Admitted, PotentiallyExposed, Admitted),
        ] {
            assert_eq!(local.join_conservative(contracts), expected);
            assert_eq!(contracts.join_conservative(local), expected);
        }
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_reorg_and_finality_never_mint_admission() -> TestResult {
        // This is the sender half: a terminal checkpoint on the owner-only
        // mirror never fabricates an admission. The receiver half needs the
        // Contracts plane and lives beside its fixture, in `contracts.rs`, as
        // `production_final_claim_v2_local_terminalization_never_mints_a_receiver_observation`.
        let (_directory, _path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (_claim_scope, _evidence, capability, facts) =
            seed_prepared_final_claim_v2(&mut store, lease, bound)?;

        // Nothing observable before the exposure latch.
        assert!(matches!(
            store.retained_final_claim_identity_v2(lease, bound, 1_513),
            Err(DomActuatorError::InvalidStage)
        ));

        let _latched = store
            .latch_final_claim_attempt_v2(lease, &capability, &facts, 1_514)
            .test_context("pre-RPC latch")?;
        let identity = store
            .retained_final_claim_identity_v2(lease, bound, 1_515)
            .test_context("exposed claim is observable without admission")?;
        assert_eq!(identity.tx_hash, facts.tx_hash);
        assert_eq!(identity.template_hash, facts.template_hash);
        assert_eq!(
            identity.shared_output_commitment,
            facts.shared_output_commitment
        );

        let checkpoint = vec![0x50; 606];
        assert_eq!(
            store
                .record_terminal_finality(
                    lease,
                    bound,
                    finality_record(DomTerminalKindV1::Claim, facts.tx_hash, &checkpoint),
                    1_516,
                )
                .test_context("terminalize the exposed claim")?,
            DomOperationDispositionV1::Prepared
        );
        let audit = store
            .audit_final_claim_custody_v2(lease, bound, 1_517)
            .test_context("audit after terminalization")?;
        assert_eq!(
            audit.classification(),
            DomClaimCustodyClassificationV1::PotentiallyExposed
        );
        assert_eq!(audit.admission_record_digest(), None);
        assert_eq!(audit.send_attempt_count(), 1);
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_rpc_holds_no_actuator_store_lock() -> TestResult {
        type DispatchWithoutControlStore<'store> =
            for<'actuator, 'runtime, 'prepared, 'latched> fn(
                &'actuator crate::contracts::DomContractsActuatorV1<'store>,
                &'runtime adapter_dom_real::RealDomRpcRuntimeV1,
                &'prepared dom_scriptless_store::PreparedOperationalFinalClaimSubmissionV2,
                &'latched LatchedFinalClaimSubmissionV2,
            ) -> DomActuatorResult<
                SubmissionReceiptV1,
            >;

        // This is a compile-time boundary assertion, not an environmental RPC
        // fixture: adding either `&mut DomActuatorStoreV1` or `DomLeaseV1` to
        // dispatch would stop the method item from coercing to this type. The
        // contrapositive below separately proves that an actually held writer
        // lock is detected by the same owner store.
        let _dispatch: DispatchWithoutControlStore<'_> =
            crate::contracts::DomContractsActuatorV1::dispatch_final_claim_broadcast_v2;
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_reentrancy_control_detects_a_held_store_lock() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store
            .bind_session(lease, bound, 1_000)
            .test_context("bind")?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let (_claim_scope, _evidence, capability, facts) =
            seed_prepared_final_claim_v2(&mut store, lease, bound)?;
        let _latched = store
            .latch_final_claim_attempt_v2(lease, &capability, &facts, 1_514)
            .test_context("pre-RPC latch")?;

        // Contrapositive of the reentrancy proof: with a writer lock genuinely
        // held on the same database file, the very same reentrant call fails.
        // Without this control the positive assertion would be vacuous.
        let blocker = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .test_context("second connection")?;
        blocker
            .busy_handler(None)
            .test_context("no busy retry on the blocker")?;
        blocker
            .execute_batch("BEGIN IMMEDIATE; UPDATE dom_sessions SET updated_at_unix_ms=9999;")
            .test_context("hold an exclusive writer transaction")?;
        assert!(matches!(
            store.audit_final_claim_custody_v2(lease, bound, 1_515),
            Err(DomActuatorError::StorageUnavailable)
        ));
        blocker
            .execute_batch("ROLLBACK;")
            .test_context("release the writer transaction")?;
        // The assertion here is the success itself — the identical call that
        // failed under the held writer lock now returns — so the audit value is
        // bound and not inspected. That is the whole contrapositive.
        let _audit = store
            .audit_final_claim_custody_v2(lease, bound, 1_516)
            .test_context("the same call succeeds once the lock is released")?;
        Ok(())
    }

    #[test]
    fn production_final_claim_v2_latched_token_binds_one_session_and_one_transaction() -> TestResult
    {
        // P1-C5: the DOM Contracts store can reissue a byte-identical
        // submission handle from the exposure record alone, so a handle by
        // itself is not proof that this control plane latched an attempt.
        // `dispatch_final_claim_broadcast_v2` therefore also demands a
        // `LatchedFinalClaimSubmissionV2`, which has no public constructor and
        // is minted only here. Dispatching without one is not a runtime
        // rejection but a type error: the call does not exist.
        let (_directory, _path, mut store, lease) = setup()?;
        let first = binding(1, 2)?;
        store
            .bind_session(lease, first, 1_000)
            .test_context("bind first")?;
        advance_to_funding_confirmed(&mut store, lease, first)?;
        let (_first_scope, _first_evidence, first_capability, first_facts) =
            seed_prepared_final_claim_v2(&mut store, lease, first)?;
        let first_latched = store
            .latch_final_claim_attempt_v2(lease, &first_capability, &first_facts, 1_514)
            .test_context("latch the first session")?;
        assert_eq!(first_latched.session_id(), first.session_id());
        assert_eq!(first_latched.tx_hash(), first_facts.tx_hash);
        assert_eq!(
            first_latched.attempt_record_digest(),
            store
                .audit_final_claim_custody_v2(lease, first, 1_515)
                .test_context("first audit")?
                .attempt_record_digest()
        );

        // A retry keeps the session and the transaction identity and only moves
        // the attempt commitment, so a stale token can never masquerade as the
        // current latch.
        let retried = store
            .latch_final_claim_attempt_v2(lease, &first_capability, &first_facts, 1_516)
            .test_context("byte-identical retry")?;
        assert_eq!(retried.session_id(), first_latched.session_id());
        assert_eq!(retried.tx_hash(), first_latched.tx_hash());
        assert_ne!(
            retried.attempt_record_digest(),
            first_latched.attempt_record_digest()
        );

        // A different session mints a structurally distinct token: neither its
        // session nor its transaction can satisfy the first session's dispatch
        // cross-check in `dispatch_final_claim_broadcast_v2`. It is seeded in
        // its own owner-only store because the route effect identifiers of the
        // shared staging fixture are session-independent by construction.
        let (_other_directory, _other_path, mut other_store, other_lease) = setup()?;
        let second = binding(1, 3)?;
        other_store
            .bind_session(other_lease, second, 1_000)
            .test_context("bind second")?;
        advance_to_funding_confirmed(&mut other_store, other_lease, second)?;
        let (_second_scope, _second_evidence, second_capability, second_facts) =
            seed_prepared_final_claim_v2_at(&mut other_store, other_lease, second, 27, 173, 180)?;
        let second_latched = other_store
            .latch_final_claim_attempt_v2(other_lease, &second_capability, &second_facts, 1_517)
            .test_context("latch the second session")?;
        assert_ne!(second_latched.session_id(), first_latched.session_id());
        assert_ne!(second_latched.tx_hash(), first_latched.tx_hash());
        assert_ne!(
            second_latched.attempt_record_digest(),
            first_latched.attempt_record_digest()
        );
        Ok(())
    }

    #[test]
    fn payout_face_is_one_immutable_journal_revision_across_restart() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store.bind_session(lease, bound, 1_000)?;
        let commitment = payout_commitment(2)?;
        let prepare_digest = {
            let prepared =
                store.prepare_payout_face(lease, bound, commitment, 50, digest(61), 1_001)?;
            assert_eq!(payout_face_progress(&store, bound)?, (0, 1, 0, 0));
            prepared.prepare_digest
        };
        drop(store);
        let mut store = DomActuatorStoreV1::open_existing(&path)?;
        let lease = store.acquire_lease(digest(9), digest(20), 1_002, 10_000)?;
        let recovered_prepared =
            store.prepare_payout_face(lease, bound, commitment, 50, digest(61), 1_003)?;
        assert_eq!(recovered_prepared.prepare_digest, prepare_digest);
        assert_eq!(payout_face_progress(&store, bound)?, (0, 1, 0, 0));
        require_dom_error(
            store.prepare_payout_face(lease, bound, commitment, 51, digest(61), 1_003),
            DomActuatorError::IdempotencyConflict,
        )?;
        require_dom_error(
            store.prepare_payout_face(lease, bound, commitment, 50, digest(62), 1_003),
            DomActuatorError::IdempotencyConflict,
        )?;
        assert_eq!(payout_face_progress(&store, bound)?, (0, 1, 0, 0));
        let first = store.activate_payout_face(lease, &recovered_prepared, digest(70), 1_004)?;
        assert_eq!(first.evidence_revision, 1);
        assert_eq!(payout_face_progress(&store, bound)?, (1, 1, 1, 1));
        store.validate_payout_face(lease, &first, 1_005)?;
        let wrong = RetainedDomPayoutFaceEvidenceV1 {
            record_digest: digest(99),
            ..first
        };
        require_dom_error(
            store.validate_payout_face(lease, &wrong, 1_005),
            DomActuatorError::CapabilityMismatch,
        )?;
        require_dom_error(
            store.prepare_payout_face(lease, bound, commitment, 50, digest(61), 1_006),
            DomActuatorError::CapabilityMismatch,
        )?;
        let repeated_prepared =
            store.recover_payout_face_preparation(lease, bound, prepare_digest, 1_006)?;
        let repeated = store.activate_payout_face(lease, &repeated_prepared, digest(71), 1_007)?;
        assert_eq!(repeated.evidence_revision, first.evidence_revision);
        assert_eq!(repeated.record_digest, first.record_digest);
        assert_eq!(payout_face_progress(&store, bound)?, (1, 1, 1, 1));
        drop(store);

        let mut reopened = DomActuatorStoreV1::open_existing(&path)?;
        let resumed = reopened.acquire_lease(digest(9), digest(20), 1_008, 10_000)?;
        let recovered_prepared =
            reopened.recover_payout_face_preparation(resumed, bound, prepare_digest, 1_009)?;
        let recovered =
            reopened.activate_payout_face(resumed, &recovered_prepared, digest(72), 1_010)?;
        assert_eq!(recovered.evidence_revision, first.evidence_revision);
        assert_eq!(recovered.record_digest, first.record_digest);
        assert_eq!(payout_face_progress(&reopened, bound)?, (1, 1, 1, 1));
        Ok(())
    }

    #[test]
    fn payout_face_commitment_cannot_be_promised_to_two_sessions() -> TestResult {
        let (_directory, _path, mut store, lease) = setup()?;
        let first = binding(1, 2)?;
        let second = binding(1, 3)?;
        store.bind_session(lease, first, 1_000)?;
        store.bind_session(lease, second, 1_000)?;
        for malformed in [[0_u8; 33], [0x04; 33]] {
            require_dom_error(
                store.prepare_payout_face(lease, first, malformed, 50, digest(61), 1_001),
                DomActuatorError::InvalidBinding,
            )?;
        }
        assert_eq!(payout_face_progress(&store, first)?, (0, 0, 0, 0));
        let commitment = payout_commitment(3)?;
        activate_payout_face_for_test(&mut store, lease, first, commitment, digest(61), 1_001)?;
        require_dom_error(
            store.prepare_payout_face(lease, second, commitment, 50, digest(62), 1_003),
            DomActuatorError::IdempotencyConflict,
        )?;
        assert_eq!(payout_face_progress(&store, first)?, (1, 1, 1, 1));
        assert_eq!(payout_face_progress(&store, second)?, (0, 0, 0, 0));
        Ok(())
    }

    #[test]
    fn payout_face_preparation_cannot_cross_store_identity() -> TestResult {
        let (_first_directory, _first_path, mut first_store, first_lease) = setup()?;
        let (_second_directory, _second_path, mut second_store, second_lease) = setup()?;
        let bound = binding(1, 2)?;
        first_store.bind_session(first_lease, bound, 1_000)?;
        second_store.bind_session(second_lease, bound, 1_000)?;
        let commitment = payout_commitment(4)?;
        let first = first_store.prepare_payout_face(
            first_lease,
            bound,
            commitment,
            50,
            digest(61),
            1_001,
        )?;
        let second = second_store.prepare_payout_face(
            second_lease,
            bound,
            commitment,
            50,
            digest(61),
            1_001,
        )?;
        assert_ne!(first.store_instance_id, second.store_instance_id);
        assert_ne!(first.prepare_digest, second.prepare_digest);
        require_dom_error(
            second_store.activate_payout_face(second_lease, &first, digest(70), 1_002),
            DomActuatorError::CapabilityMismatch,
        )?;
        assert_eq!(payout_face_progress(&second_store, bound)?, (0, 1, 0, 0));
        Ok(())
    }

    #[test]
    fn payout_face_tamper_is_rejected_on_reopen() -> TestResult {
        for statement in [
            "UPDATE dom_store_identity SET instance_id=zeroblob(32)",
            "UPDATE dom_payout_face_preparations SET prepare_digest=zeroblob(32)",
            "UPDATE dom_payout_face_preparations SET created_at_unix_ms=created_at_unix_ms+1",
            "UPDATE dom_payout_face_evidence SET payout_value=payout_value+1",
            "UPDATE dom_payout_face_evidence SET evidence_revision=evidence_revision+1",
            "UPDATE dom_payout_face_evidence SET record_digest=zeroblob(32)",
            "UPDATE dom_payout_face_evidence SET created_at_unix_ms=created_at_unix_ms+1",
            "UPDATE dom_payout_face_evidence SET payout_commitment=zeroblob(33)",
            "UPDATE dom_payout_face_evidence SET wallet_ciphertext_digest=zeroblob(32)",
            "UPDATE dom_payout_face_evidence SET store_instance_id=zeroblob(32)",
            "UPDATE dom_session_events SET event_digest=zeroblob(32)",
        ] {
            let (_directory, path, mut store, lease) = setup()?;
            let bound = binding(1, 2)?;
            store.bind_session(lease, bound, 1_000)?;
            activate_payout_face_for_test(
                &mut store,
                lease,
                bound,
                payout_commitment(2)?,
                digest(61),
                1_001,
            )?;
            drop(store);
            let tamper = Connection::open(&path)?;
            tamper.pragma_update(None, "foreign_keys", "OFF")?;
            tamper.execute(statement, [])?;
            drop(tamper);
            require_dom_error(
                DomActuatorStoreV1::open_existing(&path),
                DomActuatorError::UnsupportedFormat,
            )?;
        }
        Ok(())
    }

    // `production_final_claim_v2_contracts_failure_is_never_read_as_unattempted`
    // (P1-C4) is no longer blocked and is no longer a specification. It lives
    // in `contracts.rs`, where the real `ContractsSessionStoreV1` fixture is,
    // and it injects a genuinely unreadable durable record into that store's
    // own artifact directory instead of standing a fake authority up.
    //
    // Three tests remain unwritten, and all three are blocked on the same
    // missing thing rather than on the `0x12` surface, which now exists: a
    // real `PreparedOperationalFinalClaimSubmissionV2` or
    // `PreparedOperationalFinalClaimTransportAuthorityV2`. Only
    // `operational_final_claim_intent_sink_v2` mints the first, and it needs a
    // `ConsumedClaimSigningAuthorizationV2`; reaching that authority means
    // staging the whole productive post-anchor V2 graph — M.8/F7 gate,
    // issuance, consumption, the six real `0x0c..=0x0e` ClaimAdaptor messages
    // and the `0x0f` edge — whose only hermetic entry is the Store's
    // `evidence-only` laboratory seam, which a `ProductionRatified` policy
    // refuses outright.
    //
    // RATIFIED: that seam is not to be wired into this crate. Enabling a
    // laboratory boundary in a production crate to make a test expressible is
    // loosening the fence to reach the fruit, and the fence is the product.
    // These three wait for subtask 5-C, where the graph is staged through a
    // production path, and they are named debt here rather than a silent gap.
    //
    // * `production_final_claim_v2_admission_commits_with_a_real_submission_receipt`.
    //   The positive end-to-end of `complete_operational_final_claim_admission_v2`:
    //   marker durable before the RPC, receipt admitted, owner-only mirror
    //   after. The owner-store tests above use private `cfg(test)` receipt facts
    //   that pass the same canonical receipt validator; those facts cannot
    //   cross the productive Contracts boundary or mint a `SubmissionReceiptV1`.
    //   The end-to-end remains blocked on a real prepared handle plus a
    //   hermetic adapter harness.
    //
    // * `production_final_claim_v2_outbound_stages_class_twenty_one`. The
    //   outbound class-21 staging through
    //   `prepare_final_claim_dsc1_signing_request_v2`, including its negative:
    //   `Ok(None)` means "this node is not the frozen sender" and is not an
    //   error. It needs the transport authority, which is downstream of the
    //   same graph.
    //
    // * `production_final_claim_v2_dispatch_rejects_a_foreign_latched_token`
    //   (P1-C5 runtime half). Latch two sessions and pass the second's token
    //   to the first's dispatch; assert `CapabilityMismatch` and an exact RPC
    //   attempt count of zero. The compile-time half is already total: the
    //   handle has no public constructor, so a dispatch without one cannot be
    //   written at all.
    //
    // `production_final_claim_v2_rpc_holds_no_contracts_store_lock` (FC-27) is
    // deliberately NOT in that list, and an earlier revision of this block was
    // wrong to put it there. It is not waiting on the handle, and 5-C would not
    // unblock it — listing it as 5-C debt promised a test that 5-C cannot
    // deliver. Two separate reasons:
    //
    // * The property is already proved at compile time, the same standing this
    //   block gives the compile-time half of P1-C5.
    //   `PreparedOperationalFinalClaimSubmissionV2` (`session_store.rs:2638`)
    //   holds only owned data — six 32-byte arrays, two `u64` and a `Vec<u8>` —
    //   and carries no `&ContractsSessionStoreV1`; `submit_with`
    //   (`session_store.rs:2760`) does nothing but hand those owned bytes to
    //   the adapter. A handle with no Store reference has no operation lock to
    //   hold, and that is a fact about the type, not about a fixture.
    //
    // * The runtime half's stated contrapositive is not realizable at all, with
    //   or without the handle: the Contracts operation lock is a blocking
    //   `Mutex` (`session_store.rs:8835`), so a thread holding it makes the
    //   reentrant call *block* rather than fail. "Hold the lock and require the
    //   identical call to fail" hangs instead of failing. Anyone who wants the
    //   runtime half must write a timeout-bounded blocking proof, and that is
    //   available today — it needs no post-anchor graph.
    //
    // The reentrancy test below covers the owner-only actuator store, which is
    // the half that genuinely needed a runtime witness.
    //
    // Separately, and no longer missing: the claim verifier now has a producer.
    // `DomContractsActuatorV1::build_retained_claim_verifier_v2` in
    // `contracts.rs` assembles it from this session's own retained Store facts,
    // so `observe_claim_finality` and `observe_final_claim_finality_v2` — which
    // take `&RealDomClaimVerifierV1` and which nothing in the workspace could
    // previously call, because no production caller built one — are reachable
    // in two lines. It has no runtime test here for the same reason as the
    // three above: it takes a `ConsumedClaimSigningAuthorizationV2`. Its error
    // table is proven armwise in `contracts.rs` instead.
    //
    // Still absent, named rather than left to be discovered: nothing builds a
    // `RealDomClaimConsumerV1`, which `extract_observed_claim_secret_v2`
    // consumes. It needs `Arc<RealDomRpcRuntimeV1>` and
    // `Arc<RealDomClaimVerifierV1>`; the second half is now producible here,
    // the first is owned by whoever constructed the runtime. That is an
    // ownership question for the composition root, not a missing authority.
}
