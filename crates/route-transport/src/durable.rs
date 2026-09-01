//! Linux durable recipient inbox for the shared Relay V1 transcript.
//!
//! The Relay is deliberately at-least-once and cannot acknowledge Contracts
//! acceptance.  This authority therefore persists every envelope accepted by
//! the recipient pipeline *before* dispatching its opaque payload.  A crash at
//! that boundary leaves a pending row which is delivered again after reopen;
//! the downstream port must commit idempotently before returning a receipt.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use kaystra_core::types::Digest32;
use relay::auth::{
    accept_envelope, message_type, AuthRefusal, RecipientContextV1, RosterRegistryV1,
    TranscriptStateV1,
};
use relay::server::IdempotencyKeyV1;
use relay::{ParticipantId, RelayEnvelopeV1, TimelockSpec};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use rustix::fs::{flock, FlockOperation};
use rustix::process::geteuid;

use crate::{
    BridgeRefusal, DurableProductionCreationStateV1, RelayQueueV1, RelayQueueV2, RouteWireContextV1,
};

const DATABASE_FILE_NAME: &str = "route-inbox-v1.sqlite3";
const LOCK_FILE_NAME: &str = ".route-inbox.lock";
const ROOT_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const SCHEMA_VERSION: i64 = 2;
const APPLICATION_ID: i64 = 0x444f_4d49; // "DOMI"
const ZERO_DIGEST: Digest32 = [0; 32];
const MAX_INBOX_ENTRIES: u32 = 65_536;
const ENTRY_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-INBOX/ENTRY/V1\0";
const DELIVERY_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-INBOX/DELIVERY/V1\0";
const QUARANTINE_CONTEXT_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-INBOX/QUARANTINE-CONTEXT/V1\0";
const QUARANTINE_RECORD_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-INBOX/QUARANTINE-RECORD/V1\0";
const QUARANTINE_RESOLUTION_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-INBOX/QUARANTINE-RESOLUTION/V1\0";
const QUARANTINE_BYTES_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-INBOX/QUARANTINE-BYTES/V1\0";
const QUARANTINE_COMPACT_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-INBOX/QUARANTINE-COMPACT/V1\0";

#[cfg(test)]
const TEST_QUARANTINE_EXIT_ENV: &str = "DOM_INTEROP_INBOX_TEST_QUARANTINE_EXIT_AFTER";

#[cfg(test)]
fn exit_quarantine_resolution_for_test(boundary: &str) {
    if std::env::var_os(TEST_QUARANTINE_EXIT_ENV).as_deref() == Some(std::ffi::OsStr::new(boundary))
    {
        std::process::exit(86);
    }
}

const SCHEMA_SQL: &str = r#"
CREATE TABLE inbox_meta (
    singleton         INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version    INTEGER NOT NULL CHECK (schema_version = 2),
    inbox_id          BLOB NOT NULL CHECK (length(inbox_id) = 32),
    relay_database_id BLOB NOT NULL CHECK (
        length(relay_database_id) = 32 AND relay_database_id != zeroblob(32)
    ),
    network_id        BLOB NOT NULL CHECK (length(network_id) = 32),
    session_id        BLOB NOT NULL CHECK (length(session_id) = 32),
    route_id          BLOB NOT NULL CHECK (length(route_id) = 32),
    roster_snapshot   BLOB NOT NULL CHECK (length(roster_snapshot) = 32),
    recipient_id      BLOB NOT NULL CHECK (length(recipient_id) = 32),
    policy_version    INTEGER NOT NULL CHECK (policy_version > 0),
    max_entries       INTEGER NOT NULL CHECK (max_entries > 0 AND max_entries <= 65536),
    accepted_count    INTEGER NOT NULL CHECK (accepted_count >= 0 AND accepted_count <= max_entries),
    quarantine_count  INTEGER NOT NULL CHECK (quarantine_count >= 0 AND quarantine_count <= max_entries),
    quarantine_head_digest BLOB NOT NULL CHECK (length(quarantine_head_digest) = 32),
    quarantine_next_ordinal_be BLOB NOT NULL CHECK (length(quarantine_next_ordinal_be) = 8),
    quarantine_compact_sequence_be BLOB NOT NULL CHECK (length(quarantine_compact_sequence_be) = 8),
    quarantine_compact_root BLOB NOT NULL CHECK (length(quarantine_compact_root) = 32),
    quarantine_highest_compacted_relay_ordinal_be BLOB NOT NULL CHECK (
        length(quarantine_highest_compacted_relay_ordinal_be) = 8
    )
) STRICT;

CREATE TABLE inbox_entries (
    ordinal             INTEGER PRIMARY KEY CHECK (ordinal > 0 AND ordinal <= 65536),
    sender_id           BLOB NOT NULL CHECK (length(sender_id) = 32),
    recipient_id        BLOB NOT NULL CHECK (length(recipient_id) = 32),
    sequence_be         BLOB NOT NULL CHECK (length(sequence_be) = 8),
    message_type        INTEGER NOT NULL CHECK (message_type BETWEEN 1 AND 5),
    envelope_digest     BLOB NOT NULL CHECK (length(envelope_digest) = 32),
    canonical_bytes     BLOB NOT NULL CHECK (length(canonical_bytes) <= 16742),
    accepted_now_domain INTEGER NOT NULL CHECK (accepted_now_domain BETWEEN 1 AND 3),
    accepted_now_be     BLOB NOT NULL CHECK (length(accepted_now_be) = 8),
    delivery_state      INTEGER NOT NULL CHECK (delivery_state BETWEEN 0 AND 2),
    delivery_receipt    BLOB NOT NULL CHECK (length(delivery_receipt) = 32),
    row_digest          BLOB NOT NULL CHECK (length(row_digest) = 32),
    delivery_digest     BLOB NOT NULL CHECK (length(delivery_digest) = 32),
    UNIQUE (sender_id, recipient_id, sequence_be),
    CHECK (
        (delivery_state = 0 AND delivery_receipt = zeroblob(32)) OR
        (delivery_state IN (1, 2) AND delivery_receipt != zeroblob(32))
    )
) STRICT;

CREATE TABLE inbox_quarantine (
    ordinal_be          BLOB PRIMARY KEY CHECK (length(ordinal_be) = 8),
    relay_ordinal_be    BLOB NOT NULL UNIQUE CHECK (length(relay_ordinal_be) = 8),
    current_cursor      BLOB NOT NULL UNIQUE CHECK (length(current_cursor) = 146),
    next_cursor         BLOB NOT NULL CHECK (length(next_cursor) = 146),
    sender_id           BLOB NOT NULL CHECK (length(sender_id) = 32),
    recipient_id        BLOB NOT NULL CHECK (length(recipient_id) = 32),
    network_id          BLOB NOT NULL CHECK (length(network_id) = 32),
    session_id          BLOB NOT NULL CHECK (length(session_id) = 32),
    route_id            BLOB NOT NULL CHECK (length(route_id) = 32),
    roster_snapshot     BLOB NOT NULL CHECK (length(roster_snapshot) = 32),
    policy_version      INTEGER NOT NULL CHECK (policy_version > 0),
    reason              INTEGER NOT NULL CHECK (reason BETWEEN 1 AND 22),
    envelope_digest     BLOB NOT NULL CHECK (length(envelope_digest) = 32),
    context_digest      BLOB NOT NULL CHECK (length(context_digest) = 32),
    canonical_bytes     BLOB NOT NULL CHECK (length(canonical_bytes) <= 16742),
    canonical_bytes_digest BLOB NOT NULL CHECK (length(canonical_bytes_digest) = 32),
    quarantined_now_domain INTEGER NOT NULL CHECK (quarantined_now_domain BETWEEN 1 AND 3),
    quarantined_now_be  BLOB NOT NULL CHECK (length(quarantined_now_be) = 8),
    previous_record_digest BLOB NOT NULL CHECK (length(previous_record_digest) = 32),
    record_digest       BLOB NOT NULL UNIQUE CHECK (length(record_digest) = 32),
    resolution_state    INTEGER NOT NULL CHECK (resolution_state BETWEEN 0 AND 2),
    resolution_receipt  BLOB NOT NULL CHECK (length(resolution_receipt) = 32),
    resolution_digest   BLOB NOT NULL CHECK (length(resolution_digest) = 32),
    compact_sequence_be BLOB NOT NULL CHECK (length(compact_sequence_be) = 8),
    previous_compact_root BLOB NOT NULL CHECK (length(previous_compact_root) = 32),
    compact_digest      BLOB NOT NULL CHECK (length(compact_digest) = 32),
    CHECK (
        (resolution_state = 0 AND resolution_receipt = zeroblob(32)) OR
        (resolution_state IN (1, 2) AND resolution_receipt != zeroblob(32))
    ),
    CHECK (
        (length(canonical_bytes) > 0 AND compact_sequence_be = zeroblob(8)
         AND previous_compact_root = zeroblob(32) AND compact_digest = zeroblob(32)) OR
        (length(canonical_bytes) = 0 AND resolution_state IN (1, 2)
         AND compact_sequence_be != zeroblob(8) AND compact_digest != zeroblob(32))
    )
) STRICT;
"#;

/// Immutable identity and wire binding of one durable inbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableInboxConfigV1 {
    inbox_id: Digest32,
    expected_relay_database_id: Digest32,
    wire: RouteWireContextV1,
    recipient_id: ParticipantId,
    max_entries: u32,
}

impl DurableInboxConfigV1 {
    /// Creates a non-null, bounded inbox configuration.
    pub fn new(
        inbox_id: Digest32,
        expected_relay_database_id: Digest32,
        wire: RouteWireContextV1,
        recipient_id: ParticipantId,
        max_entries: u32,
    ) -> Result<Self, DurableInboxError> {
        if inbox_id == ZERO_DIGEST
            || expected_relay_database_id == ZERO_DIGEST
            || wire.network_id == ZERO_DIGEST
            || wire.session_id == ZERO_DIGEST
            || wire.route_id == ZERO_DIGEST
            || wire.roster_snapshot == ZERO_DIGEST
            || recipient_id.0 == ZERO_DIGEST
            || wire.policy_version == 0
            || max_entries == 0
            || max_entries > MAX_INBOX_ENTRIES
        {
            return Err(DurableInboxError::InvalidConfiguration);
        }
        Ok(Self {
            inbox_id,
            expected_relay_database_id,
            wire,
            recipient_id,
            max_entries,
        })
    }

    /// Stable public inbox identity.
    pub const fn inbox_id(&self) -> &Digest32 {
        &self.inbox_id
    }

    /// Frozen production Relay database identity admitted by this inbox.
    pub const fn expected_relay_database_id(&self) -> &Digest32 {
        &self.expected_relay_database_id
    }

    /// Frozen route wire context.
    pub const fn wire_context(&self) -> RouteWireContextV1 {
        self.wire
    }

    /// Participant whose mailbox this authority consumes.
    pub const fn recipient_id(&self) -> ParticipantId {
        self.recipient_id
    }

    /// Maximum accepted envelopes retained by this inbox.
    pub const fn max_entries(&self) -> u32 {
        self.max_entries
    }

    fn recipient_context(&self) -> RecipientContextV1 {
        RecipientContextV1 {
            recipient_id: self.recipient_id,
            network_id: self.wire.network_id,
            session_id: self.wire.session_id,
            route_id: self.wire.route_id,
        }
    }
}

/// Durable inbox failures.  Filesystem and SQLite details are redacted so a
/// caller cannot accidentally log paths, query fragments, or payload bytes.
#[derive(Debug, thiserror::Error)]
pub enum DurableInboxError {
    /// A zero identity, relative/aliased path, unsafe mode, or invalid bound.
    #[error("invalid durable inbox configuration")]
    InvalidConfiguration,
    /// Explicit creation found an existing root.
    #[error("durable inbox root already exists")]
    AlreadyExists,
    /// Reopen found no durable database.
    #[error("durable inbox database is missing")]
    DatabaseMissing,
    /// Retained metadata does not match the expected inbox identity/context.
    #[error("wrong durable inbox identity")]
    WrongIdentity,
    /// The caller supplied a real Relay authority other than the frozen V6
    /// database identity.
    #[error("wrong production relay database identity")]
    WrongRelayDatabase,
    /// A second process already owns this inbox, or storage access failed.
    #[error("durable inbox storage unavailable")]
    StorageUnavailable,
    /// Schema/backend version is not the frozen quarantine-capable V2 format.
    #[error("unsupported durable inbox format")]
    UnsupportedFormat,
    /// Retained rows, digests, or transcript do not authenticate.
    #[error("corrupt durable inbox state")]
    CorruptState,
    /// The configured bounded inbox is full.
    #[error("durable inbox capacity exhausted")]
    CapacityExceeded,
    /// The Relay queue could not return its mailbox.
    #[error("relay queue unavailable: {0}")]
    Queue(BridgeRefusal),
    /// A consumer returned a zero/non-durable receipt.
    #[error("consumer returned an invalid durable receipt")]
    InvalidConsumerCommit,
    /// One Relay ordinal/cursor was presented with different exact bytes or
    /// quarantine context.
    #[error("durable quarantine equivocation")]
    QuarantineEquivocation,
    /// A Relay position at or below the compacted watermark no longer has an
    /// exact retained receipt and cannot be safely acknowledged again.
    #[error("compacted quarantine replay is outside the retained receipt window")]
    CompactedQuarantineReplay,
}

impl From<rusqlite::Error> for DurableInboxError {
    fn from(_: rusqlite::Error) -> Self {
        Self::StorageUnavailable
    }
}

/// Per-envelope refusal retained in an ingest report.  Refused envelopes do
/// not move the durable transcript and their opaque payload is never exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableInboxEnvelopeRefusalV1 {
    /// The canonical Relay recipient pipeline refused the envelope.
    Pipeline(AuthRefusal),
    /// The envelope selected a different frozen roster snapshot.
    WrongRosterSnapshot,
    /// The envelope selected a different frozen protocol policy version.
    WrongPolicyVersion,
    /// A different canonical envelope reused an already durable flow key.
    DurableEquivocation,
}

/// Closed, stable reason retained for one Relay envelope that was durably
/// quarantined before its page was acknowledged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DurableQuarantineReasonV1 {
    /// Envelope selected a roster other than the frozen inbox roster.
    WrongRosterSnapshot = 1,
    /// Envelope selected a policy other than the frozen inbox policy.
    WrongPolicyVersion = 2,
    /// Canonical authentication found a foreign network.
    WrongNetwork = 3,
    /// Canonical authentication found a foreign recipient.
    WrongRecipient = 4,
    /// Canonical authentication found a foreign session.
    WrongSession = 5,
    /// Canonical authentication found a foreign route.
    WrongRoute = 6,
    /// Envelope was expired at the authenticated observation time.
    Expired = 7,
    /// Envelope expiry used the wrong timelock domain.
    WrongTimelockDomain = 8,
    /// Referenced roster snapshot was unavailable.
    UnknownRosterSnapshot = 9,
    /// Claimed sender was absent from the selected roster.
    SenderNotInRoster = 10,
    /// Claimed sender role disagreed with the roster.
    RoleMismatch = 11,
    /// Roster role was not permitted to emit this message kind.
    RoleNotPermitted = 12,
    /// BIP340 envelope signature did not authenticate.
    InvalidSignature = 13,
    /// Recipient transcript classified the position as a duplicate.
    Duplicate = 14,
    /// Recipient transcript classified the position as equivocation.
    Equivocation = 15,
    /// Recipient transcript classified the position as stale.
    StaleSequence = 16,
    /// Recipient transcript requires an earlier sequence first.
    SequenceGap = 17,
    /// Envelope did not extend the authenticated transcript digest.
    TranscriptDiscontinuity = 18,
    /// Selected roster public key was unusable.
    UnusableRosterKey = 19,
    /// Recipient transcript reached its configured hard bound.
    TranscriptTooLarge = 20,
    /// Reserved fail-closed code for bytes that cannot be decoded. Production
    /// cannot ACK this reason because no authenticated sender can be bound.
    NonCanonicalEnvelope = 21,
    /// Different bytes reused a key already retained by this inbox.
    DurableEquivocation = 22,
}

impl DurableQuarantineReasonV1 {
    fn from_code(code: u8) -> Result<Self, DurableInboxError> {
        match code {
            1 => Ok(Self::WrongRosterSnapshot),
            2 => Ok(Self::WrongPolicyVersion),
            3 => Ok(Self::WrongNetwork),
            4 => Ok(Self::WrongRecipient),
            5 => Ok(Self::WrongSession),
            6 => Ok(Self::WrongRoute),
            7 => Ok(Self::Expired),
            8 => Ok(Self::WrongTimelockDomain),
            9 => Ok(Self::UnknownRosterSnapshot),
            10 => Ok(Self::SenderNotInRoster),
            11 => Ok(Self::RoleMismatch),
            12 => Ok(Self::RoleNotPermitted),
            13 => Ok(Self::InvalidSignature),
            14 => Ok(Self::Duplicate),
            15 => Ok(Self::Equivocation),
            16 => Ok(Self::StaleSequence),
            17 => Ok(Self::SequenceGap),
            18 => Ok(Self::TranscriptDiscontinuity),
            19 => Ok(Self::UnusableRosterKey),
            20 => Ok(Self::TranscriptTooLarge),
            21 => Ok(Self::NonCanonicalEnvelope),
            22 => Ok(Self::DurableEquivocation),
            _ => Err(DurableInboxError::CorruptState),
        }
    }
}

/// Explicit outcome an external quarantine authority may authorize.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DurableQuarantineResolutionV1 {
    /// Retry canonical recipient authentication; success is still determined
    /// by that pipeline and is never implied by this authority.
    Reprocess = 1,
    /// Retain the evidence and close it as an explicit failed-closed release.
    ReleaseFailedClosed = 2,
}

/// Borrowed exact quarantine evidence presented only to an explicit external
/// resolution authority. Debug is manually redacted and never prints bytes.
pub struct DurableQuarantineResolutionRequestV1<'a> {
    ordinal: u64,
    relay_ordinal: u64,
    record_digest: Digest32,
    reason: DurableQuarantineReasonV1,
    sender_id: ParticipantId,
    recipient_id: ParticipantId,
    wire: RouteWireContextV1,
    current_cursor: relay::production::DeliveryCursorV2,
    next_cursor: relay::production::DeliveryCursorV2,
    canonical_bytes: &'a [u8],
}

impl core::fmt::Debug for DurableQuarantineResolutionRequestV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DurableQuarantineResolutionRequestV1")
            .field("ordinal", &self.ordinal)
            .field("relay_ordinal", &self.relay_ordinal)
            .field("record_digest", &self.record_digest)
            .field("reason", &self.reason)
            .field("sender_id", &self.sender_id)
            .field("recipient_id", &self.recipient_id)
            .field("wire", &self.wire)
            .field("current_cursor", &self.current_cursor)
            .field("next_cursor", &self.next_cursor)
            .field("canonical_bytes", &"[redacted]")
            .finish()
    }
}

impl DurableQuarantineResolutionRequestV1<'_> {
    /// Local monotonic quarantine record ordinal.
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Monotonic ordinal assigned by the durable Relay database.
    pub const fn relay_ordinal(&self) -> u64 {
        self.relay_ordinal
    }

    /// Authenticated digest of the complete retained quarantine record.
    pub const fn record_digest(&self) -> &Digest32 {
        &self.record_digest
    }

    /// Closed reason recorded before Relay acknowledgement.
    pub const fn reason(&self) -> DurableQuarantineReasonV1 {
        self.reason
    }

    /// Sender claimed by the exact canonical envelope.
    pub const fn sender_id(&self) -> ParticipantId {
        self.sender_id
    }

    /// Frozen recipient authority consuming this Relay page.
    pub const fn recipient_id(&self) -> ParticipantId {
        self.recipient_id
    }

    /// Frozen route/network/session/roster/policy context.
    pub const fn wire_context(&self) -> RouteWireContextV1 {
        self.wire
    }

    /// Cursor immediately before the quarantined Relay ordinal.
    pub const fn current_cursor(&self) -> relay::production::DeliveryCursorV2 {
        self.current_cursor
    }

    /// Cursor the Relay advanced only after this record became durable.
    pub const fn next_cursor(&self) -> relay::production::DeliveryCursorV2 {
        self.next_cursor
    }

    /// Exact bounded envelope bytes. They are intentionally available only at
    /// this explicit authority boundary and are redacted from Debug/errors.
    pub const fn canonical_bytes(&self) -> &[u8] {
        self.canonical_bytes
    }
}

/// Durable decision returned by an explicit quarantine authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableQuarantineResolutionCommitV1 {
    record_digest: Digest32,
    resolution: DurableQuarantineResolutionV1,
    durable_receipt: Digest32,
    duplicate: bool,
}

impl DurableQuarantineResolutionCommitV1 {
    /// Creates an exact nonzero durable authority receipt.
    pub fn new(
        record_digest: Digest32,
        resolution: DurableQuarantineResolutionV1,
        durable_receipt: Digest32,
        duplicate: bool,
    ) -> Result<Self, DurableInboxError> {
        if record_digest == ZERO_DIGEST || durable_receipt == ZERO_DIGEST {
            return Err(DurableInboxError::InvalidConsumerCommit);
        }
        Ok(Self {
            record_digest,
            resolution,
            durable_receipt,
            duplicate,
        })
    }
}

/// External owner that must durably authorize every quarantine reprocess or
/// failed-closed release. There is no default or permissive implementation.
pub trait DurableQuarantineAuthorityV1 {
    /// Redacted external authority error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Durably authorizes exactly one record-bound action before returning.
    fn authorize_resolution(
        &mut self,
        request: DurableQuarantineResolutionRequestV1<'_>,
    ) -> Result<DurableQuarantineResolutionCommitV1, Self::Error>;
}

/// Redacted result of one durably retained explicit resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableQuarantineResolutionReportV1 {
    /// Explicit action durably authorized and retained.
    pub resolution: DurableQuarantineResolutionV1,
    /// Whether the external authority recognized an exact prior commit.
    pub duplicate_commit: bool,
}

/// Failure while resolving an already durable quarantine record.
#[derive(Debug, thiserror::Error)]
pub enum DurableQuarantineResolutionErrorV1<E: std::error::Error + Send + Sync + 'static> {
    /// Inbox state or the authority receipt failed validation.
    #[error("durable inbox: {0}")]
    Inbox(#[source] DurableInboxError),
    /// External quarantine authority refused or was unavailable.
    #[error("quarantine authority: {0}")]
    Authority(#[source] E),
    /// Explicit reprocessing was authorized but canonical validation still
    /// refused the envelope; no inbox resolution was recorded.
    #[error("quarantine envelope remains refused")]
    StillRefused,
}

/// Result of pulling and durably authenticating one at-least-once mailbox.
#[derive(Debug, Default)]
pub struct DurableInboxIngestReportV1 {
    /// Newly authenticated envelopes committed before this call returned.
    pub accepted: usize,
    /// Exact already-durable envelopes observed again.
    pub duplicates: usize,
    /// Individually named refusals; other mailbox entries were still tried.
    pub refused: Vec<DurableInboxEnvelopeRefusalV1>,
    /// Newly durable quarantine records committed before Relay ACK.
    pub quarantined: usize,
    /// Exact quarantine records redelivered after ACK loss.
    pub quarantine_duplicates: usize,
}

/// Current durable inbox counters, split so route and F6 backlogs cannot hide
/// each other.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DurableInboxStatsV1 {
    /// Route/DSC1 envelopes awaiting Contracts acceptance.
    pub pending_route: usize,
    /// F6 envelopes awaiting the F6 consumer.
    pub pending_f6: usize,
    /// Payloads committed by their downstream authority.
    pub delivered: usize,
    /// Payloads whose downstream authority durably failed closed.
    pub failed_closed: usize,
    /// Refused Relay envelopes retained pending explicit resolution.
    pub quarantined: usize,
    /// Resolved raw records durably awaiting the separate compaction commit.
    pub quarantine_resolved_pending_compaction: usize,
    /// Total bounded quarantine rows currently retained. Resolved rows carry
    /// compact receipts rather than claiming that full historical raw exists.
    pub quarantine_retained: usize,
    /// Reprocess receipts retained in the bounded compact window.
    pub quarantine_reprocessed: usize,
    /// Failed-closed release receipts retained in the bounded compact window.
    pub quarantine_released: usize,
}

/// Downstream durable disposition.  Both variants are terminal for the inbox:
/// either the state-machine transition is durable or that authority durably
/// quarantined/failed closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurablePayloadDispositionV1 {
    /// The downstream state-machine transition is durable.
    Applied,
    /// The downstream authority durably failed closed.
    FailedClosed,
}

/// Opaque proof returned only after a downstream authority made its result
/// durable.  The nonzero receipt is persisted by the inbox before the row is
/// removed from the pending set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurablePayloadCommitV1 {
    disposition: DurablePayloadDispositionV1,
    durable_receipt: Digest32,
    duplicate: bool,
}

impl DurablePayloadCommitV1 {
    /// Creates a downstream durable commit.  A zero receipt is refused because
    /// it cannot bind a redelivery to any durable result.
    pub fn new(
        disposition: DurablePayloadDispositionV1,
        durable_receipt: Digest32,
        duplicate: bool,
    ) -> Result<Self, DurableInboxError> {
        if durable_receipt == ZERO_DIGEST {
            return Err(DurableInboxError::InvalidConsumerCommit);
        }
        Ok(Self {
            disposition,
            durable_receipt,
            duplicate,
        })
    }

    /// Durable downstream disposition.
    pub const fn disposition(&self) -> DurablePayloadDispositionV1 {
        self.disposition
    }

    /// Opaque nonzero downstream receipt.
    pub const fn durable_receipt(&self) -> &Digest32 {
        &self.durable_receipt
    }

    /// Whether the downstream authority recognized an exact prior commit.
    pub const fn duplicate(&self) -> bool {
        self.duplicate
    }
}

/// Borrowed, already Relay-authenticated route payload delivered to Contracts.
/// No constructor is public; only [`DurableRelayInboxV1`] can issue it.
pub struct ContractsRouteDeliveryV1<'a> {
    sender_id: ParticipantId,
    sequence: u64,
    envelope_digest: Digest32,
    evidence: ContractsRouteDeliveryEvidenceV2,
    payload: &'a [u8],
}

/// Authentication evidence represented by a Contracts delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractsRouteDeliveryEvidenceV2 {
    /// One direct V1 payload authenticated by its single outer Relay envelope.
    DirectRelayEnvelopeV1,
    /// One complete DSC1 object authenticated by every V2 frame and represented
    /// by their shared frame-set binding digest.
    ReassembledRouteFramesV2,
}

impl ContractsRouteDeliveryV1<'_> {
    #[cfg(test)]
    pub(crate) const fn from_authenticated_parts(
        sender_id: ParticipantId,
        sequence: u64,
        delivery_digest: Digest32,
        payload: &[u8],
    ) -> ContractsRouteDeliveryV1<'_> {
        ContractsRouteDeliveryV1 {
            sender_id,
            sequence,
            envelope_digest: delivery_digest,
            evidence: ContractsRouteDeliveryEvidenceV2::DirectRelayEnvelopeV1,
            payload,
        }
    }

    pub(crate) const fn from_reassembled_parts(
        sender_id: ParticipantId,
        first_sequence: u64,
        binding_digest: Digest32,
        payload: &[u8],
    ) -> ContractsRouteDeliveryV1<'_> {
        ContractsRouteDeliveryV1 {
            sender_id,
            sequence: first_sequence,
            envelope_digest: binding_digest,
            evidence: ContractsRouteDeliveryEvidenceV2::ReassembledRouteFramesV2,
            payload,
        }
    }

    /// Relay-roster-authenticated sender.
    pub const fn sender_id(&self) -> ParticipantId {
        self.sender_id
    }

    /// Shared-flow sequence accepted by the single inbox transcript.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Delivery evidence digest. For direct V1 this is the exact outer Relay
    /// envelope digest; after authenticated V2 reassembly it is the frame-set
    /// binding digest committed by every contributing outer envelope.
    pub const fn envelope_digest(&self) -> &Digest32 {
        &self.envelope_digest
    }

    /// Whether the evidence is one direct Relay envelope or a complete,
    /// authenticated V2 frame set.
    pub const fn delivery_evidence(&self) -> ContractsRouteDeliveryEvidenceV2 {
        self.evidence
    }

    /// Exact opaque DSC1 bytes carried by the envelope.
    pub const fn signed_dsc1(&self) -> &[u8] {
        self.payload
    }
}

/// Strict Contracts boundary used by the relay worker.
///
/// This API intentionally has no `SessionRecordV1` successor argument.  A
/// composition root must adapt an authority that derives and validates its
/// own successor (for example a phase-specific Contracts Store method); the
/// relay worker cannot manufacture a session transition from untrusted input.
pub trait ContractsTransportPortV1 {
    /// Redacted Contracts authority error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Authenticates and durably commits the exact DSC1 payload before
    /// returning.  Exact redelivery must return a duplicate durable commit.
    fn accept_signed_dsc1(
        &mut self,
        delivery: ContractsRouteDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error>;
}

/// Borrowed, already Relay-authenticated F6 payload delivered from the same
/// durable transcript as route traffic.
pub struct F6PayloadDeliveryV1<'a> {
    sender_id: ParticipantId,
    sequence: u64,
    message_type: u16,
    envelope_digest: Digest32,
    payload: &'a [u8],
}

impl F6PayloadDeliveryV1<'_> {
    /// Relay-roster-authenticated sender.
    pub const fn sender_id(&self) -> ParticipantId {
        self.sender_id
    }

    /// Shared-flow sequence accepted by the single inbox transcript.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// One of the closed F6 kinds `RFQ`, `QUOTE`, `ACCEPTANCE`, or
    /// `SELECTION`.
    pub const fn message_type(&self) -> u16 {
        self.message_type
    }

    /// Digest of the exact outer Relay envelope.
    pub const fn envelope_digest(&self) -> &Digest32 {
        &self.envelope_digest
    }

    /// Exact opaque F6 object bytes.
    pub const fn payload(&self) -> &[u8] {
        self.payload
    }
}

/// Strict F6 consumer boundary owned by the same inbox as Contracts traffic.
/// A separate worker cannot construct or advance a second transcript.
pub trait F6TransportPortV1 {
    /// Redacted F6 engine error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Durably consumes one authenticated F6 object before returning.  Exact
    /// redelivery must return a duplicate durable commit.
    fn accept_f6(
        &mut self,
        delivery: F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error>;
}

/// Summary of one route-payload drain.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RouteDispatchReportV1 {
    /// Newly or idempotently applied Contracts payloads.
    pub applied: usize,
    /// Contracts payloads that durably failed the session closed.
    pub failed_closed: usize,
    /// Calls recognized by Contracts as exact prior commits after redelivery.
    pub duplicate_commits: usize,
    /// Route rows held because an earlier F6 row in the same flow is pending.
    pub blocked_by_f6: usize,
}

/// Route drain failure.  A failed row remains pending and is retried after
/// recovery; already marked rows are never sent again.
#[derive(Debug, thiserror::Error)]
pub enum RouteDispatchErrorV1<E: std::error::Error + Send + Sync + 'static> {
    /// Inbox storage failed before the delivery outcome became durable.
    #[error("durable inbox: {0}")]
    Inbox(#[source] DurableInboxError),
    /// The Contracts authority refused or was unavailable.
    #[error("contracts transport port: {0}")]
    Contracts(#[source] E),
}

/// Summary of one F6-payload drain.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct F6DispatchReportV1 {
    /// Newly or idempotently applied F6 payloads.
    pub applied: usize,
    /// F6 payloads that durably failed the route negotiation closed.
    pub failed_closed: usize,
    /// Calls recognized by the F6 authority as exact prior commits.
    pub duplicate_commits: usize,
    /// F6 rows held because an earlier route row in the same flow is pending.
    pub blocked_by_route: usize,
}

/// F6 drain failure.  The exact row remains pending for restart-safe retry.
#[derive(Debug, thiserror::Error)]
pub enum F6DispatchErrorV1<E: std::error::Error + Send + Sync + 'static> {
    /// Inbox storage failed before the delivery outcome became durable.
    #[error("durable inbox: {0}")]
    Inbox(#[source] DurableInboxError),
    /// The F6 authority refused or was unavailable.
    #[error("F6 transport port: {0}")]
    F6(#[source] E),
}

/// Read-only recovery report for previously applied F6 deliveries.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct F6AppliedReplayReportV1 {
    /// Applied F6 rows whose downstream authority returned the exact retained
    /// receipt as an idempotent duplicate.
    pub replayed: usize,
}

/// Recovery failure while authenticating previously applied F6 history.
#[derive(Debug, thiserror::Error)]
pub enum F6AppliedReplayErrorV1<E: std::error::Error + Send + Sync + 'static> {
    /// Inbox storage or a retained receipt diverged from authenticated state.
    #[error("durable inbox: {0}")]
    Inbox(#[source] DurableInboxError),
    /// The F6 authority could not resume or revalidate the retained delivery.
    #[error("F6 transport port: {0}")]
    F6(#[source] E),
}

#[derive(Clone)]
struct StoredEntryV1 {
    ordinal: i64,
    sender_id: ParticipantId,
    recipient_id: ParticipantId,
    sequence: u64,
    message_type: u16,
    envelope_digest: Digest32,
    canonical_bytes: Vec<u8>,
    accepted_now: TimelockSpec,
    delivery_state: u8,
    delivery_receipt: Digest32,
    row_digest: Digest32,
}

#[derive(Clone)]
struct StoredQuarantineV1 {
    ordinal: u64,
    relay_ordinal: u64,
    current_cursor: relay::production::DeliveryCursorV2,
    next_cursor: relay::production::DeliveryCursorV2,
    sender_id: ParticipantId,
    envelope_recipient_id: ParticipantId,
    envelope_network_id: Digest32,
    envelope_session_id: Digest32,
    envelope_route_id: Digest32,
    envelope_roster_snapshot: Digest32,
    envelope_policy_version: u32,
    reason: DurableQuarantineReasonV1,
    envelope_digest: Digest32,
    context_digest: Digest32,
    canonical_bytes: Vec<u8>,
    canonical_bytes_digest: Digest32,
    previous_record_digest: Digest32,
    record_digest: Digest32,
    resolution_state: u8,
    resolution_receipt: Digest32,
    compact_sequence: u64,
    previous_compact_root: Digest32,
    compact_digest: Digest32,
}

enum IngestOneOutcomeV1 {
    Processed,
    Refused(DurableQuarantineReasonV1),
    Unquarantinable,
}

struct InboxMetaRowV2 {
    version: i64,
    inbox: Vec<u8>,
    relay_database: Vec<u8>,
    network: Vec<u8>,
    session: Vec<u8>,
    route: Vec<u8>,
    roster: Vec<u8>,
    recipient: Vec<u8>,
    policy: i64,
    max: i64,
    accepted_count: i64,
    quarantine_count: i64,
    quarantine_head_digest: Vec<u8>,
    quarantine_next_ordinal: Vec<u8>,
    quarantine_compact_sequence: Vec<u8>,
    quarantine_compact_root: Vec<u8>,
    quarantine_highest_compacted_relay_ordinal: Vec<u8>,
}

#[derive(Default)]
struct QuarantineStatsInternalV1 {
    unresolved_raw: usize,
    resolved_raw: usize,
    compact_reprocessed: usize,
    compact_released: usize,
    retained_rows: usize,
}

struct QuarantineAuditMetaV1 {
    pending_count: i64,
    head_digest: Vec<u8>,
    next_ordinal: Vec<u8>,
    compact_sequence: Vec<u8>,
    compact_root: Vec<u8>,
    highest_compacted_relay_ordinal: Vec<u8>,
}

/// Retained single-writer inbox and the sole recipient transcript authority
/// for F6 plus route messages of one session.
pub struct DurableRelayInboxV1 {
    connection: Connection,
    root: PathBuf,
    config: DurableInboxConfigV1,
    _database_authority: File,
    _sqlite_database_authority: File,
    _lock: File,
}

impl core::fmt::Debug for DurableRelayInboxV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DurableRelayInboxV1")
            .field("inbox_id", &self.config.inbox_id)
            .field("session_id", &self.config.wire.session_id)
            .field("root", &"[redacted]")
            .finish()
    }
}

impl DurableRelayInboxV1 {
    /// Highest timestamp-domain acceptance/quarantine time already committed
    /// by this inbox. Big-endian storage makes SQLite's BLOB maximum identical
    /// to the numeric maximum. Callers use this as a durable rollback floor;
    /// no caller-supplied time is persisted merely by reading it.
    pub fn retained_timestamp_floor(&self) -> Result<Option<u64>, DurableInboxError> {
        let accepted: Option<Vec<u8>> = self.connection.query_row(
            "SELECT MAX(accepted_now_be) FROM inbox_entries WHERE accepted_now_domain = 2",
            [],
            |row| row.get(0),
        )?;
        let quarantined: Option<Vec<u8>> = self.connection.query_row(
            "SELECT MAX(quarantined_now_be) FROM inbox_quarantine WHERE quarantined_now_domain = 2",
            [],
            |row| row.get(0),
        )?;
        let accepted = accepted.as_deref().map(as_u64_be).transpose()?;
        let quarantined = quarantined.as_deref().map(as_u64_be).transpose()?;
        Ok(match (accepted, quarantined) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        })
    }

    /// Creates a brand-new owner-only inbox and audits its empty transcript.
    pub fn create(
        root: &Path,
        config: DurableInboxConfigV1,
        rosters: &RosterRegistryV1,
    ) -> Result<Self, DurableInboxError> {
        create_root(root)?;
        let lock = acquire_lock(root, true)?;
        let database_path = root.join(DATABASE_FILE_NAME);
        let database_authority = create_database_authority(&database_path)?;
        let (connection, sqlite_database_authority) = open_connection_via_authority(
            &database_authority,
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        validate_connection_authority(
            &database_authority,
            &sqlite_database_authority,
            &database_path,
        )?;
        configure_connection(&connection)?;
        initialize_pristine_store(&connection, config)?;
        connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .map_err(|_| DurableInboxError::StorageUnavailable)?;
        sync_directory(root)?;
        let inbox = Self {
            connection,
            root: root.to_path_buf(),
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        inbox.validate_storage()?;
        inbox.audit_transcript(rosters)?;
        Ok(inbox)
    }

    /// Resumes only a pristine prefix of an explicitly journaled production
    /// create. Missing/empty roots and empty SQLite files are completed;
    /// initialized authorities are accepted only while their transcript is
    /// still empty. Foreign schema/identity, extra files, hard-link
    /// transplants and every accepted economic envelope are refused.
    pub fn resume_create_production(
        root: &Path,
        config: DurableInboxConfigV1,
        rosters: &RosterRegistryV1,
    ) -> Result<Self, DurableInboxError> {
        let lock = acquire_resume_lock(root)?;
        let database_path = root.join(DATABASE_FILE_NAME);
        let database_exists = database_path
            .try_exists()
            .map_err(|_| DurableInboxError::StorageUnavailable)?;
        validate_resumable_database_files(root, database_exists)?;
        let database_authority = if database_exists {
            open_database_authority(&database_path)?
        } else {
            create_database_authority(&database_path)?
        };
        let state = preflight_resumable_database(&database_path, &database_authority, &config)?;
        let (connection, sqlite_database_authority) = open_connection_via_authority(
            &database_authority,
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        validate_connection_authority(
            &database_authority,
            &sqlite_database_authority,
            &database_path,
        )?;
        validate_database_path(&connection, &database_path)?;
        let revalidated = classify_resumable_connection(&connection, &config)?;
        if revalidated != state {
            return Err(DurableInboxError::InvalidConfiguration);
        }
        configure_connection(&connection)?;
        validate_connection_authority(
            &database_authority,
            &sqlite_database_authority,
            &database_path,
        )?;
        match state {
            DurableProductionCreationStateV1::Incomplete => {
                initialize_pristine_store(&connection, config)?;
            }
            DurableProductionCreationStateV1::InitializedPristine => {
                require_pristine_connection(&connection, &config)?;
            }
            DurableProductionCreationStateV1::Missing => {
                return Err(DurableInboxError::CorruptState)
            }
        }
        let inbox = Self {
            connection,
            root: root.to_path_buf(),
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        inbox.validate_storage()?;
        inbox.audit_transcript(rosters)?;
        inbox.require_pristine_creation_state()?;
        inbox
            .connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .map_err(|_| DurableInboxError::StorageUnavailable)?;
        sync_directory(root)?;
        Ok(inbox)
    }

    /// Performs the non-mutating half of production resume planning.
    pub fn production_creation_state(
        root: &Path,
        config: DurableInboxConfigV1,
    ) -> Result<DurableProductionCreationStateV1, DurableInboxError> {
        inspect_creation_state(root, &config)
    }

    /// Reopens the exact existing inbox, validates every retained row and
    /// reconstructs the shared transcript from recorded acceptance times.
    pub fn open(
        root: &Path,
        expected: DurableInboxConfigV1,
        rosters: &RosterRegistryV1,
    ) -> Result<Self, DurableInboxError> {
        validate_root(root)?;
        validate_root_entries(root)?;
        let lock = acquire_lock(root, false)?;
        let database_path = root.join(DATABASE_FILE_NAME);
        if !database_path
            .try_exists()
            .map_err(|_| DurableInboxError::StorageUnavailable)?
        {
            return Err(DurableInboxError::DatabaseMissing);
        }
        validate_owner_file(&database_path)?;
        let database_authority = open_database_authority(&database_path)?;
        let (connection, sqlite_database_authority) = open_connection_via_authority(
            &database_authority,
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        validate_connection_authority(
            &database_authority,
            &sqlite_database_authority,
            &database_path,
        )?;
        validate_database_path(&connection, &database_path)?;
        let inbox = Self {
            connection,
            root: root.to_path_buf(),
            config: expected,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        inbox.validate_storage()?;
        inbox.audit_transcript(rosters)?;
        let Self {
            connection,
            root,
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        } = inbox;
        drop(connection);
        drop(sqlite_database_authority);
        validate_database_authority(&database_authority, &database_path)?;
        let (connection, sqlite_database_authority) = open_connection_via_authority(
            &database_authority,
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        validate_connection_authority(
            &database_authority,
            &sqlite_database_authority,
            &database_path,
        )?;
        validate_database_path(&connection, &database_path)?;
        let rw_preflight = Self {
            connection,
            root,
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        rw_preflight.validate_storage()?;
        rw_preflight.audit_transcript(rosters)?;
        let Self {
            connection,
            root,
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        } = rw_preflight;
        configure_connection(&connection)?;
        let inbox = Self {
            connection,
            root,
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        inbox.validate_storage()?;
        inbox.audit_transcript(rosters)?;
        Ok(inbox)
    }

    /// Pulls the queue mailbox, authenticates all known kinds through one
    /// shared transcript, and commits each accepted envelope before counting
    /// it as accepted.  Exact Relay redelivery is a no-op.
    pub fn ingest_ephemeral_v1<Q: RelayQueueV1>(
        &mut self,
        queue: &Q,
        rosters: &RosterRegistryV1,
        now: TimelockSpec,
    ) -> Result<DurableInboxIngestReportV1, DurableInboxError> {
        let mut state = self.reconstruct_transcript(rosters)?;
        let mailbox = queue
            .queue_deliver_ephemeral_v1(&self.config.recipient_id)
            .map_err(DurableInboxError::Queue)?;
        let mut report = DurableInboxIngestReportV1::default();
        for raw in mailbox {
            let _outcome = self.ingest_one(&raw, rosters, now, &mut state, &mut report)?;
        }
        Ok(report)
    }

    /// Pulls exactly one bounded production page, persists the accepted
    /// envelope before advancing the Relay cursor, and acknowledges only a
    /// fully processed page. A crash after local persistence but before the
    /// Relay ACK therefore becomes one exact duplicate on retry.
    ///
    /// A refused canonical head envelope advances only after its exact bytes,
    /// Relay position, frozen context, closed reason and chained record digest
    /// are committed to the bounded quarantine. Non-canonical bytes or a full
    /// quarantine remain pending and are never acknowledged.
    pub fn ingest(
        &mut self,
        queue: &mut relay::production::ProductionRelayV1,
        rosters: &RosterRegistryV1,
        now: TimelockSpec,
    ) -> Result<DurableInboxIngestReportV1, DurableInboxError> {
        self.ingest_v2(queue, rosters, now)
    }

    fn ingest_v2<Q: RelayQueueV2>(
        &mut self,
        queue: &mut Q,
        rosters: &RosterRegistryV1,
        now: TimelockSpec,
    ) -> Result<DurableInboxIngestReportV1, DurableInboxError> {
        if queue.queue_database_id_v2().as_bytes() != &self.config.expected_relay_database_id {
            return Err(DurableInboxError::WrongRelayDatabase);
        }
        let recipient = self.config.recipient_id;
        let current = queue
            .queue_acknowledged_cursor_v2(&recipient)
            .map_err(DurableInboxError::Queue)?;
        let limits =
            relay::production::DeliveryPageLimitsV2::new(1, relay::MAX_ENVELOPE_BYTES as u32)
                .map_err(|error| DurableInboxError::Queue(BridgeRefusal::DurableRelay(error)))?;
        let page = queue
            .queue_delivery_page_v2(&recipient, &current, limits)
            .map_err(DurableInboxError::Queue)?;
        if page.envelopes().is_empty() {
            if page.current_cursor() != page.next_cursor() || page.has_more() {
                return Err(DurableInboxError::CorruptState);
            }
            return Ok(DurableInboxIngestReportV1::default());
        }
        if page.envelopes().len() != 1
            || page.ordinals().len() != 1
            || page.current_cursor() != &current
        {
            return Err(DurableInboxError::CorruptState);
        }
        let mut state = self.reconstruct_transcript(rosters)?;
        let mut report = DurableInboxIngestReportV1::default();
        let outcome =
            self.ingest_one(&page.envelopes()[0], rosters, now, &mut state, &mut report)?;
        let fully_processed = match outcome {
            IngestOneOutcomeV1::Processed => true,
            IngestOneOutcomeV1::Refused(reason) => {
                let duplicate = self.persist_quarantine(
                    page.ordinals()[0],
                    page.current_cursor(),
                    page.next_cursor(),
                    &page.envelopes()[0],
                    reason,
                    now,
                )?;
                if duplicate {
                    report.quarantine_duplicates += 1;
                } else {
                    report.quarantined += 1;
                }
                true
            }
            IngestOneOutcomeV1::Unquarantinable => false,
        };
        if fully_processed {
            let ack = queue
                .queue_acknowledge_delivery_page_v2(&recipient, page.next_cursor())
                .map_err(DurableInboxError::Queue)?;
            if ack.cursor() != page.next_cursor() {
                return Err(DurableInboxError::CorruptState);
            }
        }
        Ok(report)
    }

    fn ingest_one(
        &mut self,
        raw: &[u8],
        rosters: &RosterRegistryV1,
        now: TimelockSpec,
        state: &mut TranscriptStateV1,
        report: &mut DurableInboxIngestReportV1,
    ) -> Result<IngestOneOutcomeV1, DurableInboxError> {
        let envelope =
            match RelayEnvelopeV1::decode(raw) {
                Ok(envelope) => envelope,
                Err(error) => {
                    report.refused.push(DurableInboxEnvelopeRefusalV1::Pipeline(
                        AuthRefusal::Codec(error),
                    ));
                    return Ok(IngestOneOutcomeV1::Unquarantinable);
                }
            };
        if envelope.roster_snapshot != self.config.wire.roster_snapshot {
            report
                .refused
                .push(DurableInboxEnvelopeRefusalV1::WrongRosterSnapshot);
            return Ok(IngestOneOutcomeV1::Refused(
                DurableQuarantineReasonV1::WrongRosterSnapshot,
            ));
        }
        if envelope.policy_version != self.config.wire.policy_version {
            report
                .refused
                .push(DurableInboxEnvelopeRefusalV1::WrongPolicyVersion);
            return Ok(IngestOneOutcomeV1::Refused(
                DurableQuarantineReasonV1::WrongPolicyVersion,
            ));
        }
        let key = IdempotencyKeyV1::of(&envelope);
        if let Some(existing) = self.entry_by_key(&key)? {
            if existing.canonical_bytes == raw {
                report.duplicates += 1;
                return Ok(IngestOneOutcomeV1::Processed);
            } else {
                report
                    .refused
                    .push(DurableInboxEnvelopeRefusalV1::DurableEquivocation);
                return Ok(IngestOneOutcomeV1::Refused(
                    DurableQuarantineReasonV1::DurableEquivocation,
                ));
            }
        }
        let accepted = match accept_envelope(
            raw,
            &self.config.recipient_context(),
            rosters,
            &mut *state,
            now,
        ) {
            Ok(accepted) => accepted,
            Err(refusal) => {
                report
                    .refused
                    .push(DurableInboxEnvelopeRefusalV1::Pipeline(refusal));
                return Ok(match quarantine_reason_from_auth_refusal(refusal) {
                    Some(reason) => IngestOneOutcomeV1::Refused(reason),
                    None => IngestOneOutcomeV1::Unquarantinable,
                });
            }
        };
        self.persist_accepted(&accepted.envelope, accepted.digest, raw, now)?;
        report.accepted += 1;
        Ok(IngestOneOutcomeV1::Processed)
    }

    /// Drains pending route payloads into a Contracts-owned, idempotent
    /// authority.  The row is marked only after the returned receipt is
    /// durable.  Crashing between those steps causes exact redelivery.
    pub fn dispatch_routes<P: ContractsTransportPortV1>(
        &mut self,
        port: &mut P,
    ) -> Result<RouteDispatchReportV1, RouteDispatchErrorV1<P::Error>> {
        let entries = self
            .entries_with_state_and_kind(0, None)
            .map_err(RouteDispatchErrorV1::Inbox)?;
        let mut report = RouteDispatchReportV1::default();
        let mut blocked_flows = BTreeSet::new();
        for entry in entries {
            let flow = (entry.sender_id.0, entry.recipient_id.0);
            if entry.message_type != message_type::ROUTE_TRANSPORT {
                blocked_flows.insert(flow);
                continue;
            }
            if blocked_flows.contains(&flow) {
                report.blocked_by_f6 += 1;
                continue;
            }
            let envelope = RelayEnvelopeV1::decode(&entry.canonical_bytes)
                .map_err(|_| RouteDispatchErrorV1::Inbox(DurableInboxError::CorruptState))?;
            let commit = port
                .accept_signed_dsc1(ContractsRouteDeliveryV1 {
                    sender_id: entry.sender_id,
                    sequence: entry.sequence,
                    envelope_digest: entry.envelope_digest,
                    evidence: ContractsRouteDeliveryEvidenceV2::DirectRelayEnvelopeV1,
                    payload: &envelope.payload,
                })
                .map_err(RouteDispatchErrorV1::Contracts)?;
            self.mark_delivered(&entry, commit)
                .map_err(RouteDispatchErrorV1::Inbox)?;
            if commit.duplicate {
                report.duplicate_commits += 1;
            }
            match commit.disposition {
                DurablePayloadDispositionV1::Applied => report.applied += 1,
                DurablePayloadDispositionV1::FailedClosed => report.failed_closed += 1,
            }
        }
        Ok(report)
    }

    /// Drains pending F6 payloads through the same durable inbox that accepted
    /// route envelopes.  This is the only F6 delivery API, making it
    /// impossible for an F6 worker to advance an independent transcript.
    pub fn dispatch_f6<P: F6TransportPortV1>(
        &mut self,
        port: &mut P,
    ) -> Result<F6DispatchReportV1, F6DispatchErrorV1<P::Error>> {
        let entries = self
            .entries_with_state_and_kind(0, None)
            .map_err(F6DispatchErrorV1::Inbox)?;
        let mut report = F6DispatchReportV1::default();
        let mut blocked_flows = BTreeSet::new();
        for entry in entries {
            let flow = (entry.sender_id.0, entry.recipient_id.0);
            if entry.message_type == message_type::ROUTE_TRANSPORT {
                blocked_flows.insert(flow);
                continue;
            }
            if blocked_flows.contains(&flow) {
                report.blocked_by_route += 1;
                continue;
            }
            let envelope = RelayEnvelopeV1::decode(&entry.canonical_bytes)
                .map_err(|_| F6DispatchErrorV1::Inbox(DurableInboxError::CorruptState))?;
            let commit = port
                .accept_f6(F6PayloadDeliveryV1 {
                    sender_id: entry.sender_id,
                    sequence: entry.sequence,
                    message_type: entry.message_type,
                    envelope_digest: entry.envelope_digest,
                    payload: &envelope.payload,
                })
                .map_err(F6DispatchErrorV1::F6)?;
            self.mark_delivered(&entry, commit)
                .map_err(F6DispatchErrorV1::Inbox)?;
            if commit.duplicate {
                report.duplicate_commits += 1;
            }
            match commit.disposition {
                DurablePayloadDispositionV1::Applied => report.applied += 1,
                DurablePayloadDispositionV1::FailedClosed => report.failed_closed += 1,
            }
        }
        Ok(report)
    }

    /// Replays every previously applied F6 delivery in transcript order
    /// without modifying the inbox.
    ///
    /// Startup uses this before dispatching pending rows. The downstream
    /// authority must recognize every delivery as an exact duplicate and
    /// return the same applied receipt retained by the inbox. A different
    /// disposition, a non-duplicate response, or a different receipt proves
    /// that the reopened authority graph is not the graph that committed the
    /// inbox history and is therefore treated as corrupt state.
    pub fn replay_applied_f6<P: F6TransportPortV1>(
        &self,
        port: &mut P,
    ) -> Result<F6AppliedReplayReportV1, F6AppliedReplayErrorV1<P::Error>> {
        let entries = self
            .entries_with_state_and_kind(1, None)
            .map_err(F6AppliedReplayErrorV1::Inbox)?;
        let mut report = F6AppliedReplayReportV1::default();
        for entry in entries {
            if !is_f6_message_type(entry.message_type) {
                continue;
            }
            let envelope = RelayEnvelopeV1::decode(&entry.canonical_bytes)
                .map_err(|_| F6AppliedReplayErrorV1::Inbox(DurableInboxError::CorruptState))?;
            let commit = port
                .accept_f6(F6PayloadDeliveryV1 {
                    sender_id: entry.sender_id,
                    sequence: entry.sequence,
                    message_type: entry.message_type,
                    envelope_digest: entry.envelope_digest,
                    payload: &envelope.payload,
                })
                .map_err(F6AppliedReplayErrorV1::F6)?;
            if entry.delivery_state != 1
                || commit.disposition() != DurablePayloadDispositionV1::Applied
                || !commit.duplicate()
                || commit.durable_receipt() != &entry.delivery_receipt
            {
                return Err(F6AppliedReplayErrorV1::Inbox(
                    DurableInboxError::CorruptState,
                ));
            }
            report.replayed =
                report
                    .replayed
                    .checked_add(1)
                    .ok_or(F6AppliedReplayErrorV1::Inbox(
                        DurableInboxError::CorruptState,
                    ))?;
        }
        Ok(report)
    }

    /// Resolves one retained quarantine record only through an explicit
    /// external durable authority. Reprocess still has to pass the canonical
    /// recipient pipeline; release is recorded as failed closed. Exact retries
    /// require the authority to return the same receipt as a duplicate until
    /// the separate compaction commit installs a retained exact receipt.
    pub fn resolve_quarantine<A: DurableQuarantineAuthorityV1>(
        &mut self,
        ordinal: u64,
        rosters: &RosterRegistryV1,
        now: TimelockSpec,
        authority: &mut A,
    ) -> Result<DurableQuarantineResolutionReportV1, DurableQuarantineResolutionErrorV1<A::Error>>
    {
        let retained = self
            .load_quarantine_by_ordinal(ordinal)
            .map_err(DurableQuarantineResolutionErrorV1::Inbox)?
            .ok_or(DurableQuarantineResolutionErrorV1::Inbox(
                DurableInboxError::CompactedQuarantineReplay,
            ))?;
        if retained.compact_sequence != 0 {
            let resolution = match retained.resolution_state {
                1 => DurableQuarantineResolutionV1::Reprocess,
                2 => DurableQuarantineResolutionV1::ReleaseFailedClosed,
                _ => {
                    return Err(DurableQuarantineResolutionErrorV1::Inbox(
                        DurableInboxError::CorruptState,
                    ))
                }
            };
            return Ok(DurableQuarantineResolutionReportV1 {
                resolution,
                duplicate_commit: true,
            });
        }
        let request = DurableQuarantineResolutionRequestV1 {
            ordinal: retained.ordinal,
            relay_ordinal: retained.relay_ordinal,
            record_digest: retained.record_digest,
            reason: retained.reason,
            sender_id: retained.sender_id,
            recipient_id: self.config.recipient_id,
            wire: self.config.wire,
            current_cursor: retained.current_cursor,
            next_cursor: retained.next_cursor,
            canonical_bytes: &retained.canonical_bytes,
        };
        let commit = authority
            .authorize_resolution(request)
            .map_err(DurableQuarantineResolutionErrorV1::Authority)?;
        if commit.record_digest != retained.record_digest || commit.durable_receipt == ZERO_DIGEST {
            return Err(DurableQuarantineResolutionErrorV1::Inbox(
                DurableInboxError::InvalidConsumerCommit,
            ));
        }
        let target_state = commit.resolution as u8;
        if retained.resolution_state != 0 {
            if retained.resolution_state != target_state
                || retained.resolution_receipt != commit.durable_receipt
                || !commit.duplicate
            {
                return Err(DurableQuarantineResolutionErrorV1::Inbox(
                    DurableInboxError::CorruptState,
                ));
            }
            self.compact_resolved_quarantine(retained.ordinal)
                .map_err(DurableQuarantineResolutionErrorV1::Inbox)?;
            return Ok(DurableQuarantineResolutionReportV1 {
                resolution: commit.resolution,
                duplicate_commit: true,
            });
        }

        if commit.resolution == DurableQuarantineResolutionV1::Reprocess {
            let envelope = RelayEnvelopeV1::decode(&retained.canonical_bytes).map_err(|_| {
                DurableQuarantineResolutionErrorV1::Inbox(DurableInboxError::CorruptState)
            })?;
            let key = IdempotencyKeyV1::of(&envelope);
            match self
                .entry_by_key(&key)
                .map_err(DurableQuarantineResolutionErrorV1::Inbox)?
            {
                Some(existing) if existing.canonical_bytes == retained.canonical_bytes => {}
                Some(_) => {
                    return Err(DurableQuarantineResolutionErrorV1::Inbox(
                        DurableInboxError::CorruptState,
                    ))
                }
                None => {
                    let mut state = self
                        .reconstruct_transcript(rosters)
                        .map_err(DurableQuarantineResolutionErrorV1::Inbox)?;
                    let accepted = accept_envelope(
                        &retained.canonical_bytes,
                        &self.config.recipient_context(),
                        rosters,
                        &mut state,
                        now,
                    )
                    .map_err(|_| DurableQuarantineResolutionErrorV1::StillRefused)?;
                    self.persist_accepted(
                        &accepted.envelope,
                        accepted.digest,
                        &retained.canonical_bytes,
                        now,
                    )
                    .map_err(DurableQuarantineResolutionErrorV1::Inbox)?;
                }
            }
        }
        self.mark_quarantine_resolved(&retained, target_state, commit.durable_receipt)
            .map_err(DurableQuarantineResolutionErrorV1::Inbox)?;
        self.compact_resolved_quarantine(retained.ordinal)
            .map_err(DurableQuarantineResolutionErrorV1::Inbox)?;
        Ok(DurableQuarantineResolutionReportV1 {
            resolution: commit.resolution,
            duplicate_commit: commit.duplicate,
        })
    }

    /// Returns bounded backlog counters without exposing payload bytes.
    pub fn stats(&self) -> Result<DurableInboxStatsV1, DurableInboxError> {
        let mut stats = DurableInboxStatsV1::default();
        let mut statement = self.connection.prepare(
            "SELECT message_type, delivery_state, COUNT(*)
             FROM inbox_entries GROUP BY message_type, delivery_state",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (kind, state, count) = row?;
            let count = usize::try_from(count).map_err(|_| DurableInboxError::CorruptState)?;
            match state {
                0 if kind == i64::from(message_type::ROUTE_TRANSPORT) => {
                    stats.pending_route += count
                }
                0 => stats.pending_f6 += count,
                1 => stats.delivered += count,
                2 => stats.failed_closed += count,
                _ => return Err(DurableInboxError::CorruptState),
            }
        }
        let quarantine = self.quarantine_stats()?;
        stats.quarantined = quarantine.unresolved_raw;
        stats.quarantine_resolved_pending_compaction = quarantine.resolved_raw;
        stats.quarantine_reprocessed = quarantine.compact_reprocessed;
        stats.quarantine_released = quarantine.compact_released;
        stats.quarantine_retained = quarantine.retained_rows;
        Ok(stats)
    }

    fn persist_accepted(
        &mut self,
        envelope: &RelayEnvelopeV1,
        envelope_digest: Digest32,
        raw: &[u8],
        now: TimelockSpec,
    ) -> Result<(), DurableInboxError> {
        let (now_domain, now_value) = timelock_parts(now);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = transaction.query_row(
            "SELECT accepted_count FROM inbox_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let pending_count = u64::try_from(count).map_err(|_| DurableInboxError::CorruptState)?;
        if pending_count >= u64::from(self.config.max_entries) {
            return Err(DurableInboxError::CapacityExceeded);
        }
        let ordinal = count
            .checked_add(1)
            .ok_or(DurableInboxError::CorruptState)?;
        let row_digest = entry_digest(
            &self.config,
            ordinal,
            envelope,
            &envelope_digest,
            raw,
            now_domain,
            now_value,
        )?;
        let delivery_digest = delivery_digest(&self.config, &row_digest, 0, &ZERO_DIGEST)?;
        transaction.execute(
            "INSERT INTO inbox_entries
             (ordinal, sender_id, recipient_id, sequence_be, message_type,
              envelope_digest, canonical_bytes, accepted_now_domain,
              accepted_now_be, delivery_state, delivery_receipt, row_digest,
              delivery_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?11, ?12)",
            params![
                ordinal,
                envelope.sender_id.0.as_slice(),
                envelope.recipient_id.0.as_slice(),
                envelope.sequence.to_be_bytes().as_slice(),
                i64::from(envelope.message_type),
                envelope_digest.as_slice(),
                raw,
                i64::from(now_domain),
                now_value.to_be_bytes().as_slice(),
                ZERO_DIGEST.as_slice(),
                row_digest.as_slice(),
                delivery_digest.as_slice(),
            ],
        )?;
        let meta_changed = transaction.execute(
            "UPDATE inbox_meta SET accepted_count = ?1
             WHERE singleton = 1 AND accepted_count = ?2",
            params![ordinal, count],
        )?;
        if meta_changed != 1 {
            return Err(DurableInboxError::CorruptState);
        }
        transaction.commit()?;
        Ok(())
    }

    fn persist_quarantine(
        &mut self,
        relay_ordinal: u64,
        current_cursor: &relay::production::DeliveryCursorV2,
        next_cursor: &relay::production::DeliveryCursorV2,
        raw: &[u8],
        reason: DurableQuarantineReasonV1,
        now: TimelockSpec,
    ) -> Result<bool, DurableInboxError> {
        if raw.len() > relay::MAX_ENVELOPE_BYTES
            || current_cursor.database_id().as_bytes() != &self.config.expected_relay_database_id
            || next_cursor.database_id().as_bytes() != &self.config.expected_relay_database_id
            || current_cursor.recipient_id() != self.config.recipient_id
            || next_cursor.recipient_id() != self.config.recipient_id
            || current_cursor.database_id() != next_cursor.database_id()
            || current_cursor.position() >= relay_ordinal
            || next_cursor.position() != relay_ordinal
        {
            return Err(DurableInboxError::CorruptState);
        }
        let envelope = RelayEnvelopeV1::decode(raw).map_err(|_| DurableInboxError::CorruptState)?;
        if envelope
            .canonical_bytes()
            .map_err(|_| DurableInboxError::CorruptState)?
            != raw
        {
            return Err(DurableInboxError::CorruptState);
        }
        let envelope_digest = envelope
            .envelope_digest()
            .map_err(|_| DurableInboxError::CorruptState)?;
        let canonical_bytes_digest = quarantine_bytes_digest(raw)?;
        let context_digest = quarantine_context_digest(
            &self.config,
            current_cursor,
            next_cursor,
            relay_ordinal,
            &envelope,
        )?;
        let (now_domain, now_value) = timelock_parts(now);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) =
            load_quarantine_by_relay_ordinal(&transaction, &self.config, relay_ordinal)?
        {
            if existing.current_cursor != *current_cursor
                || existing.next_cursor != *next_cursor
                || existing.canonical_bytes_digest != canonical_bytes_digest
                || (!existing.canonical_bytes.is_empty() && existing.canonical_bytes != raw)
                || existing.reason != reason
                || existing.envelope_digest != envelope_digest
                || existing.context_digest != context_digest
            {
                return Err(DurableInboxError::QuarantineEquivocation);
            }
            transaction.commit()?;
            return Ok(true);
        }
        let cursor_exists: i64 = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM inbox_quarantine WHERE current_cursor = ?1
             )",
            params![current_cursor.canonical_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if cursor_exists != 0 {
            return Err(DurableInboxError::QuarantineEquivocation);
        }
        let (count, previous, next_ordinal, highest_compacted): (i64, Vec<u8>, Vec<u8>, Vec<u8>) =
            transaction.query_row(
                "SELECT quarantine_count, quarantine_head_digest,
                    quarantine_next_ordinal_be,
                    quarantine_highest_compacted_relay_ordinal_be
             FROM inbox_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
        let pending_count = u64::try_from(count).map_err(|_| DurableInboxError::CorruptState)?;
        if relay_ordinal <= as_u64_be(&highest_compacted)? {
            return Err(DurableInboxError::CompactedQuarantineReplay);
        }
        if pending_count >= u64::from(self.config.max_entries) {
            return Err(DurableInboxError::CapacityExceeded);
        }
        let retained_rows: i64 =
            transaction.query_row("SELECT COUNT(*) FROM inbox_quarantine", [], |row| {
                row.get(0)
            })?;
        let max_retained_rows = i64::from(self.config.max_entries)
            .checked_mul(2)
            .ok_or(DurableInboxError::CorruptState)?;
        if !(0..max_retained_rows).contains(&retained_rows) {
            return Err(DurableInboxError::CorruptState);
        }
        let previous_record_digest = as_digest(&previous)?;
        let ordinal = as_u64_be(&next_ordinal)?;
        if ordinal == 0 {
            return Err(DurableInboxError::CorruptState);
        }
        let successor_ordinal = ordinal
            .checked_add(1)
            .ok_or(DurableInboxError::CapacityExceeded)?;
        let record_digest = quarantine_record_digest(
            &self.config,
            &QuarantineRecordMaterialV1 {
                ordinal,
                relay_ordinal,
                current_cursor,
                next_cursor,
                envelope: &envelope,
                reason,
                envelope_digest: &envelope_digest,
                context_digest: &context_digest,
                canonical_bytes: raw,
                now_domain,
                now_value,
                previous_record_digest: &previous_record_digest,
            },
        )?;
        let resolution_digest =
            quarantine_resolution_digest(&self.config, &record_digest, 0, &ZERO_DIGEST)?;
        transaction.execute(
            "INSERT INTO inbox_quarantine
             (ordinal_be, relay_ordinal_be, current_cursor, next_cursor, sender_id,
              recipient_id, network_id, session_id, route_id, roster_snapshot,
              policy_version, reason, envelope_digest, context_digest,
              canonical_bytes, canonical_bytes_digest,
              quarantined_now_domain, quarantined_now_be,
              previous_record_digest, record_digest, resolution_state,
              resolution_receipt, resolution_digest, compact_sequence_be,
              previous_compact_root, compact_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, 0, ?21, ?22,
                     ?23, ?24, ?25)",
            params![
                ordinal.to_be_bytes().as_slice(),
                relay_ordinal.to_be_bytes().as_slice(),
                current_cursor.canonical_bytes().as_slice(),
                next_cursor.canonical_bytes().as_slice(),
                envelope.sender_id.0.as_slice(),
                envelope.recipient_id.0.as_slice(),
                envelope.network_id.as_slice(),
                envelope.session_id.as_slice(),
                envelope.route_id.as_slice(),
                envelope.roster_snapshot.as_slice(),
                i64::from(envelope.policy_version),
                i64::from(reason as u8),
                envelope_digest.as_slice(),
                context_digest.as_slice(),
                raw,
                canonical_bytes_digest.as_slice(),
                i64::from(now_domain),
                now_value.to_be_bytes().as_slice(),
                previous_record_digest.as_slice(),
                record_digest.as_slice(),
                ZERO_DIGEST.as_slice(),
                resolution_digest.as_slice(),
                0_u64.to_be_bytes().as_slice(),
                ZERO_DIGEST.as_slice(),
                ZERO_DIGEST.as_slice(),
            ],
        )?;
        let next_count = count
            .checked_add(1)
            .ok_or(DurableInboxError::CorruptState)?;
        let changed = transaction.execute(
            "UPDATE inbox_meta
             SET quarantine_count = ?1, quarantine_head_digest = ?2,
                 quarantine_next_ordinal_be = ?3
             WHERE singleton = 1 AND quarantine_count = ?4
                   AND quarantine_head_digest = ?5
                   AND quarantine_next_ordinal_be = ?6",
            params![
                next_count,
                record_digest.as_slice(),
                successor_ordinal.to_be_bytes().as_slice(),
                count,
                previous_record_digest.as_slice(),
                next_ordinal,
            ],
        )?;
        if changed != 1 {
            return Err(DurableInboxError::CorruptState);
        }
        transaction.commit()?;
        Ok(false)
    }

    fn load_quarantine_by_ordinal(
        &self,
        ordinal: u64,
    ) -> Result<Option<StoredQuarantineV1>, DurableInboxError> {
        let mut statement = self.connection.prepare(
            "SELECT ordinal_be, relay_ordinal_be, current_cursor, next_cursor,
                    sender_id, recipient_id, network_id, session_id, route_id,
                    roster_snapshot, policy_version, reason, envelope_digest,
                    context_digest, canonical_bytes, canonical_bytes_digest, quarantined_now_domain,
                    quarantined_now_be, previous_record_digest, record_digest,
                    resolution_state, resolution_receipt, resolution_digest,
                    compact_sequence_be, previous_compact_root, compact_digest
             FROM inbox_quarantine WHERE ordinal_be = ?1",
        )?;
        let raw = statement
            .query_row(
                params![ordinal.to_be_bytes().as_slice()],
                quarantine_row_from_sql,
            )
            .optional()?;
        raw.map(|row| validate_quarantine_row(row, &self.config))
            .transpose()
    }

    fn mark_quarantine_resolved(
        &mut self,
        retained: &StoredQuarantineV1,
        state: u8,
        receipt: Digest32,
    ) -> Result<(), DurableInboxError> {
        if !matches!(state, 1 | 2) || receipt == ZERO_DIGEST {
            return Err(DurableInboxError::InvalidConsumerCommit);
        }
        let resolution_digest =
            quarantine_resolution_digest(&self.config, &retained.record_digest, state, &receipt)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE inbox_quarantine
             SET resolution_state = ?1, resolution_receipt = ?2,
                 resolution_digest = ?3
             WHERE ordinal_be = ?4 AND record_digest = ?5 AND resolution_state = 0
                   AND length(canonical_bytes) > 0
                   AND compact_sequence_be = zeroblob(8)",
            params![
                i64::from(state),
                receipt.as_slice(),
                resolution_digest.as_slice(),
                retained.ordinal.to_be_bytes().as_slice(),
                retained.record_digest.as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(DurableInboxError::CorruptState);
        }
        transaction.commit()?;
        #[cfg(test)]
        exit_quarantine_resolution_for_test("resolution-commit");
        Ok(())
    }

    fn compact_resolved_quarantine(&mut self, ordinal: u64) -> Result<bool, DurableInboxError> {
        let retained = self
            .load_quarantine_by_ordinal(ordinal)?
            .ok_or(DurableInboxError::CompactedQuarantineReplay)?;
        if retained.compact_sequence != 0 {
            return Ok(true);
        }
        if retained.resolution_state == 0
            || retained.resolution_receipt == ZERO_DIGEST
            || retained.canonical_bytes.is_empty()
        {
            return Err(DurableInboxError::CorruptState);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (pending_count, sequence_raw, previous_root_raw, highest_raw): (
            i64,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
        ) = transaction.query_row(
            "SELECT quarantine_count, quarantine_compact_sequence_be,
                    quarantine_compact_root,
                    quarantine_highest_compacted_relay_ordinal_be
             FROM inbox_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        if !(1..=i64::from(self.config.max_entries)).contains(&pending_count) {
            return Err(DurableInboxError::CorruptState);
        }
        let compact_sequence = as_u64_be(&sequence_raw)?
            .checked_add(1)
            .ok_or(DurableInboxError::CapacityExceeded)?;
        let previous_compact_root = as_digest(&previous_root_raw)?;
        let compact_digest = quarantine_compact_digest(
            &self.config,
            compact_sequence,
            &previous_compact_root,
            &retained,
        )?;
        let compact_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM inbox_quarantine WHERE length(canonical_bytes) = 0",
            [],
            |row| row.get(0),
        )?;
        if !(0..=i64::from(self.config.max_entries)).contains(&compact_count) {
            return Err(DurableInboxError::CorruptState);
        }
        if compact_count == i64::from(self.config.max_entries) {
            let evicted: Vec<u8> = transaction.query_row(
                "SELECT ordinal_be FROM inbox_quarantine
                 WHERE length(canonical_bytes) = 0
                 ORDER BY compact_sequence_be ASC LIMIT 1",
                [],
                |row| row.get(0),
            )?;
            if transaction.execute(
                "DELETE FROM inbox_quarantine
                 WHERE ordinal_be = ?1 AND length(canonical_bytes) = 0",
                params![evicted],
            )? != 1
            {
                return Err(DurableInboxError::CorruptState);
            }
        }
        let changed = transaction.execute(
            "UPDATE inbox_quarantine
             SET canonical_bytes = ?1, compact_sequence_be = ?2,
                 previous_compact_root = ?3, compact_digest = ?4
             WHERE ordinal_be = ?5 AND record_digest = ?6
                   AND resolution_state = ?7 AND resolution_receipt = ?8
                   AND resolution_digest = ?9 AND length(canonical_bytes) > 0
                   AND compact_sequence_be = zeroblob(8)",
            params![
                &[] as &[u8],
                compact_sequence.to_be_bytes().as_slice(),
                previous_compact_root.as_slice(),
                compact_digest.as_slice(),
                ordinal.to_be_bytes().as_slice(),
                retained.record_digest.as_slice(),
                i64::from(retained.resolution_state),
                retained.resolution_receipt.as_slice(),
                quarantine_resolution_digest(
                    &self.config,
                    &retained.record_digest,
                    retained.resolution_state,
                    &retained.resolution_receipt,
                )?
                .as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(DurableInboxError::CorruptState);
        }
        let highest = as_u64_be(&highest_raw)?.max(retained.relay_ordinal);
        let meta_changed = transaction.execute(
            "UPDATE inbox_meta
             SET quarantine_count = ?1, quarantine_compact_sequence_be = ?2,
                 quarantine_compact_root = ?3,
                 quarantine_highest_compacted_relay_ordinal_be = ?4
             WHERE singleton = 1 AND quarantine_count = ?5
                   AND quarantine_compact_sequence_be = ?6
                   AND quarantine_compact_root = ?7
                   AND quarantine_highest_compacted_relay_ordinal_be = ?8",
            params![
                pending_count - 1,
                compact_sequence.to_be_bytes().as_slice(),
                compact_digest.as_slice(),
                highest.to_be_bytes().as_slice(),
                pending_count,
                sequence_raw,
                previous_root_raw,
                highest_raw,
            ],
        )?;
        if meta_changed != 1 {
            return Err(DurableInboxError::CorruptState);
        }
        transaction.commit()?;
        #[cfg(test)]
        exit_quarantine_resolution_for_test("compaction-commit");
        Ok(false)
    }

    fn quarantine_stats(&self) -> Result<QuarantineStatsInternalV1, DurableInboxError> {
        let mut stats = QuarantineStatsInternalV1::default();
        let mut statement = self.connection.prepare(
            "SELECT resolution_state, length(canonical_bytes), COUNT(*)
             FROM inbox_quarantine
             GROUP BY resolution_state, length(canonical_bytes)",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (state, raw_len, count) = row?;
            let count = usize::try_from(count).map_err(|_| DurableInboxError::CorruptState)?;
            stats.retained_rows = stats
                .retained_rows
                .checked_add(count)
                .ok_or(DurableInboxError::CorruptState)?;
            match (state, raw_len > 0) {
                (0, true) => stats.unresolved_raw = count,
                (1 | 2, true) => {
                    stats.resolved_raw = stats
                        .resolved_raw
                        .checked_add(count)
                        .ok_or(DurableInboxError::CorruptState)?
                }
                (1, false) => stats.compact_reprocessed = count,
                (2, false) => stats.compact_released = count,
                _ => return Err(DurableInboxError::CorruptState),
            }
        }
        Ok(stats)
    }

    fn audit_quarantine(&self) -> Result<(), DurableInboxError> {
        let mut statement = self.connection.prepare(
            "SELECT ordinal_be, relay_ordinal_be, current_cursor, next_cursor,
                    sender_id, recipient_id, network_id, session_id, route_id,
                    roster_snapshot, policy_version, reason, envelope_digest,
                    context_digest, canonical_bytes, canonical_bytes_digest, quarantined_now_domain,
                    quarantined_now_be, previous_record_digest, record_digest,
                    resolution_state, resolution_receipt, resolution_digest,
                    compact_sequence_be, previous_compact_root, compact_digest
             FROM inbox_quarantine ORDER BY ordinal_be ASC",
        )?;
        let rows = statement.query_map([], quarantine_row_from_sql)?;
        let mut retained_rows = Vec::new();
        for row in rows {
            retained_rows.push(validate_quarantine_row(row?, &self.config)?);
        }
        drop(statement);
        let max_entries = usize::try_from(self.config.max_entries)
            .map_err(|_| DurableInboxError::CorruptState)?;
        let max_retained_rows = max_entries
            .checked_mul(2)
            .ok_or(DurableInboxError::CorruptState)?;
        if retained_rows.len() > max_retained_rows {
            return Err(DurableInboxError::CorruptState);
        }
        let mut raw_count = 0_u64;
        let mut prior_ordinal: Option<u64> = None;
        let mut prior_record = ZERO_DIGEST;
        for retained in &retained_rows {
            if !retained.canonical_bytes.is_empty() {
                raw_count = raw_count
                    .checked_add(1)
                    .ok_or(DurableInboxError::CorruptState)?;
            }
            if prior_ordinal.is_some_and(|ordinal| ordinal.checked_add(1) == Some(retained.ordinal))
                && retained.previous_record_digest != prior_record
            {
                return Err(DurableInboxError::CorruptState);
            }
            prior_ordinal = Some(retained.ordinal);
            prior_record = retained.record_digest;
        }
        let mut compact_rows: Vec<&StoredQuarantineV1> = retained_rows
            .iter()
            .filter(|row| row.compact_sequence != 0)
            .collect();
        compact_rows.sort_by_key(|row| row.compact_sequence);
        if compact_rows.len() > max_entries {
            return Err(DurableInboxError::CorruptState);
        }
        for pair in compact_rows.windows(2) {
            if pair[0].compact_sequence.checked_add(1) != Some(pair[1].compact_sequence)
                || pair[1].previous_compact_root != pair[0].compact_digest
            {
                return Err(DurableInboxError::CorruptState);
            }
        }
        let meta: QuarantineAuditMetaV1 = self.connection.query_row(
            "SELECT quarantine_count, quarantine_head_digest,
                    quarantine_next_ordinal_be, quarantine_compact_sequence_be,
                    quarantine_compact_root,
                    quarantine_highest_compacted_relay_ordinal_be
             FROM inbox_meta WHERE singleton = 1",
            [],
            |row| {
                Ok(QuarantineAuditMetaV1 {
                    pending_count: row.get(0)?,
                    head_digest: row.get(1)?,
                    next_ordinal: row.get(2)?,
                    compact_sequence: row.get(3)?,
                    compact_root: row.get(4)?,
                    highest_compacted_relay_ordinal: row.get(5)?,
                })
            },
        )?;
        let next_ordinal = as_u64_be(&meta.next_ordinal)?;
        let compact_sequence = as_u64_be(&meta.compact_sequence)?;
        let compact_root = as_digest(&meta.compact_root)?;
        let highest_compacted = as_u64_be(&meta.highest_compacted_relay_ordinal)?;
        let latest = retained_rows.last();
        let latest_compact = compact_rows.last();
        let maximum_retained_compacted_relay_ordinal = compact_rows
            .iter()
            .map(|row| row.relay_ordinal)
            .max()
            .unwrap_or(0);
        if u64::try_from(meta.pending_count).map_err(|_| DurableInboxError::CorruptState)?
            != raw_count
            || next_ordinal == 0
            || latest.is_some_and(|row| row.ordinal >= next_ordinal)
            || latest.map_or(ZERO_DIGEST, |row| row.record_digest) != as_digest(&meta.head_digest)?
            || compact_sequence == 0 && compact_root != ZERO_DIGEST
            || compact_sequence == 0 && highest_compacted != 0
            || compact_sequence != 0 && compact_root == ZERO_DIGEST
            || compact_sequence != 0 && highest_compacted == 0
            || (compact_sequence != 0) != latest_compact.is_some()
            || latest_compact.is_some_and(|row| {
                row.compact_sequence != compact_sequence || row.compact_digest != compact_root
            })
            || maximum_retained_compacted_relay_ordinal > highest_compacted
        {
            return Err(DurableInboxError::CorruptState);
        }
        Ok(())
    }

    fn mark_delivered(
        &mut self,
        entry: &StoredEntryV1,
        commit: DurablePayloadCommitV1,
    ) -> Result<(), DurableInboxError> {
        if commit.durable_receipt == ZERO_DIGEST {
            return Err(DurableInboxError::InvalidConsumerCommit);
        }
        let state = match commit.disposition {
            DurablePayloadDispositionV1::Applied => 1_u8,
            DurablePayloadDispositionV1::FailedClosed => 2_u8,
        };
        let next_digest = delivery_digest(
            &self.config,
            &entry.row_digest,
            state,
            &commit.durable_receipt,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE inbox_entries
             SET delivery_state = ?1, delivery_receipt = ?2, delivery_digest = ?3
             WHERE ordinal = ?4 AND delivery_state = 0 AND row_digest = ?5",
            params![
                i64::from(state),
                commit.durable_receipt.as_slice(),
                next_digest.as_slice(),
                entry.ordinal,
                entry.row_digest.as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(DurableInboxError::CorruptState);
        }
        transaction.commit()?;
        Ok(())
    }

    fn audit_transcript(&self, rosters: &RosterRegistryV1) -> Result<(), DurableInboxError> {
        self.reconstruct_transcript(rosters).map(|_| ())
    }

    fn reconstruct_transcript(
        &self,
        rosters: &RosterRegistryV1,
    ) -> Result<TranscriptStateV1, DurableInboxError> {
        let entries = self.entries_with_state_and_kind_all()?;
        let mut state = TranscriptStateV1::new();
        for entry in entries {
            let accepted = accept_envelope(
                &entry.canonical_bytes,
                &self.config.recipient_context(),
                rosters,
                &mut state,
                entry.accepted_now,
            )
            .map_err(|_| DurableInboxError::CorruptState)?;
            if accepted.digest != entry.envelope_digest
                || accepted.envelope.sender_id != entry.sender_id
                || accepted.envelope.recipient_id != entry.recipient_id
                || accepted.envelope.sequence != entry.sequence
                || accepted.envelope.message_type != entry.message_type
                || accepted.envelope.roster_snapshot != self.config.wire.roster_snapshot
                || accepted.envelope.policy_version != self.config.wire.policy_version
            {
                return Err(DurableInboxError::CorruptState);
            }
        }
        Ok(state)
    }

    fn entries_with_state_and_kind_all(&self) -> Result<Vec<StoredEntryV1>, DurableInboxError> {
        let entries = self.query_entries("SELECT ordinal, sender_id, recipient_id, sequence_be, message_type, envelope_digest, canonical_bytes, accepted_now_domain, accepted_now_be, delivery_state, delivery_receipt, row_digest, delivery_digest FROM inbox_entries ORDER BY ordinal ASC", [])?;
        for (index, entry) in entries.iter().enumerate() {
            let expected = i64::try_from(index + 1).map_err(|_| DurableInboxError::CorruptState)?;
            if entry.ordinal != expected {
                return Err(DurableInboxError::CorruptState);
            }
        }
        Ok(entries)
    }

    fn entries_with_state_and_kind(
        &self,
        state: u8,
        kind: Option<u16>,
    ) -> Result<Vec<StoredEntryV1>, DurableInboxError> {
        match kind {
            Some(kind) => {
                let mut statement = self.connection.prepare(
                    "SELECT ordinal, sender_id, recipient_id, sequence_be, message_type,
                            envelope_digest, canonical_bytes, accepted_now_domain,
                            accepted_now_be, delivery_state, delivery_receipt, row_digest,
                            delivery_digest
                     FROM inbox_entries
                     WHERE delivery_state = ?1 AND message_type = ?2
                     ORDER BY ordinal ASC",
                )?;
                load_entries(
                    &mut statement,
                    params![i64::from(state), i64::from(kind)],
                    &self.config,
                )
            }
            None => {
                let mut statement = self.connection.prepare(
                    "SELECT ordinal, sender_id, recipient_id, sequence_be, message_type,
                            envelope_digest, canonical_bytes, accepted_now_domain,
                            accepted_now_be, delivery_state, delivery_receipt, row_digest,
                            delivery_digest
                     FROM inbox_entries WHERE delivery_state = ?1 ORDER BY ordinal ASC",
                )?;
                load_entries(&mut statement, params![i64::from(state)], &self.config)
            }
        }
    }

    fn query_entries<P: rusqlite::Params>(
        &self,
        sql: &str,
        params: P,
    ) -> Result<Vec<StoredEntryV1>, DurableInboxError> {
        let mut statement = self.connection.prepare(sql)?;
        load_entries(&mut statement, params, &self.config)
    }

    fn entry_by_key(
        &self,
        key: &IdempotencyKeyV1,
    ) -> Result<Option<StoredEntryV1>, DurableInboxError> {
        let mut statement = self.connection.prepare(
            "SELECT ordinal, sender_id, recipient_id, sequence_be, message_type,
                    envelope_digest, canonical_bytes, accepted_now_domain,
                    accepted_now_be, delivery_state, delivery_receipt, row_digest,
                    delivery_digest
             FROM inbox_entries
             WHERE sender_id = ?1 AND recipient_id = ?2 AND sequence_be = ?3",
        )?;
        let raw = statement
            .query_row(
                params![
                    key.sender_id.0.as_slice(),
                    key.recipient_id.0.as_slice(),
                    key.sequence.to_be_bytes().as_slice(),
                ],
                raw_entry_from_row,
            )
            .optional()?;
        raw.map(|raw| validate_raw_entry(raw, &self.config))
            .transpose()
    }

    fn validate_storage(&self) -> Result<(), DurableInboxError> {
        validate_root(&self.root)?;
        validate_root_entries(&self.root)?;
        validate_connection_authority(
            &self._database_authority,
            &self._sqlite_database_authority,
            &self.root.join(DATABASE_FILE_NAME),
        )?;
        for suffix in ["", "-wal", "-shm"] {
            let path = self.root.join(format!("{DATABASE_FILE_NAME}{suffix}"));
            if path
                .try_exists()
                .map_err(|_| DurableInboxError::StorageUnavailable)?
            {
                validate_owner_file(&path)?;
            }
        }
        let app_id: i64 = self
            .connection
            .pragma_query_value(None, "application_id", |row| row.get(0))?;
        let version: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if app_id != APPLICATION_ID || version != SCHEMA_VERSION {
            return Err(DurableInboxError::UnsupportedFormat);
        }
        validate_database_path(&self.connection, &self.root.join(DATABASE_FILE_NAME))?;
        let quick: String = self
            .connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if quick != "ok" {
            return Err(DurableInboxError::CorruptState);
        }
        if schema_objects(&self.connection)? != reference_schema_objects()? {
            return Err(DurableInboxError::UnsupportedFormat);
        }
        self.require_meta()?;
        self.entries_with_state_and_kind_all()?;
        self.audit_quarantine()?;
        Ok(())
    }

    fn require_pristine_creation_state(&self) -> Result<(), DurableInboxError> {
        let stats = self.stats()?;
        let (accepted, quarantined): (i64, i64) = self.connection.query_row(
            "SELECT accepted_count, quarantine_count
             FROM inbox_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if accepted != 0 || quarantined != 0 || stats != DurableInboxStatsV1::default() {
            return Err(DurableInboxError::UnsupportedFormat);
        }
        Ok(())
    }

    fn require_meta(&self) -> Result<(), DurableInboxError> {
        let retained: Option<InboxMetaRowV2> = self
            .connection
            .query_row(
                "SELECT schema_version, inbox_id, relay_database_id, network_id, session_id, route_id,
                        roster_snapshot, recipient_id, policy_version, max_entries,
                        accepted_count, quarantine_count, quarantine_head_digest,
                        quarantine_next_ordinal_be, quarantine_compact_sequence_be,
                        quarantine_compact_root,
                        quarantine_highest_compacted_relay_ordinal_be
                 FROM inbox_meta WHERE singleton = 1",
                [],
                |row| {
                    Ok(InboxMetaRowV2 {
                        version: row.get(0)?,
                        inbox: row.get(1)?,
                        relay_database: row.get(2)?,
                        network: row.get(3)?,
                        session: row.get(4)?,
                        route: row.get(5)?,
                        roster: row.get(6)?,
                        recipient: row.get(7)?,
                        policy: row.get(8)?,
                        max: row.get(9)?,
                        accepted_count: row.get(10)?,
                        quarantine_count: row.get(11)?,
                        quarantine_head_digest: row.get(12)?,
                        quarantine_next_ordinal: row.get(13)?,
                        quarantine_compact_sequence: row.get(14)?,
                        quarantine_compact_root: row.get(15)?,
                        quarantine_highest_compacted_relay_ordinal: row.get(16)?,
                    })
                },
            )
            .optional()?;
        let Some(retained) = retained else {
            return Err(DurableInboxError::WrongIdentity);
        };
        if retained.version != SCHEMA_VERSION
            || as_digest(&retained.inbox)? != self.config.inbox_id
            || as_digest(&retained.relay_database)? != self.config.expected_relay_database_id
            || as_digest(&retained.network)? != self.config.wire.network_id
            || as_digest(&retained.session)? != self.config.wire.session_id
            || as_digest(&retained.route)? != self.config.wire.route_id
            || as_digest(&retained.roster)? != self.config.wire.roster_snapshot
            || as_digest(&retained.recipient)? != self.config.recipient_id.0
            || retained.policy != i64::from(self.config.wire.policy_version)
            || retained.max != i64::from(self.config.max_entries)
            || retained.accepted_count < 0
            || retained.accepted_count > retained.max
            || retained.quarantine_count < 0
            || retained.quarantine_count > retained.max
            || as_u64_be(&retained.quarantine_next_ordinal)? == 0
            || (as_u64_be(&retained.quarantine_next_ordinal)? == 1)
                != (as_digest(&retained.quarantine_head_digest)? == ZERO_DIGEST)
            || (as_u64_be(&retained.quarantine_compact_sequence)? == 0)
                != (as_digest(&retained.quarantine_compact_root)? == ZERO_DIGEST)
            || (as_u64_be(&retained.quarantine_compact_sequence)? == 0)
                != (as_u64_be(&retained.quarantine_highest_compacted_relay_ordinal)? == 0)
        {
            return Err(DurableInboxError::WrongIdentity);
        }
        let (actual_count, maximum_ordinal): (i64, i64) = self.connection.query_row(
            "SELECT COUNT(*), COALESCE(MAX(ordinal), 0) FROM inbox_entries",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if actual_count != retained.accepted_count || maximum_ordinal != retained.accepted_count {
            return Err(DurableInboxError::CorruptState);
        }
        Ok(())
    }
}

fn is_f6_message_type(kind: u16) -> bool {
    matches!(
        kind,
        message_type::RFQ
            | message_type::QUOTE
            | message_type::ACCEPTANCE
            | message_type::SELECTION
    )
}

fn quarantine_reason_from_auth_refusal(refusal: AuthRefusal) -> Option<DurableQuarantineReasonV1> {
    match refusal {
        AuthRefusal::Codec(_) => None,
        AuthRefusal::WrongNetwork => Some(DurableQuarantineReasonV1::WrongNetwork),
        AuthRefusal::WrongRecipient => Some(DurableQuarantineReasonV1::WrongRecipient),
        AuthRefusal::WrongSession => Some(DurableQuarantineReasonV1::WrongSession),
        AuthRefusal::WrongRoute => Some(DurableQuarantineReasonV1::WrongRoute),
        AuthRefusal::Expired => Some(DurableQuarantineReasonV1::Expired),
        AuthRefusal::WrongTimelockDomain => Some(DurableQuarantineReasonV1::WrongTimelockDomain),
        AuthRefusal::UnknownRosterSnapshot => {
            Some(DurableQuarantineReasonV1::UnknownRosterSnapshot)
        }
        AuthRefusal::SenderNotInRoster => Some(DurableQuarantineReasonV1::SenderNotInRoster),
        AuthRefusal::RoleMismatch => Some(DurableQuarantineReasonV1::RoleMismatch),
        AuthRefusal::RoleNotPermitted => Some(DurableQuarantineReasonV1::RoleNotPermitted),
        AuthRefusal::InvalidSignature => Some(DurableQuarantineReasonV1::InvalidSignature),
        AuthRefusal::Duplicate => Some(DurableQuarantineReasonV1::Duplicate),
        AuthRefusal::Equivocation => Some(DurableQuarantineReasonV1::Equivocation),
        AuthRefusal::StaleSequence => Some(DurableQuarantineReasonV1::StaleSequence),
        AuthRefusal::SequenceGap => Some(DurableQuarantineReasonV1::SequenceGap),
        AuthRefusal::TranscriptDiscontinuity => {
            Some(DurableQuarantineReasonV1::TranscriptDiscontinuity)
        }
        AuthRefusal::UnusableRosterKey => Some(DurableQuarantineReasonV1::UnusableRosterKey),
        AuthRefusal::TranscriptTooLarge => Some(DurableQuarantineReasonV1::TranscriptTooLarge),
    }
}

type RawEntry = (
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

struct RawQuarantineRowV1 {
    ordinal: Vec<u8>,
    relay_ordinal: Vec<u8>,
    current_cursor: Vec<u8>,
    next_cursor: Vec<u8>,
    sender_id: Vec<u8>,
    recipient_id: Vec<u8>,
    network_id: Vec<u8>,
    session_id: Vec<u8>,
    route_id: Vec<u8>,
    roster_snapshot: Vec<u8>,
    policy_version: i64,
    reason: i64,
    envelope_digest: Vec<u8>,
    context_digest: Vec<u8>,
    canonical_bytes: Vec<u8>,
    canonical_bytes_digest: Vec<u8>,
    quarantined_now_domain: i64,
    quarantined_now: Vec<u8>,
    previous_record_digest: Vec<u8>,
    record_digest: Vec<u8>,
    resolution_state: i64,
    resolution_receipt: Vec<u8>,
    resolution_digest: Vec<u8>,
    compact_sequence: Vec<u8>,
    previous_compact_root: Vec<u8>,
    compact_digest: Vec<u8>,
}

struct QuarantineRecordMaterialV1<'a> {
    ordinal: u64,
    relay_ordinal: u64,
    current_cursor: &'a relay::production::DeliveryCursorV2,
    next_cursor: &'a relay::production::DeliveryCursorV2,
    envelope: &'a RelayEnvelopeV1,
    reason: DurableQuarantineReasonV1,
    envelope_digest: &'a Digest32,
    context_digest: &'a Digest32,
    canonical_bytes: &'a [u8],
    now_domain: u8,
    now_value: u64,
    previous_record_digest: &'a Digest32,
}

fn quarantine_row_from_sql(row: &rusqlite::Row<'_>) -> Result<RawQuarantineRowV1, rusqlite::Error> {
    Ok(RawQuarantineRowV1 {
        ordinal: row.get(0)?,
        relay_ordinal: row.get(1)?,
        current_cursor: row.get(2)?,
        next_cursor: row.get(3)?,
        sender_id: row.get(4)?,
        recipient_id: row.get(5)?,
        network_id: row.get(6)?,
        session_id: row.get(7)?,
        route_id: row.get(8)?,
        roster_snapshot: row.get(9)?,
        policy_version: row.get(10)?,
        reason: row.get(11)?,
        envelope_digest: row.get(12)?,
        context_digest: row.get(13)?,
        canonical_bytes: row.get(14)?,
        canonical_bytes_digest: row.get(15)?,
        quarantined_now_domain: row.get(16)?,
        quarantined_now: row.get(17)?,
        previous_record_digest: row.get(18)?,
        record_digest: row.get(19)?,
        resolution_state: row.get(20)?,
        resolution_receipt: row.get(21)?,
        resolution_digest: row.get(22)?,
        compact_sequence: row.get(23)?,
        previous_compact_root: row.get(24)?,
        compact_digest: row.get(25)?,
    })
}

fn raw_entry_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEntry> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
    ))
}

fn load_entries<P: rusqlite::Params>(
    statement: &mut rusqlite::Statement<'_>,
    params: P,
    config: &DurableInboxConfigV1,
) -> Result<Vec<StoredEntryV1>, DurableInboxError> {
    let rows = statement.query_map(params, raw_entry_from_row)?;
    let mut entries = Vec::new();
    for row in rows {
        entries.push(validate_raw_entry(row?, config)?);
    }
    Ok(entries)
}

fn validate_raw_entry(
    raw: RawEntry,
    config: &DurableInboxConfigV1,
) -> Result<StoredEntryV1, DurableInboxError> {
    let (
        ordinal,
        sender,
        recipient,
        sequence,
        message_type_raw,
        envelope_digest_raw,
        canonical_bytes,
        now_domain_raw,
        now_value_raw,
        delivery_state_raw,
        delivery_receipt_raw,
        row_digest_raw,
        delivery_digest_raw,
    ) = raw;
    if ordinal <= 0 || ordinal > i64::from(config.max_entries) {
        return Err(DurableInboxError::CorruptState);
    }
    let sender_id = ParticipantId(as_digest(&sender)?);
    let recipient_id = ParticipantId(as_digest(&recipient)?);
    let sequence = as_u64_be(&sequence)?;
    let message_type =
        u16::try_from(message_type_raw).map_err(|_| DurableInboxError::CorruptState)?;
    let envelope_digest = as_digest(&envelope_digest_raw)?;
    let now_domain = u8::try_from(now_domain_raw).map_err(|_| DurableInboxError::CorruptState)?;
    let now_value = as_u64_be(&now_value_raw)?;
    let accepted_now = timelock_from_parts(now_domain, now_value)?;
    let delivery_state =
        u8::try_from(delivery_state_raw).map_err(|_| DurableInboxError::CorruptState)?;
    let delivery_receipt = as_digest(&delivery_receipt_raw)?;
    let row_digest = as_digest(&row_digest_raw)?;
    let retained_delivery_digest = as_digest(&delivery_digest_raw)?;
    let envelope =
        RelayEnvelopeV1::decode(&canonical_bytes).map_err(|_| DurableInboxError::CorruptState)?;
    if envelope.sender_id != sender_id
        || envelope.recipient_id != recipient_id
        || envelope.sequence != sequence
        || envelope.message_type != message_type
        || envelope.recipient_id != config.recipient_id
        || envelope.network_id != config.wire.network_id
        || envelope.session_id != config.wire.session_id
        || envelope.route_id != config.wire.route_id
        || envelope.roster_snapshot != config.wire.roster_snapshot
        || envelope.policy_version != config.wire.policy_version
        || envelope
            .envelope_digest()
            .map_err(|_| DurableInboxError::CorruptState)?
            != envelope_digest
        || entry_digest(
            config,
            ordinal,
            &envelope,
            &envelope_digest,
            &canonical_bytes,
            now_domain,
            now_value,
        )? != row_digest
        || delivery_digest(config, &row_digest, delivery_state, &delivery_receipt)?
            != retained_delivery_digest
        || (delivery_state == 0 && delivery_receipt != ZERO_DIGEST)
        || (delivery_state != 0 && delivery_receipt == ZERO_DIGEST)
        || delivery_state > 2
    {
        return Err(DurableInboxError::CorruptState);
    }
    Ok(StoredEntryV1 {
        ordinal,
        sender_id,
        recipient_id,
        sequence,
        message_type,
        envelope_digest,
        canonical_bytes,
        accepted_now,
        delivery_state,
        delivery_receipt,
        row_digest,
    })
}

fn validate_quarantine_row(
    raw: RawQuarantineRowV1,
    config: &DurableInboxConfigV1,
) -> Result<StoredQuarantineV1, DurableInboxError> {
    let ordinal = as_u64_be(&raw.ordinal)?;
    if ordinal == 0 {
        return Err(DurableInboxError::CorruptState);
    }
    let relay_ordinal = as_u64_be(&raw.relay_ordinal)?;
    let current_cursor = relay::production::DeliveryCursorV2::decode(&raw.current_cursor)
        .map_err(|_| DurableInboxError::CorruptState)?;
    let next_cursor = relay::production::DeliveryCursorV2::decode(&raw.next_cursor)
        .map_err(|_| DurableInboxError::CorruptState)?;
    let sender_id = ParticipantId(as_digest(&raw.sender_id)?);
    let recipient_id = ParticipantId(as_digest(&raw.recipient_id)?);
    let network_id = as_digest(&raw.network_id)?;
    let session_id = as_digest(&raw.session_id)?;
    let route_id = as_digest(&raw.route_id)?;
    let roster_snapshot = as_digest(&raw.roster_snapshot)?;
    let policy_version =
        u32::try_from(raw.policy_version).map_err(|_| DurableInboxError::CorruptState)?;
    let reason = DurableQuarantineReasonV1::from_code(
        u8::try_from(raw.reason).map_err(|_| DurableInboxError::CorruptState)?,
    )?;
    let envelope_digest = as_digest(&raw.envelope_digest)?;
    let context_digest = as_digest(&raw.context_digest)?;
    let canonical_bytes_digest = as_digest(&raw.canonical_bytes_digest)?;
    let now_domain =
        u8::try_from(raw.quarantined_now_domain).map_err(|_| DurableInboxError::CorruptState)?;
    let now_value = as_u64_be(&raw.quarantined_now)?;
    timelock_from_parts(now_domain, now_value)?;
    let previous_record_digest = as_digest(&raw.previous_record_digest)?;
    let record_digest = as_digest(&raw.record_digest)?;
    let resolution_state =
        u8::try_from(raw.resolution_state).map_err(|_| DurableInboxError::CorruptState)?;
    let resolution_receipt = as_digest(&raw.resolution_receipt)?;
    let resolution_digest = as_digest(&raw.resolution_digest)?;
    let compact_sequence = as_u64_be(&raw.compact_sequence)?;
    let previous_compact_root = as_digest(&raw.previous_compact_root)?;
    let compact_digest = as_digest(&raw.compact_digest)?;
    if raw.canonical_bytes.len() > relay::MAX_ENVELOPE_BYTES
        || current_cursor.recipient_id() != config.recipient_id
        || next_cursor.recipient_id() != config.recipient_id
        || current_cursor.database_id().as_bytes() != &config.expected_relay_database_id
        || next_cursor.database_id().as_bytes() != &config.expected_relay_database_id
        || current_cursor.database_id() != next_cursor.database_id()
        || current_cursor.position() >= relay_ordinal
        || next_cursor.position() != relay_ordinal
        || quarantine_resolution_digest(
            config,
            &record_digest,
            resolution_state,
            &resolution_receipt,
        )? != resolution_digest
        || (resolution_state == 0 && resolution_receipt != ZERO_DIGEST)
        || (resolution_state != 0 && resolution_receipt == ZERO_DIGEST)
        || resolution_state > 2
        || (ordinal == 1 && previous_record_digest != ZERO_DIGEST)
        || (ordinal > 1 && previous_record_digest == ZERO_DIGEST)
    {
        return Err(DurableInboxError::CorruptState);
    }
    let retained = StoredQuarantineV1 {
        ordinal,
        relay_ordinal,
        current_cursor,
        next_cursor,
        sender_id,
        envelope_recipient_id: recipient_id,
        envelope_network_id: network_id,
        envelope_session_id: session_id,
        envelope_route_id: route_id,
        envelope_roster_snapshot: roster_snapshot,
        envelope_policy_version: policy_version,
        reason,
        envelope_digest,
        context_digest,
        canonical_bytes: raw.canonical_bytes,
        canonical_bytes_digest,
        previous_record_digest,
        record_digest,
        resolution_state,
        resolution_receipt,
        compact_sequence,
        previous_compact_root,
        compact_digest,
    };
    if retained.canonical_bytes.is_empty() {
        if retained.resolution_state == 0
            || retained.canonical_bytes_digest == ZERO_DIGEST
            || retained.compact_sequence == 0
            || retained.compact_digest == ZERO_DIGEST
            || quarantine_compact_digest(
                config,
                retained.compact_sequence,
                &retained.previous_compact_root,
                &retained,
            )? != retained.compact_digest
        {
            return Err(DurableInboxError::CorruptState);
        }
    } else {
        let envelope = RelayEnvelopeV1::decode(&retained.canonical_bytes)
            .map_err(|_| DurableInboxError::CorruptState)?;
        let canonical = envelope
            .canonical_bytes()
            .map_err(|_| DurableInboxError::CorruptState)?;
        let expected_context = quarantine_context_digest(
            config,
            &retained.current_cursor,
            &retained.next_cursor,
            retained.relay_ordinal,
            &envelope,
        )?;
        let material = QuarantineRecordMaterialV1 {
            ordinal: retained.ordinal,
            relay_ordinal: retained.relay_ordinal,
            current_cursor: &retained.current_cursor,
            next_cursor: &retained.next_cursor,
            envelope: &envelope,
            reason: retained.reason,
            envelope_digest: &retained.envelope_digest,
            context_digest: &retained.context_digest,
            canonical_bytes: &retained.canonical_bytes,
            now_domain,
            now_value,
            previous_record_digest: &retained.previous_record_digest,
        };
        if canonical != retained.canonical_bytes
            || quarantine_bytes_digest(&retained.canonical_bytes)?
                != retained.canonical_bytes_digest
            || sender_id != envelope.sender_id
            || recipient_id != envelope.recipient_id
            || network_id != envelope.network_id
            || session_id != envelope.session_id
            || route_id != envelope.route_id
            || roster_snapshot != envelope.roster_snapshot
            || policy_version != envelope.policy_version
            || envelope
                .envelope_digest()
                .map_err(|_| DurableInboxError::CorruptState)?
                != retained.envelope_digest
            || expected_context != retained.context_digest
            || quarantine_record_digest(config, &material)? != retained.record_digest
            || retained.compact_sequence != 0
            || retained.previous_compact_root != ZERO_DIGEST
            || retained.compact_digest != ZERO_DIGEST
        {
            return Err(DurableInboxError::CorruptState);
        }
    }
    Ok(retained)
}

fn load_quarantine_by_relay_ordinal(
    connection: &Connection,
    config: &DurableInboxConfigV1,
    relay_ordinal: u64,
) -> Result<Option<StoredQuarantineV1>, DurableInboxError> {
    let mut statement = connection.prepare(
        "SELECT ordinal_be, relay_ordinal_be, current_cursor, next_cursor,
                sender_id, recipient_id, network_id, session_id, route_id,
                roster_snapshot, policy_version, reason, envelope_digest,
                context_digest, canonical_bytes, canonical_bytes_digest, quarantined_now_domain,
                quarantined_now_be, previous_record_digest, record_digest,
                resolution_state, resolution_receipt, resolution_digest,
                compact_sequence_be, previous_compact_root, compact_digest
         FROM inbox_quarantine WHERE relay_ordinal_be = ?1",
    )?;
    let raw = statement
        .query_row(
            params![relay_ordinal.to_be_bytes().as_slice()],
            quarantine_row_from_sql,
        )
        .optional()?;
    raw.map(|row| validate_quarantine_row(row, config))
        .transpose()
}

fn quarantine_context_digest(
    config: &DurableInboxConfigV1,
    current_cursor: &relay::production::DeliveryCursorV2,
    next_cursor: &relay::production::DeliveryCursorV2,
    relay_ordinal: u64,
    envelope: &RelayEnvelopeV1,
) -> Result<Digest32, DurableInboxError> {
    digest_parts(
        QUARANTINE_CONTEXT_DOMAIN,
        &[
            config.inbox_id.as_slice(),
            config.expected_relay_database_id.as_slice(),
            config.wire.network_id.as_slice(),
            config.wire.session_id.as_slice(),
            config.wire.route_id.as_slice(),
            config.wire.roster_snapshot.as_slice(),
            &config.wire.policy_version.to_be_bytes(),
            config.recipient_id.0.as_slice(),
            current_cursor.canonical_bytes().as_slice(),
            next_cursor.canonical_bytes().as_slice(),
            &relay_ordinal.to_be_bytes(),
            envelope.network_id.as_slice(),
            envelope.session_id.as_slice(),
            envelope.route_id.as_slice(),
            envelope.roster_snapshot.as_slice(),
            &envelope.policy_version.to_be_bytes(),
            envelope.sender_id.0.as_slice(),
            envelope.recipient_id.0.as_slice(),
            &envelope.sequence.to_be_bytes(),
            &envelope.message_type.to_be_bytes(),
            envelope.previous_transcript_hash.as_slice(),
        ],
    )
}

fn quarantine_record_digest(
    config: &DurableInboxConfigV1,
    material: &QuarantineRecordMaterialV1<'_>,
) -> Result<Digest32, DurableInboxError> {
    digest_parts(
        QUARANTINE_RECORD_DOMAIN,
        &[
            config.inbox_id.as_slice(),
            &material.ordinal.to_be_bytes(),
            &material.relay_ordinal.to_be_bytes(),
            material.current_cursor.canonical_bytes().as_slice(),
            material.next_cursor.canonical_bytes().as_slice(),
            material.envelope.sender_id.0.as_slice(),
            material.envelope.recipient_id.0.as_slice(),
            material.envelope.network_id.as_slice(),
            material.envelope.session_id.as_slice(),
            material.envelope.route_id.as_slice(),
            material.envelope.roster_snapshot.as_slice(),
            &material.envelope.policy_version.to_be_bytes(),
            &[material.reason as u8],
            material.envelope_digest.as_slice(),
            material.context_digest.as_slice(),
            &[material.now_domain],
            &material.now_value.to_be_bytes(),
            material.previous_record_digest.as_slice(),
            &(material.canonical_bytes.len() as u32).to_be_bytes(),
            material.canonical_bytes,
        ],
    )
}

fn quarantine_resolution_digest(
    config: &DurableInboxConfigV1,
    record_digest: &Digest32,
    state: u8,
    receipt: &Digest32,
) -> Result<Digest32, DurableInboxError> {
    digest_parts(
        QUARANTINE_RESOLUTION_DOMAIN,
        &[
            config.inbox_id.as_slice(),
            record_digest.as_slice(),
            &[state],
            receipt.as_slice(),
        ],
    )
}

fn quarantine_bytes_digest(raw: &[u8]) -> Result<Digest32, DurableInboxError> {
    let len = u32::try_from(raw.len()).map_err(|_| DurableInboxError::CorruptState)?;
    digest_parts(QUARANTINE_BYTES_DOMAIN, &[&len.to_be_bytes(), raw])
}

fn quarantine_compact_digest(
    config: &DurableInboxConfigV1,
    compact_sequence: u64,
    previous_compact_root: &Digest32,
    retained: &StoredQuarantineV1,
) -> Result<Digest32, DurableInboxError> {
    digest_parts(
        QUARANTINE_COMPACT_DOMAIN,
        &[
            config.inbox_id.as_slice(),
            config.expected_relay_database_id.as_slice(),
            &compact_sequence.to_be_bytes(),
            previous_compact_root.as_slice(),
            &retained.ordinal.to_be_bytes(),
            &retained.relay_ordinal.to_be_bytes(),
            retained.current_cursor.canonical_bytes().as_slice(),
            retained.next_cursor.canonical_bytes().as_slice(),
            retained.sender_id.0.as_slice(),
            retained.envelope_recipient_id.0.as_slice(),
            retained.envelope_network_id.as_slice(),
            retained.envelope_session_id.as_slice(),
            retained.envelope_route_id.as_slice(),
            retained.envelope_roster_snapshot.as_slice(),
            &retained.envelope_policy_version.to_be_bytes(),
            &[retained.reason as u8],
            retained.envelope_digest.as_slice(),
            retained.context_digest.as_slice(),
            retained.canonical_bytes_digest.as_slice(),
            retained.record_digest.as_slice(),
            &[retained.resolution_state],
            retained.resolution_receipt.as_slice(),
        ],
    )
}

fn entry_digest(
    config: &DurableInboxConfigV1,
    ordinal: i64,
    envelope: &RelayEnvelopeV1,
    envelope_digest: &Digest32,
    raw: &[u8],
    now_domain: u8,
    now_value: u64,
) -> Result<Digest32, DurableInboxError> {
    digest_parts(
        ENTRY_DOMAIN,
        &[
            config.inbox_id.as_slice(),
            config.expected_relay_database_id.as_slice(),
            &ordinal.to_be_bytes(),
            envelope.sender_id.0.as_slice(),
            envelope.recipient_id.0.as_slice(),
            &envelope.sequence.to_be_bytes(),
            &envelope.message_type.to_be_bytes(),
            envelope_digest.as_slice(),
            &[now_domain],
            &now_value.to_be_bytes(),
            &(raw.len() as u32).to_be_bytes(),
            raw,
        ],
    )
}

fn delivery_digest(
    config: &DurableInboxConfigV1,
    row_digest: &Digest32,
    state: u8,
    receipt: &Digest32,
) -> Result<Digest32, DurableInboxError> {
    digest_parts(
        DELIVERY_DOMAIN,
        &[
            config.inbox_id.as_slice(),
            row_digest.as_slice(),
            &[state],
            receipt.as_slice(),
        ],
    )
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, DurableInboxError> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| DurableInboxError::CorruptState)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut digest = [0; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| DurableInboxError::CorruptState)?;
    Ok(digest)
}

fn timelock_parts(spec: TimelockSpec) -> (u8, u64) {
    match spec {
        TimelockSpec::BlockHeight { value } => (1, value),
        TimelockSpec::TimestampSeconds { value } => (2, value),
        TimelockSpec::BtcTime512s { value } => (3, value),
    }
}

fn timelock_from_parts(domain: u8, value: u64) -> Result<TimelockSpec, DurableInboxError> {
    match domain {
        1 => Ok(TimelockSpec::BlockHeight { value }),
        2 => Ok(TimelockSpec::TimestampSeconds { value }),
        3 => Ok(TimelockSpec::BtcTime512s { value }),
        _ => Err(DurableInboxError::CorruptState),
    }
}

fn as_digest(bytes: &[u8]) -> Result<Digest32, DurableInboxError> {
    bytes
        .try_into()
        .map_err(|_| DurableInboxError::CorruptState)
}

fn as_u64_be(bytes: &[u8]) -> Result<u64, DurableInboxError> {
    let exact: [u8; 8] = bytes
        .try_into()
        .map_err(|_| DurableInboxError::CorruptState)?;
    Ok(u64::from_be_bytes(exact))
}

fn configure_connection(connection: &Connection) -> Result<(), DurableInboxError> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA foreign_keys=ON;
         PRAGMA read_uncommitted=OFF;
         PRAGMA trusted_schema=OFF;
         PRAGMA secure_delete=ON;
         PRAGMA temp_store=MEMORY;",
    )?;
    let defensive = rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE;
    if !connection.set_db_config(defensive, true)? || !connection.db_config(defensive)? {
        return Err(DurableInboxError::UnsupportedFormat);
    }
    let journal: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let read_uncommitted: i64 =
        connection.query_row("PRAGMA read_uncommitted", [], |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
    let secure_delete: i64 = connection.query_row("PRAGMA secure_delete", [], |row| row.get(0))?;
    let temp_store: i64 = connection.query_row("PRAGMA temp_store", [], |row| row.get(0))?;
    let busy_timeout: i64 = connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || read_uncommitted != 0
        || trusted_schema != 0
        || secure_delete != 1
        || temp_store != 2
        || busy_timeout != 5_000
    {
        return Err(DurableInboxError::UnsupportedFormat);
    }
    Ok(())
}

fn insert_meta(
    connection: &Connection,
    config: DurableInboxConfigV1,
) -> Result<(), DurableInboxError> {
    connection.execute(
        "INSERT INTO inbox_meta
         (singleton, schema_version, inbox_id, relay_database_id, network_id, session_id, route_id,
          roster_snapshot, recipient_id, policy_version, max_entries,
          accepted_count, quarantine_count, quarantine_head_digest,
          quarantine_next_ordinal_be, quarantine_compact_sequence_be,
          quarantine_compact_root,
          quarantine_highest_compacted_relay_ordinal_be)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, 0, ?11,
                 ?12, ?13, ?14, ?15)",
        params![
            SCHEMA_VERSION,
            config.inbox_id.as_slice(),
            config.expected_relay_database_id.as_slice(),
            config.wire.network_id.as_slice(),
            config.wire.session_id.as_slice(),
            config.wire.route_id.as_slice(),
            config.wire.roster_snapshot.as_slice(),
            config.recipient_id.0.as_slice(),
            i64::from(config.wire.policy_version),
            i64::from(config.max_entries),
            ZERO_DIGEST.as_slice(),
            1_u64.to_be_bytes().as_slice(),
            0_u64.to_be_bytes().as_slice(),
            ZERO_DIGEST.as_slice(),
            0_u64.to_be_bytes().as_slice(),
        ],
    )?;
    Ok(())
}

fn initialize_pristine_store(
    connection: &Connection,
    config: DurableInboxConfigV1,
) -> Result<(), DurableInboxError> {
    connection.execute_batch("BEGIN IMMEDIATE;")?;
    let initialized = (|| {
        connection.execute_batch(SCHEMA_SQL)?;
        connection.pragma_update(None, "application_id", APPLICATION_ID)?;
        connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        insert_meta(connection, config)
    })();
    match initialized {
        Ok(()) => connection.execute_batch("COMMIT;")?,
        Err(error) => {
            let _rollback = connection.execute_batch("ROLLBACK;");
            return Err(error);
        }
    }
    Ok(())
}

type SchemaObjectV1 = (String, String, String, String);

fn schema_objects(connection: &Connection) -> Result<BTreeSet<SchemaObjectV1>, DurableInboxError> {
    const MAX_SCHEMA_OBJECTS: i64 = 8;
    const MAX_SCHEMA_SQL_BYTES: i64 = 131_072;
    let (count, maximum, total): (i64, Option<i64>, Option<i64>) = connection.query_row(
        "SELECT COUNT(*), MAX(length(sql)), SUM(length(sql))
         FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if !(0..=MAX_SCHEMA_OBJECTS).contains(&count)
        || maximum.is_some_and(|value| !(0..=MAX_SCHEMA_SQL_BYTES).contains(&value))
        || total.is_some_and(|value| !(0..=MAX_SCHEMA_SQL_BYTES).contains(&value))
    {
        return Err(DurableInboxError::UnsupportedFormat);
    }
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut objects = BTreeSet::new();
    for row in rows {
        if !objects.insert(row?) {
            return Err(DurableInboxError::CorruptState);
        }
    }
    if i64::try_from(objects.len()).map_err(|_| DurableInboxError::CorruptState)? != count {
        return Err(DurableInboxError::UnsupportedFormat);
    }
    Ok(objects)
}

fn reference_schema_objects() -> Result<BTreeSet<SchemaObjectV1>, DurableInboxError> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA_SQL)?;
    schema_objects(&reference)
}

fn require_pristine_connection(
    connection: &Connection,
    config: &DurableInboxConfigV1,
) -> Result<(), DurableInboxError> {
    let retained: Option<InboxMetaRowV2> = connection
        .query_row(
            "SELECT schema_version, inbox_id, relay_database_id, network_id, session_id, route_id,
                    roster_snapshot, recipient_id, policy_version, max_entries,
                    accepted_count, quarantine_count, quarantine_head_digest,
                    quarantine_next_ordinal_be, quarantine_compact_sequence_be,
                    quarantine_compact_root,
                    quarantine_highest_compacted_relay_ordinal_be
             FROM inbox_meta WHERE singleton = 1",
            [],
            |row| {
                Ok(InboxMetaRowV2 {
                    version: row.get(0)?,
                    inbox: row.get(1)?,
                    relay_database: row.get(2)?,
                    network: row.get(3)?,
                    session: row.get(4)?,
                    route: row.get(5)?,
                    roster: row.get(6)?,
                    recipient: row.get(7)?,
                    policy: row.get(8)?,
                    max: row.get(9)?,
                    accepted_count: row.get(10)?,
                    quarantine_count: row.get(11)?,
                    quarantine_head_digest: row.get(12)?,
                    quarantine_next_ordinal: row.get(13)?,
                    quarantine_compact_sequence: row.get(14)?,
                    quarantine_compact_root: row.get(15)?,
                    quarantine_highest_compacted_relay_ordinal: row.get(16)?,
                })
            },
        )
        .optional()?;
    let Some(retained) = retained else {
        return Err(DurableInboxError::WrongIdentity);
    };
    let rows: i64 =
        connection.query_row("SELECT COUNT(*) FROM inbox_entries", [], |row| row.get(0))?;
    let quarantine_rows: i64 =
        connection.query_row("SELECT COUNT(*) FROM inbox_quarantine", [], |row| {
            row.get(0)
        })?;
    if retained.version != SCHEMA_VERSION
        || as_digest(&retained.inbox)? != config.inbox_id
        || as_digest(&retained.relay_database)? != config.expected_relay_database_id
        || as_digest(&retained.network)? != config.wire.network_id
        || as_digest(&retained.session)? != config.wire.session_id
        || as_digest(&retained.route)? != config.wire.route_id
        || as_digest(&retained.roster)? != config.wire.roster_snapshot
        || as_digest(&retained.recipient)? != config.recipient_id.0
        || retained.policy != i64::from(config.wire.policy_version)
        || retained.max != i64::from(config.max_entries)
        || retained.accepted_count != 0
        || retained.quarantine_count != 0
        || as_digest(&retained.quarantine_head_digest)? != ZERO_DIGEST
        || as_u64_be(&retained.quarantine_next_ordinal)? != 1
        || as_u64_be(&retained.quarantine_compact_sequence)? != 0
        || as_digest(&retained.quarantine_compact_root)? != ZERO_DIGEST
        || as_u64_be(&retained.quarantine_highest_compacted_relay_ordinal)? != 0
        || rows != 0
        || quarantine_rows != 0
    {
        return Err(DurableInboxError::UnsupportedFormat);
    }
    Ok(())
}

fn preflight_resumable_database(
    database_path: &Path,
    authority: &File,
    config: &DurableInboxConfigV1,
) -> Result<DurableProductionCreationStateV1, DurableInboxError> {
    validate_database_authority(authority, database_path)?;
    if authority
        .metadata()
        .map_err(|_| DurableInboxError::StorageUnavailable)?
        .len()
        == 0
    {
        return Ok(DurableProductionCreationStateV1::Incomplete);
    }
    let (connection, sqlite_database_authority) = open_connection_via_authority(
        authority,
        database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    validate_connection_authority(authority, &sqlite_database_authority, database_path)?;
    validate_database_path(&connection, database_path)?;
    let state = classify_resumable_connection(&connection, config)?;
    validate_connection_authority(authority, &sqlite_database_authority, database_path)?;
    Ok(state)
}

fn classify_resumable_connection(
    connection: &Connection,
    config: &DurableInboxConfigV1,
) -> Result<DurableProductionCreationStateV1, DurableInboxError> {
    let schema = schema_objects(connection)?;
    let app_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let state = if schema.is_empty() && app_id == 0 && version == 0 {
        DurableProductionCreationStateV1::Incomplete
    } else if schema == reference_schema_objects()?
        && app_id == APPLICATION_ID
        && version == SCHEMA_VERSION
    {
        require_pristine_connection(connection, config)?;
        DurableProductionCreationStateV1::InitializedPristine
    } else {
        return Err(DurableInboxError::UnsupportedFormat);
    };
    Ok(state)
}

fn validate_database_path(
    connection: &Connection,
    expected_path: &Path,
) -> Result<(), DurableInboxError> {
    let expected =
        fs::canonicalize(expected_path).map_err(|_| DurableInboxError::InvalidConfiguration)?;
    if expected != expected_path {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    let mut statement = connection.prepare("PRAGMA database_list")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
    })?;
    let mut saw_main = false;
    for row in rows {
        let (name, path) = row?;
        match name.as_str() {
            "main" if Path::new(&path) == expected => saw_main = true,
            "temp" if path.is_empty() => {}
            _ => return Err(DurableInboxError::InvalidConfiguration),
        }
    }
    if !saw_main {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    Ok(())
}

fn create_root(root: &Path) -> Result<(), DurableInboxError> {
    validate_new_path(root)?;
    match DirBuilder::new().mode(ROOT_MODE).create(root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(DurableInboxError::AlreadyExists)
        }
        Err(_) => return Err(DurableInboxError::StorageUnavailable),
    }
    sync_directory(root)?;
    let parent = root
        .parent()
        .ok_or(DurableInboxError::InvalidConfiguration)?;
    sync_directory(parent)?;
    validate_root(root)
}

fn validate_new_path(root: &Path) -> Result<(), DurableInboxError> {
    if !root.is_absolute() || root.file_name().is_none() {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    let parent = root
        .parent()
        .ok_or(DurableInboxError::InvalidConfiguration)?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|_| DurableInboxError::InvalidConfiguration)?;
    if canonical_parent != parent {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    validate_owner_directory(parent)
}

fn validate_root(root: &Path) -> Result<(), DurableInboxError> {
    if !root.is_absolute()
        || fs::canonicalize(root).map_err(|_| DurableInboxError::StorageUnavailable)? != root
    {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    validate_owner_directory(root)
}

fn validate_root_entries(root: &Path) -> Result<(), DurableInboxError> {
    let allowed = [
        LOCK_FILE_NAME,
        DATABASE_FILE_NAME,
        "route-inbox-v1.sqlite3-wal",
        "route-inbox-v1.sqlite3-shm",
    ];
    let entries = fs::read_dir(root).map_err(|_| DurableInboxError::StorageUnavailable)?;
    for entry in entries {
        let name = entry
            .map_err(|_| DurableInboxError::StorageUnavailable)?
            .file_name()
            .into_string()
            .map_err(|_| DurableInboxError::InvalidConfiguration)?;
        if !allowed.contains(&name.as_str()) {
            return Err(DurableInboxError::InvalidConfiguration);
        }
    }
    Ok(())
}

fn inspect_creation_state(
    root: &Path,
    config: &DurableInboxConfigV1,
) -> Result<DurableProductionCreationStateV1, DurableInboxError> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            validate_new_path(root)?;
            return Ok(DurableProductionCreationStateV1::Missing);
        }
        Err(_) => return Err(DurableInboxError::StorageUnavailable),
        Ok(_) => validate_root(root)?,
    }
    validate_root_entries(root)?;
    let lock_path = root.join(LOCK_FILE_NAME);
    let database_path = root.join(DATABASE_FILE_NAME);
    let lock_exists = lock_path
        .try_exists()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    let database_exists = database_path
        .try_exists()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    if !lock_exists {
        if fs::read_dir(root)
            .map_err(|_| DurableInboxError::StorageUnavailable)?
            .next()
            .is_none()
        {
            return Ok(DurableProductionCreationStateV1::Incomplete);
        }
        return Err(DurableInboxError::InvalidConfiguration);
    }
    validate_owner_file(&lock_path)?;
    validate_resumable_database_files(root, database_exists)?;
    if !database_exists {
        return Ok(DurableProductionCreationStateV1::Incomplete);
    }
    let authority = open_database_authority(&database_path)?;
    preflight_resumable_database(&database_path, &authority, config)
}

fn create_database_authority(path: &Path) -> Result<File, DurableInboxError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    validate_database_authority(&file, path)?;
    file.sync_all()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    sync_directory(
        path.parent()
            .ok_or(DurableInboxError::InvalidConfiguration)?,
    )?;
    Ok(file)
}

fn open_database_authority(path: &Path) -> Result<File, DurableInboxError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    validate_database_authority(&file, path)?;
    Ok(file)
}

fn open_connection_via_authority(
    authority: &File,
    database_path: &Path,
    flags: OpenFlags,
) -> Result<(Connection, File), DurableInboxError> {
    open_connection_via_authority_with_hooks(authority, database_path, flags, || Ok(()), || Ok(()))
}

fn open_connection_via_authority_with_hooks<BeforeOpen, AfterOpen>(
    authority: &File,
    database_path: &Path,
    flags: OpenFlags,
    before_open: BeforeOpen,
    after_open: AfterOpen,
) -> Result<(Connection, File), DurableInboxError>
where
    BeforeOpen: FnOnce() -> Result<(), DurableInboxError>,
    AfterOpen: FnOnce() -> Result<(), DurableInboxError>,
{
    validate_database_authority(authority, database_path)?;
    let before = process_descriptor_snapshot()?;
    before_open()?;
    let connection = Connection::open_with_flags(database_path, flags)?;
    after_open()?;
    let sqlite_authority = capture_new_sqlite_database_authority(authority, &before)?;
    validate_connection_authority(authority, &sqlite_authority, database_path)?;
    Ok((connection, sqlite_authority))
}

fn validate_database_authority(authority: &File, path: &Path) -> Result<(), DurableInboxError> {
    validate_owner_file(path)?;
    let retained = authority
        .metadata()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| DurableInboxError::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_connection_authority(
    authority: &File,
    sqlite_authority: &File,
    path: &Path,
) -> Result<(), DurableInboxError> {
    validate_database_authority(authority, path)?;
    let retained = authority
        .metadata()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    let sqlite = sqlite_authority
        .metadata()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    if retained.dev() != sqlite.dev() || retained.ino() != sqlite.ino() {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    Ok(())
}

fn process_descriptor_snapshot() -> Result<BTreeMap<i32, (u64, u64)>, DurableInboxError> {
    let mut snapshot = BTreeMap::new();
    for entry in fs::read_dir("/proc/self/fd").map_err(|_| DurableInboxError::StorageUnavailable)? {
        let entry = entry.map_err(|_| DurableInboxError::StorageUnavailable)?;
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        match fs::metadata(entry.path()) {
            Ok(metadata) => {
                snapshot.insert(fd, (metadata.dev(), metadata.ino()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(DurableInboxError::StorageUnavailable),
        }
    }
    Ok(snapshot)
}

fn capture_new_sqlite_database_authority(
    authority: &File,
    before: &BTreeMap<i32, (u64, u64)>,
) -> Result<File, DurableInboxError> {
    let retained = authority
        .metadata()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    let expected = (retained.dev(), retained.ino());
    let after = process_descriptor_snapshot()?;
    let mut candidates = after.iter().filter_map(|(fd, identity)| {
        (*identity == expected && before.get(fd) != Some(identity)).then_some(*fd)
    });
    let candidate = candidates
        .next()
        .ok_or(DurableInboxError::InvalidConfiguration)?;
    if candidates.next().is_some() {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    let proof = File::open(PathBuf::from("/proc/self/fd").join(candidate.to_string()))
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    let proof_metadata = proof
        .metadata()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    if (proof_metadata.dev(), proof_metadata.ino()) != expected {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    Ok(proof)
}

fn acquire_resume_lock(root: &Path) -> Result<File, DurableInboxError> {
    match fs::symlink_metadata(root) {
        Ok(_) => validate_root(root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_root(root)?,
        Err(_) => return Err(DurableInboxError::StorageUnavailable),
    }
    validate_root_entries(root)?;
    let lock_path = root.join(LOCK_FILE_NAME);
    let lock_exists = lock_path
        .try_exists()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    if lock_exists {
        acquire_lock(root, false)
    } else {
        let mut entries = fs::read_dir(root).map_err(|_| DurableInboxError::StorageUnavailable)?;
        if entries.next().is_some() {
            return Err(DurableInboxError::InvalidConfiguration);
        }
        acquire_lock(root, true)
    }
}

fn validate_resumable_database_files(
    root: &Path,
    database_exists: bool,
) -> Result<(), DurableInboxError> {
    if database_exists {
        validate_owner_file(&root.join(DATABASE_FILE_NAME))?;
    }
    for suffix in ["-wal", "-shm"] {
        let sidecar = root.join(format!("{DATABASE_FILE_NAME}{suffix}"));
        if sidecar
            .try_exists()
            .map_err(|_| DurableInboxError::StorageUnavailable)?
        {
            if !database_exists {
                return Err(DurableInboxError::InvalidConfiguration);
            }
            validate_owner_file(&sidecar)?;
        }
    }
    Ok(())
}

fn validate_owner_directory(path: &Path) -> Result<(), DurableInboxError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DurableInboxError::StorageUnavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != ROOT_MODE
        || metadata.nlink() == 0
    {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_owner_file(path: &Path) -> Result<(), DurableInboxError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DurableInboxError::StorageUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    Ok(())
}

fn acquire_lock(root: &Path, create: bool) -> Result<File, DurableInboxError> {
    let path = root.join(LOCK_FILE_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true).mode(FILE_MODE);
    if create {
        options.create_new(true);
    }
    let file = options
        .open(&path)
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    validate_owner_file(&path)?;
    let retained = file
        .metadata()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    let named = fs::symlink_metadata(&path).map_err(|_| DurableInboxError::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    if create {
        file.sync_all()
            .map_err(|_| DurableInboxError::StorageUnavailable)?;
        sync_directory(root)?;
    }
    Ok(file)
}

fn sync_directory(path: &Path) -> Result<(), DurableInboxError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| DurableInboxError::StorageUnavailable)
}

#[cfg(test)]
mod database_authority_tests {
    use std::error::Error;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn sqlite_file(path: &Path, marker: i64) -> Result<(), Box<dyn Error>> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "user_version", marker)?;
        drop(connection);
        fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE))?;
        Ok(())
    }

    #[test]
    fn sqlite_fd_proof_preserves_named_wal_authority() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let database = temporary.path().join(DATABASE_FILE_NAME);
        sqlite_file(&database, 7)?;
        let authority = open_database_authority(&database)?;
        let (connection, sqlite_authority) = open_connection_via_authority(
            &authority,
            &database,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection)?;
        connection.execute("CREATE TABLE authority_probe (value INTEGER) STRICT", [])?;
        validate_connection_authority(&authority, &sqlite_authority, &database)?;
        let journal: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        assert!(journal.eq_ignore_ascii_case("wal"));
        assert_eq!(
            connection.pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))?,
            7
        );
        assert!(temporary
            .path()
            .join(format!("{DATABASE_FILE_NAME}-wal"))
            .exists());
        Ok(())
    }

    #[test]
    fn sqlite_fd_proof_refuses_swap_open_swap_back() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let database = temporary.path().join(DATABASE_FILE_NAME);
        let retained_name = temporary.path().join("retained.sqlite3");
        let alternate = temporary.path().join("alternate.sqlite3");
        sqlite_file(&database, 11)?;
        sqlite_file(&alternate, 22)?;
        let authority = open_database_authority(&database)?;
        let result = open_connection_via_authority_with_hooks(
            &authority,
            &database,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            || {
                fs::rename(&database, &retained_name)
                    .and_then(|()| fs::rename(&alternate, &database))
                    .map_err(|_| DurableInboxError::StorageUnavailable)
            },
            || {
                fs::rename(&database, &alternate)
                    .and_then(|()| fs::rename(&retained_name, &database))
                    .map_err(|_| DurableInboxError::StorageUnavailable)
            },
        );
        assert!(matches!(
            result,
            Err(DurableInboxError::InvalidConfiguration)
        ));
        validate_database_authority(&authority, &database)?;
        Ok(())
    }
}

#[cfg(test)]
mod applied_f6_replay_tests {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;

    use btc_crypto::SecpContext;
    use relay::auth::{RosterMemberV1, RosterSnapshotV1};
    use relay::production::{ProductionRelayV1, RelayDatabaseConfigV1, RelayDatabaseIdV1};
    use relay::server::RelayV1;
    use relay::SenderRoleV1;

    use super::*;

    const NETWORK: Digest32 = [0x11; 32];
    const SESSION: Digest32 = [0x22; 32];
    const ROUTE: Digest32 = [0x33; 32];
    const SNAPSHOT: Digest32 = [0x44; 32];
    const INITIATOR: ParticipantId = ParticipantId([0x51; 32]);
    const SOLVER: ParticipantId = ParticipantId([0x52; 32]);
    const INITIATOR_SECRET: [u8; 32] = [0x53; 32];
    const SOLVER_SECRET: [u8; 32] = [0x56; 32];
    const TEST_QUARANTINE_ROOT_ENV: &str = "DOM_INTEROP_INBOX_TEST_QUARANTINE_ROOT";

    #[derive(Debug, thiserror::Error)]
    #[error("test F6 refusal")]
    struct TestF6Error;

    #[derive(Debug, thiserror::Error)]
    #[error("test quarantine authority refused")]
    struct TestQuarantineError;

    struct TestQuarantineAuthority {
        resolution: DurableQuarantineResolutionV1,
        receipts: BTreeMap<Digest32, Digest32>,
        observed_debug: Option<String>,
    }

    impl TestQuarantineAuthority {
        fn new(resolution: DurableQuarantineResolutionV1) -> Self {
            Self {
                resolution,
                receipts: BTreeMap::new(),
                observed_debug: None,
            }
        }

        fn with_committed(
            resolution: DurableQuarantineResolutionV1,
            record_digest: Digest32,
            receipt: Digest32,
        ) -> Self {
            Self {
                resolution,
                receipts: BTreeMap::from([(record_digest, receipt)]),
                observed_debug: None,
            }
        }
    }

    impl DurableQuarantineAuthorityV1 for TestQuarantineAuthority {
        type Error = TestQuarantineError;

        fn authorize_resolution(
            &mut self,
            request: DurableQuarantineResolutionRequestV1<'_>,
        ) -> Result<DurableQuarantineResolutionCommitV1, Self::Error> {
            self.observed_debug = Some(format!("{request:?}"));
            let record = *request.record_digest();
            let receipt = [0xa7; 32];
            let duplicate = self.receipts.insert(record, receipt).is_some();
            DurableQuarantineResolutionCommitV1::new(record, self.resolution, receipt, duplicate)
                .map_err(|_| TestQuarantineError)
        }
    }

    struct SubstitutedRecordAuthority;

    impl DurableQuarantineAuthorityV1 for SubstitutedRecordAuthority {
        type Error = TestQuarantineError;

        fn authorize_resolution(
            &mut self,
            _request: DurableQuarantineResolutionRequestV1<'_>,
        ) -> Result<DurableQuarantineResolutionCommitV1, Self::Error> {
            DurableQuarantineResolutionCommitV1::new(
                [0xee; 32],
                DurableQuarantineResolutionV1::ReleaseFailedClosed,
                [0xef; 32],
                false,
            )
            .map_err(|_| TestQuarantineError)
        }
    }

    #[derive(Default)]
    struct DurableTestF6Port {
        receipts: BTreeSet<Digest32>,
        disposition: Option<DurablePayloadDispositionV1>,
        force_nonduplicate: bool,
        force_receipt: Option<Digest32>,
    }

    struct RefuseDeliveryAckOnce {
        relay: ProductionRelayV1,
        refuse_next_ack: bool,
    }

    impl RelayQueueV2 for RefuseDeliveryAckOnce {
        fn queue_database_id_v2(&self) -> RelayDatabaseIdV1 {
            self.relay.database_id()
        }

        fn queue_acknowledged_cursor_v2(
            &self,
            recipient: &ParticipantId,
        ) -> Result<relay::production::DeliveryCursorV2, BridgeRefusal> {
            self.relay
                .acknowledged_delivery_cursor_v2(recipient)
                .map_err(BridgeRefusal::DurableRelay)
        }

        fn queue_delivery_page_v2(
            &mut self,
            recipient: &ParticipantId,
            current: &relay::production::DeliveryCursorV2,
            limits: relay::production::DeliveryPageLimitsV2,
        ) -> Result<relay::production::DeliveryPageV2, BridgeRefusal> {
            self.relay
                .delivery_page_v2(recipient, current, limits)
                .map_err(BridgeRefusal::DurableRelay)
        }

        fn queue_acknowledge_delivery_page_v2(
            &mut self,
            recipient: &ParticipantId,
            next: &relay::production::DeliveryCursorV2,
        ) -> Result<relay::production::DeliveryAckV2, BridgeRefusal> {
            if self.refuse_next_ack {
                self.refuse_next_ack = false;
                return Err(BridgeRefusal::AckDigestMismatch);
            }
            self.relay
                .acknowledge_delivery_page_v2(recipient, next)
                .map_err(BridgeRefusal::DurableRelay)
        }
    }

    impl F6TransportPortV1 for DurableTestF6Port {
        type Error = TestF6Error;

        fn accept_f6(
            &mut self,
            delivery: F6PayloadDeliveryV1<'_>,
        ) -> Result<DurablePayloadCommitV1, Self::Error> {
            let exact = *delivery.envelope_digest();
            let duplicate = !self.receipts.insert(exact) && !self.force_nonduplicate;
            DurablePayloadCommitV1::new(
                self.disposition
                    .unwrap_or(DurablePayloadDispositionV1::Applied),
                self.force_receipt.unwrap_or(exact),
                duplicate,
            )
            .map_err(|_| TestF6Error)
        }
    }

    #[test]
    fn zero_expected_relay_database_identity_is_rejected() {
        assert!(matches!(
            DurableInboxConfigV1::new([0x54; 32], ZERO_DIGEST, wire(), SOLVER, 16),
            Err(DurableInboxError::InvalidConfiguration)
        ));
    }

    #[test]
    fn wrong_real_relay_database_is_refused_before_mutation_even_after_reopen(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("wrong-relay-database");
        let wrong_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x90; 32])?, 64)?;
        let mut wrong_relay = ProductionRelayV1::create(&relay_root, wrong_config)?;
        let (raw, _) = envelope(message_type::RFQ, 0, ZERO_DIGEST, b"wrong-relay", 0x40)?;
        wrong_relay.submit(&raw)?;

        let inbox_root = temporary.path().join("pinned-relay-inbox");
        let config = config()?;
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config, &rosters()?)?;
        assert!(matches!(
            inbox.ingest(&mut wrong_relay, &rosters()?, now()),
            Err(DurableInboxError::WrongRelayDatabase)
        ));
        assert_eq!(inbox.stats()?, DurableInboxStatsV1::default());
        assert_eq!(wrong_relay.len()?, 1);
        drop(inbox);

        let swapped_inbox_config =
            DurableInboxConfigV1::new([0x54; 32], [0x90; 32], wire(), SOLVER, 16)?;
        assert!(matches!(
            DurableRelayInboxV1::open(&inbox_root, swapped_inbox_config, &rosters()?),
            Err(DurableInboxError::WrongIdentity)
        ));
        let mut inbox = DurableRelayInboxV1::open(&inbox_root, config, &rosters()?)?;
        assert!(matches!(
            inbox.ingest(&mut wrong_relay, &rosters()?, now()),
            Err(DurableInboxError::WrongRelayDatabase)
        ));
        assert_eq!(inbox.stats()?, DurableInboxStatsV1::default());
        assert_eq!(
            wrong_relay.len()?,
            1,
            "wrong Relay is never read, ACKed or GCed"
        );
        Ok(())
    }

    #[test]
    fn local_commit_before_lost_relay_ack_redelivers_one_exact_duplicate(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("relay-lost-delivery-ack");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut queue = RefuseDeliveryAckOnce {
            relay: ProductionRelayV1::create(&relay_root, relay_config)?,
            refuse_next_ack: true,
        };
        let (raw, _) = envelope(
            message_type::RFQ,
            0,
            ZERO_DIGEST,
            b"durable-before-ack",
            0x41,
        )?;
        queue.relay.submit(&raw)?;

        let inbox_root = temporary.path().join("inbox-lost-delivery-ack");
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config()?, &rosters()?)?;
        assert!(matches!(
            inbox.ingest_v2(&mut queue, &rosters()?, now()),
            Err(DurableInboxError::Queue(BridgeRefusal::AckDigestMismatch))
        ));
        assert_eq!(inbox.stats()?.pending_f6, 1);
        assert_eq!(queue.relay.len()?, 1, "unacknowledged page is retained");
        drop(inbox);

        let mut inbox = DurableRelayInboxV1::open(&inbox_root, config()?, &rosters()?)?;
        let retry = inbox.ingest_v2(&mut queue, &rosters()?, now())?;
        assert_eq!((retry.accepted, retry.duplicates), (0, 1));
        assert_eq!(
            queue.relay.len()?,
            0,
            "exact retry is acknowledged and GCed"
        );
        Ok(())
    }

    #[test]
    fn refused_page_is_quarantined_before_ack_and_survives_reopen() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("relay-quarantine");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
        let payload = b"quarantine-secret-payload";
        let (raw, _) =
            envelope_with_snapshot(message_type::RFQ, 0, ZERO_DIGEST, payload, 0x42, [0x99; 32])?;
        relay.submit(&raw)?;

        let inbox_root = temporary.path().join("inbox-quarantine");
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config()?, &rosters()?)?;
        let report = inbox.ingest(&mut relay, &rosters()?, now())?;
        assert_eq!((report.accepted, report.quarantined), (0, 1));
        assert_eq!(report.refused.len(), 1);
        assert_eq!(relay.len()?, 0, "ACK and GC follow quarantine commit");
        assert_eq!(inbox.stats()?.quarantined, 1);
        drop(inbox);

        let reopened = DurableRelayInboxV1::open(&inbox_root, config()?, &rosters()?)?;
        assert_eq!(reopened.stats()?.quarantined, 1);
        assert!(!format!("{reopened:?}").contains("quarantine-secret-payload"));
        Ok(())
    }

    #[test]
    fn page_read_lost_before_local_quarantine_commit_is_redelivered_unacked(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("relay-quarantine-before-local");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
        let (raw, _) = envelope_with_snapshot(
            message_type::RFQ,
            0,
            ZERO_DIGEST,
            b"read-before-local-persist",
            0x4c,
            [0x92; 32],
        )?;
        relay.submit(&raw)?;
        let current = relay.acknowledged_delivery_cursor_v2(&SOLVER)?;
        let page = relay.delivery_page_v2(
            &SOLVER,
            &current,
            relay::production::DeliveryPageLimitsV2::new(1, relay::MAX_ENVELOPE_BYTES as u32)?,
        )?;
        assert_eq!(page.envelopes(), &[raw]);
        drop(page);
        drop(relay);

        let inbox_root = temporary.path().join("inbox-quarantine-before-local");
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config()?, &rosters()?)?;
        let mut relay = ProductionRelayV1::open(&relay_root, relay_config)?;
        assert_eq!(relay.len()?, 1, "page read alone cannot ACK or GC");
        assert_eq!(inbox.ingest(&mut relay, &rosters()?, now())?.quarantined, 1);
        assert_eq!(relay.len()?, 0);
        Ok(())
    }

    #[test]
    fn quarantine_commit_before_lost_ack_converges_as_exact_duplicate() -> Result<(), Box<dyn Error>>
    {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("relay-quarantine-lost-ack");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut queue = RefuseDeliveryAckOnce {
            relay: ProductionRelayV1::create(&relay_root, relay_config)?,
            refuse_next_ack: true,
        };
        let (raw, _) = envelope_with_snapshot(
            message_type::RFQ,
            0,
            ZERO_DIGEST,
            b"quarantine-before-ack",
            0x43,
            [0x98; 32],
        )?;
        queue.relay.submit(&raw)?;
        let inbox_root = temporary.path().join("inbox-quarantine-lost-ack");
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config()?, &rosters()?)?;
        assert!(matches!(
            inbox.ingest_v2(&mut queue, &rosters()?, now()),
            Err(DurableInboxError::Queue(BridgeRefusal::AckDigestMismatch))
        ));
        assert_eq!(inbox.stats()?.quarantined, 1);
        assert_eq!(queue.relay.len()?, 1);
        drop(inbox);

        let mut inbox = DurableRelayInboxV1::open(&inbox_root, config()?, &rosters()?)?;
        let retry = inbox.ingest_v2(&mut queue, &rosters()?, now())?;
        assert_eq!((retry.quarantined, retry.quarantine_duplicates), (0, 1));
        assert_eq!(queue.relay.len()?, 0);
        assert_eq!(inbox.stats()?.quarantined, 1);
        Ok(())
    }

    #[test]
    fn resolved_quarantine_frees_raw_capacity_for_the_next_relay_head() -> Result<(), Box<dyn Error>>
    {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("relay-quarantine-quota");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
        let (first, first_digest) = envelope_with_snapshot(
            message_type::RFQ,
            0,
            ZERO_DIGEST,
            b"first-refusal",
            0x44,
            [0x97; 32],
        )?;
        let (second, _) = envelope_with_snapshot(
            message_type::RFQ,
            1,
            first_digest,
            b"second-refusal",
            0x45,
            [0x97; 32],
        )?;
        relay.submit(&first)?;
        relay.submit(&second)?;
        let inbox_root = temporary.path().join("inbox-quarantine-quota");
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config_with_max(1)?, &rosters()?)?;
        assert_eq!(inbox.ingest(&mut relay, &rosters()?, now())?.quarantined, 1);
        assert!(matches!(
            inbox.ingest(&mut relay, &rosters()?, now()),
            Err(DurableInboxError::CapacityExceeded)
        ));
        assert_eq!(relay.len()?, 1, "full quarantine never ACKs the head");
        assert_eq!(inbox.stats()?.quarantined, 1);
        let mut release =
            TestQuarantineAuthority::new(DurableQuarantineResolutionV1::ReleaseFailedClosed);
        inbox.resolve_quarantine(1, &rosters()?, now(), &mut release)?;
        assert_eq!(inbox.ingest(&mut relay, &rosters()?, now())?.quarantined, 1);
        let stats = inbox.stats()?;
        assert_eq!((stats.quarantined, stats.quarantine_released), (1, 1));
        assert_eq!(stats.quarantine_retained, 2);
        assert_eq!(relay.len()?, 0, "the next committed quarantine is ACKed");
        Ok(())
    }

    #[test]
    fn quarantine_churn_over_twice_the_quota_keeps_bounded_storage() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("relay-quarantine-churn");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
        let mut previous = ZERO_DIGEST;
        for sequence in 0_u64..6 {
            let payload = sequence.to_be_bytes();
            let (raw, digest) = envelope_with_snapshot(
                message_type::RFQ,
                sequence,
                previous,
                &payload,
                u8::try_from(0x60_u64 + sequence)?,
                [0x97; 32],
            )?;
            relay.submit(&raw)?;
            previous = digest;
        }

        let inbox_root = temporary.path().join("inbox-quarantine-churn");
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config_with_max(2)?, &rosters()?)?;
        let mut release =
            TestQuarantineAuthority::new(DurableQuarantineResolutionV1::ReleaseFailedClosed);
        for ordinal in 1_u64..=6 {
            assert_eq!(inbox.ingest(&mut relay, &rosters()?, now())?.quarantined, 1);
            inbox.resolve_quarantine(ordinal, &rosters()?, now(), &mut release)?;
            let retained: i64 =
                inbox
                    .connection
                    .query_row("SELECT COUNT(*) FROM inbox_quarantine", [], |row| {
                        row.get(0)
                    })?;
            assert!(retained <= 2, "quarantine storage must remain bounded");
            assert_eq!(inbox.stats()?.quarantine_resolved_pending_compaction, 0);
        }
        let stats = inbox.stats()?;
        assert_eq!((stats.quarantined, stats.quarantine_retained), (0, 2));
        assert_eq!(stats.quarantine_released, 2);
        assert_eq!(relay.len()?, 0);
        drop(inbox);
        assert!(DurableRelayInboxV1::open(&inbox_root, config_with_max(2)?, &rosters()?).is_ok());
        Ok(())
    }

    #[test]
    fn resolution_commit_lost_before_compaction_resumes_without_freeing_early(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("relay-resolution-before-compact");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
        let (first, first_digest) = envelope_with_snapshot(
            message_type::RFQ,
            0,
            ZERO_DIGEST,
            b"resolution-committed",
            0x68,
            [0x97; 32],
        )?;
        let (second, _) = envelope_with_snapshot(
            message_type::RFQ,
            1,
            first_digest,
            b"blocked-before-compaction",
            0x69,
            [0x97; 32],
        )?;
        relay.submit(&first)?;
        relay.submit(&second)?;
        let inbox_root = temporary.path().join("inbox-resolution-before-compact");
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config_with_max(1)?, &rosters()?)?;
        assert_eq!(inbox.ingest(&mut relay, &rosters()?, now())?.quarantined, 1);
        let retained = inbox
            .load_quarantine_by_ordinal(1)?
            .ok_or("missing quarantine")?;
        let receipt = [0xa7; 32];
        inbox.mark_quarantine_resolved(&retained, 2, receipt)?;
        drop(inbox);

        let mut inbox = DurableRelayInboxV1::open(&inbox_root, config_with_max(1)?, &rosters()?)?;
        let stats = inbox.stats()?;
        assert_eq!(
            (
                stats.quarantined,
                stats.quarantine_resolved_pending_compaction
            ),
            (0, 1)
        );
        assert!(matches!(
            inbox.ingest(&mut relay, &rosters()?, now()),
            Err(DurableInboxError::CapacityExceeded)
        ));
        assert_eq!(
            relay.len()?,
            1,
            "raw capacity is not freed before compaction"
        );
        let mut release = TestQuarantineAuthority::with_committed(
            DurableQuarantineResolutionV1::ReleaseFailedClosed,
            retained.record_digest,
            receipt,
        );
        let resumed = inbox.resolve_quarantine(1, &rosters()?, now(), &mut release)?;
        assert!(resumed.duplicate_commit);
        assert_eq!(inbox.ingest(&mut relay, &rosters()?, now())?.quarantined, 1);
        assert_eq!(relay.len()?, 0);
        Ok(())
    }

    #[test]
    fn compaction_commit_survives_reopen_and_is_an_exact_duplicate() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("relay-after-compact");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
        let (raw, _) = envelope_with_snapshot(
            message_type::RFQ,
            0,
            ZERO_DIGEST,
            b"compact-committed",
            0x6a,
            [0x97; 32],
        )?;
        relay.submit(&raw)?;
        let inbox_root = temporary.path().join("inbox-after-compact");
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config_with_max(1)?, &rosters()?)?;
        assert_eq!(inbox.ingest(&mut relay, &rosters()?, now())?.quarantined, 1);
        let retained = inbox
            .load_quarantine_by_ordinal(1)?
            .ok_or("missing quarantine")?;
        inbox.mark_quarantine_resolved(&retained, 2, [0xa7; 32])?;
        assert!(!inbox.compact_resolved_quarantine(1)?);
        drop(inbox);

        let mut inbox = DurableRelayInboxV1::open(&inbox_root, config_with_max(1)?, &rosters()?)?;
        let mut authority =
            TestQuarantineAuthority::new(DurableQuarantineResolutionV1::ReleaseFailedClosed);
        let report = inbox.resolve_quarantine(1, &rosters()?, now(), &mut authority)?;
        assert_eq!(
            report.resolution,
            DurableQuarantineResolutionV1::ReleaseFailedClosed
        );
        assert!(report.duplicate_commit);
        assert!(
            authority.observed_debug.is_none(),
            "compact receipt avoids raw reauthorization"
        );
        assert_eq!(inbox.stats()?.quarantine_released, 1);
        Ok(())
    }

    #[test]
    fn quarantine_resolution_process_loss_subprocess() {
        let Some(root) = std::env::var_os(TEST_QUARANTINE_ROOT_ENV) else {
            return;
        };
        let boundary = std::env::var_os(TEST_QUARANTINE_EXIT_ENV)
            .expect("process-loss child requires one exact boundary");
        assert!(matches!(
            boundary.to_str(),
            Some("resolution-commit" | "compaction-commit")
        ));
        let mut inbox = DurableRelayInboxV1::open(
            &PathBuf::from(root),
            config_with_max(1).expect("inbox config"),
            &rosters().expect("roster"),
        )
        .expect("open process-loss fixture");
        let mut release =
            TestQuarantineAuthority::new(DurableQuarantineResolutionV1::ReleaseFailedClosed);
        let result = inbox.resolve_quarantine(1, &rosters().expect("roster"), now(), &mut release);
        panic!("quarantine resolution reached caller instead of exiting: {result:?}");
    }

    #[test]
    fn actual_process_loss_at_resolution_and_compaction_commits_converges(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let make_fixture = |label: &str| -> Result<PathBuf, Box<dyn Error>> {
            let relay_root = temporary.path().join(format!("relay-{label}"));
            let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
            let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
            let (raw, _) = envelope_with_snapshot(
                message_type::RFQ,
                0,
                ZERO_DIGEST,
                label.as_bytes(),
                0x6f,
                [0x97; 32],
            )?;
            relay.submit(&raw)?;
            let inbox_root = temporary.path().join(format!("inbox-{label}"));
            let mut inbox =
                DurableRelayInboxV1::create(&inbox_root, config_with_max(1)?, &rosters()?)?;
            assert_eq!(inbox.ingest(&mut relay, &rosters()?, now())?.quarantined, 1);
            drop(inbox);
            drop(relay);
            Ok(inbox_root)
        };

        let resolution_root = make_fixture("loss-after-resolution")?;
        let status = Command::new(std::env::current_exe()?)
            .arg("quarantine_resolution_process_loss_subprocess")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(TEST_QUARANTINE_ROOT_ENV, &resolution_root)
            .env(TEST_QUARANTINE_EXIT_ENV, "resolution-commit")
            .status()?;
        assert_eq!(status.code(), Some(86));
        let mut inbox =
            DurableRelayInboxV1::open(&resolution_root, config_with_max(1)?, &rosters()?)?;
        assert_eq!(inbox.stats()?.quarantine_resolved_pending_compaction, 1);
        let retained = inbox
            .load_quarantine_by_ordinal(1)?
            .ok_or("missing resolution commit")?;
        let mut release = TestQuarantineAuthority::with_committed(
            DurableQuarantineResolutionV1::ReleaseFailedClosed,
            retained.record_digest,
            [0xa7; 32],
        );
        assert!(
            inbox
                .resolve_quarantine(1, &rosters()?, now(), &mut release)?
                .duplicate_commit
        );
        drop(inbox);

        let compaction_root = make_fixture("loss-after-compaction")?;
        let status = Command::new(std::env::current_exe()?)
            .arg("quarantine_resolution_process_loss_subprocess")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(TEST_QUARANTINE_ROOT_ENV, &compaction_root)
            .env(TEST_QUARANTINE_EXIT_ENV, "compaction-commit")
            .status()?;
        assert_eq!(status.code(), Some(86));
        let mut inbox =
            DurableRelayInboxV1::open(&compaction_root, config_with_max(1)?, &rosters()?)?;
        assert_eq!(inbox.stats()?.quarantine_released, 1);
        let mut release =
            TestQuarantineAuthority::new(DurableQuarantineResolutionV1::ReleaseFailedClosed);
        assert!(
            inbox
                .resolve_quarantine(1, &rosters()?, now(), &mut release)?
                .duplicate_commit
        );
        Ok(())
    }

    #[test]
    fn unresolved_quarantine_is_never_evicted_by_compact_receipt_churn(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("relay-unresolved-retained");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
        let mut previous = ZERO_DIGEST;
        for sequence in 0_u64..5 {
            let payload = sequence.to_be_bytes();
            let (raw, digest) = envelope_with_snapshot(
                message_type::RFQ,
                sequence,
                previous,
                &payload,
                u8::try_from(0x6b_u64 + sequence)?,
                [0x97; 32],
            )?;
            relay.submit(&raw)?;
            previous = digest;
        }
        let inbox_root = temporary.path().join("inbox-unresolved-retained");
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config_with_max(2)?, &rosters()?)?;
        assert_eq!(inbox.ingest(&mut relay, &rosters()?, now())?.quarantined, 1);
        let mut release =
            TestQuarantineAuthority::new(DurableQuarantineResolutionV1::ReleaseFailedClosed);
        for ordinal in 2_u64..=5 {
            assert_eq!(inbox.ingest(&mut relay, &rosters()?, now())?.quarantined, 1);
            inbox.resolve_quarantine(ordinal, &rosters()?, now(), &mut release)?;
        }

        let first = inbox
            .load_quarantine_by_ordinal(1)?
            .ok_or("unresolved record evicted")?;
        assert_eq!(first.resolution_state, 0);
        assert!(!first.canonical_bytes.is_empty());
        assert!(inbox.load_quarantine_by_ordinal(2)?.is_none());
        assert!(inbox.load_quarantine_by_ordinal(3)?.is_none());
        assert!(inbox.load_quarantine_by_ordinal(4)?.is_some());
        assert!(inbox.load_quarantine_by_ordinal(5)?.is_some());
        let stats = inbox.stats()?;
        assert_eq!((stats.quarantined, stats.quarantine_retained), (1, 3));
        assert_eq!(stats.quarantine_released, 2);
        assert_eq!(relay.len()?, 0);
        Ok(())
    }

    #[test]
    fn evicted_compact_receipt_replay_fails_closed_without_mutation() -> Result<(), Box<dyn Error>>
    {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("relay-old-compact-replay");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
        let (first, first_digest) = envelope_with_snapshot(
            message_type::RFQ,
            0,
            ZERO_DIGEST,
            b"old-compact-receipt",
            0x70,
            [0x97; 32],
        )?;
        let (second, _) = envelope_with_snapshot(
            message_type::RFQ,
            1,
            first_digest,
            b"new-compact-receipt",
            0x71,
            [0x97; 32],
        )?;
        relay.submit(&first)?;
        relay.submit(&second)?;
        let current = relay.acknowledged_delivery_cursor_v2(&SOLVER)?;
        let page = relay.delivery_page_v2(
            &SOLVER,
            &current,
            relay::production::DeliveryPageLimitsV2::new(1, relay::MAX_ENVELOPE_BYTES as u32)?,
        )?;
        let old_relay_ordinal = page.ordinals()[0];
        let old_current = *page.current_cursor();
        let old_next = *page.next_cursor();
        drop(page);

        let inbox_root = temporary.path().join("inbox-old-compact-replay");
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config_with_max(1)?, &rosters()?)?;
        let mut release =
            TestQuarantineAuthority::new(DurableQuarantineResolutionV1::ReleaseFailedClosed);
        inbox.ingest(&mut relay, &rosters()?, now())?;
        inbox.resolve_quarantine(1, &rosters()?, now(), &mut release)?;
        let recent_before = inbox.stats()?;
        assert!(inbox.persist_quarantine(
            old_relay_ordinal,
            &old_current,
            &old_next,
            &first,
            DurableQuarantineReasonV1::WrongRosterSnapshot,
            now(),
        )?);
        assert_eq!(inbox.stats()?, recent_before);
        inbox.ingest(&mut relay, &rosters()?, now())?;
        inbox.resolve_quarantine(2, &rosters()?, now(), &mut release)?;
        assert!(inbox.load_quarantine_by_ordinal(1)?.is_none());
        let before = inbox.stats()?;
        let before_rows: i64 =
            inbox
                .connection
                .query_row("SELECT COUNT(*) FROM inbox_quarantine", [], |row| {
                    row.get(0)
                })?;
        assert!(matches!(
            inbox.persist_quarantine(
                old_relay_ordinal,
                &old_current,
                &old_next,
                &first,
                DurableQuarantineReasonV1::WrongRosterSnapshot,
                now(),
            ),
            Err(DurableInboxError::CompactedQuarantineReplay)
        ));
        assert_eq!(inbox.stats()?, before);
        let after_rows: i64 =
            inbox
                .connection
                .query_row("SELECT COUNT(*) FROM inbox_quarantine", [], |row| {
                    row.get(0)
                })?;
        assert_eq!(after_rows, before_rows);
        Ok(())
    }

    #[test]
    fn same_relay_cursor_with_different_bytes_is_quarantine_equivocation(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("relay-quarantine-equivocation");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
        let (first, _) = envelope_with_snapshot(
            message_type::RFQ,
            0,
            ZERO_DIGEST,
            b"first-bytes",
            0x46,
            [0x96; 32],
        )?;
        let (different, _) = envelope_with_snapshot(
            message_type::RFQ,
            0,
            ZERO_DIGEST,
            b"different-bytes",
            0x47,
            [0x96; 32],
        )?;
        relay.submit(&first)?;
        let current = relay.acknowledged_delivery_cursor_v2(&SOLVER)?;
        let page = relay.delivery_page_v2(
            &SOLVER,
            &current,
            relay::production::DeliveryPageLimitsV2::new(1, relay::MAX_ENVELOPE_BYTES as u32)?,
        )?;
        let inbox_root = temporary.path().join("inbox-quarantine-equivocation");
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config()?, &rosters()?)?;
        assert!(!inbox.persist_quarantine(
            page.ordinals()[0],
            page.current_cursor(),
            page.next_cursor(),
            &first,
            DurableQuarantineReasonV1::WrongRosterSnapshot,
            now(),
        )?);
        assert!(matches!(
            inbox.persist_quarantine(
                page.ordinals()[0],
                page.current_cursor(),
                page.next_cursor(),
                &different,
                DurableQuarantineReasonV1::WrongRosterSnapshot,
                now(),
            ),
            Err(DurableInboxError::QuarantineEquivocation)
        ));
        assert_eq!(inbox.stats()?.quarantined, 1);
        Ok(())
    }

    #[test]
    fn quarantine_record_or_chain_tamper_fails_reopen_closed() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("relay-quarantine-tamper");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
        let (raw, _) = envelope_with_snapshot(
            message_type::RFQ,
            0,
            ZERO_DIGEST,
            b"tamper-evidence",
            0x4a,
            [0x94; 32],
        )?;
        relay.submit(&raw)?;
        let inbox_root = temporary.path().join("inbox-quarantine-tamper");
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config()?, &rosters()?)?;
        inbox.ingest(&mut relay, &rosters()?, now())?;
        drop(inbox);
        drop(relay);

        let database = inbox_root.join(DATABASE_FILE_NAME);
        let connection = Connection::open(&database)?;
        connection.execute("UPDATE inbox_quarantine SET reason = 2", [])?;
        drop(connection);
        assert!(matches!(
            DurableRelayInboxV1::open(&inbox_root, config()?, &rosters()?),
            Err(DurableInboxError::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn compact_root_or_receipt_tamper_fails_reopen_closed() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let make_compact_fixture = |label: &str| -> Result<PathBuf, Box<dyn Error>> {
            let relay_root = temporary.path().join(format!("relay-{label}"));
            let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
            let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
            let (raw, _) = envelope_with_snapshot(
                message_type::RFQ,
                0,
                ZERO_DIGEST,
                label.as_bytes(),
                0x72,
                [0x97; 32],
            )?;
            relay.submit(&raw)?;
            let inbox_root = temporary.path().join(format!("inbox-{label}"));
            let mut inbox =
                DurableRelayInboxV1::create(&inbox_root, config_with_max(1)?, &rosters()?)?;
            inbox.ingest(&mut relay, &rosters()?, now())?;
            let mut release =
                TestQuarantineAuthority::new(DurableQuarantineResolutionV1::ReleaseFailedClosed);
            inbox.resolve_quarantine(1, &rosters()?, now(), &mut release)?;
            drop(inbox);
            drop(relay);
            Ok(inbox_root)
        };

        let root_tamper = make_compact_fixture("compact-root-tamper")?;
        let connection = Connection::open(root_tamper.join(DATABASE_FILE_NAME))?;
        connection.execute(
            "UPDATE inbox_meta SET quarantine_compact_root = ?1",
            params![[0xf1_u8; 32].as_slice()],
        )?;
        drop(connection);
        assert!(matches!(
            DurableRelayInboxV1::open(&root_tamper, config_with_max(1)?, &rosters()?),
            Err(DurableInboxError::CorruptState)
        ));

        let receipt_tamper = make_compact_fixture("compact-receipt-tamper")?;
        let connection = Connection::open(receipt_tamper.join(DATABASE_FILE_NAME))?;
        connection.execute(
            "UPDATE inbox_quarantine SET resolution_receipt = ?1",
            params![[0xf2_u8; 32].as_slice()],
        )?;
        drop(connection);
        assert!(matches!(
            DurableRelayInboxV1::open(&receipt_tamper, config_with_max(1)?, &rosters()?),
            Err(DurableInboxError::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn reprocess_and_release_require_explicit_durable_authority() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("relay-quarantine-resolution");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
        let secret_payload = b"resolution-secret-payload";
        let (unknown_roster, _) =
            envelope(message_type::RFQ, 0, ZERO_DIGEST, secret_payload, 0x48)?;
        relay.submit(&unknown_roster)?;
        let inbox_root = temporary.path().join("inbox-quarantine-resolution");
        let empty_rosters = RosterRegistryV1::new();
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config()?, &empty_rosters)?;
        assert_eq!(
            inbox.ingest(&mut relay, &empty_rosters, now())?.quarantined,
            1
        );
        let mut reprocess = TestQuarantineAuthority::new(DurableQuarantineResolutionV1::Reprocess);
        let first = inbox.resolve_quarantine(1, &rosters()?, now(), &mut reprocess)?;
        assert_eq!(first.resolution, DurableQuarantineResolutionV1::Reprocess);
        assert!(!first.duplicate_commit);
        assert_eq!(inbox.stats()?.quarantine_reprocessed, 1);
        assert_eq!(inbox.stats()?.pending_f6, 1);
        let debug = reprocess.observed_debug.as_deref().ok_or("missing debug")?;
        assert!(!debug.contains("resolution-secret-payload"));
        let duplicate = inbox.resolve_quarantine(1, &rosters()?, now(), &mut reprocess)?;
        assert!(duplicate.duplicate_commit);

        let release_root = temporary.path().join("inbox-quarantine-release");
        let relay_root = temporary.path().join("relay-quarantine-release");
        let release_relay_config =
            RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut release_relay = ProductionRelayV1::create(&relay_root, release_relay_config)?;
        let (wrong_roster, _) = envelope_with_snapshot(
            message_type::RFQ,
            0,
            ZERO_DIGEST,
            b"release-failed-closed",
            0x49,
            [0x95; 32],
        )?;
        release_relay.submit(&wrong_roster)?;
        let mut release_inbox = DurableRelayInboxV1::create(&release_root, config()?, &rosters()?)?;
        release_inbox.ingest(&mut release_relay, &rosters()?, now())?;
        let mut refused_reprocess =
            TestQuarantineAuthority::new(DurableQuarantineResolutionV1::Reprocess);
        assert!(matches!(
            release_inbox.resolve_quarantine(1, &rosters()?, now(), &mut refused_reprocess,),
            Err(DurableQuarantineResolutionErrorV1::StillRefused)
        ));
        assert_eq!(release_inbox.stats()?.quarantined, 1);
        assert_eq!(release_inbox.stats()?.pending_f6, 0);
        let mut release =
            TestQuarantineAuthority::new(DurableQuarantineResolutionV1::ReleaseFailedClosed);
        release_inbox.resolve_quarantine(1, &rosters()?, now(), &mut release)?;
        assert_eq!(release_inbox.stats()?.quarantine_released, 1);
        assert_eq!(release_inbox.stats()?.pending_f6, 0);
        Ok(())
    }

    #[test]
    fn substituted_authority_record_cannot_resolve_or_free_quarantine() -> Result<(), Box<dyn Error>>
    {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let relay_root = temporary.path().join("relay-quarantine-substitution");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
        let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;
        let (raw, _) = envelope_with_snapshot(
            message_type::RFQ,
            0,
            ZERO_DIGEST,
            b"authority-substitution-evidence",
            0x4b,
            [0x93; 32],
        )?;
        relay.submit(&raw)?;
        let inbox_root = temporary.path().join("inbox-quarantine-substitution");
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config()?, &rosters()?)?;
        assert_eq!(inbox.ingest(&mut relay, &rosters()?, now())?.quarantined, 1);

        assert!(matches!(
            inbox.resolve_quarantine(1, &rosters()?, now(), &mut SubstitutedRecordAuthority,),
            Err(DurableQuarantineResolutionErrorV1::Inbox(
                DurableInboxError::InvalidConsumerCommit
            ))
        ));
        let stats = inbox.stats()?;
        assert_eq!((stats.quarantined, stats.quarantine_retained), (1, 1));
        assert_eq!(
            (stats.quarantine_reprocessed, stats.quarantine_released),
            (0, 0)
        );
        Ok(())
    }

    #[test]
    fn applied_replay_is_read_only_and_requires_exact_duplicate_receipts(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let root = temporary.path().join("applied-replay");
        let config = config()?;
        let rosters = rosters()?;
        let mut relay = RelayV1::new();
        let (rfq, rfq_digest) = envelope(message_type::RFQ, 0, ZERO_DIGEST, b"rfq", 0x61)?;
        let (acceptance, acceptance_digest) =
            envelope(message_type::ACCEPTANCE, 1, rfq_digest, b"acceptance", 0x62)?;
        relay.submit(&rfq)?;
        relay.submit(&acceptance)?;
        let mut inbox = DurableRelayInboxV1::create(&root, config, &rosters)?;
        assert_eq!(
            inbox.ingest_ephemeral_v1(&relay, &rosters, now())?.accepted,
            2
        );
        let mut initial = DurableTestF6Port::default();
        assert_eq!(inbox.dispatch_f6(&mut initial)?.applied, 2);
        drop(inbox);
        drop(initial);

        let reopened = DurableRelayInboxV1::open(&root, config, &rosters)?;
        let before = reopened.stats()?;
        let mut resumed = DurableTestF6Port {
            receipts: BTreeSet::from([rfq_digest, acceptance_digest]),
            ..DurableTestF6Port::default()
        };
        assert_eq!(reopened.replay_applied_f6(&mut resumed)?.replayed, 2);
        assert_eq!(reopened.stats()?, before);
        drop(reopened);

        let reopened = DurableRelayInboxV1::open(&root, config, &rosters)?;
        assert_eq!(reopened.stats()?, before);
        let mut wrong_receipt = DurableTestF6Port {
            receipts: BTreeSet::from([rfq_digest, acceptance_digest]),
            force_receipt: Some([0xf1; 32]),
            ..DurableTestF6Port::default()
        };
        assert!(matches!(
            reopened.replay_applied_f6(&mut wrong_receipt),
            Err(F6AppliedReplayErrorV1::Inbox(
                DurableInboxError::CorruptState
            ))
        ));
        assert_eq!(reopened.stats()?, before);
        Ok(())
    }

    #[test]
    fn applied_replay_rejects_nonduplicate_and_failed_closed_responses(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let root = temporary.path().join("divergent-replay");
        let config = config()?;
        let rosters = rosters()?;
        let mut relay = RelayV1::new();
        let (rfq, digest) = envelope(message_type::RFQ, 0, ZERO_DIGEST, b"rfq", 0x63)?;
        relay.submit(&rfq)?;
        let mut inbox = DurableRelayInboxV1::create(&root, config, &rosters)?;
        inbox.ingest_ephemeral_v1(&relay, &rosters, now())?;
        inbox.dispatch_f6(&mut DurableTestF6Port::default())?;
        let before = inbox.stats()?;

        for (disposition, force_nonduplicate) in [
            (DurablePayloadDispositionV1::Applied, true),
            (DurablePayloadDispositionV1::FailedClosed, false),
        ] {
            let mut divergent = DurableTestF6Port {
                receipts: BTreeSet::from([digest]),
                disposition: Some(disposition),
                force_nonduplicate,
                force_receipt: None,
            };
            assert!(matches!(
                inbox.replay_applied_f6(&mut divergent),
                Err(F6AppliedReplayErrorV1::Inbox(
                    DurableInboxError::CorruptState
                ))
            ));
            assert_eq!(inbox.stats()?, before);
        }
        Ok(())
    }

    fn wire() -> RouteWireContextV1 {
        RouteWireContextV1 {
            network_id: NETWORK,
            session_id: SESSION,
            route_id: ROUTE,
            roster_snapshot: SNAPSHOT,
            policy_version: 1,
        }
    }

    fn config() -> Result<DurableInboxConfigV1, DurableInboxError> {
        DurableInboxConfigV1::new([0x54; 32], [0x91; 32], wire(), SOLVER, 16)
    }

    fn config_with_max(max_entries: u32) -> Result<DurableInboxConfigV1, DurableInboxError> {
        DurableInboxConfigV1::new([0x54; 32], [0x91; 32], wire(), SOLVER, max_entries)
    }

    fn rosters() -> Result<RosterRegistryV1, Box<dyn Error>> {
        let secp = SecpContext::new(&[0x55; 32]);
        let initiator_key = secp.xonly_public_key(&INITIATOR_SECRET)?;
        let solver_key = secp.xonly_public_key(&SOLVER_SECRET)?;
        Ok(RosterRegistryV1::new().with_snapshot(
            SNAPSHOT,
            RosterSnapshotV1::new()
                .with_member(
                    INITIATOR,
                    RosterMemberV1 {
                        xonly_key: initiator_key,
                        role: SenderRoleV1::Initiator,
                    },
                )
                .with_member(
                    SOLVER,
                    RosterMemberV1 {
                        xonly_key: solver_key,
                        role: SenderRoleV1::Solver,
                    },
                ),
        ))
    }

    fn now() -> TimelockSpec {
        TimelockSpec::TimestampSeconds { value: 1_000 }
    }

    fn envelope(
        kind: u16,
        sequence: u64,
        previous: Digest32,
        payload: &[u8],
        aux: u8,
    ) -> Result<(Vec<u8>, Digest32), Box<dyn Error>> {
        envelope_with_snapshot(kind, sequence, previous, payload, aux, SNAPSHOT)
    }

    fn envelope_with_snapshot(
        kind: u16,
        sequence: u64,
        previous: Digest32,
        payload: &[u8],
        aux: u8,
        roster_snapshot: Digest32,
    ) -> Result<(Vec<u8>, Digest32), Box<dyn Error>> {
        let mut envelope = RelayEnvelopeV1 {
            network_id: NETWORK,
            message_type: kind,
            session_id: SESSION,
            route_id: ROUTE,
            sender_id: INITIATOR,
            recipient_id: SOLVER,
            sender_role: SenderRoleV1::Initiator,
            sequence,
            previous_transcript_hash: previous,
            payload: payload.to_vec(),
            expiry: TimelockSpec::TimestampSeconds { value: 10_000 },
            policy_version: 1,
            roster_snapshot,
            signature: [0; 64],
        };
        let digest = envelope.envelope_digest()?;
        envelope.signature = SecpContext::new(&[0x55; 32])
            .sign_bip340(&INITIATOR_SECRET, &digest, &[aux; 32])?
            .0;
        Ok((envelope.canonical_bytes()?, digest))
    }
}
