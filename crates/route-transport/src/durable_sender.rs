//! Linux owner-only durable sender/outbox for one addressed Relay V1 flow.
//!
//! One checkpoint is shared by every ratified F6 kind and route transport.
//! Exactly one signed envelope may be pending.  It is committed before a
//! queue call, and an authenticated ACK advances the checkpoint, appends the
//! compact history record and removes the pending row in one SQLite
//! transaction.  Store-issued DSC1 applications additionally retain their
//! exact bytes, digest, reserved sequence range and direct/framed progress so
//! restart can reconcile both sides of the handoff without another sequence.
//! The signing scalar is held only in zeroizing process memory.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use btc_crypto::SecpContext;
use kaystra_core::types::Digest32;
use relay::auth::{message_type, CanonicalMessageTypePolicyV1};
use relay::server::{AckV1, IdempotencyKeyV1, ACK_V1_LEN};
use relay::{ParticipantId, RelayEnvelopeV1, SenderRoleV1, TimelockSpec};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use rustix::fs::{flock, FlockOperation};
use rustix::process::geteuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    framing::full_message_digest_v2, DurableProductionCreationStateV1, RelayQueueV1,
    RouteFramePlanV2, RouteSenderCheckpointV1, RouteWireContextV1, MAX_FRAMED_DSC1_BYTES_V2,
    MAX_ROUTE_FRAME_COUNT_V2, MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES, ROUTE_SENDER_CHECKPOINT_LEN,
};

const DATABASE_FILE_NAME: &str = "route-sender-v1.sqlite3";
const LOCK_FILE_NAME: &str = ".route-sender.lock";
const ROOT_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const SCHEMA_VERSION: i64 = 2;
const LEGACY_SCHEMA_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x444f_4d53; // "DOMS"
const MAX_COMPLETED_ENVELOPES: u32 = 65_536;
const ZERO_DIGEST: Digest32 = [0; 32];
const PENDING_DOMAIN: &[u8] = b"DOM-INTEROP/RELAY-SENDER/PENDING/STORE-V2\0";
const HISTORY_DOMAIN: &[u8] = b"DOM-INTEROP/RELAY-SENDER/HISTORY/STORE-V2\0";
const FRAME_JOB_DOMAIN: &[u8] = b"DOM-INTEROP/RELAY-SENDER/FRAME-JOB/STORE-V2\0";
const ROUTE_APPLICATION_DOMAIN: &[u8] = b"DOM-INTEROP/RELAY-SENDER/ROUTE-APPLICATION/V2\0";
const ROUTE_APPLICATION_DIRECT: i64 = 1;
const ROUTE_APPLICATION_FRAMED: i64 = 2;
const ROUTE_APPLICATION_PENDING: i64 = 1;
const ROUTE_APPLICATION_ACKED: i64 = 2;
const _: [(); 146] = [(); ACK_V1_LEN];
const _: [(); 282] = [(); ROUTE_SENDER_CHECKPOINT_LEN];

const SCHEMA_SQL: &str = r#"
CREATE TABLE sender_meta (
    singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version     INTEGER NOT NULL CHECK (schema_version = 2),
    sender_store_id    BLOB NOT NULL CHECK (length(sender_store_id) = 32),
    network_id         BLOB NOT NULL CHECK (length(network_id) = 32),
    session_id         BLOB NOT NULL CHECK (length(session_id) = 32),
    route_id           BLOB NOT NULL CHECK (length(route_id) = 32),
    roster_snapshot    BLOB NOT NULL CHECK (length(roster_snapshot) = 32),
    policy_version     INTEGER NOT NULL CHECK (policy_version > 0),
    sender_id          BLOB NOT NULL CHECK (length(sender_id) = 32),
    recipient_id       BLOB NOT NULL CHECK (length(recipient_id) = 32),
    sender_role        INTEGER NOT NULL CHECK (sender_role BETWEEN 1 AND 2),
    signer_xonly       BLOB NOT NULL CHECK (length(signer_xonly) = 32),
    max_envelopes      INTEGER NOT NULL CHECK (max_envelopes BETWEEN 1 AND 65536),
    completed_count    INTEGER NOT NULL CHECK (
        completed_count >= 0 AND completed_count <= max_envelopes
    ),
    checkpoint_bytes   BLOB NOT NULL CHECK (length(checkpoint_bytes) = 282)
) STRICT;

CREATE TABLE sender_pending (
    singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
    application_id     BLOB CHECK (
        application_id IS NULL OR
        (length(application_id) = 32 AND application_id != zeroblob(32))
    ),
    message_type       INTEGER NOT NULL CHECK (message_type BETWEEN 1 AND 5),
    sequence_be        BLOB NOT NULL CHECK (length(sequence_be) = 8),
    previous_digest    BLOB NOT NULL CHECK (length(previous_digest) = 32),
    envelope_digest    BLOB NOT NULL CHECK (length(envelope_digest) = 32),
    canonical_bytes    BLOB NOT NULL CHECK (
        length(canonical_bytes) BETWEEN 1 AND 16742
    ),
    frame_index        INTEGER NOT NULL CHECK (frame_index BETWEEN -1 AND 32),
    frame_count        INTEGER NOT NULL CHECK (
        frame_count = 0 OR frame_count BETWEEN 2 AND 33
    ),
    frame_binding      BLOB NOT NULL CHECK (length(frame_binding) = 32),
    row_digest         BLOB NOT NULL CHECK (length(row_digest) = 32),
    FOREIGN KEY (singleton) REFERENCES sender_meta(singleton),
    FOREIGN KEY (application_id) REFERENCES route_application(application_id),
    CHECK (
        (frame_index = -1 AND frame_count = 0 AND frame_binding = zeroblob(32)) OR
        (frame_index >= 0 AND frame_index < frame_count AND
         frame_count >= 2 AND frame_binding != zeroblob(32))
    )
) STRICT;

CREATE TABLE sender_history (
    ordinal            INTEGER PRIMARY KEY CHECK (ordinal BETWEEN 1 AND 65536),
    application_id     BLOB CHECK (
        application_id IS NULL OR
        (length(application_id) = 32 AND application_id != zeroblob(32))
    ),
    sequence_be        BLOB NOT NULL UNIQUE CHECK (length(sequence_be) = 8),
    previous_digest    BLOB NOT NULL CHECK (length(previous_digest) = 32),
    message_type       INTEGER NOT NULL CHECK (message_type BETWEEN 1 AND 5),
    envelope_digest    BLOB NOT NULL CHECK (length(envelope_digest) = 32),
    ack_bytes          BLOB NOT NULL CHECK (length(ack_bytes) = 146),
    frame_index        INTEGER NOT NULL CHECK (frame_index BETWEEN -1 AND 32),
    frame_count        INTEGER NOT NULL CHECK (
        frame_count = 0 OR frame_count BETWEEN 2 AND 33
    ),
    frame_binding      BLOB NOT NULL CHECK (length(frame_binding) = 32),
    row_digest         BLOB NOT NULL CHECK (length(row_digest) = 32),
    FOREIGN KEY (application_id) REFERENCES route_application(application_id),
    CHECK (
        (frame_index = -1 AND frame_count = 0 AND frame_binding = zeroblob(32)) OR
        (frame_index >= 0 AND frame_index < frame_count AND
         frame_count >= 2 AND frame_binding != zeroblob(32))
    )
) STRICT;

CREATE TABLE frame_transfer (
    singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
    application_id     BLOB CHECK (
        application_id IS NULL OR
        (length(application_id) = 32 AND application_id != zeroblob(32))
    ),
    base_checkpoint    BLOB NOT NULL CHECK (length(base_checkpoint) = 282),
    signed_dsc1        BLOB NOT NULL CHECK (
        length(signed_dsc1) BETWEEN 16385 AND 524501
    ),
    expiry_domain      INTEGER NOT NULL CHECK (expiry_domain BETWEEN 1 AND 3),
    expiry_value_be    BLOB NOT NULL CHECK (length(expiry_value_be) = 8),
    message_digest     BLOB NOT NULL CHECK (length(message_digest) = 32),
    binding_digest     BLOB NOT NULL CHECK (length(binding_digest) = 32),
    frame_count        INTEGER NOT NULL CHECK (frame_count BETWEEN 2 AND 33),
    next_frame         INTEGER NOT NULL CHECK (
        next_frame >= 0 AND next_frame < frame_count
    ),
    row_digest         BLOB NOT NULL CHECK (length(row_digest) = 32),
    FOREIGN KEY (singleton) REFERENCES sender_meta(singleton),
    FOREIGN KEY (application_id) REFERENCES route_application(application_id)
) STRICT;

CREATE TABLE route_application (
    application_id     BLOB PRIMARY KEY NOT NULL CHECK (
        length(application_id) = 32 AND application_id != zeroblob(32)
    ),
    signed_dsc1_digest BLOB NOT NULL UNIQUE CHECK (
        length(signed_dsc1_digest) = 32 AND signed_dsc1_digest != zeroblob(32)
    ),
    signed_dsc1        BLOB NOT NULL CHECK (
        length(signed_dsc1) BETWEEN 1 AND 524501
    ),
    delivery_kind      INTEGER NOT NULL CHECK (delivery_kind BETWEEN 1 AND 2),
    delivery_status    INTEGER NOT NULL CHECK (delivery_status BETWEEN 1 AND 2),
    first_sequence_be  BLOB NOT NULL CHECK (length(first_sequence_be) = 8),
    final_sequence_be  BLOB NOT NULL CHECK (length(final_sequence_be) = 8),
    frame_count        INTEGER NOT NULL CHECK (frame_count BETWEEN 1 AND 33),
    acknowledged_frames INTEGER NOT NULL CHECK (
        acknowledged_frames BETWEEN 0 AND frame_count
    ),
    frame_binding      BLOB NOT NULL CHECK (length(frame_binding) = 32),
    expiry_domain      INTEGER NOT NULL CHECK (expiry_domain BETWEEN 1 AND 3),
    expiry_value_be    BLOB NOT NULL CHECK (length(expiry_value_be) = 8),
    row_digest         BLOB NOT NULL CHECK (length(row_digest) = 32),
    CHECK (
        (delivery_kind = 1 AND length(signed_dsc1) <= 16384 AND
         frame_count = 1 AND frame_binding = zeroblob(32)) OR
        (delivery_kind = 2 AND length(signed_dsc1) BETWEEN 16385 AND 524501 AND
         frame_count BETWEEN 2 AND 33 AND frame_binding != zeroblob(32))
    ),
    CHECK (
        (delivery_status = 1 AND acknowledged_frames < frame_count) OR
        (delivery_status = 2 AND acknowledged_frames = frame_count)
    )
) STRICT;

CREATE UNIQUE INDEX route_application_one_pending
ON route_application(delivery_status) WHERE delivery_status = 1;
"#;

/// Immutable identity and bounds of one durable outbound addressed flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableRelaySenderConfigV1 {
    sender_store_id: Digest32,
    wire: RouteWireContextV1,
    sender_id: ParticipantId,
    recipient_id: ParticipantId,
    sender_role: SenderRoleV1,
    signer_xonly: [u8; 32],
    max_envelopes: u32,
}

impl DurableRelaySenderConfigV1 {
    /// Constructs a non-null configuration bound to the roster signing key.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender_store_id: Digest32,
        wire: RouteWireContextV1,
        sender_id: ParticipantId,
        recipient_id: ParticipantId,
        sender_role: SenderRoleV1,
        signer_xonly: [u8; 32],
        max_envelopes: u32,
    ) -> Result<Self, DurableRelaySenderErrorV1> {
        let secp = SecpContext::new(&[0x53; 32]);
        if sender_store_id == ZERO_DIGEST
            || wire.network_id == ZERO_DIGEST
            || wire.session_id == ZERO_DIGEST
            || wire.route_id == ZERO_DIGEST
            || wire.roster_snapshot == ZERO_DIGEST
            || wire.policy_version == 0
            || sender_id.0 == ZERO_DIGEST
            || recipient_id.0 == ZERO_DIGEST
            || sender_id == recipient_id
            || sender_role == SenderRoleV1::Observer
            || !CanonicalMessageTypePolicyV1.permits(sender_role, message_type::ROUTE_TRANSPORT)
            || secp.validate_xonly_key(&signer_xonly).is_err()
            || max_envelopes == 0
            || max_envelopes > MAX_COMPLETED_ENVELOPES
        {
            return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            sender_store_id,
            wire,
            sender_id,
            recipient_id,
            sender_role,
            signer_xonly,
            max_envelopes,
        })
    }

    /// Stable public identity of the sender store.
    pub const fn sender_store_id(&self) -> &Digest32 {
        &self.sender_store_id
    }

    /// Frozen route wire context shared by every outbound kind.
    pub const fn wire_context(&self) -> RouteWireContextV1 {
        self.wire
    }

    /// Sender participant of this addressed flow.
    pub const fn sender_id(&self) -> ParticipantId {
        self.sender_id
    }

    /// Recipient participant of this addressed flow.
    pub const fn recipient_id(&self) -> ParticipantId {
        self.recipient_id
    }

    /// Frozen sender role used by the canonical message policy.
    pub const fn sender_role(&self) -> SenderRoleV1 {
        self.sender_role
    }

    /// Roster-authenticated BIP340 public key expected from the live signer.
    pub const fn signer_xonly(&self) -> &[u8; 32] {
        &self.signer_xonly
    }

    /// Maximum number of ACKed envelopes this store may retain.
    pub const fn max_envelopes(&self) -> u32 {
        self.max_envelopes
    }

    fn initial_checkpoint(&self) -> RouteSenderCheckpointV1 {
        RouteSenderCheckpointV1 {
            ctx: self.wire,
            sender_id: self.sender_id,
            recipient_id: self.recipient_id,
            role: self.sender_role,
            next_sequence: 0,
            previous_digest: ZERO_DIGEST,
        }
    }
}

/// Redacted failures of the durable outbound authority.
#[derive(Debug, thiserror::Error)]
pub enum DurableRelaySenderErrorV1 {
    /// A binding, path, mode, key, role, or bound is invalid.
    #[error("invalid durable Relay sender configuration")]
    InvalidConfiguration,
    /// Explicit creation found an existing store root.
    #[error("durable Relay sender root already exists")]
    AlreadyExists,
    /// Explicit reopen found no database or lock authority.
    #[error("durable Relay sender database is missing")]
    DatabaseMissing,
    /// Another process owns the store or storage access failed.
    #[error("durable Relay sender storage unavailable")]
    StorageUnavailable,
    /// A schema V1 database requires a separate, audited offline migration.
    #[error("durable Relay sender V1 requires an audited offline migration")]
    LegacyFormatRequiresOfflineMigration,
    /// Schema, SQLite safety settings, or version differ from V2.
    #[error("unsupported durable Relay sender format")]
    UnsupportedFormat,
    /// Retained public identity differs from the expected flow.
    #[error("wrong durable Relay sender identity")]
    WrongIdentity,
    /// The live secret does not correspond to the roster-bound public key.
    #[error("wrong durable Relay signing authority")]
    WrongSigningAuthority,
    /// Retained checkpoint, pending bytes, ACK history or frame job is corrupt.
    #[error("corrupt durable Relay sender state")]
    CorruptState,
    /// The fixed history bound or Relay sequence is exhausted.
    #[error("durable Relay sender capacity exhausted")]
    CapacityExceeded,
    /// A signed envelope is already pending and must be retried byte-identically.
    #[error("a durable Relay envelope is already pending")]
    PendingEnvelopeExists,
    /// No signed envelope exists for submission.
    #[error("no durable Relay envelope is pending")]
    NoPendingEnvelope,
    /// A framed route transfer is active and forbids kind interleaving.
    #[error("a framed route transfer is active")]
    FramedTransferActive,
    /// No framed route transfer is waiting for its next frame.
    #[error("no framed route transfer is active")]
    NoFramedTransfer,
    /// The kind is unknown or the canonical policy forbids this sender role.
    #[error("canonical Relay message policy refused the kind")]
    MessageTypeNotPermitted,
    /// F6 and direct route payloads must be nonempty.
    #[error("empty Relay payload")]
    EmptyPayload,
    /// The direct payload or framed DSC1 is outside its frozen bound.
    #[error("Relay payload is outside the supported bound")]
    PayloadOutOfBounds,
    /// A Store-issued application identifier must be non-zero.
    #[error("invalid route application identifier")]
    InvalidApplicationId,
    /// An application identifier or exact DSC1 bytes were reused inconsistently.
    #[error("route application identity conflicts with durable state")]
    ApplicationConflict,
    /// Canonical envelope encoding or signing failed closed.
    #[error("Relay envelope preparation failed")]
    EnvelopePreparation,
    /// The Relay queue refused submission; the exact pending row is retained.
    #[error("Relay queue refused the pending envelope: {0}")]
    Queue(crate::BridgeRefusal),
    /// The returned ACK does not bind the exact pending key and digest.
    #[error("Relay ACK does not bind the pending envelope")]
    AckMismatch,
}

impl From<rusqlite::Error> for DurableRelaySenderErrorV1 {
    fn from(_: rusqlite::Error) -> Self {
        Self::StorageUnavailable
    }
}

/// Exact signed envelope currently retained in the durable outbox.
#[derive(Clone, Eq, PartialEq)]
pub struct DurableOutboundEnvelopeV1 {
    raw: Vec<u8>,
    application_id: Option<Digest32>,
    message_type: u16,
    sequence: u64,
    previous_digest: Digest32,
    digest: Digest32,
    key: IdempotencyKeyV1,
    frame_index: Option<u16>,
    frame_count: Option<u16>,
    frame_binding: Digest32,
}

impl core::fmt::Debug for DurableOutboundEnvelopeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DurableOutboundEnvelopeV1")
            .field("application_id", &self.application_id)
            .field("message_type", &self.message_type)
            .field("sequence", &self.sequence)
            .field("digest", &self.digest)
            .field("frame_index", &self.frame_index)
            .field("length", &self.raw.len())
            .finish_non_exhaustive()
    }
}

impl DurableOutboundEnvelopeV1 {
    /// Exact canonical signed bytes that were committed before submission.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Store-issued route application carried by this envelope, when present.
    pub const fn application_id(&self) -> Option<&Digest32> {
        self.application_id.as_ref()
    }

    /// Ratified Relay message type of the pending envelope.
    pub const fn message_type(&self) -> u16 {
        self.message_type
    }

    /// Shared addressed-flow sequence of the pending envelope.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Digest from which this pending envelope chains.
    pub const fn previous_digest(&self) -> &Digest32 {
        &self.previous_digest
    }

    /// Digest an ACK must return for these exact bytes.
    pub const fn envelope_digest(&self) -> &Digest32 {
        &self.digest
    }

    /// Exact Relay idempotency key of the pending envelope.
    pub const fn idempotency_key(&self) -> &IdempotencyKeyV1 {
        &self.key
    }

    /// Frame index when this is part of a V2 transfer.
    pub const fn frame_index(&self) -> Option<u16> {
        self.frame_index
    }

    /// Total V2 frame count when this is part of a framed transfer.
    pub const fn frame_count(&self) -> Option<u16> {
        self.frame_count
    }
}

/// Durable delivery state of one Store-issued DSC1 application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteApplicationStateV2 {
    /// At least one exact Relay envelope remains to be acknowledged.
    Pending,
    /// Every direct envelope or canonical frame ACK is durable.
    Acked,
}

/// Secret-free, fully audited progress of one Store-issued DSC1 application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteApplicationStatusV2 {
    application_id: Digest32,
    signed_dsc1_digest: Digest32,
    state: RouteApplicationStateV2,
    first_sequence: u64,
    final_sequence: u64,
    frame_count: u16,
    acknowledged_frames: u16,
    frame_binding: Digest32,
}

impl RouteApplicationStatusV2 {
    /// Stable application key minted by the Contracts Store.
    pub const fn application_id(&self) -> &Digest32 {
        &self.application_id
    }

    /// Digest of the byte-identical signed DSC1 object retained by the sender.
    pub const fn signed_dsc1_digest(&self) -> &Digest32 {
        &self.signed_dsc1_digest
    }

    /// Current durable application state.
    pub const fn state(&self) -> RouteApplicationStateV2 {
        self.state
    }

    /// First outer Relay sequence reserved for this application.
    pub const fn first_sequence(&self) -> u64 {
        self.first_sequence
    }

    /// Last outer Relay sequence reserved for this application.
    pub const fn final_sequence(&self) -> u64 {
        self.final_sequence
    }

    /// One for direct delivery, or the exact canonical V2 frame count.
    pub const fn frame_count(&self) -> u16 {
        self.frame_count
    }

    /// Number of outer Relay ACKs already committed for this application.
    pub const fn acknowledged_frames(&self) -> u16 {
        self.acknowledged_frames
    }

    /// Whether this application uses canonical Route Transport V2 framing.
    pub const fn is_framed(&self) -> bool {
        self.frame_count > 1
    }

    /// Frame-flow binding, or the zero digest for direct delivery.
    pub const fn frame_binding(&self) -> &Digest32 {
        &self.frame_binding
    }
}

/// Result of staging or reconciling one Store-issued DSC1 application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteApplicationDispositionV2 {
    /// The exact current outer envelope is durable, or the next frame was just
    /// prepared without changing the application's reserved sequence range.
    Pending(RouteApplicationStatusV2),
    /// The application was already fully ACKed; no outer sequence was reused.
    AlreadyAcked(RouteApplicationStatusV2),
}

impl RouteApplicationDispositionV2 {
    /// Audited application status associated with this disposition.
    pub const fn status(&self) -> RouteApplicationStatusV2 {
        match self {
            Self::Pending(status) | Self::AlreadyAcked(status) => *status,
        }
    }
}

/// Public progress of one active, contiguous Route Transport V2 transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableFrameTransferStatusV2 {
    message_digest: Digest32,
    binding_digest: Digest32,
    frame_count: u16,
    next_frame: u16,
    total_len: u32,
}

impl DurableFrameTransferStatusV2 {
    /// Digest of the full signed DSC1 object.
    pub const fn message_digest(&self) -> &Digest32 {
        &self.message_digest
    }

    /// Context/flow binding shared by the transfer's frames.
    pub const fn binding_digest(&self) -> &Digest32 {
        &self.binding_digest
    }

    /// Total number of Relay envelopes required by this transfer.
    pub const fn frame_count(&self) -> u16 {
        self.frame_count
    }

    /// Frame index that is pending or must be prepared next.
    pub const fn next_frame(&self) -> u16 {
        self.next_frame
    }

    /// Exact byte length of the complete signed DSC1 object.
    pub const fn total_len(&self) -> u32 {
        self.total_len
    }
}

/// Secret-free counters for one durable sender.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableRelaySenderStatsV1 {
    /// Number of envelopes whose exact ACK is durable.
    pub completed: u32,
    /// Whether exactly one envelope awaits submission/ACK.
    pub pending: bool,
    /// Whether a contiguous V2 frame transfer remains active.
    pub framed_transfer_active: bool,
}

/// Result returned only after ACK, checkpoint and history are one durable commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableSenderCommitV1 {
    ack: AckV1,
    checkpoint: RouteSenderCheckpointV1,
    message_type: u16,
    frame_index: Option<u16>,
    application_id: Option<Digest32>,
}

impl DurableSenderCommitV1 {
    /// Exact ACK persisted in the compact history.
    pub const fn ack(&self) -> AckV1 {
        self.ack
    }

    /// Advanced checkpoint made durable in the same transaction.
    pub const fn checkpoint(&self) -> RouteSenderCheckpointV1 {
        self.checkpoint
    }

    /// Ratified kind that advanced the shared flow.
    pub const fn message_type(&self) -> u16 {
        self.message_type
    }

    /// V2 frame index, or `None` for an ordinary F6/direct-route envelope.
    pub const fn frame_index(&self) -> Option<u16> {
        self.frame_index
    }

    /// Store-issued route application advanced by this ACK, when present.
    pub const fn application_id(&self) -> Option<&Digest32> {
        self.application_id.as_ref()
    }
}

#[derive(Clone)]
struct FrameTransferRowV2 {
    application_id: Option<Digest32>,
    base: RouteSenderCheckpointV1,
    signed_dsc1: Vec<u8>,
    expiry: TimelockSpec,
    message_digest: Digest32,
    binding_digest: Digest32,
    frame_count: u16,
    next_frame: u16,
}

/// Owner-only sender authority retaining public state and one in-memory signer.
pub struct DurableRelaySenderV1 {
    connection: Connection,
    root: PathBuf,
    config: DurableRelaySenderConfigV1,
    secret: Zeroizing<[u8; 32]>,
    secp: SecpContext,
    _database_authority: File,
    _sqlite_database_authority: File,
    _lock: File,
}

impl core::fmt::Debug for DurableRelaySenderV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DurableRelaySenderV1")
            .field("sender_store_id", &self.config.sender_store_id)
            .field("session_id", &self.config.wire.session_id)
            .field("sender_id", &self.config.sender_id)
            .field("recipient_id", &self.config.recipient_id)
            .field("root", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl DurableRelaySenderV1 {
    /// Creates a new owner-only sender store.  The signing scalar is checked
    /// against `config.signer_xonly` and remains only in zeroizing memory.
    pub fn create(
        root: &Path,
        config: DurableRelaySenderConfigV1,
        signing_secret: [u8; 32],
        secp_seed: [u8; 32],
    ) -> Result<Self, DurableRelaySenderErrorV1> {
        let (secret, secp) = validate_signing_authority(config, signing_secret, secp_seed)?;
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
            .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
        sync_directory(root)?;
        let sender = Self {
            connection,
            root: root.to_path_buf(),
            config,
            secret,
            secp,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        sender.validate_storage()?;
        sender.audit_state()?;
        Ok(sender)
    }

    /// Resumes only an authenticated, pristine prefix of explicit production
    /// creation.  A missing root, an empty owner-only root, a published lock,
    /// an empty SQLite file, or the exact initialized-but-unused authority may
    /// be completed.  Retained envelopes, applications, history, foreign
    /// schema/identity, extra files and transplanted hard links are refused.
    pub fn resume_create_production(
        root: &Path,
        config: DurableRelaySenderConfigV1,
        signing_secret: [u8; 32],
        secp_seed: [u8; 32],
    ) -> Result<Self, DurableRelaySenderErrorV1> {
        let (secret, secp) = validate_signing_authority(config, signing_secret, secp_seed)?;
        let lock = acquire_resume_lock(root)?;
        let database_path = root.join(DATABASE_FILE_NAME);
        let database_exists = database_path
            .try_exists()
            .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
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
            return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
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
                return Err(DurableRelaySenderErrorV1::CorruptState)
            }
        }
        let sender = Self {
            connection,
            root: root.to_path_buf(),
            config,
            secret,
            secp,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        sender.validate_storage()?;
        sender.audit_state()?;
        sender.require_pristine_creation_state()?;
        sender
            .connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
        sync_directory(root)?;
        Ok(sender)
    }

    /// Performs the non-mutating half of production resume planning.
    pub fn production_creation_state(
        root: &Path,
        config: DurableRelaySenderConfigV1,
    ) -> Result<DurableProductionCreationStateV1, DurableRelaySenderErrorV1> {
        inspect_creation_state(root, &config)
    }

    /// Reopens exactly one existing store.  It never creates or migrates
    /// missing state and audits schema, checkpoint, history, pending bytes and
    /// any active frame job before returning.
    pub fn open_existing(
        root: &Path,
        expected: DurableRelaySenderConfigV1,
        signing_secret: [u8; 32],
        secp_seed: [u8; 32],
    ) -> Result<Self, DurableRelaySenderErrorV1> {
        let (secret, secp) = validate_signing_authority(expected, signing_secret, secp_seed)?;
        validate_root(root)?;
        validate_root_entries(root)?;
        let lock = acquire_lock(root, false)?;
        let database_path = root.join(DATABASE_FILE_NAME);
        if !database_path
            .try_exists()
            .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?
        {
            return Err(DurableRelaySenderErrorV1::DatabaseMissing);
        }
        validate_owner_file(&database_path)?;
        let database_authority = open_database_authority(&database_path)?;
        for suffix in ["-wal", "-shm"] {
            let sidecar = root.join(format!("{DATABASE_FILE_NAME}{suffix}"));
            if sidecar
                .try_exists()
                .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?
            {
                validate_owner_file(&sidecar)?;
            }
        }
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
        preflight_existing_schema_version(&connection)?;
        let sender = Self {
            connection,
            root: root.to_path_buf(),
            config: expected,
            secret,
            secp,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        sender.validate_persistent_storage()?;
        sender.audit_state()?;
        let Self {
            connection,
            root,
            config,
            secret,
            secp,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        } = sender;
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
            secret,
            secp,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        rw_preflight.validate_persistent_storage()?;
        rw_preflight.audit_state()?;
        let Self {
            connection,
            root,
            config,
            secret,
            secp,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        } = rw_preflight;
        configure_connection(&connection)?;
        let sender = Self {
            connection,
            root,
            config,
            secret,
            secp,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        sender.validate_storage()?;
        sender.audit_state()?;
        Ok(sender)
    }

    /// Returns the fully validated secret-free checkpoint shared by F6 and
    /// route transport.
    pub fn checkpoint(&self) -> Result<RouteSenderCheckpointV1, DurableRelaySenderErrorV1> {
        self.require_meta().map(|meta| meta.checkpoint)
    }

    /// Returns the exact pending signed bytes, if any, after full validation.
    pub fn pending_envelope(
        &self,
    ) -> Result<Option<DurableOutboundEnvelopeV1>, DurableRelaySenderErrorV1> {
        let checkpoint = self.checkpoint()?;
        let frame = self.load_frame_transfer()?;
        self.load_pending(&checkpoint, frame.as_ref())
    }

    /// Returns bounded public progress for an active V2 transfer.
    pub fn frame_transfer_status(
        &self,
    ) -> Result<Option<DurableFrameTransferStatusV2>, DurableRelaySenderErrorV1> {
        Ok(self
            .load_frame_transfer()?
            .map(|row| DurableFrameTransferStatusV2 {
                message_digest: row.message_digest,
                binding_digest: row.binding_digest,
                frame_count: row.frame_count,
                next_frame: row.next_frame,
                total_len: u32::try_from(row.signed_dsc1.len())
                    .expect("framed DSC1 bound fits u32"),
            }))
    }

    /// Returns current public counters after cross-checking retained rows.
    pub fn stats(&self) -> Result<DurableRelaySenderStatsV1, DurableRelaySenderErrorV1> {
        let meta = self.require_meta()?;
        let pending: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM sender_pending", [], |row| row.get(0))?;
        let frame: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM frame_transfer", [], |row| row.get(0))?;
        if !(0..=1).contains(&pending) || !(0..=1).contains(&frame) {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        Ok(DurableRelaySenderStatsV1 {
            completed: meta.completed,
            pending: pending == 1,
            framed_transfer_active: frame == 1,
        })
    }

    /// Returns fully audited progress for a Store-issued DSC1 application.
    ///
    /// The signed DSC1 bytes remain private to the durable sender.  `None`
    /// means this application identifier has never been staged in this store.
    pub fn route_application_status(
        &self,
        application_id: Digest32,
    ) -> Result<Option<RouteApplicationStatusV2>, DurableRelaySenderErrorV1> {
        if application_id == ZERO_DIGEST {
            return Err(DurableRelaySenderErrorV1::InvalidApplicationId);
        }
        self.audit_state()?;
        Ok(
            load_route_application_connection(&self.connection, application_id)?
                .map(|application| application.status()),
        )
    }

    /// Stages or reconciles one exact Store-issued signed DSC1 application.
    ///
    /// Creation persists the application row and its first direct envelope or
    /// frame before returning.  Repeating the same identifier and bytes never
    /// allocates a new outer sequence: it returns the retained pending state,
    /// prepares only the next already-reserved frame, or reports
    /// [`RouteApplicationDispositionV2::AlreadyAcked`].  Reusing an identifier
    /// or exact DSC1 digest inconsistently fails closed.
    pub fn prepare_route_application(
        &mut self,
        application_id: Digest32,
        signed_dsc1: &[u8],
        expiry: TimelockSpec,
        aux_rand: [u8; 32],
    ) -> Result<RouteApplicationDispositionV2, DurableRelaySenderErrorV1> {
        if application_id == ZERO_DIGEST {
            return Err(DurableRelaySenderErrorV1::InvalidApplicationId);
        }
        if signed_dsc1.is_empty() || signed_dsc1.len() > MAX_FRAMED_DSC1_BYTES_V2 {
            return Err(DurableRelaySenderErrorV1::PayloadOutOfBounds);
        }
        let signed_dsc1_digest = full_message_digest_v2(signed_dsc1)
            .map_err(|_| DurableRelaySenderErrorV1::PayloadOutOfBounds)?;
        let aux_rand = Zeroizing::new(aux_rand);
        self.audit_state()?;

        if let Some(application) =
            load_route_application_connection(&self.connection, application_id)?
        {
            if application.signed_dsc1_digest != signed_dsc1_digest
                || application.signed_dsc1 != signed_dsc1
            {
                return Err(DurableRelaySenderErrorV1::ApplicationConflict);
            }
            return match application.state {
                RouteApplicationStateV2::Acked => Ok(RouteApplicationDispositionV2::AlreadyAcked(
                    application.status(),
                )),
                RouteApplicationStateV2::Pending => {
                    if self.row_exists("sender_pending")? {
                        Ok(RouteApplicationDispositionV2::Pending(application.status()))
                    } else if application.frame_count > 1 {
                        self.prepare_next_application_frame(&application, *aux_rand)?;
                        Ok(RouteApplicationDispositionV2::Pending(application.status()))
                    } else {
                        Err(DurableRelaySenderErrorV1::CorruptState)
                    }
                }
            };
        }

        if load_route_application_by_message_digest_connection(
            &self.connection,
            signed_dsc1_digest,
        )?
        .is_some()
        {
            return Err(DurableRelaySenderErrorV1::ApplicationConflict);
        }
        let meta = self.require_meta()?;
        if self.row_exists("sender_pending")? {
            return Err(DurableRelaySenderErrorV1::PendingEnvelopeExists);
        }
        if self.row_exists("frame_transfer")? {
            return Err(DurableRelaySenderErrorV1::FramedTransferActive);
        }

        let (application, pending, frame) =
            if signed_dsc1.len() <= MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES {
                let pending = self.build_envelope(
                    meta.checkpoint,
                    message_type::ROUTE_TRANSPORT,
                    signed_dsc1.to_vec(),
                    expiry,
                    *aux_rand,
                    Some(application_id),
                    None,
                    None,
                    ZERO_DIGEST,
                )?;
                (
                    RouteApplicationRowV2 {
                        application_id,
                        signed_dsc1_digest,
                        signed_dsc1: signed_dsc1.to_vec(),
                        state: RouteApplicationStateV2::Pending,
                        first_sequence: meta.checkpoint.next_sequence(),
                        final_sequence: meta.checkpoint.next_sequence(),
                        frame_count: 1,
                        acknowledged_frames: 0,
                        frame_binding: ZERO_DIGEST,
                        expiry,
                    },
                    pending,
                    None,
                )
            } else {
                let plan = RouteFramePlanV2::new(meta.checkpoint, signed_dsc1)
                    .map_err(|_| DurableRelaySenderErrorV1::PayloadOutOfBounds)?;
                let frame_count = u16::try_from(plan.frame_count())
                    .map_err(|_| DurableRelaySenderErrorV1::PayloadOutOfBounds)?;
                let final_sequence = meta
                    .checkpoint
                    .next_sequence()
                    .checked_add(u64::from(frame_count - 1))
                    .ok_or(DurableRelaySenderErrorV1::CapacityExceeded)?;
                let first_payload = plan
                    .frame_payload_for_checkpoint(meta.checkpoint, 0)
                    .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
                let pending = self.build_envelope(
                    meta.checkpoint,
                    message_type::ROUTE_TRANSPORT,
                    first_payload.to_vec(),
                    expiry,
                    *aux_rand,
                    Some(application_id),
                    Some(0),
                    Some(frame_count),
                    *plan.binding_digest(),
                )?;
                let frame = FrameTransferRowV2 {
                    application_id: Some(application_id),
                    base: plan.base_checkpoint(),
                    signed_dsc1: signed_dsc1.to_vec(),
                    expiry,
                    message_digest: *plan.message_digest(),
                    binding_digest: *plan.binding_digest(),
                    frame_count,
                    next_frame: 0,
                };
                (
                    RouteApplicationRowV2 {
                        application_id,
                        signed_dsc1_digest,
                        signed_dsc1: signed_dsc1.to_vec(),
                        state: RouteApplicationStateV2::Pending,
                        first_sequence: meta.checkpoint.next_sequence(),
                        final_sequence,
                        frame_count,
                        acknowledged_frames: 0,
                        frame_binding: *plan.binding_digest(),
                        expiry,
                    },
                    pending,
                    Some(frame),
                )
            };
        let needed = meta
            .completed
            .checked_add(u32::from(application.frame_count));
        if !matches!(needed, Some(value) if value <= self.config.max_envelopes) {
            return Err(DurableRelaySenderErrorV1::CapacityExceeded);
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_unchanged_meta_tx(&transaction, &self.config, &meta)?;
        ensure_absent_tx(&transaction, "sender_pending")?;
        ensure_absent_tx(&transaction, "frame_transfer")?;
        ensure_no_pending_route_application_tx(&transaction)?;
        if load_route_application_tx(&transaction, application_id)?.is_some()
            || load_route_application_by_message_digest_tx(&transaction, signed_dsc1_digest)?
                .is_some()
        {
            return Err(DurableRelaySenderErrorV1::ApplicationConflict);
        }
        insert_route_application_tx(&transaction, &application)?;
        if let Some(frame) = frame.as_ref() {
            insert_frame_transfer_tx(&transaction, frame)?;
        }
        insert_pending_tx(&transaction, &pending)?;
        transaction.commit()?;
        Ok(RouteApplicationDispositionV2::Pending(application.status()))
    }

    fn prepare_next_application_frame(
        &mut self,
        application: &RouteApplicationRowV2,
        aux_rand: [u8; 32],
    ) -> Result<(), DurableRelaySenderErrorV1> {
        if application.state != RouteApplicationStateV2::Pending
            || application.frame_count <= 1
            || application.acknowledged_frames >= application.frame_count
        {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        let meta = self.require_meta()?;
        let frame = self
            .load_frame_transfer()?
            .ok_or(DurableRelaySenderErrorV1::CorruptState)?;
        if frame.application_id != Some(application.application_id)
            || frame.next_frame != application.acknowledged_frames
        {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        let plan = validate_frame_transfer(&frame, &self.config, meta.checkpoint)?;
        let payload = plan
            .frame_payload_for_checkpoint(meta.checkpoint, usize::from(frame.next_frame))
            .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
        let pending = self.build_envelope(
            meta.checkpoint,
            message_type::ROUTE_TRANSPORT,
            payload.to_vec(),
            frame.expiry,
            aux_rand,
            Some(application.application_id),
            Some(frame.next_frame),
            Some(frame.frame_count),
            frame.binding_digest,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_unchanged_meta_tx(&transaction, &self.config, &meta)?;
        ensure_absent_tx(&transaction, "sender_pending")?;
        let retained_application =
            load_route_application_tx(&transaction, application.application_id)?
                .ok_or(DurableRelaySenderErrorV1::CorruptState)?;
        if &retained_application != application {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        let retained_frame =
            load_frame_transfer_tx(&transaction)?.ok_or(DurableRelaySenderErrorV1::CorruptState)?;
        if !same_frame_transfer(&retained_frame, &frame) {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        insert_pending_tx(&transaction, &pending)?;
        transaction.commit()?;
        Ok(())
    }

    /// Signs and durably prepares one canonical F6 or direct route envelope.
    /// A pending envelope or active framed transfer must be completed first.
    ///
    /// This compatibility surface remains during the atomic worker migration.
    /// Store-issued DSC1 applications use [`Self::prepare_route_application`];
    /// product wiring must not introduce another raw Route Transport caller.
    pub fn prepare_message(
        &mut self,
        kind: u16,
        payload: &[u8],
        expiry: TimelockSpec,
        aux_rand: [u8; 32],
    ) -> Result<DurableOutboundEnvelopeV1, DurableRelaySenderErrorV1> {
        self.validate_kind_and_payload(kind, payload)?;
        let meta = self.require_meta()?;
        if meta.completed >= self.config.max_envelopes {
            return Err(DurableRelaySenderErrorV1::CapacityExceeded);
        }
        if self.row_exists("sender_pending")? {
            return Err(DurableRelaySenderErrorV1::PendingEnvelopeExists);
        }
        if self.row_exists("frame_transfer")? {
            return Err(DurableRelaySenderErrorV1::FramedTransferActive);
        }
        let pending = self.build_envelope(
            meta.checkpoint,
            kind,
            payload.to_vec(),
            expiry,
            aux_rand,
            None,
            None,
            None,
            ZERO_DIGEST,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_unchanged_meta_tx(&transaction, &self.config, &meta)?;
        ensure_absent_tx(&transaction, "sender_pending")?;
        ensure_absent_tx(&transaction, "frame_transfer")?;
        insert_pending_tx(&transaction, &pending)?;
        transaction.commit()?;
        Ok(pending)
    }

    /// Starts one durable, contiguous Route Transport V2 transfer and commits
    /// its first exact frame envelope before returning.  Other kinds cannot be
    /// interleaved until every frame ACK is durable.
    ///
    /// This is retained only for the existing worker transition.  New
    /// Store-issued DSC1 traffic uses [`Self::prepare_route_application`].
    pub fn begin_framed_route(
        &mut self,
        signed_dsc1: &[u8],
        expiry: TimelockSpec,
        aux_rand: [u8; 32],
    ) -> Result<DurableOutboundEnvelopeV1, DurableRelaySenderErrorV1> {
        let meta = self.require_meta()?;
        if self.row_exists("sender_pending")? {
            return Err(DurableRelaySenderErrorV1::PendingEnvelopeExists);
        }
        if self.row_exists("frame_transfer")? {
            return Err(DurableRelaySenderErrorV1::FramedTransferActive);
        }
        let plan = RouteFramePlanV2::new(meta.checkpoint, signed_dsc1)
            .map_err(|_| DurableRelaySenderErrorV1::PayloadOutOfBounds)?;
        let frame_count = u16::try_from(plan.frame_count())
            .map_err(|_| DurableRelaySenderErrorV1::PayloadOutOfBounds)?;
        let needed = meta.completed.checked_add(u32::from(frame_count));
        if !matches!(needed, Some(value) if value <= self.config.max_envelopes) {
            return Err(DurableRelaySenderErrorV1::CapacityExceeded);
        }
        let first_payload = plan
            .frame_payload_for_checkpoint(meta.checkpoint, 0)
            .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
        let pending = self.build_envelope(
            meta.checkpoint,
            message_type::ROUTE_TRANSPORT,
            first_payload.to_vec(),
            expiry,
            aux_rand,
            None,
            Some(0),
            Some(frame_count),
            *plan.binding_digest(),
        )?;
        let frame = FrameTransferRowV2 {
            application_id: None,
            base: plan.base_checkpoint(),
            signed_dsc1: signed_dsc1.to_vec(),
            expiry,
            message_digest: *plan.message_digest(),
            binding_digest: *plan.binding_digest(),
            frame_count,
            next_frame: 0,
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_unchanged_meta_tx(&transaction, &self.config, &meta)?;
        ensure_absent_tx(&transaction, "sender_pending")?;
        ensure_absent_tx(&transaction, "frame_transfer")?;
        insert_frame_transfer_tx(&transaction, &frame)?;
        insert_pending_tx(&transaction, &pending)?;
        transaction.commit()?;
        Ok(pending)
    }

    /// Signs and commits the next frame of an already active transfer.  It is
    /// valid only after the previous frame ACK advanced the durable checkpoint.
    /// Application-managed transfers reject this compatibility method and are
    /// advanced by repeating [`Self::prepare_route_application`].
    pub fn prepare_next_frame(
        &mut self,
        aux_rand: [u8; 32],
    ) -> Result<DurableOutboundEnvelopeV1, DurableRelaySenderErrorV1> {
        let frame = self.load_frame_transfer()?;
        if frame
            .as_ref()
            .and_then(|frame| frame.application_id)
            .is_some()
        {
            return Err(DurableRelaySenderErrorV1::ApplicationConflict);
        }
        if self.row_exists("sender_pending")? {
            return Err(DurableRelaySenderErrorV1::PendingEnvelopeExists);
        }
        let meta = self.require_meta()?;
        let frame = frame.ok_or(DurableRelaySenderErrorV1::NoFramedTransfer)?;
        let plan = validate_frame_transfer(&frame, &self.config, meta.checkpoint)?;
        let index = usize::from(frame.next_frame);
        let payload = plan
            .frame_payload_for_checkpoint(meta.checkpoint, index)
            .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
        let pending = self.build_envelope(
            meta.checkpoint,
            message_type::ROUTE_TRANSPORT,
            payload.to_vec(),
            frame.expiry,
            aux_rand,
            frame.application_id,
            Some(frame.next_frame),
            Some(frame.frame_count),
            frame.binding_digest,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_unchanged_meta_tx(&transaction, &self.config, &meta)?;
        ensure_absent_tx(&transaction, "sender_pending")?;
        let retained =
            load_frame_transfer_tx(&transaction)?.ok_or(DurableRelaySenderErrorV1::CorruptState)?;
        if !same_frame_transfer(&retained, &frame) {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        insert_pending_tx(&transaction, &pending)?;
        transaction.commit()?;
        Ok(pending)
    }

    /// Submits the exact durable pending bytes.  Queue failure, ACK loss or an
    /// inconsistent ACK leaves the row unchanged.  A valid ACK atomically
    /// appends history, advances the shared checkpoint and clears the pending
    /// row; frame progress advances in that same commit.
    pub fn submit_pending<Q: RelayQueueV1>(
        &mut self,
        queue: &mut Q,
    ) -> Result<DurableSenderCommitV1, DurableRelaySenderErrorV1> {
        let meta = self.require_meta()?;
        let frame = self.load_frame_transfer()?;
        let pending = self
            .load_pending(&meta.checkpoint, frame.as_ref())?
            .ok_or(DurableRelaySenderErrorV1::NoPendingEnvelope)?;
        let ack = queue
            .queue_submit(pending.canonical_bytes())
            .map_err(DurableRelaySenderErrorV1::Queue)?;
        if ack.key != pending.key || ack.digest != pending.digest {
            return Err(DurableRelaySenderErrorV1::AckMismatch);
        }

        let next_sequence = meta
            .checkpoint
            .next_sequence()
            .checked_add(1)
            .ok_or(DurableRelaySenderErrorV1::CapacityExceeded)?;
        let next_checkpoint = RouteSenderCheckpointV1 {
            ctx: self.config.wire,
            sender_id: self.config.sender_id,
            recipient_id: self.config.recipient_id,
            role: self.config.sender_role,
            next_sequence,
            previous_digest: pending.digest,
        };
        let next_completed = meta
            .completed
            .checked_add(1)
            .ok_or(DurableRelaySenderErrorV1::CapacityExceeded)?;
        if next_completed > self.config.max_envelopes {
            return Err(DurableRelaySenderErrorV1::CapacityExceeded);
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_unchanged_meta_tx(&transaction, &self.config, &meta)?;
        let retained_pending = load_pending_tx(
            &transaction,
            &self.config,
            &self.secp,
            &meta.checkpoint,
            frame.as_ref(),
        )?
        .ok_or(DurableRelaySenderErrorV1::CorruptState)?;
        if retained_pending != pending {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        insert_history_tx(&transaction, next_completed, &pending, ack)?;
        if let Some(index) = pending.frame_index {
            let retained_frame = load_frame_transfer_tx(&transaction)?
                .ok_or(DurableRelaySenderErrorV1::CorruptState)?;
            if !matches!(
                frame.as_ref(),
                Some(expected) if same_frame_transfer(expected, &retained_frame)
            ) || retained_frame.next_frame != index
            {
                return Err(DurableRelaySenderErrorV1::CorruptState);
            }
            let advanced = index
                .checked_add(1)
                .ok_or(DurableRelaySenderErrorV1::CorruptState)?;
            if advanced == retained_frame.frame_count {
                transaction.execute("DELETE FROM frame_transfer WHERE singleton = 1", [])?;
            } else if advanced < retained_frame.frame_count {
                let mut next_frame = retained_frame;
                next_frame.next_frame = advanced;
                update_frame_transfer_tx(&transaction, &next_frame)?;
            } else {
                return Err(DurableRelaySenderErrorV1::CorruptState);
            }
        } else if frame.is_some() {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        if pending.application_id.is_some() {
            acknowledge_route_application_tx(&transaction, &pending)?;
        }
        transaction.execute("DELETE FROM sender_pending WHERE singleton = 1", [])?;
        update_meta_checkpoint_tx(&transaction, next_completed, next_checkpoint)?;
        transaction.commit()?;

        Ok(DurableSenderCommitV1 {
            ack,
            checkpoint: next_checkpoint,
            message_type: pending.message_type,
            frame_index: pending.frame_index,
            application_id: pending.application_id,
        })
    }

    fn validate_kind_and_payload(
        &self,
        kind: u16,
        payload: &[u8],
    ) -> Result<(), DurableRelaySenderErrorV1> {
        if !CanonicalMessageTypePolicyV1.permits(self.config.sender_role, kind) {
            return Err(DurableRelaySenderErrorV1::MessageTypeNotPermitted);
        }
        if payload.is_empty() {
            return Err(DurableRelaySenderErrorV1::EmptyPayload);
        }
        if payload.len() > MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES {
            return Err(DurableRelaySenderErrorV1::PayloadOutOfBounds);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn build_envelope(
        &self,
        checkpoint: RouteSenderCheckpointV1,
        kind: u16,
        payload: Vec<u8>,
        expiry: TimelockSpec,
        mut aux_rand: [u8; 32],
        application_id: Option<Digest32>,
        frame_index: Option<u16>,
        frame_count: Option<u16>,
        frame_binding: Digest32,
    ) -> Result<DurableOutboundEnvelopeV1, DurableRelaySenderErrorV1> {
        self.validate_kind_and_payload(kind, &payload)?;
        if checkpoint.next_sequence() == u64::MAX {
            return Err(DurableRelaySenderErrorV1::CapacityExceeded);
        }
        if frame_index.is_some() != frame_count.is_some()
            || frame_index.is_some() != (frame_binding != ZERO_DIGEST)
            || application_id.is_some_and(|id| id == ZERO_DIGEST)
            || (application_id.is_some() && kind != message_type::ROUTE_TRANSPORT)
            || (frame_index.is_some() && kind != message_type::ROUTE_TRANSPORT)
            || frame_index.zip(frame_count).is_some_and(|(index, count)| {
                !(2..=MAX_ROUTE_FRAME_COUNT_V2).contains(&count) || index >= count
            })
        {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        let mut envelope = RelayEnvelopeV1 {
            network_id: self.config.wire.network_id,
            message_type: kind,
            session_id: self.config.wire.session_id,
            route_id: self.config.wire.route_id,
            sender_id: self.config.sender_id,
            recipient_id: self.config.recipient_id,
            sender_role: self.config.sender_role,
            sequence: checkpoint.next_sequence(),
            previous_transcript_hash: *checkpoint.previous_digest(),
            payload,
            expiry,
            policy_version: self.config.wire.policy_version,
            roster_snapshot: self.config.wire.roster_snapshot,
            signature: [0; 64],
        };
        let digest = envelope
            .envelope_digest()
            .map_err(|_| DurableRelaySenderErrorV1::EnvelopePreparation)?;
        let zeroizing_aux = Zeroizing::new(aux_rand);
        aux_rand.zeroize();
        let (signature, xonly) = self
            .secp
            .sign_bip340(&self.secret, &digest, &zeroizing_aux)
            .map_err(|_| DurableRelaySenderErrorV1::EnvelopePreparation)?;
        if xonly != self.config.signer_xonly {
            return Err(DurableRelaySenderErrorV1::WrongSigningAuthority);
        }
        envelope.signature = signature;
        let raw = envelope
            .canonical_bytes()
            .map_err(|_| DurableRelaySenderErrorV1::EnvelopePreparation)?;
        Ok(DurableOutboundEnvelopeV1 {
            raw,
            application_id,
            message_type: kind,
            sequence: checkpoint.next_sequence(),
            previous_digest: *checkpoint.previous_digest(),
            digest,
            key: IdempotencyKeyV1::of(&envelope),
            frame_index,
            frame_count,
            frame_binding,
        })
    }

    fn row_exists(&self, table: &str) -> Result<bool, DurableRelaySenderErrorV1> {
        let query = match table {
            "sender_pending" => "SELECT EXISTS(SELECT 1 FROM sender_pending)",
            "frame_transfer" => "SELECT EXISTS(SELECT 1 FROM frame_transfer)",
            _ => return Err(DurableRelaySenderErrorV1::CorruptState),
        };
        let exists: i64 = self.connection.query_row(query, [], |row| row.get(0))?;
        match exists {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DurableRelaySenderErrorV1::CorruptState),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct MetaRowV1 {
    checkpoint: RouteSenderCheckpointV1,
    completed: u32,
}

#[derive(Clone, Copy)]
struct HistoryRowV1 {
    ordinal: u32,
    application_id: Option<Digest32>,
    sequence: u64,
    previous_digest: Digest32,
    message_type: u16,
    envelope_digest: Digest32,
    ack: AckV1,
    frame_index: Option<u16>,
    frame_count: Option<u16>,
    frame_binding: Digest32,
}

#[derive(Clone, Eq, PartialEq)]
struct RouteApplicationRowV2 {
    application_id: Digest32,
    signed_dsc1_digest: Digest32,
    signed_dsc1: Vec<u8>,
    state: RouteApplicationStateV2,
    first_sequence: u64,
    final_sequence: u64,
    frame_count: u16,
    acknowledged_frames: u16,
    frame_binding: Digest32,
    expiry: TimelockSpec,
}

impl RouteApplicationRowV2 {
    fn status(&self) -> RouteApplicationStatusV2 {
        RouteApplicationStatusV2 {
            application_id: self.application_id,
            signed_dsc1_digest: self.signed_dsc1_digest,
            state: self.state,
            first_sequence: self.first_sequence,
            final_sequence: self.final_sequence,
            frame_count: self.frame_count,
            acknowledged_frames: self.acknowledged_frames,
            frame_binding: self.frame_binding,
        }
    }
}

impl DurableRelaySenderV1 {
    fn validate_storage(&self) -> Result<(), DurableRelaySenderErrorV1> {
        self.validate_persistent_storage()?;
        validate_connection_settings(&self.connection)
    }

    fn validate_persistent_storage(&self) -> Result<(), DurableRelaySenderErrorV1> {
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
                .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?
            {
                validate_owner_file(&path)?;
            }
        }
        validate_database_path(&self.connection, &self.root.join(DATABASE_FILE_NAME))?;
        let app_id: i64 = self
            .connection
            .pragma_query_value(None, "application_id", |row| row.get(0))?;
        let version: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if app_id != APPLICATION_ID || version != SCHEMA_VERSION {
            return Err(DurableRelaySenderErrorV1::UnsupportedFormat);
        }
        let quick: String = self
            .connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
        let foreign: Vec<String> = {
            let mut statement = self.connection.prepare("PRAGMA foreign_key_check")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        if quick != "ok" || !foreign.is_empty() {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        if schema_objects(&self.connection)? != reference_schema_objects()? {
            return Err(DurableRelaySenderErrorV1::UnsupportedFormat);
        }
        Ok(())
    }

    fn require_meta(&self) -> Result<MetaRowV1, DurableRelaySenderErrorV1> {
        require_meta_connection(&self.connection, &self.config)
    }

    fn load_frame_transfer(&self) -> Result<Option<FrameTransferRowV2>, DurableRelaySenderErrorV1> {
        load_frame_transfer_connection(&self.connection)
    }

    fn load_pending(
        &self,
        checkpoint: &RouteSenderCheckpointV1,
        frame: Option<&FrameTransferRowV2>,
    ) -> Result<Option<DurableOutboundEnvelopeV1>, DurableRelaySenderErrorV1> {
        load_pending_connection(
            &self.connection,
            &self.config,
            &self.secp,
            checkpoint,
            frame,
        )
    }

    fn audit_state(&self) -> Result<(), DurableRelaySenderErrorV1> {
        let meta = self.require_meta()?;
        let history = load_and_validate_history(&self.connection, &self.config)?;
        if usize::try_from(meta.completed).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?
            != history.len()
            || meta.checkpoint.next_sequence() != u64::from(meta.completed)
        {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        let expected_previous = history
            .last()
            .map_or(ZERO_DIGEST, |row| row.envelope_digest);
        if *meta.checkpoint.previous_digest() != expected_previous {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        let frame = self.load_frame_transfer()?;
        if let Some(frame) = frame.as_ref() {
            validate_frame_transfer(frame, &self.config, meta.checkpoint)?;
        }
        audit_frame_history_groups(&history, frame.as_ref())?;
        let pending = self.load_pending(&meta.checkpoint, frame.as_ref())?;
        let applications =
            load_all_route_applications(&self.connection, self.config.max_envelopes)?;
        audit_route_applications(
            &applications,
            &history,
            frame.as_ref(),
            pending.as_ref(),
            meta.checkpoint,
        )?;
        Ok(())
    }

    fn require_pristine_creation_state(&self) -> Result<(), DurableRelaySenderErrorV1> {
        let meta = self.require_meta()?;
        let stats = self.stats()?;
        let applications: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM route_application", [], |row| {
                    row.get(0)
                })?;
        if meta.completed != 0
            || meta.checkpoint != self.config.initial_checkpoint()
            || stats.pending
            || stats.framed_transfer_active
            || applications != 0
        {
            return Err(DurableRelaySenderErrorV1::UnsupportedFormat);
        }
        Ok(())
    }
}

fn validate_signing_authority(
    config: DurableRelaySenderConfigV1,
    mut signing_secret: [u8; 32],
    secp_seed: [u8; 32],
) -> Result<(Zeroizing<[u8; 32]>, SecpContext), DurableRelaySenderErrorV1> {
    let secret = Zeroizing::new(signing_secret);
    signing_secret.zeroize();
    let secp = SecpContext::new(&secp_seed);
    let (_, xonly) = secp
        .sign_bip340(&secret, &ZERO_DIGEST, &ZERO_DIGEST)
        .map_err(|_| DurableRelaySenderErrorV1::WrongSigningAuthority)?;
    if xonly != config.signer_xonly {
        return Err(DurableRelaySenderErrorV1::WrongSigningAuthority);
    }
    Ok((secret, secp))
}

fn insert_meta(
    connection: &Connection,
    config: DurableRelaySenderConfigV1,
    checkpoint: RouteSenderCheckpointV1,
) -> Result<(), DurableRelaySenderErrorV1> {
    let checkpoint = checkpoint
        .canonical_bytes()
        .map_err(|_| DurableRelaySenderErrorV1::InvalidConfiguration)?;
    connection.execute(
        "INSERT INTO sender_meta
         (singleton, schema_version, sender_store_id, network_id, session_id,
          route_id, roster_snapshot, policy_version, sender_id, recipient_id,
          sender_role, signer_xonly, max_envelopes, completed_count,
          checkpoint_bytes)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 0, ?13)",
        params![
            SCHEMA_VERSION,
            config.sender_store_id.as_slice(),
            config.wire.network_id.as_slice(),
            config.wire.session_id.as_slice(),
            config.wire.route_id.as_slice(),
            config.wire.roster_snapshot.as_slice(),
            i64::from(config.wire.policy_version),
            config.sender_id.0.as_slice(),
            config.recipient_id.0.as_slice(),
            i64::from(sender_role_byte(config.sender_role)),
            config.signer_xonly.as_slice(),
            i64::from(config.max_envelopes),
            checkpoint.as_slice(),
        ],
    )?;
    Ok(())
}

fn initialize_pristine_store(
    connection: &Connection,
    config: DurableRelaySenderConfigV1,
) -> Result<(), DurableRelaySenderErrorV1> {
    connection.execute_batch("BEGIN IMMEDIATE;")?;
    let initialized = (|| {
        connection.execute_batch(SCHEMA_SQL)?;
        connection.pragma_update(None, "application_id", APPLICATION_ID)?;
        connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        insert_meta(connection, config, config.initial_checkpoint())
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

fn require_meta_connection(
    connection: &Connection,
    expected: &DurableRelaySenderConfigV1,
) -> Result<MetaRowV1, DurableRelaySenderErrorV1> {
    let retained = connection
        .query_row(
            "SELECT schema_version, sender_store_id, network_id, session_id,
                    route_id, roster_snapshot, policy_version, sender_id,
                    recipient_id, sender_role, signer_xonly, max_envelopes,
                    completed_count, checkpoint_bytes
             FROM sender_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                ))
            },
        )
        .optional()?;
    let Some((
        schema,
        store_id,
        network,
        session,
        route,
        roster,
        policy,
        sender,
        recipient,
        role,
        signer,
        maximum,
        completed,
        checkpoint_bytes,
    )) = retained
    else {
        return Err(DurableRelaySenderErrorV1::WrongIdentity);
    };
    if schema != SCHEMA_VERSION
        || blob32(store_id)? != expected.sender_store_id
        || blob32(network)? != expected.wire.network_id
        || blob32(session)? != expected.wire.session_id
        || blob32(route)? != expected.wire.route_id
        || blob32(roster)? != expected.wire.roster_snapshot
        || policy != i64::from(expected.wire.policy_version)
        || blob32(sender)? != expected.sender_id.0
        || blob32(recipient)? != expected.recipient_id.0
        || role != i64::from(sender_role_byte(expected.sender_role))
        || blob32(signer)? != expected.signer_xonly
        || maximum != i64::from(expected.max_envelopes)
        || completed < 0
        || completed > maximum
    {
        return Err(DurableRelaySenderErrorV1::WrongIdentity);
    }
    let checkpoint = RouteSenderCheckpointV1::from_bytes(&checkpoint_bytes)
        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    if checkpoint.wire_context() != expected.wire
        || checkpoint.sender_id() != expected.sender_id
        || checkpoint.recipient_id() != expected.recipient_id
        || checkpoint.sender_role() != expected.sender_role
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(MetaRowV1 {
        checkpoint,
        completed: u32::try_from(completed).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?,
    })
}

fn require_unchanged_meta_tx(
    transaction: &Transaction<'_>,
    config: &DurableRelaySenderConfigV1,
    expected: &MetaRowV1,
) -> Result<(), DurableRelaySenderErrorV1> {
    let retained = require_meta_connection(transaction, config)?;
    if &retained != expected {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(())
}

fn update_meta_checkpoint_tx(
    transaction: &Transaction<'_>,
    completed: u32,
    checkpoint: RouteSenderCheckpointV1,
) -> Result<(), DurableRelaySenderErrorV1> {
    let bytes = checkpoint
        .canonical_bytes()
        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    let changed = transaction.execute(
        "UPDATE sender_meta SET completed_count = ?1, checkpoint_bytes = ?2
         WHERE singleton = 1",
        params![i64::from(completed), bytes.as_slice()],
    )?;
    if changed != 1 {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(())
}

fn insert_pending_tx(
    transaction: &Transaction<'_>,
    pending: &DurableOutboundEnvelopeV1,
) -> Result<(), DurableRelaySenderErrorV1> {
    let frame_index = pending.frame_index.map_or(-1, i64::from);
    let frame_count = pending.frame_count.map_or(0, i64::from);
    let row_digest = pending_row_digest(pending)?;
    let changed = transaction.execute(
        "INSERT INTO sender_pending
         (singleton, application_id, message_type, sequence_be, previous_digest,
          envelope_digest, canonical_bytes, frame_index, frame_count,
          frame_binding, row_digest)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            pending.application_id.as_ref().map(|id| id.as_slice()),
            i64::from(pending.message_type),
            pending.sequence.to_be_bytes().as_slice(),
            pending.previous_digest.as_slice(),
            pending.digest.as_slice(),
            pending.raw.as_slice(),
            frame_index,
            frame_count,
            pending.frame_binding.as_slice(),
            row_digest.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(())
}

fn load_pending_connection(
    connection: &Connection,
    config: &DurableRelaySenderConfigV1,
    secp: &SecpContext,
    checkpoint: &RouteSenderCheckpointV1,
    frame: Option<&FrameTransferRowV2>,
) -> Result<Option<DurableOutboundEnvelopeV1>, DurableRelaySenderErrorV1> {
    let retained = connection
        .query_row(
            "SELECT application_id, message_type, sequence_be, previous_digest,
                    envelope_digest, canonical_bytes, frame_index, frame_count,
                    frame_binding, row_digest
             FROM sender_pending WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((
        application_id,
        kind,
        sequence,
        previous,
        digest,
        raw,
        frame_index,
        frame_count,
        frame_binding,
        row_digest,
    )) = retained
    else {
        return Ok(None);
    };
    let kind = u16::try_from(kind).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    let application_id = optional_blob32(application_id)?;
    let sequence = blob_u64(sequence)?;
    let previous_digest = blob32(previous)?;
    let envelope_digest = blob32(digest)?;
    let frame_binding = blob32(frame_binding)?;
    let stored_row_digest = blob32(row_digest)?;
    let frame_index = optional_frame_index(frame_index)?;
    let frame_count = optional_frame_count(frame_count)?;
    if application_id.is_some_and(|id| id == ZERO_DIGEST)
        || frame_index.is_some() != frame_count.is_some()
        || frame_index.is_some() != (frame_binding != ZERO_DIGEST)
        || (application_id.is_some() && kind != message_type::ROUTE_TRANSPORT)
        || frame_index.zip(frame_count).is_some_and(|(index, count)| {
            !(2..=MAX_ROUTE_FRAME_COUNT_V2).contains(&count) || index >= count
        })
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    let envelope =
        RelayEnvelopeV1::decode(&raw).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    let canonical = envelope
        .canonical_bytes()
        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    let computed_digest = envelope
        .envelope_digest()
        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    if canonical != raw
        || computed_digest != envelope_digest
        || envelope.network_id != config.wire.network_id
        || envelope.session_id != config.wire.session_id
        || envelope.route_id != config.wire.route_id
        || envelope.roster_snapshot != config.wire.roster_snapshot
        || envelope.policy_version != config.wire.policy_version
        || envelope.sender_id != config.sender_id
        || envelope.recipient_id != config.recipient_id
        || envelope.sender_role != config.sender_role
        || envelope.message_type != kind
        || envelope.sequence != sequence
        || envelope.previous_transcript_hash != previous_digest
        || sequence != checkpoint.next_sequence()
        || previous_digest != *checkpoint.previous_digest()
        || envelope.payload.is_empty()
        || envelope.payload.len() > MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES
        || !CanonicalMessageTypePolicyV1.permits(config.sender_role, kind)
        || secp
            .verify_bip340(&config.signer_xonly, &computed_digest, &envelope.signature)
            .is_err()
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    let pending = DurableOutboundEnvelopeV1 {
        raw,
        application_id,
        message_type: kind,
        sequence,
        previous_digest,
        digest: envelope_digest,
        key: IdempotencyKeyV1::of(&envelope),
        frame_index,
        frame_count,
        frame_binding,
    };
    if pending_row_digest(&pending)? != stored_row_digest {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    match (frame, frame_index) {
        (None, None) => {}
        (Some(job), Some(index)) => {
            if application_id != job.application_id
                || index != job.next_frame
                || frame_count != Some(job.frame_count)
                || frame_binding != job.binding_digest
                || kind != message_type::ROUTE_TRANSPORT
                || envelope.expiry != job.expiry
            {
                return Err(DurableRelaySenderErrorV1::CorruptState);
            }
            let plan = validate_frame_transfer(job, config, *checkpoint)?;
            let expected_payload = plan
                .frame_payload_for_checkpoint(*checkpoint, usize::from(index))
                .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
            if envelope.payload != expected_payload {
                return Err(DurableRelaySenderErrorV1::CorruptState);
            }
        }
        _ => return Err(DurableRelaySenderErrorV1::CorruptState),
    }
    Ok(Some(pending))
}

fn load_pending_tx(
    transaction: &Transaction<'_>,
    config: &DurableRelaySenderConfigV1,
    secp: &SecpContext,
    checkpoint: &RouteSenderCheckpointV1,
    frame: Option<&FrameTransferRowV2>,
) -> Result<Option<DurableOutboundEnvelopeV1>, DurableRelaySenderErrorV1> {
    load_pending_connection(transaction, config, secp, checkpoint, frame)
}

fn pending_row_digest(
    pending: &DurableOutboundEnvelopeV1,
) -> Result<Digest32, DurableRelaySenderErrorV1> {
    let frame_index = pending.frame_index.unwrap_or(u16::MAX).to_be_bytes();
    let frame_count = pending.frame_count.unwrap_or(0).to_be_bytes();
    let raw_len = u32::try_from(pending.raw.len())
        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?
        .to_be_bytes();
    digest_parts(
        PENDING_DOMAIN,
        &[
            &[u8::from(pending.application_id.is_some())],
            pending
                .application_id
                .as_ref()
                .unwrap_or(&ZERO_DIGEST)
                .as_slice(),
            &pending.message_type.to_be_bytes(),
            &pending.sequence.to_be_bytes(),
            pending.previous_digest.as_slice(),
            pending.digest.as_slice(),
            &raw_len,
            pending.raw.as_slice(),
            &frame_index,
            &frame_count,
            pending.frame_binding.as_slice(),
        ],
    )
}

fn insert_history_tx(
    transaction: &Transaction<'_>,
    ordinal: u32,
    pending: &DurableOutboundEnvelopeV1,
    ack: AckV1,
) -> Result<(), DurableRelaySenderErrorV1> {
    let frame_index = pending.frame_index.map_or(-1, i64::from);
    let frame_count = pending.frame_count.map_or(0, i64::from);
    let row = HistoryRowV1 {
        ordinal,
        application_id: pending.application_id,
        sequence: pending.sequence,
        previous_digest: pending.previous_digest,
        message_type: pending.message_type,
        envelope_digest: pending.digest,
        ack,
        frame_index: pending.frame_index,
        frame_count: pending.frame_count,
        frame_binding: pending.frame_binding,
    };
    let row_digest = history_row_digest(&row)?;
    let changed = transaction.execute(
        "INSERT INTO sender_history
         (ordinal, application_id, sequence_be, previous_digest, message_type,
          envelope_digest, ack_bytes, frame_index, frame_count, frame_binding,
          row_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            i64::from(ordinal),
            pending.application_id.as_ref().map(|id| id.as_slice()),
            pending.sequence.to_be_bytes().as_slice(),
            pending.previous_digest.as_slice(),
            i64::from(pending.message_type),
            pending.digest.as_slice(),
            ack.canonical_bytes().as_slice(),
            frame_index,
            frame_count,
            pending.frame_binding.as_slice(),
            row_digest.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(())
}

fn load_and_validate_history(
    connection: &Connection,
    config: &DurableRelaySenderConfigV1,
) -> Result<Vec<HistoryRowV1>, DurableRelaySenderErrorV1> {
    let (count, maximum): (i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(MAX(ordinal), 0) FROM sender_history",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if count < 0
        || count > i64::from(config.max_envelopes)
        || maximum != count
        || count > i64::from(MAX_COMPLETED_ENVELOPES)
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    let mut statement = connection.prepare(
        "SELECT ordinal, application_id, sequence_be, previous_digest,
                message_type, envelope_digest, ack_bytes, frame_index,
                frame_count, frame_binding, row_digest
         FROM sender_history ORDER BY ordinal ASC",
    )?;
    let raw_rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Option<Vec<u8>>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, Vec<u8>>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, i64>(8)?,
            row.get::<_, Vec<u8>>(9)?,
            row.get::<_, Vec<u8>>(10)?,
        ))
    })?;
    let mut history = Vec::with_capacity(
        usize::try_from(count).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?,
    );
    let mut expected_previous = ZERO_DIGEST;
    for (index, raw) in raw_rows.enumerate() {
        let (
            ordinal,
            application_id,
            sequence,
            previous,
            kind,
            digest,
            ack_bytes,
            frame_index,
            frame_count,
            frame_binding,
            stored_digest,
        ) = raw?;
        let expected_ordinal =
            u32::try_from(index + 1).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
        let application_id = optional_blob32(application_id)?;
        let sequence = blob_u64(sequence)?;
        let previous_digest = blob32(previous)?;
        let message_type =
            u16::try_from(kind).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
        let envelope_digest = blob32(digest)?;
        let ack = AckV1::decode(&ack_bytes).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
        if ack.canonical_bytes().as_slice() != ack_bytes {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        let frame_index = optional_frame_index(frame_index)?;
        let frame_count = optional_frame_count(frame_count)?;
        let frame_binding = blob32(frame_binding)?;
        let row = HistoryRowV1 {
            ordinal: u32::try_from(ordinal).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?,
            application_id,
            sequence,
            previous_digest,
            message_type,
            envelope_digest,
            ack,
            frame_index,
            frame_count,
            frame_binding,
        };
        if row.ordinal != expected_ordinal
            || row.sequence != u64::from(expected_ordinal - 1)
            || row.previous_digest != expected_previous
            || !CanonicalMessageTypePolicyV1.permits(config.sender_role, row.message_type)
            || row.ack.key.session_id != config.wire.session_id
            || row.ack.key.sender_id != config.sender_id
            || row.ack.key.recipient_id != config.recipient_id
            || row.ack.key.sequence != row.sequence
            || row.ack.digest != row.envelope_digest
            || row.application_id.is_some_and(|id| id == ZERO_DIGEST)
            || row.frame_index.is_some() != row.frame_count.is_some()
            || row.frame_index.is_some() != (row.frame_binding != ZERO_DIGEST)
            || row
                .frame_index
                .zip(row.frame_count)
                .is_some_and(|(position, total)| {
                    !(2..=MAX_ROUTE_FRAME_COUNT_V2).contains(&total) || position >= total
                })
            || (row.frame_index.is_some() && row.message_type != message_type::ROUTE_TRANSPORT)
            || history_row_digest(&row)? != blob32(stored_digest)?
        {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        expected_previous = row.envelope_digest;
        history.push(row);
    }
    if i64::try_from(history.len()).map_err(|_| DurableRelaySenderErrorV1::CorruptState)? != count {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(history)
}

fn history_row_digest(row: &HistoryRowV1) -> Result<Digest32, DurableRelaySenderErrorV1> {
    let frame_index = row.frame_index.unwrap_or(u16::MAX).to_be_bytes();
    let frame_count = row.frame_count.unwrap_or(0).to_be_bytes();
    let ack = row.ack.canonical_bytes();
    digest_parts(
        HISTORY_DOMAIN,
        &[
            &row.ordinal.to_be_bytes(),
            &[u8::from(row.application_id.is_some())],
            row.application_id
                .as_ref()
                .unwrap_or(&ZERO_DIGEST)
                .as_slice(),
            &row.sequence.to_be_bytes(),
            row.previous_digest.as_slice(),
            &row.message_type.to_be_bytes(),
            row.envelope_digest.as_slice(),
            ack.as_slice(),
            &frame_index,
            &frame_count,
            row.frame_binding.as_slice(),
        ],
    )
}

fn insert_route_application_tx(
    transaction: &Transaction<'_>,
    application: &RouteApplicationRowV2,
) -> Result<(), DurableRelaySenderErrorV1> {
    validate_route_application_row(application)?;
    let (delivery_kind, delivery_status) = route_application_discriminants(application);
    let (expiry_domain, expiry_value) = timelock_parts(application.expiry);
    let row_digest = route_application_row_digest(application)?;
    let changed = transaction.execute(
        "INSERT INTO route_application
         (application_id, signed_dsc1_digest, signed_dsc1, delivery_kind,
          delivery_status, first_sequence_be, final_sequence_be, frame_count,
          acknowledged_frames, frame_binding, expiry_domain, expiry_value_be,
          row_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            application.application_id.as_slice(),
            application.signed_dsc1_digest.as_slice(),
            application.signed_dsc1.as_slice(),
            delivery_kind,
            delivery_status,
            application.first_sequence.to_be_bytes().as_slice(),
            application.final_sequence.to_be_bytes().as_slice(),
            i64::from(application.frame_count),
            i64::from(application.acknowledged_frames),
            application.frame_binding.as_slice(),
            i64::from(expiry_domain),
            expiry_value.to_be_bytes().as_slice(),
            row_digest.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(())
}

fn load_route_application_connection(
    connection: &Connection,
    application_id: Digest32,
) -> Result<Option<RouteApplicationRowV2>, DurableRelaySenderErrorV1> {
    let retained = connection
        .query_row(
            "SELECT application_id, signed_dsc1_digest, signed_dsc1,
                    delivery_kind, delivery_status, first_sequence_be,
                    final_sequence_be, frame_count, acknowledged_frames,
                    frame_binding, expiry_domain, expiry_value_be, row_digest
             FROM route_application WHERE application_id = ?1",
            [application_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                ))
            },
        )
        .optional()?;
    let Some((
        retained_id,
        signed_dsc1_digest,
        signed_dsc1,
        delivery_kind,
        delivery_status,
        first_sequence,
        final_sequence,
        frame_count,
        acknowledged_frames,
        frame_binding,
        expiry_domain,
        expiry_value,
        stored_row_digest,
    )) = retained
    else {
        return Ok(None);
    };
    let retained_id = blob32(retained_id)?;
    if retained_id != application_id {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    let state = match delivery_status {
        ROUTE_APPLICATION_PENDING => RouteApplicationStateV2::Pending,
        ROUTE_APPLICATION_ACKED => RouteApplicationStateV2::Acked,
        _ => return Err(DurableRelaySenderErrorV1::CorruptState),
    };
    let frame_count =
        u16::try_from(frame_count).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    let application = RouteApplicationRowV2 {
        application_id: retained_id,
        signed_dsc1_digest: blob32(signed_dsc1_digest)?,
        signed_dsc1,
        state,
        first_sequence: blob_u64(first_sequence)?,
        final_sequence: blob_u64(final_sequence)?,
        frame_count,
        acknowledged_frames: u16::try_from(acknowledged_frames)
            .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?,
        frame_binding: blob32(frame_binding)?,
        expiry: timelock_from_parts(
            u8::try_from(expiry_domain).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?,
            blob_u64(expiry_value)?,
        )?,
    };
    let expected_kind = if frame_count == 1 {
        ROUTE_APPLICATION_DIRECT
    } else {
        ROUTE_APPLICATION_FRAMED
    };
    if delivery_kind != expected_kind
        || route_application_row_digest(&application)? != blob32(stored_row_digest)?
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    validate_route_application_row(&application)?;
    Ok(Some(application))
}

fn load_route_application_tx(
    transaction: &Transaction<'_>,
    application_id: Digest32,
) -> Result<Option<RouteApplicationRowV2>, DurableRelaySenderErrorV1> {
    load_route_application_connection(transaction, application_id)
}

fn load_route_application_by_message_digest_connection(
    connection: &Connection,
    signed_dsc1_digest: Digest32,
) -> Result<Option<RouteApplicationRowV2>, DurableRelaySenderErrorV1> {
    let application_id = connection
        .query_row(
            "SELECT application_id FROM route_application
             WHERE signed_dsc1_digest = ?1",
            [signed_dsc1_digest.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(application_id) = application_id else {
        return Ok(None);
    };
    load_route_application_connection(connection, blob32(application_id)?)
}

fn load_route_application_by_message_digest_tx(
    transaction: &Transaction<'_>,
    signed_dsc1_digest: Digest32,
) -> Result<Option<RouteApplicationRowV2>, DurableRelaySenderErrorV1> {
    load_route_application_by_message_digest_connection(transaction, signed_dsc1_digest)
}

fn load_all_route_applications(
    connection: &Connection,
    maximum: u32,
) -> Result<Vec<RouteApplicationRowV2>, DurableRelaySenderErrorV1> {
    let count: i64 = connection.query_row("SELECT COUNT(*) FROM route_application", [], |row| {
        row.get(0)
    })?;
    if count < 0 || count > i64::from(maximum) {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    let mut statement = connection
        .prepare("SELECT application_id FROM route_application ORDER BY application_id ASC")?;
    let ids = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut applications = Vec::with_capacity(
        usize::try_from(count).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?,
    );
    for id in ids {
        let id = blob32(id?)?;
        applications.push(
            load_route_application_connection(connection, id)?
                .ok_or(DurableRelaySenderErrorV1::CorruptState)?,
        );
    }
    if i64::try_from(applications.len()).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?
        != count
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(applications)
}

fn ensure_no_pending_route_application_tx(
    transaction: &Transaction<'_>,
) -> Result<(), DurableRelaySenderErrorV1> {
    let count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM route_application WHERE delivery_status = 1",
        [],
        |row| row.get(0),
    )?;
    if count != 0 {
        return Err(DurableRelaySenderErrorV1::PendingEnvelopeExists);
    }
    Ok(())
}

fn acknowledge_route_application_tx(
    transaction: &Transaction<'_>,
    pending: &DurableOutboundEnvelopeV1,
) -> Result<(), DurableRelaySenderErrorV1> {
    let application_id = pending
        .application_id
        .ok_or(DurableRelaySenderErrorV1::CorruptState)?;
    let application = load_route_application_tx(transaction, application_id)?
        .ok_or(DurableRelaySenderErrorV1::CorruptState)?;
    if application.state != RouteApplicationStateV2::Pending
        || pending.message_type != message_type::ROUTE_TRANSPORT
        || pending.sequence
            != application
                .first_sequence
                .checked_add(u64::from(application.acknowledged_frames))
                .ok_or(DurableRelaySenderErrorV1::CorruptState)?
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    let envelope = RelayEnvelopeV1::decode(&pending.raw)
        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    if application.frame_count == 1 {
        if pending.frame_index.is_some()
            || pending.frame_count.is_some()
            || application.acknowledged_frames != 0
            || envelope.payload != application.signed_dsc1
        {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
    } else if pending.frame_index != Some(application.acknowledged_frames)
        || pending.frame_count != Some(application.frame_count)
        || pending.frame_binding != application.frame_binding
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    let mut advanced = application.clone();
    advanced.acknowledged_frames = advanced
        .acknowledged_frames
        .checked_add(1)
        .ok_or(DurableRelaySenderErrorV1::CorruptState)?;
    if advanced.acknowledged_frames == advanced.frame_count {
        advanced.state = RouteApplicationStateV2::Acked;
    }
    update_route_application_tx(transaction, &application, &advanced)
}

fn update_route_application_tx(
    transaction: &Transaction<'_>,
    previous: &RouteApplicationRowV2,
    next: &RouteApplicationRowV2,
) -> Result<(), DurableRelaySenderErrorV1> {
    validate_route_application_row(previous)?;
    validate_route_application_row(next)?;
    if previous.application_id != next.application_id
        || previous.signed_dsc1_digest != next.signed_dsc1_digest
        || previous.signed_dsc1 != next.signed_dsc1
        || previous.first_sequence != next.first_sequence
        || previous.final_sequence != next.final_sequence
        || previous.frame_count != next.frame_count
        || previous.frame_binding != next.frame_binding
        || previous.expiry != next.expiry
        || next.acknowledged_frames != previous.acknowledged_frames + 1
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    let (_, next_status) = route_application_discriminants(next);
    let previous_digest = route_application_row_digest(previous)?;
    let next_digest = route_application_row_digest(next)?;
    let changed = transaction.execute(
        "UPDATE route_application
         SET delivery_status = ?1, acknowledged_frames = ?2, row_digest = ?3
         WHERE application_id = ?4 AND row_digest = ?5",
        params![
            next_status,
            i64::from(next.acknowledged_frames),
            next_digest.as_slice(),
            next.application_id.as_slice(),
            previous_digest.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(())
}

fn route_application_discriminants(application: &RouteApplicationRowV2) -> (i64, i64) {
    let kind = if application.frame_count == 1 {
        ROUTE_APPLICATION_DIRECT
    } else {
        ROUTE_APPLICATION_FRAMED
    };
    let status = match application.state {
        RouteApplicationStateV2::Pending => ROUTE_APPLICATION_PENDING,
        RouteApplicationStateV2::Acked => ROUTE_APPLICATION_ACKED,
    };
    (kind, status)
}

fn validate_route_application_row(
    application: &RouteApplicationRowV2,
) -> Result<(), DurableRelaySenderErrorV1> {
    if application.application_id == ZERO_DIGEST
        || application.signed_dsc1_digest == ZERO_DIGEST
        || application.signed_dsc1.is_empty()
        || application.signed_dsc1.len() > MAX_FRAMED_DSC1_BYTES_V2
        || application.frame_count == 0
        || application.frame_count > MAX_ROUTE_FRAME_COUNT_V2
        || application.acknowledged_frames > application.frame_count
        || application.final_sequence
            != application
                .first_sequence
                .checked_add(u64::from(application.frame_count - 1))
                .ok_or(DurableRelaySenderErrorV1::CorruptState)?
        || full_message_digest_v2(&application.signed_dsc1)
            .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?
            != application.signed_dsc1_digest
        || (application.frame_count == 1
            && (application.signed_dsc1.len() > MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES
                || application.frame_binding != ZERO_DIGEST))
        || (application.frame_count > 1
            && (application.signed_dsc1.len() <= MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES
                || application.frame_binding == ZERO_DIGEST))
        || match application.state {
            RouteApplicationStateV2::Pending => {
                application.acknowledged_frames >= application.frame_count
            }
            RouteApplicationStateV2::Acked => {
                application.acknowledged_frames != application.frame_count
            }
        }
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(())
}

fn route_application_row_digest(
    application: &RouteApplicationRowV2,
) -> Result<Digest32, DurableRelaySenderErrorV1> {
    let (kind, status) = route_application_discriminants(application);
    let kind = u8::try_from(kind).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    let status = u8::try_from(status).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    let (expiry_domain, expiry_value) = timelock_parts(application.expiry);
    let signed_len = u32::try_from(application.signed_dsc1.len())
        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?
        .to_be_bytes();
    digest_parts(
        ROUTE_APPLICATION_DOMAIN,
        &[
            application.application_id.as_slice(),
            application.signed_dsc1_digest.as_slice(),
            &signed_len,
            application.signed_dsc1.as_slice(),
            &[kind],
            &[status],
            &application.first_sequence.to_be_bytes(),
            &application.final_sequence.to_be_bytes(),
            &application.frame_count.to_be_bytes(),
            &application.acknowledged_frames.to_be_bytes(),
            application.frame_binding.as_slice(),
            &[expiry_domain],
            &expiry_value.to_be_bytes(),
        ],
    )
}

fn audit_route_applications(
    applications: &[RouteApplicationRowV2],
    history: &[HistoryRowV1],
    frame: Option<&FrameTransferRowV2>,
    pending: Option<&DurableOutboundEnvelopeV1>,
    checkpoint: RouteSenderCheckpointV1,
) -> Result<(), DurableRelaySenderErrorV1> {
    let pending_applications = applications
        .iter()
        .filter(|application| application.state == RouteApplicationStateV2::Pending)
        .count();
    if pending_applications > 1 {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    for row in history {
        if let Some(application_id) = row.application_id {
            if !applications
                .iter()
                .any(|application| application.application_id == application_id)
            {
                return Err(DurableRelaySenderErrorV1::CorruptState);
            }
        }
    }

    for application in applications {
        validate_route_application_row(application)?;
        let frame_plan = if application.frame_count > 1 {
            let first_sequence = usize::try_from(application.first_sequence)
                .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
            let base_previous = if first_sequence == 0 {
                ZERO_DIGEST
            } else {
                history
                    .get(first_sequence - 1)
                    .ok_or(DurableRelaySenderErrorV1::CorruptState)?
                    .envelope_digest
            };
            let base = RouteSenderCheckpointV1 {
                ctx: checkpoint.wire_context(),
                sender_id: checkpoint.sender_id(),
                recipient_id: checkpoint.recipient_id(),
                role: checkpoint.sender_role(),
                next_sequence: application.first_sequence,
                previous_digest: base_previous,
            };
            let plan = RouteFramePlanV2::new(base, &application.signed_dsc1)
                .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
            if plan.message_digest() != &application.signed_dsc1_digest
                || plan.binding_digest() != &application.frame_binding
                || plan.frame_count() != usize::from(application.frame_count)
            {
                return Err(DurableRelaySenderErrorV1::CorruptState);
            }
            Some(plan)
        } else {
            None
        };
        let members: Vec<&HistoryRowV1> = history
            .iter()
            .filter(|row| row.application_id == Some(application.application_id))
            .collect();
        if members.len() != usize::from(application.acknowledged_frames) {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        for (offset, member) in members.iter().enumerate() {
            let offset =
                u16::try_from(offset).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
            let member_checkpoint = RouteSenderCheckpointV1 {
                ctx: checkpoint.wire_context(),
                sender_id: checkpoint.sender_id(),
                recipient_id: checkpoint.recipient_id(),
                role: checkpoint.sender_role(),
                next_sequence: member.sequence,
                previous_digest: member.previous_digest,
            };
            let payload = if let Some(plan) = frame_plan.as_ref() {
                plan.frame_payload_for_checkpoint(member_checkpoint, usize::from(offset))
                    .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?
                    .to_vec()
            } else {
                application.signed_dsc1.clone()
            };
            let expected_envelope = RelayEnvelopeV1 {
                network_id: checkpoint.wire_context().network_id,
                message_type: message_type::ROUTE_TRANSPORT,
                session_id: checkpoint.wire_context().session_id,
                route_id: checkpoint.wire_context().route_id,
                sender_id: checkpoint.sender_id(),
                recipient_id: checkpoint.recipient_id(),
                sender_role: checkpoint.sender_role(),
                sequence: member.sequence,
                previous_transcript_hash: member.previous_digest,
                payload,
                expiry: application.expiry,
                policy_version: checkpoint.wire_context().policy_version,
                roster_snapshot: checkpoint.wire_context().roster_snapshot,
                signature: [0; 64],
            };
            let expected_envelope_digest = expected_envelope
                .envelope_digest()
                .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
            if member.sequence
                != application
                    .first_sequence
                    .checked_add(u64::from(offset))
                    .ok_or(DurableRelaySenderErrorV1::CorruptState)?
                || member.message_type != message_type::ROUTE_TRANSPORT
                || member.envelope_digest != expected_envelope_digest
                || if application.frame_count == 1 {
                    member.frame_index.is_some()
                        || member.frame_count.is_some()
                        || member.frame_binding != ZERO_DIGEST
                } else {
                    member.frame_index != Some(offset)
                        || member.frame_count != Some(application.frame_count)
                        || member.frame_binding != application.frame_binding
                }
            {
                return Err(DurableRelaySenderErrorV1::CorruptState);
            }
        }

        match application.state {
            RouteApplicationStateV2::Acked => {
                if frame.and_then(|row| row.application_id) == Some(application.application_id)
                    || pending.and_then(|row| row.application_id)
                        == Some(application.application_id)
                {
                    return Err(DurableRelaySenderErrorV1::CorruptState);
                }
            }
            RouteApplicationStateV2::Pending if application.frame_count == 1 => {
                let pending = pending.ok_or(DurableRelaySenderErrorV1::CorruptState)?;
                let envelope = RelayEnvelopeV1::decode(&pending.raw)
                    .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
                if frame.is_some()
                    || pending.application_id != Some(application.application_id)
                    || pending.sequence != application.first_sequence
                    || pending.frame_index.is_some()
                    || envelope.payload != application.signed_dsc1
                    || checkpoint.next_sequence() != application.first_sequence
                {
                    return Err(DurableRelaySenderErrorV1::CorruptState);
                }
            }
            RouteApplicationStateV2::Pending => {
                let frame = frame.ok_or(DurableRelaySenderErrorV1::CorruptState)?;
                if frame.application_id != Some(application.application_id)
                    || frame.base.next_sequence() != application.first_sequence
                    || frame.signed_dsc1 != application.signed_dsc1
                    || frame.message_digest != application.signed_dsc1_digest
                    || frame.binding_digest != application.frame_binding
                    || frame.frame_count != application.frame_count
                    || frame.next_frame != application.acknowledged_frames
                    || frame.expiry != application.expiry
                    || checkpoint.next_sequence()
                        != application
                            .first_sequence
                            .checked_add(u64::from(application.acknowledged_frames))
                            .ok_or(DurableRelaySenderErrorV1::CorruptState)?
                    || pending.is_some_and(|row| {
                        row.application_id != Some(application.application_id)
                            || row.frame_index != Some(application.acknowledged_frames)
                    })
                {
                    return Err(DurableRelaySenderErrorV1::CorruptState);
                }
            }
        }
    }

    if frame
        .and_then(|row| row.application_id)
        .is_some_and(|application_id| {
            !applications
                .iter()
                .any(|application| application.application_id == application_id)
        })
        || pending
            .and_then(|row| row.application_id)
            .is_some_and(|application_id| {
                !applications
                    .iter()
                    .any(|application| application.application_id == application_id)
            })
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(())
}

fn insert_frame_transfer_tx(
    transaction: &Transaction<'_>,
    frame: &FrameTransferRowV2,
) -> Result<(), DurableRelaySenderErrorV1> {
    let base = frame
        .base
        .canonical_bytes()
        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    let (expiry_domain, expiry_value) = timelock_parts(frame.expiry);
    let row_digest = frame_transfer_digest(frame)?;
    let changed = transaction.execute(
        "INSERT INTO frame_transfer
         (singleton, application_id, base_checkpoint, signed_dsc1, expiry_domain,
          expiry_value_be, message_digest, binding_digest, frame_count,
          next_frame, row_digest)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            frame.application_id.as_ref().map(|id| id.as_slice()),
            base.as_slice(),
            frame.signed_dsc1.as_slice(),
            i64::from(expiry_domain),
            expiry_value.to_be_bytes().as_slice(),
            frame.message_digest.as_slice(),
            frame.binding_digest.as_slice(),
            i64::from(frame.frame_count),
            i64::from(frame.next_frame),
            row_digest.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(())
}

fn update_frame_transfer_tx(
    transaction: &Transaction<'_>,
    frame: &FrameTransferRowV2,
) -> Result<(), DurableRelaySenderErrorV1> {
    let row_digest = frame_transfer_digest(frame)?;
    let changed = transaction.execute(
        "UPDATE frame_transfer SET next_frame = ?1, row_digest = ?2
         WHERE singleton = 1",
        params![i64::from(frame.next_frame), row_digest.as_slice()],
    )?;
    if changed != 1 {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(())
}

fn load_frame_transfer_connection(
    connection: &Connection,
) -> Result<Option<FrameTransferRowV2>, DurableRelaySenderErrorV1> {
    let retained = connection
        .query_row(
            "SELECT application_id, base_checkpoint, signed_dsc1,
                    expiry_domain, expiry_value_be, message_digest,
                    binding_digest, frame_count, next_frame, row_digest
             FROM frame_transfer WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((
        application_id,
        base,
        signed_dsc1,
        expiry_domain,
        expiry_value,
        message_digest,
        binding_digest,
        frame_count,
        next_frame,
        stored_digest,
    )) = retained
    else {
        return Ok(None);
    };
    if signed_dsc1.len() <= MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES
        || signed_dsc1.len() > MAX_FRAMED_DSC1_BYTES_V2
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    let application_id = optional_blob32(application_id)?;
    if application_id.is_some_and(|id| id == ZERO_DIGEST) {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    let frame = FrameTransferRowV2 {
        application_id,
        base: RouteSenderCheckpointV1::from_bytes(&base)
            .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?,
        signed_dsc1,
        expiry: timelock_from_parts(
            u8::try_from(expiry_domain).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?,
            blob_u64(expiry_value)?,
        )?,
        message_digest: blob32(message_digest)?,
        binding_digest: blob32(binding_digest)?,
        frame_count: u16::try_from(frame_count)
            .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?,
        next_frame: u16::try_from(next_frame)
            .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?,
    };
    if !(2..=MAX_ROUTE_FRAME_COUNT_V2).contains(&frame.frame_count)
        || frame.next_frame >= frame.frame_count
        || frame_transfer_digest(&frame)? != blob32(stored_digest)?
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(Some(frame))
}

fn load_frame_transfer_tx(
    transaction: &Transaction<'_>,
) -> Result<Option<FrameTransferRowV2>, DurableRelaySenderErrorV1> {
    load_frame_transfer_connection(transaction)
}

fn frame_transfer_digest(
    frame: &FrameTransferRowV2,
) -> Result<Digest32, DurableRelaySenderErrorV1> {
    let base = frame
        .base
        .canonical_bytes()
        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    let (expiry_domain, expiry_value) = timelock_parts(frame.expiry);
    let source_len = u32::try_from(frame.signed_dsc1.len())
        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?
        .to_be_bytes();
    digest_parts(
        FRAME_JOB_DOMAIN,
        &[
            &[u8::from(frame.application_id.is_some())],
            frame
                .application_id
                .as_ref()
                .unwrap_or(&ZERO_DIGEST)
                .as_slice(),
            base.as_slice(),
            &source_len,
            frame.signed_dsc1.as_slice(),
            &[expiry_domain],
            &expiry_value.to_be_bytes(),
            frame.message_digest.as_slice(),
            frame.binding_digest.as_slice(),
            &frame.frame_count.to_be_bytes(),
            &frame.next_frame.to_be_bytes(),
        ],
    )
}

fn same_frame_transfer(left: &FrameTransferRowV2, right: &FrameTransferRowV2) -> bool {
    left.application_id == right.application_id
        && left.base == right.base
        && left.signed_dsc1 == right.signed_dsc1
        && left.expiry == right.expiry
        && left.message_digest == right.message_digest
        && left.binding_digest == right.binding_digest
        && left.frame_count == right.frame_count
        && left.next_frame == right.next_frame
}

fn validate_frame_transfer(
    frame: &FrameTransferRowV2,
    config: &DurableRelaySenderConfigV1,
    current: RouteSenderCheckpointV1,
) -> Result<RouteFramePlanV2, DurableRelaySenderErrorV1> {
    if frame.base.wire_context() != config.wire
        || frame.base.sender_id() != config.sender_id
        || frame.base.recipient_id() != config.recipient_id
        || frame.base.sender_role() != config.sender_role
        || current.wire_context() != config.wire
        || current.sender_id() != config.sender_id
        || current.recipient_id() != config.recipient_id
        || current.sender_role() != config.sender_role
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    let expected_sequence = frame
        .base
        .next_sequence()
        .checked_add(u64::from(frame.next_frame))
        .ok_or(DurableRelaySenderErrorV1::CorruptState)?;
    if current.next_sequence() != expected_sequence {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    let plan = RouteFramePlanV2::new(frame.base, &frame.signed_dsc1)
        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    if plan.message_digest() != &frame.message_digest
        || plan.binding_digest() != &frame.binding_digest
        || plan.frame_count() != usize::from(frame.frame_count)
    {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(plan)
}

fn audit_frame_history_groups(
    history: &[HistoryRowV1],
    active: Option<&FrameTransferRowV2>,
) -> Result<(), DurableRelaySenderErrorV1> {
    let mut cursor = 0usize;
    let mut saw_active = false;
    while cursor < history.len() {
        let row = &history[cursor];
        let Some(count) = row.frame_count else {
            if row.frame_index.is_some() || row.frame_binding != ZERO_DIGEST {
                return Err(DurableRelaySenderErrorV1::CorruptState);
            }
            cursor += 1;
            continue;
        };
        if row.frame_index != Some(0) {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        let count_usize = usize::from(count);
        let available = history.len() - cursor;
        let group_len = available.min(count_usize);
        for offset in 0..group_len {
            let member = &history[cursor + offset];
            if member.frame_index
                != Some(u16::try_from(offset).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?)
                || member.frame_count != Some(count)
                || member.frame_binding != row.frame_binding
                || member.message_type != message_type::ROUTE_TRANSPORT
            {
                return Err(DurableRelaySenderErrorV1::CorruptState);
            }
        }
        if group_len < count_usize {
            let Some(frame) = active else {
                return Err(DurableRelaySenderErrorV1::CorruptState);
            };
            if saw_active
                || cursor
                    != usize::try_from(frame.base.next_sequence())
                        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?
                || group_len != usize::from(frame.next_frame)
                || count != frame.frame_count
                || row.frame_binding != frame.binding_digest
            {
                return Err(DurableRelaySenderErrorV1::CorruptState);
            }
            saw_active = true;
            cursor += group_len;
        } else {
            cursor += count_usize;
        }
    }
    if let Some(frame) = active {
        let base_sequence = usize::try_from(frame.base.next_sequence())
            .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
        let completed_frames = usize::from(frame.next_frame);
        if !matches!(
            base_sequence.checked_add(completed_frames),
            Some(end) if end == history.len()
        ) || (completed_frames > 0 && !saw_active)
            || (completed_frames == 0 && base_sequence != history.len())
        {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
        let expected_base_previous = if base_sequence == 0 {
            ZERO_DIGEST
        } else {
            history
                .get(base_sequence - 1)
                .ok_or(DurableRelaySenderErrorV1::CorruptState)?
                .envelope_digest
        };
        if *frame.base.previous_digest() != expected_base_previous {
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
    } else if saw_active {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(())
}

fn optional_frame_index(value: i64) -> Result<Option<u16>, DurableRelaySenderErrorV1> {
    match value {
        -1 => Ok(None),
        0..=32 => Ok(Some(
            u16::try_from(value).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?,
        )),
        _ => Err(DurableRelaySenderErrorV1::CorruptState),
    }
}

fn optional_frame_count(value: i64) -> Result<Option<u16>, DurableRelaySenderErrorV1> {
    match value {
        0 => Ok(None),
        2..=33 => Ok(Some(
            u16::try_from(value).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?,
        )),
        _ => Err(DurableRelaySenderErrorV1::CorruptState),
    }
}

fn sender_role_byte(role: SenderRoleV1) -> u8 {
    match role {
        SenderRoleV1::Initiator => 1,
        SenderRoleV1::Solver => 2,
        SenderRoleV1::Observer => 3,
    }
}

fn timelock_parts(spec: TimelockSpec) -> (u8, u64) {
    match spec {
        TimelockSpec::BlockHeight { value } => (1, value),
        TimelockSpec::TimestampSeconds { value } => (2, value),
        TimelockSpec::BtcTime512s { value } => (3, value),
    }
}

fn timelock_from_parts(domain: u8, value: u64) -> Result<TimelockSpec, DurableRelaySenderErrorV1> {
    match domain {
        1 => Ok(TimelockSpec::BlockHeight { value }),
        2 => Ok(TimelockSpec::TimestampSeconds { value }),
        3 => Ok(TimelockSpec::BtcTime512s { value }),
        _ => Err(DurableRelaySenderErrorV1::CorruptState),
    }
}

fn blob32(value: Vec<u8>) -> Result<Digest32, DurableRelaySenderErrorV1> {
    value
        .try_into()
        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)
}

fn optional_blob32(value: Option<Vec<u8>>) -> Result<Option<Digest32>, DurableRelaySenderErrorV1> {
    value.map(blob32).transpose()
}

fn blob_u64(value: Vec<u8>) -> Result<u64, DurableRelaySenderErrorV1> {
    let bytes: [u8; 8] = value
        .try_into()
        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    Ok(u64::from_be_bytes(bytes))
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, DurableRelaySenderErrorV1> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    hasher.update(domain);
    for part in parts {
        let length =
            u64::try_from(part.len()).map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
        hasher.update(&length.to_be_bytes());
        hasher.update(part);
    }
    let mut digest = [0; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| DurableRelaySenderErrorV1::CorruptState)?;
    Ok(digest)
}

fn ensure_absent_tx(
    transaction: &Transaction<'_>,
    table: &str,
) -> Result<(), DurableRelaySenderErrorV1> {
    let query = match table {
        "sender_pending" => "SELECT EXISTS(SELECT 1 FROM sender_pending)",
        "frame_transfer" => "SELECT EXISTS(SELECT 1 FROM frame_transfer)",
        _ => return Err(DurableRelaySenderErrorV1::CorruptState),
    };
    let exists: i64 = transaction.query_row(query, [], |row| row.get(0))?;
    if exists != 0 {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(())
}

fn preflight_existing_schema_version(
    connection: &Connection,
) -> Result<(), DurableRelaySenderErrorV1> {
    let app_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| DurableRelaySenderErrorV1::UnsupportedFormat)?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| DurableRelaySenderErrorV1::UnsupportedFormat)?;
    if app_id == APPLICATION_ID && version == LEGACY_SCHEMA_VERSION {
        return Err(DurableRelaySenderErrorV1::LegacyFormatRequiresOfflineMigration);
    }
    if app_id != APPLICATION_ID || version != SCHEMA_VERSION {
        return Err(DurableRelaySenderErrorV1::UnsupportedFormat);
    }
    Ok(())
}

fn configure_connection(connection: &Connection) -> Result<(), DurableRelaySenderErrorV1> {
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
        return Err(DurableRelaySenderErrorV1::UnsupportedFormat);
    }
    validate_connection_settings(connection)
}

fn validate_connection_settings(connection: &Connection) -> Result<(), DurableRelaySenderErrorV1> {
    let journal: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let read_uncommitted: i64 =
        connection.query_row("PRAGMA read_uncommitted", [], |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
    let secure_delete: i64 = connection.query_row("PRAGMA secure_delete", [], |row| row.get(0))?;
    let busy_timeout: i64 = connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    let defensive = rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE;
    if !journal.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || read_uncommitted != 0
        || trusted_schema != 0
        || secure_delete != 1
        || busy_timeout != 5_000
        || !connection.db_config(defensive)?
    {
        return Err(DurableRelaySenderErrorV1::UnsupportedFormat);
    }
    Ok(())
}

type SchemaObjectV1 = (String, String, String, String);

fn schema_objects(
    connection: &Connection,
) -> Result<BTreeSet<SchemaObjectV1>, DurableRelaySenderErrorV1> {
    const MAX_SCHEMA_OBJECTS: i64 = 12;
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
        return Err(DurableRelaySenderErrorV1::CorruptState);
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
            return Err(DurableRelaySenderErrorV1::CorruptState);
        }
    }
    if i64::try_from(objects.len()).map_err(|_| DurableRelaySenderErrorV1::CorruptState)? != count {
        return Err(DurableRelaySenderErrorV1::CorruptState);
    }
    Ok(objects)
}

fn reference_schema_objects() -> Result<BTreeSet<SchemaObjectV1>, DurableRelaySenderErrorV1> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA_SQL)?;
    schema_objects(&reference)
}

fn require_pristine_connection(
    connection: &Connection,
    config: &DurableRelaySenderConfigV1,
) -> Result<(), DurableRelaySenderErrorV1> {
    let meta = require_meta_connection(connection, config)?;
    let (history, pending, transfers, applications): (i64, i64, i64, i64) = connection.query_row(
        "SELECT
                (SELECT COUNT(*) FROM sender_history),
                (SELECT COUNT(*) FROM sender_pending),
                (SELECT COUNT(*) FROM frame_transfer),
                (SELECT COUNT(*) FROM route_application)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if meta.completed != 0
        || meta.checkpoint != config.initial_checkpoint()
        || history != 0
        || pending != 0
        || transfers != 0
        || applications != 0
    {
        return Err(DurableRelaySenderErrorV1::UnsupportedFormat);
    }
    Ok(())
}

fn preflight_resumable_database(
    database_path: &Path,
    authority: &File,
    config: &DurableRelaySenderConfigV1,
) -> Result<DurableProductionCreationStateV1, DurableRelaySenderErrorV1> {
    validate_database_authority(authority, database_path)?;
    if authority
        .metadata()
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?
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
    config: &DurableRelaySenderConfigV1,
) -> Result<DurableProductionCreationStateV1, DurableRelaySenderErrorV1> {
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
        return Err(DurableRelaySenderErrorV1::UnsupportedFormat);
    };
    Ok(state)
}

fn validate_database_path(
    connection: &Connection,
    expected_path: &Path,
) -> Result<(), DurableRelaySenderErrorV1> {
    let expected = fs::canonicalize(expected_path)
        .map_err(|_| DurableRelaySenderErrorV1::InvalidConfiguration)?;
    if expected != expected_path {
        return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
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
            _ => return Err(DurableRelaySenderErrorV1::InvalidConfiguration),
        }
    }
    if !saw_main {
        return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn create_root(root: &Path) -> Result<(), DurableRelaySenderErrorV1> {
    validate_new_path(root)?;
    match DirBuilder::new().mode(ROOT_MODE).create(root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(DurableRelaySenderErrorV1::AlreadyExists)
        }
        Err(_) => return Err(DurableRelaySenderErrorV1::StorageUnavailable),
    }
    sync_directory(root)?;
    let parent = root
        .parent()
        .ok_or(DurableRelaySenderErrorV1::InvalidConfiguration)?;
    sync_directory(parent)?;
    validate_root(root)
}

fn validate_new_path(root: &Path) -> Result<(), DurableRelaySenderErrorV1> {
    if !root.is_absolute() || root.file_name().is_none() {
        return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
    }
    let parent = root
        .parent()
        .ok_or(DurableRelaySenderErrorV1::InvalidConfiguration)?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|_| DurableRelaySenderErrorV1::InvalidConfiguration)?;
    if canonical_parent != parent {
        return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
    }
    validate_owner_directory(parent)
}

fn validate_root(root: &Path) -> Result<(), DurableRelaySenderErrorV1> {
    if !root.is_absolute()
        || fs::canonicalize(root).map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?
            != root
    {
        return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
    }
    validate_owner_directory(root)
}

fn validate_root_entries(root: &Path) -> Result<(), DurableRelaySenderErrorV1> {
    let allowed = [
        LOCK_FILE_NAME,
        DATABASE_FILE_NAME,
        "route-sender-v1.sqlite3-wal",
        "route-sender-v1.sqlite3-shm",
    ];
    let entries = fs::read_dir(root).map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    for entry in entries {
        let entry = entry.map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| DurableRelaySenderErrorV1::InvalidConfiguration)?;
        if !allowed.contains(&name.as_str()) {
            return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
        }
    }
    Ok(())
}

fn inspect_creation_state(
    root: &Path,
    config: &DurableRelaySenderConfigV1,
) -> Result<DurableProductionCreationStateV1, DurableRelaySenderErrorV1> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            validate_new_path(root)?;
            return Ok(DurableProductionCreationStateV1::Missing);
        }
        Err(_) => return Err(DurableRelaySenderErrorV1::StorageUnavailable),
        Ok(_) => validate_root(root)?,
    }
    validate_root_entries(root)?;
    let lock_path = root.join(LOCK_FILE_NAME);
    let database_path = root.join(DATABASE_FILE_NAME);
    let lock_exists = lock_path
        .try_exists()
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    let database_exists = database_path
        .try_exists()
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    if !lock_exists {
        if fs::read_dir(root)
            .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?
            .next()
            .is_none()
        {
            return Ok(DurableProductionCreationStateV1::Incomplete);
        }
        return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
    }
    validate_owner_file(&lock_path)?;
    validate_resumable_database_files(root, database_exists)?;
    if !database_exists {
        return Ok(DurableProductionCreationStateV1::Incomplete);
    }
    let authority = open_database_authority(&database_path)?;
    preflight_resumable_database(&database_path, &authority, config)
}

fn create_database_authority(path: &Path) -> Result<File, DurableRelaySenderErrorV1> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    validate_database_authority(&file, path)?;
    file.sync_all()
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    sync_directory(
        path.parent()
            .ok_or(DurableRelaySenderErrorV1::InvalidConfiguration)?,
    )?;
    Ok(file)
}

fn open_database_authority(path: &Path) -> Result<File, DurableRelaySenderErrorV1> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    validate_database_authority(&file, path)?;
    Ok(file)
}

fn open_connection_via_authority(
    authority: &File,
    database_path: &Path,
    flags: OpenFlags,
) -> Result<(Connection, File), DurableRelaySenderErrorV1> {
    open_connection_via_authority_with_hooks(authority, database_path, flags, || Ok(()), || Ok(()))
}

fn open_connection_via_authority_with_hooks<BeforeOpen, AfterOpen>(
    authority: &File,
    database_path: &Path,
    flags: OpenFlags,
    before_open: BeforeOpen,
    after_open: AfterOpen,
) -> Result<(Connection, File), DurableRelaySenderErrorV1>
where
    BeforeOpen: FnOnce() -> Result<(), DurableRelaySenderErrorV1>,
    AfterOpen: FnOnce() -> Result<(), DurableRelaySenderErrorV1>,
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

fn validate_database_authority(
    authority: &File,
    path: &Path,
) -> Result<(), DurableRelaySenderErrorV1> {
    validate_owner_file(path)?;
    let retained = authority
        .metadata()
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    let named =
        fs::symlink_metadata(path).map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn validate_connection_authority(
    authority: &File,
    sqlite_authority: &File,
    path: &Path,
) -> Result<(), DurableRelaySenderErrorV1> {
    validate_database_authority(authority, path)?;
    let retained = authority
        .metadata()
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    let sqlite = sqlite_authority
        .metadata()
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    if retained.dev() != sqlite.dev() || retained.ino() != sqlite.ino() {
        return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn process_descriptor_snapshot() -> Result<BTreeMap<i32, (u64, u64)>, DurableRelaySenderErrorV1> {
    let mut snapshot = BTreeMap::new();
    for entry in
        fs::read_dir("/proc/self/fd").map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?
    {
        let entry = entry.map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        match fs::metadata(entry.path()) {
            Ok(metadata) => {
                snapshot.insert(fd, (metadata.dev(), metadata.ino()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(DurableRelaySenderErrorV1::StorageUnavailable),
        }
    }
    Ok(snapshot)
}

fn capture_new_sqlite_database_authority(
    authority: &File,
    before: &BTreeMap<i32, (u64, u64)>,
) -> Result<File, DurableRelaySenderErrorV1> {
    let retained = authority
        .metadata()
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    let expected = (retained.dev(), retained.ino());
    let after = process_descriptor_snapshot()?;
    let mut candidates = after.iter().filter_map(|(fd, identity)| {
        (*identity == expected && before.get(fd) != Some(identity)).then_some(*fd)
    });
    let candidate = candidates
        .next()
        .ok_or(DurableRelaySenderErrorV1::InvalidConfiguration)?;
    if candidates.next().is_some() {
        return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
    }
    let proof = File::open(PathBuf::from("/proc/self/fd").join(candidate.to_string()))
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    let proof_metadata = proof
        .metadata()
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    if (proof_metadata.dev(), proof_metadata.ino()) != expected {
        return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
    }
    Ok(proof)
}

fn acquire_resume_lock(root: &Path) -> Result<File, DurableRelaySenderErrorV1> {
    match fs::symlink_metadata(root) {
        Ok(_) => validate_root(root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_root(root)?,
        Err(_) => return Err(DurableRelaySenderErrorV1::StorageUnavailable),
    }
    validate_root_entries(root)?;
    let lock_path = root.join(LOCK_FILE_NAME);
    let lock_exists = lock_path
        .try_exists()
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    if lock_exists {
        acquire_lock(root, false)
    } else {
        let mut entries =
            fs::read_dir(root).map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
        if entries.next().is_some() {
            return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
        }
        acquire_lock(root, true)
    }
}

fn validate_resumable_database_files(
    root: &Path,
    database_exists: bool,
) -> Result<(), DurableRelaySenderErrorV1> {
    let database_path = root.join(DATABASE_FILE_NAME);
    if database_exists {
        validate_owner_file(&database_path)?;
    }
    for suffix in ["-wal", "-shm"] {
        let sidecar = root.join(format!("{DATABASE_FILE_NAME}{suffix}"));
        if sidecar
            .try_exists()
            .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?
        {
            if !database_exists {
                return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
            }
            validate_owner_file(&sidecar)?;
        }
    }
    Ok(())
}

fn validate_owner_directory(path: &Path) -> Result<(), DurableRelaySenderErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != ROOT_MODE
        || metadata.nlink() == 0
    {
        return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn validate_owner_file(path: &Path) -> Result<(), DurableRelaySenderErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn acquire_lock(root: &Path, create: bool) -> Result<File, DurableRelaySenderErrorV1> {
    let path = root.join(LOCK_FILE_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true).mode(FILE_MODE);
    if create {
        options.create_new(true);
    }
    let file = options
        .open(&path)
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    validate_owner_file(&path)?;
    let retained = file
        .metadata()
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    let named =
        fs::symlink_metadata(&path).map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(DurableRelaySenderErrorV1::InvalidConfiguration);
    }
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
    if create {
        file.sync_all()
            .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)?;
        sync_directory(root)?;
    }
    Ok(file)
}

fn sync_directory(path: &Path) -> Result<(), DurableRelaySenderErrorV1> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)
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
                    .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)
            },
            || {
                fs::rename(&database, &alternate)
                    .and_then(|()| fs::rename(&retained_name, &database))
                    .map_err(|_| DurableRelaySenderErrorV1::StorageUnavailable)
            },
        );
        assert!(matches!(
            result,
            Err(DurableRelaySenderErrorV1::InvalidConfiguration)
        ));
        validate_database_authority(&authority, &database)?;
        Ok(())
    }
}
