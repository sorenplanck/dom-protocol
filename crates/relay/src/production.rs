//! Durable production Relay queue.
//!
//! [`crate::server::RelayV1`] remains the small in-memory protocol reference.
//! This module implements the same store-and-forward rules over a dedicated
//! owner-only SQLite/WAL database. A commit is durable before an ACK is
//! returned; after ACK loss or process restart the ACK and delivered envelope
//! are derived from the exact persisted row. Opening never creates a missing
//! database, and corruption is never salvaged.
//!
//! The database is transport state, not participant authority. It stores only
//! canonical signed Relay envelopes and public digests. It never interprets a
//! payload, holds a protocol secret, or decides a claim/refund outcome.

use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use kaystra_core::types::Digest32;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use rustix::fs::{flock, FlockOperation};
use rustix::process::geteuid;

use crate::recovery::{AuthenticatedRecoveryBatchV1, AuthenticatedRecoveryEntryV1};
use crate::server::{AckV1, EquivocationProofV1, IdempotencyKeyV1, MAX_STORED_ENVELOPES};
use crate::{EnvelopeError, ParticipantId, RelayEnvelopeV1, MAX_ENVELOPE_BYTES};

/// Fixed database filename within an owner-only Relay root.
pub const RELAY_DATABASE_FILE_NAME: &str = "relay-v1.sqlite3";
/// Retained instance-identity filename. Database loss does not remove it.
pub const RELAY_IDENTITY_FILE_NAME: &str = "relay-identity.v1";
/// Retained single-writer lock filename.
pub const RELAY_LOCK_FILE_NAME: &str = ".relay.lock";

pub(crate) const RELAY_DATABASE_LOSS_MARKER_NAME: &str = "relay-database-loss.v1";
pub(crate) const ROOT_MODE: u32 = 0o700;
pub(crate) const FILE_MODE: u32 = 0o600;

const SCHEMA_VERSION: i64 = 3;
const SQLITE_VERSION: &str = "3.53.2";
const SQLITE_SOURCE_ID: &str =
    "2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24";
const IDENTITY_MAGIC: &[u8; 8] = b"DOMRLYI1";
const IDENTITY_VERSION: u16 = 1;
const IDENTITY_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DATABASE-IDENTITY/V1\0";
const IDENTITY_RECORD_LEN: usize = 8 + 2 + 32 + 32;
pub(crate) const DATABASE_LOSS_MAGIC: &[u8; 8] = b"DOMRLYD1";
pub(crate) const DATABASE_LOSS_VERSION: u16 = 1;
pub(crate) const DATABASE_LOSS_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DATABASE-LOSS/V1\0";
pub(crate) const DATABASE_LOSS_MARKER_LEN: usize = 8 + 2 + 32 + 32;
const ROW_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DATABASE-ROW/V1\0";
const CONFLICT_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DATABASE-CONFLICT/V1\0";
const SCHEMA_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DATABASE-SCHEMA/V3\0";
const DELIVERY_CURSOR_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DELIVERY-CURSOR/V2\0";
const DELIVERY_PAGE_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DELIVERY-PAGE/V2\0";
const DELIVERY_ACK_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DELIVERY-ACK/V2\0";
const DELIVERY_STATE_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DELIVERY-STATE/V2\0";
const DELIVERY_FLOW_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DELIVERY-FLOW/V2\0";
const DELIVERY_EXACT_BYTES_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-EXACT-BYTES/V2\0";
const DELIVERY_CURSOR_DOMAIN_V3: &[u8] = b"DOM-INTEROP/F7/RELAY-DELIVERY-CURSOR/V3\0";
const DELIVERY_PAGE_DOMAIN_V3: &[u8] = b"DOM-INTEROP/F7/RELAY-DELIVERY-PAGE/V3\0";
const DELIVERY_ACK_DOMAIN_V3: &[u8] = b"DOM-INTEROP/F7/RELAY-DELIVERY-ACK/V3\0";
const DELIVERY_STATE_KEY_DOMAIN_V3: &[u8] = b"DOM-INTEROP/F7/RELAY-DELIVERY-STATE-KEY/V3\0";
const DELIVERY_SCOPE_ROW_DOMAIN_V3: &[u8] = b"DOM-INTEROP/F7/RELAY-DELIVERY-SCOPE-ROW/V3\0";
const ZERO_DIGEST: Digest32 = [0_u8; 32];
const _: [(); MAX_ENVELOPE_BYTES] = [(); 16_742];

/// Maximum number of envelopes in one production delivery page.
pub const MAX_DELIVERY_PAGE_ITEMS_V2: u16 = 256;
/// Maximum sum of canonical envelope bytes in one production delivery page.
pub const MAX_DELIVERY_PAGE_BYTES_V2: u32 =
    (MAX_ENVELOPE_BYTES as u32) * (MAX_DELIVERY_PAGE_ITEMS_V2 as u32);
/// V3 retains the reviewed V2 item-count ceiling.
pub const MAX_DELIVERY_PAGE_ITEMS_V3: u16 = MAX_DELIVERY_PAGE_ITEMS_V2;
/// V3 retains the reviewed V2 canonical-byte ceiling.
pub const MAX_DELIVERY_PAGE_BYTES_V3: u32 = MAX_DELIVERY_PAGE_BYTES_V2;

const SCHEMA_SQL: &str = r#"
CREATE TABLE relay_meta (
    singleton               INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version          INTEGER NOT NULL CHECK (schema_version = 3),
    database_id             BLOB NOT NULL CHECK (length(database_id) = 32),
    max_envelopes           INTEGER NOT NULL CHECK (max_envelopes > 0 AND max_envelopes <= 65536),
    creation_kind           INTEGER NOT NULL CHECK (creation_kind IN (1, 2)),
    recovery_digest         BLOB NOT NULL CHECK (length(recovery_digest) = 32),
    reconstruction_complete INTEGER NOT NULL CHECK (reconstruction_complete IN (0, 1)),
    schema_digest           BLOB NOT NULL CHECK (length(schema_digest) = 32),
    next_envelope_ordinal   INTEGER NOT NULL CHECK (next_envelope_ordinal > 0)
) STRICT;

CREATE TABLE relay_envelopes (
    ordinal            INTEGER PRIMARY KEY CHECK (ordinal > 0),
    session_id         BLOB NOT NULL CHECK (length(session_id) = 32),
    sender_id          BLOB NOT NULL CHECK (length(sender_id) = 32),
    recipient_id       BLOB NOT NULL CHECK (length(recipient_id) = 32),
    sequence_be        BLOB NOT NULL CHECK (length(sequence_be) = 8),
    canonical_bytes    BLOB NOT NULL CHECK (length(canonical_bytes) <= 16742),
    envelope_digest    BLOB NOT NULL CHECK (length(envelope_digest) = 32),
    recovery_source_mask INTEGER NOT NULL CHECK (recovery_source_mask BETWEEN 0 AND 3),
    recovery_commitment  BLOB NOT NULL CHECK (length(recovery_commitment) = 32),
    row_digest         BLOB NOT NULL CHECK (length(row_digest) = 32),
    UNIQUE (session_id, sender_id, recipient_id, sequence_be),
    CHECK (
        (recovery_source_mask = 0 AND recovery_commitment = zeroblob(32)) OR
        (recovery_source_mask > 0 AND recovery_commitment != zeroblob(32))
    )
) STRICT;

CREATE TABLE relay_conflicts (
    ordinal             INTEGER PRIMARY KEY CHECK (ordinal > 0),
    session_id          BLOB NOT NULL CHECK (length(session_id) = 32),
    sender_id           BLOB NOT NULL CHECK (length(sender_id) = 32),
    recipient_id        BLOB NOT NULL CHECK (length(recipient_id) = 32),
    sequence_be         BLOB NOT NULL CHECK (length(sequence_be) = 8),
    first_digest        BLOB NOT NULL CHECK (length(first_digest) = 32),
    conflicting_bytes   BLOB NOT NULL CHECK (length(conflicting_bytes) <= 16742),
    conflicting_digest  BLOB NOT NULL CHECK (length(conflicting_digest) = 32),
    row_digest          BLOB NOT NULL CHECK (length(row_digest) = 32),
    UNIQUE (session_id, sender_id, recipient_id, sequence_be, conflicting_digest)
) STRICT;

CREATE TABLE relay_delivery_state (
    recipient_id BLOB PRIMARY KEY CHECK (length(recipient_id) = 32),
    state_bytes  BLOB NOT NULL CHECK (length(state_bytes) = 166),
    row_digest   BLOB NOT NULL CHECK (length(row_digest) = 32)
) STRICT;

CREATE TABLE relay_delivery_scopes_v3 (
    state_key    BLOB PRIMARY KEY CHECK (length(state_key) = 32),
    recipient_id BLOB NOT NULL CHECK (length(recipient_id) = 32),
    route_id     BLOB NOT NULL CHECK (length(route_id) = 32),
    session_id   BLOB NOT NULL CHECK (length(session_id) = 32),
    row_digest   BLOB NOT NULL CHECK (length(row_digest) = 32),
    UNIQUE (recipient_id, route_id, session_id)
) STRICT;

CREATE TABLE relay_delivery_flows (
    session_id      BLOB NOT NULL CHECK (length(session_id) = 32),
    sender_id       BLOB NOT NULL CHECK (length(sender_id) = 32),
    recipient_id    BLOB NOT NULL CHECK (length(recipient_id) = 32),
    sequence_be     BLOB NOT NULL CHECK (length(sequence_be) = 8),
    context_digest  BLOB NOT NULL CHECK (length(context_digest) = 32),
    terminal_digest BLOB NOT NULL CHECK (length(terminal_digest) = 32),
    terminal_bytes_digest BLOB NOT NULL CHECK (length(terminal_bytes_digest) = 32),
    row_digest      BLOB NOT NULL CHECK (length(row_digest) = 32),
    PRIMARY KEY (session_id, sender_id, recipient_id)
) STRICT;
"#;

#[cfg(test)]
const TEST_CREATION_EXIT_ENV: &str = "DOM_INTEROP_RELAY_TEST_EXIT_AFTER";

#[cfg(test)]
fn exit_production_creation_for_test(boundary: &str) {
    if std::env::var_os(TEST_CREATION_EXIT_ENV).as_deref() == Some(std::ffi::OsStr::new(boundary)) {
        std::process::exit(86);
    }
}

/// Stable public identity of one Relay database root.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayDatabaseIdV1(Digest32);

impl core::fmt::Debug for RelayDatabaseIdV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("RelayDatabaseIdV1")
            .field(&self.0)
            .finish()
    }
}

impl RelayDatabaseIdV1 {
    /// Creates a non-null public database identity.
    pub fn new(bytes: Digest32) -> Result<Self, ProductionRelayError> {
        if bytes == ZERO_DIGEST {
            return Err(ProductionRelayError::InvalidConfiguration);
        }
        Ok(Self(bytes))
    }

    /// Exact public identity bytes.
    pub const fn as_bytes(&self) -> &Digest32 {
        &self.0
    }
}

/// Immutable production database configuration.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RelayDatabaseConfigV1 {
    database_id: RelayDatabaseIdV1,
    max_envelopes: u32,
}

/// Read-only classification of an explicitly journaled Relay creation path.
///
/// The result is advisory: [`ProductionRelayV1::resume_create_production`]
/// revalidates the same prefix while holding the retained process lock before
/// it writes anything.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionRelayCreationStateV1 {
    /// No Relay root exists yet.
    Missing,
    /// Only an exact, non-economic creation prefix exists.
    Incomplete,
    /// The exact empty production database is durably initialized.
    InitializedPristine,
}

const DELIVERY_CURSOR_MAGIC_V2: &[u8; 8] = b"DOMRLCV2";
const DELIVERY_PAGE_MAGIC_V2: &[u8; 8] = b"DOMRLPG2";
const DELIVERY_ACK_MAGIC_V2: &[u8; 8] = b"DOMRLDA2";
const DELIVERY_WIRE_VERSION_V2: u16 = 2;
/// Exact canonical byte length of a V2 delivery cursor.
pub const DELIVERY_CURSOR_V2_LEN: usize = 8 + 2 + 32 + 32 + 8 + 32 + 32;
/// Exact canonical byte length of a V2 delivery acknowledgement.
pub const DELIVERY_ACK_V2_LEN: usize = 8 + 2 + DELIVERY_CURSOR_V2_LEN + 32;

const DELIVERY_CURSOR_MAGIC_V3: &[u8; 8] = b"DOMRLCV3";
const DELIVERY_PAGE_MAGIC_V3: &[u8; 8] = b"DOMRLPG3";
const DELIVERY_ACK_MAGIC_V3: &[u8; 8] = b"DOMRLDA3";
const DELIVERY_WIRE_VERSION_V3: u16 = 3;
/// Exact canonical byte length of a V3 delivery cursor.
pub const DELIVERY_CURSOR_V3_LEN: usize = 8 + 2 + (32 * 4) + 8 + 32 + 32;
/// Exact canonical byte length of a V3 delivery acknowledgement.
pub const DELIVERY_ACK_V3_LEN: usize = 8 + 2 + DELIVERY_CURSOR_V3_LEN + 32;

/// Exact route/session queue scope selected by a recipient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryScopeV3 {
    recipient_id: ParticipantId,
    route_id: Digest32,
    session_id: Digest32,
}

impl DeliveryScopeV3 {
    /// Creates a non-null recipient, route and session delivery scope.
    pub fn new(
        recipient_id: ParticipantId,
        route_id: Digest32,
        session_id: Digest32,
    ) -> Result<Self, ProductionRelayError> {
        if recipient_id.0 == ZERO_DIGEST || route_id == ZERO_DIGEST || session_id == ZERO_DIGEST {
            return Err(ProductionRelayError::InvalidConfiguration);
        }
        Ok(Self {
            recipient_id,
            route_id,
            session_id,
        })
    }

    /// Recipient authorized to consume this queue scope.
    pub const fn recipient_id(&self) -> ParticipantId {
        self.recipient_id
    }

    /// Authenticated route identifier.
    pub const fn route_id(&self) -> &Digest32 {
        &self.route_id
    }

    /// Authenticated session identifier.
    pub const fn session_id(&self) -> &Digest32 {
        &self.session_id
    }
}

/// Database-, recipient-, route- and session-bound monotonic delivery cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryCursorV3 {
    database_id: RelayDatabaseIdV1,
    scope: DeliveryScopeV3,
    position: u64,
    page_digest: Digest32,
    authenticator: Digest32,
}

impl DeliveryCursorV3 {
    /// Relay database identity this cursor belongs to.
    pub const fn database_id(&self) -> RelayDatabaseIdV1 {
        self.database_id
    }

    /// Exact recipient/route/session scope this cursor belongs to.
    pub const fn scope(&self) -> &DeliveryScopeV3 {
        &self.scope
    }

    /// Monotonic database position covered by this scoped cursor.
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Exact canonical cursor bytes.
    pub fn canonical_bytes(&self) -> [u8; DELIVERY_CURSOR_V3_LEN] {
        let mut out = [0_u8; DELIVERY_CURSOR_V3_LEN];
        let mut offset = 0_usize;
        for part in [
            DELIVERY_CURSOR_MAGIC_V3.as_slice(),
            DELIVERY_WIRE_VERSION_V3.to_be_bytes().as_slice(),
            self.database_id.as_bytes().as_slice(),
            self.scope.recipient_id.0.as_slice(),
            self.scope.route_id.as_slice(),
            self.scope.session_id.as_slice(),
            self.position.to_be_bytes().as_slice(),
            self.page_digest.as_slice(),
            self.authenticator.as_slice(),
        ] {
            let end = offset + part.len();
            out[offset..end].copy_from_slice(part);
            offset = end;
        }
        out
    }

    /// Strictly decodes the fixed-width V3 cursor.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProductionRelayError> {
        if bytes.len() != DELIVERY_CURSOR_V3_LEN
            || &bytes[..8] != DELIVERY_CURSOR_MAGIC_V3
            || u16::from_be_bytes([bytes[8], bytes[9]]) != DELIVERY_WIRE_VERSION_V3
        {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
        Ok(Self {
            database_id: RelayDatabaseIdV1::new(take_fixed_digest(bytes, 10)?)?,
            scope: DeliveryScopeV3::new(
                ParticipantId(take_fixed_digest(bytes, 42)?),
                take_fixed_digest(bytes, 74)?,
                take_fixed_digest(bytes, 106)?,
            )
            .map_err(|_| ProductionRelayError::InvalidDeliveryCursor)?,
            position: u64::from_be_bytes(
                bytes[138..146]
                    .try_into()
                    .map_err(|_| ProductionRelayError::InvalidDeliveryCursor)?,
            ),
            page_digest: take_fixed_digest(bytes, 146)?,
            authenticator: take_fixed_digest(bytes, 178)?,
        })
    }
}

/// One bounded, durably pinned V3 delivery page.
#[derive(Clone, Eq, PartialEq)]
pub struct DeliveryPageV3 {
    current_cursor: DeliveryCursorV3,
    next_cursor: DeliveryCursorV3,
    has_more: bool,
    ordinals: Vec<u64>,
    envelopes: Vec<Vec<u8>>,
}

impl core::fmt::Debug for DeliveryPageV3 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DeliveryPageV3")
            .field("current_cursor", &self.current_cursor)
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .field("ordinals", &self.ordinals)
            .field("envelope_count", &self.envelopes.len())
            .field("envelopes", &"[redacted]")
            .finish()
    }
}

impl DeliveryPageV3 {
    pub const fn current_cursor(&self) -> &DeliveryCursorV3 {
        &self.current_cursor
    }

    pub const fn next_cursor(&self) -> &DeliveryCursorV3 {
        &self.next_cursor
    }

    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    pub fn envelopes(&self) -> &[Vec<u8>] {
        &self.envelopes
    }

    pub fn ordinals(&self) -> &[u64] {
        &self.ordinals
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProductionRelayError> {
        encode_delivery_page_v3(self)
    }

    pub fn decode(
        bytes: &[u8],
        limits: DeliveryPageLimitsV3,
    ) -> Result<Self, ProductionRelayError> {
        decode_delivery_page_v3(bytes, limits)
    }
}

/// Exact idempotent receipt of a durably advanced V3 cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryAckV3 {
    cursor: DeliveryCursorV3,
    digest: Digest32,
}

impl DeliveryAckV3 {
    pub const fn cursor(&self) -> &DeliveryCursorV3 {
        &self.cursor
    }

    pub fn canonical_bytes(&self) -> [u8; DELIVERY_ACK_V3_LEN] {
        let mut out = [0_u8; DELIVERY_ACK_V3_LEN];
        out[..8].copy_from_slice(DELIVERY_ACK_MAGIC_V3);
        out[8..10].copy_from_slice(&DELIVERY_WIRE_VERSION_V3.to_be_bytes());
        out[10..10 + DELIVERY_CURSOR_V3_LEN].copy_from_slice(&self.cursor.canonical_bytes());
        out[10 + DELIVERY_CURSOR_V3_LEN..].copy_from_slice(&self.digest);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProductionRelayError> {
        if bytes.len() != DELIVERY_ACK_V3_LEN
            || &bytes[..8] != DELIVERY_ACK_MAGIC_V3
            || u16::from_be_bytes([bytes[8], bytes[9]]) != DELIVERY_WIRE_VERSION_V3
        {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
        let cursor = DeliveryCursorV3::decode(&bytes[10..10 + DELIVERY_CURSOR_V3_LEN])?;
        let ack = delivery_ack_v3(cursor)?;
        if ack.digest != as_digest(&bytes[10 + DELIVERY_CURSOR_V3_LEN..])? {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
        Ok(ack)
    }
}

/// Hard page bounds selected by the production recipient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryPageLimitsV2 {
    max_items: u16,
    max_bytes: u32,
}

impl DeliveryPageLimitsV2 {
    /// Creates bounds that always permit one maximum-sized Relay envelope.
    pub fn new(max_items: u16, max_bytes: u32) -> Result<Self, ProductionRelayError> {
        if max_items == 0
            || max_items > MAX_DELIVERY_PAGE_ITEMS_V2
            || max_bytes < MAX_ENVELOPE_BYTES as u32
            || max_bytes > MAX_DELIVERY_PAGE_BYTES_V2
        {
            return Err(ProductionRelayError::InvalidDeliveryLimits);
        }
        Ok(Self {
            max_items,
            max_bytes,
        })
    }

    /// Maximum item count.
    pub const fn max_items(&self) -> u16 {
        self.max_items
    }

    /// Maximum sum of canonical envelope bytes.
    pub const fn max_bytes(&self) -> u32 {
        self.max_bytes
    }
}

/// V3 uses the same hard page bounds as V2 while changing cursor scope.
pub type DeliveryPageLimitsV3 = DeliveryPageLimitsV2;

/// Opaque, database- and recipient-bound monotonic delivery cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryCursorV2 {
    database_id: RelayDatabaseIdV1,
    recipient_id: ParticipantId,
    position: u64,
    page_digest: Digest32,
    authenticator: Digest32,
}

impl DeliveryCursorV2 {
    /// Relay database identity this cursor belongs to.
    pub const fn database_id(&self) -> RelayDatabaseIdV1 {
        self.database_id
    }

    /// Recipient this cursor belongs to.
    pub const fn recipient_id(&self) -> ParticipantId {
        self.recipient_id
    }

    /// Monotonic database position covered by this cursor.
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Exact canonical cursor bytes for durable recipient persistence.
    pub fn canonical_bytes(&self) -> [u8; DELIVERY_CURSOR_V2_LEN] {
        let mut out = [0_u8; DELIVERY_CURSOR_V2_LEN];
        let mut offset = 0_usize;
        for part in [
            DELIVERY_CURSOR_MAGIC_V2.as_slice(),
            DELIVERY_WIRE_VERSION_V2.to_be_bytes().as_slice(),
            self.database_id.as_bytes().as_slice(),
            self.recipient_id.0.as_slice(),
            self.position.to_be_bytes().as_slice(),
            self.page_digest.as_slice(),
            self.authenticator.as_slice(),
        ] {
            let end = offset + part.len();
            out[offset..end].copy_from_slice(part);
            offset = end;
        }
        out
    }

    /// Strictly decodes the fixed-width cursor. Authority validation still
    /// occurs against the database's exact acknowledged/pending state.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProductionRelayError> {
        if bytes.len() != DELIVERY_CURSOR_V2_LEN
            || &bytes[..8] != DELIVERY_CURSOR_MAGIC_V2
            || u16::from_be_bytes([bytes[8], bytes[9]]) != DELIVERY_WIRE_VERSION_V2
        {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
        let database_id = RelayDatabaseIdV1::new(take_fixed_digest(bytes, 10)?)?;
        Ok(Self {
            database_id,
            recipient_id: ParticipantId(take_fixed_digest(bytes, 42)?),
            position: u64::from_be_bytes(
                bytes[74..82]
                    .try_into()
                    .map_err(|_| ProductionRelayError::InvalidDeliveryCursor)?,
            ),
            page_digest: take_fixed_digest(bytes, 82)?,
            authenticator: take_fixed_digest(bytes, 114)?,
        })
    }
}

/// One bounded canonical page. It is durably pinned until its exact next
/// cursor is acknowledged, so a crash only causes byte-identical redelivery.
#[derive(Clone, Eq, PartialEq)]
pub struct DeliveryPageV2 {
    current_cursor: DeliveryCursorV2,
    next_cursor: DeliveryCursorV2,
    has_more: bool,
    ordinals: Vec<u64>,
    envelopes: Vec<Vec<u8>>,
}

impl core::fmt::Debug for DeliveryPageV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let retained_bytes = self
            .envelopes
            .iter()
            .try_fold(0_usize, |total, bytes| total.checked_add(bytes.len()));
        formatter
            .debug_struct("DeliveryPageV2")
            .field("current_cursor", &self.current_cursor)
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .field("ordinals", &self.ordinals)
            .field("envelope_count", &self.envelopes.len())
            .field("retained_bytes", &retained_bytes)
            .field("envelopes", &"[redacted]")
            .finish()
    }
}

impl DeliveryPageV2 {
    /// Cursor the recipient supplied.
    pub const fn current_cursor(&self) -> &DeliveryCursorV2 {
        &self.current_cursor
    }

    /// Cursor to persist locally and acknowledge only after every envelope.
    pub const fn next_cursor(&self) -> &DeliveryCursorV2 {
        &self.next_cursor
    }

    /// Whether more rows existed when this exact page was pinned.
    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    /// Exact canonical envelope bytes, bounded before allocation.
    pub fn envelopes(&self) -> &[Vec<u8>] {
        &self.envelopes
    }

    /// Monotonic Relay database ordinals paired one-for-one with envelopes.
    pub fn ordinals(&self) -> &[u64] {
        &self.ordinals
    }

    /// Canonical page bytes for a future network face.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProductionRelayError> {
        encode_delivery_page(self)
    }

    /// Strictly decodes a bounded canonical page before allocating envelope
    /// vectors. Cursor authority is still checked against durable state when
    /// the page is acknowledged.
    pub fn decode(
        bytes: &[u8],
        limits: DeliveryPageLimitsV2,
    ) -> Result<Self, ProductionRelayError> {
        decode_delivery_page(bytes, limits)
    }
}

/// Exact idempotent receipt of a durably advanced delivery cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryAckV2 {
    cursor: DeliveryCursorV2,
    digest: Digest32,
}

impl DeliveryAckV2 {
    /// Acknowledged cursor.
    pub const fn cursor(&self) -> &DeliveryCursorV2 {
        &self.cursor
    }

    /// Exact canonical acknowledgement bytes.
    pub fn canonical_bytes(&self) -> [u8; DELIVERY_ACK_V2_LEN] {
        let mut out = [0_u8; DELIVERY_ACK_V2_LEN];
        out[..8].copy_from_slice(DELIVERY_ACK_MAGIC_V2);
        out[8..10].copy_from_slice(&DELIVERY_WIRE_VERSION_V2.to_be_bytes());
        out[10..10 + DELIVERY_CURSOR_V2_LEN].copy_from_slice(&self.cursor.canonical_bytes());
        out[10 + DELIVERY_CURSOR_V2_LEN..].copy_from_slice(&self.digest);
        out
    }

    /// Strictly decodes and authenticates the fixed-width receipt.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProductionRelayError> {
        if bytes.len() != DELIVERY_ACK_V2_LEN
            || &bytes[..8] != DELIVERY_ACK_MAGIC_V2
            || u16::from_be_bytes([bytes[8], bytes[9]]) != DELIVERY_WIRE_VERSION_V2
        {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
        let cursor = DeliveryCursorV2::decode(&bytes[10..10 + DELIVERY_CURSOR_V2_LEN])?;
        let ack = delivery_ack(cursor)?;
        if ack.digest != as_digest(&bytes[10 + DELIVERY_CURSOR_V2_LEN..])? {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
        Ok(ack)
    }
}

impl RelayDatabaseConfigV1 {
    /// Creates a bounded configuration. The compiled hard ceiling remains
    /// [`MAX_STORED_ENVELOPES`].
    pub fn new(
        database_id: RelayDatabaseIdV1,
        max_envelopes: u32,
    ) -> Result<Self, ProductionRelayError> {
        if max_envelopes == 0 || max_envelopes as usize > MAX_STORED_ENVELOPES {
            return Err(ProductionRelayError::InvalidConfiguration);
        }
        Ok(Self {
            database_id,
            max_envelopes,
        })
    }

    /// Stable database identity.
    pub const fn database_id(&self) -> RelayDatabaseIdV1 {
        self.database_id
    }

    /// Configured envelope ceiling.
    pub const fn max_envelopes(&self) -> u32 {
        self.max_envelopes
    }
}

/// Redacted, fail-closed production Relay errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProductionRelayError {
    /// Configuration, path or owner-only root requirements were not met.
    #[error("invalid relay database configuration")]
    InvalidConfiguration,
    /// Explicit first creation found an existing root.
    #[error("relay database root already exists")]
    AlreadyExists,
    /// Explicit open found the retained identity but no database.
    #[error("relay database is missing")]
    DatabaseMissing,
    /// Reconstruction was requested while database state still exists.
    #[error("relay database still exists")]
    DatabasePresent,
    /// The retained root identity differs from the expected identity.
    #[error("wrong relay database identity")]
    WrongDatabaseIdentity,
    /// SQLite/filesystem/lock access failed. No underlying message is logged.
    #[error("relay storage unavailable")]
    StorageUnavailable,
    /// The database schema/version/backend is not the frozen production one.
    #[error("unsupported relay database format")]
    UnsupportedFormat,
    /// Physical or logical database validation failed.
    #[error("corrupt relay database")]
    CorruptState,
    /// Envelope codec refusal before storage.
    #[error("codec: {0}")]
    Codec(EnvelopeError),
    /// The configured envelope capacity has been reached.
    #[error("relay storage is full")]
    StorageFull,
    /// Same idempotency key, different exact canonical bytes.
    #[error("relay envelope equivocation")]
    Equivocation,
    /// The supplied authenticated batch does not match its committed digest.
    #[error("recovery batch digest mismatch")]
    RecoveryDigestMismatch,
    /// Requested delivery page bounds are outside the compiled hard limits.
    #[error("invalid relay delivery page limits")]
    InvalidDeliveryLimits,
    /// A delivery cursor is forged, stale, future, transplanted or belongs to
    /// another recipient/database.
    #[error("invalid relay delivery cursor")]
    InvalidDeliveryCursor,
    /// The confirmed delivery prefix is not a contiguous addressed flow and
    /// therefore cannot be reduced to a bounded checkpoint.
    #[error("relay delivery flow is not contiguous")]
    NonContiguousDelivery,
    /// A submission targets a flow position already removed after its durable
    /// recipient acknowledgement.
    #[error("relay flow position was already acknowledged")]
    AcknowledgedDeliveryPrefix,
}

impl From<rusqlite::Error> for ProductionRelayError {
    fn from(_: rusqlite::Error) -> Self {
        Self::StorageUnavailable
    }
}

/// Durable production store-and-forward Relay.
pub struct ProductionRelayV1 {
    connection: Connection,
    root: PathBuf,
    config: RelayDatabaseConfigV1,
    _lock: File,
}

impl core::fmt::Debug for ProductionRelayV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionRelayV1")
            .field("database_id", &self.config.database_id)
            .field("root", &"[redacted]")
            .finish()
    }
}

impl ProductionRelayV1 {
    /// Explicitly creates a brand-new empty production Relay root.
    ///
    /// This method never reuses an existing root. Process restart must call
    /// [`Self::open`], which never creates a missing database.
    #[cfg(target_os = "linux")]
    pub fn create(
        root: &Path,
        config: RelayDatabaseConfigV1,
    ) -> Result<Self, ProductionRelayError> {
        create_root(root)?;
        #[cfg(test)]
        exit_production_creation_for_test("root");
        write_identity(root, config.database_id)?;
        #[cfg(test)]
        exit_production_creation_for_test("identity");
        let lock = acquire_lock(root, true)?;
        #[cfg(test)]
        exit_production_creation_for_test("lock");
        let connection = create_database(root, config, 1, ZERO_DIGEST, true)?;
        let relay = Self {
            connection,
            root: root.to_path_buf(),
            config,
            _lock: lock,
        };
        relay.validate_integrity()?;
        Ok(relay)
    }

    /// Performs the non-mutating half of production resume planning.
    ///
    /// Economic rows, reconstruction state, foreign files, an out-of-order
    /// prefix, wrong identity/configuration, and malformed SQLite state are
    /// refused rather than classified as resumable.
    #[cfg(target_os = "linux")]
    pub fn production_creation_state(
        root: &Path,
        config: RelayDatabaseConfigV1,
    ) -> Result<ProductionRelayCreationStateV1, ProductionRelayError> {
        inspect_production_creation_state(root, config)
    }

    /// Preflights an explicitly journaled production resume without mutation.
    #[cfg(target_os = "linux")]
    pub fn preflight_resume_create_production(
        root: &Path,
        config: RelayDatabaseConfigV1,
    ) -> Result<(), ProductionRelayError> {
        inspect_production_creation_state(root, config).map(|_| ())
    }

    /// Resumes only the exact pristine prefix of an explicitly journaled
    /// production create.
    ///
    /// A missing root, empty root, published identity, published lock, empty
    /// SQLite file, rolled-back schema transaction, or exact initialized empty
    /// database may be completed. Economic rows, reconstruction/loss state,
    /// partial committed schema, extra files, wrong identity/configuration,
    /// symlinks, unsafe modes and hard-link transplants are refused.
    #[cfg(target_os = "linux")]
    pub fn resume_create_production(
        root: &Path,
        config: RelayDatabaseConfigV1,
    ) -> Result<Self, ProductionRelayError> {
        let lock = acquire_production_resume_lock(root, config.database_id)?;
        let state = inspect_locked_production_creation_state(root, config)?;
        let path = root.join(RELAY_DATABASE_FILE_NAME);
        let connection = match state {
            ProductionRelayCreationStateV1::Missing => {
                return Err(ProductionRelayError::CorruptState)
            }
            ProductionRelayCreationStateV1::Incomplete => {
                open_or_initialize_pristine_database(root, config)?
            }
            ProductionRelayCreationStateV1::InitializedPristine => {
                let connection = Connection::open_with_flags(
                    &path,
                    OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )?;
                configure_connection(&connection, &path)?;
                connection
            }
        };
        let relay = Self {
            connection,
            root: root.to_path_buf(),
            config,
            _lock: lock,
        };
        relay.validate_integrity()?;
        relay.require_pristine_creation_state()?;
        relay
            .connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")?;
        sync_directory(root)?;
        Ok(relay)
    }

    /// Non-Linux platforms cannot satisfy the owner-only retained authority.
    #[cfg(not(target_os = "linux"))]
    pub fn create(
        _root: &Path,
        _config: RelayDatabaseConfigV1,
    ) -> Result<Self, ProductionRelayError> {
        Err(ProductionRelayError::StorageUnavailable)
    }

    /// Opens an existing database after process restart.
    ///
    /// Missing files, loss markers, a wrong identity, schema drift, tamper or
    /// any incomplete reconstruction fail closed; this method never creates or
    /// migrates anything.
    #[cfg(target_os = "linux")]
    pub fn open(
        root: &Path,
        expected: RelayDatabaseConfigV1,
    ) -> Result<Self, ProductionRelayError> {
        validate_root(root)?;
        require_identity(root, expected.database_id)?;
        let lock = acquire_lock(root, false)?;
        if root
            .join(RELAY_DATABASE_LOSS_MARKER_NAME)
            .try_exists()
            .map_err(|_| ProductionRelayError::StorageUnavailable)?
        {
            return Err(ProductionRelayError::DatabaseMissing);
        }
        let path = root.join(RELAY_DATABASE_FILE_NAME);
        if !path
            .try_exists()
            .map_err(|_| ProductionRelayError::StorageUnavailable)?
        {
            return Err(ProductionRelayError::DatabaseMissing);
        }
        validate_owner_file(&path)?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection, &path)?;
        validate_database_objects(root)?;
        let relay = Self {
            connection,
            root: root.to_path_buf(),
            config: expected,
            _lock: lock,
        };
        relay.validate_integrity()?;
        Ok(relay)
    }

    /// Non-Linux platforms fail closed.
    #[cfg(not(target_os = "linux"))]
    pub fn open(
        _root: &Path,
        _expected: RelayDatabaseConfigV1,
    ) -> Result<Self, ProductionRelayError> {
        Err(ProductionRelayError::StorageUnavailable)
    }

    /// Reconstructs a missing database from one opaque authenticated batch.
    ///
    /// The retained root/identity/lock must survive, every SQLite database
    /// object must be absent, and `batch` is consumed. All rows and the final
    /// recovery digest become visible in one `BEGIN IMMEDIATE` transaction;
    /// an interrupted reconstruction remains marked incomplete and cannot be
    /// opened.
    #[cfg(target_os = "linux")]
    pub fn reconstruct(
        root: &Path,
        config: RelayDatabaseConfigV1,
        batch: AuthenticatedRecoveryBatchV1,
    ) -> Result<Self, ProductionRelayError> {
        validate_root(root)?;
        require_identity(root, config.database_id)?;
        let lock = acquire_lock(root, false)?;
        require_database_absent(root)?;
        let expected_digest = *batch.digest();
        let connection = create_database(root, config, 2, expected_digest, false)?;
        let mut relay = Self {
            connection,
            root: root.to_path_buf(),
            config,
            _lock: lock,
        };
        relay.install_recovery_batch(batch)?;
        remove_loss_marker_if_present(root, config.database_id)?;
        relay.validate_integrity()?;
        Ok(relay)
    }

    /// Non-Linux platforms fail closed.
    #[cfg(not(target_os = "linux"))]
    pub fn reconstruct(
        _root: &Path,
        _config: RelayDatabaseConfigV1,
        _batch: AuthenticatedRecoveryBatchV1,
    ) -> Result<Self, ProductionRelayError> {
        Err(ProductionRelayError::StorageUnavailable)
    }

    /// Stable public identity of this retained root.
    pub const fn database_id(&self) -> RelayDatabaseIdV1 {
        self.config.database_id
    }

    /// Number of canonical envelopes retained in the queue.
    pub fn len(&self) -> Result<usize, ProductionRelayError> {
        let count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM relay_envelopes", [], |row| row.get(0))?;
        usize::try_from(count).map_err(|_| ProductionRelayError::CorruptState)
    }

    /// Whether the durable queue is empty.
    pub fn is_empty(&self) -> Result<bool, ProductionRelayError> {
        Ok(self.len()? == 0)
    }

    /// Durably stores one canonical envelope before returning its ACK.
    ///
    /// Same key and exact bytes returns the same canonical ACK after any
    /// restart. Same key and different bytes is durably journaled as a
    /// conflict and fails closed. Payload bytes are never decoded.
    pub fn submit(&mut self, raw: &[u8]) -> Result<AckV1, ProductionRelayError> {
        self.submit_durable(raw).map(|(ack, _inserted)| ack)
    }

    /// Test-only full-history compatibility reader. Production delivery must
    /// use the bounded cursor/page/ack V2 surface below.
    #[cfg(test)]
    fn deliver_ephemeral_v1(
        &self,
        recipient: &ParticipantId,
    ) -> Result<Vec<Vec<u8>>, ProductionRelayError> {
        let mut statement = self.connection.prepare(
            "SELECT ordinal, session_id, sender_id, recipient_id, sequence_be,
                    canonical_bytes, envelope_digest, recovery_source_mask,
                    recovery_commitment, row_digest
             FROM relay_envelopes
             WHERE recipient_id = ?1
             ORDER BY ordinal ASC",
        )?;
        let rows = statement.query_map(params![recipient.0.as_slice()], row_from_sql)?;
        let mut delivered = Vec::new();
        for row in rows {
            let row = row?;
            validate_envelope_row(&self.config, &row)?;
            if row.key.recipient_id != *recipient {
                return Err(ProductionRelayError::CorruptState);
            }
            delivered.push(row.bytes);
        }
        Ok(delivered)
    }

    /// Returns the exact durable cursor the recipient must present to read its
    /// next bounded V2 page. With no prior acknowledgement this is the
    /// authenticated position-zero cursor.
    pub fn acknowledged_delivery_cursor_v2(
        &self,
        recipient: &ParticipantId,
    ) -> Result<DeliveryCursorV2, ProductionRelayError> {
        let state = load_delivery_state(&self.connection, &self.config, recipient)?;
        acknowledged_cursor(self.config.database_id, *recipient, state)
    }

    /// Pins and returns one bounded V2 page. The pending endpoint is committed
    /// before bytes are returned. Until its exact cursor is acknowledged, any
    /// retry with the same current cursor and limits returns byte-identical
    /// content and no later page can be read.
    pub fn delivery_page_v2(
        &mut self,
        recipient: &ParticipantId,
        current: &DeliveryCursorV2,
        limits: DeliveryPageLimitsV2,
    ) -> Result<DeliveryPageV2, ProductionRelayError> {
        delivery_page_transaction(
            &mut self.connection,
            &self.config,
            recipient,
            current,
            limits,
        )
    }

    /// Durably acknowledges exactly the pending page, advances the bounded
    /// per-flow checkpoints and garbage-collects only that confirmed prefix in
    /// one transaction. Repeating the current acknowledged cursor returns the
    /// same receipt without mutation.
    pub fn acknowledge_delivery_page_v2(
        &mut self,
        recipient: &ParticipantId,
        next: &DeliveryCursorV2,
    ) -> Result<DeliveryAckV2, ProductionRelayError> {
        acknowledge_delivery_transaction(&mut self.connection, &self.config, recipient, next)
    }

    /// Returns the durable cursor for one exact recipient/route/session scope.
    pub fn acknowledged_delivery_cursor_v3(
        &self,
        scope: &DeliveryScopeV3,
    ) -> Result<DeliveryCursorV3, ProductionRelayError> {
        let state_key = delivery_state_key_v3(&self.config, scope)?;
        let state = load_delivery_state_v3(&self.connection, &self.config, scope, &state_key)?;
        acknowledged_cursor_v3(self.config.database_id, *scope, state)
    }

    /// Pins one bounded page containing only envelopes in `scope`.
    pub fn delivery_page_v3(
        &mut self,
        scope: &DeliveryScopeV3,
        current: &DeliveryCursorV3,
        limits: DeliveryPageLimitsV3,
    ) -> Result<DeliveryPageV3, ProductionRelayError> {
        delivery_page_transaction_v3(&mut self.connection, &self.config, scope, current, limits)
    }

    /// Acknowledges and garbage-collects only the exact pinned V3 scope.
    pub fn acknowledge_delivery_page_v3(
        &mut self,
        scope: &DeliveryScopeV3,
        next: &DeliveryCursorV3,
    ) -> Result<DeliveryAckV3, ProductionRelayError> {
        acknowledge_delivery_transaction_v3(&mut self.connection, &self.config, scope, next)
    }

    /// Exact durable bytes under one idempotency key.
    pub fn stored_bytes(
        &self,
        key: &IdempotencyKeyV1,
    ) -> Result<Option<Vec<u8>>, ProductionRelayError> {
        self.load_envelope_row(key)
            .map(|row| row.map(|stored| stored.bytes))
    }

    /// Returns independently verifiable exact equivocation evidence, if one
    /// was durably observed for this key. Payload bytes are available only
    /// through this explicit evidence API and are redacted from errors/Debug.
    pub fn equivocation_proof(
        &self,
        key: &IdempotencyKeyV1,
    ) -> Result<Option<EquivocationProofV1>, ProductionRelayError> {
        let Some(first) = self.load_envelope_row(key)? else {
            return Ok(None);
        };
        let mut statement = self.connection.prepare(
            "SELECT ordinal, session_id, sender_id, recipient_id, sequence_be,
                    first_digest, conflicting_bytes, conflicting_digest, row_digest
             FROM relay_conflicts
             WHERE session_id = ?1 AND sender_id = ?2 AND recipient_id = ?3 AND sequence_be = ?4
             ORDER BY ordinal ASC LIMIT 1",
        )?;
        let conflict = statement
            .query_row(
                params![
                    key.session_id.as_slice(),
                    key.sender_id.0.as_slice(),
                    key.recipient_id.0.as_slice(),
                    key.sequence.to_be_bytes().as_slice(),
                ],
                conflict_from_sql,
            )
            .optional()?;
        let Some(conflict) = conflict else {
            return Ok(None);
        };
        validate_conflict_row(&self.config, &first, &conflict)?;
        Ok(Some(EquivocationProofV1 {
            key: *key,
            first: first.bytes,
            second: conflict.bytes,
        }))
    }

    pub(crate) fn submit_durable(
        &mut self,
        raw: &[u8],
    ) -> Result<(AckV1, bool), ProductionRelayError> {
        let envelope = RelayEnvelopeV1::decode(raw).map_err(ProductionRelayError::Codec)?;
        let canonical = envelope
            .canonical_bytes()
            .map_err(ProductionRelayError::Codec)?;
        if canonical.as_slice() != raw {
            return Err(ProductionRelayError::CorruptState);
        }
        let key = IdempotencyKeyV1::of(&envelope);
        let digest = envelope
            .envelope_digest()
            .map_err(ProductionRelayError::Codec)?;
        let config = self.config;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = load_envelope_row_from(&transaction, &key)?;
        if let Some(existing) = existing {
            validate_envelope_row(&config, &existing)?;
            if existing.bytes == canonical {
                transaction.commit()?;
                return Ok((
                    AckV1 {
                        key,
                        digest: existing.digest,
                    },
                    false,
                ));
            }
            persist_conflict(&transaction, &config, &existing, &canonical, digest)?;
            transaction.commit()?;
            return Err(ProductionRelayError::Equivocation);
        }
        if audit_new_flow_position(&transaction, &config, &envelope, digest)? {
            transaction.commit()?;
            return Ok((AckV1 { key, digest }, false));
        }
        let count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM relay_envelopes", [], |row| row.get(0))?;
        if count < 0 || count as u64 >= u64::from(config.max_envelopes) {
            return Err(ProductionRelayError::StorageFull);
        }
        let ordinal: i64 = transaction.query_row(
            "SELECT next_envelope_ordinal FROM relay_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let next_ordinal = ordinal
            .checked_add(1)
            .ok_or(ProductionRelayError::StorageFull)?;
        if ordinal <= 0 {
            return Err(ProductionRelayError::CorruptState);
        }
        let row_digest = envelope_row_digest(
            config.database_id,
            &key,
            &canonical,
            &digest,
            0,
            &ZERO_DIGEST,
        )?;
        transaction.execute(
            "INSERT INTO relay_envelopes
             (ordinal, session_id, sender_id, recipient_id, sequence_be,
              canonical_bytes, envelope_digest, recovery_source_mask,
              recovery_commitment, row_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9)",
            params![
                ordinal,
                key.session_id.as_slice(),
                key.sender_id.0.as_slice(),
                key.recipient_id.0.as_slice(),
                key.sequence.to_be_bytes().as_slice(),
                canonical,
                digest.as_slice(),
                ZERO_DIGEST.as_slice(),
                row_digest.as_slice(),
            ],
        )?;
        if transaction.execute(
            "UPDATE relay_meta SET next_envelope_ordinal = ?1
             WHERE singleton = 1 AND next_envelope_ordinal = ?2",
            params![next_ordinal, ordinal],
        )? != 1
        {
            return Err(ProductionRelayError::CorruptState);
        }
        transaction.commit()?;
        let persisted = self
            .load_envelope_row(&key)?
            .ok_or(ProductionRelayError::CorruptState)?;
        if persisted.bytes.as_slice() != raw || persisted.digest != digest {
            return Err(ProductionRelayError::CorruptState);
        }
        Ok((AckV1 { key, digest }, true))
    }

    fn load_envelope_row(
        &self,
        key: &IdempotencyKeyV1,
    ) -> Result<Option<StoredEnvelopeRowV1>, ProductionRelayError> {
        let row = load_envelope_row_from(&self.connection, key)?;
        if let Some(ref row) = row {
            validate_envelope_row(&self.config, row)?;
        }
        Ok(row)
    }

    fn install_recovery_batch(
        &mut self,
        batch: AuthenticatedRecoveryBatchV1,
    ) -> Result<(), ProductionRelayError> {
        let expected_digest = *batch.digest();
        let config = self.config;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (kind, stored_digest, complete): (i64, Vec<u8>, i64) = transaction.query_row(
            "SELECT creation_kind, recovery_digest, reconstruction_complete
             FROM relay_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if kind != 2
            || complete != 0
            || as_digest(&stored_digest)? != expected_digest
            || batch.entries.len() > config.max_envelopes as usize
        {
            return Err(ProductionRelayError::RecoveryDigestMismatch);
        }
        for (index, entry) in batch.entries.into_iter().enumerate() {
            insert_recovery_entry(&transaction, &config, index + 1, entry)?;
        }
        let next_ordinal = transaction
            .query_row("SELECT COUNT(*) FROM relay_envelopes", [], |row| {
                row.get::<_, i64>(0)
            })?
            .checked_add(1)
            .ok_or(ProductionRelayError::RecoveryDigestMismatch)?;
        transaction.execute(
            "UPDATE relay_meta
             SET reconstruction_complete = 1, next_envelope_ordinal = ?1
             WHERE singleton = 1",
            params![next_ordinal],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn validate_integrity(&self) -> Result<(), ProductionRelayError> {
        validate_backend_and_schema(&self.connection, &self.root, self.config)?;
        let mut statement = self.connection.prepare(
            "SELECT ordinal, session_id, sender_id, recipient_id, sequence_be,
                    canonical_bytes, envelope_digest, recovery_source_mask,
                    recovery_commitment, row_digest
             FROM relay_envelopes ORDER BY ordinal ASC",
        )?;
        let rows = statement.query_map([], row_from_sql)?;
        let mut previous_ordinal = 0_i64;
        let mut retained = BTreeMap::<IdempotencyKeyV1, StoredEnvelopeRowV1>::new();
        for row in rows {
            let row = row?;
            if row.ordinal <= previous_ordinal {
                return Err(ProductionRelayError::CorruptState);
            }
            let ordinal = row.ordinal;
            validate_envelope_row(&self.config, &row)?;
            if retained.insert(row.key, row).is_some() {
                return Err(ProductionRelayError::CorruptState);
            }
            previous_ordinal = ordinal;
        }
        if retained.len() > self.config.max_envelopes as usize {
            return Err(ProductionRelayError::CorruptState);
        }
        let next_ordinal: i64 = self.connection.query_row(
            "SELECT next_envelope_ordinal FROM relay_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if next_ordinal <= previous_ordinal {
            return Err(ProductionRelayError::CorruptState);
        }

        let mut statement = self.connection.prepare(
            "SELECT ordinal, session_id, sender_id, recipient_id, sequence_be,
                    first_digest, conflicting_bytes, conflicting_digest, row_digest
             FROM relay_conflicts ORDER BY ordinal ASC",
        )?;
        let rows = statement.query_map([], conflict_from_sql)?;
        let mut previous_conflict = 0_i64;
        for row in rows {
            let row = row?;
            if row.ordinal <= previous_conflict {
                return Err(ProductionRelayError::CorruptState);
            }
            let first = retained
                .get(&row.key)
                .ok_or(ProductionRelayError::CorruptState)?;
            validate_conflict_row(&self.config, first, &row)?;
            previous_conflict = row.ordinal;
        }
        validate_delivery_v2_integrity(&self.connection, &self.config, &retained)?;
        Ok(())
    }

    fn require_pristine_creation_state(&self) -> Result<(), ProductionRelayError> {
        require_pristine_connection(&self.connection, &self.root, self.config)
    }

    #[cfg(feature = "relay-fault-injection")]
    pub(crate) fn into_fault_parts(self) -> (Connection, PathBuf, RelayDatabaseConfigV1, File) {
        (self.connection, self.root, self.config, self._lock)
    }

    #[cfg(feature = "relay-fault-injection")]
    pub(crate) fn fault_root_clone(&self) -> PathBuf {
        self.root.clone()
    }
}

struct StoredEnvelopeRowV1 {
    ordinal: i64,
    key: IdempotencyKeyV1,
    bytes: Vec<u8>,
    digest: Digest32,
    source_mask: u8,
    source_commitment: Digest32,
    row_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingDeliveryPageV2 {
    start_position: u64,
    end_position: u64,
    item_count: u16,
    byte_count: u32,
    page_digest: Digest32,
    authenticator: Digest32,
    has_more: bool,
    limits: DeliveryPageLimitsV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeliveryStateRowV2 {
    acknowledged_position: u64,
    acknowledged_page_digest: Digest32,
    acknowledged_authenticator: Digest32,
    pending: Option<PendingDeliveryPageV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
struct DeliveryFlowKeyV2 {
    session_id: Digest32,
    sender_id: ParticipantId,
    recipient_id: ParticipantId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeliveryFlowCheckpointV2 {
    sequence: u64,
    context_digest: Digest32,
    terminal_digest: Digest32,
    terminal_bytes_digest: Digest32,
}

struct DeliveryFlowSqlRowV2 {
    sequence: Vec<u8>,
    context_digest: Vec<u8>,
    terminal_digest: Vec<u8>,
    terminal_bytes_digest: Vec<u8>,
    row_digest: Vec<u8>,
}

struct RelayMetaValidationRowV2 {
    schema_version: i64,
    database_id: Vec<u8>,
    max_envelopes: i64,
    creation_kind: i64,
    recovery_digest: Vec<u8>,
    complete: i64,
    schema_digest: Vec<u8>,
    next_envelope_ordinal: i64,
}

fn take_fixed_digest(bytes: &[u8], offset: usize) -> Result<Digest32, ProductionRelayError> {
    bytes
        .get(offset..offset + 32)
        .ok_or(ProductionRelayError::InvalidDeliveryCursor)?
        .try_into()
        .map_err(|_| ProductionRelayError::InvalidDeliveryCursor)
}

fn delivery_state_key_v3(
    config: &RelayDatabaseConfigV1,
    scope: &DeliveryScopeV3,
) -> Result<ParticipantId, ProductionRelayError> {
    Ok(ParticipantId(digest_parts(
        DELIVERY_STATE_KEY_DOMAIN_V3,
        &[
            config.database_id.as_bytes().as_slice(),
            scope.recipient_id.0.as_slice(),
            scope.route_id.as_slice(),
            scope.session_id.as_slice(),
        ],
    )?))
}

fn initial_delivery_cursor_v3(
    database_id: RelayDatabaseIdV1,
    scope: DeliveryScopeV3,
) -> Result<DeliveryCursorV3, ProductionRelayError> {
    let authenticator = digest_parts(
        DELIVERY_CURSOR_DOMAIN_V3,
        &[
            database_id.as_bytes().as_slice(),
            scope.recipient_id.0.as_slice(),
            scope.route_id.as_slice(),
            scope.session_id.as_slice(),
            &0_u64.to_be_bytes(),
            ZERO_DIGEST.as_slice(),
            ZERO_DIGEST.as_slice(),
        ],
    )?;
    Ok(DeliveryCursorV3 {
        database_id,
        scope,
        position: 0,
        page_digest: ZERO_DIGEST,
        authenticator,
    })
}

fn acknowledged_cursor_v3(
    database_id: RelayDatabaseIdV1,
    scope: DeliveryScopeV3,
    state: Option<DeliveryStateRowV2>,
) -> Result<DeliveryCursorV3, ProductionRelayError> {
    match state {
        None => initial_delivery_cursor_v3(database_id, scope),
        Some(state) => Ok(DeliveryCursorV3 {
            database_id,
            scope,
            position: state.acknowledged_position,
            page_digest: state.acknowledged_page_digest,
            authenticator: state.acknowledged_authenticator,
        }),
    }
}

fn next_delivery_cursor_v3(
    current: DeliveryCursorV3,
    end_position: u64,
    item_count: u16,
    byte_count: u32,
    page_digest: Digest32,
    has_more: bool,
) -> Result<DeliveryCursorV3, ProductionRelayError> {
    if end_position <= current.position || item_count == 0 {
        return Err(ProductionRelayError::CorruptState);
    }
    let authenticator = digest_parts(
        DELIVERY_CURSOR_DOMAIN_V3,
        &[
            current.database_id.as_bytes().as_slice(),
            current.scope.recipient_id.0.as_slice(),
            current.scope.route_id.as_slice(),
            current.scope.session_id.as_slice(),
            &current.position.to_be_bytes(),
            current.authenticator.as_slice(),
            &end_position.to_be_bytes(),
            &item_count.to_be_bytes(),
            &byte_count.to_be_bytes(),
            page_digest.as_slice(),
            &[u8::from(has_more)],
        ],
    )?;
    Ok(DeliveryCursorV3 {
        database_id: current.database_id,
        scope: current.scope,
        position: end_position,
        page_digest,
        authenticator,
    })
}

fn delivery_ack_v3(cursor: DeliveryCursorV3) -> Result<DeliveryAckV3, ProductionRelayError> {
    let cursor_bytes = cursor.canonical_bytes();
    Ok(DeliveryAckV3 {
        digest: digest_parts(DELIVERY_ACK_DOMAIN_V3, &[cursor_bytes.as_slice()])?,
        cursor,
    })
}

fn page_digest_values_v3(
    current: &DeliveryCursorV3,
    ordinals: &[u64],
    envelopes: &[Vec<u8>],
    has_more: bool,
) -> Result<Digest32, ProductionRelayError> {
    if ordinals.len() != envelopes.len() {
        return Err(ProductionRelayError::CorruptState);
    }
    let mut hasher = Blake2bVar::new(32).map_err(|_| ProductionRelayError::CorruptState)?;
    hasher.update(DELIVERY_PAGE_DOMAIN_V3);
    hasher.update(&current.canonical_bytes());
    hasher.update(
        &u16::try_from(envelopes.len())
            .map_err(|_| ProductionRelayError::CorruptState)?
            .to_be_bytes(),
    );
    hasher.update(&[u8::from(has_more)]);
    let mut previous = current.position;
    for (ordinal, raw) in ordinals.iter().zip(envelopes) {
        if *ordinal <= previous || raw.len() > MAX_ENVELOPE_BYTES {
            return Err(ProductionRelayError::CorruptState);
        }
        previous = *ordinal;
        hasher.update(&ordinal.to_be_bytes());
        hasher.update(
            &u32::try_from(raw.len())
                .map_err(|_| ProductionRelayError::CorruptState)?
                .to_be_bytes(),
        );
        hasher.update(raw);
    }
    let mut digest = ZERO_DIGEST;
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| ProductionRelayError::CorruptState)?;
    Ok(digest)
}

fn page_digest_v3(
    current: &DeliveryCursorV3,
    rows: &[StoredEnvelopeRowV1],
    has_more: bool,
) -> Result<Digest32, ProductionRelayError> {
    let ordinals = rows
        .iter()
        .map(|row| u64::try_from(row.ordinal).map_err(|_| ProductionRelayError::CorruptState))
        .collect::<Result<Vec<_>, _>>()?;
    let envelopes = rows.iter().map(|row| row.bytes.clone()).collect::<Vec<_>>();
    page_digest_values_v3(current, &ordinals, &envelopes, has_more)
}

fn encode_delivery_page_v3(page: &DeliveryPageV3) -> Result<Vec<u8>, ProductionRelayError> {
    if page.current_cursor.database_id != page.next_cursor.database_id
        || page.current_cursor.scope != page.next_cursor.scope
        || page.ordinals.len() != page.envelopes.len()
        || page.envelopes.len() > MAX_DELIVERY_PAGE_ITEMS_V2 as usize
    {
        return Err(ProductionRelayError::CorruptState);
    }
    let byte_count = page.envelopes.iter().try_fold(0_usize, |total, raw| {
        if raw.len() > MAX_ENVELOPE_BYTES {
            return Err(ProductionRelayError::CorruptState);
        }
        total
            .checked_add(raw.len())
            .ok_or(ProductionRelayError::CorruptState)
    })?;
    if byte_count > MAX_DELIVERY_PAGE_BYTES_V2 as usize {
        return Err(ProductionRelayError::CorruptState);
    }
    let capacity = 8_usize
        .checked_add(2 + DELIVERY_CURSOR_V3_LEN * 2 + 1 + 2 + 4)
        .and_then(|value| value.checked_add(page.envelopes.len() * 12))
        .and_then(|value| value.checked_add(byte_count))
        .ok_or(ProductionRelayError::CorruptState)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(DELIVERY_PAGE_MAGIC_V3);
    out.extend_from_slice(&DELIVERY_WIRE_VERSION_V3.to_be_bytes());
    out.extend_from_slice(&page.current_cursor.canonical_bytes());
    out.extend_from_slice(&page.next_cursor.canonical_bytes());
    out.push(u8::from(page.has_more));
    out.extend_from_slice(
        &u16::try_from(page.envelopes.len())
            .map_err(|_| ProductionRelayError::CorruptState)?
            .to_be_bytes(),
    );
    out.extend_from_slice(
        &u32::try_from(byte_count)
            .map_err(|_| ProductionRelayError::CorruptState)?
            .to_be_bytes(),
    );
    let mut previous = page.current_cursor.position;
    for (ordinal, raw) in page.ordinals.iter().zip(&page.envelopes) {
        if *ordinal <= previous || *ordinal > page.next_cursor.position {
            return Err(ProductionRelayError::CorruptState);
        }
        previous = *ordinal;
        out.extend_from_slice(&ordinal.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(raw.len())
                .map_err(|_| ProductionRelayError::CorruptState)?
                .to_be_bytes(),
        );
        out.extend_from_slice(raw);
    }
    if (page.envelopes.is_empty() && (page.next_cursor != page.current_cursor || page.has_more))
        || (!page.envelopes.is_empty() && previous != page.next_cursor.position)
        || out.len() != capacity
    {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(out)
}

fn decode_delivery_page_v3(
    bytes: &[u8],
    limits: DeliveryPageLimitsV3,
) -> Result<DeliveryPageV3, ProductionRelayError> {
    const HEADER: usize = 8 + 2 + DELIVERY_CURSOR_V3_LEN * 2 + 1 + 2 + 4;
    let hard_max = HEADER
        .checked_add(usize::from(limits.max_items) * 12)
        .and_then(|value| value.checked_add(limits.max_bytes as usize))
        .ok_or(ProductionRelayError::InvalidDeliveryLimits)?;
    if bytes.len() < HEADER || bytes.len() > hard_max {
        return Err(ProductionRelayError::InvalidDeliveryLimits);
    }
    if &bytes[..8] != DELIVERY_PAGE_MAGIC_V3
        || u16::from_be_bytes([bytes[8], bytes[9]]) != DELIVERY_WIRE_VERSION_V3
    {
        return Err(ProductionRelayError::InvalidDeliveryCursor);
    }
    let current = DeliveryCursorV3::decode(&bytes[10..10 + DELIVERY_CURSOR_V3_LEN])?;
    let next_offset = 10 + DELIVERY_CURSOR_V3_LEN;
    let next = DeliveryCursorV3::decode(&bytes[next_offset..next_offset + DELIVERY_CURSOR_V3_LEN])?;
    let mut offset = next_offset + DELIVERY_CURSOR_V3_LEN;
    let has_more = match bytes[offset] {
        0 => false,
        1 => true,
        _ => return Err(ProductionRelayError::InvalidDeliveryCursor),
    };
    offset += 1;
    let item_count = u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .map_err(|_| ProductionRelayError::InvalidDeliveryCursor)?,
    );
    offset += 2;
    let declared_bytes = u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .map_err(|_| ProductionRelayError::InvalidDeliveryCursor)?,
    );
    offset += 4;
    if item_count > limits.max_items || declared_bytes > limits.max_bytes {
        return Err(ProductionRelayError::InvalidDeliveryLimits);
    }
    let exact_length = HEADER
        .checked_add(usize::from(item_count) * 12)
        .and_then(|value| value.checked_add(declared_bytes as usize))
        .ok_or(ProductionRelayError::InvalidDeliveryLimits)?;
    if bytes.len() != exact_length {
        return Err(ProductionRelayError::InvalidDeliveryCursor);
    }
    let mut ordinals = Vec::with_capacity(usize::from(item_count));
    let mut envelopes = Vec::with_capacity(usize::from(item_count));
    let mut actual_bytes = 0_u32;
    let mut previous = current.position;
    for _ in 0..item_count {
        let ordinal = u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| ProductionRelayError::InvalidDeliveryCursor)?,
        );
        offset += 8;
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| ProductionRelayError::InvalidDeliveryCursor)?,
        );
        offset += 4;
        if ordinal <= previous || length as usize > MAX_ENVELOPE_BYTES {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
        previous = ordinal;
        actual_bytes = actual_bytes
            .checked_add(length)
            .ok_or(ProductionRelayError::InvalidDeliveryLimits)?;
        if actual_bytes > declared_bytes {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
        let end = offset
            .checked_add(length as usize)
            .ok_or(ProductionRelayError::InvalidDeliveryCursor)?;
        let raw = bytes
            .get(offset..end)
            .ok_or(ProductionRelayError::InvalidDeliveryCursor)?;
        let envelope = RelayEnvelopeV1::decode(raw).map_err(ProductionRelayError::Codec)?;
        if envelope.recipient_id != current.scope.recipient_id
            || envelope.route_id != current.scope.route_id
            || envelope.session_id != current.scope.session_id
            || envelope
                .canonical_bytes()
                .map_err(ProductionRelayError::Codec)?
                .as_slice()
                != raw
        {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
        ordinals.push(ordinal);
        envelopes.push(raw.to_vec());
        offset = end;
    }
    if offset != bytes.len()
        || actual_bytes != declared_bytes
        || current.database_id != next.database_id
        || current.scope != next.scope
    {
        return Err(ProductionRelayError::InvalidDeliveryCursor);
    }
    let page = DeliveryPageV3 {
        current_cursor: current,
        next_cursor: next,
        has_more,
        ordinals,
        envelopes,
    };
    let digest = page_digest_values_v3(
        &page.current_cursor,
        &page.ordinals,
        &page.envelopes,
        has_more,
    )?;
    if page.envelopes.is_empty() {
        if page.next_cursor != page.current_cursor || has_more {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
    } else {
        let rebuilt = next_delivery_cursor_v3(
            page.current_cursor,
            *page
                .ordinals
                .last()
                .ok_or(ProductionRelayError::InvalidDeliveryCursor)?,
            item_count,
            actual_bytes,
            digest,
            has_more,
        )?;
        if rebuilt != page.next_cursor {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
    }
    Ok(page)
}

fn initial_delivery_cursor(
    database_id: RelayDatabaseIdV1,
    recipient_id: ParticipantId,
) -> Result<DeliveryCursorV2, ProductionRelayError> {
    let authenticator = digest_parts(
        DELIVERY_CURSOR_DOMAIN,
        &[
            database_id.as_bytes().as_slice(),
            recipient_id.0.as_slice(),
            &0_u64.to_be_bytes(),
            ZERO_DIGEST.as_slice(),
            ZERO_DIGEST.as_slice(),
        ],
    )?;
    Ok(DeliveryCursorV2 {
        database_id,
        recipient_id,
        position: 0,
        page_digest: ZERO_DIGEST,
        authenticator,
    })
}

fn acknowledged_cursor(
    database_id: RelayDatabaseIdV1,
    recipient_id: ParticipantId,
    state: Option<DeliveryStateRowV2>,
) -> Result<DeliveryCursorV2, ProductionRelayError> {
    match state {
        None => initial_delivery_cursor(database_id, recipient_id),
        Some(state) => Ok(DeliveryCursorV2 {
            database_id,
            recipient_id,
            position: state.acknowledged_position,
            page_digest: state.acknowledged_page_digest,
            authenticator: state.acknowledged_authenticator,
        }),
    }
}

fn next_delivery_cursor(
    current: DeliveryCursorV2,
    end_position: u64,
    item_count: u16,
    byte_count: u32,
    page_digest: Digest32,
    has_more: bool,
) -> Result<DeliveryCursorV2, ProductionRelayError> {
    if end_position <= current.position || item_count == 0 {
        return Err(ProductionRelayError::CorruptState);
    }
    let authenticator = digest_parts(
        DELIVERY_CURSOR_DOMAIN,
        &[
            current.database_id.as_bytes().as_slice(),
            current.recipient_id.0.as_slice(),
            &current.position.to_be_bytes(),
            current.authenticator.as_slice(),
            &end_position.to_be_bytes(),
            &item_count.to_be_bytes(),
            &byte_count.to_be_bytes(),
            page_digest.as_slice(),
            &[u8::from(has_more)],
        ],
    )?;
    Ok(DeliveryCursorV2 {
        database_id: current.database_id,
        recipient_id: current.recipient_id,
        position: end_position,
        page_digest,
        authenticator,
    })
}

fn delivery_ack(cursor: DeliveryCursorV2) -> Result<DeliveryAckV2, ProductionRelayError> {
    let cursor_bytes = cursor.canonical_bytes();
    Ok(DeliveryAckV2 {
        cursor,
        digest: digest_parts(DELIVERY_ACK_DOMAIN, &[cursor_bytes.as_slice()])?,
    })
}

fn encode_delivery_page(page: &DeliveryPageV2) -> Result<Vec<u8>, ProductionRelayError> {
    if page.current_cursor.database_id != page.next_cursor.database_id
        || page.current_cursor.recipient_id != page.next_cursor.recipient_id
        || page.ordinals.len() != page.envelopes.len()
        || page.envelopes.len() > MAX_DELIVERY_PAGE_ITEMS_V2 as usize
    {
        return Err(ProductionRelayError::CorruptState);
    }
    let byte_count = page.envelopes.iter().try_fold(0_usize, |total, raw| {
        if raw.len() > MAX_ENVELOPE_BYTES {
            return Err(ProductionRelayError::CorruptState);
        }
        total
            .checked_add(raw.len())
            .ok_or(ProductionRelayError::CorruptState)
    })?;
    if byte_count > MAX_DELIVERY_PAGE_BYTES_V2 as usize {
        return Err(ProductionRelayError::CorruptState);
    }
    let capacity = 8_usize
        .checked_add(2)
        .and_then(|v| v.checked_add(DELIVERY_CURSOR_V2_LEN * 2))
        .and_then(|v| v.checked_add(1 + 2 + 4))
        .and_then(|v| v.checked_add(page.envelopes.len() * 12))
        .and_then(|v| v.checked_add(byte_count))
        .ok_or(ProductionRelayError::CorruptState)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(DELIVERY_PAGE_MAGIC_V2);
    out.extend_from_slice(&DELIVERY_WIRE_VERSION_V2.to_be_bytes());
    out.extend_from_slice(&page.current_cursor.canonical_bytes());
    out.extend_from_slice(&page.next_cursor.canonical_bytes());
    out.push(u8::from(page.has_more));
    out.extend_from_slice(
        &u16::try_from(page.envelopes.len())
            .map_err(|_| ProductionRelayError::CorruptState)?
            .to_be_bytes(),
    );
    out.extend_from_slice(
        &u32::try_from(byte_count)
            .map_err(|_| ProductionRelayError::CorruptState)?
            .to_be_bytes(),
    );
    let mut previous = page.current_cursor.position;
    for (ordinal, raw) in page.ordinals.iter().zip(&page.envelopes) {
        if *ordinal <= previous || *ordinal > page.next_cursor.position {
            return Err(ProductionRelayError::CorruptState);
        }
        previous = *ordinal;
        out.extend_from_slice(&ordinal.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(raw.len())
                .map_err(|_| ProductionRelayError::CorruptState)?
                .to_be_bytes(),
        );
        out.extend_from_slice(raw);
    }
    if (page.envelopes.is_empty() && (page.next_cursor != page.current_cursor || page.has_more))
        || (!page.envelopes.is_empty() && previous != page.next_cursor.position)
    {
        return Err(ProductionRelayError::CorruptState);
    }
    if out.len() != capacity {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(out)
}

fn decode_delivery_page(
    bytes: &[u8],
    limits: DeliveryPageLimitsV2,
) -> Result<DeliveryPageV2, ProductionRelayError> {
    const HEADER: usize = 8 + 2 + DELIVERY_CURSOR_V2_LEN * 2 + 1 + 2 + 4;
    let hard_max = HEADER
        .checked_add(usize::from(limits.max_items) * 12)
        .and_then(|value| value.checked_add(limits.max_bytes as usize))
        .ok_or(ProductionRelayError::InvalidDeliveryLimits)?;
    if bytes.len() < HEADER || bytes.len() > hard_max {
        return Err(ProductionRelayError::InvalidDeliveryLimits);
    }
    if &bytes[..8] != DELIVERY_PAGE_MAGIC_V2
        || u16::from_be_bytes([bytes[8], bytes[9]]) != DELIVERY_WIRE_VERSION_V2
    {
        return Err(ProductionRelayError::InvalidDeliveryCursor);
    }
    let current = DeliveryCursorV2::decode(&bytes[10..10 + DELIVERY_CURSOR_V2_LEN])?;
    let next_offset = 10 + DELIVERY_CURSOR_V2_LEN;
    let next = DeliveryCursorV2::decode(&bytes[next_offset..next_offset + DELIVERY_CURSOR_V2_LEN])?;
    let mut offset = next_offset + DELIVERY_CURSOR_V2_LEN;
    let has_more = match bytes[offset] {
        0 => false,
        1 => true,
        _ => return Err(ProductionRelayError::InvalidDeliveryCursor),
    };
    offset += 1;
    let item_count = u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .map_err(|_| ProductionRelayError::InvalidDeliveryCursor)?,
    );
    offset += 2;
    let declared_bytes = u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .map_err(|_| ProductionRelayError::InvalidDeliveryCursor)?,
    );
    offset += 4;
    if item_count > limits.max_items || declared_bytes > limits.max_bytes {
        return Err(ProductionRelayError::InvalidDeliveryLimits);
    }
    let exact_length = HEADER
        .checked_add(usize::from(item_count) * 12)
        .and_then(|value| value.checked_add(declared_bytes as usize))
        .ok_or(ProductionRelayError::InvalidDeliveryLimits)?;
    if bytes.len() != exact_length {
        return Err(ProductionRelayError::InvalidDeliveryCursor);
    }
    let mut ordinals = Vec::with_capacity(usize::from(item_count));
    let mut envelopes = Vec::with_capacity(usize::from(item_count));
    let mut actual_bytes = 0_u32;
    for _ in 0..item_count {
        let ordinal = u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| ProductionRelayError::InvalidDeliveryCursor)?,
        );
        offset += 8;
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| ProductionRelayError::InvalidDeliveryCursor)?,
        );
        offset += 4;
        if length as usize > MAX_ENVELOPE_BYTES {
            return Err(ProductionRelayError::InvalidDeliveryLimits);
        }
        actual_bytes = actual_bytes
            .checked_add(length)
            .ok_or(ProductionRelayError::InvalidDeliveryLimits)?;
        if actual_bytes > declared_bytes {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
        let end = offset
            .checked_add(length as usize)
            .ok_or(ProductionRelayError::InvalidDeliveryCursor)?;
        let raw = bytes
            .get(offset..end)
            .ok_or(ProductionRelayError::InvalidDeliveryCursor)?;
        let envelope = RelayEnvelopeV1::decode(raw).map_err(ProductionRelayError::Codec)?;
        if envelope
            .canonical_bytes()
            .map_err(ProductionRelayError::Codec)?
            != raw
        {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
        ordinals.push(ordinal);
        envelopes.push(raw.to_vec());
        offset = end;
    }
    if offset != bytes.len()
        || actual_bytes != declared_bytes
        || current.database_id != next.database_id
        || current.recipient_id != next.recipient_id
    {
        return Err(ProductionRelayError::InvalidDeliveryCursor);
    }
    let page = DeliveryPageV2 {
        current_cursor: current,
        next_cursor: next,
        has_more,
        ordinals,
        envelopes,
    };
    let digest = page_digest_values(
        &page.current_cursor,
        &page.ordinals,
        &page.envelopes,
        page.has_more,
    )?;
    if page.envelopes.is_empty() {
        if page.next_cursor != page.current_cursor || page.has_more {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
    } else {
        let rebuilt = next_delivery_cursor(
            page.current_cursor,
            *page
                .ordinals
                .last()
                .ok_or(ProductionRelayError::InvalidDeliveryCursor)?,
            item_count,
            actual_bytes,
            digest,
            has_more,
        )?;
        if rebuilt != page.next_cursor {
            return Err(ProductionRelayError::InvalidDeliveryCursor);
        }
    }
    Ok(page)
}

fn page_digest_values(
    current: &DeliveryCursorV2,
    ordinals: &[u64],
    envelopes: &[Vec<u8>],
    has_more: bool,
) -> Result<Digest32, ProductionRelayError> {
    if ordinals.len() != envelopes.len() {
        return Err(ProductionRelayError::CorruptState);
    }
    let mut hasher = Blake2bVar::new(32).map_err(|_| ProductionRelayError::CorruptState)?;
    hasher.update(DELIVERY_PAGE_DOMAIN);
    hasher.update(&current.canonical_bytes());
    hasher.update(
        &u16::try_from(envelopes.len())
            .map_err(|_| ProductionRelayError::CorruptState)?
            .to_be_bytes(),
    );
    hasher.update(&[u8::from(has_more)]);
    let mut previous = current.position;
    for (ordinal, raw) in ordinals.iter().zip(envelopes) {
        if *ordinal <= previous || raw.len() > MAX_ENVELOPE_BYTES {
            return Err(ProductionRelayError::CorruptState);
        }
        previous = *ordinal;
        hasher.update(&ordinal.to_be_bytes());
        hasher.update(
            &u32::try_from(raw.len())
                .map_err(|_| ProductionRelayError::CorruptState)?
                .to_be_bytes(),
        );
        hasher.update(raw);
    }
    let mut digest = ZERO_DIGEST;
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| ProductionRelayError::CorruptState)?;
    Ok(digest)
}

fn page_digest(
    current: &DeliveryCursorV2,
    rows: &[StoredEnvelopeRowV1],
    has_more: bool,
) -> Result<Digest32, ProductionRelayError> {
    let ordinals = rows
        .iter()
        .map(|row| u64::try_from(row.ordinal).map_err(|_| ProductionRelayError::CorruptState))
        .collect::<Result<Vec<_>, _>>()?;
    let envelopes = rows.iter().map(|row| row.bytes.clone()).collect::<Vec<_>>();
    page_digest_values(current, &ordinals, &envelopes, has_more)
}

fn encode_delivery_state(state: DeliveryStateRowV2) -> [u8; 166] {
    let mut out = [0_u8; 166];
    out[..8].copy_from_slice(&state.acknowledged_position.to_be_bytes());
    out[8..40].copy_from_slice(&state.acknowledged_page_digest);
    out[40..72].copy_from_slice(&state.acknowledged_authenticator);
    if let Some(pending) = state.pending {
        out[72] = 1;
        out[73..81].copy_from_slice(&pending.start_position.to_be_bytes());
        out[81..89].copy_from_slice(&pending.end_position.to_be_bytes());
        out[89..91].copy_from_slice(&pending.item_count.to_be_bytes());
        out[91..95].copy_from_slice(&pending.byte_count.to_be_bytes());
        out[95..127].copy_from_slice(&pending.page_digest);
        out[127..159].copy_from_slice(&pending.authenticator);
        out[159] = u8::from(pending.has_more);
        out[160..162].copy_from_slice(&pending.limits.max_items.to_be_bytes());
        out[162..166].copy_from_slice(&pending.limits.max_bytes.to_be_bytes());
    }
    out
}

fn decode_delivery_state(bytes: &[u8]) -> Result<DeliveryStateRowV2, ProductionRelayError> {
    if bytes.len() != 166 {
        return Err(ProductionRelayError::CorruptState);
    }
    let acknowledged_position = u64::from_be_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| ProductionRelayError::CorruptState)?,
    );
    let acknowledged_page_digest = as_digest(&bytes[8..40])?;
    let acknowledged_authenticator = as_digest(&bytes[40..72])?;
    let pending = match bytes[72] {
        0 if bytes[73..].iter().all(|byte| *byte == 0) => None,
        1 => {
            let start_position = u64::from_be_bytes(
                bytes[73..81]
                    .try_into()
                    .map_err(|_| ProductionRelayError::CorruptState)?,
            );
            let end_position = u64::from_be_bytes(
                bytes[81..89]
                    .try_into()
                    .map_err(|_| ProductionRelayError::CorruptState)?,
            );
            let item_count = u16::from_be_bytes(
                bytes[89..91]
                    .try_into()
                    .map_err(|_| ProductionRelayError::CorruptState)?,
            );
            let byte_count = u32::from_be_bytes(
                bytes[91..95]
                    .try_into()
                    .map_err(|_| ProductionRelayError::CorruptState)?,
            );
            let limits = DeliveryPageLimitsV2::new(
                u16::from_be_bytes(
                    bytes[160..162]
                        .try_into()
                        .map_err(|_| ProductionRelayError::CorruptState)?,
                ),
                u32::from_be_bytes(
                    bytes[162..166]
                        .try_into()
                        .map_err(|_| ProductionRelayError::CorruptState)?,
                ),
            )
            .map_err(|_| ProductionRelayError::CorruptState)?;
            if start_position != acknowledged_position
                || end_position <= start_position
                || item_count == 0
                || item_count > limits.max_items
                || byte_count > limits.max_bytes
                || !matches!(bytes[159], 0 | 1)
            {
                return Err(ProductionRelayError::CorruptState);
            }
            Some(PendingDeliveryPageV2 {
                start_position,
                end_position,
                item_count,
                byte_count,
                page_digest: as_digest(&bytes[95..127])?,
                authenticator: as_digest(&bytes[127..159])?,
                has_more: bytes[159] == 1,
                limits,
            })
        }
        _ => return Err(ProductionRelayError::CorruptState),
    };
    Ok(DeliveryStateRowV2 {
        acknowledged_position,
        acknowledged_page_digest,
        acknowledged_authenticator,
        pending,
    })
}

fn delivery_state_row_digest(
    config: &RelayDatabaseConfigV1,
    recipient: &ParticipantId,
    state_bytes: &[u8; 166],
) -> Result<Digest32, ProductionRelayError> {
    digest_parts(
        DELIVERY_STATE_DOMAIN,
        &[
            config.database_id.as_bytes().as_slice(),
            recipient.0.as_slice(),
            state_bytes.as_slice(),
        ],
    )
}

fn load_delivery_state(
    connection: &Connection,
    config: &RelayDatabaseConfigV1,
    recipient: &ParticipantId,
) -> Result<Option<DeliveryStateRowV2>, ProductionRelayError> {
    let row: Option<(Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT state_bytes, row_digest FROM relay_delivery_state WHERE recipient_id = ?1",
            params![recipient.0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((state_bytes, row_digest)) = row else {
        return Ok(None);
    };
    let fixed: [u8; 166] = state_bytes
        .try_into()
        .map_err(|_| ProductionRelayError::CorruptState)?;
    if as_digest(&row_digest)? != delivery_state_row_digest(config, recipient, &fixed)? {
        return Err(ProductionRelayError::CorruptState);
    }
    let state = decode_delivery_state(&fixed)?;
    let cursor = acknowledged_cursor(config.database_id, *recipient, Some(state))?;
    if cursor.authenticator == ZERO_DIGEST
        || state
            .pending
            .is_some_and(|pending| pending.authenticator == ZERO_DIGEST)
    {
        return Err(ProductionRelayError::CorruptState);
    }
    if state.acknowledged_position == 0
        && cursor != initial_delivery_cursor(config.database_id, *recipient)?
    {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(Some(state))
}

fn persist_delivery_state(
    transaction: &rusqlite::Transaction<'_>,
    config: &RelayDatabaseConfigV1,
    recipient: &ParticipantId,
    state: DeliveryStateRowV2,
) -> Result<(), ProductionRelayError> {
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM relay_delivery_state WHERE recipient_id = ?1)",
        params![recipient.0.as_slice()],
        |row| row.get(0),
    )?;
    if exists == 0 {
        let count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM relay_delivery_state", [], |row| {
                row.get(0)
            })?;
        if count < 0 || count as u64 >= u64::from(config.max_envelopes) {
            return Err(ProductionRelayError::StorageFull);
        }
    } else if exists != 1 {
        return Err(ProductionRelayError::CorruptState);
    }
    let bytes = encode_delivery_state(state);
    let digest = delivery_state_row_digest(config, recipient, &bytes)?;
    transaction.execute(
        "INSERT INTO relay_delivery_state (recipient_id, state_bytes, row_digest)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(recipient_id) DO UPDATE
         SET state_bytes = excluded.state_bytes, row_digest = excluded.row_digest",
        params![recipient.0.as_slice(), bytes.as_slice(), digest.as_slice()],
    )?;
    Ok(())
}

fn delivery_scope_row_digest_v3(
    config: &RelayDatabaseConfigV1,
    state_key: &ParticipantId,
    scope: &DeliveryScopeV3,
) -> Result<Digest32, ProductionRelayError> {
    digest_parts(
        DELIVERY_SCOPE_ROW_DOMAIN_V3,
        &[
            config.database_id.as_bytes().as_slice(),
            state_key.0.as_slice(),
            scope.recipient_id.0.as_slice(),
            scope.route_id.as_slice(),
            scope.session_id.as_slice(),
        ],
    )
}

type DeliveryScopeRowV3 = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn validate_or_persist_delivery_scope_v3(
    transaction: &rusqlite::Transaction<'_>,
    config: &RelayDatabaseConfigV1,
    state_key: &ParticipantId,
    scope: &DeliveryScopeV3,
) -> Result<(), ProductionRelayError> {
    let row: Option<DeliveryScopeRowV3> = transaction
        .query_row(
            "SELECT recipient_id, route_id, session_id, row_digest
             FROM relay_delivery_scopes_v3 WHERE state_key = ?1",
            params![state_key.0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let digest = delivery_scope_row_digest_v3(config, state_key, scope)?;
    if let Some((recipient, route, session, row_digest)) = row {
        if as_digest(&recipient)? != scope.recipient_id.0
            || as_digest(&route)? != scope.route_id
            || as_digest(&session)? != scope.session_id
            || as_digest(&row_digest)? != digest
        {
            return Err(ProductionRelayError::CorruptState);
        }
        return Ok(());
    }
    let occupied: i64 = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM relay_delivery_state WHERE recipient_id = ?1
         )",
        params![state_key.0.as_slice()],
        |row| row.get(0),
    )?;
    if occupied != 0 {
        return Err(ProductionRelayError::CorruptState);
    }
    transaction.execute(
        "INSERT INTO relay_delivery_scopes_v3
         (state_key, recipient_id, route_id, session_id, row_digest)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            state_key.0.as_slice(),
            scope.recipient_id.0.as_slice(),
            scope.route_id.as_slice(),
            scope.session_id.as_slice(),
            digest.as_slice(),
        ],
    )?;
    Ok(())
}

fn load_delivery_state_v3(
    connection: &Connection,
    config: &RelayDatabaseConfigV1,
    scope: &DeliveryScopeV3,
    state_key: &ParticipantId,
) -> Result<Option<DeliveryStateRowV2>, ProductionRelayError> {
    let mapping: Option<DeliveryScopeRowV3> = connection
        .query_row(
            "SELECT recipient_id, route_id, session_id, row_digest
             FROM relay_delivery_scopes_v3 WHERE state_key = ?1",
            params![state_key.0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let state = load_delivery_state_raw(connection, config, state_key)?;
    match (mapping, state) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(ProductionRelayError::CorruptState),
        (Some(mapping), Some(state)) => {
            let (recipient, route, session, row_digest) = mapping;
            if as_digest(&recipient)? != scope.recipient_id.0
                || as_digest(&route)? != scope.route_id
                || as_digest(&session)? != scope.session_id
                || as_digest(&row_digest)?
                    != delivery_scope_row_digest_v3(config, state_key, scope)?
            {
                return Err(ProductionRelayError::CorruptState);
            }
            let cursor = acknowledged_cursor_v3(config.database_id, *scope, Some(state))?;
            if cursor.authenticator == ZERO_DIGEST
                || state
                    .pending
                    .is_some_and(|pending| pending.authenticator == ZERO_DIGEST)
                || (state.acknowledged_position == 0
                    && cursor != initial_delivery_cursor_v3(config.database_id, *scope)?)
            {
                return Err(ProductionRelayError::CorruptState);
            }
            Ok(Some(state))
        }
    }
}

fn load_delivery_state_raw(
    connection: &Connection,
    config: &RelayDatabaseConfigV1,
    state_key: &ParticipantId,
) -> Result<Option<DeliveryStateRowV2>, ProductionRelayError> {
    let row: Option<(Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT state_bytes, row_digest FROM relay_delivery_state WHERE recipient_id = ?1",
            params![state_key.0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((state_bytes, row_digest)) = row else {
        return Ok(None);
    };
    let fixed: [u8; 166] = state_bytes
        .try_into()
        .map_err(|_| ProductionRelayError::CorruptState)?;
    if as_digest(&row_digest)? != delivery_state_row_digest(config, state_key, &fixed)? {
        return Err(ProductionRelayError::CorruptState);
    }
    decode_delivery_state(&fixed).map(Some)
}

fn envelope_in_delivery_scope_v3(
    row: &StoredEnvelopeRowV1,
    scope: &DeliveryScopeV3,
) -> Result<bool, ProductionRelayError> {
    let envelope =
        RelayEnvelopeV1::decode(&row.bytes).map_err(|_| ProductionRelayError::CorruptState)?;
    if envelope.session_id != row.key.session_id
        || envelope.recipient_id != row.key.recipient_id
        || envelope.sender_id != row.key.sender_id
    {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(envelope.recipient_id == scope.recipient_id
        && envelope.route_id == scope.route_id
        && envelope.session_id == scope.session_id)
}

fn load_delivery_page_rows_v3(
    connection: &Connection,
    config: &RelayDatabaseConfigV1,
    scope: &DeliveryScopeV3,
    start_position: u64,
    end_position: u64,
) -> Result<Vec<StoredEnvelopeRowV1>, ProductionRelayError> {
    let start = i64::try_from(start_position).map_err(|_| ProductionRelayError::CorruptState)?;
    let end = i64::try_from(end_position).map_err(|_| ProductionRelayError::CorruptState)?;
    let mut statement = connection.prepare(
        "SELECT ordinal, session_id, sender_id, recipient_id, sequence_be,
                canonical_bytes, envelope_digest, recovery_source_mask,
                recovery_commitment, row_digest
         FROM relay_envelopes
         WHERE recipient_id = ?1 AND session_id = ?2
           AND ordinal > ?3 AND ordinal <= ?4
         ORDER BY ordinal ASC",
    )?;
    let rows = statement.query_map(
        params![
            scope.recipient_id.0.as_slice(),
            scope.session_id.as_slice(),
            start,
            end
        ],
        row_from_sql,
    )?;
    let mut selected = Vec::new();
    for row in rows {
        let row = row?;
        validate_envelope_row(config, &row)?;
        if envelope_in_delivery_scope_v3(&row, scope)? {
            selected.push(row);
        }
    }
    Ok(selected)
}

fn delivery_page_from_pending_v3(
    connection: &Connection,
    config: &RelayDatabaseConfigV1,
    scope: &DeliveryScopeV3,
    current: DeliveryCursorV3,
    pending: PendingDeliveryPageV2,
) -> Result<DeliveryPageV3, ProductionRelayError> {
    let rows = load_delivery_page_rows_v3(
        connection,
        config,
        scope,
        pending.start_position,
        pending.end_position,
    )?;
    let byte_count = rows.iter().try_fold(0_u32, |total, row| {
        total
            .checked_add(
                u32::try_from(row.bytes.len()).map_err(|_| ProductionRelayError::CorruptState)?,
            )
            .ok_or(ProductionRelayError::CorruptState)
    })?;
    if rows.len() != usize::from(pending.item_count)
        || byte_count != pending.byte_count
        || page_digest_v3(&current, &rows, pending.has_more)? != pending.page_digest
    {
        return Err(ProductionRelayError::CorruptState);
    }
    let next = next_delivery_cursor_v3(
        current,
        pending.end_position,
        pending.item_count,
        pending.byte_count,
        pending.page_digest,
        pending.has_more,
    )?;
    if next.authenticator != pending.authenticator {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(DeliveryPageV3 {
        current_cursor: current,
        next_cursor: next,
        has_more: pending.has_more,
        ordinals: rows
            .iter()
            .map(|row| u64::try_from(row.ordinal).map_err(|_| ProductionRelayError::CorruptState))
            .collect::<Result<Vec<_>, _>>()?,
        envelopes: rows.into_iter().map(|row| row.bytes).collect(),
    })
}

fn load_delivery_page_rows(
    connection: &Connection,
    config: &RelayDatabaseConfigV1,
    recipient: &ParticipantId,
    start_position: u64,
    end_position: u64,
) -> Result<Vec<StoredEnvelopeRowV1>, ProductionRelayError> {
    let start = i64::try_from(start_position).map_err(|_| ProductionRelayError::CorruptState)?;
    let end = i64::try_from(end_position).map_err(|_| ProductionRelayError::CorruptState)?;
    let mut statement = connection.prepare(
        "SELECT ordinal, session_id, sender_id, recipient_id, sequence_be,
                canonical_bytes, envelope_digest, recovery_source_mask,
                recovery_commitment, row_digest
         FROM relay_envelopes
         WHERE recipient_id = ?1 AND ordinal > ?2 AND ordinal <= ?3
         ORDER BY ordinal ASC",
    )?;
    let mut rows_out = Vec::new();
    let rows = statement.query_map(params![recipient.0.as_slice(), start, end], row_from_sql)?;
    for row in rows {
        let row = row?;
        validate_envelope_row(config, &row)?;
        if row.key.recipient_id != *recipient {
            return Err(ProductionRelayError::CorruptState);
        }
        rows_out.push(row);
    }
    Ok(rows_out)
}

fn delivery_page_from_pending(
    connection: &Connection,
    config: &RelayDatabaseConfigV1,
    recipient: &ParticipantId,
    current: DeliveryCursorV2,
    pending: PendingDeliveryPageV2,
) -> Result<DeliveryPageV2, ProductionRelayError> {
    let rows = load_delivery_page_rows(
        connection,
        config,
        recipient,
        pending.start_position,
        pending.end_position,
    )?;
    let byte_count = rows.iter().try_fold(0_u32, |total, row| {
        total
            .checked_add(
                u32::try_from(row.bytes.len()).map_err(|_| ProductionRelayError::CorruptState)?,
            )
            .ok_or(ProductionRelayError::CorruptState)
    })?;
    if rows.len() != usize::from(pending.item_count)
        || byte_count != pending.byte_count
        || page_digest(&current, &rows, pending.has_more)? != pending.page_digest
    {
        return Err(ProductionRelayError::CorruptState);
    }
    let next = next_delivery_cursor(
        current,
        pending.end_position,
        pending.item_count,
        pending.byte_count,
        pending.page_digest,
        pending.has_more,
    )?;
    if next.authenticator != pending.authenticator {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(DeliveryPageV2 {
        current_cursor: current,
        next_cursor: next,
        has_more: pending.has_more,
        ordinals: rows
            .iter()
            .map(|row| u64::try_from(row.ordinal).map_err(|_| ProductionRelayError::CorruptState))
            .collect::<Result<Vec<_>, _>>()?,
        envelopes: rows.into_iter().map(|row| row.bytes).collect(),
    })
}

fn delivery_page_transaction_v3(
    connection: &mut Connection,
    config: &RelayDatabaseConfigV1,
    scope: &DeliveryScopeV3,
    current: &DeliveryCursorV3,
    limits: DeliveryPageLimitsV3,
) -> Result<DeliveryPageV3, ProductionRelayError> {
    if current.database_id != config.database_id || current.scope != *scope {
        return Err(ProductionRelayError::InvalidDeliveryCursor);
    }
    let state_key = delivery_state_key_v3(config, scope)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let state = load_delivery_state_v3(&transaction, config, scope, &state_key)?;
    let expected = acknowledged_cursor_v3(config.database_id, *scope, state)?;
    if *current != expected {
        return Err(ProductionRelayError::InvalidDeliveryCursor);
    }
    if let Some(pending) = state.and_then(|state| state.pending) {
        if pending.limits != limits {
            return Err(ProductionRelayError::InvalidDeliveryLimits);
        }
        let page = delivery_page_from_pending_v3(&transaction, config, scope, expected, pending)?;
        transaction.commit()?;
        return Ok(page);
    }

    let start =
        i64::try_from(current.position).map_err(|_| ProductionRelayError::InvalidDeliveryCursor)?;
    let mut statement = transaction.prepare(
        "SELECT ordinal, session_id, sender_id, recipient_id, sequence_be,
                canonical_bytes, envelope_digest, recovery_source_mask,
                recovery_commitment, row_digest
         FROM relay_envelopes
         WHERE recipient_id = ?1 AND session_id = ?2 AND ordinal > ?3
         ORDER BY ordinal ASC",
    )?;
    let candidates = statement.query_map(
        params![
            scope.recipient_id.0.as_slice(),
            scope.session_id.as_slice(),
            start
        ],
        row_from_sql,
    )?;
    let mut rows = Vec::with_capacity(usize::from(limits.max_items));
    let mut byte_count = 0_u32;
    let mut has_more = false;
    for row in candidates {
        let row = row?;
        validate_envelope_row(config, &row)?;
        if !envelope_in_delivery_scope_v3(&row, scope)? {
            continue;
        }
        let length =
            u32::try_from(row.bytes.len()).map_err(|_| ProductionRelayError::CorruptState)?;
        let next_bytes = byte_count
            .checked_add(length)
            .ok_or(ProductionRelayError::CorruptState)?;
        if rows.len() == usize::from(limits.max_items) || next_bytes > limits.max_bytes {
            has_more = true;
            break;
        }
        byte_count = next_bytes;
        rows.push(row);
    }
    drop(statement);
    if rows.is_empty() {
        transaction.commit()?;
        return Ok(DeliveryPageV3 {
            current_cursor: expected,
            next_cursor: expected,
            has_more: false,
            ordinals: Vec::new(),
            envelopes: Vec::new(),
        });
    }
    let item_count = u16::try_from(rows.len()).map_err(|_| ProductionRelayError::CorruptState)?;
    let end_position = u64::try_from(
        rows.last()
            .ok_or(ProductionRelayError::CorruptState)?
            .ordinal,
    )
    .map_err(|_| ProductionRelayError::CorruptState)?;
    let digest = page_digest_v3(&expected, &rows, has_more)?;
    let next = next_delivery_cursor_v3(
        expected,
        end_position,
        item_count,
        byte_count,
        digest,
        has_more,
    )?;
    let pending = PendingDeliveryPageV2 {
        start_position: expected.position,
        end_position,
        item_count,
        byte_count,
        page_digest: digest,
        authenticator: next.authenticator,
        has_more,
        limits,
    };
    validate_or_persist_delivery_scope_v3(&transaction, config, &state_key, scope)?;
    persist_delivery_state(
        &transaction,
        config,
        &state_key,
        DeliveryStateRowV2 {
            acknowledged_position: expected.position,
            acknowledged_page_digest: expected.page_digest,
            acknowledged_authenticator: expected.authenticator,
            pending: Some(pending),
        },
    )?;
    let page = DeliveryPageV3 {
        current_cursor: expected,
        next_cursor: next,
        has_more,
        ordinals: rows
            .iter()
            .map(|row| u64::try_from(row.ordinal).map_err(|_| ProductionRelayError::CorruptState))
            .collect::<Result<Vec<_>, _>>()?,
        envelopes: rows.into_iter().map(|row| row.bytes).collect(),
    };
    transaction.commit()?;
    Ok(page)
}

fn delivery_page_transaction(
    connection: &mut Connection,
    config: &RelayDatabaseConfigV1,
    recipient: &ParticipantId,
    current: &DeliveryCursorV2,
    limits: DeliveryPageLimitsV2,
) -> Result<DeliveryPageV2, ProductionRelayError> {
    if current.database_id != config.database_id || current.recipient_id != *recipient {
        return Err(ProductionRelayError::InvalidDeliveryCursor);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let state = load_delivery_state(&transaction, config, recipient)?;
    let expected = acknowledged_cursor(config.database_id, *recipient, state)?;
    if *current != expected {
        return Err(ProductionRelayError::InvalidDeliveryCursor);
    }
    if let Some(pending) = state.and_then(|state| state.pending) {
        if pending.limits != limits {
            return Err(ProductionRelayError::InvalidDeliveryLimits);
        }
        let page = delivery_page_from_pending(&transaction, config, recipient, expected, pending)?;
        transaction.commit()?;
        return Ok(page);
    }

    let start =
        i64::try_from(current.position).map_err(|_| ProductionRelayError::InvalidDeliveryCursor)?;
    let query_limit = i64::from(limits.max_items) + 1;
    let mut statement = transaction.prepare(
        "SELECT ordinal, length(canonical_bytes)
         FROM relay_envelopes
         WHERE recipient_id = ?1 AND ordinal > ?2
         ORDER BY ordinal ASC LIMIT ?3",
    )?;
    let lengths = statement
        .query_map(params![recipient.0.as_slice(), start, query_limit], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?;
    let mut end = None;
    let mut item_count = 0_u16;
    let mut byte_count = 0_u32;
    let mut saw_unselected = false;
    for length in lengths {
        let (ordinal, length) = length?;
        let length = u32::try_from(length).map_err(|_| ProductionRelayError::CorruptState)?;
        if length > MAX_ENVELOPE_BYTES as u32 {
            return Err(ProductionRelayError::CorruptState);
        }
        let Some(next_bytes) = byte_count.checked_add(length) else {
            return Err(ProductionRelayError::CorruptState);
        };
        if item_count == limits.max_items || next_bytes > limits.max_bytes {
            saw_unselected = true;
            break;
        }
        if ordinal <= start {
            return Err(ProductionRelayError::CorruptState);
        }
        end = Some(ordinal);
        item_count += 1;
        byte_count = next_bytes;
    }
    drop(statement);
    let Some(end) = end else {
        transaction.commit()?;
        return Ok(DeliveryPageV2 {
            current_cursor: expected,
            next_cursor: expected,
            has_more: false,
            ordinals: Vec::new(),
            envelopes: Vec::new(),
        });
    };
    let has_more = saw_unselected
        || transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM relay_envelopes
                 WHERE recipient_id = ?1 AND ordinal > ?2
             )",
            params![recipient.0.as_slice(), end],
            |row| row.get::<_, i64>(0),
        )? != 0;
    let end_u64 = u64::try_from(end).map_err(|_| ProductionRelayError::CorruptState)?;
    let rows = load_delivery_page_rows(&transaction, config, recipient, current.position, end_u64)?;
    if rows.len() != usize::from(item_count) {
        return Err(ProductionRelayError::CorruptState);
    }
    let digest = page_digest(&expected, &rows, has_more)?;
    let next = next_delivery_cursor(expected, end_u64, item_count, byte_count, digest, has_more)?;
    let pending = PendingDeliveryPageV2 {
        start_position: expected.position,
        end_position: end_u64,
        item_count,
        byte_count,
        page_digest: digest,
        authenticator: next.authenticator,
        has_more,
        limits,
    };
    persist_delivery_state(
        &transaction,
        config,
        recipient,
        DeliveryStateRowV2 {
            acknowledged_position: expected.position,
            acknowledged_page_digest: expected.page_digest,
            acknowledged_authenticator: expected.authenticator,
            pending: Some(pending),
        },
    )?;
    let page = DeliveryPageV2 {
        current_cursor: expected,
        next_cursor: next,
        has_more,
        ordinals: rows
            .iter()
            .map(|row| u64::try_from(row.ordinal).map_err(|_| ProductionRelayError::CorruptState))
            .collect::<Result<Vec<_>, _>>()?,
        envelopes: rows.into_iter().map(|row| row.bytes).collect(),
    };
    transaction.commit()?;
    Ok(page)
}

fn delivery_flow_key(envelope: &RelayEnvelopeV1) -> DeliveryFlowKeyV2 {
    DeliveryFlowKeyV2 {
        session_id: envelope.session_id,
        sender_id: envelope.sender_id,
        recipient_id: envelope.recipient_id,
    }
}

fn delivery_flow_context_digest(
    envelope: &RelayEnvelopeV1,
) -> Result<Digest32, ProductionRelayError> {
    let role = match envelope.sender_role {
        crate::SenderRoleV1::Initiator => 1_u8,
        crate::SenderRoleV1::Solver => 2_u8,
        crate::SenderRoleV1::Observer => 3_u8,
    };
    digest_parts(
        DELIVERY_FLOW_DOMAIN,
        &[
            envelope.network_id.as_slice(),
            envelope.session_id.as_slice(),
            envelope.route_id.as_slice(),
            envelope.sender_id.0.as_slice(),
            envelope.recipient_id.0.as_slice(),
            &[role],
            envelope.roster_snapshot.as_slice(),
            &envelope.policy_version.to_be_bytes(),
        ],
    )
}

fn delivery_flow_row_digest(
    config: &RelayDatabaseConfigV1,
    key: &DeliveryFlowKeyV2,
    checkpoint: &DeliveryFlowCheckpointV2,
) -> Result<Digest32, ProductionRelayError> {
    digest_parts(
        DELIVERY_FLOW_DOMAIN,
        &[
            config.database_id.as_bytes().as_slice(),
            key.session_id.as_slice(),
            key.sender_id.0.as_slice(),
            key.recipient_id.0.as_slice(),
            &checkpoint.sequence.to_be_bytes(),
            checkpoint.context_digest.as_slice(),
            checkpoint.terminal_digest.as_slice(),
            checkpoint.terminal_bytes_digest.as_slice(),
        ],
    )
}

fn exact_envelope_bytes_digest(
    envelope: &RelayEnvelopeV1,
) -> Result<Digest32, ProductionRelayError> {
    let bytes = envelope
        .canonical_bytes()
        .map_err(ProductionRelayError::Codec)?;
    digest_parts(DELIVERY_EXACT_BYTES_DOMAIN, &[bytes.as_slice()])
}

fn load_flow_checkpoint(
    connection: &Connection,
    config: &RelayDatabaseConfigV1,
    key: &DeliveryFlowKeyV2,
) -> Result<Option<DeliveryFlowCheckpointV2>, ProductionRelayError> {
    let row: Option<DeliveryFlowSqlRowV2> = connection
        .query_row(
            "SELECT sequence_be, context_digest, terminal_digest,
                    terminal_bytes_digest, row_digest
             FROM relay_delivery_flows
             WHERE session_id = ?1 AND sender_id = ?2 AND recipient_id = ?3",
            params![
                key.session_id.as_slice(),
                key.sender_id.0.as_slice(),
                key.recipient_id.0.as_slice()
            ],
            |row| {
                Ok(DeliveryFlowSqlRowV2 {
                    sequence: row.get(0)?,
                    context_digest: row.get(1)?,
                    terminal_digest: row.get(2)?,
                    terminal_bytes_digest: row.get(3)?,
                    row_digest: row.get(4)?,
                })
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let checkpoint = DeliveryFlowCheckpointV2 {
        sequence: u64::from_be_bytes(
            row.sequence
                .try_into()
                .map_err(|_| ProductionRelayError::CorruptState)?,
        ),
        context_digest: as_digest(&row.context_digest)?,
        terminal_digest: as_digest(&row.terminal_digest)?,
        terminal_bytes_digest: as_digest(&row.terminal_bytes_digest)?,
    };
    if checkpoint.context_digest == ZERO_DIGEST
        || checkpoint.terminal_digest == ZERO_DIGEST
        || checkpoint.terminal_bytes_digest == ZERO_DIGEST
        || as_digest(&row.row_digest)? != delivery_flow_row_digest(config, key, &checkpoint)?
    {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(Some(checkpoint))
}

fn persist_flow_checkpoint(
    transaction: &rusqlite::Transaction<'_>,
    config: &RelayDatabaseConfigV1,
    key: &DeliveryFlowKeyV2,
    checkpoint: &DeliveryFlowCheckpointV2,
) -> Result<(), ProductionRelayError> {
    let digest = delivery_flow_row_digest(config, key, checkpoint)?;
    transaction.execute(
        "INSERT INTO relay_delivery_flows
         (session_id, sender_id, recipient_id, sequence_be, context_digest,
          terminal_digest, terminal_bytes_digest, row_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(session_id, sender_id, recipient_id) DO UPDATE SET
           sequence_be = excluded.sequence_be,
           context_digest = excluded.context_digest,
           terminal_digest = excluded.terminal_digest,
           terminal_bytes_digest = excluded.terminal_bytes_digest,
           row_digest = excluded.row_digest",
        params![
            key.session_id.as_slice(),
            key.sender_id.0.as_slice(),
            key.recipient_id.0.as_slice(),
            checkpoint.sequence.to_be_bytes().as_slice(),
            checkpoint.context_digest.as_slice(),
            checkpoint.terminal_digest.as_slice(),
            checkpoint.terminal_bytes_digest.as_slice(),
            digest.as_slice(),
        ],
    )?;
    Ok(())
}

fn advance_flow_checkpoint(
    prior: Option<DeliveryFlowCheckpointV2>,
    envelope: &RelayEnvelopeV1,
    digest: Digest32,
) -> Result<DeliveryFlowCheckpointV2, ProductionRelayError> {
    let context_digest = delivery_flow_context_digest(envelope)?;
    match prior {
        None => {
            if envelope.sequence != 0 || envelope.previous_transcript_hash != ZERO_DIGEST {
                return Err(ProductionRelayError::NonContiguousDelivery);
            }
        }
        Some(prior) => {
            if envelope.sequence
                != prior
                    .sequence
                    .checked_add(1)
                    .ok_or(ProductionRelayError::NonContiguousDelivery)?
                || envelope.previous_transcript_hash != prior.terminal_digest
                || context_digest != prior.context_digest
            {
                return Err(ProductionRelayError::NonContiguousDelivery);
            }
        }
    }
    Ok(DeliveryFlowCheckpointV2 {
        sequence: envelope.sequence,
        context_digest,
        terminal_digest: digest,
        terminal_bytes_digest: exact_envelope_bytes_digest(envelope)?,
    })
}

fn audit_new_flow_position(
    transaction: &rusqlite::Transaction<'_>,
    config: &RelayDatabaseConfigV1,
    candidate: &RelayEnvelopeV1,
    candidate_digest: Digest32,
) -> Result<bool, ProductionRelayError> {
    let key = delivery_flow_key(candidate);
    let checkpoint = load_flow_checkpoint(transaction, config, &key)?;
    if let Some(checkpoint) = checkpoint {
        if candidate.sequence < checkpoint.sequence {
            return Err(ProductionRelayError::AcknowledgedDeliveryPrefix);
        }
        if candidate.sequence == checkpoint.sequence {
            if candidate_digest == checkpoint.terminal_digest
                && exact_envelope_bytes_digest(candidate)? == checkpoint.terminal_bytes_digest
                && delivery_flow_context_digest(candidate)? == checkpoint.context_digest
            {
                return Ok(true);
            }
            return Err(ProductionRelayError::Equivocation);
        }
    }
    let mut latest = checkpoint;
    let mut statement = transaction.prepare(
        "SELECT ordinal, session_id, sender_id, recipient_id, sequence_be,
                canonical_bytes, envelope_digest, recovery_source_mask,
                recovery_commitment, row_digest
         FROM relay_envelopes
         WHERE session_id = ?1 AND sender_id = ?2 AND recipient_id = ?3
         ORDER BY ordinal ASC",
    )?;
    let rows = statement.query_map(
        params![
            key.session_id.as_slice(),
            key.sender_id.0.as_slice(),
            key.recipient_id.0.as_slice()
        ],
        row_from_sql,
    )?;
    let mut active = false;
    for row in rows {
        let row = row?;
        validate_envelope_row(config, &row)?;
        let envelope =
            RelayEnvelopeV1::decode(&row.bytes).map_err(|_| ProductionRelayError::CorruptState)?;
        latest = Some(advance_flow_checkpoint(latest, &envelope, row.digest)?);
        active = true;
    }
    drop(statement);
    if !active && checkpoint.is_none() {
        let flow_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM (
                 SELECT session_id, sender_id, recipient_id FROM relay_delivery_flows
                 UNION
                 SELECT session_id, sender_id, recipient_id FROM relay_envelopes
             )",
            [],
            |row| row.get(0),
        )?;
        if flow_count < 0 || flow_count as u64 >= u64::from(config.max_envelopes) {
            return Err(ProductionRelayError::StorageFull);
        }
    }
    advance_flow_checkpoint(latest, candidate, candidate_digest)?;
    Ok(false)
}

fn acknowledge_delivery_transaction(
    connection: &mut Connection,
    config: &RelayDatabaseConfigV1,
    recipient: &ParticipantId,
    next: &DeliveryCursorV2,
) -> Result<DeliveryAckV2, ProductionRelayError> {
    if next.database_id != config.database_id || next.recipient_id != *recipient {
        return Err(ProductionRelayError::InvalidDeliveryCursor);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let state = load_delivery_state(&transaction, config, recipient)?;
    let current = acknowledged_cursor(config.database_id, *recipient, state)?;
    if *next == current {
        let ack = delivery_ack(current)?;
        transaction.commit()?;
        return Ok(ack);
    }
    let pending = state
        .and_then(|state| state.pending)
        .ok_or(ProductionRelayError::InvalidDeliveryCursor)?;
    let page = delivery_page_from_pending(&transaction, config, recipient, current, pending)?;
    if *page.next_cursor() != *next {
        return Err(ProductionRelayError::InvalidDeliveryCursor);
    }
    let rows = load_delivery_page_rows(
        &transaction,
        config,
        recipient,
        pending.start_position,
        pending.end_position,
    )?;
    let mut advanced = BTreeMap::<DeliveryFlowKeyV2, DeliveryFlowCheckpointV2>::new();
    for row in &rows {
        let envelope =
            RelayEnvelopeV1::decode(&row.bytes).map_err(|_| ProductionRelayError::CorruptState)?;
        let key = delivery_flow_key(&envelope);
        let prior = match advanced.get(&key).copied() {
            Some(checkpoint) => Some(checkpoint),
            None => load_flow_checkpoint(&transaction, config, &key)?,
        };
        advanced.insert(key, advance_flow_checkpoint(prior, &envelope, row.digest)?);
    }
    let existing_flows: i64 =
        transaction.query_row("SELECT COUNT(*) FROM relay_delivery_flows", [], |row| {
            row.get(0)
        })?;
    let new_flows = advanced.keys().try_fold(0_i64, |count, key| {
        if load_flow_checkpoint(&transaction, config, key)?.is_some() {
            Ok(count)
        } else {
            count
                .checked_add(1)
                .ok_or(ProductionRelayError::StorageFull)
        }
    })?;
    if existing_flows < 0
        || existing_flows
            .checked_add(new_flows)
            .map_or(true, |total| total as u64 > u64::from(config.max_envelopes))
    {
        return Err(ProductionRelayError::StorageFull);
    }
    for (key, checkpoint) in advanced {
        persist_flow_checkpoint(&transaction, config, &key, &checkpoint)?;
    }
    transaction.execute(
        "DELETE FROM relay_conflicts
         WHERE EXISTS (
             SELECT 1 FROM relay_envelopes AS envelope
             WHERE envelope.session_id = relay_conflicts.session_id
               AND envelope.sender_id = relay_conflicts.sender_id
               AND envelope.recipient_id = relay_conflicts.recipient_id
               AND envelope.sequence_be = relay_conflicts.sequence_be
               AND envelope.recipient_id = ?1
               AND envelope.ordinal <= ?2
         )",
        params![
            recipient.0.as_slice(),
            i64::try_from(pending.end_position).map_err(|_| ProductionRelayError::CorruptState)?
        ],
    )?;
    transaction.execute(
        "DELETE FROM relay_envelopes WHERE recipient_id = ?1 AND ordinal <= ?2",
        params![
            recipient.0.as_slice(),
            i64::try_from(pending.end_position).map_err(|_| ProductionRelayError::CorruptState)?
        ],
    )?;
    persist_delivery_state(
        &transaction,
        config,
        recipient,
        DeliveryStateRowV2 {
            acknowledged_position: next.position,
            acknowledged_page_digest: next.page_digest,
            acknowledged_authenticator: next.authenticator,
            pending: None,
        },
    )?;
    let ack = delivery_ack(*next)?;
    transaction.commit()?;
    Ok(ack)
}

fn acknowledge_delivery_transaction_v3(
    connection: &mut Connection,
    config: &RelayDatabaseConfigV1,
    scope: &DeliveryScopeV3,
    next: &DeliveryCursorV3,
) -> Result<DeliveryAckV3, ProductionRelayError> {
    if next.database_id != config.database_id || next.scope != *scope {
        return Err(ProductionRelayError::InvalidDeliveryCursor);
    }
    let state_key = delivery_state_key_v3(config, scope)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let state = load_delivery_state_v3(&transaction, config, scope, &state_key)?;
    let current = acknowledged_cursor_v3(config.database_id, *scope, state)?;
    if *next == current {
        let ack = delivery_ack_v3(current)?;
        transaction.commit()?;
        return Ok(ack);
    }
    let pending = state
        .and_then(|state| state.pending)
        .ok_or(ProductionRelayError::InvalidDeliveryCursor)?;
    let page = delivery_page_from_pending_v3(&transaction, config, scope, current, pending)?;
    if *page.next_cursor() != *next {
        return Err(ProductionRelayError::InvalidDeliveryCursor);
    }
    let rows = load_delivery_page_rows_v3(
        &transaction,
        config,
        scope,
        pending.start_position,
        pending.end_position,
    )?;
    let mut advanced = BTreeMap::<DeliveryFlowKeyV2, DeliveryFlowCheckpointV2>::new();
    for row in &rows {
        let envelope =
            RelayEnvelopeV1::decode(&row.bytes).map_err(|_| ProductionRelayError::CorruptState)?;
        let key = delivery_flow_key(&envelope);
        let prior = match advanced.get(&key).copied() {
            Some(checkpoint) => Some(checkpoint),
            None => load_flow_checkpoint(&transaction, config, &key)?,
        };
        advanced.insert(key, advance_flow_checkpoint(prior, &envelope, row.digest)?);
    }
    let existing_flows: i64 =
        transaction.query_row("SELECT COUNT(*) FROM relay_delivery_flows", [], |row| {
            row.get(0)
        })?;
    let new_flows = advanced.keys().try_fold(0_i64, |count, key| {
        if load_flow_checkpoint(&transaction, config, key)?.is_some() {
            Ok(count)
        } else {
            count
                .checked_add(1)
                .ok_or(ProductionRelayError::StorageFull)
        }
    })?;
    if existing_flows < 0
        || existing_flows
            .checked_add(new_flows)
            .map_or(true, |total| total as u64 > u64::from(config.max_envelopes))
    {
        return Err(ProductionRelayError::StorageFull);
    }
    for (key, checkpoint) in advanced {
        persist_flow_checkpoint(&transaction, config, &key, &checkpoint)?;
    }
    for row in &rows {
        transaction.execute(
            "DELETE FROM relay_conflicts
             WHERE session_id = ?1 AND sender_id = ?2 AND recipient_id = ?3
               AND sequence_be = ?4",
            params![
                row.key.session_id.as_slice(),
                row.key.sender_id.0.as_slice(),
                row.key.recipient_id.0.as_slice(),
                row.key.sequence.to_be_bytes().as_slice(),
            ],
        )?;
        if transaction.execute(
            "DELETE FROM relay_envelopes
             WHERE ordinal = ?1 AND session_id = ?2 AND recipient_id = ?3",
            params![
                row.ordinal,
                scope.session_id.as_slice(),
                scope.recipient_id.0.as_slice()
            ],
        )? != 1
        {
            return Err(ProductionRelayError::CorruptState);
        }
    }
    validate_or_persist_delivery_scope_v3(&transaction, config, &state_key, scope)?;
    persist_delivery_state(
        &transaction,
        config,
        &state_key,
        DeliveryStateRowV2 {
            acknowledged_position: next.position,
            acknowledged_page_digest: next.page_digest,
            acknowledged_authenticator: next.authenticator,
            pending: None,
        },
    )?;
    let ack = delivery_ack_v3(*next)?;
    transaction.commit()?;
    Ok(ack)
}

fn validate_delivery_v2_integrity(
    connection: &Connection,
    config: &RelayDatabaseConfigV1,
    retained: &BTreeMap<IdempotencyKeyV1, StoredEnvelopeRowV1>,
) -> Result<(), ProductionRelayError> {
    let mut state_statement = connection
        .prepare("SELECT recipient_id FROM relay_delivery_state ORDER BY recipient_id ASC")?;
    let state_rows = state_statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut state_count = 0_usize;
    for recipient in state_rows {
        let recipient = ParticipantId(as_digest(&recipient?)?);
        let is_v3: i64 = connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM relay_delivery_scopes_v3 WHERE state_key = ?1
             )",
            params![recipient.0.as_slice()],
            |row| row.get(0),
        )?;
        if is_v3 == 1 {
            state_count = state_count
                .checked_add(1)
                .ok_or(ProductionRelayError::CorruptState)?;
            continue;
        }
        if is_v3 != 0 {
            return Err(ProductionRelayError::CorruptState);
        }
        let state = load_delivery_state(connection, config, &recipient)?
            .ok_or(ProductionRelayError::CorruptState)?;
        let current = acknowledged_cursor(config.database_id, recipient, Some(state))?;
        if retained
            .values()
            .any(|row| row.key.recipient_id == recipient && row.ordinal as u64 <= current.position)
        {
            return Err(ProductionRelayError::CorruptState);
        }
        if let Some(pending) = state.pending {
            delivery_page_from_pending(connection, config, &recipient, current, pending)?;
        }
        state_count = state_count
            .checked_add(1)
            .ok_or(ProductionRelayError::CorruptState)?;
    }
    drop(state_statement);
    if state_count > config.max_envelopes as usize {
        return Err(ProductionRelayError::CorruptState);
    }

    let mut scope_statement = connection.prepare(
        "SELECT state_key, recipient_id, route_id, session_id
         FROM relay_delivery_scopes_v3 ORDER BY state_key ASC",
    )?;
    let scope_rows = scope_statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
        ))
    })?;
    let mut scope_count = 0_usize;
    for scope_row in scope_rows {
        let (state_key, recipient, route, session) = scope_row?;
        let scope = DeliveryScopeV3::new(
            ParticipantId(as_digest(&recipient)?),
            as_digest(&route)?,
            as_digest(&session)?,
        )
        .map_err(|_| ProductionRelayError::CorruptState)?;
        let state_key = ParticipantId(as_digest(&state_key)?);
        if state_key != delivery_state_key_v3(config, &scope)? {
            return Err(ProductionRelayError::CorruptState);
        }
        let state = load_delivery_state_v3(connection, config, &scope, &state_key)?
            .ok_or(ProductionRelayError::CorruptState)?;
        let current = acknowledged_cursor_v3(config.database_id, scope, Some(state))?;
        for row in retained.values() {
            if row.ordinal as u64 <= current.position && envelope_in_delivery_scope_v3(row, &scope)?
            {
                return Err(ProductionRelayError::CorruptState);
            }
        }
        if let Some(pending) = state.pending {
            delivery_page_from_pending_v3(connection, config, &scope, current, pending)?;
        }
        scope_count = scope_count
            .checked_add(1)
            .ok_or(ProductionRelayError::CorruptState)?;
    }
    drop(scope_statement);
    if scope_count > config.max_envelopes as usize || scope_count > state_count {
        return Err(ProductionRelayError::CorruptState);
    }

    let mut flow_statement = connection.prepare(
        "SELECT session_id, sender_id, recipient_id
         FROM relay_delivery_flows
         ORDER BY session_id, sender_id, recipient_id",
    )?;
    let flow_rows = flow_statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut flows = BTreeMap::<DeliveryFlowKeyV2, DeliveryFlowCheckpointV2>::new();
    for flow in flow_rows {
        let (session_id, sender_id, recipient_id) = flow?;
        let key = DeliveryFlowKeyV2 {
            session_id: as_digest(&session_id)?,
            sender_id: ParticipantId(as_digest(&sender_id)?),
            recipient_id: ParticipantId(as_digest(&recipient_id)?),
        };
        let checkpoint = load_flow_checkpoint(connection, config, &key)?
            .ok_or(ProductionRelayError::CorruptState)?;
        if flows.insert(key, checkpoint).is_some() {
            return Err(ProductionRelayError::CorruptState);
        }
    }
    drop(flow_statement);
    if flows.len() > config.max_envelopes as usize {
        return Err(ProductionRelayError::CorruptState);
    }

    let mut active: Vec<&StoredEnvelopeRowV1> = retained.values().collect();
    active.sort_by_key(|row| row.ordinal);
    for row in active {
        let envelope =
            RelayEnvelopeV1::decode(&row.bytes).map_err(|_| ProductionRelayError::CorruptState)?;
        let key = delivery_flow_key(&envelope);
        let advanced = advance_flow_checkpoint(flows.get(&key).copied(), &envelope, row.digest)?;
        flows.insert(key, advanced);
    }
    if flows.len() > config.max_envelopes as usize {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(())
}

struct ConflictRowV1 {
    ordinal: i64,
    key: IdempotencyKeyV1,
    first_digest: Digest32,
    bytes: Vec<u8>,
    digest: Digest32,
    row_digest: Digest32,
}

fn create_database(
    root: &Path,
    config: RelayDatabaseConfigV1,
    creation_kind: i64,
    recovery_digest: Digest32,
    complete: bool,
) -> Result<Connection, ProductionRelayError> {
    let path = root.join(RELAY_DATABASE_FILE_NAME);
    if path
        .try_exists()
        .map_err(|_| ProductionRelayError::StorageUnavailable)?
    {
        return Err(ProductionRelayError::DatabasePresent);
    }
    let database_authority = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(&path)
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    database_authority
        .sync_all()
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    validate_owner_file(&path)?;
    sync_directory(root)?;
    #[cfg(test)]
    exit_production_creation_for_test("database-inode");
    let mut connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    validate_owner_file(&path)?;
    configure_connection(&connection, &path)?;
    initialize_database_schema(
        &mut connection,
        config,
        creation_kind,
        recovery_digest,
        complete,
    )?;
    validate_database_objects(root)?;
    Ok(connection)
}

fn initialize_database_schema(
    connection: &mut Connection,
    config: RelayDatabaseConfigV1,
    creation_kind: i64,
    recovery_digest: Digest32,
    complete: bool,
) -> Result<(), ProductionRelayError> {
    let schema_digest = digest_parts(SCHEMA_DOMAIN, &[SCHEMA_SQL.as_bytes()])?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_SQL)?;
    #[cfg(test)]
    exit_production_creation_for_test("schema-before-commit");
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.execute(
        "INSERT INTO relay_meta
         (singleton, schema_version, database_id, max_envelopes, creation_kind,
          recovery_digest, reconstruction_complete, schema_digest, next_envelope_ordinal)
         VALUES (1, 3, ?1, ?2, ?3, ?4, ?5, ?6, 1)",
        params![
            config.database_id.0.as_slice(),
            i64::from(config.max_envelopes),
            creation_kind,
            recovery_digest.as_slice(),
            if complete { 1_i64 } else { 0_i64 },
            schema_digest.as_slice(),
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

fn configure_connection(
    connection: &Connection,
    expected_path: &Path,
) -> Result<(), ProductionRelayError> {
    let version: String = connection.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
    let source: String = connection.query_row("SELECT sqlite_source_id()", [], |row| row.get(0))?;
    if version != SQLITE_VERSION || source != SQLITE_SOURCE_ID {
        return Err(ProductionRelayError::UnsupportedFormat);
    }
    connection.busy_timeout(Duration::from_millis(5_000))?;
    let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(ProductionRelayError::StorageUnavailable);
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "read_uncommitted", "OFF")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.pragma_update(None, "secure_delete", "ON")?;
    let defensive = rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE;
    if !connection.set_db_config(defensive, true)? || !connection.db_config(defensive)? {
        return Err(ProductionRelayError::UnsupportedFormat);
    }
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let read_uncommitted: i64 =
        connection.query_row("PRAGMA read_uncommitted", [], |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
    let busy_timeout: i64 = connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    let secure_delete: i64 = connection.query_row("PRAGMA secure_delete", [], |row| row.get(0))?;
    if synchronous != 2
        || foreign_keys != 1
        || read_uncommitted != 0
        || trusted_schema != 0
        || busy_timeout != 5_000
        || secure_delete != 1
    {
        return Err(ProductionRelayError::UnsupportedFormat);
    }
    let mut statement = connection.prepare("PRAGMA database_list")?;
    let rows = statement.query_map([], |row| {
        let name: String = row.get(1)?;
        let file: String = row.get(2)?;
        Ok((name, file))
    })?;
    let expected = expected_path
        .to_str()
        .ok_or(ProductionRelayError::InvalidConfiguration)?;
    let mut saw_main = false;
    for row in rows {
        let (name, file) = row?;
        match name.as_str() {
            "main" if file == expected => saw_main = true,
            "temp" if file.is_empty() => {}
            _ => return Err(ProductionRelayError::UnsupportedFormat),
        }
    }
    if !saw_main {
        return Err(ProductionRelayError::UnsupportedFormat);
    }
    Ok(())
}

fn validate_backend_and_schema(
    connection: &Connection,
    root: &Path,
    config: RelayDatabaseConfigV1,
) -> Result<(), ProductionRelayError> {
    validate_root(root)?;
    require_identity(root, config.database_id)?;
    validate_database_objects(root)?;
    let quick: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if quick != "ok" {
        return Err(ProductionRelayError::CorruptState);
    }
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if user_version != SCHEMA_VERSION {
        return Err(ProductionRelayError::UnsupportedFormat);
    }
    let expected_schema_digest = digest_parts(SCHEMA_DOMAIN, &[SCHEMA_SQL.as_bytes()])?;
    let meta: RelayMetaValidationRowV2 = connection.query_row(
        "SELECT schema_version, database_id, max_envelopes, creation_kind,
                recovery_digest, reconstruction_complete, schema_digest,
                next_envelope_ordinal
         FROM relay_meta WHERE singleton = 1",
        [],
        |row| {
            Ok(RelayMetaValidationRowV2 {
                schema_version: row.get(0)?,
                database_id: row.get(1)?,
                max_envelopes: row.get(2)?,
                creation_kind: row.get(3)?,
                recovery_digest: row.get(4)?,
                complete: row.get(5)?,
                schema_digest: row.get(6)?,
                next_envelope_ordinal: row.get(7)?,
            })
        },
    )?;
    if meta.schema_version != SCHEMA_VERSION
        || as_digest(&meta.database_id)? != config.database_id.0
        || meta.max_envelopes != i64::from(config.max_envelopes)
        || !matches!(meta.creation_kind, 1 | 2)
        || meta.complete != 1
        || meta.next_envelope_ordinal <= 0
        || as_digest(&meta.schema_digest)? != expected_schema_digest
        || (meta.creation_kind == 1 && as_digest(&meta.recovery_digest)? != ZERO_DIGEST)
        || (meta.creation_kind == 2 && as_digest(&meta.recovery_digest)? == ZERO_DIGEST)
    {
        return Err(ProductionRelayError::CorruptState);
    }
    let mut statement = connection.prepare(
        "SELECT name, sql FROM sqlite_schema
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let tables: BTreeMap<String, String> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    if tables != expected_table_schema()? {
        return Err(ProductionRelayError::UnsupportedFormat);
    }
    let other_objects: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema
         WHERE type IN ('trigger', 'view') OR (type = 'index' AND sql IS NOT NULL)",
        [],
        |row| row.get(0),
    )?;
    if other_objects != 0 {
        return Err(ProductionRelayError::UnsupportedFormat);
    }
    Ok(())
}

fn expected_table_schema() -> Result<BTreeMap<String, String>, ProductionRelayError> {
    let mut expected = BTreeMap::new();
    for statement in SCHEMA_SQL
        .split(';')
        .map(str::trim)
        .filter(|sql| !sql.is_empty())
    {
        let name = statement
            .strip_prefix("CREATE TABLE ")
            .and_then(|tail| tail.split_ascii_whitespace().next())
            .ok_or(ProductionRelayError::CorruptState)?;
        if expected
            .insert(name.to_owned(), statement.to_owned())
            .is_some()
        {
            return Err(ProductionRelayError::CorruptState);
        }
    }
    if expected.len() != 6 {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(expected)
}

fn classify_resumable_database(
    connection: &Connection,
    root: &Path,
    config: RelayDatabaseConfigV1,
) -> Result<ProductionRelayCreationStateV1, ProductionRelayError> {
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let user_objects: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if user_version == 0 && user_objects == 0 {
        return Ok(ProductionRelayCreationStateV1::Incomplete);
    }
    require_pristine_connection(connection, root, config)?;
    Ok(ProductionRelayCreationStateV1::InitializedPristine)
}

fn require_pristine_connection(
    connection: &Connection,
    root: &Path,
    config: RelayDatabaseConfigV1,
) -> Result<(), ProductionRelayError> {
    validate_backend_and_schema(connection, root, config)?;
    let (
        creation_kind,
        recovery_digest,
        complete,
        next_ordinal,
        envelopes,
        conflicts,
        states,
        scopes_v3,
        flows,
    ): (i64, Vec<u8>, i64, i64, i64, i64, i64, i64, i64) = connection.query_row(
        "SELECT creation_kind, recovery_digest, reconstruction_complete,
                next_envelope_ordinal,
                (SELECT COUNT(*) FROM relay_envelopes),
                (SELECT COUNT(*) FROM relay_conflicts),
                (SELECT COUNT(*) FROM relay_delivery_state),
                (SELECT COUNT(*) FROM relay_delivery_scopes_v3),
                (SELECT COUNT(*) FROM relay_delivery_flows)
         FROM relay_meta WHERE singleton = 1",
        [],
        |row| {
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
            ))
        },
    )?;
    if creation_kind != 1
        || as_digest(&recovery_digest)? != ZERO_DIGEST
        || complete != 1
        || next_ordinal != 1
        || envelopes != 0
        || conflicts != 0
        || states != 0
        || scopes_v3 != 0
        || flows != 0
    {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn inspect_production_creation_state(
    root: &Path,
    config: RelayDatabaseConfigV1,
) -> Result<ProductionRelayCreationStateV1, ProductionRelayError> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            validate_new_path(root)?;
            return Ok(ProductionRelayCreationStateV1::Missing);
        }
        Err(_) => return Err(ProductionRelayError::StorageUnavailable),
        Ok(_) => validate_root(root)?,
    }
    inspect_locked_production_creation_state(root, config)
}

#[cfg(target_os = "linux")]
fn inspect_locked_production_creation_state(
    root: &Path,
    config: RelayDatabaseConfigV1,
) -> Result<ProductionRelayCreationStateV1, ProductionRelayError> {
    validate_root(root)?;
    let entries = validate_production_resume_entries(root)?;
    if !entries.identity {
        return if entries.count == 0 {
            Ok(ProductionRelayCreationStateV1::Incomplete)
        } else {
            Err(ProductionRelayError::InvalidConfiguration)
        };
    }
    require_identity(root, config.database_id)?;
    if !entries.lock {
        return if entries.count == 1 {
            Ok(ProductionRelayCreationStateV1::Incomplete)
        } else {
            Err(ProductionRelayError::InvalidConfiguration)
        };
    }
    validate_owner_file(&root.join(RELAY_LOCK_FILE_NAME))?;
    if !entries.database {
        return if entries.count == 2 {
            Ok(ProductionRelayCreationStateV1::Incomplete)
        } else {
            Err(ProductionRelayError::InvalidConfiguration)
        };
    }
    validate_database_objects(root)?;
    let path = root.join(RELAY_DATABASE_FILE_NAME);
    validate_owner_file(&path)?;
    if fs::metadata(&path)
        .map_err(|_| ProductionRelayError::StorageUnavailable)?
        .len()
        == 0
    {
        return Ok(ProductionRelayCreationStateV1::Incomplete);
    }
    let connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    classify_resumable_database(&connection, root, config)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct ProductionResumeEntriesV1 {
    count: usize,
    identity: bool,
    lock: bool,
    database: bool,
    wal: bool,
    shm: bool,
}

#[cfg(target_os = "linux")]
fn validate_production_resume_entries(
    root: &Path,
) -> Result<ProductionResumeEntriesV1, ProductionRelayError> {
    let mut state = ProductionResumeEntriesV1 {
        count: 0,
        identity: false,
        lock: false,
        database: false,
        wal: false,
        shm: false,
    };
    for entry in fs::read_dir(root).map_err(|_| ProductionRelayError::StorageUnavailable)? {
        let entry = entry.map_err(|_| ProductionRelayError::StorageUnavailable)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ProductionRelayError::InvalidConfiguration)?;
        state.count = state
            .count
            .checked_add(1)
            .ok_or(ProductionRelayError::InvalidConfiguration)?;
        match name.as_str() {
            RELAY_IDENTITY_FILE_NAME if !state.identity => state.identity = true,
            RELAY_LOCK_FILE_NAME if !state.lock => state.lock = true,
            RELAY_DATABASE_FILE_NAME if !state.database => state.database = true,
            name if name == format!("{RELAY_DATABASE_FILE_NAME}-wal") && !state.wal => {
                state.wal = true
            }
            name if name == format!("{RELAY_DATABASE_FILE_NAME}-shm") && !state.shm => {
                state.shm = true
            }
            _ => return Err(ProductionRelayError::InvalidConfiguration),
        }
    }
    if state.lock && !state.identity
        || state.database && (!state.identity || !state.lock)
        || (state.wal || state.shm) && !state.database
    {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    Ok(state)
}

#[cfg(target_os = "linux")]
fn acquire_production_resume_lock(
    root: &Path,
    database_id: RelayDatabaseIdV1,
) -> Result<File, ProductionRelayError> {
    match fs::symlink_metadata(root) {
        Ok(_) => validate_root(root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_root(root)?,
        Err(_) => return Err(ProductionRelayError::StorageUnavailable),
    }
    let mut entries = validate_production_resume_entries(root)?;
    if !entries.identity {
        if entries.count != 0 {
            return Err(ProductionRelayError::InvalidConfiguration);
        }
        write_identity(root, database_id)?;
        entries = validate_production_resume_entries(root)?;
    }
    require_identity(root, database_id)?;
    if entries.lock {
        acquire_lock(root, false)
    } else {
        if entries.count != 1 || entries.database {
            return Err(ProductionRelayError::InvalidConfiguration);
        }
        acquire_lock(root, true)
    }
}

#[cfg(target_os = "linux")]
fn open_or_initialize_pristine_database(
    root: &Path,
    config: RelayDatabaseConfigV1,
) -> Result<Connection, ProductionRelayError> {
    let path = root.join(RELAY_DATABASE_FILE_NAME);
    if !path
        .try_exists()
        .map_err(|_| ProductionRelayError::StorageUnavailable)?
    {
        return create_database(root, config, 1, ZERO_DIGEST, true);
    }
    validate_database_objects(root)?;
    validate_owner_file(&path)?;
    let mut connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    if classify_resumable_database(&connection, root, config)?
        != ProductionRelayCreationStateV1::Incomplete
    {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    configure_connection(&connection, &path)?;
    if classify_resumable_database(&connection, root, config)?
        != ProductionRelayCreationStateV1::Incomplete
    {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    initialize_database_schema(&mut connection, config, 1, ZERO_DIGEST, true)?;
    validate_database_objects(root)?;
    Ok(connection)
}

fn insert_recovery_entry(
    transaction: &rusqlite::Transaction<'_>,
    config: &RelayDatabaseConfigV1,
    ordinal: usize,
    entry: AuthenticatedRecoveryEntryV1,
) -> Result<(), ProductionRelayError> {
    if entry.source_mask == 0 || entry.source_mask > 3 || entry.source_commitment == ZERO_DIGEST {
        return Err(ProductionRelayError::RecoveryDigestMismatch);
    }
    let envelope = RelayEnvelopeV1::decode(&entry.bytes).map_err(ProductionRelayError::Codec)?;
    if IdempotencyKeyV1::of(&envelope) != entry.key
        || envelope
            .envelope_digest()
            .map_err(ProductionRelayError::Codec)?
            != entry.digest
        || envelope
            .canonical_bytes()
            .map_err(ProductionRelayError::Codec)?
            != entry.bytes
    {
        return Err(ProductionRelayError::RecoveryDigestMismatch);
    }
    let row_digest = envelope_row_digest(
        config.database_id,
        &entry.key,
        &entry.bytes,
        &entry.digest,
        entry.source_mask,
        &entry.source_commitment,
    )?;
    transaction.execute(
        "INSERT INTO relay_envelopes
         (ordinal, session_id, sender_id, recipient_id, sequence_be,
          canonical_bytes, envelope_digest, recovery_source_mask,
          recovery_commitment, row_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            i64::try_from(ordinal).map_err(|_| ProductionRelayError::CorruptState)?,
            entry.key.session_id.as_slice(),
            entry.key.sender_id.0.as_slice(),
            entry.key.recipient_id.0.as_slice(),
            entry.key.sequence.to_be_bytes().as_slice(),
            entry.bytes,
            entry.digest.as_slice(),
            i64::from(entry.source_mask),
            entry.source_commitment.as_slice(),
            row_digest.as_slice(),
        ],
    )?;
    Ok(())
}

fn persist_conflict(
    transaction: &rusqlite::Transaction<'_>,
    config: &RelayDatabaseConfigV1,
    first: &StoredEnvelopeRowV1,
    conflicting_bytes: &[u8],
    conflicting_digest: Digest32,
) -> Result<(), ProductionRelayError> {
    if first.bytes == conflicting_bytes || first.digest == conflicting_digest {
        return Err(ProductionRelayError::CorruptState);
    }
    let existing: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT conflicting_bytes FROM relay_conflicts
             WHERE session_id = ?1 AND sender_id = ?2 AND recipient_id = ?3
               AND sequence_be = ?4 AND conflicting_digest = ?5",
            params![
                first.key.session_id.as_slice(),
                first.key.sender_id.0.as_slice(),
                first.key.recipient_id.0.as_slice(),
                first.key.sequence.to_be_bytes().as_slice(),
                conflicting_digest.as_slice(),
            ],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        if existing == conflicting_bytes {
            return Ok(());
        }
        return Err(ProductionRelayError::CorruptState);
    }
    let count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM relay_conflicts", [], |row| row.get(0))?;
    if count < 0 || count as usize >= MAX_STORED_ENVELOPES {
        return Err(ProductionRelayError::StorageFull);
    }
    let ordinal: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(ordinal), 0) + 1 FROM relay_conflicts",
        [],
        |row| row.get(0),
    )?;
    if ordinal <= 0 {
        return Err(ProductionRelayError::StorageFull);
    }
    let row_digest = conflict_row_digest(
        config.database_id,
        &first.key,
        &first.digest,
        conflicting_bytes,
        &conflicting_digest,
    )?;
    transaction.execute(
        "INSERT INTO relay_conflicts
         (ordinal, session_id, sender_id, recipient_id, sequence_be,
          first_digest, conflicting_bytes, conflicting_digest, row_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            ordinal,
            first.key.session_id.as_slice(),
            first.key.sender_id.0.as_slice(),
            first.key.recipient_id.0.as_slice(),
            first.key.sequence.to_be_bytes().as_slice(),
            first.digest.as_slice(),
            conflicting_bytes,
            conflicting_digest.as_slice(),
            row_digest.as_slice(),
        ],
    )?;
    Ok(())
}

trait QueryRowSource {
    fn query_stored_row(
        &self,
        key: &IdempotencyKeyV1,
    ) -> rusqlite::Result<Option<StoredEnvelopeRowV1>>;
}

impl QueryRowSource for Connection {
    fn query_stored_row(
        &self,
        key: &IdempotencyKeyV1,
    ) -> rusqlite::Result<Option<StoredEnvelopeRowV1>> {
        query_stored_row_impl(self, key)
    }
}

impl QueryRowSource for rusqlite::Transaction<'_> {
    fn query_stored_row(
        &self,
        key: &IdempotencyKeyV1,
    ) -> rusqlite::Result<Option<StoredEnvelopeRowV1>> {
        query_stored_row_impl(self, key)
    }
}

fn query_stored_row_impl(
    source: &Connection,
    key: &IdempotencyKeyV1,
) -> rusqlite::Result<Option<StoredEnvelopeRowV1>> {
    source
        .query_row(
            "SELECT ordinal, session_id, sender_id, recipient_id, sequence_be,
                    canonical_bytes, envelope_digest, recovery_source_mask,
                    recovery_commitment, row_digest
             FROM relay_envelopes
             WHERE session_id = ?1 AND sender_id = ?2 AND recipient_id = ?3 AND sequence_be = ?4",
            params![
                key.session_id.as_slice(),
                key.sender_id.0.as_slice(),
                key.recipient_id.0.as_slice(),
                key.sequence.to_be_bytes().as_slice(),
            ],
            row_from_sql,
        )
        .optional()
}

fn load_envelope_row_from(
    source: &impl QueryRowSource,
    key: &IdempotencyKeyV1,
) -> Result<Option<StoredEnvelopeRowV1>, ProductionRelayError> {
    Ok(source.query_stored_row(key)?)
}

fn row_from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEnvelopeRowV1> {
    let source_mask: i64 = row.get(7)?;
    let key = IdempotencyKeyV1 {
        session_id: sql_digest(row.get(1)?)?,
        sender_id: ParticipantId(sql_digest(row.get(2)?)?),
        recipient_id: ParticipantId(sql_digest(row.get(3)?)?),
        sequence: sql_sequence(row.get(4)?)?,
    };
    Ok(StoredEnvelopeRowV1 {
        ordinal: row.get(0)?,
        key,
        bytes: row.get(5)?,
        digest: sql_digest(row.get(6)?)?,
        source_mask: u8::try_from(source_mask).map_err(|_| rusqlite::Error::InvalidQuery)?,
        source_commitment: sql_digest(row.get(8)?)?,
        row_digest: sql_digest(row.get(9)?)?,
    })
}

fn conflict_from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConflictRowV1> {
    Ok(ConflictRowV1 {
        ordinal: row.get(0)?,
        key: IdempotencyKeyV1 {
            session_id: sql_digest(row.get(1)?)?,
            sender_id: ParticipantId(sql_digest(row.get(2)?)?),
            recipient_id: ParticipantId(sql_digest(row.get(3)?)?),
            sequence: sql_sequence(row.get(4)?)?,
        },
        first_digest: sql_digest(row.get(5)?)?,
        bytes: row.get(6)?,
        digest: sql_digest(row.get(7)?)?,
        row_digest: sql_digest(row.get(8)?)?,
    })
}

fn validate_envelope_row(
    config: &RelayDatabaseConfigV1,
    row: &StoredEnvelopeRowV1,
) -> Result<(), ProductionRelayError> {
    if row.ordinal <= 0
        || row.bytes.len() > MAX_ENVELOPE_BYTES
        || row.source_mask > 3
        || (row.source_mask == 0) != (row.source_commitment == ZERO_DIGEST)
    {
        return Err(ProductionRelayError::CorruptState);
    }
    let envelope =
        RelayEnvelopeV1::decode(&row.bytes).map_err(|_| ProductionRelayError::CorruptState)?;
    if IdempotencyKeyV1::of(&envelope) != row.key
        || envelope
            .canonical_bytes()
            .map_err(|_| ProductionRelayError::CorruptState)?
            != row.bytes
        || envelope
            .envelope_digest()
            .map_err(|_| ProductionRelayError::CorruptState)?
            != row.digest
        || envelope_row_digest(
            config.database_id,
            &row.key,
            &row.bytes,
            &row.digest,
            row.source_mask,
            &row.source_commitment,
        )? != row.row_digest
    {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(())
}

fn validate_conflict_row(
    config: &RelayDatabaseConfigV1,
    first: &StoredEnvelopeRowV1,
    row: &ConflictRowV1,
) -> Result<(), ProductionRelayError> {
    if row.ordinal <= 0
        || row.key != first.key
        || row.first_digest != first.digest
        || row.bytes == first.bytes
    {
        return Err(ProductionRelayError::CorruptState);
    }
    let envelope =
        RelayEnvelopeV1::decode(&row.bytes).map_err(|_| ProductionRelayError::CorruptState)?;
    if IdempotencyKeyV1::of(&envelope) != row.key
        || envelope
            .canonical_bytes()
            .map_err(|_| ProductionRelayError::CorruptState)?
            != row.bytes
        || envelope
            .envelope_digest()
            .map_err(|_| ProductionRelayError::CorruptState)?
            != row.digest
        || conflict_row_digest(
            config.database_id,
            &row.key,
            &row.first_digest,
            &row.bytes,
            &row.digest,
        )? != row.row_digest
    {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(())
}

fn envelope_row_digest(
    database_id: RelayDatabaseIdV1,
    key: &IdempotencyKeyV1,
    bytes: &[u8],
    digest: &Digest32,
    source_mask: u8,
    source_commitment: &Digest32,
) -> Result<Digest32, ProductionRelayError> {
    digest_parts(
        ROW_DOMAIN,
        &[
            database_id.0.as_slice(),
            key.session_id.as_slice(),
            key.sender_id.0.as_slice(),
            key.recipient_id.0.as_slice(),
            key.sequence.to_be_bytes().as_slice(),
            digest.as_slice(),
            &[source_mask],
            source_commitment.as_slice(),
            &(bytes.len() as u32).to_be_bytes(),
            bytes,
        ],
    )
}

fn conflict_row_digest(
    database_id: RelayDatabaseIdV1,
    key: &IdempotencyKeyV1,
    first_digest: &Digest32,
    bytes: &[u8],
    digest: &Digest32,
) -> Result<Digest32, ProductionRelayError> {
    digest_parts(
        CONFLICT_DOMAIN,
        &[
            database_id.0.as_slice(),
            key.session_id.as_slice(),
            key.sender_id.0.as_slice(),
            key.recipient_id.0.as_slice(),
            key.sequence.to_be_bytes().as_slice(),
            first_digest.as_slice(),
            digest.as_slice(),
            &(bytes.len() as u32).to_be_bytes(),
            bytes,
        ],
    )
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, ProductionRelayError> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| ProductionRelayError::CorruptState)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut digest = [0_u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| ProductionRelayError::CorruptState)?;
    Ok(digest)
}

fn identity_record(
    database_id: RelayDatabaseIdV1,
) -> Result<[u8; IDENTITY_RECORD_LEN], ProductionRelayError> {
    let checksum = digest_parts(IDENTITY_DOMAIN, &[database_id.0.as_slice()])?;
    let mut record = [0_u8; IDENTITY_RECORD_LEN];
    record[..8].copy_from_slice(IDENTITY_MAGIC);
    record[8..10].copy_from_slice(&IDENTITY_VERSION.to_be_bytes());
    record[10..42].copy_from_slice(&database_id.0);
    record[42..].copy_from_slice(&checksum);
    Ok(record)
}

#[cfg(target_os = "linux")]
fn create_root(root: &Path) -> Result<(), ProductionRelayError> {
    validate_new_path(root)?;
    match DirBuilder::new().mode(ROOT_MODE).create(root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ProductionRelayError::AlreadyExists)
        }
        Err(_) => return Err(ProductionRelayError::StorageUnavailable),
    }
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    let parent = root
        .parent()
        .ok_or(ProductionRelayError::InvalidConfiguration)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    validate_root(root)
}

#[cfg(target_os = "linux")]
fn sync_directory(path: &Path) -> Result<(), ProductionRelayError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ProductionRelayError::StorageUnavailable)
}

#[cfg(target_os = "linux")]
fn validate_new_path(root: &Path) -> Result<(), ProductionRelayError> {
    if !root.is_absolute() || root.file_name().is_none() {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    let parent = root
        .parent()
        .ok_or(ProductionRelayError::InvalidConfiguration)?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|_| ProductionRelayError::InvalidConfiguration)?;
    if canonical_parent != parent {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    validate_owner_directory(parent)?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_root(root: &Path) -> Result<(), ProductionRelayError> {
    if !root.is_absolute()
        || fs::canonicalize(root).map_err(|_| ProductionRelayError::StorageUnavailable)? != root
    {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    validate_owner_directory(root)
}

#[cfg(target_os = "linux")]
fn validate_owner_directory(path: &Path) -> Result<(), ProductionRelayError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ProductionRelayError::StorageUnavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != ROOT_MODE
        || metadata.nlink() == 0
    {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_owner_file(path: &Path) -> Result<(), ProductionRelayError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ProductionRelayError::StorageUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_identity(root: &Path, database_id: RelayDatabaseIdV1) -> Result<(), ProductionRelayError> {
    let path = root.join(RELAY_IDENTITY_FILE_NAME);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(&path)
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    file.write_all(&identity_record(database_id)?)
        .and_then(|_| file.sync_all())
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    validate_owner_file(&path)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ProductionRelayError::StorageUnavailable)
}

#[cfg(target_os = "linux")]
fn require_identity(root: &Path, expected: RelayDatabaseIdV1) -> Result<(), ProductionRelayError> {
    let path = root.join(RELAY_IDENTITY_FILE_NAME);
    validate_owner_file(&path)?;
    let mut file = File::open(&path).map_err(|_| ProductionRelayError::StorageUnavailable)?;
    let mut bytes = Vec::with_capacity(IDENTITY_RECORD_LEN + 1);
    Read::by_ref(&mut file)
        .take((IDENTITY_RECORD_LEN + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    if bytes.len() != IDENTITY_RECORD_LEN
        || &bytes[..8] != IDENTITY_MAGIC
        || u16::from_be_bytes([bytes[8], bytes[9]]) != IDENTITY_VERSION
    {
        return Err(ProductionRelayError::WrongDatabaseIdentity);
    }
    let database_id = as_digest(&bytes[10..42])?;
    let checksum = as_digest(&bytes[42..74])?;
    if database_id != expected.0
        || checksum != digest_parts(IDENTITY_DOMAIN, &[database_id.as_slice()])?
    {
        return Err(ProductionRelayError::WrongDatabaseIdentity);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn acquire_lock(root: &Path, create: bool) -> Result<File, ProductionRelayError> {
    let path = root.join(RELAY_LOCK_FILE_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true).mode(FILE_MODE);
    if create {
        options.create_new(true);
    }
    let file = options
        .open(&path)
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    validate_owner_file(&path)?;
    let retained = file
        .metadata()
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    let named =
        fs::symlink_metadata(&path).map_err(|_| ProductionRelayError::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    if create {
        file.sync_all()
            .map_err(|_| ProductionRelayError::StorageUnavailable)?;
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn validate_database_objects(root: &Path) -> Result<(), ProductionRelayError> {
    for name in [
        RELAY_DATABASE_FILE_NAME.to_owned(),
        format!("{RELAY_DATABASE_FILE_NAME}-wal"),
        format!("{RELAY_DATABASE_FILE_NAME}-shm"),
    ] {
        let path = root.join(name);
        if path
            .try_exists()
            .map_err(|_| ProductionRelayError::StorageUnavailable)?
        {
            validate_owner_file(&path)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_database_absent(root: &Path) -> Result<(), ProductionRelayError> {
    for name in [
        RELAY_DATABASE_FILE_NAME.to_owned(),
        format!("{RELAY_DATABASE_FILE_NAME}-wal"),
        format!("{RELAY_DATABASE_FILE_NAME}-shm"),
    ] {
        if root
            .join(name)
            .try_exists()
            .map_err(|_| ProductionRelayError::StorageUnavailable)?
        {
            return Err(ProductionRelayError::DatabasePresent);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_loss_marker_if_present(
    root: &Path,
    database_id: RelayDatabaseIdV1,
) -> Result<(), ProductionRelayError> {
    let marker = root.join(RELAY_DATABASE_LOSS_MARKER_NAME);
    if marker
        .try_exists()
        .map_err(|_| ProductionRelayError::StorageUnavailable)?
    {
        validate_owner_file(&marker)?;
        let mut file = File::open(&marker).map_err(|_| ProductionRelayError::StorageUnavailable)?;
        let mut retained = Vec::with_capacity(DATABASE_LOSS_MARKER_LEN + 1);
        Read::by_ref(&mut file)
            .take((DATABASE_LOSS_MARKER_LEN + 1) as u64)
            .read_to_end(&mut retained)
            .map_err(|_| ProductionRelayError::StorageUnavailable)?;
        if retained != database_loss_marker(database_id)?.as_slice() {
            return Err(ProductionRelayError::CorruptState);
        }
    }
    match fs::remove_file(&marker) {
        Ok(()) => File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ProductionRelayError::StorageUnavailable),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ProductionRelayError::StorageUnavailable),
    }
}

pub(crate) fn database_loss_marker(
    database_id: RelayDatabaseIdV1,
) -> Result<[u8; DATABASE_LOSS_MARKER_LEN], ProductionRelayError> {
    let checksum = digest_parts(DATABASE_LOSS_DOMAIN, &[database_id.as_bytes()])?;
    let mut marker = [0_u8; DATABASE_LOSS_MARKER_LEN];
    marker[..8].copy_from_slice(DATABASE_LOSS_MAGIC);
    marker[8..10].copy_from_slice(&DATABASE_LOSS_VERSION.to_be_bytes());
    marker[10..42].copy_from_slice(database_id.as_bytes());
    marker[42..].copy_from_slice(&checksum);
    Ok(marker)
}

fn as_digest(bytes: &[u8]) -> Result<Digest32, ProductionRelayError> {
    bytes
        .try_into()
        .map_err(|_| ProductionRelayError::CorruptState)
}

fn sql_digest(bytes: Vec<u8>) -> rusqlite::Result<Digest32> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn sql_sequence(bytes: Vec<u8>) -> rusqlite::Result<u64> {
    let array: [u8; 8] = bytes
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(u64::from_be_bytes(array))
}

#[cfg(all(test, target_os = "linux"))]
mod creation_resume_tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::process::Command;

    const TEST_CREATION_ROOT_ENV: &str = "DOM_INTEROP_RELAY_TEST_CREATION_ROOT";

    fn owner_parent() -> tempfile::TempDir {
        let parent = tempfile::tempdir().expect("temporary parent");
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(ROOT_MODE))
            .expect("owner-only parent");
        parent
    }

    fn config_with(marker: u8, max_envelopes: u32) -> RelayDatabaseConfigV1 {
        RelayDatabaseConfigV1::new(
            RelayDatabaseIdV1::new([marker; 32]).expect("database id"),
            max_envelopes,
        )
        .expect("database config")
    }

    fn flow_raws(
        recipient: ParticipantId,
        session_marker: u8,
        count: usize,
        payload_len: usize,
    ) -> Vec<Vec<u8>> {
        let mut previous = ZERO_DIGEST;
        let mut raws = Vec::with_capacity(count);
        for sequence in 0..count {
            let envelope = RelayEnvelopeV1 {
                network_id: [0x70; 32],
                message_type: crate::auth::message_type::QUOTE,
                session_id: [session_marker; 32],
                route_id: [0x71; 32],
                sender_id: ParticipantId([0x72; 32]),
                recipient_id: recipient,
                sender_role: crate::SenderRoleV1::Solver,
                sequence: sequence as u64,
                previous_transcript_hash: previous,
                payload: vec![sequence as u8; payload_len],
                expiry: crate::TimelockSpec::TimestampSeconds { value: 100 },
                policy_version: 1,
                roster_snapshot: [0x73; 32],
                signature: [sequence as u8; 64],
            };
            previous = envelope.envelope_digest().expect("flow digest");
            raws.push(envelope.canonical_bytes().expect("flow bytes"));
        }
        raws
    }

    fn publish_identity(root: &Path, config: RelayDatabaseConfigV1) {
        create_root(root).expect("root");
        write_identity(root, config.database_id()).expect("identity");
    }

    fn publish_lock(root: &Path, config: RelayDatabaseConfigV1) {
        publish_identity(root, config);
        drop(acquire_lock(root, true).expect("lock"));
    }

    fn publish_empty_database(root: &Path, config: RelayDatabaseConfigV1) {
        publish_lock(root, config);
        drop(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(FILE_MODE)
                .open(root.join(RELAY_DATABASE_FILE_NAME))
                .expect("empty database"),
        );
    }

    fn assert_resume_reopens(root: &Path, config: RelayDatabaseConfigV1) {
        ProductionRelayV1::preflight_resume_create_production(root, config)
            .expect("preflight pristine prefix");
        let resumed = ProductionRelayV1::resume_create_production(root, config)
            .expect("resume pristine prefix");
        assert!(resumed.is_empty().expect("empty relay"));
        drop(resumed);
        assert_eq!(
            ProductionRelayV1::production_creation_state(root, config).expect("initialized state"),
            ProductionRelayCreationStateV1::InitializedPristine
        );
        drop(ProductionRelayV1::open(root, config).expect("ordinary reopen"));
        drop(
            ProductionRelayV1::resume_create_production(root, config)
                .expect("idempotent pristine resume"),
        );
    }

    #[test]
    fn creation_process_loss_subprocess() {
        let Some(root) = std::env::var_os(TEST_CREATION_ROOT_ENV) else {
            return;
        };
        let boundary = std::env::var_os(TEST_CREATION_EXIT_ENV)
            .expect("process-loss subprocess requires a creation boundary");
        assert!(matches!(
            boundary.to_str(),
            Some("root" | "identity" | "lock" | "database-inode" | "schema-before-commit")
        ));
        let result = ProductionRelayV1::create(&PathBuf::from(root), config_with(0x61, 64));
        panic!("creation reached the caller instead of exiting: {result:?}");
    }

    #[test]
    fn actual_process_loss_at_each_creation_boundary_resumes_pristine() {
        let parent = owner_parent();
        let config = config_with(0x61, 64);
        for boundary in [
            "root",
            "identity",
            "lock",
            "database-inode",
            "schema-before-commit",
        ] {
            let root = parent.path().join(format!("process-loss-{boundary}"));
            let status = Command::new(std::env::current_exe().expect("current test executable"))
                .arg("creation_process_loss_subprocess")
                .arg("--test-threads=1")
                .arg("--nocapture")
                .env(TEST_CREATION_ROOT_ENV, &root)
                .env(TEST_CREATION_EXIT_ENV, boundary)
                .status()
                .expect("spawn creation process-loss subprocess");
            assert_eq!(
                status.code(),
                Some(86),
                "{boundary} child did not terminate at the process-loss hook: {status:?}"
            );
            assert_eq!(
                ProductionRelayV1::production_creation_state(&root, config)
                    .expect("classify aborted creation"),
                ProductionRelayCreationStateV1::Incomplete,
                "unexpected state after abort at {boundary}"
            );
            assert_resume_reopens(&root, config);
        }
    }

    #[test]
    fn active_process_lock_refuses_creation_resume() {
        let parent = owner_parent();
        let config = config_with(0x62, 64);
        let root = parent.path().join("active-lock");
        publish_identity(&root, config);
        let active_lock = acquire_lock(&root, true).expect("active process lock");
        assert!(ProductionRelayV1::resume_create_production(&root, config).is_err());
        drop(active_lock);
        assert_resume_reopens(&root, config);
    }

    #[test]
    fn paged_delivery_is_bounded_exact_idempotent_and_gcs_only_after_ack() {
        let parent = owner_parent();
        let config = config_with(0x63, 64);
        let root = parent.path().join("paged-delivery");
        let recipient = ParticipantId([0x81; 32]);
        let other = ParticipantId([0x82; 32]);
        let raws = flow_raws(recipient, 0x83, 3, 32);
        let other_raw = flow_raws(other, 0x84, 1, 32).remove(0);
        let mut relay = ProductionRelayV1::create(&root, config).expect("relay");
        for raw in &raws {
            relay.submit(raw).expect("submit flow");
        }
        relay.submit(&other_raw).expect("submit other recipient");

        let limits =
            DeliveryPageLimitsV2::new(2, MAX_ENVELOPE_BYTES as u32 * 2).expect("page limits");
        let initial = relay
            .acknowledged_delivery_cursor_v2(&recipient)
            .expect("initial cursor");
        let page = relay
            .delivery_page_v2(&recipient, &initial, limits)
            .expect("first page");
        assert_eq!(page.envelopes(), &raws[..2]);
        assert!(page.has_more());
        assert_eq!(relay.len().expect("nothing gc before ack"), 4);
        let canonical = page.canonical_bytes().expect("canonical page");
        assert_eq!(
            DeliveryPageV2::decode(&canonical, limits).expect("decode page"),
            page
        );
        assert_eq!(
            relay
                .delivery_page_v2(&recipient, &initial, limits)
                .expect("exact pending retry")
                .canonical_bytes()
                .expect("retry bytes"),
            canonical
        );
        assert!(matches!(
            relay.delivery_page_v2(
                &recipient,
                &initial,
                DeliveryPageLimitsV2::new(1, MAX_ENVELOPE_BYTES as u32).expect("other limits")
            ),
            Err(ProductionRelayError::InvalidDeliveryLimits)
        ));

        let next = *page.next_cursor();
        assert!(matches!(
            relay.acknowledge_delivery_page_v2(&other, &next),
            Err(ProductionRelayError::InvalidDeliveryCursor)
        ));
        let mut future = next;
        future.position += 1;
        assert!(matches!(
            relay.acknowledge_delivery_page_v2(&recipient, &future),
            Err(ProductionRelayError::InvalidDeliveryCursor)
        ));
        let ack = relay
            .acknowledge_delivery_page_v2(&recipient, &next)
            .expect("durable ack");
        assert_eq!(
            DeliveryAckV2::decode(&ack.canonical_bytes()).expect("decode ack"),
            ack
        );
        assert_eq!(relay.len().expect("recipient prefix gc"), 2);
        assert_eq!(
            relay
                .acknowledge_delivery_page_v2(&recipient, &next)
                .expect("idempotent ack")
                .canonical_bytes(),
            ack.canonical_bytes()
        );
        assert!(matches!(
            relay.delivery_page_v2(&recipient, &initial, limits),
            Err(ProductionRelayError::InvalidDeliveryCursor)
        ));
        assert_eq!(
            relay.deliver_ephemeral_v1(&other).expect("other preserved"),
            vec![other_raw]
        );

        let terminal_ack = relay.submit(&raws[1]).expect("terminal duplicate ack");
        assert_eq!(
            terminal_ack.digest,
            RelayEnvelopeV1::decode(&raws[1])
                .expect("terminal envelope")
                .envelope_digest()
                .expect("terminal digest")
        );
        assert_eq!(relay.len().expect("duplicate not reinserted"), 2);
        assert!(matches!(
            relay.submit(&raws[0]),
            Err(ProductionRelayError::AcknowledgedDeliveryPrefix)
        ));
        let mut signature_substitution =
            RelayEnvelopeV1::decode(&raws[1]).expect("terminal signature fixture");
        signature_substitution.signature[0] ^= 1;
        assert!(matches!(
            relay.submit(
                &signature_substitution
                    .canonical_bytes()
                    .expect("signature substitution bytes")
            ),
            Err(ProductionRelayError::Equivocation)
        ));
        let mut equivocation = RelayEnvelopeV1::decode(&raws[1]).expect("terminal");
        equivocation.payload.push(0xff);
        let conflicting = equivocation.canonical_bytes().expect("conflicting bytes");
        assert!(matches!(
            relay.submit(&conflicting),
            Err(ProductionRelayError::Equivocation)
        ));
    }

    #[test]
    fn process_restart_redelivers_pending_and_replays_lost_delivery_ack() {
        let parent = owner_parent();
        let config = config_with(0x64, 64);
        let root = parent.path().join("delivery-restart");
        let recipient = ParticipantId([0x85; 32]);
        let raws = flow_raws(recipient, 0x86, 2, 64);
        let limits =
            DeliveryPageLimitsV2::new(2, MAX_ENVELOPE_BYTES as u32 * 2).expect("page limits");
        let mut relay = ProductionRelayV1::create(&root, config).expect("relay");
        for raw in &raws {
            relay.submit(raw).expect("submit");
        }
        let current = relay
            .acknowledged_delivery_cursor_v2(&recipient)
            .expect("cursor");
        let page_bytes = relay
            .delivery_page_v2(&recipient, &current, limits)
            .expect("read before local persistence")
            .canonical_bytes()
            .expect("page bytes");
        drop(relay);

        let mut relay = ProductionRelayV1::open(&root, config).expect("restart after read");
        let page = relay
            .delivery_page_v2(&recipient, &current, limits)
            .expect("redelivery after local persistence");
        assert_eq!(page.canonical_bytes().expect("same page"), page_bytes);
        let next = *page.next_cursor();
        let ack_bytes = relay
            .acknowledge_delivery_page_v2(&recipient, &next)
            .expect("ack committed")
            .canonical_bytes();
        drop(relay);

        let mut relay = ProductionRelayV1::open(&root, config).expect("restart after lost ack");
        assert_eq!(relay.len().expect("gc committed"), 0);
        assert_eq!(
            relay
                .acknowledge_delivery_page_v2(&recipient, &next)
                .expect("same ack after restart")
                .canonical_bytes(),
            ack_bytes
        );
    }

    #[test]
    fn page_byte_limit_cursor_transplants_and_noncontiguous_gc_fail_closed() {
        assert!(DeliveryPageLimitsV2::new(0, MAX_ENVELOPE_BYTES as u32).is_err());
        assert!(DeliveryPageLimitsV2::new(
            MAX_DELIVERY_PAGE_ITEMS_V2 + 1,
            MAX_ENVELOPE_BYTES as u32
        )
        .is_err());
        assert!(DeliveryPageLimitsV2::new(1, MAX_ENVELOPE_BYTES as u32 - 1).is_err());
        assert!(DeliveryPageLimitsV2::new(1, MAX_DELIVERY_PAGE_BYTES_V2 + 1).is_err());
        let parent = owner_parent();
        let config = config_with(0x65, 64);
        let root = parent.path().join("delivery-adversarial");
        let recipient = ParticipantId([0x87; 32]);
        let raws = flow_raws(recipient, 0x88, 2, 10_000);
        let mut relay = ProductionRelayV1::create(&root, config).expect("relay");
        for raw in &raws {
            relay.submit(raw).expect("submit");
        }
        let limits =
            DeliveryPageLimitsV2::new(2, MAX_ENVELOPE_BYTES as u32).expect("byte-limited page");
        let current = relay
            .acknowledged_delivery_cursor_v2(&recipient)
            .expect("cursor");
        let page = relay
            .delivery_page_v2(&recipient, &current, limits)
            .expect("bounded page");
        assert_eq!(page.envelopes().len(), 1);
        assert!(page.has_more());
        let page_debug = format!("{page:?}");
        assert!(page_debug.contains("[redacted]"));
        assert!(!page_debug.contains(&format!("{:?}", page.envelopes()[0])));
        let canonical = page.canonical_bytes().expect("page bytes");
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(DeliveryPageV2::decode(&trailing, limits).is_err());
        let mut transplanted = *page.next_cursor();
        transplanted.recipient_id = ParticipantId([0x89; 32]);
        assert!(matches!(
            relay.acknowledge_delivery_page_v2(&recipient, &transplanted),
            Err(ProductionRelayError::InvalidDeliveryCursor)
        ));

        let bad_root = parent.path().join("noncontiguous");
        let mut bad =
            ProductionRelayV1::create(&bad_root, config_with(0x66, 64)).expect("bad relay");
        let mut gap =
            RelayEnvelopeV1::decode(&flow_raws(recipient, 0x8a, 1, 1)[0]).expect("gap fixture");
        gap.sequence = 1;
        let gap = gap.canonical_bytes().expect("gap bytes");
        assert!(matches!(
            bad.submit(&gap),
            Err(ProductionRelayError::NonContiguousDelivery)
        ));

        let bound_root = parent.path().join("flow-bound");
        let mut bound =
            ProductionRelayV1::create(&bound_root, config_with(0x68, 1)).expect("bounded relay");
        bound
            .submit(&flow_raws(recipient, 0x8b, 1, 1)[0])
            .expect("first bounded flow");
        assert!(matches!(
            bound.submit(&flow_raws(recipient, 0x8c, 1, 1)[0]),
            Err(ProductionRelayError::StorageFull)
        ));
    }

    #[test]
    fn delivery_state_tamper_is_refused_on_restart() {
        let parent = owner_parent();
        let config = config_with(0x69, 64);
        let root = parent.path().join("delivery-state-tamper");
        let recipient = ParticipantId([0x8d; 32]);
        let raw = flow_raws(recipient, 0x8e, 1, 1).remove(0);
        let mut relay = ProductionRelayV1::create(&root, config).expect("relay");
        relay.submit(&raw).expect("submit");
        let cursor = relay
            .acknowledged_delivery_cursor_v2(&recipient)
            .expect("cursor");
        relay
            .delivery_page_v2(
                &recipient,
                &cursor,
                DeliveryPageLimitsV2::new(1, MAX_ENVELOPE_BYTES as u32).expect("limits"),
            )
            .expect("pin page");
        drop(relay);
        let path = root.join(RELAY_DATABASE_FILE_NAME);
        let connection = Connection::open(&path).expect("tamper connection");
        let mut bytes: Vec<u8> = connection
            .query_row(
                "SELECT state_bytes FROM relay_delivery_state WHERE recipient_id = ?1",
                params![recipient.0.as_slice()],
                |row| row.get(0),
            )
            .expect("delivery state");
        bytes[95] ^= 1;
        connection
            .execute(
                "UPDATE relay_delivery_state SET state_bytes = ?1 WHERE recipient_id = ?2",
                params![bytes, recipient.0.as_slice()],
            )
            .expect("tamper state");
        connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .expect("checkpoint tamper");
        drop(connection);
        assert!(matches!(
            ProductionRelayV1::open(&root, config),
            Err(ProductionRelayError::CorruptState)
        ));
    }

    #[test]
    fn delivery_state_bound_refuses_new_recipient_without_mutation() {
        let parent = owner_parent();
        let config = config_with(0x6a, 1);
        let root = parent.path().join("delivery-state-bound");
        let recipient_a = ParticipantId([0x91; 32]);
        let recipient_b = ParticipantId([0x92; 32]);
        let raw_a = flow_raws(recipient_a, 0x93, 1, 1).remove(0);
        let raw_b = flow_raws(recipient_b, 0x94, 1, 1).remove(0);
        let limits = DeliveryPageLimitsV2::new(1, MAX_ENVELOPE_BYTES as u32).expect("limits");
        let mut relay = ProductionRelayV1::create(&root, config).expect("relay");
        relay.submit(&raw_a).expect("submit recipient A");
        let cursor_a = relay
            .acknowledged_delivery_cursor_v2(&recipient_a)
            .expect("cursor A");
        let page_a = relay
            .delivery_page_v2(&recipient_a, &cursor_a, limits)
            .expect("page A");
        relay
            .acknowledge_delivery_page_v2(&recipient_a, page_a.next_cursor())
            .expect("ack A");

        // The public submit path already refuses a second flow under this
        // one-flow configuration. Install one structurally valid active row
        // directly to isolate the independent delivery-state bound: even a
        // corrupted/imported queue cannot make the runtime write state row 2.
        let envelope_b = RelayEnvelopeV1::decode(&raw_b).expect("envelope B");
        let key_b = IdempotencyKeyV1::of(&envelope_b);
        let digest_b = envelope_b.envelope_digest().expect("digest B");
        let transaction = relay
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("fixture transaction");
        let ordinal: i64 = transaction
            .query_row(
                "SELECT next_envelope_ordinal FROM relay_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("next ordinal");
        let row_digest = envelope_row_digest(
            config.database_id,
            &key_b,
            &raw_b,
            &digest_b,
            0,
            &ZERO_DIGEST,
        )
        .expect("row digest B");
        transaction
            .execute(
                "INSERT INTO relay_envelopes
                 (ordinal, session_id, sender_id, recipient_id, sequence_be,
                  canonical_bytes, envelope_digest, recovery_source_mask,
                  recovery_commitment, row_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9)",
                params![
                    ordinal,
                    key_b.session_id.as_slice(),
                    key_b.sender_id.0.as_slice(),
                    key_b.recipient_id.0.as_slice(),
                    key_b.sequence.to_be_bytes().as_slice(),
                    raw_b,
                    digest_b.as_slice(),
                    ZERO_DIGEST.as_slice(),
                    row_digest.as_slice(),
                ],
            )
            .expect("install active row B");
        transaction
            .execute(
                "UPDATE relay_meta SET next_envelope_ordinal = ?1 WHERE singleton = 1",
                params![ordinal + 1],
            )
            .expect("advance fixture ordinal");
        transaction.commit().expect("commit fixture");

        let cursor_b = relay
            .acknowledged_delivery_cursor_v2(&recipient_b)
            .expect("cursor B");
        assert!(matches!(
            relay.delivery_page_v2(&recipient_b, &cursor_b, limits),
            Err(ProductionRelayError::StorageFull)
        ));
        let state_count: i64 = relay
            .connection
            .query_row("SELECT COUNT(*) FROM relay_delivery_state", [], |row| {
                row.get(0)
            })
            .expect("state count");
        assert_eq!(state_count, 1);
        assert_eq!(relay.len().expect("B row remains unconsumed"), 1);
    }

    #[test]
    fn obsolete_database_schema_version_is_explicitly_refused() {
        let parent = owner_parent();
        let config = config_with(0x67, 64);
        let root = parent.path().join("obsolete-schema");
        drop(ProductionRelayV1::create(&root, config).expect("relay"));
        let path = root.join(RELAY_DATABASE_FILE_NAME);
        let connection = Connection::open(&path).expect("open database for old-version fixture");
        connection
            .pragma_update(None, "user_version", 1)
            .expect("publish obsolete version");
        connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .expect("checkpoint obsolete version");
        drop(connection);
        assert!(matches!(
            ProductionRelayV1::open(&root, config),
            Err(ProductionRelayError::UnsupportedFormat)
        ));
    }

    #[test]
    fn every_published_creation_boundary_resumes_to_one_pristine_database() {
        let parent = owner_parent();
        let config = config_with(0x41, 64);

        let missing = parent.path().join("missing");
        assert_eq!(
            ProductionRelayV1::production_creation_state(&missing, config).expect("missing state"),
            ProductionRelayCreationStateV1::Missing
        );
        assert_resume_reopens(&missing, config);

        let root_only = parent.path().join("root-only");
        create_root(&root_only).expect("root-only prefix");
        assert_eq!(
            ProductionRelayV1::production_creation_state(&root_only, config)
                .expect("root-only state"),
            ProductionRelayCreationStateV1::Incomplete
        );
        assert_resume_reopens(&root_only, config);

        let identity = parent.path().join("identity");
        publish_identity(&identity, config);
        assert_eq!(
            ProductionRelayV1::production_creation_state(&identity, config)
                .expect("identity state"),
            ProductionRelayCreationStateV1::Incomplete
        );
        assert_resume_reopens(&identity, config);

        let lock = parent.path().join("lock");
        publish_lock(&lock, config);
        assert_eq!(
            ProductionRelayV1::production_creation_state(&lock, config).expect("lock state"),
            ProductionRelayCreationStateV1::Incomplete
        );
        assert_resume_reopens(&lock, config);

        let empty_database = parent.path().join("empty-database");
        publish_empty_database(&empty_database, config);
        assert_eq!(
            ProductionRelayV1::production_creation_state(&empty_database, config)
                .expect("empty database state"),
            ProductionRelayCreationStateV1::Incomplete
        );
        assert_resume_reopens(&empty_database, config);

        let rolled_back_schema = parent.path().join("rolled-back-schema");
        publish_empty_database(&rolled_back_schema, config);
        let path = rolled_back_schema.join(RELAY_DATABASE_FILE_NAME);
        let mut connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("open rolled-back database");
        configure_connection(&connection, &path).expect("configure rolled-back database");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("schema transaction");
        transaction
            .execute_batch(SCHEMA_SQL)
            .expect("uncommitted schema");
        drop(transaction);
        drop(connection);
        assert_eq!(
            ProductionRelayV1::production_creation_state(&rolled_back_schema, config)
                .expect("rolled-back schema state"),
            ProductionRelayCreationStateV1::Incomplete
        );
        assert_resume_reopens(&rolled_back_schema, config);
    }

    #[test]
    fn resume_refuses_economic_recovery_foreign_and_unsafe_state() {
        let parent = owner_parent();
        let config = config_with(0x51, 64);

        let economic = parent.path().join("economic");
        let mut relay = ProductionRelayV1::create(&economic, config).expect("economic relay");
        let envelope = RelayEnvelopeV1 {
            network_id: [0x11; 32],
            message_type: crate::auth::message_type::QUOTE,
            session_id: [0x12; 32],
            route_id: [0x13; 32],
            sender_id: ParticipantId([0x14; 32]),
            recipient_id: ParticipantId([0x15; 32]),
            sender_role: crate::SenderRoleV1::Solver,
            sequence: 0,
            previous_transcript_hash: ZERO_DIGEST,
            payload: vec![1],
            expiry: crate::TimelockSpec::TimestampSeconds { value: 1 },
            policy_version: 1,
            roster_snapshot: [0x16; 32],
            signature: [0; 64],
        };
        relay
            .submit(&envelope.canonical_bytes().expect("canonical envelope"))
            .expect("store economic row");
        drop(relay);
        assert!(ProductionRelayV1::production_creation_state(&economic, config).is_err());
        assert!(ProductionRelayV1::resume_create_production(&economic, config).is_err());

        let recovery = parent.path().join("recovery");
        publish_lock(&recovery, config);
        drop(
            create_database(&recovery, config, 2, [0x77; 32], false)
                .expect("incomplete recovery database"),
        );
        assert!(ProductionRelayV1::production_creation_state(&recovery, config).is_err());

        let wrong_identity = parent.path().join("wrong-identity");
        publish_identity(&wrong_identity, config);
        assert!(ProductionRelayV1::production_creation_state(
            &wrong_identity,
            config_with(0x52, 64)
        )
        .is_err());

        let wrong_quota = parent.path().join("wrong-quota");
        drop(ProductionRelayV1::create(&wrong_quota, config).expect("quota relay"));
        assert!(
            ProductionRelayV1::production_creation_state(&wrong_quota, config_with(0x51, 63))
                .is_err()
        );

        let foreign = parent.path().join("foreign");
        create_root(&foreign).expect("foreign root");
        File::create(foreign.join("foreign-file")).expect("foreign file");
        assert!(ProductionRelayV1::production_creation_state(&foreign, config).is_err());

        let loss_marker = parent.path().join("loss-marker");
        publish_identity(&loss_marker, config);
        File::create(loss_marker.join(RELAY_DATABASE_LOSS_MARKER_NAME)).expect("loss marker");
        assert!(ProductionRelayV1::production_creation_state(&loss_marker, config).is_err());

        let partial_schema = parent.path().join("partial-schema");
        publish_empty_database(&partial_schema, config);
        let partial_path = partial_schema.join(RELAY_DATABASE_FILE_NAME);
        let connection = Connection::open(&partial_path).expect("partial database");
        connection
            .execute_batch("CREATE TABLE foreign_state (value INTEGER) STRICT;")
            .expect("partial committed schema");
        drop(connection);
        assert!(ProductionRelayV1::production_creation_state(&partial_schema, config).is_err());

        let unsafe_mode = parent.path().join("unsafe-mode");
        publish_identity(&unsafe_mode, config);
        fs::set_permissions(
            unsafe_mode.join(RELAY_IDENTITY_FILE_NAME),
            fs::Permissions::from_mode(0o640),
        )
        .expect("unsafe identity mode");
        assert!(ProductionRelayV1::production_creation_state(&unsafe_mode, config).is_err());

        let hard_link = parent.path().join("hard-link");
        publish_identity(&hard_link, config);
        fs::hard_link(
            hard_link.join(RELAY_IDENTITY_FILE_NAME),
            parent.path().join("identity-alias"),
        )
        .expect("identity hard link");
        assert!(ProductionRelayV1::production_creation_state(&hard_link, config).is_err());

        let real_root = parent.path().join("real-root");
        create_root(&real_root).expect("real root");
        let linked_root = parent.path().join("linked-root");
        symlink(&real_root, &linked_root).expect("root symlink");
        assert!(ProductionRelayV1::production_creation_state(&linked_root, config).is_err());
    }
}
