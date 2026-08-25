//! Authenticated Relay database reconstruction.
//!
//! Database loss never falls back to opening an empty queue and never scans
//! arbitrary files. A caller must explicitly assemble candidates from one of
//! the two allowed availability authorities: a participant's durable
//! Store/outbox, or a public-chain observation. This module treats the source
//! label and source-record digest as provenance only; authenticity is decided
//! independently by replaying the complete recipient pipeline: canonical
//! codec, allow-listed route scope, roster membership/role, BIP340 signature,
//! sequence and transcript continuity. Only the resulting opaque batch can be
//! consumed by [`crate::production::ProductionRelayV1::reconstruct`].
//!
//! The Relay still does not interpret payloads or decide an outcome. Public
//! chain evidence is verified by the chain adapter before it becomes an input
//! candidate; this boundary then verifies the sender-authenticated Relay
//! envelope embedded in that retained evidence.

use std::collections::{BTreeMap, BTreeSet};

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use kaystra_core::types::Digest32;

use crate::auth::{
    accept_envelope, AuthRefusal, RecipientContextV1, RosterRegistryV1, TranscriptStateV1,
};
use crate::server::IdempotencyKeyV1;
use crate::{EnvelopeError, RelayEnvelopeV1, TimelockSpec};

const BATCH_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-RECOVERY-BATCH/V1\0";
const SOURCE_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-RECOVERY-SOURCES/V1\0";

/// The only availability sources from which a lost Relay database may be
/// reconstructed. The enum is deliberately closed.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum RecoverySourceKindV1 {
    /// Exact sender bytes retained by a participant Store/outbox.
    ParticipantStoreOutbox,
    /// Exact sender bytes retained in authenticated public-chain evidence.
    PublicChain,
}

impl RecoverySourceKindV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::ParticipantStoreOutbox => 1,
            Self::PublicChain => 2,
        }
    }

    pub(crate) const fn mask(self) -> u8 {
        1 << (self.tag() - 1)
    }
}

/// One exact candidate obtained from an allowed source.
///
/// The source digest binds the participant Store/outbox record or the public
/// chain evidence record. It is retained for audit, but it does not replace
/// sender authentication: [`authenticate_recovery_sources_v1`] always runs
/// the complete recipient pipeline over `canonical_envelope`.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryCandidateV1 {
    source: RecoverySourceKindV1,
    source_record_digest: Digest32,
    canonical_envelope: Vec<u8>,
}

impl core::fmt::Debug for RecoveryCandidateV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RecoveryCandidateV1")
            .field("source", &self.source)
            .field("source_record_digest", &self.source_record_digest)
            .field("canonical_envelope", &"[redacted]")
            .finish()
    }
}

impl RecoveryCandidateV1 {
    /// Candidate retained by a participant's authenticated Store/outbox.
    pub fn participant_store_outbox(
        source_record_digest: Digest32,
        canonical_envelope: Vec<u8>,
    ) -> Result<Self, RecoveryError> {
        Self::new(
            RecoverySourceKindV1::ParticipantStoreOutbox,
            source_record_digest,
            canonical_envelope,
        )
    }

    /// Candidate retained in authenticated public-chain evidence.
    pub fn public_chain(
        source_record_digest: Digest32,
        canonical_envelope: Vec<u8>,
    ) -> Result<Self, RecoveryError> {
        Self::new(
            RecoverySourceKindV1::PublicChain,
            source_record_digest,
            canonical_envelope,
        )
    }

    fn new(
        source: RecoverySourceKindV1,
        source_record_digest: Digest32,
        canonical_envelope: Vec<u8>,
    ) -> Result<Self, RecoveryError> {
        if source_record_digest == [0_u8; 32] {
            return Err(RecoveryError::InvalidSourceBinding);
        }
        Ok(Self {
            source,
            source_record_digest,
            canonical_envelope,
        })
    }
}

/// One allow-listed recipient/session/route scope and its authenticated clock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RecoveryScopeV1 {
    context: RecipientContextV1,
    now: TimelockSpec,
}

impl RecoveryScopeV1 {
    /// Creates an allow-listed scope. A candidate must match every context
    /// field exactly and its expiry must compare in the same clock domain.
    pub const fn new(context: RecipientContextV1, now: TimelockSpec) -> Self {
        Self { context, now }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ScopeKeyV1 {
    network_id: Digest32,
    session_id: Digest32,
    route_id: Digest32,
    recipient_id: [u8; 32],
}

impl ScopeKeyV1 {
    fn from_context(context: &RecipientContextV1) -> Self {
        Self {
            network_id: context.network_id,
            session_id: context.session_id,
            route_id: context.route_id,
            recipient_id: context.recipient_id.0,
        }
    }

    fn from_envelope(envelope: &RelayEnvelopeV1) -> Self {
        Self {
            network_id: envelope.network_id,
            session_id: envelope.session_id,
            route_id: envelope.route_id,
            recipient_id: envelope.recipient_id.0,
        }
    }
}

struct AggregatedCandidateV1 {
    scope: ScopeKeyV1,
    bytes: Vec<u8>,
    sources: BTreeSet<(u8, Digest32)>,
}

/// One authenticated row ready for an all-or-nothing reconstruction.
pub(crate) struct AuthenticatedRecoveryEntryV1 {
    pub(crate) key: IdempotencyKeyV1,
    pub(crate) bytes: Vec<u8>,
    pub(crate) digest: Digest32,
    pub(crate) source_mask: u8,
    pub(crate) source_commitment: Digest32,
}

/// Opaque, one-shot set of fully authenticated Relay rows.
///
/// It intentionally exposes only public metadata. Exact envelope bytes can be
/// consumed only by the production reconstruction transaction.
pub struct AuthenticatedRecoveryBatchV1 {
    pub(crate) entries: Vec<AuthenticatedRecoveryEntryV1>,
    digest: Digest32,
}

impl core::fmt::Debug for AuthenticatedRecoveryBatchV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthenticatedRecoveryBatchV1")
            .field("entry_count", &self.entries.len())
            .field("digest", &self.digest)
            .finish()
    }
}

impl AuthenticatedRecoveryBatchV1 {
    /// Number of distinct idempotency rows in the batch.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no authenticated row was supplied.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Digest binding the exact rows and their authenticated provenance.
    pub const fn digest(&self) -> &Digest32 {
        &self.digest
    }
}

/// Fail-closed recovery authentication errors. No variant carries payloads.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum RecoveryError {
    /// An empty set authenticates no retained availability source.
    #[error("recovery requires at least one authenticated source")]
    EmptySourceSet,
    /// A Store/outbox or chain evidence binding may not be the null digest.
    #[error("invalid recovery source binding")]
    InvalidSourceBinding,
    /// More candidates than the production Relay's hard capacity.
    #[error("recovery source set exceeds the relay bound")]
    TooManyCandidates,
    /// Two clock entries attempted to define one exact recovery scope.
    #[error("duplicate recovery scope")]
    DuplicateScope,
    /// The candidate does not belong to an explicitly allow-listed scope.
    #[error("recovery candidate is outside the allowed scopes")]
    UnknownScope,
    /// A candidate did not decode canonically.
    #[error("codec: {0}")]
    Codec(EnvelopeError),
    /// The same idempotency key was supplied with different exact bytes.
    #[error("conflicting recovery candidates")]
    ConflictingCandidate,
    /// Full recipient authentication rejected the candidate.
    #[error("recovery authentication failed: {0}")]
    Authentication(AuthRefusal),
    /// The fixed BLAKE2b-256 instance could not be initialized.
    #[error("recovery digest initialization failed")]
    DigestInitialization,
}

/// Authenticates all allowed-source candidates and returns a one-shot batch.
///
/// Exact duplicates from Store/outbox and chain evidence collapse into one
/// row with both source bindings committed. Same-key/different-byte input,
/// gaps, replay, expiry, foreign routes and signature failures abort the whole
/// batch; no partial result is returned.
pub fn authenticate_recovery_sources_v1(
    candidates: Vec<RecoveryCandidateV1>,
    scopes: &[RecoveryScopeV1],
    rosters: &RosterRegistryV1,
) -> Result<AuthenticatedRecoveryBatchV1, RecoveryError> {
    if candidates.is_empty() {
        return Err(RecoveryError::EmptySourceSet);
    }
    if candidates.len() > crate::server::MAX_STORED_ENVELOPES {
        return Err(RecoveryError::TooManyCandidates);
    }

    let mut scope_states = BTreeMap::<ScopeKeyV1, (RecoveryScopeV1, TranscriptStateV1)>::new();
    for scope in scopes {
        let key = ScopeKeyV1::from_context(&scope.context);
        if scope_states
            .insert(key, (*scope, TranscriptStateV1::new()))
            .is_some()
        {
            return Err(RecoveryError::DuplicateScope);
        }
    }

    let mut aggregated = BTreeMap::<IdempotencyKeyV1, AggregatedCandidateV1>::new();
    for candidate in candidates {
        let envelope =
            RelayEnvelopeV1::decode(&candidate.canonical_envelope).map_err(RecoveryError::Codec)?;
        let canonical = envelope.canonical_bytes().map_err(RecoveryError::Codec)?;
        if canonical != candidate.canonical_envelope {
            return Err(RecoveryError::Codec(EnvelopeError::TrailingBytes));
        }
        let scope = ScopeKeyV1::from_envelope(&envelope);
        if !scope_states.contains_key(&scope) {
            return Err(RecoveryError::UnknownScope);
        }
        let key = IdempotencyKeyV1::of(&envelope);
        match aggregated.get_mut(&key) {
            Some(existing) => {
                if existing.bytes != canonical || existing.scope != scope {
                    return Err(RecoveryError::ConflictingCandidate);
                }
                existing
                    .sources
                    .insert((candidate.source.tag(), candidate.source_record_digest));
            }
            None => {
                let mut sources = BTreeSet::new();
                sources.insert((candidate.source.tag(), candidate.source_record_digest));
                aggregated.insert(
                    key,
                    AggregatedCandidateV1 {
                        scope,
                        bytes: canonical,
                        sources,
                    },
                );
            }
        }
    }

    let mut entries = Vec::with_capacity(aggregated.len());
    for (key, candidate) in aggregated {
        let (scope, state) = scope_states
            .get_mut(&candidate.scope)
            .ok_or(RecoveryError::UnknownScope)?;
        let accepted = accept_envelope(&candidate.bytes, &scope.context, rosters, state, scope.now)
            .map_err(RecoveryError::Authentication)?;
        if IdempotencyKeyV1::of(&accepted.envelope) != key {
            return Err(RecoveryError::ConflictingCandidate);
        }
        let (source_mask, source_commitment) = source_commitment(&candidate.sources)?;
        entries.push(AuthenticatedRecoveryEntryV1 {
            key,
            bytes: candidate.bytes,
            digest: accepted.digest,
            source_mask,
            source_commitment,
        });
    }

    let digest = batch_digest(&entries)?;
    Ok(AuthenticatedRecoveryBatchV1 { entries, digest })
}

fn source_commitment(sources: &BTreeSet<(u8, Digest32)>) -> Result<(u8, Digest32), RecoveryError> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| RecoveryError::DigestInitialization)?;
    hasher.update(SOURCE_DOMAIN);
    let mut mask = 0_u8;
    for (tag, digest) in sources {
        let kind = match *tag {
            1 => RecoverySourceKindV1::ParticipantStoreOutbox,
            2 => RecoverySourceKindV1::PublicChain,
            _ => return Err(RecoveryError::InvalidSourceBinding),
        };
        mask |= kind.mask();
        hasher.update(&[*tag]);
        hasher.update(digest);
    }
    let mut commitment = [0_u8; 32];
    hasher
        .finalize_variable(&mut commitment)
        .map_err(|_| RecoveryError::DigestInitialization)?;
    Ok((mask, commitment))
}

fn batch_digest(entries: &[AuthenticatedRecoveryEntryV1]) -> Result<Digest32, RecoveryError> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| RecoveryError::DigestInitialization)?;
    hasher.update(BATCH_DOMAIN);
    hasher.update(&(entries.len() as u64).to_be_bytes());
    for entry in entries {
        hasher.update(&entry.key.session_id);
        hasher.update(&entry.key.sender_id.0);
        hasher.update(&entry.key.recipient_id.0);
        hasher.update(&entry.key.sequence.to_be_bytes());
        hasher.update(&entry.digest);
        hasher.update(&[entry.source_mask]);
        hasher.update(&entry.source_commitment);
    }
    let mut digest = [0_u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| RecoveryError::DigestInitialization)?;
    Ok(digest)
}
