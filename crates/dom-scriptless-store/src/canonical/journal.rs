//! Structurally validated canonical journal envelopes.

use std::collections::BTreeMap;

use super::{
    is_zero, read_u16, read_u32, read_u64, storage_hash, ActiveVaultGenerationV1, ArtifactKindV1,
    AttemptRecordV1, BudgetChargeV1, CanonicalCodecError, EpochAdvancePayloadV1, ExposureRecordV1,
    ExposureStateV1, ExposureVersionIdV1, NonceDerivationAttemptV1, NonceIdentityV1,
    PermitRetirementV1, RestoreCompleteV1, RestoreManifestV1, RestorePendingIndexV1,
    RestoreRecordPayloadV1, SessionClaimV1, StorageHashDomainV1, TerminalReasonV1, TombstoneV1,
    UnauthenticatedAttemptRecordV1, UnauthenticatedEpochAdvancePayloadV1,
    UnauthenticatedExposureRecordV1, UnauthenticatedExposureVersionIdV1,
    UnauthenticatedNonceDerivationAttemptV1, UnauthenticatedRestoreCompleteV1,
    UnauthenticatedRestoreManifestV1, UnauthenticatedRestoreRecordPayloadV1,
    UnauthenticatedSessionClaimV1, UnauthenticatedTombstoneV1, VaultGenerationCoreV1,
    ATTEMPT_RECORD_LEN, EPOCH_ADVANCE_PAYLOAD_LEN, EXPOSURE_RECORD_MAX_LEN,
    EXPOSURE_RECORD_MIN_LEN, EXPOSURE_VERSION_ID_LEN, NONCE_DERIVATION_ATTEMPT_LEN,
    PERMIT_RETIREMENT_LEN, RESTORE_COMPLETE_LEN, RESTORE_MANIFEST_LEN, RESTORE_RECORD_PAYLOAD_LEN,
    SESSION_CLAIM_LEN, TOMBSTONE_LEN,
};

#[cfg(test)]
use super::tombstone::TerminalEvidenceV1;

const JOURNAL_MAGIC: &[u8; 8] = b"DOMNVJR1";

/// Maximum canonical journal payload length.
pub const JOURNAL_PAYLOAD_MAX_LEN: usize = 16_384;
/// Minimum canonical journal-entry length for an empty payload.
pub const JOURNAL_ENTRY_MIN_LEN: usize = 88;
/// Maximum canonical journal-entry length.
pub const JOURNAL_ENTRY_MAX_LEN: usize = JOURNAL_ENTRY_MIN_LEN + JOURNAL_PAYLOAD_MAX_LEN;

/// Closed journal-entry-kind registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum JournalEntryKindV1 {
    /// Reserve a lifetime-unique session identity.
    Reserve = 0x01,
    /// Persist a computation attempt before opening a secret.
    ComputationAttempt = 0x02,
    /// Persist commitment bytes.
    CommitmentPersisted = 0x03,
    /// Advance an immutable exposure state.
    ExposureAuthorized = 0x04,
    /// Persist reveal bytes.
    RevealPersisted = 0x05,
    /// Persist a partial exposure and consumed tombstone.
    PartialConsumed = 0x06,
    /// Persist an authenticated-abort tombstone.
    AbortConsumed = 0x07,
    /// Persist a burned tombstone.
    Burned = 0x08,
    /// Begin a restore transaction.
    RestoreBegin = 0x09,
    /// Persist one restore projection.
    RestoreRecord = 0x0a,
    /// Complete a restore transaction.
    RestoreComplete = 0x0b,
    /// Advance the nonce epoch and generation.
    EpochAdvance = 0x0c,
    /// Carry one already charged budget record into successor history.
    BudgetCarryForward = 0x0d,
    /// Carry one retired permit into successor history.
    PermitRetirementCarryForward = 0x0e,
}

impl TryFrom<u8> for JournalEntryKindV1 {
    type Error = CanonicalCodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Reserve),
            0x02 => Ok(Self::ComputationAttempt),
            0x03 => Ok(Self::CommitmentPersisted),
            0x04 => Ok(Self::ExposureAuthorized),
            0x05 => Ok(Self::RevealPersisted),
            0x06 => Ok(Self::PartialConsumed),
            0x07 => Ok(Self::AbortConsumed),
            0x08 => Ok(Self::Burned),
            0x09 => Ok(Self::RestoreBegin),
            0x0a => Ok(Self::RestoreRecord),
            0x0b => Ok(Self::RestoreComplete),
            0x0c => Ok(Self::EpochAdvance),
            0x0d => Ok(Self::BudgetCarryForward),
            0x0e => Ok(Self::PermitRetirementCarryForward),
            _ => Err(CanonicalCodecError::InvalidEncoding),
        }
    }
}

/// Structurally parsed journal outer envelope.
///
/// This type validates only the retained outer framing. Entry-kind payload
/// semantics and both digests remain unauthenticated until parsed by the
/// complete journal layer and verified through the pinned DOM hash boundary.
pub struct UnauthenticatedJournalEnvelopeV1<'a> {
    bytes: &'a [u8],
    sequence: u64,
    kind: JournalEntryKindV1,
    payload_length: usize,
}

impl<'a> UnauthenticatedJournalEnvelopeV1<'a> {
    /// Parses exact bounded outer bytes without allocating from the payload length.
    pub fn parse_outer(input: &'a [u8]) -> Result<Self, CanonicalCodecError> {
        if !(JOURNAL_ENTRY_MIN_LEN..=JOURNAL_ENTRY_MAX_LEN).contains(&input.len())
            || &input[..8] != JOURNAL_MAGIC
            || read_u16(&input[8..10]) != 1
            || input[51] != 0
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let sequence = read_u64(&input[10..18]);
        let predecessor_is_zero = is_zero(&input[18..50]);
        let kind = JournalEntryKindV1::try_from(input[50])?;
        let payload_length = usize::try_from(read_u32(&input[52..56]))
            .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        let expected_length = JOURNAL_ENTRY_MIN_LEN
            .checked_add(payload_length)
            .ok_or(CanonicalCodecError::InvalidEncoding)?;
        if sequence == 0
            || predecessor_is_zero != (sequence == 1)
            || payload_length > JOURNAL_PAYLOAD_MAX_LEN
            || input.len() != expected_length
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes: input,
            sequence,
            kind,
            payload_length,
        })
    }

    /// Returns the exact unauthenticated journal bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the nonzero global journal sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the closed entry kind.
    pub const fn kind(&self) -> JournalEntryKindV1 {
        self.kind
    }

    /// Returns the unauthenticated predecessor digest or sequence-one zero sentinel.
    pub fn predecessor_digest(&self) -> &'a [u8] {
        &self.bytes[18..50]
    }

    /// Returns the structurally bounded but otherwise unparsed payload.
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[56..56 + self.payload_length]
    }

    /// Returns the unauthenticated journal-entry digest.
    pub fn entry_digest(&self) -> &'a [u8] {
        &self.bytes[56 + self.payload_length..]
    }
}

/// Structurally parsed complete journal entry with a kind-specific payload.
pub struct UnauthenticatedJournalEntryV1<'a> {
    envelope: UnauthenticatedJournalEnvelopeV1<'a>,
    payload: UnauthenticatedJournalPayloadV1<'a>,
}

impl<'a> UnauthenticatedJournalEntryV1<'a> {
    /// Parses the outer envelope and the complete payload assigned to its kind.
    pub fn parse_structural(input: &'a [u8]) -> Result<Self, CanonicalCodecError> {
        let envelope = UnauthenticatedJournalEnvelopeV1::parse_outer(input)?;
        let payload = UnauthenticatedJournalPayloadV1::parse(envelope.kind(), envelope.payload())?;
        Ok(Self { envelope, payload })
    }

    /// Returns the parsed outer envelope.
    pub const fn envelope(&self) -> &UnauthenticatedJournalEnvelopeV1<'a> {
        &self.envelope
    }

    /// Returns the structurally parsed kind-specific payload.
    pub const fn payload(&self) -> &UnauthenticatedJournalPayloadV1<'a> {
        &self.payload
    }
}

/// Structurally parsed journal payload selected by the closed entry-kind registry.
pub enum UnauthenticatedJournalPayloadV1<'a> {
    /// Complete variable-length SessionClaim plus BudgetCharge reservation.
    Reserve(UnauthenticatedReservePayloadV1),
    /// Closed derivation or later-stage attempt payload.
    ComputationAttempt(UnauthenticatedComputationAttemptV1),
    /// Persisted sequence-one commitment exposure.
    CommitmentPersisted(UnauthenticatedExposureRecordV1<'a>),
    /// Immutable exposure-state transition.
    ExposureAuthorized(UnauthenticatedExposureAuthorizationPayloadV1<'a>),
    /// Persisted sequence-two reveal exposure.
    RevealPersisted(UnauthenticatedExposureRecordV1<'a>),
    /// Persisted partial exposure plus consumed tombstone.
    PartialConsumed(UnauthenticatedPartialConsumedPayloadV1<'a>),
    /// Authenticated-abort tombstone.
    AbortConsumed(UnauthenticatedTombstoneV1),
    /// Burned tombstone.
    Burned(UnauthenticatedTombstoneV1),
    /// Complete restore manifest.
    RestoreBegin(UnauthenticatedRestoreManifestV1),
    /// One restore terminal projection.
    RestoreRecord(UnauthenticatedRestoreRecordPayloadV1),
    /// Complete restore-completion payload and full digest.
    RestoreComplete(UnauthenticatedRestoreCompletePayloadV1),
    /// Complete epoch-advance payload.
    EpochAdvance(UnauthenticatedEpochAdvancePayloadV1),
    /// Complete previously authenticated budget charge.
    BudgetCarryForward(BudgetChargeV1),
    /// Complete permit-retirement collision evidence.
    PermitRetirementCarryForward(PermitRetirementV1),
}

impl<'a> UnauthenticatedJournalPayloadV1<'a> {
    fn parse(kind: JournalEntryKindV1, payload: &'a [u8]) -> Result<Self, CanonicalCodecError> {
        match kind {
            JournalEntryKindV1::Reserve => Ok(Self::Reserve(
                UnauthenticatedReservePayloadV1::parse_structural(payload)?,
            )),
            JournalEntryKindV1::ComputationAttempt => Ok(Self::ComputationAttempt(
                UnauthenticatedComputationAttemptV1::parse_structural(payload)?,
            )),
            JournalEntryKindV1::CommitmentPersisted => {
                let exposure = UnauthenticatedExposureRecordV1::parse_structural(payload)?;
                if exposure.state() != ExposureStateV1::Persisted
                    || exposure.artifact() != ArtifactKindV1::Commitment
                    || exposure.sequence() != 1
                {
                    return Err(CanonicalCodecError::InvalidEncoding);
                }
                Ok(Self::CommitmentPersisted(exposure))
            }
            JournalEntryKindV1::ExposureAuthorized => Ok(Self::ExposureAuthorized(
                UnauthenticatedExposureAuthorizationPayloadV1::parse_structural(payload)?,
            )),
            JournalEntryKindV1::RevealPersisted => {
                let exposure = UnauthenticatedExposureRecordV1::parse_structural(payload)?;
                if exposure.state() != ExposureStateV1::Persisted
                    || exposure.artifact() != ArtifactKindV1::Reveal
                    || exposure.sequence() != 2
                {
                    return Err(CanonicalCodecError::InvalidEncoding);
                }
                Ok(Self::RevealPersisted(exposure))
            }
            JournalEntryKindV1::PartialConsumed => Ok(Self::PartialConsumed(
                UnauthenticatedPartialConsumedPayloadV1::parse_structural(payload)?,
            )),
            JournalEntryKindV1::AbortConsumed => {
                exact_payload_length(payload, TOMBSTONE_LEN)?;
                let tombstone = UnauthenticatedTombstoneV1::parse_structural(payload)?;
                if tombstone.reason() != TerminalReasonV1::AbortConsumed {
                    return Err(CanonicalCodecError::InvalidEncoding);
                }
                Ok(Self::AbortConsumed(tombstone))
            }
            JournalEntryKindV1::Burned => {
                exact_payload_length(payload, TOMBSTONE_LEN)?;
                let tombstone = UnauthenticatedTombstoneV1::parse_structural(payload)?;
                if tombstone.reason() != TerminalReasonV1::Burned {
                    return Err(CanonicalCodecError::InvalidEncoding);
                }
                Ok(Self::Burned(tombstone))
            }
            JournalEntryKindV1::RestoreBegin => {
                exact_payload_length(payload, RESTORE_MANIFEST_LEN)?;
                Ok(Self::RestoreBegin(
                    UnauthenticatedRestoreManifestV1::parse_structural(payload)?,
                ))
            }
            JournalEntryKindV1::RestoreRecord => {
                exact_payload_length(payload, RESTORE_RECORD_PAYLOAD_LEN)?;
                Ok(Self::RestoreRecord(
                    UnauthenticatedRestoreRecordPayloadV1::parse_structural(payload)?,
                ))
            }
            JournalEntryKindV1::RestoreComplete => Ok(Self::RestoreComplete(
                UnauthenticatedRestoreCompletePayloadV1::parse_structural(payload)?,
            )),
            JournalEntryKindV1::EpochAdvance => {
                exact_payload_length(payload, EPOCH_ADVANCE_PAYLOAD_LEN)?;
                Ok(Self::EpochAdvance(
                    UnauthenticatedEpochAdvancePayloadV1::parse_structural(payload)?,
                ))
            }
            JournalEntryKindV1::BudgetCarryForward => Ok(Self::BudgetCarryForward(
                BudgetChargeV1::from_bytes(payload)?,
            )),
            JournalEntryKindV1::PermitRetirementCarryForward => {
                exact_payload_length(payload, PERMIT_RETIREMENT_LEN)?;
                Ok(Self::PermitRetirementCarryForward(
                    PermitRetirementV1::from_bytes(payload)?,
                ))
            }
        }
    }
}

/// Structurally parsed complete NAR-DC-P1-004 Reserve payload.
pub struct UnauthenticatedReservePayloadV1 {
    bytes: Vec<u8>,
    claim: UnauthenticatedSessionClaimV1,
    charge: BudgetChargeV1,
}

impl UnauthenticatedReservePayloadV1 {
    /// Parses exact variable framing and cross-binds claim, charge, and authority.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        if !matches!(input.len(), 1_071 | 1_104) {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let claim = UnauthenticatedSessionClaimV1::parse_structural(&input[..SESSION_CLAIM_LEN])?;
        let charge = BudgetChargeV1::from_bytes(&input[SESSION_CLAIM_LEN..])?;
        let authority = charge.reservation_authority();
        let identity = authority.nonce_identity()?;
        if claim.identity().as_bytes() != identity.as_bytes()
            || authority.as_bytes().len() + 221 != input.len()
        {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: input.to_vec(),
            claim,
            charge,
        })
    }

    /// Returns the exact canonical payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the lifetime session claim.
    pub const fn claim(&self) -> &UnauthenticatedSessionClaimV1 {
        &self.claim
    }

    /// Returns the embedded append-only budget charge.
    pub const fn charge(&self) -> &BudgetChargeV1 {
        &self.charge
    }
}

/// Closed stage-specific computation-attempt payload.
pub enum UnauthenticatedComputationAttemptV1 {
    /// Exact 201-byte nonce-derivation wrapper.
    NonceDerivation(Box<UnauthenticatedNonceDerivationAttemptV1>),
    /// Exact 193-byte reveal or partial-signature attempt.
    LaterStage(Box<UnauthenticatedAttemptRecordV1>),
}

impl UnauthenticatedComputationAttemptV1 {
    /// Parses the exact stage-specific attempt body.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        match input.len() {
            NONCE_DERIVATION_ATTEMPT_LEN => Ok(Self::NonceDerivation(Box::new(
                UnauthenticatedNonceDerivationAttemptV1::parse_structural(input)?,
            ))),
            ATTEMPT_RECORD_LEN => {
                let attempt = UnauthenticatedAttemptRecordV1::parse_structural(input)?;
                if attempt.artifact() == ArtifactKindV1::Commitment {
                    return Err(CanonicalCodecError::InvalidEncoding);
                }
                Ok(Self::LaterStage(Box::new(attempt)))
            }
            _ => Err(CanonicalCodecError::InvalidEncoding),
        }
    }

    /// Returns the later-stage attempt when this is not nonce derivation.
    pub const fn later_stage_attempt(&self) -> Option<&UnauthenticatedAttemptRecordV1> {
        match self {
            Self::NonceDerivation(_) => None,
            Self::LaterStage(attempt) => Some(attempt),
        }
    }

    /// Returns the derivation wrapper when this is the commitment attempt.
    pub const fn derivation_attempt(&self) -> Option<&UnauthenticatedNonceDerivationAttemptV1> {
        match self {
            Self::NonceDerivation(wrapper) => Some(wrapper),
            Self::LaterStage(_) => None,
        }
    }

    /// Returns the canonical nonce identity from the inner attempt.
    pub const fn identity(&self) -> &NonceIdentityV1 {
        match self {
            Self::NonceDerivation(wrapper) => wrapper.attempt().identity(),
            Self::LaterStage(attempt) => attempt.identity(),
        }
    }

    /// Returns the closed artifact kind from the inner attempt.
    pub const fn artifact(&self) -> ArtifactKindV1 {
        match self {
            Self::NonceDerivation(wrapper) => wrapper.attempt().artifact(),
            Self::LaterStage(attempt) => attempt.artifact(),
        }
    }

    /// Returns the expected lifecycle revision from the inner attempt.
    pub fn expected_lifecycle_revision(&self) -> u64 {
        match self {
            Self::NonceDerivation(wrapper) => wrapper.attempt().expected_lifecycle_revision(),
            Self::LaterStage(attempt) => attempt.expected_lifecycle_revision(),
        }
    }

    /// Returns the authenticated or retained inner attempt digest.
    pub fn attempt_digest(&self) -> &[u8] {
        match self {
            Self::NonceDerivation(wrapper) => wrapper.attempt().attempt_digest(),
            Self::LaterStage(attempt) => attempt.attempt_digest(),
        }
    }
}

/// Structurally parsed predecessor/successor exposure transition payload.
pub struct UnauthenticatedExposureAuthorizationPayloadV1<'a> {
    bytes: &'a [u8],
    predecessor: UnauthenticatedExposureVersionIdV1,
    successor: UnauthenticatedExposureRecordV1<'a>,
}

impl<'a> UnauthenticatedExposureAuthorizationPayloadV1<'a> {
    /// Parses exact framing and every transition rule expressible in the payload.
    pub fn parse_structural(input: &'a [u8]) -> Result<Self, CanonicalCodecError> {
        let minimum = 159_usize
            .checked_add(EXPOSURE_RECORD_MIN_LEN)
            .ok_or(CanonicalCodecError::InvalidEncoding)?;
        let maximum = 159_usize
            .checked_add(EXPOSURE_RECORD_MAX_LEN)
            .ok_or(CanonicalCodecError::InvalidEncoding)?;
        if !(minimum..=maximum).contains(&input.len()) {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let predecessor = UnauthenticatedExposureVersionIdV1::parse_structural(
            &input[..EXPOSURE_VERSION_ID_LEN],
        )?;
        let successor_length = usize::try_from(read_u32(&input[155..159]))
            .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        if successor_length != input.len() - 159 {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let successor = UnauthenticatedExposureRecordV1::parse_structural(&input[159..])?;
        let state_transition = matches!(
            (predecessor.state(), successor.state()),
            (ExposureStateV1::Persisted, ExposureStateV1::Authorized)
                | (ExposureStateV1::Authorized, ExposureStateV1::Spent)
        );
        let revision_increment = if predecessor.artifact() == ArtifactKindV1::PartialSignature
            && predecessor.state() == ExposureStateV1::Persisted
        {
            2
        } else {
            1
        };
        let expected_revision = predecessor
            .lifecycle_revision()
            .checked_add(revision_increment)
            .ok_or(CanonicalCodecError::InvalidEncoding)?;
        if !state_transition
            || predecessor.identity().as_bytes() != successor.identity().as_bytes()
            || predecessor.sequence() != successor.sequence()
            || predecessor.artifact() != successor.artifact()
            || successor.lifecycle_revision() != expected_revision
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes: input,
            predecessor,
            successor,
        })
    }

    /// Returns the exact unauthenticated payload bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the predecessor exposure-version identifier.
    pub const fn predecessor(&self) -> &UnauthenticatedExposureVersionIdV1 {
        &self.predecessor
    }

    /// Returns the successor exposure record.
    pub const fn successor(&self) -> &UnauthenticatedExposureRecordV1<'a> {
        &self.successor
    }
}

/// Structurally parsed partial-consumption payload.
pub struct UnauthenticatedPartialConsumedPayloadV1<'a> {
    bytes: &'a [u8],
    partial: UnauthenticatedExposureRecordV1<'a>,
    tombstone: UnauthenticatedTombstoneV1,
}

impl<'a> UnauthenticatedPartialConsumedPayloadV1<'a> {
    /// Parses the persisted partial and collision-free consumed tombstone relation.
    pub fn parse_structural(input: &'a [u8]) -> Result<Self, CanonicalCodecError> {
        let minimum = 4_usize
            .checked_add(EXPOSURE_RECORD_MIN_LEN)
            .and_then(|length| length.checked_add(TOMBSTONE_LEN))
            .ok_or(CanonicalCodecError::InvalidEncoding)?;
        let maximum = 4_usize
            .checked_add(EXPOSURE_RECORD_MAX_LEN)
            .and_then(|length| length.checked_add(TOMBSTONE_LEN))
            .ok_or(CanonicalCodecError::InvalidEncoding)?;
        if !(minimum..=maximum).contains(&input.len()) {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let partial_length = usize::try_from(read_u32(&input[..4]))
            .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        if partial_length
            .checked_add(4 + TOMBSTONE_LEN)
            .ok_or(CanonicalCodecError::InvalidEncoding)?
            != input.len()
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let partial =
            UnauthenticatedExposureRecordV1::parse_structural(&input[4..4 + partial_length])?;
        let tombstone = UnauthenticatedTombstoneV1::parse_structural(&input[4 + partial_length..])?;
        let expected_tombstone_revision = partial
            .lifecycle_revision()
            .checked_add(1)
            .ok_or(CanonicalCodecError::InvalidEncoding)?;
        if partial.state() != ExposureStateV1::Persisted
            || partial.artifact() != ArtifactKindV1::PartialSignature
            || partial.sequence() != 3
            || tombstone.reason() != TerminalReasonV1::Consumed
            || partial.identity().as_bytes() != tombstone.identity().as_bytes()
            || tombstone.terminal_revision() != expected_tombstone_revision
            || partial.record_digest() != tombstone.related_exposure_digest()
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes: input,
            partial,
            tombstone,
        })
    }

    /// Returns the exact unauthenticated payload bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the persisted partial exposure.
    pub const fn partial(&self) -> &UnauthenticatedExposureRecordV1<'a> {
        &self.partial
    }

    /// Returns the consumed tombstone.
    pub const fn tombstone(&self) -> &UnauthenticatedTombstoneV1 {
        &self.tombstone
    }
}

/// Structurally parsed 130-byte restore-completion journal payload.
pub struct UnauthenticatedRestoreCompletePayloadV1 {
    bytes: [u8; RESTORE_COMPLETE_LEN + 32],
    completion: UnauthenticatedRestoreCompleteV1,
}

impl UnauthenticatedRestoreCompletePayloadV1 {
    /// Parses exact bytes and the embedded eight-byte digest-prefix equality.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = super::exact::<{ RESTORE_COMPLETE_LEN + 32 }>(input)?;
        let completion =
            UnauthenticatedRestoreCompleteV1::parse_structural(&bytes[..RESTORE_COMPLETE_LEN])?;
        if completion.completion_digest_prefix() != &bytes[RESTORE_COMPLETE_LEN..106] {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self { bytes, completion })
    }

    /// Returns the exact unauthenticated payload bytes.
    pub const fn as_bytes(&self) -> &[u8; RESTORE_COMPLETE_LEN + 32] {
        &self.bytes
    }

    /// Returns the embedded 98-byte completion record.
    pub const fn completion(&self) -> &UnauthenticatedRestoreCompleteV1 {
        &self.completion
    }

    /// Returns the unauthenticated full completion digest.
    pub fn full_completion_digest(&self) -> &[u8] {
        &self.bytes[RESTORE_COMPLETE_LEN..]
    }
}

/// Authenticated predecessor/successor exposure-transition payload.
#[derive(Clone, Eq, PartialEq)]
pub struct ExposureAuthorizationPayloadV1 {
    bytes: Vec<u8>,
    predecessor: ExposureVersionIdV1,
    successor: ExposureRecordV1,
}

impl ExposureAuthorizationPayloadV1 {
    /// Constructs an exact immutable exposure transition.
    pub fn new(
        predecessor: &ExposureRecordV1,
        successor: &ExposureRecordV1,
        intervening_tombstone: Option<&TombstoneV1>,
    ) -> Result<Self, CanonicalCodecError> {
        successor.validate_successor(predecessor, intervening_tombstone)?;
        let predecessor = predecessor.version_id();
        let successor_length = u32::try_from(successor.as_bytes().len())
            .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        let complete_length = 159_usize
            .checked_add(successor.as_bytes().len())
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        let mut bytes = vec![0_u8; complete_length];
        bytes[..155].copy_from_slice(predecessor.as_bytes());
        bytes[155..159].copy_from_slice(&successor_length.to_le_bytes());
        bytes[159..].copy_from_slice(successor.as_bytes());
        Ok(Self {
            bytes,
            predecessor,
            successor: successor.clone(),
        })
    }

    /// Parses and authenticates a transition against the referenced predecessor.
    pub fn from_bytes(
        input: &[u8],
        predecessor_record: &ExposureRecordV1,
        intervening_tombstone: Option<&TombstoneV1>,
    ) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedExposureAuthorizationPayloadV1::parse_structural(input)?;
        let successor = ExposureRecordV1::from_bytes(structural.successor().as_bytes())?;
        let expected = Self::new(predecessor_record, &successor, intervening_tombstone)?;
        if input != expected.as_bytes() {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(expected)
    }

    /// Returns the exact authenticated payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the authenticated predecessor identifier.
    pub const fn predecessor(&self) -> &ExposureVersionIdV1 {
        &self.predecessor
    }

    /// Returns the authenticated successor record.
    pub const fn successor(&self) -> &ExposureRecordV1 {
        &self.successor
    }
}

/// Authenticated persisted-partial and consumed-tombstone payload.
#[derive(Clone, Eq, PartialEq)]
pub struct PartialConsumedPayloadV1 {
    bytes: Vec<u8>,
    partial: ExposureRecordV1,
    tombstone: TombstoneV1,
}

impl PartialConsumedPayloadV1 {
    /// Constructs the partial-consumption payload from its exact lifecycle evidence.
    pub fn new(
        attempt: &AttemptRecordV1,
        preceding_reveal: &ExposureRecordV1,
        partial: &ExposureRecordV1,
        tombstone: &TombstoneV1,
    ) -> Result<Self, CanonicalCodecError> {
        partial.validate_persisted_context(attempt, Some(preceding_reveal))?;
        if partial.artifact() != ArtifactKindV1::PartialSignature
            || tombstone.triggering_attempt_digest() != attempt.attempt_digest()
        {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        tombstone.validate_intervening_consumed(partial)?;
        let partial_length = u32::try_from(partial.as_bytes().len())
            .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        let complete_length = 4_usize
            .checked_add(partial.as_bytes().len())
            .and_then(|length| length.checked_add(TOMBSTONE_LEN))
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        let mut bytes = vec![0_u8; complete_length];
        bytes[..4].copy_from_slice(&partial_length.to_le_bytes());
        bytes[4..4 + partial.as_bytes().len()].copy_from_slice(partial.as_bytes());
        bytes[4 + partial.as_bytes().len()..].copy_from_slice(tombstone.as_bytes());
        Ok(Self {
            bytes,
            partial: partial.clone(),
            tombstone: tombstone.clone(),
        })
    }

    /// Parses and authenticates the payload against its attempt and prior reveal.
    pub fn from_bytes(
        input: &[u8],
        attempt: &AttemptRecordV1,
        preceding_reveal: &ExposureRecordV1,
    ) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedPartialConsumedPayloadV1::parse_structural(input)?;
        let partial = ExposureRecordV1::from_bytes(structural.partial().as_bytes())?;
        let tombstone = TombstoneV1::from_bytes(structural.tombstone().as_bytes())?;
        let expected = Self::new(attempt, preceding_reveal, &partial, &tombstone)?;
        if input != expected.as_bytes() {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(expected)
    }

    /// Returns the exact authenticated payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the persisted partial exposure.
    pub const fn partial(&self) -> &ExposureRecordV1 {
        &self.partial
    }

    /// Returns the consumed tombstone.
    pub const fn tombstone(&self) -> &TombstoneV1 {
        &self.tombstone
    }
}

/// External authenticated evidence required by cross-record journal payloads.
pub enum JournalPayloadEvidenceV1<'a> {
    /// The payload is self-authenticating (`Reserve` or `ComputationAttempt`).
    SelfContained,
    /// A persisted commitment or reveal and its construction context.
    Persisted {
        /// The exact durable attempt.
        attempt: &'a AttemptRecordV1,
        /// The preceding spent sequence, absent only for Commitment.
        preceding_spent: Option<&'a ExposureRecordV1>,
    },
    /// An immutable exposure transition and its referenced predecessor.
    ExposureTransition {
        /// The exact predecessor record named by the payload.
        predecessor: &'a ExposureRecordV1,
        /// The consumed tombstone required only for partial `Persisted -> Authorized`.
        intervening_tombstone: Option<&'a TombstoneV1>,
    },
    /// A partial-consumption payload and its preceding Reveal.
    PartialConsumed {
        /// The exact durable partial-signature attempt.
        attempt: &'a AttemptRecordV1,
        /// The preceding spent Reveal exposure.
        preceding_reveal: &'a ExposureRecordV1,
    },
}

/// Authenticated payload for the minimal non-restore nonce lifecycle.
#[derive(Clone, Eq, PartialEq)]
pub struct JournalPayloadV1 {
    kind: JournalEntryKindV1,
    bytes: Vec<u8>,
}

impl JournalPayloadV1 {
    /// Constructs a Reserve payload.
    pub fn reserve(
        claim: &SessionClaimV1,
        charge: &BudgetChargeV1,
    ) -> Result<Self, CanonicalCodecError> {
        let identity = charge.reservation_authority().nonce_identity()?;
        if claim.identity().as_bytes() != identity.as_bytes() {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        let mut bytes = Vec::with_capacity(SESSION_CLAIM_LEN + charge.as_bytes().len());
        bytes.extend_from_slice(claim.as_bytes());
        bytes.extend_from_slice(charge.as_bytes());
        Ok(Self {
            kind: JournalEntryKindV1::Reserve,
            bytes,
        })
    }

    /// Constructs the exact 201-byte nonce-derivation attempt payload.
    pub fn nonce_derivation_attempt(attempt: &NonceDerivationAttemptV1) -> Self {
        Self {
            kind: JournalEntryKindV1::ComputationAttempt,
            bytes: attempt.as_bytes().to_vec(),
        }
    }

    /// Constructs a Reveal or PartialSignature computation-attempt payload.
    pub fn computation_attempt(attempt: &AttemptRecordV1) -> Result<Self, CanonicalCodecError> {
        if attempt.artifact() == ArtifactKindV1::Commitment {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        Ok(Self {
            kind: JournalEntryKindV1::ComputationAttempt,
            bytes: attempt.as_bytes().to_vec(),
        })
    }

    /// Constructs a budget carry-forward payload without creating a new charge.
    pub fn budget_carry_forward(charge: &BudgetChargeV1) -> Self {
        Self {
            kind: JournalEntryKindV1::BudgetCarryForward,
            bytes: charge.as_bytes().to_vec(),
        }
    }

    /// Constructs a permit-retirement carry-forward payload.
    pub fn permit_retirement_carry_forward(retirement: &PermitRetirementV1) -> Self {
        Self {
            kind: JournalEntryKindV1::PermitRetirementCarryForward,
            bytes: retirement.as_bytes().to_vec(),
        }
    }

    /// Constructs the exact restore-begin payload.
    pub(crate) fn restore_begin(manifest: &RestoreManifestV1) -> Self {
        Self {
            kind: JournalEntryKindV1::RestoreBegin,
            bytes: manifest.as_bytes().to_vec(),
        }
    }

    /// Constructs one authenticated terminal restore projection.
    pub(crate) fn restore_record(record: &RestoreRecordPayloadV1) -> Self {
        Self {
            kind: JournalEntryKindV1::RestoreRecord,
            bytes: record.as_bytes().to_vec(),
        }
    }

    /// Constructs the exact epoch-advance payload.
    pub(crate) fn epoch_advance(epoch: &EpochAdvancePayloadV1) -> Self {
        Self {
            kind: JournalEntryKindV1::EpochAdvance,
            bytes: epoch.as_bytes().to_vec(),
        }
    }

    /// Constructs the exact completion record followed by its complete digest.
    pub(crate) fn restore_complete(completion: &RestoreCompleteV1) -> Self {
        let mut bytes = Vec::with_capacity(RESTORE_COMPLETE_LEN + 32);
        bytes.extend_from_slice(completion.as_bytes());
        bytes.extend_from_slice(completion.full_digest());
        Self {
            kind: JournalEntryKindV1::RestoreComplete,
            bytes,
        }
    }

    /// Constructs an abort-consumed payload from a tombstone selected by the
    /// retained live-Store authority.
    pub(crate) fn abort_consumed(tombstone: &TombstoneV1) -> Result<Self, CanonicalCodecError> {
        if tombstone.reason() != TerminalReasonV1::AbortConsumed {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        Ok(Self {
            kind: JournalEntryKindV1::AbortConsumed,
            bytes: tombstone.as_bytes().to_vec(),
        })
    }

    /// Constructs a burned payload from a tombstone selected by the retained
    /// live-Store authority.
    pub(crate) fn burned(tombstone: &TombstoneV1) -> Result<Self, CanonicalCodecError> {
        if tombstone.reason() != TerminalReasonV1::Burned {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        Ok(Self {
            kind: JournalEntryKindV1::Burned,
            bytes: tombstone.as_bytes().to_vec(),
        })
    }

    /// Constructs a CommitmentPersisted or RevealPersisted payload.
    pub fn persisted(
        attempt: &AttemptRecordV1,
        preceding_spent: Option<&ExposureRecordV1>,
        exposure: &ExposureRecordV1,
    ) -> Result<Self, CanonicalCodecError> {
        exposure.validate_persisted_context(attempt, preceding_spent)?;
        let kind = match exposure.artifact() {
            ArtifactKindV1::Commitment => JournalEntryKindV1::CommitmentPersisted,
            ArtifactKindV1::Reveal => JournalEntryKindV1::RevealPersisted,
            ArtifactKindV1::PartialSignature => {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
        };
        Ok(Self {
            kind,
            bytes: exposure.as_bytes().to_vec(),
        })
    }

    /// Constructs an ExposureAuthorized payload.
    pub fn exposure_authorized(
        predecessor: &ExposureRecordV1,
        successor: &ExposureRecordV1,
        intervening_tombstone: Option<&TombstoneV1>,
    ) -> Result<Self, CanonicalCodecError> {
        let payload =
            ExposureAuthorizationPayloadV1::new(predecessor, successor, intervening_tombstone)?;
        Ok(Self {
            kind: JournalEntryKindV1::ExposureAuthorized,
            bytes: payload.as_bytes().to_vec(),
        })
    }

    /// Constructs a PartialConsumed payload.
    pub fn partial_consumed(
        attempt: &AttemptRecordV1,
        preceding_reveal: &ExposureRecordV1,
        partial: &ExposureRecordV1,
        tombstone: &TombstoneV1,
    ) -> Result<Self, CanonicalCodecError> {
        let payload = PartialConsumedPayloadV1::new(attempt, preceding_reveal, partial, tombstone)?;
        Ok(Self {
            kind: JournalEntryKindV1::PartialConsumed,
            bytes: payload.as_bytes().to_vec(),
        })
    }

    fn from_bytes(
        kind: JournalEntryKindV1,
        input: &[u8],
        evidence: JournalPayloadEvidenceV1<'_>,
    ) -> Result<Self, CanonicalCodecError> {
        match (kind, evidence) {
            (JournalEntryKindV1::Reserve, JournalPayloadEvidenceV1::SelfContained) => {
                let reserve = UnauthenticatedReservePayloadV1::parse_structural(input)?;
                let claim = SessionClaimV1::from_bytes(reserve.claim().as_bytes())?;
                Self::reserve(&claim, reserve.charge())
            }
            (JournalEntryKindV1::ComputationAttempt, JournalPayloadEvidenceV1::SelfContained) => {
                match UnauthenticatedComputationAttemptV1::parse_structural(input)? {
                    UnauthenticatedComputationAttemptV1::NonceDerivation(wrapper) => {
                        let authenticated =
                            NonceDerivationAttemptV1::from_bytes(wrapper.as_bytes())?;
                        Ok(Self::nonce_derivation_attempt(&authenticated))
                    }
                    UnauthenticatedComputationAttemptV1::LaterStage(attempt) => {
                        let attempt = AttemptRecordV1::from_bytes(attempt.as_bytes())?;
                        Self::computation_attempt(&attempt)
                    }
                }
            }
            (
                JournalEntryKindV1::CommitmentPersisted | JournalEntryKindV1::RevealPersisted,
                JournalPayloadEvidenceV1::Persisted {
                    attempt,
                    preceding_spent,
                },
            ) => {
                let exposure = ExposureRecordV1::from_bytes(input)?;
                let payload = Self::persisted(attempt, preceding_spent, &exposure)?;
                if payload.kind != kind {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                Ok(payload)
            }
            (
                JournalEntryKindV1::ExposureAuthorized,
                JournalPayloadEvidenceV1::ExposureTransition {
                    predecessor,
                    intervening_tombstone,
                },
            ) => {
                let payload = ExposureAuthorizationPayloadV1::from_bytes(
                    input,
                    predecessor,
                    intervening_tombstone,
                )?;
                Ok(Self {
                    kind,
                    bytes: payload.as_bytes().to_vec(),
                })
            }
            (
                JournalEntryKindV1::PartialConsumed,
                JournalPayloadEvidenceV1::PartialConsumed {
                    attempt,
                    preceding_reveal,
                },
            ) => {
                let payload =
                    PartialConsumedPayloadV1::from_bytes(input, attempt, preceding_reveal)?;
                Ok(Self {
                    kind,
                    bytes: payload.as_bytes().to_vec(),
                })
            }
            (JournalEntryKindV1::AbortConsumed | JournalEntryKindV1::Burned, _) => {
                Err(CanonicalCodecError::LiveStoreAuthorityRequired)
            }
            (JournalEntryKindV1::BudgetCarryForward, JournalPayloadEvidenceV1::SelfContained) => {
                Ok(Self::budget_carry_forward(&BudgetChargeV1::from_bytes(
                    input,
                )?))
            }
            (
                JournalEntryKindV1::PermitRetirementCarryForward,
                JournalPayloadEvidenceV1::SelfContained,
            ) => Ok(Self::permit_retirement_carry_forward(
                &PermitRetirementV1::from_bytes(input)?,
            )),
            _ => Err(CanonicalCodecError::InvalidLifecycle),
        }
    }

    /// Returns the closed entry kind assigned to the payload.
    pub const fn kind(&self) -> JournalEntryKindV1 {
        self.kind
    }

    /// Returns the exact authenticated canonical payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Authenticated predecessor-linked journal entry for the minimal lifecycle.
#[derive(Clone, Eq, PartialEq)]
pub struct JournalEntryV1 {
    bytes: Vec<u8>,
    sequence: u64,
    payload: JournalPayloadV1,
    entry_digest: [u8; 32],
}

impl JournalEntryV1 {
    /// Constructs the first journal entry, which must reserve an identity.
    pub fn first(payload: JournalPayloadV1) -> Result<Self, CanonicalCodecError> {
        if payload.kind() != JournalEntryKindV1::Reserve {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        Self::construct(1, [0; 32], payload)
    }

    /// Appends one exactly linked entry after the authenticated predecessor.
    pub fn append(
        predecessor: &Self,
        payload: JournalPayloadV1,
    ) -> Result<Self, CanonicalCodecError> {
        let sequence = predecessor
            .sequence
            .checked_add(1)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        Self::construct(sequence, predecessor.entry_digest, payload)
    }

    /// Constructs sequence one for a restore-only new-device journal.
    pub(crate) fn first_restore(payload: JournalPayloadV1) -> Result<Self, CanonicalCodecError> {
        if payload.kind() != JournalEntryKindV1::RestoreBegin {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        Self::construct(1, [0; 32], payload)
    }

    fn construct(
        sequence: u64,
        predecessor_digest: [u8; 32],
        payload: JournalPayloadV1,
    ) -> Result<Self, CanonicalCodecError> {
        if payload.as_bytes().len() > JOURNAL_PAYLOAD_MAX_LEN
            || is_zero(&predecessor_digest) != (sequence == 1)
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        if payload.kind() == JournalEntryKindV1::Reserve {
            let reserve = UnauthenticatedReservePayloadV1::parse_structural(payload.as_bytes())?;
            if reserve.charge().reserve_journal_sequence() != sequence {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
        }
        let payload_length = u32::try_from(payload.as_bytes().len())
            .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        let complete_length = JOURNAL_ENTRY_MIN_LEN
            .checked_add(payload.as_bytes().len())
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        let mut bytes = vec![0_u8; complete_length];
        bytes[..8].copy_from_slice(JOURNAL_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..18].copy_from_slice(&sequence.to_le_bytes());
        bytes[18..50].copy_from_slice(&predecessor_digest);
        bytes[50] = payload.kind() as u8;
        bytes[52..56].copy_from_slice(&payload_length.to_le_bytes());
        bytes[56..56 + payload.as_bytes().len()].copy_from_slice(payload.as_bytes());
        let digest_offset = 56 + payload.as_bytes().len();
        let entry_digest = storage_hash(StorageHashDomainV1::JournalEntry, &bytes[..digest_offset]);
        bytes[digest_offset..].copy_from_slice(&entry_digest);
        Ok(Self {
            bytes,
            sequence,
            payload,
            entry_digest,
        })
    }

    /// Parses and authenticates one exact entry and its cross-record payload evidence.
    pub fn from_bytes(
        input: &[u8],
        predecessor: Option<&Self>,
        evidence: JournalPayloadEvidenceV1<'_>,
    ) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedJournalEntryV1::parse_structural(input)?;
        let envelope = structural.envelope();
        match predecessor {
            None => {
                if envelope.sequence() != 1
                    || envelope.kind() != JournalEntryKindV1::Reserve
                    || !is_zero(envelope.predecessor_digest())
                {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
            }
            Some(previous) => {
                let expected_sequence = previous
                    .sequence
                    .checked_add(1)
                    .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
                if envelope.sequence() != expected_sequence
                    || envelope.predecessor_digest() != previous.entry_digest
                {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
            }
        }
        let digest_offset = input
            .len()
            .checked_sub(32)
            .ok_or(CanonicalCodecError::InvalidEncoding)?;
        let expected_digest =
            storage_hash(StorageHashDomainV1::JournalEntry, &input[..digest_offset]);
        if envelope.entry_digest() != expected_digest {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        let payload = JournalPayloadV1::from_bytes(envelope.kind(), envelope.payload(), evidence)?;
        Ok(Self {
            bytes: input.to_vec(),
            sequence: envelope.sequence(),
            payload,
            entry_digest: expected_digest,
        })
    }

    /// Parses one restore-tail entry against its exact authenticated payload.
    pub(crate) fn from_restore_bytes(
        input: &[u8],
        predecessor: Option<&Self>,
        expected_payload: JournalPayloadV1,
    ) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedJournalEntryV1::parse_structural(input)?;
        let envelope = structural.envelope();
        let expected_sequence = match predecessor {
            Some(previous) => previous
                .sequence
                .checked_add(1)
                .ok_or(CanonicalCodecError::ArithmeticOverflow)?,
            None => 1,
        };
        let expected_predecessor = predecessor
            .map(|previous| previous.entry_digest)
            .unwrap_or([0; 32]);
        if envelope.sequence() != expected_sequence
            || envelope.predecessor_digest() != expected_predecessor
            || envelope.kind() != expected_payload.kind()
            || envelope.payload() != expected_payload.as_bytes()
        {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        let digest_offset = input
            .len()
            .checked_sub(32)
            .ok_or(CanonicalCodecError::InvalidEncoding)?;
        let entry_digest = storage_hash(StorageHashDomainV1::JournalEntry, &input[..digest_offset]);
        if envelope.entry_digest() != entry_digest {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: input.to_vec(),
            sequence: expected_sequence,
            payload: expected_payload,
            entry_digest,
        })
    }

    /// Parses one terminal entry after the retained Store has authenticated
    /// the exact sealed tombstone under the current generation authority.
    fn from_bytes_with_retained_terminal(
        input: &[u8],
        predecessor: Option<&Self>,
        tombstone: &TombstoneV1,
    ) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedJournalEntryV1::parse_structural(input)?;
        let envelope = structural.envelope();
        let previous = predecessor.ok_or(CanonicalCodecError::InvalidLifecycle)?;
        let expected_sequence = previous
            .sequence
            .checked_add(1)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        if envelope.sequence() != expected_sequence
            || envelope.predecessor_digest() != previous.entry_digest
        {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        let payload = match tombstone.reason() {
            TerminalReasonV1::AbortConsumed => JournalPayloadV1::abort_consumed(tombstone)?,
            TerminalReasonV1::Burned => JournalPayloadV1::burned(tombstone)?,
            TerminalReasonV1::Consumed => {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
        };
        if envelope.kind() != payload.kind() || envelope.payload() != payload.as_bytes() {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        let digest_offset = input
            .len()
            .checked_sub(32)
            .ok_or(CanonicalCodecError::InvalidEncoding)?;
        let expected_digest =
            storage_hash(StorageHashDomainV1::JournalEntry, &input[..digest_offset]);
        if envelope.entry_digest() != expected_digest {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: input.to_vec(),
            sequence: envelope.sequence(),
            payload,
            entry_digest: expected_digest,
        })
    }

    /// Returns the exact authenticated journal bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the global sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the authenticated minimal-lifecycle payload.
    pub const fn payload(&self) -> &JournalPayloadV1 {
        &self.payload
    }

    /// Returns the authenticated entry digest.
    pub const fn entry_digest(&self) -> &[u8; 32] {
        &self.entry_digest
    }
}

#[derive(Clone)]
struct IdentityJournalProjectionV1 {
    claim: SessionClaimV1,
    attempts: Vec<AttemptRecordV1>,
    pending_attempt: Option<AttemptRecordV1>,
    exposures: Vec<ExposureRecordV1>,
    latest_exposures: [Option<ExposureRecordV1>; 3],
    tombstone: Option<TombstoneV1>,
}

impl IdentityJournalProjectionV1 {
    fn new(claim: SessionClaimV1) -> Self {
        Self {
            claim,
            attempts: Vec::new(),
            pending_attempt: None,
            exposures: Vec::new(),
            latest_exposures: [None, None, None],
            tombstone: None,
        }
    }

    fn current_revision(&self) -> u64 {
        let mut current = self.claim.claim_revision();
        for exposure in &self.exposures {
            current = current.max(exposure.lifecycle_revision());
        }
        if let Some(tombstone) = &self.tombstone {
            current = current.max(tombstone.terminal_revision());
        }
        current
    }

    fn latest(&self, sequence: u64) -> Result<Option<&ExposureRecordV1>, CanonicalCodecError> {
        let index = sequence_index(sequence)?;
        Ok(self.latest_exposures[index].as_ref())
    }
}

enum ValidatedMinimalEventV1 {
    Reserve(SessionClaimV1),
    Attempt(AttemptRecordV1),
    Persisted(ExposureRecordV1),
    ExposureTransition(ExposureRecordV1),
    PartialConsumed(ExposureRecordV1, Box<TombstoneV1>),
    RetainedTerminal(Box<TombstoneV1>),
}

/// Stateful authenticated verifier and constructor for the minimal journal lifecycle.
///
/// Entries must be supplied consecutively. The verifier retains authenticated
/// per-identity projections so missing reserves, duplicate attempts, sequence
/// skips, state skips, stale revisions, and post-terminal operations fail
/// before a new head is accepted. Restore payloads remain outside this minimal
/// lifecycle foundation.
pub struct MinimalJournalV1 {
    predecessor: Option<JournalEntryV1>,
    entries: Vec<JournalEntryV1>,
    sessions: BTreeMap<[u8; 32], [u8; 105]>,
    identities: BTreeMap<[u8; 105], IdentityJournalProjectionV1>,
}

impl MinimalJournalV1 {
    /// Constructs an empty journal verifier.
    pub const fn new() -> Self {
        Self {
            predecessor: None,
            entries: Vec::new(),
            sessions: BTreeMap::new(),
            identities: BTreeMap::new(),
        }
    }

    /// Authenticates and appends already encoded consecutive journal bytes.
    ///
    /// `AbortConsumed` and `Burned` remain unavailable because this pure
    /// foundation cannot prove active-secret presence or absence under the
    /// retained root, lock, and active-generation authority required by
    /// NAR-DC-P1-002. Those entries fail closed instead of accepting caller
    /// evidence.
    pub fn verify_next(&mut self, input: &[u8]) -> Result<&JournalEntryV1, CanonicalCodecError> {
        let envelope = UnauthenticatedJournalEnvelopeV1::parse_outer(input)?;
        let (entry, event) = self.authenticate_event(input, &envelope)?;
        self.commit_authenticated(entry, event)
    }

    /// Constructs, authenticates, and appends one payload to the current head.
    pub fn append(
        &mut self,
        payload: JournalPayloadV1,
    ) -> Result<&JournalEntryV1, CanonicalCodecError> {
        let candidate = match self.predecessor_head() {
            Some(predecessor) => JournalEntryV1::append(predecessor, payload)?,
            None => JournalEntryV1::first(payload)?,
        };
        self.verify_next(candidate.as_bytes())
    }

    /// Returns every verified entry in exact append order.
    pub fn entries(&self) -> &[JournalEntryV1] {
        &self.entries
    }

    /// Returns the current verified journal head, if any.
    pub fn head(&self) -> Option<&JournalEntryV1> {
        self.predecessor_head()
    }

    /// Starts one empty normal-operation segment after an exactly verified
    /// restore tail. Only the private restore verifier can mint the anchor.
    pub(crate) fn continue_after_verified_restore(anchor: &VerifiedRestoreAnchorV1) -> Self {
        Self {
            predecessor: Some(anchor.head.clone()),
            entries: Vec::new(),
            sessions: BTreeMap::new(),
            identities: BTreeMap::new(),
        }
    }

    fn predecessor_head(&self) -> Option<&JournalEntryV1> {
        self.entries.last().or(self.predecessor.as_ref())
    }

    fn authenticate_retained_terminal(
        &self,
        input: &[u8],
        tombstone: &TombstoneV1,
    ) -> Result<(JournalEntryV1, ValidatedMinimalEventV1), CanonicalCodecError> {
        let projection = self.projection(tombstone.identity())?;
        if projection.tombstone.is_some() {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        let entry = JournalEntryV1::from_bytes_with_retained_terminal(
            input,
            self.predecessor_head(),
            tombstone,
        )?;
        Ok((
            entry,
            ValidatedMinimalEventV1::RetainedTerminal(Box::new(tombstone.clone())),
        ))
    }

    fn commit_authenticated(
        &mut self,
        entry: JournalEntryV1,
        event: ValidatedMinimalEventV1,
    ) -> Result<&JournalEntryV1, CanonicalCodecError> {
        self.apply_event(event)?;
        self.entries.push(entry);
        self.entries
            .last()
            .ok_or(CanonicalCodecError::InvalidLifecycle)
    }

    fn authenticate_event(
        &self,
        input: &[u8],
        envelope: &UnauthenticatedJournalEnvelopeV1<'_>,
    ) -> Result<(JournalEntryV1, ValidatedMinimalEventV1), CanonicalCodecError> {
        let predecessor = self.predecessor_head();
        match envelope.kind() {
            JournalEntryKindV1::Reserve => {
                let reserve =
                    UnauthenticatedReservePayloadV1::parse_structural(envelope.payload())?;
                if reserve.charge().reserve_journal_sequence() != envelope.sequence() {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                let claim = SessionClaimV1::from_bytes(reserve.claim().as_bytes())?;
                let identity_key = *claim.identity().as_bytes();
                let session_key = session_key(claim.identity());
                if self.identities.contains_key(&identity_key)
                    || self.sessions.contains_key(&session_key)
                {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                let entry = JournalEntryV1::from_bytes(
                    input,
                    predecessor,
                    JournalPayloadEvidenceV1::SelfContained,
                )?;
                Ok((entry, ValidatedMinimalEventV1::Reserve(claim)))
            }
            JournalEntryKindV1::ComputationAttempt => {
                let attempt = match UnauthenticatedComputationAttemptV1::parse_structural(
                    envelope.payload(),
                )? {
                    UnauthenticatedComputationAttemptV1::NonceDerivation(wrapper) => {
                        NonceDerivationAttemptV1::from_bytes(wrapper.as_bytes())?
                            .attempt()
                            .clone()
                    }
                    UnauthenticatedComputationAttemptV1::LaterStage(attempt) => {
                        AttemptRecordV1::from_bytes(attempt.as_bytes())?
                    }
                };
                let projection = self.projection(attempt.identity())?;
                self.validate_attempt(projection, &attempt)?;
                let entry = JournalEntryV1::from_bytes(
                    input,
                    predecessor,
                    JournalPayloadEvidenceV1::SelfContained,
                )?;
                Ok((entry, ValidatedMinimalEventV1::Attempt(attempt)))
            }
            JournalEntryKindV1::CommitmentPersisted | JournalEntryKindV1::RevealPersisted => {
                let exposure = ExposureRecordV1::from_bytes(envelope.payload())?;
                let projection = self.projection(exposure.identity())?;
                if projection.tombstone.is_some()
                    || projection.latest(exposure.sequence())?.is_some()
                {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                let attempt = projection
                    .pending_attempt
                    .as_ref()
                    .ok_or(CanonicalCodecError::InvalidLifecycle)?;
                let preceding = if exposure.sequence() == 1 {
                    None
                } else {
                    projection.latest(exposure.sequence() - 1)?
                };
                exposure.validate_persisted_context(attempt, preceding)?;
                let entry = JournalEntryV1::from_bytes(
                    input,
                    predecessor,
                    JournalPayloadEvidenceV1::Persisted {
                        attempt,
                        preceding_spent: preceding,
                    },
                )?;
                Ok((entry, ValidatedMinimalEventV1::Persisted(exposure)))
            }
            JournalEntryKindV1::ExposureAuthorized => {
                let structural = UnauthenticatedExposureAuthorizationPayloadV1::parse_structural(
                    envelope.payload(),
                )?;
                let successor = ExposureRecordV1::from_bytes(structural.successor().as_bytes())?;
                let projection = self.projection(successor.identity())?;
                if projection.pending_attempt.is_some() {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                let predecessor_record = projection
                    .latest(successor.sequence())?
                    .ok_or(CanonicalCodecError::InvalidLifecycle)?;
                let is_partial = successor.artifact() == ArtifactKindV1::PartialSignature;
                let intervening_tombstone =
                    if is_partial && predecessor_record.state() == ExposureStateV1::Persisted {
                        projection.tombstone.as_ref()
                    } else {
                        None
                    };
                if (!is_partial && projection.tombstone.is_some())
                    || (is_partial && projection.tombstone.is_none())
                {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                successor.validate_successor(predecessor_record, intervening_tombstone)?;
                let entry = JournalEntryV1::from_bytes(
                    input,
                    predecessor,
                    JournalPayloadEvidenceV1::ExposureTransition {
                        predecessor: predecessor_record,
                        intervening_tombstone,
                    },
                )?;
                Ok((
                    entry,
                    ValidatedMinimalEventV1::ExposureTransition(successor),
                ))
            }
            JournalEntryKindV1::PartialConsumed => {
                let structural =
                    UnauthenticatedPartialConsumedPayloadV1::parse_structural(envelope.payload())?;
                let partial = ExposureRecordV1::from_bytes(structural.partial().as_bytes())?;
                let tombstone = TombstoneV1::from_bytes(structural.tombstone().as_bytes())?;
                let projection = self.projection(partial.identity())?;
                if projection.tombstone.is_some() || projection.latest(3)?.is_some() {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                let attempt = projection
                    .pending_attempt
                    .as_ref()
                    .ok_or(CanonicalCodecError::InvalidLifecycle)?;
                let preceding_reveal = projection
                    .latest(2)?
                    .ok_or(CanonicalCodecError::InvalidLifecycle)?;
                let payload =
                    PartialConsumedPayloadV1::new(attempt, preceding_reveal, &partial, &tombstone)?;
                if payload.as_bytes() != envelope.payload() {
                    return Err(CanonicalCodecError::AuthenticationFailed);
                }
                let entry = JournalEntryV1::from_bytes(
                    input,
                    predecessor,
                    JournalPayloadEvidenceV1::PartialConsumed {
                        attempt,
                        preceding_reveal,
                    },
                )?;
                Ok((
                    entry,
                    ValidatedMinimalEventV1::PartialConsumed(partial, Box::new(tombstone)),
                ))
            }
            JournalEntryKindV1::AbortConsumed | JournalEntryKindV1::Burned => {
                Err(CanonicalCodecError::LiveStoreAuthorityRequired)
            }
            JournalEntryKindV1::PermitRetirementCarryForward => {
                Err(CanonicalCodecError::InvalidLifecycle)
            }
            JournalEntryKindV1::RestoreBegin
            | JournalEntryKindV1::RestoreRecord
            | JournalEntryKindV1::RestoreComplete
            | JournalEntryKindV1::EpochAdvance
            | JournalEntryKindV1::BudgetCarryForward => Err(CanonicalCodecError::InvalidLifecycle),
        }
    }

    fn projection(
        &self,
        identity: &NonceIdentityV1,
    ) -> Result<&IdentityJournalProjectionV1, CanonicalCodecError> {
        self.identities
            .get(identity.as_bytes())
            .ok_or(CanonicalCodecError::InvalidLifecycle)
    }

    fn validate_attempt(
        &self,
        projection: &IdentityJournalProjectionV1,
        attempt: &AttemptRecordV1,
    ) -> Result<(), CanonicalCodecError> {
        if projection.tombstone.is_some()
            || projection.pending_attempt.is_some()
            || attempt.expected_lifecycle_revision() != projection.current_revision()
        {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        let sequence = attempt.artifact().exposure_sequence();
        if projection.latest(sequence)?.is_some() {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        if sequence == 1 {
            if projection.current_revision() != 1 {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
        } else {
            let preceding = projection
                .latest(sequence - 1)?
                .ok_or(CanonicalCodecError::InvalidLifecycle)?;
            if preceding.state() != ExposureStateV1::Spent
                || preceding.lifecycle_revision() != projection.current_revision()
            {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
        }
        Ok(())
    }

    fn apply_event(&mut self, event: ValidatedMinimalEventV1) -> Result<(), CanonicalCodecError> {
        match event {
            ValidatedMinimalEventV1::Reserve(claim) => {
                let identity_key = *claim.identity().as_bytes();
                self.sessions
                    .insert(session_key(claim.identity()), identity_key);
                self.identities
                    .insert(identity_key, IdentityJournalProjectionV1::new(claim));
            }
            ValidatedMinimalEventV1::Attempt(attempt) => {
                let projection = self
                    .identities
                    .get_mut(attempt.identity().as_bytes())
                    .ok_or(CanonicalCodecError::InvalidLifecycle)?;
                projection.attempts.push(attempt.clone());
                projection.pending_attempt = Some(attempt);
            }
            ValidatedMinimalEventV1::Persisted(exposure) => {
                self.apply_exposure(exposure, true)?;
            }
            ValidatedMinimalEventV1::ExposureTransition(exposure) => {
                self.apply_exposure(exposure, false)?;
            }
            ValidatedMinimalEventV1::PartialConsumed(partial, tombstone) => {
                let index = sequence_index(partial.sequence())?;
                let projection = self
                    .identities
                    .get_mut(partial.identity().as_bytes())
                    .ok_or(CanonicalCodecError::InvalidLifecycle)?;
                projection.pending_attempt = None;
                projection.exposures.push(partial.clone());
                projection.latest_exposures[index] = Some(partial);
                projection.tombstone = Some(*tombstone);
            }
            ValidatedMinimalEventV1::RetainedTerminal(tombstone) => {
                let projection = self
                    .identities
                    .get_mut(tombstone.identity().as_bytes())
                    .ok_or(CanonicalCodecError::InvalidLifecycle)?;
                projection.pending_attempt = None;
                projection.tombstone = Some(*tombstone);
            }
        }
        Ok(())
    }

    fn apply_exposure(
        &mut self,
        exposure: ExposureRecordV1,
        consumes_attempt: bool,
    ) -> Result<(), CanonicalCodecError> {
        let index = sequence_index(exposure.sequence())?;
        let projection = self
            .identities
            .get_mut(exposure.identity().as_bytes())
            .ok_or(CanonicalCodecError::InvalidLifecycle)?;
        if consumes_attempt {
            projection.pending_attempt = None;
        }
        projection.exposures.push(exposure.clone());
        projection.latest_exposures[index] = Some(exposure);
        Ok(())
    }
}

impl Default for MinimalJournalV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete authenticated inputs for one restore-only journal tail.
#[derive(Clone, Copy)]
pub(crate) struct RestoreJournalInputsV1<'a> {
    /// Exact restore transaction manifest.
    pub(crate) manifest: &'a RestoreManifestV1,
    /// One terminal result per union identity, already authenticated by the Store.
    pub(crate) records: &'a [RestoreRecordPayloadV1],
    /// Source budget evidence sorted and deduplicated by reservation ID.
    pub(crate) budget_carry_forwards: &'a [BudgetChargeV1],
    /// Source retirement evidence sorted and deduplicated by permit ID.
    pub(crate) permit_carry_forwards: &'a [PermitRetirementV1],
    /// Exact deterministic successor epoch/generation payload.
    pub(crate) epoch_advance: &'a EpochAdvancePayloadV1,
}

/// Codec-authenticated restore tail ending at `RestoreComplete`.
///
/// The normal [`MinimalJournalV1`] deliberately continues to reject every
/// restore-only kind. This crate-internal type checks canonical tail ordering,
/// predecessor links, exact supplied payloads, and intrinsic manifest/epoch
/// links. It is not complete restore authority. Before construction, retained
/// Store reconciliation must independently authenticate source and target
/// record-set commitments, prove the complete terminal union, prove complete
/// budget and permit carry-forward sets, and bind the predecessor generation.
pub(crate) struct RestoredJournalV1 {
    entries: Vec<JournalEntryV1>,
    encoded_verified: bool,
}

impl RestoredJournalV1 {
    /// Constructs the exact complete restore tail after an optional verified target head.
    pub(crate) fn new(
        target_head: Option<&JournalEntryV1>,
        inputs: RestoreJournalInputsV1<'_>,
    ) -> Result<Self, CanonicalCodecError> {
        validate_restore_inputs(target_head, &inputs)?;
        let mut entries = Vec::with_capacity(
            3_usize
                .checked_add(inputs.records.len())
                .and_then(|length| length.checked_add(inputs.budget_carry_forwards.len()))
                .and_then(|length| length.checked_add(inputs.permit_carry_forwards.len()))
                .ok_or(CanonicalCodecError::ArithmeticOverflow)?,
        );
        let begin_payload = JournalPayloadV1::restore_begin(inputs.manifest);
        let begin = match target_head {
            Some(predecessor) => JournalEntryV1::append(predecessor, begin_payload)?,
            None => JournalEntryV1::first_restore(begin_payload)?,
        };
        entries.push(begin);
        for record in inputs.records {
            append_restore_payload(&mut entries, JournalPayloadV1::restore_record(record))?;
        }
        for charge in inputs.budget_carry_forwards {
            append_restore_payload(&mut entries, JournalPayloadV1::budget_carry_forward(charge))?;
        }
        for retirement in inputs.permit_carry_forwards {
            append_restore_payload(
                &mut entries,
                JournalPayloadV1::permit_retirement_carry_forward(retirement),
            )?;
        }
        append_restore_payload(
            &mut entries,
            JournalPayloadV1::epoch_advance(inputs.epoch_advance),
        )?;
        let pre_complete_head = *entries
            .last()
            .ok_or(CanonicalCodecError::InvalidLifecycle)?
            .entry_digest();
        let completion = RestoreCompleteV1::new(inputs.manifest, pre_complete_head)?;
        append_restore_payload(
            &mut entries,
            JournalPayloadV1::restore_complete(&completion),
        )?;
        Ok(Self {
            entries,
            encoded_verified: false,
        })
    }

    /// Verifies a complete encoded restore tail byte for byte against authenticated inputs.
    pub(crate) fn from_encoded_tail(
        target_head: Option<&JournalEntryV1>,
        encoded_tail: &[&[u8]],
        inputs: RestoreJournalInputsV1<'_>,
    ) -> Result<Self, CanonicalCodecError> {
        let expected = Self::new(target_head, inputs)?;
        if expected.entries.len() != encoded_tail.len() {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        let mut verified = Vec::with_capacity(encoded_tail.len());
        for (index, (encoded, expected_entry)) in
            encoded_tail.iter().zip(expected.entries.iter()).enumerate()
        {
            let predecessor = if index == 0 {
                target_head
            } else {
                verified.last()
            };
            let entry = JournalEntryV1::from_restore_bytes(
                encoded,
                predecessor,
                expected_entry.payload.clone(),
            )?;
            if entry.as_bytes() != expected_entry.as_bytes() {
                return Err(CanonicalCodecError::AuthenticationFailed);
            }
            verified.push(entry);
        }
        Ok(Self {
            entries: verified,
            encoded_verified: true,
        })
    }

    /// Returns every restore-tail entry in exact append order.
    #[cfg(any(test, feature = "evidence-only"))]
    pub(crate) fn entries(&self) -> &[JournalEntryV1] {
        &self.entries
    }

    /// Returns the final verified `RestoreComplete` journal head.
    pub(crate) fn head(&self) -> Result<&JournalEntryV1, CanonicalCodecError> {
        self.entries
            .last()
            .ok_or(CanonicalCodecError::InvalidLifecycle)
    }

    fn verified_anchor(
        &self,
        manifest: &RestoreManifestV1,
        epoch_advance: &EpochAdvancePayloadV1,
    ) -> Result<VerifiedRestoreAnchorV1, CanonicalCodecError> {
        if !self.encoded_verified {
            return Err(CanonicalCodecError::LiveStoreAuthorityRequired);
        }
        Ok(VerifiedRestoreAnchorV1 {
            head: self.head()?.clone(),
            manifest_digest: *manifest.manifest_digest(),
            epoch_advance: epoch_advance.clone(),
        })
    }
}

/// Private predecessor authority minted only from a byte-verified restore tail.
///
/// It is neither persisted nor exposed as application authority. The retained
/// Store must still match the generation and generation-core digest against its
/// active filesystem authority before using the composite journal result.
#[derive(Clone)]
pub(crate) struct VerifiedRestoreAnchorV1 {
    head: JournalEntryV1,
    manifest_digest: [u8; 32],
    epoch_advance: EpochAdvancePayloadV1,
}

impl VerifiedRestoreAnchorV1 {
    fn matches_core(&self, core: &VaultGenerationCoreV1) -> bool {
        self.epoch_advance.contract_wallet_id() == &core.as_bytes()[10..42]
            && self.epoch_advance.successor_vault_id() == core.vault_id()
            && self.epoch_advance.successor_epoch() == core.nonce_epoch()
            && self.epoch_advance.successor_generation() == core.vault_generation()
            && self.epoch_advance.generation_core_digest() == core.generation_core_digest()
    }
}

/// Complete verified journal across normal-operation and restore segments.
///
/// This crate-private verifier is a composition seam for the retained Store.
/// It grants no storage, restore, signing, export, or resend authority. Restore
/// inputs remain Store-authenticated values, while the canonical layer checks
/// exact tail bytes, predecessor links, and lifetime identifier collisions.
pub(crate) struct CompositeJournalV1 {
    all_entries: Vec<JournalEntryV1>,
    current_normal_segment: MinimalJournalV1,
    lifetime: LifetimeCollisionIndexV1,
    restore_anchors: Vec<VerifiedRestoreAnchorV1>,
}

impl CompositeJournalV1 {
    /// Starts a strict generation-one journal with no predecessor authority.
    pub(crate) fn new() -> Self {
        Self {
            all_entries: Vec::new(),
            current_normal_segment: MinimalJournalV1::new(),
            lifetime: LifetimeCollisionIndexV1::default(),
            restore_anchors: Vec::new(),
        }
    }

    /// Verifies one normal-operation entry against the current segment and all
    /// lifetime collision evidence accumulated across earlier restore hops.
    pub(crate) fn verify_normal_entry(
        &mut self,
        input: &[u8],
        retained_terminal: Option<&TombstoneV1>,
    ) -> Result<&JournalEntryV1, CanonicalCodecError> {
        let envelope = UnauthenticatedJournalEnvelopeV1::parse_outer(input)?;
        let terminal_kind = matches!(
            envelope.kind(),
            JournalEntryKindV1::AbortConsumed | JournalEntryKindV1::Burned
        );
        let (entry, event) = match (terminal_kind, retained_terminal) {
            (true, Some(tombstone)) => self
                .current_normal_segment
                .authenticate_retained_terminal(input, tombstone)?,
            (false, None) => self
                .current_normal_segment
                .authenticate_event(input, &envelope)?,
            _ => return Err(CanonicalCodecError::LiveStoreAuthorityRequired),
        };

        let mut next_lifetime = self.lifetime.clone();
        next_lifetime.apply_normal_event(&entry, &event)?;
        self.current_normal_segment
            .commit_authenticated(entry.clone(), event)?;
        self.lifetime = next_lifetime;
        self.all_entries.push(entry);
        self.all_entries
            .last()
            .ok_or(CanonicalCodecError::InvalidLifecycle)
    }

    /// Verifies and appends one exact restore-only segment after the current
    /// head, then opens a fresh empty normal segment anchored to RestoreComplete.
    pub(crate) fn verify_restore_segment(
        &mut self,
        encoded_tail: &[&[u8]],
        inputs: RestoreJournalInputsV1<'_>,
    ) -> Result<&VerifiedRestoreAnchorV1, CanonicalCodecError> {
        match self.restore_anchors.last() {
            Some(previous) => {
                if inputs.epoch_advance.predecessor_generation()
                    != previous.epoch_advance.successor_generation()
                    || inputs.epoch_advance.predecessor_vault_id()
                        != previous.epoch_advance.successor_vault_id()
                    || inputs.epoch_advance.predecessor_epoch()
                        != previous.epoch_advance.successor_epoch()
                    || inputs.epoch_advance.contract_wallet_id()
                        != previous.epoch_advance.contract_wallet_id()
                {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
            }
            None => {
                if inputs.manifest.is_new_device_target() {
                    if self.head().is_some()
                        || inputs.epoch_advance.predecessor_generation() != 0
                        || inputs.epoch_advance.successor_generation() != 1
                    {
                        return Err(CanonicalCodecError::InvalidLifecycle);
                    }
                } else if inputs.epoch_advance.predecessor_generation() != 1
                    || inputs.epoch_advance.successor_generation() != 2
                {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
            }
        }
        let target_head = self.head().cloned();
        let restored =
            RestoredJournalV1::from_encoded_tail(target_head.as_ref(), encoded_tail, inputs)?;
        let anchor = restored.verified_anchor(inputs.manifest, inputs.epoch_advance)?;
        let mut next_lifetime = self.lifetime.clone();
        next_lifetime.apply_restore_inputs(&inputs)?;

        self.all_entries.extend(restored.entries.iter().cloned());
        self.current_normal_segment = MinimalJournalV1::continue_after_verified_restore(&anchor);
        self.lifetime = next_lifetime;
        self.restore_anchors.push(anchor);
        self.restore_anchors
            .last()
            .ok_or(CanonicalCodecError::InvalidLifecycle)
    }

    /// Returns the complete verified sequence across every segment.
    pub(crate) fn entries(&self) -> &[JournalEntryV1] {
        &self.all_entries
    }

    /// Returns the unique greatest verified contiguous head.
    pub(crate) fn head(&self) -> Option<&JournalEntryV1> {
        self.all_entries.last()
    }

    /// Returns the unique verified restore anchor matching one complete
    /// authenticated retained generation core.
    ///
    /// Duplicate matches are rejected instead of silently selecting one even
    /// though contiguous epoch validation makes them unreachable through the
    /// normal constructor path.
    pub(crate) fn matching_anchor(
        &self,
        core: &VaultGenerationCoreV1,
    ) -> Result<Option<&VerifiedRestoreAnchorV1>, CanonicalCodecError> {
        let mut matches = self
            .restore_anchors
            .iter()
            .filter(|anchor| anchor.matches_core(core));
        let first = matches.next();
        if matches.next().is_some() {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(first)
    }

    /// Verifies that the retained active head is exactly the unique greatest
    /// contiguous verified head of the current generation.
    pub(crate) fn verify_current_generation_active_head(
        &self,
        core: &VaultGenerationCoreV1,
        active: &ActiveVaultGenerationV1,
    ) -> Result<&VerifiedRestoreAnchorV1, CanonicalCodecError> {
        let anchor = self
            .matching_anchor(core)?
            .ok_or(CanonicalCodecError::AuthenticationFailed)?;
        let current = self
            .restore_anchors
            .last()
            .ok_or(CanonicalCodecError::AuthenticationFailed)?;
        if current.head.as_bytes() != anchor.head.as_bytes()
            || active.as_bytes()[10..154] != core.as_bytes()[10..154]
        {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        let greatest = self
            .head()
            .ok_or(CanonicalCodecError::AuthenticationFailed)?;
        let anchor_index = self
            .all_entries
            .iter()
            .position(|entry| entry.as_bytes() == anchor.head.as_bytes())
            .ok_or(CanonicalCodecError::AuthenticationFailed)?;
        if greatest.sequence() >= self.all_entries[anchor_index].sequence()
            && greatest.sequence() == active.journal_sequence()
            && greatest.entry_digest().as_slice() == active.journal_head_digest()
        {
            Ok(anchor)
        } else {
            Err(CanonicalCodecError::AuthenticationFailed)
        }
    }

    /// Verifies the exact immutable activation snapshot for the current
    /// generation even after verified normal descendants have been appended.
    pub(crate) fn verify_pending_activation_anchor(
        &self,
        core: &VaultGenerationCoreV1,
        active: &ActiveVaultGenerationV1,
        pending: &RestorePendingIndexV1,
    ) -> Result<&VerifiedRestoreAnchorV1, CanonicalCodecError> {
        let anchor = self
            .matching_anchor(core)?
            .ok_or(CanonicalCodecError::AuthenticationFailed)?;
        let current = self
            .restore_anchors
            .last()
            .ok_or(CanonicalCodecError::AuthenticationFailed)?;
        let fields = pending.fields();
        if current.head.as_bytes() != anchor.head.as_bytes()
            || active.as_bytes()[10..154] != core.as_bytes()[10..154]
            || anchor.head.sequence() != active.journal_sequence()
            || anchor.head.entry_digest().as_slice() != active.journal_head_digest()
            || fields.restore_transaction_id.as_slice()
                != anchor.epoch_advance.restore_transaction_id()
            || fields.contract_wallet_id.as_slice() != anchor.epoch_advance.contract_wallet_id()
            || fields.restore_manifest_digest != anchor.manifest_digest
            || fields.successor_generation_core_digest != *core.generation_core_digest()
            || fields.successor_master_envelope_digest.as_slice() != core.master_envelope_digest()
            || fields.successor_final_journal_sequence != anchor.head.sequence()
            || fields.successor_final_journal_head_digest != *anchor.head.entry_digest()
            || fields.successor_active_generation_digest != *active.active_generation_digest()
        {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(anchor)
    }

    /// Returns collision-only lifetime evidence for retained Store validation.
    pub(crate) const fn lifetime_index(&self) -> &LifetimeCollisionIndexV1 {
        &self.lifetime
    }
}

impl Default for CompositeJournalV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Collision-only index rebuilt exclusively from the verified composite journal.
#[derive(Clone, Default)]
pub(crate) struct LifetimeCollisionIndexV1 {
    sessions: BTreeMap<[u8; 32], [u8; 105]>,
    identities: BTreeMap<[u8; 105], [u8; 105]>,
    terminals: BTreeMap<[u8; 105], Vec<u8>>,
    requests: BTreeMap<[u8; 32], Vec<u8>>,
    reservations: BTreeMap<[u8; 32], Vec<u8>>,
    permits: BTreeMap<[u8; 32], [u8; PERMIT_RETIREMENT_LEN]>,
}

impl LifetimeCollisionIndexV1 {
    /// Rejects every lifetime identifier collision for one already
    /// authenticated reservation candidate before Store persistence.
    ///
    /// This read-only preflight grants no reservation, journal, storage,
    /// signing, export, or resend authority.
    pub(crate) fn require_fresh_reservation(
        &self,
        claim: &SessionClaimV1,
        charge: &BudgetChargeV1,
    ) -> Result<(), CanonicalCodecError> {
        let authority = charge.reservation_authority();
        let identity = authority.nonce_identity()?;
        if claim.identity() != &identity {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        let session = session_key(&identity);
        let identity_key = *identity.as_bytes();
        let request = copy_32(authority.request_lookup_id())?;
        let reservation = copy_32(authority.reservation_id())?;
        if self.sessions.contains_key(&session)
            || self.identities.contains_key(&identity_key)
            || self.requests.contains_key(&request)
            || self.reservations.contains_key(&reservation)
        {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        Ok(())
    }

    fn apply_normal_event(
        &mut self,
        entry: &JournalEntryV1,
        event: &ValidatedMinimalEventV1,
    ) -> Result<(), CanonicalCodecError> {
        match event {
            ValidatedMinimalEventV1::Reserve(claim) => {
                let structural =
                    UnauthenticatedReservePayloadV1::parse_structural(entry.payload().as_bytes())?;
                self.insert_normal_identity(claim.identity())?;
                self.insert_normal_charge(structural.charge())?;
            }
            ValidatedMinimalEventV1::ExposureTransition(exposure)
                if exposure.state() == ExposureStateV1::Spent =>
            {
                let retirement = PermitRetirementV1::new(exposure, entry)?;
                let permit = copy_32(retirement.permit_id().as_bytes())?;
                if self.permits.contains_key(&permit) {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                self.permits.insert(permit, *retirement.as_bytes());
            }
            ValidatedMinimalEventV1::PartialConsumed(_, tombstone)
            | ValidatedMinimalEventV1::RetainedTerminal(tombstone) => {
                self.insert_terminal(tombstone)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn apply_restore_inputs(
        &mut self,
        inputs: &RestoreJournalInputsV1<'_>,
    ) -> Result<(), CanonicalCodecError> {
        for record in inputs.records {
            self.merge_historical_identity(record.identity())?;
            self.insert_terminal(record.result())?;
        }
        for charge in inputs.budget_carry_forwards {
            self.insert_historical_charge(charge)?;
        }
        for retirement in inputs.permit_carry_forwards {
            self.insert_historical_retirement(retirement)?;
        }
        Ok(())
    }

    fn insert_normal_identity(
        &mut self,
        identity: &NonceIdentityV1,
    ) -> Result<(), CanonicalCodecError> {
        let identity_key = *identity.as_bytes();
        let session = session_key(identity);
        if self.identities.contains_key(&identity_key) || self.sessions.contains_key(&session) {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        self.identities.insert(identity_key, identity_key);
        self.sessions.insert(session, identity_key);
        Ok(())
    }

    fn merge_historical_identity(
        &mut self,
        identity: &NonceIdentityV1,
    ) -> Result<(), CanonicalCodecError> {
        let identity_key = *identity.as_bytes();
        let session = session_key(identity);
        if self
            .identities
            .get(&identity_key)
            .is_some_and(|existing| existing != &identity_key)
            || self
                .sessions
                .get(&session)
                .is_some_and(|existing| existing != &identity_key)
        {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        self.identities.entry(identity_key).or_insert(identity_key);
        self.sessions.entry(session).or_insert(identity_key);
        Ok(())
    }

    fn insert_normal_charge(&mut self, charge: &BudgetChargeV1) -> Result<(), CanonicalCodecError> {
        let authority = charge.reservation_authority();
        let request = copy_32(authority.request_lookup_id())?;
        let reservation = copy_32(authority.reservation_id())?;
        if self.requests.contains_key(&request) || self.reservations.contains_key(&reservation) {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        self.requests.insert(request, charge.as_bytes().to_vec());
        self.reservations
            .insert(reservation, charge.as_bytes().to_vec());
        Ok(())
    }

    fn insert_historical_charge(
        &mut self,
        charge: &BudgetChargeV1,
    ) -> Result<(), CanonicalCodecError> {
        let authority = charge.reservation_authority();
        self.merge_historical_identity(&authority.nonce_identity()?)?;
        let request = copy_32(authority.request_lookup_id())?;
        let reservation = copy_32(authority.reservation_id())?;
        if self.requests.contains_key(&request) || self.reservations.contains_key(&reservation) {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        self.requests.insert(request, charge.as_bytes().to_vec());
        self.reservations
            .insert(reservation, charge.as_bytes().to_vec());
        Ok(())
    }

    fn insert_historical_retirement(
        &mut self,
        retirement: &PermitRetirementV1,
    ) -> Result<(), CanonicalCodecError> {
        let permit = copy_32(retirement.permit_id().as_bytes())?;
        if self.permits.contains_key(&permit) {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        self.permits.insert(permit, *retirement.as_bytes());
        Ok(())
    }

    fn insert_terminal(&mut self, tombstone: &TombstoneV1) -> Result<(), CanonicalCodecError> {
        let identity = *tombstone.identity().as_bytes();
        match self.terminals.get(&identity) {
            Some(existing) if existing.as_slice() == tombstone.as_bytes() => Ok(()),
            Some(_) => Err(CanonicalCodecError::AuthenticationFailed),
            None => {
                self.terminals
                    .insert(identity, tombstone.as_bytes().to_vec());
                Ok(())
            }
        }
    }

    #[cfg(test)]
    fn counts(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.sessions.len(),
            self.identities.len(),
            self.requests.len(),
            self.reservations.len(),
            self.permits.len(),
        )
    }
}

fn copy_32(input: &[u8]) -> Result<[u8; 32], CanonicalCodecError> {
    input
        .try_into()
        .map_err(|_| CanonicalCodecError::InvalidEncoding)
}

fn append_restore_payload(
    entries: &mut Vec<JournalEntryV1>,
    payload: JournalPayloadV1,
) -> Result<(), CanonicalCodecError> {
    let predecessor = entries
        .last()
        .ok_or(CanonicalCodecError::InvalidLifecycle)?;
    let entry = JournalEntryV1::append(predecessor, payload)?;
    entries.push(entry);
    Ok(())
}

fn validate_restore_inputs(
    target_head: Option<&JournalEntryV1>,
    inputs: &RestoreJournalInputsV1<'_>,
) -> Result<(), CanonicalCodecError> {
    match target_head {
        None => {
            if inputs.manifest.target_journal_sequence() != 0
                || !is_zero(inputs.manifest.target_journal_head_digest())
            {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
        }
        Some(head) => {
            if inputs.manifest.is_new_device_target()
                || inputs.manifest.target_journal_sequence() != head.sequence()
                || inputs.manifest.target_journal_head_digest() != head.entry_digest()
            {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
        }
    }

    let mut previous_identity: Option<&[u8]> = None;
    for record in inputs.records {
        let identity = record.identity().as_bytes().as_slice();
        if previous_identity.is_some_and(|previous| previous >= identity) {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        previous_identity = Some(identity);
    }
    let mut previous_reservation: Option<&[u8]> = None;
    for charge in inputs.budget_carry_forwards {
        let reservation = charge.reservation_authority().reservation_id();
        if previous_reservation.is_some_and(|previous| previous >= reservation) {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        previous_reservation = Some(reservation);
    }
    let mut previous_permit: Option<&[u8]> = None;
    for retirement in inputs.permit_carry_forwards {
        let permit = retirement.permit_id().as_bytes().as_slice();
        if previous_permit.is_some_and(|previous| previous >= permit) {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        previous_permit = Some(permit);
    }

    let epoch = inputs.epoch_advance;
    if epoch.contract_wallet_id() != inputs.manifest.contract_wallet_id()
        || epoch.predecessor_vault_id() != inputs.manifest.target_vault_id()
        || epoch.predecessor_epoch() != inputs.manifest.target_epoch()
        || epoch.successor_epoch() != inputs.manifest.successor_epoch()
        || epoch.successor_vault_id() == inputs.manifest.source_vault_id()
        || epoch.restore_transaction_id() != inputs.manifest.restore_transaction_id()
        || is_zero(epoch.generation_core_digest())
    {
        return Err(CanonicalCodecError::InvalidLifecycle);
    }
    Ok(())
}

fn sequence_index(sequence: u64) -> Result<usize, CanonicalCodecError> {
    match sequence {
        1 => Ok(0),
        2 => Ok(1),
        3 => Ok(2),
        _ => Err(CanonicalCodecError::InvalidEncoding),
    }
}

fn session_key(identity: &NonceIdentityV1) -> [u8; 32] {
    let mut session = [0_u8; 32];
    session.copy_from_slice(identity.session_id());
    session
}

fn exact_payload_length(payload: &[u8], expected: usize) -> Result<(), CanonicalCodecError> {
    if payload.len() == expected {
        Ok(())
    } else {
        Err(CanonicalCodecError::InvalidEncoding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{NonceIdentityV1, PurposeV1, SigningPhaseV1};

    fn authenticated_reservation(
        purpose: PurposeV1,
        reserve_sequence: u64,
    ) -> Result<(SessionClaimV1, BudgetChargeV1), CanonicalCodecError> {
        crate::canonical::reservation::tests::reserve_records(purpose, reserve_sequence)
    }

    fn distinct_reservation(
        purpose: PurposeV1,
        reserve_sequence: u64,
        reservation_byte: u8,
        session_byte: u8,
    ) -> Result<(SessionClaimV1, BudgetChargeV1), CanonicalCodecError> {
        crate::canonical::reservation::tests::reserve_records_with_ids(
            purpose,
            reserve_sequence,
            reservation_byte,
            session_byte,
        )
    }

    fn reservation_with_unique_request(
        purpose: PurposeV1,
        reserve_sequence: u64,
        reservation_byte: u8,
        session_byte: u8,
        request_byte: u8,
    ) -> Result<(SessionClaimV1, BudgetChargeV1), CanonicalCodecError> {
        let (_, seed_charge) =
            distinct_reservation(purpose, reserve_sequence, reservation_byte, session_byte)?;
        let mut policy_bytes = [0_u8; crate::canonical::BUDGET_POLICY_LEN];
        policy_bytes[..8].copy_from_slice(b"DOMNVBP1");
        policy_bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        policy_bytes[10] = crate::canonical::BudgetPolicyProfileV1::EvidenceOnly as u8;
        policy_bytes[11] = 1;
        policy_bytes[16..48].fill(1);
        policy_bytes[48..56].copy_from_slice(&10_u64.to_le_bytes());
        policy_bytes[56..64].copy_from_slice(&9_u64.to_le_bytes());
        policy_bytes[64..68].copy_from_slice(&2_u32.to_le_bytes());
        policy_bytes[72..80].copy_from_slice(&8_u64.to_le_bytes());
        policy_bytes[80..88].copy_from_slice(&60_u64.to_le_bytes());
        policy_bytes[88..96].copy_from_slice(&30_u64.to_le_bytes());
        policy_bytes[96..104].copy_from_slice(&1_u64.to_le_bytes());
        policy_bytes[104..112].copy_from_slice(&100_u64.to_le_bytes());
        let digest = storage_hash(StorageHashDomainV1::BudgetPolicy, &policy_bytes[..112]);
        policy_bytes[112..].copy_from_slice(&digest);
        let policy = crate::canonical::BudgetPolicyV1::from_bytes(&policy_bytes)?;
        let authority = crate::canonical::ReservationAuthorityV1::new(
            seed_charge.reservation_authority().context_binding(),
            [request_byte; 32],
            [reservation_byte; 32],
            1,
            &policy,
        )?;
        let charge = BudgetChargeV1::new(&authority, 100, reserve_sequence, &policy)?;
        let claim = SessionClaimV1::new(authority.nonce_identity()?)?;
        Ok((claim, charge))
    }

    fn encoded_restore_tail(
        target_head: Option<&JournalEntryV1>,
        inputs: RestoreJournalInputsV1<'_>,
    ) -> Result<Vec<Vec<u8>>, CanonicalCodecError> {
        Ok(RestoredJournalV1::new(target_head, inputs)?
            .entries()
            .iter()
            .map(|entry| entry.as_bytes().to_vec())
            .collect())
    }

    fn generation_core(
        marker: u8,
        nonce_epoch: u64,
        generation: u64,
    ) -> Result<VaultGenerationCoreV1, CanonicalCodecError> {
        VaultGenerationCoreV1::new(
            [0x90; 32],
            [0x91; 32],
            [marker.wrapping_add(2); 32],
            nonce_epoch,
            generation,
            [marker.wrapping_add(5); 32],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn restore_transition(
        target_head: Option<&JournalEntryV1>,
        marker: u8,
        target_vault_id: [u8; 32],
        target_epoch: u64,
        source_epoch: u64,
        predecessor_generation: u64,
        successor_generation: u64,
        source_record_count: u32,
    ) -> Result<(RestoreManifestV1, EpochAdvancePayloadV1), CanonicalCodecError> {
        let restore_transaction_id = [marker; 16];
        let contract_wallet_id = [0x90; 32];
        let source_vault_id = [marker.wrapping_add(1); 32];
        let successor_vault_id = [marker.wrapping_add(2); 32];
        let record_set_digest = [marker.wrapping_add(3); 32];
        let manifest = if !is_zero(&target_vault_id) {
            let (target_sequence, target_digest) = target_head
                .map(|head| (head.sequence(), *head.entry_digest()))
                .unwrap_or((0, [0; 32]));
            RestoreManifestV1::new_existing_device(
                restore_transaction_id,
                contract_wallet_id,
                target_vault_id,
                target_epoch,
                target_sequence,
                target_digest,
                source_vault_id,
                source_epoch,
                0,
                [0; 32],
                source_record_count,
                record_set_digest,
            )?
        } else {
            RestoreManifestV1::new_restore_only(
                restore_transaction_id,
                contract_wallet_id,
                source_vault_id,
                source_epoch,
                0,
                [0; 32],
                source_record_count,
                record_set_digest,
            )?
        };
        let successor_epoch = target_epoch.max(source_epoch) + 1;
        let core = generation_core(marker, successor_epoch, successor_generation)?;
        let epoch = EpochAdvancePayloadV1::new(
            contract_wallet_id,
            target_vault_id,
            successor_vault_id,
            target_epoch,
            successor_epoch,
            predecessor_generation,
            successor_generation,
            restore_transaction_id,
            *core.generation_core_digest(),
        )?;
        Ok((manifest, epoch))
    }

    fn burned_restore_record(
        claim: &SessionClaimV1,
    ) -> Result<RestoreRecordPayloadV1, CanonicalCodecError> {
        let evidence = TerminalEvidenceV1::select_without_active_secret(claim, &[], &[])?;
        RestoreRecordPayloadV1::burn(&TombstoneV1::new_burn(&evidence)?)
    }

    fn pending_index(
        manifest: &RestoreManifestV1,
        core: &VaultGenerationCoreV1,
        active: &ActiveVaultGenerationV1,
        head: &JournalEntryV1,
    ) -> Result<RestorePendingIndexV1, CanonicalCodecError> {
        let mut restore_transaction_id = [0_u8; 16];
        restore_transaction_id.copy_from_slice(manifest.restore_transaction_id());
        RestorePendingIndexV1::new(crate::canonical::RestorePendingIndexFieldsV1 {
            restore_transaction_id,
            contract_wallet_id: [0x90; 32],
            restore_manifest_digest: *manifest.manifest_digest(),
            source_backup_bundle_digest: [0xa1; 32],
            source_backup_master_envelope_digest: [0xa2; 32],
            source_backup_manifest_object_envelope_digest: [0xa3; 32],
            source_journal_sequence: 0,
            source_journal_head_digest: [0; 32],
            source_record_count: 0,
            source_record_set_digest: [0xa4; 32],
            successor_generation_core_digest: *core.generation_core_digest(),
            successor_master_envelope_digest: core
                .master_envelope_digest()
                .try_into()
                .map_err(|_| CanonicalCodecError::InvalidEncoding)?,
            successor_final_journal_sequence: head.sequence(),
            successor_final_journal_head_digest: *head.entry_digest(),
            successor_record_count: 0,
            successor_record_set_digest: [0xa5; 32],
            successor_tombstone_envelope_set_digest: [0xa6; 32],
            successor_active_generation_digest: *active.active_generation_digest(),
            restore_only_root_digest: [0xa7; 32],
        })
    }

    fn authenticated_nonce_derivation(
        attempt: &AttemptRecordV1,
        effective_retry_counter: u64,
    ) -> Result<NonceDerivationAttemptV1, CanonicalCodecError> {
        let mut bytes = [0_u8; NONCE_DERIVATION_ATTEMPT_LEN];
        bytes[..ATTEMPT_RECORD_LEN].copy_from_slice(attempt.as_bytes());
        bytes[ATTEMPT_RECORD_LEN..].copy_from_slice(&effective_retry_counter.to_le_bytes());
        NonceDerivationAttemptV1::from_bytes(&bytes)
    }

    fn envelope(sequence: u64, kind: u8, payload_length: usize) -> Vec<u8> {
        let mut bytes = vec![0_u8; JOURNAL_ENTRY_MIN_LEN + payload_length];
        bytes[..8].copy_from_slice(JOURNAL_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..18].copy_from_slice(&sequence.to_le_bytes());
        if sequence > 1 {
            bytes[18..50].fill(0x11);
        }
        bytes[50] = kind;
        let payload_length_u32 = u32::try_from(payload_length).unwrap_or(u32::MAX);
        bytes[52..56].copy_from_slice(&payload_length_u32.to_le_bytes());
        bytes[56..56 + payload_length].fill(0x22);
        bytes
    }

    fn entry(kind: JournalEntryKindV1, payload: &[u8]) -> Vec<u8> {
        let mut bytes = envelope(1, kind as u8, payload.len());
        bytes[56..56 + payload.len()].copy_from_slice(payload);
        bytes
    }

    fn identity() -> [u8; 105] {
        let mut bytes = [0_u8; 105];
        bytes[..32].fill(0x11);
        bytes[32..64].fill(0x22);
        bytes[64] = 0x02;
        bytes[65..97].fill(0x33);
        bytes[97..105].copy_from_slice(&7_u64.to_le_bytes());
        bytes
    }

    fn attempt() -> [u8; ATTEMPT_RECORD_LEN] {
        let mut bytes = [0_u8; ATTEMPT_RECORD_LEN];
        bytes[..8].copy_from_slice(b"DOMNVAT1");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..115].copy_from_slice(&identity());
        bytes[115..123].copy_from_slice(&9_u64.to_le_bytes());
        bytes[123..125].copy_from_slice(&0x0100_u16.to_le_bytes());
        bytes[125] = ArtifactKindV1::Commitment as u8;
        bytes
    }

    fn derivation_attempt() -> [u8; NONCE_DERIVATION_ATTEMPT_LEN] {
        let mut bytes = [0_u8; NONCE_DERIVATION_ATTEMPT_LEN];
        bytes[..ATTEMPT_RECORD_LEN].copy_from_slice(&attempt());
        bytes[ATTEMPT_RECORD_LEN..].copy_from_slice(&3_u64.to_le_bytes());
        bytes
    }

    fn reserve_payload() -> Result<Vec<u8>, CanonicalCodecError> {
        let (claim, charge) = authenticated_reservation(PurposeV1::Funding, 1)?;
        let mut bytes = Vec::with_capacity(SESSION_CLAIM_LEN + charge.as_bytes().len());
        bytes.extend_from_slice(claim.as_bytes());
        bytes.extend_from_slice(charge.as_bytes());
        Ok(bytes)
    }

    fn exposure(
        sequence: u64,
        state: ExposureStateV1,
        revision: u64,
        record_digest: u8,
    ) -> Vec<u8> {
        let artifact = match sequence {
            1 => ArtifactKindV1::Commitment,
            2 => ArtifactKindV1::Reveal,
            3 => ArtifactKindV1::PartialSignature,
            _ => ArtifactKindV1::Commitment,
        };
        let outbound_length = 32_usize;
        let mut bytes = vec![0_u8; 233 + outbound_length];
        bytes[..8].copy_from_slice(b"DOMNVEX1");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10] = state as u8;
        bytes[11] = artifact as u8;
        bytes[12..117].copy_from_slice(&identity());
        bytes[117..125].copy_from_slice(&sequence.to_le_bytes());
        bytes[125..133].copy_from_slice(&revision.to_le_bytes());
        bytes[197..201].copy_from_slice(&32_u32.to_le_bytes());
        bytes[201..233].fill(0x44);
        bytes[233..265].fill(record_digest);
        bytes
    }

    fn exposure_version(
        sequence: u64,
        state: ExposureStateV1,
        revision: u64,
        record_digest: u8,
    ) -> [u8; EXPOSURE_VERSION_ID_LEN] {
        let artifact = match sequence {
            1 => ArtifactKindV1::Commitment,
            2 => ArtifactKindV1::Reveal,
            3 => ArtifactKindV1::PartialSignature,
            _ => ArtifactKindV1::Commitment,
        };
        let mut bytes = [0_u8; EXPOSURE_VERSION_ID_LEN];
        bytes[..105].copy_from_slice(&identity());
        bytes[105..113].copy_from_slice(&sequence.to_le_bytes());
        bytes[113] = state as u8;
        bytes[114] = artifact as u8;
        bytes[115..123].copy_from_slice(&revision.to_le_bytes());
        bytes[123..155].fill(record_digest);
        bytes
    }

    fn authorization_payload() -> Vec<u8> {
        let successor = exposure(1, ExposureStateV1::Authorized, 10, 0x55);
        let mut bytes = vec![0_u8; 159 + successor.len()];
        bytes[..155].copy_from_slice(&exposure_version(1, ExposureStateV1::Persisted, 9, 0x44));
        bytes[155..159].copy_from_slice(&265_u32.to_le_bytes());
        bytes[159..].copy_from_slice(&successor);
        bytes
    }

    fn tombstone(reason: TerminalReasonV1, revision: u64, related_digest: u8) -> [u8; 255] {
        let mut bytes = [0_u8; 255];
        bytes[..8].copy_from_slice(b"DOMNVTS1");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..115].copy_from_slice(&identity());
        bytes[115] = reason as u8;
        bytes[119..127].copy_from_slice(&revision.to_le_bytes());
        if reason == TerminalReasonV1::Consumed {
            bytes[127..159].fill(0x66);
            bytes[159..191].fill(related_digest);
            bytes[191..223].fill(0x77);
        }
        bytes
    }

    fn partial_consumed_payload() -> Vec<u8> {
        let partial = exposure(3, ExposureStateV1::Persisted, 9, 0x55);
        let consumed = tombstone(TerminalReasonV1::Consumed, 10, 0x55);
        let mut bytes = vec![0_u8; 4 + partial.len() + consumed.len()];
        bytes[..4].copy_from_slice(&265_u32.to_le_bytes());
        bytes[4..269].copy_from_slice(&partial);
        bytes[269..].copy_from_slice(&consumed);
        bytes
    }

    fn restore_manifest() -> [u8; RESTORE_MANIFEST_LEN] {
        let mut bytes = [0_u8; RESTORE_MANIFEST_LEN];
        bytes[..8].copy_from_slice(b"DOMNVRT1");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..26].fill(0x10);
        bytes[26..58].fill(0x11);
        bytes[58..90].fill(0x22);
        bytes[90..98].copy_from_slice(&3_u64.to_le_bytes());
        bytes[138..170].fill(0x33);
        bytes[170..178].copy_from_slice(&5_u64.to_le_bytes());
        bytes[218..226].copy_from_slice(&6_u64.to_le_bytes());
        bytes[230..262].fill(0x44);
        bytes
    }

    fn restore_record() -> [u8; RESTORE_RECORD_PAYLOAD_LEN] {
        let mut bytes = [0_u8; RESTORE_RECORD_PAYLOAD_LEN];
        bytes[..105].copy_from_slice(&identity());
        bytes[179] = 4;
        bytes[180..184].copy_from_slice(&255_u32.to_le_bytes());
        bytes[184..216].fill(0x55);
        bytes[216] = 2;
        bytes
    }

    fn restore_complete_payload() -> [u8; RESTORE_COMPLETE_LEN + 32] {
        let mut bytes = [0_u8; RESTORE_COMPLETE_LEN + 32];
        bytes[..8].copy_from_slice(b"DOMNVRC1");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..26].fill(0x11);
        bytes[90..98].fill(0x77);
        bytes[98..130].fill(0x77);
        bytes
    }

    fn epoch_advance() -> [u8; EPOCH_ADVANCE_PAYLOAD_LEN] {
        let mut bytes = [0_u8; EPOCH_ADVANCE_PAYLOAD_LEN];
        bytes[..32].fill(0x11);
        bytes[64..96].fill(0x33);
        bytes[104..112].copy_from_slice(&5_u64.to_le_bytes());
        bytes[120..128].copy_from_slice(&1_u64.to_le_bytes());
        bytes[128..144].fill(0x44);
        bytes[144..176].fill(0x55);
        bytes
    }

    #[test]
    fn outer_envelope_accepts_exact_minimum_and_maximum() -> Result<(), CanonicalCodecError> {
        for (sequence, payload_length) in [(1, 0), (2, JOURNAL_PAYLOAD_MAX_LEN)] {
            let bytes = envelope(sequence, JournalEntryKindV1::Reserve as u8, payload_length);
            let parsed = UnauthenticatedJournalEnvelopeV1::parse_outer(&bytes)?;
            assert_eq!(parsed.as_bytes(), bytes);
            assert_eq!(parsed.sequence(), sequence);
            assert_eq!(parsed.payload().len(), payload_length);
            assert_eq!(parsed.entry_digest(), &[0; 32]);
        }
        Ok(())
    }

    #[test]
    fn predecessor_zero_sentinel_is_sequence_one_only() {
        let mut first = envelope(1, 1, 0);
        first[18] = 1;
        assert!(UnauthenticatedJournalEnvelopeV1::parse_outer(&first).is_err());

        let mut later = envelope(2, 1, 0);
        later[18..50].fill(0);
        assert!(UnauthenticatedJournalEnvelopeV1::parse_outer(&later).is_err());
    }

    #[test]
    fn outer_envelope_rejects_mutated_framing() {
        let canonical = envelope(2, 1, 32);
        let mutations = [(0, canonical[0] ^ 1), (8, 2), (10, 0), (50, 0), (51, 1)];
        for (offset, replacement) in mutations {
            let mut bytes = canonical.clone();
            bytes[offset] = replacement;
            assert!(UnauthenticatedJournalEnvelopeV1::parse_outer(&bytes).is_err());
        }

        let mut wrong_length = canonical.clone();
        wrong_length[52..56].copy_from_slice(&31_u32.to_le_bytes());
        assert!(UnauthenticatedJournalEnvelopeV1::parse_outer(&wrong_length).is_err());
        assert!(UnauthenticatedJournalEnvelopeV1::parse_outer(&canonical[..119]).is_err());
    }

    #[test]
    fn complete_entry_parser_accepts_all_fourteen_assigned_payloads(
    ) -> Result<(), CanonicalCodecError> {
        let (_, budget_charge) = authenticated_reservation(PurposeV1::Funding, 1)?;
        let retirement = crate::canonical::permit::tests::retirement()?;
        let cases = vec![
            (JournalEntryKindV1::Reserve, reserve_payload()?),
            (
                JournalEntryKindV1::ComputationAttempt,
                derivation_attempt().to_vec(),
            ),
            (
                JournalEntryKindV1::CommitmentPersisted,
                exposure(1, ExposureStateV1::Persisted, 9, 0x44),
            ),
            (
                JournalEntryKindV1::ExposureAuthorized,
                authorization_payload(),
            ),
            (
                JournalEntryKindV1::RevealPersisted,
                exposure(2, ExposureStateV1::Persisted, 9, 0x44),
            ),
            (
                JournalEntryKindV1::PartialConsumed,
                partial_consumed_payload(),
            ),
            (
                JournalEntryKindV1::AbortConsumed,
                tombstone(TerminalReasonV1::AbortConsumed, 9, 0).to_vec(),
            ),
            (
                JournalEntryKindV1::Burned,
                tombstone(TerminalReasonV1::Burned, 9, 0).to_vec(),
            ),
            (
                JournalEntryKindV1::RestoreBegin,
                restore_manifest().to_vec(),
            ),
            (JournalEntryKindV1::RestoreRecord, restore_record().to_vec()),
            (
                JournalEntryKindV1::RestoreComplete,
                restore_complete_payload().to_vec(),
            ),
            (JournalEntryKindV1::EpochAdvance, epoch_advance().to_vec()),
            (
                JournalEntryKindV1::BudgetCarryForward,
                budget_charge.as_bytes().to_vec(),
            ),
            (
                JournalEntryKindV1::PermitRetirementCarryForward,
                retirement.to_vec(),
            ),
        ];

        for (kind, payload) in cases {
            let bytes = entry(kind, &payload);
            let parsed = UnauthenticatedJournalEntryV1::parse_structural(&bytes)?;
            assert_eq!(parsed.envelope().kind(), kind);
            let matching_variant = matches!(
                (kind, parsed.payload()),
                (
                    JournalEntryKindV1::Reserve,
                    UnauthenticatedJournalPayloadV1::Reserve(_)
                ) | (
                    JournalEntryKindV1::ComputationAttempt,
                    UnauthenticatedJournalPayloadV1::ComputationAttempt(_)
                ) | (
                    JournalEntryKindV1::CommitmentPersisted,
                    UnauthenticatedJournalPayloadV1::CommitmentPersisted(_)
                ) | (
                    JournalEntryKindV1::ExposureAuthorized,
                    UnauthenticatedJournalPayloadV1::ExposureAuthorized(_)
                ) | (
                    JournalEntryKindV1::RevealPersisted,
                    UnauthenticatedJournalPayloadV1::RevealPersisted(_)
                ) | (
                    JournalEntryKindV1::PartialConsumed,
                    UnauthenticatedJournalPayloadV1::PartialConsumed(_)
                ) | (
                    JournalEntryKindV1::AbortConsumed,
                    UnauthenticatedJournalPayloadV1::AbortConsumed(_)
                ) | (
                    JournalEntryKindV1::Burned,
                    UnauthenticatedJournalPayloadV1::Burned(_)
                ) | (
                    JournalEntryKindV1::RestoreBegin,
                    UnauthenticatedJournalPayloadV1::RestoreBegin(_)
                ) | (
                    JournalEntryKindV1::RestoreRecord,
                    UnauthenticatedJournalPayloadV1::RestoreRecord(_)
                ) | (
                    JournalEntryKindV1::RestoreComplete,
                    UnauthenticatedJournalPayloadV1::RestoreComplete(_)
                ) | (
                    JournalEntryKindV1::EpochAdvance,
                    UnauthenticatedJournalPayloadV1::EpochAdvance(_)
                ) | (
                    JournalEntryKindV1::BudgetCarryForward,
                    UnauthenticatedJournalPayloadV1::BudgetCarryForward(_)
                ) | (
                    JournalEntryKindV1::PermitRetirementCarryForward,
                    UnauthenticatedJournalPayloadV1::PermitRetirementCarryForward(_)
                )
            );
            assert!(matching_variant);
        }
        Ok(())
    }

    #[test]
    fn complete_entry_parser_rejects_kind_payload_substitution() {
        let reveal = exposure(2, ExposureStateV1::Persisted, 9, 0x44);
        assert!(UnauthenticatedJournalEntryV1::parse_structural(&entry(
            JournalEntryKindV1::CommitmentPersisted,
            &reveal,
        ))
        .is_err());

        let burned = tombstone(TerminalReasonV1::Burned, 9, 0);
        assert!(UnauthenticatedJournalEntryV1::parse_structural(&entry(
            JournalEntryKindV1::AbortConsumed,
            &burned,
        ))
        .is_err());
    }

    #[test]
    fn computation_attempt_parser_enforces_stage_specific_exact_lengths() {
        let commitment = derivation_attempt();
        assert!(matches!(
            UnauthenticatedComputationAttemptV1::parse_structural(&commitment),
            Ok(UnauthenticatedComputationAttemptV1::NonceDerivation(_))
        ));
        assert!(UnauthenticatedComputationAttemptV1::parse_structural(
            &commitment[..ATTEMPT_RECORD_LEN]
        )
        .is_err());

        for (phase, artifact) in [
            (SigningPhaseV1::SigNonceReveal, ArtifactKindV1::Reveal),
            (SigningPhaseV1::SigPartial, ArtifactKindV1::PartialSignature),
        ] {
            let mut later = attempt();
            later[123..125].copy_from_slice(&(phase as u16).to_le_bytes());
            later[125] = artifact as u8;
            assert!(matches!(
                UnauthenticatedComputationAttemptV1::parse_structural(&later),
                Ok(UnauthenticatedComputationAttemptV1::LaterStage(_))
            ));
            let mut oversized = later.to_vec();
            oversized.extend_from_slice(&0_u64.to_le_bytes());
            assert!(UnauthenticatedComputationAttemptV1::parse_structural(&oversized).is_err());
        }
    }

    #[test]
    fn exposure_authorization_rejects_revision_and_state_skips() {
        let canonical = authorization_payload();

        let mut wrong_revision = canonical.clone();
        wrong_revision[159 + 125..159 + 133].copy_from_slice(&11_u64.to_le_bytes());
        assert!(
            UnauthenticatedExposureAuthorizationPayloadV1::parse_structural(&wrong_revision)
                .is_err()
        );

        let mut state_skip = canonical;
        state_skip[159 + 10] = ExposureStateV1::Spent as u8;
        assert!(
            UnauthenticatedExposureAuthorizationPayloadV1::parse_structural(&state_skip).is_err()
        );
    }

    #[test]
    fn partial_consumed_rejects_wrong_revision_and_exposure_digest() {
        let canonical = partial_consumed_payload();

        let mut wrong_revision = canonical.clone();
        wrong_revision[269 + 119..269 + 127].copy_from_slice(&11_u64.to_le_bytes());
        assert!(
            UnauthenticatedPartialConsumedPayloadV1::parse_structural(&wrong_revision).is_err()
        );

        let mut wrong_digest = canonical;
        wrong_digest[269 + 159] ^= 1;
        assert!(UnauthenticatedPartialConsumedPayloadV1::parse_structural(&wrong_digest).is_err());
    }

    #[test]
    fn restore_complete_payload_rejects_prefix_mismatch() {
        let mut bytes = restore_complete_payload();
        bytes[98] ^= 1;
        assert!(UnauthenticatedRestoreCompletePayloadV1::parse_structural(&bytes).is_err());
    }

    #[test]
    fn journal_kind_registry_is_exhaustive() {
        for value in 0_u8..=u8::MAX {
            assert_eq!(
                JournalEntryKindV1::try_from(value).is_ok(),
                (0x01..=0x0e).contains(&value)
            );
        }
    }

    #[test]
    fn journal_records_reject_every_truncation_and_trailing_byte() -> Result<(), CanonicalCodecError>
    {
        let authorization = authorization_payload();
        for end in 0..authorization.len() {
            assert!(
                UnauthenticatedExposureAuthorizationPayloadV1::parse_structural(
                    &authorization[..end]
                )
                .is_err(),
                "authorization {end}"
            );
        }
        let mut trailing_authorization = authorization;
        trailing_authorization.push(0);
        assert!(
            UnauthenticatedExposureAuthorizationPayloadV1::parse_structural(
                &trailing_authorization
            )
            .is_err()
        );

        let partial = partial_consumed_payload();
        for end in 0..partial.len() {
            assert!(
                UnauthenticatedPartialConsumedPayloadV1::parse_structural(&partial[..end]).is_err(),
                "partial {end}"
            );
        }
        let mut trailing_partial = partial;
        trailing_partial.push(0);
        assert!(
            UnauthenticatedPartialConsumedPayloadV1::parse_structural(&trailing_partial).is_err()
        );

        let completion = restore_complete_payload();
        for end in 0..completion.len() {
            assert!(
                UnauthenticatedRestoreCompletePayloadV1::parse_structural(&completion[..end])
                    .is_err(),
                "completion {end}"
            );
        }
        let mut trailing_completion = completion.to_vec();
        trailing_completion.push(0);
        assert!(
            UnauthenticatedRestoreCompletePayloadV1::parse_structural(&trailing_completion)
                .is_err()
        );

        let reserve_payload = reserve_payload()?;
        let reserve = entry(JournalEntryKindV1::Reserve, &reserve_payload);
        for end in 0..reserve.len() {
            assert!(
                UnauthenticatedJournalEnvelopeV1::parse_outer(&reserve[..end]).is_err(),
                "outer {end}"
            );
            assert!(
                UnauthenticatedJournalEntryV1::parse_structural(&reserve[..end]).is_err(),
                "entry {end}"
            );
        }
        let mut trailing_reserve = reserve;
        trailing_reserve.push(0);
        assert!(UnauthenticatedJournalEnvelopeV1::parse_outer(&trailing_reserve).is_err());
        assert!(UnauthenticatedJournalEntryV1::parse_structural(&trailing_reserve).is_err());
        Ok(())
    }

    #[test]
    fn authenticated_journal_constructs_and_verifies_complete_minimal_lifecycle(
    ) -> Result<(), CanonicalCodecError> {
        let (claim, charge) = authenticated_reservation(PurposeV1::ClaimAdaptor, 1)?;
        let reserve = JournalEntryV1::first(JournalPayloadV1::reserve(&claim, &charge)?)?;
        let reserve_open = JournalEntryV1::from_bytes(
            reserve.as_bytes(),
            None,
            JournalPayloadEvidenceV1::SelfContained,
        )?;

        let commitment_attempt = AttemptRecordV1::new(
            *claim.identity(),
            1,
            SigningPhaseV1::SigNonceCommit,
            [0x91; 32],
        )?;
        let commitment_derivation = authenticated_nonce_derivation(&commitment_attempt, 0)?;
        let commitment_attempt_entry = JournalEntryV1::append(
            &reserve,
            JournalPayloadV1::nonce_derivation_attempt(&commitment_derivation),
        )?;
        let commitment_attempt_open = JournalEntryV1::from_bytes(
            commitment_attempt_entry.as_bytes(),
            Some(&reserve_open),
            JournalPayloadEvidenceV1::SelfContained,
        )?;

        let commitment = ExposureRecordV1::new_persisted(&commitment_attempt, None, &[0xa1; 35])?;
        let commitment_entry = JournalEntryV1::append(
            &commitment_attempt_entry,
            JournalPayloadV1::persisted(&commitment_attempt, None, &commitment)?,
        )?;
        let commitment_open = JournalEntryV1::from_bytes(
            commitment_entry.as_bytes(),
            Some(&commitment_attempt_open),
            JournalPayloadEvidenceV1::Persisted {
                attempt: &commitment_attempt,
                preceding_spent: None,
            },
        )?;

        let commitment_authorized = ExposureRecordV1::new_successor(&commitment, None)?;
        let commitment_authorized_entry = JournalEntryV1::append(
            &commitment_entry,
            JournalPayloadV1::exposure_authorized(&commitment, &commitment_authorized, None)?,
        )?;
        let commitment_authorized_open = JournalEntryV1::from_bytes(
            commitment_authorized_entry.as_bytes(),
            Some(&commitment_open),
            JournalPayloadEvidenceV1::ExposureTransition {
                predecessor: &commitment,
                intervening_tombstone: None,
            },
        )?;
        let commitment_spent = ExposureRecordV1::new_successor(&commitment_authorized, None)?;
        let commitment_spent_entry = JournalEntryV1::append(
            &commitment_authorized_entry,
            JournalPayloadV1::exposure_authorized(&commitment_authorized, &commitment_spent, None)?,
        )?;
        let commitment_spent_open = JournalEntryV1::from_bytes(
            commitment_spent_entry.as_bytes(),
            Some(&commitment_authorized_open),
            JournalPayloadEvidenceV1::ExposureTransition {
                predecessor: &commitment_authorized,
                intervening_tombstone: None,
            },
        )?;

        let reveal_attempt = AttemptRecordV1::new(
            *claim.identity(),
            4,
            SigningPhaseV1::SigNonceReveal,
            [0x92; 32],
        )?;
        let reveal_attempt_entry = JournalEntryV1::append(
            &commitment_spent_entry,
            JournalPayloadV1::computation_attempt(&reveal_attempt)?,
        )?;
        let reveal_attempt_open = JournalEntryV1::from_bytes(
            reveal_attempt_entry.as_bytes(),
            Some(&commitment_spent_open),
            JournalPayloadEvidenceV1::SelfContained,
        )?;
        let reveal =
            ExposureRecordV1::new_persisted(&reveal_attempt, Some(&commitment_spent), &[0xa2; 69])?;
        let reveal_entry = JournalEntryV1::append(
            &reveal_attempt_entry,
            JournalPayloadV1::persisted(&reveal_attempt, Some(&commitment_spent), &reveal)?,
        )?;
        let reveal_open = JournalEntryV1::from_bytes(
            reveal_entry.as_bytes(),
            Some(&reveal_attempt_open),
            JournalPayloadEvidenceV1::Persisted {
                attempt: &reveal_attempt,
                preceding_spent: Some(&commitment_spent),
            },
        )?;
        let reveal_authorized = ExposureRecordV1::new_successor(&reveal, None)?;
        let reveal_authorized_entry = JournalEntryV1::append(
            &reveal_entry,
            JournalPayloadV1::exposure_authorized(&reveal, &reveal_authorized, None)?,
        )?;
        let reveal_authorized_open = JournalEntryV1::from_bytes(
            reveal_authorized_entry.as_bytes(),
            Some(&reveal_open),
            JournalPayloadEvidenceV1::ExposureTransition {
                predecessor: &reveal,
                intervening_tombstone: None,
            },
        )?;
        let reveal_spent = ExposureRecordV1::new_successor(&reveal_authorized, None)?;
        let reveal_spent_entry = JournalEntryV1::append(
            &reveal_authorized_entry,
            JournalPayloadV1::exposure_authorized(&reveal_authorized, &reveal_spent, None)?,
        )?;
        let reveal_spent_open = JournalEntryV1::from_bytes(
            reveal_spent_entry.as_bytes(),
            Some(&reveal_authorized_open),
            JournalPayloadEvidenceV1::ExposureTransition {
                predecessor: &reveal_authorized,
                intervening_tombstone: None,
            },
        )?;

        let partial_attempt =
            AttemptRecordV1::new(*claim.identity(), 7, SigningPhaseV1::SigPartial, [0x93; 32])?;
        let partial_attempt_entry = JournalEntryV1::append(
            &reveal_spent_entry,
            JournalPayloadV1::computation_attempt(&partial_attempt)?,
        )?;
        let partial_attempt_open = JournalEntryV1::from_bytes(
            partial_attempt_entry.as_bytes(),
            Some(&reveal_spent_open),
            JournalPayloadEvidenceV1::SelfContained,
        )?;
        let partial =
            ExposureRecordV1::new_persisted(&partial_attempt, Some(&reveal_spent), &[0xa3; 67])?;
        let consumed = TombstoneV1::new_consumed(&partial_attempt, &partial, [0xb1; 32])?;
        let partial_entry = JournalEntryV1::append(
            &partial_attempt_entry,
            JournalPayloadV1::partial_consumed(
                &partial_attempt,
                &reveal_spent,
                &partial,
                &consumed,
            )?,
        )?;
        let partial_open = JournalEntryV1::from_bytes(
            partial_entry.as_bytes(),
            Some(&partial_attempt_open),
            JournalPayloadEvidenceV1::PartialConsumed {
                attempt: &partial_attempt,
                preceding_reveal: &reveal_spent,
            },
        )?;
        let partial_authorized = ExposureRecordV1::new_successor(&partial, Some(&consumed))?;
        let partial_authorized_entry = JournalEntryV1::append(
            &partial_entry,
            JournalPayloadV1::exposure_authorized(&partial, &partial_authorized, Some(&consumed))?,
        )?;
        let partial_authorized_open = JournalEntryV1::from_bytes(
            partial_authorized_entry.as_bytes(),
            Some(&partial_open),
            JournalPayloadEvidenceV1::ExposureTransition {
                predecessor: &partial,
                intervening_tombstone: Some(&consumed),
            },
        )?;
        let partial_spent = ExposureRecordV1::new_successor(&partial_authorized, None)?;
        let partial_spent_entry = JournalEntryV1::append(
            &partial_authorized_entry,
            JournalPayloadV1::exposure_authorized(&partial_authorized, &partial_spent, None)?,
        )?;
        let partial_spent_open = JournalEntryV1::from_bytes(
            partial_spent_entry.as_bytes(),
            Some(&partial_authorized_open),
            JournalPayloadEvidenceV1::ExposureTransition {
                predecessor: &partial_authorized,
                intervening_tombstone: None,
            },
        )?;
        assert_eq!(partial_spent_open.sequence(), 13);
        assert_eq!(
            partial_spent_open.payload().kind(),
            JournalEntryKindV1::ExposureAuthorized
        );

        let mut verifier = MinimalJournalV1::new();
        for encoded in [
            reserve.as_bytes(),
            commitment_attempt_entry.as_bytes(),
            commitment_entry.as_bytes(),
            commitment_authorized_entry.as_bytes(),
            commitment_spent_entry.as_bytes(),
            reveal_attempt_entry.as_bytes(),
            reveal_entry.as_bytes(),
            reveal_authorized_entry.as_bytes(),
            reveal_spent_entry.as_bytes(),
            partial_attempt_entry.as_bytes(),
            partial_entry.as_bytes(),
            partial_authorized_entry.as_bytes(),
            partial_spent_entry.as_bytes(),
        ] {
            verifier.verify_next(encoded)?;
        }
        assert_eq!(verifier.entries().len(), 13);
        assert_eq!(verifier.head().map(JournalEntryV1::sequence), Some(13));
        Ok(())
    }

    #[test]
    fn minimal_live_journal_rejects_restore_only_permit_retirement_carry_forward(
    ) -> Result<(), CanonicalCodecError> {
        let (claim, charge) = authenticated_reservation(PurposeV1::ClaimAdaptor, 1)?;
        let reserve = JournalEntryV1::first(JournalPayloadV1::reserve(&claim, &charge)?)?;
        let commitment_attempt = AttemptRecordV1::new(
            *claim.identity(),
            1,
            SigningPhaseV1::SigNonceCommit,
            [0x91; 32],
        )?;
        let commitment_derivation = authenticated_nonce_derivation(&commitment_attempt, 0)?;
        let attempt_entry = JournalEntryV1::append(
            &reserve,
            JournalPayloadV1::nonce_derivation_attempt(&commitment_derivation),
        )?;
        let commitment = ExposureRecordV1::new_persisted(&commitment_attempt, None, &[0xa1; 35])?;
        let persisted_entry = JournalEntryV1::append(
            &attempt_entry,
            JournalPayloadV1::persisted(&commitment_attempt, None, &commitment)?,
        )?;
        let authorized = ExposureRecordV1::new_successor(&commitment, None)?;
        let authorized_entry = JournalEntryV1::append(
            &persisted_entry,
            JournalPayloadV1::exposure_authorized(&commitment, &authorized, None)?,
        )?;
        let spent = ExposureRecordV1::new_successor(&authorized, None)?;
        let spent_entry = JournalEntryV1::append(
            &authorized_entry,
            JournalPayloadV1::exposure_authorized(&authorized, &spent, None)?,
        )?;
        let retirement = PermitRetirementV1::new(&spent, &spent_entry)?;
        let retirement_entry = JournalEntryV1::append(
            &spent_entry,
            JournalPayloadV1::permit_retirement_carry_forward(&retirement),
        )?;

        let reveal_attempt = AttemptRecordV1::new(
            *claim.identity(),
            4,
            SigningPhaseV1::SigNonceReveal,
            [0x92; 32],
        )?;
        let reveal_attempt_entry = JournalEntryV1::append(
            &spent_entry,
            JournalPayloadV1::computation_attempt(&reveal_attempt)?,
        )?;

        let prefix = [
            reserve.as_bytes(),
            attempt_entry.as_bytes(),
            persisted_entry.as_bytes(),
            authorized_entry.as_bytes(),
            spent_entry.as_bytes(),
        ];
        let mut verifier = MinimalJournalV1::new();
        for encoded in prefix {
            verifier.verify_next(encoded)?;
        }
        assert!(verifier.verify_next(retirement_entry.as_bytes()).is_err());
        verifier.verify_next(reveal_attempt_entry.as_bytes())?;
        assert_eq!(verifier.head().map(JournalEntryV1::sequence), Some(6));

        let premature = JournalEntryV1::append(
            &authorized_entry,
            JournalPayloadV1::permit_retirement_carry_forward(&retirement),
        )?;
        let mut premature_verifier = MinimalJournalV1::new();
        for encoded in &prefix[..4] {
            premature_verifier.verify_next(encoded)?;
        }
        assert!(premature_verifier
            .verify_next(premature.as_bytes())
            .is_err());

        let mut mismatched_bytes = *retirement.as_bytes();
        mismatched_bytes[165] ^= 1;
        let mismatched_digest = storage_hash(
            StorageHashDomainV1::PermitRetirement,
            &mismatched_bytes[..197],
        );
        mismatched_bytes[197..].copy_from_slice(&mismatched_digest);
        let mismatched = PermitRetirementV1::from_bytes(&mismatched_bytes)?;
        let mismatched_entry = JournalEntryV1::append(
            &spent_entry,
            JournalPayloadV1::permit_retirement_carry_forward(&mismatched),
        )?;
        let mut mismatched_verifier = MinimalJournalV1::new();
        for encoded in prefix {
            mismatched_verifier.verify_next(encoded)?;
        }
        assert!(mismatched_verifier
            .verify_next(mismatched_entry.as_bytes())
            .is_err());
        Ok(())
    }

    #[test]
    fn authenticated_journal_rejects_mutation_unknown_kind_and_wrong_predecessor(
    ) -> Result<(), CanonicalCodecError> {
        let (claim, charge) = authenticated_reservation(PurposeV1::ClaimAdaptor, 1)?;
        let reserve = JournalEntryV1::first(JournalPayloadV1::reserve(&claim, &charge)?)?;
        let attempt = AttemptRecordV1::new(
            *claim.identity(),
            1,
            SigningPhaseV1::SigNonceCommit,
            [0x91; 32],
        )?;
        let derivation = authenticated_nonce_derivation(&attempt, 0)?;
        let attempt_entry = JournalEntryV1::append(
            &reserve,
            JournalPayloadV1::nonce_derivation_attempt(&derivation),
        )?;

        for offset in 0..reserve.as_bytes().len() {
            let mut mutation = reserve.as_bytes().to_vec();
            mutation[offset] ^= 1;
            assert!(JournalEntryV1::from_bytes(
                &mutation,
                None,
                JournalPayloadEvidenceV1::SelfContained
            )
            .is_err());
        }

        assert!(JournalEntryV1::from_bytes(
            attempt_entry.as_bytes(),
            None,
            JournalPayloadEvidenceV1::SelfContained
        )
        .is_err());
        let (unrelated_claim, unrelated_charge) = authenticated_reservation(PurposeV1::Funding, 1)?;
        let unrelated = JournalEntryV1::first(JournalPayloadV1::reserve(
            &unrelated_claim,
            &unrelated_charge,
        )?)?;
        assert!(JournalEntryV1::from_bytes(
            attempt_entry.as_bytes(),
            Some(&unrelated),
            JournalPayloadEvidenceV1::SelfContained
        )
        .is_err());

        let mut unknown = reserve.as_bytes().to_vec();
        unknown[50] = 0xff;
        let digest_offset = unknown.len() - 32;
        let digest = storage_hash(StorageHashDomainV1::JournalEntry, &unknown[..digest_offset]);
        unknown[digest_offset..].copy_from_slice(&digest);
        assert!(JournalEntryV1::from_bytes(
            &unknown,
            None,
            JournalPayloadEvidenceV1::SelfContained
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn terminal_payload_authentication_requires_live_store_authority(
    ) -> Result<(), CanonicalCodecError> {
        let (claim, charge) = authenticated_reservation(PurposeV1::ClaimAdaptor, 1)?;
        let reserve = JournalEntryV1::first(JournalPayloadV1::reserve(&claim, &charge)?)?;
        let evidence = TerminalEvidenceV1::select_without_active_secret(&claim, &[], &[])?;
        let burned = TombstoneV1::new_burn(&evidence)?;
        let burned_entry = JournalEntryV1::append(
            &reserve,
            JournalPayloadV1 {
                kind: JournalEntryKindV1::Burned,
                bytes: burned.as_bytes().to_vec(),
            },
        )?;
        assert_eq!(burned_entry.payload().kind(), JournalEntryKindV1::Burned);
        let parsed_reserve = JournalEntryV1::from_bytes(
            reserve.as_bytes(),
            None,
            JournalPayloadEvidenceV1::SelfContained,
        )?;
        assert!(matches!(
            JournalEntryV1::from_bytes(
                burned_entry.as_bytes(),
                Some(&parsed_reserve),
                JournalPayloadEvidenceV1::SelfContained,
            ),
            Err(CanonicalCodecError::LiveStoreAuthorityRequired)
        ));
        Ok(())
    }

    #[test]
    fn minimal_journal_rejects_duplicate_stale_skipped_and_terminal_operations(
    ) -> Result<(), CanonicalCodecError> {
        let (claim, charge) = authenticated_reservation(PurposeV1::ClaimAdaptor, 1)?;
        let mut wrong_first = MinimalJournalV1::new();
        let reveal_first = AttemptRecordV1::new(
            *claim.identity(),
            1,
            SigningPhaseV1::SigNonceReveal,
            [0xd1; 32],
        )?;
        assert!(wrong_first
            .append(JournalPayloadV1::computation_attempt(&reveal_first)?)
            .is_err());

        let mut journal = MinimalJournalV1::new();
        journal.append(JournalPayloadV1::reserve(&claim, &charge)?)?;
        let commitment_attempt = AttemptRecordV1::new(
            *claim.identity(),
            1,
            SigningPhaseV1::SigNonceCommit,
            [0xd2; 32],
        )?;
        let commitment_derivation = authenticated_nonce_derivation(&commitment_attempt, 0)?;
        journal.append(JournalPayloadV1::nonce_derivation_attempt(
            &commitment_derivation,
        ))?;
        assert!(journal
            .append(JournalPayloadV1::nonce_derivation_attempt(
                &commitment_derivation
            ))
            .is_err());

        let persisted = ExposureRecordV1::new_persisted(&commitment_attempt, None, &[0xe1; 35])?;
        let authorized = ExposureRecordV1::new_successor(&persisted, None)?;
        assert!(journal
            .append(JournalPayloadV1::exposure_authorized(
                &persisted,
                &authorized,
                None
            )?)
            .is_err());
        journal.append(JournalPayloadV1::persisted(
            &commitment_attempt,
            None,
            &persisted,
        )?)?;

        let stale = AttemptRecordV1::new(
            *claim.identity(),
            1,
            SigningPhaseV1::SigNonceReveal,
            [0xd3; 32],
        )?;
        assert!(journal
            .append(JournalPayloadV1::computation_attempt(&stale)?)
            .is_err());

        let second_identity_same_session = NonceIdentityV1::new(
            session_key(claim.identity()),
            [0xf2; 32],
            PurposeV1::Funding,
            [0xf3; 32],
            12,
        )?;
        let conflicting_claim = SessionClaimV1::new(second_identity_same_session)?;
        assert!(JournalPayloadV1::reserve(&conflicting_claim, &charge).is_err());

        let (terminal_claim, terminal_charge) = authenticated_reservation(PurposeV1::Refund, 1)?;
        let terminal_evidence =
            TerminalEvidenceV1::select_without_active_secret(&terminal_claim, &[], &[])?;
        let burned = TombstoneV1::new_burn(&terminal_evidence)?;
        let mut terminal_journal = MinimalJournalV1::new();
        terminal_journal.append(JournalPayloadV1::reserve(
            &terminal_claim,
            &terminal_charge,
        )?)?;
        let terminal_payload = JournalPayloadV1 {
            kind: JournalEntryKindV1::Burned,
            bytes: burned.as_bytes().to_vec(),
        };
        assert!(matches!(
            terminal_journal.append(terminal_payload),
            Err(CanonicalCodecError::LiveStoreAuthorityRequired)
        ));
        let after_rejected_terminal = AttemptRecordV1::new(
            *terminal_claim.identity(),
            1,
            SigningPhaseV1::SigNonceCommit,
            [0xd4; 32],
        )?;
        let after_rejected_derivation =
            authenticated_nonce_derivation(&after_rejected_terminal, 0)?;
        terminal_journal.append(JournalPayloadV1::nonce_derivation_attempt(
            &after_rejected_derivation,
        ))?;
        Ok(())
    }

    #[test]
    fn restored_journal_enforces_codec_tail_order_and_supplied_cross_links(
    ) -> Result<(), CanonicalCodecError> {
        let identity =
            NonceIdentityV1::new([0x81; 32], [0x82; 32], PurposeV1::Funding, [0x83; 32], 9)?;
        let claim = SessionClaimV1::new(identity)?;
        let terminal_evidence = TerminalEvidenceV1::select_without_active_secret(&claim, &[], &[])?;
        let tombstone = TombstoneV1::new_burn(&terminal_evidence)?;
        let record = RestoreRecordPayloadV1::burn(&tombstone)?;
        let manifest = RestoreManifestV1::new_restore_only(
            [0x91; 16], [0x92; 32], [0x93; 32], 7, 0, [0; 32], 0, [0x94; 32],
        )?;
        let epoch = EpochAdvancePayloadV1::new(
            [0x92; 32], [0; 32], [0x95; 32], 0, 8, 0, 1, [0x91; 16], [0x96; 32],
        )?;
        let journal = RestoredJournalV1::new(
            None,
            RestoreJournalInputsV1 {
                manifest: &manifest,
                records: std::slice::from_ref(&record),
                budget_carry_forwards: &[],
                permit_carry_forwards: &[],
                epoch_advance: &epoch,
            },
        )?;
        assert_eq!(journal.entries().len(), 4);
        assert_eq!(
            journal.head()?.payload().kind(),
            JournalEntryKindV1::RestoreComplete
        );
        let encoded: Vec<&[u8]> = journal
            .entries()
            .iter()
            .map(JournalEntryV1::as_bytes)
            .collect();
        let verified = RestoredJournalV1::from_encoded_tail(
            None,
            &encoded,
            RestoreJournalInputsV1 {
                manifest: &manifest,
                records: std::slice::from_ref(&record),
                budget_carry_forwards: &[],
                permit_carry_forwards: &[],
                epoch_advance: &epoch,
            },
        )?;
        assert_eq!(
            verified.head()?.entry_digest(),
            journal.head()?.entry_digest()
        );

        let mut minimal = MinimalJournalV1::new();
        assert!(minimal.verify_next(encoded[0]).is_err());
        assert!(RestoredJournalV1::from_encoded_tail(
            None,
            &encoded[..3],
            RestoreJournalInputsV1 {
                manifest: &manifest,
                records: std::slice::from_ref(&record),
                budget_carry_forwards: &[],
                permit_carry_forwards: &[],
                epoch_advance: &epoch,
            },
        )
        .is_err());

        for entry_index in 0..encoded.len() {
            for offset in 0..encoded[entry_index].len() {
                let mut mutated = encoded
                    .iter()
                    .map(|bytes| bytes.to_vec())
                    .collect::<Vec<_>>();
                mutated[entry_index][offset] ^= 1;
                let mutated_refs = mutated.iter().map(Vec::as_slice).collect::<Vec<_>>();
                assert!(
                    RestoredJournalV1::from_encoded_tail(
                        None,
                        &mutated_refs,
                        RestoreJournalInputsV1 {
                            manifest: &manifest,
                            records: std::slice::from_ref(&record),
                            budget_carry_forwards: &[],
                            permit_carry_forwards: &[],
                            epoch_advance: &epoch,
                        },
                    )
                    .is_err(),
                    "entry {entry_index}, mutation {offset}"
                );
            }

            let mut truncated = encoded
                .iter()
                .map(|bytes| bytes.to_vec())
                .collect::<Vec<_>>();
            truncated[entry_index].pop();
            let truncated_refs = truncated.iter().map(Vec::as_slice).collect::<Vec<_>>();
            assert!(
                RestoredJournalV1::from_encoded_tail(
                    None,
                    &truncated_refs,
                    RestoreJournalInputsV1 {
                        manifest: &manifest,
                        records: std::slice::from_ref(&record),
                        budget_carry_forwards: &[],
                        permit_carry_forwards: &[],
                        epoch_advance: &epoch,
                    },
                )
                .is_err(),
                "entry {entry_index}, truncation"
            );
        }

        let (target_claim, target_charge) = authenticated_reservation(PurposeV1::Refund, 1)?;
        let target_head =
            JournalEntryV1::first(JournalPayloadV1::reserve(&target_claim, &target_charge)?)?;
        let shared_target_source_vault = [0xa3; 32];
        let existing_manifest = RestoreManifestV1::new_existing_device(
            [0xa1; 16],
            [0xa2; 32],
            shared_target_source_vault,
            3,
            target_head.sequence(),
            *target_head.entry_digest(),
            shared_target_source_vault,
            7,
            0,
            [0; 32],
            0,
            [0xa4; 32],
        )?;
        let existing_epoch = EpochAdvancePayloadV1::new(
            [0xa2; 32],
            shared_target_source_vault,
            [0xa5; 32],
            3,
            8,
            2,
            3,
            [0xa1; 16],
            [0xa6; 32],
        )?;
        let existing = RestoredJournalV1::new(
            Some(&target_head),
            RestoreJournalInputsV1 {
                manifest: &existing_manifest,
                records: std::slice::from_ref(&record),
                budget_carry_forwards: &[],
                permit_carry_forwards: &[],
                epoch_advance: &existing_epoch,
            },
        )?;
        assert_eq!(existing.entries().len(), 4);
        assert_eq!(existing.entries()[0].sequence(), 2);
        Ok(())
    }

    #[test]
    fn composite_accepts_a_fresh_normal_only_chain() -> Result<(), CanonicalCodecError> {
        let (claim, charge) = authenticated_reservation(PurposeV1::Funding, 1)?;
        let reserve = JournalEntryV1::first(JournalPayloadV1::reserve(&claim, &charge)?)?;
        let mut composite = CompositeJournalV1::new();
        composite.verify_normal_entry(reserve.as_bytes(), None)?;
        assert_eq!(composite.entries().len(), 1);
        assert!(composite
            .head()
            .is_some_and(|entry| entry.as_bytes() == reserve.as_bytes()));
        assert_eq!(composite.lifetime_index().counts(), (1, 1, 1, 1, 0));
        Ok(())
    }

    #[test]
    fn composite_accepts_restore_only_without_operational_suffix() -> Result<(), CanonicalCodecError>
    {
        let (manifest, epoch) = restore_transition(None, 0x20, [0; 32], 0, 7, 0, 1, 0)?;
        let inputs = RestoreJournalInputsV1 {
            manifest: &manifest,
            records: &[],
            budget_carry_forwards: &[],
            permit_carry_forwards: &[],
            epoch_advance: &epoch,
        };
        let encoded = encoded_restore_tail(None, inputs)?;
        let encoded_refs = encoded.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut composite = CompositeJournalV1::new();
        composite.verify_restore_segment(&encoded_refs, inputs)?;
        assert_eq!(composite.entries().len(), 3);
        assert_eq!(
            composite.head().map(|entry| entry.payload().kind()),
            Some(JournalEntryKindV1::RestoreComplete)
        );
        let anchor = composite
            .matching_anchor(&generation_core(0x20, manifest.successor_epoch(), 1)?)?
            .ok_or(CanonicalCodecError::InvalidLifecycle)?;
        assert!(composite
            .head()
            .is_some_and(|entry| entry.as_bytes() == anchor.head.as_bytes()));
        assert_eq!(anchor.epoch_advance.successor_generation(), 1);
        let core = generation_core(0x20, manifest.successor_epoch(), 1)?;
        let active = ActiveVaultGenerationV1::new(
            &core,
            anchor.head.sequence(),
            *anchor.head.entry_digest(),
        )?;
        let pending = pending_index(&manifest, &core, &active, &anchor.head)?;
        assert!(composite
            .verify_current_generation_active_head(&core, &active)
            .is_ok());
        assert!(composite
            .verify_pending_activation_anchor(&core, &active, &pending)
            .is_ok());
        Ok(())
    }

    #[test]
    fn composite_accepts_first_restore_into_empty_existing_generation_one(
    ) -> Result<(), CanonicalCodecError> {
        let (manifest, epoch) = restore_transition(None, 0x28, [0x29; 32], 3, 7, 1, 2, 0)?;
        assert!(!manifest.is_new_device_target());
        let inputs = RestoreJournalInputsV1 {
            manifest: &manifest,
            records: &[],
            budget_carry_forwards: &[],
            permit_carry_forwards: &[],
            epoch_advance: &epoch,
        };
        let encoded = encoded_restore_tail(None, inputs)?;
        let encoded_refs = encoded.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut composite = CompositeJournalV1::new();
        composite.verify_restore_segment(&encoded_refs, inputs)?;
        let core = generation_core(0x28, manifest.successor_epoch(), 2)?;
        assert!(composite.matching_anchor(&core)?.is_some());
        Ok(())
    }

    #[test]
    fn composite_accepts_normal_restore_and_fresh_normal_suffix_but_not_old_reservation(
    ) -> Result<(), CanonicalCodecError> {
        let (old_claim, old_charge) =
            reservation_with_unique_request(PurposeV1::Funding, 1, 0x11, 0x21, 0x31)?;
        let prefix = JournalEntryV1::first(JournalPayloadV1::reserve(&old_claim, &old_charge)?)?;
        let mut composite = CompositeJournalV1::new();
        composite.verify_normal_entry(prefix.as_bytes(), None)?;

        let target = composite.head().cloned();
        let (manifest, epoch) =
            restore_transition(target.as_ref(), 0x30, [0x31; 32], 3, 7, 1, 2, 0)?;
        let inputs = RestoreJournalInputsV1 {
            manifest: &manifest,
            records: &[],
            budget_carry_forwards: &[],
            permit_carry_forwards: &[],
            epoch_advance: &epoch,
        };
        let encoded = encoded_restore_tail(target.as_ref(), inputs)?;
        let encoded_refs = encoded.iter().map(Vec::as_slice).collect::<Vec<_>>();
        composite.verify_restore_segment(&encoded_refs, inputs)?;
        let restore_head = composite
            .head()
            .cloned()
            .ok_or(CanonicalCodecError::InvalidLifecycle)?;
        assert_eq!(
            restore_head.payload().kind(),
            JournalEntryKindV1::RestoreComplete
        );

        let old_attempt = AttemptRecordV1::new(
            *old_claim.identity(),
            1,
            SigningPhaseV1::SigNonceCommit,
            [0x61; 32],
        )?;
        let old_derivation = authenticated_nonce_derivation(&old_attempt, 0)?;
        let old_resume = JournalEntryV1::append(
            &restore_head,
            JournalPayloadV1::nonce_derivation_attempt(&old_derivation),
        )?;
        assert!(composite
            .verify_normal_entry(old_resume.as_bytes(), None)
            .is_err());

        let suffix_sequence = restore_head
            .sequence()
            .checked_add(1)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        let (fresh_claim, fresh_charge) =
            reservation_with_unique_request(PurposeV1::Refund, suffix_sequence, 0x12, 0x22, 0x32)?;
        let suffix = JournalEntryV1::append(
            &restore_head,
            JournalPayloadV1::reserve(&fresh_claim, &fresh_charge)?,
        )?;
        composite.verify_normal_entry(suffix.as_bytes(), None)?;
        assert!(composite
            .head()
            .is_some_and(|entry| entry.as_bytes() == suffix.as_bytes()));
        assert_eq!(composite.entries().len(), 5);
        Ok(())
    }

    #[test]
    fn composite_accepts_two_restore_tails_separated_by_normal_descendants_and_checks_lineage(
    ) -> Result<(), CanonicalCodecError> {
        let mut composite = CompositeJournalV1::new();
        let (manifest_one, epoch_one) = restore_transition(None, 0x40, [0; 32], 0, 7, 0, 1, 0)?;
        let inputs_one = RestoreJournalInputsV1 {
            manifest: &manifest_one,
            records: &[],
            budget_carry_forwards: &[],
            permit_carry_forwards: &[],
            epoch_advance: &epoch_one,
        };
        let tail_one = encoded_restore_tail(None, inputs_one)?;
        let tail_one_refs = tail_one.iter().map(Vec::as_slice).collect::<Vec<_>>();
        composite.verify_restore_segment(&tail_one_refs, inputs_one)?;
        let first_anchor = composite
            .head()
            .cloned()
            .ok_or(CanonicalCodecError::InvalidLifecycle)?;
        let core_one = generation_core(0x40, manifest_one.successor_epoch(), 1)?;
        let activation_one = ActiveVaultGenerationV1::new(
            &core_one,
            first_anchor.sequence(),
            *first_anchor.entry_digest(),
        )?;
        let pending_one = pending_index(&manifest_one, &core_one, &activation_one, &first_anchor)?;

        let normal_sequence = composite
            .head()
            .ok_or(CanonicalCodecError::InvalidLifecycle)?
            .sequence()
            .checked_add(1)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        let (claim, charge) =
            distinct_reservation(PurposeV1::Funding, normal_sequence, 0x31, 0x41)?;
        let normal = JournalEntryV1::append(
            composite
                .head()
                .ok_or(CanonicalCodecError::InvalidLifecycle)?,
            JournalPayloadV1::reserve(&claim, &charge)?,
        )?;
        composite.verify_normal_entry(normal.as_bytes(), None)?;
        let active_one =
            ActiveVaultGenerationV1::new(&core_one, normal.sequence(), *normal.entry_digest())?;
        assert!(composite
            .verify_current_generation_active_head(&core_one, &active_one)
            .is_ok());
        assert!(composite
            .verify_current_generation_active_head(&core_one, &activation_one)
            .is_err());
        assert!(composite
            .verify_pending_activation_anchor(&core_one, &activation_one, &pending_one)
            .is_ok());
        let (unrelated_claim, unrelated_charge) =
            reservation_with_unique_request(PurposeV1::Refund, 1, 0x32, 0x42, 0x52)?;
        let unrelated = JournalEntryV1::first(JournalPayloadV1::reserve(
            &unrelated_claim,
            &unrelated_charge,
        )?)?;
        let unrelated_active = ActiveVaultGenerationV1::new(
            &core_one,
            unrelated.sequence(),
            *unrelated.entry_digest(),
        )?;
        assert!(composite
            .verify_current_generation_active_head(&core_one, &unrelated_active)
            .is_err());

        let target = composite.head().cloned();
        let (manifest_two, epoch_two) = restore_transition(
            target.as_ref(),
            0x50,
            [0x42; 32],
            manifest_one.successor_epoch(),
            11,
            1,
            2,
            0,
        )?;
        let inputs_two = RestoreJournalInputsV1 {
            manifest: &manifest_two,
            records: &[],
            budget_carry_forwards: &[],
            permit_carry_forwards: &[],
            epoch_advance: &epoch_two,
        };
        let tail_two = encoded_restore_tail(target.as_ref(), inputs_two)?;
        let tail_two_refs = tail_two.iter().map(Vec::as_slice).collect::<Vec<_>>();
        composite.verify_restore_segment(&tail_two_refs, inputs_two)?;
        let core_two = generation_core(0x50, manifest_two.successor_epoch(), 2)?;
        assert!(composite.matching_anchor(&core_one)?.is_some());
        assert!(composite.matching_anchor(&core_two)?.is_some());
        assert!(composite
            .verify_current_generation_active_head(&core_one, &activation_one)
            .is_err());
        let second_anchor = composite
            .head()
            .cloned()
            .ok_or(CanonicalCodecError::InvalidLifecycle)?;
        let active_two = ActiveVaultGenerationV1::new(
            &core_two,
            second_anchor.sequence(),
            *second_anchor.entry_digest(),
        )?;
        let pending_two = pending_index(&manifest_two, &core_two, &active_two, &second_anchor)?;
        assert!(composite
            .verify_current_generation_active_head(&core_two, &active_two)
            .is_ok());
        assert!(composite
            .verify_pending_activation_anchor(&core_two, &active_two, &pending_two)
            .is_ok());

        let duplicate = composite
            .matching_anchor(&core_two)?
            .ok_or(CanonicalCodecError::InvalidLifecycle)?
            .clone();
        composite.restore_anchors.push(duplicate);
        assert!(composite.matching_anchor(&core_two).is_err());
        Ok(())
    }

    #[test]
    fn composite_rejects_each_multihop_predecessor_axis_mismatch() -> Result<(), CanonicalCodecError>
    {
        let mut composite = CompositeJournalV1::new();
        let (manifest_one, epoch_one) = restore_transition(None, 0x80, [0; 32], 0, 7, 0, 1, 0)?;
        let inputs_one = RestoreJournalInputsV1 {
            manifest: &manifest_one,
            records: &[],
            budget_carry_forwards: &[],
            permit_carry_forwards: &[],
            epoch_advance: &epoch_one,
        };
        let tail_one = encoded_restore_tail(None, inputs_one)?;
        let refs_one = tail_one.iter().map(Vec::as_slice).collect::<Vec<_>>();
        composite.verify_restore_segment(&refs_one, inputs_one)?;
        let target = composite.head().cloned();

        for (marker, target_vault, target_epoch, predecessor, successor) in [
            (0x83, [0x99; 32], manifest_one.successor_epoch(), 1, 2),
            (0x84, [0x82; 32], manifest_one.successor_epoch() + 1, 1, 2),
            (0x85, [0x82; 32], manifest_one.successor_epoch(), 2, 3),
        ] {
            let (manifest, epoch) = restore_transition(
                target.as_ref(),
                marker,
                target_vault,
                target_epoch,
                12,
                predecessor,
                successor,
                0,
            )?;
            let inputs = RestoreJournalInputsV1 {
                manifest: &manifest,
                records: &[],
                budget_carry_forwards: &[],
                permit_carry_forwards: &[],
                epoch_advance: &epoch,
            };
            let encoded = encoded_restore_tail(target.as_ref(), inputs)?;
            let refs = encoded.iter().map(Vec::as_slice).collect::<Vec<_>>();
            assert!(matches!(
                composite.verify_restore_segment(&refs, inputs),
                Err(CanonicalCodecError::InvalidLifecycle)
            ));
        }

        let wrong_wallet_transaction = [0x86; 16];
        let wrong_wallet = [0xef; 32];
        let wrong_wallet_manifest = RestoreManifestV1::new_existing_device(
            wrong_wallet_transaction,
            wrong_wallet,
            [0x82; 32],
            manifest_one.successor_epoch(),
            target
                .as_ref()
                .ok_or(CanonicalCodecError::InvalidLifecycle)?
                .sequence(),
            *target
                .as_ref()
                .ok_or(CanonicalCodecError::InvalidLifecycle)?
                .entry_digest(),
            [0x87; 32],
            12,
            0,
            [0; 32],
            0,
            [0x89; 32],
        )?;
        let wrong_wallet_core = VaultGenerationCoreV1::new(
            wrong_wallet,
            [0x91; 32],
            [0x88; 32],
            wrong_wallet_manifest.successor_epoch(),
            2,
            [0x8a; 32],
        )?;
        let wrong_wallet_epoch = EpochAdvancePayloadV1::new(
            wrong_wallet,
            [0x82; 32],
            [0x88; 32],
            manifest_one.successor_epoch(),
            wrong_wallet_manifest.successor_epoch(),
            1,
            2,
            wrong_wallet_transaction,
            *wrong_wallet_core.generation_core_digest(),
        )?;
        let wrong_wallet_inputs = RestoreJournalInputsV1 {
            manifest: &wrong_wallet_manifest,
            records: &[],
            budget_carry_forwards: &[],
            permit_carry_forwards: &[],
            epoch_advance: &wrong_wallet_epoch,
        };
        let wrong_wallet_tail = encoded_restore_tail(target.as_ref(), wrong_wallet_inputs)?;
        let wrong_wallet_refs = wrong_wallet_tail
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        assert!(matches!(
            composite.verify_restore_segment(&wrong_wallet_refs, wrong_wallet_inputs),
            Err(CanonicalCodecError::InvalidLifecycle)
        ));
        Ok(())
    }

    #[test]
    fn typed_anchor_requires_exact_core_active_and_pending_authority(
    ) -> Result<(), CanonicalCodecError> {
        let (manifest, epoch) = restore_transition(None, 0x88, [0; 32], 0, 7, 0, 1, 0)?;
        let inputs = RestoreJournalInputsV1 {
            manifest: &manifest,
            records: &[],
            budget_carry_forwards: &[],
            permit_carry_forwards: &[],
            epoch_advance: &epoch,
        };
        let encoded = encoded_restore_tail(None, inputs)?;
        let refs = encoded.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut composite = CompositeJournalV1::new();
        composite.verify_restore_segment(&refs, inputs)?;
        let head = composite
            .head()
            .cloned()
            .ok_or(CanonicalCodecError::InvalidLifecycle)?;
        let core = generation_core(0x88, manifest.successor_epoch(), 1)?;
        let active = ActiveVaultGenerationV1::new(&core, head.sequence(), *head.entry_digest())?;
        let pending = pending_index(&manifest, &core, &active, &head)?;
        assert!(composite
            .verify_current_generation_active_head(&core, &active)
            .is_ok());
        assert!(composite
            .verify_pending_activation_anchor(&core, &active, &pending)
            .is_ok());

        let wrong_cores = [
            VaultGenerationCoreV1::new(
                [0x90; 32],
                [0x91; 32],
                [0x8b; 32],
                manifest.successor_epoch(),
                1,
                [0x8d; 32],
            )?,
            VaultGenerationCoreV1::new(
                [0x90; 32],
                [0x91; 32],
                [0x8a; 32],
                manifest.successor_epoch() + 1,
                1,
                [0x8d; 32],
            )?,
            VaultGenerationCoreV1::new(
                [0x90; 32],
                [0x91; 32],
                [0x8a; 32],
                manifest.successor_epoch(),
                2,
                [0x8d; 32],
            )?,
            VaultGenerationCoreV1::new(
                [0x90; 32],
                [0x91; 32],
                [0x8a; 32],
                manifest.successor_epoch(),
                1,
                [0xee; 32],
            )?,
        ];
        for wrong_core in wrong_cores {
            assert!(composite.matching_anchor(&wrong_core)?.is_none());
        }

        let mut wrong_transaction_fields = pending.fields();
        wrong_transaction_fields.restore_transaction_id = [0xef; 16];
        let wrong_transaction = RestorePendingIndexV1::new(wrong_transaction_fields)?;
        assert!(composite
            .verify_pending_activation_anchor(&core, &active, &wrong_transaction)
            .is_err());

        let mut wrong_active_fields = pending.fields();
        wrong_active_fields.successor_active_generation_digest = [0xed; 32];
        let wrong_active = RestorePendingIndexV1::new(wrong_active_fields)?;
        assert!(composite
            .verify_pending_activation_anchor(&core, &active, &wrong_active)
            .is_err());
        Ok(())
    }

    #[test]
    fn lifetime_index_rejects_source_identity_and_session_reuse_and_never_operationalizes_history(
    ) -> Result<(), CanonicalCodecError> {
        let historical =
            NonceIdentityV1::new([0x61; 32], [0x62; 32], PurposeV1::Funding, [0x63; 32], 1)?;
        let same_session =
            NonceIdentityV1::new([0x61; 32], [0x64; 32], PurposeV1::Refund, [0x65; 32], 2)?;
        let mut lifetime = LifetimeCollisionIndexV1::default();
        lifetime.merge_historical_identity(&historical)?;
        assert!(lifetime.insert_normal_identity(&historical).is_err());
        assert!(lifetime.insert_normal_identity(&same_session).is_err());

        let claim = SessionClaimV1::new(historical)?;
        let record = burned_restore_record(&claim)?;
        let (manifest, epoch) = restore_transition(None, 0x60, [0; 32], 0, 7, 0, 1, 1)?;
        let inputs = RestoreJournalInputsV1 {
            manifest: &manifest,
            records: std::slice::from_ref(&record),
            budget_carry_forwards: &[],
            permit_carry_forwards: &[],
            epoch_advance: &epoch,
        };
        let encoded = encoded_restore_tail(None, inputs)?;
        let encoded_refs = encoded.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut composite = CompositeJournalV1::new();
        composite.verify_restore_segment(&encoded_refs, inputs)?;
        let attempt =
            AttemptRecordV1::new(historical, 1, SigningPhaseV1::SigNonceCommit, [0x66; 32])?;
        let derivation = authenticated_nonce_derivation(&attempt, 0)?;
        let resumed = JournalEntryV1::append(
            composite
                .head()
                .ok_or(CanonicalCodecError::InvalidLifecycle)?,
            JournalPayloadV1::nonce_derivation_attempt(&derivation),
        )?;
        assert!(composite
            .verify_normal_entry(resumed.as_bytes(), None)
            .is_err());
        Ok(())
    }

    #[test]
    fn lifetime_reservation_preflight_checks_all_four_collision_axes(
    ) -> Result<(), CanonicalCodecError> {
        let (claim, charge) = authenticated_reservation(PurposeV1::Funding, 1)?;
        let authority = charge.reservation_authority();
        let identity = *claim.identity();
        let session = session_key(&identity);
        let identity_key = *identity.as_bytes();
        let request = copy_32(authority.request_lookup_id())?;
        let reservation = copy_32(authority.reservation_id())?;

        let fresh = LifetimeCollisionIndexV1::default();
        fresh.require_fresh_reservation(&claim, &charge)?;

        let mut session_collision = LifetimeCollisionIndexV1::default();
        session_collision.sessions.insert(session, identity_key);
        assert!(matches!(
            session_collision.require_fresh_reservation(&claim, &charge),
            Err(CanonicalCodecError::InvalidLifecycle)
        ));

        let mut identity_collision = LifetimeCollisionIndexV1::default();
        identity_collision
            .identities
            .insert(identity_key, identity_key);
        assert!(matches!(
            identity_collision.require_fresh_reservation(&claim, &charge),
            Err(CanonicalCodecError::InvalidLifecycle)
        ));

        let mut request_collision = LifetimeCollisionIndexV1::default();
        request_collision.requests.insert(request, vec![0x11]);
        assert!(matches!(
            request_collision.require_fresh_reservation(&claim, &charge),
            Err(CanonicalCodecError::InvalidLifecycle)
        ));

        let mut reservation_collision = LifetimeCollisionIndexV1::default();
        reservation_collision
            .reservations
            .insert(reservation, vec![0x22]);
        assert!(matches!(
            reservation_collision.require_fresh_reservation(&claim, &charge),
            Err(CanonicalCodecError::InvalidLifecycle)
        ));

        let (different_claim, _) = authenticated_reservation(PurposeV1::Refund, 1)?;
        assert!(matches!(
            fresh.require_fresh_reservation(&different_claim, &charge),
            Err(CanonicalCodecError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn lifetime_carries_are_exact_collision_evidence_without_operational_authority(
    ) -> Result<(), CanonicalCodecError> {
        let (_, charge) = authenticated_reservation(PurposeV1::Funding, 1)?;
        let mut lifetime = LifetimeCollisionIndexV1::default();
        lifetime.insert_historical_charge(&charge)?;
        assert!(matches!(
            lifetime.insert_historical_charge(&charge),
            Err(CanonicalCodecError::InvalidLifecycle)
        ));
        assert!(lifetime.insert_normal_charge(&charge).is_err());

        let mut independent_empty_history = LifetimeCollisionIndexV1::default();
        independent_empty_history.insert_historical_charge(&charge)?;

        let retirement_bytes = crate::canonical::permit::tests::retirement()?;
        let retirement = PermitRetirementV1::from_bytes(&retirement_bytes)?;
        let mut permit_lifetime = LifetimeCollisionIndexV1::default();
        permit_lifetime.insert_historical_retirement(&retirement)?;
        assert!(matches!(
            permit_lifetime.insert_historical_retirement(&retirement),
            Err(CanonicalCodecError::InvalidLifecycle)
        ));
        assert_eq!(permit_lifetime.counts().4, 1);
        Ok(())
    }

    #[test]
    fn composite_rejects_repeated_exact_and_divergent_canonical_carries_in_one_chain(
    ) -> Result<(), CanonicalCodecError> {
        let (_, charge) = reservation_with_unique_request(PurposeV1::Funding, 1, 0x71, 0x81, 0x91)?;
        let retirement_bytes = crate::canonical::permit::tests::retirement()?;
        let retirement = PermitRetirementV1::from_bytes(&retirement_bytes)?;
        let mut composite = CompositeJournalV1::new();
        let (manifest_one, epoch_one) = restore_transition(None, 0x72, [0; 32], 0, 7, 0, 1, 0)?;
        let inputs_one = RestoreJournalInputsV1 {
            manifest: &manifest_one,
            records: &[],
            budget_carry_forwards: std::slice::from_ref(&charge),
            permit_carry_forwards: std::slice::from_ref(&retirement),
            epoch_advance: &epoch_one,
        };
        let tail_one = encoded_restore_tail(None, inputs_one)?;
        let tail_one_refs = tail_one.iter().map(Vec::as_slice).collect::<Vec<_>>();
        composite.verify_restore_segment(&tail_one_refs, inputs_one)?;

        let target = composite.head().cloned();
        let (manifest_two, epoch_two) = restore_transition(
            target.as_ref(),
            0x73,
            [0x74; 32],
            manifest_one.successor_epoch(),
            11,
            1,
            2,
            0,
        )?;
        let repeated_inputs = RestoreJournalInputsV1 {
            manifest: &manifest_two,
            records: &[],
            budget_carry_forwards: std::slice::from_ref(&charge),
            permit_carry_forwards: std::slice::from_ref(&retirement),
            epoch_advance: &epoch_two,
        };
        let repeated_tail = encoded_restore_tail(target.as_ref(), repeated_inputs)?;
        let repeated_refs = repeated_tail.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert!(matches!(
            composite.verify_restore_segment(&repeated_refs, repeated_inputs),
            Err(CanonicalCodecError::InvalidLifecycle)
        ));

        let (_, divergent_charge) =
            reservation_with_unique_request(PurposeV1::Funding, 1, 0x71, 0x82, 0x91)?;
        let divergent_inputs = RestoreJournalInputsV1 {
            manifest: &manifest_two,
            records: &[],
            budget_carry_forwards: std::slice::from_ref(&divergent_charge),
            permit_carry_forwards: &[],
            epoch_advance: &epoch_two,
        };
        let divergent_tail = encoded_restore_tail(target.as_ref(), divergent_inputs)?;
        let divergent_refs = divergent_tail.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert!(matches!(
            composite.verify_restore_segment(&divergent_refs, divergent_inputs),
            Err(CanonicalCodecError::InvalidLifecycle)
        ));

        let mut independent = CompositeJournalV1::new();
        let (manifest_three, epoch_three) = restore_transition(None, 0x75, [0; 32], 0, 9, 0, 1, 0)?;
        let independent_inputs = RestoreJournalInputsV1 {
            manifest: &manifest_three,
            records: &[],
            budget_carry_forwards: std::slice::from_ref(&charge),
            permit_carry_forwards: std::slice::from_ref(&retirement),
            epoch_advance: &epoch_three,
        };
        let independent_tail = encoded_restore_tail(None, independent_inputs)?;
        let independent_refs = independent_tail
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        independent.verify_restore_segment(&independent_refs, independent_inputs)?;
        Ok(())
    }

    #[test]
    fn strict_minimal_rejects_every_restore_kind_and_unverified_tail_cannot_mint_anchor(
    ) -> Result<(), CanonicalCodecError> {
        let (claim, charge) = authenticated_reservation(PurposeV1::Funding, 1)?;
        let record = burned_restore_record(&claim)?;
        let retirement_bytes = crate::canonical::permit::tests::retirement()?;
        let retirement = PermitRetirementV1::from_bytes(&retirement_bytes)?;
        let (manifest, epoch) = restore_transition(None, 0x70, [0; 32], 0, 7, 0, 1, 1)?;
        let anchor_inputs = RestoreJournalInputsV1 {
            manifest: &manifest,
            records: std::slice::from_ref(&record),
            budget_carry_forwards: &[],
            permit_carry_forwards: &[],
            epoch_advance: &epoch,
        };
        let unverified = RestoredJournalV1::new(None, anchor_inputs)?;
        assert!(matches!(
            unverified.verified_anchor(&manifest, &epoch),
            Err(CanonicalCodecError::LiveStoreAuthorityRequired)
        ));
        let completion = RestoreCompleteV1::new(&manifest, [0x77; 32])?;
        let restore_payloads = [
            JournalPayloadV1::restore_begin(&manifest),
            JournalPayloadV1::restore_record(&record),
            JournalPayloadV1::budget_carry_forward(&charge),
            JournalPayloadV1::permit_retirement_carry_forward(&retirement),
            JournalPayloadV1::epoch_advance(&epoch),
            JournalPayloadV1::restore_complete(&completion),
        ];
        for payload in restore_payloads {
            let reserve = JournalEntryV1::first(JournalPayloadV1::reserve(&claim, &charge)?)?;
            let candidate = JournalEntryV1::append(&reserve, payload)?;
            let mut minimal = MinimalJournalV1::new();
            minimal.verify_next(reserve.as_bytes())?;
            assert!(minimal.verify_next(candidate.as_bytes()).is_err());
        }
        Ok(())
    }
}
