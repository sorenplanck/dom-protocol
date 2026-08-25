//! Structurally validated immutable exposure records.

use super::{
    exact, parse_nonce_identity, read_u16, read_u32, read_u64, storage_hash, ArtifactKindV1,
    AttemptRecordV1, CanonicalCodecError, ExposureStateV1, NonceIdentityV1, StorageHashDomainV1,
    TombstoneV1, EXPOSURE_RECORD_MAX_LEN, EXPOSURE_RECORD_MIN_LEN,
};
use dom_adaptor::{exposure_outbound_digest_v1, ExposureKindV1};

const EXPOSURE_MAGIC: &[u8; 8] = b"DOMNVEX1";

/// Exact encoded size of `ExposureVersionIdV1`.
pub const EXPOSURE_VERSION_ID_LEN: usize = 155;

/// Computes the Contracts storage digest of exact outbound bytes.
///
/// This uses the Contracts exposure storage domain and is intentionally not
/// the adaptor permit digest returned by [`adaptor_outbound_digest_v1`].
pub fn contracts_exposure_outbound_digest_v1(
    artifact: ArtifactKindV1,
    bytes: &[u8],
) -> Result<[u8; 32], CanonicalCodecError> {
    if !(1..=4_096).contains(&bytes.len()) {
        return Err(CanonicalCodecError::InvalidEncoding);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| CanonicalCodecError::InvalidEncoding)?;
    let mut preimage = Vec::with_capacity(5 + bytes.len());
    preimage.push(artifact as u8);
    preimage.extend_from_slice(&length.to_le_bytes());
    preimage.extend_from_slice(bytes);
    Ok(storage_hash(StorageHashDomainV1::Exposure, &preimage))
}

/// Computes the adaptor-owned outbound digest used by adaptor permits.
///
/// The adaptor registry also enforces the exact canonical artifact length.
/// This digest has a different domain from the Contracts storage digest.
pub fn adaptor_outbound_digest_v1(
    artifact: ArtifactKindV1,
    bytes: &[u8],
) -> Result<[u8; 32], CanonicalCodecError> {
    exposure_outbound_digest_v1(artifact.into(), bytes)
        .map(|digest| *digest.as_bytes())
        .map_err(|_| CanonicalCodecError::InvalidEncoding)
}

impl From<ArtifactKindV1> for ExposureKindV1 {
    fn from(artifact: ArtifactKindV1) -> Self {
        match artifact {
            ArtifactKindV1::Commitment => Self::NonceCommitment,
            ArtifactKindV1::Reveal => Self::NonceReveal,
            ArtifactKindV1::PartialSignature => Self::PartialSignature,
        }
    }
}

/// Structurally parsed immutable exposure-version identifier.
///
/// The embedded record digest is retained as unauthenticated data. Production
/// authorization must recompute it through the pinned authoritative DOM hash
/// boundary before treating this identifier as evidence.
pub struct UnauthenticatedExposureVersionIdV1 {
    bytes: [u8; EXPOSURE_VERSION_ID_LEN],
    identity: NonceIdentityV1,
    sequence: u64,
    state: ExposureStateV1,
    artifact: ArtifactKindV1,
    lifecycle_revision: u64,
}

impl UnauthenticatedExposureVersionIdV1 {
    /// Parses exact bytes and all closed structural fields.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<EXPOSURE_VERSION_ID_LEN>(input)?;
        let identity = parse_nonce_identity(&bytes[..105])?;
        let sequence = read_u64(&bytes[105..113]);
        let state = ExposureStateV1::try_from(bytes[113])?;
        let artifact = ArtifactKindV1::try_from(bytes[114])?;
        let lifecycle_revision = read_u64(&bytes[115..123]);
        validate_sequence_artifact(sequence, artifact)?;
        if lifecycle_revision == 0 {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes,
            identity,
            sequence,
            state,
            artifact,
            lifecycle_revision,
        })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; EXPOSURE_VERSION_ID_LEN] {
        &self.bytes
    }

    /// Returns the canonical nonce identity.
    pub const fn identity(&self) -> &NonceIdentityV1 {
        &self.identity
    }

    /// Returns the exposure sequence in the closed range `1..=3`.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the immutable exposure state.
    pub const fn state(&self) -> ExposureStateV1 {
        self.state
    }

    /// Returns the artifact kind assigned to the sequence.
    pub const fn artifact(&self) -> ArtifactKindV1 {
        self.artifact
    }

    /// Returns the nonzero lifecycle revision.
    pub const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }

    /// Returns the embedded, unauthenticated record digest.
    pub fn record_digest(&self) -> &[u8] {
        &self.bytes[123..155]
    }
}

/// Authenticated identifier of one immutable exposure version.
#[derive(Clone, Eq, PartialEq)]
pub struct ExposureVersionIdV1 {
    bytes: [u8; EXPOSURE_VERSION_ID_LEN],
    identity: NonceIdentityV1,
    sequence: u64,
    state: ExposureStateV1,
    artifact: ArtifactKindV1,
    lifecycle_revision: u64,
    record_digest: [u8; 32],
}

impl ExposureVersionIdV1 {
    /// Constructs the exact identifier of an authenticated exposure record.
    pub fn from_record(record: &ExposureRecordV1) -> Self {
        let mut bytes = [0_u8; EXPOSURE_VERSION_ID_LEN];
        bytes[..105].copy_from_slice(record.identity().as_bytes());
        bytes[105..113].copy_from_slice(&record.sequence().to_le_bytes());
        bytes[113] = record.state() as u8;
        bytes[114] = record.artifact() as u8;
        bytes[115..123].copy_from_slice(&record.lifecycle_revision().to_le_bytes());
        bytes[123..155].copy_from_slice(record.record_digest());
        Self {
            bytes,
            identity: *record.identity(),
            sequence: record.sequence(),
            state: record.state(),
            artifact: record.artifact(),
            lifecycle_revision: record.lifecycle_revision(),
            record_digest: *record.record_digest(),
        }
    }

    /// Verifies identifier bytes against the complete referenced record.
    pub fn from_bytes_with_record(
        input: &[u8],
        record: &ExposureRecordV1,
    ) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedExposureVersionIdV1::parse_structural(input)?;
        let expected = Self::from_record(record);
        if structural.as_bytes() != expected.as_bytes() {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(expected)
    }

    /// Returns the exact canonical identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; EXPOSURE_VERSION_ID_LEN] {
        &self.bytes
    }

    /// Returns the canonical nonce identity.
    pub const fn identity(&self) -> &NonceIdentityV1 {
        &self.identity
    }

    /// Returns the exposure sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the immutable state.
    pub const fn state(&self) -> ExposureStateV1 {
        self.state
    }

    /// Returns the artifact kind.
    pub const fn artifact(&self) -> ArtifactKindV1 {
        self.artifact
    }

    /// Returns the lifecycle revision.
    pub const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }

    /// Returns the authenticated complete-record digest.
    pub const fn record_digest(&self) -> &[u8; 32] {
        &self.record_digest
    }
}

/// Structurally parsed immutable exposure record.
///
/// Digest fields are intentionally not authenticated by this parser. The
/// returned view only proves exact length, fixed syntax, registry membership,
/// and sequence-to-artifact consistency.
pub struct UnauthenticatedExposureRecordV1<'a> {
    bytes: &'a [u8],
    identity: NonceIdentityV1,
    state: ExposureStateV1,
    artifact: ArtifactKindV1,
    sequence: u64,
    lifecycle_revision: u64,
    outbound_length: usize,
}

impl<'a> UnauthenticatedExposureRecordV1<'a> {
    /// Parses exact bounded bytes without allocating from an external length.
    pub fn parse_structural(input: &'a [u8]) -> Result<Self, CanonicalCodecError> {
        if !(EXPOSURE_RECORD_MIN_LEN..=EXPOSURE_RECORD_MAX_LEN).contains(&input.len())
            || &input[..8] != EXPOSURE_MAGIC
            || read_u16(&input[8..10]) != 1
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }

        let state = ExposureStateV1::try_from(input[10])?;
        let artifact = ArtifactKindV1::try_from(input[11])?;
        let identity = parse_nonce_identity(&input[12..117])?;
        let sequence = read_u64(&input[117..125]);
        let lifecycle_revision = read_u64(&input[125..133]);
        let outbound_length = usize::try_from(read_u32(&input[197..201]))
            .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        let expected_length = 233_usize
            .checked_add(outbound_length)
            .ok_or(CanonicalCodecError::InvalidEncoding)?;

        validate_sequence_artifact(sequence, artifact)?;
        if lifecycle_revision == 0
            || !(1..=4_096).contains(&outbound_length)
            || input.len() != expected_length
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }

        Ok(Self {
            bytes: input,
            identity,
            state,
            artifact,
            sequence,
            lifecycle_revision,
            outbound_length,
        })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the canonical nonce identity.
    pub const fn identity(&self) -> &NonceIdentityV1 {
        &self.identity
    }

    /// Returns the immutable exposure state.
    pub const fn state(&self) -> ExposureStateV1 {
        self.state
    }

    /// Returns the artifact kind assigned to the sequence.
    pub const fn artifact(&self) -> ArtifactKindV1 {
        self.artifact
    }

    /// Returns the exposure sequence in the closed range `1..=3`.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the nonzero lifecycle revision.
    pub const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }

    /// Returns the unauthenticated operation-input digest.
    pub fn operation_input_digest(&self) -> &'a [u8] {
        &self.bytes[133..165]
    }

    /// Returns the unauthenticated outbound digest.
    pub fn outbound_digest(&self) -> &'a [u8] {
        &self.bytes[165..197]
    }

    /// Returns the exact persisted outbound bytes.
    pub fn outbound_bytes(&self) -> &'a [u8] {
        &self.bytes[201..201 + self.outbound_length]
    }

    /// Returns the unauthenticated complete-record digest.
    pub fn record_digest(&self) -> &'a [u8] {
        &self.bytes[201 + self.outbound_length..]
    }
}

/// Authenticated immutable exposure record.
#[derive(Clone, Eq, PartialEq)]
pub struct ExposureRecordV1 {
    bytes: Vec<u8>,
    identity: NonceIdentityV1,
    state: ExposureStateV1,
    artifact: ArtifactKindV1,
    sequence: u64,
    lifecycle_revision: u64,
    operation_input_digest: [u8; 32],
    outbound_digest: [u8; 32],
    outbound_length: usize,
    record_digest: [u8; 32],
}

impl ExposureRecordV1 {
    /// Constructs a persisted exposure from its matching durable attempt.
    ///
    /// Reveal and partial-signature construction requires the preceding
    /// sequence in `Spent` state. Commitment is the first exposure and accepts
    /// no predecessor.
    pub fn new_persisted(
        attempt: &AttemptRecordV1,
        preceding_spent: Option<&Self>,
        outbound_bytes: &[u8],
    ) -> Result<Self, CanonicalCodecError> {
        let artifact = attempt.artifact();
        let sequence = artifact.exposure_sequence();
        match (artifact, preceding_spent) {
            (ArtifactKindV1::Commitment, None) => {
                if attempt.expected_lifecycle_revision() != 1 {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
            }
            (ArtifactKindV1::Commitment, Some(_)) | (_, None) => {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
            (_, Some(predecessor)) => {
                if predecessor.identity().as_bytes() != attempt.identity().as_bytes()
                    || predecessor.state() != ExposureStateV1::Spent
                    || predecessor.sequence().checked_add(1) != Some(sequence)
                    || predecessor.lifecycle_revision() != attempt.expected_lifecycle_revision()
                {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
            }
        }
        let lifecycle_revision = attempt
            .expected_lifecycle_revision()
            .checked_add(1)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        Self::construct(
            *attempt.identity(),
            ExposureStateV1::Persisted,
            artifact,
            sequence,
            lifecycle_revision,
            *attempt.operation_input_digest(),
            outbound_bytes,
        )
    }

    /// Constructs the next immutable state from an authenticated predecessor.
    ///
    /// A partial-signature `Persisted -> Authorized` transition requires the
    /// exact intervening consumed tombstone and advances by two revisions.
    pub fn new_successor(
        predecessor: &Self,
        intervening_tombstone: Option<&TombstoneV1>,
    ) -> Result<Self, CanonicalCodecError> {
        let successor_state = match predecessor.state() {
            ExposureStateV1::Persisted => ExposureStateV1::Authorized,
            ExposureStateV1::Authorized => ExposureStateV1::Spent,
            ExposureStateV1::Spent => return Err(CanonicalCodecError::InvalidLifecycle),
        };
        let partial_intervening = predecessor.artifact() == ArtifactKindV1::PartialSignature
            && predecessor.state() == ExposureStateV1::Persisted;
        let increment = if partial_intervening {
            let tombstone = intervening_tombstone.ok_or(CanonicalCodecError::InvalidLifecycle)?;
            tombstone.validate_intervening_consumed(predecessor)?;
            2
        } else {
            if intervening_tombstone.is_some() {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
            1
        };
        let lifecycle_revision = predecessor
            .lifecycle_revision()
            .checked_add(increment)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        Self::construct(
            *predecessor.identity(),
            successor_state,
            predecessor.artifact(),
            predecessor.sequence(),
            lifecycle_revision,
            *predecessor.operation_input_digest(),
            predecessor.outbound_bytes(),
        )
    }

    /// Parses exact bytes and authenticates both exposure-domain digests.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedExposureRecordV1::parse_structural(input)?;
        structural.identity().require_strict_phase1()?;
        let expected_outbound = contracts_exposure_outbound_digest_v1(
            structural.artifact(),
            structural.outbound_bytes(),
        )?;
        if structural.outbound_digest() != expected_outbound {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        let record_preimage_length = input
            .len()
            .checked_sub(32)
            .ok_or(CanonicalCodecError::InvalidEncoding)?;
        let expected_record = storage_hash(
            StorageHashDomainV1::Exposure,
            &input[..record_preimage_length],
        );
        if structural.record_digest() != expected_record {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        let mut operation_input_digest = [0_u8; 32];
        operation_input_digest.copy_from_slice(structural.operation_input_digest());
        Ok(Self {
            bytes: input.to_vec(),
            identity: *structural.identity(),
            state: structural.state(),
            artifact: structural.artifact(),
            sequence: structural.sequence(),
            lifecycle_revision: structural.lifecycle_revision(),
            operation_input_digest,
            outbound_digest: expected_outbound,
            outbound_length: structural.outbound_bytes().len(),
            record_digest: expected_record,
        })
    }

    fn construct(
        identity: NonceIdentityV1,
        state: ExposureStateV1,
        artifact: ArtifactKindV1,
        sequence: u64,
        lifecycle_revision: u64,
        operation_input_digest: [u8; 32],
        outbound_bytes: &[u8],
    ) -> Result<Self, CanonicalCodecError> {
        identity.require_strict_phase1()?;
        validate_sequence_artifact(sequence, artifact)?;
        if lifecycle_revision == 0 || !(1..=4_096).contains(&outbound_bytes.len()) {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let outbound_length = outbound_bytes.len();
        let encoded_outbound_length =
            u32::try_from(outbound_length).map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        let complete_length = 233_usize
            .checked_add(outbound_length)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        let mut bytes = vec![0_u8; complete_length];
        bytes[..8].copy_from_slice(EXPOSURE_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10] = state as u8;
        bytes[11] = artifact as u8;
        bytes[12..117].copy_from_slice(identity.as_bytes());
        bytes[117..125].copy_from_slice(&sequence.to_le_bytes());
        bytes[125..133].copy_from_slice(&lifecycle_revision.to_le_bytes());
        bytes[133..165].copy_from_slice(&operation_input_digest);
        let outbound_digest = contracts_exposure_outbound_digest_v1(artifact, outbound_bytes)?;
        bytes[165..197].copy_from_slice(&outbound_digest);
        bytes[197..201].copy_from_slice(&encoded_outbound_length.to_le_bytes());
        bytes[201..201 + outbound_length].copy_from_slice(outbound_bytes);
        let record_digest = storage_hash(
            StorageHashDomainV1::Exposure,
            &bytes[..201 + outbound_length],
        );
        bytes[201 + outbound_length..].copy_from_slice(&record_digest);
        Ok(Self {
            bytes,
            identity,
            state,
            artifact,
            sequence,
            lifecycle_revision,
            operation_input_digest,
            outbound_digest,
            outbound_length,
            record_digest,
        })
    }

    /// Validates a persisted exposure against its exact attempt.
    pub fn validate_persisted_attempt(
        &self,
        attempt: &AttemptRecordV1,
    ) -> Result<(), CanonicalCodecError> {
        let expected_revision = attempt
            .expected_lifecycle_revision()
            .checked_add(1)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        if self.state != ExposureStateV1::Persisted
            || self.identity.as_bytes() != attempt.identity().as_bytes()
            || self.artifact != attempt.artifact()
            || self.sequence != attempt.artifact().exposure_sequence()
            || self.lifecycle_revision != expected_revision
            || self.operation_input_digest != *attempt.operation_input_digest()
        {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        Ok(())
    }

    /// Validates the complete persisted-exposure construction context,
    /// including the required preceding spent sequence.
    pub fn validate_persisted_context(
        &self,
        attempt: &AttemptRecordV1,
        preceding_spent: Option<&Self>,
    ) -> Result<(), CanonicalCodecError> {
        let expected = Self::new_persisted(attempt, preceding_spent, self.outbound_bytes())?;
        if self != &expected {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        Ok(())
    }

    /// Validates that this record is the exact successor of a predecessor.
    pub fn validate_successor(
        &self,
        predecessor: &Self,
        intervening_tombstone: Option<&TombstoneV1>,
    ) -> Result<(), CanonicalCodecError> {
        let expected = Self::new_successor(predecessor, intervening_tombstone)?;
        if self != &expected {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        Ok(())
    }

    /// Returns the identifier of this immutable version.
    pub fn version_id(&self) -> ExposureVersionIdV1 {
        ExposureVersionIdV1::from_record(self)
    }

    /// Returns the exact authenticated canonical bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the canonical nonce identity.
    pub const fn identity(&self) -> &NonceIdentityV1 {
        &self.identity
    }

    /// Returns the immutable exposure state.
    pub const fn state(&self) -> ExposureStateV1 {
        self.state
    }

    /// Returns the artifact kind.
    pub const fn artifact(&self) -> ArtifactKindV1 {
        self.artifact
    }

    /// Returns the exposure sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the lifecycle revision.
    pub const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }

    /// Returns the operation-input digest copied from the attempt.
    pub const fn operation_input_digest(&self) -> &[u8; 32] {
        &self.operation_input_digest
    }

    /// Returns the Contracts storage digest of the outbound bytes.
    pub const fn outbound_digest(&self) -> &[u8; 32] {
        &self.outbound_digest
    }

    /// Returns the exact immutable outbound bytes.
    pub fn outbound_bytes(&self) -> &[u8] {
        &self.bytes[201..201 + self.outbound_length]
    }

    /// Returns the authenticated complete-record digest.
    pub const fn record_digest(&self) -> &[u8; 32] {
        &self.record_digest
    }
}

fn validate_sequence_artifact(
    sequence: u64,
    artifact: ArtifactKindV1,
) -> Result<(), CanonicalCodecError> {
    let valid = matches!(
        (sequence, artifact),
        (1, ArtifactKindV1::Commitment)
            | (2, ArtifactKindV1::Reveal)
            | (3, ArtifactKindV1::PartialSignature)
    );
    if valid {
        Ok(())
    } else {
        Err(CanonicalCodecError::InvalidEncoding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{PurposeV1, SigningPhaseV1};

    fn authenticated_identity() -> Result<NonceIdentityV1, CanonicalCodecError> {
        NonceIdentityV1::new(
            [0x11; 32],
            [0x22; 32],
            PurposeV1::ClaimAdaptor,
            [0x33; 32],
            7,
        )
    }

    fn authenticated_attempt(
        revision: u64,
        phase: SigningPhaseV1,
    ) -> Result<AttemptRecordV1, CanonicalCodecError> {
        AttemptRecordV1::new(authenticated_identity()?, revision, phase, [0x44; 32])
    }

    fn identity_bytes() -> [u8; 105] {
        let mut bytes = [0_u8; 105];
        bytes[..32].fill(0x11);
        bytes[32..64].fill(0x22);
        bytes[64] = 0x02;
        bytes[65..97].fill(0x33);
        bytes[97..105].copy_from_slice(&7_u64.to_le_bytes());
        bytes
    }

    fn record_bytes(sequence: u64, state: u8, outbound_length: usize) -> Vec<u8> {
        let artifact = sequence_byte(sequence);
        let mut bytes = vec![0_u8; 233 + outbound_length];
        bytes[..8].copy_from_slice(EXPOSURE_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10] = state;
        bytes[11] = artifact;
        bytes[12..117].copy_from_slice(&identity_bytes());
        bytes[117..125].copy_from_slice(&sequence.to_le_bytes());
        bytes[125..133].copy_from_slice(&9_u64.to_le_bytes());
        let outbound_length_u32 = u32::try_from(outbound_length).unwrap_or(u32::MAX);
        bytes[197..201].copy_from_slice(&outbound_length_u32.to_le_bytes());
        bytes[201..201 + outbound_length].fill(0x44);
        bytes
    }

    fn version_id_bytes(sequence: u64, state: u8) -> [u8; EXPOSURE_VERSION_ID_LEN] {
        let mut bytes = [0_u8; EXPOSURE_VERSION_ID_LEN];
        bytes[..105].copy_from_slice(&identity_bytes());
        bytes[105..113].copy_from_slice(&sequence.to_le_bytes());
        bytes[113] = state;
        bytes[114] = sequence_byte(sequence);
        bytes[115..123].copy_from_slice(&9_u64.to_le_bytes());
        bytes
    }

    fn sequence_byte(sequence: u64) -> u8 {
        match sequence {
            1 => 1,
            2 => 2,
            3 => 3,
            _ => 0,
        }
    }

    #[test]
    fn exposure_record_accepts_exact_minimum_and_maximum_lengths() -> Result<(), CanonicalCodecError>
    {
        for outbound_length in [1, 4_096] {
            let bytes = record_bytes(1, 1, outbound_length);
            let record = UnauthenticatedExposureRecordV1::parse_structural(&bytes)?;
            assert_eq!(record.as_bytes(), bytes);
            assert_eq!(record.outbound_bytes().len(), outbound_length);
            assert_eq!(record.sequence(), 1);
            assert_eq!(record.artifact(), ArtifactKindV1::Commitment);
            assert_eq!(record.lifecycle_revision(), 9);
        }
        Ok(())
    }

    #[test]
    fn exposure_record_rejects_lengths_and_sequence_kind_mismatches() {
        let canonical = record_bytes(2, 2, 32);
        assert!(UnauthenticatedExposureRecordV1::parse_structural(&canonical[..264]).is_err());

        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(UnauthenticatedExposureRecordV1::parse_structural(&trailing).is_err());

        let mut wrong_length = canonical.clone();
        wrong_length[197..201].copy_from_slice(&31_u32.to_le_bytes());
        assert!(UnauthenticatedExposureRecordV1::parse_structural(&wrong_length).is_err());

        let mut wrong_kind = canonical.clone();
        wrong_kind[11] = ArtifactKindV1::Commitment as u8;
        assert!(UnauthenticatedExposureRecordV1::parse_structural(&wrong_kind).is_err());

        let mut zero_revision = canonical;
        zero_revision[125..133].fill(0);
        assert!(UnauthenticatedExposureRecordV1::parse_structural(&zero_revision).is_err());
    }

    #[test]
    fn exposure_record_accepts_structural_zero_digest_outputs() -> Result<(), CanonicalCodecError> {
        let bytes = record_bytes(3, 3, 32);
        let record = UnauthenticatedExposureRecordV1::parse_structural(&bytes)?;
        assert_eq!(record.operation_input_digest(), &[0; 32]);
        assert_eq!(record.outbound_digest(), &[0; 32]);
        assert_eq!(record.record_digest(), &[0; 32]);
        Ok(())
    }

    #[test]
    fn exposure_version_id_enforces_closed_fields() -> Result<(), CanonicalCodecError> {
        for sequence in 1..=3 {
            for state in 1..=3 {
                let bytes = version_id_bytes(sequence, state);
                let parsed = UnauthenticatedExposureVersionIdV1::parse_structural(&bytes)?;
                assert_eq!(parsed.as_bytes(), &bytes);
                assert_eq!(parsed.sequence(), sequence);
                assert_eq!(parsed.state() as u8, state);
                assert_eq!(parsed.lifecycle_revision(), 9);
                assert_eq!(parsed.record_digest(), &[0; 32]);
            }
        }

        let mut wrong_kind = version_id_bytes(1, 1);
        wrong_kind[114] = ArtifactKindV1::Reveal as u8;
        assert!(UnauthenticatedExposureVersionIdV1::parse_structural(&wrong_kind).is_err());

        let mut zero_revision = version_id_bytes(1, 1);
        zero_revision[115..123].fill(0);
        assert!(UnauthenticatedExposureVersionIdV1::parse_structural(&zero_revision).is_err());
        Ok(())
    }

    #[test]
    fn exposure_record_rejects_mutated_fixed_fields() {
        let canonical = record_bytes(1, 1, 32);
        let mutations = [
            (0, canonical[0] ^ 1),
            (8, 2),
            (10, 0),
            (11, 0),
            (64 + 12, 0),
            (117, 0),
        ];
        for (offset, replacement) in mutations {
            let mut bytes = canonical.clone();
            bytes[offset] = replacement;
            assert!(UnauthenticatedExposureRecordV1::parse_structural(&bytes).is_err());
        }
    }

    #[test]
    fn exposure_records_reject_every_truncation_and_trailing_byte() {
        let version = version_id_bytes(1, ExposureStateV1::Persisted as u8);
        for end in 0..version.len() {
            assert!(
                UnauthenticatedExposureVersionIdV1::parse_structural(&version[..end]).is_err(),
                "version {end}"
            );
        }
        let mut trailing_version = version.to_vec();
        trailing_version.push(0);
        assert!(UnauthenticatedExposureVersionIdV1::parse_structural(&trailing_version).is_err());

        for outbound_length in [1, 4_096] {
            let record = record_bytes(1, ExposureStateV1::Persisted as u8, outbound_length);
            for end in 0..record.len() {
                assert!(
                    UnauthenticatedExposureRecordV1::parse_structural(&record[..end]).is_err(),
                    "record length {outbound_length}, prefix {end}"
                );
            }
            let mut trailing_record = record;
            trailing_record.push(0);
            assert!(UnauthenticatedExposureRecordV1::parse_structural(&trailing_record).is_err());
        }
    }

    #[test]
    fn contracts_and_adaptor_outbound_digests_are_distinct_and_exhaustively_mapped(
    ) -> Result<(), CanonicalCodecError> {
        let cases = [
            (ArtifactKindV1::Commitment, vec![0x11; 35]),
            (ArtifactKindV1::Reveal, vec![0x22; 69]),
            (ArtifactKindV1::PartialSignature, vec![0x33; 67]),
        ];
        for (artifact, bytes) in cases {
            let contracts = contracts_exposure_outbound_digest_v1(artifact, &bytes)?;
            let adaptor = adaptor_outbound_digest_v1(artifact, &bytes)?;
            assert_ne!(contracts, adaptor);
            assert_ne!(contracts, [0; 32]);
            assert_ne!(adaptor, [0; 32]);
        }
        assert!(adaptor_outbound_digest_v1(ArtifactKindV1::Commitment, &[1]).is_err());
        assert!(contracts_exposure_outbound_digest_v1(ArtifactKindV1::Commitment, &[1]).is_ok());
        assert!(contracts_exposure_outbound_digest_v1(ArtifactKindV1::Reveal, &[]).is_err());
        assert!(contracts_exposure_outbound_digest_v1(
            ArtifactKindV1::PartialSignature,
            &[0; 4_097]
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn authenticated_exposure_lifecycle_enforces_predecessors_revisions_and_states(
    ) -> Result<(), CanonicalCodecError> {
        let commitment_attempt = authenticated_attempt(1, SigningPhaseV1::SigNonceCommit)?;
        let commitment = ExposureRecordV1::new_persisted(&commitment_attempt, None, &[0x51; 35])?;
        assert_eq!(commitment.lifecycle_revision(), 2);
        let commitment_authorized = ExposureRecordV1::new_successor(&commitment, None)?;
        let commitment_spent = ExposureRecordV1::new_successor(&commitment_authorized, None)?;
        assert_eq!(commitment_spent.state(), ExposureStateV1::Spent);
        assert_eq!(commitment_spent.lifecycle_revision(), 4);
        assert!(ExposureRecordV1::new_successor(&commitment_spent, None).is_err());

        let reveal_attempt = authenticated_attempt(4, SigningPhaseV1::SigNonceReveal)?;
        assert!(ExposureRecordV1::new_persisted(&reveal_attempt, None, &[0x52; 69]).is_err());
        let reveal =
            ExposureRecordV1::new_persisted(&reveal_attempt, Some(&commitment_spent), &[0x52; 69])?;
        let reveal_authorized = ExposureRecordV1::new_successor(&reveal, None)?;
        let reveal_spent = ExposureRecordV1::new_successor(&reveal_authorized, None)?;
        assert_eq!(reveal_spent.lifecycle_revision(), 7);

        let partial_attempt = authenticated_attempt(7, SigningPhaseV1::SigPartial)?;
        let partial =
            ExposureRecordV1::new_persisted(&partial_attempt, Some(&reveal_spent), &[0x53; 67])?;
        let consumed = TombstoneV1::new_consumed(&partial_attempt, &partial, [0x66; 32])?;
        assert_eq!(partial.lifecycle_revision(), 8);
        assert_eq!(consumed.terminal_revision(), 9);
        assert!(ExposureRecordV1::new_successor(&partial, None).is_err());
        let partial_authorized = ExposureRecordV1::new_successor(&partial, Some(&consumed))?;
        assert_eq!(partial_authorized.lifecycle_revision(), 10);
        let partial_spent = ExposureRecordV1::new_successor(&partial_authorized, None)?;
        assert_eq!(partial_spent.lifecycle_revision(), 11);
        assert_eq!(partial_spent.state(), ExposureStateV1::Spent);
        assert_eq!(partial.outbound_bytes(), partial_spent.outbound_bytes());
        assert_eq!(partial.outbound_digest(), partial_spent.outbound_digest());
        Ok(())
    }

    #[test]
    fn authenticated_exposure_and_version_id_reject_mutations() -> Result<(), CanonicalCodecError> {
        let attempt = authenticated_attempt(1, SigningPhaseV1::SigNonceCommit)?;
        let exposure = ExposureRecordV1::new_persisted(&attempt, None, &[0x51; 35])?;
        let parsed = ExposureRecordV1::from_bytes(exposure.as_bytes())?;
        assert_eq!(parsed.as_bytes(), exposure.as_bytes());

        for offset in 0..exposure.as_bytes().len() {
            let mut mutation = exposure.as_bytes().to_vec();
            mutation[offset] ^= 1;
            assert!(
                ExposureRecordV1::from_bytes(&mutation).is_err(),
                "offset {offset}"
            );
        }

        let version = exposure.version_id();
        assert_eq!(
            ExposureVersionIdV1::from_bytes_with_record(version.as_bytes(), &exposure)?.as_bytes(),
            version.as_bytes()
        );
        for offset in 0..EXPOSURE_VERSION_ID_LEN {
            let mut mutation = *version.as_bytes();
            mutation[offset] ^= 1;
            assert!(
                ExposureVersionIdV1::from_bytes_with_record(&mutation, &exposure).is_err(),
                "version offset {offset}"
            );
        }
        Ok(())
    }

    #[test]
    fn authenticated_exposure_rejects_reauthenticated_state_and_revision_substitution(
    ) -> Result<(), CanonicalCodecError> {
        let attempt = authenticated_attempt(1, SigningPhaseV1::SigNonceCommit)?;
        let exposure = ExposureRecordV1::new_persisted(&attempt, None, &[0x51; 35])?;

        let mut wrong_state = exposure.as_bytes().to_vec();
        wrong_state[10] = ExposureStateV1::Spent as u8;
        let digest_offset = wrong_state.len() - 32;
        let digest = storage_hash(StorageHashDomainV1::Exposure, &wrong_state[..digest_offset]);
        wrong_state[digest_offset..].copy_from_slice(&digest);
        let wrong_state = ExposureRecordV1::from_bytes(&wrong_state)?;
        assert!(wrong_state
            .validate_persisted_context(&attempt, None)
            .is_err());

        let mut wrong_revision = exposure.as_bytes().to_vec();
        wrong_revision[125..133].copy_from_slice(&3_u64.to_le_bytes());
        let digest_offset = wrong_revision.len() - 32;
        let digest = storage_hash(
            StorageHashDomainV1::Exposure,
            &wrong_revision[..digest_offset],
        );
        wrong_revision[digest_offset..].copy_from_slice(&digest);
        let wrong_revision = ExposureRecordV1::from_bytes(&wrong_revision)?;
        assert!(wrong_revision
            .validate_persisted_context(&attempt, None)
            .is_err());
        Ok(())
    }
}
