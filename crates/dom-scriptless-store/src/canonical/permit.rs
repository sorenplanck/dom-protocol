//! Public lookup identifiers for already-spent immutable exposures.

use dom_adaptor::PermitIdV1;

use super::{
    authoritative_storage_hash_v1, is_zero, read_u16, CanonicalCodecError, ExposureRecordV1,
    ExposureStateV1, JournalEntryKindV1, JournalEntryV1, StorageHashDomainV1,
    UnauthenticatedExposureVersionIdV1, EXPOSURE_VERSION_ID_LEN,
};

const RETIREMENT_MAGIC: &[u8; 8] = b"DOMNVPR1";

/// Exact encoded size of `PermitRetirementV1`.
pub const PERMIT_RETIREMENT_LEN: usize = 229;

/// Self-authenticated lifetime collision evidence for one spent permit.
///
/// This record is not resend or export authority. Its source journal ancestry
/// must be authenticated separately by the retained Store.
pub struct PermitRetirementV1 {
    bytes: [u8; PERMIT_RETIREMENT_LEN],
    exposure: UnauthenticatedExposureVersionIdV1,
    permit_id: PermitIdV1,
    retirement_digest: [u8; 32],
}

impl PermitRetirementV1 {
    /// Constructs the exact retirement record for one authenticated Spent
    /// transition. This record is collision evidence only; it grants neither
    /// export authority nor resend authority.
    pub fn new(
        spent: &ExposureRecordV1,
        spent_entry: &JournalEntryV1,
    ) -> Result<Self, CanonicalCodecError> {
        let permit_id = permit_lookup_id_v1(spent, spent_entry)?;
        let version = spent.version_id();
        let mut bytes = [0_u8; PERMIT_RETIREMENT_LEN];
        bytes[..8].copy_from_slice(RETIREMENT_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..165].copy_from_slice(version.as_bytes());
        bytes[165..197].copy_from_slice(spent_entry.entry_digest());
        let digest =
            authoritative_storage_hash_v1(StorageHashDomainV1::PermitRetirement, &bytes[..197]);
        bytes[197..].copy_from_slice(&digest);
        let record = Self::from_bytes(&bytes)?;
        if record.permit_id() != &permit_id {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(record)
    }

    /// Parses exact retirement bytes and recomputes both registered digests.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        if input.len() != PERMIT_RETIREMENT_LEN
            || &input[..8] != RETIREMENT_MAGIC
            || read_u16(&input[8..10]) != 1
            || is_zero(&input[165..197])
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let exposure = UnauthenticatedExposureVersionIdV1::parse_structural(
            &input[10..10 + EXPOSURE_VERSION_ID_LEN],
        )?;
        if exposure.state() != ExposureStateV1::Spent {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        let retirement_digest =
            authoritative_storage_hash_v1(StorageHashDomainV1::PermitRetirement, &input[..197]);
        if input[197..] != retirement_digest {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        let mut permit_preimage = [0_u8; 187];
        permit_preimage[..155].copy_from_slice(exposure.as_bytes());
        permit_preimage[155..].copy_from_slice(&input[165..197]);
        let permit_id = PermitIdV1::from_bytes(authoritative_storage_hash_v1(
            StorageHashDomainV1::ExportPermitId,
            &permit_preimage,
        ))
        .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        let mut bytes = [0_u8; PERMIT_RETIREMENT_LEN];
        bytes.copy_from_slice(input);
        Ok(Self {
            bytes,
            exposure,
            permit_id,
            retirement_digest,
        })
    }

    /// Returns the exact canonical retirement bytes.
    pub const fn as_bytes(&self) -> &[u8; PERMIT_RETIREMENT_LEN] {
        &self.bytes
    }

    /// Returns the structurally parsed spent exposure-version identifier.
    pub const fn exposure_version(&self) -> &UnauthenticatedExposureVersionIdV1 {
        &self.exposure
    }

    /// Returns the recomputed public non-authoritative permit lookup ID.
    pub const fn permit_id(&self) -> &PermitIdV1 {
        &self.permit_id
    }

    /// Returns the self-authenticated retirement digest.
    pub const fn retirement_digest(&self) -> &[u8; 32] {
        &self.retirement_digest
    }
}

/// Derives the exact NAR-DC-P1-003 public lookup ID for a spent exposure.
///
/// The supplied journal entry must be the authenticated transition whose
/// successor bytes are exactly the supplied spent exposure. This check does
/// not replace complete journal-chain validation by the persistent Store. The
/// result uses the canonical `dom-adaptor::PermitIdV1`; this crate does not
/// define a second semantic permit-ID authority.
pub fn permit_lookup_id_v1(
    spent: &ExposureRecordV1,
    spent_entry: &JournalEntryV1,
) -> Result<PermitIdV1, CanonicalCodecError> {
    if spent.state() != ExposureStateV1::Spent
        || spent_entry.payload().kind() != JournalEntryKindV1::ExposureAuthorized
    {
        return Err(CanonicalCodecError::InvalidLifecycle);
    }
    let payload = spent_entry.payload().as_bytes();
    let successor_length_offset = 155;
    let successor_offset = 159;
    if payload.len() < successor_offset {
        return Err(CanonicalCodecError::InvalidEncoding);
    }
    let successor_length = u32::from_le_bytes([
        payload[successor_length_offset],
        payload[successor_length_offset + 1],
        payload[successor_length_offset + 2],
        payload[successor_length_offset + 3],
    ]);
    let successor_length =
        usize::try_from(successor_length).map_err(|_| CanonicalCodecError::InvalidEncoding)?;
    if payload.len().checked_sub(successor_offset) != Some(successor_length)
        || &payload[successor_offset..] != spent.as_bytes()
    {
        return Err(CanonicalCodecError::AuthenticationFailed);
    }

    let version_id = spent.version_id();
    let mut preimage = [0_u8; 187];
    preimage[..155].copy_from_slice(version_id.as_bytes());
    preimage[155..].copy_from_slice(spent_entry.entry_digest());
    let digest = authoritative_storage_hash_v1(StorageHashDomainV1::ExportPermitId, &preimage);
    PermitIdV1::from_bytes(digest).map_err(|_| CanonicalCodecError::InvalidEncoding)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        AttemptRecordV1, JournalPayloadV1, NonceDerivationAttemptV1, NonceIdentityV1, PurposeV1,
        SigningPhaseV1, ATTEMPT_RECORD_LEN, NONCE_DERIVATION_ATTEMPT_LEN,
    };

    fn spent_commitment() -> Result<(ExposureRecordV1, JournalEntryV1), CanonicalCodecError> {
        let (claim, charge) =
            crate::canonical::reservation::tests::reserve_records(PurposeV1::Funding, 1)?;
        let identity = *claim.identity();
        let attempt = AttemptRecordV1::new(identity, 1, SigningPhaseV1::SigNonceCommit, [5; 32])?;
        let mut derivation_bytes = [0_u8; NONCE_DERIVATION_ATTEMPT_LEN];
        derivation_bytes[..ATTEMPT_RECORD_LEN].copy_from_slice(attempt.as_bytes());
        let derivation = NonceDerivationAttemptV1::from_bytes(&derivation_bytes)?;
        let persisted = ExposureRecordV1::new_persisted(&attempt, None, &[6; 35])?;
        let authorized = ExposureRecordV1::new_successor(&persisted, None)?;
        let spent = ExposureRecordV1::new_successor(&authorized, None)?;
        let first = JournalEntryV1::first(JournalPayloadV1::reserve(&claim, &charge)?)?;
        let attempt_entry = JournalEntryV1::append(
            &first,
            JournalPayloadV1::nonce_derivation_attempt(&derivation),
        )?;
        let persisted_entry = JournalEntryV1::append(
            &attempt_entry,
            JournalPayloadV1::persisted(&attempt, None, &persisted)?,
        )?;
        let authorized_entry = JournalEntryV1::append(
            &persisted_entry,
            JournalPayloadV1::exposure_authorized(&persisted, &authorized, None)?,
        )?;
        let spent_entry = JournalEntryV1::append(
            &authorized_entry,
            JournalPayloadV1::exposure_authorized(&authorized, &spent, None)?,
        )?;
        Ok((spent, spent_entry))
    }

    #[test]
    fn retirement_constructor_matches_its_authenticated_parser() -> Result<(), CanonicalCodecError>
    {
        let (spent, entry) = spent_commitment()?;
        let retirement = PermitRetirementV1::new(&spent, &entry)?;
        assert_eq!(
            PermitRetirementV1::from_bytes(retirement.as_bytes())?.as_bytes(),
            retirement.as_bytes()
        );
        let mut mutated = *retirement.as_bytes();
        mutated[196] ^= 1;
        assert!(PermitRetirementV1::from_bytes(&mutated).is_err());
        Ok(())
    }

    pub(crate) fn retirement() -> Result<[u8; PERMIT_RETIREMENT_LEN], CanonicalCodecError> {
        let (spent, entry) = spent_commitment()?;
        let mut bytes = [0_u8; PERMIT_RETIREMENT_LEN];
        bytes[..8].copy_from_slice(RETIREMENT_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..165].copy_from_slice(spent.version_id().as_bytes());
        bytes[165..197].copy_from_slice(entry.entry_digest());
        let digest =
            authoritative_storage_hash_v1(StorageHashDomainV1::PermitRetirement, &bytes[..197]);
        bytes[197..].copy_from_slice(&digest);
        Ok(bytes)
    }

    #[test]
    fn exact_spent_entry_derives_stable_nonzero_lookup_id() -> Result<(), CanonicalCodecError> {
        let (spent, entry) = spent_commitment()?;
        let first = permit_lookup_id_v1(&spent, &entry)?;
        let second = permit_lookup_id_v1(&spent, &entry)?;
        assert!(first == second);
        assert_ne!(first.as_bytes(), &[0; 32]);
        // Frozen deterministic KAT over the complete signed framing.
        let expected = [
            14, 136, 98, 106, 13, 174, 77, 154, 102, 255, 246, 145, 218, 139, 11, 246, 161, 25, 67,
            108, 44, 164, 61, 10, 164, 233, 74, 24, 142, 57, 6, 114,
        ];
        assert_eq!(first.as_bytes(), &expected);
        Ok(())
    }

    #[test]
    fn another_transition_cannot_authorize_the_spent_bytes() -> Result<(), CanonicalCodecError> {
        let (spent, entry) = spent_commitment()?;
        let identity = NonceIdentityV1::new([7; 32], [8; 32], PurposeV1::Refund, [9; 32], 10)?;
        let attempt = AttemptRecordV1::new(identity, 1, SigningPhaseV1::SigNonceCommit, [11; 32])?;
        let other_persisted = ExposureRecordV1::new_persisted(&attempt, None, &[12; 35])?;
        let other_authorized = ExposureRecordV1::new_successor(&other_persisted, None)?;
        let other_entry = JournalEntryV1::append(
            &entry,
            JournalPayloadV1::exposure_authorized(&other_persisted, &other_authorized, None)?,
        )?;
        assert!(permit_lookup_id_v1(&spent, &other_entry).is_err());
        Ok(())
    }

    #[test]
    fn exact_retirement_is_collision_evidence_only() -> Result<(), CanonicalCodecError> {
        let bytes = retirement()?;
        let parsed = PermitRetirementV1::from_bytes(&bytes)?;
        assert_eq!(parsed.as_bytes(), &bytes);
        assert_ne!(parsed.permit_id().as_bytes(), &[0; 32]);
        assert_eq!(parsed.exposure_version().state(), ExposureStateV1::Spent);
        Ok(())
    }

    #[test]
    fn retirement_rejects_every_truncation_mutation_and_trailing_byte(
    ) -> Result<(), CanonicalCodecError> {
        let bytes = retirement()?;
        for end in 0..bytes.len() {
            assert!(PermitRetirementV1::from_bytes(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(PermitRetirementV1::from_bytes(&trailing).is_err());
        for index in 0..bytes.len() {
            let mut mutated = bytes;
            mutated[index] ^= 1;
            assert!(
                PermitRetirementV1::from_bytes(&mutated).is_err(),
                "accepted mutation at {index}"
            );
        }
        Ok(())
    }
}
