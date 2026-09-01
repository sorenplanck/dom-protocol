//! Structurally validated irreversible tombstone records.

use super::{
    exact, is_zero, parse_nonce_identity, read_u16, read_u64, storage_hash, AttemptRecordV1,
    CanonicalCodecError, ExposureRecordV1, ExposureStateV1, NonceIdentityV1, SessionClaimV1,
    StorageHashDomainV1,
};

const TOMBSTONE_MAGIC: &[u8; 8] = b"DOMNVTS1";

/// Exact encoded size of `TombstoneV1`.
pub const TOMBSTONE_LEN: usize = 255;

/// Closed terminal-reason registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TerminalReasonV1 {
    /// The partial-signature nonce was irreversibly consumed.
    Consumed = 1,
    /// An authenticated abort irreversibly consumed the slot.
    AbortConsumed = 2,
    /// Ambiguity or invalid recovery irreversibly burned the slot.
    Burned = 3,
}

impl TryFrom<u8> for TerminalReasonV1 {
    type Error = CanonicalCodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Consumed),
            2 => Ok(Self::AbortConsumed),
            3 => Ok(Self::Burned),
            _ => Err(CanonicalCodecError::InvalidEncoding),
        }
    }
}

/// Structurally parsed canonical tombstone.
///
/// The parser enforces fixed syntax and the self-contained `Consumed` evidence
/// rule. It does not authenticate any digest or select Abort/Burn evidence from
/// a durable inventory.
pub struct UnauthenticatedTombstoneV1 {
    bytes: [u8; TOMBSTONE_LEN],
    identity: NonceIdentityV1,
    reason: TerminalReasonV1,
    terminal_revision: u64,
}

impl UnauthenticatedTombstoneV1 {
    /// Parses exact bytes and all self-contained structural rules.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<TOMBSTONE_LEN>(input)?;
        if &bytes[..8] != TOMBSTONE_MAGIC
            || read_u16(&bytes[8..10]) != 1
            || bytes[116..119] != [0; 3]
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let identity = parse_nonce_identity(&bytes[10..115])?;
        let reason = TerminalReasonV1::try_from(bytes[115])?;
        let terminal_revision = read_u64(&bytes[119..127]);
        if terminal_revision == 0
            || (reason == TerminalReasonV1::Consumed
                && (is_zero(&bytes[127..159])
                    || is_zero(&bytes[159..191])
                    || is_zero(&bytes[191..223])))
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes,
            identity,
            reason,
            terminal_revision,
        })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; TOMBSTONE_LEN] {
        &self.bytes
    }

    /// Returns the canonical nonce identity.
    pub const fn identity(&self) -> &NonceIdentityV1 {
        &self.identity
    }

    /// Returns the terminal reason.
    pub const fn reason(&self) -> TerminalReasonV1 {
        self.reason
    }

    /// Returns the nonzero terminal lifecycle revision.
    pub const fn terminal_revision(&self) -> u64 {
        self.terminal_revision
    }

    /// Returns the unauthenticated triggering-attempt digest or zero sentinel.
    pub fn triggering_attempt_digest(&self) -> &[u8] {
        &self.bytes[127..159]
    }

    /// Returns the unauthenticated related-exposure digest or zero sentinel.
    pub fn related_exposure_digest(&self) -> &[u8] {
        &self.bytes[159..191]
    }

    /// Returns the unauthenticated deleted-secret envelope digest or zero sentinel.
    pub fn deleted_secret_envelope_digest(&self) -> &[u8] {
        &self.bytes[191..223]
    }

    /// Returns the unauthenticated tombstone digest.
    pub fn tombstone_digest(&self) -> &[u8] {
        &self.bytes[223..255]
    }
}

/// Authenticated evidence for the one active nonce-secret object selected by
/// retained Store authority.
///
/// This crate-private value is not an authority and cannot be supplied by an
/// application caller. The retained Store constructs it only after verifying
/// the complete envelope, metadata, identity, and digest.
pub(crate) struct ActiveSecretEvidenceV1 {
    identity: NonceIdentityV1,
    object_header_revision: u64,
    complete_envelope_digest: [u8; 32],
}

impl ActiveSecretEvidenceV1 {
    /// Constructs authenticated active-secret evidence for terminal selection.
    pub(crate) fn new(
        identity: NonceIdentityV1,
        object_header_revision: u64,
        complete_envelope_digest: [u8; 32],
    ) -> Result<Self, CanonicalCodecError> {
        identity.require_strict_phase1()?;
        if object_header_revision == 0 || is_zero(&complete_envelope_digest) {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        Ok(Self {
            identity,
            object_header_revision,
            complete_envelope_digest,
        })
    }
}

/// Deterministically selected authenticated evidence for an abort or ordinary burn.
///
/// Only the retained Store may assemble this crate-private value from its
/// authenticated claim, attempts, exposures, and optional active-secret
/// envelope. It carries no caller-usable authority.
pub(crate) struct TerminalEvidenceV1 {
    identity: NonceIdentityV1,
    current_state_revision: u64,
    triggering_attempt_digest: [u8; 32],
    related_exposure_digest: [u8; 32],
    deleted_secret_envelope_digest: [u8; 32],
}

impl TerminalEvidenceV1 {
    /// Selects the exact P1-002/P1-004 current-stage terminal evidence.
    pub(crate) fn select(
        claim: &SessionClaimV1,
        attempts: &[&AttemptRecordV1],
        exposures: &[&ExposureRecordV1],
        active_secret: Option<&ActiveSecretEvidenceV1>,
    ) -> Result<Self, CanonicalCodecError> {
        let identity = *claim.identity();
        let mut current_state_revision = claim.claim_revision();
        if let Some(secret) = active_secret {
            if secret.identity.as_bytes() != identity.as_bytes() {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
            current_state_revision = current_state_revision.max(secret.object_header_revision);
        }
        for exposure in exposures {
            if exposure.identity().as_bytes() != identity.as_bytes() {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
            current_state_revision = current_state_revision.max(exposure.lifecycle_revision());
        }
        let mut selected_attempt: Option<&AttemptRecordV1> = None;
        for attempt in attempts {
            if attempt.identity().as_bytes() != identity.as_bytes()
                || attempt.expected_lifecycle_revision() > current_state_revision
            {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
            if attempt.expected_lifecycle_revision() == current_state_revision {
                if selected_attempt.is_some() {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                selected_attempt = Some(attempt);
            }
        }

        let mut selected_exposure: Option<&ExposureRecordV1> = None;
        for exposure in exposures {
            match selected_exposure {
                None => selected_exposure = Some(exposure),
                Some(current) if exposure.lifecycle_revision() > current.lifecycle_revision() => {
                    selected_exposure = Some(exposure);
                }
                Some(current) if exposure.lifecycle_revision() == current.lifecycle_revision() => {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                Some(_) => {}
            }
        }

        Ok(Self {
            identity,
            current_state_revision,
            triggering_attempt_digest: selected_attempt
                .map(|attempt| *attempt.attempt_digest())
                .unwrap_or([0; 32]),
            related_exposure_digest: selected_exposure
                .map(|exposure| *exposure.record_digest())
                .unwrap_or([0; 32]),
            deleted_secret_envelope_digest: active_secret
                .map(|secret| secret.complete_envelope_digest)
                .unwrap_or([0; 32]),
        })
    }

    /// Selects the exact P1-002 section 7.4 burn evidence from the fully
    /// authenticated target/source union when neither side has a tombstone.
    ///
    /// Source backup nonce-secret ciphertext is not an input to this seam.
    /// Only an authenticated active-target secret may contribute its revision
    /// and complete-envelope digest. Equal highest-revision attempts or
    /// exposures contribute a digest only when their complete canonical bytes
    /// are byte-identical; a conflicting tie uses the normative zero sentinel.
    #[cfg(any(test, feature = "evidence-only"))]
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
    )]
    pub(crate) fn select_restore_union(
        identity: NonceIdentityV1,
        target_claim: Option<&SessionClaimV1>,
        target_attempts: &[&AttemptRecordV1],
        target_exposures: &[&ExposureRecordV1],
        source_claim: Option<&SessionClaimV1>,
        source_attempts: &[&AttemptRecordV1],
        source_exposures: &[&ExposureRecordV1],
        active_target_secret: Option<&ActiveSecretEvidenceV1>,
    ) -> Result<Self, CanonicalCodecError> {
        identity.require_strict_phase1()?;

        let mut current_state_revision = 0_u64;
        let mut verified_record_present = false;
        for claim in target_claim.into_iter().chain(source_claim) {
            if claim.identity().as_bytes() != identity.as_bytes() {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
            current_state_revision = current_state_revision.max(claim.claim_revision());
            verified_record_present = true;
        }
        for attempt in target_attempts.iter().chain(source_attempts) {
            if attempt.identity().as_bytes() != identity.as_bytes() {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
            current_state_revision =
                current_state_revision.max(attempt.expected_lifecycle_revision());
            verified_record_present = true;
        }
        for exposure in target_exposures.iter().chain(source_exposures) {
            if exposure.identity().as_bytes() != identity.as_bytes() {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
            current_state_revision = current_state_revision.max(exposure.lifecycle_revision());
            verified_record_present = true;
        }
        if let Some(secret) = active_target_secret {
            if secret.identity.as_bytes() != identity.as_bytes() {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
            current_state_revision = current_state_revision.max(secret.object_header_revision);
            verified_record_present = true;
        }
        if !verified_record_present || current_state_revision == 0 {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }

        let mut highest_attempt: Option<&AttemptRecordV1> = None;
        let mut attempt_tie_is_identical = true;
        for attempt in target_attempts.iter().chain(source_attempts) {
            match highest_attempt {
                None => highest_attempt = Some(attempt),
                Some(current)
                    if attempt.expected_lifecycle_revision()
                        > current.expected_lifecycle_revision() =>
                {
                    highest_attempt = Some(attempt);
                    attempt_tie_is_identical = true;
                }
                Some(current)
                    if attempt.expected_lifecycle_revision()
                        == current.expected_lifecycle_revision() =>
                {
                    attempt_tie_is_identical &= attempt.as_bytes() == current.as_bytes()
                        && attempt.attempt_digest() == current.attempt_digest();
                }
                Some(_) => {}
            }
        }

        let mut highest_exposure: Option<&ExposureRecordV1> = None;
        let mut exposure_tie_is_identical = true;
        for exposure in target_exposures.iter().chain(source_exposures) {
            match highest_exposure {
                None => highest_exposure = Some(exposure),
                Some(current) if exposure.lifecycle_revision() > current.lifecycle_revision() => {
                    highest_exposure = Some(exposure);
                    exposure_tie_is_identical = true;
                }
                Some(current) if exposure.lifecycle_revision() == current.lifecycle_revision() => {
                    exposure_tie_is_identical &= exposure.as_bytes() == current.as_bytes()
                        && exposure.record_digest() == current.record_digest();
                }
                Some(_) => {}
            }
        }

        Ok(Self {
            identity,
            current_state_revision,
            triggering_attempt_digest: highest_attempt
                .filter(|_| attempt_tie_is_identical)
                .map(|attempt| *attempt.attempt_digest())
                .unwrap_or([0; 32]),
            related_exposure_digest: highest_exposure
                .filter(|_| exposure_tie_is_identical)
                .map(|exposure| *exposure.record_digest())
                .unwrap_or([0; 32]),
            deleted_secret_envelope_digest: active_target_secret
                .map(|secret| secret.complete_envelope_digest)
                .unwrap_or([0; 32]),
        })
    }

    /// Reconstructs terminal evidence after the retained Store has already
    /// deleted the active secret named by an authenticated tombstone.
    ///
    /// The caller must first authenticate the encrypted tombstone under the
    /// current generation key and prove its byte identity with the contiguous
    /// terminal journal payload. The nonzero deleted-envelope digest then
    /// represents historical deletion evidence, never caller input.
    pub(crate) fn select_after_authenticated_terminal(
        claim: &SessionClaimV1,
        attempts: &[&AttemptRecordV1],
        exposures: &[&ExposureRecordV1],
        tombstone: &TombstoneV1,
    ) -> Result<Self, CanonicalCodecError> {
        if tombstone.identity.as_bytes() != claim.identity().as_bytes()
            || !matches!(
                tombstone.reason,
                TerminalReasonV1::AbortConsumed | TerminalReasonV1::Burned
            )
        {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }

        let historical_secret_revision = if is_zero(&tombstone.deleted_secret_envelope_digest) {
            None
        } else {
            let mut revision: Option<u64> = None;
            for attempt in attempts {
                if attempt.identity().as_bytes() != claim.identity().as_bytes() {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                if attempt.artifact() == super::ArtifactKindV1::Commitment {
                    let candidate = attempt
                        .expected_lifecycle_revision()
                        .checked_add(1)
                        .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
                    if revision.replace(candidate).is_some() {
                        return Err(CanonicalCodecError::InvalidLifecycle);
                    }
                }
            }
            Some(revision.ok_or(CanonicalCodecError::InvalidLifecycle)?)
        };

        let mut current_state_revision = claim.claim_revision();
        if let Some(secret_revision) = historical_secret_revision {
            current_state_revision = current_state_revision.max(secret_revision);
        }
        for exposure in exposures {
            if exposure.identity().as_bytes() != claim.identity().as_bytes() {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
            current_state_revision = current_state_revision.max(exposure.lifecycle_revision());
        }
        if tombstone.terminal_revision
            != current_state_revision
                .checked_add(1)
                .ok_or(CanonicalCodecError::ArithmeticOverflow)?
        {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }

        let mut selected_attempt: Option<&AttemptRecordV1> = None;
        for attempt in attempts {
            if attempt.identity().as_bytes() != claim.identity().as_bytes()
                || attempt.expected_lifecycle_revision() > current_state_revision
            {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
            if attempt.expected_lifecycle_revision() == current_state_revision {
                if selected_attempt.is_some() {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                selected_attempt = Some(attempt);
            }
        }

        let mut selected_exposure: Option<&ExposureRecordV1> = None;
        for exposure in exposures {
            match selected_exposure {
                None => selected_exposure = Some(exposure),
                Some(current) if exposure.lifecycle_revision() > current.lifecycle_revision() => {
                    selected_exposure = Some(exposure);
                }
                Some(current) if exposure.lifecycle_revision() == current.lifecycle_revision() => {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                Some(_) => {}
            }
        }

        Ok(Self {
            identity: *claim.identity(),
            current_state_revision,
            triggering_attempt_digest: selected_attempt
                .map(|attempt| *attempt.attempt_digest())
                .unwrap_or([0; 32]),
            related_exposure_digest: selected_exposure
                .map(|exposure| *exposure.record_digest())
                .unwrap_or([0; 32]),
            deleted_secret_envelope_digest: tombstone.deleted_secret_envelope_digest,
        })
    }

    /// Selects terminal evidence when authenticated inventory proves that no
    /// active nonce-secret path exists.
    #[cfg(test)]
    pub(super) fn select_without_active_secret(
        claim: &SessionClaimV1,
        attempts: &[&AttemptRecordV1],
        exposures: &[&ExposureRecordV1],
    ) -> Result<Self, CanonicalCodecError> {
        Self::select(claim, attempts, exposures, None)
    }
}

/// Authenticated canonical irreversible tombstone.
#[derive(Clone, Eq, PartialEq)]
pub struct TombstoneV1 {
    bytes: [u8; TOMBSTONE_LEN],
    identity: NonceIdentityV1,
    reason: TerminalReasonV1,
    terminal_revision: u64,
    triggering_attempt_digest: [u8; 32],
    related_exposure_digest: [u8; 32],
    deleted_secret_envelope_digest: [u8; 32],
    tombstone_digest: [u8; 32],
}

impl TombstoneV1 {
    /// Constructs the collision-free consumed tombstone for a persisted
    /// partial signature and its matching attempt.
    pub fn new_consumed(
        attempt: &AttemptRecordV1,
        persisted_partial: &ExposureRecordV1,
        deleted_secret_envelope_digest: [u8; 32],
    ) -> Result<Self, CanonicalCodecError> {
        persisted_partial.validate_persisted_attempt(attempt)?;
        if attempt.artifact() != super::ArtifactKindV1::PartialSignature
            || persisted_partial.state() != ExposureStateV1::Persisted
            || is_zero(&deleted_secret_envelope_digest)
        {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        let terminal_revision = persisted_partial
            .lifecycle_revision()
            .checked_add(1)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        Self::construct(
            *attempt.identity(),
            TerminalReasonV1::Consumed,
            terminal_revision,
            *attempt.attempt_digest(),
            *persisted_partial.record_digest(),
            deleted_secret_envelope_digest,
        )
    }

    /// Constructs an authenticated-abort tombstone from selected evidence.
    pub(crate) fn new_abort(evidence: &TerminalEvidenceV1) -> Result<Self, CanonicalCodecError> {
        Self::new_terminal(TerminalReasonV1::AbortConsumed, evidence)
    }

    /// Constructs an ordinary or orphan-claim burn from selected evidence.
    pub(crate) fn new_burn(evidence: &TerminalEvidenceV1) -> Result<Self, CanonicalCodecError> {
        Self::new_terminal(TerminalReasonV1::Burned, evidence)
    }

    fn new_terminal(
        reason: TerminalReasonV1,
        evidence: &TerminalEvidenceV1,
    ) -> Result<Self, CanonicalCodecError> {
        let terminal_revision = evidence
            .current_state_revision
            .checked_add(1)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        Self::construct(
            evidence.identity,
            reason,
            terminal_revision,
            evidence.triggering_attempt_digest,
            evidence.related_exposure_digest,
            evidence.deleted_secret_envelope_digest,
        )
    }

    /// Parses exact bytes and authenticates the tombstone digest and purpose policy.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedTombstoneV1::parse_structural(input)?;
        structural.identity().require_strict_phase1()?;
        let expected = storage_hash(StorageHashDomainV1::Tombstone, &input[..223]);
        if structural.tombstone_digest() != expected {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        let mut triggering_attempt_digest = [0_u8; 32];
        triggering_attempt_digest.copy_from_slice(structural.triggering_attempt_digest());
        let mut related_exposure_digest = [0_u8; 32];
        related_exposure_digest.copy_from_slice(structural.related_exposure_digest());
        let mut deleted_secret_envelope_digest = [0_u8; 32];
        deleted_secret_envelope_digest.copy_from_slice(structural.deleted_secret_envelope_digest());
        Ok(Self {
            bytes: *structural.as_bytes(),
            identity: *structural.identity(),
            reason: structural.reason(),
            terminal_revision: structural.terminal_revision(),
            triggering_attempt_digest,
            related_exposure_digest,
            deleted_secret_envelope_digest,
            tombstone_digest: expected,
        })
    }

    fn construct(
        identity: NonceIdentityV1,
        reason: TerminalReasonV1,
        terminal_revision: u64,
        triggering_attempt_digest: [u8; 32],
        related_exposure_digest: [u8; 32],
        deleted_secret_envelope_digest: [u8; 32],
    ) -> Result<Self, CanonicalCodecError> {
        identity.require_strict_phase1()?;
        if terminal_revision == 0
            || (reason == TerminalReasonV1::Consumed
                && (is_zero(&triggering_attempt_digest)
                    || is_zero(&related_exposure_digest)
                    || is_zero(&deleted_secret_envelope_digest)))
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let mut bytes = [0_u8; TOMBSTONE_LEN];
        bytes[..8].copy_from_slice(TOMBSTONE_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..115].copy_from_slice(identity.as_bytes());
        bytes[115] = reason as u8;
        bytes[119..127].copy_from_slice(&terminal_revision.to_le_bytes());
        bytes[127..159].copy_from_slice(&triggering_attempt_digest);
        bytes[159..191].copy_from_slice(&related_exposure_digest);
        bytes[191..223].copy_from_slice(&deleted_secret_envelope_digest);
        let tombstone_digest = storage_hash(StorageHashDomainV1::Tombstone, &bytes[..223]);
        bytes[223..255].copy_from_slice(&tombstone_digest);
        Ok(Self {
            bytes,
            identity,
            reason,
            terminal_revision,
            triggering_attempt_digest,
            related_exposure_digest,
            deleted_secret_envelope_digest,
            tombstone_digest,
        })
    }

    /// Validates an abort/burn tombstone against deterministically selected evidence.
    pub(crate) fn validate_terminal_evidence(
        &self,
        evidence: &TerminalEvidenceV1,
    ) -> Result<(), CanonicalCodecError> {
        let expected = match self.reason {
            TerminalReasonV1::AbortConsumed => Self::new_abort(evidence)?,
            TerminalReasonV1::Burned => Self::new_burn(evidence)?,
            TerminalReasonV1::Consumed => return Err(CanonicalCodecError::InvalidLifecycle),
        };
        if self != &expected {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        Ok(())
    }

    /// Validates the consumed tombstone required between a persisted and
    /// authorized partial-signature exposure.
    pub fn validate_intervening_consumed(
        &self,
        persisted_partial: &ExposureRecordV1,
    ) -> Result<(), CanonicalCodecError> {
        let expected_revision = persisted_partial
            .lifecycle_revision()
            .checked_add(1)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        if self.reason != TerminalReasonV1::Consumed
            || self.identity.as_bytes() != persisted_partial.identity().as_bytes()
            || self.terminal_revision != expected_revision
            || self.related_exposure_digest != *persisted_partial.record_digest()
            || is_zero(&self.triggering_attempt_digest)
            || is_zero(&self.deleted_secret_envelope_digest)
        {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        Ok(())
    }

    /// Returns the exact authenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; TOMBSTONE_LEN] {
        &self.bytes
    }

    /// Returns the canonical nonce identity.
    pub const fn identity(&self) -> &NonceIdentityV1 {
        &self.identity
    }

    /// Returns the terminal reason.
    pub const fn reason(&self) -> TerminalReasonV1 {
        self.reason
    }

    /// Returns the terminal lifecycle revision.
    pub const fn terminal_revision(&self) -> u64 {
        self.terminal_revision
    }

    /// Returns the triggering attempt digest or its allowed zero sentinel.
    pub const fn triggering_attempt_digest(&self) -> &[u8; 32] {
        &self.triggering_attempt_digest
    }

    /// Returns the related exposure digest or its allowed zero sentinel.
    pub const fn related_exposure_digest(&self) -> &[u8; 32] {
        &self.related_exposure_digest
    }

    /// Returns the deleted secret-object complete-envelope digest or zero.
    pub const fn deleted_secret_envelope_digest(&self) -> &[u8; 32] {
        &self.deleted_secret_envelope_digest
    }

    /// Returns the authenticated tombstone digest.
    pub const fn tombstone_digest(&self) -> &[u8; 32] {
        &self.tombstone_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{PurposeV1, SigningPhaseV1};

    fn authenticated_claim() -> Result<SessionClaimV1, CanonicalCodecError> {
        SessionClaimV1::new(NonceIdentityV1::new(
            [0x11; 32],
            [0x22; 32],
            PurposeV1::Refund,
            [0x33; 32],
            7,
        )?)
    }

    fn tombstone_bytes(reason: TerminalReasonV1) -> [u8; TOMBSTONE_LEN] {
        let mut bytes = [0_u8; TOMBSTONE_LEN];
        bytes[..8].copy_from_slice(TOMBSTONE_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..42].fill(0x11);
        bytes[42..74].fill(0x22);
        bytes[74] = 0x02;
        bytes[75..107].fill(0x33);
        bytes[107..115].copy_from_slice(&7_u64.to_le_bytes());
        bytes[115] = reason as u8;
        bytes[119..127].copy_from_slice(&9_u64.to_le_bytes());
        if reason == TerminalReasonV1::Consumed {
            bytes[127..159].fill(0x44);
            bytes[159..191].fill(0x55);
            bytes[191..223].fill(0x66);
        }
        bytes
    }

    #[test]
    fn tombstone_accepts_all_closed_reasons() -> Result<(), CanonicalCodecError> {
        for reason in [
            TerminalReasonV1::Consumed,
            TerminalReasonV1::AbortConsumed,
            TerminalReasonV1::Burned,
        ] {
            let bytes = tombstone_bytes(reason);
            let parsed = UnauthenticatedTombstoneV1::parse_structural(&bytes)?;
            assert_eq!(parsed.as_bytes(), &bytes);
            assert_eq!(parsed.reason(), reason);
            assert_eq!(parsed.terminal_revision(), 9);
            assert_eq!(parsed.tombstone_digest(), &[0; 32]);
        }
        Ok(())
    }

    #[test]
    fn consumed_requires_all_three_evidence_digests() {
        let canonical = tombstone_bytes(TerminalReasonV1::Consumed);
        for range in [127..159, 159..191, 191..223] {
            let mut bytes = canonical;
            bytes[range].fill(0);
            assert!(UnauthenticatedTombstoneV1::parse_structural(&bytes).is_err());
        }
    }

    #[test]
    fn abort_and_burn_allow_structural_zero_evidence() -> Result<(), CanonicalCodecError> {
        for reason in [TerminalReasonV1::AbortConsumed, TerminalReasonV1::Burned] {
            let parsed = UnauthenticatedTombstoneV1::parse_structural(&tombstone_bytes(reason))?;
            assert_eq!(parsed.triggering_attempt_digest(), &[0; 32]);
            assert_eq!(parsed.related_exposure_digest(), &[0; 32]);
            assert_eq!(parsed.deleted_secret_envelope_digest(), &[0; 32]);
        }
        Ok(())
    }

    #[test]
    fn tombstone_rejects_mutated_fixed_fields() {
        let canonical = tombstone_bytes(TerminalReasonV1::Burned);
        let mutations = [(0, canonical[0] ^ 1), (8, 2), (74, 0), (115, 0), (116, 1)];
        for (offset, replacement) in mutations {
            let mut bytes = canonical;
            bytes[offset] = replacement;
            assert!(UnauthenticatedTombstoneV1::parse_structural(&bytes).is_err());
        }

        let mut zero_revision = canonical;
        zero_revision[119..127].fill(0);
        assert!(UnauthenticatedTombstoneV1::parse_structural(&zero_revision).is_err());
        assert!(UnauthenticatedTombstoneV1::parse_structural(&canonical[..254]).is_err());
    }

    #[test]
    fn terminal_reason_registry_is_exhaustive() {
        for value in 0_u8..=u8::MAX {
            assert_eq!(
                TerminalReasonV1::try_from(value).is_ok(),
                (1..=3).contains(&value)
            );
        }
    }

    #[test]
    fn tombstone_rejects_every_truncation_and_trailing_byte() {
        let bytes = tombstone_bytes(TerminalReasonV1::Consumed);
        for end in 0..bytes.len() {
            assert!(
                UnauthenticatedTombstoneV1::parse_structural(&bytes[..end]).is_err(),
                "tombstone {end}"
            );
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(UnauthenticatedTombstoneV1::parse_structural(&trailing).is_err());
    }

    #[test]
    fn orphan_claim_burn_is_authenticated_at_revision_two() -> Result<(), CanonicalCodecError> {
        let claim = authenticated_claim()?;
        let evidence = TerminalEvidenceV1::select_without_active_secret(&claim, &[], &[])?;
        let burned = TombstoneV1::new_burn(&evidence)?;
        assert_eq!(burned.terminal_revision(), 2);
        assert_eq!(burned.reason(), TerminalReasonV1::Burned);
        assert_eq!(burned.triggering_attempt_digest(), &[0; 32]);
        assert_eq!(burned.related_exposure_digest(), &[0; 32]);
        assert_eq!(burned.deleted_secret_envelope_digest(), &[0; 32]);
        assert_eq!(
            TombstoneV1::from_bytes(burned.as_bytes())?.as_bytes(),
            burned.as_bytes()
        );
        Ok(())
    }

    #[test]
    fn terminal_evidence_without_live_authority_selects_no_secret_digest(
    ) -> Result<(), CanonicalCodecError> {
        let claim = authenticated_claim()?;
        let commitment_attempt = AttemptRecordV1::new(
            *claim.identity(),
            1,
            SigningPhaseV1::SigNonceCommit,
            [0x41; 32],
        )?;
        let persisted = ExposureRecordV1::new_persisted(&commitment_attempt, None, &[0x51; 35])?;
        let authorized = ExposureRecordV1::new_successor(&persisted, None)?;
        let spent = ExposureRecordV1::new_successor(&authorized, None)?;
        let reveal_attempt = AttemptRecordV1::new(
            *claim.identity(),
            spent.lifecycle_revision(),
            SigningPhaseV1::SigNonceReveal,
            [0x42; 32],
        )?;
        let evidence = TerminalEvidenceV1::select_without_active_secret(
            &claim,
            &[&commitment_attempt, &reveal_attempt],
            &[&persisted, &authorized, &spent],
        )?;
        let abort = TombstoneV1::new_abort(&evidence)?;
        assert_eq!(abort.terminal_revision(), 5);
        assert_eq!(
            abort.triggering_attempt_digest(),
            reveal_attempt.attempt_digest()
        );
        assert_eq!(abort.related_exposure_digest(), spent.record_digest());
        assert_eq!(abort.deleted_secret_envelope_digest(), &[0; 32]);
        abort.validate_terminal_evidence(&evidence)?;

        let future_attempt = AttemptRecordV1::new(
            *claim.identity(),
            5,
            SigningPhaseV1::SigNonceReveal,
            [0x43; 32],
        )?;
        assert!(TerminalEvidenceV1::select_without_active_secret(
            &claim,
            &[&future_attempt],
            &[&spent],
        )
        .is_err());
        assert!(TerminalEvidenceV1::select_without_active_secret(
            &claim,
            &[&reveal_attempt, &reveal_attempt],
            &[&spent]
        )
        .is_err());
        assert!(TerminalEvidenceV1::select_without_active_secret(
            &claim,
            &[&reveal_attempt],
            &[&spent, &spent]
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn restore_union_burn_uses_checked_max_across_every_record_family(
    ) -> Result<(), CanonicalCodecError> {
        let claim = authenticated_claim()?;
        let identity = *claim.identity();
        let commitment_attempt =
            AttemptRecordV1::new(identity, 1, SigningPhaseV1::SigNonceCommit, [0x81; 32])?;
        let exposure = ExposureRecordV1::new_persisted(&commitment_attempt, None, &[0x82; 35])?;
        let later_attempt =
            AttemptRecordV1::new(identity, 17, SigningPhaseV1::SigNonceReveal, [0x83; 32])?;
        let active = ActiveSecretEvidenceV1::new(identity, 29, [0x84; 32])?;

        let evidence = TerminalEvidenceV1::select_restore_union(
            identity,
            Some(&claim),
            &[&commitment_attempt],
            &[&exposure],
            Some(&claim),
            &[&later_attempt],
            &[],
            Some(&active),
        )?;
        let burn = TombstoneV1::new_burn(&evidence)?;
        assert_eq!(burn.terminal_revision(), 30);
        assert_eq!(
            burn.triggering_attempt_digest(),
            later_attempt.attempt_digest()
        );
        assert_eq!(burn.related_exposure_digest(), exposure.record_digest());
        assert_eq!(burn.deleted_secret_envelope_digest(), &[0x84; 32]);
        Ok(())
    }

    #[test]
    fn restore_union_burn_is_commutative_and_idempotent_for_identical_records(
    ) -> Result<(), CanonicalCodecError> {
        let claim = authenticated_claim()?;
        let identity = *claim.identity();
        for (left_revision, right_revision) in [(1, 2), (7, 3), (13, 13), (64, 127)] {
            let left = AttemptRecordV1::new(
                identity,
                left_revision,
                SigningPhaseV1::SigNonceReveal,
                [0x91; 32],
            )?;
            let right = AttemptRecordV1::new(
                identity,
                right_revision,
                SigningPhaseV1::SigNonceReveal,
                [0x92; 32],
            )?;
            let forward = TerminalEvidenceV1::select_restore_union(
                identity,
                Some(&claim),
                &[&left],
                &[],
                Some(&claim),
                &[&right],
                &[],
                None,
            )?;
            let reverse = TerminalEvidenceV1::select_restore_union(
                identity,
                Some(&claim),
                &[&right],
                &[],
                Some(&claim),
                &[&left],
                &[],
                None,
            )?;
            assert_eq!(
                TombstoneV1::new_burn(&forward)?.as_bytes(),
                TombstoneV1::new_burn(&reverse)?.as_bytes()
            );
        }

        let identical =
            AttemptRecordV1::new(identity, 41, SigningPhaseV1::SigNonceReveal, [0x93; 32])?;
        let once = TerminalEvidenceV1::select_restore_union(
            identity,
            Some(&claim),
            &[&identical],
            &[],
            None,
            &[],
            &[],
            None,
        )?;
        let twice = TerminalEvidenceV1::select_restore_union(
            identity,
            Some(&claim),
            &[&identical],
            &[],
            None,
            &[&identical],
            &[],
            None,
        )?;
        assert_eq!(
            TombstoneV1::new_burn(&once)?.as_bytes(),
            TombstoneV1::new_burn(&twice)?.as_bytes()
        );
        Ok(())
    }

    #[test]
    fn restore_union_conflicting_highest_ties_use_zero_evidence_sentinels(
    ) -> Result<(), CanonicalCodecError> {
        let claim = authenticated_claim()?;
        let identity = *claim.identity();
        let attempt_a =
            AttemptRecordV1::new(identity, 9, SigningPhaseV1::SigNonceReveal, [0xa1; 32])?;
        let attempt_b =
            AttemptRecordV1::new(identity, 9, SigningPhaseV1::SigNonceReveal, [0xa2; 32])?;
        let commitment_a =
            AttemptRecordV1::new(identity, 1, SigningPhaseV1::SigNonceCommit, [0xa3; 32])?;
        let commitment_b =
            AttemptRecordV1::new(identity, 1, SigningPhaseV1::SigNonceCommit, [0xa4; 32])?;
        let exposure_a = ExposureRecordV1::new_persisted(&commitment_a, None, &[0xa5; 35])?;
        let exposure_b = ExposureRecordV1::new_persisted(&commitment_b, None, &[0xa6; 35])?;

        let evidence = TerminalEvidenceV1::select_restore_union(
            identity,
            Some(&claim),
            &[&attempt_a],
            &[&exposure_a],
            Some(&claim),
            &[&attempt_b],
            &[&exposure_b],
            None,
        )?;
        let burn = TombstoneV1::new_burn(&evidence)?;
        assert_eq!(burn.terminal_revision(), 10);
        assert_eq!(burn.triggering_attempt_digest(), &[0; 32]);
        assert_eq!(burn.related_exposure_digest(), &[0; 32]);
        Ok(())
    }

    #[test]
    fn restore_union_rejects_identity_mismatch_and_checked_revision_overflow(
    ) -> Result<(), CanonicalCodecError> {
        let claim = authenticated_claim()?;
        let identity = *claim.identity();
        let other_identity =
            NonceIdentityV1::new([0x12; 32], [0x22; 32], PurposeV1::Refund, [0x33; 32], 7)?;
        let mismatched = AttemptRecordV1::new(
            other_identity,
            2,
            SigningPhaseV1::SigNonceReveal,
            [0xb1; 32],
        )?;
        assert!(TerminalEvidenceV1::select_restore_union(
            identity,
            Some(&claim),
            &[],
            &[],
            None,
            &[&mismatched],
            &[],
            None,
        )
        .is_err());

        let maximum = AttemptRecordV1::new(
            identity,
            u64::MAX,
            SigningPhaseV1::SigNonceReveal,
            [0xb2; 32],
        )?;
        let evidence = TerminalEvidenceV1::select_restore_union(
            identity,
            Some(&claim),
            &[&maximum],
            &[],
            None,
            &[],
            &[],
            None,
        )?;
        assert!(matches!(
            TombstoneV1::new_burn(&evidence),
            Err(CanonicalCodecError::ArithmeticOverflow)
        ));
        Ok(())
    }

    #[test]
    fn terminal_evidence_selects_authenticated_active_secret_revision_and_digest(
    ) -> Result<(), CanonicalCodecError> {
        let claim = authenticated_claim()?;
        let stale_attempt = AttemptRecordV1::new(
            *claim.identity(),
            1,
            SigningPhaseV1::SigNonceCommit,
            [0x61; 32],
        )?;
        let current_attempt = AttemptRecordV1::new(
            *claim.identity(),
            5,
            SigningPhaseV1::SigNonceReveal,
            [0x62; 32],
        )?;
        let active_secret = ActiveSecretEvidenceV1::new(*claim.identity(), 5, [0x71; 32])?;
        let evidence = TerminalEvidenceV1::select(
            &claim,
            &[&stale_attempt, &current_attempt],
            &[],
            Some(&active_secret),
        )?;
        let burned = TombstoneV1::new_burn(&evidence)?;
        let aborted = TombstoneV1::new_abort(&evidence)?;

        assert_eq!(burned.terminal_revision(), 6);
        assert_eq!(aborted.terminal_revision(), 6);
        assert_eq!(aborted.reason(), TerminalReasonV1::AbortConsumed);
        assert_eq!(
            burned.triggering_attempt_digest(),
            current_attempt.attempt_digest()
        );
        assert_eq!(
            aborted.triggering_attempt_digest(),
            burned.triggering_attempt_digest()
        );
        assert_eq!(
            aborted.deleted_secret_envelope_digest(),
            burned.deleted_secret_envelope_digest()
        );
        assert_eq!(burned.related_exposure_digest(), &[0; 32]);
        assert_eq!(burned.deleted_secret_envelope_digest(), &[0x71; 32]);
        assert_eq!(
            TombstoneV1::from_bytes(burned.as_bytes())?.as_bytes(),
            burned.as_bytes()
        );
        burned.validate_terminal_evidence(&evidence)?;
        aborted.validate_terminal_evidence(&evidence)?;

        let changed_secret = ActiveSecretEvidenceV1::new(*claim.identity(), 5, [0x72; 32])?;
        let changed_evidence = TerminalEvidenceV1::select(
            &claim,
            &[&stale_attempt, &current_attempt],
            &[],
            Some(&changed_secret),
        )?;
        assert!(burned
            .validate_terminal_evidence(&changed_evidence)
            .is_err());

        assert!(ActiveSecretEvidenceV1::new(*claim.identity(), 0, [0x71; 32]).is_err());
        assert!(ActiveSecretEvidenceV1::new(*claim.identity(), 5, [0; 32]).is_err());
        let other_identity =
            NonceIdentityV1::new([0x12; 32], [0x22; 32], PurposeV1::Refund, [0x33; 32], 7)?;
        let other_secret = ActiveSecretEvidenceV1::new(other_identity, 5, [0x71; 32])?;
        assert!(TerminalEvidenceV1::select(&claim, &[], &[], Some(&other_secret)).is_err());
        Ok(())
    }

    #[test]
    fn authenticated_tombstone_rejects_every_mutation() -> Result<(), CanonicalCodecError> {
        let claim = authenticated_claim()?;
        let evidence = TerminalEvidenceV1::select_without_active_secret(&claim, &[], &[])?;
        let burned = TombstoneV1::new_burn(&evidence)?;
        for offset in 0..TOMBSTONE_LEN {
            let mut mutation = *burned.as_bytes();
            mutation[offset] ^= 1;
            assert!(
                TombstoneV1::from_bytes(&mutation).is_err(),
                "offset {offset}"
            );
        }
        Ok(())
    }

    #[test]
    fn consumed_tombstone_binds_attempt_partial_and_deleted_envelope(
    ) -> Result<(), CanonicalCodecError> {
        let claim = authenticated_claim()?;
        let commitment_attempt = AttemptRecordV1::new(
            *claim.identity(),
            1,
            SigningPhaseV1::SigNonceCommit,
            [1; 32],
        )?;
        let commitment = ExposureRecordV1::new_persisted(&commitment_attempt, None, &[1; 35])?;
        let commitment = ExposureRecordV1::new_successor(&commitment, None)?;
        let commitment = ExposureRecordV1::new_successor(&commitment, None)?;
        let reveal_attempt = AttemptRecordV1::new(
            *claim.identity(),
            4,
            SigningPhaseV1::SigNonceReveal,
            [2; 32],
        )?;
        let reveal = ExposureRecordV1::new_persisted(&reveal_attempt, Some(&commitment), &[2; 69])?;
        let reveal = ExposureRecordV1::new_successor(&reveal, None)?;
        let reveal = ExposureRecordV1::new_successor(&reveal, None)?;
        let partial_attempt =
            AttemptRecordV1::new(*claim.identity(), 7, SigningPhaseV1::SigPartial, [3; 32])?;
        let partial = ExposureRecordV1::new_persisted(&partial_attempt, Some(&reveal), &[3; 67])?;
        let tombstone = TombstoneV1::new_consumed(&partial_attempt, &partial, [4; 32])?;
        assert_eq!(
            tombstone.triggering_attempt_digest(),
            partial_attempt.attempt_digest()
        );
        assert_eq!(tombstone.related_exposure_digest(), partial.record_digest());
        assert_eq!(tombstone.deleted_secret_envelope_digest(), &[4; 32]);
        assert!(TombstoneV1::new_consumed(&partial_attempt, &partial, [0; 32]).is_err());
        Ok(())
    }
}
