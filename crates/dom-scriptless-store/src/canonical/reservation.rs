//! Canonical reservation, budget, and derivation records.
//!
//! These codecs authenticate their own bytes but never grant live Store,
//! reservation, budget, secret, or export authority. Runtime authority remains
//! exclusively owned by the retained Store implementation.

use dom_adaptor::{DirectionV1, PurposeV1, SigningPhaseV1};

use super::{
    is_zero, read_u16, read_u32, read_u64, storage_hash, ArtifactKindV1, AttemptRecordV1,
    CanonicalCodecError, StorageHashDomainV1, UnauthenticatedAttemptRecordV1, ATTEMPT_RECORD_LEN,
};

const CONTEXT_MAGIC: &[u8; 8] = b"DOMNVCT1";
const AUTHORITY_MAGIC: &[u8; 8] = b"DOMNVRA1";
const POLICY_MAGIC: &[u8; 8] = b"DOMNVBP1";
const CHARGE_MAGIC: &[u8; 8] = b"DOMNVBC1";

/// Exact encoded size of `BudgetPolicyV1`.
pub const BUDGET_POLICY_LEN: usize = 144;
/// Exact encoded size of a Refund/Funding reservation-context binding.
pub const RESERVATION_CONTEXT_NO_ADAPTOR_LEN: usize = 499;
/// Exact encoded size of a ClaimAdaptor reservation-context binding.
pub const RESERVATION_CONTEXT_ADAPTOR_LEN: usize = 532;
/// Exact encoded size of a Refund/Funding reservation authority.
pub const RESERVATION_AUTHORITY_NO_ADAPTOR_LEN: usize = 850;
/// Exact encoded size of a ClaimAdaptor reservation authority.
pub const RESERVATION_AUTHORITY_ADAPTOR_LEN: usize = 883;
/// Exact encoded size of a Refund/Funding budget charge.
pub const BUDGET_CHARGE_NO_ADAPTOR_LEN: usize = 916;
/// Exact encoded size of a ClaimAdaptor budget charge.
pub const BUDGET_CHARGE_ADAPTOR_LEN: usize = 949;
/// Exact encoded size of `NonceDerivationAttemptV1`.
pub const NONCE_DERIVATION_ATTEMPT_LEN: usize = 201;

/// Closed policy-profile registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BudgetPolicyProfileV1 {
    /// Separately ratified production policy bytes.
    ProductionRatified = 0x01,
    /// Explicit evidence-only policy bytes.
    EvidenceOnly = 0x02,
}

impl TryFrom<u8> for BudgetPolicyProfileV1 {
    type Error = CanonicalCodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::ProductionRatified),
            0x02 => Ok(Self::EvidenceOnly),
            _ => Err(CanonicalCodecError::InvalidEncoding),
        }
    }
}

/// Structurally and cryptographically self-authenticated budget-policy bytes.
///
/// Parsing does not establish that a production composition root ratified the
/// policy values.
#[derive(Clone, Eq, PartialEq)]
pub struct BudgetPolicyV1 {
    bytes: [u8; BUDGET_POLICY_LEN],
    profile: BudgetPolicyProfileV1,
    digest: [u8; 32],
}

impl BudgetPolicyV1 {
    /// Parses exact bytes and authenticates the closed policy codec.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        if input.len() != BUDGET_POLICY_LEN
            || &input[..8] != POLICY_MAGIC
            || read_u16(&input[8..10]) != 1
            || input[11] != 0x01
            || !is_zero(&input[12..16])
            || is_zero(&input[16..48])
            || read_u64(&input[48..56]) == 0
            || read_u64(&input[56..64]) == 0
            || read_u32(&input[64..68]) == 0
            || !is_zero(&input[68..72])
            || read_u64(&input[72..80]) == 0
            || read_u64(&input[80..88]) == 0
            || read_u64(&input[88..96]) == 0
            || read_u64(&input[96..104]) == 0
            || read_u64(&input[104..112]) == 0
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let profile = BudgetPolicyProfileV1::try_from(input[10])?;
        let digest = storage_hash(StorageHashDomainV1::BudgetPolicy, &input[..112]);
        if input[112..144] != digest {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        let mut bytes = [0_u8; BUDGET_POLICY_LEN];
        bytes.copy_from_slice(input);
        Ok(Self {
            bytes,
            profile,
            digest,
        })
    }

    /// Returns the exact canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; BUDGET_POLICY_LEN] {
        &self.bytes
    }

    /// Derives the evidence-profile variant of this exact policy.
    ///
    /// Every budget bound is preserved byte-for-byte; only the profile tag
    /// and the storage digest over it change, and the result is revalidated
    /// through [`Self::from_bytes`]. This exists solely for the F7 wallet
    /// composition, whose retained dual-custody journal is an evidence
    /// store: the composition's economic validations still require the
    /// caller's production-ratified policy before deriving this variant.
    pub fn evidence_profile_variant(&self) -> Result<Self, CanonicalCodecError> {
        let mut bytes = *self.as_bytes();
        bytes[10] = BudgetPolicyProfileV1::EvidenceOnly as u8;
        let digest = storage_hash(StorageHashDomainV1::BudgetPolicy, &bytes[..112]);
        bytes[112..144].copy_from_slice(&digest);
        Self::from_bytes(&bytes)
    }

    /// Returns the closed policy profile.
    pub const fn profile(&self) -> BudgetPolicyProfileV1 {
        self.profile
    }

    /// Returns the nonzero policy identifier.
    pub fn policy_id(&self) -> &[u8] {
        &self.bytes[16..48]
    }

    /// Returns the immutable policy digest.
    pub const fn policy_digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the policy effective time.
    pub fn effective_from_utc_seconds(&self) -> u64 {
        read_u64(&self.bytes[104..112])
    }

    /// Returns the lifetime global reservation limit.
    pub fn global_reservation_limit(&self) -> u64 {
        read_u64(&self.bytes[48..56])
    }

    /// Returns the lifetime per-counterparty reservation limit.
    pub fn counterparty_reservation_limit(&self) -> u64 {
        read_u64(&self.bytes[56..64])
    }

    /// Returns the maximum number of concurrently live reservations.
    pub fn concurrent_reservation_limit(&self) -> u32 {
        read_u32(&self.bytes[64..68])
    }

    /// Returns the global rolling-window reservation limit.
    pub fn rolling_window_reservation_limit(&self) -> u64 {
        read_u64(&self.bytes[72..80])
    }

    /// Returns the rolling-window width in seconds.
    pub fn rolling_window_seconds(&self) -> u64 {
        read_u64(&self.bytes[80..88])
    }

    /// Returns the largest accepted forward step of the trusted clock.
    pub fn maximum_forward_step_seconds(&self) -> u64 {
        read_u64(&self.bytes[88..96])
    }

    /// Returns the minimum authenticated history retention in seconds.
    pub fn history_retention_seconds(&self) -> u64 {
        read_u64(&self.bytes[96..104])
    }
}

/// Complete canonical two-participant reservation-context binding.
///
/// This type verifies the byte grammar, cross-field layout, and record digest.
/// It is not a substitute for the authoritative DOM point parser or the safe
/// signer's share/roster validation.
#[derive(Clone, Eq, PartialEq)]
pub struct ReservationContextBindingV1 {
    bytes: Vec<u8>,
    context_len: usize,
    purpose: PurposeV1,
    direction: DirectionV1,
    local_protocol_index: usize,
    digest: [u8; 32],
}

impl ReservationContextBindingV1 {
    /// Parses exact bytes and authenticates the reservation-context digest.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        if !matches!(
            input.len(),
            RESERVATION_CONTEXT_NO_ADAPTOR_LEN | RESERVATION_CONTEXT_ADAPTOR_LEN
        ) || &input[..8] != CONTEXT_MAGIC
            || read_u16(&input[8..10]) != 1
            || read_u16(&input[10..12]) != 0x0001
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let context_len = usize::try_from(read_u32(&input[12..16]))
            .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        if !matches!(context_len, 245 | 278)
            || input.len() != 254 + context_len
            || read_u16(&input[16 + context_len..18 + context_len]) != 2
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let context = &input[16..16 + context_len];
        let (purpose, direction, context_local_index) = parse_derivation_base_context(context)?;
        let roster = &input[18 + context_len..220 + context_len];
        let first = parse_protocol_roster_entry(&roster[..101])?;
        let second = parse_protocol_roster_entry(&roster[101..])?;
        if first.participant_id >= second.participant_id
            || first.g1a_index == second.g1a_index
            || !matches!((first.g1a_index, second.g1a_index), (0, 1) | (1, 0))
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let local_protocol_index =
            usize::from(read_u16(&input[220 + context_len..222 + context_len]));
        if local_protocol_index > 1 {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let local = if local_protocol_index == 0 {
            &first
        } else {
            &second
        };
        if usize::from(local.g1a_index) != context_local_index
            || local.direction != direction
            || !context_roster_matches_protocol(context, &first, &second)
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let digest_offset = 222 + context_len;
        let digest = storage_hash(
            StorageHashDomainV1::ReservationContext,
            &input[..digest_offset],
        );
        if input[digest_offset..] != digest {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: input.to_vec(),
            context_len,
            purpose,
            direction,
            local_protocol_index,
            digest,
        })
    }

    /// Returns the exact canonical bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the complete canonical derivation-base context bytes.
    pub fn derivation_base_context(&self) -> &[u8] {
        &self.bytes[16..16 + self.context_len]
    }

    /// Returns the exact strict Phase 1 purpose.
    pub const fn purpose(&self) -> PurposeV1 {
        self.purpose
    }

    /// Returns the stable local direction.
    pub const fn direction(&self) -> DirectionV1 {
        self.direction
    }

    /// Returns the local protocol-roster index.
    pub fn local_protocol_index(&self) -> u16 {
        if self.local_protocol_index == 0 {
            0
        } else {
            1
        }
    }

    /// Returns the context-binding digest.
    pub const fn context_binding_digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the trusted chain identifier encoded in the context.
    pub fn chain_id(&self) -> &[u8] {
        &self.bytes[18..50]
    }

    /// Returns the lifetime-unique session identifier.
    pub fn session_id(&self) -> &[u8] {
        &self.bytes[50..82]
    }

    /// Returns the template commitment.
    pub fn template_hash(&self) -> &[u8] {
        &self.bytes[86..118]
    }

    /// Returns the local participant identifier from the bound protocol roster.
    pub fn local_participant_id(&self) -> &[u8] {
        let start = 18 + self.context_len + self.local_protocol_index * 101;
        &self.bytes[start..start + 32]
    }

    /// Returns the remote participant identifier from the bound protocol roster.
    pub fn remote_participant_id(&self) -> &[u8] {
        let remote = 1 - self.local_protocol_index;
        let start = 18 + self.context_len + remote * 101;
        &self.bytes[start..start + 32]
    }

    /// Returns the local signing public key selected by the bound G1A index.
    pub fn local_signing_public_key(&self) -> &[u8] {
        let start = 18 + self.context_len + self.local_protocol_index * 101 + 65;
        &self.bytes[start..start + 33]
    }
}

/// Self-authenticated immutable bytes for one charged reservation.
///
/// This codec grants no live reservation handle or Store authority.
#[derive(Clone, Eq, PartialEq)]
pub struct ReservationAuthorityV1 {
    bytes: Vec<u8>,
    binding: ReservationContextBindingV1,
    bound_digest: [u8; 32],
    authority_digest: [u8; 32],
}

impl ReservationAuthorityV1 {
    /// Constructs one exact P1-004 reservation authority from its complete
    /// authenticated context binding and Store-owned assignments.
    ///
    /// Constructing record bytes grants neither a live handle nor storage
    /// authority; only the retained Store may persist this record after the
    /// complete collision and budget-admission scan.
    pub fn new(
        binding: &ReservationContextBindingV1,
        request_lookup: [u8; 32],
        reservation_id: [u8; 32],
        nonce_epoch: u64,
        policy: &BudgetPolicyV1,
    ) -> Result<Self, CanonicalCodecError> {
        let purpose = binding.purpose();
        purpose
            .require_strict_phase1()
            .map_err(|_| CanonicalCodecError::PurposeNotAuthorized)?;
        if is_zero(&reservation_id) || is_zero(&request_lookup) || nonce_epoch == 0 {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let key_id = storage_hash(
            StorageHashDomainV1::BudgetKey,
            &[binding.chain_id(), binding.local_signing_public_key()].concat(),
        );
        let counterparty = storage_hash(
            StorageHashDomainV1::Counterparty,
            &[binding.chain_id(), binding.remote_participant_id()].concat(),
        );
        let binding_len = u32::try_from(binding.as_bytes().len())
            .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        let complete_len = 351_usize
            .checked_add(binding.as_bytes().len())
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        let mut bytes = vec![0_u8; complete_len];
        bytes[..8].copy_from_slice(AUTHORITY_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..42].copy_from_slice(&reservation_id);
        bytes[42..74].copy_from_slice(&key_id);
        bytes[74..106].copy_from_slice(binding.session_id());
        bytes[106..138].copy_from_slice(&counterparty);
        bytes[138] = purpose.to_byte();
        bytes[139..171].copy_from_slice(binding.local_participant_id());
        bytes[171..203].copy_from_slice(binding.template_hash());
        bytes[203..235].copy_from_slice(&request_lookup);
        bytes[235..243].copy_from_slice(&nonce_epoch.to_le_bytes());
        bytes[243..275].copy_from_slice(policy.policy_digest());
        bytes[275..279].copy_from_slice(&binding_len.to_le_bytes());
        let bound_offset = 279 + binding.as_bytes().len();
        bytes[279..bound_offset].copy_from_slice(binding.as_bytes());
        let bound_digest = storage_hash(
            StorageHashDomainV1::ReservationBinding,
            &bytes[10..bound_offset],
        );
        bytes[bound_offset..bound_offset + 32].copy_from_slice(&bound_digest);
        let revision_offset = bound_offset + 32;
        bytes[revision_offset..revision_offset + 8].copy_from_slice(&1_u64.to_le_bytes());
        let authority_digest_offset = revision_offset + 8;
        let authority_digest = storage_hash(
            StorageHashDomainV1::ReservationAuthority,
            &bytes[..authority_digest_offset],
        );
        bytes[authority_digest_offset..].copy_from_slice(&authority_digest);
        Self::from_bytes(&bytes)
    }

    /// Parses exact signed NAR-DC-P1-004 authority bytes.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        if !matches!(
            input.len(),
            RESERVATION_AUTHORITY_NO_ADAPTOR_LEN | RESERVATION_AUTHORITY_ADAPTOR_LEN
        ) || &input[..8] != AUTHORITY_MAGIC
            || read_u16(&input[8..10]) != 1
            || is_zero(&input[10..42])
            || is_zero(&input[42..74])
            || is_zero(&input[74..106])
            || is_zero(&input[106..138])
            || is_zero(&input[139..171])
            || is_zero(&input[171..203])
            || is_zero(&input[203..235])
            || read_u64(&input[235..243]) == 0
            || is_zero(&input[243..275])
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let purpose =
            PurposeV1::try_from(input[138]).map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        purpose
            .require_strict_phase1()
            .map_err(|_| CanonicalCodecError::PurposeNotAuthorized)?;
        let binding_len = usize::try_from(read_u32(&input[275..279]))
            .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        if !matches!(
            binding_len,
            RESERVATION_CONTEXT_NO_ADAPTOR_LEN | RESERVATION_CONTEXT_ADAPTOR_LEN
        ) || input.len() != 351 + binding_len
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let binding = ReservationContextBindingV1::from_bytes(&input[279..279 + binding_len])?;
        let bound_offset = 279 + binding_len;
        let revision_offset = bound_offset + 32;
        let authority_digest_offset = revision_offset + 8;
        if read_u64(&input[revision_offset..authority_digest_offset]) != 1
            || purpose != binding.purpose()
            || input[74..106] != *binding.session_id()
            || input[139..171] != *binding.local_participant_id()
            || input[171..203] != *binding.template_hash()
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let expected_key = storage_hash(
            StorageHashDomainV1::BudgetKey,
            &[binding.chain_id(), binding.local_signing_public_key()].concat(),
        );
        let expected_counterparty = storage_hash(
            StorageHashDomainV1::Counterparty,
            &[binding.chain_id(), binding.remote_participant_id()].concat(),
        );
        if input[42..74] != expected_key || input[106..138] != expected_counterparty {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        let bound_digest = storage_hash(
            StorageHashDomainV1::ReservationBinding,
            &input[10..bound_offset],
        );
        let authority_digest = storage_hash(
            StorageHashDomainV1::ReservationAuthority,
            &input[..authority_digest_offset],
        );
        if input[bound_offset..revision_offset] != bound_digest
            || input[authority_digest_offset..] != authority_digest
        {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: input.to_vec(),
            binding,
            bound_digest,
            authority_digest,
        })
    }

    /// Returns the exact canonical authority bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the embedded complete reservation-context binding.
    pub const fn context_binding(&self) -> &ReservationContextBindingV1 {
        &self.binding
    }

    /// Returns the exact reservation identifier.
    pub fn reservation_id(&self) -> &[u8] {
        &self.bytes[10..42]
    }

    /// Returns the lifetime-unique session identifier.
    pub fn session_id(&self) -> &[u8] {
        &self.bytes[74..106]
    }

    /// Returns the canonical local signing-key budget identifier.
    pub fn budget_key_id(&self) -> &[u8] {
        &self.bytes[42..74]
    }

    /// Returns the canonical remote-counterparty budget identifier.
    pub fn counterparty_id(&self) -> &[u8] {
        &self.bytes[106..138]
    }

    /// Returns the strict Phase 1 purpose.
    pub const fn purpose(&self) -> PurposeV1 {
        self.binding.purpose()
    }

    /// Returns the local protocol participant identifier.
    pub fn participant_id(&self) -> &[u8] {
        &self.bytes[139..171]
    }

    /// Returns the distinct nonzero request/idempotency lookup identifier.
    ///
    /// This public collision-lookup value is not a permit, capability,
    /// receipt, or storage authority.
    pub fn request_lookup_id(&self) -> &[u8] {
        &self.bytes[203..235]
    }

    /// Returns the active nonzero nonce epoch.
    pub fn nonce_epoch(&self) -> u64 {
        read_u64(&self.bytes[235..243])
    }

    /// Returns the immutable budget-policy digest.
    pub fn budget_policy_digest(&self) -> &[u8] {
        &self.bytes[243..275]
    }

    /// Returns the identity-binding digest.
    pub const fn bound_digest(&self) -> &[u8; 32] {
        &self.bound_digest
    }

    /// Returns the record digest.
    pub const fn authority_digest(&self) -> &[u8; 32] {
        &self.authority_digest
    }

    /// Reconstructs the canonical nonce identity bound by this authority.
    pub fn nonce_identity(&self) -> Result<super::NonceIdentityV1, CanonicalCodecError> {
        let mut session_id = [0_u8; 32];
        session_id.copy_from_slice(self.session_id());
        let mut participant_id = [0_u8; 32];
        participant_id.copy_from_slice(self.participant_id());
        super::NonceIdentityV1::new(
            session_id,
            participant_id,
            self.purpose(),
            self.bound_digest,
            self.nonce_epoch(),
        )
    }
}

/// Self-authenticated append-only budget charge.
///
/// The caller must separately authenticate the selected `BudgetPolicyV1` and
/// journal ancestry before using this record for admission.
#[derive(Clone, Eq, PartialEq)]
pub struct BudgetChargeV1 {
    bytes: Vec<u8>,
    authority: ReservationAuthorityV1,
    digest: [u8; 32],
}

impl BudgetChargeV1 {
    /// Constructs one exact P1-004 append-only budget charge.
    ///
    /// The Store has already selected a policy and committed to the planned
    /// Reserve journal sequence before invoking this crate-visible helper.
    pub fn new(
        authority: &ReservationAuthorityV1,
        charged_at_utc_seconds: u64,
        reserve_journal_sequence: u64,
        policy: &BudgetPolicyV1,
    ) -> Result<Self, CanonicalCodecError> {
        if charged_at_utc_seconds == 0
            || charged_at_utc_seconds < policy.effective_from_utc_seconds()
            || reserve_journal_sequence == 0
            || authority.budget_policy_digest() != policy.policy_digest()
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let complete_len = 66_usize
            .checked_add(authority.as_bytes().len())
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        let mut bytes = vec![0_u8; complete_len];
        bytes[..8].copy_from_slice(CHARGE_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        let charged_offset = 10 + authority.as_bytes().len();
        bytes[10..charged_offset].copy_from_slice(authority.as_bytes());
        bytes[charged_offset..charged_offset + 8]
            .copy_from_slice(&charged_at_utc_seconds.to_le_bytes());
        bytes[charged_offset + 8..charged_offset + 16]
            .copy_from_slice(&reserve_journal_sequence.to_le_bytes());
        bytes[charged_offset + 16..charged_offset + 24].copy_from_slice(&1_u64.to_le_bytes());
        let digest_offset = charged_offset + 24;
        let digest = storage_hash(StorageHashDomainV1::BudgetCharge, &bytes[..digest_offset]);
        bytes[digest_offset..].copy_from_slice(&digest);
        let charge = Self::from_bytes(&bytes)?;
        charge.validate_policy(policy)?;
        Ok(charge)
    }

    /// Parses exact charge bytes and authenticates the embedded authority.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        if !matches!(
            input.len(),
            BUDGET_CHARGE_NO_ADAPTOR_LEN | BUDGET_CHARGE_ADAPTOR_LEN
        ) || &input[..8] != CHARGE_MAGIC
            || read_u16(&input[8..10]) != 1
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let authority_len = input.len() - 66;
        let authority = ReservationAuthorityV1::from_bytes(&input[10..10 + authority_len])?;
        let charged_offset = 10 + authority_len;
        let sequence_offset = charged_offset + 8;
        let revision_offset = sequence_offset + 8;
        let digest_offset = revision_offset + 8;
        if read_u64(&input[charged_offset..sequence_offset]) == 0
            || read_u64(&input[sequence_offset..revision_offset]) == 0
            || read_u64(&input[revision_offset..digest_offset]) != 1
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let digest = storage_hash(StorageHashDomainV1::BudgetCharge, &input[..digest_offset]);
        if input[digest_offset..] != digest {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: input.to_vec(),
            authority,
            digest,
        })
    }

    /// Returns the exact canonical bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the embedded reservation authority.
    pub const fn reservation_authority(&self) -> &ReservationAuthorityV1 {
        &self.authority
    }

    /// Returns the nonzero charge timestamp.
    pub fn charged_at_utc_seconds(&self) -> u64 {
        read_u64(&self.bytes[10 + self.authority.as_bytes().len()..])
    }

    /// Returns the original nonzero Reserve journal sequence.
    pub fn reserve_journal_sequence(&self) -> u64 {
        read_u64(&self.bytes[18 + self.authority.as_bytes().len()..])
    }

    /// Returns the charge digest.
    pub const fn charge_digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Cross-checks this charge against separately authenticated policy bytes.
    pub fn validate_policy(&self, policy: &BudgetPolicyV1) -> Result<(), CanonicalCodecError> {
        if self.authority.budget_policy_digest() != policy.policy_digest()
            || self.charged_at_utc_seconds() < policy.effective_from_utc_seconds()
        {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(())
    }
}

/// Exact authenticated derivation attempt plus final effective retry counter.
///
/// This public record is evidence only and does not authorize a computation or
/// secret open.
#[derive(Clone, Eq, PartialEq)]
pub struct NonceDerivationAttemptV1 {
    bytes: [u8; NONCE_DERIVATION_ATTEMPT_LEN],
    attempt: AttemptRecordV1,
    effective_retry_counter: u64,
}

impl NonceDerivationAttemptV1 {
    /// Constructs the exact P1-004 derivation wrapper from an authenticated
    /// commitment attempt and the final signer-owned retry counter.
    ///
    /// This constructor is crate-private because durable Store authority must
    /// establish the attempt ordering before these bytes are persisted.
    pub(crate) fn new(
        attempt: &AttemptRecordV1,
        effective_retry_counter: u64,
    ) -> Result<Self, CanonicalCodecError> {
        if attempt.phase() != SigningPhaseV1::SigNonceCommit
            || attempt.artifact() != ArtifactKindV1::Commitment
        {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        let mut bytes = [0_u8; NONCE_DERIVATION_ATTEMPT_LEN];
        bytes[..ATTEMPT_RECORD_LEN].copy_from_slice(attempt.as_bytes());
        bytes[ATTEMPT_RECORD_LEN..].copy_from_slice(&effective_retry_counter.to_le_bytes());
        Self::from_bytes(&bytes)
    }

    /// Parses exact derivation-wrapper bytes and authenticates the inner attempt.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedNonceDerivationAttemptV1::parse_structural(input)?;
        let attempt = AttemptRecordV1::from_bytes(structural.attempt().as_bytes())?;
        let effective_retry_counter = structural.effective_retry_counter();
        let mut bytes = [0_u8; NONCE_DERIVATION_ATTEMPT_LEN];
        bytes.copy_from_slice(input);
        Ok(Self {
            bytes,
            attempt,
            effective_retry_counter,
        })
    }

    /// Returns the exact wrapper bytes.
    pub const fn as_bytes(&self) -> &[u8; NONCE_DERIVATION_ATTEMPT_LEN] {
        &self.bytes
    }

    /// Returns the authenticated inner attempt.
    pub const fn attempt(&self) -> &AttemptRecordV1 {
        &self.attempt
    }

    /// Returns the final signer-owned retry counter.
    pub const fn effective_retry_counter(&self) -> u64 {
        self.effective_retry_counter
    }
}

/// Structurally parsed derivation attempt that retains an unauthenticated inner digest.
pub struct UnauthenticatedNonceDerivationAttemptV1 {
    bytes: [u8; NONCE_DERIVATION_ATTEMPT_LEN],
    attempt: UnauthenticatedAttemptRecordV1,
    effective_retry_counter: u64,
}

impl UnauthenticatedNonceDerivationAttemptV1 {
    /// Parses exact wrapper bytes without granting computation authority.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        if input.len() != NONCE_DERIVATION_ATTEMPT_LEN {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let attempt =
            UnauthenticatedAttemptRecordV1::parse_structural(&input[..ATTEMPT_RECORD_LEN])?;
        if attempt.phase() != SigningPhaseV1::SigNonceCommit
            || attempt.artifact() != ArtifactKindV1::Commitment
        {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        let effective_retry_counter = read_u64(&input[ATTEMPT_RECORD_LEN..]);
        let mut bytes = [0_u8; NONCE_DERIVATION_ATTEMPT_LEN];
        bytes.copy_from_slice(input);
        Ok(Self {
            bytes,
            attempt,
            effective_retry_counter,
        })
    }

    /// Returns the exact unauthenticated wrapper bytes.
    pub const fn as_bytes(&self) -> &[u8; NONCE_DERIVATION_ATTEMPT_LEN] {
        &self.bytes
    }

    /// Returns the structurally parsed inner attempt.
    pub const fn attempt(&self) -> &UnauthenticatedAttemptRecordV1 {
        &self.attempt
    }

    /// Returns the appended signer-owned retry counter.
    pub const fn effective_retry_counter(&self) -> u64 {
        self.effective_retry_counter
    }
}

struct ProtocolRosterEntry<'a> {
    participant_id: &'a [u8],
    signing_key: &'a [u8],
    direction: DirectionV1,
    g1a_index: u16,
}

fn parse_protocol_roster_entry(
    input: &[u8],
) -> Result<ProtocolRosterEntry<'_>, CanonicalCodecError> {
    if input.len() != 101
        || is_zero(&input[..32])
        || !compressed_point_shape(&input[32..65])
        || !compressed_point_shape(&input[65..98])
    {
        return Err(CanonicalCodecError::InvalidEncoding);
    }
    let direction =
        DirectionV1::try_from(input[98]).map_err(|_| CanonicalCodecError::InvalidEncoding)?;
    let g1a_index = read_u16(&input[99..101]);
    if g1a_index > 1 {
        return Err(CanonicalCodecError::InvalidEncoding);
    }
    Ok(ProtocolRosterEntry {
        participant_id: &input[..32],
        signing_key: &input[65..98],
        direction,
        g1a_index,
    })
}

fn parse_derivation_base_context(
    context: &[u8],
) -> Result<(PurposeV1, DirectionV1, usize), CanonicalCodecError> {
    if !matches!(context.len(), 245 | 278)
        || read_u16(&context[..2]) != 1
        || is_zero(&context[2..34])
        || is_zero(&context[34..66])
        || read_u16(&context[68..70]) != SigningPhaseV1::SigNonceCommit as u16
        || read_u64(&context[166..174]) != 0
        || read_u16(&context[174..176]) != 2
        || !compressed_point_shape(&context[176..209])
        || !compressed_point_shape(&context[209..242])
        || context[176..209] >= context[209..242]
    {
        return Err(CanonicalCodecError::InvalidEncoding);
    }
    let purpose =
        PurposeV1::try_from(context[66]).map_err(|_| CanonicalCodecError::InvalidEncoding)?;
    purpose
        .require_strict_phase1()
        .map_err(|_| CanonicalCodecError::PurposeNotAuthorized)?;
    let direction =
        DirectionV1::try_from(context[67]).map_err(|_| CanonicalCodecError::InvalidEncoding)?;
    let local_index = usize::from(read_u16(&context[242..244]));
    if local_index > 1 {
        return Err(CanonicalCodecError::InvalidEncoding);
    }
    match (purpose, context[244], context.len()) {
        (PurposeV1::ClaimAdaptor, 1, 278) if compressed_point_shape(&context[245..278]) => {}
        (PurposeV1::Refund | PurposeV1::Funding, 0, 245) => {}
        _ => return Err(CanonicalCodecError::InvalidEncoding),
    }
    Ok((purpose, direction, local_index))
}

fn context_roster_matches_protocol(
    context: &[u8],
    first: &ProtocolRosterEntry<'_>,
    second: &ProtocolRosterEntry<'_>,
) -> bool {
    let protocol = [first, second];
    protocol.iter().all(|entry| {
        let start = 176 + usize::from(entry.g1a_index) * 33;
        &context[start..start + 33] == entry.signing_key
    })
}

fn compressed_point_shape(input: &[u8]) -> bool {
    input.len() == 33 && matches!(input[0], 0x02 | 0x03) && !is_zero(&input[1..])
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const G: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    const TWO_G: [u8; 33] = [
        0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0,
        0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c,
        0x70, 0x9e, 0xe5,
    ];

    fn policy() -> [u8; BUDGET_POLICY_LEN] {
        let mut bytes = [0_u8; BUDGET_POLICY_LEN];
        bytes[..8].copy_from_slice(POLICY_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10] = BudgetPolicyProfileV1::EvidenceOnly as u8;
        bytes[11] = 1;
        bytes[16..48].fill(1);
        bytes[48..56].copy_from_slice(&10_u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&9_u64.to_le_bytes());
        bytes[64..68].copy_from_slice(&2_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&8_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&60_u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&30_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&1_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&100_u64.to_le_bytes());
        let digest = storage_hash(StorageHashDomainV1::BudgetPolicy, &bytes[..112]);
        bytes[112..].copy_from_slice(&digest);
        bytes
    }

    fn binding(purpose: PurposeV1) -> Vec<u8> {
        binding_with_session(purpose, 2)
    }

    fn binding_with_session(purpose: PurposeV1, session_byte: u8) -> Vec<u8> {
        let with_adaptor = purpose == PurposeV1::ClaimAdaptor;
        let context_len = 245 + usize::from(with_adaptor) * 33;
        let total = 254 + context_len;
        let mut bytes = vec![0_u8; total];
        bytes[..8].copy_from_slice(CONTEXT_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&1_u16.to_le_bytes());
        bytes[12..16].copy_from_slice(&(context_len as u32).to_le_bytes());
        let context = &mut bytes[16..16 + context_len];
        context[..2].copy_from_slice(&1_u16.to_le_bytes());
        context[2..34].fill(1);
        context[34..66].fill(session_byte);
        context[66] = purpose.to_byte();
        context[67] = DirectionV1::Initiator as u8;
        context[68..70].copy_from_slice(&(SigningPhaseV1::SigNonceCommit as u16).to_le_bytes());
        context[70..102].fill(3);
        context[102..134].fill(4);
        context[134..166].fill(5);
        context[174..176].copy_from_slice(&2_u16.to_le_bytes());
        context[176..209].copy_from_slice(&G);
        context[209..242].copy_from_slice(&TWO_G);
        if with_adaptor {
            context[244] = 1;
            context[245..278].copy_from_slice(&G);
        }
        bytes[16 + context_len..18 + context_len].copy_from_slice(&2_u16.to_le_bytes());
        let roster = 18 + context_len;
        bytes[roster..roster + 32].fill(0x11);
        bytes[roster + 32..roster + 65].copy_from_slice(&G);
        bytes[roster + 65..roster + 98].copy_from_slice(&G);
        bytes[roster + 98] = DirectionV1::Initiator as u8;
        bytes[roster + 99..roster + 101].copy_from_slice(&0_u16.to_le_bytes());
        let second = roster + 101;
        bytes[second..second + 32].fill(0x22);
        bytes[second + 32..second + 65].copy_from_slice(&TWO_G);
        bytes[second + 65..second + 98].copy_from_slice(&TWO_G);
        bytes[second + 98] = DirectionV1::Responder as u8;
        bytes[second + 99..second + 101].copy_from_slice(&1_u16.to_le_bytes());
        let digest_offset = 222 + context_len;
        let digest = storage_hash(
            StorageHashDomainV1::ReservationContext,
            &bytes[..digest_offset],
        );
        bytes[digest_offset..].copy_from_slice(&digest);
        bytes
    }

    fn authority(purpose: PurposeV1) -> Result<Vec<u8>, CanonicalCodecError> {
        authority_with_ids(purpose, 1, 2)
    }

    fn authority_with_ids(
        purpose: PurposeV1,
        reservation_byte: u8,
        session_byte: u8,
    ) -> Result<Vec<u8>, CanonicalCodecError> {
        let binding = binding_with_session(purpose, session_byte);
        let total = 351 + binding.len();
        let mut bytes = vec![0_u8; total];
        bytes[..8].copy_from_slice(AUTHORITY_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..42].fill(reservation_byte);
        let parsed_binding = ReservationContextBindingV1::from_bytes(&binding)?;
        let key = storage_hash(
            StorageHashDomainV1::BudgetKey,
            &[
                parsed_binding.chain_id(),
                parsed_binding.local_signing_public_key(),
            ]
            .concat(),
        );
        bytes[42..74].copy_from_slice(&key);
        bytes[74..106].copy_from_slice(parsed_binding.session_id());
        let counterparty = storage_hash(
            StorageHashDomainV1::Counterparty,
            &[
                parsed_binding.chain_id(),
                parsed_binding.remote_participant_id(),
            ]
            .concat(),
        );
        bytes[106..138].copy_from_slice(&counterparty);
        bytes[138] = purpose.to_byte();
        bytes[139..171].copy_from_slice(parsed_binding.local_participant_id());
        bytes[171..203].copy_from_slice(parsed_binding.template_hash());
        bytes[203..235].fill(6);
        bytes[235..243].copy_from_slice(&1_u64.to_le_bytes());
        bytes[243..275].copy_from_slice(&policy()[112..]);
        bytes[275..279].copy_from_slice(&(binding.len() as u32).to_le_bytes());
        bytes[279..279 + binding.len()].copy_from_slice(&binding);
        let bound_offset = 279 + binding.len();
        let bound = storage_hash(
            StorageHashDomainV1::ReservationBinding,
            &bytes[10..bound_offset],
        );
        bytes[bound_offset..bound_offset + 32].copy_from_slice(&bound);
        bytes[bound_offset + 32..bound_offset + 40].copy_from_slice(&1_u64.to_le_bytes());
        let digest = storage_hash(
            StorageHashDomainV1::ReservationAuthority,
            &bytes[..bound_offset + 40],
        );
        bytes[bound_offset + 40..].copy_from_slice(&digest);
        Ok(bytes)
    }

    fn charge_for_sequence(
        purpose: PurposeV1,
        reserve_sequence: u64,
    ) -> Result<Vec<u8>, CanonicalCodecError> {
        charge_for_ids(purpose, reserve_sequence, 1, 2)
    }

    fn charge_for_ids(
        purpose: PurposeV1,
        reserve_sequence: u64,
        reservation_byte: u8,
        session_byte: u8,
    ) -> Result<Vec<u8>, CanonicalCodecError> {
        let authority = authority_with_ids(purpose, reservation_byte, session_byte)?;
        let mut bytes = vec![0_u8; 66 + authority.len()];
        bytes[..8].copy_from_slice(CHARGE_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..10 + authority.len()].copy_from_slice(&authority);
        let offset = 10 + authority.len();
        bytes[offset..offset + 8].copy_from_slice(&100_u64.to_le_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&reserve_sequence.to_le_bytes());
        bytes[offset + 16..offset + 24].copy_from_slice(&1_u64.to_le_bytes());
        let digest = storage_hash(StorageHashDomainV1::BudgetCharge, &bytes[..offset + 24]);
        bytes[offset + 24..].copy_from_slice(&digest);
        Ok(bytes)
    }

    fn charge(purpose: PurposeV1) -> Result<Vec<u8>, CanonicalCodecError> {
        charge_for_sequence(purpose, 7)
    }

    pub(crate) fn reserve_records(
        purpose: PurposeV1,
        reserve_sequence: u64,
    ) -> Result<(super::super::SessionClaimV1, BudgetChargeV1), CanonicalCodecError> {
        let charge = BudgetChargeV1::from_bytes(&charge_for_sequence(purpose, reserve_sequence)?)?;
        let identity = charge.reservation_authority().nonce_identity()?;
        let claim = super::super::SessionClaimV1::new(identity)?;
        Ok((claim, charge))
    }

    pub(crate) fn reserve_records_with_ids(
        purpose: PurposeV1,
        reserve_sequence: u64,
        reservation_byte: u8,
        session_byte: u8,
    ) -> Result<(super::super::SessionClaimV1, BudgetChargeV1), CanonicalCodecError> {
        let charge = BudgetChargeV1::from_bytes(&charge_for_ids(
            purpose,
            reserve_sequence,
            reservation_byte,
            session_byte,
        )?)?;
        let identity = charge.reservation_authority().nonce_identity()?;
        let claim = super::super::SessionClaimV1::new(identity)?;
        Ok((claim, charge))
    }

    #[test]
    fn all_variable_records_roundtrip_both_exact_lengths() -> Result<(), CanonicalCodecError> {
        for purpose in [
            PurposeV1::Refund,
            PurposeV1::Funding,
            PurposeV1::ClaimAdaptor,
        ] {
            let binding = ReservationContextBindingV1::from_bytes(&binding(purpose))?;
            let authority = ReservationAuthorityV1::from_bytes(&authority(purpose)?)?;
            let charge = BudgetChargeV1::from_bytes(&charge(purpose)?)?;
            charge.validate_policy(&BudgetPolicyV1::from_bytes(&policy())?)?;
            assert_eq!(binding.purpose(), purpose);
            assert!(authority.context_binding() == &binding);
            assert!(charge.reservation_authority() == &authority);
        }
        Ok(())
    }

    #[test]
    fn trusted_constructors_match_the_authenticated_canonical_layout(
    ) -> Result<(), CanonicalCodecError> {
        let purpose = PurposeV1::Funding;
        let binding = ReservationContextBindingV1::from_bytes(&binding(purpose))?;
        let policy = BudgetPolicyV1::from_bytes(&policy())?;
        let constructed_authority =
            ReservationAuthorityV1::new(&binding, [6; 32], [1; 32], 1, &policy)?;
        assert_eq!(
            constructed_authority.as_bytes(),
            authority(purpose)?.as_slice()
        );

        let constructed_charge = BudgetChargeV1::new(&constructed_authority, 100, 7, &policy)?;
        assert_eq!(constructed_charge.as_bytes(), charge(purpose)?.as_slice());
        Ok(())
    }

    #[test]
    fn every_record_rejects_all_truncations_and_trailing_bytes() -> Result<(), CanonicalCodecError>
    {
        type ParseCheck = fn(&[u8]) -> bool;
        let records: Vec<(Vec<u8>, ParseCheck)> = vec![
            (policy().to_vec(), |bytes| {
                BudgetPolicyV1::from_bytes(bytes).is_ok()
            }),
            (binding(PurposeV1::Funding), |bytes| {
                ReservationContextBindingV1::from_bytes(bytes).is_ok()
            }),
            (authority(PurposeV1::Funding)?, |bytes| {
                ReservationAuthorityV1::from_bytes(bytes).is_ok()
            }),
            (charge(PurposeV1::Funding)?, |bytes| {
                BudgetChargeV1::from_bytes(bytes).is_ok()
            }),
        ];
        for (record, parse) in records {
            for end in 0..record.len() {
                assert!(!parse(&record[..end]), "accepted truncation {end}");
            }
            let mut trailing = record;
            trailing.push(0);
            assert!(!parse(&trailing));
        }
        Ok(())
    }

    #[test]
    fn mutation_of_every_authenticated_byte_fails() -> Result<(), CanonicalCodecError> {
        for record in [
            policy().to_vec(),
            binding(PurposeV1::Funding),
            authority(PurposeV1::Funding)?,
            charge(PurposeV1::Funding)?,
        ] {
            for index in 0..record.len() {
                let mut mutated = record.clone();
                mutated[index] ^= 1;
                let accepted = match record.len() {
                    BUDGET_POLICY_LEN => BudgetPolicyV1::from_bytes(&mutated).is_ok(),
                    RESERVATION_CONTEXT_NO_ADAPTOR_LEN => {
                        ReservationContextBindingV1::from_bytes(&mutated).is_ok()
                    }
                    RESERVATION_AUTHORITY_NO_ADAPTOR_LEN => {
                        ReservationAuthorityV1::from_bytes(&mutated).is_ok()
                    }
                    BUDGET_CHARGE_NO_ADAPTOR_LEN => BudgetChargeV1::from_bytes(&mutated).is_ok(),
                    _ => true,
                };
                assert!(!accepted, "accepted mutation at {index}");
            }
        }
        Ok(())
    }

    #[test]
    fn nonce_derivation_wrapper_is_exact_and_authenticates_its_inner_attempt(
    ) -> Result<(), CanonicalCodecError> {
        let (claim, _) = reserve_records(PurposeV1::Funding, 1)?;
        let attempt = AttemptRecordV1::new(
            *claim.identity(),
            1,
            SigningPhaseV1::SigNonceCommit,
            [0x91; 32],
        )?;
        let constructed = NonceDerivationAttemptV1::new(&attempt, 7)?;
        let bytes = *constructed.as_bytes();

        let structural = UnauthenticatedNonceDerivationAttemptV1::parse_structural(&bytes)?;
        let authenticated = NonceDerivationAttemptV1::from_bytes(&bytes)?;
        assert_eq!(constructed.as_bytes(), authenticated.as_bytes());
        assert_eq!(structural.effective_retry_counter(), 7);
        assert_eq!(authenticated.effective_retry_counter(), 7);
        assert!(authenticated.attempt().as_bytes() == attempt.as_bytes());

        for end in 0..bytes.len() {
            assert!(
                UnauthenticatedNonceDerivationAttemptV1::parse_structural(&bytes[..end]).is_err(),
                "accepted derivation truncation {end}"
            );
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(UnauthenticatedNonceDerivationAttemptV1::parse_structural(&trailing).is_err());

        let mut mutated_digest = bytes;
        mutated_digest[ATTEMPT_RECORD_LEN - 1] ^= 1;
        assert!(NonceDerivationAttemptV1::from_bytes(&mutated_digest).is_err());

        let mut later_stage = bytes;
        later_stage[123..125]
            .copy_from_slice(&(SigningPhaseV1::SigNonceReveal as u16).to_le_bytes());
        later_stage[125] = ArtifactKindV1::Reveal as u8;
        assert!(UnauthenticatedNonceDerivationAttemptV1::parse_structural(&later_stage).is_err());

        let reveal_attempt = AttemptRecordV1::new(
            *claim.identity(),
            4,
            SigningPhaseV1::SigNonceReveal,
            [0x92; 32],
        )?;
        assert!(NonceDerivationAttemptV1::new(&reveal_attempt, 7).is_err());
        Ok(())
    }
}
