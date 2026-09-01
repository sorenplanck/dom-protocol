//! Structural codecs for canonical restore records and payloads.

use super::{
    exact, is_zero, parse_nonce_identity, read_u16, read_u32, read_u64, storage_hash,
    ArtifactKindV1, AttemptRecordV1, CanonicalCodecError, ExposureRecordV1, ExposureStateV1,
    NonceDerivationAttemptV1, NonceIdentityV1, SessionClaimV1, StorageHashDomainV1,
    TerminalReasonV1, TombstoneV1,
};

const RESTORE_MANIFEST_MAGIC: &[u8; 8] = b"DOMNVRT1";
const RESTORE_COMPLETE_MAGIC: &[u8; 8] = b"DOMNVRC1";

/// Exact encoded size of `RestoreManifestV1`.
pub const RESTORE_MANIFEST_LEN: usize = 262;
/// Exact encoded size of `RestoreCompleteV1`.
pub const RESTORE_COMPLETE_LEN: usize = 98;
/// Exact encoded size of `RestoreRecordPayloadV1`.
pub const RESTORE_RECORD_PAYLOAD_LEN: usize = 220;
/// Exact encoded size of `EpochAdvancePayloadV1`.
pub const EPOCH_ADVANCE_PAYLOAD_LEN: usize = 176;
/// Exact encoded size of `RestoreRecordKeyV1`.
pub const RESTORE_RECORD_KEY_LEN: usize = 155;
/// Fixed key-and-length prefix of one canonical restore-record-set item.
pub const RESTORE_RECORD_ITEM_PREFIX_LEN: usize = RESTORE_RECORD_KEY_LEN + 4;
/// Exact minimum byte length of a canonical record set, containing only its count.
pub const RESTORE_RECORD_SET_MIN_LEN: usize = 4;

/// Store-validated policy limits applied before record-set allocation or copying.
///
/// Values originate from the retained Store's authenticated backup policy;
/// encoded bytes never select or enlarge these limits.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RestoreRecordSetLimitsV1 {
    max_record_count: u32,
    max_encoded_bytes: usize,
}

impl RestoreRecordSetLimitsV1 {
    /// Captures already adjudicated policy limits without choosing a default.
    pub(crate) fn new(
        max_record_count: u32,
        max_encoded_bytes: usize,
    ) -> Result<Self, CanonicalCodecError> {
        if max_encoded_bytes < RESTORE_RECORD_SET_MIN_LEN {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            max_record_count,
            max_encoded_bytes,
        })
    }

    fn validate_prefix(
        &self,
        record_count: u32,
        encoded_bytes: usize,
    ) -> Result<(), CanonicalCodecError> {
        if record_count > self.max_record_count || encoded_bytes > self.max_encoded_bytes {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(())
    }
}

/// Authenticated canonical restore transaction manifest.
#[derive(Clone, Eq, PartialEq)]
pub struct RestoreManifestV1 {
    bytes: [u8; RESTORE_MANIFEST_LEN],
    digest: [u8; 32],
}

impl RestoreManifestV1 {
    /// Constructs the existing-device restore manifest.
    #[cfg(any(test, feature = "evidence-only"))]
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
    )]
    pub fn new_existing_device(
        restore_transaction_id: [u8; 16],
        contract_wallet_id: [u8; 32],
        target_vault_id: [u8; 32],
        target_epoch: u64,
        target_journal_sequence: u64,
        target_journal_head_digest: [u8; 32],
        source_vault_id: [u8; 32],
        source_epoch: u64,
        source_journal_sequence: u64,
        source_journal_head_digest: [u8; 32],
        source_record_count: u32,
        source_record_set_digest: [u8; 32],
    ) -> Result<Self, CanonicalCodecError> {
        Self::construct(
            restore_transaction_id,
            contract_wallet_id,
            target_vault_id,
            target_epoch,
            target_journal_sequence,
            target_journal_head_digest,
            source_vault_id,
            source_epoch,
            source_journal_sequence,
            source_journal_head_digest,
            source_record_count,
            source_record_set_digest,
        )
    }

    /// Constructs the exact new-device target-sentinel manifest.
    #[cfg(any(test, feature = "evidence-only"))]
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
    )]
    pub fn new_restore_only(
        restore_transaction_id: [u8; 16],
        contract_wallet_id: [u8; 32],
        source_vault_id: [u8; 32],
        source_epoch: u64,
        source_journal_sequence: u64,
        source_journal_head_digest: [u8; 32],
        source_record_count: u32,
        source_record_set_digest: [u8; 32],
    ) -> Result<Self, CanonicalCodecError> {
        Self::construct(
            restore_transaction_id,
            contract_wallet_id,
            [0; 32],
            0,
            0,
            [0; 32],
            source_vault_id,
            source_epoch,
            source_journal_sequence,
            source_journal_head_digest,
            source_record_count,
            source_record_set_digest,
        )
    }

    #[cfg(any(test, feature = "evidence-only"))]
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
    )]
    fn construct(
        restore_transaction_id: [u8; 16],
        contract_wallet_id: [u8; 32],
        target_vault_id: [u8; 32],
        target_epoch: u64,
        target_journal_sequence: u64,
        target_journal_head_digest: [u8; 32],
        source_vault_id: [u8; 32],
        source_epoch: u64,
        source_journal_sequence: u64,
        source_journal_head_digest: [u8; 32],
        source_record_count: u32,
        source_record_set_digest: [u8; 32],
    ) -> Result<Self, CanonicalCodecError> {
        let successor_epoch = target_epoch
            .max(source_epoch)
            .checked_add(1)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        let mut bytes = [0_u8; RESTORE_MANIFEST_LEN];
        bytes[..8].copy_from_slice(RESTORE_MANIFEST_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..26].copy_from_slice(&restore_transaction_id);
        bytes[26..58].copy_from_slice(&contract_wallet_id);
        bytes[58..90].copy_from_slice(&target_vault_id);
        bytes[90..98].copy_from_slice(&target_epoch.to_le_bytes());
        bytes[98..106].copy_from_slice(&target_journal_sequence.to_le_bytes());
        bytes[106..138].copy_from_slice(&target_journal_head_digest);
        bytes[138..170].copy_from_slice(&source_vault_id);
        bytes[170..178].copy_from_slice(&source_epoch.to_le_bytes());
        bytes[178..186].copy_from_slice(&source_journal_sequence.to_le_bytes());
        bytes[186..218].copy_from_slice(&source_journal_head_digest);
        bytes[218..226].copy_from_slice(&successor_epoch.to_le_bytes());
        bytes[226..230].copy_from_slice(&source_record_count.to_le_bytes());
        bytes[230..262].copy_from_slice(&source_record_set_digest);
        Self::from_bytes(&bytes)
    }

    /// Parses exact bytes and computes the full registered manifest digest.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedRestoreManifestV1::parse_structural(input)?;
        let digest = storage_hash(StorageHashDomainV1::RestoreManifest, input);
        Ok(Self {
            bytes: *structural.as_bytes(),
            digest,
        })
    }

    /// Returns exact canonical manifest bytes.
    pub const fn as_bytes(&self) -> &[u8; RESTORE_MANIFEST_LEN] {
        &self.bytes
    }

    /// Returns the complete registered manifest digest.
    pub const fn manifest_digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the restore transaction identifier.
    pub fn restore_transaction_id(&self) -> &[u8] {
        &self.bytes[10..26]
    }

    /// Returns whether the target is the exact restore-only sentinel.
    pub fn is_new_device_target(&self) -> bool {
        is_zero(&self.bytes[58..90])
    }

    /// Returns the exact successor epoch.
    pub fn successor_epoch(&self) -> u64 {
        read_u64(&self.bytes[218..226])
    }

    /// Returns the authenticated stable Contracts wallet identifier.
    pub fn contract_wallet_id(&self) -> &[u8] {
        &self.bytes[26..58]
    }

    /// Returns the target/predecessor vault identifier or new-device zero sentinel.
    pub fn target_vault_id(&self) -> &[u8] {
        &self.bytes[58..90]
    }

    /// Returns the target/predecessor nonce epoch.
    pub fn target_epoch(&self) -> u64 {
        read_u64(&self.bytes[90..98])
    }

    /// Returns the target journal sequence or new-device zero sentinel.
    pub fn target_journal_sequence(&self) -> u64 {
        read_u64(&self.bytes[98..106])
    }

    /// Returns the target journal head or new-device zero sentinel.
    pub fn target_journal_head_digest(&self) -> &[u8] {
        &self.bytes[106..138]
    }

    /// Returns the authenticated source backup vault identifier.
    pub fn source_vault_id(&self) -> &[u8] {
        &self.bytes[138..170]
    }

    /// Returns the authenticated source backup nonce epoch.
    pub fn source_epoch(&self) -> u64 {
        read_u64(&self.bytes[170..178])
    }
}

/// Authenticated canonical restore completion record and full digest.
#[derive(Clone, Eq, PartialEq)]
pub struct RestoreCompleteV1 {
    bytes: [u8; RESTORE_COMPLETE_LEN],
    full_digest: [u8; 32],
}

impl RestoreCompleteV1 {
    /// Constructs completion bytes from the exact manifest and pre-complete head.
    pub fn new(
        manifest: &RestoreManifestV1,
        pre_complete_journal_head_digest: [u8; 32],
    ) -> Result<Self, CanonicalCodecError> {
        if is_zero(&pre_complete_journal_head_digest) {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let mut bytes = [0_u8; RESTORE_COMPLETE_LEN];
        bytes[..8].copy_from_slice(RESTORE_COMPLETE_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..26].copy_from_slice(manifest.restore_transaction_id());
        bytes[26..58].copy_from_slice(manifest.manifest_digest());
        bytes[58..90].copy_from_slice(&pre_complete_journal_head_digest);
        let full_digest = storage_hash(StorageHashDomainV1::RestoreComplete, &bytes[..90]);
        bytes[90..98].copy_from_slice(&full_digest[..8]);
        Self::from_bytes_with_manifest(&bytes, manifest)
    }

    /// Parses and authenticates completion bytes against the exact manifest.
    pub fn from_bytes_with_manifest(
        input: &[u8],
        manifest: &RestoreManifestV1,
    ) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedRestoreCompleteV1::parse_structural(input)?;
        let full_digest = storage_hash(StorageHashDomainV1::RestoreComplete, &input[..90]);
        if structural.restore_transaction_id() != manifest.restore_transaction_id()
            || structural.manifest_digest() != manifest.manifest_digest()
            || structural.completion_digest_prefix() != &full_digest[..8]
            || is_zero(structural.pre_complete_journal_head_digest())
        {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: *structural.as_bytes(),
            full_digest,
        })
    }

    /// Returns exact canonical completion bytes.
    pub const fn as_bytes(&self) -> &[u8; RESTORE_COMPLETE_LEN] {
        &self.bytes
    }

    /// Returns the complete 32-byte completion digest.
    pub const fn full_digest(&self) -> &[u8; 32] {
        &self.full_digest
    }
}

/// Closed restore-record-family registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RestoreRecordFamilyV1 {
    /// A canonical session claim.
    SessionClaim = 0x01,
    /// A canonical computation attempt.
    Attempt = 0x02,
    /// A canonical immutable exposure version.
    Exposure = 0x03,
    /// A canonical terminal tombstone.
    Tombstone = 0x04,
}

impl TryFrom<u8> for RestoreRecordFamilyV1 {
    type Error = CanonicalCodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::SessionClaim),
            0x02 => Ok(Self::Attempt),
            0x03 => Ok(Self::Exposure),
            0x04 => Ok(Self::Tombstone),
            _ => Err(CanonicalCodecError::InvalidEncoding),
        }
    }
}

/// Closed restore projection action registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RestoreActionV1 {
    /// Preserve one existing byte-identical terminal tombstone.
    PreserveTerminal = 0x01,
    /// Create one new burned tombstone because neither side is terminal.
    Burn = 0x02,
}

impl TryFrom<u8> for RestoreActionV1 {
    type Error = CanonicalCodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::PreserveTerminal),
            0x02 => Ok(Self::Burn),
            _ => Err(CanonicalCodecError::InvalidEncoding),
        }
    }
}

/// Structurally parsed restore manifest.
pub struct UnauthenticatedRestoreManifestV1 {
    bytes: [u8; RESTORE_MANIFEST_LEN],
    successor_epoch: u64,
    source_record_count: u32,
}

impl UnauthenticatedRestoreManifestV1 {
    /// Parses exact fields and the existing/new-device target sentinel.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<RESTORE_MANIFEST_LEN>(input)?;
        let target_epoch = read_u64(&bytes[90..98]);
        let target_sequence = read_u64(&bytes[98..106]);
        let source_epoch = read_u64(&bytes[170..178]);
        let source_sequence = read_u64(&bytes[178..186]);
        let successor_epoch = read_u64(&bytes[218..226]);
        let source_record_count = read_u32(&bytes[226..230]);
        let target_absent = is_zero(&bytes[58..90]);
        let target_head_zero = is_zero(&bytes[106..138]);
        let target_sentinel =
            target_absent && target_epoch == 0 && target_sequence == 0 && target_head_zero;
        let target_present =
            !target_absent && target_epoch != 0 && ((target_sequence == 0) == target_head_zero);
        let source_head_zero = is_zero(&bytes[186..218]);
        let expected_successor_epoch = target_epoch.max(source_epoch).checked_add(1);

        if &bytes[..8] != RESTORE_MANIFEST_MAGIC
            || read_u16(&bytes[8..10]) != 1
            || is_zero(&bytes[10..26])
            || is_zero(&bytes[26..58])
            || is_zero(&bytes[138..170])
            || bytes[26..58] == bytes[138..170]
            || source_epoch == 0
            || ((source_sequence == 0) != source_head_zero)
            || expected_successor_epoch != Some(successor_epoch)
            || is_zero(&bytes[230..262])
            || (!target_sentinel && !target_present)
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes,
            successor_epoch,
            source_record_count,
        })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; RESTORE_MANIFEST_LEN] {
        &self.bytes
    }

    /// Returns the nonzero restore transaction identifier.
    pub fn restore_transaction_id(&self) -> &[u8] {
        &self.bytes[10..26]
    }

    /// Returns whether the exact new-device target sentinel is present.
    pub fn is_new_device_target(&self) -> bool {
        is_zero(&self.bytes[58..90])
    }

    /// Returns the nonzero successor nonce epoch.
    pub const fn successor_epoch(&self) -> u64 {
        self.successor_epoch
    }

    /// Returns the declared source record count.
    pub const fn source_record_count(&self) -> u32 {
        self.source_record_count
    }

    /// Returns the unauthenticated source record-set digest.
    pub fn source_record_set_digest(&self) -> &[u8] {
        &self.bytes[230..262]
    }
}

/// Structurally parsed restore-completion record.
pub struct UnauthenticatedRestoreCompleteV1 {
    bytes: [u8; RESTORE_COMPLETE_LEN],
}

impl UnauthenticatedRestoreCompleteV1 {
    /// Parses exact fixed fields without authenticating either digest.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<RESTORE_COMPLETE_LEN>(input)?;
        if &bytes[..8] != RESTORE_COMPLETE_MAGIC
            || read_u16(&bytes[8..10]) != 1
            || is_zero(&bytes[10..26])
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self { bytes })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; RESTORE_COMPLETE_LEN] {
        &self.bytes
    }

    /// Returns the nonzero restore transaction identifier.
    pub fn restore_transaction_id(&self) -> &[u8] {
        &self.bytes[10..26]
    }

    /// Returns the unauthenticated manifest digest.
    pub fn manifest_digest(&self) -> &[u8] {
        &self.bytes[26..58]
    }

    /// Returns the unauthenticated pre-complete journal-head digest.
    pub fn pre_complete_journal_head_digest(&self) -> &[u8] {
        &self.bytes[58..90]
    }

    /// Returns the unauthenticated eight-byte completion sentinel.
    pub fn completion_digest_prefix(&self) -> &[u8] {
        &self.bytes[90..98]
    }
}

/// Structurally parsed restore projection payload.
pub struct UnauthenticatedRestoreRecordPayloadV1 {
    bytes: [u8; RESTORE_RECORD_PAYLOAD_LEN],
    identity: NonceIdentityV1,
    action: RestoreActionV1,
}

impl UnauthenticatedRestoreRecordPayloadV1 {
    /// Parses exact fields and the exhaustive preserve/burn sentinel rules.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<RESTORE_RECORD_PAYLOAD_LEN>(input)?;
        let identity = parse_nonce_identity(&bytes[..105])?;
        let current_present =
            parse_optional_tombstone_ref(bytes[105], &bytes[106..110], &bytes[110..142])?;
        let source_present =
            parse_optional_tombstone_ref(bytes[142], &bytes[143..147], &bytes[147..179])?;
        if bytes[179] != RestoreRecordFamilyV1::Tombstone as u8
            || read_u32(&bytes[180..184]) != 255
            || is_zero(&bytes[184..216])
            || bytes[217..220] != [0; 3]
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let action = RestoreActionV1::try_from(bytes[216])?;
        let result_digest = &bytes[184..216];
        match action {
            RestoreActionV1::PreserveTerminal => {
                if !current_present && !source_present {
                    return Err(CanonicalCodecError::InvalidEncoding);
                }
                if (current_present && &bytes[110..142] != result_digest)
                    || (source_present && &bytes[147..179] != result_digest)
                {
                    return Err(CanonicalCodecError::InvalidEncoding);
                }
            }
            RestoreActionV1::Burn => {
                if current_present || source_present {
                    return Err(CanonicalCodecError::InvalidEncoding);
                }
            }
        }
        Ok(Self {
            bytes,
            identity,
            action,
        })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; RESTORE_RECORD_PAYLOAD_LEN] {
        &self.bytes
    }

    /// Returns the canonical nonce identity.
    pub const fn identity(&self) -> &NonceIdentityV1 {
        &self.identity
    }

    /// Returns the restore projection action.
    pub const fn action(&self) -> RestoreActionV1 {
        self.action
    }

    /// Returns the nonzero unauthenticated result tombstone digest.
    pub fn result_tombstone_digest(&self) -> &[u8] {
        &self.bytes[184..216]
    }
}

/// Authenticated terminal projection committed by one restore journal entry.
#[derive(Clone, Eq, PartialEq)]
pub struct RestoreRecordPayloadV1 {
    bytes: [u8; RESTORE_RECORD_PAYLOAD_LEN],
    identity: NonceIdentityV1,
    action: RestoreActionV1,
    result: TombstoneV1,
}

impl RestoreRecordPayloadV1 {
    /// Preserves the one byte-identical terminal tombstone selected from either side.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn preserve_terminal(
        current: Option<&TombstoneV1>,
        source: Option<&TombstoneV1>,
    ) -> Result<Self, CanonicalCodecError> {
        let result = match (current, source) {
            (Some(left), Some(right)) if left == right => left,
            (Some(left), None) => left,
            (None, Some(right)) => right,
            _ => return Err(CanonicalCodecError::InvalidLifecycle),
        };
        Self::construct(current, source, result, RestoreActionV1::PreserveTerminal)
    }

    /// Validates and commits a Store-constructed burned tombstone when neither side is terminal.
    ///
    /// This codec deliberately does not select terminal evidence or construct
    /// the burn. The retained Store must first project the complete authenticated
    /// current/source union according to P1-002 section 7.4, including the
    /// maximum claim, attempt, exposure, and active-secret revision.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn burn(result: &TombstoneV1) -> Result<Self, CanonicalCodecError> {
        if result.reason() != TerminalReasonV1::Burned {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        Self::construct(None, None, result, RestoreActionV1::Burn)
    }

    fn construct(
        current: Option<&TombstoneV1>,
        source: Option<&TombstoneV1>,
        result: &TombstoneV1,
        action: RestoreActionV1,
    ) -> Result<Self, CanonicalCodecError> {
        for terminal in current.into_iter().chain(source) {
            if terminal.identity().as_bytes() != result.identity().as_bytes() {
                return Err(CanonicalCodecError::InvalidLifecycle);
            }
        }
        let mut bytes = [0_u8; RESTORE_RECORD_PAYLOAD_LEN];
        bytes[..105].copy_from_slice(result.identity().as_bytes());
        if let Some(terminal) = current {
            bytes[105] = RestoreRecordFamilyV1::Tombstone as u8;
            bytes[106..110].copy_from_slice(&(super::TOMBSTONE_LEN as u32).to_le_bytes());
            bytes[110..142].copy_from_slice(terminal.tombstone_digest());
        }
        if let Some(terminal) = source {
            bytes[142] = RestoreRecordFamilyV1::Tombstone as u8;
            bytes[143..147].copy_from_slice(&(super::TOMBSTONE_LEN as u32).to_le_bytes());
            bytes[147..179].copy_from_slice(terminal.tombstone_digest());
        }
        bytes[179] = RestoreRecordFamilyV1::Tombstone as u8;
        bytes[180..184].copy_from_slice(&(super::TOMBSTONE_LEN as u32).to_le_bytes());
        bytes[184..216].copy_from_slice(result.tombstone_digest());
        bytes[216] = action as u8;
        UnauthenticatedRestoreRecordPayloadV1::parse_structural(&bytes)?;
        Ok(Self {
            bytes,
            identity: *result.identity(),
            action,
            result: result.clone(),
        })
    }

    /// Parses and authenticates every tombstone reference and result digest.
    pub fn from_bytes(
        input: &[u8],
        current: Option<&TombstoneV1>,
        source: Option<&TombstoneV1>,
        result: &TombstoneV1,
    ) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedRestoreRecordPayloadV1::parse_structural(input)?;
        if structural.identity().as_bytes() != result.identity().as_bytes()
            || structural.result_tombstone_digest() != result.tombstone_digest()
        {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        let expected_result = match structural.action() {
            RestoreActionV1::PreserveTerminal => match (current, source) {
                (Some(left), Some(right)) if left == right => left,
                (Some(left), None) => left,
                (None, Some(right)) => right,
                _ => return Err(CanonicalCodecError::InvalidLifecycle),
            },
            RestoreActionV1::Burn => {
                if current.is_some() || source.is_some() {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                if result.reason() != TerminalReasonV1::Burned {
                    return Err(CanonicalCodecError::InvalidLifecycle);
                }
                result
            }
        };
        if expected_result != result {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        let expected = Self::construct(current, source, result, structural.action())?;
        if expected.bytes != input {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(expected)
    }

    /// Returns exact canonical projection bytes.
    pub const fn as_bytes(&self) -> &[u8; RESTORE_RECORD_PAYLOAD_LEN] {
        &self.bytes
    }

    /// Returns the canonical projected identity.
    pub const fn identity(&self) -> &NonceIdentityV1 {
        &self.identity
    }

    /// Returns the closed projection action.
    #[cfg(any(test, feature = "evidence-only"))]
    pub const fn action(&self) -> RestoreActionV1 {
        self.action
    }

    /// Returns the one authenticated successor tombstone.
    pub const fn result(&self) -> &TombstoneV1 {
        &self.result
    }
}

/// Structurally parsed epoch-advance journal payload.
pub struct UnauthenticatedEpochAdvancePayloadV1 {
    bytes: [u8; EPOCH_ADVANCE_PAYLOAD_LEN],
    predecessor_epoch: u64,
    successor_epoch: u64,
    predecessor_generation: u64,
    successor_generation: u64,
}

impl UnauthenticatedEpochAdvancePayloadV1 {
    /// Parses exact identifiers, counters, and the new-device predecessor sentinel.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<EPOCH_ADVANCE_PAYLOAD_LEN>(input)?;
        let predecessor_epoch = read_u64(&bytes[96..104]);
        let successor_epoch = read_u64(&bytes[104..112]);
        let predecessor_generation = read_u64(&bytes[112..120]);
        let successor_generation = read_u64(&bytes[120..128]);
        let predecessor_absent = is_zero(&bytes[32..64]);
        let new_device = predecessor_absent
            && predecessor_epoch == 0
            && predecessor_generation == 0
            && successor_generation == 1;
        let existing_device = !predecessor_absent
            && predecessor_epoch != 0
            && predecessor_generation != 0
            && successor_generation == predecessor_generation.checked_add(1).unwrap_or(0);
        if is_zero(&bytes[..32])
            || is_zero(&bytes[64..96])
            || bytes[..32] == bytes[64..96]
            || (!predecessor_absent && bytes[..32] == bytes[32..64])
            || (!predecessor_absent && bytes[32..64] == bytes[64..96])
            || successor_epoch == 0
            || (!predecessor_absent && successor_epoch <= predecessor_epoch)
            || is_zero(&bytes[128..144])
            || (!new_device && !existing_device)
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes,
            predecessor_epoch,
            successor_epoch,
            predecessor_generation,
            successor_generation,
        })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; EPOCH_ADVANCE_PAYLOAD_LEN] {
        &self.bytes
    }

    /// Returns whether the exact new-device predecessor sentinel is present.
    pub fn is_new_device(&self) -> bool {
        is_zero(&self.bytes[32..64])
    }

    /// Returns the predecessor nonce epoch.
    pub const fn predecessor_epoch(&self) -> u64 {
        self.predecessor_epoch
    }

    /// Returns the successor nonce epoch.
    pub const fn successor_epoch(&self) -> u64 {
        self.successor_epoch
    }

    /// Returns the predecessor vault generation.
    pub const fn predecessor_generation(&self) -> u64 {
        self.predecessor_generation
    }

    /// Returns the successor vault generation.
    pub const fn successor_generation(&self) -> u64 {
        self.successor_generation
    }

    /// Returns the unauthenticated successor generation-core digest.
    pub fn generation_core_digest(&self) -> &[u8] {
        &self.bytes[144..176]
    }
}

/// Authenticated exact epoch-advance restore payload.
#[derive(Clone, Eq, PartialEq)]
pub struct EpochAdvancePayloadV1 {
    bytes: [u8; EPOCH_ADVANCE_PAYLOAD_LEN],
}

impl EpochAdvancePayloadV1 {
    /// Constructs the exact signed epoch/generation transition.
    #[cfg(any(test, feature = "evidence-only"))]
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
    )]
    pub fn new(
        contract_wallet_id: [u8; 32],
        predecessor_vault_id: [u8; 32],
        successor_vault_id: [u8; 32],
        predecessor_epoch: u64,
        successor_epoch: u64,
        predecessor_generation: u64,
        successor_generation: u64,
        restore_transaction_id: [u8; 16],
        successor_generation_core_digest: [u8; 32],
    ) -> Result<Self, CanonicalCodecError> {
        let mut bytes = [0_u8; EPOCH_ADVANCE_PAYLOAD_LEN];
        bytes[..32].copy_from_slice(&contract_wallet_id);
        bytes[32..64].copy_from_slice(&predecessor_vault_id);
        bytes[64..96].copy_from_slice(&successor_vault_id);
        bytes[96..104].copy_from_slice(&predecessor_epoch.to_le_bytes());
        bytes[104..112].copy_from_slice(&successor_epoch.to_le_bytes());
        bytes[112..120].copy_from_slice(&predecessor_generation.to_le_bytes());
        bytes[120..128].copy_from_slice(&successor_generation.to_le_bytes());
        bytes[128..144].copy_from_slice(&restore_transaction_id);
        bytes[144..176].copy_from_slice(&successor_generation_core_digest);
        Self::from_bytes(&bytes)
    }

    /// Parses exact transition bytes and validates intrinsic branch/counter framing.
    ///
    /// The successor-epoch maximum across target and source and the actual
    /// predecessor generation remain cross-object checks of retained Store authority.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedEpochAdvancePayloadV1::parse_structural(input)?;
        if is_zero(structural.generation_core_digest()) {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes: *structural.as_bytes(),
        })
    }

    /// Returns exact canonical payload bytes.
    pub const fn as_bytes(&self) -> &[u8; EPOCH_ADVANCE_PAYLOAD_LEN] {
        &self.bytes
    }

    /// Returns the stable contract-wallet identifier.
    pub fn contract_wallet_id(&self) -> &[u8] {
        &self.bytes[..32]
    }

    /// Returns the predecessor vault ID or exact new-device zero sentinel.
    pub fn predecessor_vault_id(&self) -> &[u8] {
        &self.bytes[32..64]
    }

    /// Returns the successor vault ID.
    pub fn successor_vault_id(&self) -> &[u8] {
        &self.bytes[64..96]
    }

    /// Returns the predecessor epoch.
    pub fn predecessor_epoch(&self) -> u64 {
        read_u64(&self.bytes[96..104])
    }

    /// Returns the successor epoch.
    pub fn successor_epoch(&self) -> u64 {
        read_u64(&self.bytes[104..112])
    }

    /// Returns the predecessor generation or exact new-device zero sentinel.
    pub fn predecessor_generation(&self) -> u64 {
        read_u64(&self.bytes[112..120])
    }

    /// Returns the successor generation.
    pub fn successor_generation(&self) -> u64 {
        read_u64(&self.bytes[120..128])
    }

    /// Returns the restore transaction identifier.
    pub fn restore_transaction_id(&self) -> &[u8] {
        &self.bytes[128..144]
    }

    /// Returns the successor generation-core digest.
    pub fn generation_core_digest(&self) -> &[u8] {
        &self.bytes[144..176]
    }
}

/// Structurally parsed cross-family restore sort key.
pub struct UnauthenticatedRestoreRecordKeyV1 {
    bytes: [u8; RESTORE_RECORD_KEY_LEN],
    identity: NonceIdentityV1,
    family: RestoreRecordFamilyV1,
    subtype_sequence: u64,
    revision: u64,
}

impl UnauthenticatedRestoreRecordKeyV1 {
    /// Parses exact bytes and every family-specific assignment expressible in the key.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<RESTORE_RECORD_KEY_LEN>(input)?;
        let identity = parse_nonce_identity(&bytes[..105])?;
        let family = RestoreRecordFamilyV1::try_from(bytes[105])?;
        let subtype_sequence = read_u64(&bytes[106..114]);
        let subtype = bytes[114];
        let revision = read_u64(&bytes[115..123]);
        let valid = match family {
            RestoreRecordFamilyV1::SessionClaim => {
                subtype_sequence == 0 && subtype == 0 && revision == 1
            }
            RestoreRecordFamilyV1::Attempt => {
                revision != 0
                    && subtype_sequence == revision
                    && ArtifactKindV1::try_from(subtype).is_ok()
            }
            RestoreRecordFamilyV1::Exposure => {
                revision != 0
                    && (1..=3).contains(&subtype_sequence)
                    && ExposureStateV1::try_from(subtype).is_ok()
            }
            RestoreRecordFamilyV1::Tombstone => {
                subtype_sequence == 0
                    && revision != 0
                    && TerminalReasonV1::try_from(subtype).is_ok()
            }
        };
        if !valid {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes,
            identity,
            family,
            subtype_sequence,
            revision,
        })
    }

    /// Returns the exact unauthenticated canonical key bytes used for sorting.
    pub const fn as_bytes(&self) -> &[u8; RESTORE_RECORD_KEY_LEN] {
        &self.bytes
    }

    /// Returns the canonical nonce identity.
    pub const fn identity(&self) -> &NonceIdentityV1 {
        &self.identity
    }

    /// Returns the restore record family.
    pub const fn family(&self) -> RestoreRecordFamilyV1 {
        self.family
    }

    /// Returns the family-specific subtype sequence.
    pub const fn subtype_sequence(&self) -> u64 {
        self.subtype_sequence
    }

    /// Returns the family-specific lifecycle or claim revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the family-specific subtype version/state byte.
    pub const fn subtype_byte(&self) -> u8 {
        self.bytes[114]
    }

    /// Returns the unauthenticated full canonical record digest.
    pub fn record_digest(&self) -> &[u8] {
        &self.bytes[123..155]
    }
}

/// Structurally parsed canonical record selected by a restore key.
pub enum UnauthenticatedRestoreRecordV1<'a> {
    /// Complete canonical session claim.
    SessionClaim(super::UnauthenticatedSessionClaimV1),
    /// Complete stage-specific canonical attempt record.
    Attempt(super::UnauthenticatedComputationAttemptV1),
    /// Complete canonical exposure record.
    Exposure(super::UnauthenticatedExposureRecordV1<'a>),
    /// Complete canonical tombstone.
    Tombstone(super::UnauthenticatedTombstoneV1),
}

/// Structurally parsed key, length, and complete canonical record-set item.
pub struct UnauthenticatedRestoreRecordItemV1<'a> {
    bytes: &'a [u8],
    key: UnauthenticatedRestoreRecordKeyV1,
    record: UnauthenticatedRestoreRecordV1<'a>,
}

impl<'a> UnauthenticatedRestoreRecordItemV1<'a> {
    /// Parses exact item framing and verifies every key field against its record.
    pub fn parse_structural(input: &'a [u8]) -> Result<Self, CanonicalCodecError> {
        if input.len() < RESTORE_RECORD_ITEM_PREFIX_LEN {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let key =
            UnauthenticatedRestoreRecordKeyV1::parse_structural(&input[..RESTORE_RECORD_KEY_LEN])?;
        let record_length = usize::try_from(read_u32(
            &input[RESTORE_RECORD_KEY_LEN..RESTORE_RECORD_ITEM_PREFIX_LEN],
        ))
        .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        let expected_length = RESTORE_RECORD_ITEM_PREFIX_LEN
            .checked_add(record_length)
            .ok_or(CanonicalCodecError::InvalidEncoding)?;
        if input.len() != expected_length {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let record_bytes = &input[RESTORE_RECORD_ITEM_PREFIX_LEN..];
        let record = match key.family() {
            RestoreRecordFamilyV1::SessionClaim => {
                let claim = super::UnauthenticatedSessionClaimV1::parse_structural(record_bytes)?;
                if key.identity().as_bytes() != claim.identity().as_bytes()
                    || key.record_digest() != claim.claim_digest()
                {
                    return Err(CanonicalCodecError::InvalidEncoding);
                }
                UnauthenticatedRestoreRecordV1::SessionClaim(claim)
            }
            RestoreRecordFamilyV1::Attempt => {
                let attempt =
                    super::UnauthenticatedComputationAttemptV1::parse_structural(record_bytes)?;
                if key.identity().as_bytes() != attempt.identity().as_bytes()
                    || key.subtype_sequence() != attempt.expected_lifecycle_revision()
                    || key.subtype_byte() != attempt.artifact() as u8
                    || key.revision() != attempt.expected_lifecycle_revision()
                    || key.record_digest() != attempt.attempt_digest()
                {
                    return Err(CanonicalCodecError::InvalidEncoding);
                }
                UnauthenticatedRestoreRecordV1::Attempt(attempt)
            }
            RestoreRecordFamilyV1::Exposure => {
                let exposure =
                    super::UnauthenticatedExposureRecordV1::parse_structural(record_bytes)?;
                if key.identity().as_bytes() != exposure.identity().as_bytes()
                    || key.subtype_sequence() != exposure.sequence()
                    || key.subtype_byte() != exposure.state() as u8
                    || key.revision() != exposure.lifecycle_revision()
                    || key.record_digest() != exposure.record_digest()
                {
                    return Err(CanonicalCodecError::InvalidEncoding);
                }
                UnauthenticatedRestoreRecordV1::Exposure(exposure)
            }
            RestoreRecordFamilyV1::Tombstone => {
                let tombstone = super::UnauthenticatedTombstoneV1::parse_structural(record_bytes)?;
                if key.identity().as_bytes() != tombstone.identity().as_bytes()
                    || key.subtype_byte() != tombstone.reason() as u8
                    || key.revision() != tombstone.terminal_revision()
                    || key.record_digest() != tombstone.tombstone_digest()
                {
                    return Err(CanonicalCodecError::InvalidEncoding);
                }
                UnauthenticatedRestoreRecordV1::Tombstone(tombstone)
            }
        };
        Ok(Self {
            bytes: input,
            key,
            record,
        })
    }

    /// Returns the exact unauthenticated item bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the parsed canonical sort key.
    pub const fn key(&self) -> &UnauthenticatedRestoreRecordKeyV1 {
        &self.key
    }

    /// Returns the key-matched canonical record.
    pub const fn record(&self) -> &UnauthenticatedRestoreRecordV1<'a> {
        &self.record
    }
}

/// Structurally parsed canonical restore record-set bytes.
///
/// This parser allocates nothing from the encoded count. It enforces exact item
/// framing, strict lexicographic key order, no duplicate semantic versions,
/// one record per exposure state, one claim per session identifier, and no
/// trailing data.
/// The caller must still apply its authenticated backup-policy count bound.
pub struct UnauthenticatedRestoreRecordSetV1<'a> {
    bytes: &'a [u8],
    record_count: u32,
}

impl<'a> UnauthenticatedRestoreRecordSetV1<'a> {
    /// Parses the count and every concatenated sorted record item.
    pub fn parse_structural(input: &'a [u8]) -> Result<Self, CanonicalCodecError> {
        if input.len() < RESTORE_RECORD_SET_MIN_LEN {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let record_count = read_u32(&input[..4]);
        let mut cursor = RESTORE_RECORD_SET_MIN_LEN;
        let mut previous_key: Option<[u8; RESTORE_RECORD_KEY_LEN]> = None;
        for _ in 0..record_count {
            let prefix_end = cursor
                .checked_add(RESTORE_RECORD_ITEM_PREFIX_LEN)
                .ok_or(CanonicalCodecError::InvalidEncoding)?;
            if prefix_end > input.len() {
                return Err(CanonicalCodecError::InvalidEncoding);
            }
            let record_length = usize::try_from(read_u32(
                &input[cursor + RESTORE_RECORD_KEY_LEN..prefix_end],
            ))
            .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
            let item_end = prefix_end
                .checked_add(record_length)
                .ok_or(CanonicalCodecError::InvalidEncoding)?;
            if item_end > input.len() {
                return Err(CanonicalCodecError::InvalidEncoding);
            }
            let item =
                UnauthenticatedRestoreRecordItemV1::parse_structural(&input[cursor..item_end])?;
            let key_bytes = item.key().as_bytes();
            if let Some(previous) = previous_key.as_ref() {
                let duplicate_semantic_version = previous[..123] == key_bytes[..123];
                let duplicate_exposure_state = previous[..105] == key_bytes[..105]
                    && previous[105] == RestoreRecordFamilyV1::Exposure as u8
                    && key_bytes[105] == RestoreRecordFamilyV1::Exposure as u8
                    && previous[106..115] == key_bytes[106..115];
                let duplicate_attempt_revision = previous[..105] == key_bytes[..105]
                    && previous[105] == RestoreRecordFamilyV1::Attempt as u8
                    && key_bytes[105] == RestoreRecordFamilyV1::Attempt as u8
                    && previous[115..123] == key_bytes[115..123];
                let duplicate_tombstone_identity = previous[..105] == key_bytes[..105]
                    && previous[105] == RestoreRecordFamilyV1::Tombstone as u8
                    && key_bytes[105] == RestoreRecordFamilyV1::Tombstone as u8;
                if previous.as_slice() >= key_bytes.as_slice()
                    || duplicate_semantic_version
                    || duplicate_exposure_state
                    || duplicate_attempt_revision
                    || duplicate_tombstone_identity
                {
                    return Err(CanonicalCodecError::InvalidEncoding);
                }
            }
            if item.key().family() == RestoreRecordFamilyV1::SessionClaim
                && prior_claim_uses_session_id(input, cursor, item.key().identity().session_id())?
            {
                return Err(CanonicalCodecError::InvalidEncoding);
            }
            previous_key = Some(*key_bytes);
            cursor = item_end;
        }
        if cursor != input.len() {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes: input,
            record_count,
        })
    }

    /// Returns the exact unauthenticated record-set preimage bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the encoded item count.
    pub const fn record_count(&self) -> u32 {
        self.record_count
    }
}

fn prior_claim_uses_session_id(
    input: &[u8],
    end: usize,
    session_id: &[u8],
) -> Result<bool, CanonicalCodecError> {
    let mut cursor = RESTORE_RECORD_SET_MIN_LEN;
    while cursor < end {
        let prefix_end = cursor
            .checked_add(RESTORE_RECORD_ITEM_PREFIX_LEN)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        if prefix_end > end {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let record_length = usize::try_from(read_u32(
            &input[cursor + RESTORE_RECORD_KEY_LEN..prefix_end],
        ))
        .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        let item_end = prefix_end
            .checked_add(record_length)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        if item_end > end {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let item = UnauthenticatedRestoreRecordItemV1::parse_structural(&input[cursor..item_end])?;
        if item.key().family() == RestoreRecordFamilyV1::SessionClaim
            && item.key().identity().session_id() == session_id
        {
            return Ok(true);
        }
        cursor = item_end;
    }
    if cursor != end {
        return Err(CanonicalCodecError::InvalidEncoding);
    }
    Ok(false)
}

/// One authenticated canonical restore-record-set item.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RestoreRecordItemV1 {
    bytes: Vec<u8>,
    key: [u8; RESTORE_RECORD_KEY_LEN],
}

impl RestoreRecordItemV1 {
    /// Constructs and authenticates an item from a complete canonical record.
    pub(crate) fn from_record_bytes(
        family: RestoreRecordFamilyV1,
        record_bytes: &[u8],
    ) -> Result<Self, CanonicalCodecError> {
        let (identity, subtype_sequence, subtype, revision, digest) =
            authenticated_record_key_fields(family, record_bytes)?;
        let mut key = [0_u8; RESTORE_RECORD_KEY_LEN];
        key[..105].copy_from_slice(identity.as_bytes());
        key[105] = family as u8;
        key[106..114].copy_from_slice(&subtype_sequence.to_le_bytes());
        key[114] = subtype;
        key[115..123].copy_from_slice(&revision.to_le_bytes());
        key[123..155].copy_from_slice(&digest);
        let record_length =
            u32::try_from(record_bytes.len()).map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        let mut bytes = Vec::with_capacity(RESTORE_RECORD_ITEM_PREFIX_LEN + record_bytes.len());
        bytes.extend_from_slice(&key);
        bytes.extend_from_slice(&record_length.to_le_bytes());
        bytes.extend_from_slice(record_bytes);
        Self::from_bytes(&bytes)
    }

    /// Parses exact item bytes and authenticates the complete selected record.
    pub(crate) fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedRestoreRecordItemV1::parse_structural(input)?;
        let record_bytes = &input[RESTORE_RECORD_ITEM_PREFIX_LEN..];
        let (identity, subtype_sequence, subtype, revision, digest) =
            authenticated_record_key_fields(structural.key().family(), record_bytes)?;
        if structural.key().identity().as_bytes() != identity.as_bytes()
            || structural.key().subtype_sequence() != subtype_sequence
            || structural.key().subtype_byte() != subtype
            || structural.key().revision() != revision
            || structural.key().record_digest() != digest
        {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: input.to_vec(),
            key: *structural.key().as_bytes(),
        })
    }

    /// Returns exact key, length, and record bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Authenticated sorted canonical record set and its registered digest.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RestoreRecordSetV1 {
    bytes: Vec<u8>,
    record_count: u32,
    digest: [u8; 32],
}

impl RestoreRecordSetV1 {
    /// Sorts authenticated items by their complete 155-byte keys and rejects duplicates.
    pub(crate) fn new(
        mut items: Vec<RestoreRecordItemV1>,
        limits: &RestoreRecordSetLimitsV1,
    ) -> Result<Self, CanonicalCodecError> {
        let count = u32::try_from(items.len()).map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        if count > limits.max_record_count {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        items.sort_by_key(|left| left.key);
        let total = items.iter().try_fold(4_usize, |length, item| {
            length
                .checked_add(item.bytes.len())
                .ok_or(CanonicalCodecError::ArithmeticOverflow)
        })?;
        limits.validate_prefix(count, total)?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&count.to_le_bytes());
        for item in items {
            bytes.extend_from_slice(item.as_bytes());
        }
        let structural = UnauthenticatedRestoreRecordSetV1::parse_structural(&bytes)?;
        let record_count = structural.record_count();
        let digest = storage_hash(StorageHashDomainV1::RecordSet, &bytes);
        Ok(Self {
            bytes,
            record_count,
            digest,
        })
    }

    /// Parses every item, authenticates every record, and verifies the expected set digest.
    #[cfg(any(test, feature = "evidence-only"))]
    pub(crate) fn from_bytes(
        input: &[u8],
        expected_digest: [u8; 32],
        limits: &RestoreRecordSetLimitsV1,
    ) -> Result<Self, CanonicalCodecError> {
        if input.len() < RESTORE_RECORD_SET_MIN_LEN {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        limits.validate_prefix(read_u32(&input[..4]), input.len())?;
        let structural = UnauthenticatedRestoreRecordSetV1::parse_structural(input)?;
        let mut cursor = 4_usize;
        for _ in 0..structural.record_count() {
            let prefix_end = cursor
                .checked_add(RESTORE_RECORD_ITEM_PREFIX_LEN)
                .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
            let record_length = usize::try_from(read_u32(
                &input[cursor + RESTORE_RECORD_KEY_LEN..prefix_end],
            ))
            .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
            let item_end = prefix_end
                .checked_add(record_length)
                .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
            RestoreRecordItemV1::from_bytes(&input[cursor..item_end])?;
            cursor = item_end;
        }
        let digest = storage_hash(StorageHashDomainV1::RecordSet, input);
        if digest != expected_digest {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: input.to_vec(),
            record_count: structural.record_count(),
            digest,
        })
    }

    /// Returns the exact digest preimage bytes (`count || sorted items`).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the number of canonical record items.
    pub(crate) const fn record_count(&self) -> u32 {
        self.record_count
    }

    /// Returns the authenticated record-set digest.
    pub(crate) const fn record_set_digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

fn authenticated_record_key_fields(
    family: RestoreRecordFamilyV1,
    record_bytes: &[u8],
) -> Result<(NonceIdentityV1, u64, u8, u64, [u8; 32]), CanonicalCodecError> {
    match family {
        RestoreRecordFamilyV1::SessionClaim => {
            let record = SessionClaimV1::from_bytes(record_bytes)?;
            Ok((*record.identity(), 0, 0, 1, *record.claim_digest()))
        }
        RestoreRecordFamilyV1::Attempt => {
            let record = if record_bytes.len() == super::NONCE_DERIVATION_ATTEMPT_LEN {
                let wrapper = NonceDerivationAttemptV1::from_bytes(record_bytes)?;
                wrapper.attempt().clone()
            } else {
                AttemptRecordV1::from_bytes(record_bytes)?
            };
            Ok((
                *record.identity(),
                record.expected_lifecycle_revision(),
                record.artifact() as u8,
                record.expected_lifecycle_revision(),
                *record.attempt_digest(),
            ))
        }
        RestoreRecordFamilyV1::Exposure => {
            let record = ExposureRecordV1::from_bytes(record_bytes)?;
            Ok((
                *record.identity(),
                record.sequence(),
                record.state() as u8,
                record.lifecycle_revision(),
                *record.record_digest(),
            ))
        }
        RestoreRecordFamilyV1::Tombstone => {
            let record = TombstoneV1::from_bytes(record_bytes)?;
            Ok((
                *record.identity(),
                0,
                record.reason() as u8,
                record.terminal_revision(),
                *record.tombstone_digest(),
            ))
        }
    }
}

fn parse_optional_tombstone_ref(
    family: u8,
    length_bytes: &[u8],
    digest: &[u8],
) -> Result<bool, CanonicalCodecError> {
    let length = read_u32(length_bytes);
    match family {
        0 if length == 0 && is_zero(digest) => Ok(false),
        value
            if value == RestoreRecordFamilyV1::Tombstone as u8
                && length == 255
                && !is_zero(digest) =>
        {
            Ok(true)
        }
        _ => Err(CanonicalCodecError::InvalidEncoding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical::tombstone::TerminalEvidenceV1, PurposeV1, SigningPhaseV1};

    fn authenticated_identity() -> Result<NonceIdentityV1, CanonicalCodecError> {
        NonceIdentityV1::new([0x11; 32], [0x22; 32], PurposeV1::Funding, [0x33; 32], 7)
    }

    fn authenticated_burn() -> Result<(SessionClaimV1, TombstoneV1), CanonicalCodecError> {
        let claim = SessionClaimV1::new(authenticated_identity()?)?;
        let evidence = TerminalEvidenceV1::select_without_active_secret(&claim, &[], &[])?;
        let tombstone = TombstoneV1::new_burn(&evidence)?;
        Ok((claim, tombstone))
    }

    fn record_set_limits() -> Result<RestoreRecordSetLimitsV1, CanonicalCodecError> {
        RestoreRecordSetLimitsV1::new(16, 128 * 1024)
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

    fn manifest(new_device: bool) -> [u8; RESTORE_MANIFEST_LEN] {
        let mut bytes = [0_u8; RESTORE_MANIFEST_LEN];
        bytes[..8].copy_from_slice(RESTORE_MANIFEST_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..26].fill(0x10);
        bytes[26..58].fill(0x11);
        if !new_device {
            bytes[58..90].fill(0x22);
            bytes[90..98].copy_from_slice(&3_u64.to_le_bytes());
        }
        bytes[138..170].fill(0x33);
        bytes[170..178].copy_from_slice(&5_u64.to_le_bytes());
        bytes[218..226].copy_from_slice(&6_u64.to_le_bytes());
        bytes[230..262].fill(0x44);
        bytes
    }

    fn restore_payload(action: RestoreActionV1, current: bool, source: bool) -> [u8; 220] {
        let mut bytes = [0_u8; 220];
        bytes[..105].copy_from_slice(&identity_bytes());
        if current {
            bytes[105] = 4;
            bytes[106..110].copy_from_slice(&255_u32.to_le_bytes());
            bytes[110..142].fill(0x44);
        }
        if source {
            bytes[142] = 4;
            bytes[143..147].copy_from_slice(&255_u32.to_le_bytes());
            bytes[147..179].fill(0x44);
        }
        bytes[179] = 4;
        bytes[180..184].copy_from_slice(&255_u32.to_le_bytes());
        bytes[184..216].fill(if action == RestoreActionV1::Burn {
            0x55
        } else {
            0x44
        });
        bytes[216] = action as u8;
        bytes
    }

    fn epoch_advance(new_device: bool) -> [u8; EPOCH_ADVANCE_PAYLOAD_LEN] {
        let mut bytes = [0_u8; EPOCH_ADVANCE_PAYLOAD_LEN];
        bytes[..32].fill(0x11);
        if !new_device {
            bytes[32..64].fill(0x22);
            bytes[96..104].copy_from_slice(&4_u64.to_le_bytes());
            bytes[112..120].copy_from_slice(&2_u64.to_le_bytes());
        }
        bytes[64..96].fill(0x33);
        bytes[104..112].copy_from_slice(&5_u64.to_le_bytes());
        bytes[120..128].copy_from_slice(&(if new_device { 1_u64 } else { 3 }).to_le_bytes());
        bytes[128..144].fill(0x44);
        bytes[144..176].fill(0x55);
        bytes
    }

    fn restore_key(family: RestoreRecordFamilyV1) -> [u8; RESTORE_RECORD_KEY_LEN] {
        let mut bytes = [0_u8; RESTORE_RECORD_KEY_LEN];
        bytes[..105].copy_from_slice(&identity_bytes());
        bytes[105] = family as u8;
        match family {
            RestoreRecordFamilyV1::SessionClaim => {
                bytes[115..123].copy_from_slice(&1_u64.to_le_bytes())
            }
            RestoreRecordFamilyV1::Attempt => {
                bytes[106..114].copy_from_slice(&9_u64.to_le_bytes());
                bytes[114] = ArtifactKindV1::Commitment as u8;
                bytes[115..123].copy_from_slice(&9_u64.to_le_bytes());
            }
            RestoreRecordFamilyV1::Exposure => {
                bytes[106..114].copy_from_slice(&2_u64.to_le_bytes());
                bytes[114] = ExposureStateV1::Spent as u8;
                bytes[115..123].copy_from_slice(&9_u64.to_le_bytes());
            }
            RestoreRecordFamilyV1::Tombstone => {
                bytes[114] = TerminalReasonV1::Burned as u8;
                bytes[115..123].copy_from_slice(&9_u64.to_le_bytes());
            }
        }
        bytes
    }

    fn restore_record_bytes(family: RestoreRecordFamilyV1) -> Vec<u8> {
        match family {
            RestoreRecordFamilyV1::SessionClaim => {
                let mut bytes = vec![0_u8; super::super::SESSION_CLAIM_LEN];
                bytes[..8].copy_from_slice(b"DOMNVSC2");
                bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
                bytes[10..115].copy_from_slice(&identity_bytes());
                bytes[115..123].copy_from_slice(&1_u64.to_le_bytes());
                bytes
            }
            RestoreRecordFamilyV1::Attempt => {
                let mut bytes = vec![0_u8; super::super::NONCE_DERIVATION_ATTEMPT_LEN];
                bytes[..8].copy_from_slice(b"DOMNVAT1");
                bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
                bytes[10..115].copy_from_slice(&identity_bytes());
                bytes[115..123].copy_from_slice(&9_u64.to_le_bytes());
                bytes[123..125].copy_from_slice(&0x0100_u16.to_le_bytes());
                bytes[125] = ArtifactKindV1::Commitment as u8;
                bytes
            }
            RestoreRecordFamilyV1::Exposure => {
                let mut bytes = vec![0_u8; 234];
                bytes[..8].copy_from_slice(b"DOMNVEX1");
                bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
                bytes[10] = ExposureStateV1::Spent as u8;
                bytes[11] = ArtifactKindV1::Reveal as u8;
                bytes[12..117].copy_from_slice(&identity_bytes());
                bytes[117..125].copy_from_slice(&2_u64.to_le_bytes());
                bytes[125..133].copy_from_slice(&9_u64.to_le_bytes());
                bytes[197..201].copy_from_slice(&1_u32.to_le_bytes());
                bytes[201] = 0x44;
                bytes
            }
            RestoreRecordFamilyV1::Tombstone => {
                let mut bytes = vec![0_u8; super::super::TOMBSTONE_LEN];
                bytes[..8].copy_from_slice(b"DOMNVTS1");
                bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
                bytes[10..115].copy_from_slice(&identity_bytes());
                bytes[115] = TerminalReasonV1::Burned as u8;
                bytes[119..127].copy_from_slice(&9_u64.to_le_bytes());
                bytes
            }
        }
    }

    fn restore_item(family: RestoreRecordFamilyV1) -> Vec<u8> {
        let key = restore_key(family);
        let record = restore_record_bytes(family);
        let mut bytes = vec![0_u8; RESTORE_RECORD_ITEM_PREFIX_LEN + record.len()];
        bytes[..RESTORE_RECORD_KEY_LEN].copy_from_slice(&key);
        let record_length = u32::try_from(record.len()).unwrap_or(u32::MAX);
        bytes[RESTORE_RECORD_KEY_LEN..RESTORE_RECORD_ITEM_PREFIX_LEN]
            .copy_from_slice(&record_length.to_le_bytes());
        bytes[RESTORE_RECORD_ITEM_PREFIX_LEN..].copy_from_slice(&record);
        bytes
    }

    fn restore_set(families: &[RestoreRecordFamilyV1]) -> Vec<u8> {
        let count = u32::try_from(families.len()).unwrap_or(u32::MAX);
        let mut bytes = count.to_le_bytes().to_vec();
        for family in families {
            bytes.extend_from_slice(&restore_item(*family));
        }
        bytes
    }

    #[test]
    fn manifest_accepts_existing_and_exact_new_device_targets() -> Result<(), CanonicalCodecError> {
        for new_device in [false, true] {
            let bytes = manifest(new_device);
            let parsed = UnauthenticatedRestoreManifestV1::parse_structural(&bytes)?;
            assert_eq!(parsed.as_bytes(), &bytes);
            assert_eq!(parsed.is_new_device_target(), new_device);
            assert_eq!(parsed.successor_epoch(), 6);
        }
        Ok(())
    }

    #[test]
    fn existing_manifest_allows_equal_target_and_source_with_distinct_successor(
    ) -> Result<(), CanonicalCodecError> {
        let shared_predecessor_source = [0x33; 32];
        let successor = [0x44; 32];
        let manifest = RestoreManifestV1::new_existing_device(
            [0x10; 16],
            [0x11; 32],
            shared_predecessor_source,
            3,
            0,
            [0; 32],
            shared_predecessor_source,
            5,
            0,
            [0; 32],
            0,
            [0x55; 32],
        )?;
        assert_eq!(manifest.target_vault_id(), manifest.source_vault_id());
        assert_eq!(manifest.successor_epoch(), 6);

        let epoch = EpochAdvancePayloadV1::new(
            [0x11; 32],
            shared_predecessor_source,
            successor,
            3,
            6,
            2,
            3,
            [0x10; 16],
            [0x66; 32],
        )?;
        assert_ne!(epoch.successor_vault_id(), manifest.target_vault_id());
        assert_ne!(epoch.successor_vault_id(), manifest.source_vault_id());
        Ok(())
    }

    #[test]
    fn manifest_rejects_partial_target_sentinel() {
        let mut bytes = manifest(true);
        bytes[90..98].copy_from_slice(&1_u64.to_le_bytes());
        assert!(UnauthenticatedRestoreManifestV1::parse_structural(&bytes).is_err());
    }

    #[test]
    fn manifest_requires_the_exact_checked_successor_epoch() {
        for new_device in [false, true] {
            let canonical = manifest(new_device);
            for invalid_successor in [1_u64, 5, 7, u64::MAX] {
                let mut bytes = canonical;
                bytes[218..226].copy_from_slice(&invalid_successor.to_le_bytes());
                assert!(UnauthenticatedRestoreManifestV1::parse_structural(&bytes).is_err());
            }
        }

        let mut source_overflow = manifest(true);
        source_overflow[170..178].copy_from_slice(&u64::MAX.to_le_bytes());
        source_overflow[218..226].copy_from_slice(&1_u64.to_le_bytes());
        assert!(UnauthenticatedRestoreManifestV1::parse_structural(&source_overflow).is_err());

        let mut target_overflow = manifest(false);
        target_overflow[90..98].copy_from_slice(&u64::MAX.to_le_bytes());
        target_overflow[218..226].copy_from_slice(&1_u64.to_le_bytes());
        assert!(UnauthenticatedRestoreManifestV1::parse_structural(&target_overflow).is_err());
    }

    #[test]
    fn manifest_requires_nonzero_heads_for_nonzero_sequences() {
        let mut bytes = manifest(false);
        bytes[98..106].copy_from_slice(&3_u64.to_le_bytes());
        bytes[178..186].copy_from_slice(&4_u64.to_le_bytes());
        assert!(UnauthenticatedRestoreManifestV1::parse_structural(&bytes).is_err());
        bytes[106..138].fill(0x55);
        bytes[186..218].fill(0x66);
        assert!(UnauthenticatedRestoreManifestV1::parse_structural(&bytes).is_ok());
    }

    #[test]
    fn restore_complete_requires_exact_framing_and_transaction() -> Result<(), CanonicalCodecError>
    {
        let mut bytes = [0_u8; RESTORE_COMPLETE_LEN];
        bytes[..8].copy_from_slice(RESTORE_COMPLETE_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..26].fill(0x11);
        let parsed = UnauthenticatedRestoreCompleteV1::parse_structural(&bytes)?;
        assert_eq!(parsed.as_bytes(), &bytes);
        assert_eq!(parsed.completion_digest_prefix(), &[0; 8]);
        bytes[10..26].fill(0);
        assert!(UnauthenticatedRestoreCompleteV1::parse_structural(&bytes).is_err());
        Ok(())
    }

    #[test]
    fn restore_projection_enforces_preserve_and_burn_sentinels() -> Result<(), CanonicalCodecError>
    {
        for (action, current, source) in [
            (RestoreActionV1::PreserveTerminal, true, false),
            (RestoreActionV1::PreserveTerminal, false, true),
            (RestoreActionV1::PreserveTerminal, true, true),
            (RestoreActionV1::Burn, false, false),
        ] {
            let bytes = restore_payload(action, current, source);
            let parsed = UnauthenticatedRestoreRecordPayloadV1::parse_structural(&bytes)?;
            assert_eq!(parsed.as_bytes(), &bytes);
            assert_eq!(parsed.action(), action);
        }
        assert!(
            UnauthenticatedRestoreRecordPayloadV1::parse_structural(&restore_payload(
                RestoreActionV1::PreserveTerminal,
                false,
                false,
            ))
            .is_err()
        );
        assert!(
            UnauthenticatedRestoreRecordPayloadV1::parse_structural(&restore_payload(
                RestoreActionV1::Burn,
                true,
                false,
            ))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn epoch_advance_accepts_both_predecessor_branches() -> Result<(), CanonicalCodecError> {
        for new_device in [false, true] {
            let bytes = epoch_advance(new_device);
            let parsed = UnauthenticatedEpochAdvancePayloadV1::parse_structural(&bytes)?;
            assert_eq!(parsed.as_bytes(), &bytes);
            assert_eq!(parsed.is_new_device(), new_device);
        }
        Ok(())
    }

    #[test]
    fn restore_record_key_enforces_each_family_assignment() -> Result<(), CanonicalCodecError> {
        for family in [
            RestoreRecordFamilyV1::SessionClaim,
            RestoreRecordFamilyV1::Attempt,
            RestoreRecordFamilyV1::Exposure,
            RestoreRecordFamilyV1::Tombstone,
        ] {
            let bytes = restore_key(family);
            let parsed = UnauthenticatedRestoreRecordKeyV1::parse_structural(&bytes)?;
            assert_eq!(parsed.as_bytes(), &bytes);
            assert_eq!(parsed.family(), family);
        }
        Ok(())
    }

    #[test]
    fn restore_record_item_binds_every_key_field_to_record() -> Result<(), CanonicalCodecError> {
        for family in [
            RestoreRecordFamilyV1::SessionClaim,
            RestoreRecordFamilyV1::Attempt,
            RestoreRecordFamilyV1::Exposure,
            RestoreRecordFamilyV1::Tombstone,
        ] {
            let bytes = restore_item(family);
            let parsed = UnauthenticatedRestoreRecordItemV1::parse_structural(&bytes)?;
            assert_eq!(parsed.as_bytes(), bytes);
            assert_eq!(parsed.key().family(), family);
        }

        let mut wrong_digest = restore_item(RestoreRecordFamilyV1::SessionClaim);
        wrong_digest[123] = 1;
        assert!(UnauthenticatedRestoreRecordItemV1::parse_structural(&wrong_digest).is_err());

        let mut wrong_length = restore_item(RestoreRecordFamilyV1::Attempt);
        wrong_length[155..159].copy_from_slice(&192_u32.to_le_bytes());
        assert!(UnauthenticatedRestoreRecordItemV1::parse_structural(&wrong_length).is_err());
        Ok(())
    }

    #[test]
    fn restore_attempt_items_enforce_derivation_and_later_stage_lengths() {
        let commitment = restore_item(RestoreRecordFamilyV1::Attempt);
        assert!(UnauthenticatedRestoreRecordItemV1::parse_structural(&commitment).is_ok());

        let mut short_commitment = commitment.clone();
        short_commitment.truncate(short_commitment.len() - 8);
        short_commitment[RESTORE_RECORD_KEY_LEN..RESTORE_RECORD_ITEM_PREFIX_LEN]
            .copy_from_slice(&(super::super::ATTEMPT_RECORD_LEN as u32).to_le_bytes());
        assert!(UnauthenticatedRestoreRecordItemV1::parse_structural(&short_commitment).is_err());

        for (phase, artifact) in [
            (SigningPhaseV1::SigNonceReveal, ArtifactKindV1::Reveal),
            (SigningPhaseV1::SigPartial, ArtifactKindV1::PartialSignature),
        ] {
            let mut later = short_commitment.clone();
            later[114] = artifact as u8;
            let record_offset = RESTORE_RECORD_ITEM_PREFIX_LEN;
            later[record_offset + 123..record_offset + 125]
                .copy_from_slice(&(phase as u16).to_le_bytes());
            later[record_offset + 125] = artifact as u8;
            assert!(UnauthenticatedRestoreRecordItemV1::parse_structural(&later).is_ok());

            let mut oversized = commitment.clone();
            oversized[114] = artifact as u8;
            oversized[record_offset + 123..record_offset + 125]
                .copy_from_slice(&(phase as u16).to_le_bytes());
            oversized[record_offset + 125] = artifact as u8;
            assert!(UnauthenticatedRestoreRecordItemV1::parse_structural(&oversized).is_err());
        }
    }

    #[test]
    fn restore_record_set_requires_strict_key_order_and_exact_count(
    ) -> Result<(), CanonicalCodecError> {
        let ordered = restore_set(&[
            RestoreRecordFamilyV1::SessionClaim,
            RestoreRecordFamilyV1::Attempt,
            RestoreRecordFamilyV1::Exposure,
            RestoreRecordFamilyV1::Tombstone,
        ]);
        let parsed = UnauthenticatedRestoreRecordSetV1::parse_structural(&ordered)?;
        assert_eq!(parsed.as_bytes(), ordered);
        assert_eq!(parsed.record_count(), 4);

        let duplicate = restore_set(&[
            RestoreRecordFamilyV1::SessionClaim,
            RestoreRecordFamilyV1::SessionClaim,
        ]);
        assert!(UnauthenticatedRestoreRecordSetV1::parse_structural(&duplicate).is_err());

        let reordered = restore_set(&[
            RestoreRecordFamilyV1::Attempt,
            RestoreRecordFamilyV1::SessionClaim,
        ]);
        assert!(UnauthenticatedRestoreRecordSetV1::parse_structural(&reordered).is_err());

        let mut wrong_count = ordered.clone();
        wrong_count[..4].copy_from_slice(&5_u32.to_le_bytes());
        assert!(UnauthenticatedRestoreRecordSetV1::parse_structural(&wrong_count).is_err());

        let mut trailing = ordered;
        trailing.push(0);
        assert!(UnauthenticatedRestoreRecordSetV1::parse_structural(&trailing).is_err());
        Ok(())
    }

    #[test]
    fn restore_record_set_rejects_duplicate_semantic_versions_and_exposure_states() {
        let first = restore_item(RestoreRecordFamilyV1::Exposure);

        let mut same_version_different_digest = first.clone();
        same_version_different_digest[123] = 1;
        same_version_different_digest[RESTORE_RECORD_ITEM_PREFIX_LEN + 202] = 1;
        let mut duplicate_version = 2_u32.to_le_bytes().to_vec();
        duplicate_version.extend_from_slice(&first);
        duplicate_version.extend_from_slice(&same_version_different_digest);
        assert!(UnauthenticatedRestoreRecordSetV1::parse_structural(&duplicate_version).is_err());

        let mut later_revision_same_state = first.clone();
        later_revision_same_state[115..123].copy_from_slice(&10_u64.to_le_bytes());
        let record_revision = RESTORE_RECORD_ITEM_PREFIX_LEN + 125;
        later_revision_same_state[record_revision..record_revision + 8]
            .copy_from_slice(&10_u64.to_le_bytes());
        let mut duplicate_state = 2_u32.to_le_bytes().to_vec();
        duplicate_state.extend_from_slice(&first);
        duplicate_state.extend_from_slice(&later_revision_same_state);
        assert!(UnauthenticatedRestoreRecordSetV1::parse_structural(&duplicate_state).is_err());
    }

    #[test]
    fn restore_record_set_rejects_two_attempts_for_one_identity_revision() {
        let commitment = restore_item(RestoreRecordFamilyV1::Attempt);
        let mut reveal = commitment.clone();
        reveal[114] = ArtifactKindV1::Reveal as u8;
        let record_offset = RESTORE_RECORD_ITEM_PREFIX_LEN;
        reveal[record_offset + 123..record_offset + 125].copy_from_slice(&0x0101_u16.to_le_bytes());
        reveal[record_offset + 125] = ArtifactKindV1::Reveal as u8;

        let mut bytes = 2_u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&commitment);
        bytes.extend_from_slice(&reveal);
        assert!(UnauthenticatedRestoreRecordSetV1::parse_structural(&bytes).is_err());
    }

    #[test]
    fn restore_record_set_rejects_two_claims_for_one_session_id() {
        let first = restore_item(RestoreRecordFamilyV1::SessionClaim);
        let mut same_session_different_identity = first.clone();
        same_session_different_identity[32] = 0x23;
        same_session_different_identity[RESTORE_RECORD_ITEM_PREFIX_LEN + 42] = 0x23;
        let mut duplicate_session = 2_u32.to_le_bytes().to_vec();
        duplicate_session.extend_from_slice(&first);
        duplicate_session.extend_from_slice(&same_session_different_identity);
        assert!(UnauthenticatedRestoreRecordSetV1::parse_structural(&duplicate_session).is_err());

        let mut different_session = first.clone();
        different_session[0] = 0x12;
        different_session[RESTORE_RECORD_ITEM_PREFIX_LEN + 10] = 0x12;
        let mut distinct_sessions = 2_u32.to_le_bytes().to_vec();
        distinct_sessions.extend_from_slice(&first);
        distinct_sessions.extend_from_slice(&different_session);
        assert!(UnauthenticatedRestoreRecordSetV1::parse_structural(&distinct_sessions).is_ok());
    }

    #[test]
    fn restore_record_set_rejects_two_tombstones_for_one_identity() {
        let first = restore_item(RestoreRecordFamilyV1::Tombstone);
        let mut later_reason_and_revision = first.clone();
        later_reason_and_revision[114] = TerminalReasonV1::Burned as u8;
        later_reason_and_revision[115..123].copy_from_slice(&10_u64.to_le_bytes());
        let record_reason = RESTORE_RECORD_ITEM_PREFIX_LEN + 115;
        later_reason_and_revision[record_reason] = TerminalReasonV1::Burned as u8;
        let record_revision = RESTORE_RECORD_ITEM_PREFIX_LEN + 119;
        later_reason_and_revision[record_revision..record_revision + 8]
            .copy_from_slice(&10_u64.to_le_bytes());

        let mut duplicate_tombstone = 2_u32.to_le_bytes().to_vec();
        duplicate_tombstone.extend_from_slice(&first);
        duplicate_tombstone.extend_from_slice(&later_reason_and_revision);
        assert!(UnauthenticatedRestoreRecordSetV1::parse_structural(&duplicate_tombstone).is_err());
    }

    #[test]
    fn empty_restore_record_set_is_canonical() -> Result<(), CanonicalCodecError> {
        let bytes = 0_u32.to_le_bytes();
        let parsed = UnauthenticatedRestoreRecordSetV1::parse_structural(&bytes)?;
        assert_eq!(parsed.as_bytes(), &bytes);
        assert_eq!(parsed.record_count(), 0);
        assert!(RestoreRecordSetLimitsV1::new(0, RESTORE_RECORD_SET_MIN_LEN - 1).is_err());
        let exact_empty_limit = RestoreRecordSetLimitsV1::new(0, RESTORE_RECORD_SET_MIN_LEN)?;
        let authenticated = RestoreRecordSetV1::new(Vec::new(), &exact_empty_limit)?;
        assert_eq!(authenticated.as_bytes(), &bytes);
        assert_eq!(authenticated.record_count(), 0);
        Ok(())
    }

    #[test]
    fn authenticated_manifest_completion_and_epoch_are_byte_exact(
    ) -> Result<(), CanonicalCodecError> {
        let manifest = RestoreManifestV1::new_restore_only(
            [0x10; 16], [0x11; 32], [0x33; 32], 5, 0, [0; 32], 0, [0x44; 32],
        )?;
        assert!(RestoreManifestV1::from_bytes(manifest.as_bytes())? == manifest);
        assert_eq!(
            manifest.manifest_digest(),
            &[
                0x13, 0x56, 0x8f, 0xfe, 0x35, 0x96, 0xd1, 0xfc, 0xa4, 0x8d, 0xed, 0x60, 0x24, 0x28,
                0xed, 0x16, 0x03, 0x75, 0x1d, 0xba, 0xd3, 0x50, 0x56, 0x90, 0xed, 0x62, 0x6d, 0xa6,
                0xdc, 0x66, 0xa0, 0xc9,
            ]
        );
        let completion = RestoreCompleteV1::new(&manifest, [0x55; 32])?;
        assert_eq!(
            completion.full_digest(),
            &[
                0x7e, 0xe1, 0x6e, 0x73, 0x7c, 0x5c, 0x94, 0x45, 0xe8, 0x99, 0xd5, 0x40, 0x63, 0xe1,
                0x03, 0x9d, 0x9c, 0xfe, 0xb9, 0x51, 0x9c, 0x90, 0x11, 0x1e, 0x18, 0x23, 0x04, 0x46,
                0x80, 0x82, 0x41, 0xe7,
            ]
        );
        assert!(
            RestoreCompleteV1::from_bytes_with_manifest(completion.as_bytes(), &manifest)?
                == completion
        );
        let epoch = EpochAdvancePayloadV1::new(
            [0x11; 32], [0; 32], [0x66; 32], 0, 6, 0, 1, [0x10; 16], [0x77; 32],
        )?;
        assert!(EpochAdvancePayloadV1::from_bytes(epoch.as_bytes())? == epoch);

        let mut changed_manifest = *manifest.as_bytes();
        changed_manifest[26] ^= 1;
        let changed_manifest = RestoreManifestV1::from_bytes(&changed_manifest)?;
        assert!(RestoreCompleteV1::from_bytes_with_manifest(
            completion.as_bytes(),
            &changed_manifest
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn authenticated_restore_objects_detect_every_byte_mutation() -> Result<(), CanonicalCodecError>
    {
        let restore_only = RestoreManifestV1::new_restore_only(
            [0x10; 16], [0x11; 32], [0x33; 32], 5, 0, [0; 32], 0, [0x44; 32],
        )?;
        let existing = RestoreManifestV1::new_existing_device(
            [0x20; 16], [0x21; 32], [0x23; 32], 3, 0, [0; 32], [0x23; 32], 5, 0, [0; 32], 0,
            [0x24; 32],
        )?;
        for manifest in [&restore_only, &existing] {
            for offset in 0..manifest.as_bytes().len() {
                let mut mutated = *manifest.as_bytes();
                mutated[offset] ^= 1;
                if let Ok(parsed) = RestoreManifestV1::from_bytes(&mutated) {
                    assert_ne!(
                        parsed.manifest_digest(),
                        manifest.manifest_digest(),
                        "manifest mutation {offset}"
                    );
                }
            }
        }

        let completion = RestoreCompleteV1::new(&restore_only, [0x55; 32])?;
        for offset in 0..completion.as_bytes().len() {
            let mut mutated = *completion.as_bytes();
            mutated[offset] ^= 1;
            assert!(
                RestoreCompleteV1::from_bytes_with_manifest(&mutated, &restore_only).is_err(),
                "completion mutation {offset}"
            );
        }

        let (_, tombstone) = authenticated_burn()?;
        let projection = RestoreRecordPayloadV1::burn(&tombstone)?;
        for offset in 0..projection.as_bytes().len() {
            let mut mutated = *projection.as_bytes();
            mutated[offset] ^= 1;
            assert!(
                RestoreRecordPayloadV1::from_bytes(&mutated, None, None, &tombstone).is_err(),
                "restore projection mutation {offset}"
            );
        }
        Ok(())
    }

    #[test]
    fn authenticated_terminal_projection_and_record_set_fail_closed(
    ) -> Result<(), CanonicalCodecError> {
        let (claim, tombstone) = authenticated_burn()?;
        let preserve = RestoreRecordPayloadV1::preserve_terminal(Some(&tombstone), None)?;
        assert!(preserve.result() == &tombstone);
        assert_eq!(preserve.action(), RestoreActionV1::PreserveTerminal);
        assert!(
            RestoreRecordPayloadV1::from_bytes(
                preserve.as_bytes(),
                Some(&tombstone),
                None,
                &tombstone,
            )? == preserve
        );
        let burn = RestoreRecordPayloadV1::burn(&tombstone)?;
        assert_eq!(burn.action(), RestoreActionV1::Burn);
        assert!(RestoreRecordPayloadV1::preserve_terminal(
            Some(&tombstone),
            Some(&{
                let other_claim = SessionClaimV1::new(NonceIdentityV1::new(
                    [0x41; 32],
                    [0x42; 32],
                    PurposeV1::Refund,
                    [0x43; 32],
                    8,
                )?)?;
                let evidence =
                    TerminalEvidenceV1::select_without_active_secret(&other_claim, &[], &[])?;
                TombstoneV1::new_burn(&evidence)?
            })
        )
        .is_err());

        let claim_item = RestoreRecordItemV1::from_record_bytes(
            RestoreRecordFamilyV1::SessionClaim,
            claim.as_bytes(),
        )?;
        let tombstone_item = RestoreRecordItemV1::from_record_bytes(
            RestoreRecordFamilyV1::Tombstone,
            tombstone.as_bytes(),
        )?;
        let limits = record_set_limits()?;
        let set = RestoreRecordSetV1::new(vec![tombstone_item, claim_item], &limits)?;
        assert_eq!(set.record_count(), 2);
        assert!(
            RestoreRecordSetV1::from_bytes(set.as_bytes(), *set.record_set_digest(), &limits)?
                == set
        );
        for offset in 0..set.as_bytes().len() {
            let mut mutated = set.as_bytes().to_vec();
            mutated[offset] ^= 1;
            assert!(
                RestoreRecordSetV1::from_bytes(&mutated, *set.record_set_digest(), &limits)
                    .is_err(),
                "record-set mutation {offset}"
            );
        }
        for offset in 0..set.record_set_digest().len() {
            let mut wrong_digest = *set.record_set_digest();
            wrong_digest[offset] ^= 1;
            assert!(
                RestoreRecordSetV1::from_bytes(set.as_bytes(), wrong_digest, &limits).is_err(),
                "record-set digest mutation {offset}"
            );
        }

        let count_too_small = RestoreRecordSetLimitsV1::new(1, set.as_bytes().len())?;
        assert!(RestoreRecordSetV1::from_bytes(
            set.as_bytes(),
            *set.record_set_digest(),
            &count_too_small
        )
        .is_err());
        let bytes_too_small = RestoreRecordSetLimitsV1::new(2, set.as_bytes().len() - 1)?;
        assert!(RestoreRecordSetV1::from_bytes(
            set.as_bytes(),
            *set.record_set_digest(),
            &bytes_too_small
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn restore_registries_reject_every_undefined_byte() {
        for value in 0_u8..=u8::MAX {
            assert_eq!(
                RestoreRecordFamilyV1::try_from(value).is_ok(),
                (1..=4).contains(&value)
            );
            assert_eq!(
                RestoreActionV1::try_from(value).is_ok(),
                (1..=2).contains(&value)
            );
        }
    }

    #[test]
    fn restore_records_reject_every_truncation_and_trailing_byte() {
        let records = [
            manifest(false).to_vec(),
            {
                let mut bytes = [0_u8; RESTORE_COMPLETE_LEN];
                bytes[..8].copy_from_slice(RESTORE_COMPLETE_MAGIC);
                bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
                bytes[10..26].fill(0x11);
                bytes.to_vec()
            },
            restore_payload(RestoreActionV1::Burn, false, false).to_vec(),
            epoch_advance(false).to_vec(),
            restore_key(RestoreRecordFamilyV1::Attempt).to_vec(),
            restore_item(RestoreRecordFamilyV1::Exposure),
            restore_set(&[
                RestoreRecordFamilyV1::SessionClaim,
                RestoreRecordFamilyV1::Attempt,
                RestoreRecordFamilyV1::Exposure,
                RestoreRecordFamilyV1::Tombstone,
            ]),
        ];
        for (record_index, bytes) in records.into_iter().enumerate() {
            for end in 0..bytes.len() {
                let rejected = match record_index {
                    0 => UnauthenticatedRestoreManifestV1::parse_structural(&bytes[..end]).is_err(),
                    1 => UnauthenticatedRestoreCompleteV1::parse_structural(&bytes[..end]).is_err(),
                    2 => UnauthenticatedRestoreRecordPayloadV1::parse_structural(&bytes[..end])
                        .is_err(),
                    3 => UnauthenticatedEpochAdvancePayloadV1::parse_structural(&bytes[..end])
                        .is_err(),
                    4 => {
                        UnauthenticatedRestoreRecordKeyV1::parse_structural(&bytes[..end]).is_err()
                    }
                    5 => {
                        UnauthenticatedRestoreRecordItemV1::parse_structural(&bytes[..end]).is_err()
                    }
                    6 => {
                        UnauthenticatedRestoreRecordSetV1::parse_structural(&bytes[..end]).is_err()
                    }
                    _ => false,
                };
                assert!(rejected, "record {record_index}, prefix {end}");
            }
            let mut trailing = bytes;
            trailing.push(0);
            let rejected = match record_index {
                0 => UnauthenticatedRestoreManifestV1::parse_structural(&trailing).is_err(),
                1 => UnauthenticatedRestoreCompleteV1::parse_structural(&trailing).is_err(),
                2 => UnauthenticatedRestoreRecordPayloadV1::parse_structural(&trailing).is_err(),
                3 => UnauthenticatedEpochAdvancePayloadV1::parse_structural(&trailing).is_err(),
                4 => UnauthenticatedRestoreRecordKeyV1::parse_structural(&trailing).is_err(),
                5 => UnauthenticatedRestoreRecordItemV1::parse_structural(&trailing).is_err(),
                6 => UnauthenticatedRestoreRecordSetV1::parse_structural(&trailing).is_err(),
                _ => false,
            };
            assert!(rejected, "record {record_index}, trailing");
        }
    }
}
