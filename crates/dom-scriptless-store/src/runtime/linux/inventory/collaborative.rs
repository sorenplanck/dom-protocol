//! Retained filesystem transaction for F7 collaborative-secret custody.

use super::super::session_store::TerminalCollaborativeSessionEvidenceV1;
use super::{
    ensure_optional_namespace, retain_authority_namespace_alias, ContractsNonceVaultV1,
    ExpectedNodeType, InventoryError, LinuxCapabilityError, LiveStoreInventoryV1,
    ValidatedComponent,
};
use dom_adaptor::{
    BpRound2ShareV1, BpStatementV1, CollaborativeBpFinalizeBindingV1,
    CollaborativeBpFinalizeContinuationV1, CollaborativeBpFinalizeImportCapabilityV1,
    CollaborativeBpNonceBindingV1, CollaborativeBpNonceImportCapabilityV1,
    CollaborativeBpNonceMaterialV1, CollaborativeBpNonceSealCapabilityV1,
    CollaborativeBpNonceVaultV1, CollaborativeBpProofImportCapabilityV1,
    CollaborativeBpProofPersistenceCapabilityV1, CollaborativeBpRound2ImportCapabilityV1,
    CollaborativeBpRound2PersistenceCapabilityV1, DurableBpProofTransportV1,
    DurableBpRound2TransportV1, DurableShareBackupAckCapabilityV1, LocatedSharedBlindingStageV1,
    PendingSharedBlindingBindingV1, RangeProof739, RestartableSharedBlindingVaultV1,
    ShareBackupAckV1, SharedBlindingBindingUpgradeCapabilityV1, SharedBlindingBindingV1,
    SharedBlindingImportCapabilityV1, SharedBlindingMaterialV1,
    SharedBlindingRestartLookupCapabilityV1, SharedBlindingRestartRequestV1,
    SharedBlindingRetirementCapabilityV1, SharedBlindingSealCapabilityV1, SharedBlindingVaultV1,
};
use dom_scriptless_crypto::{
    acknowledge_pending_shared_blinding_backup_v1, acknowledge_shared_blinding_backup_v1,
    audit_collaborative_secret_envelope_v1, open_collaborative_bp_finalize_record_v1,
    open_collaborative_bp_nonce_record_v1, open_collaborative_bp_proof_record_v1,
    open_collaborative_bp_round2_record_v1, open_pending_shared_blinding_record_v1,
    open_shared_blinding_record_v1, open_shared_blinding_recovery_capsule_v1,
    seal_collaborative_bp_nonce_record_v1, seal_collaborative_bp_proof_record_v1,
    seal_collaborative_bp_round2_bundle_v1, seal_shared_blinding_bundle_v1,
    upgrade_shared_blinding_bundle_restartable_v1, upgrade_shared_blinding_bundle_v1,
    CollaborativeSecretEnvelopeV1,
};

const STATE_MAGIC: &[u8; 8] = b"DOMF7ST1";
const STATE_VERSION: u16 = 1;
const STATE_PREFIX_LEN: usize = 56;
const STATE_DIGEST_LEN: usize = 32;
const MAX_BINDING_LEN: usize = 65_536 + 220;
const MAX_ENVELOPE_LEN: usize = 1024 * 1024 + 164;
const MAX_STATE_LEN: usize =
    STATE_PREFIX_LEN + MAX_BINDING_LEN + MAX_ENVELOPE_LEN * 3 + STATE_DIGEST_LEN;
const STATE_TAG: &str = "DOM:contracts-f7-collaborative-state:v1";

#[cfg(test)]
fn collaborative_crash_hook(label: &str) {
    if std::env::var("DOM_CONTRACTS_COLLABORATIVE_CRASH_CUT").as_deref() == Ok(label) {
        if let Ok(marker) = std::env::var("DOM_CONTRACTS_COLLABORATIVE_CRASH_MARKER") {
            let _ = std::fs::write(marker, label.as_bytes());
        }
        std::process::abort();
    }
}

#[cfg(not(test))]
const fn collaborative_crash_hook(_: &str) {}

#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum StateKind {
    SharedPending = 1,
    BpNonce = 2,
    BpRound2Finalize = 3,
    BpProof = 4,
    SharedBound = 5,
    SharedPendingRetired = 6,
    SharedBoundRetired = 7,
    TerminalSession = 8,
}

impl StateKind {
    fn parse(value: u8) -> Result<Self, InventoryError> {
        match value {
            1 => Ok(Self::SharedPending),
            2 => Ok(Self::BpNonce),
            3 => Ok(Self::BpRound2Finalize),
            4 => Ok(Self::BpProof),
            5 => Ok(Self::SharedBound),
            6 => Ok(Self::SharedPendingRetired),
            7 => Ok(Self::SharedBoundRetired),
            8 => Ok(Self::TerminalSession),
            _ => Err(InventoryError::RestoreQuarantined),
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::SharedPending => "shared-pending",
            Self::BpNonce => "bp-nonce",
            Self::BpRound2Finalize => "bp-round2",
            Self::BpProof => "bp-proof",
            Self::SharedBound => "shared-bound",
            Self::SharedPendingRetired => "shared-pending-retired",
            Self::SharedBoundRetired => "shared-bound-retired",
            Self::TerminalSession => "terminal-session",
        }
    }
}

struct StateRecord {
    bytes: Vec<u8>,
    kind: StateKind,
    binding_digest: [u8; 32],
    binding: Vec<u8>,
    envelopes: Vec<CollaborativeSecretEnvelopeV1>,
}

impl StateRecord {
    fn new(
        kind: StateKind,
        binding: &[u8],
        envelopes: &[&CollaborativeSecretEnvelopeV1],
    ) -> Result<Self, InventoryError> {
        if binding.is_empty() || binding.len() > MAX_BINDING_LEN {
            return Err(InventoryError::Canonical);
        }
        let binding_digest = *dom_crypto::blake2b_256(binding).as_bytes();
        let binding_len = u32::try_from(binding.len()).map_err(|_| InventoryError::Canonical)?;
        let envelope_count =
            u8::try_from(envelopes.len()).map_err(|_| InventoryError::Canonical)?;
        let payload_len = envelopes
            .iter()
            .try_fold(binding.len(), |total, envelope| {
                total
                    .checked_add(4)
                    .and_then(|value| value.checked_add(envelope.as_bytes().len()))
                    .ok_or(InventoryError::Canonical)
            })?;
        let total = STATE_PREFIX_LEN
            .checked_add(payload_len)
            .and_then(|value| value.checked_add(STATE_DIGEST_LEN))
            .ok_or(InventoryError::Canonical)?;
        if total > MAX_STATE_LEN {
            return Err(InventoryError::Canonical);
        }
        let mut bytes = vec![0u8; total];
        bytes[..8].copy_from_slice(STATE_MAGIC);
        bytes[8..10].copy_from_slice(&STATE_VERSION.to_le_bytes());
        bytes[10] = kind as u8;
        bytes[11] = envelope_count;
        bytes[12..16].copy_from_slice(&binding_len.to_le_bytes());
        bytes[16..48].copy_from_slice(&binding_digest);
        let mut cursor = STATE_PREFIX_LEN;
        bytes[cursor..cursor + binding.len()].copy_from_slice(binding);
        cursor += binding.len();
        for envelope in envelopes {
            let length =
                u32::try_from(envelope.as_bytes().len()).map_err(|_| InventoryError::Canonical)?;
            bytes[cursor..cursor + 4].copy_from_slice(&length.to_le_bytes());
            cursor += 4;
            bytes[cursor..cursor + envelope.as_bytes().len()].copy_from_slice(envelope.as_bytes());
            cursor += envelope.as_bytes().len();
        }
        let digest = *dom_crypto::blake2b_256_tagged(STATE_TAG, &bytes[..total - STATE_DIGEST_LEN])
            .as_bytes();
        bytes[total - STATE_DIGEST_LEN..].copy_from_slice(&digest);
        Self::from_bytes(&bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, InventoryError> {
        if bytes.len() < STATE_PREFIX_LEN + STATE_DIGEST_LEN
            || bytes.len() > MAX_STATE_LEN
            || &bytes[..8] != STATE_MAGIC
            || u16::from_le_bytes(copy_array(&bytes[8..10])?) != STATE_VERSION
            || bytes[48..56] != [0; 8]
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let kind = StateKind::parse(bytes[10])?;
        let envelope_count = usize::from(bytes[11]);
        let valid_envelope_count = match kind {
            StateKind::SharedPending | StateKind::BpRound2Finalize => envelope_count == 2,
            // Legacy bound records retain two encrypted share copies.  The
            // additive F7 restartable profile retains a third authenticated
            // exact recovery-capsule envelope in the same immutable record.
            StateKind::SharedBound => matches!(envelope_count, 2 | 3),
            StateKind::BpNonce => envelope_count == 1,
            StateKind::BpProof => envelope_count == 2,
            StateKind::SharedPendingRetired
            | StateKind::SharedBoundRetired
            | StateKind::TerminalSession => envelope_count == 0,
        };
        let binding_len = u32::from_le_bytes(copy_array(&bytes[12..16])?) as usize;
        let binding_end = STATE_PREFIX_LEN
            .checked_add(binding_len)
            .filter(|end| *end <= bytes.len().saturating_sub(STATE_DIGEST_LEN))
            .ok_or(InventoryError::RestoreQuarantined)?;
        if !valid_envelope_count
            || binding_len == 0
            || binding_len > MAX_BINDING_LEN
            || bytes[16..48]
                != *dom_crypto::blake2b_256(
                    bytes
                        .get(STATE_PREFIX_LEN..binding_end)
                        .ok_or(InventoryError::RestoreQuarantined)?,
                )
                .as_bytes()
            || bytes[bytes.len() - STATE_DIGEST_LEN..]
                != *dom_crypto::blake2b_256_tagged(
                    STATE_TAG,
                    &bytes[..bytes.len() - STATE_DIGEST_LEN],
                )
                .as_bytes()
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let binding = bytes[STATE_PREFIX_LEN..binding_end].to_vec();
        let mut cursor = binding_end;
        let payload_end = bytes.len() - STATE_DIGEST_LEN;
        let mut envelopes = Vec::with_capacity(envelope_count);
        for _ in 0..envelope_count {
            let length_end = cursor
                .checked_add(4)
                .filter(|end| *end <= payload_end)
                .ok_or(InventoryError::RestoreQuarantined)?;
            let length = u32::from_le_bytes(copy_array(&bytes[cursor..length_end])?) as usize;
            cursor = length_end;
            let end = cursor
                .checked_add(length)
                .filter(|end| *end <= payload_end)
                .ok_or(InventoryError::RestoreQuarantined)?;
            envelopes.push(
                CollaborativeSecretEnvelopeV1::from_bytes(&bytes[cursor..end])
                    .map_err(|_| InventoryError::Crypto)?,
            );
            cursor = end;
        }
        if cursor != payload_end {
            return Err(InventoryError::RestoreQuarantined);
        }
        validate_binding_shape(kind, &binding)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            kind,
            binding_digest: copy_array(&bytes[16..48])?,
            binding,
            envelopes,
        })
    }
}

fn validate_binding_shape(kind: StateKind, binding: &[u8]) -> Result<(), InventoryError> {
    match kind {
        StateKind::SharedPending | StateKind::SharedPendingRetired => {
            validate_pending_shared_binding(binding)
        }
        StateKind::SharedBound | StateKind::SharedBoundRetired => {
            let pending = pending_binding_from_bound(binding)?;
            validate_pending_shared_binding(pending)
        }
        StateKind::BpNonce => {
            if binding.len() == 140
                && binding.get(..8) == Some(b"DOMBPNV1")
                && binding.get(8..10) == Some(1u16.to_le_bytes().as_slice())
            {
                Ok(())
            } else {
                Err(InventoryError::RestoreQuarantined)
            }
        }
        StateKind::BpRound2Finalize | StateKind::BpProof => {
            if binding.len() < 220
                || binding.get(..8) != Some(b"DOMBPFV1")
                || binding.get(8..10) != Some(1u16.to_le_bytes().as_slice())
                || binding.get(10..18) != Some(b"DOMBPNV1")
            {
                return Err(InventoryError::RestoreQuarantined);
            }
            let extra_len = u32::from_le_bytes(copy_array(
                binding
                    .get(216..220)
                    .ok_or(InventoryError::RestoreQuarantined)?,
            )?) as usize;
            if binding.len() != 220usize.saturating_add(extra_len) {
                return Err(InventoryError::RestoreQuarantined);
            }
            validate_binding_shape(
                StateKind::BpNonce,
                binding
                    .get(10..150)
                    .ok_or(InventoryError::RestoreQuarantined)?,
            )
        }
        StateKind::TerminalSession => validate_terminal_session_binding(binding),
    }
}

fn validate_terminal_session_binding(binding: &[u8]) -> Result<(), InventoryError> {
    if binding.len() != 76
        || binding.get(..8) != Some(b"DOMF7TM1")
        || binding.get(8..10) != Some(1u16.to_le_bytes().as_slice())
        || binding.get(10..42) == Some([0u8; 32].as_slice())
        || binding.get(44..76) == Some([0u8; 32].as_slice())
    {
        return Err(InventoryError::RestoreQuarantined);
    }
    let phase = u16::from_le_bytes(copy_array(
        binding
            .get(42..44)
            .ok_or(InventoryError::RestoreQuarantined)?,
    )?);
    if !matches!(phase, 190 | 200 | 250 | 255) {
        return Err(InventoryError::RestoreQuarantined);
    }
    Ok(())
}

fn validate_pending_shared_binding(binding: &[u8]) -> Result<(), InventoryError> {
    if binding.len() < 240
        || binding.get(..8) != Some(b"DOMSBLP1")
        || binding.get(8..10) != Some(1u16.to_le_bytes().as_slice())
    {
        return Err(InventoryError::RestoreQuarantined);
    }
    let roster_len = u16::from_le_bytes(copy_array(
        binding
            .get(74..76)
            .ok_or(InventoryError::RestoreQuarantined)?,
    )?) as usize;
    let expected = 176usize
        .checked_add(
            roster_len
                .checked_mul(32)
                .ok_or(InventoryError::RestoreQuarantined)?,
        )
        .ok_or(InventoryError::RestoreQuarantined)?;
    if !(2..=16).contains(&roster_len) || binding.len() != expected {
        return Err(InventoryError::RestoreQuarantined);
    }
    Ok(())
}

fn pending_binding_from_bound(binding: &[u8]) -> Result<&[u8], InventoryError> {
    if binding.len() < 14 + 240 + 32
        || binding.get(..8) != Some(b"DOMSBLB1")
        || binding.get(8..10) != Some(1u16.to_le_bytes().as_slice())
    {
        return Err(InventoryError::RestoreQuarantined);
    }
    let pending_len = u32::from_le_bytes(copy_array(
        binding
            .get(10..14)
            .ok_or(InventoryError::RestoreQuarantined)?,
    )?) as usize;
    let pending_end = 14usize
        .checked_add(pending_len)
        .ok_or(InventoryError::RestoreQuarantined)?;
    if pending_end
        .checked_add(32)
        .filter(|length| *length == binding.len())
        .is_none()
    {
        return Err(InventoryError::RestoreQuarantined);
    }
    binding
        .get(14..pending_end)
        .ok_or(InventoryError::RestoreQuarantined)
}

impl LiveStoreInventoryV1 {
    fn publish_collaborative_state(&self, state: &StateRecord) -> Result<(), InventoryError> {
        let final_name = state_name(state.binding_digest, state.kind);
        let final_component = ValidatedComponent::registered(&final_name)?;
        match self
            .collaborative_secrets()?
            .read_bounded_file(&final_component, MAX_STATE_LEN)
        {
            Ok(existing) if existing == state.bytes => return Ok(()),
            Ok(_) => return Err(InventoryError::RestoreQuarantined),
            Err(LinuxCapabilityError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        let staging_name = format!(".{final_name}.staging");
        let staging_component = ValidatedComponent::registered(&staging_name)?;
        if let Ok(stale) = self
            .collaborative_secrets()?
            .open_file(&staging_component, false)
        {
            self.collaborative_secrets()?
                .unlink_verified_file(&staging_component, &stale)?;
        }
        let staging = self
            .collaborative_secrets()?
            .create_immutable_file(&staging_component, &state.bytes)?;
        self.collaborative_secrets()?.rename_no_replace(
            &staging_component,
            &final_component,
            &staging,
        )?;
        let persisted = self
            .collaborative_secrets()?
            .read_bounded_file(&final_component, MAX_STATE_LEN)?;
        if persisted != state.bytes {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(())
    }

    fn load_collaborative_state(
        &self,
        binding_digest: [u8; 32],
        kind: StateKind,
    ) -> Result<StateRecord, InventoryError> {
        let name = state_name(binding_digest, kind);
        let bytes = self
            .collaborative_secrets()?
            .read_bounded_file(&ValidatedComponent::registered(&name)?, MAX_STATE_LEN)?;
        let state = StateRecord::from_bytes(&bytes)?;
        if state.kind != kind || state.binding_digest != binding_digest {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(state)
    }

    fn delete_collaborative_state(
        &self,
        binding_digest: [u8; 32],
        kind: StateKind,
    ) -> Result<(), InventoryError> {
        let component = ValidatedComponent::registered(&state_name(binding_digest, kind))?;
        let retained = self.collaborative_secrets()?.open_file(&component, false)?;
        self.collaborative_secrets()?
            .unlink_verified_file(&component, &retained)?;
        Ok(())
    }
}

pub(super) fn recover_collaborative_state(
    store: &mut LiveStoreInventoryV1,
) -> Result<(), InventoryError> {
    if store.collaborative_secrets.is_none() {
        return Ok(());
    }
    let mut staging = Vec::new();
    store
        .collaborative_secrets()?
        .scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if name.starts_with('.') && name.ends_with(".staging") {
                staging.push(name.to_owned());
            }
            Ok(())
        })?;
    for name in staging {
        let component = ValidatedComponent::registered(&name)?;
        let retained = store
            .collaborative_secrets()?
            .open_file(&component, false)?;
        store
            .collaborative_secrets()?
            .unlink_verified_file(&component, &retained)?;
    }
    // Authenticate every complete intent before applying a terminal deletion.
    // A retained round2/finalizer state is the commit intent that retires its
    // BP nonce. A retained proof is the commit intent that retires its
    // finalizer. This makes both multi-file transitions converge after crash.
    audit_namespace(store)?;
    let mut retire = Vec::new();
    let mut shared_promotions: Vec<(Vec<u8>, [u8; 32])> = Vec::new();
    let mut shared_pending: Vec<Vec<u8>> = Vec::new();
    let mut shared_pending_retired: Vec<Vec<u8>> = Vec::new();
    let namespace = store.collaborative_secrets()?;
    namespace.scan_lexicographic(|name, node| {
        if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        let bytes =
            namespace.read_bounded_file(&ValidatedComponent::registered(name)?, MAX_STATE_LEN)?;
        let state = StateRecord::from_bytes(&bytes)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        if matches!(state.kind, StateKind::BpRound2Finalize | StateKind::BpProof) {
            let nonce_aad = state
                .binding
                .get(10..150)
                .ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
            let nonce_digest = *dom_crypto::blake2b_256(nonce_aad).as_bytes();
            retire.push((nonce_digest, StateKind::BpNonce));
            if state.kind == StateKind::BpProof {
                retire.push((state.binding_digest, StateKind::BpRound2Finalize));
            }
        }
        if state.kind == StateKind::SharedBound {
            let pending = pending_binding_from_bound(&state.binding)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if shared_promotions.iter().any(|(existing, bound_digest)| {
                existing.as_slice() == pending && *bound_digest != state.binding_digest
            }) {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            shared_promotions.push((pending.to_vec(), state.binding_digest));
        }
        if state.kind == StateKind::SharedPending {
            shared_pending.push(state.binding.clone());
        }
        if state.kind == StateKind::SharedPendingRetired {
            shared_pending_retired.push(state.binding.clone());
            retire.push((state.binding_digest, StateKind::SharedPending));
        }
        if state.kind == StateKind::SharedBoundRetired {
            retire.push((state.binding_digest, StateKind::SharedBound));
        }
        Ok(())
    })?;
    for (pending, _) in shared_promotions {
        let pending_digest = *dom_crypto::blake2b_256(&pending).as_bytes();
        let has_pending = shared_pending.iter().any(|binding| binding == &pending);
        let has_pending_retired = shared_pending_retired
            .iter()
            .any(|binding| binding == &pending);
        // A bound record is a valid commit intent only if the authenticated
        // predecessor or its exact retirement tombstone also exists.  Never
        // manufacture ancestry for an orphaned bound record.
        if !has_pending && !has_pending_retired {
            return Err(InventoryError::RestoreQuarantined);
        }
        if has_pending {
            require_present_exact(store, pending_digest, StateKind::SharedPending, &pending)?;
        }
        if has_pending_retired {
            require_present_exact(
                store,
                pending_digest,
                StateKind::SharedPendingRetired,
                &pending,
            )?;
        } else {
            let tombstone = StateRecord::new(StateKind::SharedPendingRetired, &pending, &[])?;
            store.publish_collaborative_state(&tombstone)?;
        }
        if has_pending {
            delete_if_present(store, pending_digest, StateKind::SharedPending)?;
        }
    }
    for (digest, kind) in retire {
        delete_if_present(store, digest, kind)?;
    }
    Ok(())
}

pub(super) fn audit_namespace(store: &LiveStoreInventoryV1) -> Result<u64, InventoryError> {
    if store.collaborative_secrets.is_none() {
        return Ok(0);
    }
    let mut count = 0u64;
    let namespace = store.collaborative_secrets()?;
    namespace.scan_lexicographic(|name, node| {
        if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        let bytes =
            namespace.read_bounded_file(&ValidatedComponent::registered(name)?, MAX_STATE_LEN)?;
        let state = StateRecord::from_bytes(&bytes)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        if name != state_name(state.binding_digest, state.kind) {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        for (index, envelope) in state.envelopes.iter().enumerate() {
            // Round-2 is encrypted under the shorter nonce binding so that it
            // can be retransmitted from only the public nonce identity after
            // restart. Finalizer/proof envelopes use the complete finalizer
            // binding. A proof state deliberately retains the round-2
            // envelope as its second item for ACK-loss recovery.
            let binding = match (state.kind, index) {
                (StateKind::BpRound2Finalize, 0) | (StateKind::BpProof, 1) => state
                    .binding
                    .get(10..150)
                    .ok_or(LinuxCapabilityError::ExactBytesMismatch)?,
                _ => state.binding.as_slice(),
            };
            audit_collaborative_secret_envelope_v1(
                envelope,
                store
                    .storage_ids()
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
                store.core.nonce_epoch(),
                &store.master_key,
                binding,
            )
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        }
        count = count
            .checked_add(1)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        Ok(())
    })?;
    Ok(count)
}

#[cfg(any(test, feature = "evidence-only"))]
pub(super) fn has_epoch_bound_state(store: &LiveStoreInventoryV1) -> Result<bool, InventoryError> {
    if store.collaborative_secrets.is_none() {
        return Ok(false);
    }
    let mut found = false;
    let namespace = store.collaborative_secrets()?;
    namespace.scan_lexicographic(|name, node| {
        if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        let bytes =
            namespace.read_bounded_file(&ValidatedComponent::registered(name)?, MAX_STATE_LEN)?;
        let state = StateRecord::from_bytes(&bytes)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        if !state.envelopes.is_empty() {
            found = true;
        }
        Ok(())
    })?;
    Ok(found)
}

impl SharedBlindingVaultV1 for ContractsNonceVaultV1 {
    type Error = InventoryError;

    fn seal_fresh_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        material: SharedBlindingMaterialV1,
        capability: SharedBlindingSealCapabilityV1,
    ) -> Result<(), Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        let bundle = seal_shared_blinding_bundle_v1(
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            binding,
            material,
            capability,
        )
        .map_err(|_| InventoryError::Crypto)?;
        let record = StateRecord::new(
            StateKind::SharedPending,
            &binding.to_aad_bytes(),
            &[bundle.primary(), bundle.backup()],
        )?;
        self.store.publish_collaborative_state(&record)?;
        let durable = self
            .store
            .load_collaborative_state(binding.binding_digest_v1(), StateKind::SharedPending)?;
        if durable.bytes != record.bytes {
            return Err(InventoryError::RestoreQuarantined);
        }
        collaborative_crash_hook("shared-pending-after-persist");
        Ok(())
    }

    fn open_persisted_pending_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: SharedBlindingImportCapabilityV1,
    ) -> Result<SharedBlindingMaterialV1, Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        require_absent(
            &self.store,
            binding.binding_digest_v1(),
            StateKind::SharedPendingRetired,
        )?;
        let record = self
            .store
            .load_collaborative_state(binding.binding_digest_v1(), StateKind::SharedPending)?;
        if record.binding != binding.to_aad_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        open_pending_shared_blinding_record_v1(
            &record.envelopes[0],
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            binding,
            capability,
        )
        .map_err(|_| InventoryError::Crypto)
    }

    fn confirm_pending_backup_roundtrip(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: DurableShareBackupAckCapabilityV1,
    ) -> Result<ShareBackupAckV1, Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        require_absent(
            &self.store,
            binding.binding_digest_v1(),
            StateKind::SharedPendingRetired,
        )?;
        let record = self
            .store
            .load_collaborative_state(binding.binding_digest_v1(), StateKind::SharedPending)?;
        if record.binding != binding.to_aad_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        acknowledge_pending_shared_blinding_backup_v1(
            &record.envelopes[1],
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            binding,
            capability,
        )
        .map_err(|_| InventoryError::Crypto)
    }

    fn bind_recovery_capsule(
        &mut self,
        pending: &PendingSharedBlindingBindingV1,
        bound: &SharedBlindingBindingV1,
        capability: SharedBlindingBindingUpgradeCapabilityV1,
    ) -> Result<(), Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        if bound.pending_binding() != pending {
            return Err(InventoryError::Canonical);
        }
        require_absent(
            &self.store,
            pending.binding_digest_v1(),
            StateKind::SharedPendingRetired,
        )?;
        require_absent(
            &self.store,
            bound.binding_digest_v1(),
            StateKind::SharedBound,
        )?;
        let provisional = self
            .store
            .load_collaborative_state(pending.binding_digest_v1(), StateKind::SharedPending)?;
        if provisional.binding != pending.to_aad_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        let upgraded = upgrade_shared_blinding_bundle_v1(
            &provisional.envelopes[0],
            &provisional.envelopes[1],
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            pending,
            bound,
            capability,
        )
        .map_err(|_| InventoryError::Crypto)?;
        let successor = StateRecord::new(
            StateKind::SharedBound,
            &bound.to_aad_bytes(),
            &[upgraded.primary(), upgraded.backup()],
        )?;
        self.store.publish_collaborative_state(&successor)?;
        let durable = self
            .store
            .load_collaborative_state(bound.binding_digest_v1(), StateKind::SharedBound)?;
        if durable.bytes != successor.bytes {
            return Err(InventoryError::RestoreQuarantined);
        }
        let retired = StateRecord::new(
            StateKind::SharedPendingRetired,
            &pending.to_aad_bytes(),
            &[],
        )?;
        self.store.publish_collaborative_state(&retired)?;
        self.store
            .delete_collaborative_state(pending.binding_digest_v1(), StateKind::SharedPending)?;
        Ok(())
    }

    fn open_persisted_share(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: SharedBlindingImportCapabilityV1,
    ) -> Result<SharedBlindingMaterialV1, Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        require_absent(
            &self.store,
            binding.binding_digest_v1(),
            StateKind::SharedBoundRetired,
        )?;
        require_present_exact(
            &self.store,
            binding.pending_binding().binding_digest_v1(),
            StateKind::SharedPendingRetired,
            &binding.pending_binding().to_aad_bytes(),
        )?;
        require_absent(
            &self.store,
            binding.pending_binding().binding_digest_v1(),
            StateKind::SharedPending,
        )?;
        let record = self
            .store
            .load_collaborative_state(binding.binding_digest_v1(), StateKind::SharedBound)?;
        if record.binding != binding.to_aad_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        open_shared_blinding_record_v1(
            &record.envelopes[0],
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            binding,
            capability,
        )
        .map_err(|_| InventoryError::Crypto)
    }

    fn confirm_backup_roundtrip(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: DurableShareBackupAckCapabilityV1,
    ) -> Result<ShareBackupAckV1, Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        require_absent(
            &self.store,
            binding.binding_digest_v1(),
            StateKind::SharedBoundRetired,
        )?;
        require_present_exact(
            &self.store,
            binding.pending_binding().binding_digest_v1(),
            StateKind::SharedPendingRetired,
            &binding.pending_binding().to_aad_bytes(),
        )?;
        let record = self
            .store
            .load_collaborative_state(binding.binding_digest_v1(), StateKind::SharedBound)?;
        if record.binding != binding.to_aad_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        acknowledge_shared_blinding_backup_v1(
            &record.envelopes[1],
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            binding,
            capability,
        )
        .map_err(|_| InventoryError::Crypto)
    }

    fn retire_pending_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: SharedBlindingRetirementCapabilityV1,
    ) -> Result<(), Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        capability
            .authorize_pending(binding)
            .map_err(|_| InventoryError::Canonical)?;
        require_terminal_session_marker(&self.store, binding.session_id())?;
        require_absent(
            &self.store,
            binding.binding_digest_v1(),
            StateKind::SharedPendingRetired,
        )?;
        require_present_exact(
            &self.store,
            binding.binding_digest_v1(),
            StateKind::SharedPending,
            &binding.to_aad_bytes(),
        )?;
        let tombstone = StateRecord::new(
            StateKind::SharedPendingRetired,
            &binding.to_aad_bytes(),
            &[],
        )?;
        self.store.publish_collaborative_state(&tombstone)?;
        self.store
            .delete_collaborative_state(binding.binding_digest_v1(), StateKind::SharedPending)
    }

    fn retire_bound_share(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: SharedBlindingRetirementCapabilityV1,
    ) -> Result<(), Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        capability
            .authorize_bound(binding)
            .map_err(|_| InventoryError::Canonical)?;
        require_terminal_session_marker(&self.store, binding.session_id())?;
        require_absent(
            &self.store,
            binding.binding_digest_v1(),
            StateKind::SharedBoundRetired,
        )?;
        require_present_exact(
            &self.store,
            binding.binding_digest_v1(),
            StateKind::SharedBound,
            &binding.to_aad_bytes(),
        )?;
        let tombstone =
            StateRecord::new(StateKind::SharedBoundRetired, &binding.to_aad_bytes(), &[])?;
        self.store.publish_collaborative_state(&tombstone)?;
        self.store
            .delete_collaborative_state(binding.binding_digest_v1(), StateKind::SharedBound)
    }
}

impl RestartableSharedBlindingVaultV1 for ContractsNonceVaultV1 {
    fn locate_shared_blinding_after_restart(
        &mut self,
        request: &SharedBlindingRestartRequestV1,
        capability: SharedBlindingRestartLookupCapabilityV1,
    ) -> Result<LocatedSharedBlindingStageV1, Self::Error> {
        struct MatchingStages {
            pending: Option<PendingSharedBlindingBindingV1>,
            bound: Option<(
                SharedBlindingBindingV1,
                dom_crypto::recovery::RecoveryCapsule,
            )>,
            pending_retired: Option<PendingSharedBlindingBindingV1>,
            bound_retired: bool,
        }

        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        // Authenticate the complete namespace first so an unrelated live
        // mutation cannot be hidden by selecting only the requested record.
        audit_namespace(&self.store)?;
        let mut found = MatchingStages {
            pending: None,
            bound: None,
            pending_retired: None,
            bound_retired: false,
        };
        let namespace = self.store.collaborative_secrets()?;
        namespace.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let bytes = namespace
                .read_bounded_file(&ValidatedComponent::registered(name)?, MAX_STATE_LEN)?;
            let record = StateRecord::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            match record.kind {
                StateKind::SharedPending => {
                    if let Some(binding) = capability
                        .pending_candidate(request, &record.binding)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    {
                        if found.pending.replace(binding).is_some() {
                            return Err(LinuxCapabilityError::ExactBytesMismatch);
                        }
                    }
                }
                StateKind::SharedBound => {
                    let Some(binding) = capability
                        .bound_candidate(request, &record.binding)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    else {
                        return Ok(());
                    };
                    // A two-envelope legacy bound record has only a capsule
                    // hash and is deliberately ineligible for F7 restart.
                    let capsule_envelope = record
                        .envelopes
                        .get(2)
                        .ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
                    let capsule = open_shared_blinding_recovery_capsule_v1(
                        capsule_envelope,
                        self.store
                            .storage_ids()
                            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
                        self.store.core.nonce_epoch(),
                        &self.store.master_key,
                        &binding,
                    )
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    if found.bound.replace((binding, capsule)).is_some() {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                }
                StateKind::SharedPendingRetired => {
                    if let Some(binding) = capability
                        .pending_candidate(request, &record.binding)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    {
                        if found.pending_retired.replace(binding).is_some() {
                            return Err(LinuxCapabilityError::ExactBytesMismatch);
                        }
                    }
                }
                // Clippy would fold this into a match guard. The condition is
                // fallible and multi-line: a `?` in a guard is harder to read
                // and to audit than the explicit arm, and this arm decides a
                // quarantine.
                #[allow(clippy::collapsible_match)]
                StateKind::SharedBoundRetired => {
                    if capability
                        .bound_candidate(request, &record.binding)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                        .is_some()
                    {
                        found.bound_retired = true;
                    }
                }
                _ => {}
            }
            Ok(())
        })?;

        if found.bound_retired {
            return Err(InventoryError::RestoreQuarantined);
        }
        if let Some((binding, capsule)) = found.bound {
            let embedded_pending = binding.pending_binding();
            if found
                .pending
                .as_ref()
                .is_some_and(|pending| pending != embedded_pending)
                || found
                    .pending_retired
                    .as_ref()
                    .is_some_and(|pending| pending != embedded_pending)
                || (found.pending.is_none() && found.pending_retired.is_none())
            {
                return Err(InventoryError::RestoreQuarantined);
            }

            // The immutable bound record is the promotion commit intent.  A
            // crash may leave the pending record, omit its tombstone, or stop
            // between tombstone publication and pending deletion.  Converge
            // all three legal prefixes before releasing the bound authority.
            if found.pending_retired.is_none() {
                let tombstone = StateRecord::new(
                    StateKind::SharedPendingRetired,
                    &embedded_pending.to_aad_bytes(),
                    &[],
                )?;
                self.store.publish_collaborative_state(&tombstone)?;
            }
            require_present_exact(
                &self.store,
                embedded_pending.binding_digest_v1(),
                StateKind::SharedPendingRetired,
                &embedded_pending.to_aad_bytes(),
            )?;
            if found.pending.is_some() {
                require_present_exact(
                    &self.store,
                    embedded_pending.binding_digest_v1(),
                    StateKind::SharedPending,
                    &embedded_pending.to_aad_bytes(),
                )?;
                self.store.delete_collaborative_state(
                    embedded_pending.binding_digest_v1(),
                    StateKind::SharedPending,
                )?;
            }
            require_absent(
                &self.store,
                embedded_pending.binding_digest_v1(),
                StateKind::SharedPending,
            )?;
            capability
                .locate_bound(request, binding, capsule)
                .map_err(|_| InventoryError::RestoreQuarantined)
        } else {
            // A tombstone without its authenticated live bound successor is
            // either a terminal retirement or a torn/divergent promotion; it
            // must never resurrect the provisional share.
            if found.pending_retired.is_some() {
                return Err(InventoryError::RestoreQuarantined);
            }
            capability
                .locate_pending(
                    request,
                    found
                        .pending
                        .ok_or(InventoryError::NoMatchingSharedBlinding)?,
                )
                .map_err(|_| InventoryError::RestoreQuarantined)
        }
    }

    fn bind_recovery_capsule_restartable(
        &mut self,
        pending: &PendingSharedBlindingBindingV1,
        bound: &SharedBlindingBindingV1,
        capsule: &dom_crypto::recovery::RecoveryCapsule,
        capability: SharedBlindingBindingUpgradeCapabilityV1,
    ) -> Result<(), Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        if bound.pending_binding() != pending {
            return Err(InventoryError::Canonical);
        }
        require_absent(
            &self.store,
            pending.binding_digest_v1(),
            StateKind::SharedPendingRetired,
        )?;
        require_absent(
            &self.store,
            bound.binding_digest_v1(),
            StateKind::SharedBound,
        )?;
        let provisional = self
            .store
            .load_collaborative_state(pending.binding_digest_v1(), StateKind::SharedPending)?;
        if provisional.binding != pending.to_aad_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        let upgraded = upgrade_shared_blinding_bundle_restartable_v1(
            &provisional.envelopes[0],
            &provisional.envelopes[1],
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            pending,
            bound,
            capsule,
            capability,
        )
        .map_err(|_| InventoryError::Crypto)?;
        let capsule_envelope = upgraded
            .recovery_capsule()
            .ok_or(InventoryError::RestoreQuarantined)?;
        let successor = StateRecord::new(
            StateKind::SharedBound,
            &bound.to_aad_bytes(),
            &[upgraded.primary(), upgraded.backup(), capsule_envelope],
        )?;
        self.store.publish_collaborative_state(&successor)?;
        let durable = self
            .store
            .load_collaborative_state(bound.binding_digest_v1(), StateKind::SharedBound)?;
        if durable.bytes != successor.bytes {
            return Err(InventoryError::RestoreQuarantined);
        }
        collaborative_crash_hook("shared-bound-after-persist-before-pending-tombstone");
        let retired = StateRecord::new(
            StateKind::SharedPendingRetired,
            &pending.to_aad_bytes(),
            &[],
        )?;
        self.store.publish_collaborative_state(&retired)?;
        collaborative_crash_hook("shared-pending-tombstone-after-persist-before-delete");
        self.store
            .delete_collaborative_state(pending.binding_digest_v1(), StateKind::SharedPending)?;
        Ok(())
    }
}

impl CollaborativeBpNonceVaultV1 for ContractsNonceVaultV1 {
    type Error = InventoryError;

    fn seal_fresh_material(
        &mut self,
        binding: &CollaborativeBpNonceBindingV1,
        material: CollaborativeBpNonceMaterialV1,
        capability: CollaborativeBpNonceSealCapabilityV1,
    ) -> Result<(), Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        let envelope = seal_collaborative_bp_nonce_record_v1(
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            binding,
            material,
            capability,
        )
        .map_err(|_| InventoryError::Crypto)?;
        let record = StateRecord::new(StateKind::BpNonce, &binding.to_aad_bytes(), &[&envelope])?;
        self.store.publish_collaborative_state(&record)?;
        Ok(())
    }

    fn open_persisted_material(
        &mut self,
        binding: &CollaborativeBpNonceBindingV1,
        capability: CollaborativeBpNonceImportCapabilityV1,
    ) -> Result<CollaborativeBpNonceMaterialV1, Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        let record = self
            .store
            .load_collaborative_state(binding.binding_digest_v1(), StateKind::BpNonce)?;
        if record.binding != binding.to_aad_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        open_collaborative_bp_nonce_record_v1(
            &record.envelopes[0],
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            binding,
            capability,
        )
        .map_err(|_| InventoryError::Crypto)
    }

    fn persist_round2_and_consume_material(
        &mut self,
        binding: &CollaborativeBpFinalizeBindingV1,
        statement: &BpStatementV1,
        continuation: CollaborativeBpFinalizeContinuationV1,
        share: BpRound2ShareV1,
        capability: CollaborativeBpRound2PersistenceCapabilityV1,
    ) -> Result<DurableBpRound2TransportV1, Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        let nonce_binding = binding.nonce_binding();
        let nonce = self
            .store
            .load_collaborative_state(nonce_binding.binding_digest_v1(), StateKind::BpNonce)?;
        if nonce.binding != nonce_binding.to_aad_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        let bundle = seal_collaborative_bp_round2_bundle_v1(
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            binding,
            statement,
            continuation,
            share,
            capability,
        )
        .map_err(|_| InventoryError::Crypto)?;
        let record = StateRecord::new(
            StateKind::BpRound2Finalize,
            &binding.to_aad_bytes(),
            &[bundle.round2(), bundle.finalize()],
        )?;
        self.store.publish_collaborative_state(&record)?;
        let (finalize_import, round2_import) = bundle.into_import_capabilities();
        let durable = self
            .store
            .load_collaborative_state(binding.binding_digest_v1(), StateKind::BpRound2Finalize)?;
        open_collaborative_bp_finalize_record_v1(
            &durable.envelopes[1],
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            binding,
            statement,
            finalize_import,
        )
        .map_err(|_| InventoryError::Crypto)?;
        let transport = open_collaborative_bp_round2_record_v1(
            &durable.envelopes[0],
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            nonce_binding,
            statement,
            round2_import,
        )
        .map_err(|_| InventoryError::Crypto)?;
        self.store
            .delete_collaborative_state(nonce_binding.binding_digest_v1(), StateKind::BpNonce)?;
        Ok(transport)
    }

    fn open_persisted_round2(
        &mut self,
        binding: &CollaborativeBpNonceBindingV1,
        statement: &BpStatementV1,
        capability: CollaborativeBpRound2ImportCapabilityV1,
    ) -> Result<DurableBpRound2TransportV1, Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        require_absent(&self.store, binding.binding_digest_v1(), StateKind::BpNonce)?;
        let record = load_round2_by_nonce(&self.store, binding)?;
        let round2_index = match record.kind {
            StateKind::BpRound2Finalize => 0,
            StateKind::BpProof => 1,
            _ => return Err(InventoryError::RestoreQuarantined),
        };
        open_collaborative_bp_round2_record_v1(
            &record.envelopes[round2_index],
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            binding,
            statement,
            capability,
        )
        .map_err(|_| InventoryError::Crypto)
    }

    fn open_persisted_finalize_continuation(
        &mut self,
        binding: &CollaborativeBpFinalizeBindingV1,
        statement: &BpStatementV1,
        capability: CollaborativeBpFinalizeImportCapabilityV1,
    ) -> Result<CollaborativeBpFinalizeContinuationV1, Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        require_absent(
            &self.store,
            binding.nonce_binding().binding_digest_v1(),
            StateKind::BpNonce,
        )?;
        let record = self
            .store
            .load_collaborative_state(binding.binding_digest_v1(), StateKind::BpRound2Finalize)?;
        if record.binding != binding.to_aad_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        open_collaborative_bp_finalize_record_v1(
            &record.envelopes[1],
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            binding,
            statement,
            capability,
        )
        .map_err(|_| InventoryError::Crypto)
    }

    fn persist_verified_proof_and_consume_finalize(
        &mut self,
        binding: &CollaborativeBpFinalizeBindingV1,
        statement: &BpStatementV1,
        proof: RangeProof739,
        capability: CollaborativeBpProofPersistenceCapabilityV1,
    ) -> Result<DurableBpProofTransportV1, Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        require_absent(
            &self.store,
            binding.nonce_binding().binding_digest_v1(),
            StateKind::BpNonce,
        )?;
        let continuation = self
            .store
            .load_collaborative_state(binding.binding_digest_v1(), StateKind::BpRound2Finalize)?;
        if continuation.binding != binding.to_aad_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        let sealed = seal_collaborative_bp_proof_record_v1(
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            binding,
            proof,
            capability,
        )
        .map_err(|_| InventoryError::Crypto)?;
        let record = StateRecord::new(
            StateKind::BpProof,
            &binding.to_aad_bytes(),
            &[sealed.envelope(), &continuation.envelopes[0]],
        )?;
        self.store.publish_collaborative_state(&record)?;
        let import = sealed.into_import_capability();
        let durable = self
            .store
            .load_collaborative_state(binding.binding_digest_v1(), StateKind::BpProof)?;
        let transport = open_collaborative_bp_proof_record_v1(
            &durable.envelopes[0],
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            binding,
            statement,
            import,
        )
        .map_err(|_| InventoryError::Crypto)?;
        self.store
            .delete_collaborative_state(binding.binding_digest_v1(), StateKind::BpRound2Finalize)?;
        Ok(transport)
    }

    fn open_persisted_proof(
        &mut self,
        binding: &CollaborativeBpFinalizeBindingV1,
        statement: &BpStatementV1,
        capability: CollaborativeBpProofImportCapabilityV1,
    ) -> Result<DurableBpProofTransportV1, Self::Error> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        require_absent(
            &self.store,
            binding.nonce_binding().binding_digest_v1(),
            StateKind::BpNonce,
        )?;
        require_absent(
            &self.store,
            binding.binding_digest_v1(),
            StateKind::BpRound2Finalize,
        )?;
        let record = self
            .store
            .load_collaborative_state(binding.binding_digest_v1(), StateKind::BpProof)?;
        if record.binding != binding.to_aad_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        open_collaborative_bp_proof_record_v1(
            &record.envelopes[0],
            self.store.storage_ids()?,
            self.store.core.nonce_epoch(),
            &self.store.master_key,
            binding,
            statement,
            capability,
        )
        .map_err(|_| InventoryError::Crypto)
    }
}

fn load_round2_by_nonce(
    store: &LiveStoreInventoryV1,
    nonce: &CollaborativeBpNonceBindingV1,
) -> Result<StateRecord, InventoryError> {
    let mut found = None;
    let namespace = store.collaborative_secrets()?;
    namespace.scan_lexicographic(|name, node| {
        if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        if !name.ends_with(".bp-round2") && !name.ends_with(".bp-proof") {
            return Ok(());
        }
        let bytes =
            namespace.read_bounded_file(&ValidatedComponent::registered(name)?, MAX_STATE_LEN)?;
        let record = StateRecord::from_bytes(&bytes)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        if matches!(
            record.kind,
            StateKind::BpRound2Finalize | StateKind::BpProof
        ) && record.binding.get(10..150) == Some(nonce.to_aad_bytes().as_slice())
        {
            if found.is_some() {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            found = Some(record);
        }
        Ok(())
    })?;
    found.ok_or(InventoryError::RestoreQuarantined)
}

fn require_absent(
    store: &LiveStoreInventoryV1,
    digest: [u8; 32],
    kind: StateKind,
) -> Result<(), InventoryError> {
    let component = ValidatedComponent::registered(&state_name(digest, kind))?;
    match store
        .collaborative_secrets()?
        .read_bounded_file(&component, MAX_STATE_LEN)
    {
        Err(LinuxCapabilityError::NotFound) => Ok(()),
        Ok(_) => Err(InventoryError::RestoreQuarantined),
        Err(error) => Err(error.into()),
    }
}

fn require_present_exact(
    store: &LiveStoreInventoryV1,
    digest: [u8; 32],
    kind: StateKind,
    binding: &[u8],
) -> Result<(), InventoryError> {
    let record = store.load_collaborative_state(digest, kind)?;
    if record.binding != binding || record.binding_digest != digest {
        return Err(InventoryError::RestoreQuarantined);
    }
    Ok(())
}

fn require_terminal_session_marker(
    store: &LiveStoreInventoryV1,
    session_id: &[u8; 32],
) -> Result<(), InventoryError> {
    let mut found = None;
    let namespace = store.collaborative_secrets()?;
    namespace.scan_lexicographic(|name, node| {
        if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        if !name.ends_with(".terminal-session") {
            return Ok(());
        }
        let bytes =
            namespace.read_bounded_file(&ValidatedComponent::registered(name)?, MAX_STATE_LEN)?;
        let record = StateRecord::from_bytes(&bytes)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        if record.kind == StateKind::TerminalSession
            && record.binding.get(10..42) == Some(session_id.as_slice())
            && found.replace(record.binding_digest).is_some()
        {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        Ok(())
    })?;
    found.map(|_| ()).ok_or(InventoryError::RestoreQuarantined)
}

fn delete_if_present(
    store: &LiveStoreInventoryV1,
    digest: [u8; 32],
    kind: StateKind,
) -> Result<(), InventoryError> {
    let component = ValidatedComponent::registered(&state_name(digest, kind))?;
    match store.collaborative_secrets()?.open_file(&component, false) {
        Ok(retained) => {
            store
                .collaborative_secrets()?
                .unlink_verified_file(&component, &retained)?;
            Ok(())
        }
        Err(LinuxCapabilityError::NotFound) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

impl ContractsNonceVaultV1 {
    /// Persists a one-shot, independently authenticated terminal-session
    /// bridge before collaborative material may be retired.
    pub fn register_terminal_collaborative_session(
        &mut self,
        evidence: TerminalCollaborativeSessionEvidenceV1,
    ) -> Result<(), InventoryError> {
        self.store.revalidate_authority()?;
        self.ensure_collaborative_namespace()?;
        let (session_id, phase, record_digest) = evidence.into_parts();
        let mut binding = Vec::with_capacity(76);
        binding.extend_from_slice(b"DOMF7TM1");
        binding.extend_from_slice(&1u16.to_le_bytes());
        binding.extend_from_slice(&session_id);
        binding.extend_from_slice(&(phase as u16).to_le_bytes());
        binding.extend_from_slice(&record_digest);
        let marker = StateRecord::new(StateKind::TerminalSession, &binding, &[])?;
        self.store.publish_collaborative_state(&marker)?;
        let durable = self
            .store
            .load_collaborative_state(marker.binding_digest, StateKind::TerminalSession)?;
        if durable.bytes != marker.bytes {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(())
    }

    fn ensure_collaborative_namespace(&mut self) -> Result<(), InventoryError> {
        let generation = self.store.generation.retained_alias()?;
        ensure_optional_namespace(
            &generation,
            &mut self.store.collaborative_secrets,
            "collaborative-secrets",
        )?;
        retain_authority_namespace_alias(
            &self.store.collaborative_secrets,
            &self.store.authority.collaborative_secrets,
        )
    }
}

fn state_name(binding_digest: [u8; 32], kind: StateKind) -> String {
    format!("{}.{}", hex_lower(&binding_digest), kind.suffix())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], InventoryError> {
    bytes
        .try_into()
        .map_err(|_| InventoryError::RestoreQuarantined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BudgetPolicyProfileV1, BudgetPolicyV1, BUDGET_POLICY_LEN};
    use cap_std::fs::Dir;
    use dom_adaptor::{
        contribute_vault_backed_blinding_share_v1,
        resume_vault_backed_blinding_share_after_restart_v1, DirectionV1,
        RestartedSessionBlindingShareV1, SharedBlindingRestartRequestV1, SharedBlindingVaultError,
        TrustedChainIdV1,
    };
    use dom_core::Hash256;
    use dom_crypto::recovery::RecoveryCapsule;
    use dom_scriptless_crypto::{
        authoritative_storage_hash_v1, Passphrase, StorageHashDomainV1, StorageIdsV1,
    };
    use static_assertions::assert_not_impl_any;
    use std::{
        error::Error,
        fs::{self, File},
        os::unix::{fs::PermissionsExt, process::ExitStatusExt},
        path::{Path, PathBuf},
        process::{self, Command},
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    assert_not_impl_any!(SharedBlindingRestartRequestV1: Clone, Copy, std::fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(SharedBlindingRestartLookupCapabilityV1: Clone, Copy, std::fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(LocatedSharedBlindingStageV1: Clone, Copy, std::fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(RestartedSessionBlindingShareV1: Clone, Copy, std::fmt::Debug, Eq, PartialEq);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn create() -> Result<Self, Box<dyn Error>> {
            loop {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "dom-contracts-shared-restart-{}-{sequence}",
                    process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                        return Ok(Self { path });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(Box::new(error)),
                }
            }
        }

        fn capability(&self) -> Result<Arc<Dir>, Box<dyn Error>> {
            Ok(Arc::new(Dir::from_std_file(File::open(&self.path)?)))
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn passphrase() -> Result<Passphrase, Box<dyn Error>> {
        Ok(Passphrase::new(b"shared-restart-test-passphrase".to_vec())?)
    }

    fn policy() -> Result<BudgetPolicyV1, Box<dyn Error>> {
        let mut bytes = [0; BUDGET_POLICY_LEN];
        bytes[..8].copy_from_slice(b"DOMNVBP1");
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[10] = BudgetPolicyProfileV1::EvidenceOnly as u8;
        bytes[11] = 1;
        bytes[16..48].fill(0x41);
        bytes[48..56].copy_from_slice(&100u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&50u64.to_le_bytes());
        bytes[64..68].copy_from_slice(&10u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&25u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&3_600u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&60u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&86_400u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&1u64.to_le_bytes());
        let digest =
            authoritative_storage_hash_v1(StorageHashDomainV1::BudgetPolicy, &bytes[..112]);
        bytes[112..].copy_from_slice(&digest);
        Ok(BudgetPolicyV1::from_bytes(&bytes)?)
    }

    fn create_vault(directory: &TestDirectory) -> Result<ContractsNonceVaultV1, Box<dyn Error>> {
        Ok(ContractsNonceVaultV1::create_evidence_only(
            directory.capability()?,
            "shared-restart-vault",
            StorageIdsV1::new([0x11; 32], [0x44; 32])?,
            &passphrase()?,
            policy()?,
        )?)
    }

    fn open_vault(directory: &TestDirectory) -> Result<ContractsNonceVaultV1, Box<dyn Error>> {
        Ok(ContractsNonceVaultV1::open_evidence_only(
            directory.capability()?,
            "shared-restart-vault",
            passphrase()?,
            policy()?,
        )?)
    }

    fn chain() -> TrustedChainIdV1 {
        TrustedChainIdV1::from_authenticated_genesis(0x4657_4c42, &Hash256::from_bytes([0x19; 32]))
    }

    fn roster() -> [[u8; 32]; 2] {
        [[0x31; 32], [0x42; 32]]
    }

    fn request(
        chain: &TrustedChainIdV1,
        session_id: [u8; 32],
        role: DirectionV1,
        participant_index: u16,
        terms_hash: [u8; 32],
    ) -> Result<SharedBlindingRestartRequestV1, Box<dyn Error>> {
        Ok(SharedBlindingRestartRequestV1::new(
            chain,
            session_id,
            &roster(),
            role,
            participant_index,
            terms_hash,
        )?)
    }

    fn capsule() -> Result<RecoveryCapsule, Box<dyn Error>> {
        let mut bytes = [0u8; 96];
        bytes[..2].copy_from_slice(&1u16.to_le_bytes());
        bytes[14..16].copy_from_slice(&80u16.to_le_bytes());
        Ok(RecoveryCapsule::from_bytes(&bytes)?)
    }

    #[test]
    fn restart_lookup_recovers_pending_then_exact_bound_capsule() -> Result<(), Box<dyn Error>> {
        let directory =
            TestDirectory::create().map_err(|error| format!("create test directory: {error}"))?;
        let chain = chain();
        let session_id = [0x21; 32];
        let terms_hash = [0x51; 32];
        let mut vault =
            create_vault(&directory).map_err(|error| format!("create vault: {error}"))?;
        let pending = contribute_vault_backed_blinding_share_v1(
            &chain,
            session_id,
            &roster(),
            DirectionV1::Initiator,
            0,
            terms_hash,
            &mut vault,
        )
        .map_err(|error| format!("persist pending share: {error}"))?;
        let point = pending.public_key().clone();
        drop(pending);
        drop(vault);

        let mut vault =
            open_vault(&directory).map_err(|error| format!("first vault reopen: {error}"))?;
        let pending_request = request(&chain, session_id, DirectionV1::Initiator, 0, terms_hash)
            .map_err(|error| format!("build pending restart request: {error}"))?;
        let RestartedSessionBlindingShareV1::Pending(pending) =
            resume_vault_backed_blinding_share_after_restart_v1(pending_request, &mut vault)
                .map_err(|error| format!("resume pending share: {error}"))?
        else {
            return Err(Box::new(InventoryError::RestoreQuarantined));
        };
        assert_eq!(pending.public_key(), &point);
        let capsule = capsule().map_err(|error| format!("build recovery capsule: {error}"))?;
        pending
            .bind_recovery_capsule_restartable_v1(&capsule, &mut vault)
            .map_err(|error| format!("persist bound share and capsule: {error}"))?;
        drop(vault);

        let mut vault =
            open_vault(&directory).map_err(|error| format!("second vault reopen: {error}"))?;
        let bound_request = request(&chain, session_id, DirectionV1::Initiator, 0, terms_hash)
            .map_err(|error| format!("build bound restart request: {error}"))?;
        let RestartedSessionBlindingShareV1::Bound {
            capability,
            capsule: recovered,
        } = resume_vault_backed_blinding_share_after_restart_v1(bound_request, &mut vault)
            .map_err(|error| format!("resume bound share: {error}"))?
        else {
            return Err(Box::new(InventoryError::RestoreQuarantined));
        };
        assert_eq!(capability.public_key(), &point);
        assert_eq!(recovered, capsule);
        Ok(())
    }

    #[test]
    fn restart_lookup_distinguishes_authenticated_absence_from_quarantine(
    ) -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let mut vault = create_vault(&directory)?;
        let error = match resume_vault_backed_blinding_share_after_restart_v1(
            request(&chain(), [0x2a; 32], DirectionV1::Initiator, 0, [0x5a; 32])?,
            &mut vault,
        ) {
            Err(error) => error,
            Ok(_) => return Err(Box::new(InventoryError::RestoreQuarantined)),
        };
        assert!(matches!(
            error,
            SharedBlindingVaultError::Vault(InventoryError::NoMatchingSharedBlinding)
        ));
        Ok(())
    }

    #[test]
    fn restart_lookup_rejects_context_substitution_duplicates_and_legacy_bound(
    ) -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let chain = chain();
        let session_id = [0x22; 32];
        let terms_hash = [0x52; 32];
        let mut vault = create_vault(&directory)?;
        let pending = contribute_vault_backed_blinding_share_v1(
            &chain,
            session_id,
            &roster(),
            DirectionV1::Initiator,
            0,
            terms_hash,
            &mut vault,
        )?;
        assert!(resume_vault_backed_blinding_share_after_restart_v1(
            request(&chain, [0x23; 32], DirectionV1::Initiator, 0, terms_hash,)?,
            &mut vault,
        )
        .is_err());
        assert!(resume_vault_backed_blinding_share_after_restart_v1(
            request(&chain, session_id, DirectionV1::Responder, 0, terms_hash,)?,
            &mut vault,
        )
        .is_err());
        assert!(resume_vault_backed_blinding_share_after_restart_v1(
            request(&chain, session_id, DirectionV1::Initiator, 0, [0x53; 32],)?,
            &mut vault,
        )
        .is_err());
        let wrong_chain = TrustedChainIdV1::from_authenticated_genesis(
            0x4657_4c43,
            &Hash256::from_bytes([0x19; 32]),
        );
        assert!(resume_vault_backed_blinding_share_after_restart_v1(
            request(
                &wrong_chain,
                session_id,
                DirectionV1::Initiator,
                0,
                terms_hash,
            )?,
            &mut vault,
        )
        .is_err());
        assert!(resume_vault_backed_blinding_share_after_restart_v1(
            SharedBlindingRestartRequestV1::new(
                &chain,
                session_id,
                &[[0x31; 32], [0x43; 32]],
                DirectionV1::Initiator,
                0,
                terms_hash,
            )?,
            &mut vault,
        )
        .is_err());
        assert!(resume_vault_backed_blinding_share_after_restart_v1(
            request(&chain, session_id, DirectionV1::Initiator, 1, terms_hash,)?,
            &mut vault,
        )
        .is_err());

        pending.bind_recovery_capsule_v1(&capsule()?, &mut vault)?;
        drop(vault);
        let mut vault = open_vault(&directory)?;
        assert!(resume_vault_backed_blinding_share_after_restart_v1(
            request(&chain, session_id, DirectionV1::Initiator, 0, terms_hash,)?,
            &mut vault,
        )
        .is_err());
        drop(vault);

        let duplicate_directory = TestDirectory::create()?;
        let mut duplicate_vault = create_vault(&duplicate_directory)?;
        let first = contribute_vault_backed_blinding_share_v1(
            &chain,
            session_id,
            &roster(),
            DirectionV1::Initiator,
            0,
            terms_hash,
            &mut duplicate_vault,
        )?;
        let second = contribute_vault_backed_blinding_share_v1(
            &chain,
            session_id,
            &roster(),
            DirectionV1::Initiator,
            0,
            terms_hash,
            &mut duplicate_vault,
        )?;
        drop((first, second));
        assert!(resume_vault_backed_blinding_share_after_restart_v1(
            request(&chain, session_id, DirectionV1::Initiator, 0, terms_hash,)?,
            &mut duplicate_vault,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn crash_after_bound_publish_converges_to_exact_bound_stage() -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let chain = chain();
        let session_id = [0x24; 32];
        let terms_hash = [0x54; 32];
        let mut vault = create_vault(&directory)?;
        let pending = contribute_vault_backed_blinding_share_v1(
            &chain,
            session_id,
            &roster(),
            DirectionV1::Initiator,
            0,
            terms_hash,
            &mut vault,
        )?;
        let point = pending.public_key().clone();
        drop(pending);
        drop(vault);

        let marker = directory.path().join("bound-published.marker");
        let status = Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("runtime::linux::inventory::collaborative::tests::child_shared_blinding_upgrade_crashes_after_bound_publish")
            .arg("--ignored")
            .arg("--nocapture")
            .env("DOM_CONTRACTS_COLLABORATIVE_TEST_ROOT", directory.path())
            .env(
                "DOM_CONTRACTS_COLLABORATIVE_CRASH_CUT",
                "shared-bound-after-persist-before-pending-tombstone",
            )
            .env("DOM_CONTRACTS_COLLABORATIVE_CRASH_MARKER", &marker)
            .status()?;
        assert_eq!(status.signal(), Some(6));
        assert_eq!(
            fs::read(&marker)?,
            b"shared-bound-after-persist-before-pending-tombstone"
        );

        let mut vault = open_vault(&directory)?;
        let RestartedSessionBlindingShareV1::Bound {
            capability,
            capsule: recovered,
        } = resume_vault_backed_blinding_share_after_restart_v1(
            request(&chain, session_id, DirectionV1::Initiator, 0, terms_hash)?,
            &mut vault,
        )?
        else {
            return Err(Box::new(InventoryError::RestoreQuarantined));
        };
        assert_eq!(capability.public_key(), &point);
        assert_eq!(recovered, capsule()?);
        Ok(())
    }

    #[test]
    fn crash_after_pending_tombstone_publish_converges_to_exact_bound_stage(
    ) -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let chain = chain();
        let session_id = [0x28; 32];
        let terms_hash = [0x58; 32];
        let mut vault = create_vault(&directory)?;
        let pending = contribute_vault_backed_blinding_share_v1(
            &chain,
            session_id,
            &roster(),
            DirectionV1::Initiator,
            0,
            terms_hash,
            &mut vault,
        )?;
        let point = pending.public_key().clone();
        drop(pending);
        drop(vault);

        let marker = directory.path().join("pending-tombstone-published.marker");
        let status = Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("runtime::linux::inventory::collaborative::tests::child_shared_blinding_upgrade_crashes_after_pending_tombstone_publish")
            .arg("--ignored")
            .arg("--nocapture")
            .env("DOM_CONTRACTS_COLLABORATIVE_TEST_ROOT", directory.path())
            .env(
                "DOM_CONTRACTS_COLLABORATIVE_CRASH_CUT",
                "shared-pending-tombstone-after-persist-before-delete",
            )
            .env("DOM_CONTRACTS_COLLABORATIVE_CRASH_MARKER", &marker)
            .status()?;
        assert_eq!(status.signal(), Some(6));
        assert_eq!(
            fs::read(&marker)?,
            b"shared-pending-tombstone-after-persist-before-delete"
        );

        let mut vault = open_vault(&directory)?;
        let RestartedSessionBlindingShareV1::Bound {
            capability,
            capsule: recovered,
        } = resume_vault_backed_blinding_share_after_restart_v1(
            request(&chain, session_id, DirectionV1::Initiator, 0, terms_hash)?,
            &mut vault,
        )?
        else {
            return Err(Box::new(InventoryError::RestoreQuarantined));
        };
        assert_eq!(capability.public_key(), &point);
        assert_eq!(recovered, capsule()?);
        Ok(())
    }

    #[test]
    fn crash_after_pending_publish_reopens_without_reminting_share() -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let marker = directory.path().join("pending-published.marker");
        let status = Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("runtime::linux::inventory::collaborative::tests::child_shared_blinding_crashes_after_pending_publish")
            .arg("--ignored")
            .arg("--nocapture")
            .env("DOM_CONTRACTS_COLLABORATIVE_TEST_ROOT", directory.path())
            .env(
                "DOM_CONTRACTS_COLLABORATIVE_CRASH_CUT",
                "shared-pending-after-persist",
            )
            .env("DOM_CONTRACTS_COLLABORATIVE_CRASH_MARKER", &marker)
            .status()?;
        assert_eq!(status.signal(), Some(6));
        assert_eq!(fs::read(&marker)?, b"shared-pending-after-persist");

        let mut vault = open_vault(&directory)?;
        assert!(matches!(
            resume_vault_backed_blinding_share_after_restart_v1(
                request(&chain(), [0x27; 32], DirectionV1::Initiator, 0, [0x57; 32],)?,
                &mut vault,
            )?,
            RestartedSessionBlindingShareV1::Pending(_)
        ));
        Ok(())
    }

    #[test]
    fn restart_lookup_rejects_orphan_and_terminal_tombstones() -> Result<(), Box<dyn Error>> {
        let chain = chain();
        let session_id = [0x25; 32];
        let terms_hash = [0x55; 32];

        let orphan_directory = TestDirectory::create()?;
        let mut orphan_vault = create_vault(&orphan_directory)?;
        let pending = contribute_vault_backed_blinding_share_v1(
            &chain,
            session_id,
            &roster(),
            DirectionV1::Initiator,
            0,
            terms_hash,
            &mut orphan_vault,
        )?;
        let pending_binding = pending.binding().clone();
        drop(pending);
        let tombstone = StateRecord::new(
            StateKind::SharedPendingRetired,
            &pending_binding.to_aad_bytes(),
            &[],
        )?;
        orphan_vault.store.publish_collaborative_state(&tombstone)?;
        orphan_vault.store.delete_collaborative_state(
            pending_binding.binding_digest_v1(),
            StateKind::SharedPending,
        )?;
        assert!(resume_vault_backed_blinding_share_after_restart_v1(
            request(&chain, session_id, DirectionV1::Initiator, 0, terms_hash,)?,
            &mut orphan_vault,
        )
        .is_err());

        let orphan_bound_directory = TestDirectory::create()?;
        let mut orphan_bound_vault = create_vault(&orphan_bound_directory)?;
        let pending = contribute_vault_backed_blinding_share_v1(
            &chain,
            [0x29; 32],
            &roster(),
            DirectionV1::Initiator,
            0,
            [0x59; 32],
            &mut orphan_bound_vault,
        )?;
        let pending_binding = pending.binding().clone();
        let bound =
            pending.bind_recovery_capsule_restartable_v1(&capsule()?, &mut orphan_bound_vault)?;
        drop(bound);
        orphan_bound_vault.store.delete_collaborative_state(
            pending_binding.binding_digest_v1(),
            StateKind::SharedPendingRetired,
        )?;
        drop(orphan_bound_vault);
        assert!(open_vault(&orphan_bound_directory).is_err());

        let terminal_directory = TestDirectory::create()?;
        let mut terminal_vault = create_vault(&terminal_directory)?;
        let pending = contribute_vault_backed_blinding_share_v1(
            &chain,
            [0x26; 32],
            &roster(),
            DirectionV1::Initiator,
            0,
            [0x56; 32],
            &mut terminal_vault,
        )?;
        let bound =
            pending.bind_recovery_capsule_restartable_v1(&capsule()?, &mut terminal_vault)?;
        let bound_binding = bound.binding().clone();
        drop(bound);
        let tombstone = StateRecord::new(
            StateKind::SharedBoundRetired,
            &bound_binding.to_aad_bytes(),
            &[],
        )?;
        terminal_vault
            .store
            .publish_collaborative_state(&tombstone)?;
        terminal_vault.store.delete_collaborative_state(
            bound_binding.binding_digest_v1(),
            StateKind::SharedBound,
        )?;
        assert!(resume_vault_backed_blinding_share_after_restart_v1(
            request(&chain, [0x26; 32], DirectionV1::Initiator, 0, [0x56; 32],)?,
            &mut terminal_vault,
        )
        .is_err());
        Ok(())
    }

    #[test]
    #[ignore = "subprocess helper for the restartable shared-blinding crash cut"]
    fn child_shared_blinding_upgrade_crashes_after_bound_publish() -> Result<(), Box<dyn Error>> {
        let path = std::env::var_os("DOM_CONTRACTS_COLLABORATIVE_TEST_ROOT")
            .ok_or(InventoryError::Filesystem)?;
        let directory = TestDirectory {
            path: PathBuf::from(path),
        };
        let chain = chain();
        let mut vault = open_vault(&directory)?;
        let RestartedSessionBlindingShareV1::Pending(pending) =
            resume_vault_backed_blinding_share_after_restart_v1(
                request(&chain, [0x24; 32], DirectionV1::Initiator, 0, [0x54; 32])?,
                &mut vault,
            )?
        else {
            return Err(Box::new(InventoryError::RestoreQuarantined));
        };
        pending.bind_recovery_capsule_restartable_v1(&capsule()?, &mut vault)?;
        Err(Box::new(InventoryError::Canonical))
    }

    #[test]
    #[ignore = "subprocess helper for the restartable pending-tombstone crash cut"]
    fn child_shared_blinding_upgrade_crashes_after_pending_tombstone_publish(
    ) -> Result<(), Box<dyn Error>> {
        let path = std::env::var_os("DOM_CONTRACTS_COLLABORATIVE_TEST_ROOT")
            .ok_or(InventoryError::Filesystem)?;
        let directory = TestDirectory {
            path: PathBuf::from(path),
        };
        let chain = chain();
        let mut vault = open_vault(&directory)?;
        let RestartedSessionBlindingShareV1::Pending(pending) =
            resume_vault_backed_blinding_share_after_restart_v1(
                request(&chain, [0x28; 32], DirectionV1::Initiator, 0, [0x58; 32])?,
                &mut vault,
            )?
        else {
            return Err(Box::new(InventoryError::RestoreQuarantined));
        };
        pending.bind_recovery_capsule_restartable_v1(&capsule()?, &mut vault)?;
        Err(Box::new(InventoryError::Canonical))
    }

    #[test]
    #[ignore = "subprocess helper for the pending shared-blinding crash cut"]
    fn child_shared_blinding_crashes_after_pending_publish() -> Result<(), Box<dyn Error>> {
        let path = std::env::var_os("DOM_CONTRACTS_COLLABORATIVE_TEST_ROOT")
            .ok_or(InventoryError::Filesystem)?;
        let directory = TestDirectory {
            path: PathBuf::from(path),
        };
        let mut vault = create_vault(&directory)?;
        contribute_vault_backed_blinding_share_v1(
            &chain(),
            [0x27; 32],
            &roster(),
            DirectionV1::Initiator,
            0,
            [0x57; 32],
            &mut vault,
        )?;
        Err(Box::new(InventoryError::Canonical))
    }
}
