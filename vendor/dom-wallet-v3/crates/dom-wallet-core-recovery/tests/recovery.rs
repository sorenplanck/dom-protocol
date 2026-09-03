use dom_adaptor::{
    contribute_vault_backed_blinding_share_v1, DirectionV1, DurableShareBackupAckCapabilityV1,
    PendingSharedBlindingBindingV1, SessionBlindingShareCapabilityV1, ShareBackupAckV1,
    SharedBlindingBindingUpgradeCapabilityV1, SharedBlindingBindingV1,
    SharedBlindingImportCapabilityV1, SharedBlindingMaterialV1,
    SharedBlindingRetirementCapabilityV1, SharedBlindingSealCapabilityV1, SharedBlindingVaultV1,
    SigningShareV1, TrustedChainIdV1,
};
use dom_consensus::{
    validate_balance_equation, validate_range_proofs, validate_transaction_structure, Transaction,
    TransactionKernel, TransactionOutput,
};
use dom_core::{Amount, Hash256, KERNEL_FEAT_PLAIN};
use dom_crypto::{
    pedersen::{BlindingFactor, Commitment},
    range_proof_prove_bytes, range_proof_verify_with_extra_commit,
    recovery::{
        RecoveryCapsule, RECOVERY_CAPSULE_SIZE, RECOVERY_CIPHERTEXT_SIZE, RECOVERY_VERSION,
    },
    schnorr_add_public_keys, PublicKey, SecretKey, MAX_PROVABLE_VALUE,
    RANGE_PROOF_SERIALIZATION_VERSION, RANGE_PROOF_SIZE,
};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_slate::sender_excess_blinding;
use dom_wallet_core_api::CoreNetwork;
use dom_wallet_core_recovery::{
    finalize_recoverable_transaction, frozen_versions, public_output_kind,
    state_uses_canonical_seed, BoundScriptlessSigningContextV1, CanonicalWalletSeed,
    RecoverableOutputBuilder, RecoveryMaterialError, ScriptlessFundingSigningCapabilityV1,
    ScriptlessPayoutSigningCapabilityV1, WalletSlateInput, CANONICAL_TRANSACTION_OUTPUT_SIZE,
    PRODUCTION_OUTPUT_PATHS, RECOVERY_PROOF_ENVELOPE_SIZE,
};
use dom_wallet_core_sync::{CoreBlockReference, CoreChainIdentity};
use dom_wallet_domain::{
    Network, NetworkIdentity, NodeConfiguration, RecoveryMetadata, RecoveryOutputClass,
    WalletState, RECOVERY_SCHEME_BIP39_256_V1,
};
use dom_wallet_embedded_core::{
    mine_wallet_block, EmbeddedCoreConfiguration, EmbeddedCoreLifecycle, EmbeddedCoreNetwork,
    WalletMiningOutcome,
};
use std::{
    collections::BTreeSet,
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use tempfile::TempDir;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
#[error("test shared-blinding vault rejected operation")]
struct TestSharedBlindingVaultError;

#[derive(Default)]
struct TestSharedBlindingVault {
    pending: Option<PendingSharedBlindingBindingV1>,
    bound: Option<SharedBlindingBindingV1>,
    primary: Option<[u8; 32]>,
    backup: Option<[u8; 32]>,
    pending_tombstone: bool,
    bound_tombstone: bool,
}

impl SharedBlindingVaultV1 for TestSharedBlindingVault {
    type Error = TestSharedBlindingVaultError;

    fn seal_fresh_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        material: SharedBlindingMaterialV1,
        capability: SharedBlindingSealCapabilityV1,
    ) -> Result<(), Self::Error> {
        if self.pending.is_some()
            || self.bound.is_some()
            || self.primary.is_some()
            || self.backup.is_some()
            || self.pending_tombstone
        {
            return Err(TestSharedBlindingVaultError);
        }
        let plaintext = capability.into_plaintext(material);
        self.pending = Some(binding.clone());
        self.primary = Some(*plaintext);
        self.backup = Some(*plaintext);
        Ok(())
    }

    fn open_persisted_pending_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: SharedBlindingImportCapabilityV1,
    ) -> Result<SharedBlindingMaterialV1, Self::Error> {
        if self.pending.as_ref() != Some(binding) || self.pending_tombstone {
            return Err(TestSharedBlindingVaultError);
        }
        capability
            .import(Zeroizing::new(
                self.primary.ok_or(TestSharedBlindingVaultError)?,
            ))
            .map_err(|_| TestSharedBlindingVaultError)
    }

    fn confirm_pending_backup_roundtrip(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: DurableShareBackupAckCapabilityV1,
    ) -> Result<ShareBackupAckV1, Self::Error> {
        if self.pending.as_ref() != Some(binding) || self.pending_tombstone {
            return Err(TestSharedBlindingVaultError);
        }
        let recovered =
            SigningShareV1::from_be_bytes(self.backup.ok_or(TestSharedBlindingVaultError)?)
                .map_err(|_| TestSharedBlindingVaultError)?;
        capability
            .acknowledge_pending(binding, recovered.public_key().clone())
            .map_err(|_| TestSharedBlindingVaultError)
    }

    fn bind_recovery_capsule(
        &mut self,
        pending: &PendingSharedBlindingBindingV1,
        bound: &SharedBlindingBindingV1,
        capability: SharedBlindingBindingUpgradeCapabilityV1,
    ) -> Result<(), Self::Error> {
        capability
            .authorize_upgrade(pending, bound)
            .map_err(|_| TestSharedBlindingVaultError)?;
        if self.pending.as_ref() != Some(pending)
            || self.pending_tombstone
            || self.bound.is_some()
            || self.primary.is_none()
            || self.backup.is_none()
        {
            return Err(TestSharedBlindingVaultError);
        }
        self.bound = Some(bound.clone());
        self.pending = None;
        self.pending_tombstone = true;
        Ok(())
    }

    fn open_persisted_share(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: SharedBlindingImportCapabilityV1,
    ) -> Result<SharedBlindingMaterialV1, Self::Error> {
        if self.bound.as_ref() != Some(binding) || self.bound_tombstone {
            return Err(TestSharedBlindingVaultError);
        }
        capability
            .import(Zeroizing::new(
                self.primary.ok_or(TestSharedBlindingVaultError)?,
            ))
            .map_err(|_| TestSharedBlindingVaultError)
    }

    fn confirm_backup_roundtrip(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: DurableShareBackupAckCapabilityV1,
    ) -> Result<ShareBackupAckV1, Self::Error> {
        if self.bound.as_ref() != Some(binding) || self.bound_tombstone {
            return Err(TestSharedBlindingVaultError);
        }
        let recovered =
            SigningShareV1::from_be_bytes(self.backup.ok_or(TestSharedBlindingVaultError)?)
                .map_err(|_| TestSharedBlindingVaultError)?;
        capability
            .acknowledge(binding, recovered.public_key().clone())
            .map_err(|_| TestSharedBlindingVaultError)
    }

    fn retire_pending_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: SharedBlindingRetirementCapabilityV1,
    ) -> Result<(), Self::Error> {
        capability
            .authorize_pending(binding)
            .map_err(|_| TestSharedBlindingVaultError)?;
        Err(TestSharedBlindingVaultError)
    }

    fn retire_bound_share(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: SharedBlindingRetirementCapabilityV1,
    ) -> Result<(), Self::Error> {
        capability
            .authorize_bound(binding)
            .map_err(|_| TestSharedBlindingVaultError)?;
        Err(TestSharedBlindingVaultError)
    }
}

fn public_recovery_capsule_fixture(marker: u8) -> RecoveryCapsule {
    let mut bytes = [marker; RECOVERY_CAPSULE_SIZE];
    bytes[..2].copy_from_slice(&RECOVERY_VERSION.to_le_bytes());
    bytes[14..16].copy_from_slice(&(RECOVERY_CIPHERTEXT_SIZE as u16).to_le_bytes());
    RecoveryCapsule::from_bytes(&bytes)
        .expect("construct canonical public recovery capsule fixture")
}

fn test_session_share() -> SessionBlindingShareCapabilityV1 {
    let trusted = TrustedChainIdV1::from_authenticated_genesis(
        dom_core::NETWORK_MAGIC_REGTEST,
        &Hash256::from_bytes([0x41; 32]),
    );
    let mut vault = TestSharedBlindingVault::default();
    let pending = contribute_vault_backed_blinding_share_v1(
        &trusted,
        [0x42; 32],
        &[[0x11; 32], [0x22; 32]],
        DirectionV1::Initiator,
        0,
        [0x43; 32],
        &mut vault,
    )
    .expect("create real provisional DOM session share");
    pending
        .bind_recovery_capsule_v1(&public_recovery_capsule_fixture(0x44), &mut vault)
        .expect("bind real opaque DOM session share to its public capsule")
}

fn identity(network: CoreNetwork, chain_id: [u8; 32]) -> CoreChainIdentity {
    CoreChainIdentity {
        network,
        network_magic: network.magic(),
        chain_id,
        genesis_hash: if network == CoreNetwork::Regtest {
            [0; 32]
        } else {
            [9; 32]
        },
        protocol_version: dom_core::PROTOCOL_VERSION,
        range_proof_serialization_version: RANGE_PROOF_SERIALIZATION_VERSION,
        coinbase_maturity: 1,
        current_tip: CoreBlockReference {
            height: 0,
            hash: [0; 32],
        },
    }
}

fn seed(marker: u8) -> CanonicalWalletSeed {
    CanonicalWalletSeed::from_entropy(&[marker; 32]).unwrap()
}

fn domain_identity() -> NetworkIdentity {
    NetworkIdentity {
        network: Network::PrivateTestnet,
        chain_id: [8; 32],
        genesis_id: [0; 32],
    }
}

fn node_configuration() -> NodeConfiguration {
    NodeConfiguration {
        endpoint_url: "https://unused.invalid".into(),
        expected_identity: domain_identity(),
        source_identity: "test-only".into(),
        api_compatibility_version: 1,
        connect_timeout_ms: 1,
        request_timeout_ms: 1,
        poll_interval_ms: 1,
        retry_ceiling: 1,
        max_backoff_ms: 1,
        stable_success_threshold: 1,
        tls_required: true,
        credential_reference: None,
    }
}

fn state() -> WalletState {
    let mut state = WalletState::new(domain_identity(), [7; 32], node_configuration());
    state.recovery = Some(RecoveryMetadata {
        scheme: RECOVERY_SCHEME_BIP39_256_V1.into(),
        phrase_confirmed: true,
    });
    state
}

fn output_for(
    class: RecoveryOutputClass,
    value: u64,
) -> dom_wallet_core_recovery::RecoverableOutputResult {
    let mut state = state();
    let coordinate = state.reserve_recovery_coordinate(3, class).unwrap();
    RecoverableOutputBuilder::new(&seed(7), &identity(CoreNetwork::Regtest, [8; 32]))
        .unwrap()
        .build(value, coordinate)
        .unwrap()
}

#[test]
fn bip39_generation_is_english_24_word_256_bit() {
    let value = CanonicalWalletSeed::generate().unwrap();
    let text = value.mnemonic_text();
    assert_eq!(text.split_whitespace().count(), 24);
    let parsed = CanonicalWalletSeed::parse(&text).unwrap();
    let mut original = [0u8; 32];
    let mut restored = [0u8; 32];
    value.copy_entropy_to(&mut original);
    parsed.copy_entropy_to(&mut restored);
    assert_eq!(original, restored);
}

#[test]
fn bip39_checksum_and_word_count_fail_closed() {
    let value = seed(9);
    let text = value.mnemonic_text();
    let words: Vec<&str> = text.split_whitespace().collect();
    assert!(CanonicalWalletSeed::parse(&words[..23].join(" ")).is_err());
    let mut mutation_rejected = false;
    for replacement in words.iter().take(8) {
        let mut changed = words.clone();
        changed[23] = replacement;
        if CanonicalWalletSeed::parse(&changed.join(" ")).is_err() {
            mutation_rejected = true;
            break;
        }
    }
    assert!(mutation_rejected);
}

#[test]
fn bip39_nfkd_normalization_is_deterministic() {
    let value = seed(11);
    let canonical = value.mnemonic_text();
    let normalized_input = canonical.replace(' ', "\u{3000}");
    let restored = CanonicalWalletSeed::parse(&normalized_input).unwrap();
    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    value.copy_entropy_to(&mut left);
    restored.copy_entropy_to(&mut right);
    assert_eq!(left, right);
}

#[test]
fn mnemonic_and_seed_debug_are_redacted() {
    let value = seed(12);
    let text = value.mnemonic_text();
    let debug = format!("{value:?}");
    assert!(!debug.contains(text.as_str()));
    assert!(debug.contains("REDACTED"));
    assert!(!format!("{:?}", RecoveryMaterialError::InvalidMnemonic).contains(text.as_str()));
}

#[test]
fn same_mnemonic_reconstructs_same_recovery_ownership() {
    let first = seed(13);
    let phrase = first.mnemonic_text();
    let second = CanonicalWalletSeed::parse(&phrase).unwrap();
    let id = identity(CoreNetwork::Regtest, [8; 32]);
    let mut wallet = state();
    let coordinate = wallet
        .reserve_recovery_coordinate(0, RecoveryOutputClass::ReceiveSlate)
        .unwrap();
    let original = RecoverableOutputBuilder::new(&first, &id)
        .unwrap()
        .build(42, coordinate)
        .unwrap();
    let recovered = RecoverableOutputBuilder::new(&second, &id)
        .unwrap()
        .try_recover(&original.output, RecoveryOutputClass::ReceiveSlate)
        .unwrap()
        .unwrap();
    assert!(recovered.matches_original(&original));
}

#[test]
fn different_seed_chain_and_network_do_not_claim_output() {
    let id = identity(CoreNetwork::Regtest, [8; 32]);
    let original = output_for(RecoveryOutputClass::ReceiveSlate, 43);
    assert!(RecoverableOutputBuilder::new(&seed(8), &id)
        .unwrap()
        .try_recover(&original.output, RecoveryOutputClass::ReceiveSlate)
        .unwrap()
        .is_none());
    assert!(
        RecoverableOutputBuilder::new(&seed(7), &identity(CoreNetwork::Regtest, [9; 32]))
            .unwrap()
            .try_recover(&original.output, RecoveryOutputClass::ReceiveSlate)
            .unwrap()
            .is_none()
    );
    assert!(
        RecoverableOutputBuilder::new(&seed(7), &identity(CoreNetwork::Testnet, [8; 32]))
            .unwrap()
            .try_recover(&original.output, RecoveryOutputClass::ReceiveSlate)
            .unwrap()
            .is_none()
    );
}

#[test]
fn every_output_class_builds_and_self_recovers() {
    for class in [
        RecoveryOutputClass::ReceiveRequest,
        RecoveryOutputClass::ReceiveSlate,
        RecoveryOutputClass::Change,
        RecoveryOutputClass::SelfTransfer,
        RecoveryOutputClass::Coinbase,
    ] {
        let output = output_for(class, 44);
        let recovered =
            RecoverableOutputBuilder::new(&seed(7), &identity(CoreNetwork::Regtest, [8; 32]))
                .unwrap()
                .try_recover(&output.output, class)
                .unwrap()
                .unwrap();
        assert_eq!(recovered.value, 44);
        assert_eq!(recovered.account, 3);
        assert_eq!(recovered.derivation_index, 1);
        assert_eq!(recovered.class, class);
        assert!(recovered.matches_original(&output));
        assert_eq!(
            public_output_kind(class),
            if class == RecoveryOutputClass::Coinbase {
                dom_crypto::recovery::PublicOutputKind::Coinbase
            } else {
                dom_crypto::recovery::PublicOutputKind::Regular
            }
        );
    }
}

#[test]
fn canonical_output_sizes_and_round_trip_are_exact() {
    let output = output_for(RecoveryOutputClass::ReceiveSlate, 45);
    assert_eq!(output.commitment.len(), 33);
    assert_eq!(output.range_proof.len(), RANGE_PROOF_SIZE);
    assert_eq!(output.recovery_capsule.len(), RECOVERY_CAPSULE_SIZE);
    assert_eq!(output.proof_envelope.len(), RECOVERY_PROOF_ENVELOPE_SIZE);
    assert_eq!(output.output.proof.len(), 835);
    assert_eq!(
        output.canonical_bytes.len(),
        CANONICAL_TRANSACTION_OUTPUT_SIZE
    );
    assert_eq!(
        TransactionOutput::from_bytes(&output.canonical_bytes).unwrap(),
        output.output
    );
    assert_eq!(
        frozen_versions(),
        (RECOVERY_VERSION, RANGE_PROOF_SERIALIZATION_VERSION)
    );
}

#[test]
fn proof_and_commitment_are_verified() {
    let output = output_for(RecoveryOutputClass::Change, 46);
    assert!(range_proof_verify_with_extra_commit(
        &output.commitment,
        &output.range_proof,
        &output.recovery_capsule,
    )
    .unwrap());
    let mut changed_proof = output.range_proof;
    changed_proof[100] ^= 1;
    assert!(!range_proof_verify_with_extra_commit(
        &output.commitment,
        &changed_proof,
        &output.recovery_capsule,
    )
    .unwrap_or(false));
    let other_blinding = BlindingFactor::from_bytes([5; 32]).unwrap();
    let other_commitment = Commitment::commit(46, &other_blinding);
    assert!(!range_proof_verify_with_extra_commit(
        other_commitment.as_bytes(),
        &output.range_proof,
        &output.recovery_capsule,
    )
    .unwrap_or(false));
}

#[test]
fn capsule_authentication_mutation_and_framing_fail_closed() {
    let output = output_for(RecoveryOutputClass::SelfTransfer, 47);
    let builder =
        RecoverableOutputBuilder::new(&seed(7), &identity(CoreNetwork::Regtest, [8; 32])).unwrap();
    let mut mutated = output.output.clone();
    mutated.proof[RANGE_PROOF_SIZE + 40] ^= 1;
    assert!(builder
        .try_recover(&mutated, RecoveryOutputClass::SelfTransfer)
        .unwrap()
        .is_none());
    assert!(!range_proof_verify_with_extra_commit(
        mutated.commitment.as_bytes(),
        mutated.range_proof_bytes().unwrap(),
        &mutated.proof[RANGE_PROOF_SIZE..],
    )
    .unwrap_or(false));
    assert!(RecoveryCapsule::from_bytes(&output.recovery_capsule[..95]).is_err());
    let mut trailing = output.recovery_capsule.to_vec();
    trailing.push(0);
    assert!(RecoveryCapsule::from_bytes(&trailing).is_err());
    let mut unsupported = output.recovery_capsule;
    unsupported[..2].copy_from_slice(&2u16.to_le_bytes());
    assert!(RecoveryCapsule::from_bytes(&unsupported).is_err());
}

#[test]
fn value_and_coordinate_boundaries_fail_closed() {
    let id = identity(CoreNetwork::Regtest, [8; 32]);
    let builder = RecoverableOutputBuilder::new(&seed(7), &id).unwrap();
    let mut wallet = state();
    let zero = wallet
        .reserve_recovery_coordinate(u32::MAX, RecoveryOutputClass::ReceiveRequest)
        .unwrap();
    assert!(builder.build(0, zero).is_ok());
    let maximum = wallet
        .reserve_recovery_coordinate(u32::MAX, RecoveryOutputClass::ReceiveRequest)
        .unwrap();
    assert!(builder.build(MAX_PROVABLE_VALUE, maximum).is_ok());
    let above = wallet
        .reserve_recovery_coordinate(0, RecoveryOutputClass::Change)
        .unwrap();
    assert!(matches!(
        builder.build(MAX_PROVABLE_VALUE + 1, above),
        Err(RecoveryMaterialError::ValueOutOfRange)
    ));
    wallet.recovery_allocation_floors.coinbase = u64::MAX;
    assert!(wallet
        .reserve_recovery_coordinate(0, RecoveryOutputClass::Coinbase)
        .is_err());
}

#[test]
fn wrong_private_domain_is_rejected() {
    let output = output_for(RecoveryOutputClass::ReceiveSlate, 48);
    assert!(matches!(
        RecoverableOutputBuilder::new(&seed(7), &identity(CoreNetwork::Regtest, [8; 32]))
            .unwrap()
            .try_recover(&output.output, RecoveryOutputClass::Change),
        Err(RecoveryMaterialError::CoordinateDomainMismatch)
    ));
}

#[test]
fn allocation_floors_are_monotonic_burned_and_restart_safe() {
    let mut wallet = state();
    let first = wallet
        .reserve_recovery_coordinate(0, RecoveryOutputClass::ReceiveRequest)
        .unwrap();
    let cancelled = wallet
        .reserve_recovery_coordinate(0, RecoveryOutputClass::ReceiveSlate)
        .unwrap();
    let change = wallet
        .reserve_recovery_coordinate(0, RecoveryOutputClass::Change)
        .unwrap();
    assert_eq!(first.derivation_index(), 1);
    assert_eq!(cancelled.derivation_index(), 2);
    assert_eq!(change.derivation_index(), 1);
    let bytes = serde_json::to_vec(&wallet).unwrap();
    let mut reopened: WalletState = serde_json::from_slice(&bytes).unwrap();
    let next = reopened
        .reserve_recovery_coordinate(0, RecoveryOutputClass::ReceiveRequest)
        .unwrap();
    assert_eq!(next.derivation_index(), 3);
    assert_eq!(reopened.recovery_allocation_floors.received, 3);
    assert!(state_uses_canonical_seed(&reopened));
}

#[test]
fn failed_construction_still_burns_persisted_coordinate() {
    let mut wallet = state();
    let failed = wallet
        .reserve_recovery_coordinate(0, RecoveryOutputClass::Change)
        .unwrap();
    let persisted = serde_json::to_vec(&wallet).unwrap();
    let builder =
        RecoverableOutputBuilder::new(&seed(7), &identity(CoreNetwork::Regtest, [8; 32])).unwrap();
    assert!(builder.build(MAX_PROVABLE_VALUE + 1, failed).is_err());
    let mut reopened: WalletState = serde_json::from_slice(&persisted).unwrap();
    let next = reopened
        .reserve_recovery_coordinate(0, RecoveryOutputClass::Change)
        .unwrap();
    assert_eq!(next.derivation_index(), 2);
}

#[test]
fn concurrent_allocation_is_unique_under_wallet_lock() {
    let wallet = Arc::new(Mutex::new(state()));
    let mut threads = Vec::new();
    for _ in 0..32 {
        let wallet = Arc::clone(&wallet);
        threads.push(std::thread::spawn(move || {
            wallet
                .lock()
                .unwrap()
                .reserve_recovery_coordinate(0, RecoveryOutputClass::ReceiveSlate)
                .unwrap()
                .derivation_index()
        }));
    }
    let indexes: BTreeSet<u64> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(indexes.len(), 32);
    assert_eq!(indexes.first(), Some(&1));
    assert_eq!(indexes.last(), Some(&32));
}

#[test]
fn production_registry_requires_recovery_for_every_class() {
    assert_eq!(PRODUCTION_OUTPUT_PATHS.len(), 5);
    assert!(PRODUCTION_OUTPUT_PATHS
        .iter()
        .all(|path| path.recovery_required && !path.constructor.contains("add_output")));
    assert_eq!(
        PRODUCTION_OUTPUT_PATHS
            .iter()
            .map(|path| path.class)
            .collect::<BTreeSet<_>>()
            .len(),
        5
    );
}

#[test]
fn legacy_proof_only_output_is_explicitly_not_recoverable() {
    let blinding = BlindingFactor::from_bytes([6; 32]).unwrap();
    let (proof, commitment) = dom_crypto::range_proof_prove_bytes(50, &blinding).unwrap();
    let output = TransactionOutput {
        commitment: Commitment::from_compressed_bytes(&commitment).unwrap(),
        proof,
    };
    assert_eq!(output.proof.len(), RANGE_PROOF_SIZE);
    assert!(output.recovery_capsule().unwrap().is_none());
}

#[test]
fn slate_change_and_recipient_sidecars_are_exact_and_role_ordered() {
    let id = identity(CoreNetwork::Regtest, [8; 32]);
    let sender_builder = RecoverableOutputBuilder::new(&seed(21), &id).unwrap();
    let receiver_builder = RecoverableOutputBuilder::new(&seed(22), &id).unwrap();
    let input_blinding = BlindingFactor::from_bytes([3; 32]).unwrap();
    let input_commitment = Commitment::commit(1_600, &input_blinding);
    let input = WalletSlateInput::new(*input_commitment.as_bytes(), *input_blinding.as_bytes());
    let mut sender_state = state();
    let change = sender_state
        .reserve_recovery_coordinate(0, RecoveryOutputClass::Change)
        .unwrap();
    let offer = sender_builder
        .build_sender_offer(&[input], 500, 1_000, 100, change)
        .unwrap();
    assert!(offer.retains_private_material());
    assert!(offer.sidecars.sender_change.is_some());
    assert!(offer.sidecars.recipient.is_none());
    let change_bytes = offer.sidecars.sender_change.unwrap();
    let mut receiver_state = state();
    let recipient = receiver_state
        .reserve_recovery_coordinate(3, RecoveryOutputClass::ReceiveSlate)
        .unwrap();
    let response = receiver_builder
        .build_recipient_response(&offer.body, recipient)
        .unwrap();
    assert!(response.retains_private_material());
    assert_eq!(response.sidecars.sender_change, Some(change_bytes));
    assert!(response.sidecars.recipient.is_some());
    assert_ne!(response.sidecars.sender_change, response.sidecars.recipient);
    assert_eq!(
        response.sidecars.sender_change.unwrap().len(),
        RECOVERY_CAPSULE_SIZE
    );
    assert_eq!(
        response.sidecars.recipient.unwrap().len(),
        RECOVERY_CAPSULE_SIZE
    );
}

#[test]
fn recoverable_sender_receiver_round_trip_e2e() {
    let id = identity(CoreNetwork::Regtest, [8; 32]);
    let sender_builder = RecoverableOutputBuilder::new(&seed(31), &id).unwrap();
    let receiver_builder = RecoverableOutputBuilder::new(&seed(32), &id).unwrap();
    let input_blinding = BlindingFactor::from_bytes([5; 32]).unwrap();
    let input = WalletSlateInput::new(
        *Commitment::commit(1_600, &input_blinding).as_bytes(),
        *input_blinding.as_bytes(),
    );
    let mut sender_state = state();
    let sender_coordinate = sender_state
        .reserve_recovery_coordinate(0, RecoveryOutputClass::Change)
        .unwrap();
    let sender = sender_builder
        .build_sender_offer(&[input], 500, 1_000, 100, sender_coordinate)
        .unwrap()
        .into_sender_parts()
        .unwrap();
    let offer = sender.body.clone();
    let mut receiver_state = state();
    let receiver_coordinate = receiver_state
        .reserve_recovery_coordinate(0, RecoveryOutputClass::ReceiveSlate)
        .unwrap();
    let recipient = receiver_builder
        .build_recipient_response(&offer, receiver_coordinate)
        .unwrap()
        .into_recipient_parts()
        .unwrap();
    let finalized =
        finalize_recoverable_transaction(&recipient.body, &offer, &sender, id.chain_id).unwrap();
    let transaction = dom_consensus::Transaction::from_bytes(&finalized.canonical_bytes).unwrap();
    assert_eq!(transaction.outputs.len(), 2);
    assert!(transaction.outputs.iter().all(|output| {
        output.recovery_capsule().unwrap().is_some()
            && output.to_bytes().unwrap().len() == CANONICAL_TRANSACTION_OUTPUT_SIZE
    }));
}

#[test]
fn slate_wrong_coordinate_roles_fail_closed() {
    let id = identity(CoreNetwork::Regtest, [8; 32]);
    let builder = RecoverableOutputBuilder::new(&seed(23), &id).unwrap();
    let input_blinding = BlindingFactor::from_bytes([4; 32]).unwrap();
    let input = WalletSlateInput::new(
        *Commitment::commit(1_600, &input_blinding).as_bytes(),
        *input_blinding.as_bytes(),
    );
    let mut wallet = state();
    let received = wallet
        .reserve_recovery_coordinate(0, RecoveryOutputClass::ReceiveSlate)
        .unwrap();
    assert!(matches!(
        builder.build_sender_offer(&[input], 500, 1_000, 100, received),
        Err(RecoveryMaterialError::CoordinateDomainMismatch)
    ));
}

#[test]
fn scriptless_funding_components_use_real_change_proof_and_balance_authority() {
    let id = identity(CoreNetwork::Regtest, [8; 32]);
    let builder = RecoverableOutputBuilder::new(&seed(24), &id).unwrap();
    let input_blinding = BlindingFactor::from_bytes([4; 32]).unwrap();
    let input = WalletSlateInput::new(
        *Commitment::commit(1_600, &input_blinding).as_bytes(),
        *input_blinding.as_bytes(),
    );
    let mut wallet = state();
    let change_coordinate = wallet
        .reserve_recovery_coordinate(0, RecoveryOutputClass::Change)
        .unwrap();
    let prepared = builder
        .build_scriptless_funding_contribution(&[input], 500, Some(change_coordinate))
        .unwrap();
    assert_eq!(prepared.public.inputs.len(), 1);
    assert_eq!(prepared.public.other_outputs.len(), 1);
    let change = &prepared.public.other_outputs[0];
    let capsule = change.recovery_capsule().unwrap().unwrap();
    assert!(range_proof_verify_with_extra_commit(
        change.commitment.as_bytes(),
        change.range_proof_bytes().unwrap(),
        capsule.as_bytes(),
    )
    .unwrap());

    // Complete a public balance fixture using an ordinary proof for the
    // shared output. The wallet's secret `e_i` is never read: only e_i*G is
    // combined with the fixture participant's public r_i*G.
    let shared_blinding = BlindingFactor::from_bytes([7; 32]).unwrap();
    let (shared_proof, shared_commitment) =
        range_proof_prove_bytes(1_000, &shared_blinding).unwrap();
    let shared_output = TransactionOutput {
        commitment: Commitment::from_compressed_bytes(&shared_commitment).unwrap(),
        proof: shared_proof.to_vec(),
    };
    let wallet_public =
        PublicKey::from_compressed_bytes(&prepared.public.wallet_excess_public_key).unwrap();
    let shared_public = SecretKey::from_bytes(shared_blinding.as_bytes())
        .unwrap()
        .public_key();
    let aggregate_excess = schnorr_add_public_keys(&[wallet_public, shared_public]).unwrap();
    let transaction = Transaction {
        inputs: prepared.public.inputs.clone(),
        outputs: vec![change.clone(), shared_output],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(100).unwrap(),
            lock_height: 0,
            excess: Commitment::from_compressed_bytes(&aggregate_excess.to_compressed_bytes())
                .unwrap(),
            excess_signature: [0u8; 65],
        }],
        offset: prepared.public.offset_contribution,
    };
    validate_transaction_structure(&transaction).unwrap();
    validate_range_proofs(&transaction).unwrap();
    validate_balance_equation(&transaction).unwrap();
    assert!(format!("{prepared:?}").contains("REDACTED"));

    let no_change_input = WalletSlateInput::new(
        *Commitment::commit(1_600, &input_blinding).as_bytes(),
        *input_blinding.as_bytes(),
    );
    let no_change = builder
        .build_scriptless_funding_contribution(&[no_change_input], 0, None)
        .unwrap();
    assert_eq!(no_change.public.inputs.len(), 1);
    assert!(no_change.public.other_outputs.is_empty());
    assert!(no_change.change.is_none());

    let zero_debit = builder
        .build_scriptless_funding_contribution(&[], 0, None)
        .unwrap();
    assert!(zero_debit.public.inputs.is_empty());
    assert!(zero_debit.public.other_outputs.is_empty());
    assert!(zero_debit.change.is_none());
    BlindingFactor::from_bytes(zero_debit.public.offset_contribution).unwrap();
    PublicKey::from_compressed_bytes(&zero_debit.public.wallet_excess_public_key).unwrap();
    let expected_zero_debit_excess = sender_excess_blinding(
        std::iter::empty::<&[u8; 32]>(),
        None,
        &zero_debit.public.offset_contribution,
    )
    .unwrap();
    assert_eq!(
        SecretKey::from_bytes(&expected_zero_debit_excess)
            .unwrap()
            .public_key()
            .to_compressed_bytes(),
        zero_debit.public.wallet_excess_public_key
    );
}

#[test]
fn scriptless_payout_uses_recoverable_self_transfer_and_opaque_excess() {
    let id = identity(CoreNetwork::Regtest, [8; 32]);
    let builder = RecoverableOutputBuilder::new(&seed(25), &id).unwrap();
    let mut wallet = state();
    let coordinate = wallet
        .reserve_recovery_coordinate(0, RecoveryOutputClass::SelfTransfer)
        .unwrap();
    let prepared = builder
        .build_scriptless_shared_output_spend_contribution(900, Some(coordinate))
        .unwrap();
    assert_eq!(prepared.public.outputs.len(), 1);
    let output = &prepared.public.outputs[0];
    let capsule = output.recovery_capsule().unwrap().unwrap();
    assert!(range_proof_verify_with_extra_commit(
        output.commitment.as_bytes(),
        output.range_proof_bytes().unwrap(),
        capsule.as_bytes(),
    )
    .unwrap());
    assert_eq!(
        prepared.owned_output.as_ref().unwrap().commitment,
        *output.commitment.as_bytes()
    );
    assert_eq!(prepared.owned_output.as_ref().unwrap().value, 900);
    BlindingFactor::from_bytes(prepared.public.offset_contribution).unwrap();
    PublicKey::from_compressed_bytes(&prepared.public.payout_excess_public_key).unwrap();
    assert!(format!("{prepared:?}").contains("REDACTED"));

    let wrong_coordinate = wallet
        .reserve_recovery_coordinate(0, RecoveryOutputClass::Change)
        .unwrap();
    assert!(matches!(
        builder.build_scriptless_shared_output_spend_contribution(900, Some(wrong_coordinate)),
        Err(RecoveryMaterialError::CoordinateDomainMismatch)
    ));

    let no_output = builder
        .build_scriptless_shared_output_spend_contribution(0, None)
        .unwrap();
    assert!(no_output.public.outputs.is_empty());
    assert!(no_output.owned_output.is_none());
    BlindingFactor::from_bytes(no_output.public.offset_contribution).unwrap();
    PublicKey::from_compressed_bytes(&no_output.public.payout_excess_public_key).unwrap();
    let expected_no_output_excess = sender_excess_blinding(
        std::iter::empty::<&[u8; 32]>(),
        None,
        &no_output.public.offset_contribution,
    )
    .unwrap();
    assert_eq!(
        SecretKey::from_bytes(&expected_no_output_excess)
            .unwrap()
            .public_key()
            .to_compressed_bytes(),
        no_output.public.payout_excess_public_key
    );
    assert!(matches!(
        builder.build_scriptless_shared_output_spend_contribution(0, Some(coordinate)),
        Err(RecoveryMaterialError::CoordinateDomainMismatch)
    ));
}

#[test]
fn scriptless_signing_handoffs_are_purpose_specific_and_exactly_session_bound() {
    let session_share = test_session_share();
    let binding = session_share.binding();
    let context = BoundScriptlessSigningContextV1 {
        chain_id: *binding.chain_id(),
        session_id: *binding.session_id(),
        session_share_binding_digest: binding.binding_digest_v1(),
        participant_position: binding.participant_index(),
        template_hash: [0x45; 32],
    };

    let mut funding_excess = [0u8; 32];
    funding_excess[31] = 7;
    let funding_public = SigningShareV1::from_be_bytes(funding_excess)
        .unwrap()
        .public_key()
        .clone();
    let expected_funding = session_share
        .funding_kernel_excess_point_v1(&funding_public)
        .unwrap();
    let funding = ScriptlessFundingSigningCapabilityV1::from_template_bound_encrypted_context(
        funding_excess,
        context,
    )
    .unwrap();
    let composed_funding = funding
        .compose_local_funding_share_v1(&session_share)
        .unwrap();
    assert_eq!(composed_funding.public_key(), &expected_funding);

    let mut payout_excess = [0u8; 32];
    payout_excess[31] = 11;
    let payout_public = SigningShareV1::from_be_bytes(payout_excess)
        .unwrap()
        .public_key()
        .clone();
    let expected_payout = session_share
        .shared_output_spend_kernel_excess_point_v1(&payout_public)
        .unwrap();
    let payout = ScriptlessPayoutSigningCapabilityV1::from_template_bound_encrypted_context(
        payout_excess,
        context,
    )
    .unwrap();
    let composed_payout = payout
        .compose_local_shared_output_spend_share_v1(&session_share)
        .unwrap();
    assert_eq!(composed_payout.public_key(), &expected_payout);

    let mut wrong_context = context;
    wrong_context.session_share_binding_digest[0] ^= 1;
    let wrong = ScriptlessFundingSigningCapabilityV1::from_template_bound_encrypted_context(
        funding_excess,
        wrong_context,
    )
    .unwrap();
    assert!(matches!(
        wrong.compose_local_funding_share_v1(&session_share),
        Err(RecoveryMaterialError::ScriptlessSigningBinding)
    ));
    assert!(format!("{context:?}").contains("REDACTED"));
}

#[test]
fn secret_bearing_results_are_redacted() {
    let output = output_for(RecoveryOutputClass::Change, 51);
    let debug = format!("{output:?}");
    assert!(debug.contains("REDACTED"));
    let input = WalletSlateInput::new(output.commitment, [9; 32]);
    assert!(format!("{input:?}").contains("REDACTED"));
}

#[test]
fn real_embedded_core_identity_builds_and_recovers_exact_output() {
    let directory = TempDir::new().unwrap();
    let mut lifecycle = EmbeddedCoreLifecycle::new(EmbeddedCoreConfiguration::new(
        EmbeddedCoreNetwork::Regtest,
        directory.path(),
        unused_loopback_address(),
    ));
    lifecycle.start().unwrap();
    let api = lifecycle.wallet_api().unwrap();
    let core = api.chain_identity().unwrap();
    let identity = CoreChainIdentity {
        network: core.network,
        network_magic: core.network_magic,
        chain_id: core.chain_id,
        genesis_hash: core.genesis_hash,
        protocol_version: core.protocol_version,
        range_proof_serialization_version: core.range_proof_serialization_version,
        coinbase_maturity: core.coinbase_maturity,
        current_tip: CoreBlockReference {
            height: core.current_tip.height,
            hash: core.current_tip.hash,
        },
    };
    let mut wallet = state();
    let coordinate = wallet
        .reserve_recovery_coordinate(0, RecoveryOutputClass::ReceiveRequest)
        .unwrap();
    let builder = RecoverableOutputBuilder::new(&seed(31), &identity).unwrap();
    let output = builder.build(52, coordinate).unwrap();
    assert_eq!(
        output.canonical_bytes.len(),
        CANONICAL_TRANSACTION_OUTPUT_SIZE
    );
    assert_eq!(
        TransactionOutput::from_bytes(&output.canonical_bytes).unwrap(),
        output.output
    );
    assert!(builder
        .try_recover(&output.output, RecoveryOutputClass::ReceiveRequest)
        .unwrap()
        .unwrap()
        .matches_original(&output));
    lifecycle.request_shutdown().unwrap();
    lifecycle.wait_for_shutdown().unwrap();
}

#[test]
fn wallet_owned_miner_counts_real_work_and_accepts_a_regtest_block() {
    let directory = TempDir::new().unwrap();
    let mut lifecycle = EmbeddedCoreLifecycle::new(EmbeddedCoreConfiguration::new(
        EmbeddedCoreNetwork::Regtest,
        directory.path(),
        unused_loopback_address(),
    ));
    lifecycle.start().unwrap();
    let core = lifecycle.wallet_api().unwrap().chain_identity().unwrap();
    let identity = CoreChainIdentity {
        network: core.network,
        network_magic: core.network_magic,
        chain_id: core.chain_id,
        genesis_hash: core.genesis_hash,
        protocol_version: core.protocol_version,
        range_proof_serialization_version: core.range_proof_serialization_version,
        coinbase_maturity: core.coinbase_maturity,
        current_tip: CoreBlockReference {
            height: core.current_tip.height,
            hash: core.current_tip.hash,
        },
    };
    let mut wallet = state();
    let coordinate = wallet
        .reserve_recovery_coordinate(0, RecoveryOutputClass::Coinbase)
        .unwrap();
    let coinbase = RecoverableOutputBuilder::new(&seed(41), &identity)
        .unwrap()
        .build_coinbase(dom_core::BlockHeight(1), 0, coordinate)
        .unwrap();
    let attempts = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let outcome = runtime
        .block_on(mine_wallet_block(
            lifecycle.node_handle().unwrap(),
            &coinbase,
            1,
            stop,
            Arc::clone(&attempts),
        ))
        .unwrap();
    assert_eq!(outcome, WalletMiningOutcome::Accepted { height: 1 });
    assert!(attempts.load(Ordering::Relaxed) > 0);
    assert_eq!(
        lifecycle
            .node_handle()
            .unwrap()
            .metrics
            .blocks_mined
            .load(Ordering::Relaxed),
        1
    );
    lifecycle.request_shutdown().unwrap();
    lifecycle.wait_for_shutdown().unwrap();
}

#[test]
fn wallet_owned_miner_honors_stop_before_any_hash_attempt() {
    let directory = TempDir::new().unwrap();
    let mut lifecycle = EmbeddedCoreLifecycle::new(EmbeddedCoreConfiguration::new(
        EmbeddedCoreNetwork::Regtest,
        directory.path(),
        unused_loopback_address(),
    ));
    lifecycle.start().unwrap();
    let core = lifecycle.wallet_api().unwrap().chain_identity().unwrap();
    let identity = CoreChainIdentity {
        network: core.network,
        network_magic: core.network_magic,
        chain_id: core.chain_id,
        genesis_hash: core.genesis_hash,
        protocol_version: core.protocol_version,
        range_proof_serialization_version: core.range_proof_serialization_version,
        coinbase_maturity: core.coinbase_maturity,
        current_tip: CoreBlockReference {
            height: core.current_tip.height,
            hash: core.current_tip.hash,
        },
    };
    let mut wallet = state();
    let coordinate = wallet
        .reserve_recovery_coordinate(0, RecoveryOutputClass::Coinbase)
        .unwrap();
    let coinbase = RecoverableOutputBuilder::new(&seed(42), &identity)
        .unwrap()
        .build_coinbase(dom_core::BlockHeight(1), 0, coordinate)
        .unwrap();
    let attempts = Arc::new(AtomicU64::new(0));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(mine_wallet_block(
        lifecycle.node_handle().unwrap(),
        &coinbase,
        1,
        Arc::new(AtomicBool::new(true)),
        Arc::clone(&attempts),
    ));
    assert_eq!(result.unwrap(), WalletMiningOutcome::Stopped);
    assert_eq!(attempts.load(Ordering::Relaxed), 0);
    lifecycle.request_shutdown().unwrap();
    lifecycle.wait_for_shutdown().unwrap();
}

fn unused_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}
