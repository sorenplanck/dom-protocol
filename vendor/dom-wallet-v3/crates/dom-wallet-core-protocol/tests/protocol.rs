use dom_consensus::Transaction;
use dom_core::{
    address::{
        ADDRESS_HRP_MAINNET, ADDRESS_HRP_REGTEST, ADDRESS_HRP_TESTNET,
        ADDRESS_KEY_TYPE_SECP256K1_COMPRESSED, ADDRESS_PAYLOAD_VERSION_V3, ADDRESS_TYPE_STANDARD,
        ADDRESS_V3_PAYLOAD_LEN, MAX_ADDRESS_LEN,
    },
    Address,
};
use dom_crypto::{
    bp2_prove, pedersen::Commitment, recovery::RECOVERY_CAPSULE_SIZE, BlindingFactor, PublicKey,
    RangeProof, SecretKey,
};
use dom_serialization::DomSerialize;
use dom_tx::slate::{
    OutputCommitmentAndProof, Slate, SlateEnvelope, CURRENT_SLATE_ENVELOPE_VERSION,
    CURRENT_SLATE_VERSION, RECOVERY_SLATE_ENVELOPE_VERSION, RECOVERY_SLATE_VERSION,
    SLATE_PHASE_SENDER_OFFER,
};
use dom_wallet_core_api::{
    BlockRef, BlockSelector, BlockSummary, ChainIdentity, CoreNetwork, CursorValidation,
    FeeBreakdown, FeeEstimate, FeeEstimateRequest, FeeEstimateTarget, FeePolicySnapshot, FeeRate,
    FeeValidation, KernelQueryResult, MempoolPolicySnapshot, ScanRequest, ScanResult,
    SubmissionResult, SubmitTransactionRequest, SyncStatus, TransactionIdentifier,
    TransactionShape, TransactionStatus, TransactionWeight, UtxoQueryResult, WalletCoreApi,
    WalletCoreError, WalletScanCursor,
};
use dom_wallet_core_protocol::{
    AddressIdentityPurpose, CanonicalSlate, CoreFeePolicyService, ProtocolAdapterError,
    RecoverySlateBody, SlateLifecycleAction, SlateParticipantRole, SlatePhase, SlateReplayKey,
    SlateReplayProtection, WalletAddress, WalletTransactionShape, BASE_SLATE_ENVELOPE_VERSION,
    BASE_SLATE_VERSION, RECOVERY_SLATE_TEXT_PREFIX, WALLET_RECOVERY_SLATE_ENVELOPE_VERSION,
    WALLET_RECOVERY_SLATE_VERSION,
};
use dom_wallet_core_sync::{CoreBlockReference, CoreChainIdentity};
use dom_wallet_embedded_core::{
    EmbeddedCoreConfiguration, EmbeddedCoreLifecycle, EmbeddedCoreNetwork,
};
use std::{
    collections::BTreeSet,
    net::{SocketAddr, TcpListener},
    sync::{Arc, Mutex},
};
use tempfile::TempDir;

const G: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

fn key(mut value: [u8; 33]) -> [u8; 33] {
    value[0] = 0x03;
    value
}

fn identity(network: CoreNetwork) -> CoreChainIdentity {
    CoreChainIdentity {
        network,
        network_magic: network.magic(),
        chain_id: [8; 32],
        genesis_hash: if network == CoreNetwork::Regtest {
            [0; 32]
        } else {
            [9; 32]
        },
        protocol_version: dom_core::PROTOCOL_VERSION,
        range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
        coinbase_maturity: 1,
        current_tip: CoreBlockReference {
            height: 10,
            hash: [7; 32],
        },
    }
}

fn address(network: CoreNetwork, receiver: bool) -> WalletAddress {
    WalletAddress::from_public_key(
        if receiver { key(G) } else { G },
        network,
        AddressIdentityPurpose::TransactionInteraction,
    )
    .unwrap()
}

#[test]
fn address_mainnet_round_trip() {
    let value = address(CoreNetwork::Mainnet, false);
    assert!(value.encode().starts_with("dom1"));
    assert_eq!(
        WalletAddress::parse(&value.encode(), CoreNetwork::Mainnet, value.purpose()).unwrap(),
        value
    );
}

#[test]
fn address_testnet_round_trip() {
    let value = address(CoreNetwork::Testnet, false);
    assert!(value.encode().starts_with("tdom1"));
    assert_eq!(
        WalletAddress::parse(&value.encode(), CoreNetwork::Testnet, value.purpose()).unwrap(),
        value
    );
}

#[test]
fn address_regtest_round_trip() {
    let value = address(CoreNetwork::Regtest, false);
    assert!(value.encode().starts_with("rdom1"));
    assert_eq!(
        WalletAddress::parse(&value.encode(), CoreNetwork::Regtest, value.purpose()).unwrap(),
        value
    );
}

#[test]
fn address_payload_is_exactly_40_bytes() {
    assert_eq!(
        address(CoreNetwork::Regtest, false).payload_bytes().len(),
        40
    );
}
#[test]
fn address_version_is_exactly_one() {
    assert_eq!(address(CoreNetwork::Regtest, false).payload_bytes()[0], 1);
}
#[test]
fn address_type_is_exactly_zero() {
    assert_eq!(address(CoreNetwork::Regtest, false).payload_bytes()[1], 0);
}
#[test]
fn address_key_type_is_exactly_zero() {
    assert_eq!(address(CoreNetwork::Regtest, false).payload_bytes()[2], 0);
}

#[test]
fn address_network_magic_is_little_endian() {
    assert_eq!(
        &address(CoreNetwork::Regtest, false).payload_bytes()[3..7],
        &CoreNetwork::Regtest.magic().to_le_bytes()
    );
}

#[test]
fn address_compressed_key_is_preserved() {
    assert_eq!(address(CoreNetwork::Mainnet, false).public_key(), G);
}

#[test]
fn address_uppercase_is_rejected() {
    let text = address(CoreNetwork::Mainnet, false).encode().to_uppercase();
    assert!(matches!(
        WalletAddress::parse(
            &text,
            CoreNetwork::Mainnet,
            AddressIdentityPurpose::PaymentProof
        ),
        Err(ProtocolAdapterError::NonCanonicalAddress)
    ));
}

#[test]
fn address_mixed_case_is_rejected() {
    let mut text = address(CoreNetwork::Mainnet, false).encode();
    text.replace_range(0..1, "D");
    assert!(WalletAddress::parse(
        &text,
        CoreNetwork::Mainnet,
        AddressIdentityPurpose::PaymentProof
    )
    .is_err());
}

#[test]
fn address_wrong_hrp_is_rejected() {
    let text = address(CoreNetwork::Mainnet, false)
        .encode()
        .replacen("dom", "tdom", 1);
    assert!(WalletAddress::parse(
        &text,
        CoreNetwork::Testnet,
        AddressIdentityPurpose::PaymentProof
    )
    .is_err());
}

#[test]
fn address_wrong_network_is_rejected() {
    let text = address(CoreNetwork::Testnet, false).encode();
    assert!(matches!(
        WalletAddress::parse(
            &text,
            CoreNetwork::Mainnet,
            AddressIdentityPurpose::PaymentProof
        ),
        Err(ProtocolAdapterError::AddressNetworkMismatch)
    ));
}

#[test]
fn address_wrong_magic_binding_is_rejected() {
    let text = address(CoreNetwork::Regtest, false)
        .encode()
        .replacen("rdom", "dom", 1);
    assert!(WalletAddress::parse(
        &text,
        CoreNetwork::Mainnet,
        AddressIdentityPurpose::PaymentProof
    )
    .is_err());
}

#[test]
fn address_wrong_checksum_is_rejected() {
    let mut text = address(CoreNetwork::Mainnet, false).encode();
    let last = text.pop().unwrap();
    text.push(if last == 'q' { 'p' } else { 'q' });
    assert!(WalletAddress::parse(
        &text,
        CoreNetwork::Mainnet,
        AddressIdentityPurpose::PaymentProof
    )
    .is_err());
}

#[test]
fn address_bech32_not_bech32m_is_rejected() {
    assert!(WalletAddress::parse(
        "a12uel5l",
        CoreNetwork::Mainnet,
        AddressIdentityPurpose::PaymentProof
    )
    .is_err());
}

#[test]
fn address_short_payload_is_rejected() {
    assert!(WalletAddress::parse(
        "dom1qqqqqq",
        CoreNetwork::Mainnet,
        AddressIdentityPurpose::PaymentProof
    )
    .is_err());
}

#[test]
fn address_long_payload_is_rejected() {
    let text = "d".repeat(MAX_ADDRESS_LEN + 1);
    assert!(WalletAddress::parse(
        &text,
        CoreNetwork::Mainnet,
        AddressIdentityPurpose::PaymentProof
    )
    .is_err());
}

fn encoded_core_address(version: u8, address_type: u8, key_type: u8, payload: [u8; 33]) -> String {
    Address {
        payload,
        is_mainnet: true,
        version,
        address_type,
        key_type,
        network_magic: CoreNetwork::Mainnet.magic(),
    }
    .encode()
}

#[test]
fn address_unsupported_version_is_rejected() {
    assert!(WalletAddress::parse(
        &encoded_core_address(2, 0, 0, G),
        CoreNetwork::Mainnet,
        AddressIdentityPurpose::PaymentProof
    )
    .is_err());
}
#[test]
fn address_unsupported_type_is_rejected() {
    assert!(WalletAddress::parse(
        &encoded_core_address(1, 1, 0, G),
        CoreNetwork::Mainnet,
        AddressIdentityPurpose::PaymentProof
    )
    .is_err());
}
#[test]
fn address_unsupported_key_type_is_rejected() {
    assert!(WalletAddress::parse(
        &encoded_core_address(1, 0, 1, G),
        CoreNetwork::Mainnet,
        AddressIdentityPurpose::PaymentProof
    )
    .is_err());
}
#[test]
fn address_malformed_curve_key_is_rejected() {
    let mut malformed = [0xff; 33];
    malformed[0] = 0x02;
    assert!(WalletAddress::parse(
        &encoded_core_address(1, 0, 0, malformed),
        CoreNetwork::Mainnet,
        AddressIdentityPurpose::PaymentProof
    )
    .is_err());
}
#[test]
fn address_trailing_data_is_rejected() {
    let text = format!("{}q", address(CoreNetwork::Mainnet, false).encode());
    assert!(WalletAddress::parse(
        &text,
        CoreNetwork::Mainnet,
        AddressIdentityPurpose::PaymentProof
    )
    .is_err());
}
#[test]
fn address_maximum_text_length_is_enforced() {
    assert!(address(CoreNetwork::Mainnet, false).encode().len() <= MAX_ADDRESS_LEN);
    assert!(WalletAddress::parse(
        &"q".repeat(MAX_ADDRESS_LEN + 1),
        CoreNetwork::Mainnet,
        AddressIdentityPurpose::PaymentProof
    )
    .is_err());
}
#[test]
fn address_key_purpose_is_explicit_and_separate() {
    let interaction = WalletAddress::from_public_key(
        G,
        CoreNetwork::Mainnet,
        AddressIdentityPurpose::TransactionInteraction,
    )
    .unwrap();
    let proof = WalletAddress::from_public_key(
        G,
        CoreNetwork::Mainnet,
        AddressIdentityPurpose::PaymentProof,
    )
    .unwrap();
    assert_eq!(interaction.encode(), proof.encode());
    assert_ne!(interaction.purpose(), proof.purpose());
}

fn public_key(byte: u8) -> PublicKey {
    SecretKey::from_bytes(&[byte; 32]).unwrap().public_key()
}

fn output(value: u64, blind: u8) -> OutputCommitmentAndProof {
    let blinding = BlindingFactor::from_bytes([blind; 32]).unwrap();
    let (proof, commitment) = bp2_prove(value, &blinding).unwrap();
    OutputCommitmentAndProof {
        commitment: Commitment::from_compressed_bytes(&commitment).unwrap(),
        proof: RangeProof::from_bytes(proof).unwrap(),
    }
}

fn capsule(marker: u8) -> Vec<u8> {
    let mut value = vec![marker; RECOVERY_CAPSULE_SIZE];
    value[0..2].copy_from_slice(&1u16.to_le_bytes());
    value[14..16].copy_from_slice(&80u16.to_le_bytes());
    value
}

fn slate(change: bool, recipient: bool) -> Slate {
    Slate {
        version: RECOVERY_SLATE_VERSION,
        chain_id: [8; 32],
        amount: 10_000,
        fee: 45_000,
        lock_height: 0,
        sender_inputs: Vec::new(),
        sender_change_output: change.then(|| output(2_000, 3)),
        sender_public_excess: public_key(4),
        sender_public_nonce: public_key(5),
        sender_offset_contribution: [6; 32],
        recipient_output: recipient.then(|| output(10_000, 7)),
        recipient_public_excess: recipient.then(|| public_key(8)),
        recipient_public_nonce: recipient.then(|| public_key(9)),
        sender_partial_sig: None,
        recipient_partial_sig: None,
        sender_change_recovery_capsule: if change { capsule(0x31) } else { Vec::new() },
        recipient_recovery_capsule: if recipient { capsule(0x41) } else { Vec::new() },
    }
}

fn core_envelope(change: bool, recipient: bool) -> SlateEnvelope {
    let id = identity(CoreNetwork::Regtest);
    SlateEnvelope::new(
        id.network_magic,
        id.chain_id,
        [0x11; 32],
        [0x12; 32],
        SLATE_PHASE_SENDER_OFFER,
        20,
        address(CoreNetwork::Regtest, false).core_for_test(),
        address(CoreNetwork::Regtest, true).core_for_test(),
        slate(change, recipient),
    )
    .unwrap()
}

trait TestAddressCore {
    fn core_for_test(&self) -> Address;
}
impl TestAddressCore for WalletAddress {
    fn core_for_test(&self) -> Address {
        Address::decode(&self.encode()).unwrap()
    }
}

fn canonical(change: bool, recipient: bool) -> CanonicalSlate {
    let envelope = core_envelope(change, recipient);
    CanonicalSlate::from_recovery_bytes(
        &envelope.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10,
    )
    .unwrap()
}

#[derive(Default)]
struct ReplaySet(BTreeSet<SlateReplayKey>);
impl SlateReplayProtection for ReplaySet {
    fn record_if_fresh(&mut self, key: SlateReplayKey) -> Result<bool, ProtocolAdapterError> {
        Ok(self.0.insert(key))
    }
}

#[test]
fn slate_base_version_constants_match_core() {
    assert_eq!((BASE_SLATE_VERSION, BASE_SLATE_ENVELOPE_VERSION), (3, 3));
}
#[test]
fn slate_recovery_version_constants_match_core() {
    assert_eq!(
        (
            WALLET_RECOVERY_SLATE_VERSION,
            WALLET_RECOVERY_SLATE_ENVELOPE_VERSION
        ),
        (4, 4)
    );
}
#[test]
fn slate_canonical_request_encoding() {
    let body = slate(true, false).to_canonical_bytes().unwrap();
    let value = CanonicalSlate::new_recoverable(
        &identity(CoreNetwork::Regtest),
        [0x11; 32],
        [0x12; 32],
        SlatePhase::SenderOffer,
        20,
        &address(CoreNetwork::Regtest, false),
        &address(CoreNetwork::Regtest, true),
        RecoverySlateBody::from_canonical_bytes(&body).unwrap(),
    )
    .unwrap();
    assert_eq!(value.phase().unwrap(), SlatePhase::SenderOffer);
}
#[test]
fn slate_canonical_response_encoding() {
    let mut envelope = core_envelope(true, true);
    envelope.phase = dom_tx::slate::SLATE_PHASE_RECEIVER_RESPONSE;
    assert!(CanonicalSlate::from_recovery_bytes(
        &envelope.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10
    )
    .is_ok());
}
#[test]
fn slate_encode_decode_bytes_are_equal() {
    let value = canonical(true, true);
    assert_eq!(
        CanonicalSlate::from_recovery_bytes(
            value.canonical_bytes(),
            &identity(CoreNetwork::Regtest),
            10
        )
        .unwrap()
        .canonical_bytes(),
        value.canonical_bytes()
    );
}
#[test]
fn slate_correct_network_is_accepted() {
    assert!(CanonicalSlate::from_recovery_bytes(
        &core_envelope(false, false).to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10
    )
    .is_ok());
}
#[test]
fn slate_wrong_network_is_rejected() {
    assert!(matches!(
        CanonicalSlate::from_recovery_bytes(
            &core_envelope(false, false).to_canonical_bytes().unwrap(),
            &identity(CoreNetwork::Testnet),
            10
        ),
        Err(ProtocolAdapterError::SlateNetworkMismatch)
    ));
}
#[test]
fn slate_correct_chain_is_accepted() {
    assert_eq!(canonical(false, false).replay_key().slate_id, [0x11; 32]);
}
#[test]
fn slate_wrong_chain_is_rejected() {
    let mut expected = identity(CoreNetwork::Regtest);
    expected.chain_id = [0x99; 32];
    assert!(matches!(
        CanonicalSlate::from_recovery_bytes(
            &core_envelope(false, false).to_canonical_bytes().unwrap(),
            &expected,
            10
        ),
        Err(ProtocolAdapterError::SlateChainMismatch)
    ));
}
#[test]
fn slate_wrong_envelope_version_is_rejected() {
    let mut value = core_envelope(false, false);
    value.envelope_version = CURRENT_SLATE_ENVELOPE_VERSION;
    assert!(CanonicalSlate::from_recovery_bytes(
        &value.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10
    )
    .is_err());
}
#[test]
fn slate_wrong_body_version_is_rejected() {
    let mut value = core_envelope(false, false);
    value.body.version = CURRENT_SLATE_VERSION;
    assert!(CanonicalSlate::from_recovery_bytes(
        &value.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10
    )
    .is_err());
}
#[test]
fn slate_replay_id_is_bound() {
    let value = canonical(false, false);
    let digest = value
        .signature_digest(SlateParticipantRole::Sender)
        .unwrap();
    let mut changed = core_envelope(false, false);
    changed.replay_id = [0x44; 32];
    let changed = CanonicalSlate::from_recovery_bytes(
        &changed.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10,
    )
    .unwrap();
    assert_ne!(
        digest,
        changed
            .signature_digest(SlateParticipantRole::Sender)
            .unwrap()
    );
}
#[test]
fn slate_duplicate_replay_is_rejected() {
    let value = canonical(false, false);
    let mut replay = ReplaySet::default();
    value.record_replay(&mut replay).unwrap();
    assert!(matches!(
        value.record_replay(&mut replay),
        Err(ProtocolAdapterError::DuplicateReplay)
    ));
}
#[test]
fn slate_flow_is_bound() {
    assert_eq!(
        core_envelope(false, false).flow,
        dom_tx::slate::SLATE_FLOW_STANDARD_SEND
    );
}
#[test]
fn slate_phase_is_bound() {
    let sender = canonical(false, false)
        .signature_digest(SlateParticipantRole::Sender)
        .unwrap();
    let mut changed = core_envelope(false, false);
    changed.phase = dom_tx::slate::SLATE_PHASE_FINALIZED;
    let changed = CanonicalSlate::from_recovery_bytes(
        &changed.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10,
    )
    .unwrap();
    assert_ne!(
        sender,
        changed
            .signature_digest(SlateParticipantRole::Sender)
            .unwrap()
    );
}
#[test]
fn slate_role_is_bound() {
    let value = canonical(false, false);
    assert_ne!(
        value
            .signature_digest(SlateParticipantRole::Sender)
            .unwrap(),
        value
            .signature_digest(SlateParticipantRole::Receiver)
            .unwrap()
    );
}
#[test]
fn slate_role_substitution_is_rejected() {
    let value = canonical(false, false);
    let sender = value
        .signature_digest(SlateParticipantRole::Sender)
        .unwrap();
    assert!(matches!(
        value.validate_signature_digest(SlateParticipantRole::Receiver, sender),
        Err(ProtocolAdapterError::SlateDomainMismatch)
    ));
}
#[test]
fn slate_fee_mutation_is_rejected_by_domain() {
    let value = canonical(false, false);
    let digest = value
        .signature_digest(SlateParticipantRole::Sender)
        .unwrap();
    let mut changed = core_envelope(false, false);
    changed.body.fee += 1;
    let changed = CanonicalSlate::from_recovery_bytes(
        &changed.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10,
    )
    .unwrap();
    assert!(changed
        .validate_signature_digest(SlateParticipantRole::Sender, digest)
        .is_err());
}
#[test]
fn slate_body_mutation_is_rejected_by_domain() {
    let value = canonical(false, false);
    let digest = value
        .signature_digest(SlateParticipantRole::Sender)
        .unwrap();
    let mut changed = core_envelope(false, false);
    changed.body.amount += 1;
    let changed = CanonicalSlate::from_recovery_bytes(
        &changed.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10,
    )
    .unwrap();
    assert!(changed
        .validate_signature_digest(SlateParticipantRole::Sender, digest)
        .is_err());
}
#[test]
fn slate_duplicate_participant_is_rejected() {
    let id = identity(CoreNetwork::Regtest);
    let same = address(CoreNetwork::Regtest, false).core_for_test();
    assert!(SlateEnvelope::new(
        id.network_magic,
        id.chain_id,
        [1; 32],
        [2; 32],
        0,
        20,
        same.clone(),
        same,
        slate(false, false)
    )
    .is_err());
}
#[test]
fn slate_malformed_participant_address_is_rejected() {
    let mut bytes = core_envelope(false, false).to_canonical_bytes().unwrap();
    bytes[119] = 4;
    assert!(
        CanonicalSlate::from_recovery_bytes(&bytes, &identity(CoreNetwork::Regtest), 10).is_err()
    );
}
#[test]
fn slate_expiry_exact_height_is_accepted() {
    assert!(canonical(false, false).validate_height(20).is_ok());
}
#[test]
fn slate_expiry_after_height_is_rejected() {
    assert!(matches!(
        canonical(false, false).validate_height(21),
        Err(ProtocolAdapterError::SlateExpired)
    ));
}
#[test]
fn slate_cancellation_is_local_lifecycle_action() {
    assert_eq!(
        canonical(false, false).cancel(),
        SlateLifecycleAction::Cancelled
    );
}
#[test]
fn slate_resend_preserves_exact_bytes() {
    let value = canonical(false, false);
    let (bytes, action) = value.resend();
    assert_eq!(action, SlateLifecycleAction::ResendUnmodified);
    assert_eq!(bytes, value.canonical_bytes());
}
#[test]
fn slate_unsupported_flow_is_rejected() {
    let mut value = core_envelope(false, false);
    value.flow = 1;
    assert!(CanonicalSlate::from_recovery_bytes(
        &value.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10
    )
    .is_err());
}
#[test]
fn slate_sender_change_sidecar_is_preserved() {
    assert_eq!(
        canonical(true, false)
            .recovery_sidecars()
            .unwrap()
            .sender_change
            .unwrap()
            .as_slice(),
        capsule(0x31)
    );
}
#[test]
fn slate_recipient_sidecar_is_preserved() {
    assert_eq!(
        canonical(false, true)
            .recovery_sidecars()
            .unwrap()
            .recipient
            .unwrap()
            .as_slice(),
        capsule(0x41)
    );
}
#[test]
fn slate_sidecar_mutation_is_rejected_by_domain() {
    let value = canonical(true, false);
    let digest = value
        .signature_digest(SlateParticipantRole::Sender)
        .unwrap();
    let mut changed = core_envelope(true, false);
    changed.body.sender_change_recovery_capsule[20] ^= 1;
    let changed = CanonicalSlate::from_recovery_bytes(
        &changed.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10,
    )
    .unwrap();
    assert!(changed
        .validate_signature_digest(SlateParticipantRole::Sender, digest)
        .is_err());
}
#[test]
fn slate_sidecar_role_swap_is_rejected_by_domain() {
    let value = canonical(true, true);
    let digest = value
        .signature_digest(SlateParticipantRole::Sender)
        .unwrap();
    let mut changed = core_envelope(true, true);
    std::mem::swap(
        &mut changed.body.sender_change_recovery_capsule,
        &mut changed.body.recipient_recovery_capsule,
    );
    let changed = CanonicalSlate::from_recovery_bytes(
        &changed.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10,
    )
    .unwrap();
    assert!(changed
        .validate_signature_digest(SlateParticipantRole::Sender, digest)
        .is_err());
}
#[test]
fn slate_missing_required_sidecar_is_rejected() {
    let mut changed = core_envelope(true, false);
    changed.body.sender_change_recovery_capsule.clear();
    assert!(CanonicalSlate::from_recovery_bytes(
        &changed.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10
    )
    .is_err());
}
#[test]
fn slate_duplicate_sidecar_bytes_are_rejected() {
    let mut changed = core_envelope(true, false);
    changed
        .body
        .sender_change_recovery_capsule
        .extend(capsule(0x31));
    assert!(CanonicalSlate::from_recovery_bytes(
        &changed.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10
    )
    .is_err());
}
#[test]
fn slate_malformed_sidecar_is_rejected() {
    let mut changed = core_envelope(true, false);
    changed.body.sender_change_recovery_capsule[0] = 2;
    assert!(CanonicalSlate::from_recovery_bytes(
        &changed.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10
    )
    .is_err());
}
#[test]
fn slate_text_transport_round_trip() {
    let value = canonical(true, true);
    let text = value.to_text();
    assert!(text.starts_with(RECOVERY_SLATE_TEXT_PREFIX));
    assert_eq!(
        CanonicalSlate::from_text(&text, &identity(CoreNetwork::Regtest), 10)
            .unwrap()
            .canonical_bytes(),
        value.canonical_bytes()
    );
}
#[test]
fn slate_qr_compatible_bytes_round_trip() {
    let bytes = canonical(true, true).canonical_bytes().to_vec();
    assert_eq!(
        CanonicalSlate::from_recovery_bytes(&bytes, &identity(CoreNetwork::Regtest), 10)
            .unwrap()
            .canonical_bytes(),
        bytes
    );
}
#[test]
fn slate_trailing_data_is_rejected() {
    let mut bytes = canonical(false, false).canonical_bytes().to_vec();
    bytes.push(0);
    assert!(
        CanonicalSlate::from_recovery_bytes(&bytes, &identity(CoreNetwork::Regtest), 10).is_err()
    );
}
#[test]
fn slate_malformed_encoding_fails_closed() {
    assert!(
        CanonicalSlate::from_text("DOMSLATE4.%%%", &identity(CoreNetwork::Regtest), 10).is_err()
    );
}
#[test]
fn slate_signature_domain_covers_all_envelope_and_body_fields() {
    let value = canonical(true, true);
    let digest = value
        .signature_digest(SlateParticipantRole::Sender)
        .unwrap();
    let mut changed = core_envelope(true, true);
    changed.expires_at_height += 1;
    let changed = CanonicalSlate::from_recovery_bytes(
        &changed.to_canonical_bytes().unwrap(),
        &identity(CoreNetwork::Regtest),
        10,
    )
    .unwrap();
    assert_ne!(
        digest,
        changed
            .signature_digest(SlateParticipantRole::Sender)
            .unwrap()
    );
}

#[derive(Clone)]
struct FakeFeeCore(Arc<Mutex<FeeState>>);

#[derive(Clone)]
struct FeeState {
    identity: ChainIdentity,
    policy: FeePolicySnapshot,
    unavailable: bool,
    validation: FeeValidation,
}

impl FakeFeeCore {
    fn new() -> Self {
        let identity = core_identity(CoreNetwork::Regtest);
        let breakdown = breakdown(TransactionShape {
            input_count: 1,
            output_count: 1,
            kernel_count: 1,
        });
        Self(Arc::new(Mutex::new(FeeState {
            identity,
            policy: policy(CoreNetwork::Regtest),
            unavailable: false,
            validation: FeeValidation {
                accepted_by_policy: true,
                actual_fee_noms: breakdown.minimum_fee_noms,
                minimum_fee_noms: breakdown.minimum_fee_noms,
                shortfall_noms: 0,
                actual_fee_rate: FeeRate {
                    noms_per_weight_unit: 1_000,
                },
                breakdown,
            },
        })))
    }
    fn service(&self) -> Result<CoreFeePolicyService, ProtocolAdapterError> {
        CoreFeePolicyService::connect(Arc::new(self.clone()), identity(CoreNetwork::Regtest))
    }
    fn update(&self, f: impl FnOnce(&mut FeeState)) {
        f(&mut self.0.lock().unwrap());
    }
    fn state(&self) -> FeeState {
        self.0.lock().unwrap().clone()
    }
}

fn core_identity(network: CoreNetwork) -> ChainIdentity {
    let value = identity(network);
    ChainIdentity {
        network,
        network_magic: value.network_magic,
        chain_id: value.chain_id,
        genesis_hash: value.genesis_hash,
        protocol_version: value.protocol_version,
        range_proof_serialization_version: value.range_proof_serialization_version,
        coinbase_maturity: value.coinbase_maturity,
        current_tip: BlockRef {
            height: value.current_tip.height,
            hash: value.current_tip.hash,
        },
    }
}

fn policy(network: CoreNetwork) -> FeePolicySnapshot {
    FeePolicySnapshot {
        policy_version: 1,
        network,
        min_relay_fee_rate: 1_000,
        min_mempool_fee_rate: 1_000,
        recommended_fee_rate: 2_000,
        dust_threshold_noms: 0,
        max_tx_weight: 4_000,
        validity_horizon: None,
    }
}

fn weight(shape: TransactionShape) -> TransactionWeight {
    let input_weight = u64::from(shape.input_count);
    let output_weight = u64::from(shape.output_count) * 21;
    let kernel_weight = u64::from(shape.kernel_count) * 3;
    TransactionWeight {
        input_weight,
        output_weight,
        kernel_weight,
        total_weight: input_weight + output_weight + kernel_weight,
    }
}

fn breakdown(shape: TransactionShape) -> FeeBreakdown {
    let weight = weight(shape);
    let minimum = weight.total_weight * 1_000;
    FeeBreakdown {
        input_count: shape.input_count,
        output_count: shape.output_count,
        kernel_count: shape.kernel_count,
        input_weight: weight.input_weight,
        output_weight: weight.output_weight,
        kernel_weight: weight.kernel_weight,
        total_weight: weight.total_weight,
        minimum_fee_noms: minimum,
        recommended_fee_noms: minimum * 2,
        minimum_fee_rate: FeeRate {
            noms_per_weight_unit: 1_000,
        },
        recommended_fee_rate: FeeRate {
            noms_per_weight_unit: 2_000,
        },
        policy_version: 1,
        network: CoreNetwork::Regtest,
        validity_horizon: None,
        dust_threshold_noms: 0,
    }
}

impl WalletCoreApi for FakeFeeCore {
    fn chain_identity(&self) -> Result<ChainIdentity, WalletCoreError> {
        Ok(self.state().identity)
    }
    fn scan_range(&self, _: ScanRequest) -> Result<ScanResult, WalletCoreError> {
        unreachable!()
    }
    fn validate_cursor(&self, _: WalletScanCursor) -> Result<CursorValidation, WalletCoreError> {
        unreachable!()
    }
    fn canonical_hash_at_height(&self, _: u64) -> Result<Option<[u8; 32]>, WalletCoreError> {
        unreachable!()
    }
    fn get_utxo(&self, _: &[u8; 33]) -> Result<Option<UtxoQueryResult>, WalletCoreError> {
        unreachable!()
    }
    fn get_kernel(&self, _: &[u8; 33]) -> Result<Option<KernelQueryResult>, WalletCoreError> {
        unreachable!()
    }
    fn get_block_summary(&self, _: BlockSelector) -> Result<Option<BlockSummary>, WalletCoreError> {
        unreachable!()
    }
    fn transaction_status(
        &self,
        _: TransactionIdentifier,
    ) -> Result<TransactionStatus, WalletCoreError> {
        unreachable!()
    }
    fn submit_transaction(
        &self,
        _: SubmitTransactionRequest,
    ) -> Result<SubmissionResult, WalletCoreError> {
        unreachable!()
    }
    fn rebroadcast_transaction(
        &self,
        _: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        unreachable!()
    }
    fn query_submission(
        &self,
        _: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        unreachable!()
    }
    fn sync_status(&self) -> Result<SyncStatus, WalletCoreError> {
        unreachable!()
    }
    fn is_ready_for_wallet_operations(&self) -> Result<bool, WalletCoreError> {
        unreachable!()
    }
    fn mempool_policy_snapshot(&self) -> Result<MempoolPolicySnapshot, WalletCoreError> {
        unreachable!()
    }
    fn fee_policy_snapshot(&self) -> Result<FeePolicySnapshot, WalletCoreError> {
        let state = self.state();
        if state.unavailable {
            Err(WalletCoreError::NodeNotReady("test".into()))
        } else {
            Ok(state.policy)
        }
    }
    fn transaction_weight(
        &self,
        shape: TransactionShape,
    ) -> Result<TransactionWeight, WalletCoreError> {
        if shape.input_count == u32::MAX {
            Err(WalletCoreError::InternalFailure("overflow".into()))
        } else {
            Ok(weight(shape))
        }
    }
    fn minimum_fee(&self, shape: TransactionShape) -> Result<FeeBreakdown, WalletCoreError> {
        Ok(breakdown(shape))
    }
    fn estimate_fee(&self, request: FeeEstimateRequest) -> Result<FeeEstimate, WalletCoreError> {
        let breakdown = breakdown(request.shape);
        let recommended = request.target == FeeEstimateTarget::Recommended;
        Ok(FeeEstimate {
            selected_fee_noms: if recommended {
                breakdown.recommended_fee_noms
            } else {
                breakdown.minimum_fee_noms
            },
            selected_fee_rate: if recommended {
                breakdown.recommended_fee_rate
            } else {
                breakdown.minimum_fee_rate
            },
            breakdown,
        })
    }
    fn validate_fee(&self, _: &Transaction) -> Result<FeeValidation, WalletCoreError> {
        Ok(self.state().validation)
    }
}

fn shape() -> WalletTransactionShape {
    WalletTransactionShape {
        input_count: 1,
        output_count: 1,
        kernel_count: 1,
    }
}
fn empty_tx() -> Transaction {
    Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
        kernels: Vec::new(),
        offset: [0; 32],
    }
}

fn empty_tx_bytes() -> Vec<u8> {
    empty_tx().to_bytes().unwrap()
}

#[test]
fn fee_policy_version_one() {
    assert_eq!(
        FakeFeeCore::new()
            .service()
            .unwrap()
            .policy()
            .unwrap()
            .policy_version,
        1
    );
}
#[test]
fn fee_policy_network_binding() {
    assert_eq!(
        FakeFeeCore::new()
            .service()
            .unwrap()
            .policy()
            .unwrap()
            .network,
        CoreNetwork::Regtest
    );
}
#[test]
fn fee_minimum_vector() {
    assert_eq!(
        FakeFeeCore::new()
            .service()
            .unwrap()
            .minimum_fee(shape())
            .unwrap()
            .minimum_fee_noms,
        25_000
    );
}
#[test]
fn fee_recommended_vector() {
    assert_eq!(
        FakeFeeCore::new()
            .service()
            .unwrap()
            .recommended_fee(shape())
            .unwrap()
            .selected_fee_noms,
        50_000
    );
}
#[test]
fn fee_zero_shape_boundary_comes_from_core() {
    let value = FakeFeeCore::new()
        .service()
        .unwrap()
        .transaction_weight(WalletTransactionShape {
            input_count: 0,
            output_count: 0,
            kernel_count: 0,
        })
        .unwrap();
    assert_eq!(value.total_weight, 0);
}
#[test]
fn fee_weight_vector() {
    assert_eq!(
        FakeFeeCore::new()
            .service()
            .unwrap()
            .transaction_weight(shape())
            .unwrap()
            .total_weight,
        25
    );
}
#[test]
fn fee_exact_threshold_is_accepted() {
    assert!(
        FakeFeeCore::new()
            .service()
            .unwrap()
            .validate_fee(&empty_tx_bytes())
            .unwrap()
            .accepted_by_policy
    );
}
#[test]
fn fee_one_below_minimum_is_rejected() {
    let core = FakeFeeCore::new();
    core.update(|s| {
        s.validation.accepted_by_policy = false;
        s.validation.actual_fee_noms -= 1;
        s.validation.shortfall_noms = 1;
    });
    assert!(
        !core
            .service()
            .unwrap()
            .validate_fee(&empty_tx_bytes())
            .unwrap()
            .accepted_by_policy
    );
}
#[test]
fn fee_recommendation_is_not_minimum() {
    let service = FakeFeeCore::new().service().unwrap();
    assert!(
        service.recommended_fee(shape()).unwrap().selected_fee_noms
            > service.minimum_fee(shape()).unwrap().selected_fee_noms
    );
}
#[test]
fn fee_overflow_fails_closed_through_core() {
    assert!(FakeFeeCore::new()
        .service()
        .unwrap()
        .transaction_weight(WalletTransactionShape {
            input_count: u32::MAX,
            output_count: 0,
            kernel_count: 0
        })
        .is_err());
}
#[test]
fn fee_maximum_weight_is_preserved() {
    assert_eq!(
        FakeFeeCore::new()
            .service()
            .unwrap()
            .policy()
            .unwrap()
            .maximum_transaction_weight,
        4_000
    );
}
#[test]
fn fee_dust_threshold_is_zero() {
    assert_eq!(
        FakeFeeCore::new()
            .service()
            .unwrap()
            .policy()
            .unwrap()
            .dust_threshold_noms,
        0
    );
}
#[test]
fn fee_adapter_adds_no_dust_rejection() {
    assert_eq!(
        FakeFeeCore::new()
            .service()
            .unwrap()
            .minimum_fee(shape())
            .unwrap()
            .dust_threshold_noms,
        0
    );
}
#[test]
fn fee_core_unavailable_is_typed() {
    let core = FakeFeeCore::new();
    core.update(|s| s.unavailable = true);
    assert!(matches!(
        core.service(),
        Err(ProtocolAdapterError::CoreUnavailable { .. })
    ));
}
#[test]
fn fee_wrong_chain_is_rejected() {
    let core = FakeFeeCore::new();
    let service = core.service().unwrap();
    core.update(|s| s.identity.chain_id = [0x55; 32]);
    assert!(matches!(
        service.policy(),
        Err(ProtocolAdapterError::ChainIdentityMismatch)
    ));
}
#[test]
fn fee_wrong_policy_version_is_rejected() {
    let core = FakeFeeCore::new();
    core.update(|s| s.policy.policy_version = 2);
    assert!(matches!(
        core.service(),
        Err(ProtocolAdapterError::UnsupportedFeePolicyVersion)
    ));
}
#[test]
fn fee_inconsistent_snapshot_is_rejected() {
    let core = FakeFeeCore::new();
    core.update(|s| s.policy.recommended_fee_rate = 999);
    assert!(matches!(
        core.service(),
        Err(ProtocolAdapterError::InconsistentFeePolicy)
    ));
}
#[test]
fn fee_adapter_uses_core_breakdown_without_private_formula() {
    let core = FakeFeeCore::new();
    let value = core.service().unwrap().estimate_fee(shape()).unwrap();
    assert_eq!(
        value.weight.total_weight,
        breakdown(shape().core_for_test()).total_weight
    );
}

trait TestShapeCore {
    fn core_for_test(self) -> TransactionShape;
}
impl TestShapeCore for WalletTransactionShape {
    fn core_for_test(self) -> TransactionShape {
        TransactionShape {
            input_count: self.input_count,
            output_count: self.output_count,
            kernel_count: self.kernel_count,
        }
    }
}

#[test]
fn real_embedded_core_identity_fee_and_address_network_agree() {
    let directory = TempDir::new().unwrap();
    let mut lifecycle = EmbeddedCoreLifecycle::new(EmbeddedCoreConfiguration::new(
        EmbeddedCoreNetwork::Regtest,
        directory.path(),
        unused_loopback_address(),
    ));
    lifecycle.start().unwrap();
    let api = lifecycle.wallet_api().unwrap();
    let core = api.chain_identity().unwrap();
    let expected = CoreChainIdentity {
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
    let policy = CoreFeePolicyService::connect(api, expected)
        .unwrap()
        .policy()
        .unwrap();
    assert_eq!(policy.policy_version, 1);
    assert_eq!(policy.minimum_relay_fee_rate, 1_000);
    assert_eq!(policy.recommended_fee_rate, 2_000);
    assert_eq!(
        address(policy.network, false).network().unwrap(),
        policy.network
    );
    lifecycle.request_shutdown().unwrap();
    lifecycle.wait_for_shutdown().unwrap();
}

fn unused_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

#[test]
fn frozen_address_constants_are_exact() {
    assert_eq!(
        (
            ADDRESS_HRP_MAINNET,
            ADDRESS_HRP_TESTNET,
            ADDRESS_HRP_REGTEST
        ),
        ("dom", "tdom", "rdom")
    );
    assert_eq!(
        (
            ADDRESS_PAYLOAD_VERSION_V3,
            ADDRESS_TYPE_STANDARD,
            ADDRESS_KEY_TYPE_SECP256K1_COMPRESSED,
            ADDRESS_V3_PAYLOAD_LEN
        ),
        (1, 0, 0, 40)
    );
    assert_eq!(
        (
            CURRENT_SLATE_VERSION,
            CURRENT_SLATE_ENVELOPE_VERSION,
            RECOVERY_SLATE_VERSION,
            RECOVERY_SLATE_ENVELOPE_VERSION
        ),
        (3, 3, 4, 4)
    );
}
