use dom_core::{Address, DomError, NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET};
use dom_crypto::{PartialSig, PublicKey, SecretKey};
use dom_tx::slate::{
    Slate, SlateEnvelope, CURRENT_SLATE_ENVELOPE_VERSION, CURRENT_SLATE_VERSION,
    SLATE_FLOW_STANDARD_SEND, SLATE_PHASE_SENDER_OFFER, SLATE_ROLE_RECEIVER, SLATE_ROLE_SENDER,
};

const CHAIN_ID: [u8; 32] = [0x41; 32];
const WRONG_CHAIN_ID: [u8; 32] = [0x42; 32];
const SLATE_ID: [u8; 32] = [0x51; 32];
const REPLAY_ID: [u8; 32] = [0x61; 32];

fn public_key(secret_byte: u8) -> PublicKey {
    SecretKey::from_bytes(&[secret_byte; 32])
        .expect("valid secret")
        .public_key()
}

fn address(secret_byte: u8) -> Address {
    Address::new_for_network(
        public_key(secret_byte).to_compressed_bytes(),
        NETWORK_MAGIC_REGTEST,
    )
    .expect("valid address")
}

fn slate() -> Slate {
    Slate {
        version: CURRENT_SLATE_VERSION,
        chain_id: CHAIN_ID,
        amount: 1_000,
        fee: 20,
        lock_height: 144,
        sender_inputs: Vec::new(),
        sender_change_output: None,
        sender_public_excess: public_key(3),
        sender_public_nonce: public_key(4),
        sender_offset_contribution: [0x71; 32],
        recipient_output: None,
        recipient_public_excess: None,
        recipient_public_nonce: None,
        sender_partial_sig: Some(PartialSig::from_bytes(&[0x11; 32]).expect("partial")),
        recipient_partial_sig: None,
        sender_change_recovery_capsule: Vec::new(),
        recipient_recovery_capsule: Vec::new(),
    }
}

fn envelope() -> SlateEnvelope {
    SlateEnvelope::new(
        NETWORK_MAGIC_REGTEST,
        CHAIN_ID,
        SLATE_ID,
        REPLAY_ID,
        SLATE_PHASE_SENDER_OFFER,
        500,
        address(5),
        address(6),
        slate(),
    )
    .expect("valid envelope")
}

#[test]
fn slate_v3_envelope_roundtrip_is_canonical() {
    let envelope = envelope();
    let bytes = envelope.to_canonical_bytes().expect("encode");
    let decoded = SlateEnvelope::from_canonical_bytes(&bytes).expect("decode");
    assert_eq!(decoded, envelope);
    assert_eq!(decoded.to_canonical_bytes().expect("re-encode"), bytes);
}

#[test]
fn slate_v3_signature_digest_is_deterministic_and_role_bound() {
    let envelope = envelope();
    let sender = envelope
        .signature_digest(SLATE_ROLE_SENDER)
        .expect("sender digest");
    let sender_again = envelope
        .signature_digest(SLATE_ROLE_SENDER)
        .expect("sender digest again");
    let receiver = envelope
        .signature_digest(SLATE_ROLE_RECEIVER)
        .expect("receiver digest");
    assert_eq!(sender, sender_again);
    assert_ne!(sender, receiver);
}

#[test]
fn slate_v3_digest_changes_when_fee_changes() {
    let mut changed = envelope();
    let original = changed
        .signature_digest(SLATE_ROLE_SENDER)
        .expect("original digest");
    changed.body.fee = changed.body.fee.saturating_add(1);
    let mutated = changed
        .signature_digest(SLATE_ROLE_SENDER)
        .expect("mutated digest");
    assert_ne!(original, mutated);
}

#[test]
fn slate_v3_wrong_chain_id_is_rejected() {
    let mut envelope = envelope();
    envelope.chain_id = WRONG_CHAIN_ID;
    assert!(matches!(envelope.validate(), Err(DomError::Invalid(_))));
}

#[test]
fn slate_v3_wrong_network_address_is_rejected() {
    let mut envelope = envelope();
    envelope.receiver_address =
        Address::new_for_network(public_key(7).to_compressed_bytes(), NETWORK_MAGIC_TESTNET)
            .expect("valid testnet address");
    assert!(matches!(envelope.validate(), Err(DomError::Malformed(_))));
}

#[test]
fn slate_v3_expiration_is_height_based() {
    let envelope = envelope();
    assert!(!envelope.is_expired_at(500));
    assert!(envelope.is_expired_at(501));
}

#[test]
fn slate_v3_unsupported_version_and_flow_are_rejected() {
    let mut wrong_version = envelope();
    wrong_version.envelope_version = CURRENT_SLATE_ENVELOPE_VERSION + 1;
    assert!(matches!(
        wrong_version.validate(),
        Err(DomError::Invalid(_))
    ));

    let mut wrong_flow = envelope();
    wrong_flow.flow = SLATE_FLOW_STANDARD_SEND + 1;
    assert!(matches!(wrong_flow.validate(), Err(DomError::Invalid(_))));
}

#[test]
fn slate_v3_duplicate_participant_identity_is_rejected() {
    let mut envelope = envelope();
    envelope.receiver_address = envelope.sender_address.clone();
    assert!(matches!(envelope.validate(), Err(DomError::Invalid(_))));
}

#[test]
fn slate_v3_deterministic_vectors_repeat_50_times() {
    let envelope = envelope();
    let bytes = envelope.to_canonical_bytes().expect("encode");
    let sender_digest = envelope
        .signature_digest(SLATE_ROLE_SENDER)
        .expect("sender digest");
    for _ in 0..50 {
        let decoded = SlateEnvelope::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded.to_canonical_bytes().expect("encode"), bytes);
        assert_eq!(
            decoded
                .signature_digest(SLATE_ROLE_SENDER)
                .expect("sender digest"),
            sender_digest
        );
    }
}
