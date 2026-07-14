mod common;

use common::{make_input, TEST_CHAIN_ID};
use dom_crypto::recovery::{
    derive_recovery_root, recover_output_from_capsule, PublicOutputKind, RecoveryCapsule,
    RecoveryChainContext,
};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_slate::{
    build_send_recoverable, finalize, respond_receive_recoverable, RecoveryBuildContext,
};
use dom_tx::slate::{Slate, RECOVERY_SLATE_VERSION};

const SENDER_SEED: [u8; 64] = [0x41; 64];
const RECEIVER_SEED: [u8; 64] = [0x42; 64];

fn chain() -> RecoveryChainContext {
    RecoveryChainContext {
        network_magic: 0x4452_4547,
        chain_id: TEST_CHAIN_ID,
    }
}

#[test]
fn recovery_slate_roundtrip_finalizes_and_recovers_both_outputs() {
    let sender_root = derive_recovery_root(&SENDER_SEED, chain()).unwrap();
    let receiver_root = derive_recovery_root(&RECEIVER_SEED, chain()).unwrap();
    let input = make_input(1_600, 0x11);
    let sender = build_send_recoverable(
        &[input],
        500,
        1_000,
        100,
        TEST_CHAIN_ID,
        RecoveryBuildContext {
            root: &sender_root,
            chain: chain(),
            account: 0,
            derivation_index: 7,
        },
    )
    .unwrap();
    assert_eq!(sender.slate.version, RECOVERY_SLATE_VERSION);
    let encoded = sender.slate.to_bytes().unwrap();
    let decoded = Slate::from_bytes(&encoded).unwrap();
    assert_eq!(decoded, sender.slate);

    let response = respond_receive_recoverable(
        decoded,
        &TEST_CHAIN_ID,
        RecoveryBuildContext {
            root: &receiver_root,
            chain: chain(),
            account: 3,
            derivation_index: 9,
        },
    )
    .unwrap();
    let tx = finalize(
        &response.slate,
        &sender.excess_blinding,
        &sender.nonce,
        &TEST_CHAIN_ID,
    )
    .unwrap();
    assert_eq!(tx.outputs.len(), 2);

    let change_capsule = tx.outputs[0].recovery_capsule().unwrap().unwrap();
    let change = recover_output_from_capsule(
        &sender_root,
        chain(),
        tx.outputs[0].commitment.as_bytes(),
        1,
        PublicOutputKind::Regular,
        &change_capsule,
    )
    .unwrap()
    .unwrap();
    assert_eq!(change.value, 500);
    assert_eq!(change.derivation_index, 7);

    let recipient_capsule = tx.outputs[1].recovery_capsule().unwrap().unwrap();
    let recipient = recover_output_from_capsule(
        &receiver_root,
        chain(),
        tx.outputs[1].commitment.as_bytes(),
        1,
        PublicOutputKind::Regular,
        &recipient_capsule,
    )
    .unwrap()
    .unwrap();
    assert_eq!(recipient.value, 1_000);
    assert_eq!(recipient.derivation_index, 9);
}

#[test]
fn capsule_mutation_is_rejected_by_final_proof_validation() {
    let sender_root = derive_recovery_root(&SENDER_SEED, chain()).unwrap();
    let receiver_root = derive_recovery_root(&RECEIVER_SEED, chain()).unwrap();
    let sender = build_send_recoverable(
        &[make_input(1_600, 0x11)],
        500,
        1_000,
        100,
        TEST_CHAIN_ID,
        RecoveryBuildContext {
            root: &sender_root,
            chain: chain(),
            account: 0,
            derivation_index: 1,
        },
    )
    .unwrap();
    let mut response = respond_receive_recoverable(
        sender.slate.clone(),
        &TEST_CHAIN_ID,
        RecoveryBuildContext {
            root: &receiver_root,
            chain: chain(),
            account: 0,
            derivation_index: 2,
        },
    )
    .unwrap();
    response.slate.recipient_recovery_capsule[40] ^= 1;
    assert!(RecoveryCapsule::from_bytes(&response.slate.recipient_recovery_capsule).is_ok());
    assert!(finalize(
        &response.slate,
        &sender.excess_blinding,
        &sender.nonce,
        &TEST_CHAIN_ID,
    )
    .is_err());
}
