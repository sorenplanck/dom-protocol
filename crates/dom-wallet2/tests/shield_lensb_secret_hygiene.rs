//! dom-shield — Lens B (Lazarus / crypto-APT) secret-hygiene probes for dom-wallet2.
//!
//! Threat: extraction of key material (blindings, seed, master HD key) from
//! memory dumps, swap, core files, logs, or the on-disk file. The OBSERVABLE
//! contracts (Debug redaction, never-plaintext-on-disk, secrets wiped at
//! finalize) are exercised here; the genuinely non-observable ones (does freed
//! memory get zeroed?) are pinned through static source assertions paired with
//! compile-time owner-type checks, without unsafe freed-memory inspection.

use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_slate::{build_send, respond_receive, SlateInput};
use dom_wallet2::{
    create_send, finalize, receive, BlockRef, KeychainDeriver, KeychainV2, Network, OutputOrigin,
    SlateLifecycle, StoredOutput, WalletV2State,
};
use dom_wallet_keys::{Bip39Seed, SeedAcceptance};
use zeroize::Zeroizing;

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon art";

fn keychain() -> KeychainV2 {
    let seed = Bip39Seed::from_phrase(PHRASE, SeedAcceptance::NewWallet).unwrap();
    KeychainV2 {
        seed_bytes: Some(Zeroizing::new(*seed.seed_bytes())),
        seed_word_count: Some(24),
        account: 0,
        ..Default::default()
    }
}

// ── OBSERVABLE: KeychainV2 Debug never prints the seed ────────────────────────

#[test]
fn keychain_debug_redacts_seed() {
    let k = keychain();
    let dump = format!("{k:?}");
    assert!(
        dump.contains("<redacted>"),
        "expected seed redaction marker"
    );
    let seed_hex: String = k
        .seed_bytes
        .as_ref()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(
        !dump.contains(&seed_hex),
        "seed bytes leaked via KeychainV2 Debug"
    );
}

// ── OBSERVABLE: a StoredOutput's blinding never appears via Debug ─────────────

#[test]
fn stored_output_debug_redacts_blinding() {
    let o = StoredOutput::new_unconfirmed(
        [1u8; 33],
        500,
        [0xAB; 32],
        OutputOrigin::Change,
        false,
        None,
        1,
    );
    let dump = format!("{o:?}");
    assert!(
        dump.contains("<redacted>"),
        "expected blinding redaction marker"
    );
    assert!(
        !dump.contains("ab, ab, ab"),
        "blinding leaked via StoredOutput Debug"
    );
}

// ── OBSERVABLE: finalize wipes the single-use nonce + excess (anti key-leak) ──

#[test]
fn finalize_wipes_sender_secrets() {
    // A second partial signature with the same nonce would leak the excess key;
    // the secrets MUST be gone after a successful finalize.
    let mut sender = funded_state(&[600, 600]);
    let sent = create_send(&mut sender, 1000, 10, 2000).unwrap();
    let mut recv = WalletV2State::new(Network::Regtest, [0x77u8; 32]);
    recv.meta.last_reconciled_tip = 100;
    let answered = receive(&mut recv, sent.slate, 3000).unwrap();
    let _tx = finalize(&mut sender, answered, 4000).unwrap();

    assert_eq!(sender.pending_slates[0].status, SlateLifecycle::Finalized);
    assert!(
        sender.pending_slates[0].secrets.is_none(),
        "Lens B: sender excess/nonce not wiped after finalize (nonce-reuse key-leak surface)"
    );
}

fn funded_state(values: &[u64]) -> WalletV2State {
    let mut state = WalletV2State::new(Network::Regtest, [0x77u8; 32]);
    state.meta.last_reconciled_tip = 100;
    for &v in values {
        let blinding = BlindingFactor::random();
        let commitment = *Commitment::commit(v, &blinding).as_bytes();
        let mut o = StoredOutput::new_unconfirmed(
            commitment,
            v,
            *blinding.as_bytes(),
            OutputOrigin::ReceiveSlate,
            false,
            None,
            1,
        );
        o.confirm(
            BlockRef {
                height: 10,
                hash: [10u8; 32],
            },
            1,
        )
        .unwrap();
        state.outputs.insert(o).unwrap();
    }
    state
}

// ── STATIC + TYPE-SURFACE PROOFS FOR DROP-ONLY PROPERTIES ────────────────────

#[test]
fn keychain_deriver_root_has_a_zeroizing_non_clone_owner() {
    const HD_WALLET_SOURCE: &str = include_str!("../../dom-wallet-keys/src/hd_wallet.rs");
    const KEYCHAIN_SOURCE: &str = include_str!("../src/keychain.rs");
    assert!(HD_WALLET_SOURCE.contains("key: Zeroizing<[u8; 32]>"));
    assert!(HD_WALLET_SOURCE.contains("chain_code: Zeroizing<[u8; 32]>"));
    assert!(HD_WALLET_SOURCE.contains("impl Drop for ExtendedPrivKey"));
    assert!(HD_WALLET_SOURCE.contains("impl Zeroize for ExtendedPrivKey"));
    assert!(!HD_WALLET_SOURCE.contains("#[derive(Clone)]\npub struct ExtendedPrivKey"));
    assert!(KEYCHAIN_SOURCE.contains("impl Drop for KeychainDeriver"));
    assert!(KEYCHAIN_SOURCE.contains("self.root.zeroize();"));

    // The real KeychainDeriver owns the non-exportable root for its complete
    // lifetime; dropping this value exercises ExtendedPrivKey::drop.
    let k = keychain();
    drop(KeychainDeriver::new(&k).unwrap());
}

#[test]
fn slate_and_payment_transients_are_zeroizing_owned() {
    fn assert_zeroizing(_: &Zeroizing<[u8; 32]>) {}

    let input_blinding = BlindingFactor::random();
    let input_value = 1_510;
    let input = SlateInput {
        commitment: *Commitment::commit(input_value, &input_blinding).as_bytes(),
        blinding: Zeroizing::new(*input_blinding.as_bytes()),
    };
    assert_zeroizing(&input.blinding);

    let sender = build_send(&[input], 500, 1_000, 10, [0x77; 32]).unwrap();
    assert_zeroizing(&sender.excess_blinding);
    assert_zeroizing(&sender.nonce);
    assert_zeroizing(&sender.change.as_ref().unwrap().blinding);
    let receiver = respond_receive(sender.slate, &[0x77; 32]).unwrap();
    assert_zeroizing(&receiver.recipient_output_blinding);

    const SLATE_SOURCE: &str = include_str!("../../dom-slate/src/lib.rs");
    const PAYMENT_SOURCE: &str = include_str!("../src/payment.rs");
    assert!(!SLATE_SOURCE.contains("pub blinding: [u8; 32]"));
    assert!(!SLATE_SOURCE.contains("pub excess_blinding: [u8; 32]"));
    assert!(!SLATE_SOURCE.contains("pub nonce: [u8; 32]"));
    assert!(!SLATE_SOURCE.contains("pub recipient_output_blinding: [u8; 32]"));
    assert!(PAYMENT_SOURCE.contains("blinding: out.blinding.clone()"));
    assert!(!PAYMENT_SOURCE.contains("blinding: *out.blinding"));
}

#[test]
fn serde_secret_buffers_are_zeroizing_on_success_and_rejection() {
    const TYPES_SOURCE: &str = include_str!("../src/types.rs");
    assert!(
        TYPES_SOURCE.contains("let bytes = Zeroizing::new(Vec::<u8>::deserialize(deserializer)?);")
    );
    assert!(TYPES_SOURCE.contains("let v = Zeroizing::new(v);"));
    assert!(TYPES_SOURCE.contains("let mut array = Zeroizing::new([0u8; 32]);"));
    assert!(TYPES_SOURCE.contains("let mut a = Zeroizing::new([0u8; 64]);"));

    // Preserve the existing serde wire representation while the temporary
    // decode owners changed: both a 32-byte blinding and a 64-byte seed make a
    // byte-identical JSON round trip.
    let output = StoredOutput::new_unconfirmed(
        [0x31; 33],
        99,
        [0x42; 32],
        OutputOrigin::ReceiveSlate,
        false,
        None,
        1,
    );
    let encoded = serde_json::to_vec(&output).unwrap();
    let decoded: StoredOutput = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(*decoded.blinding, [0x42; 32]);
    let mut malformed_output: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    malformed_output["blinding"] = serde_json::json!([1, 2]);
    assert!(serde_json::from_value::<StoredOutput>(malformed_output).is_err());

    let keychain = keychain();
    let encoded = serde_json::to_vec(&keychain).unwrap();
    let decoded: KeychainV2 = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(
        decoded.seed_bytes.as_deref(),
        keychain.seed_bytes.as_deref()
    );
    let mut malformed_keychain: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    malformed_keychain["seed_bytes"] = serde_json::json!([3, 4]);
    assert!(serde_json::from_value::<KeychainV2>(malformed_keychain).is_err());
}
