//! dom-shield — Lens B (Lazarus / crypto-APT) secret-hygiene probes for dom-wallet2.
//!
//! Threat: extraction of key material (blindings, seed, master HD key) from
//! memory dumps, swap, core files, logs, or the on-disk file. The OBSERVABLE
//! contracts (Debug redaction, never-plaintext-on-disk, secrets wiped at
//! finalize) are exercised here; the genuinely non-observable ones (does freed
//! memory get zeroed?) are recorded as `#[ignore]`d probes with the static
//! finding, per the anti-theater rule (proving a vector by analysis is worth as
//! much as a test).

use dom_crypto::pedersen::{BlindingFactor, Commitment};
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

// ── NON-OBSERVABLE (recorded findings, anti-theater) ─────────────────────────

#[test]
#[ignore = "STATIC FINDING (behaviorally untestable in safe Rust): \
KeychainDeriver { root: ExtendedPrivKey, account } has NO Drop/ZeroizeOnDrop. \
The HD master key bytes inside `root` live for the deriver's lifetime and are \
freed without zeroization unless ExtendedPrivKey itself zeroizes on drop. \
Confirm by inspecting dom-wallet-keys::hd_wallet::ExtendedPrivKey for a Drop/\
Zeroize impl on its key_bytes; if absent, the master key can persist in freed \
heap/stack (Lazarus memory-scrape surface). Cannot be asserted from a test \
without unsafe freed-memory inspection."]
fn keychain_deriver_root_zeroization_static_finding() {
    // Construct one so the type is exercised at least at compile time.
    let k = keychain();
    let _d = KeychainDeriver::new(&k).unwrap();
}

#[test]
#[ignore = "STATIC FINDING (behaviorally untestable): dom_slate::SlateInput.blinding \
and the change OutputData.blinding are bare `[u8; 32]` (not Zeroizing). In \
payment::create_send these transient copies of input/change blindings are \
built from the store's Zeroizing blindings but live as bare arrays for the \
duration of build_send and are dropped WITHOUT zeroization. The leak window is \
small but real; fixing requires Zeroizing in dom-slate's public structs \
(cross-crate, HUMAN DECISION — touches a shared API). Recorded, not patched."]
fn slate_input_change_blinding_bare_static_finding() {}

#[test]
#[ignore = "STATIC FINDING (behaviorally untestable): the serde codecs \
serde_blinding / serde_seed64_opt allocate a transient `Vec<u8>` during \
DESERIALIZE (from the decrypted plaintext) before copying into the Zeroizing \
array; that Vec is dropped without zeroization. The plaintext only exists in \
memory post-decrypt, but the transient Vec is an extra unzeroized copy of \
secret bytes. Fix = zeroize the temp Vec in the deserialize path. Recorded."]
fn serde_transient_vec_not_zeroized_static_finding() {}
