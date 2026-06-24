//! dom-shield Onda 2 — FIX-024 reproducer for `dom_wallet::journal`.
//!
//! Subfamily: directed (Lens B funds-safety, secret-on-disk).
//!
//! When the wallet builds a spend that produces change, `reserve_built_spend`
//! appends a `Built` journal event carrying `change: Some(PendingChange{..})`.
//! `PendingChange` includes the **change output blinding factor** — the spend
//! secret for that change UTXO. The journal is a PLAINTEXT JSON file
//! (`journal.log`). `PendingChange` serializes the blinding via
//! `store::serde_blinding32`, whose `serialize_bytes` renders — in JSON — as a
//! DECIMAL BYTE ARRAY (`"blinding":[196,196,...]`), NOT a hex string. The
//! detector below matches that exact on-disk form (verified against a live
//! journal dump).
//!
//! SAFETY EXPECTATION (what a hardened wallet would guarantee): a spend secret
//! (output blinding) must NEVER appear in plaintext on disk. The encrypted
//! `wallet.dat` is the only place secrets belong.
//!
//! This test ENCODES that safety expectation: it greps the on-disk journal
//! bytes for the change blinding and asserts it is ABSENT. Because the
//! production code writes it in cleartext, the assertion FAILS → the RED is
//! the CONFIRMATION of FIX-024.
//!
//! NOTE: an existing integration test
//! (`change_output::journal_built_change_recovers_spendable_change_after_crash_before_save`)
//! treats the journalled blinding as a *crash-recovery feature*. This test is
//! the opposing security lens on the same fact: that recovery convenience puts
//! a live spend secret in plaintext. Confirm-or-dissolve is by execution; this
//! is expected to land RED.

use dom_wallet::wallet_dir::{WalletDir, WALLET_DAT_NAME};
use dom_wallet::{JournalEntry, Network, TxJournal, TxJournalEvent};
use dom_core::Hash256;
use dom_crypto::pedersen::Commitment;
use dom_crypto::BlindingFactor;
use dom_wallet::OwnedOutput;
use tempfile::TempDir;

fn genesis() -> Hash256 {
    Hash256::from_bytes([24u8; 32])
}

fn make_output(value: u64, height: u64, blinding_byte: u8) -> OwnedOutput {
    let blinding = BlindingFactor::from_bytes([blinding_byte; 32]).unwrap();
    let commitment = Commitment::commit(value, &blinding);
    OwnedOutput::new(*commitment.as_bytes(), value, *blinding.as_bytes(), height, false)
}

fn fresh_recipient(amount: u64) -> (Commitment, BlindingFactor) {
    let blinding = BlindingFactor::from_bytes([0x5Au8; 32]).unwrap();
    (Commitment::commit(amount, &blinding), blinding)
}

/// Build a spend with change, then read the plaintext journal and assert the
/// change blinding bytes are ABSENT (safety expectation). EXPECTED RED =
/// confirms FIX-024 (the blinding is present in cleartext).
#[test]
fn fix024_change_blinding_must_be_absent_from_plaintext_journal() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &genesis()).unwrap();

    // Fund the wallet so the spend overshoots and produces change.
    wd.wallet_mut().add_output(make_output(1_000, 100, 0x11));
    wd.wallet().save().unwrap();

    let amount = 500u64;
    let fee = 100u64;
    let (rc, rb) = fresh_recipient(amount);
    wd.wallet_mut()
        .build_spend(rc, rb, amount, fee, 1000)
        .expect("build spend with change");

    // Recover the change blinding the wallet actually persisted by replaying
    // the journal record's structured `change` field.
    let journal_path = wd.wallet().journal().unwrap().path().to_path_buf();
    let records = wd.wallet().journal().unwrap().replay().unwrap();
    let change = records
        .values()
        .find_map(|r| r.change.clone())
        .expect("Built event must carry PendingChange with the change blinding");
    let blinding_bytes = change.blinding; // [u8; 32] — the spend secret.

    // Read the RAW on-disk journal bytes.
    let raw = std::fs::read(&journal_path).unwrap();

    // Sanity: the journal should NOT be the encrypted wallet file.
    assert_ne!(
        journal_path.file_name().unwrap(),
        std::ffi::OsStr::new(WALLET_DAT_NAME),
        "journal must be the plaintext log, not wallet.dat"
    );

    let blinding_present =
        // Primary: the actual on-disk JSON form — a decimal byte array.
        twoway_contains(&raw, blinding_json_array(&blinding_bytes).as_bytes())
        // Defensive fallbacks: raw bytes / hex, in case the serializer changes.
        || raw.windows(32).any(|w| w == blinding_bytes)
        || twoway_contains(&raw, hex::encode(blinding_bytes).as_bytes());

    // SAFETY EXPECTATION: a spend secret must never be on disk in cleartext.
    // This SHOULD pass for a hardened wallet. It is EXPECTED to FAIL here,
    // and the failure is the FIX-024 confirmation.
    assert!(
        !blinding_present,
        "FIX-024 CONFIRMED: change output blinding (spend secret) found in plaintext journal at {}",
        journal_path.display()
    );
}

/// Lower-level confirmation that does not depend on the wallet build path:
/// directly append a `Built{change}` entry (as the production code does) and
/// confirm the blinding lands verbatim (as a JSON decimal byte array) in the
/// plaintext file. Isolates the journal serializer as the leak surface.
/// EXPECTED RED.
#[test]
fn fix024_built_event_serializes_blinding_into_cleartext() {
    use dom_wallet::store::PendingChange;
    let temp = TempDir::new().unwrap();
    let j = TxJournal::open(temp.path()).unwrap();

    let secret_blinding = [0xC4u8; 32];
    let change = PendingChange {
        commitment: [0x02u8; 33],
        value: 400,
        blinding: secret_blinding,
    };
    j.append(&JournalEntry {
        timestamp: 1,
        tx_hash: [0xAA; 32],
        event: TxJournalEvent::Built {
            inputs: vec![[0x01u8; 33]],
            tx_hex: None,
            output_count: 2,
            fee_noms: 100,
            change: Some(change),
        },
    })
    .unwrap();

    let raw = std::fs::read(j.path()).unwrap();
    let json_array = blinding_json_array(&secret_blinding);
    let present = twoway_contains(&raw, json_array.as_bytes());

    // SAFETY EXPECTATION: absent. EXPECTED RED → confirms FIX-024.
    assert!(
        !present,
        "FIX-024 CONFIRMED: Built event wrote change blinding '{json_array}' to plaintext journal"
    );
}

/// Render 32 bytes exactly as serde_json's `serialize_bytes` does in a JSON
/// value: a comma-separated decimal array `[b0,b1,...,b31]` (no spaces).
fn blinding_json_array(b: &[u8; 32]) -> String {
    let inner = b.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",");
    format!("[{inner}]")
}

fn twoway_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
