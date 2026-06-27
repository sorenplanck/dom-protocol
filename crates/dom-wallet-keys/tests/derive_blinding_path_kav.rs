//! KAV: `ExtendedPrivKey::derive_blinding` must follow its DOCUMENTED path.
//!
//! `hd_wallet.rs` documents (line ~180):
//!     /// Path: m/44'/330'/account'/change/index
//! i.e. purpose=44' (hardened), coin_type=330' (hardened), account' (hardened),
//! then NON-hardened `change` and NON-hardened `index`.
//!
//! ── EXPECTED RED (FIX-001) ──────────────────────────────────────────────
//! The implementation builds the path with this format string:
//!     format!("m/44'/{}'/{}'/{}'/{}/{}", 44u32, DOM_COIN_TYPE, account, change, index)
//! which expands to:  m/44'/44'/330'/account'/change/index
//! — a DUPLICATED 44' level (purpose written twice), pushing coin_type/account
//! down one level and adding a hardened level the doc does not describe.
//!
//! Measured drift (seed = [0x5e;64], account=3, change=0, index=7):
//!   documented m/44'/330'/3'/0/7  -> 5f31996680972ce928d8183e364f10889cdf0fcc4ca4f6b8ff004be1857876e5
//!   derive_blinding(3,0,7)        -> 2cfc1e17e3ee52d1df1c87afbff3e514b10a8dc5e4da5f92651d627e17822ec8
//!   (derive_blinding == m/44'/44'/330'/3'/0/7, the buggy literal path)
//!
//! This KAV asserts the CORRECT (documented) behaviour, so it will FAIL until
//! the format string is fixed to "m/44'/{}'/{}'/{}/{}" with
//! (DOM_COIN_TYPE, account, change, index). Fixing is a SEPARATE task and
//! requires human decision (it changes a key-derivation path — any output
//! already derived via `derive_blinding` would move). The shield only reports.
//!
//! NOTE: the wallet's production blinding helpers (`seed::coinbase_blinding`,
//! `seed::spend_output_blinding`) do NOT call `derive_blinding`; they build
//! their own paths. So the blast radius of FIX-001 is limited to any consumer
//! that calls `ExtendedPrivKey::derive_blinding` directly. (Audit those before
//! fixing.)

use dom_wallet_keys::ExtendedPrivKey;

#[test]
fn derive_blinding_matches_documented_path() {
    let seed = [0x5eu8; 64];
    let m = ExtendedPrivKey::from_seed(&seed).expect("from_seed");

    let account = 3u32;
    let change = 0u32;
    let index = 7u32;

    // Documented path: m/44'/330'/account'/change/index
    let documented = m
        .derive_path(&format!("m/44'/330'/{account}'/{change}/{index}"))
        .expect("derive_path documented");

    let actual = m
        .derive_blinding(account, change, index)
        .expect("derive_blinding");

    assert_eq!(
        actual.as_ref(),
        documented.key_bytes(),
        "derive_blinding must follow documented m/44'/330'/account'/change/index \
         (FIX-001: code emits the buggy m/44'/44'/330'/account'/change/index)"
    );
}
