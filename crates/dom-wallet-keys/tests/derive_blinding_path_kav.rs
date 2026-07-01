//! KAV: `ExtendedPrivKey::derive_blinding` must follow its DOCUMENTED path.
//!
//! `hd_wallet.rs` documents (line ~180):
//!     /// Path: m/44'/330'/account'/change/index
//! i.e. purpose=44' (hardened), coin_type=330' (hardened), account' (hardened),
//! then NON-hardened `change` and NON-hardened `index`.
//!
//! ── RESOLVED (FIX-001) — fixed in 8c1c053 ───────────────────────────────
//! `derive_blinding` originally used the format string
//!     format!("m/44'/{}'/{}'/{}'/{}/{}", 44u32, DOM_COIN_TYPE, account, change, index)
//! which expanded to m/44'/44'/330'/account'/change/index — a DUPLICATED 44'
//! level (purpose written twice) that pushed coin_type/account down one level and
//! added an undocumented hardened level. Commit 8c1c053 corrected it to
//!     format!("m/44'/{}'/{}'/{}/{}", DOM_COIN_TYPE, account, change, index)
//! i.e. the documented m/44'/330'/account'/change/index (hd_wallet.rs:188).
//!
//! This KAV asserts the documented path and is now GREEN; it guards against a
//! regression back to the duplicated-44' form.
//!
//! NOTE: the wallet's production blinding helpers (`seed::coinbase_blinding`,
//! `seed::spend_output_blinding`) build their own paths and never called the
//! buggy one — the original blast radius was limited to direct callers of
//! `ExtendedPrivKey::derive_blinding`.

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
         (FIX-001 regression guard: must NOT revert to m/44'/44'/330'/account'/change/index)"
    );
}
