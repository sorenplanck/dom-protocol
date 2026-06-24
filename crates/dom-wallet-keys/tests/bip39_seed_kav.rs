//! BIP-39 mnemonic -> seed known-answer vectors (shield detector).
//!
//! Validates `Bip39Seed::from_phrase(...).seed_bytes()` against EXTERNAL
//! ground truth — the BIP-39 spec algorithm PBKDF2-HMAC-SHA512(mnemonic,
//! "mnemonic"+passphrase, 2048, dklen=64), NOT this crate's own output.
//!
//! ## Provenance of the expected seeds
//!
//! DOM derives seeds with an EMPTY passphrase (`mnemonic.to_seed("")`), see
//! `seed.rs::from_phrase`. The canonical Trezor `vectors.json` test set uses
//! the passphrase "TREZOR", so its seeds are NOT directly reusable here.
//!
//! The expected empty-passphrase seeds below were computed with an independent
//! reference implementation of the BIP-39 KDF (Python `hashlib.pbkdf2_hmac`,
//! stdlib — a different codebase from DOM). That reference was cross-checked
//! to reproduce, byte-for-byte, two published Trezor "TREZOR"-passphrase
//! vectors (the "legal winner..." 12-word and the "letter advice..." 24-word
//! seeds), which proves the reference is spec-correct. The empty-passphrase
//! seed for the "abandon...about" mnemonic (`5eb00bbd...`) is itself a widely
//! published canonical BIP-39 value.
//!
//! These must PASS: they prove DOM's BIP-39 seed bytes are bit-identical to a
//! standard BIP-39 wallet (full interop / recoverability).

use dom_wallet_keys::{Bip39Seed, SeedAcceptance};

fn hex64(s: &str) -> [u8; 64] {
    assert_eq!(s.len(), 128, "expected 64-byte hex");
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex");
    }
    out
}

/// Assert that `phrase` parsed under `acc` yields exactly `exp_seed_hex`.
fn assert_seed(phrase: &str, acc: SeedAcceptance, exp_seed_hex: &str) {
    let seed = Bip39Seed::from_phrase(phrase, acc).expect("from_phrase");
    assert_eq!(
        seed.seed_bytes(),
        &hex64(exp_seed_hex),
        "BIP-39 seed bytes must match the spec KDF (empty passphrase) for: {phrase:?}"
    );
}

// 12-word, entropy 0x000...0 -> the canonical "abandon...about" mnemonic.
const M12_ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// 12-word, entropy 0x7f7f...7f -> "legal winner thank year wave sausage worth
// useful legal winner thank yellow" (Trezor vectors.json entry).
const M12_LEGAL: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

// 24-word, entropy 0x8080...80 -> "letter advice cage absurd amount doctor
// acoustic avoid (x2) ... acoustic bless" (Trezor vectors.json entry).
const M24_LETTER: &str = "letter advice cage absurd amount doctor acoustic avoid letter advice \
                          cage absurd amount doctor acoustic avoid letter advice cage absurd \
                          amount doctor acoustic bless";

/// 12-word KAV (legacy-restore path). Empty-passphrase canonical seed.
#[test]
fn bip39_seed_abandon12_empty_passphrase() {
    assert_seed(
        M12_ABANDON,
        SeedAcceptance::LegacyRestore,
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
         9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
    );
}

/// 12-word KAV, second independent entropy.
#[test]
fn bip39_seed_legal12_empty_passphrase() {
    assert_seed(
        M12_LEGAL,
        SeedAcceptance::LegacyRestore,
        "878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe\
         5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096",
    );
}

/// 24-word KAV (new-wallet path). Empty-passphrase seed.
#[test]
fn bip39_seed_letter24_empty_passphrase() {
    assert_seed(
        M24_LETTER,
        SeedAcceptance::NewWallet,
        "848bbe19cad445e46f35fd3d1a89463583ac2b60b5eb4cfcf955731775a5d9e1\
         7a81a71613fed83f1ae27b408478fdec2bbc75b5161d1937aa7cdf4ad686ef5f",
    );
}
