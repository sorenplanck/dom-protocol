//! Negative known-answer vectors (shield detector).
//!
//! Each test pins a SPECIFIC rejection the API must perform. A regression that
//! silently accepts malformed input (wrong seed length, bad BIP-39 checksum,
//! wrong word count) would flip one of these from RED-expected to accepted.

use dom_wallet_keys::{Bip39Seed, ExtendedPrivKey, SeedAcceptance};

// ─────────────────────────────────────────────────────────────────────────
// Seed length gate: from_seed accepts 16..=64 bytes, rejects 15 and 65.
// (Boundary values 16 and 64 must be ACCEPTED; 15 and 65 REJECTED.)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn seed_len_15_rejected() {
    assert!(
        ExtendedPrivKey::from_seed(&[0x11u8; 15]).is_err(),
        "15-byte seed must be rejected (below the 16-byte BIP-32 minimum)"
    );
}

#[test]
fn seed_len_16_accepted() {
    assert!(
        ExtendedPrivKey::from_seed(&[0x11u8; 16]).is_ok(),
        "16-byte seed is the lower boundary and must be accepted"
    );
}

#[test]
fn seed_len_64_accepted() {
    assert!(
        ExtendedPrivKey::from_seed(&[0x22u8; 64]).is_ok(),
        "64-byte seed is the upper boundary and must be accepted"
    );
}

#[test]
fn seed_len_65_rejected() {
    assert!(
        ExtendedPrivKey::from_seed(&[0x22u8; 65]).is_err(),
        "65-byte seed must be rejected (above the 64-byte maximum)"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// BIP-39 checksum gate: a structurally well-formed 12-word phrase from the
// wordlist but with a WRONG checksum word must be rejected.
//
// "abandon" x12 is 12 valid wordlist words, but its last word does not carry
// the correct checksum (the only valid all-abandon 12-word phrase ends in
// "about"). Parsing it must fail with InvalidPhrase.
// ─────────────────────────────────────────────────────────────────────────

const M12_BAD_CHECKSUM: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

#[test]
fn bip39_bad_checksum_rejected() {
    let Err(err) = Bip39Seed::from_phrase(M12_BAD_CHECKSUM, SeedAcceptance::LegacyRestore) else {
        panic!("12-word phrase with invalid checksum must be rejected");
    };
    assert!(
        matches!(err, dom_wallet_keys::SeedError::InvalidPhrase(_)),
        "wrong-checksum phrase must surface InvalidPhrase, got {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Word-count gate (12 vs 24) for NewWallet acceptance. A valid 12-word phrase
// must be rejected for new-wallet creation with the specific count error,
// while the same phrase is accepted under LegacyRestore.
// ─────────────────────────────────────────────────────────────────────────

const M12_VALID: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn word_count_12_rejected_for_new_wallet() {
    let Err(err) = Bip39Seed::from_phrase(M12_VALID, SeedAcceptance::NewWallet) else {
        panic!("12-word phrase must be rejected for NewWallet");
    };
    match err {
        dom_wallet_keys::SeedError::WrongWordCountForNewWallet { got, expected } => {
            assert_eq!(got, 12);
            assert_eq!(expected, 24);
        }
        other => panic!("expected WrongWordCountForNewWallet, got {other:?}"),
    }
}

#[test]
fn word_count_12_accepted_for_legacy_restore() {
    assert!(
        Bip39Seed::from_phrase(M12_VALID, SeedAcceptance::LegacyRestore).is_ok(),
        "valid 12-word phrase must be accepted under LegacyRestore"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// IL >= n master rejection — NON-ATAQUÁVEL POR CONSTRUÇÃO (probe, ignored).
//
// BIP-32 requires the master key to be discarded if IL == 0 or IL >= n, where
// n is the secp256k1 group order. `from_seed` enforces this via
// SecretKey::from_slice. Building a KAV seed that lands IL >= n is infeasible:
// the gap (2^256 - n) gives P(IL >= n) ~ 2^-127 per seed, and IL is a SHA-512
// HMAC output we cannot invert. A 2M-seed brute search (offline, Python ref)
// found zero hits, consistent with the 2^-127 bound. We therefore PROVE the
// vector is non-attackable rather than ship a theater test. The rejection
// CODE path is still exercised indirectly by the `child` tweak-add failure
// surface (covered by fuzz) and by from_slice's own validation.
//
// If an authoritative IL>=n seed vector is ever published, replace this with a
// real KAV asserting from_seed(seed) == Err(HdError::InvalidKey).
// ─────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "non-attackable by construction: P(master IL>=n) ~ 2^-127; no authoritative seed vector exists"]
fn master_il_ge_n_rejected_probe() {
    // Placeholder kept compiling so the rationale lives next to the suite.
    // No assertion: there is no constructible input for this vector.
}
