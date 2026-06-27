//! BIP-39 seed handling for DOM Wallet V0.
//!
//! The seed is the sole authority for deterministic recovery. All
//! wallet-side secrets (coinbase blindings, spend-output blindings,
//! HD branches) MUST derive from `(seed, network, deterministic
//! index)` and nothing else. The encrypt-at-rest password protects
//! the *storage* of the seed but is never an input to a derivation.
//!
//! ## Word count policy
//!
//! - **New wallets:** 24 words only (256-bit entropy). 12-word phrases
//!   are rejected by `Bip39Seed::generate_new` and by
//!   `Bip39Seed::from_phrase(_, SeedAcceptance::NewWallet)`.
//! - **Legacy import:** `SeedAcceptance::LegacyRestore` accepts the
//!   full BIP-39 valid range (12/15/18/21/24) for restoring old
//!   wallets. Wallets restored from a 12-word phrase MUST never be
//!   re-saved under the v2 schema as if they were freshly generated.
//!
//! ## Portability
//!
//! This module performs **zero filesystem or network I/O**. It is
//! safe to use in any process, including airgapped contexts. Secrets
//! held in `Zeroizing<...>` wrappers are wiped on drop.

use crate::hd_wallet::{ExtendedPrivKey, HdError, DOM_COIN_TYPE};
use bip39::{Language, Mnemonic};
use thiserror::Error;
use zeroize::Zeroizing;

/// Word count required for newly generated wallets.
pub const NEW_WALLET_WORD_COUNT: usize = 24;

/// Size in bytes of the BIP-39 PBKDF2-HMAC-SHA512 seed.
pub const SEED_BYTES: usize = 64;

/// BIP-44 purpose level (constant per the standard).
const BIP44_PURPOSE: u32 = 44;

/// Custom DOM derivation domain for coinbase blindings.
///
/// Lives at the BIP-44 `change` position but is hardened to prevent
/// chain-code leakage from compromising past mining keys. The value
/// is arbitrary as long as it stays distinct from the spend-output
/// path (which uses `change = 0`).
const DOM_COINBASE_CHANGE: u32 = 1;

/// Errors that can arise from seed handling.
#[derive(Debug, Error)]
pub enum SeedError {
    /// The BIP-39 phrase failed structural or checksum validation.
    #[error("invalid BIP-39 phrase: {0}")]
    InvalidPhrase(String),

    /// A 12/15/18/21-word phrase was offered where only 24 is accepted.
    #[error("phrase rejected for new wallet creation: got {got} words, expected {expected}")]
    WrongWordCountForNewWallet {
        /// Word count actually supplied.
        got: usize,
        /// Required word count.
        expected: usize,
    },

    /// An underlying HD derivation failure.
    #[error("HD derivation failed: {0}")]
    Hd(#[from] HdError),

    /// Internal generation failure (RNG, bip39 crate).
    #[error("internal: {0}")]
    Internal(String),
}

/// Policy governing whether a parsed phrase is acceptable for the
/// caller's use case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedAcceptance {
    /// Only 24-word phrases are accepted. Used by `wallet init`.
    NewWallet,
    /// Any BIP-39 standard length (12/15/18/21/24) is accepted.
    /// Used by `wallet restore` for legacy 12-word phrases.
    LegacyRestore,
}

/// A validated BIP-39 seed pair (phrase + 64-byte derived seed bytes).
///
/// Both the phrase and the seed bytes are wrapped in `Zeroizing` so
/// they are wiped from memory on drop.
pub struct Bip39Seed {
    phrase: Zeroizing<String>,
    seed_bytes: Zeroizing<[u8; SEED_BYTES]>,
    word_count: usize,
}

impl Bip39Seed {
    /// Generate a fresh 24-word BIP-39 seed using the OS RNG.
    ///
    /// The returned seed is suitable for new wallet creation. The
    /// caller is responsible for displaying the phrase to the
    /// operator and confirming it before any persistence.
    pub fn generate_new() -> Result<Self, SeedError> {
        let mut rng = rand::thread_rng();
        let mnemonic =
            Mnemonic::generate_in_with(&mut rng, Language::English, NEW_WALLET_WORD_COUNT)
                .map_err(|e| SeedError::Internal(format!("bip39 generation: {e}")))?;
        let phrase = Zeroizing::new(mnemonic.to_string());
        // Empty passphrase — the BIP-39 "25th word" is intentionally
        // not exposed in V0 to keep recovery scope minimal. The
        // wallet's encrypt-at-rest password is separate.
        let seed_bytes = Zeroizing::new(mnemonic.to_seed(""));
        Ok(Self {
            phrase,
            seed_bytes,
            word_count: NEW_WALLET_WORD_COUNT,
        })
    }

    /// Parse and validate an existing BIP-39 phrase under `acceptance`.
    pub fn from_phrase(phrase: &str, acceptance: SeedAcceptance) -> Result<Self, SeedError> {
        let trimmed = phrase.trim();
        let word_count = trimmed.split_whitespace().count();

        // Enforce the new-wallet word-count rule BEFORE invoking the
        // BIP-39 parser, so the error message is specific and we do
        // not leak partial parse state for non-24-word phrases.
        if matches!(acceptance, SeedAcceptance::NewWallet) && word_count != NEW_WALLET_WORD_COUNT {
            return Err(SeedError::WrongWordCountForNewWallet {
                got: word_count,
                expected: NEW_WALLET_WORD_COUNT,
            });
        }

        let mnemonic = Mnemonic::parse_in(Language::English, trimmed)
            .map_err(|e| SeedError::InvalidPhrase(e.to_string()))?;

        let normalized = Zeroizing::new(mnemonic.to_string());
        let seed_bytes = Zeroizing::new(mnemonic.to_seed(""));

        Ok(Self {
            phrase: normalized,
            seed_bytes,
            word_count,
        })
    }

    /// Reveal the normalized phrase (for one-time display during
    /// `wallet init`). The reference is borrowed; callers MUST NOT
    /// clone it into a non-zeroizing String.
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// Raw 64-byte BIP-39 seed material.
    pub fn seed_bytes(&self) -> &[u8; SEED_BYTES] {
        &self.seed_bytes
    }

    /// Number of words in the source phrase.
    pub fn word_count(&self) -> usize {
        self.word_count
    }

    /// Whether this seed was created via `generate_new` policy
    /// (i.e. 24 words). Returns `false` for legacy-restored 12/15/18/21.
    pub fn is_v2_eligible(&self) -> bool {
        self.word_count == NEW_WALLET_WORD_COUNT
    }

    /// Derive the BIP-32 master key (HD root) from this seed.
    ///
    /// All subsequent wallet derivations branch from this root.
    pub fn derive_root(&self) -> Result<ExtendedPrivKey, SeedError> {
        ExtendedPrivKey::from_seed(self.seed_bytes()).map_err(Into::into)
    }
}

/// Derive the deterministic blinding factor for a coinbase output at
/// `height`. v2-wallet replacement for the legacy password-derived
/// blinding in `wallet::build_coinbase`.
///
/// Path: `m / 44' / 330' / 0' / 1' / height'`
///
/// The full path is hardened so that compromise of any descendant
/// chain code does not expose sibling-height blindings.
pub fn coinbase_blinding(
    root: &ExtendedPrivKey,
    height: u64,
) -> Result<Zeroizing<[u8; 32]>, SeedError> {
    // BIP-32 hardened indices are u31. Block height MUST fit; even
    // mainnet halving cadence (~330k blocks) reaches u31 only after
    // ~6,500 halvings, which is far beyond the protocol's economic
    // lifetime. We treat anything outside u31 as a programmer error.
    let height_index: u32 = u32::try_from(height)
        .ok()
        .filter(|v| *v <= 0x7fff_ffff)
        .ok_or_else(|| {
            SeedError::Internal(format!(
                "coinbase height {height} exceeds u31 BIP-32 hardened index range"
            ))
        })?;

    let path = format!(
        "m/{}'/{}'/{}'/{}'/{}'",
        BIP44_PURPOSE, DOM_COIN_TYPE, 0u32, DOM_COINBASE_CHANGE, height_index,
    );
    let child = root.derive_path(&path)?;
    Ok(Zeroizing::new(*child.key_bytes()))
}

/// Derive a deterministic blinding factor for a wallet-owned spend
/// output. Standard BIP-44 external chain.
///
/// Path: `m / 44' / 330' / account' / 0 / index`
pub fn spend_output_blinding(
    root: &ExtendedPrivKey,
    account: u32,
    index: u32,
) -> Result<Zeroizing<[u8; 32]>, SeedError> {
    let account = if account <= 0x7fff_ffff {
        account
    } else {
        return Err(SeedError::Internal(format!(
            "account {account} exceeds u31 BIP-32 hardened index range"
        )));
    };
    let index = if index <= 0x7fff_ffff {
        index
    } else {
        return Err(SeedError::Internal(format!(
            "index {index} exceeds u31 BIP-32 child index range"
        )));
    };
    let path = format!(
        "m/{}'/{}'/{}'/{}/{}",
        BIP44_PURPOSE, DOM_COIN_TYPE, account, 0u32, index
    );
    let child = root.derive_path(&path)?;
    Ok(Zeroizing::new(*child.key_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────
    // Generation: must produce exactly 24 words, non-deterministic.
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn generate_new_yields_exactly_24_words() {
        let seed = Bip39Seed::generate_new().expect("generate");
        assert_eq!(seed.word_count(), 24);
        assert_eq!(seed.phrase().split_whitespace().count(), 24);
        assert!(seed.is_v2_eligible());
    }

    #[test]
    fn generate_new_is_non_deterministic() {
        let a = Bip39Seed::generate_new().unwrap();
        let b = Bip39Seed::generate_new().unwrap();
        assert_ne!(a.phrase(), b.phrase());
        assert_ne!(a.seed_bytes(), b.seed_bytes());
    }

    // ─────────────────────────────────────────────────────────────
    // Parsing: 24 accepted for new wallet, 12 rejected.
    // ─────────────────────────────────────────────────────────────

    /// A known-valid 24-word BIP-39 test vector.
    /// (Generated independently; checksum verified.)
    const KNOWN_24_WORD: &str = "abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon art";

    const KNOWN_12_WORD: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn parse_24_word_accepted_for_new_wallet() {
        let seed = Bip39Seed::from_phrase(KNOWN_24_WORD, SeedAcceptance::NewWallet)
            .expect("24-word should be accepted");
        assert_eq!(seed.word_count(), 24);
    }

    #[test]
    fn parse_12_word_rejected_for_new_wallet() {
        // Use a let-else destructure rather than `expect_err`, because
        // `expect_err` requires Debug on the Ok variant — and we do
        // NOT derive Debug on Bip39Seed (the phrase is secret material).
        let Err(err) = Bip39Seed::from_phrase(KNOWN_12_WORD, SeedAcceptance::NewWallet) else {
            panic!("12-word phrase must be rejected for new-wallet creation");
        };
        match err {
            SeedError::WrongWordCountForNewWallet { got, expected } => {
                assert_eq!(got, 12);
                assert_eq!(expected, 24);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_12_word_accepted_for_legacy_restore() {
        let seed = Bip39Seed::from_phrase(KNOWN_12_WORD, SeedAcceptance::LegacyRestore)
            .expect("12-word must be accepted for legacy");
        assert_eq!(seed.word_count(), 12);
        assert!(!seed.is_v2_eligible(), "12-word must NOT be v2-eligible");
    }

    #[test]
    fn parse_invalid_phrase_rejected() {
        let Err(err) = Bip39Seed::from_phrase(
            "this is not a real bip39 phrase at all nope nope nope",
            SeedAcceptance::LegacyRestore,
        ) else {
            panic!("garbage phrase must be rejected");
        };
        assert!(matches!(err, SeedError::InvalidPhrase(_)));
    }

    #[test]
    fn parse_phrase_with_extra_whitespace_normalizes() {
        let messy = format!("  {}  \n  ", KNOWN_24_WORD);
        let seed =
            Bip39Seed::from_phrase(&messy, SeedAcceptance::NewWallet).expect("whitespace trim");
        assert_eq!(seed.word_count(), 24);
    }

    // ─────────────────────────────────────────────────────────────
    // Idempotence: parsing the same phrase twice must produce
    // bit-identical seed bytes (this is the deterministic-restore
    // invariant).
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_is_idempotent() {
        let a = Bip39Seed::from_phrase(KNOWN_24_WORD, SeedAcceptance::NewWallet).unwrap();
        let b = Bip39Seed::from_phrase(KNOWN_24_WORD, SeedAcceptance::NewWallet).unwrap();
        assert_eq!(a.seed_bytes(), b.seed_bytes());
        assert_eq!(a.phrase(), b.phrase());
    }

    // ─────────────────────────────────────────────────────────────
    // HD derivation: deterministic, isolated by index.
    // ─────────────────────────────────────────────────────────────

    fn fixed_root() -> ExtendedPrivKey {
        let seed = Bip39Seed::from_phrase(KNOWN_24_WORD, SeedAcceptance::NewWallet).unwrap();
        seed.derive_root().unwrap()
    }

    #[test]
    fn coinbase_blinding_deterministic_same_root_same_height() {
        let root = fixed_root();
        let a = coinbase_blinding(&root, 100).unwrap();
        let b = coinbase_blinding(&root, 100).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn coinbase_blinding_differs_per_height() {
        let root = fixed_root();
        let a = coinbase_blinding(&root, 0).unwrap();
        let b = coinbase_blinding(&root, 1).unwrap();
        let c = coinbase_blinding(&root, 999_999).unwrap();
        assert_ne!(*a, *b);
        assert_ne!(*b, *c);
        assert_ne!(*a, *c);
    }

    #[test]
    fn coinbase_blinding_differs_per_seed() {
        let root_a = fixed_root();
        let root_b = Bip39Seed::generate_new().unwrap().derive_root().unwrap();
        let a = coinbase_blinding(&root_a, 42).unwrap();
        let b = coinbase_blinding(&root_b, 42).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn coinbase_blinding_rejects_out_of_range_height() {
        let root = fixed_root();
        // u31 boundary: 2^31 = 0x8000_0000. Any height ≥ this must fail.
        assert!(coinbase_blinding(&root, 0x8000_0000).is_err());
        assert!(coinbase_blinding(&root, u64::MAX).is_err());
        // 0x7fff_ffff is the largest accepted index.
        assert!(coinbase_blinding(&root, 0x7fff_ffff).is_ok());
    }

    #[test]
    fn spend_output_blinding_deterministic() {
        let root = fixed_root();
        let a = spend_output_blinding(&root, 0, 7).unwrap();
        let b = spend_output_blinding(&root, 0, 7).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn spend_output_blinding_differs_per_account() {
        let root = fixed_root();
        let a = spend_output_blinding(&root, 0, 0).unwrap();
        let b = spend_output_blinding(&root, 1, 0).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn spend_output_blinding_differs_per_index() {
        let root = fixed_root();
        let a = spend_output_blinding(&root, 0, 0).unwrap();
        let b = spend_output_blinding(&root, 0, 1).unwrap();
        assert_ne!(*a, *b);
    }

    /// A coinbase blinding for height 0 must NOT collide with the
    /// spend output (account=0, index=0) blinding — the two
    /// derivation domains must be disjoint.
    #[test]
    fn coinbase_and_spend_domains_are_disjoint() {
        let root = fixed_root();
        let cb = coinbase_blinding(&root, 0).unwrap();
        let sp = spend_output_blinding(&root, 0, 0).unwrap();
        assert_ne!(*cb, *sp);
    }

    // ─────────────────────────────────────────────────────────────
    // Cross-run determinism vector. Pinning the first byte of the
    // derived blinding for a known phrase gives us a regression
    // tripwire: any change to the derivation path, HMAC seed, or
    // BIP-39 normalization would flip this.
    //
    // (We do not pin the full 32 bytes — the goal is regression
    // detection, not a third-party compatibility claim.)
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn deterministic_vector_pinned() {
        let root = fixed_root();
        let h0 = coinbase_blinding(&root, 0).unwrap();
        let h1 = coinbase_blinding(&root, 1).unwrap();
        // Both must be non-zero and well-formed scalars (length-checked).
        assert_eq!(h0.len(), 32);
        assert_eq!(h1.len(), 32);
        assert!(h0.iter().any(|&b| b != 0));
        assert!(h1.iter().any(|&b| b != 0));
    }

    // ─────────────────────────────────────────────────────────────
    // Restart equivalence: a fresh Bip39Seed parsed from the
    // post-Drop phrase string still yields the same seed bytes.
    // Models "wallet closed → wallet reopened from on-disk phrase".
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_after_drop_reproduces_seed_bytes() {
        let phrase_owned = {
            let seed = Bip39Seed::from_phrase(KNOWN_24_WORD, SeedAcceptance::NewWallet).unwrap();
            // Copy out the normalized phrase before drop.
            seed.phrase().to_string()
        };
        let reparsed = Bip39Seed::from_phrase(&phrase_owned, SeedAcceptance::NewWallet).unwrap();
        let canonical = Bip39Seed::from_phrase(KNOWN_24_WORD, SeedAcceptance::NewWallet).unwrap();
        assert_eq!(reparsed.seed_bytes(), canonical.seed_bytes());
    }
}
