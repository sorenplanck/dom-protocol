//! Shared wallet key derivation, extracted from `dom-wallet` v1 so that v1 and
//! `dom-wallet2` (v2) derive keys from **one audited source** instead of two
//! copies that could drift apart.
//!
//! This matters for correctness, not just tidiness: the coinbase/spend blindings
//! a wallet derives MUST be **byte-identical** across v1 and v2 — a divergent
//! derivation produces different Pedersen commitments, so a wallet would fail to
//! recognize its own on-chain outputs. A single shared implementation makes them
//! identical by construction.
//!
//! It contains BIP-39 seed handling ([`seed::Bip39Seed`]) and BIP-32/BIP-44 HD
//! derivation ([`hd_wallet::ExtendedPrivKey`]), plus the two domain-separated
//! blinding derivations the wallet uses:
//! - [`seed::coinbase_blinding`] — coinbase, by block height
//!   (`m/44'/330'/0'/1'/height'`);
//! - [`seed::spend_output_blinding`] — deterministic spend/receive output, by
//!   index (`m/44'/330'/account'/0/index`).
//!
//! This is **wallet** logic (derivation paths / account model), deliberately
//! kept out of `dom-crypto` (primitive crypto) so the layers stay separate.

pub mod hd_wallet;
pub mod seed;

pub use hd_wallet::{ExtendedPrivKey, HdError, DOM_COIN_TYPE, HARDENED_OFFSET};
pub use seed::{
    coinbase_blinding, spend_output_blinding, Bip39Seed, SeedAcceptance, SeedError,
    NEW_WALLET_WORD_COUNT, SEED_BYTES,
};
