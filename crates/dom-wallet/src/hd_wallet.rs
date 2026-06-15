//! HD wallet key derivation — re-exported from the shared `dom-wallet-keys`
//! crate (single audited source for v1 and v2; the derivation is byte-identical
//! by construction). The implementation and its unit tests moved with the code;
//! v1's integration tests (coinbase build, restore-from-phrase) prove the
//! derivation is unchanged.
pub use dom_wallet_keys::hd_wallet::*;
