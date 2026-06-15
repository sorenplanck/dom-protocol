//! BIP-39 seed handling and deterministic blinding derivation — re-exported from
//! the shared `dom-wallet-keys` crate (single audited source for v1 and v2). The
//! implementation and its unit tests moved with the code; v1's integration tests
//! prove the coinbase/spend blindings are byte-identical.
pub use dom_wallet_keys::seed::*;
