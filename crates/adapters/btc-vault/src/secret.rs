//! The one-shot secret randomness (Annex M M.6.4).

use zeroize::Zeroize;

/// The `session_secrand` produced by a one-shot reservation (M.6.4).
///
/// Deliberately implements none of `Clone`, `Copy`, `Debug`, `Display`,
/// serde or public serialization. It is passed by value into the
/// `musig_nonce_gen` wrapper and zeroized immediately after; it never
/// enters a log, database, crash dump, fixture or error, and cannot be
/// re-obtained for the same reservation.
pub struct OneShotSessionSecrandV1 {
    bytes: [u8; 32],
}

impl OneShotSessionSecrandV1 {
    /// Wraps freshly generated randomness. Crate-private: the only way to
    /// obtain one is a successful [`crate::BitcoinNonceVault::consume`].
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Consumes the secret, handing the raw bytes to a closure that feeds
    /// them into the crypto backend, and zeroizes them immediately after
    /// the closure returns (M.6.4). The value cannot be used twice: it is
    /// taken by value.
    pub fn use_once<R>(mut self, f: impl FnOnce(&[u8; 32]) -> R) -> R {
        let result = f(&self.bytes);
        self.bytes.zeroize();
        result
    }
}

impl Drop for OneShotSessionSecrandV1 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
