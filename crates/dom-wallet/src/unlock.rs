//! Wallet lock / unlock state machine.
//!
//! Encodes the explicit transition between two operator-visible
//! states:
//!
//! - **Locked.** The wallet file exists on disk (encrypted). No key
//!   material or password resides in process memory.
//! - **Unlocked.** A password has been verified and the corresponding
//!   key derivation context lives in memory inside an
//!   [`UnlockedSession`]. The session is wiped on drop and on the
//!   explicit `into_locked()` consumption.
//!
//! ## Invariants
//!
//! 1. The wallet encryption key is NEVER persisted to disk in
//!    plaintext.
//! 2. In `Locked` state, NO password or derived key is held by the
//!    `Wallet` struct.
//! 3. Lock → Unlock requires the correct password, verified against
//!    the on-disk AEAD-tagged ciphertext. There is no offline
//!    password cache.
//! 4. The KDF parameters are pinned by [`KdfParams::OWASP_V1`]. Any
//!    change to those constants is a wallet-format break and MUST
//!    bump the wallet version.
//! 5. All secret material in this module is held inside
//!    [`zeroize::Zeroizing`] wrappers, so unintended copies are
//!    bounded.
//!
//! This module performs no transactional logic: it is purely about
//! controlling who has access to the encryption key at what time.

use zeroize::Zeroizing;

/// Key derivation (Argon2id + HKDF) and the encrypted file envelope now live in
/// the shared `dom-wallet-crypto` crate — a single audited source for v1 and
/// v2 (the on-disk format is unchanged). Re-exported here so existing paths
/// (`unlock::derive_wallet_key`, `unlock::KdfParams`, `unlock::WalletKey`) and
/// the `dom_wallet::` public surface keep working unchanged. Determinism /
/// param-pinning unit tests moved with the code to `dom-wallet-crypto`.
pub use dom_wallet_crypto::{derive_wallet_key, KdfParams, WalletKey};

/// Coarse lock state. Carries no secret material itself — it is a
/// pure marker. The owning `Wallet` carries the actual session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// No key material in memory; on-disk wallet file is encrypted.
    Locked,
    /// A verified password is held in an [`UnlockedSession`] and
    /// derived keys can be produced on demand.
    Unlocked,
}

/// An unlocked-session container. While alive, the wallet's password
/// is held (zeroized on drop) so the encryption key can be re-derived
/// for each save (every save uses a fresh salt).
///
/// **Locking is explicit and consuming:** call [`Self::into_locked`]
/// to drop the session. The `Drop` impl on the inner `Zeroizing`
/// wipes the password buffer before returning.
pub struct UnlockedSession {
    password: Zeroizing<String>,
}

impl UnlockedSession {
    /// Construct directly from a verified password.
    ///
    /// **The caller is responsible for verifying the password** —
    /// e.g. by attempting decryption of the on-disk wallet header.
    /// This constructor does NOT itself perform verification; it
    /// merely captures the password into a zeroizing buffer.
    pub fn from_verified_password(password: String) -> Self {
        Self {
            password: Zeroizing::new(password),
        }
    }

    /// Borrow the password (for re-deriving the encryption key when
    /// saving with a fresh salt). The reference's lifetime is bounded
    /// by the session.
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Explicitly lock — consumes `self`. The password is dropped
    /// here (zeroized).
    ///
    /// The return value is intentionally `()`: after this call the
    /// caller has no handle to any secret material.
    pub fn into_locked(self) {
        // self.password is dropped at end of scope; Zeroizing wipes
        // the underlying String buffer.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KDF determinism / param-pinning / wrong-password-key tests moved with the
    // code to `dom-wallet-crypto` (they exercise the now-shared KDF and its
    // crate-private key bytes). The lock state machine stays here.

    #[test]
    fn lock_state_variants_distinct() {
        assert_ne!(LockState::Locked, LockState::Unlocked);
    }

    /// `into_locked` consumes the session. The compile checks this;
    /// the runtime check just exercises the path.
    #[test]
    fn unlocked_session_into_locked_consumes() {
        let session = UnlockedSession::from_verified_password("pw".to_string());
        session.into_locked();
        // session is moved here — cannot be used again. The compiler
        // verifies this at build time; this test exercises the drop.
    }

    #[test]
    fn unlocked_session_exposes_password_borrow() {
        let session = UnlockedSession::from_verified_password("hello world".to_string());
        assert_eq!(session.password(), "hello world");
    }
}
