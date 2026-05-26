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

use crate::types::WalletError;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF domain-separation info for the post-Argon2 stretch.
///
/// MUST NOT change without a wallet format-version bump — any
/// alteration silently invalidates all existing wallets.
const HKDF_INFO: &[u8] = b"DOM:wallet-key:v1";

/// Argon2id parameters.
///
/// Pinning these as constants makes any change a deliberate, visible
/// wallet-format break instead of an accidental drift via dependency
/// upgrades or copy-paste.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Time cost (number of iterations).
    pub t_cost: u32,
    /// Parallelism factor.
    pub parallelism: u32,
}

impl KdfParams {
    /// OWASP-recommended Argon2id baseline (2025): m = 64 MiB, t = 3, p = 1.
    pub const OWASP_V1: Self = Self {
        m_cost_kib: 65536,
        t_cost: 3,
        parallelism: 1,
    };
}

/// A wallet's symmetric encryption key (32 bytes).
///
/// The inner buffer is wrapped in [`Zeroizing`] so it is wiped from
/// memory on drop. The type is opaque: there is no public way to
/// extract the raw bytes except through the crate-private
/// [`WalletKey::as_bytes`], which callers consume in narrow scopes.
pub struct WalletKey(Zeroizing<[u8; 32]>);

impl WalletKey {
    /// Construct from raw bytes. Crate-private — only constructors in
    /// this module that derive keys via the canonical KDF may use it.
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the raw key bytes. Crate-private to limit the surface
    /// over which raw key material can be observed.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive the wallet encryption key from a password and per-wallet salt.
///
/// Two stages:
///
/// 1. **Argon2id stretch.** Slow, memory-hard KDF resistant to GPU /
///    ASIC brute force. Salt is the per-wallet 32-byte random salt
///    from the on-disk header.
/// 2. **HKDF-SHA256 expand** with `info = "DOM:wallet-key:v1"` to
///    domain-separate the final key.
///
/// The output is a 32-byte key suitable for use with
/// `ChaCha20Poly1305`.
pub fn derive_wallet_key(
    password: &str,
    salt: &[u8; 32],
    params: &KdfParams,
) -> Result<WalletKey, WalletError> {
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| WalletError::Crypto(format!("Argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut stretched = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut stretched[..])
        .map_err(|e| WalletError::Crypto(format!("Argon2id failed: {e}")))?;

    let hkdf = Hkdf::<Sha256>::new(Some(&salt[..]), &stretched[..]);
    let mut key_bytes = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut key_bytes)
        .map_err(|_| WalletError::Crypto("HKDF expansion failed".into()))?;

    Ok(WalletKey::from_bytes(key_bytes))
}

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

    // ─────────────────────────────────────────────────────────────
    // KDF determinism: same (password, salt, params) → same key.
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn derive_wallet_key_is_deterministic() {
        let password = "correct horse battery staple";
        let salt = [0x42u8; 32];
        let a = derive_wallet_key(password, &salt, &KdfParams::OWASP_V1).unwrap();
        let b = derive_wallet_key(password, &salt, &KdfParams::OWASP_V1).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn derive_wallet_key_differs_per_password() {
        let salt = [0x42u8; 32];
        let a = derive_wallet_key("password_a", &salt, &KdfParams::OWASP_V1).unwrap();
        let b = derive_wallet_key("password_b", &salt, &KdfParams::OWASP_V1).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn derive_wallet_key_differs_per_salt() {
        let pw = "password";
        let salt_a = [0x01u8; 32];
        let salt_b = [0x02u8; 32];
        let a = derive_wallet_key(pw, &salt_a, &KdfParams::OWASP_V1).unwrap();
        let b = derive_wallet_key(pw, &salt_b, &KdfParams::OWASP_V1).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// Changing KDF params (even by one parameter) MUST produce a
    /// different key. This is the runtime tripwire ensuring that any
    /// silent params drift breaks loud, not subtly.
    #[test]
    fn derive_wallet_key_differs_per_params() {
        let pw = "password";
        let salt = [0x42u8; 32];
        let weaker = KdfParams {
            m_cost_kib: 8192,
            t_cost: 1,
            parallelism: 1,
        };
        let a = derive_wallet_key(pw, &salt, &KdfParams::OWASP_V1).unwrap();
        let b = derive_wallet_key(pw, &salt, &weaker).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// OWASP_V1 constants are pinned and must not drift accidentally.
    #[test]
    fn owasp_v1_params_pinned() {
        assert_eq!(KdfParams::OWASP_V1.m_cost_kib, 65536);
        assert_eq!(KdfParams::OWASP_V1.t_cost, 3);
        assert_eq!(KdfParams::OWASP_V1.parallelism, 1);
    }

    // ─────────────────────────────────────────────────────────────
    // Lock state machine.
    // ─────────────────────────────────────────────────────────────

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

    /// Multiple consecutive lock-cycles re-derive the same key.
    /// Models: unlock → lock → unlock; the recovered key must be
    /// bit-identical, otherwise saves/loads across cycles diverge.
    #[test]
    fn lock_unlock_cycle_is_deterministic() {
        let salt = [0x33u8; 32];
        let password = "pa55w0rd";

        let key_1 = {
            let session = UnlockedSession::from_verified_password(password.to_string());
            let k = derive_wallet_key(session.password(), &salt, &KdfParams::OWASP_V1).unwrap();
            session.into_locked();
            *k.as_bytes()
        };

        let key_2 = {
            let session = UnlockedSession::from_verified_password(password.to_string());
            let k = derive_wallet_key(session.password(), &salt, &KdfParams::OWASP_V1).unwrap();
            session.into_locked();
            *k.as_bytes()
        };

        assert_eq!(key_1, key_2);
    }

    /// Two distinct passwords MUST produce distinct keys, even with
    /// the same salt. This is the wrong-password rejection invariant:
    /// the AEAD decrypt at the storage layer relies on key mismatch
    /// to reject wrong passwords.
    #[test]
    fn wrong_password_yields_different_key() {
        let salt = [0x55u8; 32];
        let right = derive_wallet_key("correct", &salt, &KdfParams::OWASP_V1).unwrap();
        let wrong = derive_wallet_key("c0rrect", &salt, &KdfParams::OWASP_V1).unwrap();
        assert_ne!(right.as_bytes(), wrong.as_bytes());
    }
}
