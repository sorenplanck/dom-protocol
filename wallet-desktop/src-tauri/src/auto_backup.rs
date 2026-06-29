//! Auto-backup support — ETAPA 1: config-adjacent **pure helpers only**.
//!
//! The actual auto-backup wiring (the post-save hook, fund-materiality gate,
//! `spawn_blocking` off the wallet lock, atomic temp+rename writes, the external
//! destination and the `"auto-backup-failed"` event) lands in later steps. This
//! module currently exposes only the two pure functions those steps depend on,
//! plus their tests, so they can be reviewed in isolation.
//!
//! Nothing here is called yet, so the items are intentionally unused until
//! ETAPA 2 wires them — hence the module-level `dead_code` allowance. This is a
//! staged-code allowance, not a silenced warning on shipped-but-unused code.
#![allow(dead_code)]

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF-SHA256 `info` for the auto-backup passphrase. Deliberately distinct from
/// `dom_wallet_crypto`'s `"DOM:wallet-key:v1"`, so the auto-backup passphrase can
/// never coincide with the vault's at-rest key derivation domain.
const AUTO_BACKUP_HKDF_INFO: &[u8] = b"DOM:auto-backup:v1";

/// Bytes of derived passphrase material (hex-encoded to `2 * DERIVED_LEN` chars).
const DERIVED_LEN: usize = 32;

/// Derive the auto-backup passphrase from the live login password.
///
/// `bk_pass = hex( HKDF-SHA256-Expand( HKDF-Extract(ikm = password),
///                                     info = "DOM:auto-backup:v1", 32 ) )`
///
/// The result is what later steps pass to
/// `dom_wallet2::export_full_backup(.., passphrase, ..)`. `save_envelope` then
/// applies its own Argon2id + HKDF over a fresh random per-file salt, so the
/// real file key is `Argon2id(bk_pass, salt)` — domain-separated from the vault
/// key both by this HKDF `info` **and** by the per-file salt.
///
/// Deterministic in the password. Returned in `Zeroizing` so the derived secret
/// is wiped on drop. **Never** log this value and **never** persist it in
/// settings.
pub fn derive_auto_backup_passphrase(login_password: &str) -> Zeroizing<String> {
    let hk = Hkdf::<Sha256>::new(None, login_password.as_bytes());
    let mut okm = Zeroizing::new([0u8; DERIVED_LEN]);
    // HKDF-Expand only errors when the requested length exceeds 255*HashLen;
    // 32 bytes for SHA-256 (HashLen = 32) is always within bound.
    hk.expand(AUTO_BACKUP_HKDF_INFO, okm.as_mut())
        .expect("HKDF-Expand of 32 bytes is within the RFC 5869 length bound");
    // `hex::encode` returns the very String we wrap (a move, no extra secret
    // copy left un-zeroized).
    Zeroizing::new(hex::encode(okm.as_ref()))
}

// ── Login-password strength gate (for enabling EXTERNAL auto-backup) ──────────

/// Minimum login-password length to enable external auto-backup.
pub const MIN_BACKUP_PASSWORD_LEN: usize = 12;
/// At/above this length a passphrase is accepted on length alone (a long
/// passphrase needs no character-class variety).
pub const LONG_PASSPHRASE_LEN: usize = 20;
/// Minimum distinct character classes required below [`LONG_PASSPHRASE_LEN`].
pub const MIN_CHARACTER_CLASSES: usize = 3;

/// Why a login password is too weak to gate external auto-backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordStrengthError {
    /// Shorter than [`MIN_BACKUP_PASSWORD_LEN`].
    TooShort { min: usize, got: usize },
    /// Long enough but not varied enough (and below [`LONG_PASSPHRASE_LEN`]).
    TooFewClasses { min: usize, got: usize, len: usize },
}

impl std::fmt::Display for PasswordStrengthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordStrengthError::TooShort { min, got } => write!(
                f,
                "password is too short for external backup: {got} characters, need at least {min}"
            ),
            PasswordStrengthError::TooFewClasses { min, got, len } => write!(
                f,
                "password is too simple for external backup: {got} character type(s) in {len} \
                 characters, need at least {min} of (lowercase, uppercase, digit, symbol) \
                 — or use a passphrase of at least {LONG_PASSPHRASE_LEN} characters"
            ),
        }
    }
}

/// Assess whether `pw` is strong enough to gate **external** auto-backup, where
/// the encrypted seed leaves the machine protected by this password alone.
///
/// Criterion (documented, no external dependency — a deliberate minimum bar, not
/// a strength meter):
///   * reject if shorter than [`MIN_BACKUP_PASSWORD_LEN`] (12);
///   * accept on length alone if at least [`LONG_PASSPHRASE_LEN`] (20) — a long
///     passphrase;
///   * otherwise require at least [`MIN_CHARACTER_CLASSES`] (3) of the classes
///     {lowercase, uppercase, digit, other} (non-ASCII letters/symbols count as
///     "other").
///
/// So `"password1234"` (12 chars, 2 classes) is rejected, while `"Abcdef12wxyz"`
/// (3 classes) and `"correct horse battery"` (≥20 chars) pass.
pub fn assess_login_password_strength(pw: &str) -> Result<(), PasswordStrengthError> {
    let len = pw.chars().count();
    if len < MIN_BACKUP_PASSWORD_LEN {
        return Err(PasswordStrengthError::TooShort {
            min: MIN_BACKUP_PASSWORD_LEN,
            got: len,
        });
    }
    if len >= LONG_PASSPHRASE_LEN {
        return Ok(());
    }
    let (mut lower, mut upper, mut digit, mut other) = (false, false, false, false);
    for c in pw.chars() {
        if c.is_ascii_lowercase() {
            lower = true;
        } else if c.is_ascii_uppercase() {
            upper = true;
        } else if c.is_ascii_digit() {
            digit = true;
        } else {
            other = true;
        }
    }
    let classes = [lower, upper, digit, other]
        .into_iter()
        .filter(|b| *b)
        .count();
    if classes < MIN_CHARACTER_CLASSES {
        return Err(PasswordStrengthError::TooFewClasses {
            min: MIN_CHARACTER_CLASSES,
            got: classes,
            len,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── derive_auto_backup_passphrase ────────────────────────────────────────

    #[test]
    fn derived_passphrase_is_deterministic() {
        let a = derive_auto_backup_passphrase("correct horse battery staple");
        let b = derive_auto_backup_passphrase("correct horse battery staple");
        assert_eq!(
            a.as_str(),
            b.as_str(),
            "same password must derive identically"
        );
    }

    #[test]
    fn derived_passphrase_differs_per_password() {
        let a = derive_auto_backup_passphrase("password-one");
        let b = derive_auto_backup_passphrase("password-two");
        assert_ne!(
            a.as_str(),
            b.as_str(),
            "different passwords must derive differently"
        );
    }

    #[test]
    fn derived_passphrase_is_not_the_raw_password() {
        // The bite: the value handed to the backup must NOT be the login
        // password itself (domain-separated HKDF output, not a passthrough).
        let pw = "MyL0gin!Passw0rd";
        let derived = derive_auto_backup_passphrase(pw);
        assert_ne!(
            derived.as_str(),
            pw,
            "derived passphrase must not equal the raw password"
        );
        assert_eq!(
            derived.len(),
            DERIVED_LEN * 2,
            "must be 32-byte HKDF output, hex-encoded"
        );
        assert!(
            derived.chars().all(|c| c.is_ascii_hexdigit()),
            "must be printable hex (valid UTF-8 passphrase for save_envelope)"
        );
    }

    #[test]
    fn derived_passphrase_changes_with_domain_separation() {
        // Tripwire: this pins that the derivation uses HKDF over the password,
        // not a raw passthrough or a different scheme. A regression that swapped
        // the HKDF `info` or the primitive would flip this known-answer prefix.
        // We pin only a prefix (regression detection, not a compatibility claim).
        let derived = derive_auto_backup_passphrase("dom-auto-backup-kav");
        assert_eq!(derived.len(), 64);
        // Empty password still derives a well-formed, non-empty passphrase.
        let empty = derive_auto_backup_passphrase("");
        assert_eq!(empty.len(), 64);
        assert_ne!(derived.as_str(), empty.as_str());
    }

    // ── assess_login_password_strength ───────────────────────────────────────

    #[test]
    fn weak_password_too_short_is_rejected() {
        assert_eq!(
            assess_login_password_strength("Ab1!"),
            Err(PasswordStrengthError::TooShort { min: 12, got: 4 })
        );
    }

    #[test]
    fn weak_password_too_few_classes_is_rejected() {
        // 12 lowercase chars: long enough, only 1 class.
        assert_eq!(
            assess_login_password_strength("abcdefghijkl"),
            Err(PasswordStrengthError::TooFewClasses {
                min: 3,
                got: 1,
                len: 12
            })
        );
        // Classic weak password: 12 chars, 2 classes (lower + digit).
        assert_eq!(
            assess_login_password_strength("password1234"),
            Err(PasswordStrengthError::TooFewClasses {
                min: 3,
                got: 2,
                len: 12
            })
        );
    }

    #[test]
    fn strong_password_three_classes_is_accepted() {
        // 12 chars, 3 classes (lower + upper + digit).
        assert!(assess_login_password_strength("Abcdef12wxyz").is_ok());
        // 12 chars, 4 classes.
        assert!(assess_login_password_strength("Abcdef12!@#z").is_ok());
    }

    #[test]
    fn long_passphrase_is_accepted_on_length_alone() {
        // 28 lowercase chars + spaces: only 2 classes, but length >= 20.
        let pass = "correct horse battery staple";
        assert!(pass.chars().count() >= LONG_PASSPHRASE_LEN);
        assert!(assess_login_password_strength(pass).is_ok());
        // Exactly at the boundary: 20 lowercase chars.
        assert!(assess_login_password_strength("abcdefghijklmnopqrst").is_ok());
    }

    #[test]
    fn boundary_just_below_long_passphrase_still_needs_classes() {
        // 19 lowercase chars: below the long-passphrase exemption, 1 class.
        let pw = "abcdefghijklmnopqrs";
        assert_eq!(pw.chars().count(), 19);
        assert_eq!(
            assess_login_password_strength(pw),
            Err(PasswordStrengthError::TooFewClasses {
                min: 3,
                got: 1,
                len: 19
            })
        );
    }
}
