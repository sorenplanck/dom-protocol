//! Pinned Minisign release keys for the managed DOM node sidecar.
//!
//! Keys are deliberately compiled into the wallet. They must never be fetched
//! from the release endpoint being authenticated.

/// Primary release-signing key (key ID `74197A95CA309CF0`).
pub use dom_sidecar::sidecar_keys::PRIMARY_MINISIGN_KEY;

/// Offline-reserve release-signing key (key ID `1BD5CDF20DACC151`).
pub use dom_sidecar::sidecar_keys::RESERVE_MINISIGN_KEY;

/// Every release manifest must verify under one of these pinned keys.
pub use dom_sidecar::sidecar_keys::TRUSTED_MINISIGN_KEYS;
pub use dom_sidecar::verify_minisign;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_key_pins_are_present_and_distinct() {
        assert!(TRUSTED_MINISIGN_KEYS.iter().all(|key| !key.is_empty()));
        assert_ne!(PRIMARY_MINISIGN_KEY, RESERVE_MINISIGN_KEY);
    }
}
