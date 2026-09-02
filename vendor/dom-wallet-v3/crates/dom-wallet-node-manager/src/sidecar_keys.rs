//! Wallet-owned copy of the DOM sidecar trust root.
//!
//! Production verification never accepts keys from configuration, the
//! environment, the network, or a caller. The only accepted verifier remains
//! `dom-sidecar`, whose constants must exactly match these wallet pins.

/// Primary DOM sidecar release key (ID `74197A95CA309CF0`).
pub const PRIMARY_MINISIGN_KEY: &str = "RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3";

/// Offline reserve DOM sidecar release key (ID `1BD5CDF20DACC151`).
pub const RESERVE_MINISIGN_KEY: &str = "RWRRwawN8s3VG9LgG8OAHG62mtfF/udZJ7OblMXpcDiHh74inGACfwKC";

/// Fail closed if the wallet pins and canonical verifier pins ever diverge.
///
/// There is intentionally no argument: a release build has no key-injection
/// seam at runtime.
pub(crate) fn enforce_canonical_key_match() -> Result<(), &'static str> {
    if PRIMARY_MINISIGN_KEY != dom_sidecar::sidecar_keys::PRIMARY_MINISIGN_KEY
        || RESERVE_MINISIGN_KEY != dom_sidecar::sidecar_keys::RESERVE_MINISIGN_KEY
    {
        return Err("wallet and canonical sidecar trust roots differ");
    }
    Ok(())
}

// Test-only keys prove that unknown/rotated keys are rejected. These symbols
// do not exist in a non-test build and cannot be selected at runtime.
#[cfg(test)]
pub(crate) const TEST_KEY_LABEL: &str = "DOM SIDECAR TEST KEY - NEVER TRUST IN PRODUCTION";
