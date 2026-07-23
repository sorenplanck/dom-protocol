//! Wallet-owned location for versioned external `dom-node` sidecars.
//!
//! This deliberately exposes only the verified storage primitive. Activation
//! remains gated on the signed-identity promotion flow; the embedded node is
//! still the fallback until that wiring is enabled.

use dom_sidecar::SidecarStore;

/// Resolve the wallet application-data root and keep sidecars under its `bin`
/// child (`dom-node-<revision>` plus the `current` pointer).
#[allow(dead_code)]
pub fn store() -> Result<SidecarStore, String> {
    crate::managed_storage::resolve_app_data_base_dir()
        .map(SidecarStore::new)
        .map_err(|error| error.to_string())
}
