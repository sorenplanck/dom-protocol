//! Pinned Minisign release keys for managed DOM node sidecars.
//!
//! These values are part of the wallet's trust root and are never downloaded
//! from the release endpoint that they authenticate.

/// Primary release-signing key (key ID `74197A95CA309CF0`).
pub const PRIMARY_MINISIGN_KEY: &str = "RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3";

/// Offline-reserve release-signing key (key ID `1BD5CDF20DACC151`).
pub const RESERVE_MINISIGN_KEY: &str = "RWRRwawN8s3VG9LgG8OAHG62mtfF/udZJ7OblMXpcDiHh74inGACfwKC";

/// Every release signature must verify under one of these pinned keys.
pub const TRUSTED_MINISIGN_KEYS: [&str; 2] = [PRIMARY_MINISIGN_KEY, RESERVE_MINISIGN_KEY];
