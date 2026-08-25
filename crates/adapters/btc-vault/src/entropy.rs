//! Entropy source for the one-shot secret randomness.
//!
//! Production draws from the OS CSPRNG. Tests inject a deterministic
//! source so the one-shot and crash properties can be proved without
//! flakiness — never the reverse: no production build gets a predictable
//! source.

/// A source of 32-byte secret randomness for `session_secrand` (M.6).
pub trait EntropySource: Send + Sync {
    /// Fills `out` with fresh secret randomness. Must never fail silently
    /// with predictable bytes.
    fn fill(&self, out: &mut [u8; 32]) -> Result<(), EntropyError>;
}

/// Entropy failure — the OS CSPRNG was unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("secure entropy unavailable")]
pub struct EntropyError;

/// The production entropy source: the OS CSPRNG via `getrandom`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&self, out: &mut [u8; 32]) -> Result<(), EntropyError> {
        getrandom::getrandom(out).map_err(|_| EntropyError)
    }
}
