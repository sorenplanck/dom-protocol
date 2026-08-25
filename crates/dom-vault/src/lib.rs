//! Durable cryptographic implementation of the `NonceVaultV1` contract.
//!
//! Phase 1 deliverable. This crate is, together with `dom-leg`, one of the
//! only two authorized to depend on `dom-adaptor` (D-005). It translates the
//! `NonceVaultV1` contract — one-shot reservations, linear permits, sealing,
//! recovery and byte-identical resend — onto the neutral durable operations
//! of `store`.
//!
//! # Responsibility boundary
//!
//! The `store` holds opaque bytes and does not know what they are. This crate
//! does, and that is why the following live here: nonce identity, lifecycle
//! ordering, sealing of sensitive material and the fail-closed detection of
//! rollback, corruption and divergent revisions.
//!
//! # Ordering imposed by the contract
//!
//! The sequence is normative and cannot be reordered:
//!
//! ```text
//! claim_fresh_reservation
//!   → begin_nonce_derivation        (the private KDF already chose the final retry)
//!   → seal_derived_secret           (durable BEFORE any public computation)
//!   → open_sealed_secret_for_commitment / begin_stage_computation
//!   → persist_computed_artifact     (exact bytes BEFORE authorizing)
//!   → authorize_persisted_exposure
//!   → export                        (spends the permit DURABLY before releasing bytes)
//!   → resend_exported               (only returns persisted bytes; never recomputes)
//! ```
//!
//! # No real backend
//!
//! Without the `real-dom-adaptor` feature, this crate exposes no path that
//! fakes success: the operations that would require the backend do not exist.
//! The executable CI guard fails if the main suite passes without exercising
//! the pin.
//!
//! # One-shot capabilities
//!
//! An exposure permit cannot be duplicated: if it could, the same nonce would
//! authorize two distinct exposures. Uniqueness is enforced solely by Rust's
//! move semantics, so no capability type implements `Clone`.
//!
//! ```compile_fail
//! use dom_vault::ExposurePermit;
//! fn duplicate(permit: ExposurePermit) -> (ExposurePermit, ExposurePermit) {
//!     (permit.clone(), permit)
//! }
//! ```
//!
//! A consumed permit also cannot be re-presented:
//!
//! ```compile_fail
//! use dom_vault::{DurableNonceVault, ExposurePermit};
//! use dom_adaptor::NonceVaultV1;
//! fn replay(vault: &mut DurableNonceVault, permit: ExposurePermit) {
//!     let _first = vault.export(permit);
//!     let _second = vault.export(permit);
//! }
//! ```
//!
//! The same holds for the reservation handle, which is destroyed by cancellation:
//!
//! ```compile_fail
//! use dom_vault::{DurableNonceVault, ReservationHandle};
//! use dom_adaptor::NonceVaultV1;
//! fn revive(vault: &mut DurableNonceVault, reservation: ReservationHandle) {
//!     let _terminal = vault.cancel_reservation(reservation);
//!     let _again = vault.snapshot_reservation(&reservation);
//! }
//! ```
//!
//! The doctests above document the property; the strong executable guard is
//! the `capability_types_are_never_clone_or_copy` test, which breaks the
//! suite if anyone derives `Clone` or `Copy` on any capability.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "real-dom-adaptor")]
mod custody;
#[cfg(feature = "real-dom-adaptor")]
mod durable;
#[cfg(feature = "real-dom-adaptor")]
mod framing;
#[cfg(feature = "real-dom-adaptor")]
mod session;
#[cfg(feature = "real-dom-adaptor")]
mod vault;

#[cfg(feature = "real-dom-adaptor")]
pub use custody::{DurableLookup, DurableLookupCustody};
#[cfg(feature = "real-dom-adaptor")]
pub use durable::{BudgetScopeLocal, DurableVaultCore, VaultLimits};
#[cfg(feature = "real-dom-adaptor")]
pub use session::{AcceptedSession, SessionAuthority};
#[cfg(feature = "real-dom-adaptor")]
pub use vault::{
    ArtifactPersistencePermit, DerivationAttemptPermit, DurableNonceVault, ExportedArtifact,
    ExposurePermit, InitialSecretOpenPermit, PersistedExposureHandle, ReservationHandle,
    ReservationSnapshot, SpentArtifactSnapshot, StageComputationPermit,
};

/// Typed vault failure, with redacted observability.
///
/// No variant carries artifact bytes, raw identifiers or secret material
/// (I6).
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// Cryptographic backend disabled: build without `real-dom-adaptor`.
    #[error("dom crypto backend disabled: build with --features real-dom-adaptor")]
    CryptoBackendDisabled,
    /// Persistence layer unavailable.
    #[error("storage unavailable")]
    StorageUnavailable,
    /// Incoherent durable state: fail closed.
    #[error("corrupt state")]
    CorruptState,
    /// Rollback detected against the monotonic anchor.
    #[error("rollback detected")]
    RollbackDetected,
    /// The expected revision diverged from the durable revision.
    #[error("revision conflict")]
    RevisionConflict,
    /// The same key was re-presented with different bytes.
    #[error("idempotency conflict")]
    IdempotencyConflict,
    /// The requested reservation does not exist in durable state.
    #[error("reservation not found")]
    ReservationNotFound,
    /// Operation requested outside the order imposed by the contract.
    #[error("invalid transition")]
    InvalidTransition,
    /// Session identifier already used within the local lifetime.
    #[error("session id reused")]
    SessionIdReused,
    /// A monotonic counter would overflow.
    #[error("counter overflow")]
    CounterOverflow,
    /// Durable record declares a framing version this binary does not operate.
    #[error("unsupported record version")]
    UnsupportedVersion,
    /// One-shot permit invalid or not bound to the current durable state.
    #[error("invalid permit")]
    InvalidPermit,
    /// Configured durable budget exhausted.
    #[error("budget exhausted")]
    BudgetExhausted,
    /// Purpose outside the strict registry authorized in Phase One.
    #[error("unsupported purpose")]
    UnsupportedPurpose,
    /// Operating system CSPRNG unavailable.
    #[error("randomness unavailable")]
    RandomnessUnavailable,
    /// Adaptor operations blocked until restore reconciliation.
    #[error("restore quarantined")]
    RestoreQuarantined,
}

impl From<store::StoreError> for VaultError {
    fn from(error: store::StoreError) -> Self {
        // Explicit mapping: each store condition has its own classification
        // here. None becomes a panic and none carries content (I14).
        match error {
            store::StoreError::StorageUnavailable => VaultError::StorageUnavailable,
            store::StoreError::UnsupportedVersion { .. } => VaultError::CorruptState,
            store::StoreError::CorruptState => VaultError::CorruptState,
            store::StoreError::RevisionConflict => VaultError::RevisionConflict,
            store::StoreError::IdempotencyConflict => VaultError::IdempotencyConflict,
            store::StoreError::NotFound => VaultError::ReservationNotFound,
            store::StoreError::CounterOverflow => VaultError::CounterOverflow,
            // `StoreError` is `#[non_exhaustive]`: any condition this
            // version does not know about is a durability failure of
            // unknown shape, so it fails closed as corrupt state. It never
            // becomes a benign result and never carries content.
            _ => VaultError::CorruptState,
        }
    }
}

/// Result of vault operations.
pub type Result<T> = core::result::Result<T, VaultError>;

/// Opaque namespaces used by this crate inside the `store`.
///
/// They are domain constants, not hash tags: the `store` only uses them as a
/// partitioning key. No new cryptographic tag is invented here (I15).
pub mod namespace {
    /// Sealed record of the nonce pair.
    pub const SEALED_SECRET: &[u8] = b"dom-vault/sealed-secret";
    /// Persisted public artifact, byte for byte.
    pub const PERSISTED_ARTIFACT: &[u8] = b"dom-vault/persisted-artifact";
    /// Terminal descriptor of an already-spent artifact.
    pub const SPENT_ARTIFACT: &[u8] = b"dom-vault/spent-artifact";
    /// Permanent tombstones of session identifiers.
    pub const SESSION_TOMBSTONE: &[u8] = b"dom-vault/session-tombstone";
    /// Append-only reservation state, indexed by identifier and revision.
    pub const RESERVATION: &[u8] = b"dom-vault/reservation";
    /// Index from the public resume lookup to the reservation identifier.
    pub const REQUEST_LOOKUP: &[u8] = b"dom-vault/request-lookup";
    /// Write-once custody of the retained lookup before vault admission.
    pub const LOOKUP_CUSTODY: &[u8] = b"dom-vault/lookup-custody";
    /// Write-once tombstone of an abandoned lookup (RetryNotFound).
    pub const LOOKUP_ABANDONED: &[u8] = b"dom-vault/lookup-abandoned";
    /// Public artifact already authorized and not yet spent.
    pub const AUTHORIZED_ARTIFACT: &[u8] = b"dom-vault/authorized-artifact";
    /// Stage index to the spent permit, used for resend after restart.
    pub const SPENT_INDEX: &[u8] = b"dom-vault/spent-index";
    /// Irreversible burn marker for the secret material.
    pub const BURN_MARKER: &[u8] = b"dom-vault/burn-marker";
}

/// Durable registry of already-used session identifiers.
///
/// Implements the requirement that uniqueness be permanent for the lifetime
/// of the local identity. A memory-only registry does not satisfy the
/// contract, which is why this type requires a durable `store`.
pub struct DurableSessionIdRegistry<'a> {
    store: &'a mut store::Store,
}

impl core::fmt::Debug for DurableSessionIdRegistry<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DurableSessionIdRegistry([redacted])")
    }
}

impl<'a> DurableSessionIdRegistry<'a> {
    /// Creates the registry on top of a durable store.
    pub fn new(store: &'a mut store::Store) -> Self {
        Self { store }
    }

    /// Registers a not-yet-used identifier.
    ///
    /// Returns `true` when the identifier is new and becomes permanent, and
    /// `false` when it was already used — an identifier is never reused.
    pub fn register_unique_session_id(&mut self, session_id: &[u8; 32]) -> Result<bool> {
        // The value is irrelevant; the presence of the key is the tombstone.
        // Creation must be one atomic store operation: check-then-insert can
        // issue the same identifier twice under concurrent processes.
        Ok(self
            .store
            .put_opaque_if_absent(namespace::SESSION_TOMBSTONE, session_id, &[1u8])?)
    }
}

#[cfg(feature = "real-dom-adaptor")]
impl dom_adaptor::SessionIdRegistryV1 for DurableSessionIdRegistry<'_> {
    fn register_unique_session_id(&mut self, session_id: &[u8; 32]) -> dom_adaptor::Result<bool> {
        DurableSessionIdRegistry::register_unique_session_id(self, session_id).map_err(|_| {
            dom_adaptor::AdaptorError::InvalidContext("durable session registry unavailable")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, store::Store) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store::Store::open(&dir.path().join("vault.db")).expect("open");
        (dir, store)
    }

    #[test]
    fn session_ids_are_permanently_tombstoned() {
        let (_dir, mut store) = temp_store();
        let mut registry = DurableSessionIdRegistry::new(&mut store);
        let id = [7u8; 32];
        assert!(registry.register_unique_session_id(&id).expect("first"));
        assert!(
            !registry.register_unique_session_id(&id).expect("second"),
            "an already-used identifier can never be reused"
        );
    }

    #[test]
    fn tombstones_survive_reopening_the_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.db");
        let id = [9u8; 32];
        {
            let mut store = store::Store::open(&path).expect("open");
            let mut registry = DurableSessionIdRegistry::new(&mut store);
            assert!(registry.register_unique_session_id(&id).expect("first"));
        }
        // Reopening simulates a process restart: the tombstone is durable, not in-memory.
        let mut store = store::Store::open(&path).expect("reopen");
        let mut registry = DurableSessionIdRegistry::new(&mut store);
        assert!(
            !registry
                .register_unique_session_id(&id)
                .expect("after restart"),
            "the tombstone must survive a process restart"
        );
    }

    #[cfg(feature = "real-dom-adaptor")]
    #[test]
    fn durable_registry_is_the_real_dom_session_registry() {
        fn assert_registry<T: dom_adaptor::SessionIdRegistryV1>(_registry: &mut T) {}

        let (_dir, mut store) = temp_store();
        let mut registry = DurableSessionIdRegistry::new(&mut store);
        assert_registry(&mut registry);
    }

    #[test]
    fn error_display_never_leaks_material() {
        // Every variant must be a classification, never content.
        for error in [
            VaultError::CorruptState,
            VaultError::RollbackDetected,
            VaultError::SessionIdReused,
            VaultError::IdempotencyConflict,
        ] {
            let rendered = format!("{error}");
            assert!(!rendered.is_empty());
            assert!(
                !rendered.contains("0x") && !rendered.chars().any(|c| c.is_ascii_digit()),
                "an error must not carry bytes or indices: {rendered}"
            );
        }
    }
}
