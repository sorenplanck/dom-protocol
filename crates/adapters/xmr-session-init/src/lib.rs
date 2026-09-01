//! Pre-funding initialization of restart-safe local XMR secrets.

#![forbid(unsafe_code)]

use rand::{CryptoRng, RngCore};
use xmr_crypto::{combine_public_shares, XmrPrivateViewKey, XmrSpendShare};
use xmr_dleq_nullifier_store::{DleqNullifierStore, NullifierError, RegistrationOutcome};
use xmr_refund_policy::{RefundPolicyError, ValidatedRefundPolicy};
use xmr_secret_store::{SecretMaterialStore, SecretStoreError, XmrSecretMaterial};
use xmr_setup_profile::ValidatedXmrSetup;

/// Session-initialization failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionInitError {
    /// Local scalar/public-key material is invalid.
    #[error("invalid local XMR key material")]
    InvalidKeyMaterial,
    /// Local + DLEQ-certified remote share differs from frozen setup.
    #[error("combined XMR spend public key mismatch")]
    CombinedPublicKeyMismatch,
    /// Encrypted secret storage failed.
    #[error("XMR secret storage failed: {0}")]
    Store(#[from] SecretStoreError),
    /// One-shot DLEQ registration failed.
    #[error("DLEQ nullifier registration failed: {0}")]
    Nullifier(#[from] NullifierError),
    /// The refund path was not admitted before funding.
    #[error("XMR refund policy failed: {0}")]
    Refund(#[from] RefundPolicyError),
}

/// Validates and stores the local spend share and private view key before
/// funding. Private on purpose: it performs no refund admission and no
/// nullifier registration, so it must not be reachable as a settlement entry
/// point. [`initialize_session_guarded`] is the only public pre-funding path,
/// and it calls this only after the refund policy and the one-shot DLEQ
/// registration have both succeeded.
fn initialize_session<S: SecretMaterialStore>(
    setup: &ValidatedXmrSetup,
    store: &S,
    local_spend_share_le: [u8; 32],
    private_view_key_le: [u8; 32],
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<(), SessionInitError> {
    let local_share = XmrSpendShare::from_canonical_bytes(local_spend_share_le)
        .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
    let view_key = XmrPrivateViewKey::from_canonical_bytes(private_view_key_le)
        .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
    let local_public = local_share
        .public_share()
        .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
    let combined = combine_public_shares(local_public, setup.claim().ed_compressed)
        .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
    if combined != setup.combined_spend_public_key() {
        return Err(SessionInitError::CombinedPublicKeyMismatch);
    }
    let material = local_share
        .expose(|local| view_key.expose(|view| XmrSecretMaterial::new(*local, *view)))
        .map_err(SessionInitError::Store)?;
    store.insert(setup.settlement_id(), setup.terms_hash(), &material, rng)?;
    Ok(())
}

/// Outcome of guarded, restart-safe pre-funding initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardedSessionInitialization {
    /// Whether the DLEQ claim was newly inserted or replayed identically.
    pub nullifier: RegistrationOutcome,
}

/// Preferred pre-funding entry point.
///
/// It refuses to store usable local XMR secrets until the refund policy is
/// validated and the DLEQ public claim is durably registered one-shot.
pub fn initialize_session_guarded<S: SecretMaterialStore>(
    setup: &ValidatedXmrSetup,
    store: &S,
    nullifiers: &DleqNullifierStore,
    refund_policy: &ValidatedRefundPolicy,
    local_spend_share_le: [u8; 32],
    private_view_key_le: [u8; 32],
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<GuardedSessionInitialization, SessionInitError> {
    refund_policy.require_pre_funding()?;
    let nullifier =
        nullifiers.register(setup.settlement_id(), setup.binding_hash(), &setup.claim())?;
    initialize_session(setup, store, local_spend_share_le, private_view_key_le, rng)?;
    Ok(GuardedSessionInitialization { nullifier })
}
