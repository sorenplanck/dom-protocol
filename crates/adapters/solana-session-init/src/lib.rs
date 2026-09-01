//! Two-phase creation and durable registration of a Solana settlement setup.
//!
//! Phase 1 generates the cross-curve secret before `SettlementTermsV1` exists.
//! Phase 2 freezes `T` into terms, validates every PDA/field and registers the
//! public setup before any funding instruction is authorized.

#![forbid(unsafe_code)]

use kaystra_core::terms::SettlementTermsV1;
use rand::{CryptoRng, RngCore};
use solana_pda::derive_escrow_pdas;
use solana_profile::{
    proof_context_from_terms, proof_context_hash, setup_id, validate_setup, SetupError,
    SolanaAdapterProfileV1, SolanaAssetV1, SolanaProofContextV1, SolanaSetupBindingV1,
    ValidatedSolanaSetup,
};
use solana_route_secret::{RouteSecretError, SolanaRouteSecret};
use solana_secret_store::{SecretStoreError, SolanaWitnessMaterial, WitnessMaterialStore};
use solana_setup_store::{SetupStoreError, SolanaSetupStore};
use solana_types::SolanaPubkey;

/// Session initialization error.
#[derive(Debug, thiserror::Error)]
pub enum SessionInitError {
    #[error("Solana setup profile failed: {0}")]
    Setup(#[from] SetupError),
    #[error("Solana route secret failed: {0}")]
    Route(#[from] RouteSecretError),
    #[error("Solana PDA derivation failed")]
    Pda,
    #[error("Solana setup persistence failed: {0}")]
    Store(#[from] SetupStoreError),
    #[error("Solana witness persistence failed: {0}")]
    Witness(#[from] SecretStoreError),
    #[error("no setup registered for this settlement")]
    UnknownSettlement,
}

/// Generate the route secret from a pre-adaptor context.
pub fn prepare_route_secret(
    profile: &SolanaAdapterProfileV1,
    context: &SolanaProofContextV1,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<SolanaRouteSecret, SessionInitError> {
    let context_hash = proof_context_hash(profile, context)?;
    Ok(SolanaRouteSecret::generate(
        context.settlement_id,
        context_hash,
        rng,
    )?)
}

/// Private route secret plus validated public setup.
pub struct InitializedSolanaSession {
    route_secret: SolanaRouteSecret,
    setup: ValidatedSolanaSetup,
}

impl core::fmt::Debug for InitializedSolanaSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InitializedSolanaSession")
            .field("route_secret", &"<redacted>")
            .field("setup", &self.setup)
            .finish()
    }
}

impl InitializedSolanaSession {
    pub fn setup(&self) -> &ValidatedSolanaSetup {
        &self.setup
    }

    pub fn with_route_secret<R>(&self, operation: impl FnOnce(&SolanaRouteSecret) -> R) -> R {
        operation(&self.route_secret)
    }
}

/// Finalize the setup after the generated adaptor point is frozen into terms.
pub fn finalize_session(
    profile: &SolanaAdapterProfileV1,
    terms: &SettlementTermsV1,
    asset: SolanaAssetV1,
    funder: SolanaPubkey,
    program_data_hash: [u8; 32],
    route_secret: SolanaRouteSecret,
    store: &SolanaSetupStore,
) -> Result<InitializedSolanaSession, SessionInitError> {
    let context = proof_context_from_terms(terms, asset, funder)?;
    let context_hash = proof_context_hash(profile, &context)?;
    solana_route_secret::verify_counterparty_bundle(
        route_secret.proof(),
        &terms.settlement_id.0,
        &context_hash,
    )?;
    if route_secret.dom_adaptor_point().0 != terms.adaptor_point_sec1 {
        return Err(SetupError::BindingMismatch.into());
    }

    let pdas = derive_escrow_pdas(profile.program_id, terms.settlement_id.0)
        .map_err(|_| SessionInitError::Pda)?;
    let (vault_pda, vault_bump) = match asset {
        SolanaAssetV1::NativeSol => (pdas.native_vault, pdas.native_vault_bump),
        SolanaAssetV1::LegacySpl { .. } => (pdas.token_vault, pdas.token_vault_bump),
    };
    let terms_hash = terms.terms_hash().map_err(SetupError::from)?;
    let deadline =
        i64::try_from(context.refund_after_unix).map_err(|_| SetupError::BoundsExceeded)?;
    let amount =
        u64::try_from(terms.counterparty_leg.amount).map_err(|_| SetupError::BoundsExceeded)?;
    let mut binding = SolanaSetupBindingV1 {
        settlement_id: terms.settlement_id.0,
        terms_hash,
        dleq: route_secret.proof().clone(),
        program_id: profile.program_id,
        state_pda: pdas.state,
        vault_pda,
        vault_authority: pdas.vault_authority,
        state_bump: pdas.state_bump,
        vault_bump,
        authority_bump: pdas.vault_authority_bump,
        asset,
        funder,
        recipient: SolanaPubkey(terms.counterparty_leg.beneficiary.0),
        refund_recipient: SolanaPubkey(terms.counterparty_leg.refund_to.0),
        amount,
        refund_after_unix: deadline,
        program_data_hash,
        setup_id: [0; 32],
    };
    binding.setup_id = setup_id(&binding)?;
    let validated = validate_setup(profile, terms, binding)?;
    store.register(validated.binding())?;
    Ok(InitializedSolanaSession {
        route_secret,
        setup: validated,
    })
}

/// Persists the session's route witness encrypted at rest.
///
/// Called once the public setup is durably registered, so a restarted node
/// holds both halves — the registered binding and the encrypted witness —
/// and [`resume_session`] can rebuild the session instead of degrading the
/// settlement to its timelock refund.
pub fn persist_route_witness<S: WitnessMaterialStore>(
    session: &InitializedSolanaSession,
    witness_store: &S,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<(), SessionInitError> {
    let material = session
        .route_secret
        .with_witness_little_endian(|witness| SolanaWitnessMaterial::new(*witness))?;
    witness_store.insert(
        session.setup.settlement_id(),
        session.setup.terms_hash(),
        &material,
        rng,
    )?;
    Ok(())
}

/// Rebuilds a session after a restart from the two durable halves.
///
/// The registered binding is re-validated against the same profile and terms
/// it was frozen under — resumption earns no trust that initialization did
/// not — and the decrypted witness must reproduce the registered public
/// claim exactly, or the resume is refused.
pub fn resume_session<S: WitnessMaterialStore>(
    profile: &SolanaAdapterProfileV1,
    terms: &SettlementTermsV1,
    setup_store: &SolanaSetupStore,
    witness_store: &S,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<InitializedSolanaSession, SessionInitError> {
    let binding = setup_store
        .load(&terms.settlement_id.0)?
        .ok_or(SessionInitError::UnknownSettlement)?;
    let proof = binding.dleq.clone();
    let validated = validate_setup(profile, terms, binding)?;
    let material = witness_store.load(&validated.settlement_id(), &validated.terms_hash())?;
    let route_secret =
        material.expose(|witness| SolanaRouteSecret::restore(*witness, proof.clone(), rng))?;
    Ok(InitializedSolanaSession {
        route_secret,
        setup: validated,
    })
}
