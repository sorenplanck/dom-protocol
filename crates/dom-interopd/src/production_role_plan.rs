//! The negotiated FinalClaim role-plan artifact.
//!
//! A composed route's role plan cannot be synthesized by the composition
//! root: its two source scopes commit to the exact claim template hashes
//! frozen during the Contracts/F7 negotiation, which the wallet-side
//! compositor produces. The daemon therefore consumes the role plan the way
//! it consumes terms — as a canonical public artifact under the trusted
//! state directory — and authenticates every byte of it against the already
//! admitted composition before any authority sees it. An absent artifact is
//! the honest pre-negotiation state, not an error: the settlement runtime
//! simply cannot compose yet.

use std::path::Path;

use route_composer::{
    ComposedFinalClaimRolePlanV1, FinalClaimRevealModeV1, FinalClaimSecretSourceScopeV1,
    FinalClaimSecretSourceV1, COMPOSED_FINAL_CLAIM_ROLE_PLAN_ENCODED_LEN,
    FINAL_CLAIM_SECRET_SOURCE_SCOPE_ENCODED_LEN,
};

use crate::production_config::{
    read_owner_file_bounded, validate_state_dir, ProductionConfigErrorV1,
};
use crate::production_inputs::AuthenticatedProductionInputsV1;

/// Fixed artifact name under the trusted state directory.
pub(crate) const PRODUCTION_ROLE_PLAN_FILE_V1: &str = "role-plan.v1";

/// Exact artifact length: the role plan followed by the two scopes, in
/// canonical [upstream, downstream] order, with no framing and no slack.
const PRODUCTION_ROLE_PLAN_ARTIFACT_LEN_V1: usize =
    COMPOSED_FINAL_CLAIM_ROLE_PLAN_ENCODED_LEN + 2 * FINAL_CLAIM_SECRET_SOURCE_SCOPE_ENCODED_LEN;

/// One authenticated role plan with its two exact source scopes.
pub(crate) struct AuthenticatedProductionRolePlanV1 {
    pub(crate) role_plan: ComposedFinalClaimRolePlanV1,
    pub(crate) upstream_scope: FinalClaimSecretSourceScopeV1,
    pub(crate) downstream_scope: FinalClaimSecretSourceScopeV1,
}

impl core::fmt::Debug for AuthenticatedProductionRolePlanV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedProductionRolePlanV1([public commitments])")
    }
}

/// Loads and fully authenticates the role-plan artifact, or reports the
/// honest pre-negotiation absence.
pub(crate) fn load_production_role_plan_v1(
    state_dir: &Path,
    inputs: &AuthenticatedProductionInputsV1,
) -> Result<Option<AuthenticatedProductionRolePlanV1>, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let path = canonical_state.join(PRODUCTION_ROLE_PLAN_FILE_V1);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = read_owner_file_bounded(
        &path,
        PRODUCTION_ROLE_PLAN_ARTIFACT_LEN_V1 as u64,
        ProductionConfigErrorV1::RolePlanUnavailable,
    )?;
    authenticate_production_role_plan_bytes_v1(&bytes, inputs).map(Some)
}

/// Decodes and authenticates one exact role-plan artifact byte string.
pub(crate) fn authenticate_production_role_plan_bytes_v1(
    bytes: &[u8],
    inputs: &AuthenticatedProductionInputsV1,
) -> Result<AuthenticatedProductionRolePlanV1, ProductionConfigErrorV1> {
    if bytes.len() != PRODUCTION_ROLE_PLAN_ARTIFACT_LEN_V1 {
        return Err(ProductionConfigErrorV1::RolePlanRefused);
    }
    let (plan_bytes, scopes) = bytes.split_at(COMPOSED_FINAL_CLAIM_ROLE_PLAN_ENCODED_LEN);
    let (upstream_bytes, downstream_bytes) =
        scopes.split_at(FINAL_CLAIM_SECRET_SOURCE_SCOPE_ENCODED_LEN);
    let role_plan = ComposedFinalClaimRolePlanV1::decode_canonical(plan_bytes)
        .map_err(|_| ProductionConfigErrorV1::RolePlanRefused)?;
    let upstream_scope = FinalClaimSecretSourceScopeV1::decode_canonical(upstream_bytes)
        .map_err(|_| ProductionConfigErrorV1::RolePlanRefused)?;
    let downstream_scope = FinalClaimSecretSourceScopeV1::decode_canonical(downstream_bytes)
        .map_err(|_| ProductionConfigErrorV1::RolePlanRefused)?;

    let composition = inputs.composition();
    let admission = inputs.admission();
    if role_plan.route_id() != admission.route_id()
        || role_plan.route_scope_digest() != composition.route_scope_digest()
        || role_plan.composition_binding_digest() != composition.binding_digest()
    {
        return Err(ProductionConfigErrorV1::RolePlanRefused);
    }
    role_plan
        .authenticate(
            composition.upstream(),
            composition.downstream(),
            upstream_scope.clone(),
            downstream_scope.clone(),
        )
        .map_err(|_| ProductionConfigErrorV1::RolePlanRefused)?;
    // The production materialization owner accepts exactly one composed
    // shape: the daemon reveals first on the downstream settlement and
    // reacts to the counterparty's reveal upstream. Refusing every other
    // shape here keeps the artifact boundary as narrow as the authorities
    // behind it.
    if upstream_scope.secret_source() != FinalClaimSecretSourceV1::VerifiedCounterpartyClaim
        || upstream_scope.reveal_mode() != FinalClaimRevealModeV1::DomReactsToCounterpartyReveal
        || downstream_scope.secret_source() != FinalClaimSecretSourceV1::LocalOrigin
        || downstream_scope.reveal_mode() != FinalClaimRevealModeV1::DomRevealsFirst
    {
        return Err(ProductionConfigErrorV1::RolePlanRefused);
    }
    Ok(AuthenticatedProductionRolePlanV1 {
        role_plan,
        upstream_scope,
        downstream_scope,
    })
}
