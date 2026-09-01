//! XMR adapter profile and per-settlement public setup binding.

#![forbid(unsafe_code)]

use blake2::{digest::consts::U32, Blake2b, Digest};
use kaystra_core::{
    terms::{SettlementTermsV1, TermsError},
    types::LockMechanism,
};
use xmr_dleq_sigma::{
    verify_bound, BoundCrossCurveProofV1, CrossCurvePublicClaim, DleqError, ROLE_XMR_SHARED_SPEND,
};
use xmr_live_sidecar_api::API_VERSION_V2;

type Blake2b256 = Blake2b<U32>;

/// Static-profile hash domain.
pub const PROFILE_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-ADAPTER-PROFILE/V2\0";
/// Proof-context hash domain.
pub const PROOF_CONTEXT_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-DLEQ-CONTEXT/V2\0";
/// Full per-settlement binding domain.
pub const SETUP_BINDING_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-SETUP-BINDING/V2\0";

/// Monero network selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum XmrNetwork {
    /// Mainnet.
    Mainnet = 1,
    /// Stagenet.
    Stagenet = 2,
    /// Testnet/regtest harness.
    Testnet = 3,
}

/// Frozen static adapter profile committed in `adapter_profile_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmrAdapterProfileV1 {
    /// Monero network.
    pub network: XmrNetwork,
    /// Sidecar protocol version.
    pub sidecar_api_version: u16,
    /// Configured independent RPC nodes.
    pub rpc_node_count: u16,
    /// Required agreeing nodes.
    pub rpc_quorum: u16,
    /// Maximum accepted raw transaction bytes.
    pub max_raw_tx_bytes: u32,
}

impl XmrAdapterProfileV1 {
    /// Conservative profile constructor.
    pub fn new(
        network: XmrNetwork,
        rpc_node_count: u16,
        rpc_quorum: u16,
    ) -> Result<Self, SetupError> {
        if rpc_node_count == 0 || rpc_quorum == 0 || rpc_quorum > rpc_node_count {
            return Err(SetupError::InvalidProfile);
        }
        Ok(Self {
            network,
            sidecar_api_version: API_VERSION_V2,
            rpc_node_count,
            rpc_quorum,
            max_raw_tx_bytes: u32::try_from(xmr_live_sidecar_api::MAX_RAW_TX_BYTES)
                .map_err(|_| SetupError::BoundsExceeded)?,
        })
    }

    /// Canonical static profile hash.
    pub fn profile_hash(&self) -> [u8; 32] {
        let mut hasher = Blake2b256::new();
        hasher.update(PROFILE_DOMAIN);
        hasher.update([self.network as u8]);
        hasher.update(self.sidecar_api_version.to_be_bytes());
        hasher.update(self.rpc_node_count.to_be_bytes());
        hasher.update(self.rpc_quorum.to_be_bytes());
        hasher.update(self.max_raw_tx_bytes.to_be_bytes());
        hasher.finalize().into()
    }
}

/// Public economic context used before the adaptor point exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmrProofContextV1 {
    /// Settlement id.
    pub settlement_id: [u8; 32],
    /// XMR chain id from terms.
    pub chain_id: [u8; 32],
    /// XMR asset id from terms.
    pub asset_id: [u8; 32],
    /// Exact piconero amount.
    pub amount_piconero: u128,
    /// Confirmation target.
    pub min_confirmations: u32,
    /// Maximum reorg depth.
    pub max_reorg_depth: u32,
}

/// Computes the context passed to `XmrRouteSecret::generate`.
pub fn proof_context_hash(
    profile: &XmrAdapterProfileV1,
    context: &XmrProofContextV1,
) -> Result<[u8; 32], SetupError> {
    if context.settlement_id == [0; 32]
        || context.chain_id == [0; 32]
        || context.asset_id == [0; 32]
        || context.amount_piconero == 0
        || context.min_confirmations == 0
        || context.max_reorg_depth < context.min_confirmations
    {
        return Err(SetupError::InvalidProfile);
    }
    let mut hasher = Blake2b256::new();
    hasher.update(PROOF_CONTEXT_DOMAIN);
    hasher.update(profile.profile_hash());
    hasher.update(context.settlement_id);
    hasher.update(context.chain_id);
    hasher.update(context.asset_id);
    hasher.update(context.amount_piconero.to_be_bytes());
    hasher.update(context.min_confirmations.to_be_bytes());
    hasher.update(context.max_reorg_depth.to_be_bytes());
    Ok(hasher.finalize().into())
}

/// Explicit acknowledgement of the laboratory-era mechanism alias.
///
/// Historical: before `LockMechanism::CrossCurveSharedSpend = 0x05` was
/// ratified (NAR-DC-P1-008 §3), frozen V1 had no XMR tag and laboratory
/// terms borrowed `SchnorrAdaptor` under this token. The ratified tag needs
/// no token — it means what it says — and is the only path a production
/// setup takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V1MechanismAdmission {
    /// Laboratory-only profile-gated alias.
    LaboratoryAlias,
}

/// Public per-settlement XMR setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmrSetupBindingV1 {
    /// Settlement id.
    pub settlement_id: [u8; 32],
    /// Frozen terms hash.
    pub terms_hash: [u8; 32],
    /// Bound same-witness proof.
    pub dleq: BoundCrossCurveProofV1,
    /// Funding transaction expected by the adapter.
    pub funding_tx_hash: [u8; 32],
    /// Exact funding amount.
    pub expected_amount_piconero: u64,
    /// Destination address for sweep.
    pub destination: String,
    /// Public spend key after local + remote share addition.
    pub combined_spend_public_key: [u8; 32],
}

/// Setup failures.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    /// Static profile/context is invalid.
    #[error("invalid XMR adapter profile")]
    InvalidProfile,
    /// Terms are non-canonical.
    #[error("invalid Kaystra terms: {0}")]
    Terms(#[from] TermsError),
    /// DLEQ failed.
    #[error("invalid XMR cross-curve proof: {0}")]
    Dleq(#[from] DleqError),
    /// Public fields do not match frozen terms.
    #[error("XMR setup binding mismatch")]
    BindingMismatch,
    /// Frozen V1 alias was not explicitly authorized.
    #[error("XMR shared spend is not admitted by frozen Kaystra V1")]
    MechanismNotAdmitted,
    /// Length or integer exceeds bound.
    #[error("XMR setup bound exceeded")]
    BoundsExceeded,
}

/// Unforgeable validated setup token.
#[derive(Clone)]
pub struct ValidatedXmrSetup {
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
    claim: CrossCurvePublicClaim,
    funding_tx_hash: [u8; 32],
    expected_amount_piconero: u64,
    destination: String,
    combined_spend_public_key: [u8; 32],
    binding_hash: [u8; 32],
}

impl core::fmt::Debug for ValidatedXmrSetup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ValidatedXmrSetup")
            .field("settlement_id", &"<public-id>")
            .field("funding_tx_hash", &"<public-txid>")
            .field("expected_amount_piconero", &self.expected_amount_piconero)
            .finish_non_exhaustive()
    }
}

impl ValidatedXmrSetup {
    /// Settlement id.
    pub const fn settlement_id(&self) -> [u8; 32] {
        self.settlement_id
    }
    /// Terms hash.
    pub const fn terms_hash(&self) -> [u8; 32] {
        self.terms_hash
    }
    /// DLEQ-certified public claim.
    pub const fn claim(&self) -> CrossCurvePublicClaim {
        self.claim
    }
    /// Funding transaction hash.
    pub const fn funding_tx_hash(&self) -> [u8; 32] {
        self.funding_tx_hash
    }
    /// Expected piconero amount.
    pub const fn expected_amount_piconero(&self) -> u64 {
        self.expected_amount_piconero
    }
    /// Destination address.
    pub fn destination(&self) -> &str {
        &self.destination
    }
    /// Combined public spend key.
    pub const fn combined_spend_public_key(&self) -> [u8; 32] {
        self.combined_spend_public_key
    }
    /// Full public setup digest.
    pub const fn binding_hash(&self) -> [u8; 32] {
        self.binding_hash
    }
}

/// Validates all representable frozen-V1 bindings before funding.
pub fn validate_setup(
    terms: &SettlementTermsV1,
    profile: &XmrAdapterProfileV1,
    binding: XmrSetupBindingV1,
    admission: Option<V1MechanismAdmission>,
) -> Result<ValidatedXmrSetup, SetupError> {
    terms.validate()?;
    let terms_hash = terms.terms_hash()?;
    match (admission, terms.counterparty_leg.mechanism) {
        // The ratified tag (NAR-DC-P1-008 §3): no admission token exists or
        // is accepted for it — a token would imply the meaning needs help.
        (None, LockMechanism::CrossCurveSharedSpend) => {}
        // The laboratory-era alias, kept for the pre-ratification fixtures.
        (Some(V1MechanismAdmission::LaboratoryAlias), LockMechanism::SchnorrAdaptor) => {}
        _ => return Err(SetupError::MechanismNotAdmitted),
    }
    if terms.counterparty_leg.amount > u128::from(u64::MAX) {
        return Err(SetupError::BoundsExceeded);
    }
    let context = XmrProofContextV1 {
        settlement_id: terms.settlement_id.0,
        chain_id: terms.counterparty_leg.chain_id.0,
        asset_id: terms.counterparty_leg.asset_id.0,
        amount_piconero: terms.counterparty_leg.amount,
        min_confirmations: terms.counterparty_leg.finality.min_confirmations,
        max_reorg_depth: terms.counterparty_leg.finality.max_reorg_depth,
    };
    let context_hash = proof_context_hash(profile, &context)?;
    let claim = verify_bound(
        &binding.dleq,
        &binding.settlement_id,
        &context_hash,
        ROLE_XMR_SHARED_SPEND,
    )?;
    if terms.counterparty_leg.adapter_profile_hash != profile.profile_hash()
        || terms.settlement_id.0 != binding.settlement_id
        || terms_hash != binding.terms_hash
        || terms.adaptor_point_sec1 != claim.secp_compressed
        || terms.counterparty_leg.amount != u128::from(binding.expected_amount_piconero)
        || binding.funding_tx_hash == [0; 32]
        || binding.combined_spend_public_key == [0; 32]
        || binding.destination.is_empty()
        || binding.destination.len() > xmr_live_sidecar_api::MAX_DESTINATION_BYTES
    {
        return Err(SetupError::BindingMismatch);
    }
    let proof_hash = binding.dleq.binding_hash()?;
    let destination_len =
        u16::try_from(binding.destination.len()).map_err(|_| SetupError::BoundsExceeded)?;
    let mut hasher = Blake2b256::new();
    hasher.update(SETUP_BINDING_DOMAIN);
    hasher.update(binding.settlement_id);
    hasher.update(binding.terms_hash);
    hasher.update(profile.profile_hash());
    hasher.update(proof_hash);
    hasher.update(binding.funding_tx_hash);
    hasher.update(binding.expected_amount_piconero.to_be_bytes());
    hasher.update(destination_len.to_be_bytes());
    hasher.update(binding.destination.as_bytes());
    hasher.update(binding.combined_spend_public_key);
    let binding_hash = hasher.finalize().into();
    Ok(ValidatedXmrSetup {
        settlement_id: binding.settlement_id,
        terms_hash: binding.terms_hash,
        claim,
        funding_tx_hash: binding.funding_tx_hash,
        expected_amount_piconero: binding.expected_amount_piconero,
        destination: binding.destination,
        combined_spend_public_key: binding.combined_spend_public_key,
        binding_hash,
    })
}
