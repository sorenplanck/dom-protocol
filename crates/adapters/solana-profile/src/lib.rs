//! Static Solana adapter profile and per-settlement setup validation.

#![forbid(unsafe_code)]

use blake2::{digest::consts::U32, Blake2b, Digest};
use kaystra_core::{
    terms::{SettlementTermsV1, TermsError},
    types::{LockMechanism, TimelockSpec},
};
use serde::{Deserialize, Serialize};
use solana_pda::{derive_escrow_pdas, EscrowPdas, PdaError};
use solana_route_secret::{verify_counterparty_bundle, ROLE_SOLANA_CONDITION_LOCK};
use solana_types::{SolanaPubkey, LEGACY_TOKEN_PROGRAM_ID};
use xmr_dleq_sigma::{BoundCrossCurveProofV1, CrossCurvePublicClaim, DleqError};

type Blake2b256 = Blake2b<U32>;

pub const PROFILE_DOMAIN: &[u8] = b"DOM-INTEROP/SOLANA-ADAPTER-PROFILE/V1\0";
pub const PROOF_CONTEXT_DOMAIN: &[u8] = b"DOM-INTEROP/SOLANA-DLEQ-CONTEXT/V1\0";
pub const SETUP_DOMAIN: &[u8] = b"DOM-INTEROP/SOLANA-SETUP/V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SolanaNetwork {
    Devnet = 2,
    Testnet = 3,
    LocalValidator = 4,
}

impl SolanaNetwork {
    /// Decode the frozen discriminant. `0x01` is mainnet-beta in the
    /// adapter's own numbering and is refused here by omission, not by a
    /// special case, matching `BitcoinNetworkV1` and `MoneroNetworkV1`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            2 => Some(Self::Devnet),
            3 => Some(Self::Testnet),
            4 => Some(Self::LocalValidator),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SolanaAssetV1 {
    NativeSol,
    LegacySpl { mint: SolanaPubkey, decimals: u8 },
}

impl SolanaAssetV1 {
    pub const fn mint(self) -> SolanaPubkey {
        match self {
            Self::NativeSol => SolanaPubkey([0; 32]),
            Self::LegacySpl { mint, .. } => mint,
        }
    }
    pub const fn decimals(self) -> u8 {
        match self {
            Self::NativeSol => 0,
            Self::LegacySpl { decimals, .. } => decimals,
        }
    }
    pub const fn token_program(self) -> SolanaPubkey {
        match self {
            Self::NativeSol => SolanaPubkey([0; 32]),
            Self::LegacySpl { .. } => LEGACY_TOKEN_PROGRAM_ID,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaAdapterProfileV1 {
    pub network: SolanaNetwork,
    pub program_id: SolanaPubkey,
    pub rpc_node_count: u16,
    pub rpc_quorum: u16,
    pub allow_legacy_spl: bool,
    pub require_immutable_program: bool,
    pub max_signed_transaction_bytes: u32,
}

impl SolanaAdapterProfileV1 {
    pub fn new(
        network: SolanaNetwork,
        program_id: SolanaPubkey,
        rpc_node_count: u16,
        rpc_quorum: u16,
    ) -> Result<Self, SetupError> {
        if program_id.is_zero() || rpc_quorum == 0 || rpc_quorum > rpc_node_count {
            return Err(SetupError::InvalidProfile);
        }
        Ok(Self {
            network,
            program_id,
            rpc_node_count,
            rpc_quorum,
            allow_legacy_spl: true,
            require_immutable_program: !matches!(network, SolanaNetwork::LocalValidator),
            max_signed_transaction_bytes: 1232,
        })
    }

    pub fn profile_hash(&self) -> [u8; 32] {
        let mut hasher = Blake2b256::new();
        hasher.update(PROFILE_DOMAIN);
        hasher.update([self.network as u8]);
        hasher.update(self.program_id.0);
        hasher.update(self.rpc_node_count.to_be_bytes());
        hasher.update(self.rpc_quorum.to_be_bytes());
        hasher.update([u8::from(self.allow_legacy_spl)]);
        hasher.update([u8::from(self.require_immutable_program)]);
        hasher.update(self.max_signed_transaction_bytes.to_be_bytes());
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaSetupBindingV1 {
    pub settlement_id: [u8; 32],
    pub terms_hash: [u8; 32],
    pub dleq: BoundCrossCurveProofV1,
    pub program_id: SolanaPubkey,
    pub state_pda: SolanaPubkey,
    pub vault_pda: SolanaPubkey,
    pub vault_authority: SolanaPubkey,
    pub state_bump: u8,
    pub vault_bump: u8,
    pub authority_bump: u8,
    pub asset: SolanaAssetV1,
    pub funder: SolanaPubkey,
    pub recipient: SolanaPubkey,
    pub refund_recipient: SolanaPubkey,
    pub amount: u64,
    pub refund_after_unix: i64,
    pub program_data_hash: [u8; 32],
    pub setup_id: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("invalid Solana profile")]
    InvalidProfile,
    #[error("invalid Kaystra terms: {0}")]
    Terms(#[from] TermsError),
    #[error("DLEQ failed: {0}")]
    Dleq(#[from] DleqError),
    #[error("route-secret validation failed")]
    RouteSecret,
    #[error("PDA derivation failed: {0}")]
    Pda(#[from] PdaError),
    #[error("setup does not match frozen terms/profile")]
    BindingMismatch,
    #[error("amount/timestamp outside supported range")]
    BoundsExceeded,
}

pub struct ValidatedSolanaSetup {
    binding: SolanaSetupBindingV1,
    claim: CrossCurvePublicClaim,
    binding_hash: [u8; 32],
}

impl Clone for ValidatedSolanaSetup {
    fn clone(&self) -> Self {
        Self {
            binding: self.binding.clone(),
            claim: self.claim,
            binding_hash: self.binding_hash,
        }
    }
}

impl core::fmt::Debug for ValidatedSolanaSetup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ValidatedSolanaSetup")
            .field("settlement_id", &"<public-id>")
            .field("program_id", &self.binding.program_id)
            .field("state_pda", &self.binding.state_pda)
            .field("amount", &self.binding.amount)
            .finish_non_exhaustive()
    }
}

impl ValidatedSolanaSetup {
    pub const fn settlement_id(&self) -> [u8; 32] {
        self.binding.settlement_id
    }
    pub const fn terms_hash(&self) -> [u8; 32] {
        self.binding.terms_hash
    }
    pub const fn program_id(&self) -> SolanaPubkey {
        self.binding.program_id
    }
    pub const fn state_pda(&self) -> SolanaPubkey {
        self.binding.state_pda
    }
    pub const fn vault_pda(&self) -> SolanaPubkey {
        self.binding.vault_pda
    }
    pub const fn vault_authority(&self) -> SolanaPubkey {
        self.binding.vault_authority
    }
    pub const fn funder(&self) -> SolanaPubkey {
        self.binding.funder
    }
    pub const fn recipient(&self) -> SolanaPubkey {
        self.binding.recipient
    }
    pub const fn refund_recipient(&self) -> SolanaPubkey {
        self.binding.refund_recipient
    }
    pub const fn amount(&self) -> u64 {
        self.binding.amount
    }
    pub const fn refund_after_unix(&self) -> i64 {
        self.binding.refund_after_unix
    }
    pub const fn asset(&self) -> SolanaAssetV1 {
        self.binding.asset
    }
    pub const fn setup_id(&self) -> [u8; 32] {
        self.binding.setup_id
    }
    pub const fn claim(&self) -> CrossCurvePublicClaim {
        self.claim
    }
    pub const fn binding_hash(&self) -> [u8; 32] {
        self.binding_hash
    }
    pub const fn program_data_hash(&self) -> [u8; 32] {
        self.binding.program_data_hash
    }
    pub fn binding(&self) -> &SolanaSetupBindingV1 {
        &self.binding
    }
}

/// Economic/profile context committed before the adaptor point exists.
///
/// This avoids a circular dependency: `SettlementTermsV1` commits to `T`,
/// while `T` is produced by the route secret. The DLEQ context therefore
/// hashes every relevant counterparty field except `T` and the final terms hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SolanaProofContextV1 {
    pub settlement_id: [u8; 32],
    pub chain_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub amount: u128,
    pub beneficiary: [u8; 32],
    pub refund_to: [u8; 32],
    pub refund_after_unix: u64,
    pub min_confirmations: u32,
    pub max_reorg_depth: u32,
    pub asset: SolanaAssetV1,
    pub funder: SolanaPubkey,
}

/// Hash the pre-adaptor Solana context.
pub fn proof_context_hash(
    profile: &SolanaAdapterProfileV1,
    context: &SolanaProofContextV1,
) -> Result<[u8; 32], SetupError> {
    if context.settlement_id == [0; 32]
        || context.chain_id == [0; 32]
        || context.asset_id == [0; 32]
        || context.amount == 0
        || context.beneficiary == [0; 32]
        || context.refund_to == [0; 32]
        || context.refund_after_unix == 0
        || context.min_confirmations == 0
        || context.max_reorg_depth < context.min_confirmations
        || context.funder.is_zero()
    {
        return Err(SetupError::InvalidProfile);
    }
    if matches!(context.asset, SolanaAssetV1::LegacySpl { mint, .. } if mint.is_zero()) {
        return Err(SetupError::InvalidProfile);
    }
    let mut hasher = Blake2b256::new();
    hasher.update(PROOF_CONTEXT_DOMAIN);
    hasher.update(profile.profile_hash());
    hasher.update(context.settlement_id);
    hasher.update(context.chain_id);
    hasher.update(context.asset_id);
    hasher.update(context.amount.to_be_bytes());
    hasher.update(context.beneficiary);
    hasher.update(context.refund_to);
    hasher.update(context.refund_after_unix.to_be_bytes());
    hasher.update(context.min_confirmations.to_be_bytes());
    hasher.update(context.max_reorg_depth.to_be_bytes());
    match context.asset {
        SolanaAssetV1::NativeSol => hasher.update([1]),
        SolanaAssetV1::LegacySpl { mint, decimals } => {
            hasher.update([2]);
            hasher.update(mint.0);
            hasher.update([decimals]);
        }
    }
    hasher.update(context.funder.0);
    Ok(hasher.finalize().into())
}

/// Reconstruct the exact pre-adaptor context from frozen terms and setup fields.
pub fn proof_context_from_terms(
    terms: &SettlementTermsV1,
    asset: SolanaAssetV1,
    funder: SolanaPubkey,
) -> Result<SolanaProofContextV1, SetupError> {
    terms.validate()?;
    let refund_after_unix = match terms.counterparty_leg.deadline {
        TimelockSpec::TimestampSeconds { value } => value,
        _ => return Err(SetupError::BindingMismatch),
    };
    Ok(SolanaProofContextV1 {
        settlement_id: terms.settlement_id.0,
        chain_id: terms.counterparty_leg.chain_id.0,
        asset_id: terms.counterparty_leg.asset_id.0,
        amount: terms.counterparty_leg.amount,
        beneficiary: terms.counterparty_leg.beneficiary.0,
        refund_to: terms.counterparty_leg.refund_to.0,
        refund_after_unix,
        min_confirmations: terms.counterparty_leg.finality.min_confirmations,
        max_reorg_depth: terms.counterparty_leg.finality.max_reorg_depth,
        asset,
        funder,
    })
}

pub fn setup_id(binding: &SolanaSetupBindingV1) -> Result<[u8; 32], SetupError> {
    let mut hasher = Blake2b256::new();
    hasher.update(SETUP_DOMAIN);
    hasher.update(binding.settlement_id);
    hasher.update(binding.terms_hash);
    hasher.update(binding.dleq.binding_hash()?);
    hasher.update(binding.program_id.0);
    hasher.update(binding.state_pda.0);
    hasher.update(binding.vault_pda.0);
    hasher.update(binding.vault_authority.0);
    hasher.update([
        binding.state_bump,
        binding.vault_bump,
        binding.authority_bump,
    ]);
    match binding.asset {
        SolanaAssetV1::NativeSol => hasher.update([1]),
        SolanaAssetV1::LegacySpl { mint, decimals } => {
            hasher.update([2]);
            hasher.update(mint.0);
            hasher.update([decimals]);
        }
    }
    hasher.update(binding.funder.0);
    hasher.update(binding.recipient.0);
    hasher.update(binding.refund_recipient.0);
    hasher.update(binding.amount.to_be_bytes());
    hasher.update(binding.refund_after_unix.to_be_bytes());
    hasher.update(binding.program_data_hash);
    Ok(hasher.finalize().into())
}

pub fn validate_setup(
    profile: &SolanaAdapterProfileV1,
    terms: &SettlementTermsV1,
    binding: SolanaSetupBindingV1,
) -> Result<ValidatedSolanaSetup, SetupError> {
    terms.validate()?;
    let terms_hash = terms.terms_hash()?;
    if binding.settlement_id != terms.settlement_id.0
        || binding.terms_hash != terms_hash
        || binding.program_id != profile.program_id
        || terms.counterparty_leg.adapter_profile_hash != profile.profile_hash()
        || terms.counterparty_leg.mechanism != LockMechanism::CrossCurveConditionLock
        || binding.recipient.0 != terms.counterparty_leg.beneficiary.0
        || binding.refund_recipient.0 != terms.counterparty_leg.refund_to.0
        || binding.amount as u128 != terms.counterparty_leg.amount
        || binding.funder.is_zero()
    {
        return Err(SetupError::BindingMismatch);
    }
    let expected_deadline = match terms.counterparty_leg.deadline {
        TimelockSpec::TimestampSeconds { value } => {
            i64::try_from(value).map_err(|_| SetupError::BoundsExceeded)?
        }
        _ => return Err(SetupError::BindingMismatch),
    };
    if binding.refund_after_unix != expected_deadline || binding.refund_after_unix <= 0 {
        return Err(SetupError::BindingMismatch);
    }
    if profile.require_immutable_program && binding.program_data_hash == [0; 32] {
        return Err(SetupError::BindingMismatch);
    }
    match binding.asset {
        SolanaAssetV1::NativeSol => {}
        SolanaAssetV1::LegacySpl { mint, .. } => {
            if !profile.allow_legacy_spl || mint.is_zero() {
                return Err(SetupError::BindingMismatch);
            }
        }
    }
    let context = proof_context_from_terms(terms, binding.asset, binding.funder)?;
    let context_hash = proof_context_hash(profile, &context)?;
    let claim = verify_counterparty_bundle(&binding.dleq, &binding.settlement_id, &context_hash)
        .map_err(|_| SetupError::RouteSecret)?;
    if claim.secp_compressed != terms.adaptor_point_sec1 {
        return Err(SetupError::BindingMismatch);
    }
    if binding.dleq.role != ROLE_SOLANA_CONDITION_LOCK {
        return Err(SetupError::BindingMismatch);
    }
    let pdas: EscrowPdas = derive_escrow_pdas(binding.program_id, binding.settlement_id)?;
    let expected_vault = match binding.asset {
        SolanaAssetV1::NativeSol => pdas.native_vault,
        SolanaAssetV1::LegacySpl { .. } => pdas.token_vault,
    };
    let expected_vault_bump = match binding.asset {
        SolanaAssetV1::NativeSol => pdas.native_vault_bump,
        SolanaAssetV1::LegacySpl { .. } => pdas.token_vault_bump,
    };
    if binding.state_pda != pdas.state
        || binding.vault_pda != expected_vault
        || binding.vault_authority != pdas.vault_authority
        || binding.state_bump != pdas.state_bump
        || binding.vault_bump != expected_vault_bump
        || binding.authority_bump != pdas.vault_authority_bump
        || setup_id(&binding)? != binding.setup_id
    {
        return Err(SetupError::BindingMismatch);
    }
    let binding_hash = setup_id(&binding)?;
    Ok(ValidatedSolanaSetup {
        binding,
        claim,
        binding_hash,
    })
}
